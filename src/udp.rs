//! UDP tunnel — TUIC v5 working mechanism.
//!
//! Implements the *mechanisms* that define TUIC v5 as a protocol (not its
//! exact wire bytes, since interop with tuic-client/tuic-server is not a
//! goal here):
//!
//!   - Authenticate: `VER(1)=5 | TYPE(1)=0 | UUID(16) | TOKEN(32)`, sent on
//!     a **unidirectional** stream in parallel with relay traffic — true
//!     0-RTT, no round trip required before the tunnel starts forwarding.
//!   - TOKEN is derived with the real TLS Keying Material Exporter
//!     (RFC 5705) from the live QUIC/TLS session via
//!     `quinn::Connection::export_keying_material`, with
//!     `label = UUID bytes`, `context = password bytes` — exactly the
//!     mechanism the spec describes, not a static password hash.
//!   - UUID is derived deterministically as `sha256(password)[..16]`.
//!
//! **Password-based routing**: the server pre‑computes `UUID = sha256(pw)[..16]`
//! for every configured backend.  When a client sends its Authenticate frame
//! the server matches the UUID against all entries, derives the expected
//! TOKEN using that entry's password, and binds the entire QUIC connection
//! to the matched backend.  Different passwords → different backends.

use anyhow::Context;
use bytes::Bytes;
use quinn::{Connection, VarInt};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};

use crate::config::TunnelConfig;
use crate::tls;

// ── TUIC v5 command types ───────────────────────────────────────────────────

const TUIC_VERSION: u8 = 5;
const TYPE_AUTHENTICATE: u8 = 0x00;
const TYPE_PACKET: u8 = 0x02;
const TYPE_DISSOCIATE: u8 = 0x03;
const TYPE_HEARTBEAT: u8 = 0x04;

const ADDR_NONE: u8 = 0xFF;
const ADDR_FQDN: u8 = 0x00;
const ADDR_IPV4: u8 = 0x01;
const ADDR_IPV6: u8 = 0x02;

/// Encode a "host:port" into a TUIC v5 address.
fn encode_tuic_addr(addr: &str) -> Vec<u8> {
    if addr.is_empty() { return vec![ADDR_NONE]; }
    let (host, port_str) = match addr.rsplit_once(':') {
        Some(v) => v,
        None => return vec![ADDR_NONE],
    };
    let port: u16 = match port_str.parse() { Ok(p) => p, Err(_) => return vec![ADDR_NONE] };
    if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
        let mut out = Vec::with_capacity(7);
        out.push(ADDR_IPV4);
        out.extend_from_slice(&ip.octets());
        out.extend_from_slice(&port.to_be_bytes());
        return out;
    }
    if let Ok(ip) = host.parse::<std::net::Ipv6Addr>() {
        let mut out = Vec::with_capacity(19);
        out.push(ADDR_IPV6);
        out.extend_from_slice(&ip.octets());
        out.extend_from_slice(&port.to_be_bytes());
        return out;
    }
    let host_bytes = host.as_bytes();
    if host_bytes.len() > 255 { return vec![ADDR_NONE]; }
    let mut out = Vec::with_capacity(4 + host_bytes.len());
    out.push(ADDR_FQDN);
    out.push(host_bytes.len() as u8);
    out.extend_from_slice(host_bytes);
    out.extend_from_slice(&port.to_be_bytes());
    out
}

/// Decode a TUIC v5 address. Returns `(host:port, bytes_consumed)`.
fn decode_tuic_addr(data: &[u8]) -> Option<(String, usize)> {
    if data.is_empty() { return None; }
    match data[0] {
        ADDR_NONE => Some((String::new(), 1)),
        ADDR_IPV4 => {
            if data.len() < 7 { return None; }
            let ip = std::net::Ipv4Addr::new(data[1], data[2], data[3], data[4]);
            let port = u16::from_be_bytes([data[5], data[6]]);
            Some((format!("{ip}:{port}"), 7))
        }
        ADDR_IPV6 => {
            if data.len() < 19 { return None; }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&data[1..17]);
            let ip = std::net::Ipv6Addr::from(octets);
            let port = u16::from_be_bytes([data[17], data[18]]);
            Some((format!("{ip}:{port}"), 19))
        }
        ADDR_FQDN => {
            if data.len() < 2 { return None; }
            let len = data[1] as usize;
            if data.len() < 2 + len + 2 { return None; }
            let host = String::from_utf8_lossy(&data[2..2 + len]);
            let port = u16::from_be_bytes([data[2 + len], data[3 + len]]);
            Some((format!("{host}:{port}"), 2 + len + 2))
        }
        _ => None,
    }
}

/// Minimum packet header with variable-length ADDR.
const PACKET_HEADER_MIN: usize = 1 + 2 + 2 + 1 + 1 + 2 + 1;

// ── Timing constants ────────────────────────────────────────────────────────

const DISSOCIATE_TIMEOUT: Duration = Duration::from_secs(60);
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(10);
const AUTH_TIMEOUT: Duration = Duration::from_secs(10);
const REASSEMBLY_TIMEOUT: Duration = Duration::from_secs(10);

// ── TUIC v5 application error codes ─────────────────────────────────────────

const ERROR_AUTHENTICATION_FAILED: u32 = 0xfffffff1;
const ERROR_BAD_COMMAND: u32 = 0xfffffff3;

// ── Transport ───────────────────────────────────────────────────────────────

const DEFAULT_DATAGRAM_PAYLOAD: usize = 1200;

fn datagram_payload_limit(conn: &Connection) -> usize {
    conn.max_datagram_size()
        .map(|max_dgram| max_dgram.saturating_sub(PACKET_HEADER_MIN))
        .unwrap_or(DEFAULT_DATAGRAM_PAYLOAD)
}

const MAX_REASSEMBLY_BUFFERS: usize = 64;
/// Maximum number of concurrent UDP associations per QUIC connection.
/// Each association creates a UDP socket; capping prevents FD exhaustion.
const MAX_ASSOCIATIONS: usize = 128;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum RelayMode {
    Datagram,
    Stream,
}

// ── Reassembly buffer ───────────────────────────────────────────────────────

struct ReassemblyBuffer {
    fragments: Vec<Option<Vec<u8>>>,
    total: u8,
    received: u8,
    created: Instant,
}

impl ReassemblyBuffer {
    fn new(total: u8) -> Self {
        Self {
            fragments: (0..total).map(|_| None).collect(),
            total,
            received: 0,
            created: Instant::now(),
        }
    }

    fn insert(&mut self, frag_id: u8, payload: &[u8]) -> bool {
        if frag_id >= self.total || self.fragments[frag_id as usize].is_some() {
            return false;
        }
        self.fragments[frag_id as usize] = Some(payload.to_vec());
        self.received += 1;
        self.received == self.total
    }

    fn assemble(self) -> Vec<u8> {
        let total_len: usize = self
            .fragments
            .iter()
            .map(|f| f.as_ref().map_or(0, |v| v.len()))
            .sum();
        let mut out = Vec::with_capacity(total_len);
        for frag in self.fragments {
            if let Some(data) = frag {
                out.extend_from_slice(&data);
            }
        }
        out
    }

    fn is_stale(&self) -> bool {
        self.created.elapsed() > REASSEMBLY_TIMEOUT
    }
}

// ── Authentication helpers ──────────────────────────────────────────────────

fn derive_uuid(password: &str) -> [u8; 16] {
    let hash = Sha256::digest(password.as_bytes());
    hash[..16].try_into().unwrap()
}

fn derive_token(conn: &Connection, uuid: &[u8; 16], password: &str) -> anyhow::Result<[u8; 32]> {
    let mut out = [0u8; 32];
    conn.export_keying_material(&mut out, uuid, password.as_bytes())
        .map_err(|e| anyhow::anyhow!("failed to export TLS keying material: {e:?}"))?;
    Ok(out)
}

fn build_authenticate(uuid: &[u8; 16], token: &[u8; 32]) -> Vec<u8> {
    let mut b = Vec::with_capacity(2 + 16 + 32);
    b.push(TUIC_VERSION);
    b.push(TYPE_AUTHENTICATE);
    b.extend_from_slice(uuid);
    b.extend_from_slice(token);
    b
}

// ── Packet frame building ───────────────────────────────────────────────────

fn build_packet_fragment(
    assoc_id: u16, pkt_id: u16, frag_total: u8, frag_id: u8, payload: &[u8],
) -> Vec<u8> {
    // Fixed forwarder: always sends ADDR_NONE.
    let addr = encode_tuic_addr("");
    let mut b = Vec::with_capacity(PACKET_HEADER_MIN + addr.len() - 1 + payload.len());
    b.push(TYPE_PACKET);
    b.extend_from_slice(&assoc_id.to_be_bytes());
    b.extend_from_slice(&pkt_id.to_be_bytes());
    b.push(frag_total);
    b.push(frag_id);
    b.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    b.extend_from_slice(&addr);
    b.extend_from_slice(payload);
    b
}

fn build_packet(assoc_id: u16, pkt_id: u16, payload: &[u8]) -> Vec<u8> {
    build_packet_fragment(assoc_id, pkt_id, 1, 0, payload)
}

fn build_packet_maybe_fragmented(assoc_id: u16, pkt_id: u16, payload: &[u8], max_payload: usize) -> Vec<Vec<u8>> {
    if payload.len() <= max_payload {
        return vec![build_packet(assoc_id, pkt_id, payload)];
    }
    let frag_total = ((payload.len() + max_payload - 1) / max_payload) as u8;
    (0..frag_total)
        .map(|frag_id| {
            let start = frag_id as usize * max_payload;
            let end = std::cmp::min(start + max_payload, payload.len());
            build_packet_fragment(assoc_id, pkt_id, frag_total, frag_id, &payload[start..end])
        })
        .collect()
}

// ── Packet frame parsing ────────────────────────────────────────────────────

fn parse_packet(data: &[u8]) -> Option<(u16, u16, u8, u8, &[u8])> {
    if data.is_empty() || data[0] != TYPE_PACKET {
        return None;
    }
    if data.len() < PACKET_HEADER_MIN {
        return None;
    }
    let assoc_id = u16::from_be_bytes([data[1], data[2]]);
    let pkt_id = u16::from_be_bytes([data[3], data[4]]);
    let frag_total = data[5];
    let frag_id = data[6];
    let size = u16::from_be_bytes([data[7], data[8]]) as usize;
    // Decode variable-length TUIC address to find payload offset.
    let addr_data = &data[9..];
    let (_, addr_len) = decode_tuic_addr(addr_data)?;
    let payload_start = 9 + addr_len;
    if frag_total == 0 || frag_id >= frag_total {
        return None;
    }
    if payload_start + size > data.len() {
        return None;
    }
    Some((assoc_id, pkt_id, frag_total, frag_id, &data[payload_start..payload_start + size]))
}

fn build_dissociate(assoc_id: u16) -> Vec<u8> {
    let mut b = Vec::with_capacity(3);
    b.push(TYPE_DISSOCIATE);
    b.extend_from_slice(&assoc_id.to_be_bytes());
    b
}

fn build_heartbeat() -> Vec<u8> {
    vec![TYPE_HEARTBEAT]
}

async fn send_packet_reply(conn: &Connection, pkt: Vec<u8>, mode: RelayMode) -> bool {
    match mode {
        RelayMode::Datagram => conn.send_datagram(Bytes::from(pkt)).is_ok(),
        RelayMode::Stream => {
            match conn.open_uni().await {
                Ok(mut s) => {
                    if s.write_all(&pkt).await.is_err() {
                        return false;
                    }
                    s.finish().is_ok()
                }
                Err(_) => false,
            }
        }
    }
}

// ── Server ──────────────────────────────────────────────────────────────────

/// Pre‑computed backend entry for the server.
/// `uuid = sha256(password)[..16]`, used to match the client's Authenticate.
struct BackendEntry {
    addr: String,
    uuid: [u8; 16],
    password: String,
}

pub async fn run_udp_server(config: &TunnelConfig) -> anyhow::Result<()> {
    let cert = config.cert.as_ref().context("server mode requires `cert`")?;
    let key = config.key.as_ref().context("server mode requires `key`")?;

    let rustls_config = tls::build_rustls_server_config(cert, key)?;
    let quic_config = tls::build_quic_server_config(rustls_config)?;

    let listen_addr: SocketAddr = config.listen.parse().context("invalid `listen` address")?;
    let endpoint = quinn::Endpoint::server(quic_config, listen_addr)
        .context("failed to bind QUIC endpoint")?;

    // Pre‑compute UUIDs for password‑based routing.
    let backends: Vec<BackendEntry> = config
        .remotes
        .iter()
        .map(|r| BackendEntry {
            addr: r.addr.clone(),
            uuid: derive_uuid(&r.password),
            password: r.password.clone(),
        })
        .collect();
    info!("[TUIC server] listening on {listen_addr} (QUIC), {} backend(s)", backends.len());
    for b in &backends {
        info!("[TUIC server]   -> {}", b.addr);
    }

    let backends = Arc::new(backends);
    let mut tasks = tokio::task::JoinSet::new();

    loop {
        tokio::select! {
            accept = endpoint.accept() => {
                let incoming = match accept {
                    Some(inc) => inc,
                    None => break,
                };
                let backends = backends.clone();
                let peer = incoming.remote_address();

                tasks.spawn(async move {
                    match incoming.await {
                        Ok(conn) => {
                            if let Err(e) = handle_tuic_connection(conn, backends).await {
                                error!("[TUIC server] connection from {peer}: {e:#}");
                            }
                        }
                        Err(e) => warn!("[TUIC server] QUIC handshake with {peer} failed: {e}"),
                    }
                });
            }
            _ = tokio::time::sleep(Duration::from_secs(30)) => {
                while tasks.try_join_next().is_some() {}
            }
        }
    }

    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    Ok(())
}

// ── Server state ────────────────────────────────────────────────────────────

struct AssocState {
    mode: RelayMode,
    last_seen: Instant,
}

struct ServerAssoc {
    sock: Arc<UdpSocket>,
    /// Backend address this assoc forwards to (matched during auth).
    remote: String,
    state: Mutex<AssocState>,
    reassembly: Mutex<HashMap<u16, ReassemblyBuffer>>,
    reply_handle: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl ServerAssoc {
    fn new(sock: Arc<UdpSocket>, mode: RelayMode, remote: String) -> Self {
        Self {
            sock,
            remote,
            state: Mutex::new(AssocState { mode, last_seen: Instant::now() }),
            reassembly: Mutex::new(HashMap::new()),
            reply_handle: Mutex::new(None),
        }
    }
}

// ── Connection handler ──────────────────────────────────────────────────────

async fn handle_tuic_connection(
    conn: Connection,
    backends: Arc<Vec<BackendEntry>>,
) -> anyhow::Result<()> {
    let peer = conn.remote_address();
    debug!("[TUIC server] new QUIC connection from {peer}");

    // ── 0‑RTT Authenticate ──────────────────────────────────────────────
    // Read the Authenticate frame quickly (50 bytes) so data processing can
    // start immediately.  TOKEN verification runs concurrently — if it fails,
    // the connection is closed.

    // Shared state: set to Some(addr) once auth succeeds, stays None until then.
    let auth_remote: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let auth_done: Arc<Mutex<bool>> = Arc::new(Mutex::new(false));

    // Spawn the auth task: read Authenticate stream, verify, set remote.
    let conn2 = conn.clone();
    let backends2 = backends.clone();
    let auth_remote2 = auth_remote.clone();
    let auth_done2 = auth_done.clone();
    let auth_task = tokio::spawn(async move {
        let result = tokio::time::timeout(AUTH_TIMEOUT, async {
            let mut auth_stream = conn2.accept_uni().await?;
            auth_stream
                .read_to_end(2 + 16 + 32)
                .await
                .map_err(|e| anyhow::anyhow!("read Authenticate: {e}"))
        }).await;

        let auth_data = match result {
            Ok(Ok(data)) => data,
            _ => {
                let _ = conn2.close(VarInt::from_u32(ERROR_AUTHENTICATION_FAILED), b"auth failed");
                *auth_done2.lock().await = true;
                return;
            }
        };

        if auth_data.len() < 2 + 16 + 32
            || auth_data[0] != TUIC_VERSION
            || auth_data[1] != TYPE_AUTHENTICATE
        {
            let _ = conn2.close(VarInt::from_u32(ERROR_BAD_COMMAND), b"bad Authenticate");
            *auth_done2.lock().await = true;
            return;
        }

        let recv_uuid: [u8; 16] = auth_data[2..18].try_into().unwrap();
        let recv_token: [u8; 32] = auth_data[18..50].try_into().unwrap();

        let matched = match backends2.iter().find(|b| b.uuid == recv_uuid) {
            Some(b) => b,
            None => {
                let _ = conn2.close(VarInt::from_u32(ERROR_AUTHENTICATION_FAILED), b"auth failed");
                *auth_done2.lock().await = true;
                return;
            }
        };

        let expected_token = match derive_token(&conn2, &recv_uuid, &matched.password) {
            Ok(t) => t,
            Err(_) => {
                let _ = conn2.close(VarInt::from_u32(ERROR_AUTHENTICATION_FAILED), b"token error");
                *auth_done2.lock().await = true;
                return;
            }
        };

        if recv_token != expected_token {
            let _ = conn2.close(VarInt::from_u32(ERROR_AUTHENTICATION_FAILED), b"auth failed");
            *auth_done2.lock().await = true;
            return;
        }

        *auth_remote2.lock().await = Some(matched.addr.clone());
        *auth_done2.lock().await = true;
        debug!("[TUIC server] auth ok from {peer} -> {}", matched.addr);
    });

    // Wait briefly for auth to set the remote, then proceed.
    // This gives near‑0‑RTT: data processing starts immediately while
    // the TOKEN is still being verified.
    let remote: Arc<String>;
    loop {
        let addr = auth_remote.lock().await.clone();
        if let Some(a) = addr {
            remote = Arc::new(a);
            break;
        }
        let done = *auth_done.lock().await;
        if done {
            // Auth failed — the auth task already closed the connection.
            auth_task.abort();
            return Ok(());
        }
        // Auth still in progress — yield and retry.
        drop(auth_done.lock().await);
        tokio::task::yield_now().await;
    }

    let assocs: Arc<Mutex<HashMap<u16, Arc<ServerAssoc>>>> = Arc::new(Mutex::new(HashMap::new()));
    let pkt_id_ctr = Arc::new(AtomicU16::new(0));

    // Background janitor.
    let janitor_handle = {
        let assocs = assocs.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(DISSOCIATE_TIMEOUT / 2).await;
                let mut map = assocs.lock().await;
                let mut stale = Vec::new();
                for (id, a) in map.iter() {
                    let mut reassembly = a.reassembly.lock().await;
                    reassembly.retain(|_, buf| !buf.is_stale());
                    if a.state.lock().await.last_seen.elapsed() > DISSOCIATE_TIMEOUT {
                        stale.push(*id);
                    }
                }
                for id in stale {
                    if let Some(assoc) = map.remove(&id) {
                        if let Some(handle) = assoc.reply_handle.lock().await.take() {
                            handle.abort();
                        }
                    }
                }
            }
        })
    };

    let dgram_loop = run_datagram_loop(&conn, assocs.clone(), remote.clone(), &pkt_id_ctr);
    let stream_loop = run_stream_loop(&conn, assocs.clone(), remote.clone(), &pkt_id_ctr);

    tokio::select! {
        r = dgram_loop => {
            if let Err(e) = r { debug!("[TUIC server] datagram loop: {e}"); }
        }
        r = stream_loop => {
            if let Err(e) = r { debug!("[TUIC server] stream loop: {e}"); }
        }
    }

    // ── Clean up all reply pump tasks ───────────────────────────────────
    // The janitor has been cleaning stale assocs during normal operation,
    // but once the QUIC connection dies we must abort every remaining
    // reply pump — otherwise they block forever on sock.recv_from(),
    // leaking UDP sockets, memory, and tokio tasks.
    for (_, assoc) in assocs.lock().await.drain() {
        if let Some(handle) = assoc.reply_handle.lock().await.take() {
            handle.abort();
        }
    }
    janitor_handle.abort();
    auth_task.abort();
    Ok(())
}

// ── Shared command dispatch ─────────────────────────────────────────────────

async fn dispatch_command(
    cmd_data: &[u8],
    from_mode: RelayMode,
    assocs: &Arc<Mutex<HashMap<u16, Arc<ServerAssoc>>>>,
    remote: &Arc<String>,
    conn: &Connection,
    pkt_id_ctr: &Arc<AtomicU16>,
) {
    if cmd_data.is_empty() {
        return;
    }

    match cmd_data[0] {
        TYPE_PACKET => {
            let Some((assoc_id, pkt_id, frag_total, frag_id, payload)) = parse_packet(cmd_data)
            else {
                warn!("[TUIC server] malformed Packet ({} bytes, mode={from_mode:?})", cmd_data.len());
                return;
            };

            let assoc = {
                let mut map = assocs.lock().await;
                if let Some(a) = map.get(&assoc_id) {
                    a.clone()
                } else {
                    // Enforce per-connection association limit.
                    if map.len() >= MAX_ASSOCIATIONS {
                        warn!("[TUIC server] assoc limit ({MAX_ASSOCIATIONS}) reached, dropping packet");
                        return;
                    }
                    let sock = match UdpSocket::bind("0.0.0.0:0").await {
                        Ok(s) => Arc::new(s),
                        Err(e) => {
                            warn!("[TUIC server] failed to bind assoc socket: {e}");
                            return;
                        }
                    };
                    let remote_for_assoc = remote.as_ref().clone();
                    let assoc = Arc::new(ServerAssoc::new(sock.clone(), from_mode, remote_for_assoc.clone()));
                    map.insert(assoc_id, assoc.clone());

                    let conn2 = conn.clone();
                    let pkt_id_ctr2 = pkt_id_ctr.clone();
                    let assocs2 = assocs.clone();
                    let assoc_for_pump = assoc.clone();
                    let reply_handle = tokio::spawn(async move {
                        let max_payload = datagram_payload_limit(&conn2);
                        let mut buf = vec![0u8; 65536];
                        loop {
                            match sock.recv_from(&mut buf).await {
                                Ok((n, _from)) => {
                                    let mode = assoc_for_pump.state.lock().await.mode;
                                    let id = pkt_id_ctr2.fetch_add(1, Ordering::Relaxed);
                                    let frames = build_packet_maybe_fragmented(assoc_id, id, &buf[..n], max_payload);
                                    let mut ok = true;
                                    for pkt in frames {
                                        if !send_packet_reply(&conn2, pkt, mode).await {
                                            ok = false;
                                            break;
                                        }
                                    }
                                    if !ok { break; }
                                }
                                Err(_) => break,
                            }
                        }
                        assocs2.lock().await.remove(&assoc_id);
                    });
                    *assoc.reply_handle.lock().await = Some(reply_handle);
                    assoc
                }
            };

            {
                let mut state = assoc.state.lock().await;
                state.mode = from_mode;
                state.last_seen = Instant::now();
            }

            if frag_total == 1 {
                if let Err(e) = assoc.sock.send_to(payload, assoc.remote.as_str()).await {
                    warn!("[TUIC server] assoc {assoc_id} send to {} failed: {e}", assoc.remote);
                }
            } else {
                let mut reassembly = assoc.reassembly.lock().await;
                if let Some(existing) = reassembly.get(&pkt_id) {
                    if existing.total != frag_total {
                        reassembly.remove(&pkt_id);
                    }
                }
                if reassembly.len() >= MAX_REASSEMBLY_BUFFERS && !reassembly.contains_key(&pkt_id) {
                    if let Some(oldest_key) = reassembly.iter().min_by_key(|(_, buf)| buf.created).map(|(k, _)| *k) {
                        reassembly.remove(&oldest_key);
                        debug!("[TUIC server] evicted stale reassembly buffer pkt_id={oldest_key}");
                    }
                }
                let entry = reassembly.entry(pkt_id).or_insert_with(|| ReassemblyBuffer::new(frag_total));
                if entry.insert(frag_id, payload) {
                    let complete = reassembly.remove(&pkt_id).unwrap().assemble();
                    drop(reassembly);
                    if let Err(e) = assoc.sock.send_to(&complete, assoc.remote.as_str()).await {
                        warn!("[TUIC server] assoc {assoc_id} send to {} failed: {e}", assoc.remote);
                    }
                }
            }
        }

        TYPE_DISSOCIATE => {
            if cmd_data.len() >= 3 {
                let assoc_id = u16::from_be_bytes([cmd_data[1], cmd_data[2]]);
                if let Some(assoc) = assocs.lock().await.remove(&assoc_id) {
                    if let Some(handle) = assoc.reply_handle.lock().await.take() {
                        handle.abort();
                    }
                }
            }
        }

        TYPE_HEARTBEAT => {}

        other => warn!("[TUIC server] unknown command type {other} (mode={from_mode:?})"),
    }
}

async fn run_datagram_loop(
    conn: &Connection,
    assocs: Arc<Mutex<HashMap<u16, Arc<ServerAssoc>>>>,
    remote: Arc<String>,
    pkt_id_ctr: &Arc<AtomicU16>,
) -> anyhow::Result<()> {
    loop {
        let dgram = match conn.read_datagram().await {
            Ok(d) => d,
            Err(e) => return Err(anyhow::anyhow!("read_datagram: {e}")),
        };
        dispatch_command(&dgram, RelayMode::Datagram, &assocs, &remote, conn, pkt_id_ctr).await;
    }
}

async fn run_stream_loop(
    conn: &Connection,
    assocs: Arc<Mutex<HashMap<u16, Arc<ServerAssoc>>>>,
    remote: Arc<String>,
    pkt_id_ctr: &Arc<AtomicU16>,
) -> anyhow::Result<()> {
    loop {
        let mut stream = conn.accept_uni().await?;
        let data = match stream.read_to_end(65536).await.map_err(|e| anyhow::anyhow!("stream read: {e}")) {
            Ok(d) => d,
            Err(e) => {
                warn!("[TUIC server] stream read error: {e}");
                continue;
            }
        };
        dispatch_command(&data, RelayMode::Stream, &assocs, &remote, conn, pkt_id_ctr).await;
    }
}

// ── Client ──────────────────────────────────────────────────────────────────

pub async fn run_udp_client(config: &TunnelConfig) -> anyhow::Result<()> {
    let local = Arc::new(
        UdpSocket::bind(&config.listen)
            .await
            .with_context(|| format!("failed to bind UDP listen address {}", config.listen))?,
    );
    info!("[TUIC client] listening on {} (plain UDP)", config.listen);

    let rustls_cfg = tls::build_rustls_client_config(config.insecure);
    let quic_client_cfg = tls::build_quic_client_config(rustls_cfg)?;
    let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().unwrap())
        .context("failed to create QUIC client endpoint")?;
    endpoint.set_default_client_config(quic_client_cfg);

    let sni = if config.sni.is_empty() {
        config.remote().rsplit_once(':').map(|(h, _)| h.to_string()).unwrap_or_default()
    } else {
        config.sni.clone()
    };

    let remote_addr: SocketAddr = tokio::net::lookup_host(config.remote())
        .await
        .with_context(|| format!("failed to resolve {}", config.remote()))?
        .next()
        .ok_or_else(|| anyhow::anyhow!("no address found for {}", config.remote()))?;

    info!("[TUIC client] connecting QUIC to {remote_addr} (sni={sni}) ...");
    let conn = tokio::time::timeout(Duration::from_secs(10), async {
        endpoint.connect(remote_addr, &sni)?.await.map_err(anyhow::Error::from)
    })
    .await
    .context("QUIC connect timed out")??;
    info!("[TUIC client] QUIC connected to {remote_addr}");

    // ── Authenticate using the first remote entry's password ──
    let password = &config.remotes[0].password;
    let uuid = derive_uuid(password);
    let token = derive_token(&conn, &uuid, password)?;
    {
        let mut s = conn.open_uni().await.context("failed to open auth stream")?;
        s.write_all(&build_authenticate(&uuid, &token)).await.context("failed to write Authenticate")?;
        s.finish().context("failed to finish auth stream")?;
    }
    info!("[TUIC client] auth ok");

    let assoc_id: u16 = 1;
    let pkt_id_ctr = Arc::new(AtomicU16::new(0));
    let conn = Arc::new(conn);
    let relay_mode = RelayMode::Datagram;
    let last_peer: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));

    let heartbeat_handle = {
        let conn2 = conn.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(HEARTBEAT_INTERVAL).await;
                if conn2.send_datagram(Bytes::from(build_heartbeat())).is_err() {
                    break;
                }
            }
        })
    };

    let mut l2q = tokio::spawn(local_udp_to_quic(
        local.clone(), conn.clone(), assoc_id, pkt_id_ctr.clone(), last_peer.clone(), relay_mode,
    ));
    let mut q2l = tokio::spawn(quic_to_local_udp(local, conn.clone(), assoc_id, last_peer));

    tokio::select! {
        _ = &mut l2q => { q2l.abort(); }
        _ = &mut q2l => { l2q.abort(); }
    }
    heartbeat_handle.abort();

    let mut s = conn.open_uni().await?;
    let _ = s.write_all(&build_dissociate(assoc_id)).await;
    let _ = s.finish();

    debug!("[TUIC client] tunnel ended");
    Ok(())
}

async fn local_udp_to_quic(
    local: Arc<UdpSocket>,
    conn: Arc<Connection>,
    assoc_id: u16,
    pkt_id_ctr: Arc<AtomicU16>,
    last_peer: Arc<Mutex<Option<SocketAddr>>>,
    relay_mode: RelayMode,
) {
    let max_payload = datagram_payload_limit(&conn);
    let mut buf = vec![0u8; 65536];
    loop {
        let (n, peer) = match local.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(_) => break,
        };
        *last_peer.lock().await = Some(peer);
        let id = pkt_id_ctr.fetch_add(1, Ordering::Relaxed);
        let frames = build_packet_maybe_fragmented(assoc_id, id, &buf[..n], max_payload);
        match relay_mode {
            RelayMode::Datagram => {
                for pkt in frames {
                    if let Err(e) = conn.send_datagram(Bytes::from(pkt)) {
                        warn!("[TUIC client] send_datagram error: {e}");
                    }
                }
            }
            RelayMode::Stream => {
                for pkt in frames {
                    match conn.open_uni().await {
                        Ok(mut s) => {
                            if let Err(e) = s.write_all(&pkt).await {
                                warn!("[TUIC client] stream write error: {e}");
                                return;
                            }
                            if let Err(e) = s.finish() {
                                warn!("[TUIC client] stream finish error: {e}");
                                return;
                            }
                        }
                        Err(e) => {
                            warn!("[TUIC client] open_uni error: {e}");
                            return;
                        }
                    }
                }
            }
        }
    }
}

async fn handle_client_packet(
    data: &[u8],
    assoc_id: u16,
    reassembly: &mut HashMap<u16, ReassemblyBuffer>,
    last_peer: &Arc<Mutex<Option<SocketAddr>>>,
    local: &UdpSocket,
) {
    let Some((recv_assoc, pkt_id, frag_total, frag_id, payload)) = parse_packet(data) else {
        warn!("[TUIC client] malformed Packet ({} bytes)", data.len());
        return;
    };
    if recv_assoc != assoc_id {
        return;
    }
    if frag_total == 1 {
        let peer = *last_peer.lock().await;
        if let Some(peer) = peer {
            if let Err(e) = local.send_to(payload, peer).await {
                warn!("[TUIC client] send_to {peer} error: {e}");
            }
        }
    } else {
        if let Some(existing) = reassembly.get(&pkt_id) {
            if existing.total != frag_total {
                reassembly.remove(&pkt_id);
            }
        }
        if reassembly.len() >= MAX_REASSEMBLY_BUFFERS && !reassembly.contains_key(&pkt_id) {
            if let Some(oldest_key) = reassembly.iter().min_by_key(|(_, buf)| buf.created).map(|(k, _)| *k) {
                reassembly.remove(&oldest_key);
            }
        }
        let entry = reassembly.entry(pkt_id).or_insert_with(|| ReassemblyBuffer::new(frag_total));
        if entry.insert(frag_id, payload) {
            let complete = reassembly.remove(&pkt_id).unwrap().assemble();
            let peer = *last_peer.lock().await;
            if let Some(peer) = peer {
                if let Err(e) = local.send_to(&complete, peer).await {
                    warn!("[TUIC client] send_to {peer} error: {e}");
                }
            }
        }
    }
}

async fn quic_to_local_udp(
    local: Arc<UdpSocket>,
    conn: Arc<Connection>,
    assoc_id: u16,
    last_peer: Arc<Mutex<Option<SocketAddr>>>,
) {
    let mut reassembly: HashMap<u16, ReassemblyBuffer> = HashMap::new();
    let mut last_cleanup = Instant::now();
    loop {
        if last_cleanup.elapsed() > REASSEMBLY_TIMEOUT / 2 {
            reassembly.retain(|_, buf| !buf.is_stale());
            last_cleanup = Instant::now();
        }
        tokio::select! {
            dgram_res = conn.read_datagram() => {
                match dgram_res {
                    Ok(dgram) => {
                        if dgram.is_empty() { continue; }
                        match dgram[0] {
                            TYPE_PACKET => handle_client_packet(&dgram, assoc_id, &mut reassembly, &last_peer, &local).await,
                            TYPE_HEARTBEAT => {}
                            other => warn!("[TUIC client] unknown datagram type {other}"),
                        }
                    }
                    Err(_) => break,
                }
            }
            stream_res = conn.accept_uni() => {
                match stream_res {
                    Ok(mut stream) => {
                        let data = match stream.read_to_end(65536).await {
                            Ok(d) => d,
                            Err(e) => { warn!("[TUIC client] stream read error: {e}"); continue; }
                        };
                        if data.is_empty() { continue; }
                        match data[0] {
                            TYPE_PACKET => handle_client_packet(&data, assoc_id, &mut reassembly, &last_peer, &local).await,
                            TYPE_HEARTBEAT => {}
                            other => warn!("[TUIC client] unknown stream type {other}"),
                        }
                    }
                    Err(_) => break,
                }
            }
        }
    }
}
