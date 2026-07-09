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
//!   - UUID is derived deterministically as `sha256(password)[..16]`, since
//!     this project has no separate identity/credential store — both peers
//!     compute the same value from the shared password.
//!   - Packet: `TYPE(1)=2 | ASSOC_ID(2 BE) | PKT_ID(2 BE) | FRAG_TOTAL(1) |
//!     FRAG_ID(1) | SIZE(2 BE) | ADDR | DATA`, sent as a QUIC datagram
//!     (lossy path) or unidirectional stream (lossless path). The server
//!     mirrors whichever mode the client uses, matching TUIC v5 semantics.
//!   - UDP fragmentation: oversized payloads are split into multiple Packet
//!     frames with correct FRAG_TOTAL / FRAG_ID. The server reassembles
//!     fragments before forwarding.
//!   - Dissociate: `TYPE(1)=3 | ASSOC_ID(2 BE)`, sent on a short-lived
//!     unidirectional stream when a local UDP "session" is considered done.
//!   - Heartbeat: `TYPE(1)=4`, sent periodically as a QUIC datagram to keep
//!     NAT state alive at the application layer.
//!   - True full-cone server socket: the per-ASSOC_ID UDP socket is bound
//!     but never `.connect()`-ed, so it can receive a reply from *any*
//!     source address and relay it back — matching TUIC's actual NAT
//!     traversal design, not an artificially restricted single-peer socket.
//!   - Authentication timeout: if the client does not complete
//!     authentication within the configured window the server closes the
//!     connection with error code `0xfffffff2`.
//!
//! Scope difference from upstream TUIC, mirroring the TCP/AnyTLS side: this
//! project is a *fixed* port forwarder (the destination is the tunnel's
//! configured `remote`, not chosen per-packet by the client), so the ADDR
//! field is always encoded as `None` and the server ignores it, always
//! forwarding to its own configured `remote`.

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

use crate::config::{RemotePool, TunnelConfig};
use crate::tls;

// ── TUIC v5 command types ───────────────────────────────────────────────────

const TUIC_VERSION: u8 = 5;
const TYPE_AUTHENTICATE: u8 = 0x00;
const TYPE_PACKET: u8 = 0x02;
const TYPE_DISSOCIATE: u8 = 0x03;
const TYPE_HEARTBEAT: u8 = 0x04;

// Address type tags.
const ADDR_NONE: u8 = 0xFF;

// Packet header: TYPE(1) + ASSOC_ID(2) + PKT_ID(2) + FRAG_TOTAL(1) +
// FRAG_ID(1) + SIZE(2) + ADDR(1) = 10 bytes (ADDR is always ADDR_NONE).
const PACKET_HEADER_LEN: usize = 1 + 2 + 2 + 1 + 1 + 2 + 1;

// ── Timing constants ────────────────────────────────────────────────────────

const DISSOCIATE_TIMEOUT: Duration = Duration::from_secs(60);
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(10);
const AUTH_TIMEOUT: Duration = Duration::from_secs(10);
const REASSEMBLY_TIMEOUT: Duration = Duration::from_secs(10);

// ── TUIC v5 application error codes (RFC‑style close codes) ────────────────

const ERROR_PROTOCOL: u32 = 0xfffffff0;
const ERROR_AUTHENTICATION_FAILED: u32 = 0xfffffff1;
const ERROR_AUTHENTICATION_TIMEOUT: u32 = 0xfffffff2;
const ERROR_BAD_COMMAND: u32 = 0xfffffff3;

// ── Transport ───────────────────────────────────────────────────────────────

/// Fallback datagram payload limit used when the QUIC connection hasn't
/// completed path MTU discovery yet.  Once PMTUD settles,
/// `conn.max_datagram_size()` provides the real limit, which is typically
/// large enough (~1400 B) that most TUIC packets fit in a single datagram
/// without fragmentation.
const DEFAULT_DATAGRAM_PAYLOAD: usize = 1200;

/// Queries the QUIC connection for its actual maximum datagram payload size.
/// Falls back to `DEFAULT_DATAGRAM_PAYLOAD` while PMTUD is still in flight.
fn datagram_payload_limit(conn: &Connection) -> usize {
    conn.max_datagram_size()
        .map(|max_dgram| max_dgram.saturating_sub(PACKET_HEADER_LEN))
        .unwrap_or(DEFAULT_DATAGRAM_PAYLOAD)
}

/// Maximum number of in-flight incomplete reassembly buffers per assoc.
/// When this limit is reached the oldest incomplete buffer is evicted to
/// make room — matching the defensive bound used by upstream TUIC
/// implementations.
const MAX_REASSEMBLY_BUFFERS: usize = 64;

/// The relay transport mode for TUIC Packet commands.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum RelayMode {
    /// Lossy: Packet frames sent as QUIC datagrams (native mode).
    Datagram,
    /// Lossless: Packet frames sent over unidirectional QUIC streams.
    Stream,
}

// ── Reassembly buffer ───────────────────────────────────────────────────────

/// Buffers fragments of one UDP packet (identified by `pkt_id`) while waiting
/// for all fragments to arrive.  Discarded if incomplete for longer than
/// `REASSEMBLY_TIMEOUT`.
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

    /// Insert one fragment.  Returns `true` when all fragments have been
    /// received and the buffer is ready to be assembled.
    fn insert(&mut self, frag_id: u8, payload: &[u8]) -> bool {
        if frag_id >= self.total || self.fragments[frag_id as usize].is_some() {
            // Duplicate or out-of-bounds — ignore gracefully so a replayed
            // fragment doesn't corrupt the buffer.
            return false;
        }
        self.fragments[frag_id as usize] = Some(payload.to_vec());
        self.received += 1;
        self.received == self.total
    }

    /// Concatenate all fragments in order.  Call only after `insert` returned
    /// `true`.
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

/// Derives the TUIC v5 auth token using the connection's own TLS exported
/// keying material (RFC 5705), exactly as the real spec defines: label is
/// the client's UUID, context is the raw shared password.
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

/// Build one Packet frame (possibly a fragment when `frag_total > 1`).
fn build_packet_fragment(
    assoc_id: u16,
    pkt_id: u16,
    frag_total: u8,
    frag_id: u8,
    payload: &[u8],
) -> Vec<u8> {
    let mut b = Vec::with_capacity(PACKET_HEADER_LEN + payload.len());
    b.push(TYPE_PACKET);
    b.extend_from_slice(&assoc_id.to_be_bytes());
    b.extend_from_slice(&pkt_id.to_be_bytes());
    b.push(frag_total);
    b.push(frag_id);
    b.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    b.push(ADDR_NONE);
    b.extend_from_slice(payload);
    b
}

/// Convenience: single-fragment Packet (the common case).
fn build_packet(assoc_id: u16, pkt_id: u16, payload: &[u8]) -> Vec<u8> {
    build_packet_fragment(assoc_id, pkt_id, 1, 0, payload)
}

/// Splits a payload into one or more Packet frames, fragmenting when the
/// payload exceeds `max_payload`.  Callers should derive `max_payload` from
/// `datagram_payload_limit(conn)` so that the fragmentation threshold
/// reflects the actual QUIC path MTU instead of a conservative hard‑coded
/// constant.
fn build_packet_maybe_fragmented(assoc_id: u16, pkt_id: u16, payload: &[u8], max_payload: usize) -> Vec<Vec<u8>> {
    if payload.len() <= max_payload {
        return vec![build_packet(assoc_id, pkt_id, payload)];
    }
    let frag_total =
        ((payload.len() + max_payload - 1) / max_payload) as u8;
    (0..frag_total)
        .map(|frag_id| {
            let start = frag_id as usize * max_payload;
            let end = std::cmp::min(start + max_payload, payload.len());
            build_packet_fragment(assoc_id, pkt_id, frag_total, frag_id, &payload[start..end])
        })
        .collect()
}

// ── Packet frame parsing ────────────────────────────────────────────────────

/// Parses a Packet frame from raw bytes.  Returns
/// `(assoc_id, pkt_id, frag_total, frag_id, payload_slice)` on success.
fn parse_packet(data: &[u8]) -> Option<(u16, u16, u8, u8, &[u8])> {
    if data.is_empty() || data[0] != TYPE_PACKET {
        return None;
    }
    if data.len() < PACKET_HEADER_LEN {
        return None;
    }
    let assoc_id = u16::from_be_bytes([data[1], data[2]]);
    let pkt_id = u16::from_be_bytes([data[3], data[4]]);
    let frag_total = data[5];
    let frag_id = data[6];
    let size = u16::from_be_bytes([data[7], data[8]]) as usize;
    // ADDR is fixed-length ADDR_NONE (1 byte) in this implementation.
    let payload_start = PACKET_HEADER_LEN;
    if frag_total == 0 || frag_id >= frag_total {
        return None;
    }
    if payload_start + size > data.len() {
        return None;
    }
    Some((
        assoc_id,
        pkt_id,
        frag_total,
        frag_id,
        &data[payload_start..payload_start + size],
    ))
}

// ── Other command builders ──────────────────────────────────────────────────

fn build_dissociate(assoc_id: u16) -> Vec<u8> {
    let mut b = Vec::with_capacity(3);
    b.push(TYPE_DISSOCIATE);
    b.extend_from_slice(&assoc_id.to_be_bytes());
    b
}

fn build_heartbeat() -> Vec<u8> {
    vec![TYPE_HEARTBEAT]
}

// ── Reply helper ────────────────────────────────────────────────────────────

/// Sends one Packet frame back to the client using the relay mode the client
/// originally chose.  Returns `true` on success.
async fn send_packet_reply(
    conn: &Connection,
    pkt: Vec<u8>,
    mode: RelayMode,
) -> bool {
    match mode {
        RelayMode::Datagram => {
            conn.send_datagram(Bytes::from(pkt)).is_ok()
        }
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

pub async fn run_udp_server(config: &TunnelConfig, pool: Arc<RemotePool>) -> anyhow::Result<()> {
    let cert = config.cert.as_ref().context("server mode requires `cert`")?;
    let key = config.key.as_ref().context("server mode requires `key`")?;

    let rustls_config = tls::build_rustls_server_config(cert, key)?;
    let quic_config = tls::build_quic_server_config(rustls_config)?;

    let listen_addr: SocketAddr = config.listen.parse().context("invalid `listen` address")?;
    let endpoint = quinn::Endpoint::server(quic_config, listen_addr)
        .context("failed to bind QUIC endpoint")?;

    info!("[TUIC server] listening on {listen_addr} (QUIC)");

    let expected_uuid = derive_uuid(&config.password);
    let password = Arc::new(config.password.clone());

    // JoinSet tracks per‑connection tasks so they can be aborted when the
    // endpoint exits (sing‑box pattern: closing the server cascades to
    // close all accepted QUIC connections).
    let mut tasks = tokio::task::JoinSet::new();

    loop {
        tokio::select! {
            accept = endpoint.accept() => {
                let incoming = match accept {
                    Some(inc) => inc,
                    None => break,
                };
                let password = password.clone();
                let pool = pool.clone();
                let peer = incoming.remote_address();

                tasks.spawn(async move {
                    match incoming.await {
                        Ok(conn) => {
                            if let Err(e) =
                                handle_tuic_connection(conn, expected_uuid, password, pool).await
                            {
                                error!("[TUIC server] connection from {peer}: {e:#}");
                            }
                        }
                        Err(e) => warn!("[TUIC server] QUIC handshake with {peer} failed: {e}"),
                    }
                });
            }
            // Periodically reap finished tasks.
            _ = tokio::time::sleep(Duration::from_secs(30)) => {
                while tasks.try_join_next().is_some() {}
            }
        }
    }

    // Endpoint closed — abort remaining connection tasks (sing‑box
    // cascade: h.server.Close() terminates all sessions).
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}

    Ok(())
}

/// Per‑assoc_id server‑side relay state.  The UDP socket is bound but never
/// `.connect()`‑ed, so it behaves as a true full‑cone socket: it can accept a
/// reply from any source address.
///
/// `state` bundles `mode` and `last_seen` behind a **single** `Mutex` so the
/// hot path (one read + one write per Packet) acquires only one lock instead
/// of two.
struct AssocState {
    mode: RelayMode,
    last_seen: Instant,
}

struct ServerAssoc {
    sock: Arc<UdpSocket>,
    target_addr: String,
    state: Mutex<AssocState>,
    /// Fragmented‑packet reassembly buffers, keyed by `pkt_id`.
    reassembly: Mutex<HashMap<u16, ReassemblyBuffer>>,
    /// Handle to the reply‑pump task spawned for this assoc.  Stored so the
    /// task can be explicitly aborted on Dissociate (matching upstream
    /// TUIC's cleanup behaviour).
    reply_handle: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl ServerAssoc {
    fn new(sock: Arc<UdpSocket>, target_addr: String, mode: RelayMode) -> Self {
        Self {
            sock,
            target_addr,
            state: Mutex::new(AssocState {
                mode,
                last_seen: Instant::now(),
            }),
            reassembly: Mutex::new(HashMap::new()),
            reply_handle: Mutex::new(None),
        }
    }
}

// ── Connection handler ──────────────────────────────────────────────────────

async fn handle_tuic_connection(
    conn: Connection,
    expected_uuid: [u8; 16],
    password: Arc<String>,
    pool: Arc<RemotePool>,
) -> anyhow::Result<()> {
    let peer = conn.remote_address();
    info!("[TUIC server] new QUIC connection from {peer}");

    // ── Authenticate with timeout ───────────────────────────────────────
    let auth_result = tokio::time::timeout(AUTH_TIMEOUT, async {
        let mut auth_stream = conn.accept_uni().await?;
        auth_stream
            .read_to_end(2 + 16 + 32)
            .await
            .map_err(|e| anyhow::anyhow!("read Authenticate: {e}"))
    })
    .await;

    let auth_data = match auth_result {
        Ok(Ok(data)) => data,
        Ok(Err(e)) => {
            let _ = conn.close(
                VarInt::from_u32(ERROR_AUTHENTICATION_FAILED),
                b"authentication failed",
            );
            anyhow::bail!("auth read error from {peer}: {e:#}");
        }
        Err(_elapsed) => {
            let _ = conn.close(
                VarInt::from_u32(ERROR_AUTHENTICATION_TIMEOUT),
                b"authentication timeout",
            );
            anyhow::bail!("authentication timeout from {peer}");
        }
    };

    if auth_data.len() < 2 + 16 + 32 {
        let _ = conn.close(
            VarInt::from_u32(ERROR_BAD_COMMAND),
            b"truncated Authenticate",
        );
        anyhow::bail!("truncated Authenticate from {peer}");
    }
    if auth_data[0] != TUIC_VERSION {
        let _ = conn.close(
            VarInt::from_u32(ERROR_PROTOCOL),
            b"unsupported TUIC version",
        );
        anyhow::bail!("unsupported TUIC version {} from {peer}", auth_data[0]);
    }
    if auth_data[1] != TYPE_AUTHENTICATE {
        let _ = conn.close(
            VarInt::from_u32(ERROR_BAD_COMMAND),
            b"expected Authenticate",
        );
        anyhow::bail!(
            "expected Authenticate, got type {} from {peer}",
            auth_data[1]
        );
    }

    let recv_uuid: [u8; 16] = auth_data[2..18].try_into().unwrap();
    let recv_token: [u8; 32] = auth_data[18..50].try_into().unwrap();

    let expected_token = derive_token(&conn, &recv_uuid, &password).map_err(|e| {
        let _ = conn.close(
            VarInt::from_u32(ERROR_AUTHENTICATION_FAILED),
            b"token derivation failed",
        );
        e
    })?;

    if recv_uuid != expected_uuid || recv_token != expected_token {
        let _ = conn.close(
            VarInt::from_u32(ERROR_AUTHENTICATION_FAILED),
            b"authentication failed",
        );
        anyhow::bail!("auth failed from {peer}");
    }
    info!("[TUIC server] auth ok from {peer}");

    let assocs: Arc<Mutex<HashMap<u16, Arc<ServerAssoc>>>> =
        Arc::new(Mutex::new(HashMap::new()));

    // Packet‑id counter shared across all assocs (TUIC PKT_ID is scoped by
    // ASSOC_ID, so a single counter is fine).
    let pkt_id_ctr = Arc::new(AtomicU16::new(0));

    // Background janitor: drop stale assocs and reassembly buffers.
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
                        if let Some(handle) =
                            assoc.reply_handle.lock().await.take()
                        {
                            handle.abort();
                        }
                    }
                }
            }
        })
    };

    // Run datagram and stream receivers concurrently — whichever channel the
    // client chooses for a Packet, the server handles it.  When either loop
    // exits (connection closed) the other is cancelled.
    let dgram_loop = run_datagram_loop(&conn, assocs.clone(), pool.clone(), &pkt_id_ctr);
    let stream_loop = run_stream_loop(&conn, assocs.clone(), pool.clone(), &pkt_id_ctr);

    tokio::select! {
        r = dgram_loop => {
            if let Err(e) = r {
                debug!("[TUIC server] datagram loop: {e}");
            }
        }
        r = stream_loop => {
            if let Err(e) = r {
                debug!("[TUIC server] stream loop: {e}");
            }
        }
    }

    janitor_handle.abort();
    Ok(())
}

// ── Shared command dispatch ─────────────────────────────────────────────────

/// Process one TUIC command (the payload after VER+TYPE for Authenticate, or
/// the full frame for Packet / Dissociate / Heartbeat).  Called from both the
/// datagram and stream receive loops.
///
/// `from_mode` indicates which transport channel the command arrived on; it is
/// recorded on the `ServerAssoc` when a new assoc is created so that the reply
/// pump can mirror it.
async fn dispatch_command(
    cmd_data: &[u8],
    from_mode: RelayMode,
    assocs: &Arc<Mutex<HashMap<u16, Arc<ServerAssoc>>>>,
    pool: &Arc<RemotePool>,
    conn: &Connection,
    pkt_id_ctr: &Arc<AtomicU16>,
) {
    if cmd_data.is_empty() {
        return;
    }

    match cmd_data[0] {
        TYPE_PACKET => {
            let Some((assoc_id, pkt_id, frag_total, frag_id, payload)) =
                parse_packet(cmd_data)
            else {
                warn!(
                    "[TUIC server] malformed Packet ({} bytes, mode={from_mode:?})",
                    cmd_data.len()
                );
                return;
            };

            let assoc = {
                let mut map = assocs.lock().await;
                if let Some(a) = map.get(&assoc_id) {
                    a.clone()
                } else {
                    // New assoc_id: bind a fresh, unconnected (full‑cone) socket.
                    let sock = match UdpSocket::bind("0.0.0.0:0").await {
                        Ok(s) => Arc::new(s),
                        Err(e) => {
                            warn!("[TUIC server] failed to bind assoc socket: {e}");
                            return;
                        }
                    };
                    // Pick a target for this assoc (round‑robin).
                    let target_addr = pool.pick().to_string();
                    let assoc = Arc::new(ServerAssoc::new(sock.clone(), target_addr, from_mode));

                    // Spawn the reply pump and store its handle BEFORE
                    // inserting the assoc into the shared map, so a
                    // concurrent Dissociate always sees a valid handle.
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
                                    let mode =
                                        assoc_for_pump.state.lock().await.mode;
                                    let id = pkt_id_ctr2
                                        .fetch_add(1, Ordering::Relaxed);
                                    let frames = build_packet_maybe_fragmented(
                                        assoc_id, id, &buf[..n], max_payload,
                                    );
                                    let mut ok = true;
                                    for pkt in frames {
                                        if !send_packet_reply(
                                            &conn2, pkt, mode,
                                        )
                                        .await
                                        {
                                            ok = false;
                                            break;
                                        }
                                    }
                                    if !ok {
                                        break;
                                    }
                                }
                                Err(_) => break,
                            }
                        }
                        assocs2.lock().await.remove(&assoc_id);
                    });
                    *assoc.reply_handle.lock().await = Some(reply_handle);

                    // Only now insert — the assoc is fully initialised.
                    map.insert(assoc_id, assoc.clone());

                    assoc
                }
            };

            // Single lock for both mode + last_seen (hot‑path optimisation).
            {
                let mut state = assoc.state.lock().await;
                state.mode = from_mode;
                state.last_seen = Instant::now();
            }

            // ── Reassembly ────────────────────────────────────────────
            if frag_total == 1 {
                // Fast path: single fragment, forward immediately.
                if let Err(e) = assoc.sock.send_to(payload, &assoc.target_addr).await {
                    warn!("[TUIC server] assoc {assoc_id} send to remote failed: {e}");
                }
            } else {
                let mut reassembly = assoc.reassembly.lock().await;

                // If a buffer already exists for this pkt_id but with a
                // different fragment total, the pkt_id has wrapped around
                // and the new packet replaces the old incomplete one
                // (matching sing‑quic's
                //  `if int(m.fragmentTotal) != len(item.messages)` reset).
                if let Some(existing) = reassembly.get(&pkt_id) {
                    if existing.total != frag_total {
                        reassembly.remove(&pkt_id);
                    }
                }

                // Enforce per‑assoc cap on in‑flight reassembly buffers
                // (matching upstream TUIC's defensive bound).  When at
                // capacity the oldest incomplete buffer is evicted.
                if reassembly.len() >= MAX_REASSEMBLY_BUFFERS
                    && !reassembly.contains_key(&pkt_id)
                {
                    if let Some(oldest_key) = reassembly
                        .iter()
                        .min_by_key(|(_, buf)| buf.created)
                        .map(|(k, _)| *k)
                    {
                        reassembly.remove(&oldest_key);
                        debug!(
                            "[TUIC server] evicted stale reassembly buffer pkt_id={oldest_key}"
                        );
                    }
                }
                let entry = reassembly
                    .entry(pkt_id)
                    .or_insert_with(|| ReassemblyBuffer::new(frag_total));
                if entry.insert(frag_id, payload) {
                    // All fragments received — assemble and forward.
                    let complete = reassembly
                        .remove(&pkt_id)
                        .unwrap()
                        .assemble();
                    drop(reassembly);
                    if let Err(e) = assoc.sock.send_to(&complete, &assoc.target_addr).await {
                        warn!("[TUIC server] assoc {assoc_id} send to remote failed: {e}");
                    }
                }
            }
        }

        TYPE_DISSOCIATE => {
            if cmd_data.len() >= 3 {
                let assoc_id = u16::from_be_bytes([cmd_data[1], cmd_data[2]]);
                if let Some(assoc) = assocs.lock().await.remove(&assoc_id) {
                    // Abort the reply pump so that its UDP socket is closed
                    // promptly — matching upstream TUIC's cleanup on
                    // Dissociate.
                    if let Some(handle) = assoc.reply_handle.lock().await.take() {
                        handle.abort();
                    }
                }
                // dissociate handled
            }
        }

        TYPE_HEARTBEAT => {
            // heartbeat — silent (fires every 10 s per connection)
        }

        other => {
            warn!("[TUIC server] unknown command type {other} (mode={from_mode:?})");
        }
    }
}

// ── Datagram receive loop ───────────────────────────────────────────────────

async fn run_datagram_loop(
    conn: &Connection,
    assocs: Arc<Mutex<HashMap<u16, Arc<ServerAssoc>>>>,
    pool: Arc<RemotePool>,
    pkt_id_ctr: &Arc<AtomicU16>,
) -> anyhow::Result<()> {
    loop {
        let dgram = match conn.read_datagram().await {
            Ok(d) => d,
            Err(e) => return Err(anyhow::anyhow!("read_datagram: {e}")),
        };
        dispatch_command(&dgram, RelayMode::Datagram, &assocs, &pool, conn, pkt_id_ctr)
            .await;
    }
}

// ── Unidirectional‑stream receive loop ──────────────────────────────────────

async fn run_stream_loop(
    conn: &Connection,
    assocs: Arc<Mutex<HashMap<u16, Arc<ServerAssoc>>>>,
    pool: Arc<RemotePool>,
    pkt_id_ctr: &Arc<AtomicU16>,
) -> anyhow::Result<()> {
    loop {
        let mut stream = conn.accept_uni().await?;
        // Each TUIC command arrives on its own stream.  read_to_end gathers
        // the complete frame.
        let data = match stream
            .read_to_end(65536)
            .await
            .map_err(|e| anyhow::anyhow!("stream read: {e}"))
        {
            Ok(d) => d,
            Err(e) => {
                warn!("[TUIC server] stream read error: {e}");
                continue;
            }
        };
        dispatch_command(&data, RelayMode::Stream, &assocs, &pool, conn, pkt_id_ctr)
            .await;
    }
}

// ── Client ──────────────────────────────────────────────────────────────────

pub async fn run_udp_client(config: &TunnelConfig, pool: Arc<RemotePool>) -> anyhow::Result<()> {
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

    let remote = pool.pick().to_string();
    let sni = if config.sni.is_empty() {
        remote.rsplit_once(':').map(|(h, _)| h.to_string()).unwrap_or_default()
    } else {
        config.sni.clone()
    };

    let remote_addr: SocketAddr = tokio::net::lookup_host(&remote)
        .await
        .with_context(|| format!("failed to resolve {}", remote))?
        .next()
        .ok_or_else(|| anyhow::anyhow!("no address found for {}", remote))?;

    info!("[TUIC client] connecting QUIC to {remote_addr} (sni={sni}) ...");
    let conn = match tokio::time::timeout(Duration::from_secs(10), async {
        endpoint
            .connect(remote_addr, &sni)?
            .await
            .map_err(anyhow::Error::from)
    })
    .await
    {
        Ok(Ok(c)) => c,
        Err(_) | Ok(Err(_)) => {
            pool.mark_failed(&remote);
            anyhow::bail!("QUIC connect to {} timed out", remote);
        }
    };
    info!("[TUIC client] QUIC connected to {remote_addr}");

    // ── Authenticate (unidirectional, sent and forgotten — 0‑RTT) ──────
    let uuid = derive_uuid(&config.password);
    let token = derive_token(&conn, &uuid, &config.password)?;
    {
        let mut s = conn
            .open_uni()
            .await
            .context("failed to open auth stream")?;
        s.write_all(&build_authenticate(&uuid, &token))
            .await
            .context("failed to write Authenticate")?;
        s.finish().context("failed to finish auth stream")?;
    }
    info!("[TUIC client] auth ok");

    let assoc_id: u16 = 1;
    let pkt_id_ctr = Arc::new(AtomicU16::new(0));
    let conn = Arc::new(conn);

    // Transport mode for Packet commands.  Defaults to datagram (lossy) to
    // match the most common TUIC deployment.  Switch to `RelayMode::Stream`
    // for ordered/lossless delivery.
    let relay_mode = RelayMode::Datagram;

    // Shared between the two relay directions: `local_udp_to_quic` updates
    // this every time it sees a datagram from the local client, so
    // `quic_to_local_udp` knows where to write replies back to.
    let last_peer: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));

    // Heartbeat: keep NAT/QUIC‑path state alive at the application layer
    // (always sent as QUIC datagram per TUIC v5 spec).
    let heartbeat_handle = {
        let conn2 = conn.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(HEARTBEAT_INTERVAL).await;
                if conn2
                    .send_datagram(Bytes::from(build_heartbeat()))
                    .is_err()
                {
                    break;
                }
            }
        })
    };

    let mut l2q = tokio::spawn(local_udp_to_quic(
        local.clone(),
        conn.clone(),
        assoc_id,
        pkt_id_ctr.clone(),
        last_peer.clone(),
        relay_mode,
    ));
    let mut q2l = tokio::spawn(quic_to_local_udp(
        local,
        conn.clone(),
        assoc_id,
        last_peer,
    ));

    // Whichever direction ends first brings the other one down too.
    tokio::select! {
        _ = &mut l2q => { q2l.abort(); }
        _ = &mut q2l => { l2q.abort(); }
    }
    heartbeat_handle.abort();

    // Best‑effort Dissociate on the way out.
    let mut s = conn.open_uni().await?;
    let _ = s.write_all(&build_dissociate(assoc_id)).await;
    let _ = s.finish();

    info!("[TUIC client] tunnel ended");
    Ok(())
}

/// local UDP recv → wrap as Packet(s) → send via QUIC (datagram or stream).
/// Also records the sender's address into `last_peer` so the reply path knows
/// where to write QUIC‑side responses back to.
async fn local_udp_to_quic(
    local: Arc<UdpSocket>,
    conn: Arc<Connection>,
    assoc_id: u16,
    pkt_id_ctr: Arc<AtomicU16>,
    last_peer: Arc<Mutex<Option<SocketAddr>>>,
    relay_mode: RelayMode,
) {
    // Snapshot once — stable after QUIC handshake.
    let max_payload = datagram_payload_limit(&conn);
    let mut buf = vec![0u8; 65536];
    loop {
        let (n, peer) = match local.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(_) => break,
        };
        *last_peer.lock().await = Some(peer);
        let id = pkt_id_ctr.fetch_add(1, Ordering::Relaxed);

        // Fragment oversized payloads using the runtime datagram limit.
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

/// Processes one incoming Packet command on the client side, handling
/// fragment reassembly when the server sends multi‑fragment replies.
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
        // Fast path: single fragment, forward immediately.
        let peer = *last_peer.lock().await;
        if let Some(peer) = peer {
            if let Err(e) = local.send_to(payload, peer).await {
                warn!("[TUIC client] send_to {peer} error: {e}");
            }
        }
    } else {
        // pkt_id wrap‑around guard: if the new fragment's total differs
        // from the existing buffer, reset it (matching sing‑quic).
        if let Some(existing) = reassembly.get(&pkt_id) {
            if existing.total != frag_total {
                reassembly.remove(&pkt_id);
            }
        }

        // Enforce per‑client cap on in‑flight reassembly buffers so a
        // malicious server cannot exhaust client memory by sending fragments
        // that will never complete.
        if reassembly.len() >= MAX_REASSEMBLY_BUFFERS && !reassembly.contains_key(&pkt_id) {
            if let Some(oldest_key) = reassembly
                .iter()
                .min_by_key(|(_, buf)| buf.created)
                .map(|(k, _)| *k)
            {
                reassembly.remove(&oldest_key);
            }
        }
        let entry = reassembly
            .entry(pkt_id)
            .or_insert_with(|| ReassemblyBuffer::new(frag_total));
        if entry.insert(frag_id, payload) {
            // All fragments received — assemble and forward to the local
            // UDP socket.
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

/// QUIC → local UDP: reads Packet replies from whichever channel the server
/// is using (datagram or unidirectional stream) and writes them back to the
/// most‑recently‑seen local peer.  Fragmented replies from the server are
/// reassembled before delivery.
async fn quic_to_local_udp(
    local: Arc<UdpSocket>,
    conn: Arc<Connection>,
    assoc_id: u16,
    last_peer: Arc<Mutex<Option<SocketAddr>>>,
) {
    let mut reassembly: HashMap<u16, ReassemblyBuffer> = HashMap::new();
    let mut last_cleanup = Instant::now();

    loop {
        // Periodically evict stale reassembly buffers (same timeout the
        // server uses, matching upstream TUIC).
        if last_cleanup.elapsed() > REASSEMBLY_TIMEOUT / 2 {
            reassembly.retain(|_, buf| !buf.is_stale());
            last_cleanup = Instant::now();
        }

        // Accept from either transport — the server mirrors the client's
        // mode, and Heartbeat responses always come as datagrams.
        tokio::select! {
            dgram_res = conn.read_datagram() => {
                match dgram_res {
                    Ok(dgram) => {
                        if dgram.is_empty() {
                            continue;
                        }
                        match dgram[0] {
                            TYPE_PACKET => {
                                handle_client_packet(
                                    &dgram, assoc_id, &mut reassembly,
                                    &last_peer, &local,
                                ).await;
                            }
                            TYPE_HEARTBEAT => {
                                // heartbeat ack — silent
                            }
                            other => {
                                warn!("[TUIC client] unknown datagram type {other}");
                            }
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
                            Err(e) => {
                                warn!("[TUIC client] stream read error: {e}");
                                continue;
                            }
                        };
                        if data.is_empty() {
                            continue;
                        }
                        match data[0] {
                            TYPE_PACKET => {
                                handle_client_packet(
                                    &data, assoc_id, &mut reassembly,
                                    &last_peer, &local,
                                ).await;
                            }
                            TYPE_HEARTBEAT => {
                                // heartbeat ack — silent
                            }
                            other => {
                                warn!("[TUIC client] unknown stream type {other}");
                            }
                        }
                    }
                    Err(_) => break,
                }
            }
        }
    }
}
