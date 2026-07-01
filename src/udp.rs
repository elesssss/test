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
//!     (lossy path — the spec's "lossless via stream" variant is out of
//!     scope here).
//!   - Dissociate: `TYPE(1)=3 | ASSOC_ID(2 BE)`, sent on a short-lived
//!     unidirectional stream when a local UDP "session" is considered done.
//!   - Heartbeat: `TYPE(1)=4`, sent periodically as a QUIC datagram to keep
//!     NAT state alive at the application layer.
//!   - True full-cone server socket: the per-ASSOC_ID UDP socket is bound
//!     but never `.connect()`-ed, so it can receive a reply from *any*
//!     source address and relay it back — matching TUIC's actual NAT
//!     traversal design, not an artificially restricted single-peer socket.
//!
//! Scope difference from upstream TUIC, mirroring the TCP/AnyTLS side: this
//! project is a *fixed* port forwarder (the destination is the tunnel's
//! configured `remote`, not chosen per-packet by the client), so the ADDR
//! field is always encoded as `None` and the server ignores it, always
//! forwarding to its own configured `remote`.

use anyhow::Context;
use bytes::Bytes;
use quinn::Connection;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Arc;
use std::time::Duration;
// tokio::io traits not needed directly in udp.rs (quinn streams have their own API)
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

// Address type tags. TUIC's wire spec defines its own values for these; since
// interop isn't a goal here, these are anyst's own convention (both ends of
// this implementation agree, which is all that's required for mechanism
// parity rather than byte-for-byte compatibility).
const ADDR_NONE: u8 = 0xFF;

const PACKET_HEADER_LEN: usize = 1 + 2 + 2 + 1 + 1 + 2 + 1; // type+assoc+pkt+fragtot+fragid+size+addr(None)
const DISSOCIATE_TIMEOUT: Duration = Duration::from_secs(60);
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(10);

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

fn build_packet(assoc_id: u16, pkt_id: u16, payload: &[u8]) -> Vec<u8> {
    let mut b = Vec::with_capacity(PACKET_HEADER_LEN + payload.len());
    b.push(TYPE_PACKET);
    b.extend_from_slice(&assoc_id.to_be_bytes());
    b.extend_from_slice(&pkt_id.to_be_bytes());
    b.push(1); // FRAG_TOTAL — fragmentation across multiple Packet frames is out of scope
    b.push(0); // FRAG_ID
    b.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    b.push(ADDR_NONE);
    b.extend_from_slice(payload);
    b
}

/// Parses a Packet frame, returning `(assoc_id, payload_slice)`.
fn parse_packet(data: &[u8]) -> Option<(u16, &[u8])> {
    if data.is_empty() || data[0] != TYPE_PACKET {
        return None;
    }
    if data.len() < PACKET_HEADER_LEN {
        return None;
    }
    let assoc_id = u16::from_be_bytes([data[1], data[2]]);
    let size = u16::from_be_bytes([data[7], data[8]]) as usize;
    // ADDR is fixed-length ADDR_NONE (1 byte) in this implementation; a real
    // TUIC-faithful parser would branch on the ADDR type byte here.
    let payload_start = PACKET_HEADER_LEN;
    if payload_start + size > data.len() {
        return None;
    }
    Some((assoc_id, &data[payload_start..payload_start + size]))
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

// ── Server ───────────────────────────────────────────────────────────────────

pub async fn run_udp_server(config: &TunnelConfig) -> anyhow::Result<()> {
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
    let remote = Arc::new(config.remote.clone());

    while let Some(incoming) = endpoint.accept().await {
        let password = password.clone();
        let remote = remote.clone();
        let peer = incoming.remote_address();

        tokio::spawn(async move {
            match incoming.await {
                Ok(conn) => {
                    if let Err(e) = handle_tuic_connection(conn, expected_uuid, password, remote).await {
                        error!("[TUIC server] connection from {peer}: {e:#}");
                    }
                }
                Err(e) => warn!("[TUIC server] QUIC handshake with {peer} failed: {e}"),
            }
        });
    }

    Ok(())
}

/// Per-assoc_id server-side relay state. The UDP socket is bound but never
/// `.connect()`-ed, so it behaves as a true full-cone socket: it can accept
/// a reply from any source address.
struct ServerAssoc {
    sock: Arc<UdpSocket>,
    last_seen: Mutex<std::time::Instant>,
}

async fn handle_tuic_connection(
    conn: Connection,
    expected_uuid: [u8; 16],
    password: Arc<String>,
    remote: Arc<String>,
) -> anyhow::Result<()> {
    let peer = conn.remote_address();
    info!("[TUIC server] new QUIC connection from {peer}");

    // ── Authenticate, on a unidirectional stream (0-RTT: this races with
    //    any Packet/datagram traffic the client may already be sending) ──
    let mut auth_stream = conn.accept_uni().await.context("failed to accept auth stream")?;
    let auth_data = auth_stream
        .read_to_end(2 + 16 + 32)
        .await
        .context("failed to read Authenticate")?;

    if auth_data.len() < 2 + 16 + 32 {
        anyhow::bail!("truncated Authenticate from {peer}");
    }
    if auth_data[0] != TUIC_VERSION {
        anyhow::bail!("unsupported TUIC version {} from {peer}", auth_data[0]);
    }
    if auth_data[1] != TYPE_AUTHENTICATE {
        anyhow::bail!("expected Authenticate, got type {} from {peer}", auth_data[1]);
    }
    let recv_uuid: [u8; 16] = auth_data[2..18].try_into().unwrap();
    let recv_token: [u8; 32] = auth_data[18..50].try_into().unwrap();

    let expected_token = derive_token(&conn, &recv_uuid, &password)?;
    if recv_uuid != expected_uuid || recv_token != expected_token {
        anyhow::bail!("auth failed from {peer}");
    }
    info!("[TUIC server] auth ok from {peer}");

    let assocs: Arc<Mutex<HashMap<u16, Arc<ServerAssoc>>>> = Arc::new(Mutex::new(HashMap::new()));

    // Background janitor: drop any assoc that's had no traffic for a while
    // (mirrors the client's Dissociate, in case that frame is lost).
    // Its handle is captured so it can be aborted once this connection ends,
    // instead of leaking a task that loops forever for a dead connection.
    let janitor_handle = {
        let assocs = assocs.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(DISSOCIATE_TIMEOUT / 2).await;
                let mut map = assocs.lock().await;
                let mut stale = Vec::new();
                for (id, a) in map.iter() {
                    if a.last_seen.lock().await.elapsed() > DISSOCIATE_TIMEOUT {
                        stale.push(*id);
                    }
                }
                for id in stale {
                    map.remove(&id);
                }
            }
        })
    };

    // Reader for QUIC datagrams: Packet (relay) and Heartbeat.
    let result = run_datagram_loop(&conn, assocs.clone(), remote).await;
    janitor_handle.abort();

    if let Err(e) = result {
        debug!("[TUIC server] datagram loop: {e}");
    }
    Ok(())
}

async fn run_datagram_loop(
    conn: &Connection,
    assocs: Arc<Mutex<HashMap<u16, Arc<ServerAssoc>>>>,
    remote: Arc<String>,
) -> anyhow::Result<()> {
    let pkt_id_ctr = Arc::new(AtomicU16::new(0));

    loop {
        let dgram = match conn.read_datagram().await {
            Ok(d) => d,
            Err(e) => return Err(anyhow::anyhow!("read_datagram: {e}")),
        };
        if dgram.is_empty() {
            continue;
        }
        match dgram[0] {
            TYPE_PACKET => {
                let Some((assoc_id, payload)) = parse_packet(&dgram) else {
                    warn!("[TUIC server] malformed Packet ({} bytes)", dgram.len());
                    continue;
                };

                let assoc = {
                    let mut map = assocs.lock().await;
                    if let Some(a) = map.get(&assoc_id) {
                        a.clone()
                    } else {
                        // New assoc_id: bind a fresh, unconnected (full-cone) socket.
                        let sock = match UdpSocket::bind("0.0.0.0:0").await {
                            Ok(s) => Arc::new(s),
                            Err(e) => {
                                warn!("[TUIC server] failed to bind assoc socket: {e}");
                                continue;
                            }
                        };
                        let assoc = Arc::new(ServerAssoc {
                            sock: sock.clone(),
                            last_seen: Mutex::new(std::time::Instant::now()),
                        });
                        map.insert(assoc_id, assoc.clone());

                        // Spawn the reply pump for this assoc: any source that
                        // replies on `sock` gets relayed back to the client,
                        // tagged with this assoc_id (true full-cone behaviour).
                        let conn2 = conn.clone();
                        let pkt_id_ctr2 = pkt_id_ctr.clone();
                        let assocs2 = assocs.clone();
                        tokio::spawn(async move {
                            let mut buf = vec![0u8; 65536];
                            loop {
                                match sock.recv_from(&mut buf).await {
                                    Ok((n, _from)) => {
                                        let id = pkt_id_ctr2.fetch_add(1, Ordering::Relaxed);
                                        let pkt = build_packet(assoc_id, id, &buf[..n]);
                                        if conn2.send_datagram(Bytes::from(pkt)).is_err() {
                                            break;
                                        }
                                    }
                                    Err(_) => break,
                                }
                            }
                            assocs2.lock().await.remove(&assoc_id);
                        });

                        assoc
                    }
                };

                *assoc.last_seen.lock().await = std::time::Instant::now();
                if let Err(e) = assoc.sock.send_to(payload, remote.as_str()).await {
                    warn!("[TUIC server] assoc {assoc_id} send to remote failed: {e}");
                }
            }
            TYPE_DISSOCIATE => {
                if dgram.len() >= 3 {
                    let assoc_id = u16::from_be_bytes([dgram[1], dgram[2]]);
                    assocs.lock().await.remove(&assoc_id);
                    debug!("[TUIC server] dissociate {assoc_id}");
                }
            }
            TYPE_HEARTBEAT => {
                debug!("[TUIC server] heartbeat from {}", conn.remote_address());
            }
            other => {
                warn!("[TUIC server] unknown datagram type {other}");
            }
        }
    }
}

// ── Client ───────────────────────────────────────────────────────────────────

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
        config.remote.rsplit_once(':').map(|(h, _)| h.to_string()).unwrap_or_default()
    } else {
        config.sni.clone()
    };

    let remote_addr: SocketAddr = tokio::net::lookup_host(&config.remote)
        .await
        .with_context(|| format!("failed to resolve {}", config.remote))?
        .next()
        .ok_or_else(|| anyhow::anyhow!("no address found for {}", config.remote))?;

    info!("[TUIC client] connecting QUIC to {remote_addr} (sni={sni}) ...");
    let conn = tokio::time::timeout(Duration::from_secs(10), async {
        endpoint.connect(remote_addr, &sni)?.await.map_err(anyhow::Error::from)
    })
    .await
    .context("QUIC connect timed out")??;
    info!("[TUIC client] QUIC connected to {remote_addr}");

    // ── Authenticate (unidirectional, sent and forgotten — 0-RTT) ──
    let uuid = derive_uuid(&config.password);
    let token = derive_token(&conn, &uuid, &config.password)?;
    {
        let mut s = conn.open_uni().await.context("failed to open auth stream")?;
        s.write_all(&build_authenticate(&uuid, &token))
            .await
            .context("failed to write Authenticate")?;
        s.finish().context("failed to finish auth stream")?;
    }
    info!("[TUIC client] auth ok");

    let assoc_id: u16 = 1;
    let pkt_id_ctr = Arc::new(AtomicU16::new(0));
    let conn = Arc::new(conn);
    // Shared between the two relay directions: `local_udp_to_quic` updates
    // this every time it sees a datagram from the local client, and
    // `quic_to_local_udp` reads it to know where to write replies back to.
    let last_peer: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));

    // Heartbeat: keep NAT/QUIC-path state alive at the application layer.
    // Handle is saved so the task is aborted immediately when the tunnel
    // ends, instead of holding the conn Arc alive for one extra interval.
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
        local.clone(),
        conn.clone(),
        assoc_id,
        pkt_id_ctr,
        last_peer.clone(),
    ));
    let mut q2l = tokio::spawn(quic_to_local_udp(local, conn.clone(), assoc_id, last_peer));

    // Whichever direction ends first (local socket error, or QUIC connection
    // closing) brings the other one down too, instead of leaving it running
    // orphaned in the background.
    tokio::select! {
        _ = &mut l2q => { q2l.abort(); }
        _ = &mut q2l => { l2q.abort(); }
    }
    heartbeat_handle.abort();

    // Best-effort Dissociate on the way out.
    let mut s = conn.open_uni().await?;
    let _ = s.write_all(&build_dissociate(assoc_id)).await;
    let _ = s.finish();

    info!("[TUIC client] tunnel ended");
    Ok(())
}

/// local UDP recv → wrap as Packet → QUIC datagram. Also records the
/// sender's address into `last_peer` so the reply path knows where to write
/// QUIC-side responses back to.
async fn local_udp_to_quic(
    local: Arc<UdpSocket>,
    conn: Arc<Connection>,
    assoc_id: u16,
    pkt_id_ctr: Arc<AtomicU16>,
    last_peer: Arc<Mutex<Option<SocketAddr>>>,
) {
    let mut buf = vec![0u8; 65536];
    loop {
        let (n, peer) = match local.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(_) => break,
        };
        *last_peer.lock().await = Some(peer);
        let id = pkt_id_ctr.fetch_add(1, Ordering::Relaxed);
        let pkt = build_packet(assoc_id, id, &buf[..n]);
        if let Err(e) = conn.send_datagram(Bytes::from(pkt)) {
            warn!("[TUIC client] send_datagram error: {e}");
        }
    }
}

/// QUIC datagram (Packet replies) → write back to whichever local peer most
/// recently sent us something, tracked via `last_peer` (shared with
/// `local_udp_to_quic`). A single local listening port maps to one
/// assoc_id in this implementation, matching the tunnel's "fixed forwarder"
/// design — multiple simultaneous distinct local senders are not
/// distinguished from one another.
async fn quic_to_local_udp(
    local: Arc<UdpSocket>,
    conn: Arc<Connection>,
    assoc_id: u16,
    last_peer: Arc<Mutex<Option<SocketAddr>>>,
) {
    loop {
        let dgram = match conn.read_datagram().await {
            Ok(d) => d,
            Err(_) => break,
        };
        if dgram.is_empty() {
            continue;
        }
        match dgram[0] {
            TYPE_PACKET => {
                let Some((recv_assoc, payload)) = parse_packet(&dgram) else {
                    warn!("[TUIC client] malformed Packet ({} bytes)", dgram.len());
                    continue;
                };
                if recv_assoc != assoc_id {
                    continue;
                }
                let peer = *last_peer.lock().await;
                if let Some(peer) = peer {
                    if let Err(e) = local.send_to(payload, peer).await {
                        warn!("[TUIC client] send_to {peer} error: {e}");
                    }
                }
            }
            TYPE_HEARTBEAT => {
                debug!("[TUIC client] heartbeat ack");
            }
            other => {
                warn!("[TUIC client] unknown datagram type {other}");
            }
        }
    }
}
