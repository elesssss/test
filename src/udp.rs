//! UDP tunnel — TUIC-like protocol over QUIC.
//!
//! Protocol:
//!   1. QUIC handshake (shared TLS certificate)
//!   2. Client opens a bidirectional stream and sends auth:
//!      version(u8)  pwd_len(u16 BE)  password([u8; pwd_len])
//!   3. Server responds:  status(u8)  (0x00 = ok)
//!   4. UDP payloads are exchanged via QUIC *datagrams*.
//!
//! Datagram wire format (v2 — supports fragmentation for payloads exceeding
//! the QUIC path MTU):
//!
//!   Common prefix (5 bytes):
//!     [session_id: u32 BE][frag_type: u8]
//!
//!   frag_type 0x00 — Single complete datagram:
//!     [session_id][0x00][payload_len: u16 BE][payload]
//!     total header = 7 bytes
//!
//!   frag_type 0x01 — First fragment of a multi-fragment message:
//!     [session_id][0x01][total_len: u16 BE][fragment_data ...]
//!     total header = 7 bytes
//!
//!   frag_type 0x02 — Middle fragment:
//!     [session_id][0x02][fragment_data ...]
//!     total header = 5 bytes
//!
//!   frag_type 0x03 — Last fragment:
//!     [session_id][0x03][fragment_data ...]
//!     total header = 5 bytes
//!
//! The server creates a dedicated UDP socket per session_id, connected to
//! the configured remote.  The client assigns a unique session_id per local
//! UDP source address so responses can be routed back correctly.

use crate::config::TunnelConfig;
use anyhow::Context;
use bytes::Bytes;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};

const PROTO_VERSION: u8 = 0x01;
const AUTH_OK: u8 = 0x00;
const AUTH_FAIL: u8 = 0x01;

/// Maximum UDP payload size (65535 - 8 byte UDP header - 20 byte IP header).
const MAX_UDP_PAYLOAD: usize = 65507;

/// Fallback max datagram size when the QUIC connection doesn't report one.
const DEFAULT_MAX_DGRAM: usize = 1200;

// ---------------------------------------------------------------------------
// Fragmentation helpers
// ---------------------------------------------------------------------------

/// The four fragment types used in the wire format.
mod frag {
    pub const SINGLE: u8 = 0x00;
    pub const FIRST: u8 = 0x01;
    pub const MIDDLE: u8 = 0x02;
    pub const LAST: u8 = 0x03;
}

/// Buffer for reassembling a fragmented message.
#[derive(Debug)]
struct ReassemblyBuf {
    total_len: usize,
    data: Vec<u8>,
}

/// Split `payload` into one or more datagram frames ready to send, keyed by
/// `session_id`.  Chooses between a single-fragment (0x00) or multi-fragment
/// (0x01 / 0x02 / 0x03) encoding depending on the path MTU.
fn build_datagrams(session_id: u32, payload: &[u8], max_dgram: usize) -> Vec<Vec<u8>> {
    let payload_len = payload.len();

    // --- try single-fragment first (7-byte header) ---
    let single_header = 7; // session_id(4) + frag_type(1) + payload_len(2)
    if payload_len + single_header <= max_dgram {
        let mut d = Vec::with_capacity(single_header + payload_len);
        d.extend_from_slice(&session_id.to_be_bytes());
        d.push(frag::SINGLE);
        d.extend_from_slice(&(payload_len as u16).to_be_bytes());
        d.extend_from_slice(payload);
        return vec![d];
    }

    // --- multi-fragment ---
    let first_header = 7; // session_id(4) + frag_type(1) + total_len(2)
    let cont_header = 5; // session_id(4) + frag_type(1)

    let mut fragments = Vec::new();
    let total = payload_len;
    let mut offset = 0;
    let mut first = true;

    while offset < total {
        let remaining = total - offset;
        let (frag_type, max_chunk) = if first {
            first = false;
            (frag::FIRST, max_dgram.saturating_sub(first_header))
        } else if remaining <= max_dgram.saturating_sub(cont_header) {
            (frag::LAST, remaining) // will fit in this fragment
        } else {
            (frag::MIDDLE, max_dgram.saturating_sub(cont_header))
        };

        let chunk = remaining.min(max_chunk);
        let mut d = Vec::with_capacity(max_dgram);
        d.extend_from_slice(&session_id.to_be_bytes());
        d.push(frag_type);
        if frag_type == frag::FIRST {
            d.extend_from_slice(&(total as u16).to_be_bytes());
        }
        d.extend_from_slice(&payload[offset..offset + chunk]);
        fragments.push(d);
        offset += chunk;
    }

    fragments
}

/// Try to feed a received datagram body (everything after the 5-byte common
/// prefix) into the reassembly buffer map.  Returns `Some(payload)` when a
/// complete message has been assembled.
fn feed_fragment(
    bufs: &mut HashMap<u32, ReassemblyBuf>,
    session_id: u32,
    frag_type: u8,
    data: &[u8],
) -> Option<Vec<u8>> {
    match frag_type {
        frag::SINGLE => {
            if data.len() < 2 {
                warn!("SINGLE fragment too short for session {session_id}");
                return None;
            }
            let payload_len = u16::from_be_bytes([data[0], data[1]]) as usize;
            let start = 2;
            let end = start + payload_len;
            if end > data.len() {
                warn!("SINGLE payload overflow for session {session_id}");
                return None;
            }
            Some(data[start..end].to_vec())
        }
        frag::FIRST => {
            if data.len() < 2 {
                warn!("FIRST fragment too short for session {session_id}");
                return None;
            }
            let total_len = u16::from_be_bytes([data[0], data[1]]) as usize;
            let frag_data = &data[2..];
            // Replace any previous incomplete buffer for this session
            let mut buf = ReassemblyBuf {
                total_len,
                data: Vec::with_capacity(total_len),
            };
            buf.data.extend_from_slice(frag_data);
            bufs.insert(session_id, buf);
            None
        }
        frag::MIDDLE | frag::LAST => {
            if let Some(buf) = bufs.get_mut(&session_id) {
                buf.data.extend_from_slice(data);
                if frag_type == frag::LAST {
                    let mut finished = bufs.remove(&session_id).unwrap();
                    // Truncate to advertised total_len just in case
                    if finished.data.len() > finished.total_len {
                        finished.data.truncate(finished.total_len);
                    }
                    return Some(finished.data);
                }
            } else {
                warn!(
                    "orphan fragment type={frag_type} for session {session_id}, discarding"
                );
            }
            None
        }
        other => {
            warn!("unknown fragment type {other} for session {session_id}");
            None
        }
    }
}

// ---------------------------------------------------------------------------
// Server mode — QUIC listener, per-session UDP sockets
// ---------------------------------------------------------------------------

type ServerSessionMap = HashMap<u32, Arc<UdpSocket>>;

pub async fn run_udp_server(config: &TunnelConfig) -> anyhow::Result<()> {
    let listen_addr: SocketAddr = config.listen_addr()?;
    let password = config.password.clone();
    let remote = config.remote.clone();

    let cert_path = config.cert.as_ref().unwrap();
    let key_path = config.key.as_ref().unwrap();
    let rustls_cfg = crate::tls::build_rustls_server_config(cert_path, key_path)?;
    let quic_cfg = crate::tls::build_quic_server_config(rustls_cfg)?;

    let endpoint = quinn::Endpoint::server(quic_cfg, listen_addr)
        .with_context(|| format!("UDP server: failed to bind QUIC on {listen_addr}"))?;
    info!("[UDP-server] listening on {listen_addr} (QUIC)");

    while let Some(incoming) = endpoint.accept().await {
        info!("UDP server: incoming QUIC connection attempt from {}", incoming.remote_address());
        let conn = match incoming.await {
            Ok(c) => {
                info!("UDP server: QUIC handshake succeeded with {}", c.remote_address());
                c
            }
            Err(e) => {
                warn!("UDP server: QUIC handshake failed: {e}");
                continue;
            }
        };
        let password = password.clone();
        let remote = remote.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_quic_server_conn(conn, &password, &remote).await {
                error!("UDP server QUIC conn: {:#}", e);
            }
        });
    }
    Ok(())
}

async fn handle_quic_server_conn(
    conn: quinn::Connection,
    password: &str,
    remote: &str,
) -> anyhow::Result<()> {
    let peer = conn.remote_address();
    info!("UDP server: new QUIC conn from {peer}");

    // ---- auth via first bidirectional stream ----
    let (mut send, mut recv) = conn
        .accept_bi()
        .await
        .context("waiting for auth stream")?;

    let version = recv.read_u8().await?;
    if version != PROTO_VERSION {
        send.write_u8(AUTH_FAIL).await?;
        let _ = send.finish();
        anyhow::bail!("unsupported version {version} from {peer}");
    }

    let pwd_len = recv.read_u16().await? as usize;
    if pwd_len > 256 {
        send.write_u8(AUTH_FAIL).await?;
        let _ = send.finish();
        anyhow::bail!("excessive password length from {peer}");
    }
    let mut pwd_buf = vec![0u8; pwd_len];
    recv.read_exact(&mut pwd_buf).await?;

    if pwd_buf != password.as_bytes() {
        send.write_u8(AUTH_FAIL).await?;
        let _ = send.finish();
        anyhow::bail!("auth failed from {peer}");
    }

    send.write_u8(AUTH_OK).await?;
    let _ = send.finish();
    info!("UDP server: auth ok from {peer}");

    // Shared state
    let sessions: Arc<Mutex<ServerSessionMap>> = Arc::new(Mutex::new(HashMap::new()));
    let reassembly: Arc<Mutex<HashMap<u32, ReassemblyBuf>>> =
        Arc::new(Mutex::new(HashMap::new()));

    let read_conn = conn.clone();
    let read_sessions = sessions.clone();
    let read_remote = remote.to_string();
    let read_reassembly = reassembly.clone();

    let reader_handle = tokio::spawn(async move {
        if let Err(e) =
            server_datagram_loop(read_conn, read_sessions, read_reassembly, &read_remote).await
        {
            error!("UDP server datagram loop: {:#}", e);
        }
    });

    let _ = conn.closed().await;
    reader_handle.abort();

    {
        let map = sessions.lock().await;
        info!(
            "UDP server: connection {peer} closed, cleaning {} sessions",
            map.len()
        );
    }
    Ok(())
}

/// Loop: read QUIC datagrams, reassemble fragments, dispatch to per-session UDP sockets.
async fn server_datagram_loop(
    conn: quinn::Connection,
    sessions: Arc<Mutex<ServerSessionMap>>,
    reassembly: Arc<Mutex<HashMap<u32, ReassemblyBuf>>>,
    remote: &str,
) -> anyhow::Result<()> {
    let max_dgram = conn
        .max_datagram_size()
        .unwrap_or(DEFAULT_MAX_DGRAM);

    loop {
        let dgram = match conn.read_datagram().await {
            Ok(d) => d,
            Err(e) => {
                debug!("UDP server datagram loop: {e}");
                return Ok(());
            }
        };

        if dgram.len() < 5 {
            warn!("UDP server: datagram too short ({} bytes)", dgram.len());
            continue;
        }

        let session_id = u32::from_be_bytes([dgram[0], dgram[1], dgram[2], dgram[3]]);
        let frag_type = dgram[4];

        // Try reassembly
        let payload = {
            let mut bufs = reassembly.lock().await;
            feed_fragment(&mut bufs, session_id, frag_type, &dgram[5..])
        };

        let payload = match payload {
            Some(p) => p,
            None => continue, // fragment buffered or malformed
        };

        // Get or create per-session UDP socket, then send
        let sock = {
            let mut map = sessions.lock().await;
            if let Some(s) = map.get(&session_id) {
                s.clone()
            } else {
                let new_sock = match UdpSocket::bind("0.0.0.0:0").await {
                    Ok(s) => s,
                    Err(e) => {
                        warn!("UDP server: failed to bind session socket: {e}");
                        continue;
                    }
                };
                if let Err(e) = new_sock.connect(remote).await {
                    warn!("UDP server: failed to connect session socket to {remote}: {e}");
                    continue;
                }
                let sock = Arc::new(new_sock);
                map.insert(session_id, sock.clone());

                debug!(
                    "UDP server: session {session_id} → {remote} (local {})",
                    sock.local_addr().unwrap()
                );

                // Spawn reader task
                let reader_conn = conn.clone();
                let reader_sessions = sessions.clone();
                let reader_sock = sock.clone();
                let sid = session_id;

                tokio::spawn(async move {
                    session_reader(reader_conn, reader_sessions, sid, reader_sock, max_dgram)
                        .await;
                });

                sock
            }
        };

        if let Err(e) = sock.send(&payload).await {
            warn!("UDP server: session {session_id} send error: {e}");
            sessions.lock().await.remove(&session_id);
        }
    }
}

/// Read responses from a per-session UDP socket, fragment them if needed,
/// and forward back as QUIC datagrams.
async fn session_reader(
    conn: quinn::Connection,
    sessions: Arc<Mutex<ServerSessionMap>>,
    session_id: u32,
    sock: Arc<UdpSocket>,
    max_dgram: usize,
) {
    let mut buf = [0u8; MAX_UDP_PAYLOAD];
    loop {
        let n = match sock.recv(&mut buf).await {
            Ok(0) => {
                debug!("session {session_id}: remote closed");
                break;
            }
            Ok(n) => n,
            Err(e) => {
                debug!("session {session_id}: recv error: {e}");
                break;
            }
        };

        let fragments = build_datagrams(session_id, &buf[..n], max_dgram);
        for d in fragments {
            if let Err(e) = conn.send_datagram(Bytes::from(d)) {
                warn!("session {session_id}: send_datagram error: {e}");
                break;
            }
        }
    }
    sessions.lock().await.remove(&session_id);
    debug!("session {session_id}: cleaned up");
}

// ---------------------------------------------------------------------------
// Client mode — local UDP socket, QUIC connection to server
// ---------------------------------------------------------------------------

struct ClientSessions {
    /// session_id → local sender address
    addr_by_id: HashMap<u32, SocketAddr>,
    /// local sender address → session_id
    id_by_addr: HashMap<SocketAddr, u32>,
    next_id: u32,
}

impl ClientSessions {
    fn new() -> Self {
        Self {
            addr_by_id: HashMap::new(),
            id_by_addr: HashMap::new(),
            next_id: 1,
        }
    }

    fn get_or_create(&mut self, addr: SocketAddr) -> u32 {
        if let Some(id) = self.id_by_addr.get(&addr) {
            return *id;
        }
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        self.id_by_addr.insert(addr, id);
        self.addr_by_id.insert(id, addr);
        id
    }

    fn get_addr(&self, session_id: u32) -> Option<SocketAddr> {
        self.addr_by_id.get(&session_id).copied()
    }
}

pub async fn run_udp_client(config: &TunnelConfig) -> anyhow::Result<()> {
    let listen_addr: SocketAddr = config.listen_addr()?;
    let remote = config.remote.clone();
    let sni = config.sni.clone();
    let password = config.password.clone();
    let insecure = config.insecure;

    // 1. Bind local UDP socket
    let local_udp = UdpSocket::bind(listen_addr)
        .await
        .with_context(|| format!("UDP client: failed to bind local UDP on {listen_addr}"))?;
    info!("[UDP-client] listening on {listen_addr} (plain UDP)");

    // 2. Build QUIC client
    let rustls_cfg = crate::tls::build_rustls_client_config(insecure);
    let quic_cfg = crate::tls::build_quic_client_config(rustls_cfg)?;

    let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().unwrap())
        .context("UDP client: failed to create QUIC endpoint")?;
    endpoint.set_default_client_config(quic_cfg);

    let remote_addr: SocketAddr = tokio::net::lookup_host(&remote)
        .await
        .with_context(|| format!("UDP client: failed to resolve {remote}"))?
        .next()
        .context("UDP client: no addresses found for remote")?;

    // 3. Connect QUIC to server (with a 10 s timeout so we don't hang silently)
    info!("UDP client: connecting QUIC to {remote_addr} (sni={sni}) ...");
    let conn = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        endpoint
            .connect(remote_addr, &sni)?
            .await
            .with_context(|| format!("QUIC connect to {remote_addr} failed"))
    })
    .await
    .with_context(|| format!("QUIC connect to {remote_addr} timed out after 10 s"))??;
    info!("UDP client: QUIC connected to {remote_addr}");

    let max_dgram = conn
        .max_datagram_size()
        .unwrap_or(DEFAULT_MAX_DGRAM);

    // 4. Authenticate
    let (mut send, mut recv) = conn
        .open_bi()
        .await
        .context("UDP client: open_bi for auth failed")?;

    send.write_u8(PROTO_VERSION).await?;
    let pwd = password.as_bytes();
    send.write_u16(pwd.len() as u16).await?;
    send.write_all(pwd).await?;
    let _ = send.finish();

    let status = recv.read_u8().await?;
    if status != AUTH_OK {
        anyhow::bail!("UDP client: auth rejected (status={status})");
    }
    info!("UDP client: auth ok");

    // 5. Session state
    let sessions = Arc::new(Mutex::new(ClientSessions::new()));
    let reassembly: Arc<Mutex<HashMap<u32, ReassemblyBuf>>> =
        Arc::new(Mutex::new(HashMap::new()));

    let local_udp_arc = Arc::new(local_udp);

    // Local UDP → QUIC
    let l2q = tokio::spawn(local_udp_to_quic(
        local_udp_arc.clone(),
        conn.clone(),
        sessions.clone(),
        max_dgram,
    ));

    // QUIC → local UDP
    let q2l = tokio::spawn(quic_to_local_udp(
        conn.clone(),
        local_udp_arc.clone(),
        sessions.clone(),
        reassembly,
    ));

    tokio::select! {
        _ = l2q => {}
        _ = q2l => {}
    }

    info!("UDP client: tunnel ended");
    Ok(())
}

async fn local_udp_to_quic(
    local_udp: Arc<UdpSocket>,
    conn: quinn::Connection,
    sessions: Arc<Mutex<ClientSessions>>,
    max_dgram: usize,
) -> anyhow::Result<()> {
    let mut buf = [0u8; MAX_UDP_PAYLOAD];
    loop {
        let (n, sender_addr) = local_udp
            .recv_from(&mut buf)
            .await
            .context("local UDP recv_from failed")?;

        let session_id = {
            let mut s = sessions.lock().await;
            s.get_or_create(sender_addr)
        };

        let fragments = build_datagrams(session_id, &buf[..n], max_dgram);
        for d in fragments {
            if let Err(e) = conn.send_datagram(Bytes::from(d)) {
                warn!("UDP client: send_datagram error: {e}");
                return Err(e.into());
            }
        }
    }
}

async fn quic_to_local_udp(
    conn: quinn::Connection,
    local_udp: Arc<UdpSocket>,
    sessions: Arc<Mutex<ClientSessions>>,
    reassembly: Arc<Mutex<HashMap<u32, ReassemblyBuf>>>,
) -> anyhow::Result<()> {
    loop {
        let dgram = match conn.read_datagram().await {
            Ok(d) => d,
            Err(e) => {
                debug!("UDP client: read_datagram: {e}");
                return Ok(());
            }
        };

        if dgram.len() < 5 {
            warn!("UDP client: datagram too short ({} bytes)", dgram.len());
            continue;
        }

        let session_id = u32::from_be_bytes([dgram[0], dgram[1], dgram[2], dgram[3]]);
        let frag_type = dgram[4];

        let payload = {
            let mut bufs = reassembly.lock().await;
            feed_fragment(&mut bufs, session_id, frag_type, &dgram[5..])
        };

        let payload = match payload {
            Some(p) => p,
            None => continue,
        };

        let target_addr = {
            let s = sessions.lock().await;
            s.get_addr(session_id)
        };

        if let Some(addr) = target_addr {
            if let Err(e) = local_udp.send_to(&payload, addr).await {
                warn!("UDP client: send_to {addr} error: {e}");
            }
        } else {
            warn!("UDP client: unknown session_id {session_id}");
        }
    }
}
