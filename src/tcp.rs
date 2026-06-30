//! TCP tunnel — AnyTLS working mechanism.
//!
//! This mirrors the *mechanisms* that define AnyTLS as a protocol (not its
//! exact wire bytes, since interop with the official anytls-go is not a
//! goal here):
//!
//!   - Auth: `sha256(password)`(32) + `padding0_len`(u16 BE) + `padding0`,
//!     sent right after the TLS handshake completes.
//!   - Session frame: `cmd`(1) `streamId`(u32 BE) `len`(u16 BE) `data`,
//!     multiplexing many proxied TCP connections ("streams") over one TLS
//!     session.
//!   - Full v1+v2 command set: cmdWaste / cmdSYN / cmdPSH / cmdFIN /
//!     cmdSettings / cmdAlert / cmdUpdatePaddingScheme / cmdSYNACK /
//!     cmdHeartRequest / cmdHeartResponse / cmdServerSettings.
//!   - Client-side idle session pool: a finished session (0 active streams)
//!     is kept around and reused for the next local connection instead of
//!     dialing a new TLS handshake every time ("复用最新、清理最老").
//!   - PaddingScheme (see `crate::padding`): the actual byte-shaping
//!     mechanism that AnyTLS exists for, mitigating "TLS-in-TLS" nested
//!     handshake fingerprinting.
//!
//! Two deliberate scope differences from upstream anytls-go, both because
//! `anyst` is a *fixed* port forwarder (the destination is set once in
//! `remote:` in the YAML), not a dynamic SOCKS-style proxy:
//!   - `cmdSYN` carries no SocksAddr — the server always dials its own
//!     configured `remote`, so there is nothing for the client to negotiate.
//!   - Like real anytls-go (see its own FAQ), only the client→server
//!     direction is padded; server→client writes are sent unpadded.

use anyhow::{anyhow, Context, Result};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex};
use tokio::task::JoinHandle;
use tokio_rustls::{TlsAcceptor, TlsConnector};

use crate::config::TunnelConfig;
use crate::padding::{self, PaddingScheme};
use crate::tls;

type TlsClientStream = tokio_rustls::client::TlsStream<TcpStream>;
type TlsServerStream = tokio_rustls::server::TlsStream<TcpStream>;

// ── Commands ────────────────────────────────────────────────────────────────

const CMD_WASTE: u8 = 0;
const CMD_SYN: u8 = 1;
const CMD_PSH: u8 = 2;
const CMD_FIN: u8 = 3;
const CMD_SETTINGS: u8 = 4;
const CMD_ALERT: u8 = 5;
const CMD_UPDATE_PADDING_SCHEME: u8 = 6;
const CMD_SYNACK: u8 = 7;
const CMD_HEART_REQUEST: u8 = 8;
const CMD_HEART_RESPONSE: u8 = 9;
const CMD_SERVER_SETTINGS: u8 = 10;

const FRAME_HEADER_LEN: usize = 1 + 4 + 2; // cmd + streamId + len

const IDLE_CHECK_INTERVAL: Duration = Duration::from_secs(30);
const IDLE_SESSION_TIMEOUT: Duration = Duration::from_secs(60);
const SYNACK_TIMEOUT: Duration = Duration::from_secs(10);
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(25);

// ── Frame encode / decode ──────────────────────────────────────────────────

fn encode_frame(cmd: u8, stream_id: u32, data: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(FRAME_HEADER_LEN + data.len());
    buf.push(cmd);
    buf.extend_from_slice(&stream_id.to_be_bytes());
    buf.extend_from_slice(&(data.len() as u16).to_be_bytes());
    buf.extend_from_slice(data);
    buf
}

async fn read_frame<R: AsyncReadExt + Unpin>(r: &mut R) -> std::io::Result<(u8, u32, Vec<u8>)> {
    let mut hdr = [0u8; FRAME_HEADER_LEN];
    r.read_exact(&mut hdr).await?;
    let cmd = hdr[0];
    let stream_id = u32::from_be_bytes([hdr[1], hdr[2], hdr[3], hdr[4]]);
    let len = u16::from_be_bytes([hdr[5], hdr[6]]) as usize;
    let mut data = vec![0u8; len];
    if len > 0 {
        r.read_exact(&mut data).await?;
    }
    Ok((cmd, stream_id, data))
}

fn sha256_password(password: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    hasher.finalize().into()
}

// ── Entry point ─────────────────────────────────────────────────────────────

pub async fn run_tcp_client(cfg: &TunnelConfig) -> Result<()> {
    let client = Arc::new(AnyTlsClient::new(cfg)?);
    client.clone().spawn_idle_janitor();

    let listener = TcpListener::bind(&cfg.listen)
        .await
        .with_context(|| format!("failed to bind TCP listen address {}", cfg.listen))?;
    tracing::info!("[anytls client] listening on {}", cfg.listen);

    loop {
        let (local, peer) = listener.accept().await?;
        let client = client.clone();
        tokio::spawn(async move {
            if let Err(e) = client.handle_local_conn(local).await {
                tracing::debug!("[anytls client] connection from {peer} ended: {e:#}");
            }
        });
    }
}

pub async fn run_tcp_server(cfg: &TunnelConfig) -> Result<()> {
    let cert = cfg.cert.as_ref().ok_or_else(|| anyhow!("server mode requires `cert`"))?;
    let key = cfg.key.as_ref().ok_or_else(|| anyhow!("server mode requires `key`"))?;

    let rustls_cfg = tls::build_rustls_server_config(cert, key)?;
    let acceptor = TlsAcceptor::from(Arc::new(rustls_cfg));

    let listener = TcpListener::bind(&cfg.listen)
        .await
        .with_context(|| format!("failed to bind TCP listen address {}", cfg.listen))?;
    tracing::info!("[anytls server] listening on {}", cfg.listen);

    let expected_auth = sha256_password(&cfg.password);
    let remote = Arc::new(cfg.remote.clone());

    loop {
        let (stream, peer) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let remote = remote.clone();

        tokio::spawn(async move {
            let tls = match acceptor.accept(stream).await {
                Ok(t) => t,
                Err(e) => {
                    tracing::debug!("[anytls server] TLS handshake with {peer} failed: {e}");
                    return;
                }
            };
            if let Err(e) = serve_session(tls, expected_auth, remote).await {
                tracing::debug!("[anytls server] session with {peer} ended: {e:#}");
            }
        });
    }
}

// ── Client: connection pool + session lifecycle ────────────────────────────

/// One open TLS session, possibly multiplexing several streams.
struct ClientSession {
    write_tx: mpsc::UnboundedSender<Vec<u8>>,
    streams: Mutex<HashMap<u32, mpsc::UnboundedSender<StreamEvent>>>,
    next_stream_id: AtomicU32,
    active_streams: AtomicU32,
    closed: AtomicBool,
    reader_handle: Mutex<Option<JoinHandle<()>>>,
    writer_handle: Mutex<Option<JoinHandle<()>>>,
}

enum StreamEvent {
    SynAck(std::result::Result<(), String>),
    Data(Vec<u8>),
    Fin,
}

impl ClientSession {
    async fn close(&self) {
        if self.closed.swap(true, Ordering::SeqCst) {
            return; // already closed
        }
        if let Some(h) = self.reader_handle.lock().await.take() {
            h.abort();
        }
        if let Some(h) = self.writer_handle.lock().await.take() {
            h.abort();
        }
    }
}

struct AnyTlsClient {
    remote: String,
    sni: String,
    password: String,
    insecure: bool,
    scheme: Arc<Mutex<PaddingScheme>>,
    idle_pool: Mutex<Vec<(Instant, Arc<ClientSession>)>>,
}

impl AnyTlsClient {
    fn new(cfg: &TunnelConfig) -> Result<Self> {
        Ok(Self {
            remote: cfg.remote.clone(),
            sni: cfg.sni.clone().unwrap_or_else(|| {
                cfg.remote.rsplit_once(':').map(|(h, _)| h.to_string()).unwrap_or_default()
            }),
            password: cfg.password.clone(),
            insecure: cfg.insecure,
            scheme: Arc::new(Mutex::new(PaddingScheme::default_scheme())),
            idle_pool: Mutex::new(Vec::new()),
        })
    }

    fn spawn_idle_janitor(self: Arc<Self>) {
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(IDLE_CHECK_INTERVAL).await;
                let mut pool = self.idle_pool.lock().await;
                let now = Instant::now();
                // Oldest entries are at the front (push happens at the back);
                // close+drop anything that has been idle too long.
                let mut keep = Vec::with_capacity(pool.len());
                for (since, session) in pool.drain(..) {
                    if now.duration_since(since) > IDLE_SESSION_TIMEOUT {
                        session.close().await;
                    } else {
                        keep.push((since, session));
                    }
                }
                *pool = keep;
            }
        });
    }

    /// Handle one local TCP connection: open a Stream (reusing an idle
    /// session if one exists), relay bytes, then return the session to the
    /// idle pool once finished.
    async fn handle_local_conn(self: &Arc<Self>, local: TcpStream) -> Result<()> {
        let (session, stream_id, rx) = self.open_stream().await?;
        run_client_stream(local, self.clone(), session, stream_id, rx).await;
        Ok(())
    }

    /// Reuse the most-recently-idled session if one is available, else dial
    /// a brand-new TLS session (sending `cmdSettings` + the first `cmdSYN`
    /// batched into a single write, matching the spec's "packet 1").
    async fn open_stream(
        self: &Arc<Self>,
    ) -> Result<(Arc<ClientSession>, u32, mpsc::UnboundedReceiver<StreamEvent>)> {
        let reused = self.idle_pool.lock().await.pop().map(|(_, s)| s);

        let (session, stream_id, rx) = if let Some(session) = reused {
            let stream_id = session.next_stream_id.fetch_add(1, Ordering::Relaxed);
            let (tx, rx) = mpsc::unbounded_channel();
            session.streams.lock().await.insert(stream_id, tx);
            session.active_streams.fetch_add(1, Ordering::Relaxed);
            // Reused session already had cmdSettings sent; just open a stream.
            let frame = encode_frame(CMD_SYN, stream_id, &[]);
            session.write_tx.send(frame).map_err(|_| anyhow!("session writer gone"))?;
            (session, stream_id, rx)
        } else {
            self.dial_new_session().await?
        };

        // Wait for cmdSYNACK before handing the stream back to the caller.
        let mut rx = rx;
        let synack = tokio::time::timeout(SYNACK_TIMEOUT, rx.recv()).await;
        match synack {
            Ok(Some(StreamEvent::SynAck(Ok(())))) => Ok((session, stream_id, rx)),
            Ok(Some(StreamEvent::SynAck(Err(msg)))) => Err(anyhow!("server rejected stream: {msg}")),
            Ok(Some(_)) | Ok(None) => Err(anyhow!("session closed before SYNACK")),
            Err(_) => Err(anyhow!("timed out waiting for SYNACK")),
        }
    }

    async fn dial_new_session(
        self: &Arc<Self>,
    ) -> Result<(Arc<ClientSession>, u32, mpsc::UnboundedReceiver<StreamEvent>)> {
        let tcp = TcpStream::connect(&self.remote)
            .await
            .with_context(|| format!("failed to connect to {}", self.remote))?;

        let rustls_cfg = tls::build_rustls_client_config(self.insecure);
        let connector = TlsConnector::from(Arc::new(rustls_cfg));
        let server_name = rustls::pki_types::ServerName::try_from(self.sni.clone())
            .map_err(|_| anyhow!("invalid SNI: {}", self.sni))?;
        let mut tls = connector.connect(server_name, tcp).await.context("TLS handshake failed")?;

        // ── Auth: sha256(password) + padding0_len + padding0 ──
        let scheme_snapshot = self.scheme.lock().await.clone();
        let auth_hash = sha256_password(&self.password);
        let pad0_len = scheme_snapshot.padding0_len();
        let mut pad0 = vec![0u8; pad0_len];
        rand::Rng::fill(&mut rand::thread_rng(), pad0.as_mut_slice());

        let mut auth_msg = Vec::with_capacity(32 + 2 + pad0_len);
        auth_msg.extend_from_slice(&auth_hash);
        auth_msg.extend_from_slice(&(pad0_len as u16).to_be_bytes());
        auth_msg.extend_from_slice(&pad0);
        tls.write_all(&auth_msg).await.context("failed to send auth")?;
        tls.flush().await?;

        let (tls_read, tls_write) = tokio::io::split(tls);

        let (write_tx, write_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let session = Arc::new(ClientSession {
            write_tx,
            streams: Mutex::new(HashMap::new()),
            next_stream_id: AtomicU32::new(1),
            active_streams: AtomicU32::new(1),
            closed: AtomicBool::new(false),
            reader_handle: Mutex::new(None),
            writer_handle: Mutex::new(None),
        });

        let writer_handle = tokio::spawn(client_writer_loop(tls_write, write_rx, self.scheme.clone()));

        let (tx, rx) = mpsc::unbounded_channel();
        let stream_id = 1u32;
        session.streams.lock().await.insert(stream_id, tx);

        let reader_handle = tokio::spawn(client_reader_loop(
            tls_read,
            session.clone(),
            self.scheme.clone(),
        ));

        *session.reader_handle.lock().await = Some(reader_handle);
        *session.writer_handle.lock().await = Some(writer_handle);

        // Packet 1: cmdSettings + the first cmdSYN, batched into one write.
        let settings_data = format!(
            "v=2\nclient=anyst/0.1.0\npadding-md5={}\n",
            scheme_snapshot.md5_hex()
        );
        let mut packet1 = encode_frame(CMD_SETTINGS, 0, settings_data.as_bytes());
        packet1.extend_from_slice(&encode_frame(CMD_SYN, stream_id, &[]));
        session
            .write_tx
            .send(packet1)
            .map_err(|_| anyhow!("session writer gone immediately after dial"))?;

        spawn_heartbeat(session.clone());

        Ok((session, stream_id, rx))
    }

    async fn release_session(&self, session: Arc<ClientSession>) {
        if session.closed.load(Ordering::SeqCst) {
            return;
        }
        let remaining = session.active_streams.load(Ordering::Relaxed);
        if remaining == 0 {
            self.idle_pool.lock().await.push((Instant::now(), session));
        }
    }
}

fn spawn_heartbeat(session: Arc<ClientSession>) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(HEARTBEAT_INTERVAL).await;
            if session.closed.load(Ordering::SeqCst) {
                break;
            }
            let frame = encode_frame(CMD_HEART_REQUEST, 0, &[]);
            if session.write_tx.send(frame).is_err() {
                break;
            }
        }
    });
}

/// Client-side writer task: the single point through which every byte sent
/// to this TLS session passes, so the PaddingScheme's per-packet counter is
/// meaningful (it counts *calls to this loop*, i.e. calls to the underlying
/// TLS write, exactly as the spec defines "packet index").
async fn client_writer_loop(
    mut tls_write: WriteHalf<TlsClientStream>,
    mut write_rx: mpsc::UnboundedReceiver<Vec<u8>>,
    scheme: Arc<Mutex<PaddingScheme>>,
) {
    let mut packet_index: u32 = 1; // packet 0 was the auth message, sent before this task started
    while let Some(data) = write_rx.recv().await {
        let scheme_snapshot = scheme.lock().await.clone();
        let chunks = padding::plan_write(&scheme_snapshot, packet_index, &data);
        let mut ok = true;
        for chunk in chunks {
            let res = match chunk {
                padding::Chunk::Real(bytes) => tls_write.write_all(bytes).await,
                padding::Chunk::Waste(n) if n >= FRAME_HEADER_LEN => {
                    let waste = encode_frame(CMD_WASTE, 0, &vec![0u8; n - FRAME_HEADER_LEN]);
                    tls_write.write_all(&waste).await
                }
                padding::Chunk::Waste(_) => Ok(()), // shortfall too small to frame; negligible
            };
            if res.is_err() {
                ok = false;
                break;
            }
        }
        if !ok || tls_write.flush().await.is_err() {
            break;
        }
        packet_index = packet_index.saturating_add(1);
    }
}

/// Client-side reader task: dispatches incoming session frames to the
/// relevant stream, or handles session-level commands directly.
async fn client_reader_loop(
    mut tls_read: ReadHalf<TlsClientStream>,
    session: Arc<ClientSession>,
    scheme: Arc<Mutex<PaddingScheme>>,
) {
    loop {
        let (cmd, stream_id, data) = match read_frame(&mut tls_read).await {
            Ok(v) => v,
            Err(_) => break,
        };
        match cmd {
            CMD_SYNACK => {
                if let Some(tx) = session.streams.lock().await.get(&stream_id) {
                    let result = if data.is_empty() {
                        Ok(())
                    } else {
                        Err(String::from_utf8_lossy(&data).to_string())
                    };
                    let _ = tx.send(StreamEvent::SynAck(result));
                }
            }
            CMD_PSH => {
                if let Some(tx) = session.streams.lock().await.get(&stream_id) {
                    let _ = tx.send(StreamEvent::Data(data));
                }
            }
            CMD_FIN => {
                if let Some(tx) = session.streams.lock().await.remove(&stream_id) {
                    let _ = tx.send(StreamEvent::Fin);
                }
            }
            CMD_ALERT => {
                tracing::warn!("[anytls client] server alert: {}", String::from_utf8_lossy(&data));
                break;
            }
            CMD_SERVER_SETTINGS => {
                tracing::debug!("[anytls client] server settings: {}", String::from_utf8_lossy(&data));
            }
            CMD_UPDATE_PADDING_SCHEME => {
                if let Ok(text) = String::from_utf8(data) {
                    match PaddingScheme::parse(&text) {
                        Ok(new_scheme) => {
                            *scheme.lock().await = new_scheme;
                            tracing::info!("[anytls client] padding scheme updated by server");
                        }
                        Err(e) => tracing::warn!("[anytls client] bad padding scheme from server: {e}"),
                    }
                }
            }
            CMD_HEART_REQUEST => {
                let _ = session.write_tx.send(encode_frame(CMD_HEART_RESPONSE, 0, &[]));
            }
            CMD_HEART_RESPONSE | CMD_WASTE => {
                // heartbeat ack / filler frame, nothing to do
            }
            _ => {}
        }
    }

    session.closed.store(true, Ordering::SeqCst);
    for (_, tx) in session.streams.lock().await.drain() {
        let _ = tx.send(StreamEvent::Fin);
    }
}

/// Bridges one local TCP connection to its Stream's events, then returns the
/// (now possibly idle) session to the client's pool.
async fn run_client_stream(
    local: TcpStream,
    client: Arc<AnyTlsClient>,
    session: Arc<ClientSession>,
    stream_id: u32,
    mut rx: mpsc::UnboundedReceiver<StreamEvent>,
) {
    let (mut local_r, mut local_w) = tokio::io::split(local);
    let write_tx = session.write_tx.clone();

    let upload = async move {
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            match local_r.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let frame = encode_frame(CMD_PSH, stream_id, &buf[..n]);
                    if write_tx.send(frame).is_err() {
                        break;
                    }
                }
            }
        }
        let _ = write_tx.send(encode_frame(CMD_FIN, stream_id, &[]));
    };

    let download = async move {
        while let Some(ev) = rx.recv().await {
            match ev {
                StreamEvent::Data(data) => {
                    if local_w.write_all(&data).await.is_err() {
                        break;
                    }
                }
                StreamEvent::Fin => break,
                StreamEvent::SynAck(_) => {}
            }
        }
        let _ = local_w.shutdown().await;
    };

    tokio::join!(upload, download);

    session.streams.lock().await.remove(&stream_id);
    session.active_streams.fetch_sub(1, Ordering::Relaxed);
    client.release_session(session).await;
}

// ── Server: session dispatch + per-stream relay ────────────────────────────

struct ServerStream {
    to_remote_tx: mpsc::UnboundedSender<ServerStreamMsg>,
}

enum ServerStreamMsg {
    Data(Vec<u8>),
    Fin,
}

/// One accepted TLS connection on the server side: validates auth, then
/// dispatches session frames until the connection closes.
async fn serve_session(tls: TlsServerStream, expected_auth: [u8; 32], remote: Arc<String>) -> Result<()> {
    let (mut tls_read, tls_write) = tokio::io::split(tls);

    // ── Auth ──
    let mut auth_hash = [0u8; 32];
    tls_read.read_exact(&mut auth_hash).await.context("failed to read auth hash")?;
    let mut pad0_len_buf = [0u8; 2];
    tls_read.read_exact(&mut pad0_len_buf).await.context("failed to read padding0 length")?;
    let pad0_len = u16::from_be_bytes(pad0_len_buf) as usize;
    let mut pad0 = vec![0u8; pad0_len];
    if pad0_len > 0 {
        tls_read.read_exact(&mut pad0).await.context("failed to read padding0")?;
    }
    if auth_hash != expected_auth {
        return Err(anyhow!("authentication failed"));
    }

    let write_tx = spawn_server_writer(tls_write);
    let streams: Arc<Mutex<HashMap<u32, ServerStream>>> = Arc::new(Mutex::new(HashMap::new()));
    let mut settings_received = false;

    loop {
        let (cmd, stream_id, data) = read_frame(&mut tls_read).await?;

        match cmd {
            CMD_SETTINGS => {
                settings_received = true;
                tracing::debug!("[anytls server] client settings: {}", String::from_utf8_lossy(&data));
                let reply = encode_frame(CMD_SERVER_SETTINGS, 0, b"v=2");
                if write_tx.send(reply).is_err() {
                    break;
                }
            }
            CMD_SYN => {
                if !settings_received {
                    let _ = write_tx.send(encode_frame(
                        CMD_ALERT,
                        0,
                        b"cmdSYN received before cmdSettings",
                    ));
                    break;
                }
                let remote = remote.clone();
                let write_tx2 = write_tx.clone();
                let streams2 = streams.clone();

                match TcpStream::connect(remote.as_str()).await {
                    Ok(target) => {
                        let (to_remote_tx, to_remote_rx) = mpsc::unbounded_channel();
                        streams2.lock().await.insert(stream_id, ServerStream { to_remote_tx });
                        let _ = write_tx2.send(encode_frame(CMD_SYNACK, stream_id, &[]));
                        tokio::spawn(run_server_stream(
                            target,
                            stream_id,
                            write_tx2,
                            to_remote_rx,
                            streams2,
                        ));
                    }
                    Err(e) => {
                        let msg = format!("failed to connect to target: {e}");
                        let _ = write_tx2.send(encode_frame(CMD_SYNACK, stream_id, msg.as_bytes()));
                    }
                }
            }
            CMD_PSH => {
                if let Some(s) = streams.lock().await.get(&stream_id) {
                    let _ = s.to_remote_tx.send(ServerStreamMsg::Data(data));
                }
            }
            CMD_FIN => {
                if let Some(s) = streams.lock().await.remove(&stream_id) {
                    let _ = s.to_remote_tx.send(ServerStreamMsg::Fin);
                }
            }
            CMD_HEART_REQUEST => {
                let _ = write_tx.send(encode_frame(CMD_HEART_RESPONSE, 0, &[]));
            }
            CMD_HEART_RESPONSE | CMD_WASTE => {}
            CMD_ALERT => {
                tracing::warn!("[anytls server] client alert: {}", String::from_utf8_lossy(&data));
                break;
            }
            _ => {}
        }
    }

    for (_, s) in streams.lock().await.drain() {
        let _ = s.to_remote_tx.send(ServerStreamMsg::Fin);
    }
    Ok(())
}

/// Server→client direction is sent unpadded, matching upstream anytls-go's
/// own current behaviour (see its FAQ: only the client→server direction is
/// padded today).
fn spawn_server_writer(mut tls_write: WriteHalf<TlsServerStream>) -> mpsc::UnboundedSender<Vec<u8>> {
    let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();
    tokio::spawn(async move {
        while let Some(frame) = rx.recv().await {
            if tls_write.write_all(&frame).await.is_err() {
                break;
            }
            if tls_write.flush().await.is_err() {
                break;
            }
        }
    });
    tx
}

async fn run_server_stream(
    target: TcpStream,
    stream_id: u32,
    write_tx: mpsc::UnboundedSender<Vec<u8>>,
    mut to_remote_rx: mpsc::UnboundedReceiver<ServerStreamMsg>,
    streams: Arc<Mutex<HashMap<u32, ServerStream>>>,
) {
    let (mut target_r, mut target_w) = tokio::io::split(target);

    let write_tx2 = write_tx.clone();
    let download = async move {
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            match target_r.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let frame = encode_frame(CMD_PSH, stream_id, &buf[..n]);
                    if write_tx2.send(frame).is_err() {
                        break;
                    }
                }
            }
        }
        let _ = write_tx2.send(encode_frame(CMD_FIN, stream_id, &[]));
    };

    let upload = async move {
        while let Some(msg) = to_remote_rx.recv().await {
            match msg {
                ServerStreamMsg::Data(data) => {
                    if target_w.write_all(&data).await.is_err() {
                        break;
                    }
                }
                ServerStreamMsg::Fin => break,
            }
        }
        let _ = target_w.shutdown().await;
    };

    tokio::join!(download, upload);
    streams.lock().await.remove(&stream_id);
}
