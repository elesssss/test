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

use crate::config::{RemotePool, TunnelConfig};
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

pub async fn run_tcp_client(cfg: &TunnelConfig, pool: Arc<RemotePool>) -> Result<()> {
    let client = Arc::new(AnyTlsClient::new(cfg, pool)?);
    client.clone().spawn_idle_janitor();

    let listener = TcpListener::bind(&cfg.listen)
        .await
        .with_context(|| format!("failed to bind TCP listen address {}", cfg.listen))?;
    tracing::info!("[anytls client] listening on {}", cfg.listen);

    // JoinSet tracks per‑connection tasks for clean shutdown (sing‑box
    // pattern: closing the listener cascades to all accepted connections).
    let mut tasks = tokio::task::JoinSet::new();

    loop {
        tokio::select! {
            accept = listener.accept() => {
                let (local, peer) = match accept {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::error!("[anytls client] accept error: {e}");
                        break;
                    }
                };
                let client = client.clone();
                tasks.spawn(async move {
                    if let Err(e) = client.handle_local_conn(local).await {
                        tracing::debug!("[anytls client] connection from {peer} ended: {e:#}");
                    }
                });
            }
            // Periodically reap finished tasks.
            _ = tokio::time::sleep(Duration::from_secs(30)) => {
                while tasks.try_join_next().is_some() {}
            }
        }
    }

    // Listener exited — abort remaining tasks then let Drop clean up the
    // idle pool and janitor.
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    Ok(())
}

pub async fn run_tcp_server(cfg: &TunnelConfig, pool: Arc<RemotePool>) -> Result<()> {
    let cert = cfg.cert.as_ref().ok_or_else(|| anyhow!("server mode requires `cert`"))?;
    let key = cfg.key.as_ref().ok_or_else(|| anyhow!("server mode requires `key`"))?;

    let rustls_cfg = tls::build_rustls_server_config(cert, key)?;
    let acceptor = TlsAcceptor::from(Arc::new(rustls_cfg));

    let listener = TcpListener::bind(&cfg.listen)
        .await
        .with_context(|| format!("failed to bind TCP listen address {}", cfg.listen))?;
    tracing::info!("[anytls server] listening on {}", cfg.listen);

    let expected_auth = sha256_password(&cfg.password);

    // JoinSet tracks all per‑session tasks so they can be aborted when the
    // listener exits (matching sing‑box: closing the listener cascades to
    // close all accepted connections).
    let mut tasks = tokio::task::JoinSet::new();

    loop {
        tokio::select! {
            accept = listener.accept() => {
                let (stream, peer) = match accept {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::error!("[anytls server] accept error: {e}");
                        break;
                    }
                };
                let acceptor = acceptor.clone();
                let pool = pool.clone();

                tasks.spawn(async move {
                    let tls = match acceptor.accept(stream).await {
                        Ok(t) => t,
                        Err(e) => {
                            tracing::debug!("[anytls server] TLS handshake with {peer} failed: {e}");
                            return;
                        }
                    };
                    if let Err(e) = serve_session(tls, expected_auth, pool).await {
                        tracing::debug!("[anytls server] session with {peer} ended: {e:#}");
                    }
                });
            }
            // Periodically reap finished tasks to avoid accumulating
            // JoinHandle allocations.
            _ = tokio::time::sleep(Duration::from_secs(30)) => {
                while tasks.try_join_next().is_some() {}
            }
        }
    }

    // Listener exited — abort all remaining session tasks then close the
    // idle pool (sing‑box cascade pattern).
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    Ok(())
}

// ── Client: connection pool + session lifecycle ────────────────────────────

/// One open TLS session, possibly multiplexing several streams.
struct ClientSession {
    write_tx: mpsc::Sender<Vec<u8>>,
    streams: Mutex<HashMap<u32, mpsc::Sender<StreamEvent>>>,
    next_stream_id: AtomicU32,
    active_streams: AtomicU32,
    closed: AtomicBool,
    reader_handle: Mutex<Option<JoinHandle<()>>>,
    writer_handle: Mutex<Option<JoinHandle<()>>>,
    /// Heartbeat task handle — aborted when the session is closed so that
    /// the task does not hold an Arc<ClientSession> clone alive for up to
    /// one extra HEARTBEAT_INTERVAL after the session has already ended.
    heartbeat_handle: Mutex<Option<JoinHandle<()>>>,
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
        if let Some(h) = self.heartbeat_handle.lock().await.take() {
            h.abort();
        }
    }
}

struct AnyTlsClient {
    remote_pool: Arc<RemotePool>,
    sni: String,
    password: String,
    insecure: bool,
    scheme: Arc<Mutex<PaddingScheme>>,
    idle_pool: Mutex<Vec<(Instant, Arc<ClientSession>)>>,
    /// Handle to the idle-session janitor.  Stored so the task can be
    /// aborted when the client is dropped (matching sing‑box's
    /// `common.Close(h.client)` cascade pattern).  Uses a sync mutex
    /// because the handle is stored from a non‑async context.
    janitor_handle: std::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl Drop for AnyTlsClient {
    fn drop(&mut self) {
        // Abort the janitor first so it doesn't race with session cleanup
        // (matching sing‑box: closing the client terminates its background
        // goroutines).
        if let Ok(mut guard) = self.janitor_handle.lock() {
            if let Some(handle) = guard.take() {
                handle.abort();
            }
        }

        // Drain and close any sessions lingering in the idle pool.
        // try_lock is used because Drop cannot block; if the lock is
        // held briefly by `release_session` the OpenSSL/TLS connections
        // will be torn down by the kernel when the process exits anyway.
        if let Ok(mut pool) = self.idle_pool.try_lock() {
            let sessions: Vec<_> = pool.drain(..).map(|(_, s)| s).collect();
            if !sessions.is_empty() {
                tokio::spawn(async move {
                    for s in sessions {
                        s.close().await;
                    }
                });
            }
        }
    }
}

impl AnyTlsClient {
    fn new(cfg: &TunnelConfig, pool: Arc<RemotePool>) -> Result<Self> {
        Ok(Self {
            remote_pool: pool.clone(),
            sni: if cfg.sni.is_empty() {
                pool.first().rsplit_once(':').map(|(h, _)| h.to_string()).unwrap_or_default()
            } else {
                cfg.sni.clone()
            },
            password: cfg.password.clone(),
            insecure: cfg.insecure,
            scheme: Arc::new(Mutex::new(PaddingScheme::default_scheme())),
            idle_pool: Mutex::new(Vec::new()),
            janitor_handle: std::sync::Mutex::new(None),
        })
    }

    fn spawn_idle_janitor(self: Arc<Self>) {
        let self2 = self.clone();
        let handle = tokio::spawn(async move {
            loop {
                tokio::time::sleep(IDLE_CHECK_INTERVAL).await;
                let mut pool = self2.idle_pool.lock().await;
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
        // Store the handle so Drop can abort the task (sing‑box pattern:
        // the Close() method terminates the background goroutine).
        if let Ok(mut guard) = self.janitor_handle.lock() {
            *guard = Some(handle);
        }
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
    ) -> Result<(Arc<ClientSession>, u32, mpsc::Receiver<StreamEvent>)> {
        let reused = self.idle_pool.lock().await.pop().map(|(_, s)| s);

        let (session, stream_id, rx) = if let Some(session) = reused {
            let stream_id = session.next_stream_id.fetch_add(1, Ordering::Relaxed);
            let (tx, rx) = mpsc::channel(256);
            session.streams.lock().await.insert(stream_id, tx);
            session.active_streams.fetch_add(1, Ordering::Relaxed);
            // Reused session already had cmdSettings sent; just open a stream.
            let frame = encode_frame(CMD_SYN, stream_id, &[]);
            if session.write_tx.send(frame).await.is_err() {
                // Writer is dead — undo the registration so the stream
                // entry and active count don't leak (this was the root
                // cause of the "Too many open files" after long uptime).
                session.streams.lock().await.remove(&stream_id);
                session.active_streams.fetch_sub(1, Ordering::Relaxed);
                return Err(anyhow!("session writer gone"));
            }
            (session, stream_id, rx)
        } else {
            self.dial_new_session().await?
        };

        // Wait for cmdSYNACK before handing the stream back to the caller.
        let mut rx = rx;
        let synack = tokio::time::timeout(SYNACK_TIMEOUT, rx.recv()).await;
        match synack {
            Ok(Some(StreamEvent::SynAck(Ok(())))) => Ok((session, stream_id, rx)),
            // Error paths: clean up the stream entry we already registered so
            // that active_streams and the streams map stay consistent.
            Ok(Some(StreamEvent::SynAck(Err(msg)))) => {
                session.streams.lock().await.remove(&stream_id);
                session.active_streams.fetch_sub(1, Ordering::Relaxed);
                Err(anyhow!("server rejected stream: {msg}"))
            }
            Ok(Some(_)) | Ok(None) => {
                session.streams.lock().await.remove(&stream_id);
                session.active_streams.fetch_sub(1, Ordering::Relaxed);
                Err(anyhow!("session closed before SYNACK"))
            }
            Err(_) => {
                session.streams.lock().await.remove(&stream_id);
                session.active_streams.fetch_sub(1, Ordering::Relaxed);
                Err(anyhow!("timed out waiting for SYNACK"))
            }
        }
    }

    async fn dial_new_session(
        self: &Arc<Self>,
    ) -> Result<(Arc<ClientSession>, u32, mpsc::Receiver<StreamEvent>)> {
        let remote = self.remote_pool.pick().to_string();
        let tcp = TcpStream::connect(&remote)
            .await
            .with_context(|| format!("failed to connect to {}", remote))?;

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

        // Bounded channel: provides backpressure so that a slow TLS writer
        // cannot cause frames to pile up in memory without limit.
        // 64 frames × up to 16 KB each = up to ~1 MB peak per session.
        let (write_tx, write_rx) = mpsc::channel::<Vec<u8>>(64);
        let session = Arc::new(ClientSession {
            write_tx,
            streams: Mutex::new(HashMap::new()),
            next_stream_id: AtomicU32::new(1),
            active_streams: AtomicU32::new(1),
            closed: AtomicBool::new(false),
            reader_handle: Mutex::new(None),
            writer_handle: Mutex::new(None),
            heartbeat_handle: Mutex::new(None),
        });

        let writer_handle = tokio::spawn(client_writer_loop(tls_write, write_rx, self.scheme.clone()));

        let (tx, rx) = mpsc::channel(256);
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
            .await
            .map_err(|_| anyhow!("session writer gone immediately after dial"))?;

        let hb_handle = spawn_heartbeat(session.clone());
        *session.heartbeat_handle.lock().await = Some(hb_handle);

        Ok((session, stream_id, rx))
    }

    async fn release_session(&self, session: Arc<ClientSession>) {
        if session.closed.load(Ordering::SeqCst) {
            return;
        }
        let remaining = session.active_streams.load(Ordering::Relaxed);
        if remaining == 0 {
            let mut pool = self.idle_pool.lock().await;
            // Cap the idle pool at 64 sessions — high enough for bursty
            // workloads without excessive FD usage (~128 FDs for TLS +
            // TCP sockets).
            if pool.len() >= 64 {
                // Evict the oldest idle session to make room.
                let evicted = pool.remove(0).1;
                drop(pool);
                evicted.close().await;
                // Push current session — re‑acquire the lock.
                self.idle_pool.lock().await.push((Instant::now(), session));
                return;
            }
            pool.push((Instant::now(), session));
        }
    }
}

fn spawn_heartbeat(session: Arc<ClientSession>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(HEARTBEAT_INTERVAL).await;
            if session.closed.load(Ordering::SeqCst) {
                break;
            }
            let frame = encode_frame(CMD_HEART_REQUEST, 0, &[]);
            if session.write_tx.send(frame).await.is_err() {
                break;
            }
        }
    })
}

/// Client-side writer task: the single point through which every byte sent
/// to this TLS session passes, so the PaddingScheme's per-packet counter is
/// meaningful (it counts *calls to this loop*, i.e. calls to the underlying
/// TLS write, exactly as the spec defines "packet index").
///
/// Once `packet_index >= stop` the scheme is never consulted again —
/// the writer enters a fast path that skips the lock+clone entirely.
/// The occasional `cmdUpdatePaddingScheme` (which only fires during the
/// early handshake) invalidates the cached `stop` so the new scheme takes
/// effect on the very next write.
async fn client_writer_loop(
    mut tls_write: WriteHalf<TlsClientStream>,
    mut write_rx: mpsc::Receiver<Vec<u8>>,
    scheme: Arc<Mutex<PaddingScheme>>,
) {
    let mut packet_index: u32 = 1; // packet 0 was auth, sent before this task
    // Cache the stop index so we can skip the lock+clone once padding ends.
    // `None` means "not cached yet" — the first write always fetches it.
    let mut cached_stop: Option<u32> = None;

    while let Some(data) = write_rx.recv().await {
        // ── Fast-path check ──────────────────────────────────────────
        // If we already know padding is over, write the data verbatim
        // (no Mutex, no clone).  This is the hot path for long‑lived
        // sessions: only the first ~8 packets go through the padded
        // branch.
        let stop = match cached_stop {
            Some(s) if packet_index >= s => {
                if tls_write.write_all(&data).await.is_err() {
                    break;
                }
                if tls_write.flush().await.is_err() {
                    break;
                }
                packet_index = packet_index.saturating_add(1);
                continue;
            }
            _ => {
                // Need the real `stop` — lock once, read the u32, drop.
                let s = scheme.lock().await.stop;
                cached_stop = Some(s);
                s
            }
        };

        // ── Padded path (only for packet_index < stop) ───────────────
        let scheme_snapshot = scheme.lock().await.clone();
        // If the server pushed an updated scheme our cached `stop` may
        // be stale — refresh it.
        if scheme_snapshot.stop != stop {
            cached_stop = Some(scheme_snapshot.stop);
        }
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
                    let _ = tx.send(StreamEvent::SynAck(result)).await;
                }
            }
            CMD_PSH => {
                if let Some(tx) = session.streams.lock().await.get(&stream_id) {
                    let _ = tx.send(StreamEvent::Data(data)).await;
                }
            }
            CMD_FIN => {
                if let Some(tx) = session.streams.lock().await.remove(&stream_id) {
                    let _ = tx.send(StreamEvent::Fin).await;
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
                let _ = session.write_tx.send(encode_frame(CMD_HEART_RESPONSE, 0, &[])).await;
            }
            CMD_HEART_RESPONSE | CMD_WASTE => {
                // heartbeat ack / filler frame, nothing to do
            }
            _ => {}
        }
    }

    session.closed.store(true, Ordering::SeqCst);
    // Collect senders first, drop the lock, then notify — avoids holding
    // the streams mutex across potentially long `.await` points (the
    // channel is now bounded so `send` may wait for the receiver to drain
    // the backlog).
    let senders: Vec<_> = session
        .streams
        .lock()
        .await
        .drain()
        .map(|(_, tx)| tx)
        .collect();
    for tx in senders {
        let _ = tx.send(StreamEvent::Fin).await;
    }
}

/// Bridges one local TCP connection to its Stream's events, then returns the
/// (now possibly idle) session to the client's pool.
async fn run_client_stream(
    local: TcpStream,
    client: Arc<AnyTlsClient>,
    session: Arc<ClientSession>,
    stream_id: u32,
    mut rx: mpsc::Receiver<StreamEvent>,
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
                    if write_tx.send(frame).await.is_err() {
                        break;
                    }
                }
            }
        }
        let _ = write_tx.send(encode_frame(CMD_FIN, stream_id, &[])).await;
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
    to_remote_tx: mpsc::Sender<ServerStreamMsg>,
}

enum ServerStreamMsg {
    Data(Vec<u8>),
    Fin,
}

/// One accepted TLS connection on the server side: validates auth, then
/// dispatches session frames until the connection closes.
async fn serve_session(tls: TlsServerStream, expected_auth: [u8; 32], pool: Arc<RemotePool>) -> Result<()> {
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
                if write_tx.send(reply).await.is_err() {
                    break;
                }
            }
            CMD_SYN => {
                if !settings_received {
                    let _ = write_tx.send(encode_frame(
                        CMD_ALERT,
                        0,
                        b"cmdSYN received before cmdSettings",
                    )).await;
                    break;
                }
                let target_addr = pool.pick().to_string();
                let write_tx2 = write_tx.clone();
                let streams2 = streams.clone();

                match TcpStream::connect(target_addr.as_str()).await {
                    Ok(target) => {
                        let (to_remote_tx, to_remote_rx) = mpsc::channel(64);
                        streams2.lock().await.insert(stream_id, ServerStream { to_remote_tx });
                        let _ = write_tx2.send(encode_frame(CMD_SYNACK, stream_id, &[])).await;
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
                        let _ = write_tx2.send(encode_frame(CMD_SYNACK, stream_id, msg.as_bytes())).await;
                    }
                }
            }
            CMD_PSH => {
                if let Some(s) = streams.lock().await.get(&stream_id) {
                    let _ = s.to_remote_tx.send(ServerStreamMsg::Data(data)).await;
                }
            }
            CMD_FIN => {
                if let Some(s) = streams.lock().await.remove(&stream_id) {
                    let _ = s.to_remote_tx.send(ServerStreamMsg::Fin).await;
                }
            }
            CMD_HEART_REQUEST => {
                let _ = write_tx.send(encode_frame(CMD_HEART_RESPONSE, 0, &[])).await;
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
        let _ = s.to_remote_tx.send(ServerStreamMsg::Fin).await;
    }
    Ok(())
}

/// Server→client direction is sent unpadded, matching upstream anytls-go's
/// own current behaviour (see its FAQ: only the client→server direction is
/// padded today).
fn spawn_server_writer(mut tls_write: WriteHalf<TlsServerStream>) -> mpsc::Sender<Vec<u8>> {
    // Bounded: prevents unbounded memory growth when TLS write is slower
    // than the rate at which frames are enqueued.
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(64);
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
    write_tx: mpsc::Sender<Vec<u8>>,
    mut to_remote_rx: mpsc::Receiver<ServerStreamMsg>,
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
                    if write_tx2.send(frame).await.is_err() {
                        break;
                    }
                }
            }
        }
        let _ = write_tx2.send(encode_frame(CMD_FIN, stream_id, &[])).await;
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
