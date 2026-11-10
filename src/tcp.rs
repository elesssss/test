//! Fixed-destination TLS TCP relay using AnyTLS-style framing.
//! This is not wire-compatible with the official AnyTLS implementation.
//! FIN denotes a write-half close; both directions finish independently.

use anyhow::{anyhow, Context, Result};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex as SyncMutex, Weak};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch, Mutex, OwnedSemaphorePermit};
use tokio::task::JoinSet;
use tokio_rustls::{TlsAcceptor, TlsConnector};

use crate::config::TunnelConfig;
use crate::padding::{self, PaddingScheme};
use crate::runtime::{self, Resources, Shutdown, Task, IO_TIMEOUT, MAX_SESSIONS, MAX_STREAMS};
use crate::tls;

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
const FRAME_HEADER_LEN: usize = 7;
const QUEUE_CAPACITY: usize = 32;
const IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(25);
const MAX_IDLE_SESSIONS: usize = 32;

type Frame = (u8, u32, Vec<u8>);
type ClientStreams = Arc<Mutex<HashMap<u32, mpsc::Sender<StreamEvent>>>>;

fn encode_frame(cmd: u8, stream_id: u32, data: &[u8]) -> Vec<u8> {
    // All callers either read <=16 KiB, use validated padding sizes or short
    // control payloads. Never silently truncate a length in the wire header.
    let len = u16::try_from(data.len()).expect("frame payload exceeds u16");
    let mut buf = Vec::with_capacity(FRAME_HEADER_LEN + data.len());
    buf.push(cmd);
    buf.extend_from_slice(&stream_id.to_be_bytes());
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(data);
    buf
}

async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R) -> std::io::Result<Frame> {
    let mut header = [0; FRAME_HEADER_LEN];
    reader.read_exact(&mut header).await?;
    let id = u32::from_be_bytes([header[1], header[2], header[3], header[4]]);
    let len = u16::from_be_bytes([header[5], header[6]]) as usize;
    let mut data = vec![0; len];
    reader.read_exact(&mut data).await?;
    Ok((header[0], id, data))
}

fn sha256_password(password: &str) -> [u8; 32] {
    Sha256::digest(password.as_bytes()).into()
}

async fn send_frame(tx: &mpsc::Sender<Vec<u8>>, frame: Vec<u8>) -> Result<()> {
    tokio::time::timeout(IO_TIMEOUT, tx.send(frame))
        .await.context("session queue timed out")?
        .map_err(|_| anyhow!("session writer closed"))
}

async fn connect_target(remote: &str) -> Result<TcpStream> {
    let addresses = runtime::resolve(remote).await?;
    let mut error = anyhow!("no reachable backend address");
    for address in addresses {
        match tokio::time::timeout(IO_TIMEOUT, TcpStream::connect(address)).await {
            Ok(Ok(stream)) => return Ok(stream),
            Ok(Err(e)) => error = e.into(),
            Err(_) => error = anyhow!("TCP connect timed out"),
        }
    }
    Err(error)
}

pub async fn run_tcp_client(
    cfg: &TunnelConfig,
    resources: Resources,
    shutdown: Shutdown,
) -> Result<()> {
    let _listener_permit = resources.socket()?;
    let listener = TcpListener::bind(&cfg.listen).await.context("bind TCP listener")?;
    let client = Arc::new(AnyTlsClient::new(cfg, resources)?);
    let mut janitor = client.spawn_idle_janitor();
    let mut tasks = JoinSet::new();
    tracing::info!("[anytls client] listening on {}", cfg.listen);
    let outcome = loop {
        // Avoid transient completed JoinSet entries making a long-lived
        // process appear full during a burst of short connections.
        while let Some(result) = tasks.try_join_next() {
            if let Err(e) = result { tracing::warn!("TCP task failed: {e}"); }
        }
        tokio::select! {
            _ = shutdown.cancelled() => break Ok(()),
            result = tasks.join_next(), if !tasks.is_empty() => {
                if let Some(Err(e)) = result {
                    tracing::warn!("[anytls client] relay task failed: {e}");
                }
            }
            accepted = listener.accept() => {
                let (local, peer) = match accepted {
                    Ok(pair) => pair,
                    Err(e) => break Err(e.into()),
                };
                if tasks.len() >= MAX_SESSIONS {
                    drop(local);
                    continue;
                }
                let permit = match client.resources.socket() {
                    Ok(permit) => permit,
                    Err(_) => { drop(local); continue; }
                };
                let client = client.clone();
                tasks.spawn(async move {
                    let _permit = permit;
                    if let Err(e) = client.handle_local_conn(local).await {
                        tracing::debug!("[anytls client] {peer}: {e:#}");
                    }
                });
            }
        }
    };
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    janitor.stop().await;
    client.shutdown().await;
    outcome
}

pub async fn run_tcp_server(
    cfg: &TunnelConfig,
    resources: Resources,
    shutdown: Shutdown,
) -> Result<()> {
    let cert = cfg.cert.as_deref().context("server requires cert")?;
    let key = cfg.key.as_deref().context("server requires key")?;
    let acceptor = TlsAcceptor::from(Arc::new(tls::build_rustls_server_config(cert, key)?));
    let _listener_permit = resources.socket()?;
    let listener = TcpListener::bind(&cfg.listen).await.context("bind TCP listener")?;
    let auth_map = Arc::new(cfg.remotes_list()?.into_iter()
        .map(|r| (sha256_password(&r.password), r.addr)).collect::<HashMap<_, _>>());
    let mut tasks = JoinSet::new();
    tracing::info!("[anytls server] listening on {}", cfg.listen);
    let outcome = loop {
        // Avoid transient completed JoinSet entries making a long-lived
        // process appear full during a burst of short connections.
        while let Some(result) = tasks.try_join_next() {
            if let Err(e) = result { tracing::warn!("TCP task failed: {e}"); }
        }
        tokio::select! {
            _ = shutdown.cancelled() => break Ok(()),
            result = tasks.join_next(), if !tasks.is_empty() => {
                if let Some(Err(e)) = result {
                    tracing::warn!("[anytls server] session task failed: {e}");
                }
            }
            accepted = listener.accept() => {
                let (stream, peer) = match accepted {
                    Ok(pair) => pair,
                    Err(e) => break Err(e.into()),
                };
                if tasks.len() >= MAX_SESSIONS {
                    drop(stream);
                    continue;
                }
                let permit = match resources.socket() {
                    Ok(permit) => permit,
                    Err(_) => { drop(stream); continue; }
                };
                let acceptor = acceptor.clone();
                let auth_map = auth_map.clone();
                let resources = resources.clone();
                tasks.spawn(async move {
                    let _permit = permit;
                    let result = async {
                        let tls = tokio::time::timeout(IO_TIMEOUT, acceptor.accept(stream))
                            .await.context("TLS handshake timed out")??;
                        serve_session(tls, auth_map, resources).await
                    }.await;
                    if let Err(e) = result {
                        tracing::debug!("[anytls server] {peer}: {e:#}");
                    }
                });
            }
        }
    };
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    outcome
}

struct ClientSession {
    write_tx: mpsc::Sender<Vec<u8>>,
    streams: ClientStreams,
    next_stream_id: AtomicU32,
    shutdown: Shutdown,
    tasks: SyncMutex<Vec<Task<()>>>,
    _permit: OwnedSemaphorePermit,
}

impl ClientSession {
    fn close(&self) {
        // Cancellation and task cleanup are independent, idempotent actions.
        self.shutdown.cancel();
        if let Ok(mut tasks) = self.tasks.lock() {
            tasks.clear();
        }
    }
}

impl Drop for ClientSession {
    fn drop(&mut self) {
        self.close();
    }
}

/// Any error/cancellation before a session returns to the pool closes it.
struct SessionLease {
    session: Arc<ClientSession>,
    reusable: bool,
}

impl Drop for SessionLease {
    fn drop(&mut self) {
        if !self.reusable {
            self.session.close();
        }
    }
}

enum StreamEvent {
    SynAck(std::result::Result<(), String>),
    Data(Vec<u8>),
    Fin,
}

struct AnyTlsClient {
    remote: String,
    sni: String,
    password: String,
    connector: TlsConnector,
    scheme: watch::Sender<Arc<PaddingScheme>>,
    idle_pool: Mutex<Vec<(Instant, Arc<ClientSession>)>>,
    resources: Resources,
}

impl AnyTlsClient {
    fn new(cfg: &TunnelConfig, resources: Resources) -> Result<Self> {
        let (scheme, _) = watch::channel(Arc::new(PaddingScheme::default_scheme()));
        Ok(Self {
            remote: cfg.default_remote()?,
            sni: cfg.server_name()?,
            password: cfg.default_password()?,
            connector: TlsConnector::from(Arc::new(tls::build_rustls_client_config(cfg.insecure)?)),
            scheme,
            idle_pool: Mutex::new(Vec::new()),
            resources,
        })
    }

    fn spawn_idle_janitor(self: &Arc<Self>) -> Task<()> {
        let weak: Weak<Self> = Arc::downgrade(self);
        Task::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(15));
            loop {
                interval.tick().await;
                let Some(client) = weak.upgrade() else { break };
                let mut pool = client.idle_pool.lock().await;
                pool.retain(|(since, session)| {
                    if since.elapsed() >= IDLE_TIMEOUT || session.shutdown.is_cancelled() {
                        session.close();
                        false
                    } else { true }
                });
                // Neither the lock nor a strong client reference spans tick().
            }
        })
    }

    async fn shutdown(&self) {
        let sessions: Vec<_> = self.idle_pool.lock().await.drain(..)
            .map(|(_, session)| session).collect();
        for session in sessions { session.close(); }
    }

    async fn open_stream(&self) -> Result<(SessionLease, u32, mpsc::Receiver<StreamEvent>)> {
        let session = loop {
            let cached = self.idle_pool.lock().await.pop();
            match cached {
                Some((since, session)) if since.elapsed() < IDLE_TIMEOUT
                    && !session.shutdown.is_cancelled() => break session,
                Some((_, session)) => session.close(),
                None => break self.dial_new_session().await?,
            }
        };
        let lease = SessionLease { session, reusable: false };
        let id = lease.session.next_stream_id.fetch_update(
            Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1),
        ).map_err(|_| anyhow!("stream ID space exhausted"))?;
        let (tx, mut rx) = mpsc::channel(QUEUE_CAPACITY);
        lease.session.streams.lock().await.insert(id, tx);
        let mut opening = Vec::new();
        if id == 1 {
            let snapshot = self.scheme.borrow().clone();
            let settings = format!("v=2\nclient=anyst/{}\npadding-md5={}\n",
                env!("CARGO_PKG_VERSION"), snapshot.md5_hex());
            opening.extend_from_slice(&encode_frame(CMD_SETTINGS, 0, settings.as_bytes()));
        }
        opening.extend_from_slice(&encode_frame(CMD_SYN, id, &[]));
        send_frame(&lease.session.write_tx, opening).await?;
        let ack = tokio::select! {
            _ = lease.session.shutdown.cancelled() => return Err(anyhow!("session closed")),
            result = tokio::time::timeout(IO_TIMEOUT + IO_TIMEOUT, rx.recv()) => result?,
        };
        match ack {
            Some(StreamEvent::SynAck(Ok(()))) => Ok((lease, id, rx)),
            Some(StreamEvent::SynAck(Err(msg))) => Err(anyhow!("stream rejected: {msg}")),
            _ => Err(anyhow!("session ended before SYNACK")),
        }
    }

    async fn dial_new_session(&self) -> Result<Arc<ClientSession>> {
        let permit = self.resources.socket()?;
        let tcp = connect_target(&self.remote).await?;
        let name = rustls::pki_types::ServerName::try_from(self.sni.clone())?;
        let mut tls = tokio::time::timeout(IO_TIMEOUT, self.connector.connect(name, tcp))
            .await.context("TLS handshake timed out")??;
        let scheme = self.scheme.borrow().clone();
        let pad_len = scheme.padding0_len();
        let mut auth = Vec::with_capacity(34 + pad_len);
        auth.extend_from_slice(&sha256_password(&self.password));
        auth.extend_from_slice(&(pad_len as u16).to_be_bytes());
        let mut pad = vec![0; pad_len];
        rand::Rng::fill(&mut rand::thread_rng(), pad.as_mut_slice());
        auth.extend_from_slice(&pad);
        tokio::time::timeout(IO_TIMEOUT, async {
            tls.write_all(&auth).await?;
            tls.flush().await
        }).await.context("auth write timed out")??;
        let (reader, writer) = tokio::io::split(tls);
        let (write_tx, write_rx) = mpsc::channel(QUEUE_CAPACITY);
        let streams = Arc::new(Mutex::new(HashMap::new()));
        let shutdown = Shutdown::new();
        let session = Arc::new(ClientSession {
            write_tx,
            streams: streams.clone(),
            // The first allocated ID is 1; no separate, duplicate allocation.
            next_stream_id: AtomicU32::new(1),
            shutdown: shutdown.clone(),
            tasks: SyncMutex::new(Vec::new()),
            _permit: permit,
        });
        let writer_shutdown = shutdown.clone();
        let scheme_rx = self.scheme.subscribe();
        let writer_task = Task::spawn(async move {
            client_writer_loop(writer, write_rx, scheme_rx, &writer_shutdown).await;
            writer_shutdown.cancel();
        });
        let reader_shutdown = shutdown.clone();
        let writer_tx = session.write_tx.clone();
        let scheme_tx = self.scheme.clone();
        let reader_task = Task::spawn(async move {
            client_reader_loop(reader, streams, writer_tx, scheme_tx, &reader_shutdown).await;
            reader_shutdown.cancel();
        });
        let heartbeat_tx = session.write_tx.clone();
        let heartbeat_shutdown = shutdown;
        let heartbeat_task = Task::spawn(async move {
            let mut interval = tokio::time::interval(HEARTBEAT_INTERVAL);
            interval.tick().await;
            loop {
                tokio::select! {
                    _ = heartbeat_shutdown.cancelled() => break,
                    _ = interval.tick() => {
                        if send_frame(&heartbeat_tx, encode_frame(CMD_HEART_REQUEST, 0, &[])).await.is_err() {
                            heartbeat_shutdown.cancel();
                            break;
                        }
                    }
                }
            }
        });
        // Registration spans no await; the guard cannot make this future
        // non-Send or survive into the network relay.
        {
            let mut registry = session.tasks.lock().map_err(|_| anyhow!("task registry poisoned"))?;
            registry.extend([writer_task, reader_task, heartbeat_task]);
        }
        Ok(session)
    }

    async fn handle_local_conn(&self, local: TcpStream) -> Result<()> {
        let (mut lease, id, mut rx) = self.open_stream().await?;
        let session = &lease.session;
        let (mut local_r, mut local_w) = local.into_split();
        let upload = async {
            let mut buf = vec![0; 16 * 1024];
            loop {
                let n = local_r.read(&mut buf).await?;
                if n == 0 { break; }
                send_frame(&session.write_tx, encode_frame(CMD_PSH, id, &buf[..n])).await?;
            }
            send_frame(&session.write_tx, encode_frame(CMD_FIN, id, &[])).await
        };
        let download = async {
            while let Some(event) = rx.recv().await {
                match event {
                    StreamEvent::Data(data) => {
                        tokio::time::timeout(IO_TIMEOUT, local_w.write_all(&data)).await??;
                    }
                    StreamEvent::Fin => {
                        local_w.shutdown().await?;
                        return Ok(());
                    }
                    StreamEvent::SynAck(_) => return Err(anyhow!("unexpected SYNACK")),
                }
            }
            Err(anyhow!("session reader closed"))
        };
        let result = tokio::select! {
            biased;
            // Drain already-decoded PSH/FIN before reacting to a TLS EOF
            // observed by the reader immediately after those frames.
            result = runtime::relay_halves(upload, download) => result,
            _ = session.shutdown.cancelled() => Err(anyhow!("session closed")),
        };
        session.streams.lock().await.remove(&id);
        result?;
        if !session.shutdown.is_cancelled() {
            // Eviction and insertion are atomic under this lock.
            let mut pool = self.idle_pool.lock().await;
            if pool.len() >= MAX_IDLE_SESSIONS {
                pool.remove(0).1.close();
            }
            pool.push((Instant::now(), session.clone()));
            lease.reusable = true;
        }
        Ok(())
    }
}

async fn client_writer_loop<W: AsyncWrite + Unpin>(
    mut writer: W,
    mut rx: mpsc::Receiver<Vec<u8>>,
    mut scheme: watch::Receiver<Arc<PaddingScheme>>,
    shutdown: &Shutdown,
) {
    let mut index = 1u32; // Authentication is packet 0.
    loop {
        let data = tokio::select! {
            _ = shutdown.cancelled() => break,
            frame = rx.recv() => match frame { Some(frame) => frame, None => break },
        };
        // borrow_and_update is cheap and observes changes even after stop.
        let snapshot = scheme.borrow_and_update().clone();
        let packets = if index >= snapshot.stop || !snapshot.rules.contains_key(&index) {
            vec![data] // No clone/allocation of the payload after padding stops.
        } else {
            padding::plan_write(&snapshot, index, &data)
        };
        let write = async {
            for packet in packets {
                // Real data and its waste frame share one TLS write rather
                // than producing two unrelated record-size patterns.
                writer.write_all(&packet).await?;
                writer.flush().await?;
            }
            std::io::Result::Ok(())
        };
        tokio::select! {
            _ = shutdown.cancelled() => break,
            result = tokio::time::timeout(IO_TIMEOUT, write) => {
                if !matches!(result, Ok(Ok(()))) { break; }
            }
        }
        index = index.saturating_add(1);
    }
}

async fn client_reader_loop<R: AsyncRead + Unpin>(
    mut reader: R,
    streams: ClientStreams,
    write_tx: mpsc::Sender<Vec<u8>>,
    scheme: watch::Sender<Arc<PaddingScheme>>,
    shutdown: &Shutdown,
) {
    loop {
        // Cancellation here terminates the session; a partially read frame
        // is never discarded and then retried on the same TLS stream.
        let frame = tokio::select! {
            _ = shutdown.cancelled() => break,
            result = read_frame(&mut reader) => match result { Ok(frame) => frame, Err(_) => break },
        };
        let (cmd, id, data) = frame;
        if cmd == CMD_PSH && data.len() > 16 * 1024 { break; }
        let event = match cmd {
            CMD_SYNACK => Some(StreamEvent::SynAck(if data.is_empty() { Ok(()) }
                else { Err(String::from_utf8_lossy(&data).into_owned()) })),
            CMD_PSH => Some(StreamEvent::Data(data)),
            CMD_FIN if data.is_empty() => Some(StreamEvent::Fin),
            CMD_ALERT => break,
            CMD_UPDATE_PADDING_SCHEME => {
                match std::str::from_utf8(&data).ok().and_then(|s| PaddingScheme::parse(s).ok()) {
                    Some(new_scheme) => { scheme.send_replace(Arc::new(new_scheme)); }
                    None => { tracing::warn!("[anytls client] invalid padding scheme"); break; }
                }
                None
            }
            CMD_HEART_REQUEST => {
                if send_frame(&write_tx, encode_frame(CMD_HEART_RESPONSE, 0, &[])).await.is_err() { break; }
                None
            }
            CMD_HEART_RESPONSE | CMD_WASTE | CMD_SERVER_SETTINGS => None,
            _ => break,
        };
        if let Some(event) = event {
            let tx = streams.lock().await.get(&id).cloned();
            if let Some(tx) = tx {
                match tokio::time::timeout(IO_TIMEOUT, tx.send(event)).await {
                    Ok(Ok(())) => {}
                    _ => break,
                }
            }
        }
    }
}

struct ServerStream {
    tx: mpsc::Sender<ServerStreamMsg>,
    fin_received: bool,
}

enum ServerStreamMsg { Data(Vec<u8>), Fin }

async fn serve_session(
    mut tls: tokio_rustls::server::TlsStream<TcpStream>,
    auth_map: Arc<HashMap<[u8; 32], String>>,
    resources: Resources,
) -> Result<()> {
    let remote = tokio::time::timeout(IO_TIMEOUT, async {
        let mut hash = [0; 32];
        tls.read_exact(&mut hash).await?;
        // Reject an unknown credential before allocating/reading its padding.
        let remote = auth_map.get(&hash).cloned().context("authentication failed")?;
        let pad_len = tls.read_u16().await? as usize;
        anyhow::ensure!(pad_len <= padding::MAX_SEGMENT_SIZE, "auth padding too large");
        let mut padding = vec![0; pad_len];
        tls.read_exact(&mut padding).await?;
        Result::Ok(remote)
    }).await.context("authentication timed out")??;
    let (mut reader, mut writer) = tokio::io::split(tls);
    let shutdown = Shutdown::new();
    let (write_tx, mut write_rx) = mpsc::channel::<Vec<u8>>(QUEUE_CAPACITY);
    let writer_shutdown = shutdown.clone();
    let mut writer_task = Task::spawn(async move {
        loop {
            let frame = tokio::select! {
                _ = writer_shutdown.cancelled() => break,
                frame = write_rx.recv() => match frame { Some(frame) => frame, None => break },
            };
            let write = async {
                writer.write_all(&frame).await?;
                writer.flush().await
            };
            tokio::select! {
                _ = writer_shutdown.cancelled() => break,
                result = tokio::time::timeout(IO_TIMEOUT, write) => {
                    if !matches!(result, Ok(Ok(()))) { break; }
                }
            }
        }
        writer_shutdown.cancel();
    });
    let (frame_tx, mut frame_rx) = mpsc::channel(QUEUE_CAPACITY);
    let reader_shutdown = shutdown.clone();
    let mut reader_task = Task::spawn(async move {
        loop {
            let frame = tokio::select! {
                _ = reader_shutdown.cancelled() => break,
                result = read_frame(&mut reader) => match result { Ok(frame) => frame, Err(_) => break },
            };
            if frame_tx.send(frame).await.is_err() { break; }
        }
        reader_shutdown.cancel();
    });
    let mut streams: HashMap<u32, ServerStream> = HashMap::new();
    let mut tasks = JoinSet::new();
    let mut settings_received = false;
    // This client allocates strictly increasing IDs. Never permit a delayed
    // frame/task from a previous stream to address a new stream with that ID.
    let mut last_id = 0;
    let outcome: Result<()> = async {
        loop {
            while let Some(completed) = tasks.try_join_next() {
                match completed {
                    Ok(id) => { streams.remove(&id); }
                    Err(e) => return Err(anyhow!("backend task failed: {e}")),
                }
            }
            if streams.len() >= MAX_STREAMS {
                streams.retain(|_, stream| !stream.tx.is_closed());
            }
            tokio::select! {
                _ = shutdown.cancelled() => break,
                completed = tasks.join_next(), if !tasks.is_empty() => {
                    match completed {
                        Some(Ok(id)) => { streams.remove(&id); }
                        Some(Err(e)) => return Err(anyhow!("backend task failed: {e}")),
                        None => {}
                    }
                }
                frame = frame_rx.recv() => {
                    let Some((cmd, id, data)) = frame else { break };
                    match cmd {
                        CMD_SETTINGS if id == 0 && !settings_received => {
                            settings_received = true;
                            let settings = std::str::from_utf8(&data).context("invalid client settings")?;
                            let expected = PaddingScheme::default_scheme();
                            let expected_md5 = expected.md5_hex();
                            let matches = settings.lines().any(|line| {
                                line.strip_prefix("padding-md5=").is_some_and(|md5| md5 == expected_md5)
                            });
                            if !matches {
                                send_frame(&write_tx, encode_frame(CMD_UPDATE_PADDING_SCHEME, 0, expected.raw.as_bytes())).await?;
                            }
                            send_frame(&write_tx, encode_frame(CMD_SERVER_SETTINGS, 0, b"v=2")).await?;
                        }
                        CMD_SYN => {
                            anyhow::ensure!(settings_received && id > last_id && data.is_empty(), "invalid SYN");
                            last_id = id;
                            if streams.len() >= MAX_STREAMS || tasks.len() >= MAX_STREAMS {
                                streams.retain(|_, stream| !stream.tx.is_closed());
                            }
                            if streams.len() >= MAX_STREAMS || tasks.len() >= MAX_STREAMS {
                                send_frame(&write_tx, encode_frame(CMD_SYNACK, id, b"stream limit reached")).await?;
                                continue;
                            }
                            let permit = match resources.socket() {
                                Ok(permit) => permit,
                                Err(_) => {
                                    send_frame(&write_tx, encode_frame(CMD_SYNACK, id, b"connection budget exhausted")).await?;
                                    continue;
                                }
                            };
                            let (tx, rx) = mpsc::channel(QUEUE_CAPACITY);
                            streams.insert(id, ServerStream { tx, fin_received: false });
                            let remote = remote.clone();
                            let tx = write_tx.clone();
                            let stream_shutdown = shutdown.clone();
                            tasks.spawn(async move {
                                let _permit = permit;
                                let connected = tokio::time::timeout(IO_TIMEOUT, connect_target(&remote)).await;
                                match connected {
                                    Ok(Ok(target)) => {
                                        if send_frame(&tx, encode_frame(CMD_SYNACK, id, &[])).await.is_ok() {
                                            let result = run_server_stream(target, id, tx.clone(), rx).await;
                                            if result.is_err() {
                                                // Abnormal close cannot be represented by a FIN
                                                // half-close alone; close the containing session.
                                                let _ = send_frame(&tx, encode_frame(CMD_ALERT, 0, b"backend relay failed")).await;
                                                stream_shutdown.cancel();
                                            }
                                        }
                                    }
                                    Ok(Err(_)) | Err(_) => {
                                        let _ = send_frame(&tx, encode_frame(CMD_SYNACK, id, b"backend connect failed")).await;
                                    }
                                }
                                id
                            });
                        }
                        CMD_PSH | CMD_FIN => {
                            let sender = if let Some(stream) = streams.get_mut(&id) {
                                anyhow::ensure!(!stream.fin_received, "data after FIN");
                                anyhow::ensure!(data.len() <= 16 * 1024, "stream data frame too large");
                                let msg = if cmd == CMD_FIN {
                                    anyhow::ensure!(data.is_empty(), "invalid FIN");
                                    stream.fin_received = true;
                                    ServerStreamMsg::Fin
                                } else { ServerStreamMsg::Data(data) };
                                Some((stream.tx.clone(), msg))
                            } else { None };
                            if let Some((tx, msg)) = sender {
                                match tokio::time::timeout(IO_TIMEOUT, tx.send(msg)).await {
                                    Ok(Ok(())) => {}
                                    Ok(Err(_)) => { streams.remove(&id); }
                                    Err(_) => return Err(anyhow!("backend queue timed out")),
                                }
                            }
                        }
                        CMD_HEART_REQUEST if id == 0 => {
                            send_frame(&write_tx, encode_frame(CMD_HEART_RESPONSE, 0, &[])).await?;
                        }
                        CMD_HEART_RESPONSE | CMD_WASTE => {}
                        CMD_ALERT => break,
                        _ => return Err(anyhow!("invalid session command")),
                    }
                }
            }
        }
        Ok(())
    }.await;
    shutdown.cancel();
    // Never await FIN enqueue while queues may be full. Dropping senders and
    // aborting owned tasks releases every backend half even on cancellation.
    streams.clear();
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    reader_task.stop().await;
    writer_task.stop().await;
    outcome
}

async fn run_server_stream(
    target: TcpStream,
    id: u32,
    tx: mpsc::Sender<Vec<u8>>,
    mut rx: mpsc::Receiver<ServerStreamMsg>,
) -> Result<()> {
    let (mut reader, mut writer) = target.into_split();
    let upload = async {
        while let Some(msg) = rx.recv().await {
            match msg {
                ServerStreamMsg::Data(data) => {
                    tokio::time::timeout(IO_TIMEOUT, writer.write_all(&data)).await??;
                }
                ServerStreamMsg::Fin => {
                    writer.shutdown().await?;
                    return Ok(());
                }
            }
        }
        Err(anyhow!("stream sender closed"))
    };
    let download = async {
        let mut buf = vec![0; 16 * 1024];
        loop {
            let n = reader.read(&mut buf).await?;
            if n == 0 { break; }
            send_frame(&tx, encode_frame(CMD_PSH, id, &buf[..n])).await?;
        }
        send_frame(&tx, encode_frame(CMD_FIN, id, &[])).await
    };
    runtime::relay_halves(upload, download).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn backend_receives_half_close_and_can_finish_its_response() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let relay_socket = TcpStream::connect(listener.local_addr().unwrap()).await.unwrap();
        let (mut backend, _) = listener.accept().await.unwrap();
        let (frames_tx, mut frames_rx) = mpsc::channel(8);
        let (upload_tx, upload_rx) = mpsc::channel(8);
        let relay = tokio::spawn(run_server_stream(relay_socket, 1, frames_tx, upload_rx));
        upload_tx.send(ServerStreamMsg::Data(b"request".to_vec())).await.unwrap();
        upload_tx.send(ServerStreamMsg::Fin).await.unwrap();
        let mut request = Vec::new();
        backend.read_to_end(&mut request).await.unwrap();
        assert_eq!(request, b"request");
        backend.write_all(b"complete response").await.unwrap();
        backend.shutdown().await.unwrap();
        let mut response = Vec::new();
        while let Some(frame) = frames_rx.recv().await {
            match frame[0] {
                CMD_PSH => response.extend_from_slice(&frame[FRAME_HEADER_LEN..]),
                CMD_FIN => break,
                _ => panic!("unexpected frame"),
            }
        }
        assert_eq!(response, b"complete response");
        assert!(relay.await.unwrap().is_ok());
    }

    #[tokio::test]
    async fn frame_decoder_keeps_partial_header_across_waits() {
        let (mut input, mut output) = tokio::io::duplex(64);
        let frame = encode_frame(CMD_PSH, 123, b"payload");
        let expected = frame.clone();
        let writer = tokio::spawn(async move {
            output.write_all(&frame[..3]).await.unwrap();
            tokio::task::yield_now().await;
            output.write_all(&frame[3..]).await.unwrap();
        });
        let (cmd, id, data) = read_frame(&mut input).await.unwrap();
        assert_eq!(encode_frame(cmd, id, &data), expected);
        writer.await.unwrap();
    }

    #[test]
    fn stream_ids_are_unique_and_never_wrap() {
        let id = AtomicU32::new(1);
        assert_eq!(id.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1)).unwrap(), 1);
        assert_eq!(id.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1)).unwrap(), 2);
        id.store(u32::MAX, Ordering::Relaxed);
        assert!(id.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1)).is_err());
    }
}
