//! Fixed-destination QUIC UDP relay using TUIC-v5-style commands.
//! Authentication uses the live TLS exporter after the QUIC handshake; this
//! is not QUIC 0-RTT and is not wire-compatible with official TUIC clients.

use anyhow::{anyhow, Context, Result};
use bytes::Bytes;
use quinn::{Connection, VarInt};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, OwnedSemaphorePermit};
use tokio::task::JoinSet;

use crate::config::TunnelConfig;
use crate::runtime::{self, Resources, Shutdown, Task, IO_TIMEOUT, MAX_ASSOCIATIONS, MAX_SESSIONS, MAX_UDP_PAYLOAD};
use crate::tls;

const TUIC_VERSION: u8 = 5;
const TYPE_AUTHENTICATE: u8 = 0;
const TYPE_PACKET: u8 = 2;
const TYPE_DISSOCIATE: u8 = 3;
const TYPE_HEARTBEAT: u8 = 4;
const ADDR_NONE: u8 = 0xff;
const HEADER_LEN: usize = 10;
const AUTH_LEN: usize = 50;
const ERROR_PROTOCOL: u32 = 0xfffffff0;
const ERROR_AUTH: u32 = 0xfffffff1;
const ERROR_AUTH_TIMEOUT: u32 = 0xfffffff2;
const ASSOC_TIMEOUT: Duration = Duration::from_secs(60);
const REASSEMBLY_TIMEOUT: Duration = Duration::from_secs(10);
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(10);
const MAX_REASSEMBLY_BUFFERS: usize = 64;
const MAX_ASSOC_REASSEMBLY_BYTES: usize = 256 * 1024;
const COMMAND_QUEUE: usize = 64;

#[derive(Clone, Copy, PartialEq, Eq)]
enum RelayMode { Datagram, Stream }

fn derive_uuid(password: &str) -> [u8; 16] {
    let digest = Sha256::digest(password.as_bytes());
    let mut uuid = [0; 16];
    uuid.copy_from_slice(&digest[..16]);
    uuid
}

fn derive_token(conn: &Connection, uuid: &[u8; 16], password: &str) -> Result<[u8; 32]> {
    let mut token = [0; 32];
    conn.export_keying_material(&mut token, uuid, password.as_bytes())
        .map_err(|_| anyhow!("TLS exporter failed"))?;
    Ok(token)
}

fn packet_frames(assoc: u16, packet: u16, data: &[u8], max_payload: usize) -> Result<Vec<Vec<u8>>> {
    anyhow::ensure!(data.len() <= MAX_UDP_PAYLOAD, "UDP payload too large");
    anyhow::ensure!(max_payload > 0, "QUIC datagrams unavailable or too small");
    let max_payload = max_payload.min(MAX_UDP_PAYLOAD);
    let count = if data.is_empty() { 1 } else { (data.len() - 1) / max_payload + 1 };
    let total = u8::try_from(count).context("too many UDP fragments")?;
    let mut frames = Vec::with_capacity(count);
    for fragment in 0..total {
        let start = fragment as usize * max_payload;
        let end = (start + max_payload).min(data.len());
        let payload = &data[start..end];
        let mut frame = Vec::with_capacity(HEADER_LEN + payload.len());
        frame.push(TYPE_PACKET);
        frame.extend_from_slice(&assoc.to_be_bytes());
        frame.extend_from_slice(&packet.to_be_bytes());
        frame.push(total);
        frame.push(fragment);
        frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        frame.push(ADDR_NONE);
        frame.extend_from_slice(payload);
        frames.push(frame);
    }
    Ok(frames)
}

struct Packet<'a> {
    assoc: u16,
    id: u16,
    total: u8,
    fragment: u8,
    data: &'a [u8],
}

fn parse_packet(frame: &[u8]) -> Option<Packet<'_>> {
    if frame.len() < HEADER_LEN || frame[0] != TYPE_PACKET || frame[9] != ADDR_NONE {
        return None;
    }
    let len = u16::from_be_bytes([frame[7], frame[8]]) as usize;
    if frame[5] == 0 || frame[6] >= frame[5] || frame.len() != HEADER_LEN + len
        || len > MAX_UDP_PAYLOAD {
        return None;
    }
    let assoc = u16::from_be_bytes([frame[1], frame[2]]);
    if assoc == 0 { return None; }
    Some(Packet {
        assoc,
        id: u16::from_be_bytes([frame[3], frame[4]]),
        total: frame[5],
        fragment: frame[6],
        data: &frame[HEADER_LEN..],
    })
}

struct Fragment {
    data: Vec<u8>,
    _permit: OwnedSemaphorePermit,
}

struct ReassemblyBuffer {
    fragments: Vec<Option<Fragment>>,
    received: u8,
    bytes: usize,
    created: Instant,
    _metadata: OwnedSemaphorePermit,
}

#[derive(Default)]
struct Reassembly {
    packets: HashMap<u16, ReassemblyBuffer>,
}

impl Reassembly {
    fn cleanup(&mut self) {
        self.packets.retain(|_, packet| packet.created.elapsed() < REASSEMBLY_TIMEOUT);
    }

    fn insert(&mut self, packet: &Packet<'_>, resources: &Resources) -> Option<Vec<u8>> {
        self.cleanup();
        if packet.total == 1 {
            // A wrapped ID must not retain an old incomplete packet.
            self.packets.remove(&packet.id);
            return Some(packet.data.to_vec());
        }
        if self.packets.get(&packet.id).is_some_and(|buffer| buffer.fragments.len() != packet.total as usize) {
            self.packets.remove(&packet.id);
        }
        if !self.packets.contains_key(&packet.id) && self.packets.len() >= MAX_REASSEMBLY_BUFFERS {
            let oldest = self.packets.iter().min_by_key(|(_, buffer)| buffer.created).map(|(&id, _)| id);
            if let Some(id) = oldest { self.packets.remove(&id); }
        }
        let buffered: usize = self.packets.values().map(|buffer| buffer.bytes).sum();
        if buffered + packet.data.len() > MAX_ASSOC_REASSEMBLY_BYTES { return None; }
        if !self.packets.contains_key(&packet.id) {
            let metadata = resources.fragment(packet.total as usize * 128 + 128)?;
            self.packets.insert(packet.id, ReassemblyBuffer {
                fragments: (0..packet.total).map(|_| None).collect(),
                received: 0,
                bytes: 0,
                created: Instant::now(),
                _metadata: metadata,
            });
        }
        let buffer = self.packets.get_mut(&packet.id)?;
        let index = packet.fragment as usize;
        if buffer.fragments[index].is_some() { return None; }
        if buffer.bytes + packet.data.len() > MAX_UDP_PAYLOAD {
            self.packets.remove(&packet.id);
            return None;
        }
        // Charge payload plus per-fragment bookkeeping to a process-wide
        // budget. Permits are released on expiry, eviction and cancellation.
        let permit = resources.fragment(packet.data.len() + 128)?;
        buffer.fragments[index] = Some(Fragment { data: packet.data.to_vec(), _permit: permit });
        buffer.bytes += packet.data.len();
        buffer.received += 1;
        if buffer.received as usize != buffer.fragments.len() { return None; }
        let buffer = self.packets.remove(&packet.id)?;
        let mut payload = Vec::with_capacity(buffer.bytes);
        for fragment in buffer.fragments.into_iter().flatten() {
            payload.extend_from_slice(&fragment.data);
        }
        Some(payload)
    }
}

async fn send_command(conn: &Connection, frame: &[u8]) -> Result<()> {
    tokio::time::timeout(IO_TIMEOUT, async {
        let mut stream = conn.open_uni().await?;
        stream.write_all(frame).await?;
        stream.finish()?;
        Result::Ok(())
    }).await.context("QUIC command write timed out")?
}

async fn send_packet(conn: &Connection, assoc: u16, id: u16, data: &[u8], mode: RelayMode) -> Result<()> {
    // Re-query for every packet: path MTU can change during a connection.
    let limit = match mode {
        RelayMode::Datagram => conn.max_datagram_size()
            .context("peer does not support datagrams")?.saturating_sub(HEADER_LEN),
        RelayMode::Stream => MAX_UDP_PAYLOAD,
    };
    for frame in packet_frames(assoc, id, data, limit)? {
        match mode {
            RelayMode::Datagram => {
                if let Err(e) = conn.send_datagram(Bytes::from(frame)) {
                    if conn.close_reason().is_some() { return Err(e.into()); }
                    // MTU races/buffer pressure lose this UDP packet, not the
                    // association. The next packet uses a fresh MTU value.
                    tracing::debug!("QUIC datagram dropped: {e}");
                    break;
                }
            }
            RelayMode::Stream => send_command(conn, &frame).await?,
        }
    }
    Ok(())
}

async fn read_auth(conn: &Connection) -> Result<Vec<u8>> {
    let mut stream = conn.accept_uni().await?;
    let data = stream.read_to_end(AUTH_LEN).await?;
    anyhow::ensure!(data.len() == AUTH_LEN && data[0] == TUIC_VERSION && data[1] == TYPE_AUTHENTICATE,
        "invalid authentication command");
    Ok(data)
}

/// Read complete stream commands independently so a stream without FIN cannot
/// stop datagrams/heartbeats. JoinSet owns and continuously reaps read tasks.
async fn read_commands(conn: Connection, tx: mpsc::Sender<(Vec<u8>, RelayMode)>) -> Result<()> {
    let mut tasks = JoinSet::new();
    loop {
        tokio::select! {
            result = tasks.join_next(), if !tasks.is_empty() => {
                match result {
                    Some(Ok(Ok(data))) => {
                        tokio::time::timeout(IO_TIMEOUT, tx.send((data, RelayMode::Stream))).await??;
                    }
                    Some(Ok(Err(e))) => tracing::debug!("QUIC command read failed: {e:#}"),
                    Some(Err(e)) => return Err(e.into()),
                    None => {}
                }
            }
            stream = conn.accept_uni(), if tasks.len() < 32 => {
                let mut stream = stream?;
                tasks.spawn(async move {
                    tokio::time::timeout(IO_TIMEOUT, stream.read_to_end(HEADER_LEN + MAX_UDP_PAYLOAD))
                        .await.context("QUIC command read timed out")?
                        .map_err(anyhow::Error::from)
                });
            }
        }
    }
}

pub async fn run_udp_server(cfg: &TunnelConfig, resources: Resources, shutdown: Shutdown) -> Result<()> {
    let rustls = tls::build_rustls_server_config(
        cfg.cert.as_deref().context("server requires cert")?,
        cfg.key.as_deref().context("server requires key")?,
    )?;
    let _endpoint_permit = resources.socket()?;
    let endpoint = quinn::Endpoint::server(tls::build_quic_server_config(rustls)?, cfg.listen.parse()?)?;
    let remote_map = Arc::new(cfg.remotes_list()?.into_iter()
        .map(|remote| (derive_uuid(&remote.password), (remote.password, remote.addr)))
        .collect::<HashMap<_, _>>());
    let mut tasks = JoinSet::new();
    tracing::info!("[TUIC server] listening on {}", cfg.listen);
    loop {
        while let Some(result) = tasks.try_join_next() {
            if let Err(e) = result { tracing::warn!("QUIC session task failed: {e}"); }
        }
        tokio::select! {
            _ = shutdown.cancelled() => break,
            result = tasks.join_next(), if !tasks.is_empty() => {
                if let Some(Err(e)) = result { tracing::warn!("QUIC session task failed: {e}"); }
            }
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else { break };
                if tasks.len() >= MAX_SESSIONS {
                    incoming.refuse();
                    continue;
                }
                let permit = match resources.socket() {
                    Ok(permit) => permit,
                    Err(_) => { incoming.refuse(); continue; }
                };
                let remotes = remote_map.clone();
                let resources = resources.clone();
                let session_shutdown = shutdown.clone();
                tasks.spawn(async move {
                    let _permit = permit;
                    let result = async {
                        let connecting = incoming.accept()?;
                        let conn = tokio::time::timeout(IO_TIMEOUT, connecting).await.context("QUIC handshake timed out")??;
                        let result = server_connection(&conn, remotes, resources, session_shutdown).await;
                        conn.close(VarInt::from_u32(ERROR_PROTOCOL), b"session ended");
                        result
                    }.await;
                    if let Err(e) = result { tracing::debug!("[TUIC server] connection ended: {e:#}"); }
                });
            }
        }
    }
    endpoint.close(VarInt::from_u32(0), b"shutdown");
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    Ok(())
}

struct ServerAssoc {
    socket: Arc<UdpSocket>,
    mode: RelayMode,
    last_seen: Instant,
    reassembly: Reassembly,
    last_reply_activity: Arc<std::sync::Mutex<Instant>>,
    next_packet: u32,
    next_packet_wrap: Instant,
    _pump: Task<()>,
    _permit: OwnedSemaphorePermit,
}

async fn server_connection(
    conn: &Connection,
    remotes: Arc<HashMap<[u8; 16], (String, String)>>,
    resources: Resources,
    shutdown: Shutdown,
) -> Result<()> {
    let auth = match tokio::time::timeout(IO_TIMEOUT, read_auth(conn)).await {
        Ok(Ok(auth)) => auth,
        result => {
            let code = if result.is_err() { ERROR_AUTH_TIMEOUT } else { ERROR_AUTH };
            conn.close(VarInt::from_u32(code), b"authentication failed");
            return Err(anyhow!("QUIC authentication failed or timed out"));
        }
    };
    let mut uuid = [0; 16];
    uuid.copy_from_slice(&auth[2..18]);
    let (password, remote) = remotes.get(&uuid).context("unknown credential")?;
    let token = derive_token(conn, &uuid, password)?;
    // Constant-time token comparison, without exposing token bytes to logs.
    let matches = bool::from(token.as_slice().ct_eq(&auth[18..]));
    anyhow::ensure!(matches, "invalid authentication token");
    // Resolve once per authenticated connection; no blocking DNS per packet.
    // Try family-appropriate sockets for all candidates, including systems
    // without IPv6 even when DNS returns an AAAA record first.
    let mut backend = None;
    for remote in runtime::resolve(remote).await? {
        let _probe_permit = resources.socket()?;
        if UdpSocket::bind(runtime::unspecified_for(remote)).await.is_ok() {
            backend = Some(remote);
            break;
        }
    }
    let remote = backend.context("no supported UDP backend address family")?;
    let (command_tx, mut command_rx) = mpsc::channel(COMMAND_QUEUE);
    let stream_conn = conn.clone();
    let mut command_task = Task::spawn(async move {
        let result = read_commands(stream_conn.clone(), command_tx).await;
        if result.is_err() { stream_conn.close(VarInt::from_u32(ERROR_PROTOCOL), b"command reader failed"); }
    });
    let (reply_tx, mut replies) = mpsc::channel::<(u16, Vec<u8>)>(COMMAND_QUEUE);
    let mut assocs: HashMap<u16, ServerAssoc> = HashMap::new();
    // Association IDs are not recycled in one connection. Tombstones stop a
    // delayed datagram from recreating an association after Dissociate/expiry.
    let mut retired = vec![false; u16::MAX as usize + 1];
    let mut interval = tokio::time::interval(Duration::from_secs(5));
    let result: Result<()> = async {
        loop {
            enum Event {
                Command(Vec<u8>, RelayMode),
                Reply(u16, Vec<u8>),
                Tick,
            }
            let event = tokio::select! {
                _ = shutdown.cancelled() => break,
                _ = conn.closed() => break,
                result = conn.read_datagram() => Event::Command(result?.to_vec(), RelayMode::Datagram),
                command = command_rx.recv() => match command {
                    Some((data, mode)) => Event::Command(data, mode),
                    None => break,
                },
                reply = replies.recv() => match reply {
                    Some((id, data)) => Event::Reply(id, data),
                    None => break,
                },
                _ = interval.tick() => Event::Tick,
            };
            match event {
                Event::Tick => {
                    let stale: Vec<_> = assocs.iter()
                        .filter(|(_, assoc)| assoc._pump.is_finished()
                            || (assoc.last_seen.elapsed() >= ASSOC_TIMEOUT
                                && assoc.last_reply_activity.lock().map(|seen| seen.elapsed() >= ASSOC_TIMEOUT).unwrap_or(false)))
                        .map(|(&id, _)| id).collect();
                    for id in stale {
                        retired[id as usize] = true;
                        assocs.remove(&id);
                        // Tell the client to retire its matching mapping too;
                        // otherwise its next packet could refresh a dead ID.
                        send_command(conn, &[TYPE_DISSOCIATE, (id >> 8) as u8, id as u8]).await?;
                    }
                    for assoc in assocs.values_mut() { assoc.reassembly.cleanup(); }
                }
                Event::Reply(id, data) => {
                    if let Some(assoc) = assocs.get_mut(&id) {
                        // Downstream traffic is activity too (subscriptions,
                        // streaming replies and full-cone traffic).
                        assoc.last_seen = Instant::now();
                        // Do not reuse a 16-bit packet ID while an old
                        // fragmented packet may still be awaiting reassembly.
                        if assoc.next_packet > u16::MAX as u32 {
                            if Instant::now() < assoc.next_packet_wrap { continue; }
                            assoc.next_packet = 0;
                            assoc.next_packet_wrap = Instant::now() + REASSEMBLY_TIMEOUT;
                        }
                        let packet_id = assoc.next_packet as u16;
                        assoc.next_packet += 1;
                        send_packet(conn, id, packet_id, &data, assoc.mode).await?;
                    }
                }
                Event::Command(data, mode) => {
                    match data.first().copied() {
                        Some(TYPE_PACKET) => {
                            let packet = parse_packet(&data).context("invalid UDP packet")?;
                            if retired[packet.assoc as usize] { continue; }
                            if !assocs.contains_key(&packet.assoc) {
                                if assocs.len() >= MAX_ASSOCIATIONS { continue; }
                                let permit = match resources.socket() { Ok(permit) => permit, Err(_) => continue };
                                let socket = Arc::new(UdpSocket::bind(runtime::unspecified_for(remote)).await?);
                                let pump_socket = socket.clone();
                                let tx = reply_tx.clone();
                                let id = packet.assoc;
                                let last_reply_activity = Arc::new(std::sync::Mutex::new(Instant::now()));
                                let pump_activity = last_reply_activity.clone();
                                let pump = Task::spawn(async move {
                                    let mut buf = vec![0; 65_536];
                                    loop {
                                        match pump_socket.recv_from(&mut buf).await {
                                            Ok((len, _)) if len <= MAX_UDP_PAYLOAD => {
                                                if let Ok(mut seen) = pump_activity.lock() { *seen = Instant::now(); }
                                                if !matches!(tokio::time::timeout(IO_TIMEOUT,
                                                    tx.send((id, buf[..len].to_vec()))).await, Ok(Ok(()))) { break; }
                                            }
                                            Ok(_) => {}
                                            Err(_) => break,
                                        }
                                    }
                                });
                                assocs.insert(id, ServerAssoc {
                                    socket,
                                    mode,
                                    last_seen: Instant::now(),
                                    reassembly: Reassembly::default(),
                                    last_reply_activity,
                                    next_packet: 0,
                                    next_packet_wrap: Instant::now() + REASSEMBLY_TIMEOUT,
                                    _pump: pump,
                                    _permit: permit,
                                });
                            }
                            if let Some(assoc) = assocs.get_mut(&packet.assoc) {
                                assoc.mode = mode;
                                assoc.last_seen = Instant::now();
                                if let Some(payload) = assoc.reassembly.insert(&packet, &resources) {
                                    tokio::time::timeout(IO_TIMEOUT, assoc.socket.send_to(&payload, remote)).await??;
                                }
                            }
                        }
                        Some(TYPE_DISSOCIATE) if data.len() == 3 => {
                            let id = u16::from_be_bytes([data[1], data[2]]);
                            retired[id as usize] = true;
                            assocs.remove(&id);
                        }
                        Some(TYPE_HEARTBEAT) if data.len() == 1 => {}
                        _ => return Err(anyhow!("invalid QUIC command")),
                    }
                }
            }
        }
        Ok(())
    }.await;
    assocs.clear(); // Drop aborts every owned reply pump, no Arc cycles.
    command_task.stop().await;
    result
}

struct ClientAssoc {
    peer: SocketAddr,
    last_seen: Instant,
    next_packet: u32,
    next_packet_wrap: Instant,
    reassembly: Reassembly,
}

fn local_association(
    peer: SocketAddr,
    peers: &mut HashMap<SocketAddr, u16>,
    assocs: &mut HashMap<u16, ClientAssoc>,
    next_id: &mut u32,
) -> Result<Option<u16>> {
    if let Some(id) = peers.get(&peer) { return Ok(Some(*id)); }
    if assocs.len() >= MAX_ASSOCIATIONS { return Ok(None); }
    let id = u16::try_from(*next_id).context("association IDs exhausted; reconnecting")?;
    *next_id += 1;
    peers.insert(peer, id);
    assocs.insert(id, ClientAssoc {
        peer,
        last_seen: Instant::now(),
        next_packet: 0,
        next_packet_wrap: Instant::now() + REASSEMBLY_TIMEOUT,
        reassembly: Reassembly::default(),
    });
    Ok(Some(id))
}

pub async fn run_udp_client(cfg: &TunnelConfig, resources: Resources, shutdown: Shutdown) -> Result<()> {
    let _local_permit = resources.socket()?;
    let local = UdpSocket::bind(&cfg.listen).await.context("bind UDP listener")?;
    let remote = cfg.default_remote()?;
    let sni = cfg.server_name()?;
    let password = cfg.default_password()?;
    // Trust roots and QUIC configuration are cached across reconnections.
    let quic = tls::build_quic_client_config(tls::build_rustls_client_config(cfg.insecure)?)?;
    let mut delay = Duration::from_secs(1);
    tracing::info!("[TUIC client] listening on {}", cfg.listen);
    loop {
        let result = tokio::select! {
            _ = shutdown.cancelled() => return Ok(()),
            result = async {
                let _endpoint_permit = resources.socket()?;
                let (endpoint, conn) = connect_quic(&remote, &sni, &quic).await?;
                let connected_at = Instant::now();
                let result = async {
                    let uuid = derive_uuid(&password);
                    let token = derive_token(&conn, &uuid, &password)?;
                    let mut auth = Vec::with_capacity(AUTH_LEN);
                    auth.extend_from_slice(&[TUIC_VERSION, TYPE_AUTHENTICATE]);
                    auth.extend_from_slice(&uuid);
                    auth.extend_from_slice(&token);
                    send_command(&conn, &auth).await?;
                    // A sent auth command is not proof the server accepted it.
                    tracing::info!("[TUIC client] QUIC connected; authentication sent");
                    client_relay(&local, &conn, &resources, &shutdown).await
                }.await;
                let stable = connected_at.elapsed() >= Duration::from_secs(30);
                conn.close(VarInt::from_u32(0), b"relay ended");
                endpoint.close(VarInt::from_u32(0), b"relay ended");
                let _ = tokio::time::timeout(IO_TIMEOUT, endpoint.wait_idle()).await;
                if stable { delay = Duration::from_secs(1); }
                result
            } => result,
        };
        if shutdown.is_cancelled() { return Ok(()); }
        tracing::warn!("[TUIC client] relay ended: {}; retrying in {}s",
            result.err().map(|e| format!("{e:#}")).unwrap_or_else(|| "connection closed".into()), delay.as_secs());
        tokio::select! {
            _ = shutdown.cancelled() => return Ok(()),
            _ = tokio::time::sleep(delay) => {}
        }
        delay = (delay * 2).min(Duration::from_secs(60));
    }
}

async fn connect_quic(remote: &str, sni: &str, config: &quinn::ClientConfig) -> Result<(quinn::Endpoint, Connection)> {
    let addrs = runtime::resolve(remote).await?;
    let mut last_error = anyhow!("no reachable QUIC address");
    for addr in addrs {
        let attempt: Result<(quinn::Endpoint, Connection)> = async {
            let mut endpoint = quinn::Endpoint::client(runtime::unspecified_for(addr))?;
            endpoint.set_default_client_config(config.clone());
            let conn = tokio::time::timeout(IO_TIMEOUT, endpoint.connect(addr, sni)?)
                .await.context("QUIC connect timed out")??;
            Ok((endpoint, conn))
        }.await;
        match attempt {
            Ok(connection) => return Ok(connection),
            Err(e) => last_error = e,
        }
    }
    Err(last_error)
}

async fn client_relay(local: &UdpSocket, conn: &Connection, resources: &Resources, shutdown: &Shutdown) -> Result<()> {
    let mut peers: HashMap<SocketAddr, u16> = HashMap::new();
    let mut assocs: HashMap<u16, ClientAssoc> = HashMap::new();
    // Never reuse IDs while delayed datagrams from old associations can arrive.
    // Reconnect when the finite wire ID space is exhausted.
    let mut next_assoc = 1u32;
    let (command_tx, mut commands) = mpsc::channel(COMMAND_QUEUE);
    let stream_conn = conn.clone();
    let mut command_task = Task::spawn(async move {
        if read_commands(stream_conn.clone(), command_tx).await.is_err() {
            stream_conn.close(VarInt::from_u32(ERROR_PROTOCOL), b"command reader failed");
        }
    });
    let mut heartbeat = tokio::time::interval(HEARTBEAT_INTERVAL);
    let mut janitor = tokio::time::interval(Duration::from_secs(5));
    let mut buf = vec![0; 65_536];
    let result: Result<()> = async {
        loop {
            enum Event { Local(usize, SocketAddr), Reply(Vec<u8>), Tick, Heartbeat }
            let event = tokio::select! {
                _ = shutdown.cancelled() => break,
                _ = conn.closed() => break,
                result = local.recv_from(&mut buf) => { let (len, peer) = result?; Event::Local(len, peer) },
                result = conn.read_datagram() => Event::Reply(result?.to_vec()),
                result = commands.recv() => match result { Some((data, _)) => Event::Reply(data), None => break },
                _ = janitor.tick() => Event::Tick,
                _ = heartbeat.tick() => Event::Heartbeat,
            };
            match event {
                Event::Local(len, peer) => {
                    if len > MAX_UDP_PAYLOAD { continue; }
                    let Some(id) = local_association(peer, &mut peers, &mut assocs, &mut next_assoc)? else {
                        continue;
                    };
                    if let Some(assoc) = assocs.get_mut(&id) {
                        assoc.last_seen = Instant::now();
                        if assoc.next_packet > u16::MAX as u32 {
                            if Instant::now() < assoc.next_packet_wrap { continue; }
                            assoc.next_packet = 0;
                            assoc.next_packet_wrap = Instant::now() + REASSEMBLY_TIMEOUT;
                        }
                        let packet = assoc.next_packet as u16;
                        assoc.next_packet += 1;
                        send_packet(conn, id, packet, &buf[..len], RelayMode::Datagram).await?;
                    }
                }
                Event::Reply(data) => {
                    if data.as_slice() == [TYPE_HEARTBEAT] { continue; }
                    if data.len() == 3 && data[0] == TYPE_DISSOCIATE {
                        let id = u16::from_be_bytes([data[1], data[2]]);
                        if let Some(assoc) = assocs.remove(&id) { peers.remove(&assoc.peer); }
                        continue;
                    }
                    let packet = parse_packet(&data).context("invalid reply packet")?;
                    if let Some(assoc) = assocs.get_mut(&packet.assoc) {
                        assoc.last_seen = Instant::now();
                        if let Some(payload) = assoc.reassembly.insert(&packet, resources) {
                            tokio::time::timeout(IO_TIMEOUT, local.send_to(&payload, assoc.peer)).await??;
                        }
                    }
                }
                Event::Heartbeat => {
                    if conn.send_datagram(Bytes::from_static(&[TYPE_HEARTBEAT])).is_err()
                        && conn.close_reason().is_some() { break; }
                }
                Event::Tick => {
                    let stale: Vec<_> = assocs.iter().filter(|(_, assoc)| assoc.last_seen.elapsed() >= ASSOC_TIMEOUT)
                        .map(|(&id, _)| id).collect();
                    for id in stale {
                        if let Some(assoc) = assocs.remove(&id) { peers.remove(&assoc.peer); }
                        let frame = [TYPE_DISSOCIATE, (id >> 8) as u8, id as u8];
                        send_command(conn, &frame).await?;
                    }
                    for assoc in assocs.values_mut() { assoc.reassembly.cleanup(); }
                }
            }
        }
        Ok(())
    }.await;
    command_task.stop().await;
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fragmented_packets_reassemble_and_release_budget() {
        let resources = Resources::new();
        let data = vec![42; MAX_UDP_PAYLOAD];
        let frames = packet_frames(1, 7, &data, 1100).unwrap();
        let mut reassembly = Reassembly::default();
        let mut result = None;
        for frame in frames.iter().rev() {
            result = reassembly.insert(&parse_packet(frame).unwrap(), &resources).or(result);
        }
        assert_eq!(result.unwrap(), data);
        assert!(reassembly.packets.is_empty());
    }

    #[test]
    fn invalid_fragment_limits_and_address_tags_are_rejected() {
        assert!(packet_frames(1, 0, &[1], 0).is_err());
        assert!(packet_frames(1, 0, &[1; 256], 1).is_err());
        assert!(packet_frames(1, 0, &vec![0; MAX_UDP_PAYLOAD + 1], 1100).is_err());
        let mut frame = packet_frames(1, 0, b"data", 1100).unwrap().remove(0);
        frame[9] = 0;
        assert!(parse_packet(&frame).is_none());
    }

    #[test]
    fn different_local_peers_get_independent_reply_routes() {
        let a: SocketAddr = "127.0.0.1:1001".parse().unwrap();
        let b: SocketAddr = "127.0.0.1:1002".parse().unwrap();
        let mut peers = HashMap::new();
        let mut assocs = HashMap::new();
        let mut next_id = 1;
        let id_a = local_association(a, &mut peers, &mut assocs, &mut next_id).unwrap().unwrap();
        let id_b = local_association(b, &mut peers, &mut assocs, &mut next_id).unwrap().unwrap();
        assert_ne!(id_a, id_b);
        assert_eq!(assocs[&id_a].peer, a);
        assert_eq!(assocs[&id_b].peer, b);
        assert_eq!(local_association(a, &mut peers, &mut assocs, &mut next_id).unwrap(), Some(id_a));
        assocs.remove(&id_a);
        peers.remove(&a);
        let id_new = local_association(a, &mut peers, &mut assocs, &mut next_id).unwrap().unwrap();
        assert_ne!(id_new, id_a);
        assert!(!assocs.contains_key(&id_a));
    }

    #[test]
    fn association_reassembly_is_isolated() {
        let resources = Resources::new();
        let a = packet_frames(1, 5, b"abcdef", 3).unwrap();
        let b = packet_frames(2, 5, b"uvwxyz", 3).unwrap();
        let mut associations = HashMap::from([(1, Reassembly::default()), (2, Reassembly::default())]);
        for frame in [&a[0], &b[0]] {
            let packet = parse_packet(frame).unwrap();
            assert!(associations.get_mut(&packet.assoc).unwrap().insert(&packet, &resources).is_none());
        }
        for (frame, expected) in [(&a[1], b"abcdef"), (&b[1], b"uvwxyz")] {
            let packet = parse_packet(frame).unwrap();
            assert_eq!(associations.get_mut(&packet.assoc).unwrap().insert(&packet, &resources).unwrap(), expected);
        }
    }
}
