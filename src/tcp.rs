//! TCP tunnel — AnyTLS-like protocol over TLS.
//!
//! Protocol (after TLS handshake):
//!   1. Client → Server:  version(u8)  pwd_len(u16 BE)  password([u8; pwd_len])
//!   2. Server → Client:  status(u8)    (0x00 = success)
//!   3. Bidirectional relay of raw TCP data.

use crate::config::TunnelConfig;
use anyhow::Context;
use rustls::pki_types::ServerName;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, warn};

/// Protocol version byte.
const PROTO_VERSION: u8 = 0x01;

/// Auth success status byte.
const AUTH_OK: u8 = 0x00;
/// Auth failure status byte.
const AUTH_FAIL: u8 = 0x01;

// ---------------------------------------------------------------------------
// Server mode
// ---------------------------------------------------------------------------

/// Run the TCP tunnel in **server** mode (has cert + key).
///
/// 1. Bind a TLS listener on `listen_addr`.
/// 2. For each accepted TLS connection, authenticate the peer and pipe data
///    between the TLS stream and the configured `remote` address.
pub async fn run_tcp_server(config: &TunnelConfig) -> anyhow::Result<()> {
    let listen_addr: SocketAddr = config.listen_addr()?;
    let password = config.password.clone();
    let remote = config.remote.clone();
    let sni = config.sni.clone();

    // Build rustls server config (shared with quic)
    let cert_path = config.cert.as_ref().unwrap();
    let key_path = config.key.as_ref().unwrap();
    let rustls_cfg = crate::tls::build_rustls_server_config(cert_path, key_path)?;
    let acceptor = TlsAcceptor::from(Arc::new(rustls_cfg));

    let listener = TcpListener::bind(listen_addr).await.with_context(|| {
        format!("TCP server: failed to bind to {}", listen_addr)
    })?;
    info!("[TCP-server] listening on {} (TLS)", listen_addr);

    loop {
        let (stream, peer_addr) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                warn!("TCP server: accept error: {}", e);
                continue;
            }
        };

        let acceptor = acceptor.clone();
        let password = password.clone();
        let remote = remote.clone();
        let sni = sni.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_server_conn(acceptor, stream, peer_addr, &password, &remote, &sni).await {
                error!("TCP server conn from {}: {:#}", peer_addr, e);
            }
        });
    }
}

async fn handle_server_conn(
    acceptor: TlsAcceptor,
    stream: TcpStream,
    peer_addr: SocketAddr,
    password: &str,
    remote: &str,
    sni: &str,
) -> anyhow::Result<()> {
    debug!("TCP server: TLS handshake with {}", peer_addr);

    // Accept TLS
    let mut tls_stream = acceptor.accept(stream).await.with_context(|| {
        format!("TCP server: TLS accept failed from {}", peer_addr)
    })?;
    debug!("TCP server: TLS established with {}", peer_addr);

    // Read auth frame: version(1) + pwd_len(2) + password(pwd_len)
    let version = tls_stream.read_u8().await?;
    if version != PROTO_VERSION {
        tls_stream.write_u8(AUTH_FAIL).await?;
        anyhow::bail!("unsupported protocol version {} from {}", version, peer_addr);
    }

    let pwd_len = tls_stream.read_u16().await? as usize;
    let mut pwd_buf = vec![0u8; pwd_len];
    tls_stream.read_exact(&mut pwd_buf).await?;

    if pwd_buf != password.as_bytes() {
        tls_stream.write_u8(AUTH_FAIL).await?;
        anyhow::bail!("auth failed from {}", peer_addr);
    }

    tls_stream.write_u8(AUTH_OK).await?;
    debug!("TCP server: auth ok from {}, connecting to {}", peer_addr, remote);

    // Connect to the target
    let remote_stream = TcpStream::connect(remote).await.with_context(|| {
        format!("TCP server: failed to connect to remote {}", remote)
    })?;
    debug!("TCP server: connected to remote {} for {}", remote, peer_addr);

    // Bidirectional relay
    relay_tcp(tls_stream, remote_stream, peer_addr, sni).await;
    Ok(())
}

// ---------------------------------------------------------------------------
// Client mode
// ---------------------------------------------------------------------------

/// Run the TCP tunnel in **client** mode (no cert, optional insecure).
///
/// 1. Bind a plain TCP listener on `listen_addr`.
/// 2. For each accepted connection, establish a TLS connection to the
///    remote server, authenticate, and pipe data.
pub async fn run_tcp_client(config: &TunnelConfig) -> anyhow::Result<()> {
    let listen_addr: SocketAddr = config.listen_addr()?;
    let password = config.password.clone();
    let remote = config.remote.clone();
    let sni = config.sni.clone();
    let insecure = config.insecure;

    let listener = TcpListener::bind(listen_addr).await.with_context(|| {
        format!("TCP client: failed to bind to {}", listen_addr)
    })?;
    info!("[TCP-client] listening on {} (plain)", listen_addr);

    loop {
        let (stream, peer_addr) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                warn!("TCP client: accept error: {}", e);
                continue;
            }
        };

        let password = password.clone();
        let remote = remote.clone();
        let sni = sni.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_client_conn(stream, peer_addr, &password, &remote, &sni, insecure).await {
                error!("TCP client conn from {}: {:#}", peer_addr, e);
            }
        });
    }
}

async fn handle_client_conn(
    local: TcpStream,
    peer_addr: SocketAddr,
    password: &str,
    remote: &str,
    sni: &str,
    insecure: bool,
) -> anyhow::Result<()> {
    debug!("TCP client: new connection from {}, connecting to {}", peer_addr, remote);

    // Build TLS client config
    let rustls_cfg = crate::tls::build_rustls_client_config(insecure);
    let connector = tokio_rustls::TlsConnector::from(Arc::new(rustls_cfg));

    // Resolve server name for SNI (owned to get 'static lifetime)
    let server_name = ServerName::try_from(sni.to_string())
        .context("invalid SNI")?;

    // Connect to remote via TCP, then TLS
    let tcp = TcpStream::connect(remote).await.with_context(|| {
        format!("TCP client: failed to connect to {}", remote)
    })?;

    let mut tls_stream = connector
        .connect(server_name, tcp)
        .await
        .with_context(|| format!("TCP client: TLS handshake with {} failed", remote))?;
    debug!("TCP client: TLS established with {}", remote);

    // Send auth frame: version(1) + pwd_len(2) + password(pwd_len)
    let pwd = password.as_bytes();
    tls_stream.write_u8(PROTO_VERSION).await?;
    tls_stream.write_u16(pwd.len() as u16).await?;
    tls_stream.write_all(pwd).await?;
    tls_stream.flush().await?;

    // Read auth response
    let status = tls_stream.read_u8().await?;
    if status != AUTH_OK {
        anyhow::bail!("TCP client: auth rejected by server (status={})", status);
    }
    debug!("TCP client: auth ok with {}", remote);

    // Bidirectional relay
    relay_tcp(local, tls_stream, peer_addr, sni).await;
    Ok(())
}

// ---------------------------------------------------------------------------
// Bidirectional TCP relay
// ---------------------------------------------------------------------------

async fn relay_tcp<A, B>(mut a: A, mut b: B, peer: SocketAddr, label: &str)
where
    A: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    B: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let (mut ar, mut aw) = tokio::io::split(&mut a);
    let (mut br, mut bw) = tokio::io::split(&mut b);

    let a_to_b = async {
        match tokio::io::copy(&mut ar, &mut bw).await {
            Ok(n) => debug!("[TCP relay {peer}] {label}: a→b copied {n} bytes, done"),
            Err(e) => debug!("[TCP relay {peer}] {label}: a→b error: {e}"),
        }
    };

    let b_to_a = async {
        match tokio::io::copy(&mut br, &mut aw).await {
            Ok(n) => debug!("[TCP relay {peer}] {label}: b→a copied {n} bytes, done"),
            Err(e) => debug!("[TCP relay {peer}] {label}: b→a error: {e}"),
        }
    };

    tokio::select! {
        _ = a_to_b => {}
        _ = b_to_a => {}
    }
}
