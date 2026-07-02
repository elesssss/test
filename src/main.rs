mod config;
mod padding;
mod tcp;
mod tls;
mod udp;

use clap::Parser;
use tracing::info;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::prelude::*;

/// `anyst` — A port tunnel that simultaneously listens on TCP and UDP,
/// using a shared TLS certificate.
///
///   - TCP tunnel works like **AnyTLS** (TLS-wrapped relay).
///   - UDP tunnel works like **TUIC** (QUIC-based relay).
///
/// Both protocols authenticate with a pre-shared password and share the same
/// certificate / key pair.
#[derive(Parser)]
#[command(name = "anyst", version = env!("CARGO_PKG_VERSION"))]
struct Cli {
    /// Path to the YAML configuration file.
    #[arg(short, long, default_value = "config.yaml")]
    config: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Install the rustls crypto provider (required by rustls 0.23+).
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("failed to install rustls crypto provider");

    let cli = Cli::parse();

    // Load configuration
    let cfg = config::load_config(&cli.config)?;

    // Initialise logging (returns a guard that must be kept alive so
    // buffered file writes are flushed before the process exits).
    let _log_guard = init_logging(&cfg.log_level);

    info!("anyst starting with {} tunnel(s)", cfg.tunnels.len());

    // Spawn each tunnel
    for (i, tunnel) in cfg.tunnels.iter().enumerate() {
        let is_server = tunnel.is_server();
        let listen = tunnel.listen.clone();
        let role = if is_server { "server" } else { "client" };

        info!(
            "tunnel[{i}]: mode={role} listen={listen} remote={remote}",
            remote = tunnel.remote
        );

        let tcp_cfg = tunnel.clone();
        let udp_cfg = tunnel.clone();

        // TCP task (runs forever until shutdown)
        tokio::spawn(async move {
            if tcp_cfg.is_server() {
                if let Err(e) = tcp::run_tcp_server(&tcp_cfg).await {
                    tracing::error!("tunnel[{i}] TCP server died: {e:#}");
                }
            } else {
                if let Err(e) = tcp::run_tcp_client(&tcp_cfg).await {
                    tracing::error!("tunnel[{i}] TCP client died: {e:#}");
                }
            }
        });

        // UDP task (runs forever until shutdown)
        tokio::spawn(async move {
            if udp_cfg.is_server() {
                if let Err(e) = udp::run_udp_server(&udp_cfg).await {
                    tracing::error!("tunnel[{i}] UDP server died: {e:#}");
                }
            } else {
                if let Err(e) = udp::run_udp_client(&udp_cfg).await {
                    tracing::error!("tunnel[{i}] UDP client died: {e:#}");
                }
            }
        });
    }

    // Wait for Ctrl+C; tunnel tasks run forever as background tasks.
    // If a tunnel dies with an error it is already logged inside the task.
    tokio::signal::ctrl_c().await?;
    info!("received Ctrl+C, shutting down ...");

    // Give tasks a moment to cleanly close connections.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    info!("anyst stopped");
    Ok(())
}

/// Initialise `tracing` subscribers that write to **both** stderr and a
/// rotating log file (`log_anyst.log` in the current directory).
///
/// Returns a `WorkerGuard` that **must** be kept alive for the lifetime of
/// the process — dropping it causes the non‑blocking file writer to flush
/// and shut down.
fn init_logging(level: &str) -> tracing_appender::non_blocking::WorkerGuard {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(format!("anyst={level}")));

    // File appender: creates ./log_anyst.log (never rotates — anyst is
    // long‑lived but a single file is sufficient for its log volume).
    let file_appender = tracing_appender::rolling::never(".", "log_anyst.log");
    let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);

    // stderr layer (same format as before).
    let stderr_layer = tracing_subscriber::fmt::layer()
        .with_target(false)
        .with_thread_ids(false)
        .with_writer(std::io::stderr);

    // File layer — no ANSI escape codes so the file is easily readable
    // with `tail -f` or a text editor.
    let file_layer = tracing_subscriber::fmt::layer()
        .with_target(false)
        .with_thread_ids(false)
        .with_ansi(false)
        .with_writer(non_blocking);

    tracing_subscriber::registry()
        .with(filter)
        .with(stderr_layer)
        .with(file_layer)
        .init();

    guard
}
