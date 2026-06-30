mod config;
mod tcp;
mod tls;
mod udp;

use clap::Parser;
use tracing::info;
use tracing_subscriber::EnvFilter;

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

    // Initialise logging
    init_logging(&cfg.log_level);

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

fn init_logging(level: &str) {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(format!("anyst={level}")));

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_thread_ids(false)
        .init();
}
