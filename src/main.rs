mod config;
mod padding;
mod runtime;
mod tcp;
mod tls;
mod udp;

use anyhow::Context;
use clap::Parser;
use std::time::Duration;
use tracing::info;
use tracing_subscriber::prelude::*;
use tracing_subscriber::EnvFilter;
use runtime::{Resources, Shutdown};

/// Fixed-destination TCP/TLS and UDP/QUIC port tunnels.
#[derive(Parser)]
#[command(name = "anyst", version = env!("CARGO_PKG_VERSION"))]
struct Cli {
    #[arg(short, long, default_value = "config.yaml")]
    config: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    rustls::crypto::ring::default_provider().install_default()
        .map_err(|_| anyhow::anyhow!("failed to install TLS crypto provider"))?;
    let cli = Cli::parse();
    let cfg = config::load_config(&cli.config)?;
    let _log_guard = init_logging(&cfg.log_level)?;
    let resources = Resources::new();
    let shutdown = Shutdown::new();
    let mut tasks = tokio::task::JoinSet::new();
    info!("anyst starting with {} tunnel(s)", cfg.tunnels.len());
    for (i, tunnel) in cfg.tunnels.into_iter().enumerate() {
        let role = if tunnel.is_server() { "server" } else { "client" };
        let destinations = tunnel.remotes_list()?.into_iter().map(|remote| remote.addr)
            .collect::<Vec<_>>().join(", ");
        // Never log passwords, their hashes or raw peer settings/alerts.
        info!("tunnel[{i}]: mode={role} listen={} destinations={destinations}", tunnel.listen);
        if tunnel.insecure {
            tracing::warn!("tunnel[{i}]: TLS certificate/hostname verification disabled");
        }
        let tcp_cfg = tunnel.clone();
        let tcp_resources = resources.clone();
        let tcp_shutdown = shutdown.clone();
        tasks.spawn(async move {
            let result = if tcp_cfg.is_server() {
                tcp::run_tcp_server(&tcp_cfg, tcp_resources, tcp_shutdown).await
            } else {
                tcp::run_tcp_client(&tcp_cfg, tcp_resources, tcp_shutdown).await
            };
            result.with_context(|| format!("tunnel[{i}] TCP"))
        });
        let udp_resources = resources.clone();
        let udp_shutdown = shutdown.clone();
        tasks.spawn(async move {
            let result = if tunnel.is_server() {
                udp::run_udp_server(&tunnel, udp_resources, udp_shutdown).await
            } else {
                udp::run_udp_client(&tunnel, udp_resources, udp_shutdown).await
            };
            result.with_context(|| format!("tunnel[{i}] UDP"))
        });
    }
    // A listener error/panic is a process failure, not an apparently healthy
    // service with dead tunnels. systemd can then perform its configured retry.
    let outcome = tokio::select! {
        signal = shutdown_signal() => signal,
        result = tasks.join_next() => match result {
            Some(Ok(Err(e))) => Err(e),
            Some(Err(e)) => Err(anyhow::anyhow!("tunnel task failed: {e}")),
            _ => Err(anyhow::anyhow!("tunnel exited unexpectedly")),
        },
    };
    shutdown.cancel();
    info!("shutting down tunnels ...");
    // Allow owned tasks/endpoints to shut down; fall back to cancellation only
    // after a bounded grace period. JoinSet Drop also covers signal errors.
    if tokio::time::timeout(Duration::from_secs(5), async {
        while tasks.join_next().await.is_some() {}
    }).await.is_err() {
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
    }
    info!("anyst stopped");
    outcome
}

async fn shutdown_signal() -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut terminate = signal(SignalKind::terminate())?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => result?,
            _ = terminate.recv() => {}
        }
    }
    #[cfg(not(unix))]
    tokio::signal::ctrl_c().await?;
    Ok(())
}

fn init_logging(level: &str) -> anyhow::Result<tracing_appender::non_blocking::WorkerGuard> {
    let filter = match std::env::var("RUST_LOG") {
        Ok(value) => EnvFilter::try_new(value).context("invalid RUST_LOG")?,
        Err(_) => EnvFilter::try_new(format!("anyst={level}"))?,
    };
    let log_dir = std::env::var_os("ANYST_LOG_DIR").map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    let file_appender = tracing_appender::rolling::Builder::new()
        .rotation(tracing_appender::rolling::Rotation::DAILY)
        .filename_prefix("log_anyst")
        .filename_suffix("log")
        .max_log_files(7)
        .build(log_dir).context("create rotating log file")?;
    let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);
    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer().with_target(false).with_writer(std::io::stderr))
        .with(tracing_subscriber::fmt::layer().with_target(false).with_ansi(false).with_writer(non_blocking))
        .try_init().map_err(|e| anyhow::anyhow!("initialize logging: {e}"))?;
    Ok(guard)
}
