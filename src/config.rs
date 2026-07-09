use serde::Deserialize;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    #[serde(default = "default_log_level")]
    pub log_level: String,
    pub tunnels: Vec<TunnelConfig>,
}

fn default_log_level() -> String {
    "info".into()
}

#[derive(Debug, Deserialize, Clone)]
pub struct TunnelConfig {
    /// Local listen address, e.g. "[::]:1017" or "0.0.0.0:1017"
    pub listen: String,

    /// Remote addresses as "host:port".  When more than one is listed
    /// connections are distributed across them with round‑robin.
    #[serde(default)]
    pub remotes: Vec<String>,

    /// TLS Server Name Indication (SNI) for TLS/QUIC
    pub sni: String,

    /// Skip TLS certificate verification (client mode, typically)
    #[serde(default)]
    pub insecure: bool,

    /// Authentication password
    pub password: String,

    /// Path to TLS certificate PEM file (server mode)
    #[serde(default)]
    pub cert: Option<String>,

    /// Path to TLS private key PEM file (server mode)
    #[serde(default)]
    pub key: Option<String>,
}

impl TunnelConfig {
    /// Returns true if this tunnel should act as a TLS server (has cert + key).
    pub fn is_server(&self) -> bool {
        self.cert.is_some() && self.key.is_some()
    }

    /// Parse the listen address string into a SocketAddr.
    pub fn listen_addr(&self) -> anyhow::Result<SocketAddr> {
        self.listen
            .parse()
            .map_err(|e| anyhow::anyhow!("invalid listen address '{}': {}", self.listen, e))
    }
}

/// Thread‑safe round‑robin remote address selector with basic health
/// tracking.  Unreachable remotes are skipped for a cooldown period so a
/// single dead backend doesn't cause every Nth connection to fail.
#[derive(Debug)]
pub struct RemotePool {
    remotes: Vec<String>,
    next: AtomicUsize,
    /// Per‑remote unix‑timestamp of the last connection failure, or 0 for
    /// healthy.  A pick skips any remote that failed within the last 30 s.
    failures: Vec<AtomicU64>,
}

/// How long a remote is skipped after a connection failure (seconds).
const FAILURE_COOLDOWN_SECS: u64 = 30;

impl RemotePool {
    pub fn new(remotes: Vec<String>) -> Self {
        assert!(!remotes.is_empty(), "at least one remote required");
        let n = remotes.len();
        Self {
            remotes,
            next: AtomicUsize::new(0),
            failures: (0..n).map(|_| AtomicU64::new(0)).collect(),
        }
    }

    /// Pick the next healthy remote in round‑robin order.
    /// If all remotes are currently unhealthy the cooldown is ignored and
    /// the oldest failure is returned.
    #[inline]
    pub fn pick(&self) -> &str {
        let n = self.remotes.len();
        let now = now_secs();
        for _ in 0..n {
            let idx = self.next.fetch_add(1, Ordering::Relaxed) % n;
            let last_fail = self.failures[idx].load(Ordering::Relaxed);
            if last_fail == 0 || now.saturating_sub(last_fail) > FAILURE_COOLDOWN_SECS {
                return &self.remotes[idx];
            }
        }
        // All unhealthy — return the one that failed longest ago.
        let mut oldest = 0usize;
        let mut oldest_ts = u64::MAX;
        for (i, f) in self.failures.iter().enumerate() {
            let ts = f.load(Ordering::Relaxed);
            if ts < oldest_ts { oldest_ts = ts; oldest = i; }
        }
        &self.remotes[oldest]
    }

    /// Mark `remote` as unreachable so it is skipped for the cooldown
    /// period.
    pub fn mark_failed(&self, remote: &str) {
        if let Some(pos) = self.remotes.iter().position(|r| r == remote) {
            self.failures[pos].store(now_secs(), Ordering::Relaxed);
        }
    }

    /// Return the first remote (useful for one‑time connections like QUIC
    /// client init where the pool lives across reconnects).
    #[inline]
    pub fn first(&self) -> &str {
        &self.remotes[0]
    }
}

fn now_secs() -> u64 {
    use std::time::SystemTime;
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Load and parse the YAML config file.
pub fn load_config(path: &str) -> anyhow::Result<Config> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("failed to read config file '{}': {}", path, e))?;
    let config: Config = serde_yaml::from_str(&content)
        .map_err(|e| anyhow::anyhow!("failed to parse config: {}", e))?;

    // Validate tunnel entries
    for (i, t) in config.tunnels.iter().enumerate() {
        if t.remotes.is_empty() {
            anyhow::bail!("tunnel[{}]: at least one remote address required", i);
        }
        if t.is_server() {
            // Server mode: cert and key files must exist
            let cert_path = t.cert.as_ref().unwrap();
            let key_path = t.key.as_ref().unwrap();
            if !std::path::Path::new(cert_path).exists() {
                anyhow::bail!(
                    "tunnel[{}]: certificate file not found: {}",
                    i,
                    cert_path
                );
            }
            if !std::path::Path::new(key_path).exists() {
                anyhow::bail!("tunnel[{}]: key file not found: {}", i, key_path);
            }
        }
    }
    Ok(config)
}
