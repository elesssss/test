use serde::Deserialize;
use std::net::SocketAddr;

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

    /// Remote address as "host:port", resolved at connection time
    pub remote: String,

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

/// Load and parse the YAML config file.
pub fn load_config(path: &str) -> anyhow::Result<Config> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("failed to read config file '{}': {}", path, e))?;
    let config: Config = serde_yaml::from_str(&content)
        .map_err(|e| anyhow::anyhow!("failed to parse config: {}", e))?;

    // Validate tunnel entries
    for (i, t) in config.tunnels.iter().enumerate() {
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
