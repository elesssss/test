use serde::Deserialize;

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    #[serde(default = "default_log_level")]
    pub log_level: String,
    pub tunnels: Vec<TunnelConfig>,
}

fn default_log_level() -> String {
    "info".into()
}

/// A single remote entry: destination address paired with its authentication
/// password.  One tunnel can have multiple remotes — the server uses the
/// password the client presents to decide which target to forward to (port
/// multiplexing / "端口复用").
#[derive(Debug, Deserialize, Clone)]
pub struct RemoteConfig {
    /// Target address, e.g. "internal-service:443" or "1.2.3.4:8080".
    pub addr: String,
    /// Pre-shared password that routes to this target.
    pub password: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct TunnelConfig {
    /// Local listen address, e.g. "[::]:1017" or "0.0.0.0:1017"
    pub listen: String,

    /// New-style remote list.  Each entry pairs a password with a target
    /// address.  For client tunnels this typically has one entry (pointing
    /// at the tunnel server); for server tunnels it has one entry per target
    /// service, enabling port multiplexing.
    #[serde(default)]
    pub remotes: Vec<RemoteConfig>,

    /// TLS Server Name Indication (SNI) for TLS/QUIC
    pub sni: String,

    /// Skip TLS certificate verification (client mode, typically)
    #[serde(default)]
    pub insecure: bool,

    // ── Legacy fields (kept for backward compatibility) ──────────────
    /// @deprecated Use `remotes[0].addr` instead.
    #[serde(default)]
    pub remote: Option<String>,

    /// @deprecated Use `remotes[0].password` instead.
    #[serde(default)]
    pub password: Option<String>,

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

    /// Returns the normalised list of remote configurations.
    ///
    /// When `remotes` is non-empty it is returned directly.  Otherwise the
    /// legacy `remote`+`password` pair is used to synthesise a single-entry
    /// list.
    pub fn remotes_list(&self) -> anyhow::Result<Vec<RemoteConfig>> {
        if !self.remotes.is_empty() {
            return Ok(self.remotes.clone());
        }
        if let (Some(remote), Some(password)) = (&self.remote, &self.password) {
            return Ok(vec![RemoteConfig {
                addr: remote.clone(),
                password: password.clone(),
            }]);
        }
        anyhow::bail!(
            "tunnel must have either `remotes` (recommended) or `remote`+`password` configured"
        );
    }

    /// Returns the default remote address — the first entry in the remotes
    /// list.  Used by client-mode tunnels.
    pub fn default_remote(&self) -> anyhow::Result<String> {
        self.remotes_list()?
            .first()
            .map(|r| r.addr.clone())
            .ok_or_else(|| anyhow::anyhow!("no remotes configured"))
    }

    /// Returns the default password — the first entry in the remotes list.
    /// Used by client-mode tunnels.
    pub fn default_password(&self) -> anyhow::Result<String> {
        self.remotes_list()?
            .first()
            .map(|r| r.password.clone())
            .ok_or_else(|| anyhow::anyhow!("no remotes configured"))
    }

    /// Returns the remotes list directly (for cases where the caller needs
    /// both password and addr together, e.g. building a sha256→addr map).
    pub fn remotes_vec(&self) -> anyhow::Result<Vec<RemoteConfig>> {
        self.remotes_list()
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
        // Ensure at least one remote is configured
        if t.remotes.is_empty() && t.remote.is_none() {
            anyhow::bail!(
                "tunnel[{i}]: must have `remotes` (recommended) or `remote`+`password` configured"
            );
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
