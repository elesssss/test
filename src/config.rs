use anyhow::Context;
use serde::Deserialize;
use std::collections::HashSet;
use std::net::SocketAddr;

// These structures contain credentials: intentionally do not derive Debug.
#[derive(Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default = "default_log_level")]
    pub log_level: String,
    pub tunnels: Vec<TunnelConfig>,
}

fn default_log_level() -> String { "info".into() }

#[derive(Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct RemoteConfig {
    pub addr: String,
    pub password: String,
}

#[derive(Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct TunnelConfig {
    pub listen: String,
    #[serde(default)]
    pub remotes: Vec<RemoteConfig>,
    #[serde(default)]
    pub sni: String,
    #[serde(default)]
    pub insecure: bool,
    #[serde(default)]
    pub remote: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub cert: Option<String>,
    #[serde(default)]
    pub key: Option<String>,
}

impl TunnelConfig {
    pub fn is_server(&self) -> bool {
        self.cert.is_some() && self.key.is_some()
    }

    pub fn remotes_list(&self) -> anyhow::Result<Vec<RemoteConfig>> {
        if !self.remotes.is_empty() {
            return Ok(self.remotes.clone());
        }
        match (&self.remote, &self.password) {
            (Some(addr), Some(password)) => Ok(vec![RemoteConfig {
                addr: addr.clone(), password: password.clone(),
            }]),
            _ => anyhow::bail!("configure remotes or both remote and password"),
        }
    }

    pub fn default_remote(&self) -> anyhow::Result<String> {
        Ok(self.remotes_list()?.first().context("no remotes configured")?.addr.clone())
    }

    pub fn default_password(&self) -> anyhow::Result<String> {
        Ok(self.remotes_list()?.first().context("no remotes configured")?.password.clone())
    }

    /// Strip IPv6 brackets when deriving a TLS server name from host:port.
    pub fn server_name(&self) -> anyhow::Result<String> {
        let name = if self.sni.is_empty() {
            let remote = self.default_remote()?;
            address_host(&remote)?.to_owned()
        } else { self.sni.clone() };
        rustls::pki_types::ServerName::try_from(name.clone()).context("invalid TLS server name")?;
        Ok(name)
    }
}

fn address_host(addr: &str) -> anyhow::Result<&str> {
    let (host, port) = addr.rsplit_once(':').context("address must include a port")?;
    let port: u16 = port.parse().context("invalid address port")?;
    anyhow::ensure!(port != 0, "remote port must not be zero");
    let host = if host.starts_with('[') && host.ends_with(']') {
        let host = &host[1..host.len() - 1];
        host.parse::<std::net::Ipv6Addr>().context("invalid bracketed IPv6 address")?;
        host
    } else {
        anyhow::ensure!(!host.contains(':') && !host.contains('[') && !host.contains(']'),
            "IPv6 addresses must use [address]:port");
        host
    };
    anyhow::ensure!(!host.is_empty() && !host.chars().any(char::is_whitespace), "invalid address host");
    rustls::pki_types::ServerName::try_from(host.to_owned()).context("invalid address host")?;
    Ok(host)
}

pub fn load_config(path: &str) -> anyhow::Result<Config> {
    let content = std::fs::read_to_string(path).with_context(|| format!("read config {path}"))?;
    // Parser errors can include the offending YAML source line (a secret).
    // Report location only, never echo configuration contents into logs.
    let config: Config = serde_yaml::from_str(&content).map_err(|e| {
        if let Some(location) = e.location() {
            anyhow::anyhow!("invalid YAML config at line {}, column {}", location.line(), location.column())
        } else { anyhow::anyhow!("invalid YAML config") }
    })?;
    anyhow::ensure!(!config.tunnels.is_empty(), "at least one tunnel is required");
    anyhow::ensure!(matches!(config.log_level.as_str(), "trace" | "debug" | "info" | "warn" | "error" | "off"),
        "invalid log_level");
    let mut listens = HashSet::new();
    for (i, tunnel) in config.tunnels.iter().enumerate() {
        let validate = || -> anyhow::Result<()> {
            let listen: SocketAddr = tunnel.listen.parse().context("listen must be an IP address and port")?;
            anyhow::ensure!(listen.port() != 0, "listen port must not be zero");
            anyhow::ensure!(tunnel.cert.is_some() == tunnel.key.is_some(), "cert and key must be configured together");
            anyhow::ensure!(tunnel.remote.is_some() == tunnel.password.is_some(), "legacy remote and password must be configured together");
            anyhow::ensure!(tunnel.remotes.is_empty() || tunnel.remote.is_none(), "do not mix remotes with legacy fields");
            let remotes = tunnel.remotes_list()?;
            anyhow::ensure!(tunnel.is_server() || remotes.len() == 1, "client tunnels require exactly one remote");
            let mut passwords = HashSet::new();
            for remote in &remotes {
                address_host(&remote.addr).context("invalid remote address")?;
                anyhow::ensure!(!remote.password.is_empty(), "password must not be empty");
                anyhow::ensure!(remote.password.len() <= 4096, "password too long");
                anyhow::ensure!(passwords.insert(remote.password.as_str()), "duplicate remote password");
            }
            if tunnel.is_server() {
                for path in [tunnel.cert.as_deref(), tunnel.key.as_deref()].into_iter().flatten() {
                    anyhow::ensure!(std::path::Path::new(path).is_file(), "certificate/key must be a readable file");
                }
                anyhow::ensure!(!tunnel.insecure, "insecure applies only to client tunnels");
            } else {
                tunnel.server_name()?;
            }
            Ok(())
        };
        validate().with_context(|| format!("tunnel[{i}]"))?;
        let listen: SocketAddr = tunnel.listen.parse()?;
        anyhow::ensure!(listens.insert(listen), "tunnel[{i}]: duplicate listen address");
    }
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosts_and_ipv6_brackets_are_validated() {
        assert_eq!(address_host("[::1]:443").unwrap(), "::1");
        assert_eq!(address_host("example.com:443").unwrap(), "example.com");
        for addr in ["::1:443", "host:0", "host:65536", ":443", "bad host:443"] {
            assert!(address_host(addr).is_err());
        }
    }

    #[test]
    fn secrets_are_required_and_unknown_fields_are_rejected() {
        let cfg: TunnelConfig = serde_yaml::from_str("listen: '127.0.0.1:1234'\nremote: 'example.com:443'").unwrap();
        assert!(cfg.remotes_list().is_err());
        assert!(serde_yaml::from_str::<TunnelConfig>("listen: '127.0.0.1:1234'\ninsecur: true").is_err());
    }
}
