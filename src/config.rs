use serde::Deserialize;

/// A single backend target with its own authentication password.
///
/// In server mode the password is used to **match** the client's auth;
/// in client mode it is the password sent to authenticate to the server.
#[derive(Debug, Clone)]
pub struct RemoteEntry {
    /// Target address as "host:port".
    pub addr: String,
    /// Authentication password for this backend.
    pub password: String,
}

/// Custom deserializer for `Vec<RemoteEntry>`.
///
/// Accepts three YAML shapes (backward-compatible):
///
/// 1. Single string:
///    ```yaml
///    remote: "host:port"
///    ```
///    → `[{addr: "host:port", password: ""}]`  (filled later from tunnel-level `password`)
///
/// 2. List of strings:
///    ```yaml
///    remote:
///      - "host1:port"
///      - "host2:port"
///    ```
///    → passwords filled from tunnel-level `password`
///
/// 3. List of objects:
///    ```yaml
///    remotes:
///      - addr: "host1:port"
///        password: "pass1"
///      - addr: "host2:port"
///        password: "pass2"
///    ```
///    → self-contained, tunnel-level `password` ignored.
fn deserialize_remotes<'de, D>(deserializer: D) -> Result<Vec<RemoteEntry>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::{self, SeqAccess, Visitor};
    use std::fmt;

    #[derive(Deserialize)]
    #[serde(untagged)]
    enum RawItem {
        Str(String),
        Obj(RemoteEntryRaw),
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "lowercase")]
    struct RemoteEntryRaw {
        addr: String,
        #[serde(default)]
        password: String,
    }

    struct RemotesVisitor;

    impl<'de> Visitor<'de> for RemotesVisitor {
        type Value = Vec<RemoteEntry>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a string, a list of strings, or a list of {addr, password} objects")
        }

        // Single string: remote: "host:port"
        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(vec![RemoteEntry {
                addr: value.to_string(),
                password: String::new(),
            }])
        }

        // List: either strings or objects
        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let mut remotes = Vec::new();
            while let Some(elem) = seq.next_element::<RawItem>()? {
                match elem {
                    RawItem::Str(s) => remotes.push(RemoteEntry {
                        addr: s,
                        password: String::new(),
                    }),
                    RawItem::Obj(o) => remotes.push(RemoteEntry {
                        addr: o.addr,
                        password: o.password,
                    }),
                }
            }
            if remotes.is_empty() {
                return Err(de::Error::invalid_length(0, &"at least one remote"));
            }
            Ok(remotes)
        }
    }

    deserializer.deserialize_any(RemotesVisitor)
}

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

    /// Backend target(s).
    ///
    /// - **Server mode**: each `RemoteEntry` defines a backend (`addr`) and
    ///   the password a client must authenticate with to reach it.
    /// - **Client mode**: the first entry's `addr` is the upstream server,
    ///   and its `password` is used for authentication.
    #[serde(deserialize_with = "deserialize_remotes")]
    pub remotes: Vec<RemoteEntry>,

    /// TLS Server Name Indication (SNI) for TLS/QUIC
    pub sni: String,

    /// Skip TLS certificate verification (client mode, typically)
    #[serde(default)]
    pub insecure: bool,

    /// Fallback / shared authentication password.
    ///
    /// Only used when `remotes` entries are plain strings (old config format).
    /// When each remote entry already carries its own `password`, this field
    /// is ignored.
    #[serde(default)]
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

    /// Returns the first remote's address (client-mode upstream).
    pub fn remote(&self) -> &str {
        &self.remotes[0].addr
    }
}

/// Load, normalize, and validate the YAML config file.
pub fn load_config(path: &str) -> anyhow::Result<Config> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("failed to read config file '{}': {}", path, e))?;
    let mut config: Config = serde_yaml::from_str(&content)
        .map_err(|e| anyhow::anyhow!("failed to parse config: {}", e))?;

    // Normalize: fill empty passwords from the tunnel-level fallback.
    for (i, t) in config.tunnels.iter_mut().enumerate() {
        if t.remotes.is_empty() {
            anyhow::bail!("tunnel[{}]: at least one remote address is required", i);
        }
        for (j, r) in t.remotes.iter_mut().enumerate() {
            if r.password.is_empty() {
                if t.password.is_empty() {
                    anyhow::bail!(
                        "tunnel[{}].remotes[{}]: no password set (add `password:` to the remote entry or at tunnel level)",
                        i, j
                    );
                }
                r.password = t.password.clone();
            }
        }
        if t.is_server() {
            let cert_path = t.cert.as_ref().unwrap();
            let key_path = t.key.as_ref().unwrap();
            if !std::path::Path::new(cert_path).exists() {
                anyhow::bail!("tunnel[{}]: certificate file not found: {}", i, cert_path);
            }
            if !std::path::Path::new(key_path).exists() {
                anyhow::bail!("tunnel[{}]: key file not found: {}", i, key_path);
            }
        }
    }

    Ok(config)
}
