use anyhow::Context;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::io::BufReader;
use std::sync::Arc;
use std::time::Duration;

/// Load a certificate chain from a PEM file.
pub fn load_certs(path: &str) -> anyhow::Result<Vec<CertificateDer<'static>>> {
    let file = std::fs::File::open(path)
        .with_context(|| format!("failed to open cert file: {}", path))?;
    let mut reader = BufReader::new(file);
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut reader)
        .collect::<Result<_, _>>()
        .with_context(|| format!("failed to parse cert file: {}", path))?;
    if certs.is_empty() {
        anyhow::bail!("no certificates found in {}", path);
    }
    Ok(certs)
}

/// Load a private key from a PEM file.
pub fn load_private_key(path: &str) -> anyhow::Result<PrivateKeyDer<'static>> {
    let file = std::fs::File::open(path)
        .with_context(|| format!("failed to open key file: {}", path))?;
    let mut reader = BufReader::new(file);
    loop {
        match rustls_pemfile::read_one(&mut reader)
            .with_context(|| format!("failed to read key from {}", path))?
        {
            Some(rustls_pemfile::Item::Pkcs1Key(key)) => return Ok(key.into()),
            Some(rustls_pemfile::Item::Pkcs8Key(key)) => return Ok(key.into()),
            Some(rustls_pemfile::Item::Sec1Key(key)) => return Ok(key.into()),
            None => anyhow::bail!("no private key found in {}", path),
            _ => continue,
        }
    }
}

/// Build a `rustls::ServerConfig` with the given certificate and key.
pub fn build_rustls_server_config(
    cert_path: &str,
    key_path: &str,
) -> anyhow::Result<rustls::ServerConfig> {
    let certs = load_certs(cert_path)?;
    let key = load_private_key(key_path)?;

    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("failed to build TLS server config")?;
    config.alpn_protocols = vec![b"anyst-01".to_vec()];
    Ok(config)
}

/// Build a `rustls::ClientConfig`.
///
/// `insecure` skips chain/hostname checks, but still verifies the handshake
/// signature. Prefer trusted certificates with a matching server name.
pub fn build_rustls_client_config(insecure: bool) -> anyhow::Result<rustls::ClientConfig> {
    let builder = rustls::ClientConfig::builder();
    let mut config = if insecure {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoCertificateVerification))
            .with_no_client_auth()
    } else {
        let mut root_store = rustls::RootCertStore::empty();
        let native = rustls_native_certs::load_native_certs();
        for cert in native.certs {
            if let Err(e) = root_store.add(cert) {
                tracing::warn!("skipping invalid system trust root: {e}");
            }
        }
        for err in native.errors {
            tracing::warn!("failed to load system trust roots: {err}");
        }
        anyhow::ensure!(!root_store.is_empty(), "no usable system trust roots");
        builder
            .with_root_certificates(root_store)
            .with_no_client_auth()
    };
    config.alpn_protocols = vec![b"anyst-01".to_vec()];
    Ok(config)
}

/// Build a `quinn::ServerConfig` for QUIC (UDP tunnel), sharing the same TLS
/// certificate.
pub fn build_quic_server_config(
    rustls_config: rustls::ServerConfig,
) -> anyhow::Result<quinn::ServerConfig> {
    let quic_crypto = quinn::crypto::rustls::QuicServerConfig::try_from(rustls_config)
        .map_err(|e| anyhow::anyhow!("failed to create QUIC server crypto config: {e}"))?;
    let mut config = quinn::ServerConfig::with_crypto(Arc::new(quic_crypto));
    let mut transport = quinn::TransportConfig::default();
    transport.max_concurrent_bidi_streams(0u32.into());
    transport.max_concurrent_uni_streams(32u32.into());
    transport.datagram_receive_buffer_size(Some(65536));
    // Use a very long idle timeout (1 hour) instead of 0 which may cause issues.
    transport.max_idle_timeout(Some(quinn::VarInt::from_u32(3_600_000).into()));
    // Send PING frames every 15 s to keep NAT / firewall state alive.
    transport.keep_alive_interval(Some(Duration::from_secs(15)));
    config.transport_config(Arc::new(transport));
    Ok(config)
}

/// Build a `quinn::ClientConfig` for QUIC (UDP tunnel), sharing the same TLS
/// config.
pub fn build_quic_client_config(
    rustls_config: rustls::ClientConfig,
) -> anyhow::Result<quinn::ClientConfig> {
    let quic_crypto = quinn::crypto::rustls::QuicClientConfig::try_from(rustls_config)
        .map_err(|e| anyhow::anyhow!("failed to create QUIC client crypto config: {e}"))?;
    let mut config = quinn::ClientConfig::new(Arc::new(quic_crypto));
    let mut transport = quinn::TransportConfig::default();
    transport.max_concurrent_bidi_streams(0u32.into());
    transport.max_concurrent_uni_streams(32u32.into());
    transport.datagram_receive_buffer_size(Some(65536));
    // Use a very long idle timeout (1 hour).
    transport.max_idle_timeout(Some(quinn::VarInt::from_u32(3_600_000).into()));
    // Send PING frames every 15 s to keep NAT / firewall state alive.
    transport.keep_alive_interval(Some(Duration::from_secs(15)));
    config.transport_config(Arc::new(transport));
    Ok(config)
}

// ---------------------------------------------------------------------------
// Insecure certificate verifier (accepts everything)
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct NoCertificateVerification;

impl rustls::client::danger::ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message, cert, dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message, cert, dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms.supported_schemes()
    }
}
