//! mTLS transport for the Sliver operator gRPC API.
//!
//! Sliver deliberately skips server hostname verification: operator configs
//! often carry an `lhost` that differs from the randomly-named server
//! certificate, so the official client validates only that the server
//! certificate chains to the pinned operator CA (see Go `RootOnlyVerifyCertificate`).
//! We faithfully reproduce that here with a custom rustls verifier, while still
//! presenting our client certificate for mutual auth.

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};

use crate::config::OperatorConfig;

/// Server certificate verifier that checks the chain against the pinned CA
/// but ignores the hostname — matching Sliver's client behaviour.
#[derive(Debug)]
struct CaOnlyVerifier {
    roots: Vec<CertificateDer<'static>>,
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for CaOnlyVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        // Build trust anchors from the pinned CA certificate(s).
        let anchors: Vec<_> = self
            .roots
            .iter()
            .map(|c| webpki::anchor_from_trusted_cert(c))
            .collect::<Result<_, _>>()
            .map_err(|e| rustls::Error::General(format!("invalid CA certificate: {e}")))?;

        let cert = webpki::EndEntityCert::try_from(end_entity)
            .map_err(|e| rustls::Error::General(format!("invalid server certificate: {e}")))?;

        // Verify the chain for server auth, ignoring the DNS/IP name entirely.
        cert.verify_for_usage(
            webpki::ALL_VERIFICATION_ALGS,
            &anchors,
            intermediates,
            now,
            webpki::KeyUsage::server_auth(),
            None,
            None,
        )
        .map_err(|e| rustls::Error::General(format!("certificate not signed by operator CA: {e}")))?;

        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

/// Build a rustls `ClientConfig` from an operator config: presents the operator
/// client certificate and verifies the server against the operator CA only.
pub fn build_client_config(cfg: &OperatorConfig) -> anyhow::Result<Arc<ClientConfig>> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());

    // Parse the pinned CA certificate(s).
    let roots = read_certs(cfg.ca_certificate.as_bytes())?;
    if roots.is_empty() {
        anyhow::bail!("operator config contains no CA certificate");
    }

    // Parse our client certificate + private key for mutual TLS.
    let client_certs = read_certs(cfg.certificate.as_bytes())?;
    if client_certs.is_empty() {
        anyhow::bail!("operator config contains no client certificate");
    }
    let client_key = read_private_key(cfg.private_key.as_bytes())?;

    let verifier = Arc::new(CaOnlyVerifier {
        roots,
        provider: provider.clone(),
    });

    let config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_auth_cert(client_certs, client_key)?;

    // Sliver's gRPC server negotiates HTTP/2 via ALPN; advertise it so the TLS
    // layer routes us to the gRPC handler rather than closing the connection.
    let mut config = config;
    config.alpn_protocols = vec![b"h2".to_vec()];

    Ok(Arc::new(config))
}

fn read_certs(pem: &[u8]) -> anyhow::Result<Vec<CertificateDer<'static>>> {
    let mut reader = std::io::BufReader::new(pem);
    let certs = rustls_pemfile::certs(&mut reader).collect::<Result<Vec<_>, _>>()?;
    Ok(certs)
}

fn read_private_key(pem: &[u8]) -> anyhow::Result<PrivateKeyDer<'static>> {
    let mut reader = std::io::BufReader::new(pem);
    let key = rustls_pemfile::private_key(&mut reader)?
        .ok_or_else(|| anyhow::anyhow!("no private key found in operator config"))?;
    Ok(key)
}

/// Resolve a rustls `ServerName` for the TLS handshake. Because our verifier
/// ignores the name we only need something syntactically valid; we prefer the
/// configured host and fall back to a placeholder.
pub fn server_name_for(host: &str) -> ServerName<'static> {
    ServerName::try_from(host.to_string())
        .unwrap_or_else(|_| ServerName::try_from("sliver".to_string()).unwrap())
}
