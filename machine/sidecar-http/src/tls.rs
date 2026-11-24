//! The API's mutual TLS: the node's server configuration (its certificate, and
//! client certificates required under the deployment CA), the client
//! configuration the orchestrator, and the tests, connect with, and the PEM
//! readers the orchestrator's public listener uses too.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Once};

use eyre::Context;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use serde::Deserialize;

/// The API's mutual-TLS material, PEM files.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsFiles {
    /// The deployment CA: client certificates must chain to it.
    pub ca: PathBuf,
    /// This node's server certificate chain.
    pub cert: PathBuf,
    /// Its private key.
    pub key: PathBuf,
}

/// Pick the process-wide rustls crypto provider once. The dependency graph
/// carries more than one provider, and rustls refuses to guess.
pub fn install_crypto_provider() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        // Another component may have installed one already; either is fine.
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
}

// The API's TLS material and the mutual-TLS rule. Every route of
// the node's HTTPS API is served over TLS 1.2 or 1.3 only, with the node's
// certificate (`[tls] cert` and `key`, PEM), and the handshake requires a
// client certificate that chains to the deployment CA (`[tls] ca`) and
// carries the clientAuth usage: a client with no certificate, with one under
// another CA, or presenting a server certificate is refused during the
// handshake, before any route runs. The deployment CA is the orchestrator's:
// it issues the orchestrator's client certificate, and nobody else should
// hold a certificate under it with clientAuth, because every holder can drive
// the node (execute, register, disable, fetch). The node does not pin the
// orchestrator's certificate itself, so the operator can renew it under the
// same CA without touching the nodes; revoking it means replacing the CA. The
// development set (`sidecar-node gen-certs`, scripts/gen-dev-certs.sh) is one
// dev CA with three node certificates and the orchestrator's; a deployment
// brings its own. Only HTTP/1.1 is offered (ALPN `http/1.1`).
/// The API's server configuration from the PEM files of `files`.
pub fn server_config(files: &TlsFiles) -> eyre::Result<Arc<ServerConfig>> {
    install_crypto_provider();
    let roots = root_store(&files.ca)?;
    let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .context("building the client-certificate verifier")?;
    let mut config = ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(read_certs(&files.cert)?, read_key(&files.key)?)
        .with_context(|| format!("the server certificate {}", files.cert.display()))?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

/// A server configuration with the certificate chain `cert` and its `key`
/// that asks no client certificate (the orchestrator's public listener):
/// TLS 1.2 or 1.3, HTTP/1.1 only.
pub fn public_server_config(cert: &Path, key: &Path) -> eyre::Result<Arc<ServerConfig>> {
    install_crypto_provider();
    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(read_certs(cert)?, read_key(key)?)
        .with_context(|| format!("the server certificate {}", cert.display()))?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

/// A client configuration that trusts `ca` for the server and presents
/// `identity` (certificate chain, key; PEM) when given.
pub fn client_config(
    ca: &Path,
    identity: Option<(&Path, &Path)>,
) -> eyre::Result<Arc<ClientConfig>> {
    install_crypto_provider();
    let builder = ClientConfig::builder().with_root_certificates(root_store(ca)?);
    let mut config = match identity {
        Some((cert, key)) => builder
            .with_client_auth_cert(read_certs(cert)?, read_key(key)?)
            .with_context(|| format!("the client certificate {}", cert.display()))?,
        None => builder.with_no_client_auth(),
    };
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

fn root_store(ca: &Path) -> eyre::Result<RootCertStore> {
    let mut roots = RootCertStore::empty();
    for cert in read_certs(ca)? {
        roots
            .add(cert)
            .with_context(|| format!("the CA certificate {}", ca.display()))?;
    }
    Ok(roots)
}

/// Every certificate in a PEM file (at least one).
fn read_certs(path: &Path) -> eyre::Result<Vec<CertificateDer<'static>>> {
    let certs = CertificateDer::pem_file_iter(path)
        .with_context(|| format!("reading {}", path.display()))?
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| format!("parsing {}", path.display()))?;
    eyre::ensure!(!certs.is_empty(), "{} holds no certificate", path.display());
    Ok(certs)
}

/// The private key of a PEM file.
pub fn read_key(path: &Path) -> eyre::Result<PrivateKeyDer<'static>> {
    PrivateKeyDer::from_pem_file(path)
        .with_context(|| format!("reading the key {}", path.display()))
}
