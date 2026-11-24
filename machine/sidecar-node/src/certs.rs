//! Development TLS material, generated with rcgen. Two independent planes:
//!
//! ```text
//! mesh (node <-> node, DER)       mesh-key{i}.der, mesh-cert{i}.der        i = 0, 1, 2
//!     one self-signed certificate per party; every party config pins all three
//! HTTPS (orchestrator -> node, PEM, mutual TLS under one dev CA)
//!     https-ca.pem, https-ca-key.pem                                       the dev CA
//!     https-node{i}.pem, https-node{i}-key.pem                             node i's server certificate
//!     https-orchestrator.pem, https-orchestrator-key.pem                   the orchestrator's client certificate
//! ```
//!
//! Server certificates name `localhost` and `127.0.0.1`. Generation is
//! idempotent per plane: a plane whose files all exist is kept; a plane with
//! any file missing is generated again as a whole (its certificates pin or
//! chain to each other, so a partial plane is useless). `force` regenerates
//! both.

// These certificates are development material only, never
// deployment credentials. Their keys are written unencrypted beside the
// configs, the CA key sits next to the certificates it signed, and they carry
// rcgen's default validity (no practical expiry). A deployment replaces the
// whole set: each node operator makes its own mesh key and certificate and
// publishes the certificate, every party config pins the three published
// certificates (the pin is the mesh's only authentication: a peer whose
// certificate is not pinned for its seat cannot join), and the HTTPS leg uses
// the deployment's CA, a server certificate per node and the orchestrator's
// client certificate.

use std::path::{Path, PathBuf};

use eyre::Context;
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose,
};

use crate::files::{create_private_dir, write_file};

use sidecar_core::request::NODES;

/// One party's mesh identity: its PKCS#8 DER key and self-signed DER
/// certificate.
#[derive(Clone, Debug)]
pub struct MeshIdentity {
    pub key: Vec<u8>,
    pub cert: Vec<u8>,
}

/// The names every development certificate of node `party` carries.
pub fn node_names(party: usize) -> Vec<String> {
    vec![
        "localhost".into(),
        "127.0.0.1".into(),
        format!("sidecar-node-{party}"),
    ]
}

/// A fresh self-signed mesh certificate for `party`, valid for
/// [`node_names`].
pub fn mesh_identity(party: usize) -> eyre::Result<MeshIdentity> {
    let key = KeyPair::generate()?;
    let mut params = CertificateParams::new(node_names(party))?;
    params
        .distinguished_name
        .push(DnType::CommonName, format!("sidecar mesh party {party}"));
    let cert = params.self_signed(&key)?;
    Ok(MeshIdentity {
        key: key.serialize_der(),
        cert: cert.der().to_vec(),
    })
}

/// The file names of the mesh plane for `party`: (key, certificate).
pub fn mesh_files(party: usize) -> (String, String) {
    (
        format!("mesh-key{party}.der"),
        format!("mesh-cert{party}.der"),
    )
}

fn https_files() -> Vec<String> {
    let mut names = vec!["https-ca.pem".to_string(), "https-ca-key.pem".to_string()];
    for i in 0..NODES {
        names.push(format!("https-node{i}.pem"));
        names.push(format!("https-node{i}-key.pem"));
    }
    names.push("https-orchestrator.pem".into());
    names.push("https-orchestrator-key.pem".into());
    names
}

/// What [`generate`] did with each plane.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Generated {
    /// Files written this time.
    pub written: Vec<PathBuf>,
    /// Files kept from an earlier run.
    pub kept: Vec<PathBuf>,
}

/// Write the two planes into `out` (created with mode 0700), keeping a
/// complete plane unless `force`.
pub fn generate(out: &Path, force: bool) -> eyre::Result<Generated> {
    create_private_dir(out).with_context(|| format!("creating {}", out.display()))?;
    let mut done = Generated::default();

    let mesh_names: Vec<String> = (0..NODES)
        .flat_map(|i| {
            let (k, c) = mesh_files(i);
            [k, c]
        })
        .collect();
    if !force && all_exist(out, &mesh_names) {
        done.kept.extend(mesh_names.iter().map(|n| out.join(n)));
    } else {
        for i in 0..NODES {
            let id = mesh_identity(i)?;
            let (k, c) = mesh_files(i);
            write_file(&out.join(&k), &id.key, true)?;
            write_file(&out.join(&c), &id.cert, false)?;
            done.written.extend([out.join(k), out.join(c)]);
        }
    }

    let https_names = https_files();
    if !force && all_exist(out, &https_names) {
        done.kept.extend(https_names.iter().map(|n| out.join(n)));
    } else {
        for (name, pem, secret) in https_plane()? {
            write_file(&out.join(&name), pem.as_bytes(), secret)?;
            done.written.push(out.join(name));
        }
    }
    Ok(done)
}

/// One plane's files as (file name, PEM, is a private key).
type PlaneFiles = Vec<(String, String, bool)>;

/// A fresh development CA named `cn`, written to `{prefix}.pem` and
/// `{prefix}-key.pem` in `files`.
fn dev_ca(
    cn: &str,
    prefix: &str,
    files: &mut PlaneFiles,
) -> eyre::Result<CertifiedIssuer<'static, KeyPair>> {
    let ca_key = KeyPair::generate()?;
    let mut ca_params = CertificateParams::new(Vec::<String>::new())?;
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    ca_params.distinguished_name.push(DnType::CommonName, cn);
    let ca_pem_key = ca_key.serialize_pem();
    let ca = CertifiedIssuer::self_signed(ca_params, ca_key)?;
    files.push((format!("{prefix}.pem"), ca.pem(), false));
    files.push((format!("{prefix}-key.pem"), ca_pem_key, true));
    Ok(ca)
}

/// A certificate under `issuer` for `names` with the extended usage
/// `usage`, as (certificate PEM, key PEM).
fn dev_leaf(
    issuer: &Issuer<'_, KeyPair>,
    names: Vec<String>,
    cn: String,
    usage: ExtendedKeyUsagePurpose,
) -> eyre::Result<(String, String)> {
    let key = KeyPair::generate()?;
    let mut params = CertificateParams::new(names)?;
    params.distinguished_name.push(DnType::CommonName, cn);
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    params.extended_key_usages = vec![usage];
    params.use_authority_key_identifier_extension = true;
    let cert = params.signed_by(&key, issuer)?;
    Ok((cert.pem(), key.serialize_pem()))
}

// The HTTPS plane.
fn https_plane() -> eyre::Result<PlaneFiles> {
    let mut files = Vec::new();
    let ca = dev_ca("sidecar dev CA", "https-ca", &mut files)?;
    let leaf = |names, cn, usage| dev_leaf(&ca, names, cn, usage);
    for i in 0..NODES {
        let (cert, key) = leaf(
            node_names(i),
            format!("sidecar-node-{i}"),
            ExtendedKeyUsagePurpose::ServerAuth,
        )?;
        files.push((format!("https-node{i}.pem"), cert, false));
        files.push((format!("https-node{i}-key.pem"), key, true));
    }
    let (cert, key) = leaf(
        vec!["sidecar-orchestrator".into()],
        "sidecar-orchestrator".into(),
        ExtendedKeyUsagePurpose::ClientAuth,
    )?;
    files.push(("https-orchestrator.pem".into(), cert, false));
    files.push(("https-orchestrator-key.pem".into(), key, true));
    Ok(files)
}

fn all_exist(dir: &Path, names: &[String]) -> bool {
    names.iter().all(|n| dir.join(n).is_file())
}
