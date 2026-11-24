//! The node's configuration file (TOML): which party it is, where its API
//! listens, its mesh config, the mutual-TLS material of the API, the store
//! backend, the CRS and circuit data, the key directory, the run directory
//! with the admin socket, the `requests` retention and pruning settings, the
//! grace window of an `enc` rotation, the tip's receipt TTL, and the tip's
//! `[tip]` section (the Aztec node the chain verifier and the receipt
//! pruning read, and the namespaces they check).
//! Relative paths resolve against the directory of the config file, as the
//! mesh config's TLS paths do.
//!
//! ```toml
//! party = 0
//! api_listen = "127.0.0.1:8200"
//! mesh_config = "party0.toml"
//! mesh_session_timeout_secs = 3600   # one MPC session at most (the default)
//! key_dir = "../../../data/keys/node0"
//! run_dir = "../../../data/run/node0"
//! # admin_socket = "../../../data/run/node0/admin.sock"   (the default)
//! requests_retention_days = 30
//! prune_interval_secs = 3600
//! enc_grace_days = 30
//! receipt_ttl_blocks = 300        # the tip's receipts
//! receipt_allowance_blocks = 10
//!
//! [tls]
//! ca = "../../../data/keys/https-ca.pem"
//! cert = "../../../data/keys/https-node0.pem"
//! key = "../../../data/keys/https-node0-key.pem"
//!
//! [store]
//! backend = "memory"          # or "postgres" with url = "...", or "local" with path = "..."
//!
//! [crs]
//! g1 = "../../../data/bn254_g1.dat"
//! g2 = "../../../data/bn254_g2.dat"
//! circuits_dir = "../../../data/circuits"
//!
//! [tip]                       # optional: the chain verifier (tip namespaces)
//! aztec_node = "http://127.0.0.1:8380"
//! block_time_secs = 36        # the enc grace check's block time (the default)
//! [[tip.namespaces]]
//! contract = "0x2f01"         # the app contract: the namespace (its slots come from its contract manifest)
//! ```
//!
//! [`ConfigArgs`] reads the file and applies the command-line (or
//! environment) overrides the harness uses to move ports and sockets.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use eyre::{Context, ensure};
use serde::Deserialize;
pub use sidecar_core::crs::CrsFiles;
use sidecar_core::keys::KeyFiles;
use sidecar_core::manifest::DEFAULT_STALE_BLOCKS;
use sidecar_core::registry::RegisterHook;
use sidecar_http::admin::{ADMIN_SOCKET_FILE, check_path, normalize};
pub use sidecar_http::tls::TlsFiles;
use sidecar_tip::{AztecNode, DEFAULT_BLOCK_TIME_SECS, ReceiptLife, TipNamespace};

use crate::mesh::MeshConfig;
use crate::receipt::{DEFAULT_RECEIPT_ALLOWANCE_BLOCKS, DEFAULT_RECEIPT_TTL_BLOCKS, ReceiptConfig};

// Operator knob: DESIGN.md, "Configuration reference" (`api_listen`). The
// development node configs serve node j on 127.0.0.1:8200 + j; `--api-listen`
// (NODE_API_LISTEN) overrides it, port 0 included (the tests' free port).
/// The harness's first API port: node j listens on `DEFAULT_API_BASE_PORT + j`.
pub const DEFAULT_API_BASE_PORT: u16 = 8200;

// Operator knob: DESIGN.md, "Configuration reference"
// (`requests_retention_days`). Default 30 days, at least 1; the pruning job
// deletes the `requests` rows created before `now - retention`.
/// The default `requests` retention (ARCHITECTURE.md section 1, the store trait).
pub const DEFAULT_REQUESTS_RETENTION_DAYS: u64 = 30;

// Operator knob: DESIGN.md, "Configuration reference"
// (`prune_interval_secs`). Default one hour, 0 turns the timer off.
/// The default interval of the pruning job, in seconds (one hour; 0 turns
/// the timer off, for a deployment that runs `sidecar-node prune` from
/// cron). The job runs at start and then every `prune_interval_secs`: it
/// deletes the `requests` rows past `requests_retention_days`, the receipts
/// past their window, and on a node with `[tip]` marks every node-held tip
/// key's versions against the node's own chain view and deletes the orphans
/// marked below the settled block (the finalized tip), so a row or an idle key's orphan lives at most
/// one interval past its window; under secret-shared on-chain intake it records
/// each contract epoch's `enc` scalar once its rotation has landed and
/// retires the scalars no queued request can name
/// (`rotation::observe_epochs`). The operator's reference: DESIGN.md,
/// "Retention and pruning".
pub const DEFAULT_PRUNE_INTERVAL_SECS: u64 = 3600;

// Operator knob: DESIGN.md, "Configuration reference" (`enc_grace_days`).
// Default 30 days, at least 1, and with `[tip]` at least the life of a receipt
// (`sidecar_tip::check_enc_grace`).
/// The default grace window of an enc rotation, in days.
pub const DEFAULT_ENC_GRACE_DAYS: u64 = 30;

// Operator knob: DESIGN.md, "Configuration reference" (`[store] backend`):
// `memory` (tests and development, lost on exit), `postgres` (node-held keys)
// or `local` (client-held keys only).
/// Where a node keeps its tables. Its `Debug` leaves out a Postgres URL,
/// which may carry a password.
#[derive(Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "backend", rename_all = "lowercase")]
pub enum StoreConfig {
    /// In memory; lost on exit (tests and the in-process suites).
    Memory,
    /// Postgres, for node-held keys.
    Postgres { url: String },
    /// The local append-only file store, for deployments whose keys are all
    /// client-held.
    Local { path: PathBuf },
}

impl std::fmt::Debug for StoreConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreConfig::Memory => f.write_str("Memory"),
            StoreConfig::Postgres { .. } => f.write_str("Postgres { url: <not shown> }"),
            StoreConfig::Local { path } => f.debug_struct("Local").field("path", path).finish(),
        }
    }
}

fn default_retention_days() -> u64 {
    DEFAULT_REQUESTS_RETENTION_DAYS
}

fn default_prune_interval_secs() -> u64 {
    DEFAULT_PRUNE_INTERVAL_SECS
}

fn default_enc_grace_days() -> u64 {
    DEFAULT_ENC_GRACE_DAYS
}

fn default_receipt_ttl_blocks() -> u32 {
    DEFAULT_RECEIPT_TTL_BLOCKS
}

fn default_mesh_session_timeout_secs() -> u64 {
    crate::mesh::DEFAULT_SESSION_TIMEOUT.as_secs()
}

fn default_receipt_allowance_blocks() -> u32 {
    DEFAULT_RECEIPT_ALLOWANCE_BLOCKS
}

/// One node's configuration, with every path resolved.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeConfig {
    /// This node's party index: 0, 1 or 2. Must equal `my_id` in the mesh config.
    pub party: usize,
    /// Where the HTTPS API listens.
    pub api_listen: SocketAddr,
    /// The party mesh config (TOML: my_id, bind_addr, parties, [tls]); relative
    /// TLS paths in it resolve against its own directory.
    pub mesh_config: PathBuf,
    // Operator knob: DESIGN.md, "Configuration reference" (mesh `bind_addr`,
    // `mesh_base_port`). The development party configs put party j's mesh on
    // 127.0.0.1:10200 + j; `--mesh-base-port` moves all three together.
    /// Move the mesh to ports base, base + 1 and base + 2 (party j on base + j),
    /// overriding the ports in the mesh config.
    #[serde(default)]
    pub mesh_base_port: Option<u16>,
    /// The bound on one whole MPC session, in seconds: default 3600
    /// ([`crate::mesh::DEFAULT_SESSION_TIMEOUT`]); a send or receive after it
    /// fails the session.
    #[serde(default = "default_mesh_session_timeout_secs")]
    pub mesh_session_timeout_secs: u64,
    /// The node's key directory (enc.key, sig.key, master.share).
    pub key_dir: PathBuf,
    /// The node's run directory: the admin socket lives here.
    pub run_dir: PathBuf,
    /// The admin socket; `<run_dir>/admin.sock` when absent.
    #[serde(default)]
    pub admin_socket: Option<PathBuf>,
    /// How long `requests` rows are kept.
    #[serde(default = "default_retention_days")]
    pub requests_retention_days: u64,
    /// How often the pruning job runs; 0 turns the timer off.
    #[serde(default = "default_prune_interval_secs")]
    pub prune_interval_secs: u64,
    /// How long the previous enc key is kept after a rotation.
    #[serde(default = "default_enc_grace_days")]
    pub enc_grace_days: u64,
    /// How many L2 blocks a receipt lives: default 300
    /// ([`DEFAULT_RECEIPT_TTL_BLOCKS`]), at least 1.
    #[serde(default = "default_receipt_ttl_blocks")]
    pub receipt_ttl_blocks: u32,
    /// How far past the TTL an expiry may be: default 10 blocks
    /// ([`DEFAULT_RECEIPT_ALLOWANCE_BLOCKS`]).
    #[serde(default = "default_receipt_allowance_blocks")]
    pub receipt_allowance_blocks: u32,
    pub tls: TlsFiles,
    pub store: StoreConfig,
    pub crs: CrsFiles,
    /// The tip's chain verifier; `None` (no `[tip]` section): every queued
    /// round is refused at step 4 and every receipt request at the receipt
    /// route; intake direct is unchanged.
    #[serde(default)]
    pub tip: Option<TipConfig>,
}

// Operator knob: DESIGN.md, "Configuration reference" (`[tip]`). Optional;
// without it the node reads no chain and refuses every queued round and every
// receipt request (400), so a tip deployment configures it on all three nodes.
/// The `[tip]` section: the Aztec node this node's chain verifier and
/// receipt pruning read, and the namespaces they check.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TipConfig {
    /// The Aztec node this node's chain verifier, receipt signer and
    /// receipt pruning read: its own, never the orchestrator's.
    #[serde(flatten)]
    pub aztec_node: AztecNode,
    /// The L2 block time, in seconds, at which the `enc` grace window is
    /// checked against the receipt life
    /// ([`check_enc_grace`](sidecar_tip::check_enc_grace)); default
    /// [`DEFAULT_BLOCK_TIME_SECS`] (36, one Aztec slot); at least 1.
    #[serde(default = "default_block_time_secs")]
    pub block_time_secs: u64,
    /// The namespaces whose queued rounds this node runs; at least one;
    /// the same entries as the orchestrator's `[tip]`.
    pub namespaces: Vec<TipNamespace>,
}

fn default_block_time_secs() -> u64 {
    DEFAULT_BLOCK_TIME_SECS
}

impl TipConfig {
    /// The shared `[tip]` checks, and the node's `enc` grace window
    /// (`enc_grace_secs`) against the life of the receipts it signs, `life`
    /// (at the manifest default stale period; REGISTER checks each secret-shared
    /// receipt package's own, [`NodeConfig::register_check`]).
    fn check(&self, enc_grace_secs: u64, life: ReceiptLife) -> eyre::Result<()> {
        sidecar_tip::check_tip(&self.aztec_node, &self.namespaces)?;
        sidecar_tip::check_enc_grace(enc_grace_secs, life)
    }
}

impl NodeConfig {
    /// Read a node config file; relative paths resolve against its directory.
    pub fn load(path: &Path) -> eyre::Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading the node config {}", path.display()))?;
        let base = path.parent().unwrap_or(Path::new("."));
        Self::from_toml(&text, base).with_context(|| format!("node config {}", path.display()))
    }

    /// Parse a node config whose relative paths resolve against `base`.
    pub fn from_toml(text: &str, base: &Path) -> eyre::Result<Self> {
        let mut config: NodeConfig = toml::from_str(text).context("parsing")?;
        config.resolve(base);
        config.check()?;
        Ok(config)
    }

    fn resolve(&mut self, base: &Path) {
        let resolve = |p: &mut PathBuf| {
            if p.is_relative() {
                *p = normalize(&base.join(&*p));
            }
        };
        resolve(&mut self.mesh_config);
        resolve(&mut self.key_dir);
        resolve(&mut self.run_dir);
        if let Some(p) = &mut self.admin_socket {
            resolve(p);
        }
        resolve(&mut self.tls.ca);
        resolve(&mut self.tls.cert);
        resolve(&mut self.tls.key);
        if let StoreConfig::Local { path } = &mut self.store {
            resolve(path);
        }
        resolve(&mut self.crs.g1);
        resolve(&mut self.crs.g2);
        if let Some(p) = &mut self.crs.circuits_dir {
            resolve(p);
        }
        if let Some(p) = self.tip.as_mut().and_then(|t| t.aztec_node.ca.as_mut()) {
            resolve(p);
        }
    }

    fn check(&self) -> eyre::Result<()> {
        ensure!(
            self.party < sidecar_core::request::NODES,
            "party {} is not 0, 1 or 2",
            self.party
        );
        ensure!(
            self.requests_retention_days > 0,
            "requests_retention_days must be at least 1"
        );
        ensure!(self.enc_grace_days > 0, "enc_grace_days must be at least 1");
        ensure!(
            self.receipt_ttl_blocks > 0,
            "receipt_ttl_blocks must be at least 1"
        );
        check_path(
            &self.admin_socket(),
            "set a shorter run_dir or admin_socket",
        )?;
        if let Some(tip) = &self.tip {
            tip.check(self.enc_grace_secs(), self.receipt_life())?;
        }
        Ok(())
    }

    /// The mesh config, with the base-port override applied, checked against
    /// this node's party index.
    pub fn mesh(&self) -> eyre::Result<MeshConfig> {
        ensure!(
            self.mesh_session_timeout_secs > 0,
            "mesh_session_timeout_secs must be at least 1"
        );
        let mut mesh = MeshConfig::load(&self.mesh_config)?
            .with_session_timeout(Duration::from_secs(self.mesh_session_timeout_secs));
        if let Some(base) = self.mesh_base_port {
            mesh = mesh.with_base_port(base)?;
        }
        ensure!(
            mesh.party() == self.party,
            "the node is party {} but its mesh config {} is party {}",
            self.party,
            self.mesh_config.display(),
            mesh.party()
        );
        Ok(mesh)
    }

    /// The node's key files.
    pub fn key_files(&self) -> KeyFiles {
        KeyFiles::new(&self.key_dir)
    }

    /// The directories this node keeps on its disk: the key directory, the
    /// run directory and a local store's directory. A backup key is refused
    /// inside any of them (the `backup` module).
    pub fn own_dirs(&self) -> Vec<&Path> {
        let mut dirs = vec![self.key_dir.as_path(), self.run_dir.as_path()];
        if let StoreConfig::Local { path } = &self.store {
            dirs.push(path.as_path());
        }
        dirs
    }

    /// The admin socket path.
    pub fn admin_socket(&self) -> PathBuf {
        self.admin_socket
            .clone()
            .unwrap_or_else(|| self.run_dir.join(ADMIN_SOCKET_FILE))
    }

    /// The `requests` retention in seconds.
    pub fn retention_secs(&self) -> u64 {
        self.requests_retention_days.saturating_mul(24 * 60 * 60)
    }

    /// The grace window of an enc rotation in seconds.
    pub fn enc_grace_secs(&self) -> u64 {
        self.enc_grace_days.saturating_mul(24 * 60 * 60)
    }

    /// The receipt signer's settings.
    pub fn receipt_config(&self) -> ReceiptConfig {
        ReceiptConfig {
            ttl_blocks: self.receipt_ttl_blocks,
            allowance_blocks: self.receipt_allowance_blocks,
        }
    }

    /// The life of a receipt this node signs: its TTL and allowance, the
    /// manifest default stale period, at `[tip] block_time_secs` (without
    /// `[tip]`, [`DEFAULT_BLOCK_TIME_SECS`]).
    pub fn receipt_life(&self) -> ReceiptLife {
        ReceiptLife {
            ttl_blocks: self.receipt_ttl_blocks,
            allowance_blocks: self.receipt_allowance_blocks,
            stale_blocks: DEFAULT_STALE_BLOCKS,
            block_time_secs: self
                .tip
                .as_ref()
                .map_or(DEFAULT_BLOCK_TIME_SECS, |tip| tip.block_time_secs),
        }
    }

    /// REGISTER's check of this node's own, per package: the intake's own
    /// rules on this node's `enc` grace window and receipt life
    /// ([`sidecar_tip::check_register_intake`]; under secret-shared receipt
    /// intake the namespace's stale period, the contract manifest's
    /// `queue.stale_blocks`, never null, with the receipt life must fit the
    /// window). The intake runs them on a queued package only
    /// ([`sidecar_core::intake::IntakeRules::check_queued`]). Key layouts
    /// across packages are the contract manifest's own checks.
    pub fn register_check(&self) -> RegisterHook {
        let node = sidecar_tip::RegisterNode {
            enc_grace_secs: self.enc_grace_secs(),
            life: self.receipt_life(),
        };
        Box::new(move |view| {
            view.manifest
                .intake
                .rules()
                .check_queued(&mut |intake| sidecar_tip::check_register_intake(view, intake, &node))
        })
    }

    /// The pruning job's interval; `None` when the timer is off.
    pub fn prune_interval(&self) -> Option<Duration> {
        (self.prune_interval_secs > 0).then(|| Duration::from_secs(self.prune_interval_secs))
    }
}

/// The config file and the overrides of its entries, on the command line or
/// in the environment.
#[derive(Clone, Debug, clap::Args)]
pub struct ConfigArgs {
    /// The node config file (TOML).
    #[arg(long, env = "NODE_CONFIG")]
    pub config: PathBuf,

    /// Serve the API on this address instead of the config's `api_listen`.
    #[arg(long, env = "NODE_API_LISTEN")]
    pub api_listen: Option<SocketAddr>,

    /// Move the mesh to ports base, base + 1 and base + 2.
    #[arg(long, env = "NODE_MESH_BASE_PORT")]
    pub mesh_base_port: Option<u16>,

    /// The admin socket path instead of the config's.
    #[arg(long, env = "NODE_ADMIN_SOCKET")]
    pub admin_socket: Option<PathBuf>,
}

impl ConfigArgs {
    /// The config file with the overrides applied.
    pub fn load(&self) -> eyre::Result<NodeConfig> {
        let mut config = NodeConfig::load(&self.config)?;
        if let Some(addr) = self.api_listen {
            config.api_listen = addr;
        }
        if let Some(base) = self.mesh_base_port {
            config.mesh_base_port = Some(base);
        }
        if let Some(socket) = &self.admin_socket {
            config.admin_socket = Some(socket.clone());
        }
        config.check()?;
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sidecar_core::field::Fr;
    use sidecar_core::manifest::contract::{CheckedContractManifest, ContractManifest};
    use sidecar_core::registry::RegisterView;

    fn configs_dir() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("data/configs")
    }

    #[test]
    fn the_development_configs_use_the_harness_ports() {
        for party in 0..3 {
            let path = configs_dir().join(format!("node{party}.toml"));
            let config = NodeConfig::load(&path).unwrap();
            assert_eq!(config.party, party);
            assert_eq!(
                config.api_listen,
                format!("127.0.0.1:{}", DEFAULT_API_BASE_PORT + party as u16)
                    .parse()
                    .unwrap()
            );
            assert_eq!(config.store, StoreConfig::Memory);
            assert_eq!(config.requests_retention_days, 30);
            assert_eq!(config.retention_secs(), 30 * 24 * 3600);
            assert_eq!(config.prune_interval(), Some(Duration::from_secs(3600)));
            assert_eq!(config.enc_grace_days, DEFAULT_ENC_GRACE_DAYS);
            assert_eq!(config.enc_grace_secs(), 30 * 24 * 3600);
            // Relative paths resolve against the config's directory.
            assert_eq!(
                config.mesh_config,
                configs_dir().join(format!("party{party}.toml"))
            );
            let machine = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
            assert_eq!(config.tls.ca, machine.join("data/keys/https-ca.pem"));
            assert_eq!(
                config.admin_socket(),
                machine.join(format!("data/run/node{party}/admin.sock"))
            );
            assert_eq!(
                config.admin_socket(),
                config.run_dir.join(ADMIN_SOCKET_FILE)
            );
            // The mesh config reads scripts/gen-dev-certs.sh's mesh keys.
            let key = machine.join(format!("data/keys/mesh-key{party}.der"));
            if !key.exists() {
                sidecar_core::testing::artifacts::missing(format!(
                    "{} is missing; run scripts/gen-dev-certs.sh",
                    key.display()
                ));
                continue;
            }
            let mesh = config.mesh().unwrap();
            assert_eq!(mesh.party(), party);
        }
    }

    const MINIMAL: &str = r#"
        party = 1
        api_listen = "127.0.0.1:0"
        mesh_config = "party1.toml"
        key_dir = "keys"
        run_dir = "/run/sidecar"
        [tls]
        ca = "ca.pem"
        cert = "node.pem"
        key = "node-key.pem"
        [store]
        backend = "local"
        path = "store"
        [crs]
        g1 = "g1.dat"
        g2 = "/crs/g2.dat"
    "#;

    #[test]
    fn defaults_and_path_resolution() {
        let config = NodeConfig::from_toml(MINIMAL, Path::new("/etc/node")).unwrap();
        assert_eq!(config.key_dir, Path::new("/etc/node/keys"));
        assert_eq!(config.run_dir, Path::new("/run/sidecar"));
        assert_eq!(config.admin_socket(), Path::new("/run/sidecar/admin.sock"));
        assert_eq!(
            config.store,
            StoreConfig::Local {
                path: "/etc/node/store".into()
            }
        );
        assert_eq!(config.crs.g1, Path::new("/etc/node/g1.dat"));
        assert_eq!(config.crs.g2, Path::new("/crs/g2.dat"));
        assert_eq!(config.requests_retention_days, 30);
        assert_eq!(config.prune_interval_secs, 3600);
        assert_eq!(config.enc_grace_days, 30);
        assert_eq!(config.receipt_config(), ReceiptConfig::default());
        assert_eq!(config.receipt_ttl_blocks, 300);
    }

    #[test]
    fn bad_configs_are_refused() {
        let unknown = format!("{MINIMAL}\n[extra]\nx = 1\n");
        assert!(NodeConfig::from_toml(&unknown, Path::new("/")).is_err());
        let party = MINIMAL.replace("party = 1", "party = 3");
        assert!(NodeConfig::from_toml(&party, Path::new("/")).is_err());
        let zero = format!("requests_retention_days = 0\n{MINIMAL}");
        assert!(NodeConfig::from_toml(&zero, Path::new("/")).is_err());
        let no_window = format!("enc_grace_days = 0\n{MINIMAL}");
        assert!(NodeConfig::from_toml(&no_window, Path::new("/")).is_err());
        let no_ttl = format!("receipt_ttl_blocks = 0\n{MINIMAL}");
        assert!(NodeConfig::from_toml(&no_ttl, Path::new("/")).is_err());
        let ttl = format!("receipt_ttl_blocks = 50\nreceipt_allowance_blocks = 0\n{MINIMAL}");
        let config = NodeConfig::from_toml(&ttl, Path::new("/")).unwrap();
        assert_eq!(config.receipt_config().max_ahead(), 50);
        let long = MINIMAL.replace("/run/sidecar", &format!("/{}", "r".repeat(120)));
        let err = NodeConfig::from_toml(&long, Path::new("/")).unwrap_err();
        assert!(format!("{err:#}").contains("at most 107"), "{err:#}");
    }

    /// A Postgres URL, which may carry a password, never reaches a log
    /// through `Debug`.
    #[test]
    fn the_postgres_password_is_not_printed() {
        let text = MINIMAL.replace(
            "backend = \"local\"\n        path = \"store\"",
            "backend = \"postgres\"\n        url = \"postgres://pss:hunter2@db/pss\"",
        );
        let config = NodeConfig::from_toml(&text, Path::new("/")).unwrap();
        let printed = format!("{config:?}");
        assert!(printed.contains("Postgres"), "{printed}");
        assert!(!printed.contains("hunter2"), "{printed}");
    }

    /// The example in this module's documentation loads.
    #[test]
    fn the_documented_example_loads() {
        let source = include_str!("config.rs");
        let start = source.find("//! ```toml\n").expect("the example's start") + 12;
        let end = start
            + source[start..]
                .find("//! ```\n")
                .expect("the example's end");
        let example: String = source[start..end]
            .lines()
            .map(|line| line.strip_prefix("//!").unwrap_or(line).trim_start())
            .map(|line| format!("{line}\n"))
            .collect();
        let config = NodeConfig::from_toml(&example, Path::new("/etc/node")).unwrap();
        let tip = config.tip.expect("the example's [tip]");
        assert_eq!(tip.namespaces.len(), 1);
    }

    const TIP: &str = r#"
        [tip]
        aztec_node = "https://aztec.example:8080"
        aztec_node_ca = "aztec-ca.pem"
        [[tip.namespaces]]
        contract = "0x7195"
    "#;

    #[test]
    fn the_tip_section_names_the_aztec_node_and_the_namespaces() {
        assert_eq!(
            NodeConfig::from_toml(MINIMAL, Path::new("/")).unwrap().tip,
            None
        );
        let text = format!("{MINIMAL}{TIP}");
        let config = NodeConfig::from_toml(&text, Path::new("/etc/node")).unwrap();
        let tip = config.tip.unwrap();
        assert_eq!(
            tip.aztec_node.ca.as_deref(),
            Some(Path::new("/etc/node/aztec-ca.pem"))
        );
        assert_eq!(tip.namespaces[0].contract.fr(), Fr::from(0x7195u64));
        assert_eq!(tip.block_time_secs, DEFAULT_BLOCK_TIME_SECS);

        let refused = |text: String, needle: &str| {
            let err = NodeConfig::from_toml(&text, Path::new("/")).unwrap_err();
            assert!(format!("{err:#}").contains(needle), "{err:#}");
        };
        refused(
            text.replace("aztec_node_ca = \"aztec-ca.pem\"", ""),
            "give tip.aztec_node_ca",
        );
        refused(text.replace("https://", "ftp://"), "not an http");
        // the slots are the contract manifest's, never the config's
        refused(
            text.replace(
                "contract = \"0x7195\"",
                "contract = \"0x7195\"\nqueue_slot = \"0x0c\"",
            ),
            "queue_slot",
        );
        let twice = TIP.replace("[tip]", "").replace(
            "aztec_node = \"https://aztec.example:8080\"\n        aztec_node_ca = \"aztec-ca.pem\"",
            "",
        );
        refused(format!("{text}{twice}"), "listed twice");
    }

    /// With `[tip]`, the enc grace window must cover the receipt life,
    /// `receipt_ttl_blocks + receipt_allowance_blocks + stale_blocks` at the
    /// block time: one day at 36 s is 2400 blocks, so a TTL of 2340 (with
    /// the allowance 10 and the default stale period 50) passes and 2341 is
    /// refused; without `[tip]` the node signs no checked receipt and the
    /// window is not compared.
    #[test]
    fn the_enc_grace_window_covers_the_receipt_life() {
        let config = |head: &str, tip: bool| {
            let tip = if tip { TIP } else { "" };
            NodeConfig::from_toml(&format!("{head}\n{MINIMAL}{tip}"), Path::new("/"))
        };
        let boundary = "enc_grace_days = 1\nreceipt_ttl_blocks = 2340";
        let over = "enc_grace_days = 1\nreceipt_ttl_blocks = 2341";
        let cfg = config(boundary, true).unwrap();
        assert_eq!(cfg.enc_grace_secs(), 2400 * DEFAULT_BLOCK_TIME_SECS);
        let err = config(over, true).unwrap_err();
        let text = format!("{err:#}");
        assert!(text.contains("shorter than a receipt's life"), "{text}");
        assert!(text.contains("2401 blocks"), "{text}");
        config(over, false).unwrap();
        // the block time is the node's: a faster chain fits a longer TTL
        let fast = TIP.replace(
            "aztec_node_ca = \"aztec-ca.pem\"",
            "aztec_node_ca = \"aztec-ca.pem\"\n        block_time_secs = 6",
        );
        let text = format!("{over}\n{MINIMAL}{fast}");
        assert_eq!(
            NodeConfig::from_toml(&text, Path::new("/"))
                .unwrap()
                .tip
                .unwrap()
                .block_time_secs,
            6
        );
        let zero = fast.replace("block_time_secs = 6", "block_time_secs = 0");
        let err = NodeConfig::from_toml(&format!("{MINIMAL}{zero}"), Path::new("/")).unwrap_err();
        assert!(format!("{err:#}").contains("block_time_secs"), "{err:#}");
    }

    /// REGISTER's check of the node's own reads its config: under secret-shared
    /// receipt intake a stale period (the contract manifest's
    /// `queue.stale_blocks`) whose receipt life outlasts the window, or null,
    /// is refused (400, naming `manifest.queue.stale_blocks`); the same
    /// manifests under receipt intake register, and so does an intake direct
    /// package.
    #[test]
    fn register_checks_a_shared_receipt_stale_period_against_the_window() {
        let manifest = |intake: &str| {
            let path = match intake {
                "shared_receipt" => "testvectors/manifests/shared_receipt_round.json",
                _ => "examples/amm-tip/manifests/amm_swap_tip_receipt.json",
            };
            let v = shipped_value(path);
            assert_eq!(v["intake"], intake);
            v
        };
        // one day at 36 s is 2400 blocks: TTL 300 + allowance 10 leaves 2090
        let text = format!("enc_grace_days = 1\n{MINIMAL}{TIP}");
        let config = NodeConfig::from_toml(&text, Path::new("/")).unwrap();
        let hook = config.register_check();
        let check = |intake: &str, stale: serde_json::Value| {
            let contract = contract(manifest(intake), stale);
            hook(&alone(&contract))
        };
        check("shared_receipt", serde_json::json!(2090)).unwrap();
        for stale in [serde_json::json!(2091), serde_json::Value::Null] {
            let err = check("shared_receipt", stale.clone()).unwrap_err();
            assert_eq!(err.class, sidecar_core::ErrorClass::BadRequest);
            assert!(
                err.message
                    .starts_with("field `manifest.queue.stale_blocks`: "),
                "{err}"
            );
            check("receipt", stale).unwrap();
        }
        // intake direct: no tip check runs
        let direct = sidecar_contract(shipped_value("examples/amm/manifests/amm_swap.json"));
        hook(&alone(&direct)).unwrap();
        // the node's block time counts: at 6 s the same window fits 14090
        let fast = TIP.replace(
            "aztec_node_ca = \"aztec-ca.pem\"",
            "aztec_node_ca = \"aztec-ca.pem\"\n        block_time_secs = 6",
        );
        let text = format!("enc_grace_days = 1\n{MINIMAL}{fast}");
        let hook = NodeConfig::from_toml(&text, Path::new("/"))
            .unwrap()
            .register_check();
        let check = |stale: u64| {
            let contract = contract(manifest("shared_receipt"), serde_json::json!(stale));
            hook(&alone(&contract))
        };
        check(14090).unwrap();
        check(14091).unwrap_err();
    }

    /// A tip contract manifest of the one queued package `manifest` (its
    /// keys named `k`) under the stale period `stale`, checked.
    fn contract(manifest: serde_json::Value, stale: serde_json::Value) -> CheckedContractManifest {
        let name = manifest["circuit"].as_str().unwrap().to_string();
        let reads = vec!["k"; manifest["state_keys"]["reads"].as_u64().unwrap() as usize];
        let writes = vec!["k"; manifest["state_keys"]["writes"].as_u64().unwrap() as usize];
        let document = serde_json::json!({
            "contract_manifest": 1,
            "name": "test",
            "node_keys": "fixed",
            "upgrades": "fixed",
            "contract": { "class_id": "0x1", "package_capacity": 1 },
            "queue": { "slot": "0x0c", "stale_blocks": stale, "stale_blocks_slot": "0x01" },
            "storage": { "configured": "0x0b" },
            "state_keys": { "k": "0x10" },
            "circuits": { "c": { "vk_hash": "0x2" } },
            "packages": [{ "name": name, "circuit": "c",
                           "state_keys": { "reads": reads, "writes": writes },
                           "manifest": manifest }]
        });
        ContractManifest::parse(&document)
            .and_then(ContractManifest::check)
            .unwrap()
    }

    /// A sidecar-path contract manifest of the one package `manifest`.
    fn sidecar_contract(manifest: serde_json::Value) -> CheckedContractManifest {
        let name = manifest["circuit"].as_str().unwrap().to_string();
        let document = serde_json::json!({
            "contract_manifest": 1,
            "name": "test",
            "node_keys": "fixed",
            "upgrades": "fixed",
            "circuits": { "c": { "vk_hash": "0x2" } },
            "packages": [{ "name": name, "circuit": "c", "manifest": manifest }]
        });
        ContractManifest::parse(&document)
            .and_then(ContractManifest::check)
            .unwrap()
    }

    /// A circuit shape with no parameter: the checks these tests reach read
    /// none (secret-shared on-chain intake's request log bound is sidecar-tip's
    /// test).
    static NO_SHAPE: sidecar_core::abi::CircuitShape = sidecar_core::abi::CircuitShape {
        params: Vec::new(),
        public_param_fields: 0,
        return_paths: Vec::new(),
        public_input_count: 0,
        namespace_index: 0,
        outputs: Vec::new(),
    };

    /// The REGISTER view of the one package of `contract`.
    fn alone(contract: &CheckedContractManifest) -> RegisterView<'_> {
        let (entry, manifest) = contract.packages().next().unwrap();
        RegisterView {
            namespace: Fr::from(0x7195u64),
            name: &entry.name,
            manifest,
            shape: &NO_SHAPE,
            contract,
        }
    }

    /// A shipped manifest under `testvectors/`, `examples/` or `machine/`.
    fn shipped_value(path: &str) -> serde_json::Value {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(path);
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
    }

    /// Key layouts across packages are the contract manifest's checks, not
    /// the node's configuration: two packages that give one named key two
    /// layouts (a flat key and a tree) are refused (400) by the contract
    /// manifest's checks, whatever the node's `[tip.namespaces.circuits]`
    /// says, and the node's hook passes each package alone.
    #[test]
    fn key_layouts_are_the_contract_manifest_s_checks() {
        let flat = shipped_value("examples/amm-tip/manifests/amm_swap_tip_receipt.json");
        let tree = shipped_value("machine/circuits/manifests/tip_tree.json");
        let document = |tree_key: &str| {
            let mut d = serde_json::json!({
                "contract_manifest": 1,
                "name": "test",
                "node_keys": "fixed",
                "upgrades": "fixed",
                "contract": { "class_id": "0x1", "package_capacity": 2 },
                "queue": { "slot": "0x0c", "stale_blocks": 50, "stale_blocks_slot": "0x01" },
                "storage": { "configured": "0x0b" },
                "state_keys": { "pool": "0x7c01" },
                "circuits": { "swap": { "vk_hash": "0x2" }, "tree": { "vk_hash": "0x3" } },
                "packages": [
                    { "name": "amm_swap_tip_receipt", "circuit": "swap",
                      "state_keys": { "reads": ["pool"], "writes": ["pool"] }, "manifest": flat },
                    { "name": "tip_tree", "circuit": "tree",
                      "state_keys": { "reads": [tree_key], "writes": [tree_key] }, "manifest": tree }
                ]
            });
            d["state_keys"][tree_key] = serde_json::json!("0x7c02");
            d
        };
        let check = |doc: serde_json::Value| {
            ContractManifest::parse(&doc).and_then(ContractManifest::check)
        };
        let err = check(document("pool")).unwrap_err();
        assert_eq!(err.class, sidecar_core::ErrorClass::BadRequest);
        assert!(err.message.contains("key `pool`"), "{err}");
        let both = check(document("book")).unwrap();
        let hook = NodeConfig::from_toml(&format!("{MINIMAL}{TIP}"), Path::new("/"))
            .unwrap()
            .register_check();
        for (entry, manifest) in both.packages() {
            hook(&RegisterView {
                namespace: Fr::from(0x7195u64),
                name: &entry.name,
                manifest,
                shape: &NO_SHAPE,
                contract: &both,
            })
            .unwrap();
        }
    }
}
