//! The orchestrator's configuration file (TOML): where the public API listens
//! and its server certificate, the mutual-TLS material of the node leg, the
//! three nodes (URL and pinned public keys, node 0 first), the registry
//! store, the CRS the orchestrator computes verification keys with, the
//! tip's receipt TTL and, when present, the tip's scheduler (`[tip]`).
//! Relative paths resolve against the directory of the config file.
//!
//! ```toml
//! listen = "127.0.0.1:3200"
//! receipt_ttl_blocks = 300      # the tip's receipts
//!
//! [tls]                         # the public listener (no client certificate)
//! cert = "../../../data/keys/https-orchestrator-server.pem"
//! key = "../../../data/keys/https-orchestrator-server-key.pem"
//!
//! [node_tls]                    # the node leg: mutual TLS under the deployment CA
//! ca = "../../../data/keys/https-ca.pem"
//! cert = "../../../data/keys/https-orchestrator.pem"
//! key = "../../../data/keys/https-orchestrator-key.pem"
//!
//! # admin_socket = "../../../data/run/orchestrator/admin.sock"   (the default: beside the registry)
//! # node_call_timeout_secs = 1000   (one node call's bound; above the nodes' round bound)
//!
//! [registry]
//! path = "../../../data/run/orchestrator/registry"
//! check_interval_secs = 600     # how often the nodes' registries are compared (GET /v1/status)
//!
//! [crs]
//! g1 = "../../../data/bn254_g1.dat"
//! g2 = "../../../data/bn254_g2.dat"
//! circuits_dir = "../../../data/circuits"
//!
//! [[nodes]]                     # three times, node 0 first
//! url = "https://127.0.0.1:8200"
//! # server_name = "localhost"   (the name its certificate carries; default: the URL's host)
//! enc = { x = "0x…", y = "0x…" }
//! sig = { x = "0x…", y = "0x…" }
//!
//! [tip]                         # optional: the scheduler; absent, the orchestrator serves note mode only
//! aztec_node = "http://127.0.0.1:8080"
//! # aztec_node_ca = "ca.pem"    (for an https:// node: the only root its certificate may chain to)
//! poll_interval_ms = 1000
//! pipeline_depth = 1
//!
//! [[tip.namespaces]]            # one per served tip contract (one queue each); the nodes' list
//! contract = "0x…"              # the app contract: the namespace
//! ```
//!
//! Each listed namespace is scheduled once its contract manifest is
//! registered; its slots, request keys, plain reads, init round and stale
//! period come from that manifest (`sidecar_tip::TipLayout`).

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use eyre::{Context, bail, ensure};
use serde::Deserialize;
use sidecar_core::crs::CrsFiles;
use sidecar_core::grumpkin::{Point, point_from_wire};
use sidecar_core::request::{GrumpkinPoint, NODES};
use sidecar_core::response::{NodePublicKeys, NodesResponse};
use sidecar_http::admin::{check_path, normalize};
use sidecar_http::tls::TlsFiles;
use sidecar_tip::{AztecNode, TipNamespace};

// Operator knob: DESIGN.md, "Configuration reference" (`listen`). Default
// 127.0.0.1:3200, loopback only; `--listen` (ORCHESTRATOR_LISTEN) overrides it,
// port 0 included (the tests' free port).
/// The default listen address of the public API.
pub const DEFAULT_LISTEN: &str = "127.0.0.1:3200";

fn default_listen() -> SocketAddr {
    DEFAULT_LISTEN.parse().expect("a socket address")
}

// Operator knob: DESIGN.md, "Configuration reference" (`[tls]`, `[node_tls]`).
// The public listener asks no client certificate; the node leg is mutual TLS
// under the deployment CA.
/// The public listener's server certificate and key, PEM.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicTls {
    pub cert: PathBuf,
    pub key: PathBuf,
}

/// The registry copy: its store's directory (the local append-only store)
/// and how often it is compared with the nodes' registries.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryFiles {
    pub path: PathBuf,
    /// Seconds between runs of the registry check on its timer
    /// (`crate::status`), at least 1; default 600. The check also runs at
    /// start and after every registry body the orchestrator relays, so the
    /// timer only catches what changes at the nodes without passing through
    /// it (a node restored from a backup, a `sidecar-node sync-registry`
    /// repair, a body sent to the nodes directly). Each run reads every
    /// registry row from the three nodes over their GETs and takes no lock;
    /// a shorter interval shows such a change on `GET /v1/status` sooner,
    /// at that read's cost.
    #[serde(default = "default_check_interval_secs")]
    pub check_interval_secs: u64,
}

fn default_check_interval_secs() -> u64 {
    600
}

impl RegistryFiles {
    /// The timer's interval ([`RegistryFiles::check_interval_secs`]).
    pub fn check_interval(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.check_interval_secs)
    }
}

// Operator knob: DESIGN.md, "Configuration reference" (`[[nodes]]` `enc`,
// `sig`). The orchestrator never learns these keys from a node; `GET /v1/nodes`
// refuses (500) a node answer that differs from the pins.
/// One node: where it answers and the keys it is pinned to.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeEntry {
    /// `https://host:port`.
    pub url: String,
    /// The name the node's server certificate must carry; the URL's host when
    /// absent.
    #[serde(default)]
    pub server_name: Option<String>,
    pub enc: GrumpkinPoint,
    pub sig: GrumpkinPoint,
}

impl NodeEntry {
    /// The URL's `host:port` and host, checked to be `https://host:port`.
    fn host_port(&self) -> eyre::Result<(String, String)> {
        let rest = self
            .url
            .strip_prefix("https://")
            .ok_or_else(|| eyre::eyre!("node URL `{}` is not https://host:port", self.url))?;
        let rest = rest.strip_suffix('/').unwrap_or(rest);
        ensure!(
            !rest.contains('/'),
            "node URL `{}` has a path; give https://host:port",
            self.url
        );
        let (host, port) = rest
            .rsplit_once(':')
            .ok_or_else(|| eyre::eyre!("node URL `{}` names no port", self.url))?;
        port.parse::<u16>()
            .with_context(|| format!("node URL `{}`: the port", self.url))?;
        let host = host.trim_start_matches('[').trim_end_matches(']');
        Ok((rest.to_string(), host.to_string()))
    }

    /// The node's `host:port`, which the node leg resolves at each connect.
    pub fn host_and_port(&self) -> eyre::Result<String> {
        Ok(self.host_port()?.0)
    }

    /// The name its server certificate must carry.
    pub fn server_name(&self) -> eyre::Result<String> {
        match &self.server_name {
            Some(name) => Ok(name.clone()),
            None => Ok(self.host_port()?.1),
        }
    }

    /// The pinned keys as the wire type.
    pub fn public_keys(&self) -> NodePublicKeys {
        NodePublicKeys {
            enc: self.enc,
            sig: self.sig,
        }
    }
}

/// The orchestrator's configuration, with every path resolved.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrchestratorConfig {
    /// Where the public HTTPS API listens.
    #[serde(default = "default_listen")]
    pub listen: SocketAddr,
    pub tls: PublicTls,
    /// The node leg: `ca` the nodes' server certificates chain to, `cert` and
    /// `key` the orchestrator's client certificate.
    pub node_tls: TlsFiles,
    pub registry: RegistryFiles,
    pub crs: CrsFiles,
    /// The three nodes, node 0 first.
    pub nodes: Vec<NodeEntry>,
    /// How many L2 blocks after the current block a receipt expires
    /// (`expiry_block = current_block + receipt_ttl_blocks`); the nodes'
    /// value, at least 1.
    #[serde(default = "default_receipt_ttl_blocks")]
    pub receipt_ttl_blocks: u32,
    /// The tip's scheduler; `None` (no `[tip]` section): no scheduler runs
    /// and the orchestrator serves note-mode requests only, unchanged.
    #[serde(default)]
    pub tip: Option<TipConfig>,
    /// The operator's admin socket (pause, resume and the registry check's
    /// rows, `crate::admin`); default `admin.sock` beside the registry
    /// copy's directory.
    #[serde(default)]
    pub admin_socket: Option<PathBuf>,
    /// How long the orchestrator waits for one node call, in seconds
    /// ([`crate::nodes::DEFAULT_NODE_CALL_TIMEOUT`], 1,000, by default; at
    /// least [`MIN_NODE_CALL_TIMEOUT_SECS`]).
    #[serde(default = "default_node_call_timeout_secs")]
    pub node_call_timeout_secs: u64,
}

// Operator knob: DESIGN.md, "Configuration reference"
// (`node_call_timeout_secs`). The bound must stay above a round's (the
// nodes' mesh timeout and the proving after it); below a minute it would cut
// every round short and release the session lock while the nodes still run
// it, so a config under the floor is refused.
/// The least `node_call_timeout_secs` a config may set.
pub const MIN_NODE_CALL_TIMEOUT_SECS: u64 = 60;

fn default_node_call_timeout_secs() -> u64 {
    crate::nodes::DEFAULT_NODE_CALL_TIMEOUT.as_secs()
}

impl OrchestratorConfig {
    /// The node-leg call bound ([`OrchestratorConfig::node_call_timeout_secs`]).
    pub fn node_call_timeout(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.node_call_timeout_secs)
    }

    /// The admin socket's path: the config's `admin_socket`, or
    /// `admin.sock` in the directory that holds the registry copy.
    pub fn admin_socket(&self) -> PathBuf {
        match &self.admin_socket {
            Some(p) => p.clone(),
            None => self
                .registry
                .path
                .parent()
                .unwrap_or(Path::new("."))
                .join(sidecar_http::admin::ADMIN_SOCKET_FILE),
        }
    }
}

// Operator knob: DESIGN.md, "Configuration reference" (`[tip]`). Optional;
// without it the orchestrator starts no scheduler and reads no chain, and the
// public API is the same.
/// The `[tip]` section: the Aztec node the chain reader follows, how often
/// it polls, how far the scheduler pipelines, and the namespaces it drives.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TipConfig {
    /// The Aztec node the scheduler's chain reader follows.
    #[serde(flatten)]
    pub aztec_node: AztecNode,
    // Operator knob: DESIGN.md, "Configuration reference" (`poll_interval_ms`).
    // Default `sidecar_tip::chain::DEFAULT_POLL_INTERVAL` (1000 ms), at least 100.
    /// How often the reader asks for the proposed tip, in milliseconds.
    #[serde(default = "default_poll_interval_ms")]
    pub poll_interval_ms: u64,
    /// Requests computed after the head, on the speculative state: default
    /// 1, 0 computes the head only, at most the reader's lookahead (4). A
    /// deeper pipeline lands faster on a busy queue and wastes more rounds
    /// when the head is skipped or superseded; at 2 or more, an entry
    /// pipelined on an attempt that left a node-held key's commitment
    /// unchanged waits until the entry before that attempt lands. The
    /// operator's reference: DESIGN.md, "The tip sections".
    #[serde(default = "default_pipeline_depth")]
    pub pipeline_depth: usize,
    /// The namespaces to schedule (the allowlist); at least one; the same
    /// list as the nodes' `[tip]`.
    pub namespaces: Vec<TipNamespace>,
}

fn default_poll_interval_ms() -> u64 {
    sidecar_tip::chain::DEFAULT_POLL_INTERVAL.as_millis() as u64
}

fn default_pipeline_depth() -> usize {
    1
}

impl TipConfig {
    fn check(&self) -> eyre::Result<()> {
        sidecar_tip::check_tip(&self.aztec_node, &self.namespaces)?;
        ensure!(
            self.poll_interval_ms >= 100,
            "tip.poll_interval_ms must be at least 100"
        );
        ensure!(
            self.pipeline_depth <= sidecar_tip::chain::DEFAULT_LOOKAHEAD,
            "tip.pipeline_depth {} is past the chain reader's lookahead of {}",
            self.pipeline_depth,
            sidecar_tip::chain::DEFAULT_LOOKAHEAD
        );
        Ok(())
    }
}

// Operator knob: DESIGN.md, "Configuration reference" (`receipt_ttl_blocks`).
// Default 300 blocks, the nodes' default (`sidecar_tip::DEFAULT_RECEIPT_TTL_BLOCKS`);
// the orchestrator fixes `expiry_block` and the nodes only bound it.
fn default_receipt_ttl_blocks() -> u32 {
    sidecar_tip::DEFAULT_RECEIPT_TTL_BLOCKS
}

impl OrchestratorConfig {
    /// Read a config file; relative paths resolve against its directory.
    pub fn load(path: &Path) -> eyre::Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading the orchestrator config {}", path.display()))?;
        let base = path.parent().unwrap_or(Path::new("."));
        Self::from_toml(&text, base)
            .with_context(|| format!("orchestrator config {}", path.display()))
    }

    /// Parse a config whose relative paths resolve against `base`.
    pub fn from_toml(text: &str, base: &Path) -> eyre::Result<Self> {
        let mut config: OrchestratorConfig = toml::from_str(text).context("parsing")?;
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
        resolve(&mut self.tls.cert);
        resolve(&mut self.tls.key);
        resolve(&mut self.node_tls.ca);
        resolve(&mut self.node_tls.cert);
        resolve(&mut self.node_tls.key);
        resolve(&mut self.registry.path);
        if let Some(p) = &mut self.admin_socket {
            resolve(p);
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
        if let Some(tip) = &self.tip {
            tip.check()?;
        }
        ensure!(
            self.receipt_ttl_blocks > 0,
            "receipt_ttl_blocks must be at least 1"
        );
        ensure!(
            self.registry.check_interval_secs > 0,
            "registry.check_interval_secs must be at least 1"
        );
        ensure!(
            self.node_call_timeout_secs >= MIN_NODE_CALL_TIMEOUT_SECS,
            "node_call_timeout_secs must be at least {MIN_NODE_CALL_TIMEOUT_SECS} (above a \
             round's own bound)"
        );
        check_path(
            &self.admin_socket(),
            "set admin_socket, or a shorter [registry] path",
        )?;
        if self.nodes.len() != NODES {
            bail!(
                "the config names {} nodes; the network has exactly {NODES}",
                self.nodes.len()
            );
        }
        for (i, node) in self.nodes.iter().enumerate() {
            node.host_port().with_context(|| format!("nodes[{i}]"))?;
            for (name, key) in [("enc", &node.enc), ("sig", &node.sig)] {
                point_from_wire(key)
                    .map(drop)
                    .map_err(|e| eyre::eyre!("nodes[{i}].{name}: {e}"))?;
            }
        }
        Ok(())
    }

    /// The pinned keys of the three nodes, as `GET /v1/nodes` answers them.
    pub fn pins(&self) -> NodesResponse {
        NodesResponse {
            nodes: [0, 1, 2].map(|i| self.nodes[i].public_keys()),
        }
    }

    /// The pinned `sig` keys as points (checked on the curve at load).
    pub fn sig_pks(&self) -> [Point; NODES] {
        [0, 1, 2].map(|i| point_from_wire(&self.nodes[i].sig).expect("checked at load"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sidecar_core::field::FieldHex;
    use sidecar_core::grumpkin::{Fq, point_to_wire};
    use sidecar_core::schnorr::public_key;

    fn key(n: u64) -> String {
        let p = point_to_wire(public_key(Fq::from(n)));
        format!(r#"{{ x = "{}", y = "{}" }}"#, p.x, p.y)
    }

    fn text(nodes: usize, url0: &str) -> String {
        let mut text = String::from(
            r#"
[tls]
cert = "server.pem"
key = "server-key.pem"
[node_tls]
ca = "ca.pem"
cert = "client.pem"
key = "/abs/client-key.pem"
[registry]
path = "registry"
[crs]
g1 = "g1.dat"
g2 = "g2.dat"
"#,
        );
        for i in 0..nodes {
            let url = if i == 0 {
                url0.to_string()
            } else {
                format!("https://127.0.0.1:820{i}")
            };
            text.push_str(&format!(
                "[[nodes]]\nurl = \"{url}\"\nenc = {}\nsig = {}\n",
                key(10 + i as u64),
                key(20 + i as u64)
            ));
        }
        text
    }

    #[test]
    fn a_config_parses_and_resolves_its_paths() {
        let config =
            OrchestratorConfig::from_toml(&text(3, "https://localhost:8200/"), Path::new("/etc/o"))
                .unwrap();
        assert_eq!(config.listen, default_listen());
        assert_eq!(config.tls.cert, Path::new("/etc/o/server.pem"));
        assert_eq!(config.node_tls.key, Path::new("/abs/client-key.pem"));
        assert_eq!(config.registry.path, Path::new("/etc/o/registry"));
        assert_eq!(config.nodes[0].server_name().unwrap(), "localhost");
        assert_eq!(config.nodes[0].host_and_port().unwrap(), "localhost:8200");
        assert_eq!(config.nodes[2].server_name().unwrap(), "127.0.0.1");
        let pins = config.pins();
        assert_eq!(
            pins.nodes[1].sig,
            point_to_wire(public_key(Fq::from(21u64)))
        );
        assert_eq!(config.sig_pks()[2], public_key(Fq::from(22u64)));
        assert_eq!(config.receipt_ttl_blocks, 300);
        let ttl = format!(
            "receipt_ttl_blocks = 50\n{}",
            text(3, "https://localhost:8200/")
        );
        let config = OrchestratorConfig::from_toml(&ttl, Path::new("/etc/o")).unwrap();
        assert_eq!(config.receipt_ttl_blocks, 50);
        let zero = format!(
            "receipt_ttl_blocks = 0\n{}",
            text(3, "https://localhost:8200/")
        );
        let err = OrchestratorConfig::from_toml(&zero, Path::new("/etc/o")).unwrap_err();
        assert!(format!("{err:#}").contains("receipt_ttl_blocks"), "{err:#}");

        // The registry check's timer: 600 s unless set, never 0.
        assert_eq!(config.registry.check_interval_secs, 600);
        let interval = |secs: &str| {
            let text = text(3, "https://localhost:8200/").replace(
                "path = \"registry\"\n",
                &format!("path = \"registry\"\ncheck_interval_secs = {secs}\n"),
            );
            OrchestratorConfig::from_toml(&text, Path::new("/etc/o"))
        };
        assert_eq!(
            interval("30").unwrap().registry.check_interval(),
            std::time::Duration::from_secs(30)
        );
        let err = interval("0").unwrap_err();
        assert!(
            format!("{err:#}").contains("registry.check_interval_secs must be at least 1"),
            "{err:#}"
        );

        // The node-leg call bound: 1,000 s unless set, never under the floor.
        assert_eq!(
            config.node_call_timeout(),
            crate::nodes::DEFAULT_NODE_CALL_TIMEOUT
        );
        let bound = |secs: &str| {
            let text = format!(
                "node_call_timeout_secs = {secs}\n{}",
                text(3, "https://localhost:8200/")
            );
            OrchestratorConfig::from_toml(&text, Path::new("/etc/o"))
        };
        assert_eq!(bound("1200").unwrap().node_call_timeout_secs, 1200);
        assert_eq!(bound("60").unwrap().node_call_timeout_secs, 60);
        for low in ["0", "59"] {
            let err = bound(low).unwrap_err();
            assert!(
                format!("{err:#}").contains("node_call_timeout_secs must be at least 60"),
                "{err:#}"
            );
        }
    }

    #[test]
    fn the_admin_socket_path_is_normalised_and_bounded() {
        let config = OrchestratorConfig::from_toml(
            &text(3, "https://127.0.0.1:8200").replace(
                "path = \"registry\"",
                "path = \"../../../data/run/o/registry\"",
            ),
            Path::new("/srv/cfg/a/b/c"),
        )
        .unwrap();
        assert_eq!(
            config.admin_socket(),
            Path::new("/srv/cfg/data/run/o/admin.sock")
        );
        let long = format!("/{}/registry", "d".repeat(120));
        let err = OrchestratorConfig::from_toml(
            &text(3, "https://127.0.0.1:8200")
                .replace("path = \"registry\"", &format!("path = \"{long}\"")),
            Path::new("/etc/o"),
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("admin socket path"), "{err:#}");
    }

    #[test]
    fn a_bad_config_is_refused() {
        let base = Path::new("/etc/o");
        for (text, needle) in [
            (text(2, "https://127.0.0.1:8200"), "exactly 3"),
            (text(3, "http://127.0.0.1:8200"), "not https://host:port"),
            (text(3, "https://127.0.0.1"), "names no port"),
            (text(3, "https://127.0.0.1:8200/v1"), "has a path"),
        ] {
            let err = OrchestratorConfig::from_toml(&text, base).unwrap_err();
            assert!(format!("{err:#}").contains(needle), "{err:#}");
        }
        // A pinned key off the curve.
        let bad = text(3, "https://127.0.0.1:8200").replacen(
            &key(10),
            &format!(r#"{{ x = "{}", y = "0x2" }}"#, FieldHex::from(1)),
            1,
        );
        let err = OrchestratorConfig::from_toml(&bad, base).unwrap_err();
        assert!(format!("{err:#}").contains("nodes[0].enc"), "{err:#}");
        // An unknown field.
        let extra = format!("bogus = 1\n{}", text(3, "https://127.0.0.1:8200"));
        assert!(OrchestratorConfig::from_toml(&extra, base).is_err());
    }

    const TIP: &str = r#"
[tip]
aztec_node = "http://127.0.0.1:8080"
[[tip.namespaces]]
contract = "0x7195"
"#;

    #[test]
    fn the_tip_section_is_optional_and_checked() {
        let base = Path::new("/etc/o");
        let plain = OrchestratorConfig::from_toml(&text(3, "https://127.0.0.1:8200"), base);
        assert_eq!(plain.unwrap().tip, None);
        let with = format!("{}{TIP}", text(3, "https://127.0.0.1:8200"));
        let config = OrchestratorConfig::from_toml(&with, base).unwrap();
        let tip = config.tip.unwrap();
        assert_eq!((tip.poll_interval_ms, tip.pipeline_depth), (1000, 1));
        assert_eq!(tip.namespaces[0].contract, FieldHex::from(0x7195));
        let twice = format!("{with}[[tip.namespaces]]\ncontract = \"0x7195\"\n");
        let err = OrchestratorConfig::from_toml(&twice, base).unwrap_err();
        assert!(format!("{err:#}").contains("listed twice"), "{err:#}");
        for (from, to, needle) in [
            ("http://127", "ftp://127", "not an http"),
            ("http://127", "https://127", "aztec_node_ca"),
            (
                "aztec_node = \"http://127.0.0.1:8080\"",
                "aztec_node = \"http://127.0.0.1:8080\"\npipeline_depth = 5",
                "lookahead",
            ),
            (
                "aztec_node = \"http://127.0.0.1:8080\"",
                "aztec_node = \"http://127.0.0.1:8080\"\npoll_interval_ms = 10",
                "at least 100",
            ),
            // the slots are the contract manifest's, never the config's
            (
                "contract = \"0x7195\"",
                "contract = \"0x7195\"\nqueue_slot = \"0x0c\"",
                "queue_slot",
            ),
            // a misspelt key of the section itself, beside the flattened
            // Aztec node's keys
            (
                "aztec_node = \"http://127.0.0.1:8080\"",
                "aztec_node = \"http://127.0.0.1:8080\"\npoll_intervall_ms = 500",
                "poll_intervall_ms",
            ),
            (
                "aztec_node = \"http://127.0.0.1:8080\"",
                "aztec_node = \"http://127.0.0.1:8080\"\naztec_node_cert = \"ca.pem\"",
                "aztec_node_cert",
            ),
        ] {
            let bad = format!(
                "{}{}",
                text(3, "https://127.0.0.1:8200"),
                TIP.replace(from, to)
            );
            let err = OrchestratorConfig::from_toml(&bad, base).unwrap_err();
            assert!(format!("{err:#}").contains(needle), "{needle}: {err:#}");
        }
    }
}
