//! The `[[tip.namespaces]]` entries of the node and orchestrator config files:
//! one type, [`TipNamespace`], read by both binaries: the operator's
//! allowlist of tip contracts. Everything else about a namespace (its queue,
//! stale period, state keys, plain reads and init round) is its registered
//! contract manifest's ([`crate::TipLayout`]), so nothing slot-shaped is
//! copied into a config file; a namespace is driven when it is both listed
//! here and registered. The Aztec node of each `[tip]` section is one type
//! too, [`AztecNode`], which both binaries' sections flatten; the rest (the
//! node's block time, the orchestrator's poll interval and pipelining depth)
//! stays in each binary's config. [`check_tip`] checks the Aztec node and the
//! namespaces; a node also checks its `enc` grace window against the
//! receipt life ([`check_enc_grace`]), at config load with the default stale
//! period and at REGISTER with a secret-shared receipt package's own
//! (secret-shared receipt intake's `check_register`, on a [`RegisterNode`]).
//!
//! ```toml
//! [[tip.namespaces]]
//! contract = "0x…"              # the app contract: the namespace
//! ```
//!
//! The stale period is the registered contract manifest's
//! `queue.stale_blocks`, which the scheduler, the receipt pruning and the
//! relayer read; each node's chain verifier checks the contract's stored
//! `TipConfig.stale_blocks` (at the manifest's `queue.stale_blocks_slot`)
//! against it at every queued round, and the scheduler computes no head
//! where the two differ.

use std::path::PathBuf;

use eyre::ensure;
use serde::Deserialize;
use sidecar_core::error::Refusal;
use sidecar_core::field::FieldHex;
use sidecar_core::manifest::QueuedIntake;

use crate::chain::rpc::{HttpTransport, url_origin};
use crate::intake::intake_source;

// Operator knob: DESIGN.md, "Configuration reference" (`[[tip.namespaces]]`).
// The tip contracts this machine serves; the same list at the three nodes
// and the orchestrator.
/// One `[[tip.namespaces]]` entry: a tip contract the machine serves.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TipNamespace {
    /// The app contract's address: the namespace, the emitter of its logs
    /// and the holder of its queue and commitment slots.
    pub contract: FieldHex,
}

/// The default L2 block time at which [`check_enc_grace`] counts a receipt's
/// life in seconds: 36 s, one Aztec slot. The receipt counts follow
/// proposed blocks, about 6 s apart while the chain is busy, so the slot is
/// the slow end of the rhythm and the check errs toward a longer life.
pub const DEFAULT_BLOCK_TIME_SECS: u64 = 36;

// Operator knob: DESIGN.md, "Configuration reference" (`receipt_ttl_blocks`).
// Default 300 L2 blocks, the same at the three nodes and the orchestrator.
/// The default receipt TTL in L2 blocks.
pub const DEFAULT_RECEIPT_TTL_BLOCKS: u32 = 300;

/// How long a node may need the `enc` scalar a secret-shared receipt's envelopes
/// were sealed to: the node signs at most `ttl + allowance` blocks ahead of
/// its current block, the intake transaction lands by the expiry, and the
/// request is run or skipped within `stale_blocks` of reaching the head.
/// The node opens the stored envelopes only when the round runs, so a
/// rotation inside that life must keep the previous scalar until it ends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReceiptLife {
    /// The node's `receipt_ttl_blocks`.
    pub ttl_blocks: u32,
    /// The node's `receipt_allowance_blocks`.
    pub allowance_blocks: u32,
    /// The stale period after the expiry, in L2 blocks.
    pub stale_blocks: u64,
    /// The block time the blocks convert at, in seconds.
    pub block_time_secs: u64,
}

impl ReceiptLife {
    /// The life in L2 blocks: `ttl + allowance + stale_blocks`.
    pub fn blocks(&self) -> u64 {
        u64::from(self.ttl_blocks)
            .saturating_add(u64::from(self.allowance_blocks))
            .saturating_add(self.stale_blocks)
    }

    /// The life in seconds, at the block time.
    pub fn secs(&self) -> u64 {
        self.blocks().saturating_mul(self.block_time_secs)
    }
}

/// The check every node's `enc` grace window passes: it is at least the
/// receipt life at the block time, so a rotation keeps the previous scalar
/// until every receipt signed under it has run or gone stale. The boundary
/// (a window exactly the life) passes.
pub fn check_enc_grace(enc_grace_secs: u64, life: ReceiptLife) -> eyre::Result<()> {
    ensure!(
        life.block_time_secs > 0,
        "tip.block_time_secs must be at least 1"
    );
    ensure!(
        enc_grace_secs >= life.secs(),
        "the enc grace window ({enc_grace_secs} s) is shorter than a receipt's life: \
         receipt_ttl_blocks {} + receipt_allowance_blocks {} + stale_blocks {} = {} blocks, \
         {} s at tip.block_time_secs {}; a rotation would retire the enc key a queued \
         secret-shared receipt's envelopes are sealed to",
        life.ttl_blocks,
        life.allowance_blocks,
        life.stale_blocks,
        life.blocks(),
        life.secs(),
        life.block_time_secs
    );
    Ok(())
}

/// What REGISTER's intake checks on a node read of the node: its `enc` grace
/// window and its receipt life at the default stale period
/// ([`IntakeSource::check_register`](crate::IntakeSource::check_register)).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RegisterNode {
    /// The node's `enc` grace window, in seconds.
    pub enc_grace_secs: u64,
    /// The node's receipt life, its stale term the default stale period.
    pub life: ReceiptLife,
}

// Operator knob: DESIGN.md, "Configuration reference" (`aztec_node`,
// `aztec_node_ca`). Each node reads its own Aztec node, never the
// orchestrator's; nothing read is trusted for soundness (invariant 13).
/// The Aztec node of a `[tip]` section (`aztec_node`, `aztec_node_ca`), one
/// type in the node's and the orchestrator's config.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AztecNode {
    /// The Aztec node's JSON-RPC URL (`aztec_node`).
    #[serde(rename = "aztec_node")]
    pub url: String,
    /// For an `https://` node: the CA certificate (PEM) its certificate
    /// chains to (`aztec_node_ca`).
    #[serde(rename = "aztec_node_ca", default)]
    pub ca: Option<PathBuf>,
}

impl AztecNode {
    /// The JSON-RPC client of the node, over TLS under `ca` for an
    /// `https://` URL.
    pub fn transport(&self) -> eyre::Result<HttpTransport> {
        let mut transport =
            HttpTransport::new(&self.url).map_err(|e| eyre::eyre!("tip.aztec_node: {e}"))?;
        if let Some(ca) = &self.ca {
            transport = transport.with_tls(sidecar_http::tls::client_config(ca, None)?);
        }
        Ok(transport)
    }
}

/// REGISTER's per-intake check on a node ([`sidecar_core::registry::RegisterHook`])
/// of a package under the queued intake `intake`: the intake's own rules on
/// the manifest, the circuit's shape and the node's facts `node`
/// (`IntakeSource::check_register`: secret-shared receipt intake's stale
/// period against the `enc` grace window, secret-shared on-chain intake's
/// request log bound).
pub fn check_register_intake(
    view: &sidecar_core::registry::RegisterView,
    intake: QueuedIntake,
    node: &RegisterNode,
) -> Result<(), Refusal> {
    let tip =
        crate::TipManifest::queued(view.manifest.clone(), intake, view.contract.stale_blocks());
    intake_source(tip.intake())?.check_register(view.shape, &tip, node)
}

/// The checks every `[tip]` section passes: `aztec_node` is an `http://` or
/// `https://` URL, an `https://` one names its CA, at least one namespace is
/// listed and none twice.
pub fn check_tip(aztec_node: &AztecNode, namespaces: &[TipNamespace]) -> eyre::Result<()> {
    let url = &aztec_node.url;
    ensure!(
        url.starts_with("http://") || url.starts_with("https://"),
        "tip.aztec_node `{}` is not an http:// or https:// URL",
        url_origin(url)
    );
    ensure!(
        !url.starts_with("https://") || aztec_node.ca.is_some(),
        "tip.aztec_node is https://; give tip.aztec_node_ca"
    );
    ensure!(
        !namespaces.is_empty(),
        "tip.namespaces is empty; remove [tip] to run no queued round"
    );
    for (n, ns) in namespaces.iter().enumerate() {
        ensure!(
            !namespaces[..n]
                .iter()
                .any(|other| other.contract == ns.contract),
            "tip.namespaces[{n}]: contract {} is listed twice (one queue per namespace)",
            ns.contract
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {

    use serde_json::{Value, json};
    use sidecar_core::ErrorClass;
    use sidecar_core::manifest::{DEFAULT_STALE_BLOCKS, Manifest};

    use super::{DEFAULT_BLOCK_TIME_SECS, ReceiptLife, RegisterNode, check_enc_grace};
    use crate::TipManifest;
    use crate::synth::TipPackage;
    use crate::testing::shared_package;

    const DAY: u64 = 24 * 60 * 60;

    /// REGISTER's intake check (`IntakeSource::check_register`) of
    /// `manifest`'s queued intake under the namespace stale period
    /// `stale_blocks`, on a node with the window `grace` and the life `life`.
    /// The circuit's shape is the secret-shared receipt vectors' round's,
    /// which no intake's stale rule reads.
    fn check_register_stale(
        (manifest, stale_blocks): (Manifest, Option<u64>),
        grace: u64,
        life: ReceiptLife,
    ) -> Result<(), sidecar_core::Refusal> {
        let intake = manifest.queued_intake().unwrap();
        let shape = TipPackage::from_row(&shared_package(), Some(DEFAULT_STALE_BLOCKS))
            .unwrap()
            .unwrap()
            .shape;
        let tip = TipManifest::queued(manifest, intake, stale_blocks);
        let node = RegisterNode {
            enc_grace_secs: grace,
            life,
        };
        crate::intake_source(intake)?.check_register(&shape, &tip, &node)
    }

    fn life(ttl_blocks: u32) -> ReceiptLife {
        ReceiptLife {
            ttl_blocks,
            allowance_blocks: 10,
            stale_blocks: DEFAULT_STALE_BLOCKS,
            block_time_secs: DEFAULT_BLOCK_TIME_SECS,
        }
    }

    /// The defaults pass: 300 + 10 + 50 blocks at 36 s is 3.6 hours, inside
    /// the one-day minimum window.
    #[test]
    fn the_default_receipt_life_fits_the_shortest_window() {
        assert_eq!(life(300).blocks(), 360);
        assert_eq!(life(300).secs(), 12_960);
        check_enc_grace(DAY, life(300)).unwrap();
    }

    /// One day at 36 s is 2400 blocks: a life of exactly 2400 passes, one
    /// block more is refused, naming the terms.
    #[test]
    fn a_window_shorter_than_the_receipt_life_is_refused() {
        let boundary = life(2400 - 10 - 50);
        assert_eq!(boundary.secs(), DAY);
        check_enc_grace(DAY, boundary).unwrap();
        let err = check_enc_grace(DAY, life(2400 - 10 - 50 + 1)).unwrap_err();
        let text = format!("{err:#}");
        assert!(text.contains("shorter than a receipt's life"), "{text}");
        assert!(text.contains("2401 blocks"), "{text}");
        // a longer block time makes the same counts a longer life
        let slow = ReceiptLife {
            block_time_secs: 240,
            ..life(300)
        };
        assert_eq!(slow.secs(), 86_400);
        check_enc_grace(DAY, slow).unwrap();
        assert!(check_enc_grace(DAY - 1, slow).is_err());
        let zero = ReceiptLife {
            block_time_secs: 0,
            ..life(300)
        };
        let err = check_enc_grace(DAY, zero).unwrap_err();
        assert!(format!("{err:#}").contains("block_time_secs"), "{err:#}");
    }

    /// The manifest at `path` in a namespace whose contract manifest states
    /// the stale period `stale_blocks` (the examples' 50 when `None`; JSON
    /// null for a head never skipped).
    fn manifest(path: &str, stale_blocks: Option<Value>) -> (Manifest, Option<u64>) {
        let v = sidecar_test_fixtures::vectors::read(path);
        let stale = match stale_blocks {
            None => Some(DEFAULT_STALE_BLOCKS),
            Some(v) => v.as_u64(),
        };
        (Manifest::parse(&v).unwrap(), stale)
    }

    const SHARED: &str = "testvectors/manifests/shared_receipt_round.json";

    /// REGISTER under secret-shared receipt intake: the namespace's stale period
    /// counts in the receipt life (one day at 36 s is 2400 blocks, so with
    /// ttl 300 and allowance 10 a stale period of 2090 fits and 2091 is
    /// refused), and `stale_blocks` null is refused; the field is named.
    #[test]
    fn register_checks_a_shared_receipt_packages_stale_period() {
        let node = life(300);
        check_register_stale(manifest(SHARED, None), DAY, node).unwrap();
        check_register_stale(manifest(SHARED, Some(json!(2090))), DAY, node).unwrap();
        let err = check_register_stale(manifest(SHARED, Some(json!(2091))), DAY, node).unwrap_err();
        assert_eq!(err.class, ErrorClass::BadRequest);
        assert!(
            err.message
                .starts_with("field `manifest.queue.stale_blocks`: the enc grace window"),
            "{err}"
        );
        assert!(
            err.message.contains("stale_blocks 2091 = 2401 blocks"),
            "{err}"
        );
        // the node's block time and window are the ones counted
        let slow = ReceiptLife {
            block_time_secs: 72,
            ..node
        };
        assert!(check_register_stale(manifest(SHARED, Some(json!(2090))), DAY, slow).is_err());
        check_register_stale(manifest(SHARED, Some(json!(2091))), DAY + 36, node).unwrap();
        // null: never skipped, so never bounded
        let err =
            check_register_stale(manifest(SHARED, Some(Value::Null)), 30 * DAY, node).unwrap_err();
        assert_eq!(err.class, ErrorClass::BadRequest);
        assert!(
            err.message.contains(
                "field `manifest.queue.stale_blocks`: null (a head never skipped) is refused \
                 under secret-shared receipt intake"
            ),
            "{err}"
        );
    }

    /// The non-secret-shared intakes seal nothing to `enc` at intake: a long
    /// or null stale period registers under any window.
    #[test]
    fn register_leaves_the_plain_intakes_alone() {
        for path in [
            "examples/amm-tip/manifests/amm_swap_tip.json",
            "examples/amm-tip/manifests/amm_swap_tip_receipt.json",
        ] {
            for stale in [json!(1_000_000), Value::Null] {
                check_register_stale(manifest(path, Some(stale)), DAY, life(300)).unwrap();
            }
        }
    }

    /// The manifest's default stale period is the contract library's
    /// `DEFAULT_STALE_BLOCKS`, so a contract deployed with the library's
    /// default holds the value of a manifest that leaves `stale_blocks` out.
    #[test]
    fn the_default_stale_period_is_the_contract_librarys() {
        let path =
            sidecar_test_fixtures::dirs::repo().join("noir/pss_public_contract/src/config.nr");
        let noir = std::fs::read_to_string(&path).unwrap();
        let line = "pub global DEFAULT_STALE_BLOCKS: u32 = ";
        let value = noir
            .lines()
            .find_map(|l| l.trim().strip_prefix(line))
            .and_then(|rest| rest.strip_suffix(';'))
            .unwrap_or_else(|| panic!("no `{line}` in {}", path.display()));
        assert_eq!(value.parse::<u64>().unwrap(), DEFAULT_STALE_BLOCKS);
    }
}
