//! Node replacement on the operator's side (docs/ARCHITECTURE.md section 6,
//! "Node replacement and key epochs"; DESIGN.md, "Node replacement"):
//! `sidecar-node replace-node` runs one MPC session of the two remaining nodes
//! and the newcomer, each with the same departed index and the same new key set
//! (the newcomer's keys in the departed node's place):
//!
//! ```text
//! remaining  through the running node's admin socket (`replace_node`): rounds refused
//!            and every namespace lock taken, then its own keys checked against the
//!            new set, its tip namespaces' key epochs read from its own chain view;
//!            then the mesh lock, the session handshake, and
//!            sidecar_core::replace::replace (refresh, the newcomer's import, the checks,
//!            the declarations); the refreshed master share and the refresh journal are
//!            written to the key directory
//! newcomer   not served yet: `replace-node` loads it from its config (keys from
//!            `setup --newcomer`, an empty store), joins the same session, and writes its
//!            installed master share to its key directory when every check passed; the
//!            operator then starts it with `serve`
//! ```
//!
//! Before it: the orchestrator paused (`sidecar-orchestrator pause`), and the
//! two remaining nodes restarted with the newcomer's mesh address and
//! certificate in its place. After it: the printed `rotate_keys` arguments
//! submitted to every namespace whose contract manifest says `node_keys:
//! rotating` (one whose manifest says `fixed` has no `rotate_keys`: the
//! report names it under `redeploy`, and its app is redeployed), the
//! orchestrator configured with
//! the new key set and resumed. Every refusal is every node's: a node that refuses
//! before the session still joins the handshake with its refusal.

use std::path::Path;

use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sidecar_core::Refusal;
use sidecar_core::bind::Share;
use sidecar_core::field::{FieldHex, Fr, fr_to_hex};
use sidecar_core::handshake::Handshake;
use sidecar_core::key_epoch::KeySetEpochs;
use sidecar_core::keys::KeyFiles;
use sidecar_core::manifest::contract::NodeKeysAxis;
use sidecar_core::replace::{self, Journal, Persist, ReplaceReport};
use sidecar_core::request::NODES;
use sidecar_core::response::NodesResponse;
use sidecar_core::resync;
use sidecar_core::store::Store;

use crate::recovery::{chain_views, circuit, join};
use crate::server::App;

/// The refresh journal's file in the key directory.
pub const JOURNAL_FILE: &str = "refresh.json";

/// The key directory as the replacement persists into it: the journal
/// (`refresh.json`) and the master share (`master.share`).
pub struct KeyDirPersist {
    files: KeyFiles,
}

impl KeyDirPersist {
    pub fn new(files: KeyFiles) -> Self {
        KeyDirPersist { files }
    }

    fn journal_path(&self) -> std::path::PathBuf {
        self.files.dir().join(JOURNAL_FILE)
    }
}

fn io(what: &str, path: &Path, e: impl std::fmt::Display) -> Refusal {
    Refusal::mpc_failure(format!("replace: {what} {}: {e}", path.display()))
}

impl Persist for KeyDirPersist {
    fn journal(&self) -> Result<Option<Journal>, Refusal> {
        let path = self.journal_path();
        match std::fs::read_to_string(&path) {
            Ok(text) => serde_json::from_str(&text)
                .map(Some)
                .map_err(|e| io("parsing", &path, e)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(io("reading", &path, e)),
        }
    }

    fn save_journal(&self, journal: &Journal) -> Result<(), Refusal> {
        let path = self.journal_path();
        let mut text = serde_json::to_string(journal).expect("a journal serialises");
        text.push('\n');
        crate::files::write_file(&path, text.as_bytes(), true).map_err(|e| io("writing", &path, e))
    }

    fn clear_journal(&self) -> Result<(), Refusal> {
        let path = self.journal_path();
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(io("removing", &path, e)),
        }
    }

    fn save_master(&self, master: Share) -> Result<(), Refusal> {
        crate::setup::write_master_share(&self.files, master).map_err(|e| {
            io(
                "writing the master share to",
                &self.files.master_share_path(),
                format!("{e:#}"),
            )
        })
    }
}

/// The `node_keys` axis of `namespace`'s registered tip contract manifest in
/// this node's store; `None` without one (nothing registered, or the
/// sidecar path).
fn node_keys<S: Store>(app: &App<S>, namespace: Fr) -> Result<Option<NodeKeysAxis>, Refusal> {
    let Some(row) = app.node.store.contract_manifest(namespace)? else {
        return Ok(None);
    };
    let checked = row.parse()?;
    Ok(checked
        .document
        .queue
        .is_some()
        .then_some(checked.document.node_keys))
}

/// The key epochs a remaining node declares: every `[tip]` namespace whose
/// contract manifest says `node_keys: rotating`, at its current key epoch +
/// 1, read from the node's own chain view; none without `[tip]` (no
/// contract pins this network's keys).
fn declarations<S: Store>(app: &App<S>) -> Result<Vec<(Fr, u32)>, Refusal> {
    let mut out = Vec::new();
    for (ns, keys) in app.receipts.chain.key_epochs()?.unwrap_or_default() {
        if node_keys(app, ns)? == Some(NodeKeysAxis::Rotating) {
            out.push((ns, keys.epoch + 1));
        }
    }
    Ok(out)
}

/// The registered tip namespaces whose contract manifest says `node_keys:
/// fixed`: a replacement cannot move them.
fn fixed_key_sets<S: Store>(app: &App<S>) -> Result<Vec<FieldHex>, Refusal> {
    let mut out = Vec::new();
    for ns in app.node.store.namespaces()? {
        if node_keys(app, ns)? == Some(NodeKeysAxis::Fixed) {
            out.push(FieldHex(ns));
        }
    }
    Ok(out)
}

/// Replace node `departed` by the newcomer whose keys `pins` holds in its
/// place; this node is one of the two remaining nodes or the newcomer (all
/// three run it at once). The node's key directory is its rotation's.
pub fn replace<S: Store>(
    app: &App<S>,
    departed: usize,
    pins: &NodesResponse,
) -> Result<ReplaceReport, Refusal> {
    let node = &app.node;
    if departed >= NODES {
        return Err(Refusal::bad_request(format!(
            "field `departed`: {departed} is not a node index (0, 1 or 2)"
        )));
    }
    let newcomer = node.index == departed;
    let files = &app.rotation.files;
    // the mark that refuses rounds, every namespace lock, then the mesh lock
    // (a store that does not list refuses in the handshake, below)
    let listed = node.store.namespaces();
    let held = node.maintain("node replacement", listed.clone().unwrap_or_default());
    let pre = (|| {
        listed?;
        resync::check_own_pins(&node.keys(), node.index, pins)?;
        let declare = if newcomer {
            if !node.store.namespaces()?.is_empty() {
                return Err(Refusal::conflict(
                    "replace: the newcomer's store holds namespaces; a newcomer starts from an \
                     empty store",
                ));
            }
            Vec::new()
        } else {
            declarations(app)?
        };
        Ok((declare, circuit(app)?))
    })();
    tracing::info!(departed, newcomer, "replace: joining the session");
    let net = app.connect_mesh(held.mesh())?;
    let hs = Handshake::build(
        replace::session_id(),
        replace::session_body(departed, pins),
        &[],
        &[],
    );
    let (declare, circuit) = join(&net, &hs, pre)?;
    let persist = KeyDirPersist::new(files.clone());
    let views = chain_views(app);
    let report = replace::replace(
        node,
        held.namespaces(),
        &circuit,
        &net,
        departed,
        pins,
        &persist,
        &views,
        &declare,
        &mut OsRng,
    )?;
    // the newcomer's store holds the imported contract manifests by now
    let mut report = report;
    report.redeploy = fixed_key_sets(app)?;
    if !report.rotations.is_empty() {
        let mut sets = read_key_sets(files)?;
        for r in &report.rotations {
            sets.declare(r.namespace.fr(), r.epoch, pins);
        }
        write_key_sets(files, &sets)?;
    }
    tracing::info!(
        departed,
        refreshed = ?report.refreshed,
        namespaces = report.resync.imported.namespaces,
        versions = report.resync.imported.versions,
        audited = report.resync.audit.len(),
        passed = report.passed(),
        rotations = report.rotations.len(),
        redeploy = report.redeploy.len(),
        "replace done"
    );
    Ok(report)
}

/// The declared key-set rotations' file in the key directory
/// ([`sidecar_core::key_epoch::KeySetEpochs`]).
pub const KEY_SETS_FILE: &str = "key_epochs.json";

fn key_sets_path(files: &KeyFiles) -> std::path::PathBuf {
    files.dir().join(KEY_SETS_FILE)
}

/// The declared key-set rotations this node keeps (none when the file is
/// absent).
pub fn read_key_sets(files: &KeyFiles) -> Result<KeySetEpochs, Refusal> {
    let path = key_sets_path(files);
    match std::fs::read_to_string(&path) {
        Ok(text) => KeySetEpochs::from_json(&text).map_err(|e| io("parsing", &path, e)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(KeySetEpochs::default()),
        Err(e) => Err(io("reading", &path, e)),
    }
}

fn write_key_sets(files: &KeyFiles, sets: &KeySetEpochs) -> Result<(), Refusal> {
    let path = key_sets_path(files);
    let mut text = sets.to_json();
    text.push('\n');
    crate::files::write_file(&path, text.as_bytes(), true).map_err(|e| io("writing", &path, e))
}

/// One contract's declared key-set rotation as the pruning job observed it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeySetObserved {
    pub namespace: FieldHex,
    /// The declared epoch.
    pub epoch: u32,
    /// The contract's stored key epoch at the block read.
    pub stored_epoch: u32,
    /// Whether the rotation has landed (recorded now or before).
    pub landed: bool,
}

// The key-set half of the pruning job, the record-on-landing rule of the
// enc rotation (`rotation::observe_epochs`): a replacement keeps each
// contract's declared rotation pending in `key_epochs.json`; every run reads
// the pending contracts' key epochs through the node's own chain view and
// records each rotation the contract now carries (or has moved past). The
// operator reads what is still pending in the prune answer; the orchestrator
// computes nothing for a contract whose key set is not its configured one.
/// Observe every pending key-set rotation; empty without a pending one or a
/// chain view (no `[tip]`).
pub fn observe_key_sets<S: Store>(app: &App<S>) -> Result<Vec<KeySetObserved>, Refusal> {
    let rotation = &app.rotation;
    let mut sets = read_key_sets(&rotation.files)?;
    let pending = sets.pending();
    if pending.is_empty() {
        return Ok(Vec::new());
    }
    let stored = match app.receipts.chain.key_epochs() {
        Ok(Some(stored)) => stored,
        Ok(None) => return Ok(Vec::new()),
        Err(r) => {
            tracing::warn!(error = %r, "key sets: the chain view did not answer; pending kept");
            return Ok(Vec::new());
        }
    };
    let mut observed = Vec::new();
    let mut changed = false;
    for (contract, epoch) in pending {
        let Some((_, at)) = stored.iter().find(|(c, _)| *c == contract) else {
            continue;
        };
        let landed = sets.land(contract, at).is_some();
        if landed {
            changed = true;
            tracing::info!(
                namespace = %fr_to_hex(contract),
                epoch,
                "the key-set rotation landed in the contract; recorded"
            );
        } else {
            tracing::info!(
                namespace = %fr_to_hex(contract),
                epoch,
                stored_epoch = at.epoch,
                "the key-set rotation is still pending in the contract"
            );
        }
        observed.push(KeySetObserved {
            namespace: FieldHex(contract),
            epoch,
            stored_epoch: at.epoch,
            landed,
        });
    }
    if changed {
        write_key_sets(&rotation.files, &sets)?;
    }
    Ok(observed)
}

/// The new key set: `pins` (the current set, as `GET /v1/nodes` answers it)
/// with the newcomer's keys in place `departed`.
pub fn new_key_set(
    pins: &NodesResponse,
    departed: usize,
    newcomer: sidecar_core::response::NodePublicKeys,
) -> Result<NodesResponse, Refusal> {
    if departed >= NODES {
        return Err(Refusal::bad_request(format!(
            "`--departed {departed}` is not a node index (0, 1 or 2)"
        )));
    }
    let mut keys = *pins;
    if keys.nodes[departed] == newcomer {
        return Err(Refusal::bad_request(
            "the newcomer's keys are the departed node's: a replacement brings new keys",
        ));
    }
    keys.nodes[departed] = newcomer;
    Ok(keys)
}
