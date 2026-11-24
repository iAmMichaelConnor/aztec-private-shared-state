//! Node recovery on the operator's admin socket (docs/ARCHITECTURE.md
//! section 6, "Node-held state", recovery; DESIGN.md, "Recovery"): the
//! resync of a node from its two neighbours (its lost store, or one tip key
//! of its store), the restore of its store from its backup (a delta resync:
//! the backup's pairs, and the neighbours' for what was written since), and
//! the audit of node-held tip state. Each is one MPC session of the three
//! nodes, so the operator runs the same command on all three at once, as
//! with `setup`; none is ever served on the HTTPS listener or through the
//! orchestrator.
//!
//! ```text
//! resync  every node: its own pinned keys checked; a neighbour marks its node-held
//!         versions against its own chain view and reads its bundle under each
//!         namespace's lock; then the mesh lock, the session handshake (the lost node,
//!         the scope and the pinned keys must agree), and sidecar_core::resync::run
//! restore the same, under the delta scope: the restored node first reads and opens
//!         its backup file under the operator's backup key (crate::backup)
//! audit   every node: its versions marked against its own chain view and its audit
//!         targets read under each namespace's lock; then the mesh lock, the session
//!         handshake (the namespaces must agree), and one sidecar_core::audit round per
//!         key
//! ```
//!
//! A node that refuses before the session (wrong pins, a store it cannot
//! read) still joins the handshake with its refusal, so the other two refuse
//! with it instead of waiting out the mesh's connect timeout.
//!
//! Each node marks its versions first ([`chain_views`]) because it marks
//! them on its own schedule otherwise (a round's commit on the key, or the
//! pruning job's timer): a neighbour whose last mark is older than the
//! other's would send other versions, and pick another canonical version
//! to audit.

use std::path::Path;

use rand::rngs::OsRng;
use sidecar_core::Refusal;
use sidecar_core::audit::{self, AUDIT_LABEL, KeyAudit, Targets};
use sidecar_core::backup::StoreExport;
use sidecar_core::crs::Circuit;
use sidecar_core::field::{Fr, RequestId};
use sidecar_core::handshake::{self, Handshake};
use sidecar_core::hash::poseidon2_hash;
use sidecar_core::keys::{KeyFiles, label_field};
use sidecar_core::pipeline::UnverifiedHook;
use sidecar_core::request::NODES;
use sidecar_core::response::NodesResponse;
use sidecar_core::resync::{self, ResyncReport, Scope};
use sidecar_core::store::Store;
use sidecar_core::store::rules::VersionView;

use crate::backup::{self, BackupKey};
use crate::server::App;

/// This node's own chain view of its node-held versions, the one the
/// pruning job marks them against (the `[tip]` Aztec node's; none without
/// `[tip]`), for [`sidecar_core::state::NodeVersions::mark`].
pub fn chain_views<S: Store>(
    app: &App<S>,
) -> impl Fn(Fr, &[String]) -> Result<Option<Vec<VersionView>>, Refusal> + Sync + '_ {
    |namespace, keys| {
        app.receipts
            .chain
            .version_views(&app.node.store, namespace, keys)
    }
}

pub(crate) fn circuit<S: Store>(app: &App<S>) -> Result<Circuit, Refusal> {
    audit::audit_circuit(&app.node.crs).map_err(|e| {
        Refusal::mpc_failure(format!(
            "the audit circuit does not build under this node's CRS: {e:#}"
        ))
    })
}

/// Join the session `hs` with this node's result so far: its refusal as its
/// verdict, or the handshake proper.
pub(crate) fn join<N: mpc_net::Network, T>(
    net: &N,
    hs: &Handshake,
    pre: Result<T, Refusal>,
) -> Result<T, Refusal> {
    match pre {
        Err(refusal) => Err(handshake::exchange_refusing(net, hs, refusal)),
        Ok(value) => handshake::exchange(net, hs).map(|()| value),
    }
}

/// Resync `scope` of node `lost` from its neighbours (this node is `lost`
/// or one of them), with `pins` the three nodes' pinned public keys.
pub fn resync<S: Store>(
    app: &App<S>,
    lost: usize,
    scope: &Scope,
    pins: &NodesResponse,
) -> Result<ResyncReport, Refusal> {
    session(app, lost, scope, pins, None)
}

/// Restore node `lost`'s store from its backup with a delta resync from
/// its neighbours (this node is `lost` or one of them). At the restored
/// node `backup` is the backup file and the operator's backup key; a
/// neighbour takes none.
pub fn restore<S: Store>(
    app: &App<S>,
    lost: usize,
    pins: &NodesResponse,
    backup: Option<(&Path, &BackupKey)>,
) -> Result<ResyncReport, Refusal> {
    session(app, lost, &Scope::Delta, pins, backup)
}

fn session<S: Store>(
    app: &App<S>,
    lost: usize,
    scope: &Scope,
    pins: &NodesResponse,
    backup: Option<(&Path, &BackupKey)>,
) -> Result<ResyncReport, Refusal> {
    let node = &app.node;
    if lost >= NODES {
        return Err(Refusal::bad_request(format!(
            "field `lost`: {lost} is not a node index (0, 1 or 2)"
        )));
    }
    // the mark that refuses rounds, the scope's namespace locks, then the
    // mesh lock, held to the end of the session
    // (a store that does not list refuses in the handshake, below)
    let listed = scope.namespaces(&node.store);
    let held = node.maintain("resync", listed.clone().unwrap_or_default());
    let pre = (|| {
        listed?;
        resync::check_own_pins(&node.keys(), node.index, pins)?;
        let (sent, export): (_, Option<StoreExport>) = if node.index == lost {
            let export = match backup {
                Some((path, key)) => Some(backup::read_store(path, key, node.index)?),
                None if scope.restores_backup() => {
                    return Err(Refusal::bad_request(format!(
                        "restore: node {lost}, the node restored, takes its backup and the \
                         backup key"
                    )));
                }
                None => None,
            };
            (None, export)
        } else {
            if backup.is_some() {
                return Err(Refusal::bad_request(format!(
                    "restore: only node {lost}, the node restored, takes a backup; a \
                     neighbour runs the command without one"
                )));
            }
            let views = chain_views(app);
            (
                Some(resync::collect(
                    node,
                    held.namespaces(),
                    lost,
                    scope,
                    &views,
                )?),
                None,
            )
        };
        Ok((sent, export, circuit(app)?))
    })();
    tracing::info!(lost, ?scope, "resync: joining the session");
    let net = app.connect_mesh(held.mesh())?;
    let hs = Handshake::build(
        resync::session_id(),
        resync::session_body(lost, scope, pins),
        &[],
        &[],
    );
    let (sent, export, circuit) = join(&net, &hs, pre)?;
    let report = resync::run(
        node,
        &circuit,
        &net,
        lost,
        scope,
        pins,
        sent,
        export.as_ref(),
        &mut OsRng,
    )?;
    tracing::info!(
        lost,
        namespaces = report.imported.namespaces,
        versions = report.imported.versions,
        tree_nodes = report.imported.tree_nodes,
        values = report.imported.values,
        consumed = report.imported.consumed,
        receipts = report.imported.receipts,
        receipts_left_out = report.imported.receipts_left_out,
        requests = report.imported.requests,
        dead_records = report.imported.dead_records,
        from_backup = report.imported.from_backup,
        audited = report.audit.len(),
        passed = report.passed(),
        "resync done"
    );
    Ok(report)
}

/// The file in the key directory that marks a store holding a resync
/// import whose checks have not passed (`Node::mark_unverified`); it holds
/// what was imported.
pub const UNVERIFIED_FILE: &str = "store.unverified";

/// The hook that persists the unverified-store mark as [`UNVERIFIED_FILE`]
/// in the key directory of `files`, and the mark an earlier run left there.
pub fn unverified_store(files: &KeyFiles) -> eyre::Result<(UnverifiedHook, Option<String>)> {
    let path = files.dir().join(UNVERIFIED_FILE);
    let persisted = match std::fs::read_to_string(&path) {
        Ok(text) => Some(text.trim().to_string()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => eyre::bail!("reading {}: {e}", path.display()),
    };
    let hook: UnverifiedHook = Box::new(move |why| {
        let done = match why {
            Some(why) => crate::files::write_file(&path, format!("{why}\n").as_bytes(), false),
            None => match std::fs::remove_file(&path) {
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                    Err(eyre::eyre!("removing {}: {e}", path.display()))
                }
                _ => Ok(()),
            },
        };
        done.map_err(|e| Refusal::mpc_failure(format!("the unverified-store mark: {e:#}")))
    });
    Ok((hook, persisted))
}

/// Audit node-held tip state: every namespace of the store, or
/// `namespace` alone.
pub fn audit<S: Store>(app: &App<S>, namespace: Option<Fr>) -> Result<Vec<KeyAudit>, Refusal> {
    let node = &app.node;
    let pre = (|| -> Result<(Vec<(Fr, Targets)>, Circuit), Refusal> {
        let namespaces = match namespace {
            Some(ns) => vec![ns],
            None => node.store.namespaces()?,
        };
        let views = chain_views(app);
        let mut all = Vec::new();
        for ns in namespaces {
            all.push((ns, audit::marked_targets(node, ns, &views)?));
        }
        Ok((all, circuit(app)?))
    })();
    let namespaces: Vec<Fr> = match &pre {
        Ok((all, _)) => all.iter().map(|(ns, _)| *ns).collect(),
        Err(_) => namespace.into_iter().collect(),
    };
    let mut body = vec![label_field(AUDIT_LABEL)];
    body.extend(&namespaces);
    let hs = Handshake::build(
        RequestId(label_field(AUDIT_LABEL)),
        poseidon2_hash(&body),
        &[],
        &[],
    );
    let mesh = node.lock_mesh();
    let net = app.connect_mesh(&mesh)?;
    let (all, circuit) = join(&net, &hs, pre)?;
    let mut out = Vec::new();
    for (ns, targets) in all {
        out.extend(audit::audit(&circuit, &node.crs, ns, targets, &net)?);
    }
    tracing::info!(
        keys = out.len(),
        failed = out.iter().filter(|k| k.failed_audit()).count(),
        not_audited = out
            .iter()
            .filter(|k| !k.passed() && !k.failed_audit())
            .count(),
        "audit done"
    );
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The mark is written into the key directory, read back by the next
    /// start, and removed when cleared.
    #[test]
    fn the_unverified_store_mark_outlives_a_restart() {
        let dir = sidecar_test_fixtures::dirs::TempDir::new("sidecar-node-unverified");
        let files = KeyFiles::new(dir.path().to_path_buf());
        let (hook, persisted) = unverified_store(&files).unwrap();
        assert_eq!(persisted, None);
        hook(Some("a store resync's import")).unwrap();
        let (hook, persisted) = unverified_store(&files).unwrap();
        assert_eq!(persisted.as_deref(), Some("a store resync's import"));
        hook(None).unwrap();
        hook(None).unwrap();
        assert_eq!(unverified_store(&files).unwrap().1, None);
    }
}
