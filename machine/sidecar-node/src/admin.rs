//! The operator-only admin socket: a Unix domain socket in the node's run
//! directory, never served by the TLS listener, carrying the per-request
//! rollback (`restore`, ARCHITECTURE.md section 3, the rollback path), a
//! one-shot `prune` of the `requests` and `receipts` tables, the node-held
//! tip versions and the secret-shared on-chain epoch scalars, the rotation of the node's
//! `enc` key (`rotate_enc`, ARCHITECTURE.md section 2), the signed rotation of
//! its `enc` key into an app contract (`sign_enc_key`, secret-shared on-chain
//! intake, section 6), the store backup
//! (`backup`, the `backup` module), node recovery (`resync`,
//! `restore_backup` and `audit`, ARCHITECTURE.md section 6; the `recovery`
//! module), the read-only comparison of the three nodes' registry rows
//! (`check_registry`, `sidecar_core::registry_check`) and the resync of one
//! node's registry rows from a neighbour (`resync_registry`,
//! `sidecar_core::resync::resync_registry`), which all three nodes run at
//! once.
//!
//! Plain JSON, one object per line each way:
//!
//! ```text
//! -> {"op": "restore", "namespace": "0x..", "request_id": "0x.."}
//! <- {"ok": true}
//! -> {"op": "prune"}
//! <- {"ok": true, "pruned": 3, "pruned_receipts": 1, "kept_receipts": 2, "pruned_versions": 4,
//!     "enc_epochs": [{"namespace": "0x..", "stored_epoch": 2, "recorded": [2], "retired": []}],
//!     "key_sets": [{"namespace": "0x..", "epoch": 1, "stored_epoch": 1, "landed": true}]}
//! <- {"ok": true, "pruned": 3, "receipts_not_pruned": "this node has no [tip] section, ...",
//!     "pruned_versions": 0}
//! -> {"op": "rotate_enc", "force": false}
//! <- {"ok": true, "rotated": {"enc": {..}, "sig": {..}, "key_id": "0x..",
//!                             "previous_key_id": "0x..", "previous_retires_at": 1790000000}}
//! <- {"ok": false, "refusal": {"class": "conflict", "error": "..."}}
//! -> {"op": "sign_enc_key", "namespace": "0x..", "epoch": 1}
//! <- {"ok": true, "enc_key": {"index": 0, "namespace": "0x..", "enc": {..}, "epoch": 1,
//!                             "signature": {"s": [..], "e": [..]}}}
//! -> {"op": "resync", "lost": 1, "pins": {"nodes": [{"enc": {..}, "sig": {..}}, ..]}}
//! <- {"ok": true, "resync": {"lost": 1, "scope": {"kind": "store"}, "imported": {..},
//!                            "npk_checked": [..], "audit": [..]}}
//! -> {"op": "resync_key", "lost": 1, "namespace": "0x..", "key": "0xa002", "pins": {..}}
//! <- {"ok": true, "resync": {"lost": 1, "scope": {"kind": "key", ..}, "imported": {..},
//!                            "npk_checked": [], "audit": [..]}}
//! -> {"op": "audit", "namespace": "0x.."}
//! <- {"ok": true, "audit": [{"namespace": "0x..", "key": "0xa002", "outcome": "passed", ..}]}
//! -> {"op": "backup", "out": "/backups/node1.store", "key": "<64 hex digits>"}
//! <- {"ok": true, "backed_up": {"namespaces": 1, "versions": 3, ..}}
//! -> {"op": "restore_backup", "lost": 1, "pins": {..},
//!     "backup": "/backups/node1.store", "key": "<64 hex digits>"}   (the restored node)
//! -> {"op": "restore_backup", "lost": 1, "pins": {..}}               (each neighbour)
//! <- {"ok": true, "resync": {"lost": 1, "scope": {"kind": "delta"}, "imported": {..},
//!                            "npk_checked": [..], "audit": [..]}}
//! -> {"op": "check_registry", "namespace": "0x.."}
//! <- {"ok": true, "registry": {"namespaces": 1, "packages": 3, "divergences": [
//!       {"namespace": "0x..", "row": "package `pss_seed`", "held": [
//!         {"holders": ["node 0", "node 1"], "row": "seq 3, disabled, vk_hash 0x.."},
//!         {"holders": ["node 2"], "row": "seq 0, enabled, vk_hash 0x.."}]}]}}
//! -> {"op": "resync_registry", "lost": 2, "from": 1}
//! <- {"ok": true, "registry_resync": {"lost": 2, "from": 1, "repaired": [..],
//!                                     "namespaces": 1, "packages": 3, "vks_built": 2}}
//! -> {"op": "replace_node", "departed": 2, "pins": {"nodes": [..]}}   (the new key set)
//! <- {"ok": true, "replaced": {"departed": 2, "refreshed": {..}, "resync": {..},
//!                              "rotations": [{"namespace": "0x..", "epoch": 1,
//!                                             "keys": {"sig": [..], "enc": [..]},
//!                                             "signatures": [{..}, {..}, null]}]}}
//! ```
//!
//! `sidecar-node restore`, `prune`, `rotate-enc`, `sign-enc-key`, `resync`, `audit`,
//! `backup`, `restore-backup`, `sync-registry` (`--check`, or `--lost` and
//! `--from`) and `replace-node` (at a remaining node; the newcomer runs it
//! without a socket, crate::replace) are clients of this socket. The backup key
//! travels in the command only: the node never writes it.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use sidecar_core::Refusal;
use sidecar_core::audit::KeyAudit;
use sidecar_core::backup::ExportCounts;
use sidecar_core::field::{FieldHex, RequestId};
use sidecar_core::pipeline;
use sidecar_core::registry_check::{self, RegistryCheck};
use sidecar_core::replace::ReplaceReport;
use sidecar_core::response::NodesResponse;
use sidecar_core::resync::{self, RegistryResync, ResyncReport, Scope};
use sidecar_core::state::NodeVersions;
use sidecar_core::store::Store;
use tokio::net::UnixListener;
use tracing::Instrument;

use crate::backup::{self, BackupKey};
use crate::receipt::ReceiptPruning;
use crate::recovery;
use crate::replace::KeySetObserved;
use crate::rotation::{self, EncKeySigned, EncRotated, EpochsObserved};
use crate::server::App;

/// One admin command.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum AdminRequest {
    /// Roll back one committed request (run it on all three nodes, newest
    /// request first).
    Restore {
        namespace: FieldHex,
        request_id: RequestId,
    },
    /// Delete the `requests` rows older than the retention window, and the
    /// receipts past `expiry_block + stale_blocks` whose request never
    /// reached the queue or is done in the node's own chain view, mark
    /// every node-held tip key's versions against that view, deleting the
    /// orphans marked below its settled block, and record each secret-shared on-chain
    /// epoch whose rotation landed and retire each scalar no queued request
    /// can name, now.
    Prune,
    /// Rotate the node's enc key; refused while the previous key is inside
    /// its grace window unless `force`.
    RotateEnc {
        #[serde(default)]
        force: bool,
    },
    /// Keep the node's current enc scalar pending as `epoch`'s in the app
    /// contract `namespace` and sign the contract's rotation to its public
    /// key (secret-shared on-chain intake); the operator submits `rotate_enc_key`,
    /// and the pruning job records the scalar once it has landed.
    SignEncKey { namespace: FieldHex, epoch: u32 },
    /// Resync node `lost`'s store from its two neighbours, then check every
    /// namespace's npk_app_hash and audit it (run it on all three nodes at
    /// once). `pins` are the three nodes' pinned public keys.
    Resync {
        lost: usize,
        pins: Box<NodesResponse>,
    },
    /// Resync one tip key of node `lost`'s store from its two neighbours:
    /// their canonical and live versions of `key` under `namespace`, with
    /// their clear trees, replace the node's; then audit the key (run it on
    /// all three nodes at once).
    ResyncKey {
        lost: usize,
        namespace: FieldHex,
        key: String,
        pins: Box<NodesResponse>,
    },
    /// Audit the canonical version of every node-held tip key: of every
    /// namespace, or of `namespace` (run it on all three nodes at once).
    Audit {
        #[serde(default)]
        namespace: Option<FieldHex>,
    },
    /// Back up this node's store to the new file `out` (an absolute path),
    /// encrypted under the operator's backup `key`.
    Backup { out: PathBuf, key: BackupKey },
    /// Restore node `lost`'s store from its backup with a delta resync from
    /// its two neighbours, then check every namespace's npk_app_hash and
    /// audit it (run it on all three nodes at once). The restored node gives
    /// its `backup` file (an absolute path) and the backup `key`; a
    /// neighbour gives neither.
    RestoreBackup {
        lost: usize,
        pins: Box<NodesResponse>,
        #[serde(default)]
        backup: Option<PathBuf>,
        #[serde(default)]
        key: Option<BackupKey>,
    },
    /// Compare this node's registry rows with its two neighbours': of
    /// `namespace`, or of every namespace any of the three holds (run it on
    /// all three nodes at once). Writes nothing.
    CheckRegistry {
        #[serde(default)]
        namespace: Option<FieldHex>,
    },
    /// Resync node `lost`'s registry rows from node `from`, once the other
    /// two are seen to hold the same rows (run it on all three nodes at
    /// once). Node `lost` keeps its nsk_app shares and builds each vk itself.
    ResyncRegistry { lost: usize, from: usize },
    /// Replace node `departed` by a newcomer (run it on both remaining
    /// nodes while the newcomer runs `replace-node` itself): the share
    /// refresh, the newcomer's import, the checks and the signed
    /// declarations of the new key set `pins` (the newcomer's keys in place
    /// `departed`) for every `[tip]` namespace.
    ReplaceNode {
        departed: usize,
        pins: Box<NodesResponse>,
    },
}

/// The answer to one admin command.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminResponse {
    pub ok: bool,
    /// How many `requests` rows `prune` deleted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pruned: Option<usize>,
    /// How many `receipts` rows `prune` deleted; absent when it read no
    /// chain, and then it pruned none (`receipts_not_pruned` says why).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pruned_receipts: Option<usize>,
    /// How many `receipts` rows past their window `prune` kept, because
    /// their request is still queued (or the reads could not tell).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kept_receipts: Option<usize>,
    /// Why `prune` pruned no receipt: no `[tip]`, or the node's Aztec node
    /// did not answer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipts_not_pruned: Option<String>,
    /// How many node-held tip versions `prune` deleted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pruned_versions: Option<usize>,
    /// What `prune` read and changed of each contract's secret-shared on-chain
    /// epochs (the contracts the node's chain view read).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enc_epochs: Option<Vec<EpochsObserved>>,
    /// The pending key-set rotations `prune` observed, per contract.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_sets: Option<Vec<KeySetObserved>>,
    /// The node's keys after `rotate_enc`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rotated: Option<EncRotated>,
    /// The signed rotation `sign_enc_key` answers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enc_key: Option<EncKeySigned>,
    /// What `resync` did.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resync: Option<ResyncReport>,
    /// What `audit` found, per key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit: Option<Vec<KeyAudit>>,
    /// What `backup` wrote.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backed_up: Option<ExportCounts>,
    /// What `check_registry` found.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registry: Option<RegistryCheck>,
    /// What `resync_registry` did.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registry_resync: Option<RegistryResync>,
    /// What `replace_node` did, with the `rotate_keys` arguments.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replaced: Option<Box<ReplaceReport>>,
    /// Why the command was refused.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refusal: Option<Refusal>,
}

impl AdminResponse {
    fn ok() -> Self {
        AdminResponse {
            ok: true,
            pruned: None,
            pruned_receipts: None,
            kept_receipts: None,
            receipts_not_pruned: None,
            pruned_versions: None,
            enc_epochs: None,
            key_sets: None,
            rotated: None,
            enc_key: None,
            resync: None,
            audit: None,
            backed_up: None,
            registry: None,
            registry_resync: None,
            replaced: None,
            refusal: None,
        }
    }

    fn refused(refusal: Refusal) -> Self {
        AdminResponse {
            ok: false,
            pruned: None,
            pruned_receipts: None,
            kept_receipts: None,
            receipts_not_pruned: None,
            pruned_versions: None,
            enc_epochs: None,
            key_sets: None,
            rotated: None,
            enc_key: None,
            resync: None,
            audit: None,
            backed_up: None,
            registry: None,
            registry_resync: None,
            replaced: None,
            refusal: Some(refusal),
        }
    }
}

// The admin socket and who may reach it. Rollback, the one-shot prune, the
// enc rotation and the contract enc key signature, the backup, the resync,
// the restore, the audit, the registry check and the registry resync are
// served only on a Unix domain socket, by default `<run_dir>/admin.sock`, and
// never on the HTTPS listener or any network port, so neither the
// orchestrator nor anything that reaches the API can roll a request back,
// rotate a key or resync a node (ARCHITECTURE.md sections 2 and 6). The
// socket's permissions, stale-socket handling and path bound are
// `sidecar_http::admin`'s, shared with the orchestrator. The operator runs
// `sidecar-node restore` on each of the three nodes' hosts.
/// Bind the admin socket at `path` ([`sidecar_http::admin::bind`]).
pub fn bind(path: &Path) -> eyre::Result<UnixListener> {
    sidecar_http::admin::bind(path, "node")
}

/// Serve admin commands on `listener` until the task is aborted.
pub async fn serve<S: Store + 'static>(listener: UnixListener, app: Arc<App<S>>) {
    sidecar_http::admin::serve(listener, move |req: Result<AdminRequest, Refusal>| {
        let app = app.clone();
        async move {
            match req {
                Ok(req) => handle(&app, req).await,
                Err(r) => AdminResponse::refused(r),
            }
        }
    })
    .await
}

/// Run one admin command on a thread of its own
/// ([`crate::server::own_thread`]).
pub async fn handle<S: Store + 'static>(app: &Arc<App<S>>, req: AdminRequest) -> AdminResponse {
    let app = app.clone();
    let span = match &req {
        AdminRequest::Restore {
            namespace,
            request_id,
        } => {
            tracing::info_span!("admin", op = "restore", namespace = %namespace, request_id = %request_id)
        }
        AdminRequest::Prune => tracing::info_span!("admin", op = "prune"),
        AdminRequest::RotateEnc { force } => {
            tracing::info_span!("admin", op = "rotate_enc", force = *force)
        }
        AdminRequest::SignEncKey { namespace, epoch } => {
            tracing::info_span!("admin", op = "sign_enc_key", namespace = %namespace, epoch)
        }
        AdminRequest::Resync { lost, .. } => tracing::info_span!("admin", op = "resync", lost),
        AdminRequest::ResyncKey {
            lost,
            namespace,
            key,
            ..
        } => {
            tracing::info_span!("admin", op = "resync_key", lost, namespace = %namespace, key = %key)
        }
        AdminRequest::Audit { .. } => tracing::info_span!("admin", op = "audit"),
        AdminRequest::Backup { out, .. } => {
            tracing::info_span!("admin", op = "backup", out = %out.display())
        }
        AdminRequest::RestoreBackup { lost, .. } => {
            tracing::info_span!("admin", op = "restore_backup", lost)
        }
        AdminRequest::CheckRegistry { .. } => tracing::info_span!("admin", op = "check_registry"),
        AdminRequest::ResyncRegistry { lost, from } => {
            tracing::info_span!("admin", op = "resync_registry", lost, from)
        }
        AdminRequest::ReplaceNode { departed, .. } => {
            tracing::info_span!("admin", op = "replace_node", departed)
        }
    };
    let inner = span.clone();
    let result = crate::server::own_thread("node-admin", move || {
        inner.in_scope(|| match req {
            AdminRequest::Restore {
                namespace,
                request_id,
            } => {
                let views = recovery::chain_views(&app);
                pipeline::restore(&app.node, namespace.fr(), request_id, &views)
                    .map(|()| AdminResponse::ok())
            }
            AdminRequest::Prune => prune(&app).map(|pruned| AdminResponse {
                pruned: Some(pruned.requests),
                pruned_receipts: pruned.receipts.pruned(),
                kept_receipts: match pruned.receipts {
                    ReceiptPruning::Ran { kept, .. } => Some(kept),
                    _ => None,
                },
                receipts_not_pruned: pruned.receipts.not_pruned(),
                pruned_versions: Some(pruned.versions),
                enc_epochs: Some(pruned.epochs),
                key_sets: Some(pruned.key_sets),
                ..AdminResponse::ok()
            }),
            AdminRequest::RotateEnc { force } => {
                rotation::rotate_enc(&app, force).map(|rotated| AdminResponse {
                    rotated: Some(rotated),
                    ..AdminResponse::ok()
                })
            }
            AdminRequest::SignEncKey { namespace, epoch } => {
                rotation::sign_enc_key(&app, namespace.fr(), epoch).map(|signed| AdminResponse {
                    enc_key: Some(signed),
                    ..AdminResponse::ok()
                })
            }
            AdminRequest::Resync { lost, pins } => {
                recovery::resync(&app, lost, &Scope::Store, &pins).map(|report| AdminResponse {
                    resync: Some(report),
                    ..AdminResponse::ok()
                })
            }
            AdminRequest::ResyncKey {
                lost,
                namespace,
                key,
                pins,
            } => {
                recovery::resync(&app, lost, &Scope::Key { namespace, key }, &pins).map(|report| {
                    AdminResponse {
                        resync: Some(report),
                        ..AdminResponse::ok()
                    }
                })
            }
            AdminRequest::Audit { namespace } => recovery::audit(&app, namespace.map(FieldHex::fr))
                .map(|keys| AdminResponse {
                    audit: Some(keys),
                    ..AdminResponse::ok()
                }),
            AdminRequest::Backup { out, key } => {
                let views = recovery::chain_views(&app);
                backup::write_store(&app.node, &views, &out, &key, app.now()).map(|counts| {
                    tracing::info!(?counts, "store backed up");
                    AdminResponse {
                        backed_up: Some(counts),
                        ..AdminResponse::ok()
                    }
                })
            }
            AdminRequest::RestoreBackup {
                lost,
                pins,
                backup,
                key,
            } => {
                let given = match (&backup, &key) {
                    (Some(path), Some(key)) => Ok(Some((path.as_path(), key))),
                    (None, None) => Ok(None),
                    _ => Err(Refusal::bad_request(
                        "restore_backup: give both `backup` and `key`, or neither",
                    )),
                };
                given
                    .and_then(|given| recovery::restore(&app, lost, &pins, given))
                    .map(|report| AdminResponse {
                        resync: Some(report),
                        ..AdminResponse::ok()
                    })
            }
            AdminRequest::CheckRegistry { namespace } => {
                registry_check::check(&app.node, namespace.map(FieldHex::fr), |held| {
                    app.connect_mesh(held)
                })
                .map(|report| AdminResponse {
                    registry: Some(report),
                    ..AdminResponse::ok()
                })
            }
            AdminRequest::ResyncRegistry { lost, from } => {
                resync::resync_registry(&app.node, lost, from, |held| app.connect_mesh(held)).map(
                    |report| AdminResponse {
                        registry_resync: Some(report),
                        ..AdminResponse::ok()
                    },
                )
            }
            AdminRequest::ReplaceNode { departed, pins } => {
                crate::replace::replace(&app, departed, &pins).map(|report| AdminResponse {
                    replaced: Some(Box::new(report)),
                    ..AdminResponse::ok()
                })
            }
        })
    })
    .instrument(span)
    .await
    .unwrap_or_else(|e| {
        Err(Refusal::mpc_failure(format!(
            "the admin command failed: {e}"
        )))
    });
    result.unwrap_or_else(AdminResponse::refused)
}

/// What one run of the pruning job deleted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pruned {
    pub requests: usize,
    pub receipts: ReceiptPruning,
    /// Node-held tip versions deleted.
    pub versions: usize,
    /// The secret-shared on-chain epochs read, recorded and retired, per contract.
    pub epochs: Vec<EpochsObserved>,
    /// The pending key-set rotations observed, per contract.
    pub key_sets: Vec<KeySetObserved>,
}

/// The pruning job, once: delete the `requests` rows older than the node's
/// retention window, at the time of the node's clock ([`App::now`]), and the
/// receipts past `expiry_block + stale_blocks` whose request never reached
/// the queue or is done in the node's own chain view
/// ([`crate::receipt::prune`]; with no view or no answer, none); then the
/// node-held versions' prune pass ([`prune_versions`]); then the secret-shared
/// on-chain epoch pass ([`rotation::observe_epochs`]).
pub fn prune<S: Store>(app: &App<S>) -> Result<Pruned, Refusal> {
    let requests = app.node.prune_requests(app.now())?;
    tracing::info!(
        pruned = requests,
        retention_secs = app.node.retention_secs,
        "pruned the requests table"
    );
    let receipts = crate::receipt::prune(&app.node, &app.receipts)?;
    match &receipts {
        ReceiptPruning::Ran {
            block,
            pruned,
            kept,
        } => tracing::info!(
            block,
            pruned,
            kept,
            "pruned the receipts table (kept: past the window, request queued)"
        ),
        ReceiptPruning::NoChainView => {
            tracing::debug!("no [tip] section: no chain view, every receipt kept")
        }
        ReceiptPruning::Unavailable(why) => {
            tracing::warn!(error = %why, "the chain view did not answer: every receipt kept")
        }
    }
    let versions = prune_versions(app)?;
    tracing::info!(pruned = versions, "pruned the node-held tip versions");
    let epochs = rotation::observe_epochs(app)?;
    let key_sets = crate::replace::observe_key_sets(app)?;
    Ok(Pruned {
        requests,
        receipts,
        versions,
        key_sets,
        epochs,
    })
}

/// The node-held half of the pruning job (docs/ARCHITECTURE.md section 6,
/// "Node-held state", retention): per namespace holding node-held tip
/// versions, under its namespace lock, the prune pass against the node's own
/// chain view ([`NodeVersions::mark`]), so a key no round commits on still
/// marks and prunes. A namespace the chain view does not read, or does not
/// answer for, keeps its versions until its next round or run. Returns how
/// many versions it deleted.
pub fn prune_versions<S: Store>(app: &App<S>) -> Result<usize, Refusal> {
    let node = &app.node;
    let views = recovery::chain_views(app);
    let mut deleted = 0;
    for namespace in node.store.namespaces()? {
        if node.store.tip_keys(namespace)?.is_empty() {
            continue;
        }
        let _held = node.lock_namespace(namespace);
        deleted += NodeVersions::mark(&node.store, namespace, &views)?;
    }
    Ok(deleted)
}

/// Send one command to the admin socket at `path` and read its answer
/// (blocking; the `restore`, `prune`, `rotate-enc`, `sign-enc-key`, `resync`, `audit`,
/// `backup`, `restore-backup` and `sync-registry` subcommands use it).
pub fn call(path: &Path, req: &AdminRequest) -> eyre::Result<AdminResponse> {
    sidecar_http::admin::call(path, "node's", req)
}

/// [`call`] from async code.
pub async fn call_async(path: PathBuf, req: AdminRequest) -> eyre::Result<AdminResponse> {
    tokio::task::spawn_blocking(move || call(&path, &req)).await?
}
