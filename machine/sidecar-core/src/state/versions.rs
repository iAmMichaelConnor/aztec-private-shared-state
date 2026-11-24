//! The state mode `node` at the tip: [`NodeVersions`], versions in `tip_versions`
//! anchored to the chain's slot, and their prune pass.

use super::row::refuse_without_values;
use super::*;
use crate::bind::Elem;
use crate::error::Refusal;
use crate::field::{Fr, fr_to_hex};
use crate::manifest::KeyRef;
use crate::store::rules::{self, VersionView};
use crate::store::{Store, TipVersion, Txn, VersionStatus, VersionTree, VersionWrite};

/// The state mode `node` at the tip: each key is a set of versions in
/// `tip_versions`, each named by its commitment, with the version it came
/// from and the queue entry it was computed for (docs/ARCHITECTURE.md
/// section 6, "Node-held state"). Step 8 loads the version the round's old
/// commitment names (the one step 4's chain verifier derived); step 15
/// creates one new version under the round's new commitment and never
/// overwrites one, marks every version of the key canonical, live or orphan
/// against the chain view, and deletes the orphans first marked orphan below
/// the chain view's settled block, the node's finalized tip
/// ([`rules::VersionView::settled`]). A round whose new commitment for
/// a key equals its old one (the non-secret-shared path's `ok = false` no-op) creates no
/// version: its output for the key is discarded and the parent, whose
/// commitment the slot keeps, stays. A new commitment of 0 is
/// no state and is never stored. There is no rollback: the chain decides
/// which version counts. The request carries nothing for such a key, and
/// the round seals no thirds for it. Between rounds the node's pruning job
/// runs the same marks and deletes over every node-held key ([`Self::prune`]),
/// so a key with no fresh commit (idle, or answered only by replays) still
/// prunes.
pub struct NodeVersions;

/// A node's own chain view of its node-held versions: given a namespace and
/// its node-held tip keys, the view of each key, all read at one block with
/// the settled block read with it, in the order given; `None` for a namespace
/// the view does not read.
pub type VersionViews<'a> =
    dyn Fn(Fr, &[String]) -> Result<Option<Vec<VersionView>>, Refusal> + Sync + 'a;

impl NodeVersions {
    /// The prune pass over `namespace` against this node's own chain view
    /// `views` ([`Self::prune`] over every node-held tip key of the
    /// namespace). The caller holds the namespace lock. The pruning job runs
    /// it on its timer, and the recovery commands (the resync's bundle, the
    /// audit's targets, the backup's rows) run it right before they read the
    /// versions, so they act on marks of the node's current chain view, not
    /// of its last round or prune run. A namespace the view does not read,
    /// or does not answer for, keeps its versions as marked. Returns how
    /// many versions it deleted.
    pub fn mark<S: Store + ?Sized>(
        store: &S,
        namespace: Fr,
        views: &VersionViews<'_>,
    ) -> Result<usize, Refusal> {
        let keys = store.tip_keys(namespace)?;
        if keys.is_empty() {
            return Ok(0);
        }
        match views(namespace, &keys) {
            Ok(Some(views)) => {
                let views: Vec<_> = keys.into_iter().zip(views).collect();
                Self::prune(store, namespace, &views)
            }
            Ok(None) => {
                tracing::debug!(
                    namespace = %fr_to_hex(namespace),
                    "no chain view of the namespace: its node-held versions kept as marked"
                );
                Ok(0)
            }
            Err(r) => {
                tracing::warn!(
                    namespace = %fr_to_hex(namespace),
                    error = %r,
                    "the chain view did not answer: the namespace's node-held versions kept \
                     as marked"
                );
                Ok(0)
            }
        }
    }

    /// The prune pass between rounds over `namespace` (docs/ARCHITECTURE.md
    /// section 6, "Node-held state", retention): each key of `views`, a
    /// node-held tip key, has every held version marked against its view and
    /// the orphans marked below its settled block deleted,
    /// exactly as a round's
    /// commit on the key does ([`rules::stage_versions`] with no new
    /// version). One commit of marks and deletes with no request row, none
    /// when nothing changes. Returns how many versions it deleted. The
    /// caller holds the namespace lock and reads `views` under it, so no
    /// round on the namespace commits between the read and this commit.
    pub fn prune<S: Store + ?Sized>(
        store: &S,
        namespace: Fr,
        views: &[(String, VersionView)],
    ) -> Result<usize, Refusal> {
        let mut txn = store.begin(namespace);
        for (key, view) in views {
            rules::stage_versions(store, &mut txn, key, None, view)?;
        }
        let deleted = txn
            .versions()
            .iter()
            .filter(|w| matches!(w, VersionWrite::Delete { .. }))
            .count();
        if !txn.versions().is_empty() {
            store.commit(txn)?;
        }
        Ok(deleted)
    }

    /// The old commitment step 4 derived for `key`, 0 when the circuit has no
    /// commitment slot for it (a key the round creates).
    pub fn old(at: &StateCtx<'_>, key: &str) -> Result<Fr, Refusal> {
        let chain = at.chain.ok_or_else(|| {
            Refusal::mpc_failure(format!(
                "key `{key}` is node-held at the tip, and the round has no chain view"
            ))
        })?;
        Ok(chain.key(key).map_or(Fr::from(0u64), |k| k.old))
    }

    /// The version step 8 loads for `key`: the one its old commitment names
    /// (409 for an empty slot or one this node holds no version of, a fault).
    pub fn loaded(at: &StateCtx<'_>, keyref: KeyRef, key: &str) -> Result<TipVersion, Refusal> {
        let old = Self::old(at, key)?;
        if old == Fr::from(0u64) {
            return Err(Refusal::conflict(format!(
                "{keyref} = `{key}`: the slot holds no state (commitment 0)"
            )));
        }
        at.store
            .tip_version(at.namespace, key, old)?
            .ok_or_else(|| {
                Refusal::conflict(format!(
                    "{keyref} = `{key}`: this node holds no version under commitment {} (a fault: \
                 the operator resyncs this node from its neighbours)",
                    fr_to_hex(old)
                ))
            })
    }

    /// Step 15 for `key`: `new` (none for a new commitment of 0 or equal to
    /// the old one), and every held version marked against the chain view
    /// and the orphans marked below the settled block pruned; a key the round creates (no
    /// commitment slot) only puts `new`.
    pub fn stage_version(
        at: &StateCtx<'_>,
        txn: &mut Txn,
        key: &str,
        new: Option<TipVersion>,
    ) -> Result<(), Refusal> {
        let chain = at.chain.expect("checked by NodeVersions::old");
        match chain.key(key) {
            Some(slot) => {
                rules::stage_versions(at.store, txn, key, new, &chain.view(slot))?;
            }
            None => {
                if let Some(new) = new {
                    txn.version(VersionWrite::Put(new));
                }
            }
        }
        Ok(())
    }

    /// The version a round creates under `note_hash` on `parent`, or `None`
    /// when the new commitment is 0 (no state) or the parent's (no change).
    pub fn version(
        at: &StateCtx<'_>,
        key: &str,
        parent: Fr,
        note_hash: Fr,
        vec: Vec<Elem>,
        tree: Option<VersionTree>,
    ) -> Option<TipVersion> {
        let chain = at.chain.expect("checked by NodeVersions::old");
        (note_hash != Fr::from(0u64) && note_hash != parent).then(|| TipVersion {
            key: key.to_string(),
            commitment: note_hash,
            parent,
            index: chain.index,
            request_id: at.req.request_id,
            vec,
            tree,
            status: VersionStatus::Live,
            block: chain.block,
            block_hash: chain.block_hash,
        })
    }
}

impl StateHolder for NodeVersions {
    fn noun(&self) -> &'static str {
        "node-held"
    }

    fn check_store(&self, keys: &[KeyRef], holds_values: bool) -> Result<(), Refusal> {
        refuse_without_values(keys, holds_values)
    }

    fn note_hash(&self, _at: &StateCtx<'_>, _key: &str) -> Result<Option<Fr>, Refusal> {
        Ok(None)
    }

    fn load(
        &self,
        at: &StateCtx<'_>,
        keyref: KeyRef,
        key: &str,
        _round: &mut RoundEntries,
    ) -> Result<Held, Refusal> {
        let version = Self::loaded(at, keyref, key)?;
        Ok(Held {
            vec: version.vec,
            note_hash: version.commitment,
        })
    }

    fn summand(&self, key: &str) -> Option<String> {
        Some(format!("value `{key}`"))
    }

    fn stage(
        &self,
        at: &StateCtx<'_>,
        txn: &mut Txn,
        key: &str,
        vec: Vec<Elem>,
        note_hash: Fr,
        _round: &mut RoundEntries,
    ) -> Result<(), Refusal> {
        let parent = Self::old(at, key)?;
        let new = Self::version(at, key, parent, note_hash, vec, None);
        Self::stage_version(at, txn, key, new)
    }
}
