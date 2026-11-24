//! The node-held tip state (sidecar-core's `NodeVersions` on each node): a
//! key's state is its commitment, which the scheduler reloads, advances
//! and the chain verifier checks against its own versions; the node-held
//! tree keys add their round values ([`TreeValues`]); and the chain view the
//! node-held prune pass marks versions against ([`version_views`]), with the
//! orphan marks the chain no longer holds ([`replaced_marks`]).

use super::*;

/// A node-held tree key at the tip: the public values its rounds carry
/// besides its state (a clear tree's paths, an oblivious tree's
/// `$new_leaf`), [`TipState::round_values`] and [`TipState::node_values`].
/// Its reload, advance and check are a flat node-held key's
/// (`NodeVersions`), which every `TreeValues` gets as its [`TipState`].
pub trait TreeValues: Send + Sync {
    /// [`TipState::round_values`]; none by default.
    fn round_values(&self, _at: &TipCheck<'_>, _state: &KeyState) -> Result<PublicMap, Refusal> {
        Ok(PublicMap::new())
    }

    /// [`TipState::node_values`]; none by default.
    fn node_values<'a>(
        &'a self,
        _package: &'a TipPackage,
        _key: &'a str,
        _state: &'a KeyState,
        _public: &'a PublicMap,
        _trees: &'a dyn TreeSource,
    ) -> TipFuture<'a, Result<PublicMap, Refusal>> {
        Box::pin(async { Ok(PublicMap::new()) })
    }
}

impl<T: TreeValues> TipState for T {
    fn reload<'a>(
        &'a self,
        history: &'a dyn TipHistory,
        key: &'a str,
        commitment: Fr,
    ) -> TipFuture<'a, Result<KeyState, ReloadError>> {
        NodeVersions.reload(history, key, commitment)
    }

    fn advance(
        &self,
        package: &TipPackage,
        store: KeyRef,
        key: &str,
        response: &ExecuteResponse,
    ) -> Result<Option<KeyState>, Refusal> {
        NodeVersions.advance(package, store, key, response)
    }

    fn check(&self, at: &TipCheck<'_>) -> Result<KeyState, Refusal> {
        NodeVersions.check(at)
    }

    fn round_values(&self, at: &TipCheck<'_>, state: &KeyState) -> Result<PublicMap, Refusal> {
        TreeValues::round_values(self, at, state)
    }

    fn node_values<'a>(
        &'a self,
        package: &'a TipPackage,
        key: &'a str,
        state: &'a KeyState,
        public: &'a PublicMap,
        trees: &'a dyn TreeSource,
    ) -> TipFuture<'a, Result<PublicMap, Refusal>> {
        TreeValues::node_values(self, package, key, state, public, trees)
    }

    fn replaced<'a>(
        &'a self,
        versions: &'a [TipVersion],
        settled: u64,
        chain: &'a dyn SettledHashes,
    ) -> TipFuture<'a, Vec<Fr>> {
        NodeVersions.replaced(versions, settled, chain)
    }
}

// The node-held tip state. Its node side, step 8 and step 15 over the
// `tip_versions` table, is sidecar-core's `NodeVersions` holder; this is the
// scheduler's and the chain verifier's side of the same mode.
impl TipState for NodeVersions {
    /// A node-held slot's state is its commitment: the request carries
    /// nothing for it, and each node loads the version the commitment names.
    fn reload<'a>(
        &'a self,
        _history: &'a dyn TipHistory,
        key: &'a str,
        commitment: Fr,
    ) -> TipFuture<'a, Result<KeyState, ReloadError>> {
        Box::pin(async move { Ok(no_record(key, commitment)) })
    }

    /// The round's new commitment for the key, from the response's public
    /// inputs (the output storing `store`).
    fn advance(
        &self,
        package: &TipPackage,
        store: KeyRef,
        key: &str,
        response: &ExecuteResponse,
    ) -> Result<Option<KeyState>, Refusal> {
        let public: Vec<Fr> = response.public_inputs.iter().map(|f| f.fr()).collect();
        let commitments = result_commitments(&package.shape, &public)?;
        Ok(package
            .shape
            .outputs
            .iter()
            .zip(commitments)
            .find(|(o, _)| o.store == store)
            .map(|(_, c)| no_record(key, c)))
    }

    fn check(&self, at: &TipCheck<'_>) -> Result<KeyState, Refusal> {
        let slot = at.slot;
        let versions = at.rows.tip_versions(at.req.namespace.fr(), &slot.key)?;
        let pipelined = at
            .pending
            .and_then(|row| versions.iter().position(|v| v.request_id == row.request_id));
        if let Some(i) = pipelined {
            // the attempt's version must be live under this node's read,
            // whatever this node last marked it: its parent chain reaches the
            // slot, and no version on that chain belongs to an entry behind
            // the head that the slot does not hold (an applied or skipped
            // entry's other attempts)
            let orphan = |head| {
                let view = VersionView {
                    slot: slot.commitment,
                    head,
                    block: at.block,
                    ..VersionView::default()
                };
                version_statuses(&versions, &view)[i] == VersionStatus::Orphan
            };
            let why = if orphan(0) {
                Some("does not build on it (an orphan)".to_string())
            } else if orphan(at.head) {
                Some(format!(
                    "builds on a version of an entry behind the head {} that the slot does not \
                     hold, an applied or skipped entry's other attempt (an orphan by index)",
                    at.head
                ))
            } else {
                None
            };
            if let Some(why) = why {
                return Err(refused(format!(
                    "slot `{}` holds {} at block {}, and this node's latest attempt for the \
                     entry before, under {}, {why}: the request must be computed again on the \
                     slot's state",
                    slot.key,
                    fr_to_hex(slot.commitment),
                    at.block,
                    fr_to_hex(versions[i].commitment)
                )));
            }
        }
        let expected = pipelined.map_or(slot.commitment, |i| versions[i].commitment);
        if expected != Fr::from(0u64) && !versions.iter().any(|v| v.commitment == expected) {
            return Err(refused(format!(
                "slot `{}` holds {} at block {}, a commitment this node holds no version of: \
                 a fault (a result this node did not commit, a replacement reaching the \
                 settled block, or a chain view that lied); this node refuses rounds on the \
                 key until the operator resyncs it from its neighbours",
                slot.key,
                fr_to_hex(expected),
                at.block
            )));
        }
        Ok(no_record(&slot.key, expected))
    }

    /// The node-held orphan marks the chain no longer holds
    /// ([`replaced_marks`]).
    fn replaced<'a>(
        &'a self,
        versions: &'a [TipVersion],
        settled: u64,
        chain: &'a dyn SettledHashes,
    ) -> TipFuture<'a, Vec<Fr>> {
        Box::pin(replaced_marks(chain, versions, settled))
    }
}

/// Why a view the node marks versions under carries its block's hash: it is
/// read at a snapshot the reader took ([`ChainReader::snapshot`]), never at
/// one made by number.
pub(crate) const SNAPSHOT_HASH: &str = "a view the node marks versions under is read at a snapshot with its block's hash \
     (ChainReader::snapshot)";

/// The chain view the node-held prune pass marks `keys` against, each a
/// node-held tip key of `target`'s namespace (a request key, its commitment
/// slot written as a field) with this node's versions of it: the commitment
/// each slot holds and the queue's head, read at `snap` (and its hash), with
/// the settled block as the reader read it with its last snapshot (at most
/// `snap`'s block), the retention floor, and the versions whose orphan mark
/// the chain no longer holds ([`replaced_marks`]); in the order given. What
/// a round's commit on the key would mark its versions against, with no
/// round.
///
/// Panics if `snap` carries no hash ([`SNAPSHOT_HASH`]).
pub async fn version_views<T: Transport>(
    reader: &ChainReader<T>,
    snap: Snapshot,
    target: &QueueTarget,
    keys: &[(String, Vec<TipVersion>)],
) -> Result<Vec<VersionView>, ReadError> {
    let c = target.contract;
    let settled = reader.settled().await.min(snap.block);
    let head = reader
        .storage_u64(snap, c, target.layout.head_index(), "head")
        .await?;
    let mut views = Vec::with_capacity(keys.len());
    for (key, versions) in keys {
        let slot = fr_from_hex(key).map_err(|detail| ReadError::BadKey {
            key: key.clone(),
            detail,
        })?;
        views.push(VersionView {
            slot: reader.storage(snap, c, slot).await?,
            head,
            block: snap.block,
            block_hash: snap.hash.expect(SNAPSHOT_HASH),
            settled,
            replaced: replaced_marks(reader, versions, settled).await,
        });
    }
    Ok(views)
}

// Orphan marks on a replaced chain. A version turns orphan at the first
// block a chain view sees it so, and keeps that block (its retention counts
// from it) while it stays orphan. A replacement can undo that block: the
// version is then the slot's again on the replacement chain, and if no
// commit or prune pass sees it so before it is superseded again there, the
// old mark would stand and the version could be deleted while a later
// replacement can still bring it back. So every mark carries its block's
// hash, and before a mark below the settled block counts (the only marks
// that delete), the view reads that block's hash from the chain, final there
// since the block is below the finalized tip: a mark whose block now has
// another hash was made on a replaced chain, and is ignored. One block read
// per such orphan, each about once (it is deleted, or marked again, at the
// same commit). A mark with no hash (sidecar-core `TipVersion::block_hash`)
// cannot be checked and is marked again too, under the view's hash; that
// only delays its deletion until the finalized tip passes the view's block.
// Every view the node marks under is read at a snapshot with a hash
// (SNAPSHOT_HASH).

/// The versions among `versions` whose orphan mark below `settled` the chain
/// does not confirm: the mark carries no hash, or the block it names has
/// another hash on the chain, or none, or the node did not answer for it
/// (kept and marked again rather than deleted on an unread block).
pub async fn replaced_marks(
    chain: &dyn SettledHashes,
    versions: &[TipVersion],
    settled: u64,
) -> Vec<Fr> {
    let mut read: BTreeMap<u64, Option<Fr>> = BTreeMap::new();
    let mut out = Vec::new();
    for v in versions
        .iter()
        .filter(|v| v.status == VersionStatus::Orphan && v.block < settled)
    {
        if v.block_hash == Fr::from(0u64) {
            out.push(v.commitment);
            continue;
        }
        let on_chain = match read.get(&v.block) {
            Some(hash) => *hash,
            None => {
                let hash = chain.hash_at_settled(v.block).await;
                read.insert(v.block, hash);
                hash
            }
        };
        if on_chain != Some(v.block_hash) {
            out.push(v.commitment);
        }
    }
    out
}

/// A key's state that the request carries no record for.
fn no_record(key: &str, commitment: Fr) -> KeyState {
    KeyState {
        key: key.to_string(),
        commitment,
        record: None,
    }
}
