//! Where a stored receipt's request stands in its namespace's queue, read
//! through a node's own Aztec node for the node's receipt pruning
//! (docs/ARCHITECTURE.md section 6, the receipts row). A node keeps the
//! inputs of a receipt-intake request while the request is queued and not
//! done, and prunes them past `expiry_block + stale_blocks` only when the
//! request never reached the queue or is done:
//!
//! ```text
//! NotSeen   seen[request_id] is false: the request never entered the queue
//!           (and past its expiry it never can: append_before refuses from
//!           expiry_block on)
//! Queued    seen, and requests[index] == request_id for an index in
//!           head..tail: done[index] is not written yet
//! Done      seen, and not in requests[head..tail): its index is below the
//!           head, and finish_head writes done[index] in the same call that
//!           moves the head past it (applied or skipped)
//! Unknown   seen, and not in the part of head..tail read (the queue holds
//!           more pending entries than the scan reads): kept
//! ```
//!
//! [`standings`] makes the reads at one block; [`ReceiptChainView`] is the
//! synchronous handle the node's pruning job and receipt signer hold, with
//! a small runtime of its own like the chain verifier's. The pruning job
//! reads its node-held version views through the same handle
//! ([`ReceiptChainView::version_views`]), and under secret-shared on-chain intake
//! the node's own stored key and the queue's head and tail at one block
//! ([`ReceiptChainView::enc_key`], what `EpochKeys::apply` takes; read
//! through the namespace's intake layout, `intake::shared_onchain::enc_key`).
//!
//! What deletes reads a settled block. The reader follows proposed blocks
//! and places a replacement anywhere above the settled block, the node's
//! finalized tip (`ChainReader::settled`), so a block above it can still
//! be replaced (a proposed block, an epoch prune, an L1 reorg) and one at
//! or below it cannot. A `Done` read at a proposed block (an apply) that a replacement
//! drops would put the request back in the queue with its inputs gone, so
//! the pruning job and the `enc` retirement list expired receipts and read
//! their standings at the settled block ([`ReceiptChainView::settled`]),
//! and the stored key, head and tail the epoch retirement deletes scalars
//! by are read there too ([`ReceiptChainView::enc_key`]). The receipt
//! signer's current block ([`ReceiptChainView::proposed`]) and the version
//! views stay at the proposed tip: they sign or mark, and delete nothing by
//! themselves.

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::time::Duration;

use sidecar_core::epochs::EncKeyObservation;
use sidecar_core::error::{ErrorClass, Refusal};
use sidecar_core::field::{Fr, fr_to_hex};
use sidecar_core::pipeline::VerifierRows;
use sidecar_core::store::rules::VersionView;

use crate::blocking::{Blocking, bounded};
use crate::chain::rpc::Transport;
use crate::chain::{ChainReader, QueueTarget, ReadError, Snapshot};
use crate::intake::IntakeLayout;
use crate::intake::shared_onchain::enc_key;
use crate::namespace::TipLayout;
use crate::state::version_views;

// Operator knob: DESIGN.md, "Configuration reference" (receipt standing scan).
// One pruning run reads at most 4,096 pending entries per namespace, all within
// 120 s; a request not found is `Unknown` and its receipt kept.
/// The most queue entries one pruning run reads per namespace.
pub const DEFAULT_STANDING_SCAN: u64 = 4096;
/// The bound on one pruning run's chain reads (or one block read).
pub const DEFAULT_STANDING_TIMEOUT: Duration = Duration::from_secs(120);

/// Where one request id stands in its queue (module documentation).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Standing {
    NotSeen,
    Queued { index: u64 },
    Done,
    Unknown,
}

impl Standing {
    /// Whether the node keeps the request's stored inputs: while it is
    /// queued, or when the reads could not tell.
    pub fn keeps(self) -> bool {
        matches!(self, Standing::Queued { .. } | Standing::Unknown)
    }
}

/// Where each of `ids` (chain request ids) stands in `target`'s queue at
/// `snap`, in the order given: `seen[id]` for each, then, when any is
/// seen, `head`, `tail` and `requests[head..]` up to `scan` entries, never
/// past `tail`, stopping once every seen id is found.
pub async fn standings<T: Transport>(
    reader: &ChainReader<T>,
    snap: Snapshot,
    target: &QueueTarget,
    ids: &[Fr],
    scan: u64,
) -> Result<Vec<Standing>, ReadError> {
    let (c, q) = (target.contract, &target.layout);
    let mut seen = BTreeSet::new();
    for id in ids {
        match reader.storage_u64(snap, c, q.seen(*id), "seen").await? {
            0 => {}
            1 => {
                seen.insert(*id);
            }
            other => {
                return Err(ReadError::Malformed {
                    method: "node_getPublicStorageAt",
                    detail: format!("seen[{}] {other} is not a bool", fr_to_hex(*id)),
                });
            }
        }
    }
    let mut found = BTreeMap::new();
    let mut complete = true;
    if !seen.is_empty() {
        let (head, tail) = reader.head_and_tail(snap, target).await?;
        let end = tail.min(head.saturating_add(scan));
        complete = end == tail;
        for index in head..end {
            if found.len() == seen.len() {
                break;
            }
            let id = reader.storage(snap, c, q.request(index)).await?;
            if seen.contains(&id) {
                found.insert(id, index);
            }
        }
        // every seen id found: the scan's unread part does not matter
        complete |= found.len() == seen.len();
    }
    Ok(ids
        .iter()
        .map(|id| match (seen.contains(id), found.get(id)) {
            (false, _) => Standing::NotSeen,
            (true, Some(&index)) => Standing::Queued { index },
            (true, None) if complete => Standing::Done,
            (true, None) => Standing::Unknown,
        })
        .collect())
}

/// One namespace as a node's receipt chain view reads it: its queue and
/// where its contract keeps what its intakes read, from its contract
/// manifest ([`crate::TipLayout::receipt_target`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReceiptTarget {
    pub queue: QueueTarget,
    pub intake: IntakeLayout,
}

/// A queue whose contract keeps nothing for an intake beside it.
impl From<QueueTarget> for ReceiptTarget {
    fn from(queue: QueueTarget) -> Self {
        ReceiptTarget {
            queue,
            intake: IntakeLayout::default(),
        }
    }
}

fn refused(message: impl std::fmt::Display) -> Refusal {
    Refusal::bad_request(format!("receipt chain view: {message}"))
}

/// A node's own view of its namespaces' queues for its receipts: the
/// current proposed block, the settled block, and where a stored receipt's
/// request stands at a block; and for the node-held prune pass, each key's
/// slot and the queue's head. It reads the namespaces the node serves (its
/// `[[tip.namespaces]]`), each where its registered contract manifest says
/// ([`Self::target`]), as the chain verifier does.
pub struct ReceiptChainView<T> {
    reader: ChainReader<T>,
    listed: BTreeSet<Fr>,
    scan: u64,
    timeout: Duration,
    blocking: Blocking,
}

impl<T: Transport> ReceiptChainView<T> {
    /// The view over `transport` (the node's own Aztec node) of the queues
    /// of the namespaces `listed`.
    pub fn new(transport: T, listed: impl IntoIterator<Item = Fr>) -> std::io::Result<Self> {
        Ok(ReceiptChainView {
            reader: ChainReader::new(transport),
            listed: listed.into_iter().collect(),
            scan: DEFAULT_STANDING_SCAN,
            timeout: DEFAULT_STANDING_TIMEOUT,
            blocking: Blocking::new("receipt-chain-view")?,
        })
    }

    /// Whether `namespace` is one of the namespaces this view serves.
    pub fn knows(&self, namespace: Fr) -> bool {
        self.listed.contains(&namespace)
    }

    /// Where this view reads `namespace`: its queue and intake layout from
    /// its contract manifest in the node's `rows`; `None` when the view does
    /// not serve it, or it has no registered tip contract manifest (nothing
    /// to read yet, or a namespace of the sidecar path).
    pub fn target(
        &self,
        rows: &dyn VerifierRows,
        namespace: Fr,
    ) -> Result<Option<ReceiptTarget>, Refusal> {
        Ok(self.layout(rows, namespace)?.map(|l| l.receipt_target()))
    }

    /// `namespace`'s layout from its contract manifest in the node's
    /// `rows`; `None` when the view does not serve it, or it has no
    /// registered tip contract manifest.
    fn layout(&self, rows: &dyn VerifierRows, namespace: Fr) -> Result<Option<TipLayout>, Refusal> {
        if !self.knows(namespace) {
            return Ok(None);
        }
        match TipLayout::of_row(namespace, rows.contract_manifest(namespace)?) {
            Err(e) if e.class == ErrorClass::BadRequest => Ok(None),
            layout => layout,
        }
    }

    /// The contract manifest version `namespace`'s contract pins name in
    /// force at the current proposed block of the node's own Aztec node
    /// ([`ChainReader::manifest_in_force`]): the version a receipt's request
    /// id is computed under. `None` when the view does not serve the
    /// namespace or it has no registered tip contract manifest; 400 when a
    /// read fails.
    pub fn manifest_in_force(
        &self,
        rows: &dyn VerifierRows,
        namespace: Fr,
    ) -> Result<Option<Fr>, Refusal> {
        let Some(layout) = self.layout(rows, namespace)? else {
            return Ok(None);
        };
        let read = async {
            let snap = self.fresh().await?;
            self.reader.manifest_in_force(snap, &layout).await
        };
        self.bounded(read).map(Some)
    }

    /// The current proposed block of the node's own Aztec node, the block
    /// the receipt signer checks an expiry against (it deletes nothing);
    /// 400 when it does not answer within the timeout.
    pub fn proposed(&self) -> Result<u64, Refusal> {
        let read = async { self.fresh().await.map(|s| s.block) };
        self.bounded(read)
    }

    /// A snapshot of the current proposed block for the receipt signer's
    /// reads ([`Self::proposed`], [`Self::manifest_in_force`]), which keep
    /// nothing read at an earlier block: a replacement the follower reports
    /// voids none of them, so the view takes the next snapshot, which
    /// follows the replacement chain, instead of refusing the receipt.
    async fn fresh(&self) -> Result<Snapshot, ReadError> {
        match self.reader.snapshot().await {
            Err(e) if e.replaced() => self.reader.snapshot().await,
            snap => snap,
        }
    }

    /// The settled block: the node's finalized tip, after a poll of the
    /// tips, once the view has seen it move, clamped to the proposed tip
    /// (module documentation).
    /// What deletes a receipt or retires a key decides at this block, which
    /// a replacement cannot reach; 400 when the node does not answer within
    /// the timeout.
    pub fn settled(&self) -> Result<u64, Refusal> {
        self.bounded(self.settled_block())
    }

    /// Where each of `ids` stands in `target`'s queue at `block`, in the
    /// order given; the pruning job and the `enc` retirement pass a block
    /// [`Self::settled`] answered. 400 when a read fails.
    pub fn standings(
        &self,
        block: u64,
        target: &ReceiptTarget,
        ids: &[Fr],
    ) -> Result<Vec<Standing>, Refusal> {
        let read = standings(
            &self.reader,
            Snapshot::at(block),
            &target.queue,
            ids,
            self.scan,
        );
        self.bounded(read)
    }

    /// The views the node-held prune pass marks `keys` of `namespace`
    /// (whose queue is `target`'s) against, all read at the current
    /// proposed block, with this node's versions of each key from `rows`
    /// ([`version_views`]); 400 when a read fails.
    pub fn version_views(
        &self,
        rows: &dyn VerifierRows,
        namespace: Fr,
        target: &ReceiptTarget,
        keys: &[String],
    ) -> Result<Vec<VersionView>, Refusal> {
        let held = keys
            .iter()
            .map(|key| Ok((key.clone(), rows.tip_versions(namespace, key)?)))
            .collect::<Result<Vec<_>, Refusal>>()?;
        let read = async {
            let snap = self.reader.snapshot().await?;
            version_views(&self.reader, snap, &target.queue, &held).await
        };
        self.bounded(read)
    }

    /// Node `i`'s stored key in `namespace`'s contract and the queue's head
    /// and tail, all read at the settled block (the finalized tip, after a
    /// poll of the tips; [`enc_key`]): the epoch
    /// retirement deletes scalars by them. `None` when the contract has no
    /// `SharedOnchain` (its manifest gives no `storage.shared_onchain`); 400
    /// when a read fails.
    pub fn enc_key(
        &self,
        target: &ReceiptTarget,
        i: usize,
    ) -> Result<Option<EncKeyObservation>, Refusal> {
        let read = async {
            let settled = self.settled_block().await?;
            let snap = Snapshot::at(settled);
            enc_key(&self.reader, snap, &target.queue, &target.intake, i).await
        };
        self.bounded(read)
    }

    /// Every served namespace's key epoch at the current proposed block, in
    /// namespace order; 400 when a read fails.
    pub fn key_epochs(
        &self,
    ) -> Result<Vec<(Fr, sidecar_core::key_epoch::StoredNodeKeys)>, Refusal> {
        let read = async {
            let snap = self.reader.snapshot().await?;
            let mut out = Vec::new();
            for &contract in &self.listed {
                out.push((contract, self.reader.key_epoch(snap, contract).await?));
            }
            Ok(out)
        };
        self.bounded(read)
    }

    async fn settled_block(&self) -> Result<u64, ReadError> {
        let snap = self.reader.snapshot().await?;
        Ok(self.reader.settled().await.min(snap.block))
    }

    fn bounded<F, V>(&self, read: F) -> Result<V, Refusal>
    where
        F: Future<Output = Result<V, ReadError>> + Send,
        V: Send,
    {
        self.blocking
            .run(bounded(self.timeout, read))
            .map_err(refused)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::layout::QueueLayout;
    use crate::intake::shared_onchain::SharedOnchainLayout;
    use crate::testing::{FixtureTransport, MemoryChain};
    use serde_json::json;
    use std::sync::Arc;

    const CONTRACT: u64 = 0x2f01;

    fn target() -> QueueTarget {
        QueueTarget {
            contract: Fr::from(CONTRACT),
            layout: QueueLayout::new(Fr::from(12u64)),
        }
    }

    /// [`target`] with the app's `SharedOnchain` at slot 40.
    fn shared_onchain() -> (ReceiptTarget, SharedOnchainLayout) {
        let layout = SharedOnchainLayout::new(Fr::from(40u64));
        let t = ReceiptTarget {
            queue: target(),
            intake: IntakeLayout {
                shared_onchain: Some(layout),
            },
        };
        (t, layout)
    }

    fn id(n: u64) -> Fr {
        Fr::from(0x7000 + n)
    }

    /// A queue of four entries, ids 1 to 4, with the head at 2 (1 and 2
    /// done, 3 and 4 queued); id 5 never queued.
    fn chain() -> Arc<MemoryChain> {
        let chain = Arc::new(MemoryChain::new(500));
        let t = target();
        let ids: Vec<Fr> = (1..=4).map(id).collect();
        chain.write_queue(t.contract, t.layout, &ids, 2, 400);
        for n in 1..=4 {
            chain.set_storage(t.contract, t.layout.seen(id(n)), Fr::from(1u64));
        }
        chain.set_storage(t.contract, t.layout.done(0), Fr::from(1u64));
        chain.set_storage(t.contract, t.layout.done(1), Fr::from(2u64));
        chain
    }

    #[tokio::test]
    async fn a_seen_request_is_queued_from_the_head_on_and_done_below_it() {
        let reader = ChainReader::new(chain());
        let snap = reader.snapshot().await.unwrap();
        let ids = [id(1), id(2), id(3), id(4), id(5)];
        let got = standings(&reader, snap, &target(), &ids, 4096)
            .await
            .unwrap();
        assert_eq!(
            got,
            [
                Standing::Done,
                Standing::Done,
                Standing::Queued { index: 2 },
                Standing::Queued { index: 3 },
                Standing::NotSeen,
            ]
        );
        assert_eq!(
            got.iter().map(|s| s.keeps()).collect::<Vec<_>>(),
            [false, false, true, true, false]
        );
    }

    #[tokio::test]
    async fn a_short_scan_keeps_what_it_did_not_read() {
        let reader = ChainReader::new(chain());
        let snap = reader.snapshot().await.unwrap();
        // one entry read: id 3 is found, id 4 and the done id 1 cannot be told
        let ids = [id(1), id(3), id(4), id(5)];
        let got = standings(&reader, snap, &target(), &ids, 1).await.unwrap();
        assert_eq!(
            got,
            [
                Standing::Unknown,
                Standing::Queued { index: 2 },
                Standing::Unknown,
                Standing::NotSeen,
            ]
        );
        // every seen id found within the scan: nothing unknown
        let got = standings(&reader, snap, &target(), &[id(3), id(5)], 1)
            .await
            .unwrap();
        assert_eq!(got, [Standing::Queued { index: 2 }, Standing::NotSeen]);
    }

    #[tokio::test]
    async fn no_seen_id_reads_no_queue_and_a_bad_answer_is_an_error() {
        // only the seen slots are recorded: a queue read would fail
        let t = target();
        let seen = |n: u64| {
            json!({"method": "node_getPublicStorageAt",
                   "params": [{"number": 9}, fr_to_hex(t.contract), fr_to_hex(t.layout.seen(id(n)))],
                   "response": {"jsonrpc": "2.0", "id": 1, "result": fr_to_hex(Fr::from(n - 1))}})
        };
        let fixture = FixtureTransport::new(&json!({"calls": [seen(1), seen(3)]}));
        let reader = ChainReader::new(fixture);
        let snap = Snapshot::at(9);
        let got = standings(&reader, snap, &t, &[id(1)], 4096).await.unwrap();
        assert_eq!(got, [Standing::NotSeen]);
        let err = standings(&reader, snap, &t, &[id(3)], 4096)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("is not a bool"), "{err}");
    }

    // Node 1's stored key at epoch 3 and the queue's head and tail come
    // from one block; a contract without SharedOnchain answers none.
    #[test]
    fn the_view_reads_a_node_s_stored_key_with_the_queue_at_one_block() {
        let chain = chain();
        let (t, layout) = shared_onchain();
        let (c, slot) = (t.queue.contract, layout.enc_key(1));
        chain.set_storage(c, slot, Fr::from(0x51u64));
        chain.set_storage(c, slot + Fr::from(1u64), Fr::from(0x52u64));
        chain.set_storage(c, slot + Fr::from(2u64), Fr::from(3u64));
        let view = ReceiptChainView::new(chain.clone(), [c]).unwrap();
        let got = view.enc_key(&t, 1).unwrap().unwrap();
        assert_eq!(
            got,
            EncKeyObservation {
                epoch: 3,
                pk: (Fr::from(0x51u64), Fr::from(0x52u64)),
                head: 2,
                tail: 4,
            }
        );
        // node 0 holds no key yet: epoch 0
        assert_eq!(view.enc_key(&t, 0).unwrap().unwrap().epoch, 0);
        assert_eq!(view.enc_key(&target().into(), 1).unwrap(), None);
    }

    // Id 2 is applied in proposed block 105, above the settled block 100
    // (the finalized tip): the signer's block is 105,
    // but the pruning job reads at 100, where id 2 is still queued, and once
    // block 105 is replaced by one without the apply it is queued at the
    // proposed tip too, its inputs still held. When the settled block
    // passes an apply that stays, the request is done.
    #[test]
    fn an_apply_above_the_settled_block_keeps_the_request_s_inputs() {
        let chain = Arc::new(MemoryChain::new(100));
        let t = target();
        let ids: Vec<Fr> = (1..=3).map(id).collect();
        chain.write_queue(t.contract, t.layout, &ids, 1, 80);
        for n in 1..=3 {
            chain.set_storage(t.contract, t.layout.seen(id(n)), Fr::from(1u64));
        }
        chain.set_storage(t.contract, t.layout.done(0), Fr::from(1u64));
        chain.set_storage_at(105, t.contract, t.layout.head_index(), Fr::from(2u64));
        chain.set_storage_at(105, t.contract, t.layout.done(1), Fr::from(1u64));
        let view = ReceiptChainView::new(chain.clone(), [t.contract]).unwrap();
        let ns: ReceiptTarget = t.into();
        let ns = &ns;
        chain.node().set_proven(100);
        view.proposed().unwrap();
        chain.node().set_proven(103);
        chain.set_tip(105);
        assert_eq!(view.proposed().unwrap(), 105);
        assert_eq!(view.settled().unwrap(), 100);
        let all = [id(1), id(2), id(3)];
        assert_eq!(
            view.standings(105, ns, &all).unwrap()[1],
            Standing::Done,
            "done at the proposed tip"
        );
        let got = view.standings(100, ns, &all).unwrap();
        assert_eq!(
            got,
            [
                Standing::Done,
                Standing::Queued { index: 1 },
                Standing::Queued { index: 2 }
            ]
        );
        assert!(got.iter().skip(1).all(|s| s.keeps()));

        // block 105 is replaced by one without the apply, which takes its
        // writes with it: id 2 is queued
        chain.node().replace_from(104);
        assert!(view.settled().is_err(), "the replacement is reported once");
        assert_eq!(view.settled().unwrap(), 100);
        let got = view.standings(105, ns, &[id(2)]).unwrap();
        assert_eq!(got, [Standing::Queued { index: 1 }]);

        // the apply lands again at 106 and the settled block passes it
        chain.set_storage_at(106, t.contract, t.layout.head_index(), Fr::from(2u64));
        chain.set_storage_at(106, t.contract, t.layout.done(1), Fr::from(1u64));
        chain.set_tip(110);
        chain.node().set_proven(107);
        view.settled().unwrap();
        chain.node().set_proven(108);
        assert_eq!(view.proposed().unwrap(), 110);
        assert_eq!(view.settled().unwrap(), 107);
        assert_eq!(view.standings(107, ns, &[id(2)]).unwrap(), [Standing::Done]);
    }

    // The epoch retirement's observation is read at the settled block: a
    // rotation and an advanced head in a proposed block above it are not
    // seen until the settled block passes them.
    #[test]
    fn the_stored_key_and_the_queue_are_read_at_the_settled_block() {
        let chain = chain();
        let (t, layout) = shared_onchain();
        let (c, slot) = (t.queue.contract, layout.enc_key(0));
        chain.set_storage(c, slot + Fr::from(2u64), Fr::from(1u64));
        chain.set_storage_at(495, c, slot + Fr::from(2u64), Fr::from(2u64));
        chain.set_storage_at(495, c, t.queue.layout.head_index(), Fr::from(4u64));
        let view = ReceiptChainView::new(chain.clone(), [c]).unwrap();
        chain.node().set_proven(480);
        view.proposed().unwrap();
        chain.node().set_proven(490);
        let got = view.enc_key(&t, 0).unwrap().unwrap();
        assert_eq!(
            (got.epoch, got.head, got.tail),
            (1, 2, 4),
            "at the settled block 480"
        );
        chain.node().set_proven(496);
        view.proposed().unwrap();
        chain.node().set_proven(499);
        let got = view.enc_key(&t, 0).unwrap().unwrap();
        assert_eq!((got.epoch, got.head), (2, 4), "at the settled block 496");
    }

    // A replacement below the tip leaves the receipt signer's current block
    // readable: the view follows the replacement chain and answers its tip.
    #[test]
    fn the_signer_s_block_reads_through_a_replacement() {
        let chain = chain();
        let view = ReceiptChainView::new(chain.clone(), [Fr::from(CONTRACT)]).unwrap();
        assert_eq!(view.proposed().unwrap(), 500);
        chain.node().replace_from(498);
        assert_eq!(view.proposed().unwrap(), 500);
    }

    #[test]
    fn the_view_reads_its_own_namespaces_and_refuses_when_the_node_is_silent() {
        let view = ReceiptChainView::new(chain(), [Fr::from(CONTRACT)]).unwrap();
        assert!(view.knows(Fr::from(CONTRACT)) && !view.knows(Fr::from(1u64)));
        // an unlisted namespace, and a listed one with no contract manifest
        let rows = crate::testing::Rows::default();
        assert_eq!(view.target(&rows, Fr::from(1u64)).unwrap(), None);
        assert_eq!(view.target(&rows, Fr::from(CONTRACT)).unwrap(), None);
        assert_eq!(view.proposed().unwrap(), 500);
        let got = view
            .standings(500, &target().into(), &[id(2), id(4)])
            .unwrap();
        assert_eq!(got, [Standing::Done, Standing::Queued { index: 3 }]);

        let silent = ReceiptChainView::new(
            FixtureTransport::new(&json!({"calls": []})),
            [Fr::from(CONTRACT)],
        )
        .unwrap();
        let err = silent.proposed().unwrap_err();
        assert!(err.message.contains("this node's Aztec node"), "{err}");
        let err = silent.settled().unwrap_err();
        assert!(err.message.contains("this node's Aztec node"), "{err}");
        let err = silent
            .standings(500, &target().into(), &[id(2)])
            .unwrap_err();
        assert!(err.message.contains("this node's Aztec node"), "{err}");
    }
}
