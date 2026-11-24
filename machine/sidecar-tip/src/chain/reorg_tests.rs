//! Reorg model tests: the chain reader and a node's node-held version
//! retention over the in-memory chain as a model of an Aztec chain (per-block
//! storage that a replacement rewinds, four tips, finality one proof behind
//! the proven tip unless a test sets it). Each node is a chain reader with a
//! store of its own; the nodes poll at different times, so their views of
//! the chain differ between polls.

use std::sync::Arc;

use sidecar_core::Fr;
use sidecar_core::state::NodeVersions;
use sidecar_core::store::rules::VersionView;
use sidecar_core::store::testing::{ns, tip_round, version};
use sidecar_core::store::{MemoryStore, StoreRead, VersionStatus};
use sidecar_core::tree::fr_u64;

use super::layout::QueueLayout;
use super::{ChainReader, QueueTarget, ReadError, ReaderConfig, Snapshot};
use crate::state::version_views;
use crate::testing::MemoryChain;

/// The node-held key: its commitment slot, written as a field.
const KEY: &str = "0xa002";

fn slot() -> Fr {
    Fr::from(0xa002u64)
}

fn target() -> QueueTarget {
    QueueTarget {
        contract: ns(),
        layout: QueueLayout::new(Fr::from(12u64)),
    }
}

fn config() -> ReaderConfig {
    ReaderConfig {
        poll_interval: std::time::Duration::from_millis(1),
        ..ReaderConfig::default()
    }
}

/// One node: its chain reader over the shared chain, its store, the tip it
/// last followed, and the lowest block replaced since then that it held.
struct Node {
    reader: ChainReader<Arc<MemoryChain>>,
    store: MemoryStore,
    top: u64,
    replaced: Option<u64>,
}

impl Node {
    fn new(chain: &Arc<MemoryChain>) -> Self {
        Node {
            reader: ChainReader::with_config(chain.clone(), config()),
            store: MemoryStore::new(),
            top: 0,
            replaced: None,
        }
    }

    /// Blocks from `from` on were replaced (or are gone): the node held
    /// them if they are at or below the tip it followed.
    fn replaced_from(&mut self, from: u64) {
        if self.top > 0 && from <= self.top {
            self.replaced = Some(self.replaced.map_or(from, |r| r.min(from)));
        }
    }

    /// A snapshot of the tip. The reader reports a replacement of blocks
    /// it held exactly once, placed at or below the true point and never
    /// above it; after the poll every hash it keeps is the chain's.
    async fn snapshot(&mut self, chain: &MemoryChain) -> Snapshot {
        let snap = match self.reader.snapshot().await {
            Ok(snap) => {
                assert_eq!(self.replaced, None, "a replacement went unreported");
                snap
            }
            Err(ReadError::Pruned(prune)) => {
                let from = self.replaced.take().expect("a prune with no replacement");
                assert!(
                    prune.below_kept || prune.to < from,
                    "{prune} is shallower than the replacement from block {from}"
                );
                self.reader.snapshot().await.unwrap()
            }
            Err(e) => panic!("{e}"),
        };
        let followed = self.reader.follower.lock().await;
        let f = &followed.follower;
        for n in f.lowest().unwrap_or(0)..=snap.block {
            if let Some(hash) = f.hash_at(n) {
                assert_eq!(
                    hash,
                    chain.node().hash(n),
                    "block {n} kept from a replaced chain"
                );
            }
        }
        assert!(
            f.settled() <= chain.node().tips()[3],
            "settled above finality"
        );
        drop(followed);
        self.top = snap.block;
        snap
    }

    /// The view a round's commit or the prune pass marks the key against.
    async fn view(&mut self, chain: &MemoryChain) -> VersionView {
        let snap = self.snapshot(chain).await;
        let held = [(KEY.to_string(), self.store.tip_versions(ns(), KEY).unwrap())];
        let views = version_views(&self.reader, snap, &target(), &held)
            .await
            .unwrap();
        views.into_iter().next().unwrap()
    }

    /// The node's pruning job: mark the key against its view and delete
    /// the orphans marked below the settled block.
    async fn prune(&mut self, chain: &MemoryChain) -> usize {
        let view = self.view(chain).await;
        NodeVersions::prune(&self.store, ns(), &[(KEY.to_string(), view)]).unwrap()
    }

    /// A round on the key: it creates the version `commitment` from
    /// `parent` for queue entry `index`, under request `n`.
    async fn round(
        &mut self,
        chain: &MemoryChain,
        n: u8,
        commitment: u64,
        parent: u64,
        index: u64,
    ) {
        let view = self.view(chain).await;
        let new = version(KEY, commitment, parent, index, n);
        tip_round(&self.store, n, KEY, Some(new), view).unwrap();
    }

    /// The status, block and block hash `commitment`'s version is marked
    /// with.
    fn mark(&self, commitment: u64) -> (VersionStatus, u64, Fr) {
        let held = self.store.tip_versions(ns(), KEY).unwrap();
        let v = held
            .iter()
            .find(|v| v.commitment == Fr::from(commitment))
            .unwrap();
        (v.status, v.block, v.block_hash)
    }

    fn holds(&self, commitment: Fr) -> bool {
        self.store
            .tip_versions(ns(), KEY)
            .unwrap()
            .iter()
            .any(|v| v.commitment == commitment)
    }
}

/// `commitment` lands for entry `index` in a new block.
fn land(chain: &MemoryChain, commitment: u64, index: u64) -> u64 {
    let block = chain.node().tip() + 1;
    let t = target();
    chain.set_tip(block);
    chain.set_storage_at(block, t.contract, slot(), Fr::from(commitment));
    chain.set_storage_at(
        block,
        t.contract,
        t.layout.head_index(),
        Fr::from(index + 1),
    );
    block
}

/// The key's commitment and the queue's head at `block` on the chain.
fn at(chain: &MemoryChain, block: u64) -> (Fr, u64) {
    let t = target();
    let head = chain.storage_at(block, t.contract, t.layout.head_index());
    (
        chain.storage_at(block, t.contract, slot()),
        fr_u64(head).unwrap(),
    )
}

/// Every commitment the key holds at a block from the finalized tip up is
/// held by `node`: a replacement can make any of them current again, and
/// none below the finalized tip.
fn holds_every_restorable_version(chain: &MemoryChain, node: &Node, label: &str) {
    let [tip, _, _, finalized] = chain.node().tips();
    for b in finalized..=tip {
        let (c, _) = at(chain, b);
        if c != Fr::from(0u64) {
            assert!(
                node.holds(c),
                "{label}: the commitment at block {b} is gone"
            );
        }
    }
}

// Proofs land faster than L1 finalizes them (partial proofs, or a late
// prover's proofs in adjacent L1 blocks): the proven tip moves twice in a
// few blocks while the finalized tip stays behind. An L1 reorg then removes
// both landed rounds and their proofs. The node, which deletes only below
// the finalized tip, still holds the version the slot is back at, and
// deletes it only once finality passes the block that orphaned it.
#[tokio::test]
async fn a_reorg_below_a_proven_tip_finds_its_version() {
    let chain = Arc::new(MemoryChain::new(89));
    let mut node = Node::new(&chain);
    // proofs land, and L1 finality stays at block 90
    let prove = |block: u64| {
        chain.node().set_proven(block);
        chain.node().set_finalized(90);
    };
    let (a, b, c, b2) = (0xa0u64, 0xb0, 0xc0, 0xb2);
    node.round(&chain, 1, a, 0, 0).await;
    land(&chain, a, 0);
    chain.set_tip(100);
    chain.node().set_proven(89);
    prove(90);
    node.prune(&chain).await;
    // two rounds land in blocks 101 and 102, each proven at once; the
    // node's reads see each proof
    node.round(&chain, 2, b, a, 1).await;
    land(&chain, b, 1);
    prove(101);
    node.prune(&chain).await;
    node.round(&chain, 3, c, b, 2).await;
    land(&chain, c, 2);
    prove(102);
    node.prune(&chain).await;
    chain.set_tip(104);
    prove(103);
    assert_eq!(chain.node().tips(), [104, 104, 103, 90]);
    // A was orphaned at block 101, B at 102; the proven tip before the
    // current one (102) is past A's mark, the finalized tip is not
    assert_eq!(node.prune(&chain).await, 0);
    assert!(node.holds(Fr::from(a)) && node.holds(Fr::from(b)));
    assert_eq!(node.reader.settled().await, 90);
    // an L1 reorg removes blocks 101 on and their proofs
    chain.node().replace_from(101);
    chain.set_tip(101);
    chain.node().set_proven(100);
    node.replaced_from(101);
    assert_eq!(at(&chain, 101), (Fr::from(a), 1), "the slot is back at A");
    assert_eq!(node.prune(&chain).await, 0);
    let views = version_views(
        &node.reader,
        Snapshot {
            block: 101,
            hash: Some(chain.node().hash(101)),
        },
        &target(),
        &[(KEY.to_string(), Vec::new())],
    )
    .await
    .unwrap();
    assert_eq!(views[0].slot, Fr::from(a));
    assert!(node.holds(Fr::from(a)), "the version the slot holds again");
    holds_every_restorable_version(&chain, &node, "after the reorg");
    // another attempt of entry 1 lands in block 102 of the replacement
    // chain, orphaning A and B there. Once the finalized tip passes block
    // 104 too, A and B go; C keeps its mark of block 104, made on the
    // replaced chain, which is ignored: C is marked again, not deleted
    node.round(&chain, 4, b2, a, 1).await;
    let landed = land(&chain, b2, 1);
    node.prune(&chain).await;
    chain.set_tip(landed + 6);
    chain.node().set_proven(landed + 3);
    chain.node().set_proven(landed + 5);
    assert_eq!(chain.node().tips()[3], landed + 3);
    assert_eq!(node.prune(&chain).await, 2);
    assert!(!node.holds(Fr::from(a)) && !node.holds(Fr::from(b)));
    assert!(node.holds(Fr::from(b2)));
    assert_eq!(node.mark(c).1, landed + 6);
    assert_eq!(node.mark(c).2, chain.node().hash(landed + 6));
}

// A version orphaned on a chain that a replacement then undid. Two attempts
// of entry 1, W and W', run on V; W lands in block 101 and the node marks V
// (and W') orphan there. A replacement from block 101 makes V the slot's
// again, and W' (an attempt the nodes already hold, so no round commits)
// lands on the replacement chain in block 106 before any pass sees V
// current. The finalized tip then passes block 101 but not 105, so V is the
// slot's at blocks a replacement can still bring back. The node's pass finds
// V's mark of block 101 under a hash the chain no longer has there: it
// ignores the mark and marks V again, instead of deleting it.
#[tokio::test]
async fn a_mark_made_on_a_replaced_block_is_ignored() {
    let chain = Arc::new(MemoryChain::new(99));
    let mut node = Node::new(&chain);
    let (v, w, w2) = (0xa0u64, 0xb0, 0xb2);
    node.round(&chain, 1, v, 0, 0).await;
    assert_eq!(land(&chain, v, 0), 100);
    node.round(&chain, 2, w, v, 1).await;
    node.round(&chain, 3, w2, v, 1).await;
    assert_eq!(land(&chain, w, 1), 101);
    node.prune(&chain).await;
    assert_eq!(
        node.mark(v),
        (VersionStatus::Orphan, 101, chain.node().hash(101))
    );
    // block 101 is replaced: V is the slot's again; W' lands in block 106
    chain.node().replace_from(101);
    chain.set_tip(105);
    node.replaced_from(101);
    assert_eq!(at(&chain, 105), (Fr::from(v), 1), "V is the slot's again");
    assert_eq!(land(&chain, w2, 1), 106);
    // the finalized tip passes block 101, not 105
    chain.node().set_proven(103);
    chain.node().set_proven(106);
    assert_eq!(chain.node().tips()[3], 103);
    assert_eq!(node.prune(&chain).await, 0, "nothing deleted");
    holds_every_restorable_version(&chain, &node, "after the pass");
    assert_eq!(
        node.mark(v),
        (VersionStatus::Orphan, 106, chain.node().hash(106))
    );
    assert_eq!(node.mark(w).1, 106, "W turns orphan on this chain");
    // once the finalized tip passes block 106, V and W go
    chain.set_tip(110);
    chain.node().set_proven(107);
    chain.node().set_proven(108);
    assert_eq!(node.prune(&chain).await, 2);
    assert!(!node.holds(Fr::from(v)) && !node.holds(Fr::from(w)));
    assert!(node.holds(Fr::from(w2)));
}

// A version orphaned under a mark with no block hash (sidecar-core
// `TipVersion::block_hash`): the node cannot check the mark against the chain, so
// it marks the version again at its view's block, with that block's hash,
// rather than delete it, and deletes it once the finalized tip passes that
// block.
#[tokio::test]
async fn a_mark_with_no_hash_is_marked_again_before_it_deletes() {
    let chain = Arc::new(MemoryChain::new(20));
    let mut node = Node::new(&chain);
    let (v, w) = (0xa0u64, 0xb0);
    let by_number = |slot: u64, head: u64, block: u64| VersionView {
        slot: Fr::from(slot),
        head,
        block,
        block_hash: Fr::from(0u64),
        settled: 0,
        replaced: Vec::new(),
    };
    tip_round(
        &node.store,
        1,
        KEY,
        Some(version(KEY, v, 0, 0, 1)),
        by_number(0, 0, 5),
    )
    .unwrap();
    tip_round(&node.store, 2, KEY, None, by_number(w, 1, 6)).unwrap();
    assert_eq!(node.mark(v), (VersionStatus::Orphan, 6, Fr::from(0u64)));
    // the chain holds W at the head's entry 0, applied; finality passes
    // block 6
    let t = target();
    chain.set_storage(t.contract, slot(), Fr::from(w));
    chain.set_storage(t.contract, t.layout.head_index(), Fr::from(1u64));
    chain.node().set_proven(10);
    node.snapshot(&chain).await;
    chain.node().set_proven(12);
    assert_eq!(node.prune(&chain).await, 0, "nothing deleted");
    assert_eq!(node.reader.settled().await, 10);
    assert_eq!(
        node.mark(v),
        (VersionStatus::Orphan, 20, chain.node().hash(20))
    );
    // once the finalized tip passes block 20, V goes
    chain.set_tip(30);
    chain.node().set_proven(22);
    chain.node().set_proven(24);
    assert_eq!(node.prune(&chain).await, 1);
    assert!(!node.holds(Fr::from(v)));
}

/// A small deterministic generator (xorshift64*), so a failing sequence
/// replays from its seed.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    /// A number in `lo..=hi`.
    fn range(&mut self, lo: u64, hi: u64) -> u64 {
        lo + self.next() % (hi - lo + 1)
    }
}

// Random rounds, landings, replacements of random depth above the finalized
// tip (an L1 reorg removing the proofs above it too), proofs and finality,
// read by three nodes that poll at different times, over several seeds.
// Finality lags: a proof finalizes the one before it only half the time,
// and otherwise L1 finality stays where it is until a separate step moves
// it, so replacements land between the finalized tip and the proven tip
// before the current one, where a floor at that proven tip would already
// have deleted the versions they bring back. After every step: each node's
// reader reported every replacement of blocks it held, never shallower than
// the true point; it keeps only the chain's own hashes; and every
// commitment the key holds at a block from the finalized tip up (any state
// a further replacement can bring back) is held by every node. The nodes
// mark the key after each landing, as a round's commit does, and at random
// between; never right after a replacement, so marks made on a chain a
// replacement undid stand until a later pass ignores them by their hash.
#[tokio::test]
async fn random_reorgs_never_lose_a_restorable_version() {
    let mut total = Run::default();
    for seed in [
        0x5eed_0f9e_0c00,
        0x5eed_0f9e_0c01,
        0x5eed_0f9e_0c02,
        0x5eed_0f9e_0c03,
    ] {
        let run = random_run(seed).await;
        total.reorgs += run.reorgs;
        total.landings += run.landings;
        total.deleted += run.deleted;
        total.below_proven += run.below_proven;
    }
    assert!(
        total.reorgs > 80 && total.landings > 80,
        "{} reorgs, {} landings",
        total.reorgs,
        total.landings
    );
    assert!(total.deleted > 0, "retention deletes too");
    assert!(
        total.below_proven > 0,
        "replacements reach below the proven tip before the current one"
    );
}

/// What one seed's run did.
#[derive(Default)]
struct Run {
    reorgs: usize,
    landings: usize,
    deleted: usize,
    /// Replacements from a block at or below a proven tip, the one before
    /// the current (and above the finalized tip).
    below_proven: usize,
}

async fn random_run(seed: u64) -> Run {
    let mut rng = Rng(seed);
    let chain = Arc::new(MemoryChain::new(10));
    let mut nodes: Vec<Node> = (0..3).map(|_| Node::new(&chain)).collect();
    for node in &mut nodes {
        node.snapshot(&chain).await;
    }
    // the versions computed, not yet landed: (commitment, parent, index)
    let mut computed: Vec<(u64, u64, u64)> = Vec::new();
    let mut next_commitment = 0x1000u64;
    let mut n = 0u8;
    let mut run = Run::default();
    // the proven tip before the current one
    let mut previous_proven = 0u64;
    for step in 0..600 {
        let [tip, _, proven, finalized] = chain.node().tips();
        let label = format!("seed {seed:#x} step {step}");
        let mut mark_all = false;
        match rng.range(0, 99) {
            0..=29 => chain.set_tip(tip + 1),
            30..=49 if n < 250 => {
                // a round on the entry at the head, on the slot's state
                let (c, head) = at(&chain, tip);
                let parent = fr_u64(c).unwrap();
                n += 1;
                next_commitment += 1;
                for node in &mut nodes {
                    node.round(&chain, n, next_commitment, parent, head).await;
                }
                computed.push((next_commitment, parent, head));
            }
            50..=64 => {
                // the latest round on the slot's state at the head lands
                let (c, head) = at(&chain, tip);
                let parent = fr_u64(c).unwrap();
                if let Some(&(v, _, index)) = computed
                    .iter()
                    .rev()
                    .find(|(_, p, i)| *p == parent && *i == head)
                {
                    land(&chain, v, index);
                    run.landings += 1;
                    mark_all = true;
                }
            }
            65..=74 if tip > finalized + 1 => {
                // a replacement of 1 to 8 blocks above the finalized tip,
                // the new chain up to 3 blocks shorter or longer
                let from = tip.saturating_sub(rng.range(0, 7)).max(finalized + 1);
                if from <= previous_proven {
                    run.below_proven += 1;
                }
                chain.node().replace_from(from);
                chain.set_tip(from - 1 + rng.range(0, tip - from + 4));
                if proven >= from {
                    let back = (from - 1).max(finalized);
                    chain.node().set_proven(back);
                    previous_proven = previous_proven.min(back);
                }
                for node in &mut nodes {
                    node.replaced_from(from);
                }
                run.reorgs += 1;
            }
            75..=89 if proven < tip => {
                // a proof lands; half the time L1 finality stays put
                // (proofs landing faster than L1 finalizes them)
                let lags = rng.range(0, 1) == 0;
                chain.node().set_proven(rng.range(proven + 1, tip));
                if lags {
                    chain.node().set_finalized(finalized);
                }
                previous_proven = proven;
            }
            90..=94 if finalized < proven => {
                chain.node().set_finalized(rng.range(finalized + 1, proven))
            }
            _ => {
                let i = rng.range(0, 2) as usize;
                run.deleted += nodes[i].prune(&chain).await;
            }
        }
        if mark_all {
            for node in &mut nodes {
                run.deleted += node.prune(&chain).await;
            }
        }
        for node in &nodes {
            holds_every_restorable_version(&chain, node, &label);
        }
    }
    run
}
