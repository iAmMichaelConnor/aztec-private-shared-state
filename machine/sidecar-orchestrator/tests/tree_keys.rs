//! A tree-valued node-held key at the tip over three real nodes with real
//! MPC proofs: the machine's tree rounds (machine/circuits `tip_tree_init`
//! and `tip_tree`, depth 16, three slots: the header and two positions),
//! driven by the scheduler on sidecar-tip's in-memory Aztec node, each node
//! running the real chain verifier over it. Every round is a co-noir
//! three-party witness extension of the depth-16, K = 3 circuit.
//!
//! - The init round creates the tree, its header's append index 1; two
//!   opening rounds take the append indices 1 and 2, which the circuit
//!   checks against the header and advances (the second pipelined on the
//!   first's version).
//! - A round on positions 1 and 2 (paths 0, 1, 2 sharing ancestors) loads
//!   the three leaves and leaves the values the three nodes' leaves open to.
//! - A duplicate index and position 0 are flagged (ok = 0, no version); a
//!   short count leaves the unused slot alone.
//! - A node whose clear tree diverged stops the scheduler naming the key;
//!   a node whose leaf pairs diverged is refused at the session handshake.
//! - Versions the settled block has passed are pruned
//!   with the nodes only they reach.
//! - A node's store deleted (its key directory kept) is resynced from its
//!   two neighbours through the three admin sockets: every canonical and
//!   live version and every node of their clear trees, leaves with their
//!   pairs, come back with their counts; the audit recomputes every leaf
//!   hash; the next round runs and lands.
//!
//! Needs `scripts/prepare-data.sh` (machine/circuits under machine/data, or
//! DATA_DIR); fails naming the missing files if they are absent, so a
//! passing run proves it ran. Run with `--release`.

mod common;

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Instant;

use common::tip::*;
use common::*;
use serde_json::Value;

use sidecar_core::bind::Elem;
use sidecar_core::field::{Fr, fr_from_hex, fr_to_hex};
use sidecar_core::response::ExecuteResponse;
use sidecar_core::store::{Store, StoreRead, TipVersion, VersionStatus, VersionTree};
use sidecar_core::tree::{self, StoredNode, TreeNode};
use sidecar_node::admin::AdminRequest;
use sidecar_tip::testing::MemoryChain;

const TIP: u64 = 0x7197;
// the slot as the contract manifest writes it (fr_to_hex)
const BOOK: &str = "0x000000000000000000000000000000000000000000000000000000000000a003";
const DEPTH: u32 = 16;
const INIT: &str = "tip_tree_init";
const ROUND: &str = "tip_tree";

fn ns() -> Fr {
    Fr::from(TIP)
}

fn book() -> Fr {
    fr_from_hex(BOOK).unwrap()
}

fn namespace() -> TipEntry {
    tip_namespace(ns(), BOOK, &[INIT, ROUND], &[INIT])
}

fn tree_manifest(name: &str) -> Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join(format!("../../machine/circuits/manifests/{name}.json"));
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

/// The book's clear trees.
impl World {
    fn store(&self, i: usize) -> &sidecar_core::store::MemoryStore {
        &self.real.apps[i].node.store
    }

    fn node(&self, i: usize, hash: Fr) -> Option<StoredNode> {
        self.store(i).tip_node(ns(), BOOK, hash).unwrap()
    }

    /// The value of leaf `index` of the version under `commitment` (its
    /// first element; 0 for an empty leaf), with the leaf's hash.
    fn leaf(&self, commitment: Fr, index: u64) -> (u64, Fr) {
        let (elements, hash) = self.opened(commitment, index);
        (elements[0], hash)
    }

    /// Leaf `index` of the version under `commitment`, its value and append
    /// index (or a position's 0) opened from the three nodes' pairs (the
    /// blinding left out), with the leaf's hash.
    fn opened(&self, commitment: Fr, index: u64) -> ([u64; 2], Fr) {
        let root = self
            .version(commitment)
            .tree
            .and_then(VersionTree::clear)
            .unwrap()
            .root;
        let z = tree::zeros(DEPTH);
        let parts: Vec<Vec<Elem>> = (0..3)
            .map(|i| {
                let nodes = |h: Fr| Ok(self.node(i, h).map(|n| n.node));
                let path = tree::path(&nodes, &z, root, index).unwrap();
                assert_eq!(tree::root_of(path.leaf, &path.siblings, index), root);
                tree::leaves(&nodes, &z, root, 3, &[index]).unwrap()
            })
            .collect();
        let hash = {
            let nodes = |h: Fr| Ok(self.node(0, h).map(|n| n.node));
            tree::path(&nodes, &z, root, index).unwrap().leaf
        };
        let open = |e: usize| match [&parts[0][e], &parts[1][e], &parts[2][e]] {
            [Elem::Shared(a), Elem::Shared(b), Elem::Shared(c)] => small(a.a + b.a + c.a),
            [Elem::Public(a), Elem::Public(b), Elem::Public(c)] if a == b && b == c => small(*a),
            _ => panic!("the nodes disagree on a leaf element's kind"),
        };
        ([open(0), open(1)], hash)
    }

    /// Replace node `i`'s stored node under `hash`.
    fn tamper(&self, i: usize, hash: Fr, node: StoredNode) {
        let mut txn = self.store(i).begin(ns());
        txn.node(BOOK, hash, Some(node));
        self.store(i).commit(txn).unwrap();
    }
}

/// A tip_tree result's ok, code and position.
fn outcome(w: &World, result: &ExecuteResponse) -> (bool, u64, u64) {
    let o = w.outputs(result);
    (o.ok(), o.small("code"), o.small("position"))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn tree_rounds_run_on_node_held_trees() {
    let tmp = TempDir::new("treekeys");
    let mem = Arc::new(MemoryChain::new(100));
    let w = setup(
        &tmp,
        &mem,
        &namespace(),
        vec![
            Package::new(INIT, tree_manifest(INIT)),
            Package::new(ROUND, tree_manifest(ROUND)),
        ],
    )
    .await;
    let started = Instant::now();
    let mut clock = Clock::new(100, mem.clone());
    let mut chain = Chain::new(&clock, ns(), book(), w.sig_pks);
    let mut s = scheduler(&w, &mem, &namespace());

    // ---- the init round, two openings at the append index ------------------
    // tip_tree's app inputs: [amount, p1, p2, count]
    let c0 = chain.intake(&clock, w.vk(INIT), &[0], 1);
    let c1 = chain.intake(&clock, w.vk(ROUND), &[5, 0, 0, 1], 2);
    let r = step(&mut s, clock.next(), "init and the first opening").await;
    assert_eq!(computed(&r), [0, 1], "{r:?}");
    let (v0, v1) = (new_c(&r, 0), new_c(&r, 1));
    assert_eq!(w.version(v0).tree.unwrap().next(), 1);
    assert_eq!(w.version(v1).tree.unwrap().next(), 2);
    w.apply(&clock, &mut chain, &w.latest("init", c0).await)
        .unwrap();
    let c2 = chain.intake(&clock, w.vk(ROUND), &[7, 0, 0, 1], 3);
    let r = step(&mut s, clock.next(), "the second opening, pipelined").await;
    assert_eq!(computed(&r), [2], "{r:?}");
    let v2 = new_c(&r, 2);
    assert_eq!(r.computed[0].old[BOOK], v1);
    let open1 = w.latest("open 1", c1).await;
    assert_eq!(outcome(&w, &open1), (true, 0, 1));
    w.apply(&clock, &mut chain, &open1).unwrap();
    let open2 = w.latest("open 2", c2).await;
    assert_eq!(outcome(&w, &open2), (true, 0, 2));
    w.apply(&clock, &mut chain, &open2).unwrap();
    // the header's total and append index (the circuit's, as the version
    // records it), each position's value and 0
    assert_eq!(w.opened(v0, 0).0, [0, 1]);
    assert_eq!(w.opened(v2, 0).0, [12, 3]);
    assert_eq!(w.version(v2).tree.unwrap().next(), 3);
    assert_eq!(w.opened(v2, 1).0, [5, 0]);
    assert_eq!(w.opened(v2, 2).0, [7, 0]);
    assert_eq!(w.leaf(v2, 3), (0, Fr::from(0u64)));
    eprintln!(
        "init and two openings: {:.1}s",
        started.elapsed().as_secs_f64()
    );

    // ---- positions 1 and 2: three paths sharing ancestors ---------------------
    let c3 = chain.intake(&clock, w.vk(ROUND), &[3, 1, 2, 2], 4);
    let r = step(&mut s, clock.next(), "positions 1 and 2").await;
    assert_eq!(computed(&r), [3], "{r:?}");
    let v3 = new_c(&r, 3);
    let both = w.latest("positions 1 and 2", c3).await;
    assert_eq!(outcome(&w, &both), (true, 0, 1));
    w.apply(&clock, &mut chain, &both).unwrap();
    assert_eq!(w.leaf(v3, 0).0, 18);
    assert_eq!(w.leaf(v3, 1).0, 8);
    assert_eq!(w.leaf(v3, 2).0, 10);
    // the round's new leaf hashes are the version's clear tree
    let o = w.outputs(&both);
    for i in [0u64, 1, 2] {
        assert_eq!(o.get(&format!("new_hashes[{i}]")), w.leaf(v3, i).1);
    }

    // ---- flagged rounds create no version; a short count ---------------------
    let held = w.agreed().len();
    let c4 = chain.intake(&clock, w.vk(ROUND), &[1, 1, 1, 2], 5);
    let c5 = chain.intake(&clock, w.vk(ROUND), &[1, 2, 0, 2], 6);
    let r = step(&mut s, clock.next(), "a duplicate index and position 0").await;
    assert_eq!(computed(&r), [4, 5], "{r:?}");
    assert_eq!(new_c(&r, 4), v3, "a flagged round keeps the commitment");
    assert_eq!(new_c(&r, 5), v3);
    let dup = w.latest("duplicate", c4).await;
    assert_eq!(outcome(&w, &dup), (false, 3, 1));
    w.apply(&clock, &mut chain, &dup).unwrap();
    let zero = w.latest("position 0", c5).await;
    assert!(!outcome(&w, &zero).0);
    assert_eq!(outcome(&w, &zero).1, 2);
    w.apply(&clock, &mut chain, &zero).unwrap();
    assert_eq!(w.agreed().len(), held, "flagged rounds make no version");
    let c6 = chain.intake(&clock, w.vk(ROUND), &[4, 2, 999, 1], 7);
    let r = step(&mut s, clock.next(), "a short count").await;
    let v6 = new_c(&r, 6);
    w.apply(&clock, &mut chain, &w.latest("short count", c6).await)
        .unwrap();
    assert_eq!(w.leaf(v6, 2).0, 14);
    assert_eq!(w.leaf(v6, 1), w.leaf(v3, 1), "leaf 1 untouched");
    assert_eq!(w.leaf(v6, 999), (0, Fr::from(0u64)));
    assert_eq!(
        w.opened(v6, 0).0,
        [22, 3],
        "no opening: the append index stays"
    );

    // ---- a diverged clear tree at one node ------------------------------------
    let root6 = w
        .version(v6)
        .tree
        .and_then(VersionTree::clear)
        .unwrap()
        .root;
    let honest = w.node(2, root6).unwrap();
    let TreeNode::Inner { left, right } = honest.node.clone() else {
        panic!("the root is an internal node");
    };
    w.tamper(
        2,
        root6,
        StoredNode {
            node: TreeNode::Inner {
                left,
                right: right + Fr::from(1u64),
            },
            refs: honest.refs,
        },
    );
    let c7 = chain.intake(&clock, w.vk(ROUND), &[1, 1, 2, 2], 8);
    let r = step(&mut s, clock.next(), "a diverged tree").await;
    assert!(r.computed.is_empty(), "{r:?}");
    let error = r.error.clone().unwrap_or_default();
    assert!(
        error.contains(&format!("key `{BOOK}`")) && error.contains("clear trees differ"),
        "{r:?}"
    );
    w.tamper(2, root6, honest);

    // ---- diverged leaf pairs at one node: the handshake compares them ---------
    let (_, h1) = w.leaf(v6, 1);
    let honest = w.node(1, h1).unwrap();
    let TreeNode::Leaf { index, mut vec } = honest.node.clone() else {
        panic!("a leaf");
    };
    if let Elem::Shared(share) = &mut vec[0] {
        share.a += Fr::from(1u64);
    }
    w.tamper(
        1,
        h1,
        StoredNode {
            node: TreeNode::Leaf { index, vec },
            refs: honest.refs,
        },
    );
    let r = step(&mut s, clock.next(), "diverged leaf pairs").await;
    assert!(r.computed.is_empty(), "{r:?}");
    let error = r.error.clone().unwrap_or_default();
    assert!(error.contains("session handshake"), "{r:?}");
    w.tamper(1, h1, honest);
    // the proven tip catches up, past every version orphaned so far; the
    // nodes' reads of the next round see it
    clock.prove();
    let r = step(&mut s, clock.next(), "the stores repaired").await;
    assert_eq!(computed(&r), [7], "{r:?}");
    let v7 = new_c(&r, 7);
    w.apply(&clock, &mut chain, &w.latest("after the repair", c7).await)
        .unwrap();

    // ---- versions the settled block passed are pruned with their nodes ---
    // (the clock's proven tip moves twice before the next round, so the
    // finalized tip, one proof behind it, passes the stores-repaired round)
    let gone_leaf = w.leaf(v2, 1).1;
    assert!(w.node(0, gone_leaf).is_some());
    clock.later(PROVING_LAG + 2);
    let c8 = chain.intake(&clock, w.vk(ROUND), &[1, 1, 2, 2], 9);
    let r = step(&mut s, clock.next(), "past the settled block").await;
    let v8 = new_c(&r, 8);
    w.apply(&clock, &mut chain, &w.latest("past the depth", c8).await)
        .unwrap();
    let held = w.agreed();
    let kept: Vec<Fr> = held.iter().map(|v| v.commitment).collect();
    assert!(kept.contains(&v7) && kept.contains(&v8), "{kept:?}");
    // v3, superseded when v6 landed, was first marked orphan by the round at
    // block 108 (the two refused rounds commit nothing); this round's
    // settled block (110, the finalized tip) has passed that mark, so v3
    // goes with the older versions
    for old in [v0, v1, v2, v3] {
        assert!(!kept.contains(&old), "{} kept", fr_to_hex(old));
    }
    for i in 0..3 {
        assert!(
            w.node(i, gone_leaf).is_none(),
            "node {i} kept an unreached leaf"
        );
    }
    assert_eq!(w.leaf(v8, 1).0, 10);
    assert_eq!(w.leaf(v8, 2).0, 16);

    // ---- a lost store, resynced from the two neighbours ----------------------
    let lost = 0;
    // the versions but each node's block, and the nodes but their counts
    // (an orphan the lost node still keeps shared some)
    let tree_of = |i: usize| -> (Vec<TipVersion>, BTreeMap<Fr, TreeNode>) {
        let versions: Vec<TipVersion> = w
            .versions(i)
            .into_iter()
            .filter(|v| v.status != VersionStatus::Orphan)
            .map(|v| TipVersion { block: 0, ..v })
            .collect();
        let mut nodes = BTreeMap::new();
        for v in &versions {
            let root = v.tree.and_then(VersionTree::clear).unwrap().root;
            let read = |h: Fr| -> Result<Option<TreeNode>, sidecar_core::Refusal> {
                Ok(w.node(i, h).map(|n| n.node))
            };
            let walked = tree::walk(&read, root).unwrap();
            for h in walked
                .leaves
                .iter()
                .map(|l| l.hash)
                .chain(walked.inner.iter().map(|n| n.0))
            {
                nodes.insert(h, w.node(i, h).unwrap().node);
            }
        }
        (versions, nodes)
    };
    // the nodes mark their versions against the chain as it stands (the
    // resync marks first too), so the landed round's version is canonical
    w.prune().await;
    let before = tree_of(lost);
    w.real.apps[lost].node.store.clear();
    let resynced = Instant::now();
    let answers = w
        .real
        .admin_all(AdminRequest::Resync {
            lost,
            pins: Box::new(w.real.pins()),
        })
        .await;
    for (i, answer) in answers.into_iter().enumerate() {
        assert!(answer.ok, "resync at node {i}: {:?}", answer.refusal);
        let report = answer.resync.unwrap();
        assert!(report.passed(), "node {i}: {:?}", report.audit);
        let book_audit = &report.audit[0];
        assert_eq!((book_audit.key.as_str(), book_audit.hashes), (BOOK, 3));
    }
    eprintln!(
        "resync of node {lost}: {:.1}s",
        resynced.elapsed().as_secs_f64()
    );
    assert_eq!(tree_of(lost), before);
    let c9 = chain.intake(&clock, w.vk(ROUND), &[2, 1, 2, 2], 10);
    let r = step(&mut s, clock.next(), "a round after the resync").await;
    assert_eq!(computed(&r), [9], "{r:?}");
    let v9 = new_c(&r, 9);
    let after = w.latest("after the resync", c9).await;
    assert_eq!(outcome(&w, &after), (true, 0, 1));
    w.apply(&clock, &mut chain, &after).unwrap();
    assert_eq!(w.leaf(v9, 1).0, 12);
    assert_eq!(w.leaf(v9, 2).0, 18);
    // v3 stays gone at every node, the resynced one included
    for i in 0..3 {
        assert!(
            w.versions(i).iter().all(|v| v.commitment != v3),
            "node {i} kept v3"
        );
    }
    eprintln!(
        "tree-valued key rounds: {:.1}s",
        started.elapsed().as_secs_f64()
    );
}
