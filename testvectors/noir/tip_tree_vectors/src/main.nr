//! Checks the hashes and updates of a tree-valued node-held key with the
//! functions the round circuits call (noir/pss_core's
//! `tip::tree`): every case of testvectors/tip_tree.json, the leaf hashes
//! for leaves of 2 and 4 elements, the internal nodes, the commitments, the
//! empty subtrees of a depth-16 tree, each K = 3 update (load, then
//! update), and each window a scan round reads (the header slot loaded,
//! then `Tree::window` at the request's start). Prover.toml is written from the vector file by sidecar-core
//! (tree::vectors::write_tree_vectors); `nargo execute` fails on any
//! disagreement.

use pss_core::tip::tree;
use pss_core::tip::tree::{commitment, empty_root, leaf_hash, load, node};

global D: u32 = 16;
global K: u32 = 3;

/// One leaf-hash case: a leaf of W elements at an index.
struct LeafVector<let W: u32> {
    namespace: Field,
    key: Field,
    index: Field,
    leaf: [Field; W],
    hash: Field,
}

/// One internal-node case.
struct NodeVector {
    left: Field,
    right: Field,
    hash: Field,
}

/// One commitment case.
struct CommitmentVector {
    namespace: Field,
    key: Field,
    root: Field,
    commitment: Field,
}

/// One update case: K = 3 slots (the header and two positions) of a
/// depth-16 tree with leaves of 2 elements.
struct UpdateVector {
    namespace: Field,
    key: Field,
    leaves: [[Field; 2]; K],
    old_hashes: [Field; K],
    siblings: [[Field; D]; K],
    indices: [Field; K],
    n_used: Field,
    ok: bool,
    writes: [bool; K],
    new_leaves: [[Field; 2]; K],
    old_root: Field,
    old_c: Field,
    new_hashes: [Field; K],
    stored: [[Field; 2]; K],
    new_root: Field,
    new_c: Field,
}

/// One window case: the header slot of a depth-16 tree with leaves of 2
/// elements, and the window of N = 2^H leaves from the request's start, as
/// the nodes place it (the window root's S = D - H siblings).
struct WindowVector<let N: u32, let S: u32> {
    namespace: Field,
    key: Field,
    start: Field,
    effective_start: Field,
    aligned: bool,
    slot_leaf: [Field; 2],
    slot_hash: Field,
    slot_siblings: [Field; D],
    leaves: [[Field; 2]; N],
    old_hashes: [Field; N],
    siblings: [Field; S],
    old_root: Field,
}

fn check_leaf<let W: u32>(v: LeafVector<W>) {
    assert_eq(leaf_hash(v.namespace, v.key, v.index, v.leaf), v.hash, "leaf hash");
}

fn check_node(v: NodeVector) {
    assert_eq(node(v.left, v.right), v.hash, "node");
}

fn check_commitment(v: CommitmentVector) {
    assert_eq(commitment(v.namespace, v.key, v.root), v.commitment, "commitment");
}

fn check_update(v: UpdateVector) {
    let t = load::<K, D, 2>(
        v.namespace,
        v.key,
        v.leaves,
        v.old_hashes,
        v.siblings,
        v.indices,
        v.n_used,
    )
        .headed();
    assert_eq(t.old_root, v.old_root, "old_root");
    assert_eq(t.old_c, v.old_c, "old_c");
    assert(t.paths_ok, "paths_ok");
    assert(t.count_ok & t.in_range & t.distinct, "index flags");
    let u = t.update(v.ok, v.writes, v.new_leaves);
    assert_eq(u.new_hashes, v.new_hashes, "new_hashes");
    assert_eq(u.stored, v.stored, "stored");
    assert_eq(u.new_root, v.new_root, "new_root");
    assert_eq(u.new_c, v.new_c, "new_c");
}

fn check_window<let N: u32, let H: u32, let S: u32>(v: WindowVector<N, S>) {
    let t = load::<1, D, 2>(
        v.namespace,
        v.key,
        [v.slot_leaf],
        [v.slot_hash],
        [v.slot_siblings],
        [0],
        1,
    )
        .headed();
    assert_eq(t.old_root, v.old_root, "window: old_root");
    assert(t.paths_ok, "window: the header's path");
    let w = t.window::<N, H, S>(v.start, v.leaves, v.old_hashes, v.siblings);
    assert_eq(w.start, v.effective_start, "window: effective start");
    assert_eq(w.aligned, v.aligned, "window: aligned");
    assert(w.root_ok, "window: root");
}

fn main(
    zeros: [Field; D + 1],
    leaf2_0: LeafVector<2>,
    leaf2_1: LeafVector<2>,
    leaf2_2: LeafVector<2>,
    leaf4_0: LeafVector<4>,
    leaf4_1: LeafVector<4>,
    node0: NodeVector,
    node1: NodeVector,
    node2: NodeVector,
    commitment0: CommitmentVector,
    commitment1: CommitmentVector,
    update0: UpdateVector,
    update1: UpdateVector,
    update2: UpdateVector,
    update3: UpdateVector,
    update4: UpdateVector,
    window4_0: WindowVector<4, 14>,
    window4_1: WindowVector<4, 14>,
    window4_2: WindowVector<4, 14>,
    window8_0: WindowVector<8, 13>,
    window8_1: WindowVector<8, 13>,
    window8_2: WindowVector<8, 13>,
) {
    assert_eq(zeros, tree::zeros::<D>(), "zeros");
    assert_eq(zeros[D], empty_root::<D>(), "empty root");

    check_leaf(leaf2_0);
    check_leaf(leaf2_1);
    check_leaf(leaf2_2);
    check_leaf(leaf4_0);
    check_leaf(leaf4_1);

    check_node(node0);
    check_node(node1);
    check_node(node2);

    check_commitment(commitment0);
    check_commitment(commitment1);

    check_update(update0);
    check_update(update1);
    check_update(update2);
    check_update(update3);
    check_update(update4);

    check_window::<4, 2, 14>(window4_0);
    check_window::<4, 2, 14>(window4_1);
    check_window::<4, 2, 14>(window4_2);
    check_window::<8, 3, 13>(window8_0);
    check_window::<8, 3, 13>(window8_1);
    check_window::<8, 3, 13>(window8_2);
}
