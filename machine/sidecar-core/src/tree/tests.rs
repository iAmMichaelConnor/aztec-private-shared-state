//! The clear tree's unit tests, and the map-backed tree they share.

use super::*;
use crate::manifest::TreeLayout;
use std::collections::BTreeMap;

pub(super) fn fr(x: u64) -> Fr {
    Fr::from(x)
}

/// A clear tree in a map, as a store holds it.
#[derive(Default)]
pub(crate) struct Map(pub BTreeMap<Fr, TreeNode>);

impl Nodes for Map {
    fn get(&self, hash: Fr) -> Result<Option<TreeNode>, Refusal> {
        Ok(self.0.get(&hash).cloned())
    }
}

impl Map {
    pub(super) fn add(&mut self, rebuilt: &Rebuilt) {
        for (h, _, n) in &rebuilt.added {
            self.0.insert(*h, n.clone());
        }
    }
}

/// The root of a sparse tree by hashing every level in full (the
/// reference the incremental code is checked against).
pub(crate) fn full_root(depth: u32, leaves: &BTreeMap<u64, Fr>) -> Fr {
    let z = zeros(depth);
    let mut level: BTreeMap<u64, Fr> = leaves.clone();
    for zl in z.iter().take(depth as usize) {
        let mut up = BTreeMap::new();
        for pos in level
            .keys()
            .map(|p| p / 2)
            .collect::<std::collections::BTreeSet<_>>()
        {
            let left = level.get(&(2 * pos)).copied().unwrap_or(*zl);
            let right = level.get(&(2 * pos + 1)).copied().unwrap_or(*zl);
            up.insert(pos, node(left, right));
        }
        level = up;
    }
    level.get(&0).copied().unwrap_or(z[depth as usize])
}

#[test]
fn the_labels_are_the_dotted_ascii_bytes() {
    assert_eq!(
        label_field(PSS_TIP_LEAF),
        crate::field::fr_from_hex("0x7073732e7469702e6c656166").unwrap()
    );
    assert_eq!(zeros(3)[0], fr(0));
    assert_eq!(zeros(3)[1], node(fr(0), fr(0)));
    assert_eq!(zeros(3)[3], node(zeros(3)[2], zeros(3)[2]));
}

/// The leaves a round stores are the ones its rebuilt tree reaches: a
/// repeated index keeps its last slot's leaf, an emptied leaf (hash 0)
/// and an unused slot store none, and the stored tree walks whole.
#[test]
fn a_round_stores_only_the_leaves_its_tree_reaches() {
    let depth = 4;
    let z = zeros(depth);
    let touch = Touch {
        indices: vec![0, 3, 3, 5, 0],
        used: vec![true, true, true, true, false],
    };
    let hashes = [fr(11), fr(12), fr(13), fr(0), fr(14)];
    let written = touch.written(&hashes);
    assert_eq!(written, [(0, 0, fr(11)), (2, 3, fr(13))]);
    let mut store = Map::default();
    let rebuilt = rebuild(&store, &z, z[depth as usize], &touch.changes(&hashes)).unwrap();
    store.add(&rebuilt);
    for (_, index, hash) in &written {
        let leaf = TreeNode::Leaf {
            index: *index,
            vec: vec![],
        };
        store.0.insert(*hash, leaf);
    }
    let walked = walk(&store, rebuilt.root).unwrap();
    let reached: Vec<(u64, Fr)> = walked.leaves.iter().map(|l| (l.index, l.hash)).collect();
    assert_eq!(reached, [(0, fr(11)), (3, fr(13))]);
}

#[test]
fn rebuild_matches_hashing_the_whole_tree_and_paths_verify() {
    let depth = 5;
    let z = zeros(depth);
    let mut store = Map::default();
    let mut root = z[depth as usize];
    let mut leaves = BTreeMap::new();
    // writes sharing ancestors, a rewrite of one index, an empty write
    let rounds: [&[(u64, u64)]; 4] = [
        &[(0, 11), (1, 12)],
        &[(2, 13), (31, 14), (1, 15)],
        &[(5, 16), (5, 17)],
        &[(4, 18)],
    ];
    for round in rounds {
        let changes: Vec<(u64, Fr)> = round.iter().map(|(i, h)| (*i, fr(*h))).collect();
        let rebuilt = rebuild(&store, &z, root, &changes).unwrap();
        store.add(&rebuilt);
        for (i, h) in &changes {
            leaves.insert(*i, *h);
        }
        root = rebuilt.root;
        assert_eq!(root, full_root(depth, &leaves));
        for i in [0u64, 1, 2, 3, 4, 5, 6, 30, 31] {
            let p = path(&store, &z, root, i).unwrap();
            assert_eq!(p.leaf, leaves.get(&i).copied().unwrap_or(fr(0)));
            assert_eq!(root_of(p.leaf, &p.siblings, i), root);
        }
    }
    // a path through a node the store lost is a diverged store
    let lost = Map::default();
    assert!(
        path(&lost, &z, root, 0)
            .unwrap_err()
            .message
            .contains("diverged store")
    );
}

#[test]
fn walk_reads_every_stored_leaf_and_checks_the_tree_in_the_clear() {
    let depth = 4;
    let z = zeros(depth);
    let mut store = Map::default();
    let changes = [(0, fr(11)), (3, fr(12)), (9, fr(13))];
    let rebuilt = rebuild(&store, &z, z[depth as usize], &changes).unwrap();
    store.add(&rebuilt);
    let leaf = |index: u64| TreeNode::Leaf {
        index,
        vec: vec![Elem::Public(fr(index))],
    };
    for (i, h) in changes {
        store.0.insert(h, leaf(i));
    }
    let walked = walk(&store, rebuilt.root).unwrap();
    assert_eq!(walked.depth, depth);
    let got: Vec<(u64, Fr)> = walked.leaves.iter().map(|l| (l.index, l.hash)).collect();
    assert_eq!(got, changes);
    assert_eq!(walked.inner.len(), rebuilt.added.len());
    assert_eq!(walk(&store, z[3]).unwrap().depth, 3, "an empty tree");

    // a leaf stored under another index, a child that does not hash to
    // its parent, a lost internal node: each fails naming the tree
    let mut moved = Map(store.0.clone());
    moved.0.insert(fr(12), leaf(2));
    let err = walk(&moved, rebuilt.root).unwrap_err();
    assert!(err.message.contains("leaf 2 at position 3"), "{err}");
    let mut forged = Map(store.0.clone());
    let (h, _, _) = rebuilt.added[0];
    forged.0.insert(
        h,
        TreeNode::Inner {
            left: fr(1),
            right: fr(2),
        },
    );
    let err = walk(&forged, rebuilt.root).unwrap_err();
    assert!(err.message.contains("do not hash to it"), "{err}");
    let mut lost = Map(store.0.clone());
    lost.0.remove(&h);
    let err = walk(&lost, rebuilt.root).unwrap_err();
    assert!(err.message.contains("not empty"), "{err}");
}

fn layout(text: &str) -> TreeLayout {
    serde_json::from_str(text).unwrap()
}

// A window is the `width` leaves from the request's start, or from 0
// when the start is not below 2^D or not a multiple of the width; its
// values are its leaves' old hashes and its first leaf's siblings from
// height log2 width up, out of the paths of every loaded leaf.
#[test]
fn a_window_is_read_from_its_start_or_from_leaf_0() {
    let t = layout(
        r#"{"depth": 4, "leaf_len": 2, "probe": 1, "header": true,
            "window": {"width": 4, "start": "start",
                       "params": {"leaves": "wl", "old_hashes": "wh", "siblings": "ws"}}}"#,
    );
    let at = |start: Option<Fr>| {
        let public: BTreeMap<String, Fr> = start
            .map(|s| ("start".to_string(), s))
            .into_iter()
            .collect();
        window(&t, &public)
    };
    assert_eq!(at(Some(fr(8))), [8, 9, 10, 11]);
    assert_eq!(at(Some(fr(12))), [12, 13, 14, 15]);
    for bad in [Some(fr(2)), Some(fr(16)), Some(-Fr::from(4u64)), None] {
        assert_eq!(at(bad), [0, 1, 2, 3]);
    }
    let flat = layout(r#"{"depth": 4, "leaf_len": 2, "probe": 1, "header": true}"#);
    assert!(window(&flat, &BTreeMap::new()).is_empty());

    // the leaves 0 (the slot), then 8 .. 11 in a tree of leaves 0, 9, 13
    let mut store = Map::default();
    let z = zeros(4);
    let changes: Vec<(u64, Fr)> = [0u64, 9, 13].iter().map(|i| (*i, fr(100 + i))).collect();
    let rebuilt = rebuild(&store, &z, z[4], &changes).unwrap();
    store.add(&rebuilt);
    let loads = [vec![0], at(Some(fr(8)))].concat();
    let p = paths(&store, &z, rebuilt.root, 14, &loads).unwrap();
    let (hashes, siblings) = window_values(&p, 1, 4, 4).unwrap();
    assert_eq!(hashes, [fr(0), fr(109), fr(0), fr(0)]);
    assert_eq!(siblings.len(), 2);
    let window_root = node(node(hashes[0], hashes[1]), node(hashes[2], hashes[3]));
    // window 8 .. 11 is position 2 at height 2: left of 12 .. 15, right
    // of 0 .. 7
    assert_eq!(
        node(siblings[1], node(window_root, siblings[0])),
        rebuilt.root
    );
    assert!(window_values(&p, 2, 4, 4).is_err());
}

#[test]
fn the_touched_indices_follow_the_index_rules() {
    let t = layout(
        r#"{"depth": 4, "leaf_len": 2, "probe": 3, "header": true, "index": ["p1", "p2"],
            "count": "count", "open": "p1"}"#,
    );
    let public = |p1: u64, p2: u64, count: u64| -> BTreeMap<String, Fr> {
        [("p1", p1), ("p2", p2), ("count", count)]
            .into_iter()
            .map(|(k, v)| (k.to_string(), fr(v)))
            .collect()
    };
    let touch = |p1, p2, count, new_leaf| Touch::of(&t, &public(p1, p2, count), fr(new_leaf));
    assert_eq!(
        touch(3, 5, 2, 9),
        Touch {
            indices: vec![0, 3, 5],
            used: vec![true, true, true]
        }
    );
    // the open input at 0 takes $new_leaf; a short count leaves slot 2 at 0
    assert_eq!(touch(0, 5, 1, 9).indices, [0, 9, 0]);
    assert_eq!(touch(0, 5, 1, 9).used, [true, true, false]);
    // out of range (2^4) and a count above the inputs
    assert_eq!(touch(16, 5, 2, 9).indices, [0, 0, 5]);
    assert_eq!(touch(3, 5, 3, 9).used, [true, false, false]);
    // a full tree assigns 0
    assert_eq!(new_leaf(16, 4), 0);
    assert_eq!(new_leaf(15, 4), 15);
    assert_eq!(
        Touch {
            indices: vec![0, 9, 0],
            used: vec![true, true, false]
        }
        .changes(&[fr(1), fr(2), fr(3)]),
        [(0, fr(1)), (9, fr(2))]
    );
    assert_eq!(next_after(1, &[(0, fr(1)), (9, fr(2))]), 10);
}
