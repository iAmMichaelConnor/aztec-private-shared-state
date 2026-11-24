//! Helpers the tests of pss_core, pss_public_contract, the examples' circuit
//! libraries and the Noir vector packages share. No round calls them.
//! `keyed_map` is the clear model of a keyed map the map tests read from;
//! `full` builds a small tip tree in full for the tree and exit tests.

pub mod keyed_map;

use crate::tip::tree::{leaf_hash, node};

/// The depth of the tree `full` builds: eight leaves.
pub global FULL_DEPTH: u32 = 3;

/// A sparse depth-3 tip tree of `namespace` and `key` in full: its root and,
/// for each slot of `at`, the leaf hash, the siblings and the leaf, for
/// `filled` leaves (index, leaf) of the eight (every other leaf 0).
pub fn full<let F: u32, let K: u32, let W: u32>(
    namespace: Field,
    key: Field,
    filled: [(Field, [Field; W]); F],
    at: [Field; K],
) -> (Field, [Field; K], [[Field; FULL_DEPTH]; K], [[Field; W]; K]) {
    let mut level = [0; 8];
    let mut leaves = [[0; W]; 8];
    for f in 0..F {
        let (i, leaf) = filled[f];
        let n = i as u32;
        level[n] = leaf_hash(namespace, key, i, leaf);
        leaves[n] = leaf;
    }
    let mut tree = [[0; 8]; FULL_DEPTH + 1];
    tree[0] = level;
    for l in 0..FULL_DEPTH {
        for p in 0..8 {
            if p < (8 >> (l + 1)) {
                tree[l + 1][p] = node(tree[l][2 * p], tree[l][2 * p + 1]);
            }
        }
    }
    let mut hashes = [0; K];
    let mut siblings = [[0; FULL_DEPTH]; K];
    let mut slot_leaves = [[0; W]; K];
    for k in 0..K {
        let n = at[k] as u32;
        hashes[k] = level[n];
        slot_leaves[k] = leaves[n];
        for l in 0..FULL_DEPTH {
            siblings[k][l] = tree[l][(n >> l) ^ 1];
        }
    }
    (tree[FULL_DEPTH][0], hashes, siblings, slot_leaves)
}

/// The ASCII bytes of `s` as a big-endian integer: the form of every domain
/// separator and label (sidecar-core's `label_field`), so a test checks a
/// constant against its label.
pub fn ascii<let N: u32>(s: str<N>) -> Field {
    let mut v: Field = 0;
    for b in s.as_bytes() {
        v = v * 256 + b as Field;
    }
    v
}
