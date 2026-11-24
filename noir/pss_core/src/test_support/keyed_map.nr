//! A clear model of a keyed map (`tip::map`) for tests: the leaves the map
//! holds, at most `E`, each `[key, value ..., blinding]` at the path of its
//! key's low `D` bits (a vacant leaf, key 0, at the path of the slot that
//! wrote it), and from them what the nodes' oblivious reads give a round for
//! a slot (its leaf, old hash and `D` siblings, `slots`), the root and the
//! commitment. `after` follows a round: the leaves it stored where it
//! wrote. pss_core's map tests, the examples' circuit-library tests and
//! their TXE suites build their rounds' reads from it.
//!
//! The tree is sparse: a node whose subtree holds no leaf is the empty
//! subtree's hash (`tree::zeros`), so only the nodes on the stored leaves'
//! paths are computed, `E` per height, and any depth up to 127 works.

use crate::tip::map::{self, Map};
use crate::tip::tree::{commitment, leaf_hash, node, Updated, zeros};

/// The map's stored leaves under `namespace` and the map's key `key_slot`.
pub struct ClearMap<let E: u32, let D: u32, let W: u32> {
    pub namespace: Field,
    pub key_slot: Field,
    /// the leaves, the first `count` of them stored
    pub leaves: [[Field; W]; E],
    /// each stored leaf's path
    pub paths: [u128; E],
    pub count: u32,
}

/// The slots of a round as the nodes' oblivious reads give them (`tree::Slots`).
pub use crate::tip::tree::Slots;

impl<let E: u32, let D: u32, let W: u32> ClearMap<E, D, W> {
    /// The empty map at `key_slot`.
    pub fn empty(namespace: Field, key_slot: Field) -> Self {
        std::static_assert(D < 128, "a path fits a u128");
        ClearMap { namespace, key_slot, leaves: [[0; W]; E], paths: [0; E], count: 0 }
    }

    /// The map with `leaf` stored at its key's path, in place of the leaf
    /// that path held.
    pub fn with(self, leaf: [Field; W]) -> Self {
        self.at(path_of::<D>(leaf[0]), leaf)
    }

    /// The map with `leaf` stored at `path`, in place of the leaf that path
    /// held.
    pub fn at(self, path: u128, leaf: [Field; W]) -> Self {
        let mut out = self;
        let mut found = false;
        for i in 0..E {
            if (i < out.count) & (out.paths[i] == path) {
                out.leaves[i] = leaf;
                found = true;
            }
        }
        if !found {
            assert(out.count < E, "the model holds at most E leaves");
            out.leaves[out.count] = leaf;
            out.paths[out.count] = path;
            out.count += 1;
        }
        out
    }

    /// The map after a round over the slots of `keys`: each slot's stored
    /// leaf at its key's path where the round wrote it (`Updated::write`,
    /// `stored`).
    pub fn after<let K: u32>(self, keys: [Field; K], updated: Updated<K, W>) -> Self {
        let mut out = self;
        for k in 0..K {
            if updated.write[k] {
                out = out.at(path_of::<D>(keys[k]), updated.stored[k]);
            }
        }
        out
    }

    /// Each stored leaf's path, and its chain of nodes: `[height]` the node
    /// at that height on its path (0 the leaf hash, `D` the root).
    fn chains(self) -> ([u128; E], [[Field; D + 1]; E]) {
        let z = zeros::<D>();
        let paths = self.paths;
        let mut chains = [[0; D + 1]; E];
        for i in 0..E {
            chains[i][0] = leaf_hash(self.namespace, self.key_slot, paths[i] as Field, self.leaves[i]);
        }
        for l in 0..D {
            for i in 0..E {
                let at = paths[i] >> (l as u128);
                let mut sibling = z[l];
                for j in 0..E {
                    if (j < self.count) & ((paths[j] >> (l as u128)) == (at ^ 1)) {
                        sibling = chains[j][l];
                    }
                }
                chains[i][l + 1] = if (at & 1) == 0 {
                    node(chains[i][l], sibling)
                } else {
                    node(sibling, chains[i][l])
                };
            }
        }
        (paths, chains)
    }

    /// The node at `height` whose path prefix is `prefix`.
    fn node_at(self, paths: [u128; E], chains: [[Field; D + 1]; E], height: u32, prefix: u128) -> Field {
        let mut out = zeros::<D>()[height];
        for i in 0..E {
            if (i < self.count) & ((paths[i] >> (height as u128)) == prefix) {
                out = chains[i][height];
            }
        }
        out
    }

    /// The tree's root.
    pub fn root(self) -> Field {
        let (paths, chains) = self.chains();
        self.node_at(paths, chains, D, 0)
    }

    /// The commitment the map's key holds.
    pub fn commitment(self) -> Field {
        commitment(self.namespace, self.key_slot, self.root())
    }

    /// The slots at the paths `at`, as the nodes read them.
    pub fn slots_at<let K: u32>(self, at: [Field; K]) -> Slots<K, D, W> {
        let (paths, chains) = self.chains();
        let mut leaves = [[0; W]; K];
        let mut old_hashes = [0; K];
        let mut siblings = [[0; D]; K];
        for k in 0..K {
            let path = at[k] as u128;
            for i in 0..E {
                if (i < self.count) & (paths[i] == path) {
                    leaves[k] = self.leaves[i];
                }
            }
            old_hashes[k] = self.node_at(paths, chains, 0, path);
            for l in 0..D {
                siblings[k][l] = self.node_at(paths, chains, l, (path >> (l as u128)) ^ 1);
            }
        }
        Slots { leaves, old_hashes, siblings }
    }

    /// The slots of `keys`, every slot used.
    pub fn slots<let K: u32>(self, keys: [Field; K]) -> Slots<K, D, W> {
        self.slots_at(map::paths::<K, D>(keys, K as Field))
    }

    /// The map as a round of `K` slots at `keys` loads it (`map::load`),
    /// `n_used` of them used: an unused slot reads path 0, as the nodes read
    /// it.
    pub fn load<let K: u32>(self, keys: [Field; K], n_used: Field) -> Map<K, D, W> {
        let s = self.slots_at(map::paths::<K, D>(keys, n_used));
        map::load(self.namespace, self.key_slot, keys, s.leaves, s.old_hashes, s.siblings, n_used)
    }
}

/// The path of `key` as an integer.
fn path_of<let D: u32>(key: Field) -> u128 {
    map::path_of::<D>(key) as u128
}
