//! A tree-valued node-held key (docs/ARCHITECTURE.md section 6,
//! "Tree-valued keys"): a binary Poseidon2 Merkle tree of depth `D` whose
//! leaves are vectors of `W` field elements, of which a round touches at
//! most `K` (the manifest's probe width).
//!
//! ```text
//! leaf_hash(i, leaf) = poseidon2([TIP_LEAF_SEP, namespace, key, i, leaf...])   (0: an empty leaf)
//! node(l, r)         = poseidon2([TIP_NODE_SEP, l, r])
//! commitment         = poseidon2([TIP_TREE_SEP, namespace, key, root])
//! Z_0 = 0, Z_{l+1} = node(Z_l, Z_l): the empty subtree of height l; an empty tree's root is Z_D
//! ```
//!
//! Every leaf carries its own blinding, drawn fresh each time a round
//! writes it, so leaf and internal hashes are public data: the nodes hold
//! the tree of hashes in the clear and the leaves as Rep3 pairs. A round
//! names its touched leaves by index in the clear, one slot per touched
//! leaf, and the nodes place each slot's leaf (LOAD_LEAF, shared), its old
//! hash and its `D` siblings (PUBLIC). Every slot carries a real path of
//! the loaded tree: a slot the round does not use (past its count) holds
//! leaf 0's path at index 0.
//!
//! A round `load`s the slots (or starts from `empty` when it creates the
//! key; then `Tree::headed` when slot 0 is the tree's header leaf 0),
//! checks each old leaf against its old hash (the one assertion: a
//! mismatch is node-supplied data from a diverged store), takes the old
//! root from slot 0's path and flags every other inconsistency for the
//! app's outcome. `Tree::update` writes the new leaves of the used slots
//! and rebuilds the root path by path in slot order (`Tree::update_private`
//! under private outcomes, re-blinding every leaf the round holds); it
//! writes nothing unless the tree's own placement flags hold
//! (`Tree::placed`), whatever the app passes, so a round whose count, paths,
//! ranges or distinct indices fail cannot commit a root no node can
//! rebuild. `Updated::store` hands the stored leaves to the machine.
//!
//! A tree whose leaves open in order and are never reclaimed (the
//! manifest's `open`) keeps its append index in its header leaf: an
//! opening round requires the scheduler's `$new_leaf` to equal it and
//! writes it incremented (`append`), so the written leaves stay a prefix of
//! the tree whoever assigns the index; the scheduler's assignment and each
//! node's check of it are the hint the circuit verifies.
//!
//! A scan round also reads a window (`Tree::window`): `N = 2^H` consecutive
//! leaves at a start the request names in the clear, placed by the nodes
//! after the slots with their old hashes and the `D - H` siblings of the
//! window's subtree root, and bound to the old root through those alone; a
//! window is read, never written.
//!
//! Under a tree with `access: oblivious` (docs/ARCHITECTURE.md section 6, "The
//! oblivious tree", "The circuit") the same `load` runs over shared values: the
//! leaves, old hashes and siblings are the nodes' oblivious RAM reads, and the
//! indices are the round's own inputs composed by `slot_indices` (leaf 0 in the
//! header slot and the unused slots, `$new_leaf` in an opening slot, the shared
//! entry input elsewhere), so no node places an index: an app that calls
//! `indices_match` on both accesses (lending) compares there the inputs with
//! the indices the circuit built from them. The paths are then verified on the
//! index bits of the inputs `C` commits to, which is what makes the unproven
//! oblivious RAM verifiable. `Tree::update_paths` returns the new path nodes
//! beside the update and `Updated::store_oblivious` hands them to the machine
//! with the leaves and hashes: the nodes write them into the oblivious RAM at
//! the next session's start.
//!
//! Cost: the old paths are public values (`K·D` permutations the nodes
//! compute without communication); the new paths are `K·D` Poseidon2
//! permutations over shared values, sequential in depth; each slot hashes
//! its old and its new leaf (`ceil((W + 4) / 3)` permutations each); two
//! commitments of two permutations each. testvectors/tip_tree.json holds the
//! known answers (machine/sidecar-core src/tree/ is the reference), which
//! testvectors/noir/tip_tree_vectors checks with these functions.

use super::family::Change;
use crate::mpc_store;
use total::cmp::eq;
use total::core::{is_zero, limbs, select_field, two_pow};
use total::hash::p2_hash_sep;
use total::range::clamp_bits_or;

/// Domain separator of a leaf hash, ASCII "pss.tip.leaf" as a big-endian
/// integer.
pub global TIP_LEAF_SEP: Field = 0x7073732e7469702e6c656166;
/// Domain separator of an internal node, ASCII "pss.tip.node".
pub global TIP_NODE_SEP: Field = 0x7073732e7469702e6e6f6465;
/// Domain separator of the tree commitment, ASCII "pss.tip.tree".
pub global TIP_TREE_SEP: Field = 0x7073732e7469702e74726565;

/// The hash of leaf `index` of the tree of `key` under `namespace`:
/// p2_hash_sep([namespace, key, index, leaf...], TIP_LEAF_SEP). An empty
/// leaf's hash is 0 by definition and never this function's output.
///
/// Total: ceil((W + 4) / 3) permutations and additions.
pub fn leaf_hash<let W: u32>(
    namespace: Field,
    key: Field,
    index: Field,
    leaf: [Field; W],
) -> Field {
    p2_hash_sep([namespace, key, index].concat(leaf), TIP_LEAF_SEP)
}

/// The hash of an internal node over its two children:
/// p2_hash_sep([left, right], TIP_NODE_SEP). Total: one permutation.
pub fn node(left: Field, right: Field) -> Field {
    p2_hash_sep([left, right], TIP_NODE_SEP)
}

/// The commitment of a tree under its root, what the key's slot holds:
/// p2_hash_sep([namespace, key, root], TIP_TREE_SEP). Total: two
/// permutations.
pub fn commitment(namespace: Field, key: Field, root: Field) -> Field {
    p2_hash_sep([namespace, key, root], TIP_TREE_SEP)
}

/// `[Z_0, ..., Z_D]`, the hashes of the empty subtrees of each height.
/// Constants: the compiler folds the permutations.
pub fn zeros<let D: u32>() -> [Field; D + 1] {
    let mut z = [0; D + 1];
    for l in 0..D {
        z[l + 1] = node(z[l], z[l]);
    }
    z
}

/// `Z_D`, the root of an empty tree of depth `D`.
pub fn empty_root<let D: u32>() -> Field {
    zeros::<D>()[D]
}

/// The root a leaf hash gives under `siblings` (bottom up) at the leaf
/// whose index has the little-endian bits `bits`. Total: D permutations
/// and selects.
fn path_root<let D: u32>(leaf: Field, siblings: [Field; D], bits: [bool; D]) -> Field {
    let mut at = leaf;
    for l in 0..D {
        at = node(
            select_field(bits[l], siblings[l], at),
            select_field(bits[l], at, siblings[l]),
        );
    }
    at
}

/// The residue of a loaded leaf against its old hash, zero in every element
/// exactly when the leaf matches: the leaf itself under old hash 0 (an
/// empty leaf is the zero vector), else 0 then the leaf's hash at `index`
/// minus `old_hash`. The select is on the public old hash; the caller
/// asserts every element zero (`load`, `Tree::window`). Total: one leaf
/// hash and the selects.
fn old_leaf_residue<let W: u32>(
    namespace: Field,
    key: Field,
    index: Field,
    leaf: [Field; W],
    old_hash: Field,
) -> [Field; W + 1] {
    let empty = is_zero(old_hash);
    let h = leaf_hash(namespace, key, index, leaf);
    let mut residue = [0; W + 1];
    for e in 0..W {
        residue[e] = select_field(empty, leaf[e], 0);
    }
    residue[W] = select_field(empty, 0, h - old_hash);
    residue
}

/// The little-endian bits of `index` below 2^D (all zero when it is not
/// below 2^D) and whether it is. Total: clamp_bits_or's flag (its hint
/// runs in co-noir) and a D-bit decomposition of the clamped value, which
/// fits by construction.
fn index_bits<let D: u32>(index: Field) -> ([bool; D], bool) {
    let (clamped, fits) = clamp_bits_or::<D>(index);
    // total-lint: allow std's to_le_bits of the clamped index, which is below 2^D by clamp_bits_or: hint-satisfiable for every Field
    (clamped.to_le_bits(), fits)
}

/// The positions of a leaf's path, `index >> l` for each height l < D, as
/// Fields: linear in the bits, no constraint of their own.
fn positions<let D: u32>(bits: [bool; D]) -> [Field; D] {
    let mut pos = [0; D];
    let mut above: Field = 0;
    for m in 0..D {
        let l = D - 1 - m;
        above = 2 * above + bits[l] as Field;
        pos[l] = above;
    }
    pos
}

/// A tree-valued key as a round loads it: `K` slots of its depth-`D` tree,
/// each a leaf of `W` elements.
pub struct Tree<let K: u32, let D: u32, let W: u32> {
    /// the namespace, PUBLIC $namespace
    pub namespace: Field,
    /// the key the round reads (its slot), which every leaf hash binds
    pub key: Field,
    /// the key the round writes, under which new_c commits (`writes_to`;
    /// the read key unless set)
    pub out_key: Field,
    /// each slot's old leaf, LOAD_LEAF (shared; zero for an empty leaf)
    pub leaves: [[Field; W]; K],
    /// each slot's old leaf hash, PUBLIC (0 for an empty leaf)
    pub old_hashes: [Field; K],
    /// each slot's siblings in the old tree, bottom up, PUBLIC
    pub siblings: [[Field; D]; K],
    /// each slot's leaf index, PUBLIC (0 in an unused slot)
    pub indices: [Field; K],
    /// whether the round uses slot k: k < n_used
    pub used: [bool; K],
    /// the old tree's root: the root of slot 0's path
    pub old_root: Field,
    /// commitment(namespace, key, old_root), the commitment the key's slot
    /// must hold (0 when the round creates the key: `empty`)
    pub old_c: Field,
    /// n_used is in 1..=K
    pub count_ok: bool,
    /// every used index is below 2^D; under `headed`, slot 0's index is 0
    /// and every other used slot's index is not
    pub in_range: bool,
    /// the used indices are pairwise distinct
    pub distinct: bool,
    /// every slot's path gives slot 0's root
    pub paths_ok: bool,
    /// the round creates the key (`empty`): a failed round leaves its slot
    /// empty
    pub creates: bool,
    /// slot 0 is the tree's header leaf 0 (`headed`): its index is fixed,
    /// not the request's
    header: bool,
    bits: [[bool; D]; K],
}

/// The slots of a loaded tree (above): `leaves` LOAD_LEAF, `old_hashes`,
/// `siblings` (bottom up) and `indices` PUBLIC from the nodes, `n_used`
/// the number of slots the round uses (slot k is used when k < n_used).
/// A tree whose slot 0 is its header leaf 0 takes `Tree::headed` after it.
///
/// The one assertion: each slot's old leaf matches its old hash. An old
/// hash of 0 (an empty leaf) requires the zero vector, any other the leaf's
/// hash at its index. The leaves are the nodes' shares and the old hashes
/// their clear trees, so a mismatch means a diverged store, never a bad
/// request: the scheduler places a real path of the loaded tree in every
/// slot, used or not, whatever the request names. The branch is a select
/// on the public old hash. Every other check is a flag the app's round turns
/// into its own code: `count_ok` (the count), `in_range` (below 2^D;
/// under `headed`, index 0 only in the header slot), `distinct` (no
/// index twice), `paths_ok` and `indices_match` (the nodes' placed paths
/// and indices). The first four are the tree's placement (`Tree::placed`),
/// which every update folds in itself; the app keeps them for its codes,
/// and adds a full tree (`new_leaf` 0 when opening), an opening slot
/// whose old hash is not 0 and an opening anywhere but at the append index
/// (`append`). A flagged round is a no-op that lands (new_c =
/// old_c), so a bad request never bricks the queue and the app's outcome
/// names the violation; it costs a full round, unless an intake's
/// `is_valid` that checks the same rules in the clear refuses it before it
/// is queued. Leaf indices are clear to the nodes: they see which leaves a
/// request touches (no oblivious access).
///
/// Constraints: K old-leaf hashes and W + 1 equalities per slot (the
/// assertion), K·D public path permutations, K clamp_bits_or::<D> range
/// flags with a D-bit decomposition each, one commitment, and equality
/// gadgets on public values: K for the paths, K for the count, about K²/2
/// for distinctness.
pub fn load<let K: u32, let D: u32, let W: u32>(
    namespace: Field,
    key: Field,
    leaves: [[Field; W]; K],
    old_hashes: [Field; K],
    siblings: [[Field; D]; K],
    indices: [Field; K],
    n_used: Field,
) -> Tree<K, D, W> {
    let used = used_slots::<K>(n_used);
    // a count in [1, K] uses slot 0
    let count_ok = used[0];

    let mut bits: [[bool; D]; K] = [[false; D]; K];
    let mut in_range = true;
    let mut roots = [0; K];
    for k in 0..K {
        let residue = old_leaf_residue(namespace, key, indices[k], leaves[k], old_hashes[k]);
        for e in 0..W + 1 {
            // total-lint: allow the old leaf is node-supplied (LOAD_LEAF and the nodes' clear tree): a mismatch is a diverged store, never a request's input
            assert(
                residue[e] == 0,
                "tip tree: a loaded leaf does not match its old hash (diverged store)",
            );
        }

        let (b, fits) = index_bits::<D>(indices[k]);
        bits[k] = b;
        roots[k] = path_root(old_hashes[k], siblings[k], b);
        in_range = in_range & (!used[k] | fits);
    }

    let old_root = roots[0];
    let mut paths_ok = true;
    let mut distinct = true;
    for k in 1..K {
        paths_ok = paths_ok & eq(roots[k], old_root);
        for j in 0..K {
            if j < k {
                distinct = distinct & !(used[j] & used[k] & eq(indices[j], indices[k]));
            }
        }
    }

    Tree {
        namespace,
        key,
        out_key: key,
        leaves,
        old_hashes,
        siblings,
        indices,
        used,
        old_root,
        old_c: commitment(namespace, key, old_root),
        count_ok,
        in_range,
        distinct,
        paths_ok,
        creates: false,
        header: false,
        bits,
    }
}

/// Which slots a round of `K` uses: slot k when k < n_used, none when the
/// count is outside [1, K]. Total: K equality gadgets on the public count.
pub fn used_slots<let K: u32>(n_used: Field) -> [bool; K] {
    let mut used = [false; K];
    for c in 1..K + 1 {
        let is_c = eq(n_used, c as Field);
        for k in 0..K {
            if k < c {
                used[k] = used[k] | is_c;
            }
        }
    }
    used
}

/// The tree a round creates at `key`: every slot an empty leaf of the
/// empty tree (zero leaves, old hashes 0, siblings Z_l), at the slots'
/// `indices` and `n_used` as in `load`. Its old_c is 0, the empty
/// slot's value, and so is the new_c of a failed round. The assertion and
/// the paths are on constants and fold.
pub fn empty<let K: u32, let D: u32, let W: u32>(
    namespace: Field,
    key: Field,
    indices: [Field; K],
    n_used: Field,
) -> Tree<K, D, W> {
    let z = zeros::<D>();
    let mut siblings = [[0; D]; K];
    for k in 0..K {
        for l in 0..D {
            siblings[k][l] = z[l];
        }
    }
    let mut t = load(
        namespace,
        key,
        [[0; W]; K],
        [0; K],
        siblings,
        indices,
        n_used,
    );
    t.creates = true;
    t.old_c = 0;
    t
}

/// The append rule of a tree whose leaves open in order and are never
/// reclaimed: `next_index`, the first leaf never written, which the app
/// keeps in its header leaf (1 when the tree is created: leaf 0 is the
/// header); `opens`, whether the round opens a leaf; `new_leaf`, the index
/// the scheduler assigned (`$new_leaf`). Returns whether the opening is at
/// the append index (true when the round opens nothing) and the append
/// index the header takes after the round (`next_index + 1` when it opens).
/// The app flags the first with a code of its own and writes the second
/// into its header; with `new_leaf` 0 for a full tree (its own code) and
/// the opening slot's old hash 0, the opened leaves are exactly
/// `1 .. next_index - 1`, so a scheduler, or every node, cannot open a leaf
/// past the end of the tree where an app's scan of the prefix never looks.
///
/// `next_index` needs no range check: an opening writes `new_leaf + 1` with
/// `new_leaf` a placed index below 2^D, so from 1 it stays in 1 ..= 2^D.
///
/// Total: one equality gadget (on a shared value when the header is
/// shared) and an addition.
pub fn append(next_index: Field, opens: bool, new_leaf: Field) -> (bool, Field) {
    (!opens | eq(new_leaf, next_index), next_index + opens as Field)
}

/// The low `D` bits of the canonical integer of `x`, `x mod 2^D`: what a
/// node takes as a shared index's or key's address (sidecar-oblivious
/// `indices_to_xor`, the low bits of the `a2b` conversion). Constraints:
/// total's `limbs` set (the canonical limbs, the low one below 2^128) and
/// one split of the low limb at bit `D` (RANGE D and RANGE 128 - D on the
/// hinted parts and the reconstruction), as total's `clamp_bits_or`
/// emits; the split is unique, so the result is determined. 1 <= D <= 127.
pub fn low_bits<let D: u32>(x: Field) -> Field {
    std::static_assert((D >= 1) & (D <= 127), "low_bits: D must be in 1..=127");
    let (lo, _) = limbs(x);
    // Safety: the range checks and the reconstruction below determine the
    // split of lo (< 2^128 by limbs) uniquely, and the honest hint meets them.
    let (low, rest) = unsafe { hint_split_low::<D>(lo) };
    // total-lint: allow the hinted split of the canonical low limb at bit D (RANGE D, RANGE 128 - D, the reconstruction): unique, and hint-satisfiable for every Field
    low.assert_max_bit_size::<D>();
    // total-lint: allow the hinted split of the canonical low limb at bit D (RANGE D, RANGE 128 - D, the reconstruction): unique, and hint-satisfiable for every Field
    rest.assert_max_bit_size::<128 - D>();
    // total-lint: allow the hinted split of the canonical low limb at bit D (RANGE D, RANGE 128 - D, the reconstruction): unique, and hint-satisfiable for every Field
    assert(lo == low + rest * two_pow::<D>(), "low_bits: the split does not recompose");
    low
}

/// Hint for low_bits: `(x mod 2^D, x / 2^D)` of `x < 2^128`, by a
/// remainder and quotient on the constant 2^D (total's
/// `hint_split_128_at` form: no integer And or Shr, which co-noir's MPC
/// VM cannot run on a shared value). Trap-free: the divisor is a nonzero
/// constant below 2^128.
unconstrained fn hint_split_low<let D: u32>(x: Field) -> (Field, Field) {
    let xi = x as u128;
    let p = two_pow::<D>() as u128;
    ((xi % p) as Field, (xi / p) as Field)
}

/// The effective indices of a round over a tree of depth `D` with `access:
/// oblivious` and a header, from the round's own inputs: slot 0 is the
/// header (leaf 0); entry slot `j` takes the low `D` bits of
/// `entries[j]` when used (`j < n_entries`), `new_leaf` in slot 1 when
/// `opens`, and 0 when unused. The nodes read exactly these slots (leaf 0
/// for the header and the unused slots, `$new_leaf` for an opening, the low
/// `D` bits of the shared input otherwise), so a round whose entry input
/// is not below 2^D still loads the paths the nodes read, its old leaves
/// match their old hashes and `load`'s one assertion holds; the round's own
/// range flag on the raw input (`fits_bits::<D>`) names the violation
/// and the round is a flagged no-op. Clamping to 0 instead would compose an
/// index the nodes did not read, and the old-leaf assertion would make such
/// a request unprovable. Total: P equality gadgets on the public count, P
/// `low_bits::<D>` and selects.
pub fn slot_indices<let P: u32, let D: u32>(
    entries: [Field; P],
    n_entries: Field,
    opens: bool,
    new_leaf: Field,
) -> [Field; P + 1] {
    let mut out = [0; P + 1];
    let used = used_slots::<P>(n_entries);
    for j in 0..P {
        let low = low_bits::<D>(entries[j]);
        let index = if j == 0 {
            select_field(opens, new_leaf, low)
        } else {
            low
        };
        out[j + 1] = select_field(used[j], index, 0);
    }
    out
}

/// The slots of a round as the nodes read them (three LOAD slices, or the
/// nodes' oblivious RAM reads under `access: oblivious`): each slot's leaf
/// (the zero leaf for an empty one), its old hash (0 there) and its `D`
/// siblings, lowest first. What a main hands `load` and `map::load`.
pub struct Slots<let K: u32, let D: u32, let W: u32> {
    pub leaves: [[Field; W]; K],
    pub old_hashes: [Field; K],
    pub siblings: [[Field; D]; K],
}

/// A window of `N` consecutive leaves of a loaded tree (`Tree::window`), read
/// and never written: the leaves at `start .. start + N - 1`.
pub struct Window<let N: u32, let W: u32> {
    /// the effective start: the request's when `aligned`, else 0
    pub start: Field,
    /// the request's start is below 2^D and a multiple of N
    pub aligned: bool,
    /// each window leaf, LOAD_LEAF (shared; zero for an empty leaf)
    pub leaves: [[Field; W]; N],
    /// each window leaf's old hash, PUBLIC (0 for an empty leaf)
    pub old_hashes: [Field; N],
    /// the window's old hashes and siblings give the tree's old root
    pub root_ok: bool,
}

/// What a round leaves at a tree-valued key.
pub struct Updated<let K: u32, let W: u32> {
    /// the `ok` the update took: when false nothing was written (a non-secret-shared
    /// round's outcome; a private round's placement, `Tree::update_private`)
    pub ok: bool,
    /// whether slot k was written: ok, used and the app's write
    pub write: [bool; K],
    /// each slot's leaf hash after the round (the old hash where not
    /// written), a public output the nodes rebuild the new tree from
    pub new_hashes: [Field; K],
    /// each slot's leaf to store: the new leaf where written, the old one
    /// otherwise
    pub stored: [[Field; W]; K],
    /// the tree's root after the round (the old root when not ok)
    pub new_root: Field,
    /// the commitment of the loaded tree (`Tree::old_c`)
    pub old_c: Field,
    /// commitment(namespace, out_key, new_root) when ok; when not, the
    /// written slot's current value: old_c when the round reads the key it
    /// writes, 0 for a create or a write to another key
    pub new_c: Field,
}

/// What a round leaves at a tree-valued key with `access: oblivious`
/// (docs/ARCHITECTURE.md section 6, "The oblivious tree", "The circuit"): the
/// update and each slot's new path nodes (`Tree::update_paths`). The machine
/// stores per slot the leaf, its new hash and its `D` path nodes
/// (`Updated::store_oblivious`), which the nodes write into their oblivious RAM
/// at the next session's start. Its `T` public leaf hashes are zeros (a hash
/// that stayed would show which rounds touch one leaf): `T = K` keeps the clear
/// deployment's layout with zero hashes, `T = 0` outputs none.
pub struct Oblivious<let K: u32, let W: u32, let D: u32, let T: u32> {
    pub updated: Updated<K, W>,
    pub paths: [[Field; D]; K],
}

impl<let K: u32, let D: u32, let W: u32> Tree<K, D, W> {
    /// The tree with new_c committed under `out_key`, the slot the round
    /// writes (its out_slots entry; the read key unless set). Leaf hashes
    /// stay bound to the read key. No constraint.
    pub fn writes_to(self, out_key: Field) -> Self {
        let mut t = self;
        t.out_key = out_key;
        t
    }

    /// The tree with slot 0 its header leaf 0: `in_range` also requires slot
    /// 0's index to be 0 and every other used slot's not, so no request
    /// writes the header through an entry slot. Total: K equality gadgets
    /// on public values.
    pub fn headed(self) -> Self {
        let mut t = self;
        t.header = true;
        for k in 0..K {
            let entry_ok = if k == 0 {
                is_zero(t.indices[k])
            } else {
                !is_zero(t.indices[k])
            };
            t.in_range = t.in_range & (!t.used[k] | entry_ok);
        }
        t
    }

    /// The tree's own placement: the count is in range, every used index is
    /// in range (under `headed`, the header at 0 and no entry there), the
    /// used indices are distinct and every path gives slot 0's root. Every
    /// update ANDs it into its `ok` (`update_paths`): two used slots on one
    /// index, or a path off the loaded root, would commit a root the nodes'
    /// rebuild does not give. Total: three ANDs.
    pub fn placed(self) -> bool {
        self.count_ok & self.in_range & self.distinct & self.paths_ok
    }

    /// Whether the slots' indices are the ones the app's inputs give:
    /// `expected[k]` in every used slot, 0 in every unused one. Total: K
    /// equality gadgets on public values.
    pub fn indices_match(self, expected: [Field; K]) -> bool {
        let mut m = true;
        for k in 0..K {
            m = m & eq(self.indices[k], select_field(self.used[k], expected[k], 0));
        }
        m
    }

    /// The window of `N = 2^H` consecutive leaves at `start` that a scan
    /// round reads (the manifest's `window` form of the tree entry), bound to
    /// this tree: `leaves` LOAD_LEAF (shared), `old_hashes` and `siblings`
    /// (the window root's `S = D - H` siblings, bottom up) PUBLIC from the
    /// nodes. No window leaf carries a path of its own: the window's subtree
    /// root is rebuilt from the `N` public old hashes and taken up the `S`
    /// siblings to the root, which must be this tree's old root (slot 0's).
    ///
    /// The window is placed at the effective start: `start` when it is below
    /// 2^D and a multiple of `N`, else 0 (`Window::aligned` false), the start
    /// the nodes derive from the clear request alike, so a bad request still
    /// loads real leaves and the round flags it. Each window leaf is checked
    /// against its old hash as `load` checks a slot (the one assertion, on
    /// node-supplied data); `root_ok` is a flag for the app's code.
    ///
    /// Constraints: N old-leaf hashes and L + 1 equalities each (the
    /// assertion), N - 1 node permutations and S path permutations over
    /// public values, one clamp_bits_or::<D> flag with a D-bit decomposition
    /// on the public start, one equality.
    pub fn window<let N: u32, let H: u32, let S: u32>(
        self,
        start: Field,
        leaves: [[Field; W]; N],
        old_hashes: [Field; N],
        siblings: [Field; S],
    ) -> Window<N, W> {
        std::static_assert(N == (1 << H), "a window holds 2^H leaves");
        std::static_assert(H + S == D, "a window root has D - H siblings");
        let (bits, fits) = index_bits::<D>(start);
        let mut aligned = fits;
        for l in 0..H {
            aligned = aligned & !bits[l];
        }
        let at = select_field(aligned, start, 0);
        let mut level = [0; N];
        for j in 0..N {
            let index = at + j as Field;
            let residue =
                old_leaf_residue(self.namespace, self.key, index, leaves[j], old_hashes[j]);
            for e in 0..W + 1 {
                // total-lint: allow the window leaf is node-supplied (LOAD_LEAF and the nodes' clear tree): a mismatch is a diverged store, never a request's input
                assert(
                    residue[e] == 0,
                    "tip tree: a loaded window leaf does not match its old hash (diverged store)",
                );
            }
            level[j] = old_hashes[j];
        }
        for l in 0..H {
            for p in 0..N {
                if p < (N >> (l + 1)) {
                    level[p] = node(level[2 * p], level[2 * p + 1]);
                }
            }
        }
        let mut above = [false; S];
        for l in 0..S {
            above[l] = aligned & bits[H + l];
        }
        let root = path_root(level[0], siblings, above);
        Window { start: at, aligned, leaves, old_hashes, root_ok: eq(root, self.old_root) }
    }

    /// The round's writes: slot k takes `new_leaves[k]` when ok, the tree
    /// is placed (`placed`), the slot is used and `writes[k]` (ok and writes
    /// may be shared), with its new leaf hash; the root is rebuilt path by path in slot order over the
    /// used slots. At height l, path k's sibling is the recomputed node of
    /// the latest earlier used path j < k whose position at height l is
    /// path k's sibling position, else its old sibling; the root is the
    /// last used path's top node. On !ok (or not placed) the root, the
    /// hashes and the leaves stay and new_c is the written slot's current
    /// value (`Updated::new_c`).
    ///
    /// Constraints: K new-leaf hashes, K·D shared permutations (the new
    /// paths), K·(K - 1)/2·D equality gadgets on public positions, the
    /// selects, one commitment, the placement's ANDs.
    pub fn update(self, ok: bool, writes: [bool; K], new_leaves: [[Field; W]; K]) -> Updated<K, W> {
        let (u, _) = self.update_paths(ok, writes, new_leaves);
        u
    }

    /// `update`, and each slot's new path nodes of heights 1 to `D` (the root
    /// last), as the oblivious tree's nodes write them into their oblivious RAM
    /// (docs/ARCHITECTURE.md section 6, "The oblivious tree", "The circuit"):
    /// the recomputed node at each height, which for a slot the round does not
    /// write is its old node, since its hash and siblings are unchanged.
    /// Constraints: `update`'s.
    pub fn update_paths(
        self,
        ok: bool,
        writes: [bool; K],
        new_leaves: [[Field; W]; K],
    ) -> (Updated<K, W>, [[Field; D]; K]) {
        let (ok, write) = self.write_flags(ok, writes);
        let mut new_hashes = [0; K];
        let mut stored = [[0; W]; K];
        for k in 0..K {
            let h = leaf_hash(self.namespace, self.key, self.indices[k], new_leaves[k]);
            new_hashes[k] = select_field(write[k], h, self.old_hashes[k]);
            for e in 0..W {
                stored[k][e] = select_field(write[k], new_leaves[k][e], self.leaves[k][e]);
            }
        }

        let mut pos = [[0; D]; K];
        for k in 0..K {
            pos[k] = positions(self.bits[k]);
        }
        // nodes[k][l]: path k's recomputed node at height l (its leaf at 0);
        // paths[k][l]: its node at height l + 1 (the root last)
        let mut nodes = [[0; D]; K];
        let mut paths = [[0; D]; K];
        let mut root = self.old_root;
        for k in 0..K {
            let mut at = new_hashes[k];
            for l in 0..D {
                nodes[k][l] = at;
                let b = self.bits[k][l];
                // path k's sibling position at height l: pos ^ 1
                let sibling_pos = pos[k][l] + 1 - 2 * (b as Field);
                let mut sibling = self.siblings[k][l];
                for j in 0..K {
                    if j < k {
                        let meets = self.used[j] & eq(pos[j][l], sibling_pos);
                        sibling = select_field(meets, nodes[j][l], sibling);
                    }
                }
                at = node(select_field(b, sibling, at), select_field(b, at, sibling));
                paths[k][l] = at;
            }
            root = select_field(self.used[k], at, root);
        }

        let new_root = select_field(ok, root, self.old_root);
        let kept = select_field(!self.creates & eq(self.key, self.out_key), self.old_c, 0);
        let new_c = select_field(ok, commitment(self.namespace, self.out_key, root), kept);
        (Updated { ok, write, new_hashes, stored, new_root, old_c: self.old_c, new_c }, paths)
    }

    /// The round's writes under private outcomes (the secret-shared intakes),
    /// under the round's write policy `reblind`, one flag per slot (a
    /// constant of the round: the selects on it fold). A slot whose flag is
    /// set is re-blinded on every outcome, so its new leaf hash tells the
    /// nodes and the chain nothing of `ok` (docs/ARCHITECTURE.md section 6,
    /// "Private outcomes"; the twin of `slot::Loaded::finish_private`); a
    /// slot whose flag is clear is written only where the round writes it
    /// and otherwise keeps its leaf and its hash. The last element of a leaf
    /// is its blinding.
    ///
    /// `opened` is the intake's binding: whether C opens to the request's
    /// inputs (`intake::SharedIntake::opens`). The round writes slot k
    /// (`new_leaves[k]`) only where opened, ok and `writes[k]`, so no app
    /// lands the effect of inputs nobody committed, whatever its `ok`. When
    /// placed (the app's `placed`, its placement checks on public data, and
    /// the tree's own, `Tree::placed`), every used slot that holds a leaf
    /// and is re-blinded under the policy is written: its new leaf where the
    /// round writes it, else the old leaf, each under its fresh blinding
    /// `r_new[k]`; an empty slot is written only where the round writes it
    /// (re-blinding it would create a leaf). When not opened the slots'
    /// indices are unbound witnesses (the prover chose them), so the policy
    /// re-blinds the header alone (`headed`: its index is fixed), never an
    /// entry slot, which would replace a leaf its owner did not ask for
    /// (`private_writes`). When not
    /// placed nothing is written, as on the non-secret-shared path: the nodes
    /// know that case from public data.
    ///
    /// The policy is the app's: a round re-blinds the slots whose outcome
    /// it hides (a requester's own leaf, a header), and leaves a slot it
    /// touched on someone else's behalf and did not change, so that slot's
    /// leaf stays as its owner's latest note reports it (with
    /// `update_private_tagged`, its exit tag unspent: super::exit). A slot
    /// left that way shows one node, which sees the indices, that the round
    /// did not write it; its `new_hashes` entry is its old hash, which the
    /// nodes' rebuild takes as no change. Lending's liquidation is the worked
    /// example (examples/lending-tip/README.md, "The escape
    /// hatch", "The liquidation's write rule").
    ///
    /// A slot re-blinded without the round's write keeps `kept[k]` (its
    /// blinding replaced): the loaded leaves (`self.leaves`) for most
    /// rounds, or, for a round that changes a part of the leaf on every
    /// outcome that re-blinds it, the leaves with that part changed, e.g.
    /// the request's delivery handle (super::handle), which the requester's
    /// own entry takes whether or not the round applied. A slot that is not
    /// written keeps its loaded leaf and hash whatever `kept` says. Returns
    /// the update and each slot's new path nodes (`update_paths`).
    ///
    /// Constraints: `update`'s, K equality gadgets on the public old hashes,
    /// two ANDs per slot, the selects.
    pub fn update_private(
        self,
        placed: bool,
        opened: bool,
        ok: bool,
        writes: [bool; K],
        reblind: [bool; K],
        new_leaves: [[Field; W]; K],
        kept: [[Field; W]; K],
        r_new: [Field; K],
    ) -> (Updated<K, W>, [[Field; D]; K]) {
        let (lands, written) = self.private_writes(opened, ok, writes, reblind);
        self.write_private(placed, lands, written, new_leaves, kept, r_new)
    }

    /// Whether slot k may hold an entry: every slot but a `headed` tree's
    /// slot 0, the header leaf. No constraint: `headed` is a constant of
    /// the round.
    pub(crate) fn entry_slot(self, k: u32) -> bool {
        !(self.header & (k == 0))
    }

    /// The private updates' write rule, before the placement: slot k lands
    /// the round's leaf where opened, ok and `writes[k]` (`lands`), and is
    /// written where it lands or where the policy re-blinds it, it holds a
    /// leaf and its index is bound (`written`). When the shares do not open C
    /// only a slot that holds no entry (the header, whose index is fixed) is
    /// bound, so such a round writes no entry slot: the prover chose the
    /// indices. Total: K equality gadgets on the old hashes and the ANDs.
    pub(crate) fn private_writes(
        self,
        opened: bool,
        ok: bool,
        writes: [bool; K],
        reblind: [bool; K],
    ) -> ([bool; K], [bool; K]) {
        let mut lands = [false; K];
        let mut written = [false; K];
        for k in 0..K {
            lands[k] = opened & ok & writes[k];
            let bound = opened | !self.entry_slot(k);
            written[k] = lands[k] | (reblind[k] & bound & !is_zero(self.old_hashes[k]));
        }
        (lands, written)
    }

    /// The slots an update writes (`update_paths`): `ok` with the tree's
    /// placement (`placed`), and per slot that, the slot used and the
    /// app's write. One source for the update and for a rule that must agree
    /// with what it writes (super::exit). Total: the ANDs.
    pub(crate) fn write_flags(self, ok: bool, writes: [bool; K]) -> (bool, [bool; K]) {
        let ok = ok & self.placed();
        let mut write = [false; K];
        for k in 0..K {
            write[k] = ok & self.used[k] & writes[k];
        }
        (ok, write)
    }

    /// The private updates' write: slot k takes `new_leaves[k]` where
    /// `lands[k]`, else `kept[k]`, under its fresh blinding `r_new[k]` (the
    /// leaf's last element), and is written where `written[k]`
    /// (`update_paths` under `placed`). One source for `update_private`,
    /// `update_private_tagged` and the keyed map's `Map::update_private`.
    /// Total: the selects.
    pub(crate) fn write_private(
        self,
        placed: bool,
        lands: [bool; K],
        written: [bool; K],
        new_leaves: [[Field; W]; K],
        kept: [[Field; W]; K],
        r_new: [Field; K],
    ) -> (Updated<K, W>, [[Field; D]; K]) {
        let mut leaves = [[0; W]; K];
        for k in 0..K {
            for e in 0..W - 1 {
                leaves[k][e] = select_field(lands[k], new_leaves[k][e], kept[k][e]);
            }
            leaves[k][W - 1] = r_new[k];
        }
        self.update_paths(placed, written, leaves)
    }
}

/// What a round leaves at a tree-valued key, one implementation per tree
/// access (the key's `access` in the manifest): `Updated` under `access:
/// clear`, `Oblivious` under `access: oblivious`. A round's write
/// (`TreeChange`, `super::exit::TaggedChange`) leaves the form its result
/// type names.
pub trait Access<let K: u32, let D: u32, let W: u32> {
    /// The access's form of an update and each slot's new path nodes
    /// (`Tree::update_paths`). No constraint.
    fn of(updated: Updated<K, W>, paths: [[Field; D]; K]) -> Self;
    /// The slots as written: the stored leaves and their new hashes.
    fn updated(self) -> Updated<K, W>;
}

impl<let K: u32, let D: u32, let W: u32> Access<K, D, W> for Updated<K, W> {
    fn of(updated: Updated<K, W>, _paths: [[Field; D]; K]) -> Self {
        updated
    }

    fn updated(self) -> Updated<K, W> {
        self
    }
}

impl<let K: u32, let D: u32, let W: u32, let T: u32> Access<K, D, W> for Oblivious<K, W, D, T> {
    fn of(updated: Updated<K, W>, paths: [[Field; D]; K]) -> Self {
        Oblivious { updated, paths }
    }

    fn updated(self) -> Updated<K, W> {
        self.updated
    }
}

/// A write to a tree-valued key in either family's form (`super::family::
/// Change`): `Tree::update` under a public outcome, `Tree::update_private`
/// under a private one, left in the access's form (`Access`). The app's
/// round function makes it with `Tree::change`, and may adjust a field
/// before handing it to `family::Checked::write` (a placement known only
/// later, a part of a leaf every outcome writes). `placed` and `reblind`
/// are read by the private form only: under a public outcome the app's
/// placement is part of `ok`, and nothing is re-blinded.
pub struct TreeChange<let K: u32, let D: u32, let W: u32> {
    pub tree: Tree<K, D, W>,
    pub placed: bool,
    pub ok: bool,
    pub writes: [bool; K],
    pub reblind: [bool; K],
    pub new_leaves: [[Field; W]; K],
    pub kept: [[Field; W]; K],
    pub r_new: [Field; K],
}

impl<let K: u32, let D: u32, let W: u32> Tree<K, D, W> {
    /// The write of `new_leaves` under `ok` and `writes`, with the private
    /// form's placement `placed`, write policy `reblind`, re-blinded leaves
    /// `kept` and blindings `r_new` (`update_private`'s arguments), in the
    /// form the round's intake family picks (`TreeChange`). No constraint.
    pub fn change(
        self,
        placed: bool,
        ok: bool,
        writes: [bool; K],
        reblind: [bool; K],
        new_leaves: [[Field; W]; K],
        kept: [[Field; W]; K],
        r_new: [Field; K],
    ) -> TreeChange<K, D, W> {
        TreeChange { tree: self, placed, ok, writes, reblind, new_leaves, kept, r_new }
    }
}

impl<S, let K: u32, let D: u32, let W: u32> Change<S> for TreeChange<K, D, W>
where
    S: Access<K, D, W>,
{
    fn plain(self) -> S {
        let (updated, paths) = self.tree.update_paths(self.ok, self.writes, self.new_leaves);
        S::of(updated, paths)
    }

    fn private(self, opened: bool) -> S {
        let (updated, paths) = self.tree.update_private(
            self.placed,
            opened,
            self.ok,
            self.writes,
            self.reblind,
            self.new_leaves,
            self.kept,
            self.r_new,
        );
        S::of(updated, paths)
    }
}

impl<let K: u32, let W: u32> Updated<K, W> {
    /// Hand the stored leaves to the machine as TACEO_store("out<j>"), the
    /// K·W elements slot after slot, j the key's position in the round's
    /// out_slots (a constant; mpc_store's key convention).
    pub fn store(self, j: u32) {
        let mut flat = [0; K * W];
        for k in 0..K {
            for e in 0..W {
                flat[k * W + e] = self.stored[k][e];
            }
        }
        // Safety: side-effect-only oracle (mpc_store); the nodes keep the
        // stored leaves' shares, which new_hashes and new_c commit to
        unsafe { mpc_store::store_out(j, flat) };
    }

    /// Hand an oblivious tree's stored vector to the machine as
    /// TACEO_store("out<j>"): per slot its stored leaf, its new leaf hash
    /// and its `D` new path nodes (`Tree::update_paths`), the `K · (W + 1 +
    /// D)` elements slot after slot, which the nodes write into their
    /// oblivious RAM at the slot's write addresses
    /// (docs/ARCHITECTURE.md section 6, "The oblivious tree", "The round").
    pub fn store_oblivious<let D: u32>(self, paths: [[Field; D]; K], j: u32) {
        let mut flat = [0; K * (W + 1 + D)];
        for k in 0..K {
            let base = k * (W + 1 + D);
            for e in 0..W {
                flat[base + e] = self.stored[k][e];
            }
            flat[base + W] = self.new_hashes[k];
            for l in 0..D {
                flat[base + W + 1 + l] = paths[k][l];
            }
        }
        // Safety: side-effect-only oracle (mpc_store); the nodes keep the
        // shares, which new_c commits to through the root
        unsafe { mpc_store::store_out(j, flat) };
    }
}

mod tests {
    use super::{
        append, commitment, empty, empty_root, leaf_hash, load, low_bits, node, slot_indices,
        TIP_LEAF_SEP, TIP_NODE_SEP, TIP_TREE_SEP, Tree, zeros,
    };
    use total::hash::p2_hash;
    use crate::test_support::ascii;

    global NS: Field = 0x7196;
    global KEY: Field = 0xa003;
    global D: u32 = 3;

    /// `test_support::full` over this module's namespace and key.
    fn full<let F: u32, let K: u32>(
        filled: [(Field, [Field; 2]); F],
        at: [Field; K],
    ) -> (Field, [Field; K], [[Field; D]; K], [[Field; 2]; K]) {
        crate::test_support::full(NS, KEY, filled, at)
    }

    fn book() -> [(Field, [Field; 2]); 4] {
        [(0, [100, 7]), (1, [10, 8]), (2, [20, 9]), (5, [50, 10])]
    }

    fn loaded(at: [Field; 3], n_used: Field) -> Tree<3, D, 2> {
        let (_, hashes, siblings, leaves) = full(book(), at);
        load(NS, KEY, leaves, hashes, siblings, at, n_used).headed()
    }

    #[test]
    fn the_labels_are_the_dotted_ascii_bytes() {
        assert_eq(TIP_LEAF_SEP, ascii("pss.tip.leaf"));
        assert_eq(TIP_NODE_SEP, ascii("pss.tip.node"));
        assert_eq(TIP_TREE_SEP, ascii("pss.tip.tree"));
        // the layouts: the separator first
        assert_eq(node(1, 2), p2_hash([TIP_NODE_SEP, 1, 2]));
        assert_eq(leaf_hash(NS, KEY, 3, [4, 5]), p2_hash([TIP_LEAF_SEP, NS, KEY, 3, 4, 5]));
        assert_eq(commitment(NS, KEY, 9), p2_hash([TIP_TREE_SEP, NS, KEY, 9]));
    }

    #[test]
    fn zeros_are_the_empty_subtrees() {
        let z = zeros::<D>();
        assert_eq(z[0], 0);
        assert_eq(z[1], node(0, 0));
        assert_eq(z[3], node(z[2], z[2]));
        assert_eq(empty_root::<D>(), z[3]);
        let (root, _, _, _) = full([], [0]);
        assert_eq(root, z[3]);
    }

    #[test]
    fn a_loaded_tree_checks_its_paths_and_flags() {
        let (root, _, _, _) = full(book(), [0]);
        let t = loaded([0, 1, 5], 3);
        assert_eq(t.old_root, root);
        assert_eq(t.old_c, commitment(NS, KEY, root));
        assert(t.count_ok & t.in_range & t.distinct & t.paths_ok);
        assert_eq(t.used, [true, true, true]);
        assert(t.indices_match([0, 1, 5]));
        assert(!t.indices_match([0, 1, 4]));
        // every slot's path gives the root: slot 2's at index 5 too
        let mut moved = t.siblings;
        moved[2][0] = moved[2][0] + 1;
        assert(!load(NS, KEY, t.leaves, t.old_hashes, moved, t.indices, 3).paths_ok);
    }

    #[test]
    fn shared_ancestors_take_the_latest_earlier_path() {
        // indices 0, 1, 2: path 2's sibling at height 1 is position 0, which
        // paths 0 and 1 both pass through; only path 1's node there holds
        // both new leaves
        let t = loaded([0, 1, 2], 3);
        let new_leaves = [[130, 21], [11, 22], [21, 23]];
        let u = t.update(true, [true, true, true], new_leaves);
        let filled = [(0, [130, 21]), (1, [11, 22]), (2, [21, 23]), (5, [50, 10])];
        let (root, _, _, _) = full(filled, [0]);
        assert_eq(u.new_root, root);
        assert_eq(u.new_c, commitment(NS, KEY, root));
        assert_eq(u.new_hashes[1], leaf_hash(NS, KEY, 1, [11, 22]));
        assert_eq(u.stored, new_leaves);
        // the earliest path's node there is stale: rebuilding with it differs
        let stale = node(
            node(
                node(u.new_hashes[0], t.old_hashes[1]),
                node(u.new_hashes[2], 0),
            ),
            t.siblings[2][2],
        );
        assert(stale != root);
    }

    #[test]
    fn a_private_update_re_blinds_every_held_leaf() {
        // slot 2 names index 3, an empty leaf
        let t = loaded([0, 1, 3], 3);
        let new_leaves = [[130, 0], [11, 0], [33, 0]];
        let r_new = [31, 32, 33];
        // ok: the round's leaves land under the fresh blindings, the empty
        // slot opens
        let u = t.update_private(true, true, true, [true, true, true], [true; 3], new_leaves, t.leaves, r_new).0;
        assert(u.ok);
        assert_eq(u.write, [true, true, true]);
        assert_eq(u.stored, [[130, 31], [11, 32], [33, 33]]);
        // not ok: every held leaf keeps its value under its fresh blinding,
        // and the empty slot stays empty
        let f = t.update_private(true, true, false, [true, true, true], [true; 3], new_leaves, t.leaves, r_new).0;
        assert_eq(f.write, [true, true, false]);
        assert_eq(f.stored, [[100, 31], [10, 32], [0, 0]]);
        assert_eq(f.new_hashes[1], leaf_hash(NS, KEY, 1, [10, 32]));
        assert(f.new_c != t.old_c);
        // not placed: nothing is written
        let n = t.update_private(false, true, true, [true, true, true], [true; 3], new_leaves, t.leaves, r_new).0;
        assert(!n.ok);
        assert_eq(n.write, [false, false, false]);
        assert_eq(n.new_c, t.old_c);
    }

    #[test]
    fn a_re_blinded_slot_keeps_what_the_round_says_and_an_unwritten_one_its_leaf() {
        // the header and position 1 re-blinded on every outcome, the round
        // keeping 7 in place of position 1's value when it does not apply;
        // position 5 left unless written
        let t = loaded([0, 1, 5], 3);
        let new_leaves = [[130, 0], [11, 0], [55, 0]];
        let kept = [[100, 0], [7, 0], [77, 0]];
        let r_new = [31, 32, 33];
        let policy = [true, true, false];
        // ok: the round's leaves land, whatever is kept
        let u = t.update_private(true, true, true, [true, true, false], policy, new_leaves, kept, r_new).0;
        assert_eq(u.stored, [[130, 31], [11, 32], [50, 10]]);
        // not ok: the re-blinded slot takes what is kept, the left slot its
        // loaded leaf and hash, never what is kept for it
        let f = t.update_private(true, true, false, [true, true, true], policy, new_leaves, kept, r_new).0;
        assert_eq(f.write, [true, true, false]);
        assert_eq(f.stored, [[100, 31], [7, 32], [50, 10]]);
        assert_eq(f.new_hashes[1], leaf_hash(NS, KEY, 1, [7, 32]));
        assert_eq(f.new_hashes[2], t.old_hashes[2]);
    }

    #[test]
    fn a_slot_the_policy_leaves_keeps_its_leaf_and_hash_unless_written() {
        // the header re-blinded, positions 1 and 5 left unless written (a
        // round on others' leaves that writes 5 and leaves 1 unchanged, as
        // lending's liquidation does with a healthy probe)
        let t = loaded([0, 1, 5], 3);
        let new_leaves = [[130, 0], [11, 0], [55, 0]];
        let r_new = [31, 32, 33];
        let policy = [true, false, false];
        let u = t.update_private(true, true, true, [true, false, true], policy, new_leaves, t.leaves, r_new).0;
        assert_eq(u.write, [true, false, true]);
        assert_eq(u.stored, [[130, 31], [10, 8], [55, 33]]);
        assert_eq(u.new_hashes[1], t.old_hashes[1]);
        assert_eq(u.new_hashes[2], leaf_hash(NS, KEY, 5, [55, 33]));
        let (root, _, _, _) = full([(0, [130, 31]), (1, [10, 8]), (2, [20, 9]), (5, [55, 33])], [0]);
        assert_eq(u.new_root, root);
        // not ok: the header is re-blinded, the left slots keep their hashes
        let f = t.update_private(true, true, false, [true, true, true], policy, new_leaves, t.leaves, r_new).0;
        assert_eq(f.write, [true, false, false]);
        assert_eq(f.new_hashes[1], t.old_hashes[1]);
        assert_eq(f.new_hashes[2], t.old_hashes[2]);
        assert_eq(f.stored[0], [100, 31]);
        assert(f.new_c != t.old_c);
    }

    #[test]
    fn a_duplicate_index_is_flagged() {
        let t = loaded([0, 2, 2], 3);
        assert(!t.distinct);
        assert(t.paths_ok & t.in_range);
        // past the count it is not
        assert(loaded([0, 2, 0], 2).distinct);
    }

    // The tree's placement is folded into every update, whatever ok the app
    // passes: two used slots on one index (only the later's write would reach
    // the root, while the machine is handed two leaves for one index), a path
    // off slot 0's root, a count out of range or an entry at the header
    // write nothing and keep the commitment.
    #[test]
    fn an_update_writes_nothing_unless_the_tree_is_placed() {
        let leaves = [[1, 2], [3, 4], [5, 6]];
        let r_new = [31, 32, 33];
        let twice = loaded([0, 2, 2], 3);
        assert(!twice.placed());
        let u = twice.update(true, [true; 3], leaves);
        assert(!u.ok);
        assert_eq(u.write, [false; 3]);
        assert_eq(u.new_c, twice.old_c);
        let p = twice.update_private(true, true, true, [true; 3], [true; 3], leaves, twice.leaves, r_new).0;
        assert_eq(p.write, [false; 3]);
        assert_eq(p.new_c, twice.old_c);
        // the other flags alike
        let (_, hashes, mut siblings, l) = full(book(), [0, 1, 2]);
        siblings[2][1] = siblings[2][1] + 1;
        let off = load(NS, KEY, l, hashes, siblings, [0, 1, 2], 3).headed();
        assert_eq(off.update(true, [true; 3], leaves).new_c, off.old_c);
        assert_eq(loaded([0, 0, 0], 4).update(true, [true; 3], leaves).write, [false; 3]);
        let header_twice = loaded([0, 0, 2], 3);
        assert(!header_twice.placed());
        assert_eq(header_twice.update(true, [true; 3], leaves).new_c, header_twice.old_c);
        // a placed tree is written
        assert(loaded([0, 1, 2], 3).placed());
        assert(loaded([0, 1, 2], 3).update(true, [true; 3], leaves).ok);
    }

    // Shares that do not open C: nothing lands, whatever ok and writes say,
    // and the policy re-blinds the header alone (its index is fixed), never an
    // entry slot, whose index the prover chose; the commitment still
    // changes. Without a header no slot is bound, and nothing is written.
    #[test]
    fn an_unopened_round_lands_nothing_and_re_blinds_the_header_alone() {
        let t = loaded([0, 1, 3], 3);
        let new_leaves = [[130, 0], [11, 0], [33, 0]];
        let r_new = [31, 32, 33];
        let u = t.update_private(true, false, true, [true; 3], [true; 3], new_leaves, t.leaves, r_new).0;
        assert(u.ok);
        assert_eq(u.write, [true, false, false]);
        assert_eq(u.stored, [[100, 31], [10, 8], [0, 0]]);
        assert_eq(u.new_hashes[1], t.old_hashes[1]);
        assert_eq(u.new_hashes[2], 0);
        assert(u.new_c != t.old_c);
        // the kept form alike: a re-blinded header takes what is kept
        let kept = [[101, 0], [7, 0], [77, 0]];
        let k = t.update_private(true, false, true, [true; 3], [true; 3], new_leaves, kept, r_new).0;
        assert_eq(k.stored, [[101, 31], [10, 8], [0, 0]]);
        // an unheaded tree: every index is the request's
        let (_, hashes, siblings, leaves) = full(book(), [1, 2, 5]);
        let n = load(NS, KEY, leaves, hashes, siblings, [1, 2, 5], 3);
        let w = n.update_private(true, false, true, [true; 3], [true; 3], new_leaves, n.leaves, r_new).0;
        assert_eq(w.write, [false; 3]);
        assert_eq(w.new_c, n.old_c);
    }

    #[test]
    fn index_0_in_an_entry_slot_is_flagged() {
        let t = loaded([0, 0, 2], 3);
        assert(!t.in_range);
        assert(!t.distinct);
        // the header's slot must be leaf 0
        let (_, hashes, siblings, leaves) = full(book(), [1, 2, 5]);
        let h = load(NS, KEY, leaves, hashes, siblings, [1, 2, 5], 3).headed();
        assert(!h.in_range);
        assert(h.paths_ok);
        // without a header any index below 2^D is in range
        let n = load(NS, KEY, leaves, hashes, siblings, [1, 2, 5], 3);
        assert(n.in_range);
    }

    #[test]
    fn an_index_out_of_range_is_flagged() {
        let (_, hashes, siblings, leaves) = full(book(), [0, 1, 2]);
        let t = load(NS, KEY, leaves, hashes, siblings, [0, 1, 2], 3).headed();
        assert(t.in_range);
        // 9 is not below 2^3 (the slot carries the empty leaf 3's path)
        let (_, h0, s0, l0) = full(book(), [0, 1, 3]);
        let u = load(NS, KEY, l0, h0, s0, [0, 1, 9], 3).headed();
        assert(!u.in_range);
    }

    #[test]
    fn the_count_selects_the_used_slots() {
        assert_eq(loaded([0, 1, 0], 2).used, [true, true, false]);
        assert(loaded([0, 1, 0], 2).count_ok);
        let none = loaded([0, 0, 0], 0);
        assert(!none.count_ok);
        assert_eq(none.used, [false, false, false]);
        assert(!loaded([0, 0, 0], 4).count_ok);
        assert(loaded([0, 0, 0], 4).indices_match([7, 8, 9]));
    }

    #[test]
    fn a_short_count_skips_unused_slots() {
        // slot 2 carries leaf 0's path at index 0 and is not written
        let t = loaded([0, 1, 0], 2);
        let u = t.update(true, [true, true, true], [[1, 2], [3, 4], [5, 6]]);
        assert_eq(u.write, [true, true, false]);
        assert_eq(u.stored[2], [100, 7]);
        assert_eq(u.new_hashes[2], t.old_hashes[2]);
        let (root, _, _, _) = full([(0, [1, 2]), (1, [3, 4]), (2, [20, 9]), (5, [50, 10])], [0]);
        assert_eq(u.new_root, root);
    }

    #[test]
    fn an_unwritten_used_slot_keeps_its_leaf() {
        let t = loaded([0, 1, 5], 3);
        let u = t.update(true, [true, false, true], [[1, 2], [3, 4], [5, 6]]);
        assert_eq(u.stored[1], [10, 8]);
        assert_eq(u.new_hashes[1], t.old_hashes[1]);
        let (root, _, _, _) = full([(0, [1, 2]), (1, [10, 8]), (2, [20, 9]), (5, [5, 6])], [0]);
        assert_eq(u.new_root, root);
    }

    #[test]
    fn an_empty_leaf_is_checked_as_a_zero_vector() {
        // leaf 3 is empty: old hash 0 and a zero leaf
        let t = loaded([0, 3, 0], 2);
        assert_eq(t.old_hashes[1], 0);
        assert(t.paths_ok);
        let u = t.update(true, [true, true, false], [[105, 1], [5, 2], [0, 0]]);
        let (root, _, _, _) = full(
            [(0, [105, 1]), (1, [10, 8]), (2, [20, 9]), (3, [5, 2]), (5, [50, 10])],
            [0],
        );
        assert_eq(u.new_root, root);
    }

    #[test(should_fail_with = "diverged store")]
    fn a_nonzero_leaf_under_old_hash_0_fails() {
        let (_, hashes, siblings, _) = full(book(), [0, 3, 0]);
        let leaves = [[100, 7], [0, 1], [100, 7]];
        let _ = load(NS, KEY, leaves, hashes, siblings, [0, 3, 0], 2).headed();
    }

    #[test(should_fail_with = "diverged store")]
    fn a_leaf_that_does_not_hash_to_its_old_hash_fails() {
        let (_, hashes, siblings, _) = full(book(), [0, 1, 2]);
        let leaves = [[100, 7], [10, 9], [20, 9]];
        let _ = load(NS, KEY, leaves, hashes, siblings, [0, 1, 2], 3).headed();
    }

    #[test]
    fn a_wrong_sibling_fails_the_paths() {
        let (_, hashes, mut siblings, leaves) = full(book(), [0, 1, 2]);
        siblings[2][1] = siblings[2][1] + 1;
        let t = load(NS, KEY, leaves, hashes, siblings, [0, 1, 2], 3).headed();
        assert(!t.paths_ok);
        // a wrong sibling in slot 0 moves the old root: every other path
        // disagrees, and old_c is not the slot's
        let (root, hashes, mut siblings, leaves) = full(book(), [0, 1, 2]);
        siblings[0][2] = 1;
        let t = load(NS, KEY, leaves, hashes, siblings, [0, 1, 2], 3).headed();
        assert(!t.paths_ok);
        assert(t.old_c != commitment(NS, KEY, root));
    }

    #[test]
    fn ok_false_keeps_the_root_and_the_hashes() {
        let t = loaded([0, 1, 5], 3);
        let u = t.update(false, [true, true, true], [[1, 2], [3, 4], [5, 6]]);
        assert_eq(u.write, [false, false, false]);
        assert_eq(u.new_root, t.old_root);
        assert_eq(u.new_hashes, t.old_hashes);
        assert_eq(u.stored, t.leaves);
        assert_eq(u.new_c, t.old_c);
        // a write to another key keeps that key's empty slot
        let w = loaded([0, 1, 5], 3).writes_to(KEY + 1);
        assert_eq(w.update(false, [true; 3], [[1, 2]; 3]).new_c, 0);
        assert_eq(
            w.update(true, [true; 3], [[1, 2]; 3]).new_c,
            commitment(NS, KEY + 1, w.update(true, [true; 3], [[1, 2]; 3]).new_root),
        );
    }

    #[test]
    fn a_created_tree_starts_empty() {
        let t: Tree<1, D, 2> = empty(NS, KEY, [0], 1).headed();
        assert_eq(t.old_root, empty_root::<D>());
        assert_eq(t.old_c, 0);
        assert(t.count_ok & t.in_range & t.distinct & t.paths_ok);
        let u = t.update(true, [true], [[5, 9]]);
        let (root, _, _, _) = full([(0, [5, 9])], [0]);
        assert_eq(u.new_root, root);
        assert_eq(u.new_c, commitment(NS, KEY, root));
        assert_eq(u.new_hashes, [leaf_hash(NS, KEY, 0, [5, 9])]);
    }

    /// The window of `N` leaves at `at` (a multiple of N) of the test book,
    /// as the nodes place it: its leaves, old hashes and the window root's
    /// siblings (those of leaf `at` from height H up).
    fn placed_window<let N: u32, let H: u32, let S: u32>(at: Field) -> ([[Field; 2]; N], [Field; N], [Field; S]) {
        let mut indices = [0; N];
        for j in 0..N {
            indices[j] = at + j as Field;
        }
        let (_, hashes, siblings, leaves) = full(book(), indices);
        let mut above = [0; S];
        for l in 0..S {
            above[l] = siblings[0][H + l];
        }
        (leaves, hashes, above)
    }

    #[test]
    fn a_window_is_bound_to_the_loaded_root() {
        let t = loaded([0, 1, 5], 3);
        // leaves 4 .. 7: one root sibling above the window of height 2
        let (leaves, hashes, siblings) = placed_window::<4, 2, 1>(4);
        let w = t.window::<4, 2, 1>(4, leaves, hashes, siblings);
        assert(w.aligned & w.root_ok);
        assert_eq(w.start, 4);
        assert_eq(w.leaves[1], [50, 10]);
        assert_eq(w.old_hashes[1], leaf_hash(NS, KEY, 5, [50, 10]));
        assert_eq(w.old_hashes[0], 0);
        // leaves 0 and 1, the header among them: two siblings above
        let (leaves, hashes, siblings) = placed_window::<2, 1, 2>(0);
        let w = t.window::<2, 1, 2>(0, leaves, hashes, siblings);
        assert(w.aligned & w.root_ok);
        assert_eq(w.leaves, [[100, 7], [10, 8]]);
    }

    #[test]
    fn a_start_out_of_range_or_unaligned_reads_window_0() {
        let t = loaded([0, 1, 5], 3);
        let (leaves, hashes, siblings) = placed_window::<4, 2, 1>(0);
        for start in [2, 8, 0 - 4] {
            let w = t.window::<4, 2, 1>(start, leaves, hashes, siblings);
            assert(!w.aligned);
            assert(w.root_ok);
            assert_eq(w.start, 0);
        }
        // the nodes placed the request's window: not the effective one
        let (leaves, hashes, _) = placed_window::<4, 2, 1>(4);
        let (_, _, wrong) = placed_window::<4, 2, 1>(0);
        assert(!t.window::<4, 2, 1>(4, leaves, hashes, wrong).root_ok);
    }

    #[test]
    fn a_wrong_window_sibling_or_hash_fails_the_root() {
        let t = loaded([0, 1, 5], 3);
        let (leaves, hashes, siblings) = placed_window::<2, 1, 2>(4);
        assert(t.window::<2, 1, 2>(4, leaves, hashes, siblings).root_ok);
        let mut bad = siblings;
        bad[1] = bad[1] + 1;
        assert(!t.window::<2, 1, 2>(4, leaves, hashes, bad).root_ok);
    }

    #[test(should_fail_with = "diverged store")]
    fn a_window_leaf_that_does_not_hash_to_its_old_hash_fails() {
        let t = loaded([0, 1, 5], 3);
        let (mut leaves, hashes, siblings) = placed_window::<2, 1, 2>(4);
        leaves[1] = [50, 11];
        let _ = t.window::<2, 1, 2>(4, leaves, hashes, siblings);
    }

    #[test]
    fn a_failed_create_leaves_the_empty_slot() {
        let t: Tree<1, D, 2> = empty(NS, KEY, [0], 1).headed();
        let u = t.update(false, [true], [[5, 9]]);
        assert_eq(u.new_c, 0);
        assert_eq(u.new_hashes, [0]);
        assert_eq(u.stored, [[0, 0]]);
    }

    #[test]
    fn an_oblivious_round_composes_its_own_indices() {
        // the header, then two entries (below 2^D = 8) of which one is used
        assert_eq(slot_indices::<2, D>([4, 6], 1, false, 2), [0, 4, 0]);
        assert_eq(slot_indices::<2, D>([4, 6], 2, false, 2), [0, 4, 6]);
        // an opening takes $new_leaf in slot 1, whatever the input there
        assert_eq(slot_indices::<2, D>([0, 6], 2, true, 2), [0, 2, 6]);
        assert_eq(slot_indices::<2, D>([7, 6], 1, true, 2), [0, 2, 0]);
        // a count out of range uses no entry
        assert_eq(slot_indices::<2, D>([4, 6], 0, false, 2), [0, 0, 0]);
        assert_eq(slot_indices::<2, D>([4, 6], 3, false, 2), [0, 0, 0]);
        // an input past 2^D is read at its low bits in every slot, as the
        // nodes read it (13 = 8 + 5, 9 = 8 + 1), never clamped to 0
        assert_eq(slot_indices::<2, D>([13, 9], 2, false, 2), [0, 5, 1]);
        // the low bits of the canonical integer, across the limb boundary
        // and near p (p ends in 0b001: p - 1 ends in 0b000, p - 2 in 0b111)
        assert_eq(low_bits::<D>(0x100000000000000000000000000000003), 3);
        assert_eq(low_bits::<D>(0 - 1), 0);
        assert_eq(low_bits::<D>(0 - 2), 7);
    }

    #[test]
    fn the_new_path_nodes_are_the_new_tree_s() {
        // the last slot's path is the new tree's (an earlier slot's node
        // where a later slot shares the ancestor is stale, and the later
        // slot's write wins in the nodes' slot-order writes)
        let t = loaded([0, 1, 5], 3);
        let new_leaves = [[130, 21], [11, 22], [55, 23]];
        let (u, paths) = t.update_paths(true, [true, true, true], new_leaves);
        let filled = [(0, [130, 21]), (1, [11, 22]), (2, [20, 9]), (5, [55, 23])];
        let (root, hashes, siblings, _) = full(filled, [0, 1, 5]);
        assert_eq(u.new_root, root);
        let bits: [bool; D] = (5).to_le_bits();
        let mut at = hashes[2];
        for l in 0..D {
            at = if bits[l] { node(siblings[2][l], at) } else { node(at, siblings[2][l]) };
            assert_eq(paths[2][l], at);
        }
        assert_eq(paths[2][D - 1], root);
        // slot 1 (index 1) shares no ancestor with slot 2 below height 3: its
        // nodes there are the new tree's too
        let bits1: [bool; D] = (1).to_le_bits();
        let mut at1 = hashes[1];
        for l in 0..2 {
            at1 = if bits1[l] { node(siblings[1][l], at1) } else { node(at1, siblings[1][l]) };
            assert_eq(paths[1][l], at1);
        }
        // a round that writes nothing leaves the old path nodes
        let (f, old_paths) = loaded([0, 1, 5], 3).update_paths(false, [true; 3], new_leaves);
        assert_eq(f.new_root, loaded([0, 1, 5], 3).old_root);
        let (_, hashes, siblings, _) = full(book(), [0, 1, 5]);
        let mut at = hashes[2];
        for l in 0..D {
            at = if bits[l] { node(siblings[2][l], at) } else { node(at, siblings[2][l]) };
            assert_eq(old_paths[2][l], at);
        }
    }

    #[test]
    fn an_opening_is_at_the_append_index_and_advances_it() {
        // the append index of a created tree is 1; an opening there advances it
        assert_eq(append(1, true, 1), (true, 2));
        // a gap past the append index, an occupied leaf before it, a full tree
        assert_eq(append(3, true, 7), (false, 4));
        assert_eq(append(3, true, 2), (false, 4));
        assert_eq(append(3, true, 0), (false, 4));
        // a round that opens nothing keeps the index, whatever $new_leaf is
        assert_eq(append(3, false, 7), (true, 3));
        assert_eq(append(3, false, 0), (true, 3));
    }
}
