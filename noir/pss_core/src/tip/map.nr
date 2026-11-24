//! A keyed map: a tree-valued node-held key with `access: oblivious` and
//! `keyed: true` (docs/ARCHITECTURE.md section 6, "The keyed map's circuit"), a
//! sparse Merkle tree of depth `D` whose leaf for a key sits at the path of the
//! key's low `D` bits and holds the key as its first element, a value, and its
//! blinding last.
//!
//! The map is `tip::tree`'s tree loaded with the keys' paths in place of
//! indices, so the hashes, the commitment, the one assertion (a loaded leaf
//! against its old hash, node-supplied data), the path checks and the
//! update are the tree's. What the map adds is per slot: `present` (the
//! leaf holds a key: the key, or a key with the same low bits, is in the
//! map), `taken` (present, and the stored key is another one: a collision
//! in the low bits, which the round refuses rather than touching another
//! key's entry), and the keyed update that writes the slot's key into its
//! leaf, so no app can store a leaf under a key it did not name, and never
//! over a taken slot.
//!
//! The keys are the request's inputs, so a round whose shares do not open C
//! (`opened` false: `intake::SharedIntake::opens`) names keys nobody
//! committed. Its update inserts no key and changes no value: it re-blinds
//! every slot the policy re-blinds, a present leaf with its key and value,
//! an empty one into a vacant leaf `[0, 0 ..., r]` (key 0: no key, since
//! keys are hash outputs), so the commitment changes as on every other
//! outcome and nothing shows whether the named keys were present. A vacant
//! leaf is absent to every round (`present` is false, so `taken` too) and
//! the next round that names a key on its path writes it as it writes an
//! empty leaf.
//!
//! Non-membership is proven as membership is: an empty leaf (old hash 0,
//! the zero vector by the assertion) on a path the circuit verifies along
//! the key's own bits to the committed root. `present` is a flag the app
//! turns into its outcome: a lookup requires it, a registration requires
//! its negation, an insert-or-update selects on it.
//!
//! Unused slots (past `n_used`) read path 0, as the nodes read it; the
//! round's `count` is public. No header, no openings, no append index, no
//! windows: a keyed map cannot be enumerated.
//!
//! Keys must be hash outputs; apps hash at entry. The brick does not hash a
//! key, so the app's request function computes every key it sends as a
//! domain-separated hash of what the caller supplies (examples/credits-tip
//! `map_key`). A raw caller-chosen key lets anyone take a known key's path
//! with one request (the key plus `2^D`) and block it for ever; a hashed key
//! makes that a `2^D` search (docs/ARCHITECTURE.md section 6, "The key, the
//! path and the depth"). A request whose shares carry another key than C's
//! inserts nothing (above), so the hash binds every key that enters the map.

use crate::tip::family::Change;
use crate::tip::tree::{self, Oblivious, Tree, Updated, low_bits, used_slots};
use total::cmp::eq;
use total::core::{is_zero, select_field};

/// The path of `key`: the low `D` bits of its canonical integer, the
/// address the nodes read (sidecar-oblivious `indices_to_xor`). Total:
/// `low_bits`'s two range checks and reconstruction.
pub fn path_of<let D: u32>(key: Field) -> Field {
    low_bits::<D>(key)
}

/// Each used slot's path, 0 in an unused one: the indices `tree::load`
/// takes, exactly where the nodes read. Total: K `path_of` and selects.
pub fn paths<let K: u32, let D: u32>(keys: [Field; K], n_used: Field) -> [Field; K] {
    let used = used_slots::<K>(n_used);
    let mut out = [0; K];
    for k in 0..K {
        out[k] = select_field(used[k], path_of::<D>(keys[k]), 0);
    }
    out
}

/// A keyed map as a round loads it: `K` slots of its depth-`D` tree, each a
/// leaf of `W` elements `[key, value ..., blinding]`.
pub struct Map<let K: u32, let D: u32, let W: u32> {
    /// the tree, loaded at the keys' paths
    pub tree: Tree<K, D, W>,
    /// each slot's key, the round's INPUT_SHARED input (0 in an unused slot)
    pub keys: [Field; K],
    /// the slot's leaf holds a key (it is neither empty nor vacant): a key
    /// with this path is in the map
    pub present: [bool; K],
    /// the slot's leaf holds another key than the slot's (a collision in
    /// the low `D` bits): the entry is not this key's
    pub taken: [bool; K],
    /// no used slot is taken
    pub keys_ok: bool,
}

/// The slots of a loaded map: `keys` the round's key inputs, `leaves`
/// LOAD_LEAF, `old_hashes` and `siblings` the nodes' oblivious RAM reads
/// (LOAD slices), `n_used` the number of slots the round uses. The one
/// assertion is `tree::load`'s; the flags are `count_ok`, `distinct` (two
/// used keys with one path), `paths_ok`, `keys_ok` and per slot `present`
/// and `taken`. `in_range` always holds (a path fits `D` bits). The
/// tree's flags are its placement (`Tree::placed`), which the updates fold
/// in themselves.
///
/// Constraints: `tree::load`'s at depth `D`, K `low_bits::<D>`, 2K
/// equality gadgets on the stored keys.
pub fn load<let K: u32, let D: u32, let W: u32>(
    namespace: Field,
    key_slot: Field,
    keys: [Field; K],
    leaves: [[Field; W]; K],
    old_hashes: [Field; K],
    siblings: [[Field; D]; K],
    n_used: Field,
) -> Map<K, D, W> {
    std::static_assert(W >= 3, "a keyed map's leaf holds the key, a value and the blinding");
    let p = paths::<K, D>(keys, n_used);
    let tree = tree::load(namespace, key_slot, leaves, old_hashes, siblings, p, n_used);
    flagged(tree, keys)
}

/// The map a round creates at `key_slot`: every slot an empty leaf of the
/// empty tree at its key's path (`tree::empty`). Its old_c is 0.
pub fn empty<let K: u32, let D: u32, let W: u32>(
    namespace: Field,
    key_slot: Field,
    keys: [Field; K],
    n_used: Field,
) -> Map<K, D, W> {
    std::static_assert(W >= 3, "a keyed map's leaf holds the key, a value and the blinding");
    let p = paths::<K, D>(keys, n_used);
    flagged(tree::empty(namespace, key_slot, p, n_used), keys)
}

fn flagged<let K: u32, let D: u32, let W: u32>(tree: Tree<K, D, W>, keys: [Field; K]) -> Map<K, D, W> {
    let mut present = [false; K];
    let mut taken = [false; K];
    let mut keys_ok = true;
    for k in 0..K {
        // a vacant leaf (key 0) holds no key
        present[k] = !is_zero(tree.old_hashes[k]) & !is_zero(tree.leaves[k][0]);
        taken[k] = present[k] & !eq(tree.leaves[k][0], keys[k]);
        keys_ok = keys_ok & !(tree.used[k] & taken[k]);
    }
    Map { tree, keys, present, taken, keys_ok }
}

impl<let K: u32, let D: u32, let W: u32> Map<K, D, W> {
    /// The map with new_c committed under `out_key` (`Tree::writes_to`).
    pub fn writes_to(self, out_key: Field) -> Self {
        let mut m = self;
        m.tree = m.tree.writes_to(out_key);
        m
    }

    /// Slot k's value: the leaf's elements between the key and the
    /// blinding, zero when the slot is absent (or taken: the app checks
    /// `taken` before trusting it). No constraint.
    pub fn value(self, k: u32) -> [Field; W - 2] {
        let mut out = [0; W - 2];
        for e in 0..W - 2 {
            out[e] = self.tree.leaves[k][e + 1];
        }
        out
    }

    /// Whether slot k is a verified absence: its leaf is empty or vacant
    /// (the key is not in the map, nor any key with its path) and the slot
    /// is used.
    pub fn absent(self, k: u32) -> bool {
        self.tree.used[k] & !self.present[k]
    }

    /// Each slot's new leaf: its key, `values[k]`, the blinding `r_new[k]`.
    fn leaves_of(self, values: [[Field; W - 2]; K], r_new: [Field; K]) -> [[Field; W]; K] {
        let mut leaves = [[0; W]; K];
        for k in 0..K {
            leaves[k][0] = self.keys[k];
            for e in 0..W - 2 {
                leaves[k][e + 1] = values[k][e];
            }
            leaves[k][W - 1] = r_new[k];
        }
        leaves
    }

    /// The round's writes (`Tree::update_paths`): slot k takes the leaf
    /// `[key, values[k] ..., r_new[k]]` when ok, the map is placed, the slot
    /// is used, `writes[k]` and the slot is not taken (another key's leaf is
    /// never written under this key); an insert where the slot was absent,
    /// an update where present. Returns the update and each slot's new path
    /// nodes for `Updated::store_oblivious`. Constraints:
    /// `Tree::update_paths`'s and K ANDs.
    pub fn update(
        self,
        ok: bool,
        writes: [bool; K],
        values: [[Field; W - 2]; K],
        r_new: [Field; K],
    ) -> (Updated<K, W>, [[Field; D]; K]) {
        let leaves = self.leaves_of(values, r_new);
        let mut own = [false; K];
        for k in 0..K {
            own[k] = writes[k] & !self.taken[k];
        }
        self.tree.update_paths(ok, own, leaves)
    }

    /// The round's writes under private outcomes, `opened` whether the
    /// request's shares open C (`intake::SharedIntake::opens`). Opened:
    /// slot k takes `[key, values[k] ..., r_new[k]]` where ok, `writes[k]`
    /// and not taken; a slot the policy `reblind` re-blinds is written on
    /// every other outcome where it holds a leaf (its leaf kept under the
    /// fresh blinding), so nothing shows whether the round applied; an
    /// absent slot is written only where the round writes it, since
    /// re-blinding an empty leaf would insert the key. Not opened (the
    /// keys are unbound): nothing lands and no key enters the map; every
    /// slot the policy re-blinds is re-blinded as loaded, an empty one into a
    /// vacant leaf `[0, 0 ..., r_new[k]]`, so the commitment changes on this
    /// outcome too and shows nothing of whether the keys were present. When
    /// the map is not placed (`Tree::placed`) nothing is written. It does
    /// not keep the exit tag's rule 3 (super::exit), so a map has no tagged
    /// write.
    /// Constraints: `Tree::update_paths`'s, K equality gadgets on the public
    /// old hashes, the ANDs and selects.
    pub fn update_private(
        self,
        opened: bool,
        ok: bool,
        writes: [bool; K],
        reblind: [bool; K],
        values: [[Field; W - 2]; K],
        r_new: [Field; K],
    ) -> (Updated<K, W>, [[Field; D]; K]) {
        let leaves = self.leaves_of(values, r_new);
        let mut lands = [false; K];
        let mut written = [false; K];
        for k in 0..K {
            lands[k] = opened & ok & writes[k] & !self.taken[k];
            let held = !is_zero(self.tree.old_hashes[k]);
            written[k] = lands[k] | (reblind[k] & (held | !opened));
        }
        self.tree.write_private(true, lands, written, leaves, self.tree.leaves, r_new)
    }
}

/// A write to a keyed map in either family's form (`super::family::Change`):
/// `Map::update` under a public outcome, `Map::update_private` under a
/// private one, each with the slots' new path nodes (`tree::Oblivious`,
/// no public leaf hash). The app's round function makes it with
/// `Map::change`.
pub struct MapChange<let K: u32, let D: u32, let W: u32> {
    pub map: Map<K, D, W>,
    pub ok: bool,
    pub writes: [bool; K],
    pub reblind: [bool; K],
    pub values: [[Field; W - 2]; K],
    pub r_new: [Field; K],
}

impl<let K: u32, let D: u32, let W: u32> Map<K, D, W> {
    /// The write of `values` under `ok`, `writes` and the private write
    /// policy `reblind` (`MapChange`), in the form the round's intake family
    /// picks. No constraint.
    pub fn change(
        self,
        ok: bool,
        writes: [bool; K],
        reblind: [bool; K],
        values: [[Field; W - 2]; K],
        r_new: [Field; K],
    ) -> MapChange<K, D, W> {
        MapChange { map: self, ok, writes, reblind, values, r_new }
    }
}

impl<let K: u32, let D: u32, let W: u32> Change<Oblivious<K, W, D, 0>> for MapChange<K, D, W> {
    fn plain(self) -> Oblivious<K, W, D, 0> {
        let (updated, paths) = self.map.update(self.ok, self.writes, self.values, self.r_new);
        Oblivious { updated, paths }
    }

    fn private(self, opened: bool) -> Oblivious<K, W, D, 0> {
        let (updated, paths) =
            self.map.update_private(opened, self.ok, self.writes, self.reblind, self.values, self.r_new);
        Oblivious { updated, paths }
    }
}

mod tests {
    use super::{Map, empty, path_of, paths};
    use crate::test_support::keyed_map::ClearMap;
    use crate::tip::tree::{commitment, leaf_hash, zeros};

    global NS: Field = 0x7196;
    global KEY: Field = 0xa003;
    /// The test map's depth: 4 bits of path (the brick's own bound is the
    /// machine's, 32 to 120; the circuit takes any depth).
    global D: u32 = 4;
    global W: u32 = 3;

    /// A key whose low 4 bits are `low`, with high bits set.
    fn key(low: Field, high: Field) -> Field {
        low + high * 16
    }

    /// Two keys in the map: paths 5 and 9.
    fn book() -> ClearMap<3, D, W> {
        ClearMap::empty(NS, KEY).with([key(5, 7), 500, 51]).with([key(9, 2), 900, 91])
    }

    fn loaded(keys: [Field; 2], n_used: Field) -> Map<2, D, W> {
        book().load(keys, n_used)
    }

    #[test]
    fn a_path_is_the_low_bits() {
        assert_eq(path_of::<D>(key(5, 7)), 5);
        assert_eq(path_of::<D>(key(15, 0xabcdef)), 15);
        assert_eq(path_of::<64>(0x1_0000_0000_0000_0003), 3);
        assert_eq(paths::<2, D>([key(5, 7), key(9, 2)], 2), [5, 9]);
        assert_eq(paths::<2, D>([key(5, 7), key(9, 2)], 1), [5, 0]);
    }

    #[test]
    fn present_absent_and_taken_keys() {
        // key(5, 7) is present; key(3, 1) is absent (an empty leaf on a
        // verified path)
        let m = loaded([key(5, 7), key(3, 1)], 2);
        let root = book().root();
        assert_eq(m.tree.old_root, root);
        assert_eq(m.tree.old_c, commitment(NS, KEY, root));
        assert(m.tree.count_ok & m.tree.in_range & m.tree.distinct & m.tree.paths_ok);
        assert_eq(m.present, [true, false]);
        assert_eq(m.taken, [false, false]);
        assert(m.keys_ok);
        assert(!m.absent(0));
        assert(m.absent(1));
        assert_eq(m.value(0), [500]);
        assert_eq(m.value(1), [0]);
        // key(9, 3) collides with key(9, 2) in its low bits: taken, not its own
        let t = loaded([key(9, 3), key(3, 1)], 2);
        assert_eq(t.present, [true, false]);
        assert_eq(t.taken, [true, false]);
        assert(!t.keys_ok);
        // a taken slot past the count does not fail keys_ok
        let u = loaded([key(3, 1), key(9, 3)], 1);
        assert(u.keys_ok);
        assert(!u.absent(1));
    }

    #[test]
    fn two_keys_with_one_path_are_not_distinct() {
        let m = loaded([key(5, 7), key(5, 8)], 2);
        assert(!m.tree.distinct);
        assert(m.tree.paths_ok);
    }

    #[test]
    fn an_insert_and_an_update_write_the_keys_into_the_leaves() {
        let k_new = key(3, 1);
        let m = loaded([key(5, 7), k_new], 2);
        let (u, paths) = m.update(true, [true, true], [[501], [300]], [52, 31]);
        assert(u.ok);
        assert_eq(u.write, [true, true]);
        assert_eq(u.stored, [[key(5, 7), 501, 52], [k_new, 300, 31]]);
        let root = book().with([key(5, 7), 501, 52]).with([k_new, 300, 31]).root();
        assert_eq(u.new_root, root);
        assert_eq(book().after([key(5, 7), k_new], u).root(), root, "the model follows the round");
        assert_eq(u.new_c, commitment(NS, KEY, root));
        assert_eq(u.new_hashes[1], leaf_hash(NS, KEY, 3, [k_new, 300, 31]));
        assert_eq(paths[1][D - 1], root, "the last path node is the root");
        // not ok: nothing is written
        let (f, _) = m.update(false, [true, true], [[501], [300]], [52, 31]);
        assert_eq(f.new_c, m.tree.old_c);
        assert_eq(f.stored[1], [0, 0, 0]);
    }

    #[test]
    fn a_private_update_re_blinds_a_present_leaf_and_leaves_an_absent_one() {
        let m = loaded([key(5, 7), key(3, 1)], 2);
        // not ok under the policy: the present leaf keeps its key and value
        // under the fresh blinding, the absent slot stays empty
        let (f, _) = m.update_private(true, false, [true, true], [true, true], [[501], [300]], [52, 31]);
        assert_eq(f.write, [true, false]);
        assert_eq(f.stored, [[key(5, 7), 500, 52], [0, 0, 0]]);
        assert(f.new_c != m.tree.old_c);
        // ok: the insert lands under its blinding
        let (u, _) = m.update_private(true, true, [false, true], [true, true], [[501], [300]], [52, 31]);
        assert_eq(u.stored, [[key(5, 7), 500, 52], [key(3, 1), 300, 31]]);
    }

    // A taken slot is never written under the round's key, whatever the app
    // passes: the other key's leaf stays.
    #[test]
    fn a_taken_slot_is_never_written_under_the_rounds_key() {
        let m = loaded([key(9, 3), key(3, 1)], 2);
        assert_eq(m.taken, [true, false]);
        let (u, _) = m.update(true, [true, true], [[1], [300]], [52, 31]);
        assert_eq(u.write, [false, true]);
        assert_eq(u.stored[0], [key(9, 2), 900, 91]);
        // under private outcomes it is re-blinded with the other key's leaf
        let (p, _) = m.update_private(true, true, [true, true], [true, true], [[1], [300]], [52, 31]);
        assert_eq(p.stored, [[key(9, 2), 900, 52], [key(3, 1), 300, 31]]);
    }

    // Shares that do not open C name keys nobody committed: nothing lands
    // and no key enters the map. The present leaf is re-blinded with its key
    // and value, the absent slot becomes a vacant leaf, so the commitment
    // changes as on every outcome and shows nothing of presence. The vacant
    // leaf is absent to the next round, which inserts the key it names.
    #[test]
    fn an_unopened_round_inserts_no_key_and_still_changes_the_commitment() {
        let victim = key(3, 1);
        let squat = key(3, 2);
        let m = loaded([key(5, 7), squat], 2);
        let (u, _) = m.update_private(false, true, [true, true], [true, true], [[501], [300]], [52, 31]);
        assert_eq(u.write, [true, true]);
        assert_eq(u.stored, [[key(5, 7), 500, 52], [0, 0, 31]]);
        assert(u.new_c != m.tree.old_c);
        // the same keys absent alike: the commitment changes whatever is present
        let (a, _) = loaded([key(4, 1), squat], 2).update_private(false, true, [true; 2], [true; 2], [[1], [1]], [52, 31]);
        assert(a.new_c != a.old_c);
        let after = book().after([key(5, 7), squat], u);
        assert_eq(after.commitment(), u.new_c, "the model follows the round");
        // the victim's key on that path is absent, not taken, and inserts
        let v = after.load([victim, key(9, 2)], 2);
        assert_eq(v.present, [false, true]);
        assert_eq(v.taken, [false, false]);
        assert(v.keys_ok & v.absent(0));
        assert_eq(v.value(0), [0]);
        let (i, _) = v.update_private(true, true, [true, false], [true, true], [[7], [900]], [61, 62]);
        assert_eq(i.stored, [[victim, 7, 61], [key(9, 2), 900, 62]]);
        // an unopened round on the vacant leaf re-blinds it vacant
        let (r, _) = v.update_private(false, true, [true, true], [true, true], [[7], [1]], [63, 64]);
        assert_eq(r.stored[0], [0, 0, 63]);
    }

    // Two used keys on one path are not placed: nothing is written, so the
    // machine is never handed two leaves for one address.
    #[test]
    fn two_keys_on_one_path_write_nothing() {
        let m = loaded([key(3, 1), key(3, 2)], 2);
        assert(!m.tree.distinct);
        let (u, _) = m.update_private(true, true, [true, true], [true, true], [[1], [2]], [52, 31]);
        assert_eq(u.write, [false, false]);
        assert_eq(u.new_c, m.tree.old_c);
        let (f, _) = m.update_private(false, true, [true, true], [true, true], [[1], [2]], [52, 31]);
        assert_eq(f.write, [false, false]);
        let same = loaded([key(5, 7), key(5, 7)], 2);
        assert_eq(same.update(true, [true, true], [[1], [2]], [52, 31]).0.new_c, same.tree.old_c);
    }

    #[test]
    fn an_empty_map_has_the_empty_root() {
        let m = empty::<1, D, W>(NS, KEY, [key(5, 7)], 1);
        assert_eq(m.tree.old_root, zeros::<D>()[D]);
        assert_eq(m.tree.old_c, 0);
        assert(m.absent(0));
        let (u, _) = m.update(true, [false], [[0]], [1]);
        assert_eq(u.new_c, commitment(NS, KEY, zeros::<D>()[D]));
    }
}
