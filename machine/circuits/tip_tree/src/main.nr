//! A queued round of the machine's test tree (pss_core
//! tip::tree): a tree-valued node-held key of depth 16, K = 3 slots of
//! leaves of 3 elements. Slot 0 is the header, leaf 0 = [total,
//! next_index, blinding]; slots 1 and 2 are the positions `p1` and `p2`,
//! each [value, 0, blinding], of which the round uses `count` (n_used = 1 +
//! count). `p1` is the open input: p1 = 0 opens the empty leaf `new_leaf`
//! the scheduler assigns, which must be the header's append index
//! next_index, the first leaf never written (pss_core `tree::append`).
//!
//! On ok every used position's value grows by `amount` under its fresh
//! blinding r_new[k], and the header's total by amount * count under
//! r_new[0]; an opening advances next_index by one, every other round
//! passes it through, as each position passes its second element through.
//! The codes, the first failing check's (ok = 0 on any):
//!
//!   1  count is not 1 or 2
//!   2  an index out of range: p1 not below 2^16, or p2 (when used) 0 or
//!      not below 2^16
//!   3  a duplicate index (slot 1's index equals p2)
//!   4  a full tree (opening with new_leaf = 0)
//!   5  node data inconsistent: the placed indices are not [0, slot 1's,
//!      p2] over the used slots, or a path does not give slot 0's root
//!   6  an opening slot whose old leaf hash is not 0
//!   7  an opening whose new_leaf is not the header's next_index (a
//!      scheduler that opens a leaf anywhere but at the end of the tree);
//!      the circuit's own guard on the scheduler's choice, which each
//!      node's chain verifier also checks, so an honest network never
//!      reaches it
//!
//! On !ok nothing is written: new_c = old_c and new_hashes = old_hashes.
//! `position` is the index slot 1 names (new_leaf when opening). The tree's
//! leaf hashes and old_c bind in_slots[0], new_c out_slots[0] (the same
//! slot in every request). The stored leaves go to TACEO_store("out0"),
//! the 9 elements slot after slot.
//!
//! The round outputs the request id over its app inputs and nonce,
//! `intake::plain(namespace, vk_hash, [amount, p1, p2, count], user_nonce)`.
//!
//! The manifest (machine/circuits/manifests/tip_tree.json, intake onchain) fills
//! `namespace`, `vk_hash` ($vk_hash), `in_slots`, `out_slots`, the app
//! inputs `amount`, `p1`, `p2`, `count` and `user_nonce` ($user_nonce) with
//! PUBLIC values, `leaves` with LOAD $state_keys.reads[0] (the
//! touched leaves, slot after slot, 9 elements), `old_hashes`, `siblings`
//! and `indices` with the PUBLIC paths and effective indices its `tree`
//! entry names, `new_leaf` with PUBLIC $new_leaf and `r_new` with SAMPLE 3;
//! it stores out0 under $state_keys.writes[0] with note hash `new_c` and new leaf
//! hashes `new_hashes`, and names `old_c` as the commitment slot of
//! $state_keys.reads[0].
//!
//! Public inputs (13), in ACIR order: [namespace, vk_hash, in_slots[0],
//! out_slots[0], request_id, old_c, new_c, new_hashes[0..3], ok, code,
//! position].

use pss_core::tip::{intake, tree};
use total::cmp::eq;
use total::core::{is_zero, select_field};
use total::ctl::Outcome;
use total::range::fits_bits;

/// The tree's depth.
global D: u32 = 16;
/// The slots: the header and two positions.
global K: u32 = 3;

/// The public outputs, after the public parameters.
pub struct TreeOutputs {
    /// the chain request id over the round's inputs
    pub request_id: Field,
    /// the commitment of the loaded tree
    pub old_c: Field,
    /// the commitment of the tree the round leaves (old_c when not ok)
    pub new_c: Field,
    /// each slot's leaf hash after the round
    pub new_hashes: [Field; K],
    /// 1 when the round applied, else 0
    pub ok: Field,
    /// 0 when ok, else the first failing check's code
    pub code: Field,
    /// the index slot 1 names: p1, or new_leaf when opening
    pub position: Field,
}

fn main(
    namespace: pub Field,
    vk_hash: pub Field,
    in_slots: pub [Field; 1],
    out_slots: pub [Field; 1],
    amount: Field,
    p1: Field,
    p2: Field,
    count: Field,
    user_nonce: Field,
    leaves: [[Field; 3]; K],
    old_hashes: [Field; K],
    siblings: [[Field; D]; K],
    indices: [Field; K],
    new_leaf: Field,
    r_new: [Field; K],
) -> pub TreeOutputs {
    let t = tree::load::<K, D, 3>(
        namespace,
        in_slots[0],
        leaves,
        old_hashes,
        siblings,
        indices,
        1 + count,
    )
        .headed()
        .writes_to(out_slots[0]);

    let opens = is_zero(p1);
    let position = select_field(opens, new_leaf, p1);
    let both = eq(count, 2);
    let (appends, next_index) = tree::append(leaves[0][1], opens, new_leaf);
    let outcome = Outcome::good()
        .require(eq(count, 1) | both, 1)
        .require(fits_bits::<D>(p1) & (!both | (!is_zero(p2) & fits_bits::<D>(p2))), 2)
        .require(!(both & eq(position, p2)), 3)
        .require(!(opens & is_zero(new_leaf)), 4)
        .require(
            t.count_ok & t.in_range & t.distinct & t.paths_ok & t.indices_match([0, position, p2]),
            5,
        )
        .require(!opens | is_zero(old_hashes[1]), 6)
        .require(appends, 7);

    let new_leaves = [
        [leaves[0][0] + amount * count, next_index, r_new[0]],
        [leaves[1][0] + amount, leaves[1][1], r_new[1]],
        [leaves[2][0] + amount, leaves[2][1], r_new[2]],
    ];
    let u = t.update(outcome.ok, [true; K], new_leaves);
    u.store(0);
    TreeOutputs {
        request_id: intake::plain(namespace, vk_hash, [amount, p1, p2, count], user_nonce),
        old_c: u.old_c,
        new_c: u.new_c,
        new_hashes: u.new_hashes,
        ok: outcome.ok as Field,
        code: outcome.code,
        position,
    }
}

mod tests {
    use super::{D, K, main, TreeOutputs};
    use pss_core::tip::tree;

    global NS: Field = 0xc0ffee;
    global KEY: Field = 0xa003;

    /// The tree with the header [100, 2, 7] (append index 2) and position
    /// 1 = [10, 0, 8]: the slots for indices `at` (each 0, 1 or an empty
    /// leaf above 1).
    fn slots(at: [Field; K]) -> ([[Field; 3]; K], [Field; K], [[Field; D]; K], Field) {
        let z = tree::zeros::<D>();
        let h0 = tree::leaf_hash(NS, KEY, 0, [100, 2, 7]);
        let h1 = tree::leaf_hash(NS, KEY, 1, [10, 0, 8]);
        let mut root = tree::node(h0, h1);
        for l in 1..D {
            root = tree::node(root, z[l]);
        }
        let mut leaves = [[0; 3]; K];
        let mut hashes = [0; K];
        let mut siblings = [[0; D]; K];
        for k in 0..K {
            for l in 0..D {
                siblings[k][l] = z[l];
            }
            if at[k] == 0 {
                leaves[k] = [100, 2, 7];
                hashes[k] = h0;
                siblings[k][0] = h1;
            } else if at[k] == 1 {
                leaves[k] = [10, 0, 8];
                hashes[k] = h1;
                siblings[k][0] = h0;
            } else {
                // an empty leaf above 1: its path meets leaves 0 and 1 at the
                // lowest height where its index has a bit set above bit 0
                let bits: [bool; D] = at[k].to_le_bits();
                let mut below = tree::node(h0, h1);
                let mut met = false;
                for l in 1..D {
                    if !met & bits[l] {
                        siblings[k][l] = below;
                        met = true;
                    }
                    below = tree::node(below, z[l]);
                }
            }
        }
        (leaves, hashes, siblings, root)
    }

    fn round(p1: Field, p2: Field, count: Field, at: [Field; K], new_leaf: Field) -> TreeOutputs {
        let (leaves, hashes, siblings, _) = slots(at);
        main(
            NS,
            0x5a,
            [KEY],
            [KEY],
            3,
            p1,
            p2,
            count,
            9,
            leaves,
            hashes,
            siblings,
            at,
            new_leaf,
            [21, 22, 23],
        )
    }

    #[test]
    fn a_deposit_to_an_open_position() {
        let out = round(1, 0, 1, [0, 1, 0], 2);
        assert_eq(out.code, 0);
        assert_eq(out.ok, 1);
        assert_eq(out.position, 1);
        assert_eq(out.new_hashes[0], tree::leaf_hash(NS, KEY, 0, [103, 2, 21]));
        assert_eq(out.new_hashes[1], tree::leaf_hash(NS, KEY, 1, [13, 0, 22]));
        assert(out.new_c != out.old_c);
    }

    #[test]
    fn an_opening_takes_new_leaf() {
        let out = round(0, 0, 1, [0, 2, 0], 2);
        assert_eq(out.code, 0);
        assert_eq(out.position, 2);
        assert_eq(out.new_hashes[1], tree::leaf_hash(NS, KEY, 2, [3, 0, 22]));
        // the header's append index advances past the opened leaf
        assert_eq(out.new_hashes[0], tree::leaf_hash(NS, KEY, 0, [103, 3, 21]));
    }

    #[test]
    fn two_positions() {
        let out = round(1, 5, 2, [0, 1, 5], 2);
        assert_eq(out.code, 0);
        assert_eq(out.new_hashes[0], tree::leaf_hash(NS, KEY, 0, [106, 2, 21]));
        assert_eq(out.new_hashes[2], tree::leaf_hash(NS, KEY, 5, [3, 0, 23]));
    }

    #[test]
    fn the_codes() {
        let (_, hashes, _, _) = slots([0, 1, 0]);
        let failed = |out: TreeOutputs, code: Field| {
            assert_eq(out.code, code);
            assert_eq(out.ok, 0);
            assert_eq(out.new_c, out.old_c);
        };
        failed(round(1, 0, 0, [0, 0, 0], 2), 1);
        failed(round(1, 0, 3, [0, 0, 0], 2), 1);
        failed(round(0x10000, 0, 1, [0, 0, 0], 2), 2);
        failed(round(1, 0, 2, [0, 1, 0], 2), 2);
        failed(round(1, 1, 2, [0, 1, 1], 2), 3);
        failed(round(0, 0, 1, [0, 0, 0], 0), 4);
        failed(round(1, 0, 1, [0, 2, 0], 2), 5);
        failed(round(0, 0, 1, [0, 1, 0], 1), 6);
        // an empty leaf past the append index 2: a gap
        failed(round(0, 0, 1, [0, 3, 0], 3), 7);
        let out = round(1, 0, 0, [0, 0, 0], 2);
        assert_eq(out.new_hashes, [hashes[0], hashes[0], hashes[0]]);
    }
}
