//! The first round of the machine's test tree: it creates a tree-valued
//! node-held key of depth 16 whose header, leaf 0, is [total, next_index,
//! blinding], and its commitment (pss_core tip::tree). next_index, the
//! tree's append index, starts at 1, the first position.
//!
//!   leaf 0    = [total, 1, r_new]   stored as TACEO_store("out0", leaf 0)
//!   new_hash  = tree::leaf_hash(namespace, out_slots[0], 0, leaf 0)
//!   new_c     = tree::commitment(namespace, out_slots[0], root)
//!
//! with root the root of the empty tree with leaf 0 written, and the init
//! request id over its input, `intake::plain(namespace, vk_hash, [total],
//! 0)`. The manifest (machine/circuits/manifests/tip_tree_init.json, intake
//! onchain) fills `namespace` with PUBLIC $namespace, `vk_hash` with PUBLIC
//! $vk_hash, `out_slots` with PUBLIC
//! ["$state_keys.writes[0]"], `total` with PUBLIC "total" and `r_new` with
//! SAMPLE 1, and stores out0 (one slot of 3 elements) under $state_keys.writes[0]
//! with note hash `new_c` and new leaf hashes `new_hashes`. The round loads
//! nothing, so it has no commitment slot.
//!
//! Public inputs (6), in ACIR order: [namespace, vk_hash, out_slots[0],
//! request_id, new_c, new_hashes[0]].

use pss_core::tip::{intake, tree};

/// The tree's depth.
global D: u32 = 16;

/// The public outputs, after the public parameters.
pub struct InitOutputs {
    /// the init request id over the round's input
    pub request_id: Field,
    /// the commitment of the created tree
    pub new_c: Field,
    /// the header's leaf hash, from which the nodes build the clear tree
    pub new_hashes: [Field; 1],
}

fn main(
    namespace: pub Field,
    vk_hash: pub Field,
    out_slots: pub [Field; 1],
    total: Field,
    r_new: Field,
) -> pub InitOutputs {
    let t = tree::empty::<1, D, 3>(namespace, out_slots[0], [0], 1).headed();
    let u = t.update(true, [true], [[total, 1, r_new]]);
    u.store(0);
    InitOutputs {
        request_id: intake::plain(namespace, vk_hash, [total], 0),
        new_c: u.new_c,
        new_hashes: u.new_hashes,
    }
}

#[test]
fn the_tree_holds_the_header_alone() {
    let out = main(1, 0x5a, [0xa003], 5, 9);
    let mut root = tree::leaf_hash(1, 0xa003, 0, [5, 1, 9]);
    let z = tree::zeros::<D>();
    for l in 0..D {
        root = tree::node(root, z[l]);
    }
    assert_eq(out.new_hashes, [tree::leaf_hash(1, 0xa003, 0, [5, 1, 9])]);
    assert_eq(out.new_c, tree::commitment(1, 0xa003, root));
    assert_eq(out.request_id, intake::plain(1, 0x5a, [5], 0));
}
