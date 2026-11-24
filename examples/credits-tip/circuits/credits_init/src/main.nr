//! The credits ledger's init round (examples/credits-tip README): creates the
//! map key with the empty keyed map, nothing written. Never queued: the
//! operator's deployment runs it once (its manifest's intake is on-chain
//! intake with no app inputs; the network samples `r_new`).
//!
//! Public inputs (7), in ACIR order: [namespace, vk_hash, out_slots[0],
//! request_id, old_c, new_c, npk_app_hash] (pss_core `outputs::Init<0>`:
//! no leaf hash). The stored vector (TACEO_store "out0") is the one slot's
//! empty leaf, hash and 64 path nodes, 68 elements, which the nodes' first
//! session applies to their oblivious RAM (an untouched address already
//! reads as the empty node, so the write changes nothing).
//!
//! The manifest (manifests/credits_init.json): the public prefix, `r_new`
//! SAMPLE 1, `nsk_app` the fixed LOAD; out0 stored under $state_keys.writes[0]
//! with note hash `new_c`; the tree entry of a keyed map created
//! (`access: oblivious, keyed: true`, depth 64, leaf_len 3, probe 1).
//!
//! Constraints: pss_core's `tree::empty` on constants (folded), one
//! commitment, `init`'s request id and npk_app_hash. No assert.

use credits_tip::ledger::{DEPTH, LEAF_LEN};
use pss_core::tip::map;
use pss_core::tip::outputs::{Init, Written};
use pss_core::tip::tree::{commitment, Oblivious, zeros};

fn main(
    namespace: pub Field,
    vk_hash: pub Field,
    out_slots: pub [Field; 1],
    // the blinding of the unused slot's leaf, SAMPLE 1 (never written: the slot stays empty)
    r_new: Field,
    nsk_app: Field,
) -> pub Init<0> {
    // the key the one slot names is 0 (path 0), unused: the map is created empty
    let m = map::empty::<1, DEPTH, LEAF_LEN>(namespace, out_slots[0], [0], 1);
    let (updated, paths) = m.update(true, [false], [[0]], [r_new]);
    let created: Oblivious<1, LEAF_LEN, DEPTH, 0> = Oblivious { updated, paths };
    created.init(namespace, vk_hash, [], nsk_app)
}

#[test]
fn the_map_is_created_empty() {
    let out = main(0xc0ffee, 0x5a, [0xa004], 333, 777);
    assert_eq(out.old_c, 0);
    assert_eq(out.new_c, commitment(0xc0ffee, 0xa004, zeros::<DEPTH>()[DEPTH]));
}
