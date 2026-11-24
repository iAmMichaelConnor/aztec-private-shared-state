//! The init round: creates the counter key with the total 0 under a sampled
//! blinding and outputs its commitment, the first value of the contract's
//! `counter` slot. Never queued: the operator's deployment runs it once and
//! the contract lands it once, while the slot is empty.
//!
//! Public inputs (7), in ACIR order: [namespace, vk_hash, out_slots[0],
//! request_id, old_c = 0, new_c, npk_app_hash] (pss_core
//! `tip::outputs::Init`).
//!
//! The manifest (manifests/counter_init.json): `namespace` PUBLIC
//! $namespace, `vk_hash` PUBLIC $vk_hash, `out_slots` PUBLIC
//! [$state_keys.writes[0]], `r_new` SAMPLE 1, `nsk_app` the fixed LOAD; out0
//! stored under $state_keys.writes[0] (state mode node) with note hash
//! `new_c`.
use pss_core::tip::outputs::{Init, Written};
use pss_core::tip::slot;

fn main(namespace: pub Field, vk_hash: pub Field, out_slots: pub [Field; 1], r_new: Field, nsk_app: Field) -> pub Init<0> {
    // BRICK shape = flat (pss_core::tip::slot::create). Alternatives: tree, tree_oblivious,
    // map_oblivious (pss_core tip::tree and tip::map). docs/design-guide/BRICKS.md#shape
    slot::create(namespace, out_slots[0], [0], r_new).init(namespace, vk_hash, [], nsk_app)
}
