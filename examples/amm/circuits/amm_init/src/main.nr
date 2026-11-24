// Manifest: examples/amm/manifests/amm_init.json.
// - DEV DECISION: state mode, default node-held for every key of the pool
//   (seed and pool); the pool is shared state that many users transition,
//   and client-held shared state would make every user depend on the last
//   one publishing the latest record. Client-held fits single-owner state,
//   such as a player's game. Node-held costs a values table at the nodes,
//   and a round that never lands needs the operator's rollback. Design
//   guide: "State mode" (the note-client blueprint's node-held deviation).
// - Consume: the seed key with policy "once". This round reads the seed
//   and does not rewrite it, so without CONSUME the seed could be loaded
//   again and a second pool derived from it. "once" gives one evaluation
//   per held state; "never" would let every repeat run again.

use amm::pool::Pool;
use pss_core::effects::{self, PssEffects};

/// Start the pool: consume the seed note (so the pool cannot be seeded
/// twice), derive the starting reserves from it, and create the pool
/// note.
///
/// The contract proves `read_leaves[0]` is in the note-hash tree, pushes
/// `nullifiers[0]` and `new_note_hashes[0]`, and asserts `npk_app_hash`
/// against the identity its Config pins.
///
/// Public inputs (8), in ACIR order (pub params, then the return struct):
///   [namespace, owner, in_slots[0], out_slots[0],
///    read_leaves[0], nullifiers[0], new_note_hashes[0], npk_app_hash]
fn main(
    // ---- canonical public prefix ----
    namespace: pub Field,
    owner: pub Field,
    // Key binding: in_slots[0] (from $state_keys.reads[0], the
    // key LOAD reads) and out_slots[0] (from $state_keys.writes[0], the key
    // STORE writes) are the note slots baked into the note hashes, so the
    // value loaded is the note read-requested, and the stored value is
    // the note pushed.
    // the seed note's slot
    in_slots: pub [Field; 1],
    // the pool note's slot
    out_slots: pub [Field; 1],
    // ---- consumed seed note (from the store) ----
    in0_fields: [Field; 1],
    in0_randomness: Field,
    // protocol nonce; self-verifying: a wrong nonce yields a leaf the
    // contract's read request cannot find
    in0_nonce: Field,
    // ---- created pool note: blinding sampled by the network ----
    out0_randomness: Field,
    // nsk_app, the namespace's nullifier key, taken by this name (the fixed
    // LOAD nsk_app) and used directly as the key. The round outputs
    // npk_app_hash(nsk_app) for the contract's pin.
    nsk_app: Field,
) -> pub PssEffects<1, 1, 0> {
    let (seed_leaf, seed_nullifier) = effects::consume_note(
        namespace,
        owner,
        in_slots[0],
        in0_fields,
        in0_randomness,
        in0_nonce,
        nsk_app,
    );

    let pool = Pool::from_seed(in0_fields[0]);
    let pool_note_hash =
        effects::create_note(0, owner, out_slots[0], pool.as_field_array(), out0_randomness);

    PssEffects {
        read_leaves: [seed_leaf],
        nullifiers: [seed_nullifier],
        new_note_hashes: [pool_note_hash],
        npk_app_hash: effects::npk_app_hash(nsk_app),
        app_outputs: [],
    }
}
