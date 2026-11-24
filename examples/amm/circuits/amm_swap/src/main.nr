// Manifest: examples/amm/manifests/amm_swap.json.
// - State mode: both keys are node-held: the pool is shared state, and an
//   abandoned round must not block other traders.
// - DEV DECISION: consume policy, default "once" on the pool key; the
//   round rewrites the key, so the old row is gone anyway, and "once" also
//   refuses a repeat of the same pool state: each held state yields at
//   most one evaluation, so a trader cannot replay one pool state with
//   many amounts to collect quotes. Design guide: "consume policy".

use amm::pool::Pool;
use pss_core::effects::{self, PssEffects};

/// One swap: consume the pool note, apply the trade, create the new pool
/// note (normally at the same slot) and reveal only `amount_out`.
///
/// The contract proves `read_leaves[0]` is in the note-hash tree, pushes
/// `nullifiers[0]` and `new_note_hashes[0]`, asserts `npk_app_hash`, and
/// passes `amount_in` and `direction` in as public inputs, so the proof
/// is bound to the trade the caller asked for.
///
/// `amount_in` and `direction` are typed, so the compiler range-checks
/// them (below 2^64; 0 or 1) and the machine refuses an out-of-range
/// request before any MPC round starts. Each is still one public-input
/// field, and the contract passes them as Fields.
///
/// Public inputs (11), in ACIR order (pub params, then the return struct):
///   [namespace, owner, in_slots[0], out_slots[0],
///    amount_in, direction,
///    read_leaves[0], nullifiers[0], new_note_hashes[0], npk_app_hash,
///    app_outputs[0] = amount_out]
fn main(
    // ---- canonical public prefix ----
    namespace: pub Field,
    owner: pub Field,
    // Key binding: in_slots[0] comes from $state_keys.reads[0] and out_slots[0]
    // from $state_keys.writes[0]; both are baked into the note
    // hashes. The contract passes POOL_SLOT for both, so a request naming
    // other keys produces a proof the contract rejects.
    in_slots: pub [Field; 1],
    out_slots: pub [Field; 1],
    // ---- app public inputs ----
    // DEV DECISION: the trade's visibility, default amount_in and direction
    // PUBLIC, not INPUT_SHARED; the contract binds them (a token transfer
    // would use them), and the chain sees the transfer anyway. A private
    // trade size would need INPUT_SHARED and a contract that never learns
    // it. Design guide: "The questions, in order" (1, who must not see the
    // inputs).
    // amount sold
    amount_in: pub u64,
    // false (0) sells x for y, true (1) sells y for x
    direction: pub bool,
    // ---- consumed pool note: [reserve_x, reserve_y] ----
    in0_fields: [Field; 2],
    in0_randomness: Field,
    in0_nonce: Field,
    // ---- created pool note: blinding sampled by the network ----
    out0_randomness: Field,
    // nsk_app, the namespace's nullifier key, taken by this name (the fixed
    // LOAD nsk_app) and used directly as the key. The round outputs
    // npk_app_hash(nsk_app) for the contract's pin.
    nsk_app: Field,
) -> pub PssEffects<1, 1, 1> {
    // BRICK path = sidecar (pss_core::effects::consume_note): the round returns PssEffects, which the
    // contract's apply lands. Alternatives: tip (pss_core tip::slot and the queue: examples/amm-tip).
    // docs/design-guide/BRICKS.md#path
    let (pool_leaf, pool_nullifier) = effects::consume_note(
        namespace,
        owner,
        in_slots[0],
        in0_fields,
        in0_randomness,
        in0_nonce,
        nsk_app,
    );

    let pool = Pool::from_field_array(in0_fields);
    let (new_pool, amount_out) = pool.swap(amount_in, direction);
    let new_pool_note_hash =
        effects::create_note(0, owner, out_slots[0], new_pool.as_field_array(), out0_randomness);

    PssEffects {
        read_leaves: [pool_leaf],
        nullifiers: [pool_nullifier],
        new_note_hashes: [new_pool_note_hash],
        npk_app_hash: effects::npk_app_hash(nsk_app),
        // The reveal: amount_out is public, and with
        // amount_in it gives the pool's marginal price. Two quotes solve
        // both reserves up to rounding: two against one state (CONSUME
        // once refuses that repeat) or two consecutive swaps, since each
        // swap's change to the reserves is public. Hiding the reserves
        // needs a coarser output or a private trade size.
        app_outputs: [amount_out as Field],
    }
}
