//! The AMM tip's swap (examples/amm-tip's amm_swap_tip, through the same
//! amm_tip::tip::swap_round) with its min_out a pinned read instead of an app
//! input, for the orchestrator's node-held state test
//! (sidecar-orchestrator tests/node_held.rs), where a moved pinned value
//! forces a recompute. A pinned value is a public input of the round and an
//! app input never is, so the variant is a circuit of its own: the request's
//! app inputs are [amount_in, direction], private, and the round outputs the
//! request id over them.
//!
//! Public inputs (12), in ACIR order: [namespace, vk_hash, in_slots[0],
//! out_slots[0], min_out, request_id, old_c, new_c, npk_app_hash, ok, code,
//! amount_out], the contract library's layout with one pinned read.

use amm_tip::tip::{PlainRound, swap_round, SwapOutputs};
use pss_core::tip::family::Plain;
use pss_core::tip::{intake, slot};
use pss_core::tip::outputs::{Bound, Written};

fn main(
    namespace: pub Field,
    vk_hash: pub Field,
    in_slots: pub [Field; 1],
    out_slots: pub [Field; 1],
    // the pinned read
    min_out: pub Field,
    // the app inputs and the nonce
    amount_in: Field,
    direction: Field,
    user_nonce: Field,
    pool: [Field; 2],
    r_old: Field,
    r_new: Field,
    nsk_app: Field,
) -> pub Bound<SwapOutputs> {
    let key = slot::load(namespace, in_slots[0], out_slots[0], pool, r_old, r_new);
    // the round over the pool key and amount_out alone; this circuit binds
    // its own request id over the app inputs without min_out
    let r: PlainRound = swap_round(
        0,
        key,
        [amount_in, direction, min_out],
        Plain { partial_note: 0, user_nonce: 0 },
        0,
    );
    let outputs =
        SwapOutputs { code: r.written.outcome.code, amount_out: r.outputs.app.amount_out };
    let request_id = intake::plain(namespace, vk_hash, [amount_in, direction], user_nonce);
    r.written.bound(request_id, nsk_app, outputs)
}
