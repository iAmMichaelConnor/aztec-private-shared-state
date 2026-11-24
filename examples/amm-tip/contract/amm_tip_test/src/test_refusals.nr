//! The refusals beyond the basic cases of test_intake.nr, test_result.nr
//! and test_init.nr that are this app's: the swap's vk pin against the
//! init's, an exact replay of the init result, and the init result through
//! the swap's result function. The library's own rules (the receipts, a
//! repeated or applied request id, the request id binding, each wrong or
//! missing signature, the namespace the nodes sign under, the wrong head,
//! the moved slot, the stale clock) are pss_public_contract_test's.
use crate::{
    AMOUNT_IN, C1, C_INIT, init_id, init_vk, NONCE_A, ok_round,
    round_signatures, setup, submit_with, swap, swap_vk, swap_with_receipts,
};

// ---- process_result: the swap's vk pin ---------------------------------------

// The result function is pinned to the swap's package: the init's proof is
// refused there.
#[test(should_fail_with = "unexpected verification key")]
unconstrained fn an_on_chain_intake_result_under_the_init_vk_is_refused() {
    let s = setup();
    let a = swap(s, AMOUNT_IN, NONCE_A);
    let r = ok_round(a, C_INIT, C1);
    let _ = submit_with(s, init_vk(), r, round_signatures(s, r));
}

// A result for the init round cannot be landed as a swap: the init request
// id is never queued.
#[test(should_fail_with = "not the head")]
unconstrained fn the_init_result_through_process_result_is_refused() {
    let s = setup();
    let _ = swap_with_receipts(s, AMOUNT_IN, NONCE_A);
    let r = ok_round(init_id(s), C_INIT, C1);
    let _ = submit_with(s, swap_vk(), r, round_signatures(s, r));
}
