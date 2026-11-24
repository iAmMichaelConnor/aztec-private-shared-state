//! One refusal per app rule: the request functions' static checks (refused
//! in the requester's PXE, nothing queued), the uninitialised ledger, the
//! init row that is no queued round, and a result named with another round,
//! whose row pins another vk.
use crate::{claim, deploy, empty_map, move_to, pay, pay_round, setup, submit_as, vk_of};
use credits_tip::app::{payee_handle, ROUND_CLAIM, ROUND_PAY};
use pss_public_contract::TWO_POW_64;

global SECRET_A: Field = 0xa5ec;

#[test(should_fail_with = "invalid inputs")]
unconstrained fn a_pay_of_nothing_is_refused() {
    let s = setup();
    let _ = pay(s, s.bob, payee_handle(s.alice, SECRET_A), 0, 0x9a01);
}

#[test(should_fail_with = "invalid inputs")]
unconstrained fn a_pay_to_the_handle_zero_is_refused() {
    let s = setup();
    let _ = pay(s, s.bob, 0, 500, 0x9a01);
}

#[test(should_fail_with = "invalid inputs")]
unconstrained fn a_claim_of_more_than_a_u64_is_refused() {
    let s = setup();
    let _ = claim(s, s.alice, SECRET_A, TWO_POW_64, 0x9a01);
}

#[test(should_fail_with = "invalid inputs")]
unconstrained fn a_move_to_the_senders_own_key_is_refused() {
    let s = setup();
    let _ = move_to(s, s.alice, SECRET_A, payee_handle(s.alice, SECRET_A), 100, 0x9a01);
}

#[test(should_fail_with = "state not initialised")]
unconstrained fn a_request_before_the_init_is_refused() {
    let s = deploy();
    let _ = pay(s, s.bob, payee_handle(s.alice, SECRET_A), 500, 0x9a01);
}

#[test(should_fail_with = "not a queued round")]
unconstrained fn the_init_row_is_no_queued_round() {
    let s = setup();
    let r = pay(s, s.bob, payee_handle(s.alice, SECRET_A), 500, 0x9a01);
    submit_as(s, 0, vk_of(0), pay_round(s, empty_map(s), r, 0x111).outputs);
}

// A pay round's result named as a claim: the claim row pins the claim's vk
// hash, and the pay proof's vk is another.
#[test(should_fail_with = "unexpected verification key")]
unconstrained fn a_result_named_as_another_round_is_refused() {
    let s = setup();
    let r = pay(s, s.bob, payee_handle(s.alice, SECRET_A), 500, 0x9a01);
    submit_as(s, ROUND_CLAIM, vk_of(ROUND_PAY), pay_round(s, empty_map(s), r, 0x111).outputs);
}
