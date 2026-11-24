//! The task's cases the other modules leave out, non-secret-shared and secret-shared:
//!
//! - the race (README, "Fixtures") on the secret-shared deployment, both orders: the
//!   repayment first (the liquidation behind it liquidates nothing) and the
//!   liquidation first (the repayment behind it lands on what the
//!   liquidation left, the owner's note of before the liquidation still
//!   opening its request);
//! - a price change between the round and `apply` on the secret-shared deployment:
//!   a price the epoch never had reverts, a round one epoch behind lands and
//!   a round recomputed at the current epoch lands (a round two epochs
//!   behind reverting is test_round_shape.nr's, on a view);
//! - a non-secret-shared deposit into the owner's position from the owner
//!   (its note opens the request) and the failure of such a deposit returning
//!   its escrow under each non-secret-shared intake;
//! - the stale rule on the secret-shared deployment: `skip()` drops a stale secret-shared
//!   request, returns its escrow and its usage deposit into the
//!   requester's token refund notes, and the next request runs on the kept
//!   commitment.
//!
//! As in the rest of the suite the rounds are stand-ins (no circuit runs
//! here): the outcomes are the fixtures' (circuits/*_shared/Prover*.toml
//! comments), encrypted with the circuits' own `encrypt_outcome`.
use crate::{
    HEALTHY, LIQUIDATED,
    applied_on, assert_state, BORROW, ROUND_BORROW, BUDGET, C1, C2, C_INIT, DEPOSIT, deposit_from,
    deposit_with, deposited, EPOCH, failed_round, held_setup, LOW_PRICE, market,
    mine_until_next_block_is, FUNDED, NONCE_C, node_receipts, open_and_deliver, outcome_notes,
    plain_id, POSITION, PRICE, credit, REPAY, ROUND_REPAY,
    request_liquidation, request_owner, rho_of, set_price, setup, STALE, submit_deposit,
    submit_shared, USAGE_DEPOSIT, user_partial,
};
use aztec::test::helpers::txe_oracles;
use lending_tip::LendingTip;
use pss_public_contract::{DONE_APPLIED, DONE_SKIPPED, Head};

// ---- non-secret-shared -------------------------------------------------------

// The owner deposits again into its position, once under each
// non-secret-shared intake: each request opens the owner's note of the
// position (completed by its opening deposit's apply) and queues; each round
// here fails (a stand-in code 7) and applies as an ok = 0 no-op: the book
// stays, the head moves, each note says why, and each deposit's escrow comes
// back to the owner (`ok` is public here, so `apply` returns it); the usage
// deposits are kept.
#[test]
unconstrained fn deposits_into_an_open_position_return_their_escrow_when_they_fail() {
    let s = setup();
    deposited(s);
    deposit_from(s, s.user, POSITION, DEPOSIT, rho_of(NONCE_C), NONCE_C);
    let d = plain_id(s, POSITION, DEPOSIT, user_partial(s, NONCE_C), NONCE_C);
    let expiry = s.env.next_block_number() + 10;
    let p = user_partial(s, NONCE_C + 1);
    let receipts = node_receipts(s, POSITION, DEPOSIT, p, NONCE_C + 1, expiry);
    deposit_with(s, s.user, POSITION, DEPOSIT, rho_of(NONCE_C + 1), NONCE_C + 1, expiry, receipts);
    let r = plain_id(s, POSITION, DEPOSIT, p, NONCE_C + 1);
    assert_eq([s.queue().request_at(1), s.queue().request_at(2)], [d, r]);
    assert_eq(credit(s, s.user)[0], FUNDED - 3 * DEPOSIT);
    let _ = submit_deposit(s, failed_round(d, C1, 7).with_partial(user_partial(s, NONCE_C)));
    let _ = submit_deposit(s, failed_round(r, C1, 7).with_partial(p));
    assert_state(s, 3, 3, C1);
    assert_eq(s.queue().done_at(1), DONE_APPLIED);
    assert_eq(s.queue().done_at(2), DONE_APPLIED);
    assert_eq(outcome_notes(s, s.user).count, 3);
    assert_eq(credit(s, s.user)[0], FUNDED - DEPOSIT);
    assert_eq(credit(s, s.user)[1], FUNDED - 3 * USAGE_DEPOSIT);
    assert_eq(s.env.view_public(LendingTip::at(s.app).get_kept_deposits()), 3 * USAGE_DEPOSIT as u128);
}

// Another account, holding no note of the position, cannot deposit into it
// under either non-secret-shared intake: refused in its private function.
#[test(should_fail_with = "the sender holds no note of this position")]
unconstrained fn a_plain_deposit_into_another_accounts_position_is_refused() {
    let s = setup();
    deposited(s);
    deposit_from(s, s.other, POSITION, DEPOSIT, rho_of(NONCE_C), NONCE_C);
}

#[test(should_fail_with = "the sender holds no note of this position")]
unconstrained fn a_receipt_intake_deposit_into_another_accounts_position_is_refused() {
    let s = setup();
    deposited(s);
    let expiry = s.env.next_block_number() + 10;
    let p = crate::partial_of(s.other, rho_of(NONCE_C));
    let receipts = node_receipts(s, POSITION, DEPOSIT, p, NONCE_C, expiry);
    deposit_with(s, s.other, POSITION, DEPOSIT, rho_of(NONCE_C), NONCE_C, expiry, receipts);
}

// ---- secret-shared -----------------------------------------------------------
//
// The secret-shared deployment with the user holding its note of POSITION
// (lib.nr's `held_setup`: queue index 0 is that opening, the market still
// C_INIT) through lib.nr's secret-shared-intake helpers.

// The secret-shared race, repayment first: Alice's repayment lands (1,000 / 1,300),
// then the liquidation finds both probes healthy: its outcome reports an
// empty mask and returns the whole budget, and the book is re-blinded (a
// new commitment).
#[test]
unconstrained fn the_shared_race_with_the_repay_first_liquidates_nothing() {
    let s = held_setup();
    set_price(s, LOW_PRICE);
    let r = request_owner(s, s.user, ROUND_REPAY, POSITION, REPAY, 1);
    let l = request_liquidation(s, 2);
    let repaid = applied_on(POSITION, 1000, 1300, 0);
    let tx = submit_shared(s, r, C_INIT, C1, LOW_PRICE, EPOCH + 1, repaid);
    assert_eq(open_and_deliver(s, r, tx), repaid);
    let tx = submit_shared(s, l, C1, C2, LOW_PRICE, EPOCH + 1, HEALTHY);
    assert_eq(open_and_deliver(s, l, tx), HEALTHY);
    assert_state(s, 3, 3, C2);
    assert_eq(outcome_notes(s, s.user).count, 2);
    assert_eq(outcome_notes(s, s.other).count, 1);
}

// The secret-shared race, liquidation first: the liquidator's outcome reports the
// mask, 446 seized and 850 repaid (150 of its budget unused), then Alice's
// repayment lands on what the liquidation left (554 / 450). Her note of
// before the liquidation, stale now, still opened the repayment's request:
// the leaf is the authority, and the round's checks decide.
#[test]
unconstrained fn the_shared_race_with_the_liquidation_first_lets_the_repay_behind_it_land() {
    let s = held_setup();
    set_price(s, LOW_PRICE);
    let l = request_liquidation(s, 1);
    let tx = submit_shared(s, l, C_INIT, C1, LOW_PRICE, EPOCH + 1, LIQUIDATED);
    assert_eq(open_and_deliver(s, l, tx), LIQUIDATED);
    // the user's only note still reports the collateral the liquidation seized
    let stale = outcome_notes(s, s.user);
    assert_eq(stale.count, 1);
    assert_eq(stale.first.x, DEPOSIT);
    let r = request_owner(s, s.user, ROUND_REPAY, POSITION, REPAY, 2);
    let after = applied_on(POSITION, 554, 450, 0);
    let tx = submit_shared(s, r, C1, C2, LOW_PRICE, EPOCH + 1, after);
    assert_eq(open_and_deliver(s, r, tx), after);
    assert_state(s, 3, 3, C2);
    assert_eq(s.queue().done_at(1), DONE_APPLIED);
    assert_eq(s.queue().done_at(2), DONE_APPLIED);
    assert_eq(outcome_notes(s, s.user).count, 2);
}

// One epoch behind, at a price that epoch never had: refused.
#[test(should_fail_with = "pinned read changed")]
unconstrained fn a_shared_liquidation_at_another_price_of_the_epoch_is_refused() {
    let s = held_setup();
    let l = request_liquidation(s, 1);
    set_price(s, LOW_PRICE);
    assert_state(s, 1, 2, C_INIT);
    let _ = submit_shared(s, l, C_INIT, C1, LOW_PRICE, EPOCH, LIQUIDATED);
}

// A round one epoch behind the oracle lands; after two more epochs the
// next round, recomputed at the current price and epoch, lands too.
#[test]
unconstrained fn a_shared_round_one_epoch_behind_lands_and_a_recomputed_one_lands() {
    let s = held_setup();
    let b = request_owner(s, s.user, ROUND_BORROW, POSITION, BORROW, 1);
    set_price(s, PRICE + 1);
    let borrowed = applied_on(POSITION, 1000, BORROW, BORROW);
    let tx = submit_shared(s, b, C_INIT, C1, PRICE, EPOCH, borrowed);
    assert_eq(open_and_deliver(s, b, tx), borrowed);
    let r = request_owner(s, s.user, ROUND_REPAY, POSITION, REPAY, 2);
    set_price(s, PRICE + 2);
    set_price(s, PRICE + 3);
    let repaid = applied_on(POSITION, 1000, 1300, 0);
    let tx = submit_shared(s, r, C1, C2, PRICE + 3, EPOCH + 3, repaid);
    assert_eq(open_and_deliver(s, r, tx), repaid);
    assert_state(s, 3, 3, C2);
}

// The stale rule on the secret-shared deployment: once the head has sat
// stale_blocks, anyone skips it; the skip returns what the request put in,
// in public, into the requester's token refund notes (a liquidation's
// budget and its usage deposit: one completion each), the market keeps its
// commitment, and the next request runs on it and lands.
#[test]
unconstrained fn a_stale_shared_request_is_skipped_and_returns_its_escrow() {
    let s = held_setup();
    let kept = USAGE_DEPOSIT as u128;
    let _ = request_liquidation(s, 1);
    let since = s.queue().head().since;
    assert_eq(credit(s, s.other)[1], FUNDED - BUDGET - USAGE_DEPOSIT);
    let r = request_owner(s, s.user, ROUND_REPAY, POSITION, REPAY, 2);
    mine_until_next_block_is(s, since + STALE);
    s.env.call_public(s.user, LendingTip::at(s.app).skip());
    let block = s.env.last_block_number();
    let effects = txe_oracles::get_last_tx_effects();
    assert_eq(effects.note_hashes.len(), 2);
    assert_eq(effects.private_logs.len(), 0);
    assert_eq(s.queue().head(), Head { index: 2, since: block });
    assert_eq(s.queue().done_at(1), DONE_SKIPPED);
    assert_eq(market(s), C_INIT);
    assert_eq(outcome_notes(s, s.other).count, 0);
    assert_eq(credit(s, s.other)[1], FUNDED);
    assert_eq(s.env.view_public(LendingTip::at(s.app).get_kept_deposits()), kept);
    let repaid = applied_on(POSITION, 1000, 1300, 0);
    let tx = submit_shared(s, r, C_INIT, C1, PRICE, EPOCH, repaid);
    assert_eq(open_and_deliver(s, r, tx), repaid);
    assert_state(s, 3, 3, C1);
    // the repayment's escrow stays (it applied), its deposit is kept
    assert_eq(s.env.view_public(LendingTip::at(s.app).get_kept_deposits()), 2 * kept);
}
