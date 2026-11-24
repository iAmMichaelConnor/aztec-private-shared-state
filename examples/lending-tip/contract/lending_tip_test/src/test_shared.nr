//! The secret-shared deployment (`SHARED_PACKAGES`: the init and the secret-shared entries
//! of deposit, borrow, repay, view, liquidate and scan; the scan is
//! test_keeper.nr's): secret-shared receipt intake with private outcomes
//! delivered by partial-note completion, through lib.nr's
//! secret-shared-intake helpers.
//!
//! - Intake: each request function commits the sender's partial note, checks
//!   the three node receipts over C, takes the usage deposit and its escrow,
//!   and queues the chain request id through the one wrapper
//!   `append_receipt(request_id, expiry_block, escrow, held)`.
//! - Result: each `process_shared` or `process_header_shared` lands the round's completed note hash
//!   (the requester's partial note completed by the round) and its outcome
//!   log, and the one `apply_shared` writes the new commitment (re-blinded
//!   on every outcome); the result transactions of every round type have the
//!   same effects and a log of the full 16 fields (test_round_shape.nr).
//! - The user opens its outcome from the log with its outcome key, delivers
//!   the completed note with its rho and `redeem`s it: a borrow's redeem pays
//!   the amount once, in the borrowed asset, into a token note of the
//!   user's, and the note stays readable.
//!
//! The outcomes are stand-ins encrypted with the round's own functions
//! (`pss_core::tip::outcome::encrypt_outcome` at the contract's outcome
//! slot), with the values of the race (`lib.nr`: Alice opens
//! position 1 with 1,000, borrows 1,700, the liquidation seizes 446 and
//! repays 850 of a budget of 1,000); the circuits' own tests (circuits/lending_tip rounds.nr)
//! prove that the secret-shared rounds encrypt exactly these outcomes, and the
//! fixtures' ciphertexts open to them.
//! The proofs are dummy capsules, as in the rest of the suite.
use crate::{
    LIQUIDATED, OPENED,
    BORROWER,
    BORROW, ROUND_BORROW, BUDGET, C1, C2, C3, C_INIT, DEPOSIT, ROUND_DEPOSIT, EPOCH, hold,
    market, deposit_from, FUNDED, open_and_deliver, outcome_notes, POSITION, PRICE,
    credit, redeem, REPAY_OUT, request_liquidation, request_owner,
    request_view, rho_of, SEIZE_OUT, shared_setup, submit_shared, USAGE_DEPOSIT,
};
use aztec::protocol::traits::Packable;
use lending_market::app::{LendingOutcome, OUTCOME_SLOT};
use pss_public_contract::DONE_APPLIED;

fn note(outcome: [Field; 7], request_id: Field) -> LendingOutcome {
    LendingOutcome::unpack(outcome.concat([request_id]))
}

// the race's outcomes in the one shape [code, position, mask, x, y, payout,
// aux] beside lib.nr's opening and liquidation: Alice's borrow (the payout
// is the amount) and a view after it
global BORROWED: [Field; 7] = [0, POSITION, BORROWER, DEPOSIT, BORROW, BORROW, 0];
global VIEWED: [Field; 7] = [0, POSITION, BORROWER, DEPOSIT, BORROW, 0, 0];
// a borrow refused at the borrow limit: the request named its open
// position, so the note reports it as it stands, and pays nothing
global UNHEALTHY: [Field; 7] = [9, POSITION, BORROWER, DEPOSIT, 0, 0, 0];

// The circuits hash the completed note at the contract's outcome slot.
// The secret-shared race: each outcome log opens to the race's outcome, the
// user's PXE holds each completed note once delivered (the opening's note
// lets it borrow and view), and a view after the deposit and the borrow
// reports the position's collateral and debt. Every apply writes its new
// commitment and finishes the head.
#[test]
unconstrained fn the_shared_race_outcomes_open_to_the_plain_race_table() {
    let s = shared_setup();
    assert_eq(s.queue().state().outcome_slot, OUTCOME_SLOT);
    let d = request_owner(s, s.user, ROUND_DEPOSIT, 0, DEPOSIT, 1);
    let tx = submit_shared(s, d, C_INIT, C1, PRICE, EPOCH, OPENED);
    assert_eq(open_and_deliver(s, d, tx), OPENED);
    assert_eq(market(s), C1);
    assert_eq(outcome_notes(s, s.user).first, note(OPENED, d.id));
    let b = request_owner(s, s.user, ROUND_BORROW, POSITION, BORROW, 2);
    let tx = submit_shared(s, b, C1, C2, PRICE, EPOCH, BORROWED);
    assert_eq(open_and_deliver(s, b, tx), BORROWED);
    let v = request_view(s, POSITION, 3);
    let tx = submit_shared(s, v, C2, C3, PRICE, EPOCH, VIEWED);
    assert_eq(open_and_deliver(s, v, tx), VIEWED);
    assert_eq(market(s), C3);
    assert_eq(s.queue().head().index, 3);
    for i in 0..3 {
        assert_eq(s.queue().done_at(i as u64), DONE_APPLIED);
    }
    assert_eq(outcome_notes(s, s.user).count, 3);
    // the liquidator's outcome reaches the liquidator only
    let l = request_liquidation(s, 4);
    let tx = submit_shared(s, l, C3, C1 + 0x10, PRICE, EPOCH, LIQUIDATED);
    assert_eq(open_and_deliver(s, l, tx), LIQUIDATED);
    assert_eq(outcome_notes(s, s.other).count, 1);
    assert_eq(outcome_notes(s, s.other).first, note(LIQUIDATED, l.id));
    assert_eq(outcome_notes(s, s.user).count, 3);
}

// The user holds a note of POSITION (the market holds its collateral to pay
// a seize from) and borrows: the redeem pays the payout, the borrowed
// amount, from the market's public balance of the borrowed asset into a
// token note of the user's; the note stays readable (a redeem nullifier,
// never the note's own). A liquidation's redeem pays the seize in the
// collateral asset and the unused budget in the borrowed asset: the
// liquidator paid the budget and the deposit in, and gets back the 150 of
// the budget it did not use. A failed round lands like any other: its
// outcome says why, and its new commitment (the book re-blinded) is
// written.
#[test]
unconstrained fn redeems_pay_a_borrow_and_a_liquidation_and_a_failed_round_lands() {
    let s = shared_setup();
    let _ = hold(s, s.user, POSITION, 1);
    let b = request_owner(s, s.user, ROUND_BORROW, POSITION, BORROW, 2);
    let tx = submit_shared(s, b, C_INIT, C1, PRICE, EPOCH, BORROWED);
    let _ = open_and_deliver(s, b, tx);
    assert_eq(outcome_notes(s, s.user).count, 2);
    // the opening and the borrow paid a usage deposit each
    let before = credit(s, s.user)[1];
    assert_eq(before, FUNDED - 2 * USAGE_DEPOSIT);
    redeem(s, s.user, b.id);
    assert_eq(credit(s, s.user)[1], before + BORROW);
    assert_eq(outcome_notes(s, s.user).count, 2);

    let l = request_liquidation(s, 3);
    assert_eq(credit(s, s.other)[1], FUNDED - BUDGET - USAGE_DEPOSIT);
    let tx = submit_shared(s, l, C1, C2, PRICE, EPOCH, LIQUIDATED);
    let _ = open_and_deliver(s, l, tx);
    redeem(s, s.other, l.id);
    assert_eq(credit(s, s.other)[0], FUNDED + SEIZE_OUT);
    assert_eq(credit(s, s.other)[1], FUNDED - REPAY_OUT - USAGE_DEPOSIT);

    let f = request_owner(s, s.user, ROUND_BORROW, POSITION, BORROW, 4);
    let tx = submit_shared(s, f, C2, C3, PRICE, EPOCH, UNHEALTHY);
    assert_eq(open_and_deliver(s, f, tx), UNHEALTHY);
    assert_eq(market(s), C3);
    assert_eq(s.queue().done_at(3), DONE_APPLIED);
    assert_eq(outcome_notes(s, s.user).count, 3);
}

// The secret-shared deployment lists no non-secret-shared round: a non-secret-shared deposit is refused.
#[test(should_fail_with = "package not in this deployment")]
unconstrained fn the_shared_deployment_refuses_a_plain_request() {
    let s = shared_setup();
    deposit_from(s, s.user, 0, DEPOSIT, rho_of(1), 0xa1);
}
