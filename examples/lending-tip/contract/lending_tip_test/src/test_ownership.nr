//! Ownership by note on the secret-shared deployment (docs/ARCHITECTURE.md
//! section 6, "Ownership by note"): a request on an open position is admitted
//! only for an account that holds a note of it (`assert_holds`, in the request's
//! private function: the round never sees an owner), and a note's value is spent
//! once by `redeem` while the note keeps conferring its position.
//!
//! - who may act: the holder of a note reporting success on the position;
//!   an account with no note of it, a note of another position, a failed
//!   round's note and a liquidation's note (position 0) confer nothing;
//! - one note opens any number of requests (two outstanding ones both
//!   queue), each with a partial note of its own: a partial note is used
//!   once;
//! - redeem: once per note, by its owner only, never for a note that pays
//!   nothing; the note stays readable and still opens a request.
//!
//! The rounds are stand-ins, as in the rest of the suite.
use crate::{
    BORROWER,
    applied_on, BORROW, ROUND_BORROW, C1, C2, C_INIT, DEPOSIT, ROUND_DEPOSIT, EPOCH, held_setup, hold,
    ROUND_LIQUIDATE, open_and_deliver, OTHER_POSITION, outcome_notes, POSITION, PRICE, redeem, REPAY,
    ROUND_REPAY, request_liquidation, request_owner, request_view_by, SEIZE_OUT, REPAY_OUT, BUDGET,
    shared_setup, submit_shared, COLLATERAL_ASSET,
};
use lending_market::app::LendingOutcome;
use aztec::protocol::traits::Packable;

// ---- who may act --------------------------------------------------------------

// An account that holds no note of the position cannot request a round on
// it: its private function refuses before anything is queued.
#[test(should_fail_with = "the sender holds no note of this position")]
unconstrained fn a_borrow_by_an_account_without_a_note_is_refused() {
    let s = held_setup();
    let _ = request_owner(s, s.other, ROUND_BORROW, POSITION, BORROW, 1);
}

#[test(should_fail_with = "the sender holds no note of this position")]
unconstrained fn a_view_by_an_account_without_a_note_is_refused() {
    let s = held_setup();
    let _ = request_view_by(s, s.other, POSITION, 1);
}

#[test(should_fail_with = "the sender holds no note of this position")]
unconstrained fn a_deposit_into_a_position_by_an_account_without_a_note_is_refused() {
    let s = held_setup();
    let _ = request_owner(s, s.other, ROUND_DEPOSIT, POSITION, DEPOSIT, 1);
}

// A note of one position confers no other.
#[test(should_fail_with = "the sender holds no note of this position")]
unconstrained fn a_note_of_another_position_confers_nothing() {
    let s = held_setup();
    let _ = request_owner(s, s.user, ROUND_REPAY, OTHER_POSITION, REPAY, 1);
}

// A failed opening's note (its code nonzero, position 0) confers nothing:
// the opening that failed leaves its requester without a position, and its
// escrow comes back in the payout.
#[test(should_fail_with = "the sender holds no note of this position")]
unconstrained fn a_failed_openings_note_confers_nothing() {
    let s = shared_setup();
    let d = request_owner(s, s.user, ROUND_DEPOSIT, 0, DEPOSIT, 1);
    let tx = submit_shared(s, d, C_INIT, C1, PRICE, EPOCH, [17, 0, 0, 0, 0, COLLATERAL_ASSET + DEPOSIT, 0]);
    let _ = open_and_deliver(s, d, tx);
    assert_eq(outcome_notes(s, s.user).count, 1);
    let _ = request_owner(s, s.user, ROUND_BORROW, POSITION, BORROW, 2);
}

// A liquidation's note names no position: the liquidator gains nothing over
// the positions it liquidated.
#[test(should_fail_with = "the sender holds no note of this position")]
unconstrained fn a_liquidations_note_confers_no_position() {
    let s = held_setup();
    let l = request_liquidation(s, 1);
    let tx = submit_shared(
        s,
        l,
        C_INIT,
        C1,
        PRICE,
        EPOCH,
        [0, 0, 1, SEIZE_OUT, REPAY_OUT, BUDGET - REPAY_OUT, 0],
    );
    let _ = open_and_deliver(s, l, tx);
    assert_eq(outcome_notes(s, s.other).count, 1);
    assert_eq(l.kind, ROUND_LIQUIDATE);
    let _ = request_owner(s, s.other, ROUND_REPAY, POSITION, REPAY, 2);
}

// One note opens two outstanding requests: both queue, in order, each with
// its own partial note; the round's own checks hold at each turn.
#[test]
unconstrained fn two_requests_from_one_note_both_queue() {
    let s = held_setup();
    let b = request_owner(s, s.user, ROUND_BORROW, POSITION, BORROW, 1);
    let r = request_owner(s, s.user, ROUND_REPAY, POSITION, REPAY, 2);
    assert_eq(s.queue().tail(), 3);
    assert_eq([s.queue().request_at(1), s.queue().request_at(2)], [b.id, r.id]);
    assert(b.partial() != r.partial());
    let borrowed = applied_on(POSITION, DEPOSIT, BORROW, BORROW);
    let tx = submit_shared(s, b, C_INIT, C1, PRICE, EPOCH, borrowed);
    assert_eq(open_and_deliver(s, b, tx), borrowed);
    let repaid = applied_on(POSITION, DEPOSIT, BORROW - REPAY, 0);
    let tx = submit_shared(s, r, C1, C2, PRICE, EPOCH, repaid);
    assert_eq(open_and_deliver(s, r, tx), repaid);
    assert_eq(outcome_notes(s, s.user).count, 3);
}

// The holder of another position's note cannot act on this one either: Bob
// opens position 2 and holds its note, not position 1's.
#[test(should_fail_with = "the sender holds no note of this position")]
unconstrained fn the_holder_of_another_position_cannot_act_on_this_one() {
    let s = held_setup();
    let _ = hold(s, s.other, OTHER_POSITION, 1);
    let _ = request_owner(s, s.other, ROUND_BORROW, POSITION, BORROW, 2);
}

// ---- redeem -------------------------------------------------------------------

/// The user's borrow on its held position, landed and delivered.
unconstrained fn borrowed(s: crate::Setup) -> crate::Request {
    let b = request_owner(s, s.user, ROUND_BORROW, POSITION, BORROW, 1);
    let tx = submit_shared(s, b, C_INIT, C1, PRICE, EPOCH, applied_on(POSITION, DEPOSIT, BORROW, BORROW));
    let _ = open_and_deliver(s, b, tx);
    b
}

// After a redeem the note stays readable (its redeem nullifier is not the
// note's) and still opens a request on its position.
#[test]
unconstrained fn a_redeemed_note_stays_readable_and_still_opens_a_request() {
    let s = held_setup();
    let b = borrowed(s);
    assert_eq(outcome_notes(s, s.user).count, 2);
    redeem(s, s.user, b.id);
    assert_eq(outcome_notes(s, s.user).count, 2);
    let r = request_owner(s, s.user, ROUND_REPAY, POSITION, REPAY, 2);
    assert_eq(s.queue().request_at(2), r.id);
}

// A second redeem of one note pushes the same redeem nullifier, which the
// transaction's nullifier check refuses as a duplicate.
#[test(should_fail_with = "duplicate nullifiers")]
unconstrained fn a_second_redeem_of_one_note_is_refused() {
    let s = held_setup();
    let b = borrowed(s);
    redeem(s, s.user, b.id);
    redeem(s, s.user, b.id);
}

// Only the note's owner redeems it: another account finds no note of the
// request in its own set.
#[test(should_fail_with = "no note of this request to redeem")]
unconstrained fn a_stranger_cannot_redeem_the_users_note() {
    let s = held_setup();
    let b = borrowed(s);
    redeem(s, s.other, b.id);
}

// A note that pays nothing (an opening that applied: its collateral stays in
// the book) is not redeemed.
#[test(should_fail_with = "the note has nothing to redeem")]
unconstrained fn a_note_that_pays_nothing_is_refused() {
    let s = shared_setup();
    let d = hold(s, s.user, POSITION, 1);
    redeem(s, s.user, d.id);
}

// The naming rule (examples/lending-tip/README.md, "Notes: ownership, the
// owner's view and value"): a note names a position exactly when the round
// vouched for it, so any note that names the position confers it, a failed
// round's included (a borrow refused at the limit reports the position as it
// stands); a note of code 14, a failed opening's and a liquidation's name none.
#[test]
fn a_note_confers_the_position_it_names_whatever_its_code() {
    let note = |f: [Field; 7]| LendingOutcome::unpack(f.concat([0x1d]));
    assert(note([0, POSITION, BORROWER, DEPOSIT, 0, 0, 0]).owns(POSITION));
    assert(note([9, POSITION, BORROWER, DEPOSIT, BORROW, 0, 0]).owns(POSITION));
    assert(!note([9, POSITION, BORROWER, DEPOSIT, BORROW, 0, 0]).owns(OTHER_POSITION));
    assert(!note([14, 0, 0, 0, 0, 0, 0]).owns(POSITION));
    assert(!note([17, 0, 0, 0, 0, COLLATERAL_ASSET + DEPOSIT, 0]).owns(POSITION));
    assert(!note([0, 0, 1, SEIZE_OUT, REPAY_OUT, BUDGET - REPAY_OUT, 0]).owns(0));
}
