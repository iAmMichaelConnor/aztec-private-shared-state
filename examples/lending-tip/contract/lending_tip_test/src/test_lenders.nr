//! The lenders on the secret-shared deployment (examples/lending-tip/README.md,
//! "Interest" and "Tokens"): a supply escrows its amount of the borrowed asset and its
//! note confers the lender position (mask 0, the lender kind's marker); a
//! withdrawal of supply pays the shares' value through the note's payout; a
//! lender's note is never stale, so a second withdrawal from one note lands
//! with code 18 and pays nothing; a borrower request on a lender position
//! is refused in the private function (the circuit's code 5 is the
//! backstop); the quote reaches its sender's note and pays nothing; the
//! kept usage deposits go to the treasury by `sweep_deposits`, and no
//! payment draws on what the market holds for queued requests. The outcomes
//! are stand-ins (no circuit runs here; the rounds' arithmetic is lending_tip
//! rounds.nr's tests and the supply_shared, withdraw_supply_shared and
//! quote_shared fixtures).
use crate::{
    BORROW, ROUND_BORROW, C1, C2, C_INIT, credit, EPOCH, FUNDED, held_setup, lend, LIQUIDITY, market,
    open_and_deliver, outcome_notes, POSITION, PRICE, public_balance, redeem,
    request_owner, request_quote, shared_setup, submit_shared, SUPPLY, ROUND_SUPPLY, TREASURY,
    USAGE_DEPOSIT, ROUND_WITHDRAW_SUPPLY,
};
use aztec::protocol::address::AztecAddress;
use aztec::protocol::traits::FromField;
use lending_market::app::{INDEX_ONE, LendingOutcome};
use lending_tip::LendingTip;

/// The lender position the tests open: the next index after the user's
/// position 1 in `held_setup`.
global LENT: Field = 2;

// A supply escrows its amount of the borrowed asset (and the usage deposit)
// and lands; its note names the lender position with mask 0, its shares and
// their value.
#[test]
unconstrained fn a_supply_escrows_its_amount_and_its_note_confers_the_lender_position() {
    let s = held_setup();
    let before = credit(s, s.other);
    let _ = lend(s, s.other, LENT, 1);
    assert_eq(credit(s, s.other), [before[0], before[1] - SUPPLY - USAGE_DEPOSIT]);
    let notes = outcome_notes(s, s.other);
    assert_eq(notes.count, 1);
    assert(notes.first.owns(LENT));
    assert(notes.first.of_kind(2) & !notes.first.of_kind(1));
}

// Supply then withdraw everything: the withdrawal's note pays the shares'
// value (the supply itself, before interest) in the borrowed asset.
#[test]
unconstrained fn a_withdrawal_of_supply_pays_the_shares_value() {
    let s = held_setup();
    let before = credit(s, s.other);
    let _ = lend(s, s.other, LENT, 1);
    let w = request_owner(s, s.other, ROUND_WITHDRAW_SUPPLY, LENT, SUPPLY, 2);
    // a withdrawal of supply escrows nothing but records two refund notes,
    // as every request does: no amount shows
    let r = s.env.view_public(LendingTip::at(s.app).refunds_at(2));
    assert((r.escrow != 0) & (r.deposit != 0));
    let withdrawn = [0, LENT, 0, 0, 0, SUPPLY, 0];
    let tx = submit_shared(s, w, C_INIT, C1, PRICE, EPOCH, withdrawn);
    assert_eq(open_and_deliver(s, w, tx), withdrawn);
    redeem(s, s.other, w.id);
    assert_eq(credit(s, s.other), [before[0], before[1] - 2 * USAGE_DEPOSIT]);
}

// A lender's note is never stale in shares: two withdrawals from one note
// both queue (the note is never nullified), land in queue order, and the
// second, finding the leaf's shares spent, lands with code 18: its note
// names the position as it stands and pays nothing.
#[test(should_fail_with = "the note has nothing to redeem")]
unconstrained fn a_second_withdrawal_from_one_note_lands_code_18_and_pays_nothing() {
    let s = held_setup();
    let _ = lend(s, s.other, LENT, 1);
    let first = request_owner(s, s.other, ROUND_WITHDRAW_SUPPLY, LENT, SUPPLY, 2);
    let second = request_owner(s, s.other, ROUND_WITHDRAW_SUPPLY, LENT, SUPPLY, 3);
    let tx = submit_shared(s, first, C_INIT, C1, PRICE, EPOCH, [0, LENT, 0, 0, 0, SUPPLY, 0]);
    let _ = open_and_deliver(s, first, tx);
    let refused = [18, LENT, 0, 0, 0, 0, 0];
    let tx = submit_shared(s, second, C1, C2, PRICE, EPOCH, refused);
    assert_eq(open_and_deliver(s, second, tx), refused);
    redeem(s, s.other, second.id);
}

// A borrower request on a lender position is refused in the private
// function: the sender's note of it is a lender's (mask 0), a hint that
// saves the round the circuit would refuse with code 5.
#[test(should_fail_with = "the position is not of this request's kind")]
unconstrained fn a_borrow_on_a_lender_position_is_refused() {
    let s = held_setup();
    let _ = lend(s, s.other, LENT, 1);
    let _ = request_owner(s, s.other, ROUND_BORROW, LENT, BORROW, 2);
}

// And a lender request on a borrower position likewise.
#[test(should_fail_with = "the position is not of this request's kind")]
unconstrained fn a_withdrawal_of_supply_on_a_borrower_position_is_refused() {
    let s = held_setup();
    let _ = request_owner(s, s.user, ROUND_WITHDRAW_SUPPLY, POSITION, 1, 1);
}

// A supply into another account's lender position is refused: the sender
// holds no note of it.
#[test(should_fail_with = "the sender holds no note of this position")]
unconstrained fn a_supply_into_another_accounts_position_is_refused() {
    let s = held_setup();
    let _ = lend(s, s.other, LENT, 1);
    let _ = request_owner(s, s.user, ROUND_SUPPLY, LENT, 10, 2);
}

// The quote: anyone asks, the round's rates reach the sender's note (a
// stand-in: the borrow index, the supply index, the utilisation), which
// names no position and pays nothing.
#[test]
unconstrained fn a_quote_reaches_its_senders_note_and_pays_nothing() {
    let s = shared_setup();
    let q = request_quote(s, s.other, 1);
    let rates = [0, 0, INDEX_ONE, 0, INDEX_ONE, 0, 1700];
    let tx = submit_shared(s, q, C_INIT, C1, PRICE, EPOCH, rates);
    assert_eq(open_and_deliver(s, q, tx), rates);
    let note: LendingOutcome = outcome_notes(s, s.other).first;
    assert_eq(note.settlement(), (0, 0));
    assert(!note.owns(0));
    assert_eq(market(s), C1);
}

// The kept usage deposits go to the treasury pin: anyone sweeps, the
// treasury's public balance of the borrowed asset grows by the kept count,
// the count goes to 0, and a second sweep pays nothing.
#[test]
unconstrained fn sweep_deposits_pays_the_kept_count_to_the_treasury() {
    let s = held_setup();
    let treasury = AztecAddress::from_field(TREASURY);
    let kept = s.env.view_public(LendingTip::at(s.app).get_kept_deposits());
    assert_eq(kept, USAGE_DEPOSIT as u128);
    assert_eq(public_balance(s, s.borrowed, treasury), 0);
    s.env.call_public(s.other, LendingTip::at(s.app).sweep_deposits());
    assert_eq(public_balance(s, s.borrowed, treasury), USAGE_DEPOSIT);
    assert_eq(public_balance(s, s.borrowed, s.app), LIQUIDITY + 2 * FUNDED - USAGE_DEPOSIT);
    assert_eq(s.env.view_public(LendingTip::at(s.app).get_kept_deposits()), 0);
    s.env.call_public(s.user, LendingTip::at(s.app).sweep_deposits());
    assert_eq(public_balance(s, s.borrowed, treasury), USAGE_DEPOSIT);
}

// A withdrawal of credit never draws on the kept usage deposits: a stand-in
// borrow note pays out the whole public balance of the borrowed asset, the
// redeem credits it, and withdrawing it all is refused while kept deposits
// sit in the same balance.
#[test(should_fail_with = "the payout exceeds the payable balance")]
unconstrained fn a_withdrawal_never_draws_on_the_kept_deposits() {
    let s = held_setup();
    let all = public_balance(s, s.borrowed, s.app);
    let b = request_owner(s, s.user, ROUND_BORROW, POSITION, all, 1);
    let tx = submit_shared(s, b, C_INIT, C1, PRICE, EPOCH, [0, POSITION, INDEX_ONE, 1000, all, all, 0]);
    let _ = open_and_deliver(s, b, tx);
    redeem(s, s.user, b.id);
    s.env.call_private(s.user, LendingTip::at(s.app).withdraw_funds(0, all as u128));
}
