//! The liquidated owner's notice on the secret-shared deployment (the
//! standing delivery handle, pss_public_contract `handle`;
//! docs/ARCHITECTURE.md section 6, "The standing delivery handle"): every owner
//! request on a borrower position leaves a delivery handle in the position's
//! leaf, and a liquidation that writes the position completes it, so the owner
//! learns of the liquidation from the liquidator's result, with no round of its
//! own.
//!
//! - the result pushes the notice's note hash and emits its log under the
//!   handle's tag beside the liquidator's outcome; the owner finds the log,
//!   opens it with the handle's key and its PXE holds an owner note of the
//!   position that reports the position after the liquidation and pays
//!   nothing;
//! - nobody else can take it: the handle's partial commitment names the
//!   owner, so the note another account rebuilds is not the one the result
//!   pushed and its PXE stores nothing.
//!
//! The rounds are stand-ins, as in the rest of the suite.
use crate::{
    LIQUIDATED, notice_of,
    BUDGET, C1, C_INIT, credit, EPOCH, held_setup, HELD_N, hold, open_and_deliver,
    open_notice_as, outcome_notes, POSITION, PRICE, redeem, REPAY, ROUND_REPAY, REPAY_OUT,
    Request, request_liquidation, request_owner, SEIZE_OUT, Setup, shared_setup, Landing, submit_landing, submit_shared,
};
use aztec::protocol::traits::Packable;
use lending_market::app::LendingOutcome;
use pss_public_contract::outcome::OutcomeTx;

/// The user holds a note of POSITION (its opening deposit left a handle),
/// the liquidator's liquidation of POSITION lands with the notice to the
/// user's handle, and the liquidator takes its own note. Returns the setup,
/// the user's opening request, the liquidation and the result transaction.
unconstrained fn liquidated() -> (Setup, Request, Request, OutcomeTx) {
    let s = shared_setup();
    let d = hold(s, s.user, POSITION, HELD_N);
    let l = request_liquidation(s, 1);
    let tx = submit_landing(s, l, C_INIT, C1, PRICE, EPOCH, LIQUIDATED, Landing::now().noticing(Option::some((d, notice_of(POSITION)))));
    let _ = open_and_deliver(s, l, tx);
    (s, d, l, tx)
}

// The owner finds its notice under its handle's tag, opens it and holds an
// owner note of the position after the liquidation, which pays nothing and
// opens its next request on the position.
#[test]
unconstrained fn a_liquidated_owner_opens_its_notice_and_holds_the_position() {
    let (s, d, l, tx) = liquidated();
    let before = outcome_notes(s, s.user).count;
    let packed = open_notice_as(s, d, l, s.user, tx);
    assert_eq(packed, notice_of(POSITION).concat([s.queue().request_at(1)]));
    assert_eq(outcome_notes(s, s.user).count, before + 1);
    let note = LendingOutcome::unpack(packed);
    assert(note.owns(POSITION));
    assert_eq(note.settlement(), (0, 0));
    let _ = request_owner(s, s.user, ROUND_REPAY, POSITION, REPAY, 2);
}

// The notice's note pays nothing: the owner cannot redeem it.
#[test(should_fail_with = "the note has nothing to redeem")]
unconstrained fn a_notice_pays_nothing() {
    let (s, d, l, tx) = liquidated();
    let packed = open_notice_as(s, d, l, s.user, tx);
    redeem(s, s.user, packed[7]);
}

// A self-liquidation: the liquidator liquidates its own position, so it
// holds two notes of one request, the liquidation's, which pays, and the
// notice of its position, which pays nothing. Its redeem of the request pays
// the liquidation's note: the read sorts by position, so the order the PXE
// keeps the two notes in does not matter (here the notice is delivered
// first).
#[test]
unconstrained fn a_self_liquidator_redeems_its_liquidation_beside_its_notice() {
    let s = shared_setup();
    let d = hold(s, s.other, POSITION, HELD_N);
    let l = request_liquidation(s, 1);
    let tx = submit_landing(s, l, C_INIT, C1, PRICE, EPOCH, LIQUIDATED, Landing::now().noticing(Option::some((d, notice_of(POSITION)))));
    let notice = open_notice_as(s, d, l, s.other, tx);
    assert_eq(notice[7], l.id);
    let _ = open_and_deliver(s, l, tx);
    let before = credit(s, s.other);
    redeem(s, s.other, l.id);
    assert_eq(credit(s, s.other), [before[0] + SEIZE_OUT, before[1] + BUDGET - REPAY_OUT]);
}

// Another account that rebuilds the notice with the handle's secrets gets
// nothing: the handle's partial commitment names the owner, so its note is
// not the one the result pushed, and its PXE stores none.
#[test]
unconstrained fn nobody_but_the_owner_can_take_the_notice() {
    let (s, d, l, tx) = liquidated();
    let before = outcome_notes(s, s.other).count;
    let _ = open_notice_as(s, d, l, s.other, tx);
    assert_eq(outcome_notes(s, s.other).count, before);
}

// A round that notifies nobody lands a filler: the owner's handle tag
// carries no log, and every result shows the same two logs.
#[test]
unconstrained fn a_round_that_notifies_nobody_lands_a_filler() {
    let s = held_setup();
    let l = request_liquidation(s, 1);
    let _ = submit_shared(s, l, C_INIT, C1, PRICE, EPOCH, LIQUIDATED);
    let effects = aztec::test::helpers::txe_oracles::get_last_tx_effects();
    assert_eq(effects.private_logs.len(), 2);
    assert_eq(effects.note_hashes.len(), 2);
}
