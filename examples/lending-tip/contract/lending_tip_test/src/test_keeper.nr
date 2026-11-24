//! The keeper round on the secret-shared deployment (`scan_shared`,
//! examples/lending-tip/README.md, "Keeper round"): anyone queues a scan of the
//! window of `WINDOW` positions from a start below 2^D and a multiple of W, and
//! the round's report reaches the keeper only, as a private outcome completing
//! the keeper's partial note.
//!
//! - Intake: `scan_shared` refuses a start that is not a multiple of W or
//!   not below 2^D (code 3 never costs a round), and its request pays the
//!   usage deposit and escrows nothing, as a borrow's.
//! - Result: `process_header_shared(ROUND_SCAN, ...)` lands the completed note and the log of
//!   the report `[code, 0, report, 0, start, 0, occupied]` (position 0 and
//!   x 0: the keeper's note confers no position and pays nothing) and the
//!   one `apply_shared` writes the re-blinded book; the keeper's PXE holds
//!   the note, no one else's.
//!
//! As in the rest of the suite the rounds are stand-ins (no circuit runs
//! here): the outcomes are the scan fixtures' (circuits/scan_shared
//! Prover*.toml comments: the keeper's book, positions 1 .. 9 with 1, 3 and
//! 9 unhealthy at 2.00), encrypted with the circuits' own `encrypt_outcome`.
use crate::{
    applied_on, C1, C2, C3, C_INIT, DEPOSIT, ROUND_DEPOSIT, EPOCH, intake, Intake, market, open_and_deliver,
    outcome_notes, PRICE, Request, REQUEST_GAS, request_owner, ROUND_SCAN, Setup,
    shared_setup, submit_shared,
};
use aztec::test::helpers::txe_oracles;
use lending_market::layouts::SCAN_SHARED_LAYOUT;
use lending_market::app::{
    SCAN_SHARED_PACKAGE, SHARED_PACKAGES, TWO_POW_DEPTH, valid_scan, WINDOW,
};
use lending_tip::LendingTip;
use pss_public_contract::DONE_APPLIED;
use pss_tip_test::shape::kind_options;

/// The keeper (`other`) queues a scan of the window at `start`
/// (`SCAN_SHARED_LAYOUT`); `n` picks the outcome key, tag and blinding.
unconstrained fn request_scan(s: Setup, start: Field, n: Field) -> Request {
    let i: Intake<4> = intake(s, s.other, ROUND_SCAN, [start], n, SCAN_SHARED_LAYOUT);
    s.env.call_private_opts(
        s.other,
        kind_options(REQUEST_GAS),
        LendingTip::at(s.app).scan_shared(start, i.rho, i.key, i.tag, i.sharing, i.expiry, i.receipts),
    );
    i.request(ROUND_SCAN, s.other)
}

/// The last transaction's private effects, counted.
unconstrained fn effects() -> [u32; 4] {
    let e = txe_oracles::get_last_tx_effects();
    let first = if e.private_logs.len() == 0 { 0 } else { e.private_logs.get(0).len() };
    [e.note_hashes.len(), e.nullifiers.len(), e.private_logs.len(), first]
}

// the scan fixtures' outcomes [code, 0, report, 0, start, 0, occupied]:
// window 0 reports positions 1 and 3 (0b1010) of 7 occupied; window 16 is
// past the book's end
global WINDOW_0: [Field; 7] = [0, 0, 10, 0, 0, 0, 7];
global PAST_END: [Field; 7] = [0, 0, 0, 0, 16, 0, 0];

// The scan is in the secret-shared list, after the six rounds before it.
#[test]
unconstrained fn the_scan_is_in_the_shared_list() {
    assert_eq(SHARED_PACKAGES[6], SCAN_SHARED_PACKAGE);
    assert_eq(WINDOW, 8);
}

// The intake predicate: a start below 2^D and a multiple of W (one refusal
// below shows `scan_shared` applies it).
#[test]
fn a_scan_start_is_a_window_of_the_book() {
    for start in [0, 8, 16, TWO_POW_DEPTH - 8] {
        assert(valid_scan([start]));
    }
    for start in [1, 4, 7, 9, TWO_POW_DEPTH, TWO_POW_DEPTH + 8, 0 - 8] {
        assert(!valid_scan([start]));
    }
}

// A window with two liquidatable positions: the keeper's outcome opens to
// the report, its PXE holds the note, the user's holds none, and the book's
// new (re-blinded) commitment is written. A window past the book's end
// (the keeper's stop: nothing occupied) and an empty window (a book with no
// position) report nothing, and their results land like any other round's.
#[test]
unconstrained fn scans_report_to_the_keeper_only_and_land_whatever_the_window() {
    let s = shared_setup();
    let req = request_scan(s, 0, 1);
    let tx = submit_shared(s, req, C_INIT, C1, PRICE, EPOCH, WINDOW_0);
    assert_eq(open_and_deliver(s, req, tx), WINDOW_0);
    let notes = outcome_notes(s, s.other);
    assert_eq(notes.count, 1);
    assert(!notes.first.owns(0) & (notes.first.settlement() == (0, 0)));
    assert_eq(outcome_notes(s, s.user).count, 0);
    assert_eq(market(s), C1);
    assert_eq(s.queue().head().index, 1);
    assert_eq(s.queue().done_at(0), DONE_APPLIED);

    let past = request_scan(s, 16, 2);
    let tx = submit_shared(s, past, C1, C2, PRICE, EPOCH, PAST_END);
    assert_eq(open_and_deliver(s, past, tx), PAST_END);
    assert_eq(market(s), C2);

    let empty = [0, 0, 0, 0, 0, 0, 0];
    let req = request_scan(s, 0, 3);
    let tx = submit_shared(s, req, C2, C3, PRICE, EPOCH, empty);
    assert_eq(open_and_deliver(s, req, tx), empty);
    assert_eq(market(s), C3);
    assert_eq(outcome_notes(s, s.other).count, 3);
    assert_eq(outcome_notes(s, s.user).count, 0);
}

#[test(should_fail_with = "invalid inputs")]
unconstrained fn an_unaligned_start_is_refused_at_intake() {
    let s = shared_setup();
    let _ = request_scan(s, 4, 1);
}

// The hidden round type: a scan's request escrows nothing, as a borrow's,
// and its result has the effects of a deposit's (the outcome's note hash and
// 16-field log, and the delivery's, a filler on both).
#[test]
unconstrained fn a_scan_has_the_effects_of_every_shared_round() {
    let s = shared_setup();
    let d = request_owner(s, s.user, ROUND_DEPOSIT, 0, DEPOSIT, 1);
    let k = request_scan(s, 0, 2);
    // the scan's request committed its two refund notes, as every request does
    let refunds = s.env.view_public(LendingTip::at(s.app).refunds_at(1));
    assert((refunds.escrow != 0) & (refunds.deposit != 0));
    let _ = submit_shared(s, d, C_INIT, C1, PRICE, EPOCH, applied_on(1, DEPOSIT, 0, 0));
    let deposit_result = effects();
    let _ = submit_shared(s, k, C1, C2, PRICE, EPOCH, WINDOW_0);
    assert_eq(effects(), deposit_result);
    assert_eq(deposit_result[0], 2);
    assert_eq(deposit_result[2], 2);
    assert_eq(deposit_result[3], 16);
}
