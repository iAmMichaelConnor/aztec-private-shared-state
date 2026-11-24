//! The oblivious deployment (`lending_tip_oblivious` over
//! `OBLIVIOUS_PACKAGES`, README "The oblivious deployment",
//! docs/ARCHITECTURE.md section 6, "The oblivious tree"): the same market,
//! every round on a position through its request function with the position
//! shared under the round's oblivious layout (the openings, `deposit_shared`
//! and `supply_shared`, with the public opening flag beside it), its results
//! through the same `process_shared` and `process_header_shared` under the
//! oblivious circuits' vk pins, with no leaf hash and the header's append index
//! as the app value after the exit tag. lib.nr's helpers take the deployment
//! from `Setup::oblivious`; the round shape of every round type is
//! test_round_shape.nr's, the escape hatch test_hatch.nr's. Here: that nothing
//! a request or a result shows names a position or the append index, and the
//! refusals whose rule differs from the clear deployments'. The outcomes and
//! the append index are stand-ins (no circuit runs here); the circuits'
//! fixtures (circuits/outputs.txt) prove the rounds' own codes, the
//! out-of-range position's code 3 among them.
use crate::{
    BORROW, ROUND_BORROW, BORROWER, C1, C2, C_INIT, DEPOSIT, ROUND_DEPOSIT, EPOCH, ROUND_LIQUIDATE,
    assert_state, filler_tag, market, NEXT_INDEX, oblivious_setup, open_and_deliver, POSITION, PRICE,
    request_liquidation_of, request_opening, request_owner, shared_apply, Setup, submit_shared,
};
use aztec::test::helpers::txe_oracles;
use lending_market::app::TWO_POW_DEPTH;
use lending_tip::LendingTip;
use pss_tip_test::audit::assert_tx_holds_none;
use pss_tip_test::shape::tx_effect;

/// The position the test's owner holds: a stand-in index no other value of
/// the suite takes, so a field equal to it names it.
global HIDDEN: Field = 0x5a5a;

/// Whether `v` is one of the two values a test looks for.
fn names(v: Field, values: [Field; 2]) -> bool {
    (v == values[0]) | (v == values[1])
}

/// Assert that no field the last transaction left on chain is one of
/// `values` (pss_tip_test's audit walk).
unconstrained fn assert_tx_shows_none(s: Setup, values: [Field; 2]) {
    assert_tx_holds_none(tx_effect(s.env, txe_oracles::get_last_tx_effects().tx_hash), values);
}

// The hidden position: the user opens a position (position 0 shared, the
// flag public; the stand-in round assigns HIDDEN), borrows on it and a
// liquidator probes it. No field any of their requests or results left on
// chain is the position or the header's append index (the circuits' public
// `next_index`, in every two-slot result's app values), and the public calls
// name neither: the request's `append_receipt(id, expiry, refunds)`, and
// the result's `apply_shared(apply, opened, tags)`, whose exit tag is a
// hash the circuit outputs (the append index stays in the proof). The
// position reaches its owner only, in the outcome.
#[test]
unconstrained fn no_request_or_result_names_the_position_or_the_append_index() {
    let s = oblivious_setup();
    let app = LendingTip::at(s.app);
    let hidden = [HIDDEN, NEXT_INDEX];
    let d = request_owner(s, s.user, ROUND_DEPOSIT, 0, DEPOSIT, 1);
    assert_tx_shows_none(s, hidden);
    let opened = [0, HIDDEN, BORROWER, DEPOSIT, 0, 0, 0];
    let tx = submit_shared(s, d, C_INIT, C1, PRICE, EPOCH, opened);
    assert_tx_shows_none(s, hidden);
    assert_eq(open_and_deliver(s, d, tx), opened);

    let b = request_owner(s, s.user, ROUND_BORROW, HIDDEN, BORROW, 2);
    assert_tx_shows_none(s, hidden);
    let append = app.append_receipt(b.id, b.expiry, std::mem::zeroed());
    for v in append.args {
        assert(!names(v, hidden), "the request's public call names the index");
    }
    let borrowed = [0, HIDDEN, BORROWER, DEPOSIT, BORROW, BORROW, 0];
    let tx = submit_shared(s, b, C1, C2, PRICE, EPOCH, borrowed);
    assert_tx_shows_none(s, hidden);
    assert_eq(open_and_deliver(s, b, tx), borrowed);
    // the result's public call as process_shared builds it from the
    // verified outputs: the apply, the bit and the exit tag
    let apply = shared_apply(b, C1, C2, PRICE, EPOCH, 7);
    for v in app.apply_shared(apply, 1, [filler_tag(b)]).args {
        assert(!names(v, hidden), "the result's public call names the index");
    }

    let l = request_liquidation_of(s, [HIDDEN], 1, 3);
    assert_eq(l.kind, ROUND_LIQUIDATE);
    assert_tx_shows_none(s, hidden);
    assert_eq(market(s), C2);
}

// An out-of-range position costs no round here either: the probe is a
// shared input, which no node can range-check, but the requester's own
// private function sees it in the clear and asserts its range
// (`valid_liquidation`, as every request function asserts its round's
// static validity) before C is formed, so the request is refused at intake
// and nothing is queued. The circuit's code 3 (the range flag on the raw
// input, past 2^D read at its low bits by both the nodes and the circuit)
// is the backstop for a request no intake checked.
#[test(should_fail_with = "invalid inputs")]
unconstrained fn an_out_of_range_probe_is_refused_at_intake() {
    let s = oblivious_setup();
    assert_state(s, 0, 0, C_INIT);
    let _ = request_liquidation_of(s, [TWO_POW_DEPTH + POSITION], 1, 1);
}

// The flag tells the nodes which slot opens, so it must agree with the
// shared position: position 0 under `opens` 0 is refused at intake.
#[test(should_fail_with = "invalid inputs")]
unconstrained fn an_opening_flag_the_position_contradicts_is_refused() {
    let s = oblivious_setup();
    assert_state(s, 0, 0, C_INIT);
    let _ = request_opening(s, s.user, ROUND_DEPOSIT, 0, 0, DEPOSIT, 1);
}

// And the other way: a named position under `opens` 1, by its holder, is
// refused at intake too. The guard keeps every queued opening's flag and
// position consistent, so the circuit's code 4 for a disagreement (which
// returns no escrow in the note while the opening bit stays 1) is
// unreachable through the contract.
#[test(should_fail_with = "invalid inputs")]
unconstrained fn an_opening_flag_on_a_named_position_is_refused() {
    let s = oblivious_setup();
    let d = request_owner(s, s.user, ROUND_DEPOSIT, 0, DEPOSIT, 1);
    let opened = [0, HIDDEN, BORROWER, DEPOSIT, 0, 0, 0];
    let tx = submit_shared(s, d, C_INIT, C1, PRICE, EPOCH, opened);
    let _ = open_and_deliver(s, d, tx);
    let _ = request_opening(s, s.user, ROUND_DEPOSIT, HIDDEN, 1, DEPOSIT, 2);
}

// The result path's vk pins: the round table resolves the deposit's row to
// the oblivious package, so a result proved under the secret-shared
// deposit circuit's vk (with that circuit's outputs: the leaf hashes and
// an append index of 0) is refused.
#[test(should_fail_with = "unexpected verification key")]
unconstrained fn a_result_under_the_secret_shared_circuits_vk_is_refused() {
    let s = oblivious_setup();
    let d = request_owner(s, s.user, ROUND_DEPOSIT, 0, DEPOSIT, 1);
    let mut clear = s;
    clear.oblivious = false;
    assert_state(s, 0, 1, C_INIT);
    let _ = submit_shared(clear, d, C_INIT, C1, PRICE, EPOCH, [0, POSITION, BORROWER, DEPOSIT, 0, 0, 0]);
}
