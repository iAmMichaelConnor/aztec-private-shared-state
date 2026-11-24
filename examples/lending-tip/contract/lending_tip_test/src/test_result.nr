//! The result transaction: `process_result` through the library, whichever
//! non-secret-shared intake queued the deposit, `apply` with its public
//! completion of the request's partial note, the pinned price re-read every
//! round makes, the deposit's vk pin and the signed price, `apply`'s refusal
//! of a call from outside, and `skip()` at the configured `stale_blocks`, not
//! before. The library's result and queue rules (the signatures, a failed
//! round's kept state, the wrong head, a moved slot under ok = 1 and a
//! write-nothing round over one) are pss_public_contract_test's.
use crate::{
    assert_state, BORROWER, C1, C2, C_INIT, DEPOSIT, deploy_configured_unfunded, deposit,
    deposit_round, deposit_signatures, deposit_with_receipts, EPOCH, failed_round, init_vk,
    last_tx_log, market, mine_until_next_block_is, NONCE_A, NONCE_B, ok_round, outcome_notes,
    POSITION, PREVIOUS_BLOCKS, PRICE, public_logs, set_price, setup, signatures_at, stage_proof, STALE,
    submit_deposit, user_partial,
};
use aztec::protocol::traits::Packable;
use lending_market::app::{LendingOutcome, OUTCOME_SLOT};
use lending_tip::LendingTip;
use pss_public_contract::{DONE_APPLIED, DONE_PENDING, DONE_SKIPPED, Head};
use pss_public_contract::partial_note::completion_log_tag;

/// The completion log the last transaction emitted for the partial note
/// `partial`: `[slot, code, position, mask, 0, 0, payout, 0, request_id]`,
/// the mask the borrower kind's marker on an applied deposit.
unconstrained fn completion(s: crate::Setup, partial: Field) -> [Field; 9] {
    last_tx_log(s, completion_log_tag(partial))
}

// An ok opening deposit for the head lands: the slot takes new_c, the head
// moves to {1, the block}, done[0] = applied, and `apply` completes the
// request's partial note in public: one completion log under its tag, the
// note's fields the code, the assigned position and the borrower kind's
// marker (no collateral or debt), the request id last; the user's PXE, told
// of the partial note offchain at request, holds the note. The apply's one
// public log is the completion (no state log: node-held), and the entry
// behind is untouched. That entry, queued under receipt intake, then lands
// through the same `process_result` under the same vk pin (one compiled
// circuit for both non-secret-shared intakes) and completes its own note.
#[test]
unconstrained fn ok_deposits_under_both_intakes_apply_and_complete_the_users_notes() {
    let s = setup();
    let d = deposit(s, DEPOSIT, NONCE_A);
    let receipt = deposit_with_receipts(s, DEPOSIT, NONCE_B);
    assert_eq(outcome_notes(s, s.user).count, 0);
    let r = ok_round(d, C_INIT, C1).with_partial(user_partial(s, NONCE_A));
    let block = submit_deposit(s, r);

    assert_eq(market(s), C1);
    assert_eq(s.queue().head(), Head { index: 1, since: block });
    assert_eq(s.queue().tail(), 2);
    assert_eq(s.queue().done_at(0), DONE_APPLIED);
    assert_eq(s.queue().done_at(1), DONE_PENDING);
    assert_eq(completion(s, r.partial), [OUTCOME_SLOT, 0, POSITION, BORROWER, 0, 0, 0, 0, d]);
    let notes = outcome_notes(s, s.user);
    assert_eq(notes.count, 1);
    assert_eq(notes.first, LendingOutcome::unpack(r.note()));
    assert(notes.first.owns(POSITION));
    assert_eq(outcome_notes(s, s.other).count, 0);
    assert_eq(public_logs(s), 1);

    let round = ok_round(receipt, C1, C2).with_partial(user_partial(s, NONCE_B));
    let block = submit_deposit(s, round);
    assert_eq(market(s), C2);
    assert_eq(s.queue().head(), Head { index: 2, since: block });
    assert_eq(completion(s, round.partial), [OUTCOME_SLOT, 0, POSITION, BORROWER, 0, 0, 0, 0, receipt]);
    assert_eq(outcome_notes(s, s.user).count, 2);
}

// The oracle opened one new epoch between the round and the result: the
// round's epoch is the one before the current, at its price, so the result
// still lands. A deposit does not use the price; every round makes the read
// all the same (one apply shape for every round). After two more epochs the
// next result, recomputed at the new price and epoch, applies.
#[test]
unconstrained fn a_deposit_one_epoch_behind_applies_and_one_recomputed_at_the_new_epoch_applies() {
    let s = setup();
    let d = deposit(s, DEPOSIT, NONCE_A);
    set_price(s, PRICE + 1);
    let _ = submit_deposit(s, ok_round(d, C_INIT, C1).with_partial(user_partial(s, NONCE_A)));
    assert_state(s, 1, 1, C1);
    let r = deposit(s, DEPOSIT, NONCE_B);
    set_price(s, PRICE + 2);
    set_price(s, PRICE + 3);
    let round = deposit_round(r, C1, C2, PRICE + 3, EPOCH + 3).with_partial(user_partial(s, NONCE_B));
    let _ = submit_deposit(s, round);
    assert_state(s, 2, 2, C2);
}

// The epoch before the current lands only inside the oracle's window, up to
// PREVIOUS_BLOCKS blocks after the new price (the window's last block is
// test_oracle's)...
#[test]
unconstrained fn a_deposit_one_epoch_behind_lands_late_in_the_window() {
    let s = setup();
    let d = deposit(s, DEPOSIT, NONCE_A);
    set_price(s, PRICE + 1);
    mine_until_next_block_is(s, s.env.last_block_number() + PREVIOUS_BLOCKS - 1);
    let _ = submit_deposit(s, ok_round(d, C_INIT, C1).with_partial(user_partial(s, NONCE_A)));
    assert_state(s, 1, 1, C1);
}

// ...and not a block after: the oracle no longer offers the previous price,
// so a round computed at it reverts whatever its epoch (the nodes cannot
// pick an old price once the window has passed), and is recomputed at the
// current one.
#[test(should_fail_with = "pinned read changed")]
unconstrained fn a_deposit_one_epoch_behind_past_the_oracles_window_is_refused() {
    let s = setup();
    let d = deposit(s, DEPOSIT, NONCE_A);
    set_price(s, PRICE + 1);
    mine_until_next_block_is(s, s.env.last_block_number() + PREVIOUS_BLOCKS + 1);
    assert_state(s, 0, 1, C_INIT);
    let _ = submit_deposit(s, ok_round(d, C_INIT, C1));
}

// Two new epochs: the round's epoch is out of the window and the whole
// result reverts; the queue and the slot stay, and the round is recomputed.
#[test(should_fail_with = "pinned epoch too old")]
unconstrained fn a_deposit_two_epochs_behind_the_oracle_is_refused() {
    let s = setup();
    let d = deposit(s, DEPOSIT, NONCE_A);
    set_price(s, PRICE + 1);
    set_price(s, PRICE + 2);
    assert_state(s, 0, 1, C_INIT);
    let _ = submit_deposit(s, ok_round(d, C_INIT, C1));
}

// ---- process_result refusals ----------------------------------------------

// The deposit's vk pin: a deposit result proved under another circuit's vk
// (the init's) is refused.
#[test(should_fail_with = "unexpected verification key")]
unconstrained fn a_deposit_result_under_another_vk_is_refused() {
    let s = setup();
    let d = deposit(s, DEPOSIT, NONCE_A);
    let r = ok_round(d, C_INIT, C1);
    stage_proof(s, init_vk());
    assert_state(s, 0, 1, C_INIT);
    s.env.call_private(
        s.relayer,
        LendingTip::at(s.app).process_result(r.result(), deposit_signatures(s, r)),
    );
}

// The pinned values are signed: a result whose price differs from the one
// the nodes signed is refused.
#[test(should_fail_with = "node 0's result signature does not verify")]
unconstrained fn a_result_with_another_price_than_signed_is_refused() {
    let s = setup();
    let d = deposit(s, DEPOSIT, NONCE_A);
    let r = ok_round(d, C_INIT, C1);
    stage_proof(s, crate::deposit_vk());
    s.env.call_private(
        s.relayer,
        LendingTip::at(s.app).process_result(
            r.result(),
            signatures_at(s, d, C_INIT, [PRICE as Field + 1, EPOCH as Field, s.env.next_block_number() as Field], C1),
        ),
    );
}

// ---- apply refusals ---------------------------------------------------------

// `apply` is #[only_self] (refused before any state is read, so the
// deployment needs no balances, init or queued request).
#[test(should_fail_with = "Function apply can only be called by the same contract")]
unconstrained fn apply_from_outside_the_contract_is_refused() {
    let s = deploy_configured_unfunded();
    s.env.call_public(s.relayer, LendingTip::at(s.app).apply(ok_round(0x1d, C_INIT, C1).result()));
}

// ---- skip ---------------------------------------------------------------------

// After stale_blocks anyone may skip the head: the head moves, done =
// skipped, the market is unchanged and the skipped request's note is never
// completed; the next entry is served on the same state.
#[test]
unconstrained fn skip_after_stale_blocks_drops_the_head() {
    let s = setup();
    let _ = deposit(s, DEPOSIT, NONCE_A);
    let since = s.queue().head().since;
    let r = deposit_with_receipts(s, DEPOSIT, NONCE_B);
    mine_until_next_block_is(s, since + STALE);
    s.env.call_public(s.other, LendingTip::at(s.app).skip());
    let block = s.env.last_block_number();
    assert_eq(s.queue().head(), Head { index: 1, since: block });
    assert_eq(s.queue().done_at(0), DONE_SKIPPED);
    assert_eq(market(s), C_INIT);
    assert_eq(outcome_notes(s, s.user).count, 0);
    let _ = submit_deposit(s, failed_round(r, C_INIT, 17).with_partial(user_partial(s, NONCE_B)));
    assert_state(s, 2, 2, C_INIT);
    assert_eq(outcome_notes(s, s.user).first.code, 17);
}
