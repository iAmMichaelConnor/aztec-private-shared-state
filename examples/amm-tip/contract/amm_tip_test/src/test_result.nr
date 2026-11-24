//! The result transaction on node-held state: `process_result`, one for
//! both non-secret-shared intakes, through the library, `apply` with its
//! public completion of the trader's partial note on every round and no
//! state log, a failed swap's equal commitment and the note that says why,
//! the trader's `redeem` of a completed note, `apply`'s refusal of a call
//! from outside, and `skip()` refused one block short of `stale_blocks`
//! (through the probe) and landing at it. The library's result
//! and queue rules (the vk pin, the request id binding, the signatures, the
//! wrong head, a moved slot under ok = 1 and ok = 0, the stale clock) and
//! the public completion's own cases are pss_public_contract_test's.
use crate::{
    AMOUNT_IN, AMOUNT_OUT, assert_completed, assert_state, C1, C2, C_INIT, completion, failed_round,
    mine_until_next_block_is, notes_of, NONCE_A, NONCE_B, NONCE_C, ok_round, pool, redeem, setup,
    setup_with_probe, STALE, submit, swap, swap_with_receipts, try_skip, user_partial,
};
use amm_tip::AmmTip;
use amm_tip::app::SwapOutcomeNote;
use amm_tip_circuit::shared::OUTCOME_SLOT;
use pss_public_contract::{DONE_APPLIED, DONE_PENDING, DONE_SKIPPED, Head};
use pss_tip_test::shape::last_tx_shape;

// An ok = 1 on-chain intake result for the head lands: the slot takes new_c,
// the head moves to {1, the block}, done[0] = applied, and `apply`
// completes the trader's partial note in public with [0, amount_out,
// request_id]: one note hash and one public log, the completion log (no
// state log: the nodes hold the pool's new version under new_c); the
// trader's PXE, told of the partial note offchain at request, holds the
// note, another account none; the entry behind is untouched. The note is
// the trader's credit as a secret-shared swap's is: the trader redeems it
// once for its amount_out, and the note is gone.
#[test]
unconstrained fn an_ok_on_chain_intake_result_applies_and_completes_the_traders_note_redeemed_once() {
    let s = setup();
    let a = swap(s, AMOUNT_IN, NONCE_A);
    let _ = swap(s, AMOUNT_IN, NONCE_B);
    assert_eq(notes_of(s, s.user).count, 0);
    let r = ok_round(a, C_INIT, C1).with_partial(user_partial(s, NONCE_A));
    let block = submit(s, r);

    assert_eq(pool(s), C1);
    assert_eq(s.queue().head(), Head { index: 1, since: block });
    assert_eq(s.queue().tail(), 2);
    assert_eq(s.queue().done_at(0), DONE_APPLIED);
    assert_eq(s.queue().done_at(1), DONE_PENDING);
    assert_eq(r.note(), SwapOutcomeNote { code: 0, amount_out: AMOUNT_OUT, request_id: a });
    assert_completed(s, r, s.user, 1);
    assert_eq(notes_of(s, s.trader_b).count, 0);
    assert_eq(redeem(s, s.user, a), AMOUNT_OUT);
    assert_eq(notes_of(s, s.user).count, 0);
}

// ok = 0 is a no-op that finishes the request: its new commitment equals
// the old one (the nodes create no version for it), the slot stays, the
// head moves, done = applied (not skipped), and `apply` still completes the
// trader's note, which says why: [code, 0, request_id]. The next swap loads
// the parent version: the failed round left the commitment of a's result,
// so c's round runs on that version (old_c = C1, the commitment the slot
// kept) and lands. Each round, whichever intake queued its request,
// completes its own request's note.
#[test]
unconstrained fn an_ok_0_result_is_a_no_op_whose_note_says_why_and_the_next_swap_runs_on_the_parent_version() {
    let s = setup();
    let a = swap(s, AMOUNT_IN, NONCE_A);
    let b = swap_with_receipts(s, AMOUNT_IN, NONCE_B);
    let c = swap(s, AMOUNT_IN, NONCE_C);
    let _ = submit(s, ok_round(a, C_INIT, C1).with_partial(user_partial(s, NONCE_A)));
    // code 8: the output is below min_out
    let failed = failed_round(b, C1, 8).with_partial(user_partial(s, NONCE_B));
    assert_eq(failed.new_c, failed.old_c);
    let failed_block = submit(s, failed);
    assert_state(s, 2, 3, C1);
    assert_eq(s.queue().head(), Head { index: 2, since: failed_block });
    assert_eq(s.queue().done_at(1), DONE_APPLIED);
    assert_eq(failed.note(), SwapOutcomeNote { code: 8, amount_out: 0, request_id: b });
    let effects = last_tx_shape(s.env);
    assert_eq(effects.note_hashes, 1);
    assert_eq(effects.public_logs, 1);
    assert_eq(completion(s, failed.partial), [OUTCOME_SLOT, 8, 0, b]);
    assert_eq(notes_of(s, s.user).count, 2);
    let r = ok_round(c, C1, C2).with_partial(user_partial(s, NONCE_C));
    let block = submit(s, r);
    assert_state(s, 3, 3, C2);
    assert_eq(s.queue().head(), Head { index: 3, since: block });
    assert_eq(completion(s, r.partial), [OUTCOME_SLOT, 0, AMOUNT_OUT, c]);
    assert_eq(notes_of(s, s.user).count, 3);
}

// ---- redeem -----------------------------------------------------------------

// A non-secret-shared swap's completed note is redeemed once.
#[test(should_fail_with = "no swap note of this request to redeem")]
unconstrained fn a_non_secret_shared_swaps_note_is_not_redeemed_twice() {
    let s = setup();
    let a = swap(s, AMOUNT_IN, NONCE_A);
    let _ = submit(s, ok_round(a, C_INIT, C1).with_partial(user_partial(s, NONCE_A)));
    let _ = redeem(s, s.user, a);
    let _ = redeem(s, s.user, a);
}

// ---- apply refusals ---------------------------------------------------------

#[test(should_fail_with = "Function apply can only be called by the same contract")]
unconstrained fn apply_from_outside_the_contract_is_refused() {
    let s = setup();
    let a = swap(s, AMOUNT_IN, NONCE_A);
    s.env.call_public(
        s.relayer,
        AmmTip::at(s.app).apply(ok_round(a, C_INIT, C1).result()),
    );
}

// ---- skip ---------------------------------------------------------------------

// One block short of the configured stale_blocks the probe's skip is
// refused and changes nothing; at stale_blocks it lands (the probe refuses
// for the queue's reasons and not for its own: gas, sender): the head
// moves, done = skipped, the pool is unchanged, no note is completed for
// the skipped request, and the next entry is served on the same state.
#[test]
unconstrained fn skip_is_refused_one_block_short_and_drops_the_head_at_stale_blocks() {
    let s = setup_with_probe();
    let _ = swap(s, AMOUNT_IN, NONCE_A);
    let since = s.queue().head().since;
    let b = swap(s, AMOUNT_IN, NONCE_B);
    mine_until_next_block_is(s, since + STALE - 1);
    s.queue().assert_refused_without_effect(|| try_skip(s));
    assert_eq(s.env.last_block_number(), since + STALE - 1);
    assert(try_skip(s));
    assert_eq(s.env.last_block_number(), since + STALE);
    assert_eq(s.queue().head(), Head { index: 1, since: since + STALE });
    assert_eq(s.queue().done_at(0), DONE_SKIPPED);
    assert_eq(pool(s), C_INIT);
    let skipped = last_tx_shape(s.env);
    assert_eq(skipped.note_hashes, 0);
    assert_eq(skipped.public_logs, 0);
    assert_eq(notes_of(s, s.user).count, 0);
    let r = ok_round(b, C_INIT, C1).with_partial(user_partial(s, NONCE_B));
    let _ = submit(s, r);
    assert_state(s, 2, 2, C1);
    assert_completed(s, r, s.user, 1);
}
