//! An ok = 0 round and the round after it: the failed round is a no-op that
//! finishes its request, and the next runs on the commitment the failed
//! round kept, which names the version the nodes load for it.
use crate::{
    assert_state, C1, C2, C_INIT, DEPOSIT, deposit, deposit_with_receipts, failed_round,
    last_tx_log, NONCE_A, NONCE_B, NONCE_C, ok_round, OTHER_POSITION, outcome_notes, setup,
    submit_deposit, user_partial,
};
use lending_market::app::OUTCOME_SLOT;
use pss_public_contract::{DONE_APPLIED, Head};
use pss_public_contract::partial_note::completion_log_tag;

// ok = 0 is a no-op that finishes the request (a receipt intake opening
// flagged ok = 0, code 17): the slot stays, the head moves, done = applied,
// and the note `apply` completes says why with zeros: it names no position
// and confers nothing (test_ownership.nr's naming rule). The next round loads
// the parent version: the failed round left the opening deposit's
// commitment C1 in the slot (the nodes create no version for it), so the
// next deposit's round runs on that version (old_c = C1, the commitment the
// slot kept) and lands. Each round completes its own request's note.
#[test]
unconstrained fn a_failed_round_is_a_no_op_and_the_next_runs_on_the_kept_commitment() {
    let s = setup();
    let d = deposit(s, DEPOSIT, NONCE_A);
    let b = deposit_with_receipts(s, DEPOSIT, NONCE_B);
    let r = deposit_with_receipts(s, DEPOSIT, NONCE_C);
    let _ = submit_deposit(s, ok_round(d, C_INIT, C1).with_partial(user_partial(s, NONCE_A)));
    let failed = failed_round(b, C1, 17).with_partial(user_partial(s, NONCE_B));
    assert_eq(failed.new_c, failed.old_c);
    let failed_block = submit_deposit(s, failed);
    assert_state(s, 2, 3, C1);
    assert_eq(s.queue().head(), Head { index: 2, since: failed_block });
    let completion: [Field; 9] = last_tx_log(s, completion_log_tag(failed.partial));
    assert_eq(completion, [OUTCOME_SLOT, 17, 0, 0, 0, 0, 0, 0, b]);
    assert_eq(outcome_notes(s, s.user).count, 2);
    let mut opened = ok_round(r, C1, C2).with_partial(user_partial(s, NONCE_C));
    opened.position = OTHER_POSITION;
    let block = submit_deposit(s, opened);
    assert_state(s, 3, 3, C2);
    assert_eq(s.queue().head(), Head { index: 3, since: block });
    assert_eq(s.queue().done_at(1), DONE_APPLIED);
    assert_eq(outcome_notes(s, s.user).count, 3);
}
