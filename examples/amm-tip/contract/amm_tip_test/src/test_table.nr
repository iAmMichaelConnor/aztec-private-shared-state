//! A three-swap table (examples/amm-tip/README.md, "Running the checks"), run through the contract: trader A sells 10,000 x,
//! trader B sells 7,000 y, trader A sells 1 y, queued in that order on the
//! pool 1,000,000 / 1,500,000. Each round is computed by the circuits' own
//! `swap_round` under `Plain` over the deployed namespace and the pool key, so the
//! commitments are the real ones (c7, c8, c9 below) and the outputs
//! are the circuit's: 14,851 y, 4,738 x, then `ok = false` with code 5 (the
//! output rounds to zero), which applies as a no-op that still moves the
//! head and keeps c9 (the equal commitment: the nodes create no version for
//! it). Each round's public outputs are the circuit's own (amm_swap_tip's
//! main: the request id over the inputs and the trader's partial note,
//! `bound_partial`), and `apply` completes each trader's note with the
//! round's outcome: A holds [0, 14851] and then [5, 0], B [0, 4738]. The
//! pool is node-held, so the one public log of an apply is the completion.
//! In the TXE every transaction is a block of its own; A and B enqueuing
//! in one block would give the same queue order.
//! A's first request goes in by on-chain intake, B's and A's second by
//! receipt intake: one queue and one result path serve both.
use crate::{
    assert_completed, assert_state, deploy_with, init, mine_until_next_block_is, NONCE_A, NONCE_B,
    NSK_APP, partial_for, pool, pool_key, request_id_of, Setup, STALE, submit, swap_as,
    swap_with_receipts_as, SwapRound, try_skip,
};
use amm_tip::app::SwapOutcomeNote;
use amm_tip_circuit::tip::{PlainRound, swap_round};
use amm_total::swap::CODE_ROUNDS_TO_ZERO;
use aztec::protocol::address::AztecAddress;
use aztec::protocol::traits::ToField;
use pss_core::tip::family::Plain;
use pss_core::tip::slot::{commitment, load};
use pss_public_contract::{DONE_APPLIED, Head};

// the pool before index 7 (reserve_x / reserve_y) and the blindings the
// rounds sample
global X0: Field = 1000000;
global Y0: Field = 1500000;
global R7: Field = 0x77;
global R8: Field = 0x88;
global R9: Field = 0x99;
global R10: Field = 0xaa;

// the three requests, [amount_in, direction, min_out]: no limit set
global A_SELLS_10000_X: [Field; 3] = [10000, 0, 0];
global B_SELLS_7000_Y: [Field; 3] = [7000, 1, 0];
global A_SELLS_1_Y: [Field; 3] = [1, 1, 0];

/// The round the circuit computes for `trader`'s request of `inputs` with
/// `nonce` on `reserves` under blinding `r_old`, sampling `r_new`, as a
/// `SwapRound`, and the circuit's own result: amm_swap_tip's main, the pool
/// key loaded and `swap_round` under `Plain` over the swap inputs, the
/// trader's partial note and nonce, read from the round here since its
/// store is the nodes' oracle, which the TXE does not serve. Its request id
/// (`intake::plain` over the inputs and the partial note) is the one the
/// contract queued for the request (`queued`).
unconstrained fn tip_round(
    s: Setup,
    trader: AztecAddress,
    nonce: Field,
    queued: Field,
    reserves: [Field; 2],
    r_old: Field,
    r_new: Field,
    inputs: [Field; 3],
) -> (SwapRound, PlainRound) {
    let key = pool_key(s);
    let partial = partial_for(trader, nonce);
    let t: PlainRound = swap_round(
        s.vks.swap_vk_hash,
        load(s.app.to_field(), key, key, reserves, r_old, r_new),
        inputs,
        Plain { partial_note: partial, user_nonce: nonce },
        NSK_APP,
    );
    assert_eq(t.outputs.request_id, queued);
    let r = SwapRound {
        request_id: t.outputs.request_id,
        partial,
        old_c: t.written.old_c,
        new_c: t.written.new_c,
        ok: t.written.outcome.ok,
        code: t.outputs.app.code,
        amount_out: t.outputs.app.amount_out,
    };
    (r, t)
}

/// What a landed result leaves: the slot holds its new_c (old_c on a
/// no-op), the head is {index + 1, the block it landed in}, the index is
/// applied, and the apply completes `trader`'s note with [code, amount_out,
/// request_id]: one note hash and the completion log, no state log
/// (node-held); `trader`'s PXE then holds `held` notes.
unconstrained fn assert_landed(s: Setup, index: u64, block: u32, r: SwapRound, trader: AztecAddress, held: u32) {
    assert_eq(pool(s), r.new_c);
    assert_eq(s.queue().head(), Head { index: index + 1, since: block });
    assert_eq(s.queue().done_at(index), DONE_APPLIED);
    assert_completed(s, r, trader, held);
}

/// Initialise the pool to the table's starting state (c7) and queue the
/// three requests (A, B, A), A's first by on-chain intake and B's and A's
/// second by receipt intake (one queue, one result path for both); then
/// land the three rounds in queue order, checking each against the table.
/// Returns c9, the pool's final commitment.
unconstrained fn run_table(s: Setup) -> Field {
    let key = pool_key(s);
    let c7 = commitment(s.app.to_field(), key, [X0, Y0], R7);
    init(s, c7);

    let a: AztecAddress = s.user;
    let b: AztecAddress = s.trader_b;
    let id_a1 = swap_as(s, a, A_SELLS_10000_X, NONCE_A);
    let id_b = swap_with_receipts_as(s, b, B_SELLS_7000_Y, NONCE_A);
    let id_a2 = swap_with_receipts_as(s, a, A_SELLS_1_Y, NONCE_B);
    // the queue fixed A first; nothing has run
    assert_state(s, 0, 3, c7);
    assert_eq(id_a1, request_id_of(s, a, A_SELLS_10000_X, NONCE_A));

    // index 7 of the table: A sells 10,000 x and gets 14,851 y
    let (r0, t0) = tip_round(s, a, NONCE_A, id_a1, [X0, Y0], R7, R8, A_SELLS_10000_X);
    assert(t0.written.outcome.ok);
    assert_eq(t0.outputs.app.amount_out, 14851);
    assert_eq(t0.written.fields, [1010000, 1485149]);
    assert_eq(r0.old_c, c7);
    let block0 = submit(s, r0);
    assert_eq(r0.note(), SwapOutcomeNote { code: 0, amount_out: 14851, request_id: id_a1 });
    assert_landed(s, 0, block0, r0, a, 1);

    // index 8: B sells 7,000 y and gets 4,738 x, on the pool A left
    let (r1, t1) = tip_round(s, b, NONCE_A, id_b, t0.written.fields, R8, R9, B_SELLS_7000_Y);
    assert(t1.written.outcome.ok);
    assert_eq(t1.outputs.app.amount_out, 4738);
    assert_eq(t1.written.fields, [1005262, 1492149]);
    assert_eq(r1.old_c, r0.new_c);
    let block1 = submit(s, r1);
    assert_eq(r1.note(), SwapOutcomeNote { code: 0, amount_out: 4738, request_id: id_b });
    assert_landed(s, 1, block1, r1, b, 1);

    // index 9: A sells 1 y; it passed the static checks, but the output
    // rounds to zero against this pool: ok = false, code 5, nothing paid,
    // the stored vector the loaded one (new_c = old_c = c9)
    let c9 = r1.new_c;
    let (r2, t2) = tip_round(s, a, NONCE_B, id_a2, t1.written.fields, R9, R10, A_SELLS_1_Y);
    assert(!t2.written.outcome.ok);
    assert_eq(t2.written.outcome.code, CODE_ROUNDS_TO_ZERO);
    assert_eq(t2.outputs.app.amount_out, 0);
    assert_eq(t2.written.fields, t1.written.fields);
    assert_eq(r2.old_c, c9);
    assert_eq(r2.new_c, c9);
    let block2 = submit(s, r2);
    // the no-op lands like any result: the slot stays c9, the head moves
    // past it, the index is applied (not skipped), and A's second note says
    // why: [5, 0, request_id]
    assert_eq(r2.note(), SwapOutcomeNote { code: 5, amount_out: 0, request_id: id_a2 });
    assert_landed(s, 2, block2, r2, a, 2);
    assert_state(s, 3, 3, c9);
    // the earlier notes stand: A holds two, B its one
    assert_eq(crate::notes_of(s, b).count, 1);
    c9
}

// After the table the queue is drained (head == tail == 3): however long
// it then sits, the probe's skip() is refused and changes nothing (the
// revert itself, "queue is empty", is the library's
// skip_on_a_drained_queue_reverts).
#[test]
unconstrained fn the_three_swap_table_by_both_intakes_then_skip_is_refused_on_the_drained_queue() {
    let s = deploy_with(true);
    let c9 = run_table(s);
    mine_until_next_block_is(s, s.queue().head().since + 3 * STALE);
    s.queue().assert_refused_without_effect(|| try_skip(s));
    assert_state(s, 3, 3, c9);
}
