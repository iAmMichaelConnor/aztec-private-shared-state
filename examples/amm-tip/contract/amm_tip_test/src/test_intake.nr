//! Intake: on-chain intake (`swap`, the non-secret-shared request log) and receipt intake
//! (`swap_with_receipts`, three node receipts), each committing the
//! sender's partial note from `rho` (its use nullifier pushed, once per
//! partial note) and telling the sender's PXE of it offchain, the hidden
//! requester, the static-validity predicate and its check at both intakes,
//! the largest valid swap, and `append_receipt`'s `#[only_self]`. The queue's and the receipts' own
//! rules (order, repeats, the receipt checks and expiry) are
//! pss_public_contract_test's.
use crate::{
    AMOUNT_IN, assert_state, C_INIT, DIRECTION, is_seen, last_tx_log, MIN_OUT, node_receipts,
    NONCE_A, NONCE_B, NONCE_C, rho_of, setup, setup_with_probe, swap, swap_as, swap_id,
    swap_inputs, swap_with, swap_with_receipts_as, TWO_POW_64, user_partial,
};
use amm_tip::AmmTip;
use amm_tip::app::{valid_plain_swap, valid_swap};
use pss_public_contract::request_log_tag;
use pss_public_contract::partial_note::use_nullifier;
use aztec::protocol::hash::compute_siloed_nullifier;
use aztec::test::helpers::txe_oracles;
use pss_probe::PssProbe;
use pss_tip_test::audit::assert_no_requester;

// The static-validity predicate: a non-zero u64 amount, a direction of 0 or
// 1 and a u64 min_out (0 sets no limit).
#[test]
fn valid_swap_checks_the_static_validity_only() {
    assert(valid_swap([1, 0, 0]));
    assert(valid_swap([TWO_POW_64 - 1, 1, TWO_POW_64 - 1]));
    assert(!valid_swap([0, 0, 0]));
    assert(!valid_swap([TWO_POW_64, 0, 0]));
    assert(!valid_swap([-1, 0, 0]));
    assert(!valid_swap([1, 2, 0]));
    assert(!valid_swap([1, -1, 0]));
    assert(!valid_swap([1, 0, TWO_POW_64]));
}

// The non-secret-shared swap's predicate is `valid_swap` over its swap
// inputs: the partial note is not checked.
#[test]
fn valid_plain_swap_checks_the_swap_inputs_only() {
    assert(valid_plain_swap([1, 0, 0, 0]));
    assert(valid_plain_swap([1, 0, 0, -1]));
    assert(!valid_plain_swap([0, 0, 0, 0x5eed]));
    assert(!valid_plain_swap([1, 2, 0, 0x5eed]));
}

// On-chain intake: swap queues the content-derived id (namespace = the contract,
// vk_hash = the on-chain intake pin, no requester) over the inputs and the
// sender's partial note P, and emits the non-secret-shared request log
// [tag, amount_in, direction, min_out, P, user_nonce] that the chain reader
// fetches by compute_log_tag(request_id, REQUEST_DOMAIN). The request
// pushes P's use nullifier and its one offchain message puts nothing on
// chain: no private log, no note hash. The hidden requester: no account
// address appears in the swap's arguments, in the public call it enqueues
// (`append_onchain(id, plain)`: the queue entry and the log body) or
// anywhere in the transaction's effects. Another sender's request with the
// same rho commits another partial note (P names its owner), so it is
// queued too.
#[test]
unconstrained fn an_on_chain_intake_swap_is_queued_with_the_plain_log_names_no_requester_and_its_rho_is_per_sender() {
    let s = setup_with_probe();
    let id = swap(s, AMOUNT_IN, NONCE_A);
    assert_eq(s.queue().request_at(0), id);
    assert(is_seen(s, id));
    assert_eq(s.queue().tail(), 1);
    // the head clock restarted for the first entry; the pool is untouched
    assert_eq(s.queue().head().index, 0);
    assert_eq(crate::pool(s), C_INIT);
    let p = user_partial(s, NONCE_A);
    let log: [Field; 5] = last_tx_log(s, request_log_tag(id));
    assert_eq(log, [AMOUNT_IN, DIRECTION, MIN_OUT, p, NONCE_A]);
    let effects = txe_oracles::get_last_tx_effects();
    assert_eq(effects.private_logs.len(), 0);
    assert_eq(effects.note_hashes.len(), 0);
    let mut used = false;
    for i in 0..effects.nullifiers.len() {
        used |= effects.nullifiers.get(i) == compute_siloed_nullifier(s.app, use_nullifier(p));
    }
    assert(used);

    let accounts = [s.user, s.trader_b, s.relayer, s.deployer];
    assert_no_requester([AMOUNT_IN, DIRECTION, MIN_OUT, rho_of(NONCE_A), NONCE_A], accounts);
    assert_no_requester([id].concat(log), accounts);
    assert(s.env.execute_utility(PssProbe::at(s.probe).tx_names_no_requester(effects.tx_hash, accounts)));

    let b = swap_as(s, s.trader_b, swap_inputs(AMOUNT_IN), NONCE_A);
    assert_eq(s.queue().request_at(1), b);
    assert(b != id);
}

// A partial note is used by one request: a second swap of the same sender
// with the same rho reverts (its use nullifier collides). Both intakes
// commit the partial note through the one `commit_partial`, so this covers
// receipt intake too (and the library's a_partial_note_is_used_by_one_request
// the use nullifier itself).
#[test(should_fail_with = "Nullifier collision")]
unconstrained fn a_second_swap_with_the_same_rho_is_refused() {
    let s = setup();
    let _ = swap(s, AMOUNT_IN, NONCE_A);
    s.env.call_private(s.user, AmmTip::at(s.app).swap(AMOUNT_IN, DIRECTION, MIN_OUT, rho_of(NONCE_A), NONCE_B));
}

// The hidden requester, receipt intake: the same for swap_with_receipts,
// whose public call is `append_receipt(id, expiry_block)`. Then the largest
// valid request is queued by both intakes: an amount and a limit of
// 2^64 - 1, direction 1.
#[test]
unconstrained fn a_receipt_intake_swap_names_no_requester_and_the_largest_valid_swap_is_queued_by_both_intakes() {
    let s = setup_with_probe();
    let expiry = s.env.next_block_number() + 10;
    let r = node_receipts(s, AMOUNT_IN, NONCE_A, expiry);
    swap_with(s, AMOUNT_IN, NONCE_A, expiry, r);
    let id = swap_id(s, AMOUNT_IN, NONCE_A);
    assert_eq(s.queue().request_at(0), id);
    let accounts = [s.user, s.trader_b, s.relayer, s.deployer];
    let mut signatures = [0; 12];
    for i in 0..3 {
        signatures[4 * i] = r[i].s[0];
        signatures[4 * i + 1] = r[i].s[1];
        signatures[4 * i + 2] = r[i].e[0];
        signatures[4 * i + 3] = r[i].e[1];
    }
    assert_no_requester(
        [AMOUNT_IN, DIRECTION, MIN_OUT, rho_of(NONCE_A), NONCE_A, expiry as Field].concat(signatures),
        accounts,
    );
    assert_no_requester([id, expiry as Field], accounts);
    let tx_hash = txe_oracles::get_last_tx_effects().tx_hash;
    assert(s.env.execute_utility(PssProbe::at(s.probe).tx_names_no_requester(tx_hash, accounts)));

    let largest = [TWO_POW_64 - 1, 1, TWO_POW_64 - 1];
    let a = swap_as(s, s.user, largest, NONCE_B);
    let b = swap_with_receipts_as(s, s.user, largest, NONCE_C);
    assert_eq(s.queue().request_at(1), a);
    assert_eq(s.queue().request_at(2), b);
    assert_state(s, 0, 3, C_INIT);
}

// Each intake asserts `valid_swap` before anything is queued (here on a
// zero amount); the predicate's every case is
// valid_swap_checks_the_static_validity_only's.
#[test(should_fail_with = "invalid inputs")]
unconstrained fn a_zero_amount_is_refused_at_intake() {
    let s = setup();
    assert_state(s, 0, 0, C_INIT);
    let _ = swap(s, 0, NONCE_A);
}

#[test(should_fail_with = "invalid inputs")]
unconstrained fn a_receipt_intake_zero_amount_is_refused_at_intake() {
    let s = setup();
    let expiry = s.env.next_block_number() + 10;
    swap_with(s, 0, NONCE_A, expiry, node_receipts(s, 0, NONCE_A, expiry));
}

// The intake wrappers are #[only_self].
#[test(should_fail_with = "Function append_receipt can only be called by the same contract")]
unconstrained fn append_receipt_from_outside_is_refused() {
    let s = setup();
    s.env.call_public(s.user, AmmTip::at(s.app).append_receipt(0x1d, 1000));
}
