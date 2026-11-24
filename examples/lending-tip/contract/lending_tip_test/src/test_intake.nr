//! Intake: the non-secret-shared deposit under both non-secret-shared intakes (on-chain intake's
//! request log with the request's partial note among the inputs and no
//! address; receipt intake's three node receipts and no log; one request id
//! for both), the static-validity predicates and the refusals, on the non-secret-shared
//! deposit and on the secret-shared entries. The queue's own rules (order, a
//! repeated request id) are pss_public_contract_test's.
use crate::{
    assert_state, BORROW, ROUND_BORROW, C_INIT, DEPOSIT, deploy_configured_unfunded, deposit,
    deposit_from, deposit_with, handled_intake, held_setup, Intake, is_seen, last_tx_log, NONCE_A,
    NONCE_B, node_receipts, no_tx_log, partial_of, plain_id, POSITION, receipted, ROUND_REPAY,
    request_liquidation_of, request_owner, rho_of, setup, shared_setup, user_partial,
};
use aztec::protocol::address::AztecAddress;
use lending_market::layouts::BORROW_SHARED_LAYOUT;
use lending_market::app::{
    TWO_POW_DEPTH, valid_deposit, valid_liquidation, valid_owner_request, valid_plain_deposit, valid_quote,
    valid_view,
};
use lending_tip::LendingTip;
use pss_public_contract::{Refunds, request_log_tag, TWO_POW_128};
use pss_public_contract::partial_note::use_nullifier;
use aztec::test::helpers::txe_oracles;
use pss_probe::PssProbe;
use pss_tip_test::audit::assert_no_requester;

// The audit of the last transaction's effect, by a probe deployed for it (its `tx_names_no_requester` utility).
unconstrained fn assert_last_tx_names_no_requester(s: crate::Setup, auditor: AztecAddress, accounts: [AztecAddress; 4]) {
    let tx_hash = txe_oracles::get_last_tx_effects().tx_hash;
    assert(s.env.execute_utility(PssProbe::at(auditor).tx_names_no_requester(tx_hash, accounts)));
}

// 2^128: the smallest value that is not a u128

// The deposit predicate: a position below 2^16 (0 opens a new one) and a
// non-zero u128 amount (codes 3, 2, 1); under the non-secret-shared intakes
// the partial note after them is not checked (the request function computes
// it).
#[test]
fn valid_deposit_checks_the_static_validity_only() {
    assert(valid_deposit([0, 1]));
    assert(valid_deposit([TWO_POW_DEPTH - 1, TWO_POW_128 - 1]));
    assert(!valid_deposit([TWO_POW_DEPTH, 1]));
    assert(!valid_deposit([-1, 1]));
    assert(!valid_deposit([0, 0]));
    assert(!valid_deposit([0, TWO_POW_128]));
    assert(!valid_deposit([0, -1]));
    assert(valid_plain_deposit([0, 1, 0x1234]));
    assert(!valid_plain_deposit([0, 0, 0x1234]));
}

// The secret-shared borrow, repay and view name an open position: 1 .. 2^16 - 1,
// never the open sentinel 0; a quote takes no app input.
#[test]
fn valid_owner_request_takes_no_position_0() {
    assert(valid_owner_request([1, 1]));
    assert(valid_owner_request([TWO_POW_DEPTH - 1, TWO_POW_128 - 1]));
    assert(!valid_owner_request([0, 1]));
    assert(!valid_owner_request([TWO_POW_DEPTH, 1]));
    assert(!valid_owner_request([1, 0]));
    assert(!valid_owner_request([1, TWO_POW_128]));
    assert(valid_view([1]));
    assert(!valid_view([0]));
    assert(!valid_view([TWO_POW_DEPTH]));
    assert(valid_quote([]));
}

// A secret-shared liquidation (K = 2: one probe): a non-zero u128 budget
// (codes 1, 2), a count of 1, the counted position in 1 .. 2^16 - 1 (code 3).
// (One liquidation refusal below shows `liquidate_shared` applies it.)
#[test]
fn valid_liquidation_checks_the_index_rules() {
    assert(valid_liquidation([1, 1, 1000]));
    assert(valid_liquidation([TWO_POW_DEPTH - 1, 1, TWO_POW_128 - 1]));
    assert(!valid_liquidation([1, 0, 1000]));
    assert(!valid_liquidation([1, 2, 1000]));
    assert(!valid_liquidation([0, 1, 1000]));
    assert(!valid_liquidation([TWO_POW_DEPTH, 1, 1000]));
    assert(!valid_liquidation([-1, 1, 1000]));
    assert(!valid_liquidation([1, 1, 0]));
    assert(!valid_liquidation([1, 1, TWO_POW_128]));
}

// A partial note is used by one request: the same rho under the other
// non-secret-shared intake, with a fresh user nonce (so another request id,
// which the queue has not seen), reverts at its request on P's use
// nullifier.
#[test(should_fail_with = "Nullifier collision")]
unconstrained fn the_same_partial_note_under_the_other_plain_intake_is_refused() {
    let s = setup();
    let expiry = s.env.next_block_number() + 10;
    deposit_from(s, s.user, 0, DEPOSIT, rho_of(NONCE_A), NONCE_A);
    let r = node_receipts(s, 0, DEPOSIT, user_partial(s, NONCE_A), NONCE_B, expiry);
    deposit_with(s, s.user, 0, DEPOSIT, rho_of(NONCE_A), NONCE_B, expiry, r);
}

// Receipts over another partial note (another account's, or another rho)
// do not verify against the one the request function computes.
#[test(should_fail_with = "invalid receipt from node 0")]
unconstrained fn receipts_over_another_partial_note_are_refused() {
    let s = setup();
    let expiry = s.env.next_block_number() + 10;
    let r = node_receipts(s, 0, DEPOSIT, partial_of(s.other, rho_of(NONCE_A)), NONCE_A, expiry);
    deposit_with(s, s.user, 0, DEPOSIT, rho_of(NONCE_A), NONCE_A, expiry, r);
}

// The hidden requester: no account address appears in a deposit's
// arguments under either non-secret-shared intake, in the public call each enqueues
// (`append_onchain(id, plain, escrow, held)`: the queue entry and the log
// body; `append_receipt(id, expiry_block, escrow, held)`) or anywhere in their
// transactions' effects. The randomness rho is a private argument and
// appears nowhere either; the partial note hides the sender behind it.
//
// What each intake queues: an opening deposit under on-chain intake queues
// the content-derived id (namespace = the contract, vk_hash = the deposit
// pin, inputs [0, amount, P] with P the partial note the request function
// computes from the sender and its rho, no requester), pushes P's use
// nullifier, and emits the non-secret-shared request log [tag, 0, amount,
// P, user_nonce]. Under receipt intake the inputs stay off the chain: three
// node receipts over the request id and the inputs hash are checked in the
// private function, the queue takes the request id, which is the one
// on-chain intake gives the same inputs (one circuit, one vk pin), and the
// transaction emits no request log. The partial note comes from the sender
// and its rho, never from an argument: another account with the same rho,
// inputs and nonce sends another request (its own P in the log and the id).
#[test]
unconstrained fn an_intake_queues_the_senders_partial_note_and_names_no_requester() {
    let s = setup();
    let auditor = crate::deploy_probe(s);
    let accounts = [s.user, s.other, s.relayer, s.deployer];
    let d = deposit(s, DEPOSIT, NONCE_A);
    let dlog: [Field; 4] = last_tx_log(s, request_log_tag(d));
    assert_no_requester([0, DEPOSIT, rho_of(NONCE_A), NONCE_A], accounts);
    assert_no_requester([d].concat(dlog), accounts);
    assert_last_tx_names_no_requester(s, auditor, accounts);
    // the same scan for rho's value
    let rho = AztecAddress { inner: rho_of(NONCE_A) };
    assert_last_tx_names_no_requester(s, auditor, [rho, rho, rho, rho]);
    // what on-chain intake queued and logged
    assert_eq(s.queue().request_at(0), d);
    assert(is_seen(s, d));
    assert_state(s, 0, 1, C_INIT);
    let p = user_partial(s, NONCE_A);
    assert_eq(dlog, [0, DEPOSIT, p, NONCE_A]);
    let effects = txe_oracles::get_last_tx_effects();
    let mut found = false;
    for i in 0..effects.nullifiers.len() {
        found |= effects.nullifiers.get(i)
            == aztec::protocol::hash::compute_siloed_nullifier(s.app, use_nullifier(p));
    }
    assert(found);

    let expiry = s.env.next_block_number() + 10;
    let p = user_partial(s, NONCE_B);
    let r = node_receipts(s, 0, DEPOSIT, p, NONCE_B, expiry);
    deposit_with(s, s.user, 0, DEPOSIT, rho_of(NONCE_B), NONCE_B, expiry, r);
    let id = plain_id(s, 0, DEPOSIT, p, NONCE_B);
    let mut signatures = [0; 12];
    for i in 0..3 {
        signatures[4 * i] = r[i].s[0];
        signatures[4 * i + 1] = r[i].s[1];
        signatures[4 * i + 2] = r[i].e[0];
        signatures[4 * i + 3] = r[i].e[1];
    }
    assert_no_requester(
        [0, DEPOSIT, rho_of(NONCE_B), NONCE_B, expiry as Field].concat(signatures),
        accounts,
    );
    assert_no_requester([id, expiry as Field], accounts);
    assert_last_tx_names_no_requester(s, auditor, accounts);
    let rho = AztecAddress { inner: rho_of(NONCE_B) };
    assert_last_tx_names_no_requester(s, auditor, [rho, rho, rho, rho]);
    // what receipt intake queued: the id on-chain intake gives the same
    // inputs, and no request log
    assert_eq(s.queue().request_at(1), id);
    assert(is_seen(s, id));
    assert_state(s, 0, 2, C_INIT);
    assert(no_tx_log(s, request_log_tag(id)));

    // another account, the same rho, inputs and nonce: its own P and id
    deposit_from(s, s.other, 0, DEPOSIT, rho_of(NONCE_A), NONCE_A);
    let theirs_p = partial_of(s.other, rho_of(NONCE_A));
    let theirs = plain_id(s, 0, DEPOSIT, theirs_p, NONCE_A);
    assert(d != theirs);
    assert_eq(s.queue().request_at(2), theirs);
    let log: [Field; 4] = last_tx_log(s, request_log_tag(theirs));
    assert_eq(log, [0, DEPOSIT, theirs_p, NONCE_A]);
}

// Statically invalid requests are refused before anything is queued. A
// position out of range has no note to hold, so the note check refuses it
// first.
#[test(should_fail_with = "the sender holds no note of this position")]
unconstrained fn a_deposit_to_a_position_out_of_range_is_refused() {
    let s = setup();
    deposit_from(s, s.user, TWO_POW_DEPTH, DEPOSIT, rho_of(NONCE_A), NONCE_A);
}

#[test(should_fail_with = "invalid inputs")]
unconstrained fn a_deposit_of_zero_is_refused() {
    let s = setup();
    deposit_from(s, s.user, 0, 0, rho_of(NONCE_A), NONCE_A);
}

#[test(should_fail_with = "invalid inputs")]
unconstrained fn a_receipt_intake_deposit_wider_than_u128_is_refused() {
    let s = setup();
    let expiry = s.env.next_block_number() + 10;
    let r = node_receipts(s, 0, TWO_POW_128, user_partial(s, NONCE_A), NONCE_A, expiry);
    deposit_with(s, s.user, 0, TWO_POW_128, rho_of(NONCE_A), NONCE_A, expiry, r);
}

// The same static checks on the secret-shared entries, over the plaintext in the
// user's private function, before anything is queued (the user holds a note
// of POSITION, so only the inputs are at fault).
#[test(should_fail_with = "invalid inputs")]
unconstrained fn a_shared_borrow_of_zero_is_refused() {
    let s = held_setup();
    let _ = request_owner(s, s.user, ROUND_BORROW, POSITION, 0, 1);
}

// Position 0 opens a position only in a deposit, and names no position to
// hold a note of.
#[test(should_fail_with = "position 0 names no position")]
unconstrained fn a_shared_borrow_from_position_0_is_refused() {
    let s = held_setup();
    let _ = request_owner(s, s.user, ROUND_BORROW, 0, BORROW, 1);
}

#[test(should_fail_with = "invalid inputs")]
unconstrained fn a_shared_repayment_wider_than_u128_is_refused() {
    let s = held_setup();
    let _ = request_owner(s, s.user, ROUND_REPAY, POSITION, TWO_POW_128, 1);
}

// The nodes sign the clear values they store: a user who sends the nodes
// another position than the one C commits to gets receipts over another
// sharing digest, which the request function refuses, so the request is
// never queued (it would land as a round that does not open C).
#[test(should_fail_with = "invalid receipt from node 0")]
unconstrained fn receipts_over_another_clear_position_are_refused() {
    let s = held_setup();
    let i: Intake<7> = handled_intake(s, s.user, ROUND_BORROW, [POSITION, BORROW], 1, BORROW_SHARED_LAYOUT);
    let handle = [partial_of(s.user, i.handle_rho), i.handle_key];
    let values = [POSITION, BORROW].concat(handle).concat([partial_of(s.user, i.rho), i.key, i.tag]);
    let mut signed = values;
    signed[0] = POSITION + 1;
    let (_, expiry, r) = receipted(s, ROUND_BORROW, values, signed, i.blinding, BORROW_SHARED_LAYOUT, i.sharing);
    s.env.call_private(
        s.user,
        LendingTip::at(s.app).borrow_shared(
            POSITION,
            BORROW,
            i.handle_rho,
            i.handle_key,
            i.rho,
            i.key,
            i.tag,
            i.sharing,
            expiry,
            r,
        ),
    );
}

#[test(should_fail_with = "invalid inputs")]
unconstrained fn a_shared_liquidation_of_a_position_out_of_range_is_refused() {
    let s = shared_setup();
    let _ = request_liquidation_of(s, [TWO_POW_DEPTH], 1, 1);
}

// The append wrappers are #[only_self]: nobody queues a request id the
// private intake did not compute (refused before any state is read, so the
// deployment needs no balances or init).
#[test(should_fail_with = "Function append_onchain can only be called by the same contract")]
unconstrained fn append_onchain_from_outside_the_contract_is_refused() {
    let s = deploy_configured_unfunded();
    let plain = pss_public_contract::PlainRequest { inputs: [0, DEPOSIT, 0x9a], user_nonce: NONCE_A };
    s.env.call_public(s.user, LendingTip::at(s.app).append_onchain(0x1d, plain, Refunds::none()));
}

#[test(should_fail_with = "Function append_receipt can only be called by the same contract")]
unconstrained fn append_receipt_from_outside_the_contract_is_refused() {
    let s = deploy_configured_unfunded();
    s.env.call_public(s.user, LendingTip::at(s.app).append_receipt(0x1d, 1000, Refunds::none()));
}
