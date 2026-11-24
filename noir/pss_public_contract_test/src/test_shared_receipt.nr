//! Secret-shared receipt intake: a TXE suite of `request_shared` through the
//! test contract, on the private-outcome deployment of `test_outcome` (the
//! held key initialised, the private-outcome circuit pinned), so the first
//! case lands a secret-shared request's result through the outcome brick.
//! The inputs commitment `C` and the secret-shared chain request id are the
//! library's unit tests (`shared_intake::test`).
//!
//! The request is a swap with a shared recipient: C commits to
//! `[amount_in, direction, recipient, outcome_key, outcome_tag]`, the order
//! of the round's ABI walk, then the blinding. The recipient is the user's own
//! account, as by default, so the requester audit also shows that the
//! recipient never reaches the chain. Every value is shared, so the sharing
//! holds six-element summand vectors, the blinding's last. Receipts are
//! signed by the test signer of `nodes` with the node keys of
//! testvectors/keys.json over C and the sharing digest D; the sharing is
//! pss_tip_test's builder, and the ids, D and the messages are recomputed
//! here with aztec-nr's `poseidon2_hash`.
use crate::nodes::receipts;
use crate::PssPublicTest;
use crate::test::last_tx_summary;
use crate::test_shared_onchain::LAYOUT;
use crate::test_outcome::{
    APPLIED, H0, H1, held, OUTCOME_KEY, OUTCOME_TAG, outcome_vk, result, Setup, setup,
    signatures,
};
use aztec::protocol::abis::function_selector::FunctionSelector;
use aztec::protocol::address::AztecAddress;
use aztec::protocol::hash::poseidon2_hash;
use aztec::protocol::traits::ToField;
use aztec::test::helpers::txe_oracles;
use pss_core::tip::intake::{SHARING_DOMAIN, SUMMANDS_DOMAIN};
use pss_public_contract::{DONE_APPLIED, Head, NODES, Receipt, RECEIPT_DOMAIN, Sharing};
use pss_tip_test::sharing;
use pss_tip_test::stage_proof;

global AMOUNT: Field = 25000;
global DIRECTION: Field = 0;
global BLINDING: Field = 0x5b1b1;

/// C's values for a swap of `amount` in `direction` to the user.
unconstrained fn values_of(s: Setup, amount: Field, direction: Field) -> [Field; 5] {
    [amount, direction, s.user.to_field(), OUTCOME_KEY, OUTCOME_TAG]
}

unconstrained fn values(s: Setup) -> [Field; 5] {
    values_of(s, AMOUNT, DIRECTION)
}

unconstrained fn commitment(values: [Field; 5], blinding: Field) -> Field {
    poseidon2_hash(values.concat([blinding]))
}

/// A Rep3 sharing of `values` and `blinding` under the all-shared layout
/// (pss_tip_test's builder).
unconstrained fn sharing_of(values: [Field; 5], blinding: Field) -> Sharing<6> {
    sharing::sharing_of(LAYOUT, values, blinding)
}

/// The summand commitments S_j = poseidon2([SUMMANDS_DOMAIN, s_j...,
/// salt_j]).
unconstrained fn commitments(sharing: Sharing<6>) -> [Field; 3] {
    let mut c = [0; 3];
    for j in 0..3 {
        c[j] = poseidon2_hash([SUMMANDS_DOMAIN].concat(sharing.summands[j]).concat([sharing.salts[j]]));
    }
    c
}

/// The sharing digest D = poseidon2([SHARING_DOMAIN, S_0, S_1, S_2, kinds...,
/// clear values...]): every one of C's five values is CHOSEN (kind 1), so
/// there is no clear value.
unconstrained fn digest(sharing: Sharing<6>) -> Field {
    let c = commitments(sharing);
    poseidon2_hash([SHARING_DOMAIN, c[0], c[1], c[2], 1, 1, 1, 1, 1])
}

/// The chain request id: poseidon2([namespace, vk_hash, C]) under the
/// private-outcome circuit's vk hash.
unconstrained fn expected_id(s: Setup, values: [Field; 5], blinding: Field) -> Field {
    poseidon2_hash([s.app.to_field(), s.outcome_vk_hash, commitment(values, blinding)])
}

/// The three receipts the nodes sign over C and the digest of
/// `sharing_of(values, blinding)` for the request of `values` under
/// `blinding`, expiring at `expiry_block`.
unconstrained fn node_receipts(s: Setup, values: [Field; 5], blinding: Field, expiry_block: u32) -> [Receipt; NODES] {
    receipts_over(s, values, blinding, expiry_block, digest(sharing_of(values, blinding)))
}

/// The three receipts over C and the sharing digest `d`.
unconstrained fn receipts_over(s: Setup, values: [Field; 5], blinding: Field, expiry_block: u32, d: Field) -> [Receipt; NODES] {
    let message = poseidon2_hash([
        RECEIPT_DOMAIN,
        expected_id(s, values, blinding),
        commitment(values, blinding),
        expiry_block as Field,
        d,
    ]);
    receipts(message)
}

unconstrained fn request_from(s: Setup, from: AztecAddress, values: [Field; 5], expiry_block: u32, r: [Receipt; NODES]) {
    request_with(s, from, values, sharing_of(values, BLINDING), expiry_block, r);
}

unconstrained fn request_with(
    s: Setup,
    from: AztecAddress,
    values: [Field; 5],
    sharing: Sharing<6>,
    expiry_block: u32,
    r: [Receipt; NODES],
) {
    s.env.call_private(from, PssPublicTest::at(s.app).request_shared(values, sharing, expiry_block, r));
}

unconstrained fn is_seen(s: Setup, request_id: Field) -> bool {
    s.env.view_public(PssPublicTest::at(s.app).is_seen(request_id))
}

/// Whether none of `values` appears anywhere in the last transaction's
/// effect: the requester audit (pss_tip_test `audit`) over any four fields.
unconstrained fn assert_last_tx_holds_none(s: Setup, values: [Field; 4]) {
    let tx_hash = txe_oracles::get_last_tx_effects().tx_hash;
    let as_addresses = values.map(|v| AztecAddress { inner: v });
    assert(s.env.execute_utility(PssPublicTest::at(s.app).tx_names_no_requester(tx_hash, as_addresses)));
}

// ---- TXE: request_shared through the test contract ------------------------

// Three valid receipts over C, presented by any account (a receipt names no
// requester), queue the secret-shared request id; the transaction emits no
// log, public or private, no note and no message. The public calls the
// secret-shared intake enqueues hold the request id, the expiry block and the
// key epoch, and nothing else: the library's private half returns the
// request id and enqueues only the app's `assert_key_epoch(epoch, false)`
// (`key_epoch::signing_keys`, under the selector the library builds from
// that signature; here epoch 0, the constructor's keys); the app's one
// enqueue line (`request_shared`'s `self.enqueue_self.append_receipt(
// request_id, expiry_block)`, the contract's interface at its own address)
// is a public call to the app whose calldata after the selector is
// `[request_id, expiry_block]`. (TestEnvironment's private context cannot
// enqueue, so the calls are checked as the interface builds them.) The
// request then plugs into the private-outcome result path: the round's
// result for the queued id (the outcome sealed to the recipient under the
// outcome key C commits to) lands, writes the new commitment and finishes
// the head. A wrong or missing receipt is `check_receipts`' unit tests'
// (`test_receipt`), and the message's hashes are pss_public_contract's;
// the refusals below show the request binds the sharing's digest and that
// a sharing must open C.
#[test]
unconstrained fn three_valid_receipts_over_c_from_any_account_queue_the_request_which_lands() {
    let s = setup();
    let expiry = s.env.next_block_number() + 10;
    let v = values(s);
    let r = node_receipts(s, v, BLINDING, expiry);
    let id = expected_id(s, v, BLINDING);
    let check = PssPublicTest::at(s.app).assert_key_epoch(0, false);
    assert_eq(check.target_contract, s.app);
    assert_eq(check.selector, comptime { FunctionSelector::from_signature("assert_key_epoch(u32,bool)") });
    assert_eq(check.args, [0, 0]);
    let call = PssPublicTest::at(s.app).append_receipt(id, expiry);
    assert_eq(call.target_contract, s.app);
    assert_eq(call.selector, comptime { FunctionSelector::from_signature("append_receipt(Field,u32)") });
    assert_eq(call.args, [id, expiry as Field]);

    request_from(s, s.relayer, v, expiry, r);
    assert_eq(s.queue().request_at(0), id);
    assert(is_seen(s, id));
    assert_eq(s.queue().tail(), 1);
    let effects = last_tx_summary(s.env, s.app);
    assert_eq(effects.public_logs, 0);
    assert_eq(effects.private_logs, 0);
    assert_eq(effects.note_hashes, 0);
    assert_eq(effects.l2_to_l1_msgs, 0);

    let round = result(s, id, H0, H1, APPLIED);
    stage_proof(s.env, s.app, s.relayer, outcome_vk());
    s.env.call_private(s.relayer, PssPublicTest::at(s.app).process_result_private(round, signatures(s, round)));
    let block = s.env.last_block_number();
    assert_eq(held(s), H1);
    assert_eq(s.queue().head(), Head { index: 1, since: block });
    assert_eq(s.env.view_public(PssPublicTest::at(s.app).done_at(0)), DONE_APPLIED);
}

// The hidden requester and the hidden inputs: no account address (the
// requester, which is also the recipient, and the relayer), no input value,
// neither C, the blinding, the outcome key nor the outcome tag appears
// anywhere in the transaction's effects.
#[test]
unconstrained fn a_shared_request_names_no_requester_and_shows_no_input() {
    let s = setup();
    let expiry = s.env.next_block_number() + 10;
    let v = values(s);
    request_from(s, s.user, v, expiry, node_receipts(s, v, BLINDING, expiry));
    let c = commitment(v, BLINDING);
    assert_last_tx_holds_none(s, [s.user.to_field(), s.relayer.to_field(), AMOUNT, c]);
    assert_last_tx_holds_none(s, [BLINDING, OUTCOME_KEY, OUTCOME_TAG, s.user.to_field()]);
}

// Receipts over another sharing's digest (the nodes checked other summand
// vectors) do not cover this sharing, though both open C.
#[test(should_fail_with = "invalid receipt from node 0")]
unconstrained fn receipts_over_another_sharing_are_refused() {
    let s = setup();
    let expiry = s.env.next_block_number() + 10;
    let v = values(s);
    let mut other = sharing_of(v, BLINDING);
    other.salts[1] += 1;
    request_from(s, s.user, v, expiry, receipts_over(s, v, BLINDING, expiry, digest(other)));
}

// A sharing that does not open C is refused in the user's own proof, even
// with three receipts over its digest: the nodes signed summand vectors
// that do not add up to C's values, and such a request is never queued.
#[test(should_fail_with = "the summands do not add up to a shared value of C")]
unconstrained fn a_sharing_that_does_not_open_c_is_never_queued() {
    let s = setup();
    let expiry = s.env.next_block_number() + 10;
    let v = values(s);
    let mut bad = sharing_of(v, BLINDING);
    bad.summands[2][0] += 1;
    request_with(s, s.user, v, bad, expiry, receipts_over(s, v, BLINDING, expiry, digest(bad)));
}

// Static validity is asserted over the plaintext the nodes never see: valid
// receipts over an invalid direction are refused.
#[test(should_fail_with = "invalid inputs")]
unconstrained fn valid_receipts_over_invalid_inputs_are_refused() {
    let s = setup();
    let expiry = s.env.next_block_number() + 10;
    let v = values_of(s, AMOUNT, 2);
    request_from(s, s.user, v, expiry, node_receipts(s, v, BLINDING, expiry));
}
