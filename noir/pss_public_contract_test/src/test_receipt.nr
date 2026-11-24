//! Receipt intake: unit tests of the three-receipt check, and a TXE suite of
//! `request_with_receipts` through the test contract (the receipt message is
//! the library's unit test, `receipt::test`). Receipts are signed by the test
//! signer of `nodes` with the node keys of testvectors/keys.json.
use crate::nodes::{NODE_SIG, NODE_SIG_PK, OUTSIDER_SIG, public_key, receipts, sign, VK_HASH};
use crate::PssPublicTest;
use crate::test::{
    assert_last_tx_names_no_requester, deploy_outsider, is_seen, last_tx_summary, setup, Setup,
};
use aztec::protocol::address::AztecAddress;
use aztec::protocol::hash::poseidon2_hash;
use aztec::protocol::traits::ToField;
use pss_public_contract::{check_receipts, NODES, Receipt, receipt_message};
use pss_public_contract::result::result_signature_verifies;
use pss_tip_test::audit::assert_no_requester;

pub(crate) global AMOUNT: Field = 1000;
pub(crate) global DIRECTION: Field = 1;
pub(crate) global NONCE: Field = 0x2a2a2a;

// ---- unit tests: no contract ----------------------------------------------

// The test signer's keys are the machine's: each sig scalar of keys.json
// gives that file's sig_pk, and a receipt it signs verifies under
// noir-lang/schnorr v0.4.0.
#[test]
unconstrained fn the_test_signer_signs_with_the_node_keys_of_keys_json() {
    for i in 0..NODES {
        assert_eq(public_key(NODE_SIG[i]), NODE_SIG_PK[i]);
        let receipt = sign(NODE_SIG[i], 0x1234);
        assert(result_signature_verifies(NODE_SIG_PK[i], receipt.limbs(), 0x1234));
        assert(!result_signature_verifies(NODE_SIG_PK[i], receipt.limbs(), 0x1235));
    }
}

#[test]
unconstrained fn three_valid_receipts_pass_the_check() {
    let message = receipt_message(0x1d, 0x2e, 77);
    check_receipts(NODE_SIG_PK, receipts(message), message);
}

#[test(should_fail_with = "invalid receipt from node 1")]
unconstrained fn the_check_refuses_a_missing_receipt() {
    let message = receipt_message(0x1d, 0x2e, 77);
    let mut r = receipts(message);
    r[1] = Receipt::missing();
    check_receipts(NODE_SIG_PK, r, message);
}

#[test(should_fail_with = "invalid receipt from node 2")]
unconstrained fn the_check_refuses_a_receipt_by_a_key_no_node_holds() {
    let message = receipt_message(0x1d, 0x2e, 77);
    let mut r = receipts(message);
    r[2] = sign(OUTSIDER_SIG, message);
    check_receipts(NODE_SIG_PK, r, message);
}

// Each receipt counts only in its own node's position: node 0's receipt
// twice is not two receipts.
#[test(should_fail_with = "invalid receipt from node 1")]
unconstrained fn the_check_refuses_one_nodes_receipt_in_anothers_place() {
    let message = receipt_message(0x1d, 0x2e, 77);
    let mut r = receipts(message);
    r[1] = r[0];
    check_receipts(NODE_SIG_PK, r, message);
}

// ---- TXE: request_with_receipts through the test contract -----------------

/// The chain request id of a receipt-intake request: on-chain intake's, under
/// the pool round's vk hash (one circuit for both non-secret-shared intakes).
pub unconstrained fn expected_id(s: Setup, inputs: [Field; 2], user_nonce: Field) -> Field {
    poseidon2_hash(
        [s.app.to_field(), VK_HASH, poseidon2_hash(inputs), user_nonce],
    )
}

pub(crate) global INPUTS: [Field; 2] = [AMOUNT, DIRECTION];

/// The three receipts the nodes sign for the request of `inputs` with
/// `user_nonce`, expiring at `expiry_block`.
pub unconstrained fn node_receipts(s: Setup, inputs: [Field; 2], user_nonce: Field, expiry_block: u32) -> [Receipt; NODES] {
    let id = expected_id(s, inputs, user_nonce);
    receipts(receipt_message(id, poseidon2_hash(inputs), expiry_block))
}

pub(crate) unconstrained fn request_with_receipts(s: Setup, user: AztecAddress, inputs: [Field; 2], expiry_block: u32, r: [Receipt; NODES]) {
    request_with_receipts_nonce(s, user, inputs, NONCE, expiry_block, r);
}

unconstrained fn request_with_receipts_nonce(s: Setup, user: AztecAddress, inputs: [Field; 2], user_nonce: Field, expiry_block: u32, r: [Receipt; NODES]) {
    s.env.call_private(user, PssPublicTest::at(s.app).request_with_receipts(inputs, user_nonce, expiry_block, r));
}

unconstrained fn try_append_receipt(s: Setup, prober: AztecAddress, request_id: Field, expiry_block: u32) -> bool {
    s.env.call_public(s.user, PssPublicTest::at(prober).try_append_receipt(s.app, request_id, expiry_block))
}

// Three valid receipts queue the request id, presented by any account (a
// receipt names no requester) up to the last block a receipt is good for,
// expiry_block - 1; only the id (and the expiry) reach the chain: the
// transaction emits no log at all, public or private, and no note. A wrong
// or missing receipt is the check's unit tests' (above); the refusals below
// show the message binds the request.
#[test]
unconstrained fn three_valid_receipts_from_any_account_queue_the_request_until_their_expiry() {
    let mut s = setup();
    let other = s.env.create_light_account();
    let expiry = s.env.next_block_number() + 1;
    let r = node_receipts(s, INPUTS, NONCE, expiry);
    request_with_receipts(s, other, INPUTS, expiry, r);
    assert_eq(s.env.last_block_number() + 1, expiry);
    let id = expected_id(s, INPUTS, NONCE);
    assert_eq(s.queue().request_at(0), id);
    assert(is_seen(s, id));
    assert_eq(s.queue().tail(), 1);
    let effects = last_tx_summary(s.env, s.app);
    assert_eq(effects.public_logs, 0);
    assert_eq(effects.private_logs, 0);
    assert_eq(effects.note_hashes, 0);
    assert_eq(effects.l2_to_l1_msgs, 0);
}

// Receipts over other inputs (another inputs hash, so another request id)
// do not cover these inputs.
#[test(should_fail_with = "invalid receipt from node 0")]
unconstrained fn receipts_over_another_inputs_hash_are_refused() {
    let s = setup();
    let expiry = s.env.next_block_number() + 10;
    let r = node_receipts(s, [AMOUNT + 1, DIRECTION], NONCE, expiry);
    request_with_receipts(s, s.user, INPUTS, expiry, r);
}

// Receipts over the right request id but another inputs hash in the
// message are refused too: the message binds both.
#[test(should_fail_with = "invalid receipt from node 0")]
unconstrained fn receipts_over_the_id_with_another_inputs_hash_are_refused() {
    let s = setup();
    let expiry = s.env.next_block_number() + 10;
    let id = expected_id(s, INPUTS, NONCE);
    let r = receipts(receipt_message(id, poseidon2_hash([AMOUNT + 1, DIRECTION]), expiry));
    request_with_receipts(s, s.user, INPUTS, expiry, r);
}

// Receipts expiring at E do not cover a request that claims E + 1.
#[test(should_fail_with = "invalid receipt from node 0")]
unconstrained fn receipts_over_another_expiry_are_refused() {
    let s = setup();
    let expiry = s.env.next_block_number() + 10;
    let r = node_receipts(s, INPUTS, NONCE, expiry);
    request_with_receipts(s, s.user, INPUTS, expiry + 1, r);
}

// The hidden requester: no account address appears in the private call's
// arguments (inputs, nonce, expiry, receipts), in the public call it
// enqueues (`append_receipt(request_id, expiry_block)`) or anywhere in the
// transaction's effects.
#[test]
unconstrained fn a_receipt_request_names_no_requester() {
    let s = setup();
    let expiry = s.env.next_block_number() + 10;
    let r = node_receipts(s, INPUTS, NONCE, expiry);
    request_with_receipts(s, s.user, INPUTS, expiry, r);
    let accounts = [s.user, s.deployer];
    let id = expected_id(s, INPUTS, NONCE);
    let mut signatures = [0; 4 * NODES];
    for i in 0..NODES {
        signatures[4 * i] = r[i].s[0];
        signatures[4 * i + 1] = r[i].s[1];
        signatures[4 * i + 2] = r[i].e[0];
        signatures[4 * i + 3] = r[i].e[1];
    }
    assert_no_requester(INPUTS.concat([NONCE, expiry as Field]).concat(signatures), accounts);
    assert_no_requester([id, expiry as Field], accounts);
    assert_last_tx_names_no_requester(s.env, s.app, accounts.concat(accounts));
}

// In the expiry block itself the receipt is refused and changes nothing:
// one request's append in its expiry block (the probe), then another
// request's whole intake in its own expiry block, the next one.
#[test(should_fail_with = "receipt expired")]
unconstrained fn a_receipt_is_refused_in_its_expiry_block() {
    let s = setup();
    let expiry = s.env.next_block_number();
    let id = expected_id(s, INPUTS, NONCE);
    s.queue().assert_refused_without_effect(|| try_append_receipt(s, s.app, id, expiry));
    assert_eq(s.env.last_block_number(), expiry);
    assert(!is_seen(s, id));

    let nonce = NONCE + 1;
    let expiry = s.env.next_block_number();
    let r = node_receipts(s, INPUTS, nonce, expiry);
    request_with_receipts_nonce(s, s.user, INPUTS, nonce, expiry, r);
}

// A receipt is single-use: the same receipts again are the same request id,
// refused without effect.
#[test(should_fail_with = "duplicate request")]
unconstrained fn the_same_receipts_twice_are_refused() {
    let s = setup();
    let expiry = s.env.next_block_number() + 10;
    let r = node_receipts(s, INPUTS, NONCE, expiry);
    request_with_receipts(s, s.user, INPUTS, expiry, r);
    let id = expected_id(s, INPUTS, NONCE);
    s.queue().assert_refused_without_effect(|| try_append_receipt(s, s.app, id, expiry));
    request_with_receipts(s, s.user, INPUTS, expiry, r);
}

#[test(should_fail_with = "invalid inputs")]
unconstrained fn valid_receipts_over_invalid_inputs_are_refused() {
    let s = setup();
    let expiry = s.env.next_block_number() + 10;
    let inputs = [AMOUNT, 2];
    let r = node_receipts(s, inputs, NONCE, expiry);
    request_with_receipts(s, s.user, inputs, expiry, r);
}

// The receipt intake wrapper is #[only_self]: nobody can queue an id without the
// receipts.
#[test(should_fail_with = "Function append_receipt can only be called by the same contract")]
unconstrained fn append_receipt_from_outside_the_contract_reverts() {
    let mut s = setup();
    let outsider = deploy_outsider(&mut s.env);
    let expiry = s.env.next_block_number() + 10;
    s.queue().assert_refused_without_effect(|| try_append_receipt(s, outsider, 0x1d, expiry));
    assert(!is_seen(s, 0x1d));
    s.env.call_public(s.user, PssPublicTest::at(s.app).append_receipt(0x1d, expiry));
}
