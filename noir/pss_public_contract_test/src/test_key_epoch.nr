//! Key epochs (`key_epoch`) through the test contract: a key set rotation
//! (`rotate_keys`, `set_node_keys`) signed by two of the three current
//! nodes, the grace window of the previous set for results and receipts
//! (`assert_key_epoch`), a node's `enc` rotation under the current set only,
//! and the voided `enc` key of a replaced node under secret-shared on-chain intake.
//!
//! The replacement the tests rotate to: node 2 leaves, a newcomer takes its
//! place with its own `sig` and `enc` keys, nodes 0 and 1 keep theirs. A
//! rotation is signed by the test signer over `rotation_message` with the
//! scalars each test names (`pss_tip_test::rotation_signatures`), so every
//! signature verifies in-circuit as a node's would.
use crate::nodes::{NODE_SIG, NODE_SIG_PK, OUTSIDER_SIG, sign};
use crate::PssPublicTest;
use crate::test::deploy;
use crate::test_outcome;
use crate::test_receipt::{expected_id, INPUTS, NONCE, node_receipts, request_with_receipts};
use crate::test_result;
use crate::test_result::{C0, C1, C2, INPUTS_A, INPUTS_B, NONCE_A, NONCE_B, PRICE, pool, result, Round, submit_with};
use crate::test_shared_onchain::{
    assert_served, expected, keyed, request, rotate_by, stored_key, try_append, values,
};
use pss_tip_test::shared_onchain::{ENC, enc_key, the_request_log};
use aztec::protocol::address::AztecAddress;
use aztec::protocol::hash::poseidon2_hash;
use aztec::protocol::traits::ToField;
use aztec::test::helpers::test_environment::TestEnvironment;
use pss_core::tip::derived::pack_epochs;
use pss_public_contract::{EncKey, KeySet, NodeKeys, Receipt, receipt_message, StaleBlocks};
use pss_public_contract::chain_state::sealed_hashes;
use pss_public_contract::result::ResultSignature;
use pss_tip_test::{key_set, mine_until_next_block_is, result_signatures_by, rotation_signatures};
use std::embedded_curve_ops::EmbeddedCurvePoint;

// the stale period of the rotation and receipt tests' deployment, and so
// their grace window (test_result's and test_outcome's are 4 too)
global STALE: u32 = 4;

/// The newcomer that replaces node 2: its `sig` and `enc` scalars.
global NEWCOMER_SIG: Field = 0x0c0ffee5;
global NEWCOMER_ENC: Field = 0x0e4e4;
/// Node 1's next `sig` scalar, for the rotation that also moves node 1.
global NODE1_NEXT_SIG: Field = 0x0c0ffee6;

/// The `sig` scalars of the replacement set: nodes 0 and 1, then the
/// newcomer.
unconstrained fn new_signers() -> [Field; 3] {
    [NODE_SIG[0], NODE_SIG[1], NEWCOMER_SIG]
}

/// The replacement set: node 2's `sig` and `enc` keys are the newcomer's;
/// nodes 0 and 1 keep their `sig` keys and the `enc` keys `test_shared_onchain`
/// gives them.
unconstrained fn replacement() -> KeySet {
    key_set(new_signers(), [ENC[0], ENC[1], NEWCOMER_ENC])
}

/// Rotate `app` to `epoch` under `keys`, place i signed by `signers[i]` (0:
/// missing), sent by `sender`; returns the block it landed in.
unconstrained fn rotate_keys(
    env: TestEnvironment,
    app: AztecAddress,
    sender: AztecAddress,
    epoch: u32,
    keys: KeySet,
    signers: [Field; 3],
) -> u32 {
    let sigs = rotation_signatures(app, epoch, keys, signers);
    rotate_keys_with(env, app, sender, epoch, keys, sigs)
}

unconstrained fn rotate_keys_with(
    env: TestEnvironment,
    app: AztecAddress,
    sender: AztecAddress,
    epoch: u32,
    keys: KeySet,
    sigs: [ResultSignature; 3],
) -> u32 {
    env.call_private(sender, PssPublicTest::at(app).rotate_keys(epoch, keys, sigs));
    env.last_block_number()
}

/// The replacement at epoch 1, signed by nodes 0 and 1.
unconstrained fn replace_node_2(env: TestEnvironment, app: AztecAddress, sender: AztecAddress) -> u32 {
    rotate_keys(env, app, sender, 1, replacement(), [NODE_SIG[0], NODE_SIG[1], 0])
}

unconstrained fn node_keys(env: TestEnvironment, app: AztecAddress) -> NodeKeys {
    env.view_public(PssPublicTest::at(app).get_node_keys())
}

unconstrained fn rotation_setup() -> crate::test::Setup {
    deploy(StaleBlocks::after(STALE))
}

// ---- the rotation ---------------------------------------------------------

// A new contract stores no key epoch: its NodeKeys read as all zeros, which
// is epoch 0 (the constructor's sig keys). A rotation signed by nodes 0 and
// 1 lands without node 2 (the departed node cannot block its own
// replacement): the contract is at epoch 1 under the new sig and enc keys,
// the previous set is the constructor's, rotated_at is the block the
// rotation landed in and the grace window is the stale period. The
// newcomer is a current node from the rotation on: the next rotation, to
// epoch 2, signed by node 0 and the newcomer, lands, with the epoch-1 set as
// its previous set.
#[test]
unconstrained fn a_rotation_signed_by_nodes_0_and_1_lands_and_the_newcomer_signs_the_next() {
    let s = rotation_setup();
    let held = node_keys(s.env, s.app);
    assert_eq(held.epoch, 0);
    assert_eq(held.rotated_at, 0);
    assert_eq(held.sig[0], EmbeddedCurvePoint { x: 0, y: 0 });

    let first = replacement();
    let block = replace_node_2(s.env, s.app, s.user);
    assert_eq(
        node_keys(s.env, s.app),
        NodeKeys {
            epoch: 1,
            sig: first.sig,
            enc: first.enc,
            previous: NODE_SIG_PK,
            rotated_at: block,
            grace: STALE,
        },
    );

    let next = key_set([NODE_SIG[0], NODE1_NEXT_SIG, NEWCOMER_SIG], [ENC[0], ENC[1], NEWCOMER_ENC]);
    let block = rotate_keys(s.env, s.app, s.user, 2, next, [NODE_SIG[0], 0, NEWCOMER_SIG]);
    let held = node_keys(s.env, s.app);
    assert_eq(held.epoch, 2);
    assert_eq(held.sig, next.sig);
    assert_eq(held.previous, first.sig);
    assert_eq(held.rotated_at, block);
}

// Any two current nodes suffice: nodes 1 and 2 sign the same rotation and it
// lands with the same key epoch.
#[test]
unconstrained fn a_rotation_signed_by_nodes_1_and_2_lands() {
    let s = rotation_setup();
    let keys = replacement();
    let block = rotate_keys(s.env, s.app, s.user, 1, keys, [0, NODE_SIG[1], NODE_SIG[2]]);
    assert_eq(
        node_keys(s.env, s.app),
        NodeKeys {
            epoch: 1,
            sig: keys.sig,
            enc: keys.enc,
            previous: NODE_SIG_PK,
            rotated_at: block,
            grace: STALE,
        },
    );
}

// With skipping disabled the grace window is DEFAULT_STALE_BLOCKS, 50
// blocks.
#[test]
unconstrained fn with_skipping_disabled_the_grace_window_is_50_blocks() {
    let s = deploy(StaleBlocks::disabled());
    let _ = replace_node_2(s.env, s.app, s.user);
    assert_eq(node_keys(s.env, s.app).grace, 50);
}

// One signature is not enough: node 0 alone cannot rotate the set.
#[test(should_fail_with = "a key set rotation needs two current node signatures")]
unconstrained fn a_rotation_with_one_signature_is_refused() {
    let s = rotation_setup();
    let _ = rotate_keys(s.env, s.app, s.user, 1, replacement(), [NODE_SIG[0], 0, 0]);
}

// Each signature counts only in its own node's place: node 0's signature in
// places 0 and 1 is one signature.
#[test(should_fail_with = "a key set rotation needs two current node signatures")]
unconstrained fn one_signature_in_two_places_is_refused() {
    let s = rotation_setup();
    let keys = replacement();
    let mut sigs = rotation_signatures(s.app, 1, keys, [NODE_SIG[0], 0, 0]);
    sigs[1] = sigs[0];
    let _ = rotate_keys_with(s.env, s.app, s.user, 1, keys, sigs);
}

// A landed rotation cannot be replayed: the same arguments again name an
// epoch that is no longer the current epoch + 1.
#[test(should_fail_with = "the epoch is not the current epoch + 1")]
unconstrained fn a_replayed_rotation_is_refused() {
    let s = rotation_setup();
    let keys = replacement();
    let sigs = rotation_signatures(s.app, 1, keys, [NODE_SIG[0], NODE_SIG[1], 0]);
    let _ = rotate_keys_with(s.env, s.app, s.user, 1, keys, sigs);
    let _ = rotate_keys_with(s.env, s.app, s.user, 1, keys, sigs);
}

// A rotation skips no epoch: epoch 2 from epoch 0 is refused, though two
// current nodes signed it.
#[test(should_fail_with = "the epoch is not the current epoch + 1")]
unconstrained fn a_rotation_to_epoch_plus_2_is_refused() {
    let s = rotation_setup();
    let _ = rotate_keys(s.env, s.app, s.user, 2, replacement(), [NODE_SIG[0], NODE_SIG[1], 0]);
}

// The departed node cannot hijack the set, alone (one signature, as above)
// nor with a key no node holds in another node's place.
#[test(should_fail_with = "a key set rotation needs two current node signatures")]
unconstrained fn node_2_with_an_outsider_cannot_rotate() {
    let s = rotation_setup();
    let hijack = key_set([OUTSIDER_SIG, OUTSIDER_SIG + 1, NODE_SIG[2]], [ENC[0], ENC[1], ENC[2]]);
    let _ = rotate_keys(s.env, s.app, s.user, 1, hijack, [OUTSIDER_SIG, 0, NODE_SIG[2]]);
}

// Once the replacement lands, the departed node's old key is no current
// node's: its signature beside node 0's is one signature, inside the grace
// window too (the grace window is for results and receipts, not rotations).
#[test(should_fail_with = "a key set rotation needs two current node signatures")]
unconstrained fn the_departed_key_counts_for_nothing_after_the_rotation() {
    let s = rotation_setup();
    let _ = replace_node_2(s.env, s.app, s.user);
    let back = key_set(NODE_SIG, ENC);
    let _ = rotate_keys(s.env, s.app, s.user, 2, back, [NODE_SIG[0], 0, NODE_SIG[2]]);
}

// Every key of the new set must be a Grumpkin point.
#[test(should_fail_with = "an enc key of the new set is not a Grumpkin point")]
unconstrained fn a_rotation_to_a_non_point_is_refused() {
    let s = rotation_setup();
    let mut keys = replacement();
    keys.enc[2] = EmbeddedCurvePoint { x: 1, y: 1 };
    let _ = rotate_keys(s.env, s.app, s.user, 1, keys, [NODE_SIG[0], NODE_SIG[1], 0]);
}

// Each node keeps a key of its own: a set whose sig keys repeat one key, or
// whose enc keys do, is refused though two current nodes signed it.
#[test(should_fail_with = "the new set repeats a sig key")]
unconstrained fn a_rotation_that_repeats_a_sig_key_is_refused() {
    let s = rotation_setup();
    let keys = key_set([NODE_SIG[0], NODE_SIG[1], NODE_SIG[0]], [ENC[0], ENC[1], NEWCOMER_ENC]);
    let _ = rotate_keys(s.env, s.app, s.user, 1, keys, [NODE_SIG[0], NODE_SIG[1], 0]);
}

#[test(should_fail_with = "the new set repeats an enc key")]
unconstrained fn a_rotation_that_repeats_an_enc_key_is_refused() {
    let s = rotation_setup();
    let keys = key_set(new_signers(), [ENC[0], ENC[1], ENC[1]]);
    let _ = rotate_keys(s.env, s.app, s.user, 1, keys, [NODE_SIG[0], NODE_SIG[1], 0]);
}

// ---- results across a rotation (test_result's deployment) -----------------

/// Node i's signature over round `r`'s result made by `signers[i]`.
unconstrained fn result_sigs_by(s: test_result::Setup, r: Round, signers: [Field; 3]) -> [ResultSignature; 3] {
    result_signatures_by(
        signers,
        s.app.to_field(),
        r.request_id,
        r.old_commitments,
        r.reads,
        r.new_commitments,
        sealed_hashes(r.sealed),
    )
}

/// The head request's first result, signed by the epoch-0 set before node
/// 2 is replaced, and the block the replacement landed in.
unconstrained fn old_set_result_then_replacement(s: test_result::Setup) -> (Round, [ResultSignature; 3], u32) {
    let id = test_result::request(s, INPUTS_A, NONCE_A);
    let r = result(id, C0, C1, true, PRICE, 1);
    let sigs = result_sigs_by(s, r, NODE_SIG);
    let rotated = replace_node_2(s.env, s.app, s.relayer);
    (r, sigs, rotated)
}

// A result the epoch-0 set signed before the replacement lands in the last
// block of the grace window, rotated_at + the stale period. (Staging the
// proof capsule takes a block of its own, so the submission starts one
// block earlier.) After the window, a result the new set (nodes 0 and 1 and
// the newcomer) signs for the next request lands.
#[test]
unconstrained fn an_old_set_result_lands_inside_the_grace_window_and_a_new_set_one_after() {
    let s = test_result::setup();
    let (r, sigs, rotated) = old_set_result_then_replacement(s);
    mine_until_next_block_is(s.env, rotated + STALE - 1);
    let block = submit_with(s, r, sigs);
    assert_eq(block, rotated + STALE);
    assert_eq(pool(s), C1);

    let id_b = test_result::request(s, INPUTS_B, NONCE_B);
    assert(s.env.next_block_number() > rotated + STALE + 1);
    let r_b = result(id_b, C1, C2, true, PRICE, 2);
    let _ = submit_with(s, r_b, result_sigs_by(s, r_b, new_signers()));
    assert_eq(pool(s), C2);
}

// The block after the grace window the same result is refused: the epoch it
// verifies under has expired, and the result is recomputed under the new
// set.
#[test(should_fail_with = "key epoch expired")]
unconstrained fn an_old_set_result_is_refused_after_the_grace_window() {
    let s = test_result::setup();
    let (r, sigs, rotated) = old_set_result_then_replacement(s);
    // the capsule's block, then the submission in rotated_at + grace + 1
    mine_until_next_block_is(s.env, rotated + STALE);
    let _ = submit_with(s, r, sigs);
}

// A result signed by a mix of the two sets is refused inside the grace
// window: after a rotation that moves node 1's sig key and replaces node 2,
// node 0's and node 1's new signatures beside the departed node's old one
// verify under neither set. (Under the replacement alone, nodes 0 and 1 sign
// with the same keys in both sets, so with the departed node's signature
// they are the old set, which the grace window accepts.)
#[test(should_fail_with = "node 1's result signature does not verify")]
unconstrained fn a_result_signed_by_a_mix_of_the_two_sets_is_refused() {
    let s = test_result::setup();
    let id = test_result::request(s, INPUTS_A, NONCE_A);
    let r = result(id, C0, C1, true, PRICE, 1);
    let keys = key_set([NODE_SIG[0], NODE1_NEXT_SIG, NEWCOMER_SIG], [ENC[0], ENC[1], NEWCOMER_ENC]);
    let _ = rotate_keys(s.env, s.app, s.relayer, 1, keys, [NODE_SIG[0], NODE_SIG[1], 0]);
    let _ = submit_with(s, r, result_sigs_by(s, r, [NODE_SIG[0], NODE1_NEXT_SIG, NODE_SIG[2]]));
}

// ---- receipts across a rotation (test.nr's deployment) --------------------

/// The epoch-0 set's receipts for the request of INPUTS, signed before node
/// 2 is replaced, their expiry, and the block the replacement landed in.
unconstrained fn old_set_receipts_then_replacement(s: crate::test::Setup) -> ([Receipt; 3], u32, u32) {
    let expiry = s.env.next_block_number() + 4 * STALE;
    let r = node_receipts(s, INPUTS, NONCE, expiry);
    let rotated = replace_node_2(s.env, s.app, s.user);
    (r, expiry, rotated)
}

// Receipts the epoch-0 set signed before the replacement queue the request
// in the last block of the grace window. After the window, receipts the new
// set signs queue another request.
#[test]
unconstrained fn old_set_receipts_queue_inside_the_grace_window_and_new_set_ones_after() {
    let s = rotation_setup();
    let (r, expiry, rotated) = old_set_receipts_then_replacement(s);
    mine_until_next_block_is(s.env, rotated + STALE);
    request_with_receipts(s, s.user, INPUTS, expiry, r);
    assert_eq(s.env.last_block_number(), rotated + STALE);
    assert_eq(s.queue().request_at(0), expected_id(s, INPUTS, NONCE));

    let inputs = [INPUTS[0] + 1, INPUTS[1]];
    let expiry = s.env.next_block_number() + 10;
    let id = expected_id(s, inputs, NONCE);
    let message = receipt_message(id, poseidon2_hash(inputs), expiry);
    let r = new_signers().map(|k| sign(k, message));
    request_with_receipts(s, s.user, inputs, expiry, r);
    assert(s.env.last_block_number() > rotated + STALE);
    assert_eq(s.queue().request_at(1), id);
}

// The block after the grace window those receipts are refused, before
// their own expiry.
#[test(should_fail_with = "key epoch expired")]
unconstrained fn old_set_receipts_are_refused_after_the_grace_window() {
    let s = rotation_setup();
    let (r, expiry, rotated) = old_set_receipts_then_replacement(s);
    mine_until_next_block_is(s.env, rotated + STALE + 1);
    assert(s.env.next_block_number() < expiry);
    request_with_receipts(s, s.user, INPUTS, expiry, r);
}

// ---- a node's enc rotation (test_outcome's deployment) --------------------

// After the replacement lands, the departed node's old sig key cannot rotate
// node 2's enc key, inside the grace window too: an enc rotation verifies
// under the current set only.
#[test(should_fail_with = "invalid enc key rotation signature")]
unconstrained fn the_departed_key_cannot_rotate_node_2s_enc_key() {
    let s = test_outcome::setup();
    let _ = replace_node_2(s.env, s.app, s.relayer);
    rotate_by(s, 2, NEWCOMER_ENC, 1, NODE_SIG[2]);
}

// The newcomer's sig key signs node 2's enc rotation once the replacement
// lands (node 2 had no enc key, so the replacement left its slot at epoch
// 0).
#[test]
unconstrained fn the_newcomer_rotates_node_2s_enc_key() {
    let s = test_outcome::setup();
    let _ = replace_node_2(s.env, s.app, s.relayer);
    assert_eq(stored_key(s, 2), EncKey { x: 0, y: 0, epoch: 0 });
    rotate_by(s, 2, NEWCOMER_ENC, 1, NEWCOMER_SIG);
    assert_eq(stored_key(s, 2), enc_key(NEWCOMER_ENC, 1));
}

// ---- secret-shared on-chain intake across a replacement -------------------

/// Every node keyed at enc epoch 1, then the replacement: node 2's stored
/// enc key differs from the new set's, so it is voided.
unconstrained fn keyed_then_replaced() -> test_outcome::Setup {
    let s = keyed();
    let _ = replace_node_2(s.env, s.app, s.relayer);
    s
}

// The replacement voids node 2's enc key: the zero point at its stored epoch
// + 2 (3), so a request naming its replaced epoch reverts at intake; nodes 0
// and 1, whose keys the new set keeps, are untouched. The newcomer's own
// enc rotation at the stored epoch + 1 (4) ends the void: a request lands
// under the epochs [1, 1, 4], and the newcomer derives its pairs with its
// enc scalar.
#[test]
unconstrained fn a_replacement_voids_the_replaced_nodes_enc_key_until_the_newcomer_rotates() {
    let s = keyed_then_replaced();
    assert_eq(stored_key(s, 2), EncKey { x: 0, y: 0, epoch: 3 });
    assert_eq(stored_key(s, 0), enc_key(ENC[0], 1));
    assert_eq(stored_key(s, 1), enc_key(ENC[1], 1));
    assert(!try_append(s, 0xa1, [1, 1, 1]));

    rotate_by(s, 2, NEWCOMER_ENC, 4, NEWCOMER_SIG);
    assert_eq(stored_key(s, 2), enc_key(NEWCOMER_ENC, 4));
    let v = values(s);
    request(s, v);
    let scalars = [ENC[0], ENC[1], NEWCOMER_ENC];
    let want = expected(s, v, scalars, [1, 1, 4]);
    let log = the_request_log();
    assert_eq(log.get(2), pack_epochs([1, 1, 4]));
    assert_eq(s.env.view_public(PssPublicTest::at(s.app).request_at(0)), want.id);
    assert_served(log, scalars, want);
}

// While node 2's enc key is void, a shared on-chain request reverts.
#[test(should_fail_with = "a node's enc key is void until it rotates")]
unconstrained fn a_request_while_a_key_is_void_reverts() {
    let s = keyed_then_replaced();
    request(s, values(s));
}
