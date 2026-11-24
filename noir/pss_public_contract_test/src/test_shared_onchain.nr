//! Secret-shared on-chain intake through the test contract, on the private-outcome
//! deployment of `test_outcome`: the nodes' `enc` keys in public storage and
//! their rotation, the request function's private log of derived shares, the
//! stored data hash, and the epoch bound at intake.
//!
//! The request is a swap with a shared recipient: C commits to `[amount_in,
//! direction, recipient, outcome_key, outcome_tag]`, every one chosen by the
//! user (one correction each, `LAYOUT`), then the blinding, the encoding's.
//! The nodes'
//! `enc` scalars are test-local; each node's derivation of its pair is
//! recomputed here with pss_core's `tip::derived`, as the machine derives it.
use crate::nodes::{NODE_SIG, sign};
use crate::PssPublicTest;
use crate::test::last_tx_summary;
use crate::test_outcome::{Setup, setup};
use aztec::protocol::address::AztecAddress;
use aztec::protocol::hash::compute_siloed_private_log_first_field;
use aztec::protocol::traits::ToField;
use aztec::test::helpers::txe_oracles;
use pss_core::tip::derived::{
    CHOSEN, CLEAR, data_hash, key_exchange, Layout, node_pair, pack_epochs, request_log,
    REQUEST_LOG_LEN, shares_of, wraps,
};
use pss_core::tip::intake::{commit, shared};
use pss_core::tip::outcome::log_padding;
use pss_public_contract::{enc_rotation_message, EncKey};
use pss_public_contract::shared_onchain::request_log_tag;
use pss_utils::dh::{ecdh_x, public_key};
use pss_tip_test::shared_onchain;
use pss_tip_test::shared_onchain::{
    enc_rotation, ENC, ENC_NEXT, enc_key, EPH, Expected, opened, the_request_log,
};

/// The test round's layout: C's five values, every one chosen.
pub global LAYOUT: Layout<5, 0, 5> = Layout { kinds: [CHOSEN, CHOSEN, CHOSEN, CHOSEN, CHOSEN] };

global AMOUNT: Field = 25000;
global DIRECTION: Field = 1;
/// The outcome key and tag the client derives for the request.
global OUTCOME_KEY: Field = 0x0c0ffee1;
global OUTCOME_TAG: Field = 0x0c0ffee2;

/// Node i's signed rotation to `sk` at `epoch`, sent from `from`.
pub(crate) unconstrained fn rotate_by(s: Setup, i: u32, sk: Field, epoch: u32, signer: Field) {
    let (key, signature) = enc_rotation(s.app, i, sk, epoch, signer);
    s.env.call_private(s.relayer, PssPublicTest::at(s.app).rotate_enc_key(i, key, signature));
}

unconstrained fn rotate(s: Setup, i: u32, sk: Field, epoch: u32) {
    rotate_by(s, i, sk, epoch, NODE_SIG[i]);
}

/// Every node sets its first key: epoch 1 everywhere.
pub(crate) unconstrained fn keyed() -> Setup {
    let s = setup();
    for i in 0..3 {
        rotate(s, i, ENC[i], 1);
    }
    s
}

pub(crate) unconstrained fn stored_key(s: Setup, i: u32) -> EncKey {
    s.env.view_public(PssPublicTest::at(s.app).get_enc_key(i))
}

pub(crate) unconstrained fn values(s: Setup) -> [Field; 5] {
    [AMOUNT, DIRECTION, s.user.to_field(), OUTCOME_KEY, OUTCOME_TAG]
}

/// What the request function computes from `values` under the node scalars
/// `scalars` at `epochs`.
pub(crate) unconstrained fn expected(s: Setup, values: [Field; 5], scalars: [Field; 3], epochs: [u32; 3]) -> Expected<5, 5> {
    shared_onchain::expected(LAYOUT, s.app.to_field(), s.outcome_vk_hash, values, EPH, scalars, epochs)
}

pub(crate) unconstrained fn request(s: Setup, values: [Field; 5]) {
    s.env.call_private(s.user, PssPublicTest::at(s.app).request_shared_onchain(values, EPH));
}

/// Every node, using `scalars[i]`, opens C's values and the blinding the
/// request committed to.
pub(crate) unconstrained fn assert_served(log: BoundedVec<Field, 16>, scalars: [Field; 3], want: Expected<5, 5>) {
    let (values, blinding) = opened(log, EPH, scalars, LAYOUT.kinds);
    assert_eq(values, want.values);
    assert_eq(blinding, want.blinding);
}

pub(crate) unconstrained fn try_append(s: Setup, id: Field, epochs: [u32; 3]) -> bool {
    s.env.call_public(s.user, PssPublicTest::at(s.app).try_append_onchain_shared(s.app, id, 0x0da7a, epochs))
}

// ---- TXE ------------------------------------------------------------------

// The keys start empty; a node's signed rotation sets its key at epoch 1
// and logs nothing. A rotation must be the stored epoch + 1: skipping or
// repeating an epoch is refused at the public write.
#[test]
unconstrained fn a_signed_rotation_sets_a_nodes_key_at_the_next_epoch_only() {
    let s = setup();
    assert_eq(stored_key(s, 0), EncKey { x: 0, y: 0, epoch: 0 });
    rotate(s, 0, ENC[0], 1);
    assert_eq(stored_key(s, 0), enc_key(ENC[0], 1));
    assert_eq(stored_key(s, 1).epoch, 0);
    let effects = last_tx_summary(s.env, s.app);
    assert_eq(effects.public_logs, 0);
    assert_eq(effects.private_logs, 0);

    let set = |key: EncKey| s.env.call_public(s.user, PssPublicTest::at(s.app).try_set_enc_key(s.app, 0, key));
    assert(!set(enc_key(ENC_NEXT[0], 3)));
    assert(!set(enc_key(ENC_NEXT[0], 1)));
    assert(set(enc_key(ENC_NEXT[0], 2)));
    assert_eq(stored_key(s, 0), enc_key(ENC_NEXT[0], 2));
}

// A request under the stored keys queues its id with the data hash of its
// one private log, `[siloed tag, C, epochs, E.x, w_0..w_2, corrections…,
// padding…]`, 16 fields, and every node derives its pair of every shared
// value from it. The stored hash is the queued log's: a log differing from
// it in any field (a forged copy under the same tag) does not hash to it.
// The log's visible shape is the same for every round type: 15 fields
// after the tag, none of them a padding the world can compute from the
// public request id. The landed request logs five corrections (padding at
// 11..15); another round type, one clear value and one correction (padding
// at 8..15), built by the same library function the request function
// calls, shows no more; both are padded under their blinding. Then node 1
// rotates to epoch 2, retiring its key in the contract: the queued id and
// data hash stand, and node 1 still derives its pairs of that request with
// its epoch-1 scalar.
#[test]
unconstrained fn a_request_logs_its_derived_shares_and_is_served_after_a_rotation() {
    let s = keyed();
    let v = values(s);
    request(s, v);
    let want = expected(s, v, ENC, [1, 1, 1]);
    assert_eq(s.env.view_public(PssPublicTest::at(s.app).request_at(0)), want.id);
    let log = the_request_log();
    assert_eq(log.len(), 16);
    assert_eq(log.get(0), compute_siloed_private_log_first_field(s.app, request_log_tag(want.id)));
    let mut body = [0; REQUEST_LOG_LEN];
    for i in 0..REQUEST_LOG_LEN {
        body[i] = log.get(1 + i);
    }
    assert_eq(body, want.log);
    let stored = s.env.view_public(PssPublicTest::at(s.app).get_data_hash(want.id));
    assert_eq(stored, data_hash(body));
    let effects = last_tx_summary(s.env, s.app);
    assert_eq(effects.public_logs, 0);
    assert_eq(effects.note_hashes, 0);
    assert_served(log, ENC, want);

    // a forged copy does not hash to the stored hash
    for k in 0..REQUEST_LOG_LEN {
        let mut forged = want.log;
        forged[k] += 1;
        assert(data_hash(forged) != stored);
    }

    // another round type logs the same visible shape
    let layout: Layout<2, 1, 1> = Layout { kinds: [CLEAR, CHOSEN] };
    let (secrets, eph_x) = key_exchange(EPH, ENC.map(|k| public_key(k)));
    let other_values = [v[0], v[1]];
    let enc = shares_of(layout, other_values, secrets);
    let c = commit(other_values, enc.blinding);
    let other_id = shared(s.app.to_field(), s.outcome_vk_hash, c);
    let other = request_log(
        enc.blinding,
        c,
        pack_epochs([1, 1, 1]),
        eph_x,
        wraps(secrets),
        enc.clear,
        enc.corrections,
    );
    assert_eq(log.len(), 1 + other.len());
    let (tag, other_tag) = (request_log_tag(want.id), request_log_tag(other_id));
    for i in 0..REQUEST_LOG_LEN {
        assert(body[i] != log_padding(tag, i));
        assert(other[i] != log_padding(other_tag, i));
    }
    for i in 11..REQUEST_LOG_LEN {
        assert_eq(body[i], log_padding(want.blinding, i));
    }
    for i in 8..REQUEST_LOG_LEN {
        assert_eq(other[i], log_padding(enc.blinding, i));
    }

    // node 1 retires its epoch-1 key; the queued request is still served
    rotate(s, 1, ENC_NEXT[1], 2);
    assert_eq(stored_key(s, 1), enc_key(ENC_NEXT[1], 2));
    assert_eq(s.env.view_public(PssPublicTest::at(s.app).request_at(0)), want.id);
    assert_eq(s.env.view_public(PssPublicTest::at(s.app).get_data_hash(want.id)), stored);
    assert_eq(log.get(2), pack_epochs([1, 1, 1]));
    assert_served(log, ENC, want);
}

// The request names no requester and shows no input: no account (the user,
// also the recipient), no chosen value, neither the outcome key, the outcome
// tag nor the blinding appears in the transaction's effects.
#[test]
unconstrained fn a_shared_onchain_request_names_no_requester_and_shows_no_input() {
    let s = keyed();
    let v = values(s);
    request(s, v);
    let want = expected(s, v, ENC, [1, 1, 1]);
    let tx_hash = txe_oracles::get_last_tx_effects().tx_hash;
    let holds_none = |vals: [Field; 4]| {
        let as_addresses = vals.map(|v| AztecAddress { inner: v });
        assert(s.env.execute_utility(PssPublicTest::at(s.app).tx_names_no_requester(tx_hash, as_addresses)));
    };
    holds_none([s.user.to_field(), s.relayer.to_field(), AMOUNT, want.values[3]]);
    holds_none([want.values[4], want.blinding, want.secrets[0], want.secrets[1]]);
}

// A rotation then a request under the new key: node 1 rotates to epoch 2,
// the log names [1, 2, 1], and node 1 derives its pairs with its new
// scalar; with its old one it does not.
#[test]
unconstrained fn a_request_after_a_rotation_is_under_the_new_key() {
    let s = keyed();
    rotate(s, 1, ENC_NEXT[1], 2);
    assert_eq(stored_key(s, 1), enc_key(ENC_NEXT[1], 2));
    let v = values(s);
    request(s, v);
    let scalars = [ENC[0], ENC_NEXT[1], ENC[2]];
    let want = expected(s, v, scalars, [1, 2, 1]);
    let log = the_request_log();
    assert_eq(log.get(2), pack_epochs([1, 2, 1]));
    assert_eq(s.env.view_public(PssPublicTest::at(s.app).request_at(0)), want.id);
    assert_served(log, scalars, want);
    // node 1's old key derives another share of the first value
    let (e, wrap, correction) = (public_key(EPH), log.get(1 + 3), log.get(1 + 6));
    let share = |sk: Field| node_pair(1, ecdh_x(sk, e), wrap, 0, correction)[0];
    assert(share(ENC[1]) != share(ENC_NEXT[1]));
}

// The epoch bound at intake: a request naming the stored epoch or the one
// before is queued; one naming an epoch two behind, a later one or epoch 0
// (no key) reverts (the probe reports the revert, and nothing is queued).
#[test]
unconstrained fn an_epoch_two_behind_reverts_at_intake() {
    let s = keyed();
    rotate(s, 0, ENC_NEXT[0], 2);
    rotate(s, 0, ENC[0] + 7, 3);
    assert(!try_append(s, 0xa1, [1, 1, 1]));
    assert_eq(s.env.view_public(PssPublicTest::at(s.app).get_tail()), 0);
    assert(try_append(s, 0xa2, [2, 1, 1]));
    assert(try_append(s, 0xa3, [3, 1, 1]));
    assert(!try_append(s, 0xa4, [3, 0, 1]));
    assert(!try_append(s, 0xa5, [4, 1, 1]));
    assert_eq(s.env.view_public(PssPublicTest::at(s.app).get_tail()), 2);
    assert_eq(s.env.view_public(PssPublicTest::at(s.app).get_data_hash(0xa2)), 0x0da7a);
}

// A rotation verifies under node i's own sig key only: another node's
// signature (a key no node holds is no better) is refused.
#[test(should_fail_with = "invalid enc key rotation signature")]
unconstrained fn a_rotation_signed_by_another_node_is_refused() {
    let s = setup();
    rotate_by(s, 0, ENC[0], 1, NODE_SIG[1]);
}

#[test(should_fail_with = "the enc key is not a Grumpkin point")]
unconstrained fn a_rotation_to_a_non_point_is_refused() {
    let s = setup();
    let key = EncKey { x: 1, y: 1, epoch: 1 };
    let signature = sign(NODE_SIG[0], enc_rotation_message(s.app, 0, key));
    s.env.call_private(s.relayer, PssPublicTest::at(s.app).rotate_enc_key(0, key, signature));
}

#[test(should_fail_with = "a node has no enc key in this contract")]
unconstrained fn a_request_before_every_node_has_a_key_reverts() {
    let s = setup();
    rotate(s, 0, ENC[0], 1);
    rotate(s, 1, ENC[1], 1);
    request(s, values(s));
}

#[test(should_fail_with = "invalid inputs")]
unconstrained fn a_request_failing_static_validity_reverts() {
    let s = keyed();
    request(s, [AMOUNT, 2, s.user.to_field(), 0, 0]);
}
