//! On-chain intake and the chain request id: a TXE suite of `request_onchain`
//! through the test contract (the inputs are shaped like an AMM swap's
//! `[amount_in, direction]`). The derivation and the request log layout are
//! the library's unit tests (`intake::test`).
use crate::nodes::VK_HASH;
use crate::PssPublicTest;
use crate::test_receipt::expected_id;
use pss_tip_test::shape::LogHead;
use crate::test::{
    assert_last_tx_names_no_requester, deploy_outsider, is_seen, last_tx_summary, setup, Setup,
};
use aztec::protocol::address::AztecAddress;
use aztec::test::helpers::txe_oracles;
use pss_public_contract::{chain_request_id, inputs_hash, PlainRequest, request_log_tag};
use pss_tip_test::audit::assert_no_requester;

global AMOUNT: Field = 1000;
global DIRECTION: Field = 1;
global NONCE: Field = 0x6e6f6e6365;

// ---- TXE: request_onchain through the test contract -----------------------

unconstrained fn request_onchain(s: Setup, user: AztecAddress, inputs: [Field; 2], user_nonce: Field) {
    s.env.call_private(user, PssPublicTest::at(s.app).request_onchain(inputs, user_nonce));
}

unconstrained fn try_append_onchain(s: Setup, prober: AztecAddress, request_id: Field, plain: PlainRequest<2>) -> bool {
    s.env.call_public(s.user, PssPublicTest::at(prober).try_append_onchain(s.app, request_id, plain))
}

// request_onchain queues the content-derived id: namespace = the contract,
// vk_hash = the pinned one, no requester. Its transaction emits one public
// log, the request log, from the contract: [request_log_tag(id), inputs in
// ABI order, user_nonce], four fields, and nothing else (no note, no
// private log). Equal inputs under another nonce are another request.
#[test]
unconstrained fn request_onchain_queues_the_content_derived_id_and_another_nonce_is_another_request() {
    let s = setup();
    let inputs = [AMOUNT, DIRECTION];
    request_onchain(s, s.user, inputs, NONCE);
    let id = expected_id(s, inputs, NONCE);
    assert_eq(s.queue().request_at(0), id);
    assert(is_seen(s, id));
    assert_eq(s.queue().tail(), 1);

    let effects = last_tx_summary(s.env, s.app);
    assert_eq(effects.public_logs, 1);
    assert_eq(effects.logs[0], LogHead { emitter: s.app, tag: request_log_tag(id), length: 4 });
    assert_eq(effects.private_logs, 0);
    assert_eq(effects.note_hashes, 0);
    assert_eq(effects.l2_to_l1_msgs, 0);
    let tx_hash = txe_oracles::get_last_tx_effects().tx_hash;
    let body = s.env.execute_utility(PssPublicTest::at(s.app).request_log(tx_hash, request_log_tag(id)));
    assert_eq(body, [AMOUNT, DIRECTION, NONCE]);
    // a reader recomputes the id from the log body
    assert_eq(chain_request_id(s.app, VK_HASH, inputs_hash([body[0], body[1]]), body[2]), id);

    request_onchain(s, s.user, inputs, NONCE + 1);
    let other = expected_id(s, inputs, NONCE + 1);
    assert(other != id);
    assert_eq(s.queue().request_at(1), other);
    assert_eq(s.queue().tail(), 2);
}

// The hidden requester: no account address appears in the private call's
// arguments, in the public call it enqueues (`append_onchain(request_id,
// plain)`: the queue entry and the log body) or anywhere in the
// transaction's effects (logs, public writes, nullifiers, notes).
#[test]
unconstrained fn an_onchain_request_names_no_requester() {
    let s = setup();
    let inputs = [AMOUNT, DIRECTION];
    request_onchain(s, s.user, inputs, NONCE);
    let accounts = [s.user, s.deployer];
    let id = expected_id(s, inputs, NONCE);
    assert_no_requester(inputs.concat([NONCE]), accounts);
    let tx_hash = txe_oracles::get_last_tx_effects().tx_hash;
    let body = s.env.execute_utility(PssPublicTest::at(s.app).request_log(tx_hash, request_log_tag(id)));
    assert_no_requester([id].concat(body), accounts);
    assert_last_tx_names_no_requester(s.env, s.app, accounts.concat(accounts));
}

// The same request again is the same id, whichever account sends it (the
// id names no requester): the probe's append is refused and changes neither
// the queue nor the log, and the request from another account reverts.
#[test(should_fail_with = "duplicate request")]
unconstrained fn the_same_onchain_request_again_from_any_account_reverts() {
    let mut s = setup();
    let other = s.env.create_light_account();
    request_onchain(s, s.user, [AMOUNT, DIRECTION], NONCE);
    let id = expected_id(s, [AMOUNT, DIRECTION], NONCE);
    let plain = PlainRequest { inputs: [AMOUNT, DIRECTION], user_nonce: NONCE };
    s.queue().assert_refused_without_effect(|| try_append_onchain(s, s.app, id, plain));
    request_onchain(s, other, [AMOUNT, DIRECTION], NONCE);
}

// The static-validity predicate runs in the private function: a zero
// amount is refused before anything is queued. (The predicate's other edges
// are the test contract's own `valid_inputs`, not the library's.)
#[test(should_fail_with = "invalid inputs")]
unconstrained fn a_zero_amount_is_refused() {
    let s = setup();
    request_onchain(s, s.user, [0, DIRECTION], NONCE);
}

// The on-chain intake wrapper is #[only_self]: nobody can queue an id with a log
// of their choosing.
#[test(should_fail_with = "Function append_onchain can only be called by the same contract")]
unconstrained fn append_onchain_from_outside_the_contract_reverts() {
    let mut s = setup();
    let outsider = deploy_outsider(&mut s.env);
    let plain = PlainRequest { inputs: [AMOUNT, DIRECTION], user_nonce: NONCE };
    s.queue().assert_refused_without_effect(|| try_append_onchain(s, outsider, 0x1d, plain));
    assert(!is_seen(s, 0x1d));
    s.env.call_public(s.user, PssPublicTest::at(s.app).append_onchain(0x1d, plain));
}
