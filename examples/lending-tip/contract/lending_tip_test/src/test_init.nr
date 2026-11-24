//! The deployment Config and the init round: `init_market` lands the
//! `lending_init` result once, outside the queue, while the market slot is
//! empty, against the Config's seeded liquidity. The init's own rules (a
//! missing signature, a zero commitment, the slot already written) are
//! pss_public_contract_test's (test_node_held.nr); here, the lending wiring:
//! the Config's liquidity, its tokens in the public balance, the init vk
//! pin, and nothing funded or queued before the init. A test that moves no
//! user's token deploys without the users' balances
//! (`deploy_configured_unfunded`).
use crate::{
    assert_state, C_INIT, config, configure, deploy, deploy_bare, deploy_configured_unfunded, deposit,
    deposit_vk, deposit_with_receipts, fund, init, INIT_HASHES, init_id, init_signatures, init_vk,
    init_with, LIQUIDITY, market_key, public_logs,
};
use lending_market::app::PLAIN_PACKAGES;
use aztec::protocol::hash::poseidon2_hash;
use aztec::protocol::traits::ToField;
use pss_public_contract::init::{init_public_inputs, init_request_id};
use lending_tip::LendingTip;
use pss_public_contract::{chain_request_id, inputs_hash, is_head_of};

// The constructor writes the Config as given (the oracle among the pins);
// the market slot and the queue start empty; the market key is the slot's
// storage slot.
//
// The init request id is the chain request id of a request whose one input
// is the pinned liquidity, nonce 0, under the init vk; another liquidity or
// vk gives another id.
//
// The init layout lending_init proves (8 public inputs): the tip prefix,
// the request id over [liquidity], the empty slot's 0, new_c, npk_app_hash,
// then the tail, the book header's new leaf hash, which init_market passes.
//
// init_market writes the first commitment, logs nothing (the book is
// node-held) and touches no queue storage.
#[test]
unconstrained fn the_constructor_pins_the_config_and_the_init_writes_the_first_commitment() {
    let s = deploy_configured_unfunded();
    let pinned = s.queue().state().config;
    assert_eq(pinned, config(s.oracle, s.collateral, s.borrowed));
    assert_eq(pinned.oracle, s.oracle);
    assert_eq(pinned.init_liquidity, LIQUIDITY);
    // the public functions read the Config's head alone (`ConfigPublic`)
    assert(is_head_of(pinned.public(), pinned));
    assert_state(s, 0, 0, 0);
    assert(market_key(s) != 0);

    let vk_hash = poseidon2_hash(init_vk());
    assert_eq(
        init_id(s),
        poseidon2_hash(
            [s.app.to_field(), vk_hash, poseidon2_hash([LIQUIDITY]), 0],
        ),
    );
    assert_eq(
        init_id(s),
        chain_request_id(s.app, vk_hash, inputs_hash([LIQUIDITY]), 0),
    );
    assert(init_request_id(s.app, vk_hash, [LIQUIDITY + 1]) != init_id(s));
    assert(init_request_id(s.app, vk_hash + 1, [LIQUIDITY]) != init_id(s));

    let (ns, vk, key) = (s.app.to_field(), s.vks.init_vk_hash, market_key(s));
    let inputs = init_public_inputs(ns, vk, [key], init_id(s), [C_INIT], 0x9b, INIT_HASHES);
    assert_eq(inputs, [ns, vk, key, init_id(s), 0, C_INIT, 0x9b, INIT_HASHES[0]]);

    init(s, C_INIT);
    assert_state(s, 0, 0, C_INIT);
    assert_eq(s.queue().done_at(0), 0);
    assert_eq(public_logs(s), 0);
}

// The init vk pin: a proof under a round's vk is refused.
#[test(should_fail_with = "unexpected verification key")]
unconstrained fn an_init_proof_under_another_vk_is_refused() {
    let s = deploy_configured_unfunded();
    assert_state(s, 0, 0, 0);
    init_with(s, deposit_vk(), C_INIT, init_signatures(s, init_id(s), C_INIT));
}

// The nodes signed an init for another liquidity: its request id differs
// from the one the Config's liquidity gives, so the signatures fail.
#[test(should_fail_with = "node 0's result signature does not verify")]
unconstrained fn an_init_for_another_liquidity_is_refused() {
    let s = deploy_configured_unfunded();
    let other = init_request_id(s.app, s.vks.init_vk_hash, [LIQUIDITY + 1]);
    init_with(s, init_vk(), C_INIT, init_signatures(s, other, C_INIT));
}

#[test(should_fail_with = "Function apply_init can only be called by the same contract")]
unconstrained fn apply_init_from_outside_the_contract_is_refused() {
    let s = deploy_configured_unfunded();
    s.env.call_public(s.user, LendingTip::at(s.app).apply_init(init_id(s), C_INIT));
}

// The init requires the seeded liquidity in the market's public balance of
// the borrowed asset: a deployment funded one unit short is refused, and
// stays uninitialised.
#[test(should_fail_with = "the seeded liquidity is not in the public balance")]
unconstrained fn an_init_without_the_seeded_liquidity_in_the_balance_is_refused() {
    let s = deploy_bare(PLAIN_PACKAGES, LIQUIDITY - 1);
    configure(s);
    assert_state(s, 0, 0, 0);
    init(s, C_INIT);
}

// Nobody funds a credit before the init: the init's balance check must not
// count a user's credit as liquidity.
#[test(should_fail_with = "state not initialised")]
unconstrained fn a_fund_before_init_is_refused() {
    let s = deploy();
    fund(s, s.user, 1, 1);
}

// Intake refuses while the market is uninitialised, under both
// non-secret-shared intakes: with no credit before the init, a request
// already fails at its escrow, in its private function (its public wrapper
// refuses too, "state not initialised").
#[test(should_fail_with = "no credit note of the sender's covers the request")]
unconstrained fn a_deposit_before_init_is_refused() {
    let s = deploy();
    let _ = deposit(s, 1000, 1);
}

#[test(should_fail_with = "no credit note of the sender's covers the request")]
unconstrained fn a_receipt_intake_deposit_before_init_is_refused() {
    let s = deploy();
    let _ = deposit_with_receipts(s, 1000, 1);
}
