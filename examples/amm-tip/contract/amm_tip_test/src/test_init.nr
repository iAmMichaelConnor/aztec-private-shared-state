//! The deployment Config and the init round: `init_pool` lands the
//! `amm_init_tip` result once, outside the queue, while the pool slot is
//! empty.
use crate::{
    assert_state, C1, C_INIT, config, deploy, deploy_with, init, init_id, init_vk, init_with,
    no_public_log, pool, pool_key, signatures, swap, swap_vk,
};
use amm_tip::AmmTip;
use aztec::protocol::hash::poseidon2_hash;
use aztec::protocol::traits::ToField;
use pss_public_contract::{chain_request_id, Head, inputs_hash};
use pss_public_contract::init::init_request_id;

// The constructor writes the Config as given; the pool slot starts empty,
// the queue empty, and the pool key is the slot's storage slot. The init
// request id is the chain request id of a request with no inputs and nonce
// 0 under the init vk: no queued request can have it (every queued request
// is under a queued round's vk). init_pool writes the first commitment,
// logs nothing (the nodes hold the pool's first version under it: no public
// log at all) and touches no queue storage. After a swap the state view
// holds what the single views read: the pool's commitment and key, the
// queue's head and tail.
#[test]
unconstrained fn the_config_the_init_request_id_a_logless_init_and_the_state_view() {
    let s = deploy_with(true);
    assert_eq(s.queue().state().config, config());
    assert_state(s, 0, 0, 0);
    assert(pool_key(s) != 0);

    let vk_hash = poseidon2_hash(init_vk());
    assert_eq(init_id(s), poseidon2_hash([s.app.to_field(), vk_hash, poseidon2_hash([]), 0]));
    assert_eq(init_id(s), chain_request_id(s.app, vk_hash, inputs_hash([]), 0));
    assert(init_request_id(s.app, vk_hash + 1, []) != init_id(s));

    init(s, C_INIT);
    assert_state(s, 0, 0, C_INIT);
    assert_eq(s.queue().done_at(0), 0);
    assert(no_public_log(s));

    let _ = swap(s, 25000, 1);
    let state = s.queue().state();
    assert_eq(state.commitments, [pool(s)]);
    assert_eq(state.commitments, [C_INIT]);
    assert_eq(state.state_keys, [pool_key(s)]);
    assert_eq(state.head, s.queue().head());
    assert_eq(state.tail, 1);
    assert(state.configured.configured);
}

// Init once (`apply_init`'s empty-slot check, the library suite's
// a_second_init_is_refused): a re-init over a live pool, after it moved, is
// refused too.
#[test(should_fail_with = "already initialised")]
unconstrained fn an_init_after_swaps_is_refused() {
    let s = deploy();
    init(s, C_INIT);
    let id = swap(s, 25000, 1);
    let _ = crate::submit(s, crate::ok_round(id, C_INIT, C1).with_partial(crate::user_partial(s, 1)));
    assert_state(s, 1, 1, C1);
    assert_eq(s.queue().head(), Head { index: 1, since: s.env.last_block_number() });
    init(s, C_INIT);
}

// The init vk pin: a proof under a swap vk is refused.
#[test(should_fail_with = "unexpected verification key")]
unconstrained fn an_init_proof_under_another_vk_is_refused() {
    let s = deploy();
    assert_state(s, 0, 0, 0);
    init_with(s, swap_vk(), C_INIT, signatures(s, init_id(s), 0, C_INIT));
}

// apply_init is #[only_self]: nobody writes the first commitment without
// the proof and the signatures.
#[test(should_fail_with = "Function apply_init can only be called by the same contract")]
unconstrained fn apply_init_from_outside_the_contract_is_refused() {
    let s = deploy();
    s.env.call_public(s.user, AmmTip::at(s.app).apply_init(init_id(s), C_INIT));
}

// Intake refuses while the pool is uninitialised (both non-secret-shared intakes).
#[test(should_fail_with = "state not initialised")]
unconstrained fn a_swap_before_init_is_refused() {
    let s = deploy();
    let _ = swap(s, 25000, 1);
}

#[test(should_fail_with = "state not initialised")]
unconstrained fn a_receipt_swap_before_init_is_refused() {
    let s = deploy();
    let _ = crate::swap_with_receipts(s, 25000, 1);
}
