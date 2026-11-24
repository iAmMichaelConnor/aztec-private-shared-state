//! Circuit upgrades (pss_public_contract `upgrades`, `CircuitUpgrades`): the
//! upgrade authority schedules new circuit pins, which take effect after
//! `UPGRADE_DELAY`. Before the switch every round function verifies under
//! the constructor's pins, from the switch under the new ones; a request
//! queued under the old pins is answered by neither circuit after the
//! switch and goes stale, and anyone may `skip()` it.
//!
//! The upgraded deployment replaces the swap's circuit (another dummy vk,
//! `new_swap_vk`) and names another contract manifest; the init keeps its
//! vk.
use crate::{
    AMOUNT_IN, C_INIT, C1, C2, DIRECTION, init_id, MIN_OUT, mine_until_next_block_is, NONCE_A,
    NONCE_B, ok_round, partial_for, plain_inputs, pool, receive_offchain, rho_of, Setup, setup,
    setup_with_probe, signatures, STALE, submit, submit_with, swap, swap_inputs, swap_vk, try_skip,
    user_partial,
};
use amm_tip::AmmTip;
use amm_tip::app::{PACKAGES, UPGRADE_DELAY};
use aztec::context::PublicContext;
use aztec::protocol::hash::poseidon2_hash;
use aztec::state_vars::{DelayedPublicMutable, StateVariable};
use pss_public_contract::{chain_request_id, CircuitPins, inputs_hash};
use pss_public_contract::upgrades::UpgradedPins;

/// The upgraded swap circuit's dummy vk.
unconstrained fn new_swap_vk() -> [Field; 115] {
    [8; 115]
}

/// The deployment's circuit pins with the swap's vk hash replaced by the
/// upgraded circuit's, under another contract manifest.
unconstrained fn upgraded(s: Setup) -> CircuitPins<PACKAGES> {
    let mut circuits = s.config.tip.circuits;
    circuits.manifest_hash += 1;
    circuits.vk_hashes[1] = poseidon2_hash(new_swap_vk());
    circuits
}

/// The authority schedules the upgraded pins.
unconstrained fn schedule(s: Setup) {
    s.env.call_public(s.authority, AmmTip::at(s.app).upgrade_circuits(upgraded(s)));
}

/// Mine a block at or past the switch: the upgraded pins are in force at
/// every anchor from it on.
unconstrained fn cross_the_switch(s: Setup) {
    s.env.advance_next_block_timestamp_by(UPGRADE_DELAY + 1);
    s.env.mine_block();
}

/// The chain request id of the user's swap with `nonce` under the upgraded
/// swap circuit's vk hash.
unconstrained fn upgraded_swap_id(s: Setup, nonce: Field) -> Field {
    chain_request_id(
        s.app,
        poseidon2_hash(new_swap_vk()),
        inputs_hash(plain_inputs(swap_inputs(AMOUNT_IN), partial_for(s.user, nonce))),
        nonce,
    )
}

/// Queue the user's on-chain intake swap with `nonce` (under whichever pins
/// are in force) and hand its partial note's message to its PXE.
unconstrained fn queue_swap(s: Setup, nonce: Field) {
    s.env.call_private(
        s.user,
        AmmTip::at(s.app).swap(AMOUNT_IN, DIRECTION, MIN_OUT, rho_of(nonce), nonce),
    );
    assert_eq(receive_offchain(s), 1);
}

// Only the authority the constructor pinned may schedule new pins.
#[test(should_fail_with = "not the upgrade authority")]
unconstrained fn only_the_authority_upgrades() {
    let s = setup();
    s.env.call_public(s.user, AmmTip::at(s.app).upgrade_circuits(upgraded(s)));
}

// The new pins pass the constructor's check of a package list.
#[test(should_fail_with = "a listed package without a vk hash")]
unconstrained fn invalid_pins_are_refused() {
    let s = setup();
    let mut circuits = upgraded(s);
    circuits.vk_hashes[1] = 0;
    s.env.call_public(s.authority, AmmTip::at(s.app).upgrade_circuits(circuits));
}

// Scheduled but not yet in force: the constructor's swap circuit still
// verifies, and the pool moves as before.
#[test]
unconstrained fn the_constructors_pins_hold_until_the_switch() {
    let s = setup();
    schedule(s);
    let id = swap(s, AMOUNT_IN, NONCE_A);
    let _ = submit(s, ok_round(id, C_INIT, C1).with_partial(user_partial(s, NONCE_A)));
    assert_eq(pool(s), C1);
}

#[test(should_fail_with = "unexpected verification key")]
unconstrained fn the_upgraded_circuit_is_refused_before_the_switch() {
    let s = setup();
    schedule(s);
    let id = swap(s, AMOUNT_IN, NONCE_A);
    let r = ok_round(id, C_INIT, C1).with_partial(user_partial(s, NONCE_A));
    let _ = submit_with(s, new_swap_vk(), r, signatures(s, id, C_INIT, C1));
}

// From the switch, a request binds the upgraded circuit's vk hash, its
// result verifies under the upgraded circuit, and the pool carries over:
// the round reads the commitment the last round under the old circuit left.
#[test]
unconstrained fn after_the_switch_the_upgraded_circuit_lands() {
    let s = setup();
    schedule(s);
    let id = swap(s, AMOUNT_IN, NONCE_A);
    let _ = submit(s, ok_round(id, C_INIT, C1).with_partial(user_partial(s, NONCE_A)));
    cross_the_switch(s);
    queue_swap(s, NONCE_B);
    let new_id = upgraded_swap_id(s, NONCE_B);
    assert_eq(s.queue().request_at(1), new_id);
    let r = ok_round(new_id, C1, C2).with_partial(user_partial(s, NONCE_B));
    let _ = submit_with(s, new_swap_vk(), r, signatures(s, new_id, C1, C2));
    assert_eq(pool(s), C2);
}

// From the switch the replaced circuit verifies nothing.
#[test(should_fail_with = "unexpected verification key")]
unconstrained fn after_the_switch_the_replaced_circuit_is_refused() {
    let s = setup();
    schedule(s);
    cross_the_switch(s);
    queue_swap(s, NONCE_A);
    let id = upgraded_swap_id(s, NONCE_A);
    let r = ok_round(id, C_INIT, C1).with_partial(user_partial(s, NONCE_A));
    let _ = submit_with(s, swap_vk(), r, signatures(s, id, C_INIT, C1));
}

// A request queued before the switch binds the replaced circuit's vk hash:
// the upgraded circuit computes another request id from the same inputs,
// which is not the head.
#[test(should_fail_with = "not the head")]
unconstrained fn a_request_queued_under_the_old_pins_is_not_answered_after_the_switch() {
    let s = setup();
    schedule(s);
    let _ = swap(s, AMOUNT_IN, NONCE_A);
    cross_the_switch(s);
    let new_id = upgraded_swap_id(s, NONCE_A);
    let r = ok_round(new_id, C_INIT, C1).with_partial(user_partial(s, NONCE_A));
    let _ = submit_with(s, new_swap_vk(), r, signatures(s, new_id, C_INIT, C1));
}

// ... so it waits out the stale period and anyone may skip it; the queue
// then moves on under the upgraded circuit. Nothing is refunded: the AMM
// took nothing at request time.
#[test]
unconstrained fn a_request_queued_under_the_old_pins_is_skipped() {
    let s = setup_with_probe();
    schedule(s);
    let _ = swap(s, AMOUNT_IN, NONCE_A);
    cross_the_switch(s);
    let since = s.queue().head().since;
    mine_until_next_block_is(s, since + STALE);
    assert(try_skip(s));
    queue_swap(s, NONCE_B);
    let new_id = upgraded_swap_id(s, NONCE_B);
    let r = ok_round(new_id, C_INIT, C1).with_partial(user_partial(s, NONCE_B));
    let _ = submit_with(s, new_swap_vk(), r, signatures(s, new_id, C_INIT, C1));
    assert_eq(pool(s), C1);
}

// The init keeps its vk across the upgrade: an init result under the
// constructor's init circuit would still verify (the slot is written, so
// here it is refused by the slot, not the pin).
#[test(should_fail_with = "already initialised")]
unconstrained fn an_unchanged_package_keeps_its_pin() {
    let s = setup();
    schedule(s);
    cross_the_switch(s);
    crate::init_with(s, crate::init_vk(), C1, signatures(s, init_id(s), 0, C1));
}

// ---- class upgrades (`upgrades: contract`) -----------------------------------

// Only the authority may move the instance to another class; the check
// comes before the registry is called.
#[test(should_fail_with = "not the upgrade authority")]
unconstrained fn only_the_authority_upgrades_the_contract() {
    let s = setup();
    s.env.call_public(s.user, AmmTip::at(s.app).upgrade_contract(0xc1a5502, upgraded(s)));
}

// The pins scheduled with a class change pass the package-list check too.
#[test(should_fail_with = "a listed package without a vk hash")]
unconstrained fn a_class_upgrade_checks_its_pins() {
    let s = setup();
    let mut circuits = upgraded(s);
    circuits.vk_hashes[1] = 0;
    s.env.call_public(s.authority, AmmTip::at(s.app).upgrade_contract(0xc1a5502, circuits));
}

// Every round function enqueues the class guard, and the guard is the
// contract's own: nobody else calls it.
#[test(should_fail_with = "Function assert_upgrade_class can only be called by the same contract")]
unconstrained fn the_class_guard_is_only_self() {
    let s = setup();
    s.env.call_public(s.user, AmmTip::at(s.app).assert_upgrade_class(0));
}

// This build answers 1; the second class the e2e moves to answers 2.
#[test]
unconstrained fn the_class_version_is_this_builds() {
    let s = setup();
    assert_eq(s.env.view_public(AmmTip::at(s.app).get_class_version()), 1);
}

/// A contract class the instance does not run.
global OTHER_CLASS: Field = 0xc1a5502;

/// The pins half of `upgrade_contract(OTHER_CLASS, upgraded(s))`, written
/// into the app's storage as that call schedules it: the class change's
/// registry half needs a registered class, which the pins' rules do not
/// read.
unconstrained fn schedule_class_upgrade_pins(s: Setup) {
    let circuits = upgraded(s);
    let slot = AmmTip::storage_layout().circuit_upgrades.slot;
    s.env.public_context_at(s.app, |context| {
        let pins: DelayedPublicMutable<UpgradedPins<PACKAGES>, UPGRADE_DELAY, PublicContext> =
            DelayedPublicMutable::new(context, slot);
        pins.schedule_value_change(UpgradedPins { class_id: OTHER_CLASS, circuits });
    });
}

// A class upgrade is pending: a circuit upgrade would replace its pins with
// pins of the running class, and from the class change on every round would
// fail the class guard. Refused; the authority reschedules through
// upgrade_contract.
#[test(should_fail_with = "a class upgrade is pending: use upgrade_contract")]
unconstrained fn a_circuit_upgrade_is_refused_while_a_class_upgrade_is_pending() {
    let s = setup();
    schedule_class_upgrade_pins(s);
    schedule(s);
}

// A pending circuit upgrade of the running class is replaced, and once a
// class upgrade's time of change has passed nothing is pending.
#[test]
unconstrained fn a_circuit_upgrade_replaces_a_pending_one_and_follows_a_class_change() {
    let s = setup();
    schedule(s);
    schedule(s);
    schedule_class_upgrade_pins(s);
    cross_the_switch(s);
    schedule(s);
}

// The class guard: once pins of another class than the running one are in
// force, every round function's enqueued guard refuses, so old code never
// runs with new pins.
#[test(should_fail_with = "the circuit pins belong to another contract class")]
unconstrained fn the_class_guard_refuses_pins_of_another_class() {
    let s = setup();
    schedule_class_upgrade_pins(s);
    cross_the_switch(s);
    queue_swap(s, NONCE_A);
}
