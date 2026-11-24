//! The deployment: the package names, the constructor's circuit pins (the
//! contract manifest's hash, the package list and the vk hashes), the
//! once-only `configure` and how it binds this contract's address and the
//! constructor's pins, the entry points' refusals before `configure`, and a
//! deployment whose list leaves a package out. The library rules themselves
//! (the signature checks, a DISABLE answer, another npk_app_hash, another
//! manifest hash, the package list's shape) are pss_public_contract
//! configure.nr's unit tests; the TXE behaviour every tip app's `configure`
//! shares (it lands once, an answer at another seq configures, another
//! namespace refuses) is tested here once, for every app.
use crate::{
    answer_for, C_INIT, config, config_of, configure, configure_with, deploy, deploy_unconfigured,
    init, NPK_APP_HASH, ok_round, pool, Setup, stored_configured, submit, swap, swap_with_receipts,
    vk_hashes_of, vks,
};
use amm_tip::AmmTip;
use amm_tip::app::{AMM_INIT_TIP_PACKAGE, PLAIN_PACKAGES};
use aztec::protocol::address::AztecAddress;
use pss_tip_test::{configure_answer, manifest_answer};

// configure with the network's answer lands: the stored pins are the
// constructor's, its manifest hash and vk hashes included, with
// npk_app_hash.
#[test]
unconstrained fn configure_pins_the_signed_answer() {
    let s = deploy_unconfigured(config(), false);
    assert(!s.queue().state().configured.configured);
    configure(s);
    let configured = stored_configured(s);
    assert(configured.configured);
    assert_eq(configured.pins, config().tip);
    assert_eq(configured.npk_app_hash, NPK_APP_HASH);
    assert_eq(s.queue().state().configured, configured.head());
    assert_eq(configured.pins.circuits.vk_hashes, vk_hashes_of(PLAIN_PACKAGES));
}

// A second configure, with the very same answer, reverts at the
// immutable's initialization nullifier.
#[test(should_fail_with = "Attempted to emit duplicate nullifier")]
unconstrained fn configure_lands_once() {
    let s = deploy();
    configure(s);
}

// The nodes signed the REGISTER answer of a contract manifest whose swap
// runs another circuit than the one the constructor pinned (as for a
// namespace taken before the deployment, whose owner registered a circuit of
// its own under the name): configure cannot pin it, so the contract runs only
// the constructor's circuits.
#[test(should_fail_with = "node 0's manifest signature does not verify")]
unconstrained fn a_circuit_the_constructor_did_not_pin_is_refused() {
    let s = deploy_unconfigured(config(), false);
    let mut circuits = s.config.tip.circuits;
    circuits.vk_hashes[1] = vks().shared_vk_hash;
    configure_with(s, manifest_answer(s.app, circuits, NPK_APP_HASH, 0));
}

// ... or another contract manifest over the same circuits (another circuit
// manifest, another intake, an alias added): the address commits to the
// manifest hash, so configure refuses it.
#[test(should_fail_with = "node 0's manifest signature does not verify")]
unconstrained fn another_contract_manifest_is_refused() {
    let s = deploy_unconfigured(config(), false);
    let mut circuits = s.config.tip.circuits;
    circuits.manifest_hash += 1;
    configure_with(s, manifest_answer(s.app, circuits, NPK_APP_HASH, 0));
}

// No rule on seq: the answer at seq 3 (a resend or a re-enable of the same
// contract manifest) configures the same pins, because the signatures are
// over the constructor's manifest hash and list and the namespace's
// npk_app_hash, which no registration changes.
#[test]
unconstrained fn an_answer_at_another_seq_configures_the_same_pins() {
    let s = deploy_unconfigured(config(), false);
    configure_with(s, manifest_answer(s.app, s.config.tip.circuits, NPK_APP_HASH, 3));
    let configured = stored_configured(s);
    assert_eq(configured.pins, config().tip);
}

// An answer the nodes signed for another namespace.
#[test(should_fail_with = "node 0's manifest signature does not verify")]
unconstrained fn another_namespace_is_refused() {
    let s = deploy_unconfigured(config(), false);
    let other = AztecAddress { inner: 0x0abc };
    configure_with(s, configure_answer(other, s.config.tip, NPK_APP_HASH));
}

// ---- nothing runs before configure -------------------------------------------

// A private function's read of the unset `configured` immutable fails, and so
// does a public one: no init, result or skip runs. Every private entry
// point reads it through the same `rounds(configured.read(), ..)` as
// `init_pool`, and a request before configure has no initialised pool
// either (test_init.nr's swaps before init).
#[test(should_fail_with = "Trying to read from uninitialized PublicImmutable")]
unconstrained fn init_pool_reverts_before_configure() {
    let s = deploy_unconfigured(config(), false);
    init(s, C_INIT);
}

#[test(should_fail_with = "Trying to read from uninitialized PublicImmutable")]
unconstrained fn process_result_reverts_before_configure() {
    let s = deploy_unconfigured(config(), false);
    let _ = submit(s, ok_round(0x1d, C_INIT, 0xc1));
}

#[test(should_fail_with = "Trying to read from uninitialized PublicImmutable")]
unconstrained fn skip_reverts_before_configure() {
    let s = deploy_unconfigured(config(), false);
    s.env.call_public(s.user, AmmTip::at(s.app).skip());
}

// ---- a deployment whose list leaves a package out --------------------------

// The list [init]: the init is package 0 (seq 0), and the swap is not in
// this deployment.
unconstrained fn without_the_swap() -> Setup {
    let s = deploy_unconfigured(config_of([AMM_INIT_TIP_PACKAGE, 0]), false);
    configure(s);
    s
}

// The list [init]: configure checks the packages hash over the listed
// package alone; the listed package runs.
#[test]
unconstrained fn a_listed_package_runs_in_a_shorter_list() {
    let s = deploy_unconfigured(config_of([AMM_INIT_TIP_PACKAGE, 0]), false);
    configure_with(s, answer_for(s));
    let configured = stored_configured(s);
    assert_eq(configured.pins.circuits.vk_hashes, [vks().init_vk_hash, 0]);
    init(s, C_INIT);
    assert_eq(pool(s), C_INIT);
}

#[test(should_fail_with = "package not in this deployment")]
unconstrained fn an_unlisted_package_refuses_on_chain_intake() {
    let s = without_the_swap();
    init(s, C_INIT);
    let _ = swap(s, 25000, 1);
}

#[test(should_fail_with = "package not in this deployment")]
unconstrained fn an_unlisted_package_refuses_receipt_intake() {
    let s = without_the_swap();
    init(s, C_INIT);
    let _ = swap_with_receipts(s, 25000, 1);
}

#[test(should_fail_with = "package not in this deployment")]
unconstrained fn an_unlisted_package_refuses_its_result() {
    let s = without_the_swap();
    init(s, C_INIT);
    let _ = submit(s, ok_round(0x1d, C_INIT, 0xc1));
}
