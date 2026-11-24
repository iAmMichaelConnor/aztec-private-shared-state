//! The deployment: the constructor's vk hashes,
//! `configure` under this market's pins, every entry point's refusal before
//! `configure`, the constructor's checks of the market's own pins (one
//! intake family among them), and a deployment whose list leaves a package
//! out. The
//! signature checks themselves (another node's signature, a DISABLE answer,
//! another vk hash, manifest hash or namespace) are pss_public_contract
//! configure.nr's unit tests, and what every tip app's `configure` shares in the TXE (it lands
//! once, an answer at another seq configures, another namespace refuses) is
//! examples/amm-tip's test_configure.nr; here, that `configure` checks the
//! constructor's pins. A test that moves no token deploys
//! without the users' balances (`deploy_unfunded`).
use crate::{
    C1, C_INIT, config, config_of, configure, configure_with, deploy_unconfigured,
    deploy_unfunded, deposit, DEPOSIT, deposit_with_receipts, init, market, NONCE_A, NPK_APP_HASH,
    ok_round, ROUND_DEPOSIT, Setup, shared_vk_hash, stored_configured, submit_deposit, vk_hashes_of,
};
use lending_market::app::{BORROW_SHARED_PACKAGE, LENDING_INIT_PACKAGE, PACKAGES, PLAIN_PACKAGES};
use lending_tip::LendingTip;
use pss_public_contract::StaleBlocks;
use pss_tip_test::manifest_answer;

// configure with the network's answer lands: the stored pins are the
// constructor's, its manifest hash and vk hashes included, with
// npk_app_hash.
#[test]
unconstrained fn configure_pins_the_signed_answer() {
    let s = deploy_unfunded(PLAIN_PACKAGES);
    assert(!s.queue().state().configured.configured);
    configure(s);
    let configured = stored_configured(s);
    assert(configured.configured);
    assert_eq(configured.pins, config(s.oracle, s.collateral, s.borrowed).tip);
    assert_eq(configured.npk_app_hash, NPK_APP_HASH);
    assert_eq(s.queue().state().configured, configured.head());
    assert_eq(configured.pins.circuits.vk_hashes, vk_hashes_of(PLAIN_PACKAGES));
}

// The nodes signed the REGISTER answer of a contract manifest whose deposit
// runs another circuit than the one the constructor pinned (the
// secret-shared deposit's): configure cannot pin it, so the contract runs
// only the constructor's circuits, even under an answer three compromised
// nodes would sign.
#[test(should_fail_with = "node 0's manifest signature does not verify")]
unconstrained fn a_circuit_the_constructor_did_not_pin_is_refused() {
    let s = deploy_unfunded(PLAIN_PACKAGES);
    let mut circuits = s.config.tip.circuits;
    circuits.vk_hashes[1] = shared_vk_hash(ROUND_DEPOSIT);
    configure_with(s, manifest_answer(s.app, circuits, NPK_APP_HASH, 0));
}

// ---- nothing runs before configure -------------------------------------------

// A private function's read of the unset `configured` immutable fails, and so
// does a public one: no request, init, result or skip runs.

#[test(should_fail_with = "Trying to read from uninitialized PublicImmutable")]
unconstrained fn init_market_reverts_before_configure() {
    init(deploy_unfunded(PLAIN_PACKAGES), C_INIT);
}

#[test(should_fail_with = "Trying to read from uninitialized PublicImmutable")]
unconstrained fn deposit_reverts_before_configure() {
    let _ = deposit(deploy_unconfigured(PLAIN_PACKAGES), DEPOSIT, NONCE_A);
}

#[test(should_fail_with = "Trying to read from uninitialized PublicImmutable")]
unconstrained fn deposit_with_receipts_reverts_before_configure() {
    let _ = deposit_with_receipts(deploy_unconfigured(PLAIN_PACKAGES), DEPOSIT, NONCE_A);
}

#[test(should_fail_with = "Trying to read from uninitialized PublicImmutable")]
unconstrained fn process_result_reverts_before_configure() {
    let s = deploy_unfunded(PLAIN_PACKAGES);
    let _ = submit_deposit(s, ok_round(0x1d, C_INIT, C1));
}

#[test(should_fail_with = "Trying to read from uninitialized PublicImmutable")]
unconstrained fn skip_reverts_before_configure() {
    let s = deploy_unfunded(PLAIN_PACKAGES);
    s.env.call_public(s.user, LendingTip::at(s.app).skip());
}

// ---- the constructor's checks of the market's own pins ----------------------

/// Deploy the market under `config` (a pin varied from the tests' Config).
unconstrained fn construct(mut s: Setup, config: lending_market::app::Config) {
    let _ = s.env.deploy("../lending_tip@lending_tip/LendingTip").with_public_initializer(
        s.deployer,
        LendingTip::interface().constructor(config),
    );
}

// The market requires skipping: once the escape hatch opens no round lands,
// so `skip()` is the only way a queued request's escrow and usage deposit
// come back (`exit` pays positions only).
#[test(should_fail_with = "the market requires skipping")]
unconstrained fn a_config_with_skipping_disabled_is_refused() {
    let s = deploy_unfunded(PLAIN_PACKAGES);
    let mut config = s.config;
    config.tip.stale_blocks = StaleBlocks::disabled();
    construct(s, config);
}

// T_LIVE is at least the stale period.
#[test(should_fail_with = "T_LIVE is below the stale period")]
unconstrained fn a_t_live_below_the_stale_period_is_refused() {
    let s = deploy_unfunded(PLAIN_PACKAGES);
    let mut config = s.config;
    config.t_live = config.tip.stale_blocks.blocks - 1;
    construct(s, config);
}

// One intake family: the plain deposit's leaves hold no exit tag, so beside
// a secret-shared round it would open positions no later round can write
// (their tag 0, which a landing refuses); the constructor refuses the list.
#[test(should_fail_with = "the plain deposit is listed beside a secret-shared round")]
unconstrained fn the_plain_deposit_beside_a_secret_shared_round_is_refused() {
    let s = deploy_unfunded(PLAIN_PACKAGES);
    let mut packages = PLAIN_PACKAGES;
    packages[2] = BORROW_SHARED_PACKAGE;
    construct(s, config_of(s.oracle, s.collateral, s.borrowed, packages, vk_hashes_of(packages)));
}

// ---- a deployment whose list leaves a package out --------------------------

// The list [init]: no deposit in this deployment, so its functions refuse
// under both non-secret-shared intakes while the listed init runs (each
// test below lands it first).
unconstrained fn init_only() -> Setup {
    let mut list = [0; PACKAGES];
    list[0] = LENDING_INIT_PACKAGE;
    let s = deploy_unconfigured(list);
    configure(s);
    init(s, C_INIT);
    assert_eq(market(s), C_INIT);
    s
}

#[test(should_fail_with = "package not in this deployment")]
unconstrained fn an_unlisted_package_refuses_intake() {
    let _ = deposit(init_only(), DEPOSIT, NONCE_A);
}

#[test(should_fail_with = "package not in this deployment")]
unconstrained fn an_unlisted_package_refuses_receipt_intake() {
    let _ = deposit_with_receipts(init_only(), DEPOSIT, NONCE_A);
}

#[test(should_fail_with = "package not in this deployment")]
unconstrained fn an_unlisted_package_refuses_its_result() {
    let s = init_only();
    let _ = submit_deposit(s, ok_round(0x1d, C_INIT, C1));
}
