//! The freshness policies of a pinned read, as `apply` checks them
//! (`assert_pinned_reads`), through the test contract's check entries:
//! `check_pinned` pins its own `get_price()` exact or under a tolerance,
//! `check_pinned_epoch` its own epoch source `get_epoch_value()`. Each entry
//! is a view that reverts with `apply`'s message when the policy refuses.
//!
//! Each policy's rule (`Freshness::check`: the band edges, the epoch window,
//! the widths, a value beyond a u128) is the library's unit tests
//! (`result::test`); here every policy accepts a fresh read through the
//! contract's static call, a read made stale by the source's own epochs is
//! refused, and so is a policy whose width does not match the pinned values
//! (`assert_pinned_reads`' own check).
use crate::nodes::tip_config;
use crate::PssPublicTest;
use aztec::protocol::address::AztecAddress;
use aztec::test::helpers::test_environment::TestEnvironment;
use pss_public_contract::result::Freshness;
use pss_public_contract::StaleBlocks;

global PRICE: Field = 1000;
// the epoch source after three epochs: 100, 110, then 120 (epoch 3)
global EPOCH_VALUES: [Field; 3] = [100, 110, 120];

pub struct Setup {
    env: TestEnvironment,
    deployer: AztecAddress,
    source: AztecAddress,
}

/// One instance, its price at PRICE and its epoch source at epoch 3 (value
/// 120, previous 110).
unconstrained fn setup() -> Setup {
    let mut env = TestEnvironment::new();
    let deployer = env.create_light_account();
    let source = env.deploy("PssPublicTest").with_public_initializer(
        deployer,
        PssPublicTest::interface().constructor(tip_config(StaleBlocks::after(4)), 0, 0),
    );
    env.call_public(deployer, PssPublicTest::at(source).set_price(PRICE));
    for value in EPOCH_VALUES {
        env.call_public(deployer, PssPublicTest::at(source).open_epoch(value));
    }
    Setup { env, deployer, source }
}

unconstrained fn check(s: Setup, freshness: Freshness, value: Field) {
    s.env.view_public(PssPublicTest::at(s.source).check_pinned(freshness, value));
}

unconstrained fn check_epoch(s: Setup, value: Field, epoch: Field) {
    s.env.view_public(PssPublicTest::at(s.source).check_pinned_epoch(value, epoch));
}

// Every policy accepts a fresh read through the contract. The source's
// triple: each epoch keeps the value before it, and an epoch read accepts
// the stored epoch at its value and the epoch before it at the previous
// value. An absolute band and a relative one (100 bps of 1000: 10 either
// way) accept a value at their edges, and an exact read the equal value.
// Then the price moves mid-round: the scheduler read the source (120 at
// epoch 3), the round is computed at that pair, and the source opens epoch 4
// before apply. The read is now the epoch before the current one, at that
// epoch's value, so the round still lands without a recompute.
#[test]
unconstrained fn every_policy_accepts_a_fresh_read_and_an_epoch_read_survives_one_new_epoch() {
    let s = setup();
    let read = s.env.view_public(PssPublicTest::at(s.source).get_epoch_value());
    assert_eq(read, [120, 3, 110]);
    check_epoch(s, 120, 3);
    check_epoch(s, 110, 2);
    check(s, Freshness::absolute(10), PRICE + 10);
    check(s, Freshness::absolute(10), PRICE - 10);
    check(s, Freshness::relative_bps(100), PRICE + 10);
    check(s, Freshness::relative_bps(100), PRICE - 10);
    check(s, Freshness::exact(), PRICE);

    let (value, epoch) = (read[0], read[1]);
    s.env.call_public(s.deployer, PssPublicTest::at(s.source).open_epoch(130));
    check_epoch(s, value, epoch);
}

// The same round after a second new epoch (epoch 5): its read is two epochs
// behind, so apply refuses it and the round is recomputed.
#[test(should_fail_with = "pinned epoch too old")]
unconstrained fn a_round_read_before_two_new_epochs_is_refused() {
    let s = setup();
    let read = s.env.view_public(PssPublicTest::at(s.source).get_epoch_value());
    let (value, epoch) = (read[0], read[1]);
    s.env.call_public(s.deployer, PssPublicTest::at(s.source).open_epoch(130));
    s.env.call_public(s.deployer, PssPublicTest::at(s.source).open_epoch(140));
    check_epoch(s, value, epoch);
}

// An epoch read takes two pinned values; one is not enough.
#[test(should_fail_with = "pinned values do not match the reads")]
unconstrained fn an_epoch_policy_with_one_value_is_refused() {
    let s = setup();
    check(s, Freshness::epoch(), PRICE);
}
