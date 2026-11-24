//! The oracle: the constructor's price and first epoch, the owner's setter
//! opening epochs, the least epoch length, the previous price's window, the
//! public getters. Each test deploys the oracle alone (`oracle_with`): no
//! market, token or balance.
use crate::{EPOCH, EPOCH_BLOCKS, LOW_PRICE, PREVIOUS_BLOCKS, PRICE};
use aztec::protocol::address::AztecAddress;
use aztec::protocol::traits::Serialize;
use aztec::test::helpers::test_environment::TestEnvironment;
use lending_oracle::LendingOracle;
use lending_oracle::LendingOracle::PriceEpoch;
use pss_tip_test::mine_until_next_block_is;

/// An oracle whose epochs last at least `epoch_blocks` blocks, at price
/// PRICE, owned by a fresh account, and the block its first epoch opened in.
unconstrained fn oracle_with(epoch_blocks: u32) -> (TestEnvironment, AztecAddress, AztecAddress, u32) {
    let mut env = TestEnvironment::new();
    let owner = env.create_light_account();
    let oracle = env.deploy("../lending_oracle@lending_oracle/LendingOracle").with_public_initializer(
        owner,
        LendingOracle::interface().constructor(owner, PRICE, epoch_blocks, PREVIOUS_BLOCKS),
    );
    let opened = env.last_block_number();
    (env, owner, oracle, opened)
}

// The constructor writes the owner, the first price and epoch 1, whose
// previous price is the same; get_price and get_price_epoch read them. Each
// new price opens an epoch and keeps the price before it; every later read
// sees the new value; get_price_epoch returns three fields, [price, epoch,
// previous], the shape the pinned epoch read requires.
#[test]
unconstrained fn the_owner_opens_epochs_from_the_constructor_price() {
    let (env, owner, oracle, _) = oracle_with(EPOCH_BLOCKS);
    let o = LendingOracle::at(oracle);
    assert_eq(env.view_public(o.get_price()), PRICE);
    assert_eq(env.view_public(o.get_price_epoch()), PriceEpoch { price: PRICE, epoch: EPOCH, previous: PRICE });
    assert_eq(env.view_public(o.get_owner()), owner);
    env.call_public(owner, o.set_price(LOW_PRICE));
    assert_eq(env.view_public(o.get_price()), LOW_PRICE);
    let epoch = env.view_public(o.get_price_epoch());
    assert_eq(epoch, PriceEpoch { price: LOW_PRICE, epoch: EPOCH + 1, previous: PRICE });
    assert_eq(epoch.serialize(), [LOW_PRICE as Field, (EPOCH + 1) as Field, PRICE as Field]);
    // 0 is accepted: the circuits answer a zero price with code 6, a no-op
    env.call_public(owner, o.set_price(0));
    assert_eq(env.view_public(o.get_price_epoch()), PriceEpoch { price: 0, epoch: EPOCH + 2, previous: LOW_PRICE });
}

// The previous price is offered for PREVIOUS_BLOCKS blocks after a new
// epoch opens, the window's last block included; from the next block on the
// oracle reports the current price in its place, so a round computed at the
// old price no longer lands.
#[test]
unconstrained fn the_previous_price_expires_previous_blocks_after_a_new_epoch() {
    let (env, owner, oracle, _) = oracle_with(EPOCH_BLOCKS);
    let o = LendingOracle::at(oracle);
    env.call_public(owner, o.set_price(LOW_PRICE));
    let opened = env.last_block_number();
    // a view runs in the next block
    mine_until_next_block_is(env, opened + PREVIOUS_BLOCKS);
    assert_eq(env.view_public(o.get_price_epoch()), PriceEpoch { price: LOW_PRICE, epoch: EPOCH + 1, previous: PRICE });
    env.mine_block();
    assert_eq(env.view_public(o.get_price_epoch()), PriceEpoch { price: LOW_PRICE, epoch: EPOCH + 1, previous: LOW_PRICE });
    // the next epoch offers the price before it again
    env.call_public(owner, o.set_price(PRICE));
    assert_eq(env.view_public(o.get_price_epoch()), PriceEpoch { price: PRICE, epoch: EPOCH + 2, previous: LOW_PRICE });
}

// Nobody else may move it.
#[test(should_fail_with = "only the owner sets the price")]
unconstrained fn only_the_owner_sets_the_price() {
    let (mut env, _, oracle, _) = oracle_with(EPOCH_BLOCKS);
    let stranger = env.create_light_account();
    env.call_public(stranger, LendingOracle::at(oracle).set_price(LOW_PRICE));
}

// ---- the least epoch length -----------------------------------------------

global MIN_EPOCH_BLOCKS: u32 = 3;

/// An oracle whose epochs last at least MIN_EPOCH_BLOCKS blocks.
unconstrained fn min_epoch_oracle() -> (TestEnvironment, AztecAddress, AztecAddress, u32) {
    oracle_with(MIN_EPOCH_BLOCKS)
}

// Once the epoch has lasted epoch_blocks blocks the owner opens the next
// one, which keeps the previous price.
#[test]
unconstrained fn a_price_after_epoch_blocks_opens_the_next_epoch() {
    let (env, owner, oracle, opened) = min_epoch_oracle();
    mine_until_next_block_is(env, opened + MIN_EPOCH_BLOCKS);
    env.call_public(owner, LendingOracle::at(oracle).set_price(LOW_PRICE));
    assert_eq(
        env.view_public(LendingOracle::at(oracle).get_price_epoch()),
        PriceEpoch { price: LOW_PRICE, epoch: EPOCH + 1, previous: PRICE },
    );
}

// A second price inside epoch_blocks of the first is refused: the new epoch
// is one block old.
#[test(should_fail_with = "the price epoch is younger than epoch_blocks")]
unconstrained fn a_second_price_inside_epoch_blocks_is_refused() {
    let (env, owner, oracle, opened) = min_epoch_oracle();
    mine_until_next_block_is(env, opened + MIN_EPOCH_BLOCKS);
    env.call_public(owner, LendingOracle::at(oracle).set_price(LOW_PRICE));
    env.call_public(owner, LendingOracle::at(oracle).set_price(PRICE));
}

// The first epoch counts from the constructor's block: one block short of
// epoch_blocks is refused.
#[test(should_fail_with = "the price epoch is younger than epoch_blocks")]
unconstrained fn a_price_one_block_short_of_epoch_blocks_is_refused() {
    let (env, owner, oracle, opened) = min_epoch_oracle();
    mine_until_next_block_is(env, opened + MIN_EPOCH_BLOCKS - 1);
    env.call_public(owner, LendingOracle::at(oracle).set_price(LOW_PRICE));
}
