//! The credits the market keeps and the tokens behind them
//! (pss_public_contract `token`; docs/ARCHITECTURE.md section 6, "Tokens and
//! escrow"; examples/lending-tip/README.md, "Tokens"), on the
//! secret-shared deployment unless a case says otherwise:
//!
//! - the brick's selectors are the vendored reference token's own;
//! - `fund` moves tokens in (public amounts, a transaction of its own) and
//!   credits a note of the sender's for both assets;
//! - a request draws its escrow and the usage deposit from one credit note
//!   (the change a note of its own) and records two refund notes by queue
//!   index, commitments only: no token call, no amount; a credit that does
//!   not cover the request reverts it;
//! - `skip()` completes both refund notes; a round that runs keeps the
//!   deposit (lending's choice) or, under a Config that refunds it,
//!   completes its refund, and completes the escrow's refund when its shares
//!   did not open C; every other settlement is in the outcome, which
//!   `redeem` credits privately;
//! - `withdraw_funds` turns credit into tokens, never from the kept
//!   deposits;
//! - the constructor refuses a usage deposit in another token than the
//!   borrowed asset.
//!
//! Each user funded FUNDED of both assets at deployment (lib.nr). The
//! rounds are stand-ins, as in the rest of the suite.
use crate::{
    BORROWER,
    applied_on, BORROW, ROUND_BORROW, C1, C_INIT, configure, credit, deploy_unfunded, deploy_with, DEPOSIT, ROUND_DEPOSIT,
    EPOCH, fund, FUNDED, held_setup, hold, init, LIQUIDITY, MINTED, open_and_deliver, POSITION,
    PRICE, private_balance, public_balance, redeem, REPAY, ROUND_REPAY, request_owner, Setup,
    shared_setup, STALE, submit_shared, USAGE_DEPOSIT, COLLATERAL_ASSET, market,
    mine_until_next_block_is, outcome_notes, WITHDRAW, ROUND_WITHDRAW,
};
use aztec::protocol::address::AztecAddress;
use aztec::protocol::traits::Packable;
use lending_market::app::{LendingOutcome, SHARED_PACKAGES};
use lending_tip::LendingTip;
use pss_public_contract::token::{
    FINALIZE_TRANSFER_TO_PRIVATE, PREPARE_PRIVATE_BALANCE_INCREASE, TRANSFER_TO_PUBLIC,
};
use token::Token;

/// The user's credit after `held_setup`: FUNDED of each asset less the
/// opening's escrow (DEPOSIT of collateral) and its kept usage deposit.
unconstrained fn held_credit() -> [Field; 2] {
    [FUNDED - DEPOSIT, FUNDED - USAGE_DEPOSIT]
}

unconstrained fn withdraw_funds(s: Setup, who: AztecAddress, collateral: Field, borrowed: Field) {
    s.env.call_private(who, LendingTip::at(s.app).withdraw_funds(collateral as u128, borrowed as u128));
}

// The brick calls the token by selector: each is the vendored token's own.
#[test]
unconstrained fn the_bricks_selectors_are_the_tokens() {
    let t = Token::at(AztecAddress::zero());
    let a = AztecAddress::zero();
    assert_eq(TRANSFER_TO_PUBLIC, t.transfer_to_public(a, a, 0, 0).selector);
    assert_eq(PREPARE_PRIVATE_BALANCE_INCREASE, t.prepare_private_balance_increase(a).selector);
    assert_eq(FINALIZE_TRANSFER_TO_PRIVATE, t.finalize_transfer_to_private(0, std::mem::zeroed()).selector);
}

// Funding moves the tokens into the market's public balances, in public
// amounts, and credits the sender one note for both assets.
#[test]
unconstrained fn fund_moves_tokens_in_and_credits_the_sender() {
    let s = shared_setup();
    assert_eq(credit(s, s.user), [FUNDED, FUNDED]);
    assert_eq(private_balance(s, s.borrowed, s.user), MINTED - FUNDED);
    let before = public_balance(s, s.collateral, s.app);
    fund(s, s.user, 7, 0);
    assert_eq(credit(s, s.user), [FUNDED + 7, FUNDED]);
    assert_eq(public_balance(s, s.collateral, s.app), before + 7);
    assert_eq(private_balance(s, s.collateral, s.user), MINTED - FUNDED - 7);
}

// A request draws its escrow and the usage deposit from the sender's credit
// and records two refund notes by queue index; no token moves and no amount
// is public. A borrow draws only the deposit, and records two refund notes
// all the same.
#[test]
unconstrained fn a_request_draws_on_its_credit_and_records_its_refund_notes() {
    let s = shared_setup();
    let (collateral, borrowed) = (public_balance(s, s.collateral, s.app), public_balance(s, s.borrowed, s.app));
    let _ = request_owner(s, s.user, ROUND_DEPOSIT, 0, DEPOSIT, 1);
    assert_eq(credit(s, s.user), [FUNDED - DEPOSIT, FUNDED - USAGE_DEPOSIT]);
    assert_eq([public_balance(s, s.collateral, s.app), public_balance(s, s.borrowed, s.app)], [collateral, borrowed]);
    let r = s.env.view_public(LendingTip::at(s.app).refunds_at(0));
    assert((r.escrow != 0) & (r.deposit != 0) & (r.escrow != r.deposit));
}

// A credit that does not cover the request (escrow and deposit from one
// note) reverts it: nothing is queued.
#[test(should_fail_with = "no credit note of the sender's covers the request")]
unconstrained fn a_request_the_credit_does_not_cover_reverts() {
    let s = shared_setup();
    let _ = request_owner(s, s.user, ROUND_DEPOSIT, 0, FUNDED + 1, 1);
}

// A skipped request gets both refund notes completed: its credit comes back
// whole, with no token call.
#[test]
unconstrained fn skip_completes_both_refund_notes() {
    let s = shared_setup();
    let _ = request_owner(s, s.user, ROUND_DEPOSIT, 0, DEPOSIT, 1);
    mine_until_next_block_is(s, s.env.next_block_number() + STALE);
    s.env.call_public(s.other, LendingTip::at(s.app).skip());
    assert_eq(credit(s, s.user), [FUNDED, FUNDED]);
}

// A repayment that does not apply (code 7) returns its escrow through its
// outcome, which `redeem` credits; the usage deposit is kept.
#[test]
unconstrained fn a_failed_repayments_redeem_credits_its_escrow() {
    let s = held_setup();
    let r = request_owner(s, s.user, ROUND_REPAY, POSITION, 1701, 1);
    let h = held_credit();
    let (c, b) = (h[0], h[1]);
    assert_eq(credit(s, s.user), [c, b - 1701 - USAGE_DEPOSIT]);
    let failed = [7, POSITION, BORROWER, DEPOSIT, 0, 1701, 0];
    let tx = submit_shared(s, r, C_INIT, C1, PRICE, EPOCH, failed);
    assert_eq(open_and_deliver(s, r, tx), failed);
    redeem(s, s.user, r.id);
    assert_eq(credit(s, s.user), [c, b - USAGE_DEPOSIT]);
}

// A deposit that does not apply (code 17) returns its collateral through its
// outcome's payout, with the collateral asset's bit: the redeem credits it in
// the collateral asset.
#[test]
unconstrained fn a_failed_deposits_redeem_credits_its_collateral() {
    let s = shared_setup();
    let d = request_owner(s, s.user, ROUND_DEPOSIT, 0, DEPOSIT, 1);
    let failed = [17, 0, 0, 0, 0, COLLATERAL_ASSET + DEPOSIT, 0];
    let tx = submit_shared(s, d, C_INIT, C1, PRICE, EPOCH, failed);
    assert_eq(open_and_deliver(s, d, tx), failed);
    redeem(s, s.user, d.id);
    assert_eq(credit(s, s.user), [FUNDED, FUNDED - USAGE_DEPOSIT]);
}

// The settlement rule: payout's amount in the asset its bit names; x in the
// collateral asset only when the note names no position (a liquidation's
// seize), so an owner note's x, the position's collateral, is never paid.
#[test]
fn a_note_pays_its_payout_in_its_asset_and_a_seize_in_collateral() {
    let note = |f: [Field; 7]| LendingOutcome::unpack(f.concat([0x1d]));
    assert_eq(note([0, POSITION, BORROWER, DEPOSIT, 0, 0, 0]).settlement(), (0, 0));
    assert_eq(note([0, POSITION, BORROWER, DEPOSIT, BORROW, BORROW, 0]).settlement(), (0, BORROW as u128));
    assert_eq(note([0, 0, 1, 446, 850, 150, 0]).settlement(), (446, 150));
    assert_eq(note([0, 0, 10, 0, 0, 0, 7]).settlement(), (0, 0));
    // a withdrawal: its amount in the collateral asset
    let w = note([0, POSITION, BORROWER, DEPOSIT - WITHDRAW, 0, COLLATERAL_ASSET + WITHDRAW, 0]);
    assert_eq(w.settlement(), (WITHDRAW as u128, 0));
    // a failed deposit into its open position: the escrow back in collateral
    let f = note([7, POSITION, BORROWER, DEPOSIT, 0, COLLATERAL_ASSET + 10, 0]);
    assert_eq(f.settlement(), (10, 0));
    // a repayment's excess over the debt, in the borrowed asset
    assert_eq(note([0, POSITION, BORROWER, DEPOSIT, 0, 1, 0]).settlement(), (0, 1));
    // the widest amount of each asset
    let max = 0xffffffffffffffffffffffffffffffff;
    assert_eq(note([0, POSITION, BORROWER, 0, 0, max, 0]).settlement(), (0, max as u128));
    assert_eq(note([0, POSITION, BORROWER, 0, 0, COLLATERAL_ASSET + max, 0]).settlement(), (max as u128, 0));
}

// A code-14 round: a round whose shares did not open C outputs
// the inputs-opened bit 0, its note names nothing and pays nothing, and
// `apply_shared` completes both refund notes, the escrow's and the usage
// deposit's: the round served nobody (the nodes can force code 14 on any
// request), so nothing of the request is kept. Only the opening's deposit
// stays kept.
#[test]
unconstrained fn a_code_14_rounds_escrow_and_deposit_come_back_with_the_apply() {
    let s = held_setup();
    let r = request_owner(s, s.user, ROUND_REPAY, POSITION, REPAY, 1);
    let h = held_credit();
    let (c, b) = (h[0], h[1]);
    assert_eq(credit(s, s.user), [c, b - REPAY - USAGE_DEPOSIT]);
    let mismatch = [14, 0, 0, 0, 0, 0, 0];
    let tx = submit_shared(s, r, C_INIT, C1, PRICE, EPOCH, mismatch);
    assert_eq(open_and_deliver(s, r, tx), mismatch);
    assert_eq(market(s), C1);
    assert_eq(credit(s, s.user), [c, b]);
    assert_eq(s.env.view_public(LendingTip::at(s.app).get_kept_deposits()), USAGE_DEPOSIT as u128);
}

// A repayment of more than the debt applies: the debt is repaid and the
// excess comes back through the note's payout, credited by the redeem.
#[test]
unconstrained fn a_repayment_over_the_debt_returns_the_excess() {
    let s = held_setup();
    let r = request_owner(s, s.user, ROUND_REPAY, POSITION, 1701, 1);
    let repaid = [0, POSITION, BORROWER, DEPOSIT, 0, 1, 0];
    let tx = submit_shared(s, r, C_INIT, C1, PRICE, EPOCH, repaid);
    assert_eq(open_and_deliver(s, r, tx), repaid);
    redeem(s, s.user, r.id);
    let h = held_credit();
    let (c, b) = (h[0], h[1]);
    assert_eq(credit(s, s.user), [c, b - 1700 - USAGE_DEPOSIT]);
    // the opening's note and the repayment's: the redeem credits, it adds no note
    assert_eq(outcome_notes(s, s.user).count, 2);
}

// A withdrawal lands, its redeem credits the amount in the collateral asset,
// and `withdraw_funds` turns the credit into tokens from the market's public
// balance.
#[test]
unconstrained fn a_withdrawal_is_credited_then_withdrawn_as_tokens() {
    let s = held_setup();
    let w = request_owner(s, s.user, ROUND_WITHDRAW, POSITION, WITHDRAW, 1);
    let done = [0, POSITION, BORROWER, DEPOSIT - WITHDRAW, 0, COLLATERAL_ASSET + WITHDRAW, 0];
    let tx = submit_shared(s, w, C_INIT, C1, PRICE, EPOCH, done);
    let _ = open_and_deliver(s, w, tx);
    redeem(s, s.user, w.id);
    let h = held_credit();
    let (c, b) = (h[0], h[1]);
    assert_eq(credit(s, s.user), [c + WITHDRAW, b - USAGE_DEPOSIT]);
    let before = public_balance(s, s.collateral, s.app);
    withdraw_funds(s, s.user, WITHDRAW, 0);
    assert_eq(credit(s, s.user), [c, b - USAGE_DEPOSIT]);
    assert_eq(public_balance(s, s.collateral, s.app), before - WITHDRAW);
    assert_eq(private_balance(s, s.collateral, s.user), MINTED - FUNDED + WITHDRAW);
}

// A withdrawal past the borrow limit lands with code 9: its note reports the
// position as it stands and pays nothing, so there is nothing to redeem.
#[test(should_fail_with = "the note has nothing to redeem")]
unconstrained fn a_withdrawal_past_the_limit_pays_nothing() {
    let s = held_setup();
    let w = request_owner(s, s.user, ROUND_WITHDRAW, POSITION, WITHDRAW, 1);
    let refused = [9, POSITION, BORROWER, DEPOSIT, BORROW, 0, 0];
    let tx = submit_shared(s, w, C_INIT, C1, PRICE, EPOCH, refused);
    let _ = open_and_deliver(s, w, tx);
    redeem(s, s.user, w.id);
}

// A withdrawal of more than the sender's credit is refused.
#[test(should_fail_with = "no credit note of the sender's covers the withdrawal")]
unconstrained fn a_withdrawal_past_the_credit_is_refused() {
    let s = shared_setup();
    withdraw_funds(s, s.user, 0, FUNDED + 1);
}

// Under a Config whose usage deposit is refunded (the library's default),
// `apply` completes the deposit's refund note on every round.
#[test]
unconstrained fn a_refunded_deposit_comes_back_with_the_apply() {
    let s = deploy_with(SHARED_PACKAGES, crate::vk_hashes_of(SHARED_PACKAGES), false);
    configure(s);
    init(s, C_INIT);
    let _ = hold(s, s.user, POSITION, 9);
    assert_eq(credit(s, s.user), [FUNDED - DEPOSIT, FUNDED]);
    let b = request_owner(s, s.user, ROUND_BORROW, POSITION, BORROW, 1);
    assert_eq(credit(s, s.user), [FUNDED - DEPOSIT, FUNDED - USAGE_DEPOSIT]);
    let _ = submit_shared(s, b, C_INIT, C1, PRICE, EPOCH, applied_on(POSITION, DEPOSIT, BORROW, BORROW));
    assert_eq(credit(s, s.user), [FUNDED - DEPOSIT, FUNDED]);
    assert_eq(s.env.view_public(LendingTip::at(s.app).get_kept_deposits()), 0);
    assert_eq(public_balance(s, s.borrowed, s.app), LIQUIDITY + 2 * FUNDED);
}

// The constructor holds lending's DEV DECISION: the usage deposit is paid in
// the borrowed asset.
#[test(should_fail_with = "the usage deposit is paid in the borrowed asset")]
unconstrained fn a_deposit_in_another_token_is_refused_at_deployment() {
    let mut s = deploy_unfunded(SHARED_PACKAGES);
    let mut config = s.config;
    config.deposit.token = s.collateral;
    let _ = s.env.deploy("../lending_tip@lending_tip/LendingTip").with_public_initializer(
        s.deployer,
        LendingTip::interface().constructor(config),
    );
}
