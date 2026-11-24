//! Interest on the secret-shared deployment (examples/lending-tip/README.md,
//! "Interest"): every round's second pinned read is the market's own
//! `clock()`, the block number, which `apply_shared` re-makes under a
//! tolerance of CLOCK_BAND blocks, ahead of the landing block or behind it;
//! a clock outside the band reverts the result (liveness only: the head
//! waits for a recompute or `skip()`). The accrual itself is the circuits'
//! (lending_tip market.nr `accrue`, rounds.nr's interest tests and the
//! Prover-accrued fixtures: accrual over N blocks against the closed form,
//! a borrower at the index boundary, the band's top then its bottom
//! accruing once, the supply index after accrual, a position turned
//! liquidatable by interest alone); here the outcomes are stand-ins with
//! those numbers, as in the rest of the suite.
use crate::{
    BORROW, ROUND_BORROW, BORROWER, C1, C2, C3, C_INIT, DEPOSIT, EPOCH, held_setup, market,
    open_and_deliver, POSITION, PRICE, ROUND_REPAY, request_owner, request_view, submit_shared,
    Landing, submit_landing,
};
use lending_market::app::CLOCK_BAND;
use lending_tip::LendingTip;
use pss_tip_test::mine_until_next_block_is;

// The block `apply` runs in is the next block or the one after it (the TXE
// may mine the private part first), so the clocks below sit at the band's
// edges whichever of the two it is: within 128 blocks of both, or beyond
// 128 of both.

// The clock is the block number the public call runs in. A round computed
// at the band's top (CLOCK_BAND blocks ahead of the block it lands in)
// lands, and so does the next one at the band's bottom: the contract admits
// both, and the circuit's last_accrual' = max(last_accrual, t) accrues the
// interval between them once.
//
// The accrual reaches the owner's note: 100 blocks on, a view reports the
// debt at the current index and the borrow index in mask (stand-ins: the
// race's 1,700 at an index of 1,000,004,600 is 1,701 rounded up), and a
// repayment of the 1,700 its earlier note said then leaves the interest.
#[test]
unconstrained fn the_clock_is_the_block_and_rounds_at_the_bands_edges_land_and_deliver_the_accrual() {
    let s = held_setup();
    let block = s.env.next_block_number();
    assert_eq(s.env.view_public(LendingTip::at(s.app).clock()), block as Field);
    mine_until_next_block_is(s.env, block + 300);
    assert_eq(s.env.view_public(LendingTip::at(s.app).clock()), (block + 300) as Field);
    let b = request_owner(s, s.user, ROUND_BORROW, POSITION, BORROW, 1);
    let next = s.env.next_block_number() as Field;
    let borrowed = [0, POSITION, BORROWER, DEPOSIT, BORROW, BORROW, 0];
    let _ = submit_landing(s, b, C_INIT, C1, PRICE, EPOCH, borrowed, Landing::at(next + CLOCK_BAND));
    assert_eq(market(s), C1);
    let v = request_view(s, POSITION, 2);
    let next = s.env.next_block_number() as Field;
    let viewed = [0, POSITION, BORROWER, DEPOSIT, BORROW, 0, 0];
    let _ = submit_landing(s, v, C1, C2, PRICE, EPOCH, viewed, Landing::at(next + 1 - CLOCK_BAND));
    assert_eq(market(s), C2);

    let start = s.env.next_block_number();
    mine_until_next_block_is(s.env, start + 100);
    let v = request_view(s, POSITION, 3);
    let viewed = [0, POSITION, 1000004600, DEPOSIT, BORROW + 1, 0, 0];
    let tx = submit_shared(s, v, C2, C3, PRICE, EPOCH, viewed);
    assert_eq(open_and_deliver(s, v, tx), viewed);
    let r = request_owner(s, s.user, ROUND_REPAY, POSITION, BORROW, 4);
    let repaid = [0, POSITION, 1000004600, DEPOSIT, 1, 0, 0];
    let tx = submit_shared(s, r, C3, C1 + 0x10, PRICE, EPOCH, repaid);
    assert_eq(open_and_deliver(s, r, tx), repaid);
}

// A clock past the band's top reverts the result.
#[test(should_fail_with = "pinned read outside its band")]
unconstrained fn a_clock_past_the_bands_top_is_refused() {
    let s = held_setup();
    let b = request_owner(s, s.user, ROUND_BORROW, POSITION, BORROW, 1);
    let next = s.env.next_block_number() as Field;
    let _ = submit_landing(s, b, C_INIT, C1, PRICE, EPOCH, [0; 7], Landing::at(next + CLOCK_BAND + 2));
}

// A clock below the band's bottom (a round computed long before it lands)
// reverts the result too.
#[test(should_fail_with = "pinned read outside its band")]
unconstrained fn a_clock_below_the_bands_bottom_is_refused() {
    let s = held_setup();
    let b = request_owner(s, s.user, ROUND_BORROW, POSITION, BORROW, 1);
    let next = s.env.next_block_number();
    mine_until_next_block_is(s.env, next + 300);
    let _ = submit_landing(s, b, C_INIT, C1, PRICE, EPOCH, [0; 7], Landing::at((next + 300 - 129) as Field));
}

