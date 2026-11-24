//! The escape hatch (pss_public_contract `hatch`; examples/lending-tip/README.md,
//! "The escape hatch") on every deployment: the starving clock every request,
//! landing, `skip()` and `poke()` keeps; the opening, after which no request
//! is queued, no result lands and nobody pokes, while `skip()` and `redeem`
//! keep paying; and the private exit on the sender's newest note of a
//! position, once.
//!
//! Every landing emits its exit tag as a nullifier of the app. The tests of
//! the exit follow the chain of tags as the circuits compute it (lib.nr's
//! `Chain`): an owner round's note on position i of request r is the one
//! whose tag `exit_tag(P, r, i)` the leaf holds until the next write of i,
//! which spends it; a liquidation that writes i issues the owner's notice,
//! the note of the owner's delivery handle, and so stores that note's tag. An
//! exit pushes its note's tag, so it succeeds once and only on the newest
//! note: a second exit, an older note and a note a liquidation replaced push
//! a nullifier that exists ("duplicate nullifiers").
//!
//! The TXE mines every transaction in a block of its own, so two calls never
//! share a block here: a landing and an opening that race in one block are
//! tested in the two orders in consecutive blocks.
//!
//! The outcomes are stand-ins (no circuit runs here) and every stand-in round
//! keeps the market's commitment.
use crate::{
    HEALTHY, LIQUIDATED, MISMATCH, notice_of,
    applied_on, assert_state, BORROW, BORROWER, BUDGET, C1, C2, C_INIT, Chain,
    credit, DEPOSIT, ROUND_DEPOSIT, deposit, EPOCH, market,
    mine_until_next_block_is, NONCE_A, NONCE_B, NONCE_C, oblivious_setup, ok_round, open_notice_as,
    OTHER_POSITION, POSITION, PRICE, redeem, REPAY_OUT, Request, request_liquidation,
    request_liquidation_of, request_owner, request_quote, request_view, SEIZE_OUT, Setup, setup,
    shared_setup, STALE, submit_deposit, submit_shared, SUPPLY, ROUND_SUPPLY, T_LIVE,
    user_partial,
};
use aztec::protocol::address::AztecAddress;
use lending_tip::LendingTip;
use pss_public_contract::DONE_SKIPPED;
use pss_public_contract::hatch::HatchState;
use pss_tip_test::tx_effects::assert_last_nullifier;

/// The positions of the hatch's book beside the user's POSITION: the other
/// account's lender position and its borrower position, which a
/// liquidation writes.
global LENT: Field = 2;
global OTHERS: Field = 3;
/// The borrow the user's position carries in the hatch's book.
global DEBT: Field = 400;
/// The request number of the quote that starts the clock in `freeze` (one
/// no test uses for another request of the other account).
global FREEZE_N: Field = 0x30;

/// A quote's stand-in outcome (its rates; no position).
global QUOTED: [Field; 7] = [0, 0, 1000000000, 0, 1000000000, 0, 850];

/// The hatch's state.
unconstrained fn hatch(s: Setup) -> HatchState {
    s.env.view_public(LendingTip::at(s.app).get_hatch())
}

/// The block the market started starving at (0: not starving).
unconstrained fn starving_since(s: Setup) -> u32 {
    hatch(s).starving_since
}

/// Anyone opens the hatch.
unconstrained fn open_hatch(s: Setup) {
    s.env.call_public(s.relayer, LendingTip::at(s.app).open_hatch());
}

/// Anyone pokes the market.
unconstrained fn poke(s: Setup) {
    s.env.call_public(s.other, LendingTip::at(s.app).poke());
}

/// Mine until the next block is `block`, unless it has passed.
unconstrained fn mine_to(s: Setup, block: u32) {
    if s.env.next_block_number() < block {
        mine_until_next_block_is(s, block);
    }
}

/// Freeze the market: the other account's quote waits at the head (its
/// queueing starts the clock, or keeps a running one's start), T_LIVE
/// blocks pass and anyone opens the hatch. Returns the waiting quote.
unconstrained fn freeze(s: Setup) -> Request {
    let q = request_quote(s, s.other, FREEZE_N);
    mine_to(s, starving_since(s) + T_LIVE);
    open_hatch(s);
    assert(hatch(s).open);
    q
}

/// The relayer lands a quote's (or any header round's) result at the
/// market's commitment with `outcome`.
unconstrained fn land_quote(s: Setup, q: Request, outcome: [Field; 7]) {
    let c = market(s);
    let _ = submit_shared(s, q, c, c, PRICE, EPOCH, outcome);
}

/// `who` exits on its note of `position` from request `request_id`.
unconstrained fn exit_on(s: Setup, who: AztecAddress, position: Field, request_id: Field) {
    s.env.call_private(who, LendingTip::at(s.app).exit(position, request_id));
}

/// The hatch's book and the requests that made it.
struct Book {
    chain: Chain,
    /// the user's opening of POSITION (its older note)
    opened: Request,
    /// the user's borrow of DEBT on POSITION (its newest note)
    borrowed: Request,
    /// the other account's opening supply at LENT
    lent: Request,
    /// the other account's opening of OTHERS (a note the liquidation
    /// replaced)
    others: Request,
    /// the liquidation of OTHERS (the other account's notice)
    liquidation: Request,
}

/// The hatch's book on the initialised deployment `s`: the user opens
/// POSITION (request 1) and borrows DEBT on it (request 2), the other
/// account supplies at LENT (3) and opens OTHERS (4), a liquidation (5)
/// writes OTHERS, whose notice the other account's client opens under the
/// handle its opening left, and a liquidation (6) finds POSITION healthy and
/// writes nothing (its tag not output: the borrow's note stays the newest).
unconstrained fn book(s: Setup) -> Book {
    let mut chain = Chain::new();
    let (opened, borrowed) = chain.open_and_borrow(s, s.user, POSITION, DEBT, 1);
    let lent = request_owner(s, s.other, ROUND_SUPPLY, 0, SUPPLY, 3);
    let _ = chain.owner_round(s, lent, [0, LENT, 0, SUPPLY, SUPPLY, 0, 0]);
    let others = request_owner(s, s.other, ROUND_DEPOSIT, 0, DEPOSIT, 4);
    let _ = chain.owner_round(s, others, applied_on(OTHERS, DEPOSIT, 0, 0));
    let liquidation = request_liquidation_of(s, [OTHERS], 1, 5);
    let tx = chain.liquidation(s, liquidation, LIQUIDATED, Option::some((others, notice_of(OTHERS))));
    let _ = open_notice_as(s, others, liquidation, s.other, tx);
    let healthy = request_liquidation(s, 6);
    let _ = chain.liquidation(s, healthy, HEALTHY, Option::none());
    Book { chain, opened, borrowed, lent, others, liquidation }
}

/// The secret-shared deployment's book, frozen.
unconstrained fn frozen() -> (Setup, Book) {
    let s = shared_setup();
    let b = book(s);
    let _ = freeze(s);
    (s, b)
}

/// Every owner of the frozen book `b` exits once on its newest note: the
/// user's borrower position (the healthy liquidation left its note the
/// newest) repays its debt from the user's credit and is credited its
/// collateral; the other account's lender position is credited its shares'
/// value; the other account's liquidated position exits on its notice. Each
/// exit pushes the tag its position's leaf holds. No token moves:
/// `withdraw_funds` turns the credit into tokens later.
unconstrained fn owners_exit(s: Setup, b: Book) {
    let user = credit(s, s.user);
    exit_on(s, s.user, POSITION, b.borrowed.id);
    assert_last_nullifier(s.app, b.chain.held(POSITION));
    assert_eq(credit(s, s.user), [user[0] + DEPOSIT, user[1] - DEBT]);

    let other = credit(s, s.other);
    exit_on(s, s.other, LENT, b.lent.id);
    assert_last_nullifier(s.app, b.chain.held(LENT));
    assert_eq(credit(s, s.other), [other[0], other[1] + SUPPLY]);

    let other = credit(s, s.other);
    let notice = notice_of(OTHERS);
    exit_on(s, s.other, OTHERS, b.liquidation.id);
    assert_last_nullifier(s.app, b.chain.held(OTHERS));
    assert_eq(credit(s, s.other), [other[0] + notice[3], other[1] - notice[4]]);
}

// ---- the exit ------------------------------------------------------------------

// A borrower, a lender and a liquidated owner each exit once on their
// newest notes (`owners_exit`).
#[test]
unconstrained fn the_owners_exit_once_on_their_newest_notes() {
    let (s, b) = frozen();
    owners_exit(s, b);
}

// The whole flow on the oblivious deployment: the same book, every round on
// a position through its `*_oblivious` request function, the same exits.
#[test]
unconstrained fn the_owners_exit_on_the_oblivious_deployment() {
    let s = oblivious_setup();
    let b = book(s);
    let _ = freeze(s);
    owners_exit(s, b);
}

// An older note of the position: the borrow that replaced it spent its tag.
#[test(should_fail_with = "duplicate nullifiers")]
unconstrained fn an_older_note_of_the_position_is_refused() {
    let (s, b) = frozen();
    exit_on(s, s.user, POSITION, b.opened.id);
}

// A note a liquidation replaced: the liquidation spent its tag, and the
// owner's newest note is the notice.
#[test(should_fail_with = "duplicate nullifiers")]
unconstrained fn a_note_a_liquidation_replaced_is_refused() {
    let (s, b) = frozen();
    exit_on(s, s.other, OTHERS, b.others.id);
}

// Only the note's owner exits: another sender holds no such note.
#[test(should_fail_with = "the sender holds no note of this position and request")]
unconstrained fn a_non_owner_is_refused() {
    let (s, b) = frozen();
    exit_on(s, s.other, POSITION, b.borrowed.id);
}

// A liquidator's note names no position: the liquidator cannot exit on it
// and be paid its seize a second time. Its amounts read as a borrower's
// (collateral the seize, debt the repay), so only the hatch's "the note
// names no entry" refuses it.
#[test(should_fail_with = "the note names no entry")]
unconstrained fn a_liquidators_note_does_not_exit() {
    let (s, b) = frozen();
    exit_on(s, s.other, 0, b.liquidation.id);
}

// A plain deposit's note reports no collateral or debt (its public
// completion would publish them), so it has nothing to exit.
#[test(should_fail_with = "the note has nothing to exit")]
unconstrained fn a_plain_deposits_note_is_refused() {
    let (s, d, _) = plain_frozen();
    exit_on(s, s.user, POSITION, d);
}

// ---- liquidations in a row ------------------------------------------------------

/// The position after the k-th liquidation of the user's position, as its
/// notice reports it.
fn after(k: Field) -> [Field; 7] {
    [0, POSITION, BORROWER, DEPOSIT - 100 * k, BORROW - 400 * k, 0, 0]
}

/// The user opens POSITION (request 1) and borrows BORROW on it (request 2,
/// whose delivery handle stays in the leaf), then `times` liquidations in a
/// row (requests 10, 11, ...), with no owner round between, write the
/// position, each completing that handle with the position after it
/// (`after`), and the user's client opens each notice. Returns the chain and
/// the last liquidation.
unconstrained fn liquidated_in_a_row(s: Setup, times: u32) -> (Chain, Request) {
    let mut chain = Chain::new();
    let (_, b) = chain.open_and_borrow(s, s.user, POSITION, BORROW, 1);
    let mut last = b;
    for k in 0..times {
        let l = request_liquidation(s, 10 + k as Field);
        let tx = chain.liquidation(s, l, LIQUIDATED, Option::some((b, after(1 + k as Field))));
        let packed = open_notice_as(s, b, l, s.user, tx);
        assert_eq(packed, after(1 + k as Field).concat([l.id]));
        last = l;
    }
    (chain, last)
}

/// After `times` liquidations in a row the market freezes, and the owner
/// exits on its newest notice: its tag is the one the leaf holds.
unconstrained fn exit_after_liquidations(times: u32) {
    let s = shared_setup();
    let (chain, last) = liquidated_in_a_row(s, times);
    let _ = freeze(s);
    let before = credit(s, s.user);
    exit_on(s, s.user, POSITION, last.id);
    assert_last_nullifier(s.app, chain.held(POSITION));
    let n = after(times as Field);
    assert_eq(credit(s, s.user), [before[0] + n[3], before[1] - n[4]]);
}

#[test]
unconstrained fn an_owner_liquidated_three_times_in_a_row_exits_on_its_newest_notice() {
    exit_after_liquidations(3);
}

// On a live market the owner's view after two liquidations writes the
// position (spending the second notice's tag) and gives a note that exits
// once the hatch opens.
#[test]
unconstrained fn a_view_after_two_liquidations_gives_a_note_that_exits() {
    let s = shared_setup();
    let (mut chain, _) = liquidated_in_a_row(s, 2);
    let v = request_view(s, POSITION, 20);
    let _ = chain.owner_round(s, v, after(2));
    let _ = freeze(s);
    exit_on(s, s.user, POSITION, v.id);
    assert_last_nullifier(s.app, chain.held(POSITION));
}

// A self-liquidation: the other account liquidates its own position, so it
// holds two notes of one request, the liquidation's (position 0) and the
// notice. `exit(position, request_id)` takes the notice (repaying its debt,
// crediting its collateral), and `redeem(request_id)` still takes the
// liquidation's note (its seize and unused budget).
#[test]
unconstrained fn a_self_liquidator_exits_on_its_notice_and_redeems_its_liquidation() {
    let s = shared_setup();
    let mut chain = Chain::new();
    let d = request_owner(s, s.other, ROUND_DEPOSIT, 0, DEPOSIT, 1);
    let _ = chain.owner_round(s, d, applied_on(POSITION, DEPOSIT, 0, 0));
    let l = request_liquidation(s, 2);
    let tx = chain.liquidation(s, l, LIQUIDATED, Option::some((d, notice_of(POSITION))));
    let _ = open_notice_as(s, d, l, s.other, tx);
    let _ = freeze(s);
    let before = credit(s, s.other);
    exit_on(s, s.other, POSITION, l.id);
    assert_last_nullifier(s.app, chain.held(POSITION));
    let notice = notice_of(POSITION);
    let exited = credit(s, s.other);
    assert_eq(exited, [before[0] + notice[3], before[1] - notice[4]]);
    redeem(s, s.other, l.id);
    assert_eq(credit(s, s.other), [exited[0] + SEIZE_OUT, exited[1] + BUDGET - REPAY_OUT]);
}

// A note that pays and names a position is redeemed and exited once each,
// in either order: the user redeems its borrow's note then exits on it, the
// other account exits on its own borrow's note then redeems it.
#[test]
unconstrained fn redeem_and_exit_on_one_note_succeed_once_each_in_either_order() {
    let s = shared_setup();
    let mut chain = Chain::new();
    let (_, b1) = chain.open_and_borrow(s, s.user, POSITION, BORROW, 1);
    let (_, b2) = chain.open_and_borrow(s, s.other, OTHER_POSITION, BORROW, 3);
    let _ = freeze(s);

    let start = credit(s, s.user);
    redeem(s, s.user, b1.id);
    let redeemed = credit(s, s.user);
    assert_eq(redeemed, [start[0], start[1] + BORROW]);
    exit_on(s, s.user, POSITION, b1.id);
    assert_last_nullifier(s.app, chain.held(POSITION));
    assert_eq(credit(s, s.user), [redeemed[0] + DEPOSIT, redeemed[1] - BORROW]);

    let start = credit(s, s.other);
    exit_on(s, s.other, OTHER_POSITION, b2.id);
    assert_last_nullifier(s.app, chain.held(OTHER_POSITION));
    let exited = credit(s, s.other);
    assert_eq(exited, [start[0] + DEPOSIT, start[1] - BORROW]);
    redeem(s, s.other, b2.id);
    assert_eq(credit(s, s.other), [exited[0], exited[1] + BORROW]);
}

// ---- a landing and the opening in one block --------------------------------------

/// The user opens POSITION (request 1), then its view (request 2) waits at
/// the head, its queueing starting the clock, until the market has starved
/// T_LIVE blocks: the hatch may open, and the view's result may land.
/// Returns the chain, the opening and the view.
unconstrained fn starved_with_a_view() -> (Setup, Chain, Request, Request) {
    let s = shared_setup();
    let mut chain = Chain::new();
    let d = request_owner(s, s.user, ROUND_DEPOSIT, 0, DEPOSIT, 1);
    let _ = chain.owner_round(s, d, applied_on(POSITION, DEPOSIT, 0, 0));
    let v = request_view(s, POSITION, 2);
    mine_to(s, starving_since(s) + T_LIVE);
    (s, chain, d, v)
}

// The landing first: it lands and stops the clock, so the opening that
// raced it cannot follow (`the_opening_after_a_landing_is_refused`); the
// market starves again later, and the owner exits on the view's note, the
// newest.
#[test]
unconstrained fn a_landing_before_the_opening_lands_and_the_owner_exits_on_its_new_note() {
    let (s, mut chain, _, v) = starved_with_a_view();
    let _ = chain.owner_round(s, v, applied_on(POSITION, DEPOSIT, 0, 0));
    assert_eq(hatch(s), HatchState { open: false, starving_since: 0 });
    let _ = freeze(s);
    exit_on(s, s.user, POSITION, v.id);
    assert_last_nullifier(s.app, chain.held(POSITION));
}

#[test(should_fail_with = "the app is not starving")]
unconstrained fn the_opening_after_a_landing_is_refused() {
    let (s, mut chain, _, v) = starved_with_a_view();
    let _ = chain.owner_round(s, v, applied_on(POSITION, DEPOSIT, 0, 0));
    open_hatch(s);
}

// The opening first: the owner exits on the note it held, the opening's.
#[test]
unconstrained fn after_the_opening_the_owner_exits_on_its_old_note() {
    let (s, chain, d, _) = starved_with_a_view();
    open_hatch(s);
    exit_on(s, s.user, POSITION, d.id);
    assert_last_nullifier(s.app, chain.held(POSITION));
}

// ...and the view's result, which raced the opening, is refused.
#[test(should_fail_with = "the app is frozen: the escape hatch is open")]
unconstrained fn a_landing_after_the_opening_is_refused() {
    let (s, mut chain, _, v) = starved_with_a_view();
    open_hatch(s);
    assert_state(s, 1, 2, market(s));
    let _ = chain.owner_round(s, v, applied_on(POSITION, DEPOSIT, 0, 0));
}

// ---- a frozen market ---------------------------------------------------------------

// Once open, nothing is queued, nothing lands and nobody pokes. The public
// functions that refuse are the same on every deployment; each deployment's
// request functions and result path are its own, so the request is tried
// on each and the result on the secret-shared and the plain ones.

/// A request after the opening (an opening deposit: `deposit_shared` or
/// `deposit_oblivious`).
unconstrained fn request_after_the_opening(s: Setup) {
    let _ = freeze(s);
    let _ = request_owner(s, s.user, ROUND_DEPOSIT, 0, DEPOSIT, 1);
}

#[test(should_fail_with = "the app is frozen: the escape hatch is open")]
unconstrained fn no_request_after_the_opening() {
    request_after_the_opening(shared_setup());
}

#[test(should_fail_with = "the app is frozen: the escape hatch is open")]
unconstrained fn no_result_after_the_opening() {
    let s = shared_setup();
    let q = freeze(s);
    land_quote(s, q, QUOTED);
}

#[test(should_fail_with = "the app is frozen: the escape hatch is open")]
unconstrained fn no_poke_after_the_opening() {
    let s = shared_setup();
    let _ = freeze(s);
    poke(s);
}

#[test(should_fail_with = "the app is frozen: the escape hatch is open")]
unconstrained fn no_request_after_the_opening_on_the_oblivious_deployment() {
    request_after_the_opening(oblivious_setup());
}

/// The non-secret-shared deployment frozen: the user's opening deposit
/// (NONCE_A) lands and gives it a note of POSITION, its next deposit
/// (NONCE_B) waits at the head, its queueing starting the clock, T_LIVE
/// blocks pass and anyone opens the hatch. Returns the setup and the two
/// deposits' request ids.
unconstrained fn plain_frozen() -> (Setup, Field, Field) {
    let s = setup();
    let d = deposit(s, DEPOSIT, NONCE_A);
    let _ = submit_deposit(s, ok_round(d, C_INIT, C1).with_partial(user_partial(s, NONCE_A)));
    let waiting = deposit(s, DEPOSIT, NONCE_B);
    mine_to(s, starving_since(s) + T_LIVE);
    open_hatch(s);
    assert(hatch(s).open);
    (s, d, waiting)
}

#[test(should_fail_with = "the app is frozen: the escape hatch is open")]
unconstrained fn no_request_after_the_opening_on_the_plain_deployment() {
    let (s, _, _) = plain_frozen();
    let _ = deposit(s, DEPOSIT, NONCE_C);
}

#[test(should_fail_with = "the app is frozen: the escape hatch is open")]
unconstrained fn no_result_after_the_opening_on_the_plain_deployment() {
    let (s, _, waiting) = plain_frozen();
    let _ = submit_deposit(s, ok_round(waiting, C1, C2).with_partial(user_partial(s, NONCE_B)));
}

// The opening touches neither `skip()` nor `redeem`: the waiting quote is
// skipped (its refunds completed; T_LIVE is at least the stale period, so
// the head is stale by the opening) and the user redeems its borrow's note.
#[test]
unconstrained fn skip_and_redeem_still_work_after_the_opening() {
    let s = shared_setup();
    let mut chain = Chain::new();
    let (_, b) = chain.open_and_borrow(s, s.user, POSITION, BORROW, 1);
    let _ = freeze(s);
    let tail = s.queue().tail();
    mine_to(s, s.queue().head().since + STALE);
    s.env.call_public(s.other, LendingTip::at(s.app).skip());
    assert_eq(s.queue().head().index, tail);
    assert_eq(s.queue().done_at(tail - 1), DONE_SKIPPED);
    let before = credit(s, s.user);
    redeem(s, s.user, b.id);
    assert_eq(credit(s, s.user), [before[0], before[1] + BORROW]);
    assert(hatch(s).open);
}

// ---- the clock ---------------------------------------------------------------------

/// The starving clock on deployment `s` (initialised, its queue empty):
/// `poke()` on an empty queue starts it and a second keeps its start;
/// demand while it runs keeps its start; a served landing on an empty queue
/// stops it; demand starts it at its block and more demand keeps that
/// start; a served landing with a request behind restarts it at its own
/// block; a landing that served nobody (shares that did not open C) and a
/// `skip()` leave it; the hatch opens T_LIVE blocks after the restart.
unconstrained fn the_clock(s: Setup) {
    assert_eq(hatch(s), HatchState { open: false, starving_since: 0 });
    poke(s);
    let poked = s.env.last_block_number();
    assert_eq(starving_since(s), poked);
    poke(s);
    assert_eq(starving_since(s), poked);
    let q1 = request_quote(s, s.other, 1);
    assert_eq(starving_since(s), poked);
    land_quote(s, q1, QUOTED);
    assert_eq(starving_since(s), 0);

    let q2 = request_quote(s, s.other, 2);
    let demanded = s.env.last_block_number();
    assert_eq(starving_since(s), demanded);
    let q3 = request_quote(s, s.other, 3);
    assert_eq(starving_since(s), demanded);
    land_quote(s, q2, QUOTED);
    let restarted = s.env.last_block_number();
    assert_eq(starving_since(s), restarted);

    land_quote(s, q3, MISMATCH);
    assert_eq(starving_since(s), restarted);
    let _ = request_quote(s, s.other, 4);
    mine_to(s, s.queue().head().since + STALE);
    s.env.call_public(s.other, LendingTip::at(s.app).skip());
    assert_eq(starving_since(s), restarted);

    mine_to(s, restarted + T_LIVE);
    open_hatch(s);
    assert_eq(hatch(s), HatchState { open: true, starving_since: restarted });
}

#[test]
unconstrained fn the_clock_on_the_secret_shared_deployment() {
    the_clock(shared_setup());
}
