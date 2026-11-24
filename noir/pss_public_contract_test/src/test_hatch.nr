//! The escape hatch through the library's `hatch` brick, on `PssPublicTest`:
//! the clock every request and landing keeps, the opening, the exit tags a
//! landing emits, and the private exit on the sender's note.
//!
//! The test contract calls the brick's bodies directly (`hatch_queued`,
//! `hatch_landed`, `hatch_open`, `hatch_exit`), as an app's request
//! wrappers, landings, `open_hatch()` and `exit` do; its completed note
//! (`PartialOutcome`) names the entry its amount gives, so a test picks the
//! entry by the outcome it lands. The notes come from the partial-note
//! suite's public completion (`test_partial.nr`).
use crate::PssPublicTest;
use aztec::test::helpers::test_environment::CallPrivateOptions;
use crate::test_partial::{H0, H1, INPUTS, land, NONCE, request, RHO, Setup, setup};
use pss_core::tip::exit::exit_tag;
use pss_public_contract::hatch::HatchState;
use pss_public_contract::partial_note::partial_commitment;
use pss_tip_test::mine_until_next_block_is;
use pss_tip_test::tx_effects::assert_last_nullifier;

/// The period the tests open the hatch after.
global T_LIVE: u32 = 6;
/// The entry the user's note names (its amount, `PartialOutcome`'s rule).
global ENTRY: Field = 3;

unconstrained fn hatch(s: Setup) -> HatchState {
    s.env.view_public(PssPublicTest::at(s.app).get_hatch())
}

unconstrained fn queued(s: Setup) {
    s.env.call_public(s.stranger, PssPublicTest::at(s.app).hatch_queued());
}

unconstrained fn landed(s: Setup, served: bool, tags: [Field; 2]) {
    s.env.call_public(s.relayer, PssPublicTest::at(s.app).hatch_landed(served, tags));
}

/// Start the clock, wait T_LIVE blocks and open the hatch.
unconstrained fn opened(s: Setup) {
    queued(s);
    let since = hatch(s).starving_since;
    mine_until_next_block_is(s.env, since + T_LIVE);
    s.env.call_public(s.stranger, PssPublicTest::at(s.app).hatch_open(T_LIVE));
    assert(hatch(s).open);
}

/// The user's note naming ENTRY, landed in public; returns its exit tag.
unconstrained fn noted(s: Setup) -> Field {
    let id = request(s, INPUTS, RHO, NONCE);
    let _ = land(s, id, partial_commitment(s.user, RHO), H0, H1, true, [0, ENTRY]);
    exit_tag(partial_commitment(s.user, RHO), id, ENTRY)
}

// ---- the clock ---------------------------------------------------------------

// Demand starts the clock at its block; more demand keeps that start.
#[test]
unconstrained fn demand_starts_the_clock_once() {
    let s = setup();
    assert_eq(hatch(s), HatchState { open: false, starving_since: 0 });
    let block = s.env.next_block_number();
    queued(s);
    assert_eq(hatch(s), HatchState { open: false, starving_since: block });
    queued(s);
    assert_eq(hatch(s).starving_since, block);
}

// A served landing stops the clock when the queue is empty after it, and
// restarts it at its own block while requests wait behind it.
#[test]
unconstrained fn a_served_landing_stops_or_restarts_the_clock() {
    let s = setup();
    queued(s);
    landed(s, true, [1, 2]);
    assert_eq(hatch(s).starving_since, 0);
    let _ = request(s, INPUTS, RHO, NONCE);
    queued(s);
    let block = s.env.next_block_number();
    landed(s, true, [3, 4]);
    assert_eq(hatch(s).starving_since, block);
}

// A landing that served nobody leaves the clock as it is.
#[test]
unconstrained fn a_landing_that_served_nobody_leaves_the_clock() {
    let s = setup();
    queued(s);
    let since = hatch(s).starving_since;
    landed(s, false, [1, 2]);
    assert_eq(hatch(s).starving_since, since);
}

#[test(should_fail_with = "the app is not starving")]
unconstrained fn the_hatch_does_not_open_on_a_stopped_clock() {
    let s = setup();
    s.env.call_public(s.stranger, PssPublicTest::at(s.app).hatch_open(T_LIVE));
}

#[test(should_fail_with = "the app has starved for under T_LIVE blocks")]
unconstrained fn the_hatch_does_not_open_before_its_period() {
    let s = setup();
    queued(s);
    let since = hatch(s).starving_since;
    mine_until_next_block_is(s.env, since + T_LIVE - 1);
    s.env.call_public(s.stranger, PssPublicTest::at(s.app).hatch_open(T_LIVE));
}

#[test]
unconstrained fn the_hatch_opens_after_its_period_and_keeps_the_clock() {
    let s = setup();
    opened(s);
    assert(hatch(s).starving_since != 0);
}

#[test(should_fail_with = "the app is frozen: the escape hatch is open")]
unconstrained fn nothing_is_queued_once_open() {
    let s = setup();
    opened(s);
    queued(s);
}

#[test(should_fail_with = "the app is frozen: the escape hatch is open")]
unconstrained fn nothing_lands_once_open() {
    let s = setup();
    opened(s);
    landed(s, true, [1, 2]);
}

// ---- the landing's exit tags -------------------------------------------------

// A landing emits each of its exit tags as a nullifier of the app.
#[test]
unconstrained fn a_landing_emits_its_tags() {
    let s = setup();
    landed(s, true, [0x7a1, 0x7a2]);
    assert_last_nullifier(s.app, 0x7a1);
    assert_last_nullifier(s.app, 0x7a2);
}

#[test(should_fail_with = "an exit tag of 0")]
unconstrained fn a_zero_tag_is_refused() {
    let s = setup();
    landed(s, true, [0x7a1, 0]);
}

// ---- the exit ----------------------------------------------------------------

// The owner exits on its note once the hatch is open: the note's exit tag,
// recomputed from the note alone, is the one nullifier of the app's the exit
// pushes.
#[test]
unconstrained fn an_owner_exits_on_its_note() {
    let s = setup();
    let tag = noted(s);
    opened(s);
    s.env.call_private(s.user, PssPublicTest::at(s.app).hatch_exit(s.user));
    assert_last_nullifier(s.app, tag);
}

#[test(should_fail_with = "duplicate nullifiers")]
unconstrained fn a_second_exit_on_one_note_is_refused() {
    let s = setup();
    let _ = noted(s);
    opened(s);
    s.env.call_private(s.user, PssPublicTest::at(s.app).hatch_exit(s.user));
    s.env.call_private(s.user, PssPublicTest::at(s.app).hatch_exit(s.user));
}

// A landing that replaced the note's entry spent its tag: the note no longer
// exits.
#[test(should_fail_with = "duplicate nullifiers")]
unconstrained fn a_note_whose_tag_a_landing_spent_does_not_exit() {
    let s = setup();
    let tag = noted(s);
    landed(s, true, [tag, 0x7a2]);
    opened(s);
    s.env.call_private(s.user, PssPublicTest::at(s.app).hatch_exit(s.user));
}

// After the opening and an exit, no landing spends the exited tag: the
// frozen app refuses every landing before it emits a tag.
#[test(should_fail_with = "the app is frozen: the escape hatch is open")]
unconstrained fn no_landing_spends_an_exited_tag() {
    let s = setup();
    let tag = noted(s);
    opened(s);
    s.env.call_private(s.user, PssPublicTest::at(s.app).hatch_exit(s.user));
    assert_last_nullifier(s.app, tag);
    landed(s, true, [tag, 0x7a3]);
}

#[test(should_fail_with = "the escape hatch was not open at the anchor block")]
unconstrained fn no_exit_before_the_opening() {
    let s = setup();
    let _ = noted(s);
    queued(s);
    s.env.call_private(s.user, PssPublicTest::at(s.app).hatch_exit(s.user));
}

#[test(should_fail_with = "the note names no entry")]
unconstrained fn a_note_that_names_no_entry_does_not_exit() {
    let s = setup();
    let id = request(s, INPUTS, RHO, NONCE);
    let _ = land(s, id, partial_commitment(s.user, RHO), H0, H1, true, [0, 0]);
    opened(s);
    s.env.call_private(s.user, PssPublicTest::at(s.app).hatch_exit(s.user));
}

// Only the note's owner exits on it: another sender's PXE holds none of the
// user's notes, so it finds nothing before the ownership check.
#[test(should_fail_with = "no completed note to exit on")]
unconstrained fn another_sender_cannot_exit_on_the_users_note() {
    let s = setup();
    let _ = noted(s);
    opened(s);
    s.env.call_private(s.stranger, PssPublicTest::at(s.app).hatch_exit(s.user));
}

// A sender that can read the user's note (the user's scope added to its
// transaction) still cannot exit on it: the ownership check refuses it.
#[test(should_fail_with = "the note is not the sender's")]
unconstrained fn a_sender_that_reads_the_users_note_cannot_exit_on_it() {
    let s = setup();
    let _ = noted(s);
    opened(s);
    s.env.call_private_opts(
        s.stranger,
        CallPrivateOptions::new().with_additional_scopes([s.user]),
        PssPublicTest::at(s.app).hatch_exit(s.user),
    );
}
