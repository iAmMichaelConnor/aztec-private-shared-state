//! The queue's TXE suite: append, the seen mapping, the head clock and
//! `skip()`, through the wrappers of `PssPublicTest`. Each call the tests
//! make is one transaction in its own block, so a request's `head_since` is
//! the block its transaction landed in, and the next call runs in
//! `env.next_block_number()`.
//!
//! Refusals and their post-condition. A refused call reverts its
//! transaction, and the TXE ends a test at the revert, so a
//! `should_fail_with` test cannot read the state afterwards. Each test of a
//! public refusal therefore first makes the same call through a probe
//! (`try_*`: the call made as a nested call whose revert the probe reports)
//! and checks with `assert_refused_without_effect` (pss_tip_test's
//! `QueueReader`, `s.queue()`) that it was refused and left the queue
//! (head, tail, requests, done), the stored outputs and the commitment
//! slots as they were and the probe's transaction without a log or note;
//! then it makes the call itself, which fails with the expected message. A
//! refusal in a private function (the receipt checks, the static-validity
//! predicate, every check of `process_result`) produces no transaction at
//! all, so nothing reaches the chain and there is nothing to compare.
//!
//! The owner-grief bindings (total_aztec's `get_note_or` and
//! `contract_is_initialized_or`) have no place here: the library and this
//! contract read no notes (the queue, the slots and the pins are public
//! storage), and the only init checks are aztec-nr's on each function of a
//! contract its deployer initialises in the deployment transaction, so no
//! request can be queued before they pass and none can make them fail
//! afterwards.
use pss_tip_test::shape::TxSummary;
use crate::nodes::{HELD_VK_HASH, tip_config, VK_HASH};
use crate::PssPublicTest;
use aztec::protocol::address::AztecAddress;
use aztec::test::helpers::test_environment::TestEnvironment;
use aztec::test::helpers::txe_oracles;
use pss_public_contract::{DONE_PENDING, DONE_SKIPPED, FixedCircuits, Head, StaleBlocks, TipConfig};
use crate::rounds::Keys;
use pss_tip_test::queue::QueueReader;

// short, so the tests mine few blocks; the rule is the same at the default
global STALE: u32 = 4;

global ID_A: Field = 0xa1;
global ID_B: Field = 0xb2;
global ID_C: Field = 0xc3;

pub struct Setup {
    pub env: TestEnvironment,
    pub deployer: AztecAddress,
    pub user: AztecAddress,
    pub app: AztecAddress,
}

impl Setup {
    pub unconstrained fn queue(self) -> Reader {
        reader(self.env, self.app)
    }
}

pub unconstrained fn deploy(stale_blocks: StaleBlocks) -> Setup {
    let config = tip_config(stale_blocks);
    let mut env = TestEnvironment::new();
    let deployer = env.create_light_account();
    let user = env.create_light_account();
    let app = env.deploy("PssPublicTest").with_public_initializer(
        deployer,
        PssPublicTest::interface().constructor(config, VK_HASH, HELD_VK_HASH),
    );
    Setup { env, deployer, user, app }
}

pub unconstrained fn setup() -> Setup {
    deploy(StaleBlocks::after(STALE))
}

/// Enqueue `request_id` through the private intake stand-in; returns the
/// block its transaction landed in.
pub unconstrained fn request(s: Setup, request_id: Field) -> u32 {
    s.env.call_private(s.user, PssPublicTest::at(s.app).request(request_id));
    s.env.last_block_number()
}

/// Call `skip()` as the user; returns the block its transaction landed in.
pub unconstrained fn skip(s: Setup) -> u32 {
    s.env.call_public(s.user, PssPublicTest::at(s.app).skip());
    s.env.last_block_number()
}

/// Mine empty blocks until the next transaction lands in `block`.
pub unconstrained fn mine_until_next_block_is(s: Setup, block: u32) {
    pss_tip_test::mine_until_next_block_is(s.env, block);
}

pub unconstrained fn is_seen(s: Setup, request_id: Field) -> bool {
    s.env.view_public(PssPublicTest::at(s.app).is_seen(request_id))
}

pub unconstrained fn pool(s: Setup) -> Field {
    s.env.view_public(PssPublicTest::at(s.app).get_pool())
}

/// Deploy a second instance of the test app, whose probes call the
/// first from outside it.
pub unconstrained fn deploy_outsider(env: &mut TestEnvironment) -> AztecAddress {
    let deployer = env.create_light_account();
    env.deploy("PssPublicTest").with_public_initializer(
        deployer,
        PssPublicTest::interface().constructor(
            tip_config(StaleBlocks::after(STALE)),
            VK_HASH,
            HELD_VK_HASH,
        ),
    )
}

// ---- the post-condition of a refusal --------------------------------------

/// The test contract's queue, slots and stored outputs as pss_tip_test
/// reads every tip app's (`get_state`, `request_at`, `done_at`,
/// `outcome_at`): its TipConfig, one all-zero configured package, the four
/// slots (`pool`, `book`, `fresh`, `held`) and the app outputs `apply`
/// stores. Its `assert_refused_without_effect` is the post-condition of a
/// refusal.
pub type Reader = QueueReader<TipConfig, 4, [Field; 2], Keys, FixedCircuits>;

/// The reader of the test contract at `app`.
pub unconstrained fn reader(env: TestEnvironment, app: AztecAddress) -> Reader {
    QueueReader::at(env, app)
}

/// The side effects of the last transaction, read through `app`.
pub unconstrained fn last_tx_summary(env: TestEnvironment, app: AztecAddress) -> TxSummary {
    let tx_hash = txe_oracles::get_last_tx_effects().tx_hash;
    env.execute_utility(PssPublicTest::at(app).tx_summary(tx_hash))
}

/// The requester audit of the last transaction's effect, run by `auditor`'s
/// `tx_names_no_requester` utility (any deployed PssPublicTest).
pub unconstrained fn assert_last_tx_names_no_requester(
    env: TestEnvironment,
    auditor: AztecAddress,
    accounts: [AztecAddress; 4],
) {
    let tx_hash = txe_oracles::get_last_tx_effects().tx_hash;
    assert(env.execute_utility(PssPublicTest::at(auditor).tx_names_no_requester(tx_hash, accounts)));
}

/// The probes, made by the user: `prober` makes the call on `target`
/// (`target` itself for the library's checks, another instance for
/// `#[only_self]`).
pub unconstrained fn try_append(s: Setup, prober: AztecAddress, request_id: Field) -> bool {
    s.env.call_public(s.user, PssPublicTest::at(prober).try_append(s.app, request_id))
}

pub unconstrained fn try_skip(s: Setup) -> bool {
    s.env.call_public(s.user, PssPublicTest::at(s.app).try_skip(s.app))
}

// A fresh queue is empty: head == tail == 0 and no clock. append writes
// requests[tail] = request_id, advances tail and sets seen; the head stays
// at the first request, and nothing is finished.
#[test]
unconstrained fn a_new_queue_is_empty_and_append_queues_requests_in_order() {
    let s = setup();
    assert_eq(s.queue().head(), Head { index: 0, since: 0 });
    assert_eq(s.queue().tail(), 0);
    assert(!is_seen(s, ID_A));
    let block_a = request(s, ID_A);
    let _ = request(s, ID_B);

    assert_eq(s.queue().request_at(0), ID_A);
    assert_eq(s.queue().request_at(1), ID_B);
    assert_eq(s.queue().tail(), 2);
    assert(is_seen(s, ID_A));
    assert(is_seen(s, ID_B));
    assert(!is_seen(s, ID_C));
    // the head clock started when ID_A entered the empty queue
    assert_eq(s.queue().head(), Head { index: 0, since: block_a });
    assert_eq(s.queue().done_at(0), DONE_PENDING);
    assert_eq(s.queue().done_at(1), DONE_PENDING);
}

// A request id enters the queue once; the repeat changes nothing.
#[test(should_fail_with = "duplicate request")]
unconstrained fn a_repeated_request_id_reverts() {
    let s = setup();
    let _ = request(s, ID_A);
    let _ = request(s, ID_B);
    s.queue().assert_refused_without_effect(|| try_append(s, s.app, ID_A));
    let _ = request(s, ID_A);
}

// The app's append wrapper is #[only_self]: nobody can push an id the
// intake function did not compute and check, from an account or from
// another contract, and the attempt changes nothing.
#[test(should_fail_with = "Function append can only be called by the same contract")]
unconstrained fn append_from_outside_the_contract_reverts() {
    let mut s = setup();
    let outsider = deploy_outsider(&mut s.env);
    s.queue().assert_refused_without_effect(|| try_append(s, outsider, ID_A));
    assert(!is_seen(s, ID_A));
    s.env.call_public(s.user, PssPublicTest::at(s.app).append(ID_A));
}

// append into an empty queue restarts the head clock, here after a skip
// emptied it long before; append into a non-empty queue leaves the clock.
#[test]
unconstrained fn append_into_an_empty_queue_restarts_the_clock() {
    let s = setup();
    let block_a = request(s, ID_A);
    mine_until_next_block_is(s, block_a + STALE);
    let block_skip = skip(s);
    assert_eq(s.queue().head(), Head { index: 1, since: block_skip });
    assert_eq(s.queue().tail(), 1);

    // the queue sits empty for longer than the stale period
    mine_until_next_block_is(s, block_skip + 3 * STALE);
    let block_b = request(s, ID_B);
    assert_eq(s.queue().head(), Head { index: 1, since: block_b });

    // the queue is not empty now, so a further append keeps the clock
    let _ = request(s, ID_C);
    assert_eq(s.queue().head(), Head { index: 1, since: block_b });
    assert_eq(s.queue().tail(), 3);
}

// After a restart the new head gets its full stale period: two blocks and
// one block short of it, skip() still reverts and changes nothing, although
// the queue's last move was long ago.
#[test(should_fail_with = "head is not stale")]
unconstrained fn after_a_clock_restart_skip_waits_the_full_period() {
    let s = setup();
    let block_a = request(s, ID_A);
    mine_until_next_block_is(s, block_a + STALE);
    let block_skip = skip(s);
    mine_until_next_block_is(s, block_skip + 3 * STALE);
    let block_b = request(s, ID_B);
    mine_until_next_block_is(s, block_b + STALE - 2);
    s.queue().assert_refused_without_effect(|| try_skip(s));
    assert_eq(s.env.next_block_number(), block_b + STALE - 1);
    let _ = skip(s);
}

// skip() two blocks and one block before head_since + stale_blocks reverts
// and changes nothing.
#[test(should_fail_with = "head is not stale")]
unconstrained fn skip_before_stale_blocks_reverts() {
    let s = setup();
    let block_a = request(s, ID_A);
    mine_until_next_block_is(s, block_a + STALE - 2);
    s.queue().assert_refused_without_effect(|| try_skip(s));
    assert_eq(s.env.next_block_number(), block_a + STALE - 1);
    let _ = skip(s);
}

// The probe's own check, without a revert: a skip probe is refused one
// block short of the period and lands at it, so the probes refuse for the
// library's reasons and not for their own (gas, sender).
#[test]
unconstrained fn the_skip_probe_is_refused_one_block_short_and_lands_at_stale_blocks() {
    let s = setup();
    let block_a = request(s, ID_A);
    mine_until_next_block_is(s, block_a + STALE - 1);
    s.queue().assert_refused_without_effect(|| try_skip(s));
    assert(try_skip(s));
    assert_eq(s.env.last_block_number(), block_a + STALE);
    assert_eq(s.queue().head(), Head { index: 1, since: block_a + STALE });
    assert_eq(s.queue().done_at(0), DONE_SKIPPED);
}

// From block head_since + stale_blocks on, anyone may skip: the head moves
// to {index + 1, the current block} and done[index] = skipped; the queue's
// entries, tail and the commitment slot stay. The next head's clock starts
// at the skip, so it waits its own full period.
#[test]
unconstrained fn skip_after_stale_blocks_moves_the_head_and_marks_it_skipped() {
    let s = setup();
    let block_a = request(s, ID_A);
    let _ = request(s, ID_B);
    mine_until_next_block_is(s, block_a + STALE);
    let block_skip = skip(s);

    assert_eq(s.queue().head(), Head { index: 1, since: block_skip });
    assert_eq(s.queue().done_at(0), DONE_SKIPPED);
    assert_eq(s.queue().done_at(1), DONE_PENDING);
    assert_eq(s.queue().tail(), 2);
    assert_eq(s.queue().request_at(0), ID_A);
    assert_eq(s.queue().request_at(1), ID_B);
    assert(is_seen(s, ID_A));
    assert_eq(pool(s), 0);
    // no event and no refund: the skip's transaction emits nothing
    let effects = last_tx_summary(s.env, s.app);
    assert_eq(effects.public_logs, 0);
    assert_eq(effects.private_logs, 0);
    assert_eq(effects.note_hashes, 0);
    assert_eq(effects.l2_to_l1_msgs, 0);

    // ID_B's period runs from the skip
    mine_until_next_block_is(s, block_skip + STALE);
    let block_skip_b = skip(s);
    assert_eq(s.queue().head(), Head { index: 2, since: block_skip_b });
    assert_eq(s.queue().done_at(1), DONE_SKIPPED);
}

// A skipped request id stays seen: it cannot be queued again.
#[test(should_fail_with = "duplicate request")]
unconstrained fn a_skipped_request_id_cannot_be_queued_again() {
    let s = setup();
    let block_a = request(s, ID_A);
    mine_until_next_block_is(s, block_a + STALE);
    let _ = skip(s);
    s.queue().assert_refused_without_effect(|| try_append(s, s.app, ID_A));
    let _ = request(s, ID_A);
}

// skip() on an empty queue reverts: here a drained one (head == tail ==
// 1), although its clock is long stale; the head may not pass requests not
// yet made.
#[test(should_fail_with = "queue is empty")]
unconstrained fn skip_on_a_drained_queue_reverts() {
    let s = setup();
    let block_a = request(s, ID_A);
    mine_until_next_block_is(s, block_a + STALE);
    let block_skip = skip(s);
    mine_until_next_block_is(s, block_skip + 3 * STALE);
    s.queue().assert_refused_without_effect(|| try_skip(s));
    let _ = skip(s);
}

// With stale_blocks null, skip() reverts however long the head has sat.
#[test(should_fail_with = "skip is disabled")]
unconstrained fn skip_is_disabled_when_stale_blocks_is_null() {
    let s = deploy(StaleBlocks::disabled());
    let block_a = request(s, ID_A);
    mine_until_next_block_is(s, block_a + 3 * STALE);
    s.queue().assert_refused_without_effect(|| try_skip(s));
    let _ = skip(s);
}

// With stale_blocks null the queue still takes requests and keeps its clock.
#[test]
unconstrained fn a_queue_with_skipping_disabled_still_queues() {
    let s = deploy(StaleBlocks::disabled());
    let block_a = request(s, ID_A);
    let _ = request(s, ID_B);
    assert_eq(s.queue().head(), Head { index: 0, since: block_a });
    assert_eq(s.queue().tail(), 2);
}

// With a stale period of 0 blocks (StaleBlocks::after(0), which the
// manifest refuses but the library takes) the head is stale at once: the
// first transaction after a request may skip it, and the next head, whose
// clock the skip restarts, as soon.
#[test]
unconstrained fn with_a_stale_period_of_0_every_head_is_skippable_at_once() {
    let s = deploy(StaleBlocks::after(0));
    let _ = request(s, ID_A);
    let _ = request(s, ID_B);
    let block_skip = skip(s);
    assert_eq(s.queue().head(), Head { index: 1, since: block_skip });
    assert_eq(s.queue().done_at(0), DONE_SKIPPED);
    let block_skip = skip(s);
    assert_eq(s.queue().head(), Head { index: 2, since: block_skip });
    assert_eq(s.queue().done_at(1), DONE_SKIPPED);
}
