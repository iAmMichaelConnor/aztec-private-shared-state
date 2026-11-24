//! TXE tests for the CounterTip contract: the init lands, one add lands and
//! completes its requester's note, a replayed result is refused, and the
//! request function's one static check. The queue, the receipts and the
//! sharing's checks, the result signatures, the key epochs, `configure` and
//! `skip()` are the library's, proven by pss_public_contract_test and the
//! other examples' suites over the same bodies.
//!
//! Every round is computed by the circuit's own `add_shared` at the deployed
//! namespace and counter key, so what the contract lands is what the round
//! circuit outputs. Recursive proof verification is a no-op during TXE
//! witness execution: the staged capsule carries a dummy vk whose hash the
//! Config pins and a zero proof; the vk pin runs for real, and so does
//! everything after it. The signatures are real (pss_tip_test's network).

use aztec::protocol::address::AztecAddress;
use aztec::protocol::hash::poseidon2_hash;
use aztec::protocol::traits::ToField;
use aztec::test::helpers::test_environment::TestEnvironment;
use aztec::test::helpers::txe_oracles;
use counter_circuit::counter::OUTCOME_FIELDS;
use counter_circuit::shared::{add_shared, OUTCOME_SLOT, SharedAdd};
use counter_tip::CounterTip;
use counter_tip::app::{Config, COUNTER_ADD_PACKAGE, COUNTER_INIT_PACKAGE, Keys};
use counter_tip::layouts::COUNTER_ADD_LAYOUT;
use pss_core::tip::intake::SharedIntake;
use pss_core::tip::slot::{commitment, load};
use pss_public_contract::{DONE_APPLIED, FixedCircuits, inputs_commitment, shared_chain_request_id, Sharing, StaleBlocks, TWO_POW_64};
use pss_public_contract::init::init_request_id;
use pss_public_contract::partial_note::partial_commitment;
use pss_public_contract::result::{NodeHeld, Sealing};
use pss_tip_test::{configure_answer, last_tx, result_signatures, tip_pins};
use pss_tip_test::outcome::{open_outcome_log, outcome_result, outcome_signatures};
use pss_tip_test::queue::QueueReader;
use pss_tip_test::sharing::{shared_receipts, sharing_of};

global STALE: u32 = 4;
global NPK_APP_HASH: Field = 0x9b9b;
global NSK_APP: Field = 777;
global OUTCOME_KEY: Field = 0x6b6b;
global OUTCOME_TAG: Field = 0x7a7a;
// the init's blinding and the first add's fresh one
global R0: Field = 0x100;
global R1: Field = 0x111;
// the first add: its amount and rho; every add's blinding
global AMOUNT: Field = 5;
global RHO: Field = 0x5eed;
global BLINDING: Field = 0xb1b1;

// one dummy vk per package, so each pin is tested against the other's proof
unconstrained fn vk_of(p: u32) -> [Field; 115] {
    [5 + p as Field; 115]
}

unconstrained fn vk_hash_of(p: u32) -> Field {
    poseidon2_hash(vk_of(p))
}

struct Setup {
    env: TestEnvironment,
    alice: AztecAddress,
    relayer: AztecAddress,
    app: AztecAddress,
}

impl Setup {
    unconstrained fn queue(self) -> QueueReader<Config, 1, Field, Keys, FixedCircuits> {
        QueueReader::at(self.env, self.app)
    }

    /// The counter key: the `counter` slot's storage slot.
    unconstrained fn key(self) -> Field {
        self.queue().state().state_keys[0]
    }

    unconstrained fn stage_proof(self, p: u32) {
        pss_tip_test::stage_proof(self.env, self.app, self.relayer, vk_of(p));
    }
}

/// Deploy and configure the contract; the counter is not initialised.
unconstrained fn deploy() -> Setup {
    let mut env = TestEnvironment::new();
    let deployer = env.create_light_account();
    let alice = env.create_light_account();
    let relayer = env.create_light_account();
    let config = Config {
        tip: tip_pins(StaleBlocks::after(STALE), [COUNTER_INIT_PACKAGE, COUNTER_ADD_PACKAGE], [vk_hash_of(0), vk_hash_of(1)]),
    };
    let app = env.deploy("../counter_tip@counter_tip/CounterTip").with_public_initializer(
        deployer,
        CounterTip::interface().constructor(config),
    );
    let s = Setup { env, alice, relayer, app };
    s.env.call_private(relayer, CounterTip::at(app).configure(NPK_APP_HASH, configure_answer(app, config.tip, NPK_APP_HASH)));
    s
}

/// The counter_init round's commitment: the total 0 under R0.
unconstrained fn first_counter(s: Setup) -> Field {
    commitment(s.app.to_field(), s.key(), [0], R0)
}

/// Land the init round, signed for the empty slot.
unconstrained fn init(s: Setup) {
    let new_c = first_counter(s);
    let id = init_request_id(s.app, vk_hash_of(0), []);
    let sigs = result_signatures(s.app.to_field(), id, [0], [], [new_c], NodeHeld {}.sealed_hashes());
    s.stage_proof(0);
    s.env.call_private(s.relayer, CounterTip::at(s.app).init_counter(new_c, sigs));
}

unconstrained fn setup() -> Setup {
    let s = deploy();
    init(s);
    s
}

/// The secret-shared intake of `from`'s add of `amount` under `rho`, as the
/// nodes hold it.
fn intake(from: AztecAddress, amount: Field, rho: Field) -> SharedIntake {
    let partial = partial_commitment(from, rho);
    SharedIntake {
        inputs_hash: inputs_commitment([amount, partial, OUTCOME_KEY, OUTCOME_TAG], BLINDING),
        partial,
        outcome_key: OUTCOME_KEY,
        outcome_tag: OUTCOME_TAG,
        blinding: BLINDING,
    }
}

/// C's values of `from`'s add of `amount` under `rho`, in its order.
unconstrained fn add_values(from: AztecAddress, amount: Field, rho: Field) -> [Field; 4] {
    [amount, partial_commitment(from, rho), OUTCOME_KEY, OUTCOME_TAG]
}

/// The sharing of `from`'s add of `amount` under `rho` (`COUNTER_ADD_LAYOUT`: every
/// value of C shared, then the blinding).
unconstrained fn add_sharing(from: AztecAddress, amount: Field, rho: Field) -> Sharing<5> {
    sharing_of(COUNTER_ADD_LAYOUT, add_values(from, amount, rho), BLINDING)
}

/// `from` asks to add `amount` under `rho`, with the three nodes' receipts
/// over C and the sharing's digest; returns the chain request id.
unconstrained fn add(s: Setup, from: AztecAddress, amount: Field, rho: Field) -> Field {
    let sharing = add_sharing(from, amount, rho);
    let c = intake(from, amount, rho).inputs_hash;
    let id = shared_chain_request_id(s.app, vk_hash_of(1), c);
    let expiry = s.env.next_block_number() + 10;
    let rs = shared_receipts(id, c, expiry, COUNTER_ADD_LAYOUT, add_values(from, amount, rho), sharing);
    s.env.call_private(from, CounterTip::at(s.app).add(amount, rho, OUTCOME_KEY, OUTCOME_TAG, sharing, expiry, rs));
    id
}

/// The add round the circuit computes for `from`'s request under `RHO`,
/// over the total `total` under `r_old`, written under `r_new`.
unconstrained fn add_round(s: Setup, from: AztecAddress, amount: Field, total: Field, r_old: Field, r_new: Field) -> SharedAdd {
    let key = load(s.app.to_field(), s.key(), s.key(), [total], r_old, r_new);
    add_shared(vk_hash_of(1), key, amount, intake(from, amount, RHO), NSK_APP).outputs
}

/// The relayer lands the round's outputs with the three nodes' signatures.
unconstrained fn submit(s: Setup, o: SharedAdd) {
    let sigs = outcome_signatures(s.app.to_field(), o, [], NodeHeld {}.sealed_hashes());
    s.stage_proof(1);
    s.env.call_private(s.relayer, CounterTip::at(s.app).process_result(outcome_result(o, []), sigs));
}

/// Open the last transaction's outcome log as the requester does.
unconstrained fn opened_outcome() -> [Field; OUTCOME_FIELDS] {
    open_outcome_log(txe_oracles::get_last_tx_effects().private_logs.get(0), OUTCOME_KEY)
}

// The init lands the commitment counter_init computes for the total 0 and
// leaves the queue empty; the outcome notes sit at the circuits'
// OUTCOME_SLOT.
#[test]
unconstrained fn the_init_lands_the_first_counter() {
    let s = deploy();
    assert_eq(s.queue().commitment(0), 0);
    init(s);
    assert_eq(s.queue().commitment(0), first_counter(s));
    assert_eq(s.queue().tail(), 0);
    assert_eq(s.queue().state().outcome_slot, OUTCOME_SLOT);
}

// alice adds 5: the request queues the id over C; the round lands its new
// commitment, the total 5 under R1, and moves the head; alice opens [0, 5]
// from the outcome log, and the completed note [0, 5, request_id] is
// delivered to her PXE.
#[test]
unconstrained fn an_add_lands_and_tells_the_requester_the_total() {
    let s = setup();
    let id = add(s, s.alice, AMOUNT, RHO);
    assert_eq(s.queue().request_at(0), id);
    let o = add_round(s, s.alice, AMOUNT, 0, R0, R1);
    assert_eq(o.request_id, id);
    submit(s, o);
    assert_eq(s.queue().commitment(0), commitment(s.app.to_field(), s.key(), [AMOUNT], R1));
    assert_eq(s.queue().head().index, 1);
    assert_eq(s.queue().done_at(0), DONE_APPLIED);
    let outcome = opened_outcome();
    assert_eq(outcome, [0, AMOUNT]);
    let tx = last_tx();
    s.env.execute_utility(CounterTip::at(s.app).deliver_outcome(s.alice, RHO, outcome.concat([id]), tx));
}

// The landed add's result sent again, once a second add is queued: the head
// has moved past its request.
#[test(should_fail_with = "not the head")]
unconstrained fn a_replayed_result_is_refused() {
    let s = setup();
    let _ = add(s, s.alice, AMOUNT, RHO);
    let o = add_round(s, s.alice, AMOUNT, 0, R0, R1);
    submit(s, o);
    let _ = add(s, s.alice, 7, RHO + 1);
    submit(s, o);
}

// A request before the init round has landed is refused in its public half
// (pss_public_contract's `Queue::append_receipt`): there is no total to add to.
#[test(should_fail_with = "state not initialised")]
unconstrained fn an_add_before_the_init_is_refused() {
    let s = deploy();
    let _ = add(s, s.alice, AMOUNT, RHO);
}

// An amount that is no u64 is refused in the requester's PXE (the circuit's
// CODE_OVERFLOW, never queued).
#[test(should_fail_with = "invalid inputs")]
unconstrained fn an_amount_over_a_u64_is_refused() {
    let s = setup();
    let _ = add(s, s.alice, TWO_POW_64, RHO);
}
