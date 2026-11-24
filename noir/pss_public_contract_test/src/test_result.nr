//! The result transaction's TXE suite: `process_result` (the vk pin, the
//! binding, the three result signatures, a mixed result, a failed round's
//! state) and `apply` (the pinned read, the head, the slot, the write rule,
//! `ok = false`, `done[index]` and the sealed-thirds log) for requests of both
//! non-secret-shared intakes, which share one `process_result`, through the wrappers of
//! `PssPublicTest` around the chain-held bodies (`chain_state`), and the wide
//! shape under node-held state (`WideResult`: R = 2, W = 3, Q = 2, no thirds,
//! keys in different orders).
//!
//! The proof: recursive proof verification is a no-op during TXE witness
//! execution (as in examples/amm/contract/amm_test), so the staged capsule
//! carries a dummy vk ([7; 115] for the pool round's circuit, one for both
//! non-secret-shared intakes) whose hash the contract pins and a zero proof;
//! the vk pin in front of the verification runs for real, and so does
//! everything after it. The public-input layout the verifier receives is
//! checked by the library's own unit test (`result::test::public_input_orders`).
//!
//! The signatures are real: the nodes are testvectors/keys.json's, signing
//! with `pss_tip_test`'s signer (Schnorr in the encoding of noir-lang/schnorr
//! v0.4.0), so every signature the tests submit verifies in-circuit exactly
//! as a node's would (the machine's own signatures are checked against
//! `testvectors/results.json` and `tip_results.json` with the library's
//! functions by testvectors/noir/tip_result_vectors).
use pss_tip_test::shape::LogHead;
use crate::nodes::{NODE_SIG, receipts, sign_result, tip_config};
use crate::PssPublicTest;
use crate::PssPublicTest::{
    READ_BURN, READ_REVERT, REENTER_NONE, REENTER_PROPAGATE, REENTER_SWALLOW,
    REENTRANT_SKIP_L2_GAS,
};
use crate::rounds::{OraclePin, PoolResult, PoolThirds, WideResult};
use crate::test::{last_tx_summary, reader, Reader};
use aztec::protocol::abis::function_selector::FunctionSelector;
use aztec::protocol::address::AztecAddress;
use aztec::protocol::hash::{compute_log_tag, poseidon2_hash};
use aztec::protocol::traits::ToField;
use aztec::test::helpers::test_environment::TestEnvironment;
use aztec::test::helpers::txe_oracles;
use pss_public_contract::{
    chain_request_id, DONE_APPLIED, DONE_PENDING, DONE_SKIPPED, Head, inputs_hash, receipt_message,
    StaleBlocks,
};
use pss_public_contract::chain_state::{PSS_STATE, sealed_hashes};
use pss_public_contract::result::{
    DEFAULT_PINNED_READ_L2_GAS, machine_request_id, NodeHeld, result_message, ResultSignature,
    Sealing, TipResult,
};
use pss_tip_test::{dummy_vk, result_signatures, state_log_payload};

pub(crate) global STALE: u32 = 4;
pub(crate) global PRICE: Field = 1000;
// the request: two app inputs (as for amount_in, direction) and its nonce
pub(crate) global INPUTS_A: [Field; 2] = [500, 0];
pub(crate) global INPUTS_B: [Field; 2] = [700, 1];
pub(crate) global NONCE_A: Field = 0xa1;
pub(crate) global NONCE_B: Field = 0xb2;
// commitments: the slot starts at 0 (no init round here)
pub(crate) global C0: Field = 0;
pub(crate) global C1: Field = 0xc1;
pub(crate) global C2: Field = 0xc2;

// ---------------------------------------------------------------------------
// Setup
// ---------------------------------------------------------------------------

/// The selectors of the oracle's read targets.
unconstrained fn get_price() -> Field {
    let selector = comptime { FunctionSelector::from_signature("get_price()") };
    selector.to_field()
}

unconstrained fn get_none() -> Field {
    let selector = comptime { FunctionSelector::from_signature("get_none()") };
    selector.to_field()
}

unconstrained fn get_pair() -> Field {
    let selector = comptime { FunctionSelector::from_signature("get_pair()") };
    selector.to_field()
}

/// The L2 gas the swallowing re-entrancy test pins its read with: the
/// re-entrant `skip()`'s allotment and room for `get_price` to return.
global SWALLOWING_READ_L2_GAS: u32 = REENTRANT_SKIP_L2_GAS + 1000000;

pub struct Setup {
    pub(crate) env: TestEnvironment,
    pub(crate) deployer: AztecAddress,
    pub(crate) user: AztecAddress,
    pub(crate) relayer: AztecAddress,
    pub(crate) app: AztecAddress,
    pub(crate) oracle: AztecAddress,
    pub(crate) vk_hash: Field,
}

impl Setup {
    pub(crate) unconstrained fn queue(self) -> Reader {
        reader(self.env, self.app)
    }
}

/// Deploy the app and its oracle, `apply`'s pinned read going to `selector`
/// on the oracle with `l2_gas`.
unconstrained fn deploy_with(selector: Field, l2_gas: u32) -> Setup {
    let mut env = TestEnvironment::new();
    let deployer = env.create_light_account();
    let user = env.create_light_account();
    let relayer = env.create_light_account();
    let oracle = env.deploy("PssPublicTest").with_public_initializer(
        deployer,
        PssPublicTest::interface().constructor(tip_config(StaleBlocks::after(STALE)), 0, 0),
    );
    let vk_hash = poseidon2_hash(dummy_vk(7));
    let app = env.deploy("PssPublicTest").with_public_initializer(
        deployer,
        PssPublicTest::interface().constructor(tip_config(StaleBlocks::after(STALE)), vk_hash, 0),
    );
    env.call_public(
        deployer,
        PssPublicTest::at(app).set_oracle(OraclePin { target: oracle, selector, l2_gas }),
    );
    env.call_public(deployer, PssPublicTest::at(oracle).set_price(PRICE));
    Setup { env, deployer, user, relayer, app, oracle, vk_hash }
}

/// The app with its pinned read on `get_price()` under the default gas bound.
pub(crate) unconstrained fn setup() -> Setup {
    deploy_with(get_price(), DEFAULT_PINNED_READ_L2_GAS)
}

/// The chain request id of a request with these inputs, under either non-secret-shared
/// intake.
unconstrained fn request_id(s: Setup, inputs: [Field; 2], nonce: Field) -> Field {
    chain_request_id(s.app, s.vk_hash, inputs_hash(inputs), nonce)
}

/// Queue the user's request through the intake stand-in; returns its id.
pub(crate) unconstrained fn request(s: Setup, inputs: [Field; 2], nonce: Field) -> Field {
    let id = request_id(s, inputs, nonce);
    s.env.call_private(s.user, PssPublicTest::at(s.app).request(id));
    id
}

/// Node i's sealed third of the one chain-held output: [key id, ct…, tag],
/// five fields, distinct per node and per `round`.
unconstrained fn thirds(round: Field) -> PoolThirds {
    pss_tip_test::thirds(round)
}

/// A result as the tests build it: `PoolResult`'s fields, and the round's
/// sealed thirds, which the contract takes beside the result.
pub(crate) struct Round {
    pub(crate) request_id: Field,
    pub(crate) old_commitments: [Field; 1],
    pub(crate) new_commitments: [Field; 1],
    pub(crate) ok: bool,
    pub(crate) reads: [Field; 1],
    pub(crate) app_outputs: [Field; 2],
    pub(crate) sealed: PoolThirds,
}

impl Round {
    fn result(self) -> PoolResult {
        TipResult::new(
            self.request_id,
            self.old_commitments,
            self.new_commitments,
            self.ok,
            self.reads,
            self.app_outputs,
        )
    }
}

pub(crate) unconstrained fn result(
    request_id: Field,
    old_c: Field,
    new_c: Field,
    ok: bool,
    price: Field,
    round: Field,
) -> Round {
    Round {
        request_id,
        old_commitments: [old_c],
        new_commitments: [new_c],
        ok,
        reads: [price],
        app_outputs: [ok as Field, round * 7],
        sealed: thirds(round),
    }
}

/// The three nodes' signatures over a result, as the machine makes them:
/// node i signs poseidon2(RESULT_DOMAIN, namespace, machine request id, new
/// commitments, i, H(sealed_i)).
unconstrained fn signatures(s: Setup, r: Round) -> [ResultSignature; 3] {
    result_signatures(
        s.app.to_field(),
        r.request_id,
        r.old_commitments,
        r.reads,
        r.new_commitments,
        sealed_hashes(r.sealed),
    )
}

/// Stage the (vk, proof) capsule `process_result` loads, under the
/// relayer as scope.
unconstrained fn stage_proof(s: Setup, vk: [Field; 115]) {
    pss_tip_test::stage_proof(s.env, s.app, s.relayer, vk);
}

/// Submit a result as the relayer, with the capsule under `vk` and the given
/// signatures; returns the block it landed in. The result call carries no
/// app input or nonce under either non-secret-shared intake.
unconstrained fn submit_under(
    s: Setup,
    vk: [Field; 115],
    r: Round,
    sigs: [ResultSignature; 3],
) -> u32 {
    stage_proof(s, vk);
    s.env.call_private(
        s.relayer,
        PssPublicTest::at(s.app).process_result(r.result(), r.sealed, sigs),
    );
    s.env.last_block_number()
}

/// Submit a result under the pinned vk with the given signatures.
pub(crate) unconstrained fn submit_with(s: Setup, r: Round, sigs: [ResultSignature; 3]) -> u32 {
    submit_under(s, dummy_vk(7), r, sigs)
}

/// Submit a correctly signed result.
unconstrained fn submit(s: Setup, r: Round) -> u32 {
    submit_with(s, r, signatures(s, r))
}

pub(crate) unconstrained fn pool(s: Setup) -> Field {
    s.env.view_public(PssPublicTest::at(s.app).get_pool())
}

/// Probe `apply(r)` on the app from `prober` (the app itself for the
/// library's checks, the oracle instance for `#[only_self]`).
unconstrained fn try_apply(s: Setup, prober: AztecAddress, r: Round) -> bool {
    s.env.call_public(s.relayer, PssPublicTest::at(prober).try_apply(s.app, r.result(), r.sealed))
}

unconstrained fn try_skip(s: Setup) -> bool {
    s.env.call_public(s.relayer, PssPublicTest::at(s.app).try_skip(s.app))
}

/// Mine empty blocks until the next transaction lands in `block`.
pub(crate) unconstrained fn mine_until_next_block_is(s: Setup, block: u32) {
    pss_tip_test::mine_until_next_block_is(s.env, block);
}

/// The last transaction is an apply of `request_id` under chain-held state: its only
/// public log is the sealed-thirds log from the app (tag, new commitment,
/// three five-field thirds), and it has no other effect of its own: no
/// outcome event, no private log, no note, no message, no nullifier beyond
/// the transaction's own.
unconstrained fn assert_only_the_sealed_log(s: Setup, request_id: Field) {
    let effects = last_tx_summary(s.env, s.app);
    assert_eq(effects.public_logs, 1);
    assert_eq(
        effects.logs[0],
        LogHead { emitter: s.app, tag: compute_log_tag(request_id, PSS_STATE), length: 17 },
    );
    assert_eq(effects.private_logs, 0);
    assert_eq(effects.note_hashes, 0);
    assert_eq(effects.l2_to_l1_msgs, 0);
    assert_eq(effects.contract_class_logs, 0);
    assert_eq(effects.nullifiers, 1);
}

/// The sealed-thirds log the last transaction emitted under `tag`.
unconstrained fn last_tx_sealed_log(s: Setup, tag: Field) -> [Field; 16] {
    let tx_hash = txe_oracles::get_last_tx_effects().tx_hash;
    s.env.execute_utility(PssPublicTest::at(s.app).sealed_log(tx_hash, tag))
}

// ---------------------------------------------------------------------------
// process_result and apply: the accepted path
// ---------------------------------------------------------------------------

// A correctly signed result for the head lands: the slot takes the new
// commitment, the head moves to {1, the block}, done[0] = applied, the app
// hook stored the app outputs, and the queue behind it is untouched. In
// chain-held state apply emits the sealed thirds, tagged
// compute_log_tag(request_id, PSS_STATE) and emitted by the app contract:
// the new commitment, then node 0's, 1's and 2's third. That log is the
// result transaction's only effect: no outcome event. The next request's
// result reads the first's new commitment; with ok = false it is a no-op on
// the state that still finishes the request: the slot keeps its commitment,
// the head moves, done[index] = applied (not skipped), the hook stores the
// outputs and the thirds are still logged.
#[test]
unconstrained fn a_signed_result_applies_and_logs_its_thirds_and_an_ok_false_one_keeps_the_slot() {
    let s = setup();
    let id_a = request(s, INPUTS_A, NONCE_A);
    let id_b = request(s, INPUTS_B, NONCE_B);
    let block = submit(s, result(id_a, C0, C1, true, PRICE, 1));
    assert_eq(pool(s), C1);
    assert_eq(s.queue().head(), Head { index: 1, since: block });
    assert_eq(s.queue().done_at(0), DONE_APPLIED);
    assert_eq(s.queue().done_at(1), DONE_PENDING);
    assert_eq(s.queue().outcome_at(0), [1, 7]);
    assert_only_the_sealed_log(s, id_a);
    let log = last_tx_sealed_log(s, compute_log_tag(id_a, PSS_STATE));
    assert_eq(log, state_log_payload(C1, thirds(1)));

    // a total circuit's no-op: new_c = old_c
    let block = submit(s, result(id_b, C1, C1, false, PRICE, 2));
    assert_eq(pool(s), C1);
    assert_eq(s.queue().head(), Head { index: 2, since: block });
    assert_eq(s.queue().done_at(1), DONE_APPLIED);
    assert_eq(s.queue().outcome_at(1), [0, 14]);
    assert_only_the_sealed_log(s, id_b);
    let log = last_tx_sealed_log(s, compute_log_tag(id_b, PSS_STATE));
    assert_eq(log, state_log_payload(C1, thirds(2)));
}

// A failed round must keep its state: a result with ok = false that names
// another new commitment for the key it read is refused in process_result,
// so the slot (which apply would leave) and the sealed log (which would name
// the other commitment) never disagree.
#[test(should_fail_with = "a failed round changes its state")]
unconstrained fn a_failed_round_that_names_another_commitment_is_refused() {
    let s = setup();
    let id_a = request(s, INPUTS_A, NONCE_A);
    let _ = submit(s, result(id_a, C0, C1, false, PRICE, 1));
}

// ---------------------------------------------------------------------------
// process_result: each check
// ---------------------------------------------------------------------------

// The vk pin: a proof staged under any other vk is refused.
#[test(should_fail_with = "unexpected verification key")]
unconstrained fn a_proof_under_another_vk_is_refused() {
    let s = setup();
    let id_a = request(s, INPUTS_A, NONCE_A);
    let r = result(id_a, C0, C1, true, PRICE, 1);
    let _ = submit_under(s, [8; 115], r, signatures(s, r));
}

// The binding: the proof's request id, over the round's inputs and nonce,
// must be the queue's head. A result over other inputs than the request's
// is refused in apply (another nonce is another id alike: the id's
// derivation is the library's unit test, `intake::test`).
#[test(should_fail_with = "not the head")]
unconstrained fn a_result_with_other_inputs_than_the_request_is_refused() {
    let s = setup();
    let _ = request(s, INPUTS_A, NONCE_A);
    let _ = submit(
        s,
        result(request_id(s, INPUTS_B, NONCE_A), C0, C1, true, PRICE, 1),
    );
}

// A missing signature (all zero) is refused, naming the node.
#[test(should_fail_with = "node 0's result signature does not verify")]
unconstrained fn a_missing_signature_of_node_0_is_refused() {
    let s = setup();
    let id_a = request(s, INPUTS_A, NONCE_A);
    let r = result(id_a, C0, C1, true, PRICE, 1);
    let mut sigs = signatures(s, r);
    sigs[0] = [0; 4];
    let _ = submit_with(s, r, sigs);
}

// A wrong signature of each node is refused: node 0's tampered, node 1's
// moved into node 2's place, node 2's by node 0's key over node 2's message.
#[test(should_fail_with = "node 0's result signature does not verify")]
unconstrained fn a_tampered_signature_of_node_0_is_refused() {
    let s = setup();
    let id_a = request(s, INPUTS_A, NONCE_A);
    let r = result(id_a, C0, C1, true, PRICE, 1);
    let mut sigs = signatures(s, r);
    sigs[0][0] = sigs[0][0] + 1;
    let _ = submit_with(s, r, sigs);
}

#[test(should_fail_with = "node 1's result signature does not verify")]
unconstrained fn node_2s_signature_in_node_1s_place_is_refused() {
    let s = setup();
    let id_a = request(s, INPUTS_A, NONCE_A);
    let r = result(id_a, C0, C1, true, PRICE, 1);
    let mut sigs = signatures(s, r);
    sigs[1] = sigs[2];
    let _ = submit_with(s, r, sigs);
}

#[test(should_fail_with = "node 2's result signature does not verify")]
unconstrained fn a_signature_by_another_key_for_node_2_is_refused() {
    let s = setup();
    let id_a = request(s, INPUTS_A, NONCE_A);
    let r = result(id_a, C0, C1, true, PRICE, 1);
    let mut sigs = signatures(s, r);
    let machine_id = machine_request_id(r.request_id, r.old_commitments, r.reads);
    let message = result_message(
        s.app.to_field(),
        machine_id,
        r.new_commitments,
        2,
        sealed_hashes(r.sealed)[2],
    );
    sigs[2] = sign_result(NODE_SIG[0], message);
    let _ = submit_with(s, r, sigs);
}

// A mixed result: request A's proof values and signatures with request B's
// sealed thirds (B queued behind A, its round signed over the same old
// state). The thirds enter every node's message through H(sealed_i), so
// A's signatures refuse it.
#[test(should_fail_with = "node 0's result signature does not verify")]
unconstrained fn a_result_with_another_requests_sealed_thirds_is_refused() {
    let s = setup();
    let id_a = request(s, INPUTS_A, NONCE_A);
    let id_b = request(s, INPUTS_B, NONCE_B);
    let r_a = result(id_a, C0, C1, true, PRICE, 1);
    let r_b = result(id_b, C0, C2, true, PRICE, 2);
    let mut mixed = r_a;
    mixed.sealed = r_b.sealed;
    let _ = submit_with(s, mixed, signatures(s, r_a));
}

// The other mix: request A's proof values with request B's whole node
// answer (its thirds and its signatures). B's signatures cover B's machine
// request id and new commitment, not A's.
#[test(should_fail_with = "node 0's result signature does not verify")]
unconstrained fn a_result_with_another_requests_thirds_and_signatures_is_refused() {
    let s = setup();
    let id_a = request(s, INPUTS_A, NONCE_A);
    let id_b = request(s, INPUTS_B, NONCE_B);
    let r_b = result(id_b, C0, C2, true, PRICE, 2);
    let mut mixed = result(id_a, C0, C1, true, PRICE, 1);
    mixed.sealed = r_b.sealed;
    let _ = submit_with(s, mixed, signatures(s, r_b));
}

// The nodes signed the machine request id over the old commitment they
// read: a result signed for one state cannot be replayed against another.
#[test(should_fail_with = "node 0's result signature does not verify")]
unconstrained fn signatures_over_another_old_commitment_are_refused() {
    let s = setup();
    let id_a = request(s, INPUTS_A, NONCE_A);
    let sigs = signatures(s, result(id_a, C2, C1, true, PRICE, 1));
    let _ = submit_with(s, result(id_a, C0, C1, true, PRICE, 1), sigs);
}

// The nodes sign under the app's address as the namespace: a result they
// signed for another namespace (another deployment) is refused.
#[test(should_fail_with = "node 0's result signature does not verify")]
unconstrained fn signatures_under_another_namespace_are_refused() {
    let s = setup();
    let id_a = request(s, INPUTS_A, NONCE_A);
    let r = result(id_a, C0, C1, true, PRICE, 1);
    let sigs = result_signatures(
        s.app.to_field() + 1,
        r.request_id,
        r.old_commitments,
        r.reads,
        r.new_commitments,
        sealed_hashes(r.sealed),
    );
    let _ = submit_with(s, r, sigs);
}

// ---------------------------------------------------------------------------
// apply: each check
// ---------------------------------------------------------------------------

// A result for a request behind the head is refused and changes nothing.
#[test(should_fail_with = "not the head")]
unconstrained fn a_result_for_a_request_behind_the_head_is_refused() {
    let s = setup();
    let _ = request(s, INPUTS_A, NONCE_A);
    let id_b = request(s, INPUTS_B, NONCE_B);
    let r = result(id_b, C0, C1, true, PRICE, 1);
    s.queue().assert_refused_without_effect(|| try_apply(s, s.app, r));
    let _ = submit(s, r);
}

// The same result twice: the second finds the queue moved past it, and
// changes nothing (the slot keeps C1, request B stays the pending head).
#[test(should_fail_with = "not the head")]
unconstrained fn a_result_submitted_twice_is_refused_the_second_time() {
    let s = setup();
    let id_a = request(s, INPUTS_A, NONCE_A);
    let _ = request(s, INPUTS_B, NONCE_B);
    let r = result(id_a, C0, C1, true, PRICE, 1);
    let _ = submit(s, r);
    s.queue().assert_refused_without_effect(|| try_apply(s, s.app, r));
    assert_eq(s.queue().outcome_at(1), [0, 0]);
    let _ = submit(s, r);
}

// An applied request id stays seen: queuing it again is refused and
// changes nothing, so a request is never served twice.
#[test(should_fail_with = "duplicate request")]
unconstrained fn an_applied_request_cannot_be_queued_again() {
    let s = setup();
    let id_a = request(s, INPUTS_A, NONCE_A);
    let _ = submit(s, result(id_a, C0, C1, true, PRICE, 1));
    assert_eq(s.queue().done_at(0), DONE_APPLIED);
    assert(s.env.view_public(PssPublicTest::at(s.app).is_seen(id_a)));
    s.queue().assert_refused_without_effect(
        || s.env.call_public(s.user, PssPublicTest::at(s.app).try_append(s.app, id_a)),
    );
    let _ = request(s, INPUTS_A, NONCE_A);
}

// A result for a request that was never queued, on an empty queue.
#[test(should_fail_with = "queue is empty")]
unconstrained fn a_result_on_an_empty_queue_is_refused() {
    let s = setup();
    let id_a = request_id(s, INPUTS_A, NONCE_A);
    let r = result(id_a, C0, C1, true, PRICE, 1);
    s.queue().assert_refused_without_effect(|| try_apply(s, s.app, r));
    let _ = submit(s, r);
}

// A moved slot: the state changed since the round read it (here: request
// A's result landed first, and request B's round read the old state).
#[test(should_fail_with = "state moved")]
unconstrained fn a_result_over_a_moved_slot_is_refused() {
    let s = setup();
    let id_a = request(s, INPUTS_A, NONCE_A);
    let id_b = request(s, INPUTS_B, NONCE_B);
    let _ = submit(s, result(id_a, C0, C1, true, PRICE, 1));
    let r = result(id_b, C0, C2, true, PRICE, 2);
    s.queue().assert_refused_without_effect(|| try_apply(s, s.app, r));
    let _ = submit(s, r);
}

// A moved slot under ok = false: a no-op round over the state it read
// (new = old) is refused as a write would be, so a no-op never finishes a
// request against a state it did not read.
#[test(should_fail_with = "state moved")]
unconstrained fn an_ok_false_result_over_a_moved_slot_is_refused() {
    let s = setup();
    let id_a = request(s, INPUTS_A, NONCE_A);
    let id_b = request(s, INPUTS_B, NONCE_B);
    let _ = submit(s, result(id_a, C0, C1, true, PRICE, 1));
    let r = result(id_b, C0, C0, false, PRICE, 2);
    s.queue().assert_refused_without_effect(|| try_apply(s, s.app, r));
    let _ = submit(s, r);
}

// A changed pinned read: the oracle's value moved between the round and
// the result, so apply's nested static call returns another value.
#[test(should_fail_with = "pinned read changed")]
unconstrained fn a_result_over_a_changed_pinned_read_is_refused() {
    let s = setup();
    let id_a = request(s, INPUTS_A, NONCE_A);
    s.env.call_public(s.deployer, PssPublicTest::at(s.oracle).set_price(PRICE + 1));
    let r = result(id_a, C0, C1, true, PRICE, 1);
    s.queue().assert_refused_without_effect(|| try_apply(s, s.app, r));
    let _ = submit(s, r);
}

// The pinned value moved: a round redone at the new value applies.
#[test]
unconstrained fn a_round_redone_at_the_new_pinned_value_applies() {
    let s = setup();
    let id_a = request(s, INPUTS_A, NONCE_A);
    s.env.call_public(s.deployer, PssPublicTest::at(s.oracle).set_price(PRICE + 1));
    // the round is redone at the new price
    let block = submit(s, result(id_a, C0, C1, true, PRICE + 1, 1));
    assert_eq(pool(s), C1);
    assert_eq(s.queue().head(), Head { index: 1, since: block });
}

// apply is #[only_self]: nobody calls it without process_result, from an
// account or from another contract (here the oracle instance), and the
// attempt changes nothing.
#[test(should_fail_with = "Function apply can only be called by the same contract")]
unconstrained fn apply_from_outside_the_contract_is_refused() {
    let s = setup();
    let id_a = request(s, INPUTS_A, NONCE_A);
    let r = result(id_a, C0, C1, true, PRICE, 1);
    s.queue().assert_refused_without_effect(|| try_apply(s, s.oracle, r));
    s.env.call_public(s.relayer, PssPublicTest::at(s.app).apply(r.result(), r.sealed));
}

// ---------------------------------------------------------------------------
// apply and skip() together
// ---------------------------------------------------------------------------

// apply restarts the head clock: the next head waits a full stale period
// from the apply, not from its own request. One block short a skip is
// refused without effect; at the period it lands, and the applied request
// stays applied.
#[test]
unconstrained fn after_an_apply_the_next_head_waits_a_full_stale_period() {
    let s = setup();
    let id_a = request(s, INPUTS_A, NONCE_A);
    let _ = request(s, INPUTS_B, NONCE_B);
    // B has sat in the queue for longer than the period before A applies
    mine_until_next_block_is(s, s.env.next_block_number() + STALE);
    let block = submit(s, result(id_a, C0, C1, true, PRICE, 1));
    assert_eq(s.queue().head(), Head { index: 1, since: block });

    mine_until_next_block_is(s, block + STALE - 1);
    s.queue().assert_refused_without_effect(|| try_skip(s));
    assert(try_skip(s));
    assert_eq(s.queue().head(), Head { index: 2, since: block + STALE });
    assert_eq(s.queue().done_at(0), DONE_APPLIED);
    assert_eq(s.queue().done_at(1), DONE_SKIPPED);
    assert_eq(pool(s), C1);
}

// Re-entrancy, propagating mock. The oracle `apply` reads is a mock whose
// get_price() calls skip() on the app (aztec-nr's call, which rethrows),
// while the head is stale, so skip() itself would be allowed. apply makes
// the pinned read as a static call, so the nested skip() is static too and
// the AVM refuses its storage write: the read reverts, apply reverts, and
// the queue and the slot are unchanged (done[0] still pending; the probe
// gives apply bounded gas, since the refused write's exceptional halt
// consumes everything below it, and reports the revert). A direct
// skip() then lands, so the static-call rule, not staleness, refused the
// re-entrant one; A's result is then refused (A is no longer the head) and
// B's lands over the untouched state: A is skipped and never applied, B is
// applied and never skipped, and the head moved one step each time.
#[test]
unconstrained fn a_reentrant_skip_from_a_pinned_read_reverts_the_apply() {
    let s = setup();
    let id_a = request(s, INPUTS_A, NONCE_A);
    let id_b = request(s, INPUTS_B, NONCE_B);
    let since_a = s.queue().head().since;
    mine_until_next_block_is(s, since_a + STALE);
    s.env.call_public(s.deployer, PssPublicTest::at(s.oracle).set_reentry(s.app, REENTER_PROPAGATE));

    let r_a = result(id_a, C0, C1, true, PRICE, 1);
    s.queue().assert_refused_without_effect(|| try_apply(s, s.app, r_a));
    assert_eq(s.queue().head(), Head { index: 0, since: since_a });
    assert_eq(s.queue().done_at(0), DONE_PENDING);

    let block_skip = skip_as(s, s.user);
    assert_eq(s.queue().head(), Head { index: 1, since: block_skip });
    assert_eq(s.queue().done_at(0), DONE_SKIPPED);

    s.env.call_public(s.deployer, PssPublicTest::at(s.oracle).set_reentry(s.app, REENTER_NONE));
    s.queue().assert_refused_without_effect(|| try_apply(s, s.app, r_a));
    // B's round read the state A never changed
    assert(try_apply(s, s.app, result(id_b, C0, C2, true, PRICE, 2)));
    assert_eq(s.queue().head().index, 2);
    assert_eq(s.queue().done_at(0), DONE_SKIPPED);
    assert_eq(s.queue().done_at(1), DONE_APPLIED);
    assert_eq(pool(s), C2);
    assert_eq(s.queue().outcome_at(0), [0, 0]);
    assert_eq(s.queue().outcome_at(1), [1, 14]);
}

// The same through the result transaction: process_result enqueues apply,
// the AVM refuses the re-entrant skip()'s storage write inside the static
// pinned read, and the whole app-logic phase reverts with it.
#[test(should_fail_with = "Static call cannot update the state")]
unconstrained fn a_reentrant_skip_reverts_the_result_transaction() {
    let s = setup();
    let id_a = request(s, INPUTS_A, NONCE_A);
    mine_until_next_block_is(s, s.queue().head().since + STALE);
    s.env.call_public(s.deployer, PssPublicTest::at(s.oracle).set_reentry(s.app, REENTER_PROPAGATE));
    let _ = submit(s, result(id_a, C0, C1, true, PRICE, 1));
}

// Re-entrancy, swallowing mock: get_price() attempts skip() on the app,
// ignores its revert, and returns PRICE only if the skip did nothing (PRICE
// + 1 if it landed). The result, signed at PRICE, applies: so the static
// skip() was a no-op, and the head moved by exactly one step, to A's
// successor, with done[0] = applied and request B still pending.
#[test]
unconstrained fn a_reentrant_skip_whose_revert_is_swallowed_is_a_no_op() {
    // the read carries the re-entrant skip's allotment, so it is pinned with
    // more gas than the default bound
    let s = deploy_with(get_price(), SWALLOWING_READ_L2_GAS);
    let id_a = request(s, INPUTS_A, NONCE_A);
    let _ = request(s, INPUTS_B, NONCE_B);
    mine_until_next_block_is(s, s.queue().head().since + STALE);
    s.env.call_public(s.deployer, PssPublicTest::at(s.oracle).set_reentry(s.app, REENTER_SWALLOW));

    let block = submit(s, result(id_a, C0, C1, true, PRICE, 1));
    assert_eq(s.queue().head(), Head { index: 1, since: block });
    assert_eq(s.queue().tail(), 2);
    assert_eq(s.queue().done_at(0), DONE_APPLIED);
    assert_eq(s.queue().done_at(1), DONE_PENDING);
    assert_eq(pool(s), C1);
    assert_only_the_sealed_log(s, id_a);
}

/// Call `skip()` on the app as `from`; returns the block it landed in.
unconstrained fn skip_as(s: Setup, from: AztecAddress) -> u32 {
    s.env.call_public(from, PssPublicTest::at(s.app).skip());
    s.env.last_block_number()
}

// ---------------------------------------------------------------------------
// Receipt intake: the same process_result
// ---------------------------------------------------------------------------

/// Queue the user's request through the receipt intake function, with the
/// three node receipts over it; returns its id.
unconstrained fn request_with_receipts(s: Setup, inputs: [Field; 2], nonce: Field) -> Field {
    let id = request_id(s, inputs, nonce);
    let expiry = s.env.next_block_number() + 10;
    let r = receipts(receipt_message(id, inputs_hash(inputs), expiry));
    s.env.call_private(
        s.user,
        PssPublicTest::at(s.app).request_with_receipts(inputs, nonce, expiry, r),
    );
    id
}

// Requests of both non-secret-shared intakes answered end to end: the user
// queues one with three receipts (only its id reaches the chain) and one
// on chain, side by side; the relayer lands each result, whose proof outputs
// the id, through the one `process_result` under the round's one vk, in
// queue order: the slot, the head, done, the hook and the sealed-thirds log
// all follow.
#[test]
unconstrained fn requests_of_both_plain_intakes_are_answered_in_queue_order() {
    let s = setup();
    let id_a = request_with_receipts(s, INPUTS_A, NONCE_A);
    assert_eq(s.env.view_public(PssPublicTest::at(s.app).request_at(0)), id_a);
    s.env.call_private(s.user, PssPublicTest::at(s.app).request_onchain(INPUTS_B, NONCE_B));
    let id_b = request_id(s, INPUTS_B, NONCE_B);
    assert_eq(s.env.view_public(PssPublicTest::at(s.app).request_at(1)), id_b);

    let block = submit(s, result(id_a, C0, C1, true, PRICE, 1));
    assert_eq(pool(s), C1);
    assert_eq(s.queue().head(), Head { index: 1, since: block });
    assert_eq(s.queue().done_at(0), DONE_APPLIED);
    assert_eq(s.queue().outcome_at(0), [1, 7]);
    assert_only_the_sealed_log(s, id_a);

    let block = submit(s, result(id_b, C1, C2, true, PRICE, 2));
    assert_eq(pool(s), C2);
    assert_eq(s.queue().head(), Head { index: 2, since: block });
    assert_eq(s.queue().done_at(1), DONE_APPLIED);
    assert_eq(s.queue().outcome_at(1), [1, 14]);
    assert_only_the_sealed_log(s, id_b);
}

// One round, one request id: the same inputs and nonce give the same id
// under both non-secret-shared intakes, so a request queued by one is a duplicate for
// the other.
#[test(should_fail_with = "duplicate request")]
unconstrained fn the_same_request_under_the_other_intake_is_a_duplicate() {
    let s = setup();
    let _ = request_with_receipts(s, INPUTS_A, NONCE_A);
    s.env.call_private(s.user, PssPublicTest::at(s.app).request_onchain(INPUTS_A, NONCE_A));
}

// ---------------------------------------------------------------------------
// The pinned read's failures
// ---------------------------------------------------------------------------

// A read target that reverts fails the apply, which changes nothing, and
// the whole result transaction with it; the head then waits for skip().
#[test(should_fail_with = "the oracle reverts")]
unconstrained fn a_pinned_read_that_reverts_is_refused() {
    let s = setup();
    let id_a = request(s, INPUTS_A, NONCE_A);
    s.env.call_public(s.deployer, PssPublicTest::at(s.oracle).set_reentry(s.app, READ_REVERT));
    let r = result(id_a, C0, C1, true, PRICE, 1);
    s.queue().assert_refused_without_effect(|| try_apply(s, s.app, r));
    let _ = submit(s, r);
}

// A read target must return exactly one field: none is refused...
#[test(should_fail_with = "pinned read returns one field")]
unconstrained fn a_pinned_read_that_returns_no_field_is_refused() {
    let s = deploy_with(get_none(), DEFAULT_PINNED_READ_L2_GAS);
    let id_a = request(s, INPUTS_A, NONCE_A);
    let r = result(id_a, C0, C1, true, PRICE, 1);
    s.queue().assert_refused_without_effect(|| try_apply(s, s.app, r));
    let _ = submit(s, r);
}

// ...and so are two.
#[test(should_fail_with = "pinned read returns one field")]
unconstrained fn a_pinned_read_that_returns_two_fields_is_refused() {
    let s = deploy_with(get_pair(), DEFAULT_PINNED_READ_L2_GAS);
    let id_a = request(s, INPUTS_A, NONCE_A);
    let r = result(id_a, C0, C1, true, PRICE, 1);
    s.queue().assert_refused_without_effect(|| try_apply(s, s.app, r));
    let _ = submit(s, r);
}

// A read target that burns all the gas it gets (here: more than any
// allotment) halts exceptionally inside its bounded allotment: the apply is
// refused without effect, the probe that made it still returns, and the
// head, which no result can land for, is skipped after the stale period.
#[test]
unconstrained fn a_pinned_read_that_burns_its_gas_is_refused_and_the_head_is_skipped() {
    let s = setup();
    let id_a = request(s, INPUTS_A, NONCE_A);
    let since = s.queue().head().since;
    s.env.call_public(s.deployer, PssPublicTest::at(s.oracle).set_reentry(s.app, READ_BURN));
    s.env.call_public(s.deployer, PssPublicTest::at(s.oracle).set_burn(0xffffffff));
    let r = result(id_a, C0, C1, true, PRICE, 1);
    s.queue().assert_refused_without_effect(|| try_apply(s, s.app, r));
    mine_until_next_block_is(s, since + STALE);
    assert(try_skip(s));
    assert_eq(s.queue().done_at(0), DONE_SKIPPED);
    assert_eq(pool(s), C0);
}

// The bound is applied: a read that needs twice the default gas fails
// under the default bound (a probe gives apply far more than that)...
#[test]
unconstrained fn a_pinned_read_costing_more_than_its_bound_is_refused() {
    let s = setup();
    let id_a = request(s, INPUTS_A, NONCE_A);
    s.env.call_public(s.deployer, PssPublicTest::at(s.oracle).set_reentry(s.app, READ_BURN));
    s.env.call_public(
        s.deployer,
        PssPublicTest::at(s.oracle).set_burn(2 * DEFAULT_PINNED_READ_L2_GAS),
    );
    let r = result(id_a, C0, C1, true, PRICE, 1);
    s.queue().assert_refused_without_effect(|| try_apply(s, s.app, r));
    assert_eq(s.queue().done_at(0), DONE_PENDING);
}

// ...and lands when the app pins it with a larger bound.
#[test]
unconstrained fn the_same_read_lands_under_a_larger_bound() {
    let s = deploy_with(get_price(), 4 * DEFAULT_PINNED_READ_L2_GAS);
    let id_a = request(s, INPUTS_A, NONCE_A);
    s.env.call_public(s.deployer, PssPublicTest::at(s.oracle).set_reentry(s.app, READ_BURN));
    s.env.call_public(
        s.deployer,
        PssPublicTest::at(s.oracle).set_burn(2 * DEFAULT_PINNED_READ_L2_GAS),
    );
    let _ = submit(s, result(id_a, C0, C1, true, PRICE, 1));
    assert_eq(pool(s), C1);
    assert_eq(s.queue().done_at(0), DONE_APPLIED);
}

// ---------------------------------------------------------------------------
// The wide shape: reads [book, pool], writes [pool, book, fresh], two pinned
// reads (get_value(1), get_value(2)), node-held state (no thirds)
// ---------------------------------------------------------------------------

global P1: Field = 0x5a1;
global B1: Field = 0xb01;
global F1: Field = 0xf01;
global P2: Field = 0x5a2;
global B2: Field = 0xb02;
global F2: Field = 0xf02;
// the two pinned values: get_value(k) = PRICE + k
global READS: [Field; 2] = [PRICE + 1, PRICE + 2];

unconstrained fn wide(
    request_id: Field,
    old: [Field; 2],
    new: [Field; 3],
    ok: bool,
    reads: [Field; 2],
) -> WideResult {
    TipResult::new(request_id, old, new, ok, reads, [ok as Field])
}

unconstrained fn wide_signatures(s: Setup, w: WideResult) -> [ResultSignature; 3] {
    result_signatures(
        s.app.to_field(),
        w.request_id,
        w.old_commitments,
        w.reads(),
        w.new_commitments,
        NodeHeld {}.sealed_hashes(),
    )
}

unconstrained fn submit_wide(s: Setup, w: WideResult) -> u32 {
    stage_proof(s, dummy_vk(7));
    s.env.call_private(
        s.relayer,
        PssPublicTest::at(s.app).process_result_wide(w, wide_signatures(s, w)),
    );
    s.env.last_block_number()
}

unconstrained fn try_apply_wide(s: Setup, w: WideResult) -> bool {
    s.env.call_public(s.relayer, PssPublicTest::at(s.app).try_apply_wide(s.app, w))
}

unconstrained fn slots(s: Setup) -> [Field; 3] {
    let at = PssPublicTest::at(s.app);
    [
        s.env.view_public(at.get_pool()),
        s.env.view_public(at.get_book()),
        s.env.view_public(at.get_fresh()),
    ]
}

/// Land the first wide round: every key empty, then [P1, B1, F1].
unconstrained fn first_wide_round(s: Setup) -> Field {
    let id_a = request(s, INPUTS_A, NONCE_A);
    let _ = submit_wide(s, wide(id_a, [0, 0], [P1, B1, F1], true, READS));
    id_a
}

// A failed round keeps every key it writes: pool and book, read, keep their
// commitments, matched by key across the two orders; `fresh`, a create,
// keeps the empty slot's value, 0. It lands as a no-op and apply writes
// nothing. The next round lands key by key in manifest order: old
// commitments in the read order [book, pool], new ones in the write order
// [pool, book, fresh] (creating `fresh`), the pinned values in read order;
// under node-held state the transaction emits no log.
#[test]
unconstrained fn a_failed_wide_round_outputs_0_for_a_created_key_and_the_next_lands_each_key_in_order() {
    let s = setup();
    let id_a = request(s, INPUTS_A, NONCE_A);
    let _ = submit_wide(s, wide(id_a, [0, 0], [0, 0, 0], false, READS));
    assert_eq(slots(s), [0, 0, 0]);
    assert_eq(s.queue().done_at(0), DONE_APPLIED);
    assert_eq(s.queue().outcome_at(0), [0, 0]);

    let id_b = request(s, INPUTS_B, NONCE_B);
    let _ = submit_wide(s, wide(id_b, [0, 0], [P1, B1, F1], true, READS));
    assert_eq(slots(s), [P1, B1, F1]);
    assert_eq(last_tx_summary(s.env, s.app).public_logs, 0);
    assert_eq(s.queue().outcome_at(1), [1, 0]);
}

// The write rule holds on not ok too: once `fresh` holds state, a failed
// round that writes it without reading it (outputting 0 for it) is refused,
// since the slot does not hold the 0 the round names.
#[test(should_fail_with = "write to a live key the round did not read")]
unconstrained fn a_failed_round_over_a_live_key_it_did_not_read_is_refused() {
    let s = setup();
    let _ = first_wide_round(s);
    let id_b = request(s, INPUTS_B, NONCE_B);
    let w = wide(id_b, [B1, P1], [P1, B1, 0], false, READS);
    s.queue().assert_refused_without_effect(|| try_apply_wide(s, w));
    assert_eq(slots(s), [P1, B1, F1]);
    let _ = submit_wide(s, w);
}

// The pinned values are compared in read order: the same values swapped
// (signed as such) are refused.
#[test(should_fail_with = "pinned read changed")]
unconstrained fn a_wide_round_with_its_pinned_values_swapped_is_refused() {
    let s = setup();
    let id_a = request(s, INPUTS_A, NONCE_A);
    let w = wide(id_a, [0, 0], [P1, B1, F1], true, [READS[1], READS[0]]);
    s.queue().assert_refused_without_effect(|| try_apply_wide(s, w));
    let _ = submit_wide(s, w);
}

// The old commitments follow the read order [book, pool]: the same two in
// the write order are refused as a moved state.
#[test(should_fail_with = "state moved")]
unconstrained fn a_wide_round_with_its_old_commitments_out_of_order_is_refused() {
    let s = setup();
    let _ = first_wide_round(s);
    let id_b = request(s, INPUTS_B, NONCE_B);
    let w = wide(id_b, [P1, B1], [P2, B2, 0], true, READS);
    s.queue().assert_refused_without_effect(|| try_apply_wide(s, w));
    assert_eq(slots(s), [P1, B1, F1]);
    let _ = submit_wide(s, w);
}

// The write rule: a key the round writes without reading it is a create,
// so once `fresh` holds state an ok round that writes it again is refused,
// and the state it holds survives.
#[test(should_fail_with = "write to a live key the round did not read")]
unconstrained fn a_round_that_overwrites_a_live_key_it_did_not_read_is_refused() {
    let s = setup();
    let _ = first_wide_round(s);
    let id_b = request(s, INPUTS_B, NONCE_B);
    let w = wide(id_b, [B1, P1], [P2, B2, F2], true, READS);
    s.queue().assert_refused_without_effect(|| try_apply_wide(s, w));
    assert_eq(slots(s), [P1, B1, F1]);
    let _ = submit_wide(s, w);
}
