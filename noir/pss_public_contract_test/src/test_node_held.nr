//! Node-held state through the library's shared bricks: the init round
//! (`init::process_init`, `init::apply_init`) and a round queued by receipt
//! intake (`check_round`, `apply_round` with no pinned read), both with
//! `NodeHeld {}`, over the `held` key of `PssPublicTest`.
//!
//! Under node-held state each node's result message ends in `H(sealed_i)` =
//! 0, so a result signed over the hashes of any thirds is refused, and
//! neither apply logs anything: the init and each result write their
//! commitments and leave no public log, private log, note or message.
//!
//! The proof is the suite's dummy capsule, as in `test_result.nr`: a vk of
//! eights for the init circuit and of nines for the held round's circuit,
//! whose hashes the contract pins (the held round's for both its request
//! functions and `process_result_held`).
use crate::nodes::{receipts, tip_config};
use crate::PssPublicTest;
use crate::rounds::{HELD_INIT_INPUTS, HeldResult};
use crate::test::{last_tx_summary, reader, Reader};
use aztec::protocol::address::AztecAddress;
use aztec::protocol::hash::poseidon2_hash;
use aztec::protocol::traits::ToField;
use aztec::test::helpers::test_environment::TestEnvironment;
use pss_public_contract::{
    chain_request_id, DONE_APPLIED, Head, inputs_hash, receipt_message, StaleBlocks,
};
use pss_public_contract::chain_state::sealed_hashes;
use pss_public_contract::init::init_request_id;
use pss_public_contract::result::{NodeHeld, ResultSignature, Sealing, TipResult};
use pss_tip_test::{dummy_vk, result_signatures, stage_proof, thirds};

global STALE: u32 = 4;
global INPUTS_A: [Field; 2] = [500, 0];
global INPUTS_B: [Field; 2] = [700, 1];
global NONCE_A: Field = 0xa1;
global NONCE_B: Field = 0xb2;
// the held key's commitments: the init's, then a landed round's, then one
// the refusals name
global H0: Field = 0x4e0;
global H1: Field = 0x4e1;
global H2: Field = 0x4e2;

struct Setup {
    env: TestEnvironment,
    user: AztecAddress,
    relayer: AztecAddress,
    app: AztecAddress,
    init_vk_hash: Field,
    held_vk_hash: Field,
}

impl Setup {
    unconstrained fn queue(self) -> Reader {
        reader(self.env, self.app)
    }
}

unconstrained fn init_vk() -> [Field; 115] {
    dummy_vk(8)
}

unconstrained fn held_vk() -> [Field; 115] {
    dummy_vk(9)
}

/// Deploy the app with the held round's circuit (for both its pool and its
/// held vk pins) and the init circuit pinned to the dummy vks; the held key
/// starts empty.
unconstrained fn setup() -> Setup {
    let mut env = TestEnvironment::new();
    let deployer = env.create_light_account();
    let user = env.create_light_account();
    let relayer = env.create_light_account();
    let held_vk_hash = poseidon2_hash(held_vk());
    let init_vk_hash = poseidon2_hash(init_vk());
    let app = env.deploy("PssPublicTest").with_public_initializer(
        deployer,
        PssPublicTest::interface().constructor(
            tip_config(StaleBlocks::after(STALE)),
            held_vk_hash,
            held_vk_hash,
        ),
    );
    env.call_public(deployer, PssPublicTest::at(app).set_init_vk_hash(init_vk_hash));
    Setup { env, user, relayer, app, init_vk_hash, held_vk_hash }
}

unconstrained fn held(s: Setup) -> Field {
    s.env.view_public(PssPublicTest::at(s.app).get_held())
}

/// The last transaction left no side effect of its own beyond its writes:
/// no public log (no sealed-thirds log, no event), no private log, no note,
/// no message, no nullifier beyond the transaction's own.
unconstrained fn assert_nothing_logged(s: Setup) {
    let effects = last_tx_summary(s.env, s.app);
    assert_eq(effects.public_logs, 0);
    assert_eq(effects.private_logs, 0);
    assert_eq(effects.note_hashes, 0);
    assert_eq(effects.l2_to_l1_msgs, 0);
    assert_eq(effects.contract_class_logs, 0);
    assert_eq(effects.nullifiers, 1);
}

// ---------------------------------------------------------------------------
// The init round
// ---------------------------------------------------------------------------

/// The init request id: the init inputs, the zero address, nonce 0, under
/// the init vk hash.
unconstrained fn init_id(s: Setup) -> Field {
    init_request_id(s.app, s.init_vk_hash, HELD_INIT_INPUTS)
}

/// The nodes' signatures over the init result `new_c` under node-held state:
/// every old commitment 0, no pinned read, `H(sealed_i)` = 0.
unconstrained fn init_signatures(s: Setup, new_c: Field) -> [ResultSignature; 3] {
    result_signatures(s.app.to_field(), init_id(s), [0], [], [new_c], NodeHeld {}.sealed_hashes())
}

unconstrained fn init_with(s: Setup, vk: [Field; 115], new_c: Field, sigs: [ResultSignature; 3]) {
    stage_proof(s.env, s.app, s.relayer, vk);
    s.env.call_private(s.relayer, PssPublicTest::at(s.app).init_held(new_c, sigs));
}

unconstrained fn init(s: Setup, new_c: Field) {
    init_with(s, init_vk(), new_c, init_signatures(s, new_c));
}

// The init writes the first commitment, logs nothing and touches no queue
// storage. It lands only through its own private function: a probe of
// apply_init_held after the init is refused and the slot keeps its value.
// (The init request id's derivation is the library's unit test,
// `init::test`.)
#[test]
unconstrained fn the_init_writes_the_first_commitment_logs_nothing_and_lands_once() {
    let s = setup();
    init(s, H0);
    assert_eq(held(s), H0);
    assert_nothing_logged(s);
    assert_eq(s.queue().head(), Head { index: 0, since: 0 });
    assert_eq(s.queue().tail(), 0);
    assert(!s.env.call_public(s.relayer, PssPublicTest::at(s.app).try_apply_init_held(s.app, init_id(s), H1)));
    assert_eq(held(s), H0);
}

#[test(should_fail_with = "already initialised")]
unconstrained fn a_second_init_is_refused() {
    let s = setup();
    init(s, H0);
    init(s, H1);
}

// Anyone may land the init, but only its own function's apply writes the
// slot: apply_init_held is #[only_self].
#[test(should_fail_with = "Function apply_init_held can only be called by the same contract")]
unconstrained fn apply_init_from_outside_the_contract_is_refused() {
    let s = setup();
    s.env.call_public(s.user, PssPublicTest::at(s.app).apply_init_held(init_id(s), H0));
}

#[test(should_fail_with = "zero commitment")]
unconstrained fn an_init_of_commitment_0_is_refused() {
    let s = setup();
    init(s, 0);
}

#[test(should_fail_with = "unexpected verification key")]
unconstrained fn an_init_proved_under_another_vk_is_refused() {
    let s = setup();
    init_with(s, held_vk(), H0, init_signatures(s, H0));
}

#[test(should_fail_with = "node 1's result signature does not verify")]
unconstrained fn an_init_missing_a_signature_is_refused() {
    let s = setup();
    let mut sigs = init_signatures(s, H0);
    sigs[1] = [0; 4];
    init_with(s, init_vk(), H0, sigs);
}

// The nodes sign the init under node-held state with H(sealed_i) = 0:
// signatures over the hashes of sealed thirds are refused.
#[test(should_fail_with = "node 0's result signature does not verify")]
unconstrained fn an_init_signed_over_sealed_thirds_is_refused() {
    let s = setup();
    let sigs = result_signatures(s.app.to_field(), init_id(s), [0], [], [H0], sealed_hashes(thirds::<5>(1)));
    init_with(s, init_vk(), H0, sigs);
}

// Signatures over another init request id (other init inputs) are refused.
#[test(should_fail_with = "node 0's result signature does not verify")]
unconstrained fn an_init_signed_for_other_inputs_is_refused() {
    let s = setup();
    let other = init_request_id(s.app, s.init_vk_hash, [HELD_INIT_INPUTS[0] + 1]);
    let sigs = result_signatures(s.app.to_field(), other, [0], [], [H0], NodeHeld {}.sealed_hashes());
    init_with(s, init_vk(), H0, sigs);
}

// ---------------------------------------------------------------------------
// A round queued by receipt intake under node-held state
// ---------------------------------------------------------------------------

/// Queue the user's request through receipt intake; returns its id.
unconstrained fn request(s: Setup, inputs: [Field; 2], nonce: Field) -> Field {
    let id = chain_request_id(s.app, s.held_vk_hash, inputs_hash(inputs), nonce);
    let expiry = s.env.next_block_number() + 10;
    let r = receipts(receipt_message(id, inputs_hash(inputs), expiry));
    s.env.call_private(
        s.user,
        PssPublicTest::at(s.app).request_with_receipts(inputs, nonce, expiry, r),
    );
    id
}

unconstrained fn result(request_id: Field, old_c: Field, new_c: Field, ok: bool) -> HeldResult {
    TipResult::new(request_id, [old_c], [new_c], ok, [], [ok as Field, new_c])
}

/// The nodes' signatures over a result under node-held state: H(sealed_i) = 0.
unconstrained fn signatures(s: Setup, r: HeldResult) -> [ResultSignature; 3] {
    result_signatures(
        s.app.to_field(),
        r.request_id,
        r.old_commitments,
        [],
        r.new_commitments,
        NodeHeld {}.sealed_hashes(),
    )
}

/// Submit the held round's result as the relayer; returns its block.
unconstrained fn submit_with(s: Setup, r: HeldResult, sigs: [ResultSignature; 3]) -> u32 {
    stage_proof(s.env, s.app, s.relayer, held_vk());
    s.env.call_private(s.relayer, PssPublicTest::at(s.app).process_result_held(r, sigs));
    s.env.last_block_number()
}

unconstrained fn submit(s: Setup, r: HeldResult) -> u32 {
    submit_with(s, r, signatures(s, r))
}

// A result signed over H(sealed_i) = 0 lands: the slot takes the new
// commitment, the head moves, done[0] = applied, the hook stores the
// outputs, and the apply logs nothing. The next round, read at that
// commitment, fails (ok = false): the slot keeps its commitment, the head
// moves, nothing is logged.
#[test]
unconstrained fn a_result_signed_with_no_sealed_thirds_lands_and_a_failed_one_moves_the_head() {
    let s = setup();
    init(s, H0);
    let id_a = request(s, INPUTS_A, NONCE_A);
    let id_b = request(s, INPUTS_B, NONCE_B);
    let block = submit(s, result(id_a, H0, H1, true));
    assert_eq(held(s), H1);
    assert_eq(s.queue().head(), Head { index: 1, since: block });
    assert_eq(s.env.view_public(PssPublicTest::at(s.app).done_at(0)), DONE_APPLIED);
    assert_eq(s.queue().outcome_at(0), [1, H1]);
    assert_nothing_logged(s);

    let block = submit(s, result(id_b, H1, H1, false));
    assert_eq(held(s), H1);
    assert_eq(s.queue().head(), Head { index: 2, since: block });
    assert_eq(s.env.view_public(PssPublicTest::at(s.app).done_at(1)), DONE_APPLIED);
    assert_eq(s.queue().outcome_at(1), [0, H1]);
    assert_nothing_logged(s);
}

// Signatures over the hashes of sealed thirds are not node-held signatures.
#[test(should_fail_with = "node 0's result signature does not verify")]
unconstrained fn a_result_signed_over_sealed_thirds_is_refused() {
    let s = setup();
    init(s, H0);
    let id_a = request(s, INPUTS_A, NONCE_A);
    let r = result(id_a, H0, H1, true);
    let sigs = result_signatures(s.app.to_field(), id_a, [H0], [], [H1], sealed_hashes(thirds::<5>(1)));
    let _ = submit_with(s, r, sigs);
}

#[test(should_fail_with = "node 2's result signature does not verify")]
unconstrained fn a_result_with_a_tampered_signature_is_refused() {
    let s = setup();
    init(s, H0);
    let id_a = request(s, INPUTS_A, NONCE_A);
    let r = result(id_a, H0, H1, true);
    let mut sigs = signatures(s, r);
    sigs[2][0] = sigs[2][0] + 1;
    let _ = submit_with(s, r, sigs);
}

// Signed over other new commitments than the result carries: refused.
#[test(should_fail_with = "node 0's result signature does not verify")]
unconstrained fn a_result_whose_commitment_was_not_signed_is_refused() {
    let s = setup();
    init(s, H0);
    let id_a = request(s, INPUTS_A, NONCE_A);
    let sigs = signatures(s, result(id_a, H0, H1, true));
    let _ = submit_with(s, result(id_a, H0, H2, true), sigs);
}

// A correctly signed result over another commitment than the slot holds is
// refused at apply, and the slot keeps its value.
#[test(should_fail_with = "state moved")]
unconstrained fn a_result_over_another_commitment_than_the_slot_is_refused() {
    let s = setup();
    init(s, H0);
    let id_a = request(s, INPUTS_A, NONCE_A);
    let r = result(id_a, H1, H2, true);
    assert(!s.env.call_public(s.relayer, PssPublicTest::at(s.app).try_apply_held(s.app, r)));
    assert_eq(held(s), H0);
    let _ = submit(s, r);
}
