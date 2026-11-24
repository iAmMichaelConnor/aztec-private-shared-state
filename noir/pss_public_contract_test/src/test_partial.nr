//! Partial-note delivery through the library's `partial_note` brick, over
//! the `held` key of `PssPublicTest` under node-held state: both completions,
//! chaining, the redeem nullifier and refunds.
//!
//! - The public completion: `request_partial` commits the partial note `P`
//!   from the user's address and `rho` (pushing its use nullifier) and tells
//!   the user's PXE of it with an offchain partial-note message, which the
//!   test hands to the contract's `offchain_receive` as a client hands the
//!   send result's `offchainMessages`; `process_result_partial` and
//!   `apply_partial` land the result and complete the note in public; the
//!   PXE finds the completion log by its tag and stores the note.
//! - The private completion: `request_partial_private` commits `P` under C;
//!   the round's completed note hash and outcome log are computed here as the
//!   MPC computes them (`pss_core::tip::outcome::encrypt_outcome`), landed by
//!   `process_result_private` under private outcomes, and
//!   the user delivers the note from the log (`deliver_partial_outcome`).
//! - Chaining (`request_partial` with `chained`): a completed note of the sender's opens the
//!   next request, which commits the next partial note to the same owner.
//! - The spend of a chained note (`redeem`): once, the note still readable.
//! - Refunds: `request_partial` with an escrow commits a second partial note,
//!   `skip_refunding` completes it for the escrowed amount and
//!   `apply_partial` for none; the refund notes share the completed notes'
//!   set (`[0, amount, request_id]`).
//!
//! The proof is the suite's dummy capsule, as in `test_result.nr`.
use crate::nodes::tip_config;
use crate::PssPublicTest;
use crate::rounds::{HELD_INIT_INPUTS, OutcomeRound, PartialHeldResult, PartialOutcome, PartialOutcomes};
use crate::test::last_tx_summary;
use aztec::messages::processing::offchain::{MAX_OFFCHAIN_MESSAGES_PER_RECEIVE_CALL, OffchainMessage};
use aztec::note::note_interface::NoteHash;
use aztec::protocol::address::AztecAddress;
use aztec::protocol::hash::poseidon2_hash;
use aztec::protocol::traits::{FromField, Packable, ToField};
use aztec::test::helpers::test_environment::TestEnvironment;
use aztec::test::helpers::txe_oracles;
use pss_core::tip::outcome::encrypt_outcome;
use pss_public_contract::{chain_request_id, Head, inputs_commitment, inputs_hash, shared_chain_request_id, StaleBlocks};
use pss_public_contract::init::init_request_id;
use pss_public_contract::outcome::{OutcomeApply, OutcomeResult};
use pss_public_contract::partial_note::{
    completed_note_hash, completion_log_tag, note_hash, partial_commitment, use_nullifier,
};
use pss_public_contract::result::{NodeHeld, PartialResult, ResultSignature, Sealing, TipResult};
use pss_tip_test::last_tx;
use pss_tip_test::outcome::open_outcome_log;
use pss_tip_test::{dummy_vk, result_signatures, stage_proof};
use uint_note::UintNote;

global STALE: u32 = 4;
pub(crate) global H0: Field = 0x4e0;
pub(crate) global H1: Field = 0x4e1;
global H2: Field = 0x4e2;
pub(crate) global INPUTS: [Field; 2] = [25000, 0];
global INPUTS_B: [Field; 2] = [700, 1];
pub(crate) global NONCE: Field = 0xa1;
global NONCE_B: Field = 0xb2;
// the client's derived randomness of the user's requests
pub(crate) global RHO: Field = 0x5eed01;
global RHO_B: Field = 0x5eed02;
global RHO_REFUND: Field = 0x5eed03;
global OUTCOME_KEY: Field = 0x6b6b;
global OUTCOME_TAG: Field = 0x7a7a;
global BLINDING: Field = 0xb1;
// a swap that applied, and one that failed (code 2) with nothing out
global APPLIED: [Field; 2] = [0, 24000];
global FAILED: [Field; 2] = [2, 0];
global ESCROWED: Field = 500;

pub(crate) struct Setup {
    pub env: TestEnvironment,
    pub user: AztecAddress,
    pub stranger: AztecAddress,
    pub relayer: AztecAddress,
    pub app: AztecAddress,
    held_vk_hash: Field,
    outcome_vk_hash: Field,
    // the slot of the completed notes (refunds among them)
    slot: Field,
}

unconstrained fn held_vk() -> [Field; 115] {
    dummy_vk(9)
}

unconstrained fn outcome_vk() -> [Field; 115] {
    dummy_vk(11)
}

/// Deploy the app with the held round's, the init's and the outcome
/// circuit's vks pinned, and land the init: `held` holds H0.
pub(crate) unconstrained fn setup() -> Setup {
    let mut env = TestEnvironment::new();
    let deployer = env.create_light_account();
    let user = env.create_light_account();
    let stranger = env.create_light_account();
    let relayer = env.create_light_account();
    let held_vk_hash = poseidon2_hash(held_vk());
    let init_vk = dummy_vk(8);
    let init_vk_hash = poseidon2_hash(init_vk);
    let outcome_vk_hash = poseidon2_hash(outcome_vk());
    let app = env.deploy("PssPublicTest").with_public_initializer(
        deployer,
        PssPublicTest::interface().constructor(tip_config(StaleBlocks::after(STALE)), held_vk_hash, held_vk_hash),
    );
    env.call_public(deployer, PssPublicTest::at(app).set_init_vk_hash(init_vk_hash));
    env.call_public(deployer, PssPublicTest::at(app).set_outcome_vk_hash(outcome_vk_hash));
    let slot = env.execute_utility(PssPublicTest::at(app).partial_slot());
    let init_id = init_request_id(app, init_vk_hash, HELD_INIT_INPUTS);
    let sigs = result_signatures(app.to_field(), init_id, [0], [], [H0], NodeHeld {}.sealed_hashes());
    stage_proof(env, app, relayer, init_vk);
    env.call_private(relayer, PssPublicTest::at(app).init_held(H0, sigs));
    Setup {
        env,
        user,
        stranger,
        relayer,
        app,
        held_vk_hash,
        outcome_vk_hash,
        slot,
    }
}

unconstrained fn held(s: Setup) -> Field {
    s.env.view_public(PssPublicTest::at(s.app).get_held())
}

/// Hand the last call's offchain messages to the contract's
/// `offchain_receive`, as a client hands its PXE the send result's
/// `offchainMessages`. Returns how many there were.
unconstrained fn receive_offchain(s: Setup) -> u32 {
    let messages = s.env.offchain_messages();
    let mut batch: BoundedVec<OffchainMessage, MAX_OFFCHAIN_MESSAGES_PER_RECEIVE_CALL> = BoundedVec::new();
    for i in 0..messages.len() {
        batch.push(messages.get(i));
    }
    s.env.execute_utility(PssPublicTest::at(s.app).offchain_receive(batch));
    messages.len()
}

/// The chain request id of a request with partial note `p` over `inputs`.
unconstrained fn plain_id(s: Setup, inputs: [Field; 2], p: Field, nonce: Field) -> Field {
    chain_request_id(s.app, s.held_vk_hash, inputs_hash(inputs.concat([p])), nonce)
}

/// The user's request under the public completion, its offchain message
/// handed to its PXE. Returns the chain request id.
pub(crate) unconstrained fn request(s: Setup, inputs: [Field; 2], rho: Field, nonce: Field) -> Field {
    s.env.call_private(s.user, PssPublicTest::at(s.app).request_partial(inputs, s.user, rho, nonce, false, 0, 0));
    assert_eq(receive_offchain(s), 1);
    plain_id(s, inputs, partial_commitment(s.user, rho), nonce)
}

/// Land the public completion's result for chain request `id` with partial
/// note `p`, from `old_c` to `new_c`, with app outputs `outputs`.
pub(crate) unconstrained fn land(s: Setup, id: Field, p: Field, old_c: Field, new_c: Field, ok: bool, outputs: [Field; 2]) -> PartialHeldResult {
    let r = PartialResult { partial_note: p, result: TipResult::new(id, [old_c], [new_c], ok, [], outputs) };
    let sigs = result_signatures(s.app.to_field(), id, [old_c], [], [new_c], NodeHeld {}.sealed_hashes());
    stage_proof(s.env, s.app, s.relayer, held_vk());
    s.env.call_private(s.relayer, PssPublicTest::at(s.app).process_result_partial(r, sigs));
    r
}

unconstrained fn notes_of(s: Setup, owner: AztecAddress) -> PartialOutcomes {
    s.env.execute_utility(PssPublicTest::at(s.app).partial_notes(owner))
}

// ---- the note hash ---------------------------------------------------------

// The library's two-step hash is aztec-nr's: a UintNote of value v hashes as
// the note completing its partial commitment with [v] (request id last: the
// value), and the test contract's note type as the completed hash over its
// fields.
#[test]
unconstrained fn the_two_step_hash_is_aztec_nrs() {
    let owner = AztecAddress::from_field(50);
    let uint = UintNote { value: 17 };
    assert_eq(uint.compute_note_hash(owner, 13, 42), note_hash(owner, 13, 42, [17]));
    assert_eq(uint.compute_note_hash(owner, 13, 42), completed_note_hash(13, partial_commitment(owner, 42), [], 17));
    let note = PartialOutcome { code: 0, amount: 24000, request_id: 0x1d };
    assert_eq(
        note.compute_note_hash(owner, 13, 42),
        completed_note_hash(13, partial_commitment(owner, 42), [0, 24000], 0x1d),
    );
    assert_eq(note.pack(), [0, 24000, 0x1d]);
}

// The test contract's note type hashes testvectors/outcome.json's completed
// note (pss-client's and pss_core's) alike, and the library's partial note
// and completion tag are the vector's.
#[test]
unconstrained fn the_completed_note_is_the_vectors() {
    let owner = AztecAddress::from_field(PARTIAL_OWNER);
    let p = partial_commitment(owner, PARTIAL_RHO);
    assert_eq(p, PARTIAL_NOTE);
    assert_eq(completion_log_tag(p), PARTIAL_COMPLETION_TAG);
    let note = PartialOutcome { code: PARTIAL_FIELDS[0], amount: PARTIAL_FIELDS[1], request_id: PARTIAL_REQUEST_ID };
    assert_eq(note.compute_note_hash(owner, PARTIAL_SLOT, PARTIAL_RHO), PARTIAL_NOTE_HASH);
}

// BEGIN written by scripts/gen-noir-vectors.py from testvectors/outcome.json
// testvectors/outcome.json `partial_note`: the completed note [PARTIAL_FIELDS…,
// PARTIAL_REQUEST_ID] of the partial note of PARTIAL_OWNER under PARTIAL_RHO at
// slot PARTIAL_SLOT, as pss_core and pss-client compute it
global PARTIAL_OWNER: Field = 0xa11ce;
global PARTIAL_RHO: Field = 0x5eed01;
global PARTIAL_SLOT: Field = 0x2a;
global PARTIAL_FIELDS: [Field; 2] = [0x0, 0x5dc0];
global PARTIAL_REQUEST_ID: Field = 0x1d;
global PARTIAL_NOTE: Field = 0x078047daeae669340cf844da97625ca79c5080bfaa0386071fcd8e8c48f65f8b;
global PARTIAL_NOTE_HASH: Field = 0x189e0a80840440bbb8a123ec5da140f24881e92ba574fcb0ec4fb5edfa72c0d0;
global PARTIAL_COMPLETION_TAG: Field = 0x17c19efe8757d22097eb9bbcfe779886f6b3f499d450d953d2fd56d07f758edf;
// END written by scripts/gen-noir-vectors.py

// ---- the public completion -------------------------------------------------

// The request pushes the partial note's use nullifier and enqueues one public
// call; the request id is over the inputs and P, which names no account, and
// the offchain message puts nothing on chain. apply completes the note in
// public: the completion log [slot, code, amount, request_id] under P's
// completion tag and one note hash; the owner's PXE, told of P offchain,
// finds it and holds the note.
#[test]
unconstrained fn a_request_commits_its_partial_note_and_a_public_completion_lands_it_in_the_owners_pxe() {
    let s = setup();
    let id = request(s, INPUTS, RHO, NONCE);
    assert_eq(s.env.view_public(PssPublicTest::at(s.app).request_at(0)), id);
    let effects = txe_oracles::get_last_tx_effects();
    let p = partial_commitment(s.user, RHO);
    let mut found = false;
    for i in 0..effects.nullifiers.len() {
        found |= effects.nullifiers.get(i)
            == aztec::protocol::hash::compute_siloed_nullifier(s.app, use_nullifier(p));
    }
    assert(found);
    assert_eq(effects.private_logs.len(), 0);

    assert_eq(notes_of(s, s.user).count, 0);
    let _ = land(s, id, p, H0, H1, true, APPLIED);
    assert_eq(held(s), H1);
    assert_eq(s.env.view_public(PssPublicTest::at(s.app).get_head()).index, 1);
    let effects = last_tx_summary(s.env, s.app);
    assert_eq(effects.note_hashes, 1);
    assert_eq(effects.public_logs, 1);
    let tx_hash = txe_oracles::get_last_tx_effects().tx_hash;
    let log = s.env.execute_utility(PssPublicTest::at(s.app).completion_log(tx_hash, completion_log_tag(p)));
    assert_eq(log, [s.slot, 0, 24000, id]);
    let notes = notes_of(s, s.user);
    assert_eq(notes.count, 1);
    assert_eq(notes.first, PartialOutcome { code: 0, amount: 24000, request_id: id });
    // the note is the user's alone
    assert_eq(notes_of(s, s.stranger).count, 0);
}

// A second request naming the same partial note reverts at its request:
// other inputs and another nonce, so the chain request id is new and only
// the repeated use nullifier collides.
#[test(should_fail_with = "Nullifier collision")]
unconstrained fn a_partial_note_is_used_by_one_request() {
    let s = setup();
    let _ = request(s, INPUTS, RHO, NONCE);
    let _ = request(s, INPUTS_B, RHO, NONCE_B);
}

// A failed round completes its note too, saying so: a zero amount keeps the
// log whole, since the request id is last.
#[test]
unconstrained fn a_failed_round_completes_a_note_that_says_so() {
    let s = setup();
    let id = request(s, INPUTS, RHO, NONCE);
    let p = partial_commitment(s.user, RHO);
    let _ = land(s, id, p, H0, H0, false, FAILED);
    assert_eq(held(s), H0);
    let tx_hash = txe_oracles::get_last_tx_effects().tx_hash;
    let log = s.env.execute_utility(PssPublicTest::at(s.app).completion_log(tx_hash, completion_log_tag(p)));
    assert_eq(log, [s.slot, 2, 0, id]);
    assert_eq(notes_of(s, s.user).first, PartialOutcome { code: 2, amount: 0, request_id: id });
}

// ---- the private completion ------------------------------------------------

/// The private completion's result for chain request `id` with partial note
/// `p`: the outcome encrypted and the note completed as the MPC does.
unconstrained fn sealed(s: Setup, id: Field, p: Field, outcome: [Field; 2]) -> OutcomeRound {
    let e = encrypt_outcome(outcome, OUTCOME_KEY, p, s.slot, id);
    OutcomeResult {
        apply: OutcomeApply::new(id, [H0], [H1], []),
        outcome_tag: OUTCOME_TAG,
        note_hashes: [e.note_hash],
        ciphertext: e.ciphertext,
    }
}

/// Request under C and land the private completion of `outcome`; returns
/// the chain request id.
unconstrained fn private_round(s: Setup, outcome: [Field; 2]) -> Field {
    s.env.call_private(
        s.user,
        PssPublicTest::at(s.app).request_partial_private(INPUTS, s.user, RHO, OUTCOME_KEY, OUTCOME_TAG, BLINDING),
    );
    let p = partial_commitment(s.user, RHO);
    let c = inputs_commitment(INPUTS.concat([p, OUTCOME_KEY, OUTCOME_TAG]), BLINDING);
    let id = shared_chain_request_id(s.app, s.outcome_vk_hash, c);
    assert_eq(s.env.view_public(PssPublicTest::at(s.app).request_at(0)), id);
    let r = sealed(s, id, p, outcome);
    let sigs: [ResultSignature; 3] = result_signatures(s.app.to_field(), id, [H0], [], [H1], NodeHeld {}.sealed_hashes());
    stage_proof(s.env, s.app, s.relayer, outcome_vk());
    s.env.call_private(s.relayer, PssPublicTest::at(s.app).process_result_private(r, sigs));
    id
}

// The round's completed note hash lands with the outcome log and no public
// log or call; the user opens the log, rebuilds the note [code, amount,
// request_id] with its rho and hands it to its PXE, which holds it. A note
// rebuilt with another rho is not the completed one: nothing is stored.
#[test]
unconstrained fn a_private_completion_lands_the_note_the_user_delivers_with_its_rho() {
    let s = setup();
    let id = private_round(s, APPLIED);
    assert_eq(held(s), H1);
    let effects = last_tx_summary(s.env, s.app);
    assert_eq(effects.note_hashes, 1);
    assert_eq(effects.private_logs, 1);
    assert_eq(effects.public_logs, 0);
    let log = txe_oracles::get_last_tx_effects().private_logs.get(0);
    let opened: [Field; 2] = open_outcome_log(log, OUTCOME_KEY);
    assert_eq(opened, APPLIED);
    s.env.execute_utility(PssPublicTest::at(s.app).deliver_partial_outcome(
        s.user,
        RHO + 1,
        opened.concat([id]),
        last_tx(),
    ));
    assert_eq(notes_of(s, s.user).count, 0);
    s.env.execute_utility(PssPublicTest::at(s.app).deliver_partial_outcome(
        s.user,
        RHO,
        opened.concat([id]),
        last_tx(),
    ));
    let notes = notes_of(s, s.user);
    assert_eq(notes.count, 1);
    assert_eq(notes.first, PartialOutcome { code: 0, amount: 24000, request_id: id });
}

// ---- chaining and the redeem nullifier ---------------------------------------

// A chained note's value is redeemed once: the redeem nullifier lands and
// the note stays readable. The completed note of the sender's still opens
// the next request, which commits the next partial note to the same owner;
// its completion is the chain's next note, and the first stays.
#[test]
unconstrained fn a_completed_note_is_redeemed_once_and_opens_the_next_request() {
    let s = setup();
    let id = request(s, INPUTS, RHO, NONCE);
    let _ = land(s, id, partial_commitment(s.user, RHO), H0, H1, true, APPLIED);
    s.env.call_private(s.user, PssPublicTest::at(s.app).redeem(s.user));
    assert_eq(last_tx_summary(s.env, s.app).nullifiers, 2);
    assert_eq(notes_of(s, s.user).count, 1);
    s.env.call_private(s.user, PssPublicTest::at(s.app).request_partial(INPUTS_B, s.user, RHO_B, NONCE_B, true, 0, 0));
    assert_eq(receive_offchain(s), 1);
    let p_b = partial_commitment(s.user, RHO_B);
    let id_b = plain_id(s, INPUTS_B, p_b, NONCE_B);
    assert_eq(s.env.view_public(PssPublicTest::at(s.app).request_at(1)), id_b);
    let _ = land(s, id_b, p_b, H1, H2, true, [0, 700]);
    assert_eq(notes_of(s, s.user).count, 2);
}

// Nobody but the owner chains from its note: the stranger's PXE holds no
// note of the user's (its notes are scoped to the sender), so the request
// finds none to chain from before `assert_owned` is reached.
#[test(should_fail_with = "no completed note to chain from")]
unconstrained fn a_stranger_cannot_chain_from_the_users_note() {
    let s = setup();
    let id = request(s, INPUTS, RHO, NONCE);
    let _ = land(s, id, partial_commitment(s.user, RHO), H0, H1, true, APPLIED);
    s.env.call_private(s.stranger, PssPublicTest::at(s.app).request_partial(INPUTS_B, s.user, RHO_B, NONCE_B, true, 0, 0));
}

// A note that reports a failure confers nothing.
#[test(should_fail_with = "the note does not report success")]
unconstrained fn a_failed_note_does_not_open_a_request() {
    let s = setup();
    let id = request(s, INPUTS, RHO, NONCE);
    let _ = land(s, id, partial_commitment(s.user, RHO), H0, H0, false, FAILED);
    s.env.call_private(s.user, PssPublicTest::at(s.app).request_partial(INPUTS_B, s.user, RHO_B, NONCE_B, true, 0, 0));
}

// A second redeem of one note pushes the same redeem nullifier, which the
// transaction's nullifier check refuses as a duplicate.
#[test(should_fail_with = "duplicate nullifiers")]
unconstrained fn a_second_redeem_of_one_note_is_refused() {
    let s = setup();
    let id = request(s, INPUTS, RHO, NONCE);
    let _ = land(s, id, partial_commitment(s.user, RHO), H0, H1, true, APPLIED);
    s.env.call_private(s.user, PssPublicTest::at(s.app).redeem(s.user));
    s.env.call_private(s.user, PssPublicTest::at(s.app).redeem(s.user));
}

// A stranger cannot redeem the user's note: its PXE holds none of the
// user's notes, so `redeem` finds nothing before `assert_owned`.
#[test(should_fail_with = "no completed note to redeem")]
unconstrained fn a_stranger_cannot_redeem_the_users_note() {
    let s = setup();
    let id = request(s, INPUTS, RHO, NONCE);
    let _ = land(s, id, partial_commitment(s.user, RHO), H0, H1, true, APPLIED);
    s.env.call_private(s.stranger, PssPublicTest::at(s.app).redeem(s.user));
}

// ---- refunds -----------------------------------------------------------------

/// The user's request with an escrow; both offchain messages handed to its
/// PXE. Returns the chain request id.
unconstrained fn request_escrowed(s: Setup) -> Field {
    s.env.call_private(
        s.user,
        PssPublicTest::at(s.app).request_partial(INPUTS, s.user, RHO, NONCE, false, RHO_REFUND, ESCROWED),
    );
    assert_eq(receive_offchain(s), 2);
    plain_id(s, INPUTS, partial_commitment(s.user, RHO), NONCE)
}

// A skipped request's refund note is completed by skip() for the whole
// escrow, with no round: the owner's PXE holds it. The head moved by
// skip_refunding carries its clock as any skip does.
#[test]
unconstrained fn skip_completes_the_refund_note_and_moves_the_head_as_skip_does() {
    let s = setup();
    let id = request_escrowed(s);
    for _ in 0..STALE {
        s.env.mine_block();
    }
    s.env.call_public(s.relayer, PssPublicTest::at(s.app).skip_refunding());
    let head: Head = s.env.view_public(PssPublicTest::at(s.app).get_head());
    assert_eq(head, Head { index: 1, since: s.env.last_block_number() });
    let tx_hash = txe_oracles::get_last_tx_effects().tx_hash;
    let refund = partial_commitment(s.user, RHO_REFUND);
    let log = s.env.execute_utility(PssPublicTest::at(s.app).completion_log(tx_hash, completion_log_tag(refund)));
    assert_eq(log, [s.slot, 0, ESCROWED, id]);
    // the refund is the one note: the request's own partial note was never
    // completed
    let notes = notes_of(s, s.user);
    assert_eq(notes.count, 1);
    assert_eq(notes.first, PartialOutcome { code: 0, amount: ESCROWED, request_id: id });
}

// A served request's refund note is completed by apply, here for none (the
// round's note carries the settlement): both notes land.
#[test]
unconstrained fn apply_completes_the_refund_note_for_none() {
    let s = setup();
    let id = request_escrowed(s);
    let _ = land(s, id, partial_commitment(s.user, RHO), H0, H1, true, APPLIED);
    assert_eq(last_tx_summary(s.env, s.app).note_hashes, 2);
    let notes = notes_of(s, s.user);
    assert_eq(notes.count, 2);
    assert(notes.holds(PartialOutcome { code: 0, amount: 0, request_id: id }));
    assert(notes.holds(PartialOutcome { code: 0, amount: 24000, request_id: id }));
}
