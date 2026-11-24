//! Private outcomes through the library's `outcome` brick: a secret-shared-intake
//! round over the `held` key of `PssPublicTest` (`process_result_private`,
//! `apply_private`) under node-held state, and the completed note's delivery
//! to the user's PXE (`deliver_partial_outcome`).
//!
//! The outcome is computed here as the round computes it inside the MPC, with
//! the round's own functions (`pss_core::tip::outcome`): the machine request
//! id, the ciphertext under the outcome key and the hash of the request's
//! partial note completed with the outcome and the request id. The proof is
//! the suite's dummy capsule (a vk of elevens), as in `test_result.nr`. The
//! request stands in for a secret-shared intake's: `request` queues the chain
//! request id over C, which commits the user's partial note.
//!
//! The TXE runs every private call in the revertible phase (it sets the
//! minimum revertible counter to 1 in place of the account's entrypoint), so
//! `outcome::Private`'s refusal of a setup-phase call cannot be reached here;
//! and a transaction whose public part reverts is not mined at all, so a
//! refused `apply_private` leaves neither the note hash nor the log.
use crate::nodes::{tip_config, VK_HASH};
use crate::PssPublicTest;
use crate::rounds::{HELD_INIT_INPUTS, OutcomeApplyRound, OutcomeRound, PartialOutcome, PartialOutcomes};
use crate::test::{last_tx_summary, reader, Reader};
use aztec::protocol::address::AztecAddress;
use aztec::protocol::hash::{compute_siloed_private_log_first_field, poseidon2_hash};
use aztec::protocol::traits::ToField;
use aztec::test::helpers::test_environment::TestEnvironment;
use aztec::test::helpers::txe_oracles;
use pss_core::tip::intake::{commit, shared};
use pss_core::tip::outcome::{encrypt_outcome, log_padding, partial_commitment};
use pss_public_contract::{DONE_APPLIED, Head, StaleBlocks};
use pss_public_contract::init::init_request_id;
use pss_public_contract::outcome::{OutcomeApply, OutcomeResult};
use pss_public_contract::result::{NodeHeld, ResultSignature, Sealing};
use pss_tip_test::last_tx;
use pss_tip_test::outcome::open_outcome_log;
use pss_tip_test::{dummy_vk, result_signatures, stage_proof};

global STALE: u32 = 4;
// the held key's commitments: the init's, then one per landed round
pub(crate) global H0: Field = 0x4e0;
pub(crate) global H1: Field = 0x4e1;
pub(crate) global H2: Field = 0x4e2;
global H3: Field = 0x4e3;
// the user's request: its inputs, the randomness of its partial note, its
// blinding, outcome key and outcome tag
pub(crate) global INPUTS: [Field; 2] = [25000, 0];
pub(crate) global RHO: Field = 0x5eed;
pub(crate) global BLINDING: Field = 0xb1;
pub(crate) global OUTCOME_KEY: Field = 0x6b6b;
pub(crate) global OUTCOME_TAG: Field = 0x7a7a;
// a swap that applied, and one that failed (code 2) with nothing out
pub(crate) global APPLIED: [Field; 2] = [0, 24000];
pub(crate) global FAILED: [Field; 2] = [2, 0];

pub(crate) struct Setup {
    pub(crate) env: TestEnvironment,
    pub(crate) user: AztecAddress,
    pub(crate) relayer: AztecAddress,
    pub(crate) app: AztecAddress,
    pub(crate) init_vk_hash: Field,
    pub(crate) outcome_vk_hash: Field,
    pub(crate) slot: Field,
}

impl Setup {
    pub(crate) unconstrained fn queue(self) -> Reader {
        reader(self.env, self.app)
    }
}

unconstrained fn init_vk() -> [Field; 115] {
    dummy_vk(8)
}

pub(crate) unconstrained fn outcome_vk() -> [Field; 115] {
    dummy_vk(11)
}

/// Deploy the app with the init and the private-outcome circuits pinned,
/// and land the init: the held key holds H0.
pub(crate) unconstrained fn setup() -> Setup {
    let mut env = TestEnvironment::new();
    let deployer = env.create_light_account();
    let user = env.create_light_account();
    let relayer = env.create_light_account();
    let init_vk_hash = poseidon2_hash(init_vk());
    let outcome_vk_hash = poseidon2_hash(outcome_vk());
    let app = env.deploy("PssPublicTest").with_public_initializer(
        deployer,
        PssPublicTest::interface().constructor(tip_config(StaleBlocks::after(STALE)), VK_HASH, 0),
    );
    env.call_public(deployer, PssPublicTest::at(app).set_init_vk_hash(init_vk_hash));
    env.call_public(deployer, PssPublicTest::at(app).set_outcome_vk_hash(outcome_vk_hash));
    let slot = env.execute_utility(PssPublicTest::at(app).partial_slot());
    let s = Setup { env, user, relayer, app, init_vk_hash, outcome_vk_hash, slot };
    let init_id = init_request_id(app, init_vk_hash, HELD_INIT_INPUTS);
    let sigs = result_signatures(app.to_field(), init_id, [0], [], [H0], NodeHeld {}.sealed_hashes());
    stage_proof(env, app, relayer, init_vk());
    env.call_private(relayer, PssPublicTest::at(app).init_held(H0, sigs));
    s
}

pub(crate) unconstrained fn held(s: Setup) -> Field {
    s.env.view_public(PssPublicTest::at(s.app).get_held())
}

/// The user's partial note, `partial_commitment(user, RHO)`.
pub(crate) unconstrained fn partial(s: Setup) -> Field {
    partial_commitment(s.user.to_field(), RHO)
}

/// Queue a secret-shared-intake request: the chain request id over C =
/// poseidon2([inputs…, P, outcome_key, outcome_tag, blinding]) under the
/// outcome circuit's vk hash.
pub(crate) unconstrained fn request(s: Setup, blinding: Field) -> Field {
    let c = commit(INPUTS.concat([partial(s), OUTCOME_KEY, OUTCOME_TAG]), blinding);
    let id = shared(s.app.to_field(), s.outcome_vk_hash, c);
    s.env.call_private(s.user, PssPublicTest::at(s.app).request(id));
    id
}

/// The round's result for chain request `id` read at `old_c`, leaving
/// `new_c`, with `outcome` encrypted to the user as the MPC encrypts it and
/// the user's partial note completed with it and `id` at the contract's
/// note slot.
pub(crate) unconstrained fn result(s: Setup, id: Field, old_c: Field, new_c: Field, outcome: [Field; 2]) -> OutcomeRound {
    let encrypted = encrypt_outcome(outcome, OUTCOME_KEY, partial(s), s.slot, id);
    OutcomeResult {
        apply: OutcomeApply::new(id, [old_c], [new_c], []),
        outcome_tag: OUTCOME_TAG,
        note_hashes: [encrypted.note_hash],
        ciphertext: encrypted.ciphertext,
    }
}

pub(crate) unconstrained fn signatures(s: Setup, r: OutcomeRound) -> [ResultSignature; 3] {
    result_signatures(
        s.app.to_field(),
        r.apply.request_id,
        r.apply.old_commitments,
        [],
        r.apply.new_commitments(),
        NodeHeld {}.sealed_hashes(),
    )
}

unconstrained fn submit_with(s: Setup, vk: [Field; 115], r: OutcomeRound, sigs: [ResultSignature; 3]) -> u32 {
    stage_proof(s.env, s.app, s.relayer, vk);
    s.env.call_private(s.relayer, PssPublicTest::at(s.app).process_result_private(r, sigs));
    s.env.last_block_number()
}

unconstrained fn submit(s: Setup, r: OutcomeRound) -> u32 {
    submit_with(s, outcome_vk(), r, signatures(s, r))
}

/// The last transaction's one private log: `[siloed tag, fields…]`, 16 long.
pub(crate) unconstrained fn the_outcome_log() -> BoundedVec<Field, 16> {
    let effects = txe_oracles::get_last_tx_effects();
    assert_eq(effects.private_logs.len(), 1);
    effects.private_logs.get(0)
}

unconstrained fn notes_of(s: Setup, owner: AztecAddress) -> PartialOutcomes {
    s.env.execute_utility(PssPublicTest::at(s.app).partial_notes(owner))
}

// A private outcome lands its note hash and its log and writes the new
// commitment; the head moves and done[0] = applied; nothing public is logged.
// The log carries the siloed tag, the completed note's hash and the
// ciphertext, padded to the full 16 fields; the user opens the ciphertext
// with its key under the nonce of that note hash. The user rebuilds the completed note from the
// log, its partial note's randomness and the request id, and hands it to its
// PXE through the outcome-note utility; the PXE then holds it. A note
// rebuilt under another request id is not the one the round completed: the
// PXE stores nothing.
#[test]
unconstrained fn a_private_outcome_lands_its_note_and_log_and_the_user_delivers_the_note() {
    let s = setup();
    let id = request(s, BLINDING);
    let r = result(s, id, H0, H1, APPLIED);
    let block = submit(s, r);
    assert_eq(held(s), H1);
    assert_eq(s.queue().head(), Head { index: 1, since: block });
    assert_eq(s.env.view_public(PssPublicTest::at(s.app).done_at(0)), DONE_APPLIED);
    let effects = last_tx_summary(s.env, s.app);
    assert_eq(effects.note_hashes, 1);
    assert_eq(effects.private_logs, 1);
    assert_eq(effects.public_logs, 0);
    assert_eq(effects.l2_to_l1_msgs, 0);

    let log = the_outcome_log();
    assert_eq(log.len(), 16);
    assert_eq(log.get(0), compute_siloed_private_log_first_field(s.app, OUTCOME_TAG));
    let note_hash = log.get(1);
    assert_eq(note_hash, r.note_hashes[0]);
    for i in 0..3 {
        assert_eq(log.get(2 + i), r.ciphertext[i]);
    }
    let opened: [Field; 2] = open_outcome_log(log, OUTCOME_KEY);
    assert_eq(opened, APPLIED);

    assert_eq(notes_of(s, s.user).count, 0);
    s.env.execute_utility(PssPublicTest::at(s.app).deliver_partial_outcome(
        s.user,
        RHO,
        APPLIED.concat([id + 1]),
        last_tx(),
    ));
    assert_eq(notes_of(s, s.user).count, 0);
    s.env.execute_utility(PssPublicTest::at(s.app).deliver_partial_outcome(
        s.user,
        RHO,
        APPLIED.concat([id]),
        last_tx(),
    ));
    let notes = notes_of(s, s.user);
    assert_eq(notes.count, 1);
    assert_eq(notes.first, PartialOutcome { code: 0, amount: 24000, request_id: id });
}

// A failed round under private outcomes re-blinds its state like any other:
// apply writes its new commitment (the public-output path would refuse a
// failed round that changes its commitment), the outcome says it failed, and
// the next round builds on the re-blinded state. The log's padding is
// poseidon2([outcome_tag, i]) at every position i past the ciphertext
// (counted after the tag): the same for an applied round and a failed one
// under one tag, so it carries nothing. The result has no padding field, so
// a result whose padding differs cannot be built.
#[test]
unconstrained fn a_failed_outcome_writes_its_new_commitment_and_pads_its_log_alike() {
    let s = setup();
    let id = request(s, BLINDING);
    let _ = submit(s, result(s, id, H0, H1, APPLIED));
    let applied = the_outcome_log();
    let id2 = request(s, BLINDING + 1);
    let block = submit(s, result(s, id2, H1, H2, FAILED));
    assert_eq(held(s), H2);
    assert_eq(s.queue().head(), Head { index: 2, since: block });
    let failed = the_outcome_log();
    let opened: [Field; 2] = open_outcome_log(failed, OUTCOME_KEY);
    assert_eq(opened, FAILED);
    // [siloed tag, note hash, ciphertext (3), padding (11)]
    for i in 4..15 {
        assert_eq(applied.get(1 + i), poseidon2_hash([OUTCOME_TAG, i as Field]));
        assert_eq(applied.get(1 + i), log_padding(OUTCOME_TAG, i));
        assert_eq(failed.get(1 + i), applied.get(1 + i));
    }
    assert(failed.get(1) != applied.get(1));

    let id3 = request(s, BLINDING + 2);
    let _ = submit(s, result(s, id3, H2, H3, APPLIED));
    assert_eq(held(s), H3);
}

// A result whose apply reverts is not mined: no note hash, no log, no write.
// The probe shows the refused apply leaves the slot and the head as they
// were; the result transaction itself then reverts.
#[test(should_fail_with = "state moved")]
unconstrained fn a_result_whose_apply_reverts_leaves_nothing() {
    let s = setup();
    let id = request(s, BLINDING);
    let a: OutcomeApplyRound = OutcomeApply::new(id, [H2], [H1], []);
    assert(!s.env.call_public(s.relayer, PssPublicTest::at(s.app).try_apply_private(s.app, a)));
    assert_eq(held(s), H0);
    assert_eq(s.queue().head().index, 0);
    let effects = last_tx_summary(s.env, s.app);
    assert_eq(effects.note_hashes, 0);
    assert_eq(effects.private_logs, 0);
    let _ = submit(s, result(s, id, H2, H1, APPLIED));
}

#[test(should_fail_with = "Function apply_private can only be called by the same contract")]
unconstrained fn apply_private_from_outside_the_contract_is_refused() {
    let s = setup();
    let id = request(s, BLINDING);
    let a: OutcomeApplyRound = OutcomeApply::new(id, [H0], [H1], []);
    s.env.call_public(s.user, PssPublicTest::at(s.app).apply_private(a));
}

#[test(should_fail_with = "unexpected verification key")]
unconstrained fn an_outcome_proved_under_another_vk_is_refused() {
    let s = setup();
    let id = request(s, BLINDING);
    let r = result(s, id, H0, H1, APPLIED);
    let _ = submit_with(s, init_vk(), r, signatures(s, r));
}

// The nodes sign the machine request id and the new commitments: a result
// whose commitment they did not sign is refused.
#[test(should_fail_with = "node 0's result signature does not verify")]
unconstrained fn an_outcome_whose_commitment_was_not_signed_is_refused() {
    let s = setup();
    let id = request(s, BLINDING);
    let sigs = signatures(s, result(s, id, H0, H1, APPLIED));
    let _ = submit_with(s, outcome_vk(), result(s, id, H0, H2, APPLIED), sigs);
}

#[test(should_fail_with = "node 2's result signature does not verify")]
unconstrained fn an_outcome_with_a_tampered_signature_is_refused() {
    let s = setup();
    let id = request(s, BLINDING);
    let r = result(s, id, H0, H1, APPLIED);
    let mut sigs = signatures(s, r);
    sigs[2][0] = sigs[2][0] + 1;
    let _ = submit_with(s, outcome_vk(), r, sigs);
}
