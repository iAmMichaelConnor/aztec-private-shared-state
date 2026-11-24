//! Chain-held state (the entry points under `chain_state`'s thirds), over
//! the `pool` key of `PssPublicTest`: the init round (`init_pool`, through
//! `process_init` and `apply_init`) and a private-outcome round
//! (`process_result_private_sealed`, through `check_round` and
//! `apply_round`). The chain-held public-output path is `test_result.nr`'s.
//!
//! Under chain-held state each node's result message ends in `H(sealed_i)`
//! of its own thirds, so a third changed after the nodes signed is refused
//! at that node's signature, and every apply, the init's included, logs
//! `(new commitments, thirds)` under `compute_log_tag(request id,
//! PSS_STATE)`, from which the chain reader rebuilds the state.
//!
//! The proofs are the suite's dummy capsules, as in `test_outcome.nr`: a vk
//! of eights for the init circuit and of elevens for the private-outcome
//! circuit, whose hashes the contract pins.
use crate::nodes::{tip_config, VK_HASH};
use crate::PssPublicTest;
use crate::rounds::{OutcomeRound, PartialOutcome, POOL_INIT_INPUTS, PoolThirds};
use pss_tip_test::shape::LogHead;
use crate::test::{last_tx_summary, reader, Reader};
use crate::test_outcome::{APPLIED, BLINDING, INPUTS, OUTCOME_KEY, OUTCOME_TAG, RHO};
use aztec::protocol::address::AztecAddress;
use aztec::protocol::hash::{compute_log_tag, poseidon2_hash};
use aztec::protocol::traits::ToField;
use aztec::test::helpers::test_environment::TestEnvironment;
use aztec::test::helpers::txe_oracles;
use pss_core::tip::intake::{commit, shared};
use pss_core::tip::outcome::{encrypt_outcome, partial_commitment};
use pss_public_contract::{DONE_APPLIED, Head, StaleBlocks};
use pss_public_contract::chain_state::{PSS_STATE, sealed_hashes};
use pss_public_contract::init::init_request_id;
use pss_public_contract::outcome::{OutcomeApply, OutcomeResult, OutcomeTx};
use pss_public_contract::result::{NodeHeld, ResultSignature, Sealing};
use pss_tip_test::outcome::open_outcome_log;
use pss_tip_test::{dummy_vk, result_signatures, stage_proof, state_log_payload, thirds};

global STALE: u32 = 4;
// the pool's commitments: the init's, then the outcome round's
global P0: Field = 0x5e0;
global P1: Field = 0x5e1;

struct Setup {
    env: TestEnvironment,
    user: AztecAddress,
    relayer: AztecAddress,
    app: AztecAddress,
    init_vk_hash: Field,
    outcome_vk_hash: Field,
    slot: Field,
}

impl Setup {
    unconstrained fn queue(self) -> Reader {
        reader(self.env, self.app)
    }
}

unconstrained fn init_vk() -> [Field; 115] {
    dummy_vk(8)
}

unconstrained fn outcome_vk() -> [Field; 115] {
    dummy_vk(11)
}

/// Deploy the app with the init and the private-outcome circuits pinned;
/// the pool starts empty.
unconstrained fn setup() -> Setup {
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
    Setup { env, user, relayer, app, init_vk_hash, outcome_vk_hash, slot }
}

unconstrained fn pool(s: Setup) -> Field {
    s.env.view_public(PssPublicTest::at(s.app).get_pool())
}

/// Node i's third with one field changed after the nodes signed.
unconstrained fn tampered(sealed: PoolThirds, i: u32) -> PoolThirds {
    let mut t = sealed;
    t[i][0][2] = t[i][0][2] + 1;
    t
}

/// The last transaction's sealed-thirds log is its one public log: from the
/// app, under `compute_log_tag(request_id, PSS_STATE)`, holding `new_c` and
/// `sealed`.
unconstrained fn assert_sealed_log(s: Setup, request_id: Field, new_c: Field, sealed: PoolThirds) {
    let effects = last_tx_summary(s.env, s.app);
    let tag = compute_log_tag(request_id, PSS_STATE);
    assert_eq(effects.public_logs, 1);
    assert_eq(effects.logs[0], LogHead { emitter: s.app, tag, length: 17 });
    let tx_hash = txe_oracles::get_last_tx_effects().tx_hash;
    let fields = s.env.execute_utility(PssPublicTest::at(s.app).sealed_log(tx_hash, tag));
    assert_eq(fields, state_log_payload(new_c, sealed));
}

// ---------------------------------------------------------------------------
// The init round
// ---------------------------------------------------------------------------

unconstrained fn init_id(s: Setup) -> Field {
    init_request_id(s.app, s.init_vk_hash, POOL_INIT_INPUTS)
}

/// The nodes' signatures over the init result `new_c` under chain-held state:
/// every old commitment 0, no pinned read, `H(sealed_i)` of the first thirds.
unconstrained fn init_signatures(s: Setup, new_c: Field, sealed: PoolThirds) -> [ResultSignature; 3] {
    result_signatures(s.app.to_field(), init_id(s), [0], [], [new_c], sealed_hashes(sealed))
}

unconstrained fn init_with(s: Setup, new_c: Field, sealed: PoolThirds, sigs: [ResultSignature; 3]) {
    stage_proof(s.env, s.app, s.relayer, init_vk());
    s.env.call_private(s.relayer, PssPublicTest::at(s.app).init_pool(new_c, sealed, sigs));
}

unconstrained fn init(s: Setup, new_c: Field) {
    let sealed = thirds(1);
    init_with(s, new_c, sealed, init_signatures(s, new_c, sealed));
}

// The chain-held init writes the first commitment and logs its thirds under
// the init request id, the payload an apply logs, so the chain reader finds
// the first state for head 0; it touches no queue storage.
#[test]
unconstrained fn a_chain_held_init_writes_the_first_commitment_and_logs_its_thirds() {
    let s = setup();
    init(s, P0);
    assert_eq(pool(s), P0);
    assert_sealed_log(s, init_id(s), P0, thirds(1));
    let effects = last_tx_summary(s.env, s.app);
    assert_eq(effects.private_logs, 0);
    assert_eq(effects.note_hashes, 0);
    assert_eq(effects.nullifiers, 1);
    assert_eq(s.queue().head(), Head { index: 0, since: 0 });
    assert_eq(s.queue().tail(), 0);
}

// A third changed after the nodes signed the init: that node's signature
// does not verify, and nothing is written.
#[test(should_fail_with = "node 1's result signature does not verify")]
unconstrained fn a_chain_held_init_with_a_tampered_third_is_refused() {
    let s = setup();
    let sealed = thirds(1);
    init_with(s, P0, tampered(sealed, 1), init_signatures(s, P0, sealed));
}

// Node-held init signatures (H(sealed_i) = 0) do not cover the thirds.
#[test(should_fail_with = "node 0's result signature does not verify")]
unconstrained fn a_chain_held_init_signed_without_thirds_is_refused() {
    let s = setup();
    let sigs = result_signatures(s.app.to_field(), init_id(s), [0], [], [P0], NodeHeld {}.sealed_hashes());
    init_with(s, P0, thirds(1), sigs);
}

// ---------------------------------------------------------------------------
// A private-outcome round under chain-held state
// ---------------------------------------------------------------------------

/// The user's partial note, `partial_commitment(user, RHO)`.
unconstrained fn partial(s: Setup) -> Field {
    partial_commitment(s.user.to_field(), RHO)
}

/// Queue a secret-shared-intake request: the chain request id over C (the
/// inputs, the user's partial note, the outcome key and tag) under the
/// outcome circuit's vk hash.
unconstrained fn request(s: Setup) -> Field {
    let c = commit(INPUTS.concat([partial(s), OUTCOME_KEY, OUTCOME_TAG]), BLINDING);
    let id = shared(s.app.to_field(), s.outcome_vk_hash, c);
    s.env.call_private(s.user, PssPublicTest::at(s.app).request(id));
    id
}

/// The round's result for chain request `id` read at `old_c`, leaving
/// `new_c`, with `outcome` encrypted to the user as the MPC encrypts it and
/// the user's partial note completed with it.
unconstrained fn result(s: Setup, id: Field, old_c: Field, new_c: Field, outcome: [Field; 2]) -> OutcomeRound {
    let encrypted = encrypt_outcome(outcome, OUTCOME_KEY, partial(s), s.slot, id);
    OutcomeResult {
        apply: OutcomeApply::new(id, [old_c], [new_c], []),
        outcome_tag: OUTCOME_TAG,
        note_hashes: [encrypted.note_hash],
        ciphertext: encrypted.ciphertext,
    }
}

/// The nodes' signatures over an outcome round under chain-held state.
unconstrained fn signatures(s: Setup, r: OutcomeRound, sealed: PoolThirds) -> [ResultSignature; 3] {
    result_signatures(
        s.app.to_field(),
        r.apply.request_id,
        r.apply.old_commitments,
        [],
        r.apply.new_commitments(),
        sealed_hashes(sealed),
    )
}

unconstrained fn submit_with(s: Setup, r: OutcomeRound, sealed: PoolThirds, sigs: [ResultSignature; 3]) -> u32 {
    stage_proof(s.env, s.app, s.relayer, outcome_vk());
    s.env.call_private(
        s.relayer,
        PssPublicTest::at(s.app).process_result_private_sealed(r, sealed, sigs),
    );
    s.env.last_block_number()
}

// After the chain-held init, a chain-held outcome round lands: the pool
// takes the new commitment, the head moves, the completed note's hash and
// the outcome log land, and the apply logs the round's thirds. The user opens
// the outcome from the log and its PXE then holds the note.
#[test]
unconstrained fn a_chain_held_outcome_lands_opens_and_logs_its_thirds() {
    let s = setup();
    init(s, P0);
    let id = request(s);
    let r = result(s, id, P0, P1, APPLIED);
    let sealed = thirds(2);
    let block = submit_with(s, r, sealed, signatures(s, r, sealed));
    assert_eq(pool(s), P1);
    assert_eq(s.queue().head(), Head { index: 1, since: block });
    assert_eq(s.env.view_public(PssPublicTest::at(s.app).done_at(0)), DONE_APPLIED);
    assert_sealed_log(s, id, P1, sealed);
    let effects = last_tx_summary(s.env, s.app);
    assert_eq(effects.note_hashes, 1);
    assert_eq(effects.private_logs, 1);

    let tx = txe_oracles::get_last_tx_effects();
    let log = tx.private_logs.get(0);
    let note_hash = log.get(1);
    assert_eq(note_hash, r.note_hashes[0]);
    let opened: [Field; 2] = open_outcome_log(log, OUTCOME_KEY);
    assert_eq(opened, APPLIED);
    s.env.execute_utility(PssPublicTest::at(s.app).deliver_partial_outcome(
        s.user,
        RHO,
        APPLIED.concat([id]),
        OutcomeTx {
            tx_hash: tx.tx_hash,
            unique_note_hashes: tx.note_hashes,
            first_nullifier: tx.nullifiers.get(0),
        },
    ));
    let notes = s.env.execute_utility(PssPublicTest::at(s.app).partial_notes(s.user));
    assert_eq(notes.count, 1);
    assert_eq(notes.first, PartialOutcome { code: 0, amount: 24000, request_id: id });
}

// A third changed after the nodes signed the round: that node's signature
// does not verify, so neither the note hash nor the write lands.
#[test(should_fail_with = "node 2's result signature does not verify")]
unconstrained fn a_chain_held_outcome_with_a_tampered_third_is_refused() {
    let s = setup();
    init(s, P0);
    let id = request(s);
    let r = result(s, id, P0, P1, APPLIED);
    let sealed = thirds(2);
    let _ = submit_with(s, r, tampered(sealed, 2), signatures(s, r, sealed));
}

// Node-held signatures (H(sealed_i) = 0) do not cover the round's thirds.
#[test(should_fail_with = "node 0's result signature does not verify")]
unconstrained fn a_chain_held_outcome_signed_without_thirds_is_refused() {
    let s = setup();
    init(s, P0);
    let id = request(s);
    let r = result(s, id, P0, P1, APPLIED);
    let sigs = result_signatures(s.app.to_field(), id, [P0], [], [P1], NodeHeld {}.sealed_hashes());
    let _ = submit_with(s, r, thirds(2), sigs);
}
