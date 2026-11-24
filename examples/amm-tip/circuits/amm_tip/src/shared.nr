//! The swap under a secret-shared intake (docs/ARCHITECTURE.md section 6, "Secret-shared
//! intake" and "Private outcomes"): what the secret-shared family of the swap
//! round (`tip.nr`'s `swap_round` under pss_core's `SharedIntake`) adds to
//! the swap, its code, its outcome's layout and its note's slot.
//!
//! - The inputs commitment. The round takes the app inputs `[amount_in,
//!   direction, min_out]`, the reserved `$partial_note`, `$outcome_key` and
//!   `$outcome_tag`, the `$blinding` and C (`$inputs_hash`), every one
//!   shared but C, and checks first that C opens to them (the family's
//!   check, code 9: a flag, so shares that do not open make a failed round,
//!   never an unsatisfiable one). The request id is the secret-shared one
//!   over C.
//! - The write: `Loaded::finish_private` (the family's form of the pool's
//!   write), a fresh blinding on every outcome, so new_c differs from old_c
//!   whatever the outcome and the slot write tells nothing; the new
//!   reserves land only when C opens.
//! - The outcome `[code, amount_out]` (`code = 0` says the swap traded),
//!   encrypted under `$outcome_key` with the nonce of its note hash, and the
//!   request's partial note completed with it and the chain request id: the completed
//!   note `[code, amount_out, request_id]` the trader's PXE holds and
//!   redeems (docs/ARCHITECTURE.md section 6, "Partial-note delivery").
//!   The round sees no owner: the partial note hides it.
//!
//! The public outputs are pss_core's `Private`, the layout
//! pss_public_contract's `outcome_public_inputs` rebuilds: `[request_id,
//! machine_request_id, old_c, new_c, npk_app_hash, outcome_tag, note_hash,
//! ciphertext[3]]` after the public parameters `[namespace, vk_hash,
//! in_slots[0], out_slots[0]]`. No amount and no recipient among them.
use pss_core::tip::outcome::Private;
use pss_core::tip::outputs::Finished;
use pss_core::tip::slot::Round;

/// The shares do not open to the request's C (the MPC receipt check).
pub global CODE_INPUTS_MISMATCH: Field = 9;

/// The outcome plaintext's length, `[code, amount_out]`; the completed note
/// packs these and the chain request id.
pub global OUTCOME_FIELDS: u32 = 2;

/// The outcome ciphertext's length: the two outcome fields and the AEAD
/// tag.
pub global CIPHERTEXT_LEN: u32 = OUTCOME_FIELDS + 1;

/// The storage slot of the AMM contract's swap notes
/// (examples/amm-tip/contract `outcome_notes`, the contract's first storage
/// variable, which its TXE suite pins against the contract's
/// `get_state().outcome_slot`), where every secret-shared swap's completed
/// note lives. A constant of the circuit, so no node can put the note where
/// the trader's client does not look; a change to the contract's storage
/// that moves the slot moves this.
pub global OUTCOME_SLOT: Field = 0x1;

/// The secret-shared swap's public outputs: one key read and written (the
/// pool), no tree, one completed note hash and the three-field ciphertext.
pub type SharedSwap = Private<1, 1, 0, 1, CIPHERTEXT_LEN>;

/// A secret-shared swap finished (`tip.nr`'s `swap_round` under
/// `SharedIntake`): the round over the pool key and its public outputs; the
/// main ends in `stored`, which hands the pool to the machine (TACEO_store
/// "out0").
pub type SharedRound = Finished<Round<2>, SharedSwap>;

mod tests {
    use super::{CODE_INPUTS_MISMATCH, OUTCOME_FIELDS, OUTCOME_SLOT};
    use crate::tip::{CODE_MIN_OUT, PlainRound, swap_round};
    use pss_core::tip::family::Plain;
    use amm_total::swap::CODE_ZERO_INPUT;
    use pss_core::tip::intake::{commit, shared, SharedIntake};
    use pss_core::tip::outcome::{
        completed_note_hash, encrypt_mismatch, encrypt_outcome, EncryptedOutcome, machine_request_id,
        partial_commitment,
    };
    use pss_core::tip::slot::{commitment, load};

    // The fixture scenario of the non-secret-shared swaps (tip.nr's tests), with the
    // shared values of amm_swap_tip_shared's Prover.toml.
    // BEGIN written by scripts/gen-noir-vectors.py from testvectors/slot_commitment.json
    // testvectors/slot_commitment.json vectors[0]: the pool amm_init_tip's
    // Prover.toml creates, Pool::from_seed(111), under blinding R_OLD in
    // namespace NS at slot SLOT
    global NS: Field = 0xc0ffee;
    global SLOT: Field = 0xa002;
    global POOL: [Field; 2] = [1359373, 1852331];
    global R_OLD: Field = 333;
    // END written by scripts/gen-noir-vectors.py
    global VK: Field = 0x5a5a;
    global R_NEW: Field = 444;
    // the trader's address and its client's rho: the request's partial note
    // is partial_commitment(OWNER, RHO), which the round never opens
    global OWNER: Field = 0xa11ce;
    global RHO: Field = 0x5eed;
    global KEY: Field = 0x6b6b;
    global TAG: Field = 0x7a7a;
    global BLINDING: Field = 0xb1b1;
    global NSK: Field = 777;

    fn partial() -> Field {
        partial_commitment(OWNER, RHO)
    }

    fn intake(inputs: [Field; 3], blinding: Field) -> SharedIntake {
        SharedIntake {
            inputs_hash: commit(inputs.concat([partial(), KEY, TAG]), BLINDING),
            partial: partial(),
            outcome_key: KEY,
            outcome_tag: TAG,
            blinding,
        }
    }

    fn run(inputs: [Field; 3], blinding: Field) -> super::SharedRound {
        swap_round(VK, load(NS, SLOT, SLOT, POOL, R_OLD, R_NEW), inputs, intake(inputs, blinding), NSK)
    }

    /// The round's outcome is `fields`, `[code, amount_out]`: the note hash
    /// the partial note completed with them and the request id, the
    /// ciphertext their encryption under that note hash's nonce.
    fn assert_outcome(r: super::SharedRound, fields: [Field; OUTCOME_FIELDS]) {
        assert_sealed(r, encrypt_outcome(fields, KEY, partial(), OUTCOME_SLOT, r.outputs.request_id));
    }

    /// The round's outcome is the mismatch seal: the code alone, under the
    /// mismatch domain's nonce.
    fn assert_mismatch(r: super::SharedRound) {
        let request_id = r.outputs.request_id;
        assert_sealed(r, encrypt_mismatch(CODE_INPUTS_MISMATCH, KEY, partial(), OUTCOME_SLOT, request_id));
    }

    fn assert_sealed(r: super::SharedRound, e: EncryptedOutcome<OUTCOME_FIELDS + 1>) {
        assert_eq(r.outputs.note_hashes, [e.note_hash]);
        assert_eq(r.outputs.ciphertext, e.ciphertext);
    }

    // The trade of the non-secret-shared Prover.toml: the same reserves and amount out,
    // under the fresh blinding, the request id over C, the request's partial
    // note completed with the outcome and the outcome encrypted under its
    // note hash's nonce.
    #[test]
    fn a_shared_trade_is_the_plain_trade_completed_privately() {
        let inputs = [25000, 0, 33000];
        let r = run(inputs, BLINDING);
        let plain: PlainRound = swap_round(
            VK,
            load(NS, SLOT, SLOT, POOL, R_OLD, R_NEW),
            inputs,
            Plain { partial_note: partial(), user_nonce: 3 },
            NSK,
        );
        assert(r.written.outcome.ok);
        assert_eq(r.written.fields, plain.written.fields);
        assert_eq(r.written.new_c, plain.written.new_c);
        let o = r.outputs;
        let c = intake(inputs, BLINDING).inputs_hash;
        assert_eq(o.request_id, shared(NS, VK, c));
        assert_eq(o.machine_request_id, machine_request_id(o.request_id, [commitment(NS, SLOT, POOL, R_OLD)], []));
        assert_eq(o.old_commitments, [commitment(NS, SLOT, POOL, R_OLD)]);
        assert_outcome(r, [0, 33450]);
        assert_eq(o.outcome_tag, TAG);
    }

    // Shares that do not open to C (another blinding): code 9, whatever the
    // swap would have done; the pool kept under the fresh blinding; the
    // request id still the queued one; the note completed with nothing out.
    #[test]
    fn a_mismatch_is_code_9_first_and_re_blinds_the_pool() {
        let inputs = [25000, 0, 33000];
        let r = run(inputs, BLINDING + 1);
        assert(!r.written.outcome.ok);
        assert_eq(r.written.outcome.code, CODE_INPUTS_MISMATCH);
        assert_eq(r.written.fields, POOL);
        assert_eq(r.written.new_c, commitment(NS, SLOT, POOL, R_NEW));
        assert(r.written.new_c != r.written.old_c);
        assert_eq(r.outputs.request_id, shared(NS, VK, intake(inputs, BLINDING).inputs_hash));
        assert_mismatch(r);
        // a request that is malformed as well still reports the mismatch
        assert_eq(run([0, 0, 0], BLINDING + 1).written.outcome.code, CODE_INPUTS_MISMATCH);
    }

    // A swap that fails on the pool: its non-secret-shared code, the pool
    // kept under the fresh blinding, and a completed note of the same shape
    // as a trade's with a zero amount.
    #[test]
    fn a_failed_swap_completes_a_zero_note_and_re_blinds_the_pool() {
        let r = run([25000, 0, 33451], BLINDING);
        assert_outcome(r, [CODE_MIN_OUT, 0]);
        assert_eq(r.written.new_c, commitment(NS, SLOT, POOL, R_NEW));
        assert(r.written.new_c != r.written.old_c);
        assert_outcome(run([0, 0, 0], BLINDING), [CODE_ZERO_INPUT, 0]);
    }

    // The round completes whatever partial note the request committed: another
    // owner's or another rho's partial note gives another note hash, so the
    // note belongs to whoever opened the partial note in the request.
    #[test]
    fn the_note_is_the_partial_notes_owners() {
        let inputs = [25000, 0, 33000];
        let r = run(inputs, BLINDING);
        let other = partial_commitment(OWNER + 1, RHO);
        assert(r.outputs.note_hashes[0] != completed_note_hash(OUTCOME_SLOT, other, [0, 33450], r.outputs.request_id));
    }
}
