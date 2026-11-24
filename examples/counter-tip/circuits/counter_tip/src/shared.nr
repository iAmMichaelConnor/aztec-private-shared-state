//! The add round under a secret-shared intake with a private outcome: what
//! the intake adds to `counter::add`. C opens to the shared amount, then
//! `$partial_note`, `$outcome_key` and `$outcome_tag`, under `$blinding`
//! (code `CODE_INPUTS_MISMATCH`, ahead of the app's codes); the total is
//! written under the fresh blinding whatever the outcome, the new total
//! only when C opens and the add is ok; the outcome `[code, total]`
//! completes the requester's partial note at `OUTCOME_SLOT` and is
//! encrypted under that note hash's nonce.
//!
//! The public outputs are pss_core's `Private<1, 1, 0, 1, 3>` after the
//! public parameters `[namespace, vk_hash, in_slots[0], out_slots[0]]`:
//! `[request_id, machine_request_id, old_c, new_c, npk_app_hash,
//! outcome_tag, note_hash, ciphertext[3]]`, the layout pss_public_contract's
//! `outcome_public_inputs` rebuilds. No amount, total or requester among them.
use crate::counter::{add, CODE_INPUTS_MISMATCH, OUTCOME_FIELDS, outcome_fields};
use pss_core::tip::family::Family;
use pss_core::tip::intake::SharedIntake;
use pss_core::tip::outcome::Private;
use pss_core::tip::outputs::Finished;
use pss_core::tip::slot::{Loaded, Round};

/// The outcome ciphertext's length: the outcome fields and the AEAD tag.
pub global CIPHERTEXT_LEN: u32 = OUTCOME_FIELDS + 1;

/// The storage slot of the contract's outcome notes (its first storage
/// variable, which its TXE suite pins against `get_state().outcome_slot`):
/// where every round's completed note lives. A constant of the circuit, so
/// no node can put the note where the requester's client does not look.
pub global OUTCOME_SLOT: Field = 0x1;

/// The add round's public outputs: one key read and written, no leaf hash,
/// one completed note hash and the ciphertext.
pub type SharedAdd = Private<1, 1, 0, 1, CIPHERTEXT_LEN>;

/// An add round finished: the round over the counter key and its public
/// outputs; the main ends in `stored`, which hands the total to the machine.
pub type AddRound = Finished<Round<1>, SharedAdd>;

/// One add under a secret-shared intake, total, in pss_core's three family
/// calls (`tip::family`): the check that C opens to `[amount]` and the
/// reserved values (code 1 first); `counter::add`; the total written in the
/// private form (a fresh blinding on every outcome, the sum only when C
/// opens and the add is ok); `[code, total]` encrypted and the partial note
/// completed with it and the chain request id. A failed add completes its
/// note too, `[code, 0, request_id]`, so the chain cannot tell an add from a
/// failure.
///
/// Constraints: the family's (C: one p2_hash and one equality; the write;
/// the outcome's machine request id, AEAD, note hash and npk_app_hash) and
/// `counter::add`'s. No assert.
pub fn add_shared(vk_hash: Field, key: Loaded<1>, amount: Field, shared: SharedIntake, nsk_app: Field) -> AddRound {
    let checked = shared.check([amount], CODE_INPUTS_MISMATCH);
    let a = add(key.fields[0], amount, checked.first);
    let round = checked.write(key.change(a.outcome, [a.total]));
    checked.finish(round, key.namespace, vk_hash, [amount], [], (), outcome_fields(a), OUTCOME_SLOT, nsk_app)
}

mod tests {
    use super::{add_shared, AddRound, OUTCOME_SLOT};
    use crate::counter::{CODE_INPUTS_MISMATCH, CODE_OVERFLOW, OUTCOME_FIELDS};
    use pss_core::tip::intake::{commit, shared, SharedIntake};
    use pss_core::tip::outcome::{encrypt_mismatch, encrypt_outcome, EncryptedOutcome, partial_commitment};
    use pss_core::tip::slot::{commitment, load};

    // the fixture scenario of counter_add's Prover.toml
    global NS: Field = 0xc0ffee;
    global SLOT: Field = 0xa003;
    global VK: Field = 0x5a5a;
    global R_OLD: Field = 333;
    global R_NEW: Field = 444;
    global OWNER: Field = 0xa11ce;
    global RHO: Field = 0x5eed;
    global KEY: Field = 0x6b6b;
    global TAG: Field = 0x7a7a;
    global BLINDING: Field = 0xb1b1;
    global NSK: Field = 777;

    fn intake(amount: Field, blinding: Field) -> SharedIntake {
        let partial = partial_commitment(OWNER, RHO);
        SharedIntake {
            inputs_hash: commit([amount, partial, KEY, TAG], BLINDING),
            partial,
            outcome_key: KEY,
            outcome_tag: TAG,
            blinding,
        }
    }

    fn run(total: Field, amount: Field, blinding: Field) -> AddRound {
        add_shared(VK, load(NS, SLOT, SLOT, [total], R_OLD, R_NEW), amount, intake(amount, blinding), NSK)
    }

    /// The round's outcome is `fields`: the note hash completes the partial
    /// note with them and the ciphertext encrypts them under its nonce.
    fn assert_outcome(r: AddRound, fields: [Field; OUTCOME_FIELDS]) {
        let request_id = r.outputs.request_id;
        assert_sealed(r, encrypt_outcome(fields, KEY, partial_commitment(OWNER, RHO), OUTCOME_SLOT, request_id));
    }

    /// The round's outcome is the mismatch seal: the code alone, under the
    /// mismatch domain's nonce.
    fn assert_mismatch(r: AddRound) {
        let request_id = r.outputs.request_id;
        assert_sealed(
            r,
            encrypt_mismatch(CODE_INPUTS_MISMATCH, KEY, partial_commitment(OWNER, RHO), OUTCOME_SLOT, request_id),
        );
    }

    fn assert_sealed(r: AddRound, e: EncryptedOutcome<OUTCOME_FIELDS + 1>) {
        assert_eq(r.outputs.note_hashes, [e.note_hash]);
        assert_eq(r.outputs.ciphertext, e.ciphertext);
    }

    #[test]
    fn an_add_writes_the_new_total_and_tells_the_requester() {
        let r = run(10, 5, BLINDING);
        assert_eq(r.written.fields, [15]);
        assert_eq(r.outputs.old_commitments, [commitment(NS, SLOT, [10], R_OLD)]);
        assert_eq(r.outputs.new_commitments, [commitment(NS, SLOT, [15], R_NEW)]);
        assert_eq(r.outputs.request_id, shared(NS, VK, intake(5, BLINDING).inputs_hash));
        assert_eq(r.outputs.outcome_tag, TAG);
        assert_outcome(r, [0, 15]);
    }

    // shares that do not open C: code 1, the total kept under the fresh
    // blinding, so the slot write tells nothing; the request id the queued one
    #[test]
    fn a_mismatch_keeps_the_total_and_re_blinds_it() {
        let r = run(10, 5, BLINDING + 1);
        assert_eq(r.written.fields, [10]);
        assert_eq(r.outputs.new_commitments, [commitment(NS, SLOT, [10], R_NEW)]);
        assert(r.outputs.new_commitments != r.outputs.old_commitments);
        assert_eq(r.outputs.request_id, shared(NS, VK, intake(5, BLINDING).inputs_hash));
        assert_mismatch(r);
    }

    #[test]
    fn an_overflow_keeps_the_total_and_completes_a_zero_note() {
        let r = run(0xffffffffffffffff, 1, BLINDING);
        assert_eq(r.written.fields, [0xffffffffffffffff]);
        assert_outcome(r, [CODE_OVERFLOW, 0]);
    }
}
