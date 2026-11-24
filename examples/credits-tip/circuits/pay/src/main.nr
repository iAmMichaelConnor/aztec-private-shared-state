//! pay: credit `amount` to `key` (credits_tip ledger.nr `pay`), an insert
//! where the key is absent and an addition where it is present, under
//! secret-shared receipt intake with a private outcome (credits_tip
//! shared.nr). The map's `tree` entry says `access: oblivious, keyed:
//! true`: the key is a shared input (no node sees which entry the round
//! touches), the slot's leaf, old hash and 64 siblings are the nodes'
//! oblivious RAM reads (three LOAD slices), and the circuit verifies the
//! path along the key's own low 64 bits (pss_core `tip::map`).
//!
//! Public inputs (16), in ACIR order: [namespace, vk_hash, in_slots[0],
//! out_slots[0]], then pss_core `Private<1, 1, 0, 1, 5>`: [request_id,
//! machine_request_id, old_commitments[0], new_commitments[0], npk_app_hash,
//! outcome_tag, note_hashes[0], ciphertext[5]]. The completed note is
//! `[code, ROUND_PAY, amount, 0, request_id]`.
//!
//! The manifest (manifests/pay.json, intake shared_receipt): the public
//! prefix; `inputs_hash` PUBLIC `$inputs_hash`; `key` and `amount`
//! INPUT_SHARED; `partial_note`, `outcome_key`, `outcome_tag` and `blinding`
//! the reserved INPUT_SHARED values; `leaves`, `old_hashes` and `siblings`
//! the three LOAD slices of the key ([0, 3], [3, 4], [4, 68]); `r_new`
//! SAMPLE 1; `nsk_app` the fixed LOAD; out0 stored under $state_keys.writes[0]
//! (68 elements: the leaf, its new hash and 64 path nodes) with note hash
//! `new_commitments[0]`.
//!
//! Constraints: credits_tip's `pay` and `finish` (through shared.nr's entry,
//! stored here) (their doc comments classify them); the TACEO_store oracle is unconstrained and
//! side-effect-only. No assert here.

use credits_tip::ledger::{DEPTH, LEAF_LEN};
use credits_tip::shared::{self, Prefix, Shared, SharedIntake, Slots};

fn main(
    // ---- the public prefix, as every round's ----
    namespace: pub Field,
    vk_hash: pub Field,
    in_slots: pub [Field; 1],
    out_slots: pub [Field; 1],
    // ---- the secret-shared intake: C, then the values it commits to, in C's order ----
    inputs_hash: Field,
    // the key paid: the hash of the handle the payee handed out, computed in the
    // contract's request function (`map_key`), so no caller picks its bits (README)
    key: Field,
    amount: Field,
    partial_note: Field,
    outcome_key: Field,
    outcome_tag: Field,
    blinding: Field,
    // ---- the map's slot, the nodes' oblivious RAM reads (three LOAD slices) ----
    leaves: [[Field; LEAF_LEN]; 1],
    old_hashes: [Field; 1],
    siblings: [[Field; DEPTH]; 1],
    // ---- the new blinding, SAMPLE 1 ----
    r_new: [Field; 1],
    nsk_app: Field,
) -> pub Shared {
    shared::pay(
        Prefix { namespace, vk_hash, in_slots, out_slots },
        SharedIntake { inputs_hash, partial: partial_note, outcome_key, outcome_tag, blinding },
        [key, amount],
        Slots { leaves, old_hashes, siblings },
        r_new,
        nsk_app,
    )
        .stored()
}
