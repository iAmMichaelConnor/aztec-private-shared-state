//! The add round under secret-shared receipt intake: counter_tip's add with
//! the amount shared, bound through C, and the outcome private, the
//! requester's partial note completed inside the co-SNARK (counter_tip
//! shared.nr).
//!
//! Public inputs (14), in ACIR order: [namespace, vk_hash, in_slots[0],
//! out_slots[0]], then pss_core `tip::outcome::Private`: [request_id,
//! machine_request_id, old_commitments[0], new_commitments[0], npk_app_hash,
//! outcome_tag, note_hashes[0], ciphertext[3]].
//!
//! The manifest (manifests/counter_add.json, intake shared_receipt, outcome
//! partial): the public prefix; `inputs_hash` PUBLIC $inputs_hash; `amount`
//! INPUT_SHARED "amount"; `partial_note`, `outcome_key`, `outcome_tag` and
//! `blinding` the reserved INPUT_SHARED values; `total` and `r_old` LOAD
//! $state_keys.reads[0]; `r_new` SAMPLE 1; `nsk_app` the fixed LOAD; out0
//! stored under $state_keys.writes[0] with note hash `new_commitments[0]`.
use counter_tip::shared::{add_shared, SharedAdd};
use pss_core::tip::intake::SharedIntake;
use pss_core::tip::slot;

fn main(
    // ---- the public prefix ----
    namespace: pub Field,
    vk_hash: pub Field,
    in_slots: pub [Field; 1],
    out_slots: pub [Field; 1],
    // ---- the secret-shared intake: C, then the values it commits to, in C's order ----
    inputs_hash: Field,
    // DEV DECISION: which inputs are hidden, default the amount shared
    // (INPUT_SHARED), so no node, the orchestrator or the proof's public
    // inputs hold it. A clear amount (PUBLIC "amount" in the manifest) costs
    // less and shows the nodes the value. Design guide: "intake" (question 1).
    amount: Field,
    partial_note: Field,
    outcome_key: Field,
    outcome_tag: Field,
    blinding: Field,
    // ---- the counter, LOADed: [total] and its blinding; the new blinding, SAMPLE 1 ----
    total: [Field; 1],
    r_old: Field,
    r_new: Field,
    nsk_app: Field,
) -> pub SharedAdd {
    // BRICK shape = flat (pss_core::tip::slot::load). Alternatives: tree, tree_oblivious,
    // map_oblivious (pss_core tip::tree and tip::map). docs/design-guide/BRICKS.md#shape
    let key = slot::load(namespace, in_slots[0], out_slots[0], total, r_old, r_new);
    // BRICK intake = shared_receipt, shared_onchain (pss_core::tip::intake::SharedIntake): one circuit
    // for both. Alternatives: onchain, receipt (a non-secret-shared main of its own, amm_swap_tip).
    // docs/design-guide/BRICKS.md#intake
    let shared = SharedIntake { inputs_hash, partial: partial_note, outcome_key, outcome_tag, blinding };
    add_shared(vk_hash, key, amount, shared, nsk_app).stored()
}
