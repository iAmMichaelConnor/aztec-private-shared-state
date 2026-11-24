//! The swap round's secret-shared-intake entry: amm_tip's swap with every request
//! input shared, the inputs bound through C and the outcome private, the
//! trader's partial note completed inside the co-SNARK (amm_tip shared.nr).
//! The round is the non-secret-shared swap's (amm_tip tip.nr `swap_round`)
//! under pss_core's `SharedIntake` family; only this main, which declares
//! the secret-shared layout, is its own,
//! since the public inputs differ from the non-secret-shared intakes' (no
//! ok, code or app output; the private outcome in their place).
//!
//! Public inputs (14), in ACIR order: the public parameters [namespace,
//! vk_hash, in_slots[0], out_slots[0]], then the return value (pss_core
//! `tip::outcome::Private`): [request_id, machine_request_id,
//! old_commitments[0], new_commitments[0], npk_app_hash, outcome_tag,
//! note_hashes[0], ciphertext[3]], pss_public_contract's
//! `outcome_public_inputs`. `note_hashes[0]` is the completed note
//! `[code, amount_out, request_id]` of the request's partial note; no
//! amount, owner or partial note is a public input.
//!
//! The manifest (manifests/amm_swap_tip_shared.json, intake
//! shared_receipt, outcome partial): the public prefix as the non-secret-shared swap's;
//! `inputs_hash` PUBLIC `$inputs_hash`; `amount_in`, `direction` and
//! `min_out` INPUT_SHARED by their names; `partial_note`, `outcome_key`,
//! `outcome_tag` and `blinding` the reserved INPUT_SHARED values; `pool` and
//! `r_old` LOAD $state_keys.reads[0]; `r_new` SAMPLE 1; `nsk_app` the fixed LOAD;
//! out0 stored under $state_keys.writes[0] with note hash `new_commitments[0]`;
//! the commitment slot's old `old_commitments[0]`.
//!
//! Constraints: those of amm_tip's `swap_round` under `SharedIntake` (its doc
//! comment classifies them); the TACEO_store oracle is unconstrained and side-effect-only. No
//! assert here, and no signature verified (the receipts are checked by the
//! user's request function in the contract).

use amm_tip::shared::SharedSwap;
use amm_tip::tip::swap_round;
use pss_core::tip::intake::SharedIntake;
use pss_core::tip::slot;

fn main(
    // ---- the public prefix, as the non-secret-shared swap's ----
    namespace: pub Field,
    vk_hash: pub Field,
    in_slots: pub [Field; 1],
    out_slots: pub [Field; 1],
    // ---- the secret-shared intake: C, then the values it commits to, in C's order ----
    inputs_hash: Field,
    // DEV DECISION: which inputs are hidden, default all three swap inputs
    // shared (INPUT_SHARED), so no node, the orchestrator or the proof's
    // public inputs hold the trade; the trader's partial note
    // (`$partial_note`, reserved and always shared) hides who it pays, and
    // `amount_out` reaches nobody but the trader (the completed note and
    // the ciphertext). A clear input (a PUBLIC request name) is cheaper and
    // shows the nodes that value; none of the swap's needs to be clear.
    // Design guide: "intake" (question 1).
    amount_in: Field,
    direction: Field,
    min_out: Field,
    partial_note: Field,
    outcome_key: Field,
    outcome_tag: Field,
    blinding: Field,
    // ---- the pool, LOADed: [reserve_x, reserve_y] and its blinding ----
    pool: [Field; 2],
    r_old: Field,
    // ---- the new blinding, SAMPLE 1; stored on every outcome ----
    r_new: Field,
    nsk_app: Field,
) -> pub SharedSwap {
    // BRICK shape = flat (pss_core::tip::slot::load). Alternatives: tree, tree_oblivious,
    // map_oblivious (pss_core tip::tree and tip::map). docs/design-guide/BRICKS.md#shape
    let key = slot::load(namespace, in_slots[0], out_slots[0], pool, r_old, r_new);
    // BRICK intake = shared_receipt, shared_onchain (pss_core::tip::intake::SharedIntake): one circuit
    // for both, the swap's family. Alternatives: onchain, receipt (amm_swap_tip). docs/design-guide/BRICKS.md#intake
    let family = SharedIntake { inputs_hash, partial: partial_note, outcome_key, outcome_tag, blinding };
    swap_round(vk_hash, key, [amount_in, direction, min_out], family, nsk_app).stored()
}
