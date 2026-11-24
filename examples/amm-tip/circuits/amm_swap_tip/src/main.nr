// Registered under examples/amm-tip/manifests/amm_swap_tip.json (on-chain
// intake) and amm_swap_tip_receipt.json (receipt intake): one compiled
// circuit for both non-secret-shared intakes. The inputs, the request's partial note
// and user_nonce fill private parameters; no parameter names the requester (the
// hidden requester).

use amm_tip::tip::{swap_round, SwapOutputs};
use pss_core::tip::family::Plain;
use pss_core::tip::outputs::BoundPartial;
use pss_core::tip::slot;

/// One swap of the AMM at the tip, total: no input makes it
/// unsatisfiable. A request that cannot trade still proves, with ok = 0,
/// its code, amount_out = 0 and new_c = old_c, so it applies as a no-op
/// and the queue moves on (docs/ARCHITECTURE.md section 6).
///
/// One compiled circuit for both non-secret-shared intakes: the inputs, the
/// partial note and user_nonce are private witnesses, and the circuit outputs
/// the non-secret-shared intakes' binding (pss_core tip::intake::plain), the
/// chain request id poseidon2(namespace, vk_hash, inputs_hash, user_nonce),
/// with inputs_hash = poseidon2(amount_in, direction, min_out, partial_note),
/// both by total's fixed-length p2_hash. Under on-chain intake the request
/// log has already published the inputs; under receipt intake they never
/// reach the chain.
///
/// Value delivery is the public completion (manifest `outcome: partial`,
/// docs/ARCHITECTURE.md section 6, "Completion in a public function"): the round echoes the
/// request's partial note right after `ok`, and the contract's `apply`
/// completes it with `[code, amount_out, request_id]` on every round, so
/// the trader's note lands with the result under an owner nobody but the
/// trader sees.
///
/// Public inputs (12), in ACIR order (pub params, then the return struct):
///   [namespace, vk_hash, in_slots[0], out_slots[0],
///    request_id, old_c, new_c, npk_app_hash, ok, partial_note, code,
///    amount_out]
///
/// The pool key (pss_core tip::slot::load), the swap under the
/// non-secret-shared family (amm_tip's swap_round with pss_core's
/// `family::Plain`), then the store of the pool it leaves and the outputs
/// (tip::outputs::BoundPartial).
///
/// Constraints: those of amm_tip's swap_round under `Plain` (amm_total's
/// swap_total, two fixed-length Poseidon2 commitments, one field comparison
/// and selects, two p2_hash for the request id and pss_core's
/// npk_app_hash: the std scalar decomposition of nsk_app (hint-satisfiable
/// for every Field) and one fixed-base multi_scalar_mul on the generator,
/// which cannot fail; its doc comment classifies them). The TACEO_store oracle is
/// unconstrained and side-effect-only; it needs a resolver at execution
/// (scripts/oracle-stub.py under check-noir). No assert here; no signature
/// is verified here (the receipts are checked by the user's intake
/// function, in the contract, and no round circuit may verify ECDSA:
/// co-noir does not implement it).
fn main(
    // ---- public prefix ----
    // the namespace, PUBLIC $namespace (the app contract's address), the
    // manifest's namespace_param. Named `namespace` in every example on both
    // paths; it enters the commitments and the request id.
    namespace: pub Field,
    // vk_hash, a public input. A circuit cannot know its own verification
    // key's hash, so it takes it as an input, hashes it into request_id, and
    // process_result checks it against the vk hash the Config pins.
    vk_hash: pub Field,
    // key binding: in_slots[0] from $state_keys.reads[0] (the key
    // LOAD reads) and out_slots[0] from $state_keys.writes[0] (the key STORE
    // writes) are bound into old_c and new_c, and process_result passes
    // the contract's own pool slot for both, so a proof over another key
    // does not verify: the pool key on both sides.
    in_slots: pub [Field; 1],
    out_slots: pub [Field; 1],
    // ---- app inputs, private raw Fields ----
    // private raw Fields. Private, so receipt intake keeps
    // them off chain (on-chain intake's request log publishes them anyway)
    // and both intakes share this circuit: only request_id, the
    // commitments, ok, the partial note, the code and amount_out are
    // public. Raw Fields,
    // because a typed parameter (u64, bool) emits an entry range check a
    // bad request falsifies; swap_round flags each one (codes 2, 3 and 8).
    // the amount sold; a nonzero u64 for the trade to happen
    amount_in: Field,
    // 0 sells x for y, 1 sells y for x; anything else is code 3
    direction: Field,
    // the least amount_out the trader accepts; 0 for no limit (code 8)
    min_out: Field,
    // the request's partial note, PUBLIC $partial_note: the contract's
    // request function computes it from the sender and the client's rho
    // (pss_public_contract partial_note::commit), never an address (the
    // hidden requester); the round echoes it for apply's completion
    partial_note: Field,
    // user_nonce, private: the client's random salt, so request_id hides
    // the inputs under receipt intake. Not checked here (any value gives
    // some request id, and apply compares it with the queue).
    user_nonce: Field,
    // ---- the pool, LOADed: [reserve_x, reserve_y] and its blinding ----
    pool: [Field; 2],
    r_old: Field,
    // ---- the new blinding, SAMPLE 1; used only when ok ----
    r_new: Field,
    // nsk_app by the fixed LOAD nsk_app, only to output npk_app_hash: a
    // round on node-held state nullifies nothing, and the hash ties the
    // proof to the network that holds this namespace's key.
    nsk_app: Field,
) -> pub BoundPartial<SwapOutputs> {
    // BRICK shape = flat (pss_core::tip::slot::load). Alternatives: tree, tree_oblivious,
    // map_oblivious (pss_core tip::tree and tip::map). docs/design-guide/BRICKS.md#shape
    let key = slot::load(namespace, in_slots[0], out_slots[0], pool, r_old, r_new);
    // BRICK intake = onchain, receipt (pss_core::tip::family::Plain), one circuit for both: the
    // request id over the app inputs and the partial note.
    // Alternatives: shared_receipt, shared_onchain (amm_swap_tip_shared). docs/design-guide/BRICKS.md#intake
    // BRICK value = partial (pss_core::tip::family::Plain), the partial note echoed after ok and
    // completed in public by apply. Alternatives: none (Written::bound). docs/design-guide/BRICKS.md#value
    let family = Plain { partial_note, user_nonce };
    // the app inputs in ABI order; the request id hashes them and then the
    // partial note, the order of the circuit's parameters, so the hash
    // follows the ABI; the contract's intake
    // functions and the nodes' intake hash the same list. Adding an input
    // (a deadline) appends it here and changes every request id.
    swap_round(vk_hash, key, [amount_in, direction, min_out], family, nsk_app).stored()
}
