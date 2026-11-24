// Manifest: examples/amm/manifests/amm_swap_total.json.
// examples/amm registers this circuit as it stands: its circuits/ directory
// links amm_swap_total to this package, and the manifest lives there with
// the example's other manifests (this example has none). examples/amm-tip
// writes its own round circuit on the amm_total library.
// - State mode: both keys are node-held: the pool is shared state, and an
//   abandoned round must not block other traders.
// - Consume: the pool key with policy "once", as for amm_swap. A failed
//   swap (ok = 0) consumes the state too and stores the old reserves under
//   a fresh blinding, so its note hash is new and the re-store rule
//   (DECISIONS.md, "CONSUME is `once` or `never`") holds; each pool state still answers
//   one evaluation.

use amm_total::swap::swap_total;
use pss_core::effects::{self, PssEffects};

/// One swap, total: consume the pool note, apply the trade if every check
/// passes, create the new pool note, and reveal (ok, code, amount_out).
/// The same round as examples/amm/circuits/amm_swap, rewritten so that no
/// input can make it unsatisfiable.
///
/// The contract proves `read_leaves[0]` is in the note-hash tree, pushes
/// `nullifiers[0]` and `new_note_hashes[0]`, asserts `npk_app_hash`, and
/// passes `amount_in` and `direction` in as public inputs, as for
/// amm_swap. The difference is what a bad request does. amm_swap types
/// `amount_in: u64` and `direction: bool`, so their entry range checks,
/// and Pool::swap's asserts, make the circuit unsatisfiable for a bad
/// request; no proof exists and the round cannot settle. Here both are
/// raw Fields and every check is a flag (see amm_total's swap.nr for the
/// codes): on failure the circuit still proves, the pool note is consumed
/// and re-created with the OLD reserves under fresh randomness,
/// amount_out is 0, and app_outputs carry ok = 0 with the first failing
/// code. The queue advances either way.
///
/// Public inputs (13), in ACIR order (pub params, then the return struct):
///   [namespace, owner, in_slots[0], out_slots[0],
///    amount_in, direction,
///    read_leaves[0], nullifiers[0], new_note_hashes[0], npk_app_hash,
///    app_outputs[0] = ok (0 or 1), app_outputs[1] = code (0 when ok),
///    app_outputs[2] = amount_out]
///
/// Constraints: those of swap_total (library entries only; its doc
/// comment lists and classifies them) and those of pss_core's
/// consume_note, create_note and npk_app_hash, read from their source:
/// - Poseidon2 hashes (protocol_types poseidon2_hash_with_separator over
///   noir-lang/poseidon v0.4.0 Poseidon2::hash with message_size equal to
///   the comptime array length): permutation black boxes and additions;
///   the length logic is compile-time, so no assert, RANGE or memory
///   opcode remains. Definitions. consume_note uses nsk_app directly as
///   the nullifier key, so it has nothing else.
/// - EmbeddedCurveScalar::from_field(nsk_app), once, in npk_app_hash:
///   std bn254::decompose, the core::limbs constraint set.
///   Hint-satisfiable for every Field.
/// - fixed_base_scalar_mul: one multi_scalar_mul black box on the fixed
///   generator (on the curve) with the canonical limbs of nsk_app (below
///   the Grumpkin group order, which exceeds the field modulus). The
///   black box's only failure source is an off-curve point, so it cannot
///   fail; nsk_app = 0 gives the point at infinity, which is defined.
/// - the TACEO_store oracle in create_note: an unconstrained,
///   side-effect-only call whose outputs constrain nothing. Its body's
///   only assert is j < 8 on the constant j = 0. It needs an oracle
///   resolver at execution time (scripts/check-noir.sh starts
///   scripts/oracle-stub.py), exactly as amm_swap does.
/// None of these is input-falsifiable, and main itself has no assert.
///
/// Hint rule: the library's hints, std's decompose hint, and the oracle
/// (whose answer is ignored).
///
/// Determinedness: the hashes and the scalar limbs are functions of the
/// inputs, and swap_total's outputs are determined (its doc comment), so
/// every public output is a function of the inputs and out0_randomness.
fn main(
    // ---- canonical public prefix ----
    namespace: pub Field,
    owner: pub Field,
    // Key binding: in_slots[0] comes from $state_keys.reads[0] and out_slots[0]
    // from $state_keys.writes[0]; both are baked into the note hashes, so a
    // request naming other keys gives a proof the contract rejects. The
    // pool key is on both sides.
    in_slots: pub [Field; 1],
    out_slots: pub [Field; 1],
    // ---- app public inputs, raw Fields ----
    // amount_in and direction are PUBLIC raw Fields. Public, as in
    // amm_swap: the contract binds them (a token transfer would use them)
    // and the chain sees the transfer anyway. Raw Fields, because a typed
    // parameter (u64, bool) emits an entry range check that a bad request
    // falsifies, which is exactly what a total circuit must not have;
    // swap_total converts them with flags (codes 2 and 3).
    // amount sold; must be a nonzero u64 for the trade to happen
    amount_in: pub Field,
    // 0 sells x for y, 1 sells y for x; anything else is rejected (code 3)
    direction: pub Field,
    // ---- consumed pool note: [reserve_x, reserve_y] ----
    in0_fields: [Field; 2],
    in0_randomness: Field,
    in0_nonce: Field,
    // ---- created pool note: blinding sampled by the network ----
    // The pool note is re-created on every outcome, under
    // this fresh blinding: with the new reserves on ok = 1, with the old
    // ones on ok = 0 (DECISIONS.md, "CONSUME is `once` or `never`": a total circuit in
    // note mode re-randomises on ok = false). A failed swap therefore
    // still spends the old note and leaves a new, unlinkable one.
    out0_randomness: Field,
    // nsk_app, the namespace's nullifier key, taken by this name (the fixed
    // LOAD nsk_app) and used directly as the key. The round outputs
    // npk_app_hash(nsk_app) for the contract's pin.
    nsk_app: Field,
) -> pub PssEffects<1, 1, 3> {
    let (pool_leaf, pool_nullifier) = effects::consume_note(
        namespace,
        owner,
        in_slots[0],
        in0_fields,
        in0_randomness,
        in0_nonce,
        nsk_app,
    );

    let result = swap_total(in0_fields, amount_in, direction);
    let new_pool_note_hash =
        effects::create_note(0, owner, out_slots[0], result.new_reserves, out0_randomness);

    PssEffects {
        read_leaves: [pool_leaf],
        nullifiers: [pool_nullifier],
        new_note_hashes: [new_pool_note_hash],
        npk_app_hash: effects::npk_app_hash(nsk_app),
        // The reveal: [ok, code, amount_out]. ok and the
        // first failing code tell the contract and the trader whether the
        // trade happened and why not; amount_out is 0 on failure. As in
        // amm_swap, amount_out with amount_in gives the pool's marginal
        // price, and two quotes solve both reserves up to rounding. The
        // code adds a little: code 4 says r_in >= 2^64 - amount_in,
        // code 5 says r_out * amount_in < r_in + amount_in, and
        // code 6 (reachable only with r_in = 0) names an empty input
        // reserve. Dropping the code (ok only) hides that and leaves the
        // contract unable to tell a bad request from a dust trade.
        app_outputs: [result.outcome.ok as Field, result.outcome.code, result.amount_out],
    }
}
