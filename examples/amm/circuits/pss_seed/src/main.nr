// The generic seed round, one package for both machine examples:
// examples/monty-hall reaches it through the link circuits/pss_seed ->
// ../../amm/circuits/pss_seed. Each namespace registers it under its own
// manifest.
// - examples/amm/manifests/pss_seed.json: the written key is node-held. The
//   seed feeds the shared pool, so no single user may hold it; a client-held
//   seed would make the pool depend on whoever holds the record.
// - examples/monty-hall/manifests/pss_seed.json: the seed key is
//   client-held. The player runs this round as the requester, receives the
//   seed's state record and presents it to monty_hall_init under the same
//   key (records are owner-bound, so the seed's owner is the game's owner).
//   Node-held would keep the seed as a row at the nodes instead, so the
//   player would carry no seed record, at the cost of a values table.
// - owner: each manifest's const 0xafafaf must equal the owner its contract
//   pins; it is baked into the note hash.
// - DEV DECISION: init strategy, default a seed round before the app's init
//   round (amm_init, monty_hall_init): rand_seed and out0_randomness are
//   SAMPLE 1 each, so no party knows the seed, and so no party chose or
//   knows what the init derives from it (the AMM's starting price, the
//   winning door); public constants would publish it. Nothing proves
//   randomness; the proof shows only that the note hash commits to a value
//   the network holds as shares. Design guide: "init strategy".
// - Leakage: no app outputs. One evaluation reveals the note hash only,
//   which the blinding hides.

use pss_core::effects::{self, PssEffects};

/// The generic seed round: create a one-field note whose content is fresh
/// shared randomness, at the slot the request names.
///
/// The network samples `rand_seed` and `out0_randomness` as secret shares,
/// so no party knows the seed. The contract pushes `new_note_hashes[0]`;
/// a later round consumes the note and derives its state from the seed.
/// Nothing is nullified, so the circuit takes no nullifier key and
/// outputs 0 as npk_app_hash.
///
/// Public inputs (5), in ACIR order (pub params, then the return struct):
///   [namespace, owner, out_slots[0],
///    new_note_hashes[0], npk_app_hash = 0]
fn main(
    // ---- canonical public prefix ----
    namespace: pub Field,
    // the network's address-like identity, baked into the note hash
    owner: pub Field,
    // Key binding: out_slots[0] is the storage slot baked
    // into the note hash and is filled from $state_keys.writes[0], the key
    // STORE writes the seed to.
    out_slots: pub [Field; 1],
    // ---- created note: blinding sampled by the network ----
    out0_randomness: Field,
    // ---- fresh shared randomness: the note's only field ----
    rand_seed: Field,
) -> pub PssEffects<0, 1, 0> {
    // namespace appears in no hash here (nothing is consumed); it
    // stays a public input so every circuit shares the canonical prefix
    let _ = namespace;
    let seed_note_hash = effects::create_note(0, owner, out_slots[0], [rand_seed], out0_randomness);
    PssEffects {
        read_leaves: [],
        nullifiers: [],
        new_note_hashes: [seed_note_hash],
        npk_app_hash: 0,
        app_outputs: [],
    }
}
