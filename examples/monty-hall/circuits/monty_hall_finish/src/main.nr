// Manifest: examples/monty-hall/manifests/monty_hall_finish.json.
// - State mode: the game-state key is client-held; the player
//   presents the record open_door returned. The round writes no key.
// - Consume: the game-state key with policy "once". Without it the player
//   could run finish with switch = false, read win, run it again on the
//   same record with switch = true, and land only the winning one. "once"
//   refuses any second request on the state, whatever its inputs; a retry
//   is FETCH by request id. Records are owner-bound, so the operator
//   cannot play the player's round, and the orchestrator sees ciphertext
//   only. "never" would hand the player the win.
// - switch: PUBLIC by name. The contract passes the choice the player
//   committed in switch_door, so the proof is bound to that choice.

use monty_hall::game_state::{GAME_STATE_FIELDS, GameState};
use pss_core::effects::{self, PssEffects};

/// Finish the game: consume the game state, apply the player's
/// stick-or-switch choice and reveal whether the player won. W = 0: the
/// state is nullified and nothing replaces it, which ends the phase
/// machine.
///
/// The contract proves `read_leaves[0]` is in the note-hash tree, pushes
/// `nullifiers[0]`, asserts `npk_app_hash`, and passes `switch` in as a
/// public input.
///
/// Public inputs (8), in ACIR order (pub params, then the return struct):
///   [namespace, owner, in_slots[0],
///    switch,
///    read_leaves[0], nullifiers[0], npk_app_hash,
///    app_outputs[0] = win]
fn main(
    // ---- canonical public prefix (W = 0: no out_slots) ----
    namespace: pub Field,
    owner: pub Field,
    // Key binding: in_slots[0] comes from $state_keys.reads[0],
    // the key LOAD reads, and is baked into the note hash, so the record
    // the nodes opened is the note the contract read-requests at the
    // game-state slot.
    in_slots: pub [Field; 1],
    // ---- app public input ----
    // true (1) switches to the remaining door, false (0) sticks; typed,
    // so the machine range-checks it before the mesh
    switch: pub bool,
    // ---- consumed game state (from the player's state record) ----
    in0_fields: [Field; GAME_STATE_FIELDS],
    in0_randomness: Field,
    in0_nonce: Field,
    // nsk_app, the namespace's nullifier key, taken by this name (the fixed
    // LOAD nsk_app) and used directly as the key. The round outputs
    // npk_app_hash(nsk_app) for the contract's pin.
    nsk_app: Field,
) -> pub PssEffects<1, 0, 1> {
    let (game_leaf, game_nullifier) = effects::consume_note(
        namespace,
        owner,
        in_slots[0],
        in0_fields,
        in0_randomness,
        in0_nonce,
        nsk_app,
    );

    // asserts phase STATE_OPENED_DOOR
    let game = GameState::from_field_array(in0_fields);
    let win = GameState::switch(game, switch);

    PssEffects {
        read_leaves: [game_leaf],
        nullifiers: [game_nullifier],
        new_note_hashes: [],
        npk_app_hash: effects::npk_app_hash(nsk_app),
        // The reveal: one evaluation reveals win. With the
        // player's door, the opened door and switch, it names the winning
        // door, which is the end of the game; the state is spent here. A
        // second evaluation with the other choice is what the consumed set
        // refuses.
        app_outputs: [win as Field],
    }
}
