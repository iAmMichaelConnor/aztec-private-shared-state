// Manifest: examples/monty-hall/manifests/monty_hall_open_door.json.
// - State mode: both keys are client-held: the player holds the game's
//   state record, presents it here and receives the next one. The request
//   names the game-state key as both reads[0] and writes[0].
// - DEV DECISION: consume policy, default "once" on the game-state key;
//   two evaluations on one state with different doors would reveal the
//   winning door (door 0 opens 2 and door 2 opens 0 only when door 1
//   wins), so a second evaluation is refused, whatever the door,
//   randomness or circuit, and a retry is FETCH by request id; "never"
//   would give the winning door away. Design guide: "consume policy".
//   Records are owner-bound, so the operator cannot play the player's
//   round, and the orchestrator sees ciphertext only.
// - door, door_randomness: INPUT_SHARED, each sent as three encrypted
//   replicated shares, so neither the orchestrator nor any single node
//   learns the door.

use monty_hall::door;
use monty_hall::game_state::{GAME_STATE_FIELDS, GameState};
use pss_core::effects::{self, PssEffects};

/// The host opens a door: consume the game state, apply the player's
/// door, open a door that is neither the player's nor the winning one,
/// and create the next game state in phase STATE_OPENED_DOOR.
///
/// The contract proves `read_leaves[0]` is in the note-hash tree, pushes
/// `nullifiers[0]` and `new_note_hashes[0]`, asserts `npk_app_hash`, and
/// read-requests the leaf of `app_outputs[1]`, the door commitment the
/// player pushed in choose_door, so the door the network played is the
/// committed one.
///
/// Public inputs (10), in ACIR order (pub params, then the return struct):
///   [namespace, owner, in_slots[0], out_slots[0],
///    read_leaves[0], nullifiers[0], new_note_hashes[0], npk_app_hash,
///    app_outputs[0] = opened_door, app_outputs[1] = door_commitment]
fn main(
    // ---- canonical public prefix ----
    namespace: pub Field,
    owner: pub Field,
    // Key binding: in_slots[0] comes from $state_keys.reads[0] and out_slots[0]
    // from $state_keys.writes[0]; both are baked into the note
    // hashes. The contract passes the game-state slot for both, so a
    // request naming other keys produces a proof the contract rejects.
    in_slots: pub [Field; 1],
    out_slots: pub [Field; 1],
    // ---- the player's door (INPUT_SHARED) ----
    // DEV DECISION: the door's visibility, default a private INPUT_SHARED
    // parameter, not a public input; as a public input (door: pub u8) the
    // orchestrator and all three nodes would learn it, and the game needs
    // nobody but the player to know it. The circuit range-checks it on
    // shares and outputs its commitment instead, which the contract pins
    // to the player's committed note. A public door would remove
    // door_randomness and the commitment output, at the cost of revealing
    // the choice. Design guide: "The questions, in order" (1, who must not
    // see the inputs).
    door: Field,
    // the commitment's blinding, chosen by the player in choose_door
    door_randomness: Field,
    // ---- consumed game state (from the player's state record) ----
    in0_fields: [Field; GAME_STATE_FIELDS],
    in0_randomness: Field,
    in0_nonce: Field,
    // ---- created game state: blinding sampled by the network ----
    out0_randomness: Field,
    // nsk_app, the namespace's nullifier key, taken by this name (the fixed
    // LOAD nsk_app) and used directly as the key. The round outputs
    // npk_app_hash(nsk_app) for the contract's pin.
    nsk_app: Field,
) -> pub PssEffects<1, 1, 2> {
    // BRICK path = sidecar (pss_core::effects::consume_note): the round returns PssEffects, which the
    // contract's apply lands. Alternatives: tip (with node-held state). docs/design-guide/BRICKS.md#path
    let (game_leaf, game_nullifier) = effects::consume_note(
        namespace,
        owner,
        in_slots[0],
        in0_fields,
        in0_randomness,
        in0_nonce,
        nsk_app,
    );

    // door < 3 on shares; the game logic asserts the phase
    let chosen = door::assert_door(door);
    let game = GameState::from_field_array(in0_fields);
    let (next_game, opened_door) = GameState::choose_door(game, chosen);
    let next_game_note_hash = effects::create_note(
        0,
        owner,
        out_slots[0],
        next_game.as_field_array(),
        out0_randomness,
    );

    PssEffects {
        read_leaves: [game_leaf],
        nullifiers: [game_nullifier],
        new_note_hashes: [next_game_note_hash],
        npk_app_hash: effects::npk_app_hash(nsk_app),
        // The reveal: one evaluation reveals opened_door,
        // which rules out one door other than the player's: the game's own
        // reveal. When the player's door is not the winner, opened_door is
        // the third door and so names the winner to whoever knows the
        // player's door; that is the game, and only the player knows it.
        // door_commitment hides the door behind door_randomness. A second
        // evaluation with another door would reveal the winner outright,
        // which is why the manifest consumes the state.
        app_outputs: [opened_door as Field, door::door_commitment(door, door_randomness)],
    }
}
