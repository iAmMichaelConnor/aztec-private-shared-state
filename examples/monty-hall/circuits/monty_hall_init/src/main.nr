// Manifest: examples/monty-hall/manifests/monty_hall_init.json.
// - DEV DECISION: state mode, default client-held for every key of the
//   game (seed and game state); the game is single-owner state that only
//   its own rounds transition, so the state record travels with the game
//   and the nodes keep no row. Node-held would suit state that many users
//   transition, which a game is not. Design guide: "State mode". The
//   player, as this round's requester, receives the record and presents
//   it at open_door; the same key signed pss_seed and presents the seed
//   record here.
// - Consume: the seed key with policy "once", the default. The round reads
//   the seed and writes the game elsewhere, so the seed record could
//   otherwise be presented again: two games derived from one seed would
//   share their winning door. "once" gives the seed one evaluation, and
//   a retry is FETCH by request id. Records are owner-bound, so the
//   operator cannot start the player's game, and the orchestrator sees
//   ciphertext only. "never" would let a holder mint many games from one
//   seed.

use monty_hall::game_state::GameState;
use pss_core::effects::{self, PssEffects};

/// Start the game: consume the seed note, derive the game state from the
/// seed (the winning door and the in-state PRNG), and create the
/// game-state note in phase STATE_INITIALIZED.
///
/// The contract proves `read_leaves[0]` is in the note-hash tree, pushes
/// `nullifiers[0]` and `new_note_hashes[0]`, and asserts `npk_app_hash`
/// against the identity it pins.
///
/// Public inputs (8), in ACIR order (pub params, then the return struct):
///   [namespace, owner, in_slots[0], out_slots[0],
///    read_leaves[0], nullifiers[0], new_note_hashes[0], npk_app_hash]
fn main(
    // ---- canonical public prefix ----
    namespace: pub Field,
    owner: pub Field,
    // Key binding: in_slots[0] (from $state_keys.reads[0], the
    // key LOAD reads) and out_slots[0] (from $state_keys.writes[0], the key
    // STORE writes) are the note slots baked into the note hashes, so the
    // value loaded is the note read-requested, and the stored value is the
    // note pushed. For a client-held key the record's associated data
    // names the key too, so a record cannot be presented under another.
    // the seed note's slot
    in_slots: pub [Field; 1],
    // the game-state note's slot
    out_slots: pub [Field; 1],
    // ---- consumed seed note (from the seed's state record) ----
    in0_fields: [Field; 1],
    in0_randomness: Field,
    // protocol nonce; self-verifying: a wrong nonce yields a leaf the
    // contract's read request cannot find
    in0_nonce: Field,
    // ---- created game-state note: blinding sampled by the network ----
    out0_randomness: Field,
    // nsk_app, the namespace's nullifier key, taken by this name (the fixed
    // LOAD nsk_app) and used directly as the key. The round outputs
    // npk_app_hash(nsk_app) for the contract's pin.
    nsk_app: Field,
) -> pub PssEffects<1, 1, 0> {
    let (seed_leaf, seed_nullifier) = effects::consume_note(
        namespace,
        owner,
        in_slots[0],
        in0_fields,
        in0_randomness,
        in0_nonce,
        nsk_app,
    );

    let game = GameState::init(in0_fields[0]);
    let game_note_hash = effects::create_note(
        0,
        owner,
        out_slots[0],
        game.as_field_array(),
        out0_randomness,
    );

    PssEffects {
        read_leaves: [seed_leaf],
        nullifiers: [seed_nullifier],
        new_note_hashes: [game_note_hash],
        npk_app_hash: effects::npk_app_hash(nsk_app),
        // The reveal: no app outputs. One evaluation reveals
        // the seed's leaf and nullifier and the new note hash, none of
        // which says anything about the winning door, so the round leaks
        // nothing about the state. Outputting anything derived from the
        // game state here would reveal it before the player chooses.
        app_outputs: [],
    }
}
