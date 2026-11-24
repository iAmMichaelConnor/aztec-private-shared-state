//! The contract's single-reader state, as ordinary PXE notes.
//!
//! Where state lives (docs/DECISIONS.md, "Where state lives on Aztec"):
//! each value here has exactly one reader, so it is an aztec-nr note owned
//! by that reader and held in the reader's PXE, which
//! supplies the preimage and the nonce when the reader's own call reads
//! it:
//! - `Config`, the deployment pins, owned by the operator (read in
//!   start_game);
//! - `Game`, the pins the player's calls need, owned by the player (read in
//!   choose_door, open_door, switch_door and finish_game);
//! - `DoorNote` and `SwitchNote`, the player's two choices, owned by the
//!   player (read in open_door and finish_game).
//! Nothing here is many-reader, so the contract anchors nothing. The seed
//! and the game state are different: nobody may see them, so they live in
//! the sidecar and reach the chain only as raw note hashes.
use aztec::{
    context::PrivateContext,
    keys::getters::{get_nhk_app, get_public_keys, try_get_public_keys},
    macros::notes::{custom_note, note},
    note::{note_interface::NoteHash, utils::compute_note_nullifier},
    protocol::{
        address::AztecAddress,
        traits::{Deserialize, Packable, Serialize},
    },
};
use monty_hall_circuit::door::door_commitment;

/// The door the player committed to, with the randomness that hides it.
///
/// The note hash is the door commitment the open_door circuit outputs, so
/// the leaf the player's PXE proves in open_door is the same value the
/// network's proof is checked against.
///
/// The door note's hash is not aztec-nr's default note hash.
/// It must equal the circuit's commitment, which binds only the door and
/// the player's randomness: not the owner, the storage slot or the note's
/// own randomness. That is safe here because only the player can call
/// choose_door, only once, and the hash is siloed to this contract and
/// carries its own separator. `randomness` is chosen by the player and
/// must be uniformly random: with only three doors, a guessable value
/// lets anyone test them. The player sends the same door and randomness to
/// the network as INPUT_SHARED shares in open_door.
#[derive(Deserialize, Eq, Packable, Serialize)]
#[custom_note]
pub struct DoorNote {
    pub door: u8,
    pub randomness: Field,
}

impl DoorNote {
    /// The open_door circuit's `app_outputs[1]` for this door: the
    /// circuit's own `door_commitment` (`monty_hall::door`), so open_door
    /// pins the player's door note to exactly what the round outputs.
    pub fn commitment(self) -> Field {
        door_commitment(self.door as Field, self.randomness)
    }
}

impl NoteHash for DoorNote {
    fn compute_note_hash(
        self,
        _owner: AztecAddress,
        _storage_slot: Field,
        _randomness: Field,
    ) -> Field {
        self.commitment()
    }

    // The canonical owner nullifier the #[note] macro would generate. The
    // contract never nullifies a door note; the nullifier exists so the
    // note behaves like any other in the PXE.
    fn compute_nullifier(
        self,
        context: &mut PrivateContext,
        owner: AztecAddress,
        note_hash_for_nullification: Field,
    ) -> Field {
        let owner_npk_m_hash = get_public_keys(owner).npk_m_hash;
        let secret = context.request_nhk_app(owner_npk_m_hash);
        compute_note_nullifier(note_hash_for_nullification, [secret])
    }

    unconstrained fn compute_nullifier_unconstrained(
        self,
        owner: AztecAddress,
        note_hash_for_nullification: Field,
    ) -> Option<Field> {
        try_get_public_keys(owner).map(|public_keys| {
            let secret = get_nhk_app(public_keys.npk_m_hash);
            compute_note_nullifier(note_hash_for_nullification, [secret])
        })
    }
}

/// Stick (false) or switch (true). Only the contract reads it: finish_game
/// passes it to the finish circuit as its public app input. So it is an
/// ordinary note with aztec-nr's note hash, hidden by the note randomness
/// the PXE samples.
#[derive(Deserialize, Eq, Packable, Serialize)]
#[note]
pub struct SwitchNote {
    pub switch: bool,
}

/// The deployment pins, owned by the operator: whoever calls init_game
/// becomes the operator and the owner of this note. Read only by the
/// operator's start_game.
///
/// The deployment pins: every field is fixed at init_game;
/// changing one means a new deployment.
/// - `player` commits the choices and submits open_door and finish_game:
///   start_game creates the `Game` note for this address only;
/// - `owner` must equal the manifests' `owner` const, which the circuits
///   bake into every network-held note hash;
/// - `npk_app_hash` is the value the namespace's first REGISTER returned:
///   only that network can nullify the seed and game notes;
/// - the four vk hashes (pss_seed, monty_hall_init, monty_hall_open_door,
///   monty_hall_finish) name the only circuits whose proofs each call
///   accepts; register first, then pin the hashes the nodes agreed on.
/// The operator is trusted for liveness only: it chooses these pins and
/// start_game copies them into the player's `Game`. A pin that differs from
/// the network and circuits the player's rounds run under fails the
/// player's own open_door or finish_game; it cannot change a result.
#[derive(Deserialize, Eq, Packable, Serialize)]
#[note]
pub struct Config {
    pub player: AztecAddress,
    pub owner: Field,
    pub npk_app_hash: Field,
    pub seed_vk_hash: Field,
    pub init_vk_hash: Field,
    pub open_vk_hash: Field,
    pub finish_vk_hash: Field,
}

/// The pins the player's calls need, copied from the `Config` by
/// start_game and owned by the player. open_door and finish_game take the
/// network pin and their vk hash from it; choose_door and switch_door read
/// it only to require a started game for the caller.
///
/// What the Game holds: exactly the `Config` fields a call
/// of the player uses, so the player's PXE holds no pin it never checks;
/// the seed and init vk hashes stay with the operator. A game whose player
/// calls needed another pin would add it here and copy it in start_game.
#[derive(Deserialize, Eq, Packable, Serialize)]
#[note]
pub struct Game {
    pub owner: Field,
    pub npk_app_hash: Field,
    pub open_vk_hash: Field,
    pub finish_vk_hash: Field,
}
