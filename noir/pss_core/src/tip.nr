//! The tip round helpers: what every round circuit at the tip of the chain
//! shares, so that a round main is the key, the app's round function, the
//! intake's binding and the outputs.
//!
//! - `slot`: a chain-held key. Its contract slot holds the slot
//!   commitment; a round loads the vector and its blinding (`load`), and
//!   leaves either the new vector under the sampled blinding or the
//!   loaded one under its old blinding (`Loaded::finish`, which enforces
//!   the fail rule), with the commitment it read and the one it leaves;
//!   under private outcomes it leaves either under the sampled blinding
//!   (`Loaded::finish_private`); an init round creates it (`create`).
//! - `intake`: one binding per intake family. The non-secret-shared intakes (on-chain
//!   intake and receipt intake): the chain request id over the private
//!   inputs and nonce. The secret-shared intakes: the id over the inputs
//!   commitment C, and the receipts' summand commitments and sharing
//!   digest (`summand_commitment`, `sharing_digest`).
//! - `family`: the intake family as one interface (`Family`, `Finish`),
//!   implemented by `Plain` (the non-secret-shared intakes) and
//!   `SharedIntake` (the secret-shared intakes): the check a round makes
//!   first (whether C opens), the form of its write (`Change`, one
//!   implementation per state shape: `slot::SlotChange`, `map::MapChange`)
//!   and its public outputs, so an app writes its round once over the
//!   family; and a main's public prefix (`Prefix`).
//! - `tree`: a tree-valued node-held key. Its slot holds the commitment
//!   of a Poseidon2 Merkle tree's root; a round loads the leaves it
//!   touches with their old hashes and paths (`tree::load`, or
//!   `tree::empty` when it creates the key), which check each old leaf
//!   and flag the paths and indices, and `Tree::update` writes the new
//!   leaves and rebuilds the root, with the commitment it read and the one
//!   it leaves (`Tree::update_private` under private outcomes, re-blinding
//!   every leaf the round holds).
//! - `map`: a keyed map, the tree loaded with the keys' paths in place of
//!   indices (`map::load`, `map::empty`), with per slot whether a key is
//!   present or another key takes its leaf, and the keyed update that
//!   writes the slot's key into its leaf (`Map::update`,
//!   `Map::update_private`).
//! - `outputs`: what a round leaves at its key whatever its shape
//!   (`Written`: a flat key's `Round`, a tree's `Updated`), and the public
//!   outputs built from it, with the store: the non-secret-shared intakes' (`bound`, the
//!   binding first) and the init round's (`init`).
//! - `outcome`: private outcomes, for the secret-shared intakes: the machine request
//!   id, the outcome's encryption under `$outcome_key` and the completion of
//!   the request's partial note (`partial_commitment`, `completed_note_hash`,
//!   `encrypt_outcome`, or `encrypt_mismatch` when the shares do not open C,
//!   each under its note hash's nonce, `seal_nonce`), and the round's public
//!   outputs (`finish`:
//!   `Private`, or `Valued` with K app values after it, public values of the
//!   attempt the app's apply reads, e.g. the inputs-opened bit of an app
//!   that escrows).
//! - `handle`: the standing delivery handle, for a round that delivers a
//!   note and an outcome to a party other than its requester: the handle an
//!   entry holds (a partial commitment and a key), its completion
//!   (`deliver`), the filler of a round that completes none (`filler`), and
//!   the public outputs with the deliveries after the app values
//!   (`Delivered`).
//! - `exit`: the exit tag of a tree-valued key's entries, for an app with
//!   an escape hatch: each written entry leaf holds the tag of its newest
//!   note and the round outputs the tag it replaces, which the landing
//!   emits as a nullifier (`Tree::update_private_tagged`, `Tagged`), so an
//!   owner exits a frozen app by pushing its note's tag once.
//! - `derived`: secret-shared on-chain intake's encoding, the derived intake
//!   shares: the PRF, the seeds and wraps, the shares and corrections of the
//!   request's values, node i's pair, and the padded request log with its
//!   data hash.
//!
//! The app's round function is written once, generic over the intake
//! family, and takes the app inputs as one array in ABI order; the main
//! declares the ABI and names the family, and one compiled main serves both
//! intakes of a family. A round main:
//!
//! ```noir
//! let key = slot::load(namespace, in_slots[0], out_slots[0], pool, r_old, r_new);
//! let family = Plain { partial_note, user_nonce };
//! app::round(vk_hash, key, [amount_in, direction, min_out], family, nsk_app).stored()
//! ```
//!
//! Every helper is total (permutation black boxes, additions and selects)
//! and runs in co-noir. testvectors/slot_commitment.json and
//! testvectors/chain_request_id.json hold their known answers, which
//! testvectors/noir/tip_round_vectors checks with these functions.
pub mod derived;
pub mod exit;
pub mod family;
pub mod handle;
pub mod intake;
pub mod outcome;
pub mod outputs;
pub mod slot;
pub mod map;
pub mod tree;
