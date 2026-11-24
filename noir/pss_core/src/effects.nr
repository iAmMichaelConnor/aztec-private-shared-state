//! The canonical return value of every PSS round circuit, and the helpers
//! that compute its entries.
//!
//! The verifying contract forwards these values to the protocol kernel:
//! a read request for each `read_leaves[i]`, `nullifiers[i]` as a
//! nullifier, `new_note_hashes[j]` as a new note hash, and it asserts
//! `npk_app_hash` against the network identity it pinned. Because every
//! circuit returns the same layout, the contract-side library and the
//! machine are the same for every app.
//!
//! ACIR orders public inputs as pub parameters in declaration order, then
//! the return value flattened in field order, so the field order below
//! is part of the public-input layout. Do not reorder it. A circuit's
//! public inputs are `3 + 3R + 2W + P + A` fields:
//! `[namespace, owner, in_slots[R], out_slots[W], app_inputs[P],
//!   read_leaves[R], nullifiers[R], new_note_hashes[W], npk_app_hash,
//!   app_outputs[A]]`.

use crate::{aztec_note, mpc_store};
use protocol_types::traits::{Deserialize, Serialize};

/// `R` notes consumed, `W` notes created, `A` app public outputs.
///
/// What a round reveals: everything here and every `pub`
/// parameter is public on chain: the slots, the leaves, the nullifiers,
/// the new note hashes, npk_app_hash and the app outputs. Stored fields,
/// blindings and nsk_app never appear. `app_outputs` is the only channel
/// that reveals anything about the shared state, so choose its entries
/// as the reveal you intend; a value derived from the state leaks what it
/// is a function of.
///
/// The contract library (`pss_contract`) takes this same struct as a
/// function argument, hence the serialization derives.
#[derive(Deserialize, Eq, Serialize)]
pub struct PssEffects<let R: u32, let W: u32, let A: u32> {
    /// unique note hash (note-hash-tree leaf) of each consumed note
    pub read_leaves: [Field; R],
    /// canonical nullifier of each consumed note, under nsk_app
    pub nullifiers: [Field; R],
    /// inner note hash of each created note (the contract pushes it; the
    /// kernel silos and uniquifies it)
    pub new_note_hashes: [Field; W],
    /// the network's nullifying identity for this namespace; 0 when R = 0
    pub npk_app_hash: Field,
    pub app_outputs: [Field; A],
}

/// A consumed (settled) note: returns `(read_leaf, nullifier)`.
///
/// The note hash is recomputed from the (secret-shared) preimage, so a
/// wrong preimage, slot, owner or nonce gives a leaf the contract's read
/// request cannot find. The nullifier is bound to that leaf and to the
/// namespace's nsk_app.
///
/// Key binding: `slot` is the note's storage slot and must
/// be `in_slots[i]`, the public parameter the manifest fills from
/// `$state_keys.reads[i]`, the same request field LOAD reads from. That makes
/// the value the nodes loaded and the note the contract read-requests the
/// same one. Passing any other slot breaks that binding.
pub fn consume_note<let N: u32>(
    contract_address: Field,
    owner: Field,
    slot: Field,
    fields: [Field; N],
    randomness: Field,
    nonce: Field,
    nsk_app: Field,
) -> (Field, Field) {
    let note_hash = aztec_note::note_hash(slot, owner, fields, randomness);
    let read_leaf = aztec_note::unique_note_hash(contract_address, note_hash, nonce);
    let nullifier = aztec_note::note_nullifier(read_leaf, nsk_app);
    (read_leaf, nullifier)
}

/// A created note at position `j` of `out_slots`: returns its inner note
/// hash and hands its preimage to the machine under the key `out<j>`.
///
/// Key binding: `slot` must be `out_slots[j]`, the public
/// parameter the manifest fills from `$state_keys.writes[j]`, the key STORE
/// writes `out<j>` to. The stored vector is `[fields..., randomness]`, so
/// its length (the manifest's `len`) is N + 1.
pub fn create_note<let N: u32>(
    j: u32,
    owner: Field,
    slot: Field,
    fields: [Field; N],
    randomness: Field,
) -> Field {
    // Safety: side-effect-only oracle (see mpc_store); the next round
    // needs these shares to open the note
    unsafe { mpc_store::store_out_note(j, fields, randomness) };
    aztec_note::note_hash(slot, owner, fields, randomness)
}

/// The network identity `npk_app_hash` for the namespace's nsk_app.
///
/// nsk_app is a private parameter named `nsk_app`, filled
/// by the fixed manifest entry `LOAD nsk_app` (slice [0, 1], len 1). The
/// nodes derived it at the namespace's first REGISTER; it is the
/// nullifier key directly. Every circuit that consumes a note (R > 0)
/// outputs this hash, and the contract asserts it against the value its
/// Config pins. A circuit with R = 0 takes no key and outputs 0.
pub fn npk_app_hash(nsk_app: Field) -> Field {
    aztec_note::npk_app_hash(nsk_app)
}

mod tests {
    use super::create_note;

    global OWNER: Field = 0x1122;
    global SLOT: Field = 3;
    global RAND: Field = 0x99;

    #[test(should_fail_with = "out index too large")]
    fn create_note_rejects_out_index_past_max() {
        let _ = create_note(8, OWNER, SLOT, [0x42], RAND);
    }
}
