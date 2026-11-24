//! Anchoring without storage. A contract pushes a raw note hash that no
//! PXE ever discovers, and later proves it exists with a kernel read
//! request over the leaf the caller recomposes from the preimage (an
//! argument) and the note's protocol nonce (a self-verifying hint mined
//! from the anchoring tx's effects).
//!
//! Where state lives: use an anchor for state many parties
//! must read whose preimage is not secret (a pool's Config): the preimage
//! is published, since every caller passes it as an argument. Use an
//! ordinary PXE note for state a single user owns and reads, and the
//! sidecar for state no single party may see. An anchor cannot be
//! updated in place; a new value is a new anchor, and callers must learn
//! its preimage and nonce.
use aztec::context::{NoteExistenceRequest, PrivateContext};
use aztec::protocol::address::AztecAddress;
use aztec::protocol::hash::{
    compute_siloed_note_hash, compute_unique_note_hash, poseidon2_hash_with_separator,
};

/// The note-hash-tree leaf of a raw note hash `this` contract pushed, from
/// the protocol nonce the kernel assigned when it settled.
pub fn anchor_leaf(this: AztecAddress, note_hash: Field, nonce: Field) -> Field {
    compute_unique_note_hash(nonce, compute_siloed_note_hash(this, note_hash))
}

/// Read-request the leaf of a note hash the calling contract pushed in an
/// earlier tx. A wrong preimage or nonce composes a leaf that is not in
/// the tree, and the kernel rejects the tx.
pub fn assert_anchored(context: &mut PrivateContext, note_hash: Field, nonce: Field) {
    let leaf = anchor_leaf(context.this_address(), note_hash, nonce);
    context.assert_note_exists(NoteExistenceRequest::for_settled(leaf));
}

/// A single-use flag: pushing the same nullifier twice is rejected by the
/// protocol.
///
/// A once-nullifier is public and deterministic, so anyone
/// can see that the step ran, and nobody can run it twice. Each contract
/// passes its own separator so the raw nullifier cannot collide with any
/// other nullifier it emits; reusing a separator across purposes lets one
/// step block another.
pub fn once_nullifier(domain_separator: u32, which: Field) -> Field {
    poseidon2_hash_with_separator([which], domain_separator)
}

/// Run a step once per deployment: push `once_nullifier(domain_separator,
/// which)`, which a second run of the step repeats and the protocol
/// rejects.
pub fn push_once(context: &mut PrivateContext, domain_separator: u32, which: Field) {
    context.push_nullifier_unsafe(once_nullifier(domain_separator, which));
}
