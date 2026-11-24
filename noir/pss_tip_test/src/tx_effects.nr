//! The last transaction's effects as a suite checks them: the note-hash
//! nonce and tree leaf of a note it pushed, the leaf of a raw note hash, and
//! assertions on its note hashes and nullifiers. Shared by every contract
//! suite, the sidecar examples' included.
use aztec::protocol::address::AztecAddress;
use aztec::protocol::hash::{
    compute_note_hash_nonce, compute_siloed_note_hash, compute_siloed_nullifier,
    compute_unique_note_hash,
};
use aztec::test::helpers::txe_oracles;

/// The protocol nonce of the note hash the last tx pushed at `index`:
/// derived from that tx's first nullifier and the note's position in it,
/// exactly what a PXE stores alongside a discovered note.
pub unconstrained fn nonce_in_last_tx(index: u32) -> Field {
    compute_note_hash_nonce(txe_oracles::get_last_tx_effects().nullifiers.get(0), index)
}

/// The note-hash-tree leaf the last tx created at `index`: tx effects
/// carry settled (unique) note hashes, i.e. the tree leaves.
pub unconstrained fn leaf_in_last_tx(index: u32) -> Field {
    txe_oracles::get_last_tx_effects().note_hashes.get(index)
}

/// The note-hash-tree leaf of a raw note hash the contract pushed.
pub unconstrained fn leaf(contract_addr: AztecAddress, note_hash: Field, nonce: Field) -> Field {
    compute_unique_note_hash(nonce, compute_siloed_note_hash(contract_addr, note_hash))
}

/// Assert the last tx's note hashes are exactly `expected`, in order.
pub unconstrained fn assert_last_note_hashes<let N: u32>(expected: [Field; N]) {
    let note_hashes = txe_oracles::get_last_tx_effects().note_hashes;
    assert_eq(note_hashes.len(), N);
    for i in 0..N {
        assert_eq(note_hashes.get(i), expected[i]);
    }
}

/// Assert the last tx pushed `n` note hashes.
pub unconstrained fn assert_last_note_hash_count(n: u32) {
    assert_eq(txe_oracles::get_last_tx_effects().note_hashes.len(), n);
}

/// Assert the last tx emitted `nullifier` (siloed to the contract).
pub unconstrained fn assert_last_nullifier(contract_addr: AztecAddress, nullifier: Field) {
    let siloed = compute_siloed_nullifier(contract_addr, nullifier);
    let nullifiers = txe_oracles::get_last_tx_effects().nullifiers;
    let mut found = false;
    for i in 0..nullifiers.len() {
        if nullifiers.get(i) == siloed {
            found = true;
        }
    }
    assert(found, "nullifier not in the last tx's effects");
}
