//! The result message every node signs over a committed round, and its
//! check.

use super::*;

// ---------------------------------------------------------------------------
// The result message
// ---------------------------------------------------------------------------

// The result signature. Node i signs every committed round with
// its `sig` key over poseidon2(RESULT_DOMAIN, namespace, request_id, new
// commitments..., i, H(sealed_i)): the new commitments are the note hashes of
// the round's outputs in manifest order (read from the public inputs at the
// manifest's note-hash indices), `i` is the node's index, and H(sealed_i) is
// Poseidon2 over the list of record hashes of node i's new record thirds in
// manifest output order (0 when the round makes none). RESULT_DOMAIN is ASCII
// "sidecar.result" read as a big-endian integer, which keeps a result
// signature from being read as a registry answer or a receipt signed by the
// same key. The sealed replaced vectors stay inside the node and are not
// signed. A client, the orchestrator and the tip's process_result rebuild the
// message from the namespace, the request id, the proof's public inputs and
// the returned thirds, and require all three signatures; changing any part of
// the message changes every one of those checks.
/// ASCII "sidecar.result".
pub const RESULT_DOMAIN: u128 = 0x736964656361722e726573756c74;

/// `H(sealed_i)`: Poseidon2 over the record hashes of node i's new thirds, in
/// manifest output order; 0 when there are none.
pub fn sealed_hash(record_hashes: &[Fr]) -> Fr {
    if record_hashes.is_empty() {
        Fr::zero()
    } else {
        poseidon2_hash(record_hashes)
    }
}

/// The result message node `node` signs.
pub fn result_message(
    namespace: Fr,
    request_id: RequestId,
    commitments: &[Fr],
    node: usize,
    sealed: Fr,
) -> Fr {
    let mut inputs = vec![Fr::from(RESULT_DOMAIN), namespace, request_id.fr()];
    inputs.extend_from_slice(commitments);
    inputs.push(Fr::from(node as u64));
    inputs.push(sealed);
    poseidon2_hash(&inputs)
}

/// The new commitments of a round: the public inputs at the manifest outputs'
/// note-hash indices, in manifest order. 500 if a proof is too short for them.
pub fn result_commitments(shape: &CircuitShape, public_inputs: &[Fr]) -> Result<Vec<Fr>, Refusal> {
    shape
        .outputs
        .iter()
        .map(|o| {
            public_inputs
                .get(o.note_hash_index)
                .copied()
                .ok_or_else(|| {
                    Refusal::mpc_failure(format!(
                        "the proof has {} public inputs, none at the note-hash index {} of `{}`",
                        public_inputs.len(),
                        o.note_hash_index,
                        o.taceo_store
                    ))
                })
        })
        .collect()
}

/// Whether `result` carries node `node`'s valid signature under `sig_pk`, the
/// key the checker pinned: the message is rebuilt from the namespace, the
/// result's request id and public inputs, and the record hashes of its thirds.
pub fn verify_result_signature(
    sig_pk: Point,
    namespace: Fr,
    shape: &CircuitShape,
    result: &NodeResult,
    node: usize,
) -> Result<bool, Refusal> {
    let public_inputs: Vec<Fr> = result.public_inputs.iter().map(|f| f.fr()).collect();
    let commitments = result_commitments(shape, &public_inputs)?;
    let hashes = result
        .records
        .iter()
        .map(|r| record_hash(r.c_i.as_slice()))
        .collect::<Result<Vec<_>, _>>()?;
    let message = result_message(
        namespace,
        result.request_id,
        &commitments,
        node,
        sealed_hash(&hashes),
    );
    Ok(verify(sig_pk, result.signature, message))
}

/// The label of the result-signature nonce derivation
/// ([`schnorr::sign_derived`](crate::schnorr::sign_derived)): the result
/// signature's nonce is derived, not drawn, so the library needs no
/// randomness source from the node.
pub const RESULT_NONCE_LABEL: &[u8] = b"sidecar.result_nonce";

pub(super) fn sign_result(keys: &NodeKeys, message: Fr) -> Signature {
    sign_derived(keys.sig_scalar(), RESULT_NONCE_LABEL, message)
}
