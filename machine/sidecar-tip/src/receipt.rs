//! The tip's receipt under the non-secret-shared intakes, as a node signs it
//! (docs/ARCHITECTURE.md section 1, the hash table's receipt message;
//! section 6, the receipts row): the ids it covers, the message, the signer
//! with its derived nonce, and the verifier.
//!
//! ```text
//! inputs_hash = poseidon2(inputs)
//! request_id  = poseidon2([namespace, vk_hash, inputs_hash, user_nonce])
//! message     = poseidon2([RECEIPT_DOMAIN, request_id, inputs_hash, expiry_block])
//! signature   = Schnorr over Grumpkin (noir-lang/schnorr v0.4.0) by node i's `sig` key
//! ```
//!
//! Secret-shared receipt intake signs a five-element message over the inputs
//! commitment and the sharing digest ([`crate::ids::shared_receipt_message`])
//! with the same signer.
//!
//! The receipt route signs and checks with it (crate::intake::route), and
//! receipt intake's resync hook checks a neighbour's copied rows against the
//! receipt signatures and signs them again with this node's key
//! (crate::intake::receipt).

use sidecar_core::field::Fr;
use sidecar_core::grumpkin::{Fq, Point};
use sidecar_core::hash::poseidon2_hash;
use sidecar_core::register::Signature;
use sidecar_core::schnorr::{sign_derived, verify};

/// `inputs_hash = poseidon2(inputs)`, the app's circuit inputs in ABI order
/// (the contract's `inputs_hash` intake helper, total-noir's `p2_hash`).
pub fn inputs_hash(inputs: &[Fr]) -> Fr {
    poseidon2_hash(inputs)
}

/// The chain request id the contract computes at intake under the non-secret-shared
/// intakes: `poseidon2([namespace, vk_hash, inputs_hash(inputs),
/// user_nonce])`.
pub fn chain_request_id(namespace: Fr, vk_hash: Fr, inputs: &[Fr], user_nonce: Fr) -> Fr {
    poseidon2_hash(&[namespace, vk_hash, inputs_hash(inputs), user_nonce])
}

// RECEIPT_DOMAIN, the first element of the receipt message, is
// ASCII "sidecar.receipt" read as a big-endian integer, the value of
// pss_public_contract's `domains.nr` `RECEIPT_DOMAIN` and in the family of
// the machine's other domain elements (RESULT_DOMAIN "sidecar.result",
// REGISTRY_DOMAIN "sidecar.registry", PSS_ATTEMPT "sidecar.attempt"). A
// node's `sig` key signs results, registry answers and receipts; a distinct
// first element keeps a receipt from verifying as either of the others, or
// the other way round. Every node signs under it and every tip contract
// checks it; changing it invalidates every receipt and needs every tip
// contract redeployed.
/// ASCII "sidecar.receipt".
pub const RECEIPT_DOMAIN: u128 = 0x736964656361722e72656365697074;

/// The label of the receipt-signature nonce derivation.
pub const RECEIPT_NONCE_LABEL: &[u8] = b"sidecar.receipt_nonce";

/// The receipt message:
/// `poseidon2([RECEIPT_DOMAIN, request_id, inputs_hash, expiry_block])`, with
/// `request_id` the chain request id.
pub fn receipt_message(request_id: Fr, inputs_hash: Fr, expiry_block: u32) -> Fr {
    poseidon2_hash(&[
        Fr::from(RECEIPT_DOMAIN),
        request_id,
        inputs_hash,
        Fr::from(u64::from(expiry_block)),
    ])
}

// A receipt's Schnorr nonce is derived, like a result's (step 14), not drawn
// like a registry answer's (schnorr::sign_derived under RECEIPT_NONCE_LABEL):
// a node asked twice for the same receipt answers the same bytes, so the
// route's idempotent case needs no stored randomness.
/// Node `sig`'s receipt over `message` (either intake's), on the
/// machine's Schnorr signer with the derived nonce. It verifies under
/// noir-lang/schnorr v0.4.0 and `schnorr::verify`.
///
/// Panics if `sig` is zero, which has no public key.
pub fn sign_receipt_message(sig: Fq, message: Fr) -> Signature {
    sign_derived(sig, RECEIPT_NONCE_LABEL, message)
}

/// Node `sig`'s receipt over (request_id, inputs_hash, expiry_block)
/// ([`receipt_message`], [`sign_receipt_message`]). It verifies under
/// [`verify_receipt`].
///
/// Panics if `sig` is zero, which has no public key.
pub fn sign_receipt(sig: Fq, request_id: Fr, inputs_hash: Fr, expiry_block: u32) -> Signature {
    sign_receipt_message(sig, receipt_message(request_id, inputs_hash, expiry_block))
}

/// Whether `signature` is node `sig_pk`'s receipt over (request_id,
/// inputs_hash, expiry_block).
pub fn verify_receipt(
    sig_pk: Point,
    signature: Signature,
    request_id: Fr,
    inputs_hash: Fr,
    expiry_block: u32,
) -> bool {
    verify(
        sig_pk,
        signature,
        receipt_message(request_id, inputs_hash, expiry_block),
    )
}
