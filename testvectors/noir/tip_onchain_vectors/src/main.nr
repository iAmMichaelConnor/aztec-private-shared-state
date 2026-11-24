//! Checks testvectors/shared_onchain.json, secret-shared on-chain intake's derived
//! intake shares, with the functions the user's private function and the
//! contract library compute them with: pss_core's `tip::derived`
//! (`key_exchange`, `shares_of`, `wraps`, `pack_epochs`, `request_log`,
//! `data_hash`, each node's `node_pair`), the library's
//! `inputs_commitment`, `shared_chain_request_id` and `request_log_tag`,
//! aztec-nr's siloing of the private log's tag, the rotation message
//! (`enc_rotation_message`) and node 1's rotation signature under its `sig`
//! key, and the domain constants. Prover.toml is written from the vector file
//! by sidecar-tip (tests/write_vectors, write_shared_onchain_vectors);
//! `nargo execute` fails on any disagreement.

use aztec::protocol::address::AztecAddress;
use aztec::protocol::hash::compute_siloed_private_log_first_field;
use pss_core::tip::derived::{
    data_hash as hash_of_log, key_exchange, Layout, node_pair, pack_epochs, request_log,
    REQUEST_LOG_LEN, shares_of, SIDECAR_INTAKE_PRF, wraps as wraps_of,
};
use pss_public_contract::{
    enc_rotation_message, EncKey, inputs_commitment as commitment_of, PSS_ENC_ROTATE, Receipt,
    shared_chain_request_id,
};
use pss_public_contract::result::result_signature_verifies;
use pss_public_contract::shared_onchain::request_log_tag;
use pss_utils::dh::{ecdh_x, public_key};
use std::embedded_curve_ops::EmbeddedCurvePoint;

/// The vectors' round: five commitment values, one clear, four chosen.
global Q: u32 = 1;
global X: u32 = 4;
/// The shared values: the four of the five that are not clear, then
/// `$blinding`.
global K: u32 = 5;

struct Rotation {
    node: u32,
    x: Field,
    y: Field,
    epoch: u32,
    message: Field,
    signature: [Field; 4],
    sig_x: Field,
    sig_y: Field,
}

fn main(
    kinds: [u8; 5],
    values: [Field; 5],
    sidecar_intake_prf: Field,
    pss_enc_rotate: Field,
    namespace: Field,
    vk_hash: Field,
    eph: Field,
    epochs_packed: Field,
    eph_x: Field,
    blinding: Field,
    inputs_commitment: Field,
    chain_request_id: Field,
    tag: Field,
    siloed_tag: Field,
    data_hash: Field,
    node_enc: [Field; 3],
    epochs: [u32; 3],
    secrets: [Field; 3],
    wraps: [Field; 3],
    clear: [Field; Q],
    corrections: [Field; X],
    log: [Field; REQUEST_LOG_LEN],
    pairs: [Field; 2 * 3 * K],
    correction_at: [u32; K],
    rotation: Rotation,
) {
    assert_eq(sidecar_intake_prf, SIDECAR_INTAKE_PRF, "SIDECAR_INTAKE_PRF");
    assert_eq(pss_enc_rotate, PSS_ENC_ROTATE, "PSS_ENC_ROTATE");
    let ns = AztecAddress { inner: namespace };

    // the user's side: the key exchange with the nodes' keys, the encoding,
    // C, the id, the log and its hash
    let keys = node_enc.map(|k| public_key(k));
    let (s, ex) = key_exchange(eph, keys);
    assert_eq(s, secrets, "key-exchange secrets");
    assert_eq(ex, eph_x, "E.x");
    let layout: Layout<5, Q, X> = Layout { kinds };
    let enc = shares_of(layout, values, s);
    assert_eq(enc.blinding, blinding, "blinding");
    assert_eq(enc.clear, clear, "clear values");
    assert_eq(enc.corrections, corrections, "corrections");
    assert_eq(wraps_of(s), wraps, "wraps");
    assert_eq(pack_epochs(epochs), epochs_packed, "packed epochs");
    let c = commitment_of(values, enc.blinding);
    assert_eq(c, inputs_commitment, "C");
    let id = shared_chain_request_id(ns, vk_hash, c);
    assert_eq(id, chain_request_id, "chain request id");
    assert_eq(request_log_tag(id), tag, "request log tag");
    assert_eq(compute_siloed_private_log_first_field(ns, tag), siloed_tag, "siloed tag");
    let built = request_log(blinding, c, epochs_packed, ex, wraps, clear, corrections);
    assert_eq(built, log, "request log");
    assert_eq(hash_of_log(log), data_hash, "data hash");

    // each node's side: its secret from E and its scalar, and its pair of
    // every shared value from the log
    let e = public_key(eph);
    for i in 0..3 {
        let secret = ecdh_x(node_enc[i], e);
        assert_eq(secret, secrets[i], "a node's key-exchange secret");
        for j in 0..K {
            let at = correction_at[j];
            let correction = if at == 0 { 0 } else { log[at] };
            let pair = node_pair(i, secret, log[3 + (i + 2) % 3], j, correction);
            assert_eq(pair[0], pairs[2 * (K * i + j)], "a node's pair, first");
            assert_eq(pair[1], pairs[2 * (K * i + j) + 1], "a node's pair, second");
        }
    }

    // the rotation: the message and node 1's signature under its sig key
    let key = EncKey { x: rotation.x, y: rotation.y, epoch: rotation.epoch };
    assert(key.on_curve(), "the rotated key is a point");
    let message = enc_rotation_message(ns, rotation.node, key);
    assert_eq(message, rotation.message, "rotation message");
    let sig = rotation.signature;
    assert(
        result_signature_verifies(
            EmbeddedCurvePoint { x: rotation.sig_x, y: rotation.sig_y },
            Receipt { s: [sig[0], sig[1]], e: [sig[2], sig[3]] }.limbs(),
            message,
        ),
        "rotation signature",
    );
}
