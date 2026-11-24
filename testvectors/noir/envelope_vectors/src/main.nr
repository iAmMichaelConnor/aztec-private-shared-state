//! Checks every INPUT_SHARED envelope of testvectors/envelope.json with the
//! Noir code it must agree with: the ephemeral key from a field element and the
//! ECDH x-coordinate on both sides, the associated data hashed to the
//! nonce, and the Poseidon2 AE of pss_utils/ae.nr for two fields (`encrypt`
//! with N = 2). Prover.toml is written from the vector file
//! by sidecar-core; `nargo execute` fails on any disagreement.

use pss_utils::ae::AE;
use protocol_types::hash::{poseidon2_hash, poseidon2_hash_bytes};
use std::embedded_curve_ops::{
    EmbeddedCurvePoint, EmbeddedCurveScalar, fixed_base_scalar_mul, multi_scalar_mul,
};

global ENVELOPES: u32 = 6;

struct Envelope {
    input: u32,
    i: Field,
    eph: Field,
    pair: [Field; 2],
    enc_pk_x: Field,
    enc_pk_y: Field,
    enc_lo: Field,
    enc_hi: Field,
    e_x: Field,
    e_y: Field,
    shared_secret: Field,
    nonce: Field,
    ct: [Field; 2],
    tag: Field,
    share_hash: Field,
}

fn main(
    namespace: Field,
    request_id: Field,
    input_body_hash: Field,
    circuit_hash: Field,
    name_hashes: [Field; 2],
    envelopes: [Envelope; ENVELOPES],
) {
    // The vector file's circuit and input names.
    assert_eq(poseidon2_hash_bytes("monty_hall_open_door".as_bytes()), circuit_hash);
    assert_eq(poseidon2_hash_bytes("door".as_bytes()), name_hashes[0]);
    assert_eq(poseidon2_hash_bytes("door_randomness".as_bytes()), name_hashes[1]);
    for v in envelopes {
        let enc_pk = EmbeddedCurvePoint::new(v.enc_pk_x, v.enc_pk_y);
        let e_expected = EmbeddedCurvePoint::new(v.e_x, v.e_y);
        // The client: E = eph·G and S = (eph·enc_pk).x.
        let eph = EmbeddedCurveScalar::from_field(v.eph);
        assert_eq(fixed_base_scalar_mul(eph), e_expected);
        let secret = multi_scalar_mul([enc_pk], [eph]).x;
        assert_eq(secret, v.shared_secret);
        // The node: S = (enc·E).x.
        let enc = EmbeddedCurveScalar::new(v.enc_lo, v.enc_hi);
        assert_eq(fixed_base_scalar_mul(enc), enc_pk);
        assert_eq(multi_scalar_mul([e_expected], [enc]).x, secret);
        // The associated data, hashed into the nonce.
        let nonce = poseidon2_hash(
            [namespace, request_id, circuit_hash, name_hashes[v.input], v.i, input_body_hash],
        );
        assert_eq(nonce, v.nonce);
        // The cipher: encrypt gives the file's ciphertext and tag, and decrypt opens.
        let (ct, tag) = AE::encrypt::<2>(v.pair, secret, nonce);
        assert_eq(ct, v.ct);
        assert_eq(tag, v.tag);
        assert_eq(AE::decrypt::<2>(v.ct, v.tag, secret, nonce), v.pair);
        // share_hashes[i].
        assert_eq(poseidon2_hash([v.e_x, v.e_y, v.ct[0], v.ct[1], v.tag]), v.share_hash);
    }
}
