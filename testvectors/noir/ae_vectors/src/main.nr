//! Checks the Poseidon2 duplex AE vectors of testvectors/ae.json and every
//! sealed record third of testvectors/records.json with the Noir code they
//! must agree with: pss_utils/ae.nr's generic `AE::encrypt`, `AE::decrypt` and
//! `AE::pattern_tag` at every length the vectors carry, and, for each third,
//! the node's record key K_i, its key id, the record associated data hashed to
//! the nonce, the sealed plaintext and the record hash. Prover.toml is written
//! from the vector files by sidecar-core's tests/write_vectors.rs; `nargo
//! execute` fails on any disagreement.

use protocol_types::hash::poseidon2_hash;
use pss_utils::ae::AE;
use std::embedded_curve_ops::{EmbeddedCurvePoint, EmbeddedCurveScalar, fixed_base_scalar_mul};

/// ASCII "sidecar.seal_key" as a big-endian integer.
global SIDECAR_SEAL_KEY: Field = 0x736964656361722e7365616c5f6b6579;
/// ASCII "sidecar.record_ad" as a big-endian integer.
global SIDECAR_RECORD_AD: Field = 0x736964656361722e7265636f72645f6164;

struct AeVector<let N: u32> {
    key: Field,
    nonce: Field,
    pattern_tag: Field,
    plaintext: [Field; N],
    ciphertext: [Field; N],
    tag: Field,
}

/// One node's sealed third of a record, with that node's keys. `M` is `N + 2`,
/// the length of the record-hash input.
struct RecordVector<let N: u32, let M: u32> {
    enc_lo: Field,
    enc_hi: Field,
    enc_pk_x: Field,
    enc_pk_y: Field,
    record_key: Field,
    key_id_hash: Field,
    key_id: Field,
    machine: bool,
    owner_x: Field,
    owner_y: Field,
    namespace: Field,
    key_hash: Field,
    note_hash: Field,
    plaintext: [Field; N],
    nonce: Field,
    ciphertext: [Field; N],
    tag: Field,
    record_hash: Field,
}

fn check_ae<let N: u32>(v: AeVector<N>) {
    assert_eq(AE::pattern_tag::<N>(), v.pattern_tag);
    let (ciphertext, tag) = AE::encrypt(v.plaintext, v.key, v.nonce);
    assert_eq(ciphertext, v.ciphertext);
    assert_eq(tag, v.tag);
    assert_eq(AE::decrypt(v.ciphertext, v.tag, v.key, v.nonce), v.plaintext);
}

fn check_record<let N: u32, let M: u32>(v: RecordVector<N, M>) {
    assert_eq(M, N + 2);
    // Node i's keys: enc_pk = enc·G, K_i and the key id from enc alone.
    let enc_pk = fixed_base_scalar_mul(EmbeddedCurveScalar::new(v.enc_lo, v.enc_hi));
    assert_eq(enc_pk, EmbeddedCurvePoint::new(v.enc_pk_x, v.enc_pk_y));
    assert_eq(poseidon2_hash([v.enc_lo, v.enc_hi, SIDECAR_SEAL_KEY]), v.record_key);
    assert_eq(poseidon2_hash([enc_pk.x, enc_pk.y]), v.key_id_hash);
    let bytes: [u8; 32] = v.key_id_hash.to_be_bytes();
    let mut id: Field = 0;
    for j in 0..8 {
        id = id * 256 + bytes[j] as Field;
    }
    assert_eq(id, v.key_id);
    // A machine-owned third is owned by the node's own enc key.
    if v.machine {
        assert_eq(EmbeddedCurvePoint::new(v.owner_x, v.owner_y), enc_pk);
    }
    // The record AD, hashed into the nonce, and the plaintext header.
    let nonce = poseidon2_hash([
        v.namespace,
        v.key_hash,
        v.note_hash,
        v.owner_x,
        v.owner_y,
        SIDECAR_RECORD_AD,
    ]);
    assert_eq(nonce, v.nonce);
    assert_eq(
        [v.plaintext[0], v.plaintext[1], v.plaintext[2]],
        [v.namespace, v.key_hash, v.note_hash],
    );
    // The cipher under K_i, and the hash the request carries for the third.
    let (ciphertext, tag) = AE::encrypt(v.plaintext, v.record_key, v.nonce);
    assert_eq(ciphertext, v.ciphertext);
    assert_eq(tag, v.tag);
    assert_eq(AE::decrypt(v.ciphertext, v.tag, v.record_key, v.nonce), v.plaintext);
    let mut hashed = [0; M];
    hashed[0] = v.key_id;
    for j in 0..N {
        hashed[j + 1] = v.ciphertext[j];
    }
    hashed[N + 1] = v.tag;
    assert_eq(poseidon2_hash(hashed), v.record_hash);
}

fn main(
    ae1: AeVector<1>,
    ae2: AeVector<2>,
    ae3: AeVector<3>,
    ae4: AeVector<4>,
    ae7: AeVector<7>,
    ae10: AeVector<10>,
    rec6: [RecordVector<6, 8>; 3],
    rec8: [RecordVector<8, 10>; 6],
) {
    check_ae(ae1);
    check_ae(ae2);
    check_ae(ae3);
    check_ae(ae4);
    check_ae(ae7);
    check_ae(ae10);
    for v in rec6 {
        check_record(v);
    }
    for v in rec8 {
        check_record(v);
    }
}
