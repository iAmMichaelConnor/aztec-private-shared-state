//! Checks the machine's test vectors with the Noir code they must agree with:
//! every Schnorr vector of testvectors/schnorr.json against noir-lang/schnorr
//! v0.4.0 `verify_signature`, every testvectors/npk_app_hash.json entry
//! against pss_core's `npk_app_hash` and the nsk_app derivation, the signed
//! bodies of testvectors/bodies.json, the result messages of
//! testvectors/results.json (rebuilt here as the tip's process_result rebuilds
//! them, then their node signatures) and the registry answers of
//! testvectors/registry.json (message and signature). Prover.toml is written
//! from the vector files; `nargo execute` fails on any disagreement.

use pss_core::aztec_note::SIDECAR_NSK_APP;
use pss_core::tip::outputs::RESULT_DOMAIN;
use protocol_types::hash::{poseidon2_hash, poseidon2_hash_with_separator};
use std::embedded_curve_ops::{EmbeddedCurvePoint, EmbeddedCurveScalar};

global SCHNORR_VECTORS: u32 = 12;
global NPK_VECTORS: u32 = 3;
global BODY_VECTORS: u32 = 3;
global RESULT_VECTORS: u32 = 9;
global REGISTRY_VECTORS: u32 = 6;

/// ASCII "sidecar.registry" as a big-endian integer.
global REGISTRY_DOMAIN: Field = 0x736964656361722e7265676973747279;

struct SchnorrVector {
    pk_x: Field,
    pk_y: Field,
    s_lo: Field,
    s_hi: Field,
    e_lo: Field,
    e_hi: Field,
    message: Field,
    expected: bool,
}

struct NpkVector {
    master: Field,
    namespace: Field,
    nsk_app: Field,
    npk_app_hash: Field,
}

/// Node i's signed result of a round with two outputs: `thirds` of the
/// `record_hashes` are node i's new record thirds (the rest are zero padding).
struct ResultVector {
    namespace: Field,
    request_id: Field,
    commitments: [Field; 2],
    i: Field,
    thirds: u32,
    record_hashes: [Field; 2],
    sealed_hash: Field,
    message: Field,
    pk_x: Field,
    pk_y: Field,
    s_lo: Field,
    s_hi: Field,
    e_lo: Field,
    e_hi: Field,
}

/// Node i's signed registry answer.
struct RegistryVector {
    namespace: Field,
    name_hash: Field,
    vk_hash: Field,
    npk_app_hash: Field,
    seq: Field,
    disabled: bool,
    i: Field,
    message: Field,
    pk_x: Field,
    pk_y: Field,
    s_lo: Field,
    s_hi: Field,
    e_lo: Field,
    e_hi: Field,
}

fn verifies(pk_x: Field, pk_y: Field, s: [Field; 2], e: [Field; 2], message: Field) -> bool {
    let signature = (EmbeddedCurveScalar::new(s[0], s[1]), EmbeddedCurveScalar::new(e[0], e[1]));
    schnorr::verify_signature(EmbeddedCurvePoint::new(pk_x, pk_y), signature, message)
}

fn main(
    schnorr: [SchnorrVector; SCHNORR_VECTORS],
    npk: [NpkVector; NPK_VECTORS],
    bodies: [SchnorrVector; BODY_VECTORS],
    results: [ResultVector; RESULT_VECTORS],
    registry: [RegistryVector; REGISTRY_VECTORS],
) {
    for v in schnorr {
        let signature =
            (EmbeddedCurveScalar::new(v.s_lo, v.s_hi), EmbeddedCurveScalar::new(v.e_lo, v.e_hi));
        let public_key = EmbeddedCurvePoint::new(v.pk_x, v.pk_y);
        assert_eq(schnorr::verify_signature(public_key, signature, v.message), v.expected);
    }
    for v in bodies {
        assert_eq(
            verifies(
                v.pk_x,
                v.pk_y,
                [v.s_lo, v.s_hi],
                [v.e_lo, v.e_hi],
                v.message,
            ),
            v.expected,
        );
    }
    for v in results {
        // H(sealed_i): 0 without thirds, else poseidon2 over the list.
        let sealed = if v.thirds == 0 {
            0
        } else if v.thirds == 1 {
            poseidon2_hash([v.record_hashes[0]])
        } else {
            assert_eq(v.thirds, 2);
            poseidon2_hash(v.record_hashes)
        };
        assert_eq(sealed, v.sealed_hash);
        let message = poseidon2_hash([
            RESULT_DOMAIN,
            v.namespace,
            v.request_id,
            v.commitments[0],
            v.commitments[1],
            v.i,
            sealed,
        ]);
        assert_eq(message, v.message);
        assert(verifies(v.pk_x, v.pk_y, [v.s_lo, v.s_hi], [v.e_lo, v.e_hi], message));
        // Another node index or another sealed hash is another message.
        assert(
            !verifies(
                v.pk_x,
                v.pk_y,
                [v.s_lo, v.s_hi],
                [v.e_lo, v.e_hi],
                message + 1,
            ),
        );
    }
    for v in registry {
        let message = poseidon2_hash([
            REGISTRY_DOMAIN,
            v.namespace,
            v.name_hash,
            v.vk_hash,
            v.npk_app_hash,
            v.seq,
            v.disabled as Field,
            v.i,
        ]);
        assert_eq(message, v.message);
        assert(verifies(v.pk_x, v.pk_y, [v.s_lo, v.s_hi], [v.e_lo, v.e_hi], message));
    }
    for v in npk {
        let nsk_app = poseidon2_hash_with_separator([v.master, v.namespace], SIDECAR_NSK_APP);
        assert_eq(nsk_app, v.nsk_app);
        assert_eq(pss_core::aztec_note::npk_app_hash(nsk_app), v.npk_app_hash);
    }
}
