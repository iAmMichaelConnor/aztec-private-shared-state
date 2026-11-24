// Derived from TaceoLabs/monty-hall-aztec (MIT; the root NOTICE).
//
use std::embedded_curve_ops::{
    EmbeddedCurvePoint, EmbeddedCurveScalar, fixed_base_scalar_mul, multi_scalar_mul,
};

/// The public key `secret · G` of a secret given as a field element, read as a
/// Grumpkin scalar by the same decomposition as an ephemeral key's (the
/// machine's `grumpkin::scalar_from_field`).
pub fn public_key(secret: Field) -> EmbeddedCurvePoint {
    generate_ephemeral_key_pair(secret).1
}

/// The x-coordinate of `secret · public_key`, the key-exchange secret of one
/// ephemeral secret with one recipient key given as a point (secret-shared on-chain
/// intake's per-node secrets, `pss_core::tip::derived`). The caller supplies
/// the secret: under secret-shared on-chain intake the client draws it, since it
/// must know the values the encoding derives from it (the blinding, the
/// outcome key and tag), so a fresh, full-entropy, never reused secret is
/// the client's duty. A point not on the curve fails the
/// multiplication.
pub fn ecdh_x(secret: Field, public_key: EmbeddedCurvePoint) -> Field {
    derive_ecdh_shared_secret(EmbeddedCurveScalar::from_field(secret), public_key).x
}

/// An ephemeral key pair from `rand`, read as a Grumpkin scalar by std's
/// decomposition (`EmbeddedCurveScalar::from_field`: two 128-bit limbs, range
/// checked); the public key `rand · G`.
fn generate_ephemeral_key_pair(rand: Field) -> (EmbeddedCurveScalar, EmbeddedCurvePoint) {
    let eph_sk = EmbeddedCurveScalar::from_field(rand);
    (eph_sk, fixed_base_scalar_mul(eph_sk))
}

/// The ECDH shared point `secret · public_key`: with an ephemeral pair
/// (esk, Epk = esk · G) and a recipient pair (sk, Pk = sk · G), esk · Pk =
/// sk · Epk, so either side computes it from the secret it holds.
fn derive_ecdh_shared_secret(
    secret: EmbeddedCurveScalar,
    public_key: EmbeddedCurvePoint,
) -> EmbeddedCurvePoint {
    let shared_secret = multi_scalar_mul([public_key], [secret]);
    shared_secret
}
