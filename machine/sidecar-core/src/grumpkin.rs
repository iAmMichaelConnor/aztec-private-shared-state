//! Grumpkin, the embedded curve of BN254, in the encodings Noir uses.
//!
//! Grumpkin is defined over the BN254 scalar field, so a point's coordinates are
//! [`Fr`] elements, and its own scalar field is BN254's base field, here [`Fq`].
//! The curve is `y^2 = x^3 - 17` with generator `(1, sqrt(-16))`, cofactor 1.
//!
//! Noir writes a scalar as `EmbeddedCurveScalar { lo, hi }`: two field elements,
//! the low and the high 128 bits of the integer `lo + hi * 2^128`, which must be
//! below the Grumpkin scalar modulus `q`. It writes the point at infinity as
//! `(0, 0)`. Every key here (namespace owners, nodes, receipts) is a Grumpkin
//! point, and every secret key a Grumpkin scalar.
//!
//! This module also carries the machine's nullifier identity: the per-namespace
//! nsk_app derivation (on public values; the nodes run it inside the MPC) and
//! npk_app_hash, as `pss_core/src/aztec_note.nr` computes them.

use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{BigInt, BigInteger, PrimeField, Zero};

use crate::field::{FieldHex, Fr};
use crate::hash::poseidon2_hash;
use crate::request::GrumpkinPoint;

/// The Grumpkin scalar field (BN254's base field). Its modulus `q` is larger than
/// the BN254 scalar modulus `r`, so every [`Fr`] value is a valid scalar.
pub type Fq = ark_grumpkin::Fr;

/// A Grumpkin point in affine form; the point at infinity is a separate value
/// here, written `(0, 0)` on the wire and in Noir.
pub type Point = ark_grumpkin::Affine;

// The nullifier-identity separators SIDECAR_NSK_APP and
// SIDECAR_NPK_APP (ASCII "sidecar.nsk_app" and "sidecar.npk_app" read as
// big-endian integers). They are the machine's own constants, not Aztec's
// DOM_SEP__NHK_M or DOM_SEP__SINGLE_PUBLIC_KEY_HASH: the machine is
// chain-agnostic, and the contract that pins npk_app_hash is the only verifier
// of the nullifiers made with nsk_app, so no protocol compatibility is needed.
// pss_core (aztec_note.nr) carries the same values. Changing
// either changes every namespace's nsk_app or npk_app_hash: contracts pinned to
// the old npk_app_hash stop accepting rounds, and existing nullifiers no longer
// match the derived key.
/// Separator of `nsk_app = poseidon2([SIDECAR_NSK_APP, master, namespace])`:
/// ASCII "sidecar.nsk_app".
pub const SIDECAR_NSK_APP: u128 = 0x736964656361722e6e736b5f617070;
/// Separator of `npk_app_hash = poseidon2([SIDECAR_NPK_APP, npk.x, npk.y])`:
/// ASCII "sidecar.npk_app".
pub const SIDECAR_NPK_APP: u128 = 0x736964656361722e6e706b5f617070;

/// The Grumpkin generator `(1, sqrt(-16))`, Noir's `EmbeddedCurvePoint::generator()`.
pub fn generator() -> Point {
    Point::generator()
}

/// `y^2 = x^3 - 17`, the check noir-lang/schnorr's `is_on_curve` makes on raw
/// coordinates. `(0, 0)`, Noir's point at infinity, is not on the curve.
pub fn is_on_curve(x: Fr, y: Fr) -> bool {
    y * y == x * x * x - Fr::from(17u64)
}

/// The integer below 2^128 a field element holds, if it is one.
fn limb_u128(limb: Fr) -> Option<u128> {
    let words = limb.into_bigint().0;
    (words[2] == 0 && words[3] == 0).then(|| (words[0] as u128) | ((words[1] as u128) << 64))
}

/// An `EmbeddedCurveScalar { lo, hi }` as a Grumpkin scalar. Refused, as Noir's
/// multi-scalar multiplication refuses it, when a limb is not below 2^128 or
/// `lo + hi * 2^128` is not below the Grumpkin scalar modulus.
pub fn scalar_from_limbs(lo: Fr, hi: Fr) -> Result<Fq, String> {
    let lo_value =
        limb_u128(lo).ok_or_else(|| format!("scalar limb lo = {lo} is not below 2^128"))?;
    let hi_value =
        limb_u128(hi).ok_or_else(|| format!("scalar limb hi = {hi} is not below 2^128"))?;
    let words = [
        lo_value as u64,
        (lo_value >> 64) as u64,
        hi_value as u64,
        (hi_value >> 64) as u64,
    ];
    Fq::from_bigint(BigInt::new(words))
        .ok_or_else(|| "scalar lo + hi * 2^128 is not below the Grumpkin scalar modulus".into())
}

/// The `(lo, hi)` limbs of a Grumpkin scalar.
pub fn scalar_to_limbs(scalar: Fq) -> (Fr, Fr) {
    limbs_of(scalar.into_bigint())
}

/// Noir's `EmbeddedCurveScalar::from_field`: `lo` the low 128 bits of the field
/// element's integer, `hi` the rest. Lossless, because `r < q`.
pub fn scalar_from_field(value: Fr) -> Fq {
    Fq::from_bigint(value.into_bigint()).expect("every BN254 scalar is below the Grumpkin modulus")
}

/// The `(lo, hi)` limbs of a field element, as `std::field::bn254::decompose`.
pub fn field_to_limbs(value: Fr) -> (Fr, Fr) {
    limbs_of(value.into_bigint())
}

fn limbs_of(words: BigInt<4>) -> (Fr, Fr) {
    let lo = BigInt::new([words.0[0], words.0[1], 0, 0]);
    let hi = BigInt::new([words.0[2], words.0[3], 0, 0]);
    (
        Fr::from_bigint(lo).expect("128 bits fit"),
        Fr::from_bigint(hi).expect("128 bits fit"),
    )
}

/// A Grumpkin scalar read as a field element, if it is below the BN254 scalar
/// modulus.
pub fn scalar_to_field(scalar: Fq) -> Option<Fr> {
    let bytes = scalar.into_bigint().to_bytes_be();
    let value = Fr::from_be_bytes_mod_order(&bytes);
    (value.into_bigint().to_bytes_be() == bytes).then_some(value)
}

/// `scalar · G`, Noir's `fixed_base_scalar_mul`.
pub fn fixed_base_mul(scalar: Fq) -> Point {
    (generator() * scalar).into_affine()
}

/// `scalar · point` (ECDH and key checks).
pub fn mul(point: Point, scalar: Fq) -> Point {
    (point * scalar).into_affine()
}

/// The point's coordinates as Noir writes them: `(0, 0)` for infinity.
pub fn coordinates(point: Point) -> (Fr, Fr) {
    point.xy().unwrap_or((Fr::zero(), Fr::zero()))
}

/// A public key from the wire. Refused unless `(x, y)` is on the curve, which
/// also refuses `(0, 0)`, the point at infinity: it is no one's key. Grumpkin's
/// cofactor is 1, so a point on the curve is in the prime-order group.
pub fn point_from_wire(point: &GrumpkinPoint) -> Result<Point, String> {
    let (x, y) = (point.x.fr(), point.y.fr());
    if !is_on_curve(x, y) {
        return Err(format!(
            "({}, {}) is not a point on Grumpkin",
            point.x, point.y
        ));
    }
    Ok(Point::new_unchecked(x, y))
}

/// The wire form of a point; infinity is written `(0, 0)` as Noir does.
pub fn point_to_wire(point: Point) -> GrumpkinPoint {
    let (x, y) = coordinates(point);
    GrumpkinPoint {
        x: FieldHex(x),
        y: FieldHex(y),
    }
}

/// The namespace's npk_app: `nsk_app · G`, with the Field nsk_app converted by
/// Noir's `EmbeddedCurveScalar::from_field`.
pub fn npk_app(nsk_app: Fr) -> Point {
    fixed_base_mul(scalar_from_field(nsk_app))
}

/// `poseidon2([SIDECAR_NPK_APP, npk.x, npk.y])`, pss_core's `npk_app_hash` after
/// its fixed-base multiplication: the network's nullifying identity for one
/// namespace, which the contract pins.
pub fn npk_app_hash(npk_app: Point) -> Fr {
    let (x, y) = coordinates(npk_app);
    poseidon2_hash(&[Fr::from(SIDECAR_NPK_APP), x, y])
}

/// `poseidon2([SIDECAR_NSK_APP, master, namespace])` on public values. The nodes
/// compute the same formula inside the MPC on the shared master; this form is
/// for test vectors and dealer-known development secrets.
pub fn nsk_app_derive_public(master: Fr, namespace: Fr) -> Fr {
    poseidon2_hash(&[Fr::from(SIDECAR_NSK_APP), master, namespace])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::{fr_from_hex, fr_to_hex};
    use ark_ff::One;
    use std::str::FromStr;

    fn hex(s: &str) -> Fr {
        fr_from_hex(s).unwrap()
    }

    const TWO_POW_128: &str = "0x100000000000000000000000000000000";

    #[test]
    fn generator_is_noirs() {
        let (x, y) = coordinates(generator());
        assert_eq!(x, Fr::one());
        assert_eq!(
            y,
            Fr::from_str("17631683881184975370165255887551781615748388533673675138860").unwrap()
        );
        assert!(is_on_curve(x, y));
        assert!(!is_on_curve(Fr::zero(), Fr::zero()));
    }

    #[test]
    fn separators_are_the_ascii_names() {
        assert_eq!(
            Fr::from(SIDECAR_NSK_APP),
            Fr::from_be_bytes_mod_order(b"sidecar.nsk_app")
        );
        assert_eq!(
            Fr::from(SIDECAR_NPK_APP),
            Fr::from_be_bytes_mod_order(b"sidecar.npk_app")
        );
    }

    #[test]
    fn scalar_limbs_range_checks() {
        let two_128 = hex(TWO_POW_128);
        let max_limb = two_128 - Fr::one();
        assert_eq!(
            scalar_from_limbs(Fr::from(5u64), Fr::zero()).unwrap(),
            Fq::from(5u64)
        );
        let s = scalar_from_limbs(Fr::from(7u64), Fr::from(3u64)).unwrap();
        assert_eq!(
            s,
            Fq::from(7u64) + Fq::from(3u64) * scalar_from_field(two_128)
        );
        assert_eq!(scalar_to_limbs(s), (Fr::from(7u64), Fr::from(3u64)));
        assert!(scalar_from_limbs(max_limb, Fr::zero()).is_ok());
        assert!(
            scalar_from_limbs(two_128, Fr::zero())
                .unwrap_err()
                .contains("lo")
        );
        assert!(
            scalar_from_limbs(Fr::zero(), two_128)
                .unwrap_err()
                .contains("hi")
        );
        // q - 1 is the largest scalar; q itself and q + 1 are refused
        let q_minus_1 = -Fq::one();
        let (lo, hi) = scalar_to_limbs(q_minus_1);
        assert_eq!(scalar_from_limbs(lo, hi).unwrap(), q_minus_1);
        let err = scalar_from_limbs(lo + Fr::one(), hi).unwrap_err();
        assert!(err.contains("modulus"), "{err}");
        assert!(scalar_from_limbs(max_limb, max_limb).is_err());
    }

    #[test]
    fn from_field_decomposes_into_128_bit_limbs() {
        let f = hex("0x0123456789abcdef0fedcba9876543210123456789abcdef0fedcba987654321");
        let (lo, hi) = field_to_limbs(f);
        assert_eq!(lo, hex("0x0123456789abcdef0fedcba987654321"));
        assert_eq!(hi, hex("0x0123456789abcdef0fedcba987654321"));
        assert_eq!(lo + hi * hex(TWO_POW_128), f);
        assert_eq!(scalar_to_limbs(scalar_from_field(f)), (lo, hi));
        let r_minus_1 = -Fr::one();
        assert_eq!(
            scalar_to_field(scalar_from_field(r_minus_1)),
            Some(r_minus_1)
        );
        // r itself is a scalar but not a field element
        let r_as_scalar = scalar_from_field(r_minus_1) + Fq::one();
        assert_eq!(scalar_to_field(r_as_scalar), None);
    }

    #[test]
    fn multiplication_and_wire_form() {
        let a = Fq::from(0x1234u64);
        let p = fixed_base_mul(a);
        assert_eq!(mul(generator(), a), p);
        assert_eq!(mul(p, Fq::from(3u64)), fixed_base_mul(a * Fq::from(3u64)));
        let wire = point_to_wire(p);
        assert_eq!(point_from_wire(&wire).unwrap(), p);
        assert_eq!(
            coordinates(fixed_base_mul(Fq::zero())),
            (Fr::zero(), Fr::zero())
        );
        let infinity = point_to_wire(fixed_base_mul(Fq::zero()));
        assert!(point_from_wire(&infinity).is_err());
        let off = GrumpkinPoint {
            x: wire.x,
            y: FieldHex(wire.y.fr() + Fr::one()),
        };
        assert!(point_from_wire(&off).unwrap_err().contains("not a point"));
    }

    // pss_core's kat_register_derivation (noir/pss_core/src/aztec_note.nr).
    #[test]
    fn reproduces_pss_core_register_derivation() {
        let nsk_app = nsk_app_derive_public(hex("0x6d6173746572"), hex("0xc0ffee"));
        assert_eq!(
            fr_to_hex(nsk_app),
            "0x02ae8d3b9b6a6b6e9e5b20349f68cedb428409d2884aa23c0d98bf4d13e04eda"
        );
        assert_eq!(
            fr_to_hex(npk_app_hash(npk_app(nsk_app))),
            "0x1f21c078530872675c230b247bed26ffce80c76ab6eeb360895ca8cbd8b92e16"
        );
        // pss_core's kat_note_hash_and_nullifier pins npk_app_hash of a given nsk_app
        assert_eq!(
            fr_to_hex(npk_app_hash(npk_app(hex(
                "0x234500000000000000000000000000001234"
            )))),
            "0x144c11a9981296c70b436cc3adb6e32b387a4b9072d6e0509fd86938dfce2529"
        );
    }
}
