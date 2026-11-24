//! Schnorr signatures over Grumpkin in the construction of noir-lang/schnorr
//! v0.4.0, and the REGISTER message rule.
//!
//! The scheme, as the library's `verify_signature` checks it:
//!
//! ```text
//! DST = poseidon2_hash_bytes("schnorr_grumpkin_poseidon2")
//!     = 0x024c76938ed06b8ec1d9094b1013d190baa4011372f0604643bda812a63b832e
//! R   = s·G + e·pk                          (Grumpkin, s and e as scalars)
//! e'  = poseidon2([DST, R.x, pk.x, pk.y, message])
//! accept iff pk is on the curve, s ≠ 0, e ≠ 0, R ≠ ∞ and e' = e.lo + e.hi·2^128
//! ```
//!
//! A signer picks a random nonce k, sets R = k·G, computes e from R as above and
//! s = k − e·sk (mod q). `s` and `e` travel as `EmbeddedCurveScalar { lo, hi }`
//! limb pairs, the [`Signature`] wire type.

// The signature scheme is Schnorr over Grumpkin in the encoding of
// noir-lang/schnorr v0.4.0 (Poseidon2 challenge with the library's domain tag;
// (s, e) as two embedded-curve scalars; the message one field element). The
// only scheme (docs/DECISIONS.md section 4, "One signature scheme"): one key
// type for namespace owners, the tip's receipts and Aztec Schnorr accounts, so
// a Noir contract can check the same signature in-circuit with the library
// Aztec's own account contract uses. Another scheme (ECDSA, EdDSA, the older Blake2s
// Schnorr) means a second key type and signatures no circuit here can check.

use std::sync::LazyLock;

use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{One, PrimeField, UniformRand, Zero};
use ark_std::rand::rngs::StdRng;
use ark_std::rand::{CryptoRng, RngCore, SeedableRng};
use serde_json::Value;

use crate::error::Refusal;
use crate::field::{FieldHex, Fr, fr_to_be_bytes};
use crate::grumpkin::{
    Fq, Point, field_to_limbs, fixed_base_mul, generator, is_on_curve, point_from_wire,
    scalar_from_field, scalar_from_limbs, scalar_to_limbs,
};
use crate::hash::poseidon2_hash;
use crate::keys::label_field;
use crate::register::Signature;
use crate::request::GrumpkinPoint;

/// The source string of the challenge's domain tag.
pub const SCHNORR_DST_SOURCE: &[u8] = b"schnorr_grumpkin_poseidon2";

/// `poseidon2_hash_bytes("schnorr_grumpkin_poseidon2")`, the library's
/// `SCHNORR_CHALLENGE_DST`.
pub static SCHNORR_CHALLENGE_DST: LazyLock<Fr> =
    LazyLock::new(|| poseidon2_hash_bytes(SCHNORR_DST_SOURCE));

/// `poseidon2_hash_bytes` of protocol_types (Noir) and aztec.js
/// (`poseidon2HashBytes`): the bytes are cut into 31-byte chunks, the last one
/// shorter; each chunk is read as a little-endian integer (byte i weighs 256^i)
/// and the chunks are hashed with the Poseidon2 sponge. Zero bytes at the end of
/// the last chunk do not change its value; only the chunk count is bound, so
/// every name a binding hashes passes [`check_name`] first.
pub fn poseidon2_hash_bytes(bytes: &[u8]) -> Fr {
    let fields: Vec<Fr> = bytes.chunks(31).map(Fr::from_le_bytes_mod_order).collect();
    poseidon2_hash(&fields)
}

/// The longest name [`check_name`] admits, in bytes.
pub const MAX_NAME_BYTES: usize = 256;

/// Refuse (400, `field `<field>``) a name that a binding hashes with
/// [`poseidon2_hash_bytes`] unless it is 1 to [`MAX_NAME_BYTES`] bytes of
/// visible ASCII (0x21 to 0x7E): a store key, a record key, a circuit or
/// package name, a shared input name. The hash ignores zero bytes at the
/// end, so `k` and `k\0` would bind as one name; with no zero byte a name's
/// hash fixes its bytes. `what` names the kind in the message ("key").
pub fn check_name(field: &str, what: &str, name: &str) -> Result<(), Refusal> {
    let why = if name.is_empty() {
        format!("empty {what}")
    } else if name.len() > MAX_NAME_BYTES {
        format!("{what} longer than {MAX_NAME_BYTES} bytes")
    } else if let Some(b) = name.bytes().find(|b| !(0x21..=0x7e).contains(b)) {
        format!(
            "{what} `{}` has byte 0x{b:02x}; a {what} is visible ASCII (0x21 to 0x7E)",
            name.escape_debug()
        )
    } else {
        return Ok(());
    };
    Err(Refusal::bad_request(format!("field `{field}`: {why}")))
}

/// `poseidon2([DST, R.x, pk.x, pk.y, message])`.
fn challenge(r_x: Fr, pubkey: (Fr, Fr), message: Fr) -> Fr {
    poseidon2_hash(&[*SCHNORR_CHALLENGE_DST, r_x, pubkey.0, pubkey.1, message])
}

fn limbs(pair: &[FieldHex; 2]) -> (Fr, Fr) {
    (pair[0].fr(), pair[1].fr())
}

/// The public key of a secret: `secret · G`.
pub fn public_key(secret: Fq) -> Point {
    fixed_base_mul(secret)
}

/// noir-lang/schnorr v0.4.0 `verify_signature`, natively.
///
/// Where the library cannot run at all, this returns false: a key off the curve
/// or a scalar limb out of range makes Noir's multi-scalar multiplication fail
/// the execution, so no proof exists for such a signature either way.
pub fn verify(pubkey: Point, signature: Signature, message: Fr) -> bool {
    let Some((pk_x, pk_y)) = pubkey.xy() else {
        return false;
    };
    if !is_on_curve(pk_x, pk_y) {
        return false;
    }
    let (s_lo, s_hi) = limbs(&signature.s);
    let (e_lo, e_hi) = limbs(&signature.e);
    let zero = (Fr::zero(), Fr::zero());
    if (s_lo, s_hi) == zero || (e_lo, e_hi) == zero {
        return false;
    }
    let (Ok(s), Ok(e)) = (scalar_from_limbs(s_lo, s_hi), scalar_from_limbs(e_lo, e_hi)) else {
        return false;
    };
    let r = (generator() * s + pubkey * e).into_affine();
    let Some((r_x, _)) = r.xy() else {
        return false;
    };
    // The library compares the challenge with e's limbs composed in the field.
    let two_pow_128 = Fr::from(u128::MAX) + Fr::one();
    let e_field = e_lo + e_hi * two_pow_128;
    challenge(r_x, (pk_x, pk_y), message) == e_field
}

/// [`verify`] for a key as it arrives on the wire; false for a point off the
/// curve, `(0, 0)` included.
pub fn verify_wire(pubkey: &GrumpkinPoint, signature: Signature, message: Fr) -> bool {
    point_from_wire(pubkey).is_ok_and(|p| verify(p, signature, message))
}

// A derived nonce: the nonce generator is seeded with the 32 big-endian
// bytes of poseidon2([label, secret.lo, secret.hi, message]), a pseudorandom
// function of the secret and the message, as Ed25519 derives its nonces.
// Equal messages get equal signatures (a node asked twice answers the same
// bytes with no stored randomness), different messages independent nonces,
// and each use has its own label, so two uses over one field value never
// share a nonce. Drawing the nonce from the OS is equally sound; a nonce that
// repeats across messages, or that anyone else can predict, reveals the
// secret.
/// Sign `message` with `secret` under the nonce derived from `label`, the
/// secret and the message. The result verifies under noir-lang/schnorr
/// v0.4.0 and [`verify`].
///
/// Panics if `secret` is zero, which has no public key.
pub fn sign_derived(secret: Fq, label: &[u8], message: Fr) -> Signature {
    let (lo, hi) = scalar_to_limbs(secret);
    let seed = poseidon2_hash(&[label_field(label), lo, hi, message]);
    let bytes: [u8; 32] = fr_to_be_bytes(seed)
        .try_into()
        .expect("a field element is 32 bytes");
    sign(secret, message, &mut StdRng::from_seed(bytes))
}

/// Sign `message` with `secret`, drawing the nonce from `rng` (a CSPRNG: a
/// repeated or guessable nonce reveals the secret). The result verifies under
/// noir-lang/schnorr v0.4.0 and [`verify`].
///
/// Panics if `secret` is zero, which has no public key.
pub fn sign<R: RngCore + CryptoRng>(secret: Fq, message: Fr, rng: &mut R) -> Signature {
    assert!(!secret.is_zero(), "the zero scalar is not a secret key");
    let (pk_x, pk_y) = public_key(secret).xy().expect("a nonzero secret");
    loop {
        let k = Fq::rand(rng);
        let Some((r_x, _)) = fixed_base_mul(k).xy() else {
            continue;
        };
        let e = challenge(r_x, (pk_x, pk_y), message);
        let s = k - scalar_from_field(e) * secret;
        if e.is_zero() || s.is_zero() {
            continue;
        }
        let (s_lo, s_hi) = scalar_to_limbs(s);
        let (e_lo, e_hi) = field_to_limbs(e);
        return Signature {
            s: [FieldHex(s_lo), FieldHex(s_hi)],
            e: [FieldHex(e_lo), FieldHex(e_hi)],
        };
    }
}

/// A signature from the 64 bytes `s ‖ e` of barretenberg's and aztec.js's
/// `SchnorrSignature`: each component a 32-byte big-endian integer, so `s.hi` is
/// bytes 0..16, `s.lo` 16..32, `e.hi` 32..48 and `e.lo` 48..64 (aztec.js
/// `toLimbFields()` gives `[s.lo, s.hi, e.lo, e.hi]`).
pub fn signature_from_bytes(bytes: &[u8; 64]) -> Signature {
    let limb = |range: std::ops::Range<usize>| FieldHex(Fr::from_be_bytes_mod_order(&bytes[range]));
    Signature {
        s: [limb(16..32), limb(0..16)],
        e: [limb(48..64), limb(32..48)],
    }
}

/// The 64-byte `s ‖ e` form of a signature, the inverse of
/// [`signature_from_bytes`]. Refused when a limb is not below 2^128.
pub fn signature_to_bytes(signature: &Signature) -> Result<[u8; 64], String> {
    let mut out = [0u8; 64];
    for (offset, limb) in [
        (0, signature.s[1]),
        (16, signature.s[0]),
        (32, signature.e[1]),
        (48, signature.e[0]),
    ] {
        let bytes = fr_to_be_bytes(limb.fr());
        if bytes[..16].iter().any(|b| *b != 0) {
            return Err(format!("signature limb {limb} is not below 2^128"));
        }
        out[offset..offset + 16].copy_from_slice(&bytes[16..]);
    }
    Ok(out)
}

// The signed-body message rule. The message a key signs for a
// JSON body is poseidon2_hash_bytes(domain ‖ JCS(body without `signature`)): the
// domain string's bytes, then the RFC 8785 canonical JSON of the body with its
// top-level `signature` field removed, as UTF-8; hashed with the 31-byte
// little-endian packing of protocol_types and aztec.js (`poseidon2HashBytes`),
// so a TypeScript client and a Noir contract compute it with standard tools.
// Three domains, one per kind of signed body: REGISTER and DISABLE (signed by
// the namespace owner) and EXECUTE (signed by the requester of a request that
// supplies client-held records). The domain keeps a signature on one kind of
// body from being replayed as another, or as any other message the same key
// signs (a receipt, an Aztec authwit). Changing a domain or the hash-to-field
// step invalidates every client's signer and every signed request in flight.
/// The domain of a REGISTER body, signed by the namespace owner.
pub const REGISTER_DOMAIN: &str = "cosnark-sidecar/v1/register";
/// The domain of a `DISABLE(namespace, circuit)` body, signed by the namespace
/// owner.
pub const DISABLE_DOMAIN: &str = "cosnark-sidecar/v1/disable";
/// The domain of an execute body that supplies client-held records, signed by
/// the requester whose key the records are bound to.
pub const EXECUTE_DOMAIN: &str = "cosnark-sidecar/v1/execute";

/// The field element a key signs for `body` under `domain` (one of
/// [`REGISTER_DOMAIN`], [`DISABLE_DOMAIN`], [`EXECUTE_DOMAIN`]):
/// `poseidon2_hash_bytes(domain ‖ JCS(body))`, with a top-level `signature`
/// field left out if present. Refused when the body is not a JSON object or
/// [`canonical_json`] refuses it.
pub fn message_for(domain: &str, body: &Value) -> Result<Fr, String> {
    let object = body
        .as_object()
        .ok_or_else(|| "the signed body is not a JSON object".to_string())?;
    let mut without_signature = object.clone();
    without_signature.remove("signature");
    let canonical = canonical_json(&Value::Object(without_signature))?;
    let mut bytes = Vec::with_capacity(domain.len() + canonical.len());
    bytes.extend_from_slice(domain.as_bytes());
    bytes.extend_from_slice(canonical.as_bytes());
    Ok(poseidon2_hash_bytes(&bytes))
}

/// [`message_for`] under [`REGISTER_DOMAIN`], for the tests and vectors.
#[cfg(any(test, feature = "testing"))]
pub fn register_message(body: &Value) -> Result<Fr, String> {
    message_for(REGISTER_DOMAIN, body)
}

/// The largest integer a JSON number may hold here: 2^53 − 1, the largest that
/// every IEEE double (and so every JavaScript client) represents exactly.
pub const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;

// JSON numbers in a signed body. RFC 8785 serialises numbers as
// ECMAScript does for IEEE doubles. Only integers of magnitude at most
// 2^53 − 1 are accepted; floats (`1.0`, `1e3`, `0.5`) and larger integers are
// refused. Within that range the integer's decimal form is its ECMAScript form,
// so no float formatting is needed, and a JavaScript client cannot round the
// value differently from the nodes. Nargo output carries its large `hash` as a
// string, so real circuits fit. Admitting floats means implementing the
// ECMAScript shortest-round-trip formatting.
/// RFC 8785 (JCS) canonical serialisation: object members sorted by the UTF-16
/// code units of their names, no whitespace, strings escaped as ECMAScript's
/// `JSON.stringify` does, integers in plain decimal. Refuses non-integer numbers
/// and integers outside ±(2^53 − 1).
pub fn canonical_json(value: &Value) -> Result<String, String> {
    let mut out = String::new();
    write_canonical(value, &mut out)?;
    Ok(out)
}

fn write_canonical(value: &Value, out: &mut String) -> Result<(), String> {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => {
            let magnitude_ok = if let Some(v) = n.as_u64() {
                v <= MAX_SAFE_INTEGER
            } else if let Some(v) = n.as_i64() {
                v.unsigned_abs() <= MAX_SAFE_INTEGER
            } else {
                return Err(format!(
                    "the number {n} is not an integer; signed bodies carry integers only"
                ));
            };
            if !magnitude_ok {
                return Err(format!(
                    "the integer {n} is outside ±(2^53 − 1); write it as a string"
                ));
            }
            out.push_str(&n.to_string());
        }
        Value::String(s) => write_string(s, out),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(item, out)?;
            }
            out.push(']');
        }
        Value::Object(members) => {
            let mut names: Vec<&String> = members.keys().collect();
            names.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
            out.push('{');
            for (i, name) in names.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_string(name, out);
                out.push(':');
                write_canonical(&members[name], out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

// RFC 8785 section 3.2.2.2: `"` and `\` escaped, the two-character forms for
// \b \t \n \f \r, \u00xx (lowercase hex) for the other controls below U+0020,
// everything else as itself in UTF-8.
fn write_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\u{0c}' => out.push_str("\\f"),
            '\r' => out.push_str("\\r"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::{fr_from_hex, fr_to_hex};
    use crate::grumpkin::{point_from_wire, point_to_wire};
    use ark_std::rand::SeedableRng;
    use ark_std::rand::rngs::StdRng;
    use serde_json::json;

    fn hex(s: &str) -> Fr {
        fr_from_hex(s).unwrap()
    }

    fn sig(s: [&str; 2], e: [&str; 2]) -> Signature {
        Signature {
            s: [FieldHex(hex(s[0])), FieldHex(hex(s[1]))],
            e: [FieldHex(hex(e[0])), FieldHex(hex(e[1]))],
        }
    }

    fn key(x: &str, y: &str) -> Point {
        point_from_wire(&GrumpkinPoint {
            x: FieldHex(hex(x)),
            y: FieldHex(hex(y)),
        })
        .unwrap()
    }

    #[test]
    fn a_trailing_nul_hashes_alike_so_check_name_refuses_it() {
        assert_eq!(poseidon2_hash_bytes(b"k"), poseidon2_hash_bytes(b"k\0"));
        for good in [
            "k",
            "0x01",
            "pool_total",
            "$state_keys.reads[0]",
            &"a".repeat(MAX_NAME_BYTES),
        ] {
            check_name("f", "key", good).unwrap();
        }
        for (bad, why) in [
            ("", "empty key"),
            ("k\0", "byte 0x00"),
            ("\0k", "byte 0x00"),
            ("a b", "byte 0x20"),
            ("caf\u{e9}", "byte 0xc3"),
            (&"a".repeat(MAX_NAME_BYTES + 1), "longer than"),
        ] {
            let err = check_name("f", "key", bad).unwrap_err();
            assert!(err.message.starts_with("field `f`: "), "{err}");
            assert!(err.message.contains(why), "{err}");
        }
    }

    #[test]
    fn dst_is_the_librarys() {
        assert_eq!(
            fr_to_hex(*SCHNORR_CHALLENGE_DST),
            "0x024c76938ed06b8ec1d9094b1013d190baa4011372f0604643bda812a63b832e"
        );
    }

    // Known answers from @aztec-labs/foundation 6.0.0 `poseidon2HashBytes`.
    #[test]
    fn poseidon2_hash_bytes_matches_aztec_js() {
        let seq = |n: usize, f: fn(usize) -> u8| (0..n).map(f).collect::<Vec<u8>>();
        let cases = [
            (
                Vec::new(),
                "0x18dfb8dc9b82229cff974efefc8df78b1ce96d9d844236b496785c698bc6732e",
            ),
            (
                seq(31, |i| i as u8 + 1),
                "0x21212ad5663e36b78b2ebb43560ee47d3b00d822755787a35e2e6bc937a4994c",
            ),
            (
                seq(32, |i| i as u8 + 1),
                "0x038114de233f2021227e7ebe26d9c48d963fbb05340b9408ea809f9685ea5a73",
            ),
            (
                seq(62, |i| ((i * 7 + 3) & 255) as u8),
                "0x11040eb13a55407c06ecbb6d96795c0d23878070325bdcb25ffc355a3d356bcf",
            ),
            (
                seq(100, |i| ((i * 13 + 250) & 255) as u8),
                "0x2910d939341af3d55ce9238683e0f47099f6c94bac66994447354bc09861e580",
            ),
        ];
        for (bytes, expected) in cases {
            assert_eq!(
                fr_to_hex(poseidon2_hash_bytes(&bytes)),
                expected,
                "{} bytes",
                bytes.len()
            );
        }
        // protocol_types' poseidon2_hash_bytes_matches_hash_of_packed_chunks
        let mut bytes = [0u8; 32];
        bytes[0] = 1;
        bytes[1] = 2;
        bytes[31] = 3;
        assert_eq!(
            poseidon2_hash_bytes(&bytes),
            poseidon2_hash(&[Fr::from(1u64 + 2 * 256), Fr::from(3u64)])
        );
    }

    // The library's pinned_vector_small and pinned_vector_large.
    #[test]
    fn library_pinned_vectors_verify() {
        let small = key(
            "0x2c39bbbde2d0ffcb5c4317dcbfa1771cf554a2f33c647446632fa707a5bf5f3f",
            "0x2b9c81935298af5ebe22f1a7279bb76781e6cadba3fb6c5c41ed942392dc687c",
        );
        let small_sig = sig(
            [
                "0x5fd1ac0ad411110674830c54cb506212",
                "0x281906862cdb4e0efec7226d757fe803",
            ],
            [
                "0x6c368959f958e525d761d06c47fd2ad6",
                "0x013f6a902c6c0efafdadbd4de409690d",
            ],
        );
        assert!(verify(small, small_sig, Fr::from(0x2bcu64)));
        assert!(!verify(small, small_sig, Fr::from(0x2bdu64)));
        let large = key(
            "0x065812e335a97c2108ea8cf4ccfe2f9dd6b117a0714f5e18461575be93f61da6",
            "0x1a915003e8ec534f9a15d926a7ded478e178468ccc4f28e236e67450a55ac622",
        );
        let large_sig = sig(
            [
                "0xf3bc3b7147acb9c621fd9f72dbf15ffa",
                "0x08599f379f0301dfefdbd0272554454d",
            ],
            [
                "0x97065383ebbbd76620398792bd259bc2",
                "0x2ceaee87f45b7a417f0ffb05451a8c92",
            ],
        );
        let message = hex("0x0123456789abcdef0fedcba9876543210123456789abcdef0fedcba987654321");
        assert!(verify(large, large_sig, message));
        assert!(!verify(small, large_sig, message));
    }

    #[test]
    fn sign_verify_and_refusals() {
        let mut rng = StdRng::seed_from_u64(7);
        let secret = Fq::from(0x5ec2e7u64);
        let pk = public_key(secret);
        let message = Fr::from(0xabcdefu64);
        let good = sign(secret, message, &mut rng);
        assert!(verify(pk, good, message));
        assert!(verify_wire(&point_to_wire(pk), good, message));
        // a fresh nonce each time, both valid
        let again = sign(secret, message, &mut rng);
        assert_ne!(again, good);
        assert!(verify(pk, again, message));
        // tampered message, key, s, e
        assert!(!verify(pk, good, message + Fr::one()));
        assert!(!verify(public_key(secret + Fq::one()), good, message));
        let mut bad = good;
        bad.s[0] = FieldHex(bad.s[0].fr() + Fr::one());
        assert!(!verify(pk, bad, message));
        let mut bad = good;
        bad.e[0] = FieldHex(bad.e[0].fr() + Fr::one());
        assert!(!verify(pk, bad, message));
        // swapped limbs
        let mut bad = good;
        bad.s.swap(0, 1);
        assert!(!verify(pk, bad, message));
        // zero signature, zero s, zero e
        let zero = [FieldHex::default(); 2];
        assert!(!verify(pk, Signature { s: zero, e: zero }, message));
        assert!(!verify(pk, Signature { s: zero, e: good.e }, message));
        assert!(!verify(pk, Signature { s: good.s, e: zero }, message));
        // a limb at 2^128 (Noir fails the execution; false here)
        let mut bad = good;
        bad.s[0] = FieldHex(hex("0x100000000000000000000000000000000"));
        assert!(!verify(pk, bad, message));
        // infinity and off-curve keys
        assert!(!verify(Point::zero(), good, message));
        let (x, y) = pk.xy().unwrap();
        assert!(!verify(
            Point::new_unchecked(x, y + Fr::one()),
            good,
            message
        ));
        let infinity = GrumpkinPoint::default();
        assert!(!verify_wire(&infinity, good, message));
    }

    #[test]
    fn signature_byte_layout() {
        let mut rng = StdRng::seed_from_u64(8);
        let s = sign(Fq::from(99u64), Fr::from(5u64), &mut rng);
        let bytes = signature_to_bytes(&s).unwrap();
        assert_eq!(signature_from_bytes(&bytes), s);
        let mut wide = s;
        wide.e[1] = FieldHex(hex("0x100000000000000000000000000000000"));
        assert!(signature_to_bytes(&wide).is_err());
    }

    // @aztec-labs/foundation 6.0.0 `Schnorr.constructSignature(msg, sk)` with
    // sk = 0x0123…cdef, on the register message of `small_body()`.
    #[test]
    fn accepts_the_typescript_signer() {
        let pk = key(
            "0x1e80aee3834e1297b47c859a4a26339b5c7c4c4096342b360e2b7ba402d1873e",
            "0x0e3faf018f2e20f0811785d35bd8491f32e42833ede83ca1a5f3e1975ce7e25e",
        );
        let secret = scalar_from_field(hex(
            "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        ));
        assert_eq!(public_key(secret), pk);
        let bytes: [u8; 64] = "0x297cda4c102742d5d8e78340925d705e7ba4c6f530a1f8c829c613261349f14615bb6481d37caa2c2cc38b092009ce8fa62153463a6cb796d88e45b8092d29f0"
            .parse::<crate::field::HexBytes>()
            .unwrap()
            .0
            .try_into()
            .unwrap();
        let signature = signature_from_bytes(&bytes);
        // aztec.js toLimbFields() of the same signature
        assert_eq!(
            signature,
            sig(
                [
                    "0x7ba4c6f530a1f8c829c613261349f146",
                    "0x297cda4c102742d5d8e78340925d705e"
                ],
                [
                    "0xa62153463a6cb796d88e45b8092d29f0",
                    "0x15bb6481d37caa2c2cc38b092009ce8f"
                ],
            )
        );
        let message = register_message(&small_body()).unwrap();
        assert!(verify(pk, signature, message));
        assert!(!verify(pk, signature, message + Fr::one()));
    }

    fn small_body() -> Value {
        json!({"b": "x", "a": 1, "c": [true, false, null, -7]})
    }

    fn unicode_body() -> Value {
        json!({
            "\u{20ac}": "\u{e9}\n\t\"\\\u{1}\u{1f}\u{7f}\u{2028}",
            "a": {"z": 0, "\u{1f600}": 1, "\u{ffff}": 2, "B": 3}
        })
    }

    // Canonical forms and messages computed in node with JSON.stringify over
    // members sorted by JavaScript's default (UTF-16) order, which is RFC 8785
    // for strings and safe integers, and @aztec-labs/foundation 6.0.0
    // poseidon2HashBytes.
    #[test]
    fn canonical_json_and_register_message_match_javascript() {
        assert_eq!(
            canonical_json(&small_body()).unwrap(),
            r#"{"a":1,"b":"x","c":[true,false,null,-7]}"#
        );
        assert_eq!(
            canonical_json(&unicode_body()).unwrap(),
            "{\"a\":{\"B\":3,\"z\":0,\"\u{1f600}\":1,\"\u{ffff}\":2},\"\u{20ac}\":\"\u{e9}\\n\\t\\\"\\\\\\u0001\\u001f\u{7f}\u{2028}\"}"
        );
        assert_eq!(
            fr_to_hex(register_message(&small_body()).unwrap()),
            "0x160f3f51dd9740241a118eaa76c560c0c121a0a70ce9ddf986cbaa3dfd347514"
        );
        assert_eq!(
            fr_to_hex(register_message(&unicode_body()).unwrap()),
            "0x02ad3fb2a4d4c2e875c0cccee094752baddf39f92a44167d55a4587177d2a570"
        );
        // the top-level signature is left out; a nested one is not
        let mut signed = small_body();
        signed["signature"] = json!({"s": ["0x1", "0x2"], "e": ["0x3", "0x4"]});
        assert_eq!(register_message(&signed), register_message(&small_body()));
        let mut nested = small_body();
        nested["c"] = json!([{"signature": 1}]);
        assert_ne!(register_message(&nested), register_message(&small_body()));
        // the remaining escapes
        assert_eq!(
            canonical_json(&json!("\u{8}\u{c}\r/\u{0}")).unwrap(),
            r#""\b\f\r/\u0000""#
        );
    }

    // aztec.js poseidon2HashBytes over the same domains and JCS bodies.
    #[test]
    fn message_domains_match_javascript() {
        let disable = json!({"namespace": "0x1f2ea9c0", "circuit": "amm_swap"});
        assert_eq!(
            fr_to_hex(message_for(DISABLE_DOMAIN, &disable).unwrap()),
            "0x1d11df88671db4dd6a10540576fb8dbeedae8403b0a4fb7d1b7be2611dd96784"
        );
        assert_eq!(
            fr_to_hex(message_for(EXECUTE_DOMAIN, &small_body()).unwrap()),
            "0x260beda661080ba3ca5c452a2f1665891ec720a0b941de0464cd97fc8cdb3202"
        );
        assert_eq!(
            message_for(REGISTER_DOMAIN, &small_body()),
            register_message(&small_body())
        );
        // one body, three different messages
        let messages: Vec<Fr> = [REGISTER_DOMAIN, DISABLE_DOMAIN, EXECUTE_DOMAIN]
            .iter()
            .map(|d| message_for(d, &small_body()).unwrap())
            .collect();
        assert!(
            messages[0] != messages[1] && messages[1] != messages[2] && messages[0] != messages[2]
        );
    }

    #[test]
    fn canonical_json_refuses_floats_and_unsafe_integers() {
        for bad in [
            "1.0",
            "0.5",
            "1e3",
            "9007199254740992",
            "-9007199254740992",
            "18446744073709551615",
        ] {
            let value: Value = serde_json::from_str(&format!("{{\"n\":[{bad}]}}")).unwrap();
            assert!(canonical_json(&value).is_err(), "{bad}");
            assert!(register_message(&value).is_err(), "{bad}");
        }
        let edge = json!({"max": 9007199254740991u64, "min": -9007199254740991i64, "zero": 0});
        assert_eq!(
            canonical_json(&edge).unwrap(),
            r#"{"max":9007199254740991,"min":-9007199254740991,"zero":0}"#
        );
        assert!(
            register_message(&json!([1]))
                .unwrap_err()
                .contains("not a JSON object")
        );
    }
}
