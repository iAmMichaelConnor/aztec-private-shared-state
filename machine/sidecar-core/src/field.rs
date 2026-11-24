//! The hex encodings every JSON type uses: field elements, opaque bytes and
//! request ids.

use std::fmt;
use std::str::FromStr;

use ark_ff::{BigInteger, PrimeField};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// The BN254 scalar field. Grumpkin's base field is the same field, so Grumpkin
/// point coordinates are `Fr` too.
pub type Fr = ark_bn254::Fr;

/// 32-byte big-endian encoding (bb's public-input format; also the store key).
pub fn fr_to_be_bytes(value: Fr) -> Vec<u8> {
    value.into_bigint().to_bytes_be()
}

/// `0x` + 64 lowercase hex digits, as aztec.js prints an `Fr`.
pub fn fr_to_hex(value: Fr) -> String {
    let mut out = String::with_capacity(66);
    out.push_str("0x");
    push_hex(&mut out, &fr_to_be_bytes(value));
    out
}

/// `0x` + lowercase hex digits without leading zeros (`0x0` for zero): the
/// one spelling of a request key that names a field element under intake
/// direct (`bind::check_request`).
pub fn fr_to_short_hex(value: Fr) -> String {
    let full = fr_to_hex(value);
    let digits = full[2..].trim_start_matches('0');
    format!("0x{}", if digits.is_empty() { "0" } else { digits })
}

// Field-element encoding. Input is an optional `0x`, then 1 to 64
// hex digits, big-endian, left-padded to 32 bytes. A value at or above the BN254
// scalar modulus is refused (bad_request), never reduced mod r, so every field
// element has exactly one meaning and a client bug that overflows is caught here
// rather than silently aliasing another value. Reducing instead would let two
// different strings hash and bind as the same field. Output is always `0x` + 64
// lowercase digits.
/// Parse a `0x`-prefixed (or bare) big-endian hex field element.
pub fn fr_from_hex(text: &str) -> Result<Fr, String> {
    let digits = text.strip_prefix("0x").unwrap_or(text);
    if digits.is_empty() || digits.len() > 64 || !digits.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("`{text}` is not a 1 to 64 digit hex number"));
    }
    let padded = format!("{digits:0>64}");
    let mut bytes = [0u8; 32];
    for (i, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&padded[2 * i..2 * i + 2], 16)
            .map_err(|_| format!("`{text}` is not valid hex"))?;
    }
    let value = Fr::from_be_bytes_mod_order(&bytes);
    // Reduction changed the bytes exactly when the value was >= the modulus.
    if fr_to_be_bytes(value) != bytes {
        return Err(format!(
            "`{text}` is not below the bn254 scalar field modulus"
        ));
    }
    Ok(value)
}

/// Append `bytes` as lowercase hex digits, two per byte.
pub(crate) fn push_hex(out: &mut String, bytes: &[u8]) {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    for byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0xf) as usize] as char);
    }
}

/// The bytes of an even number of hex digits (no `0x`).
pub(crate) fn bytes_from_hex(digits: &str) -> Result<Vec<u8>, String> {
    if !digits.len().is_multiple_of(2) {
        return Err("odd number of hex digits".into());
    }
    if !digits.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("not valid hex".into());
    }
    (0..digits.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&digits[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

/// A field element as it appears in JSON: a hex string under the rule of
/// [`fr_from_hex`]. Serialises as `0x` + 64 lowercase hex digits.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FieldHex(pub Fr);

impl FieldHex {
    pub fn fr(self) -> Fr {
        self.0
    }
}

impl From<Fr> for FieldHex {
    fn from(value: Fr) -> Self {
        FieldHex(value)
    }
}

impl From<u64> for FieldHex {
    fn from(value: u64) -> Self {
        FieldHex(Fr::from(value))
    }
}

impl From<FieldHex> for Fr {
    fn from(value: FieldHex) -> Self {
        value.0
    }
}

impl FromStr for FieldHex {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        fr_from_hex(s).map(FieldHex)
    }
}

impl fmt::Display for FieldHex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&fr_to_hex(self.0))
    }
}

impl Serialize for FieldHex {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&fr_to_hex(self.0))
    }
}

impl<'de> Deserialize<'de> for FieldHex {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        fr_from_hex(&text)
            .map(FieldHex)
            .map_err(serde::de::Error::custom)
    }
}

/// Opaque bytes as `0x` hex (a proof, a state-record ciphertext, a vk). The `0x`
/// is required and the digit count must be even; `0x` alone is the empty string.
/// Serialises as `0x` + lowercase hex.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct HexBytes(pub Vec<u8>);

impl HexBytes {
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl From<Vec<u8>> for HexBytes {
    fn from(value: Vec<u8>) -> Self {
        HexBytes(value)
    }
}

impl FromStr for HexBytes {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let digits = s
            .strip_prefix("0x")
            .ok_or_else(|| format!("`{s}` does not start with 0x"))?;
        bytes_from_hex(digits)
            .map(HexBytes)
            .map_err(|e| format!("`{s}`: {e}"))
    }
}

impl fmt::Display for HexBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut out = String::with_capacity(2 + 2 * self.0.len());
        out.push_str("0x");
        push_hex(&mut out, &self.0);
        f.write_str(&out)
    }
}

impl Serialize for HexBytes {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for HexBytes {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        text.parse().map_err(serde::de::Error::custom)
    }
}

// A request id is one field element, written and parsed like
// any field (`0x` + 1 to 64 hex digits in, `0x` + 64 out, refused at or above
// the modulus), so it enters every hash (the envelope AD, the handshake
// summands, the result message) as itself, with no conversion. A note-mode
// client draws 128 random bits for it: FETCH is open and scoped only by
// (namespace, request_id), so the id's unguessability is what keeps one
// requester from fetching another's proof and public outputs, and fewer bits
// make it guessable. The tip's scheduler instead derives it from the chain
// request and the old commitments, which makes results public on purpose. The
// machine does not check the entropy of an id; that is the client's property.
/// The request id: one field element.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RequestId(pub Fr);

impl RequestId {
    /// The id as the field element every hash takes.
    pub fn fr(self) -> Fr {
        self.0
    }

    /// A note-mode id: 128 bits from `bytes` read as a big-endian integer.
    pub fn from_u128_bytes(bytes: [u8; 16]) -> Self {
        RequestId(Fr::from(u128::from_be_bytes(bytes)))
    }
}

impl From<Fr> for RequestId {
    fn from(value: Fr) -> Self {
        RequestId(value)
    }
}

impl From<u64> for RequestId {
    fn from(value: u64) -> Self {
        RequestId(Fr::from(value))
    }
}

impl FromStr for RequestId {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        fr_from_hex(s).map(RequestId)
    }
}

impl fmt::Display for RequestId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&fr_to_hex(self.0))
    }
}

impl Serialize for RequestId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&fr_to_hex(self.0))
    }
}

impl<'de> Deserialize<'de> for RequestId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        text.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MODULUS: &str = "0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001";

    fn hex(s: &str) -> Fr {
        fr_from_hex(s).unwrap()
    }

    #[test]
    fn hex_roundtrip() {
        let x = Fr::from_str("12345678901234567890").unwrap();
        assert_eq!(hex(&fr_to_hex(x)), x);
        assert_eq!(fr_to_hex(Fr::from(1u64)).len(), 66);
        assert_eq!(hex("0x1"), Fr::from(1u64));
        assert_eq!(hex("ff02"), Fr::from(0xff02u64));
        assert_eq!(hex("0xFF02"), Fr::from(0xff02u64));
        assert_eq!(
            fr_to_hex(Fr::from(0xabcu64)),
            "0x0000000000000000000000000000000000000000000000000000000000000abc"
        );
    }

    #[test]
    fn hex_refusals() {
        assert!(fr_from_hex("").is_err());
        assert!(fr_from_hex("0x").is_err());
        assert!(fr_from_hex("0xzz").is_err());
        assert!(fr_from_hex("0x-1").is_err());
        assert!(fr_from_hex(&format!("0x{}", "0".repeat(65))).is_err());
        // the modulus itself and the largest 64-digit value: refused, not reduced
        let err = fr_from_hex(MODULUS).unwrap_err();
        assert!(err.contains("modulus"), "{err}");
        assert!(fr_from_hex(&format!("0x{}", "f".repeat(64))).is_err());
        // modulus - 1 is the largest accepted value
        let below = "0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000";
        assert_eq!(fr_to_hex(hex(below)), below);
    }

    #[test]
    fn field_hex_serde() {
        let v: FieldHex = serde_json::from_str("\"0x2710\"").unwrap();
        assert_eq!(v.0, Fr::from(10000u64));
        assert_eq!(
            serde_json::to_string(&v).unwrap(),
            "\"0x0000000000000000000000000000000000000000000000000000000000002710\""
        );
        assert!(serde_json::from_str::<FieldHex>("10000").is_err());
        assert!(serde_json::from_str::<FieldHex>(&format!("\"{MODULUS}\"")).is_err());
    }

    #[test]
    fn hex_bytes_serde() {
        let b: HexBytes = serde_json::from_str("\"0xDEadbeef\"").unwrap();
        assert_eq!(b.0, vec![0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(serde_json::to_string(&b).unwrap(), "\"0xdeadbeef\"");
        let empty: HexBytes = serde_json::from_str("\"0x\"").unwrap();
        assert!(empty.0.is_empty());
        assert!(serde_json::from_str::<HexBytes>("\"deadbeef\"").is_err());
        assert!(serde_json::from_str::<HexBytes>("\"0xabc\"").is_err());
        assert!(serde_json::from_str::<HexBytes>("\"0xgg\"").is_err());
    }

    #[test]
    fn request_id_is_one_field_element() {
        let text = "0x000102030405060708090a0b0c0d0e0f";
        let id: RequestId = text.parse().unwrap();
        assert_eq!(id.fr(), Fr::from(0x000102030405060708090a0b0c0d0e0fu128));
        assert_eq!(
            id,
            RequestId::from_u128_bytes([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15])
        );
        let wide = format!("0x{}", "0".repeat(32) + &text[2..]);
        assert_eq!(id.to_string(), wide);
        assert_eq!(serde_json::to_string(&id).unwrap(), format!("\"{wide}\""));
        let upper: RequestId = "0x000102030405060708090A0B0C0D0E0F".parse().unwrap();
        assert_eq!(upper, id);
        // Any field element is an id, the tip's derived ones included.
        let below = "0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000";
        assert_eq!(below.parse::<RequestId>().unwrap().to_string(), below);
        for bad in [
            MODULUS,
            "0x",
            "0xzz",
            &format!("0x{}", "1".repeat(65)),
            "swap-41d3",
        ] {
            assert!(bad.parse::<RequestId>().is_err(), "{bad}");
        }
        assert!(serde_json::from_str::<RequestId>("7").is_err());
    }
}
