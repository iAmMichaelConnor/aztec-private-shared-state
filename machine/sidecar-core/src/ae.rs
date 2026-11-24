//! The field-native authenticated encryption every sealed value uses: the
//! Poseidon2 duplex (SAFE sponge) of `pss_utils/src/ae.nr`, generalised to any
//! number of plaintext fields.
//!
//! The permutation is Poseidon2 of width 4 (rate 3, capacity 1). For `n`
//! plaintext fields, with blocks of at most 3 fields:
//!
//! ```text
//! state = permutation([key, nonce, 0, pattern_tag(n)])
//! for each block (fields 3b .. 3b+k):
//!     if b > 0: state = permutation(state)
//!     for j in 0..k: state[j] += pt[3b + j]; ct[3b + j] = state[j]
//! tag = permutation(state)[0]
//! ```
//!
//! Decryption runs the same transitions with `pt = ct - state[j]` and
//! `state[j] = ct`, and refuses a tag that differs. For `n` of 1, 2 and 3 this
//! is one block with no inner permutation, ae.nr's `AE::encrypt` at those
//! lengths.
//!
//! The pattern tag is the SAFE IO pattern "absorb 2 (key, nonce), then per
//! block squeeze k and absorb k, then squeeze 1 (the tag)", written as 32-bit
//! words (absorb `0x80000000 | k`, squeeze `k`) followed by the 16-bit domain
//! separator `0x4142`:
//!
//! ```text
//! words(n) = [0x80000002, k_0, 0x80000000|k_0, k_1, 0x80000000|k_1, ..., 1]
//! ```
//!
//! While the packed words fit one field element they are packed big-endian into
//! one integer, `((w_0 · 2^32 + w_1) · 2^32 + ...) · 2^16 + 0x4142`, as ae.nr's
//! `pattern_tag` does. That holds for up to two blocks (n ≤ 6, 208 bits). From three
//! blocks (n ≥ 7) the packing would need 272 bits or more, and the tag is
//! instead `poseidon2_hash([w_0, ..., w_last, 0x4142])`, each word a field
//! element.

use ark_ff::Zero;
use mpc_core::gadgets::poseidon2::Poseidon2;

use crate::field::Fr;
use crate::hash::poseidon2_hash;

/// Fields per duplex block: the sponge's rate.
pub const RATE: usize = 3;

// The AEAD pattern tags. The capacity element of the initial state
// carries the SAFE IO pattern of the call, so a ciphertext of one length can
// never be decrypted as another length, and an envelope (n = 2) and a record
// (n ≥ 5) never share a keystream. The domain separator is ae.nr's 0x4142
// ("AB"); n = 1, 2, 3 reproduce ae.nr's T1, T2, T3 bit for bit, n ≤ 6 pack the
// words into one field, n ≥ 7 hash them. Changing the separator, the word
// encoding or the packing threshold changes every ciphertext: every state record
// and every INPUT_SHARED envelope sealed before stops opening, and pss_utils'
// `AE::encrypt/decrypt` (the in-circuit side) must change in the same way.
/// The domain separator appended to every IO pattern.
pub const DOMAIN_SEPARATOR: u64 = 0x4142;

/// The most blocks whose packed pattern still fits one field element.
pub const MAX_PACKED_BLOCKS: usize = 2;

const ABSORB: u32 = 0x8000_0000;

/// The SAFE IO-pattern words for `n` plaintext fields (without the domain
/// separator). Panics if `n` is zero.
pub fn pattern_words(n: usize) -> Vec<u32> {
    assert!(
        n > 0,
        "the authenticated encryption needs at least one field"
    );
    let mut words = vec![ABSORB | 2];
    let mut left = n;
    while left > 0 {
        let k = left.min(RATE) as u32;
        words.push(k);
        words.push(ABSORB | k);
        left -= k as usize;
    }
    words.push(1);
    words
}

/// The capacity element of the initial state for `n` plaintext fields: the
/// packed IO pattern for up to [`MAX_PACKED_BLOCKS`] blocks, its Poseidon2 hash
/// beyond. Panics if `n` is zero.
pub fn pattern_tag(n: usize) -> Fr {
    let words = pattern_words(n);
    let blocks = n.div_ceil(RATE);
    if blocks <= MAX_PACKED_BLOCKS {
        let two32 = Fr::from(1u64 << 32);
        let packed = words
            .iter()
            .fold(Fr::zero(), |acc, w| acc * two32 + Fr::from(*w as u64));
        packed * Fr::from(1u64 << 16) + Fr::from(DOMAIN_SEPARATOR)
    } else {
        let mut fields: Vec<Fr> = words.iter().map(|w| Fr::from(*w as u64)).collect();
        fields.push(Fr::from(DOMAIN_SEPARATOR));
        poseidon2_hash(&fields)
    }
}

fn permute(state: &mut [Fr; 4]) {
    Poseidon2::<Fr, 4, 5>::default().permutation_in_place(state);
}

fn initial_state(key: Fr, nonce: Fr, n: usize) -> [Fr; 4] {
    let mut state = [key, nonce, Fr::zero(), pattern_tag(n)];
    permute(&mut state);
    state
}

/// Encrypt `plaintext` under `(key, nonce)`: the ciphertext (one field per
/// plaintext field) and the tag. A `(key, nonce)` pair must never encrypt two
/// different plaintexts. Panics if `plaintext` is empty.
pub fn encrypt(key: Fr, nonce: Fr, plaintext: &[Fr]) -> (Vec<Fr>, Fr) {
    let mut state = initial_state(key, nonce, plaintext.len());
    let mut ciphertext = Vec::with_capacity(plaintext.len());
    for (i, pt) in plaintext.iter().enumerate() {
        if i > 0 && i % RATE == 0 {
            permute(&mut state);
        }
        state[i % RATE] += pt;
        ciphertext.push(state[i % RATE]);
    }
    permute(&mut state);
    (ciphertext, state[0])
}

/// The ciphertext does not open: wrong key, nonce (associated data) or length,
/// or a tampered ciphertext or tag.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TagMismatch;

impl std::fmt::Display for TagMismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("authentication tag mismatch")
    }
}

impl std::error::Error for TagMismatch {}

/// Decrypt and authenticate. Refuses an empty ciphertext and a tag mismatch;
/// on refusal no plaintext is returned.
pub fn decrypt(key: Fr, nonce: Fr, ciphertext: &[Fr], tag: Fr) -> Result<Vec<Fr>, TagMismatch> {
    if ciphertext.is_empty() {
        return Err(TagMismatch);
    }
    let mut state = initial_state(key, nonce, ciphertext.len());
    let mut plaintext = Vec::with_capacity(ciphertext.len());
    for (i, ct) in ciphertext.iter().enumerate() {
        if i > 0 && i % RATE == 0 {
            permute(&mut state);
        }
        plaintext.push(*ct - state[i % RATE]);
        state[i % RATE] = *ct;
    }
    permute(&mut state);
    if state[0] != tag {
        return Err(TagMismatch);
    }
    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::{fr_from_hex, fr_to_hex};
    use serde_json::{Value, json};

    fn hex(s: &str) -> Fr {
        fr_from_hex(s).unwrap()
    }

    fn vectors_path() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testvectors/ae.json")
    }

    // ae.nr's kat_encrypt_n1, reproduced bit for bit.
    #[test]
    fn kat_encrypt_n1_of_ae_nr() {
        let (ct, tag) = encrypt(
            Fr::from(0x456u64),
            Fr::from(0x789u64),
            &[Fr::from(0x123u64)],
        );
        assert_eq!(
            ct,
            [hex(
                "0x286c1a243c558666b5831713c826988e93d25672dccc21d787e88c81c78209b9"
            )]
        );
        assert_eq!(
            tag,
            hex("0x143e77b81535095f93e3a50e6fbc2debc978878f97c60407a07c839736d98df4")
        );
    }

    // T1, T2 and T3 as ae.nr writes them.
    #[test]
    fn single_block_tags_are_ae_nr_globals() {
        assert_eq!(
            pattern_tag(1),
            hex("0x800000020000000180000001000000014142")
        );
        assert_eq!(
            pattern_tag(2),
            hex("0x800000020000000280000002000000014142")
        );
        assert_eq!(
            pattern_tag(3),
            hex("0x800000020000000380000003000000014142")
        );
        // Two blocks still pack; three hash.
        assert_eq!(
            pattern_tag(4),
            hex("0x8000000200000003800000030000000180000001000000014142")
        );
        assert_eq!(
            pattern_words(7),
            [
                0x8000_0002,
                3,
                0x8000_0003,
                3,
                0x8000_0003,
                1,
                0x8000_0001,
                1
            ]
        );
        let mut fields: Vec<Fr> = pattern_words(7)
            .iter()
            .map(|w| Fr::from(*w as u64))
            .collect();
        fields.push(Fr::from(0x4142u64));
        assert_eq!(pattern_tag(7), poseidon2_hash(&fields));
    }

    #[test]
    fn round_trip_and_refusals() {
        for n in 1..=12usize {
            let pt: Vec<Fr> = (0..n as u64).map(|j| Fr::from(1000 + j)).collect();
            let (key, nonce) = (Fr::from(7u64), Fr::from(9u64));
            let (ct, tag) = encrypt(key, nonce, &pt);
            assert_eq!(decrypt(key, nonce, &ct, tag).unwrap(), pt, "n = {n}");
            assert_eq!(
                decrypt(key + Fr::from(1u64), nonce, &ct, tag),
                Err(TagMismatch)
            );
            assert_eq!(
                decrypt(key, nonce + Fr::from(1u64), &ct, tag),
                Err(TagMismatch)
            );
            assert_eq!(
                decrypt(key, nonce, &ct, tag + Fr::from(1u64)),
                Err(TagMismatch)
            );
            for j in 0..n {
                let mut bad = ct.clone();
                bad[j] += Fr::from(1u64);
                assert_eq!(
                    decrypt(key, nonce, &bad, tag),
                    Err(TagMismatch),
                    "n {n} j {j}"
                );
            }
            // A prefix or an extension is another length, so another pattern.
            if n > 1 {
                assert_eq!(decrypt(key, nonce, &ct[..n - 1], tag), Err(TagMismatch));
            }
            let mut longer = ct.clone();
            longer.push(Fr::zero());
            assert_eq!(decrypt(key, nonce, &longer, tag), Err(TagMismatch));
        }
        assert_eq!(
            decrypt(Fr::zero(), Fr::zero(), &[], Fr::zero()),
            Err(TagMismatch)
        );
    }

    // The ae.json vectors: n = 1 is ae.nr's kat_encrypt_n1; the others take
    // full-width values from Poseidon2 so every lane is exercised.
    const LENGTHS: [usize; 6] = [1, 2, 3, 4, 7, 10];

    fn vector_inputs(n: usize) -> (Fr, Fr, Vec<Fr>) {
        if n == 1 {
            return (
                Fr::from(0x456u64),
                Fr::from(0x789u64),
                vec![Fr::from(0x123u64)],
            );
        }
        let nf = Fr::from(n as u64);
        let key = poseidon2_hash(&[Fr::from(1u64), nf]);
        let nonce = poseidon2_hash(&[Fr::from(2u64), nf]);
        let pt = (0..n as u64)
            .map(|j| poseidon2_hash(&[Fr::from(3u64), nf, Fr::from(j)]))
            .collect();
        (key, nonce, pt)
    }

    fn vectors_json() -> Value {
        let to_hex = |v: &[Fr]| v.iter().map(|f| fr_to_hex(*f)).collect::<Vec<_>>();
        let vectors: Vec<Value> = LENGTHS
            .iter()
            .map(|&n| {
                let (key, nonce, pt) = vector_inputs(n);
                let (ct, tag) = encrypt(key, nonce, &pt);
                json!({
                    "n": n,
                    "key": fr_to_hex(key),
                    "nonce": fr_to_hex(nonce),
                    "pattern_tag": fr_to_hex(pattern_tag(n)),
                    "plaintext": to_hex(&pt),
                    "ciphertext": to_hex(&ct),
                    "tag": fr_to_hex(tag),
                })
            })
            .collect();
        json!({
            "construction": "Poseidon2 (width 4, rate 3) duplex as pss_utils/src/ae.nr: state = permutation([key, nonce, 0, pattern_tag(n)]); per block of up to 3 fields, after the first block state = permutation(state), then state[j] += pt[j] and ct[j] = state[j]; tag = permutation(state)[0].",
            "pattern_rule": "words = [0x80000002, then per block k and 0x80000000|k, then 1]; for up to two blocks (n <= 6) pattern_tag packs the 32-bit words big-endian followed by the 16-bit domain 0x4142 (n = 1, 2, 3 are ae.nr's T1, T2, T3); from three blocks (n >= 7) pattern_tag = poseidon2_hash([words..., 0x4142]).",
            "inputs": "n = 1 is ae.nr's kat_encrypt_n1 (pt 0x123, key 0x456, nonce 0x789); otherwise key = poseidon2_hash([1, n]), nonce = poseidon2_hash([2, n]), pt[j] = poseidon2_hash([3, n, j]).",
            "vectors": vectors,
        })
    }

    // Regenerates testvectors/ae.json:
    // cargo test -p sidecar-core ae::tests::write_ae_json -- --ignored
    #[test]
    #[ignore = "writes testvectors/; run on purpose"]
    fn write_ae_json() {
        let text = serde_json::to_string_pretty(&vectors_json()).unwrap() + "\n";
        std::fs::write(vectors_path(), text).unwrap();
    }
}
