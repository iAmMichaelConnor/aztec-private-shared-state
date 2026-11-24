//! Sealed state records: node i's third of a stored vector, encrypted under its
//! record key `K_i` with the Poseidon2 AE of [`crate::ae`].
//!
//! ```text
//! key_hash  = poseidon2_hash_bytes(key)        31-byte chunks, as aztec.js poseidon2HashBytes
//! plaintext = [namespace, key_hash, note_hash, elem_0, elem_1, ...]
//!   elem    = [0, v]          a Public element v
//!           | [1, x_i, x_i-1] node i's pair of a Shared element (blinding included)
//! nonce     = poseidon2_hash([namespace, key_hash, note_hash, owner.x, owner.y, SIDECAR_RECORD_AD])
//! (ct, tag) = ae::encrypt(K_i, nonce, plaintext)
//! c_i       = key_id (8 bytes) ‖ ct[0] ‖ ... ‖ ct[n-1] ‖ tag   each field 32 bytes big-endian
//! key_id    = poseidon2([enc_pk.x, enc_pk.y]) as 32 bytes big-endian, first 8 bytes
//! H(c_i)    = poseidon2_hash([key_id as a big-endian integer, ct[0], ..., tag])   record_hashes[i]
//! ```
//!
//! The associated data is carried by the nonce, which the tag covers, so a
//! record opens only under the namespace, key, note hash and owner it was sealed
//! for. The same seal holds the replaced vector of a rewritten node-held key,
//! with the node's own encryption key as owner (see [`crate::store`]).
//!
//! A third is sealed under the node's current encryption key and opens under
//! the key its key id names: the current one, or the previous one during an
//! enc rotation's grace window ([`crate::keys::NodeKeys::rotate_enc`]).

use ark_ff::{One, PrimeField, Zero};

use crate::ae;
use crate::bind::{Elem, Share};
use crate::error::Refusal;
use crate::field::{Fr, fr_to_be_bytes};
use crate::grumpkin::{Point, coordinates};
use crate::hash::poseidon2_hash;
pub use crate::keys::KEY_ID_LEN;
use crate::keys::{NodeKeys, label_field};
use crate::schnorr::poseidon2_hash_bytes;

/// The associated-data separator: ASCII "sidecar.record_ad" read as a
/// big-endian integer.
pub const SIDECAR_RECORD_AD: &[u8] = b"sidecar.record_ad";

// The sealed-record plaintext layout. The AE plaintext of a
// third is the header `[namespace, key_hash, note_hash]` (HEADER fields: the
// associated data repeated inside the ciphertext, which `open` compares after
// decryption as a second check, independent of the nonce, that the record is
// the one the request names), then per element `[TAG_PUBLIC, v]` for a
// public value or `[TAG_SHARED, x_i, x_{i-1}]` for node i's share pair,
// blinding included. On the wire each field is FIELD_LEN = 32 bytes
// big-endian after the 8-byte key id, with the AE tag last; clients, the
// orchestrator and the tip only carry these bytes and hash them
// (`record_hash`), and only the node that sealed a third opens it. Changing
// any of it (the header, the tag values, the field width or the byte order)
// makes every record a client holds, every sealed replaced vector in
// `requests` and every chain-held third unreadable, and changes every
// `record_hashes` entry; a change needs a versioned record.
const FIELD_LEN: usize = 32;
const HEADER: usize = 3;
const TAG_PUBLIC: u64 = 0;
const TAG_SHARED: u64 = 1;

/// The field a key string is bound as: `poseidon2_hash_bytes(key)`, the bytes
/// cut into 31-byte little-endian chunks (aztec.js `poseidon2HashBytes`, the
/// helper the Schnorr message rule uses too).
pub fn key_hash(key: &str) -> Fr {
    poseidon2_hash_bytes(key.as_bytes())
}

// The record's associated data is (namespace, key, note_hash,
// owner), hashed to the AE nonce with the separator SIDECAR_RECORD_AD. namespace
// and key stop a record moving to another namespace or key; note_hash stops it
// claiming another state; owner is the requester's Grumpkin public key from the
// request that created the record, so only a request carrying that key (and,
// at the node, the owner's signature over the body) can spend the state's one
// evaluation: the orchestrator or anyone else who saw the ciphertext cannot. For
// a replaced node-held vector the owner is the node's own enc_pk. The nonce is
// unique per sealed value as long as each stored value's note hash is unique,
// which it is when the circuit's note hash commits to a fresh blinding
// (pss_core's note layout ends in one); a circuit that output the same note
// hash for two different vectors under one key would reuse (K_i, nonce).
// Dropping owner makes records bearer capabilities; adding a field changes
// every record.
/// The AE nonce of a record: its associated data hashed to one field.
pub fn associated_data(namespace: Fr, key: &str, note_hash: Fr, owner: Point) -> Fr {
    let (x, y) = coordinates(owner);
    poseidon2_hash(&[
        namespace,
        key_hash(key),
        note_hash,
        x,
        y,
        label_field(SIDECAR_RECORD_AD),
    ])
}

/// A stored vector as fields: `[0, v]` per public element, `[1, a, b]` per
/// share pair (`a` = this node's `x_i`, `b` = `x_{i-1}`).
pub fn encode_elements(vec: &[Elem]) -> Vec<Fr> {
    let mut out = Vec::with_capacity(3 * vec.len());
    for elem in vec {
        match elem {
            Elem::Public(v) => out.extend([Fr::from(TAG_PUBLIC), *v]),
            Elem::Shared(s) => out.extend([Fr::from(TAG_SHARED), s.a, s.b]),
        }
    }
    out
}

/// The inverse of [`encode_elements`]; refuses an unknown tag or a truncated
/// element.
pub fn decode_elements(mut fields: &[Fr]) -> Result<Vec<Elem>, String> {
    let mut out = Vec::new();
    while let Some((tag, rest)) = fields.split_first() {
        if tag.is_zero() {
            let [v, tail @ ..] = rest else {
                return Err("a public element is truncated".into());
            };
            out.push(Elem::Public(*v));
            fields = tail;
        } else if tag.is_one() {
            let [a, b, tail @ ..] = rest else {
                return Err("a shared element is truncated".into());
            };
            out.push(Elem::Shared(Share::new(*a, *b)));
            fields = tail;
        } else {
            return Err(format!("unknown element tag {tag}"));
        }
    }
    Ok(out)
}

/// Seal node `keys`'s third `vec` of the value at (namespace, key) with note
/// hash `note_hash`, for `owner`.
pub fn seal(
    keys: &NodeKeys,
    namespace: Fr,
    key: &str,
    note_hash: Fr,
    owner: Point,
    vec: &[Elem],
) -> Vec<u8> {
    let mut plaintext = vec![namespace, key_hash(key), note_hash];
    plaintext.extend(encode_elements(vec));
    let nonce = associated_data(namespace, key, note_hash, owner);
    let (ct, tag) = ae::encrypt(keys.seal_key(), nonce, &plaintext);
    let mut out = Vec::with_capacity(KEY_ID_LEN + FIELD_LEN * (ct.len() + 1));
    out.extend_from_slice(&keys.key_id());
    for field in ct.iter().chain(std::iter::once(&tag)) {
        out.extend(fr_to_be_bytes(*field));
    }
    out
}

// The size of a sealed third in fields, as [`third_fields`] gives it: the
// key id as one field (as `record_hash` reads it), the HEADER fields, three
// per element counted as shared (`[TAG_SHARED, x_i, x_{i-1}]`; a public
// element takes two, so this is the most a vector of n elements takes), and
// the tag: 3n + 5. A size bound over thirds (sidecar-tip counts with this
// function) follows this layout and cannot drift from it; a change to the
// plaintext layout (the comment at FIELD_LEN) changes the bound with it.
/// The most fields [`third_fields`] gives for node i's sealed third of an
/// `elements`-element vector: the key id, the three header fields, three per
/// element (each counted as shared) and the tag, `3·elements + 5`. On the
/// wire the key id is [`KEY_ID_LEN`] bytes and every other field 32 bytes.
pub const fn third_fields_len(elements: usize) -> usize {
    const KEY_ID: usize = 1;
    const PER_SHARED: usize = 3;
    const TAG: usize = 1;
    KEY_ID + HEADER + PER_SHARED * elements + TAG
}

// The field elements of a sealed third after its key id: each 32-byte chunk,
// refused if it is not a canonical field encoding.
fn sealed_fields(body: &[u8]) -> Option<Vec<Fr>> {
    body.chunks(FIELD_LEN)
        .map(|chunk| {
            let value = Fr::from_be_bytes_mod_order(chunk);
            (fr_to_be_bytes(value) == chunk).then_some(value)
        })
        .collect()
}

/// The hash a request carries for a sealed third in `record_hashes[i]`, as
/// `share_hashes` for envelopes: `poseidon2_hash([key_id, ct[0], ..., ct[n-1],
/// tag])`, the 8-byte key id read as a big-endian integer, so the hash covers
/// every byte of `c_i`. Node i refuses a request whose `c_i` does not hash to
/// `record_hashes[i]`; the client and the orchestrator can check all three.
/// Refuses (400) bytes that are not a sealed record.
pub fn record_hash(c_i: &[u8]) -> Result<Fr, Refusal> {
    Ok(poseidon2_hash(&third_fields(c_i)?))
}

/// A sealed third as the field elements `[key id, ct[0], ..., ct[n-1], tag]`
/// that [`record_hash`] hashes, the 8-byte key id read as a big-endian
/// integer. Refuses (400) bytes that are not a sealed record.
pub fn third_fields(c_i: &[u8]) -> Result<Vec<Fr>, Refusal> {
    let not_a_record =
        || Refusal::bad_request(format!("{} bytes are not a sealed state record", c_i.len()));
    let body = c_i
        .get(KEY_ID_LEN..)
        .filter(|b| b.len().is_multiple_of(FIELD_LEN) && b.len() >= FIELD_LEN * 2)
        .ok_or_else(not_a_record)?;
    let mut fields = vec![Fr::from_be_bytes_mod_order(&c_i[..KEY_ID_LEN])];
    fields.extend(sealed_fields(body).ok_or_else(not_a_record)?);
    Ok(fields)
}

fn hex8(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(2 * bytes.len());
    crate::field::push_hex(&mut out, bytes);
    out
}

/// Open a sealed third under this node's keys and the associated data the
/// request implies: under the current record key, or the previous one during a
/// grace window, as the third's key id says. Every refusal is `bad_request`
/// naming the key: a record that is not a sealed record, one sealed under
/// another node key (or a retired key of this node), and one that does not
/// authenticate (tampered, or sealed for another namespace, key, note hash or
/// owner).
pub fn open(
    keys: &NodeKeys,
    namespace: Fr,
    key: &str,
    note_hash: Fr,
    owner: Point,
    c_i: &[u8],
) -> Result<Vec<Elem>, Refusal> {
    let body = c_i
        .get(KEY_ID_LEN..)
        .filter(|b| b.len().is_multiple_of(FIELD_LEN) && b.len() >= FIELD_LEN * (HEADER + 1))
        .ok_or_else(|| {
            Refusal::bad_request(format!(
                "state record for key `{key}` is not a sealed record ({} bytes)",
                c_i.len()
            ))
        })?;
    let Some(seal_key) = keys.seal_key_for(&c_i[..KEY_ID_LEN]) else {
        return Err(Refusal::bad_request(format!(
            "state record for key `{key}` was sealed under another node key (key id 0x{}, this node's is 0x{})",
            hex8(&c_i[..KEY_ID_LEN]),
            hex8(&keys.key_id())
        )));
    };
    let not_open = || {
        Refusal::bad_request(format!(
            "state record for key `{key}`: record does not open or its associated data differs"
        ))
    };
    // A non-canonical encoding (>= the modulus) was never sealed.
    let mut fields = sealed_fields(body).ok_or_else(not_open)?;
    let tag = fields.pop().expect("at least one field");
    let nonce = associated_data(namespace, key, note_hash, owner);
    let plaintext = ae::decrypt(seal_key, nonce, &fields, tag).map_err(|_| not_open())?;
    if plaintext[..HEADER] != [namespace, key_hash(key), note_hash] {
        return Err(not_open());
    }
    decode_elements(&plaintext[HEADER..]).map_err(|why| {
        Refusal::bad_request(format!(
            "state record for key `{key}` opens but does not decode: {why}"
        ))
    })
}

// The owner of a record the node seals for itself (a sealed
// replaced vector; at the tip, a chain-held record) is the enc public key the
// third is sealed under: the current key at seal time. Such a record is
// opened with the owner its own key id names (`NodeKeys::enc_pk_for`), never
// with whatever key is current when it is opened, so a rollback or a
// chain-held load still opens it after an enc rotation, for as long as the
// grace window keeps the previous key. Opening with the current key instead
// would make every record sealed before a rotation fail its tag at once; once
// the previous key is retired its records are lost either way, like a lost
// record. Binding the owner to the sealing key (rather than to a fixed node
// identity) keeps one rule for every record: the owner is in the associated
// data, and a record moved to another owner does not open.
/// Open a third this node sealed for itself: as [`open`], with the owner
/// taken from the third's key id (the current or, during a grace window, the
/// previous enc public key). A key id this node no longer holds is refused as
/// [`open`] refuses it.
pub fn open_own(
    keys: &NodeKeys,
    namespace: Fr,
    key: &str,
    note_hash: Fr,
    c_i: &[u8],
) -> Result<Vec<Elem>, Refusal> {
    let owner = c_i
        .get(..KEY_ID_LEN)
        .and_then(|id| keys.enc_pk_for(id))
        .unwrap_or_else(|| keys.enc_pk());
    open(keys, namespace, key, note_hash, owner, c_i)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ErrorClass;
    use crate::grumpkin::{fixed_base_mul, scalar_from_field};

    fn keys(i: u8) -> NodeKeys {
        crate::keys::tests::sample_keys(i as usize)
    }

    fn owner(seed: u64) -> Point {
        fixed_base_mul(scalar_from_field(Fr::from(seed)))
    }

    fn vector(len: usize) -> Vec<Elem> {
        (0..len as u64)
            .map(|i| {
                if i == 1 {
                    Elem::Public(Fr::from(500 + i))
                } else {
                    Elem::Shared(Share::new(Fr::from(10 * i + 1), Fr::from(10 * i + 2)))
                }
            })
            .collect()
    }

    const NS: u64 = 0x1f2e;
    const KEY: &str = "0xa002";

    #[test]
    fn seal_and_open_round_trip() {
        let k = keys(1);
        for len in [1, 2, 10] {
            let vec = vector(len);
            let c = seal(&k, Fr::from(NS), KEY, Fr::from(77u64), owner(5), &vec);
            // key id, then 3 header fields, the elements, and the tag
            let fields = HEADER + encode_elements(&vec).len() + 1;
            assert_eq!(c.len(), KEY_ID_LEN + FIELD_LEN * fields);
            assert_eq!(c[..8], k.key_id());
            let opened = open(&k, Fr::from(NS), KEY, Fr::from(77u64), owner(5), &c).unwrap();
            assert_eq!(opened, vec, "len {len}");
        }
        // A public element survives as public.
        assert!(matches!(vector(2)[1], Elem::Public(_)));
    }

    fn refused(result: Result<Vec<Elem>, Refusal>, needle: &str) {
        crate::error::assert_refused(result, ErrorClass::BadRequest, &[needle, KEY]);
    }

    #[test]
    fn associated_data_mismatch_is_refused() {
        let k = keys(1);
        let (ns, nh) = (Fr::from(NS), Fr::from(77u64));
        let c = seal(&k, ns, KEY, nh, owner(5), &vector(3));
        let differs = "does not open or its associated data differs";
        refused(
            open(&k, ns + Fr::from(1u64), KEY, nh, owner(5), &c),
            differs,
        );
        let err = open(&k, ns, "0xa003", nh, owner(5), &c).unwrap_err();
        assert!(err.message.contains(differs) && err.message.contains("0xa003"));
        refused(
            open(&k, ns, KEY, nh + Fr::from(1u64), owner(5), &c),
            differs,
        );
        refused(open(&k, ns, KEY, nh, owner(6), &c), differs);
        // Tampered ciphertext or tag.
        for at in [KEY_ID_LEN + 31, c.len() - 1] {
            let mut bad = c.clone();
            bad[at] ^= 1;
            refused(open(&k, ns, KEY, nh, owner(5), &bad), differs);
        }
        // A non-canonical field.
        let mut bad = c.clone();
        bad[KEY_ID_LEN..KEY_ID_LEN + 32].fill(0xff);
        refused(open(&k, ns, KEY, nh, owner(5), &bad), differs);
    }

    #[test]
    fn another_nodes_key_is_refused_by_key_id() {
        let c = seal(
            &keys(1),
            Fr::from(NS),
            KEY,
            Fr::from(77u64),
            owner(5),
            &vector(2),
        );
        refused(
            open(&keys(2), Fr::from(NS), KEY, Fr::from(77u64), owner(5), &c),
            "sealed under another node key",
        );
        // Truncated or not a record at all.
        for bad in [&c[..5], &c[..c.len() - 1], &c[..KEY_ID_LEN + 3 * FIELD_LEN]] {
            refused(
                open(&keys(1), Fr::from(NS), KEY, Fr::from(77u64), owner(5), bad),
                "not a sealed record",
            );
        }
    }

    #[test]
    fn a_third_under_the_previous_key_opens_in_the_grace_window() {
        let (ns, nh) = (Fr::from(NS), Fr::from(77u64));
        let old = keys(1);
        let c = seal(&old, ns, KEY, nh, owner(5), &vector(3));
        let rotated = old.rotate_enc(keys(2).enc_scalar(), 0).unwrap();
        assert_eq!(
            open(&rotated, ns, KEY, nh, owner(5), &c).unwrap(),
            vector(3)
        );
        // New thirds carry the new key id and open after the window closes.
        let resealed = seal(&rotated, ns, KEY, nh, owner(5), &vector(3));
        assert_eq!(resealed[..8], rotated.key_id());
        assert_ne!(resealed[..8], old.key_id());
        let retired = rotated.retire_previous_enc();
        assert_eq!(
            open(&retired, ns, KEY, nh, owner(5), &resealed).unwrap(),
            vector(3)
        );
        refused(
            open(&retired, ns, KEY, nh, owner(5), &c),
            "sealed under another node key",
        );
    }

    #[test]
    fn record_hash_covers_every_byte() {
        let c = seal(
            &keys(1),
            Fr::from(NS),
            KEY,
            Fr::from(77u64),
            owner(5),
            &vector(2),
        );
        let mut fields = vec![Fr::from_be_bytes_mod_order(&c[..8])];
        fields.extend(c[8..].chunks(32).map(Fr::from_be_bytes_mod_order));
        assert_eq!(record_hash(&c).unwrap(), poseidon2_hash(&fields));
        for at in [0, 8, c.len() - 1] {
            let mut other = c.clone();
            other[at] ^= 1;
            assert_ne!(
                record_hash(&other).unwrap(),
                record_hash(&c).unwrap(),
                "{at}"
            );
        }
        let mut junk = c.clone();
        junk[8..40].fill(0xff);
        assert_eq!(
            record_hash(&junk).unwrap_err().class,
            ErrorClass::BadRequest
        );
        assert!(record_hash(&c[..c.len() - 1]).is_err());
        assert!(record_hash(&c[..8]).is_err());
    }

    /// `third_fields_len` is the layout `seal` writes: a vector of n shared
    /// elements seals to the key id and `third_fields_len(n) - 1` 32-byte
    /// fields; a public element takes one field less.
    #[test]
    fn third_fields_len_is_the_seal_as_built() {
        let k = keys(0);
        let shared = |n: u64| -> Vec<Elem> {
            (0..n)
                .map(|i| Elem::Shared(Share::new(Fr::from(i + 1), Fr::from(i + 2))))
                .collect()
        };
        for n in [0usize, 1, 2, 3, 7, 453] {
            let c = seal(
                &k,
                Fr::from(NS),
                KEY,
                Fr::from(9u64),
                owner(5),
                &shared(n as u64),
            );
            assert_eq!(
                c.len(),
                KEY_ID_LEN + FIELD_LEN * (third_fields_len(n) - 1),
                "n = {n}"
            );
        }
        assert_eq!(third_fields_len(1), 8);
        assert_eq!(third_fields_len(453), 1364);
        let mixed = vector(3); // one public element of three
        let c = seal(&k, Fr::from(NS), KEY, Fr::from(9u64), owner(5), &mixed);
        assert_eq!(c.len(), KEY_ID_LEN + FIELD_LEN * (third_fields_len(3) - 2));
    }

    #[test]
    fn third_fields_hash_as_record_hash() {
        let c = seal(
            &keys(1),
            Fr::from(NS),
            KEY,
            Fr::from(77u64),
            owner(5),
            &vector(3),
        );
        let fields = third_fields(&c).unwrap();
        assert_eq!(fields.len(), 1 + (c.len() - KEY_ID_LEN) / FIELD_LEN);
        assert_eq!(poseidon2_hash(&fields), record_hash(&c).unwrap());
    }

    #[test]
    fn element_encoding_round_trips_and_refuses_junk() {
        let vec = vector(4);
        assert_eq!(decode_elements(&encode_elements(&vec)).unwrap(), vec);
        assert!(decode_elements(&[Fr::from(2u64), Fr::from(1u64)]).is_err());
        assert!(decode_elements(&[Fr::from(1u64), Fr::from(1u64)]).is_err());
        assert!(decode_elements(&[Fr::zero()]).is_err());
        assert_eq!(decode_elements(&[]).unwrap(), vec![]);
    }
}
