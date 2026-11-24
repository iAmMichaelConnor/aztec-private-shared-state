//! The standing delivery handle (docs/ARCHITECTURE.md section 6, "The
//! standing delivery handle"): how a round requested by one party delivers a note and an outcome to
//! another party, privately, without that party being the requester.
//!
//! A recipient leaves a handle in its entry of the shared state: a partial
//! note commitment and an outcome key (`Handle`). Its own requests write it
//! (the handle travels as two shared values in C, which the recipient's
//! private request function computes from its own address); a later round
//! requested by anyone else may complete it (`deliver`): the partial note
//! completed with the round's fields for the recipient, and the note's packed
//! fields encrypted under the handle's key, under a log tag derived from that
//! key and the delivering round's chain request id. A handle may be
//! completed by any number of rounds until the recipient's next request
//! writes a new one: each completion is another note (its hash covers the
//! request id) under another tag, so deliveries to one handle share nothing
//! on chain, and the recipient looks a delivery up under the request id of
//! the round that may have made it (an app with exit tags learns that round
//! from the tag it spent: super::exit).
//!
//! Every round of an app that uses the brick outputs the same deliveries,
//! whatever the round type and whether a handle was present: a delivery
//! without a handle, and a round that delivers to no handle (`filler`), is
//! made from a seed only the nodes know (`filler_seed`, from the request's
//! `$blinding`), so it looks like any other and is no note anyone can own.
//! An app without the brick has none of this: no output, no gate.
//!
//! The handle authorises nothing: its partial commitment binds the
//! recipient (invariant 0), the delivered note is the recipient's alone, and
//! knowing the handle only opens the delivery.
//!
//! Every function here is permutation black boxes, additions and selects:
//! total, with no failure source, and runs in co-noir.
use super::outcome::{completed_note_hash, encrypt, shown, Valued};
use super::outputs::Finished;
use total::core::{is_zero, select_field};
use total::hash::p2_hash;

/// ASCII "pss.handle_tag" as a big-endian integer: the domain of a
/// delivery's log tag (pss-client's PSS_HANDLE_TAG holds the same value).
pub global PSS_HANDLE_TAG: Field = 0x7073732e68616e646c655f746167;

/// ASCII "pss.handle_filler" as a big-endian integer: the domain of the seed
/// a delivery without a handle is made from, and of a filler's note hash.
pub global PSS_HANDLE_FILLER: Field = 0x7073732e68616e646c655f66696c6c6572;

/// A standing delivery handle, as an entry of the shared state holds it.
pub struct Handle {
    /// `partial_commitment(recipient, randomness)` (super::outcome), computed
    /// by the recipient's private request function from its own address and
    /// its client's randomness, never taken as an argument; 0 for no handle
    pub partial: Field,
    /// the delivery's AEAD key, the recipient's client's
    pub key: Field,
}

impl Handle {
    /// No handle: an entry that holds none.
    pub fn none() -> Self {
        Handle { partial: 0, key: 0 }
    }

    /// The handle as two consecutive fields of an entry, `[partial, key]`.
    pub fn of(fields: [Field; 2]) -> Self {
        Handle { partial: fields[0], key: fields[1] }
    }

    /// `[partial, key]`: the order C commits them in and an entry holds them.
    pub fn fields(self) -> [Field; 2] {
        [self.partial, self.key]
    }

    /// Whether this is a handle (its partial commitment is not 0). Total:
    /// one is_zero.
    pub fn present(self) -> bool {
        !is_zero(self.partial)
    }
}

/// A delivery's log tag, `poseidon2([key, PSS_HANDLE_TAG, request_id])`,
/// `request_id` the delivering round's chain request id: the recipient finds
/// the log under it (the kernel silos it with the contract address), and two
/// deliveries to one handle are logged under two tags. Total: one
/// permutation.
pub fn handle_tag(key: Field, request_id: Field) -> Field {
    p2_hash([key, PSS_HANDLE_TAG, request_id])
}

/// The seed of a round's deliveries without a handle, `poseidon2([blinding,
/// PSS_HANDLE_FILLER])` from the request's `$blinding`, a secret of the
/// requester's and the nodes'. Total.
pub fn filler_seed(blinding: Field) -> Field {
    p2_hash([blinding, PSS_HANDLE_FILLER])
}

/// One delivery among a round's public outputs: the log tag, the completed
/// note's hash and the ciphertext of the note's packed fields with the AEAD
/// tag.
pub struct Delivery<let L: u32> {
    pub tag: Field,
    pub note_hash: Field,
    pub ciphertext: [Field; L],
}

/// Complete `handle` when `delivers`: the partial note completed at the
/// app's `storage_slot` with `fields` and the chain `request_id`
/// (super::outcome `completed_note_hash`: the note packs `[fields...,
/// request_id]`), those packed fields encrypted under the handle's key
/// with the nonce of that note hash (super::outcome `encrypt`; the
/// recipient made no request, so the ciphertext carries the request id),
/// under the tag `handle_tag(key, request_id)`. The note hash is over the slot, the
/// partial commitment and the whole plaintext, so one nonce only ever
/// seals one plaintext. `delivers` is the app's rule and must imply a
/// handle (`Handle::present`).
///
/// When not `delivers`: the same computation under `seed` in place of the
/// partial commitment and the key, over zero fields, so the delivery looks
/// like any other; its note hash completes `seed`, a hash under
/// PSS_HANDLE_FILLER that no partial commitment equals, so it is no note
/// anyone holds. Total: permutations and selects.
pub fn deliver<let N: u32>(
    handle: Handle,
    delivers: bool,
    fields: [Field; N],
    storage_slot: Field,
    request_id: Field,
    seed: Field,
) -> Delivery<N + 2> {
    let partial = select_field(delivers, handle.partial, seed);
    let key = select_field(delivers, handle.key, seed);
    let plaintext = shown(delivers, 0, fields);
    let note_hash = completed_note_hash(storage_slot, partial, plaintext, request_id);
    Delivery { tag: handle_tag(key, request_id), note_hash, ciphertext: encrypt(plaintext.concat([request_id]), key, note_hash) }
}

/// A delivery of a round that completes no handle, made from `seed` alone:
/// the tag `handle_tag(seed, request_id)`, the note hash `poseidon2([seed,
/// PSS_HANDLE_FILLER])` (no note hash of any note: not under the note-hash
/// separator), and the encryption of N + 1 zeros under `seed` with that
/// note hash's nonce. The plaintext is the constant zero, so one seed's
/// nonce only ever seals that one plaintext. The same shape as
/// `deliver::<N>`'s, and as unpredictable to anyone without the seed.
/// Total.
pub fn filler<let N: u32>(seed: Field, request_id: Field) -> Delivery<N + 2> {
    let note_hash = p2_hash([seed, PSS_HANDLE_FILLER]);
    Delivery { tag: handle_tag(seed, request_id), note_hash, ciphertext: encrypt([0; N + 1], seed, note_hash) }
}

/// The public outputs of a round under private outcomes with K app values
/// and D deliveries: `Valued`'s fields in its order, then each delivery's
/// `[tag, note_hash, ciphertext[M]]`. Flat, so its return paths are
/// `Valued`'s and then `deliveries[d].tag`, `deliveries[d].note_hash` and
/// `deliveries[d].ciphertext[i]`, the layout pss_public_contract's
/// `handle::Delivered` verifies.
pub struct Delivered<let R: u32, let W: u32, let T: u32, let H: u32, let L: u32, let K: u32, let D: u32, let M: u32> {
    pub request_id: Field,
    pub machine_request_id: Field,
    pub old_commitments: [Field; R],
    pub new_commitments: [Field; W],
    pub npk_app_hash: Field,
    pub new_hashes: [Field; T],
    pub outcome_tag: Field,
    pub note_hashes: [Field; H],
    pub ciphertext: [Field; L],
    pub app_values: [Field; K],
    pub deliveries: [Delivery<M>; D],
}

impl<S, let R: u32, let W: u32, let T: u32, let H: u32, let L: u32, let K: u32> Finished<S, Valued<R, W, T, H, L, K>> {
    /// The round with its deliveries after its outputs (`Delivered`). No
    /// constraint.
    pub fn delivered<let D: u32, let M: u32>(
        self,
        deliveries: [Delivery<M>; D],
    ) -> Finished<S, Delivered<R, W, T, H, L, K, D, M>> {
        let o = self.outputs;
        Finished {
            written: self.written,
            outputs: Delivered {
                request_id: o.request_id,
                machine_request_id: o.machine_request_id,
                old_commitments: o.old_commitments,
                new_commitments: o.new_commitments,
                npk_app_hash: o.npk_app_hash,
                new_hashes: o.new_hashes,
                outcome_tag: o.outcome_tag,
                note_hashes: o.note_hashes,
                ciphertext: o.ciphertext,
                app_values: o.app_values,
                deliveries,
            },
        }
    }
}

mod tests {
    use super::{deliver, filler, filler_seed, Handle, handle_tag, PSS_HANDLE_FILLER, PSS_HANDLE_TAG};
    use crate::tip::outcome::{completed_note_hash, encrypt, outcome_nonce, partial_commitment};
    use crate::test_support::ascii;
    use pss_utils::ae::AE;
    use protocol_types::hash::poseidon2_hash;

    global SLOT: Field = 0x2a;
    global REQUEST: Field = 0x1d;
    global KEY: Field = 0x6b;
    global SEED: Field = 0x5eed;

    #[test]
    fn the_domains_are_the_labels() {
        assert_eq(ascii("pss.handle_tag"), PSS_HANDLE_TAG);
        assert_eq(ascii("pss.handle_filler"), PSS_HANDLE_FILLER);
        assert_eq(handle_tag(KEY, REQUEST), poseidon2_hash([KEY, PSS_HANDLE_TAG, REQUEST]));
        assert(handle_tag(KEY, REQUEST) != handle_tag(KEY, REQUEST + 1));
        assert_eq(filler_seed(0xb1), poseidon2_hash([0xb1, PSS_HANDLE_FILLER]));
    }

    #[test]
    fn a_zero_partial_is_no_handle() {
        assert(!Handle::none().present());
        assert(Handle::of([1, 0]).present());
        assert_eq(Handle::of([3, 4]).fields(), [3, 4]);
    }

    // A delivery completes the handle's partial note with the fields and the
    // request id, and its ciphertext opens under the handle's key, with its
    // note hash's nonce, to the note's packed fields: the recipient rebuilds
    // the note from it alone.
    #[test]
    fn a_delivery_completes_the_handle_and_opens_under_its_key() {
        let p = partial_commitment(0xa11ce, 0x5eed);
        let d = deliver(Handle { partial: p, key: KEY }, true, [0, 7, 9], SLOT, REQUEST, SEED);
        assert_eq(d.tag, handle_tag(KEY, REQUEST));
        assert_eq(d.note_hash, completed_note_hash(SLOT, p, [0, 7, 9], REQUEST));
        let opened = AE::decrypt([d.ciphertext[0], d.ciphertext[1], d.ciphertext[2], d.ciphertext[3]], d.ciphertext[4], KEY, outcome_nonce(d.note_hash));
        assert_eq(opened, [0, 7, 9, REQUEST]);
    }

    // Two deliveries of different fields to one handle's key: two note
    // hashes, so two nonces, and the ciphertexts' difference is not the
    // plaintexts'.
    #[test]
    fn two_deliveries_of_different_fields_use_different_nonces() {
        let h = Handle { partial: partial_commitment(0xa11ce, 0x5eed), key: KEY };
        let a = deliver(h, true, [0, 7, 9], SLOT, REQUEST, SEED);
        let b = deliver(h, true, [0, 7, 10], SLOT, REQUEST, SEED);
        assert(a.note_hash != b.note_hash);
        assert(b.ciphertext[2] - a.ciphertext[2] != 1);
    }

    // One handle completed by two rounds: two notes under two tags, each
    // opening under the handle's key.
    #[test]
    fn a_handle_completed_twice_gives_two_deliveries() {
        let h = Handle { partial: partial_commitment(0xa11ce, 0x5eed), key: KEY };
        let a = deliver(h, true, [0, 7, 9], SLOT, REQUEST, SEED);
        let b = deliver(h, true, [0, 7, 9], SLOT, REQUEST + 1, SEED);
        assert(a.tag != b.tag);
        assert(a.note_hash != b.note_hash);
        assert_eq(b.note_hash, completed_note_hash(SLOT, h.partial, [0, 7, 9], REQUEST + 1));
    }

    // Without a handle the delivery is made from the seed over zero fields:
    // nothing of the fields, and no note of the handle's.
    #[test]
    fn no_delivery_is_the_seeds() {
        let p = partial_commitment(0xa11ce, 0x5eed);
        let d = deliver(Handle { partial: p, key: KEY }, false, [0, 7, 9], SLOT, REQUEST, SEED);
        assert_eq(d.tag, handle_tag(SEED, REQUEST));
        assert_eq(d.note_hash, completed_note_hash(SLOT, SEED, [0, 0, 0], REQUEST));
        assert_eq(d.ciphertext, encrypt([0, 0, 0, REQUEST], SEED, d.note_hash));
        assert(d.note_hash != completed_note_hash(SLOT, p, [0, 7, 9], REQUEST));
    }

    // A filler has a delivery's shape and nothing of a note.
    #[test]
    fn a_filler_has_the_delivery_shape() {
        let f = filler::<3>(SEED, REQUEST);
        assert_eq(f.tag, handle_tag(SEED, REQUEST));
        assert_eq(f.note_hash, poseidon2_hash([SEED, PSS_HANDLE_FILLER]));
        assert_eq(f.ciphertext, encrypt([0, 0, 0, 0], SEED, f.note_hash));
    }
}
