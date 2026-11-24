//! The standing delivery handle, the contract side (pss_core `tip::handle`;
//! docs/ARCHITECTURE.md section 6, "The standing delivery handle"): a round requested by one
//! party delivers a note and an outcome to another party, the holder of a
//! handle in the shared state, privately.
//!
//! - `commit`: the handle's partial commitment, which the recipient's own
//!   request function computes from its address and its client's handle
//!   randomness and puts in C (never an argument, so the delivered note is
//!   always the sender's: invariant 0). No nullifier: each round that
//!   completes a handle makes another note (its hash covers the round's
//!   request id), which reaches the owner's PXE through the app's
//!   outcome-note utility, never by a completion log.
//! - `Delivered`: a private outcome (`crate::outcome::Private`) with the
//!   round's deliveries after its app values, the outputs seam's
//!   implementation for an app whose rounds deliver: it verifies the proof
//!   over the outcome's public inputs then each delivery's `[tag, note_hash,
//!   ciphertext...]`, and after the outcome's note hash and log it pushes
//!   each delivery's note hash and emits each delivery's log `[tag,
//!   note_hash, ciphertext..., padding...]` (the outcome log's format,
//!   `crate::outcome::outcome_log`, with the delivery's own note hash, from
//!   which the recipient derives the nonce). Every round of such an app
//!   outputs the same deliveries (a round with no handle to complete outputs
//!   fillers), so every result transaction shows the same note hashes and
//!   logs.
//!
//! An app's wrapper over it:
//!
//! ```noir
//! #[external("private")]
//! fn process_result(result: OutcomeResult<1, 1, 3, 1, 8>, new_hashes: [Field; 2],
//!     values: [Field; 2], deliveries: [Delivery<9>; 1], signatures: [ResultSignature; 3]) {
//!     let apply = check_round(row, self.context, self.msg_sender(),
//!         Delivered::of(Private::of(result, outcome_notes_slot, OUTCOME_SLOT).tree(new_hashes).valued(values), deliveries),
//!         NodeHeld {}, signatures);
//!     self.enqueue_self.apply(apply);
//! }
//! ```
use crate::outcome::{outcome_log, OutcomeApply, Private};
use crate::partial_note;
use crate::result::{Outputs, Transition, verify_proof};
use aztec::context::PrivateContext;
use aztec::protocol::address::AztecAddress;
use aztec::protocol::traits::{Deserialize, Serialize, ToField};
pub use pss_core::tip::handle::{handle_tag, PSS_HANDLE_FILLER, PSS_HANDLE_TAG};

/// A handle's partial commitment, `partial_commitment(owner, randomness)`
/// (aztec-nr's partial-note commitment, `crate::partial_note`): the request
/// function passes its `msg_sender()` as `owner` and the client's handle
/// randomness, and puts the result in C as the request's `handle_partial`.
pub fn commit(owner: AztecAddress, randomness: Field) -> Field {
    partial_note::partial_commitment(owner, randomness)
}

/// One delivery of a round, as the result function takes it: the log tag,
/// the completed note's hash and the ciphertext of the note's packed fields
/// with the AEAD tag (pss_core `handle::Delivery`).
#[derive(Deserialize, Eq, Serialize)]
pub struct Delivery<let M: u32> {
    pub tag: Field,
    pub note_hash: Field,
    pub ciphertext: [Field; M],
}

impl<let M: u32> Delivery<M> {
    /// The delivery as the proof's public inputs, `[tag, note_hash,
    /// ciphertext...]`.
    pub fn fields(self) -> [Field; 2 + M] {
        [self.tag, self.note_hash].concat(self.ciphertext)
    }
}

/// A private outcome with D deliveries of M ciphertext fields after its app
/// values: the result an app whose rounds deliver to handles hands
/// `check_round` (module doc).
pub struct Delivered<let R: u32, let W: u32, let Q: u32, let H: u32, let L: u32, let T: u32, let K: u32, let D: u32, let M: u32> {
    pub outcome: Private<R, W, Q, H, L, T, K>,
    pub deliveries: [Delivery<M>; D],
}

impl<let R: u32, let W: u32, let Q: u32, let H: u32, let L: u32, let T: u32, let K: u32, let D: u32, let M: u32> Delivered<R, W, Q, H, L, T, K, D, M> {
    pub fn of(outcome: Private<R, W, Q, H, L, T, K>, deliveries: [Delivery<M>; D]) -> Self {
        Delivered { outcome, deliveries }
    }
}

impl<let R: u32, let W: u32, let Q: u32, let H: u32, let L: u32, let T: u32, let K: u32, let D: u32, let M: u32> Transition<R, W, Q> for Delivered<R, W, Q, H, L, T, K, D, M> {
    fn request_id(self) -> Field {
        self.outcome.request_id()
    }
    fn old_commitments(self) -> [Field; R] {
        self.outcome.old_commitments()
    }
    fn new_commitments(self) -> [Field; W] {
        self.outcome.new_commitments()
    }
    fn reads(self) -> [Field; Q] {
        self.outcome.reads()
    }
}

impl<let R: u32, let W: u32, let Q: u32, let H: u32, let L: u32, let T: u32, let K: u32, let D: u32, let M: u32> Outputs<R, W, Q> for Delivered<R, W, Q, H, L, T, K, D, M> {
    type Landed = OutcomeApply<R, W, Q>;

    fn admit(self, context: &mut PrivateContext, in_keys: [Field; R], out_keys: [Field; W]) {
        self.outcome.admit(context, in_keys, out_keys);
    }

    /// The outcome's public inputs, then each delivery's.
    fn verify(
        self,
        context: &mut PrivateContext,
        scope: AztecAddress,
        vk_hash: Field,
        in_keys: [Field; R],
        out_keys: [Field; W],
        npk_app_hash: Field,
        machine_id: Field,
    ) {
        let mut sent = [0; D * (2 + M)];
        for d in 0..D {
            let fields = self.deliveries[d].fields();
            for i in 0..2 + M {
                sent[d * (2 + M) + i] = fields[i];
            }
        }
        let public_inputs = self
            .outcome
            .public_inputs(context.this_address().to_field(), vk_hash, in_keys, out_keys, npk_app_hash, machine_id)
            .concat(sent);
        verify_proof(context, scope, vk_hash, public_inputs);
    }

    /// The outcome's note hashes and log, then each delivery's note hash and
    /// its log `[note_hash, ciphertext..., padding...]` under its tag (the
    /// kernel silos it), padded as the outcome log is.
    fn land(self, context: &mut PrivateContext) -> OutcomeApply<R, W, Q> {
        let apply = self.outcome.land(context);
        for d in 0..D {
            let delivery = self.deliveries[d];
            context.push_note_hash(delivery.note_hash);
            context.emit_private_log_unsafe(
                delivery.tag,
                outcome_log(delivery.tag, delivery.note_hash, delivery.ciphertext),
            );
        }
        apply
    }
}

mod test {
    use super::{commit, Delivery};
    use crate::partial_note::partial_commitment;
    use aztec::protocol::address::AztecAddress;
    use aztec::protocol::traits::{Deserialize, FromField, Serialize};

    #[test]
    fn a_handle_commits_its_owner_as_a_partial_note_does() {
        let owner = AztecAddress::from_field(0xa11ce);
        assert_eq(commit(owner, 0x5eed), partial_commitment(owner, 0x5eed));
        assert(commit(AztecAddress::from_field(0xb0b), 0x5eed) != commit(owner, 0x5eed));
    }

    #[test]
    fn a_delivery_is_its_tag_its_note_hash_and_its_ciphertext() {
        let d: Delivery<3> = Delivery { tag: 0x7a, note_hash: 0x4a, ciphertext: [0xc0, 0xc1, 0xc2] };
        assert_eq(d.fields(), [0x7a, 0x4a, 0xc0, 0xc1, 0xc2]);
        assert_eq(d.serialize(), d.fields());
        assert(Delivery::deserialize(d.serialize()) == d);
    }
}
