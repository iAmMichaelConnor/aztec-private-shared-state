//! Private outcomes (docs/ARCHITECTURE.md section 6, "Private outcomes"): the
//! result path of the secret-shared intakes, beside `crate::result`'s public
//! outputs. The round's outcome is inside a ciphertext and a completed note,
//! both computed in the MPC (`pss_core::tip::outcome`: the round completes
//! the partial note the request committed, `crate::partial_note`); the
//! result transaction lands them privately and its public call only marks
//! the request resolved and writes the new commitments.
//!
//! The private-outcome implementation of the outputs seam (`crate::result`'s
//! `Outputs` and `Lands`), behind the library's one `check_round` and
//! `apply_round`:
//!
//! - `Private` (what the app's `process_result` hands `check_round`: the
//!   `OutcomeResult`, a tree-valued key's new leaf hashes and the round's
//!   public app values): asserts the revertible phase, verifies the proof
//!   over `outcome_public_inputs` then the app values under the machine
//!   request id the contract computes, and after the three result
//!   signatures (the message of `crate::result`) pushes each
//!   outcome note hash and emits one private log `[outcome_tag, note_hash,
//!   ct…, padding…]` of the full 16 fields, the note hash the outcome's
//!   (the reader derives the AEAD nonce from it), its padding derived from
//!   the tag (`outcome_log`); `check_round` returns the
//!   `OutcomeApply` the wrapper enqueues;
//! - `OutcomeApply` (what the app's `apply` hands `apply_round`): the
//!   pinned reads, the head and slot checks, every new commitment written
//!   whatever the outcome (there is no public `ok`), then `done[index]`. No
//!   app hook stores an outcome;
//! - `deliver_outcome_note` (the app's outcome-note utility): the user hands
//!   its PXE the completed note it rebuilt from the log, through aztec-nr's
//!   `process_private_note_msg`; `deliver_outcome_into` is the same call
//!   that reads the note type and the slot from the app's outcome-note set.
//!
//! Value delivery is partial-note completion inside the co-SNARK (the
//! manifest's `outcome: partial`): the note hash the result pushes is the
//! completed note, the user's value note, and nothing runs after the log, so
//! the result transaction makes no call into another contract and shows the
//! relayer no amount and no owner. The state mode is the other seam
//! (`crate::result`'s `Sealing`, the `sealed` argument of both entry
//! points: `NodeHeld {}` or the chain-held thirds of `crate::chain_state`);
//! every state mode lands the same note hashes, the same log and the same
//! `apply`.
//!
//! An app's wrapper pair:
//!
//! ```noir
//! #[external("private")]
//! fn process_result(result: OutcomeResult<1, 1, 0, 1, 3>, signatures: [ResultSignature; 3]) {
//!     let apply = check_round(rounds(self.internal.configured_in_force(), self.storage.pool).swap,
//!         self.context, self.msg_sender(),
//!         Private::of(result, self.storage.outcome_notes.get_storage_slot(), OUTCOME_SLOT),
//!         NodeHeld {}, signatures);
//!     self.enqueue_self.apply(apply);
//! }
//!
//! #[external("public")]
//! #[only_self]
//! fn apply(apply: OutcomeApply<1, 1, 0>) {
//!     let _ = apply_round(self.context, self.storage.queue, no_pinned_reads(),
//!         StateKeys::one(self.storage.pool), apply, NodeHeld {});
//! }
//! ```
use crate::result::{AppliedResult, Lands, Outputs, public_input_prefix, Transition, verify_proof};
use aztec::context::{PrivateContext, PublicContext, UtilityContext};
use aztec::messages::discovery::{ComputeNoteHash, ComputeNoteNullifier};
use aztec::messages::discovery::private_notes::process_private_note_msg;
use aztec::messages::processing::validate_and_store_enqueued_notes_and_events;
use aztec::note::note_interface::NoteType;
use aztec::protocol::address::AztecAddress;
use aztec::protocol::constants::{MAX_NOTE_HASHES_PER_TX, PRIVATE_LOG_CIPHERTEXT_LEN};
use aztec::protocol::traits::{Deserialize, Packable, Serialize, ToField};
use aztec::state_vars::{Owned, PrivateSet, StateVariable};
use pss_core::tip::outcome::log_padding;

/// Refuse an outcome-note set whose storage slot (`storage_slot`, the app's
/// `outcome_notes.get_storage_slot()`) is not the slot the round circuits
/// hash each completed note at (`circuit_slot`, the storage slot the
/// circuits hand `pss_core::tip::outcome::finish`, the examples'
/// `OUTCOME_SLOT`). A note hashed at another slot than the set's lands, but
/// the owner's PXE never stores it (`deliver_outcome_note` rebuilds it at
/// the set's slot), so the user loses it; `Private::of` checks it for every
/// private outcome. Both arguments are constants in an app, so the check
/// costs nothing, and a mismatch fails every result landing, in the app's
/// first test.
pub fn assert_outcome_slot(storage_slot: Field, circuit_slot: Field) {
    assert(
        storage_slot == circuit_slot,
        "the outcome notes are not at the slot the round circuits hash them at",
    );
}

/// The fields of an outcome log after its tag: the v6 private log's 15
/// (`PRIVATE_LOG_CIPHERTEXT_LEN`), `[note_hash, ct…, padding…]`.
pub global OUTCOME_LOG_LEN: u32 = PRIVATE_LOG_CIPHERTEXT_LEN;

/// What `apply_round` lands under private outcomes: R keys read, W written, Q pinned values (one
/// per read, two per epoch read). Every field is an argument of the enqueued
/// public call, so it is public: the request id, the old and new commitments
/// (hiding: fresh blindings) and the pinned values, the same on every round
/// type of an app. Nothing about
/// the outcome is here.
///
/// The new commitments and the pinned values share one array (`new`
/// builds it, `new_commitments()` and `reads()` split it), so that a round
/// without pinned reads still has a type an entry point can take; it
/// serialises as the fields in declaration order.
#[derive(Deserialize, Eq, Serialize)]
pub struct OutcomeApply<let R: u32, let W: u32, let Q: u32> {
    /// the chain request id, as the queue holds it
    pub request_id: Field,
    /// the commitments the round read, in `in_slots` order
    pub old_commitments: [Field; R],
    /// the new commitments in `out_slots` order, then the pinned values in
    /// the manifest's `public_reads` order
    values: [Field; W + Q],
}

impl<let R: u32, let W: u32, let Q: u32> OutcomeApply<R, W, Q> {
    pub fn new(
        request_id: Field,
        old_commitments: [Field; R],
        new_commitments: [Field; W],
        reads: [Field; Q],
    ) -> Self {
        OutcomeApply { request_id, old_commitments, values: new_commitments.concat(reads) }
    }

    pub fn new_commitments(self) -> [Field; W] {
        let mut out = [0; W];
        for w in 0..W {
            out[w] = self.values[w];
        }
        out
    }

    pub fn reads(self) -> [Field; Q] {
        let mut out = [0; Q];
        for q in 0..Q {
            out[q] = self.values[W + q];
        }
        out
    }
}

/// One round's result under private outcomes, inside the `Private` that
/// `result::check_round` takes:
/// what `apply` lands, and the outcome, H note hashes and an L-field
/// ciphertext (the app's outcome plaintext and the AEAD tag). These are
/// private arguments of `process_result`: the chain sees the note hashes and
/// the outcome log, never `ok` or an app output.
#[derive(Deserialize, Eq, Serialize)]
pub struct OutcomeResult<let R: u32, let W: u32, let Q: u32, let H: u32, let L: u32> {
    pub apply: OutcomeApply<R, W, Q>,
    /// `$outcome_tag`, the outcome log's tag (the kernel silos it)
    pub outcome_tag: Field,
    pub note_hashes: [Field; H],
    pub ciphertext: [Field; L],
}

/// The public-input array of a round under private outcomes (both secret-shared
/// intakes):
///
/// ```text
/// [namespace, vk_hash, in_slots[0..R], out_slots[0..W], reads[0..Q],
///  request_id, machine_request_id, old_commitments[0..R],
///  new_commitments[0..W], npk_app_hash, new_hashes[0..T], outcome_tag,
///  note_hashes[0..H], ciphertext[0..L]]
/// ```
///
/// `new_hashes` are the new leaf hashes of a tree-valued key the round
/// writes (none for a flat key, T = 0), which the nodes rebuild their clear
/// tree from; they are hiding (every written leaf carries a fresh blinding)
/// and stay private arguments of `process_result`, never `apply`'s, since
/// their number is the round's touched leaves.
///
/// The public parameters are those of `crate::result::proved_public_inputs`;
/// the return value is `pss_core::tip::outcome::Private` in field order.
/// The contract computes `machine_request_id` itself (`Private::verify`), so a
/// proof of another attempt does not verify.
///
/// The layout is the proved layout's prefix and the request id first, then
/// the machine request id, the commitments and `npk_app_hash` as there, and
/// the outcome (tag, note hashes, ciphertext) in place of `ok`
/// and the app outputs. Every secret-shared-intake round circuit and this function
/// must agree, or no proof verifies.
pub fn outcome_public_inputs<let R: u32, let W: u32, let Q: u32, let T: u32, let H: u32, let L: u32>(
    namespace: Field,
    vk_hash: Field,
    in_slots: [Field; R],
    out_slots: [Field; W],
    reads: [Field; Q],
    request_id: Field,
    machine_request_id: Field,
    old_commitments: [Field; R],
    new_commitments: [Field; W],
    npk_app_hash: Field,
    new_hashes: [Field; T],
    outcome_tag: Field,
    note_hashes: [Field; H],
    ciphertext: [Field; L],
) -> [Field; 2 + R + W + Q + 2 + R + W + 1 + T + 1 + H + L] {
    public_input_prefix(namespace, vk_hash, in_slots, out_slots, reads, request_id)
        .concat([machine_request_id])
        .concat(old_commitments)
        .concat(new_commitments)
        .concat([npk_app_hash])
        .concat(new_hashes)
        .concat([outcome_tag])
        .concat(note_hashes)
        .concat(ciphertext)
}

/// The outcome log's fields after its tag: `[note_hash, ct…, padding…]`,
/// `note_hash` the hash of the completed note whose plaintext the
/// ciphertext seals, from which the reader derives the AEAD nonce
/// (pss_core `seal_nonce`; the chain shows only the siloed unique note
/// hash, so the log carries it). Always `OUTCOME_LOG_LEN` long, so its
/// length tells neither the app nor the round type. Position `i` from
/// `1 + L` on holds
/// `pss_core::tip::outcome::log_padding(outcome_tag, i)`, `poseidon2([outcome_tag,
/// i])`: the padding is fixed by the tag and the ciphertext length, so the
/// result transaction's submitter cannot choose any field of the log. The
/// client reads the ciphertext length from the app and ignores the padding.
pub fn outcome_log<let L: u32>(
    outcome_tag: Field,
    note_hash: Field,
    ciphertext: [Field; L],
) -> BoundedVec<Field, OUTCOME_LOG_LEN> {
    std::static_assert(
        1 + L <= OUTCOME_LOG_LEN,
        "the outcome ciphertext does not fit one private log",
    );
    let mut fields = [0; OUTCOME_LOG_LEN];
    fields[0] = note_hash;
    for i in 0..L {
        fields[1 + i] = ciphertext[i];
    }
    for i in 1 + L..OUTCOME_LOG_LEN {
        fields[i] = log_padding(outcome_tag, i);
    }
    BoundedVec::from_array(fields)
}

/// One round's result under private outcomes as `result::check_round`
/// takes it, the private-outcome implementation of the outputs seam
/// (`result::Outputs`): the `OutcomeResult`, the T new leaf hashes of a
/// tree-valued key the round writes (`[]` for flat keys) and the K public
/// values of its attempt the round outputs after the ciphertext (`[]` for
/// none; the manifest's `app_values`, `pss_core::tip::outcome::Valued`).
/// The app's `process_result` builds it from its private arguments
/// (`Private::of(result, outcome_notes_slot, circuit_slot)`, `.tree(new_hashes)`,
/// `.valued(values)`).
///
/// `new_hashes` are bound through the proof only (the nodes rebuild their
/// clear tree from them); nothing stores them. An app value is bound as the
/// proof's last public inputs and is public, so it must be one the app may
/// show, e.g. the inputs-opened bit of an app that escrows, by which `apply`
/// refunds a request's escrow when its shares did not open C, which no
/// completed note can settle (its owner is not the one the user committed).
///
/// `check_round` over it:
///
/// 1. asserts that the call runs in the revertible phase (`admit`);
/// 2. verifies the co-SNARK over `outcome_public_inputs` then the app
///    values, with the machine request id the contract computed, so a proof
///    of another attempt does not verify (`verify`);
/// 3. after the signatures, pushes each outcome note hash and emits the
///    outcome log `[note_hash, ct…, padding…]` under `outcome_tag`, the
///    note hash the first, the outcome's (`emit_private_log_unsafe`; the
///    kernel silos the tag with the contract address), padded with
///    `poseidon2([outcome_tag, i])` at each position `i` past the ciphertext
///    (`outcome_log`), and returns the `OutcomeApply` the wrapper enqueues
///    (`land`).
///
/// Nothing runs after the log: the result transaction makes no call into
/// another contract. There is no `ok` to check: a failed round re-blinds its
/// state like any other, and its outcome says it failed. The result carries
/// no padding: the log is a function of the verified public inputs (the
/// tag, the outcome's note hash and the ciphertext), so no field of it is
/// the submitter's choice.
///
/// The revertible-phase assertion (a settled rule, on in every app): the note hashes
/// and the log are then revertible, so they land only with an `apply` that
/// lands; a submitter who controls the entrypoint could otherwise run this
/// before `end_setup()`, making them non-revertible. v6 drops a transaction
/// whose setup-phase public call reverts, so that cannot mint a note without
/// its `apply` at present; the library does not rest on that. The fee-payment
/// contract's `pay_fee()` ends the setup phase, so the relayer's and the
/// user's transactions pass. Without it the guarantee rests on the v6 rule
/// alone.
pub struct Private<let R: u32, let W: u32, let Q: u32, let H: u32, let L: u32, let T: u32, let K: u32> {
    pub result: OutcomeResult<R, W, Q, H, L>,
    pub new_hashes: [Field; T],
    pub app_values: [Field; K],
}

impl<let R: u32, let W: u32, let Q: u32, let H: u32, let L: u32> Private<R, W, Q, H, L, 0, 0> {
    /// A round over flat keys with no app values, whose completed notes
    /// belong to the outcome-note set at storage slot `outcome_notes_slot`;
    /// the round circuits hash them at `circuit_slot`, which must be that
    /// slot (`assert_outcome_slot`).
    pub fn of(result: OutcomeResult<R, W, Q, H, L>, outcome_notes_slot: Field, circuit_slot: Field) -> Self {
        assert_outcome_slot(outcome_notes_slot, circuit_slot);
        Private { result, new_hashes: [], app_values: [] }
    }
}

impl<let R: u32, let W: u32, let Q: u32, let H: u32, let L: u32, let K: u32> Private<R, W, Q, H, L, 0, K> {
    /// The same round with the new leaf hashes of the tree-valued key it
    /// writes.
    pub fn tree<let T: u32>(self, new_hashes: [Field; T]) -> Private<R, W, Q, H, L, T, K> {
        Private { result: self.result, new_hashes, app_values: self.app_values }
    }
}

impl<let R: u32, let W: u32, let Q: u32, let H: u32, let L: u32, let T: u32> Private<R, W, Q, H, L, T, 0> {
    /// The same round with the public values of its attempt.
    pub fn valued<let K: u32>(self, app_values: [Field; K]) -> Private<R, W, Q, H, L, T, K> {
        Private { result: self.result, new_hashes: self.new_hashes, app_values }
    }
}

impl<let R: u32, let W: u32, let Q: u32, let H: u32, let L: u32, let T: u32, let K: u32> Private<R, W, Q, H, L, T, K> {
    /// The public inputs the proof is verified over: `outcome_public_inputs`
    /// at `namespace` (the app's address) with the machine request id the
    /// contract computed, then the app values.
    pub fn public_inputs(
        self,
        namespace: Field,
        vk_hash: Field,
        in_keys: [Field; R],
        out_keys: [Field; W],
        npk_app_hash: Field,
        machine_id: Field,
    ) -> [Field; 2 + R + W + Q + 2 + R + W + 1 + T + 1 + H + L + K] {
        let apply = self.result.apply;
        outcome_public_inputs(
            namespace,
            vk_hash,
            in_keys,
            out_keys,
            apply.reads(),
            apply.request_id,
            machine_id,
            apply.old_commitments,
            apply.new_commitments(),
            npk_app_hash,
            self.new_hashes,
            self.result.outcome_tag,
            self.result.note_hashes,
            self.result.ciphertext,
        )
            .concat(self.app_values)
    }
}

impl<let R: u32, let W: u32, let Q: u32, let H: u32, let L: u32, let T: u32, let K: u32> Transition<R, W, Q> for Private<R, W, Q, H, L, T, K> {
    fn request_id(self) -> Field {
        self.result.apply.request_id
    }
    fn old_commitments(self) -> [Field; R] {
        self.result.apply.old_commitments
    }
    fn new_commitments(self) -> [Field; W] {
        self.result.apply.new_commitments()
    }
    fn reads(self) -> [Field; Q] {
        self.result.apply.reads()
    }
}

impl<let R: u32, let W: u32, let Q: u32, let H: u32, let L: u32, let T: u32, let K: u32> Outputs<R, W, Q> for Private<R, W, Q, H, L, T, K> {
    type Landed = OutcomeApply<R, W, Q>;

    fn admit(self, context: &mut PrivateContext, _in_keys: [Field; R], _out_keys: [Field; W]) {
        assert(context.in_revertible_phase(), "a private outcome lands only in the revertible phase");
    }

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
        let public_inputs =
            self.public_inputs(context.this_address().to_field(), vk_hash, in_keys, out_keys, npk_app_hash, machine_id);
        verify_proof(context, scope, vk_hash, public_inputs);
    }

    fn land(self, context: &mut PrivateContext) -> OutcomeApply<R, W, Q> {
        std::static_assert(H > 0, "a private outcome completes a note: its hash is the first");
        for h in 0..H {
            context.push_note_hash(self.result.note_hashes[h]);
        }
        context.emit_private_log_unsafe(
            self.result.outcome_tag,
            outcome_log(self.result.outcome_tag, self.result.note_hashes[0], self.result.ciphertext),
        );
        self.result.apply
    }
}

impl<let R: u32, let W: u32, let Q: u32> Transition<R, W, Q> for OutcomeApply<R, W, Q> {
    fn request_id(self) -> Field {
        self.request_id
    }
    fn old_commitments(self) -> [Field; R] {
        self.old_commitments
    }
    fn new_commitments(self) -> [Field; W] {
        OutcomeApply::new_commitments(self)
    }
    fn reads(self) -> [Field; Q] {
        OutcomeApply::reads(self)
    }
}

/// The public half under private outcomes, what the app's `apply` hands
/// `result::apply_round`: every new commitment written whatever the
/// outcome, and no app output for the hook.
///
/// The unconditional write (a settled rule). Every new commitment is written
/// whatever the outcome: there is no public `ok`, and every round draws a
/// fresh blinding, so the write reveals nothing about the outcome. A round
/// that failed leaves its state under a new blinding. No app hook stores an
/// outcome here: the outcome is the user's, in the note and the log.
impl<let R: u32, let W: u32, let Q: u32> Lands<R, W, Q, 0> for OutcomeApply<R, W, Q> {
    fn writes(self) -> bool {
        true
    }

    fn app_outputs(self) -> [Field; 0] {
        []
    }

    fn deliver(self, _context: PublicContext, _applied: AppliedResult<0>) {}
}

/// The transaction that carried an outcome, as the user's client reads it
/// from the node's transaction effect: its hash, its unique note hashes and
/// its first nullifier, the context aztec-nr's note discovery needs.
#[derive(Deserialize, Eq, Serialize)]
pub struct OutcomeTx {
    pub tx_hash: Field,
    pub unique_note_hashes: BoundedVec<Field, MAX_NOTE_HASHES_PER_TX>,
    pub first_nullifier: Field,
}

/// The body of the app's outcome-note utility: hand the user's PXE the
/// note the client rebuilt from the outcome log, owned by `owner` (an
/// account in this PXE) with the app's note type `note_type_id` at
/// `storage_slot`, its `randomness` and its packed fields: the completed
/// note, whose randomness is the request's `rho` and whose packed fields are
/// the outcome plaintext then the chain request id (`[fields…,
/// request_id]`), at most eight; the note type's two-step
/// `compute_note_hash` recomputes `P` and the completed hash. It
/// builds the standard private-note message and calls aztec-nr's
/// `process_private_note_msg` with the contract's `_compute_note_hash` and
/// `_compute_note_nullifier`, which finds the note's nonce among the
/// transaction's unique note hashes, then stores it in the PXE under
/// `owner`'s scope. A note whose hash is not in the transaction is dropped
/// (aztec-nr logs a warning), so a wrong rebuild stores nothing.
pub unconstrained fn deliver_outcome_note<let P: u32>(
    contract_address: AztecAddress,
    compute_note_hash: ComputeNoteHash,
    compute_note_nullifier: ComputeNoteNullifier,
    note_type_id: Field,
    owner: AztecAddress,
    storage_slot: Field,
    randomness: Field,
    packed: [Field; P],
    tx: OutcomeTx,
) {
    let content = BoundedVec::from_array([owner.to_field(), storage_slot, randomness].concat(packed));
    process_private_note_msg(
        contract_address,
        tx.tx_hash,
        tx.unique_note_hashes,
        tx.first_nullifier,
        compute_note_hash,
        compute_note_nullifier,
        note_type_id as u64,
        content,
    );
    validate_and_store_enqueued_notes_and_events(owner);
}

/// The whole body of the app's outcome-note utility, over its outcome-note
/// set `notes` (the `#[storage]` field the rounds complete notes in):
/// `deliver_outcome_note` with the note type's id and the set's storage
/// slot read from `notes`, and `packed` of the note type's own packed
/// length, so a utility whose argument does not fit its note does not
/// compile. `compute_note_hash` and `compute_note_nullifier` are the
/// contract's `_compute_note_hash` and `_compute_note_nullifier`, which only
/// the `#[aztec]` module can name.
///
/// ```noir
/// #[external("utility")]
/// unconstrained fn deliver_outcome(owner: AztecAddress, rho: Field, packed: [Field; 3], tx: OutcomeTx) {
///     deliver_outcome_into(self.storage.outcome_notes, self.address, _compute_note_hash, _compute_note_nullifier, owner, rho, packed, tx);
/// }
/// ```
pub unconstrained fn deliver_outcome_into<Note, let P: u32>(
    notes: Owned<PrivateSet<Note, UtilityContext>, UtilityContext>,
    contract_address: AztecAddress,
    compute_note_hash: ComputeNoteHash,
    compute_note_nullifier: ComputeNoteNullifier,
    owner: AztecAddress,
    randomness: Field,
    packed: [Field; P],
    tx: OutcomeTx,
)
where
    Note: NoteType + Packable<N = P>,
{
    deliver_outcome_note(
        contract_address,
        compute_note_hash,
        compute_note_nullifier,
        Note::get_id(),
        owner,
        notes.get_storage_slot(),
        randomness,
        packed,
        tx,
    );
}

mod test {
    use super::{
        assert_outcome_slot, OUTCOME_LOG_LEN, outcome_log, outcome_public_inputs, OutcomeApply, OutcomeResult,
        Private,
    };
    use aztec::protocol::hash::poseidon2_hash;
    use aztec::protocol::traits::{Deserialize, Serialize};

    #[test]
    fn the_public_inputs_are_the_prefix_then_the_private_outputs() {
        assert_eq(
            outcome_public_inputs(
                0xa0,
                0x7e,
                [0x51],
                [0x51],
                [0xe0],
                0x1d,
                0x3a,
                [0x0c],
                [0x1c],
                0x9b,
                [],
                0x7a,
                [0x4a],
                [0xc0, 0xc1, 0xc2, 0xc3],
            ),
            [0xa0, 0x7e, 0x51, 0x51, 0xe0, 0x1d, 0x3a, 0x0c, 0x1c, 0x9b, 0x7a, 0x4a, 0xc0, 0xc1, 0xc2, 0xc3],
        );
    }

    // A tree-valued key's new leaf hashes sit between npk_app_hash and the
    // tag; a flat key's round (T = 0) has none.
    #[test]
    fn the_new_leaf_hashes_follow_npk_app_hash() {
        assert_eq(
            outcome_public_inputs(
                0xa0, 0x7e, [0x51], [0x51], [0xe0, 0xe1], 0x1d, 0x3a, [0x0c], [0x1c], 0x9b,
                [0x11, 0x12], 0x7a, [0x4a], [0xc0, 0xc1],
            ),
            [
                0xa0, 0x7e, 0x51, 0x51, 0xe0, 0xe1, 0x1d, 0x3a, 0x0c, 0x1c, 0x9b, 0x11, 0x12, 0x7a,
                0x4a, 0xc0, 0xc1,
            ],
        );
    }

    // The padding at position i is poseidon2([tag, i]), from the first
    // position past the ciphertext to the end of the log.
    #[test]
    fn the_log_is_the_note_hash_the_ciphertext_and_the_padding() {
        let log = outcome_log(0x7a, 0x3a, [0xc0, 0xc1, 0xc2, 0xc3]);
        assert_eq(log.len(), OUTCOME_LOG_LEN);
        assert_eq(OUTCOME_LOG_LEN, 15);
        let fields = log.storage();
        assert_eq([fields[0], fields[1], fields[2], fields[3], fields[4]], [0x3a, 0xc0, 0xc1, 0xc2, 0xc3]);
        for i in 5..OUTCOME_LOG_LEN {
            assert_eq(fields[i], poseidon2_hash([0x7a, i as Field]));
        }
        // a longer ciphertext moves where the padding starts, not its values
        let longer = outcome_log(0x7a, 0x3a, [0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7]);
        for i in 9..OUTCOME_LOG_LEN {
            assert_eq(longer.storage()[i], fields[i]);
        }
        // another tag, another padding
        assert(outcome_log(0x7b, 0x3a, [0xc0, 0xc1, 0xc2, 0xc3]).storage()[5] != fields[5]);
    }

    // The outcome notes at the slot the circuits hash them at pass; at
    // another slot every private outcome is refused, before anything lands.
    #[test]
    fn outcome_notes_at_the_circuits_slot_pass() {
        assert_outcome_slot(1, 1);
        let r: OutcomeResult<1, 1, 0, 1, 4> = std::mem::zeroed();
        let _ = Private::of(r, 1, 1);
    }

    #[test(should_fail_with = "the outcome notes are not at the slot the round circuits hash them at")]
    fn outcome_notes_at_another_slot_are_refused() {
        let r: OutcomeResult<1, 1, 0, 1, 4> = std::mem::zeroed();
        let _ = Private::of(r, 2, 1);
    }

    // The enqueued apply's public arguments are the request id, the
    // commitments and the reads only: no field holds ok, a code or an app
    // output.
    #[test]
    fn an_apply_splits_its_values_and_serialises_in_order() {
        let a: OutcomeApply<1, 2, 1> = OutcomeApply::new(0x1d, [0x0c], [0x1c, 0x2c], [0x7d0]);
        assert_eq(a.new_commitments(), [0x1c, 0x2c]);
        assert_eq(a.reads(), [0x7d0]);
        assert_eq(a.serialize(), [0x1d, 0x0c, 0x1c, 0x2c, 0x7d0]);
        let r: OutcomeResult<1, 1, 0, 1, 4> = OutcomeResult {
            apply: OutcomeApply::new(0x1d, [0x0c], [0x1c], []),
            outcome_tag: 0x7a,
            note_hashes: [0x4a],
            ciphertext: [0xc0, 0xc1, 0xc2, 0xc3],
        };
        assert_eq(r.serialize(), [0x1d, 0x0c, 0x1c, 0x7a, 0x4a, 0xc0, 0xc1, 0xc2, 0xc3]);
        assert(OutcomeResult::deserialize(r.serialize()) == r);
    }
}
