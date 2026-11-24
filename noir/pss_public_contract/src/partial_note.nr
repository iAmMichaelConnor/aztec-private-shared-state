//! Partial-note delivery (docs/ARCHITECTURE.md section 6, "Partial-note
//! delivery", "Private outcomes"): how a round's value
//! and outcome reach the user as a standard note of the app contract.
//!
//! The user's request function commits a partial note `P =
//! partial_commitment(owner, rho)` (`commit`), from the address the
//! completed note will belong to and the randomness its client derives, and
//! puts `P` in the request as the reserved value `$partial_note`. The note is
//! completed once, by the result that lands that request:
//!
//! - inside the co-SNARK, for a private result (`pss_core::tip::outcome::
//!   finish`): the round outputs the completed note's hash, the result
//!   transaction pushes it (`crate::outcome::Private`),
//!   and the user hands its PXE the note through the app's outcome-note
//!   utility (`crate::outcome::deliver_outcome_note`, randomness `rho`);
//! - in a public function, for a public result (`complete_in_public`, which
//!   `crate::result::PartialResult::completing` runs on every round): the
//!   completion log under `completion_log_tag(P)` and the completed note's
//!   hash. The owner's PXE, told of the partial note by the request's
//!   partial-note message (`deliver_partial_note`), finds the log and stores
//!   the note.
//!
//! Either way the note's hash is `poseidon2_hash_with_separator(
//! [storage_slot, P, fields…, request_id], DOM_SEP__NOTE_HASH)`, aztec-nr v6's
//! two-step hash (`uint_note.nr`): the app's outcome note is a struct of
//! its outcome fields, `request_id` last, under `#[outcome_note]`, which
//! makes it a note whose `compute_note_hash(owner, storage_slot,
//! randomness)` performs both steps over its packed fields `[fields…,
//! request_id]` (at most `pss_core::tip::outcome::MAX_NOTE_PACKED_LEN`,
//! eight) and whose nullifier is the canonical one.
//!
//! A refund (an escrow returned when no round serves the request) is a
//! partial note with private content (`partial_commitment_with`: the
//! commitment binds the amounts beside the owner and the randomness, so the
//! completion publishes none of them) that the request commits
//! (`commit_with`) and tells the owner's PXE of with its content
//! (`deliver_partial_note_with`), and that the app's `skip()` or `apply`
//! completes in public (`complete_in_public` with no public field but the
//! request id), never a round, so no refund waits on the nodes
//! (pss_public_contract `token`, "Refunds").
//!
//! Single use. Each partial note is used by one request: `commit` pushes
//! the use nullifier `poseidon2_hash_with_separator([P], PSS_PARTIAL_USED)`,
//! so a second request naming the same `P` reverts at its request. With
//! `P` computed inside the request function from its preimage, nobody but
//! the holder of `rho` can name it at all, and with the use nullifier no `P`
//! is ever completed twice: the owner's PXE completes a partial note on the
//! first log under its tag, and that log is the one request's.
//!
//! The spend. An unchained note is nullified by its spend like any note. A
//! chained note (one the app's private function opens as the proof of a
//! position's ownership, `assert_owned`) is never nullified, so its value is
//! spent once through the redeem nullifier `poseidon2_hash_with_separator(
//! [note_hash_for_nullification, nhk_app], PSS_REDEEM)` (`redeem`), which a
//! second redeem of the same note repeats and the kernel refuses, while the
//! note stays readable.
use aztec::context::{PrivateContext, PublicContext};
use aztec::keys::getters::{get_nhk_app, get_public_keys, try_get_public_keys};
use aztec::macros::notes::custom_note;
use aztec::messages::delivery::{do_private_message_delivery, MessageDeliveryBuilder};
use aztec::messages::logs::partial_note::encode_partial_note_private_message;
use aztec::note::ConfirmedNote;
use aztec::note::note_interface::NoteType;
use aztec::note::partial_note::DOM_SEP__PARTIAL_NOTE_COMMITMENT;
use aztec::note::utils::{compute_confirmed_note_hash_for_nullification, compute_note_hash, compute_note_nullifier};
use aztec::protocol::address::AztecAddress;
use aztec::protocol::hash::poseidon2_hash_with_separator;
use aztec::protocol::traits::{Packable, ToField};
use pss_core::tip::outcome::MAX_NOTE_PACKED_LEN;

/// ASCII "pss.partial_used" read big-endian: the separator of a partial
/// note's use nullifier (`use_nullifier`).
pub global PSS_PARTIAL_USED: Field = 0x7073732e7061727469616c5f75736564;

/// ASCII "pss.redeem" read big-endian: the separator of a chained note's
/// redeem nullifier (`redeem_nullifier`).
pub global PSS_REDEEM: Field = 0x7073732e72656465656d;

/// The partial note's commitment, `poseidon2_hash_with_separator([owner,
/// rho], DOM_SEP__PARTIAL_NOTE_COMMITMENT)`: pss_core's, the function the
/// round circuits and pss-client compute.
pub fn partial_commitment(owner: AztecAddress, rho: Field) -> Field {
    pss_core::tip::outcome::partial_commitment(owner.to_field(), rho)
}

/// The commitment of a partial note with private content `content`,
/// `poseidon2_hash_with_separator([owner, rho, content…],
/// DOM_SEP__PARTIAL_NOTE_COMMITMENT)`: the content is fixed at the request,
/// hidden by `rho`, and travels to the owner's PXE in the partial-note
/// message (`deliver_partial_note_with`), never in the completion. With no
/// content it is `partial_commitment(owner, rho)`. An app note type whose
/// packed fields start with the content computes its hash as
/// `compute_note_hash(storage_slot, [partial_commitment_with(owner,
/// randomness, content), public fields…])`, so a note completed in public
/// and one created whole in private hash alike.
pub fn partial_commitment_with<let M: u32>(owner: AztecAddress, rho: Field, content: [Field; M]) -> Field {
    poseidon2_hash_with_separator(
        [owner.to_field(), rho].concat(content),
        DOM_SEP__PARTIAL_NOTE_COMMITMENT,
    )
}

/// The hash of the note completing `partial` at `storage_slot` with
/// `fields` and `request_id` (pss_core's `completed_note_hash`).
pub fn completed_note_hash<let N: u32>(
    storage_slot: Field,
    partial: Field,
    fields: [Field; N],
    request_id: Field,
) -> Field {
    pss_core::tip::outcome::completed_note_hash(storage_slot, partial, fields, request_id)
}

/// The hash of a note of an app's partial-note type, created whole or
/// completed from a partial note, owned by `owner` at `storage_slot` with
/// `randomness` and the packed fields `packed` (`[fields…, request_id]`):
/// both steps of aztec-nr v6's two-step hash, `compute_note_hash(
/// storage_slot, [partial_commitment(owner, randomness), packed…])`
/// (`uint_note.nr`). An `#[outcome_note]` returns it from
/// `NoteHash::compute_note_hash`, so the completed note the round or `apply`
/// lands is an ordinary note in the owner's PXE; its nullifier is the
/// canonical one. At most `pss_core::tip::outcome::MAX_NOTE_PACKED_LEN`
/// fields.
pub fn note_hash<let N: u32>(
    owner: AztecAddress,
    storage_slot: Field,
    randomness: Field,
    packed: [Field; N],
) -> Field {
    std::static_assert(
        N <= MAX_NOTE_PACKED_LEN,
        "a partial-note type packs at most eight fields, request_id last",
    );
    compute_note_hash(storage_slot, [partial_commitment(owner, randomness)].concat(packed))
}

/// The canonical nullifier of `owner`'s note, `compute_note_nullifier(
/// note_hash_for_nullification, [nhk_app])` under the owner's app
/// nullifier hiding key, as aztec-nr's `#[note]` derives it: what an
/// `#[outcome_note]` and an app's other partial-note types return from
/// `NoteHash::compute_nullifier`.
pub fn nullifier(context: &mut PrivateContext, owner: AztecAddress, note_hash_for_nullification: Field) -> Field {
    let secret = context.request_nhk_app(get_public_keys(owner).npk_m_hash);
    compute_note_nullifier(note_hash_for_nullification, [secret])
}

/// `nullifier` in a utility, for `NoteHash::compute_nullifier_unconstrained`:
/// none when the PXE holds no keys of `owner`.
pub unconstrained fn nullifier_unconstrained(owner: AztecAddress, note_hash_for_nullification: Field) -> Option<Field> {
    try_get_public_keys(owner).map(|keys: aztec::protocol::public_keys::PublicKeys| {
        compute_note_nullifier(note_hash_for_nullification, [get_nhk_app(keys.npk_m_hash)])
    })
}

/// The outcome note: the completed note of a round, an app struct of its
/// outcome fields with the chain request id last,
///
/// ```noir
/// #[derive(Deserialize, Eq, Packable, Serialize)]
/// #[outcome_note]
/// pub struct SwapOutcomeNote { pub code: Field, pub amount_out: Field, pub request_id: Field }
/// ```
///
/// made a note of the app contract (aztec-nr's `#[custom_note]`: its note
/// type id and property selectors) whose hash is `note_hash` over its packed
/// fields, so the note a round completes inside the co-SNARK, the one
/// `apply` completes in public and one created whole hash alike, and whose
/// nullifier is the canonical one (`nullifier`). The fields are the app's
/// (the struct names them); the note's behaviour is this one. An attribute
/// rather than a library struct because aztec-nr v6's note macros take a
/// struct without generics, so one library type cannot carry each app's
/// outcome width. Fails at compile time unless the last field is
/// `request_id` (and, through `note_hash`, unless the note packs at most
/// eight fields).
pub comptime fn outcome_note(s: TypeDefinition) -> Quoted {
    let name = s.name();
    let fields = s.fields_as_written();
    assert(
        (fields.len() > 1) & (fields[fields.len() - 1].name() == quote { request_id }),
        f"{name}: an outcome note's fields are the outcome, then request_id",
    );
    let registered = custom_note(s);
    quote {
        $registered

        impl aztec::note::note_interface::NoteHash for $name {
            fn compute_note_hash(
                self,
                owner: aztec::protocol::address::AztecAddress,
                storage_slot: Field,
                randomness: Field,
            ) -> Field {
                $crate::partial_note::note_hash(owner, storage_slot, randomness, aztec::protocol::traits::Packable::pack(self))
            }

            fn compute_nullifier(
                self,
                context: &mut aztec::context::PrivateContext,
                owner: aztec::protocol::address::AztecAddress,
                note_hash_for_nullification: Field,
            ) -> Field {
                $crate::partial_note::nullifier(context, owner, note_hash_for_nullification)
            }

            unconstrained fn compute_nullifier_unconstrained(
                self,
                owner: aztec::protocol::address::AztecAddress,
                note_hash_for_nullification: Field,
            ) -> Option<Field> {
                $crate::partial_note::nullifier_unconstrained(owner, note_hash_for_nullification)
            }
        }
    }
}

/// The tag of `partial`'s completion log, aztec-nr's
/// `compute_log_tag(partial, DOM_SEP__NOTE_COMPLETION_LOG_TAG)`.
pub fn completion_log_tag(partial: Field) -> Field {
    pss_core::tip::outcome::completion_log_tag(partial)
}

/// The use nullifier of a partial note, `poseidon2_hash_with_separator([P],
/// PSS_PARTIAL_USED)` (the kernel silos it with the app's address). It
/// hides `P` as `P` hides its owner.
pub fn use_nullifier(partial: Field) -> Field {
    poseidon2_hash_with_separator([partial], PSS_PARTIAL_USED)
}

/// The request side, in the user's private request function: commit the
/// partial note of `owner` (an address in the user's PXE; an owner-bound
/// round asserts it is `msg_sender`) under the client's `rho`, push its use
/// nullifier, and return `P` for the request's `$partial_note`. `owner` and
/// `rho` enter nothing but `P`, and `P` is never an argument: a request can
/// name only a partial note its sender can open. The refund note of a round
/// with an escrow is committed the same way, under its own `rho`.
pub fn commit(context: &mut PrivateContext, owner: AztecAddress, rho: Field) -> Field {
    let partial = partial_commitment(owner, rho);
    context.push_nullifier_unsafe(use_nullifier(partial));
    partial
}

/// `commit` for a partial note with private content `content`
/// (`partial_commitment_with`): a refund note, whose amounts the
/// commitment binds. Its use nullifier is pushed the same way.
pub fn commit_with<let M: u32>(
    context: &mut PrivateContext,
    owner: AztecAddress,
    rho: Field,
    content: [Field; M],
) -> Field {
    let partial = partial_commitment_with(owner, rho, content);
    context.push_nullifier_unsafe(use_nullifier(partial));
    partial
}

/// The private content of a partial note whose fields a public function
/// completes: nothing. Its note type id is the app note type's, `Note`.
pub struct NoPrivateContent<Note> {}

impl<Note> NoteType for NoPrivateContent<Note>
where
    Note: NoteType,
{
    fn get_id() -> Field {
        Note::get_id()
    }
}

impl<Note> Packable for NoPrivateContent<Note> {
    let N: u32 = 0;

    fn pack(self) -> [Field; Self::N] {
        []
    }

    fn unpack(_packed: [Field; Self::N]) -> Self {
        NoPrivateContent {}
    }
}

/// The private content of a partial note: `M` packed fields that the
/// commitment binds (`partial_commitment_with`) and the partial-note
/// message carries, the first `M` of the app note type `Note`'s packed
/// fields; the completion log carries the rest. Its note type id is
/// `Note`'s.
pub struct PrivateContent<Note, let M: u32> {
    pub fields: [Field; M],
}

impl<Note, let M: u32> NoteType for PrivateContent<Note, M>
where
    Note: NoteType,
{
    fn get_id() -> Field {
        Note::get_id()
    }
}

impl<Note, let M: u32> Packable for PrivateContent<Note, M> {
    let N: u32 = M;

    fn pack(self) -> [Field; Self::N] {
        self.fields
    }

    fn unpack(packed: [Field; Self::N]) -> Self {
        PrivateContent { fields: packed }
    }
}

/// Tell `owner`'s PXE of the partial note `P = partial_commitment(owner,
/// rho)` of the app's note type `Note`, which a public function will
/// complete: aztec-nr's partial-note private message (no private content,
/// the completion log tag `P`), under `delivery`. The PXE's partial-note
/// state machine then waits for the completion log under
/// `completion_log_tag(P)` and stores the completed note. Only a public
/// completion needs it: a private result's note the client delivers itself.
///
/// DEV DECISION: how the request's partial-note message reaches the owner's
/// PXE (the `delivery` argument; default `MessageDelivery::offchain()`). The
/// user is sender and recipient. Offchain costs nothing and puts nothing on
/// chain, but the message exists only in the send result: the client must
/// hand it to the app's `offchain_receive` utility (aztec.js returns it as
/// `offchainMessages`; the wallet does not deliver it), and a client that
/// loses it before the completion recovers the note by rescanning the
/// completion tag from the re-derived `rho`. `MessageDelivery::
/// onchain_unconstrained()` emits it as a private log (DA gas, one more log
/// in the request transaction), so a PXE recovers from the chain alone.
/// Design: docs/ARCHITECTURE.md section 6, "Completion in a public function".
pub fn deliver_partial_note<Note, D>(
    context: &mut PrivateContext,
    owner: AztecAddress,
    rho: Field,
    partial: Field,
    delivery: D,
)
where
    Note: NoteType,
    D: MessageDeliveryBuilder,
{
    let content: NoPrivateContent<Note> = NoPrivateContent {};
    do_private_message_delivery(
        context,
        || encode_partial_note_private_message(content, owner, rho, partial),
        Option::none(),
        owner,
        delivery,
    );
}

/// `deliver_partial_note` for a partial note with private content
/// `content` (`partial_commitment_with`): the message carries the content,
/// so the owner's PXE stores the note `[content…, public fields…]` when the
/// completion log appears. Under `MessageDelivery::onchain_unconstrained()`
/// the request transaction itself holds the message, so a PXE restored from
/// the owner's keys alone finds the partial note, content included, on
/// chain (the refund notes' recovery route, pss_public_contract `token`).
pub fn deliver_partial_note_with<Note, D, let M: u32>(
    context: &mut PrivateContext,
    owner: AztecAddress,
    rho: Field,
    partial: Field,
    content: [Field; M],
    delivery: D,
)
where
    Note: NoteType,
    D: MessageDeliveryBuilder,
{
    let content: PrivateContent<Note, M> = PrivateContent { fields: content };
    do_private_message_delivery(
        context,
        || encode_partial_note_private_message(content, owner, rho, partial),
        Option::none(),
        owner,
        delivery,
    );
}

/// Complete `partial` in a public function: emit the completion log
/// `[storage_slot, fields…, request_id]` under `completion_log_tag(partial)`
/// and push the completed note's hash (`completed_note_hash`), exactly as
/// aztec-nr's `PartialUintNote::complete` does. The kernel silos the hash
/// with the app's address and makes it unique. `request_id` is last and
/// never zero, so the log keeps every field (v6 trims a public log's
/// trailing zeros). Makes no external call. The note packs `N + 1` fields,
/// at most eight.
pub fn complete_in_public<let N: u32>(
    context: PublicContext,
    storage_slot: Field,
    partial: Field,
    fields: [Field; N],
    request_id: Field,
) {
    // Safety: a public function is bytecode the AVM proves, so an
    // unconstrained body enforces what a constrained one would; it is only
    // out of line (`complete_in_public_body`).
    unsafe { complete_in_public_body(context, storage_slot, partial, fields, request_id) };
}

/// The body of `complete_in_public`, compiled once per field count instead
/// of inlined into every caller (an app's result, its refunds), since the
/// class's public bytecode, which its first deployment publishes, must stay
/// under the network's per-transaction DA limit.
#[inline_never]
unconstrained fn complete_in_public_body<let N: u32>(
    context: PublicContext,
    storage_slot: Field,
    partial: Field,
    fields: [Field; N],
    request_id: Field,
) {
    let note_hash = completed_note_hash(storage_slot, partial, fields, request_id);
    context.emit_public_log_unsafe(
        completion_log_tag(partial),
        [storage_slot].concat(fields).concat([request_id]),
    );
    context.push_note_hash(note_hash);
}

/// Require that the note the app's private function opened belongs to
/// `msg_sender`: a chained note confers ownership of what it reports only
/// on its owner. The note is read with its inclusion check (the app's
/// `get_notes` over the owner's set) and not nullified.
pub fn assert_owned<Note>(note: ConfirmedNote<Note>, msg_sender: AztecAddress) {
    assert(note.owner == msg_sender, "the note is not the sender's");
}

/// The redeem nullifier of a chained note, `poseidon2_hash_with_separator(
/// [note_hash_for_nullification, nhk_app], PSS_REDEEM)`: the canonical
/// nullifier's preimage under a separator of its own.
pub fn redeem_nullifier(note_hash_for_nullification: Field, nhk_app: Field) -> Field {
    poseidon2_hash_with_separator([note_hash_for_nullification, nhk_app], PSS_REDEEM)
}

/// Spend a chained note's value once, in the app's private `redeem`:
/// require the note to be `msg_sender`'s (`assert_owned`) and push its
/// redeem nullifier under the owner's `nhk_app`. A second redeem of the same
/// note pushes the same nullifier and the transaction is refused; the note
/// is not nullified and stays readable. The app pays what the note's fields
/// say after this call.
pub fn redeem<Note>(context: &mut PrivateContext, note: ConfirmedNote<Note>, msg_sender: AztecAddress) {
    assert_owned(note, msg_sender);
    let note_hash_for_nullification = compute_confirmed_note_hash_for_nullification(note);
    let nhk_app = context.request_nhk_app(get_public_keys(note.owner).npk_m_hash);
    context.push_nullifier_unsafe(redeem_nullifier(note_hash_for_nullification, nhk_app));
}

mod test {
    use super::{
        partial_commitment, partial_commitment_with, PSS_PARTIAL_USED, PSS_REDEEM, redeem_nullifier,
        use_nullifier,
    };
    use aztec::note::utils::compute_note_nullifier;
    use aztec::protocol::address::AztecAddress;
    use aztec::protocol::hash::poseidon2_hash;
    use aztec::protocol::traits::FromField;
    use pss_core::test_support::ascii;

    #[test]
    fn the_separators_are_their_labels() {
        assert_eq(ascii("pss.partial_used"), PSS_PARTIAL_USED);
        assert_eq(ascii("pss.redeem"), PSS_REDEEM);
    }

    // The redeem nullifier is the canonical preimage under its own
    // separator, so it is never the note's own nullifier.
    #[test]
    fn a_partial_note_without_content_is_the_plain_commitment() {
        let owner = AztecAddress::from_field(0x0a);
        assert_eq(partial_commitment_with(owner, 0x9a, []), partial_commitment(owner, 0x9a));
        assert(partial_commitment_with(owner, 0x9a, [7]) != partial_commitment_with(owner, 0x9a, [8]));
    }

    #[test]
    fn the_nullifiers_are_poseidon2_under_their_separators() {
        assert_eq(use_nullifier(0x9a), poseidon2_hash([PSS_PARTIAL_USED, 0x9a]));
        assert_eq(redeem_nullifier(0x4a, 0x7b), poseidon2_hash([PSS_REDEEM, 0x4a, 0x7b]));
        assert(redeem_nullifier(0x4a, 0x7b) != compute_note_nullifier(0x4a, [0x7b]));
    }
}
