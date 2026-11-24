//! The escape hatch (docs/ARCHITECTURE.md section 5 and section 6, "The
//! escape hatch"): how an app whose network stops serving it is frozen for
//! good, and how each owner of an entry then leaves it privately, with no
//! node, on its newest note.
//!
//! `Hatch` is a state variable of one storage slot, `HatchState` packed: a
//! clock and an open flag.
//!
//! - The clock. `starving_since` is the block from which the app has had
//!   demand and no landed round (0: not starving). The first request queued
//!   while it is 0 (`Hatch::queued`, in every request wrapper) or anyone's
//!   `poke()` starts it; every landed round that served its request
//!   (`Hatch::landed`) stops it, or restarts it at the current block when
//!   requests are still queued behind it. A round that served nobody (a
//!   secret-shared round whose shares did not open C) leaves it running,
//!   and so does `skip()`, which anyone can call on a frozen network's
//!   heads: only the nodes stop the clock, by serving a request.
//! - The opening. `Hatch::open` sets `open` once the clock has run the
//!   app's period (its `t_live` pin), and nothing clears it. While open, no
//!   request is queued (`queued`) and no round lands (`landed`), so no round
//!   replaces a leaf an owner is about to exit on; `skip()` keeps refunding
//!   what is queued.
//! - The landing's exit tags. `landed` emits each exit tag the round's proof
//!   outputs (pss_core `tip::exit`, `Tagged::nullifiers`) as a nullifier, in
//!   the public call that moves the commitment, so a tag is spent exactly
//!   when its leaf is replaced, and two landings of one result share no
//!   nullifier in the transaction pool (the pool keeps one pending
//!   transaction per nullifier, so a private push would let anyone outbid an
//!   honest landing with a copy that reverts). A tag of 0 is refused.
//! - The exit (`Hatch::exit`, private): the sender's note names an entry,
//!   the hatch was open at the transaction's anchor block (read from the
//!   slot's history, so the exit has no public call), and the note's exit
//!   tag, recomputed from the note alone, is pushed. It succeeds once and
//!   only on the entry's newest note: every later write of the entry spent
//!   the tags of the notes before. The app pays what its note says after
//!   the call (`ExitNote`).
//!
//! One place refuses a landing once open, for every deployment of an app;
//! `skip()` and the app's own `redeem` are not touched.
use crate::partial_note::{assert_owned, partial_commitment};
use crate::queue::Queue;
use aztec::context::{PrivateContext, PublicContext};
use aztec::history::storage::public_storage_historical_read;
use aztec::note::ConfirmedNote;
use aztec::protocol::address::AztecAddress;
use aztec::protocol::traits::{Deserialize, Packable, Serialize};
use aztec::state_vars::{PublicMutable, StateVariable};
use pss_core::tip::exit::exit_tag;

/// The hatch's state: whether it is open and the block the app started
/// starving at (0: not starving). Packed in one field, `open + 2 *
/// starving_since`, so the clock is one storage write and the exit one
/// historical read.
#[derive(Deserialize, Eq, Serialize)]
pub struct HatchState {
    pub open: bool,
    pub starving_since: u32,
}

impl Packable for HatchState {
    let N: u32 = 1;

    fn pack(self) -> [Field; Self::N] {
        [self.open as Field + 2 * self.starving_since as Field]
    }

    fn unpack(packed: [Field; Self::N]) -> Self {
        // a packed state is below 2^33: the truncation keeps it whole
        let v = packed[0] as u64;
        HatchState { open: v % 2 == 1, starving_since: (v / 2) as u32 }
    }
}

/// What an app's outcome note must say to be exited on.
pub trait ExitNote {
    /// the entry the note reports (its leaf index); 0 when it reports none.
    /// It comes from pss_core's `Tagged::entry` for the slot whose partial
    /// commitment the note completes, and from no other note of the round;
    /// an entry at index 0 can never exit (`Tagged::entry`'s rules).
    fn entry(self) -> Field;
    /// the chain request id of the round that issued the note
    fn request_id(self) -> Field;
}

/// The escape hatch's state variable (module doc): one slot.
pub struct Hatch<Context> {
    context: Context,
    state: PublicMutable<HatchState, Context>,
}

impl<Context> StateVariable<1, Context> for Hatch<Context> {
    fn new(context: Context, storage_slot: Field) -> Self {
        Hatch { context, state: PublicMutable::new(context, storage_slot) }
    }

    fn get_storage_slot(self) -> Field {
        self.state.get_storage_slot()
    }
}

impl Hatch<PublicContext> {
    /// Every request wrapper's, and `poke()`'s: refuse while open (a frozen
    /// app queues nothing) and start the clock at the current block when it
    /// is stopped; a running clock keeps its start.
    pub fn queued(self) {
        // Safety: a public function is bytecode the AVM proves, so an
        // unconstrained body enforces what a constrained one would; it is
        // only out of line (`queued_body`).
        unsafe { queued_body(self.context, self.state) };
    }

    /// Every landing of a queued request's: refuse while open (a frozen app
    /// lands nothing), emit each exit tag of the round as a nullifier
    /// (refusing 0), and when the round `served` its request stop the clock,
    /// or restart it at the current block when requests are still queued
    /// in `queue` (head below tail, after the landing moved the head).
    pub fn landed<let N: u32>(self, queue: Queue<PublicContext>, served: bool, tags: [Field; N]) {
        // Safety: as `queued`.
        unsafe { landed_body(self.context, self.state, queue, served, tags) };
    }

    /// The body of the app's `open_hatch()`, anyone's: open the hatch for
    /// good once the clock has run `t_live` blocks.
    pub fn open(self, t_live: u32) {
        let h = self.state.read();
        assert(h.starving_since != 0, "the app is not starving");
        assert(
            self.context.block_number() - h.starving_since >= t_live,
            "the app has starved for under T_LIVE blocks",
        );
        self.state.write(HatchState { open: true, starving_since: h.starving_since });
    }

    /// The hatch's state (the app's view of it, which pss-client's
    /// `hatchReady` reads).
    pub fn state(self) -> HatchState {
        self.state.read()
    }
}

impl Hatch<&mut PrivateContext> {
    /// The private exit: require `note` (read by the app with its inclusion
    /// check) to be `sender`'s and to name an entry, and the hatch to have
    /// been open at the anchor block, then push the note's exit tag,
    /// `exit_tag(P, request_id, entry)` with `P` the note's partial
    /// commitment, rebuilt from its owner and randomness. Every input of the
    /// tag comes from the note, so the sender has nothing to vary: a second
    /// exit on the note, or an exit on an older note of the entry, pushes a
    /// nullifier that exists and the transaction is refused. The app pays
    /// what the note says after this call.
    pub fn exit<Note>(self, note: ConfirmedNote<Note>, sender: AztecAddress)
    where
        Note: ExitNote,
    {
        assert_owned(note, sender);
        let entry = note.note.entry();
        assert(entry != 0, "the note names no entry");
        let header = self.context.get_anchor_block_header();
        let packed = public_storage_historical_read(header, self.state.get_storage_slot(), self.context.this_address());
        assert(HatchState::unpack([packed]).open, "the escape hatch was not open at the anchor block");
        let partial = partial_commitment(note.owner, note.randomness);
        self.context.push_nullifier_unsafe(exit_tag(partial, note.note.request_id(), entry));
    }
}

/// The body of `Hatch::queued`, compiled once.
#[inline_never]
unconstrained fn queued_body(context: PublicContext, state: PublicMutable<HatchState, PublicContext>) {
    let h = state.read();
    assert(!h.open, "the app is frozen: the escape hatch is open");
    if h.starving_since == 0 {
        state.write(HatchState { open: false, starving_since: context.block_number() });
    }
}

/// The body of `Hatch::landed`, compiled once per tag count.
#[inline_never]
unconstrained fn landed_body<let N: u32>(
    context: PublicContext,
    state: PublicMutable<HatchState, PublicContext>,
    queue: Queue<PublicContext>,
    served: bool,
    tags: [Field; N],
) {
    assert(!state.read().open, "the app is frozen: the escape hatch is open");
    for i in 0..N {
        assert(tags[i] != 0, "an exit tag of 0");
        context.push_nullifier_unsafe(tags[i]);
    }
    if served {
        let starving_since = if queue.get_head().index < queue.get_tail() {
            context.block_number()
        } else {
            0
        };
        state.write(HatchState { open: false, starving_since });
    }
}

mod test {
    use super::HatchState;
    use crate::partial_note::{partial_commitment, redeem_nullifier, use_nullifier};
    use aztec::note::utils::compute_note_nullifier;
    use aztec::protocol::address::AztecAddress;
    use aztec::protocol::traits::{FromField, Packable};
    use pss_core::tip::exit::exit_tag;

    // The state packs into one field and back, open and the clock apart.
    #[test]
    fn the_state_packs_into_one_field() {
        let s = HatchState { open: true, starving_since: 4000000000 };
        assert_eq(s.pack(), [1 + 2 * 4000000000]);
        assert_eq(HatchState::unpack(s.pack()), s);
        let t = HatchState { open: false, starving_since: 12 };
        assert_eq(HatchState::unpack(t.pack()), t);
        assert_eq(HatchState::unpack([0]), HatchState { open: false, starving_since: 0 });
    }

    // An exit tag is none of the contract's other nullifiers on the same
    // inputs: the use nullifier of the partial note, the redeem nullifier
    // and the canonical note nullifier.
    #[test]
    fn a_tag_is_no_other_nullifier() {
        let p = partial_commitment(AztecAddress::from_field(0x0a), 0x9a);
        let tag = exit_tag(p, 0x1d, 1);
        assert(tag != use_nullifier(p));
        assert(tag != redeem_nullifier(p, 0x1d));
        assert(tag != compute_note_nullifier(p, [0x1d]));
    }
}
