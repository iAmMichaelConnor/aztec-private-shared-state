//! One entry per round, the one call a round's main makes: the main declares
//! the ABI (the manifest binds by parameter name, so the parameter list is
//! the main's to keep) and hands its parameters here, grouped; everything
//! between the ABI and the round's `Step` (the book's slots, their indices,
//! the intake's checks, the writes and the outputs) is this module's.
//!
//! A round's mains differ by their entry, one `Entry` implementation per
//! intake family and access, chosen by the main's first argument. The
//! intake family is pss_core's (`tip::family`): its check, its write form
//! and its outputs; an entry adds where the book's indices come from and
//! what the lending outcome adds to the family's outputs.
//!
//! - `Plain`: the non-secret-shared intakes (on-chain intake and receipt
//!   intake), one compiled circuit for both, pss_core's `family::Plain`;
//!   the book's indices from the nodes; partial-note delivery in public
//!   (`OwnerRound::note_outputs`, `OwnerNoteOutputs`).
//! - `Clear`: the secret-shared intakes over the clear book (`access:
//!   clear`, the default), pss_core's `SharedIntake`; the indices from the
//!   nodes; the private outcome and the deliveries (shared.nr `finish` over
//!   pss_core's `Updated`).
//! - `Oblivious`: the secret-shared intakes over the oblivious book
//!   (`access: oblivious`); the circuit composes the indices from its own
//!   position input (pss_core `tree::slot_indices`), outputs no leaf hash
//!   (shared.nr `finish` over pss_core's `tree::Oblivious`).
//! - `Opening`: `Oblivious` for a round that may open a position (deposit,
//!   supply): C commits the opening flag `opens` after the position, and the
//!   flag must agree with the position (`opens == (position == 0)`, code 4),
//!   since a flag the nodes could flip is what would redirect a deposit into
//!   a fresh position.
//!
//! The total-lint markers of what every round inherits (tree::load's
//! old-leaf assertion on node-supplied data, the index and key bit splits,
//! npk_app_hash's scalar decomposition) sit at their lines in pss_core,
//! whose markers scripts/check-noir.sh counts; a main carries none.
use crate::market::{
    CODE_INPUTS_MISMATCH, DEPTH, Leaf, LEAF_LEN, OWNER_SLOTS, PROBES, SCAN_SLOTS, WINDOW, WINDOW_HEIGHT,
    WINDOW_SIBLINGS,
};
use crate::rounds::{self, OwnerNoteOutputs, OwnerRound, Step};
use crate::shared::{Booked, finish, ObliviousRound, OUTCOME_SLOT, SharedRound};
pub use crate::shared::{Handle, Shared, SharedIntake};
/// A main's public prefix (pss_core's): the namespace, the circuit's vk
/// hash and the market key read and written.
pub use pss_core::tip::family::Prefix;
use pss_core::tip::family::{self, Family};
use pss_core::tip::outputs::{BoundPartial, Finished};
use pss_core::tip::tree::{self, Tree, Updated};
use total::cmp::eq;
use total::core::is_zero;

/// The pinned reads every lending round makes, after the prefix, so that
/// every round's apply is the same (the hidden round type): the oracle's
/// price and its epoch (`get_price_epoch`, freshness epoch) and the
/// market's clock (`clock()`, the L2 block number, within CLOCK_BAND blocks
/// of the block apply lands in).
pub struct Pinned {
    pub price: Field,
    pub price_epoch: Field,
    pub clock: Field,
}

impl Pinned {
    /// The pinned values in the manifests' `public_reads` order.
    pub fn values(self) -> [Field; 3] {
        [self.price, self.price_epoch, self.clock]
    }
}

/// The book's slots as the nodes read them (pss_core's `tree::Slots`): the
/// leaves (LOAD_LEAF, shared), their old hashes (0 for an empty leaf) and
/// their siblings, bottom up.
pub type Slots<let K: u32> = tree::Slots<K, DEPTH, LEAF_LEN>;

/// A scan's window as the nodes read it: WINDOW consecutive leaves, their
/// old hashes and the window root's siblings (pss_core `Tree::window`).
pub struct WindowSlots {
    pub leaves: [Leaf; WINDOW],
    pub hashes: [Field; WINDOW],
    pub siblings: [Field; WINDOW_SIBLINGS],
}

/// A non-secret-shared owner round's public outputs (`Plain`): pss_core's
/// `BoundPartial` with `OwnerNoteOutputs`.
pub type PlainOwner = BoundPartial<OwnerNoteOutputs>;

/// How a main reaches its round: where the book's indices come from, the
/// intake family it runs under and what the lending outcome adds to the
/// family's outputs (one implementation per intake family and access,
/// module doc).
pub trait Entry<let K: u32> {
    /// the main's public outputs
    type Out;
    /// The slots' indices: slot 0 the header, slot 1 onwards the request's
    /// positions (`position` the first, `n_positions` of them, `new_leaf`
    /// the scheduler's assignment for an opening).
    fn indices(self, position: Field, n_positions: Field, new_leaf: Field) -> [Field; K];
    /// Write the step and return the outputs; `inputs` are the round's app
    /// inputs in ABI order.
    fn finish<let I: u32>(
        self,
        p: Prefix,
        pin: Pinned,
        t: Tree<K, DEPTH, LEAF_LEN>,
        step: Step<K>,
        inputs: [Field; I],
        nsk_app: Field,
    ) -> Self::Out;
}

/// The non-secret-shared intakes: the nodes' indices and pss_core's
/// `family::Plain` values, the request's partial note (PUBLIC
/// `$partial_note`, echoed right after `ok` for apply's public completion)
/// and its salt (`user_nonce`, not checked here: apply compares the request
/// id with the queue's).
pub struct Plain {
    pub indices: [Field; OWNER_SLOTS],
    pub partial_note: Field,
    pub user_nonce: Field,
}

/// The secret-shared intakes over the clear book: the nodes' indices, the
/// intake's values (C, `$partial_note`, `$outcome_key`, `$outcome_tag`,
/// `$blinding`) and the request's delivery handle (`handle_partial`,
/// `handle_key`, after the app inputs in C), which an owner round on a
/// borrower position carries and every other round does not (none).
pub struct Clear<let K: u32> {
    pub indices: [Field; K],
    pub shared: SharedIntake,
    pub handle: Option<Handle>,
}

/// The secret-shared intakes over the oblivious book, for a round that opens
/// nothing.
pub struct Oblivious {
    pub shared: SharedIntake,
    pub handle: Option<Handle>,
}

/// The secret-shared intakes over the oblivious book, for a round that may
/// open a position: `opens`, shared, 1 when the request opens.
pub struct Opening {
    pub opens: Field,
    pub shared: SharedIntake,
    pub handle: Option<Handle>,
}

impl Entry<OWNER_SLOTS> for Plain {
    type Out = PlainOwner;

    fn indices(self, _position: Field, _n_positions: Field, _new_leaf: Field) -> [Field; OWNER_SLOTS] {
        self.indices
    }

    /// The step written in the non-secret-shared form (`Tree::update`: a
    /// round that cannot apply proves with ok = 0 and new_c = old_c), the
    /// request id over the inputs and the partial note, and the outputs
    /// `[ok, partial_note, code, position, mask, payout, new_hashes]`
    /// (pss_core's `family::Plain`).
    ///
    /// DEV DECISION: the non-secret-shared owner rounds' reveal, default
    /// `OwnerNoteOutputs` (design guide: "the outcome fields"). ok tells apply
    /// whether the request landed (and whether to return the escrow); the
    /// code says why not, which reveals one fact about the position or the
    /// market; position names the leaf the round touched (an opening's
    /// assigned index); mask the position's kind marker and payout what the
    /// note pays, which apply completes the request's note with; the new
    /// leaf hashes are hiding (each leaf carries a fresh blinding) and let
    /// the nodes rebuild the clear tree. The position's collateral and debt
    /// stay out: a public completion would publish them (the secret-shared
    /// rounds' notes report them, inside the co-SNARK). The alternative is a
    /// secret-shared intake, whose outcome is private.
    ///
    /// Constraints: Tree::update, two p2_hash for the request id,
    /// npk_app_hash; the store is an unconstrained side-effect-only oracle.
    fn finish<let I: u32>(
        self,
        p: Prefix,
        pin: Pinned,
        t: Tree<OWNER_SLOTS, DEPTH, LEAF_LEN>,
        step: Step<OWNER_SLOTS>,
        inputs: [Field; I],
        nsk_app: Field,
    ) -> PlainOwner {
        // BRICK intake = onchain, receipt (pss_core::tip::family::Plain), one circuit for both.
        // Alternatives: shared_receipt, shared_onchain (the Clear, Oblivious and Opening entries below).
        // docs/design-guide/BRICKS.md#intake
        // BRICK value = partial (pss_core::tip::family::Plain), completed in public by apply.
        // Alternatives: none (Written::bound). docs/design-guide/BRICKS.md#value
        let plain = family::Plain { partial_note: self.partial_note, user_nonce: self.user_nonce };
        let checked = plain.check(inputs, CODE_INPUTS_MISMATCH);
        let booked: Booked<Updated<OWNER_SLOTS, LEAF_LEN>, OWNER_SLOTS> = checked.write(step.change(t));
        let updated = booked.written;
        let r = OwnerRound::of(updated, step);
        let round: Finished<Updated<OWNER_SLOTS, LEAF_LEN>, PlainOwner> =
            checked.finish(updated, p.namespace, p.vk_hash, inputs, pin.values(), r.note_outputs(), [], OUTCOME_SLOT, nsk_app);
        round.stored()
    }
}

impl<let K: u32> Entry<K> for Clear<K> {
    type Out = Shared<K>;

    fn indices(self, _position: Field, _n_positions: Field, _new_leaf: Field) -> [Field; K] {
        self.indices
    }

    fn finish<let I: u32>(
        self,
        p: Prefix,
        pin: Pinned,
        t: Tree<K, DEPTH, LEAF_LEN>,
        step: Step<K>,
        inputs: [Field; I],
        nsk_app: Field,
    ) -> Shared<K> {
        let round: SharedRound<K> = finish(p, pin, t, step, true, inputs, self.handle, self.shared, nsk_app);
        round.stored()
    }
}

/// The oblivious indices of a round over K slots: the header, then (K > 1)
/// the low DEPTH bits of the first position input in each used position
/// slot, `new_leaf` when `opens` (pss_core `tree::slot_indices`). No
/// constraint for K = 1.
fn oblivious_indices<let K: u32>(position: Field, n_positions: Field, opens: bool, new_leaf: Field) -> [Field; K] {
    let mut out = [0; K];
    if K > 1 {
        // BRICK shape = tree_oblivious (pss_core::tip::tree::slot_indices): the circuit places the
        // oblivious book's indices itself. Alternatives: tree (the nodes place them: the Clear entry).
        // docs/design-guide/BRICKS.md#shape
        let placed = tree::slot_indices::<1, DEPTH>([position], n_positions, opens, new_leaf);
        for k in 1..K {
            out[k] = placed[k];
        }
    }
    out
}

impl<let K: u32> Entry<K> for Oblivious {
    type Out = Shared<K>;

    fn indices(self, position: Field, n_positions: Field, _new_leaf: Field) -> [Field; K] {
        oblivious_indices(position, n_positions, false, 0)
    }

    fn finish<let I: u32>(
        self,
        p: Prefix,
        pin: Pinned,
        t: Tree<K, DEPTH, LEAF_LEN>,
        step: Step<K>,
        inputs: [Field; I],
        nsk_app: Field,
    ) -> Shared<K> {
        let round: ObliviousRound<K> = finish(p, pin, t, step, true, inputs, self.handle, self.shared, nsk_app);
        round.stored()
    }
}

impl<let K: u32> Entry<K> for Opening {
    type Out = Shared<K>;

    fn indices(self, position: Field, n_positions: Field, new_leaf: Field) -> [Field; K] {
        oblivious_indices(position, n_positions, eq(self.opens, 1), new_leaf)
    }

    /// C commits `[position, opens, the other inputs]`, `position` the first
    /// app input.
    fn finish<let I: u32>(
        self,
        p: Prefix,
        pin: Pinned,
        t: Tree<K, DEPTH, LEAF_LEN>,
        step: Step<K>,
        inputs: [Field; I],
        nsk_app: Field,
    ) -> Shared<K> {
        let mut committed = [0; I + 1];
        committed[0] = inputs[0];
        committed[1] = self.opens;
        for i in 1..I {
            committed[i + 1] = inputs[i];
        }
        // opens == (position == 0), by AND and OR: no equality hint
        let opening = eq(self.opens, 1);
        let unnamed = is_zero(inputs[0]);
        let consistent = (opening & unnamed) | (!opening & !unnamed);
        let round: ObliviousRound<K> = finish(p, pin, t, step, consistent, committed, self.handle, self.shared, nsk_app);
        round.stored()
    }
}

/// The book (`rounds::book`, `1 + n_positions` slots used, at the entry's
/// indices), the round on it, and the entry's finish.
fn run<F, let K: u32, let I: u32, Env>(
    entry: F,
    p: Prefix,
    pin: Pinned,
    slots: Slots<K>,
    inputs: [Field; I],
    position: Field,
    n_positions: Field,
    new_leaf: Field,
    nsk_app: Field,
    round: fn[Env](Tree<K, DEPTH, LEAF_LEN>) -> Step<K>,
) -> <F as Entry<K>>::Out
where
    F: Entry<K>,
{
    let indices = entry.indices(position, n_positions, new_leaf);
    let t = rounds::book(
        p.namespace,
        p.in_slots[0],
        p.out_slots[0],
        slots.leaves,
        slots.old_hashes,
        slots.siblings,
        indices,
        1 + n_positions,
    );
    entry.finish(p, pin, t, round(t), inputs, nsk_app)
}

/// deposit(position, amount): rounds.nr `deposit`; position 0 opens the
/// empty leaf the scheduler assigns (`new_leaf`, PUBLIC `$new_leaf`, 0
/// when the book is full).
pub fn deposit<F>(
    entry: F,
    p: Prefix,
    pin: Pinned,
    inputs: [Field; 2],
    slots: Slots<OWNER_SLOTS>,
    new_leaf: Field,
    r_new: [Field; OWNER_SLOTS],
    nsk_app: Field,
) -> <F as Entry<OWNER_SLOTS>>::Out
where
    F: Entry<OWNER_SLOTS>,
{
    run(entry, p, pin, slots, inputs, inputs[0], 1, new_leaf, nsk_app, |t| rounds::deposit(t, inputs, new_leaf, pin.clock, r_new))
}

/// supply(position, amount): rounds.nr `supply`; position 0 opens a lender
/// leaf at `new_leaf`.
pub fn supply<F>(
    entry: F,
    p: Prefix,
    pin: Pinned,
    inputs: [Field; 2],
    slots: Slots<OWNER_SLOTS>,
    new_leaf: Field,
    r_new: [Field; OWNER_SLOTS],
    nsk_app: Field,
) -> <F as Entry<OWNER_SLOTS>>::Out
where
    F: Entry<OWNER_SLOTS>,
{
    run(entry, p, pin, slots, inputs, inputs[0], 1, new_leaf, nsk_app, |t| rounds::supply(t, inputs, new_leaf, pin.clock, r_new))
}

/// borrow(position, amount) at the pinned price: rounds.nr `borrow`.
pub fn borrow<F>(
    entry: F,
    p: Prefix,
    pin: Pinned,
    inputs: [Field; 2],
    slots: Slots<OWNER_SLOTS>,
    r_new: [Field; OWNER_SLOTS],
    nsk_app: Field,
) -> <F as Entry<OWNER_SLOTS>>::Out
where
    F: Entry<OWNER_SLOTS>,
{
    run(entry, p, pin, slots, inputs, inputs[0], 1, 0, nsk_app, |t| rounds::borrow(t, inputs, pin.price, pin.clock, r_new))
}

/// withdraw(position, amount) at the pinned price: rounds.nr `withdraw`.
pub fn withdraw<F>(
    entry: F,
    p: Prefix,
    pin: Pinned,
    inputs: [Field; 2],
    slots: Slots<OWNER_SLOTS>,
    r_new: [Field; OWNER_SLOTS],
    nsk_app: Field,
) -> <F as Entry<OWNER_SLOTS>>::Out
where
    F: Entry<OWNER_SLOTS>,
{
    run(entry, p, pin, slots, inputs, inputs[0], 1, 0, nsk_app, |t| rounds::withdraw(t, inputs, pin.price, pin.clock, r_new))
}

/// repay(position, amount): rounds.nr `repay`.
pub fn repay<F>(
    entry: F,
    p: Prefix,
    pin: Pinned,
    inputs: [Field; 2],
    slots: Slots<OWNER_SLOTS>,
    r_new: [Field; OWNER_SLOTS],
    nsk_app: Field,
) -> <F as Entry<OWNER_SLOTS>>::Out
where
    F: Entry<OWNER_SLOTS>,
{
    run(entry, p, pin, slots, inputs, inputs[0], 1, 0, nsk_app, |t| rounds::repay(t, inputs, pin.clock, r_new))
}

/// withdraw_supply(position, shares): rounds.nr `withdraw_supply`.
pub fn withdraw_supply<F>(
    entry: F,
    p: Prefix,
    pin: Pinned,
    inputs: [Field; 2],
    slots: Slots<OWNER_SLOTS>,
    r_new: [Field; OWNER_SLOTS],
    nsk_app: Field,
) -> <F as Entry<OWNER_SLOTS>>::Out
where
    F: Entry<OWNER_SLOTS>,
{
    run(entry, p, pin, slots, inputs, inputs[0], 1, 0, nsk_app, |t| rounds::withdraw_supply(t, inputs, pin.clock, r_new))
}

/// view(position): rounds.nr `view`.
pub fn view<F>(
    entry: F,
    p: Prefix,
    pin: Pinned,
    inputs: [Field; 1],
    slots: Slots<OWNER_SLOTS>,
    r_new: [Field; OWNER_SLOTS],
    nsk_app: Field,
) -> <F as Entry<OWNER_SLOTS>>::Out
where
    F: Entry<OWNER_SLOTS>,
{
    run(entry, p, pin, slots, inputs, inputs[0], 1, 0, nsk_app, |t| rounds::view(t, inputs, pin.clock, r_new))
}

/// liquidate(p1, count, budget) at the pinned price: rounds.nr `liquidate`,
/// the header and `count` probes used.
pub fn liquidate<F>(
    entry: F,
    p: Prefix,
    pin: Pinned,
    inputs: [Field; PROBES + 1],
    slots: Slots<PROBES>,
    r_new: [Field; PROBES],
    nsk_app: Field,
) -> <F as Entry<PROBES>>::Out
where
    F: Entry<PROBES>,
{
    let count = inputs[PROBES - 1];
    run(entry, p, pin, slots, inputs, inputs[0], count, 0, nsk_app, |t| rounds::liquidate(t, inputs, pin.price, pin.clock, r_new))
}

/// quote_rates(): rounds.nr `quote_rates`, over the header alone (the
/// quote round; `quote` is a Noir keyword).
pub fn quote_rates<F>(
    entry: F,
    p: Prefix,
    pin: Pinned,
    slots: Slots<SCAN_SLOTS>,
    r_new: [Field; SCAN_SLOTS],
    nsk_app: Field,
) -> <F as Entry<SCAN_SLOTS>>::Out
where
    F: Entry<SCAN_SLOTS>,
{
    let inputs: [Field; 0] = [];
    run(entry, p, pin, slots, inputs, 0, 0, 0, nsk_app, |t| rounds::quote_rates(t, pin.clock, r_new))
}

/// scan(start) at the pinned price: rounds.nr `scan`, over the header and
/// the window at `start`.
pub fn scan<F>(
    entry: F,
    p: Prefix,
    pin: Pinned,
    inputs: [Field; 1],
    slots: Slots<SCAN_SLOTS>,
    window: WindowSlots,
    r_new: [Field; SCAN_SLOTS],
    nsk_app: Field,
) -> <F as Entry<SCAN_SLOTS>>::Out
where
    F: Entry<SCAN_SLOTS>,
{
    run(entry, p, pin, slots, inputs, 0, 0, 0, nsk_app, |t: Tree<SCAN_SLOTS, DEPTH, LEAF_LEN>| {
        let w = t.window::<WINDOW, WINDOW_HEIGHT, WINDOW_SIBLINGS>(inputs[0], window.leaves, window.hashes, window.siblings);
        rounds::scan(t, w, pin.price, pin.clock, r_new)
    })
}
