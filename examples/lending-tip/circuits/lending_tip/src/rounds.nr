//! The total rounds of the lending market (deposit, withdraw, borrow, repay,
//! supply, withdraw_supply, view, quote, liquidate and the keeper's scan)
//! and its init, over the book's tree (pss_core::tip::tree;
//! market.nr has the layout and the codes). Each round is one source for
//! every intake.
//!
//! Each round takes the slots the nodes load (`book`: the touched leaves,
//! their old hashes and paths, the effective indices), applies one request
//! and returns its `Step`: the outcome, the leaves it writes when ok and the
//! values it reports. The intake's finisher writes the step into the tree
//! (pss_core's `Updated`: the stored leaves, the new leaf hashes, old_c and
//! new_c): `Tree::update` under the non-secret-shared intakes (`owner_round`,
//! the owner rounds' only non-secret-shared finisher), where a round that cannot apply proves with ok = false
//! and new_c = old_c and applies as a no-op, and `Tree::update_private`
//! under private outcomes (the secret-shared intakes, shared.nr), where every
//! outcome re-blinds the state. None fails a constraint but the
//! tree's own old-leaf check (a diverged store): every other check is a
//! flag folded into one Outcome.
//!
//! Slots. The owner rounds take two: the header (leaf 0) and the
//! position; a quote takes the header alone. A deposit or a supply that
//! names position 0 (the open sentinel) opens the empty leaf the scheduler
//! assigns, `$new_leaf`, as a borrower's or a lender's, which must be the
//! header's append index `next_index` (code 17); the header then records
//! `next_index + 1`. A liquidation takes the
//! header and up to PROBES - 1 positions, `count` of them used; each used
//! probe that is unhealthy at the price is liquidated, the others are
//! skipped. Every written leaf takes a fresh blinding (SAMPLE, one per
//! slot), so leaf hashes hide the leaves.
//!
//! Who may act on a position is decided before a request is queued, never
//! here: the app's private request function opens the requester's own
//! completed note of the position (ownership by note,
//! docs/ARCHITECTURE.md section 6, "Ownership by note") and the round never
//! sees an owner, in shares or otherwise. The rounds keep one backstop: every
//! owner round but an opening requires the position's leaf to be of its kind
//! (code 5: a borrower's for deposit, withdraw, borrow and repay, a lender's
//! for supply and withdraw_supply, either for view), which an honest request
//! never trips. Liquidate, scan and quote are open to anyone.
//!
//! The market's scope (docs/DECISIONS.md section 13, "Lending is a full,
//! realistic market"; examples/lending-tip/README.md): the
//! borrower rounds deposit, withdraw (collateral), borrow and repay, a
//! borrow limit (market.nr `LTV_BPS`) below the liquidation threshold
//! checked at borrow and withdraw, repayments capped at the debt with the
//! excess returned; the lender rounds supply and withdraw_supply, shares of
//! the pool priced by its value (the exchange-rate supply index), and the
//! quote of the rates; liquidators with a repay budget, the keeper's scan,
//! and real tokens, every payout and refund in the note's payout with its
//! asset bit. The init seeds the liquidity as protocol-owned shares.
//! Interest accrues by time (market.nr `accrue`): every round takes the
//! pinned clock (the market's `clock()`, the L2 block number) beside the
//! price and accrues the header first, so every round that applies writes
//! the accrued borrow index, total_debt and last_accrual; a round that
//! writes a borrower position brings it to the current index first
//! (market.nr `debt_at`), and the liquidation and the scan decide health on
//! the accrued debt without dividing (market.nr `unhealthy_accrued`). A
//! round that does not apply writes nothing, so it accrues nothing, and the
//! next applying round accrues the whole interval. `view`, owner-bound and
//! read-only, is the secret-shared intakes' way for an owner to read its
//! position of either kind (the refresh of a note a liquidation left
//! stale), and `scan` the keeper's.

use crate::market::{
    accrue, Accrued, add_sat, add_u128, amount_or, ASSET_BORROWED, ASSET_COLLATERAL, BONUS_BPS,
    BPS, CLOSE_BPS, CODE_AMOUNT_RANGE, CODE_APPEND_INDEX, CODE_BAD_STATE, CODE_DUPLICATE,
    CODE_EXCEEDS_COLLATERAL, CODE_EXCEEDS_SHARES, CODE_FULL_BOOK, CODE_KIND, CODE_LIMIT,
    CODE_LIQUIDITY, CODE_OVERFLOW, CODE_POSITION_RANGE, CODE_PRICE, CODE_ZERO_AMOUNT,
    CODE_ZERO_QUOTIENT, debt_at, DEPTH, field, H_BORROW_INDEX, H_DEBT, H_LAST_ACCRUAL,
    H_LIQUIDITY, H_NEXT_INDEX, H_SHARES, Header, header, INDEX_ONE, KIND_BORROWER, KIND_LENDER,
    Leaf, LEAF_LEN, mul_div_wide, OWNER_SLOTS, payout, Position, position, PRICE_SCALE, PROBES,
    SCAN_SLOTS, sub_sat, sub_u128, unhealthy_accrued, value_of, WINDOW, within_limit_at_price,
};
use pss_core::tip::exit::{TaggedChange, Tagging};
use pss_core::tip::family::Change;
use pss_core::tip::tree;
use pss_core::tip::tree::{Oblivious, Tree, Updated, Window};
use total::cmp::lt;
use total::core::{is_zero, select_field};
use total::ctl::Outcome;
use total::range::{clamp_bits_or, fits_bits};

/// The tree an owner-bound round loads: the header and one position.
pub type OwnerBook = Tree<OWNER_SLOTS, DEPTH, LEAF_LEN>;
/// The tree a liquidation loads: the header and PROBES - 1 positions.
pub type ProbeBook = Tree<PROBES, DEPTH, LEAF_LEN>;
/// The tree a scan loads besides its window, and a quote: the header.
pub type ScanBook = Tree<SCAN_SLOTS, DEPTH, LEAF_LEN>;

/// The book's slots as the nodes place them (the manifest's `tree` entry:
/// `leaves` LOAD_LEAF, `old_hashes`, `siblings` and `indices` PUBLIC from
/// the nodes' clear trees), `n_used` of them used, slot 0 the header,
/// reading `in_key` and writing `out_key` (the market key on both sides).
/// Constraints: tree::load's (its one assertion, the old leaves against
/// their old hashes, is on node-supplied data).
pub fn book<let K: u32>(
    namespace: Field,
    in_key: Field,
    out_key: Field,
    leaves: [Leaf; K],
    old_hashes: [Field; K],
    siblings: [[Field; DEPTH]; K],
    indices: [Field; K],
    n_used: Field,
) -> Tree<K, DEPTH, LEAF_LEN> {
    // BRICK shape = tree, tree_oblivious (pss_core::tip::tree::load), one source for both accesses.
    // Alternatives: flat (pss_core tip::slot), map_oblivious (tip::map). docs/design-guide/BRICKS.md#shape
    tree::load::<K, DEPTH, LEAF_LEN>(
        namespace,
        in_key,
        leaves,
        old_hashes,
        siblings,
        indices,
        n_used,
    )
        .headed()
        .writes_to(out_key)
}

/// What a round computes from its slots and its request before anything is
/// written: the outcome, the leaves it writes when ok, whether the request's
/// placement holds, and the values its outcome reports. The intake's
/// finisher writes it (`Tree::update` under the non-secret-shared intakes,
/// `Tree::update_private` under private outcomes), and `with_intake` puts the
/// intake's own checks first. One source per round, whatever the intake.
pub struct Step<let K: u32> {
    pub outcome: Outcome,
    /// the placement checks on public data hold: the request's indices are
    /// in range and distinct, the count is in range, the book is not full
    /// for an opening, and the nodes' paths and indices are the request's
    /// (codes 3, 15, 16 and the placement part of 4). The nodes can tell
    /// whether it holds from the clear request and their clear trees, so a
    /// round whose placement fails writes nothing under every intake. The
    /// append index (code 17) is not part of it: the header holds it
    /// shared, so a mismatch is an ok = false outcome, under which a
    /// private round re-blinds the header and leaves the opening slot empty
    pub placed: bool,
    /// the slots the round writes when ok
    pub writes: [bool; K],
    /// the round's write policy under private outcomes (pss_core's
    /// `Tree::update_private`): slot k is re-blinded on every outcome when
    /// set, and written only when the round writes it otherwise. Set for the
    /// header and an owner round's position (the requester's own leaf, whose
    /// note the round issues); clear for a liquidation's probes, so a probe
    /// it does not liquidate keeps its leaf, and its owner's newest note
    /// keeps its unspent exit tag (examples/lending-tip/README.md, "The
    /// escape hatch", "The liquidation's write rule")
    pub reblind: [bool; K],
    /// their leaves when ok, each under its fresh blinding `r_new[k]`
    pub new_leaves: [Leaf; K],
    /// the fresh blindings, SAMPLE, one per slot
    pub r_new: [Field; K],
    /// what the outcome reports after `code` when ok (`Report`): the
    /// owner rounds' position after the round, a liquidation's settlement,
    /// a scan's or a quote's numbers
    pub report: Report,
    /// the position as the leaf holds it (unchanged) when the round does
    /// not apply but vouches for the requester's leaf (`vouches`; an owner
    /// report); the payout is the refund
    pub held: Report,
    /// the round vouches for the leaf the request named, so a failed
    /// round's note still names it (examples/lending-tip/README.md,
    /// "Notes: ownership, the owner's view and value", "Ownership: the
    /// naming rule"): the request named an open leaf that the private function
    /// proved the requester owns, the placement and the loaded state hold
    /// (codes 3, 4, 5 and the placement failures excluded), and the shares
    /// open C (`with_intake`). Never for an opening, a liquidation or a
    /// scan: an opening that does not apply opened nothing, and a note
    /// naming its `$new_leaf` would own an index someone else opens later
    pub vouches: bool,
    /// the round's note names its position (slot 1), the index the tagged
    /// write wrote there (`named`): true for the owner rounds
    pub names_position: bool,
    /// the escrow a round that does not apply returns, as a payout
    /// (`market::payout`): a deposit's amount in the collateral asset, a
    /// repayment's amount or a liquidation's budget in the borrowed asset,
    /// else 0. The outcome reports it when not ok, in payout
    /// (`outcome_fields`), and only when the request's inputs are the ones
    /// the user committed (`with_intake`)
    pub refund: Field,
    /// the slots whose owner the round notifies: where the round writes
    /// slot k, the delivery handle its loaded leaf holds (market.nr
    /// `P_HANDLE`) is completed with the position after the round
    /// (shared.nr `deliveries`), and the new leaf keeps it and holds the
    /// notice's exit tag. Set for a liquidation's probes, clear for every
    /// other slot
    pub notices: [bool; K],
}

/// What a round's outcome reports after `code`: `[position, mask, x, y,
/// payout, aux]` (`OUTCOME_FIELDS`, `fields`). The contract pays
/// `payout` (`market::payout(amount, asset)`) and, on a note that names no
/// position, `x` in the collateral asset (lending_tip's
/// `LendingOutcome::settlement`), so the fields are private and every report
/// comes from one of the constructors below: only `liquidation` names no
/// position and sets an `x`, its seize; an owner report names its position,
/// which is never 0 where the round applies or vouches for it, and a header
/// report pays nothing. No constraint.
pub struct Report {
    position: Field,
    mask: Field,
    x: Field,
    y: Field,
    payout: Field,
    aux: Field,
}

impl Report {
    /// An owner round's: the position's index, its kind's mask (a borrower
    /// leaf's index_at_touch, never 0; a lender leaf's 0), `view` (`[x, y]`:
    /// a borrower's collateral and debt, a lender's shares and their value)
    /// and `payout`: a borrow's amount (the borrowed asset), a withdrawal's
    /// (the collateral asset), a repayment's excess over the debt, else 0.
    /// aux is 0.
    pub fn owner(position: Field, mask: Field, view: [Field; 2], payout: Field) -> Self {
        Report { position, mask, x: view[0], y: view[1], payout, aux: 0 }
    }

    /// A liquidation's: no position, the mask of the liquidated probes, the
    /// total seize in x (paid in the collateral asset), the total repay in
    /// y and the unused budget in payout (the borrowed asset).
    pub fn liquidation(mask: Field, seize: Field, repay: Field, payout: Field) -> Self {
        Report { position: 0, mask, x: seize, y: repay, payout, aux: 0 }
    }

    /// A header-only round's, which pays nothing: no position, x and payout
    /// 0, its numbers in mask, y and aux (a scan: its report, its start and
    /// the occupied count; a quote: the borrow index, the supply index and
    /// the utilisation).
    pub fn header(mask: Field, y: Field, aux: Field) -> Self {
        Report { position: 0, mask, x: 0, y, payout: 0, aux }
    }

    /// The report of a round that reports nothing (the held view of a round
    /// that vouches for no leaf): all zero.
    pub fn none() -> Self {
        Report::header(0, 0, 0)
    }

    /// The report with `payout` in place of its own (a failed round's
    /// refund).
    fn with_payout(self, payout: Field) -> Self {
        let mut r = self;
        r.payout = payout;
        r
    }

    /// `[position, mask, x, y, payout, aux]`.
    pub fn fields(self) -> [Field; 6] {
        [self.position, self.mask, self.x, self.y, self.payout, self.aux]
    }
}

/// The fields of every lending round's outcome: `[code, position, mask, x,
/// y, payout, aux]`, one shape for every round type, `code = 0` when
/// the round applied (there is no `ok` field: total's `Outcome` sets the
/// code to 0 exactly when ok). With the chain request id last they are the
/// completed note's eight packed fields, aztec-nr's cap
/// (docs/ARCHITECTURE.md section 6, "The note hash and randomness rule").
///
/// A note with `position != 0` is an owner note of that position: the
/// round names a position exactly when it vouches for the requester's leaf
/// (`Step::vouches`, or an opening that applied), on success and on a
/// failure after the placement and the leaf's checks (a borrow refused at
/// the limit still reports the position as it stands). The contract's
/// private request functions require one before a request on the
/// position, and its exit tag, which the round stored in the leaf it wrote
/// (pss_core `tip::exit`), is the one the escape hatch's exit spends while
/// the note is the position's newest. A note names a position only where
/// the round wrote its leaf (`Step::named`). A liquidation's, a scan's and a
/// failed opening's notes report position 0 and confer nothing; `aux` is a
/// header-only round's third number (a scan's occupied count, a quote's
/// utilisation), else 0.
///
/// What the contract pays on the note (the app's `redeem`, from its public
/// balances): `payout`'s amount in the asset its bit names
/// (`market::payout`), and `x` in the collateral asset when the note names
/// no position (`position = 0`: a liquidation's seize). So the outcome is
/// the settlement of the request's escrow too: every refund travels in
/// payout, a deposit's amount in the collateral asset, a repayment's amount
/// or a liquidation's budget in the borrowed asset.
pub global OUTCOME_FIELDS: u32 = 7;

impl<let K: u32> Step<K> {
    /// The step with the intake's checks first (the secret-shared intakes' inputs
    /// commitment check, code 14): their code wins over the round's. A
    /// request whose shares do not open C returns no escrow in its outcome:
    /// its inputs, and the note's owner, are not the ones the user
    /// committed, so a refund computed from them could pay anyone anything;
    /// the contract's apply refunds its escrow instead, on the round's
    /// inputs-opened bit (examples/lending-tip/README.md, "Tokens", "The
    /// inputs-opened bit").
    ///
    /// Nor does it write any position slot: its position is an unbound
    /// witness when the shares do not open C, so the prover chooses the
    /// placed index, and a re-blind there would spend that position's
    /// owner's exit tag without a note for it. pss_core's
    /// `Tree::update_private` keeps that rule under its
    /// `opened` flag (shared.nr `finish` passes the opening bit): such a
    /// round re-blinds the header alone, as a header-only round does
    /// (examples/lending-tip/README.md, "The escape hatch", "The
    /// liquidation's write rule"). Constraints: one AND and the selects.
    pub fn with_intake(self, intake: Outcome) -> Self {
        let mut s = self;
        s.outcome = intake.and_outcome(self.outcome);
        s.refund = intake.mask_field(self.refund);
        s.vouches = intake.ok & self.vouches;
        s
    }

    /// The step with the position its note names taken from the write:
    /// `entry`, the index the tagged write wrote in slot 1 and 0 where it
    /// wrote none (pss_core `Tagged::entry`), in its report's and its held
    /// view's position when the round names its position
    /// (`names_position`); unchanged otherwise. A round that applies or
    /// vouches for the requester's leaf writes it, so the index is the
    /// request's; a note names a position only where its leaf holds the
    /// note's exit tag. No constraint but selects.
    pub fn named(self, entry: Field) -> Self {
        let mut s = self;
        s.report.position = select_field(self.names_position, entry, self.report.position);
        s.held.position = select_field(self.names_position, entry, self.held.position);
        s
    }

    /// The step's write to the book `t` (pss_core's `Tree::change_tagged`),
    /// in the form the round's intake family picks: its writes, its leaves,
    /// its placement, its write policy and its blindings, a re-blinded slot
    /// keeping its loaded leaf; the tagged write's inputs are the
    /// secret-shared finisher's (shared.nr `finish`). No constraint.
    pub fn change(self, t: Tree<K, DEPTH, LEAF_LEN>) -> TaggedChange<K, DEPTH, LEAF_LEN> {
        // BRICK escape-hatch (pss_core::tip::exit::Tree::change_tagged): every written position leaf
        // takes its newest note's exit tag. No alternative; an app without a hatch writes with
        // Tree::change. docs/design-guide/BRICKS.md#other-bricks
        t.change_tagged(
            self.placed,
            self.outcome.ok,
            self.writes,
            self.reblind,
            self.new_leaves,
            t.leaves,
            self.r_new,
            Tagging { request_id: 0, requester: 0, partials: [0; K] },
        )
    }

    /// The outcome plaintext `[code, position, mask, x, y, payout, aux]`:
    /// the report when ok; when not ok, the code, the escrow
    /// returned in payout (`refund`) and, when the round vouches for the
    /// requester's leaf, the position as the leaf holds it (`held`), else
    /// nothing of any position, so the note confers nothing.
    pub fn outcome_fields(self) -> [Field; OUTCOME_FIELDS] {
        let ok = self.outcome.ok;
        let failed = Report::none().with_payout(self.refund).fields();
        let held = self.held.with_payout(self.refund).fields();
        let applied = self.report.fields();
        let mut report = [0; 6];
        for i in 0..6 {
            let not_ok = select_field(self.vouches, held[i], failed[i]);
            report[i] = select_field(ok, applied[i], not_ok);
        }
        [self.outcome.code].concat(report)
    }
}

/// What an owner-bound round leaves under the non-secret-shared intakes.
pub struct OwnerRound {
    pub updated: Updated<OWNER_SLOTS, LEAF_LEN>,
    pub outcome: Outcome,
    /// the position's index: the request's, or $new_leaf for an opening
    /// deposit
    pub position: Field,
    /// the report's mask when ok: a borrower leaf's index at touch (never
    /// 0), a lender leaf's 0
    pub mask: Field,
    /// the report's payout when ok (`market::payout`: amount and asset bit)
    pub payout: Field,
}

/// The app outputs of an owner round that pays or names its position's
/// kind under the non-secret-shared intakes with partial-note delivery,
/// after `ok` and the partial note: what the contract's `apply` completes
/// the request's note with, `[code, position, mask, 0, 0, payout, 0]`
/// (entry.nr's `Plain` entry outputs it), and the new leaf hashes the nodes
/// rebuild their tree from. The position's
/// collateral and debt stay out: the public
/// completion would publish them. Every field but the code and the leaf
/// hashes is 0 when not ok: the contract returns a failed round's escrow
/// itself (`ok` is public), so the payout never carries a refund.
pub struct OwnerNoteOutputs {
    /// 0 when ok, else the first failing check (market.nr)
    pub code: Field,
    /// the position's index (an opening's assigned one), 0 when not ok
    pub position: Field,
    /// the position's kind marker: a borrower leaf's index at touch, a
    /// lender leaf's 0; 0 when not ok
    pub mask: Field,
    /// what the note pays (`market::payout`), 0 when not ok
    pub payout: Field,
    /// the header's and the position's leaf hashes after the round
    pub new_hashes: [Field; OWNER_SLOTS],
}

/// An owner-bound step written under the non-secret-shared intakes (the
/// step's `change` in its public form, `Change::plain`).
pub fn owner_round(t: OwnerBook, s: Step<OWNER_SLOTS>) -> OwnerRound {
    OwnerRound::of(s.change(t).change.plain(), s)
}

impl OwnerRound {
    /// The owner round the step `s` leaves as `updated`. No constraint.
    pub fn of(updated: Updated<OWNER_SLOTS, LEAF_LEN>, s: Step<OWNER_SLOTS>) -> Self {
        OwnerRound {
            updated,
            outcome: s.outcome,
            position: s.report.position,
            mask: s.report.mask,
            payout: s.report.payout,
        }
    }

    /// The outputs under partial-note delivery for a round whose note pays
    /// or must name its position's kind (`OwnerNoteOutputs`). No constraint
    /// but the masks.
    pub fn note_outputs(self) -> OwnerNoteOutputs {
        let o = self.outcome;
        OwnerNoteOutputs {
            code: o.code,
            position: o.mask_field(self.position),
            mask: o.mask_field(self.mask),
            payout: o.mask_field(self.payout),
            new_hashes: self.updated.new_hashes,
        }
    }
}

/// The price as a nonzero u64: (price, true), else (0, false).
///
/// The price width: a u64 (with PRICE_SCALE 100,
/// prices up to about 1.8e17 borrowed units per collateral unit), which
/// keeps unhealthy_accrued's left product below 2^253 (with the 48-bit
/// index) and exact. A price
/// below 1 / PRICE_SCALE cannot be expressed; a deployment pricing a
/// cheap collateral against a dear token raises PRICE_SCALE (any value
/// keeping the product bound) or the token decimals do it. The example
/// takes u64 with PRICE_SCALE 100; a deployment sets the scale with its
/// oracle.
fn price_or(price: Field) -> (Field, bool) {
    let (p, in_range) = clamp_bits_or::<64>(price);
    (p, in_range & !is_zero(p))
}

/// A position index a round may name: nonzero and below 2^D.
fn named(p: Field) -> bool {
    fits_bits::<DEPTH>(p) & !is_zero(p)
}

/// The owner-bound slot of a round: the effective index, whether the
/// request's position is in range, whether it opens a full book, the
/// nodes' placement, the loaded state's check (code 4) and the append
/// index (code 17).
struct OwnerSlot {
    index: Field,
    opens: bool,
    in_range: bool,
    full: bool,
    /// the nodes' paths and indices are the request's (public data)
    nodes_ok: bool,
    state_ok: bool,
    /// an opening is at the header's append index (true when not opening)
    appends: bool,
    /// the header's append index after the round
    next_index: Field,
}

impl OwnerSlot {
    /// The placement on public data: in range, not a full book, the nodes'
    /// data the request's.
    fn placed(self) -> bool {
        self.in_range & !self.full & self.nodes_ok
    }

    /// Whether the round vouches for the leaf the request named (`Step::
    /// vouches`), given whether that leaf is of the round's kind: a request
    /// on an open position of its kind, in range, with the nodes' data and
    /// the loaded state sound (codes 3, 4 and 5 pass). Never an opening.
    fn vouches(self, of_kind: bool) -> bool {
        !self.opens & self.in_range & self.state_ok & of_kind
    }
}

/// `opening`: the round may name position 0 to open `new_leaf` (deposit,
/// supply). The nodes' data must be the request's: every path gives slot
/// 0's root, the placed indices are [0, index], and an opening slot is
/// empty (old hash 0, so its loaded leaf is the zero vector); an opening's
/// `new_leaf` must be the header's append index (pss_core `tree::append`),
/// which a placement check on the clear tree cannot give: the header holds
/// it shared and the circuit, not the scheduler, keeps the opened positions
/// a prefix of the book.
fn owner_slot(t: OwnerBook, position_in: Field, opening: bool, new_leaf: Field) -> OwnerSlot {
    let opens = opening & is_zero(position_in);
    let index = select_field(opens, new_leaf, position_in);
    // the request's own range, and the placed indices' (pss_core's
    // `in_range`: below 2^D, the header at 0 and the position not), which is
    // the only range check `$new_leaf`, scheduler-supplied, gets; a full
    // book's opening places its slot at 0 and is code 16 instead
    let request_in_range = if opening {
        fits_bits::<DEPTH>(position_in)
    } else {
        named(position_in)
    };
    let full = opens & is_zero(new_leaf);
    let in_range = request_in_range & (t.in_range | full);
    let h = header(t.leaves[0]);
    let p = position(t.leaves[1]);
    let nodes_ok = t.paths_ok
        & t.count_ok
        & t.indices_match([0, index])
        & (!opens | is_zero(t.old_hashes[1]));
    let (appends, next_index) = tree::append(h.next_index, opens, new_leaf);
    OwnerSlot {
        index,
        opens,
        in_range,
        full,
        nodes_ok,
        state_ok: nodes_ok & h.ok & p.ok,
        appends,
        next_index,
    }
}

/// `leaf` with `values` at its places 0 .. 3 kept where `keep[i]` (the
/// leaf's own value there) and its blinding `r`; the other places pass
/// through. No constraint but selects.
fn rewrite(leaf: Leaf, values: [Field; 4], keep: [bool; 4], r: Field) -> Leaf {
    let mut out = leaf;
    for i in 0..4 {
        out[i] = select_field(keep[i], leaf[i], values[i]);
    }
    out[LEAF_LEN - 1] = r;
    out
}

/// The header after a round: total_debt, liquidity and total_shares
/// replaced, the accrual's borrow index and last accrual `a`, the append
/// index `next_index` and the blinding `r`.
fn new_header(
    head: Leaf,
    a: Accrued,
    total_debt: Field,
    liquidity: Field,
    total_shares: Field,
    next_index: Field,
    r: Field,
) -> Leaf {
    let mut out = head;
    out[H_DEBT] = total_debt;
    out[H_LIQUIDITY] = liquidity;
    out[H_SHARES] = total_shares;
    out[H_BORROW_INDEX] = a.borrow_index;
    out[H_LAST_ACCRUAL] = a.last_accrual;
    out[H_NEXT_INDEX] = next_index;
    out[LEAF_LEN - 1] = r;
    out
}

/// The header decoded and accrued at the round's pinned `clock` (market.nr
/// `accrue`), first in every round.
fn accrued(head: Leaf, clock: Field) -> (Header, Accrued) {
    let h = header(head);
    (h, accrue(h, clock))
}

/// The header after a round that changes only the accrual (and the
/// blinding `r`): the accrued total_debt, the rest as loaded.
fn accrued_header(head: Leaf, a: Accrued, r: Field) -> Leaf {
    new_header(head, a, a.total_debt, head[H_LIQUIDITY], head[H_SHARES], head[H_NEXT_INDEX], r)
}

/// An owner-bound step: the header and the position written on ok,
/// reporting the position's index, its kind's marker in mask (a borrower
/// leaf's index_at_touch, a lender's 0), and `view` (`[x, y]`: a
/// borrower's collateral and debt, a lender's shares and their value) after
/// the round, with `payout`; when not ok, `refund`, and the position as it
/// stands (`held_view`, the loaded leaf `old`'s mask) when the round
/// vouches for it (`of_kind`: the leaf is of the round's kind).
fn owner_step(
    slot: OwnerSlot,
    of_kind: bool,
    old: Leaf,
    outcome: Outcome,
    new_leaves: [Leaf; OWNER_SLOTS],
    r_new: [Field; OWNER_SLOTS],
    view: [Field; 2],
    held_view: [Field; 2],
    payout: Field,
    refund: Field,
) -> Step<OWNER_SLOTS> {
    Step {
        outcome,
        placed: slot.placed(),
        writes: [true; OWNER_SLOTS],
        reblind: [true; OWNER_SLOTS],
        new_leaves,
        r_new,
        report: Report::owner(slot.index, new_leaves[1][3], view, payout),
        held: Report::owner(slot.index, old[3], held_view, 0),
        vouches: slot.vouches(of_kind),
        names_position: true,
        refund,
        notices: [false; OWNER_SLOTS],
    }
}

/// A borrower round's step: the view is the leaf's collateral and debt.
fn borrower_step(
    slot: OwnerSlot,
    p: Position,
    old: Leaf,
    outcome: Outcome,
    new_leaves: [Leaf; OWNER_SLOTS],
    r_new: [Field; OWNER_SLOTS],
    payout: Field,
    refund: Field,
) -> Step<OWNER_SLOTS> {
    owner_step(
        slot,
        p.borrower,
        old,
        outcome,
        new_leaves,
        r_new,
        [new_leaves[1][1], new_leaves[1][2]],
        [old[1], old[2]],
        payout,
        refund,
    )
}

/// deposit(position, amount): add collateral, total.
///
/// Codes, first failure wins: 1 amount not a u128, 2 amount zero,
/// 3 position not below 2^D, 16 an opening deposit (position 0) with the
/// book full ($new_leaf 0), 4 the loaded state or the nodes' data, 17 an
/// opening deposit whose $new_leaf is not the header's append index, 5 a
/// deposit into a position that is not a borrower's, 7 collateral
/// overflows u128 or the position's debt at the current index does. Every
/// round accrues the header first at the pinned `clock` (market.nr
/// `accrue`). On ok: an opening deposit writes a borrower leaf
/// `[KIND_BORROWER, amount, 0, B', ...]` (B' the accrued borrow index) and
/// advances the header's append index by one; a deposit into a position
/// brings it to the current index (its debt to debt_at, its index at touch
/// to B') and adds amount to its collateral; both leaves take fresh
/// blindings `r_new`. Reports the
/// position's index, its index_at_touch and its collateral and debt after
/// the round, payout 0; when not ok, returns the amount (the escrowed
/// collateral) in payout with the collateral asset's bit, and names the
/// position (as it stands) only when it was a borrower's already: a failed
/// opening names none. Anyone may open; a deposit into an open position is
/// one its owner's private function admitted.
///
/// Constraints: library entries only (to_u128_or and TotalArith's
/// u128 add_or and sub_or through market.nr, the accrual's and
/// debt_at's mul_div_wide_to_or, clamp_bits_or and fits_bits, eq,
/// is_zero, Outcome, selects; the intake's finisher adds
/// Tree::update). No assert of its own, no native arithmetic on an
/// input-driven value, no cast, no index by an input: nothing
/// input-falsifiable. This package adds no hint. Every output is a function
/// of the arguments.
pub fn deposit(
    t: OwnerBook,
    inputs: [Field; 2],
    new_leaf: Field,
    clock: Field,
    r_new: [Field; OWNER_SLOTS],
) -> Step<OWNER_SLOTS> {
    let (position_in, amount) = (inputs[0], inputs[1]);
    let slot = owner_slot(t, position_in, true, new_leaf);
    let (_, a) = accrued(t.leaves[0], clock);
    let p = position(t.leaves[1]);
    let (amt, amt_ok) = amount_or(amount);
    let (collateral, c_ok) = add_u128(p.collateral, amt);
    // the position brought to the current index; an opening's debt is 0
    // (an empty leaf's index at touch is 0, so debt_at refuses with 0)
    let (debt, d_ok) = debt_at(p.debt, p.index_at_touch, a.borrow_index);

    let outcome = Outcome::good()
        .require(amt_ok, CODE_AMOUNT_RANGE)
        .require(!is_zero(amount), CODE_ZERO_AMOUNT)
        .require(slot.in_range, CODE_POSITION_RANGE)
        .require(!slot.full, CODE_FULL_BOOK)
        .require(slot.state_ok, CODE_BAD_STATE)
        .require(slot.appends, CODE_APPEND_INDEX)
        .require(slot.opens | p.borrower, CODE_KIND)
        .require(c_ok & (slot.opens | d_ok), CODE_OVERFLOW);

    let head = t.leaves[0];
    let pos = t.leaves[1];
    borrower_step(
        slot,
        p,
        pos,
        outcome,
        [
            new_header(head, a, a.total_debt, head[H_LIQUIDITY], head[H_SHARES], slot.next_index, r_new[0]),
            rewrite(pos, [KIND_BORROWER, field(collateral), debt, a.borrow_index], [false; 4], r_new[1]),
        ],
        r_new,
        0,
        payout(field(amt), ASSET_COLLATERAL),
    )
}

/// borrow(position, amount) at price: add debt, take liquidity.
///
/// Codes, first failure wins: 1 amount not a u128, 2 amount zero,
/// 3 position 0 or not below 2^D, 4 the loaded state or the nodes' data,
/// 5 the position is not a borrower's, 6 price zero or not a u64, 7 the
/// debt at the current index plus amount overflows u128, 8 liquidity below
/// amount, 9 the position would be below the borrow limit (market.nr
/// `LTV_BPS`) with the new debt at price. On ok: the position is brought to
/// the current index, then its debt and the accrued total_debt (saturating:
/// an aggregate) grow by amount and liquidity falls by it; the payout is
/// amount in the borrowed asset, which the contract pays
/// to the owner when it redeems its note. Reports the position and its
/// collateral and new debt; when not ok after the position's own checks
/// (6 onwards), the position as it stands. Escrows nothing, so returns
/// nothing.
///
/// Constraints: as deposit, plus clamp_bits_or and is_zero on the price
/// and within_limit_at_price (two products and a Field lt) on the written
/// debt. Nothing input-falsifiable; no hint of its own; determined.
pub fn borrow(
    t: OwnerBook,
    inputs: [Field; 2],
    price: Field,
    clock: Field,
    r_new: [Field; OWNER_SLOTS],
) -> Step<OWNER_SLOTS> {
    let (position_in, amount) = (inputs[0], inputs[1]);
    let slot = owner_slot(t, position_in, false, 0);
    let (h, a) = accrued(t.leaves[0], clock);
    let p = position(t.leaves[1]);
    let (amt, amt_ok) = amount_or(amount);
    let (pr, price_ok) = price_or(price);
    let (owed, owed_ok) = debt_at(p.debt, p.index_at_touch, a.borrow_index);
    // both below 2^128: the sum fits 128 bits exactly when it is a u128
    let debt = owed + field(amt);
    let debt_ok = owed_ok & fits_bits::<128>(debt);
    let (liquidity, liq_ok) = sub_u128(h.liquidity, amt);
    let within = within_limit_at_price(field(p.collateral), debt, pr);

    let outcome = Outcome::good()
        .require(amt_ok, CODE_AMOUNT_RANGE)
        .require(!is_zero(amount), CODE_ZERO_AMOUNT)
        .require(slot.in_range, CODE_POSITION_RANGE)
        .require(slot.state_ok, CODE_BAD_STATE)
        .require(p.borrower, CODE_KIND)
        .require(price_ok, CODE_PRICE)
        .require(debt_ok, CODE_OVERFLOW)
        .require(liq_ok, CODE_LIQUIDITY)
        .require(within, CODE_LIMIT);

    let head = t.leaves[0];
    let pos = t.leaves[1];
    borrower_step(
        slot,
        p,
        pos,
        outcome,
        [
            new_header(
                head,
                a,
                add_sat(a.total_debt, field(amt)),
                field(liquidity),
                head[H_SHARES],
                head[H_NEXT_INDEX],
                r_new[0],
            ),
            rewrite(pos, [0, 0, debt, a.borrow_index], [true, true, false, false], r_new[1]),
        ],
        r_new,
        payout(field(amt), ASSET_BORROWED),
        0,
    )
}

/// withdraw(position, amount) at price: remove collateral, total.
///
/// Codes, first failure wins: 1 amount not a u128, 2 amount zero,
/// 3 position 0 or not below 2^D, 4 the loaded state or the nodes' data,
/// 5 the position is not a borrower's, 6 price zero or not a u64 while the
/// position has debt (a position without debt withdraws at any price),
/// 7 the debt at the current index overflows u128, 19 amount above the
/// collateral, 9 the position would be below the borrow limit (market.nr
/// `LTV_BPS`) with the collateral left, at price, on its debt at the
/// current index. On ok: the position is brought to the current index and
/// its collateral falls by amount (the header changes by the accrual
/// only); the payout is amount in the collateral asset, which
/// the contract pays to the owner when it redeems its note. Reports the
/// position and its new collateral and debt; when not ok after the
/// position's own checks, the position as it stands. Escrows nothing, so
/// returns nothing.
///
/// Constraints: as borrow. Nothing input-falsifiable; no hint of its own;
/// determined.
pub fn withdraw(
    t: OwnerBook,
    inputs: [Field; 2],
    price: Field,
    clock: Field,
    r_new: [Field; OWNER_SLOTS],
) -> Step<OWNER_SLOTS> {
    let (position_in, amount) = (inputs[0], inputs[1]);
    let slot = owner_slot(t, position_in, false, 0);
    let (_, a) = accrued(t.leaves[0], clock);
    let p = position(t.leaves[1]);
    let (amt, amt_ok) = amount_or(amount);
    let (pr, price_ok) = price_or(price);
    let (debt, debt_ok) = debt_at(p.debt, p.index_at_touch, a.borrow_index);
    let (collateral, c_ok) = sub_u128(p.collateral, amt);
    let within = within_limit_at_price(field(collateral), debt, pr);

    let outcome = Outcome::good()
        .require(amt_ok, CODE_AMOUNT_RANGE)
        .require(!is_zero(amount), CODE_ZERO_AMOUNT)
        .require(slot.in_range, CODE_POSITION_RANGE)
        .require(slot.state_ok, CODE_BAD_STATE)
        .require(p.borrower, CODE_KIND)
        .require(price_ok | is_zero(field(p.debt)), CODE_PRICE)
        .require(debt_ok, CODE_OVERFLOW)
        .require(c_ok, CODE_EXCEEDS_COLLATERAL)
        .require(within, CODE_LIMIT);

    let head = t.leaves[0];
    let pos = t.leaves[1];
    borrower_step(
        slot,
        p,
        pos,
        outcome,
        [
            accrued_header(head, a, r_new[0]),
            rewrite(pos, [0, field(collateral), debt, a.borrow_index], [true, false, false, false], r_new[1]),
        ],
        r_new,
        payout(field(amt), ASSET_COLLATERAL),
        0,
    )
}

/// repay(position, amount): reduce the debt at the current index by
/// min(amount, debt), return liquidity and the excess.
///
/// Codes, first failure wins: 1 amount not a u128, 2 amount zero,
/// 3 position 0 or not below 2^D, 4 the loaded state or the nodes' data,
/// 5 the position is not a borrower's, 7 the debt at the current index or
/// the liquidity overflows u128. On ok: the position is brought to the
/// current index, its debt falls by the repaid part, min(amount, debt), the
/// accrued total_debt by it too (saturating at 0: an aggregate) and
/// liquidity grows by it; the amount,
/// escrowed at request, stays in the contract but for the excess over the
/// debt, which the payout returns in the borrowed asset. So "repay
/// everything" works without knowing the debt to the unit, and a repayment
/// queued behind a liquidation that already reduced the debt still
/// applies. Reports the position and its collateral and new debt; when not
/// ok, returns the amount in payout (the borrowed asset).
///
/// Constraints: as deposit, plus selects and a 128-bit range. Nothing
/// input-falsifiable; determined.
pub fn repay(t: OwnerBook, inputs: [Field; 2], clock: Field, r_new: [Field; OWNER_SLOTS]) -> Step<OWNER_SLOTS> {
    let (position_in, amount) = (inputs[0], inputs[1]);
    let slot = owner_slot(t, position_in, false, 0);
    let (h, a) = accrued(t.leaves[0], clock);
    let p = position(t.leaves[1]);
    let (amt, amt_ok) = amount_or(amount);
    let (owed, owed_ok) = debt_at(p.debt, p.index_at_touch, a.borrow_index);
    // repaid = min(amount, debt'): both below 2^128, so debt' - amount fits
    // 128 bits exactly when amount <= debt'
    let within_debt = fits_bits::<128>(owed - field(amt));
    let repaid = select_field(within_debt, field(amt), owed);
    let excess = field(amt) - repaid;
    // exact: repaid <= debt'
    let debt = owed - repaid;
    let total_debt = sub_sat(a.total_debt, repaid);
    let liquidity = field(h.liquidity) + repaid;

    let outcome = Outcome::good()
        .require(amt_ok, CODE_AMOUNT_RANGE)
        .require(!is_zero(amount), CODE_ZERO_AMOUNT)
        .require(slot.in_range, CODE_POSITION_RANGE)
        .require(slot.state_ok, CODE_BAD_STATE)
        .require(p.borrower, CODE_KIND)
        .require(owed_ok & fits_bits::<128>(liquidity), CODE_OVERFLOW);

    let head = t.leaves[0];
    let pos = t.leaves[1];
    borrower_step(
        slot,
        p,
        pos,
        outcome,
        [
            new_header(head, a, total_debt, liquidity, head[H_SHARES], head[H_NEXT_INDEX], r_new[0]),
            rewrite(pos, [0, 0, debt, a.borrow_index], [true, true, false, false], r_new[1]),
        ],
        r_new,
        payout(excess, ASSET_BORROWED),
        payout(field(amt), ASSET_BORROWED),
    )
}

/// The value of a lender's `shares` against header `h` after a round that
/// leaves the pool at `pool` and `total_shares` outstanding, 0 when it
/// cannot be computed (no shares outstanding): for a report, never a flag.
fn report_value(shares: Field, pool: Field, total_shares: Field) -> Field {
    let (v, _) = value_of(shares, pool, total_shares);
    v
}

/// supply(position, amount): a lender adds `amount` of the borrowed asset
/// to the pool for shares of it, total.
///
///   shares = amount                                             when total_shares = 0
///   shares = floor(amount * total_shares / (liquidity + total_debt))   otherwise
///
/// on the header accrued at the pinned `clock` (total_debt the accrued one),
/// rounding toward zero, in the pool's favour (examples/lending-tip/README.md,
/// "Interest", "Supply and withdrawal of supply"). Position 0 opens a new
/// lender position at `$new_leaf` (as an opening deposit does); another
/// position must be a lender's.
///
/// Codes, first failure wins: 1 amount not a u128, 2 amount zero,
/// 3 position not below 2^D, 16 an opening with the book full, 4 the loaded
/// state or the nodes' data, 17 an opening whose $new_leaf is not the
/// header's append index, 5 a supply into a position that is not a
/// lender's, 7 the shares' multiply-divide refuses (the pool's value not a
/// u128, or zero with shares outstanding) or liquidity, total_shares or the
/// leaf's shares overflow u128, 20 the shares round to zero. On ok:
/// liquidity grows by amount, total_shares and the leaf's shares by shares;
/// an opening writes `[KIND_LENDER, shares, 0, ...]` and advances the
/// append index. Reports the position, mask 0 (the lender kind's marker),
/// its shares and their value after the round, payout 0; when not ok,
/// returns the amount (escrowed in the borrowed asset) in payout, and names
/// the position (as it stands) only when it was a lender's already.
///
/// Constraints: as deposit, plus two mul_div_wide (the shares and the
/// reported value) and selects. Nothing input-falsifiable; no hint of its
/// own; determined.
pub fn supply(
    t: OwnerBook,
    inputs: [Field; 2],
    new_leaf: Field,
    clock: Field,
    r_new: [Field; OWNER_SLOTS],
) -> Step<OWNER_SLOTS> {
    let (position_in, amount) = (inputs[0], inputs[1]);
    let slot = owner_slot(t, position_in, true, new_leaf);
    let (h, a) = accrued(t.leaves[0], clock);
    let p = position(t.leaves[1]);
    let (amt, amt_ok) = amount_or(amount);
    // the pool's value after the accrual
    let pool = field(h.liquidity) + a.total_debt;
    let total = field(h.total_shares);
    let first = is_zero(total);
    let (quotient, q_ok) = mul_div_wide(field(amt), total, pool);
    let minted = select_field(first, field(amt), quotient);
    let minted_ok = first | q_ok;
    let liquidity = field(h.liquidity) + field(amt);
    let total_after = total + minted;
    let shares_after = field(p.collateral) + minted;
    let fits = fits_bits::<128>(liquidity)
        & fits_bits::<128>(total_after)
        & fits_bits::<128>(shares_after);

    let outcome = Outcome::good()
        .require(amt_ok, CODE_AMOUNT_RANGE)
        .require(!is_zero(amount), CODE_ZERO_AMOUNT)
        .require(slot.in_range, CODE_POSITION_RANGE)
        .require(!slot.full, CODE_FULL_BOOK)
        .require(slot.state_ok, CODE_BAD_STATE)
        .require(slot.appends, CODE_APPEND_INDEX)
        .require(slot.opens | p.lender, CODE_KIND)
        .require(minted_ok & fits, CODE_OVERFLOW)
        .require(!is_zero(minted), CODE_ZERO_QUOTIENT);

    // the shares and their value as they stand after the round: the new
    // ones when it applies, the leaf's when it does not (the held view)
    let ok = outcome.ok;
    let pool_after = pool + field(amt);
    let shown = select_field(ok, shares_after, field(p.collateral));
    let value = report_value(
        shown,
        select_field(ok, pool_after, pool),
        select_field(ok, total_after, total),
    );
    let head = t.leaves[0];
    let pos = t.leaves[1];
    owner_step(
        slot,
        p.lender,
        pos,
        outcome,
        [
            new_header(head, a, a.total_debt, liquidity, total_after, slot.next_index, r_new[0]),
            rewrite(pos, [KIND_LENDER, shares_after, 0, 0], [false; 4], r_new[1]),
        ],
        r_new,
        [shown, value],
        [shown, value],
        0,
        payout(field(amt), ASSET_BORROWED),
    )
}

/// withdraw_supply(position, shares): a lender burns `shares` for their
/// value, total.
///
///   value = floor(shares * (liquidity + total_debt) / total_shares)
///
/// on the header accrued at the pinned `clock`, so the value carries the
/// interest accrued since the supply (the exchange-rate supply index),
/// rounding toward zero, in the pool's favour, paid if the liquidity
/// covers it (the lender waits for repayments otherwise).
///
/// Codes, first failure wins: 1 shares not a u128, 2 shares zero,
/// 3 position 0 or not below 2^D, 4 the loaded state or the nodes' data,
/// 5 the position is not a lender's, 18 shares above the leaf's, 7 the
/// value's multiply-divide refuses (no shares outstanding, the pool's value
/// not a u128), 20 the value rounds to zero, 8 the value above the
/// liquidity. On ok: the leaf's shares and total_shares (saturating) fall
/// by shares, liquidity by the value; the payout is the value in the
/// borrowed asset. Reports the position, mask 0, the shares left and their
/// value after the round; when not ok after the position's own checks, the
/// position as it stands. A lender's leaf changes only by its owner's
/// rounds, so the note's shares are exact: two withdrawals from one note
/// land in queue order and the second fails on the leaf (18). Escrows
/// nothing, so returns nothing.
///
/// Constraints: as supply. Nothing input-falsifiable; no hint of its own;
/// determined.
pub fn withdraw_supply(
    t: OwnerBook,
    inputs: [Field; 2],
    clock: Field,
    r_new: [Field; OWNER_SLOTS],
) -> Step<OWNER_SLOTS> {
    let (position_in, shares) = (inputs[0], inputs[1]);
    let slot = owner_slot(t, position_in, false, 0);
    let (h, a) = accrued(t.leaves[0], clock);
    let p = position(t.leaves[1]);
    let (sh, sh_ok) = amount_or(shares);
    let (left, enough) = sub_u128(p.collateral, sh);
    // the pool's value after the accrual: the shares earn the interest
    let pool = field(h.liquidity) + a.total_debt;
    let total = field(h.total_shares);
    let (value, v_ok) = value_of(field(sh), pool, total);
    // value and liquidity below 2^135 and 2^128: liquidity - value fits 128
    // bits exactly when value <= liquidity
    let covered = fits_bits::<128>(field(h.liquidity) - value);

    let outcome = Outcome::good()
        .require(sh_ok, CODE_AMOUNT_RANGE)
        .require(!is_zero(shares), CODE_ZERO_AMOUNT)
        .require(slot.in_range, CODE_POSITION_RANGE)
        .require(slot.state_ok, CODE_BAD_STATE)
        .require(p.lender, CODE_KIND)
        .require(enough, CODE_EXCEEDS_SHARES)
        .require(v_ok, CODE_OVERFLOW)
        .require(!is_zero(value), CODE_ZERO_QUOTIENT)
        .require(covered, CODE_LIQUIDITY);

    let ok = outcome.ok;
    let liquidity = field(h.liquidity) - value;
    let total_after = sub_sat(field(h.total_shares), field(sh));
    let shown = select_field(ok, field(left), field(p.collateral));
    let shown_value = report_value(
        shown,
        select_field(ok, pool - value, pool),
        select_field(ok, total_after, total),
    );
    let head = t.leaves[0];
    let pos = t.leaves[1];
    owner_step(
        slot,
        p.lender,
        pos,
        outcome,
        [
            new_header(head, a, a.total_debt, liquidity, total_after, head[H_NEXT_INDEX], r_new[0]),
            rewrite(pos, [0, field(left), 0, 0], [true, false, true, true], r_new[1]),
        ],
        r_new,
        [shown, shown_value],
        [shown, shown_value],
        payout(value, ASSET_BORROWED),
        0,
    )
}

/// view(position): report the position to its owner, total. The rounds'
/// one owner request that moves no value: under a secret-shared
/// intake nobody holds a position in the clear, so an owner learns its
/// position after a price move or a liquidation (which leaves its latest
/// note stale) only by a round of its own; view is that round when it has
/// nothing else to do. It reads either kind: a borrower's collateral and
/// debt at the current index (mask the accrued borrow index), a lender's
/// shares and their value at the pool's value after the accrual (mask 0).
///
/// Codes, first failure wins: 3 position 0 or not below 2^D, 4 the loaded
/// state or the nodes' data, 5 the position is empty, 7 a borrower's debt at
/// the current index overflows u128. Writes the accrued header and, as
/// every owner round touching a borrower position does, the position
/// brought to the current index (its debt to debt_at, its index at touch to
/// B'; its collateral unchanged), so the owner's note equals its leaf; a
/// lender's leaf changes its blinding only. Reports the position, payout
/// 0.
///
/// Constraints: as deposit, without the amounts, plus one mul_div_wide (a
/// lender's value). Nothing input-falsifiable; determined.
pub fn view(t: OwnerBook, inputs: [Field; 1], clock: Field, r_new: [Field; OWNER_SLOTS]) -> Step<OWNER_SLOTS> {
    let position_in = inputs[0];
    let slot = owner_slot(t, position_in, false, 0);
    let (h, a) = accrued(t.leaves[0], clock);
    let p = position(t.leaves[1]);
    let (debt, debt_ok) = debt_at(p.debt, p.index_at_touch, a.borrow_index);

    let outcome = Outcome::good()
        .require(slot.in_range, CODE_POSITION_RANGE)
        .require(slot.state_ok, CODE_BAD_STATE)
        .require(p.opened, CODE_KIND)
        .require(!p.borrower | debt_ok, CODE_OVERFLOW);

    let head = t.leaves[0];
    let pos = t.leaves[1];
    let value = report_value(field(p.collateral), field(h.liquidity) + a.total_debt, field(h.total_shares));
    // a borrower's leaf brought to the current index; any other kept
    let touched = rewrite(pos, [0, 0, debt, a.borrow_index], [true, true, !p.borrower, !p.borrower], r_new[1]);
    owner_step(
        slot,
        p.opened,
        pos,
        outcome,
        [accrued_header(head, a, r_new[0]), touched],
        r_new,
        [pos[1], select_field(p.lender, value, debt)],
        [pos[1], select_field(p.lender, value, pos[2])],
        0,
        0,
    )
}

/// quote_rates() by anyone, the quote round: the market's rates, total. It
/// reads the header only, accrues it at the pinned `clock` and reports, in
/// the outcome's `[position, mask, x, y, payout, aux]`, `[0,
/// borrow_index, 0, supply_index, 0, utilisation]` after the accrual:
///
///   supply_index = floor((liquidity + total_debt) * INDEX_ONE / total_shares)   (INDEX_ONE with no shares)
///   utilisation  = floor(total_debt * BPS / (liquidity + total_debt))           (0 with an empty pool)
///
/// position 0, so the quoter's note confers no position, and x and payout
/// 0, the fields a note naming no position is paid (the rates in mask, y
/// and aux pay nothing). A prospective lender learns the share price
/// and the utilisation for a usage deposit and a queue turn; no per-round
/// rate is public, so the round type stays hidden
/// (examples/lending-tip/README.md, "Choices and limits", "The quote round").
///
/// Codes: 4 the nodes' data (the header's slot) or the header not well
/// formed. Writes the accrued header, so its result looks like every other
/// round's.
///
/// Constraints: the header's decode and accrual, two mul_div_wide, two
/// is_zero and selects. Nothing input-falsifiable; no hint of its own;
/// determined.
pub fn quote_rates(t: ScanBook, clock: Field, r_new: [Field; SCAN_SLOTS]) -> Step<SCAN_SLOTS> {
    let head = t.leaves[0];
    let (h, a) = accrued(head, clock);
    let nodes_ok = t.paths_ok & t.indices_match([0]);
    let pool = field(h.liquidity) + a.total_debt;
    let (index, _) = mul_div_wide(pool, INDEX_ONE, field(h.total_shares));
    let supply_index = select_field(is_zero(field(h.total_shares)), INDEX_ONE, index);
    let (utilisation, _) = mul_div_wide(a.total_debt, BPS, pool);

    let outcome = Outcome::good().require(nodes_ok & h.ok, CODE_BAD_STATE);
    Step {
        outcome,
        placed: nodes_ok,
        writes: [true],
        reblind: [true],
        new_leaves: [accrued_header(head, a, r_new[0])],
        r_new,
        report: Report::header(a.borrow_index, supply_index, utilisation),
        held: Report::none(),
        vouches: false,
        names_position: false,
        refund: 0,
        notices: [false; SCAN_SLOTS],
    }
}

/// The liquidation's write policy (`Step::reblind`): the header re-blinded
/// on every outcome, each probe written only when liquidated. A probe the
/// round finds healthy, without debt or past the budget keeps its leaf and
/// its leaf hash, so its owner's latest note keeps its unspent exit tag
/// (the escape hatch's exit) and nobody can strand an owner by naming its
/// position in a liquidation. One node, which sees the probe's index,
/// learns from the unchanged hash that the probe was not liquidated (its
/// health bit at the pinned price, which the liquidator's mask and the
/// keeper's scan already carry); the world sees a round like every other,
/// whose exit-tag output is a filler.
fn probe_policy() -> [bool; PROBES] {
    let mut policy = [false; PROBES];
    policy[0] = true;
    policy
}

/// The liquidation's notices (`Step::notices`): every probe, none for the
/// header. A probe the round liquidates has its owner's delivery handle
/// completed with the position after the liquidation, so the owner learns
/// of it privately, without a round of its own.
fn probe_notices() -> [bool; PROBES] {
    let mut notices = [true; PROBES];
    notices[0] = false;
    notices
}

/// liquidate(p_1, ..., p_{K-1}, count, budget) by anyone at price: the
/// liquidation (examples/lending-tip/README.md, "Rules and constants", "The
/// liquidation") over each of the first `count` probes, in probe order, paid
/// out of the liquidator's `budget` (the most it repays, escrowed in the
/// borrowed asset at request), total.
///
///   unhealthy = collateral * price * LT_BPS * index_at_touch < debt * B' * PRICE_SCALE * BPS
///   debt'     = ceil(debt * B' / index_at_touch)    the debt at the current index
///   close     = floor(debt' * CLOSE_BPS / BPS)
///   repay     = min(close, remaining)               remaining starts at budget
///   want      = floor(repay * PRICE_SCALE * (BPS + BONUS_BPS) / (price * BPS))
///   seize     = want < collateral ? want : collateral
///   remaining = remaining - repay                   for a liquidated probe
///   written   = want < collateral ? 0 : debt' - repay   the write-off
///   debt''    = debt' - repay - written             the probe's debt after
///   total     = sub_sat(total, repay + written)     for a liquidated probe,
///                                                   total starting at total_debt'
///
/// on the header accrued at the pinned `clock` (B' the accrued borrow index;
/// the health test needs no division, market.nr `unhealthy_accrued`, so a
/// position becomes liquidatable by interest alone, with no round touching
/// it). A used probe is liquidated when it is unhealthy at the price and its
/// repay is not zero; otherwise it is skipped (healthy or without debt,
/// the per-probe code 11; repay rounding to zero or the budget spent, 12)
/// and its mask bit is 0. A lender leaf decodes as a position without debt,
/// so it is never liquidated and needs no kind check. A request that
/// liquidates nothing is ok with mask 0 and writes the accrued header
/// alone.
/// The seize scales with the repay, so a probe the budget covers in part
/// gives up its collateral in the same proportion.
///
/// Bad debt is written off in the liquidation that leaves it: when the
/// seize takes a liquidated probe's whole collateral (want at or above it,
/// a collateral of 0 included), the probe keeps no debt, and total_debt
/// loses its whole debt' (the repay and the residual) instead of the repay
/// alone. The supply index, (liquidity + total_debt) * INDEX_ONE /
/// total_shares, is formed from the header each round writes, so every
/// later round values a share on the reduced total: the loss falls on the
/// lenders pro rata, not on whoever withdraws last. The residual is in the
/// header's units (debt' is at the accrued index B', as total_debt is) and
/// rounded up as debt' is, so it is never below the exact accrued residual:
/// it errs toward a lower supply index, the pool's side. At CLOSE_BPS below BPS a liquidated probe always leaves
/// a residual (repay is at most half of debt'). A probe whose repay rounds to
/// zero (debt' 1) is skipped and keeps its debt: dust.
///
/// Request-level codes (ok = false), first failure wins: 1 budget not a
/// u128, 2 budget zero, 3 count outside 1 .. K - 1 or a used position 0 or
/// not below 2^D, 15 a used position named twice (K > 2), 4 the loaded
/// state (a used probe or the header not u128s) or the nodes' data, 6
/// price zero or not a u64, 7 a multiply-divide refused (defensive, below)
/// or liquidity + the total repay overflows u128. On ok: each liquidated
/// position's collateral falls by its seize and its debt by its repay (to 0
/// when the seize empties it), total_debt by the total repay and the
/// written-off residuals (saturating at 0: an aggregate), liquidity grows by
/// the total repay; each liquidated position is brought to the
/// current index first (its index at touch B'); the outcome reports the mask, the total seize
/// (x, paid in the collateral asset) and the total repay (y), and pays back
/// the unused budget (payout, the borrowed asset). When not ok the whole
/// budget is returned (payout). The outcome names no position (position 0),
/// so the liquidator's note confers nothing. Each liquidated position's
/// owner is notified (`Step::notices`): the handle its leaf holds is
/// completed with the position after the liquidation, an owner note of the
/// position that pays nothing and whose exit tag the written leaf holds,
/// and the leaf keeps the handle, so a later liquidation notifies the owner
/// again.
///
/// The subtractions are exact Field arithmetic: repay <= debt' (at most
/// half of it), seize <= collateral (the select), repay <= remaining (the
/// min); total_debt's are saturating, one per probe, each of a u128 (debt'
/// or repay) from a u128, so no sum of probes' debts needs a width of its
/// own; on ok = false nothing is written.
///
/// The multiply-divides' flags: every used unhealthy probe's
/// three flags join ok under code 7. debt_at's fails only on a debt past
/// u128 at the current index (code 7, as in the owner rounds); once codes 4
/// and 6 pass the others are always true: debt' is a u128, so close is
/// below 2^127; the divisors BPS and
/// price * BPS are nonzero and below 2^78; want is below 2^134, inside
/// WIDE_QUOTIENT_BITS. They are kept so that a later change to the
/// constants or the price width that broke this bound would fail the
/// request, never apply a liquidation with a zeroed seize or repay. The
/// min compares two values below 2^128 by the 128-bit range of their
/// difference.
///
/// Constraints: tree::load and Tree::update at K slots, the header's
/// accrual, the budget's amount_or, per probe the position's decode,
/// unhealthy_accrued, three mul_div_wide, a Field lt, two 128-bit ranges
/// (the min and total_debt's saturation) and selects, fits_bits per
/// position (the count, the used slots and
/// distinctness are the book's flags). Nothing input-falsifiable; no hint
/// of its own; determined.
pub fn liquidate(
    t: ProbeBook,
    inputs: [Field; PROBES + 1],
    price: Field,
    clock: Field,
    r_new: [Field; PROBES],
) -> Step<PROBES> {
    let count = inputs[PROBES - 1];
    let budget = inputs[PROBES];
    let (h, a) = accrued(t.leaves[0], clock);
    let (pr, price_ok) = price_or(price);
    let (budget_u, budget_ok) = amount_or(budget);

    // the used probes are the book's (`load` with 1 + count slots used):
    // slot k (1 .. K - 1) when k <= count, none when the count is out of
    // range; the request must use at least one, and its positions are named
    // (nonzero, below 2^D) on the raw inputs and distinct (the book's flag
    // on the placed indices, which `indices_match` makes the inputs)
    let used = t.used;
    let count_ok = t.count_ok & !is_zero(count);
    let mut expected = [0; PROBES];
    let mut in_range = count_ok & t.in_range;
    for k in 1..PROBES {
        expected[k] = inputs[k - 1];
        in_range = in_range & (!used[k] | named(inputs[k - 1]));
    }
    let distinct = t.distinct;

    let nodes_ok = t.paths_ok & t.indices_match(expected);
    let mut state_ok = h.ok & nodes_ok;
    let mut muldiv_ok = true;
    let mut seize_total: Field = 0;
    let mut repay_total: Field = 0;
    // the accrued total_debt, falling by each liquidated probe's repay and,
    // for a probe the seize empties, its written-off residual: one
    // saturating subtraction per probe, each of a u128 from a u128
    let mut total_debt = a.total_debt;
    // a u128 (the budget's clamp, 0 when the budget is not one), falling by
    // each liquidated probe's repay, which is at most it
    let mut remaining = field(budget_u);
    let mut mask: Field = 0;
    let mut writes = [false; PROBES];
    let mut new_leaves = [[0; LEAF_LEN]; PROBES];
    let mut bit: Field = 1;
    for k in 1..PROBES {
        let p = position(t.leaves[k]);
        state_ok = state_ok & (!used[k] | p.ok);
        let collateral = field(p.collateral);

        // health on the accrued debt, without dividing; the debt at the
        // current index only for the probe it liquidates (it writes it)
        let unhealthy = unhealthy_accrued(collateral, field(p.debt), p.index_at_touch, a.borrow_index, pr);
        let (debt, debt_ok) = debt_at(p.debt, p.index_at_touch, a.borrow_index);
        let (close, close_ok) = mul_div_wide(debt, CLOSE_BPS, BPS);
        // close and remaining are below 2^128: remaining - close fits 128
        // bits exactly when close <= remaining
        let covered = fits_bits::<128>(remaining - close);
        let repay = select_field(covered, close, remaining);
        let (want, want_ok) = mul_div_wide(repay, PRICE_SCALE * (BPS + BONUS_BPS), pr * BPS);
        // the seize leaves collateral exactly when want is below it
        let keeps = lt(want, collateral);
        let seize = select_field(keeps, want, collateral);
        muldiv_ok = muldiv_ok & (!(used[k] & unhealthy) | (debt_ok & close_ok & want_ok));
        let liquidated = used[k] & unhealthy & !is_zero(repay);
        // the write-off: a probe the seize empties keeps no debt, and
        // total_debt loses its whole debt' (the repay and the residual
        // debt' - repay) where it would lose the repay alone
        let emptied = liquidated & !keeps;
        let cleared = select_field(emptied, debt, repay);

        writes[k] = liquidated;
        seize_total += select_field(liquidated, seize, 0);
        repay_total += select_field(liquidated, repay, 0);
        total_debt = sub_sat(total_debt, select_field(liquidated, cleared, 0));
        remaining -= select_field(liquidated, repay, 0);
        mask += select_field(liquidated, bit, 0);
        bit *= 2;
        new_leaves[k] = rewrite(
            t.leaves[k],
            [0, collateral - seize, select_field(emptied, 0, debt - repay), a.borrow_index],
            [true, false, false, false],
            r_new[k],
        );
    }
    let liquidity = field(h.liquidity) + repay_total;

    let outcome = Outcome::good()
        .require(budget_ok, CODE_AMOUNT_RANGE)
        .require(!is_zero(budget), CODE_ZERO_AMOUNT)
        .require(in_range, CODE_POSITION_RANGE)
        .require(distinct, CODE_DUPLICATE)
        .require(state_ok, CODE_BAD_STATE)
        .require(price_ok, CODE_PRICE)
        .require(muldiv_ok, CODE_OVERFLOW)
        .require(fits_bits::<128>(liquidity), CODE_OVERFLOW);

    let head = t.leaves[0];
    // the header always: every applying round writes its accrual
    writes[0] = true;
    new_leaves[0] = new_header(
        head,
        a,
        total_debt,
        liquidity,
        head[H_SHARES],
        head[H_NEXT_INDEX],
        r_new[0],
    );
    Step {
        outcome,
        placed: in_range & distinct & nodes_ok,
        writes,
        reblind: probe_policy(),
        new_leaves,
        r_new,
        report: Report::liquidation(mask, seize_total, repay_total, payout(remaining, ASSET_BORROWED)),
        held: Report::none(),
        vouches: false,
        names_position: false,
        refund: payout(field(budget_u), ASSET_BORROWED),
        notices: probe_notices(),
    }
}

/// scan(start) by anyone at price: the keeper round
/// (examples/lending-tip/README.md, "Keeper round"), total. It reads
/// the window of WINDOW positions `start .. start + W - 1` (`Window`, bound
/// to the book's root through its old hashes and the window root's
/// siblings) and reports, for each, whether it is unhealthy at the price
/// on its debt at the borrow index B' the round accrues at the pinned
/// `clock` (market.nr `unhealthy_accrued`: no division per position, so the
/// bits are never stale by interest), and how many of them are occupied. It liquidates nothing: the liquidate
/// round does, at the indices the report names.
///
///   bit j of report = unhealthy_accrued(collateral, debt, index_at_touch, B', price) of leaf start + j
///   occupied        = the window's leaves that are open, of either kind
///
/// An empty leaf and a lender's have debt 0 and are never unhealthy; index
/// 0 (the header, in window 0) counts for neither. The report is `[0, report, 0, start, 0,
/// occupied]` in the outcome's `[position, mask, x, y, payout, aux]`:
/// position 0, so the keeper's note confers no position, and x and payout
/// 0, the fields a note naming no position is paid (the counts in y and
/// aux pay nothing). Positions are
/// appended and never reclaimed, so the keeper stops a pass at the first
/// window that is not full: fewer than W occupied leaves, or fewer than
/// W - 1 in window 0, whose header is never counted.
///
/// Codes, first failure wins: 3 start not below 2^D or not a multiple of W,
/// 4 the nodes' data (the header's slot, or a window that does not give its
/// root), the header not well formed, or a window leaf's collateral or debt
/// not a u128 or its index at touch not below 2^48 (a leaf the rounds wrote
/// always passes), 6 price zero or not a u64. It writes the accrued header
/// and no position, so the new commitment hides the round type like every
/// other round's.
///
/// Constraints: the window's (pss_core `Tree::window`), the header's decode
/// and accrual, per window leaf the position's decode, unhealthy_accrued
/// and is_zero, the price's clamp; selects and additions. Nothing input-falsifiable; no hint of its own; determined.
pub fn scan(
    t: ScanBook,
    w: Window<WINDOW, LEAF_LEN>,
    price: Field,
    clock: Field,
    r_new: [Field; SCAN_SLOTS],
) -> Step<SCAN_SLOTS> {
    let head = t.leaves[0];
    let (h, a) = accrued(head, clock);
    let (pr, price_ok) = price_or(price);
    let nodes_ok = t.paths_ok & t.indices_match([0]) & w.root_ok;
    let mut state_ok = nodes_ok & h.ok;
    let mut report: Field = 0;
    let mut occupied: Field = 0;
    let mut bit: Field = 1;
    for j in 0..WINDOW {
        let p = position(w.leaves[j]);
        state_ok = state_ok & p.ok;
        // index 0 is the header: only window 0 holds it, at j = 0
        let counts = if j == 0 { !is_zero(w.start) } else { true };
        let unhealthy = counts
            & unhealthy_accrued(field(p.collateral), field(p.debt), p.index_at_touch, a.borrow_index, pr);
        report += select_field(unhealthy, bit, 0);
        occupied += select_field(counts & p.opened, 1, 0);
        bit *= 2;
    }

    let outcome = Outcome::good()
        .require(w.aligned, CODE_POSITION_RANGE)
        .require(state_ok, CODE_BAD_STATE)
        .require(price_ok, CODE_PRICE);
    Step {
        outcome,
        placed: w.aligned & nodes_ok,
        writes: [true],
        reblind: [true],
        new_leaves: [accrued_header(head, a, r_new[0])],
        r_new,
        report: Report::header(report, w.start, occupied),
        held: Report::none(),
        vouches: false,
        names_position: false,
        refund: 0,
        notices: [false; SCAN_SLOTS],
    }
}

/// The book an init round creates at `key`: the empty tree with the header
/// [0, liquidity, liquidity, INDEX_ONE, 0, 1, 0, r_new] at leaf 0: no debt,
/// the seeded liquidity and as many shares, protocol-owned and never
/// withdrawable (a buffer that earns its part of the pool's value; a
/// deployment that seeds none starts with no shares), the borrow index at
/// INDEX_ONE, no accrual yet, its append index 1 (the first position). Its
/// old_c is 0 (the empty slot).
pub fn empty_book(namespace: Field, key: Field, liquidity: Field, r_new: Field) -> Updated<1, LEAF_LEN> {
    empty_book_oblivious(namespace, key, liquidity, r_new).updated
}

/// `empty_book` as the oblivious deployment's init leaves it, with the
/// header's path nodes (pss_core `tree::Oblivious`, no public leaf hash
/// but the zero in its place).
pub fn empty_book_oblivious(
    namespace: Field,
    key: Field,
    liquidity: Field,
    r_new: Field,
) -> Oblivious<1, LEAF_LEN, DEPTH, 1> {
    let t: Tree<1, DEPTH, LEAF_LEN> = tree::empty(namespace, key, [0], 1).headed();
    let (updated, paths) = t.update_paths(true, [true], [[0, liquidity, liquidity, INDEX_ONE, 0, 1, 0, r_new]]);
    Oblivious { updated, paths }
}

mod tests {
    use crate::market::{
        ASSET_BIT, CODE_AMOUNT_RANGE, CODE_APPEND_INDEX, CODE_BAD_STATE, CODE_EXCEEDS_COLLATERAL,
        CODE_EXCEEDS_SHARES, CODE_FULL_BOOK, CODE_KIND, CODE_LIMIT, CODE_LIQUIDITY, CODE_OVERFLOW,
        CODE_POSITION_RANGE, CODE_PRICE, CODE_ZERO_AMOUNT, CODE_ZERO_QUOTIENT, DEPTH, INDEX_MAX,
        INDEX_ONE, Leaf, LEAF_LEN, OWNER_SLOTS, PROBES, SCAN_SLOTS, WINDOW, WINDOW_HEIGHT,
        WINDOW_SIBLINGS,
    };
    use pss_core::tip::tree;
    use super::{
        book, borrow, deposit, empty_book, liquidate, owner_round, OwnerBook, OwnerRound, ProbeBook,
        quote_rates, repay, Report, scan, ScanBook, Step, supply, view, withdraw, withdraw_supply,
    };
    use pss_core::tip::tree::Updated;
    use total::ctl::Outcome;
    use crate::market::{CODE_INPUTS_MISMATCH, P_EXIT_TAG, P_HANDLE};
    use crate::entry::{Pinned, Prefix};
    use crate::shared::{AppendIndex, EXIT_TAGS, finish, Handle, ObliviousRound, OUTCOME_SLOT, Shared, SharedRound};
    use pss_core::tip::outputs::{Finished, Written};
    use pss_core::tip::exit::{exit_filler, exit_tag};
    use pss_core::tip::handle::{filler, filler_seed, handle_tag};
    use pss_core::tip::intake::{commit, shared, SharedIntake};
    use pss_core::tip::outcome::{completed_note_hash, encrypt, encrypt_mismatch, encrypt_outcome, partial_commitment};
    use pss_core::tip::tree::{Access, Tree};

    // The fixture scenario (gen-fixtures.py writes the same numbers into
    // every Prover*.toml): namespace 0xc0ffee, market key 0xa003, a market
    // seeded with 1,000,000 liquidity and as many protocol-owned shares;
    // Alice opens position 1, Bob position 2. A leaf's first element is its
    // kind; the book records no owner.
    global NS: Field = 0xc0ffee;
    global KEY: Field = 0xa003;
    global OPEN: Field = 1;
    global LENDER: Field = 2;
    global ONE: Field = INDEX_ONE;
    global LIQ: Field = 1000000;
    global R: [Field; 3] = [21, 22, 23];
    global TWO_POW_127: Field = 0x80000000000000000000000000000000;
    global TWO_POW_128: Field = 0x100000000000000000000000000000000;
    global U128_MAX: Field = 0xffffffffffffffffffffffffffffffff;
    global TWO_POW_64: Field = 0x10000000000000000;
    global P_MINUS_1: Field = 0 - 1;
    global ZERO: Leaf = [0; LEAF_LEN];
    /// 2^D, the first index the tree cannot hold.
    global TWO_POW_D: Field = 0x10000;
    /// The secret-shared liquidations' budget (the fixtures' 1,000).
    global BUDGET: Field = 1000;
    /// The pinned clock of the rounds that accrue nothing: the books' last
    /// accrual, block 0.
    global CLOCK: Field = 0;

    /// The book's first eight leaves (the rest empty).
    type Sparse = [Leaf; 8];

    /// A liquidation written with `Tree::update`, as a non-secret-shared
    /// round would leave it: the tests' view of a step's public effect.
    struct Liquidation {
        updated: Updated<PROBES, LEAF_LEN>,
        outcome: Outcome,
        /// bit k - 1 set when probe k was liquidated; 0 when not ok
        mask: Field,
        /// the collateral paid to the liquidator over every liquidated probe
        seize: Field,
        /// the debt the liquidator pays to the market over every liquidated
        /// probe
        repay: Field,
    }

    /// A liquidation step written with `Tree::update`.
    fn liquidation(t: ProbeBook, s: Step<PROBES>) -> Liquidation {
        let o = s.outcome;
        Liquidation {
            updated: t.update(o.ok, s.writes, s.new_leaves),
            outcome: o,
            mask: o.mask_field(s.report.fields()[1]),
            seize: o.mask_field(s.report.fields()[2]),
            repay: o.mask_field(s.report.fields()[3]),
        }
    }

    /// The header: total_debt, liquidity, total_shares, the borrow index
    /// INDEX_ONE, last_accrual 0, the append index, 0, the blinding.
    fn hdr(td: Field, liq: Field, ts: Field, next: Field, r: Field) -> Leaf {
        [td, liq, ts, ONE, 0, next, 0, r]
    }

    /// A borrower leaf: collateral c, debt d, index_at_touch INDEX_ONE.
    fn bor_leaf(c: Field, d: Field, r: Field) -> Leaf {
        [OPEN, c, d, ONE, 0, 0, 0, r]
    }

    /// A lender leaf of `s` shares.
    fn lend_leaf(s: Field, r: Field) -> Leaf {
        [LENDER, s, 0, 0, 0, 0, 0, r]
    }

    /// `leaf` holding the exit tag `tag` (market.nr `P_EXIT_TAG`).
    fn tagged(leaf: Leaf, tag: Field) -> Leaf {
        let mut out = leaf;
        out[P_EXIT_TAG] = tag;
        out
    }

    /// `leaf` without its exit tag: what a non-secret-shared round, which
    /// writes no tag, and a secret-shared one leave alike.
    fn untagged(leaf: Leaf) -> Leaf {
        tagged(leaf, 0)
    }

    fn hash_at(i: u32, leaf: Leaf) -> Field {
        if leaf == ZERO {
            0
        } else {
            tree::leaf_hash(NS, KEY, i as Field, leaf)
        }
    }

    /// The root of a sparse book and, for each index of `at` (each below
    /// 8), its leaf, old hash and siblings.
    fn slots<let K: u32>(b: Sparse, at: [Field; K]) -> (Field, [Leaf; K], [Field; K], [[Field; DEPTH]; K]) {
        let z = tree::zeros::<DEPTH>();
        let mut levels = [[0; 8]; 4];
        for i in 0..8 {
            levels[0][i] = hash_at(i, b[i]);
        }
        for l in 0..3 {
            for p in 0..8 {
                if p < (8 >> (l + 1)) {
                    levels[l + 1][p] = tree::node(levels[l][2 * p], levels[l][2 * p + 1]);
                }
            }
        }
        let mut root = levels[3][0];
        for l in 3..DEPTH {
            root = tree::node(root, z[l]);
        }
        let mut leaves = [ZERO; K];
        let mut hashes = [0; K];
        let mut siblings = [[0; DEPTH]; K];
        for k in 0..K {
            let n = at[k] as u32;
            leaves[k] = b[n];
            hashes[k] = levels[0][n];
            for l in 0..DEPTH {
                siblings[k][l] = if l < 3 { levels[l][(n >> l) ^ 1] } else { z[l] };
            }
        }
        (root, leaves, hashes, siblings)
    }

    fn commitment(b: Sparse) -> Field {
        let (root, _, _, _) = slots(b, [0]);
        tree::commitment(NS, KEY, root)
    }

    /// Alice's position 1 (c, d), Bob's 2 (bc, 0) when bc != 0, and the
    /// header (total_debt d, the liquidity, the init's LIQ shares), its
    /// append index the next leaf.
    fn market(c: Field, d: Field, bc: Field, liquidity: Field) -> Sparse {
        let mut b = [ZERO; 8];
        b[0] = hdr(d, liquidity, LIQ, if bc != 0 { 3 } else { 2 }, 7);
        b[1] = bor_leaf(c, d, 8);
        if bc != 0 {
            b[2] = bor_leaf(bc, 0, 9);
        }
        b
    }

    fn owner_book(b: Sparse, at: Field) -> OwnerBook {
        let (_, leaves, hashes, siblings) = slots(b, [0, at]);
        book(NS, KEY, KEY, leaves, hashes, siblings, [0, at], 2)
    }

    fn placed(position: Field) -> Field {
        if (position as u64) < 8 { position } else { 0 }
    }

    fn dep(b: Sparse, position: Field, amount: Field, new_leaf: Field) -> OwnerRound {
        let at = placed(if position == 0 { new_leaf } else { position });
        let t = owner_book(b, at);
        owner_round(t, deposit(t, [position, amount], new_leaf, CLOCK, [R[0], R[1]]))
    }

    fn bor(b: Sparse, position: Field, amount: Field, price: Field) -> OwnerRound {
        let t = owner_book(b, placed(position));
        owner_round(t, borrow(t, [position, amount], price, CLOCK, [R[0], R[1]]))
    }

    fn rep(b: Sparse, position: Field, amount: Field) -> OwnerRound {
        let t = owner_book(b, placed(position));
        owner_round(t, repay(t, [position, amount], CLOCK, [R[0], R[1]]))
    }

    fn wd(b: Sparse, position: Field, amount: Field, price: Field) -> OwnerRound {
        let t = owner_book(b, placed(position));
        owner_round(t, withdraw(t, [position, amount], price, CLOCK, [R[0], R[1]]))
    }

    fn sup(b: Sparse, position: Field, amount: Field, new_leaf: Field) -> OwnerRound {
        let at = placed(if position == 0 { new_leaf } else { position });
        let t = owner_book(b, at);
        owner_round(t, supply(t, [position, amount], new_leaf, CLOCK, [R[0], R[1]]))
    }

    fn wds(b: Sparse, position: Field, shares: Field) -> OwnerRound {
        let t = owner_book(b, placed(position));
        owner_round(t, withdraw_supply(t, [position, shares], CLOCK, [R[0], R[1]]))
    }

    /// A liquidation of `positions[..count]` (the rest 0), as the
    /// scheduler places it, with a budget no repay reaches.
    fn liq(b: Sparse, positions: [Field; PROBES - 1], count: Field, price: Field) -> Liquidation {
        liq_with(b, positions, count, price, U128_MAX)
    }

    /// The placed indices of a liquidation: slot k at its position when the
    /// count uses it.
    fn liq_at(positions: [Field; PROBES - 1], count: Field) -> [Field; PROBES] {
        let mut at = [0; PROBES];
        for k in 1..PROBES {
            if (k as Field).lt(count + 1) & (count as u32 < PROBES) {
                at[k] = placed(positions[k - 1]);
            }
        }
        at
    }

    /// `liq` with the liquidator's `budget`.
    fn liq_with(b: Sparse, positions: [Field; PROBES - 1], count: Field, price: Field, budget: Field) -> Liquidation {
        let at = liq_at(positions, count);
        let (_, leaves, hashes, siblings) = slots(b, at);
        let t: ProbeBook = book(NS, KEY, KEY, leaves, hashes, siblings, at, 1 + count);
        liquidation(t, liquidate(t, positions.concat([count, budget]), price, CLOCK, [R[0], R[1]]))
    }

    /// An applied owner round: the new commitment is the book `after`'s.
    fn applied(r: OwnerRound, before: Sparse, after: Sparse) {
        assert_eq(r.outcome.code, 0);
        assert(r.outcome.ok);
        assert_eq(r.updated.old_c, commitment(before));
        assert_eq(r.updated.new_c, commitment(after));
    }

    /// A rejected round: ok = false with the code and new_c = old_c, the
    /// leaves stored back unchanged.
    fn rejected(r: OwnerRound, b: Sparse, code: Field) {
        assert_eq(r.outcome.code, code);
        assert(!r.outcome.ok);
        assert_eq(r.updated.old_c, commitment(b));
        assert_eq(r.updated.new_c, r.updated.old_c);
        assert_eq(r.updated.write, [false; OWNER_SLOTS]);
        assert_eq(r.outcome.mask_field(r.position), 0);
    }

    /// A liquidation that liquidated nothing: the header alone written, as
    /// loaded (at a zero elapsed the accrual changes nothing) under its fresh
    /// blinding.
    fn header_only(l: Liquidation, b: Sparse) {
        assert_eq(l.updated.write, [true, false]);
        let mut head = b[0];
        head[LEAF_LEN - 1] = R[0];
        assert_eq(l.updated.new_c, commitment(with(b, 0, head)));
    }

    fn liq_rejected(l: Liquidation, b: Sparse, code: Field) {
        assert_eq(l.outcome.code, code);
        assert(!l.outcome.ok);
        assert_eq(l.updated.new_c, commitment(b));
        assert_eq([l.mask, l.seize, l.repay], [0, 0, 0]);
    }

    fn with(b: Sparse, i: u32, leaf: Leaf) -> Sparse {
        let mut out = b;
        out[i] = leaf;
        out
    }

    // The contract pays x in the collateral asset on a note that names no
    // position (lending_tip's `LendingOutcome::settlement`): of the reports
    // that name none, only a liquidation's carries an x, and a header-only
    // round's pays nothing at all.
    #[test]
    fn only_a_liquidation_report_names_no_position_and_pays_x() {
        assert_eq(Report::liquidation(1, 446, 850, 150).fields(), [0, 1, 446, 850, 150, 0]);
        assert_eq(Report::header(7, 8, 9).fields(), [0, 7, 0, 8, 0, 9]);
        assert_eq(Report::none().fields(), [0; 6]);
        assert_eq(Report::owner(3, 1, [554, 850], 20).fields(), [3, 1, 554, 850, 20, 0]);
    }

    // ---- the fixtures' race, each Prover.toml ----

    #[test]
    fn the_init_creates_the_header() {
        let u = empty_book(NS, KEY, LIQ, 333);
        let b = with([ZERO; 8], 0, hdr(0, LIQ, LIQ, 1, 333));
        assert_eq(u.old_c, 0);
        assert_eq(u.new_c, commitment(b));
        assert_eq(u.new_hashes, [tree::leaf_hash(NS, KEY, 0, hdr(0, LIQ, LIQ, 1, 333))]);
    }

    // The oblivious deployment's init (circuits/lending_init_oblivious): the
    // same book under the same commitment, with no leaf hash out.
    #[test]
    fn the_oblivious_init_outputs_the_same_book_and_no_hash() {
        let out = super::empty_book_oblivious(NS, KEY, LIQ, 333).init(NS, 0x5a, [LIQ], 777);
        assert_eq(out.old_c, 0);
        assert_eq(out.new_c, empty_book(NS, KEY, LIQ, 333).new_c);
        assert_eq(out.new_hashes, [0]);
    }

    #[test]
    fn race_setup_open_deposit_then_borrow() {
        let s0 = with([ZERO; 8], 0, hdr(0, LIQ, LIQ, 1, 7));
        // Alice opens: position 0 takes $new_leaf 1
        let r = dep(s0, 0, 1000, 1);
        let s1 = with(with(s0, 0, hdr(0, LIQ, LIQ, 2, R[0])), 1, bor_leaf(1000, 0, R[1]));
        applied(r, s0, s1);
        assert_eq(r.outcome.mask_field(r.position), 1);
        assert_eq(r.updated.new_hashes[1], tree::leaf_hash(NS, KEY, 1, bor_leaf(1000, 0, R[1])));
        // borrow 1700 at 2.50, within the borrow limit (1000 * 250 * 7500 >=
        // 1700 * 100 * 10000)
        let r = bor(s1, 1, 1700, 250);
        let s2 = with(with(s1, 0, hdr(1700, LIQ - 1700, LIQ, 2, R[0])), 1, bor_leaf(1000, 1700, R[1]));
        applied(r, s1, s2);
        assert_eq(r.outcome.mask_field(r.position), 1);
        // the same borrow at the race's price 2.00 is past the limit
        rejected(bor(s1, 1, 1700, 200), s1, CODE_LIMIT);
    }

    #[test]
    fn race_a_repay_first_then_the_liquidation_liquidates_nothing() {
        let m = market(1000, 1700, 1000, LIQ - 1700);
        let r = rep(m, 1, 400);
        let after = with(with(m, 0, hdr(1300, LIQ - 1300, LIQ, 3, R[0])), 1, bor_leaf(1000, 1300, R[1]));
        applied(r, m, after);
        // 12,307 bps at 2.00: ok, mask 0, the header alone written (its
        // accrual, nothing at a zero elapsed, under a fresh blinding)
        let l = liq(after, [1], 1, 200);
        assert(l.outcome.ok);
        assert_eq([l.mask, l.seize, l.repay], [0, 0, 0]);
        header_only(l, after);
    }

    #[test]
    fn race_b_liquidation_first() {
        // position 1 (Alice, 9,411 bps at 2.00) is liquidated: mask 1
        let m = market(1000, 1700, 1000, LIQ - 1700);
        let l = liq(m, [1], 1, 200);
        assert(l.outcome.ok);
        assert_eq(l.outcome.code, 0);
        assert_eq([l.mask, l.seize, l.repay], [1, 446, 850]);
        let after = with(with(m, 0, hdr(850, LIQ - 850, LIQ, 3, R[0])), 1, bor_leaf(554, 850, R[1]));
        assert_eq(l.updated.new_c, commitment(after));
        assert_eq(l.updated.write, [true, true]);
        // Alice's repayment then brings the debt to 450
        let r = rep(after, 1, 400);
        assert(r.outcome.ok);
        assert_eq(r.updated.stored[1], bor_leaf(554, 450, R[1]));
    }

    // A lender leaf decodes as a position without debt: a liquidation never
    // liquidates it (no kind check needed), and writes nothing.
    #[test]
    fn a_lender_leaf_is_never_liquidated() {
        let m = with(with(market(1000, 1700, 0, LIQ - 1700), 0, hdr(1700, LIQ - 1700, LIQ + 300, 4, 7)), 3, lend_leaf(300, 10));
        let l = liq(m, [3], 1, 1);
        assert(l.outcome.ok);
        assert_eq([l.mask, l.seize, l.repay], [0, 0, 0]);
        header_only(l, m);
    }

    // ---- the write-off of bad debt ----

    /// Alice's position 1 (c, 1,700) beside Bob's 2, under a header whose
    /// total_debt 5,000 holds other debt beside hers and whose liquidity is
    /// 0, so the write-off shows as total_debt's fall alone.
    fn bad(c: Field) -> Sparse {
        with(market(c, 1700, 1000, 0), 0, hdr(5000, 0, LIQ, 3, 7))
    }

    /// The quote's supply index on `b` at the books' clock.
    fn supply_index(b: Sparse) -> Field {
        let (_, leaves, hashes, siblings) = slots(b, [0]);
        let t: ScanBook = book(NS, KEY, KEY, leaves, hashes, siblings, [0], 1);
        quote_rates(t, CLOCK, [R[0]]).report.fields()[3]
    }

    // A full seize with a residual: 100 collateral at 2.00 against 1,700
    // debt; the repay 850 wants 446, the seize takes the 100, and the
    // residual 1,700 - 850 = 850 is written off: the position keeps no
    // debt, total_debt falls by the repay and exactly the residual, and the
    // supply index falls by the residual per share.
    #[test]
    fn a_full_seize_writes_off_the_residual() {
        let m = bad(100);
        let l = liq(m, [1], 1, 200);
        assert(l.outcome.ok);
        assert_eq([l.mask, l.seize, l.repay], [1, 100, 850]);
        let after = with(with(m, 0, hdr(5000 - 850 - 850, 850, LIQ, 3, R[0])), 1, bor_leaf(0, 0, R[1]));
        assert_eq(l.updated.stored, [after[0], after[1]]);
        assert_eq(l.updated.new_c, commitment(after));
        // the pool's value was 5,000 over 10^6 shares and is 850 + 3,300:
        // the residual's 850 is gone from it, the repay's moved to liquidity
        assert_eq(supply_index(m), 5000000);
        assert_eq(supply_index(after), 4150000);
        // a budget below the close: repay 425 wants 223, still past the
        // collateral, so the residual 1,700 - 425 = 1,275 is written off
        let l = liq_with(m, [1], 1, 200, 425);
        assert_eq([l.mask, l.seize, l.repay], [1, 100, 425]);
        assert_eq(l.updated.stored[0], hdr(5000 - 425 - 1275, 425, LIQ, 3, R[0]));
        assert_eq(l.updated.stored[1], bor_leaf(0, 0, R[1]));
        // want equal to the collateral empties it too
        let l = liq(bad(446), [1], 1, 200);
        assert_eq([l.mask, l.seize, l.repay], [1, 446, 850]);
        assert_eq(l.updated.stored[0], hdr(5000 - 1700, 850, LIQ, 3, R[0]));
        assert_eq(l.updated.stored[1], bor_leaf(0, 0, R[1]));
        // a total_debt below the position's debt saturates at 0
        let short = with(m, 0, hdr(1000, 0, LIQ, 3, 7));
        assert_eq(liq(short, [1], 1, 200).updated.stored[0], hdr(0, 850, LIQ, 3, R[0]));
    }

    // A partial seize writes off nothing: one collateral unit past the want, the
    // seize leaves it and the position keeps debt' - repay; total_debt falls
    // by the repay alone.
    #[test]
    fn a_partial_seize_writes_off_nothing() {
        let m = bad(447);
        let l = liq(m, [1], 1, 200);
        assert_eq([l.mask, l.seize, l.repay], [1, 446, 850]);
        assert_eq(l.updated.stored[0], hdr(5000 - 850, 850, LIQ, 3, R[0]));
        assert_eq(l.updated.stored[1], bor_leaf(1, 850, R[1]));
        assert_eq(supply_index(with(with(m, 0, l.updated.stored[0]), 1, l.updated.stored[1])), 5000000);
    }

    // A full seize with no residual cannot happen: the repay is at most half
    // of debt' (CLOSE_BPS 5,000), so a liquidated probe always leaves one.
    // The smallest case: no collateral and debt 2, repay 1, seize 0 (the
    // whole collateral), the residual 1 written off; debt 1 repays 0 and is
    // skipped, its dust kept (liquidate_codes).
    #[test]
    fn the_smallest_full_seize_writes_off_one() {
        let m = market(0, 2, 0, 0);
        let l = liq(m, [1], 1, 200);
        assert_eq([l.mask, l.seize, l.repay], [1, 0, 1]);
        assert_eq(l.updated.stored[0], hdr(0, 1, LIQ, 2, R[0]));
        assert_eq(l.updated.stored[1], bor_leaf(0, 0, R[1]));
    }

    // ---- deposit ----

    #[test]
    fn deposit_codes() {
        let m = market(1000, 1700, 0, LIQ - 1700);
        rejected(dep(m, 1, TWO_POW_128, 2), m, CODE_AMOUNT_RANGE);
        rejected(dep(m, 1, P_MINUS_1, 2), m, CODE_AMOUNT_RANGE);
        rejected(dep(m, 1, 0, 2), m, CODE_ZERO_AMOUNT);
        rejected(dep(m, TWO_POW_D, 10, 2), m, CODE_POSITION_RANGE);
        rejected(dep(m, P_MINUS_1, 10, 2), m, CODE_POSITION_RANGE);
        // a full book: an opening deposit with $new_leaf 0
        rejected(dep(m, 0, 10, 0), m, CODE_FULL_BOOK);
        // an opening anywhere but at the append index 2: an empty leaf past
        // the end of the book, where the keeper's scan never looks
        rejected(dep(m, 0, 10, 3), m, CODE_APPEND_INDEX);
        rejected(dep(m, 0, 10, 7), m, CODE_APPEND_INDEX);
        let bad = with(m, 1, bor_leaf(TWO_POW_128, 1700, 8));
        rejected(dep(bad, 1, 10, 2), bad, CODE_BAD_STATE);
        // an opening slot that is not empty is the nodes' fault
        rejected(dep(m, 0, 10, 1), m, CODE_BAD_STATE);
        // an empty leaf is opened only through position 0: a deposit that
        // names it is code 5, the backstop of the contract's note check
        rejected(dep(m, 4, 10, 2), m, CODE_KIND);
        // a lender's leaf and a leaf of any other kind take no deposit
        let lent = with(m, 1, lend_leaf(1000, 8));
        rejected(dep(lent, 1, 10, 2), lent, CODE_KIND);
        let odd = with(m, 1, [3, 1000, 1700, ONE, 0, 0, 0, 8]);
        rejected(dep(odd, 1, 10, 2), odd, CODE_KIND);
        rejected(dep(m, 1, U128_MAX - 999, 2), m, CODE_OVERFLOW);
        assert(dep(m, 1, U128_MAX - 1000, 2).outcome.ok);
        // Bob opens leaf 2: a borrower leaf, its index at touch INDEX_ONE
        let r = dep(m, 0, 10, 2);
        applied(r, m, with(with(m, 0, hdr(1700, LIQ - 1700, LIQ, 3, R[0])), 2, bor_leaf(10, 0, R[1])));
        assert_eq(r.outcome.mask_field(r.position), 2);
    }

    #[test]
    fn a_wrong_placement_is_code_4() {
        let m = market(1000, 1700, 0, LIQ - 1700);
        // the nodes place leaf 2 for position 1
        let (_, leaves, hashes, siblings) = slots(m, [0, 2]);
        let t: OwnerBook = book(NS, KEY, KEY, leaves, hashes, siblings, [0, 2], 2);
        rejected(owner_round(t, borrow(t, [1, 10], 250, CLOCK, [R[0], R[1]])), m, CODE_BAD_STATE);
        // a wrong sibling
        let (_, leaves, hashes, mut siblings) = slots(m, [0, 1]);
        siblings[1][5] = 1;
        let t: OwnerBook = book(NS, KEY, KEY, leaves, hashes, siblings, [0, 1], 2);
        rejected(owner_round(t, borrow(t, [1, 10], 250, CLOCK, [R[0], R[1]])), m, CODE_BAD_STATE);
    }

    // A `$new_leaf` the tree cannot hold (2^D, which a full book's scheduler
    // should have sent as 0) is out of range (code 3) by the book's own
    // range flag, before the paths it cannot have are looked at.
    #[test]
    fn an_opening_at_new_leaf_two_pow_d_is_code_3() {
        let m = market(1000, 0, 0, LIQ);
        let (_, leaves, hashes, siblings) = slots(m, [0, 0]);
        let at = [0, TWO_POW_D];
        let t: OwnerBook = book(NS, KEY, KEY, [leaves[0], ZERO], [hashes[0], 0], siblings, at, 2);
        assert(!t.in_range);
        rejected(owner_round(t, deposit(t, [0, 500], TWO_POW_D, CLOCK, [R[0], R[1]])), m, CODE_POSITION_RANGE);
    }

    // ---- borrow ----

    // The non-secret-shared note outputs: an applied borrow names the
    // position and its kind and pays the amount; a withdrawal pays in the
    // collateral asset; a lender's supply names its kind with mask 0; a
    // refused round names nothing and pays nothing (its escrow goes back
    // through the contract, ok being public).
    #[test]
    fn note_outputs_name_the_position_and_the_payout_when_ok() {
        let m = market(1000, 0, 0, LIQ);
        let b = bor(m, 1, 1500, 200);
        let o = b.note_outputs();
        assert_eq([o.code, o.position, o.mask, o.payout], [0, 1, ONE, 1500]);
        assert_eq(o.new_hashes, b.updated.new_hashes);
        let o = wd(market(1000, 600, 1000, LIQ), 1, 200, 200).note_outputs();
        assert_eq([o.code, o.position, o.mask, o.payout], [0, 1, ONE, ASSET_BIT + 200]);
        let o = sup(m, 0, 500, 2).note_outputs();
        assert_eq([o.code, o.position, o.mask, o.payout], [0, 2, 0, 0]);
        let o = bor(m, 1, 1501, 200).note_outputs();
        assert_eq([o.code, o.position, o.mask, o.payout], [CODE_LIMIT, 0, 0, 0]);
        let o = rep(m, 1, 0).note_outputs();
        assert_eq([o.code, o.position, o.mask, o.payout], [CODE_ZERO_AMOUNT, 0, 0, 0]);
    }

    #[test]
    fn borrow_codes() {
        let m = market(1000, 0, 0, LIQ);
        rejected(bor(m, 1, TWO_POW_128, 200), m, CODE_AMOUNT_RANGE);
        rejected(bor(m, 1, 0, 200), m, CODE_ZERO_AMOUNT);
        rejected(bor(m, 0, 10, 200), m, CODE_POSITION_RANGE);
        rejected(bor(m, TWO_POW_D, 10, 200), m, CODE_POSITION_RANGE);
        let bad = with(m, 0, hdr(0, P_MINUS_1, LIQ, 2, 7));
        rejected(bor(bad, 1, 10, 200), bad, CODE_BAD_STATE);
        rejected(bor(m, 3, 10, 200), m, CODE_KIND);
        let lent = with(m, 1, lend_leaf(1000, 8));
        rejected(bor(lent, 1, 10, 200), lent, CODE_KIND);
        rejected(bor(m, 1, 10, 0), m, CODE_PRICE);
        rejected(bor(m, 1, 10, TWO_POW_64), m, CODE_PRICE);
        let big = market(U128_MAX, U128_MAX - 5, 0, LIQ);
        rejected(bor(big, 1, 6, 200), big, CODE_OVERFLOW);
        rejected(bor(m, 1, LIQ + 1, 200), m, CODE_LIQUIDITY);
        // the borrow limit at 2.00: 1,000 collateral is worth 2,000, 75% of
        // it 1,500 (the liquidation threshold's 1,600 is not the limit)
        assert(bor(m, 1, 1500, 200).outcome.ok);
        rejected(bor(m, 1, 1501, 200), m, CODE_LIMIT);
        rejected(bor(m, 1, 1600, 200), m, CODE_LIMIT);
        // the full u128 width: 2^127 against U128_MAX collateral at 2.00
        // (within the limit: 2 * 0.75 > 1)
        let wide = market(U128_MAX, 0, 0, U128_MAX);
        let r = bor(wide, 1, TWO_POW_127, 200);
        assert(r.outcome.ok);
        assert_eq(r.updated.stored[0], hdr(TWO_POW_127, U128_MAX - TWO_POW_127, LIQ, 2, R[0]));
        assert_eq(r.updated.stored[1], bor_leaf(U128_MAX, TWO_POW_127, R[1]));
    }

    // ---- repay ----

    #[test]
    fn repay_codes() {
        let m = market(1000, 1700, 0, LIQ - 1700);
        rejected(rep(m, 1, TWO_POW_128), m, CODE_AMOUNT_RANGE);
        rejected(rep(m, 1, 0), m, CODE_ZERO_AMOUNT);
        rejected(rep(m, 0, 400), m, CODE_POSITION_RANGE);
        let bad = with(m, 0, hdr(P_MINUS_1, LIQ - 1700, LIQ, 2, 7));
        rejected(rep(bad, 1, 400), bad, CODE_BAD_STATE);
        rejected(rep(m, 3, 400), m, CODE_KIND);
        let full = market(1000, 1700, 0, U128_MAX - 1000);
        rejected(rep(full, 1, 1700), full, CODE_OVERFLOW);
        let r = rep(m, 1, 1700);
        assert(r.outcome.ok);
        assert_eq(r.updated.stored[1], bor_leaf(1000, 0, R[1]));
        // the total debt is an aggregate: one below the position's debt
        // saturates at 0, the position is the authority
        let short = with(m, 0, hdr(1000, LIQ - 1700, LIQ, 2, 7));
        let r = rep(short, 1, 1700);
        assert(r.outcome.ok);
        assert_eq(r.updated.stored[0], hdr(0, LIQ, LIQ, 2, R[0]));
    }

    // A repayment caps at the debt: the excess is the payout, in the
    // borrowed asset, and only the repaid part reaches the liquidity.
    #[test]
    fn a_repayment_over_the_debt_repays_the_debt_and_returns_the_excess() {
        let m = market(1000, 1700, 0, LIQ - 1700);
        let t = owner_book(m, 1);
        let s = repay(t, [1, 2000], CLOCK, [R[0], R[1]]);
        assert(s.outcome.ok);
        assert_eq(s.report.fields(), [1, ONE, 1000, 0, 300, 0]);
        let r = rep(m, 1, 2000);
        applied(r, m, with(with(m, 0, hdr(0, LIQ, LIQ, 2, R[0])), 1, bor_leaf(1000, 0, R[1])));
        // a position without debt takes a repayment whole as excess
        let none = market(1000, 0, 0, LIQ);
        let s = repay(owner_book(none, 1), [1, 5], CLOCK, [R[0], R[1]]);
        assert(s.outcome.ok);
        assert_eq(s.report.fields()[4], 5);
        // a failed repayment returns its amount in the borrowed asset
        assert_eq(repay(owner_book(m, 3), [3, 5], CLOCK, [R[0], R[1]]).refund, 5);
    }

    // ---- withdraw ----

    #[test]
    fn withdraw_codes() {
        // 1,000 collateral with 1,200 debt at 2.00: the limit needs 800
        // collateral (800 * 200 * 7500 = 1200 * 100 * 10000)
        let m = market(1000, 1200, 0, LIQ - 1200);
        rejected(wd(m, 1, TWO_POW_128, 200), m, CODE_AMOUNT_RANGE);
        rejected(wd(m, 1, 0, 200), m, CODE_ZERO_AMOUNT);
        rejected(wd(m, 0, 10, 200), m, CODE_POSITION_RANGE);
        rejected(wd(m, TWO_POW_D, 10, 200), m, CODE_POSITION_RANGE);
        let bad = with(m, 1, bor_leaf(1000, TWO_POW_128, 8));
        rejected(wd(bad, 1, 10, 200), bad, CODE_BAD_STATE);
        rejected(wd(m, 3, 10, 200), m, CODE_KIND);
        rejected(wd(m, 1, 10, 0), m, CODE_PRICE);
        rejected(wd(m, 1, 1001, 200), m, CODE_EXCEEDS_COLLATERAL);
        rejected(wd(m, 1, 201, 200), m, CODE_LIMIT);
        let r = wd(m, 1, 200, 200);
        applied(r, m, with(with(m, 0, hdr(1200, LIQ - 1200, LIQ, 2, R[0])), 1, bor_leaf(800, 1200, R[1])));
        assert_eq(r.outcome.mask_field(r.position), 1);
        // the payout is the amount in the collateral asset
        let t = owner_book(m, 1);
        assert_eq(withdraw(t, [1, 200], 200, CLOCK, [R[0], R[1]]).report.fields(), [1, ONE, 800, 1200, ASSET_BIT + 200, 0]);
        // a position without debt withdraws everything, at any price
        let free = market(1000, 0, 0, LIQ);
        applied(wd(free, 1, 1000, 0), free, with(with(free, 0, hdr(0, LIQ, LIQ, 2, R[0])), 1, bor_leaf(0, 0, R[1])));
        rejected(wd(free, 1, 1001, 0), free, CODE_EXCEEDS_COLLATERAL);
    }

    // ---- lenders: supply, withdraw_supply, the quote ----

    // A pool whose value has moved past its shares (as accrued interest
    // moves it): 100,000 of debt beside the 1,000,000 of liquidity, the
    // init's 1,000,000 shares and a lender's 2,000 at leaf 1: each share is
    // worth 1.1.
    fn lent_book() -> Sparse {
        let mut b = [ZERO; 8];
        b[0] = hdr(100000, 1000000, 1002000, 2, 7);
        b[1] = lend_leaf(2000, 8);
        b
    }

    #[test]
    fn supply_mints_shares_at_the_pools_value() {
        // the first supply into the seeded book: one share per unit
        let s0 = with([ZERO; 8], 0, hdr(0, LIQ, LIQ, 1, 7));
        let r = sup(s0, 0, 5000, 1);
        applied(r, s0, with(with(s0, 0, hdr(0, LIQ + 5000, LIQ + 5000, 2, R[0])), 1, lend_leaf(5000, R[1])));
        let t = owner_book(s0, 1);
        // the lender's note: mask 0 (the lender kind), its shares and their value
        assert_eq(supply(t, [0, 5000], 1, CLOCK, [R[0], R[1]]).report.fields(), [1, 0, 5000, 5000, 0, 0]);
        // into an existing lender leaf at a pool worth 1.1 per share: 1,100
        // buys floor(1100 * 1002000 / 1100000) = 1002 shares
        let b = lent_book();
        let r = sup(b, 1, 1100, 0);
        applied(r, b, with(with(b, 0, hdr(100000, 1001100, 1003002, 2, R[0])), 1, lend_leaf(3002, R[1])));
        // 3002 shares of a pool of 1,101,100 over 1,003,002: 3,295
        assert_eq(supply(owner_book(b, 1), [1, 1100], 0, CLOCK, [R[0], R[1]]).report.fields(), [1, 0, 3002, 3295, 0, 0]);
        // with no shares outstanding the amount mints as many
        let empty = with([ZERO; 8], 0, hdr(0, 0, 0, 1, 7));
        assert_eq(supply(owner_book(empty, 1), [0, 7], 1, CLOCK, [R[0], R[1]]).report.fields(), [1, 0, 7, 7, 0, 0]);
    }

    #[test]
    fn supply_codes() {
        let b = lent_book();
        rejected(sup(b, 1, TWO_POW_128, 0), b, CODE_AMOUNT_RANGE);
        rejected(sup(b, 1, 0, 0), b, CODE_ZERO_AMOUNT);
        rejected(sup(b, TWO_POW_D, 10, 0), b, CODE_POSITION_RANGE);
        rejected(sup(b, 0, 10, 0), b, CODE_FULL_BOOK);
        rejected(sup(b, 0, 10, 5), b, CODE_APPEND_INDEX);
        let bad = with(b, 0, hdr(100000, 1000000, TWO_POW_128, 2, 7));
        rejected(sup(bad, 1, 10, 0), bad, CODE_BAD_STATE);
        // a borrower's leaf and an empty one take no supply
        let borrowed = with(b, 1, bor_leaf(1000, 0, 8));
        rejected(sup(borrowed, 1, 10, 0), borrowed, CODE_KIND);
        rejected(sup(b, 3, 10, 0), b, CODE_KIND);
        // 1 at 1.1 per share mints 0: refused, nothing taken
        rejected(sup(b, 1, 1, 0), b, CODE_ZERO_QUOTIENT);
        assert(sup(b, 1, 2, 0).outcome.ok);
        // the liquidity would pass u128
        let full = with(b, 0, hdr(0, U128_MAX - 5, 1002000, 2, 7));
        rejected(sup(full, 1, 6, 0), full, CODE_OVERFLOW);
        // shares outstanding in a pool worth nothing: the multiply-divide refuses
        let worthless = with(b, 0, hdr(0, 0, 1002000, 2, 7));
        rejected(sup(worthless, 1, 10, 0), worthless, CODE_OVERFLOW);
        // an opening supply writes a lender leaf
        let r = sup(b, 0, 1100, 2);
        applied(r, b, with(with(b, 0, hdr(100000, 1001100, 1003002, 3, R[0])), 2, lend_leaf(1002, R[1])));
    }

    #[test]
    fn withdraw_supply_pays_the_shares_value() {
        let b = lent_book();
        // 1,000 shares at 1.1: floor(1000 * 1100000 / 1002000) = 1,097
        let r = wds(b, 1, 1000);
        applied(r, b, with(with(b, 0, hdr(100000, 1000000 - 1097, 1001000, 2, R[0])), 1, lend_leaf(1000, R[1])));
        let t = owner_book(b, 1);
        // the payout 1,097 in the borrowed asset; the 1,000 shares left worth
        // floor(1000 * 1098903 / 1001000) = 1,097
        assert_eq(withdraw_supply(t, [1, 1000], CLOCK, [R[0], R[1]]).report.fields(), [1, 0, 1000, 1097, 1097, 0]);
    }

    #[test]
    fn withdraw_supply_codes() {
        let b = lent_book();
        rejected(wds(b, 1, TWO_POW_128), b, CODE_AMOUNT_RANGE);
        rejected(wds(b, 1, 0), b, CODE_ZERO_AMOUNT);
        rejected(wds(b, 0, 10), b, CODE_POSITION_RANGE);
        let bad = with(b, 1, lend_leaf(TWO_POW_128, 8));
        rejected(wds(bad, 1, 10), bad, CODE_BAD_STATE);
        let borrowed = with(b, 1, bor_leaf(2000, 0, 8));
        rejected(wds(borrowed, 1, 10), borrowed, CODE_KIND);
        rejected(wds(b, 1, 2001), b, CODE_EXCEEDS_SHARES);
        // no shares outstanding: the multiply-divide refuses
        let none = with(b, 0, hdr(100000, 1000000, 0, 2, 7));
        rejected(wds(none, 1, 10), none, CODE_OVERFLOW);
        // a pool worth less than one unit per share: 1 share is worth 0
        let thin = with(b, 0, hdr(0, 999999, 1002000, 2, 7));
        rejected(wds(thin, 1, 1), thin, CODE_ZERO_QUOTIENT);
        // the value above the liquidity: the lender waits for repayments
        let lent_out = with(b, 0, hdr(1100000, 1000, 1002000, 2, 7));
        rejected(wds(lent_out, 1, 2000), lent_out, CODE_LIQUIDITY);
        assert(wds(lent_out, 1, 900).outcome.ok);
    }

    #[test]
    fn a_view_reads_either_kind_and_a_quote_the_rates() {
        let b = with(lent_book(), 2, bor_leaf(1000, 500, 9));
        let b = with(b, 0, hdr(100000, 1000000, 1002000, 3, 7));
        // a lender: its shares and their value, mask 0
        assert_eq(view(owner_book(b, 1), [1], CLOCK, [R[0], R[1]]).report.fields(), [1, 0, 2000, 2195, 0, 0]);
        // a borrower: its collateral and debt, mask its index at touch
        assert_eq(view(owner_book(b, 2), [2], CLOCK, [R[0], R[1]]).report.fields(), [2, ONE, 1000, 500, 0, 0]);
        // an empty leaf: code 5
        assert_eq(view(owner_book(b, 4), [4], CLOCK, [R[0], R[1]]).outcome.code, CODE_KIND);
        // the quote: [0, borrow_index, 0, supply_index, 0, utilisation], x 0
        let (_, leaves, hashes, siblings) = slots(b, [0]);
        let t: ScanBook = book(NS, KEY, KEY, leaves, hashes, siblings, [0], 1);
        let q = quote_rates(t, CLOCK, [R[0]]);
        assert(q.outcome.ok & q.placed);
        // 1,100,000 * 10^9 / 1,002,000 = 1,097,804,391; 100,000 * 10,000 /
        // 1,100,000 = 909
        assert_eq(q.report.fields(), [0, ONE, 0, 1097804391, 0, 909]);
        // the header is written: its accrual
        assert_eq(q.writes, [true]);
        // a pool with no shares quotes INDEX_ONE; an empty one utilisation 0
        let (_, leaves, hashes, siblings) = slots(with([ZERO; 8], 0, hdr(0, 0, 0, 1, 7)), [0]);
        let t: ScanBook = book(NS, KEY, KEY, leaves, hashes, siblings, [0], 1);
        assert_eq(quote_rates(t, CLOCK, [R[0]]).report.fields(), [0, ONE, 0, ONE, 0, 0]);
    }

    // ---- liquidate ----

    #[test]
    fn liquidate_codes() {
        let m = market(1000, 1700, 1000, LIQ - 1700);
        liq_rejected(liq(m, [1], 0, 200), m, CODE_POSITION_RANGE);
        liq_rejected(liq(m, [1], PROBES as Field, 200), m, CODE_POSITION_RANGE);
        liq_rejected(liq(m, [0], 1, 200), m, CODE_POSITION_RANGE);
        liq_rejected(liq(m, [TWO_POW_D], 1, 200), m, CODE_POSITION_RANGE);
        let bad = with(m, 1, bor_leaf(1000, TWO_POW_128, 8));
        liq_rejected(liq(bad, [1], 1, 200), bad, CODE_BAD_STATE);
        liq_rejected(liq(m, [1], 1, 0), m, CODE_PRICE);
        liq_rejected(liq(m, [1], 1, P_MINUS_1), m, CODE_PRICE);
        let full = market(1000, 1700, 0, U128_MAX - 849);
        liq_rejected(liq(full, [1], 1, 200), full, CODE_OVERFLOW);
        assert(liq(market(1000, 1700, 0, U128_MAX - 850), [1], 1, 200).outcome.ok);
        // a debt of 1 repays 0: skipped, ok with mask 0
        let dust = market(0, 1, 0, 0);
        let l = liq(dust, [1], 1, 200);
        assert(l.outcome.ok);
        assert_eq(l.mask, 0);
        header_only(l, dust);
        // an empty leaf is never unhealthy
        let l = liq(m, [5], 1, 200);
        assert(l.outcome.ok & (l.mask == 0));
        // the widest: a debt of U128_MAX at price 1, seize capped, so the
        // residual 2^127 is written off and total_debt falls to 0
        let wide = market(U128_MAX, U128_MAX, 0, 0);
        let l = liq(wide, [1], 1, 1);
        assert(l.outcome.ok);
        assert_eq([l.mask, l.seize, l.repay], [1, U128_MAX, TWO_POW_127 - 1]);
        assert_eq(l.updated.stored[1], bor_leaf(0, 0, R[1]));
        assert_eq(l.updated.stored[0], hdr(0, TWO_POW_127 - 1, LIQ, 2, R[0]));
        // the total debt saturates: a header below the repay ends at 0
        let short = with(m, 0, hdr(100, LIQ - 1700, LIQ, 3, 7));
        let l = liq(short, [1], 1, 200);
        assert_eq(l.updated.stored[0], hdr(0, LIQ - 850, LIQ, 3, R[0]));
    }

    // The liquidator's budget: the probe repays min(close, budget), the seize
    // scaled with the repay; the unused budget is the payout.
    #[test]
    fn a_budget_caps_the_repay() {
        let m = market(1000, 1700, 0, LIQ - 1700);
        // a budget below the probe's close of 850: repay 425, seize 223
        let l = liq_with(m, [1], 1, 200, 425);
        assert_eq([l.mask, l.seize, l.repay], [1, 223, 425]);
        assert_eq(l.updated.stored[1], bor_leaf(1000 - 223, 1700 - 425, R[1]));
        // the budget's own codes, ahead of the probe's
        liq_rejected(liq_with(m, [1], 1, 200, TWO_POW_128), m, CODE_AMOUNT_RANGE);
        liq_rejected(liq_with(m, [1], 1, 200, 0), m, CODE_ZERO_AMOUNT);
        liq_rejected(liq_with(m, [1], 3, 200, 0), m, CODE_ZERO_AMOUNT);
    }

    #[test]
    fn first_failure_wins() {
        let m = market(1000, 1700, 0, LIQ - 1700);
        rejected(dep(m, P_MINUS_1, 0, 2), m, CODE_ZERO_AMOUNT);
        rejected(rep(m, P_MINUS_1, 400), m, CODE_POSITION_RANGE);
        rejected(bor(m, 3, 10, 0), m, CODE_KIND);
        rejected(bor(m, 1, 1_000_000_000, 0), m, CODE_PRICE);
        rejected(wd(m, 1, 1_000_000_000, 0), m, CODE_PRICE);
        // position range before the price
        liq_rejected(liq(m, [1], 3, 0), m, CODE_POSITION_RANGE);
    }

    // ---- interest (examples/lending-tip/README.md, "Interest") ----

    /// The header with borrow index `b` and last accrual `last`.
    fn hdr_at(td: Field, liq: Field, ts: Field, b: Field, last: Field, next: Field, r: Field) -> Leaf {
        [td, liq, ts, b, last, next, 0, r]
    }

    /// A borrower leaf touched at index `iat`.
    fn bor_at(c: Field, d: Field, iat: Field, r: Field) -> Leaf {
        [OPEN, c, d, iat, 0, 0, 0, r]
    }

    /// The pool at the kink (80% lent out, rate(u) = 46 per 10^9 per block),
    /// its one borrower at position 1 touched at block 0 at INDEX_ONE.
    fn kinked(c: Field, d: Field) -> Sparse {
        let mut b = [ZERO; 8];
        b[0] = hdr_at(800000, 200000, 1000000, ONE, 0, 2, 7);
        b[1] = bor_at(c, d, ONE, 8);
        b
    }

    /// The header's borrow index after `dt` blocks at the kink from INDEX_ONE:
    /// 10^9 + 46 * dt, exact.
    fn kink_index(dt: Field) -> Field {
        ONE + 46 * dt
    }

    // A view after 100 blocks shows the debt grown by the closed form and
    // writes the accrual: B' = 10^9 + 4,600; total_debt' = ceil(800,000 *
    // 1.0000046) = 800,004; the position brought to the index, its debt
    // ceil(800,000 * 1.0000046) = 800,004, its index at touch B'.
    #[test]
    fn accrual_over_n_blocks_matches_the_closed_form() {
        let m = kinked(2000000, 800000);
        let t = owner_book(m, 1);
        let r = owner_round(t, view(t, [1], 100, [R[0], R[1]]));
        let b = kink_index(100);
        let after = with(with(m, 0, hdr_at(800004, 200000, 1000000, b, 100, 2, R[0])), 1, bor_at(2000000, 800004, b, R[1]));
        applied(r, m, after);
        assert_eq(view(t, [1], 100, [R[0], R[1]]).report.fields(), [1, b, 2000000, 800004, 0, 0]);
        // 10,000 blocks: 10^9 + 460,000; ceil(800,000 * 1.00046) = 800,368
        let r = owner_round(t, view(t, [1], 10000, [R[0], R[1]]));
        assert_eq(r.updated.stored[0], hdr_at(800368, 200000, 1000000, kink_index(10000), 10000, 2, R[0]));
        assert_eq(r.updated.stored[1], bor_at(2000000, 800368, kink_index(10000), R[1]));
        // a zero elapsed accrues nothing and leaves the position exact
        let r = owner_round(t, view(t, [1], 0, [R[0], R[1]]));
        applied(r, m, with(with(m, 0, hdr_at(800000, 200000, 1000000, ONE, 0, 2, R[0])), 1, bor_at(2000000, 800000, ONE, R[1])));
    }

    // A repayment of the note's debt after 100 blocks leaves the interest;
    // one of more clears it and returns the excess. A borrow brings the
    // position to the index before it adds.
    #[test]
    fn a_repayment_after_accrual_meets_the_accrued_debt() {
        let m = kinked(2000000, 800000);
        let b = kink_index(100);
        let t = owner_book(m, 1);
        // the note said 800,000: 4 of interest remain, total_debt 800,004 - 800,000
        let s = repay(t, [1, 800000], 100, [R[0], R[1]]);
        assert_eq(s.report.fields(), [1, b, 2000000, 4, 0, 0]);
        let r = owner_round(t, s);
        assert_eq(r.updated.stored[0], hdr_at(4, 1000000, 1000000, b, 100, 2, R[0]));
        // 800,010 clears the 800,004 and returns 6
        let s = repay(t, [1, 800010], 100, [R[0], R[1]]);
        assert_eq(s.report.fields(), [1, b, 2000000, 0, 6, 0]);
        // a borrow of 10 at 2.50 after 100 blocks: 800,004 + 10
        let s = borrow(t, [1, 10], 250, 100, [R[0], R[1]]);
        assert(s.outcome.ok);
        assert_eq(s.report.fields(), [1, b, 2000000, 800014, 10, 0]);
        let r = owner_round(t, s);
        assert_eq(r.updated.stored[0], hdr_at(800014, 199990, 1000000, b, 100, 2, R[0]));
        // a withdrawal tests the limit on the accrued debt: at 2.00 the limit
        // for 800,004 debt needs 533,336 collateral (533,336 * 200 * 7,500 >=
        // 800,004 * 100 * 10,000), so 1,466,664 may leave and one more may not
        assert(withdraw(t, [1, 1466664], 200, 100, [R[0], R[1]]).outcome.ok);
        assert_eq(withdraw(t, [1, 1466665], 200, 100, [R[0], R[1]]).outcome.code, CODE_LIMIT);
        // without the accrual (a zero elapsed, 800,000 debt needs 533,334)
        // two units more could leave
        assert(withdraw(t, [1, 1466666], 200, 0, [R[0], R[1]]).outcome.ok);
        assert_eq(withdraw(t, [1, 1466667], 200, 0, [R[0], R[1]]).outcome.code, CODE_LIMIT);
    }

    // A borrower at the index boundary: touched at the current index its
    // debt is exact; the index and every index at touch stay below 2^48 (code
    // 4 beyond); a saturated index stops interest and keeps the market live.
    #[test]
    fn a_borrower_at_the_index_boundary() {
        let top = with(with([ZERO; 8], 0, hdr_at(1000, 0, 1000, INDEX_MAX, 0, 2, 7)), 1, bor_at(5000, 1000, INDEX_MAX, 8));
        // full utilisation, 1,000 blocks: the index cannot grow, nothing accrues
        let s = repay(owner_book(top, 1), [1, 1], 1000, [R[0], R[1]]);
        assert(s.outcome.ok);
        assert_eq(s.report.fields(), [1, INDEX_MAX, 5000, 999, 0, 0]);
        // just below the bound, the index saturates at it: the debt at the
        // index rounds up by one, ceil(1,000 * (2^48 - 1) / (2^48 - 11))
        let near = with(with(top, 0, hdr_at(1000, 0, 1000, INDEX_MAX - 10, 0, 2, 7)), 1, bor_at(5000, 1000, INDEX_MAX - 10, 8));
        let s = view(owner_book(near, 1), [1], 1000, [R[0], R[1]]);
        assert_eq(s.report.fields(), [1, INDEX_MAX, 5000, 1001, 0, 0]);
        // an index at touch of 2^48, or a header index of 2^48 or 0, is code 4
        let wide = with(top, 1, bor_at(5000, 1000, INDEX_MAX + 1, 8));
        rejected(rep(wide, 1, 1), wide, CODE_BAD_STATE);
        let wide_head = with(top, 0, hdr_at(1000, 0, 1000, INDEX_MAX + 1, 0, 2, 7));
        rejected(rep(wide_head, 1, 1), wide_head, CODE_BAD_STATE);
        let zero_head = with(top, 0, hdr_at(1000, 0, 1000, 0, 0, 2, 7));
        rejected(rep(zero_head, 1, 1), zero_head, CODE_BAD_STATE);
        // a borrower leaf with index at touch 0 (no round writes one) cannot
        // be brought to the index: code 7 on that position
        let lost = with(top, 1, bor_at(5000, 1000, 0, 8));
        rejected(rep(lost, 1, 1), lost, CODE_OVERFLOW);
        // a debt past u128 at the current index: code 7
        let deep = with(with(top, 0, hdr_at(1000, 0, 1000, ONE + 1, 0, 2, 7)), 1, bor_at(5000, U128_MAX, ONE, 8));
        rejected(rep(deep, 1, 1), deep, CODE_OVERFLOW);
    }

    // The clock band's max rule: a round at the band's top (128 blocks ahead
    // of the chain's 1,000) accrues to 1,128; one at its bottom (872) then
    // accrues nothing and leaves last_accrual at 1,128: the interval accrues
    // once, never twice.
    #[test]
    fn a_round_at_the_bands_top_then_its_bottom_accrues_once() {
        let mut m = kinked(2000000, 800000);
        m[0] = hdr_at(800000, 200000, 1000000, ONE, 1000, 2, 7);
        let (_, leaves, hashes, siblings) = slots(m, [0]);
        let t: ScanBook = book(NS, KEY, KEY, leaves, hashes, siblings, [0], 1);
        let top = quote_rates(t, 1128, [R[0]]);
        let b = kink_index(128);
        // 800,000 * 1.0000058880 = 800,004.71, rounded up
        assert_eq(top.new_leaves[0], hdr_at(800005, 200000, 1000000, b, 1128, 2, R[0]));
        let m2 = with(m, 0, top.new_leaves[0]);
        let (_, leaves, hashes, siblings) = slots(m2, [0]);
        let t2: ScanBook = book(NS, KEY, KEY, leaves, hashes, siblings, [0], 1);
        let bottom = quote_rates(t2, 872, [R[1]]);
        assert_eq(bottom.new_leaves[0], hdr_at(800005, 200000, 1000000, b, 1128, 2, R[1]));
        // the chain catching up to the top accrues nothing either; one block
        // past it accrues one block
        assert_eq(quote_rates(t2, 1128, [R[1]]).new_leaves[0][3], b);
        assert(quote_rates(t2, 1129, [R[1]]).new_leaves[0][3] != b);
    }

    // The supply index after accrual: the quote reports the pool's value per
    // share over the accrued total_debt, and a lender's withdrawal pays its
    // shares' part of the interest.
    #[test]
    fn the_supply_index_rises_with_accrual() {
        let mut m = kinked(2000000, 800000);
        m[2] = lend_leaf(10000, 9);
        m[0] = hdr_at(800000, 200000, 1000000, ONE, 0, 3, 7);
        let (_, leaves, hashes, siblings) = slots(m, [0]);
        let t: ScanBook = book(NS, KEY, KEY, leaves, hashes, siblings, [0], 1);
        // at block 0: 1.0 per share, 80% utilisation
        assert_eq(quote_rates(t, 0, [R[0]]).report.fields(), [0, ONE, 0, ONE, 0, 8000]);
        // 10,000 blocks: total_debt 800,368, the pool 1,000,368 over 10^6
        // shares; the utilisation floor(800,368 * 10^4 / 1,000,368) = 8,000
        let q = quote_rates(t, 10000, [R[0]]);
        assert_eq(q.report.fields(), [0, kink_index(10000), 0, 1000368000, 0, 8000]);
        // the lender's 10,000 shares were worth 10,000 and now pay 10,003
        let t2 = owner_book(m, 2);
        assert_eq(withdraw_supply(t2, [2, 10000], 0, [R[0], R[1]]).report.fields()[4], 10000);
        let s = withdraw_supply(t2, [2, 10000], 10000, [R[0], R[1]]);
        assert(s.outcome.ok);
        assert_eq(s.report.fields()[4], 10003);
        // and a supply at the moved value mints fewer shares: floor(10,000 *
        // 10^6 / 1,000,368) = 9,996
        let s = supply(t2, [2, 10000], 0, 10000, [R[0], R[1]]);
        assert_eq(s.report.fields()[2], 10000 + 9996);
    }

    /// The pool at the kink with a borrower of 1,000 collateral and 1,599
    /// debt touched at INDEX_ONE: healthy at 2.00 (1,599 < 1,600) until
    /// interest carries its debt past 1,600.
    fn creeping() -> Sparse {
        let mut b = [ZERO; 8];
        b[0] = hdr_at(800000, 200000, 1000000, ONE, 0, 3, 7);
        b[1] = bor_at(1000, 1599, ONE, 8);
        b[2] = bor_at(1000, 0, ONE, 9);
        b
    }

    // Health with accrued debt flips to liquidatable without any round
    // touching the position: the scan at block 0 reports it healthy, at block
    // 20,000 (debt 1,599 * 1.00092 = 1,600.47) unhealthy, and the
    // liquidation then liquidates it at its debt at the current index.
    #[test]
    fn health_flips_by_interest_alone() {
        let b = creeping();
        let (_, leaves, hashes, siblings) = slots(b, [0]);
        let t: ScanBook = book(NS, KEY, KEY, leaves, hashes, siblings, [0], 1);
        let (wl, wh, ws) = window_at(b, 0);
        let w = t.window::<WINDOW, WINDOW_HEIGHT, WINDOW_SIBLINGS>(0, wl, wh, ws);
        let early = scan(t, w, 200, 0, [R[0]]);
        assert_eq(early.report.fields(), [0, 0, 0, 0, 0, 2]);
        // 13,000 blocks is not enough: 1,599 * 1.000598 = 1,599.96
        assert_eq(scan(t, w, 200, 13000, [R[0]]).report.fields()[1], 0);
        let late = scan(t, w, 200, 20000, [R[0]]);
        assert_eq(late.report.fields(), [0, 2, 0, 0, 0, 2]);
        // the scan writes the accrual into the header
        assert_eq(late.new_leaves[0], hdr_at(800736, 200000, 1000000, kink_index(20000), 20000, 3, R[0]));
        // the liquidation at block 0 skips it; at 20,000 it brings it to the
        // index (ceil(1,600.47) = 1,601), repays 800, seizes floor(800 *
        // 1.05 / 2) = 420
        let at = liq_at([1], 1);
        let (_, leaves, hashes, siblings) = slots(b, at);
        let tl: ProbeBook = book(NS, KEY, KEY, leaves, hashes, siblings, at, 2);
        let l = liquidation(tl, liquidate(tl, [1, 1, U128_MAX], 200, 0, [R[0], R[1]]));
        assert_eq(l.mask, 0);
        let l = liquidation(tl, liquidate(tl, [1, 1, U128_MAX], 200, 20000, [R[0], R[1]]));
        assert_eq([l.mask, l.seize, l.repay], [1, 420, 800]);
        assert_eq(l.updated.stored[1], bor_at(580, 801, kink_index(20000), R[1]));
        assert_eq(l.updated.stored[0], hdr_at(800736 - 800, 200800, 1000000, kink_index(20000), 20000, 3, R[0]));
        // with 100 collateral the seize takes it all and the residual is
        // written off at the current index: debt' 1,601, repay 800, residual
        // 801, so total_debt' 800,736 falls by the whole 1,601
        let poor = with(b, 1, bor_at(100, 1599, ONE, 8));
        let (_, leaves, hashes, siblings) = slots(poor, at);
        let tp: ProbeBook = book(NS, KEY, KEY, leaves, hashes, siblings, at, 2);
        let l = liquidation(tp, liquidate(tp, [1, 1, U128_MAX], 200, 20000, [R[0], R[1]]));
        assert_eq([l.mask, l.seize, l.repay], [1, 100, 800]);
        assert_eq(l.updated.stored[1], bor_at(0, 0, kink_index(20000), R[1]));
        assert_eq(l.updated.stored[0], hdr_at(800736 - 1601, 200800, 1000000, kink_index(20000), 20000, 3, R[0]));
    }

    // Under the secret-shared intake the clock is a pinned value of the
    // attempt (the machine request id covers it) and the outcome reports
    // the accrued position.
    #[test]
    fn a_shared_round_reports_the_accrued_position() {
        let m = kinked(2000000, 800000);
        let t = owner_book(m, 1);
        let s = shared_round_at(t, view(t, [1], 100, [31, 32]), [1], 200, 100, true);
        reports(s, [0, 1, kink_index(100), 2000000, 800004, 0]);
        let at_zero = shared_round_at(t, view(t, [1], 100, [31, 32]), [1], 200, 0, true);
        assert(at_zero.outputs.machine_request_id != s.outputs.machine_request_id);
    }

    // ---- the secret-shared intakes (shared.nr): the same rounds, private outcomes ----

    // the secret-shared requests' reserved values: the user's partial note
    // (its owner and randomness never reach the round), the outcome key and
    // tag and the blinding
    global OUTCOME_KEY: Field = 0x6b;
    global OUTCOME_TAG: Field = 0x7a;
    global BLINDING: Field = 0xb1;
    global VK: Field = 0x7e57;
    /// The pinned price's epoch the secret-shared rounds read.
    global PRICE_EPOCH: Field = 1;
    /// The exit tag a position's leaf holds from the round that last wrote
    /// it, in the books that start with a tagged position.
    global OLD_TAG: Field = 0x7a90;

    /// The partial note every test request commits: Alice's address and
    /// randomness, as her request function computes it.
    fn partial() -> Field {
        partial_commitment(0xa11ce5, 0x9a)
    }

    /// The secret-shared intake of `inputs` (the app inputs before
    /// `$partial_note`): C over them, or a C they do not open when `good` is
    /// false.
    fn intake<let I: u32>(inputs: [Field; I], good: bool) -> SharedIntake {
        let c = commit(inputs.concat([partial(), OUTCOME_KEY, OUTCOME_TAG]), BLINDING);
        SharedIntake {
            inputs_hash: if good { c } else { c + 1 },
            partial: partial(),
            outcome_key: OUTCOME_KEY,
            outcome_tag: OUTCOME_TAG,
            blinding: BLINDING,
        }
    }

    /// The main's prefix the round tests run under (shared.nr `finish`
    /// reads its namespace and vk hash).
    fn prefix() -> Prefix {
        Prefix { namespace: NS, vk_hash: VK, in_slots: [KEY], out_slots: [KEY] }
    }

    /// The pinned values at `price` and `clock`.
    fn pinned(price: Field, clock: Field) -> Pinned {
        Pinned { price, price_epoch: PRICE_EPOCH, clock }
    }

    /// A round finished under the secret-shared intake of `inputs` at the
    /// pinned `clock`, on the book `B`: the clear book's `Updated`
    /// (`shared_round`, entry.nr's `Clear` entry) or the oblivious book's
    /// `Oblivious` (`oblivious_round`, entry.nr's `Oblivious` entry;
    /// `inputs` are what C commits, `[position, opens, amount]` for an
    /// opening round, entry.nr's `Opening`), on a tree loaded at the slots
    /// the nodes read.
    fn round_at<B, let K: u32, let I: u32>(
        t: Tree<K, DEPTH, LEAF_LEN>,
        s: Step<K>,
        inputs: [Field; I],
        price: Field,
        clock: Field,
        good: bool,
    ) -> Finished<B, Shared<K>>
    where
        B: Access<K, DEPTH, LEAF_LEN> + AppendIndex + Written<K>,
    {
        finish(prefix(), pinned(price, clock), t, s, true, inputs, Option::none(), intake(inputs, good), 777)
    }

    fn shared_round<let K: u32, let I: u32>(
        t: Tree<K, DEPTH, LEAF_LEN>,
        s: Step<K>,
        inputs: [Field; I],
        price: Field,
        good: bool,
    ) -> SharedRound<K> {
        round_at(t, s, inputs, price, CLOCK, good)
    }

    /// `shared_round` at the pinned `clock`.
    fn shared_round_at<let K: u32, let I: u32>(
        t: Tree<K, DEPTH, LEAF_LEN>,
        s: Step<K>,
        inputs: [Field; I],
        price: Field,
        clock: Field,
        good: bool,
    ) -> SharedRound<K> {
        round_at(t, s, inputs, price, clock, good)
    }

    fn oblivious_round<let K: u32, let I: u32>(
        t: Tree<K, DEPTH, LEAF_LEN>,
        s: Step<K>,
        inputs: [Field; I],
        price: Field,
        good: bool,
    ) -> ObliviousRound<K> {
        round_at(t, s, inputs, price, CLOCK, good)
    }

    /// The header with append index 2 and Alice's borrower position 1
    /// (1,000 collateral, no debt), its leaf holding OLD_TAG.
    fn tagged_book() -> Sparse {
        with(with([ZERO; 8], 0, hdr(0, LIQ, LIQ, 2, 7)), 1, tagged(bor_leaf(1000, 0, 8), OLD_TAG))
    }

    /// The requester's filler of the round of `request_id`: the exit value
    /// of a round that spends no tag (pss_core `exit_filler`, place 0).
    fn filler_of(request_id: Field) -> Field {
        exit_filler(partial(), request_id, 0)
    }

    /// A deposit, borrow or repay under both intakes on one book: the
    /// non-secret-shared round and the secret-shared one over the same inputs.
    fn s_dep(b: Sparse, position: Field, amount: Field, new_leaf: Field, good: bool) -> (OwnerRound, SharedRound<OWNER_SLOTS>) {
        let t = owner_book(b, placed(if position == 0 { new_leaf } else { position }));
        let s = deposit(t, [position, amount], new_leaf, CLOCK, [R[0], R[1]]);
        (owner_round(t, s), shared_round(t, s, [position, amount], 250, good))
    }

    fn s_bor(b: Sparse, position: Field, amount: Field, price: Field, good: bool) -> (OwnerRound, SharedRound<OWNER_SLOTS>) {
        let t = owner_book(b, placed(position));
        let s = borrow(t, [position, amount], price, CLOCK, [R[0], R[1]]);
        (owner_round(t, s), shared_round(t, s, [position, amount], price, good))
    }

    fn s_rep(b: Sparse, position: Field, amount: Field) -> (OwnerRound, SharedRound<OWNER_SLOTS>) {
        let t = owner_book(b, placed(position));
        let s = repay(t, [position, amount], CLOCK, [R[0], R[1]]);
        (owner_round(t, s), shared_round(t, s, [position, amount], 200, true))
    }

    fn s_wd(b: Sparse, position: Field, amount: Field, good: bool) -> (OwnerRound, SharedRound<OWNER_SLOTS>) {
        let t = owner_book(b, placed(position));
        let s = withdraw(t, [position, amount], 200, CLOCK, [R[0], R[1]]);
        (owner_round(t, s), shared_round(t, s, [position, amount], 200, good))
    }

    fn s_sup(b: Sparse, position: Field, amount: Field, new_leaf: Field, good: bool) -> SharedRound<OWNER_SLOTS> {
        let t = owner_book(b, placed(if position == 0 { new_leaf } else { position }));
        shared_round(t, supply(t, [position, amount], new_leaf, CLOCK, [R[0], R[1]]), [position, amount], 200, good)
    }

    fn s_wds(b: Sparse, position: Field, shares: Field, good: bool) -> SharedRound<OWNER_SLOTS> {
        let t = owner_book(b, placed(position));
        shared_round(t, withdraw_supply(t, [position, shares], CLOCK, [R[0], R[1]]), [position, shares], 200, good)
    }

    fn s_view(b: Sparse, position: Field) -> SharedRound<OWNER_SLOTS> {
        let t = owner_book(b, placed(position));
        shared_round(t, view(t, [position], CLOCK, [31, 32]), [position], 200, true)
    }

    fn s_liq(b: Sparse, positions: [Field; PROBES - 1], count: Field, good: bool) -> (Liquidation, SharedRound<PROBES>) {
        s_liq_with(b, positions, count, BUDGET, good)
    }

    /// `s_liq` with the liquidator's `budget`.
    fn s_liq_with(
        b: Sparse,
        positions: [Field; PROBES - 1],
        count: Field,
        budget: Field,
        good: bool,
    ) -> (Liquidation, SharedRound<PROBES>) {
        let at = liq_at(positions, count);
        let (_, leaves, hashes, siblings) = slots(b, at);
        let t: ProbeBook = book(NS, KEY, KEY, leaves, hashes, siblings, at, 1 + count);
        let inputs = positions.concat([count, budget]);
        // blindings other than the books', so a re-blinded leaf always
        // changes its hash
        let s = liquidate(t, inputs, 200, CLOCK, [41, 42]);
        (liquidation(t, s), shared_round(t, s, inputs, 200, good))
    }

    /// The round's outcome is `fields`, sealed in `o` over the book `u` the
    /// round leaves: its note the request's partial note completed with
    /// them and the chain request id, its ciphertext their encryption under
    /// the outcome key with that note hash's nonce (the mismatch domain's
    /// when the shares do not open C, code 14, whose plaintext is the code
    /// alone). A note that names a position p is one the round wrote: leaf
    /// p holds the note's exit tag, `exit_tag(P, request_id, p)` (P the
    /// request's partial note), so the note's exit spends what the leaf
    /// holds.
    fn sealed<let K: u32>(o: Shared<K>, u: Updated<K, LEAF_LEN>, fields: [Field; 7]) {
        if fields[0] == CODE_INPUTS_MISMATCH {
            assert_eq(fields, [CODE_INPUTS_MISMATCH, 0, 0, 0, 0, 0, 0]);
            let e = encrypt_mismatch::<7>(CODE_INPUTS_MISMATCH, OUTCOME_KEY, partial(), OUTCOME_SLOT, o.request_id);
            assert_eq(o.note_hashes, [e.note_hash]);
            assert_eq(o.ciphertext, e.ciphertext);
        } else {
            let e = encrypt_outcome(fields, OUTCOME_KEY, partial(), OUTCOME_SLOT, o.request_id);
            assert_eq(o.note_hashes, [e.note_hash]);
            assert_eq(o.ciphertext, e.ciphertext);
        }
        assert_eq(o.outcome_tag, OUTCOME_TAG);
        let p = fields[1];
        if (fields[0] != CODE_INPUTS_MISMATCH) & (p != 0) {
            // only an owner round names a position: its slot 1
            assert(K > 1);
            for k in 1..K {
                if k == 1 {
                    assert(u.write[k]);
                    assert_eq(u.stored[k][P_EXIT_TAG], exit_tag(partial(), o.request_id, p));
                    assert_eq(u.new_hashes[k], tree::leaf_hash(NS, KEY, p, u.stored[k]));
                }
            }
        }
    }

    /// `sealed` for a round over the clear book, whose public leaf hashes
    /// are the written ones.
    fn says<let K: u32>(r: SharedRound<K>, fields: [Field; 7]) {
        sealed(r.outputs, r.written, fields);
        assert_eq(r.outputs.new_hashes, r.written.new_hashes);
    }

    /// `sealed` for a round over the oblivious book, which outputs no leaf
    /// hash (zeros in their place).
    fn says_oblivious<let K: u32>(r: ObliviousRound<K>, fields: [Field; 7]) {
        sealed(r.outputs, r.written.updated, fields);
        assert_eq(r.outputs.new_hashes, [0; K]);
    }

    /// The round's outcome is `report` (`[code, position, mask, x, y,
    /// payout]`, aux 0: an owner round's, a liquidation's or a failed
    /// header-only round's); its app values are its exit value, the clear
    /// book's append index 0 (when it has a position slot) and the
    /// inputs-opened bit, 1 unless its code is 14; and its exit value is
    /// the requester's filler exactly when it wrote no position slot
    /// (`agrees` pins what a written slot spends).
    fn reports<let K: u32>(r: SharedRound<K>, report: [Field; 6]) {
        let values = r.outputs.app_values;
        assert_eq(values[EXIT_TAGS + K - 1], (report[0] != CODE_INPUTS_MISMATCH) as Field);
        if K > 1 {
            assert_eq(values[EXIT_TAGS], 0);
        }
        let mut writes_position = false;
        for k in 1..K {
            writes_position = writes_position | r.written.write[k];
        }
        assert_eq(values[0] == filler_of(r.outputs.request_id), !writes_position);
        says(r, report.concat([0]));
    }

    /// The non-secret-shared twin's code and position are the
    /// secret-shared outcome's, and an ok twin leaves the leaves the
    /// secret-shared round leaves, under the same blindings, but for the
    /// exit tag, which only the secret-shared round writes.
    fn twins(p: OwnerRound, s: SharedRound<OWNER_SLOTS>, report: [Field; 6]) {
        reports(s, report);
        // the non-secret-shared round's position output is 0 when not ok
        let position = if report[0] == 0 { report[1] } else { 0 };
        assert_eq([p.outcome.code, p.outcome.mask_field(p.position)], [report[0], position]);
        assert_eq(p.outcome.ok, report[0] == 0);
        assert_eq(s.outputs.old_commitments, [p.updated.old_c]);
        if p.outcome.ok {
            for k in 0..OWNER_SLOTS {
                assert_eq(untagged(s.written.stored[k]), untagged(p.updated.stored[k]));
            }
        }
    }

    /// The commitment the nodes' clear tree (sidecar-core tree/clear.rs
    /// `rebuild`) holds after the round: book `b`'s leaf hashes with each
    /// used slot's new hash written at its placed index, in slot order, a
    /// later slot of one index winning. Each placed index is below 8.
    fn node_tree<let K: u32>(b: Sparse, t: Tree<K, DEPTH, LEAF_LEN>, new_hashes: [Field; K]) -> Field {
        let mut level = [0; 8];
        for i in 0..8 {
            level[i] = hash_at(i, b[i]);
        }
        for k in 0..K {
            if t.used[k] {
                level[t.indices[k] as u32] = new_hashes[k];
            }
        }
        for l in 0..3 {
            for p in 0..8 {
                if p < (8 >> (l + 1)) {
                    level[p] = tree::node(level[2 * p], level[2 * p + 1]);
                }
            }
        }
        let z = tree::zeros::<DEPTH>();
        let mut root = level[0];
        for l in 3..DEPTH {
            root = tree::node(root, z[l]);
        }
        tree::commitment(NS, KEY, root)
    }

    /// The circuit's new commitment is the nodes' clear tree's after the
    /// round's new leaf hashes, and its exit value (the first app value) is
    /// what its write of book `b` spends (pss_core `Tagged::nullifiers`):
    /// the old leaf's tag where it wrote a position slot that held a leaf;
    /// where it opened an empty one, a value that is neither 0, the tag it
    /// stored nor the requester's filler; else the requester's filler.
    fn agrees<let K: u32>(b: Sparse, at: [Field; K], n_used: Field, r: SharedRound<K>) {
        let (_, leaves, hashes, siblings) = slots(b, at);
        let t: Tree<K, DEPTH, LEAF_LEN> = book(NS, KEY, KEY, leaves, hashes, siblings, at, n_used);
        assert_eq(r.outputs.new_commitments, [node_tree(b, t, r.outputs.new_hashes)]);
        let out = r.outputs.app_values[0];
        let filler = filler_of(r.outputs.request_id);
        let mut spends = false;
        // one position slot at most (EXIT_TAGS of them)
        for k in 1..K {
            if r.written.write[k] {
                spends = true;
                if hashes[k] != 0 {
                    assert_eq(out, leaves[k][P_EXIT_TAG]);
                } else {
                    assert(out != 0);
                    assert(out != r.written.stored[k][P_EXIT_TAG]);
                    assert(out != filler);
                }
            }
        }
        if !spends {
            assert_eq(out, filler);
        }
    }

    #[test]
    fn the_shared_race_reports_the_plain_outcomes() {
        let s0 = with([ZERO; 8], 0, hdr(0, LIQ, LIQ, 1, 7));
        // Alice opens position 1 with 1,000: mask INDEX_ONE, the borrower
        // kind's marker; the leaf holds her note's exit tag
        let (p, s) = s_dep(s0, 0, 1000, 1, true);
        twins(p, s, [0, 1, ONE, 1000, 0, 0]);
        let s1 = with(
            with(s0, 0, hdr(0, LIQ, LIQ, 2, R[0])),
            1,
            tagged(bor_leaf(1000, 0, R[1]), exit_tag(partial(), s.outputs.request_id, 1)),
        );
        assert_eq(s.outputs.new_commitments, [commitment(s1)]);
        agrees(s0, [0, 1], 2, s);
        // she borrows 1,700 at 2.50: the payout is the amount; the round
        // spends the deposit's tag and stores the borrow's
        let (p, s) = s_bor(s1, 1, 1700, 250, true);
        twins(p, s, [0, 1, ONE, 1000, 1700, 1700]);
        let s2 = with(
            with(s1, 0, hdr(1700, LIQ - 1700, LIQ, 2, R[0])),
            1,
            tagged(bor_leaf(1000, 1700, R[1]), exit_tag(partial(), s.outputs.request_id, 1)),
        );
        assert_eq(s.outputs.new_commitments, [commitment(s2)]);
        agrees(s1, [0, 1], 2, s);
        // a view after the deposit and the borrow reports the position and
        // re-blinds its leaves only, the position's under a new tag
        let v = s_view(s2, 1);
        reports(v, [0, 1, ONE, 1000, 1700, 0]);
        assert(v.outputs.new_commitments[0] != commitment(s2));
        assert_eq(
            v.written.stored,
            [hdr(1700, LIQ - 1700, LIQ, 2, 31), tagged(bor_leaf(1000, 1700, 32), exit_tag(partial(), v.outputs.request_id, 1))],
        );
        agrees(s2, [0, 1], 2, v);
        // Bob opens position 2
        let (p, s) = s_dep(s2, 0, 1000, 2, true);
        twins(p, s, [0, 2, ONE, 1000, 0, 0]);
        let s3 = with(
            with(s2, 0, hdr(1700, LIQ - 1700, LIQ, 3, R[0])),
            2,
            tagged(bor_leaf(1000, 0, R[1]), exit_tag(partial(), s.outputs.request_id, 2)),
        );
        assert_eq(s.outputs.new_commitments, [commitment(s3)]);
        agrees(s2, [0, 2], 2, s);
        // race (a): Alice repays 400, then the liquidation liquidates nothing:
        // it re-blinds the header and leaves its probe, whose leaf, leaf
        // hash and exit tag stay (her note of the repayment stays her
        // newest, its tag unspent)
        let (p, s) = s_rep(s3, 1, 400);
        twins(p, s, [0, 1, ONE, 1000, 1300, 0]);
        agrees(s3, [0, 1], 2, s);
        let s4 = with(
            with(s3, 0, hdr(1300, LIQ - 1300, LIQ, 3, R[0])),
            1,
            tagged(bor_leaf(1000, 1300, R[1]), exit_tag(partial(), s.outputs.request_id, 1)),
        );
        assert_eq(s.outputs.new_commitments, [commitment(s4)]);
        let (l, s) = s_liq(s4, [1], 1, true);
        assert(l.outcome.ok & (l.mask == 0));
        assert_eq(l.updated.write, [true, false]);
        assert_eq(s.written.write, [true, false]);
        assert_eq(s.outputs.new_hashes[1], hash_at(1, s4[1]));
        assert_eq(s.written.stored[1], s4[1]);
        // nothing repaid: the whole budget comes back
        reports(s, [0, 0, 0, 0, 0, BUDGET]);
        assert(s.outputs.new_commitments[0] != commitment(s4));
        agrees(s4, [0, 1], 2, s);
        // its exit value is the liquidator's filler, as a quote's or a scan's
        assert_eq(s.outputs.app_values[0], filler_of(s.outputs.request_id));
        // a liquidation that fails (no price) also leaves its probe
        let at = liq_at([1], 1);
        let (_, leaves, hashes, siblings) = slots(s4, at);
        let t: ProbeBook = book(NS, KEY, KEY, leaves, hashes, siblings, at, 2);
        let f = shared_round(t, liquidate(t, [1, 1, BUDGET], 0, CLOCK, [41, 42]), [1, 1, BUDGET], 0, true);
        reports(f, [CODE_PRICE, 0, 0, 0, 0, BUDGET]);
        assert_eq(f.outputs.new_hashes[1], hash_at(1, s4[1]));
        assert_eq(f.outputs.app_values[0], filler_of(f.outputs.request_id));
        agrees(s4, at, 2, f);
        // race (b): the liquidation first: mask 1, seize 446 (x, paid in the
        // collateral asset), repay 850, as the non-secret-shared round, and
        // the 150 of the budget it did not use (the payout); it writes the
        // probe it liquidated and spends the borrow's tag there
        let (l, s) = s_liq(s3, [1], 1, true);
        assert_eq([l.mask, l.seize, l.repay], [1, 446, 850]);
        reports(s, [0, 0, 1, 446, 850, BUDGET - 850]);
        assert_eq(untagged(s.written.stored[1]), untagged(l.updated.stored[1]));
        agrees(s3, [0, 1], 2, s);
        assert_eq(s.outputs.app_values[0], s3[1][P_EXIT_TAG]);
        assert(s.outputs.new_hashes[1] != hash_at(1, s3[1]));
    }

    #[test]
    fn a_failed_shared_round_names_only_a_position_it_vouches_for_and_re_blinds() {
        let m = with(with([ZERO; 8], 0, hdr(0, LIQ, LIQ, 2, 7)), 1, bor_leaf(1000, 0, 8));
        // a borrow that fails (1,700 at 2.00 is past the limit): code 9; the
        // request named an open leaf its owner's note admitted, so the note
        // reports the position as it stands (and the leaf holds its tag);
        // every leaf re-blinded
        let (p, s) = s_bor(m, 1, 1700, 200, true);
        twins(p, s, [CODE_LIMIT, 1, ONE, 1000, 0, 0]);
        assert(s.outputs.new_commitments[0] != s.outputs.old_commitments[0]);
        assert_eq(
            s.written.stored,
            [hdr(0, LIQ, LIQ, 2, R[0]), tagged(bor_leaf(1000, 0, R[1]), exit_tag(partial(), s.outputs.request_id, 1))],
        );
        agrees(m, [0, 1], 2, s);
        assert_eq(p.updated.new_c, p.updated.old_c);
        // a borrow or a view of a leaf that is not open (no note of it can
        // exist, so only a request the contract never admits names it): code 5
        let (p, s) = s_bor(m, 3, 10, 250, true);
        twins(p, s, [CODE_KIND, 0, 0, 0, 0, 0]);
        agrees(m, [0, 3], 2, s);
        reports(s_view(m, 3), [CODE_KIND, 0, 0, 0, 0, 0]);
        // shares that do not open C: code 14 first, ahead of the round's
        let (_, s) = s_bor(m, 1, 1700, 250, false);
        reports(s, [CODE_INPUTS_MISMATCH, 0, 0, 0, 0, 0]);
        let (_, s) = s_bor(m, 1, 10, 250, false);
        reports(s, [CODE_INPUTS_MISMATCH, 0, 0, 0, 0, 0]);
        assert(s.outputs.new_commitments[0] != s.outputs.old_commitments[0]);
        // the request id is the secret-shared one over C, whatever the outcome
        let c = commit([1, 10, partial(), OUTCOME_KEY, OUTCOME_TAG], BLINDING);
        assert_eq(s.outputs.request_id, shared(NS, VK, c + 1));
        // an opening that fails on the shares leaves its empty slot empty
        let (_, s) = s_dep(m, 0, 10, 2, false);
        reports(s, [CODE_INPUTS_MISMATCH, 0, 0, 0, 0, 0]);
        assert_eq(s.written.new_hashes[1], 0);
        agrees(m, [0, 2], 2, s);
        // an opening past the append index (2) is code 17, not a placement
        // failure: the header is re-blinded and the opening slot stays empty;
        // its amount comes back in payout with the collateral asset's bit,
        // and the note names no position (a note of $new_leaf would own an
        // index someone else opens later)
        let (p, s) = s_dep(m, 0, 10, 4, true);
        twins(p, s, [CODE_APPEND_INDEX, 0, 0, 0, 0, ASSET_BIT + 10]);
        assert_eq(s.written.new_hashes[1], 0);
        assert_eq(s.written.stored, [hdr(0, LIQ, LIQ, 2, R[0]), [0; LEAF_LEN]]);
        assert(s.outputs.new_commitments[0] != commitment(m));
        agrees(m, [0, 4], 2, s);
        // a deposit into an open position that fails (collateral overflows):
        // the position as it stands, the amount back in the collateral asset
        let (p, s) = s_dep(m, 1, U128_MAX - 999, 0, true);
        twins(p, s, [CODE_OVERFLOW, 1, ONE, 1000, 0, ASSET_BIT + U128_MAX - 999]);
        // a withdrawal past the collateral, and one past the limit, report the
        // position and pay nothing
        let debt = with(with(m, 0, hdr(1200, LIQ - 1200, LIQ, 2, 7)), 1, bor_leaf(1000, 1200, 8));
        let (_, s) = s_wd(debt, 1, 1001, true);
        reports(s, [CODE_EXCEEDS_COLLATERAL, 1, ONE, 1000, 1200, 0]);
        let (_, s) = s_wd(debt, 1, 201, true);
        reports(s, [CODE_LIMIT, 1, ONE, 1000, 1200, 0]);
        let (_, s) = s_wd(debt, 1, 200, true);
        reports(s, [0, 1, ONE, 800, 1200, ASSET_BIT + 200]);
        let (_, s) = s_wd(debt, 1, 200, false);
        reports(s, [CODE_INPUTS_MISMATCH, 0, 0, 0, 0, 0]);
    }

    // A round that does not apply returns its escrow in the outcome's
    // payout with its asset bit: a deposit's amount in the collateral asset,
    // a repayment's, a supply's and a liquidation's whole budget in the
    // borrowed asset; a borrow, a withdrawal, a withdrawal of supply and a
    // view escrow nothing. Shares that do not open C return nothing (their
    // amounts and their recipient are not the user's): their inputs-opened
    // bit is 0, and the contract's apply refunds the escrow.
    #[test]
    fn a_failed_shared_round_returns_its_escrow_unless_its_shares_miss_c() {
        let m = with(with([ZERO; 8], 0, hdr(1700, LIQ - 1700, LIQ, 2, 7)), 1, bor_leaf(1000, 1700, 8));
        // a repayment of more than the debt applies: the excess comes back
        let (_, s) = s_rep(m, 1, 1701);
        reports(s, [0, 1, ONE, 1000, 0, 1]);
        let full = with(m, 0, hdr(1700, U128_MAX - 1000, LIQ, 2, 7));
        let (_, s) = s_rep(full, 1, 1700);
        reports(s, [CODE_OVERFLOW, 1, ONE, 1000, 1700, 1700]);
        let (p, s) = s_dep(m, 3, 10, 0, true);
        twins(p, s, [CODE_KIND, 0, 0, 0, 0, ASSET_BIT + 10]);
        let (_, s) = s_dep(m, 1, 10, 0, false);
        reports(s, [CODE_INPUTS_MISMATCH, 0, 0, 0, 0, 0]);
        let (_, s) = s_liq_with(m, [1], 0, 777, true);
        reports(s, [CODE_POSITION_RANGE, 0, 0, 0, 0, 777]);
        let (_, s) = s_liq_with(m, [1], 1, 777, false);
        reports(s, [CODE_INPUTS_MISMATCH, 0, 0, 0, 0, 0]);
        // an applied liquidation of position 1 at 2.00 with 777: all of it
        // repaid (below the close of 850), nothing returned
        let (l, s) = s_liq_with(m, [1], 1, 777, true);
        assert_eq([l.mask, l.repay], [1, 777]);
        reports(s, [0, 0, 1, l.seize, 777, 0]);
        // a supply into a borrower's position: code 5, its amount back
        reports(s_sup(m, 1, 50, 0, true), [CODE_KIND, 0, 0, 0, 0, 50]);
    }

    // Shares that do not open C leave every position's leaf: the position is
    // an unbound witness then, so the prover may place any live index (here
    // position 1, someone else's), and a write there would spend its
    // owner's exit tag without a note for it. Such a round re-blinds the
    // header alone, writes no position slot, outputs the requester's filler
    // and its note names nothing, for every owner round type, on the clear
    // book and on the oblivious one: the victim's leaf, leaf hash and tag
    // are untouched.
    #[test]
    fn a_code_14_round_leaves_a_foreign_live_leaf() {
        let m = with(with([ZERO; 8], 0, hdr(1700, LIQ - 1700, LIQ, 2, 7)), 1, tagged(bor_leaf(1000, 1700, 8), OLD_TAG));
        let victim = hash_at(1, m[1]);
        let rounds = [
            s_bor(m, 1, 10, 250, false).1,
            s_wd(m, 1, 10, false).1,
            s_dep(m, 1, 10, 0, false).1,
            s_sup(m, 1, 10, 0, false),
            s_wds(m, 1, 10, false),
        ];
        for s in rounds {
            reports(s, [CODE_INPUTS_MISMATCH, 0, 0, 0, 0, 0]);
            assert_eq(s.written.write, [true, false]);
            assert_eq(s.outputs.new_hashes[1], victim);
            assert_eq(s.written.stored[1], m[1]);
            assert(s.outputs.new_commitments[0] != s.outputs.old_commitments[0]);
            assert_eq(s.outputs.app_values, [filler_of(s.outputs.request_id), 0, 0]);
            agrees(m, [0, 1], 2, s);
        }
        // the same request whose shares open C re-blinds the position too,
        // spending the tag it held
        let (_, s) = s_wd(m, 1, 10, true);
        assert_eq(s.written.write, [true, true]);
        assert(s.outputs.new_hashes[1] != victim);
        assert_eq(s.outputs.app_values[0], OLD_TAG);
        // the oblivious book writes the header alone as well; its append
        // index is the header's, 2
        let t = owner_book(m, placed(1));
        let step = withdraw(t, [1, 10], 200, CLOCK, [R[0], R[1]]);
        let o = oblivious_round(t, step, [1, 10], 200, false);
        says_oblivious(o, [CODE_INPUTS_MISMATCH, 0, 0, 0, 0, 0, 0]);
        assert_eq(o.written.updated.write, [true, false]);
        assert_eq(o.written.updated.new_hashes[1], victim);
        assert_eq(o.written.updated.stored[1], m[1]);
        assert_eq(o.outputs.app_values, [filler_of(o.outputs.request_id), 2, 0]);
        // opened: 10 past the limit (1,700 debt on 990 at 2.00), code 9,
        // the position re-blinded under the note's tag
        let o = oblivious_round(t, step, [1, 10], 200, true);
        says_oblivious(o, [CODE_LIMIT, 1, ONE, 1000, 1700, 0, 0]);
        assert_eq(o.written.updated.write, [true, true]);
        assert_eq(o.outputs.app_values, [OLD_TAG, 2, 1]);
    }

    // The lender rounds under the secret-shared intake: the note names the
    // lender's position with mask 0 (the lender kind's marker), its shares
    // and their value; a borrower round on a lender's leaf is code 5 and
    // names nothing; a failed withdrawal of supply names the position as it
    // stands.
    #[test]
    fn the_shared_lender_rounds_report_shares_and_value() {
        let b = lent_book();
        let s = s_sup(b, 1, 1100, 0, true);
        reports(s, [0, 1, 0, 3002, 3295, 0]);
        let s = s_sup(b, 0, 1100, 2, true);
        reports(s, [0, 2, 0, 1002, 1100, 0]);
        agrees(b, [0, 2], 2, s);
        reports(s_sup(b, 1, 1, 0, true), [CODE_ZERO_QUOTIENT, 1, 0, 2000, 2195, 1]);
        reports(s_sup(b, 0, 1, 2, true), [CODE_ZERO_QUOTIENT, 0, 0, 0, 0, 1]);
        reports(s_wds(b, 1, 1000, true), [0, 1, 0, 1000, 1097, 1097]);
        reports(s_wds(b, 1, 2001, true), [CODE_EXCEEDS_SHARES, 1, 0, 2000, 2195, 0]);
        reports(s_wds(b, 1, 1000, false), [CODE_INPUTS_MISMATCH, 0, 0, 0, 0, 0]);
        let (_, s) = s_bor(b, 1, 10, 250, true);
        reports(s, [CODE_KIND, 0, 0, 0, 0, 0]);
        reports(s_view(b, 1), [0, 1, 0, 2000, 2195, 0]);
    }

    // Under a full book or an out-of-range position the placement fails,
    // nothing is written, and the circuit's root is the nodes' clear tree's
    // (sidecar-core tree/clear.rs `rebuild` over the round's new leaf hashes),
    // whatever the placed indices.
    #[test]
    fn a_flagged_placement_leaves_the_nodes_tree() {
        let m = with(
            with(with([ZERO; 8], 0, hdr(1700, LIQ - 1700, LIQ, 3, 7)), 1, bor_leaf(1000, 1700, 8)),
            2,
            bor_leaf(1000, 0, 9),
        );
        // code 16: an opening with the book full ($new_leaf 0: slot 1 at
        // index 0, the header's)
        let (_, s) = s_dep(m, 0, 10, 0, true);
        reports(s, [CODE_FULL_BOOK, 0, 0, 0, 0, ASSET_BIT + 10]);
        assert_eq(s.outputs.new_commitments, [commitment(m)]);
        agrees(m, [0, 0], 2, s);
        // code 3: a position 2^D (placed at index 0) and p - 1, and a
        // liquidation count of 0
        for position in [TWO_POW_D, P_MINUS_1] {
            let (_, s) = s_bor(m, position, 10, 250, true);
            reports(s, [CODE_POSITION_RANGE, 0, 0, 0, 0, 0]);
            assert_eq(s.outputs.new_commitments, [commitment(m)]);
            agrees(m, [0, 0], 2, s);
        }
        let (_, s) = s_liq(m, [1], 0, true);
        reports(s, [CODE_POSITION_RANGE, 0, 0, 0, 0, BUDGET]);
        assert_eq(s.outputs.new_commitments, [commitment(m)]);
        agrees(m, [0, 0], 1, s);
        // the same shares mismatch on a placement failure: code 14 reported,
        // nothing written
        let (_, s) = s_liq(m, [1], 0, false);
        reports(s, [CODE_INPUTS_MISMATCH, 0, 0, 0, 0, 0]);
        agrees(m, [0, 0], 1, s);
        assert_eq(s.outputs.new_commitments, [commitment(m)]);
    }

    // ---- the exit tag (pss_core tip::exit; market.nr P_EXIT_TAG) ----

    // A borrow refused at the limit still vouches for the position: it
    // re-blinds the leaf under a new tag, its requester's note's, spends the
    // tag the leaf held, and its note names the position.
    #[test]
    fn a_borrow_refused_at_the_limit_re_tags_the_position() {
        let m = tagged_book();
        let (_, s) = s_bor(m, 1, 1700, 200, true);
        reports(s, [CODE_LIMIT, 1, ONE, 1000, 0, 0]);
        assert_eq(s.written.write, [true, true]);
        assert_eq(
            s.written.stored[1],
            tagged(bor_leaf(1000, 0, R[1]), exit_tag(partial(), s.outputs.request_id, 1)),
        );
        assert_eq(s.outputs.app_values, [OLD_TAG, 0, 1]);
        agrees(m, [0, 1], 2, s);
    }

    // An opening (position 0) stores the tag of its requester's note at
    // the leaf it opens and spends none: its exit value is neither that tag
    // nor the filler, and its note names the new leaf. An opening that fails
    // writes no position and outputs the filler.
    #[test]
    fn an_opening_stores_its_tag_and_spends_none() {
        let m = tagged_book();
        let (p, s) = s_dep(m, 0, 500, 2, true);
        twins(p, s, [0, 2, ONE, 500, 0, 0]);
        let rid = s.outputs.request_id;
        let tag = exit_tag(partial(), rid, 2);
        assert_eq(s.written.stored[1], tagged(bor_leaf(500, 0, R[1]), tag));
        let out = s.outputs.app_values[0];
        assert(out != 0);
        assert(out != tag);
        assert(out != filler_of(rid));
        agrees(m, [0, 2], 2, s);
        // a supply opens a lender leaf the same way
        let s = s_sup(m, 0, 500, 2, true);
        assert_eq(s.written.stored[1][P_EXIT_TAG], exit_tag(partial(), s.outputs.request_id, 2));
        agrees(m, [0, 2], 2, s);
        // past the append index (code 17): nothing at the leaf, the filler out
        let (_, s) = s_dep(m, 0, 10, 4, true);
        reports(s, [CODE_APPEND_INDEX, 0, 0, 0, 0, ASSET_BIT + 10]);
        assert_eq(s.written.write, [true, false]);
        assert_eq(s.written.new_hashes[1], 0);
        assert_eq(s.outputs.app_values, [filler_of(s.outputs.request_id), 0, 1]);
        // shares that do not open C: the same
        let (_, s) = s_dep(m, 0, 10, 2, false);
        assert_eq(s.written.write, [true, false]);
        assert_eq(s.outputs.app_values, [filler_of(s.outputs.request_id), 0, 0]);
    }

    // Two attempts of one request (other blindings, another pinned clock,
    // so another machine request id) store the same tag and output the same
    // values: the tag and the exit value depend on the chain request id
    // alone, so every attempt lands the same nullifiers.
    #[test]
    fn the_attempts_of_one_request_agree_on_the_exit() {
        let m = tagged_book();
        let t = owner_book(m, 1);
        let a = shared_round_at(t, borrow(t, [1, 10], 250, CLOCK, [R[0], R[1]]), [1, 10], 250, CLOCK, true);
        let b = shared_round_at(t, borrow(t, [1, 10], 250, 5, [31, 32]), [1, 10], 250, 5, true);
        assert_eq(a.outputs.request_id, b.outputs.request_id);
        assert(a.outputs.machine_request_id != b.outputs.machine_request_id);
        assert(a.outputs.new_hashes[1] != b.outputs.new_hashes[1]);
        assert_eq(a.written.stored[1][P_EXIT_TAG], b.written.stored[1][P_EXIT_TAG]);
        assert_eq(a.outputs.app_values, b.outputs.app_values);
        assert_eq(a.outputs.app_values, [OLD_TAG, 0, 1]);
        // an opening's exit value too
        let to = owner_book(m, 2);
        let a = shared_round_at(to, deposit(to, [0, 500], 2, CLOCK, [R[0], R[1]]), [0, 500], 250, CLOCK, true);
        let b = shared_round_at(to, deposit(to, [0, 500], 2, 5, [31, 32]), [0, 500], 250, 5, true);
        assert(a.outputs.machine_request_id != b.outputs.machine_request_id);
        assert(a.outputs.new_hashes[1] != b.outputs.new_hashes[1]);
        assert_eq(a.written.stored[1][P_EXIT_TAG], b.written.stored[1][P_EXIT_TAG]);
        assert_eq(a.outputs.app_values, b.outputs.app_values);
    }

    // An owner round's app values: its exit value, the book's append index
    // and the inputs-opened bit; the append index is 0 on the clear book
    // and the header's as stored on the oblivious one (an opening's after
    // it, which the nodes advance theirs to).
    #[test]
    fn an_owner_rounds_app_values_carry_the_append_index_on_the_oblivious_book() {
        let m = tagged_book();
        let (_, s) = s_bor(m, 1, 10, 250, true);
        reports(s, [0, 1, ONE, 1000, 10, 10]);
        assert_eq(s.outputs.app_values, [OLD_TAG, 0, 1]);
        let t = owner_book(m, 1);
        let o = oblivious_round(t, borrow(t, [1, 10], 250, CLOCK, [R[0], R[1]]), [1, 10], 250, true);
        says_oblivious(o, [0, 1, ONE, 1000, 10, 10, 0]);
        assert_eq(o.outputs.app_values, [OLD_TAG, 2, 1]);
        // an opening on the oblivious book (C commits [position, opens,
        // amount], entry.nr's `Opening`): the header's next index after it
        let to = owner_book(m, 2);
        let o = oblivious_round(to, deposit(to, [0, 500], 2, CLOCK, [R[0], R[1]]), [0, 1, 500], 250, true);
        says_oblivious(o, [0, 2, ONE, 500, 0, 0, 0]);
        let values = o.outputs.app_values;
        assert_eq([values[1], values[2]], [3, 1]);
        assert(values[0] != filler_of(o.outputs.request_id));
        assert(values[0] != o.written.updated.stored[1][P_EXIT_TAG]);
    }

    // The oblivious deployment composes a position input past the tree at
    // its low bits (`tree::slot_indices`; here leaf 1, someone else's), the
    // slot the nodes read: the round loads that leaf's real path, `load`'s
    // one assertion holds, and the raw input's range flag refuses it (code
    // 3) as the clear deployment's does, a flagged no-op rather than an
    // unprovable round. It writes nothing, that leaf keeps its leaf and tag,
    // and the round outputs the filler; its note names nothing.
    #[test]
    fn an_oblivious_position_past_the_tree_is_not_written() {
        let m = tagged_book();
        let position = TWO_POW_D + 1;
        let at = tree::slot_indices::<1, DEPTH>([position], 1, false, 0);
        assert_eq(at, [0, 1]);
        let t = owner_book(m, at[1]);
        let o = oblivious_round(t, borrow(t, [position, 10], 250, CLOCK, [R[0], R[1]]), [position, 10], 250, true);
        says_oblivious(o, [CODE_POSITION_RANGE, 0, 0, 0, 0, 0, 0]);
        assert_eq(o.written.updated.write, [false, false]);
        assert_eq(o.written.updated.stored[1], m[1]);
        assert_eq(o.outputs.new_commitments, o.outputs.old_commitments);
        assert_eq(o.outputs.app_values, [filler_of(o.outputs.request_id), 2, 1]);
    }

    // ---- the keeper's scan ----

    /// The window of WINDOW leaves at `at` (0 or 8) of a sparse book as the
    /// nodes place it: the leaves, their old hashes and the window root's
    /// siblings (window 0's root is the sparse range's; window 8 is empty,
    /// its first sibling window 0's root).
    fn window_at(b: Sparse, at: Field) -> ([Leaf; WINDOW], [Field; WINDOW], [Field; WINDOW_SIBLINGS]) {
        let z = tree::zeros::<DEPTH>();
        let (_, _, _, s0) = slots(b, [0]);
        let mut leaves = [ZERO; WINDOW];
        let mut hashes = [0; WINDOW];
        let mut siblings = [0; WINDOW_SIBLINGS];
        for l in 0..WINDOW_SIBLINGS {
            siblings[l] = z[WINDOW_HEIGHT + l];
        }
        if at == 0 {
            for j in 0..WINDOW {
                leaves[j] = b[j];
                hashes[j] = hash_at(j, b[j]);
            }
        } else {
            // window 8's sibling at height 3 is window 0's root: rebuild it
            // from leaf 0's path below height 3
            let mut root = hash_at(0, b[0]);
            for l in 0..WINDOW_HEIGHT {
                root = tree::node(root, s0[0][l]);
            }
            siblings[0] = root;
        }
        (leaves, hashes, siblings)
    }

    /// A scan of `start` at `price` as the nodes place it (the window at the
    /// effective start, 0 for a bad one), its non-secret-shared step and its secret-shared
    /// round.
    fn s_scan(b: Sparse, start: Field, price: Field, good: bool) -> (Step<SCAN_SLOTS>, SharedRound<SCAN_SLOTS>) {
        let (_, leaves, hashes, siblings) = slots(b, [0]);
        let t: ScanBook = book(NS, KEY, KEY, leaves, hashes, siblings, [0], 1);
        let effective = if (start == 0) | (start == 8) { start } else { 0 };
        let (wl, wh, ws) = window_at(b, effective);
        let w = t.window::<WINDOW, WINDOW_HEIGHT, WINDOW_SIBLINGS>(start, wl, wh, ws);
        let s = scan(t, w, price, CLOCK, [R[0]]);
        (s, shared_round(t, s, [start], price, good))
    }

    /// Alice (1,000 / 1,700) and Carol (500 / 900) unhealthy at 2.00, Bob
    /// (1,000, no debt) healthy, at positions 1, 2 and 3, and a lender at 4
    /// (occupied, never unhealthy); the header's totals (which the scan does
    /// not read as a position) are not a position's.
    fn keeper_book() -> Sparse {
        let mut b = [ZERO; 8];
        b[0] = hdr(2600, LIQ - 2600, LIQ + 500, 5, 7);
        b[1] = bor_leaf(1000, 1700, 8);
        b[2] = bor_leaf(1000, 0, 9);
        b[3] = bor_leaf(500, 900, 10);
        b[4] = lend_leaf(500, 11);
        b
    }

    #[test]
    fn a_scan_reports_the_windows_unhealthy_positions() {
        let b = keeper_book();
        let (step, s) = s_scan(b, 0, 200, true);
        assert(step.placed);
        // bits 1 and 3 (Alice, Carol: 0b1010), four occupied (the lender
        // among them), the header neither: [code, 0, report, 0, start, 0,
        // occupied], position 0 and x 0, so the keeper's note confers nothing
        // and pays nothing
        says(s, [0, 0, 10, 0, 0, 0, 4]);
        // one exit value, the keeper's filler, then the inputs-opened bit
        assert_eq(s.outputs.app_values, [filler_of(s.outputs.request_id), 1]);
        // only the header is written, re-blinded: the commitment moves
        assert_eq(s.written.stored, [hdr(2600, LIQ - 2600, LIQ + 500, 5, R[0])]);
        assert(s.outputs.new_commitments[0] != s.outputs.old_commitments[0]);
        assert_eq(s.outputs.old_commitments, [commitment(b)]);
        assert_eq(s.outputs.new_commitments, [commitment(with(b, 0, hdr(2600, LIQ - 2600, LIQ + 500, 5, R[0])))]);
        agrees(b, [0], 1, s);
        // at 2.20 Alice is healthy (1000 * 220 * 8000 >= 1700 * 100 * 10000)
        // and Carol is not (0b1000)
        let (_, s) = s_scan(b, 0, 220, true);
        says(s, [0, 0, 8, 0, 0, 0, 4]);
    }

    #[test]
    fn an_empty_window_and_one_past_the_book_report_nothing() {
        // window 0 of a book with no position: the header only
        let empty = with([ZERO; 8], 0, hdr(0, LIQ, LIQ, 1, 7));
        let (_, s) = s_scan(empty, 0, 200, true);
        says(s, [0, 0, 0, 0, 0, 0, 0]);
        assert(s.outputs.new_commitments[0] != s.outputs.old_commitments[0]);
        // window 8, past the keeper book's positions: the keeper stops
        let (step, s) = s_scan(keeper_book(), 8, 200, true);
        assert(step.placed);
        says(s, [0, 0, 0, 0, 8, 0, 0]);
        agrees(keeper_book(), [0], 1, s);
    }

    #[test]
    fn a_scan_flags_its_start_its_window_and_the_price() {
        let b = keeper_book();
        // code 3: unaligned, 2^D, p - 1; the nodes place window 0, and
        // nothing is written
        for start in [4, TWO_POW_D, P_MINUS_1] {
            let (step, s) = s_scan(b, start, 200, true);
            assert(!step.placed);
            reports(s, [CODE_POSITION_RANGE, 0, 0, 0, 0, 0]);
            assert_eq(s.outputs.new_commitments, [commitment(b)]);
        }
        // code 6: no price; the header is still re-blinded
        let (_, s) = s_scan(b, 0, 0, true);
        reports(s, [CODE_PRICE, 0, 0, 0, 0, 0]);
        assert(s.outputs.new_commitments[0] != commitment(b));
        // code 4: a window leaf's debt not a u128
        let bad = with(b, 2, bor_leaf(1000, TWO_POW_128, 9));
        let (step, s) = s_scan(bad, 0, 200, true);
        assert(step.placed);
        reports(s, [CODE_BAD_STATE, 0, 0, 0, 0, 0]);
        // code 4: the nodes placed another window's siblings, nothing written
        let (_, leaves, hashes, siblings) = slots(b, [0]);
        let t: ScanBook = book(NS, KEY, KEY, leaves, hashes, siblings, [0], 1);
        let (wl, wh, mut ws) = window_at(b, 0);
        ws[0] = 1;
        let step = scan(t, t.window::<WINDOW, WINDOW_HEIGHT, WINDOW_SIBLINGS>(0, wl, wh, ws), 200, CLOCK, [R[0]]);
        assert(!step.placed);
        assert_eq(step.outcome.code, CODE_BAD_STATE);
        // code 14 first
        let (_, s) = s_scan(b, 4, 0, false);
        reports(s, [CODE_INPUTS_MISMATCH, 0, 0, 0, 0, 0]);
        assert_eq(s.outputs.app_values, [filler_of(s.outputs.request_id), 0]);
    }

    // The quote under the secret-shared intake: no app input, C over the
    // reserved values alone; position 0 and x 0, so its note confers and
    // pays nothing; only the header is written, re-blinded.
    #[test]
    fn a_shared_quote_reports_the_rates_and_re_blinds_the_header() {
        let b = lent_book();
        let (_, leaves, hashes, siblings) = slots(b, [0]);
        let t: ScanBook = book(NS, KEY, KEY, leaves, hashes, siblings, [0], 1);
        let s = shared_round(t, quote_rates(t, CLOCK, [R[0]]), [], 200, true);
        // 1,100,000 * 10^9 / 1,002,000 and 100,000 * 10,000 / 1,100,000
        says(s, [0, 0, ONE, 0, 1097804391, 0, 909]);
        // one exit value, the quoter's filler, then the inputs-opened bit
        assert_eq(s.outputs.app_values, [filler_of(s.outputs.request_id), 1]);
        assert_eq(s.written.stored, [hdr(100000, 1000000, 1002000, 2, R[0])]);
        agrees(b, [0], 1, s);
        let s = shared_round(t, quote_rates(t, CLOCK, [R[0]]), [], 200, false);
        says(s, [CODE_INPUTS_MISMATCH, 0, 0, 0, 0, 0, 0]);
        assert_eq(s.outputs.app_values, [filler_of(s.outputs.request_id), 0]);
    }

    // ---- the delivery handle (pss_core tip::handle; market.nr P_HANDLE) ----

    /// The owner's next delivery handle, as its request function commits it.
    fn alice_handle() -> Handle {
        Handle { partial: partial_commitment(0xa11ce5, 0xaa01), key: 0x6c01 }
    }

    /// `intake` over the app inputs then the handle.
    fn handled_intake<let I: u32>(inputs: [Field; I], h: Handle, good: bool) -> SharedIntake {
        intake(inputs.concat(h.fields()), good)
    }

    /// An owner round's step finished with the request's handle `h`.
    fn with_request_handle<let I: u32>(t: OwnerBook, step: Step<OWNER_SLOTS>, inputs: [Field; I], h: Handle, good: bool) -> SharedRound<OWNER_SLOTS> {
        finish(prefix(), pinned(200, CLOCK), t, step, true, inputs, Option::some(h), handled_intake(inputs, h, good), 777)
    }

    // An owner round writes the request's handle into the borrower's leaf on
    // every outcome that writes or re-blinds it, applied or refused, with
    // its note's exit tag, and the round's delivery is a filler: nobody is
    // notified. A lender's leaf takes no handle; shares that do not open C
    // write no position at all.
    #[test]
    fn an_owner_round_refreshes_the_handle_applied_or_not() {
        let m = with(with([ZERO; 8], 0, hdr(1700, LIQ - 1700, LIQ, 2, 7)), 1, tagged(bor_leaf(1000, 1700, 8), OLD_TAG));
        let h = alice_handle();
        let t = owner_book(m, placed(1));
        // applied: a repayment of 10
        let s = with_request_handle(t, repay(t, [1, 10], CLOCK, [R[0], R[1]]), [1, 10], h, true);
        says(s, [0, 1, ONE, 1000, 1690, 0, 0]);
        assert_eq([s.written.stored[1][P_HANDLE], s.written.stored[1][P_HANDLE + 1]], h.fields());
        assert_eq(s.outputs.app_values, [OLD_TAG, 0, 1]);
        agrees(m, [0, 1], 2, s);
        // refused (a withdrawal past the limit at 2.00): the leaf re-blinded
        // with the new handle and the note's tag
        let s = with_request_handle(t, withdraw(t, [1, 900], 200, CLOCK, [R[0], R[1]]), [1, 900], h, true);
        says(s, [CODE_LIMIT, 1, ONE, 1000, 1700, 0, 0]);
        assert_eq(s.outputs.app_values, [OLD_TAG, 0, 1]);
        assert(s.written.write[1]);
        let mut kept = m[1];
        kept[P_HANDLE] = h.partial;
        kept[P_HANDLE + 1] = h.key;
        kept[P_EXIT_TAG] = exit_tag(partial(), s.outputs.request_id, 1);
        kept[LEAF_LEN - 1] = R[1];
        assert_eq(s.written.stored[1], kept);
        agrees(m, [0, 1], 2, s);
        // nobody notified: the delivery is the filler of the request's seed
        let seed = filler_seed(BLINDING);
        let f = filler::<7>(seed, s.outputs.request_id);
        assert_eq(s.outputs.deliveries[0].tag, f.tag);
        assert_eq(s.outputs.deliveries[0].note_hash, f.note_hash);
        assert_eq(s.outputs.deliveries[0].ciphertext, f.ciphertext);
        // shares that do not open C leave the position, handle and tag and all
        let s = with_request_handle(t, repay(t, [1, 10], CLOCK, [R[0], R[1]]), [1, 10], h, false);
        assert_eq(s.written.write, [true, false]);
        assert_eq(s.written.stored[1], m[1]);
        assert_eq(s.outputs.app_values, [filler_of(s.outputs.request_id), 0, 0]);
        // a lender's leaf takes none
        let l = with(lent_book(), 1, lend_leaf(2000, 881));
        let tl = owner_book(l, placed(1));
        let s = with_request_handle(tl, view(tl, [1], CLOCK, [R[0], R[1]]), [1], h, true);
        assert_eq([s.written.stored[1][P_HANDLE], s.written.stored[1][P_HANDLE + 1]], [0, 0]);
    }

    /// The race's book on which position 1 is liquidatable at 2.00, its leaf
    /// holding the handle `h` and the tag OLD_TAG of its owner's newest note.
    fn handled_race(h: Handle) -> Sparse {
        let mut leaf = tagged(bor_leaf(1000, 1700, 8), OLD_TAG);
        leaf[P_HANDLE] = h.partial;
        leaf[P_HANDLE + 1] = h.key;
        with(with([ZERO; 8], 0, hdr(1700, LIQ - 1700, LIQ, 2, 7)), 1, leaf)
    }

    /// The liquidation of position 1 of `b` with `budget` (each budget its
    /// own request, so its own request id), which liquidates it: the round
    /// spends `spent` (the tag leaf 1 held), the written leaf keeps the
    /// handle `h` and holds `exit_tag(h.partial, request_id, 1)`, and the
    /// delivery is that note, the handle's partial note completed with the
    /// position after the liquidation (an owner note of position 1 that
    /// pays nothing) and the request id, sealed under the handle's key and
    /// logged under `handle_tag(h.key, request_id)`.
    fn notifies(b: Sparse, budget: Field, h: Handle, spent: Field) -> SharedRound<PROBES> {
        let (l, s) = s_liq_with(b, [1], 1, budget, true);
        assert_eq(l.mask, 1);
        let rid = s.outputs.request_id;
        let after = s.written.stored[1];
        assert_eq(untagged(after), untagged(l.updated.stored[1]));
        assert_eq([after[P_HANDLE], after[P_HANDLE + 1]], h.fields());
        assert_eq(after[P_EXIT_TAG], exit_tag(h.partial, rid, 1));
        assert_eq(s.outputs.app_values[0], spent);
        let notice = [0, 1, ONE, after[1], after[2], 0, 0];
        let d = s.outputs.deliveries[0];
        assert_eq(d.tag, handle_tag(h.key, rid));
        assert_eq(d.note_hash, completed_note_hash(OUTCOME_SLOT, h.partial, notice, rid));
        assert_eq(d.ciphertext, encrypt(notice.concat([rid]), h.key, d.note_hash));
        agrees(b, liq_at([1], 1), 2, s);
        s
    }

    // A liquidation that liquidates its probe tags the owner's notice: the
    // written leaf keeps the handle and holds the tag of the note the
    // delivery completes, which is the position's newest note, and the round
    // spends the tag of the owner's note before it.
    #[test]
    fn a_liquidation_tags_the_owners_notice_and_keeps_the_handle() {
        let h = alice_handle();
        let m = handled_race(h);
        let s = notifies(m, BUDGET, h, OLD_TAG);
        // seize 446 and repay 850 of 1,000 / 1,700
        assert_eq(untagged(s.written.stored[1]), [1, 554, 850, ONE, h.partial, h.key, 0, 42]);
        reports(s, [0, 0, 1, 446, 850, BUDGET - 850]);
    }

    // Twice and three times liquidated: each liquidation of the position
    // (its debt raised between, so it is unhealthy again), each its own
    // request, spends the previous notice's tag, stores its own, and
    // delivers to the same handle under its own log tag, so the owner's
    // newest note is always the last notice.
    #[test]
    fn a_position_liquidated_again_chains_its_notices() {
        let h = alice_handle();
        let m = handled_race(h);
        let first = notifies(m, BUDGET, h, OLD_TAG);
        let mut again = first.written.stored[1];
        again[2] = 1700;
        let second = notifies(with(m, 1, again), BUDGET + 1, h, first.written.stored[1][P_EXIT_TAG]);
        assert_eq(first.written.stored[1][P_EXIT_TAG], exit_tag(h.partial, first.outputs.request_id, 1));
        let mut again = second.written.stored[1];
        again[2] = 1700;
        let third = notifies(with(m, 1, again), BUDGET + 2, h, second.written.stored[1][P_EXIT_TAG]);
        assert_eq(second.written.stored[1][P_EXIT_TAG], exit_tag(h.partial, second.outputs.request_id, 1));
        // three requests, three tags and three log tags
        let rids = [first.outputs.request_id, second.outputs.request_id, third.outputs.request_id];
        assert((rids[0] != rids[1]) & (rids[1] != rids[2]) & (rids[0] != rids[2]));
        let tags = [first.written.stored[1][P_EXIT_TAG], second.written.stored[1][P_EXIT_TAG], third.written.stored[1][P_EXIT_TAG]];
        assert((tags[0] != tags[1]) & (tags[1] != tags[2]) & (tags[0] != tags[2]));
        let logs = [first.outputs.deliveries[0].tag, second.outputs.deliveries[0].tag, third.outputs.deliveries[0].tag];
        assert((logs[0] != logs[1]) & (logs[1] != logs[2]) & (logs[0] != logs[2]));
        // the third seizes the 108 left and writes off the rest
        assert_eq(untagged(third.written.stored[1]), [1, 0, 0, ONE, h.partial, h.key, 0, 42]);
    }

    // A liquidation that leaves the probe (healthy), one whose shares do not
    // open C, and one of a position that holds no handle deliver nothing of
    // the owner's: the seeded stand-in, the same shape. A probe the round
    // does not write keeps its leaf, handle and tag included, and the round
    // outputs the liquidator's filler; a liquidated probe without a handle
    // takes a tag of the delivery's seed, which no note of the liquidator's
    // (nor anyone's) gives.
    #[test]
    fn no_handle_or_no_write_delivers_the_stand_in() {
        let h = alice_handle();
        // healthy: the repaid book (1,000 / 1,300 at 2.00)
        let mut healthy = handled_race(h);
        healthy[1][2] = 1300;
        let (l, s) = s_liq(healthy, [1], 1, true);
        assert_eq(l.mask, 0);
        assert_eq(s.written.write, [true, false]);
        assert_eq(s.written.stored[1], healthy[1]);
        assert_eq(s.outputs.new_hashes[1], hash_at(1, healthy[1]));
        assert_eq(s.outputs.app_values[0], filler_of(s.outputs.request_id));
        assert_eq(s.outputs.deliveries[0].tag, handle_tag(filler_seed(BLINDING), s.outputs.request_id));
        agrees(healthy, liq_at([1], 1), 2, s);
        // shares that do not open C
        let race = handled_race(h);
        let (_, s) = s_liq(race, [1], 1, false);
        assert_eq(s.written.stored[1], race[1]);
        assert_eq(s.outputs.app_values[0], filler_of(s.outputs.request_id));
        assert_eq(s.outputs.deliveries[0].tag, handle_tag(filler_seed(BLINDING), s.outputs.request_id));
        // a liquidated position without a handle
        let bare = handled_race(Handle::none());
        let (l, s) = s_liq(bare, [1], 1, true);
        assert_eq(l.mask, 1);
        let rid = s.outputs.request_id;
        let d = s.outputs.deliveries[0];
        assert_eq(d.tag, handle_tag(filler_seed(BLINDING), rid));
        assert_eq(d.note_hash, completed_note_hash(OUTCOME_SLOT, filler_seed(BLINDING), [0; 7], rid));
        let tag = s.written.stored[1][P_EXIT_TAG];
        assert_eq(tag, exit_tag(filler_seed(BLINDING), rid, 1));
        assert(tag != exit_tag(partial(), rid, 1));
        assert_eq(s.outputs.app_values[0], OLD_TAG);
        agrees(bare, liq_at([1], 1), 2, s);
    }
}
