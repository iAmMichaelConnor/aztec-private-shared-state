//! The lending market's layout, its failure codes and the arithmetic the
//! rounds share. The book is one tree-valued node-held key
//! (pss_core::tip::tree, docs/ARCHITECTURE.md section 6, "Tree-valued
//! keys"): a binary Poseidon2 Merkle tree of depth DEPTH whose leaves are
//! LEAF_LEN = 8 field elements, the last one each leaf's own blinding.
//!
//!   leaf 0 (the header)  [total_debt, liquidity, total_shares, borrow_index, last_accrual, next_index, 0, blinding]
//!   borrower leaf i      [1, collateral, debt, index_at_touch, handle_partial, handle_key, exit_tag, blinding]
//!   lender leaf i        [2, shares, 0, 0, 0, 0, exit_tag, blinding]
//!   empty leaf           the zero vector (leaf hash 0)
//!
//! The first element is the leaf's kind (KIND_BORROWER, KIND_LENDER; 0
//! while empty), written by the opening deposit or supply and never changed:
//! the book records no owner. A position's
//! owner is whoever holds a completed note of it, which the app's private
//! function opens before it queues a request on the position
//! (docs/ARCHITECTURE.md section 6, "Ownership by note"), so the rounds never see an
//! owner, in shares or otherwise. Because a note confers ownership for as long as the
//! book lives, an index is never reassigned: a position emptied by repayments or
//! liquidations stays an opened leaf with zero collateral and debt. collateral is in
//! units of the collateral token, debt and liquidity in units of the borrowed token. A
//! lender's shares are its part of the pool, whose value is liquidity + total_debt: the
//! supply index, the pool's value per share, (liquidity + total_debt) * INDEX_ONE /
//! total_shares, is never stored (it rises as total_debt accrues). total_debt and
//! total_shares are aggregates (the utilisation, the share price, the quote), never an
//! authority over a position: a subtraction from one saturates at 0 (`sub_sat`), and no
//! round requires a total to cover a position's part. borrow_index B and last_accrual are
//! the interest's (`accrue`: every applying round grows B by the kinked per-block rate
//! times the blocks since last_accrual, at the round's pinned clock), and index_at_touch
//! the borrow index at a borrower position's last touch, so its debt at the current index
//! is debt * B / index_at_touch (`debt_at`); its owner's note carries it in `mask`, the
//! borrower kind's marker (never 0; a lender's note carries 0). next_index is the book's
//! append index, the first leaf never written (1 in an empty book, 2^D in a full one): an
//! opening deposit or supply requires the scheduler's `$new_leaf` to equal it and
//! increments it (pss_core `tree::append`), so the opened positions are the prefix 1 ..
//! next_index - 1 that the keeper's scan relies on, whatever the nodes assign. exit_tag
//! is the position's exit tag (pss_core `tip::exit`, the escape hatch): the tag of the
//! newest note that reports the position, which every write of the leaf replaces
//! (`P_EXIT_TAG`). One root commits to the whole market: the key's slot holds
//! `tree::commitment(namespace, key, root)`.
//!
//! DEV DECISION: a lender's position is a leaf of the book, kind 2, default
//! here, beside the borrowers'. Why: the escape hatch
//! (examples/lending-tip/README.md, "The escape hatch") pays a lender's exit
//! what its newest note reports, which the leaf's exit tag names and spends
//! once; a share note held outside the book has no leaf to tie its value to the
//! pool. Consequences: one ownership brick, one note type and one `view` for
//! both kinds; two colluding nodes read a lender's shares as they read a
//! borrower's collateral (privacy); a lender's leaf changes only by its owner's
//! rounds, so its note is never stale. The alternative is a share note of the
//! lender's (more minimal: no leaf, a lender round touching the header alone),
//! if the hatch is given a public supply index. Design:
//! examples/lending-tip/README.md, "What is a note, what is shared".
//!
//! DEV DECISION: the market's totals live in a header leaf, leaf 0 of the
//! book, default here; one root then commits to the totals and every
//! position, and every round touches leaf 0. The alternative is a second
//! small key of its own (another slot, another commitment the round loads
//! and stores). Design guide: "state shape" (tree).
//!
//! Units. price is the oracle's value of one collateral unit in borrowed
//! units, times PRICE_SCALE: price 200 means one collateral unit is worth
//! 2.00 borrowed units. A position is healthy while
//!     collateral * price / PRICE_SCALE * LT_BPS / BPS >= debt,
//! that is, its health factor collateral * price * LT_BPS /
//! (debt * PRICE_SCALE), in basis points, is at least BPS.

use total::arith::{mul_div_wide_to_or, TotalArith};
use total::cmp::{eq, lt};
use total::convert::{from_u128, to_u128_or};
use total::core::{is_zero, select_field};
use total::range::{clamp_bits_or, fits_bits};

// ---------------------------------------------------------------------
// Capacity and layout
// ---------------------------------------------------------------------

/// The tree's depth D: positions 1 .. 2^D - 1, opened in order and never
/// reclaimed, so 2^D - 1 bounds the positions a market opens over its life.
///
/// DEV DECISION: the capacity, D and the probe width PROBES (K), default
/// D = 16 (65,535 positions) and K = 2 (a liquidation names one position);
/// design guide: the tree's depth and probe width. By the 2^14 rule, K is
/// the largest value at which every lending round, the secret-shared
/// entries included, is a 2^14 circuit (bb 6.0.0 `gates` below 16,384).
/// Each slot costs about 3,700 gates at D = 16: its leaf hashes (four
/// Poseidon2 permutations each for the eight-element leaf,
/// ceil((LEAF_LEN + 4) / 3)), D permutations over public values (the old
/// path) and D over shared ones (the new path), and a liquidation probe's
/// arithmetic; a secret-shared entry adds about 1,000 to 1,100. The
/// secret-shared liquidation is 15,129 gates at K = 2, so a third slot
/// passes the bound (the README's capacity table has every round's count).
/// So K = 2 at D = 16: one position per liquidation round, which the
/// keeper's scan finds (examples/lending-tip/README.md, "Keeper round"). A
/// round's cost depends on K and D only, never on the positions in use. Raising D or K is these constants, gen-fixtures.py (which reads
/// them), the liquidate mains' position parameters for K, the manifests'
/// `tree` entries and the contract's `DEPTH` and `PROBES`; for K also the
/// contract's `process_shared`, which lands the owner rounds and the
/// liquidation through one result layout of PROBES slots and so needs
/// PROBES == OWNER_SLOTS (a static assertion there), or a result function
/// of its own for the liquidation.
pub global DEPTH: u32 = 16;

/// The probe width K of a liquidation: the header and up to K - 1
/// positions. The owner rounds touch the header and one position
/// (OWNER_SLOTS). See DEPTH for the choice.
pub global PROBES: u32 = 2;

/// The slots of an owner-bound round: the header and the position.
pub global OWNER_SLOTS: u32 = 2;

/// The keeper round's window W, the positions one scan reads (rounds.nr
/// `scan`; examples/lending-tip/README.md, "Keeper round", over
/// docs/ARCHITECTURE.md section 6, "A read-only window on a tree key";
/// DECISIONS.md section 7, "Liquidation discovery under
/// hidden positions is a lottery among liquidators"). W = 8
/// (WINDOW_HEIGHT 3), the window the 2^14 rule allows: scan_shared, the
/// busiest round, is 15,795 gates at D = 16 (bb 6.0.0 `gates`), and eight
/// more window leaves (their hashes, decodes and health checks) would pass
/// 16,384; the window's subtree replaces per-leaf paths, so D adds about
/// 250 gates per level. A full pass over a book of n opened positions is
/// ceil(n / W) rounds, at most 2^D / W (8,192 at D = 16) against about
/// 2^D / (K - 1) by sweeping. A gate budget of the scan round's own (2^15
/// gives W = 32) would break the rule every round keeps. Raising W is these two constants,
/// gen-fixtures.py (which reads them), the manifest's `window.width`
/// (REGISTER refuses a width above its bound, sidecar-core
/// `MAX_TREE_WINDOW`) and the contract's `WINDOW`.
pub global WINDOW: u32 = 8;

/// log2 of WINDOW: the window's subtree height.
pub global WINDOW_HEIGHT: u32 = 3;

/// The window root's siblings up to the book's root: D - log2 W.
pub global WINDOW_SIBLINGS: u32 = DEPTH - WINDOW_HEIGHT;

/// The slots a scan loads besides its window: the header.
pub global SCAN_SLOTS: u32 = 1;

/// Elements per leaf: seven values (the header's six, padded with a 0; a
/// position's kind, three values and, for a borrower, its delivery handle,
/// padded with 0s) and the blinding.
pub global LEAF_LEN: u32 = 8;

/// A leaf's first element: the kind of position it holds (0 while empty).
pub global KIND_BORROWER: Field = 1;
pub global KIND_LENDER: Field = 2;

/// The fixed point of the borrow index and the supply index: 10^9. The
/// init's borrow index is it, and the supply index of a pool with no shares.
pub global INDEX_ONE: Field = 1000000000;

/// The borrow index's width: B (and so every index_at_touch, a B a round
/// wrote) stays below 2^48, which keeps the division-free health test
/// (`unhealthy_accrued`) exact: its left product collateral * price * LT_BPS
/// * index_at_touch is below 2^128 * 2^64 * 2^13 * 2^48 = 2^253, under the
/// field modulus. The header's and a position's decode check it (code 4: a
/// round never writes a wider one), and the accrual saturates B at
/// INDEX_MAX instead of passing it, so interest stops there rather than the
/// market failing every round. At the defaults B reaches 2^48 from
/// INDEX_ONE after about nineteen years at full utilisation.
pub global INDEX_BITS: u32 = 48;
/// 2^48 - 1, the largest borrow index.
pub global INDEX_MAX: Field = 0xffffffffffff;

/// The clock's width: the L2 block number, a u32. A pinned clock that is not
/// one accrues nothing (the contract's band check refuses it anyway).
pub global CLOCK_BITS: u32 = 32;

/// 2^128 - 1: where a total saturates.
pub global U128_MAX: Field = 0xffffffffffffffffffffffffffffffff;

/// A leaf as the tree stores it.
pub type Leaf = [Field; LEAF_LEN];

// ---------------------------------------------------------------------
// The market's constants (examples/lending-tip/README.md, "Rules and constants")
// ---------------------------------------------------------------------

/// The oracle price's fixed-point scale: price 200 is 2.00.
pub global PRICE_SCALE: Field = 100;
/// One in basis points.
pub global BPS: Field = 10000;

/// The liquidation threshold: 8,000 bps: a position is
/// liquidatable once its debt exceeds 80% of its collateral's value. Only
/// a liquidation and the scan use it; borrow and withdraw test the borrow
/// limit LTV_BPS below it. Changing it changes every round's vk.
pub global LT_BPS: Field = 8000;

/// The borrow limit (loan-to-value): 7,500 bps. A borrow or a withdrawal
/// of collateral must leave the position at or above it at the pinned
/// price (code 9), decided without dividing as
///     collateral * price * LTV_BPS >= debt * PRICE_SCALE * BPS.
///
/// DEV DECISION: the borrow limit, default LTV_BPS 7,500 against LT_BPS
/// 8,000. Why: a position borrowed to the limit then survives a price fall
/// of 1 - LTV/LT (6.25% at the defaults) before it can be liquidated, so a
/// new loan starts with a margin instead of on the threshold. Consequences:
/// borrowers may draw at most 75% of their collateral's value; a change is
/// a new deployment (the constant is in every vk). Alternative: LTV equal
/// to LT (borrowing to the threshold, liquidatable on any price fall), or
/// a wider gap (safer loans, less credit). Design:
/// examples/lending-tip/README.md, "Rules and constants".
pub global LTV_BPS: Field = 7500;

/// The close factor: 5,000 bps: one liquidation repays half the debt, rounded down, so a
/// position is wound down in steps and a liquidator cannot take all of a
/// barely unhealthy position at once.
pub global CLOSE_BPS: Field = 5000;

/// The liquidation bonus: 500 bps: the liquidator seizes collateral worth 105% of what it
/// repays, at the oracle price, capped at the position's collateral.
pub global BONUS_BPS: Field = 500;

/// The per-block interest rate model, kinked at the optimal utilisation
/// U_OPT (basis points of the pool lent out): the borrow index grows per
/// block, in INDEX_ONE units, by
///     rate(u) = R0 + R1 * min(u, U_OPT) / U_OPT + R2 * max(0, u - U_OPT) / (BPS - U_OPT)
/// (`accrue`, which never rounds rate(u) on its own: the accrual over the
/// elapsed blocks is one quotient, rounded up).
///
/// DEV DECISION: the rate model, default R0 0, R1 46, R2 690 and U_OPT
/// 8,000 bps. Why: at a 36-second block (the testnet's) that is about 4% a
/// year at the optimal utilisation and about 64% a year at full utilisation,
/// a steep slope past the kink that pulls lenders in and borrowers out when
/// the pool runs dry, the usual shape of a pooled lending market.
/// Consequences: the rates are constants in every round's vk, so a change is
/// a new deployment; the block time sets the yearly rate (a faster chain at
/// the same constants charges more per year). Alternatives: a linear rate
/// (R2 = R1, no kink), a rate per second on a timestamp clock, or rates in a
/// Config pin read per round (one more pinned read). Design:
/// examples/lending-tip/README.md, "Interest".
pub global R0: Field = 0;
pub global R1: Field = 46;
pub global R2: Field = 690;
pub global U_OPT: Field = 8000;

/// The pinned clock's tolerance: `apply` accepts a round's clock within
/// CLOCK_BAND blocks of the block it lands in (the manifests' `tolerance`
/// band, the contract's clock read; no round uses it).
///
/// DEV DECISION: the clock band, default 128 blocks. Why: a round is
/// computed at the scheduler's snapshot and lands minutes later, so an exact
/// block never matches twice; 128 blocks covers a round's proving and
/// landing with room. Consequences: the network (the orchestrator choosing
/// the clock, the sequencer the block) places each accrual anywhere within
/// the band of the chain's clock, so it can move up to rate * CLOCK_BAND of
/// interest between adjacent rounds' parties, and bring forward at most
/// CLOCK_BAND blocks of interest in total, once (last_accrual never moves
/// back: `accrue`). A narrower band shrinks that power and recomputes more
/// rounds; a wider one the reverse. Design:
/// examples/lending-tip/README.md, "Interest", "The clock".
pub global CLOCK_BAND: Field = 128;

// ---------------------------------------------------------------------
// Failure codes, shared by every round
// ---------------------------------------------------------------------
//
// One table for every round, so a code means the same thing whichever
// round reports it. Each round's doc comment (rounds.nr) lists the codes
// it can report and their order; the first failing check wins. Every code
// is a flag, never an assertion, so every round stays total.
//
//   code  meaning                                                  rounds
//   1     amount is not a u128                                     the owner rounds
//   2     amount is zero                                           the owner rounds
//   3     a position is not below 2^D; position 0 in a round that
//         is not an opening deposit; a liquidation count outside
//         1 .. K - 1; a scan's start not below 2^D or not a
//         multiple of W                                            all
//   4     the loaded state is not well formed (an amount or total
//         not a u128, the header's borrow index not in 1 .. 2^48 - 1
//         or its last accrual not a u32, a position's index at touch
//         not below 2^48), or the
//         nodes' placed paths and indices are not the request's
//         (a path that does not give slot 0's root, an index the
//         request does not name, an opening slot that is not empty,
//         a window that does not give the root)                   all
//   5     the position is not one of this round's kind (its
//         leaf's kind is not KIND_BORROWER for a deposit into it,
//         a withdrawal, a borrow or a repayment, not KIND_LENDER
//         for a supply into it or a withdrawal of supply, 0 for a
//         view): a backstop the app's private function keeps an
//         honest request from reaching, since it requires the
//         owner's note of the position                             the owner rounds
//   6     price is zero or not a u64                               borrow, withdraw, liquidate, scan
//   7     a result does not fit u128 (collateral, debt, shares,
//         liquidity), or a multiply-divide refuses (a
//         liquidation's, defensive; a supply's or a withdrawal of
//         supply's when the pool's value is not a u128 or zero
//         with shares outstanding; a borrower position's debt at
//         the current index when it passes u128 or its index at
//         touch is 0). Never a total: the totals saturate          the owner rounds, liquidate
//   8     the market's liquidity is below the amount (a
//         withdrawal of supply: its value)                         borrow, withdraw_supply
//   9     the position would be below the borrow limit (LTV_BPS)
//         after the round at the price                             borrow, withdraw
//   10    reserved: no round reports it
//   11    a probe is healthy at the price (or has no debt): the
//         liquidation skips it, mask bit 0; never a round's code   liquidate
//   12    a probe's repayment rounds to zero (debt 1): skipped
//         likewise                                                 liquidate
//   13    reserved: no round reports it
//   14    the inputs do not open the request's C (a secret-shared request
//         whose shares do not reconstruct to its commitment);
//         checked first                                            the secret-shared rounds
//   15    a position named twice                                   liquidate
//   16    the book is full: an opening deposit with $new_leaf 0    deposit
//   17    an opening deposit's $new_leaf is not the header's
//         append index next_index (a scheduler that opens a
//         position anywhere but at the end of the book)          deposit
//   18    the shares exceed the lender's                           withdraw_supply
//   19    the amount exceeds the position's collateral             withdraw
//   20    a supply's shares or a withdrawal of supply's value
//         rounds to zero (the pool's value per share is above the
//         amount, or below one unit per share): refused, so no
//         amount is taken or shares burned for nothing             supply, withdraw_supply
//
// The codes and their order: the table above, and
// in each round the order of its doc comment, after a secret-shared round's
// inputs check (14), which comes first: the request's own fields
// first (amount, positions, count, a duplicate, a full book), then the
// loaded state and the nodes' data (4, then the append index 17), then
// whether the position is open (5), then the price, then
// what the request does to the state. A code is a public output under the
// non-secret-shared intakes (and inside the outcome under the secret-shared ones), so
// renumbering changes every consumer and every vk. Reporting the first
// failure, not a mask, reveals one reason only; a liquidation reports
// per-probe skips (11, 12) in its mask instead, so that one healthy probe
// does not fail the others. Code 4 is defensive: the state was written by
// earlier proven rounds, and the nodes place paths from agreeing clear
// trees, so it marks a diverged store or a faulty scheduler. Code 17 is
// the circuit's own guard on the scheduler's choice: each node's chain
// verifier refuses a `$new_leaf` other than its own tree's append index,
// so an honest network never reaches it, and a network whose every node
// is compromised cannot open a position past the end of the book, where
// the keeper's scan would never look. 10 and 13 are reserved: no round
// reports either.

pub global CODE_AMOUNT_RANGE: Field = 1;
pub global CODE_ZERO_AMOUNT: Field = 2;
pub global CODE_POSITION_RANGE: Field = 3;
pub global CODE_BAD_STATE: Field = 4;
pub global CODE_KIND: Field = 5;
pub global CODE_PRICE: Field = 6;
pub global CODE_OVERFLOW: Field = 7;
pub global CODE_LIQUIDITY: Field = 8;
pub global CODE_LIMIT: Field = 9;
pub global CODE_INPUTS_MISMATCH: Field = 14;
pub global CODE_DUPLICATE: Field = 15;
pub global CODE_FULL_BOOK: Field = 16;
pub global CODE_APPEND_INDEX: Field = 17;
pub global CODE_EXCEEDS_SHARES: Field = 18;
pub global CODE_EXCEEDS_COLLATERAL: Field = 19;
pub global CODE_ZERO_QUOTIENT: Field = 20;

// ---------------------------------------------------------------------
// The payout and its asset bit
// ---------------------------------------------------------------------

/// The asset a payout is in: the borrowed asset (a borrow's amount, a
/// repayment's excess, a liquidation's unused budget, a failed repayment's
/// or liquidation's escrow).
pub global ASSET_BORROWED: Field = 0;
/// The collateral asset (a withdrawal's amount, a failed deposit's escrow).
pub global ASSET_COLLATERAL: Field = 1;

/// 2^128: the asset bit's place in a payout.
pub global ASSET_BIT: Field = 0x100000000000000000000000000000000;

/// A note's payout: `amount + 2^128 * asset`, an amount below 2^128 in the
/// asset its bit names (ASSET_BORROWED or ASSET_COLLATERAL), which the
/// contract's `redeem` splits and pays. Every refund and every payment an
/// owner round makes travels here, so a note's `x` is a position's
/// collateral whenever the note names a position and a liquidation's seize
/// (in the collateral asset) when it does not. One addition and one
/// product by a constant; no constraint of its own.
pub fn payout(amount: Field, asset: Field) -> Field {
    amount + ASSET_BIT * asset
}

// ---------------------------------------------------------------------
// Amounts
// ---------------------------------------------------------------------

/// The amount width: u128 for every amount,
/// collateral, debt, total and the liquidity, because Aztec tokens keep
/// balances as u128 (the token contract's U128 notes), so a market that
/// moves real tokens must take any amount a token can hold. The price is
/// a u64 (see unhealthy_accrued). The liquidation's fused
/// multiply-divides take u128 operands through total's
/// mul_div_wide_to_or (mul_div_wide below), which checks the 256-bit
/// product in two 128-bit halves; total's narrower mul_div_or stops at 84
/// bits (3N <= 253 keeps q*d + r below p), a bound of that gadget, never
/// an application choice. A narrower amount (u64) would make the rounds
/// cheaper but refuse balances the token contract allows.
///
/// to_u128_or flags a raw Field (any Field, p - 1 included) and
/// returns 0 when it is not a u128 (its hints, std's limb decomposition
/// and a truncating cast, run in co-noir).
pub fn amount_or(x: Field) -> (u128, bool) {
    to_u128_or(x)
}

/// a + b at u128, flagged: (sum, true) when it fits, else (0, false).
/// TotalArith's u128 add_or (a carry hint).
pub fn add_u128(a: u128, b: u128) -> (u128, bool) {
    a.add_or(b)
}

/// a - b at u128, flagged: (difference, true) when a >= b, else
/// (0, false). The flag doubles as the comparison b <= a.
/// TotalArith's u128 sub_or (a borrow hint).
pub fn sub_u128(a: u128, b: u128) -> (u128, bool) {
    a.sub_or(b)
}

/// A u128 as a Field (exact).
pub fn field(x: u128) -> Field {
    from_u128(x)
}

/// a - b, saturating at 0: the totals' subtraction (an aggregate is never
/// an authority over a position, so a total that would go below 0 stays at
/// 0 instead of flagging). PRECONDITION: a and b below 2^128, so a - b fits
/// 128 bits exactly when b <= a. Constraints: a 128-bit flag and a select.
pub fn sub_sat(a: Field, b: Field) -> Field {
    let d = a - b;
    select_field(fits_bits::<128>(d), d, 0)
}

// ---------------------------------------------------------------------
// The two arithmetic gadgets: every ratio and every fused multiply-divide
// of the rounds goes through one of these.
// ---------------------------------------------------------------------

/// True when a borrower position of `collateral`, `debt` and
/// `index_at_touch` is unhealthy at `price` on its debt at the borrow index
/// `b`, debt * b / index_at_touch: its health factor is below BPS, decided
/// without dividing (examples/lending-tip/README.md, "Interest", "Health
/// on the accrued debt, without dividing"), the index folded into
/// both sides:
///     collateral * price * LT_BPS * index_at_touch < debt * b * PRICE_SCALE * BPS.
/// A zero debt makes the right side 0, which nothing is below, so a
/// position without debt (a lender's, an empty leaf) is never unhealthy.
/// The exact accrued debt, not the rounded-up debt_at, decides, so the
/// scan and a liquidation agree with every round's own view.
///
/// PRECONDITIONS (the callers pass clamped values): collateral and debt
/// below 2^128, price below 2^64, index_at_touch and b below 2^48
/// (INDEX_BITS).
///
/// Exact within its bound. The products are formed in the field and
/// compared with total's Field lt (the order of canonical values). Sound
/// while both stay below the field modulus p (about 2^253.6): the left one
/// is below 2^128 * 2^64 * 2^13 * 2^48 = 2^253 and the right one below
/// 2^128 * 2^48 * 2^7 * 2^14 = 2^197, so neither wraps and the comparison
/// is the integer comparison at every admissible input.
///
/// Constraints: two products and one Field lt (total::cmp field_lt:
/// canonical-limb decompositions with hinted limbs, range checks and a
/// borrow; reviewed in total, whitelisted by --lib-src total/src/).
/// Nothing input-falsifiable; the flag is determined.
pub fn unhealthy_accrued(collateral: Field, debt: Field, index_at_touch: Field, b: Field, price: Field) -> bool {
    lt(collateral * price * LT_BPS * index_at_touch, debt * b * PRICE_SCALE * BPS)
}

/// True when a position of `collateral` and `debt` (its debt at the
/// current index, which borrow and withdraw write) is at or above the
/// borrow limit at `price`: collateral * price * LTV_BPS >= debt *
/// PRICE_SCALE * BPS, unhealthy_accrued's test at LTV_BPS in place of
/// LT_BPS, an index of one on both sides, and negated. A zero debt is
/// always within it. PRECONDITIONS: collateral and debt below 2^128, price
/// below 2^64; the left product is below 2^205, the right below 2^149, so
/// the comparison is exact. Constraints: two products and a Field lt.
pub fn within_limit_at_price(collateral: Field, debt: Field, price: Field) -> bool {
    !lt(collateral * price * LTV_BPS, debt * PRICE_SCALE * BPS)
}

/// The liquidation's quotient bound: 135 bits, the
/// smallest width that holds every quotient liquidate forms: repay =
/// floor(debt * CLOSE_BPS / BPS) is below 2^127, and want =
/// floor(repay * PRICE_SCALE * (BPS + BONUS_BPS) / (price * BPS)) is at
/// most repay * 105, at price 1, so below 2^134. want may exceed u128
/// because the seize that follows caps it at the collateral, so 128 would
/// refuse a liquidation at a low price where the cap gives the right
/// answer; a wider bound only lengthens the quotient's limb split.
/// Raising PRICE_SCALE or BONUS_BPS raises the need (repay * PRICE_SCALE
/// * (BPS + BONUS_BPS) / BPS must stay below 2^WIDE_QUOTIENT_BITS, at
/// most 253).
pub global WIDE_QUOTIENT_BITS: u32 = 135;

/// floor(a * b / d) and whether it was computed: (q, true) when a, b and
/// d are below 2^128, d != 0 and the quotient is below
/// 2^WIDE_QUOTIENT_BITS, else (0, false).
///
/// total's mul_div_wide_to_or checks the 256-bit product a * b =
/// q * d + r in two 128-bit halves with a carry, r below d, and returns
/// q = r = 0 on ok = false.
///
/// Constraints: mul_div_wide_to_or's (the operands' 128-bit clamps,
/// is_zero on the clamped divisor, selects, the wide split's constraints
/// and the quotient's width split; reviewed in total). Determined.
pub fn mul_div_wide(a: Field, b: Field, d: Field) -> (Field, bool) {
    let (q, _, ok) = mul_div_wide_to_or::<WIDE_QUOTIENT_BITS>(a, b, d);
    (q, ok)
}

/// ceil(a * b / d) and whether it was computed: mul_div_wide's quotient
/// plus one when the remainder is not zero (the rounding rule's two
/// round-ups: a debt brought to the current index and the accrual). The
/// result may reach 2^WIDE_QUOTIENT_BITS; the callers check its width.
/// On ok = false q and r are 0, so the result is 0.
/// Constraints: mul_div_wide_to_or's, an is_zero and a select.
/// Determined.
pub fn mul_div_wide_up(a: Field, b: Field, d: Field) -> (Field, bool) {
    let (q, r, ok) = mul_div_wide_to_or::<WIDE_QUOTIENT_BITS>(a, b, d);
    (q + select_field(is_zero(r), 0, 1), ok)
}

// ---------------------------------------------------------------------
// Interest: the accrual, once per applying round, and a position's debt at
// the current index (examples/lending-tip/README.md, "Interest")
// ---------------------------------------------------------------------
//
// The rounding rule, stated once. Every quotient the rounds form goes
// through mul_div_wide and rounds toward zero, except a debt brought to the
// current index (debt_at) and the header's accrual (accrue), which round up
// (mul_div_wide_up). So interest never rounds in the borrower's favour, and
// shares minted and value withdrawn round in the pool's favour. The totals
// are aggregates (the utilisation, the quote, the share price), never an
// authority over a position: a subtraction from one saturates at 0
// (sub_sat), an addition or an accrual that would pass u128 saturates at
// 2^128 - 1 (add_sat; flagging would fail every later round and freeze the
// market), and the borrow index saturates at INDEX_MAX. The two round-ups
// drift apart: total_debt gains at most one unit per accrual, each
// position's debt at most one unit per touch, so total_debt tends to exceed
// the sum of the positions' debts by up to the number of accruals since
// their last touches and may fall short of it by up to one unit per
// position; the difference is dust the last lender finds or leaves.

/// The rate model's common denominator, INDEX_ONE * U_OPT * (BPS - U_OPT)
/// (1.6 * 10^16, below 2^54): `accrue` scales rate(u) by U_OPT * (BPS -
/// U_OPT) so that it is an integer and divides once.
global RATE_DENOM: Field = INDEX_ONE * U_OPT * (BPS - U_OPT);

/// The header after the accrual at the round's clock.
pub struct Accrued {
    /// B' = B + ceil(B * rate(u) * dt / INDEX_ONE), saturating at INDEX_MAX
    pub borrow_index: Field,
    /// ceil(total_debt * B' / B), saturating at 2^128 - 1
    pub total_debt: Field,
    /// max(last_accrual, t): never moves back
    pub last_accrual: Field,
    /// the utilisation the rate was set by, floor(total_debt * BPS /
    /// (liquidity + total_debt)) before the accrual (0 for an empty pool)
    pub utilisation: Field,
}

/// Accrue the header `h` at the pinned clock `clock` (the L2 block number,
/// examples/lending-tip/README.md, "Interest"):
///
///   t             = clock (0 when it is not a u32: nothing accrues)
///   dt            = max(0, t - last_accrual)
///   u             = floor(total_debt * BPS / (total_debt + liquidity))     (0 when both are 0)
///   rate(u)       = R0 + R1 * min(u, U_OPT) / U_OPT + R2 * max(0, u - U_OPT) / (BPS - U_OPT)
///   B'            = B + ceil(B * rate(u) * dt / INDEX_ONE)                  saturating at INDEX_MAX
///   total_debt'   = ceil(total_debt * B' / B)                               saturating at 2^128 - 1
///   last_accrual' = max(last_accrual, t)
///
/// last_accrual never moves back: the clock is admitted anywhere within
/// CLOCK_BAND of the block `apply` lands in, ahead of it included, so a
/// round may accrue into the future, and a later round whose clock falls
/// below last_accrual then accrues nothing and leaves last_accrual where it
/// is. So the interest the market ever accrues is bounded by the true
/// elapsed blocks plus CLOCK_BAND, once; with last_accrual' = t a network
/// choosing clocks could re-accrue every band's worth twice, round after
/// round. A long idle period is one large dt: B * rate * dt is below 2^48 *
/// 2^34 * 2^32 = 2^114, inside the multiply-divide's operands, so it never
/// refuses. A zero dt leaves B and total_debt as they are (the round-ups add
/// nothing to an exact quotient).
///
/// rate(u) is never formed on its own: rate(u) * U_OPT * (BPS - U_OPT) is
/// an integer (below 2^34), and the growth is one quotient by RATE_DENOM.
/// The accrual never flags: a value it cannot represent saturates.
///
/// PRECONDITION: h decoded (`header`): B in 1 .. 2^48 - 1, last_accrual
/// below 2^32, the amounts u128s (their clamps otherwise, under h.ok false).
///
/// Constraints: the clock's clamp, three range flags, three
/// mul_div_wide(_up) and selects. Determined.
pub fn accrue(h: Header, clock: Field) -> Accrued {
    let (t, _) = clamp_bits_or::<CLOCK_BITS>(clock);
    // both below 2^32: t - last_accrual fits 32 bits exactly when t >= last_accrual
    let elapsed = t - h.last_accrual;
    let forward = fits_bits::<CLOCK_BITS>(elapsed);
    let dt = select_field(forward, elapsed, 0);
    let pool = h.pool();
    let (u, _) = mul_div_wide(field(h.total_debt), BPS, pool);
    // u <= BPS < 2^14: U_OPT - u fits 14 bits exactly when u <= U_OPT
    let low = select_field(fits_bits::<14>(U_OPT - u), u, U_OPT);
    let high = u - low;
    let rate = R0 * U_OPT * (BPS - U_OPT) + R1 * low * (BPS - U_OPT) + R2 * high * U_OPT;
    let (growth, g_ok) = mul_div_wide_up(h.borrow_index, rate * dt, RATE_DENOM);
    let grown = h.borrow_index + growth;
    let b = select_field(g_ok & fits_bits::<INDEX_BITS>(grown), grown, INDEX_MAX);
    let (debt, d_ok) = mul_div_wide_up(field(h.total_debt), b, h.borrow_index);
    Accrued {
        borrow_index: b,
        total_debt: select_field(d_ok & fits_bits::<128>(debt), debt, U128_MAX),
        last_accrual: select_field(forward, t, h.last_accrual),
        utilisation: u,
    }
}

/// A borrower position's debt at the borrow index `b`, rounded up:
/// ceil(debt * b / index_at_touch), and whether it is a u128 (false, 0, when
/// index_at_touch is 0, as no borrower leaf has, or the debt passes u128:
/// code 7 on that position alone; B' / index_at_touch past 2^7 takes more
/// than a century at the defaults). A round that writes the position brings
/// it to the index first (debt', index_at_touch' = b), then makes its own
/// change. Constraints: mul_div_wide_up and a 128-bit flag. Determined.
pub fn debt_at(debt: u128, index_at_touch: Field, b: Field) -> (Field, bool) {
    let (d, ok) = mul_div_wide_up(field(debt), b, index_at_touch);
    let fits = ok & fits_bits::<128>(d);
    (select_field(fits, d, 0), fits)
}

/// a + b, saturating at 2^128 - 1: an addition to a total. PRECONDITION:
/// a and b below 2^128, so the sum is below 2^129 and the flag exact.
/// Constraints: a 128-bit flag and a select.
pub fn add_sat(a: Field, b: Field) -> Field {
    let s = a + b;
    select_field(fits_bits::<128>(s), s, U128_MAX)
}

// ---------------------------------------------------------------------
// Decoding the loaded leaves
// ---------------------------------------------------------------------

/// The header's numbers, each 0 when its Field is not a u128, with ok
/// false, and its append index.
pub struct Header {
    pub total_debt: u128,
    pub liquidity: u128,
    pub total_shares: u128,
    /// the borrow index B, in 1 .. 2^48 - 1 (its clamp, with ok false,
    /// otherwise)
    pub borrow_index: Field,
    /// the block of the last accrual, a u32 (its clamp otherwise)
    pub last_accrual: Field,
    /// the first leaf never written, as a Field: only an opening reads it,
    /// comparing it with `$new_leaf` (below 2^D) and adding one, so it
    /// stays in 1 ..= 2^D from the init's 1 without a range check
    pub next_index: Field,
    /// every amount is a u128, the index and the clock in range
    pub ok: bool,
}

impl Header {
    /// The pool's value, liquidity + total_debt (below 2^129): what the
    /// lenders' shares are worth together.
    pub fn pool(self) -> Field {
        field(self.liquidity) + field(self.total_debt)
    }
}

/// The header's places: total_debt, liquidity, total_shares, the borrow
/// index, the last accrual, the append index.
pub global H_DEBT: u32 = 0;
pub global H_LIQUIDITY: u32 = 1;
pub global H_SHARES: u32 = 2;
pub global H_BORROW_INDEX: u32 = 3;
pub global H_LAST_ACCRUAL: u32 = 4;
pub global H_NEXT_INDEX: u32 = 5;

/// A borrower leaf's place of index_at_touch.
pub global P_INDEX_AT_TOUCH: u32 = 3;

/// A borrower leaf's places of its delivery handle (pss_core `tip::handle`):
/// the partial commitment at P_HANDLE and the key after it, both 0 while
/// the position holds none. The owner's rounds on the position write it
/// (the request's new handle, on every outcome that writes or re-blinds the
/// leaf); every liquidation that writes the position completes it with the
/// position after the liquidation and keeps it, so the owner learns of each
/// liquidation privately, its notice the position's newest note however
/// many liquidations follow. A lender leaf holds none: no round of another
/// party's changes it.
pub global P_HANDLE: u32 = 4;

/// A position leaf's place of its exit tag (pss_core `tip::exit`): the
/// element before the blinding, which the tagged write fills on every write
/// of the leaf (a round's own value there is replaced). The header holds 0.
pub global P_EXIT_TAG: u32 = LEAF_LEN - 2;

/// Decode the header leaf's three amounts, its borrow index (nonzero, below
/// 2^48) and its last accrual (a u32); its append index and blinding pass
/// through. Constraints: three amount_or, two range clamps and an is_zero.
/// Determined.
pub fn header(leaf: Leaf) -> Header {
    let (total_debt, td_ok) = amount_or(leaf[H_DEBT]);
    let (liquidity, l_ok) = amount_or(leaf[H_LIQUIDITY]);
    let (total_shares, ts_ok) = amount_or(leaf[H_SHARES]);
    let (borrow_index, b_ok) = clamp_bits_or::<INDEX_BITS>(leaf[H_BORROW_INDEX]);
    let (last_accrual, t_ok) = clamp_bits_or::<CLOCK_BITS>(leaf[H_LAST_ACCRUAL]);
    Header {
        total_debt,
        liquidity,
        total_shares,
        borrow_index,
        last_accrual,
        next_index: leaf[H_NEXT_INDEX],
        ok: td_ok & l_ok & ts_ok & b_ok & !is_zero(borrow_index) & t_ok,
    }
}

/// A position's numbers, each 0 when its Field is not a u128, with ok
/// false, and its kind.
pub struct Position {
    /// the leaf's kind is KIND_BORROWER: an opening deposit wrote it
    pub borrower: bool,
    /// the leaf's kind is KIND_LENDER: an opening supply wrote it
    pub lender: bool,
    /// the leaf is not empty (any kind)
    pub opened: bool,
    /// a borrower's collateral, a lender's shares
    pub collateral: u128,
    /// a borrower's debt as of its last touch; a lender's 0
    pub debt: u128,
    /// a borrower's borrow index at its last touch (below 2^48); a
    /// lender's 0
    pub index_at_touch: Field,
    /// both values are u128s and the index below 2^48
    pub ok: bool,
}

/// Decode a position leaf's two amounts and its kind. A lender leaf decodes
/// as a position with no debt, so a liquidation and a scan treat it as one
/// that is never unhealthy (and the scan counts it occupied) without a kind
/// check. Constraints: two amount_or, a 48-bit clamp, two eq and an
/// is_zero. Determined.
pub fn position(leaf: Leaf) -> Position {
    let (collateral, c_ok) = amount_or(leaf[1]);
    let (debt, d_ok) = amount_or(leaf[2]);
    let (index_at_touch, i_ok) = clamp_bits_or::<INDEX_BITS>(leaf[P_INDEX_AT_TOUCH]);
    Position {
        borrower: eq(leaf[0], KIND_BORROWER),
        lender: eq(leaf[0], KIND_LENDER),
        opened: !is_zero(leaf[0]),
        collateral,
        debt,
        index_at_touch,
        ok: c_ok & d_ok & i_ok,
    }
}

/// The value of `shares` of a pool worth `pool` with `total_shares`
/// outstanding, floor(shares * pool / total_shares), rounding toward zero
/// (in the pool's favour), and whether it was computed (false, value 0,
/// when total_shares is 0 or an operand is not a u128). Constraints:
/// mul_div_wide. Determined.
pub fn value_of(shares: Field, pool: Field, total_shares: Field) -> (Field, bool) {
    mul_div_wide(shares, pool, total_shares)
}

mod tests {
    use super::{
        accrue, add_sat, ASSET_BIT, ASSET_COLLATERAL, debt_at, header, INDEX_MAX, INDEX_ONE,
        LEAF_LEN, mul_div_wide, mul_div_wide_up, payout, position, sub_sat, unhealthy_accrued,
        value_of, within_limit_at_price,
    };

    /// The health test at an index of one on both sides: a position whose
    /// debt is as of the current index.
    fn unhealthy_at_price(collateral: Field, debt: Field, price: Field) -> bool {
        unhealthy_accrued(collateral, debt, 1, 1, price)
    }

    /// A header of total_debt `td` and liquidity `liq` (as many shares),
    /// borrow index `b`, last accrual `last`.
    fn hdr(td: Field, liq: Field, b: Field, last: Field) -> super::Header {
        header([td, liq, liq, b, last, 2, 0, 7])
    }

    global TWO_POW_127: Field = 0x80000000000000000000000000000000;
    global TWO_POW_128: Field = 0x100000000000000000000000000000000;
    global U128_MAX: Field = 0xffffffffffffffffffffffffffffffff;
    global U64_MAX: Field = 0xffffffffffffffff;

    #[test]
    fn totals_saturate_and_shares_are_valued_toward_zero() {
        assert_eq(sub_sat(10, 4), 6);
        assert_eq(sub_sat(4, 10), 0);
        // 300 shares of a pool of 1,000 with 700 outstanding: floor(428.57)
        assert_eq(value_of(300, 1000, 700), (428, true));
        assert_eq(value_of(300, 1000, 0), (0, false));
    }

    #[test]
    fn health_of_the_race_position() {
        // Alice's position in the race (README, "Fixtures"): 1000 collateral, 1700 debt
        // at 2.00 is 9,411 bps (unhealthy); after repaying 400, 12,307 bps
        assert(unhealthy_at_price(1000, 1700, 200));
        assert(!unhealthy_at_price(1000, 1300, 200));
        // exactly at the threshold is healthy: 1000 * 200 * 8000 =
        // 1600 * 100 * 10000
        assert(!unhealthy_at_price(1000, 1600, 200));
        assert(unhealthy_at_price(1000, 1601, 200));
        // no debt is never unhealthy, whatever the collateral
        assert(!unhealthy_at_price(0, 0, 200));
        assert(!unhealthy_at_price(0, 0, 1));
        // no collateral with debt is unhealthy
        assert(unhealthy_at_price(0, 1, U64_MAX));
    }

    #[test]
    fn the_borrow_limit_is_below_the_threshold() {
        // 1000 collateral at 2.00 is worth 2000: the limit is 1500 debt, the
        // threshold 1600
        assert(within_limit_at_price(1000, 1500, 200));
        assert(!within_limit_at_price(1000, 1501, 200));
        assert(!unhealthy_at_price(1000, 1501, 200));
        assert(within_limit_at_price(0, 0, 1));
        assert(!within_limit_at_price(0, 1, 0xffffffffffffffff));
    }

    #[test]
    fn a_payout_carries_its_asset_above_the_amount() {
        assert_eq(payout(5, 0), 5);
        assert_eq(payout(5, ASSET_COLLATERAL), ASSET_BIT + 5);
        assert_eq(payout(U128_MAX, ASSET_COLLATERAL), 2 * ASSET_BIT - 1);
    }

    #[test]
    fn health_is_exact_at_the_widest_operands() {
        assert(!unhealthy_at_price(U128_MAX, U128_MAX, U64_MAX));
        assert(unhealthy_at_price(1, U128_MAX, U64_MAX));
        assert(!unhealthy_at_price(625 * U64_MAX, 1000 * U64_MAX, 200));
        assert(unhealthy_at_price(625 * U64_MAX - 1, 1000 * U64_MAX, 200));
    }

    #[test]
    fn mul_div_wide_gives_the_race_liquidation() {
        // the race's liquidation (README): repay = 1700 * 5000 / 10000 = 850; want = 850 * 1050000 /
        // 2000000 = 446.25, floored to 446
        assert_eq(mul_div_wide(1700, 5000, 10000), (850, true));
        assert_eq(mul_div_wide(850, 100 * 10500, 200 * 10000), (446, true));
        assert_eq(mul_div_wide(1, 5000, 10000), (0, true));
    }

    #[test]
    fn mul_div_wide_takes_u128_operands() {
        assert_eq(mul_div_wide(U128_MAX, 5000, 10000), (TWO_POW_127 - 1, true));
        assert_eq(
            mul_div_wide(TWO_POW_127 - 1, 100 * 10500, 10000),
            (105 * (TWO_POW_127 - 1), true),
        );
        assert_eq(mul_div_wide(U128_MAX, U128_MAX, U128_MAX), (U128_MAX, true));
    }

    #[test]
    fn mul_div_wide_refuses_with_zero() {
        assert_eq(mul_div_wide(TWO_POW_127, 257, 1), (0, false));
        assert_eq(mul_div_wide(TWO_POW_127, 256, 1), (0, false));
        assert_eq(mul_div_wide(TWO_POW_127, 128, 1), (TWO_POW_127 * 128, true));
        assert_eq(mul_div_wide(TWO_POW_128, 5000, 10000), (0, false));
        assert_eq(mul_div_wide(1700, TWO_POW_128, 10000), (0, false));
        assert_eq(mul_div_wide(1700, 5000, TWO_POW_128), (0, false));
        assert_eq(mul_div_wide(1700, 5000, 0), (0, false));
    }

    // The accrual (examples/lending-tip/README.md, "Interest") against its
    // closed form. At 80% utilisation (the kink) rate(u) is R0 + R1 = 46 per
    // 10^9 per block: B' = B + ceil(B * 46 * dt / 10^9).
    #[test]
    fn the_accrual_matches_the_closed_form() {
        let h = hdr(800000, 200000, INDEX_ONE, 1000);
        let a = accrue(h, 1100);
        assert_eq(a.utilisation, 8000);
        // 10^9 * 46 * 100 / 10^9 = 4,600 exactly
        assert_eq(a.borrow_index, INDEX_ONE + 4600);
        // 800,000 * 1,000,004,600 / 10^9 = 800,003.68, rounded up
        assert_eq(a.total_debt, 800004);
        assert_eq(a.last_accrual, 1100);
        // at full utilisation rate(u) is 46 + 690 = 736
        let full = accrue(hdr(1000, 0, INDEX_ONE, 0), 10);
        assert_eq(full.borrow_index, INDEX_ONE + 7360);
        // at half the kink (40%): 46 * 4000 / 8000 = 23
        let half = accrue(hdr(400, 600, INDEX_ONE, 0), 1);
        assert_eq(half.borrow_index, INDEX_ONE + 23);
        // past the kink, at 90%: 46 + 690 * 1000 / 2000 = 391
        let past = accrue(hdr(900, 100, INDEX_ONE, 0), 1);
        assert_eq(past.borrow_index, INDEX_ONE + 391);
        // the growth rounds up: B = 3, 1 block at 736 adds a sliver, so 1
        assert_eq(accrue(hdr(1000, 0, 3, 0), 1).borrow_index, 4);
        // an empty pool and a pool without debt accrue nothing at R0 = 0
        assert_eq(accrue(hdr(0, 0, INDEX_ONE, 0), 500).borrow_index, INDEX_ONE);
        assert_eq(accrue(hdr(0, LIQ_ANY, INDEX_ONE, 0), 500).borrow_index, INDEX_ONE);
    }

    global LIQ_ANY: Field = 1000000;

    // A zero elapsed, and a clock behind the last accrual, accrue nothing and
    // never move last_accrual back: a round at the top of the clock band then
    // one at its bottom accrue the interval once.
    #[test]
    fn last_accrual_never_moves_back() {
        let h = hdr(800000, 200000, INDEX_ONE, 1000);
        let same = accrue(h, 1000);
        assert_eq([same.borrow_index, same.total_debt, same.last_accrual], [INDEX_ONE, 800000, 1000]);
        // the top of the band: 128 blocks ahead of the chain's 1,000
        let top = accrue(h, 1128);
        assert_eq(top.last_accrual, 1128);
        let after_top = hdr(top.total_debt, 200000, top.borrow_index, top.last_accrual);
        // then a round at the bottom (872): nothing, last_accrual stays
        let bottom = accrue(after_top, 872);
        assert_eq(
            [bottom.borrow_index, bottom.total_debt, bottom.last_accrual],
            [top.borrow_index, top.total_debt, 1128],
        );
        // and the chain catching up to 1,128 accrues nothing more either
        assert_eq(accrue(after_top, 1128).borrow_index, top.borrow_index);
        // a clock that is not a u32 accrues nothing
        let wild = accrue(h, 0x100000000);
        assert_eq([wild.borrow_index, wild.last_accrual], [INDEX_ONE, 1000]);
    }

    // A long idle period is one large dt, inside the operands: 2^32 - 1
    // blocks at full utilisation multiplies B by about 3,162.
    #[test]
    fn a_long_idle_period_accrues_in_one_step() {
        let a = accrue(hdr(1000, 0, INDEX_ONE, 0), 0xffffffff);
        // 10^9 + 736 * 4,294,967,295 (exact); 1,000 debt to 3,162,095.93, rounded up
        assert_eq(a.borrow_index, INDEX_ONE + 3161095929120);
        assert_eq(a.total_debt, 3162096);
        assert_eq(a.last_accrual, 0xffffffff);
    }

    // The accrual saturates: the borrow index at INDEX_MAX (interest stops),
    // total_debt at 2^128 - 1; it never flags.
    #[test]
    fn the_accrual_saturates() {
        let near = accrue(hdr(1000, 0, INDEX_MAX - 10, 0), 1000);
        assert_eq(near.borrow_index, INDEX_MAX);
        assert_eq(near.total_debt, 1001);
        let top = accrue(hdr(1000, 0, INDEX_MAX, 0), 1000);
        assert_eq([top.borrow_index, top.total_debt], [INDEX_MAX, 1000]);
        let huge = accrue(hdr(U128_MAX, 0, INDEX_ONE, 0), 0xffffffff);
        assert_eq(huge.total_debt, U128_MAX);
        assert_eq(add_sat(U128_MAX, 1), U128_MAX);
        assert_eq(add_sat(5, 6), 11);
    }

    // A position brought to the index rounds up; the health test folds the
    // index into both sides and is exact at the widest operands.
    #[test]
    fn debt_at_the_index_and_health_without_dividing() {
        assert_eq(debt_at(1700, INDEX_ONE, INDEX_ONE), (1700, true));
        // 1,700 * 1.0001 = 1,700.17, rounded up
        assert_eq(debt_at(1700, INDEX_ONE, INDEX_ONE + 100000), (1701, true));
        assert_eq(debt_at(0, INDEX_ONE, INDEX_MAX), (0, true));
        assert_eq(debt_at(1700, 0, INDEX_ONE), (0, false));
        assert_eq(debt_at(U128_MAX as u128, INDEX_ONE, INDEX_ONE + 1), (0, false));
        assert_eq(mul_div_wide_up(7, 3, 2), (11, true));
        assert_eq(mul_div_wide_up(6, 3, 2), (9, true));
        // 1,000 collateral at 2.00 is at the threshold with 1,600 debt; at an
        // index 1.0001 times its touch the same debt is past it
        assert(!unhealthy_accrued(1000, 1600, INDEX_ONE, INDEX_ONE, 200));
        assert(unhealthy_accrued(1000, 1600, INDEX_ONE, INDEX_ONE + 100000, 200));
        // 1,599.84 at touch is 1,599.999... at 1.0001: still healthy
        assert(!unhealthy_accrued(1000, 1599, INDEX_ONE, INDEX_ONE + 100000, 200));
        // a lender's leaf (debt 0, index 0) and an empty one never
        assert(!unhealthy_accrued(300, 0, 0, INDEX_MAX, 1));
        // the widest: collateral, price and index at their bounds
        assert(!unhealthy_accrued(U128_MAX, U128_MAX, INDEX_MAX, INDEX_MAX, U64_MAX));
        assert(unhealthy_accrued(1, U128_MAX, INDEX_MAX, INDEX_MAX, U64_MAX));
    }

    #[test]
    fn decoding_flags_every_bad_value() {
        let h = header([20, 30, 40, 1000000000, 0, 2, 0, 7]);
        let p = position([1, 10, 20, 1000000000, 0, 0, 0, 8]);
        assert(h.ok & p.ok);
        assert(p.borrower & !p.lender & p.opened);
        assert_eq([h.total_debt, h.liquidity, h.total_shares], [20, 30, 40]);
        assert_eq(h.next_index, 2);
        assert_eq(h.pool(), 50);
        // a lender leaf decodes as a position without debt
        let l = position([2, 300, 0, 0, 0, 0, 0, 9]);
        assert(l.lender & !l.borrower & l.opened & (l.debt == 0) & (l.collateral == 300));
        // an empty leaf is no kind
        let e = position([0; LEAF_LEN]);
        assert(!e.opened & !e.borrower & !e.lender);
        // a third kind is neither
        let odd = position([3, 10, 20, 0, 0, 0, 0, 8]);
        assert(odd.opened & !odd.borrower & !odd.lender);
        assert_eq([h.borrow_index, h.last_accrual, p.index_at_touch], [INDEX_ONE, 0, INDEX_ONE]);
        assert(header([U128_MAX, 0, U128_MAX, INDEX_MAX, 0xffffffff, 1, 0, 0]).ok);
        assert(!position([1, TWO_POW_128, 20, 0, 0, 0, 0, 0]).ok);
        assert(!position([1, 10, 0 - 1, 0, 0, 0, 0, 0]).ok);
        assert(!position([1, 10, 20, INDEX_MAX + 1, 0, 0, 0, 0]).ok);
        assert(!header([10, 20, TWO_POW_128, INDEX_ONE, 0, 1, 0, 0]).ok);
        // the borrow index nonzero and below 2^48, the last accrual a u32
        assert(!header([10, 20, 30, 0, 0, 1, 0, 0]).ok);
        assert(!header([10, 20, 30, INDEX_MAX + 1, 0, 1, 0, 0]).ok);
        assert(!header([10, 20, 30, INDEX_ONE, 0x100000000, 1, 0, 0]).ok);
    }
}
