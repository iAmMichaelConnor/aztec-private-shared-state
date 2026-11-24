//! The total constant-product swap: the trade the baseline's
//! amm::pool::Pool::swap makes, with every failure reported in an Outcome
//! instead of failing a constraint. The baseline is
//! examples/amm/circuits/amm (src/pool.nr) and its amm_swap round here;
//! total-noir's examples/amm_swap_baseline is the same circuit.
//!
//! Pool state is the note preimage [reserve_x, reserve_y]. A swap sells
//! amount_in of one asset (direction 0 sells x for y, 1 sells y for x)
//! and pays out
//!     out = r_out * amount_in / (r_in + amount_in)   (rounded down)
//! with the same integer semantics as the baseline: reserves and amounts
//! are u64, the product is formed at double width (128 bits), the
//! quotient is floored.
//!
//! Rounding: floor, as the baseline does, so the pool never pays out the
//! fraction and the product of the reserves never decreases. Rounding up
//! (or to nearest) would let a trader extract value one unit at a time;
//! any change here must keep the product invariant.
//!
//! Failure codes. The Outcome keeps the code of the first failing check,
//! and the checks run in the order the baseline evaluates them: first the
//! range checks the baseline puts on its typed entry parameters
//! (amount_in, then direction), then the decoding of the note preimage
//! (which the baseline does not check), then Pool::swap's asserts in
//! source order (zero input, overflow, rounds to zero, drain).
//!
//!   check order  code  meaning                              baseline
//!   1            2     amount_in is not a u64               u64 param range
//!   2            3     direction is not 0 or 1              bool param range
//!   3            7     a reserve in the preimage is not u64 none (truncates)
//!   4            1     amount_in is zero                    assert in > 0
//!   5            4     r_in + amount_in overflows 64 bits   u64 add overflow
//!   6            5     the output rounds to zero            assert out > 0
//!   7            6     the output would drain the pool      assert out < r_out
//!
//! Code 7 is defensive: the note preimage was written by an earlier
//! proven round, which only ever writes u64 reserves (see swap_total), so
//! the protocol cannot reach it. Code 6 is reachable only with an empty
//! input reserve (r_in = 0 gives out = r_out); otherwise out < r_out
//! because amount_in < r_in + amount_in.
//!
//! The zero check reads the raw Field, so codes 1 and 2 never both apply
//! (0 is a u64); their relative order does not matter.
//!
//! The codes and their order are fixed as above. The code is a public
//! output that contracts and clients read (the total swaps of
//! examples/amm and examples/amm-tip pass it on with ok), so a renumbering
//! changes every consumer and every vk hash built on this function.
//! Reporting the first failure rather than a bit mask keeps the output one
//! small Field and reveals less about the pool (one reason, not every
//! reason).

// co-noir: the network extends this circuit's witness in co-noir, whose
// Brillig VM at the pinned co-snarks rev has no integer shift, mask or
// ConditionalMov. Every total entry called here (to_u64_or, bool_or,
// TotalArith's add_or, TotalMulDiv's mul_div_or, is_zero, lt and neq on
// u64, from_u64, Outcome and Select) has hints that avoid them
// (total-noir's page "co-noir compatibility of the library's hints"), and
// `total-lint --brillig-ops` on the compiled round reports 0 such ops.
use total::arith::{TotalArith, TotalMulDiv};
use total::cmp::{is_zero, lt, neq};
use total::convert::{bool_or, from_u64, to_u64_or};
use total::ctl::{Outcome, Select};

/// amount_in is zero.
pub global CODE_ZERO_INPUT: Field = 1;
/// amount_in is not below 2^64.
pub global CODE_AMOUNT_RANGE: Field = 2;
/// direction is neither 0 nor 1.
pub global CODE_DIRECTION: Field = 3;
/// The new input reserve r_in + amount_in is not below 2^64.
pub global CODE_RESERVE_OVERFLOW: Field = 4;
/// The output r_out * amount_in / (r_in + amount_in) floors to zero.
pub global CODE_ROUNDS_TO_ZERO: Field = 5;
/// The output is at least the output reserve.
pub global CODE_DRAINS_POOL: Field = 6;
/// A reserve in the note preimage is not below 2^64.
pub global CODE_BAD_RESERVE: Field = 7;

/// What one swap produces. On outcome.ok = false, new_reserves equals the
/// reserves passed in (raw, unchanged) and amount_out is 0.
pub struct SwapResult {
    pub outcome: Outcome,
    pub new_reserves: [Field; 2],
    pub amount_out: Field,
}

/// Apply one swap to the pool preimage `reserves` = [x, y], with raw
/// Field inputs. Defined for every input; never fails a constraint.
///
/// On success (outcome.ok) the result equals the baseline's
/// Pool::swap(amount_in, direction): new_reserves = [x', y'] with the
/// input reserve increased by amount_in and the output reserve decreased
/// by amount_out, both below 2^64, so the next round decodes them without
/// code 7. On failure the reserves are returned unchanged, amount_out is
/// 0, and outcome.code is the first failing check (module header).
///
/// Steps, all library calls (co-noir-safe; see the comment at the
/// imports):
/// - to_u64_or on amount_in and on each reserve, bool_or on direction:
///   the flags feed codes 2, 3 and 7; the values are 0 (or false) when the
///   flag is false, so the arithmetic below always runs on in-range
///   operands.
/// - r_in, r_out by u64 Select::select on the direction bit.
/// - new_in by u64 add_or (code 4).
/// - out = floor(r_out * amount_in / new_in) by the fused u64 mul_div_or:
///   the product is formed in the field at double width, and the
///   quotient is range-checked to 64 bits, so out is a u64 with no
///   further cast. mul_div_or selects the divisor to 1 (and the dividend
///   to 0) before its hint runs when new_in is 0.
/// - rounds-to-zero by neq(out, 0) (code 5), drain by lt(out, r_out)
///   (code 6).
/// - the new reserves by select on the direction bit, then
///   Outcome::guard against the old reserves; amount_out by mask_field.
///
/// The quotient width: 64 bits (the u64 facade),
/// with mul_div_or's flag (new_in != 0 and the quotient fits 64 bits)
/// folded into the overflow check, code 4. The flag cannot fire on its
/// own: without a 64-bit overflow, out <= r_out < 2^64 because
/// amount_in <= r_in + amount_in, and new_in = 0 needs amount_in = 0
/// (code 1) or an overflow (code 4), both checked earlier. Taking the
/// 128-bit quotient (mul_div_or::<64> on Fields) would never set the
/// flag but would cost the input clamps and a wider drain comparison, so
/// 64 bits stands while reserves are u64.
///
/// Constraints, all emitted by the library entries above (see their doc
/// comments): the core::limbs set, a low-limb split, two is_zero gadgets
/// and an exact cast (64-bit RANGE on a hinted u64 plus an equality) per
/// to_u64_or; two eq gadgets in bool_or; one is_zero gadget on amount_in;
/// core add_split at 64 bits in add_or (hinted carry with 1-bit RANGE,
/// 64-bit RANGE on the low part); in mul_div_or an is_zero on the
/// divisor, two selects, 64-bit RANGEs on the hinted quotient's low and
/// high halves, an is_zero on the high half, 64-bit RANGEs on the hinted
/// remainder and on divisor - remainder - 1, and the identity
/// r_out * amount_in == quotient * divisor + remainder in the field;
/// the inversion gadget for neq; the native u64 `<` (hinted borrow bit
/// with a 1-bit RANGE, a hinted remainder with a 64-bit RANGE, and the
/// reconstruction); and select arithmetic for Select, Outcome,
/// guard and mask_field.
///
/// Classification: no constraint here is input-falsifiable. The range
/// checks and asserts restrict library hints, and every library entry is
/// total for every value of its argument types; this function passes
/// those entries only values of the right type and range (raw Fields go
/// through to_u64_or and bool_or first; u64 operands carry the
/// type invariant, established by the library's exact casts and
/// range-checked results). The rest are definitions.
///
/// Hint rule: this package adds no hint of its own; the honest prover
/// runs the library's hints (canonical limbs, exact splits, the true
/// carry, borrow and comparison bits, the Euclidean quotient and
/// remainder of the double-width product).
///
/// Determinedness: every flag the library returns is determined, every
/// value it returns is the unique one its constraints allow (exact casts
/// pin the typed values, the splits and the Euclidean pair are unique),
/// and everything else is select arithmetic on those. So outcome.ok,
/// outcome.code, new_reserves and amount_out are functions of
/// (reserves, amount_in, direction): a dishonest prover cannot change any
/// of them.
pub fn swap_total(reserves: [Field; 2], amount_in: Field, direction: Field) -> SwapResult {
    let (amount, amount_ok) = to_u64_or(amount_in);
    let (dir, dir_ok) = bool_or(direction);
    let (x, x_ok) = to_u64_or(reserves[0]);
    let (y, y_ok) = to_u64_or(reserves[1]);

    let r_in: u64 = Select::select(dir, y, x);
    let r_out: u64 = Select::select(dir, x, y);

    let (new_in, add_ok) = r_in.add_or(amount);
    let (out, _, quotient_ok) = r_out.mul_div_or(amount, new_in);

    let outcome = Outcome::good()
        .require(amount_ok, CODE_AMOUNT_RANGE)
        .require(dir_ok, CODE_DIRECTION)
        .require(x_ok & y_ok, CODE_BAD_RESERVE)
        .require(!is_zero(amount_in), CODE_ZERO_INPUT)
        .require(add_ok & quotient_ok, CODE_RESERVE_OVERFLOW)
        .require(neq(out, 0), CODE_ROUNDS_TO_ZERO)
        .require(lt(out, r_out), CODE_DRAINS_POOL);

    // On success out < r_out, so this is the exact new output reserve; on
    // failure it is discarded by the guard.
    let out_value = from_u64(out);
    let new_in_value = from_u64(new_in);
    let new_out_value = from_u64(r_out) - out_value;
    let swapped: [Field; 2] = Select::select(
        dir,
        [new_out_value, new_in_value],
        [new_in_value, new_out_value],
    );

    SwapResult {
        outcome,
        new_reserves: outcome.guard(swapped, reserves),
        amount_out: outcome.mask_field(out_value),
    }
}

mod tests {
    use super::{
        CODE_AMOUNT_RANGE, CODE_BAD_RESERVE, CODE_DIRECTION, CODE_DRAINS_POOL,
        CODE_RESERVE_OVERFLOW, CODE_ROUNDS_TO_ZERO, CODE_ZERO_INPUT, swap_total,
    };
    use amm::pool::Pool;
    use pss_core::prng::Prng;

    global TWO_POW_64: Field = 0x10000000000000000;
    global P_MINUS_1: Field = 0 - 1;

    /// The baseline's numbers, `(new_x, new_y, out)`: examples/amm's
    /// asserting `Pool::swap` itself, a second implementation (native u64
    /// and u128 arithmetic with asserts) of the formula `swap_total` computes
    /// with total gadgets. Fails (as the baseline does) on inputs the
    /// baseline rejects; tests call it only on accepted inputs.
    fn reference_swap(x: u64, y: u64, amount_in: u64, direction: bool) -> (u64, u64, u64) {
        let (pool, out) = Pool { x, y }.swap(amount_in, direction);
        (pool.x, pool.y, out)
    }

    /// The baseline's starting reserves (`Pool::from_seed`): each in [1e6, 2e6).
    fn pool_from_seed(seed: Field) -> (u64, u64) {
        let pool = Pool::from_seed(seed);
        (pool.x, pool.y)
    }

    /// Swap, require success, and require the baseline's numbers.
    fn swap_matches_reference(x: u64, y: u64, amount_in: u64, direction: bool) -> (u64, u64, u64) {
        let r = swap_total(
            [x as Field, y as Field],
            amount_in as Field,
            direction as Field,
        );
        assert(r.outcome.ok);
        assert_eq(r.outcome.code, 0);
        let (nx, ny, out) = reference_swap(x, y, amount_in, direction);
        assert_eq(r.amount_out, out as Field);
        assert_eq(r.new_reserves, [nx as Field, ny as Field]);
        (nx, ny, out)
    }

    /// Swap and require the rejection contract: ok = false, the expected
    /// first-failure code, amount_out = 0, reserves unchanged.
    fn assert_rejected(reserves: [Field; 2], amount_in: Field, direction: Field, code: Field) {
        let r = swap_total(reserves, amount_in, direction);
        assert(!r.outcome.ok);
        assert_eq(r.outcome.code, code);
        assert_eq(r.amount_out, 0);
        assert_eq(r.new_reserves, reserves);
    }

    // ---- the baseline's tests, numerically ----

    #[test]
    fn swap_x_for_y() {
        let (nx, ny, out) = swap_matches_reference(1_000_000, 2_000_000, 1_000, false);
        // 2_000_000 * 1_000 / 1_001_000 = 1998.002 -> 1998
        assert_eq(out, 1998);
        assert_eq(nx, 1_001_000);
        assert_eq(ny, 2_000_000 - 1998);
    }

    #[test]
    fn swap_y_for_x() {
        let (nx, ny, out) = swap_matches_reference(1_000_000, 2_000_000, 1_000, true);
        // 1_000_000 * 1_000 / 2_001_000 = 499.75 -> 499
        assert_eq(out, 499);
        assert_eq(nx, 1_000_000 - 499);
        assert_eq(ny, 2_001_000);
    }

    #[test]
    fn round_trip_swap_does_not_profit() {
        let (x, y) = pool_from_seed(7);
        let (x1, y1, y_out) = swap_matches_reference(x, y, 50_000, false);
        let (_, _, x_back) = swap_matches_reference(x1, y1, y_out, true);
        assert(x_back <= 50_000);
    }

    #[test]
    fn product_never_decreases() {
        for seed in 0..3 {
            let (mut x, mut y) = pool_from_seed(seed as Field);
            let mut prng = Prng::init(seed as Field + 1000);
            for i in 0..6 {
                let amount_in = 1_000 + (prng.get_field() as u64 % 1_000_000);
                let before = (x as u128) * (y as u128);
                let (nx, ny, out) = swap_matches_reference(x, y, amount_in, i % 2 == 1);
                assert(out > 0);
                assert((nx as u128) * (ny as u128) >= before);
                x = nx;
                y = ny;
            }
        }
    }

    #[test]
    fn baseline_prover_trade() {
        // The baseline Prover.toml: 25000 x for y on [1359373, 1852331].
        let (nx, ny, out) = swap_matches_reference(1_359_373, 1_852_331, 25_000, false);
        assert_eq(out, 33_450);
        assert_eq(nx, 1_384_373);
        assert_eq(ny, 1_818_881);
    }

    #[test]
    fn largest_amount_without_overflow() {
        // r_in + amount_in = 2^64 - 1: accepted, and the output reserve
        // keeps 1.
        let amount: u64 = 0xffffffffffffffff - 1_000_000;
        let (nx, ny, out) = swap_matches_reference(1_000_000, 2_000_000, amount, false);
        assert_eq(nx, 0xffffffffffffffff);
        assert_eq(out, 1_999_999);
        assert_eq(ny, 1);
    }

    // ---- adversarial: ok = false, the right code, nothing moves ----

    #[test]
    fn zero_amount() {
        assert_rejected([1_000_000, 1_000_000], 0, 0, CODE_ZERO_INPUT);
    }

    #[test]
    fn amount_two_pow_64() {
        assert_rejected([1_000_000, 1_000_000], TWO_POW_64, 0, CODE_AMOUNT_RANGE);
    }

    #[test]
    fn amount_p_minus_1() {
        assert_rejected([1_000_000, 1_000_000], P_MINUS_1, 1, CODE_AMOUNT_RANGE);
    }

    #[test]
    fn direction_two() {
        assert_rejected([1_000_000, 1_000_000], 1_000, 2, CODE_DIRECTION);
    }

    #[test]
    fn direction_p_minus_1() {
        assert_rejected([1_000_000, 1_000_000], 1_000, P_MINUS_1, CODE_DIRECTION);
    }

    #[test]
    fn empty_input_reserve() {
        // r_in = 0: the formula pays out all of r_out
        assert_rejected([0, 1_000_000], 5, 0, CODE_DRAINS_POOL);
        assert_rejected([1_000_000, 0], 5, 1, CODE_DRAINS_POOL);
    }

    #[test]
    fn dust_rounds_to_zero() {
        // 1_000_000 * 1 / 2_000_001 = 0
        assert_rejected([2_000_000, 1_000_000], 1, 0, CODE_ROUNDS_TO_ZERO);
    }

    #[test]
    fn add_overflow() {
        // r_in + amount_in = 2^64 exactly
        assert_rejected(
            [1_000_000, 2_000_000],
            TWO_POW_64 - 1_000_000,
            0,
            CODE_RESERVE_OVERFLOW,
        );
        // the baseline's oversize case: amount = 2^64 - 1
        assert_rejected(
            [1_000_000, 1_000_000],
            0xffffffffffffffff,
            0,
            CODE_RESERVE_OVERFLOW,
        );
        // overflow that wraps the new reserve to exactly 0 (the divisor
        // is selected to 1)
        assert_rejected([2_000_000, 1], TWO_POW_64 - 1, 1, CODE_RESERVE_OVERFLOW);
    }

    #[test]
    fn reserve_two_pow_64() {
        assert_rejected([TWO_POW_64, 1_000_000], 1_000, 0, CODE_BAD_RESERVE);
        assert_rejected([1_000_000, TWO_POW_64], 1_000, 1, CODE_BAD_RESERVE);
        assert_rejected([1_000_000, P_MINUS_1], 1_000, 0, CODE_BAD_RESERVE);
    }

    // ---- first failure wins, in the baseline's order ----

    #[test]
    fn first_failure_code_wins() {
        // bad direction is checked before zero input
        assert_rejected([1_000_000, 1_000_000], 0, 2, CODE_DIRECTION);
        // oversize amount before bad direction
        assert_rejected([1_000_000, 1_000_000], TWO_POW_64, 2, CODE_AMOUNT_RANGE);
        // bad reserve before zero input
        assert_rejected([TWO_POW_64, 1_000_000], 0, 0, CODE_BAD_RESERVE);
        // zero input before drain on an empty input reserve
        assert_rejected([0, 1_000_000], 0, 0, CODE_ZERO_INPUT);
        // overflow before drain: r_in = 0 cannot overflow, so overflow on
        // the other side with a small output reserve
        assert_rejected([5, 1], TWO_POW_64 - 1, 0, CODE_RESERVE_OVERFLOW);
        // dust before drain cannot both apply (out = 0 < r_out unless
        // r_out = 0); with r_out = 0 the output rounds to zero first
        assert_rejected([1_000_000, 0], 1_000, 0, CODE_ROUNDS_TO_ZERO);
    }
}
