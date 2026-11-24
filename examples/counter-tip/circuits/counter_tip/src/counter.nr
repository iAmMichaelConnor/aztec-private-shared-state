//! The app's rule: add an amount to a running total. Total: a request that
//! cannot apply is a flagged no-op, never an unsatisfiable circuit, so the
//! queue always moves.
use total::arith::add_or;
use total::ctl::Outcome;

/// The shares do not open to the request's C (the round's first check).
pub global CODE_INPUTS_MISMATCH: Field = 1;

/// The new total does not fit in a u64.
pub global CODE_OVERFLOW: Field = 2;

/// The total's width: a u64.
pub global TOTAL_BITS: u32 = 64;

/// The outcome the requester reads, `[code, total]`: the code (0 when the
/// amount was added) and the total after the round (0 when it failed).
pub global OUTCOME_FIELDS: u32 = 2;

/// One round's step: its outcome and the total to store when it is ok.
pub struct Added {
    pub outcome: Outcome,
    pub total: Field,
}

/// Add `amount` to `total`, after the checks `outcome` already holds.
/// `CODE_OVERFLOW` when the sum (or either value) is not a u64; the slot
/// brick keeps the loaded total whenever the outcome is not ok, so the step
/// does not select.
///
/// Constraints: total-noir's `add_or::<64>` (two range clamps, a split and a
/// select, hint-satisfiable for every Field) and one `require`. No assert.
pub fn add(total: Field, amount: Field, outcome: Outcome) -> Added {
    let (sum, fits) = add_or::<TOTAL_BITS>(total, amount);
    Added { outcome: outcome.require(fits, CODE_OVERFLOW), total: sum }
}

/// The outcome plaintext of a step: `[code, total]`, the total masked to 0
/// when the step failed, so a failed request learns nothing of it.
///
/// DEV DECISION: what the requester learns, default the total after its own
/// add. A requester then sees the running total at its turn; an add of 0 is
/// a private read of it. Alternative: `[code]` alone (OUTCOME_FIELDS 1, the
/// contract's note one field shorter), so nobody but two colluding nodes
/// ever sees the total. Design guide: "who learns the outcome".
pub fn outcome_fields(a: Added) -> [Field; OUTCOME_FIELDS] {
    [a.outcome.code, a.outcome.mask_field(a.total)]
}

mod tests {
    use super::{add, CODE_INPUTS_MISMATCH, CODE_OVERFLOW, outcome_fields};
    use total::ctl::Outcome;

    global U64_MAX: Field = 0xffffffffffffffff;

    #[test]
    fn an_add_sums_and_reports_the_new_total() {
        let a = add(10, 5, Outcome::good());
        assert(a.outcome.ok);
        assert_eq(a.total, 15);
        assert_eq(outcome_fields(a), [0, 15]);
    }

    #[test]
    fn an_add_of_zero_reads_the_total() {
        assert_eq(outcome_fields(add(42, 0, Outcome::good())), [0, 42]);
    }

    #[test]
    fn an_add_to_the_u64_limit_fits_and_one_more_overflows() {
        assert_eq(outcome_fields(add(U64_MAX - 1, 1, Outcome::good())), [0, U64_MAX]);
        let a = add(U64_MAX, 1, Outcome::good());
        assert(!a.outcome.ok);
        assert_eq(outcome_fields(a), [CODE_OVERFLOW, 0]);
        // an amount that is no u64 overflows too
        assert_eq(add(0, U64_MAX + 1, Outcome::good()).outcome.code, CODE_OVERFLOW);
    }

    #[test]
    fn an_earlier_failure_keeps_its_code_and_hides_the_total() {
        let a = add(10, 5, Outcome::good().require(false, CODE_INPUTS_MISMATCH));
        assert_eq(outcome_fields(a), [CODE_INPUTS_MISMATCH, 0]);
    }
}
