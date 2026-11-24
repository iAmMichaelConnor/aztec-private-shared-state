//! One swap at the tip, total, under either intake family.
//!
//! swap_round applies amm_total's swap_total to the pool the machine LOADs
//! (pss_core's tip::slot::Loaded), adds the trader's slippage limit
//! (min_out, code 8), writes the pool key and returns the round's public
//! outputs under the family the main names (pss_core's tip::family:
//! `Plain`, the public outcome, or `SharedIntake`, the private one). It
//! never fails a constraint: every check is a flag folded into one Outcome.
//!
//! Failure codes. Codes 1 to 7 are amm_total's (examples/amm-swap-total
//! src/swap.nr has the table and the check order 2, 3, 7, 1, 4, 5, 6);
//! this library adds three:
//!
//!   code  meaning                                      checked
//!   9     the shares do not open to C (secret-shared intake)   first (shared.nr)
//!   10    amount_in below MIN_TRADE (the upgraded swap,
//!         `swap_round_min_trade`, only)                 first
//!   8     the swap succeeds but pays out below min_out  after codes 1 to 7
//!
//! The codes and their order: under a secret-shared intake code 9 (the MPC receipt check) first, then amm_total's codes 1 to 7 in
//! its first-failure order, then code 8. Code 9 comes first because inputs
//! that are not the request's make every later check meaningless; code 8
//! is checked last because it is the only condition the trader sets
//! against the state, so a request that is malformed or cannot trade at
//! all reports that reason, not the limit. The non-secret-shared intakes' code is a
//! public output the contract, the relayer and the trader read, and the
//! secret-shared intake's is inside the outcome the trader opens, so renumbering
//! changes every consumer and the vk hashes.
//!
//! The state width: one flat node-held key of 3 shared elements (two u64
//! reserves and the blinding: the manifest's outputs[0].len and the LOAD's
//! len). The nodes store the vector as one version per commitment and no
//! apply logs it, so the width is bounded by the circuit, not by a public
//! log. The reserves are u64 because amm_total's swap is (its quotient
//! width); a wider pool needs a wider swap there first.

// co-noir: the network extends this circuit's witness in co-noir, whose
// Brillig VM at the pinned co-snarks rev has no integer shift, mask or
// ConditionalMov. The swap arithmetic comes from amm_total's swap_total
// (to_u64_or, add_or, mul_div_or); this file adds gte on Field (limbs and
// two bounded comparisons), Outcome and pss_core's tip helpers (p2_hash_sep
// and selects). Every one has hints co-noir runs (total-noir's page
// "co-noir compatibility of the library's hints"; `total-lint --brillig-ops` on
// amm_swap_tip reports 0). A total entry added here must be one that page does not
// exclude; required inside the co-SNARK.
use crate::shared::{CODE_INPUTS_MISMATCH, OUTCOME_FIELDS, OUTCOME_SLOT};
use amm_total::swap::swap_total;
use pss_core::tip::family::{Checked, Family, Finish};
use pss_core::tip::outputs::{BoundPartial, Finished};
use pss_core::tip::slot::{Loaded, Round};
use total::cmp::gte;
use total::ctl::Outcome;

/// The swap paid out less than the trader's min_out.
pub global CODE_MIN_OUT: Field = 8;

/// A swap under the non-secret-shared intakes, finished: the round over the
/// pool key and its public outputs, `[request_id, old_c, new_c,
/// npk_app_hash, ok, partial_note, code, amount_out]`. On ok = false the
/// round stores the pool as loaded under r_old, amount_out is 0, so new_c
/// is old_c.
pub type PlainRound = Finished<Round<2>, BoundPartial<SwapOutputs>>;

/// The swap's app outputs, after `ok` in the round's public outputs.
///
/// DEV DECISION: the swap's reveal, default [ok, code, amount_out] as
/// Fields: public outputs under the non-secret-shared intakes, the encrypted outcome
/// under the secret-shared one (shared.nr `OUTCOME_FIELDS`). Design guide: "the
/// outcome fields".
///
/// ok and the code tell apply, the relayer and the trader whether the
/// trade happened and why not; amount_out is what apply pays. As in every AMM, amount_out
/// with amount_in prices the pool, and the code adds a little (code 5
/// bounds r_out * amount_in, code 6 names an empty input reserve). Under
/// receipt intake, whose inputs stay off the chain, they stay public too,
/// because apply pays amount_out: they tell the world that some request
/// succeeded or failed and for which reason, though not whose or with
/// which inputs.
pub struct SwapOutputs {
    /// 0 when ok, else the first failing check, 1 to 8 (10 under the
    /// upgraded swap)
    pub code: Field,
    /// the amount paid out, 0 when ok = 0
    pub amount_out: Field,
}

/// One swap of the AMM at the tip under the intake family `family`, total:
/// defined for every input, never fails a constraint.
///
/// - the intake's check (`Family::check`): under a secret-shared intake, C
///   opens to the inputs, `$partial_note`, `$outcome_key` and
///   `$outcome_tag` under `$blinding`, else code 9 first; nothing under
///   the non-secret-shared intakes.
/// - swap_total(pool, amount_in, direction): codes 1 to 7, the new
///   reserves or the old ones, amount_out or 0.
/// - min_out: gte(amount_out, min_out) over the field order, code 8.
/// - the write (`Checked::write` of the pool's `Loaded::change`): under the
///   non-secret-shared intakes `Loaded::finish`, the new reserves when ok
///   and the loaded ones under r_old when not (the fail rule and the
///   blinding rule), so new_c = old_c on failure; under a secret-shared
///   one `Loaded::finish_private`, a fresh blinding on every outcome and
///   the new reserves only when C opens.
/// - the outputs (`Checked::finish`): under the non-secret-shared intakes
///   the request id over the inputs and the partial note and
///   `SwapOutputs` after `ok` and the partial note, which apply completes
///   the trader's note with; under a secret-shared one `[code,
///   amount_out]`, the trader's partial note completed with it at
///   `OUTCOME_SLOT` and the outcome encrypted under that note hash's nonce
///   (shared.nr). A failed swap
///   completes its note too, `[code, 0, request_id]`.
///
/// `inputs` is [amount_in, direction, min_out], the app inputs in ABI
/// order, the array inputs_hash covers.
///
/// min_out is the trader's limit against earlier requests in the queue:
/// a raw Field input, always present; 0 means no limit (every amount_out >= 0). It is
/// compared with amount_out over the canonical field order, so a min_out
/// at or above 2^64 can never be met and reports code 8: no separate
/// range code, and the intake's static checks may refuse such a request
/// first. Optional in the sense that 0 disables it; dropping the
/// parameter instead would change the ABI and the request id.
///
/// The widths: amount_in and the reserves are u64 (amm_total converts the
/// raw Fields with flags, codes 2 and 7); direction is 0 or 1 (code 3);
/// min_out is any Field (above).
///
/// Constraints: the family's check (under a secret-shared intake one
/// p2_hash and one equality), swap_total's (library entries only; its doc
/// comment lists and classifies them), the write (its selects, one
/// equality and two p2_hash_sep: permutations and additions), one Field gte
/// (total::cmp field_lt: canonical-limb decompositions with hinted limbs,
/// range checks and the borrow; reviewed, whitelisted by --lib-src
/// total/src/), one Outcome::require and the selects of guard and
/// mask_field, and the family's outputs (pss_core tip::family: two p2_hash
/// for the request id, or the machine request id, the outcome's AEAD and
/// the completed note hash; and npk_app_hash, the std scalar decomposition
/// of nsk_app, hint-satisfiable for every Field, and one fixed-base
/// multi_scalar_mul, which cannot fail). The store is an unconstrained
/// side-effect-only oracle (`Finished::stored`). No assert, no native
/// arithmetic on an input-driven value, no cast, no index: nothing
/// input-falsifiable. This package adds no hint.
///
/// Determinedness: swap_total's outputs are determined, gte's flag is
/// determined, and the rest is hashing and select arithmetic, so every
/// output is a function of the arguments.
pub fn swap_round<F>(
    vk_hash: Field,
    key: Loaded<2>,
    inputs: [Field; 3],
    family: F,
    nsk_app: Field,
) -> <F as Finish<Round<2>, SwapOutputs, 0, OUTCOME_FIELDS>>::Out
where
    F: Family + Finish<Round<2>, SwapOutputs, 0, OUTCOME_FIELDS>,
{
    let checked = family.check(inputs, CODE_INPUTS_MISMATCH);
    finish_swap(vk_hash, key, inputs, checked, checked.first, nsk_app)
}

/// The upgraded swap's own code: `amount_in` below `MIN_TRADE`.
pub global CODE_BELOW_MIN_TRADE: Field = 10;

/// The least `amount_in` the upgraded swap trades.
pub global MIN_TRADE: Field = 100;

/// The swap of `amm_swap_tip_next`, the upgraded circuit the e2e's circuit
/// upgrade registers under the package `amm_swap_tip`: `swap_round` with
/// one rule after the intake's check, a trade of less than `MIN_TRADE` is
/// refused with code `CODE_BELOW_MIN_TRADE` (10), which wins over every
/// swap code, so a zero input reports 10 here where `swap_round` reports 1.
/// A visible and harmless difference: such a request lands as a no-op that
/// pays nothing, and every other request trades exactly as under
/// `swap_round`.
///
/// Total, as `swap_round`: one more Field gte and Outcome::require.
pub fn swap_round_min_trade<F>(
    vk_hash: Field,
    key: Loaded<2>,
    inputs: [Field; 3],
    family: F,
    nsk_app: Field,
) -> <F as Finish<Round<2>, SwapOutputs, 0, OUTCOME_FIELDS>>::Out
where
    F: Family + Finish<Round<2>, SwapOutputs, 0, OUTCOME_FIELDS>,
{
    let checked = family.check(inputs, CODE_INPUTS_MISMATCH);
    let first = checked.first.require(gte(inputs[0], MIN_TRADE), CODE_BELOW_MIN_TRADE);
    finish_swap(vk_hash, key, inputs, checked, first, nsk_app)
}

/// The swap after the checks `first`, the pool written in the family's
/// form and the family's outputs: the one body of `swap_round` and
/// `swap_round_min_trade`.
fn finish_swap<F>(
    vk_hash: Field,
    key: Loaded<2>,
    inputs: [Field; 3],
    checked: Checked<F>,
    first: Outcome,
    nsk_app: Field,
) -> <F as Finish<Round<2>, SwapOutputs, 0, OUTCOME_FIELDS>>::Out
where
    F: Family + Finish<Round<2>, SwapOutputs, 0, OUTCOME_FIELDS>,
{
    let s = swap(key.fields, inputs, first);
    let round = checked.write(key.change(s.outcome, s.new_reserves));
    let outputs = SwapOutputs { code: s.outcome.code, amount_out: s.amount_out };
    let fields = [s.outcome.code, s.amount_out];
    checked.finish(round, key.namespace, vk_hash, inputs, [], outputs, fields, OUTCOME_SLOT, nsk_app)
}

/// One swap over a pool, before the round over its key is finished: the
/// outcome, the reserves to store when it is ok and the amount paid out (0
/// when not).
pub struct Swap {
    pub outcome: Outcome,
    pub new_reserves: [Field; 2],
    pub amount_out: Field,
}

/// The swap of `swap_round` over `pool` after the checks `first` has already
/// made: swap_total's codes, then min_out's, each recorded only while
/// `first` and every earlier check pass, so `first`'s code wins (a secret-shared
/// intake's code 9, shared.nr). `Outcome::good()` for the non-secret-shared intakes.
/// amount_out is masked by the final outcome, so it is 0 whenever ok is
/// false, whichever check failed.
///
/// Total, as `swap_round`; and_outcome is one bool product and one select.
pub fn swap(pool: [Field; 2], inputs: [Field; 3], first: Outcome) -> Swap {
    let swap = swap_total(pool, inputs[0], inputs[1]);
    let outcome =
        first.and_outcome(swap.outcome).require(gte(swap.amount_out, inputs[2]), CODE_MIN_OUT);
    Swap {
        outcome,
        new_reserves: swap.new_reserves,
        amount_out: outcome.mask_field(swap.amount_out),
    }
}

mod tests {
    use super::{CODE_MIN_OUT, PlainRound, swap_round};
    use amm_total::swap::{
        CODE_AMOUNT_RANGE, CODE_BAD_RESERVE, CODE_DIRECTION, CODE_DRAINS_POOL,
        CODE_RESERVE_OVERFLOW, CODE_ROUNDS_TO_ZERO, CODE_ZERO_INPUT,
    };
    use pss_core::tip::family::Plain;
    use pss_core::tip::intake;
    use pss_core::tip::slot::{commitment, load};

    // The fixture scenario (every Prover*.toml of the three circuits); each
    // swap samples blinding R_NEW.
    // BEGIN written by scripts/gen-noir-vectors.py from testvectors/slot_commitment.json
    // testvectors/slot_commitment.json vectors[0]: the pool amm_init_tip's
    // Prover.toml creates, Pool::from_seed(111), under blinding R_OLD in
    // namespace NS at slot SLOT
    global NS: Field = 0xc0ffee;
    global SLOT: Field = 0xa002;
    global POOL: [Field; 2] = [1359373, 1852331];
    global R_OLD: Field = 333;
    // END written by scripts/gen-noir-vectors.py
    global R_NEW: Field = 444;
    global VK: Field = 0x5a5a;
    global PARTIAL: Field = 0x9a;
    global NONCE: Field = 3;
    global NSK: Field = 777;
    global TWO_POW_64: Field = 0x10000000000000000;
    global P_MINUS_1: Field = 0 - 1;

    /// The swap under the non-secret-shared intakes (`Plain`).
    fn swap_on(pool: [Field; 2], amount_in: Field, direction: Field, min_out: Field) -> PlainRound {
        swap_round(
            VK,
            load(NS, SLOT, SLOT, pool, R_OLD, R_NEW),
            [amount_in, direction, min_out],
            Plain { partial_note: PARTIAL, user_nonce: NONCE },
            NSK,
        )
    }

    /// The rejection contract at the tip: the round is satisfiable (this
    /// call returns), ok = false with the expected first-failure code,
    /// amount_out = 0, the loaded vector stored back with its old blinding,
    /// and new_c = old_c, the commitment of that vector.
    fn assert_rejected(
        pool: [Field; 2],
        amount_in: Field,
        direction: Field,
        min_out: Field,
        code: Field,
    ) {
        let r = swap_on(pool, amount_in, direction, min_out);
        assert(!r.written.outcome.ok);
        assert_eq(r.written.outcome.code, code);
        assert_eq(r.outputs.ok, 0);
        assert_eq(r.outputs.app.code, code);
        assert_eq(r.outputs.app.amount_out, 0);
        assert_eq(r.written.fields, pool);
        assert_eq(r.written.blinding, R_OLD);
        assert_eq(r.written.old_c, commitment(NS, SLOT, pool, R_OLD));
        assert_eq(r.written.new_c, r.written.old_c);
    }

    // ---- the passing fixture, Prover.toml ----

    #[test]
    fn trade_matches_amm_total() {
        // amm_swap_total's Prover.toml trade: 25000 x for y pays 33450
        let r = swap_on(POOL, 25000, 0, 33000);
        assert(r.written.outcome.ok);
        assert_eq(r.written.outcome.code, 0);
        assert_eq(r.outputs.app.amount_out, 33450);
        assert_eq(r.written.fields, [1384373, 1818881]);
        assert_eq(r.written.blinding, R_NEW);
        assert_eq(r.written.old_c, commitment(NS, SLOT, POOL, R_OLD));
        assert_eq(r.written.new_c, commitment(NS, SLOT, [1384373, 1818881], R_NEW));
        assert(r.written.new_c != r.written.old_c);
    }

    // The non-secret-shared outputs: the request id over the inputs and the
    // partial note, the round's commitments, ok, the partial note echoed
    // right after it, then the code and amount_out.
    #[test]
    fn the_plain_outputs_bind_the_request_and_echo_the_partial_note() {
        let r = swap_on(POOL, 25000, 0, 33000);
        let o = r.outputs;
        assert_eq(o.request_id, intake::plain(NS, VK, [25000, 0, 33000, PARTIAL], NONCE));
        assert_eq(o.old_c, r.written.old_c);
        assert_eq(o.new_c, r.written.new_c);
        assert_eq(o.ok, 1);
        assert_eq(o.partial_note, PARTIAL);
        assert_eq(o.app.code, 0);
        assert_eq(o.app.amount_out, 33450);
    }

    #[test]
    fn min_out_zero_is_no_limit_and_equal_passes() {
        assert(swap_on(POOL, 25000, 0, 0).written.outcome.ok);
        assert(swap_on(POOL, 25000, 0, 33450).written.outcome.ok);
    }

    // ---- one test per failure code, each a Prover-<case>.toml ----

    #[test]
    fn zero_amount() {
        // Prover-zero.toml
        assert_rejected(POOL, 0, 0, 0, CODE_ZERO_INPUT);
    }

    #[test]
    fn amount_two_pow_64() {
        // Prover-oversize.toml
        assert_rejected(POOL, TWO_POW_64, 0, 0, CODE_AMOUNT_RANGE);
        assert_rejected(POOL, P_MINUS_1, 1, 0, CODE_AMOUNT_RANGE);
    }

    #[test]
    fn direction_two() {
        // Prover-direction2.toml
        assert_rejected(POOL, 25000, 2, 0, CODE_DIRECTION);
        assert_rejected(POOL, 25000, P_MINUS_1, 0, CODE_DIRECTION);
    }

    #[test]
    fn add_overflow() {
        // Prover-overflow.toml: 1359373 + (2^64 - 1359373) = 2^64
        assert_rejected(POOL, TWO_POW_64 - 1359373, 0, 0, CODE_RESERVE_OVERFLOW);
    }

    #[test]
    fn dust_rounds_to_zero() {
        // Prover-dust.toml: 1359373 * 1 / 1852332 floors to 0
        assert_rejected(POOL, 1, 1, 0, CODE_ROUNDS_TO_ZERO);
    }

    #[test]
    fn empty_input_reserve_drains() {
        // Prover-drain.toml: r_in = 0 pays out all of r_out
        assert_rejected([0, 1000000], 5, 0, 0, CODE_DRAINS_POOL);
    }

    #[test]
    fn reserve_two_pow_64() {
        // Prover-bad-reserve.toml
        assert_rejected([TWO_POW_64, 1852331], 25000, 0, 0, CODE_BAD_RESERVE);
    }

    #[test]
    fn below_min_out() {
        // Prover-min-out.toml: pays 33450, asked for 33451
        assert_rejected(POOL, 25000, 0, 33451, CODE_MIN_OUT);
        // a limit no u64 output can meet
        assert_rejected(POOL, 25000, 0, TWO_POW_64, CODE_MIN_OUT);
        assert_rejected(POOL, 25000, 0, P_MINUS_1, CODE_MIN_OUT);
    }

    #[test]
    fn swap_codes_win_over_min_out() {
        // a failed swap pays 0; its own code stands whatever the limit
        assert_rejected(POOL, 0, 0, 1, CODE_ZERO_INPUT);
        assert_rejected(POOL, 1, 1, 1, CODE_ROUNDS_TO_ZERO);
    }
}
