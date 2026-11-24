//! What the world learns of a secret-shared swap (docs/ARCHITECTURE.md section 6,
//! "What the world learns: not the round type"). The AMM has one secret-shared
//! round type, the swap, so the cases compare what a round type would
//! betray within it: a trade selling x, a trade selling y, a swap that
//! misses its min_out (code 8) and one whose shares do not open to the
//! queued C (code 9). Each request and each result shows the same
//! - public call: the request enqueues receipt intake's
//!   `append_receipt(request_id, expiry_block)` and the result
//!   `apply_shared(apply)`, whose arguments are the request id and the
//!   pool's old and new commitments (blinded; the AMM pins no read);
//! - effects: the counts of note hashes (a result's completed note, on a
//!   failed swap a note that says so), nullifiers (a request's partial-note
//!   use nullifier), L2-to-L1 messages, public data writes and logs, and
//!   every private log's length (the outcome log at the full 16 fields);
//! - gas the protocol meters for those effects, and gas settings: one per
//!   transaction kind (lib.nr's `REQUEST_GAS`, `RESULT_GAS`; no claim, and
//!   the trader's later `redeem` is its own, unlinked transaction), under
//!   which every case lands.
//!
//! The TXE exposes neither a transaction's enqueued calls nor its AVM
//! execution gas (pss_tip_test `shape`), so the calls are compared as the
//! contract's interface builds them from each round's values (the one
//! enqueue line of `swap_shared` and of `process_result_shared`), together
//! with the queue and pool state their execution leaves; the AVM gas is
//! measured by the e2e (e2e/scenarios/README.md, "Gas per transaction
//! kind"). Timing is a stated residual, not tested.
//!
//! Every round is the circuits' own `swap_round`, through lib.nr's
//! secret-shared-intake helpers (as in test_shared.nr), which send each
//! transaction under its kind's gas setting.
use crate::{
    deploy_shared, init, opened_outcome, pool, pool_key, POOL, REQUEST_GAS, request_shared,
    RESULT_GAS, RHO, Setup, shared_apply, shared_round, submit_shared,
};
use amm_tip::AmmTip;
use amm_tip_circuit::shared::CODE_INPUTS_MISMATCH;
use amm_tip_circuit::tip::CODE_MIN_OUT;
use aztec::protocol::abis::{function_selector::FunctionSelector, gas::Gas};
use aztec::protocol::address::AztecAddress;
use aztec::protocol::traits::ToField;
use pss_core::tip::slot::commitment;
use pss_public_contract::DONE_APPLIED;
use pss_tip_test::shape::{last_tx_shape, metered_gas, TxShape};

// the blindings the rounds sample, the init's first
global BLINDINGS: [Field; CASES + 1] = [333, 444, 555, 666, 777];

// the cases, in the order they run: a sale of x that misses its min_out,
// a sale of x whose shares open to another C, the sale of x that pays
// 33450, then a sale of y on the pool it leaves
global CASES: u32 = 4;
global NAMES: [str<8>; CASES] = ["min_out ", "mismatch", "sell x  ", "sell y  "];
global INPUTS: [[Field; 3]; CASES] = [[25000, 0, 33451], [25000, 0, 33000], [25000, 0, 33000], [1000, 1, 0]];
global CODES: [Field; CASES] = [CODE_MIN_OUT, CODE_INPUTS_MISMATCH, 0, 0];

/// What the world can tell apart in each case: the request's and the
/// result's shapes, and the public calls the request and the result
/// functions build (target, selector, argument count).
pub struct Seen {
    intake: TxShape,
    result: TxShape,
    append: (AztecAddress, FunctionSelector, u32),
    apply: (AztecAddress, FunctionSelector, u32),
}

/// Run the four cases in order, each request and result under its kind's
/// gas setting, and return what each showed.
unconstrained fn run_every_case() -> (Setup, [Seen; CASES]) {
    let s = deploy_shared();
    init(s, commitment(s.app.to_field(), pool_key(s), POOL, BLINDINGS[0]));
    let app = AmmTip::at(s.app);
    let mut reserves = POOL;
    let mut seen: [Seen; CASES] = std::mem::zeroed();
    for k in 0..CASES {
        let blinding = 0xb1b1 + k as Field;
        let rho = RHO + k as Field;
        let (id, expiry) = request_shared(s, INPUTS[k], rho, blinding);
        let intake = last_tx_shape(s.env);
        assert_eq(s.queue().tail(), 1 + k as u64);
        assert_eq(s.queue().request_at(k as u64), id);
        let append = app.append_receipt(id, expiry);
        // the mismatch's shares open under another blinding than C's
        let shares = if CODES[k] == CODE_INPUTS_MISMATCH { blinding + 0x100 } else { blinding };
        let r = shared_round(s, INPUTS[k], rho, blinding, shares, reserves, BLINDINGS[k], BLINDINGS[k + 1]);
        assert_eq(r.outputs.request_id, id);
        let _ = submit_shared(s, r);
        let result = last_tx_shape(s.env);
        assert_eq(pool(s), r.outputs.new_commitments[0]);
        assert_eq(s.queue().head().index, 1 + k as u64);
        assert_eq(s.queue().done_at(k as u64), DONE_APPLIED);
        assert_eq(opened_outcome()[0], CODES[k]);
        let apply = app.apply_shared(shared_apply(r));
        reserves = r.written.fields;
        seen[k] = Seen {
            intake,
            result,
            append: (append.target_contract, append.selector, append.args.len()),
            apply: (apply.target_contract, apply.selector, apply.args.len()),
        };
    }
    (s, seen)
}

// One run of the four cases, three comparisons; a difference is a finding
// and the assertion names the case.
//
// Effects: the request and the result of every case show the same: a
// request no note hash and no log, and its partial note's use nullifier; a
// result the completed note's hash and one 16-field outcome log; the same
// count of public data writes; no public log, no message.
//
// Public calls: `swap_shared` enqueues `append_receipt(request_id,
// expiry_block)` (two arguments) and `process_result_shared` enqueues
// `apply_shared(apply)` (three: the request id, the old and the new
// commitment) in every case.
//
// Gas: what each transaction kind meters for its effects (pss_tip_test
// `metered_gas`) is the same in every case, and every case lands under the
// kind's one gas setting. The AVM's execution gas is not reported by the
// TXE.
#[test]
unconstrained fn every_swap_has_the_same_effects_public_calls_and_metered_gas() {
    let (s, seen) = run_every_case();
    let append_receipt = comptime { FunctionSelector::from_signature("append_receipt(Field,u32)") };
    let (_, first_apply, _) = seen[0].apply;
    for k in 0..CASES {
        let name = NAMES[k];
        assert(seen[k].intake == seen[0].intake, f"finding: the {name} request's effects differ from the min_out case's");
        assert(seen[k].result == seen[0].result, f"finding: the {name} result's effects differ from the min_out case's");
        assert(
            seen[k].append == (s.app, append_receipt, 2),
            f"finding: the {name} request enqueues another call than append_receipt(id, expiry)",
        );
        assert(
            seen[k].apply == (s.app, first_apply, 3),
            f"finding: the {name} result enqueues another call than apply_shared(id, old, new)",
        );
        assert(
            metered_gas(seen[k].intake, 1) == metered_gas(seen[0].intake, 1),
            f"finding: the {name} request meters other gas",
        );
        assert(
            metered_gas(seen[k].result, 1) == metered_gas(seen[0].result, 1),
            f"finding: the {name} result meters other gas",
        );
    }
    let (intake, result) = (seen[0].intake, seen[0].result);
    assert(
        (intake == INTAKE_SHAPE) & (result == RESULT_SHAPE),
        f"the shapes are: request {intake}, result {result}",
    );
    let (intake_gas, result_gas) = (metered_gas(intake, 1), metered_gas(result, 1));
    assert(intake_gas.within(REQUEST_GAS) & result_gas.within(RESULT_GAS));
    // the README's gas table
    assert(
        (intake_gas == Gas::new(480, 621600)) & (result_gas == Gas::new(960, 612575)),
        f"the metered gas: request {intake_gas}, result {result_gas}",
    );
}

global INTAKE_SHAPE: TxShape = TxShape {
    note_hashes: 0,
    nullifiers: 2,
    l2_to_l1_msgs: 0,
    public_data_writes: 5,
    private_logs: 0,
    private_log_lengths: [0, 0, 0, 0],
    public_logs: 0,
    contract_class_logs: 0,
};
global RESULT_SHAPE: TxShape = TxShape {
    note_hashes: 1,
    nullifiers: 1,
    l2_to_l1_msgs: 0,
    public_data_writes: 4,
    private_logs: 1,
    private_log_lengths: [16, 0, 0, 0],
    public_logs: 0,
    contract_class_logs: 0,
};
