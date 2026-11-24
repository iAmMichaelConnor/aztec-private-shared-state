//! The round type under secret-shared receipt intake (docs/ARCHITECTURE.md section
//! 6, "What the world learns: not the round type"): across deposit, borrow,
//! repay, view, liquidate and withdraw on the secret-shared deployment, the result
//! transaction has one shape the world can see, whichever round type it
//! carries, and so has the request: every request spends one of the
//! sender's credit notes for its escrow and usage deposit, inserts the
//! change and commits two refund notes (private effects, the same count for
//! every round type), and its public part is the queue's writes and the
//! refund record, with no token call and no amount. The redeem credits a
//! note's settlement privately, with no public part; a note that pays
//! nothing is not redeemed.
//!
//! - the public call: the request enqueues `append_receipt(request_id,
//!   expiry_block, refunds)` and the result `apply_shared(apply, opened,
//!   tags)`, whose arguments are the request id, the market's old and new
//!   commitments (blinded), the price read's value and epoch, the same
//!   pinned read on every round, the inputs-opened bit (1 on every round
//!   whose shares open C) and the round's EXIT_TAGS exit tags (a spent tag
//!   or a filler, which nobody but the requester tells apart);
//! - the effects: the counts of note hashes, nullifiers (every landing
//!   emits its EXIT_TAGS exit tags as nullifiers of the app beside the
//!   transaction's own), L2-to-L1 messages, public data writes and logs,
//!   and every private log's length (the outcome log at the full 16
//!   fields);
//! - the gas the protocol meters for those effects, and the gas settings:
//!   one per transaction kind (lib.nr's `REQUEST_GAS`, `RESULT_GAS`,
//!   `REDEEM_GAS`), under which every round type lands.
//!
//! The TXE exposes neither a transaction's enqueued calls nor its AVM
//! execution gas (pss_tip_test `shape`), so the calls are compared as the
//! contract's interface builds them from each round's values (the one
//! enqueue line of each request and result function), together with the
//! queue and slot state their execution leaves; the AVM gas is measured by the
//! e2e (e2e/scenarios/README.md, "Gas per transaction kind"). Timing is a
//! stated residual and not tested: proving time differs by circuit, and only
//! some outcomes are worth a redeem.
//!
//! The outcomes are the stand-ins of test_shared.nr's race (no circuit runs
//! here), encrypted with the rounds' own `encrypt_outcome`; the requests and results are
//! lib.nr's secret-shared-intake helpers, which send each transaction under its
//! kind's gas setting; the proofs are dummy capsules.
use crate::{
    BORROWER,
    COLLATERAL_ASSET, ROUND_QUOTE, request_quote, SUPPLY, ROUND_SUPPLY, WITHDRAW, ROUND_WITHDRAW,
    ROUND_WITHDRAW_SUPPLY,
    BORROW, ROUND_BORROW, BUDGET, C1, C2, C3, C_INIT, DEPOSIT, ROUND_DEPOSIT, EPOCH, filler_tag, ROUND_LIQUIDATE,
    market, open_and_deliver, POSITION, PRICE, redeem, REDEEM_GAS, REPAY, ROUND_REPAY, REPAY_OUT,
    Request, REQUEST_GAS, request_liquidation, request_owner, request_view, RESULT_GAS, SEIZE_OUT,
    Setup, shared_apply, shared_setup, submit_shared, ROUND_VIEW,
};
use aztec::protocol::abis::{function_selector::FunctionSelector, gas::Gas};
use aztec::protocol::address::AztecAddress;
use lending_market::app::EXIT_TAGS;
use lending_tip::LendingTip;
use pss_public_contract::DONE_APPLIED;
use pss_tip_test::shape::{last_tx_shape, metered_gas, TxShape};
use pss_tip_test::tx_effects::assert_last_nullifier;

// the round types compared, in the secret-shared list's order after the init (the
// scan, test_keeper.nr's, is compared there with a deposit)
global KINDS: u32 = 9;
global KIND: [u32; KINDS] = [
    ROUND_DEPOSIT, ROUND_BORROW, ROUND_REPAY, ROUND_VIEW, ROUND_LIQUIDATE, ROUND_WITHDRAW, ROUND_SUPPLY, ROUND_WITHDRAW_SUPPLY,
    ROUND_QUOTE,
];
global NAMES: [str<9>; KINDS] = [
    "deposit  ", "borrow   ", "repay    ", "view     ", "liquidate", "withdraw ", "supply   ",
    "wd supply", "quote    ",
];
// whether its note pays anything, and so is redeemed: the borrow (its
// amount), the liquidation (the seize and the unused budget) and the
// withdrawal (its amount, in the collateral asset) and the withdrawal of
// supply (the shares' value)
global PAYS: [bool; KINDS] = [false, true, false, false, true, true, false, true, false];

/// The position of round type `kind` in KIND, which indexes `seen` (the
/// round types are the round table's indices, not KIND's positions).
fn at(kind: u32) -> u32 {
    let mut position = KINDS;
    for k in 0..KINDS {
        if KIND[k] == kind {
            position = k;
        }
    }
    assert(position < KINDS, "the round type is not compared here");
    position
}

/// Queue a secret-shared request of `kind` with the race's values (Alice opens
/// position 1, then borrows, repays and views it with the note the opening
/// completed; Bob liquidates positions 1 and 2); `n` picks its partial
/// note's randomness, outcome key, tag and blinding.
unconstrained fn request(s: Setup, kind: u32, n: Field) -> Request {
    if kind == ROUND_DEPOSIT {
        request_owner(s, s.user, kind, 0, DEPOSIT, n)
    } else if kind == ROUND_BORROW {
        request_owner(s, s.user, kind, POSITION, BORROW, n)
    } else if kind == ROUND_REPAY {
        request_owner(s, s.user, kind, POSITION, REPAY, n)
    } else if kind == ROUND_VIEW {
        request_view(s, POSITION, n)
    } else if kind == ROUND_WITHDRAW {
        request_owner(s, s.user, kind, POSITION, WITHDRAW, n)
    } else if kind == ROUND_SUPPLY {
        request_owner(s, s.user, kind, 0, SUPPLY, n)
    } else if kind == ROUND_WITHDRAW_SUPPLY {
        request_owner(s, s.user, kind, LENT, SUPPLY, n)
    } else if kind == ROUND_QUOTE {
        request_quote(s, s.other, n)
    } else {
        assert_eq(kind, ROUND_LIQUIDATE);
        request_liquidation(s, n)
    }
}

// the stand-in outcomes in the one shape [code, position, mask, x, y,
// payout, aux]: the opening deposit, the borrow (its payout the
// amount), the repayment, the view after it, the liquidation (the seize in
// x, the unused budget its payout), the withdrawal after it (its payout the
// amount in the collateral asset), the lender's opening supply at position
// 2 (mask 0), its withdrawal (its payout the shares' value) and a quote (its
// rates; x 0)
global LENT: Field = 2;
global OUTCOMES: [[Field; 7]; KINDS] = [
    [0, POSITION, BORROWER, DEPOSIT, 0, 0, 0],
    [0, POSITION, BORROWER, DEPOSIT, BORROW, BORROW, 0],
    [0, POSITION, BORROWER, DEPOSIT, BORROW - REPAY, 0, 0],
    [0, POSITION, BORROWER, DEPOSIT, BORROW - REPAY, 0, 0],
    [0, 0, 1, SEIZE_OUT, REPAY_OUT, BUDGET - REPAY_OUT, 0],
    [0, POSITION, BORROWER, DEPOSIT - SEIZE_OUT - WITHDRAW, BORROW - REPAY - REPAY_OUT, COLLATERAL_ASSET + WITHDRAW, 0],
    [0, LENT, 0, SUPPLY, SUPPLY, 0, 0],
    [0, LENT, 0, 0, 0, SUPPLY, 0],
    [0, 0, 1000000000, 0, 1000000000, 0, 850],
];
// the market's commitment before and after each round
global COMMITMENTS: [Field; KINDS + 1] = [
    C_INIT, C1, C2, C3, C1 + 0x10, C2 + 0x10, C3 + 0x10, C1 + 0x20, C2 + 0x20, C3 + 0x20,
];

/// What the world can tell apart in one round of each type: the request's,
/// the result's and the redeem's shapes (zero for a note that pays nothing),
/// the public calls the request and the result functions build, and the head
/// index after the result.
pub struct Seen {
    intake: TxShape,
    result: TxShape,
    redeem: TxShape,
    append: (AztecAddress, FunctionSelector, u32, Field),
    apply: (AztecAddress, FunctionSelector, u32, [Field; 4]),
}

/// A clock for the apply call the test builds to inspect its shape (the
/// landed results carry the block they land in).
global CLOCK: Field = 7;

/// Run one round of every type in the race's order, each request, result
/// and redeem under its kind's gas setting, and return what each showed.
unconstrained fn run_every_round_type(s: Setup) -> [Seen; KINDS] {
    let app = LendingTip::at(s.app);
    let mut seen: [Seen; KINDS] = std::mem::zeroed();
    for k in 0..KINDS {
        let round = request(s, KIND[k], 1 + k as Field);
        let intake = last_tx_shape(s.env);
        assert_eq(s.queue().tail(), 1 + k as u64);
        assert_eq(s.queue().request_at(k as u64), round.id);
        let append = app.append_receipt(round.id, round.expiry, std::mem::zeroed());
        let (old_c, new_c) = (COMMITMENTS[k], COMMITMENTS[k + 1]);
        let tx = submit_shared(s, round, old_c, new_c, PRICE, EPOCH, OUTCOMES[k]);
        let result = last_tx_shape(s.env);
        // the landing's one exit tag, a nullifier of the app
        assert_last_nullifier(s.app, filler_tag(round));
        assert_eq(market(s), new_c);
        assert_eq(s.queue().head().index, 1 + k as u64);
        assert_eq(s.queue().done_at(k as u64), DONE_APPLIED);
        let apply = app.apply_shared(shared_apply(round, old_c, new_c, PRICE, EPOCH, CLOCK), 1, [filler_tag(round); EXIT_TAGS]);
        let outcome = open_and_deliver(s, round, tx);
        assert_eq(outcome, OUTCOMES[k]);
        let mut paid: TxShape = std::mem::zeroed();
        if PAYS[k] {
            redeem(s, round.owner, round.id);
            paid = last_tx_shape(s.env);
        }
        seen[k] = Seen {
            intake,
            result,
            redeem: paid,
            append: (append.target_contract, append.selector, append.args.len(), append.args[1]),
            apply: (
                apply.target_contract,
                apply.selector,
                apply.args.len(),
                [apply.args[3], apply.args[4], apply.args[5], apply.args[6]],
            ),
        };
    }
    seen
}

// The result of every round type shows the same effects (one completed note
// hash and one 16-field outcome log, the apply's writes). A request's public
// part (its public data
// writes, public logs and messages) is the same within its escrow class;
// its notes, nullifiers and private logs follow the sender's token notes
// (how many notes the token spends for each transfer and whether a change
// note is spent again in the same transaction), as any token transfer's
// do, so they are not compared. A difference is a finding: the assertion
// names the round type.
//
// The same run of every round type also shows the public calls and the
// metered gas (below: `assert_one_public_call`, `assert_one_gas_setting`).
#[test]
unconstrained fn every_round_type_has_one_shape_one_public_call_and_one_gas_setting() {
    let s = shared_setup();
    let seen = run_every_round_type(s);
    let (result, redeemed) = (seen[0].result, seen[at(ROUND_BORROW)].redeem);
    let (d, b) = (seen[at(ROUND_DEPOSIT)].intake, seen[at(ROUND_BORROW)].intake);
    assert(
        (result == RESULT_SHAPE) & (redeemed == REDEEM_SHAPE) & (d == b),
        f"the shapes are: result {result}, a borrow's redeem {redeemed}; the requests: deposit {d}, borrow {b}",
    );
    for k in 0..KINDS {
        let name = NAMES[k];
        let (mine, theirs) = (seen[k].intake, seen[0].intake);
        assert(mine == theirs, f"finding: the {name} request's effects {mine} differ from the deposit's {theirs}");
        assert(public_part(mine) == public_part(theirs));
        assert(seen[k].result == seen[0].result, f"finding: the {name} result's effects differ from the deposit's");
    }
    assert_one_public_call(s, seen);
    assert_one_gas_setting(seen);
}

/// What a request shows in public: its public data writes, public logs and
/// L2-to-L1 messages.
fn public_part(t: TxShape) -> [u32; 3] {
    [t.public_data_writes, t.public_logs, t.l2_to_l1_msgs]
}

// The expected shapes. A result pushes the completed note hash and its
// 16-field log, then its delivery's note hash and 16-field log (a
// liquidated owner's notice or a filler, the same on every round type),
// emits its EXIT_TAGS exit tags as nullifiers beside the transaction's own,
// makes the apply's writes (the market, the head, done[index], the kept
// deposit's count and the hatch's one slot) and emits no public log; a
// borrow's redeem pushes the note's redeem nullifier and one credit note
// with its on-chain message, and has
// no public call: its one public data write is the fee payer's balance
// write that every private-only transaction carries. A request spends one
// credit note and inserts its change, commits its two refund notes, all
// with on-chain messages, and its public part is the queue's writes, the
// refund record and, on a market whose hatch clock is not running (every
// request here lands on an empty queue), the hatch's one slot: the same
// for every round type (no token call, no amount). Both deployments, the
// clear one and the oblivious one, show these shapes.
// The constants below follow from the code; the private log lengths and the
// gas await a measured run.
global RESULT_SHAPE: TxShape = TxShape {
    note_hashes: 2,
    nullifiers: 1 + EXIT_TAGS,
    l2_to_l1_msgs: 0,
    public_data_writes: 6,
    private_logs: 2,
    private_log_lengths: [16, 16, 0, 0],
    public_logs: 0,
    contract_class_logs: 0,
};
global REDEEM_SHAPE: TxShape = TxShape {
    note_hashes: 1,
    nullifiers: 2,
    l2_to_l1_msgs: 0,
    public_data_writes: 1,
    private_logs: 1,
    private_log_lengths: [16, 0, 0, 0],
    public_logs: 0,
    contract_class_logs: 0,
};

// The public calls: every request function enqueues the one wrapper
// `append_receipt(request_id, expiry_block, refunds)` (four fields: the
// expiry the client's, ten blocks on here, then the two refund notes'
// commitments, which hide their amounts) and every
// result function the one `apply_shared(apply, opened, tags)` (6 +
// EXIT_TAGS + 1 fields: the request id, the old and the new commitment,
// then the price read's value and epoch and the clock, the same on every
// round type, the deposit, the repayment and the view included, the
// inputs-opened bit, 1 here, and the exit tags).
unconstrained fn assert_one_public_call(s: Setup, seen: [Seen; KINDS]) {
    let append_receipt = comptime {
        FunctionSelector::from_signature("append_receipt(Field,u32,(Field,Field))")
    };
    for k in 0..KINDS {
        let name = NAMES[k];
        let (target, selector, count, _) = seen[k].append;
        assert(
            (target == s.app) & (selector == append_receipt) & (count == 4),
            f"finding: the {name} request enqueues another call than append_receipt(id, expiry, refunds)",
        );
        let (target, selector, count, reads) = seen[k].apply;
        let (_, first_selector, _, _) = seen[0].apply;
        assert(
            (target == s.app) & (selector == first_selector) & (count == 7 + EXIT_TAGS),
            f"finding: the {name} result enqueues another call than the deposit's apply_shared",
        );
        assert(
            reads == [PRICE as Field, EPOCH as Field, CLOCK, 1],
            f"finding: the {name} result's apply carries another pinned read or bit",
        );
    }
}

// The gas each transaction kind meters for its effects (pss_tip_test
// `metered_gas`: the private part as the kernel meters it, and the DA of the
// public writes) is the same for every round type's result; a request's
// follows its private effects (the sender's token notes, above), and a
// redeem's what it pays. Every round type lands under the kind's one gas
// setting (REQUEST_GAS, RESULT_GAS, REDEEM_GAS: each transaction above was
// sent under it). The AVM's execution gas is not reported by the TXE.
unconstrained fn assert_one_gas_setting(seen: [Seen; KINDS]) {
    for k in 0..KINDS {
        let name = NAMES[k];
        assert(metered_gas(seen[k].intake, 1).within(REQUEST_GAS), f"the {name} request exceeds REQUEST_GAS");
        assert(
            metered_gas(seen[k].result, 1) == metered_gas(seen[0].result, 1),
            f"finding: the {name} result meters other gas",
        );
        if PAYS[k] {
            assert(metered_gas(seen[k].redeem, 0).within(REDEEM_GAS), f"the {name} redeem exceeds REDEEM_GAS");
        }
    }
    let (result, redeemed) = (metered_gas(seen[0].result, 1), metered_gas(seen[at(ROUND_BORROW)].redeem, 0));
    let request = metered_gas(seen[at(ROUND_BORROW)].intake, 1);
    assert(result.within(RESULT_GAS));
    // the metered gas of each kind: the result's from RESULT_SHAPE (below
    // the oblivious test), the redeem's and the request's as measured, the
    // request's with the hatch's one slot
    assert(
        (result == Gas::new(RESULT_DA, RESULT_L2)) & (redeemed == Gas::new(800, 483700)) & (request == Gas::new(2432, 740775)),
        f"the metered gas: result {result}, a borrow's redeem {redeemed}, a borrow's request {request}",
    );
}

// The oblivious deployment (README "The oblivious deployment"): the same
// round of every type, every round on a position through its `*_oblivious`
// request function (the position shared under the round's oblivious layout;
// the openings with the flag) and the quote through `quote_shared`, so each
// of those request functions queues under its layout here as each
// `*_shared` one does in the test above; each result through the same `process_shared` or
// `process_header_shared` under the oblivious circuits' vk pins. Every
// result shows the clear deployment's effects (RESULT_SHAPE: the exit tag
// and the hatch's slot included) and meters its gas, the requests the same
// public part, and every call is the deployment's one wrapper with the same
// pinned reads, as on the secret-shared deployment.
#[test]
unconstrained fn every_oblivious_round_type_has_one_shape_one_public_call_and_one_gas_setting() {
    let s = crate::oblivious_setup();
    let seen = run_every_round_type(s);
    let (result, request) = (seen[0].result, seen[0].intake);
    assert(result == RESULT_SHAPE, f"the oblivious result's shape is {result}");
    for k in 0..KINDS {
        let name = NAMES[k];
        let mine = seen[k].intake;
        assert(public_part(mine) == public_part(request), f"finding: the oblivious {name} request's public part differs from the deposit's");
        assert(seen[k].result == result, f"finding: the oblivious {name} result's effects differ from the deposit's");
        assert(metered_gas(mine, 1).within(REQUEST_GAS), f"the oblivious {name} request exceeds REQUEST_GAS");
        assert(
            metered_gas(seen[k].result, 1) == metered_gas(result, 1),
            f"finding: the oblivious {name} result meters other gas",
        );
        if PAYS[k] {
            assert(metered_gas(seen[k].redeem, 0).within(REDEEM_GAS), f"the oblivious {name} redeem exceeds REDEEM_GAS");
        }
    }
    assert_one_public_call(s, seen);
    let gas = metered_gas(result, 1);
    assert(gas.within(RESULT_GAS));
    assert(gas == Gas::new(RESULT_DA, RESULT_L2), f"the oblivious result's metered gas: {gas}");
}

// The result's metered gas (`metered_gas` of RESULT_SHAPE, one public call):
// DA, 38 fields (two note hashes, two nullifiers, two 16-field private logs
// with their lengths) at 32, the transaction's 96 and six public data writes
// at 64; L2, two private logs, two note hashes and two nullifiers at the
// AVM's rates, one call's startup and the public transaction's overhead.
global RESULT_DA: u32 = 1696;
global RESULT_L2: u32 = 665150;
