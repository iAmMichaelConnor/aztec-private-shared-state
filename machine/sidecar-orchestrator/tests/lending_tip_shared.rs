//! Lending's secret-shared rounds under secret-shared receipt intake, in process over
//! three real nodes with real MPC proofs (docs/ARCHITECTURE.md section 6,
//! "Secret-shared intake", "Private outcomes", "Ownership by note" and the
//! tree-valued node-held state): examples/lending-tip's `lending_init` and
//! the secret-shared receipt intake entries `deposit_shared`, `borrow_shared`,
//! `liquidate_shared`, `repay_shared` and `withdraw_shared` (partial-note
//! delivery), their
//! manifests and compiled circuits as committed, the book one tree-valued
//! node-held key, every round's price an epoch read of the oracle and its
//! clock a tolerance read of the market's own `clock()`. Each
//! request goes receipt -> head -> round -> result, as in
//! `amm_tip_shared.rs`: the position indices are clear to the nodes (which
//! place their leaves), the amount and the requester's partial note shared.
//! No round sees an owner: the contract's request function (not run here)
//! admits a request on a position only for the holder of a note of it.
//!
//! - The audit: no shared app input (`amount`, `$partial_note`) and no
//!   requester address (the depositor's and the liquidator's, the owners of
//!   the partial notes) appears in a receipt body's clear inputs, a node's
//!   receipts row, a request a node receives (the synthesised public map
//!   with the clear tree's paths), the intake's public call or the proof's
//!   public inputs.
//! - Every outcome ciphertext opens under its `$outcome_key` with the nonce
//!   of the completed note's hash, which the log carries, to `[code,
//!   position, mask, x, y, payout, aux]`, and the completed note's hash is
//!   the completion of the request's partial note the user recomputes: an
//!   opening deposit reports its assigned index and its collateral, a borrow
//!   the position after it and its payout, a liquidation the mask, the total
//!   seize and repay and the payout, and no position; the book's leaves open
//!   to the same values, an opened position's first element 1.
//! - Exit tags: every round that writes a position stores in its leaf
//!   (element 6) the exit tag of the note it issues,
//!   `poseidon2([PSS_EXIT_TAG + 2^128 * position, P, request_id])` with P
//!   the requester's partial note (a liquidation's: the position's delivery
//!   handle, the notice's) and the chain request id, and outputs the tag it
//!   replaced as its first app value: an opening outputs a nonzero value
//!   that is no tag, each later round on the position the tag before it, so
//!   the position's tags form a chain whose one unspent tag is its newest
//!   note's.
//! - A failed borrow (past the borrow limit, code 9) still writes a new
//!   commitment, different from the old one, and reports its code and the
//!   position as it stands; it re-tags the position (the round vouches for
//!   the owner's leaf), which keeps its values.
//! - Shares that do not open to C give code 14 inside the outcome and the
//!   inputs-opened bit 0 (the proof's last app value, 1 on every other
//!   round), and the round commits and lands without writing the position:
//!   its exit value is none of the position's tags and the leaf stays.
//! - A repayment after the liquidation reduces the position's debt and the
//!   header's total debt by its amount and returns it to the liquidity,
//!   with payout 0; a withdrawal down to the borrow limit pays its amount in
//!   the collateral asset (the payout's asset bit).
//! - A lender opens a position with a supply (mask 0, one share per unit
//!   while the pool is worth its shares), withdraws part of its shares for
//!   their value, and a quote reports the borrow index, the supply index and
//!   the utilisation (its `aux`).
//! - Interest by time: with the clock 100 blocks past the book's last
//!   accrual, a repayment first accrues the header's borrow index at the
//!   utilisation and brings the position's debt to it (rounded up), then
//!   repays; the outcome's mask is the new index.
//! - A recompute after the price moved two epochs: the borrow is recomputed
//!   once on the same book version from the same stored envelopes under a
//!   new machine request id; its two attempts agree on the outcome, the exit
//!   value and the stored tag, and so on the note hash, the nonce and the
//!   ciphertext (the outcome holds nothing of the fresh leaf blinding).
//!
//!
//! The opening deposit under secret-shared on-chain intake
//! (`deposit_shared_onchain`, the secret-shared deposit's compiled circuit
//! registered a second time), on a market of its own: each node signs its
//! `enc` key into the contract at epoch 1 and records the scalar once the
//! contract stores it; the user's private function
//! encodes the deposit (`position` clear, the amount, the partial note and
//! the outcome key and tag the user chose, one correction each) into one
//! private log whose hash the contract stores; the round is
//! computed from the log the scheduler and every chain verifier read, its
//! outcome opened under the chosen key and its result applied, with the
//! audit above over the public call, the log and what the nodes receive,
//! and its note's exit tag in the new position's leaf.
//!
//! Needs `scripts/prepare-data.sh` (examples/lending-tip's circuits and the
//! CRS under machine/data, or DATA_DIR); fails naming the missing files if
//! they are absent, so a passing run proves it ran. Run with `--release`.

mod common;
mod lending;
mod shared_intake;

use common::tip::*;
use lending::*;
use serde_json::Value;
use shared_intake::*;

use sidecar_core::field::Fr;
use sidecar_tip::machine_request_id;

const M: Market = Market {
    tip: 0x7e5d,
    book: "0x000000000000000000000000000000000000000000000000000000000000a004",
    oracle: 0x0a13,
};
const CIRCUITS: [&str; 10] = [
    SEED,
    INIT,
    DEPOSIT,
    BORROW,
    LIQUIDATE,
    REPAY,
    WITHDRAW,
    SUPPLY,
    WITHDRAW_SUPPLY,
    QUOTE,
];

/// The borrow index `b` after `dt` blocks at utilisation `u` (bps), at the
/// market's default rate (market.nr `accrue`: R1 = 46 below U_OPT = 8000,
/// R2 = 690 above it): b + ceil(b * rate(u) * dt / (INDEX_ONE * U_OPT *
/// (BPS - U_OPT))).
fn accrued_index(b: u64, u: u64, dt: u64) -> u64 {
    let (low, high) = (u.min(8_000), u.saturating_sub(8_000));
    let rate = u128::from(46 * low * 2_000 + 690 * high * 8_000);
    let denom = u128::from(ONE) * 8_000 * 2_000;
    let growth = (u128::from(b) * rate * u128::from(dt)).div_ceil(denom);
    b + u64::try_from(growth).unwrap()
}

/// Leaf `index` of the book version under `commitment`: [1, collateral,
/// debt, index_at_touch] for a borrower position and [total_debt,
/// liquidity, total_shares, borrow_index] for the header (the rest of the
/// leaf left out).
fn leaf(net: &Net, commitment: Fr, index: u64) -> [Fr; 4] {
    leaf_of(net, M, commitment, index)
}

/// [`leaf`] of market `m`'s book.
fn leaf_of(net: &Net, m: Market, commitment: Fr, index: u64) -> [Fr; 4] {
    let l = m.leaf(net, commitment, index);
    [l[0], l[1], l[2], l[3]]
}

/// The exit tag position `index`'s leaf holds in the book version under
/// `commitment`.
fn stored_tag(net: &Net, commitment: Fr, index: u64) -> Fr {
    M.leaf(net, commitment, index)[P_EXIT_TAG]
}

#[test]
fn the_exit_tag_agrees_with_the_vectors() {
    check_exit_tag_vectors();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn lending_shared_rounds_run_receipt_to_result_on_three_nodes() {
    let Lending {
        tmp: _tmp,
        mem,
        net,
        started,
        mut clock,
        mut chain,
        mut s,
        mut hidden,
        init,
    } = M.start("lendshared", &CIRCUITS).await;
    // the init round's [namespace, vk_hash, out_slots[0], request_id, old_c,
    // new_c, npk_app_hash, new_hashes[0]]
    assert_eq!(init.len(), 8);

    // ---- an opening deposit ---------------------------------------------------
    let owner = random();
    let collateral = 5_011;
    let deposit = M.owned(&net, DEPOSIT, 0, collateral, owner);
    M.queue(&net, &clock, &mut chain, &deposit, &mut hidden)
        .await;
    let r = step(&mut s, clock.next(), "an opening deposit").await;
    assert_eq!(computed(&r), [1], "{r:?}");
    assert_eq!(net.audit_received(&deposit, &hidden), 3);
    let (_, o, exit, _) = M.land(&net, &clock, &mut chain, &deposit, 2, &hidden).await;
    assert_eq!(
        o,
        [0, 1, ONE, collateral, 0, 0],
        "ok, the assigned position 1"
    );
    let v1 = chain.slot;
    assert_eq!(leaf(&net, v1, 1), [fr(1), fr(collateral), fr(0), fr(ONE)]);
    let deposited = tag_of(&deposit, 1);
    assert_eq!(
        stored_tag(&net, v1, 1),
        deposited,
        "the leaf holds the exit tag of the depositor's note"
    );
    assert!(
        exit != fr(0) && exit != deposited,
        "an opening replaces no tag: its exit value is a filler"
    );

    // ---- a borrow, recomputed once after two price epochs -----------------------
    // the borrow limit is collateral * 2.50 * 75% = 9395
    let debt = 9_013;
    let borrow = M.owned(&net, BORROW, 1, debt, owner);
    M.queue(&net, &clock, &mut chain, &borrow, &mut hidden)
        .await;
    net.received.lock().unwrap().clear();
    let r = step(&mut s, clock.next(), "a borrow at epoch 1").await;
    assert_eq!(computed(&r), [2], "{r:?}");
    let at1 = r.computed[0].clone();
    let held = net.latest(M.ns(), borrow.chain).await;
    let (first, o1, exit1, _) = M.opened(&borrow, &held, 2);
    let tag1 = stored_tag(&net, first.new_c, 1);
    M.set_price(&mem, 250, 2, 250);
    let r = step(&mut s, clock.next(), "epoch 2: kept").await;
    assert!(!r.repriced && computed(&r).is_empty(), "{r:?}");
    M.set_price(&mem, 250, 3, 250);
    let r = step(&mut s, clock.next(), "epoch 3: recomputed").await;
    assert!(r.repriced, "{r:?}");
    assert_eq!(computed(&r), [2], "{r:?}");
    let at3 = r.computed[0].clone();
    assert_eq!(at3.old, at1.old, "the same book version");
    assert_ne!(at3.request_id, at1.request_id, "a new machine request id");
    assert_eq!(
        at3.request_id.fr(),
        machine_request_id(borrow.chain, &[v1], &[fr(250), fr(3), fr(0)])
    );
    let received = net.received_for(borrow.chain);
    assert_eq!(received.len(), 6, "three nodes, two attempts");
    for i in 0..3 {
        let mine: Vec<&Value> = received
            .iter()
            .filter(|(n, _)| *n == i)
            .map(|(_, r)| r)
            .collect();
        assert_eq!(
            mine[0]["shared_inputs"], mine[1]["shared_inputs"],
            "node {i}: the recompute reuses the stored envelopes"
        );
    }
    assert_eq!(net.audit_received(&borrow, &hidden), 6);
    let (second, o3, exit3, _) = M.land(&net, &clock, &mut chain, &borrow, 2, &hidden).await;
    assert_eq!(second.machine_request_id, at3.request_id.fr());
    assert_eq!(o1, o3, "one outcome, two attempts");
    assert_eq!(
        o3,
        [0, 1, ONE, collateral, debt, debt],
        "the payout is the amount"
    );
    let v2 = chain.slot;
    assert_eq!(
        leaf(&net, v2, 1),
        [fr(1), fr(collateral), fr(debt), fr(ONE)]
    );
    // the exit tag is of the chain request id, not the attempt's: both
    // attempts replace the deposit's tag with the borrower's note's
    let borrowed = tag_of(&borrow, 1);
    assert_eq!(
        (exit1, exit3),
        (deposited, deposited),
        "both attempts output the deposit's tag"
    );
    assert_eq!(
        (tag1, stored_tag(&net, v2, 1)),
        (borrowed, borrowed),
        "both attempts store the borrower's note's tag"
    );
    // one plaintext under one chain request id: one note hash, so one
    // nonce and one ciphertext, whatever each run's leaf blinding
    assert_eq!(first.note_hash, second.note_hash);
    assert_eq!(first.ciphertext, second.ciphertext);

    // ---- a borrow past the limit and a mismatch, pipelined: both commit -------
    // the mismatch: an honest borrow whose shares the nodes change after its
    // intake (the request function refuses a sharing that does not open C)
    let over = M.owned(&net, BORROW, 1, 4_019, owner);
    let honest = M.request(&net, BORROW, owned_inputs(1, 1_031, owner));
    for q in [&over, &honest] {
        M.queue(&net, &clock, &mut chain, q, &mut hidden).await;
    }
    let skewed = honest.reshared(&net.enc_pks, ("amount", 1), &net.package(M.ns(), BORROW));
    net.change_shares(&honest, &skewed);
    let r = step(
        &mut s,
        clock.next(),
        "a borrow past the limit and a mismatch",
    )
    .await;
    assert_eq!(computed(&r), [3, 4], "{r:?}");
    let (out, o, exit, _) = M.land(&net, &clock, &mut chain, &over, 2, &hidden).await;
    assert_eq!(
        o,
        [CODE_LIMIT, 1, ONE, collateral, debt, 0],
        "its code and the position as it stands: the round vouches for the owner's leaf"
    );
    assert_ne!(out.new_hashes[1], fr(0), "the position is re-blinded");
    let v3 = chain.slot;
    assert_ne!(v3, v2);
    assert_eq!(
        leaf(&net, v3, 1),
        [fr(1), fr(collateral), fr(debt), fr(ONE)]
    );
    let refused = tag_of(&over, 1);
    assert_eq!(exit, borrowed, "the re-blind replaces the borrow's tag");
    assert_eq!(
        stored_tag(&net, v3, 1),
        refused,
        "and stores the refused borrow's note's tag"
    );
    let (_, o, exit, _) = M.land(&net, &clock, &mut chain, &skewed, 2, &hidden).await;
    assert_eq!(
        o,
        [CODE_INPUTS_MISMATCH, 0, 0, 0, 0, 0],
        "code 14 inside the outcome"
    );
    let v4 = chain.slot;
    assert_ne!(v4, v3);
    assert_eq!(
        leaf(&net, v4, 1),
        [fr(1), fr(collateral), fr(debt), fr(ONE)]
    );
    assert!(
        ![fr(0), deposited, borrowed, refused].contains(&exit),
        "shares that do not open C spend no tag: a filler"
    );
    assert_eq!(
        M.leaf(&net, v4, 1),
        M.leaf(&net, v3, 1),
        "nor write the position: its leaf stays, tag and blinding"
    );
    for q in [&over, &skewed] {
        assert_eq!(net.audit_received(q, &hidden), 3);
    }

    // ---- the price falls: a liquidation ---------------------------------------
    let price = 200;
    M.set_price(&mem, price, 4, 250);
    let liquidator = random();
    let budget = 10_000;
    let liquidate = M.liquidate(&net, 1, 1, budget, liquidator);
    M.queue(&net, &clock, &mut chain, &liquidate, &mut hidden)
        .await;
    let r = step(&mut s, clock.next(), "a liquidation").await;
    assert_eq!(computed(&r), [5], "{r:?}");
    assert_eq!(net.audit_received(&liquidate, &hidden), 3);
    let (out, o, exit, _) = M
        .land(&net, &clock, &mut chain, &liquidate, 2, &hidden)
        .await;
    // half the debt repaid (within the budget); the seize its value at the
    // price with the bonus; the unused budget the payout
    let (repay, seize) = liquidation(debt, price);
    assert!(repay <= budget);
    assert_eq!(
        o,
        [0, 0, 1, seize, repay, budget - repay],
        "mask 1, the totals, the unused budget"
    );
    // the liquidator's note names no position: it confers nothing; the
    // round replaces the owner's tag with the tag of the notice it delivers
    // through the position's handle (the refused borrow wrote it), which is
    // the owner's newest note of position 1
    assert_ne!(out.new_hashes[1], fr(0));
    assert_eq!(
        leaf(&net, chain.slot, 1),
        [fr(1), fr(collateral - seize), fr(debt - repay), fr(ONE)]
    );
    let handle = over.value("handle_partial");
    assert_eq!(
        M.leaf(&net, chain.slot, 1)[P_HANDLE],
        handle,
        "the liquidation keeps the handle"
    );
    assert_eq!(exit, refused, "the liquidation replaces the owner's tag");
    let noticed = exit_tag(handle, liquidate.chain, Fr::from(1u64));
    assert_eq!(
        stored_tag(&net, chain.slot, 1),
        noticed,
        "and stores the notice's tag"
    );

    // ---- a repayment of part of what the liquidation left -----------------------
    let amount = 1_009;
    let repayment = M.owned(&net, REPAY, 1, amount, owner);
    M.queue(&net, &clock, &mut chain, &repayment, &mut hidden)
        .await;
    let r = step(&mut s, clock.next(), "a repayment").await;
    assert_eq!(computed(&r), [6], "{r:?}");
    assert_eq!(net.audit_received(&repayment, &hidden), 3);
    let before = chain.slot;
    let (_, o, exit, _) = M
        .land(&net, &clock, &mut chain, &repayment, 2, &hidden)
        .await;
    let left = debt - repay - amount;
    assert_eq!(
        o,
        [0, 1, ONE, collateral - seize, left, 0],
        "the position after it, payout 0"
    );
    assert_ne!(chain.slot, before);
    assert_eq!(exit, noticed, "the repayment replaces the notice's tag");
    assert_eq!(
        stored_tag(&net, chain.slot, 1),
        tag_of(&repayment, 1),
        "a fresh note: the owner's view refreshed"
    );
    assert_eq!(
        leaf(&net, chain.slot, 1),
        [fr(1), fr(collateral - seize), fr(left), fr(ONE)]
    );
    assert_eq!(
        leaf(&net, chain.slot, 0),
        [
            fr(left),
            fr(LIQUIDITY - debt + repay + amount),
            fr(LIQUIDITY),
            fr(ONE)
        ],
        "the header: total debt down, liquidity up by the amount, the init's shares, the \
         borrow index"
    );

    // ---- a withdrawal down to the borrow limit at 2.00 --------------------------
    // the collateral left must keep left * PRICE_SCALE * BPS within
    // collateral * price * LTV_BPS
    let have = collateral - seize;
    let need = (left * PRICE_SCALE * BPS).div_ceil(price * LTV_BPS);
    let take = have - need;
    let withdrawal = M.owned(&net, WITHDRAW, 1, take, owner);
    M.queue(&net, &clock, &mut chain, &withdrawal, &mut hidden)
        .await;
    let r = step(&mut s, clock.next(), "a withdrawal").await;
    assert_eq!(computed(&r), [7], "{r:?}");
    let (_, o, exit, _) = M
        .land(&net, &clock, &mut chain, &withdrawal, 2, &hidden)
        .await;
    assert_eq!(
        o,
        [0, 1, ONE, need, left, COLLATERAL_ASSET | take],
        "the collateral left, the amount paid in the collateral asset"
    );
    assert_eq!(exit, tag_of(&repayment, 1));
    assert_eq!(stored_tag(&net, chain.slot, 1), tag_of(&withdrawal, 1));
    assert_eq!(
        leaf(&net, chain.slot, 1),
        [fr(1), fr(need), fr(left), fr(ONE)]
    );

    // ---- a lender: supply, withdrawal of supply, and a quote ---------------------
    // the pool is worth its shares (no interest yet): the init's LIQUIDITY
    let lender = random();
    let supplied = 5_003;
    let supply = M.owned(&net, SUPPLY, 0, supplied, lender);
    M.queue(&net, &clock, &mut chain, &supply, &mut hidden)
        .await;
    let r = step(&mut s, clock.next(), "an opening supply").await;
    assert_eq!(computed(&r), [8], "{r:?}");
    let (_, o, exit, _) = M.land(&net, &clock, &mut chain, &supply, 2, &hidden).await;
    assert_eq!(
        o,
        [0, 2, 0, supplied, supplied, 0],
        "a lender position at the next index, mask 0, one share per unit"
    );
    let lent = tag_of(&supply, 2);
    assert_eq!(stored_tag(&net, chain.slot, 2), lent);
    assert!(exit != fr(0) && exit != lent, "an opening: a filler");
    let burnt = 2_001;
    let unwind = M.withdraw_supply(&net, 2, burnt, lender);
    M.queue(&net, &clock, &mut chain, &unwind, &mut hidden)
        .await;
    let r = step(&mut s, clock.next(), "a withdrawal of supply").await;
    assert_eq!(computed(&r), [9], "{r:?}");
    let (_, o, spent, _) = M.land(&net, &clock, &mut chain, &unwind, 2, &hidden).await;
    let kept = supplied - burnt;
    assert_eq!(o, [0, 2, 0, kept, kept, burnt], "the shares' value paid");
    assert_eq!(spent, lent);
    assert_eq!(stored_tag(&net, chain.slot, 2), tag_of(&unwind, 2));
    let quote = M.quote(&net, random());
    M.queue(&net, &clock, &mut chain, &quote, &mut hidden).await;
    let r = step(&mut s, clock.next(), "a quote").await;
    assert_eq!(computed(&r), [10], "{r:?}");
    let (_, o, _, utilisation) = M.land(&net, &clock, &mut chain, &quote, 1, &hidden).await;
    let pool = LIQUIDITY + kept;
    assert_eq!(
        (o, utilisation),
        ([0, 0, ONE, 0, ONE, 0], fr(left * BPS / pool)),
        "the borrow index, the supply index at par, the utilisation in bps"
    );

    // ---- the clock moves on: a repayment accrues interest first ---------------
    // the book last accrued at 0; at 100 the borrow index grows at the
    // utilisation the quote reported and the position's debt is brought to
    // it, rounded up (market.nr `accrue`, `debt_at`)
    let dt = 100;
    M.set_clock(&mem, dt);
    let index = accrued_index(ONE, left * BPS / pool, dt);
    let owed = (left * index).div_ceil(ONE);
    assert!(owed > left, "the debt grew");
    let paid = 1_001;
    let late = M.owned(&net, REPAY, 1, paid, owner);
    M.queue(&net, &clock, &mut chain, &late, &mut hidden).await;
    let r = step(&mut s, clock.next(), "a repayment 100 blocks on").await;
    assert_eq!(computed(&r), [11], "{r:?}");
    let (_, o, exit, _) = M.land(&net, &clock, &mut chain, &late, 2, &hidden).await;
    assert_eq!(
        o,
        [0, 1, index, need, owed - paid, 0],
        "the position at the new index, its accrued debt less the amount"
    );
    assert_eq!(exit, tag_of(&withdrawal, 1));
    assert_eq!(stored_tag(&net, chain.slot, 1), tag_of(&late, 1));
    assert_eq!(
        leaf(&net, chain.slot, 1),
        [fr(1), fr(need), fr(owed - paid), fr(index)]
    );
    assert_eq!(
        leaf(&net, chain.slot, 0),
        [
            fr(owed - paid),
            fr(pool - left + paid),
            fr(LIQUIDITY + kept),
            fr(index)
        ],
        "the header: total debt accrued then repaid, the borrow index grown"
    );
    eprintln!(
        "lending secret-shared rounds: deposit {collateral}, borrow {debt}, liquidation seize {seize} \
         repay {repay}, repayment {amount}, withdrawal {take}, supply {supplied}, withdrawal of \
         supply {burnt}, a quote, a repayment {paid} of the accrued debt {owed} ({:.1}s)",
        started.elapsed().as_secs_f64()
    );
}

/// The deposit under secret-shared on-chain intake: the same compiled circuit.
const DEPOSIT_ONCHAIN: &str = "deposit_shared_onchain";

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_shared_onchain_deposit_runs_intake_to_result_on_three_nodes() {
    let m = Market {
        tip: 0x7e5e,
        book: "0x000000000000000000000000000000000000000000000000000000000000a005",
        oracle: 0x0a14,
    };
    let Lending {
        tmp: _tmp,
        net,
        started,
        clock,
        mut chain,
        mut s,
        mut hidden,
        ..
    } = m
        .start_packages(
            "lendonchain",
            &[(SEED, SEED), (INIT, INIT), (DEPOSIT_ONCHAIN, DEPOSIT)],
            true,
        )
        .await;
    let mut clock = clock;
    let pkg = net.package(m.ns(), DEPOSIT_ONCHAIN);
    assert_eq!(
        pkg.tip.intake(),
        sidecar_core::manifest::QueuedIntake::SharedOnchain
    );
    let mut stored = EncKeys {
        pks: net.enc_pks,
        epochs: [0; 3],
    };
    for i in 0..3 {
        net.rotate_onchain(&mut chain, &mut stored, i, None, 1, 0);
    }

    // ---- an opening deposit, its outcome key and tag the user's ----------------
    let owner = random();
    let (outcome_key, outcome_tag) = (random(), random());
    let collateral = 5_011;
    let deposit = OnchainRequest::new(
        m.ns(),
        &pkg,
        stored,
        owned_inputs(0, collateral, owner),
        &[("$outcome_key", outcome_key), ("$outcome_tag", outcome_tag)],
    );
    assert_eq!(
        (deposit.req.outcome_key, deposit.req.outcome_tag),
        (outcome_key, outcome_tag),
        "the user's"
    );
    assert_eq!(deposit.log[6], fr(0), "position is clear in the log");
    hidden.add(&deposit.req);
    hidden.values.push(("$outcome_key".into(), outcome_key));
    chain.intake_shared_onchain(&clock, &stored, &deposit, &hidden);
    let round = std::time::Instant::now();
    let r = step(
        &mut s,
        clock.next(),
        "a secret-shared on-chain opening deposit",
    )
    .await;
    assert_eq!(r.error, None, "{r:?}");
    assert_eq!(computed(&r), [1], "{r:?}");
    eprintln!(
        "MPC: a secret-shared on-chain deposit round in {:.1}s",
        round.elapsed().as_secs_f64()
    );
    assert_eq!(net.audit_received_onchain(&deposit, &hidden), 3);
    let (_, o, exit, _) = m
        .land(&net, &clock, &mut chain, &deposit.req, 2, &hidden)
        .await;
    assert_eq!(
        o,
        [0, 1, ONE, collateral, 0, 0],
        "ok, the assigned position 1"
    );
    assert_eq!(
        leaf_of(&net, m, chain.slot, 1),
        [fr(1), fr(collateral), fr(0), fr(ONE)]
    );
    let deposited = tag_of(&deposit.req, 1);
    assert_eq!(m.leaf(&net, chain.slot, 1)[P_EXIT_TAG], deposited);
    assert!(exit != fr(0) && exit != deposited, "an opening: a filler");
    eprintln!(
        "lending secret-shared on-chain deposit: {collateral} at position 1 ({:.1}s)",
        started.elapsed().as_secs_f64()
    );
}
