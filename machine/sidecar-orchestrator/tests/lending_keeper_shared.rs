//! Lending's keeper round under secret-shared receipt intake, in process over three
//! real nodes with real MPC proofs (docs/ARCHITECTURE.md section 6,
//! "A read-only window on a tree key"): examples/lending-tip's
//! `scan_shared` with its manifest as committed (the `tree` entry's `window`
//! form), on a book the secret-shared deposit and borrow rounds build, then
//! `liquidate_shared` at the index the report names. Each request goes
//! receipt -> head -> round -> result, as in `lending_tip_shared.rs`.
//!
//! - The scheduler places each scan's window in the slots' one tree read:
//!   the request every node receives carries the window's eight old hashes
//!   and its root's thirteen siblings, which give the book's root at the
//!   window's position, and the round binds them (an `ok` outcome).
//! - Two scans pipelined on one book version: window 0 reports
//!   `[0, 0, 0b10, 0, 0, 0, 2]` at 2.00 (`[code, 0, report, 0, start, 0,
//!   occupied]`, the occupied count the outcome's `aux`: position 1
//!   unhealthy, position 2 healthy, two occupied, the header counting for
//!   neither; position 0 and x 0, so the keeper's note confers and pays
//!   nothing), window 8 `[0, 0, 0, 0, 8, 0, 0]` (empty: the book ends inside
//!   window 0). Each writes nothing but the header's fresh blinding: the
//!   book's positions keep their values and the commitment moves.
//! - The audit: no shared input (`$partial_note`) and no requester (the
//!   owner of a partial note) appears in a
//!   receipt, a node's received request or the proof's public inputs.
//! - The liquidation at the reported index lands with a budget below the
//!   close-factor repay: mask 1, the whole budget repaid and the seize
//!   scaled with it at the price with the bonus, nothing of the budget left.
//!   It outputs the borrow's exit tag (the one it replaces) and stores in
//!   the position's leaf the exit tag of the notice it delivers through the
//!   owner's delivery handle.
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

use sidecar_core::field::{Fr, fr_from_hex, fr_to_hex};
use sidecar_core::store::{StoreRead, VersionTree};
use sidecar_core::tree;

const M: Market = Market {
    tip: 0x7e5e,
    book: "0x000000000000000000000000000000000000000000000000000000000000a005",
    oracle: 0x0a14,
};
const CIRCUITS: [&str; 6] = [SEED, INIT, DEPOSIT, BORROW, LIQUIDATE, SCAN];

fn hexes(v: &Value) -> Vec<Fr> {
    v.as_array()
        .unwrap_or_else(|| panic!("not an array: {v}"))
        .iter()
        .map(|x| fr_from_hex(x.as_str().unwrap()).unwrap())
        .collect()
}
/// The scan's window as each node received it: eight old hashes and the
/// window root's thirteen siblings, the same at every node, which give the
/// root of the book version under `commitment` at window `start`.
fn assert_window_placed(net: &Net, scan: &SharedRequest, start: u64, commitment: Fr) {
    let received = net.received_for(scan.chain);
    assert_eq!(received.len(), 3, "one request per node");
    let store = &net.real.apps[0].node.store;
    let root = store
        .tip_version(M.ns(), M.book, commitment)
        .unwrap()
        .unwrap_or_else(|| panic!("no version {}", fr_to_hex(commitment)))
        .tree
        .and_then(VersionTree::clear)
        .unwrap()
        .root;
    assert_eq!(tree::commitment(M.ns(), M.book(), root), commitment);
    let first = &received[0].1["public"];
    for (i, r) in &received {
        assert_eq!(r["public"]["start"], first["start"], "node {i}");
        assert_eq!(
            r["public"]["window_hashes"], first["window_hashes"],
            "node {i}"
        );
        assert_eq!(
            r["public"]["window_siblings"], first["window_siblings"],
            "node {i}"
        );
    }
    let hashes = hexes(&first["window_hashes"]);
    let siblings = hexes(&first["window_siblings"]);
    assert_eq!(hashes.len() as u64, WINDOW);
    assert_eq!(siblings.len() as u32, DEPTH - WINDOW.trailing_zeros());
    let mut level = hashes;
    while level.len() > 1 {
        level = level.chunks(2).map(|p| tree::node(p[0], p[1])).collect();
    }
    assert_eq!(
        tree::root_of(level[0], &siblings, start / WINDOW),
        root,
        "window {start}: its hashes and siblings give the book's root"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn lending_scan_reports_unhealthy_positions_on_three_nodes() {
    let Lending {
        tmp: _tmp,
        mem,
        net,
        started,
        mut clock,
        mut chain,
        mut s,
        mut hidden,
        ..
    } = M.start("lendscan", &CIRCUITS).await;

    // ---- the book: two opening deposits, a borrow ------------------------------
    let (alice, bob) = (random(), random());
    let collateral = 1_000;
    let a = M.owned(&net, DEPOSIT, 0, collateral, alice);
    let b = M.owned(&net, DEPOSIT, 0, collateral, bob);
    for (k, q) in [&a, &b].into_iter().enumerate() {
        M.queue(&net, &clock, &mut chain, q, &mut hidden).await;
        let r = step(&mut s, clock.next(), "an opening deposit").await;
        assert_eq!(computed(&r), [k as u64 + 1], "{r:?}");
        let (_, o, _, _) = M.land(&net, &clock, &mut chain, q, 2, &hidden).await;
        assert_eq!(
            o,
            [0, k as u64 + 1, ONE, collateral, 0, 0],
            "position {}",
            k + 1
        );
    }
    // within the borrow limit at 2.50 (1,875), unhealthy at 2.00 (the
    // liquidation threshold 1,600)
    let debt = 1_700;
    let borrow = M.owned(&net, BORROW, 1, debt, alice);
    M.queue(&net, &clock, &mut chain, &borrow, &mut hidden)
        .await;
    let r = step(&mut s, clock.next(), "a borrow at 2.50").await;
    assert_eq!(computed(&r), [3], "{r:?}");
    let (_, o, _, _) = M.land(&net, &clock, &mut chain, &borrow, 2, &hidden).await;
    assert_eq!(o, [0, 1, ONE, collateral, debt, debt]);

    // ---- the price falls; two scans pipelined on one book version -------------
    let price = 200;
    M.set_price(&mem, price, 2, 250);
    let keeper = random();
    let scan = |start: u64| {
        M.request(
            &net,
            SCAN,
            vec![
                clear("start", fr(start)),
                shared("$partial_note", partial_commitment(keeper, random())),
            ],
        )
        .owned_by(keeper)
    };
    let (w0, w8) = (scan(0), scan(WINDOW));
    for q in [&w0, &w8] {
        M.queue(&net, &clock, &mut chain, q, &mut hidden).await;
    }
    let before = chain.slot;
    let r = step(&mut s, clock.next(), "scans of windows 0 and 8").await;
    assert_eq!(computed(&r), [4, 5], "{r:?}");
    assert_window_placed(&net, &w0, 0, before);
    assert_eq!(net.audit_received(&w0, &hidden), 3);
    let (_, o, _, occupied) = M.land(&net, &clock, &mut chain, &w0, 1, &hidden).await;
    assert_eq!(
        (o, occupied),
        ([0, 0, 0b10, 0, 0, 0], fr(2)),
        "position 1 unhealthy, two occupied; position 0 and x 0, so the note confers and pays nothing"
    );
    let after_w0 = chain.slot;
    assert_window_placed(&net, &w8, WINDOW, after_w0);
    assert_eq!(net.audit_received(&w8, &hidden), 3);
    let (_, o, _, occupied) = M.land(&net, &clock, &mut chain, &w8, 1, &hidden).await;
    assert_eq!(
        (o, occupied),
        ([0, 0, 0, 0, WINDOW, 0], fr(0)),
        "an empty window: the book ends in window 0"
    );

    // ---- the liquidation at the reported index ---------------------------------
    // a budget of half the close-factor repay (850 of the debt's 1,700)
    let budget = 425;
    let liquidate = M.liquidate(&net, 1, 1, budget, keeper);
    M.queue(&net, &clock, &mut chain, &liquidate, &mut hidden)
        .await;
    let r = step(&mut s, clock.next(), "the liquidation the report names").await;
    assert_eq!(computed(&r), [6], "{r:?}");
    assert_eq!(net.audit_received(&liquidate, &hidden), 3);
    let (_, o, exit, _) = M
        .land(&net, &clock, &mut chain, &liquidate, 2, &hidden)
        .await;
    let (close, _) = liquidation(debt, price);
    assert!(budget < close);
    let repay = budget;
    let seize = repay * PRICE_SCALE * (BPS + BONUS_BPS) / (price * BPS);
    assert_eq!(
        o,
        [0, 0, 1, seize, repay, 0],
        "mask 1, the budget repaid, the seize scaled, nothing unused"
    );
    assert_eq!(exit, tag_of(&borrow, 1), "it replaces the borrow's tag");
    assert_eq!(
        M.leaf(&net, chain.slot, 1)[P_EXIT_TAG],
        exit_tag(
            borrow.value("handle_partial"),
            liquidate.chain,
            Fr::from(1u64)
        ),
        "with the tag of the notice it delivers through alice's handle"
    );
    eprintln!(
        "lending keeper: window 0 reported position 1, window 8 empty; liquidation seize {seize} \
         repay {repay} ({:.1}s)",
        started.elapsed().as_secs_f64()
    );
}
