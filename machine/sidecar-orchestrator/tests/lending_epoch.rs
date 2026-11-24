//! Lending's tree rounds under the epoch policy over three real nodes with
//! real MPC proofs: examples/lending-tip's `lending_init` and `deposit` as
//! committed (the book one tree-valued node-held key, every
//! round's price an epoch read of the oracle, `get_price_epoch()` answering
//! [price, epoch, the previous epoch's price], and its clock a tolerance read
//! of the market's own `clock()`, held at 0), driven by the scheduler on
//! sidecar-tip's in-memory Aztec node, each node running the real chain
//! verifier over it.
//!
//! The price moves while a non-secret-shared round is in flight:
//!
//! - One epoch opens between the scheduler's read and `apply` (an opening
//!   deposit): the attempt is kept, `apply`'s freshness rule admits it at
//!   the new epoch, and it lands as computed.
//! - Two epochs open (a second deposit into that position): the scheduler
//!   recomputes the round exactly once, on the same book version at the new
//!   price under a new machine request id; the recompute lands and the
//!   position holds both deposits. A deposit does not use the price, but
//!   every lending round makes the read, so the rule is the same for every
//!   round.
//!
//! The bound: a lending round lands at its first attempt when at most one
//! epoch opens between the scheduler's read and `apply`, and costs one
//! recompute per two epochs otherwise.
//!
//! Needs `scripts/prepare-data.sh` (examples/lending-tip's circuits and the
//! CRS under machine/data, or DATA_DIR); fails naming the missing files if
//! they are absent, so a passing run proves it ran. Run with `--release`.

mod common;

use std::sync::Arc;

use common::tip::*;
use common::*;
use serde_json::{Value, json};

use sidecar_core::bind::Elem;
use sidecar_core::field::{Fr, fr_from_hex, fr_to_hex};
use sidecar_core::response::ExecuteResponse;
use sidecar_core::store::{StoreRead, VersionTree};
use sidecar_core::tree;
use sidecar_tip::machine_request_id;
use sidecar_tip::testing::MemoryChain;

const TIP: u64 = 0x7198;
// the slot as the contract manifest writes it (fr_to_hex)
const BOOK: &str = "0x000000000000000000000000000000000000000000000000000000000000a004";
const ORACLE: u64 = 0x0a13;
const INIT: &str = "lending_init";
const DEPOSIT: &str = "deposit";
/// The book's tree (the lending manifests' `tree`): depth 16, leaves
/// [opened, collateral, debt, 0, blinding].
const DEPTH: u32 = 16;
const LEAF_LEN: usize = 8;
/// INDEX_ONE (market.nr): a borrower leaf's index at touch.
const ONE: u64 = 1_000_000_000;
const LIQUIDITY: u64 = 1_000_000;
/// The partial note the non-secret-shared deposits carry (any field: the
/// round echoes it for the contract's public completion and never checks an
/// owner).
const PARTIAL: u64 = 0x0a11ce;

fn ns() -> Fr {
    Fr::from(TIP)
}

fn book() -> Fr {
    fr_from_hex(BOOK).unwrap()
}

fn namespace() -> TipEntry {
    tip_namespace(ns(), BOOK, &[INIT, DEPOSIT], &[INIT])
}

/// A lending manifest as committed, its price read pointed at the oracle;
/// its clock read stays `$self`, the market (the namespace) itself.
fn lending(name: &str) -> Value {
    let mut m = manifest("lending-tip", name);
    for read in m["public_reads"].as_array_mut().unwrap() {
        if read["function"] != "clock" {
            read["contract"] = json!(fr_to_hex(Fr::from(ORACLE)));
        }
    }
    m
}

/// The oracle's epoch source: [price, epoch, the previous epoch's price].
fn set_price(mem: &MemoryChain, price: u64, epoch: u64, previous: u64) {
    mem.set_call(
        Fr::from(ORACLE),
        "get_price_epoch()",
        &[],
        Ok(vec![Fr::from(price), Fr::from(epoch), Fr::from(previous)]),
    );
}

/// The market's `clock()`: the block number a round accrues interest to.
/// The book's last accrual is 0, so a clock of 0 accrues nothing.
fn set_clock(mem: &MemoryChain, block: u64) {
    mem.set_call(ns(), "clock()", &[], Ok(vec![Fr::from(block)]));
}

impl World {
    /// Whether `apply`'s freshness rule (pss_public_contract `Freshness`)
    /// admits a deposit's price read, the price and its epoch the result
    /// carries, while the oracle answers [price, epoch, previous].
    fn applies(&self, result: &ExecuteResponse, now: [u64; 3]) -> bool {
        let pkg = self.package(DEPOSIT);
        let read = &pkg.tip.public_reads()[0];
        let o = self.outputs(result);
        let used = [o.param("price"), o.param("price_epoch")];
        read.admits(&[fr(now[0]), fr(now[1])], Some(fr(now[2])), &used)
    }

    /// Leaf `index` of the book version under `commitment`, opened from the
    /// three nodes' pairs, its blinding left out: [1, collateral, debt,
    /// index_at_touch, 0, 0, 0] for a borrower position and [total_debt,
    /// liquidity, total_shares, borrow_index, last_accrual, next_index, 0]
    /// for the header.
    fn leaf(&self, commitment: Fr, index: u64) -> [Fr; 7] {
        let z = tree::zeros(DEPTH);
        let parts: Vec<Vec<Elem>> = (0..3)
            .map(|i| {
                let store = &self.real.apps[i].node.store;
                let root = store
                    .tip_version(ns(), BOOK, commitment)
                    .unwrap()
                    .unwrap_or_else(|| panic!("node {i}: no version {}", fr_to_hex(commitment)))
                    .tree
                    .and_then(VersionTree::clear)
                    .unwrap()
                    .root;
                let nodes = |h: Fr| Ok(store.tip_node(ns(), BOOK, h).unwrap().map(|n| n.node));
                tree::leaves(&nodes, &z, root, LEAF_LEN, &[index]).unwrap()
            })
            .collect();
        [0, 1, 2, 3, 4, 5, 6].map(|k| match [&parts[0][k], &parts[1][k], &parts[2][k]] {
            [Elem::Shared(a), Elem::Shared(b), Elem::Shared(c)] => a.a + b.a + c.a,
            [Elem::Public(a), Elem::Public(b), Elem::Public(c)] if a == b && b == c => *a,
            _ => panic!("the nodes disagree on a leaf element"),
        })
    }

    /// A deposit's [ok, code, position], with its echoed partial note
    /// checked.
    fn outcome(&self, result: &ExecuteResponse) -> [Fr; 3] {
        let o = self.outputs(result);
        assert_eq!(
            o.get("partial_note"),
            fr(PARTIAL),
            "the round echoes the request's partial note after ok"
        );
        [o.get("ok"), o.get("app.code"), o.get("app.position")]
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_lending_round_lands_across_one_price_epoch_and_is_recomputed_once_after_two() {
    let tmp = TempDir::new("lending");
    let mem = Arc::new(MemoryChain::new(100));
    let w = setup(
        &tmp,
        &mem,
        &namespace(),
        vec![
            Package::new(INIT, lending(INIT)),
            Package::new(DEPOSIT, lending(DEPOSIT)),
        ],
    )
    .await;
    let mut clock = Clock::new(100, mem.clone());
    let mut chain = Chain::new(&clock, ns(), book(), w.sig_pks);
    let mut s = scheduler(&w, &mem, &namespace());
    set_price(&mem, 250, 1, 250);
    set_clock(&mem, 0);

    // ---- one epoch opens during an opening deposit: the attempt lands ------
    // lending_init's request id is over [liquidity] with nonce 0 (its
    // main.nr); deposit's app inputs are [position, amount, partial_note]
    let c0 = chain.intake_onchain(&clock, w.vk(INIT), &[fr(LIQUIDITY)], 0);
    let c1 = chain.intake_onchain(&clock, w.vk(DEPOSIT), &[fr(0), fr(1000), fr(PARTIAL)], 1);
    let r = step(
        &mut s,
        clock.next(),
        "init and an opening deposit at epoch 1",
    )
    .await;
    assert_eq!(r.error, None);
    assert_eq!(computed(&r), [0, 1]);
    let at1 = r.computed[1].clone();
    assert_eq!(at1.pinned, [fr(250), fr(1), fr(0)]);
    let init = w.latest("init", c0).await;
    w.apply(&clock, &mut chain, &init).unwrap();
    // the oracle opens epoch 2 before the relayer lands the deposit
    set_price(&mem, 260, 2, 250);
    let r = step(
        &mut s,
        clock.next(),
        "epoch 2: the deposit at epoch 1 is kept",
    )
    .await;
    assert!(
        !r.repriced && !r.reloaded && computed(&r).is_empty(),
        "{r:?}"
    );
    let deposited = w.latest("deposit", c1).await;
    assert_eq!(deposited.request_id, at1.request_id, "the first attempt");
    assert!(
        w.applies(&deposited, [260, 2, 250]),
        "apply admits epoch 1 at epoch 2"
    );
    assert!(!w.applies(&deposited, [270, 3, 260]), "and not at epoch 3");
    assert_eq!(
        w.outcome(&deposited),
        [fr(1), fr(0), fr(1)],
        "ok, position 1"
    );
    w.apply(&clock, &mut chain, &deposited).unwrap();
    let v1 = chain.slot;
    assert_eq!(
        w.leaf(v1, 1),
        [fr(1), fr(1000), fr(0), fr(ONE), fr(0), fr(0), fr(0)]
    );

    // ---- two epochs open during a second deposit: recomputed exactly once --
    let c2 = chain.intake_onchain(&clock, w.vk(DEPOSIT), &[fr(1), fr(500), fr(PARTIAL)], 2);
    set_price(&mem, 270, 3, 260);
    let r = step(&mut s, clock.next(), "a deposit at epoch 3").await;
    assert_eq!(r.error, None);
    assert_eq!(computed(&r), [2]);
    let at3 = r.computed[0].clone();
    assert_eq!(at3.old[BOOK], v1);
    assert_eq!(at3.pinned, [fr(270), fr(3), fr(0)]);
    set_price(&mem, 280, 4, 270);
    let r = step(&mut s, clock.next(), "epoch 4: kept").await;
    assert!(!r.repriced && computed(&r).is_empty(), "{r:?}");
    set_price(&mem, 290, 5, 280);
    let r = step(&mut s, clock.next(), "epoch 5: recomputed").await;
    assert!(r.repriced && !r.reloaded, "{r:?}");
    assert_eq!(r.error, None);
    assert_eq!(computed(&r), [2]);
    let at5 = r.computed[0].clone();
    assert_eq!(at5.old, at3.old, "the same book version");
    assert_eq!(at5.pinned, [fr(290), fr(5), fr(0)]);
    assert_ne!(at5.request_id, at3.request_id, "a new machine request id");
    assert_eq!(
        at5.request_id.fr(),
        machine_request_id(c2, &[v1], &at5.pinned)
    );
    let r = step(&mut s, clock.next(), "epoch 5 still: nothing more").await;
    assert!(!r.repriced && computed(&r).is_empty(), "{r:?}");
    let added = w.latest("deposit", c2).await;
    assert_eq!(
        added.request_id, at5.request_id,
        "FETCH answers the recompute"
    );
    assert!(w.applies(&added, [290, 5, 280]));
    assert_eq!(w.outcome(&added), [fr(1), fr(0), fr(1)], "ok, position 1");
    w.apply(&clock, &mut chain, &added).unwrap();
    assert_eq!(
        w.leaf(chain.slot, 1),
        [fr(1), fr(1500), fr(0), fr(ONE), fr(0), fr(0), fr(0)]
    );
    // the header's append index: past the one opened position
    assert_eq!(w.leaf(chain.slot, 0)[5], fr(2));
    let r = step(&mut s, clock.next(), "after the second deposit lands").await;
    assert!(
        !r.repriced && !r.reloaded && computed(&r).is_empty(),
        "{r:?}"
    );
    eprintln!(
        "BOUND: the deposit landed at its first attempt across one epoch; the second \
         deposit, two epochs behind, was recomputed exactly once and landed"
    );
}
