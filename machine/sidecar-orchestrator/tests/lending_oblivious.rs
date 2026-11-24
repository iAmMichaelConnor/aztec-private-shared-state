//! Lending's oblivious deployment over three real nodes with real MPC
//! proofs (docs/ARCHITECTURE.md section 6, "The oblivious tree";
//! examples/lending-tip "The oblivious deployment"): the manifests of
//! `lending_init_oblivious`, `deposit_oblivious` and `borrow_oblivious` as
//! committed, whose book has `access: oblivious`, REGISTERed at the three nodes;
//! every request under secret-shared receipt intake with its position a shared
//! input, so the nodes read the slots' paths from their oblivious RAM (step 10b
//! over the mesh) and no node learns which leaf a round touches.
//!
//! - The init round creates the book, its append index 1.
//! - An opening deposit (`opens` 1, the position 0 shared) takes the
//!   scheduler's `$new_leaf` from the nodes' append index: the outcome
//!   reports position 1, and the round's first app value, the header's
//!   append index after it, is the new version's (2).
//! - A second opening takes position 2 (append index 3), reading the
//!   header the first opening wrote into the oblivious RAM at the next
//!   session's start.
//! - A borrow on position 1 reads the first opening's leaf at a shared
//!   address and reports its collateral and the debt; the append index
//!   stays, and its exit value is the exit tag of the opening's note
//!   (`poseidon2([PSS_EXIT_TAG + 2^128 * 1, P, request_id])`, P the
//!   opening's partial note), the tag its write replaced.
//! - The three nodes agree on every version; the leaf-hash outputs are
//!   zeros.
//!
//! Needs `scripts/prepare-data.sh` (examples/lending-tip's circuits and the
//! CRS under machine/data, or DATA_DIR); fails naming the missing files if
//! they are absent. Run with `--release`.

mod common;
mod lending;
mod shared_intake;

use common::tip::*;
use common::*;
use lending::*;
use shared_intake::*;

use sidecar_core::field::Fr;
use sidecar_core::store::StoreRead;

const M: Market = Market {
    tip: 0x7e6b,
    book: "0x000000000000000000000000000000000000000000000000000000000000a0b1",
    oracle: 0x0a1b,
};
const INIT_OBLIVIOUS: &str = "lending_init_oblivious";
const DEPOSIT_OBLIVIOUS: &str = "deposit_oblivious";
const BORROW_OBLIVIOUS: &str = "borrow_oblivious";
const CIRCUITS: [&str; 4] = [SEED, INIT_OBLIVIOUS, DEPOSIT_OBLIVIOUS, BORROW_OBLIVIOUS];

/// The append index of the book version under `commitment`, which the
/// three nodes record alike.
fn next_index(net: &Net, commitment: Fr) -> u64 {
    let all: Vec<u64> = (0..3)
        .map(|i| {
            net.real.apps[i]
                .node
                .store
                .tip_version(M.ns(), M.book, commitment)
                .unwrap()
                .unwrap_or_else(|| panic!("node {i} holds no version"))
                .tree
                .unwrap_or_else(|| panic!("node {i}: the version has no tree"))
                .next()
        })
        .collect();
    assert!(all.iter().all(|n| *n == all[0]), "{all:?}");
    all[0]
}

/// An opening deposit of `amount` on the oblivious deployment: the position
/// 0 shared, the opening flag public, `owner`'s delivery handle and partial
/// note.
fn opening(net: &Net, amount: u64, owner: Fr) -> SharedRequest {
    M.request(
        net,
        DEPOSIT_OBLIVIOUS,
        vec![
            shared("position", fr(0)),
            clear("opens", fr(1)),
            shared("amount", fr(amount)),
            shared("handle_partial", partial_commitment(owner, random())),
            shared("handle_key", random()),
            shared("$partial_note", partial_commitment(owner, random())),
        ],
    )
    .owned_by(owner)
}

/// The latest attempt's last two app values: the header's append index,
/// then the inputs-opened bit (after the exit value; the round's delivery
/// after them).
async fn app_values(net: &Net, req: &SharedRequest) -> (u64, u64) {
    let pi = net.latest(M.ns(), req.chain).await.public_inputs;
    let n = pi.len() - DELIVERY_FIELDS;
    (small(pi[n - 2].fr()), small(pi[n - 1].fr()))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn lending_oblivious_rounds_run_on_three_nodes() {
    let Lending {
        tmp: _tmp,
        mem: _mem,
        net,
        started,
        mut clock,
        mut chain,
        mut s,
        mut hidden,
        init,
    } = M
        .start_with_init("lendobliv", &CIRCUITS, INIT_OBLIVIOUS)
        .await;
    // [namespace, vk_hash, out_slots[0], request_id, old_c, new_c,
    // npk_app_hash, new_hashes[0] = 0]
    assert_eq!(init.len(), 8);
    assert_eq!(init[7], fr(0), "no leaf hash on the oblivious deployment");
    let v0 = chain.slot;
    assert_eq!(next_index(&net, v0), 1, "the init's append index");

    // ---- an opening deposit: $new_leaf from the nodes' append index ----------
    let alice = random();
    let collateral = 5_011;
    let deposit = opening(&net, collateral, alice);
    M.queue(&net, &clock, &mut chain, &deposit, &mut hidden)
        .await;
    let r = step(&mut s, clock.next(), "an opening deposit").await;
    assert_eq!(computed(&r), [1], "{r:?}");
    assert_eq!(net.audit_received(&deposit, &hidden), 3);
    let (next, opened) = app_values(&net, &deposit).await;
    let (out, o, _, _) = M.land(&net, &clock, &mut chain, &deposit, 2, &hidden).await;
    assert_eq!(
        o,
        [0, 1, ONE, collateral, 0, 0],
        "ok, the assigned position 1"
    );
    assert_eq!((next, opened), (2, 1), "the append index after the round");
    assert!(
        out.new_hashes.iter().all(|h| *h == fr(0)),
        "no leaf hash output: {:?}",
        out.new_hashes
    );
    let v1 = chain.slot;
    assert_eq!(next_index(&net, v1), 2);

    // ---- a second opening reads the header the first wrote --------------------
    let bob = random();
    let deposit2 = opening(&net, 7_019, bob);
    M.queue(&net, &clock, &mut chain, &deposit2, &mut hidden)
        .await;
    let r = step(&mut s, clock.next(), "a second opening").await;
    assert_eq!(computed(&r), [2], "{r:?}");
    let (next, _) = app_values(&net, &deposit2).await;
    let (_, o, _, _) = M
        .land(&net, &clock, &mut chain, &deposit2, 2, &hidden)
        .await;
    assert_eq!(o, [0, 2, ONE, 7_019, 0, 0], "ok, the assigned position 2");
    assert_eq!(next, 3);
    let v2 = chain.slot;
    assert_eq!(next_index(&net, v2), 3);

    // ---- a borrow on position 1 reads alice's leaf at a shared address --------
    // the borrow limit is collateral * 2.50 * 75% = 9395
    let debt = 9_013;
    let borrow = M
        .request(
            &net,
            BORROW_OBLIVIOUS,
            vec![
                shared("position", fr(1)),
                shared("amount", fr(debt)),
                shared("handle_partial", partial_commitment(alice, random())),
                shared("handle_key", random()),
                shared("$partial_note", partial_commitment(alice, random())),
            ],
        )
        .owned_by(alice);
    M.queue(&net, &clock, &mut chain, &borrow, &mut hidden)
        .await;
    let r = step(&mut s, clock.next(), "a borrow on position 1").await;
    assert_eq!(computed(&r), [3], "{r:?}");
    assert_eq!(net.audit_received(&borrow, &hidden), 3);
    let (next, _) = app_values(&net, &borrow).await;
    let (_, o, exit, _) = M.land(&net, &clock, &mut chain, &borrow, 2, &hidden).await;
    assert_eq!(
        o,
        [0, 1, ONE, collateral, debt, debt],
        "the payout is the amount"
    );
    assert_eq!(exit, tag_of(&deposit, 1), "it replaces alice's opening tag");
    assert_eq!(next, 3, "a borrow opens nothing");
    let v3 = chain.slot;
    assert_eq!(next_index(&net, v3), 3);

    // ---- the three nodes agree on every version ----------------------------------
    for v in [v0, v1, v2, v3] {
        assert!(net.holds(M.ns(), M.book, v));
    }
    eprintln!(
        "oblivious lending rounds: {:.1}s",
        started.elapsed().as_secs_f64()
    );
}
