//! The tip's two non-secret-shared intakes and its receipts in one process
//! (ARCHITECTURE.md section 6; section 8, the tip): three real nodes, each
//! with its real chain verifier and its receipt signer over its own view of
//! sidecar-tip's in-memory Aztec node; the orchestrator with its receipt
//! route; the scheduler with its chain reader over the same chain; and a
//! mock contract, which the test writes as intake, `apply` and `skip()`
//! would. Every round is a real three-party MPC round with a real proof:
//! the AMM tip rounds of examples/amm-tip (`amm_init_tip`, and the one
//! compiled `amm_swap_tip` under its on-chain and its receipt manifest),
//! the pool node-held.
//!
//! The mock contract's intake appends the requester-free chain request id
//! (`poseidon2(namespace, vk_hash, inputs_hash, user_nonce)`) and writes
//! `seen`; on-chain intake logs the inputs and the nonce, receipt intake
//! checks the three receipt signatures against the pinned `sig` keys and
//! refuses a receipt at or past its `expiry_block`. Its `apply` checks the
//! three result signatures against the pinned `sig` keys (`H(sealed_i) = 0`
//! under node-held state), that the request id the round output is the
//! head's and the slot, then writes the slot, `done` and the head.
//!
//! - Both non-secret-shared intakes, in queue order: the head and one
//!   pipelined entry are computed, nothing outside that window; the relayer
//!   FETCHes each result by chain request id; each landed result carries no
//!   records and the three signatures; the pool's versions open to the
//!   reserves the swaps' outputs give.
//! - A receipt-intake request whose input is not the stored receipt's is
//!   refused (400) by every node with nothing stored.
//! - Receipts: the same receipt queued twice is refused (its id is seen); a
//!   receipt at its expiry is refused at intake; past `expiry +
//!   stale_blocks` each node prunes a never-queued receipt and a done one,
//!   keeps a queued one until `done` is written (the head skipped), then
//!   prunes it.
//! - The hidden requester: no account address appears in a chain request
//!   id, a request log, a receipt body or row, a request any node receives,
//!   or a proof's public inputs (sidecar-tip's `audit`).
//!
//! Needs `scripts/prepare-data.sh` (examples/amm-tip's circuits and the CRS
//! under machine/data, or DATA_DIR); the test fails naming the missing files
//! if they are absent, so a passing run proves it ran. Run with `--release`.

mod common;

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Instant;

use common::tip::*;
use common::*;
use serde_json::{Value, json};

use sidecar_core::field::{FieldHex, Fr, fr_from_hex};
use sidecar_core::request::{PublicValue, Request};
use sidecar_core::response::ExecuteResponse;
use sidecar_core::store::Store;
use sidecar_tip::audit::Requesters;
use sidecar_tip::testing::MemoryChain;
use sidecar_tip::{
    KeyState, PinnedValues, PlainFound, PublicMap, QueueEntry, ReceiptResponse, SynthesisView,
    inputs_hash, synthesise, verify_receipt,
};

const TIP: u64 = 0x7197;
// the slot as the contract manifest writes it (fr_to_hex)
const POOL: &str = "0x000000000000000000000000000000000000000000000000000000000000a002";
const INIT: &str = "amm_init_tip";
const SWAP: &str = "amm_swap_tip";
const RECEIPT_SWAP: &str = "amm_swap_tip_receipt";
/// The accounts the requests come from, which nothing may name.
const ALICE: u64 = 0x2a11_ce00_0000_0001;
const BOB: u64 = 0x2b0b_0000_0000_0002;

fn ns() -> Fr {
    Fr::from(TIP)
}

fn pool_slot() -> Fr {
    fr_from_hex(POOL).unwrap()
}

fn namespace() -> TipEntry {
    tip_namespace(ns(), POOL, &[INIT, SWAP, RECEIPT_SWAP], &[INIT])
}

/// A swap's app inputs: `inputs` (amount_in, direction, min_out), then the
/// partial note of the request with `nonce` (a stand-in for the contract's
/// commitment of the trader's address and `rho`, one per request).
fn with_partial_note(inputs: &[u64], nonce: u64) -> Vec<u64> {
    let mut all = inputs.to_vec();
    all.push(0x9a00_0000 + nonce);
    all
}

/// What `apply` reads of a result's public inputs.
struct Outcome {
    /// The chain request id the round computed in-circuit.
    chain_request_id: Fr,
    new_c: Fr,
    ok: bool,
    amount_out: u64,
}

fn outcome(w: &World, result: &ExecuteResponse) -> Outcome {
    let o = w.outputs(result);
    Outcome {
        chain_request_id: o.get("request_id"),
        new_c: o.get("new_c"),
        ok: o.ok(),
        amount_out: o.find("app.amount_out").map_or(0, small),
    }
}

/// The mock contract: the queue and the pool's slot, and every intake
/// argument and log field, for the requester audit.
struct Contract {
    chain: Chain,
    intake_args: Vec<Fr>,
}

impl Contract {
    /// On-chain intake by `user` (`msg_sender`, which the id and the log
    /// leave out) of the swap's `inputs` and the partial note of `nonce`
    /// (the init's none): the request log holds the app inputs and the
    /// nonce.
    fn intake_onchain(
        &mut self,
        clock: &Clock,
        user: u64,
        vk_hash: Fr,
        inputs: &[u64],
        nonce: u64,
    ) -> Fr {
        let _sender = user;
        let id = self.chain.intake(clock, vk_hash, inputs, nonce);
        self.intake_args.extend(frs(inputs));
        self.intake_args.extend([fr(nonce), id]);
        id
    }

    /// Receipt intake by `user` of the receipt swap's `inputs` and the
    /// partial note of `nonce`: the three receipts must verify under the
    /// pinned keys over the id and inputs_hash the contract recomputes, and
    /// the block must be before `expiry_block`; a seen id reverts; nothing
    /// is logged.
    fn intake_receipt(
        &mut self,
        clock: &Clock,
        user: u64,
        vk_hash: Fr,
        inputs: &[u64],
        nonce: u64,
        receipt: &ReceiptResponse,
    ) -> Result<Fr, String> {
        let _sender = user;
        let inputs = frs(&with_partial_note(inputs, nonce));
        let nonce = fr(nonce);
        let id = sidecar_tip::chain_request_id(ns(), vk_hash, &inputs, nonce);
        let ih = inputs_hash(&inputs);
        self.intake_args.extend(&inputs);
        self.intake_args
            .extend([nonce, id, ih, fr(u64::from(receipt.expiry_block))]);
        for (i, sig) in receipt.signatures.iter().enumerate() {
            if !verify_receipt(self.chain.sig_pks[i], *sig, id, ih, receipt.expiry_block) {
                return Err(format!("receipt {i} does not verify"));
            }
        }
        if clock.block >= u64::from(receipt.expiry_block) {
            return Err("receipt expired".into());
        }
        if self.chain.seen(id) {
            return Err("request already seen".into());
        }
        self.chain.append(clock, id);
        Ok(id)
    }
}

/// The relayer FETCHes the latest result of `chain` by chain request id;
/// its public inputs name no account.
async fn latest(w: &World, accounts: &Requesters, label: &str, chain: Fr) -> ExecuteResponse {
    let result = w.latest(label, chain).await;
    let pi: Vec<Fr> = result.public_inputs.iter().map(|f| f.fr()).collect();
    accounts.assert_call_args(label, &pi);
    result
}

/// FETCH the latest result for the head and land it.
async fn land(
    w: &World,
    accounts: &Requesters,
    clock: &Clock,
    contract: &mut Contract,
    label: &str,
) -> ExecuteResponse {
    let head = contract.chain.head_id().expect("a queued head");
    let result = latest(w, accounts, label, head).await;
    w.apply(clock, &mut contract.chain, &result)
        .unwrap_or_else(|e| panic!("{label}: apply reverts: {e}"));
    result
}

/// A receipt for a swap of `inputs` (amount_in, direction, min_out) with
/// the partial note of `nonce` at `block`, through the orchestrator's
/// route; the body and every node's row are audited.
async fn receipt(
    w: &World,
    accounts: &Requesters,
    block: u64,
    inputs: [u64; 3],
    nonce: u64,
) -> ReceiptResponse {
    let body = json!({
        "namespace": FieldHex(ns()),
        "circuit": RECEIPT_SWAP,
        "inputs": {
            "amount_in": FieldHex::from(inputs[0]),
            "direction": FieldHex::from(inputs[1]),
            "min_out": FieldHex::from(inputs[2]),
            "partial_note": FieldHex::from(with_partial_note(&inputs, nonce)[3]),
        },
        "user_nonce": FieldHex::from(nonce),
        "current_block": block,
    });
    accounts.assert_absent_in("receipt body", &body);
    let answer = w.orch.post_json("/v1/receipt", &body).await;
    let receipt: ReceiptResponse = answer
        .json::<ReceiptResponse>()
        .unwrap()
        .unwrap_or_else(|e| panic!("receipt: {e}"));
    let id = receipt.request_id.fr();
    accounts.assert_plain_id(
        id,
        ns(),
        w.vk(RECEIPT_SWAP),
        &frs(&with_partial_note(&inputs, nonce)),
        fr(nonce),
    );
    for (i, app) in w.real.apps.iter().enumerate() {
        let row = app
            .node
            .store
            .receipt(ns(), id)
            .unwrap()
            .unwrap_or_else(|| panic!("node {i} stored no receipt row"));
        accounts.assert_receipt_row(ns(), &row);
    }
    receipt
}

/// Whether node `i` still holds the receipt of `chain`.
fn has_receipt(w: &World, i: usize, chain: Fr) -> bool {
    w.real.apps[i]
        .node
        .store
        .receipt(ns(), chain)
        .unwrap()
        .is_some()
}

/// Run the pruning job at the three nodes; each answers (pruned, kept)
/// receipts.
async fn prune_receipts(w: &World) -> Vec<(usize, usize)> {
    w.prune()
        .await
        .into_iter()
        .enumerate()
        .map(|(i, answer)| {
            (
                answer
                    .pruned_receipts
                    .unwrap_or_else(|| panic!("node {i}: {:?}", answer.receipts_not_pruned)),
                answer.kept_receipts.unwrap(),
            )
        })
        .collect()
}

/// The request the scheduler would build for entry `index` (chain request
/// `chain`) of the receipt swap, its inputs and the partial note of `nonce`
/// as queued, on the pool version `on`.
fn synth_receipt(
    w: &World,
    (index, chain): (u64, Fr),
    inputs: &[u64],
    nonce: u64,
    on: Fr,
) -> Request {
    let namespace = namespace();
    let state = [KeyState {
        key: POOL.into(),
        commitment: on,
        record: None,
    }];
    let view = SynthesisView {
        namespace: ns(),
        entry: QueueEntry {
            index,
            chain_request_id: chain,
        },
        state_keys: &namespace.circuits[RECEIPT_SWAP],
        pinned: &PinnedValues::default(),
        state: &state,
        node_values: &PublicMap::new(),
    };
    let log = PlainFound::new(frs(&with_partial_note(inputs, nonce)), fr(nonce));
    synthesise(&view, &w.package(RECEIPT_SWAP), &log)
        .unwrap()
        .request
}

/// The hidden requester over everything every node received.
fn audit_received(w: &World, accounts: &Requesters) -> usize {
    let received = w.received.lock().unwrap();
    for (_, req) in received.iter() {
        assert!(
            req.get("requester").is_none_or(Value::is_null),
            "a queued request names a requester key: {req}"
        );
        accounts.assert_absent_in("a request a node received", req);
    }
    received.len()
}

/// Reserves after a swap of `amount_in` in `direction` (0: x for y) that
/// paid `out`.
fn after(pool: [u64; 2], amount_in: u64, direction: u64, out: u64) -> [u64; 2] {
    if direction == 0 {
        [pool[0] + amount_in, pool[1] - out]
    } else {
        [pool[0] - out, pool[1] + amount_in]
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn the_tip_network_runs_both_plain_intakes_and_prunes_receipts() {
    let tmp = TempDir::new("tipnet");
    let mem = Arc::new(MemoryChain::new(100));
    let w = setup(
        &tmp,
        &mem,
        &namespace(),
        vec![
            Package::new(INIT, manifest("amm-tip", INIT)),
            Package::new(SWAP, manifest("amm-tip", SWAP)),
            Package::on(RECEIPT_SWAP, SWAP, manifest("amm-tip", RECEIPT_SWAP)),
        ],
    )
    .await;
    let accounts = Requesters::new([fr(ALICE), fr(BOB)]);
    let started = Instant::now();
    let mut clock = Clock::new(100, mem.clone());
    let mut contract = Contract {
        chain: Chain::new(&clock, ns(), pool_slot(), w.sig_pks),
        intake_args: vec![],
    };
    let mut s = scheduler(&w, &mem, &namespace());
    let (init_vk, swap_vk, receipt_vk) = (w.vk(INIT), w.vk(SWAP), w.vk(RECEIPT_SWAP));

    // ---- both non-secret-shared intakes, in queue order --------------------------------
    // the init round's request id takes no inputs and nonce 0
    let c0 = contract.intake_onchain(&clock, ALICE, init_vk, &[], 0);
    let r1 = receipt(&w, &accounts, clock.block, [1000, 0, 1], 2).await;
    let c1 = contract
        .intake_receipt(&clock, ALICE, receipt_vk, &[1000, 0, 1], 2, &r1)
        .unwrap();
    assert_eq!(c1, r1.request_id.fr(), "the contract's id is the nodes'");
    let swap2 = with_partial_note(&[500, 1, 1], 3);
    let c2 = contract.intake_onchain(&clock, BOB, swap_vk, &swap2, 3);
    accounts.assert_plain_id(c2, ns(), swap_vk, &frs(&swap2), fr(3));
    let r3 = receipt(&w, &accounts, clock.block, [300, 0, 1], 4).await;
    let c3 = contract
        .intake_receipt(&clock, BOB, receipt_vk, &[300, 0, 1], 4, &r3)
        .unwrap();
    // the same receipt twice: the id is seen
    assert!(
        contract
            .intake_receipt(&clock, BOB, receipt_vk, &[300, 0, 1], 4, &r3)
            .is_err()
    );

    let r = step(&mut s, clock.next(), "the head and one pipelined").await;
    assert!(r.reloaded && r.error.is_none(), "{r:?}");
    assert_eq!(computed(&r), [0, 1], "the head and one pipelined entry");
    let (v0, v1) = (new_c(&r, 0), new_c(&r, 1));
    assert_eq!(
        attempt(&r, 1).old[POOL],
        v0,
        "pipelined on the head's version"
    );
    assert!(w.has_row(c0) && w.has_row(c1));
    assert!(
        !w.has_row(c2) && !w.has_row(c3),
        "an entry outside the head window was computed"
    );
    assert_eq!(w.verified.load(Ordering::SeqCst), 6);
    let r = step(&mut s, clock.next(), "nothing new").await;
    assert!(
        !r.reloaded && computed(&r).is_empty() && r.error.is_none(),
        "{r:?}"
    );

    let init = land(&w, &accounts, &clock, &mut contract, "init").await;
    assert_eq!(outcome(&w, &init).new_c, v0);
    let r = step(&mut s, clock.next(), "entry 2 on entry 1's attempt").await;
    assert!(!r.reloaded, "{r:?}");
    assert_eq!(computed(&r), [2]);
    let v2 = new_c(&r, 2);
    assert_eq!(attempt(&r, 2).old[POOL], v1);
    assert!(!w.has_row(c3));
    let swap1 = land(&w, &accounts, &clock, &mut contract, "swap 1 (receipt)").await;
    let r = step(&mut s, clock.next(), "entry 3 on entry 2's attempt").await;
    assert_eq!(computed(&r), [3]);
    let v3 = new_c(&r, 3);
    let swap2 = land(&w, &accounts, &clock, &mut contract, "swap 2 (on-chain)").await;
    let swap3 = land(&w, &accounts, &clock, &mut contract, "swap 3 (receipt)").await;
    assert_eq!(contract.chain.slot, v3);
    let (o1, o2, o3) = (
        outcome(&w, &swap1),
        outcome(&w, &swap2),
        outcome(&w, &swap3),
    );
    assert_eq!(
        [
            o1.chain_request_id,
            o2.chain_request_id,
            o3.chain_request_id
        ],
        [c1, c2, c3]
    );
    assert!(o1.ok && o2.ok && o3.ok);
    let pool0 = w.reserves(v0);
    let pool1 = after(pool0, 1000, 0, o1.amount_out);
    let pool2 = after(pool1, 500, 1, o2.amount_out);
    let pool3 = after(pool2, 300, 0, o3.amount_out);
    assert_eq!([v1, v2, v3].map(|v| w.reserves(v)), [pool1, pool2, pool3]);
    assert_eq!([v1, v2, v3].map(|v| w.version(v).parent), [v0, v1, v2]);
    eprintln!(
        "NON-SECRET-SHARED INTAKES: pool {pool0:?} -> {pool3:?} ({:.1}s)",
        started.elapsed().as_secs_f64()
    );

    // ---- the chain verifier holds a receipt-intake request to its receipt ----
    let r4 = receipt(&w, &accounts, clock.block, [200, 1, 1], 5).await;
    let c4 = contract
        .intake_receipt(&clock, ALICE, receipt_vk, &[200, 1, 1], 5, &r4)
        .unwrap();
    let mut other = synth_receipt(&w, (4, c4), &[200, 1, 1], 5, v3);
    other
        .public
        .insert("amount_in".into(), PublicValue::One(FieldHex::from(201)));
    w.refused(
        "an input the receipt does not hold",
        &other,
        &["field `public.amount_in`", "the queued request's input"],
    )
    .await;
    let r = step(&mut s, clock.next(), "entry 4").await;
    assert_eq!(computed(&r), [4], "{r:?}");
    assert_eq!(attempt(&r, 4).old[POOL], v3);
    let swap4 = land(&w, &accounts, &clock, &mut contract, "swap 4 (receipt)").await;
    assert!(outcome(&w, &swap4).ok);

    // ---- receipts: expiry at intake, and the pruning rule ---------------------
    let never = receipt(&w, &accounts, clock.block, [10, 0, 1], 6).await;
    let r5 = receipt(&w, &accounts, clock.block, [20, 0, 1], 7).await;
    let c5 = contract
        .intake_receipt(&clock, BOB, receipt_vk, &[20, 0, 1], 7, &r5)
        .unwrap();
    // a receipt at its expiry is refused at intake
    let expiry = u64::from(never.expiry_block);
    clock.later(expiry - clock.block);
    assert_eq!(
        contract.intake_receipt(&clock, ALICE, receipt_vk, &[10, 0, 1], 6, &never),
        Err("receipt expired".into())
    );
    assert!(!contract.chain.seen(never.request_id.fr()));
    // inside every window nothing is pruned
    let done = [c1, c3, c4];
    assert_eq!(prune_receipts(&w).await, [(0, 0); 3]);
    // past expiry + stale_blocks at the settled block: the never-queued and
    // the done receipts go, the queued head's stays
    clock.later(expiry + STALE_BLOCKS + 1 - clock.block);
    w.settle(&mut clock);
    let pruned = prune_receipts(&w).await;
    assert_eq!(pruned, [(1 + done.len(), 1); 3]);
    for i in 0..3 {
        assert!(!has_receipt(&w, i, never.request_id.fr()), "node {i}");
        assert!(
            has_receipt(&w, i, c5),
            "node {i}: a queued receipt was pruned"
        );
        for c in done {
            assert!(!has_receipt(&w, i, c), "node {i}: a done receipt was kept");
        }
    }
    // the head is skipped: its receipt is done, pruned once the settled
    // block passes the skip
    contract.chain.skip(&clock);
    w.settle(&mut clock);
    let pruned = prune_receipts(&w).await;
    assert!(pruned.iter().all(|p| *p == (1, 0)), "{pruned:?}");
    assert!((0..3).all(|i| !has_receipt(&w, i, c5)));

    // ---- the hidden requester -------------------------------------------------
    accounts.assert_call_args("intake arguments and request logs", &contract.intake_args);
    let audited = audit_received(&w, &accounts);
    assert!(audited > 0);
    eprintln!(
        "TIP NETWORK: {audited} node requests audited, {:.1}s in all",
        started.elapsed().as_secs_f64()
    );
}
