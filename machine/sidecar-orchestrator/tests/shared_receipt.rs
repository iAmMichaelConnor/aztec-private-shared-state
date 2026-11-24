//! Secret-shared receipt intake at the tip over three real nodes with real MPC
//! proofs (docs/ARCHITECTURE.md section 6, "Secret-shared receipt intake, end to
//! end"): the client seals a Rep3 sharing of every shared value to each
//! node under the intake associated data and asks the orchestrator's
//! receipt route for the three receipts over the inputs commitment C; the
//! mock contract checks them and queues the chain request id; the scheduler
//! reads the three nodes' stored rows, synthesises the request with every
//! node's envelopes, and each node's chain verifier rebuilds its own
//! projection from its own row. The rounds are the machine's queued test
//! counter (machine/circuits): `tip_counter_init` under on-chain intake
//! writes the counter, a node-held key, and `tip_counter_shared` adds a
//! shared amount to it. Both packages register in one namespace before the
//! init round: the init reads no key, so it sits beside the secret-shared round.
//!
//! - Two secret-shared requests are computed in queue order, the second pipelined
//!   on the first's version; the request each node receives carries in
//!   `public` only `$vk_hash` and `$inputs_hash` = C, and of every shared
//!   input its own envelope, the one it stored; no amount appears in the
//!   clear in a receipt body, a stored row or a received request; the
//!   counter's versions open to the start plus the amounts.
//! - A sharing that does not open C gets receipts but is refused by the
//!   request function, so it never reaches the queue; shares the nodes
//!   change after an honest intake run as an `ok = false` round: its new
//!   commitment is the old one, and the queue moves on.
//! - A request with one node's envelope swapped for another of its
//!   envelopes, with its share hash, is refused (400) by the chain
//!   verifiers with nothing stored; so is one with another C.
//! - A request whose pairs disagree between neighbours (each envelope well
//!   formed) gets no receipt: the node whose pair misses a summand
//!   commitment refuses it (400 naming `summand_commitments[j]`), so it
//!   never reaches the queue or a session handshake.
//!
//! Needs `scripts/prepare-data.sh` (the machine's circuits and the CRS under
//! machine/data, or DATA_DIR); the test fails naming the missing files if
//! they are absent, so a passing run proves it ran. Run with `--release`.

mod common;
mod shared_intake;

use std::sync::Arc;
use std::time::Instant;

use common::tip::*;
use common::*;
use serde_json::{Value, json};
use shared_intake::*;

use sidecar_core::bind::Elem;
use sidecar_core::field::{FieldHex, Fr, fr_from_hex};
use sidecar_core::request::{PublicValue, Request};
use sidecar_core::store::{Store, StoreRead};
use sidecar_tip::testing::MemoryChain;
use sidecar_tip::{
    KeyState, PinnedValues, PublicMap, QueueEntry, SharedReceiptFound, SynthesisView, synthesise,
};

const TIP: u64 = 0x7198;
// the slot as the contract manifest writes it (fr_to_hex)
const COUNTER: &str = "0x0000000000000000000000000000000000000000000000000000000000007c02";
const INIT: &str = "tip_counter_init";
const SHARED: &str = "tip_counter_shared";
const CIRCUITS: [&str; 3] = ["pss_seed", INIT, SHARED];
/// The counter's first value.
const START: u64 = 5;

fn ns() -> Fr {
    Fr::from(TIP)
}

fn counter_slot() -> Fr {
    fr_from_hex(COUNTER).unwrap()
}

fn init_manifest() -> Value {
    json!({
        "manifest": 1,
        "circuit": INIT,
        "namespace_param": "namespace",
        "state_keys": {"reads": 0, "writes": 1},
        "intake": "onchain",
        "outcome": "none",
        "witness": [
            {"param": "namespace", "from": {"PUBLIC": "$namespace"}},
            {"param": "vk_hash", "from": {"PUBLIC": "$vk_hash"}},
            {"param": "out_slots", "from": {"PUBLIC": ["$state_keys.writes[0]"]}},
            {"param": "start", "from": {"PUBLIC": "start"}},
            {"param": "r_new", "from": {"SAMPLE": 1}}
        ],
        "outputs": [
            {"TACEO_store": "out0", "STORE": "$state_keys.writes[0]", "len": 2, "note_hash": "new_c"}
        ],
        "state": {"$state_keys.writes[0]": "node"}
    })
}

/// `tip_counter_shared` (machine/circuits): the amount and the reserved
/// shared values INPUT_SHARED (the partial note among them, which the round
/// binds through C and completes no note for), C by PUBLIC `$inputs_hash`,
/// the counter node-held, under the default `outcome: partial`.
fn shared_manifest() -> Value {
    json!({
        "manifest": 1,
        "circuit": SHARED,
        "namespace_param": "namespace",
        "state_keys": {"reads": 1, "writes": 1},
        "intake": "shared_receipt",
        "binding": "turn",
        "witness": [
            {"param": "namespace", "from": {"PUBLIC": "$namespace"}},
            {"param": "vk_hash", "from": {"PUBLIC": "$vk_hash"}},
            {"param": "in_slots", "from": {"PUBLIC": ["$state_keys.reads[0]"]}},
            {"param": "out_slots", "from": {"PUBLIC": ["$state_keys.writes[0]"]}},
            {"param": "inputs_hash", "from": {"PUBLIC": "$inputs_hash"}},
            {"param": "amount", "from": {"INPUT_SHARED": "amount"}},
            {"param": "partial_note", "from": {"INPUT_SHARED": "$partial_note"}},
            {"param": "outcome_key", "from": {"INPUT_SHARED": "$outcome_key"}},
            {"param": "blinding", "from": {"INPUT_SHARED": "$blinding"}},
            {"param": "outcome_tag", "from": {"INPUT_SHARED": "$outcome_tag"}},
            {"param": "value", "from": {"LOAD": "$state_keys.reads[0]", "slice": [0, 1], "len": 2}},
            {"param": "r_old", "from": {"LOAD": "$state_keys.reads[0]", "slice": [1, 2], "len": 2}},
            {"param": "r_new", "from": {"SAMPLE": 1}}
        ],
        "outputs": [
            {"TACEO_store": "out0", "STORE": "$state_keys.writes[0]", "len": 2, "note_hash": "new_c"}
        ],
        "state": {"$state_keys.reads[0]": "node", "$state_keys.writes[0]": "node"},
        "commitment_slot": {"$state_keys.reads[0]": {"old": "old_c"}},
        "public_reads": []
    })
}

fn namespace() -> TipEntry {
    tip_namespace(ns(), COUNTER, &[INIT, SHARED], &[INIT])
}

// ---------------------------------------------------------------------------
// The client
// ---------------------------------------------------------------------------

/// The counter's shared inputs: the amount, then a partial note.
fn counter_inputs(amount: u64) -> Vec<Input> {
    vec![
        shared("amount", Fr::from(amount)),
        shared("$partial_note", random()),
    ]
}

/// A secret-shared request adding `amount`; the shares of `amount` reconstruct to
/// `amount + skew` (0 for an honest client). Sealed in the circuit's ABI
/// order, which puts `$blinding` before `$outcome_tag`.
fn counter_request(net: &Net, vk_hash: Fr, amount: u64, skew: u64) -> SharedRequest {
    SharedRequest::skewed(
        ns(),
        SHARED,
        vk_hash,
        &net.enc_pks,
        counter_inputs(amount),
        (skew != 0).then_some(("amount", skew)),
    )
    .in_abi_order(&net.package(ns(), SHARED))
}

/// The amount of `req` as the audit looks for it.
fn hidden(req: &SharedRequest) -> Hidden {
    Hidden {
        values: req.hidden(),
        ..Hidden::default()
    }
}

/// The three receipts of `req`, through the orchestrator's route (each node
/// stored its own envelopes and no amount in the clear), and no node stored
/// a clear input: the counter takes none.
async fn receipt(net: &Net, clock: &Clock, req: &SharedRequest) -> sidecar_tip::ReceiptResponse {
    let receipt = net.receipt(clock.block, req, &hidden(req)).await;
    for (i, app) in net.real.apps.iter().enumerate() {
        let row = app.node.store.receipt(ns(), req.chain).unwrap().unwrap();
        assert!(row.inputs.is_empty(), "node {i} stored a clear input");
    }
    receipt
}

/// The counter's value in the version under `commitment`, opened from the
/// three nodes' pairs.
fn value(net: &Net, commitment: Fr) -> u64 {
    let parts: Vec<Elem> = (0..3)
        .map(|i| {
            net.real.apps[i]
                .node
                .store
                .tip_version(ns(), COUNTER, commitment)
                .unwrap()
                .expect("the version is held")
                .vec[0]
                .clone()
        })
        .collect();
    match [&parts[0], &parts[1], &parts[2]] {
        [Elem::Shared(a), Elem::Shared(b), Elem::Shared(c)] => small(a.a + b.a + c.a),
        // the init's public start
        [Elem::Public(a), Elem::Public(b), Elem::Public(c)] if a == b && b == c => small(*a),
        other => panic!("the nodes disagree on the counter: {other:?}"),
    }
}

/// The request the scheduler would build for `req` at queue index `index`,
/// on the counter's commitment `on`.
fn synth(net: &Net, req: &SharedRequest, index: u64, on: Fr) -> Request {
    let namespace = namespace();
    let state = [KeyState {
        key: COUNTER.into(),
        commitment: on,
        record: None,
    }];
    let view = SynthesisView {
        namespace: ns(),
        entry: QueueEntry {
            index,
            chain_request_id: req.chain,
        },
        state_keys: &namespace.circuits[SHARED],
        pinned: &PinnedValues::default(),
        state: &state,
        node_values: &PublicMap::new(),
    };
    let inputs = SharedReceiptFound::new(vec![], req.c, req.sealed.clone());
    synthesise(&view, &net.package(ns(), SHARED), &inputs)
        .unwrap()
        .request
}

/// Every request a node received for `req`: `public` holds only
/// `$vk_hash` and C, no requester, no amount, and node i's own envelope of
/// each shared input. How many there were.
fn audit_received(net: &Net, req: &SharedRequest) -> usize {
    for (_, r) in net.received_for(req.chain) {
        let public: Vec<&String> = r["public"].as_object().unwrap().keys().collect();
        assert_eq!(public, ["inputs_hash", "vk_hash"], "{r}");
    }
    net.audit_received(req, &hidden(req))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn shared_receipt_rounds_run_on_the_nodes_stored_envelopes() {
    let tmp = TempDir::new("sharedrx");
    let mem = Arc::new(MemoryChain::new(100));
    let net = start(&tmp, mem.clone(), &CIRCUITS, &[namespace()]).await;
    let vk = net
        .register_entry(
            &namespace(),
            &[
                (INIT, INIT, init_manifest()),
                (SHARED, SHARED, shared_manifest()),
            ],
        )
        .await;
    let (init_vk, shared_vk) = (vk[INIT], vk[SHARED]);
    let started = Instant::now();
    let mut clock = Clock::new(100, mem.clone());
    let mut chain = Chain::new(&clock, ns(), counter_slot(), net.sig_pks);
    let mut s = scheduler(&net, &mem, &namespace());

    // ---- the init round, beside the secret-shared package --------------------------
    // the init round's request id takes nonce 0
    let c0 = chain.intake_onchain(&clock, init_vk, &[Fr::from(START)], 0);
    let r = step(&mut s, clock.next(), "the init").await;
    assert_eq!(computed(&r), [0], "{r:?}");
    let v0 = new_c(&r, 0);
    let init = net.land(&clock, &mut chain, "init").await;
    let o = net.outputs(ns(), &init);
    assert_eq!((o.get("request_id"), o.get("new_c")), (c0, v0));
    assert_eq!(value(&net, v0), START);
    net.received.lock().unwrap().clear();

    // ---- two secret-shared requests, the second pipelined on the first ------------
    let (a1, a2) = (0x51a7_e001_u64, 0x51a7_e002_u64);
    let q1 = counter_request(&net, shared_vk, a1, 0);
    let rx = receipt(&net, &clock, &q1).await;
    let c1 = chain.intake_shared(&clock, shared_vk, &q1, &rx, &hidden(&q1));
    assert_eq!(c1, q1.chain);

    // a node's envelope swapped for another of its own, with its hash, and
    // another C: every chain verifier refuses before anything is stored
    let honest = synth(&net, &q1, 1, v0);
    let mut swapped = honest.clone();
    swapped.shared_inputs.swap(0, 1);
    let names = (
        swapped.shared_inputs[0].name.clone(),
        swapped.shared_inputs[1].name.clone(),
    );
    swapped.shared_inputs[0].name = names.1;
    swapped.shared_inputs[1].name = names.0;
    net.refused("swapped envelopes", &swapped, &["field `shared_inputs[0]`"])
        .await;
    let mut other_c = honest.clone();
    other_c.public.insert(
        "inputs_hash".into(),
        PublicValue::One(FieldHex(Fr::from(1u64))),
    );
    net.refused("another C", &other_c, &["field `public.inputs_hash`"])
        .await;
    net.received.lock().unwrap().clear();

    let q2 = counter_request(&net, shared_vk, a2, 0);
    let rx = receipt(&net, &clock, &q2).await;
    let c2 = chain.intake_shared(&clock, shared_vk, &q2, &rx, &hidden(&q2));
    assert_eq!(c2, q2.chain);

    let r = step(&mut s, clock.next(), "two secret-shared requests").await;
    assert!(r.error.is_none(), "{r:?}");
    assert_eq!(computed(&r), [1, 2], "the head and one pipelined entry");
    let (v1, v2) = (new_c(&r, 1), new_c(&r, 2));
    assert_eq!(r.computed[0].request_id, honest.request_id);
    // node i received its projection: `$vk_hash` and C in `public`, its own
    // envelope of each shared input, no requester, no amount
    assert_eq!(
        audit_received(&net, &q1) + audit_received(&net, &q2),
        6,
        "each node verified both requests"
    );

    // ---- shares that do not reconstruct to C: an ok = false round ----------
    // a client's sharing of 7 + 1 gets receipts (each node's envelopes match
    // the summand commitments) but never reaches the queue: the request
    // function refuses a sharing that does not open C
    let lying = counter_request(&net, shared_vk, 7, 1);
    let _ = receipt(&net, &clock, &lying).await;
    assert!(!lying.sharing.opens(), "the request function refuses it");
    // so only nodes that change their shares after an honest intake make
    // such a round: it lands as a no-op with the mismatch code
    let honest3 = counter_request(&net, shared_vk, 7, 0);
    let rx = receipt(&net, &clock, &honest3).await;
    let c3 = chain.intake_shared(&clock, shared_vk, &honest3, &rx, &hidden(&honest3));
    let q3 = honest3.reshared(&net.enc_pks, ("amount", 1), &net.package(ns(), SHARED));
    net.change_shares(&honest3, &q3);
    net.land(&clock, &mut chain, "shared 1").await;
    let r = step(&mut s, clock.next(), "the mismatch, pipelined").await;
    assert_eq!(computed(&r), [3], "{r:?}");
    let v3 = new_c(&r, 3);
    assert_eq!(v3, v2, "a mismatched C keeps the counter");
    net.land(&clock, &mut chain, "shared 2").await;
    let mismatch = net.land(&clock, &mut chain, "the mismatch").await;
    assert_eq!(net.outputs(ns(), &mismatch).get("request_id"), c3);
    assert_eq!(chain.slot, v2);
    assert_eq!(chain.head, 4);
    assert_eq!(
        [value(&net, v1), value(&net, v2)],
        [START + a1, START + a1 + a2]
    );

    // ---- pairs that disagree between neighbours: no receipt -----------------
    // node 2's pair of the amount does not share its b summand with node 1's
    // a: every envelope opens and hashes correctly, but node 2's b summands
    // miss the summand commitment S_1, which node 1 checked its a summands
    // against, so node 2 refuses and the request gets no receipt; it never
    // reaches the queue, so no handshake ever refuses it
    let q4 = SharedRequest::inconsistent(
        ns(),
        SHARED,
        shared_vk,
        &net.enc_pks,
        counter_inputs(0x51a7_e004),
        2,
        "amount",
    )
    .in_abi_order(&net.package(ns(), SHARED));
    net.receipt_refused(
        clock.block,
        &q4,
        "field `summand_commitments[1]`: the summands and salt node 2's envelopes open to do not hash to it",
    )
    .await;
    let r = step(&mut s, clock.next(), "after the refused receipt").await;
    assert!(r.computed.is_empty() && r.error.is_none(), "{r:?}");
    assert_eq!(chain.head as usize, chain.ids.len(), "nothing was queued");
    eprintln!(
        "secret-shared receipt intake: {:.1}s",
        started.elapsed().as_secs_f64()
    );
}
