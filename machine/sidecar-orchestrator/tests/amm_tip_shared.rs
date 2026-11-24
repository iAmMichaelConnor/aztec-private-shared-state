//! The AMM tip's swap under secret-shared receipt intake, in process over three
//! real nodes with real MPC proofs (docs/ARCHITECTURE.md section 6, "Secret-shared
//! intake", "Private outcomes" and "Node-held state"): examples/amm-tip's
//! `amm_init_tip` and the swap round's secret-shared receipt intake entry
//! `amm_swap_tip_shared` (partial-note delivery), their manifests and compiled
//! circuits as committed, the pool node-held. Each request goes receipt ->
//! head -> round -> result: the client seals every shared value to the
//! nodes and takes the three receipts over C through the orchestrator's
//! receipt route; the mock contract checks them and queues the chain
//! request id; the scheduler synthesises the head's request from the three
//! nodes' stored rows; each node's chain verifier rebuilds its projection
//! from its own row; the relayer fetches the result and the mock `apply`
//! checks the head, the slot and the three result signatures and writes the
//! new commitment.
//!
//! - The audit: no shared app input (`amount_in`, `min_out`, the
//!   `$partial_note`) and no requester address (the partial note's owner)
//!   appears in a receipt body's clear inputs, a node's receipts row, the
//!   synthesised request's public map, a request a node receives, the
//!   intake's public call or the proof's public inputs: no amount and no
//!   recipient reaches the nodes, the orchestrator or the relayer.
//! - The outcome ciphertext opens under `$outcome_key` with the nonce of
//!   the completed note's hash, which the log carries, to `[code,
//!   amount_out]`, and the note hash is the completion of
//!   the request's partial note with them and the chain request id, the
//!   note the user rebuilds; the pool's new version opens to the reserves
//!   the outcome gives.
//! - A failed swap (an output below `min_out`, code 8) still writes a new
//!   commitment, different from the old one, and creates a version holding
//!   the same reserves; its note carries 0.
//! - Shares that do not open to C give code 9 inside the outcome, and the
//!   round commits and lands like any other.
//! - A request in which one node's envelope is substituted (a well-formed
//!   envelope of another pair, with its share hash) is refused (400) with
//!   nothing stored.
//! - A recompute: the head is skipped before its result lands, the swap
//!   pipelined on it is recomputed on the slot's canonical version, from
//!   the same stored envelopes, under a new machine request id. Each
//!   attempt is sealed under its own note hash's nonce: equal plaintexts give
//!   one note hash and one ciphertext; different ones give different nonces,
//!   the first does not open under the second's, and their difference is not
//!   the difference of their plaintexts. The skipped attempts' versions turn
//!   orphan and the pruning job deletes them once the settled block
//!   passes them.
//! - A partial note of an owner that is no account's address (the field
//!   p - 1): the round runs and lands like any other and completes that
//!   partial note; the machine never sees the owner and never interprets
//!   the partial note.
//! - An enc key rotation while a secret-shared receipt request is queued: node 1
//!   rotates after it signed two receipts; the queued one is served under
//!   its previous key inside the grace window, and the receipt route refuses
//!   a new envelope to the previous key. Past the window the previous key is
//!   held while the second request (queued late, its envelope to node 1
//!   opening only under the previous key) may still reach the head, so its
//!   round lands; once the head has passed it nothing holds the key.
//! - Beside it, in a namespace of its own (REGISTER keeps one intake family
//!   per namespace), the non-secret-shared swap under on-chain intake: a failed swap's
//!   new commitment is its old one and it creates no version (the
//!   equal-commitment rule), where the secret-shared swap's failure creates one.
//!
//!
//! The same swap under secret-shared on-chain intake (`amm_swap_tip_shared_onchain`,
//! the secret-shared swap's compiled circuit registered a second time), on a
//! network of its own: each node signs its current `enc` key into the
//! contract at epoch 1 (`rotate_into`, the scalar pending), the contract
//! stores the signed keys and each node records its scalar on seeing them;
//! the user's private function encodes the swap under the keys at its anchor
//! into one private log whose hash the contract stores beside the queue
//! entry; the scheduler and every node's chain verifier read the log by its
//! siloed tag and its stored hash, and each node derives its pairs with its
//! scalar of the epoch the log names.
//!
//! - A swap proven against an anchor older than a rotation (its log names
//!   epoch 1 for node 1 after node 1's epoch 2 landed, the previous `enc`
//!   key's grace window ended) is still served: node 1 keeps epoch 1's
//!   scalar for this contract. Beside it a swap under node 1's new key.
//!   Both are computed and applied, their outcomes opened by their users.
//! - The audit: no shared app input and no requester address in the public
//!   call, the private log, a request a node receives (its public map and
//!   `shared_log`) or the proof's public inputs.
//! - A request whose `shared_log` differs from the log on chain in one
//!   correction is refused (400) by the chain verifiers, with nothing
//!   stored.
//!
//! Needs `scripts/prepare-data.sh` (examples/amm-tip's circuits and the CRS
//! under machine/data, or DATA_DIR); the test fails naming the missing files
//! if they are absent, so a passing run proves it ran. Run with `--release`.

mod common;
mod shared_intake;

use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use common::tip::*;
use common::*;
use rand::rngs::OsRng;
use serde_json::Value;
use shared_intake::*;

use sidecar_core::field::{Fr, fr_from_hex};
use sidecar_core::keys::random_scalar;
use sidecar_core::request::Request;
use sidecar_core::response::ExecuteResponse;
use sidecar_core::store::VersionStatus;
use sidecar_node::rotation::held_by_queued_receipts;
use sidecar_orchestrator::scheduler::{InitStep, Scheduler};
use sidecar_tip::testing::MemoryChain;
use sidecar_tip::{
    KeyState, PinnedValues, PublicMap, QueueEntry, SharedReceiptFound, SynthesisView,
    chain_request_id, machine_request_id, synthesise,
};

/// The secret-shared swap's namespace, and the non-secret-shared swap's beside it.
const SHARED_NS: u64 = 0x7a5a;
const PLAIN_NS: u64 = 0x7a50;
// the slot as the contract manifest writes it (fr_to_hex)
const POOL: &str = "0x000000000000000000000000000000000000000000000000000000000000a003";
/// Where the mock contract keeps `Configured.configured`.
const CONFIGURED_SLOT: u64 = 0x20;
const INIT: &str = "amm_init_tip";
const SWAP: &str = "amm_swap_tip";
const SHARED: &str = "amm_swap_tip_shared";
/// The secret-shared swap under secret-shared on-chain intake: the same compiled circuit.
const SHARED_ONCHAIN: &str = "amm_swap_tip_shared_onchain";
const CIRCUITS: [&str; 4] = ["pss_seed", INIT, SWAP, SHARED];
/// amm_tip's `OUTCOME_SLOT`, the contract's swap notes.
const OUTCOME_SLOT: u64 = 1;
/// The public parameters before the outputs, and the ciphertext's length
/// (`[code, amount_out]` and the tag).
const PARAMS: usize = 4;
const CIPHERTEXT: usize = 3;
const CODE_MIN_OUT: u64 = 8;
const CODE_INPUTS_MISMATCH: u64 = 9;

fn shared_ns() -> Fr {
    Fr::from(SHARED_NS)
}

fn plain_ns() -> Fr {
    Fr::from(PLAIN_NS)
}

fn pool_slot() -> Fr {
    fr_from_hex(POOL).unwrap()
}

/// The pool's namespace `ns`, its init round sent by the scheduler once
/// configured.
fn namespace(ns: Fr, swap: &str) -> TipEntry {
    TipEntry {
        init: Some(tip_init(INIT, CONFIGURED_SLOT, &[])),
        ..tip_namespace(ns, POOL, &[INIT, swap], &[INIT])
    }
}

/// `configure` lands: the flag.
fn configure(chain: &Chain) {
    chain
        .mem
        .set_storage(chain.ns, Fr::from(CONFIGURED_SLOT), Fr::from(1u64));
}

/// A secret-shared swap of `amount_in` in `direction` with `min_out`,
/// committing `owner`'s partial note under a fresh `rho`, in C's order.
fn swap(
    net: &Net,
    vk: Fr,
    amount_in: u64,
    direction: u64,
    min_out: u64,
    owner: Fr,
    skew: Option<(&str, u64)>,
) -> SharedRequest {
    SharedRequest::skewed(
        shared_ns(),
        SHARED,
        vk,
        &net.enc_pks,
        vec![
            shared("amount_in", fr(amount_in)),
            shared("direction", fr(direction)),
            shared("min_out", fr(min_out)),
            shared("$partial_note", partial_commitment(owner, random())),
        ],
        skew,
    )
    .owned_by(owner)
}

/// The reserves a swap of `amount_in` in `direction` paying `out` leaves.
fn after(pool: [u64; 2], amount_in: u64, direction: u64, out: u64) -> [u64; 2] {
    if direction == 0 {
        [pool[0] + amount_in, pool[1] - out]
    } else {
        [pool[0] - out, pool[1] + amount_in]
    }
}

/// The secret-shared swap's outputs, opened as the user opens them: the outcome
/// `[code, amount_out]`, the note hash the completion of the request's
/// partial note, and nothing after the ciphertext.
fn opened(req: &SharedRequest, result: &ExecuteResponse) -> (PrivateOutputs, [u64; 2]) {
    let out = private_outputs(result, PARAMS, 0, CIPHERTEXT);
    let plain = req.open(&out, fr(OUTCOME_SLOT), &[]);
    assert_eq!(plain.len(), 2);
    (out, [small(plain[0]), small(plain[1])])
}

/// The proof's public inputs.
fn public_inputs(result: &ExecuteResponse) -> Vec<Fr> {
    result.public_inputs.iter().map(|f| f.fr()).collect()
}

/// The relayer lands `req`'s latest result: apply writes the new
/// commitment whatever the outcome.
async fn land(
    net: &Net,
    clock: &Clock,
    chain: &mut Chain,
    req: &SharedRequest,
    hidden: &Hidden,
) -> (PrivateOutputs, [u64; 2]) {
    let result = net.latest(shared_ns(), req.chain).await;
    hidden.assert_absent("the proof's public inputs", &public_inputs(&result));
    let (out, o) = opened(req, &result);
    chain
        .apply(clock, &result, out.request_id, out.old_c, out.new_c, true)
        .unwrap_or_else(|e| panic!("apply: {e}"));
    (out, o)
}

/// The request the scheduler would build for `req` at queue index `index`
/// on the pool's commitment `on`.
fn synth(net: &Net, req: &SharedRequest, index: u64, on: Fr) -> Request {
    let namespace = namespace(shared_ns(), SHARED);
    let state = [KeyState {
        key: POOL.into(),
        commitment: on,
        record: None,
    }];
    let view = SynthesisView {
        namespace: shared_ns(),
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
    synthesise(&view, &net.package(shared_ns(), SHARED), &inputs)
        .unwrap()
        .request
}

/// The init round of `chain`'s namespace, sent by the scheduler once
/// configured and landed by the relayer: the pool's first commitment.
async fn init(
    net: &Net,
    clock: &mut Clock,
    chain: &mut Chain,
    s: &mut Scheduler<Arc<MemoryChain>>,
    init_vk: Fr,
) -> Fr {
    configure(chain);
    let id = chain_request_id(chain.ns, init_vk, &[], Fr::from(0u64));
    let r = step(s, clock.next(), "configured").await;
    assert_eq!(r.error, None, "{r:?}");
    let Some(InitStep::Sent(attempt)) = &r.init else {
        panic!("no init round sent: {:?}", r.init);
    };
    let v0 = attempt.new[0].commitment;
    let landed = net.latest(chain.ns, id).await;
    assert_eq!(net.outputs(chain.ns, &landed).get("new_c"), v0);
    chain.init(v0);
    v0
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[test]
fn the_outcome_opener_agrees_with_the_vectors() {
    check_outcome_vectors();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn the_amm_shared_swap_runs_receipt_to_result_on_three_nodes() {
    let tmp = TempDir::new("ammshared");
    let mem = Arc::new(MemoryChain::new(100));
    let net = start(
        &tmp,
        mem.clone(),
        &CIRCUITS,
        &[namespace(shared_ns(), SHARED), namespace(plain_ns(), SWAP)],
    )
    .await;
    let started = Instant::now();
    let mut clock = Clock::new(100, mem.clone());
    let mut chain = Chain::new(&clock, shared_ns(), pool_slot(), net.sig_pks);
    let mut plain = Chain::new(&clock, plain_ns(), pool_slot(), net.sig_pks);
    for (ns, swap) in [(shared_ns(), SHARED), (plain_ns(), SWAP)] {
        net.register_entry(
            &namespace(ns, swap),
            &[
                (INIT, INIT, manifest("amm-tip", INIT)),
                (swap, swap, manifest("amm-tip", swap)),
            ],
        )
        .await;
    }
    let init_vk = net.package(shared_ns(), INIT).vk_hash;
    let vk = net.package(shared_ns(), SHARED).vk_hash;
    let plain_vk = net.package(plain_ns(), SWAP).vk_hash;
    let mut s = scheduler(&net, &mem, &namespace(shared_ns(), SHARED));
    let mut p = scheduler(&net, &mem, &namespace(plain_ns(), SWAP));
    let mut hidden = Hidden::default();

    // ---- the non-secret-shared swap's failure creates no version --------------------------
    let p0 = init(&net, &mut clock, &mut plain, &mut p, init_vk).await;
    let partial = partial_commitment(random(), random());
    let failed = plain.intake_onchain(
        &clock,
        plain_vk,
        &[fr(30_011), fr(0), fr(1 << 40), partial],
        1,
    );
    let r = step(
        &mut p,
        clock.next(),
        "a non-secret-shared swap below its min_out",
    )
    .await;
    assert_eq!(computed(&r), [0], "{r:?}");
    assert_eq!(
        new_c(&r, 0),
        p0,
        "a non-secret-shared ok = false keeps the commitment"
    );
    let result = net.latest(plain_ns(), failed).await;
    // the failed round returns the request's partial note, which `apply`
    // completes
    let o = net.outputs(plain_ns(), &result);
    assert_eq!(
        (
            o.get("ok"),
            o.get("partial_note"),
            o.small("app.code"),
            o.get("app.amount_out")
        ),
        (fr(0), partial, CODE_MIN_OUT, fr(0))
    );
    assert_eq!(o.get("old_c"), o.get("new_c"));
    net.apply(&clock, &mut plain, &result).unwrap();
    assert_eq!(plain.slot, p0);
    let held = net.agreed(plain_ns(), POOL);
    assert_eq!(
        held.len(),
        1,
        "the non-secret-shared failure made no version: {held:?}"
    );

    // ---- the shared pool ---------------------------------------------------------
    let v0 = init(&net, &mut clock, &mut chain, &mut s, init_vk).await;
    let pool0 = net.reserves(shared_ns(), POOL, v0);

    // ---- a secret-shared swap: audited, its outcome opened ------------------------------
    // min_out below every seeded pool's amount_out, so it lands ok whatever
    // the seed: init samples each reserve from a random seed in [1_000_000,
    // 2_000_000), and 25_013 of x pays y * 25_013 / (x + 25_013), at least
    // 1_000_000 * 25_013 / 2_025_012 = 12_351
    let q1 = swap(&net, vk, 25_013, 0, 12_011, random(), None);
    hidden.add(&q1);
    let receipt = net.receipt(clock.block, &q1, &hidden).await;
    let c1 = chain.intake_shared(&clock, vk, &q1, &receipt, &hidden);
    assert_eq!(c1, q1.chain);
    // the request the scheduler synthesises: no requester, no app input
    let honest = synth(&net, &q1, 0, v0);
    hidden.requesters.assert_synthesised(&honest);
    hidden.assert_absent_in("the synthesised public map", &honest.public);
    // node 1's envelope of amount_in substituted, with its share hash: refused
    let mut substituted = honest.clone();
    substituted.shared_inputs = q1.substituted(&net.enc_pks, 1, "amount_in");
    net.refused("a substituted envelope", &substituted, &["shared_inputs"])
        .await;
    net.received.lock().unwrap().clear();

    let r = step(&mut s, clock.next(), "the secret-shared swap").await;
    assert_eq!(computed(&r), [0], "{r:?}");
    assert_eq!(
        r.computed[0].request_id.fr(),
        machine_request_id(c1, &[v0], &[])
    );
    let v1 = new_c(&r, 0);
    assert_eq!(net.audit_received(&q1, &hidden), 3);
    let (out, o) = land(&net, &clock, &mut chain, &q1, &hidden).await;
    assert_eq!((out.old_c, out.new_c), (v0, v1));
    assert_eq!(o[0], 0, "traded");
    assert_eq!(
        net.reserves(shared_ns(), POOL, v1),
        after(pool0, 25_013, 0, o[1])
    );
    eprintln!("secret-shared swap: 25013 x -> {} y", o[1]);

    // ---- a failed swap and a mismatch, pipelined: both commit ----------------------
    // the mismatch: an honest request whose shares the nodes change after
    // its intake (the request function refuses a sharing that does not
    // open C, so only the nodes can make such a round)
    let q2 = swap(&net, vk, 26_017, 0, 1 << 40, random(), None);
    let honest3 = swap(&net, vk, 27_019, 1, 21_013, random(), None);
    for q in [&q2, &honest3] {
        hidden.add(q);
        let receipt = net.receipt(clock.block, q, &hidden).await;
        chain.intake_shared(&clock, vk, q, &receipt, &hidden);
    }
    let q3 = honest3.reshared(
        &net.enc_pks,
        ("amount_in", 1),
        &net.package(shared_ns(), SHARED),
    );
    net.change_shares(&honest3, &q3);
    let r = step(&mut s, clock.next(), "a failed swap and a mismatch").await;
    assert_eq!(computed(&r), [1, 2], "{r:?}");
    let (v2, v3) = (new_c(&r, 1), new_c(&r, 2));
    assert_ne!(
        v2, v1,
        "a failed secret-shared swap writes a new commitment"
    );
    assert_ne!(v3, v2, "so does a mismatch");
    assert_eq!(
        r.computed[1].old[POOL], v2,
        "pipelined on the failure's version"
    );
    let (_, o2) = land(&net, &clock, &mut chain, &q2, &hidden).await;
    assert_eq!(o2, [CODE_MIN_OUT, 0], "a failure's note carries 0");
    assert_eq!(
        net.reserves(shared_ns(), POOL, v2),
        net.reserves(shared_ns(), POOL, v1)
    );
    assert_eq!(
        net.agreed(shared_ns(), POOL)
            .iter()
            .filter(|v| v.commitment == v2)
            .count(),
        1
    );
    let (_, o3) = land(&net, &clock, &mut chain, &q3, &hidden).await;
    assert_eq!(o3, [CODE_INPUTS_MISMATCH, 0], "code 9 inside the outcome");
    assert_eq!(chain.slot, v3, "the mismatch landed");
    assert_eq!(
        net.reserves(shared_ns(), POOL, v3),
        net.reserves(shared_ns(), POOL, v1)
    );
    for q in [&q2, &q3] {
        assert_eq!(net.audit_received(q, &hidden), 3);
    }

    // ---- a recompute after a skip: the same envelopes, a new attempt -------------
    let d = swap(&net, vk, 28_031, 0, 0, random(), None);
    let e = swap(&net, vk, 29_033, 1, 0, random(), None);
    for q in [&d, &e] {
        hidden.add(q);
        let receipt = net.receipt(clock.block, q, &hidden).await;
        chain.intake_shared(&clock, vk, q, &receipt, &hidden);
    }
    net.received.lock().unwrap().clear();
    let r = step(&mut s, clock.next(), "the head and its pipelined swap").await;
    assert_eq!(computed(&r), [3, 4], "{r:?}");
    let (vd, ve1) = (new_c(&r, 3), new_c(&r, 4));
    let first = r.computed[1].request_id;
    let held_d = net.latest(shared_ns(), d.chain).await;
    let held_e = net.latest(shared_ns(), e.chain).await;
    let (out_e1, o_e1) = opened(&e, &held_e);
    assert_eq!(out_e1.old_c, vd);
    // the head is skipped before its result lands: both held results revert
    clock.later(STALE_BLOCKS);
    chain.skip(&clock);
    let out_d = private_outputs(&held_d, PARAMS, 0, CIPHERTEXT);
    assert_eq!(
        chain.apply(
            &clock,
            &held_d,
            out_d.request_id,
            out_d.old_c,
            out_d.new_c,
            true
        ),
        Err("not the head")
    );
    assert_eq!(
        chain.apply(
            &clock,
            &held_e,
            out_e1.request_id,
            out_e1.old_c,
            out_e1.new_c,
            true
        ),
        Err("state moved")
    );
    let r = step(
        &mut s,
        clock.next(),
        "the recompute on the canonical version",
    )
    .await;
    assert_eq!(r.error, None, "{r:?}");
    assert_eq!(computed(&r), [4], "{r:?}");
    assert_eq!(
        r.computed[0].old[POOL], v3,
        "on the slot's canonical version"
    );
    let second = r.computed[0].request_id;
    assert_ne!(second, first, "a new machine request id");
    assert_eq!(second.fr(), machine_request_id(e.chain, &[v3], &[]));
    // the nodes received both attempts with the envelopes they stored
    let received = net.received_for(e.chain);
    assert_eq!(received.len(), 6, "three nodes, two attempts");
    for i in 0..3 {
        let mine: Vec<&Value> = received
            .iter()
            .filter(|(n, _)| *n == i)
            .map(|(_, r)| r)
            .collect();
        assert_eq!(mine.len(), 2);
        assert_ne!(mine[0]["request_id"], mine[1]["request_id"]);
        assert_eq!(
            mine[0]["shared_inputs"], mine[1]["shared_inputs"],
            "node {i}: the recompute reuses the stored envelopes"
        );
    }
    assert_eq!(net.audit_received(&e, &hidden), 6);
    let recomputed = net.latest(shared_ns(), e.chain).await;
    let (out_e2, o_e2) = opened(&e, &recomputed);
    assert_eq!(out_e2.machine_request_id, second.fr());
    // two attempts of one chain request: each sealed under its own note
    // hash's nonce, so two outcomes are two nonces and one outcome is one
    // ciphertext
    let (p1, p2) = (
        open_outcome(e.outcome_key, out_e1.note_hash, &out_e1.ciphertext).unwrap(),
        open_outcome(e.outcome_key, out_e2.note_hash, &out_e2.ciphertext).unwrap(),
    );
    if p1 == p2 {
        assert_eq!(out_e1.note_hash, out_e2.note_hash);
        assert_eq!(
            out_e1.ciphertext, out_e2.ciphertext,
            "one plaintext, one ciphertext"
        );
    } else {
        assert_ne!(
            outcome_nonce(out_e1.note_hash),
            outcome_nonce(out_e2.note_hash)
        );
        assert!(
            open_outcome(e.outcome_key, out_e2.note_hash, &out_e1.ciphertext).is_err(),
            "the first attempt's ciphertext opens only under its own nonce"
        );
        for k in 0..2 {
            assert_ne!(
                out_e1.ciphertext[k] - out_e2.ciphertext[k],
                p1[k] - p2[k],
                "ciphertext field {k}: the difference is the plaintexts'"
            );
        }
    }
    let (_, o_e2_landed) = land(&net, &clock, &mut chain, &e, &hidden).await;
    assert_eq!(o_e2_landed, o_e2);
    let ve2 = chain.slot;
    assert_eq!(o_e1[0], 0);
    assert_eq!(o_e2[0], 0);
    assert_eq!(
        net.reserves(shared_ns(), POOL, ve2),
        after(net.reserves(shared_ns(), POOL, v3), 29_033, 1, o_e2[1])
    );
    eprintln!(
        "two attempts of one swap: {} then {} out ({:.1}s)",
        o_e1[1],
        o_e2[1],
        started.elapsed().as_secs_f64()
    );

    // the pruning job marks the versions against the slot: the skipped
    // attempts' are orphans, kept while the finalized tip (on this chain,
    // the proven tip before the current one) has not passed them and
    // deleted once it has
    assert_eq!(
        net.prune_versions().await,
        [0; 3],
        "a proven tip behind them: nothing goes"
    );
    let versions = net.agreed(shared_ns(), POOL);
    let status = |c: Fr| {
        versions
            .iter()
            .find(|v| v.commitment == c)
            .map(|v| v.status)
    };
    assert_eq!(status(vd), Some(VersionStatus::Orphan));
    assert_eq!(status(ve1), Some(VersionStatus::Orphan));
    assert_eq!(status(ve2), Some(VersionStatus::Canonical));
    // the proven tip passes them (the pruning job's reads see it), then
    // moves again, so the one before it has passed them
    clock.later(2);
    clock.prove();
    assert_eq!(
        net.prune_versions().await,
        [0; 3],
        "the settled block is behind them"
    );
    clock.later(1);
    clock.prove();
    let pruned = net.prune_versions().await;
    assert!(
        pruned.iter().all(|n| *n == pruned[0] && *n >= 2),
        "{pruned:?}"
    );
    for gone in [vd, ve1] {
        assert!(
            !net.holds(shared_ns(), POOL, gone),
            "a skipped attempt's version kept"
        );
    }
    assert!(net.holds(shared_ns(), POOL, ve2));

    // ---- a partial note of an owner that is no account's address ------------------
    // p - 1: no key derives it and no PXE holds it; the machine sees only
    // the partial note, which it never interprets
    let nobody = Fr::from(0u64) - Fr::from(1u64);
    let h = swap(&net, vk, 25_013, 0, 0, nobody, None);
    hidden.add(&h);
    let receipt = net.receipt(clock.block, &h, &hidden).await;
    chain.intake_shared(&clock, vk, &h, &receipt, &hidden);
    let before = chain.slot;
    let r = step(&mut s, clock.next(), "a swap for no account").await;
    assert_eq!(computed(&r), [5], "{r:?}");
    assert_eq!(net.audit_received(&h, &hidden), 3);
    let (_, oh) = land(&net, &clock, &mut chain, &h, &hidden).await;
    assert_eq!(oh[0], 0, "traded");
    assert_eq!(
        net.reserves(shared_ns(), POOL, chain.slot),
        after(net.reserves(shared_ns(), POOL, before), 25_013, 0, oh[1])
    );

    // ---- an enc key rotation while a secret-shared receipt request is queued -------------
    let f = swap(&net, vk, 30_037, 0, 0, random(), None);
    let g = swap(&net, vk, 31_039, 0, 0, random(), None);
    let mut receipts = vec![];
    for q in [&f, &g] {
        hidden.add(q);
        receipts.push(net.receipt(clock.block, q, &hidden).await);
    }
    chain.intake_shared(&clock, vk, &f, &receipts[0], &hidden);
    let rotated = &net.real.apps[1].node;
    let previous = rotated.keys();
    rotated.set_keys(
        previous
            .rotate_enc(random_scalar(&mut OsRng), now())
            .unwrap(),
    );
    // the receipt route takes an envelope to the current key only
    let late = swap(&net, vk, 32_041, 0, 0, random(), None);
    net.receipt_refused(clock.block, &late, "previous enc key")
        .await;
    let r = step(&mut s, clock.next(), "served under the previous key").await;
    assert_eq!(r.error, None, "{r:?}");
    assert_eq!(computed(&r), [6], "{r:?}");
    let (_, of) = land(&net, &clock, &mut chain, &f, &hidden).await;
    assert_eq!(of[0], 0, "inside the grace window");
    // the grace window lapses: node 1 keeps its previous key while the second
    // request, whose envelope to it opens only under that key, may still reach
    // the head (not yet queued before its expiry, then queued); the first,
    // landed, holds it no longer once the settled block (the finalized tip,
    // as node 1's chain view reads it) passes it
    let held = || held_by_queued_receipts(&net.real.apps[1]).unwrap();
    net.settle(&mut clock);
    assert_eq!(held(), [(shared_ns(), g.chain)], "seen nowhere yet");
    chain.intake_shared(&clock, vk, &g, &receipts[1], &hidden);
    assert_eq!(held(), [(shared_ns(), g.chain)], "queued");
    assert!(rotated.keys().previous_key_id().is_some());
    let r = step(&mut s, clock.next(), "queued past the grace window").await;
    assert_eq!(r.error, None, "{r:?}");
    assert_eq!(computed(&r), [chain.head], "{r:?}");
    let (_, og) = land(&net, &clock, &mut chain, &g, &hidden).await;
    assert_eq!(og[0], 0, "past the grace window, before retirement");
    assert_eq!(chain.head as usize, chain.ids.len());
    // the head has passed it and the settled block passes the landing:
    // nothing holds the previous key, which retires
    net.settle(&mut clock);
    assert!(held().is_empty());
    rotated.set_keys(rotated.keys().as_ref().clone().retire_previous_enc());
    eprintln!(
        "AMM secret-shared swap rounds: {:.1}s",
        started.elapsed().as_secs_f64()
    );
}

/// A secret-shared on-chain swap of `amount_in` in `direction` with `min_out`,
/// committing `owner`'s partial note under a fresh `rho`, its outcome key and
/// tag the user's, encoded under `keys`.
fn swap_onchain(
    pkg: &sidecar_tip::TipPackage,
    keys: EncKeys,
    amount_in: u64,
    direction: u64,
    min_out: u64,
    owner: Fr,
) -> OnchainRequest {
    let mut r = OnchainRequest::new(
        shared_ns(),
        pkg,
        keys,
        vec![
            shared("amount_in", fr(amount_in)),
            shared("direction", fr(direction)),
            shared("min_out", fr(min_out)),
            shared("$partial_note", partial_commitment(owner, random())),
        ],
        &[("$outcome_key", random()), ("$outcome_tag", random())],
    );
    r.req.owner = Some(owner);
    r
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn the_amm_shared_onchain_swap_runs_intake_to_result_on_three_nodes() {
    let tmp = TempDir::new("ammonchain");
    let mem = Arc::new(MemoryChain::new(100));
    let sched = || with_shared_onchain(namespace(shared_ns(), SHARED_ONCHAIN));
    let net = start(&tmp, mem.clone(), &["pss_seed", INIT, SHARED], &[sched()]).await;
    let started = Instant::now();
    let mut clock = Clock::new(100, mem.clone());
    let mut chain = Chain::new(&clock, shared_ns(), pool_slot(), net.sig_pks).with_shared_onchain();
    let vk = net
        .register_entry(
            &sched(),
            &[
                (INIT, INIT, manifest("amm-tip", INIT)),
                (SHARED_ONCHAIN, SHARED, manifest("amm-tip", SHARED_ONCHAIN)),
            ],
        )
        .await[SHARED_ONCHAIN];
    let init_vk = net.package(shared_ns(), INIT).vk_hash;
    let pkg = net.package(shared_ns(), SHARED_ONCHAIN);
    assert_eq!(pkg.vk_hash, vk);
    assert_eq!(
        pkg.tip.intake(),
        sidecar_core::manifest::QueuedIntake::SharedOnchain
    );
    let mut s = scheduler(&net, &mem, &sched());
    let mut hidden = Hidden::default();

    // each node sets its current key in the contract at epoch 1
    let mut stored = EncKeys {
        pks: net.enc_pks,
        epochs: [0; 3],
    };
    for i in 0..3 {
        net.rotate_onchain(&mut chain, &mut stored, i, None, 1, now());
    }
    assert_eq!(stored.pks, net.enc_pks);
    let v0 = init(&net, &mut clock, &mut chain, &mut s, init_vk).await;
    let pool0 = net.reserves(shared_ns(), POOL, v0);

    // ---- a swap proven before node 1's rotation, queued after it ----------------
    // min_out below every seeded pool's amount_out (12_351 at least, as in
    // the receipt suite above)
    let anchor = stored;
    let old = swap_onchain(&pkg, anchor, 25_013, 0, 12_011, random());
    assert_eq!(old.epochs, [1, 1, 1]);
    let node1 = &net.real.apps[1].node;
    net.rotate_onchain(
        &mut chain,
        &mut stored,
        1,
        Some(random_scalar(&mut OsRng)),
        2,
        now(),
    );
    assert_eq!(stored.epochs, [1, 2, 1]);
    assert_ne!(stored.pks[1], anchor.pks[1], "node 1's new key");
    assert_eq!(node1.keys().epochs().epochs(shared_ns()), [1, 2]);
    // its grace window ends: only the epoch rule keeps epoch 1's scalar
    node1.set_keys(node1.keys().as_ref().clone().retire_previous_enc());
    assert!(node1.keys().previous_enc_scalar().is_none());
    hidden.add(&old.req);
    let c_old = chain.intake_shared_onchain(&clock, &stored, &old, &hidden);
    // ---- and a swap under node 1's new key -----------------------------------------
    let new = swap_onchain(&pkg, stored, 26_017, 1, 12_011, random());
    assert_eq!(new.epochs, [1, 2, 1]);
    hidden.add(&new.req);
    chain.intake_shared_onchain(&clock, &stored, &new, &hidden);

    // the request the scheduler synthesises: no requester, no app input, the
    // chain's log; one correction moved is refused by the chain verifiers
    let state = [KeyState {
        key: POOL.into(),
        commitment: v0,
        record: None,
    }];
    let plan = sched();
    let view = SynthesisView {
        namespace: shared_ns(),
        entry: QueueEntry {
            index: 0,
            chain_request_id: c_old,
        },
        state_keys: &plan.circuits[SHARED_ONCHAIN],
        pinned: &PinnedValues::default(),
        state: &state,
        node_values: &PublicMap::new(),
    };
    let honest = synthesise(&view, &pkg, &old.intake_inputs())
        .unwrap()
        .request;
    hidden.requesters.assert_synthesised(&honest);
    hidden.assert_absent_in("the synthesised public map", &honest.public);
    assert!(honest.shared_inputs.is_empty());
    let mut tampered = honest.clone();
    let log = tampered.shared_log.as_mut().unwrap();
    let at = old.shared[0].correction.unwrap();
    log.fields[at] = sidecar_core::field::FieldHex(log.fields[at].fr() + fr(1));
    net.refused(
        "a tampered shared_log",
        &tampered,
        &["field `shared_log`: differs"],
    )
    .await;
    net.received.lock().unwrap().clear();

    let round = Instant::now();
    let r = step(
        &mut s,
        clock.next(),
        "the old anchor's swap and the new key's",
    )
    .await;
    assert_eq!(r.error, None, "{r:?}");
    assert_eq!(computed(&r), [0, 1], "{r:?}");
    assert_eq!(
        r.computed[0].request_id.fr(),
        machine_request_id(c_old, &[v0], &[])
    );
    eprintln!(
        "MPC: two secret-shared on-chain swap rounds in {:.1}s",
        round.elapsed().as_secs_f64()
    );
    let (v1, v2) = (new_c(&r, 0), new_c(&r, 1));
    for q in [&old, &new] {
        assert_eq!(net.audit_received_onchain(q, &hidden), 3);
    }
    let (out, o) = land(&net, &clock, &mut chain, &old.req, &hidden).await;
    assert_eq!((out.old_c, out.new_c), (v0, v1));
    assert_eq!(o[0], 0, "traded: node 1 served epoch 1 after its rotation");
    let pool1 = after(pool0, 25_013, 0, o[1]);
    assert_eq!(net.reserves(shared_ns(), POOL, v1), pool1);
    let (out, o2) = land(&net, &clock, &mut chain, &new.req, &hidden).await;
    assert_eq!((out.old_c, out.new_c), (v1, v2));
    assert_eq!(o2[0], 0, "traded under node 1's new key");
    assert_eq!(
        net.reserves(shared_ns(), POOL, v2),
        after(pool1, 26_017, 1, o2[1])
    );
    assert_eq!(chain.head as usize, chain.ids.len());
    eprintln!(
        "AMM secret-shared on-chain swaps: 25013 x -> {} y, 26017 y -> {} x ({:.1}s)",
        o[1],
        o2[1],
        started.elapsed().as_secs_f64()
    );
}
