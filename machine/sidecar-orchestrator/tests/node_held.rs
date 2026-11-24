//! Node-held state at the tip over three real nodes with real MPC proofs:
//! the AMM tip rounds of examples/amm-tip, their pool key node-held. The
//! init and the swap are the example's own manifests (`amm_init_tip`,
//! `amm_swap_tip`, the pool `state: node` as the example declares it) and
//! compiled circuits; beside them, `amm_swap_tip_priced` (machine/circuits)
//! is the swap with its `min_out` a pinned read of an oracle, so a moved
//! value recomputes an attempt. The scheduler drives the queue step by step
//! on sidecar-tip's in-memory Aztec node, which the test writes as
//! `configure`, intake, `init_pool`, `apply` and `skip()` would; each node
//! runs the real chain verifier over it. `apply` writes the new commitment
//! and logs nothing.
//!
//! - The init round: nothing before `configure`; then sent once, its
//!   result carries no records, and it creates the pool's first version,
//!   under the commitment `init_pool` writes.
//! - A swap creates one version of the pool under its new commitment; the
//!   swap after the head is pipelined on the head's live version; each
//!   round returns the request's partial note.
//! - A failed swap (an output below `min_out`: `ok = 0`, new commitment =
//!   old) creates no version and lands; the next swap loads its parent,
//!   the version the slot still names.
//! - A recompute after a revert: the head is skipped before its result
//!   lands, so the head's result and the pipelined swap's (computed on the
//!   head's version) both revert at `apply`; the scheduler recomputes the
//!   pipelined swap on the slot's canonical version, which lands, and the
//!   skipped attempts' versions are orphans.
//! - An older attempt lands after a recompute (a pinned value moved): its
//!   version was kept, and the next entry is recomputed on it. While both
//!   attempts are live, a request pipelined on the older one is refused by
//!   every node, as is a request for the head on a superseded version.
//! - A replaced proposed block that puts an orphaned commitment back in the
//!   slot finds its version, with no fault.
//! - A slot at a commitment no node holds is refused at every node (a fault).
//! - A skipped entry's attempts are orphans, kept while the proven tip
//!   before the current one has not passed the block they turned orphan at,
//!   and pruned once it has.
//! - A node's store deleted (its key directory kept) is resynced from its
//!   two neighbours through the three admin sockets: the namespace with its
//!   nsk_app pair and packages, and every canonical and live version of the
//!   pool come back, the npk_app_hash check and the audit pass, and the next
//!   swap runs on the resynced node and lands; an audit afterwards passes.
//! - The node's store backed up through its admin socket (under a backup
//!   key the test holds), a swap run after the backup, the store deleted
//!   and restored from the backup with a delta resync from the neighbours:
//!   the namespace and every canonical and live version come back (the
//!   backup's version from the backup, the later one from the neighbours),
//!   the checks and the audit pass, and the next swap runs on the restored
//!   node and lands.
//! - Throughout, the three nodes' pairs open to the reserves the swaps'
//!   outputs give.
//!
//! Needs `scripts/prepare-data.sh` (examples/amm-tip's circuits and the CRS
//! under machine/data, or DATA_DIR); the test fails naming the missing files
//! if they are absent, so a passing run proves it ran. Run with `--release`.

mod common;

use std::sync::Arc;
use std::time::Instant;

use common::tip::*;
use common::*;
use serde_json::{Value, json};

use sidecar_core::field::{FieldHex, Fr, fr_from_hex, fr_to_hex};
use sidecar_core::request::Request;
use sidecar_core::response::ExecuteResponse;
use sidecar_core::resync::Scope;
use sidecar_core::store::{StoreRead, TipVersion, VersionStatus};
use sidecar_node::admin::{self, AdminRequest};
use sidecar_node::backup::BackupKey;
use sidecar_orchestrator::scheduler::InitStep;
use sidecar_tip::chain::{PinnedSource, PinnedValue};
use sidecar_tip::testing::MemoryChain;
use sidecar_tip::{
    KeyState, PinnedValues, PlainFound, PublicMap, QueueEntry, SynthesisView, chain_request_id,
    synthesise,
};

const TIP: u64 = 0x7196;
// the slot as the contract manifest writes it (fr_to_hex)
const POOL: &str = "0x000000000000000000000000000000000000000000000000000000000000a002";
/// The oracle the priced swap's `min_out` is read from.
const ORACLE: u64 = 0x0a12;
/// Where the mock contract keeps `Configured.configured`.
const CONFIGURED_SLOT: u64 = 0x20;
const INIT: &str = "amm_init_tip";
const SWAP: &str = "amm_swap_tip";
const PRICED: &str = "amm_swap_tip_priced";

fn ns() -> Fr {
    Fr::from(TIP)
}

fn pool_slot() -> Fr {
    fr_from_hex(POOL).unwrap()
}

/// The pool's namespace: the init round sent by the scheduler once the
/// contract is configured, both swaps queued.
fn namespace() -> TipEntry {
    TipEntry {
        init: Some(tip_init(INIT, CONFIGURED_SLOT, &[])),
        ..tip_namespace(ns(), POOL, &[INIT, SWAP, PRICED], &[INIT])
    }
}

/// The example's manifest `name`, as registered, with its pool key
/// node-held in every entry.
fn example(name: &str) -> Value {
    let m = manifest("amm-tip", name);
    let state = m["state"].as_object().unwrap();
    assert!(!state.is_empty(), "{name} names its state modes");
    assert!(
        state.values().all(|mode| mode == "node"),
        "{name}: {state:?}"
    );
    m
}

/// `amm_swap_tip` with `min_out` a pinned read of the oracle and no partial
/// note (`outcome: none`): the manifest of `amm_swap_tip_priced`, whose
/// `min_out` is a public parameter after the key slots.
fn priced() -> Value {
    let mut m = example(SWAP);
    m["circuit"] = json!(PRICED);
    let witness = m["witness"].as_array_mut().unwrap();
    let at = witness
        .iter()
        .position(|w| w["param"] == "min_out")
        .unwrap();
    let min_out = witness.remove(at);
    witness.insert(4, min_out);
    // the machine copy completes no partial note
    witness.retain(|w| w["param"] != "partial_note");
    m["outcome"] = json!("none");
    m["public_reads"] = json!([
        {"contract": fr_to_hex(fr(ORACLE)), "function": "get_min_out", "args": [], "param": "min_out"}
    ]);
    m
}

/// The partial note the swap of `nonce` commits (a stand-in for the
/// contract's commitment of the trader's address and `rho`).
fn partial_note(nonce: u64) -> Fr {
    fr(0x9a00_0000 + nonce)
}

/// Queue an on-chain intake swap `[amount_in, direction, min_out]` with its
/// partial note (one per nonce).
fn swap(w: &World, clock: &Clock, chain: &mut Chain, inputs: [u64; 3], nonce: u64) -> Fr {
    let mut inputs = frs(&inputs);
    inputs.push(partial_note(nonce));
    chain.intake_onchain(clock, w.vk(SWAP), &inputs, nonce)
}

/// `configure` lands: the flag.
fn configure(chain: &Chain) {
    chain.mem.set_storage(chain.ns, fr(CONFIGURED_SLOT), fr(1));
}

/// A swap result's `ok`, `code` and `amount_out`.
fn swapped(w: &World, result: &ExecuteResponse) -> (bool, u64, u64) {
    let o = w.outputs(result);
    (o.ok(), o.small("app.code"), o.small("app.amount_out"))
}

/// The request the scheduler would build for entry `index` (chain request
/// `chain`) of the priced swap, its inputs and nonce as queued, on the pool
/// version `on` with `min_out` as the oracle's pinned value.
fn synth_priced(
    w: &World,
    (index, chain): (u64, Fr),
    inputs: &[u64],
    nonce: u64,
    on: Fr,
    min_out: u64,
) -> Request {
    let pinned = PinnedValues(vec![PinnedValue {
        param: "min_out".into(),
        contract: fr(ORACLE),
        function: "get_min_out()".into(),
        args: vec![],
        values: vec![fr(min_out)],
        previous: None,
        block: 0,
        source: PinnedSource::Simulated,
    }]);
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
        state_keys: &namespace.circuits[PRICED],
        pinned: &pinned,
        state: &state,
        node_values: &PublicMap::new(),
    };
    let log = PlainFound::new(frs(inputs), fr(nonce));
    synthesise(&view, &w.package(PRICED), &log).unwrap().request
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn amm_rounds_run_on_node_held_versions() {
    let tmp = TempDir::new("nodeheld");
    let mem = Arc::new(MemoryChain::new(100));
    let w = setup(
        &tmp,
        &mem,
        &namespace(),
        vec![
            // the example's packages as it declares them: its compiled
            // circuits and its manifests, unchanged
            Package::new(INIT, example(INIT)),
            Package::new(SWAP, example(SWAP)),
            Package::new(PRICED, priced()),
        ],
    )
    .await;
    let started = Instant::now();
    let mut clock = Clock::new(100, mem.clone());
    let mut chain = Chain::new(&clock, ns(), pool_slot(), w.sig_pks);
    let mut s = scheduler(&w, &mem, &namespace());
    let zero = fr(0);

    // ---- the init round, sent by the scheduler once configured -------------
    let r = step(&mut s, clock.next(), "unconfigured").await;
    assert_eq!(r.init, Some(InitStep::Unconfigured));
    assert!(r.computed.is_empty() && r.error.is_none(), "{r:?}");
    assert!(w.agreed().is_empty());

    configure(&chain);
    let init_id = chain_request_id(ns(), w.vk(INIT), &[], zero);
    let r = step(&mut s, clock.next(), "configured").await;
    assert_eq!(r.error, None, "{r:?}");
    let Some(InitStep::Sent(attempt)) = &r.init else {
        panic!("no init round sent: {:?}", r.init);
    };
    assert_eq!(attempt.chain_request_id, init_id);
    let v0 = attempt.new[0].commitment;
    let r = step(&mut s, clock.next(), "init held").await;
    assert_eq!(r.init, Some(InitStep::Due), "sent once");
    let init = w.version(v0);
    assert_eq!((init.parent, init.status), (zero, VersionStatus::Live));
    assert_eq!(w.agreed().len(), 1);
    // the relayer lands it through init_pool: no records, nothing logged
    let landed = w.latest("init", init_id).await;
    assert!(landed.records.is_empty() && landed.stored.is_empty());
    assert_eq!(landed.vk_hash, FieldHex(w.vk(INIT)));
    chain.init(w.outputs(&landed).get("new_c"));
    assert_eq!(chain.slot, v0);
    let pool0 = w.reserves(v0);

    // ---- a swap, a failed swap and the swap after it -------------------------
    let a = swap(&w, &clock, &mut chain, [1000, 0, 0], 1);
    // an output below its min_out: ok = 0, code 8
    let b = swap(&w, &clock, &mut chain, [1000, 0, 1 << 40], 2);
    let c = swap(&w, &clock, &mut chain, [500, 1, 0], 3);
    let r = step(&mut s, clock.next(), "the first swap and the failed swap").await;
    assert_eq!(r.init, Some(InitStep::Done));
    assert!(
        !r.reloaded,
        "the landed init is the attempt the scheduler held"
    );
    assert_eq!(computed(&r), [0, 1], "{r:?}");
    assert_eq!(r.computed[0].old[POOL], v0);
    let va = new_c(&r, 0);
    // the failed swap ran on the head's live version and kept its commitment
    assert_eq!(r.computed[1].old[POOL], va);
    assert_eq!(new_c(&r, 1), va, "ok = 0 keeps the commitment");
    // one version per swap that changed the pool: the failed one made none
    let held = w.agreed();
    assert_eq!(held.len(), 2, "{held:?}");
    let first = w.version(va);
    assert_eq!((first.parent, first.index), (v0, 0));
    // the commit marked the init's version against the slot that names it
    assert_eq!(w.version(v0).status, VersionStatus::Canonical);
    assert_eq!(first.status, VersionStatus::Live);

    let swap_a = w.latest("swap a", a).await;
    let (ok_a, _, out_a) = swapped(&w, &swap_a);
    assert!(ok_a);
    // the round returns the request's partial note, which `apply` completes
    assert_eq!(w.outputs(&swap_a).get("partial_note"), partial_note(1));
    assert_eq!(w.reserves(va), [pool0[0] + 1000, pool0[1] - out_a]);
    w.apply(&clock, &mut chain, &swap_a).unwrap();
    let r = step(&mut s, clock.next(), "the swap after the failed swap").await;
    assert_eq!(computed(&r), [2], "{r:?}");
    // the failed swap created no version, so the next loads its parent
    assert_eq!(r.computed[0].old[POOL], va);
    let vc = new_c(&r, 2);
    assert_eq!(w.version(vc).parent, va);
    let failed = w.latest("failed swap", b).await;
    assert_eq!(swapped(&w, &failed), (false, 8, 0));
    let o = w.outputs(&failed);
    assert_eq!(o.get("old_c"), o.get("new_c"));
    // a failed round returns its partial note too: the note it completes says so
    assert_eq!(o.get("partial_note"), partial_note(2));
    w.apply(&clock, &mut chain, &failed).unwrap();
    assert_eq!(chain.slot, va, "the failed swap left the slot");
    let swap_c = w.latest("swap c", c).await;
    let (ok_c, _, out_c) = swapped(&w, &swap_c);
    assert!(ok_c);
    w.apply(&clock, &mut chain, &swap_c).unwrap();
    assert_eq!(chain.slot, vc);
    let pool_a = w.reserves(va);
    assert_eq!(w.reserves(vc), [pool_a[0] - out_c, pool_a[1] + 500]);
    eprintln!(
        "AMM: init {pool0:?}, swap 1000 x -> {out_a} y, a failed swap, swap 500 y -> {out_c} x \
         ({:.1}s)",
        started.elapsed().as_secs_f64()
    );

    // ---- a recompute after a revert ------------------------------------------
    let d = swap(&w, &clock, &mut chain, [300, 0, 0], 4);
    let e = swap(&w, &clock, &mut chain, [200, 1, 0], 5);
    let r = step(&mut s, clock.next(), "the head and its pipelined swap").await;
    assert_eq!(computed(&r), [3, 4], "{r:?}");
    let vd = new_c(&r, 3);
    let ve = new_c(&r, 4);
    assert_eq!(r.computed[1].old[POOL], vd);
    let held_d = w.latest("swap d", d).await;
    let held_e = w.latest("swap e on d's version", e).await;
    // the head is skipped before its result lands: both held results revert
    clock.later(STALE_BLOCKS);
    chain.skip(&clock);
    assert_eq!(w.apply(&clock, &mut chain, &held_d), Err("not the head"));
    assert_eq!(w.apply(&clock, &mut chain, &held_e), Err("state moved"));
    assert_eq!((chain.head, chain.slot), (4, vc));
    // the scheduler recomputes the new head on the slot's canonical version
    let r = step(&mut s, clock.next(), "the recompute after the revert").await;
    assert_eq!(r.error, None, "{r:?}");
    assert_eq!(computed(&r), [4], "{r:?}");
    assert_eq!(r.computed[0].old[POOL], vc);
    let ve2 = new_c(&r, 4);
    assert_ne!(ve2, ve);
    assert_eq!(w.version(ve2).parent, vc);
    let recomputed = w.latest("swap e, recomputed", e).await;
    assert_eq!(w.outputs(&recomputed).get("new_c"), ve2);
    let (ok_e, _, out_e) = swapped(&w, &recomputed);
    assert!(ok_e);
    w.apply(&clock, &mut chain, &recomputed).unwrap();
    assert_eq!(chain.slot, ve2);
    let pool_c = w.reserves(vc);
    assert_eq!(w.reserves(ve2), [pool_c[0] - out_e, pool_c[1] + 200]);

    // the next round's commit marks the versions against the slot: the
    // skipped head's version and the attempt built on it are orphans, the
    // recompute is canonical
    let f = swap(&w, &clock, &mut chain, [100, 0, 0], 6);
    let r = step(&mut s, clock.next(), "the swap after the recompute").await;
    assert_eq!(computed(&r), [5], "{r:?}");
    assert_eq!(r.computed[0].old[POOL], ve2);
    assert_eq!(w.version(vd).status, VersionStatus::Orphan);
    assert_eq!(w.version(ve).status, VersionStatus::Orphan);
    assert_eq!(w.version(ve2).status, VersionStatus::Canonical);
    w.apply(&clock, &mut chain, &w.latest("swap f", f).await)
        .unwrap();
    let vf = chain.slot;

    // ---- an older attempt lands after a recompute ----------------------------
    let oracle = fr(ORACLE);
    let min_out = |v: u64| mem.set_call(oracle, "get_min_out()", &[], Ok(vec![fr(v)]));
    min_out(1);
    let c6 = chain.intake(&clock, w.vk(PRICED), &[300, 0], 7);
    let c7 = chain.intake(&clock, w.vk(PRICED), &[100, 1], 8);
    // a request for the head on a superseded version (the slot's parent) is
    // refused by every node
    let superseded = synth_priced(&w, (6, c6), &[300, 0], 7, ve2, 1);
    w.refused(
        "a superseded version",
        &superseded,
        &["field `request_id`", "the 1 old commitments"],
    )
    .await;
    let r = step(&mut s, clock.next(), "entry 6 at min_out 1").await;
    assert_eq!(computed(&r), [6, 7], "{r:?}");
    assert_eq!(r.computed[0].old[POOL], vf);
    let v6a = new_c(&r, 6);
    let older = w.latest("entry 6, first attempt", c6).await;
    min_out(2);
    let r = step(&mut s, clock.next(), "the oracle moved").await;
    assert!(r.repriced, "{r:?}");
    assert_eq!(computed(&r), [6, 7], "{r:?}");
    let (v6b, v7b) = (new_c(&r, 6), new_c(&r, 7));
    assert_ne!(v6a, v6b);
    // both attempts of entry 6 are live; a request pipelined on the older
    // one is refused (the verifier's latest-attempt rule)
    for c in [v6a, v6b] {
        assert_eq!(w.version(c).index, 6);
    }
    let on_older = synth_priced(&w, (7, c7), &[100, 1], 8, v6a, 2);
    w.refused(
        "pipelined on an older attempt",
        &on_older,
        &["field `request_id`", "the 1 old commitments"],
    )
    .await;
    // the older attempt lands (the oracle moved back); the next step
    // recomputes entry 7 on it
    min_out(1);
    w.apply(&clock, &mut chain, &older).unwrap();
    assert_eq!(chain.slot, v6a);
    // (the same machine request id as the first attempt of entry 7, which
    // ran on it: answered from the nodes' rows)
    let r = step(&mut s, clock.next(), "the older attempt landed").await;
    assert!(r.reloaded, "{r:?}");
    assert_eq!(computed(&r), [7], "{r:?}");
    assert_eq!(r.computed[0].old[POOL], v6a);
    assert_eq!(w.version(new_c(&r, 7)).parent, v6a);

    // ---- a replaced proposed block restores an orphaned commitment ----------
    chain.slot = v6b;
    chain.write();
    let r = step(&mut s, clock.next(), "the slot back at the recompute").await;
    assert_eq!(r.error, None, "{r:?}");
    assert_eq!(computed(&r), [7], "{r:?}");
    assert_eq!(r.computed[0].old[POOL], v6b);
    // a new attempt (min_out is 1 again), whose commit found the orphaned
    // version and marked it canonical
    let v7d = new_c(&r, 7);
    assert_ne!(v7d, v7b);
    assert_eq!(w.version(v7d).parent, v6b);
    assert_eq!(w.version(v6b).status, VersionStatus::Canonical);

    // ---- a slot at a commitment no node holds --------------------------------
    chain.slot = fr(0xdead);
    chain.write();
    let r = step(&mut s, clock.next(), "an unknown commitment").await;
    assert!(r.computed.is_empty(), "{r:?}");
    let error = r.error.clone().unwrap_or_default();
    assert!(error.contains("holds no version of: a fault"), "{r:?}");
    chain.slot = v6a;
    chain.write();

    // ---- a skipped entry's attempts are pruned once the settled block passes them
    clock.later(STALE_BLOCKS);
    chain.skip(&clock);
    let c8 = chain.intake(&clock, w.vk(PRICED), &[100, 0], 9);
    let r = step(&mut s, clock.next(), "entry 8 after the skip").await;
    assert_eq!(computed(&r), [8], "{r:?}");
    // the commit marked every version against the slot (v6a) and the head (8)
    assert_eq!(w.version(v6a).status, VersionStatus::Canonical);
    assert_eq!(w.version(v6b).status, VersionStatus::Orphan);
    let skipped: Vec<TipVersion> = w.agreed().into_iter().filter(|v| v.index == 7).collect();
    assert_eq!(skipped.len(), 3, "{skipped:?}");
    assert!(skipped.iter().all(|v| v.status == VersionStatus::Orphan));
    let first = skipped.iter().map(|v| v.block).min().unwrap();
    let last = skipped.iter().map(|v| v.block).max().unwrap();
    w.apply(&clock, &mut chain, &w.latest("swap 8", c8).await)
        .unwrap();
    // the proven tip passes every orphan of the entry, but the one before
    // it (what the nodes' reads of entry 8 saw) has not: every orphan is kept
    let c9 = {
        clock.next();
        clock.prove();
        chain.intake(&clock, w.vk(PRICED), &[100, 1], 10)
    };
    let r = step(
        &mut s,
        clock.next(),
        "entry 9, the proven tip past the orphans",
    )
    .await;
    assert_eq!(computed(&r), [9], "{r:?}");
    assert!(clock.proven > last && first > 0);
    assert_eq!(
        w.agreed().iter().filter(|v| v.index == 7).count(),
        skipped.len()
    );
    // the proven tip moves again: the one before it has passed them all
    w.apply(&clock, &mut chain, &w.latest("swap 9", c9).await)
        .unwrap();
    let c10 = {
        clock.next();
        clock.prove();
        chain.intake(&clock, w.vk(PRICED), &[100, 0], 11)
    };
    let r = step(
        &mut s,
        clock.next(),
        "entry 10, the settled block past them",
    )
    .await;
    assert_eq!(computed(&r), [10], "{r:?}");
    assert!(w.agreed().iter().all(|v| v.index != 7));
    w.apply(&clock, &mut chain, &w.latest("swap 10", c10).await)
        .unwrap();

    // ---- a lost store, resynced from the two neighbours ----------------------
    let lost = 1;
    // every canonical and live version, but the block each node marked it at
    let held = |i: usize| -> Vec<TipVersion> {
        w.versions(i)
            .into_iter()
            .filter(|v| v.status != VersionStatus::Orphan)
            .map(|v| TipVersion { block: 0, ..v })
            .collect()
    };
    // the nodes mark their versions against the chain as it stands (the
    // resync marks first too), so the landed swap's version is canonical
    w.prune().await;
    let before = held(lost);
    let row = w.real.apps[lost].node.store.namespace(ns()).unwrap();
    w.real.apps[lost].node.store.clear();
    let resynced = Instant::now();
    let answers = w
        .real
        .admin_all(AdminRequest::Resync {
            lost,
            pins: Box::new(w.real.pins()),
        })
        .await;
    for (i, answer) in answers.into_iter().enumerate() {
        assert!(answer.ok, "resync at node {i}: {:?}", answer.refusal);
        let report = answer.resync.unwrap();
        assert_eq!(report.npk_checked, [FieldHex(ns())], "node {i}");
        assert_eq!(report.audit.len(), 1, "node {i}: {:?}", report.audit);
        assert!(report.passed(), "node {i}: {:?}", report.audit);
        assert_eq!(
            (report.imported.namespaces, report.imported.packages),
            (1, w.vk.len()),
            "node {i}"
        );
    }
    eprintln!(
        "resync of node {lost}: {:.1}s",
        resynced.elapsed().as_secs_f64()
    );
    assert_eq!(w.real.apps[lost].node.store.namespace(ns()).unwrap(), row);
    assert_eq!(held(lost), before);
    // the next swap runs on the resynced node and lands
    let c11 = chain.intake(&clock, w.vk(PRICED), &[100, 1], 12);
    let r = step(&mut s, clock.next(), "entry 11 after the resync").await;
    assert_eq!(computed(&r), [11], "{r:?}");
    let v11 = new_c(&r, 11);
    let swap11 = w.latest("swap 11", c11).await;
    assert!(swapped(&w, &swap11).0);
    // (the resynced node holds no orphans, so the nodes' version lists differ)
    let pool = w.reserves(r.computed[0].old[POOL]);
    assert_eq!(w.reserves(v11)[1], pool[1] + 100);
    w.apply(&clock, &mut chain, &swap11).unwrap();
    let audited = w
        .real
        .admin_all(AdminRequest::Audit { namespace: None })
        .await;
    for (i, answer) in audited.into_iter().enumerate() {
        let keys = answer.audit.unwrap();
        assert!(keys.iter().all(|k| k.passed()), "node {i}: {keys:?}");
    }

    // ---- a store backup, restored with a delta resync ------------------------
    let key = BackupKey::generate().unwrap();
    let file = tmp.path().join("node-backup.store");
    let socket = |i: usize| w.real.running[i].admin_socket.clone();
    let backup = AdminRequest::Backup {
        out: file.clone(),
        key: key.clone(),
    };
    let answer = admin::call_async(socket(lost), backup).await.unwrap();
    assert!(answer.ok, "backup: {:?}", answer.refusal);
    assert_eq!(answer.backed_up.unwrap().namespaces, 1);
    // a swap after the backup, computed and not yet landed: its live version
    // is the neighbours' alone to send, the canonical one the backup's
    let c12 = chain.intake(&clock, w.vk(PRICED), &[100, 0], 13);
    let r = step(&mut s, clock.next(), "entry 12 after the backup").await;
    assert_eq!(computed(&r), [12], "{r:?}");
    let v12 = new_c(&r, 12);
    let swap12 = w.latest("swap 12", c12).await;
    w.prune().await;
    let before = held(lost);
    assert!(before.iter().any(|v| v.commitment == v12));
    w.real.apps[lost].node.store.clear();
    let restored = Instant::now();
    let restore = |i: usize| {
        let (backup, key) = if i == lost {
            (Some(file.clone()), Some(key.clone()))
        } else {
            (None, None)
        };
        admin::call_async(
            socket(i),
            AdminRequest::RestoreBackup {
                lost,
                pins: Box::new(w.real.pins()),
                backup,
                key,
            },
        )
    };
    let (a, b, c) = tokio::join!(restore(0), restore(1), restore(2));
    for (i, answer) in [a, b, c].into_iter().enumerate() {
        let answer = answer.unwrap();
        assert!(answer.ok, "restore at node {i}: {:?}", answer.refusal);
        let report = answer.resync.unwrap();
        assert_eq!(report.scope, Scope::Delta, "node {i}");
        assert_eq!(report.npk_checked, [FieldHex(ns())], "node {i}");
        assert!(report.passed(), "node {i}: {:?}", report.audit);
        if i == lost {
            let imported = &report.imported;
            assert!(
                imported.from_backup >= 1 && imported.from_backup < imported.versions,
                "{imported:?}"
            );
            assert!(imported.requests > 0, "{imported:?}");
        }
    }
    eprintln!(
        "restore of node {lost}: {:.1}s",
        restored.elapsed().as_secs_f64()
    );
    assert_eq!(w.real.apps[lost].node.store.namespace(ns()).unwrap(), row);
    assert_eq!(held(lost), before);
    // swap 12 lands, and the next swap runs on the restored node and lands
    w.apply(&clock, &mut chain, &swap12).unwrap();
    let c13 = chain.intake(&clock, w.vk(PRICED), &[100, 1], 14);
    let r = step(&mut s, clock.next(), "entry 13 after the restore").await;
    assert_eq!(computed(&r), [13], "{r:?}");
    let swap13 = w.latest("swap 13", c13).await;
    assert!(swapped(&w, &swap13).0);
    w.apply(&clock, &mut chain, &swap13).unwrap();
    eprintln!(
        "node-held AMM rounds: {:.1}s",
        started.elapsed().as_secs_f64()
    );
}
