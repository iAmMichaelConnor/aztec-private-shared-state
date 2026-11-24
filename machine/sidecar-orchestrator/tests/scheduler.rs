//! The tip's scheduler and the nodes' chain verifiers over three real nodes
//! with real MPC proofs, driven step by step: the chain is sidecar-tip's
//! in-memory Aztec node, which the test writes as intake, `apply` and
//! `skip()` would, and every step is given an explicit snapshot instead of a
//! timer. Each node runs the real chain verifier (sidecar-tip's
//! `ChainVerifier`) over its own view of that chain; node 2's view can be made
//! to lie, lag or fail. The rounds are the machine's queued test counter
//! (`tip_counter_init`, `tip_counter`, machine/circuits): one chain-held key,
//! the slot 0x7c01.
//!
//! The scheduler's test:
//!
//! - A queue of three requests is processed in order: the head and one
//!   pipelined entry on the head's result, never the entry after that (no
//!   node row holds it); a step with nothing new computes nothing; the relayer
//!   reads each result by chain request id and lands it, and the next step
//!   computes the next entry.
//! - A reverted apply (the slot and the head did not move) keeps the attempts;
//!   a scheduler that starts afresh reloads the state from the sealed-thirds
//!   log and recomputes the head against the old commitment, which is the
//!   same machine request id, answered from the nodes' rows.
//! - A skip (the head moved without a slot change) discards the pipelined
//!   attempt and recomputes the new head against the reloaded state.
//! - A result for the head's chain request that the scheduler did not
//!   produce (its rows were pruned and someone else resent the same request,
//!   which ran again under a fresh blinding) lands: the scheduler reloads from
//!   that apply's log and recomputes the next head.
//! - A stale head stops all work; it resumes when the head moves.
//! - FETCH by chain request id, at the nodes and the orchestrator, answers the
//!   latest attempt only, 404 for an unknown id and 409 after a rollback.
//! - Every request the scheduler sends, the head and the pipelined entry
//!   alike, passes the three chain verifiers.
//!
//! The key-set gate's test: a contract at key epoch 0 whose constructor
//! keys are not the orchestrator's [[nodes]] gets nothing computed and the
//! step names epoch 0; under the configured keys its head is computed.
//!
//! The class-upgrade test: two versions of the contract manifest, built for
//! two classes, and the chain switched from the first to the second (its
//! class and its circuit pins together). The scheduler driving the first
//! version reads the version in force before the class, so it hands the
//! namespace back instead of refusing the new class; the version in force
//! is then the second, and its head is computed.
//!
//! The replaced-block test: a scheduler that follows the chain itself
//! recovers, without intervention, from a replaced block holding an intake
//! (same height) and from one holding the head's apply (a shorter chain):
//! it drops what it built, steps at once at the replacement's tip, reloads
//! and recomputes, and the chain verifiers read the replacement.
//!
//! The chain verifier's test (the counter's amount is a pinned read of an
//! oracle, `tip_counter_priced`): a note-mode round never reaches the
//! verifier; the scheduler's head and pipelined requests are accepted; a
//! request for an entry below the head or never queued, one with a
//! substituted input, one on a state older than the slot, one with a wrong
//! pinned value, and any round while the contract's stored stale period
//! differs from the manifest's are refused 400 with nothing stored at any
//! node (the scheduler reads that period and computes no such head); a node whose Aztec node lies about the slot, is down or lags the
//! queue refuses, the round is refused at all three within the handshake,
//! and the queue moves on once its view is honest again. When the oracle's
//! value moves while the state does not (the held attempt's `apply` would
//! revert), the scheduler recomputes the head on the same state under a new
//! machine request id, which the nodes run and the relayer lands.
//!
//! Needs `scripts/prepare-data.sh` (the circuits and the CRS under
//! machine/data, or DATA_DIR); the tests fail naming the missing files if
//! they are absent. Run with `--release`.

mod common;

use std::ops::Deref;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use common::tip::*;
use common::*;
use serde_json::{Value, json};
use std::sync::Mutex;

use sidecar_core::bind::Elem;
use sidecar_core::field::{FieldHex, Fr, RequestId, fr_from_hex, fr_to_hex};
use sidecar_core::record;
use sidecar_core::request::{PublicValue, Request, StateKeys};
use sidecar_core::response::{ExecuteResponse, NodeResult};
use sidecar_core::{ErrorClass, Refusal};
use sidecar_http::client::Answer;
use sidecar_orchestrator::scheduler::{
    InitStep, Schedule, Scheduler, StepReport, layout_in_force, registered_layout,
};
use sidecar_tip::chain::layout::request_log_tag;
use sidecar_tip::chain::rpc::RpcError;
use sidecar_tip::chain::{PinnedSource, PinnedValue};
use sidecar_tip::state::chain::{SealedLog, next_states, sealed_log_tag};
use sidecar_tip::testing::{MEMORY_CLASS_ID, MemoryChain, block_timestamp};
use sidecar_tip::{
    ChainReader, KeyState, PinnedValues, PlainFound, Prune, QueueEntry, QueueLayout, ReaderConfig,
    SynthesisView, Transport, chain_request_id, machine_request_id, synthesise,
};

const TIP: u64 = 0x7195;
// the slot as the contract manifest writes it (fr_to_hex)
const COUNTER_KEY: &str = "0x0000000000000000000000000000000000000000000000000000000000007c01";
/// The oracle `tip_counter_priced` and `tip_counter_epoch` read their amount
/// from: the `contract` of their manifests' public reads
/// (machine/circuits/manifests).
const ORACLE: u64 = 0x0a11;
/// The note-mode key of the direct seed round.
const SEED_KEY: &str = "0xc001";
const INIT: &str = "tip_counter_init";

fn ns() -> Fr {
    Fr::from(TIP)
}

fn counter_slot() -> Fr {
    fr_from_hex(COUNTER_KEY).unwrap()
}

fn ok<T: serde::de::DeserializeOwned>(label: &str, answer: &Answer) -> T {
    answer
        .json::<T>()
        .unwrap()
        .unwrap_or_else(|e| panic!("{label}: {e}"))
}

fn expect(label: &str, answer: &Answer, class: ErrorClass, needle: &str) -> Refusal {
    let refusal = answer.json::<Value>().unwrap().unwrap_err();
    assert_eq!(refusal.class, class, "{label}: {refusal}");
    assert!(refusal.message.contains(needle), "{label}: {refusal}");
    refusal
}

// ---------------------------------------------------------------------------
// The chain-held counter's `apply`
// ---------------------------------------------------------------------------

impl Chain {
    /// `apply` of the counter's `result` for the head: refused (a revert,
    /// nothing written) when a loaded state's old commitment is not the
    /// slot; otherwise the new commitment is written and the sealed thirds
    /// are logged under the head's request.
    fn apply_sealed(
        &mut self,
        w: &World,
        clock: &Clock,
        result: &ExecuteResponse,
    ) -> Result<(), String> {
        let head = self.head_id().expect("apply on an empty queue");
        if let Some(old) = w.outputs(result).find("old_c")
            && old != self.slot
        {
            return Err(format!(
                "slot holds {}, the result read {}",
                fr_to_hex(self.slot),
                fr_to_hex(old)
            ));
        }
        let record = &result.records[0];
        let fields = SealedLog {
            new_commitments: vec![record.note_hash.fr()],
            thirds: vec![record.c.clone().map(|c| c.as_slice().to_vec())],
        }
        .to_fields()
        .unwrap();
        self.mem
            .push_log(self.ns, clock.block, sealed_log_tag(head), &fields);
        self.advance(clock, 1, Some(record.note_hash.fr()));
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// The network
// ---------------------------------------------------------------------------

/// What node 2's Aztec node answers.
#[derive(Clone, Copy, Debug, PartialEq)]
enum View {
    Honest,
    /// The counter's slot holds this commitment.
    LyingSlot(Fr),
    /// Every call fails.
    Down,
    /// The queue is behind: `tail` equals `head`, so nothing is queued.
    Behind,
}

/// One node's own Aztec node: the shared chain, as `view` says.
struct NodeView {
    mem: Arc<MemoryChain>,
    view: Mutex<View>,
}

impl NodeView {
    fn new(mem: Arc<MemoryChain>) -> Arc<Self> {
        Arc::new(NodeView {
            mem,
            view: Mutex::new(View::Honest),
        })
    }

    fn set(&self, view: View) {
        *self.view.lock().unwrap() = view;
    }
}

impl Transport for NodeView {
    async fn call(&self, method: &str, params: Value) -> Result<Value, RpcError> {
        let view = *self.view.lock().unwrap();
        let storage = method == "node_getPublicStorageAt";
        let slot = || params[2].as_str().map(|s| fr_from_hex(s).unwrap());
        let layout = QueueLayout::new(fr(QUEUE_SLOT));
        match view {
            View::Down => Err(RpcError::Transport("connection refused".into())),
            View::LyingSlot(c) if storage && slot() == Some(counter_slot()) => {
                Ok(json!(fr_to_hex(c)))
            }
            View::Behind if storage && slot() == Some(layout.tail()) => {
                let mut head = params.clone();
                head[2] = json!(fr_to_hex(layout.head_index()));
                self.mem.call(method, head).await
            }
            _ => self.mem.call(method, params).await,
        }
    }
}

/// The counter's network and its two packages' vk_hashes.
struct Counted {
    w: World,
    init_vk: FieldHex,
    counter_vk: FieldHex,
    /// Node 2's Aztec node.
    node2: Arc<NodeView>,
}

impl Deref for Counted {
    type Target = World;

    fn deref(&self) -> &World {
        &self.w
    }
}

impl World {
    async fn post<T: serde::Serialize>(&self, path: &str, body: &T) -> Answer {
        self.orch.post_json(path, body).await
    }

    /// The counter value of a stored record, opened from the three thirds
    /// with the node keys.
    fn opened(&self, result: &ExecuteResponse) -> u64 {
        let r = &result.records[0];
        let parts: Vec<Vec<Elem>> = (0..3)
            .map(|i| {
                record::open_own(
                    &self.real.keys[i],
                    ns(),
                    &r.key,
                    r.note_hash.fr(),
                    r.c[i].as_slice(),
                )
                .unwrap()
            })
            .collect();
        let value = match [&parts[0][0], &parts[1][0], &parts[2][0]] {
            [Elem::Public(a), Elem::Public(b), Elem::Public(c)] => {
                assert!(a == b && b == c);
                *a
            }
            [Elem::Shared(a), Elem::Shared(b), Elem::Shared(c)] => a.a + b.a + c.a,
            _ => panic!("the nodes disagree on the element's kind"),
        };
        small(value)
    }
}

/// Which counter round a test registers: its amount an input, an exact
/// pinned read, or an epoch read.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Counter {
    Plain,
    Priced,
    Epoch,
}

/// The counter circuit's registered name, its compiled circuit's.
fn counter(kind: Counter) -> &'static str {
    match kind {
        Counter::Plain => "tip_counter",
        Counter::Priced => "tip_counter_priced",
        Counter::Epoch => "tip_counter_epoch",
    }
}

/// The counter's namespace: the init queued, then the counter rounds.
fn namespace(kind: Counter) -> TipEntry {
    tip_namespace(ns(), COUNTER_KEY, &[INIT, counter(kind)], &[INIT])
}

/// Where the test contract keeps the init round's pins: `configure`'s flag
/// and the init's one input (`start`).
const CONFIGURED_SLOT: u64 = 0x20;
const START_SLOT: u64 = 0x22;

/// The non-secret-shared counter's namespace with `tip_counter_init` as the
/// init round, sent by the scheduler instead of queued.
fn init_namespace() -> TipEntry {
    TipEntry {
        init: Some(tip_init(INIT, CONFIGURED_SLOT, &[START_SLOT])),
        ..namespace(Counter::Plain)
    }
}

/// Three real nodes, each with the real chain verifier over its own view of
/// `mem` (node 2's is [`Counted::node2`]), and the orchestrator; the counter
/// circuit registered as `counter(kind)`.
async fn setup(tmp: &TempDir, mem: &Arc<MemoryChain>, kind: Counter) -> Counted {
    setup_with(tmp, mem, kind, namespace(kind)).await
}

/// [`setup`], the nodes' chain verifiers configured with `ns`.
async fn setup_with(tmp: &TempDir, mem: &Arc<MemoryChain>, kind: Counter, ns: TipEntry) -> Counted {
    let node2 = NodeView::new(mem.clone());
    let view2 = node2.clone();
    let packages = vec![
        Package::new(INIT, machine_manifest(INIT)),
        Package::new(counter(kind), machine_manifest(counter(kind))),
    ];
    let w = setup_viewing(tmp, mem, &ns, packages, |i| {
        if i == 2 {
            view2.clone()
        } else {
            NodeView::new(mem.clone())
        }
    })
    .await;
    Counted {
        init_vk: FieldHex(w.vk(INIT)),
        counter_vk: FieldHex(w.vk(counter(kind))),
        w,
        node2,
    }
}

/// The counter's contract on the chain.
fn contract(w: &World, clock: &Clock) -> Chain {
    Chain::new(clock, ns(), counter_slot(), w.sig_pks)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn the_scheduler_drives_a_queue_through_reverts_skips_and_supersession() {
    let tmp = TempDir::new("sched");
    let mem = Arc::new(MemoryChain::new(100));
    let w = setup(&tmp, &mem, Counter::Plain).await;
    let started = Instant::now();
    let mut clock = Clock::new(100, mem.clone());
    let mut chain = contract(&w, &clock);

    // ---- three requests, processed in order -------------------------------
    let c0 = chain.intake(&clock, w.init_vk.fr(), &[5], 1);
    let c1 = chain.intake(&clock, w.counter_vk.fr(), &[7], 2);
    let c2 = chain.intake(&clock, w.counter_vk.fr(), &[30], 3);
    let mut s = scheduler(&w, &mem, &namespace(Counter::Plain));
    let snap = clock.next();
    let r = step(&mut s, snap, "first").await;
    assert!(r.reloaded, "the first step loads the live state");
    assert_eq!(r.error, None);
    assert_eq!(computed(&r), [0, 1], "the head and one pipelined entry");
    assert_eq!(r.computed[0].circuit, "tip_counter_init");
    assert!(r.computed[0].old.is_empty());
    // the pipelined entry ran on the head's result, not yet on chain
    let n0 = r.computed[0].new[0].commitment;
    assert_eq!(r.computed[1].old[COUNTER_KEY], n0);
    assert_eq!(
        r.computed[1].request_id.fr(),
        machine_request_id(c1, &[n0], &[])
    );
    assert!(w.has_row(c0) && w.has_row(c1));
    assert!(
        !w.has_row(c2),
        "an entry outside the head window was computed"
    );
    assert_eq!(w.verified.load(Ordering::SeqCst), 6);

    let snap = clock.next();
    let r = step(&mut s, snap, "nothing new").await;
    assert!(!r.reloaded && computed(&r).is_empty() && r.error.is_none());
    assert!(!w.has_row(c2));

    // The FETCH routes answer: each node's by chain request id equals its
    // FETCH by the machine request id; the orchestrator's assembles them.
    let attempt0 = s.attempts().next().unwrap().clone();
    let body =
        serde_json::to_vec(&json!({"namespace": FieldHex(ns()), "chain_request_id": FieldHex(c0)}))
            .unwrap();
    let by_id = serde_json::to_vec(
        &json!({"namespace": FieldHex(ns()), "request_id": attempt0.request_id}),
    )
    .unwrap();
    let chained = w.real.post_same(&w.certs, "/v1/fetch/chain", &body).await;
    let direct = w.real.post_same(&w.certs, "/v1/fetch", &by_id).await;
    for i in 0..3 {
        let a: NodeResult = ok("node fetch by chain", &chained[i]);
        let b: NodeResult = ok("node fetch", &direct[i]);
        assert_eq!(a, b, "node {i}");
        assert_eq!(a.request_id, attempt0.request_id);
    }
    let landed0 = w.latest("fetch c0", c0).await;
    assert_eq!(landed0.request_id, attempt0.request_id);
    assert_eq!(landed0.vk_hash, w.init_vk);
    assert_eq!(w.opened(&landed0), 5);
    chain.apply_sealed(&w, &clock, &landed0).unwrap();

    let snap = clock.next();
    let r = step(&mut s, snap, "after apply 0").await;
    assert!(
        !r.reloaded,
        "the landed result is the one the scheduler expected"
    );
    assert_eq!(computed(&r), [2], "the next entry, on entry 1's result");
    let n1 = s.attempts().next().unwrap().new[0].commitment;
    assert_eq!(r.computed[0].old[COUNTER_KEY], n1);
    assert!(w.has_row(c2));

    // ---- a reverted apply -------------------------------------------------
    // The relayer's apply of entry 1 reverts: nothing on chain moves.
    let before: Vec<_> = s.attempts().cloned().collect();
    let snap = clock.next();
    let r = step(&mut s, snap, "after a reverted apply").await;
    assert!(!r.reloaded && computed(&r).is_empty());
    assert_eq!(s.attempts().cloned().collect::<Vec<_>>(), before);
    // A scheduler that starts afresh reloads entry 0's state from its log and
    // recomputes the head against the old commitment: the same machine
    // request id, so the nodes answer it from their rows (a replay) and the
    // latest attempt per chain request id is unchanged.
    let verified = w.verified.load(Ordering::SeqCst);
    let mut s = scheduler(&w, &mem, &namespace(Counter::Plain));
    let snap = clock.next();
    let r = step(&mut s, snap, "a fresh scheduler").await;
    assert!(r.reloaded);
    assert_eq!(computed(&r), [1, 2]);
    assert_eq!(
        r.computed[0].old[COUNTER_KEY], n0,
        "against the old commitment"
    );
    assert_eq!(r.computed[0].request_id, before[0].request_id);
    assert_eq!(r.computed[1].request_id, before[1].request_id);
    assert_eq!(r.computed[0].new, before[0].new, "answered from the row");
    assert_eq!(w.verified.load(Ordering::SeqCst), verified + 6);
    assert_eq!(
        w.latest("fetch c1", c1).await.request_id,
        before[0].request_id
    );
    // The relayer's retry lands.
    let landed1 = w.latest("fetch c1", c1).await;
    assert_eq!(w.opened(&landed1), 12);
    chain.apply_sealed(&w, &clock, &landed1).unwrap();

    // ---- a skip -----------------------------------------------------------
    let c3 = chain.intake(&clock, w.counter_vk.fr(), &[1], 4);
    let snap = clock.next();
    let r = step(&mut s, snap, "head 2, entry 3 queued").await;
    assert!(!r.reloaded);
    assert_eq!(computed(&r), [3], "entry 3 on entry 2's result");
    let pipelined3 = r.computed[0].clone();
    // Entry 2 is skipped once stale: the head moves, the slot keeps entry
    // 1's state.
    clock.later(STALE_BLOCKS);
    chain.skip(&clock);
    let snap = clock.next();
    let r = step(&mut s, snap, "after a skip").await;
    assert!(r.reloaded, "the slot is not entry 2's result");
    assert_eq!(computed(&r), [3]);
    assert_eq!(
        r.computed[0].old[COUNTER_KEY], n1,
        "recomputed on entry 1's state"
    );
    assert_ne!(r.computed[0].request_id, pipelined3.request_id);
    // FETCH by chain request id answers only the latest attempt; the result
    // pipelined on entry 2 would revert.
    let latest3 = w.latest("fetch c3", c3).await;
    assert_eq!(latest3.request_id, r.computed[0].request_id);
    let direct3 = w
        .post(
            "/v1/fetch",
            &json!({"namespace": FieldHex(ns()), "request_id": pipelined3.request_id}),
        )
        .await;
    let superseded3: ExecuteResponse = ok("fetch the superseded attempt", &direct3);
    assert!(
        chain.apply_sealed(&w, &clock, &superseded3).is_err(),
        "a stale attempt reverts"
    );

    // ---- a superseded result landed by someone else ------------------------
    let c4 = chain.intake(&clock, w.counter_vk.fr(), &[2], 5);
    let snap = clock.next();
    let r = step(&mut s, snap, "entry 4 queued").await;
    assert_eq!(computed(&r), [4], "entry 4 on the scheduler's entry 3");
    let ours3 = s.attempts().next().unwrap().clone();
    // A result the scheduler did not produce: the nodes' rows of the round
    // are pruned (the retention window passed), and someone else resends the
    // same synthesised request (the same machine request id), which the
    // nodes now run as a new round under a fresh blinding, and lands it.
    let theirs: Request = sidecar_tip::synthesise(
        &sidecar_tip::SynthesisView {
            namespace: ns(),
            entry: sidecar_tip::QueueEntry {
                index: 3,
                chain_request_id: c3,
            },
            state_keys: &namespace(Counter::Plain).circuits["tip_counter"],
            pinned: &Default::default(),
            state: &next_states(&landed1).unwrap(),
            node_values: &sidecar_tip::PublicMap::new(),
        },
        &w.package("tip_counter"),
        &PlainFound::new(vec![Fr::from(1u64)], Fr::from(4u64)),
    )
    .unwrap()
    .request;
    assert_eq!(
        theirs.request_id, ours3.request_id,
        "the scheduler's own synthesis"
    );
    for app in &w.real.apps {
        assert!(app.node.prune_requests(u64::MAX).unwrap() > 0);
    }
    assert!(!w.has_row(c3));
    let theirs: ExecuteResponse = ok("their attempt", &w.post("/v1/execute", &theirs).await);
    assert_eq!(theirs.request_id, ours3.request_id);
    assert_ne!(
        theirs.records[0].note_hash.fr(),
        ours3.new[0].commitment,
        "a fresh blinding"
    );
    let latest3 = w.latest("fetch c3", c3).await;
    assert_eq!(latest3.records, theirs.records);
    chain.apply_sealed(&w, &clock, &theirs).unwrap();
    let snap = clock.next();
    let r = step(&mut s, snap, "after a superseded result landed").await;
    assert!(
        r.reloaded,
        "the slot holds a commitment the scheduler did not produce"
    );
    assert_eq!(computed(&r), [4]);
    let n3 = theirs.records[0].note_hash.fr();
    assert_eq!(
        r.computed[0].old[COUNTER_KEY], n3,
        "on their result, from its log"
    );
    let landed4 = w.latest("fetch c4", c4).await;
    assert_eq!(landed4.request_id, r.computed[0].request_id);
    assert_eq!(w.opened(&landed4), 5 + 7 + 1 + 2);
    chain.apply_sealed(&w, &clock, &landed4).unwrap();

    // ---- a stale head -----------------------------------------------------
    let snap = clock.next();
    let r = step(&mut s, snap, "an empty queue").await;
    assert!(computed(&r).is_empty() && r.error.is_none());
    let c5 = chain.intake(&clock, w.counter_vk.fr(), &[100], 6);
    let c6 = chain.intake(&clock, w.counter_vk.fr(), &[1000], 7);
    // The head is skippable from head_since + stale_blocks (50, the default).
    clock.block = chain.since + 49;
    let snap = clock.next();
    let r = step(&mut s, snap, "a stale head").await;
    assert!(r.stale);
    assert!(computed(&r).is_empty());
    assert!(!w.has_row(c5) && !w.has_row(c6), "work on a stale head");
    let snap = clock.next();
    assert!(step(&mut s, snap, "still stale").await.stale);
    chain.skip(&clock);
    let snap = clock.next();
    let r = step(&mut s, snap, "after the stale head was skipped").await;
    assert!(!r.stale);
    assert_eq!(computed(&r), [6]);
    assert_eq!(
        r.computed[0].old[COUNTER_KEY],
        landed4.records[0].note_hash.fr()
    );
    assert!(!w.has_row(c5), "the skipped head was never computed");
    let attempt6 = r.computed[0].clone();
    assert_eq!(w.opened(&w.latest("fetch c6", c6).await), 15 + 1000);

    // ---- FETCH by chain request id after a rollback -----------------------
    w.real.restore(ns(), attempt6.request_id).await;
    expect(
        "fetch after rollback",
        &w.fetch_chain(ns(), c6).await,
        ErrorClass::Conflict,
        "rolled back",
    );
    let body =
        serde_json::to_vec(&json!({"namespace": FieldHex(ns()), "chain_request_id": FieldHex(c6)}))
            .unwrap();
    for answer in w.real.post_same(&w.certs, "/v1/fetch/chain", &body).await {
        expect(
            "node fetch after rollback",
            &answer,
            ErrorClass::Conflict,
            "rolled back",
        );
    }
    expect(
        "fetch an unknown chain request",
        &w.fetch_chain(ns(), c5).await,
        ErrorClass::NotFound,
        "",
    );
    expect(
        "a malformed body",
        &w.orch
            .post("/v1/fetch/chain", "{\"namespace\": \"0x1\"}")
            .await,
        ErrorClass::BadRequest,
        "chain_request_id",
    );
    eprintln!("SCHEDULER: {:.3}s in all", started.elapsed().as_secs_f64());
}

// ---------------------------------------------------------------------------
// The chain verifier
// ---------------------------------------------------------------------------

// The key-set gate at key epoch 0 (docs/ARCHITECTURE.md section 6, "The
// machine"): a contract that has never rotated carries the constructor's
// `node_sig_keys`, and so does a contract with a fixed key set, which never
// writes the key-epoch slot. When they are not the orchestrator's [[nodes]]
// (the orchestrator reconfigured after a replacement before this contract's
// rotation landed, or for good under a fixed key set; here the same three
// keys in another node order), a step computes nothing, names epoch 0 and,
// as the contract manifest says node_keys fixed, the redeployment, and no
// node is reached; once the
// contract's keys are the configured ones the head is computed, as a fixed
// key set's namespace is served for its whole life.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn the_key_set_gate_compares_key_epoch_0_with_the_configured_set() {
    let tmp = TempDir::new("sched-epoch0");
    let mem = Arc::new(MemoryChain::new(100));
    let w = setup(&tmp, &mem, Counter::Plain).await;
    let mut clock = Clock::new(100, mem.clone());
    let mut chain = contract(&w, &clock);
    let c0 = chain.intake(&clock, w.init_vk.fr(), &[5], 1);
    let configured = sig_keys_of(&w.real.pins());
    let mut s = scheduler(&w, &mem, &namespace(Counter::Plain));

    // ---- epoch 0 under another key set: nothing is computed ---------------
    let other = [configured[1], configured[0], configured[2]];
    pin_epoch0(&mem, ns(), Fr::from(STALE_SLOT), other);
    for label in ["epoch 0, another set", "epoch 0, another set, again"] {
        let snap = clock.next();
        let r = step(&mut s, snap, label).await;
        assert!(computed(&r).is_empty(), "{label}: {r:?}");
        let why = r.error.as_deref().unwrap_or_default();
        assert!(why.contains("key epoch 0"), "{label}: {why}");
        assert!(why.contains("[[nodes]]"), "{label}: {why}");
        // the test contract manifest says node_keys fixed (TipFacts)
        assert!(why.contains("node_keys fixed"), "{label}: {why}");
        assert!(why.contains("redeployed"), "{label}: {why}");
        assert!(!w.has_row(c0), "{label}: a node holds the head");
        assert_eq!(w.verified.load(Ordering::SeqCst), 0, "{label}");
        assert_eq!(s.attempts().count(), 0, "{label}");
    }

    // ---- epoch 0 under the configured set: the head is computed ------------
    pin_epoch0(&mem, ns(), Fr::from(STALE_SLOT), configured);
    let snap = clock.next();
    let r = step(&mut s, snap, "epoch 0, the configured set").await;
    assert_eq!(r.error, None);
    assert_eq!(computed(&r), [0]);
    assert_eq!(r.computed[0].circuit, "tip_counter_init");
    assert!(w.has_row(c0));
    assert_eq!(w.verified.load(Ordering::SeqCst), 3);
}

/// A class upgrade (`upgrades: contract`): the counter's contract manifest
/// registered at seq 0 for the in-memory chain's class and at seq 1 for
/// another, the constructor's pins naming the first. The chain then switches
/// both at one block, as `upgrade_contract` schedules them: the instance
/// runs the second class and the pins name the second version. A scheduler
/// driving the first version must read the version in force first: it
/// names the pins and hands the namespace back (its run returns), where a
/// class check first would refuse the new class at every step and never
/// return. The version in force is then the second, whose head is computed
/// and accepted by the three chain verifiers.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_class_upgrade_moves_the_scheduler_to_the_version_the_pins_name() {
    let tmp = TempDir::new("sched-class");
    let mem = Arc::new(MemoryChain::new(100));
    let entry = namespace(Counter::Plain);
    let round = counter(Counter::Plain);
    let net = start(
        &tmp,
        mem.clone(),
        &["pss_seed", INIT, round],
        std::slice::from_ref(&entry),
    )
    .await;
    let packages = [
        TestPackage::new("pss_seed", manifest("amm", "pss_seed")),
        tip_package(&entry, INIT, INIT, machine_manifest(INIT)),
        tip_package(&entry, round, round, machine_manifest(round)),
    ];
    let version = |class_id: Fr| {
        let tip = TipFacts {
            upgrades: "contract",
            class_id,
            ..facts(&entry, &packages, packages.len(), Some(STALE_BLOCKS)).upgradable()
        };
        contract_manifest("tip", &packages, Some(&tip), vk_hash)
    };
    let (old_class, new_class) = (Fr::from(MEMORY_CLASS_ID), Fr::from(MEMORY_CLASS_ID + 1));
    net.register_body(&signed_register(ns(), version(old_class), 0))
        .await;
    let old = registered_layout(&net.orch.app, ns()).unwrap().unwrap();
    net.register_body(&signed_register(ns(), version(new_class), 1))
        .await;
    let new = registered_layout(&net.orch.app, ns()).unwrap().unwrap();
    assert_eq!((old.class_id, new.class_id), (old_class, new_class));
    let pins = old.circuit_pins.expect("an upgradable layout has pins");
    mem.set_storage(ns(), pins.constructor_manifest_hash, old.manifest_hash);
    let mut clock = Clock::new(100, mem.clone());
    let mut chain = Chain::new(&clock, ns(), counter_slot(), net.sig_pks);

    // ---- the first version in force: the scheduler drives it --------------
    let reader = ChainReader::new(mem.clone());
    let first = layout_in_force(&net.orch.app, &reader, ns())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(first.manifest_hash, old.manifest_hash);
    let mut s = Scheduler::new(net.orch.app.clone(), reader, Schedule::new(first, 1));
    let r = step(&mut s, clock.next(), "the first version").await;
    assert_eq!(r.error, None);

    // ---- the class and the pins switch at one block ------------------------
    let at = clock.block + 1;
    mem.set_class(ns(), Some(new_class));
    mem.set_storage(ns(), pins.slots.metadata, Fr::from(block_timestamp(at)));
    mem.set_storage(ns(), pins.slots.after[0], new_class);
    mem.set_storage(ns(), pins.slots.after[1], new.manifest_hash);
    let c0 = chain.intake(&clock, vk_hash(INIT), &[5], 1);
    let r = step(&mut s, clock.next(), "the switch, under the first version").await;
    let why = r.error.as_deref().unwrap_or_default();
    assert!(
        why.contains("circuit pins name contract manifest"),
        "the first version must yield to the pins, not refuse the class: {why}"
    );
    assert!(computed(&r).is_empty(), "{r:?}");
    assert!(!net.has_row(ns(), c0));
    let reader = tokio::time::timeout(Duration::from_secs(30), s.run())
        .await
        .expect("the scheduler hands the namespace back once the pins name another version");

    // ---- the second version in force: its head is computed ----------------
    let second = layout_in_force(&net.orch.app, &reader, ns())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(second.manifest_hash, new.manifest_hash);
    let mut s = Scheduler::new(net.orch.app.clone(), reader, Schedule::new(second, 1));
    let r = step(&mut s, clock.next(), "the second version").await;
    assert_eq!(r.error, None);
    assert_eq!(computed(&r), [0]);
    assert_eq!(r.computed[0].circuit, INIT);
    assert!(net.has_row(ns(), c0));
    assert_eq!(net.verified.load(Ordering::SeqCst), 3);
}

/// A scheduler that follows the chain itself ([`Scheduler::follow`]), as
/// its run loop does, with a follow timeout short enough that waiting for a
/// block that never comes fails the test instead of stalling it.
fn following(w: &World, mem: &Arc<MemoryChain>) -> Scheduler<Arc<MemoryChain>> {
    let config = ReaderConfig {
        poll_interval: Duration::from_millis(20),
        follow_timeout: Duration::from_secs(2),
        ..ReaderConfig::default()
    };
    Scheduler::new(
        w.orch.app.clone(),
        ChainReader::with_config(mem.clone(), config),
        schedule(w, &namespace(Counter::Plain)),
    )
}

/// One turn of the scheduler's run loop, which must not fail.
async fn follow(s: &mut Scheduler<Arc<MemoryChain>>, label: &str) -> StepReport {
    let report = s.follow().await.unwrap_or_else(|e| panic!("{label}: {e}"));
    eprintln!(
        "FOLLOW {label} (block {}, head {}, tail {}): replaced {:?}, reloaded {}, computed {:?}, \
         error {:?}",
        report.block,
        report.head,
        report.tail,
        report.replaced,
        report.reloaded,
        computed(&report),
        report.error
    );
    report
}

/// A replaced proposed block, recovered without intervention: the scheduler
/// follows the chain itself, so it alone notices the replacement.
///
/// - The block holding an intake is replaced at the same height by one
///   holding another request: the scheduler drops its attempts, steps at
///   once at the same block number (no wait for a new block), reloads and
///   recomputes the head (the same machine request id: its reads did not
///   change) and the new entry; the three chain verifiers, whose followers
///   held the replaced block, read the replacement and accept both.
/// - The block holding the head's apply is replaced by a shorter chain
///   without it: the scheduler steps at the lower tip, finds the head back
///   at entry 0 and recomputes both entries (both replays the nodes answer
///   from their rows); the relayer lands them again and the counter holds
///   the sum of the replacement's inputs.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn the_scheduler_recomputes_when_a_proposed_block_is_replaced() {
    let tmp = TempDir::new("sched-replaced");
    let mem = Arc::new(MemoryChain::new(100));
    let w = setup(&tmp, &mem, Counter::Plain).await;
    let mut clock = Clock::new(100, mem.clone());
    let mut chain = contract(&w, &clock);

    // ---- an intake replaced at the same height ----------------------------
    let c0 = chain.intake(&clock, w.init_vk.fr(), &[5], 1);
    clock.next();
    let c1 = chain.intake(&clock, w.counter_vk.fr(), &[7], 2);
    let mut s = following(&w, &mem);
    let r = follow(&mut s, "block 101").await;
    assert_eq!((r.block, r.replaced, r.error.clone()), (101, None, None));
    assert_eq!(computed(&r), [0, 1]);
    assert_eq!(r.computed[1].chain_request_id, c1);
    let head0 = r.computed[0].request_id;
    // Block 101 is replaced: its intake of c1 is gone, and c1b is queued in
    // its place in the replacement block 101.
    mem.node().replace_from(101);
    let gone = chain.ids.pop().unwrap();
    mem.set_storage(ns(), chain.layout.seen(gone), fr(0));
    let c1b = chain.intake(&clock, w.counter_vk.fr(), &[9], 3);
    let verified = w.verified.load(Ordering::SeqCst);
    let r = follow(&mut s, "block 101 replaced").await;
    // the scheduler's reader has followed block 101 only, so the replacement
    // reaches below every block hash it holds
    assert_eq!(
        r.replaced,
        Some(Prune {
            from: 101,
            to: 100,
            below_kept: true
        })
    );
    assert_eq!(r.block, 101, "stepped at once, without a new block");
    assert!(r.reloaded, "the speculative state was dropped");
    assert_eq!(r.error, None);
    assert_eq!(computed(&r), [0, 1]);
    assert_eq!(r.computed[0].request_id, head0, "the head's reads stood");
    assert_eq!(r.computed[1].chain_request_id, c1b);
    assert_eq!(
        s.attempts().map(|a| a.chain_request_id).collect::<Vec<_>>(),
        [c0, c1b],
        "nothing built on the replaced block is held"
    );
    assert_eq!(w.verified.load(Ordering::SeqCst), verified + 6);

    // ---- an apply replaced by a shorter chain -----------------------------
    let landed0 = w.latest("fetch c0", c0).await;
    assert_eq!(landed0.request_id, head0);
    let before = (chain.head, chain.since, chain.slot);
    clock.next();
    chain.apply_sealed(&w, &clock, &landed0).unwrap();
    let r = follow(&mut s, "after apply 0").await;
    assert_eq!((r.block, r.head, r.replaced), (102, 1, None));
    assert!(!r.reloaded && computed(&r).is_empty());
    let entry1 = s.attempts().next().unwrap().request_id;
    // Block 102 is replaced by a chain whose tip is 101: the apply is gone.
    mem.node().replace_from(102);
    (chain.head, chain.since, chain.slot) = before;
    mem.set_storage(ns(), chain.layout.done(0), Fr::from(0u64));
    chain.write();
    clock.block = 101;
    mem.set_tip(101);
    let r = follow(&mut s, "block 102 gone").await;
    assert_eq!(
        r.replaced,
        Some(Prune {
            from: 102,
            to: 101,
            below_kept: false
        })
    );
    assert_eq!((r.block, r.head), (101, 0), "stepped at the lower tip");
    assert!(r.reloaded);
    assert_eq!(computed(&r), [0, 1]);
    assert_eq!(r.computed[0].request_id, head0);
    assert_eq!(r.computed[1].request_id, entry1);
    // The relayer lands both again on the replacement chain.
    clock.next();
    chain
        .apply_sealed(&w, &clock, &w.latest("fetch c0 again", c0).await)
        .unwrap();
    let r = follow(&mut s, "apply 0 again").await;
    assert!(!r.reloaded && r.replaced.is_none() && r.error.is_none());
    let landed1 = w.latest("fetch c1b", c1b).await;
    assert_eq!(landed1.request_id, entry1);
    assert_eq!(w.opened(&landed1), 14, "5 + 9: the replacement's input");
    clock.next();
    chain.apply_sealed(&w, &clock, &landed1).unwrap();
    let r = follow(&mut s, "apply 1").await;
    assert_eq!((r.head, r.tail), (2, 2));
    assert!(!r.reloaded && r.error.is_none());

    // ---- replacements back to the settled block ----------------------------
    // Blocks with no logs, the proven tip moving twice (the in-memory node
    // finalizes the proven tip before each move): the reader holds the
    // hashes back to the settled block, the finalized tip, so a replacement
    // at the proven tip or between the two is placed exactly, and one that
    // reaches the settled block is past every hash it holds. Each voids the
    // last step's reads: the scheduler drops its state, reloads and steps
    // at once.
    let quiet = clock.block;
    for _ in 0..3 {
        clock.next();
        follow(&mut s, "a quiet block").await;
    }
    for proven in [quiet + 1, quiet + 3] {
        clock.prove_to(proven);
        clock.next();
        follow(&mut s, "the proven tip moved").await;
    }
    assert_eq!(s.reader().settled().await, quiet + 1);
    let held = s.reader().held().await;
    assert_eq!(
        (held.lowest, held.tip, held.blocks),
        (Some(quiet + 1), quiet + 5, 5)
    );
    for (first, to, below_kept, label) in [
        (quiet + 3, quiet + 2, false, "replaced at the proven tip"),
        (
            quiet + 2,
            quiet + 1,
            false,
            "replaced between the settled block and the proven tip",
        ),
        (quiet + 1, quiet, true, "replaced at the settled block"),
    ] {
        mem.node().replace_from(first);
        let r = follow(&mut s, label).await;
        assert_eq!(
            r.replaced,
            Some(Prune {
                from: quiet + 5,
                to,
                below_kept
            }),
            "{label}"
        );
        assert_eq!(r.block, quiet + 5, "{label}: stepped at once");
        assert!(r.reloaded, "{label}: the state was dropped and reloaded");
        assert_eq!((r.head, r.tail, r.error), (2, 2, None), "{label}");
    }
}

/// The init round sent by the scheduler: nothing before `configure`; once
/// the contract is configured, the init round, exactly once, which the three
/// chain verifiers accept and the relayer lands through the app's init
/// function (the slot written, the sealed thirds logged under the init id);
/// then the queue, on the init's state without a reload, or, for a fresh
/// scheduler, reloaded from the init's log.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn the_scheduler_sends_the_init_round_once_configured() {
    let tmp = TempDir::new("sched-init");
    let mem = Arc::new(MemoryChain::new(100));
    let w = setup_with(&tmp, &mem, Counter::Plain, init_namespace()).await;
    let started = Instant::now();
    let mut clock = Clock::new(100, mem.clone());
    let mut chain = contract(&w, &clock);
    mem.set_storage(ns(), Fr::from(START_SLOT), Fr::from(5u64));
    let fresh = |w: &World| {
        Scheduler::new(
            w.orch.app.clone(),
            ChainReader::new(mem.clone()),
            schedule(w, &init_namespace()),
        )
    };
    let mut s = fresh(&w);

    let r = step(&mut s, clock.next(), "unconfigured").await;
    assert_eq!(r.init, Some(InitStep::Unconfigured));
    assert!(r.computed.is_empty() && r.error.is_none());
    assert_eq!(w.verified.load(Ordering::SeqCst), 0);

    // configure lands: the flag
    mem.set_storage(ns(), Fr::from(CONFIGURED_SLOT), Fr::from(1u64));
    let init_id = chain_request_id(ns(), w.init_vk.fr(), &[Fr::from(5u64)], Fr::from(0u64));
    let r = step(&mut s, clock.next(), "configured").await;
    assert_eq!(r.error, None);
    let Some(InitStep::Sent(attempt)) = r.init else {
        panic!("no init round sent: {:?}", r.init);
    };
    assert_eq!(attempt.chain_request_id, init_id);
    assert_eq!(
        attempt.request_id.fr(),
        machine_request_id(init_id, &[Fr::from(0u64)], &[]),
        "process_init's machine request id"
    );
    assert!(r.computed.is_empty(), "the queue waits for the init");
    assert_eq!(
        w.verified.load(Ordering::SeqCst),
        3,
        "three chain verifiers"
    );

    let r = step(&mut s, clock.next(), "init held").await;
    assert_eq!(r.init, Some(InitStep::Due));
    assert_eq!(w.verified.load(Ordering::SeqCst), 3, "sent once");

    // the relayer reads it by chain request id and lands it (init_pool):
    // the slot written, the thirds logged under the init id's tag
    let landed = w.latest("fetch init", init_id).await;
    assert_eq!(landed.request_id, attempt.request_id);
    assert_eq!(landed.vk_hash, w.init_vk);
    assert_eq!(w.opened(&landed), 5);
    let record = &landed.records[0];
    let fields = SealedLog {
        new_commitments: vec![record.note_hash.fr()],
        thirds: vec![record.c.clone().map(|c| c.as_slice().to_vec())],
    }
    .to_fields()
    .unwrap();
    mem.push_log(ns(), clock.block, sealed_log_tag(init_id), &fields);
    chain.slot = record.note_hash.fr();
    chain.write();
    let new_c = chain.slot;

    // the queue runs on the init's state
    let c0 = chain.intake(&clock, w.counter_vk.fr(), &[7], 2);
    let verified = w.verified.load(Ordering::SeqCst);
    let mut again = fresh(&w);
    let r = step(&mut s, clock.next(), "after the init landed").await;
    assert_eq!(r.init, Some(InitStep::Done));
    assert!(
        !r.reloaded,
        "the landed init is the attempt the scheduler held"
    );
    assert_eq!(computed(&r), [0]);
    assert_eq!(r.computed[0].old[COUNTER_KEY], new_c);
    // a fresh scheduler reloads the slot from the init's log: the same
    // attempt, a replay at the nodes
    let r2 = step(&mut again, clock.next(), "a fresh scheduler").await;
    assert_eq!(r2.init, Some(InitStep::Done));
    assert!(r2.reloaded);
    assert_eq!(r2.computed[0].request_id, r.computed[0].request_id);
    assert_eq!(w.verified.load(Ordering::SeqCst), verified + 6);
    let result = w.latest("fetch c0", c0).await;
    assert_eq!(w.opened(&result), 12);
    chain.apply_sealed(&w, &clock, &result).unwrap();
    eprintln!(
        "INIT the scheduler's init round and one queued round: {:.1}s",
        started.elapsed().as_secs_f64()
    );
}

/// The request the scheduler would build for `entry` of circuit `name`
/// (inputs and nonce as queued) on `state`, with `amount` as the oracle's
/// pinned value when the circuit has the pinned read.
fn synth(
    w: &World,
    name: &str,
    entry: QueueEntry,
    inputs: &[Fr],
    nonce: u64,
    state: &[KeyState],
    amount: Option<u64>,
) -> Request {
    let pinned = PinnedValues(
        amount
            .map(|a| PinnedValue {
                param: "amount".into(),
                contract: Fr::from(ORACLE),
                function: "get_amount()".into(),
                args: vec![],
                values: vec![Fr::from(a)],
                previous: None,
                block: 0,
                source: PinnedSource::Simulated,
            })
            .into_iter()
            .collect(),
    );
    let namespace = namespace(Counter::Priced);
    let view = SynthesisView {
        namespace: ns(),
        entry,
        state_keys: &namespace.circuits[name],
        pinned: &pinned,
        state,
        node_values: &sidecar_tip::PublicMap::new(),
    };
    let log = PlainFound::new(inputs.to_vec(), Fr::from(nonce));
    synthesise(&view, &w.package(name), &log).unwrap().request
}

/// A refused scheduler step: the head's attempt was refused naming every
/// needle, and no node holds a row for `chain`.
fn step_refused(w: &World, report: &StepReport, chain: Fr, needles: &[&str]) {
    assert!(report.computed.is_empty(), "{report:?}");
    let error = report.error.as_deref().unwrap_or("");
    for needle in needles {
        assert!(error.contains(needle), "`{needle}` not in: {error}");
    }
    assert!(!w.has_row(chain), "a refused attempt stored a row");
}

/// The snapshot at which the head's request, refused with a hold of `wait`
/// blocks at the clock's block, is sent again. When the hold spans more than
/// one block, the step at its last held block answers the kept refusal and
/// reaches no node.
async fn after_hold(
    s: &mut Scheduler<Arc<MemoryChain>>,
    w: &World,
    clock: &mut Clock,
    chain: Fr,
    wait: u64,
) -> sidecar_tip::Snapshot {
    if wait > 1 {
        clock.later(wait - 2);
        let verified = w.verified.load(Ordering::SeqCst);
        let snap = clock.next();
        let r = step(s, snap, "inside a hold").await;
        step_refused(w, &r, chain, &["not sent again before block"]);
        assert_eq!(
            w.verified.load(Ordering::SeqCst),
            verified,
            "a held request reached a node"
        );
    }
    clock.next()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn the_chain_verifier_refuses_what_its_own_view_does_not_hold() {
    let tmp = TempDir::new("verif");
    let mem = Arc::new(MemoryChain::new(100));
    let w = setup(&tmp, &mem, Counter::Priced).await;
    let started = Instant::now();
    let mut clock = Clock::new(100, mem.clone());
    let mut chain = contract(&w, &clock);
    let oracle = Fr::from(ORACLE);
    mem.set_call(oracle, "get_amount()", &[], Ok(vec![Fr::from(7u64)]));
    const PRICED: &str = "tip_counter_priced";

    // ---- note mode never reaches the verifier ------------------------------
    let seed: Request = Request {
        namespace: FieldHex(ns()),
        circuit: "pss_seed".into(),
        request_id: RequestId::from(0x5eed_0001u64),
        public: Default::default(),
        state_keys: StateKeys {
            reads: vec![],
            writes: vec![SEED_KEY.into()],
        },
        shared_inputs: vec![],
        records: vec![],
        requester: None,
        signature: None,
        chain_request_id: None,
        shared_log: None,
        manifest_hash: None,
    };
    let _: ExecuteResponse = ok("a note-mode round", &w.post("/v1/execute", &seed).await);
    assert_eq!(w.verified.load(Ordering::SeqCst), 0);

    // ---- the scheduler's head and pipelined requests pass -------------------
    let c0 = chain.intake(&clock, w.init_vk.fr(), &[5], 1);
    let c1 = chain.intake_onchain(&clock, w.counter_vk.fr(), &[], 2);
    let c2 = chain.intake_onchain(&clock, w.counter_vk.fr(), &[], 3);
    let mut s = scheduler(&w, &mem, &namespace(Counter::Priced));
    let snap = clock.next();
    let r = step(&mut s, snap, "head and pipelined").await;
    assert_eq!(r.error, None);
    assert_eq!(computed(&r), [0, 1]);
    assert_eq!(w.verified.load(Ordering::SeqCst), 6);
    let landed0 = w.latest("fetch c0", c0).await;
    chain.apply_sealed(&w, &clock, &landed0).unwrap();
    let state0 = next_states(&landed0).unwrap();

    // ---- a wrong head --------------------------------------------------------
    let applied = synth(
        &w,
        "tip_counter_init",
        QueueEntry {
            index: 0,
            chain_request_id: c0,
        },
        &[Fr::from(5u64)],
        1,
        &[],
        None,
    );
    w.refused("an entry below the head", &applied, &["is not the head"])
        .await;
    let stray = chain_request_id(ns(), w.counter_vk.fr(), &[], Fr::from(99u64));
    mem.push_log(
        ns(),
        clock.block,
        request_log_tag(stray),
        &[Fr::from(99u64)],
    );
    let never = synth(
        &w,
        PRICED,
        QueueEntry {
            index: 2,
            chain_request_id: stray,
        },
        &[],
        99,
        &state0,
        Some(7),
    );
    w.refused("an entry never queued", &never, &["is not the head"])
        .await;

    // ---- a stale slot commitment ----------------------------------------------
    let landed1 = w.latest("fetch c1", c1).await;
    chain.apply_sealed(&w, &clock, &landed1).unwrap();
    let state1 = next_states(&landed1).unwrap();
    let entry2 = QueueEntry {
        index: 2,
        chain_request_id: c2,
    };
    let old = synth(&w, PRICED, entry2, &[], 3, &state0, Some(7));
    w.refused("a stale slot commitment", &old, &["stale state record"])
        .await;

    // ---- a wrong pinned value ---------------------------------------------------
    let wrong = synth(&w, PRICED, entry2, &[], 3, &state1, Some(8));
    w.refused(
        "a wrong pinned value",
        &wrong,
        &["the pinned read `get_amount()`"],
    )
    .await;

    // ---- substituted inputs ---------------------------------------------------
    let c3 = chain.intake(&clock, w.init_vk.fr(), &[11], 4);
    let entry3 = QueueEntry {
        index: 3,
        chain_request_id: c3,
    };
    let mut swapped = synth(
        &w,
        "tip_counter_init",
        entry3,
        &[Fr::from(11u64)],
        4,
        &[],
        None,
    );
    swapped
        .public
        .insert("start".into(), PublicValue::One(FieldHex::from(12)));
    w.refused("a substituted input", &swapped, &["field `public.start`"])
        .await;
    let mut extra = synth(&w, PRICED, entry2, &[], 3, &state1, Some(7));
    extra
        .public
        .insert("bonus".into(), PublicValue::One(FieldHex::from(1)));
    w.refused("an extra input", &extra, &["field `public.bonus`"])
        .await;

    // ---- the contract's stale period differs from the manifest's ----------------
    // The scheduler reads the stored period and computes nothing for the
    // head, which no node reaches; the request it would send is refused by
    // every node's chain verifier.
    mem.set_storage(ns(), Fr::from(STALE_SLOT + 1), Fr::from(40u64));
    let verified = w.verified.load(Ordering::SeqCst);
    let snap = clock.next();
    let r = step(&mut s, snap, "a stored stale period of 40").await;
    step_refused(
        &w,
        &r,
        c2,
        &[
            "entry 2: the contract's TipConfig.stale_blocks is 40 blocks",
            "`tip_counter_priced` says 50 blocks; every node refuses its rounds",
        ],
    );
    assert!(!r.stale, "{r:?}");
    assert_eq!(
        w.verified.load(Ordering::SeqCst),
        verified,
        "the head reached a node's chain verifier"
    );
    let at40 = synth(&w, PRICED, entry2, &[], 3, &state1, Some(7));
    w.refused(
        "a stored stale period of 40",
        &at40,
        &["TipConfig.stale_blocks is 40 blocks"],
    )
    .await;
    mem.set_storage(ns(), Fr::from(STALE_SLOT + 1), Fr::from(50u64));

    // ---- node 2's Aztec node lies, fails, lags -----------------------------------
    // Each refusal holds entry 2's machine request id for 1, then 2, then 4
    // blocks (the scheduler's "Retries"), so each view is stepped at the
    // block the last hold ends: `wait` is the hold before it.
    for (view, needle, wait) in [
        (
            View::LyingSlot(Fr::from(0xdeadu64)),
            "stale state record",
            1,
        ),
        (View::Down, "connection refused", 1),
        (View::Behind, "is not the head", 2),
    ] {
        w.node2.set(view);
        let snap = after_hold(&mut s, &w, &mut clock, c2, wait).await;
        let started = Instant::now();
        let r = step(&mut s, snap, &format!("node 2 {view:?}")).await;
        step_refused(&w, &r, c2, &["node 2", needle]);
        assert!(
            started.elapsed().as_secs() < 15,
            "the other two nodes waited for the mesh"
        );
    }
    w.node2.set(View::Honest);

    // ---- an honest view again: the queue moves on ---------------------------------
    let snap = after_hold(&mut s, &w, &mut clock, c2, 4).await;
    let verified = w.verified.load(Ordering::SeqCst);
    let r = step(&mut s, snap, "honest again").await;
    assert_eq!(r.error, None);
    assert_eq!(computed(&r), [2, 3]);
    assert_eq!(w.verified.load(Ordering::SeqCst), verified + 6);
    let landed2 = w.latest("fetch c2", c2).await;
    assert_eq!(w.opened(&landed2), 5 + 7 + 7);
    chain.apply_sealed(&w, &clock, &landed2).unwrap();
    let landed3 = w.latest("fetch c3", c3).await;
    assert_eq!(w.opened(&landed3), 11);
    chain.apply_sealed(&w, &clock, &landed3).unwrap();

    // ---- a pinned value moves while the state does not -----------------------------
    // Entry 4 is computed at amount 7. The oracle moves to 9 before the
    // relayer lands it, so its apply would revert (apply rechecks the read)
    // and the slot stays. The next step finds the held attempt's pinned value
    // moved and recomputes on the same state: a new machine request id, which
    // the nodes run (under the old id the new body would be refused, 409 at
    // step 5).
    let c4 = chain.intake_onchain(&clock, w.counter_vk.fr(), &[], 5);
    let snap = clock.next();
    let r = step(&mut s, snap, "entry 4 at amount 7").await;
    assert_eq!(r.error, None);
    assert_eq!(computed(&r), [4]);
    let at7 = r.computed[0].clone();
    let n3 = landed3.records[0].note_hash.fr();
    assert_eq!(at7.old[COUNTER_KEY], n3);
    assert_eq!(at7.pinned, [Fr::from(7u64)]);
    assert_eq!(
        at7.request_id.fr(),
        machine_request_id(c4, &[n3], &[Fr::from(7u64)])
    );
    let snap = clock.next();
    let r = step(&mut s, snap, "amount still 7").await;
    assert!(!r.repriced && computed(&r).is_empty(), "{r:?}");
    mem.set_call(oracle, "get_amount()", &[], Ok(vec![Fr::from(9u64)]));
    let verified = w.verified.load(Ordering::SeqCst);
    let snap = clock.next();
    let r = step(&mut s, snap, "the amount moved to 9").await;
    assert!(r.repriced && !r.reloaded, "{r:?}");
    assert_eq!(r.error, None);
    assert_eq!(computed(&r), [4]);
    let at9 = r.computed[0].clone();
    assert_eq!(at9.old, at7.old, "the same state");
    assert_eq!(at9.pinned, [Fr::from(9u64)]);
    assert_ne!(at9.request_id, at7.request_id, "a new machine request id");
    assert_eq!(
        at9.request_id.fr(),
        machine_request_id(c4, &[n3], &[Fr::from(9u64)])
    );
    assert_eq!(w.verified.load(Ordering::SeqCst), verified + 3);
    let landed4 = w.latest("fetch c4", c4).await;
    assert_eq!(
        landed4.request_id, at9.request_id,
        "FETCH answers the recompute"
    );
    assert_eq!(w.opened(&landed4), 11 + 9);
    chain.apply_sealed(&w, &clock, &landed4).unwrap();
    let snap = clock.next();
    let r = step(&mut s, snap, "after apply 4").await;
    assert!(
        !r.repriced && !r.reloaded && computed(&r).is_empty(),
        "{r:?}"
    );
    eprintln!(
        "CHAIN VERIFIER: {:.3}s in all",
        started.elapsed().as_secs_f64()
    );
}

// ---------------------------------------------------------------------------
// An epoch read across a round
// ---------------------------------------------------------------------------

/// The oracle's epoch source: `get_amount_epoch()` answers [amount, epoch,
/// the previous epoch's amount].
fn set_epoch(mem: &MemoryChain, amount: u64, epoch: u64, previous: u64) {
    mem.set_call(
        Fr::from(ORACLE),
        "get_amount_epoch()",
        &[],
        Ok(vec![Fr::from(amount), Fr::from(epoch), Fr::from(previous)]),
    );
}

/// What `apply` checks of a counter result's epoch read against the
/// oracle's [amount, epoch, previous] now (pss_public_contract
/// `Freshness`, the rule [`PublicRead::admits`] states), the amount and its
/// epoch the result carries.
fn epoch_applies(w: &World, result: &ExecuteResponse, now: [u64; 3]) -> bool {
    let pkg = w.package("tip_counter_epoch");
    let read = &pkg.tip.public_reads()[0];
    let o = w.outputs(result);
    let used = [o.param("amount"), o.param("amount_epoch")];
    read.admits(
        &[Fr::from(now[0]), Fr::from(now[1])],
        Some(Fr::from(now[2])),
        &used,
    )
}

/// The request for entry `entry` of `tip_counter_epoch` on `state`, at
/// `amount` and `epoch` (the scheduler's, made at that read).
fn synth_epoch(
    w: &World,
    entry: QueueEntry,
    nonce: u64,
    state: &[KeyState],
    amount: u64,
    epoch: u64,
) -> Request {
    let pinned = PinnedValues(vec![PinnedValue {
        param: "amount".into(),
        contract: Fr::from(ORACLE),
        function: "get_amount_epoch()".into(),
        args: vec![],
        values: vec![Fr::from(amount), Fr::from(epoch)],
        previous: None,
        block: 0,
        source: PinnedSource::Simulated,
    }]);
    let namespace = namespace(Counter::Epoch);
    let view = SynthesisView {
        namespace: ns(),
        entry,
        state_keys: &namespace.circuits["tip_counter_epoch"],
        pinned: &pinned,
        state,
        node_values: &sidecar_tip::PublicMap::new(),
    };
    let log = PlainFound::new(vec![], Fr::from(nonce));
    synthesise(&view, &w.package("tip_counter_epoch"), &log)
        .unwrap()
        .request
}

// The amount moves while a round is in flight. Under freshness epoch the
// attempt made at epoch e lands while the oracle is at e or e + 1: the
// scheduler keeps it across one new epoch and the nodes admit a request
// made one epoch before their own read; when a second epoch opens before
// the result lands, the scheduler recomputes it exactly once and the
// recompute lands. The bound: a round lands at its first attempt when at
// most one epoch opens between the scheduler's read and apply.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn an_epoch_read_lands_across_one_epoch_and_is_recomputed_once_after_two() {
    let tmp = TempDir::new("epoch");
    let mem = Arc::new(MemoryChain::new(100));
    let w = setup(&tmp, &mem, Counter::Epoch).await;
    let started = Instant::now();
    let mut clock = Clock::new(100, mem.clone());
    let mut chain = contract(&w, &clock);
    set_epoch(&mem, 7, 1, 7);
    let mut s = scheduler(&w, &mem, &namespace(Counter::Epoch));

    // ---- one epoch opens during the round: the attempt lands ---------------
    let c0 = chain.intake(&clock, w.init_vk.fr(), &[5], 1);
    let c1 = chain.intake_onchain(&clock, w.counter_vk.fr(), &[], 2);
    let snap = clock.next();
    let r = step(&mut s, snap, "init and counter at epoch 1").await;
    assert_eq!(r.error, None);
    assert_eq!(computed(&r), [0, 1]);
    let at1 = r.computed[1].clone();
    assert_eq!(at1.pinned, [Fr::from(7u64), Fr::from(1u64)]);
    let landed0 = w.latest("fetch c0", c0).await;
    chain.apply_sealed(&w, &clock, &landed0).unwrap();
    // the oracle opens epoch 2 before the relayer lands entry 1
    set_epoch(&mem, 9, 2, 7);
    let snap = clock.next();
    let r = step(&mut s, snap, "epoch 2: the attempt at epoch 1 is kept").await;
    assert!(!r.repriced && computed(&r).is_empty(), "{r:?}");
    let landed1 = w.latest("fetch c1", c1).await;
    assert_eq!(landed1.request_id, at1.request_id, "the first attempt");
    assert!(
        epoch_applies(&w, &landed1, [9, 2, 7]),
        "apply admits epoch 1 at epoch 2"
    );
    assert!(
        !epoch_applies(&w, &landed1, [11, 3, 9]),
        "and not at epoch 3"
    );
    assert_eq!(w.opened(&landed1), 5 + 7);
    chain.apply_sealed(&w, &clock, &landed1).unwrap();
    let state1 = next_states(&landed1).unwrap();

    // ---- the nodes admit a request one epoch behind their read -------------
    let c2 = chain.intake_onchain(&clock, w.counter_vk.fr(), &[], 3);
    let entry2 = QueueEntry {
        index: 2,
        chain_request_id: c2,
    };
    set_epoch(&mem, 11, 3, 9);
    let _ = clock.next();
    let two_behind = synth_epoch(&w, entry2, 3, &state1, 7, 1);
    w.refused(
        "an epoch two behind",
        &two_behind,
        &["the pinned read `get_amount_epoch()`"],
    )
    .await;
    let wrong = synth_epoch(&w, entry2, 3, &state1, 8, 2);
    w.refused(
        "the epoch before at another amount",
        &wrong,
        &["the pinned read `get_amount_epoch()`"],
    )
    .await;
    let behind = synth_epoch(&w, entry2, 3, &state1, 9, 2);
    let at2: ExecuteResponse = ok(
        "a request one epoch behind",
        &w.post("/v1/execute", &behind).await,
    );
    assert_eq!(at2.request_id, behind.request_id);
    let current = synth_epoch(&w, entry2, 3, &state1, 11, 3);
    let _: ExecuteResponse = ok(
        "a request at the current epoch",
        &w.post("/v1/execute", &current).await,
    );

    // ---- two epochs open during the round: recomputed exactly once ---------
    let snap = clock.next();
    let r = step(&mut s, snap, "entry 2 at epoch 3").await;
    assert_eq!(r.error, None);
    assert_eq!(computed(&r), [2]);
    let at3 = r.computed[0].clone();
    assert_eq!(at3.pinned, [Fr::from(11u64), Fr::from(3u64)]);
    set_epoch(&mem, 13, 4, 11);
    let snap = clock.next();
    let r = step(&mut s, snap, "epoch 4: kept").await;
    assert!(!r.repriced && computed(&r).is_empty(), "{r:?}");
    set_epoch(&mem, 15, 5, 13);
    let snap = clock.next();
    let r = step(&mut s, snap, "epoch 5: recomputed").await;
    assert!(r.repriced && !r.reloaded, "{r:?}");
    assert_eq!(r.error, None);
    assert_eq!(computed(&r), [2]);
    let at5 = r.computed[0].clone();
    assert_eq!(at5.old, at3.old, "the same state");
    assert_eq!(at5.pinned, [Fr::from(15u64), Fr::from(5u64)]);
    assert_eq!(
        at5.request_id.fr(),
        machine_request_id(c2, &[state1[0].commitment], &at5.pinned)
    );
    let snap = clock.next();
    let r = step(&mut s, snap, "epoch 5 still: nothing more").await;
    assert!(!r.repriced && computed(&r).is_empty(), "{r:?}");
    let landed2 = w.latest("fetch c2", c2).await;
    assert_eq!(
        landed2.request_id, at5.request_id,
        "FETCH answers the recompute"
    );
    assert!(epoch_applies(&w, &landed2, [15, 5, 13]));
    assert_eq!(w.opened(&landed2), 5 + 7 + 15);
    chain.apply_sealed(&w, &clock, &landed2).unwrap();
    let snap = clock.next();
    let r = step(&mut s, snap, "after apply 2").await;
    assert!(
        !r.repriced && !r.reloaded && computed(&r).is_empty(),
        "{r:?}"
    );
    eprintln!("EPOCH READ: {:.3}s in all", started.elapsed().as_secs_f64());
}
