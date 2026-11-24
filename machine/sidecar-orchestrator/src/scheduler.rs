//! The tip's scheduler (docs/ARCHITECTURE.md section 1, "The coordinator
//! (tip)"; section 6, "scheduler"): the one driver the tip adds. One
//! [`Scheduler`] per namespace (one queue each) follows the chain
//! reader's snapshots, synthesises the head's request
//! ([`sidecar_tip::synthesise`]) and runs it through the ordinary execute
//! path ([`crate::api::run_execute`]: the stateless checks, the global
//! session lock, projection, fan-out, agreement, proof verification, the
//! three signature checks, record assembly). Each node then runs steps 4 to
//! 16 as for any request, its chain verifier at step 4.
//!
//! One step, at one snapshot:
//!
//! ```text
//! read      the queue (head, head_since, tail, the window), every slot and,
//!           for a namespace with an init round, its pins (sidecar_tip::init)
//! reconcile drop the attempts the head has passed, applying each one's new
//!           state to the live state; if any slot differs from what that
//!           gives, or a remaining attempt does not chain from it, discard
//!           every attempt (the speculative state) and reload the live state
//!           of each slot through its key's tip state (sidecar_tip::TipState);
//!           a held init attempt whose commitments the slots now hold landed
//! init      until the contract is configured, compute nothing; once it is,
//!           while every slot the init creates is empty, send the init round
//!           (once: its attempt is held until the slots move, and a resend
//!           after a restart or a refusal is a replay the nodes answer from
//!           their rows) and compute nothing for the queue
//! stale     a head every node's chain verifier refuses (the contract's
//!           stored TipConfig.stale_blocks is not its manifest's) or the
//!           chain may skip (head_since + stale_blocks reached): compute
//!           nothing until the head or the stored period moves
//! reprice   a held attempt whose pinned values the chain's no longer
//!           admit (each read's freshness policy: under `exact` an oracle
//!           price that moved, under `epoch` one two epochs on, under
//!           `tolerance` one out of the band; its apply would revert) is
//!           discarded with the attempts after it
//! compute   the head, then up to `pipeline_depth` entries after it, each on
//!           the state the attempt before it leaves (the speculative state:
//!           the previous result's, not yet on chain); entries that already
//!           have an attempt are kept
//! ```
//!
//! Before a step, a replaced block: when the reader's snapshot reports
//! that blocks the scheduler read were replaced (the follower's prune event,
//! [`sidecar_tip::Prune::voids`]: the scheduler's held state and attempts
//! rest on the reads of its last step, at that step's block and the logs up
//! to it), every attempt, the held init attempt and the live state are
//! dropped, and the step runs at once at the replacement chain's tip,
//! however high it is: it reloads the queue and the live state from the
//! chain as it stands and recomputes the head. An attempt whose reads the
//! replacement did not change is the same machine request id, which the
//! nodes answer from their rows; a result built on the replaced block that
//! the relayer still lands reverts at `apply` (`requests[head]` or a slot
//! differs), harmlessly.
//! Each step parses the namespace's queued packages from the registry copy
//! once, at its start, and every part of the step reads that parse, so a
//! REGISTER that lands mid-step is seen from the next step on.
//!
//! A recompute at a moved pinned value is a new request (the machine request
//! id covers the pinned values), so the nodes run it instead of refusing it
//! as another body under a request id they hold.
//!
//! Retries. A request the nodes refused (any class but a node failure) is
//! not sent again at every block: the machine request id covers the chain
//! request id, the old commitments and the pinned values, so the same id
//! meets the same refusal unless a node's own view moves (a node whose chain
//! reader lags, for one). The scheduler keeps the refusal ([`Refusals`]) and
//! sends that id again only after 1, 2, 4, ... blocks, at most
//! [`MAX_REFUSAL_WAIT`] blocks apart; a different id (a moved slot or pinned
//! value) runs at once. A replaced block forgets the refusals made at it
//! ([`Refusals::forget_voided`]): the chain went back, and the waits were
//! counted in block numbers that come again. A step that stopped at a
//! failure that can pass with no new block (a node failure, a chain read, an
//! entry whose inputs no node gave yet) is stepped again at the same block
//! after a backoff ([`retry_backoff`]), so a quiet chain does not leave the
//! head uncomputed.
//!
//! The scheduler keeps, per queue index, the latest attempt it computed: a
//! copy of what the nodes' rows hold (FETCH by chain request id answers the
//! latest attempt from those rows), never anything they do not (invariant
//! 12). It never computes an entry outside `head..=head + pipeline_depth`.
//! Nothing it reads is trusted (invariant 13): a wrong view makes a request
//! the nodes or `apply` refuse, which only delays the queue.

use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use sidecar_core::field::{FieldHex, Fr, RequestId, fr_to_hex};
use sidecar_core::manifest::contract::NodeKeysAxis;
use sidecar_core::request::{NODES, Request, StateKeys};
use sidecar_core::response::ChainFetchRequest;
use sidecar_core::response::ExecuteResponse;
use sidecar_core::store::StoreRead;
use sidecar_core::tree::{TreePaths, TreeQuery};
use sidecar_core::{ErrorClass, Refusal};
use sidecar_tip::chain::TaggedLogs;
use sidecar_tip::{
    ChainAt, ChainLogs, ChainReader, Found, InitRead, IntakeLayout, IntakeLookup, KeyState, Prune,
    PublicMap, QueueEntry, QueueTarget, QueueView, ReadError, ReaderConfig, ReloadError, Snapshot,
    StoredReceipt, SynthesisView, TipFuture, TipHistory, TipLayout, TipPackage, TipState,
    Transport, TreeSource, find_entry, init_request, key_tip_state, synthesise,
};
use tokio::sync::OnceCell;
use tokio::task::JoinSet;

use crate::api::{self, Orchestrator};
use crate::config::TipConfig;
use crate::gate::Class;
use crate::nodes::{all_answers, node_answer};
use crate::status::ReaderStatus;

/// One namespace's schedule: its layout from its registered contract
/// manifest and the pipelining depth.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Schedule {
    /// The namespace's facts (`sidecar_tip::TipLayout`): its queue, stale
    /// period slot, request keys, plain reads and init round.
    pub layout: TipLayout,
    /// Requests computed after the head.
    pub pipeline_depth: usize,
}

impl Schedule {
    pub fn new(layout: TipLayout, pipeline_depth: usize) -> Self {
        Schedule {
            layout,
            pipeline_depth,
        }
    }

    fn target(&self) -> QueueTarget {
        self.layout.target()
    }
}

/// One slot as the scheduler holds it: the commitment and the state a round
/// on it runs on (none for an empty slot).
#[derive(Clone, Debug, PartialEq, Eq)]
struct Slot {
    commitment: Fr,
    state: Option<KeyState>,
}

/// The state of every slot of the schedule, by request key.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct State {
    slots: BTreeMap<String, Slot>,
}

impl State {
    fn commitments(&self) -> BTreeMap<String, Fr> {
        self.slots
            .iter()
            .map(|(k, s)| (k.clone(), s.commitment))
            .collect()
    }

    /// The state once `attempt` is applied: each key it wrote holds its new
    /// state, and a key whose new commitment is 0 stays empty.
    ///
    /// A failed round outputs, for every key it writes, the value its slot
    /// holds (pss_public_contract's `assert_failed_round_keeps_its_state`):
    /// a key it read keeps its commitment, and a key it creates keeps the
    /// empty slot's 0, which `apply` leaves in the slot. So the 0 a failed
    /// round outputs for a created key is the slot's value, not a state:
    /// the slot stays empty and holds no state, as a reload finds it.
    fn advance(&mut self, attempt: &Attempt) {
        for state in &attempt.new {
            if let Some(slot) = self.slots.get_mut(&state.key) {
                *slot = Slot {
                    commitment: state.commitment,
                    state: (state.commitment != Fr::from(0u64)).then(|| state.clone()),
                };
            }
        }
    }

    /// The state a round runs on: every slot's that has one.
    fn view(&self) -> Vec<KeyState> {
        self.slots
            .values()
            .filter_map(|s| s.state.clone())
            .collect()
    }
}

/// One computed attempt at a queue entry: the latest the scheduler ran for
/// it, which the nodes' rows hold.
#[derive(Clone, Debug, PartialEq)]
pub struct Attempt {
    pub index: u64,
    pub chain_request_id: Fr,
    /// The machine request id.
    pub request_id: RequestId,
    pub circuit: String,
    /// The commitment of each key the round loaded.
    pub old: BTreeMap<String, Fr>,
    /// The pinned values the round used, in `public_reads` order (empty for
    /// a circuit without pinned reads).
    pub pinned: Vec<Fr>,
    /// The state the round left for each key it stored, as the next round
    /// runs on it.
    pub new: Vec<KeyState>,
}

/// Where a namespace's init round stood at a step.
#[derive(Clone, Debug, PartialEq)]
pub enum InitStep {
    /// The contract is not configured: nothing was computed.
    Unconfigured,
    /// The init round is due and was sent in this step: its attempt.
    Sent(Attempt),
    /// The init round is due and was not sent: its attempt is held (the
    /// relayer lands it), or the send was refused (`StepReport::error`).
    Due,
    /// A slot the init creates is written: the queue runs.
    Done,
}

impl InitStep {
    /// The step's name, for the log.
    pub fn name(&self) -> &'static str {
        match self {
            InitStep::Unconfigured => "unconfigured",
            InitStep::Sent(_) => "sent",
            InitStep::Due => "due",
            InitStep::Done => "done",
        }
    }
}

/// What one step did.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct StepReport {
    pub block: u64,
    pub head: u64,
    pub tail: u64,
    /// The speculative state was discarded and the live state reloaded from
    /// the chain.
    pub reloaded: bool,
    /// The head may be skipped: nothing was computed. (A head the nodes
    /// refuse for the contract's stored stale period computes nothing
    /// either, named in `error`.)
    pub stale: bool,
    /// A held attempt's pinned values are no longer admitted: it and the
    /// attempts after it were discarded (and recomputed as far as the step
    /// got).
    pub repriced: bool,
    /// The attempts computed in this step, head first.
    pub computed: Vec<Attempt>,
    /// Why the step computed less than its window: the first refusal.
    pub error: Option<String>,
    /// The init round, for a namespace with one.
    pub init: Option<InitStep>,
    /// The replacement the reader reported before the step
    /// ([`Scheduler::follow`]); when it voided the scheduler's reads, the
    /// step `reloaded`.
    pub replaced: Option<Prune>,
    /// Scheduling is paused ([`Orchestrator::pause`]): the step read the
    /// queue and computed nothing.
    pub paused: bool,
    /// The step stopped at a failure that can pass with no new block (a
    /// node failure, a chain read, an entry whose inputs no node gave): the
    /// next step runs at the same block after a backoff.
    pub retry: bool,
}

/// Why a step could not read the chain or reload the state; the next
/// snapshot retries.
#[derive(Clone, Debug, PartialEq)]
pub enum StepError {
    Read(ReadError),
    /// The tip state of a slot's key found no state for the commitment the
    /// slot holds.
    NoState {
        key: String,
        commitment: Fr,
        /// Why, after "slot `key` holds c, and".
        why: String,
    },
}

impl std::fmt::Display for StepError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StepError::Read(e) => write!(f, "chain read: {e}"),
            StepError::NoState {
                key,
                commitment,
                why,
            } => write!(
                f,
                "slot `{key}` holds {}, and {why}",
                fr_to_hex(*commitment)
            ),
        }
    }
}

impl std::error::Error for StepError {}

impl From<ReadError> for StepError {
    fn from(e: ReadError) -> Self {
        StepError::Read(e)
    }
}

/// The scheduler of one namespace.
pub struct Scheduler<T> {
    app: Arc<Orchestrator>,
    reader: ChainReader<T>,
    schedule: Schedule,
    /// The chain's state at the head of the last step; `None` until loaded.
    live: Option<State>,
    /// The attempts at `head`, `head + 1`, ... in queue order.
    attempts: VecDeque<Attempt>,
    /// The init round's attempt, held while its slots are empty.
    init: Option<Attempt>,
    /// The block of the last step's reads, on which `live`, `attempts` and
    /// `init` rest; `None` before the first step.
    read_at: Option<u64>,
    /// The block [`Self::follow`] last stepped at; the next step waits for
    /// a block above it.
    followed: u64,
    /// The namespace's queued packages, parsed at the start of the step.
    packages: Vec<TipPackage>,
    /// The contract's key epoch field last seen to carry the machine's
    /// pinned key set ([`Scheduler::key_set_differs`]).
    key_epoch_ok: Option<Fr>,
    /// The requests the nodes refused, not sent again before their wait
    /// ends (module documentation, "Retries").
    refusals: std::sync::Mutex<Refusals>,
    /// The retryable failures in a row, for [`retry_backoff`].
    failures: u32,
    /// Set by a step that found the contract's circuit pins naming another
    /// contract manifest version: [`Self::run`] returns, and the caller
    /// picks the version in force again.
    reselect: bool,
}

/// The longest wait, in blocks, before a refused request is sent again.
pub const MAX_REFUSAL_WAIT: u64 = 32;

/// The longest wait before a step that stopped at a retryable failure runs
/// again.
pub const MAX_RETRY_BACKOFF: Duration = Duration::from_secs(30);

/// How long to wait before stepping again after `failures` retryable
/// failures in a row: the poll interval, doubled per failure, at most
/// [`MAX_RETRY_BACKOFF`].
pub fn retry_backoff(poll: Duration, failures: u32) -> Duration {
    poll.saturating_mul(1u32 << failures.min(16))
        .min(MAX_RETRY_BACKOFF)
        .max(poll)
}

/// One refused request: its refusal, the block it was refused at, and when
/// it may be sent again.
#[derive(Clone, Debug)]
struct Refused {
    refusal: Refusal,
    at: u64,
    wait: u64,
}

impl Refused {
    fn retry_at(&self) -> u64 {
        self.at.saturating_add(self.wait)
    }
}

/// The requests the nodes refused, by machine request id (module
/// documentation, "Retries").
#[derive(Debug, Default)]
pub struct Refusals {
    held: BTreeMap<Fr, Refused>,
}

impl Refusals {
    /// The refusal of `id` while its wait runs at `block`, said as such.
    pub fn held(&self, id: RequestId, block: u64) -> Option<Refusal> {
        let r = self.held.get(&id.0)?;
        (block < r.retry_at()).then(|| {
            Refusal::new(
                r.refusal.class,
                format!(
                    "{} (refused at block {}; not sent again before block {})",
                    r.refusal.message,
                    r.at,
                    r.retry_at()
                ),
            )
        })
    }

    /// Forget the refusals made at a block `prune` voids: the chain went
    /// back below them, so their waits, counted in block numbers that will
    /// come again, say nothing about the replacement chain.
    pub fn forget_voided(&mut self, prune: &Prune) {
        self.held.retain(|_, r| !prune.voids(r.at));
    }

    /// Keep what running `id` at `block` gave: a refusal waits one block,
    /// twice the last wait when the same class refused it before (at most
    /// [`MAX_REFUSAL_WAIT`]); a node failure (500) is not kept, nor an
    /// answer. Entries whose wait ended long ago are dropped.
    pub fn record(&mut self, id: RequestId, result: Result<(), &Refusal>, block: u64) {
        self.held
            .retain(|_, r| r.retry_at().saturating_add(MAX_REFUSAL_WAIT) >= block);
        let refusal = match result {
            Err(r) if r.class != ErrorClass::MpcFailure => r,
            _ => {
                self.held.remove(&id.0);
                return;
            }
        };
        let wait = match self.held.get(&id.0) {
            Some(last) if last.refusal.class == refusal.class => {
                (last.wait * 2).min(MAX_REFUSAL_WAIT)
            }
            _ => 1,
        };
        self.held.insert(
            id.0,
            Refused {
                refusal: refusal.clone(),
                at: block,
                wait,
            },
        );
    }
}

/// How many replacements one [`Scheduler::follow`] recovers from before it
/// gives up until the next call: each one is a new prune event, so more
/// than a few in a row is a chain that will not settle.
const REPLACEMENTS_PER_FOLLOW: usize = 3;

impl<T: Transport> Scheduler<T> {
    pub fn new(app: Arc<Orchestrator>, reader: ChainReader<T>, schedule: Schedule) -> Self {
        Scheduler {
            app,
            reader,
            schedule,
            live: None,
            attempts: VecDeque::new(),
            init: None,
            read_at: None,
            followed: 0,
            packages: Vec::new(),
            key_epoch_ok: None,
            refusals: std::sync::Mutex::new(Refusals::default()),
            failures: 0,
            reselect: false,
        }
    }

    pub fn reader(&self) -> &ChainReader<T> {
        &self.reader
    }

    /// The attempts held for the window, head first.
    pub fn attempts(&self) -> impl Iterator<Item = &Attempt> {
        self.attempts.iter()
    }

    /// Follow the reader's snapshots while the orchestrator's registry
    /// copy holds the contract manifest the schedule was read from: one step
    /// per new proposed block. A failed read or step is logged and retried
    /// after a backoff ([`Self::follow`]). Returns the reader once the
    /// namespace's contract manifest is another (or gone), so the caller
    /// reads the schedule again ([`spawn`]).
    pub async fn run(mut self) -> ChainReader<T> {
        let ns = fr_to_hex(self.schedule.layout.contract);
        loop {
            let held = held_versions(&self.app, self.schedule.layout.contract);
            if !held.contains(&self.schedule.layout.manifest_hash) || self.reselect {
                tracing::info!(
                    namespace = %ns,
                    "scheduler: the namespace's contract manifest changed; reading it again"
                );
                return self.reader;
            }
            let followed = self.follow().await;
            self.app
                .record_reader(ReaderStatus::of(ns.clone(), self.reader.held().await));
            match followed {
                Ok(r) => tracing::info!(
                    namespace = %ns,
                    block = r.block,
                    head = r.head,
                    tail = r.tail,
                    replaced = %r.replaced.map(|p| p.to_string()).unwrap_or_default(),
                    reloaded = r.reloaded,
                    stale = r.stale,
                    computed = r.computed.len(),
                    init = r.init.as_ref().map_or("", InitStep::name),
                    error = r.error.as_deref().unwrap_or(""),
                    "scheduler step"
                ),
                Err(e) => {
                    tracing::warn!(namespace = %ns, error = %e, "scheduler step failed");
                }
            }
        }
    }

    /// One turn of [`Self::run`]: wait for the next proposed block and step
    /// at it. When the reader reports that blocks were replaced, drop what
    /// rested on them ([`Self::replaced`]) and step at once at the
    /// replacement chain's tip, even one no higher than the last step's
    /// block (module documentation, "a replaced block"). A paused step, and
    /// one that failed or stopped at a retryable failure, waits (the poll
    /// interval when paused, else [`retry_backoff`]) and leaves the next turn
    /// to step at the same block, without waiting for a new one.
    pub async fn follow(&mut self) -> Result<StepReport, StepError> {
        let mut replaced = None;
        let mut replacements = 0;
        let snap = loop {
            match self.reader.next_snapshot(self.followed).await {
                Ok(snap) => break snap,
                Err(ReadError::Pruned(prune)) if replacements < REPLACEMENTS_PER_FOLLOW => {
                    replacements += 1;
                    self.replaced(prune);
                    replaced = Some(prune);
                }
                Err(e) => {
                    self.wait_to_retry(false).await;
                    return Err(e.into());
                }
            }
        };
        self.followed = snap.block;
        let stepped = self.step(snap).await;
        let again = match &stepped {
            Ok(report) if report.paused => Some(true),
            Ok(report) if report.retry => Some(false),
            Ok(_) => None,
            Err(_) => Some(false),
        };
        match again {
            // step this block again (a quiet chain may make no new one):
            // once resumed, or once the failure may have passed
            Some(paused) => {
                self.followed = snap.block.saturating_sub(1);
                self.wait_to_retry(paused).await;
            }
            None => self.failures = 0,
        }
        let mut report = stepped?;
        report.replaced = replaced;
        Ok(report)
    }

    /// Wait before the next turn: the poll interval while `paused`, else
    /// [`retry_backoff`] of the failures in a row (counting this one).
    async fn wait_to_retry(&mut self, paused: bool) {
        let poll = self.reader.config().poll_interval;
        let wait = if paused {
            poll
        } else {
            self.failures = self.failures.saturating_add(1);
            retry_backoff(poll, self.failures - 1)
        };
        tokio::time::sleep(wait).await;
    }

    /// The reader reported `prune`: blocks it followed were replaced. The
    /// refusals made at a replaced block are forgotten
    /// ([`Refusals::forget_voided`]). When the prune voids the last step's
    /// reads, drop every attempt, the held init attempt and the live state,
    /// so the next step reloads from the chain as it stands and recomputes
    /// the head; either way the next step runs at the replacement chain's
    /// tip, whose block is at least `prune.to`.
    fn replaced(&mut self, prune: Prune) {
        self.followed = self.followed.min(prune.to.saturating_sub(1));
        self.refusals().forget_voided(&prune);
        let void = self.read_at.is_some_and(|block| prune.voids(block));
        if void {
            self.attempts.clear();
            self.init = None;
            self.live = None;
            self.read_at = None;
        }
        tracing::info!(
            namespace = %fr_to_hex(self.schedule.layout.contract),
            prune = %prune,
            dropped = void,
            "scheduler: blocks were replaced"
        );
    }

    /// One step at `snap` (module documentation).
    pub async fn step(&mut self, snap: Snapshot) -> Result<StepReport, StepError> {
        self.read_at = Some(snap.block);
        self.packages = self.parse_packages();
        let target = self.schedule.target();
        let queue = self.reader.queue(snap, &target).await?;
        let slots = self.read_slots(snap).await?;
        let init = self.read_init(snap).await?;
        let mut report = StepReport {
            block: snap.block,
            head: queue.head,
            tail: queue.tail,
            ..StepReport::default()
        };
        if self.app.paused() {
            report.paused = true;
            return Ok(report);
        }
        // The version in force first: a class upgrade switches the class
        // and the pins together, so the schedule's version, built for the
        // old class, is replaced by the one the pins name rather than
        // refused against the new class for ever.
        let in_force = self
            .reader
            .manifest_in_force(snap, &self.schedule.layout)
            .await?;
        if let Some(why) = self.schedule.layout.version_differs(in_force, snap.block) {
            tracing::info!(
                namespace = %fr_to_hex(self.schedule.layout.contract),
                reason = %why,
                "scheduler: the circuit pins changed; picking the version in force"
            );
            self.reselect = true;
            report.error = Some(why);
            return Ok(report);
        }
        let class = self
            .reader
            .current_class(snap, self.schedule.layout.contract)
            .await?;
        if let Some(why) = self.schedule.layout.class_differs(class, snap.block) {
            tracing::warn!(
                namespace = %fr_to_hex(self.schedule.layout.contract),
                reason = %why,
                "scheduler: computing nothing"
            );
            report.error = Some(why);
            return Ok(report);
        }
        if let Some(why) = self.key_set_differs(snap).await? {
            report.error = Some(why);
            return Ok(report);
        }
        if !self.reconcile(&queue, &slots) {
            self.attempts.clear();
            // Cleared first: a reload that fails leaves no live state, and
            // the next step reloads again.
            self.live = None;
            self.live = Some(self.reload(snap, &queue, &slots, init.as_ref()).await?);
            report.reloaded = true;
        }
        if let Some(read) = &init {
            let step = self.init_step(read, &mut report).await;
            let done = step == InitStep::Done;
            report.init = Some(step);
            if !done {
                return Ok(report);
            }
        }
        let Some(&head) = queue.head_entry() else {
            return Ok(report);
        };
        let identified = match self.identify(snap, head).await {
            Ok(Some(found)) => found,
            Ok(None) => {
                report.error = Some(no_inputs(head));
                report.retry = true;
                return Ok(report);
            }
            Err(e) => {
                report.error = Some(e.to_string());
                report.retry = true;
                return Ok(report);
            }
        };
        let period = identified.0.tip.stale_blocks();
        let (contract, slot) = (
            self.schedule.layout.contract,
            self.schedule.layout.stale_blocks_slot,
        );
        let stored = self.reader.stale_blocks(snap, contract, slot).await?;
        if let Some(differs) = stored.differs(&identified.0.name, period) {
            report.error = Some(format!(
                "entry {}: {differs}; every node refuses its rounds until the two agree",
                head.index
            ));
            return Ok(report);
        }
        if let Some(from) = queue.skippable_from(period)
            && snap.block >= from
        {
            report.stale = true;
            return Ok(report);
        }
        let mut base = self.live.clone().expect("loaded above");
        let mut head_found = Some(identified);
        let last = self.schedule.pipeline_depth.min(queue.window.len() - 1);
        for k in 0..=last {
            let entry = queue.window[k];
            if let Some(attempt) = self.attempts.get(k) {
                match self.repriced(snap, attempt).await {
                    Ok(false) => {
                        base.advance(attempt);
                        head_found = None;
                        continue;
                    }
                    Ok(true) => {
                        tracing::info!(
                            index = attempt.index,
                            chain_request_id = %fr_to_hex(attempt.chain_request_id),
                            "scheduler: a pinned value is no longer admitted; recomputing"
                        );
                        self.attempts.truncate(k);
                        report.repriced = true;
                    }
                    Err(e) => {
                        report.error = Some(format!("entry {}: pinned reads: {e}", entry.index));
                        report.retry = true;
                        break;
                    }
                }
            }
            let found = match head_found.take() {
                Some(found) => Some(found),
                None => match self.identify(snap, entry).await {
                    Ok(found) => found,
                    Err(e) => {
                        report.error = Some(e.to_string());
                        report.retry = true;
                        break;
                    }
                },
            };
            let Some((pkg, inputs)) = found else {
                report.error = Some(no_inputs(entry));
                report.retry = true;
                break;
            };
            match self.compute(snap, entry, &pkg, &inputs, &base).await {
                Ok(attempt) => {
                    base.advance(&attempt);
                    report.computed.push(attempt.clone());
                    self.attempts.push_back(attempt);
                }
                Err(e) => {
                    tracing::info!(
                        index = entry.index,
                        chain_request_id = %fr_to_hex(entry.chain_request_id),
                        error = %e,
                        "scheduler: attempt refused"
                    );
                    report.error = Some(format!("entry {}: {e}", entry.index));
                    report.retry = e.class == ErrorClass::MpcFailure;
                    break;
                }
            }
        }
        Ok(report)
    }

    // The key-set gate (docs/ARCHITECTURE.md section 6, "Node replacement
    // and key epochs"). The machine's key set is the operator's
    // configuration ([[nodes]]), never the contract's: a hostile rotation
    // must not drive the orchestrator. A namespace whose contract's current
    // key epoch has `sig` keys other than the configured ones (a rotation
    // landed in some contracts and not others, or the orchestrator
    // reconfigured after a replacement while a contract still has the keys it
    // was constructed with) gets nothing computed: its results would be
    // signed by a set the contract refuses, and its head would stall behind
    // an attempt that cannot land. Every epoch is compared, epoch 0 included:
    // epoch 0's keys are the constructor's `node_sig_keys`, read beside
    // `TipConfig.stale_blocks` (sidecar-core `key_epoch::epoch0_sig_slots`),
    // which match the configuration only until the operator moves it. A
    // contract with a fixed key set (pss_public_contract `FixedKeys`) never
    // writes the key-epoch slot, so it is a contract at epoch 0 for good:
    // served while the configuration is its constructor's keys, refused after
    // a node replacement until its app is redeployed; the refusal names which,
    // from the contract manifest's `node_keys`. The gate reads one slot
    // per step and the whole key epoch only when that slot changes (epoch 0's
    // keys are immutable, so a match is kept until the contract rotates).
    /// Why nothing is computed for this namespace at `snap`: its contract's
    /// current key epoch, epoch 0 (the constructor's keys) included, carries
    /// other `sig` keys than the configured ones; `None` when they match.
    async fn key_set_differs(&mut self, snap: Snapshot) -> Result<Option<String>, ReadError> {
        let ns = self.schedule.layout.contract;
        let epoch = self
            .reader
            .storage(snap, ns, sidecar_core::key_epoch::node_keys_slot())
            .await?;
        if self.key_epoch_ok == Some(epoch) {
            return Ok(None);
        }
        let stored = self
            .reader
            .key_set(snap, ns, epoch, self.schedule.layout.stale_blocks_slot)
            .await?;
        if stored.sig_is(&self.app.pins) {
            self.key_epoch_ok = Some(epoch);
            return Ok(None);
        }
        self.key_epoch_ok = None;
        let why = if stored.epoch == 0 {
            let remedy = match self.schedule.layout.node_keys {
                NodeKeysAxis::Rotating => {
                    "submit its rotate_keys to the configured set, or configure the contract's \
                     key set and restart"
                }
                NodeKeysAxis::Fixed => {
                    "its contract manifest says node_keys fixed: the contract has no \
                     rotate_keys and stays at epoch 0 for good, so after a node replacement \
                     its app is redeployed (or configure the contract's key set and restart)"
                }
            };
            format!(
                "the contract is at key epoch 0, whose sig keys (the constructor's \
                 node_sig_keys) are not this orchestrator's [[nodes]]: nothing is computed \
                 until the configured key set is the contract's ({remedy})"
            )
        } else {
            format!(
                "the contract is at key epoch {} under sig keys other than this orchestrator's \
                 [[nodes]]: nothing is computed until the configured key set is the contract's \
                 (submit the rotation everywhere, or configure the new key set and restart)",
                stored.epoch
            )
        };
        tracing::warn!(
            namespace = %fr_to_hex(ns),
            epoch = stored.epoch,
            reason = %why,
            "scheduler: the contract's key set is not the configured one; computing nothing"
        );
        Ok(Some(why))
    }

    /// Every slot of the schedule at `snap`, by request key.
    async fn read_slots(&self, snap: Snapshot) -> Result<BTreeMap<String, Fr>, ReadError> {
        let mut out = BTreeMap::new();
        for (slot, key) in &self.schedule.layout.slots {
            let c = self
                .reader
                .storage(snap, self.schedule.layout.contract, *slot)
                .await?;
            out.insert(key.clone(), c);
        }
        Ok(out)
    }

    /// The init round's reads at `snap`, for a namespace with one.
    async fn read_init(&self, snap: Snapshot) -> Result<Option<InitRead>, ReadError> {
        let Some(init) = &self.schedule.layout.init else {
            return Ok(None);
        };
        let state_keys = self
            .schedule
            .layout
            .circuits
            .get(&init.circuit)
            .ok_or_else(|| ReadError::BadKey {
                key: init.circuit.clone(),
                detail: "the init circuit has no request keys in the schedule".into(),
            })?;
        let read = self
            .reader
            .init(snap, &self.schedule.target(), init, state_keys)
            .await?;
        Ok(Some(read))
    }

    /// The init part of a step (module documentation, "init"): what the
    /// init round's state is at `read`, sending it when it is due and no
    /// attempt is held. A refused send is named in `report.error` and
    /// retried at the next step.
    async fn init_step(&mut self, read: &InitRead, report: &mut StepReport) -> InitStep {
        if !read.is_configured() {
            return InitStep::Unconfigured;
        }
        if !read.due() {
            self.init = None;
            return InitStep::Done;
        }
        let Some(chain) = self.init_chain_request_id(read) else {
            report.error = Some(format!(
                "init round: the init package `{}` is not a registered queued package",
                self.schedule
                    .layout
                    .init
                    .as_ref()
                    .map_or("", |i| i.circuit.as_str())
            ));
            return InitStep::Due;
        };
        if self
            .init
            .as_ref()
            .is_some_and(|held| held.chain_request_id == chain)
        {
            return InitStep::Due;
        }
        match self.compute_init(read, report.block).await {
            Ok(attempt) => {
                self.init = Some(attempt.clone());
                InitStep::Sent(attempt)
            }
            Err(e) => {
                tracing::info!(
                    chain_request_id = %fr_to_hex(chain),
                    error = %e,
                    "scheduler: init round refused"
                );
                report.error = Some(format!("init round: {e}"));
                report.retry = e.class == ErrorClass::MpcFailure;
                InitStep::Due
            }
        }
    }

    /// The init round's fixed chain request id at `read`, under the
    /// registered init package's vk hash; `None` when the init package is
    /// not a registered queued package.
    fn init_chain_request_id(&self, read: &InitRead) -> Option<Fr> {
        let init = self.schedule.layout.init.as_ref()?;
        let pkg = self.packages().iter().find(|p| p.name == init.circuit)?;
        Some(read.chain_request_id(self.schedule.layout.contract, pkg.vk_hash))
    }

    /// Synthesise the init round at `read` and run it through the execute
    /// path at `block`.
    async fn compute_init(&self, read: &InitRead, block: u64) -> Result<Attempt, Refusal> {
        let init = self
            .schedule
            .layout
            .init
            .as_ref()
            .expect("read only with an init");
        let pkg = self
            .packages()
            .iter()
            .find(|p| p.name == init.circuit)
            .ok_or_else(|| {
                Refusal::bad_request(format!(
                    "the init circuit `{}` is not a registered queued package",
                    init.circuit
                ))
            })?;
        let state_keys = &self.schedule.layout.circuits[&init.circuit];
        self.check_layouts(pkg, state_keys)?;
        let synthesised = init_request(self.schedule.layout.contract, read, pkg, state_keys)?;
        let req = synthesised.request;
        let (request_id, chain) = (
            req.request_id,
            read.chain_request_id(self.schedule.layout.contract, pkg.vk_hash),
        );
        let response = self.execute(req, block).await?;
        Ok(Attempt {
            index: read.head,
            chain_request_id: chain,
            request_id,
            circuit: pkg.name.clone(),
            old: synthesised.old,
            pinned: vec![],
            new: pkg.advance(state_keys, &response)?,
        })
    }

    /// Run `req` through the execute path at `block`, unless the nodes
    /// refused its machine request id and its wait has not ended (module
    /// documentation, "Retries"); keep what it gave.
    async fn execute(&self, req: Request, block: u64) -> Result<ExecuteResponse, Refusal> {
        let id = req.request_id;
        if let Some(held) = self.refusals().held(id, block) {
            return Err(held);
        }
        let result = api::run_execute(self.app.clone(), req, Class::Scheduler)
            .await
            .map_err(Refusal::from);
        self.refusals().record(id, result.as_ref().map(drop), block);
        result
    }

    fn refusals(&self) -> std::sync::MutexGuard<'_, Refusals> {
        self.refusals
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Whether the held state and attempts still match the chain; updates the
    /// live state when they do (module documentation, "reconcile").
    fn reconcile(&mut self, queue: &QueueView, slots: &BTreeMap<String, Fr>) -> bool {
        let Some(mut state) = self.live.clone() else {
            return false;
        };
        if let Some(init) = &self.init {
            let mut landed = state.clone();
            landed.advance(init);
            if landed.commitments() == *slots && state.commitments() != *slots {
                state = landed;
                self.init = None;
            }
        }
        while self.attempts.front().is_some_and(|a| a.index < queue.head) {
            let passed = self.attempts.pop_front().expect("checked");
            state.advance(&passed);
        }
        if state.commitments() != *slots {
            return false;
        }
        let mut base = state.clone();
        for (k, attempt) in self.attempts.iter().enumerate() {
            match queue.window.get(k) {
                Some(e)
                    if e.index == attempt.index
                        && e.chain_request_id == attempt.chain_request_id => {}
                _ => return false,
            }
            let chained = attempt
                .old
                .iter()
                .all(|(key, c)| base.slots.get(key).map(|s| s.commitment) == Some(*c));
            if !chained {
                return false;
            }
            base.advance(attempt);
        }
        self.live = Some(state);
        true
    }

    /// The live state at `snap`: each slot's state from its key's tip state;
    /// an empty slot (0) has none.
    async fn reload(
        &self,
        snap: Snapshot,
        queue: &QueueView,
        slots: &BTreeMap<String, Fr>,
        init: Option<&InitRead>,
    ) -> Result<State, StepError> {
        let history = History {
            scheduler: self,
            snap,
            head: queue.head,
            init: init
                .filter(|read| read.is_configured())
                .and_then(|read| self.init_chain_request_id(read)),
        };
        let packages = self.packages();
        let mut state = State::default();
        for (key, &commitment) in slots {
            let held = if commitment == Fr::from(0u64) {
                None
            } else {
                let missing = |why: String| StepError::NoState {
                    key: key.clone(),
                    commitment,
                    why,
                };
                let tip_state = self.tip_state_of(packages, key).map_err(missing)?;
                match tip_state.reload(&history, key, commitment).await {
                    Ok(held) => Some(held),
                    Err(ReloadError::Read(e)) => return Err(StepError::Read(e)),
                    Err(ReloadError::Missing(why)) => return Err(missing(why)),
                }
            };
            state.slots.insert(
                key.clone(),
                Slot {
                    commitment,
                    state: held,
                },
            );
        }
        Ok(state)
    }

    /// The tip state of the request key `key`: the one the namespace's
    /// queued `packages` give it, which must agree on its layout
    /// ([`key_tip_state`]); why not, after "slot `key` holds c, and".
    fn tip_state_of<'p>(
        &'p self,
        packages: &'p [TipPackage],
        key: &str,
    ) -> Result<&'p dyn TipState, String> {
        let scheduled = packages
            .iter()
            .filter_map(|pkg| Some((pkg, self.schedule.layout.circuits.get(&pkg.name)?)));
        key_tip_state(scheduled, key)
    }

    /// 400 when a request key of `pkg` under `state_keys` has another layout in
    /// another queued package of the namespace: a round of `pkg` would read
    /// state the other leaves under its own layout. Run before every round
    /// is computed, since a key the round creates has no state to reload.
    fn check_layouts(&self, pkg: &TipPackage, state_keys: &StateKeys) -> Result<(), Refusal> {
        for key in pkg.request_keys(state_keys) {
            self.tip_state_of(self.packages(), key)
                .map_err(|why| Refusal::bad_request(format!("key `{key}`: {why}")))?;
        }
        Ok(())
    }

    /// The queued packages of the namespace, as the step parsed them.
    fn packages(&self) -> &[TipPackage] {
        &self.packages
    }

    /// The queued packages of the namespace in the registry copy. A row that
    /// no longer parses, or names a state mode no tip state serves (REGISTER
    /// refuses both), is logged and left out.
    fn parse_packages(&self) -> Vec<TipPackage> {
        let namespace = self.schedule.layout.contract;
        let stale = match sidecar_tip::stale_blocks_of(self.app.registry.store(), namespace) {
            Ok(stale) => stale,
            Err(e) => {
                tracing::warn!(error = %e.message, "scheduler: no contract manifest; no package read");
                return Vec::new();
            }
        };
        let layout = &self.schedule.layout;
        let version = layout.circuit_pins.map(|_| layout.manifest_hash);
        self.app
            .registry
            .packages_in(namespace, layout.manifest_hash)
            .iter()
            .filter_map(|row| match TipPackage::from_row(row, stale) {
                Ok(pkg) => pkg.map(|p| p.with_version(version)),
                Err(e) => {
                    tracing::warn!(package = %row.name, error = %e.message, "scheduler: package skipped");
                    None
                }
            })
            .collect()
    }

    /// The package and inputs of a queue entry; `None` when nothing the
    /// scheduler can read names it yet: the packages' intakes asked in
    /// `sidecar_tip::find_entry`'s order (the packages in name order within
    /// each), through a lookup that reads each chain read and the nodes'
    /// stored receipts once per entry. A receipt one node lost is read from
    /// another under receipt intake, and holds the entry under secret-shared
    /// receipt intake (the round needs every node's envelope) until it goes
    /// stale and is skipped.
    async fn identify(
        &self,
        snap: Snapshot,
        entry: QueueEntry,
    ) -> Result<Option<(TipPackage, Found)>, ReadError> {
        let lookup = Lookup {
            scheduler: self,
            chain: ChainAt {
                reader: &self.reader,
                snap,
                namespace: self.schedule.layout.contract,
                layout: self.schedule.layout.intake,
            },
            public: Mutex::default(),
            private: Mutex::default(),
            storage: Mutex::default(),
            receipts: OnceCell::new(),
        };
        let found = find_entry(&lookup, self.packages(), entry.chain_request_id).await?;
        Ok(found.map(|(pkg, inputs)| (pkg.clone(), inputs)))
    }

    /// Each node's stored receipt of `chain`, node 0 first (`None` for a
    /// node that holds none or does not answer).
    async fn stored_receipts(&self, chain: Fr) -> [Option<StoredReceipt>; NODES] {
        let path = format!(
            "/v1/receipt/{}/{}",
            fr_to_hex(self.schedule.layout.contract),
            fr_to_hex(chain)
        );
        let replies = self.app.nodes.lookups().get(&path).await;
        let mut out: [Option<StoredReceipt>; NODES] = Default::default();
        for (i, reply) in replies.into_iter().enumerate() {
            out[i] = node_answer::<StoredReceipt>(i, reply).ok();
        }
        out
    }

    /// The package an applied chain request ran under: from its inputs, or,
    /// when they are gone (a pruned receipt), from the vk_hash of the nodes'
    /// latest row for it.
    async fn package_of(&self, snap: Snapshot, chain: Fr) -> Option<TipPackage> {
        let entry = QueueEntry {
            index: 0,
            chain_request_id: chain,
        };
        if let Ok(Some((pkg, _))) = self.identify(snap, entry).await {
            return Some(pkg);
        }
        let req = ChainFetchRequest {
            namespace: FieldHex(self.schedule.layout.contract),
            chain_request_id: FieldHex(chain),
        };
        let response = api::run_fetch_chain(self.app.clone(), req).await.ok()?;
        self.packages()
            .iter()
            .find(|p| p.vk_hash == response.vk_hash.fr())
            .cloned()
    }

    /// Whether the chain's pinned values at `snap` no longer admit
    /// `attempt`'s. Every step re-reads the pinned public reads of each held
    /// attempt in the window (one simulation or storage read per read, at
    /// the step's snapshot) and discards the attempt, with the attempts
    /// after it, when a read's freshness policy no longer admits the value
    /// the attempt used (`PublicRead::admits`: `exact` a moved value,
    /// `epoch` an epoch two behind, `tolerance` a value out of the band);
    /// circuits without pinned reads cost nothing. `apply` rechecks each
    /// pinned read by the same rule, so such an attempt only reverts, and
    /// the nodes run the recompute because the machine request id covers the
    /// pinned values; an attempt the rule still admits is kept, since
    /// recomputing it would only restart the round. Under `exact` a value
    /// that moves every block makes a new attempt (a full MPC round) every
    /// block, none of which lands, until the value settles or the head goes
    /// stale and is skipped; under `epoch` an attempt lands when at most one
    /// new epoch opens before its apply, and is recomputed at most once per
    /// two epochs; a relayer that sent a dropped attempt sees its apply
    /// revert and re-fetches the new one.
    async fn repriced(&self, snap: Snapshot, attempt: &Attempt) -> Result<bool, Refusal> {
        let Some(pkg) = self.packages().iter().find(|p| p.name == attempt.circuit) else {
            return Ok(false);
        };
        if pkg.tip.public_reads().is_empty() {
            return Ok(false);
        }
        let pinned = self
            .reader
            .pinned_values(
                snap,
                self.schedule.layout.contract,
                &pkg.tip,
                &self.schedule.layout.plain_reads,
            )
            .await
            .map_err(|e| Refusal::bad_request(e.to_string()))?;
        Ok(!pkg.pinned_admitted(&pinned, &attempt.pinned)?)
    }

    /// Synthesise `entry` on `base` and run it through the execute path.
    async fn compute(
        &self,
        snap: Snapshot,
        entry: QueueEntry,
        pkg: &TipPackage,
        inputs: &Found,
        base: &State,
    ) -> Result<Attempt, Refusal> {
        let ns = self.schedule.layout.contract;
        let state_keys = self
            .schedule
            .layout
            .circuits
            .get(&pkg.name)
            .ok_or_else(|| {
                Refusal::bad_request(format!(
                    "circuit `{}` is queued, and the schedule lists no request keys for it",
                    pkg.name
                ))
            })?;
        self.check_layouts(pkg, state_keys)?;
        let pinned = self
            .reader
            .pinned_values(snap, ns, &pkg.tip, &self.schedule.layout.plain_reads)
            .await
            .map_err(|e| Refusal::bad_request(format!("pinned reads: {e}")))?;
        let state = base.view();
        let app_public = pkg.app_public(&**inputs)?;
        let trees = NodeTrees {
            app: &self.app,
            namespace: ns,
        };
        let mut node_values = PublicMap::new();
        for (old, key) in pkg.tip.old_commitments().zip(pkg.state_keys(state_keys)?) {
            let Some(held) = state.iter().find(|s| s.key == key) else {
                continue;
            };
            let values = pkg
                .tip_state(old.key)?
                .node_values(pkg, key, held, &app_public, &trees)
                .await?;
            node_values.extend(values);
        }
        let view = SynthesisView {
            namespace: ns,
            entry,
            state_keys,
            pinned: &pinned,
            state: &state,
            node_values: &node_values,
        };
        let synthesised = synthesise(&view, pkg, &**inputs)?;
        let (req, old) = (synthesised.request, synthesised.old);
        let used = pkg.pinned_fields(&pinned)?;
        let request_id = req.request_id;
        let response = self.execute(req, snap.block).await?;
        Ok(Attempt {
            index: entry.index,
            chain_request_id: entry.chain_request_id,
            request_id,
            circuit: pkg.name.clone(),
            old,
            pinned: used,
            new: pkg.advance(state_keys, &response)?,
        })
    }
}

/// The nodes' clear trees as the scheduler reads them: the same query to
/// the three, whose answers must agree.
struct NodeTrees<'s> {
    app: &'s Orchestrator,
    namespace: Fr,
}

impl TreeSource for NodeTrees<'_> {
    fn paths(
        &self,
        key: String,
        commitment: Fr,
        depth: u32,
        indices: Vec<u64>,
        open: Option<usize>,
    ) -> TipFuture<'_, Result<TreePaths, Refusal>> {
        Box::pin(async move {
            let query = TreeQuery {
                namespace: FieldHex(self.namespace),
                key,
                commitment: FieldHex(commitment),
                depth,
                indices,
                open,
            };
            let body = serde_json::to_vec(&query).expect("a query serialises");
            let [a, b, c] = all_answers::<TreePaths>(
                self.app.nodes.lookups().post_same("/v1/tree", &body).await,
            )?;
            if a != b || a != c {
                return Err(Refusal::bad_request(format!(
                    "key `{}`: the nodes' clear trees differ at commitment {} (a diverged tree \
                     at one node: the operator resyncs it from its neighbours)",
                    query.key,
                    fr_to_hex(commitment)
                )));
            }
            Ok(a)
        })
    }
}

fn no_inputs(entry: QueueEntry) -> String {
    format!(
        "entry {}: no request log or stored receipt gives chain request {} under a \
         registered queued package",
        entry.index,
        fr_to_hex(entry.chain_request_id)
    )
}

/// A cache of one kind of chain read, by tag or slot.
type Reads<V> = Mutex<BTreeMap<Fr, Result<V, ReadError>>>;

/// Where one queue entry's inputs are found: the chain at the step's
/// snapshot (each read, by kind and tag or slot, made at most once) and the
/// nodes' stored receipts (asked at most once). The intakes' finds run one
/// at a time, so a read is never made twice in flight.
struct Lookup<'s, T> {
    scheduler: &'s Scheduler<T>,
    chain: ChainAt<'s, T>,
    public: Reads<TaggedLogs>,
    private: Reads<TaggedLogs>,
    storage: Reads<Fr>,
    receipts: OnceCell<[Option<StoredReceipt>; NODES]>,
}

/// `read`'s answer for `key`, from `cache` when it was made before.
async fn cached<V: Clone>(
    cache: &Reads<V>,
    key: Fr,
    read: TipFuture<'_, Result<V, ReadError>>,
) -> Result<V, ReadError> {
    let held = cache
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(&key)
        .cloned();
    if let Some(answer) = held {
        return answer;
    }
    let answer = read.await;
    cache
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert(key, answer.clone());
    answer
}

impl<T: Transport> ChainLogs for Lookup<'_, T> {
    fn namespace(&self) -> Fr {
        self.chain.namespace()
    }

    fn layout(&self) -> &IntakeLayout {
        self.chain.layout()
    }

    fn public_logs(&self, tag: Fr) -> TipFuture<'_, Result<TaggedLogs, ReadError>> {
        Box::pin(cached(&self.public, tag, self.chain.public_logs(tag)))
    }

    fn private_logs(&self, siloed_tag: Fr) -> TipFuture<'_, Result<TaggedLogs, ReadError>> {
        Box::pin(cached(
            &self.private,
            siloed_tag,
            self.chain.private_logs(siloed_tag),
        ))
    }

    fn storage(&self, slot: Fr) -> TipFuture<'_, Result<Fr, ReadError>> {
        Box::pin(cached(&self.storage, slot, self.chain.storage(slot)))
    }
}

impl<T: Transport> IntakeLookup for Lookup<'_, T> {
    fn stored_receipts(&self, chain: Fr) -> TipFuture<'_, [Option<StoredReceipt>; NODES]> {
        Box::pin(async move {
            self.receipts
                .get_or_init(|| self.scheduler.stored_receipts(chain))
                .await
                .clone()
        })
    }
}

/// The chain and the registry as a tip state reads them while the scheduler
/// reloads, at one snapshot.
struct History<'s, T> {
    scheduler: &'s Scheduler<T>,
    snap: Snapshot,
    head: u64,
    /// The init round's chain request id, once the contract is configured.
    init: Option<Fr>,
}

impl<T: Transport> TipHistory for History<'_, T> {
    fn head(&self) -> u64 {
        self.head
    }

    fn applied(&self, index: u64) -> TipFuture<'_, Result<Option<Fr>, ReadError>> {
        Box::pin(async move {
            let s = self.scheduler;
            if s.reader
                .done(self.snap, &s.schedule.target(), index)
                .await?
                != sidecar_tip::chain::layout::DONE_APPLIED
            {
                return Ok(None);
            }
            let slot = s.schedule.layout.queue.request(index);
            Ok(Some(
                s.reader
                    .storage(self.snap, s.schedule.layout.contract, slot)
                    .await?,
            ))
        })
    }

    fn logs(&self, tag: Fr) -> TipFuture<'_, Result<TaggedLogs, ReadError>> {
        let s = self.scheduler;
        Box::pin(s.reader.logs(self.snap, s.schedule.layout.contract, tag))
    }

    fn package(&self, chain_request_id: Fr) -> TipFuture<'_, Option<(TipPackage, StateKeys)>> {
        Box::pin(async move {
            let s = self.scheduler;
            let pkg = match (&s.schedule.layout.init, self.init) {
                (Some(init), Some(id)) if id == chain_request_id => s
                    .packages()
                    .iter()
                    .find(|p| p.name == init.circuit)?
                    .clone(),
                _ => s.package_of(self.snap, chain_request_id).await?,
            };
            let state_keys = s.schedule.layout.circuits.get(&pkg.name)?.clone();
            Some((pkg, state_keys))
        })
    }

    fn init(&self) -> Option<Fr> {
        self.init
    }
}

/// The hashes of the contract manifest versions the orchestrator's
/// registry copy holds for `namespace`; none when it holds none or cannot be
/// read.
fn held_versions(app: &Orchestrator, namespace: Fr) -> Vec<Fr> {
    match app.registry.store().contract_manifests(namespace) {
        Ok(rows) => rows.iter().map(|r| r.manifest_hash).collect(),
        Err(e) => {
            tracing::warn!(
                namespace = %fr_to_hex(namespace),
                error = %e.message,
                "scheduler: the registry copy cannot be read"
            );
            Vec::new()
        }
    }
}

/// The layout of `namespace` the scheduler drives: the version of its
/// contract manifest the contract's circuit pins name in force at the
/// reader's current block, among those the orchestrator's registry copy
/// holds (the newest under `fixed`, the only one). `Ok(Err(why))` when it
/// holds none, or not the version in force.
pub async fn layout_in_force<T: Transport>(
    app: &Orchestrator,
    reader: &ChainReader<T>,
    namespace: Fr,
) -> Result<Result<TipLayout, String>, Refusal> {
    let Some(newest) = registered_layout(app, namespace)? else {
        return Ok(Err(
            "the namespace holds no contract manifest yet".to_string()
        ));
    };
    if newest.circuit_pins.is_none() {
        return Ok(Ok(newest));
    }
    let read = async {
        let snap = reader.snapshot().await?;
        reader.manifest_in_force(snap, &newest).await
    };
    let in_force = match read.await {
        Ok(hash) => hash,
        Err(e) => return Ok(Err(format!("the circuit pins cannot be read: {e}"))),
    };
    let rows = app.registry.store().contract_manifests(namespace)?;
    Ok(
        TipLayout::of_version(namespace, rows, in_force)?.ok_or_else(|| {
            format!(
                "the contract's circuit pins name contract manifest {}, which the registry copy \
             does not hold",
                fr_to_hex(in_force)
            )
        }),
    )
}

/// The layout of `namespace` from the contract manifest the orchestrator's
/// registry copy holds; `None` when it holds none.
pub fn registered_layout(app: &Orchestrator, namespace: Fr) -> Result<Option<TipLayout>, Refusal> {
    TipLayout::of_row(
        namespace,
        app.registry.store().contract_manifest(namespace)?,
    )
}

/// Drive one listed namespace for ever: wait until the orchestrator's
/// registry copy holds a tip contract manifest for it, then run its
/// scheduler until that manifest changes, and read it again. A namespace
/// listed and not registered (or registered without a queue) is driven
/// once it is.
async fn drive<T: Transport>(
    app: Arc<Orchestrator>,
    mut reader: ChainReader<T>,
    namespace: Fr,
    pipeline_depth: usize,
) {
    let poll = reader.config().poll_interval;
    let mut waiting = None;
    loop {
        match layout_in_force(&app, &reader, namespace).await {
            Ok(Ok(layout)) => {
                waiting = None;
                tracing::info!(
                    namespace = %fr_to_hex(namespace),
                    manifest_hash = %fr_to_hex(layout.manifest_hash),
                    "scheduler: driving the namespace's queue"
                );
                let schedule = Schedule::new(layout, pipeline_depth);
                reader = Scheduler::new(app.clone(), reader, schedule).run().await;
            }
            other => {
                let why = match other {
                    Ok(Err(why)) => why,
                    Err(e) => e.message,
                    Ok(Ok(_)) => unreachable!("matched above"),
                };
                if waiting.as_ref() != Some(&why) {
                    tracing::info!(
                        namespace = %fr_to_hex(namespace),
                        reason = %why,
                        "scheduler: waiting for the namespace's registration"
                    );
                    waiting = Some(why);
                }
                tokio::time::sleep(poll).await;
            }
        }
    }
}

/// Start one scheduler task per `[[tip.namespaces]]` entry, each with its
/// own chain reader over the configured Aztec node; each drives its
/// namespace once the namespace is registered ([`drive`]). The tasks run
/// for ever; the caller watches the set (`crate::server::run`).
pub fn spawn(app: Arc<Orchestrator>, tip: &TipConfig) -> eyre::Result<JoinSet<()>> {
    let transport = tip.aztec_node.transport()?;
    let config = ReaderConfig {
        poll_interval: Duration::from_millis(tip.poll_interval_ms),
        ..ReaderConfig::default()
    };
    let mut tasks = JoinSet::new();
    for ns in &tip.namespaces {
        tracing::info!(
            namespace = %ns.contract,
            aztec_node = %sidecar_tip::url_origin(&tip.aztec_node.url),
            pipeline_depth = tip.pipeline_depth,
            "scheduler started"
        );
        let reader = ChainReader::with_config(transport.clone(), config);
        tasks.spawn(drive(
            app.clone(),
            reader,
            ns.contract.fr(),
            tip.pipeline_depth,
        ));
    }
    Ok(tasks)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn key_state(key: &str, commitment: u64) -> KeyState {
        KeyState {
            key: key.into(),
            commitment: Fr::from(commitment),
            record: None,
        }
    }

    fn attempt(new: Vec<KeyState>) -> Attempt {
        Attempt {
            index: 0,
            chain_request_id: Fr::from(1u64),
            request_id: RequestId(Fr::from(2u64)),
            circuit: "c".into(),
            old: BTreeMap::new(),
            pinned: vec![],
            new,
        }
    }

    fn empty(keys: &[&str]) -> State {
        State {
            slots: keys
                .iter()
                .map(|k| {
                    (
                        k.to_string(),
                        Slot {
                            commitment: Fr::from(0u64),
                            state: None,
                        },
                    )
                })
                .collect(),
        }
    }

    // A refused request waits 1, 2, 4, ... blocks (at most MAX_REFUSAL_WAIT)
    // before it is sent again; another class starts over at 1, a node
    // failure or an answer forgets it, and other ids are not held.
    #[test]
    fn a_refused_request_is_sent_again_after_a_growing_wait() {
        let id = RequestId(Fr::from(9u64));
        let no = Refusal::new(ErrorClass::Unsatisfied, "constraints");
        let mut r = Refusals::default();
        r.record(id, Err(&no), 100);
        let held = r.held(id, 100).unwrap();
        assert_eq!(held.class, ErrorClass::Unsatisfied);
        assert_eq!(
            held.message,
            "constraints (refused at block 100; not sent again before block 101)"
        );
        assert!(r.held(id, 101).is_none());
        assert!(r.held(RequestId(Fr::from(8u64)), 100).is_none());
        let mut at = 101;
        for wait in [2, 4, 8, 16, 32, 32] {
            r.record(id, Err(&no), at);
            assert!(r.held(id, at + wait - 1).is_some(), "wait {wait}");
            assert!(r.held(id, at + wait).is_none(), "wait {wait}");
            at += wait;
        }
        r.record(id, Err(&Refusal::new(ErrorClass::Conflict, "held")), at);
        assert!(r.held(id, at + 1).is_none(), "another class waits 1 block");
        r.record(id, Err(&Refusal::mpc_failure("node 1: no answer")), at + 1);
        assert!(
            r.held(id, at + 1).is_none(),
            "a node failure is retried at once"
        );
        r.record(id, Err(&no), at + 2);
        r.record(id, Ok(()), at + 3);
        assert!(r.held.is_empty());
        // an entry whose wait ended long ago is dropped
        r.record(id, Err(&no), 10);
        r.record(
            RequestId(Fr::from(1u64)),
            Err(&no),
            10 + 1 + MAX_REFUSAL_WAIT + 1,
        );
        assert!(!r.held.contains_key(&id.0));
    }

    // A prune forgets the refusals made at the blocks it replaced: after the
    // chain goes back, a refused id is sent again on the replacement chain
    // without waiting out a back-off counted in block numbers that come
    // again. A refusal below the prune stands.
    #[test]
    fn a_prune_forgets_the_refusals_made_at_replaced_blocks() {
        let no = Refusal::new(ErrorClass::Unsatisfied, "constraints");
        let (early, late) = (RequestId(Fr::from(1u64)), RequestId(Fr::from(2u64)));
        let mut r = Refusals::default();
        r.record(early, Err(&no), 100);
        r.record(late, Err(&no), 120);
        for _ in 0..4 {
            r.record(late, Err(&no), 120);
        }
        assert!(r.held(late, 121).is_some(), "a wait of 16 blocks from 120");
        let prune = Prune {
            from: 125,
            to: 110,
            below_kept: false,
        };
        r.forget_voided(&prune);
        assert!(r.held(late, 111).is_none(), "refused at a replaced block");
        assert!(r.held(early, 100).is_some(), "refused below the prune");
        // a prune past every block kept voids every refusal
        r.forget_voided(&Prune {
            below_kept: true,
            ..prune
        });
        assert!(r.held.is_empty());
    }

    #[test]
    fn the_retry_backoff_doubles_up_to_its_bound() {
        let poll = Duration::from_secs(1);
        let waits: Vec<u64> = (0..8).map(|f| retry_backoff(poll, f).as_secs()).collect();
        assert_eq!(waits, [1, 2, 4, 8, 16, 30, 30, 30]);
        assert_eq!(
            retry_backoff(Duration::from_secs(60), 3),
            Duration::from_secs(60)
        );
    }

    // A failed round outputs 0 for a key it creates: the slot stays empty
    // with no state (what a reload of the empty slot gives), while the key
    // it read keeps its state. An ok round's create fills the slot.
    #[test]
    fn a_created_key_with_commitment_0_stays_empty() {
        let mut state = empty(&["pool", "fresh"]);
        state.advance(&attempt(vec![key_state("pool", 0x5a1)]));
        state.advance(&attempt(vec![
            key_state("pool", 0x5a1),
            key_state("fresh", 0),
        ]));
        assert_eq!(state.slots["fresh"], empty(&["fresh"]).slots["fresh"]);
        assert_eq!(state.slots["pool"].commitment, Fr::from(0x5a1u64));
        assert_eq!(state.view(), vec![key_state("pool", 0x5a1)]);

        state.advance(&attempt(vec![key_state("fresh", 0xf01)]));
        assert_eq!(state.slots["fresh"].state, Some(key_state("fresh", 0xf01)));
        assert_eq!(state.commitments()["fresh"], Fr::from(0xf01u64));
    }
}
