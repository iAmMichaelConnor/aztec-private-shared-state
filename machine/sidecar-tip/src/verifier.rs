//! The node's chain verifier (docs/ARCHITECTURE.md section 6, "The chain
//! verifier"; section 3, step 4; section 5, invariant 13): the one step the
//! tip adds to a node. Before a queued round loads anything, the node
//! re-reads the chain through its own Aztec node, rebuilds the request the
//! scheduler should have sent with the same synthesis code
//! ([`crate::synthesise`]) and refuses (400) the received one when it
//! differs:
//!
//! ```text
//! class           the instance's current contract class is the contract
//!                 manifest's contract.class_id
//! head            the chain request id is requests[head] or one of the
//!                 entries after it within the reader's lookahead
//! stale period    the contract's stored TipConfig.stale_blocks equals the
//!                 contract manifest's queue.stale_blocks
//! state           each commitment slot's state, checked by the key's tip
//!                 state (crate::state) against the commitment the slot
//!                 holds or, for a pipelined request, this node's own latest
//!                 committed result for the entry just before it, while that
//!                 entry is live (done[index] not yet written); a node-held
//!                 slot at a commitment this node holds no version of is
//!                 refused (a fault)
//! inputs          as the package's intake finds them (crate::intake): the
//!                 request log on chain under on-chain intake, the inputs
//!                 this node stored when it signed the receipt under receipt
//!                 intake, and under secret-shared receipt intake the clear inputs,
//!                 C and this node's own envelopes with their share hashes
//! ids             check_request_ids: the chain request id from those
//!                 inputs (from C under a secret-shared intake), the machine request
//!                 id from it, the records' note hashes and the pinned
//!                 values below
//! pinned values   each public read simulated (or read from its backing
//!                 slot) by this node, under its parameters' PUBLIC names;
//!                 on an entry's first attempt the request's own value
//!                 where the read's freshness policy admits it against
//!                 this node's (under `epoch` the epoch before this node's,
//!                 under `tolerance` a value in the band), as `apply`
//!                 would; once this node holds another attempt of the
//!                 entry, this node's own value (`admit_pinned`)
//! the rest        state_keys (the package's request keys from the contract
//!                 manifest), the shared inputs (none under the non-secret-shared
//!                 intakes; under a secret-shared intake this node's own envelope
//!                 and the stored share hashes of each), no requester: the
//!                 whole request equals the rebuilt one, byte for byte
//! ```
//!
//! The init round (crate::init) takes an init branch instead, since no
//! `requests[head]` holds it: on this node's own view the contract is
//! configured, every slot the init creates is empty, and the request is the
//! one rebuilt from the init inputs under the fixed init request id
//! ([`ChainVerifier::check_init`]).
//!
//! Every fact about the namespace's contract (its queue, stale period slot,
//! state keys, plain reads and init round) comes from the namespace's
//! registered contract manifest, read from this node's own store at each
//! request ([`crate::TipLayout`]); the node's `[[tip.namespaces]]` only lists
//! which namespaces it serves.
//!
//! It only refuses and never changes a request. Nothing it reads is trusted
//! for soundness: `apply` checks the head, the slots and the pinned reads on
//! chain, so a lying or stale Aztec node can only make this node refuse
//! (which delays the queue), never make a wrong result land.
//!
//! [`ChainVerifier::read`] makes every chain read at one proposed block and
//! then confirms that block is still on the chain (the reader's one
//! detection of a replaced block, [`ChainReader::confirm`]); a replaced block
//! at the snapshot or during the reads restarts them at a new snapshot, so
//! a request is only ever checked against the chain as it stands: one built
//! on a replaced block is refused unless the replacement gives the same
//! request;
//! [`ChainVerifier::check`] compares without any I/O but this node's own
//! rows; [`ChainVerifier::verify`] is the step 4 hook, synchronous like the
//! rest of the lifecycle, running the reads on a small runtime of its own.
//! An accepted request's [`QueueRead`] (the block, the head, the entry's
//! index, each slot with the old commitment the round runs on) is what the
//! tip's holders load and commit against at steps 8 and 15.
//!
//! An accepted request's view also names, per key, the versions whose
//! orphan mark the chain no longer holds (the key's tip state's
//! [`TipState::replaced`](crate::TipState::replaced) over this node's rows:
//! node-held keys only), which the round's commit marks again rather than
//! delete.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use sidecar_core::abi::CircuitShape;
use sidecar_core::error::Refusal;
use sidecar_core::field::{FieldHex, Fr, fr_to_hex};
use sidecar_core::manifest::{KeyRef, PublicOperand, PublicSource, Source};
use sidecar_core::pipeline::{self, ChainRound, VerifierRows};
use sidecar_core::request::{NODES, NodeRequest, PublicValue, StateKeys};
use sidecar_core::state::{ChainKey, QueueRead};
use sidecar_core::store::{RequestRow, RequestStatus};

use crate::blocking::{Blocking, bounded};
use crate::chain::rpc::Transport;
use crate::chain::{
    ChainReader, PinnedValues, QueueEntry, ReadError, ReaderConfig, StoredStaleBlocks,
    commitment_slots, short,
};
use crate::check_request_ids;
use crate::init::{InitLayout, InitRead, init_request};
use crate::intake::{ChainAt, ChainHeld, NodeInputs};
use crate::namespace::TipLayout;
use crate::state::tree::{PublicMap, check_values};
use crate::state::{KeyState, TipCheck, request_key};
use crate::synth::{SynthesisView, TipPackage, synthesise};

/// The bound on one request's chain reads, 20 s: all of them (the tip, the
/// queue window, `done` of the entry before a pipelined request, the slots,
/// the request log, the pinned reads, the stored stale period), each call
/// also bounded by the RPC timeout (10 s). The hook runs under the
/// namespace lock, so a silent Aztec node must not hold the namespace for
/// long; a healthy node answers the reads in well under a second. A slow or
/// silent node makes this node refuse (400) every queued round until it
/// recovers (liveness only).
pub const DEFAULT_VERIFY_TIMEOUT: Duration = Duration::from_secs(20);
/// How many snapshots one request's reads may take, 3: a pinned read
/// simulated on a block other than the snapshot's (the tip moved during the
/// reads) or a replaced block the reads used ([`ReadError::replaced`]: the
/// follower's prune event at the snapshot or at the confirming poll after
/// the reads, a log query's reference block gone) restarts the reads at a
/// new snapshot; a new block every 6 s rarely lands during them.
pub const SNAPSHOT_ATTEMPTS: usize = 3;

/// The queue entry just before a pipelined request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Previous {
    pub index: u64,
    pub chain_request_id: Fr,
    /// `done[index]`: 0 pending, 1 applied, 2 skipped.
    pub done: u8,
}

/// One commitment slot as the verifier read it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SlotRead {
    /// The manifest key whose commitment the slot holds.
    pub at: KeyRef,
    /// The request key naming it (the slot written as a field).
    pub key: String,
    pub slot: Fr,
    pub commitment: Fr,
}

/// Everything [`ChainVerifier::read`] read for one request, at one block.
#[derive(Clone, Debug)]
pub struct ChainCheck {
    pub block: u64,
    /// The hash of `block`, the snapshot's.
    pub block_hash: Fr,
    /// The settled block, as the reader read it with `block`
    /// (`ChainReader::settled`): the retention floor.
    pub settled: u64,
    pub head: u64,
    pub tail: u64,
    /// The request's entry: the head or a pipelined entry after it.
    pub entry: QueueEntry,
    /// The entry before it, when it is not the head.
    pub previous: Option<Previous>,
    /// The circuit's commitment slots, in `commitment_slot` order.
    pub slots: Vec<SlotRead>,
    /// What the package's intake keeps on chain for the request
    /// ([`crate::IntakeSource::read_chain`]: the request log under on-chain
    /// intake), opaque to the verifier.
    pub held: ChainHeld,
    pub pinned: PinnedValues,
    pub stale_blocks: StoredStaleBlocks,
}

/// The chain verifier of one node.
pub struct ChainVerifier<T> {
    /// This node's index: the request it receives is its own projection.
    node: usize,
    reader: ChainReader<T>,
    /// The namespaces this node serves (its `[[tip.namespaces]]`).
    listed: BTreeSet<Fr>,
    timeout: Duration,
    blocking: Blocking,
}

pub(crate) fn refused(message: impl std::fmt::Display) -> Refusal {
    Refusal::bad_request(format!("chain verifier: {message}"))
}

impl<T: Transport> ChainVerifier<T> {
    /// The verifier of node `node` over `transport` (the node's own Aztec
    /// node), serving the namespaces `listed`, with the reader's default
    /// lookahead.
    pub fn new(
        node: usize,
        transport: T,
        listed: impl IntoIterator<Item = Fr>,
    ) -> std::io::Result<Self> {
        Self::with_config(node, transport, listed, ReaderConfig::default())
    }

    pub fn with_config(
        node: usize,
        transport: T,
        listed: impl IntoIterator<Item = Fr>,
        config: ReaderConfig,
    ) -> std::io::Result<Self> {
        assert!(node < NODES, "node index {node} out of range");
        Ok(ChainVerifier {
            node,
            reader: ChainReader::with_config(transport, config),
            listed: listed.into_iter().collect(),
            timeout: DEFAULT_VERIFY_TIMEOUT,
            blocking: Blocking::new("chain-verifier")?,
        })
    }

    /// Bound one request's reads by `timeout` instead of the default.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn reader(&self) -> &ChainReader<T> {
        &self.reader
    }

    /// The layout of `namespace` from its contract manifest in this node's
    /// `rows`, the version `version` (the one a round resolved its package
    /// in); 400 when this node does not serve it (not one of its
    /// `[[tip.namespaces]]`) or it is not a registered tip namespace.
    pub fn layout_of(
        &self,
        rows: &dyn VerifierRows,
        namespace: Fr,
        version: Fr,
    ) -> Result<TipLayout, Refusal> {
        self.check_listed(namespace)?;
        TipLayout::of_version(namespace, rows.contract_manifests(namespace)?, version)?.ok_or_else(
            || {
                refused(format!(
                    "namespace {} holds no contract manifest {} at this node",
                    fr_to_hex(namespace),
                    fr_to_hex(version)
                ))
            },
        )
    }

    fn check_listed(&self, namespace: Fr) -> Result<(), Refusal> {
        if !self.listed.contains(&namespace) {
            return Err(refused(format!(
                "namespace {} is not one of this node's [[tip.namespaces]], so it reads no \
                 chain for it and runs none of its queued rounds",
                fr_to_hex(namespace)
            )));
        }
        Ok(())
    }

    /// The request keys of package `circuit` in `ns`'s contract manifest,
    /// or 400.
    pub fn state_keys<'n>(
        &self,
        ns: &'n TipLayout,
        circuit: &str,
    ) -> Result<&'n StateKeys, Refusal> {
        ns.circuits.get(circuit).ok_or_else(|| {
            refused(format!(
                "package `{circuit}` names no request keys in the contract manifest of {}",
                fr_to_hex(ns.contract)
            ))
        })
    }

    /// Every chain read for chain request `chain` of `pkg` under `ns`, at
    /// one proposed block (module documentation). 400 when the request is
    /// not in this node's head window or a read fails.
    pub async fn read(
        &self,
        ns: &TipLayout,
        pkg: &TipPackage,
        state_keys: &StateKeys,
        chain: Fr,
    ) -> Result<ChainCheck, Refusal> {
        self.bounded_read(|| self.read_once(ns, pkg, state_keys, chain))
            .await
            .and_then(|found| found)
    }

    /// `read` until it gives an answer, at most [`SNAPSHOT_ATTEMPTS`] times
    /// while a block it read is replaced or a simulation ran on a newer
    /// block, all within the verifier's timeout; 400 on a failure.
    async fn bounded_read<R, F, Fut>(&self, mut read: F) -> Result<R, Refusal>
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = Result<R, ReadError>>,
    {
        let reads = async {
            let mut attempt = 0;
            loop {
                attempt += 1;
                match read().await {
                    Err(e) if retried(&e) && attempt < SNAPSHOT_ATTEMPTS => continue,
                    other => return other,
                }
            }
        };
        bounded(self.timeout, reads).await.map_err(refused)
    }

    async fn read_once(
        &self,
        ns: &TipLayout,
        pkg: &TipPackage,
        state_keys: &StateKeys,
        chain: Fr,
    ) -> Result<Result<ChainCheck, Refusal>, ReadError> {
        let snap = self.reader.snapshot().await?;
        if let Some(why) = self.runs_nothing(snap, ns).await? {
            return Ok(Err(refused(why)));
        }
        let settled = self.reader.settled().await.min(snap.block);
        let target = ns.target();
        let queue = self.reader.queue(snap, &target).await?;
        let Some(&entry) = queue.find(chain) else {
            return Ok(Err(refused(format!(
                "chain request {} is not the head or one of the {} entries after it in this \
                 node's view (block {}: head {}, tail {})",
                fr_to_hex(chain),
                self.reader.config().lookahead,
                snap.block,
                queue.head,
                queue.tail
            ))));
        };
        // the window holds every entry from the head up to the request's
        let previous = if entry.index > queue.head {
            let before = queue.window[(entry.index - queue.head - 1) as usize];
            Some(Previous {
                index: before.index,
                chain_request_id: before.chain_request_id,
                done: self.reader.done(snap, &target, before.index).await?,
            })
        } else {
            None
        };
        let named = match commitment_slots(&pkg.tip, state_keys) {
            Ok(named) => named,
            Err(e) => return Ok(Err(refused(e))),
        };
        // `commitment_slots` found a request key for every slot
        let views = self.reader.slots(snap, ns.contract, &named).await?;
        let slots = views
            .iter()
            .map(|v| SlotRead {
                at: v.key,
                key: request_key(state_keys, v.key)
                    .expect("a named key")
                    .to_string(),
                slot: v.slot,
                commitment: v.commitment,
            })
            .collect();
        let at = ChainAt {
            reader: &self.reader,
            snap,
            namespace: ns.contract,
            layout: ns.intake,
        };
        let held = pkg.intake.read_chain(&at, chain).await?;
        let stale_blocks = self
            .reader
            .stale_blocks(snap, ns.contract, ns.stale_blocks_slot)
            .await?;
        // last: a simulation that ran on a newer block restarts the reads
        let pinned = self
            .reader
            .pinned_values(snap, ns.contract, &pkg.tip, &ns.plain_reads)
            .await?;
        // every read above was of the snapshot's block, still on the chain
        self.reader.confirm(snap).await?;
        Ok(Ok(ChainCheck {
            block: snap.block,
            block_hash: snap.hash.expect(crate::state::SNAPSHOT_HASH),
            settled,
            head: queue.head,
            tail: queue.tail,
            entry,
            previous,
            slots,
            held,
            pinned,
            stale_blocks,
        }))
    }

    /// Compare `req` with the request this node rebuilds from `chain` and its
    /// own `rows` (module documentation). 400 naming the first difference;
    /// else what the round runs on.
    pub fn check(
        &self,
        req: &NodeRequest,
        pkg: &TipPackage,
        state_keys: &StateKeys,
        chain: &ChainCheck,
        rows: &dyn VerifierRows,
    ) -> Result<QueueRead, Refusal> {
        let ns = req.namespace.fr();
        let at = format!("block {}", chain.block);
        if let Some(differs) = chain
            .stale_blocks
            .differs(&pkg.name, pkg.tip.stale_blocks())
        {
            return Err(refused(format!("{differs} (at {at})")));
        }

        // the state: every slot against this node's view, by its tip state
        let pending = self.pending(ns, chain, rows)?;
        let mut state: Vec<KeyState> = Vec::new();
        let mut node_values = PublicMap::new();
        let mut old_commitments = Vec::with_capacity(chain.slots.len());
        let mut ran_on = QueueRead {
            block: chain.block,
            block_hash: chain.block_hash,
            settled: chain.settled,
            head: chain.head,
            index: chain.entry.index,
            keys: Vec::new(),
        };
        for slot in &chain.slots {
            let held = pkg.tip_state(slot.at).map_err(|e| refused(e.message))?;
            let at = TipCheck {
                node: self.node,
                req,
                package: pkg,
                slot,
                block: chain.block,
                head: chain.head,
                previous: chain.previous,
                pending: pending.as_ref(),
                rows,
            };
            let key_state = held.check(&at)?;
            let own = held.round_values(&at, &key_state)?;
            check_values(&key_state.key, key_state.commitment, &own, req)?;
            node_values.extend(own);
            old_commitments.push(key_state.commitment);
            if ran_on.key(&key_state.key).is_none() {
                ran_on.keys.push(ChainKey {
                    key: key_state.key.clone(),
                    slot: slot.commitment,
                    old: key_state.commitment,
                    replaced: Vec::new(),
                });
            }
            if !state.iter().any(|s| s.key == key_state.key) {
                state.push(key_state);
            }
        }

        // the inputs, as the package's intake finds them in this node's view
        let inputs = pkg.intake.node_view(&NodeInputs {
            node: self.node,
            namespace: ns,
            chain_request_id: chain.entry.chain_request_id,
            package: pkg,
            block: chain.block,
            held: &chain.held,
            rows,
        })?;
        // the pinned values: on an entry's first attempt the request's own
        // where its read's freshness policy admits them against this node's
        // view (`apply` would accept them), else this node's
        let earlier = rows
            .chain_request(ns, chain.entry.chain_request_id)?
            .map(|row| row.request_id)
            .filter(|id| *id != req.request_id);
        let admitted = match earlier {
            None => admit_pinned(pkg, &chain.pinned, req),
            Some(_) => chain.pinned.clone(),
        };
        let pinned = pkg
            .pinned_fields(&admitted)
            .map_err(|e| refused(e.message))?;
        let ids = check_request_ids(
            pkg.chain_request_id(ns, &*inputs),
            ns,
            &old_commitments,
            &pinned,
            req,
        );

        // the whole request, rebuilt
        let view = SynthesisView {
            namespace: ns,
            entry: chain.entry,
            state_keys,
            pinned: &admitted,
            state: &state,
            node_values: &node_values,
        };
        let expected = synthesise(&view, pkg, &*inputs).map(|x| x.request);
        if let Err(e) = ids {
            // A request at another pinned value carries a machine request id
            // over that value: name the pinned read, the cause, not the id.
            let named = expected.ok().and_then(|x| {
                pinned_difference(&x.project(self.node), req, pkg, &chain.pinned, chain.block)
            });
            return Err(match (named, earlier) {
                (Some(mut named), Some(attempt)) => {
                    named.message = format!(
                        "{}; this node already ran attempt {attempt} of this entry, so a new \
                         attempt takes this node's own pinned values",
                        named.message
                    );
                    named
                }
                (Some(named), None) => named,
                (None, _) => refused(e.message),
            });
        }
        let expected = expected.map_err(|e| refused(e.message))?.project(self.node);
        first_difference(&expected, req, pkg, &chain.pinned, chain.block)?;
        Ok(ran_on)
    }

    // Which state a request may run on, by the key's tip state
    // (crate::state, `TipState::check`). A chain-held key's state is
    // accepted when its record's note hash is the commitment its slot holds
    // or, for a pipelined request (an entry after the head), the new
    // commitment for the same key of this node's own latest committed result
    // for the entry just before it, while that entry is live: `done[index]`
    // not yet written and the entry not below the head. A node-held key
    // derives one expected commitment: that result's new commitment when the
    // previous entry is live and its latest attempt created a version of the
    // key, else the slot's, and that version must be live under the slot and
    // the head this node read (its parent chain reaches the slot and passes
    // no version of an entry behind the head that the slot does not hold); a
    // request on any other state is refused on its machine request id rather
    // than as a stale record. The scheduler builds only the request this rule
    // expects. A rolled-back result, an older attempt, or a result two
    // entries back is not accepted. The rule limits what a new round may
    // build on only: the store keeps every live
    // attempt's node-held version, so an older attempt that lands is the
    // slot's commitment, and the next round runs on it. The scheduler
    // pipelines on the previous result before it is logged, and each node
    // knows which result it committed itself; one step back covers any
    // pipeline depth, since every entry chains from the one before it. An
    // entry whose predecessor did not write the key it reads (another
    // circuit), or wrote it with an unchanged commitment, runs only on the
    // slot's commitment; once the predecessor is applied or skipped only the
    // slot counts, so a pipelined attempt on a skipped entry's result is
    // refused and the scheduler recomputes.
    /// The entry before a pipelined request, with this node's latest
    /// committed result for it, while that entry is still live.
    fn pending(
        &self,
        ns: Fr,
        chain: &ChainCheck,
        rows: &dyn VerifierRows,
    ) -> Result<Option<RequestRow>, Refusal> {
        let Some(previous) = chain.previous else {
            return Ok(None);
        };
        if previous.done != crate::chain::layout::DONE_PENDING {
            return Ok(None);
        }
        Ok(rows
            .chain_request(ns, previous.chain_request_id)?
            .filter(|row| row.status == RequestStatus::Committed))
    }

    /// The step 4 hook: the namespace's layout from this node's rows
    /// ([`Self::layout_of`]), then [`Self::verify_in`]. Queued rounds only (the
    /// lifecycle calls it for nothing else).
    pub fn verify(&self, req: &NodeRequest, round: &ChainRound<'_>) -> Result<QueueRead, Refusal>
    where
        T: 'static,
    {
        let ns = self.layout_of(round.rows, req.namespace.fr(), round.manifest_hash)?;
        self.verify_in(&ns, req, round)
    }

    /// Read, then check, under the namespace layout `ns`.
    pub fn verify_in(
        &self,
        ns: &TipLayout,
        req: &NodeRequest,
        round: &ChainRound<'_>,
    ) -> Result<QueueRead, Refusal>
    where
        T: 'static,
    {
        let pkg = TipPackage::from_round(round)
            .map_err(|e| refused(e.message))?
            .with_version(req.manifest_hash.map(FieldHex::fr));
        let state_keys = self.state_keys(ns, &pkg.name)?;
        let chain = req
            .chain_request_id
            .ok_or_else(|| refused("the request carries no chain request id"))?
            .fr();
        let (what, result) = match ns.init.as_ref().filter(|i| i.circuit == pkg.name) {
            Some(init) => (
                "the init round",
                self.blocking
                    .run(self.read_init(ns, init, state_keys))
                    .and_then(|read| self.check_init(req, &pkg, state_keys, &read)),
            ),
            None => (
                "the request",
                self.blocking
                    .run(self.read(ns, &pkg, state_keys, chain))
                    .and_then(|read| self.check(req, &pkg, state_keys, &read, round.rows))
                    .and_then(|read| {
                        self.with_replaced_marks(req, &pkg, state_keys, read, round.rows)
                    }),
            ),
        };
        match &result {
            Ok(view) => tracing::info!(
                chain_request_id = %fr_to_hex(chain),
                block = view.block,
                index = view.index,
                head = view.head,
                "chain verifier: {what} is this node's view"
            ),
            Err(refusal) => tracing::info!(
                chain_request_id = %fr_to_hex(chain),
                error = %refusal.message,
                "chain verifier: {what} refused"
            ),
        }
        result
    }

    /// `read` with each key's versions whose orphan mark the chain no longer
    /// holds (sidecar-core `VersionView::replaced`), each by its key's tip
    /// state ([`TipState::replaced`](crate::TipState::replaced)), from this
    /// node's rows, which the round's commit marks again rather than delete.
    fn with_replaced_marks(
        &self,
        req: &NodeRequest,
        pkg: &TipPackage,
        state_keys: &StateKeys,
        mut read: QueueRead,
        rows: &dyn VerifierRows,
    ) -> Result<QueueRead, Refusal>
    where
        T: 'static,
    {
        let ns = req.namespace.fr();
        for key in &mut read.keys {
            let held = pkg.tip_state_of(state_keys, &key.key).ok_or_else(|| {
                refused(format!(
                    "circuit `{}` loads or stores no request key `{}`",
                    pkg.name, key.key
                ))
            })?;
            let versions = rows.tip_versions(ns, &key.key)?;
            key.replaced = self
                .blocking
                .run(held.replaced(&versions, read.settled, &self.reader));
        }
        Ok(read)
    }

    /// Why no round of `ns`'s version runs at `snap`: the instance runs
    /// another class than the version was built for, or the contract's
    /// circuit pins name another version; `None` when it may run.
    async fn runs_nothing(
        &self,
        snap: crate::chain::Snapshot,
        ns: &TipLayout,
    ) -> Result<Option<String>, ReadError> {
        let class = self.reader.current_class(snap, ns.contract).await?;
        if let Some(why) = ns.class_differs(class, snap.block) {
            return Ok(Some(why));
        }
        let in_force = self.reader.manifest_in_force(snap, ns).await?;
        Ok(ns.version_differs(in_force, snap.block))
    }

    /// The init round's chain reads ([`crate::init`]) at one proposed block,
    /// bounded as [`Self::read`]'s. 400 when a read fails.
    pub async fn read_init(
        &self,
        ns: &TipLayout,
        init: &InitLayout,
        state_keys: &StateKeys,
    ) -> Result<InitRead, Refusal> {
        self.bounded_read(|| async {
            let snap = self.reader.snapshot().await?;
            if let Some(why) = self.runs_nothing(snap, ns).await? {
                return Ok(Err(refused(why)));
            }
            let read = self
                .reader
                .init(snap, &ns.target(), init, state_keys)
                .await?;
            self.reader.confirm(snap).await?;
            Ok(Ok(read))
        })
        .await
        .and_then(|read| read)
    }

    /// Compare `req`, a request of the init circuit `pkg`, with the init
    /// request this node rebuilds from `chain`, its own init reads: 400 when
    /// the contract is not configured, a slot the init creates is written,
    /// or the request is not the
    /// rebuilt one (naming the first difference). Else what the round runs
    /// on: no commitment slot, at the head.
    pub fn check_init(
        &self,
        req: &NodeRequest,
        pkg: &TipPackage,
        state_keys: &StateKeys,
        chain: &InitRead,
    ) -> Result<QueueRead, Refusal> {
        let ns = req.namespace.fr();
        let at = format!("block {}", chain.block);
        if !chain.is_configured() {
            return Err(refused(format!(
                "the contract is not configured at {at} (Configured.configured is {}): the init \
                 round waits for `configure`",
                short(chain.configured)
            )));
        }
        if let Some((key, commitment)) = chain.written() {
            return Err(refused(format!(
                "slot `{key}` holds {} at {at}: the init round runs only while every slot it \
                 creates is empty",
                fr_to_hex(*commitment)
            )));
        }
        let expected = init_request(ns, chain, pkg, state_keys)
            .map_err(|e| refused(e.message))?
            .request;
        let empty = pkg.init_commitments().unwrap_or_default();
        check_request_ids(
            chain.chain_request_id(ns, pkg.vk_hash),
            ns,
            &empty,
            &[],
            req,
        )
        .map_err(|e| refused(format!("{} (the init round's fixed ids)", e.message)))?;
        first_difference(
            &expected.project(self.node),
            req,
            pkg,
            &PinnedValues::default(),
            chain.block,
        )?;
        // the init round creates its keys: it marks and prunes no version
        Ok(QueueRead {
            block: chain.block,
            head: chain.head,
            index: chain.head,
            ..QueueRead::default()
        })
    }
}

/// Whether a failed read restarts at a new snapshot: the tip moved under a
/// simulation, or a block the reads used was replaced.
fn retried(e: &ReadError) -> bool {
    e.replaced() || matches!(e, ReadError::SnapshotMoved { .. })
}

impl<T: Transport + 'static> ChainVerifier<T> {
    /// The verifier as sidecar-core's step 4 hook.
    pub fn into_hook(self) -> pipeline::ChainVerifier {
        let verifier = Arc::new(self);
        Box::new(move |req, round| verifier.verify(req, round))
    }
}

// The attempts one queue entry may run at. Each pinned value is a new
// machine request id and a full round whose outputs the orchestrator reads,
// so an orchestrator free to pick any admitted value on every attempt could
// run the same queued inputs at many values within a band and learn from the
// outputs. The freshness admission therefore applies to an entry's first
// attempt only: once this node holds a row of another attempt of the entry
// (any status: a rolled-back attempt still ran), a new attempt is checked at
// this node's own pinned values, as under `exact`, and a replay of the same
// attempt is checked as before. The distinct values an entry runs at are then
// the first attempt's and each value the source actually takes on chain. The
// scheduler keeps its held attempt while its values are admitted and builds a
// new one from its own fresh read, which is this node's unless the source
// moved between the two reads; such an attempt is refused and rebuilt at the
// next step, the liveness of an `exact` read.
/// This node's pinned values with each read's replaced by the request's
/// where the read's freshness policy admits the request's against this
/// node's view ([`sidecar_core::manifest::PublicRead::admits`]): under
/// `epoch` a request made one epoch before this node's read, under
/// `tolerance` one within the band, is checked as made; anything else is
/// checked against this node's own values, and so refused naming the read.
/// The chain verifier admits so on an entry's first attempt only.
fn admit_pinned(pkg: &TipPackage, own: &PinnedValues, req: &NodeRequest) -> PinnedValues {
    let mut admitted = own.clone();
    for value in &mut admitted.0 {
        let Some(read) = pkg
            .tip
            .public_reads()
            .iter()
            .find(|r| r.param == value.param)
        else {
            continue;
        };
        if let Some(used) = pkg.pinned_in(read, &req.public)
            && read.admits(&value.values, value.previous, &used)
        {
            value.values = used;
        }
    }
    admitted
}

/// The pinned read that fills the public name `name` (its value or, under
/// `epoch`, its epoch), if one does: its `param`.
fn pinned_param_of<'p>(shape: &CircuitShape, pkg: &'p TipPackage, name: &str) -> Option<&'p str> {
    pkg.tip.public_reads().iter().find_map(|read| {
        read.params()
            .any(|param| {
                let source = shape.param(param).map(|p| &p.source);
                matches!(
                    source,
                    Some(Source::Public(PublicSource::One(PublicOperand::Name(n)))) if n == name
                )
            })
            .then_some(read.param.as_str())
    })
}

/// 400 for the public name `name` whose value in the received request is
/// `got` and in the rebuilt one `want`, rebuilt with this node's `pinned`
/// values read at `block`.
fn public_difference(
    name: &str,
    want: Option<&PublicValue>,
    got: Option<&PublicValue>,
    pkg: &TipPackage,
    pinned: &PinnedValues,
    block: u64,
) -> Refusal {
    let pinned = pinned_param_of(&pkg.shape, pkg, name).and_then(|p| pinned.get(p));
    let what = match pinned {
        Some(value) => format!(
            "the pinned read `{}` in this node's view at block {block}",
            value.function
        ),
        None => "the queued request's input".into(),
    };
    refused(match (want, got) {
        (Some(w), Some(g)) => format!(
            "field `public.{name}`: {} differs from {}, {what}",
            json(g),
            json(w)
        ),
        (Some(w), None) => format!("field `public.{name}`: missing; {what} is {}", json(w)),
        (None, _) => {
            format!("field `public.{name}`: not an input of the queued request or a pinned read")
        }
    })
}

/// 400 naming the first pinned read whose value in `received` is not the one
/// this node read, if any.
fn pinned_difference(
    expected: &NodeRequest,
    received: &NodeRequest,
    pkg: &TipPackage,
    pinned: &PinnedValues,
    block: u64,
) -> Option<Refusal> {
    expected.public.iter().find_map(|(name, want)| {
        let got = received.public.get(name);
        (pinned_param_of(&pkg.shape, pkg, name).is_some() && got != Some(want))
            .then(|| public_difference(name, Some(want), got, pkg, pinned, block))
    })
}

/// 400 naming the first field where `received` is not `expected`, which
/// this node rebuilt with its `pinned` values at `block`.
fn first_difference(
    expected: &NodeRequest,
    received: &NodeRequest,
    pkg: &TipPackage,
    pinned: &PinnedValues,
    block: u64,
) -> Result<(), Refusal> {
    // the package was resolved by the request's circuit name, and REGISTER
    // binds the manifest's `circuit` to that name: the two circuits agree
    if expected == received {
        return Ok(());
    }
    if expected.state_keys != received.state_keys {
        return Err(refused(format!(
            "field `state_keys`: {} is not {}, this node's configured request keys for circuit `{}`",
            json(&received.state_keys),
            json(&expected.state_keys),
            pkg.name
        )));
    }
    let names: std::collections::BTreeSet<&String> = expected
        .public
        .keys()
        .chain(received.public.keys())
        .collect();
    for name in names {
        let (want, got) = (expected.public.get(name), received.public.get(name));
        if want == got {
            continue;
        }
        return Err(public_difference(name, want, got, pkg, pinned, block));
    }
    if expected.shared_inputs != received.shared_inputs {
        let (want, got) = (&expected.shared_inputs, &received.shared_inputs);
        if want.len() != got.len() {
            return Err(refused(format!(
                "field `shared_inputs`: {} shared input(s), and the request this node rebuilds \
                 from its own view carries {} ({:?})",
                got.len(),
                want.len(),
                want.iter().map(|s| &s.name).collect::<Vec<_>>()
            )));
        }
        let k = want.iter().zip(got).position(|(w, g)| w != g).unwrap_or(0);
        return Err(refused(format!(
            "field `shared_inputs[{k}]` (`{}`): differs from `{}` with this node's envelope and \
             the share hashes it stored when it signed the receipt",
            got[k].name, want[k].name
        )));
    }
    if expected.shared_log != received.shared_log {
        return Err(refused(format!(
            "field `shared_log`: differs from the request log this node read at block {block}, \
             the one whose hash the contract stores"
        )));
    }
    if received.requester.is_some() || received.signature.is_some() {
        return Err(refused(
            "fields `requester` and `signature`: a queued request carries neither (its \
             records are machine-owned)",
        ));
    }
    if expected.records != received.records {
        return Err(refused(format!(
            "field `records`: {} record(s) for keys {:?}; the circuit's commitment slots take \
             one each, for keys {:?}",
            received.records.len(),
            received.records.iter().map(|r| &r.key).collect::<Vec<_>>(),
            expected.records.iter().map(|r| &r.key).collect::<Vec<_>>()
        )));
    }
    Err(refused(format!(
        "the request differs from the one this node rebuilds at block {block} (namespace {}, \
         request id {}, chain request id {:?})",
        FieldHex(expected.namespace.fr()),
        expected.request_id,
        expected.chain_request_id
    )))
}

/// JSON of a value, for messages.
fn json<T: serde::Serialize>(value: &T) -> String {
    serde_json::to_string(value).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::layout::QueueLayout;
    use crate::chain::rpc::RpcError;
    use crate::intake::IntakeLayout;
    use crate::intake::{PlainFound, SharedReceiptFound};
    use crate::state::TipFuture;
    use crate::state::chain::key_state;
    use crate::state::tree::TreeSource;
    use crate::testing::MemoryChain;
    use crate::testing::Rows;
    use crate::{chain_request_id, inputs_hash, machine_request_id};
    use serde_json::Value;
    use sidecar_core::error::{ErrorClass, parse_json};
    use sidecar_core::field::{HexBytes, fr_from_hex};
    use sidecar_core::register::Signature;
    use sidecar_core::request::{Request, StateRecord};
    use sidecar_core::store::{
        MemoryStore, PackageRow, ReceiptRow, Sealed, SealedKind, TipVersion, VersionStatus,
    };
    use sidecar_core::tree::{TreePaths, TreeQuery};
    use std::collections::BTreeMap;

    use crate::testing::AMM_SWAP_TIP;
    /// The same manifest with the pool node-held (the AMM tip example's).
    const AMM_SWAP_TIP_NODE: &str =
        include_str!("../../../examples/amm-tip/manifests/amm_swap_tip.json");

    const NS: u64 = 0x5e;
    const POOL: &str = "0x12";
    const QUEUE: u64 = 12;
    const STALE_SLOT: u64 = 1;
    const ORACLE: u64 = 0x1234;
    const NODE: usize = 1;

    fn ns() -> Fr {
        Fr::from(NS)
    }

    fn package(intake: &str, priced: bool) -> TipPackage {
        package_of(AMM_SWAP_TIP, intake, priced)
    }

    /// The package of the amm-tip manifest `manifest` under `intake`, with
    /// `direction` filled by a pinned read when `priced`.
    fn package_of(manifest: &str, intake: &str, priced: bool) -> TipPackage {
        let reads = if priced {
            r#"[{"contract": "0x1234", "function": "get_price", "args": [], "param": "direction"}]"#
        } else {
            "[]"
        };
        let pinned: &[&str] = if priced { &["direction"] } else { &[] };
        package_with_reads(manifest, intake, reads, pinned)
    }

    /// The package of the amm-tip manifest `manifest` under `intake` with
    /// the public reads `reads`, filling the public parameters `pinned`.
    fn package_with_reads(
        manifest: &str,
        intake: &str,
        reads: &str,
        pinned: &[&str],
    ) -> TipPackage {
        let text = manifest
            .replace("\"onchain\"", &format!("\"{intake}\""))
            .replace(
                "\"public_reads\": []",
                &format!("\"public_reads\": {reads}"),
            );
        // synth.rs's test ABI: the amm-tip circuit, its read public
        let row = PackageRow {
            name: "amm_swap_tip".into(),
            manifest_hash: Fr::from(0u64),
            circuit_json: serde_json::to_vec(&serde_json::json!({
                "abi": crate::testing::amm_swap_tip_abi(pinned)
            }))
            .unwrap(),
            manifest: parse_json(&text).unwrap(),
            vk: vec![],
            vk_hash: Fr::from(0x7e57u64),
            disabled: false,
            seq: 1,
        };
        TipPackage::from_row(&row, Some(50)).unwrap().unwrap()
    }

    fn state_keys() -> StateKeys {
        StateKeys {
            reads: vec![POOL.into()],
            writes: vec![POOL.into()],
        }
    }

    /// The namespace's layout: what its contract manifest would state.
    fn namespace() -> TipLayout {
        layout(
            ns(),
            BTreeMap::from([("amm_swap_tip".to_string(), state_keys())]),
        )
    }

    /// The layout of `contract`, the mock contract's queue and stale period
    /// slots and `circuits`' request keys, under the in-memory chain's class.
    fn layout(contract: Fr, circuits: BTreeMap<String, StateKeys>) -> TipLayout {
        let slots = circuits
            .values()
            .flat_map(|k| k.reads.iter().chain(&k.writes))
            .map(|k| (fr_from_hex(k).unwrap(), k.clone()))
            .collect();
        TipLayout {
            contract,
            manifest_hash: Fr::from(0x6du64),
            class_id: Fr::from(crate::testing::MEMORY_CLASS_ID),
            node_keys: sidecar_core::manifest::contract::NodeKeysAxis::Rotating,
            upgrades: sidecar_core::manifest::contract::Upgrades::Fixed,
            circuit_pins: None,
            queue: QueueLayout::new(Fr::from(QUEUE)),
            intake: IntakeLayout::default(),
            stale_blocks_slot: Fr::from(STALE_SLOT),
            circuits,
            slots,
            plain_reads: BTreeMap::new(),
            init: None,
        }
    }

    fn state(note_hash: u64) -> StateRecord {
        StateRecord {
            key: POOL.into(),
            note_hash: FieldHex(Fr::from(note_hash)),
            c: [0, 1, 2].map(|i| HexBytes(vec![i; 4])),
            record_hashes: [0, 1, 2].map(|i| FieldHex(Fr::from(i as u64 + 1))),
        }
    }

    /// The app inputs of queue entry `n`: amount_in, direction (unless the
    /// package's pinned read fills it), min_out and the partial note.
    fn inputs(n: u64, priced: bool) -> Vec<Fr> {
        let partial = Fr::from(0x9a00 + n);
        if priced {
            vec![Fr::from(1000 + n), Fr::from(900u64), partial]
        } else {
            vec![
                Fr::from(1000 + n),
                Fr::from(1u64),
                Fr::from(900u64),
                partial,
            ]
        }
    }

    fn chain_id(pkg: &TipPackage, n: u64, priced: bool) -> Fr {
        chain_request_id(ns(), pkg.vk_hash, &inputs(n, priced), Fr::from(n))
    }

    /// The chain the scheduler and the verifier read: `count` entries queued
    /// (on-chain request logs for each), the head at `head`, the pool slot holding
    /// `slot`, the stored stale period 50, the oracle at 1.
    struct World {
        pkg: TipPackage,
        priced: bool,
        mem: Arc<MemoryChain>,
        ids: Vec<Fr>,
    }

    impl World {
        fn new(intake: &str, priced: bool, count: u64, head: u64, slot: u64) -> World {
            Self::with(package(intake, priced), priced, count, head, slot)
        }

        /// On-chain intake of the amm-tip manifest with the pool node-held.
        fn node_held(count: u64, head: u64, slot: u64) -> World {
            let pkg = package_of(AMM_SWAP_TIP_NODE, "onchain", false);
            Self::with(pkg, false, count, head, slot)
        }

        fn with(pkg: TipPackage, priced: bool, count: u64, head: u64, slot: u64) -> World {
            let short = priced;
            let mem = Arc::new(MemoryChain::new(60));
            let ids: Vec<Fr> = (0..count).map(|n| chain_id(&pkg, n, short)).collect();
            for (n, id) in ids.iter().enumerate() {
                let mut fields = inputs(n as u64, short);
                fields.push(Fr::from(n as u64));
                mem.push_log(
                    ns(),
                    40,
                    crate::chain::layout::request_log_tag(*id),
                    &fields,
                );
            }
            mem.write_queue(ns(), QueueLayout::new(Fr::from(QUEUE)), &ids, head, 41);
            mem.set_storage(ns(), Fr::from(0x12u64), Fr::from(slot));
            mem.set_storage(ns(), Fr::from(STALE_SLOT), Fr::from(1u64));
            mem.set_storage(ns(), Fr::from(STALE_SLOT + 1), Fr::from(50u64));
            mem.set_call(
                Fr::from(ORACLE),
                "get_price()",
                &[],
                Ok(vec![Fr::from(1u64)]),
            );
            World {
                pkg,
                priced,
                mem,
                ids,
            }
        }

        fn verifier(&self) -> ChainVerifier<Arc<MemoryChain>> {
            ChainVerifier::new(NODE, self.mem.clone(), [ns()]).unwrap()
        }

        /// The scheduler's request for entry `n` on the chain-held `record`,
        /// with `price` as the pinned read.
        fn request(&self, n: u64, record: StateRecord, price: u64) -> Request {
            self.request_on(n, key_state(record), price)
        }

        /// The scheduler's request for entry `n` on the node-held pool at
        /// `commitment`: the request carries no record for it.
        fn node_request(&self, n: u64, commitment: u64) -> Request {
            let state = KeyState {
                key: POOL.into(),
                commitment: Fr::from(commitment),
                record: None,
            };
            self.request_on(n, state, 1)
        }

        fn request_on(&self, n: u64, state: KeyState, price: u64) -> Request {
            let pinned = PinnedValues(if self.priced {
                vec![crate::chain::PinnedValue {
                    param: "direction".into(),
                    contract: Fr::from(ORACLE),
                    function: "get_price()".into(),
                    args: vec![],
                    values: vec![Fr::from(price)],
                    previous: None,
                    block: 60,
                    source: crate::chain::PinnedSource::Simulated,
                }]
            } else {
                vec![]
            });
            let app = inputs(n, self.priced);
            let state_keys = state_keys();
            let state = [state];
            let view = SynthesisView {
                namespace: ns(),
                entry: QueueEntry {
                    index: n,
                    chain_request_id: chain_id(&self.pkg, n, self.priced),
                },
                state_keys: &state_keys,
                pinned: &pinned,
                state: &state,
                node_values: &PublicMap::new(),
            };
            let log = PlainFound::new(app, Fr::from(n));
            synthesise(&view, &self.pkg, &log).unwrap().request
        }

        fn verify(&self, rows: &Rows, req: &Request) -> Result<(), Refusal> {
            self.verify_with(&self.verifier(), rows, req)
        }

        fn verify_with<T: Transport + 'static>(
            &self,
            verifier: &ChainVerifier<T>,
            rows: &Rows,
            req: &Request,
        ) -> Result<(), Refusal> {
            self.verify_under(verifier, &namespace(), rows, req)
        }

        /// The verifier's check under the layout `ns`.
        fn verify_under<T: Transport + 'static>(
            &self,
            verifier: &ChainVerifier<T>,
            ns: &TipLayout,
            rows: &Rows,
            req: &Request,
        ) -> Result<(), Refusal> {
            verifier
                .verify_in(ns, &req.project(NODE), &self.round(rows))
                .map(|_| ())
        }

        fn round<'r>(&'r self, rows: &'r Rows) -> ChainRound<'r> {
            ChainRound {
                manifest: self.pkg.tip.manifest(),
                intake: self.pkg.tip.intake(),
                shape: &self.pkg.shape,
                vk_hash: self.pkg.vk_hash,
                manifest_hash: Fr::from(0u64),
                stale_blocks: self.pkg.tip.stale_blocks(),
                rows,
            }
        }

        fn refused(&self, rows: &Rows, req: &Request, needle: &str) {
            let err = self.verify(rows, req).unwrap_err();
            assert_eq!(err.class, ErrorClass::BadRequest, "{err}");
            assert!(err.message.contains(needle), "`{needle}` not in: {err}");
        }
    }

    /// The machine request id of the attempt that left `new_commitment`.
    fn attempt(new_commitment: u64) -> sidecar_core::RequestId {
        sidecar_core::RequestId(Fr::from(new_commitment))
    }

    impl Rows {
        /// This node's latest result for `chain`: the attempt
        /// `attempt(new_commitment)`, which sealed a record of the pool under
        /// `new_commitment` (a chain-held pool) or created its version under
        /// it (a node-held pool, [`Self::with_version`]).
        fn with_result(mut self, chain: Fr, new_commitment: u64, status: RequestStatus) -> Self {
            self.results.insert(
                chain,
                RequestRow {
                    request_id: attempt(new_commitment),
                    body_hash: Fr::from(2u64),
                    vk_hash: Fr::from(0x7e57u64),
                    proof: vec![],
                    public_inputs: vec![],
                    stored_keys: vec![],
                    created_keys: vec![],
                    sealed: vec![Sealed {
                        kind: SealedKind::Record,
                        key: POOL.into(),
                        note_hash: Fr::from(new_commitment),
                        c_i: vec![1; 4],
                    }],
                    signature: None,
                    status,
                    created_at: 1,
                    chain_request_id: Some(chain),
                },
            );
            self
        }

        /// A version of the node-held pool under `commitment`, built on
        /// `parent` by the attempt `attempt(made_by)` of entry 0.
        fn with_version(self, commitment: u64, parent: u64, made_by: u64) -> Self {
            self.with_version_of(0, commitment, parent, made_by)
        }

        /// A version of the node-held pool under `commitment`, built on
        /// `parent` by the attempt `attempt(made_by)` of entry `index`.
        fn with_version_of(
            mut self,
            index: u64,
            commitment: u64,
            parent: u64,
            made_by: u64,
        ) -> Self {
            self.versions.push((
                None,
                TipVersion {
                    key: POOL.into(),
                    commitment: Fr::from(commitment),
                    parent: Fr::from(parent),
                    index,
                    request_id: attempt(made_by),
                    vec: vec![],
                    tree: None,
                    status: VersionStatus::Live,
                    block: 41,
                    block_hash: Fr::from(0u64),
                },
            ));
            self
        }
    }

    #[test]
    fn the_scheduler_s_head_request_is_accepted() {
        let w = World::new("onchain", false, 3, 0, 0xc0);
        let req = w.request(0, state(0xc0), 1);
        w.verify(&Rows::default(), &req).unwrap();
        assert_eq!(
            req.request_id.fr(),
            machine_request_id(w.ids[0], &[Fr::from(0xc0u64)], &[])
        );
    }

    #[test]
    fn a_wrong_head_is_refused() {
        let w = World::new("onchain", false, 3, 1, 0xc0);
        // entry 0 is below the head
        w.refused(
            &Rows::default(),
            &w.request(0, state(0xc0), 1),
            "is not the head",
        );
        // an entry never queued (its inputs are logged, its id is not queued)
        let stray = chain_id(&w.pkg, 9, false);
        let mut fields = inputs(9, false);
        fields.push(Fr::from(9u64));
        w.mem.push_log(
            ns(),
            40,
            crate::chain::layout::request_log_tag(stray),
            &fields,
        );
        w.refused(
            &Rows::default(),
            &w.request(9, state(0xc0), 1),
            "is not the head",
        );
        // past the lookahead: head 1 + 4 entries
        let w = World::new("onchain", false, 7, 1, 0xc0);
        w.refused(
            &Rows::default(),
            &w.request(6, state(0xc0), 1),
            "is not the head",
        );
    }

    /// A reserved operand's value is part of the request the verifier
    /// rebuilds: the scheduler places the log's nonce under the parameter's
    /// name, and an orchestrator that changes or drops it is refused.
    #[test]
    fn a_substituted_reserved_value_is_refused() {
        let w = World::new("onchain", false, 1, 0, 0xc0);
        let rows = Rows::default();
        let req = w.request(0, state(0xc0), 1);
        let one = |v: u64| sidecar_core::request::PublicValue::One(FieldHex(Fr::from(v)));
        assert_eq!(req.public["user_nonce"], one(0));
        assert_eq!(req.public["vk_hash"], one(0x7e57));
        w.verify(&rows, &req).unwrap();
        for name in ["user_nonce", "vk_hash"] {
            let mut other = req.clone();
            other.public.insert(name.into(), one(1));
            w.refused(&rows, &other, &format!("field `public.{name}`"));
            let mut dropped = req.clone();
            dropped.public.remove(name);
            w.refused(&rows, &dropped, name);
        }
    }

    #[test]
    fn substituted_inputs_are_refused() {
        let w = World::new("onchain", false, 3, 0, 0xc0);
        let rows = Rows::default();
        // the ids are the entry's, the amount is not
        let mut req = w.request(0, state(0xc0), 1);
        req.public.insert(
            "amount_in".into(),
            sidecar_core::request::PublicValue::One(FieldHex(Fr::from(5u64))),
        );
        w.refused(&rows, &req, "field `public.amount_in`");
        // an extra public value
        let mut req = w.request(0, state(0xc0), 1);
        req.public.insert(
            "bonus".into(),
            sidecar_core::request::PublicValue::One(FieldHex(Fr::from(5u64))),
        );
        w.refused(&rows, &req, "field `public.bonus`");
        // a machine request id that is not the attempt's
        let mut req = w.request(0, state(0xc0), 1);
        req.request_id = sidecar_core::RequestId(Fr::from(77u64));
        w.refused(&rows, &req, "field `request_id`");
        // another chain request id under the head's machine request id
        let mut req = w.request(0, state(0xc0), 1);
        req.chain_request_id = Some(FieldHex(w.ids[1]));
        w.refused(&rows, &req, "field `request_id`");
        // other request keys than the node's configuration
        let mut req = w.request(0, state(0xc0), 1);
        req.state_keys.writes = vec!["0x13".into()];
        w.refused(&rows, &req, "field `state_keys`");
        // a record for a key the circuit has no commitment slot for
        let mut req = w.request(0, state(0xc0), 1);
        let mut extra = state(0xc0);
        extra.key = "0x13".into();
        req.records.push(extra);
        w.refused(&rows, &req, "field `records`");
        // the inputs on chain are not the ones the ids were made from
        let w = World::new("onchain", false, 3, 0, 0xc0);
        w.mem.push_log(
            ns(),
            30,
            crate::chain::layout::request_log_tag(w.ids[0]),
            &[Fr::from(1u64), Fr::from(0u64), Fr::from(0u64)],
        );
        w.refused(
            &rows,
            &w.request(0, state(0xc0), 1),
            "field `chain_request_id`",
        );
    }

    #[test]
    fn a_stale_slot_commitment_is_refused() {
        let w = World::new("onchain", false, 3, 0, 0xc1);
        w.refused(
            &Rows::default(),
            &w.request(0, state(0xc0), 1),
            "stale state record",
        );
        // no record at all
        let mut req = w.request(0, state(0xc1), 1);
        req.records.clear();
        w.refused(&Rows::default(), &req, "no state record");
    }

    #[test]
    fn a_pipelined_request_runs_on_this_node_s_pending_result() {
        let w = World::new("onchain", false, 3, 0, 0xc0);
        let rows = Rows::default()
            .with_result(w.ids[0], 0xd0, RequestStatus::Committed)
            .with_result(w.ids[1], 0xd1, RequestStatus::Committed);
        // entry 1 on this node's result for entry 0, entry 2 on entry 1's
        w.verify(&rows, &w.request(1, state(0xd0), 1)).unwrap();
        w.verify(&rows, &w.request(2, state(0xd1), 1)).unwrap();
        // the slot's own commitment is accepted too
        w.verify(&rows, &w.request(1, state(0xc0), 1)).unwrap();
        // not the result before it: entry 2 on entry 0's result
        w.refused(&rows, &w.request(2, state(0xd0), 1), "stale state record");
        // a result this node does not hold
        w.refused(
            &Rows::default(),
            &w.request(1, state(0xd0), 1),
            "holds no committed result for entry 0",
        );
        // a rolled-back result is not pending
        let rolled = Rows::default().with_result(w.ids[0], 0xd0, RequestStatus::RolledBack);
        w.refused(&rolled, &w.request(1, state(0xd0), 1), "stale state record");
        // pending ends when done[0] is written
        w.mem.set_storage(
            ns(),
            QueueLayout::new(Fr::from(QUEUE)).done(0),
            Fr::from(2u64),
        );
        w.refused(&rows, &w.request(1, state(0xd0), 1), "no longer pending");
        // once applied, the head's state is the slot
        let w = World::new("onchain", false, 3, 1, 0xd0);
        w.verify(&rows, &w.request(1, state(0xd0), 1)).unwrap();
    }

    /// A node-held pool: the request carries no record, and the round runs
    /// on the commitment the slot holds, which this node must hold a version
    /// of (`NodeVersions`' check); a slot at a commitment it holds no version
    /// of is a fault, and an empty slot is no state.
    #[test]
    fn a_node_held_request_runs_on_the_slot_s_version() {
        let w = World::node_held(3, 0, 0xc0);
        let rows = Rows::default().with_version(0xc0, 0, 0xb0);
        let req = w.node_request(0, 0xc0);
        assert!(req.records.is_empty());
        w.verify(&rows, &req).unwrap();
        assert_eq!(
            req.request_id.fr(),
            machine_request_id(w.ids[0], &[Fr::from(0xc0u64)], &[])
        );
        // a request on another commitment than the slot's
        w.refused(&rows, &w.node_request(0, 0xc1), "field `request_id`");
        // a record for the node-held pool
        let mut carried = req.clone();
        carried.records.push(state(0xc0));
        w.refused(&rows, &carried, "field `records`");
        // a slot at a commitment this node holds no version of
        w.refused(&Rows::default(), &req, "holds no version of: a fault");
        // an empty slot is no state, and no fault
        let empty = World::node_held(1, 0, 0);
        empty
            .verify(&Rows::default(), &empty.node_request(0, 0))
            .unwrap();
    }

    /// A pipelined request on a node-held pool runs on one commitment: the
    /// version this node's latest attempt for the live entry before it
    /// created, else the slot's. Unlike a chain-held record, the slot's own
    /// commitment is refused while that version exists, and so is an older
    /// attempt's version; a latest attempt that does not build on the slot
    /// refuses the request.
    #[test]
    fn a_pipelined_node_held_request_runs_on_this_node_s_latest_attempt() {
        let w = World::node_held(3, 0, 0xc0);
        // entry 0's attempts: 0xd5 an older one, 0xd0 the latest
        let versions = || {
            Rows::default()
                .with_version(0xc0, 0, 0xb0)
                .with_version(0xd5, 0xc0, 0xd5)
                .with_version(0xd0, 0xc0, 0xd0)
        };
        let rows = versions().with_result(w.ids[0], 0xd0, RequestStatus::Committed);
        w.verify(&rows, &w.node_request(1, 0xd0)).unwrap();
        w.refused(&rows, &w.node_request(1, 0xc0), "field `request_id`");
        w.refused(&rows, &w.node_request(1, 0xd5), "field `request_id`");
        // one step back only: entry 2 on entry 1's latest attempt
        let chained = versions()
            .with_version(0xd1, 0xd0, 0xd1)
            .with_result(w.ids[0], 0xd0, RequestStatus::Committed)
            .with_result(w.ids[1], 0xd1, RequestStatus::Committed);
        w.verify(&chained, &w.node_request(2, 0xd1)).unwrap();
        w.refused(&chained, &w.node_request(2, 0xd0), "field `request_id`");
        // a latest attempt whose parent chain does not reach the slot (an
        // orphan, however this node last marked it) is refused
        let orphan = Rows::default()
            .with_version(0xc0, 0, 0xb0)
            .with_version(0xd0, 0xbb, 0xd0)
            .with_result(w.ids[0], 0xd0, RequestStatus::Committed);
        w.refused(&orphan, &w.node_request(1, 0xd0), "does not build on it");
        w.refused(&orphan, &w.node_request(1, 0xc0), "does not build on it");
        // the latest attempt created no version (it left the pool's
        // commitment unchanged): the slot's
        let unchanged = versions().with_result(w.ids[0], 0xd7, RequestStatus::Committed);
        w.verify(&unchanged, &w.node_request(1, 0xc0)).unwrap();
        w.refused(&unchanged, &w.node_request(1, 0xd0), "field `request_id`");
        // a rolled-back result is not pending: the slot's
        let rolled = versions().with_result(w.ids[0], 0xd0, RequestStatus::RolledBack);
        w.verify(&rolled, &w.node_request(1, 0xc0)).unwrap();
        w.refused(&rolled, &w.node_request(1, 0xd0), "field `request_id`");
        // pending ends when done[0] is written: the slot's
        w.mem.set_storage(
            ns(),
            QueueLayout::new(Fr::from(QUEUE)).done(0),
            Fr::from(2u64),
        );
        w.verify(&rows, &w.node_request(1, 0xc0)).unwrap();
        w.refused(&rows, &w.node_request(1, 0xd0), "field `request_id`");
    }

    /// The pipelined rule reads the queue's head too: once entry 0 is
    /// skipped, entry 1's latest attempt built on entry 0's attempt is an
    /// orphan by index (its parent chain still reaches the slot), and a
    /// request for entry 2 is refused; entry 1's attempt on the slot's
    /// version, or on entry 0's attempt once that is applied, is accepted.
    #[test]
    fn a_pipelined_node_held_request_on_an_entry_behind_the_head_is_refused() {
        let queue = QueueLayout::new(Fr::from(QUEUE));
        // entry 0 skipped: the head is 1, the slot still 0xc0
        let w = World::node_held(3, 1, 0xc0);
        w.mem.set_storage(ns(), queue.done(0), Fr::from(2u64));
        let versions = || {
            Rows::default()
                .with_version(0xc0, 0, 0xb0)
                .with_version(0xd0, 0xc0, 0xd0)
                .with_version_of(1, 0xd1, 0xd0, 0xd1)
                .with_version_of(1, 0xd2, 0xc0, 0xd2)
        };
        let stale = versions().with_result(w.ids[1], 0xd1, RequestStatus::Committed);
        let by_index = "builds on a version of an entry behind the head 1";
        w.refused(&stale, &w.node_request(2, 0xd1), by_index);
        w.refused(&stale, &w.node_request(2, 0xc0), by_index);
        let fresh = versions().with_result(w.ids[1], 0xd2, RequestStatus::Committed);
        w.verify(&fresh, &w.node_request(2, 0xd2)).unwrap();
        // entry 0 applied under 0xd0: entry 1's attempt on it builds on the slot
        let applied = World::node_held(3, 1, 0xd0);
        applied.mem.set_storage(ns(), queue.done(0), Fr::from(1u64));
        applied
            .verify(&stale, &applied.node_request(2, 0xd1))
            .unwrap();
    }

    /// The three nodes' clear trees, as one store holds them.
    struct StoreTrees<'s> {
        store: &'s MemoryStore,
        ns: Fr,
    }

    impl TreeSource for StoreTrees<'_> {
        fn paths(
            &self,
            key: String,
            commitment: Fr,
            depth: u32,
            indices: Vec<u64>,
            open: Option<usize>,
        ) -> TipFuture<'_, Result<TreePaths, Refusal>> {
            let query = TreeQuery {
                namespace: FieldHex(self.ns),
                key,
                commitment: FieldHex(commitment),
                depth,
                indices,
                open,
            };
            Box::pin(async move { sidecar_core::tree::answer(self.store, &query) })
        }
    }

    /// A tree-valued node-held key (machine/circuits/manifests/tip_tree.json):
    /// the round runs on the version the slot names or, pipelined, on the
    /// version this node's latest attempt for the live entry before it
    /// created (`NodeVersions`' check, which `NodeTree` keeps), and the
    /// request's paths must be that version's clear tree at this node.
    #[test]
    fn a_tree_request_runs_on_this_node_s_latest_attempt() {
        use crate::state::tree::tests::{
            BOOK, NS as TREE_NS, app, book_leaf, package as tree_package, put_book,
        };
        let pkg = tree_package();
        let ns = Fr::from(TREE_NS);
        let store = MemoryStore::new();
        let leaves: Vec<(u64, Vec<Fr>)> = (0..3u64).map(|i| (i, book_leaf(i))).collect();
        let v1 = put_book(&store, TREE_NS, None, &leaves, 1, None);
        // entry n: amount 5 + n on positions 0 (an opening) and 2, nonce n
        let inputs = |n: u64| [5 + n, 0, 2, 2].map(Fr::from).to_vec();
        let ids: Vec<Fr> = (0..3)
            .map(|n| chain_request_id(ns, pkg.vk_hash, &inputs(n), Fr::from(n)))
            .collect();
        // entry 0's latest attempt rewrote leaf 2
        let rewrite = [(2, [99u64, 0, 1].map(Fr::from).to_vec())];
        let v2 = put_book(&store, TREE_NS, Some(&v1), &rewrite, 2, Some(ids[0]));

        let queue = QueueLayout::new(Fr::from(QUEUE));
        let chain = |head: u64, slot: Fr| {
            let mem = Arc::new(MemoryChain::new(60));
            for (n, id) in ids.iter().enumerate() {
                let mut fields = inputs(n as u64);
                fields.push(Fr::from(n as u64));
                mem.push_log(ns, 40, crate::chain::layout::request_log_tag(*id), &fields);
            }
            mem.write_queue(ns, queue, &ids, head, 41);
            mem.set_storage(ns, fr_from_hex(BOOK).unwrap(), slot);
            mem.set_storage(ns, Fr::from(STALE_SLOT), Fr::from(1u64));
            mem.set_storage(ns, Fr::from(STALE_SLOT + 1), Fr::from(50u64));
            mem
        };
        let state_keys = StateKeys {
            reads: vec![BOOK.into()],
            writes: vec![BOOK.into()],
        };
        // the scheduler's request for entry n on the version under `on`,
        // with the paths the nodes' trees give
        let request = |n: u64, on: Fr| {
            let state = [KeyState {
                key: BOOK.into(),
                commitment: on,
                record: None,
            }];
            let held = pkg.tip_state(KeyRef::Read(0)).unwrap();
            let trees = StoreTrees { store: &store, ns };
            let public = app(5 + n, 0, 2, 2);
            let node_values = sidecar_test_fixtures::block_on(
                held.node_values(&pkg, BOOK, &state[0], &public, &trees),
            )
            .unwrap();
            let view = SynthesisView {
                namespace: ns,
                entry: QueueEntry {
                    index: n,
                    chain_request_id: ids[n as usize],
                },
                state_keys: &state_keys,
                pinned: &PinnedValues::default(),
                state: &state,
                node_values: &node_values,
            };
            let log = PlainFound::new(inputs(n), Fr::from(n));
            synthesise(&view, &pkg, &log).unwrap().request
        };
        let verify = |mem: &Arc<MemoryChain>, req: &Request| {
            let verifier = ChainVerifier::new(NODE, mem.clone(), [ns]).unwrap();
            let layout = TipLayout {
                queue,
                ..layout(ns, BTreeMap::from([(pkg.name.clone(), state_keys.clone())]))
            };
            let round = ChainRound {
                manifest: pkg.tip.manifest(),
                intake: pkg.tip.intake(),
                shape: &pkg.shape,
                vk_hash: pkg.vk_hash,
                manifest_hash: Fr::from(0u64),
                stale_blocks: pkg.tip.stale_blocks(),
                rows: &store,
            };
            verifier
                .verify_in(&layout, &req.project(NODE), &round)
                .map(|_| ())
        };
        let refused = |mem: &Arc<MemoryChain>, req: &Request, needle: &str| {
            let err = verify(mem, req).unwrap_err();
            assert_eq!(err.class, ErrorClass::BadRequest, "{err}");
            assert!(err.message.contains(needle), "`{needle}` not in: {err}");
        };
        let off_tree = format!("key `{BOOK}`: the request's `old_hashes` is not this node's");

        let mem = chain(0, v1.commitment);
        let head = request(0, v1.commitment);
        assert!(head.public.contains_key("siblings") && head.records.is_empty());
        verify(&mem, &head).unwrap();
        // pipelined on entry 0's latest attempt, with that version's paths
        verify(&mem, &request(1, v2.commitment)).unwrap();
        // the slot's own version, while that attempt is pending
        refused(&mem, &request(1, v1.commitment), &off_tree);
        // a slot at a commitment this node holds no version of
        let lost = chain(0, Fr::from(0x99u64));
        refused(&lost, &head, "holds no version of: a fault");
        // once entry 0 is skipped, only the slot counts
        mem.set_storage(ns, queue.done(0), Fr::from(2u64));
        verify(&mem, &request(1, v1.commitment)).unwrap();
        refused(&mem, &request(1, v2.commitment), &off_tree);
        // once entry 0 is applied, entry 1 is the head on the slot's new version
        let applied = chain(1, v2.commitment);
        verify(&applied, &request(1, v2.commitment)).unwrap();
    }

    #[test]
    fn a_wrong_pinned_value_is_refused() {
        let w = World::new("onchain", true, 2, 0, 0xc0);
        let req = w.request(0, state(0xc0), 1);
        w.verify(&Rows::default(), &req).unwrap();
        // the machine request id covers the pinned value
        assert_eq!(
            req.request_id.fr(),
            machine_request_id(w.ids[0], &[Fr::from(0xc0u64)], &[Fr::from(1u64)])
        );
        w.refused(
            &Rows::default(),
            &w.request(0, state(0xc0), 2),
            "the pinned read `get_price()`",
        );
        // the right value under the id of another value, or under the id
        // without the pinned part, is refused on the id
        let mut other = req.clone();
        other.request_id = w.request(0, state(0xc0), 2).request_id;
        w.refused(&Rows::default(), &other, "field `request_id`");
        let mut unpinned = req.clone();
        unpinned.request_id =
            sidecar_core::RequestId(machine_request_id(w.ids[0], &[Fr::from(0xc0u64)], &[]));
        w.refused(&Rows::default(), &unpinned, "field `request_id`");
        // the price moved after the scheduler read it
        w.mem.set_call(
            Fr::from(ORACLE),
            "get_price()",
            &[],
            Ok(vec![Fr::from(3u64)]),
        );
        w.refused(
            &Rows::default(),
            &w.request(0, state(0xc0), 1),
            "field `public.direction`",
        );
        // a pinned read that reverts
        w.mem
            .set_call(Fr::from(ORACLE), "get_price()", &[], Err("paused".into()));
        w.refused(&Rows::default(), &w.request(0, state(0xc0), 1), "paused");
    }

    /// A tolerance read of the oracle into `direction`, an absolute band of 5.
    const TOLERANCE_READ: &str = r#"[{"contract": "0x1234", "function": "get_price", "args": [],
        "param": "direction", "freshness": "tolerance", "band": {"absolute": "5"}}]"#;

    /// This node's value `values` (and under `epoch` the value of the epoch
    /// before, `previous`) of the oracle read into `direction`.
    fn own(values: &[u64], previous: Option<u64>) -> PinnedValues {
        PinnedValues(vec![crate::chain::PinnedValue {
            param: "direction".into(),
            contract: Fr::from(ORACLE),
            function: "get_price()".into(),
            args: vec![],
            values: values.iter().map(|v| Fr::from(*v)).collect(),
            previous: previous.map(Fr::from),
            block: 60,
            source: crate::chain::PinnedSource::Simulated,
        }])
    }

    /// The values `admit_pinned` checks a request carrying `used` (by
    /// public name) against, under the read `reads`.
    fn admitted(
        reads: &str,
        pinned: &[&str],
        own: &PinnedValues,
        used: &[(&str, u64)],
    ) -> Vec<u64> {
        let pkg = package_with_reads(AMM_SWAP_TIP, "onchain", reads, pinned);
        let w = World::new("onchain", true, 1, 0, 0xc0);
        let mut req = w.request(0, state(0xc0), 1).project(NODE);
        req.public
            .retain(|name, _| !pinned.contains(&name.as_str()));
        for (name, v) in used {
            req.public.insert(
                name.to_string(),
                sidecar_core::request::PublicValue::One(FieldHex(Fr::from(*v))),
            );
        }
        let got = admit_pinned(&pkg, own, &req);
        let as_u64 = |v: &Fr| {
            (0..2000u64)
                .find(|n| Fr::from(*n) == *v)
                .expect("a small value")
        };
        got.0[0].values.iter().map(as_u64).collect()
    }

    #[test]
    fn an_exact_read_admits_only_this_node_s_value() {
        let read = r#"[{"contract": "0x1234", "function": "get_price", "args": [], "param": "direction"}]"#;
        let own = own(&[5], None);
        assert_eq!(
            admitted(read, &["direction"], &own, &[("direction", 5)]),
            [5]
        );
        assert_eq!(
            admitted(read, &["direction"], &own, &[("direction", 6)]),
            [5]
        );
        // a request without the read's public name is checked at this node's
        assert_eq!(admitted(read, &["direction"], &own, &[]), [5]);
    }

    #[test]
    fn an_epoch_read_admits_this_node_s_epoch_and_the_one_before() {
        let read = r#"[{"contract": "0x1234", "function": "get_price_epoch", "args": [],
            "param": "direction", "freshness": "epoch", "epoch_param": "min_out"}]"#;
        let pinned = ["direction", "min_out"];
        // this node reads value 7 at epoch 3, the epoch before held 6
        let own = own(&[7, 3], Some(6));
        let at = |value, epoch| {
            admitted(
                read,
                &pinned,
                &own,
                &[("direction", value), ("min_out", epoch)],
            )
        };
        assert_eq!(at(7, 3), [7, 3], "this node's epoch");
        assert_eq!(at(6, 2), [6, 2], "the previous epoch at its value");
        assert_eq!(at(5, 1), [7, 3], "two epochs back");
        assert_eq!(at(5, 2), [7, 3], "the previous epoch at another value");
        assert_eq!(at(7, 2), [7, 3], "this value under the previous epoch");
        assert_eq!(at(6, 4), [7, 3], "a later epoch");
        // a request missing the epoch is checked at this node's values
        assert_eq!(admitted(read, &pinned, &own, &[("direction", 6)]), [7, 3]);
    }

    #[test]
    fn a_tolerance_read_admits_a_value_within_the_band() {
        let own100 = own(&[100], None);
        let at = |used| {
            admitted(
                TOLERANCE_READ,
                &["direction"],
                &own100,
                &[("direction", used)],
            )
        };
        assert_eq!(at(105), [105], "in the band, above");
        assert_eq!(at(95), [95], "in the band, below");
        assert_eq!(at(106), [100], "out of the band");
        assert_eq!(at(94), [100], "out of the band, below");
        let relative = r#"[{"contract": "0x1234", "function": "get_price", "args": [],
            "param": "direction", "freshness": "tolerance", "band": {"relative_bps": 100}}]"#;
        let own1000 = own(&[1000], None);
        let at = |used| admitted(relative, &["direction"], &own1000, &[("direction", used)]);
        assert_eq!(at(1010), [1010], "1% of 1000");
        assert_eq!(at(1011), [1000], "past 1%");
    }

    // A tolerance read lets an entry's first attempt run at any value within
    // the band of this node's; once this node holds a row of another attempt
    // of the entry, a new attempt runs only at this node's own value, and a
    // replay of the same attempt is still checked as made.
    #[test]
    fn a_second_attempt_of_an_entry_takes_this_node_s_own_pinned_value() {
        let pkg = package_with_reads(AMM_SWAP_TIP, "onchain", TOLERANCE_READ, &["direction"]);
        let w = World::with(pkg, true, 2, 0, 0xc0);
        // this node reads the oracle at 1: 3 is in the band
        let at3 = w.request(0, state(0xc0), 3);
        w.verify(&Rows::default(), &at3).unwrap();
        let earlier = Rows::default().with_result(w.ids[0], 0x99, RequestStatus::Committed);
        w.refused(&earlier, &at3, "this node already ran attempt");
        w.refused(&earlier, &at3, "the pinned read `get_price()`");
        // a rolled-back attempt counts as well
        let rolled = Rows::default().with_result(w.ids[0], 0x99, RequestStatus::RolledBack);
        w.refused(&rolled, &at3, "this node already ran attempt");
        // this node's own value is accepted
        w.verify(&earlier, &w.request(0, state(0xc0), 1)).unwrap();
        // a replay of the earlier attempt itself is checked as made
        let mut replayed = Rows::default().with_result(w.ids[0], 0x99, RequestStatus::Committed);
        replayed.results.get_mut(&w.ids[0]).unwrap().request_id = at3.request_id;
        w.verify(&replayed, &at3).unwrap();
        // another entry's attempt does not count against this one
        let other = Rows::default().with_result(w.ids[1], 0x99, RequestStatus::Committed);
        w.verify(&other, &at3).unwrap();
    }

    #[test]
    fn the_stored_stale_period_must_be_the_manifest_s() {
        let w = World::new("onchain", false, 1, 0, 0xc0);
        let req = w.request(0, state(0xc0), 1);
        w.mem
            .set_storage(ns(), Fr::from(STALE_SLOT + 1), Fr::from(40u64));
        w.refused(
            &Rows::default(),
            &req,
            "TipConfig.stale_blocks is 40 blocks",
        );
        w.mem
            .set_storage(ns(), Fr::from(STALE_SLOT), Fr::from(0u64));
        w.refused(&Rows::default(), &req, "is disabled (null)");
        let stored = StoredStaleBlocks {
            enabled: Fr::from(0u64),
            blocks: Fr::from(0u64),
        };
        assert!(stored.matches(None) && !stored.matches(Some(50)));
        let stored = StoredStaleBlocks {
            enabled: Fr::from(1u64),
            blocks: Fr::from(50u64),
        };
        assert!(stored.matches(Some(50)) && !stored.matches(None) && !stored.matches(Some(49)));
    }

    #[test]
    fn receipt_intake_inputs_are_this_node_s_stored_receipt() {
        let w = World::new("receipt", false, 1, 0, 0xc0);
        let req = w.request(0, state(0xc0), 1);
        w.refused(&Rows::default(), &req, "holds no receipt");
        let app = inputs(0, false);
        let receipt = ReceiptRow {
            request_id: w.ids[0],
            circuit: "amm_swap_tip".into(),
            vk_hash: w.pkg.vk_hash,
            inputs: app.clone(),
            inputs_hash: inputs_hash(&app),
            user_nonce: Some(Fr::from(0u64)),
            shares: vec![],
            expiry_block: 400,
            stale_blocks: Some(50),
            signature: Signature::default(),
        };
        let mut rows = Rows::default();
        rows.receipts.insert(w.ids[0], receipt.clone());
        w.verify(&rows, &req).unwrap();
        // a receipt of other inputs under the same chain request id
        let mut other = receipt;
        other.inputs = vec![
            Fr::from(1u64),
            Fr::from(1u64),
            Fr::from(900u64),
            Fr::from(0x9a00u64),
        ];
        rows.receipts.insert(w.ids[0], other);
        w.refused(&rows, &req, "field `chain_request_id`");
    }

    /// Secret-shared receipt intake: the chain verifier rebuilds the scheduler's
    /// request from this node's own row (its envelope of every shared input,
    /// the stored share hashes, C) and refuses a swapped envelope, share hash
    /// or C, a missing shared input, and a request it holds no row for.
    #[test]
    fn a_shared_request_is_this_node_s_stored_receipt() {
        use crate::intake::tests::SharedFixture;
        let f = SharedFixture::new();
        let queue = QueueLayout::new(Fr::from(QUEUE));
        let mem = Arc::new(MemoryChain::new(60));
        mem.write_queue(f.ns, queue, &[f.chain], 0, 41);
        mem.set_storage(f.ns, Fr::from(STALE_SLOT), Fr::from(1u64));
        mem.set_storage(f.ns, Fr::from(STALE_SLOT + 1), Fr::from(50u64));
        let state_keys = state_keys();
        let verifier = ChainVerifier::new(NODE, mem, [f.ns]).unwrap();
        let shared_layout = TipLayout {
            queue,
            ..layout(
                f.ns,
                BTreeMap::from([(f.pkg.name.clone(), state_keys.clone())]),
            )
        };
        // the scheduler's request, on the node-held pool's empty slot
        let state = [KeyState {
            key: POOL.into(),
            commitment: Fr::from(0u64),
            record: None,
        }];
        let view = SynthesisView {
            namespace: f.ns,
            entry: QueueEntry {
                index: 0,
                chain_request_id: f.chain,
            },
            state_keys: &state_keys,
            pinned: &PinnedValues::default(),
            state: &state,
            node_values: &PublicMap::new(),
        };
        let inputs = SharedReceiptFound::new(vec![Fr::from(7u64)], f.c, f.shared.clone());
        let req = synthesise(&view, &f.pkg, &inputs).unwrap().request;
        let rows = Rows::with_receipts([(f.chain, f.row(NODE))]);
        let verify = |req: &Request, rows: &Rows| {
            let round = ChainRound {
                manifest: f.pkg.tip.manifest(),
                intake: f.pkg.tip.intake(),
                shape: &f.pkg.shape,
                vk_hash: f.pkg.vk_hash,
                manifest_hash: Fr::from(0u64),
                stale_blocks: f.pkg.tip.stale_blocks(),
                rows,
            };
            verifier
                .verify_in(&shared_layout, &req.project(NODE), &round)
                .map(|_| ())
        };
        verify(&req, &rows).unwrap();
        // another node's envelope differs, and this node never sees it
        let mut theirs = req.clone();
        theirs.shared_inputs[0].shares[(NODE + 1) % NODES] = f.shared[1].shares[0];
        verify(&theirs, &rows).unwrap();

        let refused = |req: &Request, rows: &Rows, needle: &str| {
            let err = verify(req, rows).unwrap_err();
            assert_eq!(err.class, ErrorClass::BadRequest, "{err}");
            assert!(err.message.contains(needle), "`{needle}` not in: {err}");
        };
        type Edit = fn(&mut Request);
        let cases: Vec<(Edit, &str)> = vec![
            // this node's envelope of `amount` swapped for its `$partial_note` one
            (
                |r| r.shared_inputs[0].shares[NODE] = r.shared_inputs[1].shares[NODE],
                "field `shared_inputs[0]` (`amount`)",
            ),
            (
                |r| r.shared_inputs[2].share_hashes[0] = FieldHex(Fr::from(1u64)),
                "field `shared_inputs[2]` (`$outcome_key`)",
            ),
            (
                |r| {
                    r.public.insert(
                        "inputs_hash".into(),
                        PublicValue::One(FieldHex(Fr::from(1u64))),
                    );
                },
                "field `public.inputs_hash`",
            ),
            (
                |r| {
                    r.shared_inputs.pop();
                },
                "field `shared_inputs`: 4 shared input(s)",
            ),
            (|r| r.shared_inputs.swap(0, 1), "field `shared_inputs[0]`"),
        ];
        for (edit, needle) in cases {
            let mut other = req.clone();
            edit(&mut other);
            refused(&other, &rows, needle);
        }
        refused(&req, &Rows::default(), "holds no receipt");
        let wrong = Rows::with_receipts([(f.chain, f.row((NODE + 1) % NODES))]);
        refused(&req, &wrong, "does not hash to share_hashes[1]");
    }

    /// A namespace this node does not list, one with no contract manifest
    /// in its rows, and a package the manifest names no keys for are
    /// refused.
    #[test]
    fn unlisted_unregistered_namespaces_and_unnamed_packages_are_refused() {
        let w = World::new("onchain", false, 1, 0, 0xc0);
        let req = w.request(0, state(0xc0), 1).project(NODE);
        let rows = Rows::default();
        let none = ChainVerifier::new(NODE, w.mem.clone(), []).unwrap();
        let err = none.verify(&req, &w.round(&rows)).unwrap_err();
        assert!(err.message.contains("is not one of this node's"), "{err}");
        let err = w.verifier().verify(&req, &w.round(&rows)).unwrap_err();
        assert!(err.message.contains("holds no contract manifest"), "{err}");
        let other = layout(
            ns(),
            BTreeMap::from([("amm_init_tip".to_string(), state_keys())]),
        );
        let err = w
            .verify_under(&w.verifier(), &other, &rows, &w.request(0, state(0xc0), 1))
            .unwrap_err();
        assert!(err.message.contains("names no request keys"), "{err}");
    }

    /// The instance's current class is not the manifest's, or no instance
    /// is published: refused, naming both.
    #[test]
    fn another_contract_class_is_refused() {
        let w = World::new("onchain", false, 1, 0, 0xc0);
        let req = w.request(0, state(0xc0), 1);
        w.verify(&Rows::default(), &req).unwrap();
        w.mem.set_class(ns(), Some(Fr::from(0xbeefu64)));
        w.refused(&Rows::default(), &req, "current contract class is 0x");
        w.mem.set_class(ns(), None);
        w.refused(&Rows::default(), &req, "no contract instance is published");
    }

    /// A request with no chain request id, a configured request key that is
    /// not a storage slot, and a queued request carrying a requester or a
    /// signature are refused.
    #[test]
    fn malformed_queued_requests_are_refused() {
        let w = World::new("onchain", false, 1, 0, 0xc0);
        let rows = Rows::default();
        let req = w.request(0, state(0xc0), 1);
        let mut unchained = req.clone();
        unchained.chain_request_id = None;
        w.refused(&rows, &unchained, "carries no chain request id");

        let mut named = namespace();
        let words = StateKeys {
            reads: vec!["pool".into()],
            writes: vec!["pool".into()],
        };
        named.circuits = BTreeMap::from([("amm_swap_tip".to_string(), words)]);
        let err = w
            .verify_under(&w.verifier(), &named, &rows, &req)
            .unwrap_err();
        assert!(err.message.contains("request key `pool`"), "{err}");

        let point = sidecar_core::request::GrumpkinPoint {
            x: FieldHex(Fr::from(1u64)),
            y: FieldHex(Fr::from(2u64)),
        };
        let mut signed = req.clone();
        signed.requester = Some(point);
        w.refused(&rows, &signed, "fields `requester` and `signature`");
        let mut signed = req;
        signed.signature = Some(Signature::default());
        w.refused(&rows, &signed, "fields `requester` and `signature`");
    }

    /// An Aztec node that fails every call, or answers an older chain.
    struct Failing;

    impl Transport for Failing {
        async fn call(&self, method: &str, _: Value) -> Result<Value, RpcError> {
            Err(RpcError::Transport(format!("{method}: connection refused")))
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_failing_or_stale_aztec_node_only_refuses() {
        // from inside a runtime: the reads run on a scoped thread
        let w = World::new("onchain", false, 2, 0, 0xc0);
        let req = w.request(0, state(0xc0), 1);
        w.verify(&Rows::default(), &req).unwrap();
        let failing = ChainVerifier::new(NODE, Failing, [ns()]).unwrap();
        let err = w.verify_with(&failing, &Rows::default(), &req).unwrap_err();
        assert_eq!(err.class, ErrorClass::BadRequest);
        assert!(err.message.contains("connection refused"), "{err}");
        // a node behind the chain: the entry is not queued in its view yet
        let behind = World::new("onchain", false, 0, 0, 0xc0);
        let stale = ChainVerifier::new(NODE, behind.mem.clone(), [ns()]).unwrap();
        let err = w.verify_with(&stale, &Rows::default(), &req).unwrap_err();
        assert!(err.message.contains("is not the head"), "{err}");
        // a node that lies about the slot
        let lying = World::new("onchain", false, 2, 0, 0xee);
        let liar = ChainVerifier::new(NODE, lying.mem.clone(), [ns()]).unwrap();
        let err = w.verify_with(&liar, &Rows::default(), &req).unwrap_err();
        assert!(err.message.contains("stale state record"), "{err}");
        // a node whose tip went backwards reads again at the new tip, where
        // the request is still its view
        w.mem.script_tips(&[60, 59]);
        let verifier = w.verifier();
        verifier.reader().snapshot().await.unwrap();
        w.verify_with(&verifier, &Rows::default(), &req).unwrap();
        // one whose chain is replaced at every read refuses once the
        // snapshots run out
        // (each prune is followed by the follower's second read of the tips)
        w.mem.script_tips(&[60, 59, 59, 58, 58, 57, 57]);
        let verifier = w.verifier();
        verifier.reader().snapshot().await.unwrap();
        let err = w
            .verify_with(&verifier, &Rows::default(), &req)
            .unwrap_err();
        assert!(err.message.contains("went back"), "{err}");
    }

    /// The pool slot's block, 60, replaced by one in which the slot holds
    /// 0xd0, when the verifier reads the stored stale period (after the
    /// queue, the slots and the request log): its reads straddle the
    /// replacement.
    struct ReplacedMidRead {
        mem: Arc<MemoryChain>,
        replaced: std::sync::atomic::AtomicBool,
    }

    impl Transport for ReplacedMidRead {
        async fn call(&self, method: &str, params: Value) -> Result<Value, RpcError> {
            let stale_slot = params[2]
                .as_str()
                .is_some_and(|s| fr_from_hex(s) == Ok(Fr::from(STALE_SLOT)));
            if method == "node_getPublicStorageAt"
                && stale_slot
                && !self
                    .replaced
                    .swap(true, std::sync::atomic::Ordering::SeqCst)
            {
                self.mem.node().replace_from(60);
                self.mem
                    .set_storage(ns(), Fr::from(0x12u64), Fr::from(0xd0u64));
            }
            self.mem.call(method, params).await
        }
    }

    #[test]
    fn a_request_built_on_a_replaced_block_is_refused() {
        // The scheduler built the head's request at block 60, where the
        // pool slot held 0xc0; this node accepted it there.
        let w = World::new("onchain", false, 2, 0, 0xc0);
        let verifier = w.verifier();
        let built = w.request(0, state(0xc0), 1);
        w.verify_with(&verifier, &Rows::default(), &built).unwrap();
        // Block 60 is replaced by one in which another result moved the
        // slot to 0xd0. The node's next reads see the follower's prune,
        // read again on the replacement and refuse the request on its
        // content, not on the prune; the request rebuilt on the replacement
        // is accepted by the same verifier.
        w.mem.node().replace_from(60);
        w.mem
            .set_storage(ns(), Fr::from(0x12u64), Fr::from(0xd0u64));
        let err = w
            .verify_with(&verifier, &Rows::default(), &built)
            .unwrap_err();
        assert_eq!(err.class, ErrorClass::BadRequest, "{err}");
        assert!(err.message.contains("stale state record"), "{err}");
        let rebuilt = w.request(0, state(0xd0), 1);
        w.verify_with(&verifier, &Rows::default(), &rebuilt)
            .unwrap();

        // The block is replaced while the node reads: the slot was read on
        // the replaced block, where the request held. The confirming poll
        // after the reads sees the replacement, the reads restart on the
        // chain as it stands, and the request is refused.
        let w = World::new("onchain", false, 2, 0, 0xc0);
        let mid = ReplacedMidRead {
            mem: w.mem.clone(),
            replaced: Default::default(),
        };
        let verifier = ChainVerifier::new(NODE, mid, [ns()]).unwrap();
        let err = w
            .verify_with(&verifier, &Rows::default(), &built)
            .unwrap_err();
        assert!(err.message.contains("stale state record"), "{err}");
        w.verify_with(&verifier, &Rows::default(), &rebuilt)
            .unwrap();
    }

    // Three nodes read through three Aztec nodes, which see a replacement
    // at different times: until their views agree, the node whose view
    // differs refuses the round (a delay only), and once they agree every
    // node checks the request against the replacement chain.
    #[test]
    fn three_nodes_that_see_a_replacement_at_different_times_only_delay() {
        let w = World::new("onchain", false, 2, 0, 0xc0);
        let views: Vec<Arc<MemoryChain>> = (0..NODES).map(|_| Arc::new(w.mem.copy())).collect();
        let verifiers: Vec<_> = views
            .iter()
            .map(|v| ChainVerifier::new(NODE, v.clone(), [ns()]).unwrap())
            .collect();
        let built = w.request(0, state(0xc0), 1);
        let rebuilt = w.request(0, state(0xd0), 1);
        let verdicts = |req: &Request| -> Vec<bool> {
            verifiers
                .iter()
                .map(|v| w.verify_with(v, &Rows::default(), req).is_ok())
                .collect()
        };
        assert_eq!(verdicts(&built), [true, true, true]);
        // block 60 is replaced by one in which another result moved the slot
        // to 0xd0: node 0's Aztec node sees it first
        let replace = |view: &MemoryChain| {
            view.node().replace_from(60);
            view.set_storage(ns(), Fr::from(0x12u64), Fr::from(0xd0u64));
        };
        replace(views[0].as_ref());
        assert_eq!(verdicts(&built), [false, true, true]);
        assert_eq!(verdicts(&rebuilt), [true, false, false]);
        replace(views[1].as_ref());
        assert_eq!(verdicts(&rebuilt), [true, true, false]);
        replace(views[2].as_ref());
        assert_eq!(verdicts(&built), [false, false, false]);
        assert_eq!(verdicts(&rebuilt), [true, true, true]);
    }

    #[test]
    fn a_silent_aztec_node_times_out() {
        struct Silent;
        impl Transport for Silent {
            async fn call(&self, _: &str, _: Value) -> Result<Value, RpcError> {
                tokio::time::sleep(Duration::from_secs(60)).await;
                Err(RpcError::Transport("late".into()))
            }
        }
        let w = World::new("onchain", false, 1, 0, 0xc0);
        let req = w.request(0, state(0xc0), 1);
        let silent = ChainVerifier::new(NODE, Silent, [ns()])
            .unwrap()
            .with_timeout(Duration::from_millis(200));
        let err = w.verify_with(&silent, &Rows::default(), &req).unwrap_err();
        assert!(err.message.contains("did not answer"), "{err}");
    }

    // ---- the init round ---------------------------------------------------

    /// The machine's counter init (machine/circuits/tip_counter_init): one
    /// input, `start`, and the key it creates.
    const INIT_ABI: &str = r#"{
      "parameters": [
        {"name": "namespace", "type": {"kind": "field"}, "visibility": "public"},
        {"name": "out_slots", "type": {"kind": "array", "length": 1, "type": {"kind": "field"}}, "visibility": "public"},
        {"name": "start", "type": {"kind": "field"}, "visibility": "public"},
        {"name": "r_new", "type": {"kind": "field"}, "visibility": "private"}
      ],
      "return_type": {"abi_type": {"kind": "struct", "path": "InitOutputs", "fields": [
        {"name": "new_c", "type": {"kind": "field"}}
      ]}, "visibility": "public"},
      "error_types": {}
    }"#;

    const INIT_MANIFEST: &str = r#"{
      "manifest": 1, "circuit": "tip_counter_init", "namespace_param": "namespace",
      "state_keys": {"reads": 0, "writes": 1}, "intake": "onchain", "outcome": "none",
      "witness": [
        {"param": "namespace", "from": {"PUBLIC": "$namespace"}},
        {"param": "out_slots", "from": {"PUBLIC": ["$state_keys.writes[0]"]}},
        {"param": "start", "from": {"PUBLIC": "start"}},
        {"param": "r_new", "from": {"SAMPLE": 1}}
      ],
      "outputs": [{"TACEO_store": "out0", "STORE": "$state_keys.writes[0]", "len": 2, "note_hash": "new_c"}],
      "state": {"$state_keys.writes[0]": "chain"}
    }"#;

    const CONFIGURED_SLOT: u64 = 0x20;
    const START_SLOT: u64 = 0x22;
    const INIT_VK: u64 = 0x1417;

    fn init_package() -> TipPackage {
        let row = PackageRow {
            name: "tip_counter_init".into(),
            manifest_hash: Fr::from(0u64),
            circuit_json: serde_json::to_vec(&serde_json::json!({
                "abi": parse_json::<Value>(INIT_ABI).unwrap()
            }))
            .unwrap(),
            manifest: parse_json(INIT_MANIFEST).unwrap(),
            vk: vec![],
            vk_hash: Fr::from(INIT_VK),
            disabled: false,
            seq: 0,
        };
        TipPackage::from_row(&row, Some(50)).unwrap().unwrap()
    }

    fn init_state_keys() -> StateKeys {
        StateKeys {
            reads: vec![],
            writes: vec![POOL.into()],
        }
    }

    fn init_layout() -> InitLayout {
        InitLayout {
            circuit: "tip_counter_init".into(),
            configured_slot: Fr::from(CONFIGURED_SLOT),
            input_slots: vec![Fr::from(START_SLOT)],
        }
    }

    fn init_namespace() -> TipLayout {
        let mut ns = namespace();
        ns.circuits
            .insert("tip_counter_init".to_string(), init_state_keys());
        ns.init = Some(init_layout());
        ns
    }

    /// A deployed contract with nothing queued and the pool slot empty;
    /// [`configure`] lands `configure`.
    fn deployed() -> Arc<MemoryChain> {
        let mem = Arc::new(MemoryChain::new(60));
        mem.write_queue(ns(), QueueLayout::new(Fr::from(QUEUE)), &[], 0, 41);
        mem.set_storage(ns(), Fr::from(START_SLOT), Fr::from(5u64));
        mem
    }

    fn configure(mem: &MemoryChain) {
        mem.set_storage(ns(), Fr::from(CONFIGURED_SLOT), Fr::from(1u64));
    }

    /// The scheduler's init reads and its due init request, if any.
    async fn scheduler_init(mem: &Arc<MemoryChain>) -> (InitRead, Option<Request>) {
        let reader = ChainReader::new(mem.clone());
        let snap = reader.snapshot().await.unwrap();
        let read = reader
            .init(
                snap,
                &namespace().target(),
                &init_layout(),
                &init_state_keys(),
            )
            .await
            .unwrap();
        let req = read.due().then(|| {
            crate::init_request(ns(), &read, &init_package(), &init_state_keys())
                .unwrap()
                .request
        });
        (read, req)
    }

    /// Node `node`'s chain verifier, on its own view `mem`, given `req`.
    fn verify_init(
        node: usize,
        mem: &Arc<MemoryChain>,
        req: &Request,
    ) -> Result<QueueRead, Refusal> {
        let pkg = init_package();
        let verifier = ChainVerifier::new(node, mem.clone(), [ns()]).unwrap();
        let round = ChainRound {
            manifest: pkg.tip.manifest(),
            intake: pkg.tip.intake(),
            shape: &pkg.shape,
            vk_hash: pkg.vk_hash,
            manifest_hash: Fr::from(0u64),
            stale_blocks: pkg.tip.stale_blocks(),
            rows: &Rows::default(),
        };
        verifier.verify_in(&init_namespace(), &req.project(node), &round)
    }

    fn init_refused(node: usize, mem: &Arc<MemoryChain>, req: &Request, needle: &str) {
        let err = verify_init(node, mem, req).unwrap_err();
        assert_eq!(err.class, ErrorClass::BadRequest, "{err}");
        assert!(err.message.contains(needle), "`{needle}` not in: {err}");
    }

    /// The scheduler's trigger: no init request before `configure`, one
    /// once the contract is configured while the slot is empty (the same
    /// request at every later read, so a resend is a replay), accepted by
    /// the three chain verifiers, and none once the slot is written.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_init_round_is_due_once_configured_and_while_its_slot_is_empty() {
        let mem = deployed();
        let (read, req) = scheduler_init(&mem).await;
        assert!(!read.is_configured() && !read.due());
        assert_eq!(req, None, "an unconfigured contract gets no init request");

        configure(&mem);
        let (read, req) = scheduler_init(&mem).await;
        let req = req.expect("a configured contract with an empty slot gets the init request");
        let init_id = chain_request_id(ns(), Fr::from(INIT_VK), &[Fr::from(5u64)], Fr::from(0u64));
        assert_eq!(read.chain_request_id(ns(), Fr::from(INIT_VK)), init_id);
        assert_eq!(req.chain_request_id, Some(FieldHex(init_id)));
        // process_init's id: one old commitment of 0 per created key
        assert_eq!(
            req.request_id.fr(),
            machine_request_id(init_id, &[Fr::from(0u64)], &[])
        );
        assert_eq!(
            req.public["start"],
            sidecar_core::request::PublicValue::One(FieldHex(Fr::from(5u64)))
        );
        assert!(req.records.is_empty() && req.requester.is_none() && req.signature.is_none());
        assert_eq!(req.state_keys, init_state_keys());
        let (_, again) = scheduler_init(&mem).await;
        assert_eq!(
            again,
            Some(req.clone()),
            "one init request, rebuilt identically"
        );
        for node in 0..NODES {
            let view = verify_init(node, &mem, &req).unwrap();
            assert_eq!((view.block, view.head, view.index), (60, 0, 0));
            assert!(view.keys.is_empty(), "the init loads no slot");
        }

        mem.set_storage(ns(), fr_from_hex(POOL).unwrap(), Fr::from(0xc0u64));
        let (read, none) = scheduler_init(&mem).await;
        assert!(read.is_configured() && !read.due());
        assert_eq!(none, None, "a written slot gets no init request");
        init_refused(NODE, &mem, &req, "holds 0x");
    }

    /// Each chain verifier checks the init on its own view: unconfigured,
    /// other inputs, or the machine request id without the empty slots'
    /// zeros are refused.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_chain_verifier_refuses_an_init_its_view_does_not_hold() {
        let configured = deployed();
        configure(&configured);
        let (_, req) = scheduler_init(&configured).await;
        let req = req.unwrap();

        // a node whose view says unconfigured
        let behind = deployed();
        init_refused(2, &behind, &req, "not configured");
        // a node whose Config holds another init input
        let other_start = deployed();
        configure(&other_start);
        other_start.set_storage(ns(), Fr::from(START_SLOT), Fr::from(6u64));
        init_refused(1, &other_start, &req, "field `chain_request_id`");

        // the init as a queued round would carry it: no zeros in its id
        let mut queued = req.clone();
        queued.request_id = sidecar_core::RequestId(machine_request_id(
            req.chain_request_id.unwrap().fr(),
            &[],
            &[],
        ));
        init_refused(NODE, &configured, &queued, "field `request_id`");
        // another input under the right ids
        let mut other = req.clone();
        other.public.insert(
            "start".into(),
            sidecar_core::request::PublicValue::One(FieldHex(Fr::from(6u64))),
        );
        init_refused(NODE, &configured, &other, "field `public.start`");
        // a namespace without an init entry checks the circuit as a queued
        // round, which the queue does not hold
        let pkg = init_package();
        let mut plain = namespace();
        plain
            .circuits
            .insert("tip_counter_init".into(), init_state_keys());
        let verifier = ChainVerifier::new(NODE, configured.clone(), [ns()]).unwrap();
        let round = ChainRound {
            manifest: pkg.tip.manifest(),
            intake: pkg.tip.intake(),
            shape: &pkg.shape,
            vk_hash: pkg.vk_hash,
            manifest_hash: Fr::from(0u64),
            stale_blocks: pkg.tip.stale_blocks(),
            rows: &Rows::default(),
        };
        let err = verifier
            .verify_in(&plain, &req.project(NODE), &round)
            .unwrap_err();
        assert!(err.message.contains("is not the head"), "{err}");
    }
}
