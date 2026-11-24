//! The chain reader (docs/ARCHITECTURE.md section 6, "Following the chain"): what
//! the orchestrator's scheduler and each node's chain verifier know about a
//! namespace's queue, read from one Aztec node at one proposed block.
//!
//! It holds no store, writes nothing and holds no key. Nothing it reads is
//! trusted for soundness (section 5, invariant 13): a lying or stale node can
//! make the scheduler build a request that a chain verifier or `apply`
//! refuses, so it can only delay the queue.
//!
//! The tip and the logs come through log discovery (section 6, "Log
//! discovery, a standalone module"). An Aztec 6 node cannot list a
//! contract's logs; it answers tag queries, at most [`MAX_LOGS_PER_TAG`]
//! logs per tag and [`MAX_TAGS_PER_CALL`] tags per call. Every tag the tip
//! reads is predictable from a request id its queue holds, so the reader
//! names the tags and finds their logs:
//!
//! - [`follow`]: the tip follower, a port of the block-hash comparison in
//!   aztec's `L2BlockStream` (stdlib `block/l2_block_stream`): the node's
//!   four tips, and `(number, hash)` of the followed proposed blocks back
//!   to the settled block (the node's finalized tip); a hash that differs
//!   on a poll is a [`Prune`] event. Each snapshot is a poll of it, and a
//!   replaced block the follower held is refused as its prune event
//!   ([`ReadError::Pruned`]).
//! - [`logs`]: tag queries (`node_getPublicLogsByTags` by contract address,
//!   `node_getPrivateLogsByTags` by siloed tag), paged with `afterLog` while
//!   a tag returns a full page, anchored by `referenceBlock` at the
//!   snapshot's block hash; a reference block the node no longer has is a
//!   replaced block ([`ReadError::ReferenceGone`]).
//! - [`rpc`]: the JSON-RPC call every read makes ([`Transport`]).
//!
//! A replaced block is detected one way for every consumer: the follower's
//! prune event, which voids every read made at a block above the last block
//! both chains share ([`Prune::voids`]). The scheduler drops what it built on
//! such reads when a snapshot reports the prune; the chain verifier, after
//! its reads, polls once more ([`ChainReader::confirm`]) and re-reads at a
//! new snapshot when its own block was replaced. Every read of a snapshot
//! taken from the follower names the block's hash as well as its number, so
//! the node itself refuses a read of a block replaced in the meantime
//! ([`ReadError::ReferenceGone`]), as the PXE pins its reads.
//!
//! RPC methods (Aztec node 6.0.0, `@aztec-labs/stdlib`
//! `interfaces/aztec-node.d.ts`):
//! - `node_getChainTips([])`, `node_getBlockData([n])`: the four tips and
//!   block hashes (the follower).
//! - `node_getPublicStorageAt([{"number": n, "hash": h}, contract, slot])` →
//!   a field: the queue, the commitment slots, a plain getter's backing
//!   slot. The block is named by number and hash (`AnchoredBlockParameter`),
//!   and the node answers "Block hash ... not found ... possibly a reorg has
//!   occurred" for a hash that is no longer its block's; a snapshot made by
//!   number ([`Snapshot::at`]) names the number alone.
//! - `node_getPublicLogsByTags([{"contractAddress", "tags": [tag],
//!   "referenceBlock": hash}])` → per tag, the logs that `contractAddress`
//!   emitted with that tag in field 0, up to the block of that hash, paged
//!   (the tag queries): the request log and the sealed-thirds log.
//! - `node_simulatePublicCalls([tx, true])` → the return values of the
//!   transaction's public calls, run on top of the latest proposed block: a
//!   pinned public read (`crate::chain::simulate`).

pub mod follow;
pub mod layout;
pub mod logs;
mod pinned;
#[cfg(test)]
mod reorg_tests;
pub mod rpc;
pub mod simulate;

pub use follow::{BlockId, Follower, Poll, Prune, Tips, block_hash, chain_tips};
pub use logs::{Log, MAX_LOGS_PER_TAG, MAX_TAGS_PER_CALL, Source, logs_by_tag, logs_by_tags};
pub use pinned::{PinnedSource, PinnedValue, PinnedValues};

use std::time::{Duration, Instant};

use serde_json::{Value, json};
use sidecar_core::Fr;
use sidecar_core::field::{fr_from_hex, fr_to_be_bytes, fr_to_hex};
use sidecar_core::manifest::KeyRef;
use sidecar_core::request::StateKeys;

use crate::TipManifest;
use crate::chain::layout::QueueLayout;
use crate::chain::rpc::{RpcError, Transport, field, malformed};
use crate::state::request_key;

// Operator knob: DESIGN.md, "Configuration reference" (reader lookahead). The
// reader reads `requests[head]` and up to 4 entries after it, never past
// `tail`; it bounds `pipeline_depth` and what a chain verifier accepts.
pub const DEFAULT_LOOKAHEAD: usize = 4;

// Operator knob: DESIGN.md, "Configuration reference" (`poll_interval_ms`,
// follow timeout). The reader follows the proposed tip, polled every 1 s, and
// `next_snapshot` gives up after 60 s without a new block.
pub const DEFAULT_POLL_INTERVAL: Duration = Duration::from_secs(1);
pub const DEFAULT_FOLLOW_TIMEOUT: Duration = Duration::from_secs(60);

// How far back the reader keeps block hashes (docs/DECISIONS.md section 8,
// "The chain reader keeps block hashes back to the settled block"): every
// block from the proposed tip back to the settled block, the node's
// finalized tip (the block whose proof's L1 transaction is final, below
// which neither an epoch prune nor an L1 reorg reaches), not a fixed depth,
// so a replacement anywhere above it voids exactly the reads made above the
// last block both chains share (`Prune::voids`). Only a replacement that
// reaches the settled block or below, which the node's own finality rules
// out, is reported `below_kept` and voids every read: the scheduler drops all
// it holds and reloads from the chain, a chain verifier reads again.
// Node-held version retention, receipt pruning and the retirement of
// encryption scalars take the same floor (`ChainReader::settled`). Memory is
// bounded by the blocks between the finalized tip and the tip and grows,
// with nothing dropped, while finality stalls: the reader logs each doubling
// of the hashes it holds and the orchestrator reports them on `GET
// /v1/status` (`ChainReader::held`). There is no knob; DESIGN.md,
// "Configuration reference", block hashes kept.
/// The reader's knobs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReaderConfig {
    /// Entries read after the head.
    pub lookahead: usize,
    pub poll_interval: Duration,
    pub follow_timeout: Duration,
}

impl Default for ReaderConfig {
    fn default() -> Self {
        ReaderConfig {
            lookahead: DEFAULT_LOOKAHEAD,
            poll_interval: DEFAULT_POLL_INTERVAL,
            follow_timeout: DEFAULT_FOLLOW_TIMEOUT,
        }
    }
}

/// Why a read failed. Every case is a liveness matter: the caller retries
/// with a new snapshot or refuses the request it was checking.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReadError {
    /// The call failed or the node refused it.
    Rpc {
        method: &'static str,
        error: RpcError,
    },
    /// The node answered something the reader cannot use.
    Malformed {
        method: &'static str,
        detail: String,
    },
    /// The node replaced proposed blocks the reader followed (the tip
    /// follower's prune event): the snapshot is refused, the next one follows
    /// the replacement chain.
    Pruned(Prune),
    /// A log query's reference block, the snapshot's, is no longer on the
    /// node's chain; the next snapshot reports the prune.
    ReferenceGone { block: u64 },
    /// The node has no block `block` below its own tip `tip`: its chain is
    /// changing under the read; take a new snapshot.
    Unsettled { block: u64, tip: u64 },
    /// No block after `after` within the follow timeout.
    NoNewBlock { after: u64, waited: Duration },
    /// A simulation ran on another block than the snapshot's (the tip moved
    /// between the snapshot and the call); take a new snapshot.
    SnapshotMoved { snapshot: u64, simulated: u64 },
    /// A simulated pinned read reverted.
    Reverted { function: String, reason: String },
    /// A request key that is not a storage slot.
    BadKey { key: String, detail: String },
}

impl std::fmt::Display for ReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReadError::Rpc { method, error } => write!(f, "{method}: {error}"),
            ReadError::Malformed { method, detail } => write!(f, "{method}: {detail}"),
            ReadError::Pruned(prune) => prune.fmt(f),
            ReadError::ReferenceGone { block } => write!(
                f,
                "the node no longer has block {block}, the snapshot's: it was replaced"
            ),
            ReadError::Unsettled { block, tip } => write!(
                f,
                "the node has no block {block} below its tip {tip}: its chain is changing"
            ),
            ReadError::NoNewBlock { after, waited } => {
                write!(f, "no block after {after} within {waited:?}")
            }
            ReadError::SnapshotMoved {
                snapshot,
                simulated,
            } => write!(
                f,
                "the simulation ran on block {simulated}, not on the snapshot's block {snapshot}"
            ),
            ReadError::Reverted { function, reason } => {
                write!(f, "the pinned read {function} reverted: {reason}")
            }
            ReadError::BadKey { key, detail } => write!(f, "request key `{key}`: {detail}"),
        }
    }
}

impl std::error::Error for ReadError {}

impl ReadError {
    /// A block the read used was replaced (the follower's prune event, or a
    /// log query's reference block gone): the reads restart at a new
    /// snapshot, which follows the replacement chain.
    pub fn replaced(&self) -> bool {
        matches!(self, ReadError::Pruned(_) | ReadError::ReferenceGone { .. })
    }
}

/// One proposed block: every read made with it reads that block's state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Snapshot {
    pub block: u64,
    /// The block's hash when the snapshot was taken ([`ChainReader::snapshot`]);
    /// `None` for a snapshot made by number ([`Snapshot::at`]), whose reads
    /// take the hash the reader or the node holds when they run.
    pub hash: Option<Fr>,
}

impl Snapshot {
    /// A snapshot of block `block` made by number, with no hash of its own.
    pub fn at(block: u64) -> Self {
        Snapshot { block, hash: None }
    }
}

/// `TipConfig.stale_blocks` as the contract stores it ([`ChainReader::stale_blocks`]).
/// At every queued round each node's chain verifier and the scheduler read it (`StaleBlocks {enabled: bool, blocks: u32}`,
/// two fields at the namespace's `stale_blocks_slot` and the slot after it)
/// and refuses (400) when it is not the manifest's `stale_blocks` (a number:
/// enabled and that many blocks; null: disabled). The slot is where the
/// app's `#[storage]` puts its Config (a `PublicImmutable` stores the packed
/// value from its own slot on, the hash after it) plus the offset of the
/// `tip` member in the Config's packing: `PssPublicTest` 1 (its Config is
/// the `TipConfig`), the AMM-tip example its config slot + 3 (three vk
/// hashes first). REGISTER never reads the contract, and the scheduler, the
/// relayer's `skip()` and the receipt pruning all assume the two are equal:
/// a contract that lets anyone skip earlier than the network expects drops
/// requests the network is still serving, and one that waits longer keeps a
/// head the network has given up on. A namespace whose contract and
/// manifest disagree runs no queued round (every one refused, logged) until
/// one is redeployed; a wrong slot reads zeros, which is "disabled" and is
/// refused unless the manifest says null.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StoredStaleBlocks {
    pub enabled: Fr,
    pub blocks: Fr,
}

impl StoredStaleBlocks {
    /// Why the stored value is not `manifest`, the `stale_blocks` of the
    /// manifest of `circuit`; `None` when they agree.
    pub fn differs(&self, circuit: &str, manifest: Option<u64>) -> Option<String> {
        (!self.matches(manifest)).then(|| {
            format!(
                "the contract's TipConfig.stale_blocks is {}, and the manifest of circuit \
                 `{circuit}` says {}",
                self.describe(),
                match manifest {
                    Some(n) => format!("{n} blocks"),
                    None => "null (disabled)".into(),
                }
            )
        })
    }

    /// Whether the stored value is the manifest's `stale_blocks`.
    pub fn matches(&self, manifest: Option<u64>) -> bool {
        match manifest {
            Some(n) => self.enabled == Fr::from(1u64) && self.blocks == Fr::from(n),
            None => self.enabled == Fr::from(0u64),
        }
    }

    /// The stored value as a refusal names it.
    pub fn describe(&self) -> String {
        if self.enabled == Fr::from(0u64) {
            "disabled (null)".into()
        } else if self.enabled == Fr::from(1u64) {
            format!("{} blocks", short(self.blocks))
        } else {
            format!("not a StaleBlocks (enabled {})", fr_to_hex(self.enabled))
        }
    }
}

pub(crate) fn short(v: Fr) -> String {
    let hex = fr_to_hex(v);
    let digits = hex.trim_start_matches("0x").trim_start_matches('0');
    if digits.len() <= 16 {
        u64::from_str_radix(if digits.is_empty() { "0" } else { digits }, 16)
            .map(|n| n.to_string())
            .unwrap_or(hex)
    } else {
        hex
    }
}

/// A namespace's queue: the namespace contract (the address that emits the
/// logs and holds the slots) and its queue's storage layout.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QueueTarget {
    pub contract: Fr,
    pub layout: QueueLayout,
}

/// One queue entry: `requests[index]`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QueueEntry {
    pub index: u64,
    /// The content-derived chain request id the entry holds.
    pub chain_request_id: Fr,
}

/// The queue at one block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueueView {
    pub block: u64,
    pub head: u64,
    /// `head_since`: the block at which the head last moved.
    pub head_since: u64,
    pub tail: u64,
    /// `requests[head..]`, at most `1 + lookahead` entries and never past
    /// `tail`; empty when the queue is.
    pub window: Vec<QueueEntry>,
}

impl QueueView {
    pub fn is_empty(&self) -> bool {
        self.head >= self.tail
    }

    /// The entry to process next.
    pub fn head_entry(&self) -> Option<&QueueEntry> {
        self.window.first()
    }

    /// The window's entry holding `chain_request_id`, if any: the head or a
    /// pipelined request after it.
    pub fn find(&self, chain_request_id: Fr) -> Option<&QueueEntry> {
        self.window
            .iter()
            .find(|e| e.chain_request_id == chain_request_id)
    }

    /// The first block in which `skip()` succeeds for the current head
    /// (`head_since + stale_blocks`), or `None` when the queue is empty or
    /// skipping is disabled. The scheduler stops working on a head once the
    /// chain reaches it.
    pub fn skippable_from(&self, stale_blocks: Option<u64>) -> Option<u64> {
        if self.is_empty() {
            return None;
        }
        stale_blocks.map(|s| self.head_since + s)
    }
}

/// A commitment slot at one block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SlotView {
    /// The manifest key whose commitment the slot holds.
    pub key: KeyRef,
    pub slot: Fr,
    /// The stored commitment (note hash); 0 before the first apply.
    pub commitment: Fr,
    pub block: u64,
}

/// The logs under one tag, in chain order: each one's fields after the tag
/// and where it sits.
pub type TaggedLogs = Vec<(Vec<Fr>, LogRef)>;

/// Where a log sits on chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogRef {
    pub block: u64,
    pub tx_hash: String,
    pub tx_index: u64,
    pub log_index: u64,
}

// The key-to-slot mapping: the request key of every key a
// queued round loads or stores, node-held or chain-held, is its commitment
// slot, written as a field (`0x` hex), so the slot of `$state_keys.reads[i]` is the
// field value of the request's `state_keys.reads[i]`. On Aztec a key is its
// storage slot: the app's `#[storage]` slot of its `CommitmentSlot`, read
// from the artifact's storage layout. A synthesised request names its keys by slot; a key that is not a
// field is refused here.
/// The storage slot of each key the manifest's `commitment_slot` names, from
/// the request's `state_keys`.
pub fn commitment_slots(
    manifest: &TipManifest,
    state_keys: &StateKeys,
) -> Result<Vec<(KeyRef, Fr)>, ReadError> {
    manifest
        .old_commitments()
        .map(|old| {
            let key = request_key(state_keys, old.key).ok_or_else(|| ReadError::BadKey {
                key: format!("{:?}", old.key),
                detail: "the request names no such key".into(),
            })?;
            let slot = fr_from_hex(key).map_err(|detail| ReadError::BadKey {
                key: key.to_string(),
                detail,
            })?;
            Ok((old.key, slot))
        })
        .collect()
}

/// The block hashes a chain reader holds, the gauge of its memory, which is
/// bounded by the blocks between the finalized tip and the tip and grows
/// while finality stalls; and the node's four tips as the last poll read
/// them, which an operator compares to see a reorg.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HeldBlocks {
    /// How many `(number, hash)` pairs it keeps.
    pub blocks: usize,
    /// The lowest block kept; `None` before the first snapshot.
    pub lowest: Option<u64>,
    /// The proposed tip at the last poll; 0 before the first.
    pub tip: u64,
    /// The checkpointed tip at the last poll.
    pub checkpointed: u64,
    /// The proven tip at the last poll.
    pub proven: u64,
    /// The finalized tip at the last poll.
    pub finalized: u64,
    /// The settled block, the floor of what is kept: the finalized tip
    /// once the reader has seen it move, else 0.
    pub settled: u64,
}

impl HeldBlocks {
    fn of(f: &Follower) -> Self {
        let tips = f.tips();
        let at = |pick: fn(&Tips) -> BlockId| tips.as_ref().map_or(0, |t| pick(t).number);
        HeldBlocks {
            blocks: f.retained(),
            lowest: f.lowest(),
            tip: f.tip().map_or(0, |b| b.number),
            checkpointed: at(|t| t.checkpointed),
            proven: at(|t| t.proven),
            finalized: at(|t| t.finalized),
            settled: f.settled(),
        }
    }

    /// The tips that went down since `before`, by name: the first sign of
    /// a replacement, logged by the reader.
    fn went_down(&self, before: &HeldBlocks) -> Vec<(&'static str, u64, u64)> {
        [
            ("proposed", before.tip, self.tip),
            ("checkpointed", before.checkpointed, self.checkpointed),
            ("proven", before.proven, self.proven),
            ("finalized", before.finalized, self.finalized),
        ]
        .into_iter()
        .filter(|(_, was, now)| now < was)
        .collect()
    }
}

/// The follower and when the reader next logs the hashes it holds.
struct Followed {
    follower: Follower,
    /// The settled block at the last log check.
    floor: u64,
    /// The count of held hashes at which the reader logs next: twice the
    /// count right after the floor last moved, doubling with each log.
    report_at: usize,
}

impl Followed {
    /// Log a doubling of the held hashes since the floor last moved:
    /// finality is stalling, and memory grows with nothing dropped.
    fn note(&mut self) {
        let f = &self.follower;
        let held = f.retained();
        if f.settled() != self.floor || self.report_at == 0 {
            self.floor = f.settled();
            self.report_at = 2 * held.max(1);
            return;
        }
        if held < self.report_at {
            return;
        }
        self.report_at *= 2;
        let (lowest, proven, settled) = (f.lowest().unwrap_or(0), f.proven(), f.settled());
        if self.floor == 0 {
            // the finalized tip has not moved since the reader started: it
            // keeps every block since its first snapshot
            tracing::info!(
                held,
                lowest,
                proven,
                "the chain reader keeps every block hash since it started until the finalized \
                 tip moves"
            );
        } else {
            tracing::warn!(
                held,
                lowest,
                proven,
                settled,
                "the chain reader holds twice the block hashes it held when the finalized tip \
                 last moved: finality is stalling, and it keeps every block back to the \
                 finalized tip"
            );
        }
    }
}

/// The chain reader over one Aztec node.
pub struct ChainReader<T> {
    transport: T,
    config: ReaderConfig,
    /// The proposed blocks followed, by hash, back to the settled block. A
    /// poll holds it across its calls to the node, so polls run one at a
    /// time.
    follower: tokio::sync::Mutex<Followed>,
    /// What the follower held after the last poll, read without waiting on
    /// a poll in flight (the status gauge, the settled block).
    held: std::sync::Mutex<HeldBlocks>,
}

impl<T: Transport> ChainReader<T> {
    pub fn new(transport: T) -> Self {
        Self::with_config(transport, ReaderConfig::default())
    }

    pub fn with_config(transport: T, config: ReaderConfig) -> Self {
        ChainReader {
            transport,
            config,
            follower: tokio::sync::Mutex::new(Followed {
                follower: Follower::new(),
                floor: 0,
                report_at: 0,
            }),
            held: std::sync::Mutex::new(HeldBlocks::default()),
        }
    }

    pub fn config(&self) -> &ReaderConfig {
        &self.config
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    async fn call(&self, method: &'static str, params: Value) -> Result<Value, ReadError> {
        self.transport
            .call(method, params)
            .await
            .map_err(|error| ReadError::Rpc { method, error })
    }

    /// The current proposed tip, refused once when the node replaced blocks
    /// the reader followed ([`ReadError::Pruned`]).
    pub async fn snapshot(&self) -> Result<Snapshot, ReadError> {
        let poll = self.poll().await?;
        if let Some(prune) = poll.prune {
            return Err(ReadError::Pruned(prune));
        }
        Ok(Snapshot {
            block: poll.tip.number,
            hash: Some(poll.tip.hash),
        })
    }

    /// Whether the reads made at `snap` still read the followed chain: one
    /// more poll of the follower, refused ([`ReadError::Pruned`]) when its
    /// prune voids `snap`'s block ([`Prune::voids`]), and refused
    /// ([`ReadError::ReferenceGone`]) when the block's hash is no longer the
    /// one `snap` was taken with. The comparison is what makes the check
    /// hold for every caller sharing the reader: a prune is reported to the
    /// one poll that sees it, so another caller's poll may have consumed it.
    /// A prune of blocks above `snap` only extends the follower, which
    /// follows the replacement from then on. The chain verifier confirms
    /// after its reads, so it never checks a request against reads that
    /// straddle a replaced block.
    pub async fn confirm(&self, snap: Snapshot) -> Result<(), ReadError> {
        let poll = self.poll().await?;
        if let Some(prune) = poll.prune
            && prune.voids(snap.block)
        {
            return Err(ReadError::Pruned(prune));
        }
        match snap.hash {
            Some(hash) if self.anchor(Snapshot::at(snap.block)).await?.hash != hash => {
                Err(ReadError::ReferenceGone { block: snap.block })
            }
            _ => Ok(()),
        }
    }

    /// One poll of the follower, with the log check of what it holds; the
    /// gauge is updated whether the poll succeeds or not, and a tip that
    /// went down since the last poll is logged.
    async fn poll(&self) -> Result<Poll, ReadError> {
        let mut followed = self.follower.lock().await;
        let poll = followed.follower.poll(&self.transport).await;
        if poll.is_ok() {
            followed.note();
        }
        let now = HeldBlocks::of(&followed.follower);
        let mut held = self
            .held
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for (tip, was, is) in now.went_down(&held) {
            tracing::warn!(tip, was, now = is, "the chain reader saw a tip go down");
        }
        *held = now;
        poll
    }

    /// The settled block, as the snapshots read it: the node's finalized
    /// tip once the reader has seen it move (0 until then), the lowest
    /// block whose hash the reader keeps, and the floor of everything a
    /// node deletes by its chain view (node-held versions, receipt inputs,
    /// retired encryption scalars). No replacement reaches it.
    pub async fn settled(&self) -> u64 {
        self.held().await.settled
    }

    /// The hash block `block`, below the settled block, has on the chain
    /// (final there: no replacement reaches it); `None` when the node has no
    /// such block or does not answer.
    pub async fn hash_at_settled(&self, block: u64) -> Option<Fr> {
        block_hash(&self.transport, block).await.ok().flatten()
    }

    /// The block hashes the reader holds after its last poll (the status
    /// endpoint's gauge), without waiting on a poll in flight.
    pub async fn held(&self) -> HeldBlocks {
        *self
            .held
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// The snapshot's block with its hash: the snapshot's own, else the one
    /// the follower holds, else (a block it does not hold) the node's.
    async fn anchor(&self, snap: Snapshot) -> Result<BlockId, ReadError> {
        let held = match snap.hash {
            Some(hash) => Some(hash),
            None => self.follower.lock().await.follower.hash_at(snap.block),
        };
        let hash = match held {
            Some(hash) => hash,
            None => block_hash(&self.transport, snap.block)
                .await?
                .ok_or(ReadError::ReferenceGone { block: snap.block })?,
        };
        Ok(BlockId {
            number: snap.block,
            hash,
        })
    }

    /// The first snapshot whose block is above `after`, polling the tip.
    pub async fn next_snapshot(&self, after: u64) -> Result<Snapshot, ReadError> {
        let start = Instant::now();
        loop {
            let snap = self.snapshot().await?;
            if snap.block > after {
                return Ok(snap);
            }
            if start.elapsed() >= self.config.follow_timeout {
                return Err(ReadError::NoNewBlock {
                    after,
                    waited: start.elapsed(),
                });
            }
            tokio::time::sleep(self.config.poll_interval).await;
        }
    }

    /// A call that names the snapshot's block ([`block_param`]): the node's
    /// refusal of a block hash that is no longer its block's ("Block hash …
    /// not found", or "Reference block … not found" from a contract or log
    /// query) is a replaced block ([`ReadError::ReferenceGone`]); any other
    /// refusal is the call's failure.
    async fn call_at(
        &self,
        snap: Snapshot,
        method: &'static str,
        params: Value,
    ) -> Result<Value, ReadError> {
        self.transport
            .call(method, params)
            .await
            .map_err(|error| match error {
                RpcError::Node { ref message, .. }
                    if snap.hash.is_some() && replaced_block(message) =>
                {
                    ReadError::ReferenceGone { block: snap.block }
                }
                error => ReadError::Rpc { method, error },
            })
    }

    /// One storage slot of `contract` at the snapshot's block.
    pub async fn storage(&self, snap: Snapshot, contract: Fr, slot: Fr) -> Result<Fr, ReadError> {
        const METHOD: &str = "node_getPublicStorageAt";
        let answer = self
            .call_at(
                snap,
                METHOD,
                json!([block_param(snap), fr_to_hex(contract), fr_to_hex(slot)]),
            )
            .await?;
        field(METHOD, &answer)
    }

    /// The current contract class of the instance at `contract`, at the
    /// snapshot's block (`node_getContract`: the instance with
    /// `currentContractClassId`, which the node resolves at the block from
    /// the registry's update events, so it is the original class until an
    /// upgrade takes effect); `None` when no instance is published there.
    pub async fn current_class(
        &self,
        snap: Snapshot,
        contract: Fr,
    ) -> Result<Option<Fr>, ReadError> {
        const METHOD: &str = "node_getContract";
        let answer = self
            .call_at(
                snap,
                METHOD,
                json!([fr_to_hex(contract), block_param(snap)]),
            )
            .await?;
        if answer.is_null() {
            return Ok(None);
        }
        let class = answer
            .get("currentContractClassId")
            .ok_or_else(|| malformed(METHOD, "the instance has no currentContractClassId"))?;
        field(METHOD, class).map(Some)
    }

    /// The timestamp of the snapshot's block (`node_getBlockData`: the
    /// header's `globalVariables.timestamp`, in seconds), the time a delayed
    /// value read at that block is evaluated at.
    pub async fn block_timestamp(&self, snap: Snapshot) -> Result<u64, ReadError> {
        const METHOD: &str = "node_getBlockData";
        let answer = self.call(METHOD, json!([snap.block])).await?;
        let stamp = answer
            .pointer("/header/globalVariables/timestamp")
            .ok_or_else(|| malformed(METHOD, format!("block {} has no timestamp", snap.block)))?;
        let parsed = match stamp {
            Value::Number(n) => n.as_u64(),
            Value::String(s) => match s.strip_prefix("0x") {
                Some(hex) => u64::from_str_radix(hex, 16).ok(),
                None => s.parse().ok(),
            },
            _ => None,
        };
        parsed.ok_or_else(|| malformed(METHOD, format!("the timestamp {stamp} is not a u64")))
    }

    /// The contract manifest version `layout`'s contract pins name in force
    /// at the snapshot's block: under `fixed` the layout's own; else the
    /// scheduled pins in force at the block's timestamp, or, while none was
    /// ever scheduled, the constructor's manifest hash (sidecar-core
    /// `circuit_pins`). The slots are the layout's: the pins never move
    /// between the versions of one namespace.
    pub async fn manifest_in_force(
        &self,
        snap: Snapshot,
        layout: &crate::namespace::TipLayout,
    ) -> Result<Fr, ReadError> {
        let Some(pins) = &layout.circuit_pins else {
            return Ok(layout.manifest_hash);
        };
        let contract = layout.contract;
        let s = pins.slots;
        let stored = sidecar_core::circuit_pins::StoredPins::new(
            self.storage(snap, contract, s.metadata).await?,
            [
                self.storage(snap, contract, s.before[0]).await?,
                self.storage(snap, contract, s.before[1]).await?,
            ],
            [
                self.storage(snap, contract, s.after[0]).await?,
                self.storage(snap, contract, s.after[1]).await?,
            ],
        );
        let timestamp = self.block_timestamp(snap).await?;
        match stored.in_force(timestamp) {
            Some(pinned) => Ok(pinned.manifest_hash),
            None => {
                self.storage(snap, contract, pins.constructor_manifest_hash)
                    .await
            }
        }
    }

    /// `contract`'s `TipConfig.stale_blocks` at the snapshot's block: the two
    /// fields from `slot` on.
    pub async fn stale_blocks(
        &self,
        snap: Snapshot,
        contract: Fr,
        slot: Fr,
    ) -> Result<StoredStaleBlocks, ReadError> {
        Ok(StoredStaleBlocks {
            enabled: self.storage(snap, contract, slot).await?,
            blocks: self.storage(snap, contract, slot + Fr::from(1u64)).await?,
        })
    }

    /// `contract`'s key epoch at the snapshot's block (pss_public_contract
    /// `key_epoch`, at its own slot): epoch 0 with zero keys when nothing is
    /// stored, the constructor's pins then being the epoch's `sig` keys.
    pub async fn key_epoch(
        &self,
        snap: Snapshot,
        contract: Fr,
    ) -> Result<sidecar_core::key_epoch::StoredNodeKeys, ReadError> {
        use sidecar_core::key_epoch::{NODE_KEYS_LEN, StoredNodeKeys, node_keys_slot};
        let slot = node_keys_slot();
        let mut fields = Vec::with_capacity(NODE_KEYS_LEN as usize);
        for k in 0..NODE_KEYS_LEN {
            fields.push(self.storage(snap, contract, slot + Fr::from(k)).await?);
        }
        StoredNodeKeys::unpack(&fields)
            .map_err(|detail| malformed("node_getPublicStorageAt", detail))
    }

    /// `contract`'s current key set at the snapshot's block, given `epoch`,
    /// the value its key epoch's slot holds there
    /// ([`node_keys_slot`](sidecar_core::key_epoch::node_keys_slot)): while
    /// it is 0, epoch 0's keys (the constructor's, beside
    /// `TipConfig.stale_blocks` at `stale_blocks_slot`); else the stored key
    /// epoch ([`Self::key_epoch`]).
    pub async fn key_set(
        &self,
        snap: Snapshot,
        contract: Fr,
        epoch: Fr,
        stale_blocks_slot: Fr,
    ) -> Result<sidecar_core::key_epoch::StoredNodeKeys, ReadError> {
        if epoch == Fr::from(0u64) {
            self.epoch0_keys(snap, contract, stale_blocks_slot).await
        } else {
            self.key_epoch(snap, contract).await
        }
    }

    /// `contract`'s key epoch 0 at the snapshot's block: the constructor's
    /// `sig` keys, read at [`epoch0_sig_slots`] from `stale_blocks_slot`
    /// (the namespace's `TipConfig.stale_blocks` slot).
    ///
    /// [`epoch0_sig_slots`]: sidecar_core::key_epoch::epoch0_sig_slots
    async fn epoch0_keys(
        &self,
        snap: Snapshot,
        contract: Fr,
        stale_blocks_slot: Fr,
    ) -> Result<sidecar_core::key_epoch::StoredNodeKeys, ReadError> {
        use sidecar_core::key_epoch::{StoredNodeKeys, epoch0_sig_slots};
        let mut fields = Vec::new();
        for slot in epoch0_sig_slots(stale_blocks_slot) {
            fields.push(self.storage(snap, contract, slot).await?);
        }
        Ok(StoredNodeKeys::epoch0(std::array::from_fn(|i| {
            (fields[2 * i], fields[2 * i + 1])
        })))
    }

    pub(crate) async fn storage_u64(
        &self,
        snap: Snapshot,
        contract: Fr,
        slot: Fr,
        what: &str,
    ) -> Result<u64, ReadError> {
        let value = self.storage(snap, contract, slot).await?;
        to_u64(value).ok_or_else(|| {
            malformed(
                "node_getPublicStorageAt",
                format!("{what} {} is not a u64", fr_to_hex(value)),
            )
        })
    }

    /// The queue's `head` and `tail` at the snapshot's block; refused when
    /// the head is past the tail.
    pub async fn head_and_tail(
        &self,
        snap: Snapshot,
        target: &QueueTarget,
    ) -> Result<(u64, u64), ReadError> {
        let (c, q) = (target.contract, &target.layout);
        let tail = self.storage_u64(snap, c, q.tail(), "tail").await?;
        let head = self.storage_u64(snap, c, q.head_index(), "head").await?;
        if head > tail {
            return Err(malformed(
                "node_getPublicStorageAt",
                format!("head {head} is past tail {tail}"),
            ));
        }
        Ok((head, tail))
    }

    /// `head`, `head_since`, `tail` and the window of entries from the head.
    pub async fn queue(
        &self,
        snap: Snapshot,
        target: &QueueTarget,
    ) -> Result<QueueView, ReadError> {
        let (c, q) = (target.contract, &target.layout);
        let (head, tail) = self.head_and_tail(snap, target).await?;
        let head_since = self
            .storage_u64(snap, c, q.head_since(), "head_since")
            .await?;
        let end = tail.min(head.saturating_add(1 + self.config.lookahead as u64));
        let mut window = Vec::with_capacity((end - head) as usize);
        for index in head..end {
            let chain_request_id = self.storage(snap, c, q.request(index)).await?;
            window.push(QueueEntry {
                index,
                chain_request_id,
            });
        }
        Ok(QueueView {
            block: snap.block,
            head,
            head_since,
            tail,
            window,
        })
    }

    /// `done[index]`: 0 pending, 1 applied, 2 skipped.
    pub async fn done(
        &self,
        snap: Snapshot,
        target: &QueueTarget,
        index: u64,
    ) -> Result<u8, ReadError> {
        let value = self
            .storage(snap, target.contract, target.layout.done(index))
            .await?;
        to_u64(value)
            .and_then(|v| u8::try_from(v).ok())
            .ok_or_else(|| {
                malformed(
                    "node_getPublicStorageAt",
                    format!("done[{index}] {} is not a u8", fr_to_hex(value)),
                )
            })
    }

    /// The commitment each slot holds, for the keys and slots
    /// [`commitment_slots`] maps.
    pub async fn slots(
        &self,
        snap: Snapshot,
        contract: Fr,
        keys: &[(KeyRef, Fr)],
    ) -> Result<Vec<SlotView>, ReadError> {
        let mut out = Vec::with_capacity(keys.len());
        for &(key, slot) in keys {
            out.push(SlotView {
                key,
                slot,
                commitment: self.storage(snap, contract, slot).await?,
                block: snap.block,
            });
        }
        Ok(out)
    }

    /// The logs `contract` emitted with `tag` up to the snapshot's block, in
    /// chain order, every page of them. The query names the contract, and
    /// the node matches it against the emitting address the AVM sets on each
    /// public log, so only the namespace contract's own logs come back; the
    /// reader applies no other filter (docs/DECISIONS.md, "The chain reader
    /// follows proposed blocks").
    pub async fn logs(
        &self,
        snap: Snapshot,
        contract: Fr,
        tag: Fr,
    ) -> Result<TaggedLogs, ReadError> {
        self.tagged(snap, Source::Public { contract }, tag).await
    }

    /// The private logs under `siloed_tag` (a tag the kernel siloed with
    /// the emitting contract's address) up to the snapshot's block, in
    /// chain order, every page of them.
    pub async fn private_logs(
        &self,
        snap: Snapshot,
        siloed_tag: Fr,
    ) -> Result<TaggedLogs, ReadError> {
        self.tagged(snap, Source::Private, siloed_tag).await
    }

    /// The logs of `source` under `tag`, anchored at the snapshot's block.
    async fn tagged(
        &self,
        snap: Snapshot,
        source: Source,
        tag: Fr,
    ) -> Result<TaggedLogs, ReadError> {
        let reference = self.anchor(snap).await?;
        let logs = logs_by_tag(&self.transport, source, tag, reference).await?;
        Ok(logs
            .into_iter()
            .map(|log| {
                let at = LogRef {
                    block: log.block,
                    tx_hash: log.tx_hash.clone(),
                    tx_index: log.tx_index,
                    log_index: log.log_index,
                };
                (log.fields().to_vec(), at)
            })
            .collect())
    }
}

/// Whether a node's refusal of a call pinned to a block hash says the block
/// is gone (Aztec node 6.0.0: `Block hash … not found when resolving
/// query`, `Reference block … not found …`).
fn replaced_block(message: &str) -> bool {
    message.contains("not found")
        && (message.contains("Block hash 0x") || message.contains("Reference block "))
}

/// The block a read at `snap` names: its number and, for a snapshot taken
/// from the follower, its hash, so the node refuses the read once the block
/// is replaced (`AnchoredBlockParameter`); its number alone for a snapshot
/// made by number.
fn block_param(snap: Snapshot) -> Value {
    match snap.hash {
        Some(hash) => json!({"number": snap.block, "hash": fr_to_hex(hash)}),
        None => json!({"number": snap.block}),
    }
}

fn to_u64(value: Fr) -> Option<u64> {
    let bytes = fr_to_be_bytes(value);
    bytes[..24]
        .iter()
        .all(|b| *b == 0)
        .then(|| u64::from_be_bytes(bytes[24..].try_into().expect("8 bytes")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::layout::request_log_tag;
    use crate::intake::onchain::RequestInputs;
    use crate::testing::{FixtureTransport, MemoryChain};
    use sidecar_core::Manifest;
    use sidecar_core::error::parse_json;
    use sidecar_core::manifest::PublicRead;
    use std::collections::BTreeMap;

    // Recorded from a local Aztec 6.0.0 network: see each file's "recorded".
    const QUEUE: &str = include_str!("../../tests/fixtures/queue.json");
    const PINNED: &str = include_str!("../../tests/fixtures/pinned.json");
    const LOGS: &str = include_str!("../../tests/fixtures/logs.json");
    use crate::testing::AMM_SWAP_TIP;

    fn f(hex: &str) -> Fr {
        fr_from_hex(hex).unwrap()
    }

    /// On-chain intake's request log of `id` in namespace `ns`, read at
    /// `snap`.
    async fn request_inputs<T: Transport>(
        reader: &ChainReader<T>,
        snap: Snapshot,
        ns: Fr,
        id: Fr,
    ) -> Result<Option<RequestInputs>, ReadError> {
        let at = crate::intake::ChainAt {
            reader,
            snap,
            namespace: ns,
            layout: Default::default(),
        };
        crate::intake::onchain::request_log(&at, id).await
    }

    fn fixture_address(text: &str, key: &str) -> Fr {
        let v: Value = serde_json::from_str(text).unwrap();
        f(v[key].as_str().unwrap())
    }

    fn target(contract: Fr) -> QueueTarget {
        QueueTarget {
            contract,
            layout: QueueLayout::new(Fr::from(4u64)),
        }
    }

    fn manifest_with_reads(reads: &str) -> TipManifest {
        let text = AMM_SWAP_TIP.replace(
            "\"public_reads\": []",
            &format!("\"public_reads\": {reads}"),
        );
        TipManifest::from_manifest(
            &Manifest::parse(&parse_json(&text).unwrap()).unwrap(),
            Some(50),
        )
        .unwrap()
    }

    /// The recorded queue's request ids, each on-chain intake id recomputed
    /// from its recorded inputs and nonce under the non-secret-shared request layout.
    fn fixture_ids(text: &str) -> Vec<Fr> {
        let v: Value = serde_json::from_str(text).unwrap();
        let ids: Vec<Fr> = v["request_ids"]
            .as_array()
            .unwrap()
            .iter()
            .map(|id| f(id.as_str().unwrap()))
            .collect();
        let (contract, vk_hash) = (
            fixture_address(text, "contract"),
            fixture_address(text, "vk_hash"),
        );
        let onchain = v["onchain"].as_array().unwrap();
        assert!(!onchain.is_empty());
        for (i, request) in onchain.iter().enumerate() {
            let inputs: Vec<Fr> = request["inputs"]
                .as_array()
                .unwrap()
                .iter()
                .map(|x| f(x.as_str().unwrap()))
                .collect();
            let nonce = f(request["user_nonce"].as_str().unwrap());
            assert_eq!(
                crate::chain_request_id(contract, vk_hash, &inputs, nonce),
                ids[i],
                "request {i}"
            );
        }
        ids
    }

    /// A recorded PssPublicTest storage slot (`queue` or `pool`), from its
    /// compiled storage layout.
    fn fixture_slot(text: &str, name: &str) -> Fr {
        let v: Value = serde_json::from_str(text).unwrap();
        f(v["slots"][name].as_str().unwrap())
    }

    fn test_contract(text: &str) -> QueueTarget {
        QueueTarget {
            contract: fixture_address(text, "contract"),
            layout: QueueLayout::new(fixture_slot(text, "queue")),
        }
    }

    #[tokio::test]
    async fn the_recorded_queue_parses() {
        let target = test_contract(QUEUE);
        let contract = target.contract;
        let ids = fixture_ids(QUEUE);
        let reader = ChainReader::new(FixtureTransport::from_json(QUEUE));
        // the recording's tip
        let snap = Snapshot::at(12);
        let queue = reader.queue(snap, &target).await.unwrap();
        // seven requests appended from block 6 on, none applied or skipped
        assert_eq!((queue.head, queue.head_since, queue.tail), (0, 6, 7));
        let window: Vec<Fr> = queue.window.iter().map(|e| e.chain_request_id).collect();
        assert_eq!(
            window,
            ids[..5],
            "the head and DEFAULT_LOOKAHEAD entries after it"
        );
        assert_eq!(
            queue.window.iter().map(|e| e.index).collect::<Vec<_>>(),
            [0, 1, 2, 3, 4]
        );
        assert_eq!(queue.head_entry().unwrap().chain_request_id, ids[0]);
        assert_eq!(queue.find(Fr::from(0xd4u64)).unwrap().index, 3);
        assert!(queue.find(Fr::from(0xf6u64)).is_none(), "past the window");
        assert_eq!(queue.skippable_from(Some(4)), Some(10));
        assert_eq!(queue.skippable_from(None), None);

        // the commitment slot `pool` under the "key = storage slot" mapping
        let pool = fixture_slot(QUEUE, "pool");
        let manifest = manifest_with_reads("[]");
        let state_keys = StateKeys {
            reads: vec![fr_to_hex(pool)],
            writes: vec![fr_to_hex(pool)],
        };
        let mapped = commitment_slots(&manifest, &state_keys).unwrap();
        assert_eq!(mapped, [(KeyRef::Read(0), pool)]);
        let slots = reader.slots(snap, contract, &mapped).await.unwrap();
        assert_eq!(
            slots[0].commitment,
            Fr::from(0u64),
            "only apply writes the slot"
        );
        assert_eq!(slots[0].block, 12);

        // a block the node does not have
        let err = reader
            .storage(Snapshot::at(1012), contract, target.layout.tail())
            .await
            .unwrap_err();
        assert!(
            matches!(
                err,
                ReadError::Rpc {
                    error: RpcError::Node { code: -32702, .. },
                    ..
                }
            ),
            "{err}"
        );
        assert!(
            reader.transport().unused().is_empty(),
            "{:?}",
            reader.transport().unused()
        );
    }

    #[tokio::test]
    async fn pinned_reads_are_filled_by_the_simulated_call() {
        let contract = fixture_address(PINNED, "contract");
        let ids = fixture_ids(PINNED);
        let reader = ChainReader::new(FixtureTransport::from_json(PINNED));
        let snap = Snapshot::at(12);
        let c = fr_to_hex(contract);
        let manifest = manifest_with_reads(&format!(
            r#"[{{"contract": "{c}", "function": "get_tail", "args": [], "param": "amount_in"}}]"#
        ));
        // the request bytes the reader builds equal the recorded ones, which
        // stdlib serialised: FixtureTransport answers only an equal request
        let pinned = reader
            .pinned_values(snap, contract, &manifest, &BTreeMap::new())
            .await
            .unwrap();
        let tail = pinned.get("amount_in").unwrap();
        assert_eq!(
            (tail.function.as_str(), tail.values.as_slice()),
            ("get_tail()", &[Fr::from(7u64)][..])
        );
        assert_eq!(tail.source, PinnedSource::Simulated);
        assert_eq!(tail.block, 12);
        // a getter with a u64 parameter, named by its full signature (the
        // manifest takes names only, so this read is built directly)
        let read = PublicRead {
            contract: contract.into(),
            function: "request_at(u64)".into(),
            args: vec![Fr::from(1u64).into()],
            param: "direction".into(),
            freshness: sidecar_core::manifest::Freshness::Exact,
            epoch_param: None,
            band: None,
        };
        let entry = reader.simulate(snap, contract, &read).await.unwrap();
        assert_eq!(entry.values, [ids[1]]);
        assert_eq!(entry.args, [Fr::from(1u64)]);

        // the same getter read from its backing slot (the queue's tail)
        let tail_slot = test_contract(PINNED).layout.tail();
        let plain = BTreeMap::from([("amount_in".to_string(), tail_slot)]);
        let pinned = reader
            .pinned_values(snap, contract, &manifest, &plain)
            .await
            .unwrap();
        assert_eq!(pinned.0[0].values, [Fr::from(7u64)]);
        assert_eq!(
            pinned.0[0].source,
            PinnedSource::Storage { slot: tail_slot }
        );

        // a call that writes reverts in the static call
        let read = PublicRead {
            contract: contract.into(),
            function: "skip".into(),
            args: vec![],
            param: "p".into(),
            freshness: sidecar_core::manifest::Freshness::Exact,
            epoch_param: None,
            band: None,
        };
        let err = reader.simulate(snap, contract, &read).await.unwrap_err();
        let ReadError::Reverted { function, reason } = err else {
            panic!("{err}")
        };
        assert_eq!(function, "skip()");
        assert!(
            reason.contains("Static call cannot update the state"),
            "{reason}"
        );
        assert!(
            reader.transport().unused().is_empty(),
            "{:?}",
            reader.transport().unused()
        );
    }

    #[tokio::test]
    async fn the_recorded_logs_parse_and_only_the_namespace_contracts_count() {
        let c = fixture_address(LOGS, "c");
        let (a, b) = (fixture_address(LOGS, "a"), fixture_address(LOGS, "b"));
        let r0 = fixture_address(LOGS, "r0");
        let vk_hash = fixture_address(LOGS, "vk_hash");
        let reader = ChainReader::new(FixtureTransport::from_json(LOGS));
        // the follower's first poll; every query is anchored at its hash
        let snap = reader.snapshot().await.unwrap();
        assert_eq!(snap.block, 12);
        // C's intake emitted R0's request log; B later emitted other inputs
        // under the same tag. Reading for namespace C gives C's own log.
        let ours = request_inputs(&reader, snap, c, r0).await.unwrap().unwrap();
        // the non-secret-shared split: every field but the last is an app input, the
        // last is the nonce (the recording's three fields after the tag)
        let plain = ours.plain().unwrap();
        assert_eq!(plain.inputs, [Fr::from(1000u64), Fr::from(0u64)]);
        assert_eq!(plain.user_nonce, Fr::from(0x77u64));
        assert_eq!(ours.log.block, 6);
        // the log's content is all the contract hashed into R0
        assert_eq!(
            crate::chain_request_id(c, vk_hash, plain.inputs, plain.user_nonce),
            r0
        );
        let theirs = request_inputs(&reader, snap, b, r0).await.unwrap().unwrap();
        let other = theirs.plain().unwrap();
        assert_eq!(other.inputs, [Fr::from(999999u64), Fr::from(1u64)]);
        assert_eq!(other.user_nonce, Fr::from(0xbadu64));
        assert_eq!(theirs.log.block, 10);

        let tag = crate::state::chain::sealed_log_tag(r0);
        let sealed_logs = reader.logs(snap, a, tag).await.unwrap();
        let sealed = crate::SealedState::latest(r0, sealed_logs).unwrap();
        assert_eq!(
            sealed.fields,
            (11u64..=16).map(Fr::from).collect::<Vec<_>>()
        );
        assert_eq!(sealed.log.block, 12);
        let sealed_logs = reader.logs(snap, b, tag).await.unwrap();
        let sealed_b = crate::SealedState::latest(r0, sealed_logs).unwrap();
        assert_eq!(sealed_b.fields, vec![Fr::from(9u64); 6]);
        assert_eq!(sealed_b.log.block, 11);

        // a request appended without intake has no log
        assert_eq!(
            request_inputs(&reader, snap, c, Fr::from(0xd4u64))
                .await
                .unwrap(),
            None
        );

        // the tag queries over the node's answers: the follower's next poll
        // compares the block it held (12) and, the new tip being proven,
        // fills in no block below it on its way there, without a prune
        let later = reader.snapshot().await.unwrap();
        assert_eq!(later.block, 14);
        assert_eq!(reader.held().await.proven, 14);
        // more logs under one tag than a page: 20, then the rest after the
        // 20th (afterLog), every one in a single transaction
        let paged_tag = fixture_address(LOGS, "paged_tag");
        let paged = reader.logs(later, a, paged_tag).await.unwrap();
        assert_eq!(
            paged.iter().map(|(f, _)| f.clone()).collect::<Vec<_>>(),
            (0..21u64).map(|i| vec![Fr::from(i)]).collect::<Vec<_>>()
        );
        assert_eq!(
            paged.iter().map(|(_, at)| at.log_index).collect::<Vec<_>>(),
            (0..21).collect::<Vec<_>>()
        );
        assert!(paged.iter().all(|(_, at)| at.block == 13));
        // a private log, by its siloed tag, at the tip's hash
        let v: Value = serde_json::from_str(LOGS).unwrap();
        let tips = v["calls"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|call| call["method"] == "node_getChainTips")
            .nth(1)
            .unwrap();
        let at = BlockId {
            number: 14,
            hash: f(tips["response"]["result"]["proposed"]["hash"]
                .as_str()
                .unwrap()),
        };
        let private_tag = fixture_address(LOGS, "private_tag");
        let private = logs_by_tag(reader.transport(), Source::Private, private_tag, at)
            .await
            .unwrap();
        assert_eq!(private.len(), 1);
        assert_eq!(private[0].fields(), [21u64, 22, 23].map(Fr::from));
        assert_eq!(private[0].block, 14);
        // the node's refusal of a reference block it does not have is a
        // replaced block
        let gone = BlockId {
            number: 14,
            hash: fixture_address(LOGS, "gone"),
        };
        assert_eq!(
            logs_by_tag(
                reader.transport(),
                Source::Public { contract: a },
                paged_tag,
                gone
            )
            .await,
            Err(ReadError::ReferenceGone { block: 14 })
        );
        // and a block past the tip has no hash
        assert_eq!(block_hash(reader.transport(), 15).await, Ok(None));
        assert!(
            reader.transport().unused().is_empty(),
            "{:?}",
            reader.transport().unused()
        );
    }

    #[tokio::test]
    async fn a_same_tag_log_from_another_contract_is_ignored() {
        let (ns, other) = (Fr::from(0x1111u64), Fr::from(0x2222u64));
        let chain = MemoryChain::new(30);
        let id = Fr::from(0xa1u64);
        let tag = request_log_tag(id);
        // the other contract front-runs the namespace's intake
        chain.push_log(
            other,
            20,
            tag,
            &[Fr::from(5u64), Fr::from(6u64), Fr::from(7u64)],
        );
        chain.push_log(
            ns,
            21,
            tag,
            &[Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)],
        );
        let reader = ChainReader::new(chain);
        let snap = reader.snapshot().await.unwrap();
        let inputs = request_inputs(&reader, snap, ns, id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(inputs.fields, [1u64, 2, 3].map(Fr::from));
        assert_eq!(inputs.log.block, 21);
    }

    fn quick() -> ReaderConfig {
        ReaderConfig {
            lookahead: 2,
            poll_interval: Duration::from_millis(1),
            follow_timeout: Duration::from_millis(200),
        }
    }

    #[tokio::test]
    async fn the_reader_follows_the_proposed_tip_and_refuses_a_prune_once() {
        let chain = MemoryChain::new(5);
        chain.script_tips(&[5, 5, 5, 6]);
        let reader = ChainReader::with_config(chain, quick());
        assert_eq!(reader.snapshot().await.unwrap().block, 5);
        // waits out two polls at 5, then sees 6
        assert_eq!(reader.next_snapshot(5).await.unwrap().block, 6);
        // already past: no wait
        assert_eq!(reader.next_snapshot(3).await.unwrap().block, 6);

        // a tip below one seen is the follower's prune, refused once (the
        // follower reads the tips again after its walk-back); the shorter
        // chain is followed from then on
        let chain = MemoryChain::new(7);
        chain.script_tips(&[7, 6, 6, 6, 8]);
        let reader = ChainReader::with_config(chain, quick());
        assert_eq!(reader.snapshot().await.unwrap().block, 7);
        let err = reader.snapshot().await.unwrap_err();
        assert_eq!(
            err,
            ReadError::Pruned(Prune {
                from: 7,
                to: 6,
                below_kept: true
            }),
            "the reader never held block 6"
        );
        assert!(err.to_string().contains("went back"), "{err}");
        assert_eq!(reader.snapshot().await.unwrap().block, 6);
        assert_eq!(reader.snapshot().await.unwrap().block, 8);

        // a block replaced at the same height
        let chain = std::sync::Arc::new(MemoryChain::new(20));
        let reader = ChainReader::with_config(chain.clone(), quick());
        reader.snapshot().await.unwrap();
        chain.set_tip(21);
        reader.snapshot().await.unwrap();
        chain.node().replace_from(21);
        assert_eq!(
            reader.snapshot().await,
            Err(ReadError::Pruned(Prune {
                from: 21,
                to: 20,
                below_kept: false
            }))
        );
        assert_eq!(reader.snapshot().await.unwrap().block, 21);
        chain.node().set_proven(15);
        reader.snapshot().await.unwrap();
        assert_eq!(reader.held().await.proven, 15);

        // no new block
        let reader = ChainReader::with_config(MemoryChain::new(9), quick());
        assert!(matches!(
            reader.next_snapshot(9).await,
            Err(ReadError::NoNewBlock { after: 9, .. })
        ));
    }

    /// A reader that followed blocks 85 to 110 while the proven tip moved
    /// 80, 90, 95, finalizing 80 and then 90: it keeps the hashes of blocks
    /// 90 (the settled block) to 110, and its snapshot is at 110.
    async fn reading_two_finalized_tips(
        chain: &std::sync::Arc<MemoryChain>,
    ) -> ChainReader<std::sync::Arc<MemoryChain>> {
        let reader = ChainReader::with_config(chain.clone(), quick());
        for (tip, proven) in [(85, 80), (100, 90), (110, 95)] {
            chain.set_tip(tip);
            chain.node().set_proven(proven);
            assert_eq!(reader.snapshot().await.unwrap().block, tip);
        }
        assert_eq!(
            reader.held().await,
            HeldBlocks {
                blocks: 21,
                lowest: Some(90),
                tip: 110,
                checkpointed: 110,
                proven: 95,
                finalized: 90,
                settled: 90
            }
        );
        assert_eq!(reader.settled().await, 90);
        reader
    }

    /// Two callers on one reader (two namespaces' chain verifiers on one
    /// node): both read at one snapshot, the node replaces its block, one
    /// caller's poll consumes the prune, and the other's confirm still
    /// refuses, by the hash its snapshot carries.
    #[tokio::test]
    async fn every_caller_sharing_a_reader_refuses_a_replaced_block() {
        let chain = std::sync::Arc::new(MemoryChain::new(0));
        let reader = reading_two_finalized_tips(&chain).await;
        let a = reader.snapshot().await.unwrap();
        let b = reader.snapshot().await.unwrap();
        assert_eq!(a, b);
        assert_eq!(a.hash, Some(chain.node().hash(110)));
        chain.node().replace_from(105);
        assert!(matches!(reader.confirm(b).await, Err(ReadError::Pruned(_))));
        assert_eq!(
            reader.confirm(a).await,
            Err(ReadError::ReferenceGone { block: 110 })
        );
        // a snapshot of the replacement stands, and one made by number
        // confirms on the prune alone
        let c = reader.snapshot().await.unwrap();
        assert_ne!(c.hash, a.hash);
        assert_eq!(reader.confirm(c).await, Ok(()));
        assert_eq!(reader.confirm(Snapshot::at(110)).await, Ok(()));
    }

    #[tokio::test]
    async fn the_reader_places_a_replacement_back_to_the_settled_block() {
        // at the proven tip: reads at 94 stand, reads at 95 and above are void
        let chain = std::sync::Arc::new(MemoryChain::new(0));
        let reader = reading_two_finalized_tips(&chain).await;
        chain.node().replace_from(95);
        let err = reader.confirm(Snapshot::at(94)).await;
        assert_eq!(err, Ok(()), "a read below the replacement stands");
        let chain = std::sync::Arc::new(MemoryChain::new(0));
        let reader = reading_two_finalized_tips(&chain).await;
        chain.node().replace_from(95);
        assert_eq!(
            reader.snapshot().await,
            Err(ReadError::Pruned(Prune {
                from: 110,
                to: 94,
                below_kept: false
            }))
        );
        assert_eq!(reader.snapshot().await.unwrap().block, 110);
        assert_eq!(reader.held().await.blocks, 21);

        // between the settled block and the proven tip
        let chain = std::sync::Arc::new(MemoryChain::new(0));
        let reader = reading_two_finalized_tips(&chain).await;
        chain.node().replace_from(92);
        let err = reader.confirm(Snapshot::at(100)).await.unwrap_err();
        assert_eq!(
            err,
            ReadError::Pruned(Prune {
                from: 110,
                to: 91,
                below_kept: false
            })
        );

        // reaching the settled block: every read is void
        let chain = std::sync::Arc::new(MemoryChain::new(0));
        let reader = reading_two_finalized_tips(&chain).await;
        chain.node().replace_from(60);
        let err = reader.snapshot().await.unwrap_err();
        assert_eq!(
            err,
            ReadError::Pruned(Prune {
                from: 110,
                to: 89,
                below_kept: true
            })
        );
        assert!(matches!(err, ReadError::Pruned(p) if p.voids(1)));
        assert_eq!(reader.held().await.blocks, 1);
    }

    #[tokio::test]
    async fn a_finality_stall_grows_the_held_hashes() {
        let chain = std::sync::Arc::new(MemoryChain::new(0));
        let reader = reading_two_finalized_tips(&chain).await;
        chain.set_tip(400);
        reader.snapshot().await.unwrap();
        let held = reader.held().await;
        assert_eq!((held.blocks, held.lowest), (311, Some(90)), "{held:?}");
        chain.node().set_proven(390);
        chain.set_tip(401);
        reader.snapshot().await.unwrap();
        assert_eq!(reader.held().await.lowest, Some(95));
    }

    /// Reads of a snapshot taken from the follower name the block's hash,
    /// and the node refuses one whose block was replaced (a replaced
    /// block, read again at a new snapshot); a snapshot made by number
    /// reads whatever block holds the number. The in-memory chain's storage
    /// goes back with a replaced block by itself.
    #[tokio::test]
    async fn a_read_pinned_to_a_replaced_block_is_refused_by_the_node() {
        let (ns, slot) = (Fr::from(0xabcdu64), Fr::from(10u64));
        let chain = std::sync::Arc::new(MemoryChain::new(30));
        chain.set_storage(ns, slot, Fr::from(1u64));
        chain.set_storage_at(30, ns, slot, Fr::from(2u64));
        let reader = ChainReader::with_config(chain.clone(), quick());
        let snap = reader.snapshot().await.unwrap();
        assert_eq!(reader.storage(snap, ns, slot).await, Ok(Fr::from(2u64)));
        assert_eq!(
            reader.current_class(snap, ns).await.map(|c| c.is_some()),
            Ok(true)
        );
        chain.node().replace_from(30);
        assert_eq!(
            reader.storage(snap, ns, slot).await,
            Err(ReadError::ReferenceGone { block: 30 })
        );
        assert_eq!(
            reader.current_class(snap, ns).await,
            Err(ReadError::ReferenceGone { block: 30 })
        );
        assert!(ReadError::ReferenceGone { block: 30 }.replaced());
        // by number: block 30 of the replacement, whose write went with it
        assert_eq!(
            reader.storage(Snapshot::at(30), ns, slot).await,
            Ok(Fr::from(1u64))
        );
        // the next snapshot reports the replacement, then reads it
        assert!(matches!(reader.snapshot().await, Err(ReadError::Pruned(_))));
        let again = reader.snapshot().await.unwrap();
        assert_eq!(reader.storage(again, ns, slot).await, Ok(Fr::from(1u64)));
    }

    /// Only the node's two answers to a gone block hash are a replaced block;
    /// another "not found" (a contract, a block by number) is the call's
    /// failure.
    #[test]
    fn only_a_gone_block_hash_is_a_replaced_block() {
        for gone in [
            "Block hash 0x0d not found when resolving query. If the node API has been queried \
             with anchor block hash possibly a reorg has occurred.",
            "Reference block 0x0d not found in the node. This might indicate a reorg has occurred.",
            "Reference block 0x0d not found when querying contract 0x0c. If the node API has \
             been queried with an anchor block hash, possibly a reorg has occurred.",
        ] {
            assert!(replaced_block(gone), "{gone}");
        }
        for other in [
            "Block not found for number=12 when resolving query.",
            "Contract 0x0c not found",
            "Block hash not found for block number 12",
        ] {
            assert!(!replaced_block(other), "{other}");
        }
    }

    /// The node switches fork right after answering its tips: the snapshot
    /// carries the stale tip's hash, which agrees with what the follower
    /// held, so the poll reports nothing; every read pinned to it is refused
    /// by the node, and the next snapshot places the replacement.
    #[tokio::test]
    async fn a_stale_tip_cannot_fake_agreement_for_the_reads() {
        let (ns, slot) = (Fr::from(0xabcdu64), Fr::from(10u64));
        let chain = std::sync::Arc::new(MemoryChain::new(40));
        let reader = ChainReader::with_config(chain.clone(), quick());
        reader.snapshot().await.unwrap();
        chain.set_tip(42);
        chain.set_storage_at(42, ns, slot, Fr::from(7u64));
        reader.snapshot().await.unwrap();
        chain.node().replace_after_next_tips(41);
        let stale = reader.snapshot().await.unwrap();
        assert_eq!(stale.block, 42);
        assert_eq!(
            reader.storage(stale, ns, slot).await,
            Err(ReadError::ReferenceGone { block: 42 })
        );
        assert_eq!(
            reader.confirm(stale).await,
            Err(ReadError::Pruned(Prune {
                from: 42,
                to: 40,
                below_kept: false
            }))
        );
        let snap = reader.snapshot().await.unwrap();
        assert_eq!(reader.storage(snap, ns, slot).await, Ok(Fr::from(0u64)));
    }

    /// The reader reads and reports the node's four tips with every poll.
    #[tokio::test]
    async fn the_reader_reports_the_four_tips() {
        let chain = std::sync::Arc::new(MemoryChain::new(60));
        chain.node().set_proven(50);
        chain.node().set_proven(55);
        chain.node().set_checkpointed(Some(58));
        let reader = ChainReader::with_config(chain.clone(), quick());
        reader.snapshot().await.unwrap();
        let held = reader.held().await;
        assert_eq!(
            (
                held.tip,
                held.checkpointed,
                held.proven,
                held.finalized,
                held.settled
            ),
            (60, 58, 55, 50, 0)
        );
    }

    #[tokio::test]
    async fn reads_at_a_replaced_block_are_refused_when_confirmed() {
        let chain = std::sync::Arc::new(MemoryChain::new(30));
        let reader = ChainReader::with_config(chain.clone(), quick());
        let snap = reader.snapshot().await.unwrap();
        reader.confirm(snap).await.unwrap();
        // the chain moved on: the reads at 30 stand
        chain.set_tip(32);
        reader.confirm(snap).await.unwrap();
        // a replacement above the snapshot's block leaves them standing
        chain.node().replace_from(31);
        reader.confirm(snap).await.unwrap();
        // the snapshot's own block replaced: refused, once
        chain.node().replace_from(30);
        let err = reader.confirm(snap).await.unwrap_err();
        assert!(err.replaced(), "{err}");
        assert!(
            matches!(err, ReadError::Pruned(p) if p.from == 32 && p.voids(30)),
            "{err}"
        );
        assert_eq!(reader.snapshot().await.unwrap().block, 32);
        assert!(ReadError::ReferenceGone { block: 30 }.replaced());
        assert!(
            !ReadError::NoNewBlock {
                after: 1,
                waited: Duration::ZERO
            }
            .replaced()
        );
    }

    #[tokio::test]
    async fn the_queue_slots_and_pinned_values_come_from_one_block() {
        let ns = Fr::from(0xabcdu64);
        let oracle = Fr::from(0x0e0eu64);
        let t = target(ns);
        let chain = MemoryChain::new(40);
        let ids: Vec<Fr> = (1u64..=6).map(Fr::from).collect();
        // two finished entries; the head is index 2
        chain.write_queue(ns, t.layout, &ids, 2, 33);
        chain.set_storage(ns, Fr::from(10u64), Fr::from(0xc0ffeeu64));
        chain.set_call(
            oracle,
            "get_price(Field)",
            &[Fr::from(1u64)],
            Ok(vec![Fr::from(4242u64)]),
        );
        let reader = ChainReader::with_config(chain, quick());
        let manifest = manifest_with_reads(&format!(
            r#"[{{"contract": "{}", "function": "get_price", "args": ["0x01"], "param": "direction"}}]"#,
            fr_to_hex(oracle)
        ));
        let keys = commitment_slots(
            &manifest,
            &StateKeys {
                reads: vec!["0x0a".into()],
                writes: vec!["0x0a".into()],
            },
        )
        .unwrap();
        let snap = reader.snapshot().await.unwrap();
        let queue = reader.queue(snap, &t).await.unwrap();
        let slots = reader.slots(snap, t.contract, &keys).await.unwrap();
        let pinned = reader
            .pinned_values(snap, t.contract, &manifest, &BTreeMap::new())
            .await
            .unwrap();
        assert_eq!(snap.block, 40);
        assert_eq!((queue.head, queue.head_since, queue.tail), (2, 33, 6));
        // head plus lookahead 2
        assert_eq!(
            queue.window.iter().map(|e| e.index).collect::<Vec<_>>(),
            [2, 3, 4]
        );
        assert_eq!(slots[0].commitment, Fr::from(0xc0ffeeu64));
        assert_eq!(pinned.get("direction").unwrap().values, [Fr::from(4242u64)]);

        // the window stops at the tail
        let chain = MemoryChain::new(40);
        chain.write_queue(ns, t.layout, &ids, 5, 39);
        let reader = ChainReader::new(chain);
        let queue = reader
            .queue(reader.snapshot().await.unwrap(), &t)
            .await
            .unwrap();
        assert_eq!(queue.window.len(), 1);
        // an empty queue
        let chain = MemoryChain::new(40);
        chain.write_queue(ns, t.layout, &ids, 6, 39);
        let reader = ChainReader::new(chain);
        let queue = reader
            .queue(reader.snapshot().await.unwrap(), &t)
            .await
            .unwrap();
        assert!(
            queue.is_empty() && queue.window.is_empty() && queue.skippable_from(Some(4)).is_none()
        );
    }

    #[tokio::test]
    async fn a_simulation_on_a_newer_block_is_refused() {
        let oracle = Fr::from(0x0e0eu64);
        let chain = MemoryChain::new(40);
        chain.set_call(
            oracle,
            "get_price(Field)",
            &[Fr::from(1u64)],
            Ok(vec![Fr::from(1u64)]),
        );
        chain.script_tips(&[40, 41]);
        let reader = ChainReader::new(chain);
        let snap = reader.snapshot().await.unwrap();
        // the next tip read (inside the in-memory node) moves to 41
        let _ = reader.snapshot().await.unwrap();
        let read = PublicRead {
            contract: oracle.into(),
            function: "get_price".into(),
            args: vec![Fr::from(1u64).into()],
            param: "p".into(),
            freshness: sidecar_core::manifest::Freshness::Exact,
            epoch_param: None,
            band: None,
        };
        assert_eq!(
            reader.simulate(snap, Fr::from(1u64), &read).await,
            Err(ReadError::SnapshotMoved {
                snapshot: 40,
                simulated: 41
            })
        );
    }

    #[tokio::test]
    async fn an_epoch_read_keeps_the_value_and_its_epoch_and_the_previous_value() {
        let oracle = Fr::from(0x0e0eu64);
        let chain = MemoryChain::new(40);
        chain.set_call(
            oracle,
            "get_price_epoch()",
            &[],
            Ok(vec![Fr::from(250u64), Fr::from(4u64), Fr::from(240u64)]),
        );
        let reader = ChainReader::new(chain);
        let snap = reader.snapshot().await.unwrap();
        let o = fr_to_hex(oracle);
        let manifest = manifest_with_reads(&format!(
            r#"[{{"contract": "{o}", "function": "get_price_epoch", "args": [], "param": "direction",
                 "freshness": "epoch", "epoch_param": "min_out"}}]"#
        ));
        let pinned = reader
            .pinned_values(snap, Fr::from(1u64), &manifest, &BTreeMap::new())
            .await
            .unwrap();
        let price = pinned.get("direction").unwrap();
        assert_eq!(price.values, [Fr::from(250u64), Fr::from(4u64)]);
        assert_eq!(price.previous, Some(Fr::from(240u64)));
        // a source that does not return three fields, or a backing slot
        // in place of the call, is refused
        let chain = MemoryChain::new(40);
        chain.set_call(oracle, "get_price_epoch()", &[], Ok(vec![Fr::from(250u64)]));
        let reader = ChainReader::new(chain);
        let snap = reader.snapshot().await.unwrap();
        let err = reader
            .pinned_values(snap, Fr::from(1u64), &manifest, &BTreeMap::new())
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("returned 1 field(s), not 3"),
            "{err}"
        );
        let plain = BTreeMap::from([("direction".to_string(), Fr::from(13u64))]);
        let err = reader
            .pinned_values(snap, Fr::from(1u64), &manifest, &plain)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("one storage slot does not hold"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn the_logs_are_paged_past_twenty_per_tag() {
        let ns = Fr::from(0x1111u64);
        let chain = std::sync::Arc::new(MemoryChain::new(40));
        let id = Fr::from(0xa1u64);
        // 25 logs under the request tag and 25 under the sealed tag: the
        // request log taken is the earliest, the sealed one the latest, which
        // sits on the second page
        for i in 0..25u64 {
            chain.push_log(
                ns,
                10 + i,
                request_log_tag(id),
                &[Fr::from(i), Fr::from(0x77u64)],
            );
            chain.push_log(
                ns,
                10 + i,
                crate::state::chain::sealed_log_tag(id),
                &[Fr::from(100 + i)],
            );
        }
        let reader = ChainReader::new(chain.clone());
        let snap = reader.snapshot().await.unwrap();
        let logs = reader.logs(snap, ns, request_log_tag(id)).await.unwrap();
        assert_eq!(logs.len(), 25);
        assert!(logs.windows(2).all(|w| w[0].1.block < w[1].1.block));
        assert_eq!(chain.node().calls("node_getPublicLogsByTags"), 2);
        let request = request_inputs(&reader, snap, ns, id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!((request.log.block, request.fields[0]), (10, Fr::from(0u64)));
        let tag = crate::state::chain::sealed_log_tag(id);
        let logs = reader.logs(snap, ns, tag).await.unwrap();
        let sealed = crate::SealedState::latest(id, logs).unwrap();
        assert_eq!((sealed.log.block, sealed.fields[0]), (34, Fr::from(124u64)));
        // every page names the snapshot's block hash
        let query = chain.node().last_query("node_getPublicLogsByTags").unwrap();
        assert_eq!(
            query["referenceBlock"],
            json!(fr_to_hex(chain.node().hash(40)))
        );
        assert!(query["tags"][0]["afterLog"].is_object(), "{query}");
    }

    #[tokio::test]
    async fn a_replaced_block_is_a_prune_and_its_request_log_is_read_again() {
        let ns = Fr::from(0x1111u64);
        let id = Fr::from(0xa1u64);
        let chain = std::sync::Arc::new(MemoryChain::new(20));
        let reader = ChainReader::new(chain.clone());
        reader.snapshot().await.unwrap();
        chain.set_tip(21);
        chain.push_log(
            ns,
            21,
            request_log_tag(id),
            &[Fr::from(1u64), Fr::from(2u64)],
        );
        let snap = reader.snapshot().await.unwrap();
        let first = request_inputs(&reader, snap, ns, id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(first.fields, [1u64, 2].map(Fr::from));
        // block 21 is replaced by one whose intake carries another nonce,
        // between the snapshot and a read: the read's reference block is gone
        chain.node().replace_from(21);
        chain.push_log(
            ns,
            21,
            request_log_tag(id),
            &[Fr::from(1u64), Fr::from(3u64)],
        );
        assert_eq!(
            request_inputs(&reader, snap, ns, id).await,
            Err(ReadError::ReferenceGone { block: 21 })
        );
        // the next snapshot is the prune, the one after reads the replacement
        assert!(matches!(
            reader.snapshot().await,
            Err(ReadError::Pruned(Prune {
                from: 21,
                to: 20,
                below_kept: false
            }))
        ));
        let snap = reader.snapshot().await.unwrap();
        let again = request_inputs(&reader, snap, ns, id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(again.fields, [1u64, 3].map(Fr::from));
        // a snapshot made by hand is anchored at the node's hash of its block
        let fresh = ChainReader::new(chain.clone());
        let by_hand = request_inputs(&fresh, Snapshot::at(21), ns, id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(by_hand, again);
        assert_eq!(
            request_inputs(&fresh, Snapshot::at(22), ns, id).await,
            Err(ReadError::ReferenceGone { block: 22 })
        );
        // as of block 20 the request log had not landed
        assert_eq!(
            request_inputs(&reader, Snapshot::at(20), ns, id)
                .await
                .unwrap(),
            None
        );
    }

    #[tokio::test]
    async fn malformed_answers_are_refused() {
        let ns = Fr::from(7u64);
        let chain = MemoryChain::new(3);
        // head past tail
        chain.set_storage(ns, Fr::from(5u64), Fr::from(1u64));
        chain.set_storage(ns, Fr::from(6u64), Fr::from(2u64));
        let reader = ChainReader::new(chain);
        let snap = reader.snapshot().await.unwrap();
        assert!(matches!(
            reader.queue(snap, &target(ns)).await,
            Err(ReadError::Malformed { .. })
        ));
        // a tail that is not a u64
        let chain = MemoryChain::new(3);
        chain.set_storage(
            ns,
            Fr::from(5u64),
            f("0x0100000000000000000000000000000000000000000000000000000000000000"),
        );
        let reader = ChainReader::new(chain);
        let snap = reader.snapshot().await.unwrap();
        assert!(matches!(
            reader.queue(snap, &target(ns)).await,
            Err(ReadError::Malformed { .. })
        ));
        // a request log too short for the non-secret-shared layout: no nonce
        let short = RequestInputs {
            chain_request_id: Fr::from(1u64),
            fields: vec![],
            log: LogRef {
                block: 1,
                tx_hash: String::new(),
                tx_index: 0,
                log_index: 0,
            },
        };
        assert!(short.plain().is_err());
        // a key that is not a slot
        let manifest = manifest_with_reads("[]");
        let err = commitment_slots(
            &manifest,
            &StateKeys {
                reads: vec!["pool".into()],
                writes: vec![],
            },
        )
        .unwrap_err();
        assert!(matches!(err, ReadError::BadKey { .. }));
        let err = commitment_slots(&manifest, &StateKeys::default()).unwrap_err();
        assert!(matches!(err, ReadError::BadKey { .. }));
    }

    // A poll holds the follower across its calls to the node; the gauges
    // (the status endpoint's, the retention floor) read the last poll's
    // values without waiting on one in flight.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_gauges_do_not_wait_on_a_poll_in_flight() {
        struct Slow {
            chain: MemoryChain,
            stall: std::sync::atomic::AtomicBool,
        }
        impl Transport for Slow {
            async fn call(&self, method: &str, params: Value) -> Result<Value, RpcError> {
                if self.stall.load(std::sync::atomic::Ordering::SeqCst) {
                    tokio::time::sleep(Duration::from_secs(30)).await;
                }
                self.chain.call(method, params).await
            }
        }
        let slow = std::sync::Arc::new(Slow {
            chain: MemoryChain::new(50),
            stall: std::sync::atomic::AtomicBool::new(false),
        });
        slow.chain.node().set_proven(20);
        let reader = std::sync::Arc::new(ChainReader::new(slow.clone()));
        reader.snapshot().await.unwrap();
        slow.chain.node().set_proven(30);
        reader.snapshot().await.unwrap();
        slow.stall.store(true, std::sync::atomic::Ordering::SeqCst);
        let polling = reader.clone();
        let stalled = tokio::spawn(async move { polling.snapshot().await });
        tokio::time::sleep(Duration::from_millis(50)).await;
        let quick = Duration::from_secs(1);
        let held = tokio::time::timeout(quick, reader.held()).await.unwrap();
        assert_eq!(
            (held.tip, held.proven, held.finalized, held.settled),
            (50, 30, 20, 20)
        );
        assert_eq!(tokio::time::timeout(quick, reader.settled()).await, Ok(20));
        stalled.abort();
    }
}
