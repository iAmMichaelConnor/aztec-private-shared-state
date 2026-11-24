//! The request queue: ordinary public storage that serialises a namespace's
//! requests on chain (docs/ARCHITECTURE.md section 6, rows "intake" and
//! "relayer").
//!
//! An app contract declares one `Queue` in its `#[storage]` struct and one
//! `CommitmentSlot` per key its manifests' `commitment_slot` names, and
//! writes thin wrappers around the library's bodies:
//!
//! ```noir
//! #[storage]
//! struct Storage<Context> {
//!     config: PublicImmutable<Config, Context>,             // the constructor's pins
//!     configured: PublicImmutable<Configured<P>, Context>,  // configure's
//!     queue: Queue<Context>,
//!     pool: CommitmentSlot<Context>,
//! }
//!
//! #[external("public")]
//! #[only_self]
//! fn append(request_id: Field) {
//!     let _ = self.storage.queue.append(request_id);
//! }
//!
//! #[external("public")]
//! fn skip() {
//!     let stale_blocks = self.storage.configured.read().config().stale_blocks;
//!     let _ = self.storage.queue.skip(stale_blocks);
//! }
//! ```
//!
//! The intake functions add their mode's part around `append` (the request
//! log under on-chain intake, the expiry check under receipt intake); `apply` checks the head and
//! the slots and ends with `finish_head(head, DONE_APPLIED)`. Every public
//! half of a request refuses first before `configure` and while the state
//! key is uninitialised (`assert_ready`); the public half of a receipt
//! request that does nothing more is one call, `append_receipt`:
//!
//! ```noir
//! #[external("public")]
//! #[only_self]
//! fn append_receipt(request_id: Field, expiry_block: u32) {
//!     let _ = self.storage.queue.append_receipt(self.storage.configured, self.storage.pool, request_id, expiry_block);
//! }
//! ```
//!
//! One queue per namespace. Entries below the head are finished;
//! nothing is ever deleted, so `requests`, `seen` and `done` stay readable
//! for every index ever used.
use crate::config::StaleBlocks;
use crate::configure::{assert_configured_in_public, Configured};
use aztec::context::{PublicContext, UtilityContext};
use aztec::protocol::traits::{Deserialize, Packable, Serialize};
use aztec::state_vars::{Map, PublicImmutable, PublicMutable, StateVariable};

/// The `done[index]` codes, read by the relayer and clients
/// to tell an apply from a skip: 0 = not finished (the storage default),
/// 1 = applied (by `apply`, `ok` true or false), 2 = skipped (by `skip()`).
/// They are part of the interface with pss-client and pss-relayer;
/// testvectors/queue.json holds them, with the queue's slots.
pub global DONE_PENDING: u8 = 0;
pub global DONE_APPLIED: u8 = 1;
pub global DONE_SKIPPED: u8 = 2;

/// The head of the queue and its clock, stored as one value so `apply` and
/// `skip()` move both in one write.
#[derive(Deserialize, Eq, Packable, Serialize)]
pub struct Head {
    /// the index of the request to process next; `head.index == tail` is
    /// an empty queue
    pub index: u64,
    /// `head_since`: the block at which the head last moved, or at which
    /// `append` wrote into an empty queue
    pub since: u32,
}

/// A slot holding the current commitment (note hash) of one chain-held
/// key: written by `apply` only, read by the chain reader and checked
/// against the circuit's old commitment.
pub type CommitmentSlot<Context> = PublicMutable<Field, Context>;

/// Whether `slot` holds a commitment: the key's init round has landed.
///
/// Intake refuses while the key is uninitialised: the app's intake
/// wrappers assert this of the key they queue requests for
/// (`assert_initialised`, one public read per request). A request
/// queued before the init round lands has no state to run against: the
/// network cannot serve it, it would block the queue for `stale_blocks` and
/// then be skipped for nothing. Allowing it costs nothing on chain but hands
/// users a request that can only be skipped.
pub fn initialised(slot: CommitmentSlot<PublicContext>) -> bool {
    slot.read() != 0
}

/// Refuse while the key at `slot` is uninitialised ("state not
/// initialised"; `initialised`).
pub fn assert_initialised(slot: CommitmentSlot<PublicContext>) {
    assert(initialised(slot), "state not initialised");
}

/// What every public half of a request checks first, whatever its intake:
/// the contract is configured (`assert_configured_in_public`, "not
/// configured") and the key at `state` is initialised
/// (`assert_initialised`). An app whose requests queue for several keys
/// calls `assert_initialised` for each of the others.
pub fn assert_ready<let P: u32>(
    context: PublicContext,
    configured: PublicImmutable<Configured<P>, PublicContext>,
    state: CommitmentSlot<PublicContext>,
) {
    assert_configured_in_public(context, configured);
    assert_initialised(state);
}

/// The queue's storage: `requests[index] = request_id`, `tail` (the next
/// free index), `head` ({index, since}), `seen[request_id]` and
/// `done[index]`.
///
/// Storage layout, from the slot the app's `#[storage]` gives the queue
/// (the chain reader and the relayer derive slots from it): +0 `requests`
/// (a map), +1 `tail`, +2 and +3 `head` (index, since), +4 `seen` (a map),
/// +5 `done` (a map). Six slots in all. The layout is the interface with
/// sidecar-tip's `QueueLayout` and the operator's `queue_slot`, so it has one
/// right answer: a change here is a change there, or the chain reader reads
/// the wrong slots.
pub struct Queue<Context> {
    pub(crate) context: Context,
    pub requests: Map<u64, PublicMutable<Field, Context>, Context>,
    pub tail: PublicMutable<u64, Context>,
    pub head: PublicMutable<Head, Context>,
    pub seen: Map<Field, PublicMutable<bool, Context>, Context>,
    pub done: Map<u64, PublicMutable<u8, Context>, Context>,
}

impl<Context> StateVariable<6, Context> for Queue<Context> {
    fn new(context: Context, storage_slot: Field) -> Self {
        Queue {
            context,
            requests: Map::new(context, storage_slot),
            tail: PublicMutable::new(context, storage_slot + 1),
            head: PublicMutable::new(context, storage_slot + 2),
            seen: Map::new(context, storage_slot + 4),
            done: Map::new(context, storage_slot + 5),
        }
    }

    fn get_storage_slot(self) -> Field {
        self.requests.get_storage_slot()
    }
}

impl Queue<PublicContext> {
    /// The body of the app's `append`: enqueue `request_id` at the tail and
    /// return its index. Reverts on a request id the queue has seen, in
    /// both intake modes (under receipt intake this makes a receipt single-use), so
    /// results stay keyed by (namespace, request id) everywhere. Writing
    /// into an empty queue restarts the head clock, so a request that
    /// arrives after a quiet period gets its full stale period.
    ///
    /// The app's wrapper is `#[external("public")]` and
    /// `#[only_self]`, enqueued by the app's own private intake function
    /// after it has computed the request id and checked the inputs; a
    /// wrapper without `#[only_self]` lets anyone push an unchecked id.
    pub fn append(self, request_id: Field) -> u64 {
        let seen = self.seen.at(request_id);
        assert(!seen.read(), "duplicate request");
        seen.write(true);

        let tail = self.tail.read();
        let head = self.head.read();
        if head.index == tail {
            self.head.write(Head { index: head.index, since: self.context.block_number() });
        }
        self.requests.at(tail).write(request_id);
        self.tail.write(tail + 1);
        tail
    }

    /// The body of the app's receipt intake `append_receipt` wrapper
    /// (`#[external("public")]`, `#[only_self]`): assert the current block
    /// is below `expiry_block`, then `append(request_id)`. A receipt is
    /// accepted in blocks up to `expiry_block - 1` and refused from
    /// `expiry_block` on; the seen flag makes it single-use. Two writes
    /// besides the seen flag (`requests[tail]`, `tail`; `head` too when the
    /// queue was empty) and no log.
    pub fn append_before(self, request_id: Field, expiry_block: u32) -> u64 {
        assert(self.context.block_number() < expiry_block, "receipt expired");
        self.append(request_id)
    }

    /// The whole body of a receipt intake's `append_receipt` wrapper (either
    /// receipt intake, `#[external("public")]`, `#[only_self]`) for an app
    /// whose public half does nothing more: `assert_ready` over the
    /// configured pins and the key the request queues for, then
    /// `append_before`. Returns the request's index, for an app that records
    /// something beside it (refund notes); the long form stays open to an
    /// app that checks more first.
    pub fn append_receipt<let P: u32>(
        self,
        configured: PublicImmutable<Configured<P>, PublicContext>,
        state: CommitmentSlot<PublicContext>,
        request_id: Field,
        expiry_block: u32,
    ) -> u64 {
        assert_ready(self.context, configured, state);
        self.append_before(request_id, expiry_block)
    }

    /// The body of the app's `skip()`: once the head has sat
    /// `stale_blocks` blocks, drop it and return its index. Sets the head
    /// to {index + 1, the current block} and `done[index]` to
    /// `DONE_SKIPPED`; the commitment slots and the state do not change.
    /// Reverts when skipping is disabled, when the queue is empty (without
    /// that guard an empty queue's old clock would let anyone advance the
    /// head past requests not yet made), and before the period has passed:
    /// skipping is allowed from block `head_since + stale_blocks` on.
    ///
    /// It reads the head itself and makes no external call, so `apply`'s
    /// ordering rule (every external call before its first storage read)
    /// is enough to stop a re-entrant `skip()` from interleaving with an
    /// apply.
    ///
    /// DEV DECISION: who may call `skip()`, default anyone (normally the
    /// operator's relayer once the head is stale); an app that restricts its
    /// wrapper to the relayer makes the relayer a liveness dependency of its
    /// queue. Design guide: "access control".
    ///
    /// In an app that takes a usage deposit, each request pays a pinned
    /// amount in its private function and commits a refund note for the
    /// sender. The public wrapper records it beside the queue entry, with
    /// any escrow refund (`token::Refunds`). The deposit prices queue access
    /// for a hidden requester (docs/DECISIONS.md section 12).
    /// This function drops the head and records `done[index] = DONE_SKIPPED`.
    /// It emits no log.
    /// When the stale period is enabled and the app's skip wrapper calls
    /// `token::refund_skipped`, the wrapper returns any escrow and usage
    /// deposit without a round. For a landed round, the public apply wrapper
    /// settles the refund notes. The app chooses whether a served round
    /// keeps the deposit. Keeping a deposit on skip is forbidden
    /// (invariant 0). See docs/ARCHITECTURE.md section 6, "The refund rule".
    /// A declared maximum gas cost is not a payment, so checking it
    /// does not price queue access.
    pub fn skip(self, stale_blocks: StaleBlocks) -> u64 {
        assert(stale_blocks.enabled, "skip is disabled");
        let head = self.head.read();
        assert(head.index < self.tail.read(), "queue is empty");
        // `since` is a block at or before the current one, so this cannot
        // underflow, and unlike `since + blocks` it cannot overflow
        let waited = self.context.block_number() - head.since;
        assert(waited >= stale_blocks.blocks, "head is not stale");
        self.finish_head(head, DONE_SKIPPED)
    }

    /// Finish the head request: set the head to {index + 1, the current
    /// block} and `done[index]` to `status` (`DONE_APPLIED` or
    /// `DONE_SKIPPED`), and return the finished index. For `apply` and
    /// `skip()`; `head` is the value the caller read and checked in the
    /// same call.
    pub fn finish_head(self, head: Head, status: u8) -> u64 {
        self.head.write(Head { index: head.index + 1, since: self.context.block_number() });
        self.done.at(head.index).write(status);
        head.index
    }

    pub fn get_head(self) -> Head {
        self.head.read()
    }

    pub fn get_tail(self) -> u64 {
        self.tail.read()
    }

    pub fn request_at(self, index: u64) -> Field {
        self.requests.at(index).read()
    }

    pub fn is_seen(self, request_id: Field) -> bool {
        self.seen.at(request_id).read()
    }

    pub fn done_at(self, index: u64) -> u8 {
        self.done.at(index).read()
    }
}

/// The same reads from a utility function, for clients that poll the
/// queue through simulation rather than raw storage reads.
impl Queue<UtilityContext> {
    pub unconstrained fn get_head(self) -> Head {
        self.head.read()
    }

    pub unconstrained fn get_tail(self) -> u64 {
        self.tail.read()
    }

    pub unconstrained fn request_at(self, index: u64) -> Field {
        self.requests.at(index).read()
    }

    pub unconstrained fn is_seen(self, request_id: Field) -> bool {
        self.seen.at(request_id).read()
    }

    pub unconstrained fn done_at(self, index: u64) -> u8 {
        self.done.at(index).read()
    }
}
