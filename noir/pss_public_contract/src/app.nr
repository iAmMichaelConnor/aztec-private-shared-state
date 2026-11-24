//! The app skeleton: what every tip app contract shares, so that an app
//! writes only its round table, its pins, its validity checks and its
//! outcome fields, and each of its `#[external]` functions is one call into
//! this library.
//!
//! The deployment comes first (`crate::configure`): the constructor stores
//! the app's Config with the library's `TipPins` (the stale period, the
//! node `sig` keys, the circuit pins), and the once-only `configure` checks
//! the nodes' REGISTER answer and stores `Configured`, which every other
//! function reads and which asserts `configured`.
//!
//! The round table is the app's function from its `Configured` and its
//! commitment slots to one `TipRound` per circuit (`Configured::round`, by
//! the package's name hash): the vk pin and the keys the circuit reads and
//! writes. Every generic entry point takes a `TipRound`:
//!
//! - intake: `intake::onchain_request`, `receipt::receipt_request` and
//!   `shared_intake::shared_receipt_request` take the row with the app's
//!   inputs and validity check; both non-secret-shared intakes queue a round's requests
//!   under the same row (one compiled circuit per round serves both);
//! - process: `result::check_round(round, context, scope, result, sealed,
//!   signatures)`, one per row whichever intake queued the request (the
//!   proof outputs the request id);
//! - apply: `result::apply_round(context, queue, pinned, keys, landed,
//!   sealed)`, after which the app's hook stores its outcome;
//! - the init round: `init::process_init(round, ...)` and
//!   `init::apply_init(context, keys, ...)`.
//!
//! The public halves take the row's keys alone, which the app builds from
//! its slots with the same function its round table uses (lending's
//! `market_state_keys`): they need no pin, so they read nothing of `Configured`.
//!
//! The app picks each brick by naming its implementation: the outputs by
//! the result type it hands `check_round` (`TipResult`, `PartialResult`, or
//! `outcome::Private`), the state mode by `sealed` (`NodeHeld {}`, or its
//! `chain_state` thirds), the node keys by its rows' last type parameter
//! (`key_epoch::KeyEpochs` or `signing_keys::FixedKeys`, `crate::signing_keys`).
//!
//! examples/amm-tip and examples/lending-tip are built on it:
//!
//! ```noir
//! // the app's round table (app.nr): one row per package name, each a
//! // TipRound<C, R, W, Keys>
//! pub fn rounds<C>(tip: Configured<PACKAGES>, pool: CommitmentSlot<C>) -> Rounds<C> {
//!     Rounds { swap: tip.round(AMM_SWAP_TIP_PACKAGE, StateKeys::one(pool)), ... }
//! }
//!
//! #[external("private")]
//! fn process_result(round: SwapResult, signatures: [ResultSignature; 3]) {
//!     let checked = check_round(rounds(self.storage.configured.read(), self.storage.pool).swap,
//!         self.context, self.msg_sender(), round, NodeHeld {}, signatures);
//!     self.enqueue_self.apply(checked);
//! }
//! ```
//!
//! An Aztec entry point cannot be generic, so each round keeps its own thin
//! `#[external]` wrappers; what differs between them is data (the table
//! row, the inputs, the result type), never a code path. Nor can a comptime
//! macro add one: aztec-nr's `#[aztec]` and `#[external]` rewrite a function
//! body before it is resolved, and a function a macro inserts into the
//! contract is resolved as it is inserted ("cannot find `self` in this
//! scope", and `#[aztec]` then fails with "Function already resolved"), so
//! the views and `skip()` stay written out in each app too.
//!
//! The app's reads that take no argument are one view (`view::TipState`).
use crate::config::TipConfig;
use crate::queue::CommitmentSlot;

/// The state keys a round reads and writes, as their commitment slots, each
/// list in its manifest's `$state_keys.reads` and `$state_keys.writes` order.
/// The library derives the key ids the proof is checked over from the slots
/// (key = storage slot), so a key and its slot cannot disagree; `check_round`
/// and `apply_round` must be given the same keys in the same order.
pub struct StateKeys<C, let R: u32, let W: u32> {
    pub reads: [CommitmentSlot<C>; R],
    pub writes: [CommitmentSlot<C>; W],
}

impl<C> StateKeys<C, 1, 1> {
    /// A round that reads and writes one key, `slot`.
    pub fn one(slot: CommitmentSlot<C>) -> Self {
        StateKeys { reads: [slot], writes: [slot] }
    }
}

impl<C, let W: u32> StateKeys<C, 0, W> {
    /// A round that reads no key and creates `writes` (the init round).
    pub fn create(writes: [CommitmentSlot<C>; W]) -> Self {
        StateKeys { reads: [], writes }
    }
}

/// One row of an app's round table: a circuit's pinned vk hash, the app's
/// TipConfig and the state keys the circuit reads and writes. `K` is the app's
/// `node_keys` brick (`crate::signing_keys::SigningKeys`: `KeyEpochs` or
/// `FixedKeys`), which every entry point that takes the row checks the node
/// signatures under; a type only, no field, so the app names it once in its
/// rows' types and `Configured::round` infers it.
///
/// Built by `Configured::round` from the app's stored `Configured`, never
/// from a caller's argument (`TipConfig`; `check_round`'s vk pin): the vk
/// hash of the package the row names, 0 when the deployment does not list
/// it, which every entry point refuses (`configure::assert_deployed`).
pub struct TipRound<C, let R: u32, let W: u32, K> {
    pub vk_hash: Field,
    pub tip: TipConfig,
    pub state_keys: StateKeys<C, R, W>,
}

impl<C, K> TipRound<C, 1, 1, K> {
    /// A round over one key, read and written.
    pub fn one(vk_hash: Field, tip: TipConfig, slot: CommitmentSlot<C>) -> Self {
        TipRound { vk_hash, tip, state_keys: StateKeys::one(slot) }
    }
}
