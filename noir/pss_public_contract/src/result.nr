//! The result transaction (docs/ARCHITECTURE.md section 6, rows "result",
//! "relayer" and "outputs"): private
//! `process_result` verifies one round's result, public `apply` lands it.
//!
//! An app contract writes thin wrappers around the two bodies here
//! (`check_round` in its `process_result`, `apply_round` in its `apply`),
//! as it does for `append` and `skip()`, over its round table's `TipRound`
//! (`crate::app`) for the vk pin and the keys (examples/amm-tip's
//! `process_result` and `apply`):
//!
//! ```noir
//! #[external("private")]
//! fn process_result(round: TipResult<1, 1, 0, 2>, signatures: [ResultSignature; 3]) {
//!     let checked = check_round(rounds(self.storage.configured.read(), self.storage.pool).swap,
//!         self.context, self.msg_sender(), round, NodeHeld {}, signatures);
//!     self.enqueue_self.apply(checked);
//! }
//!
//! #[external("public")]
//! #[only_self]
//! fn apply(round: TipResult<1, 1, 0, 2>) {
//!     let state_keys = rounds(self.storage.configured.read(), self.storage.pool).swap.state_keys;
//!     let applied = apply_round(self.context, self.storage.queue, no_pinned_reads(), state_keys,
//!         round, NodeHeld {});
//!     // the app hook: store or use applied.app_outputs (no external call here)
//! }
//! ```
//!
//! One `process_result` per row serves both non-secret-shared intakes: every round's
//! proof outputs the chain request id (`proved_public_inputs`), and
//! `apply`'s queue check binds it, whether on-chain intake's request log or
//! receipt intake's receipts queued the request.
//!
//! Two seams, one implementation per value, each chosen by the value the
//! app hands the two bodies:
//!
//! - the outputs (`Outputs` in private, `Lands` in public): public outputs,
//!   for the non-secret-shared intakes, as `TipResult` (`ok` and the app
//!   outputs, which `apply` hands the app hook; no delivery) or
//!   `PartialResult` (partial-note delivery: the round echoes the request's
//!   `$partial_note` as one more public output after `ok`, and `apply` lands
//!   `PartialResult::completing(storage_slot)`, which completes that note in
//!   public on every round, `crate::partial_note::complete_in_public`, so the
//!   value lands with the result in a note whose owner nobody but the user
//!   sees); or private outcomes, for the secret-shared intakes
//!   (`crate::outcome::Private` in private, `OutcomeApply` in public: the
//!   outcome note hashes and the outcome log, no `ok`). All share the vk
//!   pin, the result signatures and `apply`'s pinned reads, head and slot
//!   checks (`assert_lands_at_head`);
//! - the state mode (`Sealing`, the `sealed` argument): node-held state
//!   (`NodeHeld {}`: the nodes sign each result with no sealed thirds,
//!   `H(sealed_i)` = 0, and apply logs nothing), or the opt-in chain-held
//!   state (`crate::chain_state`'s `SealedThirds`, which each node's
//!   signature covers and apply logs).
//!
//! Anyone may submit a result; the operator's relayer does so by default.
//! Every check is an assertion, so a failure reverts the whole app-logic
//! phase and the queue and slots are unchanged.
use crate::app::{StateKeys, TipRound};
use crate::config::NODES;
use crate::configure::assert_deployed;
use crate::domains::RESULT_DOMAIN;
use crate::intake::{is_u128, is_u64};
use crate::signing_keys::SigningKeys;
use crate::partial_note::complete_in_public;
use crate::queue::{CommitmentSlot, DONE_APPLIED, Head, Queue};
use aztec::context::gas::GasOpts;
use aztec::context::{PrivateContext, PublicContext};
use aztec::protocol::abis::function_selector::FunctionSelector;
use aztec::protocol::address::AztecAddress;
use aztec::protocol::hash::poseidon2_hash;
use aztec::protocol::traits::{Deserialize, Serialize, ToField};
use aztec::state_vars::StateVariable;
use pss_contract::verify_pinned;
use std::embedded_curve_ops::{EmbeddedCurvePoint, EmbeddedCurveScalar};

/// One node's signature, Schnorr over Grumpkin (noir-lang/schnorr v0.4.0)
/// as four 128-bit limbs `[s.lo, s.hi, e.lo, e.hi]`: the wire's
/// `{s: [lo, hi], e: [lo, hi]}` in order, aztec.js `toLimbFields()`. Every
/// node signature the library checks (results, REGISTER answers, key
/// rotations, receipts through `Receipt::limbs`) is one, checked by
/// `result_signature_verifies`.
pub type ResultSignature = [Field; 4];

/// One round's result as `process_result` checks it and `apply` lands it:
/// R keys read, W keys written, Q pinned values (one per read, two per
/// epoch read), A app outputs.
///
/// The pinned values and the app outputs share one private array
/// (`new` builds it, `reads()` and `app_outputs()` split it), so that a
/// round without pinned reads still has a `TipResult` a contract function
/// can take: an entry point may not take an empty array. Q + A = 0 is
/// therefore no result an entry point can take; a round always outputs at
/// least its code (the first app output), so no round needs it. It
/// serialises as the fields in declaration order, so the split changes no
/// encoding.
///
/// What the result reveals: every field here is an argument
/// of the enqueued public call, so it is public in the transaction:
/// `request_id`, the old and new commitments (hiding: each commits to a
/// blinded vector), `ok` (one bit about the state: a failed swap says the
/// pool could not pay), the pinned values and the app outputs (and,
/// under chain-held state, the sealed thirds, ciphertext to the nodes' own
/// keys). An app whose outputs must stay private encrypts them to the user
/// inside the circuit and outputs the ciphertext (docs/ARCHITECTURE.md
/// section 6, "Private outcomes"). The app inputs and `user_nonce` are
/// no argument of the result transaction under either non-secret-shared intake (the
/// proof outputs the request id over them); on-chain intake's request log
/// published them already.
#[derive(Deserialize, Eq, Serialize)]
pub struct TipResult<let R: u32, let W: u32, let Q: u32, let A: u32> {
    /// the chain request id, as the queue holds it
    pub request_id: Field,
    /// the commitments the round read, one per read key (the manifest's
    /// `commitment_slot` old outputs), in `in_slots` order
    pub old_commitments: [Field; R],
    /// the commitments the round leaves, one per written key (the
    /// outputs' note hashes), in manifest order = `out_slots` order
    pub new_commitments: [Field; W],
    /// false: the round could not apply (a total circuit's no-op); the
    /// slots stay, the head still moves
    pub ok: bool,
    /// the pinned values the circuit used, in the manifest's
    /// `public_reads` order (each read's value, and an epoch read's epoch
    /// after it; the machine request id the nodes sign under covers them),
    /// then the app outputs
    values: [Field; Q + A],
}

impl<let R: u32, let W: u32, let Q: u32, let A: u32> TipResult<R, W, Q, A> {
    pub fn new(
        request_id: Field,
        old_commitments: [Field; R],
        new_commitments: [Field; W],
        ok: bool,
        reads: [Field; Q],
        app_outputs: [Field; A],
    ) -> Self {
        TipResult {
            request_id,
            old_commitments,
            new_commitments,
            ok,
            values: reads.concat(app_outputs),
        }
    }

    /// The pinned values, in the manifest's `public_reads` order.
    pub fn reads(self) -> [Field; Q] {
        let mut reads = [0; Q];
        for q in 0..Q {
            reads[q] = self.values[q];
        }
        reads
    }

    pub fn app_outputs(self) -> [Field; A] {
        let mut outputs = [0; A];
        for a in 0..A {
            outputs[a] = self.values[Q + a];
        }
        outputs
    }
}

/// One round's result under public outputs with partial-note delivery: the
/// result, and the request's partial note `P` (its `$partial_note`, a clear
/// input under the non-secret-shared intakes), which the round outputs
/// right after `ok` and `apply` completes in public with the app outputs
/// (`code` first) and the request id. Both halves take it; it serialises as
/// `P`, then the result's fields.
#[derive(Deserialize, Eq, Serialize)]
pub struct PartialResult<let R: u32, let W: u32, let Q: u32, let A: u32> {
    /// the request's partial note, the public output after `ok`
    pub partial_note: Field,
    pub result: TipResult<R, W, Q, A>,
}

/// What `apply_round` hands the app hook.
pub struct AppliedResult<let A: u32> {
    /// the queue index the result finished
    pub index: u64,
    pub request_id: Field,
    /// whether the new commitments were written: the public `ok` under
    /// public outputs, true under private outcomes
    pub ok: bool,
    pub app_outputs: [Field; A],
}

/// The L2 gas `apply` gives each pinned read's static call unless the app
/// sets another (`PinnedRead::l2_gas`): about ten times what a read of one
/// public storage value costs (a nested static call, the dispatch and one
/// storage read), and a small part of a transaction's L2 gas.
pub global DEFAULT_PINNED_READ_L2_GAS: u32 = 100000;

/// The DA gas each pinned read's static call is given. A static call writes
/// no state and emits nothing, so it needs none; it gets 32 fields' worth so
/// that a write inside it meets the AVM's static-call rule instead of
/// failing for DA gas first (the AVM charges a write's DA gas before it
/// checks the context), and an exceptional halt costs the submitter at most
/// this much DA gas.
pub global PINNED_READ_DA_GAS: u32 = 1024;

/// The freshness policies of a pinned read (`Freshness::policy`).
pub global FRESHNESS_EXACT: u8 = 0;
pub global FRESHNESS_EPOCH: u8 = 1;
pub global FRESHNESS_ABSOLUTE: u8 = 2;
pub global FRESHNESS_RELATIVE: u8 = 3;

/// How fresh a pinned read's value must be when `apply` lands the round:
/// the manifest's `public_reads[k].freshness` (with its `band`), the same
/// rule the scheduler and the nodes' chain verifiers apply.
///
/// - exact (`Freshness::exact()`, the manifest's default): the read returns
///   one field, equal to the circuit's value.
/// - epoch (`Freshness::epoch()`): the read returns three fields `[value,
///   epoch, previous]`, the source's current value, its epoch (a u64 counter
///   the source increments each time it publishes a value) and the value of
///   the epoch before; the circuit takes the value and its epoch (two pinned
///   values). `apply` accepts the current epoch at the current value, or the
///   epoch before it at the previous value; both epochs must be u64s, and
///   are compared as integers. The epoch source's window: the source offers
///   `previous` only for a bounded number of blocks after its epoch opens,
///   and from then on reports the current value in its place (so only the
///   current value lands, under either epoch). Whoever computes the round
///   chooses between the two values while both are offered, so a source
///   that keeps `previous` for ever lets that party land a round at a stale
///   value for as long as the source stays quiet; for a price, that is
///   funds mispriced (examples/lending-tip's oracle offers it for
///   `previous_blocks`, the market's stale period). The window lives in the
///   source because the read's three fields are the machine's interface
///   too (the scheduler and the nodes' chain verifiers apply this rule to
///   the same fields).
/// - tolerance (`Freshness::absolute(band)`, `Freshness::relative_bps(bps)`):
///   the read returns one field; the circuit's value and the returned one
///   are both u128s and differ by at most `band`, or by at most `bps`
///   basis points of the returned value.
///
/// The policy of each read, exact unless the app chooses another (design
/// guide: "freshness"). The app pins it with the read's target (a Config field or a constant; `PinnedRead`'s
/// "What to pin" says which suits which value) and writes the same policy
/// and band in the manifest; the two must agree, or the network computes at
/// one rule and `apply` checks another, and every result of the round
/// reverts (liveness only). Under a tolerance the round lands at a value up
/// to the band away from the one on chain, which the app's rule must allow.
#[derive(Deserialize, Eq, Serialize)]
pub struct Freshness {
    /// `FRESHNESS_EXACT`, `FRESHNESS_EPOCH`, `FRESHNESS_ABSOLUTE` or
    /// `FRESHNESS_RELATIVE`
    pub policy: u8,
    /// the absolute band (a u128) or the relative band in basis points
    /// (1 to 10,000); 0 for exact and epoch
    pub band: Field,
}

impl Freshness {
    pub fn exact() -> Self {
        Freshness { policy: FRESHNESS_EXACT, band: 0 }
    }

    pub fn epoch() -> Self {
        Freshness { policy: FRESHNESS_EPOCH, band: 0 }
    }

    /// Accept a value at most `band` away from the source's; `band` > 0.
    pub fn absolute(band: u128) -> Self {
        assert(band != 0, "an absolute band is positive");
        Freshness { policy: FRESHNESS_ABSOLUTE, band: band as Field }
    }

    /// Accept a value at most `bps` basis points of the source's value away
    /// from it; 1 <= `bps` <= 10,000.
    pub fn relative_bps(bps: u16) -> Self {
        assert((bps != 0) & (bps <= 10000), "a relative band is 1 to 10000 bps");
        Freshness { policy: FRESHNESS_RELATIVE, band: bps as Field }
    }

    /// How many pinned values the read contributes: 2 for an epoch read (the
    /// value, then its epoch), 1 otherwise.
    pub fn values(self) -> u32 {
        if self.policy == FRESHNESS_EPOCH {
            2
        } else {
            1
        }
    }

    /// Require the source's answer to accept the circuit's values: the read
    /// returned `returned_len` fields, the first of them (up to 3) in
    /// `returned`; the circuit used `value` and, for an epoch read, `epoch`.
    pub fn check(self, returned_len: u32, returned: [Field; 3], value: Field, epoch: Field) {
        if self.policy == FRESHNESS_EPOCH {
            assert(returned_len == 3, "pinned epoch read returns three fields");
            let (current, current_epoch, previous) = (returned[0], returned[1], returned[2]);
            assert(is_u64(epoch) & is_u64(current_epoch), "pinned epoch is not a u64");
            // both below 2^64, so `epoch + 1` cannot wrap: an integer comparison
            let at_current = epoch == current_epoch;
            let at_previous = epoch + 1 == current_epoch;
            assert(at_current | at_previous, "pinned epoch too old");
            let expected = if at_current { current } else { previous };
            assert(value == expected, "pinned read changed");
        } else {
            assert(returned_len == 1, "pinned read returns one field");
            let current = returned[0];
            if self.policy == FRESHNESS_EXACT {
                assert(value == current, "pinned read changed");
            } else {
                assert(
                    is_u128(value) & is_u128(current),
                    "pinned read is not a u128",
                );
                let diff = if value.lt(current) {
                    current - value
                } else {
                    value - current
                };
                // every product below 2^142, far below the field modulus
                let within = if self.policy == FRESHNESS_ABSOLUTE {
                    !self.band.lt(diff)
                } else {
                    assert(self.policy == FRESHNESS_RELATIVE, "unknown pinned read freshness");
                    !(self.band * current).lt(diff * 10000)
                };
                assert(within, "pinned read outside its band");
            }
        }
    }
}

/// A pinned public read: the manifest's `public_reads` entry `{contract,
/// function, args, freshness}`, re-made by `apply` as a nested static call
/// whose return fields must accept the values the circuit used under the
/// read's `Freshness`, under `l2_gas` and `PINNED_READ_DA_GAS`.
///
/// The target of each read is pinned by the app (a Config
/// field or a constant), never taken from the result or a caller: a
/// caller-chosen target returns whatever value the caller's proof used.
/// The call is static, so the callee cannot write state, emit a log or make
/// a non-static call; a re-entrant `skip()` from inside it reverts. All
/// reads of one app share the argument count N (an app with reads of
/// different arity makes the extra calls itself, before `apply_round`).
/// The function returns exactly one Field, or three for an epoch read.
///
/// What to pin. Each read's freshness policy is chosen per read. `apply`
/// lands only while every read accepts the values the round was computed
/// at, so whoever can move a pinned value can delay the head: each move the
/// policy refuses costs a recompute of the round, and a value that moves
/// faster than a round lands keeps the head waiting until anyone may
/// `skip()` it. Exact suits a value a trusted party moves rarely (an
/// owner-set parameter, a `DelayedPublicMutable`). Epoch suits a source
/// that publishes epochs (a price feed): the round stays valid while the
/// source opens at most one new epoch between the scheduler's read and
/// `apply` and still offers the previous value (its window, `Freshness`),
/// so a source whose epochs and window outlast a round never forces a
/// recompute. A tolerance suits a value whose small moves the app accepts:
/// the round lands at a value within the band of the one on chain. Never
/// pin a value anyone can move (a public AMM's spot price, a permissionless
/// setter) or one that depends on the block (a TWAP, a timestamp) under
/// exact, which never matches twice.
///
/// The read target is a liveness trust assumption of the queue: the target,
/// and whoever can upgrade its class or set its value, can make every
/// `apply` that reads it fail (a revert, an exceptional halt, a value the
/// policy refuses), and the head then waits for `skip()`. It can never make
/// a value the policy refuses land.
///
/// `l2_gas`, the gas bound of the read: default
/// `DEFAULT_PINNED_READ_L2_GAS` (100,000), set by `PinnedRead::new`. A call
/// the AVM halts exceptionally (a loop, a write in the static context, an
/// upgraded class that does either) consumes its whole allotment, so the
/// bound caps what a bad target costs whoever submits the result, where an
/// unbounded call would burn the transaction's whole L2 gas limit on every
/// attempt. Raise it for a read that costs more (several storage reads, a
/// nested call); too small a bound fails every result that reads it for
/// gas, a liveness failure and never a wrong value.
pub struct PinnedRead<let N: u32> {
    pub target: AztecAddress,
    pub selector: FunctionSelector,
    pub args: [Field; N],
    /// the L2 gas the static call is given
    pub l2_gas: u32,
    /// how fresh the returned value must be (`Freshness`)
    pub freshness: Freshness,
}

/// The pinned reads of a round that has none, typed for `apply_round`.
pub fn no_pinned_reads() -> [PinnedRead<0>; 0] {
    []
}

impl<let N: u32> PinnedRead<N> {
    /// An exact read of `selector(args)` on `target` with the default gas
    /// bound.
    pub fn new(target: AztecAddress, selector: FunctionSelector, args: [Field; N]) -> Self {
        PinnedRead {
            target,
            selector,
            args,
            l2_gas: DEFAULT_PINNED_READ_L2_GAS,
            freshness: Freshness::exact(),
        }
    }

    /// The same read under `freshness`.
    pub fn with_freshness(self, freshness: Freshness) -> Self {
        PinnedRead {
            target: self.target,
            selector: self.selector,
            args: self.args,
            l2_gas: self.l2_gas,
            freshness,
        }
    }
}

// ---------------------------------------------------------------------------
// The hashes (docs/ARCHITECTURE.md section 1)
// ---------------------------------------------------------------------------

/// The machine request id the nodes sign under, `poseidon2(PSS_ATTEMPT,
/// chain_request_id, old commitments…, pinned values…)` (docs/ARCHITECTURE.md
/// section 1): the round circuits' own function, which a round under private
/// outcomes outputs and derives its AEAD nonce from. sidecar-tip's
/// `machine_request_id` and pss-client's `machineRequestId` derive the same
/// id; a different layout refuses every result at the signature checks.
pub use pss_core::tip::outcome::machine_request_id;

/// The result message node `node` signs:
/// `poseidon2(RESULT_DOMAIN, namespace, request_id, new commitments…,
/// node, H(sealed_node))` (sidecar-core `pipeline::result_message`), with
/// `H(sealed_node)` = 0 under node-held state (`crate::chain_state` makes it
/// from the thirds under chain-held state).
pub fn result_message<let W: u32>(
    namespace: Field,
    request_id: Field,
    new_commitments: [Field; W],
    node: u32,
    sealed_hash: Field,
) -> Field {
    poseidon2_hash([RESULT_DOMAIN, namespace, request_id].concat(new_commitments).concat([
        node as Field,
        sealed_hash,
    ]))
}

/// The three nodes' result messages: node i's `result_message` with
/// `sealed_hashes[i]`.
pub fn result_messages<let W: u32>(
    namespace: Field,
    request_id: Field,
    new_commitments: [Field; W],
    sealed_hashes: [Field; NODES],
) -> [Field; NODES] {
    let mut messages = [0; NODES];
    for i in 0..NODES {
        messages[i] = result_message(namespace, request_id, new_commitments, i, sealed_hashes[i]);
    }
    messages
}

/// Whether `signature` is a valid Schnorr signature over `message` under
/// `key` (noir-lang/schnorr v0.4.0: a key off the curve, a zero `s` or `e`
/// and a wrong challenge all give false).
pub fn result_signature_verifies(
    key: EmbeddedCurvePoint,
    signature: ResultSignature,
    message: Field,
) -> bool {
    let s = EmbeddedCurveScalar::new(signature[0], signature[1]);
    let e = EmbeddedCurveScalar::new(signature[2], signature[3]);
    schnorr::verify_signature(key, (s, e), message)
}

/// Require the three result signatures: node i's over its own message
/// `messages[i]` (`result_messages`, with `sealed_hashes[i]` its
/// `H(sealed_i)`, every hash 0 under node-held state, `NodeHeld`) under
/// `keys[i]`. A missing signature (all zero), a
/// tampered one, one moved to another node's place, and a signature over any
/// other namespace, request id, commitment or third all fail here. One assertion per node, so the
/// refusal names the node (`NODES` is 3: the Rep3 network has three parties).
///
/// Cost, measured with bb 6.0.0 `gates` on nargo 1.0.0-rc.3 output: the three
/// Schnorr verifications alone are 98 ACIR opcodes, 6,630 gates as a private
/// function circuit (chonk; 6,927 as UltraHonk), about 2,200 each (a two-point
/// multi-scalar multiplication on Grumpkin, an on-curve check and one
/// Poseidon2 of five fields). With the machine request id, H(sealed_i) of one
/// five-field third per node and the three messages: 130 opcodes, 6,994 gates
/// (7,967 UltraHonk). The whole `process_result` of the library's test
/// contract (capsule, vk pin, binding, proof verification, signatures) is
/// 1,789 opcodes, 24,301 gates.
pub fn assert_result_signatures(
    keys: [EmbeddedCurvePoint; NODES],
    messages: [Field; NODES],
    signatures: [ResultSignature; NODES],
) {
    let mut verifies = [false; NODES];
    for i in 0..NODES {
        verifies[i] = result_signature_verifies(keys[i], signatures[i], messages[i]);
    }
    assert(verifies[0], "node 0's result signature does not verify");
    assert(verifies[1], "node 1's result signature does not verify");
    assert(verifies[2], "node 2's result signature does not verify");
}

/// `assert_result_signatures` under the keys the app's `node_keys` brick `K`
/// gives (`crate::signing_keys`): under key epochs the anchor's current
/// `sig` keys, or the previous epoch's for signatures made before a
/// rotation (`key_epoch::signing_keys`, which enqueues the public check of
/// that epoch's grace window); under a fixed key set `set0`. `set0` is the
/// stored `TipConfig::node_sig_keys`, the constructor's keys. Every private
/// function that checks result signatures (results, private outcomes, the
/// init round) calls this.
pub fn assert_epoch_signatures<K, let W: u32>(
    context: &mut PrivateContext,
    set0: [EmbeddedCurvePoint; NODES],
    namespace: Field,
    request_id: Field,
    new_commitments: [Field; W],
    sealed_hashes: [Field; NODES],
    signatures: [ResultSignature; NODES],
)
where
    K: SigningKeys,
{
    let messages = result_messages(namespace, request_id, new_commitments, sealed_hashes);
    let keys = K::signing_keys(context, set0, messages, signatures);
    assert_result_signatures(keys, messages, signatures);
}

// ---------------------------------------------------------------------------
// The state mode seam
// ---------------------------------------------------------------------------

/// What the state mode adds to the result path: each node's `H(sealed_i)`,
/// which its result signature covers, and what `apply` logs after its
/// writes. One implementation per state mode, the `sealed` argument of
/// `check_round`, `apply_round` and the init round's two bodies: `NodeHeld`
/// here, and `crate::chain_state`'s `SealedThirds`.
pub trait Sealing {
    /// `H(sealed_i)` of each node, node 0 first.
    fn sealed_hashes(self) -> [Field; NODES];
    /// What `apply` emits after its writes for the result of `request_id`
    /// with these new commitments (on `ok` and on not `ok`).
    fn log<let W: u32>(
        self,
        context: PublicContext,
        request_id: Field,
        new_commitments: [Field; W],
    );
}

/// Node-held state: the nodes keep the state and seal no thirds, so each
/// node's message ends in `H(sealed_i)` = 0, and `apply` logs nothing.
pub struct NodeHeld {}

impl Sealing for NodeHeld {
    fn sealed_hashes(self) -> [Field; NODES] {
        [0; NODES]
    }

    fn log<let W: u32>(
        self,
        _context: PublicContext,
        _request_id: Field,
        _new_commitments: [Field; W],
    ) {}
}

// ---------------------------------------------------------------------------
// The outputs seam
// ---------------------------------------------------------------------------

/// The request a result answers and the state transition it makes: R keys
/// read, W written, Q pinned values. Both halves of the outputs seam
/// (`Outputs`, `Lands`) read these.
pub trait Transition<let R: u32, let W: u32, let Q: u32> {
    /// the chain request id, as the queue holds it
    fn request_id(self) -> Field;
    /// the commitments the round read, in `in_slots` order
    fn old_commitments(self) -> [Field; R];
    /// the commitments the round leaves, in `out_slots` order
    fn new_commitments(self) -> [Field; W];
    /// the pinned values the circuit used, in the manifest's `public_reads`
    /// order
    fn reads(self) -> [Field; Q];
}

/// The outputs brick's private half, what `check_round` checks: one
/// implementation per value of the outputs axis. Public outputs are
/// `TipResult` (`ok` and the app outputs in the clear; the non-secret-shared
/// intakes) and `PartialResult` (the same, with the request's partial note
/// completed in public); private outcomes are `crate::outcome::Private`
/// (outcome note hashes and an outcome log, no `ok`; the secret-shared
/// intakes). The app picks one by the type it hands `check_round`.
pub trait Outputs<let R: u32, let W: u32, let Q: u32>: Transition<R, W, Q> {
    /// What the wrapper enqueues to its `apply`, a public argument.
    type Landed;
    /// The brick's check before the proof, over the row's key ids.
    fn admit(self, context: &mut PrivateContext, in_keys: [Field; R], out_keys: [Field; W]);
    /// Verify the co-SNARK under `vk_hash` over the brick's public-input
    /// layout, with the row's key ids, the Config's `npk_app_hash` and the
    /// machine request id the contract computed.
    fn verify(
        self,
        context: &mut PrivateContext,
        scope: AztecAddress,
        vk_hash: Field,
        in_keys: [Field; R],
        out_keys: [Field; W],
        npk_app_hash: Field,
        machine_id: Field,
    );
    /// What lands in private once the signatures verified; returns what the
    /// wrapper enqueues.
    fn land(self, context: &mut PrivateContext) -> Self::Landed;
}

/// The outputs brick's public half, what `apply_round` lands, with A app
/// outputs for the hook: `TipResult`, `PartialResult::completing` and
/// `crate::outcome::OutcomeApply` (no app output).
pub trait Lands<let R: u32, let W: u32, let Q: u32, let A: u32>: Transition<R, W, Q> {
    /// Whether the new commitments are written, `AppliedResult::ok`: the
    /// public `ok` under public outputs, always under private outcomes.
    fn writes(self) -> bool;
    /// The app outputs the hook takes (none under private outcomes).
    fn app_outputs(self) -> [Field; A];
    /// What runs after the effects and the state mode's log (nothing, or a
    /// partial note's completion).
    fn deliver(self, context: PublicContext, applied: AppliedResult<A>);
}

impl<let R: u32, let W: u32, let Q: u32, let A: u32> Transition<R, W, Q> for TipResult<R, W, Q, A> {
    fn request_id(self) -> Field {
        self.request_id
    }
    fn old_commitments(self) -> [Field; R] {
        self.old_commitments
    }
    fn new_commitments(self) -> [Field; W] {
        self.new_commitments
    }
    fn reads(self) -> [Field; Q] {
        TipResult::reads(self)
    }
}

/// Public outputs, no delivery: the proof over `proved_public_inputs`, a
/// failed round keeping its state, nothing landed in private, the new
/// commitments written on `ok`, and the app outputs for the hook.
impl<let R: u32, let W: u32, let Q: u32, let A: u32> Outputs<R, W, Q> for TipResult<R, W, Q, A> {
    type Landed = Self;

    fn admit(self, _context: &mut PrivateContext, in_keys: [Field; R], out_keys: [Field; W]) {
        assert_failed_round_keeps_its_state(
            in_keys,
            out_keys,
            self.old_commitments,
            self.new_commitments,
            self.ok,
        );
    }

    fn verify(
        self,
        context: &mut PrivateContext,
        scope: AztecAddress,
        vk_hash: Field,
        in_keys: [Field; R],
        out_keys: [Field; W],
        npk_app_hash: Field,
        _machine_id: Field,
    ) {
        verify_public(context, scope, vk_hash, in_keys, out_keys, npk_app_hash, self, []);
    }

    fn land(self, _context: &mut PrivateContext) -> Self {
        self
    }
}

impl<let R: u32, let W: u32, let Q: u32, let A: u32> Lands<R, W, Q, A> for TipResult<R, W, Q, A> {
    fn writes(self) -> bool {
        self.ok
    }

    fn app_outputs(self) -> [Field; A] {
        TipResult::app_outputs(self)
    }

    fn deliver(self, _context: PublicContext, _applied: AppliedResult<A>) {}
}

impl<let R: u32, let W: u32, let Q: u32, let A: u32> Transition<R, W, Q> for PartialResult<R, W, Q, A> {
    fn request_id(self) -> Field {
        self.result.request_id
    }
    fn old_commitments(self) -> [Field; R] {
        self.result.old_commitments
    }
    fn new_commitments(self) -> [Field; W] {
        self.result.new_commitments
    }
    fn reads(self) -> [Field; Q] {
        self.result.reads()
    }
}

/// Public outputs with partial-note delivery: `TipResult`'s checks, the
/// proof over `proved_public_inputs_with` with the partial note after `ok`.
/// Its `apply` lands `completing(storage_slot)`, never the result alone, so
/// the completion cannot be left out.
impl<let R: u32, let W: u32, let Q: u32, let A: u32> Outputs<R, W, Q> for PartialResult<R, W, Q, A> {
    type Landed = Self;

    fn admit(self, context: &mut PrivateContext, in_keys: [Field; R], out_keys: [Field; W]) {
        self.result.admit(context, in_keys, out_keys);
    }

    fn verify(
        self,
        context: &mut PrivateContext,
        scope: AztecAddress,
        vk_hash: Field,
        in_keys: [Field; R],
        out_keys: [Field; W],
        npk_app_hash: Field,
        _machine_id: Field,
    ) {
        verify_public(
            context,
            scope,
            vk_hash,
            in_keys,
            out_keys,
            npk_app_hash,
            self.result,
            [self.partial_note],
        );
    }

    fn land(self, _context: &mut PrivateContext) -> Self {
        self
    }
}

impl<let R: u32, let W: u32, let Q: u32, let A: u32> PartialResult<R, W, Q, A> {
    /// What `apply_round` lands for this result: its effects, then the
    /// completion of its partial note at the app's note `storage_slot`
    /// (`Completing`).
    pub fn completing(self, storage_slot: Field) -> Completing<R, W, Q, A> {
        Completing { result: self, storage_slot }
    }
}

/// A partial result as `apply_round` lands it: the same checks and effects
/// as its `TipResult`, then the completion of the result's partial note at
/// the app's note `storage_slot` (the slot of the app's note set, the same
/// constant the owner's PXE stores the note under) with the app outputs
/// (`code` first) and the request id (`crate::partial_note::complete_in_public`):
/// the completion log under the partial note's completion tag and the
/// completed note's hash. It runs on every round whatever `ok` is (a failed
/// round completes a note that says so), so every outcome has the same
/// public effects; the world sees the amount and `P`, never the owner. The
/// note packs `A + 1` fields, at most eight. An app that completes the note
/// with other fields lands `result.result` and completes it in its hook.
pub struct Completing<let R: u32, let W: u32, let Q: u32, let A: u32> {
    result: PartialResult<R, W, Q, A>,
    storage_slot: Field,
}

impl<let R: u32, let W: u32, let Q: u32, let A: u32> Transition<R, W, Q> for Completing<R, W, Q, A> {
    fn request_id(self) -> Field {
        self.result.request_id()
    }
    fn old_commitments(self) -> [Field; R] {
        self.result.old_commitments()
    }
    fn new_commitments(self) -> [Field; W] {
        self.result.new_commitments()
    }
    fn reads(self) -> [Field; Q] {
        self.result.result.reads()
    }
}

impl<let R: u32, let W: u32, let Q: u32, let A: u32> Lands<R, W, Q, A> for Completing<R, W, Q, A> {
    fn writes(self) -> bool {
        self.result.result.ok
    }

    fn app_outputs(self) -> [Field; A] {
        self.result.result.app_outputs()
    }

    fn deliver(self, context: PublicContext, applied: AppliedResult<A>) {
        complete_in_public(
            context,
            self.storage_slot,
            self.result.partial_note,
            applied.app_outputs,
            applied.request_id,
        );
    }
}

/// The proof of a round under public outputs, over `proved_public_inputs_with`
/// with `partial` (none, or the partial note) after `ok`.
fn verify_public<let R: u32, let W: u32, let Q: u32, let D: u32, let A: u32>(
    context: &mut PrivateContext,
    scope: AztecAddress,
    vk_hash: Field,
    in_keys: [Field; R],
    out_keys: [Field; W],
    npk_app_hash: Field,
    result: TipResult<R, W, Q, A>,
    partial: [Field; D],
) {
    let public_inputs = proved_public_inputs_with(
        context.this_address().to_field(),
        vk_hash,
        in_keys,
        out_keys,
        result.reads(),
        result.request_id,
        result.old_commitments,
        result.new_commitments,
        npk_app_hash,
        result.ok,
        partial,
        result.app_outputs(),
    );
    verify_proof(context, scope, vk_hash, public_inputs);
}

// ---------------------------------------------------------------------------
// The co-SNARK's public inputs
// ---------------------------------------------------------------------------

/// The public-input prefix every tip circuit opens with, non-secret-shared, private
/// outcome or init: `[namespace, vk_hash, in_slots[0..R], out_slots[0..W],
/// reads[0..Q], request_id]`, the pub parameters and the request id first in
/// the return value (an init round reads no key and no pinned value, R = Q =
/// 0). `proved_public_inputs`, `outcome::outcome_public_inputs` and
/// `init::init_public_inputs` continue it.
pub fn public_input_prefix<let R: u32, let W: u32, let Q: u32>(
    namespace: Field,
    vk_hash: Field,
    in_slots: [Field; R],
    out_slots: [Field; W],
    reads: [Field; Q],
    request_id: Field,
) -> [Field; 2 + R + W + Q + 1] {
    [namespace, vk_hash].concat(in_slots).concat(out_slots).concat(reads).concat([request_id])
}

/// The public-input array of a tip circuit, rebuilt from what the contract
/// holds; one layout for every round of both non-secret-shared intakes (the secret-shared
/// intakes' rounds output the request id too):
///
/// ```text
/// [namespace, vk_hash, in_slots[0..R], out_slots[0..W], reads[0..Q],
///  request_id, old_commitments[0..R], new_commitments[0..W], npk_app_hash,
///  ok, app_outputs[0..A]]
/// ```
///
/// ACIR orders public inputs as pub parameters in declaration order, then
/// the return value flattened in field order: the circuit declares
/// `namespace`, `vk_hash`, `in_slots`, `out_slots` and its pinned values
/// (one pub parameter per read, and an epoch read's epoch right after its
/// value), and returns the request id, the old commitments, the new
/// commitments, `npk_app_hash`, `ok` (a Field 0 or 1) and its app outputs,
/// in that order. The circuit takes the app inputs and `user_nonce` as
/// private witnesses and computes the chain request id over them
/// (`pss_core::tip::intake::plain`); it cannot know its own vk hash, so it
/// takes `vk_hash` as a public input, which this library sets to the
/// pinned one. examples/amm-tip's `amm_swap_tip` is this layout with
/// R = W = 1, Q = 0 and A = 2 (`code`, `amount_out`).
///
/// The layout: the note mode order
/// (`pss_contract::canonical_public_inputs`) with the tip's old commitments
/// in place of the read leaves and nullifiers: `vk_hash` right after
/// `namespace` (the two pub parameters the request id is built from), the
/// pinned values after the keys, `request_id` first in the return value
/// and `ok` before the app outputs. Every tip circuit and this function must
/// agree, or no proof verifies. What it reveals is what the result reveals
/// (see `TipResult`): the app inputs are no public input, so receipt intake
/// keeps them off the chain, and one compiled circuit per round serves both
/// non-secret-shared intakes.
///
/// Its limits: the pub parameters are exactly `namespace`, `vk_hash`
/// (filled by `$vk_hash`), `in_slots` (omitted when the round reads no
/// key), `out_slots` and the pinned values in the manifest's `public_reads`
/// order (one per read, two per epoch read), and nothing else; the app
/// inputs and `$user_nonce` are private. sidecar-core's
/// `abi::check_tip_public_prefix` checks a circuit's ABI against this
/// order: a circuit that breaks it registers, but no proof of it ever
/// verifies here and every request of it is skipped.
pub fn proved_public_inputs<let R: u32, let W: u32, let Q: u32, let A: u32>(
    namespace: Field,
    vk_hash: Field,
    in_slots: [Field; R],
    out_slots: [Field; W],
    reads: [Field; Q],
    request_id: Field,
    old_commitments: [Field; R],
    new_commitments: [Field; W],
    npk_app_hash: Field,
    ok: bool,
    app_outputs: [Field; A],
) -> [Field; 2 + R + W + Q + 1 + R + W + 2 + A] {
    proved_public_inputs_with(
        namespace,
        vk_hash,
        in_slots,
        out_slots,
        reads,
        request_id,
        old_commitments,
        new_commitments,
        npk_app_hash,
        ok,
        [],
        app_outputs,
    )
}

/// `proved_public_inputs` with `partial` (D fields, the request's partial
/// note under partial-note delivery, none otherwise) between `ok` and the
/// app outputs:
///
/// ```text
/// [namespace, vk_hash, in_slots[0..R], out_slots[0..W], reads[0..Q],
///  request_id, old_commitments[0..R], new_commitments[0..W], npk_app_hash,
///  ok, partial[0..D], app_outputs[0..A]]
/// ```
///
/// A round under partial-note delivery returns its `$partial_note` input
/// right after `ok`; sidecar-core's REGISTER checks the manifest names it so.
pub fn proved_public_inputs_with<let R: u32, let W: u32, let Q: u32, let D: u32, let A: u32>(
    namespace: Field,
    vk_hash: Field,
    in_slots: [Field; R],
    out_slots: [Field; W],
    reads: [Field; Q],
    request_id: Field,
    old_commitments: [Field; R],
    new_commitments: [Field; W],
    npk_app_hash: Field,
    ok: bool,
    partial: [Field; D],
    app_outputs: [Field; A],
) -> [Field; 2 + R + W + Q + 1 + R + W + 2 + D + A] {
    public_input_prefix(namespace, vk_hash, in_slots, out_slots, reads, request_id)
        .concat(old_commitments)
        .concat(new_commitments)
        .concat([npk_app_hash, ok as Field])
        .concat(partial)
        .concat(app_outputs)
}

// ---------------------------------------------------------------------------
// process_result (private)
// ---------------------------------------------------------------------------

/// Verify the co-SNARK over `public_inputs` under the pinned vk
/// (`pss_contract::verify_pinned`).
pub(crate) fn verify_proof<let N: u32>(
    context: &mut PrivateContext,
    scope: AztecAddress,
    expected_vk_hash: Field,
    public_inputs: [Field; N],
) {
    // The capsule slot: the (vk, proof) pair arrives at
    // `pss_contract::CAPSULE_SLOT_PROOF` (0x10) under the submitter's address
    // as scope, the slot every PSS call loads from; the relayer and
    // pss-client stage it there. A transaction verifies one result; one
    // that verified two (or a result and a note-mode round) would need a
    // slot per call.
    //
    // The vk-hash pin: `expected_vk_hash` names the one
    // circuit whose results this call accepts; pass a hash fixed at
    // deployment (the app's Config, beside its TipConfig), never a caller
    // argument, or any circuit's proof is accepted.
    verify_pinned(context, scope, expected_vk_hash, public_inputs);
}

/// The key ids of the slots a round reads or writes: each slot's storage
/// slot, the Aztec "key = storage slot" mapping that sidecar-tip's chain
/// reader reads the commitment by.
pub(crate) fn slot_keys<C, let K: u32>(slots: [CommitmentSlot<C>; K]) -> [Field; K] {
    slots.map(|slot: CommitmentSlot<C>| slot.get_storage_slot())
}

/// A failed round is a no-op on its state: when `ok` is false, every key the
/// round writes keeps the value its slot holds, checked by key whatever the
/// positions. A key the round reads keeps its commitment
/// (`new_commitments[w] == old_commitments[r]` wherever `out_keys[w] ==
/// in_keys[r]`); a key it writes without reading it (a create) keeps the
/// empty slot's value, 0 (`new_commitments[w] == 0`), and `apply` requires
/// that slot to be empty (the write rule, on `ok` and on not `ok`). The round
/// circuits' `pss_core::tip::slot::Loaded::finish` outputs exactly these.
///
/// This is the public-output path's rule. Under private outcomes
/// (`crate::outcome`) there is no `ok` to test: every round draws a fresh
/// blinding and every write lands, so a failed round keeps its state under a
/// new blinding.
///
/// `apply` writes nothing on `ok = false`, so every slot keeps its value.
/// Whoever follows the state from the results (the scheduler, and under
/// chain-held state the chain reader through the sealed-thirds log) takes a
/// result's new commitments whatever `ok` is. A failed round that named
/// another commitment, for a kept key or a created one, would leave the slot
/// and the result disagreeing, and the scheduler would compute the next
/// request over a commitment the slot does not hold.
pub fn assert_failed_round_keeps_its_state<let R: u32, let W: u32>(
    in_keys: [Field; R],
    out_keys: [Field; W],
    old_commitments: [Field; R],
    new_commitments: [Field; W],
    ok: bool,
) {
    if !ok {
        for w in 0..W {
            // the empty slot's value, unless the round read the key
            let mut kept = 0;
            for r in 0..R {
                if out_keys[w] == in_keys[r] {
                    kept = old_commitments[r];
                }
            }
            assert_eq(new_commitments[w], kept, "a failed round changes its state");
        }
    }
}

/// The body of the app's `process_result` for one row of its round table,
/// over the outputs brick `O` and the state mode `S`:
///
/// 1. pin the vk (`assert_deployed`) and run the brick's check before the
///    proof (`Outputs::admit`: a failed round keeps its state under public
///    outputs, the revertible phase under private outcomes);
/// 2. compute the machine request id from the request id, the old
///    commitments and the pinned reads, and verify the co-SNARK under the
///    row's pinned vk over the brick's public-input layout with the row's
///    keys and the Config's `npk_app_hash` (`Outputs::verify`);
/// 3. check the three result signatures under the machine request id, each
///    node's message ending in its `H(sealed_i)` from `sealed` (0 under
///    `NodeHeld`);
/// 4. land what the brick lands in private (`Outputs::land`: nothing under
///    public outputs; the outcome note hashes and the outcome log under
///    private outcomes) and return what the wrapper enqueues to its `apply`.
///
/// The proof's `request_id` output, over the private inputs and nonce under
/// the pinned vk hash, is the result's binding to its request: `apply`
/// compares it with the queue's head. So the result transaction carries no
/// app input, nonce or requester under any intake.
///
/// `scope` selects the capsule: the account that staged it, normally the
/// msg_sender. The wrapper's `apply` passes the same row's keys to
/// `apply_round`.
///
/// The namespace is the contract's own address, as intake and
/// the circuits' `PUBLIC $namespace` take it; a result of another
/// contract's namespace does not verify here.
///
/// The nodes signed the machine request id, so a result whose proof is for
/// one request and whose thirds are another's fails the signatures: the
/// thirds enter every message through `H(sealed_i)`, and the pinned values
/// through the machine request id.
pub fn check_round<C, O, S, K, let R: u32, let W: u32, let Q: u32>(
    round: TipRound<C, R, W, K>,
    context: &mut PrivateContext,
    scope: AztecAddress,
    result: O,
    sealed: S,
    signatures: [ResultSignature; NODES],
) -> <O as Outputs<R, W, Q>>::Landed
where
    O: Outputs<R, W, Q>,
    S: Sealing,
    K: SigningKeys,
{
    assert_deployed(round.vk_hash);
    let in_keys = slot_keys(round.state_keys.reads);
    let out_keys = slot_keys(round.state_keys.writes);
    result.admit(context, in_keys, out_keys);
    let machine_id =
        machine_request_id(result.request_id(), result.old_commitments(), result.reads());
    result.verify(
        context,
        scope,
        round.vk_hash,
        in_keys,
        out_keys,
        round.tip.npk_app_hash,
        machine_id,
    );
    assert_epoch_signatures::<K, W>(
        context,
        round.tip.node_sig_keys,
        context.this_address().to_field(),
        machine_id,
        result.new_commitments(),
        sealed.sealed_hashes(),
        signatures,
    );
    result.land(context)
}

// ---------------------------------------------------------------------------
// apply (public, #[only_self])
// ---------------------------------------------------------------------------

/// One pinned read's static call, with its gas bounds: how many fields it
/// returned and the first of them, up to three.
unconstrained fn static_call_fields<let N: u32>(
    context: PublicContext,
    read: PinnedRead<N>,
) -> (u32, [Field; 3]) {
    let returned = context.static_call_public_function(
        read.target,
        read.selector,
        read.args,
        GasOpts::new(read.l2_gas, PINNED_READ_DA_GAS),
    );
    let mut fields = [0; 3];
    for i in 0..3 {
        if i < returned.len() {
            fields[i] = returned[i];
        }
    }
    (returned.len(), fields)
}

/// Re-make each pinned read as a nested static call and require its return
/// fields to accept the values the circuit used under the read's
/// `Freshness` (`Freshness::check`). `values` holds the reads' values in
/// order, each read taking `Freshness::values()` of them (an epoch read its
/// value, then its epoch); together they take all Q.
pub fn assert_pinned_reads<let P: u32, let Q: u32, let N: u32>(
    context: PublicContext,
    pinned: [PinnedRead<N>; P],
    values: [Field; Q],
) {
    let mut offset = 0;
    for p in 0..P {
        let read = pinned[p];
        let width = read.freshness.values();
        assert(offset + width <= Q, "pinned values do not match the reads");
        // Safety: a public function is bytecode the AVM proves, and the
        // fields are the return data the AVM's static call produced.
        let (returned_len, returned) = unsafe { static_call_fields(context, read) };
        // the last of the read's values: its epoch, or the value itself
        read.freshness.check(returned_len, returned, values[offset], values[offset + width - 1]);
        offset += width;
    }
    assert(offset == Q, "pinned values do not match the reads");
}

/// The body of the app's `apply`, over what the wrapper's `process_result`
/// enqueued (`L`, the outputs brick's public half) and the state mode `S`,
/// in checks-effects-interactions order:
///
/// 1. every external call: each pinned read re-made as a static call
///    (`assert_pinned_reads`);
/// 2. the storage reads and checks: the queue is not empty, `requests[head]
///    == request_id`, each old commitment equals its slot, and each slot
///    written but not read is empty (the write rule below);
/// 3. the effects: the new commitments when `Lands::writes` (a public `ok`
///    under public outputs, none written when it is false, a no-op that
///    still moves the head; always under private outcomes), head = {index +
///    1, the current block} and `done[index] = DONE_APPLIED`
///    (`Queue::finish_head`); then the state mode's log (none under
///    `NodeHeld`, the sealed-thirds log under `SealedThirds`) and the
///    brick's delivery (`Lands::deliver`: a partial note completed in public
///    under `PartialResult::completing`).
///
/// No external call follows the first storage read, so a re-entrant
/// `skip()` cannot run between the head check and the head write. Returns
/// what the app hook needs (`AppliedResult`: under private outcomes `ok` is
/// true and there is no app output).
///
/// `state_keys` are the state keys of the round table row the wrapper's
/// `process_result` took (`row.state_keys`, from the same table): `check_round`
/// checked the proof over their storage slots as key ids, in that order.
///
/// The write rule. A slot the round writes but does not read must hold 0
/// (the round creates that key): the slot is the only copy of the
/// commitment of the state it holds, so overwriting a live slot the round
/// never loaded would make that state unreachable. This is the machine's
/// own store rule (a key is written only when it is empty or the request
/// loaded it), applied at the tip's only store writer; it refuses a
/// manifest or circuit that writes a key it does not read once the key
/// holds state. It holds on `ok` and on not `ok`: a failed round outputs 0
/// for a key it creates (`assert_failed_round_keeps_its_state`), the value
/// the slot must then hold.
///
/// The app hook: the app's wrapper runs its hook after this
/// call, with the returned value: it stores or uses the app
/// outputs as the app wishes (a balance the user redeems later, a value other
/// contracts read), on `ok` and on not `ok`. The library emits no outcome
/// event; `done[index]` is the one library-level write. The hook may read
/// and write the app's storage but must make no external call (a token
/// transfer, a call into another app): one would come after the queue's
/// writes, so a re-entrant call could observe the moved head and act on it
/// within this transaction. An app that must pay out through another
/// contract records the payout here and pays it in a later call. A public
/// log the hook emits (an event) shares the transaction's public-log payload
/// with the sealed-thirds log under chain-held state: Aztec v6 gives every public log of a
/// transaction, each behind a 2-field header (`PUBLIC_LOG_HEADER_LENGTH`), one
/// payload of `FLAT_PUBLIC_LOGS_PAYLOAD_LENGTH` = 4,096 fields, and REGISTER
/// lets the state log alone fill up to 4,094 of them, so an app that logs here
/// under chain-held state keeps its state under the bound by its own logs' length plus
/// 2 each, or its apply reverts on every attempt until the head is skipped.
/// The same holds for any other public log of the apply transaction (a fee
/// payer's).
///
/// The wrapper reads its Config (a `PublicImmutable`) before
/// this call to build `pinned`; immutable reads cannot change, so they may
/// precede the external calls. Every `PublicMutable` read comes after.
pub fn apply_round<L, S, let R: u32, let W: u32, let P: u32, let Q: u32, let A: u32, let N: u32>(
    context: PublicContext,
    queue: Queue<PublicContext>,
    pinned: [PinnedRead<N>; P],
    state_keys: StateKeys<PublicContext, R, W>,
    landed: L,
    sealed: S,
) -> AppliedResult<A>
where
    L: Lands<R, W, Q, A>,
    S: Sealing,
{
    // 1. interactions first, 2. reads and checks
    let head = assert_lands_at_head(
        context,
        queue,
        pinned,
        state_keys,
        landed.request_id(),
        landed.old_commitments(),
        landed.reads(),
    );

    // 3. effects
    let new_commitments = landed.new_commitments();
    if landed.writes() {
        for w in 0..W {
            state_keys.writes[w].write(new_commitments[w]);
        }
    }
    let index = queue.finish_head(head, DONE_APPLIED);
    sealed.log(context, landed.request_id(), new_commitments);
    let applied = AppliedResult {
        index,
        request_id: landed.request_id(),
        ok: landed.writes(),
        app_outputs: landed.app_outputs(),
    };
    landed.deliver(context, applied);
    applied
}

/// Steps 1 and 2 of `apply_round`, under either outputs brick: each pinned read
/// re-made as a static call (`assert_pinned_reads`), then the queue is not
/// empty, `requests[head] == request_id`, each old commitment equals its slot,
/// and each slot written but not read is empty (the write rule). Returns the
/// head for `Queue::finish_head`.
pub(crate) fn assert_lands_at_head<let R: u32, let W: u32, let P: u32, let Q: u32, let N: u32>(
    context: PublicContext,
    queue: Queue<PublicContext>,
    pinned: [PinnedRead<N>; P],
    state_keys: StateKeys<PublicContext, R, W>,
    request_id: Field,
    old_commitments: [Field; R],
    reads: [Field; Q],
) -> Head {
    let read_slots = state_keys.reads;
    let write_slots = state_keys.writes;
    // 1. interactions first
    assert_pinned_reads(context, pinned, reads);

    // 2. reads and checks
    let head = queue.get_head();
    assert(head.index < queue.get_tail(), "queue is empty");
    assert_eq(queue.request_at(head.index), request_id, "not the head");
    // The state binding, the manifest's `binding` (design guide: "binding"):
    // `turn`, the only value built. The round runs against whatever the
    // slots hold when its request reaches the head (the scheduler computes
    // it then), and this check refuses it only if the slots moved after
    // that. A user never binds a request to the state they saw when they
    // made it, so requests never fail for queueing behind one another; any
    // protection against a state that moved in between is the app's, in its
    // inputs and its circuit (an AMM swap's `min_out`, a limit price).
    // `exact`, a request run only against the old commitments its user
    // signed, is deferred and REGISTER refuses it; built, it would compare
    // each slot with the commitment the user's request carries instead of
    // the round's `old_commitments`, and fail the request when they differ.
    for r in 0..R {
        assert_eq(read_slots[r].read(), old_commitments[r], "state moved");
    }
    // the write rule: a slot written but not read is a create
    for w in 0..W {
        let key = write_slots[w].get_storage_slot();
        let mut read = false;
        for r in 0..R {
            read |= read_slots[r].get_storage_slot() == key;
        }
        if !read {
            assert_eq(write_slots[w].read(), 0, "write to a live key the round did not read");
        }
    }
    head
}

mod test {
    use crate::domains::RESULT_DOMAIN;
    use super::{
        assert_failed_round_keeps_its_state, Freshness, PartialResult,
        proved_public_inputs, proved_public_inputs_with, result_message, TipResult,
    };
    use aztec::protocol::hash::poseidon2_hash;
    use aztec::protocol::traits::{Deserialize, Serialize};
    use pss_core::test_support::ascii;

    // A failed round keeps every key it writes, matched by key id whatever
    // the positions: reads [B, A], writes [A, B, C] with C a create, whose
    // kept value is the empty slot's, 0.
    #[test]
    fn a_failed_round_keeps_its_state_by_key() {
        let (a, b, c) = (0xa, 0xb, 0xc);
        // ok: anything goes
        assert_failed_round_keeps_its_state(
            [b, a],
            [a, b, c],
            [0x1b, 0x1a],
            [0x2a, 0x2b, 0x2c],
            true,
        );
        // not ok: new[A] = old[A], new[B] = old[B], new[C] = 0
        assert_failed_round_keeps_its_state(
            [b, a],
            [a, b, c],
            [0x1b, 0x1a],
            [0x1a, 0x1b, 0],
            false,
        );
        // only a create: it outputs 0
        assert_failed_round_keeps_its_state([a], [c], [0x1a], [0], false);
    }

    // A failed round outputs 0 for a key it creates, never a commitment the
    // slot would not hold.
    #[test(should_fail_with = "a failed round changes its state")]
    fn a_failed_round_that_names_a_created_key_is_refused() {
        let (a, b, c) = (0xa, 0xb, 0xc);
        assert_failed_round_keeps_its_state(
            [b, a],
            [a, b, c],
            [0x1b, 0x1a],
            [0x1a, 0x1b, 0x2c],
            false,
        );
    }

    // The pinned reads and the app outputs split one array, which serialises
    // in declaration order: a result without pinned reads is the fields
    // [request_id, old…, new…, ok, outputs…].
    #[test]
    fn a_result_splits_its_values_and_serialises_in_order() {
        let r: TipResult<1, 2, 1, 2> =
            TipResult::new(0x1d, [0x0c], [0x1c, 0x2c], true, [0x7d0], [5, 6]);
        assert_eq(r.reads(), [0x7d0]);
        assert_eq(r.app_outputs(), [5, 6]);
        assert_eq(r.serialize(), [0x1d, 0x0c, 0x1c, 0x2c, 1, 0x7d0, 5, 6]);
        let unpinned: TipResult<1, 1, 0, 2> =
            TipResult::new(0x1d, [0x0c], [0x1c], false, [], [3, 0]);
        assert_eq(unpinned.reads(), []);
        assert_eq(unpinned.serialize(), [0x1d, 0x0c, 0x1c, 0, 3, 0]);
        assert(TipResult::deserialize(unpinned.serialize()) == unpinned);
    }

    #[test(should_fail_with = "a failed round changes its state")]
    fn a_failed_round_that_moves_a_key_is_refused() {
        assert_failed_round_keeps_its_state([0xa], [0xa], [0x1a], [0x2a], false);
    }

    // The positions alone do not pair keys: new[0] = old[0] is not enough
    // when out_keys[0] is in_keys[1].
    #[test(should_fail_with = "a failed round changes its state")]
    fn a_failed_round_is_compared_by_key_not_by_position() {
        let (a, b) = (0xa, 0xb);
        assert_failed_round_keeps_its_state([b, a], [a, b], [0x1b, 0x1a], [0x1b, 0x1a], false);
    }

    #[test]
    fn domains_are_the_machine_labels() {
        // ASCII big-endian, as sidecar-core's label_field reads them
        assert_eq(ascii("sidecar.result"), RESULT_DOMAIN);
    }

    #[test]
    fn message_shape() {
        assert_eq(
            result_message(0xaa, 0xbb, [0xc1, 0xc2], 2, 0xdd),
            poseidon2_hash([RESULT_DOMAIN, 0xaa, 0xbb, 0xc1, 0xc2, 2, 0xdd]),
        );
    }

    #[test]
    fn public_input_orders() {
        // examples/amm-tip amm_swap_tip: [namespace, vk_hash, in_slots[0],
        // out_slots[0], request_id, old_c, new_c, npk_app_hash, ok, code,
        // amount_out]
        assert_eq(
            proved_public_inputs(
                0xa0,
                0x7e,
                [0x51],
                [0x51],
                [],
                0x1d,
                [0x0c],
                [0x1c],
                0x9b,
                true,
                [0, 9],
            ),
            [0xa0, 0x7e, 0x51, 0x51, 0x1d, 0x0c, 0x1c, 0x9b, 1, 0, 9],
        );
        assert_eq(
            proved_public_inputs(
                0xa0,
                0x7e,
                [0x51],
                [0x51],
                [0xe0],
                0x1d,
                [0x0c],
                [0x1c],
                0x9b,
                true,
                [9],
            ),
            [0xa0, 0x7e, 0x51, 0x51, 0xe0, 0x1d, 0x0c, 0x1c, 0x9b, 1, 9],
        );
    }

    // Under partial-note delivery the partial note sits between ok and the
    // app outputs, and changes nothing before them.
    #[test]
    fn the_partial_note_follows_ok() {
        let none = proved_public_inputs(0xa0, 0x7e, [0x51], [0x51], [], 0x1d, [0x0c], [0x1c], 0x9b, true, [0, 9]);
        let partial = proved_public_inputs_with(
            0xa0, 0x7e, [0x51], [0x51], [], 0x1d, [0x0c], [0x1c], 0x9b, true, [0x9a], [0, 9],
        );
        assert_eq(partial, [0xa0, 0x7e, 0x51, 0x51, 0x1d, 0x0c, 0x1c, 0x9b, 1, 0x9a, 0, 9]);
        assert_eq(
            proved_public_inputs_with(0xa0, 0x7e, [0x51], [0x51], [], 0x1d, [0x0c], [0x1c], 0x9b, true, [], [0, 9]),
            none,
        );
        let r = PartialResult {
            partial_note: 0x9a,
            result: TipResult::new(0x1d, [0x0c], [0x1c], true, [], [0, 9]),
        };
        assert_eq(r.serialize(), [0x9a, 0x1d, 0x0c, 0x1c, 1, 0, 9]);
    }

    // The freshness rule (`Freshness::check`): the source returned
    // `returned_len` fields, `returned`; the circuit used (value, epoch).

    #[test]
    fn freshness_widths_and_constructors() {
        assert_eq(Freshness::exact().values(), 1);
        assert_eq(Freshness::epoch().values(), 2);
        assert_eq(Freshness::absolute(5).values(), 1);
        assert_eq(Freshness::relative_bps(10000).values(), 1);
        assert(Freshness::deserialize(Freshness::relative_bps(1).serialize()) == Freshness::relative_bps(1));
    }

    #[test(should_fail_with = "a relative band is 1 to 10000 bps")]
    fn a_relative_band_above_10000_bps_is_refused() {
        let _ = Freshness::relative_bps(10001);
    }

    #[test(should_fail_with = "a relative band is 1 to 10000 bps")]
    fn a_relative_band_of_0_bps_is_refused() {
        let _ = Freshness::relative_bps(0);
    }

    #[test(should_fail_with = "an absolute band is positive")]
    fn an_absolute_band_of_0_is_refused() {
        let _ = Freshness::absolute(0);
    }

    #[test]
    fn an_epoch_read_accepts_the_current_epoch_and_the_one_before() {
        // the source at epoch 7, value 110; epoch 6's value was 100
        Freshness::epoch().check(3, [110, 7, 100], 110, 7);
        Freshness::epoch().check(3, [110, 7, 100], 100, 6);
    }

    #[test(should_fail_with = "pinned epoch too old")]
    fn an_epoch_two_behind_is_refused() {
        Freshness::epoch().check(3, [110, 7, 100], 100, 5);
    }

    #[test(should_fail_with = "pinned epoch too old")]
    fn an_epoch_ahead_of_the_source_is_refused() {
        Freshness::epoch().check(3, [110, 7, 100], 110, 8);
    }

    #[test(should_fail_with = "pinned read changed")]
    fn an_epoch_read_at_another_value_is_refused() {
        Freshness::epoch().check(3, [110, 7, 100], 110, 6);
    }

    // The epochs are u64s compared as integers: an epoch of p - 1 is not the
    // one before a source's epoch 0 (it would be in Field arithmetic), and
    // an epoch past u64 is refused on either side.
    #[test(should_fail_with = "pinned epoch is not a u64")]
    fn an_epoch_of_p_minus_one_is_not_the_one_before_epoch_zero() {
        Freshness::epoch().check(3, [110, 0, 100], 100, 0 - 1);
    }

    #[test(should_fail_with = "pinned epoch is not a u64")]
    fn a_source_epoch_past_u64_is_refused() {
        Freshness::epoch().check(3, [110, 0x10000000000000000, 100], 110, 0x10000000000000000);
    }

    #[test]
    fn the_largest_u64_epochs_compare_as_integers() {
        Freshness::epoch().check(3, [110, 0xffffffffffffffff, 100], 100, 0xfffffffffffffffe);
    }

    // A source past its window reports its current value as the previous
    // one: a round at the previous epoch lands only at the current value.
    #[test(should_fail_with = "pinned read changed")]
    fn a_previous_value_the_source_no_longer_offers_is_refused() {
        Freshness::epoch().check(3, [110, 7, 110], 100, 6);
    }

    #[test(should_fail_with = "pinned epoch read returns three fields")]
    fn an_epoch_read_of_one_field_is_refused() {
        Freshness::epoch().check(1, [110, 0, 0], 110, 7);
    }

    #[test]
    fn an_exact_read_accepts_only_the_value() {
        Freshness::exact().check(1, [1000, 0, 0], 1000, 1000);
    }

    #[test(should_fail_with = "pinned read changed")]
    fn an_exact_read_at_a_moved_value_is_refused() {
        Freshness::exact().check(1, [1001, 0, 0], 1000, 1000);
    }

    #[test(should_fail_with = "pinned read returns one field")]
    fn an_exact_read_of_three_fields_is_refused() {
        Freshness::exact().check(3, [1000, 7, 900], 1000, 1000);
    }

    #[test]
    fn a_tolerance_read_accepts_a_value_inside_its_band() {
        let absolute = Freshness::absolute(10);
        absolute.check(1, [1000, 0, 0], 1010, 1010);
        absolute.check(1, [1000, 0, 0], 990, 990);
        // 1% of the source's value, 1000: up to 10 either way
        let relative = Freshness::relative_bps(100);
        relative.check(1, [1000, 0, 0], 1010, 1010);
        relative.check(1, [1000, 0, 0], 990, 990);
        // the widest values and band
        let max = 0xffffffffffffffffffffffffffffffff;
        Freshness::relative_bps(10000).check(1, [max, 0, 0], 0, 0);
    }

    #[test(should_fail_with = "pinned read outside its band")]
    fn a_value_beyond_an_absolute_band_is_refused() {
        Freshness::absolute(10).check(1, [1000, 0, 0], 989, 989);
    }

    #[test(should_fail_with = "pinned read outside its band")]
    fn a_value_beyond_a_relative_band_is_refused() {
        Freshness::relative_bps(100).check(1, [1000, 0, 0], 1011, 1011);
    }

    #[test(should_fail_with = "pinned read is not a u128")]
    fn a_tolerance_read_beyond_a_u128_is_refused() {
        let two_pow_128 = 0x100000000000000000000000000000000;
        Freshness::absolute(10).check(1, [two_pow_128, 0, 0], two_pow_128, two_pow_128);
    }
}
