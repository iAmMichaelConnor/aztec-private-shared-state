//! Intake: the chain request id and on-chain intake (`intake: onchain`),
//! the request log of the inputs in the clear (docs/ARCHITECTURE.md section 6, row
//! "intake"). Receipt intake, the receipt check,
//! is in `receipt`.
//!
//! An app's private request function computes the request id and checks
//! the inputs' static validity with `onchain_request`, then enqueues its own
//! `#[only_self]` public wrapper, whose body is `Queue::append_onchain`:
//!
//! ```noir
//! #[external("private")]
//! fn request_swap(inputs: [Field; 2], user_nonce: Field) {
//!     let round = rounds(self.storage.configured.read(), self.storage.pool).swap;
//!     let (request_id, plain) =
//!         onchain_request(self.context, round, inputs, user_nonce, valid_swap);
//!     self.enqueue_self.append_onchain(request_id, plain);
//! }
//!
//! #[external("public")]
//! #[only_self]
//! fn append_onchain(request_id: Field, plain: PlainRequest<2>) {
//!     let _ = self.storage.queue.append_onchain(request_id, plain);
//! }
//! ```
//!
//! The library cannot name the app's wrapper, so the enqueue is the app's
//! one line; the wrapper must be `#[only_self]` (see `Queue::append`). The
//! row is the one receipt intake's `receipt_request` takes: one compiled
//! circuit per round serves both non-secret-shared intakes, so the request id is the
//! same function of the inputs and the nonce under both, and one
//! `process_result` lands the round's results whichever intake queued them.
//!
//! # The hidden requester
//!
//! No intake function reads `msg_sender` or asserts a calling account:
//! anyone may queue a request from any account or entrypoint. The private
//! function enqueues the app's own `#[only_self]` wrapper, so the public
//! call's `msg_sender` is the app contract, and the request id, the request
//! log and the public call's arguments hold the inputs and `user_nonce`
//! only (docs/ARCHITECTURE.md section 6, "The hidden requester"). An app
//! that needs ownership proves it in the round (an owner commitment the
//! private function computes from a secret), never through `msg_sender`,
//! and an app's intake function that calls into another contract's public
//! function does so through an incognito enqueue.
//!
//! # The on-chain intake request log
//!
//! Written down here once; the chain reader (`sidecar-tip`), pss-client and
//! pss-relayer read the same layout, and every case of
//! testvectors/chain_request_id.json carries its `request_log`. One public log per request, emitted by
//! the app's `append_onchain` in the transaction that queues the request,
//! from the app contract's address (the namespace):
//!
//! ```text
//! field 0           tag = compute_log_tag(request_id, REQUEST_DOMAIN)
//!                       = poseidon2_hash_with_separator([request_id], REQUEST_DOMAIN)
//! fields 1 ..= N    inputs[0 .. N], the app's circuit inputs in ABI order
//! field N + 1       user_nonce
//! ```
//!
//! N + 2 fields in all; fields 1 to N + 1 are `PlainRequest::serialize()`.
//! From them a reader recomputes, with `namespace` the emitting contract and
//! `vk_hash` the circuit's pin:
//!
//! ```text
//! inputs_hash = poseidon2(inputs)
//! request_id  = poseidon2([namespace, vk_hash, inputs_hash, user_nonce])
//! ```
//!
//! where `poseidon2` is the width-4 sponge of ARCHITECTURE section 1
//! (protocol_types' `poseidon2_hash`, total's `p2_hash`), and checks the tag
//! against `compute_log_tag(request_id, REQUEST_DOMAIN)`.
use crate::app::TipRound;
use crate::configure::assert_deployed;
use crate::domains::REQUEST_DOMAIN;
use crate::queue::Queue;
use aztec::context::{PrivateContext, PublicContext};
use aztec::protocol::address::AztecAddress;
use aztec::protocol::hash::compute_log_tag;
use aztec::protocol::traits::{Deserialize, Serialize, ToField};

/// `inputs_hash = poseidon2(inputs)`, the app's circuit inputs in ABI order:
/// pss_core's, the function the round circuits call (total's fixed-length
/// `p2_hash`, Aztec's `poseidon2_hash`, with no failure source).
pub use pss_core::tip::intake::inputs_hash;

/// 2^64 and 2^128: the bounds of a u64 and a u128 value (total's).
pub use total::core::{TWO_POW_128, TWO_POW_64};

/// Whether `x`'s canonical value fits a u64: the static check of a u64
/// request input (an amount, a limit) before anything is queued.
pub fn is_u64(x: Field) -> bool {
    x.lt(TWO_POW_64)
}

/// Whether `x`'s canonical value fits a u128 (`is_u64`'s 128-bit twin).
pub fn is_u128(x: Field) -> bool {
    x.lt(TWO_POW_128)
}

/// The chain request id:
/// `poseidon2([namespace, vk_hash, inputs_hash, user_nonce])`, with
/// `namespace` the app contract's address (taken from the context, never
/// from an argument), `vk_hash` the pinned vk hash of the circuit that
/// serves the request and `user_nonce` the request's random salt: pss_core's
/// `chain_request_id` over the address as a field. Both non-secret-shared intakes key
/// the queue, the nodes' rows and the results by it; the scheduler derives
/// the machine request id from it. It names no requester.
pub fn chain_request_id(
    namespace: AztecAddress,
    vk_hash: Field,
    inputs_hash: Field,
    user_nonce: Field,
) -> Field {
    pss_core::tip::intake::chain_request_id(namespace.to_field(), vk_hash, inputs_hash, user_nonce)
}

/// The body of the on-chain intake request log after its tag: the inputs and
/// `user_nonce`, serialised in that order (the layout in the module docs).
///
/// On-chain intake inputs are in the clear (DECISIONS.md, "On-chain intake"); a
/// manifest that shares an input under on-chain intake is refused
/// at REGISTER. What the request log reveals to the world: every input and the
/// nonce, so anyone can recompute `inputs_hash` and `request_id`, but not
/// who sent the request (no address is logged or hashed). Choose receipt
/// intake for inputs that must stay off the chain. The inputs are private
/// witnesses of the co-SNARK, which outputs the request id over them, as
/// under receipt intake. Inputs hidden on chain take secret-shared on-chain
/// intake, a private log only the nodes open (DECISIONS.md,
/// "Secret-shared on-chain intake"), not this log.
#[derive(Deserialize, Eq, Serialize)]
pub struct PlainRequest<let N: u32> {
    /// the app's circuit inputs in ABI order
    pub inputs: [Field; N],
    /// the request's salt, drawn at random per request: distinct requests
    /// with equal inputs get distinct ids
    pub user_nonce: Field,
}

/// The tag of request `request_id`'s on-chain intake log (field 0), and of
/// secret-shared on-chain intake's private request log before the kernel silos it
/// (the node finds that one by the siloed tag).
pub fn request_log_tag(request_id: Field) -> Field {
    compute_log_tag(request_id, REQUEST_DOMAIN)
}

impl<C, let R: u32, let W: u32, K> TipRound<C, R, W, K> {
    /// Admission, the prefix of every intake's private request function:
    /// assert that the row's circuit is deployed (`assert_deployed`) and the
    /// app inputs' static validity with `is_valid`,
    /// then return the request's chain request id, `id(namespace, vk_hash)`
    /// with `namespace` this contract's address (taken from the context,
    /// never from an argument) and `vk_hash` the row's pin. `id` closes over
    /// the request's commitment: `chain_request_id` over `inputs_hash` and
    /// `user_nonce` under the non-secret-shared intakes, `shared_chain_request_id` over
    /// `C` under the secret-shared ones. Reads no `msg_sender`: whoever calls queues
    /// the request.
    ///
    /// `is_valid` is the app's static-validity predicate (ranges, enum values,
    /// non-zero amounts): it sees the app inputs only, and must decide from
    /// them alone. Nothing state-dependent belongs there: the state is secret
    /// and moves before the request runs, so whether a request succeeds
    /// against the state is the circuit's `ok`, not intake's.
    pub fn admit<let N: u32, Env, IdEnv>(
        self,
        context: &mut PrivateContext,
        inputs: [Field; N],
        is_valid: fn[Env]([Field; N]) -> bool,
        id: fn[IdEnv](AztecAddress, Field) -> Field,
    ) -> Field {
        assert_deployed(self.vk_hash);
        assert(is_valid(inputs), "invalid inputs");
        id(context.this_address(), self.vk_hash)
    }
}

/// The private half of on-chain intake: admit the request under `round`,
/// the app's round table row (`TipRound::admit`: the vk pin and
/// `is_valid`), with the chain request id of `inputs` and
/// `user_nonce`, and return it with the log body the app's `append_onchain`
/// wrapper takes.
pub fn onchain_request<C, K, let R: u32, let W: u32, let N: u32, Env>(
    context: &mut PrivateContext,
    round: TipRound<C, R, W, K>,
    inputs: [Field; N],
    user_nonce: Field,
    is_valid: fn[Env]([Field; N]) -> bool,
) -> (Field, PlainRequest<N>) {
    let inputs_hash = inputs_hash(inputs);
    let request_id = round.admit(
        context,
        inputs,
        is_valid,
        |namespace, vk_hash| chain_request_id(namespace, vk_hash, inputs_hash, user_nonce),
    );
    (request_id, PlainRequest { inputs, user_nonce })
}

impl Queue<PublicContext> {
    /// The body of the app's on-chain intake `append_onchain` wrapper
    /// (`#[external("public")]`, `#[only_self]`): `append(request_id)`, then
    /// the request log `[request_log_tag(request_id), plain...]`. Returns the
    /// queue index. The request id is the one the app's private function
    /// computed from `plain`; `#[only_self]` is what makes it trustworthy,
    /// so it is not recomputed here.
    pub fn append_onchain<let N: u32>(self, request_id: Field, plain: PlainRequest<N>) -> u64 {
        let index = self.append(request_id);
        self.context.emit_public_log_unsafe(request_log_tag(request_id), plain);
        index
    }
}

mod test {
    use super::{chain_request_id, inputs_hash, PlainRequest, request_log_tag};
    use crate::domains::REQUEST_DOMAIN;
    use aztec::protocol::address::AztecAddress;
    use aztec::protocol::hash::{compute_log_tag, poseidon2_hash, poseidon2_hash_with_separator};
    use aztec::protocol::traits::{Deserialize, FromField, Serialize};

    global AMOUNT: Field = 1000;
    global DIRECTION: Field = 1;
    global NONCE: Field = 0x6e6f6e6365;
    global VK_HASH: Field = 0x0f1e2d3c4b5a6978;

    // inputs_hash is poseidon2 over the inputs in ABI order, and the chain
    // request id is poseidon2([namespace, vk_hash, inputs_hash, user_nonce]),
    // with no requester: Aztec's poseidon2_hash on the same preimages, so the
    // machine, the client and the relayer recompute it with their own Poseidon2.
    #[test]
    fn inputs_hash_and_request_id_are_poseidon2_of_their_preimages() {
        let inputs = [AMOUNT, DIRECTION];
        assert_eq(inputs_hash(inputs), poseidon2_hash([AMOUNT, DIRECTION]));
        // ABI order matters
        assert(inputs_hash([DIRECTION, AMOUNT]) != inputs_hash(inputs));

        let namespace = AztecAddress::from_field(0x0a11ce);
        let h = inputs_hash(inputs);
        let id = chain_request_id(namespace, VK_HASH, h, NONCE);
        assert_eq(id, poseidon2_hash([0x0a11ce, VK_HASH, h, NONCE]));
        // every element of the preimage changes the id
        assert(chain_request_id(AztecAddress::from_field(0x0a11cf), VK_HASH, h, NONCE) != id);
        assert(chain_request_id(namespace, VK_HASH + 1, h, NONCE) != id);
        assert(chain_request_id(namespace, VK_HASH, h + 1, NONCE) != id);
        assert(chain_request_id(namespace, VK_HASH, h, NONCE + 1) != id);
    }

    // The request log: field 0 the tag
    // compute_log_tag(request_id, REQUEST_DOMAIN), then the inputs in ABI
    // order and user_nonce; four fields for a swap's two inputs, and no
    // address. append_onchain emits [tag] ++ PlainRequest::serialize().
    #[test]
    fn the_plain_log_is_the_tag_then_the_inputs_and_nonce() {
        let plain = PlainRequest { inputs: [AMOUNT, DIRECTION], user_nonce: NONCE };
        let body = plain.serialize();
        assert_eq(body, [AMOUNT, DIRECTION, NONCE]);
        assert_eq(PlainRequest::<2>::deserialize(body), plain);

        let id = 0x1d;
        let tag = request_log_tag(id);
        assert_eq(tag, compute_log_tag(id, REQUEST_DOMAIN));
        assert_eq(tag, poseidon2_hash_with_separator([id], REQUEST_DOMAIN));
        // REQUEST_DOMAIN is ASCII "psrq"
        assert_eq(REQUEST_DOMAIN, 0x70737271);
        // the tag is per request id
        assert(request_log_tag(id + 1) != tag);
    }
}
