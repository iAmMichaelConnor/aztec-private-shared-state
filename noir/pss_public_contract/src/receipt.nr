//! Receipt intake (`intake: receipt`): three node receipts verified in the
//! user's private function (docs/ARCHITECTURE.md section 6, rows "intake"
//! and "receipts").
//!
//! The user first sends the inputs and `user_nonce` to every node's
//! receipt route (through the orchestrator). Each node checks static
//! validity, stores the inputs and signs
//!
//! ```text
//! message = poseidon2([RECEIPT_DOMAIN, request_id, inputs_hash, expiry_block])
//! ```
//!
//! with its `sig` key (Schnorr over Grumpkin, noir-lang/schnorr v0.4.0),
//! where `inputs_hash` and `request_id` are `intake::inputs_hash` and
//! `intake::chain_request_id` and `expiry_block` is a u32 block number as a
//! field. The app's private request function then calls `receipt_request`,
//! which recomputes both hashes and checks all three receipts against the
//! `sig` keys of the stored `TipConfig`, and enqueues its `#[only_self]`
//! wrapper with only the request id and the expiry block, whose body is
//! `Queue::append_before`:
//!
//! ```noir
//! #[external("private")]
//! fn request_swap_private(inputs: [Field; 2], user_nonce: Field, expiry_block: u32, receipts: [Receipt; 3]) {
//!     let round = rounds(self.storage.configured.read(), self.storage.pool).swap;
//!     let request_id = receipt_request(self.context, round, inputs, user_nonce,
//!         expiry_block, receipts, valid_swap);
//!     self.enqueue_self.append_receipt(request_id, expiry_block);
//! }
//!
//! #[external("public")]
//! #[only_self]
//! fn append_receipt(request_id: Field, expiry_block: u32) {
//!     let _ = self.storage.queue.append_before(request_id, expiry_block);
//! }
//! ```
//!
//! The inputs never reach the chain: they are private arguments of the
//! request function and private witnesses of the co-SNARK, which outputs
//! `request_id`. With a random `user_nonce`, `request_id` is a hiding
//! commitment to the inputs. The row is the one on-chain intake's
//! `onchain_request` takes: one compiled circuit per round serves both
//! non-secret-shared intakes.
//!
//! Operator knob: DESIGN.md, "Configuration reference" (`receipt_ttl_blocks`):
//! the `expiry_block` the three receipts sign; the user's intake transaction
//! must land in a block below it (`Queue::append_before`).
//!
//! Clear inputs: the inputs reach the nodes in the clear over TLS, so every node computes `inputs_hash`
//! itself and the scheduler takes the head's inputs from the nodes' stored
//! copies; the orchestrator, which proxies the route, sees them too. A
//! manifest whose inputs must be hidden from the orchestrator and the nodes
//! takes secret-shared receipt intake instead (INPUT_SHARED envelopes, the receipts
//! over the commitment `C`; DECISIONS.md, "Secret-shared receipt intake"), and
//! REGISTER refuses (400) `intake: receipt` with an INPUT_SHARED source
//! (DECISIONS.md, "Manifests"). This helper sees only the inputs and the
//! receipts.
use crate::app::TipRound;
use crate::config::NODES;
use crate::domains::RECEIPT_DOMAIN;
use crate::intake::{chain_request_id, inputs_hash};
use crate::signing_keys::SigningKeys;
use crate::result::{ResultSignature, result_signature_verifies};
use aztec::context::PrivateContext;
use aztec::protocol::traits::{Deserialize, Serialize};
use std::embedded_curve_ops::EmbeddedCurvePoint;
use total::hash::p2_hash;

/// One node's receipt: a node signature (`result::ResultSignature`) as the
/// request functions take it, in sidecar-core's wire shape `{s: [lo, hi],
/// e: [lo, hi]}`, the low 128 bits and the rest of each scalar. `limbs`
/// gives the four limbs every signature check takes. A missing receipt is
/// the zero signature, which never verifies.
#[derive(Deserialize, Eq, Serialize)]
pub struct Receipt {
    pub s: [Field; 2],
    pub e: [Field; 2],
}

impl Receipt {
    pub fn missing() -> Self {
        Receipt { s: [0, 0], e: [0, 0] }
    }

    /// The signature as four limbs `[s.lo, s.hi, e.lo, e.hi]`.
    pub fn limbs(self) -> ResultSignature {
        [self.s[0], self.s[1], self.e[0], self.e[1]]
    }
}

/// The message every node signs:
/// `poseidon2([RECEIPT_DOMAIN, request_id, inputs_hash, expiry_block])`.
pub fn receipt_message(request_id: Field, inputs_hash: Field, expiry_block: u32) -> Field {
    p2_hash([RECEIPT_DOMAIN, request_id, inputs_hash, expiry_block as Field])
}

/// The message every node signs under secret-shared receipt intake:
/// `poseidon2([RECEIPT_DOMAIN, request_id, C, expiry_block, D])`, `C` the
/// inputs commitment and `D` the sharing digest
/// (`pss_core::tip::intake::sharing_digest`) over the summand commitments
/// the node checked its envelopes against, the round's layout and the clear
/// values it stores. Five elements, so it is never a receipt intake
/// message.
pub fn shared_receipt_message(request_id: Field, c: Field, expiry_block: u32, d: Field) -> Field {
    p2_hash([RECEIPT_DOMAIN, request_id, c, expiry_block as Field, d])
}

/// Assert that receipt i verifies under node i's pinned `sig` key, for every
/// node: all three are required, and a receipt is accepted only in its own
/// node's position.
pub fn check_receipts(
    node_sig_keys: [EmbeddedCurvePoint; NODES],
    receipts: [Receipt; NODES],
    message: Field,
) {
    let keys = node_sig_keys;
    assert(result_signature_verifies(keys[0], receipts[0].limbs(), message), "invalid receipt from node 0");
    assert(result_signature_verifies(keys[1], receipts[1].limbs(), message), "invalid receipt from node 1");
    assert(result_signature_verifies(keys[2], receipts[2].limbs(), message), "invalid receipt from node 2");
}

/// `check_receipts` under the keys the app's `node_keys` brick `K` gives
/// (`crate::signing_keys`): under key epochs the anchor's current `sig`
/// keys, or the previous epoch's for receipts signed before a rotation,
/// inside its grace window (`key_epoch::signing_keys`, which enqueues the
/// public check), so a user's receipts under the previous epoch are good
/// for the grace window and then expire; under a fixed key set `set0`.
/// `set0` is the stored `TipConfig::node_sig_keys`, the constructor's keys.
pub fn check_epoch_receipts<K>(
    context: &mut PrivateContext,
    set0: [EmbeddedCurvePoint; NODES],
    receipts: [Receipt; NODES],
    message: Field,
)
where
    K: SigningKeys,
{
    let signatures = receipts.map(|r: Receipt| r.limbs());
    let keys = K::signing_keys(context, set0, [message; NODES], signatures);
    check_receipts(keys, receipts, message);
}

/// The private half of receipt intake: admit the request under `round`
/// (`TipRound::admit`: the vk pin and `is_valid`, which the nodes check
/// too before they sign) with the chain request id of
/// `inputs` and `user_nonce`, check the three receipts over
/// `receipt_message(request_id, inputs_hash, expiry_block)` against the
/// node `sig` keys, and return the request id for the app's
/// `append_receipt` wrapper, which enqueues it with `expiry_block`.
///
/// `round` is the app's round table row (`crate::app`): the vk pin and the
/// stored `TipConfig` with the `sig` keys (see its doc comment), never an
/// argument of the request function.
pub fn receipt_request<C, K, let R: u32, let W: u32, let N: u32, Env>(
    context: &mut PrivateContext,
    round: TipRound<C, R, W, K>,
    inputs: [Field; N],
    user_nonce: Field,
    expiry_block: u32,
    receipts: [Receipt; NODES],
    is_valid: fn[Env]([Field; N]) -> bool,
) -> Field
where
    K: SigningKeys,
{
    let inputs_hash = inputs_hash(inputs);
    let request_id = round.admit(
        context,
        inputs,
        is_valid,
        |namespace, vk_hash| chain_request_id(namespace, vk_hash, inputs_hash, user_nonce),
    );
    check_epoch_receipts::<K>(
        context,
        round.tip.node_sig_keys,
        receipts,
        receipt_message(request_id, inputs_hash, expiry_block),
    );
    request_id
}

mod test {
    use super::{receipt_message, shared_receipt_message};
    use crate::domains::RECEIPT_DOMAIN;
    use aztec::protocol::hash::poseidon2_hash;

    // The receipt message is poseidon2([RECEIPT_DOMAIN, request_id,
    // inputs_hash, expiry_block]), RECEIPT_DOMAIN ASCII "sidecar.receipt".
    #[test]
    fn the_receipt_message_is_poseidon2_of_domain_id_hash_and_expiry() {
        assert_eq(RECEIPT_DOMAIN, 0x736964656361722e72656365697074);
        assert_eq(receipt_message(0x1d, 0x2e, 77), poseidon2_hash([RECEIPT_DOMAIN, 0x1d, 0x2e, 77]));
        assert(receipt_message(0x1d, 0x2e, 78) != receipt_message(0x1d, 0x2e, 77));
        assert(receipt_message(0x1d, 0x2f, 77) != receipt_message(0x1d, 0x2e, 77));
        assert(receipt_message(0x1e, 0x2e, 77) != receipt_message(0x1d, 0x2e, 77));
    }

    // The secret-shared receipt message adds the sharing digest D as a fifth
    // element: it binds D and is never a four-element receipt message.
    #[test]
    fn the_shared_receipt_message_binds_the_sharing_digest() {
        let m = shared_receipt_message(0x1d, 0x2e, 77, 0xd1);
        assert_eq(m, poseidon2_hash([RECEIPT_DOMAIN, 0x1d, 0x2e, 77, 0xd1]));
        assert(m != shared_receipt_message(0x1d, 0x2e, 77, 0xd2));
        assert(m != shared_receipt_message(0x1d, 0x2e, 78, 0xd1));
        assert(shared_receipt_message(0x1d, 0x2e, 77, 0) != receipt_message(0x1d, 0x2e, 77));
    }
}
