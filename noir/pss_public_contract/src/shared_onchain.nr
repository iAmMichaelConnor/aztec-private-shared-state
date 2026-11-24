//! Secret-shared on-chain intake (`intake: shared_onchain`, docs/ARCHITECTURE.md
//! section 6, "Secret-shared on-chain intake"): the user's private function shares
//! the request's values among the nodes itself, puts the encoded shares in
//! one private log only the nodes open, and stores one hash of it beside the
//! queue entry. The round circuits, the MPC receipt check and the result
//! path are secret-shared receipt intake's (`shared_intake`, `outcome`); only the
//! source of the shares differs.
//!
//! The nodes' keys are in public storage, not pinned: `SharedOnchain` holds
//! `enc_keys[i] = (pk, epoch)` and the data hash of each request. A node
//! rotates its own key with a transaction to the app's rotation function,
//! whose private half checks node i's Schnorr signature under its pinned
//! `sig` key over
//!
//! ```text
//! poseidon2([PSS_ENC_ROTATE, namespace, i, pk.x, pk.y, epoch])
//! ```
//!
//! (`enc_rotation_message`) and whose public half requires `epoch` to be the
//! stored epoch + 1 (`SharedOnchain::rotate`). An app wires its storage and
//! four one-line functions:
//!
//! ```noir
//! #[storage]
//! struct Storage<Context> { ..., queue: Queue<Context>, shared_onchain: SharedOnchain<Context> }
//!
//! #[external("private")]
//! fn swap_onchain(swap: [Field; 3], rho: Field, outcome_key: Field, outcome_tag: Field, eph: Field) {
//!     let round = rounds(self.internal.configured_in_force(), self.storage.pool).swap;
//!     let slot = self.storage.shared_onchain.get_storage_slot();
//!     let r: SharedOnchainRequest = outcome_request(self.context, round, self.msg_sender(), swap,
//!         SWAP_SHARED_ONCHAIN_LAYOUT, SharedOnchainArgs { rho, outcome_key, outcome_tag, slot, eph },
//!         valid_swap);
//!     self.enqueue_self.append_onchain_shared(r.request_id, r.data_hash, r.epochs);
//! }
//!
//! #[external("public")]
//! #[only_self]
//! fn append_onchain_shared(request_id: Field, data_hash: Field, epochs: [u32; 3]) {
//!     let _ = self.storage.shared_onchain.append(self.storage.queue, request_id, data_hash, epochs);
//! }
//!
//! #[external("private")]
//! fn rotate_enc_key(i: u32, key: EncKey, signature: Receipt) {
//!     check_enc_rotation(self.context, self.storage.configured.read().config(), i, key,
//!         signature);
//!     self.enqueue_self.set_enc_key(i, key);
//! }
//!
//! #[external("public")]
//! #[only_self]
//! fn set_enc_key(i: u32, key: EncKey) {
//!     self.storage.shared_onchain.rotate(i, key);
//! }
//! ```
//!
//! The request function reads the three keys at its anchor block (a
//! historical public-storage read against the anchor header), so the anchor
//! may be old: `append` asserts that each named epoch is the stored epoch or
//! the one before it, and a request on an older anchor reverts at intake
//! and is resent. A node retires a scalar once the contract's epoch is two
//! ahead of it and the head has passed every request naming it (sidecar-core
//! `epochs`). The encoding and the request log are `pss_core::tip::derived`'s;
//! the user's proof covers the keys, the encoding and the hash, so a correct
//! proof is a correct sharing, and the stored hash gives integrity, so the
//! log carries no authentication tag. The log stays on chain for good:
//! anyone who later learns two nodes' scalars of one epoch opens every
//! request that named it.
use crate::app::TipRound;
use crate::config::{NODES, TipConfig};
use crate::domains::PSS_ENC_ROTATE;
use crate::key_epoch::{EncKeys, on_curve};
use crate::signing_keys::{RetiresEncKeys, SigningKeys};
pub use crate::intake::request_log_tag;
use crate::queue::Queue;
use crate::receipt::Receipt;
use crate::result::result_signature_verifies;
use crate::shared_intake::{app_inputs, inputs_commitment, shared_chain_request_id, SharedRequest};
use aztec::context::{PrivateContext, PublicContext, UtilityContext};
use aztec::history::storage::public_storage_historical_read;
use aztec::protocol::address::AztecAddress;
use aztec::protocol::storage::map::derive_storage_slot_in_map;
use aztec::protocol::traits::{Deserialize, Packable, Serialize, ToField};
use aztec::state_vars::{Map, PublicMutable, StateVariable};
use pss_core::tip::derived::{
    data_hash, key_exchange, Layout, pack_epochs, request_log, shares_of, wraps,
};
use std::embedded_curve_ops::EmbeddedCurvePoint;
use total::hash::p2_hash;

/// Node i's current `enc` public key in one contract and its epoch. Epoch 0
/// with the zero point is the storage default: no key yet, and a request
/// naming it reverts.
#[derive(Deserialize, Eq, Packable, Serialize)]
pub struct EncKey {
    pub x: Field,
    pub y: Field,
    pub epoch: u32,
}

impl EncKey {
    /// The key as a point.
    pub fn point(self) -> EmbeddedCurvePoint {
        EmbeddedCurvePoint { x: self.x, y: self.y }
    }

    /// Whether the key is a point of Grumpkin (`key_epoch::on_curve`).
    pub fn on_curve(self) -> bool {
        on_curve(self.point())
    }
}

/// The storage of secret-shared on-chain intake: `enc_keys[i]` (node i's key and
/// epoch) and `data_hashes[request_id]`. Layout, from the slot the app's
/// `#[storage]` gives it (the machine's `shared_onchain_slot`): +0
/// `enc_keys` (a map by node index, each entry three slots: x, y, epoch),
/// +1 `data_hashes` (a map by chain request id). Two slots in all.
pub struct SharedOnchain<Context> {
    pub(crate) context: Context,
    pub enc_keys: Map<u32, PublicMutable<EncKey, Context>, Context>,
    pub data_hashes: Map<Field, PublicMutable<Field, Context>, Context>,
}

impl<Context> StateVariable<2, Context> for SharedOnchain<Context> {
    fn new(context: Context, storage_slot: Field) -> Self {
        SharedOnchain {
            context,
            enc_keys: Map::new(context, storage_slot),
            data_hashes: Map::new(context, storage_slot + 1),
        }
    }

    fn get_storage_slot(self) -> Field {
        self.enc_keys.get_storage_slot()
    }
}

/// The message node i signs to set its key in `namespace` to `key`:
/// `poseidon2([PSS_ENC_ROTATE, namespace, i, pk.x, pk.y, epoch])`.
pub fn enc_rotation_message(namespace: AztecAddress, i: u32, key: EncKey) -> Field {
    p2_hash([PSS_ENC_ROTATE, namespace.to_field(), i as Field, key.x, key.y, key.epoch as Field])
}

/// The private half of a rotation: `key` is a point and node i signed it
/// for this contract under its current `sig` key, as the app's `node_keys` brick
/// `K` gives it (`SigningKeys::current_sig_key`, the app names it:
/// `check_enc_rotation::<Keys>`). Under key epochs that is the anchor's
/// set, epoch 0 being `config`'s pinned keys (the app's stored ones, never
/// an argument), with no grace window: a key rotated out of the key set must
/// not rotate node i's `enc` after the rotation lands, and the key epoch is
/// checked by the enqueued `assert_key_epoch`. Under a fixed key set it is
/// the pinned key. The enc epoch is checked in public
/// (`SharedOnchain::rotate`). Reads no `msg_sender`: the node or the orchestrator
/// submits it, through the PrivateFPC as every tip transaction.
pub fn check_enc_rotation<K>(
    context: &mut PrivateContext,
    config: TipConfig,
    i: u32,
    key: EncKey,
    signature: Receipt,
)
where
    K: SigningKeys,
{
    assert(i < NODES, "node index out of range");
    assert(key.on_curve(), "the enc key is not a Grumpkin point");
    let namespace = context.this_address();
    let sig_key = K::current_sig_key(context, config.node_sig_keys, i);
    assert(
        result_signature_verifies(sig_key, signature.limbs(), enc_rotation_message(namespace, i, key)),
        "invalid enc key rotation signature",
    );
}

/// The three keys at the anchor block of the private function: storage slot
/// `slot` of `SharedOnchain` in this contract, read against the anchor
/// header.
pub fn anchor_keys(context: &mut PrivateContext, slot: Field) -> [EncKey; NODES] {
    let header = context.get_anchor_block_header();
    let this = context.this_address();
    let mut keys = [EncKey { x: 0, y: 0, epoch: 0 }; NODES];
    for i in 0..NODES {
        let base = derive_storage_slot_in_map(slot, i as Field);
        let mut packed = [0; 3];
        for k in 0..3 {
            packed[k] = public_storage_historical_read(header, base + k as Field, this);
        }
        keys[i] = EncKey::unpack(packed);
    }
    keys
}

/// What the app's request wrapper enqueues: the request id, the data hash
/// and the epochs the log names.
pub struct SharedOnchainRequest {
    pub request_id: Field,
    pub data_hash: Field,
    pub epochs: [u32; NODES],
}

/// The private half of secret-shared on-chain intake: assert that every node has a
/// key at the anchor, encode `values` (in the inputs commitment's order,
/// each of its `layout` kind: CLEAR or CHOSEN,
/// `pss_core::tip::derived::Layout`) under the ephemeral secret `eph` and the
/// anchor's keys, compute `C`, admit the request under `round`
/// (`TipRound::admit`: the vk pin and `is_valid` over the app inputs,
/// `shared_intake::app_inputs`, as secret-shared receipt intake) with the secret-shared chain request id over `C`, emit the request log
/// under `request_log_tag(request_id)` (`intake`) and return what the app's
/// `append_onchain_shared` wrapper takes.
///
/// `slot` is the app's `SharedOnchain` storage slot. The layout must be the
/// one the machine derives from the round's manifest (every shared value,
/// INPUT_SHARED app input or reserved value, CHOSEN, every other app input
/// CLEAR); a layout that differs gives shares that do not open to C, which
/// the round's MPC receipt check flags. `values` (the outcome key and tag
/// among them, which the client derives from its wallet secret and request
/// counter) and `eph` are private arguments and never reach the chain: the
/// log holds the clear values and the corrections only, and `$blinding` is
/// the encoding's. `eph` must be fresh, full-entropy and used once (pss_utils
/// `dh::ecdh_x`). The row's `node_keys` brick `K` must retire a replaced
/// node's stored key (`signing_keys::RetiresEncKeys`: `FixedKeys`, or
/// `KeyEpochs<SharedOnchain<PublicContext>>`, whose `install` voids it), so
/// no request encrypts to a node the key set no longer holds.
pub fn shared_onchain_request<C, K, let R: u32, let W: u32, let M: u32, let Q: u32, let X: u32, let I: u32, Env>(
    context: &mut PrivateContext,
    round: TipRound<C, R, W, K>,
    slot: Field,
    layout: Layout<M, Q, X>,
    values: [Field; M],
    eph: Field,
    is_valid: fn[Env]([Field; I]) -> bool,
) -> SharedOnchainRequest
where
    K: RetiresEncKeys,
{
    let keys = anchor_keys(context, slot);
    let mut epochs = [0; NODES];
    for i in 0..NODES {
        assert(keys[i].epoch != 0, "a node has no enc key in this contract");
        // a key a key-set rotation voided (`EncKeys::void_replaced`) stays the zero
        // point until the node's own rotation sets its new key
        assert(keys[i].on_curve(), "a node's enc key is void until it rotates");
        epochs[i] = keys[i].epoch;
    }
    let (secrets, eph_x) = key_exchange(eph, keys.map(|k: EncKey| k.point()));
    let encoding = shares_of(layout, values, secrets);
    let c = inputs_commitment(values, encoding.blinding);
    let request_id = round.admit(
        context,
        app_inputs(values),
        is_valid,
        |namespace, vk_hash| shared_chain_request_id(namespace, vk_hash, c),
    );
    let tag = request_log_tag(request_id);
    let log = request_log(
        encoding.blinding,
        c,
        pack_epochs(epochs),
        eph_x,
        wraps(secrets),
        encoding.clear,
        encoding.corrections,
    );
    context.emit_private_log_unsafe(tag, BoundedVec::from_array(log));
    SharedOnchainRequest { request_id, data_hash: data_hash(log), epochs }
}

/// A secret-shared on-chain intake request (`shared_intake::SharedRequest`):
/// the partial note's randomness, the outcome key and tag, the app's
/// `SharedOnchain` storage slot and the ephemeral secret `eph` (fresh,
/// full-entropy, used once), all but the slot private arguments of the
/// request function. `shared_intake::outcome_request` over it shares the
/// request's values in the request log (`shared_onchain_request`) and
/// returns the `SharedOnchainRequest` the app's `append_onchain_shared`
/// wrapper takes.
pub struct SharedOnchainArgs {
    pub rho: Field,
    pub outcome_key: Field,
    pub outcome_tag: Field,
    pub slot: Field,
    pub eph: Field,
}

impl<K> SharedRequest<SharedOnchainRequest, K> for SharedOnchainArgs
where
    K: SigningKeys + RetiresEncKeys,
{
    fn rho(self) -> Field {
        self.rho
    }

    fn outcome_key_tag(self) -> [Field; 2] {
        [self.outcome_key, self.outcome_tag]
    }

    fn request<C, let R: u32, let W: u32, let M: u32, let Q: u32, let X: u32, let I: u32, Env>(
        self,
        context: &mut PrivateContext,
        round: TipRound<C, R, W, K>,
        layout: Layout<M, Q, X>,
        values: [Field; M],
        is_valid: fn[Env]([Field; I]) -> bool,
    ) -> SharedOnchainRequest {
        shared_onchain_request(context, round, self.slot, layout, values, self.eph, is_valid)
    }
}

impl SharedOnchain<PublicContext> {
    /// The body of the app's `set_enc_key` wrapper (`#[only_self]`, enqueued
    /// by its rotation function after `check_enc_rotation`): node i's key
    /// becomes `key`, whose epoch must be the stored one + 1.
    pub fn rotate(self, i: u32, key: EncKey) {
        assert(i < NODES, "node index out of range");
        let entry = self.enc_keys.at(i);
        assert_eq(key.epoch, entry.read().epoch + 1, "the epoch is not the stored epoch + 1");
        entry.write(key);
    }

    /// The body of the app's `append_onchain_shared` wrapper
    /// (`#[only_self]`): each named epoch is node i's stored epoch or the
    /// one before it, and never 0 (no key), then `queue.append(request_id)` and the data hash
    /// beside it. Returns the queue index.
    pub fn append(
        self,
        queue: Queue<PublicContext>,
        request_id: Field,
        data_hash: Field,
        epochs: [u32; NODES],
    ) -> u64 {
        for i in 0..NODES {
            let stored = self.enc_keys.at(i).read().epoch;
            assert(epochs[i] != 0, "the request names epoch 0, no enc key");
            assert(
                (epochs[i] == stored) | (epochs[i] + 1 == stored),
                "the request names an enc key epoch older than the one before the stored one",
            );
        }
        let index = queue.append(request_id);
        self.data_hashes.at(request_id).write(data_hash);
        index
    }

    pub fn enc_key(self, i: u32) -> EncKey {
        self.enc_keys.at(i).read()
    }

    pub fn data_hash(self, request_id: Field) -> Field {
        self.data_hashes.at(request_id).read()
    }
}

/// The key-set rotation's part (`KeyEpochs::install`, which every
/// `set_node_keys` calls with the app's `SharedOnchain`): every node whose
/// stored key is not its `enc` key in the new set `enc` (the replaced
/// node's, in a replacement) gets the zero point at its stored epoch + 2.
/// The skipped epoch voids the one before: `append` accepts the stored
/// epoch or the one before it, so a request naming the replaced key's epoch
/// reverts at intake instead of waiting in the queue for a node that cannot
/// open it, and the zero point refuses every new request
/// (`shared_onchain_request`) until the node's own `rotate_enc_key`, signed
/// under the new key set, sets its key at the stored epoch + 1. A node with
/// no key yet (epoch 0) is left alone.
impl EncKeys for SharedOnchain<PublicContext> {
    fn void_replaced(self, enc: [EmbeddedCurvePoint; NODES]) {
        for i in 0..NODES {
            let entry = self.enc_keys.at(i);
            let held = entry.read();
            if (held.epoch != 0) & ((held.x != enc[i].x) | (held.y != enc[i].y)) {
                entry.write(EncKey { x: 0, y: 0, epoch: held.epoch + 2 });
            }
        }
    }
}

/// The same reads from a utility function.
impl SharedOnchain<UtilityContext> {
    pub unconstrained fn enc_key(self, i: u32) -> EncKey {
        self.enc_keys.at(i).read()
    }

    pub unconstrained fn data_hash(self, request_id: Field) -> Field {
        self.data_hashes.at(request_id).read()
    }
}

mod test {
    use super::{enc_rotation_message, EncKey};
    use crate::domains::PSS_ENC_ROTATE;
    use aztec::protocol::address::AztecAddress;
    use aztec::protocol::hash::poseidon2_hash;
    use pss_core::test_support::ascii;

    #[test]
    fn the_rotation_domain_is_its_label_and_the_message_its_hash() {
        assert_eq(PSS_ENC_ROTATE, ascii("pss.enc_rotate"));
        let ns = AztecAddress { inner: 0xc0ffee };
        let key = EncKey { x: 1, y: 2, epoch: 3 };
        assert_eq(enc_rotation_message(ns, 1, key), poseidon2_hash([PSS_ENC_ROTATE, 0xc0ffee, 1, 1, 2, 3]));
    }
}
