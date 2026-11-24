//! Key epochs (docs/ARCHITECTURE.md section 6, "Node replacement and key
//! epochs"; DECISIONS.md section 15): the numbered key set every node
//! signature is checked under, and its rotation by two of the three current
//! nodes.
//!
//! A key set is the three nodes' `sig` and `enc` public keys, node 0 first;
//! an epoch is a number and a key set, not a time period. Epoch 0 is the
//! constructor's `sig` keys (`TipPins::node_sig_keys`, read through
//! `TipConfig`), with no `enc` keys on record. `rotate_keys` moves the
//! contract from epoch `E` to `E + 1` when two of epoch `E`'s nodes sign the
//! new set over
//!
//! ```text
//! poseidon2([PSS_ROTATE_KEYS, namespace, E + 1, H(keys)])
//! H(keys) = poseidon2([sig_0.x, sig_0.y, enc_0.x, enc_0.y, sig_1.x, ..., enc_2.y])
//! ```
//!
//! (`rotation_message`, `keys_hash`; sidecar-core's `epoch` module signs the
//! same). One signature would let one stolen key rotate all three keys to
//! the attacker's; three would give a departed node a veto over its own
//! removal; two is the threshold the network already lives with.
//!
//! This is the `rotating` brick of the `node_keys` axis, `KeyEpochs`
//! (`crate::signing_keys`; the alternative is `FixedKeys`). Every private
//! function that verifies node signatures (results, the init round,
//! receipts, shared receipts) of an app whose round table names
//! `KeyEpochs` calls `signing_keys` through it: it reads the
//! stored `NodeKeys` at its anchor block, verifies under the current set, or
//! under the previous set when the signatures were made before the rotation,
//! and enqueues the app's `assert_key_epoch` with the epoch it verified
//! under. That public check accepts the stored epoch, or the one before it
//! while `block <= rotated_at + grace` (`grace` = the namespace's
//! `stale_blocks`: no head outlives it), and refuses anything older ("key
//! epoch expired"). So a result the nodes signed before the rotation lands
//! inside the window and is recomputed after it, and the departed node's
//! signatures are worth nothing once the window closes.
//!
//! The epoch a request names is the one its signatures verify under: a
//! signature names its key, so the submitter passes no epoch argument and
//! no caller-facing function changes. The choice between the two admissible
//! sets is an unconstrained hint (which one the signatures verify under);
//! the verification under the chosen set is constrained, and the public
//! check binds the chosen epoch, so a wrong hint only fails.
//!
//! Storage: one `NodeKeys` value with its hash (aztec-nr's `WithHash`, so a
//! private function proves one public-storage slot) at the library's own
//! slot `NODE_KEYS_SLOT`, outside the app's `#[storage]` layout, so an app
//! declares nothing and the machine and the clients read every contract's
//! key set at the same slot. Unset, it reads as epoch 0. The public check
//! reads only the value's head (`NodeKeysHead`: `epoch`, `rotated_at`,
//! `grace`, packed first), three storage reads.
//!
//! An app names `KeyEpochs<E>` in its round table rows (`TipRound<C, R, W,
//! Keys>`, `pub type Keys = KeyEpochs<E>`), `E` the node `enc` keys the
//! contract holds (`EncKeys`: its `SharedOnchain<PublicContext>` under
//! secret-shared on-chain intake, else `NoEncKeys`), and writes four
//! one-line wrappers (examples/amm-tip):
//!
//! ```noir
//! #[external("private")]
//! fn rotate_keys(epoch: u32, keys: KeySet, signatures: [ResultSignature; 3]) {
//!     let config = self.storage.configured.read().config();
//!     let node_keys = key_epoch::check_rotation(self.context, config, epoch, keys, signatures);
//!     self.enqueue_self.set_node_keys(node_keys);
//! }
//!
//! #[external("public")]
//! #[only_self]
//! fn set_node_keys(node_keys: NodeKeys) {
//!     // the enc keys `Keys` names: here its SharedOnchain (a replaced node's
//!     // key is voided); NoEncKeys {} under KeyEpochs<NoEncKeys>
//!     Keys::install(self.context, node_keys, self.storage.shared_onchain);
//! }
//!
//! #[external("public")]
//! #[only_self]
//! fn assert_key_epoch(epoch: u32, current_only: bool) {
//!     key_epoch::assert_epoch(self.context, epoch, current_only);
//! }
//!
//! #[external("public")]
//! #[view]
//! fn get_node_keys() -> NodeKeys {
//!     key_epoch::stored(self.context)
//! }
//! ```
//!
//! One key set per chain: no signed message carries a chain id, and an
//! Aztec address does not depend on the chain, so a contract deployed with
//! the same salt and pins on two chains has one namespace on both, and a
//! rotation or a registry answer signed for one verifies on the other. A
//! network serves one chain under one key directory (docs/ARCHITECTURE.md
//! section 6, "Node replacement and key epochs").
//!
//! What a rotation reveals: it is public and dated, the new key set and the
//! two signing nodes' indices are in the transaction. The honest third,
//! every client and every relayer see a rotation they did not approve the
//! moment it lands.
use crate::config::{DEFAULT_STALE_BLOCKS, NODES, StaleBlocks, TipConfig};
use crate::configure::read_stored_head;
use crate::domains::PSS_ROTATE_KEYS;
use crate::result::{ResultSignature, result_signature_verifies};
use crate::signing_keys::SigningKeys;
use crate::shared_onchain::SharedOnchain;
use crate::signing_keys::RetiresEncKeys;
use aztec::context::{PrivateContext, PublicContext};
use aztec::protocol::abis::function_selector::FunctionSelector;
use aztec::protocol::traits::{Deserialize, Packable, Serialize, ToField};
use aztec::protocol::utils::{reader::Reader, writer::Writer};
use aztec::utils::WithHash;
use std::embedded_curve_ops::EmbeddedCurvePoint;
use total::hash::p2_hash;

/// The public-storage slot of a contract's `NodeKeys`: ASCII
/// "pss.node_keys" read big-endian, far from the slots an app's `#[storage]`
/// assigns (small integers) and from a map's derived slots (hashes). The
/// value takes `NODE_KEYS_LEN` slots from here and its hash the next one.
/// sidecar-tip's chain reader and pss-client read it here.
pub global NODE_KEYS_SLOT: Field = 0x7073732e6e6f64655f6b657973;

/// The packed length of `NodeKeys` in fields (`WithHash` stores its hash at
/// `NODE_KEYS_SLOT + NODE_KEYS_LEN`).
pub global NODE_KEYS_LEN: u32 = 21;

/// A key set: node i's `sig` and `enc` public keys (Grumpkin) at index i.
#[derive(Deserialize, Eq, Packable, Serialize)]
pub struct KeySet {
    pub sig: [EmbeddedCurvePoint; NODES],
    pub enc: [EmbeddedCurvePoint; NODES],
}

/// A contract's key epoch: the epoch number, the block the rotation landed
/// in, the grace window in blocks, its key set and the previous epoch's
/// `sig` keys (accepted for `grace` blocks after `rotated_at`). Epoch 0
/// (nothing stored) is the constructor's `sig` keys with no previous set.
/// The members the public check reads come first (`NodeKeysHead`).
#[derive(Deserialize, Eq, Packable, Serialize)]
pub struct NodeKeys {
    pub epoch: u32,
    pub rotated_at: u32,
    pub grace: u32,
    pub sig: [EmbeddedCurvePoint; NODES],
    pub enc: [EmbeddedCurvePoint; NODES],
    pub previous: [EmbeddedCurvePoint; NODES],
}

/// The head of `NodeKeys`: its first packed fields, all `assert_epoch`
/// reads of it. Keep these first, in this order: the check reads these
/// three fields alone (`read_stored_head`).
#[derive(Deserialize, Eq, Packable, Serialize)]
pub struct NodeKeysHead {
    pub epoch: u32,
    pub rotated_at: u32,
    pub grace: u32,
}

/// The zero point, the storage default of an unset key.
fn zero_point() -> EmbeddedCurvePoint {
    EmbeddedCurvePoint { x: 0, y: 0 }
}

/// Whether `p` is a point of Grumpkin, `y^2 = x^3 - 17` (which excludes the
/// zero point).
pub fn on_curve(p: EmbeddedCurvePoint) -> bool {
    p.y * p.y == p.x * p.x * p.x - 17
}

impl NodeKeys {
    /// What an unset slot reads as: epoch 0 under the constructor's `sig`
    /// keys `set0`, no `enc` keys and no previous set.
    pub fn epoch_zero(set0: [EmbeddedCurvePoint; NODES]) -> Self {
        NodeKeys {
            epoch: 0,
            rotated_at: 0,
            grace: 0,
            sig: set0,
            enc: [zero_point(); NODES],
            previous: [zero_point(); NODES],
        }
    }

    /// The head the public check reads (`NodeKeysHead`).
    pub fn head(self) -> NodeKeysHead {
        NodeKeysHead { epoch: self.epoch, rotated_at: self.rotated_at, grace: self.grace }
    }

    /// The stored value, or epoch 0 under `set0` when nothing is stored (a
    /// stored value always has an epoch of at least 1).
    fn or_epoch_zero(self, set0: [EmbeddedCurvePoint; NODES]) -> Self {
        if self.epoch == 0 {
            NodeKeys::epoch_zero(set0)
        } else {
            self
        }
    }
}

/// The grace window of the previous epoch, in blocks: the namespace's
/// `stale_blocks` (no head outlives it, so a longer window buys nothing),
/// or `DEFAULT_STALE_BLOCKS` when skipping is disabled (no stale period to
/// take; heads then wait for ever, and a result signed under the old set
/// that has not landed by then is recomputed under the new one).
pub fn grace_blocks(stale_blocks: StaleBlocks) -> u32 {
    if stale_blocks.enabled {
        stale_blocks.blocks
    } else {
        DEFAULT_STALE_BLOCKS
    }
}

/// `H(keys)`: the Poseidon2 of the six points' coordinates, node by node,
/// `sig` before `enc`.
pub fn keys_hash(keys: KeySet) -> Field {
    let mut fields = [0; 4 * NODES];
    for i in 0..NODES {
        fields[4 * i] = keys.sig[i].x;
        fields[4 * i + 1] = keys.sig[i].y;
        fields[4 * i + 2] = keys.enc[i].x;
        fields[4 * i + 3] = keys.enc[i].y;
    }
    p2_hash(fields)
}

/// The message two of the current nodes sign to move `namespace` to `epoch`
/// under `keys`: `poseidon2([PSS_ROTATE_KEYS, namespace, epoch, H(keys)])`.
pub fn rotation_message(namespace: Field, epoch: u32, keys: KeySet) -> Field {
    p2_hash([PSS_ROTATE_KEYS, namespace, epoch as Field, keys_hash(keys)])
}

/// This contract's `NodeKeys` at the anchor block of the private function
/// (one historical public-storage read, of the value's hash), or epoch 0
/// under `set0` (`TipConfig::node_sig_keys`) when none is stored.
pub fn at_anchor(context: &mut PrivateContext, set0: [EmbeddedCurvePoint; NODES]) -> NodeKeys {
    let header = context.get_anchor_block_header();
    let stored: NodeKeys = WithHash::<NodeKeys, NODE_KEYS_LEN>::historical_public_storage_read(
        header,
        context.this_address(),
        NODE_KEYS_SLOT,
    );
    stored.or_epoch_zero(set0)
}

/// The stored `NodeKeys` in public, read whole (`install`, the app's
/// `get_node_keys`; epoch 0 has no stored value and reads as all zeros:
/// epoch 0, no previous set).
pub fn stored(context: PublicContext) -> NodeKeys {
    read_stored_head::<NodeKeys, NodeKeys, NODE_KEYS_LEN, NODE_KEYS_LEN>(context, NODE_KEYS_SLOT)
}

/// Whether node i's signature verifies under `keys[i]` over `messages[i]`
/// for every node: the hint of `signing_keys`, run unconstrained.
unconstrained fn all_verify(
    keys: [EmbeddedCurvePoint; NODES],
    messages: [Field; NODES],
    signatures: [ResultSignature; NODES],
) -> bool {
    let mut all = true;
    for i in 0..NODES {
        all &= result_signature_verifies(keys[i], signatures[i], messages[i]);
    }
    all
}

/// Enqueue the app's `assert_key_epoch(epoch, current_only)` (`assert_epoch`
/// in public) on this contract.
pub fn enqueue_epoch_check(context: &mut PrivateContext, epoch: u32, current_only: bool) {
    let selector = comptime { FunctionSelector::from_signature("assert_key_epoch(u32,bool)") };
    context.call_public_function(
        context.this_address(),
        selector,
        [epoch as Field, current_only as Field],
        false,
    );
}

/// The `sig` keys to verify the three node signatures of a private function
/// under: the anchor's current set, or the previous set when the signatures
/// verify under it and not under the current one (they were made before
/// the rotation). Enqueues the public check of the chosen epoch
/// (`assert_epoch`), which refuses an epoch older than the one before the
/// stored one, or the one before after its grace window. `set0` is the
/// app's stored `TipConfig::node_sig_keys` (epoch 0), `messages[i]` node i's
/// message and `signatures[i]` its signature. The caller then verifies
/// every signature under the returned keys (its own assertions name the
/// failing node); only the choice of set is a hint.
pub fn signing_keys(
    context: &mut PrivateContext,
    set0: [EmbeddedCurvePoint; NODES],
    messages: [Field; NODES],
    signatures: [ResultSignature; NODES],
) -> [EmbeddedCurvePoint; NODES] {
    let node_keys = at_anchor(context, set0);
    // Safety: a hint. The caller verifies the signatures under the chosen
    // set with constraints, and the enqueued check binds the chosen epoch, so
    // a wrong choice can only fail the transaction.
    let current = unsafe { all_verify(node_keys.sig, messages, signatures) };
    let previous = !current & (node_keys.epoch != 0);
    let epoch = node_keys.epoch - (previous as u32);
    enqueue_epoch_check(context, epoch, false);
    if previous {
        node_keys.previous
    } else {
        node_keys.sig
    }
}

/// The current epoch's `sig` key of node `i` at the anchor block, for a
/// message only the current set may sign (a node's own `enc` rotation, no
/// grace); enqueues the public check that the epoch is still the stored one.
pub fn current_sig_key(
    context: &mut PrivateContext,
    set0: [EmbeddedCurvePoint; NODES],
    i: u32,
) -> EmbeddedCurvePoint {
    let node_keys = at_anchor(context, set0);
    enqueue_epoch_check(context, node_keys.epoch, true);
    node_keys.sig[i]
}

/// Key epochs as the `node_keys` brick (`crate::signing_keys::SigningKeys`):
/// `signing_keys` and `current_sig_key` above. An app names it in its round
/// table rows and its state view and declares `rotate_keys`,
/// `set_node_keys`, `assert_key_epoch` and `get_node_keys`. `E` is the
/// node `enc` keys the contract holds (`EncKeys`), the one value
/// `set_node_keys` hands `install`, so the choice is made once, in the
/// app's `Keys` alias: secret-shared on-chain intake takes only
/// `KeyEpochs<SharedOnchain<PublicContext>>`
/// (`signing_keys::RetiresEncKeys`), and `install` takes only an `E`. No
/// field: the ABI names the brick by its path alone, whatever `E`.
pub struct KeyEpochs<E> {}

impl<E> Serialize for KeyEpochs<E> {
    let N: u32 = 0;

    fn serialize(_self: Self) -> [Field; 0] {
        []
    }

    fn stream_serialize<let L: u32>(_self: Self, _writer: &mut Writer<L>) {}
}

impl<E> Deserialize for KeyEpochs<E> {
    let N: u32 = 0;

    fn deserialize(_fields: [Field; 0]) -> Self {
        KeyEpochs {}
    }

    fn stream_deserialize<let L: u32>(_reader: &mut Reader<L>) -> Self {
        KeyEpochs {}
    }
}

impl<E> Eq for KeyEpochs<E> {
    fn eq(_self: Self, _other: Self) -> bool {
        true
    }
}

impl<E> SigningKeys for KeyEpochs<E> {
    fn signing_keys(
        context: &mut PrivateContext,
        set0: [EmbeddedCurvePoint; NODES],
        messages: [Field; NODES],
        signatures: [ResultSignature; NODES],
    ) -> [EmbeddedCurvePoint; NODES] {
        crate::key_epoch::signing_keys(context, set0, messages, signatures)
    }

    fn current_sig_key(
        context: &mut PrivateContext,
        set0: [EmbeddedCurvePoint; NODES],
        i: u32,
    ) -> EmbeddedCurvePoint {
        crate::key_epoch::current_sig_key(context, set0, i)
    }
}

/// The body of the app's `assert_key_epoch` (`#[only_self]`, enqueued by
/// `signing_keys`): `epoch` is the stored epoch, or (unless `current_only`)
/// the one before it while the block is at most `rotated_at + grace`.
/// It reads the stored value's head alone (`NodeKeysHead`, three storage
/// reads).
pub fn assert_epoch(context: PublicContext, epoch: u32, current_only: bool) {
    let node_keys = read_stored_head::<NodeKeysHead, NodeKeys, 3, NODE_KEYS_LEN>(
        context,
        NODE_KEYS_SLOT,
    );
    let at_current = epoch == node_keys.epoch;
    // the block bound, written so that no u32 overflows: grace and
    // rotated_at are block numbers and a stale period
    let in_grace =
        context.block_number() as u64 <= node_keys.rotated_at as u64 + node_keys.grace as u64;
    let at_previous = !current_only & (epoch as u64 + 1 == node_keys.epoch as u64) & in_grace;
    assert(at_current | at_previous, "key epoch expired");
}

/// The private half of `rotate_keys`: `epoch` is the anchor's epoch + 1,
/// every key of `keys` is a Grumpkin point, and at least two of the anchor's
/// current nodes signed `rotation_message(this contract, epoch, keys)`,
/// each in its own place (`signatures[i]` under `sig_i`; a missing signature
/// is all zeros and never verifies). Returns the `NodeKeys` the app's
/// `set_node_keys` installs (`install`), with the anchor's current `sig`
/// keys as the previous set and the grace window from `config`'s
/// `stale_blocks`. Open to anyone: the node or the orchestrator submits it,
/// once per namespace.
///
/// Each node keeps a key of its own: a set that repeats a `sig` key would
/// let one key make every result signature and the next rotation alone, and
/// one that repeats an `enc` key would let one key open two nodes' shares,
/// which together open every secret-shared input; both are refused.
///
/// What it does not do: check that the departed node is gone, or which
/// node the new set replaces. One rotation may replace any subset of the
/// six keys; two colluding nodes can rotate the third out (they already
/// open every shared value, DESIGN.md "the trust boundary").
pub fn check_rotation(
    context: &mut PrivateContext,
    config: TipConfig,
    epoch: u32,
    keys: KeySet,
    signatures: [ResultSignature; NODES],
) -> NodeKeys {
    let current = at_anchor(context, config.node_sig_keys);
    assert(epoch as u64 == current.epoch as u64 + 1, "the epoch is not the current epoch + 1");
    for i in 0..NODES {
        assert(on_curve(keys.sig[i]), "a sig key of the new set is not a Grumpkin point");
        assert(on_curve(keys.enc[i]), "an enc key of the new set is not a Grumpkin point");
    }
    assert(all_distinct(keys.sig), "the new set repeats a sig key");
    assert(all_distinct(keys.enc), "the new set repeats an enc key");
    let message = rotation_message(context.this_address().to_field(), epoch, keys);
    let mut signed = 0;
    for i in 0..NODES {
        if result_signature_verifies(current.sig[i], signatures[i], message) {
            signed += 1;
        }
    }
    assert(signed >= 2, "a key set rotation needs two current node signatures");
    NodeKeys {
        epoch,
        rotated_at: 0,
        grace: grace_blocks(config.stale_blocks),
        sig: keys.sig,
        enc: keys.enc,
        previous: current.sig,
    }
}

/// Whether the three keys are pairwise different.
fn all_distinct(keys: [EmbeddedCurvePoint; NODES]) -> bool {
    (keys[0] != keys[1]) & (keys[0] != keys[2]) & (keys[1] != keys[2])
}

/// The node `enc` keys a contract holds on chain, which a key-set rotation
/// must update with the key set: `SharedOnchain` (secret-shared on-chain
/// intake), whose `void_replaced` voids every node's stored key that the new
/// set replaces, or `NoEncKeys`, for a contract that holds none. The app's
/// `KeyEpochs<E>` names one and `KeyEpochs::install` takes that one, so a
/// contract cannot install a new key set and leave a replaced node's `enc`
/// key accepted by new requests.
pub trait EncKeys {
    /// Update the stored `enc` keys for the new set's `enc` keys.
    fn void_replaced(self, enc: [EmbeddedCurvePoint; NODES]);
}

/// A contract that holds no node `enc` keys (no secret-shared on-chain
/// intake): a rotation changes nothing else.
pub struct NoEncKeys {}

impl EncKeys for NoEncKeys {
    fn void_replaced(_self: Self, _enc: [EmbeddedCurvePoint; NODES]) {}
}

/// Rotation voids a replaced node's stored `enc` key (`SharedOnchain`'s
/// `void_replaced`): the key epochs secret-shared on-chain intake takes.
impl RetiresEncKeys for KeyEpochs<SharedOnchain<PublicContext>> {}

impl<E> KeyEpochs<E>
where
    E: EncKeys,
{
    /// The body of the app's `set_node_keys` (`#[only_self]`, enqueued by
    /// `rotate_keys` after `check_rotation`), called as `Keys::install`:
    /// `node_keys.epoch` must be the stored epoch + 1, so a replayed rotation
    /// and a rotation checked against a stale anchor both revert; the new
    /// value is stored with `rotated_at` the current block, and the `enc`
    /// keys the contract holds, `enc_keys` of the type the app's `Keys`
    /// names, are updated with it (`EncKeys::void_replaced`).
    pub fn install(context: PublicContext, node_keys: NodeKeys, enc_keys: E) {
        let held = stored(context);
        assert(
            node_keys.epoch as u64 == held.epoch as u64 + 1,
            "the epoch is not the stored epoch + 1",
        );
        let installed = NodeKeys {
            epoch: node_keys.epoch,
            rotated_at: context.block_number(),
            grace: node_keys.grace,
            sig: node_keys.sig,
            enc: node_keys.enc,
            previous: node_keys.previous,
        };
        context.storage_write(NODE_KEYS_SLOT, WithHash::new(installed));
        enc_keys.void_replaced(node_keys.enc);
    }
}

mod test {
    use super::{grace_blocks, KeySet, keys_hash, NODE_KEYS_LEN, NodeKeys, NodeKeysHead, rotation_message};
    use crate::config::StaleBlocks;
    use crate::configure::is_head_of;
    use crate::domains::PSS_ROTATE_KEYS;
    use aztec::protocol::traits::Packable;
    use std::embedded_curve_ops::EmbeddedCurvePoint;
    use total::hash::p2_hash;

    fn point(k: Field) -> EmbeddedCurvePoint {
        EmbeddedCurvePoint { x: k, y: k + 1 }
    }

    fn keys() -> KeySet {
        KeySet { sig: [point(1), point(3), point(5)], enc: [point(7), point(9), point(11)] }
    }

    // NODE_KEYS_LEN is the packed length WithHash stores the value in.
    #[test]
    fn the_packed_length_is_node_keys_len() {
        let packed = NodeKeys::epoch_zero(keys().sig).pack();
        assert_eq(packed.len(), NODE_KEYS_LEN);
    }

    // The public check reads the first three packed fields as the head:
    // epoch, rotated_at, grace, then the key sets.
    #[test]
    fn the_head_leads_node_keys() {
        let mut node_keys = NodeKeys::epoch_zero(keys().sig);
        node_keys.epoch = 2;
        node_keys.rotated_at = 40;
        node_keys.grace = 10;
        assert(is_head_of(node_keys.head(), node_keys));
        let packed = node_keys.pack();
        assert_eq([packed[0], packed[1], packed[2], packed[3], packed[4]], [2, 40, 10, 1, 2]);
        let other = NodeKeysHead { epoch: 2, rotated_at: 40, grace: 11 };
        assert(!is_head_of(other, node_keys));
    }

    // H(keys) takes the coordinates node by node, sig before enc, and the
    // message puts the epoch before it.
    #[test]
    fn the_rotation_message_layout() {
        let h = p2_hash([1, 2, 7, 8, 3, 4, 9, 10, 5, 6, 11, 12]);
        assert_eq(keys_hash(keys()), h);
        assert_eq(rotation_message(0x2a, 1, keys()), p2_hash([PSS_ROTATE_KEYS, 0x2a, 1, h]));
        // the machine's value (sidecar-core key_epoch
        // `the_rotation_message_is_the_contracts`)
        assert_eq(
            rotation_message(0x2a, 1, keys()),
            0x1731f2cc82d3d4f8a29ccbe697a04bf1ba45a6a681ce23b7c9aa16b5144bf05b,
        );
        assert(rotation_message(0x2a, 2, keys()) != rotation_message(0x2a, 1, keys()));
        assert(rotation_message(0x2b, 1, keys()) != rotation_message(0x2a, 1, keys()));
    }

    #[test]
    fn the_grace_window_is_the_stale_period() {
        assert_eq(grace_blocks(StaleBlocks::after(7)), 7);
        assert_eq(grace_blocks(StaleBlocks::disabled()), 50);
    }
}
