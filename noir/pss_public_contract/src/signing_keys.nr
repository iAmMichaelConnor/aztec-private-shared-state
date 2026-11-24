//! The `node_keys` axis (docs/design-guide/README.md section 14, "Node keys"):
//! where the `sig` keys a node signature is checked under come from. One
//! trait, `SigningKeys`, with one implementation per brick:
//!
//! - `crate::key_epoch::KeyEpochs` (key epochs, rotating): the contract's
//!   current key epoch at the anchor block, or the previous one inside its
//!   grace window, with the public epoch check enqueued;
//! - `FixedKeys` (here, the fixed key set): the constructor's keys
//!   (`TipPins::node_sig_keys`) for the life of the contract, nothing read
//!   and nothing enqueued.
//!
//! The app names its brick once, as the last type parameter of its round
//! table rows (`TipRound<C, R, W, K>`); every library entry point that takes
//! a row checks the node signatures under `K`, and `check_enc_rotation`,
//! which takes no row, takes it by turbofish. The choice is made at compile
//! time: an app on `FixedKeys` compiles none of `key_epoch`'s code, reads no
//! key-epoch slot and declares none of `rotate_keys`, `set_node_keys`,
//! `assert_key_epoch` or `get_node_keys`:
//!
//! ```noir
//! pub fn queued_round<C>(tip: Configured<PACKAGES>, ledger: CommitmentSlot<C>, round: u32)
//!     -> TipRound<C, 1, 1, FixedKeys> {
//!     tip.round(CREDITS_PACKAGES[round], StateKeys::one(ledger))
//! }
//! ```
//!
//! Each brick is a struct with no fields, and the app's state view reports
//! it (`crate::view::TipState::node_keys`): the contract manifest generator
//! reads the `node_keys` value from the brick's path in the artifact
//! (pss-client `bricks.ts`), never from the app's function names.
//!
//! Either way the caller verifies all three signatures under the returned
//! keys with constraints, so the brick chooses which keys, never whether
//! the signatures are checked (invariant 0). A contract with a fixed key set
//! never writes the key-epoch slot, so the machine and the clients read it
//! as key epoch 0, the constructor's keys, for good; after a node
//! replacement its app is redeployed (docs/ARCHITECTURE.md section 6, "Node
//! replacement and key epochs").
use crate::config::NODES;
use crate::result::ResultSignature;
use aztec::context::PrivateContext;
use aztec::protocol::traits::{Deserialize, Serialize};
use std::embedded_curve_ops::EmbeddedCurvePoint;

/// Where a private function takes the `sig` keys it verifies node
/// signatures under. `set0` is the app's stored `TipConfig::node_sig_keys`,
/// the constructor's keys, never an argument of the caller's.
pub trait SigningKeys {
    /// The keys to verify the three node signatures under: node i's
    /// signature `signatures[i]` over `messages[i]`. Only the choice of keys
    /// may be a hint; the caller verifies every signature under the returned
    /// keys, and its assertions name the failing node.
    fn signing_keys(
        context: &mut PrivateContext,
        set0: [EmbeddedCurvePoint; NODES],
        messages: [Field; NODES],
        signatures: [ResultSignature; NODES],
    ) -> [EmbeddedCurvePoint; NODES];

    /// Node `i`'s `sig` key for a message only the current set may sign (a
    /// node's own `enc` rotation, no grace window).
    fn current_sig_key(
        context: &mut PrivateContext,
        set0: [EmbeddedCurvePoint; NODES],
        i: u32,
    ) -> EmbeddedCurvePoint;
}

/// A `node_keys` brick under which no node's `enc` key stays accepted after
/// the key set replaces that node: what secret-shared on-chain intake needs,
/// since a request encrypts to the `enc` keys the contract stores
/// (`shared_onchain::SharedOnchainArgs` and `shared_onchain_request` take
/// only such a brick). `FixedKeys` (no rotation replaces a node) and
/// `KeyEpochs<SharedOnchain<PublicContext>>` (every rotation voids a
/// replaced node's stored key, `key_epoch::EncKeys`) are; `KeyEpochs<NoEncKeys>`
/// is not, so a contract with that intake cannot name it.
pub trait RetiresEncKeys {}

/// The fixed key set: the constructor's `sig` keys for the life of the
/// contract. No storage, no rotation and no enqueued epoch check.
#[derive(Deserialize, Eq, Serialize)]
pub struct FixedKeys {}

impl RetiresEncKeys for FixedKeys {}

impl SigningKeys for FixedKeys {
    fn signing_keys(
        _context: &mut PrivateContext,
        set0: [EmbeddedCurvePoint; NODES],
        _messages: [Field; NODES],
        _signatures: [ResultSignature; NODES],
    ) -> [EmbeddedCurvePoint; NODES] {
        set0
    }

    fn current_sig_key(
        _context: &mut PrivateContext,
        set0: [EmbeddedCurvePoint; NODES],
        i: u32,
    ) -> EmbeddedCurvePoint {
        set0[i]
    }
}
