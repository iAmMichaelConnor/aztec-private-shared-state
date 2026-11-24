//! The deployment pins of a tip app that the library reads.
use aztec::protocol::traits::{Deserialize, Packable, Serialize};
use std::embedded_curve_ops::EmbeddedCurvePoint;

/// The number of nodes in a network: three, by the scheme (Rep3 has three
/// parties). Every per-node array (signatures, receipts, `sig` keys, sealed
/// thirds) has this length; the checks that name the failing node are
/// written out once per node.
pub global NODES: u32 = 3;

/// The stale period the manifests default to, in L2 blocks: about five
/// minutes at one proposed block every 6 s.
pub global DEFAULT_STALE_BLOCKS: u32 = 50;

/// How long the head may sit before anyone may `skip()` it: the manifest's
/// `stale_blocks`, a number of L2 blocks or null.
///
/// The constructor takes the manifests' value at deployment (`TipPins`;
/// default `DEFAULT_STALE_BLOCKS`, 50 L2 blocks), and it never changes. The
/// nodes check it: REGISTER refuses a queued package whose `stale_blocks`
/// differs from the namespace's other queued packages, and each node's
/// chain verifier reads the stored value and refuses every queued round
/// while it differs from the manifest's. So the scheduler, the relayer's
/// `skip()` and the receipt pruning (after `expiry_block + stale_blocks`)
/// all run on the value this contract enforces. It is the longest a
/// request may block the queue when the network does not answer (a crashed
/// node, a round the network refuses), and the shortest time the network
/// has to land a result before anyone may drop the request. Shorter: a
/// silent network stalls the app for less time, but a slow round (proof
/// plus the result transaction, a few blocks at the measured 4 to 5 s per
/// round) can be skipped by anyone before it lands, and its proof is
/// wasted; 0 lets anyone skip every request in the block it is queued in.
/// Longer: fewer wasted rounds, longer stalls.
///
/// null disables skipping (`StaleBlocks::disabled()`, the manifest's
/// `"stale_blocks": null`); skipping is enabled unless the manifest says
/// null. It suits a queue where a frozen queue is better than a dropped
/// request, for example where every request must run in order or not at
/// all: while the network cannot answer the head, nothing behind it runs,
/// and the only way forward is a result for the head; there is no operator
/// override. The app chooses it in the manifest's `stale_blocks` (design
/// guide: "stale_blocks").
#[derive(Deserialize, Eq, Packable, Serialize)]
pub struct StaleBlocks {
    /// false is the manifest's null: `skip()` always reverts
    pub enabled: bool,
    /// the stale period in L2 blocks; ignored when `enabled` is false
    pub blocks: u32,
}

impl StaleBlocks {
    /// Skipping allowed once the head has sat `blocks` L2 blocks.
    pub fn after(blocks: u32) -> Self {
        StaleBlocks { enabled: true, blocks }
    }

    /// Skipping disabled (the manifest's `"stale_blocks": null`).
    pub fn disabled() -> Self {
        StaleBlocks { enabled: false, blocks: 0 }
    }
}

/// The tip pins the intake, result and init bodies read: the stale policy
/// and the network's three `sig` public keys, node 0 first, which receipt
/// intake checks receipts against and the result transaction checks result
/// signatures against (the constructor's `TipPins`), the namespace's
/// `npk_app_hash`, which the result transaction feeds to the co-SNARK (the
/// one `configure` checked). An app takes it from its stored `Configured`
/// (`Configured::config`, through its round table), never from a caller's
/// argument, or a caller chooses its own stale period and skips any head
/// at once, or signs its own receipts and results.
///
/// The node `sig` keys here are key epoch 0, the constructor's. The keys a
/// signature is checked under come from the app's `node_keys` brick
/// (`crate::signing_keys`): under a fixed key set these, for good; under key
/// epochs the contract's current key epoch (`crate::key_epoch`), epoch 0
/// until two of the current nodes sign a new key set (`rotate_keys`, a node
/// replacement), then that set, with the previous one accepted for a grace
/// window. The node `enc` keys are not
/// pinned: no contract function needs one at deployment (chain-held thirds
/// are sealed by the nodes, and the non-secret-shared intakes encrypt
/// nothing in the user's private function). Secret-shared on-chain intake, which
/// does, keeps each node's current `enc` key in public storage that the node
/// rotates (DECISIONS.md, "Secret-shared on-chain intake"), not a pin here; a
/// key-set rotation voids a replaced node's key there. Chain-held state
/// follows an `enc` rotation only through an `apply` within the grace
/// window: see the sealed-thirds log, `chain_state::emit_state_log`.
#[derive(Deserialize, Eq, Packable, Serialize)]
pub struct TipConfig {
    pub stale_blocks: StaleBlocks,
    /// node i's `sig` public key (Grumpkin) of key epoch 0, as GET /v1/nodes
    /// listed it when the contract was deployed
    pub node_sig_keys: [EmbeddedCurvePoint; NODES],
    /// The network pin: the value the namespace's REGISTER
    /// answers carry, whose three node signatures `configure` checked;
    /// `process_result` feeds it to the co-SNARK as the `npk_app_hash`
    /// public input, so only a round of the network that holds this
    /// namespace's nsk_app verifies (a round on chain-held state nullifies
    /// nothing, so this, the vk pin and the node signatures are what tie a
    /// proof to the network). Fixed once by `configure`: a new network is a
    /// new deployment.
    pub npk_app_hash: Field,
}
