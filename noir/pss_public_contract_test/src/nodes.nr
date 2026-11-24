//! The test network (the shared test crate's: testvectors/keys.json's node
//! keys and the test-only Schnorr signer) and the test contract's own pins.
pub use pss_tip_test::nodes::{NODE_SIG, NODE_SIG_PK, OUTSIDER_SIG, public_key, receipts, sign, sign_result};
use pss_public_contract::{StaleBlocks, TipConfig};

/// The vk hashes the test contract pins for its pool round, one circuit for
/// both non-secret-shared intakes, and its node-held round (stand-ins: no circuit runs
/// in these tests).
pub global VK_HASH: Field = 0x0f1e2d3c4b5a6978;
pub global HELD_VK_HASH: Field = 0x0f1e2d3c4b5a6979;

/// The network identity the test contract pins (a stand-in: no round runs
/// in these tests).
pub global NPK_APP_HASH: Field = 0x9b9b;

pub fn tip_config(stale_blocks: StaleBlocks) -> TipConfig {
    pss_tip_test::tip_config(stale_blocks, NPK_APP_HASH)
}
