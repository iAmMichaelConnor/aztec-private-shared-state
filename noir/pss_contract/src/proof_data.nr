use aztec::protocol::constants::{RECURSIVE_PROOF_LENGTH, ULTRA_VK_LENGTH_IN_FIELDS};
use aztec::protocol::traits::{Deserialize, Serialize};

/// ZK UltraHonk (HONK_ZK). Not exported by protocol constants (the enum
/// slot between ROOT_ROLLUP_HONK=5 and HN_FINAL=7); the proof is 48
/// fields longer than the non-ZK RECURSIVE_PROOF_LENGTH.
pub global PROOF_TYPE_HONK_ZK: u32 = 6;
pub global ZK_PROOF_LENGTH: u32 = RECURSIVE_PROOF_LENGTH + 48; // 458
pub global VK_LENGTH: u32 = ULTRA_VK_LENGTH_IN_FIELDS; // 115

/// Capsule slot for out-of-band (vk, proof) delivery (aztec.js `Capsule`,
/// TXE `capsules::store`); keyed, not order-coupled.
///
/// The slot is a contract-wide constant shared by every PSS
/// call: every `apply` loads from it. A contract that makes two
/// `apply` calls in one tx needs a slot per call. The client must stage
/// the capsule at this slot, under the caller's address as scope.
pub global CAPSULE_SLOT_PROOF: Field = 0x10;

/// The verification key + ZK proof the caller stages as a capsule for each
/// PSS call. A nominal type (rather than two loose arrays) so capsule
/// store/load resolve unambiguously, and so a test crate can build one.
#[derive(Deserialize, Serialize)]
pub struct ProofData {
    pub vk: [Field; VK_LENGTH],
    pub proof: [Field; ZK_PROOF_LENGTH],
}
