//! What tests of the tip and of its consumers (the scheduler, the chain
//! verifier, the receipt route) share (feature `test-util`): the reader's
//! transports ([`FixtureTransport`] over recorded bodies, [`MemoryChain`] an
//! in-memory Aztec node over [`MemoryNode`]'s blocks and logs), and one
//! node's rows as the chain verifier reads them ([`Rows`]), and the shared
//! manifests and rounds ([`AMM_SWAP_TIP`], [`shared_package`], and
//! secret-shared on-chain intake's request, [`shared_onchain`]).

mod fixtures;
mod node;
mod rows;
pub mod shared_onchain;
mod transports;

pub use fixtures::{
    AMM_SWAP_TIP, AMM_SWAP_TIP_ABI, SHARED_RECEIPT_ROUND, SUMMAND_SALT_SEED, amm_swap_tip_abi,
    shared_circuit_abi, shared_package, shared_values, sharing, summand_salts,
};
pub use node::MemoryNode;
pub use rows::Rows;
pub use transports::{FixtureTransport, MEMORY_CLASS_ID, MemoryChain};

/// The timestamp of block `number` on the in-memory node: one block every
/// 36 s from 1,000,000 (the header's `globalVariables.timestamp`).
pub fn block_timestamp(number: u64) -> u64 {
    1_000_000 + 36 * number
}
