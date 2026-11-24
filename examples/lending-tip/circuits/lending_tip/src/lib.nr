//! Lending with liquidation at the tip of the chain: what its round
//! circuits compute, as one library so that the queued rounds (deposit,
//! borrow, repay, view, liquidate, scan) and the init round share one book
//! layout and one table of failure codes, on pss_core's tree-valued key
//! (`tip::tree`).
//!
//! The book is node-held (docs/ARCHITECTURE.md section 6, "Tree-valued
//! keys" and "The examples on node-held state"): a Poseidon2 Merkle tree of
//! depth DEPTH whose leaf 0 is the market's header and whose other leaves
//! are positions, the nodes holding the leaves as Rep3 pairs and the tree
//! of hashes in the clear. On chain it is one commitment to the root, in one
//! public slot of the app contract; every round outputs the commitment it
//! read (`old_c`, the manifest's commitment_slot old), the one it leaves
//! (`new_c`, the key's outputs[].note_hash) and the new hashes of the leaves
//! it touched, and hands those leaves to the machine through TACEO_store.
//!
//! - market.nr: the layout, the capacity (DEPTH, PROBES, WINDOW), the
//!   constants, the failure codes and the arithmetic every round goes
//!   through.
//! - rounds.nr: the total rounds (deposit, borrow, repay, view,
//!   liquidate, scan), one source for every intake, and the init's book.
//! - shared.nr: what a round adds under a secret-shared intake (the C check of
//!   pss_core's `SharedIntake`, the re-blinding writes, the private
//!   outcome completing the user's partial note).
//! - entry.nr: one entry per round, the one call each round's main makes,
//!   generic over the main's intake family and access (`Family`).
//!
//! No round checks ownership: the app's private request function opens the
//! requester's own completed note of a position before it queues a request
//! on it (docs/ARCHITECTURE.md section 6, "Ownership by note"), so the rounds
//! never see an owner.
pub mod entry;
pub mod market;
pub mod rounds;
pub mod shared;
