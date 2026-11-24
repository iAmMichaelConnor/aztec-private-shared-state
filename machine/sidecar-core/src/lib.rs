//! The chain-agnostic core of the co-SNARK sidecar: the JSON wire types of both
//! legs (client to orchestrator, orchestrator to node), the field-element encoding,
//! the manifest, the error classes, the Poseidon2 helpers and the admission hook.
//!
//! It also holds the proving core both services share: the CRS and verification
//! keys (`crs`) and EXECUTE and VERIFY over the party mesh (`executor`), generic
//! over the mesh transport. And the node's state core: its keys (`keys`), the
//! field-native authenticated encryption (`ae`), sealed state records
//! (`record`), the state-holder seam with the client- and node-held
//! implementations (`state`), the store trait with its rules and
//! in-memory backend (`store`), the local append-only store on the same
//! tables (`local`), and the byte codec of the stores' rows (`codec`). And the request lifecycle that ties them together
//! (`pipeline`): one library call per execute request, FETCH and the
//! operator rollback, with the intake brick that differs between intake
//! direct and a queued intake (`intake`). And node recovery: the resync of a lost store, or of
//! one tip key, from the two neighbours (`resync`, which carries receipt
//! rows through the node's receipt hook, filled by sidecar-tip), the store
//! export a backup carries and a restore's delta resync takes its pairs from
//! (`backup`), and the audit of node-held tip state (`audit`); and the
//! comparison of registry rows between the three nodes and the
//! orchestrator's copy (`registry_check`).
//! It has no database dependencies and no network transport; sidecar-node
//! and sidecar-orchestrator build on it.

// Field encoding and cryptography.
pub mod ae;
pub mod field;
pub mod grumpkin;
pub mod hash;
pub mod schnorr;

// The wire types of both legs and the error classes.
pub mod error;
pub mod register;
pub mod request;
pub mod response;

// Node keys and their epochs.
pub mod circuit_pins;
pub mod epochs;
pub mod key_epoch;
pub mod keys;

// The manifest and the circuit shapes it is checked against.
pub mod abi;
pub mod manifest;

// Sealed inputs and records, binding, and the state holders.
pub mod bind;
pub mod derived;
pub mod envelope;
pub mod record;
pub mod state;
pub mod tree;

// The store, its backends' codec and the local store; the consumed set and
// the dead records.
pub mod codec;
pub mod consumed;
pub mod dead;
pub mod local;
pub mod store;

// The request lifecycle: proving, the session handshake and admission.
pub mod admit;
pub mod crs;
pub mod executor;
pub mod handshake;
pub mod intake;
pub mod mesh_lock;
pub mod pipeline;

// The registry.
pub mod registry;
pub mod registry_check;

// Recovery: resync, node replacement, backups and the audit.
pub mod audit;
pub mod backup;
pub mod replace;
pub mod resync;

// The three-node test harness.
#[cfg(feature = "testing")]
pub mod testing;

pub use admit::admit;
pub use error::{ErrorClass, Refusal};
pub use field::{FieldHex, Fr, HexBytes, RequestId};
pub use manifest::Manifest;
pub use pipeline::{Node, fetch, restore, run_request, stateless_prefix};
pub use register::{DisableRequest, ManifestMessage, ManifestResponse};
pub use request::{NodeRequest, Request};
pub use response::{ExecuteResponse, FetchRequest, NodeResult, NodesResponse};
