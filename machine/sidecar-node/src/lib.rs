//! The node process of the co-SNARK sidecar, around `sidecar-core`: its
//! configuration (`config`), the pinned-TLS Rep3 mesh and the node-wide mesh
//! session lock (`mesh`), the session handshake carried over the mesh
//! (`session`, the one session type, opened with or without the handshake),
//! the development TLS material (`certs`) and the node's private
//! directories and whole-file writes (`files`). The process
//! shell: the HTTPS API over mutual TLS (`api`, on the listener, TLS set-up
//! and client of sidecar-http, re-exported as `tls` and `client`), the
//! operator-only admin socket (`admin`, its socket plumbing sidecar-http's),
//! key setup (`setup`),
//! the store behind the config's backend (`backend`: memory, Postgres
//! (`postgres`) or the local store of sidecar-core, re-exported as `local`), the running node
//! (`server`), the rotation of its `enc` key (`rotation`), node recovery
//! on the admin socket (`recovery`: the resync from the neighbours, the
//! restore of a backup and the audit), node replacement (`replace`: the
//! share refresh, the newcomer's import and the signed key-set rotation), the
//! backup files of the store and the
//! key directory (`backup`), and the tip's receipt signer (`receipt`). Test support, behind the `test-util` feature:
//! loopback ports reserved for test meshes (`testing`).

pub mod admin;
pub mod api;
pub mod backend;
pub mod backup;
pub mod certs;
pub mod config;
mod files;
pub mod mesh;
pub mod postgres;
pub mod receipt;
pub mod recovery;
pub mod replace;
pub mod rotation;
pub mod server;
pub mod session;
pub mod setup;
#[cfg(feature = "test-util")]
pub mod testing;

pub use config::NodeConfig;
pub use mesh::{Mesh, MeshConfig, NodeNetwork};
pub use session::{Session, open_session};
pub use sidecar_core::local;
pub use sidecar_http::{client, tls};

// The stores' row codec, shared with the local store in sidecar-core.
use sidecar_core::codec;
