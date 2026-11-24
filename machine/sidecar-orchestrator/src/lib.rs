//! The orchestrator of the co-SNARK sidecar (ARCHITECTURE.md section 1): the
//! public HTTPS API (`api`), the stateless request checks and the global
//! session lock before any fan-out (`gate`: the schedulers first, a bounded
//! public waiting room), the per-node projection and the node leg
//! over mutual TLS (`nodes`), the checks of the three answers and the
//! assembled response (`answer`), and its copy of the registry with the
//! verification keys it computes itself (`registry`), rebuilt from the three
//! nodes when it is lost or behind (`sync`); `status` runs the registry
//! check (at start, after registry bodies, on a timer) and keeps what it
//! found, for `GET /v1/status`; `admin` is the operator's socket that pauses
//! and resumes scheduling around a node replacement. At the tip, `scheduler` drives
//! each configured namespace's queue through the same execute path. It holds
//! no secret and stores nothing the nodes do not also hold. `config` reads
//! its TOML file; `server` runs it.

pub mod admin;
pub mod answer;
pub mod api;
pub mod config;
pub mod gate;
pub mod nodes;
pub mod registry;
pub mod scheduler;
pub mod server;
pub mod status;
pub mod sync;

pub use api::Orchestrator;
pub use config::OrchestratorConfig;
