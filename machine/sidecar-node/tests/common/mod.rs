//! What the node API tests share: `sidecar-test-fixtures` (scratch
//! directories, the prepared data, the requests, the TLS material, meshes and
//! started nodes), re-exported here, a node started on MemoryStore and API
//! clients. `net` is the orchestrator's half over three started nodes.

#![allow(dead_code)]

pub mod net;

use std::path::Path;

use sidecar_core::bind::Share;
use sidecar_core::crs::Crs;
use sidecar_core::keys::NodeKeys;
use sidecar_core::pipeline::Node;
use sidecar_core::store::{MemoryStore, Store};
use sidecar_node::Mesh;
use sidecar_node::client::ApiClient;
use sidecar_node::server::App;
pub use sidecar_test_fixtures::data::*;
pub use sidecar_test_fixtures::dirs::*;
pub use sidecar_test_fixtures::nodes::*;
pub use sidecar_test_fixtures::requests::*;

/// Start node `i` on MemoryStore: the API on a free loopback port with the
/// dev certificates in `certs`, the admin socket in `run_dir`.
pub async fn start_node(
    i: usize,
    keys: NodeKeys,
    master: Share,
    crs: Crs,
    mesh: Mesh,
    certs: &Path,
    run_dir: &Path,
) -> Started {
    let node = Node::new(i, keys, master, MemoryStore::new(), crs).unwrap();
    serve_node(node, mesh, certs, run_dir).await
}

/// Serve `node` (whatever its store): the API on a free loopback port with
/// the dev certificates in `certs`, its keys and admin socket in `run_dir`,
/// no pruning timer.
pub async fn serve_node<S: Store + 'static>(
    node: Node<S>,
    mesh: Mesh,
    certs: &Path,
    run_dir: &Path,
) -> Started<S> {
    let files = key_files(&run_dir.join(format!("keys{}", node.index)), &node.keys());
    serve_app(App::new(node, mesh, rotation(files)), certs, run_dir).await
}

/// A client of `node` with the orchestrator's certificate from `certs`.
pub fn orchestrator<S>(certs: &Path, node: &Started<S>) -> ApiClient {
    orchestrator_client(certs, node.running.api_addr)
}
