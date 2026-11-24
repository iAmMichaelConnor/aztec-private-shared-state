//! Three in-process nodes on any store, each behind its HTTPS API with
//! mutual TLS and its admin socket, over the pinned-TLS mesh on loopback,
//! with the development dealer's keys and certificates; and the TLS material
//! a test's own clients use.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use sidecar_core::crs::Crs;
use sidecar_core::keys::{KeyFiles, NodeKeys};
use sidecar_core::pipeline::Node;
use sidecar_core::request::NODES;
use sidecar_core::store::{MemoryStore, Store};
use sidecar_node::certs::{self, MeshIdentity, mesh_identity};
use sidecar_node::client::{Answer, ApiClient};
use sidecar_node::config::{DEFAULT_ENC_GRACE_DAYS, TlsFiles};
use sidecar_node::rotation::KeyRotation;
use sidecar_node::server::{self, App, Running, StartOptions};
use sidecar_node::{Mesh, MeshConfig, tls};

/// The development TLS material (the `gen-certs` set) in `dir`.
pub fn dev_certs(dir: &Path) -> PathBuf {
    let out = dir.join("certs");
    certs::generate(&out, false).unwrap();
    out
}

/// `keys` written to the key directory `dir` (created): a test node's key
/// files.
pub fn key_files(dir: &Path, keys: &NodeKeys) -> KeyFiles {
    let files = KeyFiles::new(dir);
    files.write(keys).unwrap();
    files
}

/// The enc rotation of a test node over its key directory `files`, with the
/// default grace window: the rotation [`App::new`] takes.
pub fn rotation(files: KeyFiles) -> KeyRotation {
    KeyRotation::new(files, DEFAULT_ENC_GRACE_DAYS * 24 * 60 * 60)
}

/// Node `i`'s API certificate under the development CA.
pub fn node_tls(certs: &Path, i: usize) -> TlsFiles {
    TlsFiles {
        ca: certs.join("https-ca.pem"),
        cert: certs.join(format!("https-node{i}.pem")),
        key: certs.join(format!("https-node{i}-key.pem")),
    }
}

/// The node leg's TLS: the dev CA and the orchestrator's client certificate.
pub fn orchestrator_tls(certs: &Path) -> TlsFiles {
    TlsFiles {
        ca: certs.join("https-ca.pem"),
        cert: certs.join("https-orchestrator.pem"),
        key: certs.join("https-orchestrator-key.pem"),
    }
}

/// A client of the node API at `addr` with the orchestrator's certificate.
pub fn orchestrator_client(certs: &Path, addr: SocketAddr) -> ApiClient {
    let leg = orchestrator_tls(certs);
    let config = tls::client_config(&leg.ca, Some((&leg.cert, &leg.key))).unwrap();
    ApiClient::new(addr, "localhost", config).unwrap()
}

/// POST node i's own body to node i through `clients`, the three at once.
pub async fn post_each(
    clients: &[ApiClient],
    path: &str,
    bodies: [Vec<u8>; NODES],
) -> [Answer; NODES] {
    let [a, b, c] = bodies;
    let (x, y, z) = tokio::join!(
        clients[0].post_raw(path, a),
        clients[1].post_raw(path, b),
        clients[2].post_raw(path, c),
    );
    [x.unwrap(), y.unwrap(), z.unwrap()]
}

/// POST the same bytes to the three nodes through `clients`, at once.
pub async fn post_same(clients: &[ApiClient], path: &str, body: &[u8]) -> [Answer; NODES] {
    post_each(clients, path, [body.to_vec(), body.to_vec(), body.to_vec()]).await
}

/// Three honest meshes on ports reserved for this test process
/// (`sidecar_node::testing::reserve_ports`), each pinning the three
/// certificates.
pub fn meshes() -> [Mesh; NODES] {
    let ids: [MeshIdentity; NODES] = [0, 1, 2].map(|i| mesh_identity(i).unwrap());
    let ports: [u16; NODES] = sidecar_node::testing::reserve_ports();
    [0, 1, 2].map(|i| {
        let bind: SocketAddr = format!("127.0.0.1:{}", ports[i]).parse().unwrap();
        let config = MeshConfig::from_der(
            i,
            bind,
            ports.map(|p| format!("127.0.0.1:{p}")),
            ids[i].key.clone(),
            [0, 1, 2].map(|j| ids[j].cert.clone()),
        )
        .unwrap()
        .with_timeouts(Duration::from_secs(30), Duration::from_secs(600));
        Mesh::new(config)
    })
}

/// A started node and its context.
pub struct Started<S = MemoryStore> {
    pub app: Arc<App<S>>,
    pub running: Running,
}

/// Serve `app` (whatever its store): the API on a free loopback port with
/// the dev certificates in `certs`, the admin socket at
/// `run_dir/n<i>/admin.sock`, no pruning timer.
pub async fn serve_app<S: Store + 'static>(
    app: App<S>,
    certs: &Path,
    run_dir: &Path,
) -> Started<S> {
    let i = app.node.index;
    let app = Arc::new(app);
    let running = server::start(
        app.clone(),
        StartOptions {
            api_listen: "127.0.0.1:0".parse().unwrap(),
            tls: tls::server_config(&node_tls(certs, i)).unwrap(),
            admin_socket: run_dir.join(format!("n{i}/admin.sock")),
            prune_interval: None,
        },
    )
    .await
    .unwrap();
    Started { app, running }
}

/// Three started nodes and the keys the dealer gave them.
pub struct Three<S> {
    pub nodes: Vec<Started<S>>,
    pub keys: [NodeKeys; NODES],
}

/// Start three nodes on `stores` under `dir`: the development dealer's keys
/// and master sharing (`dir/keys<i>`), the mesh on fresh loopback ports, the
/// API with the dev certificates in `certs`, the admin sockets. `app` builds
/// node `i`'s application from its node, mesh and enc rotation over its key
/// directory ([`rotation`]) (a chain verifier, state holders, a receipt
/// signer, a retention window), as each suite needs.
pub async fn start_three<S: Store + 'static>(
    dir: &Path,
    certs: &Path,
    crs: Crs,
    stores: [S; NODES],
    app: impl Fn(usize, Node<S>, Mesh, KeyRotation) -> App<S>,
) -> Three<S> {
    let dirs = [0, 1, 2].map(|i| KeyFiles::new(dir.join(format!("keys{i}"))));
    sidecar_node::setup::setup_dealer([&dirs[0], &dirs[1], &dirs[2]], false).unwrap();
    let mut nodes = Vec::new();
    let mut keys = Vec::new();
    for ((i, mesh), store) in meshes().into_iter().enumerate().zip(stores) {
        let (node_keys, master) = sidecar_node::setup::load(dirs[i].dir()).unwrap();
        keys.push(node_keys.clone());
        let node = Node::new(i, node_keys, master, store, crs.clone()).unwrap();
        let rotation = rotation(dirs[i].clone());
        nodes.push(serve_app(app(i, node, mesh, rotation), certs, dir).await);
    }
    Three {
        nodes,
        keys: keys.try_into().unwrap_or_else(|_| unreachable!()),
    }
}
