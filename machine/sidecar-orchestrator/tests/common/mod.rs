//! What the orchestrator tests share beyond `sidecar-test-fixtures` (whose
//! directories, data, requests and nodes are re-exported here): registry
//! bodies, node stubs (small axum servers speaking the node routes over
//! mutual TLS, which record what they receive and answer what the test tells
//! them), an orchestrator over three node addresses, a public client of it,
//! and three real nodes as the orchestrator suites start them; `tip`, what
//! the tip suites share on top of them.

#![allow(dead_code)]

pub mod tip;

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{Method, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use serde_json::Value;
use sidecar_core::crs::Crs;
use sidecar_core::field::FieldHex;
use sidecar_core::grumpkin::Fq;
use sidecar_core::register::{ManifestMessage, ManifestResponse, Signature};
use sidecar_core::response::{NodePublicKeys, NodesResponse};
pub use sidecar_core::testing::{
    TestPackage, TipFacts, contract_manifest, manifest_message, sign_message,
};
use sidecar_core::{ErrorClass, Fr, Refusal};
use sidecar_http::client::{Answer, ApiClient};
use sidecar_node::tls;
use sidecar_orchestrator::Orchestrator;
use sidecar_orchestrator::config::PublicTls;
use sidecar_orchestrator::nodes::Nodes;
use sidecar_orchestrator::registry::Registry;
use sidecar_orchestrator::server::{self, Running};
use sidecar_tip::testing::MemoryChain;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;

pub use sidecar_test_fixtures::data::*;
pub use sidecar_test_fixtures::dirs::*;
pub use sidecar_test_fixtures::nodes::{dev_certs, node_tls, orchestrator_tls};
pub use sidecar_test_fixtures::requests::*;

/// The public listener's certificate: node 0's development server
/// certificate, which names `localhost` under the dev CA (the development set
/// has no separate public certificate).
pub fn public_tls(certs: &Path) -> PublicTls {
    PublicTls {
        cert: certs.join("https-node0.pem"),
        key: certs.join("https-node0-key.pem"),
    }
}

// ---------------------------------------------------------------------------
// Keys and registry bodies
// ---------------------------------------------------------------------------

/// The sidecar-path contract manifest of `packages`, each circuit's vk hash
/// built from the prepared circuit.
pub fn sidecar_manifest(example: &str, packages: &[TestPackage]) -> Value {
    contract_manifest(example, packages, None, vk_hash)
}

/// A manifest message of the sidecar-path packages `names` of `example`
/// (each named after its circuit) under `namespace` at `seq`, signed by the
/// owner.
pub fn register_body(example: &str, namespace: Fr, names: &[&str], seq: u64) -> ManifestMessage {
    let packages: Vec<TestPackage> = names
        .iter()
        .map(|name| TestPackage::new(name, manifest(example, name)))
        .collect();
    signed_register(namespace, sidecar_manifest(example, &packages), seq)
}

/// A manifest message of the contract manifest `document` under `namespace`
/// at `seq`, carrying each circuit it names (stripped), signed by the owner.
pub fn signed_register(namespace: Fr, document: Value, seq: u64) -> ManifestMessage {
    let circuits: BTreeMap<String, Value> = document["circuits"]
        .as_object()
        .unwrap()
        .keys()
        .map(|id| (id.clone(), circuit_json(id)))
        .collect();
    let body = manifest_message(namespace, document, &circuits, owner_secret(), seq);
    sign_message(body, owner_secret(), &mut rand::rngs::OsRng).body
}

/// The vk hash the manifest message `body` gives package `name` (its
/// circuit's entry of the contract manifest's `circuits`).
pub fn vk_of(body: &ManifestMessage, name: &str) -> FieldHex {
    let checked = body.contract_manifest().unwrap();
    let (package, _) = checked
        .package(name)
        .unwrap_or_else(|| panic!("no package `{name}` in the body"));
    FieldHex(checked.vk_hash(package))
}

/// Write the sidecar-path packages `names` of `example` into the
/// orchestrator's registry copy as if the nodes had answered their manifest
/// message at `seq` (the copy's own rows only; no node is involved): at seq
/// 0 the first REGISTER, later the same contract manifest again (a
/// re-enable, which moves every package to `seq`).
pub fn seed_registry(registry: &Registry, example: &str, namespace: Fr, names: &[&str], seq: u64) {
    let body = register_body(example, namespace, names, seq);
    record(registry, &body);
}

/// Record `body` in the orchestrator's registry copy as if the three nodes
/// had answered it (no node is involved; the answer carries no signature).
pub fn record(registry: &Registry, body: &ManifestMessage) {
    let computed = registry.compute(body).unwrap();
    let facts = &computed.facts;
    let response = ManifestResponse {
        manifest_hash: FieldHex(facts.manifest_hash),
        packages_hash: FieldHex(facts.packages_hash),
        npk_app_hash: FieldHex::from(0x9e9e),
        seq: body.seq,
        signatures: [Signature::default(); 3],
    };
    registry.record_register(body, &response, computed).unwrap();
}

/// Three distinct node key pairs, as stubs answer and an orchestrator pins.
pub fn stub_keys() -> [sidecar_core::keys::NodeKeys; 3] {
    [0u64, 1, 2].map(|i| {
        sidecar_core::keys::NodeKeys::from_scalars(Fq::from(100 + i), Fq::from(200 + i)).unwrap()
    })
}

/// Store `sig` (node 0 first, each key as (x, y)) as `contract`'s key
/// epoch 0 on `mem`: the constructor's `node_sig_keys`, beside
/// `TipConfig.stale_blocks` at `stale_blocks_slot`
/// (sidecar-core `key_epoch::epoch0_sig_slots`), where the scheduler's
/// key-set gate reads them while the contract has never rotated.
pub fn pin_epoch0(mem: &MemoryChain, contract: Fr, stale_blocks_slot: Fr, sig: [(Fr, Fr); 3]) {
    let slots = sidecar_core::key_epoch::epoch0_sig_slots(stale_blocks_slot);
    for (i, (x, y)) in sig.into_iter().enumerate() {
        mem.set_storage(contract, slots[2 * i], x);
        mem.set_storage(contract, slots[2 * i + 1], y);
    }
}

/// `pins`' `sig` keys as [`pin_epoch0`] takes them.
pub fn sig_keys_of(pins: &NodesResponse) -> [(Fr, Fr); 3] {
    pins.nodes.map(|k| (k.sig.x.fr(), k.sig.y.fr()))
}

pub fn pins_of(keys: &[sidecar_core::keys::NodeKeys; 3]) -> NodesResponse {
    NodesResponse {
        nodes: [0, 1, 2].map(|i| keys[i].public_keys()),
    }
}

// ---------------------------------------------------------------------------
// Node stubs
// ---------------------------------------------------------------------------

/// How a stub answers one call: (node index, method, path, body) to (status,
/// body).
pub type Respond = Arc<dyn Fn(usize, &Method, &str, &[u8]) -> (u16, Vec<u8>) + Send + Sync>;

/// One call a stub received.
#[derive(Clone, Debug)]
pub struct Call {
    pub method: Method,
    pub path: String,
    pub body: Vec<u8>,
}

impl Call {
    pub fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap()
    }
}

/// What the three stubs of one network share: how they answer, how long
/// they take, and which request ids are in flight at once.
pub struct StubNet {
    pub respond: Mutex<Respond>,
    pub delay: Mutex<Duration>,
    in_flight: Mutex<BTreeMap<String, usize>>,
    /// The most distinct execute request ids ever in flight together.
    pub max_sessions: Mutex<usize>,
    pub calls: [Mutex<Vec<Call>>; 3],
}

impl StubNet {
    pub fn set(&self, respond: Respond) {
        *self.respond.lock().unwrap() = respond;
    }

    pub fn calls(&self, i: usize) -> Vec<Call> {
        self.calls[i].lock().unwrap().clone()
    }

    /// Calls of every stub.
    pub fn total_calls(&self) -> usize {
        (0..3).map(|i| self.calls[i].lock().unwrap().len()).sum()
    }

    pub fn clear(&self) {
        for c in &self.calls {
            c.lock().unwrap().clear();
        }
    }
}

/// A refusal in the node's error shape.
pub fn refused(class: ErrorClass, message: &str) -> (u16, Vec<u8>) {
    (
        class.status(),
        Refusal::new(class, message).to_json().into_bytes(),
    )
}

pub fn ok_json<T: serde::Serialize>(value: &T) -> (u16, Vec<u8>) {
    (200, serde_json::to_vec(value).unwrap())
}

/// The default stub answer: `GET /v1/nodes` with `keys[i]`, 409 to
/// everything else.
pub fn default_respond(keys: [NodePublicKeys; 3]) -> Respond {
    Arc::new(move |i, method, path, _| {
        if method == Method::GET && path == "/v1/nodes" {
            ok_json(&keys[i])
        } else {
            refused(ErrorClass::Conflict, "stub refuses")
        }
    })
}

struct StubState {
    index: usize,
    net: Arc<StubNet>,
}

async fn stub_handler(
    State(state): State<Arc<StubState>>,
    method: Method,
    uri: Uri,
    body: Bytes,
) -> Response {
    let path = uri.path().to_string();
    state.net.calls[state.index].lock().unwrap().push(Call {
        method: method.clone(),
        path: path.clone(),
        body: body.to_vec(),
    });
    let session = (path == "/v1/execute")
        .then(|| serde_json::from_slice::<Value>(&body).ok())
        .flatten()
        .and_then(|v| v.get("request_id").map(|id| id.to_string()));
    if let Some(id) = &session {
        let mut in_flight = state.net.in_flight.lock().unwrap();
        *in_flight.entry(id.clone()).or_default() += 1;
        let distinct = in_flight.len();
        let mut max = state.net.max_sessions.lock().unwrap();
        *max = (*max).max(distinct);
    }
    let delay = *state.net.delay.lock().unwrap();
    if !delay.is_zero() {
        tokio::time::sleep(delay).await;
    }
    if let Some(id) = &session {
        let mut in_flight = state.net.in_flight.lock().unwrap();
        let n = in_flight.get_mut(id).unwrap();
        *n -= 1;
        if *n == 0 {
            in_flight.remove(id);
        }
    }
    let respond = state.net.respond.lock().unwrap().clone();
    let (status, body) = respond(state.index, &method, &path, &body);
    (
        StatusCode::from_u16(status).unwrap(),
        [(header::CONTENT_TYPE, "application/json")],
        body,
    )
        .into_response()
}

/// Three stubs on free loopback ports, each with node i's development server
/// certificate and the node's mutual-TLS rule.
pub struct Stubs {
    pub net: Arc<StubNet>,
    pub addrs: [SocketAddr; 3],
    tasks: Vec<JoinHandle<()>>,
}

impl Drop for Stubs {
    fn drop(&mut self) {
        for t in &self.tasks {
            t.abort();
        }
    }
}

impl Stubs {
    pub async fn start(certs: &Path, respond: Respond) -> Stubs {
        let net = Arc::new(StubNet {
            respond: Mutex::new(respond),
            delay: Mutex::new(Duration::ZERO),
            in_flight: Mutex::new(BTreeMap::new()),
            max_sessions: Mutex::new(0),
            calls: [Mutex::new(vec![]), Mutex::new(vec![]), Mutex::new(vec![])],
        });
        let mut addrs = Vec::new();
        let mut tasks = Vec::new();
        for i in 0..3 {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            addrs.push(listener.local_addr().unwrap());
            let router = Router::new()
                .fallback(stub_handler)
                .with_state(Arc::new(StubState {
                    index: i,
                    net: net.clone(),
                }));
            let acceptor = TlsAcceptor::from(tls::server_config(&node_tls(certs, i)).unwrap());
            tasks.push(tokio::spawn(sidecar_http::listen::serve(
                listener,
                acceptor,
                router,
                sidecar_node::api::NODE_LISTENER,
            )));
        }
        Stubs {
            net,
            addrs: addrs.try_into().unwrap(),
            tasks,
        }
    }

    /// Stop stub `i`: its port refuses connections from then on.
    pub fn stop(&mut self, i: usize) {
        self.tasks[i].abort();
    }
}

// ---------------------------------------------------------------------------
// The orchestrator and its public client
// ---------------------------------------------------------------------------

/// A started orchestrator, its context and a public client of it.
pub struct Started {
    pub app: Arc<Orchestrator>,
    pub running: Running,
    pub client: ApiClient,
}

impl Started {
    pub fn registry(&self) -> &Registry {
        &self.app.registry
    }

    pub async fn post(&self, path: &str, body: impl Into<Vec<u8>>) -> Answer {
        self.client.post_raw(path, body).await.unwrap()
    }

    pub async fn post_json<T: serde::Serialize>(&self, path: &str, body: &T) -> Answer {
        self.client.post(path, body).await.unwrap()
    }

    pub async fn get(&self, path: &str) -> Answer {
        self.client.get(path).await.unwrap()
    }
}

/// Start an orchestrator over the nodes at `addrs` (their certificates name
/// `localhost`), pinned to `pins`, with its registry copy in `registry_dir`.
pub async fn start_orchestrator(
    certs: &Path,
    addrs: [SocketAddr; 3],
    pins: NodesResponse,
    registry_dir: &Path,
    crs: Crs,
) -> Started {
    start_orchestrator_with(
        certs,
        addrs,
        pins,
        registry_dir,
        crs,
        server::PUBLIC_LISTENER,
        sidecar_orchestrator::nodes::DEFAULT_NODE_CALL_TIMEOUT,
    )
    .await
}

/// [`start_orchestrator`] with the public listener under `limits` and every
/// node call bounded by `call_timeout`.
pub async fn start_orchestrator_with(
    certs: &Path,
    addrs: [SocketAddr; 3],
    pins: NodesResponse,
    registry_dir: &Path,
    crs: Crs,
    limits: sidecar_http::listen::ListenerLimits,
    call_timeout: Duration,
) -> Started {
    let registry = Registry::open(registry_dir, crs).unwrap();
    let leg = orchestrator_tls(certs);
    let tls = tls::client_config(&leg.ca, Some((&leg.cert, &leg.key))).unwrap();
    let clients = addrs.map(|addr| ApiClient::new(addr, "localhost", tls.clone()).unwrap());
    let nodes = Nodes::with_timeout(clients, call_timeout);
    let sig_pks = pins
        .nodes
        .map(|k| sidecar_core::grumpkin::point_from_wire(&k.sig).unwrap());
    let app = Arc::new(Orchestrator::new(registry, nodes, pins, sig_pks));
    let running = server::start(
        app.clone(),
        "127.0.0.1:0".parse().unwrap(),
        server::server_config(&public_tls(certs)).unwrap(),
        limits,
    )
    .await
    .unwrap();
    // The public: the dev CA as the only root, no client certificate.
    let public = tls::client_config(&certs.join("https-ca.pem"), None).unwrap();
    let client = ApiClient::new(running.addr, "localhost", public).unwrap();
    Started {
        app,
        running,
        client,
    }
}

/// A raw TLS connection to the public listener at `addr`, as a client with
/// no certificate opens it; the handshake is complete when this returns.
pub async fn raw_public(
    certs: &Path,
    addr: SocketAddr,
) -> tokio_rustls::client::TlsStream<tokio::net::TcpStream> {
    let config = tls::client_config(&certs.join("https-ca.pem"), None).unwrap();
    let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    tokio_rustls::TlsConnector::from(config)
        .connect(
            rustls::pki_types::ServerName::try_from("localhost").unwrap(),
            tcp,
        )
        .await
        .unwrap()
}

/// Everything `stream` sends until it closes (or fails), as text.
pub async fn read_to_close<S: tokio::io::AsyncRead + Unpin>(stream: &mut S) -> String {
    use tokio::io::AsyncReadExt;
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match stream.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => out.extend_from_slice(&buf[..n]),
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

// ---------------------------------------------------------------------------
// Real nodes
// ---------------------------------------------------------------------------

/// Three in-process nodes on MemoryStore, each behind its HTTPS API with
/// mutual TLS and its admin socket, over the pinned-TLS mesh on loopback,
/// with development dealer keys; their keys for the tests to sign with.
pub struct RealNodes {
    pub apps: Vec<Arc<sidecar_node::server::App<sidecar_core::store::MemoryStore>>>,
    pub running: Vec<sidecar_node::server::Running>,
    pub keys: [sidecar_core::keys::NodeKeys; 3],
}

impl RealNodes {
    pub fn addrs(&self) -> [SocketAddr; 3] {
        [0, 1, 2].map(|i| self.running[i].api_addr)
    }

    pub fn pins(&self) -> NodesResponse {
        pins_of(&self.keys)
    }

    /// A client of node `i` with the orchestrator's certificate, for the
    /// tests' own direct calls.
    pub fn client(&self, certs: &Path, i: usize) -> ApiClient {
        sidecar_test_fixtures::nodes::orchestrator_client(certs, self.running[i].api_addr)
    }

    /// The same body posted to the three nodes directly.
    pub async fn post_same(&self, certs: &Path, path: &str, body: &[u8]) -> [Answer; 3] {
        let clients = [0, 1, 2].map(|i| self.client(certs, i));
        sidecar_test_fixtures::nodes::post_same(&clients, path, body).await
    }

    /// Send `req` to the three nodes' admin sockets at once (a resync or an
    /// audit runs one session of all three) and return their answers.
    pub async fn admin_all(
        &self,
        req: sidecar_node::admin::AdminRequest,
    ) -> Vec<sidecar_node::admin::AdminResponse> {
        let call = |i: usize| {
            sidecar_node::admin::call_async(self.running[i].admin_socket.clone(), req.clone())
        };
        let (a, b, c) = tokio::join!(call(0), call(1), call(2));
        [a, b, c].into_iter().map(|r| r.unwrap()).collect()
    }

    /// Roll `request_id` back on the three nodes through their admin sockets.
    pub async fn restore(&self, namespace: Fr, request_id: sidecar_core::RequestId) {
        for (i, running) in self.running.iter().enumerate() {
            let answer = sidecar_node::admin::call_async(
                running.admin_socket.clone(),
                sidecar_node::admin::AdminRequest::Restore {
                    namespace: FieldHex(namespace),
                    request_id,
                },
            )
            .await
            .unwrap();
            assert!(answer.ok, "restore on node {i}: {:?}", answer.refusal);
        }
    }
}

/// Start three real nodes with keys, certificates and sockets under `dir`,
/// with the default chain verifier (every queued round refused).
pub async fn start_real_nodes(dir: &Path, certs: &Path, crs: Crs) -> RealNodes {
    start_real_nodes_signing(
        dir,
        certs,
        crs,
        |_| Box::new(sidecar_core::pipeline::chain_verifier_not_built),
        |_| sidecar_node::receipt::Receipts::default(),
    )
    .await
}

/// [`start_real_nodes`] with node i's step 4 chain verifier `verifier(i)`,
/// node i signing receipts with `receipts(i)` (its settings and its own
/// chain view).
pub async fn start_real_nodes_signing(
    dir: &Path,
    certs: &Path,
    crs: Crs,
    verifier: impl Fn(usize) -> sidecar_core::pipeline::ChainVerifier,
    receipts: impl Fn(usize) -> sidecar_node::receipt::Receipts,
) -> RealNodes {
    let three = sidecar_test_fixtures::nodes::start_three(
        dir,
        certs,
        crs,
        [0, 1, 2].map(|_| sidecar_core::store::MemoryStore::new()),
        |i, node, mesh, rotation| {
            let node = node
                .with_chain_verifier(verifier(i))
                .with_state_holders(sidecar_tip::holders())
                .with_receipt_resync(sidecar_tip::receipt_resync());
            sidecar_node::server::App::new(node, mesh, rotation).with_receipts(receipts(i))
        },
    )
    .await;
    let (apps, running) = three
        .nodes
        .into_iter()
        .map(|started| (started.app, started.running))
        .unzip();
    RealNodes {
        apps,
        running,
        keys: three.keys,
    }
}
