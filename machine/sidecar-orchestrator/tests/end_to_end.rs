//! The orchestrator and three real nodes in one test process, driven only
//! through the orchestrator's public HTTPS API, as a client sees the
//! note-mode machine (ARCHITECTURE.md sections 3, 4 and 8), with real MPC
//! proofs.
//!
//! Between the orchestrator and each node sits a proxy that logs the request
//! line of every call the orchestrator makes, so the test sees which requests
//! reached the nodes and which were refused before fan-out.
//!
//! - Registry: the first REGISTER of a namespace (seq 0, one manifest
//!   message of all its packages) answers the manifest hash, the packages
//!   hash, npk_app_hash, seq and each package's vk_hash; a second namespace
//!   gets another npk_app_hash; an identical REGISTER answers the same; a
//!   body signed by another key and a body of another owner are 403 and a
//!   wrong seq is 409, all before fan-out; DISABLE makes an execute of the
//!   circuit 400, and REGISTER of the same contract manifest re-enables it;
//!   a contract manifest that puts a disabled name on another circuit makes
//!   a FETCH of the name's earlier round 409; the registry GETs answer the
//!   stored values.
//! - Execute: the AMM on node-held state (seed, init, swaps), and Monty Hall
//!   on client-held records (seed, init, open_door with INPUT_SHARED inputs,
//!   finish), each record created under `requester` and supplied back with
//!   its signature; record-supplying requests without a valid signature are
//!   403 before fan-out.
//! - Retry: a client that drops its connection mid-round FETCHes the round,
//!   and the FETCH answers what a resend of the same body answers; a request
//!   id reused with another body is 409; FETCH of an unknown id is 404, and
//!   of a round the operator rolled back 409.
//! - `GET /v1/nodes` answers the three pinned key pairs.
//! - A fresh orchestrator on an empty registry directory rebuilds its copy
//!   from the three nodes (`sync-registry`) and then answers an execute and a
//!   FETCH of an earlier round.
//! - Every execute, FETCH and registry response's three signatures are
//!   checked here against the pinned sig keys, with sidecar-core's
//!   verification functions and shapes built by the test itself.
//!
//! Needs `scripts/prepare-data.sh` (the circuits and the CRS under
//! machine/data, or DATA_DIR); the test fails naming the missing files if
//! they are absent. Run with `--release`.

mod common;

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use common::*;
use rand::RngCore;
use rand::rngs::OsRng;
use rustls::pki_types::ServerName;
use serde_json::{Value, json};
use sidecar_core::abi::{CircuitShape, check_manifest_value};
use sidecar_core::bind::Elem;
use sidecar_core::envelope::{EnvelopeAd, seal_envelope};
use sidecar_core::field::{FieldHex, Fr, fr_to_hex};
use sidecar_core::grumpkin::{Fq, Point, point_from_wire, point_to_wire};
use sidecar_core::pipeline::verify_result_signature;
use sidecar_core::record;
use sidecar_core::register::{
    DisableRequest, DisableResponse, ManifestMessage, ManifestResponse, NamespaceResponse,
    PackageResponse, Signature, stripped_circuit,
};
use sidecar_core::registry::{manifest_message, registry_message};
use sidecar_core::request::{Request, SharedInput, StateRecord};
use sidecar_core::response::{ExecuteResponse, NodeResult, NodeResultRecord, NodesResponse};
use sidecar_core::schnorr::{self, public_key};
use sidecar_core::store::StoreRead;
use sidecar_core::{ErrorClass, Refusal};
use sidecar_http::client::Answer;
use sidecar_node::tls;
use sidecar_test_fixtures::requests::amm::{POOL_KEY, SEED_KEY};
use sidecar_test_fixtures::requests::monty::{
    CHOSEN_DOOR, CIRCUITS as MONTY_CIRCUITS, GAME_KEY, GAME_SEED_KEY, WINNING_DOOR,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tokio_rustls::{TlsAcceptor, TlsConnector};

const AMM: u64 = 0xa3300;
const MONTY: u64 = 0x3a300;
const ALL_CIRCUITS: [&str; 6] = [
    "pss_seed",
    "amm_init",
    "amm_swap",
    "monty_hall_init",
    "monty_hall_open_door",
    "monty_hall_finish",
];

// ---------------------------------------------------------------------------
// Counting proxies
// ---------------------------------------------------------------------------

// How the test sees the node leg without changing it. Each node
// is reached through a loopback proxy that terminates the orchestrator's
// mutual TLS with the node's own certificate, logs the request line (method
// and path), and forwards the call to the node over a second mutual-TLS
// connection with the orchestrator's client certificate, so the orchestrator
// and the nodes each see exactly the peer they see as deployed. The
// orchestrator opens one connection per node call (src/nodes.rs), and the
// line is logged before the node sees the call, so when the orchestrator
// answers, every call it made for that request is in the log. The assertions
// read the log by request line, not a count of connections: besides the calls
// a request makes, the orchestrator reads the three registries in a task of
// its own after every registry body and on a timer (src/status.rs), and those
// GETs run unsynchronised with the test.
/// A request-logging proxy in front of one node.
struct Proxy {
    addr: SocketAddr,
    calls: Arc<Mutex<Vec<String>>>,
    task: JoinHandle<()>,
}

impl Drop for Proxy {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// The proxy in front of node `i`, at `target`.
async fn proxy(certs: &Path, i: usize, target: SocketAddr) -> Proxy {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let acceptor = TlsAcceptor::from(tls::server_config(&node_tls(certs, i)).unwrap());
    let leg = orchestrator_tls(certs);
    let connector =
        TlsConnector::from(tls::client_config(&leg.ca, Some((&leg.cert, &leg.key))).unwrap());
    let calls = Arc::new(Mutex::new(Vec::new()));
    let log = calls.clone();
    let task = tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let (acceptor, connector, log) = (acceptor.clone(), connector.clone(), log.clone());
            tokio::spawn(async move {
                let Ok(mut inbound) = acceptor.accept(tcp).await else {
                    return;
                };
                let Some((line, head)) = request_line(&mut inbound).await else {
                    return;
                };
                log.lock().unwrap().push(line);
                let Ok(tcp) = TcpStream::connect(target).await else {
                    return;
                };
                let name = ServerName::try_from("localhost").unwrap();
                let Ok(mut outbound) = connector.connect(name, tcp).await else {
                    return;
                };
                if outbound.write_all(&head).await.is_ok() {
                    let _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await;
                }
            });
        }
    });
    Proxy { addr, calls, task }
}

/// The first line of the HTTP request on `stream` as "METHOD /path" (the
/// query dropped), and every byte read so far, to forward.
async fn request_line<S: AsyncRead + Unpin>(stream: &mut S) -> Option<(String, Vec<u8>)> {
    let mut head = Vec::new();
    let mut buf = [0u8; 4096];
    let end = loop {
        if let Some(end) = head.windows(2).position(|w| w == b"\r\n") {
            break end;
        }
        let n = stream.read(&mut buf).await.ok()?;
        if n == 0 {
            return None;
        }
        head.extend_from_slice(&buf[..n]);
    };
    let line = String::from_utf8_lossy(&head[..end]).into_owned();
    let mut parts = line.split(' ');
    let method = parts.next()?;
    let path = parts.next()?.split('?').next()?;
    Some((format!("{method} {path}"), head))
}

/// How many calls each node has had so far: a mark for [`calls_since`].
fn mark(proxies: &[Proxy]) -> [usize; 3] {
    [0, 1, 2].map(|i| proxies[i].calls.lock().unwrap().len())
}

/// The calls each node has had since `mark`, other than GETs. Every call a
/// request of this test makes the orchestrator send is a POST; its GETs are
/// the registry check's reads (and `GET /v1/nodes`, which no assertion
/// spans).
fn calls_since(proxies: &[Proxy], mark: [usize; 3]) -> [Vec<String>; 3] {
    [0, 1, 2].map(|i| {
        proxies[i].calls.lock().unwrap()[mark[i]..]
            .iter()
            .filter(|line| !line.starts_with("GET "))
            .cloned()
            .collect()
    })
}

/// The same calls at each of the three nodes.
fn each(calls: &[&str]) -> [Vec<String>; 3] {
    [(); 3].map(|_| calls.iter().map(|c| c.to_string()).collect())
}

const EXECUTE: &str = "POST /v1/execute";

// ---------------------------------------------------------------------------
// Requests, as a client builds them
// ---------------------------------------------------------------------------

/// Seal `inputs` as INPUT_SHARED envelopes to the three pinned enc keys: a
/// fresh replicated sharing of each value, node i's pair to node i.
fn seal_inputs(req: &mut Request, enc_pks: &[Point; 3], inputs: &[(&str, Fr)]) {
    for (name, value) in inputs {
        let random = || {
            let mut bytes = [0u8; 16];
            OsRng.fill_bytes(&mut bytes);
            Fr::from(u128::from_be_bytes(bytes))
        };
        let (x0, x1) = (random(), random());
        let sharing = [x0, x1, *value - x0 - x1];
        let ad = EnvelopeAd::for_input(req, name);
        let shares = [0, 1, 2].map(|i| {
            seal_envelope(
                enc_pks[i],
                i,
                &ad,
                [sharing[i], sharing[(i + 2) % 3]],
                &mut OsRng,
            )
        });
        let share_hashes = shares.map(|s| FieldHex(s.hash()));
        req.shared_inputs.push(SharedInput {
            name: name.to_string(),
            shares,
            share_hashes,
        });
    }
}

fn owner_signed_disable(namespace: u64, circuit: &str, seq: u64) -> DisableRequest {
    let mut body = DisableRequest {
        namespace: FieldHex(Fr::from(namespace)),
        circuit: circuit.into(),
        owner_pubkey: point_to_wire(public_key(owner_secret())),
        seq,
        signature: Signature::default(),
    };
    let message = schnorr::message_for(
        schnorr::DISABLE_DOMAIN,
        &serde_json::to_value(&body).unwrap(),
    )
    .unwrap();
    body.signature = schnorr::sign(owner_secret(), message, &mut OsRng);
    body
}

/// A manifest message of `names` whose owner key and signature are `key`'s.
fn register_as(
    key: Fq,
    example: &str,
    namespace: u64,
    names: &[&str],
    seq: u64,
) -> ManifestMessage {
    let mut body = register_body(example, Fr::from(namespace), names, seq);
    body.owner_pubkey = point_to_wire(public_key(key));
    body.signature = Signature::default();
    let message = schnorr::message_for(
        schnorr::REGISTER_DOMAIN,
        &serde_json::to_value(&body).unwrap(),
    )
    .unwrap();
    body.signature = schnorr::sign(key, message, &mut OsRng);
    body
}

// ---------------------------------------------------------------------------
// Opening values, as only a test that holds the node keys can
// ---------------------------------------------------------------------------

/// The pool the three nodes hold, opened.
fn pool(real: &RealNodes) -> [u64; 2] {
    let rows: Vec<Vec<Elem>> = real
        .apps
        .iter()
        .map(|app| {
            app.node
                .store
                .value(Fr::from(AMM), POOL_KEY)
                .unwrap()
                .unwrap()
                .vec
        })
        .collect();
    let opened = open_vec([&rows[0], &rows[1], &rows[2]]);
    [small(opened[0]), small(opened[1])]
}

/// A client-held record opened from its three thirds for `owner`.
fn opened_record(real: &RealNodes, record: &StateRecord, owner: Point) -> Vec<Fr> {
    let vecs: Vec<Vec<Elem>> = (0..3)
        .map(|i| {
            record::open(
                &real.keys[i],
                Fr::from(MONTY),
                &record.key,
                record.note_hash.fr(),
                owner,
                record.c[i].as_slice(),
            )
            .unwrap()
        })
        .collect();
    open_vec([&vecs[0], &vecs[1], &vecs[2]])
}

// ---------------------------------------------------------------------------
// The client's checks
// ---------------------------------------------------------------------------

/// The shape of `name` under `example`'s manifest, built by the test from the
/// compiled circuit's ABI.
fn shape(example: &str, name: &str) -> CircuitShape {
    let circuit = circuit_json(name);
    let abi: noirc_abi::Abi = serde_json::from_value(circuit["abi"].clone()).unwrap();
    check_manifest_value(&manifest(example, name), &abi)
        .unwrap()
        .1
}

/// The client's view of the network: the pinned keys and the shapes.
struct Client {
    sig_pks: [Point; 3],
    enc_pks: [Point; 3],
}

impl Client {
    fn new(pins: &NodesResponse) -> Self {
        Client {
            sig_pks: pins.nodes.map(|k| point_from_wire(&k.sig).unwrap()),
            enc_pks: pins.nodes.map(|k| point_from_wire(&k.enc).unwrap()),
        }
    }

    /// Node i's answer as it signed it, rebuilt from the response: the agreed
    /// parts, its own third of each record and its own signature.
    fn node_view(response: &ExecuteResponse, i: usize) -> NodeResult {
        NodeResult {
            request_id: response.request_id,
            vk_hash: None,
            proof: response.proof.clone(),
            public_inputs: response.public_inputs.clone(),
            stored: response.stored.clone(),
            records: response
                .records
                .iter()
                .map(|r| NodeResultRecord {
                    key: r.key.clone(),
                    note_hash: r.note_hash,
                    c_i: r.c[i].clone(),
                })
                .collect(),
            signature: response.signatures[i],
        }
    }

    /// Every signature of an execute or FETCH response verifies under its
    /// node's pinned sig key, and under no other node's key.
    fn check_result(&self, label: &str, ns: u64, shape: &CircuitShape, r: &ExecuteResponse) {
        let ns = Fr::from(ns);
        for i in 0..3 {
            let view = Self::node_view(r, i);
            assert!(
                verify_result_signature(self.sig_pks[i], ns, shape, &view, i).unwrap(),
                "{label}: node {i}'s result signature under its pinned key"
            );
            let next = (i + 1) % 3;
            assert!(
                !verify_result_signature(self.sig_pks[next], ns, shape, &view, i).unwrap(),
                "{label}: node {i}'s result signature under node {next}'s key"
            );
        }
        for (k, record) in r.records.iter().enumerate() {
            let path = format!("new_note_hashes[{k}]");
            let index = shape.return_index(&path).unwrap();
            assert_eq!(record.note_hash, r.public_inputs[index], "{label}: {path}");
        }
    }

    /// Every signature of a registry answer verifies under its node's pinned
    /// sig key over the manifest result message.
    fn check_manifest(&self, label: &str, ns: u64, response: &ManifestResponse) {
        for (i, signature) in response.signatures.iter().enumerate() {
            let message = manifest_message(
                Fr::from(ns),
                response.manifest_hash.fr(),
                response.packages_hash.fr(),
                response.npk_app_hash.fr(),
                response.seq,
                i,
            );
            assert!(
                schnorr::verify(self.sig_pks[i], *signature, message),
                "{label}: node {i}'s manifest signature"
            );
        }
    }

    /// Every signature of a DISABLE answer verifies under its node's pinned
    /// sig key over the registry result message.
    #[allow(clippy::too_many_arguments)]
    fn check_registry(
        &self,
        label: &str,
        ns: u64,
        name: &str,
        vk_hash: FieldHex,
        npk_app_hash: FieldHex,
        seq: u64,
        disabled: bool,
        signatures: &[Signature; 3],
    ) {
        for (i, signature) in signatures.iter().enumerate() {
            let message = registry_message(
                Fr::from(ns),
                name,
                vk_hash.fr(),
                npk_app_hash.fr(),
                seq,
                disabled,
                i,
            );
            assert!(
                schnorr::verify(self.sig_pks[i], *signature, message),
                "{label}: node {i}'s registry signature"
            );
        }
    }
}

fn ok<T: serde::de::DeserializeOwned>(label: &str, answer: &Answer) -> T {
    answer
        .json::<T>()
        .unwrap()
        .unwrap_or_else(|e| panic!("{label}: {e}"))
}

fn expect(label: &str, answer: &Answer, class: ErrorClass, needle: &str) -> Refusal {
    let refusal = answer.json::<Value>().unwrap().unwrap_err();
    assert_eq!(answer.status, refusal.status(), "{label}");
    assert_eq!(refusal.class, class, "{label}: {refusal}");
    assert!(refusal.message.contains(needle), "{label}: {refusal}");
    eprintln!("REFUSED {label}: {refusal}");
    refusal
}

// ---------------------------------------------------------------------------
// The test
// ---------------------------------------------------------------------------

/// The network, the orchestrator and the client's state.
struct World {
    real: RealNodes,
    certs: PathBuf,
    proxies: Vec<Proxy>,
    orch: Started,
    client: Client,
    pins: NodesResponse,
}

impl World {
    async fn post<T: serde::Serialize>(&self, path: &str, body: &T) -> Answer {
        self.orch.post_json(path, body).await
    }

    /// A request that must reach the three nodes once each and commit; its
    /// response is checked by the client.
    async fn execute(
        &self,
        label: &str,
        example: &str,
        req: &Request,
        vk_hash: FieldHex,
    ) -> ExecuteResponse {
        let before = mark(&self.proxies);
        let start = Instant::now();
        let response: ExecuteResponse = ok(label, &self.post("/v1/execute", req).await);
        eprintln!(
            "ROUND {label} ({}) through the orchestrator: {:.3}s",
            req.circuit,
            start.elapsed().as_secs_f64()
        );
        assert_eq!(
            calls_since(&self.proxies, before),
            each(&[EXECUTE]),
            "{label}"
        );
        assert_eq!(response.request_id, req.request_id, "{label}");
        assert_eq!(response.vk_hash, vk_hash, "{label}: vk_hash");
        let ns = small(req.namespace.fr());
        self.client
            .check_result(label, ns, &shape(example, &req.circuit), &response);
        response
    }

    /// A request the orchestrator refuses before any node sees it.
    async fn refused_here(&self, label: &str, req: &Request, class: ErrorClass, needle: &str) {
        let before = mark(&self.proxies);
        expect(label, &self.post("/v1/execute", req).await, class, needle);
        assert_eq!(
            calls_since(&self.proxies, before),
            each(&[]),
            "{label}: a node was called"
        );
    }

    /// FETCH of a committed round, checked by the client.
    async fn fetch(&self, label: &str, example: &str, req: &Request) -> ExecuteResponse {
        let body = json!({"namespace": req.namespace, "request_id": req.request_id});
        let response: ExecuteResponse = ok(label, &self.post("/v1/fetch", &body).await);
        let ns = small(req.namespace.fr());
        self.client
            .check_result(label, ns, &shape(example, &req.circuit), &response);
        response
    }

    /// REGISTER `body` through the orchestrator; the answer is checked by
    /// the client.
    async fn register_message(&self, ns: u64, body: &ManifestMessage) -> ManifestResponse {
        let seq = body.seq;
        let start = Instant::now();
        let response: ManifestResponse = ok(
            &format!("REGISTER under {ns:#x}"),
            &self.post("/v1/register", body).await,
        );
        eprintln!(
            "REGISTER of {} circuit(s) under {ns:#x} (seq {seq}): {:.3}s",
            body.circuits.len(),
            start.elapsed().as_secs_f64()
        );
        assert_eq!(response.seq, seq);
        self.client.check_manifest("REGISTER", ns, &response);
        response
    }

    /// REGISTER the sidecar-path packages `names` of `example` in one
    /// manifest message.
    async fn register(&self, example: &str, ns: u64, names: &[&str], seq: u64) -> ManifestResponse {
        self.register_message(ns, &register_body(example, Fr::from(ns), names, seq))
            .await
    }

    /// The registry GETs answer what REGISTER answered, and what each node
    /// answers itself.
    async fn check_package(&self, ns: u64, name: &str, vk_hash: FieldHex, seq: u64, off: bool) {
        let path = format!("/v1/packages/{}/{name}", fr_to_hex(Fr::from(ns)));
        let pkg: PackageResponse = ok(&path, &self.orch.get(&path).await);
        assert_eq!(
            (pkg.vk_hash, pkg.seq, pkg.disabled),
            (vk_hash, seq, off),
            "{path}"
        );
        assert_eq!(pkg.name, name);
        assert_eq!(pkg.circuit, stripped_circuit(&circuit_json(name)));
        let example = if ns == AMM { "amm" } else { "monty-hall" };
        assert_eq!(pkg.manifest, manifest(example, name));
        for i in 0..3 {
            let node: PackageResponse = ok(
                &path,
                &self.real.client(&self.certs, i).get(&path).await.unwrap(),
            );
            assert_eq!(node, pkg, "{path} at node {i}");
        }
    }

    async fn check_namespace(&self, ns: u64, seq: u64, npk_app_hash: FieldHex) {
        let path = format!("/v1/namespaces/{}", fr_to_hex(Fr::from(ns)));
        let info: NamespaceResponse = ok(&path, &self.orch.get(&path).await);
        assert_eq!(info.namespace, FieldHex(Fr::from(ns)));
        assert_eq!(info.owner_pubkey, point_to_wire(public_key(owner_secret())));
        assert_eq!((info.seq, info.npk_app_hash), (seq, npk_app_hash), "{path}");
        for i in 0..3 {
            let node: NamespaceResponse = ok(
                &path,
                &self.real.client(&self.certs, i).get(&path).await.unwrap(),
            );
            assert_eq!(node, info, "{path} at node {i}");
        }
    }
}

// The store the three nodes run on here is MemoryStore, for
// both applications on one network: the AMM's keys are node-held (so the
// append-only LocalStore, which has no `values`, cannot serve it) and the
// Postgres backend is covered by sidecar-node's own three-party suite, while
// the orchestrator's behaviour does not depend on the nodes' backend. One
// network keeps the run to one mesh and one set of verification keys.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn the_machine_end_to_end_through_the_public_api() {
    let crs = require_crs(&ALL_CIRCUITS);
    let started = Instant::now();
    let tmp = TempDir::new("e2e");
    let certs = dev_certs(tmp.path());
    let real = start_real_nodes(tmp.path(), &certs, crs.clone()).await;
    let mut proxies = Vec::new();
    for addr in real.addrs() {
        proxies.push(proxy(&certs, proxies.len(), addr).await);
    }
    let pins = real.pins();
    let orch = start_orchestrator(
        &certs,
        [0, 1, 2].map(|i| proxies[i].addr),
        pins,
        &tmp.path().join("registry"),
        crs.clone(),
    )
    .await;
    let world = World {
        client: Client::new(&pins),
        real,
        certs,
        proxies,
        orch,
        pins,
    };

    nodes_route(&world).await;
    let amm = amm_registry(&world).await;
    let monty = monty_registry(&world, amm.npk_app_hash).await;
    let swap1 = amm_rounds(&world, &amm).await;
    monty_rounds(&world, &monty).await;
    rebuilt_registry(&world, &amm, &swap1, crs, tmp.path()).await;
    eprintln!("END TO END: {:.3}s in all", started.elapsed().as_secs_f64());
}

/// A fresh orchestrator on an empty registry directory: `sync-registry`
/// rebuilds the copy from the three nodes (the same rows the first
/// orchestrator recorded), refuses while a running orchestrator holds the
/// copy, and the rebuilt orchestrator answers an execute and a FETCH of a
/// round the first one ran.
async fn rebuilt_registry(
    w: &World,
    amm: &Amm,
    swap1: &(Request, ExecuteResponse),
    crs: sidecar_core::crs::Crs,
    tmp: &std::path::Path,
) {
    let dir = tmp.join("registry-rebuilt");
    let leg = orchestrator_tls(&w.certs);
    let tls = sidecar_http::tls::client_config(&leg.ca, Some((&leg.cert, &leg.key))).unwrap();
    let nodes =
        sidecar_orchestrator::nodes::Nodes::from_clients(w.real.addrs().map(|addr| {
            sidecar_http::client::ApiClient::new(addr, "localhost", tls.clone()).unwrap()
        }));
    let start = Instant::now();
    let synced = sidecar_orchestrator::sync::sync_registry(&nodes, &crs, &dir)
        .await
        .unwrap();
    eprintln!(
        "SYNC-REGISTRY: {synced:?} in {:.3}s",
        start.elapsed().as_secs_f64()
    );
    assert_eq!(
        synced,
        sidecar_orchestrator::sync::Synced {
            namespaces: 2,
            packages: 3 + MONTY_CIRCUITS.len()
        }
    );
    // The rebuilt copy holds exactly the rows the first orchestrator recorded.
    {
        let rebuilt = sidecar_core::local::LocalStore::open(&dir).unwrap();
        let first = w.orch.registry().store();
        for ns in [AMM, MONTY].map(Fr::from) {
            assert_eq!(
                rebuilt.namespace(ns).unwrap(),
                first.namespace(ns).unwrap(),
                "namespace {ns}"
            );
            assert_eq!(rebuilt.packages(ns), first.packages(ns), "packages of {ns}");
            assert_eq!(
                rebuilt.contract_manifest(ns).unwrap(),
                first.contract_manifest(ns).unwrap(),
                "the contract manifest of {ns}"
            );
        }
    }
    let orch = start_orchestrator(&w.certs, w.real.addrs(), w.pins, &dir, crs.clone()).await;
    // A sync refuses while a running orchestrator holds the copy.
    let err = sidecar_orchestrator::sync::sync_registry(&nodes, &crs, &dir)
        .await
        .unwrap_err();
    assert!(
        format!("{err:#}").contains("is open in another process"),
        "{err:#}"
    );
    // The rebuilt orchestrator runs a swap of the re-enabled circuit (the
    // namespace is at seq 2) and answers FETCH of swap 1.
    let swap = amm::swap(AMM, random_id(), 3000, 1);
    let answered: ExecuteResponse = ok(
        "a swap through the rebuilt orchestrator",
        &orch.post_json("/v1/execute", &swap).await,
    );
    assert_eq!(answered.vk_hash, amm.vk[2]);
    w.client
        .check_result("rebuilt swap", AMM, &shape("amm", "amm_swap"), &answered);
    let (swap1, swapped1) = swap1;
    let fetch = json!({"namespace": swap1.namespace, "request_id": swap1.request_id});
    let fetched: ExecuteResponse = ok(
        "FETCH swap 1 through the rebuilt orchestrator",
        &orch.post_json("/v1/fetch", &fetch).await,
    );
    assert_eq!(&fetched, swapped1);
}

/// `GET /v1/nodes` answers the keys the nodes were set up with, as pinned.
async fn nodes_route(w: &World) {
    let served: NodesResponse = ok("GET /v1/nodes", &w.orch.get("/v1/nodes").await);
    assert_eq!(served, w.pins);
    for i in 0..3 {
        assert_eq!(served.nodes[i], w.real.keys[i].public_keys(), "node {i}");
    }
    assert_eq!(served.nodes.map(|k| k.sig), w.pins.nodes.map(|k| k.sig));
}

/// What the AMM's registry leaves for its rounds.
struct Amm {
    npk_app_hash: FieldHex,
    vk: [FieldHex; 3],
}

/// The AMM namespace: one manifest message at seq 0, the identical resend,
/// the refusals.
async fn amm_registry(w: &World) -> Amm {
    const NAMES: [&str; 3] = ["pss_seed", "amm_init", "amm_swap"];
    let first = w.register("amm", AMM, &NAMES, 0).await;
    let first_body = register_body("amm", Fr::from(AMM), &NAMES, 0);
    let computed = w.orch.registry().compute(&first_body).unwrap();
    assert_eq!(first.manifest_hash.fr(), computed.facts.manifest_hash);
    assert_eq!(first.packages_hash.fr(), computed.facts.packages_hash);
    let [seed, init, swap] = NAMES.map(|n| vk_of(&first_body, n));
    // the copy holds this contract manifest now, so compute builds nothing
    assert!(computed.circuits.is_empty());
    assert_eq!(seed.fr(), vk_hash("pss_seed"));
    assert_ne!(init, swap);

    // An identical body (the first REGISTER, while the namespace's seq is
    // still 0, as a repair) is answered with the same values.
    let resent: ManifestResponse = ok(
        "REGISTER of the AMM resent",
        &w.post(
            "/v1/register",
            &register_body("amm", Fr::from(AMM), &NAMES, 0),
        )
        .await,
    );
    assert_eq!(
        (resent.manifest_hash, resent.npk_app_hash, resent.seq),
        (first.manifest_hash, first.npk_app_hash, 0)
    );
    w.check_namespace(AMM, 0, first.npk_app_hash).await;
    w.check_package(AMM, "pss_seed", seed, 0, false).await;
    w.check_package(AMM, "amm_swap", swap, 0, false).await;

    // The owner's key named, another key's signature: 403 at the orchestrator,
    // before any node sees it.
    let mut forged = register_body("amm", Fr::from(AMM), &NAMES, 1);
    forged.signature = register_as(monty::other(), "amm", AMM, &NAMES, 1).signature;
    let before = mark(&w.proxies);
    expect(
        "REGISTER signed by another key",
        &w.post("/v1/register", &forged).await,
        ErrorClass::Forbidden,
        "does not verify under `owner_pubkey`",
    );
    assert_eq!(calls_since(&w.proxies, before), each(&[]));
    // Another owner's own signed body, and a seq that is neither the stored
    // one (a resend) nor the next one: the registry copy holds the owner and
    // the seq, so the orchestrator refuses both in the nodes' words, before
    // any node sees them (and before it builds a vk).
    expect(
        "REGISTER by a non-owner",
        &w.post(
            "/v1/register",
            &register_as(monty::other(), "amm", AMM, &NAMES, 1),
        )
        .await,
        ErrorClass::Forbidden,
        "is not the owner of namespace",
    );
    expect(
        "REGISTER with a wrong seq",
        &w.post(
            "/v1/register",
            &register_body("amm", Fr::from(AMM), &NAMES, 7),
        )
        .await,
        ErrorClass::Conflict,
        "is not the namespace's next",
    );
    assert_eq!(calls_since(&w.proxies, before), each(&[]));
    w.check_namespace(AMM, 0, first.npk_app_hash).await;
    Amm {
        npk_app_hash: first.npk_app_hash,
        vk: [seed, init, swap],
    }
}

/// What the Monty Hall registry leaves for its rounds: the npk_app_hash and
/// each circuit's vk_hash, as REGISTER answered them.
struct Monty {
    npk_app_hash: FieldHex,
    vk: BTreeMap<&'static str, FieldHex>,
}

/// The Monty Hall namespace: one manifest message, another npk_app_hash.
async fn monty_registry(w: &World, amm_npk: FieldHex) -> Monty {
    let response = w.register("monty-hall", MONTY, &MONTY_CIRCUITS, 0).await;
    assert_ne!(response.npk_app_hash, amm_npk, "two namespaces, two keys");
    let vk: BTreeMap<&'static str, FieldHex> = MONTY_CIRCUITS
        .iter()
        .map(|name| {
            let body = register_body("monty-hall", Fr::from(MONTY), &MONTY_CIRCUITS, 0);
            (*name, vk_of(&body, name))
        })
        .collect();
    let npk = response.npk_app_hash;
    w.check_namespace(MONTY, 0, npk).await;
    for name in MONTY_CIRCUITS {
        w.check_package(MONTY, name, vk[name], 0, false).await;
    }
    Monty {
        npk_app_hash: npk,
        vk,
    }
}

/// The AMM through the orchestrator: seed, init, two swaps (the second one's
/// client drops its connection mid-round and FETCHes), the refusals, DISABLE
/// of the swap and the re-enabling REGISTER of the same contract manifest,
/// and a swap on the re-enabled circuit; returns
/// swap 1 and its answer.
async fn amm_rounds(w: &World, amm: &Amm) -> (Request, ExecuteResponse) {
    let [seed_vk, init_vk, swap_vk] = amm.vk;
    let seed = amm::seed(AMM, random_id());
    let seeded = w.execute("amm seed", "amm", &seed, seed_vk).await;
    assert_eq!(seeded.stored, [SEED_KEY]);
    assert!(seeded.records.is_empty());

    let init = amm::init(AMM, random_id());
    let inited = w.execute("amm init", "amm", &init, init_vk).await;
    assert_eq!(inited.stored, [POOL_KEY]);
    let init_shape = shape("amm", "amm_init");
    let npk_index = init_shape.return_index("npk_app_hash").unwrap();
    assert_eq!(inited.public_inputs[npk_index], amm.npk_app_hash);

    let swap_shape = shape("amm", "amm_swap");
    let out_index = swap_shape.return_index("app_outputs[0]").unwrap();
    let before = pool(&w.real);
    let swap1 = amm::swap(AMM, random_id(), 25000, 0);
    let swapped1 = w.execute("amm swap 1", "amm", &swap1, swap_vk).await;
    let expected = amm::swap_out(before, 25000, false);
    assert_eq!(small(swapped1.public_inputs[out_index].fr()), expected);
    assert_eq!(pool(&w.real), [before[0] + 25000, before[1] - expected]);
    // FETCH answers what the execute answered.
    assert_eq!(w.fetch("FETCH amm swap 1", "amm", &swap1).await, swapped1);

    // Swap 2: the client sends it and drops the connection once the round
    // has reached the three nodes, as if it crashed; the nodes finish the
    // round, and the client FETCHes it.
    let before = pool(&w.real);
    let swap2 = amm::swap(AMM, random_id(), 10000, 1);
    let fetched = crashed_then_fetched(w, "amm swap 2", "amm", &swap2).await;
    let expected = amm::swap_out(before, 10000, true);
    assert_eq!(small(fetched.public_inputs[out_index].fr()), expected);
    assert_eq!(fetched.vk_hash, swap_vk);
    assert_eq!(pool(&w.real), [before[0] - expected, before[1] + 10000]);

    // The request id of swap 1 with another body: the nodes refuse it.
    let mut reused = amm::swap(AMM, random_id(), 30000, 0);
    reused.request_id = swap1.request_id;
    let before = mark(&w.proxies);
    expect(
        "swap 1's request id with another body",
        &w.post("/v1/execute", &reused).await,
        ErrorClass::Conflict,
        "with another body",
    );
    assert_eq!(calls_since(&w.proxies, before), each(&[EXECUTE]));
    // An unknown circuit and an unknown id, as a client sees them.
    w.refused_here(
        "an unregistered circuit",
        &request(AMM, "amm_drain", random_id(), &[], &[], &[]),
        ErrorClass::BadRequest,
        "amm_drain",
    )
    .await;
    expect(
        "FETCH of an unknown id",
        &w.post(
            "/v1/fetch",
            &json!({"namespace": FieldHex(Fr::from(AMM)), "request_id": random_id()}),
        )
        .await,
        ErrorClass::NotFound,
        "no request",
    );

    // DISABLE the swap (seq 1): an execute of it is refused at resolution.
    let disable = owner_signed_disable(AMM, "amm_swap", 1);
    let disabled: DisableResponse = ok("DISABLE amm_swap", &w.post("/v1/disable", &disable).await);
    assert!(disabled.disabled);
    assert_eq!(
        (disabled.vk_hash, disabled.seq, disabled.npk_app_hash),
        (swap_vk, 1, amm.npk_app_hash)
    );
    w.client.check_registry(
        "DISABLE amm_swap",
        AMM,
        "amm_swap",
        disabled.vk_hash,
        disabled.npk_app_hash,
        1,
        true,
        &disabled.signatures,
    );
    w.check_package(AMM, "amm_swap", swap_vk, 1, true).await;
    w.refused_here(
        "a swap of the disabled circuit",
        &amm::swap(AMM, random_id(), 5000, 0),
        ErrorClass::BadRequest,
        "is disabled",
    )
    .await;
    // A disabled circuit's rounds stay fetchable.
    assert_eq!(
        w.fetch("FETCH swap 2 while disabled", "amm", &swap2).await,
        fetched
    );

    // REGISTER of the same contract manifest (seq 2) re-enables it; the next
    // swap commits.
    let names = ["pss_seed", "amm_init", "amm_swap"];
    let again = w.register("amm", AMM, &names, 2).await;
    assert_eq!(
        (
            vk_of(&register_body("amm", Fr::from(AMM), &names, 2), "amm_swap"),
            again.npk_app_hash
        ),
        (swap_vk, amm.npk_app_hash)
    );
    w.check_package(AMM, "amm_swap", swap_vk, 2, false).await;
    w.check_namespace(AMM, 2, amm.npk_app_hash).await;
    let before = pool(&w.real);
    let swap3 = amm::swap(AMM, random_id(), 5000, 0);
    let swapped3 = w
        .execute("amm swap 3 after the re-REGISTER", "amm", &swap3, swap_vk)
        .await;
    let expected = amm::swap_out(before, 5000, false);
    assert_eq!(small(swapped3.public_inputs[out_index].fr()), expected);
    (swap1, swapped1)
}

// How the test simulates a client crash. The client's call
// runs in a task that is aborted as soon as the first node's proxy logs the
// execute call, which drops its connection to the orchestrator while the
// fan-out has only begun (the other two node calls may not have been made
// yet). The orchestrator runs the fan-out in a task of its own, so the three
// nodes still get the body, finish and commit the round; the test then checks
// that every node was called once and polls FETCH every 250 ms, accepting 404
// until the commit, for up to 120 s from the send. A crash before the request
// reaches the orchestrator's session is not a retry case: the client resends
// the body and the round runs once.
/// Send `req`, drop the connection once the first node has been called, wait
/// for the round to commit, and FETCH it: the FETCH answers what a resend of
/// the same body answers (the nodes answer it from their rows, with no second
/// round), and the same again on a second FETCH.
async fn crashed_then_fetched(
    w: &World,
    label: &str,
    example: &str,
    req: &Request,
) -> ExecuteResponse {
    let before = mark(&w.proxies);
    let executed = |calls: &[String]| calls.iter().filter(|c| *c == EXECUTE).count();
    let body = serde_json::to_vec(req).unwrap();
    let client = w.orch.client.clone();
    let start = Instant::now();
    let send = tokio::spawn(async move { client.post_raw("/v1/execute", body).await });
    while calls_since(&w.proxies, before)
        .iter()
        .all(|c| executed(c) == 0)
    {
        assert!(
            start.elapsed() < Duration::from_secs(60),
            "{label}: the round never reached a node"
        );
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    send.abort();
    assert!(send.await.unwrap_err().is_cancelled(), "{label}");
    eprintln!(
        "{label}: the client dropped its connection after {:.3}s, with {:?} node calls \
         made of 3",
        start.elapsed().as_secs_f64(),
        calls_since(&w.proxies, before)
            .iter()
            .map(|c| executed(c))
            .sum::<usize>()
    );
    let fetch = json!({"namespace": req.namespace, "request_id": req.request_id});
    let mut fetches = 0;
    let fetched = loop {
        let answer = w.post("/v1/fetch", &fetch).await;
        fetches += 1;
        if answer.status == 200 {
            break ok::<ExecuteResponse>(label, &answer);
        }
        // Not committed yet at every node.
        expect(
            &format!("{label}: FETCH before the commit"),
            &answer,
            ErrorClass::NotFound,
            "",
        );
        assert!(
            start.elapsed() < Duration::from_secs(120),
            "{label}: the round never committed"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    };
    eprintln!(
        "{label}: FETCH answered {:.3}s after the send",
        start.elapsed().as_secs_f64()
    );
    // The abandoned round reached every node once, and every FETCH reached
    // the three nodes once each.
    let calls = calls_since(&w.proxies, before);
    for (i, calls) in calls.iter().enumerate() {
        assert_eq!(executed(calls), 1, "{label}: node {i}'s execute calls");
        assert_eq!(
            calls.len(),
            1 + fetches,
            "{label}: node {i}'s calls: {calls:?}"
        );
        assert!(
            calls.iter().all(|c| c == EXECUTE || c == "POST /v1/fetch"),
            "{label}: node {i}'s calls: {calls:?}"
        );
    }
    w.client.check_result(
        label,
        small(req.namespace.fr()),
        &shape(example, &req.circuit),
        &fetched,
    );
    let start = Instant::now();
    let resent: ExecuteResponse = ok(label, &w.post("/v1/execute", req).await);
    eprintln!(
        "{label}: the resent body answered in {:.3}s (from the nodes' rows)",
        start.elapsed().as_secs_f64()
    );
    assert_eq!(resent, fetched, "{label}: resend and FETCH");
    let again = w
        .fetch(&format!("{label}: FETCH again"), example, req)
        .await;
    assert_eq!(again, fetched, "{label}: FETCH twice");
    fetched
}

/// Monty Hall on client-held records: the seed creates a record under the
/// requester; init supplies it back signed (unsigned and wrongly signed
/// attempts are refused first, before fan-out); the client crashes during
/// init and FETCHes the game record; open_door seals the door to the pinned
/// enc keys; finish wins by switching. Then init's name is disabled and
/// registered under the finish's circuit, and the finish is rolled back.
async fn monty_rounds(w: &World, monty: &Monty) {
    let npk = monty.npk_app_hash;
    let vk = |name: &str| monty.vk[name];
    let player_pk = public_key(monty::player());

    // The seed stores a client-held key, so it names a requester and is
    // signed; without a requester the orchestrator refuses it.
    let mut seed = monty::seed(MONTY, random_id());
    w.refused_here(
        "monty seed without a requester",
        &seed,
        ErrorClass::BadRequest,
        "field `requester`: missing",
    )
    .await;
    sign_as(&mut seed, monty::player(), monty::player());
    let seeded = w
        .execute("monty seed", "monty-hall", &seed, vk("pss_seed"))
        .await;
    assert!(seeded.stored.is_empty());
    let [record] = &seeded.records[..] else {
        panic!("one record")
    };
    assert_eq!(record.key, GAME_SEED_KEY);
    assert_eq!(opened_record(&w.real, &present(record), player_pk).len(), 2);

    // Record-supplying requests without a valid signature: 403 before fan-out.
    let mut unsigned = monty::init(MONTY, random_id(), &present(&seeded.records[0]));
    unsigned.requester = Some(point_to_wire(player_pk));
    w.refused_here(
        "monty init unsigned",
        &unsigned,
        ErrorClass::Forbidden,
        "field `signature`: missing",
    )
    .await;
    let mut forged = monty::init(MONTY, random_id(), &present(&seeded.records[0]));
    sign_as(&mut forged, monty::player(), monty::other());
    w.refused_here(
        "monty init signed by another key",
        &forged,
        ErrorClass::Forbidden,
        "does not verify under `requester`",
    )
    .await;

    // init, signed; the client crashes mid-round and FETCHes the game record.
    let mut init = monty::init(MONTY, random_id(), &present(&seeded.records[0]));
    sign_as(&mut init, monty::player(), monty::player());
    let inited = crashed_then_fetched(w, "monty init", "monty-hall", &init).await;
    assert_eq!(inited.vk_hash, vk("monty_hall_init"));
    let init_shape = shape("monty-hall", "monty_hall_init");
    let npk_index = init_shape.return_index("npk_app_hash").unwrap();
    assert_eq!(inited.public_inputs[npk_index], npk);
    let game = present(&inited.records[0]);
    assert_eq!(game.key, GAME_KEY);
    let state = opened_record(&w.real, &game, player_pk);
    assert_eq!(state.len(), monty::STATE_LEN);
    let winning = small(state[WINNING_DOOR]);
    assert!(winning < 3);

    // open_door: the door and its blinding sealed to the pinned enc keys.
    let chosen = (winning + 1) % 3;
    // The envelopes' associated data covers the requester, so the builder
    // names it before they are sealed, and the body is signed after.
    let mut open_door = monty::open_door(MONTY, random_id(), &game);
    seal_inputs(
        &mut open_door,
        &w.client.enc_pks,
        &monty::door_inputs(chosen),
    );
    sign_as(&mut open_door, monty::player(), monty::player());
    let opened = w
        .execute(
            "monty open_door",
            "monty-hall",
            &open_door,
            vk("monty_hall_open_door"),
        )
        .await;
    let out_index = shape("monty-hall", "monty_hall_open_door")
        .return_index("app_outputs[0]")
        .unwrap();
    let host_opened = small(opened.public_inputs[out_index].fr());
    assert!(host_opened < 3 && host_opened != chosen && host_opened != winning);
    let game = present(&opened.records[0]);
    let state = opened_record(&w.real, &game, player_pk);
    assert_eq!(small(state[CHOSEN_DOOR]), chosen);

    // finish: switch and win; the round creates no record.
    let mut finish = monty::finish(MONTY, random_id(), &game);
    sign_as(&mut finish, monty::player(), monty::player());
    let finished = w
        .execute(
            "monty finish",
            "monty-hall",
            &finish,
            vk("monty_hall_finish"),
        )
        .await;
    let out_index = shape("monty-hall", "monty_hall_finish")
        .return_index("app_outputs[0]")
        .unwrap();
    assert_eq!(
        finished.public_inputs[out_index],
        FieldHex::from(1),
        "switching wins"
    );
    assert!(finished.records.is_empty() && finished.stored.is_empty());
    assert_eq!(
        w.fetch("FETCH monty finish", "monty-hall", &finish).await,
        finished
    );
    // Every round of the game, FETCHed again, answers as it did.
    for (label, req, answer) in [("seed", &seed, &seeded), ("open_door", &open_door, &opened)] {
        assert_eq!(
            &w.fetch(&format!("FETCH monty {label}"), "monty-hall", req)
                .await,
            answer
        );
    }

    // DISABLE monty_hall_init (seq 1), then REGISTER a contract manifest that
    // puts the name on the finish's circuit (seq 2; the sidecar path may
    // replace its contract manifest): the init round's rows name the old vk,
    // which no package of the namespace carries any more.
    let disable = owner_signed_disable(MONTY, "monty_hall_init", 1);
    let disabled: DisableResponse = ok(
        "DISABLE monty_hall_init",
        &w.post("/v1/disable", &disable).await,
    );
    assert!(disabled.disabled);
    let mut renamed = manifest("monty-hall", "monty_hall_finish");
    renamed["circuit"] = json!("monty_hall_init");
    let packages: Vec<TestPackage> = MONTY_CIRCUITS
        .iter()
        .map(|name| match *name {
            "monty_hall_init" => {
                TestPackage::on("monty_hall_init", "monty_hall_finish", renamed.clone())
            }
            name => TestPackage::new(name, manifest("monty-hall", name)),
        })
        .collect();
    let body = signed_register(
        Fr::from(MONTY),
        sidecar_manifest("monty-hall", &packages),
        2,
    );
    let again = w.register_message(MONTY, &body).await;
    assert_eq!(
        (vk_of(&body, "monty_hall_init"), again.seq),
        (vk("monty_hall_finish"), 2)
    );
    let fetch = |req: &Request| json!({"namespace": req.namespace, "request_id": req.request_id});
    expect(
        "FETCH monty init after its name was registered again",
        &w.post("/v1/fetch", &fetch(&init)).await,
        ErrorClass::Conflict,
        "the round's circuit is no longer registered",
    );
    assert_eq!(
        w.fetch(
            "FETCH monty seed after the re-registration",
            "monty-hall",
            &seed
        )
        .await,
        seeded
    );

    // The operator rolls the finish back: its FETCH is 409.
    w.real.restore(Fr::from(MONTY), finish.request_id).await;
    expect(
        "FETCH monty finish rolled back",
        &w.post("/v1/fetch", &fetch(&finish)).await,
        ErrorClass::Conflict,
        "rolled back",
    );
}
