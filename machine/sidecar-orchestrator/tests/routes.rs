//! The public API over node stubs: every route answers in the one error
//! shape; a request refused at steps 1 to 4 (or at the ciphertext-hash check)
//! never reaches a node; node i receives only its own envelope and third; two
//! concurrent requests run one at a time; registry bodies are forwarded byte
//! for byte; `GET /v1/nodes` answers both keys of each node and refuses a key
//! that differs from the pins; the public listener refuses an oversized body
//! in the one error shape, closes a connection whose head does not arrive in
//! time and serves at most its cap of connections at once; a node that does
//! not answer in time is a 500 naming it, and the session lock is released;
//! a node's own refusal wins over the handshake verdicts that relay it; a
//! registry body the copy's owner and `seq` refuse, or whose contract
//! manifest fails its checks (a stale period of 0, an upgradable app with no
//! stale period, a non-secret-shared key reader beside a secret-shared
//! writer), never costs a vk build or reaches a node; a client that disconnects mid-round leaves the round
//! running under the session lock until the three nodes have answered; a
//! registry sync refuses nodes that disagree or a vk_hash the circuit does not
//! build to, and leaves the copy as it was; the start-up registry check names
//! every row the three nodes and the copy differ on, and whose it is,
//! `GET /v1/status` answers its counts and when it ran and never a row, and
//! the admin socket's `status` answers the rows; the check reruns after a
//! registry body a node may have written and on its timer; at most two
//! manifest messages' vk builds run at once.
//!
//! The stubs answer what each test tells them (409 by default), so nothing
//! here proves; the orchestrator's registry copy is seeded with the Monty Hall
//! circuits directly (one contract manifest at seq 0, then again at seq 1). Needs the CRS and the compiled circuits of
//! `scripts/prepare-data.sh` (a test fails naming what is missing). Run with
//! `--release`.

mod common;

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::http::Method;
use common::*;
use rand::rngs::OsRng;
use sidecar_core::field::{FieldHex, Fr, HexBytes, RequestId, fr_to_be_bytes, fr_to_hex};
use sidecar_core::grumpkin::{Fq, point_to_wire};
use sidecar_core::record::record_hash;
use sidecar_core::register::{
    ContractManifestResponse, DisableRequest, ManifestMessage, NamespaceResponse, PackageResponse,
    Signature,
};
use sidecar_core::registry_check::Divergence;
use sidecar_core::request::{
    NodeRequest, PublicValue, Request, ShareCiphertext, SharedInput, StateKeys, StateRecord,
};
use sidecar_core::response::NodesResponse;
use sidecar_core::schnorr::{self, public_key};
use sidecar_core::{ErrorClass, Refusal};
use sidecar_http::client::Answer;
use sidecar_http::listen::ListenerLimits;
use sidecar_orchestrator::api::PUBLIC_MAX_BODY_BYTES;
use sidecar_orchestrator::status::{
    RegistryCounts, RegistryStatus, RegistrySummary, StatusResponse, When, check_registry,
    spawn_timer,
};
use tokio::io::AsyncWriteExt;

const MONTY: u64 = 0x40e7;
const SEED_KEY: &str = "0xc001";
const GAME_KEY: &str = "0xc002";
const CIRCUITS: [&str; 2] = ["pss_seed", "monty_hall_open_door"];

fn ns() -> Fr {
    Fr::from(MONTY)
}

fn player() -> Fq {
    Fq::from(0x009a_7e12_u64)
}

fn id(n: u64) -> RequestId {
    RequestId::from(0x5eed_0000 + n)
}

fn request(circuit: &str, n: u64, reads: &[&str], writes: &[&str]) -> Request {
    Request {
        namespace: FieldHex(ns()),
        circuit: circuit.to_string(),
        request_id: id(n),
        public: Default::default(),
        state_keys: StateKeys {
            reads: reads.iter().map(|k| k.to_string()).collect(),
            writes: writes.iter().map(|k| k.to_string()).collect(),
        },
        shared_inputs: vec![],
        records: vec![],
        requester: None,
        signature: None,
        chain_request_id: None,
        shared_log: None,
        manifest_hash: None,
    }
}

fn sign(req: &mut Request, requester: Fq, signer: Fq) {
    req.requester = Some(point_to_wire(public_key(requester)));
    req.signature = Some(schnorr::sign(signer, req.signed_message(), &mut OsRng));
}

/// A signed seed: stores a client-held key, so it needs its requester.
fn seed(n: u64) -> Request {
    let mut req = request("pss_seed", n, &[], &[SEED_KEY]);
    sign(&mut req, player(), player());
    req
}

/// A third that parses as a sealed record: node i's key id, then three
/// distinct field elements.
fn third(i: usize, tag: u64) -> HexBytes {
    let mut bytes = vec![0xa0 + i as u8; 8];
    for k in 0..3 {
        bytes.extend(fr_to_be_bytes(Fr::from(tag * 1000 + 10 * i as u64 + k)));
    }
    HexBytes(bytes)
}

fn envelope(i: usize, tag: u64) -> ShareCiphertext {
    ShareCiphertext {
        eph: point_to_wire(public_key(Fq::from(tag * 10 + i as u64 + 1))),
        ct: [
            FieldHex::from(tag * 1000 + 100 + i as u64),
            FieldHex::from(tag * 1000 + 200 + i as u64),
        ],
        tag: FieldHex::from(tag * 1000 + 300 + i as u64),
    }
}

/// A signed open-door request: one supplied record and two shared inputs,
/// each with a different ciphertext per node.
fn open_door(n: u64) -> Request {
    let mut req = request("monty_hall_open_door", n, &[GAME_KEY], &[GAME_KEY]);
    req.public
        .insert("in0_nonce".into(), PublicValue::One(FieldHex::from(7)));
    for (k, name) in ["door", "door_randomness"].iter().enumerate() {
        let shares = [0, 1, 2].map(|i| envelope(i, k as u64 + 1));
        req.shared_inputs.push(SharedInput {
            name: name.to_string(),
            share_hashes: shares.map(|s| FieldHex(s.hash())),
            shares,
        });
    }
    let c = [0, 1, 2].map(|i| third(i, 9));
    req.records.push(StateRecord {
        key: GAME_KEY.into(),
        note_hash: FieldHex::from(0x4e4e),
        record_hashes: c
            .clone()
            .map(|c| FieldHex(record_hash(c.as_slice()).unwrap())),
        c,
    });
    sign(&mut req, player(), player());
    req
}

struct Net {
    tmp: TempDir,
    certs: std::path::PathBuf,
    stubs: Stubs,
    orch: Started,
    keys: [sidecar_core::keys::NodeKeys; 3],
    crs: sidecar_core::crs::Crs,
}

async fn network(label: &str) -> Net {
    let crs = require_crs(&CIRCUITS);
    let tmp = TempDir::new(label);
    let certs = dev_certs(tmp.path());
    let keys = stub_keys();
    let pins = pins_of(&keys);
    let stubs = Stubs::start(&certs, default_respond(pins.nodes)).await;
    let orch = start_orchestrator(
        &certs,
        stubs.addrs,
        pins,
        &tmp.path().join("registry"),
        crs.clone(),
    )
    .await;
    for seq in [0, 1] {
        seed_registry(orch.registry(), "monty-hall", ns(), &CIRCUITS, seq);
    }
    Net {
        tmp,
        certs,
        stubs,
        orch,
        keys,
        crs,
    }
}

fn refusal_of(answer: &Answer) -> Refusal {
    let refusal = answer.json::<serde_json::Value>().unwrap().unwrap_err();
    assert_eq!(answer.status, refusal.status());
    refusal
}

fn expect(answer: &Answer, class: ErrorClass, needle: &str) {
    let refusal = refusal_of(answer);
    assert_eq!(refusal.class, class, "{refusal}");
    assert!(refusal.message.contains(needle), "{refusal}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_request_refused_at_steps_1_to_4_never_reaches_a_node() {
    let net = network("prefix").await;
    let text = |req: &Request| serde_json::to_string(req).unwrap();
    let mut cases: Vec<(String, ErrorClass, &str)> = vec![
        ("not json".into(), ErrorClass::BadRequest, "body"),
        ("{}".into(), ErrorClass::BadRequest, "missing field"),
    ];
    // 1 parse: an unknown field, a key twice, the fixed key as a request key.
    let mut v: serde_json::Value = serde_json::to_value(seed(1)).unwrap();
    v["effects"] = serde_json::json!({});
    cases.push((v.to_string(), ErrorClass::BadRequest, "effects"));
    let mut twice = request("pss_seed", 2, &[], &[SEED_KEY, SEED_KEY]);
    sign(&mut twice, player(), player());
    cases.push((text(&twice), ErrorClass::BadRequest, "twice"));
    let mut fixed = request("pss_seed", 3, &[], &["nsk_app"]);
    sign(&mut fixed, player(), player());
    cases.push((text(&fixed), ErrorClass::BadRequest, "nsk_app"));
    // 3 resolve: an unknown circuit, a wrong key count.
    let mut unknown = request("monty_hall_finish", 4, &[GAME_KEY], &[GAME_KEY]);
    sign(&mut unknown, player(), player());
    cases.push((text(&unknown), ErrorClass::BadRequest, "is not registered"));
    let mut counts = request("pss_seed", 5, &[], &[SEED_KEY, GAME_KEY]);
    sign(&mut counts, player(), player());
    cases.push((text(&counts), ErrorClass::BadRequest, "takes 1 key"));
    // 4 authenticate: no requester (400), no signature (403), a signature by
    // another key (403).
    let anonymous = request("pss_seed", 6, &[], &[SEED_KEY]);
    cases.push((
        text(&anonymous),
        ErrorClass::BadRequest,
        "field `requester`: missing",
    ));
    let mut unsigned = request("pss_seed", 7, &[], &[SEED_KEY]);
    unsigned.requester = Some(point_to_wire(public_key(player())));
    cases.push((
        text(&unsigned),
        ErrorClass::Forbidden,
        "field `signature`: missing",
    ));
    let mut forged = request("pss_seed", 8, &[], &[SEED_KEY]);
    sign(&mut forged, player(), Fq::from(0xbad_u64));
    cases.push((text(&forged), ErrorClass::Forbidden, "does not verify"));
    // The ciphertext hashes, for all three nodes: a third that does not hash
    // to its record hash, an envelope that does not hash to its share hash.
    let mut bad_third = open_door(9);
    bad_third.records[0].c[1] = third(1, 8);
    sign(&mut bad_third, player(), player());
    cases.push((text(&bad_third), ErrorClass::BadRequest, "record_hashes[1]"));
    let mut bad_share = open_door(10);
    bad_share.shared_inputs[1].shares[2] = envelope(2, 5);
    sign(&mut bad_share, player(), player());
    cases.push((text(&bad_share), ErrorClass::BadRequest, "share_hashes[2]"));

    for (body, class, needle) in &cases {
        let answer = net.orch.post("/v1/execute", body.clone()).await;
        expect(&answer, *class, needle);
    }
    assert_eq!(
        net.stubs.net.total_calls(),
        0,
        "a refused request reached a node"
    );

    // A request that passes is sent, once, to each node, and the stubs'
    // refusal comes back in the one error shape, naming the node.
    let answer = net.orch.post_json("/v1/execute", &seed(11)).await;
    expect(&answer, ErrorClass::Conflict, "node 0: stub refuses");
    for i in 0..3 {
        let calls = net.stubs.net.calls(i);
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].path, "/v1/execute");
        assert_eq!(calls[0].method, Method::POST);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn node_i_receives_only_its_own_share_and_third() {
    let net = network("project").await;
    let req = open_door(1);
    let answer = net.orch.post_json("/v1/execute", &req).await;
    expect(&answer, ErrorClass::Conflict, "stub refuses");
    for i in 0..3 {
        let calls = net.stubs.net.calls(i);
        assert_eq!(calls.len(), 1);
        let text = std::str::from_utf8(&calls[0].body).unwrap();
        let got = NodeRequest::from_json(text).unwrap();
        assert_eq!(got, req.project(i), "node {i}'s view");
        // Its own ciphertexts, the three hashes whole.
        assert_eq!(got.records[0].c_i, req.records[0].c[i]);
        assert_eq!(got.records[0].record_hashes, req.records[0].record_hashes);
        for (k, input) in got.shared_inputs.iter().enumerate() {
            assert_eq!(input.share, req.shared_inputs[k].shares[i]);
            assert_eq!(input.share_hashes, req.shared_inputs[k].share_hashes);
        }
        got.check_own_ciphertexts(i).unwrap();
        // No other node's third or envelope appears anywhere in the body.
        for j in (0..3).filter(|j| *j != i) {
            let other = req.records[0].c[j].to_string();
            assert!(!text.contains(&other[2..]), "node {i} got node {j}'s third");
            for input in &req.shared_inputs {
                for field in [
                    input.shares[j].ct[0],
                    input.shares[j].ct[1],
                    input.shares[j].tag,
                ] {
                    assert!(
                        !text.contains(&fr_to_hex(field.fr())),
                        "node {i} got node {j}'s envelope"
                    );
                }
            }
        }
        let value: serde_json::Value = serde_json::from_str(text).unwrap();
        assert!(value["records"][0].get("c").is_none());
        assert!(value["shared_inputs"][0].get("shares").is_none());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn two_concurrent_requests_run_one_at_a_time() {
    let net = network("serial").await;
    *net.stubs.net.delay.lock().unwrap() = Duration::from_millis(400);
    let start = Instant::now();
    let (one, two) = (seed(1), seed(2));
    let (a, b) = tokio::join!(
        net.orch.post_json("/v1/execute", &one),
        net.orch.post_json("/v1/execute", &two),
    );
    let elapsed = start.elapsed();
    expect(&a, ErrorClass::Conflict, "stub refuses");
    expect(&b, ErrorClass::Conflict, "stub refuses");
    assert_eq!(*net.stubs.net.max_sessions.lock().unwrap(), 1);
    assert!(elapsed >= Duration::from_millis(800), "{elapsed:?}");
    for i in 0..3 {
        assert_eq!(net.stubs.net.calls(i).len(), 2);
    }
    // FETCH and the GETs take no session: they are answered while an execute
    // holds it, its node calls held until the test releases them.
    *net.stubs.net.delay.lock().unwrap() = Duration::ZERO;
    net.stubs.net.clear();
    let release = Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
    let held = release.clone();
    net.stubs.net.set(Arc::new(move |_, _, path, _| {
        if path == "/v1/execute" {
            let (released, signal) = &*held;
            let mut released = released.lock().unwrap();
            while !*released {
                released = signal.wait(released).unwrap();
            }
        }
        refused(ErrorClass::Conflict, "stub refuses")
    }));
    let execute = {
        let (client, three) = (net.orch.client.clone(), seed(3));
        tokio::spawn(async move { client.post("/v1/execute", &three).await.unwrap() })
    };
    while (0..3).any(|i| net.stubs.net.calls(i).is_empty()) {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let body = serde_json::json!({"namespace": FieldHex(ns()), "request_id": id(1)});
    let path = format!("/v1/packages/{}/pss_seed", fr_to_hex(ns()));
    let (fetched, pkg) = tokio::time::timeout(Duration::from_secs(30), async {
        tokio::join!(net.orch.post_json("/v1/fetch", &body), net.orch.get(&path))
    })
    .await
    .expect("FETCH and GET waited for the execute's session");
    expect(&fetched, ErrorClass::Conflict, "stub refuses");
    assert_eq!(pkg.status, 200);
    assert!(
        !execute.is_finished(),
        "the execute ended before the release"
    );
    *release.0.lock().unwrap() = true;
    release.1.notify_all();
    expect(
        &execute.await.unwrap(),
        ErrorClass::Conflict,
        "stub refuses",
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn get_nodes_answers_both_keys_per_node_and_refuses_a_pin_mismatch() {
    let mut net = network("nodes").await;
    let pins = pins_of(&net.keys);
    let answer = net.orch.get("/v1/nodes").await;
    let served: NodesResponse = answer.json().unwrap().unwrap();
    assert_eq!(served, pins);
    let value: serde_json::Value = serde_json::from_slice(&answer.body).unwrap();
    for i in 0..3 {
        for key in ["enc", "sig"] {
            assert!(value["nodes"][i][key]["x"].is_string(), "node {i} {key}");
        }
    }
    // An orchestrator pinned to another key refuses the answer, naming it:
    // node 2's sig, then node 0's enc.
    let pinned_to = |wrong: NodesResponse, registry: &'static str| {
        let dir = net.tmp.path().join(registry);
        let (certs, addrs, crs) = (net.certs.clone(), net.stubs.addrs, net.crs.clone());
        async move { start_orchestrator(&certs, addrs, wrong, &dir, crs).await }
    };
    let mut wrong = pins;
    wrong.nodes[2].sig = point_to_wire(public_key(Fq::from(999u64)));
    let other = pinned_to(wrong, "registry2").await;
    expect(
        &other.get("/v1/nodes").await,
        ErrorClass::MpcFailure,
        "node 2's sig",
    );
    drop(other);
    let mut wrong = pins;
    wrong.nodes[0].enc = pins.nodes[1].enc;
    let other = pinned_to(wrong, "registry3").await;
    expect(
        &other.get("/v1/nodes").await,
        ErrorClass::MpcFailure,
        "node 0's enc",
    );
    // A node that does not answer is 500 naming it.
    net.stubs.stop(1);
    expect(
        &net.orch.get("/v1/nodes").await,
        ErrorClass::MpcFailure,
        "node 1: no answer",
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_route_answers_in_the_one_error_shape() {
    let net = network("routes").await;
    let ns_hex = fr_to_hex(ns());

    // GET /v1/packages and /v1/namespaces answer from the registry copy.
    let pkg: PackageResponse = net
        .orch
        .get(&format!("/v1/packages/{ns_hex}/monty_hall_open_door"))
        .await
        .json()
        .unwrap()
        .unwrap();
    assert_eq!(pkg.seq, 1);
    assert!(!pkg.disabled);
    assert_eq!(pkg.manifest, manifest("monty-hall", "monty_hall_open_door"));
    let info: NamespaceResponse = net
        .orch
        .get(&format!("/v1/namespaces/{ns_hex}"))
        .await
        .json()
        .unwrap()
        .unwrap();
    assert_eq!(info.seq, 1);
    assert_eq!(info.owner_pubkey, point_to_wire(public_key(owner_secret())));
    expect(
        &net.orch.get(&format!("/v1/packages/{ns_hex}/nope")).await,
        ErrorClass::NotFound,
        "no circuit `nope`",
    );
    expect(
        &net.orch.get("/v1/namespaces/0x99").await,
        ErrorClass::NotFound,
        "no namespace",
    );
    expect(
        &net.orch.get("/v1/namespaces/zz").await,
        ErrorClass::BadRequest,
        "path `namespace`",
    );
    assert_eq!(net.stubs.net.total_calls(), 0);

    // POST /v1/fetch fans out; a node without the row makes it 404, ahead of
    // another node's 409.
    net.stubs.net.set(Arc::new(|i, _, path, _| match (i, path) {
        (1, "/v1/fetch") => refused(ErrorClass::NotFound, "no request"),
        _ => refused(ErrorClass::Conflict, "rolled back"),
    }));
    let body = serde_json::json!({"namespace": FieldHex(ns()), "request_id": id(1)});
    expect(
        &net.orch.post_json("/v1/fetch", &body).await,
        ErrorClass::NotFound,
        "node 1: no request",
    );
    for i in 0..3 {
        let calls = net.stubs.net.calls(i);
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].path, "/v1/fetch");
        assert_eq!(calls[0].json(), body);
    }
    expect(
        &net.orch.post("/v1/fetch", r#"{"namespace":"0x1"}"#).await,
        ErrorClass::BadRequest,
        "request_id",
    );
    net.stubs.net.clear();
    net.stubs.net.set(Arc::new(|_, _, _, _| {
        refused(ErrorClass::Conflict, "stub refuses")
    }));

    // POST /v1/register: a malformed body (400) and a bad owner signature
    // (403) never reach a node; a good body is forwarded byte for byte, here
    // pretty-printed, which its signature (over the canonical body) allows.
    let body = register_body("monty-hall", ns(), &["monty_hall_finish"], 2);
    expect(
        &net.orch.post("/v1/register", "{").await,
        ErrorClass::BadRequest,
        "EOF",
    );
    let mut forged = body.clone();
    forged.seq = 3;
    expect(
        &net.orch.post_json("/v1/register", &forged).await,
        ErrorClass::Forbidden,
        "REGISTER signature",
    );
    assert_eq!(net.stubs.net.total_calls(), 0);
    let raw = serde_json::to_vec_pretty(&body).unwrap();
    expect(
        &net.orch.post("/v1/register", raw.clone()).await,
        ErrorClass::Conflict,
        "node 0",
    );
    for i in 0..3 {
        let calls = net.stubs.net.calls(i);
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].path, "/v1/register");
        assert_eq!(calls[0].body, raw, "node {i} got other bytes");
    }
    net.stubs.net.clear();

    // POST /v1/disable: the same rules.
    let mut disable = DisableRequest {
        namespace: FieldHex(ns()),
        circuit: "pss_seed".into(),
        owner_pubkey: point_to_wire(public_key(owner_secret())),
        seq: 2,
        signature: Signature::default(),
    };
    expect(
        &net.orch.post_json("/v1/disable", &disable).await,
        ErrorClass::Forbidden,
        "DISABLE signature",
    );
    assert_eq!(net.stubs.net.total_calls(), 0);
    let message = schnorr::message_for(
        schnorr::DISABLE_DOMAIN,
        &serde_json::to_value(&disable).unwrap(),
    )
    .unwrap();
    disable.signature = schnorr::sign(owner_secret(), message, &mut OsRng);
    net.stubs.net.set(Arc::new(|_, _, _, _| {
        refused(ErrorClass::NotFound, "no circuit")
    }));
    let raw = serde_json::to_vec(&disable).unwrap();
    expect(
        &net.orch.post("/v1/disable", raw.clone()).await,
        ErrorClass::NotFound,
        "node 0: no circuit",
    );
    for i in 0..3 {
        assert_eq!(net.stubs.net.calls(i)[0].body, raw);
    }
    // The disable was refused: the copy still resolves the circuit.
    assert!(
        !net.orch
            .get(&format!("/v1/packages/{ns_hex}/pss_seed"))
            .await
            .json::<PackageResponse>()
            .unwrap()
            .unwrap()
            .disabled
    );

    // An unknown route, or a known one under another method, is 404.
    expect(
        &net.orch.get("/v1/execute").await,
        ErrorClass::NotFound,
        "no route GET /v1/execute",
    );
    expect(
        &net.orch.post("/v1/restore", "{}").await,
        ErrorClass::NotFound,
        "no route",
    );
    expect(&net.orch.get("/").await, ErrorClass::NotFound, "no route");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_public_listener_bounds_bodies_heads_and_connections() {
    let net = network("listener").await;
    // A second orchestrator over the same stubs with a 1 s head timeout and
    // room for two connections, and four in their handshake.
    let limits = ListenerLimits {
        tls_handshake: Duration::from_secs(10),
        header_read: Duration::from_secs(1),
        max_connections: 2,
        max_handshakes: 4,
    };
    let orch = start_orchestrator_with(
        &net.certs,
        net.stubs.addrs,
        pins_of(&net.keys),
        &net.tmp.path().join("registry-limits"),
        net.crs.clone(),
        limits,
        Duration::from_secs(120),
    )
    .await;
    let addr = orch.running.addr;

    // A body one byte over the limit: 413 in the one error shape, class
    // bad_request, naming the limit; no node is called.
    let mut conn = raw_public(&net.certs, addr).await;
    let head = format!(
        "POST /v1/execute HTTP/1.1\r\nhost: localhost\r\ncontent-type: application/json\r\n\
         content-length: {}\r\n\r\n",
        PUBLIC_MAX_BODY_BYTES + 1
    );
    conn.write_all(head.as_bytes()).await.unwrap();
    conn.write_all(b"{").await.unwrap();
    let answer = read_to_close(&mut conn).await;
    assert!(answer.starts_with("HTTP/1.1 413"), "{answer}");
    let body = answer.split("\r\n\r\n").nth(1).unwrap();
    let refusal: Refusal = serde_json::from_str(body).unwrap();
    assert_eq!(refusal.class, ErrorClass::BadRequest);
    assert!(
        refusal.message.contains(&PUBLIC_MAX_BODY_BYTES.to_string()),
        "{refusal}"
    );
    // The node client reads the same answer as a bad_request refusal.
    let parsed = Answer {
        status: 413,
        body: body.as_bytes().to_vec(),
    };
    assert_eq!(
        parsed.json::<serde_json::Value>().unwrap().unwrap_err(),
        refusal
    );
    assert_eq!(net.stubs.net.total_calls(), 0);

    // Half a request line, then nothing: the listener closes the connection
    // once the head timeout passes.
    let mut conn = raw_public(&net.certs, addr).await;
    let start = Instant::now();
    conn.write_all(b"POST /v1/exe").await.unwrap();
    conn.flush().await.unwrap();
    let rest = tokio::time::timeout(Duration::from_secs(10), read_to_close(&mut conn))
        .await
        .expect("the listener never closed a connection whose head did not arrive");
    let waited = start.elapsed();
    assert!(waited >= Duration::from_millis(900), "{waited:?}");
    assert!(!rest.contains("200 OK"), "{rest}");
    eprintln!("a trickling head was closed after {waited:?}");

    // Two TCP connections that never start their handshake take no
    // connection slot: a client is served at once, long before the 10 s
    // handshake bound would close them.
    let silent = [
        tokio::net::TcpStream::connect(addr).await.unwrap(),
        tokio::net::TcpStream::connect(addr).await.unwrap(),
    ];
    let start = Instant::now();
    let served = tokio::time::timeout(Duration::from_secs(5), orch.get("/v1/nodes"))
        .await
        .expect("silent connections held the connection slots");
    assert_eq!(served.status, 200);
    assert!(start.elapsed() < Duration::from_secs(5));
    drop(silent);

    // Two idle connections fill the cap: a third client is served only once
    // the head timeout has closed them.
    let idle = [
        raw_public(&net.certs, addr).await,
        raw_public(&net.certs, addr).await,
    ];
    let start = Instant::now();
    let served = tokio::time::timeout(Duration::from_secs(10), orch.get("/v1/nodes"))
        .await
        .expect("the third connection was never served");
    let waited = start.elapsed();
    assert_eq!(served.status, 200);
    assert!(waited >= Duration::from_millis(500), "{waited:?}");
    eprintln!("the third connection was served after {waited:?}");
    drop(idle);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_node_that_does_not_answer_in_time_is_a_500_and_frees_the_session() {
    let net = network("timeout").await;
    let orch = start_orchestrator_with(
        &net.certs,
        net.stubs.addrs,
        pins_of(&net.keys),
        &net.tmp.path().join("registry-timeout"),
        net.crs.clone(),
        sidecar_orchestrator::server::PUBLIC_LISTENER,
        Duration::from_millis(500),
    )
    .await;
    for seq in [0, 1] {
        seed_registry(orch.registry(), "monty-hall", ns(), &CIRCUITS, seq);
    }
    *net.stubs.net.delay.lock().unwrap() = Duration::from_secs(3);
    let start = Instant::now();
    let answer = orch.post_json("/v1/execute", &seed(1)).await;
    expect(&answer, ErrorClass::MpcFailure, "node 0: no answer: ");
    expect(&answer, ErrorClass::MpcFailure, "no answer within 500ms");
    assert!(
        start.elapsed() < Duration::from_secs(2),
        "{:?}",
        start.elapsed()
    );
    // The session lock was released with the answer: the next request is
    // sent at once.
    *net.stubs.net.delay.lock().unwrap() = Duration::ZERO;
    let start = Instant::now();
    let answer = orch.post_json("/v1/execute", &seed(2)).await;
    expect(&answer, ErrorClass::Conflict, "stub refuses");
    assert!(
        start.elapsed() < Duration::from_secs(2),
        "{:?}",
        start.elapsed()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_refusing_node_s_class_wins_over_the_verdicts_it_caused() {
    let net = network("relayed").await;
    // Node 2 refuses a REGISTER body locally (409, as for a wrong seq), and
    // the other two refuse at the handshake on its verdict.
    net.stubs.net.set(Arc::new(|i, _, _, _| match i {
        2 => refused(
            ErrorClass::Conflict,
            "a seq 0 REGISTER is accepted only while the namespace's seq is 0; it is 1",
        ),
        _ => refused(
            ErrorClass::BadRequest,
            "session handshake: node 2 refused the request: a seq 0 REGISTER is accepted \
             only while the namespace's seq is 0; it is 1",
        ),
    }));
    let body = register_body("monty-hall", ns(), &["monty_hall_finish"], 2);
    expect(
        &net.orch.post_json("/v1/register", &body).await,
        ErrorClass::Conflict,
        "node 2: a seq 0 REGISTER",
    );
    // An execute node 1 refuses 403 behind the same kind of verdicts.
    net.stubs.net.set(Arc::new(|i, _, _, _| match i {
        1 => refused(ErrorClass::Forbidden, "not the owner"),
        _ => refused(
            ErrorClass::BadRequest,
            "session handshake: node 1 refused the request: not the owner",
        ),
    }));
    expect(
        &net.orch.post_json("/v1/execute", &seed(1)).await,
        ErrorClass::Forbidden,
        "node 1: not the owner",
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_registry_body_the_copy_refuses_costs_no_vk_build() {
    let net = network("precheck").await;
    // Bodies whose circuit has the real ABI but no program in its bytecode:
    // had the orchestrator built a vk first, each would be 400 naming the
    // circuit.
    let intruder = Fq::from(0xbad_u64);
    let stranger = junk_body(ns(), intruder, 2);
    expect(
        &net.orch.post_json("/v1/register", &stranger).await,
        ErrorClass::Forbidden,
        "is not the owner of namespace",
    );
    // The owner's own bodies with a seq the copy refuses: 7 (the copy holds
    // seq 1, so the next is 2), and 0 for a namespace past seq 0.
    for (seq, needle) in [
        (7, "registry body seq 7 is not the namespace's next (2)"),
        (
            0,
            "a seq 0 REGISTER is accepted only while the namespace's seq is 0",
        ),
    ] {
        expect(
            &net.orch
                .post_json("/v1/register", &junk_body(ns(), owner_secret(), seq))
                .await,
            ErrorClass::Conflict,
            needle,
        );
    }
    // A DISABLE with a wrong seq, and one by another key.
    let disable = |key: Fq, seq: u64| {
        let mut body = DisableRequest {
            namespace: FieldHex(ns()),
            circuit: "pss_seed".into(),
            owner_pubkey: point_to_wire(public_key(key)),
            seq,
            signature: Signature::default(),
        };
        let message = schnorr::message_for(
            schnorr::DISABLE_DOMAIN,
            &serde_json::to_value(&body).unwrap(),
        )
        .unwrap();
        body.signature = schnorr::sign(key, message, &mut OsRng);
        body
    };
    expect(
        &net.orch
            .post_json("/v1/disable", &disable(owner_secret(), 5))
            .await,
        ErrorClass::Conflict,
        "is not the namespace's next",
    );
    expect(
        &net.orch
            .post_json("/v1/disable", &disable(intruder, 2))
            .await,
        ErrorClass::Forbidden,
        "is not the owner of namespace",
    );
    assert_eq!(
        net.stubs.net.total_calls(),
        0,
        "a refused body reached a node"
    );
    // The next seq passes the copy and reaches the vk build, which refuses the
    // junk circuit; a namespace the copy does not hold passes to the vk build
    // too, for the nodes to decide.
    let next = junk_body(ns(), owner_secret(), 2);
    expect(
        &net.orch.post_json("/v1/register", &next).await,
        ErrorClass::BadRequest,
        JUNK,
    );
    let elsewhere = junk_body(Fr::from(0x5151u64), owner_secret(), 4);
    expect(
        &net.orch.post_json("/v1/register", &elsewhere).await,
        ErrorClass::BadRequest,
        JUNK,
    );
    assert_eq!(net.stubs.net.total_calls(), 0);

    // The vk builds are bounded: with every permit taken, a body waits for
    // one, and runs once a permit is free.
    let permits = net
        .orch
        .app
        .vk_builds
        .clone()
        .acquire_many_owned(sidecar_orchestrator::api::MAX_CONCURRENT_VK_BUILDS as u32)
        .await
        .unwrap();
    let waiting = {
        let client = net.orch.client.clone();
        tokio::spawn(async move { client.post("/v1/register", &elsewhere).await.unwrap() })
    };
    drop(permits);
    let answer = tokio::time::timeout(Duration::from_secs(30), waiting)
        .await
        .expect("the waiting build ran once a permit was free")
        .unwrap();
    expect(&answer, ErrorClass::BadRequest, JUNK);
}

/// What the vk build of a junk circuit answers.
const JUNK: &str = "field `circuits.monty_hall_finish`: ";

/// `circuit`'s compiled JSON with no program in its bytecode: the real ABI,
/// so a body carrying it passes every check before the vk build.
fn junk(circuit: &str) -> serde_json::Value {
    let mut junk = circuit_json(circuit);
    junk["bytecode"] = serde_json::json!("H4sIAAAAAAAA/wMAAAAAAAAAAAA=");
    junk
}

/// A manifest message of `document` under `namespace` at `seq` whose
/// circuits are junk ([`junk`]), naming `key` as the owner and signed by it.
/// Signed without the body checks, so a document the checks refuse reaches
/// the orchestrator.
fn junk_message(namespace: Fr, document: serde_json::Value, key: Fq, seq: u64) -> ManifestMessage {
    let circuits: BTreeMap<String, serde_json::Value> = document["circuits"]
        .as_object()
        .unwrap()
        .keys()
        .map(|id| (id.clone(), junk(id)))
        .collect();
    let mut body = manifest_message(namespace, document, &circuits, key, seq);
    let message = schnorr::message_for(
        schnorr::REGISTER_DOMAIN,
        &serde_json::to_value(&body).unwrap(),
    )
    .unwrap();
    body.signature = schnorr::sign(key, message, &mut OsRng);
    body
}

/// A manifest message of Monty Hall's finish whose circuit is junk.
fn junk_body(namespace: Fr, key: Fq, seq: u64) -> ManifestMessage {
    let finish = TestPackage::new(
        "monty_hall_finish",
        manifest("monty-hall", "monty_hall_finish"),
    );
    junk_message(
        namespace,
        sidecar_manifest("monty-hall", &[finish]),
        key,
        seq,
    )
}

/// The queued manifests of the machine's test counter (machine/circuits,
/// as tests/scheduler.rs registers them): the init round, which writes the
/// one chain-held key, and the round on it.
fn counter_manifest(name: &str) -> serde_json::Value {
    if name == "tip_counter_init" {
        serde_json::json!({
            "manifest": 1,
            "circuit": "tip_counter_init",
            "namespace_param": "namespace",
            "state_keys": {"reads": 0, "writes": 1},
            "intake": "onchain",
            "outcome": "none",
            "witness": [
                {"param": "namespace", "from": {"PUBLIC": "$namespace"}},
                {"param": "out_slots", "from": {"PUBLIC": ["$state_keys.writes[0]"]}},
                {"param": "start", "from": {"PUBLIC": "start"}},
                {"param": "r_new", "from": {"SAMPLE": 1}}
            ],
            "outputs": [
                {"TACEO_store": "out0", "STORE": "$state_keys.writes[0]", "len": 2, "note_hash": "new_c"}
            ],
            "state": {"$state_keys.writes[0]": "chain"}
        })
    } else {
        serde_json::json!({
            "manifest": 1,
            "circuit": "tip_counter",
            "namespace_param": "namespace",
            "state_keys": {"reads": 1, "writes": 1},
            "intake": "onchain",
            "outcome": "none",
            "witness": [
                {"param": "namespace", "from": {"PUBLIC": "$namespace"}},
                {"param": "in_slots", "from": {"PUBLIC": ["$state_keys.reads[0]"]}},
                {"param": "out_slots", "from": {"PUBLIC": ["$state_keys.writes[0]"]}},
                {"param": "amount", "from": {"PUBLIC": "amount"}},
                {"param": "value", "from": {"LOAD": "$state_keys.reads[0]", "slice": [0, 1], "len": 2}},
                {"param": "r_old", "from": {"LOAD": "$state_keys.reads[0]", "slice": [1, 2], "len": 2}},
                {"param": "r_new", "from": {"SAMPLE": 1}}
            ],
            "outputs": [
                {"TACEO_store": "out0", "STORE": "$state_keys.writes[0]", "len": 2, "note_hash": "new_c"}
            ],
            "state": {"$state_keys.reads[0]": "chain", "$state_keys.writes[0]": "chain"},
            "commitment_slot": {"$state_keys.reads[0]": {"old": "old_c"}}
        })
    }
}

/// The contract manifest of the tip namespace `tip` with the queued
/// `packages` on the counter key, under the stale period `stale_blocks`.
fn counter_contract(packages: &[TestPackage], stale_blocks: Option<u64>) -> serde_json::Value {
    counter_contract_on(packages, stale_blocks, &[("counter", Fr::from(0x7c01u64))])
}

/// The same with the state keys `keys`.
fn counter_contract_on(
    packages: &[TestPackage],
    stale_blocks: Option<u64>,
    keys: &[(&str, Fr)],
) -> serde_json::Value {
    let tip = TipFacts {
        stale_blocks,
        ..TipFacts::new(Fr::from(12u64), packages.len(), keys)
    };
    contract_manifest("counter", packages, Some(&tip), vk_hash)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_queued_body_whose_contract_manifest_fails_its_checks_reaches_no_node() {
    let net = network("contract-checks").await;
    let tip = Fr::from(0x7171u64);
    let init = TestPackage::new("tip_counter_init", counter_manifest("tip_counter_init"))
        .keys(&[], &["counter"]);
    let round = TestPackage::new("tip_counter", counter_manifest("tip_counter"))
        .keys(&["counter"], &["counter"]);
    let packages = [init.clone(), round];
    // A stale period of 0, and an upgradable app with none, are refused
    // (400) at parse, before the vk build: the circuits have the real ABI but
    // no program in their bytecode, so a body that passed would be 400
    // naming a circuit.
    let mut upgradable = counter_contract(&packages, None);
    upgradable["upgrades"] = serde_json::json!("circuits");
    upgradable["storage"]["circuit_pins"] = serde_json::json!(FieldHex::from(20));
    for (document, needle) in [
        (
            counter_contract(&packages, Some(0)),
            "field `manifest.queue.stale_blocks`: 0 would make every head skippable",
        ),
        (
            upgradable,
            "field `manifest.queue.stale_blocks`: null under upgrades `circuits`",
        ),
    ] {
        expect(
            &net.orch
                .post_json(
                    "/v1/register",
                    &junk_message(tip, document, owner_secret(), 0),
                )
                .await,
            ErrorClass::BadRequest,
            needle,
        );
    }
    assert_eq!(
        net.stubs.net.total_calls(),
        0,
        "a refused body reached a node"
    );
    // A contract manifest that passes reaches the vk build.
    expect(
        &net.orch
            .post_json(
                "/v1/register",
                &junk_message(
                    tip,
                    counter_contract(&packages, Some(50)),
                    owner_secret(),
                    0,
                ),
            )
            .await,
        ErrorClass::BadRequest,
        "field `circuits.tip_counter",
    );
    assert_eq!(net.stubs.net.total_calls(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_plain_key_reader_beside_a_shared_writer_reaches_no_node() {
    let net = network("intake-family").await;
    // A secret-shared receipt round that reads and writes a key of its own,
    // the pool: the rule is namespace-wide, so it needs no shared key, and
    // the pool's node-held state never meets the counter's chain-held state
    // in the state key check that runs before it.
    let tip = Fr::from(0x7272u64);
    let mut shared_manifest: serde_json::Value = serde_json::from_slice(
        &std::fs::read(repo().join("testvectors/manifests/shared_receipt_round.json")).unwrap(),
    )
    .unwrap();
    shared_manifest["circuit"] = serde_json::json!("shared_round");
    let shared = TestPackage::on("shared_round", "tip_counter_shared", shared_manifest)
        .keys(&["pool"], &["pool"]);
    let keys = [
        ("counter", Fr::from(0x7c01u64)),
        ("pool", Fr::from(0x7c02u64)),
    ];
    let init = TestPackage::new("tip_counter_init", counter_manifest("tip_counter_init"))
        .keys(&[], &["counter"]);
    let round = TestPackage::new("tip_counter", counter_manifest("tip_counter"))
        .keys(&["counter"], &["counter"]);
    // Beside it a non-secret-shared round that reads the counter is refused
    // (400) at parse, before the vk build.
    let mixed = counter_contract_on(&[shared.clone(), init.clone(), round], Some(50), &keys);
    expect(
        &net.orch
            .post_json("/v1/register", &junk_message(tip, mixed, owner_secret(), 0))
            .await,
        ErrorClass::BadRequest,
        "package `shared_round` (secret-shared receipt intake `shared_receipt`) and package \
         `tip_counter` (on-chain intake `onchain`)",
    );
    assert_eq!(
        net.stubs.net.total_calls(),
        0,
        "a refused body reached a node"
    );
    // The init round reads no key: beside it the contract manifest passes and
    // reaches the vk build.
    let beside = counter_contract_on(&[shared, init], Some(50), &keys);
    expect(
        &net.orch
            .post_json(
                "/v1/register",
                &junk_message(tip, beside, owner_secret(), 0),
            )
            .await,
        ErrorClass::BadRequest,
        "field `circuits.",
    );
    assert_eq!(net.stubs.net.total_calls(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_client_that_disconnects_mid_round_keeps_the_session_until_the_nodes_answer() {
    let net = network("disconnect").await;
    *net.stubs.net.delay.lock().unwrap() = Duration::from_millis(1500);
    let client = net.orch.client.clone();
    let body = serde_json::to_vec(&seed(1)).unwrap();
    let first = tokio::spawn(async move { client.post_raw("/v1/execute", body).await });
    // Once the first node call is in flight, the client goes away.
    let start = Instant::now();
    while net.stubs.net.calls(0).is_empty() {
        assert!(start.elapsed() < Duration::from_secs(10), "no node call");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    first.abort();
    assert!(first.await.unwrap_err().is_cancelled());
    // Another request at once: it reaches the nodes only after the abandoned
    // round's three calls have completed.
    let answer = net.orch.post_json("/v1/execute", &seed(2)).await;
    expect(&answer, ErrorClass::Conflict, "stub refuses");
    assert!(
        start.elapsed() >= Duration::from_millis(2900),
        "{:?}",
        start.elapsed()
    );
    assert_eq!(*net.stubs.net.max_sessions.lock().unwrap(), 1);
    for i in 0..3 {
        let ids: Vec<serde_json::Value> = net
            .stubs
            .net
            .calls(i)
            .iter()
            .map(|c| c.json()["request_id"].clone())
            .collect();
        assert_eq!(
            ids,
            [
                serde_json::to_value(id(1)).unwrap(),
                serde_json::to_value(id(2)).unwrap()
            ],
            "node {i}"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_registry_sync_refuses_disagreeing_nodes_and_a_wrong_vk_hash() {
    let net = network("sync").await;
    let ns_hex = fr_to_hex(ns());
    let computed = net
        .orch
        .registry()
        .compute(&register_body("monty-hall", ns(), &["pss_seed"], 0))
        .unwrap();
    let built = &computed.circuits["pss_seed"];
    let (vk, real_vk) = (HexBytes(built.vk.to_buffer()), built.vk_hash);
    // The nodes as they answer the listings and reads: `extra` is a second
    // namespace node 2 alone lists, `vk_hash` what every node says (the
    // contract manifest and the package alike).
    let answers = move |extra: bool, vk_hash: FieldHex| -> Respond {
        let ns_hex = ns_hex.clone();
        let document = contract_manifest(
            "monty-hall",
            &[TestPackage::new(
                "pss_seed",
                manifest("monty-hall", "pss_seed"),
            )],
            None,
            |_| vk_hash.fr(),
        );
        let manifest_hash =
            FieldHex(sidecar_core::manifest::contract::manifest_hash(&document).unwrap());
        let package = PackageResponse {
            namespace: FieldHex(ns()),
            name: "pss_seed".into(),
            manifest_hash,
            circuit: sidecar_core::register::stripped_circuit(&circuit_json("pss_seed")),
            manifest: manifest("monty-hall", "pss_seed"),
            vk: vk.clone(),
            vk_hash,
            disabled: false,
            seq: 0,
        };
        Arc::new(move |i, _, path, _| {
            if path == "/v1/namespaces" {
                let mut list = vec![FieldHex(ns())];
                if extra && i == 2 {
                    list.push(FieldHex::from(0x99));
                }
                ok_json(&serde_json::json!({ "namespaces": list }))
            } else if path == format!("/v1/namespaces/{ns_hex}") {
                ok_json(&NamespaceResponse {
                    namespace: FieldHex(ns()),
                    owner_pubkey: point_to_wire(public_key(owner_secret())),
                    seq: 0,
                    npk_app_hash: FieldHex::from(0x9e9e),
                    manifest_hash,
                })
            } else if path == format!("/v1/namespaces/{ns_hex}/manifest") {
                ok_json(&ContractManifestResponse {
                    namespace: FieldHex(ns()),
                    manifest_hash,
                    seq: 0,
                    manifest: document.clone(),
                })
            } else if path == format!("/v1/packages/{ns_hex}") {
                ok_json(&serde_json::json!({"namespace": FieldHex(ns()), "packages": ["pss_seed"]}))
            } else if path == format!("/v1/packages/{ns_hex}/pss_seed") {
                ok_json(&package)
            } else {
                refused(ErrorClass::NotFound, "no route")
            }
        })
    };
    let leg = orchestrator_tls(&net.certs);
    let tls = sidecar_http::tls::client_config(&leg.ca, Some((&leg.cert, &leg.key))).unwrap();
    let nodes = sidecar_orchestrator::nodes::Nodes::from_clients(
        net.stubs
            .addrs
            .map(|a| sidecar_http::client::ApiClient::new(a, "localhost", tls.clone()).unwrap()),
    );
    let dir = net.tmp.path().join("registry-sync");
    // A copy that already holds a row, which a refused sync keeps.
    {
        let copy = sidecar_orchestrator::registry::Registry::open(&dir, net.crs.clone()).unwrap();
        seed_registry(&copy, "monty-hall", Fr::from(0x77u64), &["pss_seed"], 0);
    }
    let held = |dir: &std::path::Path| {
        let store = sidecar_core::local::LocalStore::open(dir).unwrap();
        use sidecar_core::store::Store;
        store.namespaces().unwrap()
    };
    assert_eq!(held(&dir), [Fr::from(0x77u64)]);

    net.stubs.net.set(answers(true, FieldHex(real_vk)));
    let err = sidecar_orchestrator::sync::sync_registry(&nodes, &net.crs, &dir)
        .await
        .unwrap_err();
    assert!(
        format!("{err:#}").contains("the nodes disagree on GET /v1/namespaces: node 2's"),
        "{err:#}"
    );
    assert_eq!(held(&dir), [Fr::from(0x77u64)]);

    net.stubs.net.set(answers(false, FieldHex::from(0x1234)));
    let err = sidecar_orchestrator::sync::sync_registry(&nodes, &net.crs, &dir)
        .await
        .unwrap_err();
    assert!(
        format!("{err:#}").contains("the circuit builds to vk_hash"),
        "{err:#}"
    );
    assert_eq!(held(&dir), [Fr::from(0x77u64)]);

    // Agreeing nodes with the right vk_hash: the copy is replaced by theirs.
    net.stubs.net.set(answers(false, FieldHex(real_vk)));
    let synced = sidecar_orchestrator::sync::sync_registry(&nodes, &net.crs, &dir)
        .await
        .unwrap();
    assert_eq!((synced.namespaces, synced.packages), (1, 1));
    assert_eq!(held(&dir), [ns()]);
    assert!(!dir.with_file_name("registry-sync.sync").exists());
    assert!(!dir.with_file_name("registry-sync.old").exists());
}

/// The rows a stub node holds: the namespace row and its packages.
type Rows = (NamespaceResponse, Vec<PackageResponse>);

/// Stubs that answer the registry GETs of the Monty Hall namespace from the
/// rows `rows(i)` gives node i, and its contract manifest `manifest` at every
/// node.
fn serve_rows(
    manifest: ContractManifestResponse,
    rows: Arc<dyn Fn(usize) -> Rows + Send + Sync>,
) -> Respond {
    let ns_hex = fr_to_hex(ns());
    Arc::new(move |i, _, path, _| {
        let (info, packages) = rows(i);
        if path == "/v1/namespaces" {
            ok_json(&serde_json::json!({ "namespaces": [FieldHex(ns())] }))
        } else if path == format!("/v1/namespaces/{ns_hex}/manifest") {
            ok_json(&manifest)
        } else if path == format!("/v1/namespaces/{ns_hex}") {
            ok_json(&info)
        } else if path == format!("/v1/packages/{ns_hex}") {
            let names: Vec<&str> = packages.iter().map(|p| p.name.as_str()).collect();
            ok_json(&serde_json::json!({"namespace": FieldHex(ns()), "packages": names}))
        } else if let Some(p) = packages
            .iter()
            .find(|p| path == format!("/v1/packages/{ns_hex}/{}", p.name))
        {
            ok_json(p)
        } else {
            refused(ErrorClass::NotFound, "no route")
        }
    })
}

/// The contract manifest the copy `store` holds for the Monty Hall namespace.
fn held_manifest(store: &sidecar_core::local::LocalStore) -> ContractManifestResponse {
    sidecar_core::registry::manifest_info(store, ns()).unwrap()
}

/// What `GET /v1/status` answers about the registry check.
async fn registry_status(orch: &Started) -> Option<RegistryStatus> {
    orch.get("/v1/status")
        .await
        .json::<StatusResponse>()
        .unwrap()
        .unwrap_or_else(|r| panic!("GET /v1/status: {r}"))
        .registry
}

/// The start-up registry check (`status::check_registry`, run before the
/// listener serves): nodes that agree with the copy pass; a DISABLE nodes 0
/// and 1 committed and node 2 did not is named row by row as a divergence
/// between the nodes; the same DISABLE at all three that the copy lacks is
/// named as the copy's alone; a node that cannot be read, or lists a name
/// that is no package name, leaves the check unrun. The check writes nothing
/// to the copy. `GET /v1/status` answers no
/// check before the first, then each check's counts (or that the nodes were
/// not read) with the time it ran, and never a row; the admin socket's
/// `status` answers the rows and the reason.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_start_up_check_names_registry_rows_the_nodes_and_the_copy_differ_on() {
    let net = network("start-check").await;
    let store = net.orch.registry().store();
    let info = sidecar_core::registry::namespace_info(store, ns()).unwrap();
    let packages: Vec<PackageResponse> = CIRCUITS
        .iter()
        .map(|name| sidecar_core::registry::package_info(store, ns(), name).unwrap())
        .collect();
    let mut after = (info, packages.clone());
    after.0.seq = 2;
    after.1[1].disabled = true;
    after.1[1].seq = 2;
    let check = || check_registry(&net.orch.app, When::Start);
    let copy_before = sidecar_core::registry_check::NamespaceRows::read(store, ns()).unwrap();
    let status = || registry_status(&net.orch);
    assert_eq!(status().await, None, "a status before the first check");
    let started = sidecar_core::pipeline::unix_now();
    let summary_is = |registry: Option<RegistryStatus>, found: &RegistrySummary| {
        let registry = registry.expect("a status after the check");
        assert!(registry.compared_at >= started, "{registry:?}");
        assert_eq!(
            registry.counts,
            Some(RegistryCounts {
                namespaces: found.check.namespaces,
                packages: found.check.packages,
                between_nodes: found.between_nodes,
                copy_only: found.copy_only,
            })
        );
        assert!(!registry.unread);
    };
    let admin_status = || async {
        sidecar_orchestrator::admin::handle(
            &net.orch.app,
            sidecar_orchestrator::admin::AdminRequest::Status,
        )
        .await
        .registry
        .expect("the admin status after a check")
    };

    let same = (info, packages.clone());
    net.stubs.net.set(serve_rows(
        held_manifest(store),
        Arc::new(move |_| same.clone()),
    ));
    let found = check().await.agreement.expect("the nodes answer");
    assert_eq!((found.check.namespaces, found.check.packages), (1, 2));
    assert!(
        found.check.divergences.is_empty(),
        "{:?}",
        found.check.divergences
    );
    summary_is(status().await, &found);

    let (diverged, behind) = (after.clone(), (info, packages.clone()));
    net.stubs.net.set(serve_rows(
        held_manifest(store),
        Arc::new(move |i| {
            if i < 2 {
                diverged.clone()
            } else {
                behind.clone()
            }
        }),
    ));
    let found = check().await.agreement.expect("the nodes answer");
    let d = &found.check.divergences;
    assert_eq!((found.between_nodes, found.copy_only), (2, 0), "{d:#?}");
    assert_divergence(
        &d[0],
        "the namespace row",
        &[
            (&["node 0", "node 1"], "seq 2"),
            (&["node 2", "the copy"], "seq 1"),
        ],
    );
    assert_divergence(
        &d[1],
        "package `monty_hall_open_door`",
        &[
            (&["node 0", "node 1"], "seq 2, disabled"),
            (&["node 2", "the copy"], "seq 1, enabled"),
        ],
    );
    summary_is(status().await, &found);
    let public = net.orch.get("/v1/status").await.body;
    let public = String::from_utf8(public).unwrap();
    assert!(
        !public.contains("monty_hall") && !public.contains(&fr_to_hex(ns())[2..]),
        "the public status names a row: {public}"
    );
    assert_eq!(admin_status().await.agreement.as_ref(), Some(&found));

    let everywhere = after.clone();
    net.stubs.net.set(serve_rows(
        held_manifest(store),
        Arc::new(move |_| everywhere.clone()),
    ));
    let found = check().await.agreement.expect("the nodes answer");
    assert_eq!((found.between_nodes, found.copy_only), (0, 2), "{found:?}");
    assert_divergence(
        &found.check.divergences[1],
        "package `monty_hall_open_door`",
        &[
            (&["node 0", "node 1", "node 2"], "seq 2, disabled"),
            (&["the copy"], "seq 1, enabled"),
        ],
    );

    let behind = after.clone();
    let respond = serve_rows(held_manifest(store), Arc::new(move |_| behind.clone()));
    net.stubs.net.set(Arc::new(move |i, method, path, body| {
        if i == 1 {
            refused(ErrorClass::MpcFailure, "store: unavailable")
        } else {
            respond(i, method, path, body)
        }
    }));
    assert!(
        check().await.agreement.is_none(),
        "a node that is not read is no check"
    );
    let unread = status().await.expect("a status after the check");
    assert!(unread.compared_at >= started && unread.counts.is_none() && unread.unread);
    let why = admin_status().await;
    assert!(
        why.unread
            .as_deref()
            .is_some_and(|e| e.contains("store: unavailable")),
        "{why:?}"
    );

    let rows = after.clone();
    let respond = serve_rows(held_manifest(store), Arc::new(move |_| rows.clone()));
    let names_path = format!("/v1/packages/{}", fr_to_hex(ns()));
    net.stubs.net.set(Arc::new(move |i, method, path, body| {
        if i == 2 && path == names_path {
            ok_json(&serde_json::json!({
                "namespace": fr_to_hex(ns()),
                "packages": ["monty hall"],
            }))
        } else {
            respond(i, method, path, body)
        }
    }));
    assert!(check().await.agreement.is_none(), "a name with a space");
    let why = admin_status().await;
    assert!(
        why.unread
            .as_deref()
            .is_some_and(|e| e.contains("node 2") && e.contains("package name")),
        "{why:?}"
    );
    assert_eq!(
        sidecar_core::registry_check::NamespaceRows::read(store, ns()).unwrap(),
        copy_before,
        "the check wrote to the copy"
    );
}

/// The registry check reruns while the orchestrator serves. After a DISABLE
/// the three nodes commit (a body all three refuse starts none:
/// `registry::all_refused`'s unit test), once the copy has recorded it, so `GET /v1/status`
/// reports the three nodes and the copy agreeing on the rows the body left;
/// and on its timer (`status::spawn_timer`, here every 200 ms), which names a
/// row a node changed without the orchestrator (node 2 back at its rows
/// before the DISABLE).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_registry_check_reruns_after_a_registry_body_and_on_its_timer() {
    let net = network("recheck").await;
    let store = net.orch.registry().store();
    let before: Rows = (
        sidecar_core::registry::namespace_info(store, ns()).unwrap(),
        CIRCUITS
            .iter()
            .map(|name| sidecar_core::registry::package_info(store, ns(), name).unwrap())
            .collect(),
    );
    let mut after = before.clone();
    after.0.seq = 2;
    after.1[1].disabled = true;
    after.1[1].seq = 2;
    // Each node serves its own rows; a DISABLE it commits moves them to
    // `after`, and it answers with its signature over the result.
    let held: Arc<[std::sync::Mutex<Rows>; 3]> =
        Arc::new([0, 1, 2].map(|_| std::sync::Mutex::new(before.clone())));
    let rows = {
        let held = held.clone();
        serve_rows(
            held_manifest(store),
            Arc::new(move |i| held[i].lock().unwrap().clone()),
        )
    };
    let committing: Respond = {
        let held = held.clone();
        let after = after.clone();
        Arc::new(move |i, method, path, body| {
            if path != "/v1/disable" {
                return rows(i, method, path, body);
            }
            *held[i].lock().unwrap() = after.clone();
            let (info, pkg) = (&after.0, &after.1[1]);
            let message = sidecar_core::registry::registry_message(
                ns(),
                &pkg.name,
                pkg.vk_hash.fr(),
                info.npk_app_hash.fr(),
                pkg.seq,
                true,
                i,
            );
            ok_json(&sidecar_core::register::DisableAnswer {
                namespace: FieldHex(ns()),
                circuit: pkg.name.clone(),
                vk_hash: pkg.vk_hash,
                npk_app_hash: info.npk_app_hash,
                disabled: true,
                seq: pkg.seq,
                signature: schnorr::sign(Fq::from(200 + i as u64), message, &mut OsRng),
            })
        })
    };
    let mut disable = DisableRequest {
        namespace: FieldHex(ns()),
        circuit: "monty_hall_open_door".into(),
        owner_pubkey: point_to_wire(public_key(owner_secret())),
        seq: 2,
        signature: Signature::default(),
    };
    let message = schnorr::message_for(
        schnorr::DISABLE_DOMAIN,
        &serde_json::to_value(&disable).unwrap(),
    )
    .unwrap();
    disable.signature = schnorr::sign(owner_secret(), message, &mut OsRng);
    // Poll `GET /v1/status` until `done` holds of it, for at most 10 s.
    let status_until = |done: fn(&Option<RegistryStatus>) -> bool| {
        let orch = &net.orch;
        async move {
            let deadline = Instant::now() + Duration::from_secs(10);
            loop {
                let status = registry_status(orch).await;
                if done(&status) || Instant::now() > deadline {
                    return status;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    };

    // Every node refuses the body: nothing to compare again.
    net.stubs.net.set(Arc::new(|_, _, _, _| {
        refused(ErrorClass::Conflict, "stub refuses")
    }));
    expect(
        &net.orch.post_json("/v1/disable", &disable).await,
        ErrorClass::Conflict,
        "stub refuses",
    );
    for i in 0..3 {
        let paths: Vec<String> = net.stubs.net.calls(i).into_iter().map(|c| c.path).collect();
        assert_eq!(paths, ["/v1/disable"], "node {i}");
    }

    // The three commit it: the check reruns once the copy holds it too.
    net.stubs.net.set(committing);
    let started = sidecar_core::pipeline::unix_now();
    let _: sidecar_core::register::DisableResponse = net
        .orch
        .post_json("/v1/disable", &disable)
        .await
        .json()
        .unwrap()
        .unwrap();
    let rerun = status_until(|s| s.is_some())
        .await
        .expect("a check after the committed DISABLE");
    assert!(rerun.compared_at >= started, "{rerun:?}");
    let found = rerun.counts.expect("the nodes answer");
    assert_eq!(
        found,
        RegistryCounts {
            namespaces: 1,
            packages: 2,
            between_nodes: 0,
            copy_only: 0
        },
        "the check ran before the copy recorded the DISABLE"
    );
    assert!(
        sidecar_core::registry::package_info(store, ns(), "monty_hall_open_door")
            .unwrap()
            .disabled
    );

    // Node 2 goes back to its rows before the DISABLE behind the
    // orchestrator's back: the timer's next run names both rows.
    let timer = spawn_timer(net.orch.app.clone(), Duration::from_millis(200));
    *held[2].lock().unwrap() = before.clone();
    let named = status_until(|s| {
        s.as_ref()
            .and_then(|s| s.counts.as_ref())
            .is_some_and(|a| a.between_nodes > 0)
    })
    .await
    .expect("a status");
    timer.abort();
    let counts = named.counts.expect("the nodes answer");
    assert_eq!(
        (counts.between_nodes, counts.copy_only),
        (2, 0),
        "{counts:?}"
    );
    let report = sidecar_orchestrator::admin::handle(
        &net.orch.app,
        sidecar_orchestrator::admin::AdminRequest::Status,
    )
    .await
    .registry
    .and_then(|r| r.agreement)
    .expect("the admin status names the rows");
    assert_divergence(
        &report.check.divergences[1],
        "package `monty_hall_open_door`",
        &[
            (&["node 0", "node 1", "the copy"], "seq 2, disabled"),
            (&["node 2"], "seq 1, enabled"),
        ],
    );
}

/// `d` is the divergence of `row`, held as `held` lists it: each group's
/// holders, and the leading fields of the row they hold.
fn assert_divergence(d: &Divergence, row: &str, held: &[(&[&str], &str)]) {
    assert_eq!(d.namespace, FieldHex(ns()), "{d:?}");
    assert_eq!(d.row, row, "{d:?}");
    let got: Vec<(Vec<&str>, &str)> = d
        .held
        .iter()
        .map(|h| {
            (
                h.holders.iter().map(String::as_str).collect(),
                h.row.as_str(),
            )
        })
        .collect();
    assert_eq!(got.len(), held.len(), "{d:?}");
    for ((holders, fields), (want_holders, want_fields)) in got.iter().zip(held) {
        assert_eq!(holders.as_slice(), *want_holders, "{d:?}");
        assert!(
            fields.starts_with(&format!("{want_fields}, ")),
            "{want_fields}: {d:?}"
        );
    }
}

/// The pause around a node replacement (`Orchestrator::pause`, the admin
/// socket's `pause` and `resume`): while paused, an execute is refused after
/// it takes the session lock (500, "paused") and reaches no node, and FETCH
/// and the GETs are still served; a resume is refused, still paused, while
/// the nodes' registries differ (a node behind on a DISABLE, as a newcomer
/// whose import left it behind would be), and resumes once they agree; the
/// next execute reaches the nodes again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_paused_orchestrator_starts_no_session_and_resumes_when_the_registries_agree() {
    let net = network("pause").await;
    let app = &net.orch.app;
    let answer =
        sidecar_orchestrator::admin::handle(app, sidecar_orchestrator::admin::AdminRequest::Pause)
            .await;
    assert!(answer.ok && answer.paused, "{answer:?}");
    assert!(app.paused());
    let refused = net.orch.post_json("/v1/execute", &seed(1)).await;
    expect(&refused, ErrorClass::MpcFailure, "paused");
    for i in 0..3 {
        assert!(net.stubs.net.calls(i).is_empty(), "node {i} was called");
    }
    let path = format!("/v1/packages/{}/pss_seed", fr_to_hex(ns()));
    assert_eq!(net.orch.get(&path).await.status, 200);

    let store = net.orch.registry().store();
    let info = sidecar_core::registry::namespace_info(store, ns()).unwrap();
    let packages: Vec<PackageResponse> = CIRCUITS
        .iter()
        .map(|name| sidecar_core::registry::package_info(store, ns(), name).unwrap())
        .collect();
    let mut ahead = (info, packages.clone());
    ahead.0.seq = 2;
    ahead.1[1].disabled = true;
    ahead.1[1].seq = 2;
    let behind = (info, packages.clone());
    net.stubs.net.set(serve_rows(
        held_manifest(store),
        Arc::new(move |i| if i < 2 { ahead.clone() } else { behind.clone() }),
    ));
    let answer =
        sidecar_orchestrator::admin::handle(app, sidecar_orchestrator::admin::AdminRequest::Resume)
            .await;
    assert!(!answer.ok && answer.paused, "{answer:?}");
    let why = answer.refusal.unwrap();
    assert_eq!(why.class, ErrorClass::Conflict, "{why}");
    assert!(why.message.contains("still paused"), "{why}");
    assert!(app.paused());

    let same = (info, packages);
    net.stubs.net.set(serve_rows(
        held_manifest(store),
        Arc::new(move |_| same.clone()),
    ));
    let answer =
        sidecar_orchestrator::admin::handle(app, sidecar_orchestrator::admin::AdminRequest::Resume)
            .await;
    assert!(answer.ok && !answer.paused, "{answer:?}");
    assert_eq!(answer.registry.unwrap().agreement.unwrap().between_nodes, 0);
    net.stubs.net.set(default_respond(pins_of(&net.keys).nodes));
    // the resume's check read the registries: count the execute only
    let before: Vec<usize> = (0..3).map(|i| net.stubs.net.calls(i).len()).collect();
    let again = net.orch.post_json("/v1/execute", &seed(1)).await;
    expect(&again, ErrorClass::Conflict, "stub refuses");
    for (i, n) in before.iter().enumerate() {
        assert_eq!(net.stubs.net.calls(i).len(), n + 1, "node {i}");
    }
}
