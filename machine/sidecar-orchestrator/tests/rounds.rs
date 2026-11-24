//! The orchestrator's answering half, end to end over three real nodes with
//! real MPC proofs, then over node stubs that replay (and alter) what the
//! real nodes answered.
//!
//! Real nodes: REGISTER (seq 0 with the registration proof verified against
//! the built-in vk, seq 1, and a second circuit with the same public-input
//! count as the first), the Monty Hall seed (a client-held record assembled
//! from three thirds, three result signatures) and the game's init (which
//! supplies that record back), FETCH of both under the package their rows
//! name; the nodes' own answers to the seq 0 REGISTER, the two rounds' FETCH
//! and a DISABLE are recorded for the stubs. DISABLE, re-REGISTER and FETCH
//! after a rollback over real nodes are end_to_end.rs's.
//!
//! Stubs, pinned to the real nodes' keys: disagreement on each agreed field,
//! a proof that fails verification, a namespace public input that differs, a
//! bad or missing signature from each node in turn, a substituted third; the
//! same over FETCH, and FETCH answers whose vk_hash is missing, differs
//! between the nodes, names the other circuit of the same public-input count
//! or names no registered circuit; REGISTER answers that disagree, carry a bad registration
//! proof or a bad signature, or a vk_hash the orchestrator does not compute;
//! DISABLE answers that disagree or carry a bad signature; a node that does
//! not answer.
//!
//! Then, over three more real nodes: a REGISTER of a disabled name with the
//! same circuit and another manifest governs the next round on the three
//! nodes and at the orchestrator without a restart.
//!
//! Needs `scripts/prepare-data.sh` (the circuits and the CRS under
//! machine/data, or DATA_DIR); the tests fail naming the missing files if
//! they are absent. Run with `--release`.

mod common;

use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

use axum::http::Method;
use common::*;
use rand::RngCore;
use rand::rngs::OsRng;
use serde_json::{Value, json};
use sidecar_core::field::{FieldHex, Fr, RequestId, fr_to_hex};
use sidecar_core::grumpkin::{Fq, point_to_wire};
use sidecar_core::record::record_hash;
use sidecar_core::register::{
    DisableAnswer, DisableRequest, DisableResponse, ManifestAnswer, ManifestMessage,
    ManifestResponse, NamespaceResponse, PackageResponse, Signature,
};
use sidecar_core::registry::manifest_message;
use sidecar_core::request::{PublicValue, Request, StateKeys, StateRecord};
use sidecar_core::response::{ExecuteResponse, NodeResult, NodesResponse};
use sidecar_core::schnorr::{self, public_key};
use sidecar_core::{ErrorClass, Refusal};
use sidecar_http::client::Answer;

const MONTY: u64 = 0x40e7;
/// A second namespace the stub orchestrator's copy also holds pss_seed under.
const OTHER: u64 = 0x40e8;
const SEED_KEY: &str = "0xc001";
const GAME_KEY: &str = "0xc002";
const NONCE: u64 = 0x0d935b18;
const CIRCUITS: [&str; 3] = ["pss_seed", "monty_hall_init", "monty_hall_finish"];
/// The namespace of the re-registration test.
const REREG: u64 = 0x40e9;
const RESEED_KEY: &str = "0xc003";

fn ns() -> Fr {
    Fr::from(MONTY)
}

fn player() -> Fq {
    Fq::from(0x009a_7e12_u64)
}

fn random_id() -> RequestId {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    RequestId::from_u128_bytes(bytes)
}

fn request(
    namespace: u64,
    circuit: &str,
    id: RequestId,
    reads: &[&str],
    writes: &[&str],
) -> Request {
    Request {
        namespace: FieldHex(Fr::from(namespace)),
        circuit: circuit.to_string(),
        request_id: id,
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

fn sign(req: &mut Request) {
    req.requester = Some(point_to_wire(public_key(player())));
    req.signature = Some(schnorr::sign(player(), req.signed_message(), &mut OsRng));
}

fn seed_request(namespace: u64, id: RequestId) -> Request {
    let mut req = request(namespace, "pss_seed", id, &[], &[SEED_KEY]);
    sign(&mut req);
    req
}

/// The game's init, supplying `seed`'s record as the client re-presents it:
/// its three thirds and their hashes.
fn init_request(id: RequestId, seed: &ExecuteResponse) -> Request {
    let mut req = request(MONTY, "monty_hall_init", id, &[SEED_KEY], &[GAME_KEY]);
    req.public
        .insert("in0_nonce".into(), PublicValue::One(FieldHex::from(NONCE)));
    let record = &seed.records[0];
    req.records.push(StateRecord {
        key: record.key.clone(),
        note_hash: record.note_hash,
        record_hashes: record
            .c
            .clone()
            .map(|c| FieldHex(record_hash(c.as_slice()).unwrap())),
        c: record.c.clone(),
    });
    sign(&mut req);
    req
}

fn ok<T: serde::de::DeserializeOwned>(label: &str, answer: &Answer) -> T {
    answer
        .json::<T>()
        .unwrap()
        .unwrap_or_else(|e| panic!("{label}: {e}"))
}

fn refusal_of(answer: &Answer) -> Refusal {
    let refusal = answer.json::<Value>().unwrap().unwrap_err();
    assert_eq!(answer.status, refusal.status());
    refusal
}

fn expect(label: &str, answer: &Answer, class: ErrorClass, needle: &str) {
    let refusal = refusal_of(answer);
    assert_eq!(refusal.class, class, "{label}: {refusal}");
    assert!(refusal.message.contains(needle), "{label}: {refusal}");
    eprintln!("REFUSED {label}: {refusal}");
}

/// The JSON of three answers, one per node.
type Three = [Value; 3];

fn three<T: serde::Serialize>(values: &[T; 3]) -> Three {
    [0, 1, 2].map(|i| serde_json::to_value(&values[i]).unwrap())
}

/// The stubs answer `path` with `bodies` (status 200) and 409 elsewhere.
fn replay(path: &'static str, bodies: Three) -> Respond {
    let bodies: [Vec<u8>; 3] = bodies.map(|b| serde_json::to_vec(&b).unwrap());
    Arc::new(move |i, _: &Method, p: &str, _: &[u8]| {
        if p == path {
            (200, bodies[i].clone())
        } else {
            refused(ErrorClass::Conflict, "stub refuses")
        }
    })
}

/// A 0x hex string with one nibble near the end of its `k`-th 32-byte word
/// changed, so the bytes still decode as field elements.
fn flip(hex: &Value, k: usize) -> Value {
    let mut s: Vec<char> = hex.as_str().unwrap().chars().collect();
    let at = 2 + 64 * k + 63;
    s[at] = if s[at] == '0' { '1' } else { '0' };
    Value::String(s.into_iter().collect())
}

/// What the real phase hands the stub phase.
struct Recorded {
    seed: Request,
    seed_response: ExecuteResponse,
    seed_results: [NodeResult; 3],
    init: Request,
    init_response: ExecuteResponse,
    init_results: [NodeResult; 3],
    finish_vk_hash: FieldHex,
    body0: ManifestMessage,
    register0: ManifestResponse,
    register0_answers: [ManifestAnswer; 3],
    disable: DisableRequest,
    disable_answers: [DisableAnswer; 3],
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn rounds_registry_and_fetch_over_real_nodes_then_altered_answers_over_stubs() {
    let crs = require_crs(&CIRCUITS);
    let tmp = TempDir::new("rounds");
    let certs = dev_certs(tmp.path());
    let real = start_real_nodes(tmp.path(), &certs, crs.clone()).await;
    let recorded = real_phase(&tmp, &certs, &real, crs.clone()).await;
    let keys = real.keys.clone();
    drop(real);
    stub_phase(&tmp, &certs, &keys, crs, recorded).await;
}

/// A contract manifest that registers a disabled name with the same circuit
/// and another circuit manifest (the sidecar path may replace its contract
/// manifest) governs the next round through the orchestrator without a
/// restart, though
/// the three nodes and the orchestrator have the package cached from a round
/// before the DISABLE under the same vk_hash: pss_seed re-registered with
/// another `owner` const binds the new const on all three nodes (the owner
/// public input of the proof each node's row holds), and the orchestrator's
/// verifier is rebuilt from the new row (its seq, the new manifest's shape).
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_manifest_only_re_registration_governs_the_next_round_without_a_restart() {
    let crs = require_crs(&["pss_seed"]);
    let tmp = TempDir::new("rereg");
    let certs = dev_certs(tmp.path());
    let real = start_real_nodes(tmp.path(), &certs, crs.clone()).await;
    let a = start_orchestrator(
        &certs,
        real.addrs(),
        real.pins(),
        &tmp.path().join("reg"),
        crs,
    )
    .await;
    let namespace = Fr::from(REREG);
    let package = || {
        sidecar_core::store::StoreRead::package(a.registry().store(), namespace, "pss_seed")
            .unwrap()
            .unwrap()
    };
    let seed = |key: &str| {
        let mut req = request(REREG, "pss_seed", random_id(), &[], &[key]);
        sign(&mut req);
        req
    };
    let fetched = |req: &Request| {
        serde_json::to_vec(&json!({"namespace": FieldHex(namespace), "request_id": req.request_id}))
            .unwrap()
    };

    let body0 = register_body("monty-hall", namespace, &["pss_seed"], 0);
    let register0: ManifestResponse = ok(
        "REGISTER pss_seed",
        &a.post_json("/v1/register", &body0).await,
    );
    let seed_vk = vk_of(&body0, "pss_seed");
    let first = seed(SEED_KEY);
    let first_response: ExecuteResponse = ok("seed", &a.post_json("/v1/execute", &first).await);
    let old = a.registry().verifier(namespace, &package()).unwrap();
    let owner = old.shape.param("owner").unwrap().public_index.unwrap();
    assert_eq!(
        first_response.public_inputs[owner].fr(),
        Fr::from(0xafafafu64)
    );

    // DISABLE (seq 1), then REGISTER a contract manifest of the same circuit
    // with another owner const (seq 2).
    let mut disable = DisableRequest {
        namespace: FieldHex(namespace),
        circuit: "pss_seed".into(),
        owner_pubkey: point_to_wire(public_key(owner_secret())),
        seq: 1,
        signature: Signature::default(),
    };
    let message = schnorr::message_for(
        schnorr::DISABLE_DOMAIN,
        &serde_json::to_value(&disable).unwrap(),
    )
    .unwrap();
    disable.signature = schnorr::sign(owner_secret(), message, &mut OsRng);
    let _: DisableResponse = ok("DISABLE", &a.post_json("/v1/disable", &disable).await);
    let mut changed = manifest("monty-hall", "pss_seed");
    for entry in changed["witness"].as_array_mut().unwrap() {
        if entry["param"] == "owner" {
            entry["from"] = json!({ "PUBLIC": { "const": "0xbbbbbb" } });
        }
    }
    let body2 = signed_register(
        namespace,
        sidecar_manifest("monty-hall", &[TestPackage::new("pss_seed", changed)]),
        2,
    );
    let register2: ManifestResponse = ok(
        "REGISTER pss_seed again",
        &a.post_json("/v1/register", &body2).await,
    );
    assert_eq!(
        (register2.seq, vk_of(&body2, "pss_seed")),
        (2, seed_vk),
        "the same circuit at the next seq"
    );
    assert_ne!(register2.manifest_hash, register0.manifest_hash);

    let second = seed(RESEED_KEY);
    let second_response: ExecuteResponse =
        ok("seed again", &a.post_json("/v1/execute", &second).await);
    assert_eq!(
        second_response.public_inputs[owner].fr(),
        Fr::from(0xbbbbbbu64)
    );
    let results = real
        .post_same(&certs, "/v1/fetch", &fetched(&second))
        .await
        .map(|a| ok::<NodeResult>("node FETCH seed again", &a));
    for (i, result) in results.iter().enumerate() {
        assert_eq!(
            result.public_inputs[owner].fr(),
            Fr::from(0xbbbbbbu64),
            "node {i} bound the new manifest's owner"
        );
    }
    let new = a.registry().verifier(namespace, &package()).unwrap();
    assert_ne!(
        new.shape, old.shape,
        "the orchestrator reads the new manifest"
    );
    assert_eq!(new.shape, a.registry().shape(&package()).unwrap());
    assert_eq!((new.seq, new.vk_hash), (2, seed_vk.fr()));
}

async fn real_phase(
    tmp: &TempDir,
    certs: &Path,
    real: &RealNodes,
    crs: sidecar_core::crs::Crs,
) -> Recorded {
    let pins = real.pins();
    let a = start_orchestrator(certs, real.addrs(), pins, &tmp.path().join("reg-a"), crs).await;
    let served: NodesResponse = ok("GET /v1/nodes", &a.get("/v1/nodes").await);
    assert_eq!(served, pins);

    // REGISTER seq 0, one manifest message of the three packages, runs the
    // registration round; the orchestrator verifies its proof and every
    // signature and returns the values and the signatures. A second circuit
    // with as many public inputs as the init (the finish): a FETCH of the
    // init must pick the init's package by the vk_hash the rows carry.
    let body0 = register_body(
        "monty-hall",
        ns(),
        &["pss_seed", "monty_hall_init", "monty_hall_finish"],
        0,
    );
    let start = Instant::now();
    let answer = a.post_json("/v1/register", &body0).await;
    let register0: ManifestResponse = ok("REGISTER", &answer);
    eprintln!(
        "REGISTER of the Monty Hall packages (seq 0): {:.3}s",
        start.elapsed().as_secs_f64()
    );
    let raw: Value = serde_json::from_slice(&answer.body).unwrap();
    assert!(
        raw.get("registration").is_none(),
        "the proof is not forwarded"
    );
    assert_eq!(register0.seq, 0);
    for i in 0..3 {
        let message = manifest_message(
            ns(),
            register0.manifest_hash.fr(),
            register0.packages_hash.fr(),
            register0.npk_app_hash.fr(),
            0,
            i,
        );
        assert!(schnorr::verify(
            real.keys[i].sig_pk(),
            register0.signatures[i],
            message
        ));
    }
    let computed = a.registry().compute(&body0).unwrap();
    assert_eq!(register0.manifest_hash.fr(), computed.facts.manifest_hash);
    // The nodes' own answers to the same body (a repair: the registration
    // round runs again), recorded for the stubs.
    let body0_bytes = serde_json::to_vec(&body0).unwrap();
    let register0_answers = real
        .post_same(certs, "/v1/register", &body0_bytes)
        .await
        .map(|a| ok::<ManifestAnswer>("repair REGISTER", &a));
    assert!(register0_answers[0].registration.is_some());
    let [seed_vk, init_vk, finish_vk] =
        ["pss_seed", "monty_hall_init", "monty_hall_finish"].map(|n| vk_of(&body0, n));
    assert_ne!(finish_vk, init_vk);
    let shape_of = |name: &str| {
        let pkg = sidecar_core::store::StoreRead::package(a.registry().store(), ns(), name)
            .unwrap()
            .unwrap();
        a.registry().shape(&pkg).unwrap().public_input_count
    };
    assert_eq!(shape_of("monty_hall_init"), shape_of("monty_hall_finish"));

    // The seed: one client-held record, assembled from the three thirds.
    let seed = seed_request(MONTY, random_id());
    let start = Instant::now();
    let seed_response: ExecuteResponse = ok("seed", &a.post_json("/v1/execute", &seed).await);
    eprintln!(
        "ROUND monty seed through the orchestrator: {:.3}s",
        start.elapsed().as_secs_f64()
    );
    assert_eq!(seed_response.request_id, seed.request_id);
    assert_eq!(seed_response.vk_hash, seed_vk);
    assert!(seed_response.stored.is_empty());
    let fetch_body =
        serde_json::to_vec(&json!({"namespace": FieldHex(ns()), "request_id": seed.request_id}))
            .unwrap();
    let seed_results = real
        .post_same(certs, "/v1/fetch", &fetch_body)
        .await
        .map(|a| ok::<NodeResult>("node FETCH seed", &a));
    let [record] = &seed_response.records[..] else {
        panic!("one record")
    };
    assert_eq!(record.key, SEED_KEY);
    for (i, result) in seed_results.iter().enumerate() {
        assert_eq!(result.vk_hash, Some(seed_vk), "node {i}'s row");
        assert_eq!(record.c[i], result.records[0].c_i, "third {i}");
        assert_eq!(seed_response.signatures[i], result.signature);
        assert_eq!(seed_response.proof, result.proof);
    }
    assert_ne!(record.c[0], record.c[1]);
    assert_ne!(record.c[1], record.c[2]);

    // The init supplies the record back, as the client holds it.
    let init = init_request(random_id(), &seed_response);
    let start = Instant::now();
    let init_response: ExecuteResponse = ok("init", &a.post_json("/v1/execute", &init).await);
    eprintln!(
        "ROUND monty init through the orchestrator: {:.3}s",
        start.elapsed().as_secs_f64()
    );
    assert_eq!(init_response.vk_hash, init_vk);
    assert_eq!(init_response.records.len(), 1);
    assert_eq!(init_response.records[0].key, GAME_KEY);
    let init_body =
        serde_json::to_vec(&json!({"namespace": FieldHex(ns()), "request_id": init.request_id}))
            .unwrap();
    let init_results = real
        .post_same(certs, "/v1/fetch", &init_body)
        .await
        .map(|a| ok::<NodeResult>("node FETCH init", &a));
    for result in &init_results {
        assert_eq!(result.vk_hash, Some(init_vk));
    }

    // FETCH answers the same responses, the init's under its own package
    // though the finish has as many public inputs.
    let fetch = |id: RequestId| json!({"namespace": FieldHex(ns()), "request_id": id});
    let fetched: ExecuteResponse = ok(
        "FETCH seed",
        &a.post_json("/v1/fetch", &fetch(seed.request_id)).await,
    );
    assert_eq!(fetched, seed_response);
    let fetched: ExecuteResponse = ok(
        "FETCH init",
        &a.post_json("/v1/fetch", &fetch(init.request_id)).await,
    );
    assert_eq!(fetched, init_response);
    // the stub phase's registry copy: the rows as they stand now
    std::fs::create_dir_all(tmp.path().join("reg-c")).unwrap();
    std::fs::copy(
        tmp.path().join("reg-a/store.log"),
        tmp.path().join("reg-c/store.log"),
    )
    .unwrap();

    // The nodes' answers to a DISABLE of monty_hall_init (seq 1).
    let mut disable = DisableRequest {
        namespace: FieldHex(ns()),
        circuit: "monty_hall_init".into(),
        owner_pubkey: point_to_wire(public_key(owner_secret())),
        seq: 1,
        signature: Signature::default(),
    };
    let message = schnorr::message_for(
        schnorr::DISABLE_DOMAIN,
        &serde_json::to_value(&disable).unwrap(),
    )
    .unwrap();
    disable.signature = schnorr::sign(owner_secret(), message, &mut OsRng);
    let disable_answers = real
        .post_same(certs, "/v1/disable", &serde_json::to_vec(&disable).unwrap())
        .await
        .map(|a| ok::<DisableAnswer>("node DISABLE", &a));
    assert!(disable_answers.iter().all(|a| a.disabled));

    Recorded {
        seed,
        seed_response,
        seed_results,
        init,
        init_response,
        init_results,
        finish_vk_hash: finish_vk,
        body0,
        register0,
        register0_answers,
        disable,
        disable_answers,
    }
}

async fn stub_phase(
    tmp: &TempDir,
    certs: &Path,
    keys: &[sidecar_core::keys::NodeKeys; 3],
    crs: sidecar_core::crs::Crs,
    rec: Recorded,
) {
    let pins = pins_of(keys);
    let mut stubs = Stubs::start(certs, default_respond(pins.nodes)).await;
    // c: the registry as it stood after the init; it also holds pss_seed
    // under a second namespace.
    let c = start_orchestrator(
        certs,
        stubs.addrs,
        pins,
        &tmp.path().join("reg-c"),
        crs.clone(),
    )
    .await;
    seed_registry(
        c.registry(),
        "monty-hall",
        Fr::from(OTHER),
        &["pss_seed"],
        0,
    );

    // --- execute ---------------------------------------------------------
    let results = three(&rec.seed_results);
    let run = |bodies: Three| {
        stubs.net.set(replay("/v1/execute", bodies));
        c.post_json("/v1/execute", &rec.seed)
    };
    let honest: ExecuteResponse = ok("replayed seed", &run(results.clone()).await);
    assert_eq!(honest, rec.seed_response);

    let altered = |node: usize, change: &dyn Fn(&mut Value)| {
        let mut r = results.clone();
        change(&mut r[node]);
        r
    };
    let disagreements: Vec<(&str, Three)> = vec![
        (
            "request_id",
            altered(2, &|v| v["request_id"] = json!(FieldHex::from(7))),
        ),
        ("proof", altered(1, &|v| v["proof"] = flip(&v["proof"], 20))),
        (
            "public_inputs",
            altered(2, &|v| v["public_inputs"][0] = json!(FieldHex::from(5))),
        ),
        ("stored", altered(0, &|v| v["stored"] = json!(["0xc009"]))),
        ("records", altered(2, &|v| v["records"] = json!([]))),
        (
            "records[0].key",
            altered(1, &|v| v["records"][0]["key"] = json!("0xc009")),
        ),
        (
            "records[0].note_hash",
            altered(0, &|v| {
                v["records"][0]["note_hash"] = json!(FieldHex::from(5))
            }),
        ),
    ];
    for (field, bodies) in disagreements {
        let answer = run(bodies).await;
        expect(
            &format!("disagreement on {field}"),
            &answer,
            ErrorClass::MpcFailure,
            &format!("disagree on `{field}`"),
        );
    }

    // The three agree on a proof that does not verify.
    let mut bad = results.clone();
    for v in &mut bad {
        v["proof"] = flip(&v["proof"], 40);
    }
    expect(
        "an agreed proof that fails",
        &run(bad).await,
        ErrorClass::MpcFailure,
        "does not verify under the orchestrator's vk",
    );

    // A bad signature from each node in turn (another node's), a missing one,
    // and a substituted third (which changes what the node signed).
    for i in 0..3 {
        let other = results[(i + 1) % 3]["signature"].clone();
        let bodies = altered(i, &|v| v["signature"] = other.clone());
        expect(
            &format!("node {i}'s bad signature"),
            &run(bodies).await,
            ErrorClass::MpcFailure,
            &format!("node {i}'s result signature does not verify"),
        );
        let bodies = altered(i, &|v| {
            v.as_object_mut().unwrap().remove("signature");
        });
        expect(
            &format!("node {i}'s missing signature"),
            &run(bodies).await,
            ErrorClass::MpcFailure,
            &format!("node {i}: its answer"),
        );
    }
    let foreign = results[0]["records"][0]["c_i"].clone();
    let bodies = altered(1, &|v| v["records"][0]["c_i"] = foreign.clone());
    expect(
        "a substituted third",
        &run(bodies).await,
        ErrorClass::MpcFailure,
        "node 1's result signature does not verify",
    );

    // The same seed under the second namespace: the nodes' proof verifies
    // (same circuit, same vk) but names the first namespace.
    let mut elsewhere = seed_request(OTHER, rec.seed.request_id);
    sign(&mut elsewhere);
    stubs.net.set(replay("/v1/execute", results.clone()));
    expect(
        "namespace public input",
        &c.post_json("/v1/execute", &elsewhere).await,
        ErrorClass::Unsatisfied,
        "namespace public input",
    );

    // --- FETCH -----------------------------------------------------------
    let fetch = json!({"namespace": FieldHex(ns()), "request_id": rec.seed.request_id});
    stubs.net.set(replay("/v1/fetch", results.clone()));
    let fetched: ExecuteResponse = ok("replayed FETCH", &c.post_json("/v1/fetch", &fetch).await);
    assert_eq!(fetched, rec.seed_response);
    let other = results[2]["signature"].clone();
    stubs.net.set(replay(
        "/v1/fetch",
        altered(0, &|v| v["signature"] = other.clone()),
    ));
    expect(
        "FETCH with a bad signature",
        &c.post_json("/v1/fetch", &fetch).await,
        ErrorClass::MpcFailure,
        "node 0's result signature",
    );
    stubs.net.set(replay(
        "/v1/fetch",
        altered(2, &|v| v["stored"] = json!(["0xc009"])),
    ));
    expect(
        "FETCH disagreement",
        &c.post_json("/v1/fetch", &fetch).await,
        ErrorClass::MpcFailure,
        "disagree on `stored`",
    );
    let elsewhere_fetch =
        json!({"namespace": FieldHex(Fr::from(OTHER)), "request_id": rec.seed.request_id});
    stubs.net.set(replay("/v1/fetch", results.clone()));
    expect(
        "FETCH under the other namespace",
        &c.post_json("/v1/fetch", &elsewhere_fetch).await,
        ErrorClass::Unsatisfied,
        "namespace public input",
    );
    // The vk_hash the rows carry picks the package: missing at one node,
    // different at one node, the other circuit with as many public inputs
    // (the init's proof does not verify under the finish's vk, and no other
    // package is tried), and a vk_hash no package of the namespace carries.
    let init_fetch = json!({"namespace": FieldHex(ns()), "request_id": rec.init.request_id});
    let init_results = three(&rec.init_results);
    stubs.net.set(replay("/v1/fetch", init_results.clone()));
    let fetched: ExecuteResponse = ok(
        "replayed FETCH of the init",
        &c.post_json("/v1/fetch", &init_fetch).await,
    );
    assert_eq!(fetched, rec.init_response);
    let with_vk = |nodes: &[usize], vk: Option<FieldHex>| {
        let mut r = init_results.clone();
        for &i in nodes {
            match vk {
                Some(vk) => r[i]["vk_hash"] = json!(vk),
                None => {
                    r[i].as_object_mut().unwrap().remove("vk_hash");
                }
            }
        }
        r
    };
    for (label, bodies, class, needle) in [
        (
            "FETCH without a vk_hash",
            with_vk(&[1], None),
            ErrorClass::MpcFailure,
            "node 1's FETCH answer carries no vk_hash",
        ),
        (
            "FETCH vk_hash disagreement",
            with_vk(&[2], Some(rec.finish_vk_hash)),
            ErrorClass::MpcFailure,
            "disagree on `vk_hash`",
        ),
        (
            "FETCH naming the other circuit",
            with_vk(&[0, 1, 2], Some(rec.finish_vk_hash)),
            ErrorClass::MpcFailure,
            "of `monty_hall_finish`",
        ),
        (
            "FETCH naming no registered circuit",
            with_vk(&[0, 1, 2], Some(FieldHex::from(0x5e))),
            ErrorClass::Conflict,
            "the round's circuit is no longer registered",
        ),
    ] {
        stubs.net.set(replay("/v1/fetch", bodies));
        expect(
            label,
            &c.post_json("/v1/fetch", &init_fetch).await,
            class,
            needle,
        );
    }
    let seed_results = results.clone();
    stubs.net.set(Arc::new(move |i, _, _, _| match i {
        2 => refused(ErrorClass::NotFound, "no request"),
        _ => (200, serde_json::to_vec(&seed_results[i]).unwrap()),
    }));
    expect(
        "FETCH, one node without the row",
        &c.post_json("/v1/fetch", &fetch).await,
        ErrorClass::NotFound,
        "node 2",
    );
    stubs.net.set(Arc::new(|_, _, _, _| {
        refused(ErrorClass::Conflict, "rolled back")
    }));
    expect(
        "FETCH of a rolled-back row",
        &c.post_json("/v1/fetch", &fetch).await,
        ErrorClass::Conflict,
        "rolled back",
    );

    // --- REGISTER --------------------------------------------------------
    // d: an empty registry copy; each refused answer records nothing.
    let d = start_orchestrator(
        certs,
        stubs.addrs,
        pins,
        &tmp.path().join("reg-d"),
        crs.clone(),
    )
    .await;
    let body0 = &rec.body0;
    let reg = three(&rec.register0_answers);
    let alter_reg = |node: usize, change: &dyn Fn(&mut Value)| {
        let mut r = reg.clone();
        change(&mut r[node]);
        r
    };
    let mut cases: Vec<(&str, Three, &str)> = vec![
        (
            "manifest_hash",
            alter_reg(1, &|v| v["manifest_hash"] = json!(FieldHex::from(5))),
            "node 1's answer differs",
        ),
        (
            "npk_app_hash",
            alter_reg(2, &|v| v["npk_app_hash"] = json!(FieldHex::from(5))),
            "node 2's answer differs",
        ),
        (
            "seq",
            alter_reg(1, &|v| v["seq"] = json!(1)),
            "node 1's answer differs",
        ),
        (
            "packages_hash",
            alter_reg(2, &|v| v["packages_hash"] = json!(FieldHex::from(5))),
            "node 2's answer differs",
        ),
        (
            "one registration proof",
            alter_reg(1, &|v| {
                v["registration"]["proof"] = flip(&v["registration"]["proof"], 30)
            }),
            "registration proof",
        ),
    ];
    let mut bad_proof = reg.clone();
    for v in &mut bad_proof {
        v["registration"]["proof"] = flip(&v["registration"]["proof"], 30);
    }
    cases.push((
        "an agreed registration proof that fails",
        bad_proof,
        "does not verify against the built-in vk",
    ));
    let mut no_proof = reg.clone();
    for v in &mut no_proof {
        v.as_object_mut().unwrap().remove("registration");
    }
    cases.push((
        "no registration proof",
        no_proof,
        "carries no registration proof",
    ));
    let mut other_inputs = reg.clone();
    for v in &mut other_inputs {
        v["registration"]["public_inputs"][0] = json!(FieldHex::from(OTHER));
    }
    cases.push((
        "registration public inputs",
        other_inputs,
        "public inputs are not [namespace, npk_app_hash]",
    ));
    for i in 0..3 {
        let other = reg[(i + 1) % 3]["signature"].clone();
        let bodies = alter_reg(i, &|v| v["signature"] = other.clone());
        cases.push((
            "a bad manifest signature",
            bodies,
            [
                "node 0's registry answer",
                "node 1's registry answer",
                "node 2's registry answer",
            ][i],
        ));
    }
    // Three answers that agree and are signed, but on a contract manifest the
    // body does not carry.
    let mut forged = reg.clone();
    for (i, v) in forged.iter_mut().enumerate() {
        let manifest_hash = Fr::from(0x5eu64);
        let message = manifest_message(
            ns(),
            manifest_hash,
            rec.register0.packages_hash.fr(),
            rec.register0.npk_app_hash.fr(),
            0,
            i,
        );
        v["manifest_hash"] = json!(FieldHex(manifest_hash));
        v["signature"] = json!(schnorr::sign(keys[i].sig_scalar(), message, &mut OsRng));
    }
    cases.push((
        "a contract manifest the body does not carry",
        forged,
        "names another contract manifest than the body's",
    ));
    let ns_path = format!("/v1/namespaces/{}", fr_to_hex(ns()));
    for (label, bodies, needle) in cases {
        stubs.net.set(replay("/v1/register", bodies));
        expect(
            label,
            &d.post_json("/v1/register", body0).await,
            ErrorClass::MpcFailure,
            needle,
        );
        expect(
            label,
            &d.get(&ns_path).await,
            ErrorClass::NotFound,
            "no namespace",
        );
    }
    stubs.net.set(replay("/v1/register", reg.clone()));
    let registered: ManifestResponse = ok(
        "replayed REGISTER",
        &d.post_json("/v1/register", body0).await,
    );
    assert_eq!(
        (registered.manifest_hash, registered.npk_app_hash),
        (rec.register0.manifest_hash, rec.register0.npk_app_hash)
    );
    let info: NamespaceResponse = ok("GET namespace at d", &d.get(&ns_path).await);
    assert_eq!(
        (info.seq, info.npk_app_hash, info.manifest_hash),
        (0, rec.register0.npk_app_hash, rec.register0.manifest_hash)
    );

    // --- DISABLE ---------------------------------------------------------
    let dis = three(&rec.disable_answers);
    let alter_dis = |node: usize, change: &dyn Fn(&mut Value)| {
        let mut r = dis.clone();
        change(&mut r[node]);
        r
    };
    let pkg_path = format!("/v1/packages/{}/monty_hall_init", fr_to_hex(ns()));
    let other = dis[2]["signature"].clone();
    for (label, bodies, needle) in [
        (
            "DISABLE seq",
            alter_dis(2, &|v| v["seq"] = json!(2)),
            "node 2's answer differs",
        ),
        (
            "DISABLE signature",
            alter_dis(0, &|v| v["signature"] = other.clone()),
            "node 0's registry answer signature",
        ),
    ] {
        stubs.net.set(replay("/v1/disable", bodies));
        expect(
            label,
            &c.post_json("/v1/disable", &rec.disable).await,
            ErrorClass::MpcFailure,
            needle,
        );
        assert!(!ok::<PackageResponse>("GET package at c", &c.get(&pkg_path).await).disabled);
    }
    stubs.net.set(replay("/v1/disable", dis));
    let disabled: DisableResponse = ok(
        "replayed DISABLE",
        &c.post_json("/v1/disable", &rec.disable).await,
    );
    assert!(disabled.disabled);
    assert!(ok::<PackageResponse>("GET package at c", &c.get(&pkg_path).await).disabled);

    // --- a node that does not answer --------------------------------------
    stubs.net.set(replay("/v1/execute", results));
    stubs.stop(2);
    expect(
        "a node that does not answer",
        &c.post_json("/v1/execute", &rec.seed).await,
        ErrorClass::MpcFailure,
        "node 2: no answer",
    );
}
