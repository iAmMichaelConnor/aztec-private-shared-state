//! The queued (tip) rounds of the request lifecycle on three in-process
//! nodes, on sidecar-core's `testing` harness (feature `testing`) with
//! sidecar-tip's state holders: a chain-held test counter
//! (machine/circuits), its state [value, blinding] a machine-owned record,
//! with real MPC proofs.
//!
//! Needs `scripts/prepare-data.sh` (pss_seed of examples/amm, the machine's
//! queued test counter under machine/circuits, and the CRS under
//! machine/data, or DATA_DIR); every test prints why and passes if they are
//! missing, and fails instead under `PSS_REQUIRE_DATA=1`. Run with `--release`.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use sidecar_core::bind::Elem;
use sidecar_core::error::ErrorClass;
use sidecar_core::field::{FieldHex, Fr, HexBytes, RequestId, fr_from_hex};
use sidecar_core::pipeline;
use sidecar_core::record::{self, record_hash};
use sidecar_core::request::{NODES, Request, StateRecord};
use sidecar_core::schnorr::public_key;
use sidecar_core::state::{ChainKey, QueueRead};
use sidecar_core::store::rules::VersionView;
use sidecar_core::store::{RequestStatus, StoreRead};
use sidecar_core::testing::{
    Answer, Fixture, Network, TestPackage, TipFacts, manifest, open_vec, owner_secret, request,
    serial, small, views,
};
use sidecar_test_fixtures::data::machine_manifest;
use sidecar_tip::state::chain::SealedLog;

const SEED_KEY: &str = "0xa001";
// The machine's queued (tip) test rounds (machine/circuits): a chain-held
// counter, its state [value, blinding] a machine-owned record.
const TIP_CIRCUITS: [&str; 3] = ["pss_seed", "tip_counter_init", "tip_counter"];
const TIP: u64 = 0x7195;
const COUNTER_KEY: &str = "0x7c01";

/// pss_seed and the two counter circuits, and a CRS sized for the largest
/// (`None`, having skipped or failed under `PSS_REQUIRE_DATA=1`, when they
/// are missing).
fn fixture() -> Option<&'static Fixture> {
    sidecar_core::testing::fixture(&TIP_CIRCUITS)
}

/// A three-node network whose nodes serve the tip's state modes.
fn tip_network(fx: &Fixture, seed: u64) -> Network {
    let mut net = Network::new(fx, seed);
    net.with_state_holders(sidecar_tip::holders());
    net
}

/// Register the namespace TIP in one manifest message at seq 0 (which runs
/// the registration circuit): pss_seed under intake direct and the two
/// counter packages under queued manifests on the state key `counter`
/// (COUNTER_KEY), on all three nodes, every key of the counter's in the
/// state mode `mode` (the manifests' own is `chain`).
fn register_tip(fx: &Fixture, net: &mut Network, mode: &str) {
    let queued = |name: &str| {
        let mut manifest = machine_manifest(name);
        for state in manifest["state"].as_object_mut().unwrap().values_mut() {
            *state = mode.into();
        }
        manifest
    };
    let packages = [
        TestPackage::new("pss_seed", manifest("amm", "pss_seed")),
        TestPackage::new("tip_counter_init", queued("tip_counter_init")).keys(&[], &["counter"]),
        TestPackage::new("tip_counter", queued("tip_counter")).keys(&["counter"], &["counter"]),
    ];
    let tip = TipFacts {
        init: Some(("tip_counter_init".into(), vec![])),
        ..TipFacts::new(
            Fr::from(0x0cu64),
            packages.len(),
            &[("counter", fr_from_hex(COUNTER_KEY).unwrap())],
        )
    };
    let mut body = Network::manifest_message(fx, TIP, "tip", &packages, Some(&tip), 0);
    net.register_body(&mut body, &mut None);
    for node in &net.nodes {
        for p in &packages {
            let row = node.store.package(Fr::from(TIP), &p.name).unwrap().unwrap();
            assert_eq!(row.manifest, p.manifest);
        }
    }
}

/// The machine request id the scheduler derives for an attempt of `chain`
/// against `old_commitments` (the test counter has no pinned reads).
fn machine_request_id(chain: Fr, old_commitments: &[Fr]) -> RequestId {
    RequestId(sidecar_tip::machine_request_id(chain, old_commitments, &[]))
}

/// The stand-in vk hash and nonce the scheduler's synthesis would place
/// under the counter's `$vk_hash` and `$user_nonce` parameters (the stub
/// verifier compares neither with the chain).
const VK_HASH: u64 = 0x5a5a;
const USER_NONCE: u64 = 3;

/// A queued counter request, as the scheduler synthesises it: the machine
/// request id, the chain request id, the app input with the reserved
/// operands, and the state as the machine-owned record `state` (none for the
/// first round, which takes no nonce).
fn counter_request(
    request_id: RequestId,
    chain: Fr,
    public: (&str, u64),
    state: Option<StateRecord>,
) -> Request {
    let (circuit, reads): (&str, &[&str]) = match state {
        None => ("tip_counter_init", &[]),
        Some(_) => ("tip_counter", &[COUNTER_KEY]),
    };
    let mut values = vec![
        (public.0, Fr::from(public.1)),
        ("vk_hash", Fr::from(VK_HASH)),
    ];
    if state.is_some() {
        values.push(("user_nonce", Fr::from(USER_NONCE)));
    }
    let mut req = request(TIP, circuit, request_id, &values, reads, &[COUNTER_KEY]);
    req.records = state.into_iter().collect();
    req.chain_request_id = Some(FieldHex(chain));
    req
}

/// An accepting stub of the step 4 chain verifier: it checks that it is
/// handed the queued package the request names (its manifest, shape and
/// vk_hash) and a chain request id, counts its calls, and accepts.
fn accepting_verifier(calls: Arc<AtomicUsize>) -> pipeline::ChainVerifier {
    Box::new(move |req, round| {
        assert_eq!(round.manifest.circuit, req.circuit);
        assert!(req.chain_request_id.is_some());
        assert_ne!(round.vk_hash, Fr::from(0u64));
        assert_eq!(round.shape.namespace_index, 0);
        calls.fetch_add(1, Ordering::SeqCst);
        Ok(QueueRead::default())
    })
}

/// The counter's state from a committed round's answer, opened from the three
/// nodes' new thirds: each node opens its own third with its record key K_i
/// under owner enc_pk_i, the third does not open for another owner (the
/// requester key) or at another node, and the opened shares are consistent.
/// Returns the value and the blinding.
fn open_machine_owned(net: &Network, answer: &Answer, note_hash: Fr) -> Vec<Fr> {
    let ns = Fr::from(TIP);
    let parts: Vec<Vec<Elem>> = net
        .nodes
        .iter()
        .enumerate()
        .map(|(i, node)| {
            let keys = node.keys();
            let r = &answer.results[i].records[0];
            assert_eq!((r.key.as_str(), r.note_hash.fr()), (COUNTER_KEY, note_hash));
            let c_i = r.c_i.as_slice();
            let opened =
                record::open(&keys, ns, COUNTER_KEY, note_hash, keys.enc_pk(), c_i).unwrap();
            assert_eq!(
                record::open_own(&keys, ns, COUNTER_KEY, note_hash, c_i).unwrap(),
                opened
            );
            let requester = public_key(owner_secret());
            assert!(record::open(&keys, ns, COUNTER_KEY, note_hash, requester, c_i).is_err());
            let other = net.nodes[(i + 1) % NODES].keys();
            assert!(record::open_own(&other, ns, COUNTER_KEY, note_hash, c_i).is_err());
            opened
        })
        .collect();
    open_vec([&parts[0], &parts[1], &parts[2]])
}

/// The state record the next round carries, taken the way the scheduler
/// takes it: the round's thirds as the apply log carries them (the new
/// commitments, then each node's third, `SealedLog::to_fields`)
/// decoded back (`SealedLog::from_fields`) into a request record. It equals
/// the record the orchestrator assembled from the three answers.
///
/// `public` is how many of the state's 2 elements the round stored as public
/// values: each takes 2 fields of a third instead of 3, so a third is
/// `third_fields_len(2) - public` fields and the log `1 + 3 × that`.
fn record_from_apply_log(answer: &Answer, new_c: Fr, public: usize) -> StateRecord {
    let thirds = [0, 1, 2].map(|i| answer.results[i].records[0].c_i.as_slice().to_vec());
    let third_len = record::third_fields_len(2) - public;
    for c_i in &thirds {
        assert_eq!(record::third_fields(c_i).unwrap().len(), third_len);
    }
    let fields = SealedLog {
        new_commitments: vec![new_c],
        thirds: vec![thirds],
    }
    .to_fields()
    .unwrap();
    assert_eq!(fields.len(), 1 + 3 * third_len);
    let log = SealedLog::from_fields(&fields, 1, 1).unwrap();
    let c = log.thirds[0].clone().map(HexBytes);
    let record_hashes = c
        .clone()
        .map(|c_i| FieldHex(record_hash(c_i.as_slice()).unwrap()));
    let record = StateRecord {
        key: COUNTER_KEY.into(),
        note_hash: FieldHex(log.new_commitments[0]),
        c,
        record_hashes,
    };
    assert_eq!(answer.records, std::slice::from_ref(&record));
    record
}

/// A queued round runs end to end on three nodes with an accepting stub
/// chain verifier: the first round writes the counter's state as a
/// machine-owned record (sealed at step 13 with owner enc_pk_i), the requests
/// row and the NodeResult carry the thirds as `records` with the chain
/// request id; the next round's state enters as that record, taken from the
/// apply log's fields, opens at step 8 (the round proves against the old
/// commitment) and is sealed again for the nodes, while the same thirds under
/// another note hash do not open (400, nothing stored); FETCH by chain
/// request id answers the latest attempt. The verifier runs on every node for
/// every queued request, and no requester signs anything.
#[test]
fn a_queued_round_carries_its_state_as_machine_owned_records() {
    let Some(fx) = fixture() else { return };
    let _serial = serial();
    let mut net = tip_network(fx, 8);
    let calls = Arc::new(AtomicUsize::new(0));
    net.with_chain_verifier(|_| accepting_verifier(calls.clone()));
    register_tip(fx, &mut net, "chain");
    let ns = Fr::from(TIP);

    // The first round: no state read, the counter's state written.
    let chain0 = Fr::from(0xc0u64);
    let init = counter_request(machine_request_id(chain0, &[]), chain0, ("start", 5), None);
    let first = net.execute(fx, "tip: counter init", &init);
    assert_eq!(calls.load(Ordering::SeqCst), NODES);
    let c0 = first.output("new_c");
    let state = open_machine_owned(&net, &first, c0);
    assert_eq!(small(state[0]), 5);
    // pss_core tip::slot::commitment over the counter's slot
    let slot = sidecar_core::field::fr_from_hex(COUNTER_KEY).unwrap();
    let sep = sidecar_core::keys::label_field(b"pss.tip.state");
    assert_eq!(
        sidecar_core::hash::poseidon2_hash(&[sep, ns, slot, state[0], state[1]]),
        c0
    );
    for (i, node) in net.nodes.iter().enumerate() {
        let row = node.store.request(ns, init.request_id).unwrap().unwrap();
        assert_eq!(row.chain_request_id, Some(chain0));
        assert!(row.stored_keys.is_empty() && row.created_keys.is_empty());
        let rows: Vec<_> = row.records().collect();
        assert_eq!(rows.len(), 1);
        assert_eq!((rows[0].key.as_str(), rows[0].note_hash), (COUNTER_KEY, c0));
        assert_eq!(rows[0].c_i, first.results[i].records[0].c_i.as_slice());
        // nothing node-held: the state lives in the record only
        assert!(node.store.value(ns, COUNTER_KEY).unwrap().is_none());
        let fetched = pipeline::fetch_by_chain_request_id(node, ns, chain0).unwrap();
        assert_eq!(fetched, pipeline::fetch(node, ns, init.request_id).unwrap());
        assert_eq!(fetched.records, first.results[i].records);
    }

    // The next round: the state enters as the machine-owned record. The
    // first round stored `start`, a public input, as a public element.
    let record = record_from_apply_log(&first, c0, 1);
    let chain1 = Fr::from(0xc1u64);
    // Claimed under another note hash, the thirds do not open at step 8
    // (the note hash is in their associated data), and nothing changes.
    let mut moved = record.clone();
    moved.note_hash = FieldHex(c0 + Fr::from(1u64));
    let wrong = counter_request(
        machine_request_id(chain1, &[moved.note_hash.fr()]),
        chain1,
        ("amount", 7),
        Some(moved),
    );
    net.refused(
        "tip: a machine-owned record under another note hash",
        views(&wrong),
        ErrorClass::BadRequest,
        "does not open or its associated data differs",
    );
    let add = counter_request(
        machine_request_id(chain1, &[c0]),
        chain1,
        ("amount", 7),
        Some(record.clone()),
    );
    let second = net.execute(fx, "tip: counter add 7", &add);
    assert_eq!(calls.load(Ordering::SeqCst), 3 * NODES);
    assert_eq!(second.output("old_c"), c0, "step 8 opened the state");
    let c1 = second.output("new_c");
    assert_ne!(c1, c0);
    let state = open_machine_owned(&net, &second, c1);
    assert_eq!(small(state[0]), 12);
    let latest = |net: &Network, chain: Fr, id: RequestId| {
        for node in &net.nodes {
            let found = pipeline::fetch_by_chain_request_id(node, ns, chain).unwrap();
            assert_eq!(found, pipeline::fetch(node, ns, id).unwrap());
            assert_eq!(found.request_id, id);
            assert_eq!(
                node.store
                    .request(ns, id)
                    .unwrap()
                    .unwrap()
                    .chain_request_id,
                Some(chain)
            );
        }
    };
    latest(&net, chain1, add.request_id);
    // FETCH by its request id answers the same round again.
    net.fetch(fx, "tip: fetch counter add 7", &add);

    // A second attempt at the same chain request (the scheduler recomputed
    // it under another machine request id) is a new round; FETCH by the chain
    // request id then answers the latest attempt.
    let retry = counter_request(
        RequestId(add.request_id.fr() + Fr::from(1u64)),
        chain1,
        ("amount", 7),
        Some(record),
    );
    let third = net.execute(fx, "tip: counter add 7, second attempt", &retry);
    assert_eq!(third.output("old_c"), c0);
    assert_ne!(third.output("new_c"), c1, "a fresh blinding");
    latest(&net, chain1, retry.request_id);
    assert_eq!(calls.load(Ordering::SeqCst), 4 * NODES);

    // The state of the latest round is the next round's input in turn.
    // `start` was public, so `value + amount` stays public: still one public
    // element (the blinding is a fresh SAMPLE, shared).
    let record = record_from_apply_log(&third, third.output("new_c"), 1);
    let chain2 = Fr::from(0xc2u64);
    let c2_old = third.output("new_c");
    let again = counter_request(
        machine_request_id(chain2, &[c2_old]),
        chain2,
        ("amount", 30),
        Some(record),
    );
    let fourth = net.execute(fx, "tip: counter add 30", &again);
    assert_eq!(
        small(open_machine_owned(&net, &fourth, fourth.output("new_c"))[0]),
        42
    );
}

/// With the default chain verifier (sidecar-core's
/// `chain_verifier_not_built`, which a node gets unless one is injected) a
/// queued round is refused 400 at step 4 on every node, and nothing is
/// stored; the orchestrator's prefix passes it (step 3 resolves a queued
/// package, and its step 4 is empty at the tip: the verifier is the nodes'),
/// and refuses it at step 3 without a chain request id. A direct round
/// beside it still runs.
#[test]
fn a_queued_round_is_refused_at_step_4_without_a_chain_verifier() {
    let Some(fx) = fixture() else { return };
    let _serial = serial();
    let mut net = tip_network(fx, 6);
    register_tip(fx, &mut net, "chain");
    let ns = Fr::from(TIP);

    let chain0 = Fr::from(0xc0u64);
    let init = counter_request(machine_request_id(chain0, &[]), chain0, ("start", 5), None);
    let (_, shape) = pipeline::stateless_prefix(&init, &net.nodes[0].store).unwrap();
    assert_eq!(shape.outputs.len(), 1);
    net.refused(
        "a queued round without a chain verifier",
        views(&init),
        ErrorClass::BadRequest,
        pipeline::CHAIN_VERIFIER_NOT_BUILT,
    );
    for node in &net.nodes {
        assert!(node.store.request(ns, init.request_id).unwrap().is_none());
        let err = pipeline::fetch_by_chain_request_id(node, ns, chain0).unwrap_err();
        assert_eq!(err.class, ErrorClass::NotFound, "{err}");
    }

    // A queued round with a record is refused at the same step, before the
    // record would be opened: a record no node sealed is never looked at.
    let junk = StateRecord {
        key: COUNTER_KEY.into(),
        note_hash: FieldHex(Fr::from(9u64)),
        c: [0, 1, 2].map(|_| HexBytes(vec![0; 8 + 64])),
        record_hashes: [0, 1, 2].map(|_| FieldHex(record_hash(&[0; 8 + 64]).unwrap())),
    };
    let chain1 = Fr::from(0xc1u64);
    let add = counter_request(
        machine_request_id(chain1, &[Fr::from(9u64)]),
        chain1,
        ("amount", 7),
        Some(junk),
    );
    pipeline::stateless_prefix(&add, &net.nodes[0].store).unwrap();
    net.refused(
        "a queued round with a record, without a chain verifier",
        views(&add),
        ErrorClass::BadRequest,
        pipeline::CHAIN_VERIFIER_NOT_BUILT,
    );

    // Without a chain request id it is refused at step 3, here and there.
    let mut bare = init.clone();
    bare.chain_request_id = None;
    let needle = "field `chain_request_id`: missing";
    let err = pipeline::stateless_prefix(&bare, &net.nodes[0].store).unwrap_err();
    assert!(err.message.contains(needle), "{err}");
    net.refused(
        "a queued round without a chain request id",
        views(&bare),
        ErrorClass::BadRequest,
        needle,
    );

    // The direct package beside it still runs.
    let seed = request(TIP, "pss_seed", net.id(), &[], &[], &[SEED_KEY]);
    net.execute(fx, "a direct package beside queued ones", &seed);
}

/// A step 4 stub that accepts every request with the chain view `read`
/// holds, which the test sets before each round.
fn queue_verifier(read: Arc<Mutex<QueueRead>>) -> pipeline::ChainVerifier {
    Box::new(move |req, _| {
        assert!(req.chain_request_id.is_some());
        Ok(read.lock().unwrap().clone())
    })
}

/// A node-held counter round's new version at node `i` (the version its
/// request wrote), if the node holds one.
fn version_of(net: &Network, i: usize, id: RequestId) -> Option<Fr> {
    let versions = net.nodes[i]
        .store
        .tip_versions(Fr::from(TIP), COUNTER_KEY)
        .unwrap();
    versions
        .iter()
        .find(|v| v.request_id == id)
        .map(|v| v.commitment)
}

/// A tip attempt committed at two nodes (the third node's commit fails) is
/// stuck: a resend is the same machine request id, which the two answer
/// from their rows while the third refuses at the handshake. The operator
/// rolls it back at the two nodes that hold it: each refuses while its own
/// chain view says the slot holds the attempt's version (it landed), then
/// deletes that version and keeps the row as `rolled_back`; the third
/// node, which never committed it, has no row to roll back (404). The
/// resend then runs at all three nodes under the same request id and its
/// rows replace the rolled-back ones, with a version under a fresh
/// blinding.
#[test]
fn a_tip_attempt_committed_at_two_nodes_is_rolled_back_and_run_again() {
    let Some(fx) = fixture() else { return };
    let _serial = serial();
    let mut net = tip_network(fx, 9);
    let read = Arc::new(Mutex::new(QueueRead {
        block: 10,
        ..QueueRead::default()
    }));
    net.with_chain_verifier(|_| queue_verifier(read.clone()));
    register_tip(fx, &mut net, "node");
    let ns = Fr::from(TIP);

    // The init round creates the counter's first version at all three.
    let chain0 = Fr::from(0xc0u64);
    let init = counter_request(machine_request_id(chain0, &[]), chain0, ("start", 5), None);
    let c0 = net
        .execute(fx, "tip: node-held counter init", &init)
        .output("new_c");
    for i in 0..NODES {
        assert_eq!(version_of(&net, i, init.request_id), Some(c0));
    }

    // The next entry's attempt commits at nodes 0 and 1 only.
    *read.lock().unwrap() = QueueRead {
        block: 11,
        block_hash: Fr::from(0u64),
        settled: 0,
        head: 1,
        index: 1,
        keys: vec![ChainKey {
            key: COUNTER_KEY.into(),
            slot: c0,
            old: c0,
            ..Default::default()
        }],
    };
    let chain1 = Fr::from(0xc1u64);
    let mut add = request(
        TIP,
        "tip_counter",
        machine_request_id(chain1, &[c0]),
        &[
            ("amount", Fr::from(7u64)),
            ("vk_hash", Fr::from(VK_HASH)),
            ("user_nonce", Fr::from(USER_NONCE)),
        ],
        &[COUNTER_KEY],
        &[COUNTER_KEY],
    );
    add.chain_request_id = Some(FieldHex(chain1));
    net.nodes[2].store.fail_next_commit();
    let results = net.run(views(&add));
    assert!(results[0].is_ok() && results[1].is_ok(), "{results:?}");
    let err = results[2].as_ref().unwrap_err();
    assert_eq!(err.class, ErrorClass::MpcFailure, "{err}");
    let lone = version_of(&net, 0, add.request_id).unwrap();
    assert_eq!(version_of(&net, 1, add.request_id), Some(lone));
    assert_eq!(version_of(&net, 2, add.request_id), None);

    // The resend is stuck: nodes 0 and 1 replay, node 2 refuses.
    let results = net.run(views(&add));
    assert!(results[0].is_ok() && results[1].is_ok(), "{results:?}");
    let err = results[2].as_ref().unwrap_err();
    assert!(err.message.contains("already holds request"), "{err}");

    // The rollback, at each node against its own chain view.
    let view = |slot: Fr| {
        move |_: Fr, keys: &[String]| {
            Ok(Some(
                keys.iter()
                    .map(|_| VersionView {
                        slot,
                        head: 1,
                        block: 12,
                        settled: 0,
                        ..Default::default()
                    })
                    .collect(),
            ))
        }
    };
    let err = pipeline::restore(&net.nodes[0], ns, add.request_id, &view(lone)).unwrap_err();
    assert_eq!(err.class, ErrorClass::Conflict, "{err}");
    assert!(err.message.contains("the attempt landed"), "{err}");
    let err = pipeline::restore(&net.nodes[2], ns, add.request_id, &view(c0)).unwrap_err();
    assert_eq!(err.class, ErrorClass::NotFound, "{err}");
    for i in [0, 1] {
        let node = &net.nodes[i];
        pipeline::restore(node, ns, add.request_id, &view(c0)).unwrap();
        assert_eq!(version_of(&net, i, add.request_id), None);
        assert_eq!(version_of(&net, i, init.request_id), Some(c0));
        let row = node.store.request(ns, add.request_id).unwrap().unwrap();
        assert_eq!(row.status, RequestStatus::RolledBack);
        let err = pipeline::fetch_by_chain_request_id(node, ns, chain1).unwrap_err();
        assert_eq!(err.class, ErrorClass::Conflict, "{err}");
    }

    // The resend runs at all three and replaces the rolled-back rows.
    let again = net.execute(fx, "tip: node-held counter add 7, run again", &add);
    let rerun = again.output("new_c");
    assert_eq!(again.output("old_c"), c0);
    assert_ne!(rerun, lone, "a fresh blinding");
    for (i, node) in net.nodes.iter().enumerate() {
        assert_eq!(version_of(&net, i, add.request_id), Some(rerun));
        let row = node.store.request(ns, add.request_id).unwrap().unwrap();
        assert_eq!(row.status, RequestStatus::Committed);
        let found = pipeline::fetch_by_chain_request_id(node, ns, chain1).unwrap();
        assert_eq!(found.public_inputs, again.results[i].public_inputs);
    }
}
