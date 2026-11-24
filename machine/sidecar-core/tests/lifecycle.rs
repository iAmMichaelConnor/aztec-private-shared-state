//! The request lifecycle on three in-process nodes (sidecar-core's `testing`
//! harness: mpc_net's local network, one thread per node, each with its own
//! MemoryStore and keys), over the compiled AMM and Monty Hall circuits with
//! real MPC proofs, checked by the harness's small orchestrator. The queued
//! (chain-held) rounds run on the same harness in sidecar-tip's
//! `tests/lifecycle.rs`.
//!
//! Needs `scripts/prepare-data.sh` (the circuits of examples/amm and
//! examples/monty-hall and the CRS under machine/data, or DATA_DIR); every
//! test prints why and passes if they are missing. Run with `--release`.

use std::time::Instant;

use serde_json::Value;
use sidecar_core::bind::Share;
use sidecar_core::crs::{Artifact, Circuit};
use sidecar_core::error::{ErrorClass, Refusal};
use sidecar_core::field::{FieldHex, Fr, RequestId, fr_to_hex};
use sidecar_core::grumpkin::{Fq, point_to_wire};
use sidecar_core::keys::NodeKeys;
use sidecar_core::pipeline;
use sidecar_core::record::{self, record_hash};
use sidecar_core::register::ManifestAnswer;
use sidecar_core::registry::Signed;
use sidecar_core::request::{NODES, PublicValue, Request, StateRecord};
use sidecar_core::response::NodeResult;
use sidecar_core::schnorr::public_key;
use sidecar_core::store::{NamespaceRow, NewRequest, RequestStatus, Store, StoreRead, rules};
use sidecar_core::testing::{
    Answer, Fixture, Network, TestPackage, manifest, owner_secret, request, rng, serial, sign_as,
    small, views,
};
use sidecar_test_fixtures::requests::monty::{CHOSEN_DOOR, GAME_KEY, GAME_SEED_KEY, WINNING_DOOR};
use sidecar_test_fixtures::requests::{NONCE, amm, amm::POOL_KEY, amm::SEED_KEY, monty};

const AMM: u64 = 0xc0ffee;
const MONTY: u64 = 0x6a3e;
const AMM_CIRCUITS: [&str; 3] = amm::CIRCUITS;
const MONTY_CIRCUITS: [&str; 4] = monty::CIRCUITS;

/// The AMM and Monty Hall round circuits and a CRS sized for the largest.
fn fixture() -> Option<&'static Fixture> {
    let mut names = AMM_CIRCUITS.to_vec();
    names.extend(&MONTY_CIRCUITS[1..]);
    sidecar_core::testing::fixture(&names)
}

/// One swap on the opened pool: the round's amount_out is the constant-product
/// output on the pool the three nodes hold.
fn checked_swap(
    fx: &Fixture,
    net: &Network,
    label: &str,
    req: &Request,
    amount_in: u64,
    direction: bool,
) -> Answer {
    let before = net.opened_value(AMM, POOL_KEY);
    let pool = [small(before[0]), small(before[1])];
    let answer = net.execute(fx, label, req);
    let expected = amm::swap_out(pool, amount_in, direction);
    assert_eq!(
        small(answer.output("app_outputs[0]")),
        expected,
        "{label}: amount_out"
    );
    let after = net.opened_value(AMM, POOL_KEY);
    let [x, y] = amm::swapped(pool, amount_in, expected, direction);
    assert_eq!(
        [small(after[0]), small(after[1])],
        [x, y],
        "{label}: new pool"
    );
    eprintln!("{label}: pool {pool:?} -> [{x}, {y}], amount_out {expected}");
    answer
}

/// The AMM sequence: seed, init and two swaps on node-held state, a FETCH and a
/// replay equal to the first answer, a second init refused, the npk_app_hash
/// and nullifiers across rounds, three result signatures per round, and a
/// rollback of the second swap followed by a third swap on the restored pool.
#[test]
fn amm_sequence_with_fetch_and_rollback() {
    let Some(fx) = fixture() else { return };
    let _serial = serial();
    let mut net = Network::new(fx, 1);
    let npk_app_hash = net.register(fx, AMM, "amm", &AMM_CIRCUITS);

    let seed = amm::seed(AMM, net.id());
    let seeded = net.execute(fx, "amm seed", &seed);
    assert_eq!(seeded.results[0].stored, [SEED_KEY]);
    assert!(seeded.records.is_empty());

    let init = amm::init(AMM, net.id());
    let inited = net.execute(fx, "amm init", &init);
    assert_eq!(inited.results[0].stored, [POOL_KEY]);
    let pool = net.opened_value(AMM, POOL_KEY);
    eprintln!("amm init: pool [{}, {}]", small(pool[0]), small(pool[1]));
    for reserve in &pool[..2] {
        assert!((1_000_000..2_000_000).contains(&small(*reserve)));
    }

    let swap1 = amm::swap(AMM, net.id(), 25000, 0);
    let swapped1 = checked_swap(fx, &net, "amm swap 1", &swap1, 25000, false);
    let after_swap1: Vec<_> = net
        .nodes
        .iter()
        .map(|n| n.store.value(Fr::from(AMM), POOL_KEY).unwrap().unwrap())
        .collect();
    let swap2 = amm::swap(AMM, net.id(), 10000, 1);
    let swapped2 = checked_swap(fx, &net, "amm swap 2", &swap2, 10000, true);

    // FETCH of the first answer equals it, on every node; so does a replay of
    // its body, which runs no second round, only the handshake.
    let fetched = net.fetch(fx, "amm fetch seed", &seed);
    assert_eq!(fetched.results, seeded.results);
    let start = Instant::now();
    let replayed: Vec<NodeResult> = net
        .run(views(&seed))
        .into_iter()
        .map(|r| r.unwrap())
        .collect();
    assert_eq!(replayed, seeded.results.to_vec());
    eprintln!(
        "amm replay of the seed: {:.3}s",
        start.elapsed().as_secs_f64()
    );
    for node in &net.nodes {
        let err = pipeline::fetch(node, Fr::from(AMM), RequestId::from(7u64)).unwrap_err();
        assert_eq!(err.class, ErrorClass::NotFound);
    }

    // A second init on the consumed seed.
    let again = amm::init(AMM, net.id());
    net.refused(
        "amm second init",
        views(&again),
        ErrorClass::Conflict,
        "is already consumed",
    );

    // Every nullifying round outputs the npk_app_hash REGISTER signed, and the
    // rounds nullify three different notes.
    for answer in [&inited, &swapped1, &swapped2] {
        assert_eq!(answer.output("npk_app_hash"), npk_app_hash);
    }
    assert_eq!(seeded.output("npk_app_hash"), Fr::from(0u64));
    let nullifiers: Vec<Fr> = [&inited, &swapped1, &swapped2]
        .iter()
        .map(|a| a.output("nullifiers[0]"))
        .collect();
    assert!(nullifiers[0] != nullifiers[1] && nullifiers[1] != nullifiers[2]);

    // Rolling back swap 1 first is out of order.
    for node in &net.nodes {
        let err =
            pipeline::restore(node, Fr::from(AMM), swap1.request_id, &|_, _| Ok(None)).unwrap_err();
        assert_eq!(err.class, ErrorClass::Conflict, "{err}");
        assert!(
            err.message.contains("roll that request back first"),
            "{err}"
        );
    }
    // Roll back swap 2 on the three nodes.
    let consumed_by_swap2 = swapped1.output("new_note_hashes[0]");
    assert!(
        net.nodes[0]
            .store
            .consumed(Fr::from(AMM), consumed_by_swap2)
            .unwrap()
            .is_some()
    );
    for node in &net.nodes {
        pipeline::restore(node, Fr::from(AMM), swap2.request_id, &|_, _| Ok(None)).unwrap();
    }
    for (node, row) in net.nodes.iter().zip(&after_swap1) {
        let ns = Fr::from(AMM);
        assert_eq!(&node.store.value(ns, POOL_KEY).unwrap().unwrap(), row);
        assert!(
            node.store
                .consumed(ns, consumed_by_swap2)
                .unwrap()
                .is_none()
        );
        let status = node
            .store
            .request(ns, swap2.request_id)
            .unwrap()
            .unwrap()
            .status;
        assert_eq!(status, RequestStatus::RolledBack);
        let err = pipeline::fetch(node, ns, swap2.request_id).unwrap_err();
        assert_eq!(err.class, ErrorClass::Conflict, "{err}");
        let err = pipeline::restore(node, ns, swap2.request_id, &|_, _| Ok(None)).unwrap_err();
        assert_eq!(err.class, ErrorClass::Conflict, "{err}");
    }
    // Its replay is refused too.
    net.refused(
        "amm replay of a rolled-back swap",
        views(&swap2),
        ErrorClass::Conflict,
        "was rolled back",
    );

    // A third swap loads the restored pool: the same state and key as swap 2,
    // so the same leaf, nullifier and amount out.
    let swap3 = amm::swap(AMM, net.id(), 10000, 1);
    let swapped3 = checked_swap(fx, &net, "amm swap 3 after rollback", &swap3, 10000, true);
    assert_eq!(
        swapped3.output("app_outputs[0]"),
        swapped2.output("app_outputs[0]")
    );
    assert_eq!(
        swapped3.output("read_leaves[0]"),
        swapped2.output("read_leaves[0]")
    );
    assert_eq!(
        swapped3.output("nullifiers[0]"),
        swapped2.output("nullifiers[0]")
    );
    assert_eq!(swapped3.output("npk_app_hash"), npk_app_hash);
    assert_ne!(
        swapped3.output("new_note_hashes[0]"),
        swapped2.output("new_note_hashes[0]")
    );

    // Every stored vk is the one its circuit rebuilds to, on every node.
    let ns = Fr::from(AMM);
    for name in AMM_CIRCUITS {
        let row = net.nodes[0].store.package(ns, name).unwrap().unwrap();
        let rebuilt = Circuit::new(
            Artifact::from_json(name, &row.circuit_json).unwrap(),
            &fx.crs.prover,
        )
        .unwrap();
        for node in &net.nodes {
            let row = node.store.package(ns, name).unwrap().unwrap();
            assert_eq!(row.vk, rebuilt.vk.to_buffer(), "{name}: the stored vk");
        }
    }
    // A restart: the first swap on the fresh nodes loads amm_swap from the vk
    // its row stores (no node builds a vk during the round) and proves and
    // verifies as before.
    net.restart(fx);
    let swap4 = amm::swap(AMM, net.id(), 5000, 0);
    checked_swap(fx, &net, "amm swap 4 after a restart", &swap4, 5000, false);
    assert_eq!(*net.vk_builds.lock().unwrap(), [0; NODES]);
}

/// A committed row carrying a chain request id is found by it, on every
/// node, and answered as FETCH by its request id answers it. A direct
/// request may not carry one, nor name a contract manifest version: the
/// orchestrator's prefix and every node refuse it at step 3 and nothing
/// changes; a direct round's row carries
/// none, so FETCH by the id is 404. Here the row is committed as step 15 of
/// a queued round writes it: each node's row of a real round,
/// under a second request id (the next attempt's machine request id) with
/// the chain request id. Rolled back, the latest row is 409.
#[test]
fn a_committed_row_carrying_a_chain_request_id_is_found_by_it() {
    let Some(fx) = fixture() else { return };
    let _serial = serial();
    let mut net = Network::new(fx, 7);
    net.register(fx, AMM, "amm", &AMM_CIRCUITS);
    let ns = Fr::from(AMM);
    let chain = Fr::from(0xc4a1u64);
    let needle = "only a queued (tip) request carries a chain request id";

    let mut tip = amm::seed(AMM, net.id());
    tip.chain_request_id = Some(FieldHex(chain));
    let err = pipeline::stateless_prefix(&tip, &net.nodes[0].store).unwrap_err();
    assert_eq!(err.class, ErrorClass::BadRequest, "{err}");
    assert!(err.message.contains(needle), "{err}");
    net.refused(
        "a chain request id under intake direct",
        views(&tip),
        ErrorClass::BadRequest,
        needle,
    );
    let mut versioned = amm::seed(AMM, net.id());
    let held = net.nodes[0].store.contract_manifest(ns).unwrap().unwrap();
    versioned.manifest_hash = Some(FieldHex(held.manifest_hash));
    let named = "only a queued (tip) request names a contract manifest version";
    let err = pipeline::stateless_prefix(&versioned, &net.nodes[0].store).unwrap_err();
    assert_eq!(err.class, ErrorClass::BadRequest, "{err}");
    assert!(err.message.contains(named), "{err}");
    net.refused(
        "a contract manifest version under intake direct",
        views(&versioned),
        ErrorClass::BadRequest,
        named,
    );

    let seed = amm::seed(AMM, net.id());
    let seeded = net.execute(fx, "chain: amm seed", &seed);
    let attempt = net.id();
    for node in &net.nodes {
        let row = node.store.request(ns, seed.request_id).unwrap().unwrap();
        assert_eq!(row.chain_request_id, None);
        let err = pipeline::fetch_by_chain_request_id(node, ns, chain).unwrap_err();
        assert_eq!(err.class, ErrorClass::NotFound, "{err}");
        let mut txn = node.store.begin(ns);
        txn.put_request(NewRequest {
            request_id: attempt,
            body_hash: row.body_hash,
            vk_hash: row.vk_hash,
            proof: row.proof,
            public_inputs: row.public_inputs,
            stored_keys: vec![],
            created_keys: vec![],
            signature: row.signature,
            created_at: rules::chain_created_at(&node.store, ns, chain, pipeline::unix_now())
                .unwrap(),
            chain_request_id: Some(chain),
        });
        node.store.commit(txn).unwrap();
    }
    for (i, node) in net.nodes.iter().enumerate() {
        let found = pipeline::fetch_by_chain_request_id(node, ns, chain).unwrap();
        assert_eq!(found, pipeline::fetch(node, ns, attempt).unwrap());
        assert_eq!(found.request_id, attempt);
        assert_eq!(found.proof, seeded.results[i].proof);
        assert_eq!(found.public_inputs, seeded.results[i].public_inputs);
        let pkg = node.store.package(ns, "pss_seed").unwrap().unwrap();
        assert_eq!(found.vk_hash, Some(FieldHex(pkg.vk_hash)));
        assert!(
            pipeline::fetch_by_chain_request_id(node, Fr::from(MONTY), chain)
                .is_err_and(|e| e.class == ErrorClass::NotFound)
        );
        pipeline::restore(node, ns, attempt, &|_, _| Ok(None)).unwrap();
        let err = pipeline::fetch_by_chain_request_id(node, ns, chain).unwrap_err();
        assert_eq!(err.class, ErrorClass::Conflict, "{err}");
    }
}

/// On the sidecar path a REGISTER of another contract manifest (amm_init's
/// circuit manifest changed, the same circuit) replaces the namespace's
/// manifest and governs the next round on all three nodes without a
/// restart, though every node has the package cached from a round before
/// under the same vk_hash. amm_init re-registered without its consume entry
/// lets a second init read the seed the first consumed, and records
/// nothing; re-registered with the entry again, it refuses a third init.
#[test]
fn a_manifest_only_re_registration_governs_the_next_round_on_every_node() {
    let Some(fx) = fixture() else { return };
    let _serial = serial();
    let mut net = Network::new(fx, 4);
    let ns = Fr::from(AMM);
    let npk_app_hash = net.register(fx, AMM, "amm", &AMM_CIRCUITS[..2]);
    let vk_hash = net.nodes[0]
        .store
        .package(ns, "amm_init")
        .unwrap()
        .unwrap()
        .vk_hash;

    let seed = amm::seed(AMM, net.id());
    let seed_note = net
        .execute(fx, "re-register seed", &seed)
        .output("new_note_hashes[0]");
    let init = |net: &mut Network, pool: &str| {
        request(
            AMM,
            "amm_init",
            net.id(),
            &[("in0_nonce", Fr::from(NONCE))],
            &[SEED_KEY],
            &[pool],
        )
    };
    let first = init(&mut net, POOL_KEY);
    net.execute(fx, "re-register init under `once`", &first);
    let refused = init(&mut net, "0xa003");
    net.refused(
        "re-register second init under `once`",
        views(&refused),
        ErrorClass::Conflict,
        "is already consumed",
    );

    // REGISTER the contract manifest with amm_init's consume entry removed.
    let reregister = |net: &mut Network, init_manifest: Value, seq: u64| {
        let packages = [
            TestPackage::new("pss_seed", manifest("amm", "pss_seed")),
            TestPackage::new("amm_init", init_manifest),
        ];
        let mut body = Network::manifest_message(fx, AMM, "amm", &packages, None, seq);
        net.register_body(&mut body, &mut Some(npk_app_hash));
        for node in &net.nodes {
            let row = node.store.package(ns, "amm_init").unwrap().unwrap();
            assert_eq!((row.seq, row.vk_hash), (seq, vk_hash));
        }
    };
    let mut unconsumed = manifest("amm", "amm_init");
    unconsumed["consume"] = Value::Array(vec![]);
    reregister(&mut net, unconsumed, 1);
    let second = init(&mut net, "0xa003");
    let answer = net.execute(fx, "re-register init with no consume entry", &second);
    assert_eq!(answer.results[0].stored, ["0xa003"]);
    // The node reloads the package from its row, with the stored vk.
    assert_eq!(*net.vk_builds.lock().unwrap(), [0; NODES]);
    for (i, node) in net.nodes.iter().enumerate() {
        let row = node.store.consumed(ns, seed_note).unwrap().unwrap();
        assert_eq!(
            row.request_id, first.request_id,
            "node {i}: the unlisted read recorded nothing"
        );
    }

    // REGISTER it with the entry restored.
    reregister(&mut net, manifest("amm", "amm_init"), 2);
    let third = init(&mut net, "0xa004");
    net.refused(
        "re-register third init under `once` again",
        views(&third),
        ErrorClass::Conflict,
        "is already consumed",
    );
}

/// The Monty Hall sequence on client-held state: every record-supplying (and
/// record-storing) request is signed by its requester, each new record opens
/// only for that owner, the door is an INPUT_SHARED value, FETCH answers the
/// records' thirds as the round did, and a consumed record presented again is
/// refused naming the request (and the circuit, when another) that consumed
/// it.
#[test]
fn monty_hall_sequence_with_client_held_records() {
    let Some(fx) = fixture() else { return };
    let _serial = serial();
    let mut net = Network::new(fx, 2);
    let npk_app_hash = net.register(fx, MONTY, "monty-hall", &MONTY_CIRCUITS);
    let player = monty::player();
    let other = monty::other();
    let player_pk = public_key(player);

    // The seed stores a client-held key, so it is signed.
    let mut seed = monty::seed(MONTY, net.id());
    let unsigned = seed.clone();
    net.refused(
        "monty seed without a requester",
        views(&unsigned),
        ErrorClass::BadRequest,
        "field `requester`: missing",
    );
    sign_as(&mut seed, player, player);
    let seeded = net.execute(fx, "monty seed", &seed);
    assert!(seeded.results[0].stored.is_empty());
    let [seed_record] = &seeded.records[..] else {
        panic!("one record")
    };
    assert_eq!(seed_record.key, GAME_SEED_KEY);
    assert_eq!(
        seed_record.note_hash.fr(),
        seeded.output("new_note_hashes[0]")
    );
    assert_eq!(net.opened_record(MONTY, seed_record, player_pk).len(), 2);
    // Nothing of the game lives in `values`.
    for node in &net.nodes {
        assert!(
            node.store
                .value(Fr::from(MONTY), GAME_SEED_KEY)
                .unwrap()
                .is_none()
        );
    }
    // FETCH answers each node's stored third with its signature.
    let fetched = net.fetch(fx, "monty fetch seed", &seed);
    assert_eq!(fetched.results, seeded.results);
    assert_eq!(fetched.records, seeded.records);

    let init_with = |net: &mut Network, requester: Fq, signer: Option<Fq>| {
        let mut init = monty::init(MONTY, net.id(), seed_record);
        match signer {
            Some(signer) => sign_as(&mut init, requester, signer),
            None => init.requester = Some(point_to_wire(public_key(requester))),
        }
        init
    };
    // The record opens only for its owner: another requester's own valid
    // signature gets 400 at open, an unsigned request 403.
    let stolen = init_with(&mut net, other, Some(other));
    net.refused(
        "monty init by another requester",
        views(&stolen),
        ErrorClass::BadRequest,
        "record does not open",
    );
    let forged = init_with(&mut net, player, Some(other));
    net.refused(
        "monty init signed by another key",
        views(&forged),
        ErrorClass::Forbidden,
        "does not verify",
    );
    let bare = init_with(&mut net, player, None);
    net.refused(
        "monty init unsigned",
        views(&bare),
        ErrorClass::Forbidden,
        "field `signature`: missing",
    );
    let init = init_with(&mut net, player, Some(player));
    let inited = net.execute(fx, "monty init", &init);
    assert_eq!(inited.output("npk_app_hash"), npk_app_hash);
    let [game] = &inited.records[..] else {
        panic!("one record")
    };
    let state = net.opened_record(MONTY, game, player_pk);
    assert_eq!(state.len(), 10);
    let winning = small(state[WINNING_DOOR]);
    assert!(winning < 3);
    for (i, node) in net.nodes.iter().enumerate() {
        let err = record::open(
            &node.keys(),
            Fr::from(MONTY),
            GAME_KEY,
            game.note_hash.fr(),
            public_key(other),
            game.c[i].as_slice(),
        )
        .unwrap_err();
        assert_eq!(err.class, ErrorClass::BadRequest);
    }
    // The consumed seed record presented again, under a fresh id.
    let replayed = init_with(&mut net, player, Some(player));
    net.refused(
        "monty init on the consumed seed record",
        views(&replayed),
        ErrorClass::Conflict,
        "is already consumed; a retry of the consuming round uses FETCH",
    );

    // open_door: the door and its blinding as INPUT_SHARED envelopes.
    let chosen = (winning + 1) % 3;
    let open_door = |net: &mut Network, tamper: bool| {
        let mut req = request(
            MONTY,
            "monty_hall_open_door",
            net.id(),
            &[("in0_nonce", Fr::from(NONCE + 1))],
            &[GAME_KEY],
            &[GAME_KEY],
        );
        req.records = vec![game.clone()];
        req.requester = Some(point_to_wire(player_pk));
        net.seal_inputs(
            &mut req,
            &[
                ("door", Fr::from(chosen)),
                ("door_randomness", Fr::from(0x4242u64)),
            ],
            tamper,
        );
        sign_as(&mut req, player, player);
        req
    };
    // An envelope changed in transit, at every node: each node's no longer
    // hashes to its listed hash.
    let honest = open_door(&mut net, false);
    let mut changed = views(&honest);
    for view in changed.iter_mut() {
        view.shared_inputs[0].share.ct[0].0 += Fr::from(1u64);
    }
    net.refused(
        "monty open_door with a tampered envelope",
        changed,
        ErrorClass::BadRequest,
        "does not hash to share_hashes[",
    );
    // Node 1's pair of `door` is inconsistent with its neighbours': nodes 1
    // and 2, which share that summand, refuse at the handshake.
    let tampered = open_door(&mut net, true);
    net.refused_at(
        "monty open_door with an inconsistent sharing",
        views(&tampered),
        &[1, 2],
        ErrorClass::BadRequest,
        "session handshake: shared input `door` is not shared consistently",
    );
    let req = open_door(&mut net, false);
    let opened = net.execute(fx, "monty open_door", &req);
    // The game state open_door consumed, presented to finish: refused, naming
    // the consuming circuit (and never the consuming request).
    let mut stale = monty::finish(MONTY, net.id(), game);
    sign_as(&mut stale, player, player);
    let open_door_vk = net.nodes[0]
        .store
        .package(Fr::from(MONTY), "monty_hall_open_door")
        .unwrap()
        .unwrap()
        .vk_hash;
    net.refused(
        "monty finish on the state open_door consumed",
        views(&stale),
        ErrorClass::Conflict,
        &format!(
            "is already consumed by another circuit (vk_hash {});",
            fr_to_hex(open_door_vk),
        ),
    );
    let host_opened = small(opened.output("app_outputs[0]"));
    assert!(host_opened < 3 && host_opened != chosen && host_opened != winning);
    let [game] = &opened.records[..] else {
        panic!("one record")
    };
    let state = net.opened_record(MONTY, game, player_pk);
    assert_eq!(small(state[CHOSEN_DOOR]), chosen);
    assert_eq!(small(state[WINNING_DOOR]), winning);

    // finish: switch, and win (the chosen door was not the winning one).
    let mut finish = monty::finish(MONTY, net.id(), game);
    sign_as(&mut finish, player, player);
    let finished = net.execute(fx, "monty finish", &finish);
    assert_eq!(
        finished.output("app_outputs[0]"),
        Fr::from(1u64),
        "switching wins"
    );
    assert!(finished.records.is_empty() && finished.results[0].stored.is_empty());
    let fetched = net.fetch(fx, "monty fetch finish", &finish);
    assert_eq!(fetched.results, finished.results);
    // The finished game's state is consumed; it cannot be finished again.
    let mut again = finish.clone();
    again.request_id = net.id();
    sign_as(&mut again, player, player);
    net.refused(
        "monty finish twice",
        views(&again),
        ErrorClass::Conflict,
        "is already consumed",
    );
}

/// The client-held recovery of a round that cannot land (ARCHITECTURE.md
/// section 3, the rollback path; section 8, an unlandable client-held round):
/// open_door commits, the operator rolls it back on the three nodes, and the
/// owner presents the old game record to open_door again. Steps 7 (consumed)
/// and 8 (open) and the handshake accept it, and the round computes what the
/// rolled-back one did; the rolled-back request answers 409 to FETCH, to a
/// second rollback and to a replay of its body, and the record it created is
/// dead: a finish that presents it is refused at step 7 on every node.
#[test]
fn a_client_held_record_is_accepted_again_after_its_round_is_rolled_back() {
    let Some(fx) = fixture() else { return };
    let _serial = serial();
    let mut net = Network::new(fx, 8);
    let ns = Fr::from(MONTY);
    net.register(fx, MONTY, "monty-hall", &MONTY_CIRCUITS);
    let player = Fq::from(0x0052_011b_u64);
    let player_pk = public_key(player);

    let mut seed = monty::seed(MONTY, net.id());
    sign_as(&mut seed, player, player);
    let seed_record = net.execute(fx, "rollback: monty seed", &seed).records[0].clone();
    let mut init = request(
        MONTY,
        "monty_hall_init",
        net.id(),
        &[("in0_nonce", Fr::from(NONCE))],
        &[GAME_SEED_KEY],
        &[GAME_KEY],
    );
    init.records = vec![seed_record];
    sign_as(&mut init, player, player);
    let game = net.execute(fx, "rollback: monty init", &init).records[0].clone();
    let winning = small(net.opened_record(MONTY, &game, player_pk)[WINNING_DOOR]);
    let chosen = (winning + 1) % 3;
    let open_door = |net: &mut Network| {
        let mut req = request(
            MONTY,
            "monty_hall_open_door",
            net.id(),
            &[("in0_nonce", Fr::from(NONCE + 1))],
            &[GAME_KEY],
            &[GAME_KEY],
        );
        req.records = vec![game.clone()];
        req.requester = Some(point_to_wire(player_pk));
        net.seal_inputs(
            &mut req,
            &[
                ("door", Fr::from(chosen)),
                ("door_randomness", Fr::from(0x4244u64)),
            ],
            false,
        );
        sign_as(&mut req, player, player);
        req
    };

    let first = open_door(&mut net);
    let opened = net.execute(fx, "rollback: monty open_door", &first);
    let game_note = game.note_hash.fr();
    for node in &net.nodes {
        let row = node.store.consumed(ns, game_note).unwrap().unwrap();
        assert_eq!(row.request_id, first.request_id);
    }

    // The round cannot land: the operator rolls it back on the three nodes.
    // Its consumed entry goes, so the old record loads again.
    for node in &net.nodes {
        pipeline::restore(node, ns, first.request_id, &|_, _| Ok(None)).unwrap();
    }
    for (i, node) in net.nodes.iter().enumerate() {
        assert!(
            node.store.consumed(ns, game_note).unwrap().is_none(),
            "node {i}: the old record's consumed entry"
        );
        let status = node
            .store
            .request(ns, first.request_id)
            .unwrap()
            .unwrap()
            .status;
        assert_eq!(status, RequestStatus::RolledBack, "node {i}");
        let err = pipeline::fetch(node, ns, first.request_id).unwrap_err();
        assert_eq!(err.class, ErrorClass::Conflict, "node {i}: {err}");
        assert_eq!(err.status(), 409, "node {i}: {err}");
        let err = pipeline::restore(node, ns, first.request_id, &|_, _| Ok(None)).unwrap_err();
        assert_eq!(err.class, ErrorClass::Conflict, "node {i}: {err}");
    }
    net.refused(
        "rollback: replay of the rolled-back open_door",
        views(&first),
        ErrorClass::Conflict,
        "was rolled back",
    );

    // The record the rolled-back round created is dead on every node: a
    // finish that presents it is refused (400) before it is opened.
    let [abandoned] = &opened.records[..] else {
        panic!("one record")
    };
    for (i, node) in net.nodes.iter().enumerate() {
        let dead = node
            .store
            .dead_record(ns, abandoned.note_hash.fr())
            .unwrap()
            .map(|d| d.request_id);
        assert_eq!(dead, Some(first.request_id), "node {i}: the dead record");
    }
    let mut finish = monty::finish(MONTY, net.id(), abandoned);
    sign_as(&mut finish, player, player);
    net.refused(
        "rollback: monty finish on the rolled-back round's record",
        views(&finish),
        ErrorClass::BadRequest,
        "was created by a round that was rolled back",
    );

    // The owner presents the old record again, in a new request: the same
    // state and key, so the same leaf, nullifier and opened door.
    let second = open_door(&mut net);
    let reopened = net.execute(fx, "rollback: monty open_door again", &second);
    for path in ["read_leaves[0]", "nullifiers[0]", "app_outputs[0]"] {
        assert_eq!(reopened.output(path), opened.output(path), "{path}");
    }
    let [regame] = &reopened.records[..] else {
        panic!("one record")
    };
    let state = net.opened_record(MONTY, regame, player_pk);
    assert_eq!(small(state[CHOSEN_DOOR]), chosen);
    assert_eq!(small(state[WINNING_DOOR]), winning);
    for node in &net.nodes {
        let row = node.store.consumed(ns, game_note).unwrap().unwrap();
        assert_eq!(row.request_id, second.request_id);
    }
}

/// An enc rotation on all three nodes (ARCHITECTURE.md section 2, setup and
/// rotation). Within the grace window a record sealed under the previous keys
/// opens, envelopes sealed to the previous keys decrypt, and a round that
/// loads the record and stores the key again returns thirds under the new
/// keys. Once the previous keys are retired, a record sealed only under them
/// is refused (400, wrong key id), and so is an envelope to them, while the
/// re-sealed record still opens and plays on.
#[test]
fn an_enc_rotation_reseals_records_within_the_grace_window() {
    let Some(fx) = fixture() else { return };
    let _serial = serial();
    let mut net = Network::new(fx, 3);
    net.register(fx, MONTY, "monty-hall", &MONTY_CIRCUITS);
    let player = Fq::from(0x0071_7e12_u64);
    let player_pk = public_key(player);
    let key_ids =
        |net: &Network| -> Vec<[u8; 8]> { net.nodes.iter().map(|n| n.keys().key_id()).collect() };

    // Two seed records and a game, all sealed under the original keys.
    let seed = |net: &mut Network, label: &str| {
        let mut req = monty::seed(MONTY, net.id());
        sign_as(&mut req, player, player);
        net.execute(fx, label, &req).records[0].clone()
    };
    let kept_seed = seed(&mut net, "rotation seed kept");
    let game_seed = seed(&mut net, "rotation seed for the game");
    let mut init = request(
        MONTY,
        "monty_hall_init",
        net.id(),
        &[("in0_nonce", Fr::from(NONCE))],
        &[GAME_SEED_KEY],
        &[GAME_KEY],
    );
    init.records = vec![game_seed];
    sign_as(&mut init, player, player);
    let game = net.execute(fx, "rotation init", &init).records[0].clone();
    let winning = small(net.opened_record(MONTY, &game, player_pk)[WINNING_DOOR]);
    let old_ids = key_ids(&net);
    for (i, id) in old_ids.iter().enumerate() {
        assert_eq!(
            game.c[i].as_slice()[..8],
            id[..],
            "node {i}: sealed under the original key"
        );
    }

    // The operator rotates enc on all three nodes. The client still seals
    // envelopes to the enc keys it pinned before the rotation (`enc_pks`).
    for (i, node) in net.nodes.iter().enumerate() {
        let next = NodeKeys::generate(&mut rng(0x7e00 + i as u64)).enc_scalar();
        node.set_keys(node.keys().rotate_enc(next, 1_800_000_000).unwrap());
    }
    let new_ids = key_ids(&net);
    for i in 0..NODES {
        assert_ne!(new_ids[i], old_ids[i]);
        assert_eq!(net.nodes[i].keys().previous_key_id(), Some(old_ids[i]));
        assert_ne!(net.nodes[i].keys().enc_pk(), net.enc_pks[i]);
    }
    // Inside the window a record under the previous keys still opens.
    assert_eq!(net.opened_record(MONTY, &kept_seed, player_pk).len(), 2);

    let chosen = (winning + 1) % 3;
    let open_door = |net: &mut Network, game: &StateRecord, nonce: u64| {
        let mut req = request(
            MONTY,
            "monty_hall_open_door",
            net.id(),
            &[("in0_nonce", Fr::from(nonce))],
            &[GAME_KEY],
            &[GAME_KEY],
        );
        req.records = vec![game.clone()];
        req.requester = Some(point_to_wire(player_pk));
        net.seal_inputs(
            &mut req,
            &[
                ("door", Fr::from(chosen)),
                ("door_randomness", Fr::from(0x4243u64)),
            ],
            false,
        );
        sign_as(&mut req, player, player);
        req
    };

    // open_door inside the window: the game opens under the previous key id,
    // the envelopes to the previous enc keys decrypt under the previous
    // scalars, and the stored game comes back sealed under the new keys.
    let req = open_door(&mut net, &game, NONCE + 1);
    let opened = net.execute(fx, "open_door inside the grace window", &req);
    let [resealed] = &opened.records[..] else {
        panic!("one record")
    };
    for (i, id) in new_ids.iter().enumerate() {
        assert_eq!(
            resealed.c[i].as_slice()[..8],
            id[..],
            "node {i}: re-sealed under the new key"
        );
    }
    let state = net.opened_record(MONTY, resealed, player_pk);
    assert_eq!(small(state[CHOSEN_DOOR]), chosen);
    assert_eq!(small(state[WINNING_DOOR]), winning);

    // The window lapses: every node retires its previous key.
    for node in &net.nodes {
        node.set_keys(node.keys().as_ref().clone().retire_previous_enc());
    }
    for (i, node) in net.nodes.iter().enumerate() {
        let err = record::open(
            &node.keys(),
            Fr::from(MONTY),
            GAME_SEED_KEY,
            kept_seed.note_hash.fr(),
            player_pk,
            kept_seed.c[i].as_slice(),
        )
        .unwrap_err();
        assert_eq!(err.class, ErrorClass::BadRequest, "node {i}: {err}");
    }

    // A round on the record sealed only under the retired keys: 400, wrong
    // key id, at every node.
    let mut stale = request(
        MONTY,
        "monty_hall_init",
        net.id(),
        &[("in0_nonce", Fr::from(NONCE + 7))],
        &[GAME_SEED_KEY],
        &[GAME_KEY],
    );
    stale.records = vec![kept_seed.clone()];
    sign_as(&mut stale, player, player);
    net.refused(
        "init from a record under the retired keys",
        views(&stale),
        ErrorClass::BadRequest,
        "sealed under another node key",
    );

    // Envelopes to the retired keys no longer decrypt (the re-sealed game
    // itself opens; the refusal is the envelopes').
    let stale_envelopes = open_door(&mut net, resealed, NONCE + 2);
    net.refused(
        "envelopes to the retired keys",
        views(&stale_envelopes),
        ErrorClass::BadRequest,
        "does not decrypt",
    );

    // The client re-pins the new enc keys; the re-sealed game plays on.
    net.enc_pks = [0, 1, 2].map(|i| net.nodes[i].keys().enc_pk());
    let mut finish = monty::finish(MONTY, net.id(), resealed);
    sign_as(&mut finish, player, player);
    let finished = net.execute(fx, "finish the re-sealed game", &finish);
    assert_eq!(
        finished.output("app_outputs[0]"),
        Fr::from(1u64),
        "switching wins"
    );
}

/// A swap whose commit fails on nodes 1 and 2 while node 0 commits (step 15):
/// nodes 1 and 2 store nothing; the resend is answered by node 0 from its row
/// (step 5), whose handshake verdict names the replay, so nodes 1 and 2 refuse
/// it 400 at once instead of waiting on the mesh; and the next swap on the
/// pool, whose rows now differ at node 0, is refused 400 at the handshake on
/// all three nodes, naming the key, before any computation.
#[test]
fn a_commit_refused_on_two_nodes_is_refused_at_the_next_handshake() {
    let Some(fx) = fixture() else { return };
    let _serial = serial();
    let mut net = Network::new(fx, 5);
    net.register(fx, AMM, "amm", &AMM_CIRCUITS);
    let seed = amm::seed(AMM, net.id());
    net.execute(fx, "diverged: amm seed", &seed);
    let init = amm::init(AMM, net.id());
    net.execute(fx, "diverged: amm init", &init);

    // 15 commit: the stores of nodes 1 and 2 refuse the swap's commit.
    let swap = amm::swap(AMM, net.id(), 25000, 0);
    let before = net.snapshots();
    net.nodes[1].store.fail_next_commit();
    net.nodes[2].store.fail_next_commit();
    let results = net.run(views(&swap));
    let after = net.snapshots();
    let mut committed = None;
    for (i, result) in results.into_iter().enumerate() {
        match (i, result) {
            (0, result) => committed = Some(result.unwrap_or_else(|e| panic!("node 0: {e}"))),
            (i, Err(err)) => {
                eprintln!("REFUSED diverged commit: node {i}: {err}");
                assert_eq!(err.class, ErrorClass::MpcFailure, "{err}");
                assert_eq!(err.status(), 500);
                assert!(err.message.contains("store: "), "{err}");
            }
            (i, Ok(_)) => panic!("node {i} committed"),
        }
    }
    for i in [1, 2] {
        assert!(
            after[i] == before[i],
            "node {i} stored part of a refused commit"
        );
    }
    assert!(after[0] != before[0]);

    // The resend: node 0 answers from its row (step 5) and joins the session
    // with a verdict naming the replay; nodes 1 and 2, which lack the row,
    // pass steps 5 to 9 and refuse 400 at the handshake, naming node 0, at
    // once instead of waiting out the mesh connect timeout.
    let start = Instant::now();
    let results = net.run(views(&swap));
    let took = start.elapsed();
    eprintln!(
        "REFUSED diverged resend: {:.3}s on three nodes",
        took.as_secs_f64()
    );
    let relayed = "session handshake: node 0 refused the request: this node already holds \
                   request";
    for (i, result) in results.into_iter().enumerate() {
        match (i, result) {
            (0, result) => assert_eq!(result.unwrap(), committed.clone().unwrap()),
            (i, Err(err)) => {
                eprintln!("REFUSED diverged resend: node {i}: {err}");
                assert_eq!(err.class, ErrorClass::BadRequest, "{err}");
                assert_eq!(err.status(), 400);
                assert!(err.message.contains(relayed), "{err}");
            }
            (i, Ok(_)) => panic!("node {i} committed the resend without node 0"),
        }
    }
    assert!(took.as_secs_f64() < 1.0, "the resend took {took:?}");
    assert!(after == net.snapshots(), "the resend changed a table");

    // 10 session: the next swap loads the pool, which node 0 holds from after
    // the swap and nodes 1 and 2 from before it. Node 0 differs from both its
    // neighbours, so all three refuse at the handshake, naming the key.
    let next = amm::swap(AMM, net.id(), 10000, 1);
    let needles = [
        "session handshake: value `0xa002` element 0 is not shared consistently with the previous node",
        "session handshake: value `0xa002` element 0 is not shared consistently with the previous node",
        "session handshake: value `0xa002` element 0 is not shared consistently with the next node",
    ];
    let results = net.run(views(&next));
    for (i, result) in results.into_iter().enumerate() {
        let err = match result {
            Ok(_) => panic!("node {i} committed on a diverged pool"),
            Err(e) => e,
        };
        eprintln!("REFUSED diverged next swap: node {i}: {err}");
        assert_eq!(err.class, ErrorClass::BadRequest, "node {i}: {err}");
        assert_eq!(err.status(), 400, "node {i}: {err}");
        assert!(
            err.message.contains(needles[i]),
            "node {i}: `{}` lacks `{}`",
            err.message,
            needles[i]
        );
    }
    assert!(
        after == net.snapshots(),
        "a request refused at the handshake changed a table"
    );
}

/// A DISABLE whose commit fails on node 2 while nodes 0 and 1 commit it: the
/// registries diverge. The next request naming the circuit is refused at
/// step 3 by nodes 0 and 1, which join the session's handshake with that
/// refusal as their verdict, so node 2, which still holds the circuit enabled
/// and reaches the handshake, refuses 400 at once naming the disabled circuit
/// instead of waiting out the mesh connect timeout. Resending the signed
/// DISABLE repairs the divergence: nodes 0 and 1 answer it unchanged, node 2
/// commits it, and the next request is refused at step 3 on all three.
#[test]
fn a_disable_one_node_did_not_commit_is_refused_at_the_handshake() {
    let Some(fx) = fixture() else { return };
    let _serial = serial();
    let mut net = Network::new(fx, 8);
    net.register(fx, AMM, "amm", &AMM_CIRCUITS);
    let disabled = "`pss_seed` is disabled under namespace";

    // DISABLE pss_seed (seq 1); node 2's store refuses the commit.
    let body = net.signed_disable(AMM, "pss_seed", 1);
    let before = net.snapshots();
    net.nodes[2].store.fail_next_commit();
    let answers = net.disable_each(&body);
    let mut committed = Vec::new();
    for (i, answer) in answers.into_iter().enumerate() {
        match (i, answer) {
            (2, Err(err)) => {
                eprintln!("REFUSED diverged DISABLE: node 2: {err}");
                assert_eq!(err.class, ErrorClass::MpcFailure, "{err}");
                assert!(err.message.contains("store: "), "{err}");
            }
            (2, Ok(_)) => panic!("node 2 committed the DISABLE"),
            (i, answer) => {
                committed.push(answer.unwrap_or_else(|e| panic!("node {i}: {e}")));
            }
        }
    }
    let diverged = net.snapshots();
    assert!(
        diverged[2] == before[2],
        "node 2 stored part of the DISABLE"
    );
    assert!(diverged[0] != before[0] && diverged[1] != before[1]);

    // The operator's registry check (`sidecar-node sync-registry --check`)
    // names the rows that diverged, the same at all three nodes, and writes
    // nothing.
    let pkg_row = "package `pss_seed`: node 0 and node 1 hold seq 1, disabled, vk_hash ";
    for (i, check) in net
        .check_registry(Some(Fr::from(AMM)))
        .into_iter()
        .enumerate()
    {
        let check = check.unwrap_or_else(|e| panic!("registry check: node {i}: {e}"));
        let text: Vec<String> = check.divergences.iter().map(ToString::to_string).collect();
        eprintln!("REGISTRY CHECK node {i}: {text:#?}");
        assert_eq!((check.namespaces, check.packages), (1, 3));
        assert_eq!(text.len(), 2, "node {i}: {text:#?}");
        assert!(
            text[0].contains("the namespace row: node 0 and node 1 hold seq 1, ")
                && text[0].contains("; node 2 holds seq 0, "),
            "node {i}: {}",
            text[0]
        );
        assert!(
            text[1].contains(pkg_row) && text[1].contains("; node 2 holds seq 0, enabled, "),
            "node {i}: {}",
            text[1]
        );
    }
    assert!(
        net.snapshots() == diverged,
        "the registry check wrote a row"
    );

    // 3 resolve: nodes 0 and 1 refuse the circuit as disabled and send that as
    // their handshake verdict; node 2 passes steps 3 to 9 and refuses at the
    // handshake, naming a node that refused and why, at once.
    let seed = amm::seed(AMM, net.id());
    let took = net.refused_each(
        "a seed after a DISABLE node 2 did not commit",
        views(&seed),
        [
            (ErrorClass::BadRequest, &[disabled]),
            (ErrorClass::BadRequest, &[disabled]),
            (
                ErrorClass::BadRequest,
                &[
                    "session handshake: node ",
                    " refused the request: ",
                    disabled,
                ],
            ),
        ],
    );
    assert!(took.as_secs_f64() < 1.0, "the refusal took {took:?}");

    // The resend: nodes 0 and 1 answer it as they did, node 2 commits it.
    let answers = net.disable_each(&body);
    for (i, answer) in answers.into_iter().enumerate() {
        let answer = answer.unwrap_or_else(|e| panic!("resent DISABLE: node {i}: {e}"));
        if i < 2 {
            assert_eq!(answer, committed[i], "node {i} answered the resend anew");
        }
    }
    let repaired = net.snapshots();
    assert!(repaired[0] == diverged[0] && repaired[1] == diverged[1]);
    assert!(
        repaired[2] != diverged[2],
        "node 2 did not commit the resend"
    );
    net.refused(
        "a seed after the resent DISABLE",
        views(&seed),
        ErrorClass::BadRequest,
        disabled,
    );
    for (i, check) in net.check_registry(None).into_iter().enumerate() {
        let check = check.unwrap_or_else(|e| panic!("registry check: node {i}: {e}"));
        assert_eq!((check.namespaces, check.packages), (1, 3));
        assert!(
            check.divergences.is_empty(),
            "node {i}: {:?}",
            check.divergences
        );
    }
}

/// A request one node's own admit hook refuses at step 2 (here a quota the
/// other two and the orchestrator do not apply) joins the session with that
/// refusal as its verdict: that node answers its own refusal (403) and the
/// other two refuse 400 at the handshake naming it, at once, instead of
/// waiting out the mesh connect timeout. Nothing is stored.
#[test]
fn an_admit_refusal_at_one_node_is_refused_at_the_handshake() {
    let Some(fx) = fixture() else { return };
    let _serial = serial();
    let mut net = Network::new(fx, 12);
    net.register(fx, AMM, "amm", &AMM_CIRCUITS[..1]);
    let quota = "node 2's quota for this requester is spent";
    net.with_admit(2, Box::new(move |_| Err(Refusal::forbidden(quota))));

    // A signed seed, which passes steps 3 to 9 at nodes 0 and 1.
    let mut seed = amm::seed(AMM, net.id());
    let player = Fq::from(0x5eed_u64);
    sign_as(&mut seed, player, player);
    pipeline::stateless_prefix(&seed, &net.nodes[0].store)
        .expect("the orchestrator's prefix (the default admit) passes the seed");
    let took = net.refused_each(
        "a seed node 2's admit hook refuses",
        views(&seed),
        [
            (
                ErrorClass::BadRequest,
                &["session handshake: node 2 refused the request: ", quota],
            ),
            (
                ErrorClass::BadRequest,
                &["session handshake: node 2 refused the request: ", quota],
            ),
            (ErrorClass::Forbidden, &[quota]),
        ],
    );
    assert!(took.as_secs_f64() < 1.0, "the refusal took {took:?}");
}

/// A first REGISTER (seq 0) that one node refuses at its own checks (section
/// 4 step 2), before any session, is refused at the handshake by the other two
/// (400, before the registration circuit), and no node stores anything: once
/// for a copy of the body that names another owner at node 2, once for the
/// same body everywhere with node 2's store holding the namespace under
/// another owner.
#[test]
fn a_first_register_one_node_refuses_is_refused_at_the_handshake() {
    let Some(fx) = fixture() else { return };
    let _serial = serial();
    let mut net = Network::new(fx, 6);
    let other = monty::other();
    let check = |label: &str,
                 answers: Vec<Result<ManifestAnswer, Refusal>>,
                 needles: [(ErrorClass, &str); NODES]| {
        for (i, (answer, (class, needle))) in answers.into_iter().zip(needles).enumerate() {
            let err = match answer {
                Ok(_) => panic!("{label}: node {i} registered"),
                Err(e) => e,
            };
            eprintln!("REFUSED {label}: node {i}: {err}");
            assert_eq!(err.class, class, "{label}: node {i}: {err}");
            assert!(
                err.message.contains(needle),
                "{label}: node {i}: `{}` lacks `{needle}`",
                err.message
            );
        }
    };

    // Node 2's copy names another owner: its signature does not verify there
    // (403); nodes 0 and 1 see its other body hash at the handshake.
    let body = net.signed_register(fx, AMM, "amm", &["pss_seed"], owner_secret());
    let mut copy = body.body.clone();
    copy.owner_pubkey = point_to_wire(public_key(other));
    let copy = Signed::new(copy).unwrap();
    let before = net.snapshots();
    let answers = net.register_each([&body, &body, &copy]);
    check(
        "register: another owner in node 2's copy",
        answers,
        [
            (
                ErrorClass::BadRequest,
                "session handshake: the previous node's body hash differs",
            ),
            (
                ErrorClass::BadRequest,
                "session handshake: the next node's body hash differs",
            ),
            (
                ErrorClass::Forbidden,
                "the REGISTER signature does not verify",
            ),
        ],
    );
    assert!(
        before == net.snapshots(),
        "a refused REGISTER changed a table"
    );

    // The same body everywhere, but node 2 already holds the namespace under
    // another owner: node 2 refuses at step 2 (403) and says so in its
    // verdict, so nodes 0 and 1 refuse at the handshake (400).
    let ns = Fr::from(MONTY);
    let store = &net.nodes[2].store;
    let mut txn = store.begin(ns);
    txn.register_namespace(NamespaceRow {
        owner_pubkey: public_key(other),
        nsk_app: Share::new(Fr::from(5u64), Fr::from(6u64)),
        npk_app_hash: Fr::from(7u64),
        seq: 0,
    });
    store.commit(txn).unwrap();
    let body = net.signed_register(fx, MONTY, "monty-hall", &["pss_seed"], owner_secret());
    let before = net.snapshots();
    let answers = net.register_each([&body, &body, &body]);
    check(
        "register: node 2 holds the namespace under another owner",
        answers,
        [
            (
                ErrorClass::BadRequest,
                "session handshake: node 2 refused the request: `owner_pubkey` is not the owner",
            ),
            (
                ErrorClass::BadRequest,
                "session handshake: node 2 refused the request: `owner_pubkey` is not the owner",
            ),
            (
                ErrorClass::Forbidden,
                "`owner_pubkey` is not the owner of namespace",
            ),
        ],
    );
    assert!(
        before == net.snapshots(),
        "a refused REGISTER changed a table"
    );
    for node in &net.nodes[..2] {
        assert!(node.store.namespace(ns).unwrap().is_none());
        assert!(node.store.namespace(Fr::from(AMM)).unwrap().is_none());
    }

    // Nothing is left half-done: the first REGISTER then runs on all three.
    net.register(fx, AMM, "amm", &AMM_CIRCUITS[..1]);
}

/// An inconsistent INPUT_SHARED sharing that only two nodes can see is
/// refused at all three, through the verdict round.
#[test]
fn an_inconsistent_sharing_is_refused_at_all_three_nodes() {
    let Some(fx) = fixture() else { return };
    let _serial = serial();
    let mut net = Network::new(fx, 4);
    net.register(fx, MONTY, "monty-hall", &MONTY_CIRCUITS[..3]);
    let player = monty::player();
    let mut seed = monty::seed(MONTY, net.id());
    sign_as(&mut seed, player, player);
    let seeded = net.execute(fx, "verdict: monty seed", &seed);
    let mut init = request(
        MONTY,
        "monty_hall_init",
        net.id(),
        &[("in0_nonce", Fr::from(NONCE))],
        &[GAME_SEED_KEY],
        &[GAME_KEY],
    );
    init.records = seeded.records.clone();
    sign_as(&mut init, player, player);
    let inited = net.execute(fx, "verdict: monty init", &init);

    // open_door with node 1's pair of `door` inconsistent: node 1's x_1 is
    // not node 2's copy of it, so their summand hashes differ. Node 0 holds
    // neither copy of x_1 and its own checks pass; the verdict round makes it
    // refuse with them, at step 10, before witness extension.
    let mut req = request(
        MONTY,
        "monty_hall_open_door",
        net.id(),
        &[("in0_nonce", Fr::from(NONCE + 1))],
        &[GAME_KEY],
        &[GAME_KEY],
    );
    req.records = inited.records.clone();
    req.requester = Some(point_to_wire(public_key(player)));
    net.seal_inputs(
        &mut req,
        &[
            ("door", Fr::from(1u64)),
            ("door_randomness", Fr::from(0x4242u64)),
        ],
        true,
    );
    sign_as(&mut req, player, player);
    let before = net.snapshots();
    let results = net.run(views(&req));
    let needles = [
        "session handshake: node 2 refused the request: shared input `door` is not shared \
         consistently with the previous node",
        "session handshake: shared input `door` is not shared consistently with the next node",
        "session handshake: shared input `door` is not shared consistently with the previous node",
    ];
    for (i, result) in results.into_iter().enumerate() {
        let err = match result {
            Ok(_) => panic!("node {i} committed"),
            Err(e) => e,
        };
        eprintln!("REFUSED verdict: node {i}: {err}");
        assert_eq!(err.class, ErrorClass::BadRequest, "node {i}: {err}");
        assert_eq!(err.status(), 400, "node {i}: {err}");
        assert!(
            err.message.contains(needles[i]),
            "node {i}: `{}` lacks `{}`",
            err.message,
            needles[i]
        );
    }
    assert!(
        before == net.snapshots(),
        "a request refused at the handshake changed a table"
    );
}

/// One refused request per step, each leaving every table of every node
/// unchanged; and requests one node alone refuses before the session (steps
/// 6 and 8), which the other two refuse at the handshake, naming it.
#[test]
fn every_step_refuses_and_changes_nothing() {
    let Some(fx) = fixture() else { return };
    let _serial = serial();
    let mut net = Network::new(fx, 3);
    // The AMM circuits and a copy of amm_swap under another name, disabled
    // below.
    let mut renamed = manifest("amm", "amm_swap");
    renamed["circuit"] = "amm_swap_v0".into();
    let mut amm_packages: Vec<TestPackage> = AMM_CIRCUITS
        .iter()
        .map(|c| TestPackage::new(c, manifest("amm", c)))
        .collect();
    amm_packages.push(TestPackage::on("amm_swap_v0", "amm_swap", renamed));
    let mut body = Network::manifest_message(fx, AMM, "amm", &amm_packages, None, 0);
    net.register_body(&mut body, &mut None);
    net.register(fx, MONTY, "monty-hall", &MONTY_CIRCUITS);
    net.disable(AMM, "amm_swap_v0", 1);

    let seed = amm::seed(AMM, net.id());
    net.execute(fx, "refusals: amm seed", &seed);
    let init = amm::init(AMM, net.id());
    net.execute(fx, "refusals: amm init", &init);
    let player = monty::player();
    let other = monty::other();
    let mut game_seed = monty::seed(MONTY, net.id());
    sign_as(&mut game_seed, player, player);
    let seeded = net.execute(fx, "refusals: monty seed", &game_seed);
    let seed_record = seeded.records[0].clone();
    let game_init = |net: &mut Network, requester: Fq, signer: Fq| {
        let mut init = monty::init(MONTY, net.id(), &seed_record);
        sign_as(&mut init, requester, signer);
        init
    };

    // 1 parse: a key listed twice.
    let mut dup = amm::swap(AMM, net.id(), 100, 0);
    dup.state_keys.reads = vec![POOL_KEY.into(), POOL_KEY.into()];
    net.refused(
        "parse: a duplicated key",
        views(&dup),
        ErrorClass::BadRequest,
        "is listed twice",
    );

    // 3 resolve: unknown, another namespace's, disabled.
    let mut unknown = amm::swap(AMM, net.id(), 100, 0);
    unknown.circuit = "amm_nope".into();
    net.refused(
        "resolve: an unknown circuit",
        views(&unknown),
        ErrorClass::BadRequest,
        "`amm_nope` is not registered",
    );
    let foreign = request(
        AMM,
        "monty_hall_init",
        net.id(),
        &[("in0_nonce", Fr::from(NONCE))],
        &[POOL_KEY],
        &[GAME_KEY],
    );
    net.refused(
        "resolve: another namespace's circuit",
        views(&foreign),
        ErrorClass::BadRequest,
        "`monty_hall_init` is not registered under namespace",
    );
    let mut disabled = amm::swap(AMM, net.id(), 100, 0);
    disabled.circuit = "amm_swap_v0".into();
    net.refused(
        "resolve: a disabled circuit",
        views(&disabled),
        ErrorClass::BadRequest,
        "`amm_swap_v0` is disabled",
    );

    // 4 authenticate: a missing requester, a signature by another key.
    let mut anonymous = game_init(&mut net, player, player);
    anonymous.requester = None;
    net.refused(
        "authenticate: a missing requester",
        views(&anonymous),
        ErrorClass::BadRequest,
        "field `requester`: missing",
    );
    let forged = game_init(&mut net, player, other);
    net.refused(
        "authenticate: a bad requester signature",
        views(&forged),
        ErrorClass::Forbidden,
        "does not verify under `requester`",
    );

    // 5 replay: a used id with another body.
    let reused = amm::swap(AMM, init.request_id, 100, 0);
    net.refused(
        "replay: a reused id with another body",
        views(&reused),
        ErrorClass::Conflict,
        "with another body",
    );

    // 6 own ciphertexts: each node gets the next node's third.
    let honest = game_init(&mut net, player, player);
    let mut rotated = views(&honest);
    for (i, view) in rotated.iter_mut().enumerate() {
        view.records[0].c_i = seed_record.c[(i + 1) % NODES].clone();
    }
    net.refused(
        "own ciphertexts: a third for the wrong node",
        rotated,
        ErrorClass::BadRequest,
        "does not hash to record_hashes",
    );

    // 6 own ciphertexts at one node only: node 2 receives node 0's third.
    // Node 2 refuses at step 6 and still joins the session with its refusal
    // as its verdict; nodes 0 and 1, which passed steps 5 to 9, refuse at the
    // handshake naming node 2, within a second, instead of waiting out the
    // mesh connect timeout. Nothing is stored anywhere.
    let honest = game_init(&mut net, player, player);
    let mut one_off = views(&honest);
    one_off[2].records[0].c_i = seed_record.c[0].clone();
    let relayed: &[&str] = &[
        "session handshake: node 2 refused the request: ",
        "does not hash to record_hashes",
    ];
    let took = net.refused_each(
        "own ciphertexts: a wrong third at node 2 only",
        one_off,
        [
            (ErrorClass::BadRequest, relayed),
            (ErrorClass::BadRequest, relayed),
            (ErrorClass::BadRequest, &["does not hash to record_hashes"]),
        ],
    );
    assert!(took.as_secs_f64() < 1.0, "the three answers took {took:?}");

    // 8 open at one node only: the client replaces node 2's third with bytes
    // of its own and lists their hash, so step 6 passes everywhere (and at
    // the orchestrator, which checks the three hashes) and node 2 alone
    // refuses at step 8; the other two refuse at the handshake.
    let mut forged = game_init(&mut net, player, player);
    forged.records[0].c[2] = seed_record.c[0].clone();
    forged.records[0].record_hashes[2] =
        FieldHex(record_hash(seed_record.c[0].as_slice()).unwrap());
    sign_as(&mut forged, player, player);
    forged.check_ciphertext_hashes().unwrap();
    let relayed: &[&str] = &[
        "session handshake: node 2 refused the request: ",
        "was sealed under another node key",
    ];
    let took = net.refused_each(
        "open: a replaced third at node 2 only",
        views(&forged),
        [
            (ErrorClass::BadRequest, relayed),
            (ErrorClass::BadRequest, relayed),
            (
                ErrorClass::BadRequest,
                &["was sealed under another node key"],
            ),
        ],
    );
    assert!(took.as_secs_f64() < 1.0, "the three answers took {took:?}");

    // 7 consumed: a second init on the consumed seed.
    let again = request(
        AMM,
        "amm_init",
        net.id(),
        &[("in0_nonce", Fr::from(NONCE))],
        &[SEED_KEY],
        &["0xa003"],
    );
    net.refused(
        "consumed: a consumed state",
        views(&again),
        ErrorClass::Conflict,
        "is already consumed",
    );

    // 8 open: a record presented under another namespace, whose
    // monty_hall_init it was not sealed for. The AMM namespace's contract
    // manifest is replaced (the sidecar path) by one that also holds
    // monty_hall_init and the two copies of pss_seed of step 12, whose
    // manifests name the wrong output.
    let seed_copy = |name: &str, edit: &dyn Fn(&mut Value)| {
        let mut m = manifest("amm", "pss_seed");
        m["circuit"] = name.into();
        edit(&mut m);
        TestPackage::on(name, "pss_seed", m)
    };
    amm_packages.extend([
        TestPackage::new("monty_hall_init", manifest("monty-hall", "monty_hall_init")),
        seed_copy("pss_seed_fixed", &|m| {
            m["outputs"][0]["note_hash"] = "npk_app_hash".into()
        }),
        seed_copy("pss_seed_misnamed", &|m| {
            m["outputs"][0]["TACEO_store"] = "out9".into()
        }),
    ]);
    let mut replaced = Network::manifest_message(fx, AMM, "amm", &amm_packages, None, 2);
    net.register_body(&mut replaced, &mut None);
    for name in ["pss_seed_fixed", "pss_seed_misnamed"] {
        net.aliases.insert(name.into(), "pss_seed".into());
    }
    let mut elsewhere = game_init(&mut net, player, player);
    elsewhere.namespace = FieldHex(Fr::from(AMM));
    sign_as(&mut elsewhere, player, player);
    net.refused(
        "open: a record under another namespace",
        views(&elsewhere),
        ErrorClass::BadRequest,
        "record does not open",
    );
    // 8 open: a record presented by another owner.
    let stolen = game_init(&mut net, other, other);
    net.refused(
        "open: a record for another owner",
        views(&stolen),
        ErrorClass::BadRequest,
        "record does not open",
    );
    // 8 open: a client-held read with no record supplied.
    let mut bare = game_init(&mut net, player, player);
    bare.records.clear();
    sign_as(&mut bare, player, player);
    net.refused(
        "open: a missing record",
        views(&bare),
        ErrorClass::Conflict,
        "no state record for $state_keys.reads[0] = `0xff01`",
    );
    // 8 open: a record for a key no client-held read opens.
    let mut stray = game_init(&mut net, player, player);
    let mut unread = seed_record.clone();
    unread.key = "0xff09".into();
    stray.records.push(unread);
    sign_as(&mut stray, player, player);
    net.refused(
        "open: a record no read opens",
        views(&stray),
        ErrorClass::BadRequest,
        "loads no client-held key `0xff09`",
    );

    // 9 bind: an out-of-range public value (direction is a bool).
    let wide = amm::swap(AMM, net.id(), 100, 2);
    net.refused(
        "bind: an out-of-range public value",
        views(&wide),
        ErrorClass::BadRequest,
        "does not fit in 1 bit(s)",
    );
    // 9 bind: amm_init loads a seed of two elements; the pool has three.
    let long = request(
        AMM,
        "amm_init",
        net.id(),
        &[("in0_nonce", Fr::from(NONCE))],
        &[POOL_KEY],
        &["0xa00d"],
    );
    net.refused(
        "bind: a stored vector of another length",
        views(&long),
        ErrorClass::Conflict,
        "the stored value has 3 element(s), the manifest expects 2",
    );

    // 10 session: node 1 runs another body under the same id.
    let swap = amm::swap(AMM, net.id(), 100, 0);
    let mut split = views(&swap);
    split[1].public.insert(
        "amount_in".into(),
        PublicValue::One(FieldHex(Fr::from(101u64))),
    );
    net.refused(
        "session: a handshake mismatch",
        split,
        ErrorClass::BadRequest,
        "body hash differs",
    );

    // 11 execute and verify: a swap the circuit rejects.
    let zero = amm::swap(AMM, net.id(), 0, 0);
    net.refused(
        "execute: an unsatisfiable witness",
        views(&zero),
        ErrorClass::Unsatisfied,
        "does not verify",
    );

    // 12 outputs: pss_seed onto the pool, which it did not load.
    let clobber = request(AMM, "pss_seed", net.id(), &[], &[], &[POOL_KEY]);
    net.refused(
        "outputs: the write rule",
        views(&clobber),
        ErrorClass::Conflict,
        "key occupied and not loaded",
    );

    // 12 outputs: a re-stored consumed note hash. pss_seed registered with a
    // manifest that names its npk_app_hash output (0 for a seed) as the note
    // hash (`pss_seed_fixed`, registered at step 8) makes every seed it
    // stores have note hash 0; once amm_init has consumed one, the next seed
    // re-stores a consumed state.
    let fixed = request(AMM, "pss_seed_fixed", net.id(), &[], &[], &["0xa00a"]);
    let first = net.execute(fx, "refusals: a seed with note hash 0", &fixed);
    assert_eq!(first.output("npk_app_hash"), Fr::from(0u64));
    let spend = request(
        AMM,
        "amm_init",
        net.id(),
        &[("in0_nonce", Fr::from(NONCE))],
        &["0xa00a"],
        &["0xa00b"],
    );
    net.execute(fx, "refusals: amm init consumes note hash 0", &spend);
    let again = request(AMM, "pss_seed_fixed", net.id(), &[], &[], &["0xa00c"]);
    net.refused(
        "outputs: a re-stored consumed note hash",
        views(&again),
        ErrorClass::Conflict,
        "key `0xa00c`: the round stores a consumed state",
    );

    // 12 outputs: the circuit stores `out0`, which this manifest calls `out9`.
    let misnamed = request(AMM, "pss_seed_misnamed", net.id(), &[], &[], &["0xa00e"]);
    net.refused(
        "outputs: an output the manifest does not name",
        views(&misnamed),
        ErrorClass::MpcFailure,
        "the circuit stored `out0`, which the manifest does not name",
    );
}
