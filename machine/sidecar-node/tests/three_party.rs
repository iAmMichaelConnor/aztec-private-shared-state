//! Three nodes in one process on the deployment store backends, each behind
//! its own HTTPS API with mutual TLS and its own admin socket, over the real
//! pinned-TLS mesh on loopback, with real MPC proofs. The AMM and Monty Hall
//! sequences run in full on sidecar-core's in-process harness
//! (`tests/lifecycle.rs`) and across the orchestrator and the nodes
//! (sidecar-orchestrator's `tests/end_to_end.rs`); here each backend runs the
//! rounds that write its tables, and the operator's pruning.
//!
//! `postgres_backend` runs on three PostgresStores (one schema per node on
//! one server): Monty Hall's seed and init (a client-held record created,
//! then consumed), FETCH of both, the consumed record presented again and
//! refused with every table of every node unchanged; two namespaces'
//! requests at once, the second waiting on the mesh lock; and pruning past
//! the retention window. `local_store_backend` runs the same Monty Hall
//! rounds on three LocalStores, refuses the REGISTER of the AMM's node-held
//! manifests there, and prunes through the admin socket.
//!
//! Needs `scripts/prepare-data.sh` (the circuits of examples/amm and
//! examples/monty-hall and the CRS under machine/data, or DATA_DIR; a test
//! fails naming what is missing) and, for the Postgres test, docker or
//! `SIDECAR_TEST_POSTGRES_URL` (without either it prints why and passes).
//! Run with `--release`.

mod common;

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use common::net::*;
use common::*;
use sha2::{Digest, Sha256};
use sidecar_core::ErrorClass;
use sidecar_core::field::Fr;
use sidecar_core::pipeline::unix_now;
use sidecar_core::request::{NODES, Request, StateRecord};
use sidecar_core::schnorr::public_key;
use sidecar_core::store::{DEFAULT_REQUESTS_RETENTION_SECS, RequestStatus, Store, StoreRead};
use sidecar_node::admin::AdminRequest;
use sidecar_node::local::{LOG_FILE, LocalStore};
use sidecar_node::postgres::PostgresStore;
use sidecar_test_fixtures::postgres::{block, postgres_server};
use sqlx::postgres::{PgConnectOptions, PgConnection};
use sqlx::{Connection, Row};

const AMM: u64 = 0xc0ffee;
const MONTY: u64 = 0x6a3e;

/// The circuits of both networks: Monty Hall's seed and init, which run on
/// each backend, and the AMM's, registered on Postgres and refused on the
/// local store.
const CIRCUITS: [&str; 4] = ["pss_seed", "amm_init", "amm_swap", "monty_hall_init"];

// The two networks share nothing (their own stores, key directories, ports
// and admin sockets), so the tests run in parallel. With PSS_SERIAL_ROUNDS=1
// (sidecar-core's `testing::serial_rounds`) they take this lock in turn, one
// network at a time, so the TIMING lines are those of an unloaded machine.
// An async lock, so a test holds it across its awaits; it is not poisoned by
// a failing test.
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Hold while a test runs its network: the lock with PSS_SERIAL_ROUNDS=1,
/// else nothing.
async fn serial() -> Option<tokio::sync::MutexGuard<'static, ()>> {
    if sidecar_core::testing::serial_rounds() {
        Some(SERIAL.lock().await)
    } else {
        None
    }
}

/// Every table of a node, as the migration names them.
const TABLES: [&str; 10] = [
    "namespaces",
    "packages",
    "consumed",
    "requests",
    "values",
    "tip_versions",
    "tip_nodes",
    "tip_blobs",
    "receipts",
    "dead_records",
];

/// A node's tables: each table's row count and the MD5 of its rows'
/// text, in order.
fn pg_dump(options: &PgConnectOptions) -> Dump {
    block(async {
        let mut c = PgConnection::connect_with(options).await.unwrap();
        let mut out = Vec::new();
        for table in TABLES {
            let row = sqlx::query(&format!(
                "SELECT count(*)::text || ' rows, ' || \
                 coalesce(md5(string_agg(t::text, E'\\n' ORDER BY t::text)), '') \
                 FROM \"{table}\" t"
            ))
            .fetch_one(&mut c)
            .await
            .unwrap();
            out.push((table.to_string(), row.get::<String, _>(0)));
        }
        let _ = c.close().await;
        out
    })
}

/// A local store's tables: its log, every committed transaction in order.
fn local_dump(dir: &std::path::Path) -> Dump {
    let bytes = std::fs::read(dir.join(LOG_FILE)).unwrap();
    let digest: String = Sha256::digest(&bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    vec![(LOG_FILE.into(), format!("{} bytes, {digest}", bytes.len()))]
}

/// The one record of a round, checked against the round's output.
fn only_record(round: &Round, key: &str) -> StateRecord {
    let [record] = &round.records[..] else {
        panic!("{} records, not one", round.records.len())
    };
    assert_eq!(record.key, key);
    assert_eq!(record.note_hash.fr(), round.output("new_note_hashes[0]"));
    record.clone()
}

/// What Monty Hall's first rounds leave for the later cases.
struct Game {
    seed: Request,
    seed_record: StateRecord,
    init: Request,
}

/// Monty Hall's seed and init on the backend: the seed creates a record for
/// the player (nothing of the game lives in `values`), init consumes it,
/// FETCH answers both rounds as they committed, and the seed record presented
/// again is refused naming init, with every table of every node unchanged.
async fn monty_rounds<S: Store>(net: &mut Net<S>, label: &str) -> Game {
    let player = monty::player();
    let player_pk = public_key(player);
    let npk_app_hash = net
        .register_all(MONTY, monty::EXAMPLE, &monty::CIRCUITS[..2])
        .await;

    let mut seed = monty::seed(MONTY, net.id());
    sign_as(&mut seed, player, player);
    let before = net.dump();
    let seeded = net.execute(&format!("{label}: seed"), &seed).await;
    // A committed round changes the dumps, so the refusal's comparison of
    // them is not vacuous.
    if before.is_some() {
        assert_ne!(before, net.dump(), "{label}: the seed changed no table");
    }
    let seed_record = only_record(&seeded, monty::GAME_SEED_KEY);
    assert_eq!(net.opened_record(MONTY, &seed_record, player_pk).len(), 2);
    for node in &net.nodes {
        let store = &node.app.node.store;
        assert!(
            store
                .value(Fr::from(MONTY), monty::GAME_SEED_KEY)
                .unwrap()
                .is_none(),
            "{label}: nothing of the game lives in `values`"
        );
    }

    let mut init = monty::init(MONTY, net.id(), &seed_record);
    sign_as(&mut init, player, player);
    let inited = net.execute(&format!("{label}: init"), &init).await;
    assert_eq!(inited.output("npk_app_hash"), npk_app_hash);
    let game = only_record(&inited, monty::GAME_KEY);
    assert_eq!(
        net.opened_record(MONTY, &game, player_pk).len(),
        monty::STATE_LEN
    );
    for (req, round) in [(&seed, &seeded), (&init, &inited)] {
        let fetched = net
            .fetch_checked(&format!("{label}: fetch {}", req.circuit), req)
            .await;
        assert_eq!(fetched.results, round.results);
        assert_eq!(fetched.records, round.records);
    }

    let mut replayed = monty::init(MONTY, net.id(), &seed_record);
    sign_as(&mut replayed, player, player);
    net.refused(
        &format!("{label}: the consumed seed record again"),
        &replayed,
        ErrorClass::Conflict,
        &format!(
            "state {} is already consumed; a retry",
            seed_record.note_hash
        ),
    )
    .await;
    Game {
        seed,
        seed_record,
        init,
    }
}

/// After the `requests` rows are pruned: FETCH answers 404, and a resent
/// body is a new request that the consumed set still refuses (409), with no
/// table changed.
async fn after_pruning<S: Store>(
    net: &Net<S>,
    label: &str,
    fetch: &[&Request],
    resend: &[&Request],
) {
    for req in fetch {
        net.fetch_refused(
            &format!("{label}: pruned {}", req.circuit),
            req,
            ErrorClass::NotFound,
        )
        .await;
    }
    for req in resend {
        net.refused(
            &format!("{label}: {} resent after pruning", req.circuit),
            req,
            ErrorClass::Conflict,
            "is already consumed",
        )
        .await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn postgres_backend() {
    let crs = require_crs(&CIRCUITS);
    let Some(mut server) = postgres_server("three-party") else {
        return;
    };
    let _serial = serial().await;
    let started = Instant::now();
    let options: [PgConnectOptions; NODES] = [0, 1, 2].map(|_| server.fresh());
    let stores = options
        .clone()
        .map(|o| PostgresStore::connect_with(o, 4).unwrap());
    let tables: Tables = Some(Box::new(move |i| pg_dump(&options[i])));
    let mut net = start_net(TempDir::new("pg3"), crs, &CIRCUITS, stores, tables, |_| {}).await;
    eprintln!(
        "postgres: three nodes up in {:.1} s",
        started.elapsed().as_secs_f64()
    );

    let t = Instant::now();
    let game = monty_rounds(&mut net, "postgres").await;
    eprintln!(
        "TIMING postgres: Monty Hall rounds {:.1} s",
        t.elapsed().as_secs_f64()
    );

    let t = Instant::now();
    two_namespaces_at_once(&mut net, &game).await;
    eprintln!(
        "TIMING postgres: two namespaces at once {:.1} s",
        t.elapsed().as_secs_f64()
    );

    // Pruning past the window: `prune_requests` with a time beyond the
    // default retention removes every row; the consumed set stays.
    let t = Instant::now();
    let consumed_seed = game.seed_record.note_hash.fr();
    let future = unix_now() + DEFAULT_REQUESTS_RETENTION_SECS + 60;
    let mut pruned = Vec::new();
    for node in &net.nodes {
        pruned.push(node.app.node.prune_requests(future).unwrap());
        assert!(
            node.app
                .node
                .store
                .consumed(Fr::from(MONTY), consumed_seed)
                .unwrap()
                .is_some()
        );
    }
    eprintln!("postgres: pruned {pruned:?} request rows");
    // Every row the rounds wrote: the game's seed and init, and the two of
    // the lock case.
    assert_eq!(pruned, [4; NODES]);
    after_pruning(&net, "postgres", &[&game.seed, &game.init], &[&game.init]).await;
    eprintln!(
        "TIMING postgres: pruning {:.1} s",
        t.elapsed().as_secs_f64()
    );
    drop(net);
    drop(server);
    eprintln!(
        "TIMING postgres_backend: {:.1} s",
        started.elapsed().as_secs_f64()
    );
}

/// Two namespaces' requests through the lifecycle at once: an AMM seed takes
/// the mesh on all three nodes, a Monty Hall seed then waits on each node's
/// mesh lock and runs after it; requests refused at step 3 or at step 7 join
/// a session (its handshake only) once the mesh is free; refused cases leave
/// every store unchanged.
async fn two_namespaces_at_once<S: Store>(net: &mut Net<S>, game: &Game) {
    let player = monty::player();
    net.register_all(AMM, amm::EXAMPLE, &amm::CIRCUITS[..2])
        .await;
    let first = amm::seed(AMM, net.id());
    let mut second = monty::seed(MONTY, net.id());
    sign_as(&mut second, player, player);
    let mut refused = monty::init(MONTY, net.id(), &game.seed_record);
    sign_as(&mut refused, player, player);
    // A circuit of one namespace named under the other, both ways.
    let amm_under_monty = amm::init(MONTY, net.id());
    let mut monty_under_amm = monty::init(AMM, net.id(), &game.seed_record);
    sign_as(&mut monty_under_amm, player, player);
    let first_done = AtomicBool::new(false);
    let net = &*net;
    let run_first = async {
        let start = Instant::now();
        let round = net.execute("lock: amm seed first", &first).await;
        first_done.store(true, Ordering::SeqCst);
        (round, start.elapsed(), Instant::now())
    };
    let run_second = async {
        // Wait until the first request holds the mesh on all three nodes.
        let start = Instant::now();
        while net.nodes.iter().any(|n| n.app.mesh.lock().is_free()) {
            assert!(
                start.elapsed() < Duration::from_secs(60),
                "the first request never held all three meshes"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert!(!first_done.load(Ordering::SeqCst));
        // A request refused at step 3 waits for the mesh lock and sends its
        // refusal as its verdict once the mesh is free; each node answers its
        // own 400.
        let answers = net.run(views(&amm_under_monty)).await;
        for (i, a) in answers.into_iter().enumerate() {
            let err = a.expect_err("a circuit of another namespace");
            assert_eq!(err.class, ErrorClass::BadRequest, "node {i}: {err}");
        }
        let start = Instant::now();
        let round = net.execute("lock: monty seed second", &second).await;
        (round, start.elapsed(), Instant::now())
    };
    let ((_, first_took, first_end), (seeded, second_took, second_end)) =
        tokio::join!(run_first, run_second);
    assert!(
        second_end > first_end,
        "the second request finished before the first"
    );
    eprintln!(
        "lock: first {:.3}s; second {:.3}s from its post, {:.3}s after the first",
        first_took.as_secs_f64(),
        second_took.as_secs_f64(),
        (second_end - first_end).as_secs_f64()
    );
    // Both committed, each under its own namespace.
    for node in &net.nodes {
        let store = &node.app.node.store;
        let a = store.request(Fr::from(AMM), first.request_id).unwrap();
        assert_eq!(a.unwrap().status, RequestStatus::Committed);
        assert!(
            store
                .request(Fr::from(MONTY), first.request_id)
                .unwrap()
                .is_none()
        );
        let b = store.request(Fr::from(MONTY), second.request_id).unwrap();
        assert_eq!(b.unwrap().status, RequestStatus::Committed);
    }
    assert_eq!(
        net.opened_record(
            MONTY,
            &only_record(&seeded, monty::GAME_SEED_KEY),
            public_key(player)
        )
        .len(),
        2
    );
    // Requests refused at step 7 (a consumed record) or at step 3 (a circuit
    // of the other namespace) take the mesh for their handshake, so each node
    // sends its refusal as its verdict; all three answer their own refusal.
    net.refused(
        "lock: a consumed record",
        &refused,
        ErrorClass::Conflict,
        "is already consumed",
    )
    .await;
    net.refused(
        "lock: amm_init under the Monty namespace",
        &amm_under_monty,
        ErrorClass::BadRequest,
        "`amm_init` is not registered under namespace",
    )
    .await;
    net.refused(
        "lock: monty_hall_init under the AMM namespace",
        &monty_under_amm,
        ErrorClass::BadRequest,
        "`monty_hall_init` is not registered under namespace",
    )
    .await;
}

// The retention window of the LocalStore test, 1 s instead of
// the default 30 days, so the operator's one-shot prune through the admin
// socket removes the rows of a sequence that has just run (after a 2 s wait).
// Nothing else reads the window; the pruning timer is off in these tests.
const LOCAL_RETENTION_SECS: u64 = 1;

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn local_store_backend() {
    let crs = require_crs(&CIRCUITS);
    let _serial = serial().await;
    let started = Instant::now();
    let tmp = TempDir::new("loc3");
    let dirs: [PathBuf; NODES] = [0, 1, 2].map(|i| tmp.path().join(format!("store{i}")));
    let stores = dirs.clone().map(|d| LocalStore::open(d).unwrap());
    let tables: Tables = Some(Box::new(move |i| local_dump(&dirs[i])));
    let mut net = start_net(tmp, crs, &CIRCUITS, stores, tables, |node| {
        node.retention_secs = LOCAL_RETENTION_SECS
    })
    .await;

    let t = Instant::now();
    let game = monty_rounds(&mut net, "local").await;
    eprintln!(
        "TIMING local: Monty Hall rounds {:.1} s",
        t.elapsed().as_secs_f64()
    );

    // A manifest with a node-held key is refused at REGISTER (400, step 3)
    // by every node, since the local store holds no `values`; no round runs
    // and no table changes, so the namespace stays unregistered. The
    // client-held Monty Hall manifests above registered and ran.
    let t = Instant::now();
    for name in amm::CIRCUITS {
        let label = format!("local: REGISTER of the node-held {name}");
        let before = net.dump();
        let (_, answers) = net.register_answers(AMM, amm::EXAMPLE, &[name], 0).await;
        for (i, answer) in answers.into_iter().enumerate() {
            let err = answer.expect_err(&label);
            eprintln!("REFUSED {label}: node {i}: {err}");
            assert_eq!(
                err.class,
                ErrorClass::BadRequest,
                "{label}: node {i}: {err}"
            );
            assert!(
                err.message.contains("has the state mode `node`")
                    && err.message.contains("holds no `values` table"),
                "{label}: node {i}: {err}"
            );
        }
        net.unchanged(&label, &before);
        for node in &net.nodes {
            let store = &node.app.node.store;
            assert!(store.namespace(Fr::from(AMM)).unwrap().is_none(), "{label}");
            assert!(
                store.package(Fr::from(AMM), name).unwrap().is_none(),
                "{label}"
            );
        }
    }
    eprintln!(
        "TIMING local: the node-held REGISTER refusals {:.1} s",
        t.elapsed().as_secs_f64()
    );

    // The operator's prune through the admin socket, past the window.
    let t = Instant::now();
    tokio::time::sleep(Duration::from_secs(LOCAL_RETENTION_SECS + 1)).await;
    for i in 0..NODES {
        let pruned = net.admin(i, AdminRequest::Prune).await;
        assert!(pruned.ok, "node {i}: {:?}", pruned.refusal);
        assert_eq!(pruned.pruned, Some(2), "node {i}: the game's two rows");
        let consumed = net.nodes[i]
            .app
            .node
            .store
            .consumed(Fr::from(MONTY), game.seed_record.note_hash.fr())
            .unwrap();
        assert!(consumed.is_some(), "node {i}: the consumed set was pruned");
    }
    after_pruning(&net, "local", &[&game.seed, &game.init], &[&game.init]).await;
    eprintln!("TIMING local: pruning {:.1} s", t.elapsed().as_secs_f64());
    eprintln!(
        "TIMING local_store_backend: {:.1} s",
        started.elapsed().as_secs_f64()
    );
}
