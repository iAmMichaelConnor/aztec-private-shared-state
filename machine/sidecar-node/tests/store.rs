//! The core's store suite on the node's Postgres store, and what is
//! particular to it: its transactions (a commit that fails half-way,
//! concurrent commits of one namespace, calls from inside a tokio runtime),
//! its rows outliving the store and its pruning. The local store's cases are
//! sidecar-core's (tests/local_store.rs), with the type.
//!
//! The Postgres tests run against a throwaway Postgres container
//! or the server `SIDECAR_TEST_POSTGRES_URL` names
//! (`sidecar_test_fixtures::postgres`).

use std::sync::Arc;
use std::time::Instant;

use sidecar_core::ErrorClass;
use sidecar_core::field::Fr;
use sidecar_core::store::testing::{
    self, client_round, conflict, id, new_request, node_keys, ns, round, shared,
};
use sidecar_core::store::{ConsumedRow, Store, StoreRead, rules};
use sidecar_node::postgres::PostgresStore;
use sidecar_test_fixtures::postgres::{PgServer, postgres_server};

/// A Postgres test beyond the suite, by name.
type PgCase = (&'static str, fn(&mut PgServer));

/// Every Postgres test, in one test so they share one server.
#[test]
fn the_postgres_store() {
    let Some(mut server) = postgres_server("store-test") else {
        return;
    };
    let start = Instant::now();
    let ran = {
        let server = std::cell::RefCell::new(&mut server);
        testing::suite(|| server.borrow_mut().store())
    };
    eprintln!(
        "postgres store: {ran} suite cases passed in {:.1} s",
        start.elapsed().as_secs_f64()
    );
    assert_eq!(
        ran,
        testing::cases_without_values::<PostgresStore>().len()
            + testing::cases_with_values::<PostgresStore>().len()
    );

    let cases: [PgCase; 5] = [
        (
            "a_commit_that_fails_half_way_leaves_nothing",
            a_commit_that_fails_half_way_leaves_nothing,
        ),
        (
            "rows_outlive_the_store_and_migrations_rerun",
            rows_outlive_the_store_and_migrations_rerun,
        ),
        (
            "concurrent_commits_of_one_namespace_see_each_other",
            concurrent_commits_of_one_namespace_see_each_other,
        ),
        (
            "calls_from_inside_a_runtime_do_not_panic",
            calls_from_inside_a_runtime_do_not_panic,
        ),
        (
            "pruning_removes_old_requests_only",
            pruning_removes_old_requests_only,
        ),
    ];
    for (name, case) in cases {
        eprintln!("postgres store: {name}");
        case(&mut server);
    }
    eprintln!("postgres store: {} backend cases passed", cases.len());
}

/// A commit whose writes have started and then fails (here: a created_at
/// beyond BIGINT, refused at the request row, after the consumed entries and
/// the value were written) rolls back every one of them.
fn a_commit_that_fails_half_way_leaves_nothing(server: &mut PgServer) {
    let store = server.store();
    let keys = node_keys();
    let mut txn = store.begin(ns());
    txn.consume(ConsumedRow {
        note_hash: Fr::from(5u64),
        circuit: Fr::from(0xc1u64),
        request_id: id(1),
    });
    rules::stage_store(
        &store,
        &keys,
        &mut txn,
        "pool",
        vec![shared(1)],
        Fr::from(1u64),
    )
    .unwrap();
    txn.put_request(sidecar_core::store::NewRequest {
        stored_keys: vec!["pool".into()],
        created_keys: vec!["pool".into()],
        ..new_request(1, u64::MAX)
    });
    let err = store.commit(txn).unwrap_err();
    assert_eq!(err.class, ErrorClass::MpcFailure, "{err}");
    assert!(err.message.contains("created_at"), "{err}");
    assert!(store.consumed(ns(), Fr::from(5u64)).unwrap().is_none());
    assert!(store.value(ns(), "pool").unwrap().is_none());
    assert!(store.request(ns(), id(1)).unwrap().is_none());
    // The connection went back to the pool clean: the next commit works.
    round(
        &store,
        1,
        &[],
        &[Fr::from(5u64)],
        &[("pool", vec![shared(1)], Fr::from(1u64))],
    )
    .unwrap();
}

fn rows_outlive_the_store_and_migrations_rerun(server: &mut PgServer) {
    let options = server.fresh();
    let (row, value) = {
        let store = PostgresStore::connect_with(options.clone(), 2).unwrap();
        round(
            &store,
            1,
            &[],
            &[Fr::from(5u64)],
            &[("pool", vec![shared(1)], Fr::from(1u64))],
        )
        .unwrap();
        (
            store.request(ns(), id(1)).unwrap().unwrap(),
            store.value(ns(), "pool").unwrap().unwrap(),
        )
    };
    let receipt = testing::receipt_row(1, 100, Some(50));
    {
        let store = PostgresStore::connect_with(options.clone(), 2).unwrap();
        store.put_receipt(ns(), receipt.clone()).unwrap();
    }
    let store = PostgresStore::connect_with(options, 2).unwrap();
    assert_eq!(store.request(ns(), id(1)).unwrap(), Some(row));
    assert_eq!(store.value(ns(), "pool").unwrap(), Some(value));
    assert_eq!(
        store.receipt(ns(), receipt.request_id).unwrap(),
        Some(receipt)
    );
}

/// Eight threads consume one state under eight request ids at once: exactly
/// one commits, and every other is refused by the rules (409), not by a
/// database error.
fn concurrent_commits_of_one_namespace_see_each_other(server: &mut PgServer) {
    let store = Arc::new(server.store());
    let results: Vec<_> = (1..=8u8)
        .map(|n| {
            let store = store.clone();
            std::thread::spawn(move || round(&*store, n, &[], &[Fr::from(5u64)], &[]))
        })
        .collect::<Vec<_>>()
        .into_iter()
        .map(|t| t.join().unwrap())
        .collect();
    assert_eq!(
        results.iter().filter(|r| r.is_ok()).count(),
        1,
        "{results:?}"
    );
    for result in results.into_iter().filter(|r| r.is_err()) {
        conflict(result, "already consumed");
    }
}

/// The store answers from an async task (on both runtime flavours) and from
/// `spawn_blocking`, and can be dropped inside a runtime.
fn calls_from_inside_a_runtime_do_not_panic(server: &mut PgServer) {
    let store = Arc::new(server.store());
    round(&*store, 1, &[], &[Fr::from(5u64)], &[]).unwrap();
    let multi = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let s = store.clone();
    multi.block_on(async move {
        assert!(s.request(ns(), id(1)).unwrap().is_some());
        let t = s.clone();
        tokio::task::spawn_blocking(move || round(&*t, 2, &[], &[Fr::from(6u64)], &[]))
            .await
            .unwrap()
            .unwrap();
        let t = s.clone();
        tokio::spawn(async move { t.consumed(ns(), Fr::from(6u64)).unwrap() })
            .await
            .unwrap()
            .expect("the consumed entry");
    });
    let current = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let options = server.fresh();
    current.block_on(async move {
        assert!(store.request(ns(), id(2)).unwrap().is_some());
        // Constructed and dropped inside a runtime too.
        let other = PostgresStore::connect_with(options, 2).unwrap();
        assert!(other.request(ns(), id(2)).unwrap().is_none());
        drop(other);
        drop(store);
    });
}

fn pruning_removes_old_requests_only(server: &mut PgServer) {
    let store = server.store();
    for n in 1..=5u8 {
        client_round(
            &store,
            n,
            &[Fr::from(n as u64)],
            &[("0xa002", Fr::from(100 + n as u64))],
        )
        .unwrap();
    }
    // created_at is 1000 + n: rounds 1 to 3 are older than 1004.
    assert_eq!(store.prune_requests(1004).unwrap(), 3);
    for n in 1..=5u8 {
        assert_eq!(
            store.request(ns(), id(n)).unwrap().is_some(),
            n >= 4,
            "request {n}"
        );
        assert!(store.consumed(ns(), Fr::from(n as u64)).unwrap().is_some());
    }
    // A rollback of a pruned request is 404.
    let missing = rules::restore(&store, &node_keys(), ns(), id(1)).unwrap_err();
    assert_eq!(missing.class, ErrorClass::NotFound);
}
