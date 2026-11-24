//! The suite's cases for the `requests`, `consumed` and `dead_records` tables.

use super::*;

pub fn a_reused_request_id_is_refused<S: Store>(store: &S) {
    round(store, 1, &[], &[], &[]).unwrap();
    conflict(round(store, 1, &[], &[], &[]), "already used");
}

pub fn prune_requests_by_age_keeps_the_consumed_set<S: Store>(store: &S) {
    round(store, 1, &[], &[Fr::from(5u64)], &[]).unwrap(); // created_at 1001
    round(store, 2, &[], &[], &[]).unwrap(); // created_at 1002
    assert_eq!(store.prune_requests(1002).unwrap(), 1);
    // FETCH of the pruned id finds no row (404).
    assert!(store.request(ns(), id(1)).unwrap().is_none());
    assert!(store.request(ns(), id(2)).unwrap().is_some());
    assert_eq!(
        store.consumed(ns(), Fr::from(5u64)).unwrap(),
        Some(ConsumedRow {
            note_hash: Fr::from(5u64),
            circuit: Fr::from(0xc1u64),
            request_id: id(1),
        })
    );
    // After the window the id is free, and the consumed set still bounds
    // a resent body.
    conflict(
        round(store, 1, &[], &[Fr::from(5u64)], &[]),
        "already consumed",
    );
    round(store, 1, &[], &[Fr::from(6u64)], &[]).unwrap();
    assert_eq!(store.prune_requests(1001).unwrap(), 0);
    assert_eq!(store.prune_requests(2000).unwrap(), 2);
    assert!(store.consumed(ns(), Fr::from(5u64)).unwrap().is_some());
    assert!(store.consumed(ns(), Fr::from(6u64)).unwrap().is_some());
    assert_eq!(DEFAULT_REQUESTS_RETENTION_SECS, 2_592_000);
}

pub fn client_records_are_kept_in_the_request_row<S: Store>(store: &S) {
    let mut txn = store.begin(ns());
    txn.add_record("0xa002", Fr::from(77u64), vec![1, 2, 3]);
    txn.put_request(new_request(1, 0));
    store.commit(txn).unwrap();
    let row = store.request(ns(), id(1)).unwrap().unwrap();
    assert_eq!(row.sealed.len(), 1);
    assert_eq!(row.sealed[0].kind, SealedKind::Record);
    assert_eq!(row.status, RequestStatus::Committed);
    // A round's writes without a request row are refused.
    let mut orphan = store.begin(ns());
    orphan.add_record("0xa002", Fr::from(78u64), vec![]);
    assert_eq!(
        store.commit(orphan).unwrap_err().class,
        ErrorClass::MpcFailure
    );
}

/// Every field of a request row reads back as committed.
pub fn a_request_row_round_trips<S: Store>(store: &S) {
    let mut txn = store.begin(ns());
    txn.consume(ConsumedRow {
        note_hash: Fr::from(9u64),
        circuit: Fr::from(0xc1u64),
        request_id: id(7),
    });
    txn.add_record("0xa002", Fr::from(77u64), vec![1, 2, 3]);
    txn.add_record("0xa003", Fr::from(78u64), vec![]);
    txn.put_request(NewRequest {
        public_inputs: vec![Fr::from(1u64), -Fr::from(1u64), Fr::from(0u64)],
        signature: Some(Signature {
            s: [1u64.into(), 2u64.into()],
            e: [3u64.into(), (-Fr::from(4u64)).into()],
        }),
        proof: (0..=255u8).collect(),
        ..new_request(7, 1_700_000_000)
    });
    let expected = txn.request_row().unwrap();
    store.commit(txn).unwrap();
    assert_eq!(store.request(ns(), id(7)).unwrap(), Some(expected));
    assert!(store.request(Fr::from(1u64), id(7)).unwrap().is_none());
    assert!(
        store
            .consumed(Fr::from(1u64), Fr::from(9u64))
            .unwrap()
            .is_none()
    );
}

/// Commit request `n` carrying `chain` (or none), created at `created_at`,
/// with one record third so a rollback has something to undo.
pub fn chain_round<S: Store + ?Sized>(
    store: &S,
    n: u8,
    chain: Option<Fr>,
    created_at: u64,
) -> Result<(), Refusal> {
    let mut txn = store.begin(ns());
    txn.add_record("0xa002", Fr::from(0x100 + n as u64), vec![n]);
    txn.put_request(NewRequest {
        chain_request_id: chain,
        ..new_request(n, created_at)
    });
    store.commit(txn)
}

/// The chain request id reads back as committed, `None` stays `None`,
/// and the lookup by it is scoped by namespace.
pub fn a_chain_request_id_round_trips<S: Store>(store: &S) {
    let chain = -Fr::from(0xc4a1u64);
    let mut txn = store.begin(ns());
    txn.add_record("0xa002", Fr::from(77u64), vec![1, 2, 3]);
    txn.put_request(NewRequest {
        chain_request_id: Some(chain),
        ..new_request(1, 1_700_000_000)
    });
    let expected = txn.request_row().unwrap();
    assert_eq!(expected.chain_request_id, Some(chain));
    store.commit(txn).unwrap();
    assert_eq!(store.request(ns(), id(1)).unwrap(), Some(expected.clone()));
    assert_eq!(store.chain_request(ns(), chain).unwrap(), Some(expected));
    chain_round(store, 2, None, 1_700_000_001).unwrap();
    assert_eq!(
        store
            .request(ns(), id(2))
            .unwrap()
            .unwrap()
            .chain_request_id,
        None
    );
    assert!(
        store
            .chain_request(Fr::from(1u64), chain)
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .chain_request(ns(), Fr::from(0xc4a2u64))
            .unwrap()
            .is_none()
    );
}

/// FETCH by chain request id answers the latest row carrying it: 404
/// before any, the later of two attempts, 409 once the latest is rolled
/// back (not the earlier committed one), the next attempt after that, and
/// 404 again once pruning removed them. A row no later than the latest
/// is refused at commit, and `chain_created_at` dates the next one after
/// it.
pub fn fetch_by_chain_request_id_answers_the_latest_row<S: Store>(store: &S) {
    let (chain, other) = (Fr::from(0xc4a1u64), Fr::from(0xc4a2u64));
    let class = |r: Result<RequestRow, Refusal>| r.unwrap_err().class;
    assert_eq!(
        class(store.fetch_by_chain_request_id(ns(), chain)),
        ErrorClass::NotFound
    );
    chain_round(store, 1, Some(chain), 1000).unwrap();
    chain_round(store, 2, Some(chain), 1005).unwrap();
    chain_round(store, 3, Some(other), 1010).unwrap();
    chain_round(store, 4, None, 1020).unwrap();
    let latest = store.fetch_by_chain_request_id(ns(), chain).unwrap();
    assert_eq!(latest.request_id, id(2));
    assert_eq!(latest, store.request(ns(), id(2)).unwrap().unwrap());
    assert_eq!(
        store
            .fetch_by_chain_request_id(ns(), other)
            .unwrap()
            .request_id,
        id(3)
    );
    assert_eq!(
        class(store.fetch_by_chain_request_id(Fr::from(1u64), chain)),
        ErrorClass::NotFound
    );

    // A row dated no later than the latest is refused; the next attempt
    // is dated after it whatever the clock says.
    let err = chain_round(store, 5, Some(chain), 1005).unwrap_err();
    assert_eq!(err.class, ErrorClass::MpcFailure, "{err}");
    assert!(
        err.message.contains("is not later than its latest row"),
        "{err}"
    );
    assert!(store.request(ns(), id(5)).unwrap().is_none());
    assert_eq!(
        rules::chain_created_at(store, ns(), chain, 1003).unwrap(),
        1006
    );
    assert_eq!(
        rules::chain_created_at(store, ns(), chain, 1007).unwrap(),
        1007
    );
    assert_eq!(
        rules::chain_created_at(store, ns(), Fr::from(9u64), 5).unwrap(),
        5
    );

    // The latest rolled back: 409, not the earlier committed attempt.
    rules::restore(store, &node_keys(), ns(), id(2)).unwrap();
    let err = store.fetch_by_chain_request_id(ns(), chain).unwrap_err();
    assert_eq!(err.class, ErrorClass::Conflict, "{err}");
    assert!(err.message.contains("rolled back"), "{err}");
    assert_eq!(
        store.chain_request(ns(), chain).unwrap().unwrap().status,
        RequestStatus::RolledBack
    );

    // The next attempt is the latest again.
    let at = rules::chain_created_at(store, ns(), chain, 1003).unwrap();
    chain_round(store, 6, Some(chain), at).unwrap();
    assert_eq!(
        store
            .fetch_by_chain_request_id(ns(), chain)
            .unwrap()
            .request_id,
        id(6)
    );

    // Pruned with the retention window: 404 again.
    assert_eq!(store.prune_requests(1007).unwrap(), 3);
    assert_eq!(
        class(store.fetch_by_chain_request_id(ns(), chain)),
        ErrorClass::NotFound
    );
    assert_eq!(
        store
            .fetch_by_chain_request_id(ns(), other)
            .unwrap()
            .request_id,
        id(3)
    );
}

/// The node-held entries of a request row read back as committed too:
/// replaced vectors interleaved with records, created and stored keys.
pub fn a_request_row_with_replaced_vectors_round_trips<S: Store>(store: &S) {
    let keys = node_keys();
    let (a, b) = (Fr::from(0xa1u64), Fr::from(0xb1u64));
    round(store, 1, &[], &[], &[("pool", vec![shared(1)], a)]).unwrap();
    let mut txn = store.begin(ns());
    txn.add_record("0xa002", Fr::from(77u64), vec![4, 5]);
    txn.loaded("pool");
    txn.consume(ConsumedRow {
        note_hash: a,
        circuit: Fr::from(0xc1u64),
        request_id: id(2),
    });
    rules::stage_store(store, &keys, &mut txn, "pool", vec![shared(2)], b).unwrap();
    rules::stage_store(
        store,
        &keys,
        &mut txn,
        "fees",
        vec![shared(3)],
        Fr::from(3u64),
    )
    .unwrap();
    txn.add_record("0xa004", Fr::from(79u64), vec![6]);
    txn.put_request(NewRequest {
        stored_keys: vec!["pool".into(), "fees".into()],
        created_keys: vec!["fees".into()],
        ..new_request(2, 2000)
    });
    let expected = txn.request_row().unwrap();
    store.commit(txn).unwrap();
    let row = store.request(ns(), id(2)).unwrap().unwrap();
    assert_eq!(row, expected);
    assert_eq!(row.records().count(), 2);
    assert_eq!(
        store.value(ns(), "fees").unwrap().unwrap().request_id,
        id(2)
    );
}

/// A transaction that is never committed changes nothing.
pub fn a_dropped_transaction_leaves_nothing<S: Store>(store: &S) {
    let mut txn = store.begin(ns());
    txn.register_namespace(namespace_row(3));
    txn.consume(ConsumedRow {
        note_hash: Fr::from(5u64),
        circuit: Fr::from(0xc1u64),
        request_id: id(1),
    });
    txn.add_record("0xa002", Fr::from(77u64), vec![1]);
    txn.put_request(new_request(1, 0));
    drop(txn);
    assert!(store.namespace(ns()).unwrap().is_none());
    assert!(store.consumed(ns(), Fr::from(5u64)).unwrap().is_none());
    assert!(store.request(ns(), id(1)).unwrap().is_none());
}

/// A commit the rules refuse changes nothing, though some of its writes
/// would have passed.
pub fn a_refused_commit_leaves_nothing<S: Store>(store: &S) {
    client_round(store, 1, &[Fr::from(5u64)], &[]).unwrap();
    let mut txn = store.begin(ns());
    txn.register_namespace(namespace_row(3));
    for note_hash in [6u64, 5] {
        txn.consume(ConsumedRow {
            note_hash: Fr::from(note_hash),
            circuit: Fr::from(0xc1u64),
            request_id: id(2),
        });
    }
    txn.put_request(new_request(2, 0));
    conflict(store.commit(txn), "already consumed");
    assert!(store.namespace(ns()).unwrap().is_none());
    assert!(store.consumed(ns(), Fr::from(6u64)).unwrap().is_none());
    assert!(store.request(ns(), id(2)).unwrap().is_none());
}

/// The rollback of a client-held round: the request row stays and is
/// marked `rolled_back`, its own consumed entries go, every other
/// request's stay, and it waits for a later round that consumed one of
/// its records to be rolled back first.
pub fn a_client_held_rollback_deletes_only_its_consumed_entries<S: Store>(store: &S) {
    let keys = node_keys();
    let (a, b, c, x) = (
        Fr::from(0xa1u64),
        Fr::from(0xb1u64),
        Fr::from(0xc1u64),
        Fr::from(0x77u64),
    );
    client_round(store, 1, &[a, b], &[("0xa002", x)]).unwrap();
    client_round(store, 2, &[c], &[]).unwrap();
    client_round(store, 3, &[x], &[]).unwrap();
    let row = store.request(ns(), id(1)).unwrap().unwrap();

    conflict(
        rules::restore(store, &keys, ns(), id(1)),
        "was consumed after request",
    );
    rules::restore(store, &keys, ns(), id(3)).unwrap();
    assert!(store.consumed(ns(), x).unwrap().is_none());
    rules::restore(store, &keys, ns(), id(1)).unwrap();

    assert_eq!(
        store.request(ns(), id(1)).unwrap().unwrap(),
        RequestRow {
            status: RequestStatus::RolledBack,
            ..row
        }
    );
    assert!(store.consumed(ns(), a).unwrap().is_none());
    assert!(store.consumed(ns(), b).unwrap().is_none());
    assert_eq!(
        store.consumed(ns(), c).unwrap().map(|r| r.request_id),
        Some(id(2))
    );
    assert_eq!(
        store.request(ns(), id(2)).unwrap().unwrap().status,
        RequestStatus::Committed
    );
    // The old records load again: a new round may consume them.
    client_round(store, 4, &[a, b], &[]).unwrap();
    conflict(
        rules::restore(store, &keys, ns(), id(1)),
        "already rolled back",
    );
}

/// A rollback marks every record the request created dead, under its id,
/// and nothing else; the prune keeps the marks; a later round that creates
/// a record with the same note hash deletes its mark, and a rollback of
/// that round marks it again.
pub fn a_rollback_marks_the_records_it_created_dead<S: Store>(store: &S) {
    let keys = node_keys();
    let (old, x, y) = (Fr::from(0xa1u64), Fr::from(0x77u64), Fr::from(0x78u64));
    let dead = |note_hash: Fr| store.dead_record(ns(), note_hash).unwrap();
    client_round(store, 1, &[], &[("0xff01", old)]).unwrap();
    client_round(store, 2, &[old], &[("0xff02", x), ("0xff03", y)]).unwrap();
    assert_eq!(dead(x), None);
    rules::restore(store, &keys, ns(), id(2)).unwrap();
    for note_hash in [x, y] {
        assert_eq!(
            dead(note_hash),
            Some(DeadRecord {
                note_hash,
                request_id: id(2)
            })
        );
    }
    assert_eq!(dead(old), None);
    assert_eq!(store.dead_record(Fr::from(0x99u64), x).unwrap(), None);

    assert_eq!(store.prune_requests(2000).unwrap(), 2);
    assert_eq!(dead(x).map(|d| d.request_id), Some(id(2)));

    // The old record again, and a round that computes the same record x.
    client_round(store, 3, &[old], &[("0xff02", x)]).unwrap();
    assert_eq!(dead(x), None);
    assert_eq!(dead(y).map(|d| d.request_id), Some(id(2)));
    rules::restore(store, &keys, ns(), id(3)).unwrap();
    assert_eq!(dead(x).map(|d| d.request_id), Some(id(3)));
}

/// A rolled-back attempt at a queued request stays as its `rolled_back`
/// row; a round with the same body runs again under its id and its row
/// replaces that one ([`Txn::rerun`]), reviving the record the rollback
/// marked dead. Refused (409): the same id without the rerun mark, a rerun
/// of another body, of a committed row, of a rolled-back direct request,
/// or of an id with no row.
pub fn a_rolled_back_tip_attempt_is_replaced_by_its_rerun<S: Store>(store: &S) {
    let chain = Fr::from(0xc4a1u64);
    let rerun = |n: u8, chain: Option<Fr>, body: Option<Fr>| {
        let mut txn = store.begin(ns());
        txn.add_record("0xa002", Fr::from(0x100 + n as u64), vec![n, 9]);
        let created_at = match chain {
            Some(c) => rules::chain_created_at(store, ns(), c, 1001).unwrap(),
            None => 1001,
        };
        let base = new_request(n, created_at);
        txn.put_request(NewRequest {
            chain_request_id: chain,
            body_hash: body.unwrap_or(base.body_hash),
            proof: vec![9; 4],
            ..base
        });
        txn.rerun();
        let expected = txn.request_row().unwrap();
        store.commit(txn).map(|()| expected)
    };
    chain_round(store, 1, Some(chain), 1001).unwrap();
    conflict(rerun(1, Some(chain), None).map(drop), "no longer holds");
    rules::restore(store, &node_keys(), ns(), id(1)).unwrap();
    let tombstone = store.request(ns(), id(1)).unwrap().unwrap();
    assert_eq!(tombstone.status, RequestStatus::RolledBack);
    assert!(tombstone.reruns(tombstone.body_hash, Some(chain)));
    assert!(
        store
            .dead_record(ns(), Fr::from(0x101u64))
            .unwrap()
            .is_some()
    );

    conflict(chain_round(store, 1, Some(chain), 1002), "already used");
    conflict(
        rerun(1, Some(chain), Some(Fr::from(0xbadu64))).map(drop),
        "no longer holds",
    );
    let expected = rerun(1, Some(chain), None).unwrap();
    let row = store.request(ns(), id(1)).unwrap().unwrap();
    assert_eq!(row, expected);
    assert_eq!(
        (row.status, row.proof.as_slice(), row.created_at),
        (RequestStatus::Committed, &[9u8; 4][..], 1002)
    );
    assert_eq!(store.chain_request(ns(), chain).unwrap(), Some(row));
    assert!(
        store
            .dead_record(ns(), Fr::from(0x101u64))
            .unwrap()
            .is_none()
    );
    assert_eq!(store.requests(ns()).unwrap().len(), 1);

    chain_round(store, 2, None, 1002).unwrap();
    rules::restore(store, &node_keys(), ns(), id(2)).unwrap();
    conflict(rerun(2, None, None).map(drop), "no longer holds");
    conflict(rerun(3, Some(chain), None).map(drop), "no longer holds");
}
