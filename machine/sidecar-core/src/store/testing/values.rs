//! The suite's cases for node-held `values` rows and their rollback.

use super::*;
use crate::record;

pub fn write_requires_read_or_consumed<S: Store>(store: &S) {
    let (a, b, c) = (Fr::from(0xa1u64), Fr::from(0xb1u64), Fr::from(0xc1u64));
    // A fresh key: no read needed.
    round(store, 1, &[], &[], &[("pool", vec![shared(1)], a)]).unwrap();
    // Occupied and not loaded.
    conflict(
        round(store, 2, &[], &[], &[("pool", vec![shared(2)], b)]),
        "key occupied and not loaded",
    );
    assert!(store.request(ns(), id(2)).unwrap().is_none());
    // Occupied and loaded.
    round(store, 3, &["pool"], &[a], &[("pool", vec![shared(3)], b)]).unwrap();
    let row = store.value(ns(), "pool").unwrap().unwrap();
    assert_eq!(
        (row.vec, row.note_hash, row.request_id),
        (vec![shared(3)], b, id(3))
    );
    // Consumed by a round that did not rewrite it (amm_init on the seed),
    // then rewritten by a round that does not load it (pss_seed again).
    round(store, 4, &[], &[], &[("seed", vec![shared(4)], c)]).unwrap();
    round(store, 5, &["seed"], &[c], &[]).unwrap();
    round(
        store,
        6,
        &[],
        &[],
        &[("seed", vec![shared(6)], Fr::from(0xd1u64))],
    )
    .unwrap();
    assert_eq!(
        store.value(ns(), "seed").unwrap().unwrap().request_id,
        id(6)
    );
}

pub fn a_staged_write_is_checked_again_at_commit<S: Store>(store: &S) {
    let keys = node_keys();
    let mut txn = store.begin(ns());
    rules::stage_store(
        store,
        &keys,
        &mut txn,
        "pool",
        vec![shared(1)],
        Fr::from(1u64),
    )
    .unwrap();
    txn.put_request(new_request(1, 0));
    // Another round writes the key first.
    round(
        store,
        2,
        &[],
        &[],
        &[("pool", vec![shared(2)], Fr::from(2u64))],
    )
    .unwrap();
    conflict(store.commit(txn), "changed since the round read it");
}

pub fn replaced_vector_is_sealed_and_restore_brings_it_back<S: Store>(store: &S) {
    let keys = node_keys();
    let (a, b, c) = (Fr::from(0xa1u64), Fr::from(0xb1u64), Fr::from(0xc1u64));
    let old = vec![Elem::Public(Fr::from(42u64)), shared(1), shared(3)];
    round(store, 1, &[], &[], &[("pool", old.clone(), a)]).unwrap();
    // amm_swap: loads the pool, consumes its note hash, rewrites it.
    round(store, 2, &["pool"], &[a], &[("pool", vec![shared(7)], b)]).unwrap();

    let row = store.request(ns(), id(2)).unwrap().unwrap();
    let [sealed] = &row.sealed[..] else {
        panic!("one sealed entry: {:?}", row.sealed)
    };
    assert_eq!(
        sealed.kind,
        SealedKind::Replaced {
            prior_request_id: id(1)
        }
    );
    assert_eq!((sealed.key.as_str(), sealed.note_hash), ("pool", a));
    let opened = record::open(&keys, ns(), "pool", a, keys.enc_pk(), &sealed.c_i).unwrap();
    assert_eq!(opened, old);

    // Round 3 swaps again; rolling back round 2 first is out of order.
    round(store, 3, &["pool"], &[b], &[("pool", vec![shared(9)], c)]).unwrap();
    conflict(
        rules::restore(store, &keys, ns(), id(2)),
        "roll that request back first",
    );
    rules::restore(store, &keys, ns(), id(3)).unwrap();
    rules::restore(store, &keys, ns(), id(2)).unwrap();

    let back = store.value(ns(), "pool").unwrap().unwrap();
    assert_eq!((back.vec, back.note_hash, back.request_id), (old, a, id(1)));
    // The rolled-back row is kept whole, marked `rolled_back`.
    assert_eq!(
        store.request(ns(), id(2)).unwrap().unwrap(),
        RequestRow {
            status: RequestStatus::RolledBack,
            ..row
        }
    );
    // The restored state can be loaded and spent again.
    assert!(store.consumed(ns(), a).unwrap().is_none());
    assert!(store.consumed(ns(), b).unwrap().is_none());
    round(
        store,
        4,
        &["pool"],
        &[a],
        &[("pool", vec![shared(11)], Fr::from(5u64))],
    )
    .unwrap();
    // A second rollback of the same request, and an unknown request.
    conflict(
        rules::restore(store, &keys, ns(), id(2)),
        "already rolled back",
    );
    let missing = rules::restore(store, &keys, ns(), id(9)).unwrap_err();
    assert_eq!(missing.class, ErrorClass::NotFound);
}

pub fn restore_opens_replaced_vectors_across_an_enc_rotation<S: Store>(store: &S) {
    let keys = node_keys();
    let (a, b, c) = (Fr::from(0xa1u64), Fr::from(0xb1u64), Fr::from(0xc1u64));
    let old = vec![Elem::Public(Fr::from(42u64)), shared(1), shared(3)];
    round(store, 1, &[], &[], &[("pool", old.clone(), a)]).unwrap();
    // Round 2 replaces the pool; its sealed vector is under the enc key
    // current at commit.
    round(store, 2, &["pool"], &[a], &[("pool", vec![shared(7)], b)]).unwrap();

    // The operator rotates enc; within the grace window the rollback
    // opens the vector under the previous key and puts the row back.
    let next_enc = NodeKeys::generate(&mut StdRng::seed_from_u64(0x5c4e_6b01)).enc_scalar();
    let rotated = keys.rotate_enc(next_enc, 0).unwrap();
    assert_ne!(rotated.enc_pk(), keys.enc_pk());
    rules::restore(store, &rotated, ns(), id(2)).unwrap();
    let back = store.value(ns(), "pool").unwrap().unwrap();
    assert_eq!((back.vec, back.note_hash, back.request_id), (old, a, id(1)));
    assert_eq!(
        store.request(ns(), id(2)).unwrap().unwrap().status,
        RequestStatus::RolledBack
    );

    // Round 3 replaces the restored pool with a vector sealed under the
    // old key (`round` seals with `node_keys()`, as the node did before
    // the rotation). Once that key is retired the vector no longer opens:
    // 500, and nothing changes.
    round(store, 3, &["pool"], &[a], &[("pool", vec![shared(9)], c)]).unwrap();
    let before = (
        store.value(ns(), "pool").unwrap(),
        store.request(ns(), id(3)).unwrap(),
        store.consumed(ns(), a).unwrap(),
    );
    let retired = rotated.retire_previous_enc();
    let err = rules::restore(store, &retired, ns(), id(3)).unwrap_err();
    assert_eq!(err.class, ErrorClass::MpcFailure, "{err}");
    assert!(
        err.message.contains("the replaced vector of key `pool`")
            && err.message.contains("does not open"),
        "{err}"
    );
    let after = (
        store.value(ns(), "pool").unwrap(),
        store.request(ns(), id(3)).unwrap(),
        store.consumed(ns(), a).unwrap(),
    );
    assert_eq!(before, after);
}

pub fn a_rollback_deletes_created_rows_and_every_consumed_entry<S: Store>(store: &S) {
    let keys = node_keys();
    let (seed, pool) = (Fr::from(0x5eu64), Fr::from(0x9001u64));
    // pss_seed creates the seed; amm_init consumes it (without rewriting
    // it) and creates the pool.
    round(store, 1, &[], &[], &[("seed", vec![shared(1)], seed)]).unwrap();
    round(
        store,
        2,
        &["seed"],
        &[seed],
        &[("pool", vec![shared(2)], pool)],
    )
    .unwrap();
    assert_eq!(
        store.request(ns(), id(2)).unwrap().unwrap().created_keys,
        ["pool"]
    );
    // The seed round's state was consumed by round 2: out of order.
    conflict(
        rules::restore(store, &keys, ns(), id(1)),
        "was consumed after request",
    );
    rules::restore(store, &keys, ns(), id(2)).unwrap();
    assert!(store.value(ns(), "pool").unwrap().is_none());
    assert!(store.consumed(ns(), seed).unwrap().is_none());
    assert_eq!(
        store.value(ns(), "seed").unwrap().unwrap().request_id,
        id(1)
    );
    // Now the seed round may go too: its created row is deleted.
    rules::restore(store, &keys, ns(), id(1)).unwrap();
    assert!(store.value(ns(), "seed").unwrap().is_none());
}

pub fn a_round_may_not_store_a_consumed_state<S: Store>(store: &S) {
    let a = Fr::from(0xa1u64);
    round(store, 1, &[], &[], &[("pool", vec![shared(1)], a)]).unwrap();
    conflict(
        round(store, 2, &["pool"], &[a], &[("pool", vec![shared(2)], a)]),
        "which is consumed",
    );
    round(store, 3, &["pool"], &[a], &[]).unwrap();
    conflict(
        round(store, 4, &[], &[], &[("other", vec![shared(2)], a)]),
        "which is consumed",
    );
    let mut txn = store.begin(ns());
    txn.add_record("0xb001", a, vec![1]);
    txn.put_request(new_request(5, 0));
    conflict(store.commit(txn), "which is consumed");
}

pub fn a_replacement_without_its_sealed_vector_is_refused<S: Store>(store: &S) {
    round(
        store,
        1,
        &[],
        &[],
        &[("pool", vec![shared(1)], Fr::from(1u64))],
    )
    .unwrap();
    let mut txn = store.begin(ns());
    txn.loaded("pool");
    txn.values.push(ValueWrite {
        key: "pool".into(),
        vec: vec![shared(2)],
        note_hash: Fr::from(2u64),
        replaces: Some(Fr::from(1u64)),
    });
    txn.put_request(new_request(2, 0));
    assert_eq!(store.commit(txn).unwrap_err().class, ErrorClass::MpcFailure);
    assert_eq!(
        store.value(ns(), "pool").unwrap().unwrap().note_hash,
        Fr::from(1u64)
    );
}

/// A node-held transaction that is never committed changes nothing.
pub fn a_dropped_node_held_transaction_leaves_nothing<S: Store>(store: &S) {
    let keys = node_keys();
    round(
        store,
        1,
        &[],
        &[],
        &[("pool", vec![shared(1)], Fr::from(1u64))],
    )
    .unwrap();
    let mut txn = store.begin(ns());
    txn.loaded("pool");
    rules::stage_store(
        store,
        &keys,
        &mut txn,
        "pool",
        vec![shared(2)],
        Fr::from(2u64),
    )
    .unwrap();
    rules::stage_store(
        store,
        &keys,
        &mut txn,
        "new",
        vec![shared(3)],
        Fr::from(3u64),
    )
    .unwrap();
    txn.put_request(new_request(2, 0));
    drop(txn);
    let row = store.value(ns(), "pool").unwrap().unwrap();
    assert_eq!((row.vec, row.request_id), (vec![shared(1)], id(1)));
    assert!(store.value(ns(), "new").unwrap().is_none());
    assert!(store.request(ns(), id(2)).unwrap().is_none());
}

/// A backend without `values` refuses a node-held write and stores none
/// of the round.
pub fn a_node_held_write_is_refused<S: Store>(store: &S) {
    let err = round(
        store,
        1,
        &[],
        &[Fr::from(5u64)],
        &[("pool", vec![shared(1)], Fr::from(1u64))],
    )
    .unwrap_err();
    assert_eq!(err.class, ErrorClass::MpcFailure, "{err}");
    assert!(store.value(ns(), "pool").unwrap().is_none());
    assert!(store.request(ns(), id(1)).unwrap().is_none());
    assert!(store.consumed(ns(), Fr::from(5u64)).unwrap().is_none());
}
