//! The suite's cases for a resync's imports and the listings it sends.

use super::*;

fn package(name: &str, seq: u64) -> PackageRow {
    PackageRow {
        name: name.into(),
        manifest_hash: Fr::from(0xaau64),
        circuit_json: b"{\"noir_version\":\"1.0.0\"}".to_vec(),
        manifest: serde_json::json!({"manifest": 1, "circuit": name}),
        vk: vec![1, 2, 0, 255],
        vk_hash: Fr::from(0xc1u64),
        disabled: seq == 2,
        seq,
    }
}

fn consumed_row(note_hash: u64, n: u8) -> ConsumedRow {
    ConsumedRow {
        note_hash: Fr::from(note_hash),
        circuit: Fr::from(0xc1u64),
        request_id: id(n),
    }
}

/// A resync's import writes a namespace row at any seq with its
/// packages and consumed rows, in one commit with no request row; it is
/// refused (409) for a namespace the store holds, and (500) with any
/// other write.
pub fn an_import_writes_a_namespace_the_store_does_not_hold<S: Store>(store: &S) {
    let row = NamespaceRow {
        seq: 3,
        ..namespace_row(5)
    };
    let mut txn = store.begin(ns());
    txn.import_namespace(row.clone());
    txn.put_manifest(manifest_row(0xaa, 1));
    txn.put_package(package("a", 1));
    txn.put_package(package("b", 2));
    txn.consume(consumed_row(0x51, 4));
    txn.consume(consumed_row(0x50, 3));
    store.commit(txn).unwrap();
    assert_eq!(store.namespace(ns()).unwrap(), Some(row.clone()));
    assert_eq!(store.package_names(ns()).unwrap(), ["a", "b"]);
    assert_eq!(store.package(ns(), "b").unwrap(), Some(package("b", 2)));
    assert!(store.tip_keys(ns()).unwrap().is_empty());
    assert_eq!(
        store.consumed_rows(ns()).unwrap(),
        [consumed_row(0x50, 3), consumed_row(0x51, 4)]
    );
    assert!(store.value_keys(ns()).unwrap().is_empty());
    // the store holds it now
    let mut again = store.begin(ns());
    again.import_namespace(row.clone());
    conflict(
        store.commit(again),
        "a resync imports into a store without it",
    );
    // an import with anything else is refused
    let other = Fr::from(NS + 1);
    let mut mixed = store.begin(other);
    mixed.import_namespace(row);
    mixed.put_request(new_request(9, 1009));
    let err = store.commit(mixed).unwrap_err();
    assert_eq!(err.class, ErrorClass::MpcFailure, "{err}");
    assert!(store.namespace(other).unwrap().is_none());
}

/// The consumed rows and the receipts rows of a namespace are listed
/// in ascending order of their note hash and chain request id, and only
/// under their namespace.
pub fn consumed_rows_and_receipts_are_listed_by_namespace<S: Store>(store: &S) {
    assert!(store.consumed_rows(ns()).unwrap().is_empty());
    assert!(store.receipts(ns()).unwrap().is_empty());
    client_round(store, 1, &[Fr::from(0x92u64), Fr::from(0x91u64)], &[]).unwrap();
    let other = Fr::from(NS + 1);
    let mut txn = store.begin(other);
    txn.consume(consumed_row(0x90, 2));
    txn.put_request(new_request(2, 1002));
    store.commit(txn).unwrap();
    assert_eq!(
        store.consumed_rows(ns()).unwrap(),
        [consumed_row(0x91, 1), consumed_row(0x92, 1)]
    );
    assert_eq!(store.consumed_rows(other).unwrap(), [consumed_row(0x90, 2)]);
    let rows = [
        receipt_row(2, 1000, Some(50)),
        shared_receipt_row(1, 1000, None),
    ];
    for row in &rows {
        store.put_receipt(ns(), row.clone()).unwrap();
    }
    store
        .put_receipt(other, receipt_row(3, 1000, None))
        .unwrap();
    assert_eq!(
        store.receipts(ns()).unwrap(),
        [rows[1].clone(), rows[0].clone()]
    );
    assert_eq!(store.receipts(other).unwrap(), [receipt_row(3, 1000, None)]);
}

/// The `requests` and `dead_records` rows of a namespace are listed in
/// ascending order, under their namespace only; a namespace import
/// (a restore from a backup) writes them as they stand, a rolled-back
/// request with its status and sealed entries included. A request twice
/// in one import is refused (500), and so is either row outside a
/// namespace import.
pub fn an_import_writes_requests_and_dead_records_as_they_stand<S: Store>(store: &S) {
    let (old, new) = (Fr::from(0x70u64), Fr::from(0x71u64));
    client_round(store, 1, &[], &[("0xff02", old)]).unwrap();
    client_round(store, 2, &[old], &[("0xff02", new)]).unwrap();
    rules::restore(store, &node_keys(), ns(), id(2)).unwrap();
    let requests = store.requests(ns()).unwrap();
    let ids: Vec<RequestId> = requests.iter().map(|r| r.request_id).collect();
    assert_eq!(ids, [id(1), id(2)]);
    assert_eq!(requests[1].status, RequestStatus::RolledBack);
    assert!(requests[1].records().next().is_some());
    let dead = store.dead_records(ns()).unwrap();
    assert_eq!(
        dead,
        [DeadRecord {
            note_hash: new,
            request_id: id(2)
        }]
    );
    let other = Fr::from(NS + 1);
    assert!(store.requests(other).unwrap().is_empty());
    assert!(store.dead_records(other).unwrap().is_empty());

    let mut txn = store.begin(other);
    txn.import_namespace(namespace_row(6));
    for row in requests.iter().rev() {
        txn.import_request(row.clone());
    }
    txn.import_dead(dead[0].clone());
    store.commit(txn).unwrap();
    assert_eq!(store.requests(other).unwrap(), requests);
    assert_eq!(store.dead_records(other).unwrap(), dead);
    assert_eq!(
        store.request(other, id(2)).unwrap().as_ref(),
        Some(&requests[1])
    );
    assert_eq!(
        store.dead_record(other, new).unwrap(),
        Some(dead[0].clone())
    );

    let third = Fr::from(NS + 2);
    let mut twice = store.begin(third);
    twice.import_namespace(namespace_row(7));
    twice.import_request(requests[0].clone());
    twice.import_request(requests[0].clone());
    let err = store.commit(twice).unwrap_err();
    assert_eq!(err.class, ErrorClass::MpcFailure, "{err}");
    assert!(store.namespace(third).unwrap().is_none());
    let mut loose = store.begin(ns());
    loose.import_dead(dead[0].clone());
    let err = store.commit(loose).unwrap_err();
    assert_eq!(err.class, ErrorClass::MpcFailure, "{err}");
    let mut loose = store.begin(third);
    loose.import_request(requests[0].clone());
    let err = store.commit(loose).unwrap_err();
    assert_eq!(err.class, ErrorClass::MpcFailure, "{err}");
    assert!(store.requests(third).unwrap().is_empty());
}

/// A resync's import writes `values` rows with the request that wrote
/// each (no request row of its own); the store lists their keys; a
/// `values` row imported outside a namespace import is refused (500).
pub fn an_import_writes_values_rows_with_their_writers<S: Store>(store: &S) {
    let value = |key: &str, n: u8| RestoredValue {
        key: key.into(),
        vec: vec![shared(n as u64), Elem::Public(Fr::from(n as u64))],
        note_hash: Fr::from(0x700 + n as u64),
        prior_request_id: id(n),
    };
    let mut txn = store.begin(ns());
    txn.import_namespace(namespace_row(8));
    txn.import_value(value("pool", 4));
    txn.import_value(value("book", 5));
    store.commit(txn).unwrap();
    assert_eq!(store.value_keys(ns()).unwrap(), ["book", "pool"]);
    let row = store.value(ns(), "pool").unwrap().unwrap();
    let want = value("pool", 4);
    assert_eq!(
        (row.vec, row.note_hash, row.request_id),
        (want.vec, want.note_hash, want.prior_request_id)
    );
    assert!(store.request(ns(), id(4)).unwrap().is_none());
    assert!(store.value_keys(Fr::from(NS + 1)).unwrap().is_empty());
    // outside an import
    let mut stray = store.begin(ns());
    stray.import_value(value("other", 6));
    stray.put_request(new_request(6, 1006));
    let err = store.commit(stray).unwrap_err();
    assert_eq!(err.class, ErrorClass::MpcFailure, "{err}");
    assert!(store.value(ns(), "other").unwrap().is_none());
}

/// A resync's import of one key replaces every version and tree node of
/// that key, held ones included, and leaves the namespace's other keys
/// alone; it is refused (409) for a namespace the store does not hold,
/// and (500) with a write of another key or anything else.
pub fn a_key_import_replaces_one_key_s_versions_and_tree<S: Store>(store: &S) {
    use crate::tree::{self, TreeNode};
    let z = tree::zeros(2);
    let empty = |_: Fr| -> Result<Option<TreeNode>, Refusal> { Ok(None) };
    // a book of one leaf at `index` holding `a`, as version `c`
    let book = |txn: &mut Txn, read: &dyn StoreRead, index: u64, a: u64, c: u64| {
        let leaf = Fr::from(0x1ea0 + a);
        let rebuilt = tree::rebuild(&empty, &z, z[2], &[(index, leaf)]).unwrap();
        let mut added = vec![(
            leaf,
            TreeNode::Leaf {
                index,
                vec: vec![shared(a)],
            },
        )];
        added.extend(rebuilt.added.iter().map(|(h, _, n)| (*h, n.clone())));
        rules::TreeNodes { read, key: "book" }
            .add_version(txn, rebuilt.root, added)
            .unwrap();
        let mut v = version("book", c, 0, 0, c as u8);
        v.vec = vec![];
        v.tree = Some(VersionTree::Clear(TreeRoot {
            root: rebuilt.root,
            next: index + 1,
        }));
        txn.version(VersionWrite::Put(v.clone()));
        (leaf, rebuilt.root, v)
    };
    let mut txn = store.begin(ns());
    txn.import_namespace(namespace_row(9));
    let (old_leaf, old_root, _) = book(&mut txn, store, 1, 3, 7);
    let pool = version("pool", 5, 0, 0, 1);
    txn.version(VersionWrite::Put(pool.clone()));
    txn.version(VersionWrite::Put(version("book", 8, 7, 1, 2)));
    store.commit(txn).unwrap();
    assert_eq!(store.tip_versions(ns(), "book").unwrap().len(), 2);

    // the key's versions and tree are replaced, also one under a
    // commitment the store held (7); the other key is untouched
    let fresh = MemoryStore::new();
    let mut txn = store.begin(ns());
    txn.import_key("book");
    let (leaf, root, mut v) = book(&mut txn, &fresh, 2, 4, 7);
    v.status = VersionStatus::Canonical;
    let mut put = store.begin(ns());
    put.import_key("book");
    for ((key, hash), node) in txn.nodes() {
        put.node(key, *hash, node.clone());
    }
    put.version(VersionWrite::Put(v.clone()));
    store.commit(put).unwrap();
    assert_eq!(store.tip_versions(ns(), "book").unwrap(), [v]);
    assert!(store.tip_node(ns(), "book", old_leaf).unwrap().is_none());
    assert!(store.tip_node(ns(), "book", old_root).unwrap().is_none());
    assert_eq!(store.tip_node(ns(), "book", leaf).unwrap().unwrap().refs, 1);
    assert_eq!(store.tip_node(ns(), "book", root).unwrap().unwrap().refs, 1);
    assert_eq!(store.tip_versions(ns(), "pool").unwrap(), [pool]);

    // another key's write, or a namespace the store does not hold
    let mut mixed = store.begin(ns());
    mixed.import_key("book");
    mixed.version(VersionWrite::Put(version("pool", 6, 5, 1, 3)));
    let err = store.commit(mixed).unwrap_err();
    assert_eq!(err.class, ErrorClass::MpcFailure, "{err}");
    assert_eq!(store.tip_versions(ns(), "pool").unwrap().len(), 1);
    let mut absent = store.begin(Fr::from(NS + 1));
    absent.import_key("book");
    absent.version(VersionWrite::Put(version("book", 9, 0, 0, 4)));
    conflict(store.commit(absent), "is not held");
}

/// A resync's import writes versions (their status and block as given)
/// and a tree's nodes with their counts; the store lists the tip keys;
/// a version under commitment 0 is refused.
pub fn an_import_writes_versions_and_tree_nodes_and_lists_the_keys<S: Store>(store: &S) {
    use crate::tree::{self, TreeNode};
    let z = tree::zeros(2);
    let leaf = Fr::from(0x1eafu64);
    let empty = |_: Fr| -> Result<Option<TreeNode>, Refusal> { Ok(None) };
    let rebuilt = tree::rebuild(&empty, &z, z[2], &[(1, leaf)]).unwrap();
    let mut txn = store.begin(ns());
    txn.import_namespace(namespace_row(6));
    let mut added = vec![(
        leaf,
        TreeNode::Leaf {
            index: 1,
            vec: vec![shared(9)],
        },
    )];
    added.extend(rebuilt.added.iter().map(|(h, _, n)| (*h, n.clone())));
    rules::TreeNodes {
        read: store,
        key: "book",
    }
    .add_version(&mut txn, rebuilt.root, added)
    .unwrap();
    let mut canonical = version("pool", 5, 0, 0, 1);
    canonical.status = VersionStatus::Canonical;
    canonical.block = 120;
    let live = version("pool", 6, 5, 1, 2);
    let mut book = version("book", 7, 0, 0, 3);
    book.vec = vec![];
    book.tree = Some(VersionTree::Clear(TreeRoot {
        root: rebuilt.root,
        next: 2,
    }));
    for v in [&canonical, &live, &book] {
        txn.version(VersionWrite::Put(v.clone()));
    }
    store.commit(txn).unwrap();
    assert_eq!(store.tip_keys(ns()).unwrap(), ["book", "pool"]);
    assert_eq!(
        store.tip_version(ns(), "pool", Fr::from(5u64)).unwrap(),
        Some(canonical)
    );
    assert_eq!(store.tip_versions(ns(), "pool").unwrap().len(), 2);
    assert_eq!(
        store.tip_version(ns(), "book", Fr::from(7u64)).unwrap(),
        Some(book)
    );
    let stored = store.tip_node(ns(), "book", leaf).unwrap().unwrap();
    assert_eq!(stored.refs, 1);
    let root = store.tip_node(ns(), "book", rebuilt.root).unwrap().unwrap();
    assert_eq!(root.refs, 1, "the version's reference");
    assert!(store.tip_keys(Fr::from(NS + 1)).unwrap().is_empty());
    let mut zero = store.begin(Fr::from(NS + 2));
    zero.import_namespace(namespace_row(7));
    zero.version(VersionWrite::Put(version("pool", 0, 0, 0, 4)));
    assert_eq!(
        store.commit(zero).unwrap_err().class,
        ErrorClass::MpcFailure
    );
}
