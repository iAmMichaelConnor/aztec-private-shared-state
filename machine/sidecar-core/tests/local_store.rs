//! The local store (sidecar-core's `local`): the core's store suite on it,
//! and what is particular to it: the log's replay, a torn last record,
//! corruption, compaction, the files' modes and the directory lock.

use std::fs::OpenOptions;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use sidecar_core::field::Fr;
use sidecar_core::local::{LOG_FILE, LocalStore};
use sidecar_core::store::testing::{
    self, chain_round, client_round, id, namespace_row, node_keys, ns,
};
use sidecar_core::store::{RequestStatus, Store, StoreRead, rules};
use sidecar_test_fixtures::dirs::TempDir;

/// A store directory under `dir` no other case uses.
fn sub(dir: &TempDir) -> PathBuf {
    static COUNTER: AtomicUsize = AtomicUsize::new(0);
    dir.path()
        .join(format!("case-{}", COUNTER.fetch_add(1, Ordering::Relaxed)))
}

#[test]
fn the_store_suite_on_local_store() {
    let dir = TempDir::new("local-suite");
    let ran = testing::suite_without_values(|| LocalStore::open(sub(&dir)).unwrap());
    eprintln!("local store: {ran} suite cases passed");
    // the shared cases and the node-held refusal
    assert_eq!(ran, testing::cases_without_values::<LocalStore>().len() + 1);
}

/// A commit of only `tip_nodes` or only `tip_blobs` writes is node-held
/// state the local store has no table for: refused (500), nothing written.
#[test]
fn tree_node_and_blob_writes_are_refused() {
    let dir = TempDir::new("local-node-held");
    let path = sub(&dir);
    let store = LocalStore::open(&path).unwrap();
    let before = log_len(&path);
    let mut nodes = store.begin(ns());
    nodes.node("tree", Fr::from(1u64), None);
    let mut blobs = store.begin(ns());
    blobs.blob("tree", "doram", Some(vec![1]));
    for txn in [nodes, blobs] {
        let err = store.commit(txn).unwrap_err();
        assert_eq!(err.status(), 500, "{err}");
        assert!(err.message.contains("no node-held values"), "{err}");
    }
    assert_eq!(log_len(&path), before);
}

fn log_len(store_dir: &Path) -> u64 {
    std::fs::metadata(store_dir.join(LOG_FILE)).unwrap().len()
}

fn truncate(store_dir: &Path, len: u64) {
    OpenOptions::new()
        .write(true)
        .open(store_dir.join(LOG_FILE))
        .unwrap()
        .set_len(len)
        .unwrap();
}

fn flip_byte(store_dir: &Path, at: u64) {
    let path = store_dir.join(LOG_FILE);
    let mut bytes = std::fs::read(&path).unwrap();
    bytes[at as usize] ^= 0x40;
    std::fs::write(&path, bytes).unwrap();
}

#[test]
fn a_reopened_local_store_replays_every_commit() {
    let dir = TempDir::new("local-replay");
    let path = sub(&dir);
    let keys = node_keys();
    let (a, x) = (Fr::from(0xa1u64), Fr::from(0x77u64));
    let (row1, row2) = {
        let store = LocalStore::open(&path).unwrap();
        let mut txn = store.begin(ns());
        txn.register_namespace(namespace_row(3));
        store.commit(txn).unwrap();
        let mut txn = store.begin(ns());
        txn.advance_seq(1);
        store.commit(txn).unwrap();
        client_round(&store, 1, &[a], &[("0xa002", x)]).unwrap();
        client_round(&store, 2, &[x], &[]).unwrap();
        rules::restore(&store, &keys, ns(), id(2)).unwrap();
        (
            store.request(ns(), id(1)).unwrap().unwrap(),
            store.request(ns(), id(2)).unwrap().unwrap(),
        )
    };
    let store = LocalStore::open(&path).unwrap();
    assert_eq!(
        store.namespace(ns()).unwrap(),
        Some(sidecar_core::store::NamespaceRow {
            seq: 1,
            ..namespace_row(3)
        })
    );
    assert_eq!(store.request(ns(), id(1)).unwrap(), Some(row1));
    assert_eq!(store.request(ns(), id(2)).unwrap(), Some(row2.clone()));
    assert_eq!(row2.status, RequestStatus::RolledBack);
    assert!(store.consumed(ns(), a).unwrap().is_some());
    assert!(store.consumed(ns(), x).unwrap().is_none());
}

#[test]
fn a_torn_last_record_is_dropped_on_reload() {
    let dir = TempDir::new("local-torn");
    let a = Fr::from(0xa1u64);
    // Cut the second commit's record anywhere: in its header, in its payload,
    // one byte short.
    for cut in [1u64, 5, 12, 40, u64::MAX] {
        let path = sub(&dir);
        let (after_first, after_second) = {
            let store = LocalStore::open(&path).unwrap();
            client_round(&store, 1, &[a], &[]).unwrap();
            let after_first = log_len(&path);
            client_round(
                &store,
                2,
                &[Fr::from(0xb1u64)],
                &[("0xa002", Fr::from(9u64))],
            )
            .unwrap();
            (after_first, log_len(&path))
        };
        let record = after_second - after_first;
        let keep = after_first + cut.min(record - 1);
        truncate(&path, keep);

        let store = LocalStore::open(&path).unwrap();
        assert!(store.request(ns(), id(1)).unwrap().is_some(), "cut {cut}");
        assert!(store.request(ns(), id(2)).unwrap().is_none(), "cut {cut}");
        assert!(store.consumed(ns(), Fr::from(0xb1u64)).unwrap().is_none());
        assert_eq!(log_len(&path), after_first, "the torn bytes are cut off");
        // The store goes on from the last whole record.
        client_round(&store, 3, &[Fr::from(0xc1u64)], &[]).unwrap();
        drop(store);
        let store = LocalStore::open(&path).unwrap();
        assert!(store.request(ns(), id(3)).unwrap().is_some());
        assert!(store.consumed(ns(), a).unwrap().is_some());
    }
}

#[test]
fn a_bad_checksum_drops_the_last_record_and_refuses_an_earlier_one() {
    let dir = TempDir::new("local-checksum");
    let path = sub(&dir);
    let after_first = {
        let store = LocalStore::open(&path).unwrap();
        client_round(&store, 1, &[Fr::from(1u64)], &[]).unwrap();
        let after_first = log_len(&path);
        client_round(&store, 2, &[Fr::from(2u64)], &[]).unwrap();
        after_first
    };
    // A flipped byte in the last record: a torn write, dropped.
    flip_byte(&path, log_len(&path) - 3);
    let store = LocalStore::open(&path).unwrap();
    assert!(store.request(ns(), id(1)).unwrap().is_some());
    assert!(store.request(ns(), id(2)).unwrap().is_none());
    client_round(&store, 2, &[Fr::from(2u64)], &[]).unwrap();
    drop(store);
    // A flipped byte in an earlier record: corruption, refused.
    flip_byte(&path, after_first - 3);
    let err = LocalStore::open(&path)
        .err()
        .expect("a corrupt log is refused");
    assert!(err.to_string().contains("corrupt"), "{err}");
}

// The first record's length (after the 8-byte format marker) altered: its
// header checksum fails with records after it, so the store refuses to open
// rather than truncating the committed records as a torn tail.
#[test]
fn a_bad_length_before_the_last_record_is_refused() {
    let dir = TempDir::new("local-length");
    let path = sub(&dir);
    {
        let store = LocalStore::open(&path).unwrap();
        client_round(&store, 1, &[Fr::from(1u64)], &[]).unwrap();
        client_round(&store, 2, &[Fr::from(2u64)], &[]).unwrap();
    }
    let len = log_len(&path);
    flip_byte(&path, 10);
    let err = LocalStore::open(&path)
        .err()
        .expect("a corrupt length is refused");
    assert!(err.to_string().contains("corrupt"), "{err}");
    assert_eq!(log_len(&path), len, "nothing is truncated");
}

#[test]
fn local_pruning_rewrites_the_log_and_keeps_the_consumed_set() {
    let dir = TempDir::new("local-prune");
    let path = sub(&dir);
    {
        let store = LocalStore::open(&path).unwrap();
        for n in 1..=20 {
            client_round(
                &store,
                n,
                &[Fr::from(n as u64)],
                &[("0xa002", Fr::from(100 + n as u64))],
            )
            .unwrap();
        }
        let before = log_len(&path);
        // created_at is 1000 + n: rounds 1 to 14 are older than 1015.
        assert_eq!(store.prune_requests(1015).unwrap(), 14);
        assert!(log_len(&path) < before);
        assert!(store.request(ns(), id(14)).unwrap().is_none());
        assert!(store.request(ns(), id(15)).unwrap().is_some());
        // Appends go on after the rewrite.
        client_round(&store, 21, &[Fr::from(21u64)], &[]).unwrap();
    }
    let store = LocalStore::open(&path).unwrap();
    for n in 1..=21u8 {
        assert_eq!(
            store.request(ns(), id(n)).unwrap().is_some(),
            n >= 15,
            "request {n}"
        );
        assert_eq!(
            store
                .consumed(ns(), Fr::from(n as u64))
                .unwrap()
                .map(|r| r.request_id),
            Some(id(n)),
            "consumed entry of request {n}"
        );
    }
    assert_eq!(store.prune_requests(1015).unwrap(), 0);
}

/// A rollback's dead records, and a later round's deletion of one, survive
/// replay and the pruning rewrite.
#[test]
fn dead_records_survive_replay_and_compaction() {
    let dir = TempDir::new("local-dead");
    let path = sub(&dir);
    let keys = node_keys();
    let (a, b, x, y) = (
        Fr::from(0xa1u64),
        Fr::from(0xb1u64),
        Fr::from(0x77u64),
        Fr::from(0x78u64),
    );
    {
        let store = LocalStore::open(&path).unwrap();
        client_round(&store, 1, &[a], &[("0xa002", x)]).unwrap();
        rules::restore(&store, &keys, ns(), id(1)).unwrap();
        client_round(&store, 2, &[b], &[("0xa002", y)]).unwrap();
        rules::restore(&store, &keys, ns(), id(2)).unwrap();
        // The old record again, and the same record x as the rolled-back round.
        client_round(&store, 3, &[a], &[("0xa002", x)]).unwrap();
    }
    let check = |store: &LocalStore, when: &str| {
        assert_eq!(store.dead_record(ns(), x).unwrap(), None, "{when}");
        assert_eq!(
            store.dead_record(ns(), y).unwrap().map(|d| d.request_id),
            Some(id(2)),
            "{when}"
        );
    };
    let store = LocalStore::open(&path).unwrap();
    check(&store, "after replay");
    assert_eq!(store.prune_requests(2000).unwrap(), 3);
    drop(store);
    check(&LocalStore::open(&path).unwrap(), "after the rewrite");
}

#[test]
fn a_chain_request_id_survives_replay_and_compaction() {
    let dir = TempDir::new("local-chain");
    let path = sub(&dir);
    let chain = Fr::from(0xc4a1u64);
    {
        let store = LocalStore::open(&path).unwrap();
        chain_round(&store, 1, Some(chain), 1000).unwrap();
        chain_round(&store, 2, Some(chain), 1010).unwrap();
        chain_round(&store, 3, None, 1020).unwrap();
        // The rewrite drops request 1 and keeps the others' chain request ids.
        assert_eq!(store.prune_requests(1005).unwrap(), 1);
        chain_round(&store, 4, Some(chain), 1011).unwrap();
    }
    let store = LocalStore::open(&path).unwrap();
    assert_eq!(
        store
            .fetch_by_chain_request_id(ns(), chain)
            .unwrap()
            .request_id,
        id(4)
    );
    let chain_of = |n| {
        store
            .request(ns(), id(n))
            .unwrap()
            .unwrap()
            .chain_request_id
    };
    assert_eq!(chain_of(2), Some(chain));
    assert_eq!(chain_of(3), None);
    assert!(store.request(ns(), id(1)).unwrap().is_none());
}

/// Receipts survive replay; a replacement replays as the last write; the
/// pruning rewrite drops only the receipts past expiry + stale period and
/// keeps every other row.
#[test]
fn receipts_survive_replay_and_compaction() {
    let dir = TempDir::new("local-receipts");
    let path = sub(&dir);
    let early = testing::receipt_row(1, 100, Some(50));
    let late = testing::receipt_row(2, 200, Some(50));
    let replaced = sidecar_core::store::ReceiptRow {
        expiry_block: 300,
        ..late.clone()
    };
    {
        let store = LocalStore::open(&path).unwrap();
        chain_round(&store, 1, None, 1000).unwrap();
        store.put_receipt(ns(), early.clone()).unwrap();
        store.put_receipt(ns(), late.clone()).unwrap();
        store.put_receipt(ns(), replaced.clone()).unwrap();
    }
    {
        let store = LocalStore::open(&path).unwrap();
        assert_eq!(
            store.receipt(ns(), early.request_id).unwrap(),
            Some(early.clone())
        );
        assert_eq!(
            store.receipt(ns(), late.request_id).unwrap(),
            Some(replaced.clone())
        );
        let before = log_len(&path);
        let expired = store.expired_receipts(151).unwrap();
        assert_eq!(expired, [(ns(), early.request_id)]);
        assert_eq!(store.prune_receipts(151, &expired).unwrap(), 1);
        assert!(log_len(&path) < before, "the log was not rewritten");
    }
    let store = LocalStore::open(&path).unwrap();
    assert!(store.receipt(ns(), early.request_id).unwrap().is_none());
    assert_eq!(
        store.receipt(ns(), late.request_id).unwrap(),
        Some(replaced)
    );
    assert!(store.request(ns(), id(1)).unwrap().is_some());
}

/// The mode bits of `path`.
#[cfg(unix)]
fn mode(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

/// The store directory is the node's alone (0700) and so are its log and lock
/// (0600), when created, after a compaction (the log is a new file renamed
/// over the old), and after reopening a store whose files had looser modes.
#[cfg(unix)]
#[test]
fn the_local_store_is_private_to_its_user() {
    use std::os::unix::fs::PermissionsExt;
    let dir = TempDir::new("local-modes");
    let path = sub(&dir);
    let log = path.join(LOG_FILE);
    let lock = path.join("store.lock");
    let check = |when: &str| {
        assert_eq!(mode(&path), 0o700, "{when}: the store directory");
        assert_eq!(mode(&log), 0o600, "{when}: the log");
        assert_eq!(mode(&lock), 0o600, "{when}: the lock");
    };
    {
        let store = LocalStore::open(&path).unwrap();
        check("created");
        for n in 1..=3 {
            client_round(&store, n, &[Fr::from(n as u64)], &[]).unwrap();
        }
        check("after commits");
        // created_at is 1000 + n: the first two rows are pruned and the log
        // is rewritten into a new file.
        assert_eq!(store.prune_requests(1003).unwrap(), 2);
        check("after a compaction");
        assert!(!path.join("store.log.compact").exists());
    }
    // A store whose files were left readable by others is narrowed on open.
    for (p, m) in [(&path, 0o755), (&log, 0o644), (&lock, 0o644)] {
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(m)).unwrap();
    }
    let store = LocalStore::open(&path).unwrap();
    check("reopened");
    assert!(store.request(ns(), id(3)).unwrap().is_some());
}

#[test]
fn a_local_store_is_open_in_one_process_at_a_time() {
    let dir = TempDir::new("local-lock");
    let path = sub(&dir);
    let store = LocalStore::open(&path).unwrap();
    let err = LocalStore::open(&path)
        .err()
        .expect("the second open is refused");
    assert!(err.to_string().contains("another process"), "{err}");
    drop(store);
    LocalStore::open(&path).unwrap();
}
