//! The node's backup files (sidecar-node's `backup` module): a store
//! backup's rows come back as they were exported, every kind of row with
//! this node's pairs; a backup opens under its key only, for its own node
//! only; the key directory backs up and restores into a lost directory
//! only; a backup key inside the node's own directories is refused.
//!
//! The delta resync a store backup is restored by runs in sidecar-core's
//! `tests/recovery.rs`, and through the three admin sockets, then a round,
//! in sidecar-orchestrator's `tests/node_held.rs`.

use sidecar_core::ErrorClass;
use sidecar_core::backup::{StoreExport, export_namespace};
use sidecar_core::field::Fr;
use sidecar_core::keys::KeyFiles;
use sidecar_core::store::testing::{
    client_round, id, manifest_row, node_keys, ns, receipt_row, round, shared, shared_receipt_row,
    tip_round, version,
};
use sidecar_core::store::{MemoryStore, PackageRow, Store, rules};
use sidecar_core::tree::TreeNode;
use sidecar_node::backup::{
    self, BackupKey, Kind, decode_export, encode_export, read_key, read_store, restore_keys,
    write_keys,
};
use sidecar_node::replace::KEY_SETS_FILE;
use sidecar_test_fixtures::dirs::TempDir;

fn key(text: char) -> BackupKey {
    BackupKey::parse(&text.to_string().repeat(64)).unwrap()
}

/// A store with a row of every kind under the test namespace: the
/// namespace, a package-less node-held round (a `values` row and a
/// consumed state), tip versions, a rolled-back client-held round (a
/// rolled-back `requests` row and a dead record, which the export leaves
/// out), non-secret-shared and secret-shared receipt rows, and two contract
/// manifest versions with their packages.
fn populated() -> StoreExport {
    let store = MemoryStore::new();
    let mut txn = store.begin(ns());
    txn.register_namespace(sidecar_core::store::testing::namespace_row(3));
    txn.put_request(sidecar_core::store::testing::new_request(9, 900));
    store.commit(txn).unwrap();
    round(
        &store,
        1,
        &[],
        &[Fr::from(0x51u64)],
        &[("pool", vec![shared(5), shared(7)], Fr::from(0x901u64))],
    )
    .unwrap();
    let view = rules::VersionView {
        slot: Fr::from(0xa1u64),
        head: 0,
        block: 10,
        settled: 10,
        ..Default::default()
    };
    tip_round(
        &store,
        2,
        "0xa002",
        Some(version("0xa002", 0xa1, 0, 0, 2)),
        view,
    )
    .unwrap();
    client_round(&store, 3, &[], &[("0xff02", Fr::from(0x71u64))]).unwrap();
    rules::restore(&store, &node_keys(), ns(), id(3)).unwrap();
    assert_eq!(store.dead_records(ns()).unwrap().len(), 1);
    store
        .put_receipt(ns(), receipt_row(1, 500, Some(50)))
        .unwrap();
    store
        .put_receipt(ns(), shared_receipt_row(2, 500, None))
        .unwrap();
    let mut export = StoreExport {
        party: 1,
        namespaces: vec![export_namespace(&store, ns()).unwrap()],
    };
    // a clear tree's two kinds of node (the store above holds no tree key)
    export.namespaces[0].nodes = vec![
        (
            "0xa003".into(),
            Fr::from(0x31u64),
            TreeNode::Inner {
                left: Fr::from(1u64),
                right: Fr::from(2u64),
            },
        ),
        (
            "0xa003".into(),
            Fr::from(0x32u64),
            TreeNode::Leaf {
                index: 4,
                vec: vec![shared(9), sidecar_core::bind::Elem::Public(Fr::from(3u64))],
            },
        ),
    ];
    // holder blobs (an oblivious key's DORAM head and a journal), as bytes
    export.namespaces[0].blobs = vec![
        ("0xa005".into(), "oram".into(), vec![1, 0, 7, 255]),
        ("0xa005".into(), "journal.0x01".into(), vec![]),
    ];
    // the held contract manifest versions of an upgradable namespace, oldest
    // first, and a package of each
    export.namespaces[0].manifests = vec![manifest_row(0xa1, 1), manifest_row(0xa2, 2)];
    export.namespaces[0].packages = [(0xa1u64, 1), (0xa2, 2)]
        .map(|(hash, seq)| PackageRow {
            name: "amm_swap".into(),
            manifest_hash: Fr::from(hash),
            circuit_json: format!("{{\"v\":{hash}}}").into_bytes(),
            manifest: serde_json::json!({"manifest": 1, "circuit": "amm_swap"}),
            vk: vec![hash as u8],
            vk_hash: Fr::from(hash + 0x100),
            disabled: false,
            seq,
        })
        .to_vec();
    export
}

#[test]
fn a_store_backup_holds_every_row_as_it_was_exported() {
    let export = populated();
    let counts = export.counts();
    assert_eq!(
        (
            counts.namespaces,
            counts.versions,
            counts.tree_nodes,
            counts.values,
            counts.consumed,
            counts.receipts,
        ),
        (1, 1, 2, 1, 1, 2),
        "{counts:?}"
    );
    assert_eq!((counts.requests, counts.blobs), (4, 2), "{counts:?}");
    let ns_export = &export.namespaces[0];
    assert!(
        ns_export
            .requests
            .iter()
            .any(|r| r.status == sidecar_core::store::RequestStatus::RolledBack)
    );
    let bytes = encode_export(&export);
    assert_eq!(decode_export(1, &bytes).unwrap(), export);
    let mut cut = bytes.clone();
    cut.pop();
    assert!(decode_export(1, &cut).is_err());

    let dir = TempDir::new("backup-store");
    let path = dir.path().join("node1.store");
    let sealed = backup::seal(&key('a'), Kind::Store, 1, 1000, bytes).unwrap();
    std::fs::write(&path, sealed).unwrap();
    assert_eq!(read_store(&path, &key('a'), 1).unwrap(), export);
    let refused = |party: usize, k: char, needle: &str| {
        let err = read_store(&path, &key(k), party).unwrap_err();
        assert_eq!(err.class, ErrorClass::BadRequest, "{err}");
        assert!(err.message.contains(needle), "{err}");
    };
    refused(1, 'b', "does not open under this backup key");
    refused(2, 'a', "node 1's, not this node's (2)");
}

#[test]
fn a_store_backup_of_another_format_is_refused_naming_both_formats() {
    let mut bytes = encode_export(&populated());
    assert_eq!(bytes[0], 6, "the store backup format");
    let dir = TempDir::new("backup-format");
    for format in [5u8, 7] {
        bytes[0] = format;
        let err = decode_export(1, &bytes).unwrap_err();
        assert!(
            err.contains(&format!("a store backup of format {format}"))
                && err.contains("reads format 6 only: take a new store backup"),
            "{err}"
        );
        let path = dir.path().join(format!("node1-format{format}.store"));
        let sealed = backup::seal(&key('a'), Kind::Store, 1, 1000, bytes.clone()).unwrap();
        std::fs::write(&path, sealed).unwrap();
        let err = read_store(&path, &key('a'), 1).unwrap_err();
        assert_eq!(err.class, ErrorClass::BadRequest, "{err}");
        assert!(err.message.contains(&format!("format {format}")), "{err}");
    }
}

#[test]
fn the_key_directory_restores_into_a_lost_directory_only() {
    let dir = TempDir::new("backup-keys");
    let files = KeyFiles::new(dir.path().join("keys"));
    let keys = node_keys();
    files.write(&keys).unwrap();
    std::fs::write(files.master_share_path(), "0x01 0x02\n").unwrap();
    let out = dir.path().join("node0.keys");
    let held = write_keys(&files, 0, &out, &key('c'), 1000).unwrap();
    assert_eq!(held, [KeyFiles::ENC, KeyFiles::SIG, KeyFiles::MASTER_SHARE]);
    // never over an existing file
    assert!(write_keys(&files, 0, &out, &key('c'), 1000).is_err());

    // into a directory that holds the keys: refused, nothing changed
    let err = restore_keys(&files, 0, &out, &key('c')).unwrap_err();
    assert!(
        format!("{err:#}").contains("lost key directory only"),
        "{err:#}"
    );
    // into the lost directory: every file back, private
    let lost = KeyFiles::new(dir.path().join("lost/keys"));
    let err = restore_keys(&lost, 1, &out, &key('c')).unwrap_err();
    assert!(format!("{err:#}").contains("node 0's"), "{err:#}");
    let err = restore_keys(&lost, 0, &out, &key('d')).unwrap_err();
    assert!(format!("{err:#}").contains("does not open"), "{err:#}");
    restore_keys(&lost, 0, &out, &key('c')).unwrap();
    assert_eq!(lost.read().unwrap().public_keys(), keys.public_keys());
    for name in held {
        let path = lost.dir().join(&name);
        assert_eq!(
            std::fs::read(&path).unwrap(),
            std::fs::read(files.dir().join(&name)).unwrap()
        );
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "{}", path.display());
    }
    // a store backup is not a key backup
    let store = dir.path().join("node0.store");
    let sealed = backup::seal(&key('c'), Kind::Store, 0, 1000, vec![1]).unwrap();
    std::fs::write(&store, sealed).unwrap();
    let again = KeyFiles::new(dir.path().join("again/keys"));
    let err = restore_keys(&again, 0, &store, &key('c')).unwrap_err();
    assert!(
        format!("{err:#}").contains("not a key directory backup"),
        "{err:#}"
    );
}

// A node that holds secret-shared on-chain epoch scalars backs them up with the
// rest of its key directory, the pending ones included, and its declared
// key-set rotations with them; a restored directory holds both again.
#[test]
fn the_key_directory_backup_carries_the_contract_epochs() {
    let dir = TempDir::new("backup-epochs");
    let files = KeyFiles::new(dir.path().join("keys"));
    let mut keys = node_keys();
    let contract = sidecar_core::field::Fr::from(0xc0ffeeu64);
    let scalar = keys.enc_scalar();
    keys.epochs_mut().record(contract, 1, scalar).unwrap();
    keys.epochs_mut().sign(contract, 2, scalar).unwrap();
    files.write(&keys).unwrap();
    std::fs::write(files.master_share_path(), "0x01 0x02\n").unwrap();
    let key_sets = files.dir().join(KEY_SETS_FILE);
    std::fs::write(&key_sets, b"{\"declared\": []}\n").unwrap();
    let out = dir.path().join("node0.keys");
    let held = write_keys(&files, 0, &out, &key('e'), 1000).unwrap();
    assert!(held.iter().any(|n| n == KeyFiles::EPOCHS), "{held:?}");
    assert!(held.iter().any(|n| n == KEY_SETS_FILE), "{held:?}");
    let lost = KeyFiles::new(dir.path().join("lost/keys"));
    restore_keys(&lost, 0, &out, &key('e')).unwrap();
    let back = lost.read().unwrap();
    assert_eq!(back.epochs(), keys.epochs());
    assert_eq!(back.epochs().pending(contract), [2]);
    assert_eq!(back.epochs().scalar(contract, 1), Some(scalar));
    assert_eq!(
        std::fs::read(lost.dir().join(KEY_SETS_FILE)).unwrap(),
        std::fs::read(&key_sets).unwrap()
    );
}

#[test]
fn a_backup_key_is_read_from_outside_the_node_s_directories_only() {
    let dir = TempDir::new("backup-key");
    let offline = dir.path().join("media/backup.key");
    std::fs::create_dir_all(offline.parent().unwrap()).unwrap();
    backup::write_new_key(&offline).unwrap();
    assert!(
        backup::write_new_key(&offline).is_err(),
        "never overwritten"
    );
    let node_dir = dir.path().join("node");
    std::fs::create_dir_all(node_dir.join("keys")).unwrap();
    let k = read_key(&offline, &[&node_dir]).unwrap();
    let inside = node_dir.join("keys/backup.key");
    std::fs::copy(&offline, &inside).unwrap();
    let err = read_key(&inside, &[&node_dir]).unwrap_err();
    assert!(format!("{err:#}").contains("keep it offline"), "{err:#}");
    // the same key, read from where it is allowed
    assert_eq!(read_key(&offline, &[&node_dir.join("keys")]).unwrap(), k);
}
