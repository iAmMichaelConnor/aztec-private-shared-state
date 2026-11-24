//! The suite's cases for the `namespaces` and `packages` tables.

use super::*;

pub fn nsk_app_row_is_written_once_and_read_only_under_its_namespace<S: Store>(store: &S) {
    let mut txn = store.begin(ns());
    txn.register_namespace(namespace_row(3));
    store.commit(txn).unwrap();
    let mut other = store.begin(Fr::from(0xbeefu64));
    other.register_namespace(namespace_row(8));
    store.commit(other).unwrap();

    assert_eq!(store.namespace(ns()).unwrap(), Some(namespace_row(3)));
    assert_eq!(
        store.load_nsk_app(ns()).unwrap(),
        Some(namespace_row(3).nsk_app)
    );
    assert_eq!(
        store.load_nsk_app(Fr::from(0xbeefu64)).unwrap(),
        Some(namespace_row(8).nsk_app)
    );
    assert_eq!(store.load_nsk_app(Fr::from(0xdeadu64)).unwrap(), None);

    let mut again = store.begin(ns());
    again.register_namespace(namespace_row(5));
    conflict(store.commit(again), "written once");
    assert_eq!(
        store.load_nsk_app(ns()).unwrap(),
        Some(namespace_row(3).nsk_app)
    );
}

pub fn registry_seq_advances_by_one<S: Store>(store: &S) {
    let mut first = store.begin(ns());
    first.register_namespace(NamespaceRow {
        seq: 1,
        ..namespace_row(3)
    });
    conflict(store.commit(first), "seq 0");
    let mut unknown = store.begin(ns());
    unknown.advance_seq(1);
    conflict(store.commit(unknown), "not registered");

    let mut first = store.begin(ns());
    first.register_namespace(namespace_row(3));
    store.commit(first).unwrap();
    for (seq, ok) in [(2, false), (0, false), (1, true), (1, false), (2, true)] {
        let mut txn = store.begin(ns());
        txn.advance_seq(seq);
        let result = store.commit(txn);
        assert_eq!(result.is_ok(), ok, "seq {seq}: {result:?}");
        if !ok {
            conflict(result, "is not the namespace's next");
        }
    }
    assert_eq!(store.namespace(ns()).unwrap().unwrap().seq, 2);
}

pub fn a_repair_replaces_only_the_share<S: Store>(store: &S) {
    let mut absent = store.begin(ns());
    absent.repair_namespace(namespace_row(3));
    conflict(store.commit(absent), "needs the stored namespace row");
    let mut first = store.begin(ns());
    first.register_namespace(namespace_row(3));
    store.commit(first).unwrap();

    let fresh = Share::new(Fr::from(40u64), Fr::from(41u64));
    let mut other_owner = store.begin(ns());
    other_owner.repair_namespace(NamespaceRow {
        nsk_app: fresh,
        ..namespace_row(4)
    });
    conflict(store.commit(other_owner), "keep the stored owner");
    let mut repair = store.begin(ns());
    repair.repair_namespace(NamespaceRow {
        nsk_app: fresh,
        ..namespace_row(3)
    });
    store.commit(repair).unwrap();
    let row = store.namespace(ns()).unwrap().unwrap();
    assert_eq!(row.nsk_app, fresh);
    assert_eq!(
        row,
        NamespaceRow {
            nsk_app: fresh,
            ..namespace_row(3)
        }
    );

    let mut next = store.begin(ns());
    next.advance_seq(1);
    store.commit(next).unwrap();
    let mut late = store.begin(ns());
    late.repair_namespace(namespace_row(3));
    conflict(store.commit(late), "only while the stored seq is 0, not 1");
}

pub fn namespaces_and_package_names_are_listed<S: Store>(store: &S) {
    assert!(store.namespaces().unwrap().is_empty());
    assert!(store.package_names(ns()).unwrap().is_empty());
    let package = |name: &str| PackageRow {
        name: name.into(),
        manifest_hash: Fr::from(0xaau64),
        circuit_json: b"{}".to_vec(),
        manifest: serde_json::json!({"manifest": 1}),
        vk: vec![1],
        vk_hash: Fr::from(0xc1u64),
        disabled: false,
        seq: 0,
    };
    // Two namespaces, committed in descending order; packages out of
    // name order, one of them disabled.
    let other = Fr::from(0x1234u64);
    assert!(other < ns() || other > ns());
    for (namespace, seed, names) in [
        (other.max(ns()), 11, &["zeta", "amm_swap", "Zed"][..]),
        (other.min(ns()), 12, &["b"][..]),
    ] {
        let mut txn = store.begin(namespace);
        txn.register_namespace(namespace_row(seed));
        txn.put_manifest(manifest_row(0xaa, 0));
        for name in names {
            txn.put_package(package(name));
        }
        store.commit(txn).unwrap();
    }
    let mut disable = store.begin(other.max(ns()));
    disable.put_package(PackageRow {
        disabled: true,
        ..package("zeta")
    });
    store.commit(disable).unwrap();
    assert_eq!(
        store.namespaces().unwrap(),
        vec![other.min(ns()), other.max(ns())]
    );
    assert_eq!(
        store.package_names(other.max(ns())).unwrap(),
        ["Zed", "amm_swap", "zeta"]
    );
    assert_eq!(store.package_names(other.min(ns())).unwrap(), ["b"]);
    assert!(store.package_names(Fr::from(7u64)).unwrap().is_empty());
}

pub fn packages_and_disable<S: Store>(store: &S) {
    let package = PackageRow {
        name: "amm_swap".into(),
        manifest_hash: Fr::from(0xaau64),
        circuit_json: b"{\"noir_version\":\"1.0.0\"}".to_vec(),
        manifest: serde_json::json!({"manifest": 1, "circuit": "amm_swap", "state_keys": {"reads": 1}}),
        vk: vec![1, 2, 0, 255],
        vk_hash: Fr::from(0xc1u64),
        disabled: false,
        seq: 0,
    };
    // a package of a contract manifest the namespace does not hold
    let mut orphan = store.begin(ns());
    orphan.register_namespace(namespace_row(3));
    orphan.put_package(package.clone());
    internal(store.commit(orphan), "which the namespace does not hold");
    // REGISTER: the namespace row, its contract manifest and its package
    let mut txn = store.begin(ns());
    txn.register_namespace(namespace_row(3));
    txn.put_manifest(manifest_row(0xaa, 0));
    txn.put_package(package.clone());
    store.commit(txn).unwrap();
    assert_eq!(
        store.package(ns(), "amm_swap").unwrap(),
        Some(package.clone())
    );
    assert_eq!(
        store.contract_manifest(ns()).unwrap(),
        Some(manifest_row(0xaa, 0))
    );
    assert!(store.contract_manifest(Fr::from(1u64)).unwrap().is_none());
    // DISABLE rewrites the row (registry::disable) with the next seq.
    let disabled = PackageRow {
        disabled: true,
        seq: 1,
        ..package.clone()
    };
    let mut disable = store.begin(ns());
    disable.advance_seq(1);
    disable.put_package(disabled.clone());
    store.commit(disable).unwrap();
    assert_eq!(store.package(ns(), "amm_swap").unwrap(), Some(disabled));
    assert!(store.package(Fr::from(1u64), "amm_swap").unwrap().is_none());
    // the same contract manifest again re-enables it
    let enabled = PackageRow {
        seq: 2,
        ..package.clone()
    };
    let mut again = store.begin(ns());
    again.advance_seq(2);
    again.put_manifest(manifest_row(0xaa, 2));
    again.put_package(enabled.clone());
    store.commit(again).unwrap();
    assert_eq!(store.package(ns(), "amm_swap").unwrap(), Some(enabled));
    // another contract manifest replaces the version: its packages only
    let other = PackageRow {
        name: "amm_init".into(),
        manifest_hash: Fr::from(0xbbu64),
        seq: 3,
        ..package
    };
    let mut replace = store.begin(ns());
    replace.advance_seq(3);
    replace.put_manifest(manifest_row(0xbb, 3));
    replace.put_package(other.clone());
    store.commit(replace).unwrap();
    assert_eq!(
        store.contract_manifest(ns()).unwrap(),
        Some(manifest_row(0xbb, 3))
    );
    assert!(store.package(ns(), "amm_swap").unwrap().is_none());
    assert_eq!(store.package(ns(), "amm_init").unwrap(), Some(other));
    assert_eq!(store.package_names(ns()).unwrap(), ["amm_init"]);
}

/// A namespace under upgrades keeps the newest `MAX_HELD_VERSIONS` versions
/// with their packages, by seq; the newest answers `contract_manifest` and
/// `package`, every held one `package_in`; a version without upgrades
/// written over them leaves itself alone.
pub fn upgradable_namespaces_keep_their_newest_versions<S: Store>(store: &S) {
    let version = |hash: u64, seq: u64| ManifestRow {
        document: serde_json::json!({"contract_manifest": 1, "upgrades": "circuits", "name": format!("m{hash}")}),
        ..manifest_row(hash, seq)
    };
    let package = |hash: u64, seq: u64| PackageRow {
        name: "amm_swap".into(),
        manifest_hash: Fr::from(hash),
        circuit_json: format!("{{\"v\":{hash}}}").into_bytes(),
        manifest: serde_json::json!({"manifest": 1, "circuit": "amm_swap"}),
        vk: vec![hash as u8],
        vk_hash: Fr::from(hash + 0x100),
        disabled: false,
        seq,
    };
    let mut first = store.begin(ns());
    first.register_namespace(namespace_row(3));
    first.put_manifest(version(0xa1, 0));
    first.put_package(package(0xa1, 0));
    store.commit(first).unwrap();
    for (hash, seq) in [(0xa2, 1), (0xa3, 2), (0xa4, 3)] {
        let mut txn = store.begin(ns());
        txn.advance_seq(seq);
        txn.put_manifest(version(hash, seq));
        txn.put_package(package(hash, seq));
        store.commit(txn).unwrap();
    }
    let held: Vec<Fr> = store
        .contract_manifests(ns())
        .unwrap()
        .iter()
        .map(|m| m.manifest_hash)
        .collect();
    assert_eq!(held, [0xa4u64, 0xa3, 0xa2].map(Fr::from));
    assert_eq!(
        store.contract_manifest(ns()).unwrap(),
        Some(version(0xa4, 3))
    );
    assert_eq!(
        store.package(ns(), "amm_swap").unwrap(),
        Some(package(0xa4, 3))
    );
    assert_eq!(
        store
            .package_in(ns(), Fr::from(0xa2u64), "amm_swap")
            .unwrap(),
        Some(package(0xa2, 1))
    );
    assert_eq!(
        store
            .package_in(ns(), Fr::from(0xa1u64), "amm_swap")
            .unwrap(),
        None
    );
    assert_eq!(store.package_names(ns()).unwrap(), ["amm_swap"]);
    // a version without upgrades keeps nothing else
    let mut fixed = store.begin(ns());
    fixed.advance_seq(4);
    fixed.put_manifest(manifest_row(0xa5, 4));
    store.commit(fixed).unwrap();
    assert_eq!(
        store.contract_manifests(ns()).unwrap(),
        [manifest_row(0xa5, 4)]
    );
    assert_eq!(
        store
            .package_in(ns(), Fr::from(0xa4u64), "amm_swap")
            .unwrap(),
        None
    );
}

/// What a resync and a store backup copy of an upgradable namespace
/// ([`held_versions`]): every held version, oldest first, each with its
/// packages; a namespace import that writes them in that order holds them
/// all, so the copy can run rounds under whichever version is in force.
pub fn a_namespace_import_writes_every_held_version<S: Store>(store: &S) {
    let version = |hash: u64, seq: u64| ManifestRow {
        document: serde_json::json!({
            "contract_manifest": 1,
            "upgrades": "circuits",
            "name": format!("m{hash}"),
            "packages": [{"name": "amm_init"}, {"name": "amm_swap"}],
        }),
        ..manifest_row(hash, seq)
    };
    let package = |name: &str, hash: u64, seq: u64| PackageRow {
        name: name.into(),
        manifest_hash: Fr::from(hash),
        circuit_json: format!("{{\"{name}\":{hash}}}").into_bytes(),
        manifest: serde_json::json!({"manifest": 1, "circuit": name}),
        vk: vec![hash as u8],
        vk_hash: Fr::from(hash + 0x100),
        disabled: false,
        seq,
    };
    for (hash, seq) in [(0xa1, 0), (0xa2, 1), (0xa3, 2)] {
        let mut txn = store.begin(ns());
        match seq {
            0 => txn.register_namespace(namespace_row(3)),
            _ => txn.advance_seq(seq),
        }
        txn.put_manifest(version(hash, seq));
        txn.put_package(package("amm_init", hash, seq));
        txn.put_package(package("amm_swap", hash, seq));
        store.commit(txn).unwrap();
    }
    let held = held_versions(store, ns()).unwrap();
    assert_eq!(
        held,
        [(0xa1, 0), (0xa2, 1), (0xa3, 2)].map(|(hash, seq)| (
            version(hash, seq),
            vec![
                package("amm_init", hash, seq),
                package("amm_swap", hash, seq)
            ]
        ))
    );
    let copy = Fr::from(NS + 1);
    let mut txn = store.begin(copy);
    txn.import_namespace(NamespaceRow {
        seq: 2,
        ..namespace_row(3)
    });
    for (m, packages) in held.clone() {
        txn.put_manifest(m);
        packages.into_iter().for_each(|p| txn.put_package(p));
    }
    store.commit(txn).unwrap();
    assert_eq!(held_versions(store, copy).unwrap(), held);
    assert_eq!(
        store.contract_manifest(copy).unwrap(),
        Some(version(0xa3, 2))
    );
}
