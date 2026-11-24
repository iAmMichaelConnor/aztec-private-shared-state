//! The registry plan tests.

use super::*;
use serde_json::json;

fn pkg(name: &str, seq: u64, disabled: bool) -> PackageRows {
    PackageRows {
        name: name.into(),
        vk_hash: FieldHex::from(0x77),
        manifest: json!({"version": 1}),
        disabled,
        seq,
    }
}

fn rows(ns: u64, seq: u64, packages: Vec<PackageRows>) -> NamespaceRows {
    NamespaceRows {
        namespace: FieldHex::from(ns),
        owner_pubkey: GrumpkinPoint {
            x: FieldHex::from(5),
            y: FieldHex::from(6),
        },
        seq,
        npk_app_hash: FieldHex::from(0x9e),
        manifest: Some(manifest(0xaa)),
        packages,
    }
}

fn manifest(hash: u64) -> ManifestRows {
    ManifestRows {
        manifest_hash: FieldHex::from(hash),
        seq: 0,
        document: json!({"contract_manifest": 1, "name": format!("m{hash}")}),
    }
}

#[test]
fn the_plan_writes_what_differs_and_advances_seq() {
    let own = vec![
        rows(0x40, 1, vec![pkg("a", 0, false), pkg("b", 1, false)]),
        rows(0x41, 0, vec![pkg("a", 0, false)]),
    ];
    let agreed = vec![
        rows(
            0x40,
            3,
            vec![pkg("a", 0, false), pkg("b", 2, true), pkg("c", 3, false)],
        ),
        rows(0x41, 0, vec![pkg("a", 0, false)]),
    ];
    let plan = registry_plan(&own, &agreed).unwrap();
    assert_eq!(
        plan,
        [RegistryPlan {
            namespace: Fr::from(0x40u64),
            seq: (1, 3),
            manifest: None,
            packages: vec![pkg("b", 2, true), pkg("c", 3, false)],
        }]
    );
    assert!(registry_plan(&agreed, &agreed).unwrap().is_empty());
}

/// Another contract manifest at the other two: the plan writes it with
/// every package of theirs, and a package only the node holds goes with
/// its old manifest.
#[test]
fn the_plan_writes_another_contract_manifest_whole() {
    let own = vec![rows(0x40, 1, vec![pkg("a", 0, false), pkg("x", 1, false)])];
    let mut theirs = rows(0x40, 2, vec![pkg("a", 0, false), pkg("b", 2, false)]);
    theirs.manifest = Some(manifest(0xbb));
    let plan = registry_plan(&own, &[theirs]).unwrap();
    assert_eq!(
        plan,
        [RegistryPlan {
            namespace: Fr::from(0x40u64),
            seq: (1, 2),
            manifest: Some(manifest(0xbb)),
            packages: vec![pkg("a", 0, false), pkg("b", 2, false)],
        }]
    );
}

#[test]
fn the_plan_refuses_every_row_it_cannot_bring_level() {
    let mut other_owner = rows(0x43, 1, vec![]);
    other_owner.npk_app_hash = FieldHex::from(0x9f);
    let own = vec![
        rows(0x40, 4, vec![]),
        rows(0x42, 1, vec![]),
        other_owner,
        rows(0x44, 1, vec![pkg("a", 0, false), pkg("x", 1, false)]),
    ];
    let agreed = vec![
        rows(0x40, 3, vec![]),
        rows(0x41, 0, vec![]),
        rows(0x43, 1, vec![]),
        rows(0x44, 2, vec![pkg("a", 0, false)]),
    ];
    let err = registry_plan(&own, &agreed).unwrap_err();
    assert_eq!(err.class, crate::error::ErrorClass::Conflict);
    for needle in [
        "5 row(s) a registry resync cannot bring level",
        "holds seq 4, ahead of the other two's 3",
        "holds no row of it, and its nsk_app share",
        "the other two nodes hold no row of it",
        "another owner or npk_app_hash",
        "package(s) `x` the other two do not",
    ] {
        assert!(err.message.contains(needle), "{needle}: {err}");
    }
}
