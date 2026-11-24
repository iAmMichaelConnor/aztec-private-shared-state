//! A tree-valued key's layout is declared once: the reference a loaded tree
//! is stored back at (`store`) takes the loaded entry's layout
//! (`Manifest::tree_of`), so the two sides of one tree cannot differ; and a
//! round that loads and stores trees stores each tree it loads.

use serde_json::{Value, json};
use sidecar_core::error::ErrorClass;
use sidecar_core::manifest::{KeyRef, Manifest, TreeAccess};
use sidecar_core::testing::artifacts::{repo, shipped_manifests};
use sidecar_test_fixtures::vectors::read as repo_file;

fn parsed(value: &Value) -> Manifest {
    Manifest::parse(value).unwrap()
}

fn refused(value: &Value, needle: &str) {
    sidecar_core::error::assert_refused(Manifest::parse(value), ErrorClass::BadRequest, &[needle]);
}

/// Every manifest the repository ships with a `tree` entry, by its path
/// from the repository root.
fn tree_manifests() -> Vec<String> {
    let root = repo();
    shipped_manifests()
        .into_iter()
        .map(|path| path.strip_prefix(&root).unwrap().display().to_string())
        .filter(|rel| repo_file(rel).get("tree").is_some())
        .collect()
}

#[test]
fn every_shipped_tree_is_declared_once_and_its_stored_reference_derived() {
    let paths = tree_manifests();
    assert!(paths.iter().any(|p| p.contains("lending-tip")), "{paths:?}");
    for path in paths {
        let m = parsed(&repo_file(&path));
        for (key, tree) in m.trees() {
            // one entry per tree: a loaded entry's stored reference has no
            // entry of its own, and resolves to the loaded one
            if let Some(store) = tree.store {
                assert!(
                    !m.trees().any(|(k, _)| *k == store),
                    "{path}: {store} declared twice"
                );
                assert!(std::ptr::eq(m.tree_of(store).unwrap(), tree), "{path}");
                assert_eq!(
                    m.key_layout(store).unwrap().tree,
                    m.key_layout(*key).unwrap().tree,
                    "{path}"
                );
            }
        }
        // every stored tree key has a layout; a clear one names the output
        // of its new leaf hashes, an oblivious one names none (they would
        // show which leaves changed)
        for out in &m.outputs {
            if m.trees()
                .any(|(k, t)| *k == out.store || t.store == Some(out.store))
            {
                let tree = m.tree_of(out.store).unwrap();
                let clear = tree.access == TreeAccess::Clear;
                assert_eq!(tree.new_hashes.is_some(), clear, "{path}: {}", out.store);
            }
        }
    }
}

#[test]
fn the_stored_reference_takes_the_loaded_layout() {
    let m = parsed(&repo_file("machine/circuits/manifests/tip_tree.json"));
    let loaded = m.tree_of(KeyRef::Read(0)).unwrap();
    let stored = m.tree_of(KeyRef::Write(0)).unwrap();
    assert!(std::ptr::eq(loaded, stored));
    assert_eq!(
        (stored.depth, stored.probe, stored.open.as_deref()),
        (16, 3, Some("p1"))
    );
    assert_eq!(m.trees().count(), 1);
}

#[test]
fn a_round_that_loads_a_tree_and_stores_another_is_refused() {
    // the tree stored at $state_keys.writes[0] declared on its own, beside a
    // loaded tree that is not stored back
    let mut v = repo_file("machine/circuits/manifests/tip_tree.json");
    let mut created = v["tree"]["$state_keys.reads[0]"].clone();
    let fields = created.as_object_mut().unwrap();
    fields.remove("params");
    fields.remove("store");
    v["tree"]["$state_keys.writes[0]"] = created;
    let loaded = v["tree"]["$state_keys.reads[0]"].as_object_mut().unwrap();
    loaded.remove("store");
    loaded.remove("new_hashes");
    refused(
        &v,
        "loads 1 tree key(s), stores 0 of them back and creates 1",
    );
}

#[test]
fn a_round_that_creates_a_tree_declares_it_under_its_stored_reference() {
    // the init round loads no tree; its stored entry stands alone
    let v = repo_file("machine/circuits/manifests/tip_tree_init.json");
    let init = parsed(&v);
    assert!(init.tree_of(KeyRef::Read(0)).is_none());
    assert!(init.tree_of(KeyRef::Write(0)).unwrap().new_hashes.is_some());
    // a created tree is not stored back anywhere
    let mut stores = v.clone();
    stores["tree"]["$state_keys.writes[0]"]["store"] = json!("$state_keys.writes[0]");
    refused(&stores, "only under the key reference that loads the tree");
}
