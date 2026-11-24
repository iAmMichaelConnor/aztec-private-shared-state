//! The unit tests of the state holders.

use super::*;
use crate::abi::check_manifest_value;
use crate::abi::tests::{abi, array, field};
use crate::bind::Share;
use crate::error::{ErrorClass, parse_json};
use crate::field::{FieldHex, fr_from_hex};
use crate::request::{Request, StateKeys};
use crate::store::testing::{new_request, node_keys, ns};
use crate::store::{MemoryStore, Store, TreeRoot, VersionTree};
use crate::tree;
use serde_json::json;

const BOOK: &str = "0xa003";

/// Step 15 of a round that creates a tree key (tip_tree_init): the new
/// leaf hashes give the root the new commitment names, and the version
/// holds the tree and leaf 0; a round whose leaf hashes give another root
/// is refused (500) and stores nothing.
#[test]
fn a_created_tree_is_stored_only_under_the_root_its_leaf_hashes_give() {
    let text = include_str!("../../../../machine/circuits/manifests/tip_tree_init.json");
    let init_abi = abi(
        &[
            ("namespace", "public", field()),
            ("vk_hash", "public", field()),
            ("out_slots", "public", array(1, field())),
            ("total", "private", field()),
            ("r_new", "private", field()),
        ],
        Some(json!({"kind": "struct", "path": "InitOutputs", "fields": [
            {"name": "request_id", "type": field()},
            {"name": "new_c", "type": field()},
            {"name": "new_hashes", "type": array(1, field())}
        ]})),
    );
    let (manifest, shape) = check_manifest_value(&parse_json(text).unwrap(), &init_abi).unwrap();
    let holder = NodeTree::new(manifest.tree_of(KeyRef::Write(0)).unwrap().clone());
    let store = MemoryStore::new();
    let keys = node_keys();
    let key = fr_from_hex(BOOK).unwrap();
    let req = Request {
        namespace: FieldHex(ns()),
        circuit: "tip_tree_init".into(),
        request_id: crate::store::testing::id(1),
        public: [(
            "total".to_string(),
            crate::request::PublicValue::One(FieldHex(Fr::from(7u64))),
        )]
        .into(),
        state_keys: StateKeys {
            reads: vec![],
            writes: vec![BOOK.into()],
        },
        shared_inputs: vec![],
        records: vec![],
        requester: None,
        signature: None,
        chain_request_id: Some(FieldHex(Fr::from(0xc0u64))),
        shared_log: None,
        manifest_hash: None,
    }
    .project(0);
    let chain = QueueRead {
        block: 5,
        block_hash: Fr::from(0u64),
        settled: 5,
        head: 0,
        index: 0,
        keys: vec![],
    };
    let leaf = [Fr::from(7u64), Fr::from(1u64), Fr::from(99u64)];
    let h0 = tree::leaf_hash(ns(), key, 0, &leaf);
    let z = tree::zeros(16);
    let root = tree::root_of(h0, &z[..16], 0);
    let new_c = tree::commitment(ns(), key, root);
    let vec: Vec<Elem> = leaf
        .iter()
        .map(|x| Elem::Shared(Share::new(*x, Fr::from(0u64))))
        .collect();
    let stage = |hash: Fr| {
        // [namespace, vk_hash, out_slots[0], request_id, new_c, new_hashes[0]]
        let public = [ns(), Fr::from(0x5au64), key, Fr::from(0x1du64), new_c, hash];
        let at = StateCtx {
            store: &store,
            keys: &keys,
            node: 0,
            namespace: ns(),
            manifest: &manifest,
            shape: &shape,
            req: &req,
            requester: None,
            chain: Some(&chain),
            public_inputs: &public,
        };
        let mut txn = store.begin(ns());
        holder
            .stage(
                &at,
                &mut txn,
                BOOK,
                vec.clone(),
                new_c,
                &mut RoundEntries::default(),
            )
            .map(|_| txn)
    };
    let err = stage(h0 + Fr::from(1u64)).err().unwrap();
    assert_eq!(err.class, ErrorClass::MpcFailure);
    assert!(err.message.contains("nothing was stored"), "{err}");
    let mut txn = stage(h0).unwrap();
    txn.put_request(new_request(1, 100));
    store.commit(txn).unwrap();
    let version = store.tip_version(ns(), BOOK, new_c).unwrap().unwrap();
    assert_eq!(
        version.tree,
        Some(VersionTree::Clear(TreeRoot { root, next: 1 }))
    );
    let nodes = |h: Fr| Ok(store.tip_node(ns(), BOOK, h)?.map(|n| n.node));
    assert_eq!(
        tree::leaves(&nodes, &z, root, 3, &[0, 1]).unwrap()[..3],
        vec[..]
    );
}

/// A loaded tree and the reference it is stored back at name one key, so
/// they share one holder instance: what the holder keeps from its load is
/// there at its stage. References of other keys get their own.
#[test]
fn a_tree_key_has_one_holder_for_its_read_and_write_references() {
    fn fresh(_: &Manifest, _: KeyRef) -> Arc<dyn StateHolder> {
        Arc::new(NodeRow)
    }
    let held =
        [StateMode::Node, StateMode::Chain]
            .into_iter()
            .fold(StateHolders::core(), |held, mode| {
                held.with(HolderEntry {
                    mode,
                    path: Path::Tip,
                    make: fresh,
                })
            });
    let tree: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../machine/circuits/manifests/tip_tree.json"
    ))
    .unwrap();
    let manifest = Manifest::parse(&tree).unwrap();
    assert_eq!(manifest.holder_ref(KeyRef::Write(0)), KeyRef::Read(0));
    let holding = held.choose(&manifest).unwrap();
    let ptr = |k| holding.get(k).unwrap() as *const dyn StateHolder as *const ();
    assert_eq!(ptr(KeyRef::Read(0)), ptr(KeyRef::Write(0)));

    let counter: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../machine/circuits/manifests/tip_counter.json"
    ))
    .unwrap();
    let manifest = Manifest::parse(&counter).unwrap();
    let holding = held.choose(&manifest).unwrap();
    let keys: Vec<KeyRef> = holding.iter().map(|(k, _)| k).collect();
    assert!(keys.len() >= 2, "{keys:?}");
    let ptr = |k| holding.get(k).unwrap() as *const dyn StateHolder as *const ();
    assert_ne!(ptr(keys[0]), ptr(keys[1]));
}
