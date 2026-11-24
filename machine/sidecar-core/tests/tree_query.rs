//! `POST /v1/tree` (`tree::answer`): a query is answered at the depth of the
//! version's own tree, a query of another depth is refused, and a round
//! that opens a leaf gets the assigned index's path in the same answer.

use sidecar_core::bind::{Elem, Share};
use sidecar_core::error::{ErrorClass, Refusal};
use sidecar_core::field::{FieldHex, Fr, RequestId, fr_from_hex};
use sidecar_core::store::rules::TreeNodes;
use sidecar_core::store::{
    MemoryStore, NewRequest, Store, StoreRead, TipVersion, TreeRoot, VersionStatus, VersionTree,
    VersionWrite,
};
use sidecar_core::tree::{self, TreeNode, TreePaths, TreeQuery};

const NS: u64 = 0x7197;
const BOOK: &str = "0xa003";
const DEPTH: u32 = 16;

/// A store holding one version of a depth-16 book with leaves 0, 1 and 2
/// written (append index 3), and that version's commitment.
fn store() -> (MemoryStore, Fr) {
    let store = MemoryStore::new();
    let (ns, key) = (Fr::from(NS), fr_from_hex(BOOK).unwrap());
    let z = tree::zeros(DEPTH);
    let leaves: Vec<(u64, Vec<Fr>)> = (0..3u64)
        .map(|i| (i, vec![Fr::from(10 + i), Fr::from(77 + i)]))
        .collect();
    let changes: Vec<(u64, Fr)> = leaves
        .iter()
        .map(|(i, l)| (*i, tree::leaf_hash(ns, key, *i, l)))
        .collect();
    let mut txn = store.begin(ns);
    let nodes = TreeNodes {
        read: &store,
        key: BOOK,
    };
    let rebuilt = {
        let read = |h: Fr| nodes.get(&txn, h).map(|n| n.map(|n| n.node));
        tree::rebuild(&read, &z, z[DEPTH as usize], &changes).unwrap()
    };
    let mut added: Vec<(Fr, TreeNode)> = leaves
        .iter()
        .zip(&changes)
        .map(|((i, l), (_, h))| {
            let vec = l
                .iter()
                .map(|x| Elem::Shared(Share::new(*x, Fr::from(0u64))))
                .collect();
            (*h, TreeNode::Leaf { index: *i, vec })
        })
        .collect();
    added.extend(rebuilt.added.into_iter().map(|(h, _, n)| (h, n)));
    nodes.add_version(&mut txn, rebuilt.root, added).unwrap();
    let request_id = RequestId::from_u128_bytes([1; 16]);
    let commitment = tree::commitment(ns, key, rebuilt.root);
    txn.version(VersionWrite::Put(TipVersion {
        key: BOOK.into(),
        commitment,
        parent: Fr::from(0u64),
        index: 0,
        request_id,
        vec: vec![],
        tree: Some(VersionTree::Clear(TreeRoot {
            root: rebuilt.root,
            next: 3,
        })),
        status: VersionStatus::Canonical,
        block: 1,
        block_hash: Fr::from(0u64),
    }));
    txn.put_request(NewRequest {
        request_id,
        body_hash: Fr::from(0u64),
        vk_hash: Fr::from(0x7e57u64),
        proof: vec![],
        public_inputs: vec![],
        stored_keys: vec![],
        created_keys: vec![],
        signature: None,
        created_at: 1,
        chain_request_id: None,
    });
    store.commit(txn).unwrap();
    (store, commitment)
}

fn query(commitment: Fr, depth: u32, indices: &[u64], open: Option<usize>) -> TreeQuery {
    TreeQuery {
        namespace: FieldHex(Fr::from(NS)),
        key: BOOK.into(),
        commitment: FieldHex(commitment),
        depth,
        indices: indices.to_vec(),
        open,
    }
}

fn ask(store: &MemoryStore, q: &TreeQuery) -> Result<TreePaths, Refusal> {
    tree::answer(store, q)
}

#[test]
fn a_query_of_another_depth_than_the_tree_s_is_refused() {
    let (store, commitment) = store();
    let paths = ask(&store, &query(commitment, DEPTH, &[0, 2], None)).unwrap();
    assert_eq!(paths.siblings.len(), 2 * DEPTH as usize);
    assert_eq!(paths.next, 3);
    for depth in [1, DEPTH - 1, DEPTH + 1, 32] {
        let err = ask(&store, &query(commitment, depth, &[0, 1], None)).unwrap_err();
        assert_eq!(err.class, ErrorClass::BadRequest, "{err}");
        assert!(
            err.message.contains(&format!("key `{BOOK}`"))
                && err.message.contains(&format!("depth {DEPTH}, not {depth}")),
            "{err}"
        );
    }
}

#[test]
fn the_depth_of_a_tree_is_read_from_its_nodes() {
    let (store, commitment) = store();
    let ns = Fr::from(NS);
    let root = store
        .tip_version(ns, BOOK, commitment)
        .unwrap()
        .unwrap()
        .tree
        .and_then(VersionTree::clear)
        .unwrap()
        .root;
    let nodes = |h: Fr| Ok(store.tip_node(ns, BOOK, h)?.map(|n| n.node));
    assert_eq!(tree::depth_of(&nodes, root).unwrap(), DEPTH);
    // an empty tree's root is the empty subtree of its height
    for depth in [1, 5, 32] {
        let z = tree::zeros(depth);
        assert_eq!(tree::depth_of(&nodes, z[depth as usize]).unwrap(), depth);
    }
    // a root the store does not hold is a diverged store
    let err = tree::depth_of(&nodes, Fr::from(5u64)).unwrap_err();
    assert_eq!(err.class, ErrorClass::MpcFailure, "{err}");
}

#[test]
fn an_opening_slot_takes_the_append_index_in_the_same_answer() {
    let (store, commitment) = store();
    // slot 1 opens: whatever the query names there, each node places 3
    let opened = ask(&store, &query(commitment, DEPTH, &[0, 0, 2], Some(1))).unwrap();
    let named = ask(&store, &query(commitment, DEPTH, &[0, 3, 2], None)).unwrap();
    assert_eq!(opened, named);
    assert_eq!(opened.old_hashes[1].fr(), Fr::from(0u64), "leaf 3 is empty");
    // an open slot past the indices is out of bounds
    let err = ask(&store, &query(commitment, DEPTH, &[0, 0], Some(2))).unwrap_err();
    assert_eq!(err.class, ErrorClass::BadRequest, "{err}");
}
