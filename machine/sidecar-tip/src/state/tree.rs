//! The scheduler's and the chain verifier's side of a tree-valued node-held
//! key (docs/ARCHITECTURE.md section 6, "Tree-valued keys"); each node's own
//! side, steps 8 and 15 over its clear tree, is sidecar-core's `NodeTree`.
//!
//! A round on a tree key carries, besides the key's commitment, the
//! node-sourced public values of its touched leaves: each slot's old leaf
//! hash and siblings, the effective indices, a window's old leaf hashes and
//! root siblings, and under an `open` input the assigned `$new_leaf`. The scheduler reads them from all three nodes'
//! clear trees ([`TreeSource`], which requires the three to agree) and
//! places them in the synthesised request, so `body_hash` covers them; each
//! node's chain verifier derives them from its own tree and refuses (400,
//! naming the key) a request that carries others.
//!
//! `$new_leaf` is a hint the round's circuit verifies: an app whose tree
//! opens leaves keeps the append index in its header leaf and requires the
//! assigned index to equal it (pss_core `tree::append`; lending's code
//! 17), so the opened leaves stay a prefix of the tree even if every node's
//! check here were skipped.

use std::collections::BTreeMap;

use sidecar_core::error::Refusal;
use sidecar_core::field::{FieldHex, Fr, fr_to_hex};
use sidecar_core::manifest::{Manifest, PublicOperand, PublicSource, Source, TreeLayout};
use sidecar_core::request::{PublicValue, flatten_public_map};
use sidecar_core::state::NodeTree;
use sidecar_core::store::VersionTree;
use sidecar_core::tree::{self, Touch, TreePaths};

use crate::state::{KeyState, TipCheck, TipFuture, TreeValues};
use crate::synth::TipPackage;
use crate::verifier::refused;

/// Public values a request carries, by request public name.
pub type PublicMap = BTreeMap<String, PublicValue>;

/// Where the scheduler reads a tree key's paths: the version under a
/// commitment at every node, which must agree.
pub trait TreeSource: Sync {
    /// The paths of `indices` in the tree of `key` (depth `depth`) under
    /// `commitment`, in the schedule's namespace, with the version's
    /// `$new_leaf` in slot `open` (sidecar-core's `TreeQuery`); 400 when the
    /// nodes' clear trees differ, and the refusal of a node that fails.
    fn paths(
        &self,
        key: String,
        commitment: Fr,
        depth: u32,
        indices: Vec<u64>,
        open: Option<usize>,
    ) -> TipFuture<'_, Result<TreePaths, Refusal>>;
}

/// The request public name `param` is filled from (REGISTER checked it is
/// one PUBLIC name).
fn public_name<'m>(manifest: &'m Manifest, param: &str) -> Result<&'m str, Refusal> {
    match manifest.witness_entry(param).map(|(_, w)| &w.from) {
        Some(Source::Public(PublicSource::One(PublicOperand::Name(n)))) => Ok(n),
        _ => Err(Refusal::mpc_failure(format!(
            "parameter `{param}` is not filled by one PUBLIC name (REGISTER checks it)"
        ))),
    }
}

fn many(values: impl IntoIterator<Item = Fr>) -> PublicValue {
    PublicValue::Many(values.into_iter().map(FieldHex).collect())
}

/// The values a request carries for a loaded tree key with `layout`, from
/// the paths of its loaded leaves (the slots, then a window's): the slots'
/// paths under the request public names of `old_hashes` and `siblings`,
/// the touched indices under that of `indices`, a window's old hashes and
/// root siblings under its own names, and `$new_leaf` under its parameter's
/// name.
fn values(
    manifest: &Manifest,
    layout: &TreeLayout,
    touch: &Touch,
    paths: &TreePaths,
    new_leaf: Option<u64>,
) -> Result<PublicMap, Refusal> {
    let params = layout.params.as_ref().ok_or_else(|| {
        Refusal::mpc_failure("a loaded tree key names its params (REGISTER checks it)")
    })?;
    let slots = touch.indices.len();
    let depth = layout.depth as usize;
    let mut out = PublicMap::new();
    if let Some(w) = &layout.window {
        let (hashes, siblings) = tree::window_values(paths, slots, w.width, layout.depth)?;
        out.insert(
            public_name(manifest, &w.params.old_hashes)?.to_string(),
            many(hashes),
        );
        out.insert(
            public_name(manifest, &w.params.siblings)?.to_string(),
            many(siblings),
        );
    }
    out.insert(
        public_name(manifest, &params.old_hashes)?.to_string(),
        many(paths.old_hashes.iter().take(slots).map(|h| h.fr())),
    );
    out.insert(
        public_name(manifest, &params.siblings)?.to_string(),
        many(paths.siblings.iter().take(slots * depth).map(|h| h.fr())),
    );
    let indices = params.indices.as_deref().ok_or_else(|| {
        Refusal::mpc_failure(
            "a clear-access tree names its `indices` parameter (REGISTER checks it)",
        )
    })?;
    out.insert(
        public_name(manifest, indices)?.to_string(),
        many(touch.indices.iter().map(|i| Fr::from(*i))),
    );
    if let (Some(param), Some(leaf)) = (manifest.new_leaf_param(), new_leaf) {
        out.insert(
            param.to_string(),
            PublicValue::One(FieldHex(Fr::from(leaf))),
        );
    }
    Ok(out)
}

/// `$new_leaf` for a version with append index `next`, when the layout opens
/// leaves: the hint the round's circuit checks against the append index its
/// header leaf carries (pss_core `tree::append`).
fn assigned(layout: &TreeLayout, next: u64) -> Option<u64> {
    layout
        .open
        .as_ref()
        .map(|_| tree::new_leaf(next, layout.depth))
}

// The node-held tip state of a tree-valued key: a flat node-held key's
// (`NodeVersions`), with the round's tree values beside.
impl TreeValues for NodeTree {
    /// This node's own paths of the request's touched leaves and window at
    /// the version `state` names (none for an empty slot, which step 8
    /// refuses).
    fn round_values(&self, at: &TipCheck<'_>, state: &KeyState) -> Result<PublicMap, Refusal> {
        if state.commitment == Fr::from(0u64) {
            return Ok(PublicMap::new());
        }
        let ns = at.req.namespace.fr();
        let key = &at.slot.key;
        let layout = self.layout();
        let version = at
            .rows
            .tip_versions(ns, key)?
            .into_iter()
            .find(|v| v.commitment == state.commitment)
            .and_then(|v| v.tree.and_then(VersionTree::clear))
            .ok_or_else(|| {
                refused(format!(
                    "key `{key}`: this node holds no tree under commitment {}",
                    fr_to_hex(state.commitment)
                ))
            })?;
        let new_leaf = assigned(layout, version.next);
        let flat: BTreeMap<String, Fr> = at.req.flatten_public()?.into_iter().collect();
        let touch = Touch::of(layout, &flat, Fr::from(new_leaf.unwrap_or(0)));
        let loads = [touch.indices.clone(), tree::window(layout, &flat)].concat();
        let nodes = |h: Fr| at.rows.tip_node(ns, key, h);
        let zeros = tree::zeros(layout.depth);
        let own = tree::paths(&nodes, &zeros, version.root, version.next, &loads)?;
        values(at.package.tip.manifest(), layout, &touch, &own, new_leaf)
    }

    /// The paths of the touched leaves the app inputs `public` name, and of
    /// a window's leaves after them, from the three nodes' trees at the
    /// version `state` names, in one read: a round that opens a leaf names
    /// its slot, where each node places the assigned index.
    fn node_values<'a>(
        &'a self,
        package: &'a TipPackage,
        key: &'a str,
        state: &'a KeyState,
        public: &'a PublicMap,
        trees: &'a dyn TreeSource,
    ) -> TipFuture<'a, Result<PublicMap, Refusal>> {
        Box::pin(async move {
            let layout = self.layout();
            let flat: BTreeMap<String, Fr> =
                flatten_public_map(public, "public")?.into_iter().collect();
            let named = Touch::of(layout, &flat, Fr::from(0u64));
            let loads = [named.indices, tree::window(layout, &flat)].concat();
            let paths = trees
                .paths(
                    key.to_string(),
                    state.commitment,
                    layout.depth,
                    loads,
                    Touch::opening(layout, &flat),
                )
                .await?;
            let new_leaf = assigned(layout, paths.next);
            let touch = Touch::of(layout, &flat, Fr::from(new_leaf.unwrap_or(0)));
            values(package.tip.manifest(), layout, &touch, &paths, new_leaf)
        })
    }
}

/// Refuse (400, naming the key) a request whose public values for a key
/// differ from `own`, this node's values for it.
pub(crate) fn check_values(
    key: &str,
    commitment: Fr,
    own: &PublicMap,
    req: &sidecar_core::request::NodeRequest,
) -> Result<(), Refusal> {
    for (name, value) in own {
        if req.public.get(name) != Some(value) {
            return Err(refused(format!(
                "key `{key}`: the request's `{name}` is not this node's clear tree at commitment \
                 {} (a diverged tree at one node: the operator resyncs it from its neighbours)",
                fr_to_hex(commitment)
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::TipManifest;
    use crate::verifier::SlotRead;
    use serde_json::{Value, json};
    use sidecar_core::abi::check_manifest_value;
    use sidecar_core::bind::{Elem, Share};
    use sidecar_core::error::{ErrorClass, parse_json};
    use sidecar_core::field::RequestId;
    use sidecar_core::manifest::KeyRef;
    use sidecar_core::request::{Request, StateKeys};
    use sidecar_core::store::rules::TreeNodes;
    use sidecar_core::store::{
        MemoryStore, Store, TipVersion, TreeRoot, VersionStatus, VersionWrite,
    };
    use sidecar_core::tree::TreeNode;

    const MANIFEST: &str = include_str!("../../../../machine/circuits/manifests/tip_tree.json");
    pub(crate) const BOOK: &str = "0xa003";
    pub(crate) const NS: u64 = 0x7197;

    pub(crate) fn abi() -> Value {
        let f = json!({"kind": "field"});
        let arr = |n: u32, t: &Value| json!({"kind": "array", "length": n, "type": t});
        let p =
            |name: &str, vis: &str, t: Value| json!({"name": name, "type": t, "visibility": vis});
        json!({
            "parameters": [
                p("namespace", "public", f.clone()),
                p("vk_hash", "public", f.clone()),
                p("in_slots", "public", arr(1, &f)),
                p("out_slots", "public", arr(1, &f)),
                p("amount", "private", f.clone()),
                p("p1", "private", f.clone()),
                p("p2", "private", f.clone()),
                p("count", "private", f.clone()),
                p("user_nonce", "private", f.clone()),
                p("leaves", "private", arr(3, &arr(3, &f))),
                p("old_hashes", "private", arr(3, &f)),
                p("siblings", "private", arr(3, &arr(16, &f))),
                p("indices", "private", arr(3, &f)),
                p("new_leaf", "private", f.clone()),
                p("r_new", "private", arr(3, &f)),
            ],
            "return_type": {"abi_type": {"kind": "struct", "path": "TreeOutputs", "fields": [
                {"name": "request_id", "type": f},
                {"name": "old_c", "type": f},
                {"name": "new_c", "type": f},
                {"name": "new_hashes", "type": arr(3, &f)},
                {"name": "ok", "type": f},
                {"name": "code", "type": f},
                {"name": "position", "type": f}
            ]}, "visibility": "public"},
            "error_types": {}
        })
    }

    pub(crate) fn package() -> TipPackage {
        let abi = parse_json(&abi().to_string()).unwrap();
        let (manifest, shape) = check_manifest_value(&parse_json(MANIFEST).unwrap(), &abi).unwrap();
        TipPackage::new(
            "tip_tree".into(),
            Fr::from(0x7e57u64),
            TipManifest::new(manifest, Some(50)).unwrap(),
            shape,
        )
        .unwrap()
    }

    /// Leaf `i` of the book [`store`] holds: the header [10, 3, 77] (its
    /// append index 3) at 0, the position [10 + i, 0, 77 + i] above.
    pub(crate) fn book_leaf(i: u64) -> Vec<Fr> {
        let second = if i == 0 { 3 } else { 0 };
        [10 + i, second, 77 + i].map(Fr::from).to_vec()
    }

    /// A store holding one version of the book: leaves 0, 1 and 2 written,
    /// append index 3.
    fn store() -> (MemoryStore, Fr) {
        let store = MemoryStore::new();
        let leaves: Vec<(u64, Vec<Fr>)> = (0..3u64).map(|i| (i, book_leaf(i))).collect();
        let version = put_book(&store, NS, None, &leaves, 1, None);
        (store, version.commitment)
    }

    /// Add to `store` (namespace `ns`) a version of the book: `leaves`
    /// written over the tree of `parent` (the empty tree when `None`), by
    /// round `n` (request id `[n; 16]`, a committed `requests` row carrying
    /// `chain`); canonical without a parent, live over one.
    pub(crate) fn put_book(
        store: &MemoryStore,
        ns: u64,
        parent: Option<&TipVersion>,
        leaves: &[(u64, Vec<Fr>)],
        n: u8,
        chain: Option<Fr>,
    ) -> TipVersion {
        let z = tree::zeros(16);
        let (ns, key) = (
            Fr::from(ns),
            sidecar_core::field::fr_from_hex(BOOK).unwrap(),
        );
        let (root, next) = parent
            .and_then(|p| p.tree.and_then(VersionTree::clear))
            .map_or((z[16], 0), |t| (t.root, t.next));
        let mut txn = store.begin(ns);
        let changes: Vec<(u64, Fr)> = leaves
            .iter()
            .map(|(i, l)| (*i, tree::leaf_hash(ns, key, *i, l)))
            .collect();
        let rebuilt = {
            let nodes = TreeNodes {
                read: store,
                key: BOOK,
            };
            let read = |h: Fr| nodes.get(&txn, h).map(|n| n.map(|n| n.node));
            tree::rebuild(&read, &z, root, &changes).unwrap()
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
        TreeNodes {
            read: store,
            key: BOOK,
        }
        .add_version(&mut txn, rebuilt.root, added)
        .unwrap();
        let next = leaves.iter().map(|(i, _)| i + 1).fold(next, u64::max);
        let version = TipVersion {
            key: BOOK.into(),
            commitment: tree::commitment(ns, key, rebuilt.root),
            parent: parent.map_or(Fr::from(0u64), |p| p.commitment),
            index: parent.map_or(0, |p| p.index + 1),
            request_id: RequestId::from_u128_bytes([n; 16]),
            vec: vec![],
            tree: Some(VersionTree::Clear(TreeRoot {
                root: rebuilt.root,
                next,
            })),
            status: if parent.is_some() {
                VersionStatus::Live
            } else {
                VersionStatus::Canonical
            },
            block: 1,
            block_hash: Fr::from(0u64),
        };
        txn.version(VersionWrite::Put(version.clone()));
        txn.put_request(sidecar_core::store::NewRequest {
            request_id: RequestId::from_u128_bytes([n; 16]),
            body_hash: Fr::from(0u64),
            vk_hash: Fr::from(0x7e57u64),
            proof: vec![],
            public_inputs: vec![],
            stored_keys: vec![],
            created_keys: vec![],
            signature: None,
            created_at: 1,
            chain_request_id: chain,
        });
        store.commit(txn).unwrap();
        version
    }

    fn request(public: PublicMap) -> sidecar_core::request::NodeRequest {
        Request {
            namespace: FieldHex(Fr::from(NS)),
            circuit: "tip_tree".into(),
            request_id: RequestId::from_u128_bytes([9; 16]),
            public,
            state_keys: StateKeys {
                reads: vec![BOOK.into()],
                writes: vec![BOOK.into()],
            },
            shared_inputs: vec![],
            records: vec![],
            requester: None,
            signature: None,
            chain_request_id: Some(FieldHex(Fr::from(0xc5u64))),
            shared_log: None,
            manifest_hash: None,
        }
        .project(0)
    }

    pub(crate) fn app(amount: u64, p1: u64, p2: u64, count: u64) -> PublicMap {
        [("amount", amount), ("p1", p1), ("p2", p2), ("count", count)]
            .into_iter()
            .map(|(k, v)| (k.to_string(), PublicValue::One(FieldHex(Fr::from(v)))))
            .collect()
    }

    /// The chain verifier derives a tree key's paths, indices and
    /// `$new_leaf` from its own clear tree, and refuses (400, naming the key)
    /// a request whose sibling, old hash or assigned index differs.
    #[test]
    fn a_request_off_this_node_s_tree_is_refused_naming_the_key() {
        let (store, commitment) = store();
        let pkg = package();
        let state = KeyState {
            key: BOOK.into(),
            commitment,
            record: None,
        };
        let slot = SlotRead {
            at: KeyRef::Read(0),
            key: BOOK.into(),
            slot: Fr::from(0xa003u64),
            commitment,
        };
        let held = pkg.tip_state(KeyRef::Read(0)).unwrap();
        let values_for = |public: PublicMap| {
            let req = request(public);
            let at = TipCheck {
                node: 0,
                req: &req,
                package: &pkg,
                slot: &slot,
                block: 2,
                head: 0,
                previous: None,
                pending: None,
                rows: &store,
            };
            held.round_values(&at, &state).unwrap()
        };
        // an opening round on positions 0 (open) and 2: the open slot takes 3
        let inputs = app(5, 0, 2, 2);
        let own = values_for(inputs.clone());
        assert_eq!(own["new_leaf"], PublicValue::One(FieldHex(Fr::from(3u64))));
        assert_eq!(own["indices"], many([0u64, 3, 2].map(Fr::from)));
        let PublicValue::Many(hashes) = &own["old_hashes"] else {
            panic!("a list");
        };
        assert_eq!(hashes[1].fr(), Fr::from(0u64), "leaf 3 is empty");
        assert_ne!(hashes[2].fr(), Fr::from(0u64));

        let honest: PublicMap = inputs.clone().into_iter().chain(own.clone()).collect();
        check_values(BOOK, commitment, &own, &request(honest.clone())).unwrap();
        let refuse = |name: &str, tamper: &dyn Fn(&mut PublicValue)| {
            let mut public = honest.clone();
            tamper(public.get_mut(name).unwrap());
            let err = check_values(BOOK, commitment, &own, &request(public)).unwrap_err();
            assert_eq!(err.class, ErrorClass::BadRequest);
            assert!(
                err.message.contains(&format!("key `{BOOK}`")) && err.message.contains(name),
                "{err}"
            );
        };
        let bump = |v: &mut PublicValue| match v {
            PublicValue::One(x) => x.0 += Fr::from(1u64),
            PublicValue::Many(xs) => xs[5].0 += Fr::from(1u64),
        };
        refuse("siblings", &bump);
        refuse("old_hashes", &|v| {
            if let PublicValue::Many(xs) = v {
                xs[0].0 += Fr::from(1u64)
            }
        });
        refuse("new_leaf", &bump);
        refuse("indices", &|v| {
            if let PublicValue::Many(xs) = v {
                xs[1].0 = Fr::from(4u64)
            }
        });
    }

    /// The scheduler's tree source over one store, counting its reads.
    struct Counted<'s> {
        store: &'s MemoryStore,
        reads: std::sync::atomic::AtomicUsize,
    }

    impl TreeSource for Counted<'_> {
        fn paths(
            &self,
            key: String,
            commitment: Fr,
            depth: u32,
            indices: Vec<u64>,
            open: Option<usize>,
        ) -> TipFuture<'_, Result<TreePaths, Refusal>> {
            self.reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let query = sidecar_core::tree::TreeQuery {
                namespace: FieldHex(Fr::from(NS)),
                key,
                commitment: FieldHex(commitment),
                depth,
                indices,
                open,
            };
            Box::pin(async move { sidecar_core::tree::answer(self.store, &query) })
        }
    }

    /// The tip_tree package read as a scan: the header's slot and a window of
    /// four leaves at the app input `p1` (the layout's `window` form), its
    /// ABI to match.
    fn scan_package() -> TipPackage {
        let mut m: Value = parse_json(MANIFEST).unwrap();
        let load =
            |slice: [u64; 2]| json!({"LOAD": "$state_keys.reads[0]", "slice": slice, "len": 15});
        let w = m["witness"].as_array_mut().unwrap();
        w.retain(|e| e["param"] != "new_leaf");
        for e in w.iter_mut() {
            match e["param"].as_str().unwrap() {
                "leaves" => e["from"] = load([0, 3]),
                "r_new" => e["from"] = json!({"SAMPLE": 1}),
                _ => {}
            }
        }
        w.extend([
            json!({"param": "window_leaves", "from": load([3, 15])}),
            json!({"param": "window_hashes", "from": {"PUBLIC": "window_hashes"}}),
            json!({"param": "window_siblings", "from": {"PUBLIC": "window_siblings"}}),
        ]);
        m["outputs"][0]["len"] = json!(3);
        m["tree"]["$state_keys.reads[0]"] = json!({
            "depth": 16, "leaf_len": 3, "probe": 1, "header": true,
            "params": {"leaves": "leaves", "old_hashes": "old_hashes", "siblings": "siblings", "indices": "indices"},
            "window": {"width": 4, "start": "p1",
                       "params": {"leaves": "window_leaves", "old_hashes": "window_hashes", "siblings": "window_siblings"}},
            "store": "$state_keys.writes[0]", "new_hashes": "new_hashes"
        });
        let mut a = abi();
        let f = json!({"kind": "field"});
        let arr = |n: u32, t: &Value| json!({"kind": "array", "length": n, "type": t});
        let params = a["parameters"].as_array_mut().unwrap();
        params.retain(|p| p["name"] != "new_leaf");
        for p in params.iter_mut() {
            match p["name"].as_str().unwrap() {
                "leaves" => p["type"] = arr(1, &arr(3, &f)),
                "old_hashes" | "indices" | "r_new" => p["type"] = arr(1, &f),
                "siblings" => p["type"] = arr(1, &arr(16, &f)),
                _ => {}
            }
        }
        let p = |name: &str, t: Value| json!({"name": name, "type": t, "visibility": "private"});
        params.extend([
            p("window_leaves", arr(4, &arr(3, &f))),
            p("window_hashes", arr(4, &f)),
            p("window_siblings", arr(14, &f)),
        ]);
        a["return_type"]["abi_type"]["fields"][3]["type"] = arr(1, &f);
        let abi = parse_json(&a.to_string()).unwrap();
        let (manifest, shape) = check_manifest_value(&m, &abi).unwrap();
        TipPackage::new(
            "tip_scan".into(),
            Fr::from(0x7e58u64),
            TipManifest::new(manifest, Some(50)).unwrap(),
            shape,
        )
        .unwrap()
    }

    /// A scan's window: the scheduler places its four old hashes and the
    /// window root's 14 siblings from the nodes' trees in the same one read
    /// as the header's path, from the effective start (0 for an unaligned
    /// one); the chain verifier derives the same from its own tree and
    /// refuses a request whose window values differ, naming the key.
    #[test]
    fn the_scheduler_places_a_window_and_the_verifier_checks_it() {
        let (store, commitment) = store();
        let pkg = scan_package();
        let state = KeyState {
            key: BOOK.into(),
            commitment,
            record: None,
        };
        let held = pkg.tip_state(KeyRef::Read(0)).unwrap();
        let slot = SlotRead {
            at: KeyRef::Read(0),
            key: BOOK.into(),
            slot: Fr::from(0xa003u64),
            commitment,
        };
        let (ns, key) = (
            Fr::from(NS),
            sidecar_core::field::fr_from_hex(BOOK).unwrap(),
        );
        let version = sidecar_core::store::StoreRead::tip_version(&store, ns, BOOK, commitment)
            .unwrap()
            .unwrap();
        let root = version.tree.and_then(VersionTree::clear).unwrap().root;
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let hash = |i: u64| tree::leaf_hash(ns, key, i, &book_leaf(i));
        let list = |v: &PublicValue| match v {
            PublicValue::Many(xs) => xs.iter().map(|x| x.fr()).collect::<Vec<_>>(),
            PublicValue::One(_) => panic!("a list"),
        };
        // window 0 holds leaves 0, 1, 2 and the empty 3; window 4 is empty
        let window_root = |h: &[Fr]| tree::node(tree::node(h[0], h[1]), tree::node(h[2], h[3]));
        for (start, at) in [(0u64, 0u64), (2, 0), (4, 4), (1 << 16, 0)] {
            let inputs = app(5, start, 0, 0);
            let trees = Counted {
                store: &store,
                reads: Default::default(),
            };
            let scheduled = runtime
                .block_on(held.node_values(&pkg, BOOK, &state, &inputs, &trees))
                .unwrap();
            assert_eq!(trees.reads.into_inner(), 1);
            assert_eq!(scheduled["indices"], many([Fr::from(0u64)]));
            let hashes = list(&scheduled["window_hashes"]);
            let want: Vec<Fr> = (at..at + 4)
                .map(|i| if i < 3 { hash(i) } else { Fr::from(0u64) })
                .collect();
            assert_eq!(hashes, want, "start {start}");
            let siblings = list(&scheduled["window_siblings"]);
            assert_eq!(siblings.len(), 14);
            assert_eq!(
                tree::root_of(window_root(&hashes), &siblings, at >> 2),
                root
            );
            let req = request(inputs.clone());
            let at = TipCheck {
                node: 0,
                req: &req,
                package: &pkg,
                slot: &slot,
                block: 2,
                head: 0,
                previous: None,
                pending: None,
                rows: &store,
            };
            let own = held.round_values(&at, &state).unwrap();
            assert_eq!(own, scheduled);
            let honest: PublicMap = inputs.clone().into_iter().chain(own.clone()).collect();
            check_values(BOOK, commitment, &own, &request(honest.clone())).unwrap();
            for name in ["window_hashes", "window_siblings"] {
                let mut public = honest.clone();
                if let Some(PublicValue::Many(xs)) = public.get_mut(name) {
                    xs[1].0 += Fr::from(1u64);
                }
                let err = check_values(BOOK, commitment, &own, &request(public)).unwrap_err();
                assert!(
                    err.message.contains(name) && err.message.contains(BOOK),
                    "{err}"
                );
            }
        }
    }

    /// The scheduler reads the nodes' trees once per tree key, an opening
    /// round included: the query names the open slot and each node places
    /// the assigned index there, and the values are the chain verifier's.
    #[test]
    fn the_scheduler_reads_the_trees_once_on_an_opening_round() {
        let (store, commitment) = store();
        let pkg = package();
        let state = KeyState {
            key: BOOK.into(),
            commitment,
            record: None,
        };
        let held = pkg.tip_state(KeyRef::Read(0)).unwrap();
        let slot = SlotRead {
            at: KeyRef::Read(0),
            key: BOOK.into(),
            slot: Fr::from(0xa003u64),
            commitment,
        };
        let runtime = tokio::runtime::Runtime::new().unwrap();
        // an opening round (p1 = 0) and one that opens nothing
        for (inputs, open) in [(app(5, 0, 2, 2), 3u64), (app(5, 1, 2, 2), 1)] {
            let trees = Counted {
                store: &store,
                reads: Default::default(),
            };
            let scheduled = runtime
                .block_on(held.node_values(&pkg, BOOK, &state, &inputs, &trees))
                .unwrap();
            assert_eq!(trees.reads.into_inner(), 1);
            assert_eq!(scheduled["indices"], many([0, open, 2].map(Fr::from)));
            let req = request(inputs.clone());
            let at = TipCheck {
                node: 0,
                req: &req,
                package: &pkg,
                slot: &slot,
                block: 2,
                head: 0,
                previous: None,
                pending: None,
                rows: &store,
            };
            assert_eq!(held.round_values(&at, &state).unwrap(), scheduled);
        }
    }
}
