//! The import of a rebuilt resync into the store.

use super::*;

/// How many rows a resync imported (at a neighbour: how many it sent).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Imported {
    pub namespaces: usize,
    pub packages: usize,
    pub versions: usize,
    pub tree_nodes: usize,
    /// The sidecar path's `values` rows.
    pub values: usize,
    /// The holder blobs.
    #[serde(default)]
    pub blobs: usize,
    /// The `consumed` rows.
    pub consumed: usize,
    /// The non-secret-shared receipt rows.
    pub receipts: usize,
    /// The non-secret-shared receipt rows the neighbours sent that were not kept
    /// (`rebuild`); 0 at a neighbour.
    pub receipts_left_out: usize,
    /// The `requests` rows, from the backup (a delta resync).
    #[serde(default)]
    pub requests: usize,
    /// The dead records.
    #[serde(default)]
    pub dead_records: usize,
    /// The versions, leaves and `values` rows whose pairs came from the
    /// backup rather than the neighbours (a delta resync; 0 at a neighbour).
    #[serde(default)]
    pub from_backup: usize,
    /// The blob parts (two per blob) taken from the backup rather than a
    /// neighbour (a delta resync; 0 at a neighbour).
    #[serde(default)]
    pub blob_parts_from_backup: usize,
}

/// Stage the clear tree of tree version `v` of `namespace` from the
/// rebuilt `nodes`, counted against `read` (the store's nodes, or none for a
/// key whose tree the commit replaces). 400 for a version whose clear tree
/// does not give its commitment.
fn stage_tree<R: StoreRead + ?Sized>(
    read: &R,
    txn: &mut crate::store::Txn,
    namespace: Fr,
    v: &TipVersion,
    nodes: &BTreeMap<(String, Fr), TreeNode>,
) -> Result<(), Refusal> {
    let Some(t) = v.tree.and_then(VersionTree::clear) else {
        return Ok(());
    };
    let get = |h: Fr| -> Result<Option<TreeNode>, Refusal> {
        Ok(nodes.get(&(v.key.clone(), h)).cloned())
    };
    let walked = tree::walk(&get, t.root)?;
    let slot = crate::field::fr_from_hex(&v.key).map_err(|e| {
        Refusal::bad_request(format!("resync: key `{}` is not a field ({e})", v.key))
    })?;
    if tree::commitment(namespace, slot, t.root) != v.commitment {
        return Err(Refusal::bad_request(format!(
            "resync: key `{}`: the tree's root does not give the version's commitment {}",
            v.key,
            fr_to_hex(v.commitment)
        )));
    }
    // children before parents: the leaves, then the internal nodes bottom
    // up (the walk lists them top down)
    let mut added: Vec<(Fr, TreeNode)> = walked
        .leaves
        .into_iter()
        .map(|l| {
            (
                l.hash,
                TreeNode::Leaf {
                    index: l.index,
                    vec: l.vec,
                },
            )
        })
        .collect();
    added.extend(
        walked
            .inner
            .into_iter()
            .rev()
            .map(|(h, left, right)| (h, TreeNode::Inner { left, right })),
    );
    TreeNodes { read, key: &v.key }.add_version(txn, t.root, added)
}

/// Import `rebuilt` into `store`. A store or delta scope: one commit per
/// namespace (with its dead records, and a delta's `requests` rows), then its
/// receipt rows; 409 if the store holds the namespace already (a resync
/// imports into an empty store). A key scope: one commit that
/// replaces the key's versions and clear tree; 409 if the store does not
/// hold the namespace, 400 if its namespace row is not the rebuilt one (the
/// row itself needs a store resync). 400 for a tree version whose clear
/// tree does not give its commitment.
pub fn import<S: Store>(store: &S, rebuilt: Rebuilt) -> Result<Imported, Refusal> {
    let mut done = Imported {
        receipts_left_out: rebuilt.receipts_left_out,
        from_backup: rebuilt.from_backup,
        blob_parts_from_backup: rebuilt.blob_parts_from_backup,
        ..Imported::default()
    };
    for ns in rebuilt.namespaces {
        let mut txn = store.begin(ns.namespace);
        let fresh = MemoryStore::new();
        let read: &dyn StoreRead = match rebuilt.scope.key() {
            None => {
                txn.import_namespace(ns.row);
                store
            }
            Some((_, key)) => {
                let stored = store.namespace(ns.namespace)?.ok_or_else(|| {
                    Refusal::conflict(format!(
                        "resync: this node holds no namespace {}; a resync of one key imports \
                         into a store that holds it",
                        fr_to_hex(ns.namespace)
                    ))
                })?;
                if stored != ns.row {
                    return Err(Refusal::bad_request(format!(
                        "resync: namespace {}: this node's row is not the one its neighbours \
                         rebuild (resync the whole store)",
                        fr_to_hex(ns.namespace)
                    )));
                }
                txn.import_key(key);
                &fresh
            }
        };
        done.packages += ns.packages.len();
        for m in ns.manifests {
            txn.put_manifest(m);
        }
        for p in ns.packages {
            txn.put_package(p);
        }
        for v in &ns.versions {
            stage_tree(read, &mut txn, ns.namespace, v, &ns.nodes)?;
        }
        done.tree_nodes += txn.nodes().len();
        done.versions += ns.versions.len();
        for v in ns.versions {
            txn.version(crate::store::VersionWrite::Put(v));
        }
        done.values += ns.values.len();
        for v in ns.values {
            txn.import_value(v);
        }
        done.blobs += ns.blobs.len();
        for (key, name, bytes) in ns.blobs {
            txn.blob(&key, &name, Some(bytes));
        }
        done.consumed += ns.consumed.len();
        for c in ns.consumed {
            txn.consume(c);
        }
        done.requests += ns.requests.len();
        for r in ns.requests {
            txn.import_request(r);
        }
        done.dead_records += ns.dead.len();
        for d in ns.dead {
            txn.import_dead(d);
        }
        store.commit(txn)?;
        done.receipts += ns.receipts.len();
        for r in ns.receipts {
            store.put_receipt(ns.namespace, r)?;
        }
        done.namespaces += 1;
    }
    Ok(done)
}
