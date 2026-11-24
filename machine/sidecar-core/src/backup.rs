//! The store export a node's backup carries (docs/ARCHITECTURE.md section 6,
//! "Node-held state", recovery), and what a restore takes from it.
//!
//! An export is every row of every namespace of one node's store, this
//! node's pairs included: the namespace row with its `nsk_app` pair, the
//! packages, every canonical and live tip version with the nodes of its
//! clear tree, the `values` and `consumed` rows, the receipt rows, the
//! `requests` rows and every holder blob (`tip_blobs`, crate::store::blob:
//! the oblivious tree's DORAM levels, applied list and journals) as its
//! bytes. sidecar-node encrypts it under the operator's offline backup key;
//! this module neither encrypts nor writes files.
//!
//! A restore is a delta resync ([`crate::resync`], `Scope::Delta`): the
//! restored node tells its neighbours what its backup holds ([`Held`]: the
//! versions, leaves and `values` rows by name, each blob by name with the
//! digests of the two components its neighbours would send), they send every
//! row as a resync does but the components of those only (a blob's component
//! only when its digest differs: a DORAM level a rebuild has not replaced
//! since the backup is not sent), and the node takes the pairs of what its
//! backup holds from the backup ([`Own`]) and the rest from the
//! neighbours. The rows no neighbour can send come from the backup: the
//! `requests` rows and the receipt rows (a secret-shared receipt intake row's
//! envelope is sealed to this node alone).
//!
//! Orphaned versions and the dead records are not exported: a restore takes
//! its version list from the neighbours, which send no orphans, and its dead
//! records from the neighbours too, whose set is the current one (with the
//! rollbacks since the backup, and without the marks a later round cleared).

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::bind::Elem;
use crate::error::Refusal;
use crate::field::{FieldHex, Fr, RequestId};
use crate::pipeline::Node;
use crate::state::{NodeVersions, VersionViews};
use crate::store::blob::{Blob, Part};
use crate::store::{
    ConsumedRow, ManifestRow, NamespaceRow, PackageRow, ReceiptRow, RequestRow, Store, TipRows,
    TipVersion, ValueRow, VersionStatus, held_versions, tip_rows,
};
use crate::tree::TreeNode;

/// One namespace of an export.
#[derive(Clone, Debug, PartialEq)]
pub struct NamespaceExport {
    pub namespace: Fr,
    pub row: NamespaceRow,
    /// Every contract manifest version, oldest first.
    pub manifests: Vec<ManifestRow>,
    /// The packages of every version.
    pub packages: Vec<PackageRow>,
    /// Every canonical and live version, by key and commitment.
    pub versions: Vec<TipVersion>,
    /// Every node of the versions' clear trees, as (key, hash, node).
    pub nodes: Vec<(String, Fr, TreeNode)>,
    /// Every `values` row, by key.
    pub values: Vec<(String, ValueRow)>,
    pub consumed: Vec<ConsumedRow>,
    pub receipts: Vec<ReceiptRow>,
    pub requests: Vec<RequestRow>,
    /// Every holder blob, as (key, name, bytes).
    pub blobs: Vec<(String, String, Vec<u8>)>,
}

/// Every namespace of one node's store, and the node it is.
#[derive(Clone, Debug, PartialEq)]
pub struct StoreExport {
    /// The node's index: a backup restores into the same node only (its
    /// pairs are that node's).
    pub party: usize,
    pub namespaces: Vec<NamespaceExport>,
}

impl StoreExport {
    /// The export's row counts, for the operator's report.
    pub fn counts(&self) -> ExportCounts {
        let sum = |f: fn(&NamespaceExport) -> usize| self.namespaces.iter().map(f).sum();
        ExportCounts {
            namespaces: self.namespaces.len(),
            versions: sum(|n| n.versions.len()),
            tree_nodes: sum(|n| n.nodes.len()),
            values: sum(|n| n.values.len()),
            consumed: sum(|n| n.consumed.len()),
            receipts: sum(|n| n.receipts.len()),
            requests: sum(|n| n.requests.len()),
            blobs: sum(|n| n.blobs.len()),
        }
    }

    pub fn namespace(&self, namespace: Fr) -> Option<&NamespaceExport> {
        self.namespaces.iter().find(|n| n.namespace == namespace)
    }
}

/// How many rows an export holds.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportCounts {
    pub namespaces: usize,
    pub versions: usize,
    pub tree_nodes: usize,
    pub values: usize,
    pub consumed: usize,
    pub receipts: usize,
    pub requests: usize,
    #[serde(default)]
    pub blobs: usize,
}

/// Export every namespace of `node`'s store, each read under its namespace
/// lock (so a namespace's rows are those of one point between its commits;
/// a receipt the receipt route writes meanwhile may or may not be in it),
/// right after the prune pass marks its versions against the node's own
/// chain view `views` ([`NodeVersions::mark`]).
pub fn export<S: Store>(node: &Node<S>, views: &VersionViews<'_>) -> Result<StoreExport, Refusal> {
    let mut namespaces = Vec::new();
    for ns in node.store.namespaces()? {
        let _lock = node.lock_namespace(ns);
        NodeVersions::mark(&node.store, ns, views)?;
        namespaces.push(export_namespace(&node.store, ns)?);
    }
    Ok(StoreExport {
        party: node.index,
        namespaces,
    })
}

/// Every row of `namespace` in `store` (the caller holds its lock).
pub fn export_namespace<S: Store + ?Sized>(
    store: &S,
    namespace: Fr,
) -> Result<NamespaceExport, Refusal> {
    let ns = namespace;
    let row = store
        .namespace(ns)?
        .ok_or_else(|| Refusal::mpc_failure("store: a listed namespace has no row"))?;
    let (manifests, packages): (Vec<_>, Vec<_>) = held_versions(store, ns)?.into_iter().unzip();
    let TipRows { versions, nodes } = tip_rows(store, ns, &store.tip_keys(ns)?, |v| {
        v.status != VersionStatus::Orphan
    })?;
    let mut values = Vec::new();
    for key in store.value_keys(ns)? {
        if let Some(v) = store.value(ns, &key)? {
            values.push((key, v));
        }
    }
    let mut blobs = Vec::new();
    for key in store.blob_keys(ns)? {
        for name in store.blob_names(ns, &key)? {
            if let Some(bytes) = store.blob(ns, &key, &name)? {
                blobs.push((key.clone(), name, bytes));
            }
        }
    }
    Ok(NamespaceExport {
        namespace: ns,
        blobs,
        row,
        manifests,
        packages: packages.into_iter().flatten().collect(),
        versions,
        nodes: nodes.into_iter().map(|((k, h), n)| (k, h, n)).collect(),
        values,
        consumed: store.consumed_rows(ns)?,
        receipts: store.receipts(ns)?,
        requests: store.requests(ns)?,
    })
}

/// What a restored node's backup holds, by name: the items a delta resync's
/// neighbours send no components of. The restored node sends it to both.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Held {
    /// (namespace, key, commitment) of every version.
    pub versions: BTreeSet<(FieldHex, String, FieldHex)>,
    /// (namespace, key, leaf hash) of every leaf of a clear tree.
    pub leaves: BTreeSet<(FieldHex, String, FieldHex)>,
    /// (namespace, key, note hash, writer) of every `values` row.
    pub values: BTreeSet<(FieldHex, String, FieldHex, RequestId)>,
    /// (namespace, key, name, digest of the part node `i + 1` would send,
    /// digest of the part node `i - 1` would send) of every holder blob
    /// ([`part_digest`]).
    #[serde(default)]
    pub blobs: BTreeSet<(FieldHex, String, String, FieldHex, FieldHex)>,
}

/// The digest of one neighbour's part of a blob, as a delta resync
/// compares it: Poseidon2 over its public bytes, share component and
/// copies, each length-prefixed.
pub fn part_digest(part: &Part) -> Fr {
    let mut bytes =
        Vec::with_capacity(24 + part.public.len() + part.shares.len() + part.copies.len());
    for p in [&part.public, &part.shares, &part.copies] {
        bytes.extend_from_slice(&(p.len() as u64).to_le_bytes());
        bytes.extend_from_slice(p);
    }
    crate::schnorr::poseidon2_hash_bytes(&bytes)
}

/// The two parts of node `me`'s `blob` its neighbours hold alike: what
/// node `me + 1` sends (its `b` components, the blob's `a`) and what node
/// `me - 1` sends (its `a`, the blob's `b`).
pub fn own_parts(blob: &Blob) -> (Part, Part) {
    (
        Part {
            public: blob.public.clone(),
            shares: blob.shares.a.clone(),
            copies: blob.copies.a.clone(),
        },
        Part {
            public: blob.public.clone(),
            shares: blob.shares.b.clone(),
            copies: blob.copies.b.clone(),
        },
    )
}

impl Held {
    pub fn version(&self, namespace: Fr, key: &str, commitment: Fr) -> bool {
        self.versions
            .contains(&(FieldHex(namespace), key.to_string(), FieldHex(commitment)))
    }

    pub fn leaf(&self, namespace: Fr, key: &str, hash: Fr) -> bool {
        self.leaves
            .contains(&(FieldHex(namespace), key.to_string(), FieldHex(hash)))
    }

    pub fn value(&self, namespace: Fr, key: &str, note_hash: Fr, writer: RequestId) -> bool {
        self.values.contains(&(
            FieldHex(namespace),
            key.to_string(),
            FieldHex(note_hash),
            writer,
        ))
    }

    /// The digests of the blob `name` of `key` the backup holds: of the
    /// part node `i + 1` sends and of the part node `i - 1` sends.
    pub fn blob(&self, namespace: Fr, key: &str, name: &str) -> Option<(Fr, Fr)> {
        self.blobs
            .iter()
            .find(|(n, k, m, _, _)| n.fr() == namespace && k == key && m == name)
            .map(|(_, _, _, from_next, from_prev)| (from_next.fr(), from_prev.fr()))
    }
}

/// A backup's pairs, by the names [`Held`] lists, and its rows by namespace:
/// what the restored node takes from its backup.
pub struct Own<'a> {
    export: &'a StoreExport,
    versions: BTreeMap<(Fr, &'a str, Fr), &'a [Elem]>,
    leaves: BTreeMap<(Fr, &'a str, Fr), &'a [Elem]>,
    values: BTreeMap<(Fr, &'a str, Fr, RequestId), &'a [Elem]>,
    blobs: BTreeMap<(Fr, String, String), Blob>,
}

impl<'a> Own<'a> {
    pub fn new(export: &'a StoreExport) -> Self {
        let mut own = Own {
            export,
            versions: BTreeMap::new(),
            leaves: BTreeMap::new(),
            values: BTreeMap::new(),
            blobs: BTreeMap::new(),
        };
        for ns in &export.namespaces {
            let n = ns.namespace;
            for v in &ns.versions {
                own.versions
                    .insert((n, v.key.as_str(), v.commitment), v.vec.as_slice());
            }
            for (key, hash, node) in &ns.nodes {
                if let TreeNode::Leaf { vec, .. } = node {
                    own.leaves.insert((n, key.as_str(), *hash), vec.as_slice());
                }
            }
            for (key, v) in &ns.values {
                own.values.insert(
                    (n, key.as_str(), v.note_hash, v.request_id),
                    v.vec.as_slice(),
                );
            }
            for (key, name, bytes) in &ns.blobs {
                // a blob that does not parse is not held: the neighbours
                // send both its parts
                if let Ok(blob) = Blob::from_bytes(bytes) {
                    own.blobs.insert((n, key.clone(), name.clone()), blob);
                }
            }
        }
        own
    }

    /// The names of everything whose pairs the backup holds.
    pub fn held(&self) -> Held {
        Held {
            versions: self
                .versions
                .keys()
                .map(|(n, k, c)| (FieldHex(*n), k.to_string(), FieldHex(*c)))
                .collect(),
            leaves: self
                .leaves
                .keys()
                .map(|(n, k, h)| (FieldHex(*n), k.to_string(), FieldHex(*h)))
                .collect(),
            values: self
                .values
                .keys()
                .map(|(n, k, h, w)| (FieldHex(*n), k.to_string(), FieldHex(*h), *w))
                .collect(),
            blobs: self
                .blobs
                .iter()
                .map(|((n, k, m), blob)| {
                    let (from_next, from_prev) = own_parts(blob);
                    (
                        FieldHex(*n),
                        k.to_string(),
                        m.to_string(),
                        FieldHex(part_digest(&from_next)),
                        FieldHex(part_digest(&from_prev)),
                    )
                })
                .collect(),
        }
    }

    /// The backup's blob `name` of `key`, if it holds one.
    pub fn blob(&self, namespace: Fr, key: &str, name: &str) -> Option<&Blob> {
        self.blobs
            .get(&(namespace, key.to_string(), name.to_string()))
    }

    pub fn version(&self, namespace: Fr, key: &str, commitment: Fr) -> Option<&'a [Elem]> {
        self.versions.get(&(namespace, key, commitment)).copied()
    }

    pub fn leaf(&self, namespace: Fr, key: &str, hash: Fr) -> Option<&'a [Elem]> {
        self.leaves.get(&(namespace, key, hash)).copied()
    }

    pub fn value(
        &self,
        namespace: Fr,
        key: &str,
        note_hash: Fr,
        writer: RequestId,
    ) -> Option<&'a [Elem]> {
        self.values
            .get(&(namespace, key, note_hash, writer))
            .copied()
    }

    /// The backup's rows of `namespace`, if it holds the namespace.
    pub fn namespace(&self, namespace: Fr) -> Option<&'a NamespaceExport> {
        self.export.namespace(namespace)
    }

    pub fn party(&self) -> usize {
        self.export.party
    }
}
