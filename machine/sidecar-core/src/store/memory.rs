//! The tables in memory and the in-memory backend over them.

use std::collections::BTreeSet;
use std::sync::Mutex;

use super::*;

/// Map key for a namespace-scoped row.
type NsKey<K> = (Fr, K);

/// Every table of the store trait, in memory: the in-memory backend's state,
/// and the local store's (which keeps its log beside them, `crate::local`).
#[derive(Clone, Debug, Default, PartialEq)]
pub(crate) struct Tables {
    pub(crate) namespaces: BTreeMap<Fr, NamespaceRow>,
    /// `manifests`, by (namespace, manifest hash): the versions a namespace
    /// holds (`retained_versions`).
    pub(crate) manifests: BTreeMap<NsKey<Fr>, ManifestRow>,
    /// `packages` of each held version, by (namespace, (manifest hash,
    /// name)).
    pub(crate) packages: BTreeMap<NsKey<(Fr, String)>, PackageRow>,
    pub(crate) consumed: BTreeMap<NsKey<Fr>, ConsumedRow>,
    pub(crate) dead: BTreeMap<NsKey<Fr>, DeadRecord>,
    pub(crate) requests: BTreeMap<NsKey<RequestId>, RequestRow>,
    /// `values` as the backends store it: the encoded vector.
    pub(crate) values: BTreeMap<NsKey<String>, (Vec<u8>, Fr, RequestId)>,
    pub(crate) receipts: BTreeMap<NsKey<Fr>, ReceiptRow>,
    /// `tip_versions`, by (namespace, (key, commitment)).
    pub(crate) versions: BTreeMap<NsKey<(String, Fr)>, TipVersion>,
    /// `tip_nodes`, by (namespace, (key, hash)).
    pub(crate) nodes: BTreeMap<NsKey<(String, Fr)>, StoredNode>,
    /// `tip_blobs`, by (namespace, (key, name)).
    pub(crate) blobs: BTreeMap<NsKey<(String, String)>, Vec<u8>>,
}

/// The rows of `namespace` in a namespace-keyed table, in key order.
fn rows_of<K: Ord, V: Clone>(table: &BTreeMap<NsKey<K>, V>, namespace: Fr) -> Vec<V> {
    table
        .iter()
        .filter(|((ns, _), _)| *ns == namespace)
        .map(|(_, row)| row.clone())
        .collect()
}

/// The listings of the store trait over the tables, shared by both
/// in-memory backends.
impl Tables {
    pub(crate) fn namespace_list(&self) -> Vec<Fr> {
        self.namespaces.keys().copied().collect()
    }

    /// Write `row`, a contract manifest version of `namespace`: the versions
    /// `retained_versions` does not keep are dropped with their packages.
    pub(crate) fn put_manifest(&mut self, namespace: Fr, row: ManifestRow) {
        let held: Vec<(Fr, u64)> = rows_of(&self.manifests, namespace)
            .iter()
            .map(|m| (m.manifest_hash, m.seq))
            .collect();
        let keep = retained_versions(&held, &row);
        self.manifests
            .retain(|(ns, h), _| *ns != namespace || keep.contains(h));
        self.packages
            .retain(|(ns, (h, _)), _| *ns != namespace || keep.contains(h));
        self.manifests.insert((namespace, row.manifest_hash), row);
    }

    /// The hash of the newest version `namespace` holds.
    fn newest_hash(&self, namespace: Fr) -> Option<Fr> {
        newest_version(rows_of(&self.manifests, namespace)).map(|m| m.manifest_hash)
    }

    pub(crate) fn packages_of(&self, namespace: Fr) -> Vec<PackageRow> {
        rows_of(&self.packages, namespace)
    }

    /// The package names of the newest version, in byte order.
    pub(crate) fn package_names(&self, namespace: Fr) -> Vec<String> {
        let newest = self.newest_hash(namespace);
        self.packages
            .keys()
            .filter(|(ns, (h, _))| *ns == namespace && Some(*h) == newest)
            .map(|(_, (_, name))| name.clone())
            .collect()
    }

    pub(crate) fn tip_keys(&self, namespace: Fr) -> Vec<String> {
        let keys: BTreeSet<String> = self
            .versions
            .keys()
            .filter(|(ns, _)| *ns == namespace)
            .map(|(_, (key, _))| key.clone())
            .collect();
        keys.into_iter().collect()
    }

    pub(crate) fn value_keys(&self, namespace: Fr) -> Vec<String> {
        self.values
            .keys()
            .filter(|(ns, _)| *ns == namespace)
            .map(|(_, key)| key.clone())
            .collect()
    }

    pub(crate) fn blob_keys(&self, namespace: Fr) -> Vec<String> {
        let keys: BTreeSet<String> = self
            .blobs
            .keys()
            .filter(|(ns, _)| *ns == namespace)
            .map(|(_, (key, _))| key.clone())
            .collect();
        keys.into_iter().collect()
    }

    pub(crate) fn consumed_rows(&self, namespace: Fr) -> Vec<ConsumedRow> {
        rows_of(&self.consumed, namespace)
    }

    pub(crate) fn receipt_rows(&self, namespace: Fr) -> Vec<ReceiptRow> {
        rows_of(&self.receipts, namespace)
    }

    pub(crate) fn receipt_row(&self, namespace: Fr, request_id: Fr) -> Option<ReceiptRow> {
        self.receipts.get(&(namespace, request_id)).cloned()
    }

    pub(crate) fn request_rows(&self, namespace: Fr) -> Vec<RequestRow> {
        rows_of(&self.requests, namespace)
    }

    pub(crate) fn dead_rows(&self, namespace: Fr) -> Vec<DeadRecord> {
        rows_of(&self.dead, namespace)
    }

    pub(crate) fn expired_receipts(&self, block: u64) -> Vec<(Fr, Fr)> {
        self.receipts
            .iter()
            .filter(|(_, row)| row.prunable_at(block))
            .map(|(key, _)| *key)
            .collect()
    }
}

impl StoreRead for Tables {
    fn namespace(&self, namespace: Fr) -> Result<Option<NamespaceRow>, Refusal> {
        Ok(self.namespaces.get(&namespace).cloned())
    }
    fn contract_manifest(&self, namespace: Fr) -> Result<Option<ManifestRow>, Refusal> {
        Ok(newest_version(rows_of(&self.manifests, namespace)))
    }
    fn contract_manifests(&self, namespace: Fr) -> Result<Vec<ManifestRow>, Refusal> {
        let mut rows = rows_of(&self.manifests, namespace);
        rows.sort_by(|a, b| b.seq.cmp(&a.seq));
        Ok(rows)
    }
    fn package(&self, namespace: Fr, name: &str) -> Result<Option<PackageRow>, Refusal> {
        Ok(match self.newest_hash(namespace) {
            Some(hash) => self.package_in(namespace, hash, name)?,
            None => None,
        })
    }
    fn package_in(
        &self,
        namespace: Fr,
        manifest_hash: Fr,
        name: &str,
    ) -> Result<Option<PackageRow>, Refusal> {
        Ok(self
            .packages
            .get(&(namespace, (manifest_hash, name.to_string())))
            .cloned())
    }
    fn consumed(&self, namespace: Fr, note_hash: Fr) -> Result<Option<ConsumedRow>, Refusal> {
        Ok(self.consumed.get(&(namespace, note_hash)).cloned())
    }
    fn dead_record(&self, namespace: Fr, note_hash: Fr) -> Result<Option<DeadRecord>, Refusal> {
        Ok(self.dead.get(&(namespace, note_hash)).cloned())
    }
    fn request(&self, namespace: Fr, request_id: RequestId) -> Result<Option<RequestRow>, Refusal> {
        Ok(self.requests.get(&(namespace, request_id)).cloned())
    }
    fn chain_request(
        &self,
        namespace: Fr,
        chain_request_id: Fr,
    ) -> Result<Option<RequestRow>, Refusal> {
        let rows = self
            .requests
            .iter()
            .filter(|((ns, _), _)| *ns == namespace)
            .map(|(_, row)| row);
        Ok(latest_chain_row(rows, chain_request_id))
    }
    fn value(&self, namespace: Fr, key: &str) -> Result<Option<ValueRow>, Refusal> {
        self.values
            .get(&(namespace, key.to_string()))
            .map(|(bytes, note_hash, request_id)| {
                Ok(ValueRow {
                    vec: decode_vec(bytes)
                        .map_err(|e| Refusal::mpc_failure(format!("store: key `{key}`: {e}")))?,
                    note_hash: *note_hash,
                    request_id: *request_id,
                })
            })
            .transpose()
    }
    fn tip_version(
        &self,
        namespace: Fr,
        key: &str,
        commitment: Fr,
    ) -> Result<Option<TipVersion>, Refusal> {
        Ok(self
            .versions
            .get(&(namespace, (key.to_string(), commitment)))
            .cloned())
    }
    fn tip_versions(&self, namespace: Fr, key: &str) -> Result<Vec<TipVersion>, Refusal> {
        Ok(self
            .versions
            .range((namespace, (key.to_string(), Fr::from(0u64)))..)
            .take_while(|((ns, (k, _)), _)| *ns == namespace && k == key)
            .map(|(_, v)| v.clone())
            .collect())
    }
    fn tip_node(&self, namespace: Fr, key: &str, hash: Fr) -> Result<Option<StoredNode>, Refusal> {
        Ok(self
            .nodes
            .get(&(namespace, (key.to_string(), hash)))
            .cloned())
    }
    fn blob(&self, namespace: Fr, key: &str, name: &str) -> Result<Option<Vec<u8>>, Refusal> {
        Ok(self
            .blobs
            .get(&(namespace, (key.to_string(), name.to_string())))
            .cloned())
    }
    fn blob_names(&self, namespace: Fr, key: &str) -> Result<Vec<String>, Refusal> {
        Ok(self
            .blobs
            .keys()
            .filter(|(ns, (k, _))| *ns == namespace && k == key)
            .map(|(_, (_, name))| name.clone())
            .collect())
    }
}

impl Tables {
    /// Apply one row write of a commit under namespace `ns`.
    fn apply(&mut self, ns: Fr, write: RowWrite<'_>) {
        match write {
            RowWrite::Namespace(row) => {
                self.namespaces.insert(ns, row.clone());
            }
            RowWrite::NskApp(share) => {
                if let Some(row) = self.namespaces.get_mut(&ns) {
                    row.nsk_app = *share;
                }
            }
            RowWrite::Manifest(row) => self.put_manifest(ns, row.clone()),
            RowWrite::Package(row) => {
                self.packages
                    .insert((ns, (row.manifest_hash, row.name.clone())), row.clone());
            }
            RowWrite::Seq(seq) => {
                if let Some(row) = self.namespaces.get_mut(&ns) {
                    row.seq = seq;
                }
            }
            RowWrite::Consumed(row) => {
                self.consumed.insert((ns, row.note_hash), row.clone());
            }
            RowWrite::Revive(note_hash) => {
                self.dead.remove(&(ns, note_hash));
            }
            RowWrite::Value {
                key,
                vec,
                note_hash,
                request_id,
            } => {
                self.values.insert(
                    (ns, key.to_string()),
                    (encode_vec(vec), note_hash, request_id),
                );
            }
            RowWrite::Rerun(request_id) => {
                self.requests.remove(&(ns, request_id));
            }
            RowWrite::Request(row) => {
                self.requests.insert((ns, row.request_id), *row);
            }
            RowWrite::ImportDead(row) => {
                self.dead.insert((ns, row.note_hash), row.clone());
            }
            RowWrite::Dead(row) => {
                self.dead.insert((ns, row.note_hash), row);
            }
            RowWrite::ClearKey(key) => {
                self.versions.retain(|(n, (k, _)), _| *n != ns || k != key);
                self.nodes.retain(|(n, (k, _)), _| *n != ns || k != key);
                self.blobs.retain(|(n, (k, _)), _| *n != ns || k != key);
            }
            RowWrite::ClearTip => {
                self.versions.retain(|(n, _), _| *n != ns);
                self.nodes.retain(|(n, _), _| *n != ns);
            }
            RowWrite::Version(VersionWrite::Put(v)) => {
                self.versions
                    .insert((ns, (v.key.clone(), v.commitment)), v.clone());
            }
            RowWrite::Version(VersionWrite::Mark {
                key,
                commitment,
                status,
                block,
                block_hash,
            }) => {
                if let Some(v) = self.versions.get_mut(&(ns, (key.clone(), *commitment))) {
                    v.status = *status;
                    v.block = *block;
                    v.block_hash = *block_hash;
                }
            }
            RowWrite::Version(VersionWrite::Delete { key, commitment }) => {
                self.versions.remove(&(ns, (key.clone(), *commitment)));
            }
            RowWrite::Node { key, hash, node } => {
                let at = (ns, (key.to_string(), hash));
                match node {
                    Some(node) => self.nodes.insert(at, node.clone()),
                    None => self.nodes.remove(&at),
                };
            }
            RowWrite::Blob { key, name, bytes } => {
                let at = (ns, (key.to_string(), name.to_string()));
                match bytes {
                    Some(bytes) => self.blobs.insert(at, bytes.to_vec()),
                    None => self.blobs.remove(&at),
                };
            }
            RowWrite::DeleteValue(key) => {
                self.values.remove(&(ns, key.to_string()));
            }
            RowWrite::Unconsume(request_id) => {
                self.consumed
                    .retain(|(n, _), row| *n != ns || row.request_id != request_id);
            }
            RowWrite::RolledBack(request_id) => {
                if let Some(row) = self.requests.get_mut(&(ns, request_id)) {
                    row.status = RequestStatus::RolledBack;
                }
            }
        }
    }
}

/// The in-memory backend, for tests and single-process development. One mutex
/// serialises every commit, so a commit's check and its writes see one state.
#[derive(Default)]
pub struct MemoryStore {
    tables: Mutex<Tables>,
}

/// A copy of every table of a [`MemoryStore`], for tests that check a refused
/// request changed nothing.
#[derive(Clone, Debug, PartialEq)]
pub struct MemorySnapshot(pub(crate) Tables);

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Drop every row, as a store deleted under a running node (tests of
    /// the resync).
    pub fn clear(&self) {
        *self.lock() = Tables::default();
    }

    /// Every table as it stands.
    pub fn snapshot(&self) -> MemorySnapshot {
        MemorySnapshot(self.lock().clone())
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Tables> {
        // A panic inside a commit leaves no half-applied writes (apply does not
        // fail), so a poisoned lock still guards a consistent state.
        self.tables
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl StoreRead for MemoryStore {
    fn namespace(&self, namespace: Fr) -> Result<Option<NamespaceRow>, Refusal> {
        self.lock().namespace(namespace)
    }
    fn contract_manifest(&self, namespace: Fr) -> Result<Option<ManifestRow>, Refusal> {
        self.lock().contract_manifest(namespace)
    }
    fn contract_manifests(&self, namespace: Fr) -> Result<Vec<ManifestRow>, Refusal> {
        self.lock().contract_manifests(namespace)
    }
    fn package(&self, namespace: Fr, name: &str) -> Result<Option<PackageRow>, Refusal> {
        self.lock().package(namespace, name)
    }
    fn package_in(
        &self,
        namespace: Fr,
        manifest_hash: Fr,
        name: &str,
    ) -> Result<Option<PackageRow>, Refusal> {
        self.lock().package_in(namespace, manifest_hash, name)
    }
    fn consumed(&self, namespace: Fr, note_hash: Fr) -> Result<Option<ConsumedRow>, Refusal> {
        self.lock().consumed(namespace, note_hash)
    }
    fn dead_record(&self, namespace: Fr, note_hash: Fr) -> Result<Option<DeadRecord>, Refusal> {
        self.lock().dead_record(namespace, note_hash)
    }
    fn request(&self, namespace: Fr, request_id: RequestId) -> Result<Option<RequestRow>, Refusal> {
        self.lock().request(namespace, request_id)
    }
    fn chain_request(
        &self,
        namespace: Fr,
        chain_request_id: Fr,
    ) -> Result<Option<RequestRow>, Refusal> {
        self.lock().chain_request(namespace, chain_request_id)
    }
    fn value(&self, namespace: Fr, key: &str) -> Result<Option<ValueRow>, Refusal> {
        self.lock().value(namespace, key)
    }
    fn tip_version(
        &self,
        namespace: Fr,
        key: &str,
        commitment: Fr,
    ) -> Result<Option<TipVersion>, Refusal> {
        self.lock().tip_version(namespace, key, commitment)
    }
    fn tip_versions(&self, namespace: Fr, key: &str) -> Result<Vec<TipVersion>, Refusal> {
        self.lock().tip_versions(namespace, key)
    }
    fn tip_node(&self, namespace: Fr, key: &str, hash: Fr) -> Result<Option<StoredNode>, Refusal> {
        self.lock().tip_node(namespace, key, hash)
    }
    fn blob(&self, namespace: Fr, key: &str, name: &str) -> Result<Option<Vec<u8>>, Refusal> {
        self.lock().blob(namespace, key, name)
    }
    fn blob_names(&self, namespace: Fr, key: &str) -> Result<Vec<String>, Refusal> {
        self.lock().blob_names(namespace, key)
    }
}

impl Store for MemoryStore {
    fn commit(&self, txn: Txn) -> Result<(), Refusal> {
        let mut tables = self.lock();
        rules::check_commit(&*tables, &txn)?;
        let ns = txn.namespace();
        for write in txn.writes() {
            tables.apply(ns, write);
        }
        Ok(())
    }

    fn prune_requests(&self, older_than: u64) -> Result<usize, Refusal> {
        let mut tables = self.lock();
        let before = tables.requests.len();
        tables
            .requests
            .retain(|_, row| row.created_at >= older_than);
        Ok(before - tables.requests.len())
    }

    fn holds_values(&self) -> bool {
        true
    }

    fn namespaces(&self) -> Result<Vec<Fr>, Refusal> {
        Ok(self.lock().namespace_list())
    }

    fn package_names(&self, namespace: Fr) -> Result<Vec<String>, Refusal> {
        Ok(self.lock().package_names(namespace))
    }

    fn tip_keys(&self, namespace: Fr) -> Result<Vec<String>, Refusal> {
        Ok(self.lock().tip_keys(namespace))
    }

    fn value_keys(&self, namespace: Fr) -> Result<Vec<String>, Refusal> {
        Ok(self.lock().value_keys(namespace))
    }

    fn blob_keys(&self, namespace: Fr) -> Result<Vec<String>, Refusal> {
        Ok(self.lock().blob_keys(namespace))
    }

    fn consumed_rows(&self, namespace: Fr) -> Result<Vec<ConsumedRow>, Refusal> {
        Ok(self.lock().consumed_rows(namespace))
    }

    fn receipts(&self, namespace: Fr) -> Result<Vec<ReceiptRow>, Refusal> {
        Ok(self.lock().receipt_rows(namespace))
    }

    fn receipt(&self, namespace: Fr, request_id: Fr) -> Result<Option<ReceiptRow>, Refusal> {
        Ok(self.lock().receipt_row(namespace, request_id))
    }

    fn requests(&self, namespace: Fr) -> Result<Vec<RequestRow>, Refusal> {
        Ok(self.lock().request_rows(namespace))
    }

    fn dead_records(&self, namespace: Fr) -> Result<Vec<DeadRecord>, Refusal> {
        Ok(self.lock().dead_rows(namespace))
    }

    fn put_receipt(&self, namespace: Fr, row: ReceiptRow) -> Result<(), Refusal> {
        self.lock()
            .receipts
            .insert((namespace, row.request_id), row);
        Ok(())
    }

    fn expired_receipts(&self, block: u64) -> Result<Vec<(Fr, Fr)>, Refusal> {
        Ok(self.lock().expired_receipts(block))
    }

    fn prune_receipts(&self, block: u64, ids: &[(Fr, Fr)]) -> Result<usize, Refusal> {
        let mut tables = self.lock();
        let mut pruned = 0;
        for key in ids {
            if tables
                .receipts
                .get(key)
                .is_some_and(|row| row.prunable_at(block))
            {
                tables.receipts.remove(key);
                pruned += 1;
            }
        }
        Ok(pruned)
    }
}
