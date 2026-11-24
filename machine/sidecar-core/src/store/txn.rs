//! [`Txn`]: the writes of one commit, with its builders and getters.

use std::collections::BTreeSet;

use super::*;

/// The writes of one commit, under one namespace. Built by the round (or
/// REGISTER, DISABLE, rollback) and applied by [`Store::commit`].
#[derive(Clone, Debug, PartialEq)]
pub struct Txn {
    pub(super) namespace: Fr,
    pub(super) namespace_row: Option<NamespaceRow>,
    pub(super) namespace_repair: Option<NamespaceRow>,
    pub(super) manifests: Vec<ManifestRow>,
    pub(super) packages: Vec<PackageRow>,
    pub(super) loaded: BTreeSet<String>,
    pub(super) consumed: Vec<ConsumedRow>,
    pub(super) values: Vec<ValueWrite>,
    pub(super) sealed: Vec<Sealed>,
    pub(super) request: Option<NewRequest>,
    pub(super) rerun: bool,
    pub(super) rollback: Option<Rollback>,
    pub(super) seq: Option<u64>,
    pub(super) versions: Vec<VersionWrite>,
    pub(super) nodes: NodeWrites,
    pub(super) blobs: BlobWrites,
    pub(super) import: Option<Import>,
    pub(super) imported_values: Vec<RestoredValue>,
    pub(super) imported_requests: Vec<RequestRow>,
    pub(super) imported_dead: Vec<DeadRecord>,
}

impl Txn {
    /// An empty transaction under `namespace`.
    pub fn new(namespace: Fr) -> Self {
        Txn {
            namespace,
            namespace_row: None,
            namespace_repair: None,
            manifests: Vec::new(),
            packages: Vec::new(),
            loaded: BTreeSet::new(),
            consumed: Vec::new(),
            values: Vec::new(),
            sealed: Vec::new(),
            request: None,
            rerun: false,
            rollback: None,
            seq: None,
            versions: Vec::new(),
            nodes: BTreeMap::new(),
            blobs: BTreeMap::new(),
            import: None,
            imported_values: Vec::new(),
            imported_requests: Vec::new(),
            imported_dead: Vec::new(),
        }
    }

    pub fn namespace(&self) -> Fr {
        self.namespace
    }

    /// The first REGISTER's namespace row. The commit refuses it if the
    /// namespace already has one.
    pub fn register_namespace(&mut self, row: NamespaceRow) {
        self.namespace_row = Some(row);
    }

    /// A resync's import of a namespace this store does not hold (ARCHITECTURE.md
    /// section 6, "Node-held state", recovery): its row as the two neighbours
    /// sent it, at any `seq`, then [`Txn::put_package`], [`Txn::version`]
    /// puts, [`Txn::node`] writes, [`Txn::import_value`] rows and
    /// [`Txn::consume`] rows, and nothing else, with no request row. The
    /// commit refuses it (409) if the namespace is held.
    pub fn import_namespace(&mut self, row: NamespaceRow) {
        self.namespace_row = Some(row);
        self.import = Some(Import::Namespace);
    }

    /// A resync's import of one tip key of a namespace this store holds:
    /// the commit deletes every `tip_versions` row of `key` and every node
    /// of its clear tree, then writes the transaction's [`Txn::version`]
    /// puts and [`Txn::node`] writes, all of `key`, and nothing else. The
    /// commit refuses it (409) if the namespace is not held.
    pub fn import_key(&mut self, key: &str) {
        self.import = Some(Import::Key(key.to_string()));
    }

    /// A share refresh of a namespace this store holds (ARCHITECTURE.md
    /// section 6, "Node replacement and key epochs"): `row` is the stored
    /// namespace row with its refreshed `nsk_app` pair, then
    /// [`Txn::version`] puts of every stored version and [`Txn::node`]
    /// writes of every stored tree node (the leaves' pairs refreshed),
    /// [`Txn::import_value`] rows of every `values` row (their pairs
    /// refreshed), and nothing else. The commit replaces the `nsk_app` pair,
    /// deletes every `tip_versions` row and tree node of the namespace and
    /// writes the transaction's, and replaces each `values` row; it refuses
    /// (409) if the namespace is not held, and (500) a row that changes the
    /// owner, `npk_app_hash` or `seq`.
    pub fn import_refresh(&mut self, row: NamespaceRow) {
        self.namespace_repair = Some(row);
        self.import = Some(Import::Refresh);
    }

    /// A `values` row of a namespace import, with the request that wrote it.
    pub fn import_value(&mut self, value: RestoredValue) {
        self.imported_values.push(value);
    }

    /// A `requests` row of a namespace import, written as it stands (its
    /// status and sealed entries included): a restore's rows from the
    /// node's backup.
    pub fn import_request(&mut self, row: RequestRow) {
        self.imported_requests.push(row);
    }

    /// A `dead_records` row of a namespace import (a restore's, from the
    /// node's backup).
    pub fn import_dead(&mut self, row: DeadRecord) {
        self.imported_dead.push(row);
    }

    /// A resent first REGISTER at a node that already holds the namespace row:
    /// replace its nsk_app share with the fresh one in `row`. The commit refuses
    /// it (409) unless the stored row has the same owner and npk_app_hash and a
    /// stored `seq` of 0, so a repair never changes the owner, the identity or
    /// the sequence number.
    pub fn repair_namespace(&mut self, row: NamespaceRow) {
        self.namespace_repair = Some(row);
    }

    /// A contract manifest version of the namespace (REGISTER, a registry
    /// resync, a namespace import, which writes every version the
    /// neighbours hold, oldest first): the commit stores each in turn and
    /// keeps the versions [`retained_versions`] names, dropping the others
    /// with their packages. The [`Txn::put_package`] rows of a transaction
    /// that writes a version belong to the versions it writes.
    pub fn put_manifest(&mut self, row: ManifestRow) {
        self.manifests.push(row);
    }

    /// Add or replace a package of the contract manifest this transaction
    /// writes, or of the stored one (REGISTER, DISABLE; the register handler
    /// decides whether a replacement is allowed).
    pub fn put_package(&mut self, row: PackageRow) {
        self.packages.push(row);
    }

    /// A later signed REGISTER or DISABLE body's `seq`. The commit refuses it
    /// (409) unless it is the stored sequence number plus one, so a replayed
    /// registry body changes nothing.
    pub fn advance_seq(&mut self, seq: u64) {
        self.seq = Some(seq);
    }

    /// Record that the round LOADed the node-held `key`, which allows it to
    /// rewrite the key.
    pub fn loaded(&mut self, key: &str) {
        self.loaded.insert(key.to_string());
    }

    /// Add a consumed row (CONSUME with policy `once`).
    pub fn consume(&mut self, row: ConsumedRow) {
        self.consumed.push(row);
    }

    /// This node's third of a new client-held state record, kept in the request
    /// row for FETCH.
    pub fn add_record(&mut self, key: &str, note_hash: Fr, c_i: Vec<u8>) {
        self.sealed.push(Sealed {
            kind: SealedKind::Record,
            key: key.to_string(),
            note_hash,
            c_i,
        });
    }

    /// The round's request row.
    pub fn put_request(&mut self, request: NewRequest) {
        self.request = Some(request);
    }

    /// The round's request row replaces the stored row of its request id, a
    /// rolled-back attempt at the same queued request with the same body,
    /// which step 5 treated as absent ([`RequestRow::reruns`]). The commit
    /// refuses (409) unless the stored row is still such a row.
    pub fn rerun(&mut self) {
        self.rerun = true;
    }

    /// A `tip_versions` write of the round (a node-held tip key).
    pub fn version(&mut self, write: VersionWrite) {
        self.versions.push(write);
    }

    /// Stage a `tip_nodes` write of `key` (the last staged write of a hash
    /// wins); [`rules::TreeNodes`] stages them.
    pub fn node(&mut self, key: &str, hash: Fr, node: Option<StoredNode>) {
        self.nodes.insert((key.to_string(), hash), node);
    }

    /// Stage a `tip_blobs` write of `key` under `name` (the last staged write
    /// of a name wins): the bytes to store, or `None` to delete the row.
    pub fn blob(&mut self, key: &str, name: &str, bytes: Option<Vec<u8>>) {
        self.blobs
            .insert((key.to_string(), name.to_string()), bytes);
    }

    pub fn blobs(&self) -> &BlobWrites {
        &self.blobs
    }

    pub fn namespace_row(&self) -> Option<&NamespaceRow> {
        self.namespace_row.as_ref()
    }
    pub fn namespace_repair(&self) -> Option<&NamespaceRow> {
        self.namespace_repair.as_ref()
    }
    pub fn seq(&self) -> Option<u64> {
        self.seq
    }
    /// The contract manifest versions this transaction writes, in order.
    pub fn manifests(&self) -> &[ManifestRow] {
        &self.manifests
    }

    pub fn packages(&self) -> &[PackageRow] {
        &self.packages
    }
    pub fn loaded_keys(&self) -> &BTreeSet<String> {
        &self.loaded
    }
    pub fn consumed(&self) -> &[ConsumedRow] {
        &self.consumed
    }
    pub fn values(&self) -> &[ValueWrite] {
        &self.values
    }
    pub fn sealed(&self) -> &[Sealed] {
        &self.sealed
    }
    pub fn request(&self) -> Option<&NewRequest> {
        self.request.as_ref()
    }
    pub fn rollback(&self) -> Option<&Rollback> {
        self.rollback.as_ref()
    }
    pub fn versions(&self) -> &[VersionWrite] {
        &self.versions
    }
    pub fn nodes(&self) -> &NodeWrites {
        &self.nodes
    }
    /// What a resync's import writes, if the transaction is one.
    pub fn import(&self) -> Option<&Import> {
        self.import.as_ref()
    }
    /// The `values` rows of a namespace import.
    pub fn imported_values(&self) -> &[RestoredValue] {
        &self.imported_values
    }
    /// The `requests` rows of a namespace import.
    pub fn imported_requests(&self) -> &[RequestRow] {
        &self.imported_requests
    }
    /// The `dead_records` rows of a namespace import.
    pub fn imported_dead(&self) -> &[DeadRecord] {
        &self.imported_dead
    }

    /// The request row the commit writes: the new request with the collected
    /// sealed entries.
    pub fn request_row(&self) -> Option<RequestRow> {
        self.request.as_ref().map(|r| RequestRow {
            request_id: r.request_id,
            body_hash: r.body_hash,
            vk_hash: r.vk_hash,
            proof: r.proof.clone(),
            public_inputs: r.public_inputs.clone(),
            stored_keys: r.stored_keys.clone(),
            created_keys: r.created_keys.clone(),
            sealed: self.sealed.clone(),
            signature: r.signature,
            status: RequestStatus::Committed,
            created_at: r.created_at,
            chain_request_id: r.chain_request_id,
        })
    }
}
