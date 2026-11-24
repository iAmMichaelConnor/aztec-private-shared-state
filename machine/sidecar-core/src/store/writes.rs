//! A checked commit's writes as one ordered list of row writes
//! ([`Txn::writes`]): the one description of what a commit changes, which
//! every backend applies write by write. A new kind of write is a new
//! [`RowWrite`] variant, so every backend's `match` must take it.

use super::*;

/// One row write of a commit, in the order [`Txn::writes`] lists them.
#[derive(Clone, Debug, PartialEq)]
pub enum RowWrite<'t> {
    /// Insert the namespace row (the first REGISTER, a namespace import).
    Namespace(&'t NamespaceRow),
    /// Replace the stored namespace row's `nsk_app` pair (a REGISTER repair,
    /// a share refresh).
    NskApp(&'t Share),
    /// Insert or replace a contract manifest version, and delete the
    /// versions [`retained_versions`] does not
    /// keep with their packages.
    Manifest(&'t ManifestRow),
    /// Insert or replace a package.
    Package(&'t PackageRow),
    /// Set the stored namespace row's `seq`.
    Seq(u64),
    /// Insert a `consumed` row.
    Consumed(&'t ConsumedRow),
    /// Delete the dead record of a note hash: the request row about to be
    /// written carries a record under it again.
    Revive(Fr),
    /// Insert or replace a `values` row.
    Value {
        key: &'t str,
        vec: &'t [Elem],
        note_hash: Fr,
        request_id: RequestId,
    },
    /// Delete the rolled-back `requests` row of a request id: the
    /// [`RowWrite::Request`] after it replaces that attempt ([`Txn::rerun`]).
    Rerun(RequestId),
    /// Insert a `requests` row.
    Request(Box<RequestRow>),
    /// Insert a dead record (a namespace import).
    ImportDead(&'t DeadRecord),
    /// Delete every `tip_versions`, `tip_nodes` and `tip_blobs` row of a key
    /// (a key import).
    ClearKey(&'t str),
    /// Delete every `tip_versions` and `tip_nodes` row of the namespace (a
    /// share refresh).
    ClearTip,
    /// A `tip_versions` write.
    Version(&'t VersionWrite),
    /// Insert the node or replace its count, or delete it (`None`).
    Node {
        key: &'t str,
        hash: Fr,
        node: Option<&'t StoredNode>,
    },
    /// Insert or replace the blob, or delete it (`None`).
    Blob {
        key: &'t str,
        name: &'t str,
        bytes: Option<&'t [u8]>,
    },
    /// Delete a `values` row (a rollback of the request that created it).
    DeleteValue(&'t str),
    /// Delete every `consumed` row of a request (its rollback; the one
    /// deletion of the append-only consumed set).
    Unconsume(RequestId),
    /// Insert or replace a dead record (a rollback marks a record the request
    /// created dead).
    Dead(DeadRecord),
    /// Mark a stored request `rolled_back`.
    RolledBack(RequestId),
}

impl Txn {
    /// Every row write of this transaction, in apply order: the namespace
    /// row, its repair, the contract manifest, the packages and `seq`; the consumed rows; the
    /// request row with the records it revives, the values it writes and
    /// the rolled-back attempt it replaces;
    /// the imported rows and the key or namespace clear of an import; the
    /// tip versions, nodes and blobs; the rollback. The rules
    /// (`rules::check_commit`) check the transaction; the backends apply
    /// these writes and nothing else.
    pub fn writes(&self) -> Vec<RowWrite<'_>> {
        let mut out = Vec::new();
        if let Some(row) = &self.namespace_row {
            out.push(RowWrite::Namespace(row));
        }
        if let Some(repair) = &self.namespace_repair {
            out.push(RowWrite::NskApp(&repair.nsk_app));
        }
        out.extend(self.manifests.iter().map(RowWrite::Manifest));
        out.extend(self.packages.iter().map(RowWrite::Package));
        if let Some(seq) = self.seq {
            out.push(RowWrite::Seq(seq));
        }
        out.extend(self.consumed.iter().map(RowWrite::Consumed));
        if let Some(row) = self.request_row() {
            out.extend(row.records().map(|r| RowWrite::Revive(r.note_hash)));
            out.extend(self.values.iter().map(|w| RowWrite::Value {
                key: &w.key,
                vec: &w.vec,
                note_hash: w.note_hash,
                request_id: row.request_id,
            }));
            if self.rerun {
                out.push(RowWrite::Rerun(row.request_id));
            }
            out.push(RowWrite::Request(Box::new(row)));
        }
        out.extend(
            self.imported_requests
                .iter()
                .map(|row| RowWrite::Request(Box::new(row.clone()))),
        );
        out.extend(self.imported_dead.iter().map(RowWrite::ImportDead));
        out.extend(self.imported_values.iter().map(restored));
        match &self.import {
            Some(Import::Key(key)) => out.push(RowWrite::ClearKey(key)),
            Some(Import::Refresh) => out.push(RowWrite::ClearTip),
            Some(Import::Namespace) | None => {}
        }
        out.extend(self.versions.iter().map(RowWrite::Version));
        out.extend(self.nodes.iter().map(|((key, hash), node)| RowWrite::Node {
            key,
            hash: *hash,
            node: node.as_ref(),
        }));
        out.extend(
            self.blobs
                .iter()
                .map(|((key, name), bytes)| RowWrite::Blob {
                    key,
                    name,
                    bytes: bytes.as_deref(),
                }),
        );
        if let Some(rb) = &self.rollback {
            out.extend(rb.restore.iter().map(restored));
            out.extend(rb.delete.iter().map(|key| RowWrite::DeleteValue(key)));
            out.push(RowWrite::Unconsume(rb.request_id));
            out.extend(rb.dead.iter().map(|&note_hash| {
                RowWrite::Dead(DeadRecord {
                    note_hash,
                    request_id: rb.request_id,
                })
            }));
            out.push(RowWrite::RolledBack(rb.request_id));
        }
        out
    }
}

/// The `values` write of a restored row, under the request that wrote it.
fn restored(value: &RestoredValue) -> RowWrite<'_> {
    RowWrite::Value {
        key: &value.key,
        vec: &value.vec,
        note_hash: value.note_hash,
        request_id: value.prior_request_id,
    }
}
