//! The local store: the in-memory backend's tables ([`crate::store`]) without
//! the node-held ones (`values`, `tip_versions`, `tip_nodes`, which stay
//! empty), for a deployment whose keys are all client-held, kept on disk as
//! one append-only log of committed transactions, replayed on open.
//!
//! Construct it with [`LocalStore::open`] on a directory (created if
//! missing); the directory holds `store.log` and a `store.lock` that keeps a
//! second process from opening the same store. REGISTER refuses (400) a
//! manifest that gives a key the state mode `node` on this store
//! ([`Store::holds_values`] is false), and a node-held write that reaches
//! `commit` anyway (a round that stores into `values` or `tip_versions`, or
//! a rollback that restores a value) is refused with 500: such a deployment
//! runs on the Postgres store.
//!
//! The commit rules are the core's (`rules::check_commit`), checked against
//! the in-memory tables under one mutex; a commit that passes is written to
//! the log and synced to disk before it is applied in memory and `commit`
//! returns.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, PoisonError};

use crate::Refusal;
use crate::dead::DeadRecord;
use crate::field::{Fr, RequestId};
use crate::store::{
    ConsumedRow, ManifestRow, NamespaceRow, PackageRow, ReceiptRow, RequestRow, RequestStatus,
    RowWrite, Store, StoreRead, Tables, TipVersion, Txn, ValueRow, rules,
};
use crate::tree::StoredNode;
use eyre::{WrapErr, bail};
use sha2::{Digest, Sha256};

use crate::codec::{Decoded, Reader, Writer};

/// The log file inside the store directory.
pub const LOG_FILE: &str = "store.log";
const LOCK_FILE: &str = "store.lock";
const COMPACT_FILE: &str = "store.log.compact";

/// The first bytes of the log: the log format's marker, version 3.
const MAGIC: &[u8; 8] = b"psslog\x00\x03";
/// Bytes before each record's payload: its length (u32), the payload's
/// checksum and the header's checksum.
const HEADER_LEN: usize = 4 + 2 * CHECKSUM_LEN;
const CHECKSUM_LEN: usize = 8;
/// The payload format; the first byte of every payload.
const FORMAT: u8 = 1;

// The local store's log format and fsync. The store is one file,
// `store.log`, the 8-byte marker MAGIC (format version 3) then records
// appended one per committed transaction. A record is `length (u32,
// little-endian) ‖ payload checksum ‖ header checksum ‖ payload`, the payload
// checksum the first 8 bytes of SHA-256 of the payload, the header checksum
// the first 8 bytes of SHA-256 of the length and the payload checksum, the
// payload a format byte and the transaction's row writes (whole rows put,
// consumed entries deleted, dead records marked and unmarked), in the stores'
// codec (`crate::codec`). A log without the marker is refused, never read.
// `commit` writes the record and calls fsync (`sync_data`) before it applies
// the writes in memory and returns, so a committed round survives a crash or
// power loss; it costs one disk sync per round, small beside the proof. On
// open the log is replayed in order. A write torn by a crash, which never
// returned from `commit`, is dropped and the file truncated to the last whole
// record: a header cut short, a header that passes its checksum whose payload
// is cut short or (the last record) fails its checksum, or a header that fails
// its checksum with nothing but zero bytes after it (blocks the file system
// allocated and never wrote). Anything else is corruption, a bad length
// before the last record among it, and the store refuses to open rather than
// lose committed rows silently. Pruning is the one rewrite: it writes the
// remaining rows to a new log, syncs it and renames it over the old one, so
// the disk holds only the retention window. A failed write makes the store
// refuse every later commit until the node restarts and replays the log.
//
// The local store is private to the node's user, like the key
// directory. The log holds in clear this node's replicated share of every
// namespace's `nsk_app` (a Rep3 share is two of the three summands, so two
// nodes' logs give the whole `nsk_app`), every request row with this node's
// record thirds, and every package. `open` therefore creates the directory
// with mode 0700 and `store.log`, `store.lock` and the compaction file
// `store.log.compact` with mode 0600 (on Unix; the process umask can only
// narrow them), and narrows an existing directory, log or lock to the same
// modes, so an existing store with looser modes is tightened on its next open.
// An operator who backs the store up copies it as it backs up the key
// directory. The orchestrator's registry copy uses this store too; its
// `nsk_app` column is a zero placeholder, but it gets the same modes.
/// The local append-only store.
pub struct LocalStore {
    dir: PathBuf,
    inner: Mutex<Inner>,
}

struct Inner {
    tables: Tables,
    log: File,
    len: u64,
    /// Set by a write that failed half-way; every later commit is refused.
    failed: Option<String>,
    // Held for the store's lifetime: one process per store directory.
    _lock: File,
}

// The tip's `receipts` table in the local log. A receipt row
// is written as row write 8, one record per receipt the route stores (a
// replacement writes the whole row again; the last write wins on replay),
// and pruning drops rows by compaction, as for `requests`. Write 8 carries
// the optional nonce (receipt intake) and this node's envelopes (secret-shared
// receipt intake). Tags 6 and 7 are not row writes. A request row's optional
// chain request id is the last field of write 4.
/// One row write of a committed transaction.
#[derive(Debug, PartialEq)]
enum Op {
    Namespace(Fr, NamespaceRow),
    /// A contract manifest version of the namespace; the versions it does
    /// not retain are dropped with their packages (`retained_versions`).
    Manifest(Fr, ManifestRow),
    Package(Fr, PackageRow),
    Consumed(Fr, ConsumedRow),
    // Boxed: a request row is several times the size of the other rows.
    Request(Fr, Box<RequestRow>),
    /// A rollback deletes the consumed entry of `(namespace, note_hash)`.
    Unconsume(Fr, Fr),
    /// A receipt the receipt route stored (tip).
    Receipt(Fr, Box<ReceiptRow>),
    /// A rollback marks a record the rolled-back request created dead.
    Dead(Fr, DeadRecord),
    /// A round that creates a dead record's note hash deletes the mark.
    Revive(Fr, Fr),
}

impl Op {
    fn write(&self, w: &mut Writer) {
        match self {
            Op::Namespace(ns, row) => {
                w.u8(1);
                w.fr(*ns);
                w.namespace_row(row);
            }
            Op::Package(ns, row) => {
                w.u8(2);
                w.fr(*ns);
                w.package_row(row);
            }
            Op::Manifest(ns, row) => {
                w.u8(11);
                w.fr(*ns);
                w.manifest_row(row);
            }
            Op::Consumed(ns, row) => {
                w.u8(3);
                w.fr(*ns);
                w.consumed_row(row);
            }
            Op::Request(ns, row) => {
                w.u8(4);
                w.fr(*ns);
                w.request_row(row);
            }
            Op::Unconsume(ns, note_hash) => {
                w.u8(5);
                w.fr(*ns);
                w.fr(*note_hash);
            }
            Op::Receipt(ns, row) => {
                w.u8(8);
                w.fr(*ns);
                w.receipt_row(row);
            }
            Op::Dead(ns, row) => {
                w.u8(9);
                w.fr(*ns);
                w.fr(row.note_hash);
                w.fr(row.request_id.fr());
            }
            Op::Revive(ns, note_hash) => {
                w.u8(10);
                w.fr(*ns);
                w.fr(*note_hash);
            }
        }
    }

    fn read(r: &mut Reader<'_>) -> Decoded<Op> {
        let tag = r.u8()?;
        let ns = r.fr()?;
        Ok(match tag {
            1 => Op::Namespace(ns, r.namespace_row()?),
            2 => Op::Package(ns, r.package_row()?),
            3 => Op::Consumed(ns, r.consumed_row()?),
            4 => Op::Request(ns, Box::new(r.request_row()?)),
            5 => Op::Unconsume(ns, r.fr()?),
            8 => Op::Receipt(ns, Box::new(r.receipt_row()?)),
            9 => Op::Dead(
                ns,
                DeadRecord {
                    note_hash: r.fr()?,
                    request_id: RequestId(r.fr()?),
                },
            ),
            10 => Op::Revive(ns, r.fr()?),
            11 => Op::Manifest(ns, r.manifest_row()?),
            t => return Err(format!("unknown row write {t}")),
        })
    }
}

/// The log's row writes over the core tables.
impl Tables {
    fn apply_op(&mut self, op: Op) {
        match op {
            Op::Namespace(ns, row) => {
                self.namespaces.insert(ns, row);
            }
            Op::Manifest(ns, row) => self.put_manifest(ns, row),
            Op::Package(ns, row) => {
                self.packages
                    .insert((ns, (row.manifest_hash, row.name.clone())), row);
            }
            Op::Consumed(ns, row) => {
                self.consumed.insert((ns, row.note_hash), row);
            }
            Op::Request(ns, row) => {
                self.requests.insert((ns, row.request_id), *row);
            }
            Op::Unconsume(ns, note_hash) => {
                self.consumed.remove(&(ns, note_hash));
            }
            Op::Receipt(ns, row) => {
                self.receipts.insert((ns, row.request_id), *row);
            }
            Op::Dead(ns, row) => {
                self.dead.insert((ns, row.note_hash), row);
            }
            Op::Revive(ns, note_hash) => {
                self.dead.remove(&(ns, note_hash));
            }
        }
    }

    /// The log's row writes of a commit's `writes` under `ns`, which the
    /// rules passed against `self`: each write as the whole rows it leaves
    /// (the namespace row once, as its writes leave it), with the effect of
    /// [`RowWrite`]'s apply. The local store holds no tip rows, so a key or
    /// namespace clear has nothing to delete.
    fn log_ops(&self, ns: Fr, writes: Vec<RowWrite<'_>>) -> Vec<Op> {
        let mut ops = Vec::new();
        let stored_namespace = self.namespaces.get(&ns).cloned();
        let mut namespace = stored_namespace.clone();
        let mut namespace_at = None;
        for write in writes {
            match write {
                RowWrite::Namespace(row) => {
                    namespace_at.get_or_insert(ops.len());
                    namespace = Some(row.clone());
                }
                RowWrite::NskApp(share) => {
                    namespace_at.get_or_insert(ops.len());
                    if let Some(row) = namespace.as_mut() {
                        row.nsk_app = *share;
                    }
                }
                RowWrite::Seq(seq) => {
                    namespace_at.get_or_insert(ops.len());
                    if let Some(row) = namespace.as_mut() {
                        row.seq = seq;
                    }
                }
                RowWrite::Manifest(row) => ops.push(Op::Manifest(ns, row.clone())),
                RowWrite::Package(row) => ops.push(Op::Package(ns, row.clone())),
                RowWrite::Consumed(row) => ops.push(Op::Consumed(ns, row.clone())),
                RowWrite::Revive(note_hash) => {
                    if self.dead.contains_key(&(ns, note_hash)) {
                        ops.push(Op::Revive(ns, note_hash));
                    }
                }
                // the request row that follows replaces the whole row
                RowWrite::Rerun(_) => {}
                RowWrite::Request(row) => ops.push(Op::Request(ns, row)),
                RowWrite::ImportDead(row) => ops.push(Op::Dead(ns, row.clone())),
                RowWrite::Dead(row) => ops.push(Op::Dead(ns, row)),
                RowWrite::Unconsume(request_id) => ops.extend(
                    self.consumed
                        .iter()
                        .filter(|((n, _), row)| *n == ns && row.request_id == request_id)
                        .map(|((_, note_hash), _)| Op::Unconsume(ns, *note_hash)),
                ),
                RowWrite::RolledBack(request_id) => {
                    if let Some(row) = self.requests.get(&(ns, request_id)) {
                        ops.push(Op::Request(
                            ns,
                            Box::new(RequestRow {
                                status: RequestStatus::RolledBack,
                                ..row.clone()
                            }),
                        ));
                    }
                }
                RowWrite::ClearKey(_) | RowWrite::ClearTip => {}
                // refused before the rules run (`node_held`)
                RowWrite::Value { .. }
                | RowWrite::DeleteValue(_)
                | RowWrite::Version(_)
                | RowWrite::Node { .. }
                | RowWrite::Blob { .. } => {}
            }
        }
        if let (Some(at), Some(row)) = (namespace_at, namespace)
            && namespace_changed(&stored_namespace, &row)
        {
            ops.insert(at, Op::Namespace(ns, row));
        }
        ops
    }

    /// Every row, as the writes that rebuild it.
    fn log_snapshot(&self) -> impl Iterator<Item = Op> + '_ {
        let namespaces = self
            .namespaces
            .iter()
            .map(|(ns, row)| Op::Namespace(*ns, row.clone()));
        let manifests = self
            .manifests
            .iter()
            .map(|((ns, _), row)| Op::Manifest(*ns, row.clone()));
        let packages = self
            .packages
            .iter()
            .map(|((ns, _), row)| Op::Package(*ns, row.clone()));
        let consumed = self
            .consumed
            .iter()
            .map(|((ns, _), row)| Op::Consumed(*ns, row.clone()));
        let dead = self
            .dead
            .iter()
            .map(|((ns, _), row)| Op::Dead(*ns, row.clone()));
        let requests = self
            .requests
            .iter()
            .map(|((ns, _), row)| Op::Request(*ns, Box::new(row.clone())));
        let receipts = self
            .receipts
            .iter()
            .map(|((ns, _), row)| Op::Receipt(*ns, Box::new(row.clone())));
        namespaces
            .chain(manifests)
            .chain(packages)
            .chain(consumed)
            .chain(dead)
            .chain(requests)
            .chain(receipts)
    }
}

/// Whether a write is to a node-held table (`values`, `tip_versions`,
/// `tip_nodes`, `tip_blobs`), which the local store does not hold.
fn node_held(write: &RowWrite<'_>) -> bool {
    matches!(
        write,
        RowWrite::Value { .. }
            | RowWrite::DeleteValue(_)
            | RowWrite::Version(_)
            | RowWrite::Node { .. }
            | RowWrite::Blob { .. }
    )
}

fn namespace_changed(stored: &Option<NamespaceRow>, row: &NamespaceRow) -> bool {
    stored.as_ref() != Some(row)
}

/// One record: length, checksum, payload.
fn frame(ops: &[Op]) -> Vec<u8> {
    let mut payload = Writer::new();
    payload.u8(FORMAT);
    payload.count(ops.len());
    for op in ops {
        op.write(&mut payload);
    }
    let payload = payload.out;
    let length = u32::try_from(payload.len())
        .expect("a transaction is under 4 GiB")
        .to_le_bytes();
    let sum = checksum(&payload);
    let mut out = Vec::with_capacity(HEADER_LEN + payload.len());
    out.extend_from_slice(&length);
    out.extend_from_slice(&sum);
    out.extend_from_slice(&checksum(&[&length[..], &sum[..]].concat()));
    out.extend_from_slice(&payload);
    out
}

fn checksum(bytes: &[u8]) -> [u8; CHECKSUM_LEN] {
    Sha256::digest(bytes)[..CHECKSUM_LEN].try_into().unwrap()
}

fn decode_payload(payload: &[u8]) -> Decoded<Vec<Op>> {
    let mut r = Reader::new(payload);
    if r.u8()? != FORMAT {
        return Err("unknown record format".into());
    }
    let ops = (0..r.count()?)
        .map(|_| Op::read(&mut r))
        .collect::<Decoded<Vec<_>>>()?;
    r.finish()?;
    Ok(ops)
}

/// What [`replay`] found in a log.
struct Replayed {
    tables: Tables,
    /// The length of the whole records; anything after it is a torn write.
    good_len: u64,
}

fn replay(bytes: &[u8], path: &Path) -> eyre::Result<Replayed> {
    let mut tables = Tables::default();
    if !bytes.starts_with(MAGIC) {
        bail!(
            "the local store {} is not a version 3 log (it does not begin with the format \
             marker): an older build wrote it, and this build does not read it; keep it with \
             that build, or move it aside to start an empty store",
            path.display()
        );
    }
    let mut at = MAGIC.len();
    while at < bytes.len() {
        let rest = &bytes[at..];
        if rest.len() < HEADER_LEN {
            break; // a torn header
        }
        let (header, after) = rest.split_at(HEADER_LEN);
        let sum = &header[4..4 + CHECKSUM_LEN];
        if checksum(&header[..4 + CHECKSUM_LEN]) != header[4 + CHECKSUM_LEN..] {
            if after.iter().all(|b| *b == 0) {
                break; // a torn header over blocks never written
            }
            bail!(
                "the local store {} is corrupt: the record header at byte {at} fails its \
                 checksum and records follow it; restore the log from a backup",
                path.display()
            );
        }
        let len = u32::from_le_bytes(header[..4].try_into().unwrap()) as usize;
        let Some(payload) = after.get(..len) else {
            break; // a torn payload
        };
        let last = HEADER_LEN + len == rest.len();
        if checksum(payload) != sum {
            if last {
                break; // the last record, torn
            }
            bail!(
                "the local store {} is corrupt: the record at byte {at} fails its checksum \
                 and is not the last; restore the log from a backup",
                path.display()
            );
        }
        let ops = decode_payload(payload).map_err(|e| {
            eyre::eyre!(
                "the local store {} is corrupt: the record at byte {at}: {e}",
                path.display()
            )
        })?;
        for op in ops {
            tables.apply_op(op);
        }
        at += HEADER_LEN + len;
    }
    Ok(Replayed {
        tables,
        good_len: at as u64,
    })
}

fn sync_dir(dir: &Path) -> std::io::Result<()> {
    File::open(dir)?.sync_all()
}

/// The modes of the store directory and of its files: the operator's user
/// only.
const DIR_MODE: u32 = 0o700;
const FILE_MODE: u32 = 0o600;

/// Open options for a store file: created with [`FILE_MODE`] on Unix.
fn private_file() -> OpenOptions {
    let mut options = OpenOptions::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(FILE_MODE);
    }
    options
}

/// Narrow an existing store file or directory to `mode` (a no-op off Unix).
fn restrict(path: &Path, mode: u32) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    }
    #[cfg(not(unix))]
    let _ = (path, mode);
    Ok(())
}

impl LocalStore {
    /// Open the store in `dir`, creating the directory (0700) and a log
    /// (0600) holding only the format marker if missing, and replay the log.
    /// A log without the marker is refused. A torn last record is
    /// dropped (and the file truncated); any other bad record refuses to open.
    /// Fails if another process holds the store.
    pub fn open(dir: impl AsRef<Path>) -> eyre::Result<Self> {
        let dir = dir.as_ref().to_path_buf();
        crate::keys::create_private_dir(&dir)
            .and_then(|()| restrict(&dir, DIR_MODE))
            .wrap_err_with(|| format!("creating the local store {}", dir.display()))?;
        let lock_path = dir.join(LOCK_FILE);
        let lock = private_file()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&lock_path)?;
        restrict(&lock_path, FILE_MODE)
            .wrap_err_with(|| format!("restricting {}", lock_path.display()))?;
        if lock.try_lock().is_err() {
            bail!(
                "the local store {} is open in another process",
                dir.display()
            );
        }
        // A compaction that did not reach its rename left this behind.
        let _ = fs::remove_file(dir.join(COMPACT_FILE));
        let path = dir.join(LOG_FILE);
        let existed = path.exists();
        let log = private_file()
            .create(true)
            .truncate(false)
            .read(true)
            .append(true)
            .open(&path)
            .wrap_err_with(|| format!("opening {}", path.display()))?;
        restrict(&path, FILE_MODE).wrap_err_with(|| format!("restricting {}", path.display()))?;
        if !existed {
            sync_dir(&dir)?;
        }
        let mut bytes = fs::read(&path)?;
        // A new log, or one whose marker a crash cut short: write the marker.
        if MAGIC.starts_with(&bytes) {
            log.set_len(0)?;
            (&log).write_all(MAGIC)?;
            log.sync_all()?;
            bytes = MAGIC.to_vec();
        }
        let Replayed { tables, good_len } = replay(&bytes, &path)?;
        if good_len < bytes.len() as u64 {
            tracing::warn!(
                log = %path.display(),
                dropped_bytes = bytes.len() as u64 - good_len,
                "local store: dropping a torn last record"
            );
            log.set_len(good_len)?;
            log.sync_all()?;
        }
        Ok(LocalStore {
            dir,
            inner: Mutex::new(Inner {
                tables,
                log,
                len: good_len,
                failed: None,
                _lock: lock,
            }),
        })
    }

    /// The store directory.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The log file.
    pub fn log_path(&self) -> PathBuf {
        self.dir.join(LOG_FILE)
    }

    /// Every package row of `namespace`, of every version it holds,
    /// disabled ones included, by version and then name. The orchestrator's
    /// FETCH looks among them for the circuit a stored round ran under.
    pub fn packages(&self, namespace: Fr) -> Vec<PackageRow> {
        self.lock().tables.packages_of(namespace)
    }

    /// The package rows of the contract manifest version `manifest_hash`,
    /// disabled ones included, in name order.
    pub fn packages_in(&self, namespace: Fr, manifest_hash: Fr) -> Vec<PackageRow> {
        self.lock()
            .tables
            .packages_of(namespace)
            .into_iter()
            .filter(|p| p.manifest_hash == manifest_hash)
            .collect()
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        // A panic inside a commit happens before the tables change (the
        // writes are applied after the log is synced, and applying does not
        // fail), so a poisoned lock still guards a consistent state.
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

fn io_failure(what: &str, e: impl std::fmt::Display) -> Refusal {
    Refusal::mpc_failure(format!("store: local: {what}: {e}"))
}

impl Inner {
    fn usable(&self) -> Result<(), Refusal> {
        match &self.failed {
            None => Ok(()),
            Some(why) => Err(Refusal::mpc_failure(format!(
                "store: local: refusing commits after a failed write ({why}); restart the node"
            ))),
        }
    }

    /// Append one record and sync it; on failure cut the file back.
    fn append(&mut self, record: &[u8]) -> Result<(), Refusal> {
        let written = self
            .log
            .write_all(record)
            .and_then(|()| self.log.sync_data());
        if let Err(e) = written {
            let why = e.to_string();
            if self
                .log
                .set_len(self.len)
                .and_then(|()| self.log.sync_data())
                .is_err()
            {
                self.failed = Some(why.clone());
            }
            return Err(io_failure("writing the log", why));
        }
        self.len += record.len() as u64;
        Ok(())
    }
}

impl StoreRead for LocalStore {
    fn namespace(&self, namespace: Fr) -> Result<Option<NamespaceRow>, Refusal> {
        self.lock().tables.namespace(namespace)
    }
    fn contract_manifest(&self, namespace: Fr) -> Result<Option<ManifestRow>, Refusal> {
        self.lock().tables.contract_manifest(namespace)
    }
    fn contract_manifests(&self, namespace: Fr) -> Result<Vec<ManifestRow>, Refusal> {
        self.lock().tables.contract_manifests(namespace)
    }
    fn package(&self, namespace: Fr, name: &str) -> Result<Option<PackageRow>, Refusal> {
        self.lock().tables.package(namespace, name)
    }
    fn package_in(
        &self,
        namespace: Fr,
        manifest_hash: Fr,
        name: &str,
    ) -> Result<Option<PackageRow>, Refusal> {
        self.lock()
            .tables
            .package_in(namespace, manifest_hash, name)
    }
    fn consumed(&self, namespace: Fr, note_hash: Fr) -> Result<Option<ConsumedRow>, Refusal> {
        self.lock().tables.consumed(namespace, note_hash)
    }
    fn dead_record(&self, namespace: Fr, note_hash: Fr) -> Result<Option<DeadRecord>, Refusal> {
        self.lock().tables.dead_record(namespace, note_hash)
    }
    fn request(&self, namespace: Fr, request_id: RequestId) -> Result<Option<RequestRow>, Refusal> {
        self.lock().tables.request(namespace, request_id)
    }
    fn chain_request(
        &self,
        namespace: Fr,
        chain_request_id: Fr,
    ) -> Result<Option<RequestRow>, Refusal> {
        self.lock()
            .tables
            .chain_request(namespace, chain_request_id)
    }
    fn value(&self, namespace: Fr, key: &str) -> Result<Option<ValueRow>, Refusal> {
        self.lock().tables.value(namespace, key)
    }
    fn tip_version(&self, ns: Fr, key: &str, c: Fr) -> Result<Option<TipVersion>, Refusal> {
        self.lock().tables.tip_version(ns, key, c)
    }
    fn tip_versions(&self, namespace: Fr, key: &str) -> Result<Vec<TipVersion>, Refusal> {
        self.lock().tables.tip_versions(namespace, key)
    }
    fn tip_node(&self, namespace: Fr, key: &str, hash: Fr) -> Result<Option<StoredNode>, Refusal> {
        self.lock().tables.tip_node(namespace, key, hash)
    }
    fn blob(&self, namespace: Fr, key: &str, name: &str) -> Result<Option<Vec<u8>>, Refusal> {
        self.lock().tables.blob(namespace, key, name)
    }
    fn blob_names(&self, namespace: Fr, key: &str) -> Result<Vec<String>, Refusal> {
        self.lock().tables.blob_names(namespace, key)
    }
}

impl Store for LocalStore {
    fn commit(&self, txn: Txn) -> Result<(), Refusal> {
        let writes = txn.writes();
        if writes.iter().any(node_held) {
            return Err(Refusal::mpc_failure(
                "store: the local store holds no node-held values; a deployment with \
                 node-held keys runs on the Postgres store",
            ));
        }
        let mut inner = self.lock();
        inner.usable()?;
        rules::check_commit(&inner.tables, &txn)?;
        let ops = inner.tables.log_ops(txn.namespace(), writes);
        if ops.is_empty() {
            return Ok(());
        }
        inner.append(&frame(&ops))?;
        for op in ops {
            inner.tables.apply_op(op);
        }
        Ok(())
    }

    // The cutoff is the Postgres store's (see `crate::postgres`): rows with
    // `created_at` strictly before `older_than`; `consumed` is untouched. The
    // log is then rewritten without the pruned rows (the log format note).
    fn prune_requests(&self, older_than: u64) -> Result<usize, Refusal> {
        let mut inner = self.lock();
        inner.usable()?;
        let pruned = inner
            .tables
            .requests
            .values()
            .filter(|row| row.created_at < older_than)
            .count();
        if pruned == 0 {
            return Ok(0);
        }
        let mut tables = inner.tables.clone();
        tables
            .requests
            .retain(|_, row| row.created_at >= older_than);
        self.compact(&mut inner, tables)?;
        Ok(pruned)
    }

    // No `values` table: REGISTER refuses a manifest with a node-held key on
    // this store (400), and `commit` refuses a node-held write (500) should
    // one reach it anyway.
    fn holds_values(&self) -> bool {
        false
    }

    fn namespaces(&self) -> Result<Vec<Fr>, Refusal> {
        Ok(self.lock().tables.namespace_list())
    }

    fn package_names(&self, namespace: Fr) -> Result<Vec<String>, Refusal> {
        Ok(self.lock().tables.package_names(namespace))
    }

    // No `tip_versions` table (no `values`): no tip key.
    fn tip_keys(&self, _: Fr) -> Result<Vec<String>, Refusal> {
        Ok(vec![])
    }

    // No `values` table.
    fn value_keys(&self, _: Fr) -> Result<Vec<String>, Refusal> {
        Ok(vec![])
    }

    // No `tip_blobs` table (no `values`).
    fn blob_keys(&self, _: Fr) -> Result<Vec<String>, Refusal> {
        Ok(vec![])
    }

    fn consumed_rows(&self, namespace: Fr) -> Result<Vec<ConsumedRow>, Refusal> {
        Ok(self.lock().tables.consumed_rows(namespace))
    }

    fn receipts(&self, namespace: Fr) -> Result<Vec<ReceiptRow>, Refusal> {
        Ok(self.lock().tables.receipt_rows(namespace))
    }

    fn receipt(&self, namespace: Fr, request_id: Fr) -> Result<Option<ReceiptRow>, Refusal> {
        Ok(self.lock().tables.receipt_row(namespace, request_id))
    }

    fn requests(&self, namespace: Fr) -> Result<Vec<RequestRow>, Refusal> {
        Ok(self.lock().tables.request_rows(namespace))
    }

    fn dead_records(&self, namespace: Fr) -> Result<Vec<DeadRecord>, Refusal> {
        Ok(self.lock().tables.dead_rows(namespace))
    }

    // One record per receipt, synced before it returns, like a commit.
    fn put_receipt(&self, namespace: Fr, row: ReceiptRow) -> Result<(), Refusal> {
        let mut inner = self.lock();
        inner.usable()?;
        let op = Op::Receipt(namespace, Box::new(row));
        inner.append(&frame(std::slice::from_ref(&op)))?;
        inner.tables.apply_op(op);
        Ok(())
    }

    fn expired_receipts(&self, block: u64) -> Result<Vec<(Fr, Fr)>, Refusal> {
        Ok(self.lock().tables.expired_receipts(block))
    }

    // The rows of `ids` still past their window (the core's
    // `ReceiptRow::prunable_at`) go; the log is then rewritten without them,
    // as `prune_requests` does.
    fn prune_receipts(&self, block: u64, ids: &[(Fr, Fr)]) -> Result<usize, Refusal> {
        let mut inner = self.lock();
        inner.usable()?;
        let gone: Vec<(Fr, Fr)> = ids
            .iter()
            .copied()
            .filter(|key| {
                inner
                    .tables
                    .receipts
                    .get(key)
                    .is_some_and(|row| row.prunable_at(block))
            })
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect();
        if gone.is_empty() {
            return Ok(0);
        }
        let mut tables = inner.tables.clone();
        for key in &gone {
            tables.receipts.remove(key);
        }
        self.compact(&mut inner, tables)?;
        Ok(gone.len())
    }
}

impl LocalStore {
    /// Write `tables` as a fresh log beside the current one, sync it, rename
    /// it over the current one and append to it from then on. The current log
    /// is untouched until the rename, so a crash at any point leaves one whole
    /// log; a failure after the rename stops further commits (`failed`),
    /// because they could land in a log the directory does not yet name.
    fn compact(&self, inner: &mut Inner, tables: Tables) -> Result<(), Refusal> {
        let tmp = self.dir.join(COMPACT_FILE);
        let fail = |e: std::io::Error| io_failure("compacting the log", e);
        let _ = fs::remove_file(&tmp);
        // The handle follows the file through the rename.
        let mut file = private_file()
            .create_new(true)
            .read(true)
            .append(true)
            .open(&tmp)
            .map_err(fail)?;
        file.write_all(MAGIC).map_err(fail)?;
        let mut len = MAGIC.len() as u64;
        for op in tables.log_snapshot() {
            let record = frame(std::slice::from_ref(&op));
            file.write_all(&record).map_err(fail)?;
            len += record.len() as u64;
        }
        file.sync_all().map_err(fail)?;
        fs::rename(&tmp, self.log_path()).map_err(fail)?;
        inner.log = file;
        inner.len = len;
        inner.tables = tables;
        if let Err(e) = sync_dir(&self.dir) {
            inner.failed = Some(format!("syncing the directory after compaction: {e}"));
            return Err(fail(e));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_record_round_trips_and_a_flipped_byte_is_caught() {
        let ops = vec![
            Op::Unconsume(Fr::from(1u64), Fr::from(2u64)),
            Op::Consumed(
                Fr::from(1u64),
                ConsumedRow {
                    note_hash: Fr::from(3u64),
                    circuit: Fr::from(4u64),
                    request_id: RequestId(Fr::from(5u64)),
                },
            ),
        ];
        let record = frame(&ops);
        assert_eq!(decode_payload(&record[HEADER_LEN..]).unwrap(), ops);
        let mut flipped = record.clone();
        *flipped.last_mut().unwrap() ^= 1;
        assert_ne!(
            checksum(&flipped[HEADER_LEN..]),
            flipped[4..4 + CHECKSUM_LEN]
        );
    }

    fn ops(n: u64) -> Vec<Op> {
        vec![Op::Unconsume(Fr::from(1u64), Fr::from(n))]
    }

    fn replayed(bytes: &[u8]) -> eyre::Result<u64> {
        replay(bytes, Path::new("store.log")).map(|r| r.good_len)
    }

    // A record's length is under the header checksum: a bad length before
    // the last record is corruption, not a torn tail, while a tail cut
    // anywhere, or zero blocks after the last record, is torn.
    #[test]
    fn a_bad_length_mid_log_is_corruption_and_a_torn_tail_is_dropped() {
        let (first, second) = (frame(&ops(2)), frame(&ops(3)));
        let log = [&MAGIC[..], &first, &second].concat();
        let whole = (MAGIC.len() + first.len()) as u64;
        assert_eq!(replayed(&log).unwrap(), log.len() as u64);
        // The first record's length pointing past the end of the file.
        let mut bad = log.clone();
        bad[MAGIC.len()..MAGIC.len() + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        let err = replayed(&bad).unwrap_err().to_string();
        assert!(err.contains("corrupt") && err.contains("header"), "{err}");
        // The second record cut in its header, in its payload, one byte short.
        for cut in [1, HEADER_LEN, second.len() - 1] {
            assert_eq!(
                replayed(&log[..whole as usize + cut]).unwrap(),
                whole,
                "cut {cut}"
            );
        }
        // Zero blocks the file system allocated after the first record.
        let zeros = [&MAGIC[..], &first, &[0u8; 64][..]].concat();
        assert_eq!(replayed(&zeros).unwrap(), whole);
        // The last record's length altered: its header fails, nothing follows
        // but its payload, which is not zero: corruption too.
        let mut bad = log.clone();
        bad[whole as usize] ^= 1;
        assert!(replayed(&bad).unwrap_err().to_string().contains("corrupt"));
    }

    #[test]
    fn a_log_without_the_version_3_marker_is_refused() {
        let first = frame(&ops(2));
        let err = replayed(&first).unwrap_err().to_string();
        assert!(err.contains("not a version 3 log"), "{err}");
    }

    /// A request row is write 4 and reads back whole, with and without a
    /// chain request id.
    #[test]
    fn a_request_row_is_write_4() {
        let ns = Fr::from(1u64);
        let mut txn = Txn::new(ns);
        txn.put_request(crate::store::testing::new_request(3, 7));
        let row = txn.request_row().unwrap();
        let tip = RequestRow {
            chain_request_id: Some(-Fr::from(5u64)),
            ..row.clone()
        };
        for row in [row, tip] {
            let op = Op::Request(ns, Box::new(row));
            let mut w = Writer::new();
            op.write(&mut w);
            assert_eq!(w.out[0], 4);
            let mut r = Reader::new(&w.out);
            assert_eq!(Op::read(&mut r).unwrap(), op);
            r.finish().unwrap();
        }
    }

    /// A receipt row is write 8 and reads back whole, with and without a
    /// stale period, with a nonce (receipt intake) and with envelopes
    /// (secret-shared receipt intake).
    #[test]
    fn a_receipt_row_is_write_8() {
        use crate::store::testing::{receipt_row, shared_receipt_row};
        let ns = Fr::from(1u64);
        for stale in [Some(50), None] {
            for row in [
                receipt_row(4, 1300, stale),
                shared_receipt_row(4, 1300, stale),
            ] {
                let op = Op::Receipt(ns, Box::new(row));
                let mut w = Writer::new();
                op.write(&mut w);
                assert_eq!(w.out[0], 8);
                let mut r = Reader::new(&w.out);
                assert_eq!(Op::read(&mut r).unwrap(), op);
                r.finish().unwrap();
            }
        }
    }
}
