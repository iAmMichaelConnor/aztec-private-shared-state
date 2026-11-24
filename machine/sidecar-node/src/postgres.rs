//! The Postgres store: every table of the core's `Store` trait in one
//! database per node (migrations in `sidecar-node/migrations/`), through sqlx.
//!
//! Construct it with [`PostgresStore::connect`] (a `postgres://` URL) or
//! [`PostgresStore::connect_with`] (sqlx connect options and a pool size);
//! both run the migrations before they return. It can be called from any
//! thread, inside a tokio runtime or not.
//!
//! One `Store::commit` is one database transaction: it takes a per-namespace
//! advisory lock, runs the core's commit rules (`rules::check_commit`) against
//! that transaction's view, applies every write and commits; any refusal or
//! failure drops the transaction, which rolls it back. The rules themselves
//! stay in the core; this backend only reads and writes rows.

use std::cell::RefCell;
use std::future::Future;

use sidecar_core::Refusal;
use sidecar_core::bind::Share;
use sidecar_core::dead::DeadRecord;
use sidecar_core::field::{Fr, RequestId};
use sidecar_core::request::NodeSharedInput;
use sidecar_core::store::{
    ConsumedRow, ManifestRow, NamespaceRow, PackageRow, ReceiptRow, RequestRow, RowWrite, Store,
    StoreRead, TipVersion, Txn, ValueRow, VersionStatus, VersionTree, VersionWrite, decode_vec,
    encode_vec, retained_versions, rules,
};
use sidecar_core::tree::{StoredNode, TreeNode};
use sqlx::migrate::Migrator;
use sqlx::postgres::{PgConnectOptions, PgConnection, PgPoolOptions, PgRow, PgSslMode};
use sqlx::{PgPool, Postgres, Row, Transaction};
use tokio::runtime::{Handle, Runtime};

use crate::codec::{
    self, Reader, Writer, fr_bytes, fr_from_bytes, point_bytes, point_from_bytes, share_bytes,
    share_from_bytes, signature_bytes, signature_from_bytes,
};

static MIGRATOR: Migrator = sqlx::migrate!("./migrations");

// Operator knob: DESIGN.md, "Configuration reference" (Postgres pool size).
// `connect` opens at most 8 connections (`connect_with` takes another number)
// on a store runtime of two worker threads.
/// The pool size [`PostgresStore::connect`] opens.
pub const DEFAULT_MAX_CONNECTIONS: u32 = 8;

// Which store backend a deployment runs (`[store] backend`). `postgres` (this
// module) for any deployment with node-held keys (`state: node` in a manifest,
// such as an AMM pool): it holds every table, `values` included, with the
// durability and backups of a database server. `local` (`crate::local`) for a
// deployment whose keys are all client-held (such as Monty Hall): every table
// but `values`, in one append-only file, with no server to run; REGISTER
// refuses (400, before any round) a manifest that gives a key the state mode
// `node` on it (`Store::holds_values` is false), and its commit refuses a
// node-held write (500) as a second line.
// `memory` is for tests and development and loses everything on exit. The
// default of the node's config is `memory`; a deployment names its backend.
// Choosing `local` for a namespace that later registers a node-held circuit
// means moving the node to Postgres first; the tables are the same.
/// The Postgres backend.
pub struct PostgresStore {
    // Both are `Some` until `Drop` takes them; the pool closes on the runtime
    // before the runtime shuts down.
    pool: Option<PgPool>,
    rt: Option<Runtime>,
}

// The sync/async bridge. The core's `Store` trait is synchronous
// (a round reads and commits from the blocking thread that runs its proof), and
// sqlx is async. The store owns a small tokio runtime of its own (two worker
// threads, `store-postgres`) and runs every query with that runtime's
// `block_on`: on the calling thread when it is outside any tokio runtime (the
// pipeline's threads, the tests), and on a short-lived scoped thread when the
// caller is inside one (an async handler, or a `spawn_blocking` thread), since
// `block_on` may not run there. The alternatives are `block_in_place`, which
// panics on a current-thread runtime and needs the caller's runtime, and making
// the trait async, which would change the core and every backend. The
// consequences: a call never panics whatever thread makes it; an async caller
// blocks its worker for the query (callers should use `spawn_blocking`); and a
// call from inside a runtime pays for one thread spawn, small beside a query.
fn bridge<T: Send>(rt: &Runtime, f: impl FnOnce(&Runtime) -> T + Send) -> T {
    let run = |rt: &Runtime| {
        // sqlx returns pooled connections by spawning onto the current
        // runtime, so every sqlx value is dropped inside this context.
        let _context = rt.enter();
        f(rt)
    };
    if Handle::try_current().is_err() {
        return run(rt);
    }
    std::thread::scope(|scope| {
        std::thread::Builder::new()
            .name("store-postgres-call".into())
            .spawn_scoped(scope, || run(rt))
            .expect("spawning a store thread")
            .join()
            .unwrap_or_else(|panic| std::panic::resume_unwind(panic))
    })
}

// Operator knob: DESIGN.md, "Configuration reference" (`[store]` Postgres
// `url`). The link to Postgres carries the node's nsk_app shares, `values`
// and version shares, so a server on another host is reached over TLS that
// checks its certificate and host name (`sslmode=verify-full`) unless the URL
// or `PGSSLMODE` names another mode, which the node then uses and warns
// about. The server's CA is one of the webpki roots or the URL's
// `sslrootcert`. A loopback host or a Unix socket keeps sqlx's default,
// `prefer`.
/// The connect options of the Postgres `url`: its own, with
/// `sslmode=verify-full` for a server on another host when neither the URL
/// nor `PGSSLMODE` names a mode.
pub fn connect_options(url: &str) -> eyre::Result<PgConnectOptions> {
    let options: PgConnectOptions = url
        .parse()
        .map_err(|e| eyre::eyre!("store: the Postgres URL does not parse: {e}"))?;
    let local = options.get_socket().is_some()
        || options.get_host() == "localhost"
        || options.get_host().starts_with('/')
        || options
            .get_host()
            .trim_matches(['[', ']'])
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback());
    let named = url.split_once('?').is_some_and(|(_, query)| {
        query
            .split('&')
            .any(|pair| matches!(pair.split('=').next(), Some("sslmode" | "ssl-mode")))
    }) || std::env::var_os("PGSSLMODE").is_some();
    if local {
        return Ok(options);
    }
    if !named {
        return Ok(options.ssl_mode(PgSslMode::VerifyFull));
    }
    if !matches!(options.get_ssl_mode(), PgSslMode::VerifyFull) {
        tracing::warn!(
            host = options.get_host(),
            sslmode = ?options.get_ssl_mode(),
            "store: the Postgres server is on another host and its link does not check its \
             certificate and host name (sslmode=verify-full)"
        );
    }
    Ok(options)
}

impl PostgresStore {
    /// Connect to the database at `url` (`postgres://user:password@host:port/db`,
    /// TLS by [`connect_options`]) with a pool of [`DEFAULT_MAX_CONNECTIONS`]
    /// and run the migrations.
    pub fn connect(url: &str) -> eyre::Result<Self> {
        Self::connect_with(connect_options(url)?, DEFAULT_MAX_CONNECTIONS)
    }

    /// Connect with `options` and a pool of at most `max_connections`, and run
    /// the migrations.
    pub fn connect_with(options: PgConnectOptions, max_connections: u32) -> eyre::Result<Self> {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("store-postgres")
            .enable_all()
            .build()?;
        let pool = bridge(&rt, |rt| {
            rt.block_on(async {
                let pool = PgPoolOptions::new()
                    .max_connections(max_connections)
                    .connect_with(options)
                    .await
                    .map_err(|e| eyre::eyre!("store: connecting to Postgres: {e}"))?;
                MIGRATOR
                    .run(&pool)
                    .await
                    .map_err(|e| eyre::eyre!("store: running the migrations: {e}"))?;
                eyre::Ok(pool)
            })
        })?;
        Ok(PostgresStore {
            pool: Some(pool),
            rt: Some(rt),
        })
    }

    fn pool(&self) -> &PgPool {
        self.pool
            .as_ref()
            .expect("the pool lives as long as the store")
    }

    fn rt(&self) -> &Runtime {
        self.rt
            .as_ref()
            .expect("the runtime lives as long as the store")
    }

    /// Run one async query (a read, or a write outside `commit`) on a
    /// pooled connection.
    fn run<T, F>(&self, query: impl FnOnce(PgPool) -> F + Send) -> Result<T, Refusal>
    where
        T: Send,
        F: Future<Output = Result<T, Refusal>>,
    {
        let pool = self.pool().clone();
        bridge(self.rt(), |rt| rt.block_on(query(pool)))
    }
}

impl Drop for PostgresStore {
    fn drop(&mut self) {
        if let (Some(pool), Some(rt)) = (self.pool.take(), self.rt.take()) {
            bridge(&rt, move |rt| {
                rt.block_on(pool.close());
                drop(pool);
            });
            rt.shutdown_background();
        }
    }
}

fn db(e: sqlx::Error) -> Refusal {
    Refusal::mpc_failure(format!("store: postgres: {e}"))
}

fn corrupt(what: &str, e: String) -> Refusal {
    Refusal::mpc_failure(format!("store: postgres: a stored {what}: {e}"))
}

fn to_i64(what: &str, v: u64) -> Result<i64, Refusal> {
    i64::try_from(v)
        .map_err(|_| Refusal::mpc_failure(format!("store: postgres: {what} {v} exceeds BIGINT")))
}

fn to_u64(what: &str, v: i64) -> Result<u64, Refusal> {
    u64::try_from(v).map_err(|_| corrupt(what, format!("negative ({v})")))
}

fn get<'r, T>(row: &'r PgRow, col: &str) -> Result<T, Refusal>
where
    T: sqlx::Decode<'r, Postgres> + sqlx::Type<Postgres>,
{
    row.try_get(col).map_err(db)
}

fn fr_col(row: &PgRow, col: &str) -> Result<Fr, Refusal> {
    fr_from_col(col, &get::<Vec<u8>>(row, col)?)
}

fn fr_from_col(col: &str, bytes: &[u8]) -> Result<Fr, Refusal> {
    fr_from_bytes(bytes).map_err(|e| corrupt(col, e))
}

fn opt_fr_col(row: &PgRow, col: &str) -> Result<Option<Fr>, Refusal> {
    get::<Option<Vec<u8>>>(row, col)?
        .map(|bytes| fr_from_col(col, &bytes))
        .transpose()
}

/// A receipt's shared inputs in the codec's layout ([`Writer::shares`]).
fn shares_bytes(v: &[NodeSharedInput]) -> Vec<u8> {
    let mut w = Writer::new();
    w.shares(v);
    w.out
}

fn shares_from_bytes(bytes: &[u8]) -> Result<Vec<NodeSharedInput>, String> {
    let mut r = Reader::new(bytes);
    let shares = r.shares()?;
    r.finish()?;
    Ok(shares)
}

fn frs_bytes(v: &[Fr]) -> Vec<u8> {
    v.iter().flat_map(|f| fr_bytes(*f)).collect()
}

fn frs_from_bytes(bytes: &[u8]) -> Result<Vec<Fr>, String> {
    if !bytes.len().is_multiple_of(32) {
        return Err(format!(
            "{} bytes is not a list of field elements",
            bytes.len()
        ));
    }
    bytes.chunks(32).map(fr_from_bytes).collect()
}

// --- The reads, on any connection: the pool's, or a commit's transaction. ---

async fn q_namespace(c: &mut PgConnection, ns: Fr) -> Result<Option<NamespaceRow>, Refusal> {
    let row = sqlx::query(
        "SELECT owner_pubkey, nsk_app, npk_app_hash, seq FROM namespaces WHERE namespace = $1",
    )
    .bind(fr_bytes(ns).to_vec())
    .fetch_optional(c)
    .await
    .map_err(db)?;
    row.map(|row| {
        Ok(NamespaceRow {
            owner_pubkey: point_from_bytes(&get::<Vec<u8>>(&row, "owner_pubkey")?)
                .map_err(|e| corrupt("owner_pubkey", e))?,
            nsk_app: share_from_bytes(&get::<Vec<u8>>(&row, "nsk_app")?)
                .map_err(|e| corrupt("nsk_app", e))?,
            npk_app_hash: fr_col(&row, "npk_app_hash")?,
            seq: to_u64("seq", get(&row, "seq")?)?,
        })
    })
    .transpose()
}

// Every version a namespace holds, newest (highest seq) first.
async fn q_manifests(c: &mut PgConnection, ns: Fr) -> Result<Vec<ManifestRow>, Refusal> {
    q_manifests_of(c, &fr_bytes(ns)).await
}

async fn q_manifests_of(c: &mut PgConnection, ns: &[u8]) -> Result<Vec<ManifestRow>, Refusal> {
    let rows = sqlx::query(
        "SELECT manifest_hash, document, seq FROM manifests WHERE namespace = $1 \
         ORDER BY seq DESC",
    )
    .bind(ns)
    .fetch_all(c)
    .await
    .map_err(db)?;
    rows.iter()
        .map(|row| {
            Ok(ManifestRow {
                manifest_hash: fr_col(row, "manifest_hash")?,
                document: codec::manifest_from_text(&get::<String>(row, "document")?)
                    .map_err(|e| corrupt("document", e))?,
                seq: to_u64("seq", get(row, "seq")?)?,
            })
        })
        .collect()
}

async fn q_manifest(c: &mut PgConnection, ns: Fr) -> Result<Option<ManifestRow>, Refusal> {
    Ok(q_manifests(c, ns).await?.into_iter().next())
}

// A package of the newest version.
async fn q_package(
    c: &mut PgConnection,
    ns: Fr,
    name: &str,
) -> Result<Option<PackageRow>, Refusal> {
    match q_manifest(&mut *c, ns).await? {
        Some(m) => q_package_in(c, ns, m.manifest_hash, name).await,
        None => Ok(None),
    }
}

async fn q_package_in(
    c: &mut PgConnection,
    ns: Fr,
    manifest_hash: Fr,
    name: &str,
) -> Result<Option<PackageRow>, Refusal> {
    let row = sqlx::query(
        "SELECT manifest_hash, circuit_json, manifest, vk, vk_hash, disabled, seq FROM packages \
         WHERE namespace = $1 AND manifest_hash = $2 AND name = $3",
    )
    .bind(fr_bytes(ns).to_vec())
    .bind(fr_bytes(manifest_hash).to_vec())
    .bind(name)
    .fetch_optional(c)
    .await
    .map_err(db)?;
    row.map(|row| {
        Ok(PackageRow {
            name: name.to_string(),
            manifest_hash: fr_col(&row, "manifest_hash")?,
            circuit_json: get(&row, "circuit_json")?,
            manifest: codec::manifest_from_text(&get::<String>(&row, "manifest")?)
                .map_err(|e| corrupt("manifest", e))?,
            vk: get(&row, "vk")?,
            vk_hash: fr_col(&row, "vk_hash")?,
            disabled: get(&row, "disabled")?,
            seq: to_u64("seq", get(&row, "seq")?)?,
        })
    })
    .transpose()
}

async fn q_consumed(
    c: &mut PgConnection,
    ns: Fr,
    note_hash: Fr,
) -> Result<Option<ConsumedRow>, Refusal> {
    let row = sqlx::query(
        "SELECT circuit, request_id FROM consumed WHERE namespace = $1 AND note_hash = $2",
    )
    .bind(fr_bytes(ns).to_vec())
    .bind(fr_bytes(note_hash).to_vec())
    .fetch_optional(c)
    .await
    .map_err(db)?;
    row.map(|row| {
        Ok(ConsumedRow {
            note_hash,
            circuit: fr_col(&row, "circuit")?,
            request_id: RequestId(fr_col(&row, "request_id")?),
        })
    })
    .transpose()
}

async fn q_dead(
    c: &mut PgConnection,
    ns: Fr,
    note_hash: Fr,
) -> Result<Option<DeadRecord>, Refusal> {
    let row =
        sqlx::query("SELECT request_id FROM dead_records WHERE namespace = $1 AND note_hash = $2")
            .bind(fr_bytes(ns).to_vec())
            .bind(fr_bytes(note_hash).to_vec())
            .fetch_optional(c)
            .await
            .map_err(db)?;
    row.map(|row| {
        Ok(DeadRecord {
            note_hash,
            request_id: RequestId(fr_col(&row, "request_id")?),
        })
    })
    .transpose()
}

/// The columns a `requests` row is read from.
const REQUEST_COLUMNS: &str = "request_id, body_hash, vk_hash, proof, public_inputs, \
     stored_keys, created_keys, sealed, signature, status, created_at, chain_request_id";

async fn q_request(
    c: &mut PgConnection,
    ns: Fr,
    request_id: RequestId,
) -> Result<Option<RequestRow>, Refusal> {
    let row = sqlx::query(&format!(
        "SELECT {REQUEST_COLUMNS} FROM requests WHERE namespace = $1 AND request_id = $2"
    ))
    .bind(fr_bytes(ns).to_vec())
    .bind(fr_bytes(request_id.fr()).to_vec())
    .fetch_optional(c)
    .await
    .map_err(db)?;
    row.as_ref().map(request_row).transpose()
}

// The order is the core's `latest_chain_row`: the greatest created_at, then
// the greatest request id (the 32-byte big-endian columns sort as integers).
async fn q_chain_request(
    c: &mut PgConnection,
    ns: Fr,
    chain_request_id: Fr,
) -> Result<Option<RequestRow>, Refusal> {
    let row = sqlx::query(&format!(
        "SELECT {REQUEST_COLUMNS} FROM requests WHERE namespace = $1 AND chain_request_id = $2 \
         ORDER BY created_at DESC, request_id DESC LIMIT 1"
    ))
    .bind(fr_bytes(ns).to_vec())
    .bind(fr_bytes(chain_request_id).to_vec())
    .fetch_optional(c)
    .await
    .map_err(db)?;
    row.as_ref().map(request_row).transpose()
}

fn request_row(row: &PgRow) -> Result<RequestRow, Refusal> {
    let sealed = get::<Vec<u8>>(row, "sealed")?;
    let mut reader = Reader::new(&sealed);
    let sealed = reader
        .sealed()
        .and_then(|s| reader.finish().map(|()| s))
        .map_err(|e| corrupt("sealed", e))?;
    Ok(RequestRow {
        request_id: RequestId(fr_col(row, "request_id")?),
        body_hash: fr_col(row, "body_hash")?,
        vk_hash: fr_col(row, "vk_hash")?,
        proof: get(row, "proof")?,
        public_inputs: frs_from_bytes(&get::<Vec<u8>>(row, "public_inputs")?)
            .map_err(|e| corrupt("public_inputs", e))?,
        stored_keys: get(row, "stored_keys")?,
        created_keys: get(row, "created_keys")?,
        sealed,
        signature: get::<Option<Vec<u8>>>(row, "signature")?
            .map(|b| signature_from_bytes(&b).map_err(|e| corrupt("signature", e)))
            .transpose()?,
        status: codec::status_from_str(&get::<String>(row, "status")?)
            .map_err(|e| corrupt("status", e))?,
        created_at: to_u64("created_at", get(row, "created_at")?)?,
        chain_request_id: get::<Option<Vec<u8>>>(row, "chain_request_id")?
            .map(|b| fr_from_bytes(&b).map_err(|e| corrupt("chain_request_id", e)))
            .transpose()?,
    })
}

async fn q_value(c: &mut PgConnection, ns: Fr, key: &str) -> Result<Option<ValueRow>, Refusal> {
    let row = sqlx::query(
        "SELECT vec, note_hash, request_id FROM \"values\" WHERE namespace = $1 AND key = $2",
    )
    .bind(fr_bytes(ns).to_vec())
    .bind(key)
    .fetch_optional(c)
    .await
    .map_err(db)?;
    row.map(|row| {
        Ok(ValueRow {
            vec: decode_vec(&get::<Vec<u8>>(&row, "vec")?)
                .map_err(|e| corrupt(&format!("vector of key `{key}`"), e))?,
            note_hash: fr_col(&row, "note_hash")?,
            request_id: RequestId(fr_col(&row, "request_id")?),
        })
    })
    .transpose()
}

const VERSION_COLUMNS: &str = "key, commitment, parent, queue_index, request_id, vec, tree_root, tree_next, status, block, \
     block_hash";

fn version_row(row: &PgRow) -> Result<TipVersion, Refusal> {
    let key: String = get(row, "key")?;
    let status: String = get(row, "status")?;
    Ok(TipVersion {
        vec: decode_vec(&get::<Vec<u8>>(row, "vec")?)
            .map_err(|e| corrupt(&format!("version vector of key `{key}`"), e))?,
        commitment: fr_col(row, "commitment")?,
        parent: fr_col(row, "parent")?,
        index: to_u64("queue_index", get(row, "queue_index")?)?,
        request_id: RequestId(fr_col(row, "request_id")?),
        tree: match get::<Option<Vec<u8>>>(row, "tree_root")? {
            Some(root) => Some(VersionTree::from_stored(
                fr_from_col("tree_root", &root)?,
                to_u64(
                    "tree_next",
                    get::<Option<i64>>(row, "tree_next")?.unwrap_or(0),
                )?,
            )),
            None => None,
        },
        status: VersionStatus::parse(&status)
            .ok_or_else(|| corrupt("status", format!("unknown version status `{status}`")))?,
        block: to_u64("block", get(row, "block")?)?,
        block_hash: fr_col(row, "block_hash")?,
        key,
    })
}

async fn q_tip_version(
    c: &mut PgConnection,
    ns: Fr,
    key: &str,
    commitment: Fr,
) -> Result<Option<TipVersion>, Refusal> {
    let row = sqlx::query(&format!(
        "SELECT {VERSION_COLUMNS} FROM tip_versions \
         WHERE namespace = $1 AND key = $2 AND commitment = $3"
    ))
    .bind(fr_bytes(ns).to_vec())
    .bind(key)
    .bind(fr_bytes(commitment).to_vec())
    .fetch_optional(c)
    .await
    .map_err(db)?;
    row.as_ref().map(version_row).transpose()
}

async fn q_tip_versions(
    c: &mut PgConnection,
    ns: Fr,
    key: &str,
) -> Result<Vec<TipVersion>, Refusal> {
    let rows = sqlx::query(&format!(
        "SELECT {VERSION_COLUMNS} FROM tip_versions WHERE namespace = $1 AND key = $2 \
         ORDER BY commitment"
    ))
    .bind(fr_bytes(ns).to_vec())
    .bind(key)
    .fetch_all(c)
    .await
    .map_err(db)?;
    rows.iter().map(version_row).collect()
}

async fn q_tip_node(
    c: &mut PgConnection,
    ns: Fr,
    key: &str,
    hash: Fr,
) -> Result<Option<StoredNode>, Refusal> {
    let row = sqlx::query(
        "SELECT left_child, right_child, leaf_index, leaf_vec, refs FROM tip_nodes \
         WHERE namespace = $1 AND key = $2 AND hash = $3",
    )
    .bind(fr_bytes(ns).to_vec())
    .bind(key)
    .bind(fr_bytes(hash).to_vec())
    .fetch_optional(c)
    .await
    .map_err(db)?;
    let Some(row) = row else {
        return Ok(None);
    };
    let left: Option<Vec<u8>> = get(&row, "left_child")?;
    let right: Option<Vec<u8>> = get(&row, "right_child")?;
    let node = match (left, right) {
        (Some(l), Some(r)) => TreeNode::Inner {
            left: fr_from_col("left_child", &l)?,
            right: fr_from_col("right_child", &r)?,
        },
        _ => TreeNode::Leaf {
            index: to_u64(
                "leaf_index",
                get::<Option<i64>>(&row, "leaf_index")?.unwrap_or(0),
            )?,
            vec: decode_vec(&get::<Option<Vec<u8>>>(&row, "leaf_vec")?.unwrap_or_default())
                .map_err(|e| corrupt(&format!("leaf of key `{key}`"), e))?,
        },
    };
    Ok(Some(StoredNode {
        node,
        refs: to_u64("refs", get(&row, "refs")?)?,
    }))
}

impl StoreRead for PostgresStore {
    fn namespace(&self, namespace: Fr) -> Result<Option<NamespaceRow>, Refusal> {
        self.run(|pool| async move {
            q_namespace(&mut *pool.acquire().await.map_err(db)?, namespace).await
        })
    }
    fn contract_manifest(&self, namespace: Fr) -> Result<Option<ManifestRow>, Refusal> {
        self.run(|pool| async move {
            q_manifest(&mut *pool.acquire().await.map_err(db)?, namespace).await
        })
    }
    fn contract_manifests(&self, namespace: Fr) -> Result<Vec<ManifestRow>, Refusal> {
        self.run(|pool| async move {
            q_manifests(&mut *pool.acquire().await.map_err(db)?, namespace).await
        })
    }
    fn package(&self, namespace: Fr, name: &str) -> Result<Option<PackageRow>, Refusal> {
        self.run(|pool| async move {
            q_package(&mut *pool.acquire().await.map_err(db)?, namespace, name).await
        })
    }
    fn package_in(
        &self,
        namespace: Fr,
        manifest_hash: Fr,
        name: &str,
    ) -> Result<Option<PackageRow>, Refusal> {
        self.run(|pool| async move {
            q_package_in(
                &mut *pool.acquire().await.map_err(db)?,
                namespace,
                manifest_hash,
                name,
            )
            .await
        })
    }
    fn consumed(&self, namespace: Fr, note_hash: Fr) -> Result<Option<ConsumedRow>, Refusal> {
        self.run(|pool| async move {
            q_consumed(
                &mut *pool.acquire().await.map_err(db)?,
                namespace,
                note_hash,
            )
            .await
        })
    }
    fn dead_record(&self, namespace: Fr, note_hash: Fr) -> Result<Option<DeadRecord>, Refusal> {
        self.run(|pool| async move {
            q_dead(
                &mut *pool.acquire().await.map_err(db)?,
                namespace,
                note_hash,
            )
            .await
        })
    }
    fn request(&self, namespace: Fr, request_id: RequestId) -> Result<Option<RequestRow>, Refusal> {
        self.run(|pool| async move {
            q_request(
                &mut *pool.acquire().await.map_err(db)?,
                namespace,
                request_id,
            )
            .await
        })
    }
    fn chain_request(
        &self,
        namespace: Fr,
        chain_request_id: Fr,
    ) -> Result<Option<RequestRow>, Refusal> {
        self.run(|pool| async move {
            q_chain_request(
                &mut *pool.acquire().await.map_err(db)?,
                namespace,
                chain_request_id,
            )
            .await
        })
    }
    fn value(&self, namespace: Fr, key: &str) -> Result<Option<ValueRow>, Refusal> {
        self.run(|pool| async move {
            q_value(&mut *pool.acquire().await.map_err(db)?, namespace, key).await
        })
    }
    fn tip_version(
        &self,
        namespace: Fr,
        key: &str,
        commitment: Fr,
    ) -> Result<Option<TipVersion>, Refusal> {
        self.run(|pool| async move {
            q_tip_version(
                &mut *pool.acquire().await.map_err(db)?,
                namespace,
                key,
                commitment,
            )
            .await
        })
    }
    fn tip_versions(&self, namespace: Fr, key: &str) -> Result<Vec<TipVersion>, Refusal> {
        self.run(|pool| async move {
            q_tip_versions(&mut *pool.acquire().await.map_err(db)?, namespace, key).await
        })
    }
    fn tip_node(&self, namespace: Fr, key: &str, hash: Fr) -> Result<Option<StoredNode>, Refusal> {
        self.run(|pool| async move {
            q_tip_node(
                &mut *pool.acquire().await.map_err(db)?,
                namespace,
                key,
                hash,
            )
            .await
        })
    }
    fn blob(&self, namespace: Fr, key: &str, name: &str) -> Result<Option<Vec<u8>>, Refusal> {
        self.run(|pool| async move {
            q_blob(
                &mut *pool.acquire().await.map_err(db)?,
                namespace,
                key,
                name,
            )
            .await
        })
    }
    fn blob_names(&self, namespace: Fr, key: &str) -> Result<Vec<String>, Refusal> {
        self.run(|pool| async move {
            q_blob_names(&mut *pool.acquire().await.map_err(db)?, namespace, key).await
        })
    }
}

/// The view of a commit's open transaction, which the commit rules read.
/// Only used inside [`bridge`], on a thread outside any runtime.
struct TxRead<'a> {
    rt: &'a Runtime,
    tx: RefCell<Transaction<'static, Postgres>>,
}

impl StoreRead for TxRead<'_> {
    fn namespace(&self, namespace: Fr) -> Result<Option<NamespaceRow>, Refusal> {
        let mut tx = self.tx.borrow_mut();
        self.rt.block_on(q_namespace(&mut tx, namespace))
    }
    fn contract_manifest(&self, namespace: Fr) -> Result<Option<ManifestRow>, Refusal> {
        let mut tx = self.tx.borrow_mut();
        self.rt.block_on(q_manifest(&mut tx, namespace))
    }
    fn contract_manifests(&self, namespace: Fr) -> Result<Vec<ManifestRow>, Refusal> {
        let mut tx = self.tx.borrow_mut();
        self.rt.block_on(q_manifests(&mut tx, namespace))
    }
    fn package(&self, namespace: Fr, name: &str) -> Result<Option<PackageRow>, Refusal> {
        let mut tx = self.tx.borrow_mut();
        self.rt.block_on(q_package(&mut tx, namespace, name))
    }
    fn package_in(
        &self,
        namespace: Fr,
        manifest_hash: Fr,
        name: &str,
    ) -> Result<Option<PackageRow>, Refusal> {
        let mut tx = self.tx.borrow_mut();
        self.rt
            .block_on(q_package_in(&mut tx, namespace, manifest_hash, name))
    }
    fn consumed(&self, namespace: Fr, note_hash: Fr) -> Result<Option<ConsumedRow>, Refusal> {
        let mut tx = self.tx.borrow_mut();
        self.rt.block_on(q_consumed(&mut tx, namespace, note_hash))
    }
    fn dead_record(&self, namespace: Fr, note_hash: Fr) -> Result<Option<DeadRecord>, Refusal> {
        let mut tx = self.tx.borrow_mut();
        self.rt.block_on(q_dead(&mut tx, namespace, note_hash))
    }
    fn request(&self, namespace: Fr, request_id: RequestId) -> Result<Option<RequestRow>, Refusal> {
        let mut tx = self.tx.borrow_mut();
        self.rt.block_on(q_request(&mut tx, namespace, request_id))
    }
    fn chain_request(
        &self,
        namespace: Fr,
        chain_request_id: Fr,
    ) -> Result<Option<RequestRow>, Refusal> {
        let mut tx = self.tx.borrow_mut();
        self.rt
            .block_on(q_chain_request(&mut tx, namespace, chain_request_id))
    }
    fn value(&self, namespace: Fr, key: &str) -> Result<Option<ValueRow>, Refusal> {
        let mut tx = self.tx.borrow_mut();
        self.rt.block_on(q_value(&mut tx, namespace, key))
    }
    fn tip_version(
        &self,
        namespace: Fr,
        key: &str,
        commitment: Fr,
    ) -> Result<Option<TipVersion>, Refusal> {
        let mut tx = self.tx.borrow_mut();
        self.rt
            .block_on(q_tip_version(&mut tx, namespace, key, commitment))
    }
    fn tip_versions(&self, namespace: Fr, key: &str) -> Result<Vec<TipVersion>, Refusal> {
        let mut tx = self.tx.borrow_mut();
        self.rt.block_on(q_tip_versions(&mut tx, namespace, key))
    }
    fn tip_node(&self, namespace: Fr, key: &str, hash: Fr) -> Result<Option<StoredNode>, Refusal> {
        let mut tx = self.tx.borrow_mut();
        self.rt.block_on(q_tip_node(&mut tx, namespace, key, hash))
    }
    fn blob(&self, namespace: Fr, key: &str, name: &str) -> Result<Option<Vec<u8>>, Refusal> {
        let mut tx = self.tx.borrow_mut();
        self.rt.block_on(q_blob(&mut tx, namespace, key, name))
    }
    fn blob_names(&self, namespace: Fr, key: &str) -> Result<Vec<String>, Refusal> {
        let mut tx = self.tx.borrow_mut();
        self.rt.block_on(q_blob_names(&mut tx, namespace, key))
    }
}

/// The `tip_blobs` row of (`key`, `name`).
async fn q_blob(
    c: &mut PgConnection,
    ns: Fr,
    key: &str,
    name: &str,
) -> Result<Option<Vec<u8>>, Refusal> {
    let row =
        sqlx::query("SELECT bytes FROM tip_blobs WHERE namespace = $1 AND key = $2 AND name = $3")
            .bind(fr_bytes(ns).to_vec())
            .bind(key)
            .bind(name)
            .fetch_optional(c)
            .await
            .map_err(db)?;
    row.map(|row| get::<Vec<u8>>(&row, "bytes")).transpose()
}

/// The names of every `tip_blobs` row of `key`, in byte order.
async fn q_blob_names(c: &mut PgConnection, ns: Fr, key: &str) -> Result<Vec<String>, Refusal> {
    let rows = sqlx::query("SELECT name FROM tip_blobs WHERE namespace = $1 AND key = $2")
        .bind(fr_bytes(ns).to_vec())
        .bind(key)
        .fetch_all(c)
        .await
        .map_err(db)?;
    let mut out = rows
        .iter()
        .map(|row| get::<String>(row, "name"))
        .collect::<Result<Vec<_>, _>>()?;
    // Byte order, whatever the database's collation.
    out.sort();
    Ok(out)
}

/// The advisory lock key of a namespace: the low 64 bits of its integer. Two
/// namespaces that share it only wait for each other.
fn lock_key(ns: Fr) -> i64 {
    i64::from_be_bytes(fr_bytes(ns)[24..].try_into().unwrap())
}

/// Insert the `requests` row `row` of namespace `ns`.
async fn put_request(c: &mut PgConnection, ns: &[u8], row: &RequestRow) -> Result<(), Refusal> {
    let mut sealed = Writer::new();
    sealed.sealed(&row.sealed);
    sqlx::query(
        "INSERT INTO requests (namespace, request_id, body_hash, vk_hash, proof, public_inputs, \
         stored_keys, created_keys, sealed, signature, status, created_at, chain_request_id) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)",
    )
    .bind(ns)
    .bind(fr_bytes(row.request_id.fr()).to_vec())
    .bind(fr_bytes(row.body_hash).to_vec())
    .bind(fr_bytes(row.vk_hash).to_vec())
    .bind(&row.proof)
    .bind(frs_bytes(&row.public_inputs))
    .bind(&row.stored_keys)
    .bind(&row.created_keys)
    .bind(sealed.out)
    .bind(row.signature.as_ref().map(signature_bytes))
    .bind(row.status.as_str())
    .bind(to_i64("created_at", row.created_at)?)
    .bind(row.chain_request_id.map(|c| fr_bytes(c).to_vec()))
    .execute(&mut *c)
    .await
    .map_err(db)?;
    Ok(())
}

/// Every row write of `txn` ([`Txn::writes`]), in order.
async fn apply(c: &mut PgConnection, txn: &Txn) -> Result<(), Refusal> {
    let ns = fr_bytes(txn.namespace()).to_vec();
    for write in txn.writes() {
        apply_write(c, &ns, write).await?;
    }
    Ok(())
}

/// One row write of a commit under namespace `ns`.
async fn apply_write(c: &mut PgConnection, ns: &[u8], write: RowWrite<'_>) -> Result<(), Refusal> {
    match write {
        RowWrite::Namespace(row) => {
            sqlx::query(
                "INSERT INTO namespaces (namespace, owner_pubkey, nsk_app, npk_app_hash, seq) \
                 VALUES ($1, $2, $3, $4, $5)",
            )
            .bind(ns)
            .bind(point_bytes(&row.owner_pubkey))
            .bind(share_bytes(&row.nsk_app))
            .bind(fr_bytes(row.npk_app_hash).to_vec())
            .bind(to_i64("seq", row.seq)?)
            .execute(&mut *c)
            .await
            .map_err(db)?;
        }
        RowWrite::NskApp(share) => set_nsk_app(c, ns, share).await?,
        RowWrite::Manifest(row) => {
            let hash = fr_bytes(row.manifest_hash).to_vec();
            let held: Vec<(Fr, u64)> = q_manifests_of(&mut *c, ns)
                .await?
                .iter()
                .map(|m| (m.manifest_hash, m.seq))
                .collect();
            let keep: Vec<Vec<u8>> = retained_versions(&held, row)
                .into_iter()
                .map(|h| fr_bytes(h).to_vec())
                .collect();
            sqlx::query(
                "DELETE FROM packages WHERE namespace = $1 AND NOT (manifest_hash = ANY($2))",
            )
            .bind(ns)
            .bind(&keep)
            .execute(&mut *c)
            .await
            .map_err(db)?;
            sqlx::query(
                "DELETE FROM manifests WHERE namespace = $1 AND NOT (manifest_hash = ANY($2))",
            )
            .bind(ns)
            .bind(&keep)
            .execute(&mut *c)
            .await
            .map_err(db)?;
            sqlx::query(
                "INSERT INTO manifests (namespace, manifest_hash, document, seq) \
                 VALUES ($1, $2, $3, $4) \
                 ON CONFLICT (namespace, manifest_hash) DO UPDATE SET \
                 document = EXCLUDED.document, seq = EXCLUDED.seq",
            )
            .bind(ns)
            .bind(&hash)
            .bind(row.document.to_string())
            .bind(to_i64("seq", row.seq)?)
            .execute(&mut *c)
            .await
            .map_err(db)?;
        }
        RowWrite::Package(row) => {
            sqlx::query(
                "INSERT INTO packages (namespace, manifest_hash, name, circuit_json, manifest, vk, \
                 vk_hash, disabled, seq) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
                 ON CONFLICT (namespace, manifest_hash, name) DO UPDATE SET \
                 circuit_json = EXCLUDED.circuit_json, manifest = EXCLUDED.manifest, \
                 vk = EXCLUDED.vk, vk_hash = EXCLUDED.vk_hash, disabled = EXCLUDED.disabled, \
                 seq = EXCLUDED.seq",
            )
            .bind(ns)
            .bind(fr_bytes(row.manifest_hash).to_vec())
            .bind(&row.name)
            .bind(&row.circuit_json)
            .bind(row.manifest.to_string())
            .bind(&row.vk)
            .bind(fr_bytes(row.vk_hash).to_vec())
            .bind(row.disabled)
            .bind(to_i64("seq", row.seq)?)
            .execute(&mut *c)
            .await
            .map_err(db)?;
        }
        RowWrite::Seq(seq) => {
            sqlx::query("UPDATE namespaces SET seq = $2 WHERE namespace = $1")
                .bind(ns)
                .bind(to_i64("seq", seq)?)
                .execute(&mut *c)
                .await
                .map_err(db)?;
        }
        RowWrite::Consumed(row) => {
            sqlx::query(
                "INSERT INTO consumed (namespace, note_hash, circuit, request_id) VALUES ($1, $2, $3, $4)",
            )
            .bind(ns)
            .bind(fr_bytes(row.note_hash).to_vec())
            .bind(fr_bytes(row.circuit).to_vec())
            .bind(fr_bytes(row.request_id.fr()).to_vec())
            .execute(&mut *c)
            .await
            .map_err(db)?;
        }
        RowWrite::Revive(note_hash) => {
            sqlx::query("DELETE FROM dead_records WHERE namespace = $1 AND note_hash = $2")
                .bind(ns)
                .bind(fr_bytes(note_hash).to_vec())
                .execute(&mut *c)
                .await
                .map_err(db)?;
        }
        RowWrite::Value {
            key,
            vec,
            note_hash,
            request_id,
        } => put_value(c, ns, key, &encode_vec(vec), note_hash, request_id).await?,
        RowWrite::Rerun(request_id) => {
            let deleted = sqlx::query(
                "DELETE FROM requests WHERE namespace = $1 AND request_id = $2 \
                 AND status = 'rolled_back'",
            )
            .bind(ns)
            .bind(fr_bytes(request_id.fr()).to_vec())
            .execute(&mut *c)
            .await
            .map_err(db)?;
            if deleted.rows_affected() != 1 {
                // Pruned between the rules' read and this write.
                return Err(Refusal::conflict(format!(
                    "the rolled-back attempt {request_id} the round replaces is gone"
                )));
            }
        }
        RowWrite::Request(row) => put_request(c, ns, &row).await?,
        RowWrite::ImportDead(row) => {
            sqlx::query(
                "INSERT INTO dead_records (namespace, note_hash, request_id) VALUES ($1, $2, $3)",
            )
            .bind(ns)
            .bind(fr_bytes(row.note_hash).to_vec())
            .bind(fr_bytes(row.request_id.fr()).to_vec())
            .execute(&mut *c)
            .await
            .map_err(db)?;
        }
        RowWrite::ClearKey(key) => {
            for table in ["tip_versions", "tip_nodes", "tip_blobs"] {
                sqlx::query(&format!(
                    "DELETE FROM {table} WHERE namespace = $1 AND key = $2"
                ))
                .bind(ns)
                .bind(key)
                .execute(&mut *c)
                .await
                .map_err(db)?;
            }
        }
        RowWrite::ClearTip => {
            for table in ["tip_versions", "tip_nodes"] {
                sqlx::query(&format!("DELETE FROM {table} WHERE namespace = $1"))
                    .bind(ns)
                    .execute(&mut *c)
                    .await
                    .map_err(db)?;
            }
        }
        RowWrite::Version(write) => put_version(c, ns, write).await?,
        RowWrite::Node { key, hash, node } => put_node(c, ns, key, hash, node).await?,
        RowWrite::Blob {
            key,
            name,
            bytes: Some(bytes),
        } => {
            sqlx::query(
                "INSERT INTO tip_blobs (namespace, key, name, bytes) VALUES ($1, $2, $3, $4) \
                 ON CONFLICT (namespace, key, name) DO UPDATE SET bytes = EXCLUDED.bytes",
            )
            .bind(ns)
            .bind(key)
            .bind(name)
            .bind(bytes)
            .execute(&mut *c)
            .await
            .map_err(db)?;
        }
        RowWrite::Blob {
            key,
            name,
            bytes: None,
        } => {
            sqlx::query("DELETE FROM tip_blobs WHERE namespace = $1 AND key = $2 AND name = $3")
                .bind(ns)
                .bind(key)
                .bind(name)
                .execute(&mut *c)
                .await
                .map_err(db)?;
        }
        RowWrite::DeleteValue(key) => {
            sqlx::query("DELETE FROM \"values\" WHERE namespace = $1 AND key = $2")
                .bind(ns)
                .bind(key)
                .execute(&mut *c)
                .await
                .map_err(db)?;
        }
        // The consumed set is append-only in both backends. A commit
        // only inserts `consumed` rows; `prune_requests` never touches the
        // table; the one deletion is here, the operator rollback, which
        // deletes exactly the rows whose request id is the rolled-back
        // request, in the same transaction that restores its rows and marks
        // it `rolled_back`. The rule that decides when a rollback may run is
        // the core's (`rules::restore` and `rules::check_commit`), not the
        // backend's. Pruning consumed rows would let a still-unspent state be
        // evaluated a second time (the core's `consumed` module); the cost is
        // under 100 bytes per consuming round, kept for the life of the
        // namespace.
        RowWrite::Unconsume(request_id) => {
            sqlx::query("DELETE FROM consumed WHERE namespace = $1 AND request_id = $2")
                .bind(ns)
                .bind(fr_bytes(request_id.fr()).to_vec())
                .execute(&mut *c)
                .await
                .map_err(db)?;
        }
        RowWrite::Dead(row) => {
            sqlx::query(
                "INSERT INTO dead_records (namespace, note_hash, request_id) VALUES ($1, $2, $3) \
                 ON CONFLICT (namespace, note_hash) DO UPDATE SET request_id = EXCLUDED.request_id",
            )
            .bind(ns)
            .bind(fr_bytes(row.note_hash).to_vec())
            .bind(fr_bytes(row.request_id.fr()).to_vec())
            .execute(&mut *c)
            .await
            .map_err(db)?;
        }
        RowWrite::RolledBack(request_id) => {
            let marked = sqlx::query(
                "UPDATE requests SET status = 'rolled_back' WHERE namespace = $1 AND request_id = $2",
            )
            .bind(ns)
            .bind(fr_bytes(request_id.fr()).to_vec())
            .execute(&mut *c)
            .await
            .map_err(db)?;
            if marked.rows_affected() != 1 {
                // Pruned between the rules' read and this write.
                return Err(Refusal::not_found(format!(
                    "no request {request_id} to roll back"
                )));
            }
        }
    }
    Ok(())
}

async fn set_nsk_app(c: &mut PgConnection, ns: &[u8], share: &Share) -> Result<(), Refusal> {
    sqlx::query("UPDATE namespaces SET nsk_app = $2 WHERE namespace = $1")
        .bind(ns)
        .bind(share_bytes(share))
        .execute(c)
        .await
        .map_err(db)?;
    Ok(())
}

async fn put_version(c: &mut PgConnection, ns: &[u8], write: &VersionWrite) -> Result<(), Refusal> {
    let query = match write {
        VersionWrite::Put(v) => sqlx::query(
            "INSERT INTO tip_versions (namespace, key, commitment, parent, queue_index, \
             request_id, vec, tree_root, tree_next, status, block, block_hash) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
        )
        .bind(ns)
        .bind(&v.key)
        .bind(fr_bytes(v.commitment).to_vec())
        .bind(fr_bytes(v.parent).to_vec())
        .bind(to_i64("queue_index", v.index)?)
        .bind(fr_bytes(v.request_id.fr()).to_vec())
        .bind(encode_vec(&v.vec))
        .bind(v.tree.map(|t| fr_bytes(t.stored().0).to_vec()))
        .bind(v.tree.map(|t| to_i64("tree_next", t.next())).transpose()?)
        .bind(v.status.as_str())
        .bind(to_i64("block", v.block)?)
        .bind(fr_bytes(v.block_hash).to_vec()),
        VersionWrite::Mark {
            key,
            commitment,
            status,
            block,
            block_hash,
        } => sqlx::query(
            "UPDATE tip_versions SET status = $4, block = $5, block_hash = $6 \
             WHERE namespace = $1 AND key = $2 AND commitment = $3",
        )
        .bind(ns)
        .bind(key)
        .bind(fr_bytes(*commitment).to_vec())
        .bind(status.as_str())
        .bind(to_i64("block", *block)?)
        .bind(fr_bytes(*block_hash).to_vec()),
        VersionWrite::Delete { key, commitment } => sqlx::query(
            "DELETE FROM tip_versions WHERE namespace = $1 AND key = $2 AND commitment = $3",
        )
        .bind(ns)
        .bind(key)
        .bind(fr_bytes(*commitment).to_vec()),
    };
    query.execute(c).await.map_err(db)?;
    Ok(())
}

/// One `tip_nodes` write: insert the node or replace its count, or delete it.
async fn put_node(
    c: &mut PgConnection,
    ns: &[u8],
    key: &str,
    hash: Fr,
    node: Option<&StoredNode>,
) -> Result<(), Refusal> {
    let hash = fr_bytes(hash).to_vec();
    let Some(stored) = node else {
        sqlx::query("DELETE FROM tip_nodes WHERE namespace = $1 AND key = $2 AND hash = $3")
            .bind(ns)
            .bind(key)
            .bind(hash)
            .execute(c)
            .await
            .map_err(db)?;
        return Ok(());
    };
    let (left, right, index, vec) = match &stored.node {
        TreeNode::Inner { left, right } => (
            Some(fr_bytes(*left).to_vec()),
            Some(fr_bytes(*right).to_vec()),
            None,
            None,
        ),
        TreeNode::Leaf { index, vec } => (
            None,
            None,
            Some(to_i64("leaf_index", *index)?),
            Some(encode_vec(vec)),
        ),
    };
    sqlx::query(
        "INSERT INTO tip_nodes (namespace, key, hash, left_child, right_child, leaf_index, \
         leaf_vec, refs) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
         ON CONFLICT (namespace, key, hash) DO UPDATE SET refs = EXCLUDED.refs",
    )
    .bind(ns)
    .bind(key)
    .bind(hash)
    .bind(left)
    .bind(right)
    .bind(index)
    .bind(vec)
    .bind(to_i64("refs", stored.refs)?)
    .execute(c)
    .await
    .map_err(db)?;
    Ok(())
}

/// The columns a `receipts` row is read from.
const RECEIPT_COLUMNS: &str = "request_id, circuit, vk_hash, inputs, inputs_hash, user_nonce, \
     shares, expiry_block, stale_blocks, signature";

fn receipt_row(row: &PgRow) -> Result<ReceiptRow, Refusal> {
    Ok(ReceiptRow {
        request_id: fr_col(row, "request_id")?,
        circuit: get(row, "circuit")?,
        vk_hash: fr_col(row, "vk_hash")?,
        inputs: frs_from_bytes(&get::<Vec<u8>>(row, "inputs")?)
            .map_err(|e| corrupt("inputs", e))?,
        inputs_hash: fr_col(row, "inputs_hash")?,
        user_nonce: opt_fr_col(row, "user_nonce")?,
        shares: shares_from_bytes(&get::<Vec<u8>>(row, "shares")?)
            .map_err(|e| corrupt("shares", e))?,
        expiry_block: to_u64("expiry_block", get(row, "expiry_block")?)?,
        stale_blocks: get::<Option<i64>>(row, "stale_blocks")?
            .map(|v| to_u64("stale_blocks", v))
            .transpose()?,
        signature: signature_from_bytes(&get::<Vec<u8>>(row, "signature")?)
            .map_err(|e| corrupt("signature", e))?,
    })
}

async fn put_value(
    c: &mut PgConnection,
    ns: &[u8],
    key: &str,
    vec: &[u8],
    note_hash: Fr,
    request_id: RequestId,
) -> Result<(), Refusal> {
    sqlx::query(
        "INSERT INTO \"values\" (namespace, key, vec, note_hash, request_id) VALUES ($1, $2, $3, $4, $5) \
         ON CONFLICT (namespace, key) DO UPDATE SET vec = EXCLUDED.vec, \
         note_hash = EXCLUDED.note_hash, request_id = EXCLUDED.request_id",
    )
    .bind(ns)
    .bind(key)
    .bind(vec)
    .bind(fr_bytes(note_hash).to_vec())
    .bind(fr_bytes(request_id.fr()).to_vec())
    .execute(c)
    .await
    .map_err(db)?;
    Ok(())
}

impl Store for PostgresStore {
    fn commit(&self, txn: Txn) -> Result<(), Refusal> {
        let pool = self.pool().clone();
        bridge(self.rt(), move |rt| {
            let mut tx = rt.block_on(pool.begin()).map_err(db)?;
            // Commits of one namespace wait for each other, so the rules and
            // the writes see one state even if two processes share the
            // database; the lock is released when the transaction ends.
            rt.block_on(
                sqlx::query("SELECT pg_advisory_xact_lock($1)")
                    .bind(lock_key(txn.namespace()))
                    .execute(&mut *tx),
            )
            .map_err(db)?;
            let read = TxRead {
                rt,
                tx: RefCell::new(tx),
            };
            rules::check_commit(&read, &txn)?;
            let mut tx = read.tx.into_inner();
            rt.block_on(apply(&mut tx, &txn))?;
            rt.block_on(tx.commit()).map_err(db)
        })
    }

    // The pruning cutoff. `prune_requests(older_than)` deletes the
    // `requests` rows whose `created_at` (the node's clock at commit, unix
    // seconds) is strictly before `older_than`; the node's pruning job passes
    // `now - retention` (`Node::prune_requests`, default 30 days, the core's
    // DEFAULT_REQUESTS_RETENTION_SECS). It touches no other table: `consumed`
    // is never pruned (the core's `consumed` module says why), and `values`
    // rows are current state. A pruned id then answers FETCH with 404, cannot
    // be rolled back, and is free for a new body, which the consumed set still
    // bounds. Both backends implement exactly this; a node whose clock jumps
    // forward prunes early.
    fn prune_requests(&self, older_than: u64) -> Result<usize, Refusal> {
        let pool = self.pool().clone();
        bridge(self.rt(), move |rt| {
            rt.block_on(async {
                let deleted = match i64::try_from(older_than) {
                    Ok(cutoff) => {
                        sqlx::query("DELETE FROM requests WHERE created_at < $1")
                            .bind(cutoff)
                            .execute(&pool)
                            .await
                    }
                    // Every stored created_at fits a BIGINT, so all are older.
                    Err(_) => sqlx::query("DELETE FROM requests").execute(&pool).await,
                }
                .map_err(db)?;
                Ok(deleted.rows_affected() as usize)
            })
        })
    }

    fn holds_values(&self) -> bool {
        true
    }

    fn namespaces(&self) -> Result<Vec<Fr>, Refusal> {
        self.run(|pool| async move {
            let rows = sqlx::query("SELECT namespace FROM namespaces")
                .fetch_all(&pool)
                .await
                .map_err(db)?;
            let mut out = rows
                .iter()
                .map(|row| fr_col(row, "namespace"))
                .collect::<Result<Vec<_>, _>>()?;
            out.sort();
            Ok(out)
        })
    }

    // The names are sorted here, not by the database, so the order is the
    // names' byte order whatever the database's collation.
    fn package_names(&self, namespace: Fr) -> Result<Vec<String>, Refusal> {
        self.run(|pool| async move {
            let Some(newest) =
                q_manifest(&mut *pool.acquire().await.map_err(db)?, namespace).await?
            else {
                return Ok(Vec::new());
            };
            let rows = sqlx::query(
                "SELECT name FROM packages WHERE namespace = $1 AND manifest_hash = $2",
            )
            .bind(fr_bytes(namespace).to_vec())
            .bind(fr_bytes(newest.manifest_hash).to_vec())
            .fetch_all(&pool)
            .await
            .map_err(db)?;
            let mut out = rows
                .iter()
                .map(|row| get::<String>(row, "name"))
                .collect::<Result<Vec<_>, _>>()?;
            out.sort();
            Ok(out)
        })
    }

    // Sorted here too, for the byte order whatever the collation.
    fn tip_keys(&self, namespace: Fr) -> Result<Vec<String>, Refusal> {
        self.run(|pool| async move {
            let rows = sqlx::query("SELECT DISTINCT key FROM tip_versions WHERE namespace = $1")
                .bind(fr_bytes(namespace).to_vec())
                .fetch_all(&pool)
                .await
                .map_err(db)?;
            let mut out = rows
                .iter()
                .map(|row| get::<String>(row, "key"))
                .collect::<Result<Vec<_>, _>>()?;
            out.sort();
            Ok(out)
        })
    }

    // Sorted here, for the byte order whatever the collation.
    fn value_keys(&self, namespace: Fr) -> Result<Vec<String>, Refusal> {
        self.run(|pool| async move {
            let rows = sqlx::query("SELECT key FROM \"values\" WHERE namespace = $1")
                .bind(fr_bytes(namespace).to_vec())
                .fetch_all(&pool)
                .await
                .map_err(db)?;
            let mut out = rows
                .iter()
                .map(|row| get::<String>(row, "key"))
                .collect::<Result<Vec<_>, _>>()?;
            out.sort();
            Ok(out)
        })
    }

    fn blob_keys(&self, namespace: Fr) -> Result<Vec<String>, Refusal> {
        self.run(|pool| async move {
            let rows =
                sqlx::query("SELECT DISTINCT key FROM tip_blobs WHERE namespace = $1 ORDER BY key")
                    .bind(fr_bytes(namespace).to_vec())
                    .fetch_all(&pool)
                    .await
                    .map_err(db)?;
            let mut out = rows
                .iter()
                .map(|row| get::<String>(row, "key"))
                .collect::<Result<Vec<_>, _>>()?;
            // Byte order, whatever the database's collation.
            out.sort();
            Ok(out)
        })
    }

    fn consumed_rows(&self, namespace: Fr) -> Result<Vec<ConsumedRow>, Refusal> {
        self.run(|pool| async move {
            let rows = sqlx::query(
                "SELECT note_hash, circuit, request_id FROM consumed WHERE namespace = $1",
            )
            .bind(fr_bytes(namespace).to_vec())
            .fetch_all(&pool)
            .await
            .map_err(db)?;
            let mut out = rows
                .iter()
                .map(|row| {
                    Ok(ConsumedRow {
                        note_hash: fr_col(row, "note_hash")?,
                        circuit: fr_col(row, "circuit")?,
                        request_id: RequestId(fr_col(row, "request_id")?),
                    })
                })
                .collect::<Result<Vec<_>, Refusal>>()?;
            out.sort_by_key(|row| row.note_hash);
            Ok(out)
        })
    }

    fn receipts(&self, namespace: Fr) -> Result<Vec<ReceiptRow>, Refusal> {
        self.run(|pool| async move {
            let rows = sqlx::query(&format!(
                "SELECT {RECEIPT_COLUMNS} FROM receipts WHERE namespace = $1"
            ))
            .bind(fr_bytes(namespace).to_vec())
            .fetch_all(&pool)
            .await
            .map_err(db)?;
            let mut out = rows
                .iter()
                .map(receipt_row)
                .collect::<Result<Vec<_>, _>>()?;
            out.sort_by_key(|row| row.request_id);
            Ok(out)
        })
    }

    fn receipt(&self, namespace: Fr, request_id: Fr) -> Result<Option<ReceiptRow>, Refusal> {
        self.run(|pool| async move {
            let row = sqlx::query(&format!(
                "SELECT {RECEIPT_COLUMNS} FROM receipts WHERE namespace = $1 AND request_id = $2"
            ))
            .bind(fr_bytes(namespace).to_vec())
            .bind(fr_bytes(request_id).to_vec())
            .fetch_optional(&pool)
            .await
            .map_err(db)?;
            row.as_ref().map(receipt_row).transpose()
        })
    }

    fn requests(&self, namespace: Fr) -> Result<Vec<RequestRow>, Refusal> {
        self.run(|pool| async move {
            let rows = sqlx::query(&format!(
                "SELECT {REQUEST_COLUMNS} FROM requests WHERE namespace = $1"
            ))
            .bind(fr_bytes(namespace).to_vec())
            .fetch_all(&pool)
            .await
            .map_err(db)?;
            let mut out = rows
                .iter()
                .map(request_row)
                .collect::<Result<Vec<_>, _>>()?;
            out.sort_by_key(|row| row.request_id);
            Ok(out)
        })
    }

    fn dead_records(&self, namespace: Fr) -> Result<Vec<DeadRecord>, Refusal> {
        self.run(|pool| async move {
            let rows =
                sqlx::query("SELECT note_hash, request_id FROM dead_records WHERE namespace = $1")
                    .bind(fr_bytes(namespace).to_vec())
                    .fetch_all(&pool)
                    .await
                    .map_err(db)?;
            let mut out = rows
                .iter()
                .map(|row| {
                    Ok(DeadRecord {
                        note_hash: fr_col(row, "note_hash")?,
                        request_id: RequestId(fr_col(row, "request_id")?),
                    })
                })
                .collect::<Result<Vec<_>, Refusal>>()?;
            out.sort_by_key(|row| row.note_hash);
            Ok(out)
        })
    }

    fn put_receipt(&self, namespace: Fr, row: ReceiptRow) -> Result<(), Refusal> {
        let expiry = to_i64("expiry_block", row.expiry_block)?;
        let stale = row
            .stale_blocks
            .map(|v| to_i64("stale_blocks", v))
            .transpose()?;
        let keep_until = i64::try_from(row.keep_until()).unwrap_or(i64::MAX);
        self.run(|pool| async move {
            sqlx::query(
                "INSERT INTO receipts (namespace, request_id, circuit, vk_hash, inputs, \
                 inputs_hash, user_nonce, shares, expiry_block, stale_blocks, keep_until, \
                 signature) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) \
                 ON CONFLICT (namespace, request_id) DO UPDATE SET circuit = EXCLUDED.circuit, \
                 vk_hash = EXCLUDED.vk_hash, inputs = EXCLUDED.inputs, \
                 inputs_hash = EXCLUDED.inputs_hash, user_nonce = EXCLUDED.user_nonce, \
                 shares = EXCLUDED.shares, \
                 expiry_block = EXCLUDED.expiry_block, \
                 stale_blocks = EXCLUDED.stale_blocks, keep_until = EXCLUDED.keep_until, \
                 signature = EXCLUDED.signature",
            )
            .bind(fr_bytes(namespace).to_vec())
            .bind(fr_bytes(row.request_id).to_vec())
            .bind(&row.circuit)
            .bind(fr_bytes(row.vk_hash).to_vec())
            .bind(frs_bytes(&row.inputs))
            .bind(fr_bytes(row.inputs_hash).to_vec())
            .bind(row.user_nonce.map(|v| fr_bytes(v).to_vec()))
            .bind(shares_bytes(&row.shares))
            .bind(expiry)
            .bind(stale)
            .bind(keep_until)
            .bind(signature_bytes(&row.signature))
            .execute(&pool)
            .await
            .map_err(db)?;
            Ok(())
        })
    }

    // The rule is the core's `ReceiptRow::prunable_at`: `keep_until`
    // (`ReceiptRow::keep_until`, saturating at the BIGINT maximum) strictly
    // below `block`. A block beyond BIGINT is clamped, so a saturated row is
    // never listed (block numbers are u32 at the tip).
    fn expired_receipts(&self, block: u64) -> Result<Vec<(Fr, Fr)>, Refusal> {
        let block = i64::try_from(block).unwrap_or(i64::MAX);
        self.run(|pool| async move {
            let rows =
                sqlx::query("SELECT namespace, request_id FROM receipts WHERE keep_until < $1")
                    .bind(block)
                    .fetch_all(&pool)
                    .await
                    .map_err(db)?;
            rows.iter()
                .map(|row| Ok((fr_col(row, "namespace")?, fr_col(row, "request_id")?)))
                .collect()
        })
    }

    // One statement over the given ids, each still past its window by the
    // same rule as `expired_receipts`, so a row re-signed with a later
    // expiry since it was listed stays.
    fn prune_receipts(&self, block: u64, ids: &[(Fr, Fr)]) -> Result<usize, Refusal> {
        if ids.is_empty() {
            return Ok(0);
        }
        let block = i64::try_from(block).unwrap_or(i64::MAX);
        let namespaces: Vec<Vec<u8>> = ids.iter().map(|(ns, _)| fr_bytes(*ns).to_vec()).collect();
        let request_ids: Vec<Vec<u8>> = ids.iter().map(|(_, id)| fr_bytes(*id).to_vec()).collect();
        self.run(|pool| async move {
            let deleted = sqlx::query(
                "DELETE FROM receipts r USING UNNEST($1::bytea[], $2::bytea[]) AS d(namespace, \
                 request_id) WHERE r.namespace = d.namespace AND r.request_id = d.request_id \
                 AND r.keep_until < $3",
            )
            .bind(namespaces)
            .bind(request_ids)
            .bind(block)
            .execute(&pool)
            .await
            .map_err(db)?;
            Ok(deleted.rows_affected() as usize)
        })
    }
}

#[cfg(test)]
mod tls_tests {
    use super::*;

    fn mode(url: &str) -> PgSslMode {
        connect_options(url).unwrap().get_ssl_mode()
    }

    /// A server on another host is reached with `verify-full` unless the URL
    /// names a mode; a loopback host or a socket keeps sqlx's `prefer`.
    #[test]
    fn a_remote_server_is_verified_by_default() {
        if std::env::var_os("PGSSLMODE").is_some() {
            eprintln!("SKIPPED: PGSSLMODE is set");
            return;
        }
        assert!(matches!(
            mode("postgres://u:p@db.example:5432/pss"),
            PgSslMode::VerifyFull
        ));
        assert!(matches!(
            mode("postgres://u:p@10.0.0.7/pss"),
            PgSslMode::VerifyFull
        ));
        assert!(matches!(
            mode("postgres://u:p@db.example/pss?sslmode=require"),
            PgSslMode::Require
        ));
        assert!(matches!(
            mode("postgres://u:p@db.example/pss?sslrootcert=ca.pem&sslmode=verify-ca"),
            PgSslMode::VerifyCa
        ));
        for local in [
            "postgres://u:p@localhost/pss",
            "postgres://u:p@127.0.0.1:5432/pss",
            "postgres://u:p@[::1]/pss",
            "postgres://u@%2Fvar%2Frun%2Fpostgresql/pss",
        ] {
            assert!(matches!(mode(local), PgSslMode::Prefer), "{local}");
        }
    }
}
