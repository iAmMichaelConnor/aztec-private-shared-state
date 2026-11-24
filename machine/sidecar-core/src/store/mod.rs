//! A node's tables (docs/ARCHITECTURE.md section 1, "The store trait") behind
//! one backend-agnostic trait, the rules every backend enforces at commit, and
//! the in-memory backend the tests use.
//!
//! | table        | key                     | holds                                                      |
//! |--------------|-------------------------|------------------------------------------------------------|
//! | `namespaces` | namespace               | owner key, nsk_app share, npk_app_hash (once); registry seq |
//! | `manifests`  | (namespace, manifest hash) | the contract manifest, the seq of the REGISTER that wrote it |
//! | `packages`   | (namespace, manifest hash, name) | circuit JSON, manifest, vk, vk_hash, disabled, seq  |
//! | `consumed`   | (namespace, note_hash)  | circuit vk_hash, request_id; append-only except rollback   |
//! | `dead_records` | (namespace, note_hash) | the rolled-back request that created the record ([`crate::dead`]) |
//! | `requests`   | (namespace, request_id) | body hash, proof, sealed, ...; chain request id (tip)      |
//! | `values`     | (namespace, key)        | this node's vector, note_hash, request_id; node-held keys  |
//! | `receipts`   | (namespace, request_id) | receipt intake inputs, nonce, expiry, signature (tip)              |
//! | `tip_versions` | (namespace, key, commitment) | parent, queue index, creating request, this node's vector, status, block (tip, node-held keys) |
//!
//! A namespace holds one contract manifest version and its packages, or,
//! under `upgrades` `circuits` or `contract`, up to [`MAX_HELD_VERSIONS`]
//! of them: the newest registered and the ones before it, of which the
//! contract's pins name the one in force ([`retained_versions`]).
//!
//! A resync from the two neighbours ([`Txn::import_namespace`]) writes a
//! namespace's row, contract manifest, packages, versions and tree nodes into a store that
//! does not hold the namespace, in one commit with no request row.
//!
//! Reads go through [`StoreRead`]. Writes are collected in a [`Txn`] and applied
//! by [`Store::commit`] all together or not at all, after [`rules::check_commit`]
//! has passed against the state the commit sees. A backend runs that check
//! inside its own transaction (a Postgres backend implements [`StoreRead`] for
//! its transaction handle), so the rules hold whatever the backend.
//!
//! The trait is synchronous: a round binds its sources and commits from the
//! blocking thread that runs the proof (the binder's `Sources::load` is
//! synchronous), under the namespace lock. A database backend blocks that
//! thread for its queries.
//!
//! Stored vectors use one encoding ([`encode_vec`]): per element a tag
//! byte, then `0x00` + 32 bytes for a public value or `0x01` + 64 bytes for a
//! share pair, little-endian ark serialisation.

use std::collections::BTreeMap;

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use noirc_abi::Abi;
use serde_json::Value;

use crate::abi::{CircuitShape, check_manifest_value};
use crate::bind::{Elem, Share};
use crate::dead::DeadRecord;
use crate::error::{Refusal, parse_value};
use crate::field::{Fr, RequestId, fr_to_hex};
use crate::grumpkin::Point;
use crate::manifest::Manifest;
use crate::register::Signature;
use crate::request::NodeSharedInput;
use crate::tree::StoredNode;

pub mod blob;
mod memory;
pub mod rules;
mod txn;
mod versions;
mod writes;

pub(crate) use memory::Tables;
pub use memory::{MemorySnapshot, MemoryStore};
pub use txn::Txn;
pub use versions::{TipRows, tip_rows};
pub use writes::RowWrite;

/// A namespace's row, written by its first REGISTER.
#[derive(Clone, Debug, PartialEq)]
pub struct NamespaceRow {
    /// The owner's Grumpkin key; every later REGISTER and DISABLE is signed by it.
    pub owner_pubkey: Point,
    /// This node's share of the namespace's derived nullifier key.
    pub nsk_app: Share,
    /// The network's nullifying identity for the namespace, which its contract pins.
    pub npk_app_hash: Fr,
    /// The registry sequence number: 0 after the first REGISTER, one more after
    /// each later signed REGISTER or DISABLE.
    pub seq: u64,
}

/// A namespace's contract manifest, written by a REGISTER with its packages.
#[derive(Clone, Debug, PartialEq)]
pub struct ManifestRow {
    /// `poseidon2_hash_bytes(JCS(document))`.
    pub manifest_hash: Fr,
    /// The contract manifest as the owner sent it.
    pub document: serde_json::Value,
    /// The `seq` of the REGISTER that last wrote it (a resend with this
    /// `seq` is answered from the rows).
    pub seq: u64,
}

impl ManifestRow {
    /// The stored document, parsed and checked: what a round and the tip
    /// read the namespace's contract facts from (500 if it no longer parses:
    /// REGISTER checked it).
    pub fn parse(&self) -> Result<crate::manifest::contract::CheckedContractManifest, Refusal> {
        crate::manifest::contract::ContractManifest::parse(&self.document)
            .and_then(crate::manifest::contract::ContractManifest::check)
            .map_err(|e| {
                Refusal::mpc_failure(format!(
                    "store: contract manifest {}: {}",
                    fr_to_hex(self.manifest_hash),
                    e.message
                ))
            })
    }
}

/// A registered package of a namespace's contract manifest.
#[derive(Clone, Debug, PartialEq)]
pub struct PackageRow {
    pub name: String,
    /// The hash of the contract manifest it belongs to.
    pub manifest_hash: Fr,
    /// nargo's output: ACIR bytecode and ABI.
    pub circuit_json: Vec<u8>,
    pub manifest: serde_json::Value,
    pub vk: Vec<u8>,
    pub vk_hash: Fr,
    /// Set by the owner's DISABLE; a disabled circuit is refused at resolution
    /// and its row is kept. A later REGISTER of the same contract manifest
    /// clears it.
    pub disabled: bool,
    /// The `seq` of the registry body that last wrote the row: the REGISTER
    /// that registered it, or the DISABLE that disabled it. A resent body with
    /// this `seq` is answered from the row (the idempotent case).
    pub seq: u64,
}

impl PackageRow {
    /// The stored manifest and its circuit's shape, checked against the ABI of
    /// the stored circuit: what a round, the synthesiser and the registry copy
    /// read a package as (500 if the row no longer parses: REGISTER checked it).
    pub fn parse(&self) -> Result<(Manifest, CircuitShape), Refusal> {
        let broken = |what: &str, message: String| {
            Refusal::mpc_failure(format!("store: package `{}`: {what}: {message}", self.name))
        };
        let circuit: Value = serde_json::from_slice(&self.circuit_json)
            .map_err(|e| broken("the circuit", e.to_string()))?;
        let abi: Abi = parse_value(circuit.get("abi").unwrap_or(&Value::Null))
            .map_err(|e| broken("the ABI", e.message))?;
        check_manifest_value(&self.manifest, &abi).map_err(|e| broken("the manifest", e.message))
    }
}

/// One consumed state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConsumedRow {
    /// The consumed value's note hash.
    pub note_hash: Fr,
    /// The vk_hash of the circuit that consumed it.
    pub circuit: Fr,
    pub request_id: RequestId,
}

/// Whether a committed round still stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RequestStatus {
    Committed,
    /// An operator rolled the round back ([`rules::restore`]).
    RolledBack,
}

impl RequestStatus {
    /// The stored name: `committed` or `rolled_back`.
    pub fn as_str(self) -> &'static str {
        match self {
            RequestStatus::Committed => "committed",
            RequestStatus::RolledBack => "rolled_back",
        }
    }
}

/// What a sealed entry of a request row is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SealedKind {
    /// This node's third `c_i` of a new client-held state record.
    Record,
    /// The node-held vector this round replaced, sealed to the node's own key,
    /// with the request that had written it.
    Replaced { prior_request_id: RequestId },
}

/// One sealed vector in a request row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sealed {
    pub kind: SealedKind,
    pub key: String,
    /// The new record's note hash, or the replaced value's.
    pub note_hash: Fr,
    pub c_i: Vec<u8>,
}

/// A committed round as this node keeps it, for FETCH and for rollback.
#[derive(Clone, Debug, PartialEq)]
pub struct RequestRow {
    pub request_id: RequestId,
    /// Refuses a reused id with a different body.
    pub body_hash: Fr,
    /// The vk_hash of the circuit that ran.
    pub vk_hash: Fr,
    pub proof: Vec<u8>,
    pub public_inputs: Vec<Fr>,
    /// The node-held keys the round stored.
    pub stored_keys: Vec<String>,
    /// The node-held keys among `stored_keys` that held no row before the
    /// round; a rollback deletes them.
    pub created_keys: Vec<String>,
    /// This node's thirds of the new client-held records, in manifest output
    /// order, then the node-held vectors the round replaced.
    pub sealed: Vec<Sealed>,
    /// This node's Schnorr signature over the round's result, if it signed one.
    pub signature: Option<Signature>,
    /// `rolled_back` after [`rules::restore`]; a replay or FETCH of it is 409.
    pub status: RequestStatus,
    /// Unix seconds; what [`Store::prune_requests`] compares. Among the rows
    /// of one chain request id it strictly increases in commit order
    /// ([`rules::chain_created_at`]).
    pub created_at: u64,
    /// At the tip (a queued intake), the chain request id the round
    /// answers, which [`StoreRead::fetch_by_chain_request_id`] looks rows up
    /// by; `None` for every direct round.
    pub chain_request_id: Option<Fr>,
}

impl RequestRow {
    /// This node's thirds of the round's new records, as (key, note hash,
    /// c_i), in the order the round sealed them.
    pub fn records(&self) -> impl Iterator<Item = &Sealed> {
        self.sealed
            .iter()
            .filter(|s| matches!(s.kind, SealedKind::Record))
    }

    /// Whether a round of `body_hash` carrying `chain_request_id` runs again
    /// under this row's request id and replaces the row: the row is a
    /// rolled-back attempt at a queued request (it carries a chain request
    /// id) with the same body. Step 5 treats such a row as absent and the
    /// commit lets the round's row replace it ([`Txn::rerun`]); any other
    /// stored row is a replay, a reused id or a rolled-back request (409).
    pub fn reruns(&self, body_hash: Fr, chain_request_id: Option<Fr>) -> bool {
        self.status == RequestStatus::RolledBack
            && self.chain_request_id.is_some()
            && self.chain_request_id == chain_request_id
            && self.body_hash == body_hash
    }
}

/// The request row a round's commit writes; [`Store::commit`] adds the sealed
/// entries the transaction collected and the status.
#[derive(Clone, Debug, PartialEq)]
pub struct NewRequest {
    pub request_id: RequestId,
    pub body_hash: Fr,
    pub vk_hash: Fr,
    pub proof: Vec<u8>,
    pub public_inputs: Vec<Fr>,
    pub stored_keys: Vec<String>,
    pub created_keys: Vec<String>,
    pub signature: Option<Signature>,
    pub created_at: u64,
    pub chain_request_id: Option<Fr>,
}

// The `receipts` row (tip, receipt intake and secret-shared receipt
// intake), keyed by (namespace, chain request id). It holds what the node
// signed and what the scheduler and the chain verifier read back: the clear
// app inputs in ABI order (sidecar-tip's `intake_inputs`), the commitment
// the receipt signs (`inputs_hash`, or `C` under secret-shared receipt intake), under
// receipt intake the nonce, under secret-shared receipt intake per shared input this
// node's own envelope and all three share hashes (never a plaintext shared
// input), never a requester (the hidden requester), the expiry block, the
// signature, and three columns the receipt message does not name: the
// circuit's registered name and its vk_hash when the node signed (so a reader
// finds the package and can tell a later re-registration), and the manifest's
// `stale_blocks` at signing time, which fixes the earliest block at which
// the row may be pruned (after `expiry_block + stale_blocks`; never, for
// `null`). Fixing it at signing means a later REGISTER of the circuit with a
// shorter stale period cannot shorten the window of receipts already handed
// out. Past that block the store only offers the row; the node's pruning job
// deletes it only when its own chain view says the request never entered
// the queue or is done (sidecar-node's `receipt` module). The table is
// outside the round's transaction: the receipt route writes it, the pruning
// job deletes from it, and no round reads or writes it, so it has its own
// four trait methods instead of `Txn` entries.
/// A receipt this node signed (tip only): the inputs it checked and
/// stored, and its signature over its intake's receipt message (sidecar-tip
/// `receipt`, `ids`).
#[derive(Clone, Debug, PartialEq)]
pub struct ReceiptRow {
    /// The chain request id: `poseidon2(namespace, vk_hash, inputs_hash,
    /// user_nonce)` under receipt intake, `poseidon2(namespace, vk_hash, C)`
    /// under secret-shared receipt intake.
    pub request_id: Fr,
    /// The registered circuit name the receipt was signed for.
    pub circuit: String,
    /// That package's vk_hash when the node signed.
    pub vk_hash: Fr,
    /// The clear app inputs in ABI order.
    pub inputs: Vec<Fr>,
    /// The commitment the receipt signs: `inputs_hash`, or the inputs
    /// commitment `C` under secret-shared receipt intake.
    pub inputs_hash: Fr,
    /// The request's nonce (receipt intake); `None` under secret-shared receipt
    /// intake.
    pub user_nonce: Option<Fr>,
    /// Per shared input, this node's own envelope and all three share hashes
    /// (secret-shared receipt intake); empty under receipt intake.
    pub shares: Vec<NodeSharedInput>,
    /// The first L2 block at which the receipt no longer enters the queue.
    pub expiry_block: u64,
    /// The manifest's stale period when the node signed; `None` when a head
    /// is never skipped.
    pub stale_blocks: Option<u64>,
    /// This node's Schnorr signature over the receipt message. Under
    /// secret-shared receipt intake that message also covers the sharing
    /// digest, which the row does not keep (nor the salts it is over), so
    /// the signature is the node's record of its first answer, not a
    /// receipt anyone can check from the row; nothing reads it.
    pub signature: Signature,
}

// A receipt of a manifest whose stale period is `null` (a head is never
// skipped) is kept past its expiry by a fixed margin instead. The window
// only bounds when the pruning job may look at the row: the job then keeps
// it while its request is queued and not done, however long that is, and
// prunes it once the request is done or, read at the node's settled block,
// never reached the queue (past the expiry the contract refuses it, so it
// never will). So the margin guards only a slow chain view; the examples'
// stale period serves.
/// The blocks a receipt is kept past its expiry when its manifest has no
/// stale period.
pub const UNSKIPPED_KEEP_BLOCKS: u64 = 50;

impl ReceiptRow {
    /// The last block at which the row must still be kept, `expiry_block +
    /// stale_blocks` ([`UNSKIPPED_KEEP_BLOCKS`] when skipping is disabled),
    /// saturating.
    pub fn keep_until(&self) -> u64 {
        self.expiry_block
            .saturating_add(self.stale_blocks.unwrap_or(UNSKIPPED_KEEP_BLOCKS))
    }

    /// Whether the row is past its window at `block`: [`Self::keep_until`]
    /// is below `block`. Only such a row may be pruned, and only once the
    /// chain says its request never entered the queue or is done
    /// ([`Store::prune_receipts`] is given those).
    pub fn prunable_at(&self, block: u64) -> bool {
        self.keep_until() < block
    }
}

// The state mode decides which table a key's value lives in.
// Node-held keys (`state: node` in the manifest: shared state such as an AMM
// pool) have one `values` row per key at each node, rewritten in place; only
// they need a database for state. Client-held keys (`state: client`: single-
// owner state such as a player's game) have no row here at all: the value
// travels as a sealed state record and the node keeps only the consumed set and
// the request row. Moving a key to node-held puts its users' state in the
// operator's database; moving it to client-held makes users responsible for
// their records.
/// A node-held value: this node's third of the vector.
#[derive(Clone, Debug, PartialEq)]
pub struct ValueRow {
    pub vec: Vec<Elem>,
    pub note_hash: Fr,
    /// The request that wrote it.
    pub request_id: RequestId,
}

/// A node-held write staged by [`rules::stage_store`].
#[derive(Clone, Debug, PartialEq)]
pub struct ValueWrite {
    pub key: String,
    pub vec: Vec<Elem>,
    pub note_hash: Fr,
    /// The note hash of the row this write replaces, as staged; `None` for a
    /// fresh key. The commit refuses if the row changed since.
    pub replaces: Option<Fr>,
}

/// A node-held row put back as it was: by a rollback, the vector, note hash
/// and writer the rolled-back request replaced; by a resync's import, the
/// row as the two neighbours hold it.
#[derive(Clone, Debug, PartialEq)]
pub struct RestoredValue {
    pub key: String,
    pub vec: Vec<Elem>,
    pub note_hash: Fr,
    /// The request that wrote the row.
    pub prior_request_id: RequestId,
}

/// An operator rollback of one request, staged by [`rules::restore`]. The
/// commit puts back every row in `restore`, deletes every row in `delete`,
/// deletes every `consumed` row whose request id is `request_id`, writes a
/// `dead_records` row under `request_id` for every note hash in `dead`, and
/// marks the request `rolled_back`. For a tip attempt the transaction's
/// [`VersionWrite::Delete`] writes (with their tree nodes released) delete
/// every `tip_versions` row the request wrote.
#[derive(Clone, Debug, PartialEq)]
pub struct Rollback {
    /// The request that is undone.
    pub request_id: RequestId,
    /// Every key the request replaced.
    pub restore: Vec<RestoredValue>,
    /// Every key the request created.
    pub delete: Vec<String>,
    /// The note hash of every client-held record the request created.
    pub dead: Vec<Fr>,
}

/// Where a tip version stands against the chain (docs/ARCHITECTURE.md
/// section 6, "Node-held state").
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum VersionStatus {
    /// Its commitment is the one the slot holds.
    Canonical,
    /// Computed for a queue entry whose `done` is unwritten, on a parent that
    /// is canonical or live.
    Live,
    /// Neither: an attempt of a done entry the slot does not hold, a version
    /// built on one, or a canonical version the slot has moved past.
    Orphan,
}

impl VersionStatus {
    /// The stored name.
    pub fn as_str(self) -> &'static str {
        match self {
            VersionStatus::Canonical => "canonical",
            VersionStatus::Live => "live",
            VersionStatus::Orphan => "orphan",
        }
    }

    /// The status a stored name names.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "canonical" => Some(VersionStatus::Canonical),
            "live" => Some(VersionStatus::Live),
            "orphan" => Some(VersionStatus::Orphan),
            _ => None,
        }
    }
}

/// One version of a node-held tip key at this node, the `tip_versions` row
/// of (namespace, `key`, `commitment`): written once by the round that
/// created it, never overwritten; only its status and block change.
#[derive(Clone, Debug, PartialEq)]
pub struct TipVersion {
    pub key: String,
    /// The commitment the version is named by: the round's new commitment
    /// for the key. Never 0 (0 is no state).
    pub commitment: Fr,
    /// The commitment of the version the round loaded; 0 for a key the round
    /// created.
    pub parent: Fr,
    /// The queue index of the entry the round was computed for.
    pub index: u64,
    /// The round that created it, one attempt of that entry.
    pub request_id: RequestId,
    /// This node's pairs of the key's vector (empty for a tree-valued key,
    /// whose leaves are nodes of its clear tree).
    pub vec: Vec<Elem>,
    /// For a tree-valued key: where the version's tree is held and its
    /// append index.
    pub tree: Option<VersionTree>,
    pub status: VersionStatus,
    /// Canonical or live: the last block at which this node's chain view saw
    /// it so. Orphan: the block at which it was first marked orphan, which
    /// its retention counts from.
    pub block: u64,
    /// The hash of `block` as the chain view that set it read it. An orphan
    /// mark whose block the chain has since replaced (its hash is no longer
    /// this one) is ignored (`rules::stage_versions`). 0 is a mark with no
    /// hash, which cannot be checked: a version a resync rebuilt from two
    /// neighbours that marked it at one block under different hashes
    /// carries one (`resync::rebuild`; otherwise it takes the later mark
    /// with its sender's hash). Such an orphan mark below the settled block is
    /// ignored too, and the version marked again under the view (sidecar-tip
    /// `state::replaced_marks`), so it is kept until the settled block
    /// passes that view's block; it is never deleted on an unchecked mark.
    pub block_hash: Fr,
}

/// A tree-valued version's tree: a clear tree in the store's `tip_nodes`,
/// or a tree its holder keeps in its blobs (the oblivious tree, whose
/// versions carry the append index alone).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VersionTree {
    Clear(TreeRoot),
    Blobs { next: u64 },
}

/// A clear tree: the root (the store's `tip_nodes` hold the nodes it
/// reaches) and the append index, one past the highest leaf ever written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TreeRoot {
    pub root: Fr,
    pub next: u64,
}

impl VersionTree {
    /// The append index, one past the highest leaf ever written.
    pub fn next(&self) -> u64 {
        match self {
            Self::Clear(t) => t.next,
            Self::Blobs { next } => *next,
        }
    }

    /// The clear tree, when the store's `tip_nodes` hold it.
    pub fn clear(self) -> Option<TreeRoot> {
        match self {
            Self::Clear(t) => Some(t),
            Self::Blobs { .. } => None,
        }
    }

    /// The stored pair (root, append index) of the stores, backups and
    /// bundles: a root of 0 names a tree held in blobs (no clear tree has the
    /// root 0, the empty tree's being `Z_D`).
    pub fn stored(&self) -> (Fr, u64) {
        match self {
            Self::Clear(t) => (t.root, t.next),
            Self::Blobs { next } => (Fr::from(0u64), *next),
        }
    }

    /// The tree a stored pair names ([`VersionTree::stored`]).
    pub fn from_stored(root: Fr, next: u64) -> Self {
        if root == Fr::from(0u64) {
            Self::Blobs { next }
        } else {
            Self::Clear(TreeRoot { root, next })
        }
    }
}

impl From<TreeRoot> for VersionTree {
    fn from(t: TreeRoot) -> Self {
        Self::Clear(t)
    }
}

/// A `tip_versions` write of a round's commit.
#[derive(Clone, Debug, PartialEq)]
pub enum VersionWrite {
    /// A new version; the commit refuses one whose commitment the key already
    /// holds.
    Put(TipVersion),
    /// A held version's status, block and block hash.
    Mark {
        key: String,
        commitment: Fr,
        status: VersionStatus,
        block: u64,
        block_hash: Fr,
    },
    /// Delete a held version.
    Delete { key: String, commitment: Fr },
}

/// What a resync's import writes (docs/ARCHITECTURE.md section 6,
/// "Node-held state", recovery).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Import {
    /// A namespace the store does not hold, whole ([`Txn::import_namespace`]).
    Namespace,
    /// One tip key of a namespace the store holds ([`Txn::import_key`]).
    Key(String),
    /// A share refresh of a namespace the store holds ([`Txn::import_refresh`]).
    Refresh,
}

/// The `tip_nodes` writes of a commit, by (key, hash): the node as it is
/// to be stored (inserted or its count replaced), or `None` to delete it.
pub type NodeWrites = BTreeMap<(String, Fr), Option<StoredNode>>;

/// The `tip_blobs` writes of a commit, by (key, name): the bytes to store
/// (inserted or replaced), or `None` to delete the row. A blob is a
/// node-held tip key holder's opaque state (the oblivious tree brick's DORAM
/// state and journal entries, docs/ARCHITECTURE.md section 6, "Versions,
/// rollback and pipelining" and "Persistence, resync, share refresh,
/// audit"), written and read whole by the holder and never interpreted by the
/// store's backends or the version retention.
pub type BlobWrites = BTreeMap<(String, String), Option<Vec<u8>>>;

// How many contract manifest versions a namespace keeps. A tip namespace
// under `upgrades` `circuits` or `contract` runs a round under the version
// its contract's pins name, read on each node's own chain view, so a node
// must still hold the version in force after a replacement is registered,
// and the one before it while results proven under it may still land. Three:
// the version in force, one registered and scheduled after it, and the one
// before it; a REGISTER beyond that drops the oldest by seq. An owner who
// registers several versions the chain never names can so drop the one in
// force, a liveness cost only: registering it again (at the next seq) brings
// it back. Every other namespace keeps one version.
/// The most contract manifest versions an upgradable namespace holds.
pub const MAX_HELD_VERSIONS: usize = 3;

/// The versions a namespace keeps when `new` is written over the `held`
/// ones ((manifest hash, seq) each): `new`'s, and while `new` is
/// upgradable (its `upgrades` is not `fixed`) the newest of the others by
/// seq, up to [`MAX_HELD_VERSIONS`] in all. One rule for every backend, so
/// replaying a log rebuilds the same tables.
pub fn retained_versions(held: &[(Fr, u64)], new: &ManifestRow) -> Vec<Fr> {
    let upgradable = new
        .document
        .get("upgrades")
        .and_then(Value::as_str)
        .is_some_and(|u| u != "fixed");
    let mut others: Vec<(Fr, u64)> = held
        .iter()
        .copied()
        .filter(|(h, _)| *h != new.manifest_hash)
        .collect();
    others.sort_by(|a, b| b.1.cmp(&a.1));
    let keep = if upgradable { MAX_HELD_VERSIONS - 1 } else { 0 };
    std::iter::once(new.manifest_hash)
        .chain(others.into_iter().take(keep).map(|(h, _)| h))
        .collect()
}

/// The newest of a namespace's versions: the highest `seq`.
pub fn newest_version(rows: impl IntoIterator<Item = ManifestRow>) -> Option<ManifestRow> {
    rows.into_iter().max_by_key(|m| m.seq)
}

/// Every contract manifest version `namespace` holds, oldest first (by
/// `seq`), each with its stored packages in the order its document lists
/// them: what a resync and a store backup copy, so a copy holds the
/// version in force while a newer one waits for its time of change.
/// Written back in this order, each version is kept ([`retained_versions`]).
pub fn held_versions<S: StoreRead + ?Sized>(
    store: &S,
    namespace: Fr,
) -> Result<Vec<(ManifestRow, Vec<PackageRow>)>, Refusal> {
    let mut manifests = store.contract_manifests(namespace)?;
    manifests.sort_by_key(|m| m.seq);
    let mut out = Vec::with_capacity(manifests.len());
    for m in manifests {
        let names = m
            .document
            .get("packages")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|p| p.get("name").and_then(Value::as_str));
        let mut packages = Vec::new();
        for name in names {
            packages.extend(store.package_in(namespace, m.manifest_hash, name)?);
        }
        out.push((m, packages));
    }
    Ok(out)
}

/// The reads every table answers. Each lookup is scoped by namespace; nothing
/// reads across namespaces. A backend failure is `mpc_failure` (500: retry later).
pub trait StoreRead {
    fn namespace(&self, namespace: Fr) -> Result<Option<NamespaceRow>, Refusal>;
    /// The newest contract manifest version the namespace holds (the
    /// highest `seq`): the one REGISTER compares a body with.
    fn contract_manifest(&self, namespace: Fr) -> Result<Option<ManifestRow>, Refusal>;
    /// Every contract manifest version the namespace holds, newest first
    /// (one, except under upgrades: [`MAX_HELD_VERSIONS`]).
    fn contract_manifests(&self, namespace: Fr) -> Result<Vec<ManifestRow>, Refusal>;
    /// The package of this name of the newest contract manifest version.
    fn package(&self, namespace: Fr, name: &str) -> Result<Option<PackageRow>, Refusal>;
    /// The package of this name of the contract manifest version
    /// `manifest_hash`.
    fn package_in(
        &self,
        namespace: Fr,
        manifest_hash: Fr,
        name: &str,
    ) -> Result<Option<PackageRow>, Refusal>;
    fn consumed(&self, namespace: Fr, note_hash: Fr) -> Result<Option<ConsumedRow>, Refusal>;
    fn request(&self, namespace: Fr, request_id: RequestId) -> Result<Option<RequestRow>, Refusal>;
    fn value(&self, namespace: Fr, key: &str) -> Result<Option<ValueRow>, Refusal>;

    /// The `dead_records` row of (namespace, note_hash), if the record was
    /// created by a rolled-back request ([`crate::dead`]).
    fn dead_record(&self, namespace: Fr, note_hash: Fr) -> Result<Option<DeadRecord>, Refusal>;

    /// The `tip_versions` row of (namespace, key, commitment), if held. A
    /// backend without `values` holds none.
    fn tip_version(
        &self,
        namespace: Fr,
        key: &str,
        commitment: Fr,
    ) -> Result<Option<TipVersion>, Refusal>;

    /// Every `tip_versions` row of (namespace, key), in commitment order.
    fn tip_versions(&self, namespace: Fr, key: &str) -> Result<Vec<TipVersion>, Refusal>;

    /// The `tip_nodes` row of (namespace, key, hash): one node of a
    /// tree-valued key's clear tree, content-addressed, with its reference
    /// count. A backend without `values` holds none.
    fn tip_node(&self, namespace: Fr, key: &str, hash: Fr) -> Result<Option<StoredNode>, Refusal>;

    /// The `tip_blobs` row of (`key`, `name`) under `namespace`: a holder's
    /// state, in the format of [`blob::Blob`] ([`BlobWrites`]).
    fn blob(&self, namespace: Fr, key: &str, name: &str) -> Result<Option<Vec<u8>>, Refusal>;

    /// The names of every `tip_blobs` row of `key` under `namespace`, in
    /// byte order. A backend without `values` holds none.
    fn blob_names(&self, namespace: Fr, key: &str) -> Result<Vec<String>, Refusal>;

    /// The latest `requests` row of `namespace` carrying `chain_request_id`,
    /// whatever its status: the one with the greatest `created_at`, and of
    /// two with the same, the greater request id. `None` when no row carries
    /// it (never committed, or pruned).
    fn chain_request(
        &self,
        namespace: Fr,
        chain_request_id: Fr,
    ) -> Result<Option<RequestRow>, Refusal>;

    /// This node's nsk_app share of `namespace`, and only of that namespace.
    fn load_nsk_app(&self, namespace: Fr) -> Result<Option<Share>, Refusal> {
        Ok(self.namespace(namespace)?.map(|row| row.nsk_app))
    }

    // FETCH by chain request id answers the latest row only. At
    // the tip one chain request id may have several rows, one per attempt
    // (each a different machine request id, computed against a different
    // state); the relayer and the scheduler want the attempt the chain can
    // still apply, which is the latest. If the latest was rolled back the
    // answer is 409, never an earlier committed attempt: an earlier attempt
    // ran against a state the later one already replaced, so the scheduler
    // recomputes instead. No row is 404 (never committed, or pruned with the
    // requests retention window). The rule lives here, above the backends,
    // which only find the latest row (`chain_request`); a backend never
    // overrides it.
    /// FETCH by chain request id: the latest row carrying `chain_request_id`
    /// under `namespace` ([`StoreRead::chain_request`]). 404 when none does;
    /// 409 when the latest was rolled back.
    fn fetch_by_chain_request_id(
        &self,
        namespace: Fr,
        chain_request_id: Fr,
    ) -> Result<RequestRow, Refusal> {
        let row = self
            .chain_request(namespace, chain_request_id)?
            .ok_or_else(|| {
                Refusal::not_found(format!(
                    "no request for chain request id {} under namespace {} (unknown, or pruned)",
                    fr_to_hex(chain_request_id),
                    fr_to_hex(namespace)
                ))
            })?;
        if row.status == RequestStatus::RolledBack {
            return Err(Refusal::conflict(format!(
                "the latest request {} for chain request id {} was rolled back",
                row.request_id,
                fr_to_hex(chain_request_id)
            )));
        }
        Ok(row)
    }
}

// Operator knob: DESIGN.md, "Configuration reference" (sidecar-node
// `requests_retention_days`). The node calls `prune_requests(now -
// retention)`; the consumed set is never pruned (see `consumed`).
/// The node's default `requests` retention, in seconds.
pub const DEFAULT_REQUESTS_RETENTION_SECS: u64 = 30 * 24 * 60 * 60;

/// [`StoreRead::chain_request`] over a backend's rows of one namespace: the
/// row carrying `chain_request_id` with the greatest (`created_at`, request
/// id). The in-memory backends answer with it; a database orders the same.
pub fn latest_chain_row<'a>(
    rows: impl IntoIterator<Item = &'a RequestRow>,
    chain_request_id: Fr,
) -> Option<RequestRow> {
    rows.into_iter()
        .filter(|row| row.chain_request_id == Some(chain_request_id))
        .max_by_key(|row| (row.created_at, row.request_id))
        .cloned()
}

/// A node's store. [`Store::commit`] runs [`rules::check_commit`] against the
/// state it commits over and applies every write of the transaction, or none.
pub trait Store: StoreRead + Send + Sync {
    /// An empty transaction under `namespace`.
    fn begin(&self, namespace: Fr) -> Txn {
        Txn::new(namespace)
    }

    /// Check and apply `txn` atomically. A rule refusal (409, 404) leaves the
    /// store unchanged.
    fn commit(&self, txn: Txn) -> Result<(), Refusal>;

    /// Delete every `requests` row created before `older_than` (unix seconds);
    /// returns how many. Never touches `consumed`.
    fn prune_requests(&self, older_than: u64) -> Result<usize, Refusal>;

    /// Whether this backend holds the `values` table, so it can serve keys
    /// whose state mode is `node`. A backend without it refuses every
    /// node-held write at commit, and REGISTER refuses (400, section 4 step 3)
    /// a manifest that gives any key the state mode `node` on it, before any
    /// round runs. Every backend states it; a wrapper forwards its inner
    /// store's answer.
    fn holds_values(&self) -> bool;

    /// Every namespace with a `namespaces` row, in ascending order: the
    /// listing an orchestrator rebuilds its registry copy from.
    fn namespaces(&self) -> Result<Vec<Fr>, Refusal>;

    /// The name of every `packages` row of `namespace`, disabled ones
    /// included, in byte order of the names.
    fn package_names(&self, namespace: Fr) -> Result<Vec<String>, Refusal>;

    /// Every node-held tip key of `namespace` with a `tip_versions` row, in
    /// byte order: what a resync sends and an audit walks. A backend without
    /// `values` holds none.
    fn tip_keys(&self, namespace: Fr) -> Result<Vec<String>, Refusal>;

    /// Every key of `namespace` with a `values` row, in byte order: what a
    /// resync sends. A backend without `values` holds none.
    fn value_keys(&self, namespace: Fr) -> Result<Vec<String>, Refusal>;

    /// Every key of `namespace` with a `tip_blobs` row, in byte order: what
    /// a node replacement refreshes, a resync sends and a backup exports
    /// beside the key's versions. A backend without `values` holds none.
    fn blob_keys(&self, namespace: Fr) -> Result<Vec<String>, Refusal>;

    /// Every `consumed` row of `namespace`, in ascending note hash order:
    /// what a resync sends.
    fn consumed_rows(&self, namespace: Fr) -> Result<Vec<ConsumedRow>, Refusal>;

    /// Every `receipts` row of `namespace`, in ascending chain request id
    /// order: what a resync sends (tip).
    fn receipts(&self, namespace: Fr) -> Result<Vec<ReceiptRow>, Refusal>;

    /// Every `requests` row of `namespace`, in ascending request id order:
    /// what a backup carries.
    fn requests(&self, namespace: Fr) -> Result<Vec<RequestRow>, Refusal>;

    /// Every `dead_records` row of `namespace`, in ascending note hash
    /// order: what a backup carries.
    fn dead_records(&self, namespace: Fr) -> Result<Vec<DeadRecord>, Refusal>;

    /// The `receipts` row of (namespace, chain request id), if any (tip).
    fn receipt(&self, namespace: Fr, request_id: Fr) -> Result<Option<ReceiptRow>, Refusal>;

    /// Write the `receipts` row of (namespace, `row.request_id`), replacing
    /// any stored one, durably before it returns. Whether a second receipt
    /// for an id may replace the first is the receipt route's rule, not the
    /// backend's.
    fn put_receipt(&self, namespace: Fr, row: ReceiptRow) -> Result<(), Refusal>;

    /// The (namespace, chain request id) of every `receipts` row that is
    /// [`ReceiptRow::prunable_at`] `block` (its [`ReceiptRow::keep_until`]
    /// is below `block`), in no particular order: the rows the pruning job
    /// asks the chain about.
    fn expired_receipts(&self, block: u64) -> Result<Vec<(Fr, Fr)>, Refusal>;

    /// Delete the `receipts` rows of `ids` (namespace, chain request id)
    /// that are still [`ReceiptRow::prunable_at`] `block`, durably before it
    /// returns; returns how many. An id with no row, or whose row was
    /// re-signed with a later expiry since it was listed, is left alone.
    /// Which expired rows to delete is the pruning job's rule (it keeps the
    /// inputs of a request still queued), not the backend's.
    fn prune_receipts(&self, block: u64, ids: &[(Fr, Fr)]) -> Result<usize, Refusal>;
}

/// A boxed store is a store: every read and write goes to the boxed one, so
/// `Box<dyn Store>` (a node's backend chosen by its configuration) and any
/// wrapper over a box need no forwarding code of their own.
impl<S: StoreRead + ?Sized> StoreRead for Box<S> {
    fn namespace(&self, namespace: Fr) -> Result<Option<NamespaceRow>, Refusal> {
        (**self).namespace(namespace)
    }
    fn contract_manifest(&self, namespace: Fr) -> Result<Option<ManifestRow>, Refusal> {
        (**self).contract_manifest(namespace)
    }
    fn contract_manifests(&self, namespace: Fr) -> Result<Vec<ManifestRow>, Refusal> {
        (**self).contract_manifests(namespace)
    }
    fn package(&self, namespace: Fr, name: &str) -> Result<Option<PackageRow>, Refusal> {
        (**self).package(namespace, name)
    }
    fn package_in(
        &self,
        namespace: Fr,
        manifest_hash: Fr,
        name: &str,
    ) -> Result<Option<PackageRow>, Refusal> {
        (**self).package_in(namespace, manifest_hash, name)
    }
    fn consumed(&self, namespace: Fr, note_hash: Fr) -> Result<Option<ConsumedRow>, Refusal> {
        (**self).consumed(namespace, note_hash)
    }
    fn request(&self, namespace: Fr, request_id: RequestId) -> Result<Option<RequestRow>, Refusal> {
        (**self).request(namespace, request_id)
    }
    fn value(&self, namespace: Fr, key: &str) -> Result<Option<ValueRow>, Refusal> {
        (**self).value(namespace, key)
    }
    fn dead_record(&self, namespace: Fr, note_hash: Fr) -> Result<Option<DeadRecord>, Refusal> {
        (**self).dead_record(namespace, note_hash)
    }
    fn tip_version(
        &self,
        namespace: Fr,
        key: &str,
        commitment: Fr,
    ) -> Result<Option<TipVersion>, Refusal> {
        (**self).tip_version(namespace, key, commitment)
    }
    fn tip_versions(&self, namespace: Fr, key: &str) -> Result<Vec<TipVersion>, Refusal> {
        (**self).tip_versions(namespace, key)
    }
    fn tip_node(&self, namespace: Fr, key: &str, hash: Fr) -> Result<Option<StoredNode>, Refusal> {
        (**self).tip_node(namespace, key, hash)
    }
    fn blob(&self, namespace: Fr, key: &str, name: &str) -> Result<Option<Vec<u8>>, Refusal> {
        (**self).blob(namespace, key, name)
    }
    fn blob_names(&self, namespace: Fr, key: &str) -> Result<Vec<String>, Refusal> {
        (**self).blob_names(namespace, key)
    }
    fn chain_request(
        &self,
        namespace: Fr,
        chain_request_id: Fr,
    ) -> Result<Option<RequestRow>, Refusal> {
        (**self).chain_request(namespace, chain_request_id)
    }
    fn load_nsk_app(&self, namespace: Fr) -> Result<Option<Share>, Refusal> {
        (**self).load_nsk_app(namespace)
    }
}

impl<S: Store + ?Sized> Store for Box<S> {
    fn begin(&self, namespace: Fr) -> Txn {
        (**self).begin(namespace)
    }
    fn commit(&self, txn: Txn) -> Result<(), Refusal> {
        (**self).commit(txn)
    }
    fn prune_requests(&self, older_than: u64) -> Result<usize, Refusal> {
        (**self).prune_requests(older_than)
    }
    fn holds_values(&self) -> bool {
        (**self).holds_values()
    }
    fn namespaces(&self) -> Result<Vec<Fr>, Refusal> {
        (**self).namespaces()
    }
    fn package_names(&self, namespace: Fr) -> Result<Vec<String>, Refusal> {
        (**self).package_names(namespace)
    }
    fn tip_keys(&self, namespace: Fr) -> Result<Vec<String>, Refusal> {
        (**self).tip_keys(namespace)
    }
    fn value_keys(&self, namespace: Fr) -> Result<Vec<String>, Refusal> {
        (**self).value_keys(namespace)
    }
    fn blob_keys(&self, namespace: Fr) -> Result<Vec<String>, Refusal> {
        (**self).blob_keys(namespace)
    }
    fn consumed_rows(&self, namespace: Fr) -> Result<Vec<ConsumedRow>, Refusal> {
        (**self).consumed_rows(namespace)
    }
    fn receipts(&self, namespace: Fr) -> Result<Vec<ReceiptRow>, Refusal> {
        (**self).receipts(namespace)
    }
    fn requests(&self, namespace: Fr) -> Result<Vec<RequestRow>, Refusal> {
        (**self).requests(namespace)
    }
    fn dead_records(&self, namespace: Fr) -> Result<Vec<DeadRecord>, Refusal> {
        (**self).dead_records(namespace)
    }
    fn receipt(&self, namespace: Fr, request_id: Fr) -> Result<Option<ReceiptRow>, Refusal> {
        (**self).receipt(namespace, request_id)
    }
    fn put_receipt(&self, namespace: Fr, row: ReceiptRow) -> Result<(), Refusal> {
        (**self).put_receipt(namespace, row)
    }
    fn expired_receipts(&self, block: u64) -> Result<Vec<(Fr, Fr)>, Refusal> {
        (**self).expired_receipts(block)
    }
    fn prune_receipts(&self, block: u64, ids: &[(Fr, Fr)]) -> Result<usize, Refusal> {
        (**self).prune_receipts(block, ids)
    }
}

// The stored-vector encoding, how a `values` row (and a
// backend's copy of any stored vector) holds its elements: per element one tag
// byte, `0x00` followed by the public value (32 bytes) or `0x01` followed by
// this node's share pair `(a, b)` (64 bytes), each field in ark's uncompressed
// little-endian serialisation, with no length prefix (the length is the
// manifest's `len`, checked at bind). Every backend stores the same bytes (the Postgres `values.vec` column
// holds them). Changing it makes every `values` row already stored unreadable
// (decode_vec refuses an unknown tag or a truncated element); a change needs a
// migration of every node's rows.
/// The stored-vector encoding: per element `0x00` + the public value
/// (32 bytes) or `0x01` + the share pair (64 bytes), ark's little-endian
/// uncompressed serialisation.
pub fn encode_vec(vec: &[Elem]) -> Vec<u8> {
    let mut out = Vec::with_capacity(65 * vec.len());
    for elem in vec {
        match elem {
            Elem::Public(v) => {
                out.push(0);
                v.serialize_uncompressed(&mut out)
                    .expect("writing to a Vec cannot fail");
            }
            Elem::Shared(s) => {
                out.push(1);
                s.serialize_uncompressed(&mut out)
                    .expect("writing to a Vec cannot fail");
            }
        }
    }
    out
}

/// The inverse of [`encode_vec`].
pub fn decode_vec(mut bytes: &[u8]) -> Result<Vec<Elem>, String> {
    let mut out = Vec::new();
    while let Some((tag, rest)) = bytes.split_first() {
        bytes = rest;
        match tag {
            0 => out.push(Elem::Public(
                Fr::deserialize_uncompressed(&mut bytes).map_err(|e| e.to_string())?,
            )),
            1 => out.push(Elem::Shared(
                Share::deserialize_uncompressed(&mut bytes).map_err(|e| e.to_string())?,
            )),
            _ => return Err(format!("corrupt stored vector: unknown tag {tag}")),
        }
    }
    Ok(out)
}

/// The store test suite, one set of cases for every backend: the in-memory
/// one here, and the Postgres and local stores of `sidecar-node`, which run
/// it through the `test-util` feature. Each case takes a fresh, empty store.
#[cfg(any(test, feature = "test-util"))]
pub mod testing;

#[cfg(test)]
pub(crate) mod tests;
