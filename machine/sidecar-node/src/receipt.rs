//! The tip's receipt signer (docs/ARCHITECTURE.md section 6, the
//! receipts row): `POST /v1/receipt` checks a request's inputs (under secret-shared
//! receipt intake, this node's envelopes of them), stores them and signs a
//! receipt with this node's `sig` key; `GET
//! /v1/receipt/{namespace}/{request_id}` serves the stored inputs to the
//! scheduler and the chain verifier; the pruning job deletes a receipt past
//! `expiry_block + stale_blocks` whose request, in the node's own chain
//! view, never reached the queue or is done, and keeps every other ([`prune`]).
//!
//! ```text
//! POST /v1/receipt   {namespace, circuit, inputs, user_nonce, current_block, expiry_block}
//!                    {namespace, circuit, inputs, inputs_hash: C,
//!                     shared_inputs [{name, share, share_hashes[3]}, ..., $summand_salt],
//!                     summand_commitments [S_0, S_1, S_2], sharing_digest: D,
//!                     current_block, expiry_block}                     secret-shared receipt intake
//!                    -> {request_id, inputs_hash, expiry_block, signature}
//! GET  /v1/receipt/{namespace}/{request_id}
//!                    -> {namespace, request_id, circuit, vk_hash, inputs, inputs_hash,
//!                        user_nonce | shared_inputs, expiry_block, stale_blocks,
//!                        signature}                                    (404 none)
//! ```
//!
//! The order of the checks: the node's chain view (400 on a node without
//! `[tip]`), the expiry bound against its current block (400), resolution
//! (absent or disabled: 400), the package's manifest (`intake: receipt` or
//! `intake: shared_receipt`: 400 otherwise), the static-validity check (400),
//! under secret-shared receipt intake that `D` is the digest of the summand
//! commitments, the circuit's layout and the clear inputs the node is about
//! to store (400: the receipt signs `D`, so the node signs only the clear
//! inputs `D` covers), then the ids, then this node's envelopes
//! (secret-shared receipt intake: each, and the salts', hashes to its share
//! hash and opens under the current `enc` key, and the pairs and salts they
//! open to hash to the request's summand commitments `S_i` and `S_{i-1}`;
//! 400 otherwise), all before anything is stored or signed. The node
//! checks alone; the pairs are dropped, and the salts' envelope is not
//! stored. The message, the signer and the checks are sidecar-tip's; the
//! `receipts` table is the store trait's.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, PoisonError};

use sidecar_core::Refusal;
use sidecar_core::epochs::EncKeyObservation;
use sidecar_core::field::{FieldHex, Fr, fr_to_hex};
use sidecar_core::key_epoch::StoredNodeKeys;
use sidecar_core::pipeline::{Node, VerifierRows};
use sidecar_core::register::Signature;
use sidecar_core::registry;
use sidecar_core::store::rules::VersionView;
use sidecar_core::store::{ReceiptRow, Store};
use sidecar_tip::{
    ReceiptAnswer, ReceiptChainView, ReceiptRequest, Standing, StoredReceipt, Transport,
    check_expiry, check_receipt_request, sign_receipt_message,
};

// The receipt chain view, the node's one seam for the chain at its receipts:
// the current block a receipt's expiry is checked against, and where a stored
// receipt's request stands in its queue. A node with a `[tip]` section reads
// both through its own Aztec node (`tip.aztec_node`, the chain verifier's,
// never the orchestrator's), with sidecar-tip's [`ReceiptChainView`] over the
// `[[tip.namespaces]]` queues; the receipt signer then ignores the block a
// body claims, and refuses (400) while its Aztec node does not answer. A node
// without `[tip]` has [`NoChainView`]: it refuses every receipt request (400,
// "this node has no [tip] section") and reads no queue. Only the chain can say
// whether a request is still queued, a block a client or the orchestrator
// claims must never bound what a node signs or make it drop inputs, and a node
// that cannot prune must not store. See the pruning rule at [`prune`]; a tip
// deployment configures `[tip]` on every node that signs receipts.
/// Where the node learns the current L2 block and the queue standing of a
/// stored receipt's request, and the pruning job its node-held version
/// views.
pub trait ReceiptChain: Send + Sync {
    /// The block a receipt request is checked against, given the block the
    /// request claims (the orchestrator's view); a refusal refuses the
    /// request.
    fn current_block(&self, claimed: u32) -> Result<u32, Refusal>;

    /// The settled block of the node's own chain view (the finalized tip,
    /// which a replacement cannot reach), the block
    /// the pruning job and the `enc` retirement decide deletion at; `None`
    /// when it has none (no `[tip]`), and then no receipt is pruned.
    fn settled(&self) -> Result<Option<u64>, Refusal>;

    /// Where each of `ids` (chain request ids of `namespace`) stands in its
    /// queue at `block` (a block [`Self::settled`] answered), in the order
    /// given, the queue where the namespace's contract manifest in `rows`
    /// says; `None` for a namespace the view does not read (not listed, or
    /// no registered tip contract manifest), whose receipts are then kept.
    fn standings(
        &self,
        rows: &dyn VerifierRows,
        block: u64,
        namespace: Fr,
        ids: &[Fr],
    ) -> Result<Option<Vec<Standing>>, Refusal>;

    /// The chain views the node-held prune pass marks `keys` (node-held tip
    /// keys of `namespace`) against, all read at one block, in the order
    /// given; `None` for a namespace the view does not read, whose versions
    /// then change only at its next round. None by default (no `[tip]`).
    fn version_views(
        &self,
        _rows: &dyn VerifierRows,
        _namespace: Fr,
        _keys: &[String],
    ) -> Result<Option<Vec<VersionView>>, Refusal> {
        Ok(None)
    }

    /// Node `i`'s stored `enc` key in `namespace`'s contract with the
    /// queue's head and tail, all read at one block (secret-shared on-chain intake;
    /// the pruning job's `EpochKeys::apply`); `None` for a namespace the
    /// view does not read or whose contract manifest gives no
    /// `storage.shared_onchain`, whose epochs then stay as they are. None by
    /// default (no `[tip]`).
    fn enc_key(
        &self,
        _rows: &dyn VerifierRows,
        _namespace: Fr,
        _i: usize,
    ) -> Result<Option<EncKeyObservation>, Refusal> {
        Ok(None)
    }

    /// Every `[tip]` namespace's key epoch on the node's own chain view, for
    /// a replacement's declarations; `None` without `[tip]`.
    fn key_epochs(&self) -> Result<Option<Vec<(Fr, StoredNodeKeys)>>, Refusal> {
        Ok(None)
    }

    /// The contract manifest version `namespace`'s contract pins name in
    /// force on the node's own chain view (the one a receipt's request id is
    /// computed under); `None` for a namespace the view does not read, whose
    /// receipts are computed under its newest version.
    fn manifest_in_force(
        &self,
        _rows: &dyn VerifierRows,
        _namespace: Fr,
    ) -> Result<Option<Fr>, Refusal> {
        Ok(None)
    }
}

/// The chain view of a node without `[tip]`: none, so every receipt
/// request is refused and nothing is pruned.
#[derive(Debug, Default)]
pub struct NoChainView;

/// The refusal of a receipt request on a node without `[tip]`.
pub const NO_TIP_SECTION: &str = "receipt signer: this node has no [tip] section, so it reads \
     no chain to bound an expiry by or prune by, and signs no receipt";

impl ReceiptChain for NoChainView {
    fn current_block(&self, _claimed: u32) -> Result<u32, Refusal> {
        Err(Refusal::bad_request(NO_TIP_SECTION))
    }

    fn settled(&self) -> Result<Option<u64>, Refusal> {
        Ok(None)
    }

    fn standings(
        &self,
        _: &dyn VerifierRows,
        _: u64,
        _: Fr,
        _: &[Fr],
    ) -> Result<Option<Vec<Standing>>, Refusal> {
        Ok(None)
    }
}

/// The node's own chain view (`[tip]`).
impl<T: Transport + 'static> ReceiptChain for ReceiptChainView<T> {
    fn current_block(&self, _claimed: u32) -> Result<u32, Refusal> {
        let block = self.proposed().map_err(|r| {
            Refusal::bad_request(format!("receipt signer: no current block: {}", r.message))
        })?;
        u32::try_from(block).map_err(|_| {
            Refusal::bad_request(format!(
                "receipt signer: this node's Aztec node is at block {block}, past u32"
            ))
        })
    }

    fn settled(&self) -> Result<Option<u64>, Refusal> {
        ReceiptChainView::settled(self).map(Some)
    }

    fn standings(
        &self,
        rows: &dyn VerifierRows,
        block: u64,
        namespace: Fr,
        ids: &[Fr],
    ) -> Result<Option<Vec<Standing>>, Refusal> {
        match self.target(rows, namespace)? {
            Some(target) => ReceiptChainView::standings(self, block, &target, ids).map(Some),
            None => Ok(None),
        }
    }

    fn version_views(
        &self,
        rows: &dyn VerifierRows,
        namespace: Fr,
        keys: &[String],
    ) -> Result<Option<Vec<VersionView>>, Refusal> {
        match self.target(rows, namespace)? {
            Some(target) => {
                ReceiptChainView::version_views(self, rows, namespace, &target, keys).map(Some)
            }
            None => Ok(None),
        }
    }

    fn enc_key(
        &self,
        rows: &dyn VerifierRows,
        namespace: Fr,
        i: usize,
    ) -> Result<Option<EncKeyObservation>, Refusal> {
        match self.target(rows, namespace)? {
            Some(target) => ReceiptChainView::enc_key(self, &target, i),
            None => Ok(None),
        }
    }

    fn key_epochs(&self) -> Result<Option<Vec<(Fr, StoredNodeKeys)>>, Refusal> {
        ReceiptChainView::key_epochs(self).map(Some)
    }

    fn manifest_in_force(
        &self,
        rows: &dyn VerifierRows,
        namespace: Fr,
    ) -> Result<Option<Fr>, Refusal> {
        ReceiptChainView::manifest_in_force(self, rows, namespace)
    }
}

pub use sidecar_tip::DEFAULT_RECEIPT_TTL_BLOCKS;

// Operator knob: DESIGN.md, "Configuration reference"
// (`receipt_allowance_blocks`). A node signs an `expiry_block` at most
// `ttl + allowance` blocks after its own current block.
/// The default expiry allowance in L2 blocks.
pub const DEFAULT_RECEIPT_ALLOWANCE_BLOCKS: u32 = 10;

/// The receipt signer's settings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReceiptConfig {
    pub ttl_blocks: u32,
    pub allowance_blocks: u32,
}

impl Default for ReceiptConfig {
    fn default() -> Self {
        ReceiptConfig {
            ttl_blocks: DEFAULT_RECEIPT_TTL_BLOCKS,
            allowance_blocks: DEFAULT_RECEIPT_ALLOWANCE_BLOCKS,
        }
    }
}

impl ReceiptConfig {
    /// How far after the current block an expiry may be.
    pub fn max_ahead(&self) -> u32 {
        self.ttl_blocks.saturating_add(self.allowance_blocks)
    }
}

/// The receipt signer of a node: its settings, its chain view, and the
/// lock that makes a receipt's read-check-write one step.
pub struct Receipts {
    pub config: ReceiptConfig,
    pub chain: Arc<dyn ReceiptChain>,
    lock: Mutex<()>,
}

impl Receipts {
    /// The signer with `config` and no chain view (a node without `[tip]`,
    /// which refuses every receipt request).
    pub fn new(config: ReceiptConfig) -> Self {
        Self::with_chain(config, Arc::new(NoChainView))
    }

    pub fn with_chain(config: ReceiptConfig, chain: Arc<dyn ReceiptChain>) -> Self {
        Receipts {
            config,
            chain,
            lock: Mutex::new(()),
        }
    }
}

impl Default for Receipts {
    fn default() -> Self {
        Self::new(ReceiptConfig::default())
    }
}

// The answer from a stored row and the signature over this request's
// message.
fn answer_of(row: &ReceiptRow, signature: Signature) -> Result<ReceiptAnswer, Refusal> {
    Ok(ReceiptAnswer {
        request_id: FieldHex(row.request_id),
        inputs_hash: FieldHex(row.inputs_hash),
        expiry_block: u32::try_from(row.expiry_block).map_err(|_| {
            Refusal::mpc_failure(format!(
                "store: receipt {}: expiry_block {} is not a u32",
                fr_to_hex(row.request_id),
                row.expiry_block
            ))
        })?,
        signature,
    })
}

// A second receipt request for a stored request id (the same
// namespace, circuit vk, inputs and nonce; under secret-shared receipt intake the
// same C) is idempotent, not refused.
// With the stored `expiry_block` it answers the stored row (and, the nonce
// being derived, the same signature a fresh signing would give); with a
// later one it signs again and replaces the row's expiry and signature, so a
// user whose receipt is about to expire asks again with the same nonce and
// the node keeps the inputs for the later window; with an earlier one it is
// refused (409), because the row keeps the latest expiry the node signed and
// an earlier receipt would hold the inputs for less time than the one
// already out. A request id is single-use on chain (the contract's seen
// mapping), so two receipts for one id can never both enter the queue.
// Refusing every repeat instead would make a user whose first attempt
// reached only some nodes pick a new nonce; that is the alternative. Under
// secret-shared receipt intake the id commits to C alone, so a repeat must also
// carry the stored clear inputs and the stored envelopes and share hashes
// (409 otherwise): the three nodes' rows must agree on everything but the
// envelope for the scheduler to synthesise the request, and a repeat with
// fresh envelopes that reached only some nodes would split them; a client
// that resealed draws a new blinding instead, which gives a new C and id.
// The answer signs the repeat's own message: its sharing digest passed this
// node's check against the stored envelopes and clear inputs, and with the
// derived nonce the same request gets the same bytes. The salts are not
// stored: a repeat under other salts is a sharing of the same summands,
// which the user's request function proves opens C either way. Neither is
// the digest, so under secret-shared receipt intake the row's signature is
// the first answer's, which the row alone cannot check (`ReceiptRow`), and
// an equal-expiry repeat under other salts answers a signature the row
// does not hold.
/// `POST /v1/receipt`: check `req` and sign its receipt with this node's
/// `sig` key, storing the row first (see the module documentation for the
/// order of the checks).
pub fn sign<S: Store>(
    node: &Node<S>,
    receipts: &Receipts,
    req: &ReceiptRequest,
) -> Result<ReceiptAnswer, Refusal> {
    node.check_serving()?;
    sidecar_core::schnorr::check_name("circuit", "circuit name", &req.circuit)?;
    let expiry = req.expiry_block.ok_or_else(|| {
        Refusal::bad_request(
            "field `expiry_block`: missing; the orchestrator's receipt route sets it",
        )
    })?;
    let current = receipts.chain.current_block(req.current_block)?;
    check_expiry(current, expiry, receipts.config.max_ahead())?;
    let namespace = req.namespace.fr();
    let version = receipts.chain.manifest_in_force(&node.store, namespace)?;
    if let (Some(named), Some(in_force)) = (req.manifest_hash, version)
        && named.fr() != in_force
    {
        return Err(Refusal::bad_request(format!(
            "field `manifest_hash`: {}, but the contract's pins name contract manifest {} on \
             this node's chain view; build the request under that one",
            fr_to_hex(named.fr()),
            fr_to_hex(in_force)
        )));
    }
    let pkg = registry::resolve(&node.store, namespace, &req.circuit, version)?;
    let stale_blocks = sidecar_tip::stale_blocks_of(&node.store, namespace)?;
    let checked = check_receipt_request(&pkg, stale_blocks, req)?;
    checked.check_own_envelopes(&node.keys(), node.index, namespace, &pkg.name)?;
    let signature = sign_receipt_message(node.keys().sig_scalar(), checked.message(expiry));

    let _guard = receipts.lock.lock().unwrap_or_else(PoisonError::into_inner);
    if let Some(stored) = node.store.receipt(namespace, checked.request_id)? {
        if stored.inputs != checked.inputs || stored.shares != checked.shares {
            return Err(Refusal::conflict(format!(
                "a receipt for request {} is stored with other clear inputs or envelopes; \
                 resend those, or seal under a new blinding",
                fr_to_hex(checked.request_id)
            )));
        }
        let wanted = u64::from(expiry);
        if stored.expiry_block == wanted {
            tracing::info!(request_id = %fr_to_hex(checked.request_id), "receipt answered from the stored row");
            return answer_of(&stored, signature);
        }
        if stored.expiry_block > wanted {
            return Err(Refusal::conflict(format!(
                "a receipt for request {} with the later expiry {} is stored; ask with that \
                 expiry, or with another user_nonce",
                fr_to_hex(checked.request_id),
                stored.expiry_block
            )));
        }
    }
    let row = checked.into_row(pkg.name, expiry, signature);
    node.store.put_receipt(namespace, row.clone())?;
    tracing::info!(
        request_id = %fr_to_hex(row.request_id),
        expiry_block = expiry,
        "receipt signed"
    );
    answer_of(&row, signature)
}

/// `GET /v1/receipt/{namespace}/{request_id}`: the stored row (404 none:
/// never signed here, or pruned).
pub fn stored<S: Store>(
    node: &Node<S>,
    namespace: Fr,
    request_id: Fr,
) -> Result<StoredReceipt, Refusal> {
    let row = node.store.receipt(namespace, request_id)?.ok_or_else(|| {
        Refusal::not_found(format!(
            "no receipt for request {} under namespace {} (never signed here, or pruned)",
            fr_to_hex(request_id),
            fr_to_hex(namespace)
        ))
    })?;
    Ok(StoredReceipt::new(namespace, &row))
}

/// What one run of the receipt pruning did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReceiptPruning {
    /// The node has no chain view (no `[tip]`): every receipt kept.
    NoChainView,
    /// The chain view did not answer: every receipt kept.
    Unavailable(String),
    /// At `block` of the node's own chain view: `pruned` rows deleted, and
    /// `kept` rows past their window kept because their request is queued
    /// (or the reads could not tell).
    Ran {
        block: u64,
        pruned: usize,
        kept: usize,
    },
}

impl ReceiptPruning {
    /// How many rows the run deleted; `None` when it read no chain.
    pub fn pruned(&self) -> Option<usize> {
        match self {
            ReceiptPruning::Ran { pruned, .. } => Some(*pruned),
            _ => None,
        }
    }

    /// Why no receipt was pruned, when the run read no chain.
    pub fn not_pruned(&self) -> Option<String> {
        match self {
            ReceiptPruning::NoChainView => Some(
                "this node has no [tip] section, so it reads no chain and keeps every receipt"
                    .into(),
            ),
            ReceiptPruning::Unavailable(why) => Some(format!("every receipt kept: {why}")),
            ReceiptPruning::Ran { .. } => None,
        }
    }
}

// The receipt pruning rule, decided (docs/DECISIONS.md section 9, "Receipt
// pruning by queue standing"): prune by the request's queue standing, not on a
// fixed clock. A receipt's stored
// inputs are kept while its request is queued and not done, and pruned only
// after `expiry_block + stale_blocks` (the stale period fixed at signing;
// `UNSKIPPED_KEEP_BLOCKS` for `null`) and only when the node's own chain view, at its settled
// block (the finalized tip, so an apply in a block that is later replaced
// never counts), says the request never reached
// the queue (`seen` false: past the
// expiry `append_before` refuses it, so it never will) or is done
// (`done[index]` written: applied or skipped). A request still queued keeps
// its inputs however long it waits behind a backlog. A node without `[tip]`,
// or whose Aztec node does not answer, prunes no receipt and keeps them all;
// a receipt of a namespace outside `[[tip.namespaces]]` is kept too. A request
// deeper in the queue reaches the head long after its expiry under load;
// dropping its inputs on a fixed clock would stall the queue a full stale
// period and lose the user's request, and an attacker could cause that on
// purpose by queueing ahead of it. Keeping inputs when the chain cannot be
// read can only cost storage, never a queued request. The stale period after
// expiry also covers a replaced proposed block that held the intake
// transaction. The cost is storage: with a chain view, the rows kept are those
// of requests still queued (bounded by the queue's depth; a row is about 350
// bytes plus 32 per app input) plus those not yet past their window (signed
// within about `receipt_ttl_blocks + stale_blocks` blocks); while the chain
// view is down (its proposed tip going back counts), or on a node without
// `[tip]`, every receipt signed is kept, bounded only by the rate of receipt
// requests the orchestrator forwards (its mutual-TLS route is the only way
// in), until the view answers again. A node that signs receipts should run
// with `[tip]`.
/// The receipt half of the pruning job: read the node's own chain view's
/// settled block, list the receipts past `expiry_block + stale_blocks` at
/// it, and delete those whose request never reached the queue or is done
/// there.
pub fn prune<S: Store>(node: &Node<S>, receipts: &Receipts) -> Result<ReceiptPruning, Refusal> {
    let block = match receipts.chain.settled() {
        Ok(Some(block)) => block,
        Ok(None) => return Ok(ReceiptPruning::NoChainView),
        Err(r) => return Ok(ReceiptPruning::Unavailable(r.message)),
    };
    let mut by_namespace: BTreeMap<Fr, Vec<Fr>> = BTreeMap::new();
    for (namespace, request_id) in node.store.expired_receipts(block)? {
        by_namespace.entry(namespace).or_default().push(request_id);
    }
    let mut gone = Vec::new();
    let mut kept = 0;
    for (namespace, ids) in by_namespace {
        let standings = match receipts
            .chain
            .standings(&node.store, block, namespace, &ids)
        {
            Ok(Some(standings)) => standings,
            Ok(None) => {
                tracing::warn!(
                    namespace = %fr_to_hex(namespace),
                    receipts = ids.len(),
                    "receipts of a namespace the chain view does not read kept"
                );
                kept += ids.len();
                continue;
            }
            Err(r) => return Ok(ReceiptPruning::Unavailable(r.message)),
        };
        for (request_id, standing) in ids.into_iter().zip(standings) {
            if standing.keeps() {
                tracing::debug!(
                    request_id = %fr_to_hex(request_id),
                    ?standing,
                    "receipt past its window kept: its request is queued"
                );
                kept += 1;
            } else {
                gone.push((namespace, request_id));
            }
        }
    }
    let pruned = node.store.prune_receipts(block, &gone)?;
    Ok(ReceiptPruning::Ran {
        block,
        pruned,
        kept,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn without_tip_nothing_is_signed_or_pruned() {
        let chain = NoChainView;
        let err = chain.current_block(100).unwrap_err();
        assert_eq!(err.class, sidecar_core::ErrorClass::BadRequest);
        assert_eq!(err.message, NO_TIP_SECTION);
        assert_eq!(chain.settled().unwrap(), None);
        let rows = sidecar_core::store::MemoryStore::new();
        assert_eq!(
            chain.standings(&rows, 1, Fr::from(1u64), &[]).unwrap(),
            None
        );
        assert!(ReceiptPruning::NoChainView.not_pruned().is_some());
        assert_eq!(ReceiptPruning::NoChainView.pruned(), None);
    }

    #[test]
    fn the_bound_is_ttl_plus_allowance() {
        let config = ReceiptConfig::default();
        assert_eq!((config.ttl_blocks, config.allowance_blocks), (300, 10));
        assert_eq!(config.max_ahead(), 310);
        let wide = ReceiptConfig {
            ttl_blocks: u32::MAX,
            allowance_blocks: 1,
        };
        assert_eq!(wide.max_ahead(), u32::MAX);
    }
}
