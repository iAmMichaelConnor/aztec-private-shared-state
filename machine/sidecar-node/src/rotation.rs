//! Rotating the node's `enc` key (ARCHITECTURE.md section 2, setup and
//! rotation): `sidecar-node rotate-enc` asks the running node, through its
//! admin socket, to draw a new `enc` scalar; the node keeps the previous one
//! for the configured grace window and retires it once the window has lapsed
//! and the head has passed every queued secret-shared receipt request whose stored
//! envelope opens only under it ([`held_by_queued_receipts`]), checking at
//! start and on a timer.
//!
//! ```text
//! rotate-enc         new enc scalar from the OS CSPRNG; current → previous, rotated at now;
//!                    key files written (enc.rotated_at, enc.previous.key, enc.key), then the
//!                    running node's keys replaced; prints the new public keys
//! inside the window  thirds open under either key id, envelopes under either scalar,
//!                    every new third is sealed under the new key
//! window lapsed      kept while a stored secret-shared receipt row whose request may still reach
//!                    the head opens only under it; then enc.previous.key and
//!                    enc.rotated_at removed, the previous key dropped; a third sealed only
//!                    under it is refused (400, wrong key id)
//! ```
//!
//! `sig` never rotates; `GET /v1/nodes` always answers the current keys.
//!
//! Secret-shared on-chain intake keeps each node's `enc` key in every app contract
//! that takes it (ARCHITECTURE.md section 6, "Secret-shared on-chain intake"):
//! `sidecar-node sign-enc-key --namespace <contract> --epoch <e>` asks the
//! running node to keep its current `enc` scalar pending as epoch `e`'s in
//! that contract (`enc.epochs.json`) and to sign the rotation message the
//! contract's `rotate_enc_key(i, key, signature)` checks; the operator
//! submits that transaction (pss-relayer's `rotate-enc-key` signs and
//! submits it, contract by contract). The pruning job reads each contract's
//! stored key for this node with its queue ([`observe_epochs`]): it records
//! the scalar once the rotation has landed and retires the scalars no queued
//! request can name any more.
//!
//! ```text
//! sign-enc-key     current enc scalar pending at epoch e of the contract; prints
//!                  rotate_enc_key's arguments; signing e again replaces it
//! landed           the pruning job sees the contract store this node's key at e
//!                  (or past e): recorded; e is refused under another scalar
//! two epochs on    once the head reaches the tail read then: deleted
//! ```

use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use std::collections::BTreeMap;

use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sidecar_core::Refusal;
use sidecar_core::field::{FieldHex, Fr, fr_to_hex};
use sidecar_core::grumpkin::Fq;
use sidecar_core::keys::{KEY_ID_LEN, KeyFiles, random_scalar};
use sidecar_core::register::Signature;
use sidecar_core::request::GrumpkinPoint;
use sidecar_core::response::NodePublicKeys;
use sidecar_core::store::{ReceiptRow, Store};
use sidecar_tip::Standing;

use crate::server::App;

// How often a running node checks whether its previous enc key's
// grace window has lapsed: once at start, before the node serves, and then
// every hour. A previous key therefore lives between its window and the window
// plus one hour, which is nothing against a window of days; a shorter interval
// only rereads one timestamp more often. The check is fixed rather than a
// config setting because the window, not the check, is what an operator
// chooses; tests shorten it through `KeyRotation::check_interval`.
/// The default interval of the retirement check, in seconds.
pub const DEFAULT_RETIRE_CHECK_SECS: u64 = 3600;

/// What a node needs to rotate and retire its `enc` key: the key directory it
/// writes, the grace window, and how often it checks the window.
pub struct KeyRotation {
    pub files: KeyFiles,
    /// How long the previous enc key is kept after a rotation, in seconds.
    pub grace_secs: u64,
    /// How often the running node checks whether the window has lapsed.
    pub check_interval: Duration,
    // Serialises rotations and retirements: each reads the keys, writes the
    // files and replaces the keys as one step.
    lock: Mutex<()>,
}

impl KeyRotation {
    pub fn new(files: KeyFiles, grace_secs: u64) -> Self {
        KeyRotation {
            files,
            grace_secs,
            check_interval: Duration::from_secs(DEFAULT_RETIRE_CHECK_SECS),
            lock: Mutex::new(()),
        }
    }
}

/// A key id as `0x` and 16 hex digits.
pub fn key_id_hex(id: &[u8; KEY_ID_LEN]) -> String {
    let digits: String = id.iter().map(|b| format!("{b:02x}")).collect();
    format!("0x{digits}")
}

/// The answer to a rotation: the node's public keys after it (what clients
/// and the orchestrator pin), the new and previous key ids, and when the
/// previous key is retired.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EncRotated {
    /// The new enc public key.
    pub enc: GrumpkinPoint,
    /// The sig public key, unchanged.
    pub sig: GrumpkinPoint,
    /// The key id every new record third starts with.
    pub key_id: String,
    /// The key id of the previous key, still opened until `previous_retires_at`.
    pub previous_key_id: String,
    /// When the grace window ends (unix seconds).
    pub previous_retires_at: u64,
}

// `rotate-enc` refuses (409) while a previous key is still
// inside its grace window, or past it while a queued secret-shared receipt request
// still needs it ([`held_by_queued_receipts`]), unless `--force`. A second
// rotation drops the previous key at once, and with it every third and
// envelope still sealed only under it, so rotating while it is still needed
// must be deliberate. The new scalar is drawn
// from the OS CSPRNG on the node itself and never leaves it; the files are
// written before the running keys are replaced, so a failed write changes
// nothing, and a node killed after the write starts with the new keys.
/// Rotate this node's `enc` key now. Refuses (409) while the previous key is
/// inside its grace window, or held past it by a queued secret-shared receipt
/// request, unless `force`.
pub fn rotate_enc<S: Store>(app: &App<S>, force: bool) -> Result<EncRotated, Refusal> {
    let rotation = &app.rotation;
    let _serial = rotation.lock.lock().unwrap_or_else(PoisonError::into_inner);
    let now = app.now();
    let keys = app.node.keys();
    if let (Some(ends), Some(previous)) = (
        keys.grace_ends_at(rotation.grace_secs),
        keys.previous_key_id(),
    ) && !force
    {
        if now < ends {
            return Err(Refusal::conflict(format!(
                "the previous enc key (key id {}) is inside its grace window until {ends} \
                 (unix seconds); rotating again drops it and loses every third still sealed \
                 only under it: wait for the window to lapse, or pass --force",
                key_id_hex(&previous)
            )));
        }
        let held = held_by_queued_receipts(app)?;
        if !held.is_empty() {
            return Err(Refusal::conflict(format!(
                "the previous enc key (key id {}) is past its grace window but held by {} \
                 queued secret-shared receipt request(s) whose envelope to this node opens only \
                 under it; rotating again loses them: wait for the queue to pass them, or pass --force",
                key_id_hex(&previous),
                held.len()
            )));
        }
    }
    let rotated = keys
        .rotate_enc(random_scalar(&mut OsRng), now)
        .map_err(Refusal::mpc_failure)?;
    rotation.files.write(&rotated).map_err(|e| {
        Refusal::mpc_failure(format!(
            "writing the rotated keys into {}: {e}",
            rotation.files.dir().display()
        ))
    })?;
    let NodePublicKeys { enc, sig } = rotated.public_keys();
    let answer = EncRotated {
        enc,
        sig,
        key_id: key_id_hex(&rotated.key_id()),
        previous_key_id: key_id_hex(&keys.key_id()),
        previous_retires_at: now.saturating_add(rotation.grace_secs),
    };
    app.node.set_keys(rotated);
    tracing::info!(
        key_id = %answer.key_id,
        previous_key_id = %answer.previous_key_id,
        previous_retires_at = answer.previous_retires_at,
        enc = %serde_json::to_string(&answer.enc).unwrap_or_default(),
        "enc key rotated; pin the new enc key in the clients and the orchestrator"
    );
    Ok(answer)
}

/// A node's signed rotation of its current `enc` key into one app contract
/// under secret-shared on-chain intake: the arguments of the contract's
/// `rotate_enc_key(i, key, signature)`, `key` being `enc` at `epoch`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EncKeySigned {
    /// The node's index, the function's `i`.
    pub index: usize,
    /// The app contract.
    pub namespace: FieldHex,
    /// The node's current `enc` public key.
    pub enc: GrumpkinPoint,
    /// The epoch the key takes in the contract: its stored epoch + 1.
    pub epoch: u32,
    /// The Schnorr signature under the node's `sig` key over
    /// `poseidon2([PSS_ENC_ROTATE, namespace, i, enc.x, enc.y, epoch])`.
    pub signature: Signature,
}

// When the node records a contract epoch's scalar (docs/DESIGN.md, "Rotating
// a node's `enc` key"): once the rotation lands.
// `sign-enc-key` keeps its current `enc` scalar pending as `epoch`'s in
// `namespace` (sidecar-tip `rotate_into`, written to enc.epochs.json before
// the running keys are replaced) and only then answers the signature, so a
// request naming the epoch finds its scalar as soon as the rotation lands.
// The pruning job records it once the node's own chain view shows the
// contract storing its key at that epoch ([`observe_epochs`]). Signing a
// pending epoch again replaces its scalar (a resend after a lost
// transaction answers the same key; after `rotate-enc`, the new one), so a
// rotation that never landed leaves nothing to clear. A recorded epoch
// answers again under its scalar and is refused (409) under another, as is
// an epoch below it: neither can land.
/// Keep this node's current `enc` scalar pending as `epoch`'s in
/// `namespace` and sign the contract's rotation to its public key. Refuses
/// epoch 0 (no key) and (409) an epoch that landed under another scalar or
/// lies below a landed one.
pub fn sign_enc_key<S: Store>(
    app: &App<S>,
    namespace: Fr,
    epoch: u32,
) -> Result<EncKeySigned, Refusal> {
    let rotation = &app.rotation;
    let _serial = rotation.lock.lock().unwrap_or_else(PoisonError::into_inner);
    if epoch == 0 {
        return Err(Refusal::bad_request(
            "field `epoch`: 0 is no key in a contract; a contract's first key takes epoch 1",
        ));
    }
    let index = app.node.index;
    let mut keys = (*app.node.keys()).clone();
    let signature = sidecar_tip::rotate_into(&mut keys, index, namespace, epoch, &mut OsRng)
        .map_err(Refusal::conflict)?;
    rotation.files.write(&keys).map_err(|e| {
        Refusal::mpc_failure(format!(
            "writing the contract epochs into {}: {e}",
            rotation.files.dir().display()
        ))
    })?;
    let enc = keys.public_keys().enc;
    app.node.set_keys(keys);
    tracing::info!(
        namespace = %fr_to_hex(namespace),
        epoch,
        "enc key pending at this epoch of the contract and its rotation signed; submit \
         rotate_enc_key to the contract (recorded once the pruning job sees it land)"
    );
    Ok(EncKeySigned {
        index,
        namespace: FieldHex(namespace),
        enc,
        epoch,
        signature,
    })
}

/// What the pruning job's epoch pass read and changed in one contract.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EpochsObserved {
    /// The app contract.
    pub namespace: FieldHex,
    /// The contract's stored epoch for this node at the block read.
    pub stored_epoch: u32,
    /// The epochs recorded: their rotation landed.
    pub recorded: Vec<u32>,
    /// The epochs whose scalar was deleted.
    pub retired: Vec<u32>,
}

/// The secret-shared on-chain intake half of the pruning job: for every contract
/// this node holds an epoch of, read the contract's stored key for this
/// node and its queue's head and tail at one block through the node's own
/// chain view, then record each epoch whose rotation landed and delete each
/// scalar no queued request can name any more
/// ([`sidecar_core::epochs::EpochKeys::apply`]); the key files are written
/// before the running keys are replaced. A contract the view does not read
/// (no `[tip]`, outside `[[tip.namespaces]]`, no `storage.shared_onchain` in
/// its contract manifest) or
/// that does not answer keeps its epochs as they are.
pub fn observe_epochs<S: Store>(app: &App<S>) -> Result<Vec<EpochsObserved>, Refusal> {
    let rotation = &app.rotation;
    let index = app.node.index;
    let mut reads = Vec::new();
    for contract in app.node.keys().epochs().contracts() {
        match app.receipts.chain.enc_key(&app.node.store, contract, index) {
            Ok(Some(at)) => reads.push((contract, at)),
            Ok(None) => tracing::debug!(
                namespace = %fr_to_hex(contract),
                "enc epochs: the chain view does not read this contract's keys; its epochs kept"
            ),
            Err(r) => tracing::warn!(
                namespace = %fr_to_hex(contract),
                error = %r,
                "enc epochs: the chain view did not answer; the contract's epochs kept"
            ),
        }
    }
    if reads.is_empty() {
        return Ok(Vec::new());
    }
    let _serial = rotation.lock.lock().unwrap_or_else(PoisonError::into_inner);
    let mut keys = (*app.node.keys()).clone();
    let candidates: Vec<Fq> = std::iter::once(keys.enc_scalar())
        .chain(keys.previous_enc_scalar())
        .collect();
    let mut observed = Vec::new();
    for (contract, at) in reads {
        let seen = keys.epochs_mut().apply(contract, &at, &candidates);
        for e in &seen.recorded {
            tracing::info!(
                namespace = %fr_to_hex(contract),
                epoch = e,
                "enc key's rotation landed in the contract; scalar recorded at this epoch"
            );
        }
        for e in &seen.retired {
            tracing::info!(
                namespace = %fr_to_hex(contract),
                epoch = e,
                "enc scalar of this epoch retired: no queued request can name it"
            );
        }
        let held_pending = keys.epochs().pending(contract);
        if held_pending.contains(&at.epoch) {
            tracing::warn!(
                namespace = %fr_to_hex(contract),
                epoch = at.epoch,
                "the contract stores a key at this epoch that this node holds no scalar of; \
                 the signed scalar stays pending"
            );
        }
        observed.push(EpochsObserved {
            namespace: FieldHex(contract),
            stored_epoch: at.epoch,
            recorded: seen.recorded,
            retired: seen.retired,
        });
    }
    if observed
        .iter()
        .any(|o| !o.recorded.is_empty() || !o.retired.is_empty())
    {
        rotation.files.write(&keys).map_err(|e| {
            Refusal::mpc_failure(format!(
                "writing the contract epochs into {}: {e}",
                rotation.files.dir().display()
            ))
        })?;
        app.node.set_keys(keys);
    }
    Ok(observed)
}

/// Retire the previous `enc` key if its grace window has lapsed and no
/// queued secret-shared receipt request still needs it ([`held_by_queued_receipts`]):
/// remove it from the key directory, then from the running node. Returns the
/// retired key id, or `None` when there was nothing to retire yet.
pub fn retire_lapsed<S: Store>(app: &App<S>) -> Result<Option<String>, Refusal> {
    let rotation = &app.rotation;
    let _serial = rotation.lock.lock().unwrap_or_else(PoisonError::into_inner);
    let keys = app.node.keys();
    let (Some(ends), Some(previous)) = (
        keys.grace_ends_at(rotation.grace_secs),
        keys.previous_key_id(),
    ) else {
        return Ok(None);
    };
    if app.now() < ends {
        return Ok(None);
    }
    let held = held_by_queued_receipts(app)?;
    if !held.is_empty() {
        tracing::info!(
            key_id = %key_id_hex(&previous),
            requests = held.len(),
            "the previous enc key's grace window lapsed; kept while a queued secret-shared \
             receipt request's envelope to this node opens only under it"
        );
        return Ok(None);
    }
    let retired = (*keys).clone().retire_previous_enc();
    rotation.files.write(&retired).map_err(|e| {
        Refusal::mpc_failure(format!(
            "removing the previous enc key from {}: {e}",
            rotation.files.dir().display()
        ))
    })?;
    app.node.set_keys(retired);
    let id = key_id_hex(&previous);
    tracing::info!(
        key_id = %id,
        "the previous enc key's grace window lapsed; retired it (thirds sealed only under it no longer open)"
    );
    Ok(Some(id))
}

/// The stored secret-shared receipt rows that hold the previous `enc` key past its
/// grace window, as (namespace, chain request id): those whose intake keeps
/// the previous scalar for them (`sidecar_tip::holds_previous_enc`: an
/// envelope to this node that opens under it and not the current one),
/// whose request may still reach the head in the node's own chain view at
/// its settled block (queued, or not yet seen before its `expiry_block`; the
/// pruning job's [`Standing`] and block). This is secret-shared on-chain
/// intake's retirement rule (sidecar-core `epochs`) for the receipt intake's
/// one node-wide scalar: kept until the head has passed every queued request
/// that needs it, where secret-shared on-chain intake reads that from the
/// contract's epochs and the queue alone and receipt intake from each stored
/// row. When the chain view cannot tell (no
/// `[tip]`, an Aztec node that does not answer, a namespace outside
/// `[[tip.namespaces]]`) every such row holds the key: it can only be kept
/// longer, never retired under a queued request. Empty when the node holds
/// no previous key.
pub fn held_by_queued_receipts<S: Store>(app: &App<S>) -> Result<Vec<(Fr, Fr)>, Refusal> {
    let keys = app.node.keys();
    if keys.previous_key_id().is_none() {
        return Ok(Vec::new());
    }
    let index = app.node.index;
    let mut needing: BTreeMap<Fr, Vec<ReceiptRow>> = BTreeMap::new();
    for namespace in app.node.store.namespaces()? {
        for row in app.node.store.receipts(namespace)? {
            if sidecar_tip::holds_previous_enc(&keys, index, namespace, &row) {
                needing.entry(namespace).or_default().push(row);
            }
        }
    }
    if needing.is_empty() {
        return Ok(Vec::new());
    }
    let all = |needing: BTreeMap<Fr, Vec<ReceiptRow>>| {
        needing
            .into_iter()
            .flat_map(|(ns, rows)| rows.into_iter().map(move |r| (ns, r.request_id)))
            .collect()
    };
    let block = match app.receipts.chain.settled() {
        Ok(Some(block)) => block,
        Ok(None) => return Ok(all(needing)),
        Err(r) => {
            tracing::warn!(error = %r, "enc retirement: the chain view did not answer; the previous key is kept");
            return Ok(all(needing));
        }
    };
    let mut held = Vec::new();
    for (namespace, rows) in needing {
        let ids: Vec<Fr> = rows.iter().map(|r| r.request_id).collect();
        let standings = match app
            .receipts
            .chain
            .standings(&app.node.store, block, namespace, &ids)
        {
            Ok(Some(standings)) => standings,
            Ok(None) => vec![Standing::Unknown; ids.len()],
            Err(r) => {
                tracing::warn!(
                    namespace = %fr_to_hex(namespace),
                    error = %r,
                    "enc retirement: the queue read failed; the previous key is kept"
                );
                vec![Standing::Unknown; ids.len()]
            }
        };
        for (row, standing) in rows.iter().zip(standings) {
            let may_queue = standing == Standing::NotSeen && block < row.expiry_block;
            if standing.keeps() || may_queue {
                held.push((namespace, row.request_id));
            }
        }
    }
    Ok(held)
}

/// The retirement check on a thread of its own, logging a failure.
pub async fn retire_once<S: Store + 'static>(app: Arc<App<S>>) {
    match crate::server::own_thread("node-retire", move || retire_lapsed(&app)).await {
        Ok(Ok(_)) => {}
        Ok(Err(r)) => tracing::warn!(error = %r, "the enc key retirement check failed"),
        Err(e) => tracing::warn!(error = %e, "the enc key retirement check panicked"),
    }
}

/// The retirement timer: every `interval` after the first one (the check at
/// start runs before the node serves).
pub async fn retire_timer<S: Store + 'static>(app: Arc<App<S>>, interval: Duration) {
    let mut ticks = tokio::time::interval_at(tokio::time::Instant::now() + interval, interval);
    ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        ticks.tick().await;
        retire_once(app.clone()).await;
    }
}
