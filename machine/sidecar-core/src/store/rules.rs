//! The write rules, checked at commit by every backend.

use std::collections::BTreeSet;

use super::*;
use crate::keys::NodeKeys;
use crate::record;

pub use super::versions::{TreeNodes, VersionView, stage_versions, version_statuses};

// Write-requires-read-or-consumed. A node-held key that holds a
// value may be rewritten only by a round that LOADed it (so the round's proof
// covers the value it replaces), or when the stored value's note hash is in
// the consumed set (a spent value can never be loaded again, so overwriting
// it loses nothing the rule protects; a key reused after a wind-down, such as
// the AMM seed after amm_init, stays usable). Anything else is 409 "key
// occupied and not loaded". Dropping the rule lets any request clobber shared
// state it never read; dropping the consumed branch turns every consumed
// node-held key into a tombstone for the namespace's lifetime.
/// Whether the round in `txn` may rewrite `key`, whose row is `current`.
pub fn write_allowed<R: StoreRead + ?Sized>(
    read: &R,
    txn: &Txn,
    key: &str,
    current: &ValueRow,
) -> Result<bool, Refusal> {
    if txn.loaded.contains(key)
        || txn
            .consumed
            .iter()
            .any(|c| c.note_hash == current.note_hash)
    {
        return Ok(true);
    }
    Ok(read.consumed(txn.namespace, current.note_hash)?.is_some())
}

/// Refuse (409) a registry body whose `seq` is not the stored `stored`
/// plus one: a replayed or reordered body changes nothing.
pub fn check_next_seq(stored: u64, seq: u64) -> Result<(), Refusal> {
    if stored.checked_add(1) == Some(seq) {
        Ok(())
    } else {
        Err(Refusal::conflict(format!(
            "registry body seq {seq} is not the namespace's next ({})",
            stored.saturating_add(1)
        )))
    }
}

/// Refuse a consumed state: 409 whatever the circuit or inputs, naming the
/// consuming circuit's vk_hash when it is not `circuit`, the requesting
/// circuit's. The refusal never names the consuming request: its id is
/// what scopes FETCH of that round's proof and outputs, so it goes to the
/// node's log only.
pub fn check_consumed<R: StoreRead + ?Sized>(
    read: &R,
    namespace: Fr,
    note_hash: Fr,
    circuit: Fr,
) -> Result<(), Refusal> {
    let Some(row) = read.consumed(namespace, note_hash)? else {
        return Ok(());
    };
    tracing::info!(
        consumed_by = %row.request_id,
        note_hash = %fr_to_hex(note_hash),
        "refused: state already consumed"
    );
    let by = if row.circuit == circuit {
        String::new()
    } else {
        format!(" by another circuit (vk_hash {})", fr_to_hex(row.circuit))
    };
    Err(Refusal::conflict(format!(
        "state {} is already consumed{by}; a retry of the consuming round uses FETCH",
        fr_to_hex(note_hash),
    )))
}

// The order of one chain request id's rows is `created_at`.
// A row carrying a chain request id is committed with `created_at` at
// least one second after the latest row already carrying it
// (`chain_created_at`: the clock, or the latest plus one if the clock is
// not past it), and the commit refuses (500) a row that is not later, so
// within one chain request id `created_at` strictly increases in commit
// order and every backend finds the same latest row with one ordered
// lookup, with no commit counter of its own. The cost: a row committed in
// the same second as an earlier attempt, or after the clock stepped back,
// is dated up to that many seconds late, and is pruned that much later.
/// The `created_at` for a new row carrying `chain_request_id`: `now`, or
/// one second after the latest row carrying it if `now` is not past it.
pub fn chain_created_at<R: StoreRead + ?Sized>(
    read: &R,
    namespace: Fr,
    chain_request_id: Fr,
    now: u64,
) -> Result<u64, Refusal> {
    Ok(match read.chain_request(namespace, chain_request_id)? {
        Some(latest) if latest.created_at >= now => latest.created_at.saturating_add(1),
        _ => now,
    })
}

fn occupied(key: &str) -> Refusal {
    Refusal::conflict(format!("key `{key}`: key occupied and not loaded"))
}

// The sealed replaced vector. When a round rewrites a node-held
// row, the node seals the row it replaces (a state record with associated
// data namespace, key, old note hash and the node's own enc_pk as owner) into
// the round's `requests.sealed`, in the same commit. `values` stays one row
// per key; the old vector survives only there, for the requests retention
// window, so an operator can undo a round whose transaction can never land.
// Without it one unlandable round loses the shared state for good.
/// Stage a STORE of a node-held key: check write-requires-read-or-consumed
/// against the current row and, if the key holds a value, seal that value
/// into the transaction. Call it after the round's [`Txn::loaded`] and
/// [`Txn::consume`] calls; the commit checks everything again.
pub fn stage_store<R: StoreRead + ?Sized>(
    read: &R,
    keys: &NodeKeys,
    txn: &mut Txn,
    key: &str,
    vec: Vec<Elem>,
    note_hash: Fr,
) -> Result<(), Refusal> {
    let current = read.value(txn.namespace, key)?;
    if let Some(current) = &current {
        if !write_allowed(read, txn, key, current)? {
            return Err(occupied(key));
        }
        let c_i = record::seal(
            keys,
            txn.namespace,
            key,
            current.note_hash,
            keys.enc_pk(),
            &current.vec,
        );
        txn.sealed.push(Sealed {
            kind: SealedKind::Replaced {
                prior_request_id: current.request_id,
            },
            key: key.to_string(),
            note_hash: current.note_hash,
            c_i,
        });
    }
    txn.values.push(ValueWrite {
        key: key.to_string(),
        vec,
        note_hash,
        replaces: current.map(|c| c.note_hash),
    });
    Ok(())
}

// The operator rollback, per request. `restore(namespace,
// request_id)` undoes one committed round: it puts back every node-held
// row the round replaced (opening the sealed replaced vector, owner the
// node's enc_pk its key id names, so the vector still opens after an enc
// rotation within the grace window), deletes every row the round created,
// deletes every consumed entry the round wrote (so a client-held or
// read-only consumed state becomes loadable again and its owner
// re-presents the old record), marks every client-held record the round
// created dead (`crate::dead`: step 7 refuses it), and marks the request
// rolled back, so its FETCH answers 409. It is the one exception to the append-only consumed
// set, and it is operator-only: the
// operator asserts the round's transaction can never land (if it did land,
// the chain has nullified the restored state and any round on it fails at
// the contract). Rollbacks are a stack in reverse order of commit: the
// commit refuses (409) while a key the request wrote holds a later
// request's row, or while a later request has consumed a state this one
// created, until that later request is rolled back first. The node exposes
// this on its admin socket, never on the client API. A tip attempt's
// rollback also deletes the versions it wrote (`check_discarded_versions`).
/// Roll back `request_id` under `namespace` from its request row, and for a
/// row carrying a chain request id delete every `tip_versions` row the
/// request wrote. 404 for an unknown (or pruned) request; 409 for a request
/// already rolled back or out of order, or a version that is canonical, held
/// in blobs or built on.
pub fn restore<S: Store + ?Sized>(
    store: &S,
    keys: &NodeKeys,
    namespace: Fr,
    request_id: RequestId,
) -> Result<(), Refusal> {
    let row = store.request(namespace, request_id)?.ok_or_else(|| {
        Refusal::not_found(format!(
            "no request {request_id} under namespace {}",
            fr_to_hex(namespace)
        ))
    })?;
    if row.status == RequestStatus::RolledBack {
        return Err(Refusal::conflict(format!(
            "request {request_id} is already rolled back"
        )));
    }
    let mut restore = Vec::new();
    for entry in &row.sealed {
        let SealedKind::Replaced { prior_request_id } = entry.kind else {
            continue;
        };
        // The owner is the enc key the vector was sealed under, which its
        // key id names: an enc rotation since the commit does not stop
        // the rollback while the grace window lasts.
        let opened = record::open_own(keys, namespace, &entry.key, entry.note_hash, &entry.c_i);
        let vec = opened.map_err(|e| {
            Refusal::mpc_failure(format!(
                "store: the replaced vector of key `{}` in request {request_id} does not open: {}",
                entry.key, e.message
            ))
        })?;
        restore.push(RestoredValue {
            key: entry.key.clone(),
            vec,
            note_hash: entry.note_hash,
            prior_request_id,
        });
    }
    let mut txn = store.begin(namespace);
    if row.chain_request_id.is_some() {
        for key in store.tip_keys(namespace)? {
            for v in store.tip_versions(namespace, &key)? {
                if v.request_id != request_id {
                    continue;
                }
                if let Some(tree) = v.tree.and_then(VersionTree::clear) {
                    TreeNodes {
                        read: store,
                        key: &key,
                    }
                    .drop_version(&mut txn, tree.root)?;
                }
                txn.version(VersionWrite::Delete {
                    key: v.key,
                    commitment: v.commitment,
                });
            }
        }
    }
    txn.rollback = Some(Rollback {
        request_id,
        restore,
        delete: row.created_keys.clone(),
        dead: row.records().map(|r| r.note_hash).collect(),
    });
    store.commit(txn)
}

/// The `tip_versions` rules of a commit: no version under 0, none put
/// twice or under a commitment the key holds (a version is never
/// overwritten), and every marked or deleted version held.
fn check_versions<R: StoreRead + ?Sized>(read: &R, txn: &Txn) -> Result<(), Refusal> {
    let ns = txn.namespace;
    let internal = |why: String| Refusal::mpc_failure(format!("store: {why}"));
    let mut put = BTreeSet::new();
    for write in &txn.versions {
        match write {
            VersionWrite::Put(v) => {
                if v.commitment == Fr::from(0u64) {
                    return Err(internal(format!(
                        "key `{}`: a version under commitment 0 (0 is no state)",
                        v.key
                    )));
                }
                if !put.insert((v.key.as_str(), v.commitment))
                    || read.tip_version(ns, &v.key, v.commitment)?.is_some()
                {
                    return Err(Refusal::conflict(format!(
                        "key `{}`: a version under commitment {} is already held; a version \
                         is never overwritten",
                        v.key,
                        fr_to_hex(v.commitment)
                    )));
                }
            }
            VersionWrite::Mark {
                key, commitment, ..
            }
            | VersionWrite::Delete { key, commitment } => {
                if read.tip_version(ns, key, *commitment)?.is_none() {
                    return Err(internal(format!(
                        "key `{key}`: no version under commitment {} to update",
                        fr_to_hex(*commitment)
                    )));
                }
            }
        }
    }
    Ok(())
}

/// Every package a transaction writes belongs to a contract manifest
/// version the namespace holds after it: one the transaction writes, else
/// one of the stored ones (500 otherwise: the node assembled the
/// transaction).
fn check_package_versions<R: StoreRead + ?Sized>(read: &R, txn: &Txn) -> Result<(), Refusal> {
    if txn.packages.is_empty() {
        return Ok(());
    }
    let held: Vec<Fr> = match txn.manifests.as_slice() {
        [] => read
            .contract_manifests(txn.namespace)?
            .iter()
            .map(|m| m.manifest_hash)
            .collect(),
        written => written.iter().map(|m| m.manifest_hash).collect(),
    };
    match txn
        .packages
        .iter()
        .find(|p| !held.contains(&p.manifest_hash))
    {
        Some(p) => Err(Refusal::mpc_failure(format!(
            "store: package `{}` belongs to contract manifest {}, which the namespace does not \
             hold",
            p.name,
            fr_to_hex(p.manifest_hash)
        ))),
        None => Ok(()),
    }
}

/// The rules of a resync's import. A namespace import: the namespace is
/// not held, and the transaction writes its row, contract manifest, packages, version
/// puts, tree nodes, `values`, `consumed`, `requests` and `dead_records`
/// rows only, each version once and under a commitment other than 0,
/// each request once. A key import: the
/// namespace is held, and the transaction writes version puts and tree
/// nodes of that key only, each version once and under a commitment
/// other than 0 (the key's stored versions are deleted first).
fn check_import<R: StoreRead + ?Sized>(
    read: &R,
    txn: &Txn,
    import: &Import,
) -> Result<(), Refusal> {
    let ns = txn.namespace;
    let internal = |why: &str| Refusal::mpc_failure(format!("store: {why}"));
    let held = read.namespace(ns)?.is_some();
    let others = txn.namespace_repair.is_some()
        || txn.seq.is_some()
        || !txn.loaded.is_empty()
        || !txn.values.is_empty()
        || !txn.sealed.is_empty()
        || txn.request.is_some()
        || txn.rollback.is_some()
        || txn
            .versions
            .iter()
            .any(|w| !matches!(w, VersionWrite::Put(_)));
    match import {
        Import::Namespace => {
            if held {
                return Err(Refusal::conflict(format!(
                    "namespace {} is already held: a resync imports into a store without it",
                    fr_to_hex(ns)
                )));
            }
            check_package_versions(read, txn)?;
            let mut ids = BTreeSet::new();
            if txn.namespace_row.is_none()
                || others
                || !txn
                    .imported_requests
                    .iter()
                    .all(|r| ids.insert(r.request_id))
            {
                return Err(internal(
                    "an import writes a namespace row, a contract manifest, packages, versions, \
                     tree nodes, values, consumed, requests (each once) and dead records rows \
                     only",
                ));
            }
            check_versions(read, txn)
        }
        Import::Key(key) => {
            if !held {
                return Err(Refusal::conflict(format!(
                    "namespace {} is not held: a resync of one key imports into a store \
                     that holds its namespace",
                    fr_to_hex(ns)
                )));
            }
            let mut put = BTreeSet::new();
            let only_key = txn.versions.iter().all(|w| match w {
                VersionWrite::Put(v) => {
                    v.key == *key && v.commitment != Fr::from(0u64) && put.insert(v.commitment)
                }
                _ => false,
            }) && txn.nodes.keys().all(|(k, _)| k == key);
            if !only_key
                || others
                || txn.namespace_row.is_some()
                || !txn.manifests.is_empty()
                || !txn.packages.is_empty()
                || !txn.consumed.is_empty()
                || !txn.imported_values.is_empty()
                || !txn.imported_requests.is_empty()
                || !txn.imported_dead.is_empty()
            {
                return Err(internal(&format!(
                    "a key import writes versions (each once, none under 0) and tree nodes \
                     of key `{key}` only"
                )));
            }
            Ok(())
        }
        Import::Refresh => {
            let Some(stored) = read.namespace(ns)? else {
                return Err(Refusal::conflict(format!(
                    "namespace {} is not held: a share refresh rewrites a namespace the \
                     store holds",
                    fr_to_hex(ns)
                )));
            };
            let row = txn
                .namespace_repair
                .as_ref()
                .ok_or_else(|| internal("a share refresh carries the namespace row"))?;
            if row.owner_pubkey != stored.owner_pubkey
                || row.npk_app_hash != stored.npk_app_hash
                || row.seq != stored.seq
            {
                return Err(internal(
                    "a share refresh changes the nsk_app pair only, never the owner, the \
                     npk_app_hash or the seq",
                ));
            }
            let mut put = BTreeSet::new();
            let puts_once = txn.versions.iter().all(|w| match w {
                VersionWrite::Put(v) => {
                    v.commitment != Fr::from(0u64) && put.insert((v.key.as_str(), v.commitment))
                }
                _ => false,
            });
            if !puts_once
                || txn.seq.is_some()
                || !txn.loaded.is_empty()
                || !txn.values.is_empty()
                || !txn.sealed.is_empty()
                || txn.request.is_some()
                || txn.rollback.is_some()
                || txn.namespace_row.is_some()
                || !txn.manifests.is_empty()
                || !txn.packages.is_empty()
                || !txn.consumed.is_empty()
                || !txn.imported_requests.is_empty()
                || !txn.imported_dead.is_empty()
            {
                return Err(internal(
                    "a share refresh writes the nsk_app pair, versions (each once, none \
                     under 0), tree nodes and values rows only",
                ));
            }
            Ok(())
        }
    }
}

/// Every rule a commit must pass, checked against `read` (the state the
/// commit applies to). Refusals: 409 for a namespace registered twice, a
/// reused request id (but a rerun of a rolled-back tip attempt,
/// [`Txn::rerun`]), a consumed state, a key occupied and not loaded or
/// changed since staged, a rollback out of order or of a tip version it
/// may not delete; 404 for DISABLE of an
/// unknown circuit; 400 for a key stored twice in one round; 500 for a
/// transaction the node assembled inconsistently.
pub fn check_commit<R: StoreRead + ?Sized>(read: &R, txn: &Txn) -> Result<(), Refusal> {
    let ns = txn.namespace;
    let internal = |why: &str| Refusal::mpc_failure(format!("store: {why}"));

    if let Some(import) = &txn.import {
        return check_import(read, txn, import);
    }
    if !txn.imported_values.is_empty()
        || !txn.imported_requests.is_empty()
        || !txn.imported_dead.is_empty()
    {
        return Err(internal(
            "values, requests and dead records rows are imported by a namespace import only",
        ));
    }
    if let Some(row) = &txn.namespace_row {
        if read.namespace(ns)?.is_some() {
            return Err(Refusal::conflict(format!(
                "namespace {} is already registered: its owner and nsk_app are written once",
                fr_to_hex(ns)
            )));
        }
        if row.seq != 0 || txn.seq.is_some() {
            return Err(Refusal::conflict(
                "the first REGISTER of a namespace carries seq 0",
            ));
        }
    }
    if let Some(row) = &txn.namespace_repair {
        let refuse = |why: &str| {
            Refusal::conflict(format!(
                "namespace {}: a repeated first REGISTER {why}",
                fr_to_hex(ns)
            ))
        };
        let stored = read
            .namespace(ns)?
            .ok_or_else(|| refuse("needs the stored namespace row"))?;
        if txn.namespace_row.is_some() || txn.seq.is_some() || row.seq != 0 {
            return Err(internal("a repair carries seq 0 and nothing else"));
        }
        if stored.seq != 0 {
            return Err(refuse(&format!(
                "is accepted only while the stored seq is 0, not {}",
                stored.seq
            )));
        }
        if stored.owner_pubkey != row.owner_pubkey || stored.npk_app_hash != row.npk_app_hash {
            return Err(refuse("must keep the stored owner and npk_app_hash"));
        }
    }
    if let Some(seq) = txn.seq {
        let stored = read.namespace(ns)?.ok_or_else(|| {
            Refusal::conflict(format!(
                "namespace {} is not registered; its first REGISTER carries seq 0",
                fr_to_hex(ns)
            ))
        })?;
        check_next_seq(stored.seq, seq)?;
    }
    if !txn.manifests.is_empty() && txn.namespace_row.is_none() && read.namespace(ns)?.is_none() {
        return Err(internal(
            "a contract manifest is written with its namespace row or under a held namespace",
        ));
    }
    check_package_versions(read, txn)?;

    // Marks and deletes of held versions alone are the prune pass's
    // commit, which carries no request row.
    let round_writes = !txn.consumed.is_empty()
        || !txn.values.is_empty()
        || !txn.sealed.is_empty()
        || txn
            .versions
            .iter()
            .any(|w| matches!(w, VersionWrite::Put(_)));
    match &txn.request {
        Some(request) => {
            match (read.request(ns, request.request_id)?, txn.rerun) {
                (None, false) => {}
                (Some(row), true) if row.reruns(request.body_hash, request.chain_request_id) => {}
                (Some(_), false) => {
                    return Err(Refusal::conflict(format!(
                        "request id {} is already used under this namespace",
                        request.request_id
                    )));
                }
                (_, true) => {
                    return Err(Refusal::conflict(format!(
                        "request {} no longer holds the rolled-back attempt with this body that \
                         the round runs again",
                        request.request_id
                    )));
                }
            }
            if txn
                .consumed
                .iter()
                .any(|c| c.request_id != request.request_id)
            {
                return Err(internal("a consumed row names another request"));
            }
            if let Some(chain) = request.chain_request_id
                && let Some(latest) = read.chain_request(ns, chain)?
                && latest.created_at >= request.created_at
            {
                return Err(internal(&format!(
                    "request {} for chain request id {} is not later than its latest row {}",
                    request.request_id,
                    fr_to_hex(chain),
                    latest.request_id
                )));
            }
        }
        None if round_writes || txn.rerun => {
            return Err(internal("a round's writes need its request row"));
        }
        None => {}
    }

    let mut seen = BTreeSet::new();
    for row in &txn.consumed {
        if !seen.insert(row.note_hash) {
            return Err(Refusal::conflict(format!(
                "state {} is consumed twice in one round",
                fr_to_hex(row.note_hash)
            )));
        }
        check_consumed(read, ns, row.note_hash, row.circuit)?;
    }

    // No round may store a state that is consumed, in the store or by
    // this round itself (a total circuit re-randomises its note instead).
    let new_states = txn.values.iter().map(|w| (&w.key, w.note_hash)).chain(
        txn.sealed
            .iter()
            .filter(|s| s.kind == SealedKind::Record)
            .map(|s| (&s.key, s.note_hash)),
    );
    for (key, note_hash) in new_states {
        if txn.consumed.iter().any(|c| c.note_hash == note_hash)
            || read.consumed(ns, note_hash)?.is_some()
        {
            return Err(Refusal::conflict(format!(
                "key `{key}`: the round stores state {}, which is consumed",
                fr_to_hex(note_hash)
            )));
        }
    }

    check_versions(read, txn)?;

    let mut stored = BTreeSet::new();
    for write in &txn.values {
        if !stored.insert(write.key.as_str()) {
            return Err(Refusal::bad_request(format!(
                "key `{}` is stored twice in one round",
                write.key
            )));
        }
        let current = read.value(ns, &write.key)?;
        if write.replaces != current.as_ref().map(|c| c.note_hash) {
            return Err(Refusal::conflict(format!(
                "key `{}` changed since the round read it",
                write.key
            )));
        }
        if let Some(current) = current {
            if !write_allowed(read, txn, &write.key, &current)? {
                return Err(occupied(&write.key));
            }
            let sealed = txn.sealed.iter().any(|s| {
                s.key == write.key
                    && s.note_hash == current.note_hash
                    && matches!(s.kind, SealedKind::Replaced { prior_request_id }
                        if prior_request_id == current.request_id)
            });
            if !sealed {
                return Err(internal(&format!(
                    "the replaced value of key `{}` is not sealed into the request row",
                    write.key
                )));
            }
        }
    }

    if let Some(rollback) = &txn.rollback {
        if round_writes || txn.request.is_some() {
            return Err(internal("a rollback is a transaction of its own"));
        }
        let id = rollback.request_id;
        let row = read
            .request(ns, id)?
            .ok_or_else(|| Refusal::not_found(format!("no request {id} to roll back")))?;
        if row.status == RequestStatus::RolledBack {
            return Err(Refusal::conflict(format!(
                "request {id} is already rolled back"
            )));
        }
        let mut touched: BTreeSet<&str> = rollback.restore.iter().map(|r| r.key.as_str()).collect();
        touched.extend(rollback.delete.iter().map(String::as_str));
        let stored: BTreeSet<&str> = row.stored_keys.iter().map(String::as_str).collect();
        if touched != stored {
            return Err(internal(&format!(
                "the rollback of request {id} does not cover exactly the keys it stored"
            )));
        }
        let later = |what: String, by: RequestId| {
            Refusal::conflict(format!(
                "{what} after request {id} (by request {by}); roll that request back first"
            ))
        };
        let mut created = Vec::new();
        for key in &row.stored_keys {
            match read.value(ns, key)? {
                Some(current) if current.request_id == id => created.push(current.note_hash),
                Some(current) => {
                    return Err(later(
                        format!("key `{key}` was rewritten"),
                        current.request_id,
                    ));
                }
                None => {
                    return Err(internal(&format!(
                        "key `{key}` holds no value to roll back"
                    )));
                }
            }
        }
        created.extend(row.records().map(|r| r.note_hash));
        for note_hash in created {
            if let Some(c) = read.consumed(ns, note_hash)?
                && c.request_id != id
            {
                return Err(later(
                    format!("state {} was consumed", fr_to_hex(note_hash)),
                    c.request_id,
                ));
            }
        }
        check_discarded_versions(read, txn, &row, later)?;
    }
    Ok(())
}

// The rollback of a tip attempt. A round at the tip commits at each node
// on its own, so an attempt can be committed at one or two nodes only (a
// node stopped or timed out between the commits). Its machine request id
// is fixed by the chain request id, the old commitments and the pinned
// values, so every resend is the same request: the nodes that hold the row
// replay it and the third, which cannot run the round alone, refuses at the
// handshake, until the entry is skipped. The operator's rollback of the
// row at the nodes that hold it discards the attempt: it deletes every
// `tip_versions` row the request wrote (with the tree nodes only those
// versions reached) and keeps the row as `rolled_back`, which the chain
// verifier's first-attempt rule still counts as an attempt of the entry;
// step 5 then treats the row as absent for a resend with the same body,
// whose commit replaces it ([`RequestRow::reruns`]). Such an attempt can
// never land: `process_result` needs the three result signatures, and a
// node signs only after it commits, so a node that lacks the row never
// signed. The node cannot see that the other nodes lack the row; the
// operator checks it (DESIGN.md, the rollback) and the node refuses (409)
// what it can see: a version its slot holds at this node's chain view
// (canonical: the attempt landed), a version another kept version builds
// on (roll that one back first), and a version held in blobs (the oblivious
// tree: a rollback cannot put back its DORAM state; the key is resynced
// from the neighbours instead).
/// The version deletes of a rollback: each a `tip_versions` row of the
/// rolled-back request `row`, which must carry a chain request id; refused
/// (409) for a canonical version, one held in blobs, or one a kept version
/// builds on. The tree-node writes are of the deleted versions' keys only.
fn check_discarded_versions<R: StoreRead + ?Sized>(
    read: &R,
    txn: &Txn,
    row: &RequestRow,
    later: impl Fn(String, RequestId) -> Refusal,
) -> Result<(), Refusal> {
    let (ns, id) = (txn.namespace, row.request_id);
    let internal = |why: String| Refusal::mpc_failure(format!("store: {why}"));
    let mut deleted = BTreeSet::new();
    for write in &txn.versions {
        let VersionWrite::Delete { key, commitment } = write else {
            return Err(internal(format!(
                "the rollback of request {id} writes a version other than a delete"
            )));
        };
        let held = read.tip_version(ns, key, *commitment)?;
        let Some(v) = held.filter(|v| v.request_id == id && row.chain_request_id.is_some()) else {
            return Err(internal(format!(
                "the rollback of request {id} deletes a version it did not write"
            )));
        };
        let at = format!("key `{key}`: version {}", fr_to_hex(*commitment));
        if v.status == VersionStatus::Canonical {
            return Err(Refusal::conflict(format!(
                "{at} of request {id} is the commitment the slot holds in this node's chain \
                 view: the attempt landed, and a landed attempt is never rolled back"
            )));
        }
        if matches!(v.tree, Some(VersionTree::Blobs { .. })) {
            return Err(Refusal::conflict(format!(
                "{at} of request {id} is held in blobs (an oblivious tree), whose state a \
                 rollback cannot put back: resync the key from the two neighbours instead"
            )));
        }
        deleted.insert((key.as_str(), *commitment));
    }
    for &(key, commitment) in &deleted {
        for v in read.tip_versions(ns, key)? {
            if v.parent == commitment && !deleted.contains(&(key, v.commitment)) {
                return Err(later(
                    format!(
                        "key `{key}`: version {} was built on version {}",
                        fr_to_hex(v.commitment),
                        fr_to_hex(commitment)
                    ),
                    v.request_id,
                ));
            }
        }
    }
    if !txn.blobs.is_empty()
        || txn
            .nodes
            .keys()
            .any(|(k, _)| !deleted.iter().any(|(d, _)| d == k))
    {
        return Err(internal(format!(
            "the rollback of request {id} writes tree nodes or blobs of no version it deletes"
        )));
    }
    Ok(())
}
