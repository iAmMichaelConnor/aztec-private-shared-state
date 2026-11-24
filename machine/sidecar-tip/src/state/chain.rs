//! Chain-held state (the state mode `chain`, queued intakes only), in one
//! module: a record the nodes seal to their own `enc` keys (owner
//! `enc_pk_i`), which `apply_round` logs and the scheduler hands back to the
//! next round. It is the option for small fixed-size states: the whole state
//! of a round fits one public log.
//!
//! - [`ChainSealed`]: sidecar-core's [`StateHolder`] for the mode (step 8
//!   opens the node's own third, step 13 seals the new value to the node
//!   itself, REGISTER bounds the size); its entry in the tip-mode table
//!   ([`crate::state::TIP_MODES`]) pairs it with [`ChainTip`].
//! - [`ChainTip`]: the [`TipState`] for the mode. The scheduler reloads a
//!   slot's record from the sealed-thirds log of the apply that wrote it
//!   ([`RELOAD_LOOKBACK`]) and pipelines on a result's records; a request
//!   carries the record; the chain verifier accepts a record under the slot's
//!   commitment or the new commitment of this node's pending result.
//! - The REGISTER size bound: [`check_chain_size`] over the apply log's
//!   size ([`apply_log_fields`], [`sealed_thirds_fields`]) against Aztec v6's
//!   one public log ([`MAX_PUBLIC_LOG_SIZE_IN_FIELDS`]).
//! - The apply log's codec ([`SealedLog`]), its read ([`SealedState`]
//!   over the logs under [`sealed_log_tag`]) and its decoding into the state records
//!   a queued request carries ([`SealedRecord`],
//!   [`TipManifest::sealed_records`]). Nothing here opens a third but the
//!   holder at the node that sealed it.

use std::sync::Arc;

use sidecar_core::bind::Elem;
use sidecar_core::error::Refusal;
use sidecar_core::field::{FieldHex, Fr, HexBytes, fr_to_be_bytes, fr_to_hex};
use sidecar_core::manifest::{KeyRef, Manifest, Output, StateMode};
use sidecar_core::record::{self, KEY_ID_LEN, record_hash, third_fields};
use sidecar_core::request::{NODES, NodeStateRecord, StateRecord};
use sidecar_core::response::{ExecuteResponse, ResultRecord};
use sidecar_core::state::{Held, RoundEntries, StateCtx, StateHolder};
use sidecar_core::store::Txn;

use crate::TipManifest;
use crate::chain::layout::compute_log_tag;
use crate::chain::{LogRef, TaggedLogs};
use crate::state::{KeyState, ReloadError, TipCheck, TipFuture, TipHistory, TipState, request_key};
use crate::synth::TipPackage;
use crate::verifier::refused;

// ---------------------------------------------------------------------------
// The holder
// ---------------------------------------------------------------------------

/// The state mode `chain`: the request carries the state as a record each
/// node sealed to itself (no requester signs for it), the round seals the
/// new value to the node again, and REGISTER refuses a state whose apply log
/// does not fit one public log ([`check_chain_size`]).
pub struct ChainSealed;

impl StateHolder for ChainSealed {
    fn noun(&self) -> &'static str {
        "chain-held"
    }

    fn check_manifest(&self, manifest: &Manifest, _keys: &[KeyRef]) -> Result<(), Refusal> {
        check_chain_size(manifest)
    }

    fn note_hash(&self, at: &StateCtx<'_>, key: &str) -> Result<Option<Fr>, Refusal> {
        Ok(at.supplied(key).map(|r| r.note_hash.fr()))
    }

    fn check_dead(&self, at: &StateCtx<'_>, key: &str) -> Result<(), Refusal> {
        at.check_supplied_dead(key)
    }

    fn load(
        &self,
        at: &StateCtx<'_>,
        keyref: KeyRef,
        key: &str,
        round: &mut RoundEntries,
    ) -> Result<Held, Refusal> {
        let record = round.open_record(at, keyref, key)?;
        let note_hash = record.note_hash.fr();
        // the machine's own record: no requester, owner enc_pk_i
        let vec = record::open_own(at.keys, at.namespace, key, note_hash, record.c_i.as_slice())?;
        Ok(Held { vec, note_hash })
    }

    fn check_supplied(&self, at: &StateCtx<'_>, round: &RoundEntries) -> Result<(), Refusal> {
        round.refuse_unopened(at, self.noun())
    }

    fn summand(&self, key: &str) -> Option<String> {
        Some(format!("record `{key}`"))
    }

    fn stage(
        &self,
        at: &StateCtx<'_>,
        _txn: &mut Txn,
        key: &str,
        vec: Vec<Elem>,
        note_hash: Fr,
        round: &mut RoundEntries,
    ) -> Result<(), Refusal> {
        // 13. seal, for this node itself (owner enc_pk_i): the record the
        // apply log carries and the next round opens at step 8
        let owner = at.keys.enc_pk();
        let c_i = record::seal(at.keys, at.namespace, key, note_hash, owner, &vec);
        round.sealed(key, note_hash, c_i);
        Ok(())
    }
}

/// The holder of a chain-held key, for the tip-mode table.
pub fn chain_sealed(_: &Manifest, _: KeyRef) -> Arc<dyn StateHolder> {
    Arc::new(ChainSealed)
}

/// The tip state of a chain-held key, for the tip-mode table.
pub fn chain_tip(_: &TipManifest, _: KeyRef) -> Arc<dyn TipState> {
    Arc::new(ChainTip)
}

// ---------------------------------------------------------------------------
// The tip state
// ---------------------------------------------------------------------------

// Operator knob: DESIGN.md, "Configuration reference" (reload lookback). A
// reload walks back at most 64 entries from the one before the head for the
// apply that wrote a slot; past that the scheduler stops for the namespace.
/// The most queue entries a reload walks back.
pub const RELOAD_LOOKBACK: u64 = 64;

/// The record of `key` under `commitment` in the sealed-thirds log that the
/// apply (or the init) of chain request `chain` emitted, if it holds one.
async fn logged_state(
    history: &dyn TipHistory,
    chain: Fr,
    key: &str,
    commitment: Fr,
) -> Result<Option<KeyState>, ReloadError> {
    let logs = history.logs(sealed_log_tag(chain)).await?;
    let Some(log) = SealedState::latest(chain, logs) else {
        return Ok(None);
    };
    let Some((pkg, state_keys)) = history.package(chain).await else {
        return Ok(None);
    };
    let Ok(records) = pkg.tip.sealed_records(&log.fields) else {
        tracing::warn!(chain_request_id = %fr_to_hex(chain), circuit = %pkg.name, "scheduler: a sealed-thirds log does not decode");
        return Ok(None);
    };
    for record in records {
        let written = match record.key {
            KeyRef::Write(_) => request_key(&state_keys, record.key),
            _ => None,
        };
        if written == Some(key)
            && record.note_hash == commitment
            && let Ok(state) = record.state_record(key)
        {
            return Ok(Some(key_state(state)));
        }
    }
    Ok(None)
}

/// The state mode `chain` at the tip: a key's state is the record each node
/// sealed to itself, which a request carries. The scheduler reloads it from
/// the sealed-thirds log of the apply that wrote the slot, or takes it from
/// the result of the attempt before (not yet logged); the chain verifier
/// accepts a record whose note hash is the slot's commitment, or the new
/// commitment for the key of this node's pending result before it.
pub struct ChainTip;

impl TipState for ChainTip {
    fn reload<'a>(
        &'a self,
        history: &'a dyn TipHistory,
        key: &'a str,
        commitment: Fr,
    ) -> TipFuture<'a, Result<KeyState, ReloadError>> {
        Box::pin(async move {
            let head = history.head();
            let stop = head.saturating_sub(RELOAD_LOOKBACK);
            for index in (stop..head).rev() {
                let Some(chain) = history.applied(index).await? else {
                    continue;
                };
                if let Some(state) = logged_state(history, chain, key, commitment).await? {
                    return Ok(state);
                }
            }
            // a slot the init round wrote, with no apply since
            if let Some(init) = history.init()
                && let Some(state) = logged_state(history, init, key, commitment).await?
            {
                return Ok(state);
            }
            Err(ReloadError::Missing(format!(
                "no apply within {RELOAD_LOOKBACK} entries before the head, nor the init round, \
                 logged a record of it"
            )))
        })
    }

    fn advance(
        &self,
        _package: &TipPackage,
        _store: KeyRef,
        key: &str,
        response: &ExecuteResponse,
    ) -> Result<Option<KeyState>, Refusal> {
        response
            .records
            .iter()
            .find(|r| r.key == key)
            .map(|r| result_record(r).map(key_state))
            .transpose()
    }

    fn check(&self, at: &TipCheck<'_>) -> Result<KeyState, Refusal> {
        let slot = at.slot;
        let record = at
            .req
            .records
            .iter()
            .find(|r| r.key == slot.key)
            .ok_or_else(|| {
                refused(format!(
                    "the request carries no state record for `{}`, a commitment slot of \
                     circuit `{}`",
                    slot.key, at.package.name
                ))
            })?;
        let note_hash = record.note_hash.fr();
        let from_pending = at.pending.is_some_and(|row| {
            row.records()
                .any(|s| s.key == slot.key && s.note_hash == note_hash)
        });
        if note_hash != slot.commitment && !from_pending {
            let pending_note = match (at.pending, &at.previous) {
                (Some(_), Some(p)) => format!(
                    ", nor the new commitment of this node's result for the pending entry {} \
                     before it",
                    p.index
                ),
                (_, Some(p)) if p.done != 0 => format!(
                    " (entry {} before it is no longer pending: done = {})",
                    p.index, p.done
                ),
                (_, Some(p)) => format!(
                    " (this node holds no committed result for entry {} before it)",
                    p.index
                ),
                (_, None) => String::new(),
            };
            return Err(refused(format!(
                "stale state record for `{}`: its note hash {} is not the commitment {} its slot \
                 holds at block {}{pending_note}",
                slot.key,
                record.note_hash,
                fr_to_hex(slot.commitment),
                at.block
            )));
        }
        Ok(key_state(own_record(record, at.node)))
    }
}

/// A record as the state of its key: the commitment is its note hash.
pub fn key_state(record: StateRecord) -> KeyState {
    KeyState {
        key: record.key.clone(),
        commitment: record.note_hash.fr(),
        record: Some(record),
    }
}

/// The state every record of a result leaves, as the next round carries it
/// (what [`ChainTip`]'s `advance` gives each key, for tests that hold a
/// result without its package).
#[cfg(any(test, feature = "test-util"))]
pub fn next_states(response: &ExecuteResponse) -> Result<Vec<KeyState>, Refusal> {
    response
        .records
        .iter()
        .map(|r| result_record(r).map(key_state))
        .collect()
}

/// A result's record as the next request carries it, with its three record
/// hashes.
fn result_record(r: &ResultRecord) -> Result<StateRecord, Refusal> {
    let mut record_hashes = [FieldHex(Fr::from(0u64)); NODES];
    for (i, c_i) in r.c.iter().enumerate() {
        record_hashes[i] = FieldHex(record_hash(c_i.as_slice())?);
    }
    Ok(StateRecord {
        key: r.key.clone(),
        note_hash: r.note_hash,
        c: r.c.clone(),
        record_hashes,
    })
}

/// A received record as synthesis takes it: node `node`'s third in its
/// place (the others are not this node's to see; the projection drops them).
fn own_record(record: &NodeStateRecord, node: usize) -> StateRecord {
    let mut c: [HexBytes; NODES] = Default::default();
    c[node] = record.c_i.clone();
    StateRecord {
        key: record.key.clone(),
        note_hash: record.note_hash,
        c,
        record_hashes: record.record_hashes,
    }
}

// ---------------------------------------------------------------------------
// The REGISTER size bound
// ---------------------------------------------------------------------------

/// Aztec v6's public-log payload of one transaction, in fields: every public
/// log the transaction emits, each behind its [`PUBLIC_LOG_HEADER_LENGTH`]
/// header, shares it (protocol types `constants.nr`,
/// `FLAT_PUBLIC_LOGS_PAYLOAD_LENGTH`, the payload of `PublicLogs`).
pub const FLAT_PUBLIC_LOGS_PAYLOAD_LENGTH: usize = 4096;

/// The fields Aztec v6 puts before each public log in that payload, its length
/// and the emitting contract's address (`PUBLIC_LOG_HEADER_LENGTH`).
pub const PUBLIC_LOG_HEADER_LENGTH: usize = 2;

/// The most fields one public log carries, its tag included: 4,096 − 2 =
/// 4,094 (`MAX_PUBLIC_LOG_SIZE_IN_FIELDS`). The bound on a chain-held round's
/// sealed-thirds log.
pub const MAX_PUBLIC_LOG_SIZE_IN_FIELDS: usize =
    FLAT_PUBLIC_LOGS_PAYLOAD_LENGTH - PUBLIC_LOG_HEADER_LENGTH;

/// The tag field the sealed-thirds log starts with
/// (`compute_log_tag(request_id, PSS_STATE)`).
pub const APPLY_LOG_TAG_FIELDS: usize = 1;

// The chain-held size bound is the size of the sealed-thirds log
// the contract library emits (noir/pss_public_contract,
// chain_state.nr `emit_state_log`), checked against Aztec v6's limit on one
// public log. The log is the tag, the W new commitments (one per output)
// and the three sealed thirds of every
// chain-held output, and the thirds are the record seal of sidecar-core's
// `record` unchanged: each node's third of a stored vector of n elements takes
// `record::third_fields_len(n)` = 3n + 5 fields (the key id, the three-field header,
// three fields per shared element, the tag), so the three thirds of one output
// take 9n + 15. REGISTER refuses (400) a manifest whose log,
// 1 + W + 9 · sum(n) + 15 · T over its T chain-held outputs, exceeds
// MAX_PUBLIC_LOG_SIZE_IN_FIELDS = FLAT_PUBLIC_LOGS_PAYLOAD_LENGTH (4,096) −
// PUBLIC_LOG_HEADER_LENGTH (2) = 4,094 fields (v6 protocol types
// constants.nr: every public log of a transaction, behind its 2-field header,
// comes out of one 4,096-field payload, so no log is longer). One output
// (W = T = 1) holds at most 453 elements (2 + 4,077 + 15 = 4,094); three hold
// at most 449 together (4 + 4,041 + 45 = 4,090; three of 150 take 4,099).
// `len` counts every stored element, blinding included, and every element is
// counted as shared, since the manifest does not say which are public. The
// count comes from the one function beside the seal, so it cannot drift from
// the layout; a leaner log encoding would raise the bound and needs a
// versioned record. The bound makes the state log fit a transaction on its
// own: any other public log of the apply transaction (an event of the app's
// hook, a fee payer's log) takes its length plus 2 header fields from the same
// 4,096, and an apply whose logs together overflow reverts on every attempt
// until the head is skipped, so an app that logs beside its state keeps the
// state that much under the bound. Raising the count refuses manifests
// REGISTER accepts; lowering it accepts states whose apply cannot log them.
/// The public-log fields the three sealed thirds of one chain-held output of
/// `len` elements take: 3 × [`record::third_fields_len`]`(len)` = 9·len + 15.
pub fn sealed_thirds_fields(len: usize) -> usize {
    NODES * record::third_fields_len(len)
}

/// The fields of the sealed-thirds log one apply emits for a round of
/// `writes` outputs whose chain-held outputs hold `chain_lens` elements: the
/// tag, the `writes` new commitments and the [`sealed_thirds_fields`] of every
/// chain-held output, 1 + W + 9 · sum(n) + 15 · T; 0 for a round without a
/// chain-held output (apply emits no log then).
pub fn apply_log_fields(writes: usize, chain_lens: impl IntoIterator<Item = usize>) -> usize {
    let mut thirds = chain_lens.into_iter().map(sealed_thirds_fields).peekable();
    if thirds.peek().is_none() {
        return 0;
    }
    APPLY_LOG_TAG_FIELDS + writes + thirds.sum::<usize>()
}

/// The outputs a manifest stores under a chain-held key, in manifest order.
fn chain_outputs(manifest: &Manifest) -> impl Iterator<Item = &Output> {
    manifest
        .outputs
        .iter()
        .filter(|o| manifest.state_mode(o.store) == Some(StateMode::Chain))
}

/// The public-log fields the sealed thirds of one round take: the
/// [`sealed_thirds_fields`] of every chain-held output.
pub fn sealed_thirds_size(manifest: &Manifest) -> usize {
    chain_outputs(manifest)
        .map(|o| sealed_thirds_fields(o.len))
        .sum()
}

/// The fields of the sealed-thirds log one apply of this round emits, its
/// tag included ([`apply_log_fields`]; 0 without a chain-held output).
pub fn apply_log_size(manifest: &Manifest) -> usize {
    apply_log_fields(
        manifest.outputs.len(),
        chain_outputs(manifest).map(|o| o.len),
    )
}

/// The chain-held size bound, a REGISTER check: the sealed-thirds log of
/// one apply fits one public log, [`MAX_PUBLIC_LOG_SIZE_IN_FIELDS`] (400
/// otherwise, naming the size and the bound).
pub fn check_chain_size(manifest: &Manifest) -> Result<(), Refusal> {
    let size = apply_log_size(manifest);
    if size <= MAX_PUBLIC_LOG_SIZE_IN_FIELDS {
        return Ok(());
    }
    let lens: Vec<String> = chain_outputs(manifest)
        .map(|o| format!("{} of len {}", o.store, o.len))
        .collect();
    Err(Refusal::bad_request(format!(
        "field `outputs`: the chain-held state is too large: the sealed-thirds log of one \
         apply takes {size} fields (the tag, {} new commitment(s) and {} fields of sealed \
         thirds for {}; 9 per element plus 15 per output), over the \
         {MAX_PUBLIC_LOG_SIZE_IN_FIELDS} fields of one public log; shard the state across \
         commitment slots",
        manifest.outputs.len(),
        sealed_thirds_size(manifest),
        lens.join(", ")
    )))
}

// ---------------------------------------------------------------------------
// The apply log
// ---------------------------------------------------------------------------

/// The domain of the sealed-thirds log's tag: 0x50535302, ASCII "PSS" and
/// index 2, the value of the contract library's `PSS_STATE`
/// (pss_public_contract, chain_state.nr; the log-tag rule of
/// [`crate::chain::layout`]'s domains; testvectors/log_tags.json pins it).
pub const PSS_STATE: u32 = 0x5053_5302;

/// The tag of the sealed-thirds log that the apply of chain request
/// `request_id` emits.
pub fn sealed_log_tag(request_id: Fr) -> Fr {
    compute_log_tag(request_id, PSS_STATE)
}

/// The inverse of [`third_fields`]: the bytes `c_i` of a third the log
/// carries as `[key id, ct..., tag]`. Refuses (400) a key id that does not
/// fit [`KEY_ID_LEN`] bytes and a list shorter than a key id, one ciphertext
/// field and the tag. Whether the third opens is the sealing node's check.
pub fn third_from_fields(fields: &[Fr]) -> Result<Vec<u8>, Refusal> {
    let [key_id, rest @ ..] = fields else {
        return Err(Refusal::bad_request("a sealed third has no fields"));
    };
    if rest.len() < 2 {
        return Err(Refusal::bad_request(format!(
            "a sealed third of {} field(s) is shorter than a key id, a ciphertext field and a tag",
            fields.len()
        )));
    }
    let id = fr_to_be_bytes(*key_id);
    let (high, low) = id.split_at(id.len() - KEY_ID_LEN);
    if high.iter().any(|b| *b != 0) {
        return Err(Refusal::bad_request(format!(
            "a sealed third's key id {key_id} does not fit {KEY_ID_LEN} bytes"
        )));
    }
    let mut out = Vec::with_capacity(KEY_ID_LEN + id.len() * rest.len());
    out.extend_from_slice(low);
    for field in rest {
        out.extend(fr_to_be_bytes(*field));
    }
    Ok(out)
}

// The sealed-thirds log body, the layout
// noir/pss_public_contract's `chain_state::emit_state_log` emits
// (from `apply_round` and `apply_init`) under
// compute_log_tag(chain_request_id, PSS_STATE) and the chain reader returns
// as `SealedState.fields` (the fields after the tag):
//
//   new_commitments[0..W]                  the outputs' note hashes, manifest order
//   sealed[0][0..T], sealed[1][0..T], sealed[2][0..T]
//                                          node by node, then output by output
//   sealed[i][t] = third_fields(c_i)       [key id, ct..., tag], L fields each
//
// with W the written keys (every output), T the chain-held outputs in
// manifest order and L one length for every third (the contract's
// `chain_state::SealedThirds<T, L>` has one L). So a body of W + 3·T·L fields, L =
// record::third_fields_len(len) = 3·len + 5 for a vector of shared elements: the
// count the REGISTER size bound uses. The log is the record seal unchanged:
// no second encoding, so a third read from the log hashes to the
// `record_hashes[i]` the node signed (H(sealed_i)), and each node opens its
// own third under the note hash the log names. A leaner log needs a
// versioned record and a new contract; the contract's `emit_state_log`
// writes the same layout.
/// The sealed-thirds log of one apply, decoded: the round's new commitments
/// and, per chain-held output in manifest order, the three nodes' thirds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedLog {
    /// The outputs' note hashes, in manifest order.
    pub new_commitments: Vec<Fr>,
    /// `thirds[t][i]`: node i's third `c_i` of chain-held output t.
    pub thirds: Vec<[Vec<u8>; NODES]>,
}

impl SealedLog {
    /// The log body `apply_round` emits for this result: the new
    /// commitments, then every third's [`third_fields`] node by node, output
    /// by output. Refuses (400) a third that is not a sealed record, and
    /// thirds of different lengths (the contract has one length L).
    pub fn to_fields(&self) -> Result<Vec<Fr>, Refusal> {
        let mut out = self.new_commitments.clone();
        let mut len = None;
        for i in 0..NODES {
            for (t, thirds) in self.thirds.iter().enumerate() {
                let fields = third_fields(&thirds[i])?;
                if *len.get_or_insert(fields.len()) != fields.len() {
                    return Err(Refusal::bad_request(format!(
                        "node {i}'s third of chain-held output {t} takes {} fields, another takes {}; \
                         the log carries one length",
                        fields.len(),
                        len.unwrap_or(0)
                    )));
                }
                out.extend(fields);
            }
        }
        Ok(out)
    }

    /// Decode a log body (`SealedState.fields`) of a round with `writes`
    /// outputs, `chain_outputs` of them chain-held: the first `writes` fields
    /// are the new commitments, the rest splits into 3 × `chain_outputs`
    /// thirds of one length. Refuses (400) a body that does not split so.
    pub fn from_fields(
        fields: &[Fr],
        writes: usize,
        chain_outputs: usize,
    ) -> Result<SealedLog, Refusal> {
        let malformed = |why: String| {
            Refusal::bad_request(format!(
                "a sealed-thirds log of {} fields for {writes} output(s), {chain_outputs} chain-held: {why}",
                fields.len()
            ))
        };
        if fields.len() < writes {
            return Err(malformed("shorter than its new commitments".into()));
        }
        let (commitments, body) = fields.split_at(writes);
        let count = 3 * chain_outputs;
        if count == 0 {
            if !body.is_empty() {
                return Err(malformed("thirds of no chain-held output".into()));
            }
            return Ok(SealedLog {
                new_commitments: commitments.to_vec(),
                thirds: vec![],
            });
        }
        if body.is_empty() || !body.len().is_multiple_of(count) {
            return Err(malformed(format!(
                "{} fields of thirds do not split into {count} of one length",
                body.len()
            )));
        }
        let len = body.len() / count;
        let mut thirds: Vec<[Vec<u8>; NODES]> = vec![Default::default(); chain_outputs];
        for (k, chunk) in body.chunks(len).enumerate() {
            let (i, t) = (k / chain_outputs, k % chain_outputs);
            thirds[t][i] = third_from_fields(chunk)
                .map_err(|e| malformed(format!("node {i}'s third of output {t}: {}", e.message)))?;
        }
        Ok(SealedLog {
            new_commitments: commitments.to_vec(),
            thirds,
        })
    }
}

/// The sealed-thirds log of the apply of one chain request: its fields after
/// the tag, the three sealed thirds of the state the slot then committed to,
/// in the encoding the apply log uses ([`SealedLog`];
/// [`TipManifest::sealed_records`] turns it into request records).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedState {
    pub chain_request_id: Fr,
    pub fields: Vec<Fr>,
    pub log: LogRef,
}

impl SealedState {
    /// The sealed-thirds log of `chain_request_id` among `logs`, the logs
    /// under its tag in chain order: the latest (the reader's rule for
    /// several logs under one tag); `None` before the apply.
    pub fn latest(chain_request_id: Fr, logs: TaggedLogs) -> Option<SealedState> {
        logs.into_iter().last().map(|(fields, log)| SealedState {
            chain_request_id,
            fields,
            log,
        })
    }
}

/// One chain-held output's state as the apply log carries it: the key the
/// round stored it under, the note hash it is sealed under (the output's new
/// commitment) and node i's third in `c[i]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedRecord {
    /// The manifest's key reference of the output (`$state_keys.writes[j]`).
    pub key: KeyRef,
    pub note_hash: Fr,
    pub c: [Vec<u8>; NODES],
}

impl SealedRecord {
    /// The record as a request carries it under the request key `key` (the
    /// key the next round reads; the thirds open only under the key string
    /// they were sealed for), with the three record hashes. 400 if a third is
    /// not a sealed record.
    pub fn state_record(&self, key: &str) -> Result<StateRecord, Refusal> {
        let mut record_hashes = [FieldHex(Fr::from(0u64)); NODES];
        for (i, c_i) in self.c.iter().enumerate() {
            record_hashes[i] = FieldHex(record_hash(c_i)?);
        }
        Ok(StateRecord {
            key: key.to_string(),
            note_hash: FieldHex(self.note_hash),
            c: self.c.clone().map(HexBytes),
            record_hashes,
        })
    }
}

impl TipManifest {
    /// The public-log fields the sealed thirds of one round take.
    pub fn sealed_thirds_size(&self) -> usize {
        sealed_thirds_size(self.manifest())
    }

    /// The fields of the sealed-thirds log one apply emits, its tag included
    /// (at most one public log's [`MAX_PUBLIC_LOG_SIZE_IN_FIELDS`]: REGISTER
    /// refuses a larger manifest).
    pub fn apply_log_size(&self) -> usize {
        apply_log_size(self.manifest())
    }

    /// Decode the sealed-thirds log `fields` (a [`crate::SealedState`]'s) of a
    /// round under this manifest: one [`SealedRecord`] per chain-held output,
    /// in manifest order, each with the new commitment of its output. 400 for
    /// a log that does not have this manifest's shape.
    pub fn sealed_records(&self, fields: &[Fr]) -> Result<Vec<SealedRecord>, Refusal> {
        let outputs = &self.manifest().outputs;
        let chain: Vec<usize> = outputs
            .iter()
            .enumerate()
            .filter(|(_, o)| self.state_mode(o.store) == Some(StateMode::Chain))
            .map(|(k, _)| k)
            .collect();
        let log = SealedLog::from_fields(fields, outputs.len(), chain.len())?;
        Ok(chain
            .into_iter()
            .zip(log.thirds)
            .map(|(k, c)| SealedRecord {
                key: outputs[k].store,
                note_hash: log.new_commitments[k],
                c,
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};
    use sidecar_core::ErrorClass;
    use sidecar_core::bind::Share;
    use sidecar_core::error::parse_json;
    use sidecar_core::keys::NodeKeys;
    use sidecar_core::record::third_fields_len;
    use sidecar_core::state::StateHolders;

    use crate::state::holders;

    use super::*;

    const AMM_SWAP_TIP: &str = include_str!("../../../../testvectors/manifests/amm_swap_tip.json");

    fn keys(i: u64) -> NodeKeys {
        use ark_std::rand::SeedableRng;
        NodeKeys::generate(&mut ark_std::rand::rngs::StdRng::seed_from_u64(70 + i))
    }

    fn amm_swap_tip() -> Value {
        serde_json::from_str(AMM_SWAP_TIP).unwrap()
    }

    // A known answer from aztec.js 6.0.0 (`computeLogTag` of
    // @aztec-labs/stdlib/hash), and testvectors/log_tags.json, which the
    // Noir side and pss-client check too: the domain and the tags aztec.js
    // computed with it.
    #[test]
    fn the_sealed_log_tag_is_the_vector_files() {
        use sidecar_core::field::fr_from_hex;
        assert_eq!(
            fr_to_hex(sealed_log_tag(Fr::from(0xa1u64))),
            "0x259ea36028d558d9c5b79fd56007a1684164f271f1d087f2779911190666ac61"
        );
        assert_eq!(PSS_STATE.to_be_bytes(), *b"PSS\x02");
        let file: Value =
            serde_json::from_str(include_str!("../../../../testvectors/log_tags.json")).unwrap();
        assert_eq!(file["pss_state"], u64::from(PSS_STATE));
        for v in file["vectors"].as_array().unwrap() {
            let id = fr_from_hex(v["chain_request_id"].as_str().unwrap()).unwrap();
            assert_eq!(fr_to_hex(sealed_log_tag(id)), v["sealed_tag"]);
        }
    }

    fn tip(v: &Value) -> Manifest {
        let m = Manifest::parse(v).unwrap();
        assert!(m.queued(), "intake {}", m.intake.as_str());
        m
    }

    /// The log body is `new_commitments ‖ sealed[0][..] ‖ sealed[1][..] ‖
    /// sealed[2][..]`, node-major as the contract's `[[[Field; L]; T]; 3]`,
    /// and decodes back to the same thirds.
    #[test]
    fn the_sealed_log_round_trips_node_major() {
        let shared = |seed: u64| -> Vec<Elem> {
            (0..2)
                .map(|k| Elem::Shared(Share::new(Fr::from(seed + k), Fr::from(seed + k + 7))))
                .collect()
        };
        let (ns, keyname) = (Fr::from(0x1f2eu64), "0xa002");
        let thirds: Vec<[Vec<u8>; 3]> = (0..2u64)
            .map(|t| {
                [0, 1, 2].map(|i| {
                    record::seal(
                        &keys(i),
                        ns,
                        keyname,
                        Fr::from(40 + t),
                        keys(i).enc_pk(),
                        &shared(t),
                    )
                })
            })
            .collect();
        let log = SealedLog {
            new_commitments: vec![Fr::from(40u64), Fr::from(41u64)],
            thirds: thirds.clone(),
        };
        let fields = log.to_fields().unwrap();
        let l = third_fields_len(2);
        assert_eq!(fields.len(), 2 + 3 * 2 * l);
        assert_eq!(fields[..2], [Fr::from(40u64), Fr::from(41u64)]);
        // node 0 output 1 sits right after node 0 output 0
        assert_eq!(
            fields[2 + l..2 + 2 * l],
            third_fields(&thirds[1][0]).unwrap()[..]
        );
        assert_eq!(
            fields[2 + 2 * l..2 + 3 * l],
            third_fields(&thirds[0][1]).unwrap()[..]
        );
        assert_eq!(SealedLog::from_fields(&fields, 2, 2).unwrap(), log);
        // each node opens its own third from the log
        let back = SealedLog::from_fields(&fields, 2, 2).unwrap();
        for i in 0..3 {
            let opened = record::open_own(
                &keys(i as u64),
                ns,
                keyname,
                Fr::from(41u64),
                &back.thirds[1][i],
            );
            assert_eq!(opened.unwrap(), shared(1));
        }
        // a body that does not split, or that is too short, is refused
        assert!(SealedLog::from_fields(&fields[..fields.len() - 1], 2, 2).is_err());
        assert!(SealedLog::from_fields(&fields[..1], 2, 2).is_err());
        assert!(SealedLog::from_fields(&fields, 2, 0).is_err());
        let none = SealedLog::from_fields(&fields[..2], 2, 0).unwrap();
        assert!(none.thirds.is_empty());
        // thirds of two lengths are refused in one sentence: the contract has
        // one length L
        let mut uneven = log.clone();
        uneven.thirds[1][0] = record::seal(
            &keys(0),
            ns,
            keyname,
            Fr::from(41u64),
            keys(0).enc_pk(),
            &shared(1)[..1],
        );
        assert_eq!(
            uneven.to_fields().unwrap_err().message,
            format!(
                "node 0's third of chain-held output 1 takes {} fields, another takes {l}; the \
                 log carries one length",
                third_fields_len(1)
            )
        );
    }

    /// `third_from_fields` inverts `third_fields`, and refuses a key id wider
    /// than its 8 bytes and a third too short to hold a ciphertext field and
    /// a tag.
    #[test]
    fn third_from_fields_inverts_third_fields() {
        let vec: Vec<Elem> = (0..3u64)
            .map(|k| Elem::Shared(Share::new(Fr::from(k + 1), Fr::from(k + 5))))
            .collect();
        let c = record::seal(
            &keys(1),
            Fr::from(0x1f2eu64),
            "0xa002",
            Fr::from(77u64),
            keys(1).enc_pk(),
            &vec,
        );
        let fields = third_fields(&c).unwrap();
        assert_eq!(third_from_fields(&fields).unwrap(), c);
        let mut wide = fields.clone();
        wide[0] = Fr::from(u64::MAX) + Fr::from(1u64);
        assert!(third_from_fields(&wide).is_err());
        assert!(third_from_fields(&fields[..2]).is_err());
        assert!(third_from_fields(&[]).is_err());
    }

    /// The log `apply_round` emits for the amm-tip manifest (one chain-held
    /// output of 3 elements: W = T = 1, L = 3·3 + 5) decodes to the record
    /// the round sealed, which each node opens as its own.
    #[test]
    fn the_amm_tip_log_decodes_to_the_sealed_record() {
        let tip = TipManifest::from_manifest(
            &Manifest::parse(&parse_json(AMM_SWAP_TIP).unwrap()).unwrap(),
            Some(50),
        )
        .unwrap();
        let (ns, key, note_hash) = (Fr::from(0x5eu64), "0xa002", Fr::from(0xc0u64));
        let vec: Vec<Elem> = (0..3u64)
            .map(|k| Elem::Shared(Share::new(Fr::from(k + 1), Fr::from(k + 9))))
            .collect();
        let nodes = [0, 1, 2].map(keys);
        let c =
            [0, 1, 2].map(|i| record::seal(&nodes[i], ns, key, note_hash, nodes[i].enc_pk(), &vec));
        let fields = SealedLog {
            new_commitments: vec![note_hash],
            thirds: vec![c.clone()],
        }
        .to_fields()
        .unwrap();
        assert_eq!(fields.len(), 1 + 3 * third_fields_len(3));
        assert_eq!(fields.len(), 1 + tip.sealed_thirds_size());
        // the tag before the body: the size REGISTER bounds
        assert_eq!(1 + fields.len(), tip.apply_log_size());

        let records = tip.sealed_records(&fields).unwrap();
        assert_eq!(
            records,
            [SealedRecord {
                key: KeyRef::Write(0),
                note_hash,
                c: c.clone()
            }]
        );
        let request_record = records[0].state_record(key).unwrap();
        for i in 0..3 {
            assert_eq!(request_record.c[i].as_slice(), c[i].as_slice());
            assert_eq!(
                request_record.record_hashes[i].fr(),
                record_hash(&c[i]).unwrap()
            );
            let opened = record::open_own(&nodes[i], ns, key, note_hash, &c[i]).unwrap();
            assert_eq!(opened, vec);
        }
        // one field short is not this manifest's log
        assert!(tip.sealed_records(&fields[..fields.len() - 1]).is_err());
    }

    #[test]
    fn the_chain_held_size_bound_is_the_apply_log_under_one_public_log() {
        // Aztec v6: one 4,096-field payload, 2 header fields per log
        assert_eq!(FLAT_PUBLIC_LOGS_PAYLOAD_LENGTH, 4096);
        assert_eq!(PUBLIC_LOG_HEADER_LENGTH, 2);
        assert_eq!(MAX_PUBLIC_LOG_SIZE_IN_FIELDS, 4094);
        // 3 thirds of (key id + 3-field header + 3 fields per element + tag)
        assert_eq!(sealed_thirds_fields(1), 24);
        assert_eq!(sealed_thirds_fields(453), 4092);
        assert_eq!(sealed_thirds_fields(454), 4101);
        // the log: tag, W new commitments, the thirds; none without chain-held state
        assert_eq!(apply_log_fields(1, [453]), 4094);
        assert_eq!(apply_log_fields(1, [454]), 4103);
        assert_eq!(apply_log_fields(3, [150, 150, 150]), 4099);
        assert_eq!(apply_log_fields(2, []), 0);

        // the amm-tip manifest: one output of 3 elements
        let m = tip(&amm_swap_tip());
        assert_eq!(sealed_thirds_size(&m), 9 * 3 + 15);
        check_chain_size(&m).unwrap();

        // one output at the bound: accepted
        let mut v = amm_swap_tip();
        v["outputs"][0]["len"] = json!(453);
        let at = tip(&v);
        assert_eq!(sealed_thirds_size(&at), 4092);
        assert_eq!(apply_log_size(&at), 4094);
        check_chain_size(&at).unwrap();

        // one element over: refused, naming the size and the bound
        v["outputs"][0]["len"] = json!(454);
        let over = tip(&v);
        let err = check_chain_size(&over).unwrap_err();
        assert_eq!(err.class, ErrorClass::BadRequest);
        for needle in [
            "field `outputs`",
            "takes 4103 fields",
            "1 new commitment(s) and 4101 fields of sealed thirds",
            "$state_keys.writes[0] of len 454",
            "9 per element plus 15 per output",
            "over the 4094 fields of one public log",
        ] {
            assert!(
                err.message.contains(needle),
                "`{}` lacks `{needle}`",
                err.message
            );
        }

        // the bound covers every chain-held output of the round together, and
        // each output adds its new commitment: two outputs hold 451 elements
        // (2 + 1 + 9 × 451 + 2 × 15 = 4092), one more (4101) does not
        let mut v = amm_swap_tip();
        v["state_keys"]["writes"] = json!(2);
        v["state"]["$state_keys.writes[1]"] = json!("chain");
        v["outputs"][0]["len"] = json!(226);
        v["outputs"] = json!([
            v["outputs"][0].clone(),
            {"TACEO_store": "out1", "STORE": "$state_keys.writes[1]", "len": 225, "note_hash": "other_c"}
        ]);
        let two = tip(&v);
        assert_eq!(sealed_thirds_size(&two), 4089);
        assert_eq!(apply_log_size(&two), 4092);
        check_chain_size(&two).unwrap();
        v["outputs"][1]["len"] = json!(226);
        assert_eq!(apply_log_size(&tip(&v)), 4101);
        assert!(check_chain_size(&tip(&v)).is_err());

        // three outputs of 150 (4,095 fields of thirds, under 4,096) take 4,099
        // with the tag and the three commitments: refused; three of 149 fit
        let three = |len: usize| {
            let mut v = amm_swap_tip();
            v["state_keys"]["writes"] = json!(3);
            let mut outputs = vec![];
            for w in 0..3 {
                v["state"][format!("$state_keys.writes[{w}]")] = json!("chain");
                outputs.push(json!({"TACEO_store": format!("out{w}"),
                    "STORE": format!("$state_keys.writes[{w}]"), "len": len,
                    "note_hash": if w == 0 { "new_c".to_string() } else { format!("c{w}") }}));
            }
            v["outputs"] = json!(outputs);
            tip(&v)
        };
        let fits = three(149);
        assert_eq!(apply_log_size(&fits), 4072);
        check_chain_size(&fits).unwrap();
        let over = three(150);
        assert_eq!(sealed_thirds_size(&over), 4095);
        assert_eq!(apply_log_size(&over), 4099);
        let err = check_chain_size(&over).unwrap_err();
        assert!(err.message.contains("takes 4099 fields"), "{}", err.message);

        // a key that is not chain-held seals nothing to the log
        let mut v = amm_swap_tip();
        v["outputs"][0]["len"] = json!(454);
        v["state"]["$state_keys.writes[0]"] = json!("node");
        let node = tip(&v);
        assert_eq!(sealed_thirds_size(&node), 0);
        assert_eq!(apply_log_size(&node), 0);
        check_chain_size(&node).unwrap();
    }

    /// REGISTER's state checks under the holders of a tip machine run the
    /// chain-held size bound (400, under `manifest`); sidecar-core's holders
    /// alone serve no chain-held key.
    #[test]
    fn register_bounds_the_chain_held_state_under_one_public_log() {
        // REGISTER's state checks of one package (ManifestMessage::check_state
        // runs them per package of the contract manifest)
        let check = |manifest: Value, holders: &StateHolders| {
            holders
                .check_register(&Manifest::parse(&manifest)?)
                .map(|_| ())
        };
        let refused = |manifest: Value, needle: &str| {
            let err = check(manifest, &holders()).unwrap_err();
            assert_eq!(err.class, ErrorClass::BadRequest);
            assert!(err.message.contains(needle), "`{err}` lacks `{needle}`");
        };

        // REGISTER runs the size bound (the bound itself is
        // the_chain_held_size_bound_is_the_apply_log_under_one_public_log's)
        let mut v = amm_swap_tip();
        check(v.clone(), &holders()).unwrap();
        v["outputs"][0]["len"] = json!(454);
        refused(
            v,
            "field `manifest.outputs`: the chain-held state is too large: the sealed-thirds log of one apply takes 4103 fields",
        );

        // without this module a chain-held key is not served
        let err = check(amm_swap_tip(), &StateHolders::core()).unwrap_err();
        assert!(
            err.message.contains(
                "field `manifest.state.$state_keys.reads[0]`: the state mode `chain` is not served by this node at the tip"
            ),
            "{err}"
        );
    }

    /// The chain-held AMM swap vector (testvectors/manifests/amm_swap_tip.json)
    /// is within the bound: one chain-held output of 3 elements (9 × 3 + 15
    /// fields of thirds, behind the tag and the one new commitment). The
    /// example tip manifests (amm-tip's pool, lending's book) are node-held
    /// and log no thirds.
    #[test]
    fn the_chain_held_swap_fits_one_public_log_and_the_examples_log_none() {
        let read =
            |path: &str| Manifest::parse(&sidecar_test_fixtures::vectors::read(path)).unwrap();
        let chain = read("testvectors/manifests/amm_swap_tip.json");
        holders().check_register(&chain).unwrap();
        assert_eq!(sealed_thirds_size(&chain), 42);
        assert_eq!(apply_log_size(&chain), 44);
        assert!(apply_log_size(&chain) <= MAX_PUBLIC_LOG_SIZE_IN_FIELDS);
        let examples: [(&str, &[&str]); 2] = [
            (
                "amm-tip",
                &["amm_swap_tip", "amm_swap_tip_receipt", "amm_init_tip"],
            ),
            (
                "lending-tip",
                &["lending_init", "deposit", "deposit_receipt"],
            ),
        ];
        for (example, names) in examples {
            for name in names {
                let manifest = read(&format!("examples/{example}/manifests/{name}.json"));
                holders().check_register(&manifest).unwrap();
                assert_eq!(sealed_thirds_size(&manifest), 0, "{name}");
                assert_eq!(apply_log_size(&manifest), 0, "{name}");
            }
        }
    }
}
