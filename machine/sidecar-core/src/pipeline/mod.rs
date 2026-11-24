//! The request lifecycle (ARCHITECTURE.md section 3) as one library call:
//! [`run_request`] runs steps 1 to 16 for one execute request on one node,
//! [`fetch`] answers a committed request again ([`fetch_by_chain_request_id`]
//! the latest one for a chain request id), [`restore`] is the operator's
//! per-request rollback, and [`stateless_prefix`] is the part of steps 1 to 4
//! the orchestrator runs before fan-out.
//!
//! Nothing here knows about sockets, TLS or a chain: the node's HTTPS handler
//! and the tip's scheduler call the same functions, the caller hands in the
//! mesh as a connect function, and the chain verifier is a hook the node
//! injects. Every failure before step 15 changes nothing.
//!
//! Every step is logged under a `request` span carrying the namespace, circuit
//! and request id; the library installs no subscriber.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Condvar, Mutex, PoisonError, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ark_ff::Zero;
use ark_std::rand::{CryptoRng, RngCore};
use mpc_net::Network;

use crate::abi::CircuitShape;
use crate::bind::{self, Bound, Elem, Share, Sources};
use crate::consumed::{check_consumed, consumed_rows, once_keys};
use crate::crs::{Artifact, Circuit, Crs};
use crate::error::Refusal;
use crate::executor::{self, NamespaceCheck, Rep3State, RoundOutput};
use crate::field::{FieldHex, Fr, HexBytes, RequestId, fr_to_hex};
use crate::grumpkin::{Point, point_from_wire};
use crate::handshake::{self, Handshake};
use crate::hash::poseidon2_hash;
use crate::intake::{AuthCtx, Authenticated};
use crate::keys::NodeKeys;
use crate::manifest::{KeyRef, Manifest, QueuedIntake, ShareSource};
use crate::mesh_lock::{MeshHeld, MeshLock};
use crate::record::record_hash;
use crate::register::{DisableAnswer, DisableRequest, ManifestAnswer, ManifestMessage, Signature};
use crate::registry::{self, RegisterHook, RegistryNode, Signed};
use crate::request::{ForNode, NODES, NodeRequest, Request, View};
use crate::response::{NodeResult, NodeResultRecord};
use crate::resync::{NoReceiptResync, ReceiptResyncHook};
use crate::schnorr::{sign_derived, verify};
use crate::state::{
    Holding, NodeVersions, QueueRead, RoundEntries, StateCtx, StateHolder, StateHolders,
    VersionViews,
};
use crate::store::{
    DEFAULT_REQUESTS_RETENTION_SECS, ManifestRow, NewRequest, PackageRow, ReceiptRow, RequestRow,
    RequestStatus, Store, StoreRead, TipVersion, rules,
};
use crate::tree::TreeNode;

mod node;
mod prefix;
mod result;

pub use node::*;
pub use prefix::*;
pub use result::*;

// ---------------------------------------------------------------------------
// The lifecycle
// ---------------------------------------------------------------------------

/// The binder's sources for one round: the vectors opened and read at step 8
/// by key reference, this node's envelopes, and either no randomness (the
/// step 9 check, which draws placeholder zeros) or the round's correlated
/// randomness (the step 10 bind).
struct RoundSources<'a> {
    keys: &'a NodeKeys,
    index: usize,
    req: &'a NodeRequest,
    /// Where this node's shares come from (the manifest intake's row).
    shares: ShareSource,
    loaded: &'a BTreeMap<KeyRef, Vec<Elem>>,
    shared: BTreeMap<String, Share>,
    state: Option<&'a mut Rep3State>,
}

impl Sources for RoundSources<'_> {
    fn load(&mut self, keyref: KeyRef, key: &str) -> Result<Vec<Elem>, Refusal> {
        self.loaded.get(&keyref).cloned().ok_or_else(|| {
            Refusal::mpc_failure(format!("{keyref} = `{key}` was not loaded at step 8"))
        })
    }

    fn sample(&mut self) -> Share {
        match self.state.as_deref_mut() {
            Some(state) => executor::sample_share(state),
            None => Share::default(),
        }
    }

    fn shared_input(&mut self, name: &str) -> Result<Share, Refusal> {
        if let Some(share) = self.shared.get(name) {
            return Ok(*share);
        }
        let share = self.shares.share(self.keys, self.index, self.req, name)?;
        self.shared.insert(name.to_string(), share);
        Ok(share)
    }
}

impl<'a> RoundSources<'a> {
    /// The sources of the step 9 check bind: the vectors step 8 loaded, this
    /// node's envelopes, and placeholder zeros for the samples.
    fn check<S>(
        node: &'a Node<S>,
        keys: &'a NodeKeys,
        req: &'a NodeRequest,
        shares: ShareSource,
        loaded: &'a BTreeMap<KeyRef, Vec<Elem>>,
    ) -> Self {
        RoundSources {
            keys,
            index: node.index,
            req,
            shares,
            loaded,
            shared: BTreeMap::new(),
            state: None,
        }
    }
}

/// What step 8 loaded for a round.
struct Loaded {
    /// Every vector a LOAD names, by key reference: each key's state from its
    /// holder, and the namespace's `nsk_app` share for the fixed key.
    values: BTreeMap<KeyRef, Vec<Elem>>,
    /// The note hash of each loaded state, for the consumed rows.
    note_hashes: Vec<(KeyRef, Fr)>,
    /// Each key loaded, with its request key, for steps 10 and 12
    /// ([`StateHolder::load_in_session`], [`StateHolder::mark_loaded`]).
    loads: Vec<(KeyRef, String)>,
    /// What the holders record for the round: the records step 8 opened,
    /// then the request row's entries of steps 12 and 13.
    round: RoundEntries,
    /// Step 5 found this request id's rolled-back attempt with the same
    /// body, which the round's row replaces ([`Txn::rerun`]).
    rerun: bool,
}

/// Step 8, open and load: each key's state from its holder
/// ([`StateHolder::load`]: a supplied record opened under this node's record
/// key, or this node's row), and the fixed key `nsk_app` from the namespace's
/// row (this node's share of the namespace's derived key, never the master);
/// then refuse a supplied record no holder opened
/// ([`Holding::check_supplied`]). 409 for a missing value, record or
/// nsk_app; 400 for a record that does not open or that no read uses.
fn open_and_load<S: Store>(
    node: &Node<S>,
    at: &StateCtx<'_>,
    holding: &Holding,
) -> Result<Loaded, Refusal> {
    let store = &node.store;
    let (namespace, req, manifest) = (at.namespace, at.req, at.manifest);
    let mut loaded: BTreeMap<KeyRef, Vec<Elem>> = BTreeMap::new();
    let mut loaded_note_hashes: Vec<(KeyRef, Fr)> = Vec::new();
    let mut loads = Vec::new();
    let mut round = RoundEntries::default();
    for (_, load) in manifest.loads() {
        let keyref = load.key;
        if loaded.contains_key(&keyref) {
            continue;
        }
        let key = key_of(req, keyref);
        let value = if keyref.is_fixed() {
            let share = store.load_nsk_app(namespace)?.ok_or_else(|| {
                Refusal::conflict(format!(
                    "namespace {} has no nsk_app at this node",
                    fr_to_hex(namespace)
                ))
            })?;
            vec![Elem::Shared(share)]
        } else {
            let held = holder_of(manifest, holding, keyref)?.load(at, keyref, key, &mut round)?;
            loaded_note_hashes.push((keyref, held.note_hash));
            loads.push((keyref, key.to_string()));
            held.vec
        };
        loaded.insert(keyref, value);
    }
    holding.check_supplied(at, &round)?;
    Ok(Loaded {
        values: loaded,
        note_hashes: loaded_note_hashes,
        loads,
        round,
        rerun: false,
    })
}

/// The holder of a key the manifest uses (500 for one it gives no holder).
fn holder_of<'h>(
    manifest: &Manifest,
    holding: &'h Holding,
    keyref: KeyRef,
) -> Result<&'h dyn StateHolder, Refusal> {
    holding.get(keyref).ok_or_else(|| {
        Refusal::mpc_failure(format!(
            "the manifest of `{}` gives {keyref} no state mode",
            manifest.circuit
        ))
    })
}

/// The wall-clock time of a round's parts, logged at the end of the round.
#[derive(Clone, Copy, Debug, Default)]
pub struct RoundTimings {
    /// Steps 1 to 9.
    pub prepare: Duration,
    /// Step 10: waiting for the mesh, connecting, the handshake, randomness.
    pub session: Duration,
    /// Step 11, as the executor reports it.
    pub execute: executor::Timings,
    /// Steps 12 to 15.
    pub commit: Duration,
}

/// The step a round is at, for the log.
struct Step {
    name: &'static str,
}

impl Step {
    fn at(&mut self, name: &'static str) {
        self.name = name;
        tracing::debug!(step = name, "step");
    }
}

/// Run one execute request on this node: steps 1 to 16 of ARCHITECTURE.md
/// section 3. `connect` opens the Rep3 mesh session to the other two nodes; it
/// is called at step 10, under the mesh lock, when the request passed step 1:
/// for the round, or to send as this node's handshake verdict its answer from
/// the stored row (step 5) or its refusal of steps 2 to 9.
/// Returns this node's [`NodeResult`], or the refusal of the first step that
/// failed; before step 15 nothing is stored.
pub fn run_request<S, N>(
    node: &Node<S>,
    req: NodeRequest,
    connect: impl FnOnce(&MeshHeld) -> Result<N, Refusal>,
) -> Result<NodeResult, Refusal>
where
    S: Store,
    N: Network,
{
    let span = tracing::info_span!(
        "request",
        node = node.index,
        namespace = %req.namespace,
        circuit = %req.circuit,
        request_id = %req.request_id,
    );
    let _span = span.enter();
    let start = Instant::now();
    let mut step = Step { name: "parse" };
    let result = lifecycle(node, &req, connect, &mut step);
    match &result {
        Ok(_) => tracing::info!(
            elapsed_ms = start.elapsed().as_millis() as u64,
            "request answered"
        ),
        Err(refusal) => tracing::info!(
            step = step.name,
            class = %refusal.class,
            status = refusal.status(),
            error = %refusal.message,
            elapsed_ms = start.elapsed().as_millis() as u64,
            "request refused"
        ),
    }
    result
}

fn lifecycle<S, N>(
    node: &Node<S>,
    req: &NodeRequest,
    connect: impl FnOnce(&MeshHeld) -> Result<N, Refusal>,
    step: &mut Step,
) -> Result<NodeResult, Refusal>
where
    S: Store,
    N: Network,
{
    let started = Instant::now();
    let store = &node.store;
    let namespace = req.namespace.fr();
    let i = node.index;
    let keys = node.keys();

    // 1. parse: the handler parsed the JSON; the field checks run again here
    // so a request built in code is checked too.
    step.at("parse");
    req.validate()?;
    // A node running a resync or a replacement refuses at once and joins no
    // session: the session holds the mesh and its namespaces' locks to its
    // end (`Node::maintain`).
    node.check_serving()?;

    // 2. admit. A refusal here, and at every later step before the session,
    // still joins the session (see `refuse_in_session`).
    step.at("admit");
    let body_hash = req.body_hash();
    if let Err(refusal) = (node.admit)(req) {
        return Err(refuse_in_session(node, req, body_hash, connect, refusal));
    }

    // 3 and 4: resolve and authenticate, under the namespace lock.
    step.at("resolve");
    let _namespace_lock = node.lock_namespace(namespace);
    let Resolved {
        package,
        vk_hash,
        requester,
        chain,
    } = match steps_3_and_4(node, req, step) {
        Ok(resolved) => resolved,
        Err(refusal) => return Err(refuse_in_session(node, req, body_hash, connect, refusal)),
    };
    let (manifest, shape, holding) = (&package.manifest, &package.shape, &package.holding);
    let at = StateCtx {
        store,
        keys: &keys,
        node: i,
        namespace,
        manifest,
        shape,
        req,
        requester,
        chain: chain.as_ref(),
        public_inputs: &[],
    };

    // 5 to 8: replay, own ciphertexts, consumed, open and load. A replay, or a
    // refusal here or at step 9, still joins the session (see
    // `replay_in_session` and `refuse_in_session`).
    let Loaded {
        values: mut loaded,
        note_hashes: loaded_note_hashes,
        loads,
        mut round,
        rerun,
    } = match steps_5_to_8(node, &at, holding, vk_hash, body_hash, step) {
        Ok(Prepared::Replayed(result)) => {
            return Ok(replay_in_session(node, req, body_hash, connect, *result));
        }
        Ok(Prepared::Loaded(loaded)) => loaded,
        Err(refusal) => return Err(refuse_in_session(node, req, body_hash, connect, refusal)),
    };

    // 9. bind: everything but the samples, which need the session's randomness
    // (and but the in-session loads, bound here as their zero placeholders).
    step.at("bind");
    let checked: Bound = {
        let mut sources =
            RoundSources::check(node, &keys, req, manifest.intake.share_source(), &loaded);
        match bind::bind(shape, manifest, req, &mut sources) {
            Ok(checked) => checked,
            Err(refusal) => {
                return Err(refuse_in_session(node, req, body_hash, connect, refusal));
            }
        }
    };
    let prepared = started.elapsed();

    // 10. session
    step.at("session");
    let session_start = Instant::now();
    let mesh = node.lock_mesh();
    let net = connect(&mesh)?;
    if net.id() != i {
        return Err(Refusal::mpc_failure(format!(
            "the mesh gives this node party id {}, not its index {i}",
            net.id()
        )));
    }
    let handshake = Handshake::from_bound(
        req.request_id,
        body_hash,
        shape,
        manifest,
        holding,
        &checked,
    );
    handshake::exchange(&net, &handshake)?;
    let mut state = executor::round_state(&net)?;

    // 10b. the in-session loads: a key whose holder reads it by a joint
    // protocol of the three nodes (the oblivious tree brick) is loaded now,
    // in the open session, in place of its step 8 placeholder.
    let mut in_session: BTreeSet<KeyRef> = BTreeSet::new();
    for (keyref, key) in &loads {
        let holder = holder_of(manifest, holding, *keyref)?;
        if let Some(held) = holder.load_in_session(&at, *keyref, key, &net, &mut state)? {
            loaded.insert(*keyref, held.vec);
            in_session.insert(*keyref);
        }
    }
    let mut sources = RoundSources {
        state: Some(&mut state),
        ..RoundSources::check(node, &keys, req, manifest.intake.share_source(), &loaded)
    };
    let bound = bind::bind(shape, manifest, req, &mut sources)?;
    let outside = |reads: &[bind::Read]| -> Vec<(KeyRef, String, Option<Vec<Elem>>)> {
        reads
            .iter()
            .map(|r| {
                let value = (!in_session.contains(&r.keyref)).then(|| r.value.clone());
                (r.keyref, r.key.clone(), value)
            })
            .collect()
    };
    if outside(&bound.reads) != outside(&checked.reads) || bound.samples != checked.samples {
        return Err(Refusal::mpc_failure(
            "the witness bound twice differently; nothing was stored",
        ));
    }
    let session = session_start.elapsed();

    // 11. execute and verify
    step.at("execute and verify");
    let check = NamespaceCheck {
        index: shape.namespace_index,
        namespace,
    };
    let out: RoundOutput =
        executor::execute(&package.circuit, &node.crs, bound.input, check, &net)?;
    drop(net);
    let commit_start = Instant::now();

    // 12. outputs
    step.at("outputs");
    let mut stores = out.stores;
    let names: BTreeSet<&str> = shape
        .outputs
        .iter()
        .map(|o| o.taceo_store.as_str())
        .collect();
    if let Some(extra) = stores.keys().find(|k| !names.contains(k.as_str())) {
        return Err(Refusal::mpc_failure(format!(
            "the circuit stored `{extra}`, which the manifest does not name"
        )));
    }
    let at = StateCtx {
        public_inputs: &out.public_inputs,
        ..at
    };
    let mut txn = store.begin(namespace);
    for (keyref, key) in &loads {
        holder_of(manifest, holding, *keyref)?.mark_loaded(&mut txn, key);
    }
    for row in consumed_rows(manifest, &loaded_note_hashes, vk_hash, req.request_id) {
        txn.consume(row);
    }
    let commitments = result_commitments(shape, &out.public_inputs)?;
    for (output, note_hash) in shape.outputs.iter().zip(&commitments) {
        let vec = stores.remove(&output.taceo_store).ok_or_else(|| {
            Refusal::mpc_failure(format!(
                "the circuit did not store `{}`",
                output.taceo_store
            ))
        })?;
        if vec.len() != output.len {
            return Err(Refusal::mpc_failure(format!(
                "the circuit stored {} element(s) in `{}`, the manifest says {}",
                vec.len(),
                output.taceo_store,
                output.len
            )));
        }
        let key = key_of(req, output.store);
        if txn.consumed().iter().any(|c| c.note_hash == *note_hash) {
            return Err(Refusal::conflict(format!(
                "key `{key}`: the round stores state {}, which it consumes",
                fr_to_hex(*note_hash)
            )));
        }
        check_consumed(store, namespace, *note_hash, vk_hash).map_err(|e| {
            Refusal::conflict(format!(
                "key `{key}`: the round stores a consumed state: {}",
                e.message
            ))
        })?;
        holder_of(manifest, holding, output.store)?
            .stage(&at, &mut txn, key, vec, *note_hash, &mut round)?;
    }

    // 13. seal: the record thirds the holders sealed into the request row
    // (a replaced node-held vector was sealed as it was staged).
    step.at("seal");
    let mut record_hashes = Vec::with_capacity(round.records().len());
    for (key, note_hash, c_i) in round.records() {
        record_hashes.push(record_hash(c_i)?);
        txn.add_record(key, *note_hash, c_i.clone());
    }

    // 14. sign
    step.at("sign");
    let message = result_message(
        namespace,
        req.request_id,
        &commitments,
        i,
        sealed_hash(&record_hashes),
    );
    let signature = sign_result(&keys, message);

    // 15. commit: the row carries the chain request id a queued intake's
    // request carries (step 3 refuses one under intake direct), dated by the
    // intake ([`crate::intake::IntakeRules::created_at`]).
    step.at("commit");
    let chain_request_id = req.chain_request_id.map(|c| c.0);
    let created_at = manifest
        .intake
        .rules()
        .created_at(store, namespace, req, unix_now())?;
    txn.put_request(NewRequest {
        request_id: req.request_id,
        body_hash,
        vk_hash,
        proof: out.proof.clone(),
        public_inputs: out.public_inputs.clone(),
        stored_keys: round.stored_keys().to_vec(),
        created_keys: round.created_keys().to_vec(),
        signature: Some(signature),
        created_at,
        chain_request_id,
    });
    if rerun {
        txn.rerun();
    }
    store.commit(txn)?;
    let timings = RoundTimings {
        prepare: prepared,
        session,
        execute: out.timings,
        commit: commit_start.elapsed(),
    };
    tracing::info!(
        prepare_ms = timings.prepare.as_millis() as u64,
        session_ms = timings.session.as_millis() as u64,
        witness_ms = timings.execute.witness_extension.as_millis() as u64,
        proving_key_ms = timings.execute.proving_key.as_millis() as u64,
        proof_ms = timings.execute.proof.as_millis() as u64,
        verify_ms = timings.execute.verify.as_millis() as u64,
        commit_ms = timings.commit.as_millis() as u64,
        "round committed"
    );

    // 16. respond
    step.at("respond");
    Ok(NodeResult {
        request_id: req.request_id,
        vk_hash: None,
        proof: HexBytes(out.proof),
        public_inputs: out.public_inputs.into_iter().map(FieldHex).collect(),
        stored: round.stored_keys().to_vec(),
        records: round
            .records()
            .iter()
            .map(|(key, note_hash, c_i)| NodeResultRecord {
                key: key.clone(),
                note_hash: FieldHex(*note_hash),
                c_i: HexBytes(c_i.clone()),
            })
            .collect(),
        signature,
    })
}

/// What steps 5 to 8 leave a round with: the stored answer of a replay, or
/// the loaded values.
enum Prepared {
    Replayed(Box<NodeResult>),
    Loaded(Loaded),
}

/// What steps 3 and 4 give the rest of a round.
struct Resolved {
    package: Arc<LoadedPackage>,
    /// The `packages` row's vk_hash.
    vk_hash: Fr,
    requester: Option<Point>,
    chain: Option<QueueRead>,
}

/// Steps 3 and 4, under the namespace lock: resolution (the package, absent
/// or disabled: 400; its loaded circuit; the key counts and
/// `chain_request_id` against its manifest) and the intake's authentication
/// ([`crate::intake::IntakeRules::authenticate`]: the requester signature,
/// or under a queued intake the node's chain verifier in its place).
fn steps_3_and_4<S: Store>(
    node: &Node<S>,
    req: &NodeRequest,
    step: &mut Step,
) -> Result<Resolved, Refusal> {
    let store = &node.store;
    let pkg = resolve_package(store, req)?;
    let package = node.loaded(req.namespace.fr(), &pkg)?;
    let manifest = &package.manifest;
    check_key_counts(req, manifest)?;
    check_tip_fields(req, manifest)?;

    // 4. authenticate
    step.at("authenticate");
    let Authenticated { requester, chain } = manifest.intake.rules().authenticate(&AuthCtx {
        req,
        manifest,
        shape: &package.shape,
        holding: &package.holding,
        vk_hash: pkg.vk_hash,
        manifest_hash: pkg.manifest_hash,
        rows: store,
        chain_verifier: &node.chain_verifier,
    })?;
    Ok(Resolved {
        vk_hash: pkg.vk_hash,
        package,
        requester,
        chain,
    })
}

/// Steps 5 to 8 on this node, under the namespace lock: replay, own
/// ciphertexts, consumed, open and load. None needs the mesh.
fn steps_5_to_8<S: Store>(
    node: &Node<S>,
    at: &StateCtx<'_>,
    holding: &Holding,
    vk_hash: Fr,
    body_hash: Fr,
    step: &mut Step,
) -> Result<Prepared, Refusal> {
    let store = &node.store;
    let (namespace, req, manifest) = (at.namespace, at.req, at.manifest);

    // 5. replay: a stored row is answered or refused, but a rolled-back
    // attempt at a queued request with this body runs again
    step.at("replay");
    let mut rerun = false;
    if let Some(row) = store.request(namespace, req.request_id)? {
        let chain_request_id = req.chain_request_id.map(|c| c.0);
        if !row.reruns(body_hash, chain_request_id) {
            return replay(req, &row, body_hash).map(|r| Prepared::Replayed(Box::new(r)));
        }
        tracing::info!("a rolled-back attempt with this body: the round runs again");
        rerun = true;
    }

    // 6. own ciphertexts
    step.at("own ciphertexts");
    req.check_own_ciphertexts(node.index)?;

    // 7. consumed, and a record a rolled-back round created
    step.at("consumed");
    for (keyref, holder) in holding.iter() {
        holder.check_dead(at, key_of(req, keyref))?;
    }
    for keyref in once_keys(manifest) {
        let key = key_of(req, keyref);
        let note_hash = match holding.get(keyref) {
            Some(holder) => holder.note_hash(at, key)?,
            None => None,
        };
        // A missing state is step 8's 409.
        if let Some(note_hash) = note_hash {
            check_consumed(store, namespace, note_hash, vk_hash)?;
        }
    }

    // 8. open and load
    step.at("open and load");
    let loaded = open_and_load(node, at, holding)?;
    Ok(Prepared::Loaded(Loaded { rerun, ..loaded }))
}

// A node that refuses a request at steps 2 to 9 (its admit
// hook, an unknown or disabled circuit, key counts, `chain_request_id`, the requester signature
// or the chain verifier, a replay with another body or of a rolled-back
// request, its own ciphertext hashes, a consumed state, a record or value
// that does not open or load, the check bind) still takes the mesh lock, opens the session and sends its refusal as
// its handshake verdict (`handshake::exchange_refusing`, with no summand
// hashes), the pattern of a refused `seq` 0 REGISTER. It runs no circuit and
// stores nothing, and answers its own refusal; if the mesh does not open it
// answers its own refusal after the connect timeout. The other two nodes,
// which passed those steps (their stores, or their thirds and envelopes,
// differ from this one's), then refuse 400 at the handshake, naming this node
// and its reason, within the handshake instead of waiting out the mesh
// connect timeout and answering 500. The orchestrator mirrors steps 1 to 4
// and 6 before fan-out, but cannot see what makes one node alone refuse at
// steps 2 to 9: a node's own admit hook (the orchestrator runs the default
// `admit`, so hooks that differ between nodes refuse at one node only), a
// client that replaces one third with bytes of its own
// whose hash it lists, an envelope to one node that does not open, stores
// that diverged (a rollback run on two nodes only), a registry that diverged
// (a REGISTER or DISABLE one node did not commit, which the orchestrator's
// copy, written only from three agreeing answers, does not hold either), or
// the chain verifier at step 4 under a queued intake, which only the nodes
// run (see the chain-verifier hook's comment). Without this a public
// client could hold the machine's one session for the connect timeout per
// request. The cost: a request that all three nodes refuse at those steps
// opens one mesh session (the handshake only) before it is answered, and
// waits for the mesh lock while another round holds it: an admit hook that
// refuses many requests (a quota) makes each refusal wait for the session in
// progress. From an honest orchestrator a request all three refuse at steps
// 2 to 4 arrives only when its copy is behind the nodes or the nodes' admit
// hooks refuse what the orchestrator's admits. Step 1 stays local: it reads
// only the body, and the orchestrator runs the same checks first.
/// Step 10 for a request this node refused at steps 2 to 9: take the mesh
/// lock, connect and send `refusal` as this node's verdict. Returns
/// `refusal`, whatever the session did.
fn refuse_in_session<S, N>(
    node: &Node<S>,
    req: &NodeRequest,
    body_hash: Fr,
    connect: impl FnOnce(&MeshHeld) -> Result<N, Refusal>,
    refusal: Refusal,
) -> Refusal
where
    S: Store,
    N: Network,
{
    let mesh = node.lock_mesh();
    let handshake = Handshake::build(req.request_id, body_hash, &[], &[]);
    match connect(&mesh) {
        Ok(net) => handshake::exchange_refusing(&net, &handshake, refusal),
        Err(_) => refusal,
    }
}

/// Step 10 for a request this node answered from its stored row at step 5:
/// take the mesh lock, connect and send a refusing verdict that names the
/// replay ("this node already holds the request"), as [`refuse_in_session`]
/// does. When the commit of the first attempt failed on one or two nodes,
/// those nodes lack the row, pass steps 5 to 9 and open the session; this
/// verdict makes them refuse 400 at the handshake at once, naming this node,
/// instead of waiting out the mesh connect timeout, and the refusal tells the
/// operator which stores diverged (at the tip the operator rolls the attempt
/// back at the nodes that hold it, and the next resend runs at all three:
/// [`RequestRow::reruns`]). When all three nodes replay, every verdict
/// refuses and each answers its own row: a resend costs one handshake-only
/// session. Returns `result`, whatever the session did; if the mesh does not
/// open, this node's row alone after the connect timeout.
fn replay_in_session<S, N>(
    node: &Node<S>,
    req: &NodeRequest,
    body_hash: Fr,
    connect: impl FnOnce(&MeshHeld) -> Result<N, Refusal>,
    result: NodeResult,
) -> NodeResult
where
    S: Store,
    N: Network,
{
    let verdict = Refusal::conflict(format!(
        "this node already holds request {} and answered it from its stored row",
        req.request_id
    ));
    let _ = refuse_in_session(node, req, body_hash, connect, verdict);
    result
}

/// Step 5 for a request id this namespace has seen: the same body, committed,
/// is answered from the row; another body, or a rolled-back request, is 409
/// (step 5 runs a rolled-back tip attempt with the same body again instead,
/// [`RequestRow::reruns`]).
fn replay(req: &NodeRequest, row: &RequestRow, body_hash: Fr) -> Result<NodeResult, Refusal> {
    if row.body_hash != body_hash {
        return Err(Refusal::conflict(format!(
            "request id {} is already used under this namespace with another body",
            req.request_id
        )));
    }
    tracing::info!("replay of a committed request: answered from its row");
    result_from_row(row)
}

/// A committed request row as this node's [`NodeResult`] (409 when it was
/// rolled back).
fn result_from_row(row: &RequestRow) -> Result<NodeResult, Refusal> {
    if row.status == RequestStatus::RolledBack {
        return Err(Refusal::conflict(format!(
            "request {} was rolled back",
            row.request_id
        )));
    }
    let signature = row.signature.ok_or_else(|| {
        Refusal::mpc_failure(format!(
            "store: request {} has no signature",
            row.request_id
        ))
    })?;
    Ok(NodeResult {
        request_id: row.request_id,
        vk_hash: None,
        proof: HexBytes(row.proof.clone()),
        public_inputs: row.public_inputs.iter().copied().map(FieldHex).collect(),
        stored: row.stored_keys.clone(),
        records: row
            .records()
            .map(|s| NodeResultRecord {
                key: s.key.clone(),
                note_hash: FieldHex(s.note_hash),
                c_i: HexBytes(s.c_i.clone()),
            })
            .collect(),
        signature,
    })
}

/// FETCH: the committed request `request_id` under `namespace`, as this node
/// answered it, with the vk_hash its row stores. 404 for an unknown or pruned
/// id, 409 for a rolled-back one.
pub fn fetch<S: Store>(
    node: &Node<S>,
    namespace: Fr,
    request_id: RequestId,
) -> Result<NodeResult, Refusal> {
    let row = node.store.request(namespace, request_id)?.ok_or_else(|| {
        Refusal::not_found(format!(
            "no request {request_id} under namespace {} (unknown, or pruned)",
            fr_to_hex(namespace)
        ))
    })?;
    let mut result = result_from_row(&row)?;
    result.vk_hash = Some(FieldHex(row.vk_hash));
    Ok(result)
}

/// FETCH by chain request id: the latest committed request carrying
/// `chain_request_id` under `namespace`
/// ([`StoreRead::fetch_by_chain_request_id`]), answered as [`fetch`] answers
/// its request id. 404 when no row carries it, 409 when the latest was
/// rolled back.
pub fn fetch_by_chain_request_id<S: Store>(
    node: &Node<S>,
    namespace: Fr,
    chain_request_id: Fr,
) -> Result<NodeResult, Refusal> {
    let row = node
        .store
        .fetch_by_chain_request_id(namespace, chain_request_id)?;
    let mut result = result_from_row(&row)?;
    result.vk_hash = Some(FieldHex(row.vk_hash));
    Ok(result)
}

/// The operator's rollback of one request (ARCHITECTURE.md section 3, the
/// rollback path), under the namespace lock: [`rules::restore`]. A tip
/// attempt's versions are first marked against this node's own chain view
/// `views` (the keys holding a version the request wrote), so a version the
/// slot holds is refused as landed; a namespace the view does not answer for
/// is refused (409) while the request holds versions. 404 for an unknown
/// request; 409 for one already rolled back, or while a later request
/// rewrote a key it wrote or consumed a state it created.
pub fn restore<S: Store>(
    node: &Node<S>,
    namespace: Fr,
    request_id: RequestId,
    views: &VersionViews<'_>,
) -> Result<(), Refusal> {
    let span = tracing::info_span!(
        "rollback",
        node = node.index,
        namespace = %fr_to_hex(namespace),
        request_id = %request_id,
    );
    let _span = span.enter();
    let _namespace_lock = node.lock_namespace(namespace);
    let result = mark_attempt(&node.store, namespace, request_id, views)
        .and_then(|()| rules::restore(&node.store, &node.keys(), namespace, request_id));
    match &result {
        Ok(()) => tracing::info!("request rolled back"),
        Err(refusal) => tracing::info!(
            class = %refusal.class,
            status = refusal.status(),
            error = %refusal.message,
            "rollback refused"
        ),
    }
    result
}

/// Mark the versions of every tip key holding a version `request_id` wrote
/// against this node's chain view `views` ([`NodeVersions::prune`]): what
/// a rollback refuses a landed version by. 409 when the view does not
/// answer for the namespace.
fn mark_attempt<S: Store>(
    store: &S,
    namespace: Fr,
    request_id: RequestId,
    views: &VersionViews<'_>,
) -> Result<(), Refusal> {
    let mut keys = Vec::new();
    for key in store.tip_keys(namespace)? {
        if store
            .tip_versions(namespace, &key)?
            .iter()
            .any(|v| v.request_id == request_id)
        {
            keys.push(key);
        }
    }
    if keys.is_empty() {
        return Ok(());
    }
    let Some(read) = views(namespace, &keys)? else {
        return Err(Refusal::conflict(format!(
            "request {request_id} wrote tip versions, and this node has no chain view of \
             namespace {} to check that none landed",
            fr_to_hex(namespace)
        )));
    };
    let views: Vec<_> = keys.into_iter().zip(read).collect();
    NodeVersions::prune(store, namespace, &views).map(|_| ())
}

#[cfg(test)]
mod tests;
