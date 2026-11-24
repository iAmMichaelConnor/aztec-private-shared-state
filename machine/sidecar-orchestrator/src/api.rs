//! The public HTTPS API: JSON in, JSON out, the node's one error shape
//! (`{"error", "class"}` with the class's HTTP code, ARCHITECTURE.md section 8).
//!
//! ```text
//! POST /v1/execute                      Request<Full> -> ExecuteResponse
//! POST /v1/fetch                        {namespace, request_id} -> ExecuteResponse
//! POST /v1/fetch/chain                  {namespace, chain_request_id} -> ExecuteResponse (the latest attempt)
//! POST /v1/register                     signed manifest message -> ManifestResponse
//! POST /v1/disable                      signed DISABLE body -> DisableResponse
//! GET  /v1/packages/{namespace}/{name}  the registered package
//! GET  /v1/namespaces/{namespace}       owner_pubkey, seq, npk_app_hash, manifest_hash
//! GET  /v1/namespaces/{namespace}/manifest  the contract manifest as registered
//! GET  /v1/namespaces/{namespace}/manifests/{manifest_hash}  a held contract manifest version
//! GET  /v1/nodes                        the three nodes' {enc, sig}, checked against the pins
//! GET  /v1/status                       the latest registry check's counts and the chain readers' held block hashes (crate::status), from memory
//! POST /v1/receipt                      ReceiptRequest<Full> -> ReceiptResponse (the tip's receipts)
//! ```
//!
//! An execute request runs steps 1 to 4 here, on the full request, before
//! anything is sent; then it takes the global session lock ([`crate::gate`]:
//! the schedulers first, public sessions in a bounded waiting room, 503 with
//! `Retry-After` past it), is projected to
//! each node's view and fanned out to the three at once, in a task that
//! outlives the client's connection. REGISTER and DISABLE bodies are parsed
//! and their owner and `seq` checked against the registry copy here, then
//! forwarded byte for byte under the same lock; once a node may have written
//! one, the registry check reruns in a task of its own ([`crate::status::recheck`]).
//! FETCH, the receipt route and the GETs take no lock.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use axum::Router;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::response::Response;
use axum::routing::{get, post};
use serde::Serialize;
use sidecar_core::Refusal;
use sidecar_core::error::parse_json;
use sidecar_core::field::FieldHex;
use sidecar_core::grumpkin::Point;
use sidecar_core::pipeline;
use sidecar_core::register::{
    DisableAnswer, DisableRequest, DisableResponse, ManifestAnswer, ManifestMessage,
    ManifestResponse,
};
use sidecar_core::registry::{self, Signed};
use sidecar_core::request::{Full, NODES, Request};
use sidecar_core::response::{
    ChainFetchRequest, ExecuteResponse, FetchRequest, NodePublicKeys, NodeResult, NodesResponse,
};
use sidecar_http::listen::{BodyLimits, limit_bodies};
use sidecar_http::respond::{
    self, blocking, manifest_hash_param, namespace_param, unknown_route, utf8,
};
use tokio::sync::Semaphore;
use tracing::Instrument;

use crate::answer;
use crate::gate::{Busy, Class, SessionGate};
use crate::nodes::{Nodes, Reply, all_answers};
use crate::registry::{Registry, all_refused, committed_answers};
use crate::status::{ReaderStatus, RegistryReport, RegistryStatus, StatusResponse, recheck};

/// Everything the routes share: the registry copy, the three node clients,
/// the pinned keys and the global session lock.
pub struct Orchestrator {
    pub registry: Arc<Registry>,
    pub nodes: Nodes,
    /// The pinned keys of the three nodes, from the configuration.
    pub pins: NodesResponse,
    /// The pinned `sig` keys as points.
    pub sig_pks: [Point; NODES],
    /// `expiry_block = current_block + receipt_ttl_blocks` for a receipt.
    pub receipt_ttl_blocks: u32,
    /// The REGISTER vk builds that may run at once
    /// ([`MAX_CONCURRENT_VK_BUILDS`] permits).
    pub vk_builds: Arc<Semaphore>,
    session: SessionGate,
    /// The registry check reruns after registry bodies, coalesced
    /// ([`crate::status::recheck`]).
    pub rechecks: crate::status::Rechecks,
    // Scheduling paused for maintenance (a node replacement): no session
    // starts and no scheduler computes while set ([`Orchestrator::pause`]).
    paused: AtomicBool,
    // Each scheduler's chain reader as of its last step, by namespace, for
    // `GET /v1/status` ([`Orchestrator::record_reader`]).
    readers: std::sync::Mutex<BTreeMap<String, ReaderStatus>>,
}

impl Orchestrator {
    pub fn new(
        registry: Registry,
        nodes: Nodes,
        pins: NodesResponse,
        sig_pks: [Point; NODES],
    ) -> Self {
        Orchestrator {
            registry: Arc::new(registry),
            nodes,
            pins,
            sig_pks,
            receipt_ttl_blocks: sidecar_tip::DEFAULT_RECEIPT_TTL_BLOCKS,
            vk_builds: Arc::new(Semaphore::new(MAX_CONCURRENT_VK_BUILDS)),
            session: SessionGate::default(),
            rechecks: crate::status::Rechecks::default(),
            paused: AtomicBool::new(false),
            readers: std::sync::Mutex::new(BTreeMap::new()),
        }
    }

    /// Record a scheduler's chain reader for `GET /v1/status`.
    pub fn record_reader(&self, status: ReaderStatus) {
        let mut readers = self.readers.lock().unwrap_or_else(|e| e.into_inner());
        readers.insert(status.namespace.clone(), status);
    }

    /// Every scheduler's chain reader as last recorded, by namespace.
    pub fn readers(&self) -> Vec<ReaderStatus> {
        let readers = self.readers.lock().unwrap_or_else(|e| e.into_inner());
        readers.values().cloned().collect()
    }

    // The pause between rounds (docs/ARCHITECTURE.md section 6, "Node
    // replacement and key epochs"): the operator pauses the orchestrator
    // before a node replacement and resumes it after the new key set is
    // declared. A pause waits for the session in flight (it takes the
    // global session lock once, after setting the flag, in the schedulers'
    // class, so no waiting public session goes before it), so it lands
    // between rounds; while paused, every execute, REGISTER and DISABLE is refused
    // after it takes the lock (500, retry later), and every scheduler step
    // reads the chain and computes nothing. FETCH, the GET routes and the
    // receipt route are served: they open no mesh session. A resume first
    // runs the registry check and refuses while the nodes' registries differ
    // (a newcomer whose import left it behind), so the queue never resumes on
    // a network that would refuse its rounds.
    /// Whether scheduling is paused.
    pub fn paused(&self) -> bool {
        self.paused.load(Ordering::SeqCst)
    }

    /// Pause between rounds: no new session starts; returns once the
    /// session in flight (if any) has ended.
    pub async fn pause(&self) {
        self.paused.store(true, Ordering::SeqCst);
        drop(self.session.enter_first().await);
        tracing::info!("scheduling paused");
    }

    /// Start paused (the `--paused` start of a restarted orchestrator).
    pub fn start_paused(self) -> Self {
        self.paused.store(true, Ordering::SeqCst);
        self
    }

    /// Resume, once the registry check finds the three nodes' registries
    /// alike (409 naming the divergences otherwise; 500 when the nodes
    /// cannot all be read). Returns what the check found.
    pub async fn resume(&self) -> Result<RegistryReport, Refusal> {
        let report = crate::status::check_registry(self, crate::status::When::Resume).await;
        let summary = report.agreement.as_ref().ok_or_else(|| {
            Refusal::mpc_failure(
                "resume: the nodes' registries could not all be read; still paused",
            )
        })?;
        if summary.between_nodes > 0 {
            let rows: Vec<String> = summary
                .check
                .divergences
                .iter()
                .map(ToString::to_string)
                .collect();
            return Err(Refusal::conflict(format!(
                "resume: the nodes' registries differ on {} row(s); still paused: {}",
                summary.between_nodes,
                rows.join("; ")
            )));
        }
        self.paused.store(false, Ordering::SeqCst);
        tracing::info!("scheduling resumed");
        Ok(report)
    }

    /// Set receipts to expire `ttl` blocks after the current block.
    pub fn with_receipt_ttl(mut self, ttl: u32) -> Self {
        self.receipt_ttl_blocks = ttl;
        self
    }
}

// Operator knob: DESIGN.md, "Configuration reference" (public body limit).
// 4 MiB and a 60 s body read timeout: a larger body is 413, a late one 408.
/// The largest request body the public API accepts.
pub const PUBLIC_MAX_BODY_BYTES: usize = 4 * 1024 * 1024;

// Operator knob: DESIGN.md, "Configuration reference" (concurrent vk
// builds; no knob). A manifest message whose owner signature verifies costs
// one vk build per circuit (seconds of CPU and the circuit's memory each,
// run in parallel) before the session lock, and anyone can sign a seq 0 body
// for a namespace no node holds; even a junk-signed one costs a parse that
// hashes the whole body. Two messages in the parse, the pre-check and the
// builds at a time bound what the public listener spends on them, and a
// third message waits for a permit. Rounds are not affected: they build no
// vk here.
/// The manifest messages whose vks the orchestrator builds at once.
pub const MAX_CONCURRENT_VK_BUILDS: usize = 2;

/// The public API's body bounds.
pub const PUBLIC_BODY: BodyLimits = BodyLimits {
    max_bytes: PUBLIC_MAX_BODY_BYTES,
    read_timeout: std::time::Duration::from_secs(60),
};

/// The API's routes over `app`.
pub fn router(app: Arc<Orchestrator>) -> Router {
    let routes = Router::new()
        .route("/v1/execute", post(execute))
        .route("/v1/fetch", post(fetch))
        .route("/v1/fetch/chain", post(fetch_chain))
        .route("/v1/register", post(register))
        .route("/v1/disable", post(disable))
        .route("/v1/packages/{namespace}/{name}", get(package))
        .route("/v1/namespaces/{namespace}", get(namespace))
        .route(
            "/v1/namespaces/{namespace}/manifest",
            get(contract_manifest),
        )
        .route(
            "/v1/namespaces/{namespace}/manifests/{manifest_hash}",
            get(contract_manifest_version),
        )
        .route("/v1/nodes", get(nodes))
        .route("/v1/status", get(status))
        .route("/v1/receipt", post(receipt))
        .fallback(unknown_route)
        .method_not_allowed_fallback(unknown_route);
    limit_bodies(routes, PUBLIC_BODY).with_state(app)
}

// ---------------------------------------------------------------------------
// Responses and helpers
// ---------------------------------------------------------------------------

/// `result` as an answer; a refusal is logged with its class and status.
fn answer<T: Serialize>(result: Result<T, Refusal>) -> Response {
    if let Err(r) = &result {
        tracing::info!(class = %r.class, status = r.status(), error = %r.message, "refused");
    }
    respond::answer(result)
}

/// Why a session route gave no answer: a refusal, or the gate's waiting
/// room was full ([`Busy`]).
#[derive(Debug)]
pub enum SessionError {
    Refused(Refusal),
    Busy(Busy),
}

impl From<Refusal> for SessionError {
    fn from(r: Refusal) -> Self {
        SessionError::Refused(r)
    }
}

/// A scheduler's session is never turned away; a [`Busy`] that reaches a
/// caller expecting a refusal is a retryable 500.
impl From<SessionError> for Refusal {
    fn from(e: SessionError) -> Self {
        match e {
            SessionError::Refused(r) => r,
            SessionError::Busy(b) => Refusal::mpc_failure(b.message),
        }
    }
}

/// A session route's `result` as an answer: [`answer`], or 503 with
/// `Retry-After` when the waiting room was full.
fn session_answer<T: Serialize>(result: Result<T, SessionError>) -> Response {
    match result {
        Err(SessionError::Busy(busy)) => {
            tracing::info!(error = %busy.message, "turned away: the session waiting room is full");
            respond::busy(busy.message, busy.retry_after)
        }
        Err(SessionError::Refused(r)) => answer::<()>(Err(r)),
        Ok(value) => answer(Ok(value)),
    }
}

// The orchestrator's one global session lock, decided (docs/DECISIONS.md
// section 5, "Security checks"): per-queue locks arrive with sharding, which
// is not designed. One execute, REGISTER or DISABLE session is in flight at
// a time across all namespaces:
// each takes the gate ([`crate::gate`]: a waiting scheduler attempt before
// any waiting public session, first come first served within each class,
// a bounded public waiting room) after its stateless checks and holds it
// from the fan-out until the three answers are checked and, for a registry
// body, recorded in the registry copy. The nodes have one
// mesh session port each, so concurrent sessions would only queue at the
// nodes, where a node that took a second request first could leave the three
// waiting on different sessions until the mesh timeouts; one lock here keeps
// the three nodes on the same request. The fan-out and its checks run in a
// task of their own that owns the lock ([`in_session`]), so a client that
// disconnects mid-round cancels nothing: the three node calls complete, the
// answers are checked (and a registry body recorded), and the lock is
// released only when that task ends; the client recovers the round with
// FETCH. A client that disconnects while it still waits for the lock gives up
// its place, and nothing was sent. FETCH and the GET routes read committed
// rows and take no lock. The alternative, sharding, needs one mesh port per
// concurrent session and per-queue locks (DECISIONS.md section 3, "No `queue`
// field").
/// Take the global session lock as `class`, then run `work` in a spawned
/// task that holds it until `work` ends; the caller awaits the task, and
/// dropping the caller (a client disconnect) leaves the task running.
async fn in_session<T, F, Fut>(
    app: &Arc<Orchestrator>,
    class: Class,
    work: F,
) -> Result<T, SessionError>
where
    T: Send + 'static,
    F: FnOnce(Arc<Orchestrator>) -> Fut,
    Fut: std::future::Future<Output = Result<T, Refusal>> + Send + 'static,
{
    let guard = app.session.enter(class).await.map_err(SessionError::Busy)?;
    if app.paused() {
        return Err(Refusal::mpc_failure(
            "the orchestrator is paused for maintenance (a node replacement); retry later",
        )
        .into());
    }
    let work = work(app.clone());
    let task = tokio::spawn(
        async move {
            let result = work.await;
            drop(guard);
            result
        }
        .instrument(tracing::Span::current()),
    );
    task.await
        .unwrap_or_else(|e| {
            Err(Refusal::mpc_failure(format!(
                "the session task failed: {e}"
            )))
        })
        .map_err(SessionError::Refused)
}

// ---------------------------------------------------------------------------
// Execute and FETCH
// ---------------------------------------------------------------------------

async fn execute(State(app): State<Arc<Orchestrator>>, body: Bytes) -> Response {
    let req = match utf8(&body).and_then(Request::from_json) {
        Ok(req) => req,
        Err(r) => return answer::<()>(Err(r)),
    };
    let span = tracing::info_span!(
        "execute",
        namespace = %req.namespace,
        circuit = %req.circuit,
        request_id = %req.request_id
    );
    let class = Class::Public(req.namespace.fr());
    session_answer(run_execute(app, req, class).instrument(span).await)
}

// The orchestrator's stateless checks. Before anything is sent
// it runs steps 1 to 4 on the full request (`pipeline::stateless_prefix`:
// parse, `admit`, resolution against its registry copy with the key counts,
// and the requester signature), and also step 6 for all three nodes at once
// (`check_ciphertext_hashes`: every envelope and record third hashes to the
// hash the body carries for it), because a third that fails at one node
// would otherwise leave the other two waiting on a mesh session that never
// opens. The `admit` hook is sidecar-core's (`admit::admit`, which admits
// everything) and runs again on every node, so a fee or quota
// added there binds whether or not the orchestrator is honest. A refused
// request never reaches a node. The tip's scheduler drives the same call
// with the requests it synthesises (`crate::scheduler`).
/// One execute request the whole way: the stateless checks, the global
/// session lock as `class`, the fan-out and the checks of the three answers.
pub async fn run_execute(
    app: Arc<Orchestrator>,
    req: Request,
    class: Class,
) -> Result<ExecuteResponse, SessionError> {
    let registry = app.registry.clone();
    let checked = req.clone();
    blocking(move || {
        pipeline::stateless_prefix(&checked, registry.store())?;
        checked.check_ciphertext_hashes()?;
        // Build the verifier before the lock: the first use of a circuit
        // computes its vk.
        let pkg = registry::resolve(
            registry.store(),
            checked.namespace.fr(),
            &checked.circuit,
            checked.manifest_hash.map(FieldHex::fr),
        )?;
        registry.verifier(checked.namespace.fr(), &pkg)?;
        Ok(())
    })
    .await?;

    in_session(&app, class, move |app| async move {
        let registry = app.registry.clone();
        let (namespace, circuit) = (req.namespace.fr(), req.circuit.clone());
        let version = req.manifest_hash.map(FieldHex::fr);
        let verifier = blocking(move || {
            let pkg = registry::resolve(registry.store(), namespace, &circuit, version)?;
            registry.verifier(namespace, &pkg)
        })
        .await?;
        let views =
            [0, 1, 2].map(|i| serde_json::to_vec(&req.project(i)).expect("a request serialises"));
        let replies = app.nodes.post_each("/v1/execute", views).await;
        let results = all_answers::<NodeResult>(replies)?;
        let (registry, sig_pks, request_id) = (app.registry.clone(), app.sig_pks, req.request_id);
        blocking(move || {
            answer::check_execute(
                &registry, &verifier, &sig_pks, namespace, request_id, results,
            )
        })
        .await
    })
    .await
}

async fn fetch(State(app): State<Arc<Orchestrator>>, body: Bytes) -> Response {
    let req = match utf8(&body).and_then(FetchRequest::from_json) {
        Ok(req) => req,
        Err(r) => return answer::<()>(Err(r)),
    };
    let span =
        tracing::info_span!("fetch", namespace = %req.namespace, request_id = %req.request_id);
    answer(run_fetch(app, req).instrument(span).await)
}

// FETCH keeps nothing at the orchestrator. It asks the three
// nodes for their `requests` row of (namespace, request_id) and answers from
// those alone, so a fresh orchestrator answers the same FETCH. Each node's
// answer carries the vk_hash its row stores; the orchestrator picks the
// package of the namespace with that vk_hash in its registry copy and checks
// the answers under it (`answer::check_fetch`), so the response carries the
// vk_hash the round ran under. A round whose circuit has since been
// registered again under another vk is 409. Any node without the row makes it
// 404, a rolled-back row 409 (the most specific refusal wins, as for
// execute). FETCH takes no lock: it reads committed rows.
async fn run_fetch(app: Arc<Orchestrator>, req: FetchRequest) -> Result<ExecuteResponse, Refusal> {
    let body = serde_json::to_vec(&req).expect("a FETCH body serialises");
    let replies = app.nodes.lookups().post_same("/v1/fetch", &body).await;
    let results = all_answers::<NodeResult>(replies)?;
    let (registry, sig_pks) = (app.registry.clone(), app.sig_pks);
    blocking(move || {
        answer::check_fetch(
            &registry,
            &sig_pks,
            req.namespace.fr(),
            req.request_id,
            results,
        )
    })
    .await
}

async fn fetch_chain(State(app): State<Arc<Orchestrator>>, body: Bytes) -> Response {
    let req = match utf8(&body).and_then(ChainFetchRequest::from_json) {
        Ok(req) => req,
        Err(r) => return answer::<()>(Err(r)),
    };
    let span = tracing::info_span!(
        "fetch_chain",
        namespace = %req.namespace,
        chain_request_id = %req.chain_request_id
    );
    answer(run_fetch_chain(app, req).instrument(span).await)
}

// FETCH by chain request id, the way the relayer and clients
// read a queued request's result. It asks the three nodes for the latest
// row carrying the chain request id (`POST /v1/fetch/chain`), requires the
// three to answer the same attempt (`agree` on results[0]'s request id) and
// checks it exactly as FETCH does (`answer::check_fetch`), then checks that
// the answered request id is the machine request id of this chain request,
// the round's own old commitments and its pinned values (both read from its
// public inputs; `answer::check_chain_attempt`, 500
// otherwise): the result signatures cover the request id but not the chain
// request id, so this is what binds the answer to the chain request asked
// for. Like FETCH it takes no lock and keeps nothing; 404 when no node row
// carries the id, 409 when the latest attempt was rolled back.
/// FETCH by chain request id: the latest attempt the three nodes hold.
pub async fn run_fetch_chain(
    app: Arc<Orchestrator>,
    req: ChainFetchRequest,
) -> Result<ExecuteResponse, Refusal> {
    let body = serde_json::to_vec(&req).expect("a FETCH body serialises");
    let replies = app
        .nodes
        .lookups()
        .post_same("/v1/fetch/chain", &body)
        .await;
    let results = all_answers::<NodeResult>(replies)?;
    let (registry, sig_pks) = (app.registry.clone(), app.sig_pks);
    blocking(move || {
        let (namespace, chain) = (req.namespace.fr(), req.chain_request_id.fr());
        let request_id = results[0].request_id;
        let response = answer::check_fetch(&registry, &sig_pks, namespace, request_id, results)?;
        answer::check_chain_attempt(&registry, namespace, chain, &response)?;
        Ok(response)
    })
    .await
}

// ---------------------------------------------------------------------------
// REGISTER and DISABLE
// ---------------------------------------------------------------------------

async fn register(State(app): State<Arc<Orchestrator>>, body: Bytes) -> Response {
    let permit = match app.vk_builds.clone().acquire_owned().await {
        Ok(permit) => permit,
        Err(_) => {
            return answer::<()>(Err(Refusal::mpc_failure(
                "the orchestrator is stopping; no REGISTER body is checked",
            )));
        }
    };
    let (registry, raw) = (app.registry.clone(), body.clone());
    let checked = blocking(move || {
        let signed = utf8(&raw)
            .and_then(Signed::<ManifestMessage>::from_json)
            .and_then(|s| s.body.check_state(&sidecar_tip::holders()).map(|()| s))?;
        registry::precheck_register(registry.store(), &signed)?;
        Ok(signed)
    })
    .await;
    let signed = match checked {
        Ok(signed) => signed,
        Err(r) => return answer::<()>(Err(r)),
    };
    let span = tracing::info_span!(
        "register",
        namespace = %signed.body.namespace,
        circuits = signed.body.circuits.len(),
        seq = signed.body.seq
    );
    session_answer(
        run_register(app, signed, body, permit)
            .instrument(span)
            .await,
    )
}

// Registry bodies are forwarded verbatim. The nodes sign over, and check the
// owner signature against, the JSON bytes they receive, so the orchestrator
// forwards the client's bytes unchanged to all three. Before that it parses
// the manifest message and runs the checks that need no node: the contract
// manifest and its checks across packages (`ManifestMessage::check`, at
// parse), each package's state modes against the holders (400), and section
// 4 step 2 against its registry copy (`registry::precheck_register`: the
// owner signature, and the stored owner and `seq` when the copy holds the
// namespace, 403 and 409 in the nodes' words); only then does it compute
// every circuit's vk itself from the body and its CRS, in parallel, and
// require each to hash to the manifest's vk hash (400 if not), so a body
// anyone can sign costs no vk build unless the copy's rows allow it, and a
// body the orchestrator could never serve is not committed at the nodes. The
// parse (which hashes the whole body), the pre-check and the builds run on a
// blocking thread, never on the runtime's workers, and at most
// [`MAX_CONCURRENT_VK_BUILDS`] messages are in them at once; a message past
// them waits for a permit. The nodes run these rules again on their own
// rows, which are authoritative: a namespace the copy does not hold is
// forwarded for them to decide. The three answers must agree, name the
// body's manifest hash, packages hash and listed packages, carry the body's
// `seq`, a `seq` 0 answer's registration proof must verify against the
// built-in vk with the public inputs (namespace, npk_app_hash), and every
// signature must verify under the pinned `sig` keys
// (`registry::check_manifest_answers`, 500 otherwise). A body some nodes
// committed and others refused or failed to commit is 500 naming the
// divergence and its repair (`crate::registry::committed_answers`). Only
// then is the manifest recorded in the registry copy, in one transaction
// with the orchestrator's own vks, and the client gets the values and the
// signatures, never the proof.
async fn run_register(
    app: Arc<Orchestrator>,
    signed: Signed<ManifestMessage>,
    raw: Bytes,
    permit: tokio::sync::OwnedSemaphorePermit,
) -> Result<ManifestResponse, SessionError> {
    let namespace = signed.body.namespace.fr();
    let registry = app.registry.clone();
    let body = signed.body.clone();
    let computed = blocking(move || {
        let computed = registry.compute(&body);
        drop(permit);
        computed
    })
    .await?;

    in_session(&app, Class::Public(namespace), move |app| async move {
        let (registry, sig_pks) = (app.registry.clone(), app.sig_pks);
        relay_body(&app, "/v1/register", &raw, |replies| async move {
            let answers = committed_answers::<ManifestAnswer>("REGISTER", replies)?;
            blocking(move || {
                let body = &signed.body;
                let response = registry::check_manifest_answers(
                    body,
                    &computed.facts,
                    &answers,
                    &sig_pks,
                    registry.registration_vk(),
                    registry.g2(),
                )?;
                registry.record_register(body, &response, computed)?;
                Ok(response)
            })
            .await
        })
        .await
    })
    .await
}

/// Forward a registry body's bytes to the three nodes and `record` their
/// replies (check them and write the copy). Unless every node refused the
/// body, the registry check then reruns in a task of its own
/// ([`crate::status::recheck`]), after the copy has the body, so `GET /v1/status`
/// compares the rows the body left.
async fn relay_body<T, F, Fut>(
    app: &Arc<Orchestrator>,
    path: &str,
    raw: &[u8],
    record: F,
) -> Result<T, Refusal>
where
    F: FnOnce([Reply; NODES]) -> Fut,
    Fut: std::future::Future<Output = Result<T, Refusal>>,
{
    let replies = app.nodes.post_same(path, raw).await;
    let rerun = !all_refused(&replies);
    let recorded = record(replies).await;
    if rerun {
        recheck(app);
    }
    recorded
}

async fn disable(State(app): State<Arc<Orchestrator>>, body: Bytes) -> Response {
    let signed = match utf8(&body).and_then(Signed::<DisableRequest>::from_json) {
        Ok(signed) => signed,
        Err(r) => return answer::<()>(Err(r)),
    };
    let span = tracing::info_span!(
        "disable",
        namespace = %signed.body.namespace,
        name = %signed.body.circuit,
        seq = signed.body.seq
    );
    session_answer(run_disable(app, signed, body).instrument(span).await)
}

async fn run_disable(
    app: Arc<Orchestrator>,
    signed: Signed<DisableRequest>,
    raw: Bytes,
) -> Result<DisableResponse, SessionError> {
    // The same pre-check as REGISTER's (`registry::precheck_disable`).
    registry::precheck_disable(app.registry.store(), &signed)?;
    let namespace = signed.body.namespace.fr();
    in_session(&app, Class::Public(namespace), move |app| async move {
        let (registry, sig_pks) = (app.registry.clone(), app.sig_pks);
        relay_body(&app, "/v1/disable", &raw, |replies| async move {
            let answers = committed_answers::<DisableAnswer>("DISABLE", replies)?;
            blocking(move || {
                let response = registry::check_disable_answers(&signed.body, &answers, &sig_pks)?;
                registry.record_disable(&signed.body, &response)?;
                Ok(response)
            })
            .await
        })
        .await
    })
    .await
}

// ---------------------------------------------------------------------------
// Receipts
// ---------------------------------------------------------------------------

async fn receipt(State(app): State<Arc<Orchestrator>>, body: Bytes) -> Response {
    let req = match utf8(&body).and_then(parse_json::<sidecar_tip::ReceiptRequest<Full>>) {
        Ok(req) => req,
        Err(r) => return answer::<()>(Err(r)),
    };
    let span = tracing::info_span!("receipt", namespace = %req.namespace, circuit = %req.circuit);
    answer(run_receipt(app, req).instrument(span).await)
}

// The orchestrator's receipt route. It fixes the one expiry the
// three nodes sign, `expiry_block = current_block + receipt_ttl_blocks`, and
// takes `current_block` from the client's body: the route reads no chain (the
// chain reader runs only under `[tip]`, for the scheduler), so the client says
// which block it saw
// (a client that claims an earlier block gets a receipt the contract refuses
// sooner; one that claims a later block is refused by every node beyond
// its own block plus TTL and allowance, and a node without `[tip]` signs no
// receipt at all: the nodes bound and prune by their own chain view, never
// by a body's block). A client may not set `expiry_block` (400). Before
// anything is sent it checks every shared input's three share hashes
// against its envelopes (secret-shared receipt intake, as for an execute request)
// and runs the nodes' checks against its registry copy (resolution, a
// manifest whose intake takes receipts, the static-validity check, and
// under secret-shared receipt intake that the summand commitments give the
// sharing digest) and computes both ids, so a bad request never reaches a
// node; then it sends node i the body with the expiry and only node i's
// envelope of each shared input, to the three nodes at once, without the
// session lock (a receipt opens no mesh session), and returns the agreed
// values with the three signatures (`answer::check_receipt`). Each node
// checks its own envelopes against the summand commitments; the
// orchestrator opens none.
// The orchestrator stores nothing: each node keeps its own row, which the
// scheduler reads back from the nodes.
async fn run_receipt(
    app: Arc<Orchestrator>,
    mut req: sidecar_tip::ReceiptRequest<Full>,
) -> Result<sidecar_tip::ReceiptResponse, Refusal> {
    if req.expiry_block.is_some() {
        return Err(Refusal::bad_request(
            "field `expiry_block`: set by the orchestrator, not the client",
        ));
    }
    let expiry = req
        .current_block
        .checked_add(app.receipt_ttl_blocks)
        .ok_or_else(|| {
            Refusal::bad_request(format!(
                "field `current_block`: {} plus the receipt TTL of {} blocks is past the \
                 largest block number",
                req.current_block, app.receipt_ttl_blocks
            ))
        })?;
    req.check_share_hashes()?;
    let registry = app.registry.clone();
    let checked_req = req.project(0);
    let checked = blocking(move || {
        let pkg = registry::resolve(
            registry.store(),
            checked_req.namespace.fr(),
            &checked_req.circuit,
            checked_req.manifest_hash.map(FieldHex::fr),
        )?;
        let stale = sidecar_tip::stale_blocks_of(registry.store(), checked_req.namespace.fr())?;
        sidecar_tip::check_receipt_request(&pkg, stale, &checked_req)
    })
    .await?;
    req.expiry_block = Some(expiry);
    let bodies = [0, 1, 2]
        .map(|i| serde_json::to_vec(&req.project(i)).expect("a receipt request serialises"));
    let replies = app.nodes.lookups().post_each("/v1/receipt", bodies).await;
    let answers = all_answers::<sidecar_tip::ReceiptAnswer>(replies)?;
    answer::check_receipt(&app.sig_pks, &checked, expiry, answers)
}

// ---------------------------------------------------------------------------
// The GET routes
// ---------------------------------------------------------------------------

// The registry GETs answer from the orchestrator's registry
// copy, which holds the rows the nodes committed for every registry body it
// relayed (invariant 12), so a GET costs no node round trip. A client that
// wants the nodes' own word pins what REGISTER answered: the vk_hash and
// npk_app_hash with the three node signatures over them.
async fn package(
    State(app): State<Arc<Orchestrator>>,
    Path((namespace, name)): Path<(String, String)>,
) -> Response {
    let namespace = match namespace_param(&namespace) {
        Ok(ns) => ns,
        Err(r) => return answer::<()>(Err(r)),
    };
    let registry = app.registry.clone();
    answer(blocking(move || registry::package_info(registry.store(), namespace, &name)).await)
}

async fn namespace(
    State(app): State<Arc<Orchestrator>>,
    Path(namespace): Path<String>,
) -> Response {
    let namespace = match namespace_param(&namespace) {
        Ok(ns) => ns,
        Err(r) => return answer::<()>(Err(r)),
    };
    let registry = app.registry.clone();
    answer(blocking(move || registry::namespace_info(registry.store(), namespace)).await)
}

async fn contract_manifest(
    State(app): State<Arc<Orchestrator>>,
    Path(namespace): Path<String>,
) -> Response {
    let namespace = match namespace_param(&namespace) {
        Ok(ns) => ns,
        Err(r) => return answer::<()>(Err(r)),
    };
    let registry = app.registry.clone();
    answer(blocking(move || registry::manifest_info(registry.store(), namespace)).await)
}

async fn contract_manifest_version(
    State(app): State<Arc<Orchestrator>>,
    Path((namespace, hash)): Path<(String, String)>,
) -> Response {
    let (namespace, hash) = match (namespace_param(&namespace), manifest_hash_param(&hash)) {
        (Ok(ns), Ok(hash)) => (ns, hash),
        (Err(r), _) | (_, Err(r)) => return answer::<()>(Err(r)),
    };
    let registry = app.registry.clone();
    answer(
        blocking(move || registry::manifest_version_info(registry.store(), namespace, hash)).await,
    )
}

/// `GET /v1/nodes`: each node's keys as it serves them, refused (500, naming
/// the node and key) unless they equal the pinned ones.
async fn nodes(State(app): State<Arc<Orchestrator>>) -> Response {
    let replies = app.nodes.lookups().get("/v1/nodes").await;
    answer(all_answers::<NodePublicKeys>(replies).and_then(|nodes| {
        let served = NodesResponse { nodes };
        served.check_pins(&app.pins)?;
        Ok(served)
    }))
}

/// `GET /v1/status`: the latest registry check's time and counts, and the
/// block hashes each scheduler's chain reader holds ([`StatusResponse`]),
/// from memory, with no node round trip. The rows that differ are on the
/// admin socket ([`crate::status`]).
async fn status(State(app): State<Arc<Orchestrator>>) -> Response {
    respond::json(&StatusResponse {
        registry: app.registry.agreement().as_ref().map(RegistryStatus::of),
        readers: app.readers(),
    })
}
