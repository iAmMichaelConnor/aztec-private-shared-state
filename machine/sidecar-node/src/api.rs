//! The node's HTTPS API, served to the orchestrator over mutual TLS: JSON in,
//! JSON out, one error shape (`{"error", "class"}`, ARCHITECTURE.md section 8)
//! with the class's HTTP code.
//!
//! ```text
//! POST /v1/execute                      Request<ForNode> -> NodeResult         (run_request)
//! POST /v1/fetch                        {namespace, request_id} -> NodeResult with the row's vk_hash  (404 unknown or pruned, 409 rolled back)
//! POST /v1/fetch/chain                  {namespace, chain_request_id} -> the latest attempt's NodeResult with its vk_hash  (404 none, 409 latest rolled back)
//! POST /v1/register                     signed manifest message -> ManifestAnswer
//! POST /v1/disable                      signed DISABLE body -> DisableAnswer
//! GET  /v1/packages/{namespace}         the names of the namespace's packages, disabled ones included
//! GET  /v1/packages/{namespace}/{name}  the stored package
//! GET  /v1/namespaces                   every namespace this node holds
//! GET  /v1/namespaces/{namespace}       owner_pubkey, seq, npk_app_hash, manifest_hash
//! GET  /v1/namespaces/{namespace}/manifest  the contract manifest, its hash and seq
//! GET  /v1/namespaces/{namespace}/manifests/{manifest_hash}  a held contract manifest version, its hash and seq
//! GET  /v1/nodes                        this node's {enc: {x, y}, sig: {x, y}}
//! POST /v1/receipt                      ReceiptRequest -> ReceiptAnswer (the tip's receipt, crate::receipt)
//! GET  /v1/receipt/{namespace}/{request_id}  the stored receipt row (404 none or pruned)
//! POST /v1/tree                         TreeQuery -> TreePaths: a tree-valued key's paths at one version (404 no such version)
//! ```
//!
//! Every handler parses the body, then runs the lifecycle call on a blocking
//! thread (the calls take locks, open the mesh and prove) inside a span that
//! carries the request id or the registry body's namespace, so every line of
//! a request is logged under its id. The rollback and the one-shot prune are
//! not here: they are on the admin socket ([`crate::admin`]), which this
//! listener never serves.

use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::response::Response;
use axum::routing::{get, post};
use rand::rngs::OsRng;
use serde::Serialize;
use sidecar_core::Refusal;
use sidecar_core::field::fr_from_hex;
use sidecar_core::pipeline;
use sidecar_core::register::{DisableRequest, ManifestMessage};
use sidecar_core::registry::{self, Signed};
use sidecar_core::request::NodeRequest;
use sidecar_core::response::{ChainFetchRequest, FetchRequest};
use sidecar_core::schnorr::check_name;
use sidecar_core::store::Store;
use sidecar_core::tree::TreeQuery;
use sidecar_http::listen::{BodyLimits, ListenerLimits, TLS_HANDSHAKE_TIMEOUT, limit_bodies};
use sidecar_http::respond::{
    answer, blocking, json, manifest_hash_param, namespace_param, refusal, unknown_route, utf8,
};
use tracing::Instrument;

use crate::receipt;
use crate::server::App;

// Operator knob: DESIGN.md, "Configuration reference" (node body limit).
// 32 MiB and a 60 s body read timeout: a larger body is 413, a late one 408
// ([`sidecar_http::listen::read_body`]).
/// The largest request body the API accepts.
pub const MAX_BODY_BYTES: usize = 32 * 1024 * 1024;

/// The node API's body bounds.
pub const NODE_BODY: BodyLimits = BodyLimits {
    max_bytes: MAX_BODY_BYTES,
    read_timeout: Duration::from_secs(60),
};

/// The node API's listener bounds.
pub const NODE_LISTENER: ListenerLimits = ListenerLimits {
    tls_handshake: TLS_HANDSHAKE_TIMEOUT,
    header_read: Duration::from_secs(30),
    max_connections: 512,
    max_handshakes: 512,
};

/// The API's routes over `app`.
pub fn router<S: Store + 'static>(app: Arc<App<S>>) -> Router {
    let routes = Router::new()
        .route("/v1/execute", post(execute::<S>))
        .route("/v1/fetch", post(fetch::<S>))
        .route("/v1/fetch/chain", post(fetch_chain::<S>))
        .route("/v1/register", post(register::<S>))
        .route("/v1/disable", post(disable::<S>))
        .route("/v1/packages/{namespace}", get(package_names::<S>))
        .route("/v1/packages/{namespace}/{name}", get(package::<S>))
        .route("/v1/namespaces", get(namespaces::<S>))
        .route("/v1/namespaces/{namespace}", get(namespace::<S>))
        .route("/v1/namespaces/{namespace}/manifest", get(manifest::<S>))
        .route(
            "/v1/namespaces/{namespace}/manifests/{manifest_hash}",
            get(manifest_version::<S>),
        )
        .route("/v1/nodes", get(nodes::<S>))
        .route("/v1/receipt", post(sign_receipt::<S>))
        .route(
            "/v1/receipt/{namespace}/{request_id}",
            get(stored_receipt::<S>),
        )
        .route("/v1/tree", post(tree_paths::<S>))
        .fallback(unknown_route)
        .method_not_allowed_fallback(unknown_route);
    limit_bodies(routes, NODE_BODY).with_state(app)
}

/// Run `f` on a blocking thread inside `span`, and answer with its result.
async fn in_span<T, F>(span: tracing::Span, f: F) -> Response
where
    T: Serialize + Send + 'static,
    F: FnOnce() -> Result<T, Refusal> + Send + 'static,
{
    answer(blocking(f).instrument(span).await)
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

async fn execute<S: Store + 'static>(State(app): State<Arc<App<S>>>, body: Bytes) -> Response {
    let req = match utf8(&body).and_then(NodeRequest::from_json) {
        Ok(req) => req,
        Err(r) => {
            tracing::info!(route = "/v1/execute", error = %r, "request refused at parse");
            return refusal(r);
        }
    };
    let span = tracing::info_span!("http", route = "/v1/execute", request_id = %req.request_id);
    in_span(span, move || {
        pipeline::run_request(&app.node, req, |held| app.connect_mesh(held))
    })
    .await
}

async fn fetch<S: Store + 'static>(State(app): State<Arc<App<S>>>, body: Bytes) -> Response {
    let req = match utf8(&body).and_then(FetchRequest::from_json) {
        Ok(req) => req,
        Err(r) => return refusal(r),
    };
    let span = tracing::info_span!(
        "http",
        route = "/v1/fetch",
        namespace = %req.namespace,
        request_id = %req.request_id
    );
    in_span(span, move || {
        let result = pipeline::fetch(&app.node, req.namespace.fr(), req.request_id);
        match &result {
            Ok(_) => tracing::info!("fetch answered"),
            Err(r) => tracing::info!(class = %r.class, error = %r.message, "fetch refused"),
        }
        result
    })
    .await
}

async fn fetch_chain<S: Store + 'static>(State(app): State<Arc<App<S>>>, body: Bytes) -> Response {
    let req = match utf8(&body).and_then(ChainFetchRequest::from_json) {
        Ok(req) => req,
        Err(r) => return refusal(r),
    };
    let span = tracing::info_span!(
        "http",
        route = "/v1/fetch/chain",
        namespace = %req.namespace,
        chain_request_id = %req.chain_request_id
    );
    in_span(span, move || {
        let result = pipeline::fetch_by_chain_request_id(
            &app.node,
            req.namespace.fr(),
            req.chain_request_id.fr(),
        );
        match &result {
            Ok(r) => tracing::info!(request_id = %r.request_id, "fetch by chain request id answered"),
            Err(r) => tracing::info!(class = %r.class, error = %r.message, "fetch by chain request id refused"),
        }
        result
    })
    .await
}

async fn register<S: Store + 'static>(State(app): State<Arc<App<S>>>, body: Bytes) -> Response {
    let body = match utf8(&body)
        .and_then(Signed::<ManifestMessage>::from_json)
        .and_then(|b| b.body.check_state(&app.node.holders()).map(|()| b))
    {
        Ok(body) => body,
        Err(r) => return refusal(r),
    };
    let span = tracing::info_span!(
        "http",
        route = "/v1/register",
        namespace = %body.body.namespace,
        seq = body.body.seq
    );
    in_span(span, move || {
        let result = app
            .node
            .register(&body, |held| app.connect_mesh(held), &mut OsRng);
        match &result {
            Ok(_) => tracing::info!("register answered"),
            Err(r) => tracing::info!(class = %r.class, error = %r.message, "register refused"),
        }
        result
    })
    .await
}

async fn disable<S: Store + 'static>(State(app): State<Arc<App<S>>>, body: Bytes) -> Response {
    let body = match utf8(&body).and_then(Signed::<DisableRequest>::from_json) {
        Ok(body) => body,
        Err(r) => return refusal(r),
    };
    let span = tracing::info_span!(
        "http",
        route = "/v1/disable",
        namespace = %body.body.namespace,
        name = %body.body.circuit,
        seq = body.body.seq
    );
    in_span(span, move || {
        let result = app.node.disable(&body, &mut OsRng);
        match &result {
            Ok(_) => tracing::info!("disable answered"),
            Err(r) => tracing::info!(class = %r.class, error = %r.message, "disable refused"),
        }
        result
    })
    .await
}

async fn package<S: Store + 'static>(
    State(app): State<Arc<App<S>>>,
    Path((namespace, name)): Path<(String, String)>,
) -> Response {
    let namespace = match namespace_param(&namespace)
        .and_then(|ns| check_name("name", "package name", &name).map(|()| ns))
    {
        Ok(ns) => ns,
        Err(r) => return refusal(r),
    };
    let span = tracing::debug_span!("http", route = "/v1/packages");
    in_span(span, move || {
        registry::package_info(&app.node.store, namespace, &name)
    })
    .await
}

async fn namespace<S: Store + 'static>(
    State(app): State<Arc<App<S>>>,
    Path(namespace): Path<String>,
) -> Response {
    let namespace = match namespace_param(&namespace) {
        Ok(ns) => ns,
        Err(r) => return refusal(r),
    };
    let span = tracing::debug_span!("http", route = "/v1/namespaces");
    in_span(span, move || {
        registry::namespace_info(&app.node.store, namespace)
    })
    .await
}

async fn manifest<S: Store + 'static>(
    State(app): State<Arc<App<S>>>,
    Path(namespace): Path<String>,
) -> Response {
    let namespace = match namespace_param(&namespace) {
        Ok(ns) => ns,
        Err(r) => return refusal(r),
    };
    let span = tracing::debug_span!("http", route = "/v1/namespaces/manifest");
    in_span(span, move || {
        registry::manifest_info(&app.node.store, namespace)
    })
    .await
}

async fn manifest_version<S: Store + 'static>(
    State(app): State<Arc<App<S>>>,
    Path((namespace, hash)): Path<(String, String)>,
) -> Response {
    let (namespace, hash) = match (namespace_param(&namespace), manifest_hash_param(&hash)) {
        (Ok(ns), Ok(hash)) => (ns, hash),
        (Err(r), _) | (_, Err(r)) => return refusal(r),
    };
    let span = tracing::debug_span!("http", route = "/v1/namespaces/manifests");
    in_span(span, move || {
        registry::manifest_version_info(&app.node.store, namespace, hash)
    })
    .await
}

// The registry listings, `GET /v1/namespaces` and `GET
// /v1/packages/{namespace}`, exist so an orchestrator can rebuild its
// registry copy from the three nodes (`sidecar-orchestrator sync-registry`).
// They answer on this mutual-TLS listener only; the orchestrator's public API
// does not relay them, so the public cannot enumerate the namespaces and
// circuits a network serves (a client names the namespace it uses). They read
// the store without a lock, like the other GETs.
async fn namespaces<S: Store + 'static>(State(app): State<Arc<App<S>>>) -> Response {
    let span = tracing::debug_span!("http", route = "/v1/namespaces");
    in_span(span, move || registry::namespace_list(&app.node.store)).await
}

async fn package_names<S: Store + 'static>(
    State(app): State<Arc<App<S>>>,
    Path(namespace): Path<String>,
) -> Response {
    let namespace = match namespace_param(&namespace) {
        Ok(ns) => ns,
        Err(r) => return refusal(r),
    };
    let span = tracing::debug_span!("http", route = "/v1/packages");
    in_span(span, move || {
        registry::package_names(&app.node.store, namespace)
    })
    .await
}

async fn nodes<S: Store + 'static>(State(app): State<Arc<App<S>>>) -> Response {
    json(&app.node.keys().public_keys())
}

// The receipt routes are served by every node, note mode or
// tip: there is no mode switch. A namespace that registers no
// circuit with `intake: receipt` gets nothing from them (every request is
// refused 400 at the package check, nothing is stored), and the `receipts`
// table stays empty. Like every route here they are reached only over the
// mutual-TLS listener, so only the orchestrator asks for a receipt; the
// orchestrator's public route is what users call.
async fn sign_receipt<S: Store + 'static>(State(app): State<Arc<App<S>>>, body: Bytes) -> Response {
    let req = match utf8(&body).and_then(sidecar_tip::ReceiptRequest::from_json) {
        Ok(req) => req,
        Err(r) => return refusal(r),
    };
    let span = tracing::info_span!(
        "http",
        route = "/v1/receipt",
        namespace = %req.namespace,
        circuit = %req.circuit
    );
    in_span(span, move || {
        let result = receipt::sign(&app.node, &app.receipts, &req);
        if let Err(r) = &result {
            tracing::info!(class = %r.class, error = %r.message, "receipt refused");
        }
        result
    })
    .await
}

async fn stored_receipt<S: Store + 'static>(
    State(app): State<Arc<App<S>>>,
    Path((namespace, request_id)): Path<(String, String)>,
) -> Response {
    let namespace = match namespace_param(&namespace) {
        Ok(ns) => ns,
        Err(r) => return refusal(r),
    };
    let request_id = match fr_from_hex(&request_id) {
        Ok(id) => id,
        Err(e) => return refusal(Refusal::bad_request(format!("path `request_id`: {e}"))),
    };
    let span = tracing::debug_span!("http", route = "/v1/receipt");
    in_span(span, move || {
        receipt::stored(&app.node, namespace, request_id)
    })
    .await
}

// The paths the scheduler places in a round on a tree-valued key, read from
// this node's clear tree (sidecar-core `tree::answer`); each node's chain
// verifier checks them again against its own tree at step 4.
async fn tree_paths<S: Store + 'static>(State(app): State<Arc<App<S>>>, body: Bytes) -> Response {
    let query = match utf8(&body)
        .and_then(sidecar_core::error::parse_json::<TreeQuery>)
        .and_then(|q| check_name("key", "store key", &q.key).map(|()| q))
    {
        Ok(q) => q,
        Err(r) => return refusal(r),
    };
    let span = tracing::debug_span!("http", route = "/v1/tree", key = %query.key);
    in_span(span, move || {
        sidecar_core::tree::answer(&app.node.store, &query)
    })
    .await
}
