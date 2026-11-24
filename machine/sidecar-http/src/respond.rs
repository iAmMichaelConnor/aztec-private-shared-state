//! The answers of both binaries' routes: JSON in, JSON out, one error shape
//! (`{"error", "class"}` with the class's HTTP code, ARCHITECTURE.md
//! section 8), and the small parsers every handler starts with.

use axum::body::Bytes;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use sidecar_core::field::fr_from_hex;
use sidecar_core::{Fr, Refusal};

/// A 200 answer with `value` as its JSON body (500 if it does not serialise).
pub fn json<T: Serialize>(value: &T) -> Response {
    match serde_json::to_vec(value) {
        Ok(body) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/json")],
            body,
        )
            .into_response(),
        Err(e) => refusal(Refusal::mpc_failure(format!("answer: {e}"))),
    }
}

/// A refusal in the one error shape, with its class's code.
pub fn refusal(refusal: Refusal) -> Response {
    let status =
        StatusCode::from_u16(refusal.status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    (
        status,
        [(header::CONTENT_TYPE, "application/json")],
        refusal.to_json(),
    )
        .into_response()
}

/// 503 with `Retry-After: retry_after` (whole seconds, at least 1) and the
/// one error shape under the class `mpc_failure`: the server is busy, and
/// the same request may be sent again after that long. Like the listener's
/// 408 and 413, a status other than its class's.
pub fn busy(message: impl Into<String>, retry_after: std::time::Duration) -> Response {
    let secs = retry_after.as_secs().max(1).to_string();
    (
        StatusCode::SERVICE_UNAVAILABLE,
        [
            (header::CONTENT_TYPE, "application/json".to_string()),
            (header::RETRY_AFTER, secs),
        ],
        Refusal::mpc_failure(message).to_json(),
    )
        .into_response()
}

/// `result` as an answer: its value, or the refusal.
pub fn answer<T: Serialize>(result: Result<T, Refusal>) -> Response {
    match result {
        Ok(value) => json(&value),
        Err(r) => refusal(r),
    }
}

/// Run `f` on a blocking thread (the lifecycle calls take locks, open the
/// mesh, prove and verify) inside the current span; a panic in `f` is a 500.
pub async fn blocking<T, F>(f: F) -> Result<T, Refusal>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, Refusal> + Send + 'static,
{
    let span = tracing::Span::current();
    tokio::task::spawn_blocking(move || span.in_scope(f))
        .await
        .unwrap_or_else(|e| {
            Err(Refusal::mpc_failure(format!(
                "the request handler failed: {e}"
            )))
        })
}

/// The body as text (400 if it is not UTF-8).
pub fn utf8(body: &Bytes) -> Result<&str, Refusal> {
    std::str::from_utf8(body).map_err(|e| Refusal::bad_request(format!("body: not UTF-8: {e}")))
}

/// A `{namespace}` path parameter (400 if it is not a field element).
pub fn namespace_param(text: &str) -> Result<Fr, Refusal> {
    fr_from_hex(text).map_err(|e| Refusal::bad_request(format!("path `namespace`: {e}")))
}

/// A contract manifest hash path parameter (400 naming it).
pub fn manifest_hash_param(text: &str) -> Result<Fr, Refusal> {
    fr_from_hex(text).map_err(|e| Refusal::bad_request(format!("path `manifest_hash`: {e}")))
}

/// The fallback of every router: an unknown path, or a known path under
/// another method, is 404 `not_found` in the one error shape, never a bare
/// status.
pub async fn unknown_route(method: axum::http::Method, uri: axum::http::Uri) -> Response {
    refusal(Refusal::not_found(format!(
        "no route {method} {}",
        uri.path()
    )))
}
