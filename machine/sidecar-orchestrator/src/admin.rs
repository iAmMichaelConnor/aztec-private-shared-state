//! The orchestrator's operator-only admin socket (`sidecar_http::admin`: a
//! Unix domain socket, never served by a TLS listener, its directory 0700 and
//! the socket 0600), carrying the pause and resume of scheduling around a
//! node replacement (docs/ARCHITECTURE.md section 6, "Node replacement and
//! key epochs"; [`Orchestrator::pause`]) and the latest registry check with
//! the rows that differ, which `GET /v1/status` only counts. Plain JSON, one
//! object per line each way:
//!
//! ```text
//! -> {"op": "pause"}
//! <- {"ok": true, "paused": true}
//! -> {"op": "resume"}
//! <- {"ok": true, "paused": false, "registry": {"compared_at": 1790000000,
//!       "agreement": {"check": {..}, "between_nodes": 0, "copy_only": 0}}}
//! <- {"ok": false, "paused": true, "refusal": {"class": "conflict", "error": "resume: .."}}
//! -> {"op": "status"}
//! <- {"ok": true, "paused": false, "registry": {"compared_at": 1790000000,
//!       "agreement": {"check": {"namespaces": 1, "packages": 2, "divergences": [..]},
//!                     "between_nodes": 1, "copy_only": 0}}}
//! ```
//!
//! `sidecar-orchestrator pause`, `resume` and `status` are its clients.

use std::path::Path;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use sidecar_core::Refusal;
use tokio::net::UnixListener;

use crate::api::Orchestrator;
use crate::status::RegistryReport;

/// One admin command.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum AdminRequest {
    /// Pause scheduling between rounds; answers once the session in flight
    /// has ended.
    Pause,
    /// Resume, once the registry check finds the nodes alike.
    Resume,
    /// Whether scheduling is paused, and the latest registry check whole.
    Status,
}

/// The answer to one admin command.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminResponse {
    pub ok: bool,
    pub paused: bool,
    /// The registry check a resume ran, or for `status` the latest one
    /// (absent before the first).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registry: Option<RegistryReport>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refusal: Option<Refusal>,
}

/// Bind the admin socket at `path` ([`sidecar_http::admin::bind`]).
pub fn bind(path: &Path) -> eyre::Result<UnixListener> {
    sidecar_http::admin::bind(path, "orchestrator")
}

/// Serve admin commands on `listener` until the task is aborted.
pub async fn serve(listener: UnixListener, app: Arc<Orchestrator>) {
    sidecar_http::admin::serve(listener, move |req: Result<AdminRequest, Refusal>| {
        let app = app.clone();
        async move {
            match req {
                Ok(req) => handle(&app, req).await,
                Err(refusal) => AdminResponse {
                    ok: false,
                    paused: app.paused(),
                    registry: None,
                    refusal: Some(refusal),
                },
            }
        }
    })
    .await
}

/// Run one admin command.
pub async fn handle(app: &Orchestrator, req: AdminRequest) -> AdminResponse {
    let answer = |registry: Option<RegistryReport>, refusal: Option<Refusal>| AdminResponse {
        ok: refusal.is_none(),
        paused: app.paused(),
        registry,
        refusal,
    };
    match req {
        AdminRequest::Pause => {
            app.pause().await;
            answer(None, None)
        }
        AdminRequest::Resume => match app.resume().await {
            Ok(report) => answer(Some(report), None),
            Err(refusal) => answer(None, Some(refusal)),
        },
        AdminRequest::Status => answer(app.registry.agreement(), None),
    }
}

/// Send one command to the admin socket at `path` and read the answer
/// (blocking).
pub fn call(path: &Path, req: &AdminRequest) -> eyre::Result<AdminResponse> {
    sidecar_http::admin::call(path, "orchestrator's", req)
}
