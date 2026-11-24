//! The running orchestrator: [`load`] builds it from a config and its CRS
//! (the registry copy, the node clients and the pins), [`start`] serves the
//! public API, [`sync_registry`] rebuilds the registry copy from the nodes,
//! and [`run`] is the whole process: the admin socket (`crate::admin`, the
//! pause and resume), the registry check at start and on its timer
//! (`crate::status`) and the tip's schedulers when the config has a `[tip]`
//! section. A scheduler task that stops (it runs for ever, so only a panic
//! stops it) stops the process with an error, for its supervisor to restart:
//! a namespace whose queue silently stopped would be worse.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use eyre::Context;
use rustls::ServerConfig;
use sidecar_core::crs::Crs;
use sidecar_http::listen::{self, ListenerLimits, TLS_HANDSHAKE_TIMEOUT};
use sidecar_http::tls;
use tokio::net::TcpListener;
use tokio::task::{JoinHandle, JoinSet};
use tokio_rustls::TlsAcceptor;

use crate::api::{self, Orchestrator};
use crate::config::{OrchestratorConfig, PublicTls};
use crate::nodes::Nodes;
use crate::registry::Registry;
use crate::status::{self, When};
use crate::sync::Synced;

/// The public listener's TLS: the orchestrator's server certificate, TLS 1.2
/// or 1.3, no client certificate asked, HTTP/1.1 only.
pub fn server_config(files: &PublicTls) -> eyre::Result<Arc<ServerConfig>> {
    tls::public_server_config(&files.cert, &files.key)
}

/// Build the orchestrator a config describes under `crs` (loaded as a node
/// sizes it): the registry copy, the node clients and the pinned keys.
pub fn load(config: &OrchestratorConfig, crs: Crs) -> eyre::Result<Orchestrator> {
    let registry = Registry::open(&config.registry.path, crs)?;
    let nodes = Nodes::new(config)?;
    Ok(
        Orchestrator::new(registry, nodes, config.pins(), config.sig_pks())
            .with_receipt_ttl(config.receipt_ttl_blocks),
    )
}

/// Rebuild the registry copy at `config.registry.path` from the three nodes
/// ([`crate::sync`]), with the config's node clients and the CRS.
pub async fn sync_registry(config: &OrchestratorConfig, crs: &Crs) -> eyre::Result<Synced> {
    let nodes = Nodes::new(config)?;
    crate::sync::sync_registry(&nodes, crs, &config.registry.path).await
}

/// A started orchestrator: its address. Dropping it stops the listener.
pub struct Running {
    pub addr: SocketAddr,
    task: JoinHandle<()>,
}

impl Running {
    /// Wait until the listener task ends (it does not, unless it panics).
    pub async fn wait(&mut self) {
        let _ = (&mut self.task).await;
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        self.task.abort();
    }
}

// Operator knob: DESIGN.md, "Configuration reference" (listener transport
// bounds). The public listener: the TLS handshake within 10 s, each request
// head within 30 s, at most 256 connections and 256 more in their handshake
// (`sidecar_http::listen::serve`).
/// The public listener's bounds.
pub const PUBLIC_LISTENER: ListenerLimits = ListenerLimits {
    tls_handshake: TLS_HANDSHAKE_TIMEOUT,
    header_read: Duration::from_secs(30),
    max_connections: 256,
    max_handshakes: 256,
};

/// Serve `app`'s public API on `listen` (port 0 picks a free port) under
/// `limits` ([`PUBLIC_LISTENER`] in the process).
pub async fn start(
    app: Arc<Orchestrator>,
    listen: SocketAddr,
    tls: Arc<ServerConfig>,
    limits: ListenerLimits,
) -> eyre::Result<Running> {
    let listener = TcpListener::bind(listen)
        .await
        .with_context(|| format!("binding the public API on {listen}"))?;
    let addr = listener.local_addr()?;
    // The shared connection loop: the connection cap, the TLS handshake
    // under a timeout, then HTTP/1.1 on the router with the head timeout.
    let task = tokio::spawn(listen::serve(
        listener,
        TlsAcceptor::from(tls),
        api::router(app),
        limits,
    ));
    tracing::info!(api = %addr, "orchestrator serving");
    Ok(Running { addr, task })
}

/// The whole process: load (after rebuilding the registry copy from the
/// nodes when `sync` is set), start, and run until interrupted.
pub async fn run(config: OrchestratorConfig, sync: bool, paused: bool) -> eyre::Result<()> {
    let tls = server_config(&config.tls)?;
    let crs = tokio::task::block_in_place(|| sidecar_core::crs::Crs::load(&config.crs))?;
    if sync {
        sync_registry(&config, &crs).await?;
    }
    let mut app = tokio::task::block_in_place(|| load(&config, crs))?;
    if paused {
        app = app.start_paused();
        tracing::info!("starting paused: `sidecar-orchestrator resume` starts scheduling");
    }
    let app = Arc::new(app);
    // The admin socket first: the operator can pause or read the status
    // while the start-up check waits on a slow node.
    let admin_path = config.admin_socket();
    let admin = tokio::spawn(crate::admin::serve(
        crate::admin::bind(&admin_path)?,
        app.clone(),
    ));
    tracing::info!(admin_socket = %admin_path.display(), "admin socket bound");
    status::check_registry(&app, When::Start).await;
    let rechecks = status::spawn_timer(app.clone(), config.registry.check_interval());
    // The tip's schedulers, one task per namespace; none without `[tip]`.
    let mut schedulers = match &config.tip {
        Some(tip) => crate::scheduler::spawn(app.clone(), tip)?,
        None => JoinSet::new(),
    };
    let mut running = start(app, config.listen, tls, PUBLIC_LISTENER).await?;
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let outcome = tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("interrupted; stopping");
            Ok(())
        }
        _ = terminate.recv() => {
            tracing::info!("terminated; stopping");
            Ok(())
        }
        _ = running.wait() => {
            tracing::warn!("the API listener stopped");
            Ok(())
        }
        Some(ended) = schedulers.join_next() => {
            let why = match ended {
                Err(e) => e.to_string(),
                Ok(()) => "it returned".to_string(),
            };
            tracing::error!(error = %why, "a scheduler task stopped; stopping the orchestrator");
            Err(eyre::eyre!("a scheduler task stopped: {why}"))
        }
    };
    rechecks.abort();
    admin.abort();
    let _ = std::fs::remove_file(&admin_path);
    schedulers.abort_all();
    outcome
}
