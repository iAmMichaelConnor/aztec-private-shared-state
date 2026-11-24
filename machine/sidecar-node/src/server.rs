//! The running node: its lifecycle context and mesh ([`App`]), the HTTPS API
//! listener, the admin socket, the pruning timer and the enc key retirement
//! timer ([`start`]), and the whole process from a config file ([`load`],
//! [`run`]).

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use eyre::Context;
use sidecar_core::Refusal;
use sidecar_core::crs::Crs;
use sidecar_core::mesh_lock::MeshHeld;
use sidecar_core::pipeline::{self, ChainRound, Node};
use sidecar_core::request::{ForNode, NodeRequest};
use sidecar_core::state::QueueRead;
use sidecar_core::store::Store;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;

use crate::backend::{self, NodeStore};
use crate::config::{NodeConfig, TipConfig};
use crate::mesh::Mesh;
use crate::receipt::{ReceiptChain, Receipts};
use crate::rotation::{self, KeyRotation};
use crate::session::Session;

// The node's clock, one seam for every time-dependent decision
// of the process. `App::now` reads it, and so do the enc rotation
// (`rotation::rotate_enc` stamps the rotation time), the retirement of the
// previous enc key (`rotation::retire_lapsed` compares the grace window with
// it) and the `requests` pruning job (`admin::prune` passes `App::now` to
// `Node::prune_requests`, which deletes the rows created before `now -
// retention`), so the three never disagree. It is the system clock
// (`pipeline::unix_now`) unless a test replaces it with `App::with_clock`;
// nothing in a running node sets it, and there is no setting for it. The
// `created_at` of a `requests` row is stamped inside the core's lifecycle with
// the system clock, not this one: a test that moves this clock moves the
// pruning cutoff against rows stamped at the real time. A node whose system
// clock is wrong prunes early or late and retires a previous enc key early or
// late; the three nodes need roughly the same time (NTP), as with any
// retention window.
/// The node's clock: the current time in unix seconds.
pub type Clock = Arc<dyn Fn() -> u64 + Send + Sync>;

/// One node's lifecycle context and its mesh, with what rotating its `enc`
/// key needs, its clock and its receipt signer.
pub struct App<S> {
    pub node: Node<S>,
    pub mesh: Mesh,
    pub rotation: KeyRotation,
    pub receipts: Receipts,
    clock: Clock,
}

impl<S: Store> App<S> {
    /// A node that rotates and retires its enc key with `rotation` (its key
    /// directory and grace window), on the system clock, with the default
    /// receipt settings and no receipt chain view (a node without `[tip]`,
    /// which refuses every receipt request).
    /// The node shares the mesh's session lock ([`Node::with_mesh_lock`]).
    pub fn new(node: Node<S>, mesh: Mesh, rotation: KeyRotation) -> Self {
        App {
            node: node.with_mesh_lock(mesh.lock().clone()),
            mesh,
            rotation,
            receipts: Receipts::default(),
            clock: Arc::new(sidecar_core::pipeline::unix_now),
        }
    }

    /// Sign receipts with `receipts` (its settings and chain view).
    pub fn with_receipts(mut self, receipts: Receipts) -> Self {
        self.receipts = receipts;
        self
    }

    /// Read the time from `clock` instead of the system clock (tests; see
    /// the comment at [`Clock`]).
    pub fn with_clock(mut self, clock: Clock) -> Self {
        self.clock = clock;
        self
    }

    /// The current time in unix seconds, from the node's clock.
    pub fn now(&self) -> u64 {
        (self.clock)()
    }

    /// The `connect` the lifecycle calls at step 10 (and REGISTER `seq` 0
    /// before its registration round): open the TLS mesh to the other two
    /// nodes while `held`, the node's mesh lock, is held. The lifecycle runs
    /// the handshake on it.
    pub fn connect_mesh(&self, held: &MeshHeld) -> Result<Session, Refusal> {
        Session::connect(&self.mesh, held)
    }
}

/// Where and how [`start`] serves.
pub struct StartOptions {
    /// The API address (port 0 picks a free port).
    pub api_listen: SocketAddr,
    pub tls: Arc<rustls::ServerConfig>,
    pub admin_socket: PathBuf,
    /// The pruning timer's interval; `None` turns it off.
    pub prune_interval: Option<Duration>,
}

/// A started node: its API address and admin socket. Dropping it stops the
/// listeners and the timer and removes the socket file.
pub struct Running {
    pub api_addr: SocketAddr,
    pub admin_socket: PathBuf,
    tasks: Vec<JoinHandle<()>>,
}

impl Running {
    /// Wait until a listener task ends (it does not, unless it panics).
    pub async fn wait(&mut self) {
        if let Some(task) = self.tasks.first_mut() {
            let _ = task.await;
        }
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
        let _ = std::fs::remove_file(&self.admin_socket);
    }
}

/// Serve `app`: the HTTPS API with mutual TLS on `opts.api_listen`, the admin
/// socket at `opts.admin_socket`, and the pruning timer. The node first
/// retires a previous enc key whose grace window has lapsed, then checks
/// again on the retirement timer.
pub async fn start<S: Store + 'static>(
    app: Arc<App<S>>,
    opts: StartOptions,
) -> eyre::Result<Running> {
    rotation::retire_once(app.clone()).await;
    let listener = TcpListener::bind(opts.api_listen)
        .await
        .with_context(|| format!("binding the API on {}", opts.api_listen))?;
    let api_addr = listener.local_addr()?;
    let admin = crate::admin::bind(&opts.admin_socket)?;
    let mut tasks = vec![
        tokio::spawn(sidecar_http::listen::serve(
            listener,
            TlsAcceptor::from(opts.tls),
            crate::api::router(app.clone()),
            crate::api::NODE_LISTENER,
        )),
        tokio::spawn(crate::admin::serve(admin, app.clone())),
    ];
    if let Some(interval) = opts.prune_interval {
        tasks.push(tokio::spawn(prune_timer(app.clone(), interval)));
    }
    tasks.push(tokio::spawn(rotation::retire_timer(
        app.clone(),
        app.rotation.check_interval,
    )));
    tracing::info!(
        party = app.node.index,
        api = %api_addr,
        admin_socket = %opts.admin_socket.display(),
        "node serving"
    );
    Ok(Running {
        api_addr,
        admin_socket: opts.admin_socket,
        tasks,
    })
}

// Every API handler runs on the runtime's shared blocking pool and may wait
// there on a round's namespace or mesh lock, so a client that holds the
// node-leg certificate can fill the pool with waiting executes. The admin
// socket's commands and the timers run on threads of their own instead, so
// they never queue behind those handlers for a pool thread (they may still
// wait on a lock a round holds, as any session does).
/// Run `f` on a thread of its own named `name`, in the runtime's context but
/// off its blocking pool; `Err` names the thread when `f` panicked.
pub async fn own_thread<T: Send + 'static>(
    name: &str,
    f: impl FnOnce() -> T + Send + 'static,
) -> Result<T, String> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    let runtime = tokio::runtime::Handle::current();
    std::thread::Builder::new()
        .name(name.to_string())
        .spawn(move || {
            let _context = runtime.enter();
            let _ = tx.send(f());
        })
        .map_err(|e| format!("spawning the {name} thread: {e}"))?;
    rx.await.map_err(|_| format!("the {name} thread panicked"))
}

/// The pruning job (`requests` by age, `receipts` by block): once at start,
/// then every `interval`.
async fn prune_timer<S: Store + 'static>(app: Arc<App<S>>, interval: Duration) {
    let mut ticks = tokio::time::interval(interval);
    ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        ticks.tick().await;
        let app = app.clone();
        let result = own_thread("node-prune", move || crate::admin::prune(&app)).await;
        match result {
            Ok(Ok(_)) => {}
            Ok(Err(r)) => tracing::warn!(error = %r, "the pruning job failed"),
            Err(e) => tracing::warn!(error = %e, "the pruning job panicked"),
        }
    }
}

/// Build the node a config describes: its keys and master share, its store,
/// the CRS, the retention window, the mesh and the enc grace window (which
/// REGISTER also checks a secret-shared receipt package's stale period against).
pub fn load(config: &NodeConfig) -> eyre::Result<App<NodeStore>> {
    let (keys, master) = crate::setup::load(&config.key_dir)?;
    build(config, keys, master)
}

/// Build a newcomer (a node replacing a departed one) from its config: its
/// keys from `setup --newcomer`, no master share yet (the zero pair until
/// the replacement installs the rebuilt one), an empty store. It is never
/// served before `sidecar-node replace-node` completes.
pub fn load_newcomer(config: &NodeConfig) -> eyre::Result<App<NodeStore>> {
    let keys = crate::setup::load_newcomer(&config.key_dir)?;
    let zero = sidecar_core::field::Fr::from(0u64);
    build(config, keys, sidecar_core::bind::Share::new(zero, zero))
}

fn build(
    config: &NodeConfig,
    keys: sidecar_core::keys::NodeKeys,
    master: sidecar_core::bind::Share,
) -> eyre::Result<App<NodeStore>> {
    let store = backend::open(&config.store)?;
    let crs = Crs::load(&config.crs)?;
    let mesh = Mesh::new(config.mesh()?);
    // The node's two lifecycle hooks, injected here. `admit`
    // (step 2) is sidecar-core's, which admits everything. The
    // chain verifier (step 4 under a queued intake) is the tip's
    // ([`TipHooks`]). Direct rounds never reach it.
    let TipHooks { verifier, receipts } = TipHooks::of(config)?;
    let (hook, persisted) = crate::recovery::unverified_store(&config.key_files())?;
    if let Some(why) = &persisted {
        tracing::warn!(
            mark = %why,
            "the store holds a resync import whose checks have not passed; no round is served \
             until a resync passes"
        );
    }
    let mut node = Node::new(config.party, keys, master, store, crs)?
        .with_admit(Box::new(sidecar_core::admit::admit::<ForNode>))
        .with_chain_verifier(verifier)
        .with_register_check(config.register_check())
        .with_state_holders(sidecar_tip::holders())
        .with_receipt_resync(sidecar_tip::receipt_resync())
        .with_unverified_store(hook, persisted);
    node.retention_secs = config.retention_secs();
    let rotation = KeyRotation::new(config.key_files(), config.enc_grace_secs());
    Ok(App::new(node, mesh, rotation).with_receipts(receipts))
}

/// What a node's `[tip]` section gives it: the step 4 chain verifier and the
/// receipt signer, both reading this node's own `[tip] aztec_node` (the
/// receipt signer and its pruning read the same Aztec node as the chain
/// verifier; see the comment at `ReceiptChain`). Without `[tip]` the
/// verifier refuses every queued round 400, so a node never runs a queued
/// round it did not check, and the signer refuses every receipt request.
/// Each holds a chain reader of its own on that Aztec node: a reader reports
/// a replaced block ([`sidecar_tip::ReadError::Pruned`]) to the one poll
/// that sees it and serialises its polls, so a shared reader would hand one
/// caller's prune report to the other and put the pruning job's polls in
/// the verifier's way.
struct TipHooks {
    verifier: pipeline::ChainVerifier,
    receipts: Receipts,
}

impl TipHooks {
    fn of(config: &NodeConfig) -> eyre::Result<Self> {
        Ok(match &config.tip {
            Some(tip) => TipHooks {
                verifier: chain_verifier(config.party, tip)?,
                receipts: Receipts::with_chain(config.receipt_config(), receipt_chain(tip)?),
            },
            None => TipHooks {
                verifier: Box::new(no_tip_section),
                receipts: Receipts::new(config.receipt_config()),
            },
        })
    }
}

/// The receipt chain view over the Aztec node of `tip`, reading the queues
/// of its namespaces where their contract manifests say.
pub fn receipt_chain(tip: &TipConfig) -> eyre::Result<Arc<dyn ReceiptChain>> {
    let view = sidecar_tip::ReceiptChainView::new(tip.aztec_node.transport()?, listed(tip))
        .context("starting the receipt chain view's runtime")?;
    Ok(Arc::new(view))
}

/// The namespaces a `[tip]` section lists.
fn listed(tip: &TipConfig) -> Vec<sidecar_core::field::Fr> {
    tip.namespaces.iter().map(|ns| ns.contract.fr()).collect()
}

/// Node `party`'s chain verifier over the Aztec node of `tip`, checking its
/// namespaces.
pub fn chain_verifier(party: usize, tip: &TipConfig) -> eyre::Result<pipeline::ChainVerifier> {
    let transport = tip.aztec_node.transport()?;
    let verifier = sidecar_tip::ChainVerifier::new(party, transport, listed(tip))
        .context("starting the chain verifier's runtime")?;
    tracing::info!(
        aztec_node = %sidecar_tip::url_origin(&tip.aztec_node.url),
        namespaces = tip.namespaces.len(),
        "chain verifier configured"
    );
    Ok(verifier.into_hook())
}

/// The step 4 hook of a node without a `[tip]` section.
fn no_tip_section(req: &NodeRequest, round: &ChainRound<'_>) -> Result<QueueRead, Refusal> {
    Err(Refusal::bad_request(format!(
        "chain verifier: this node has no [tip] section, so it reads no chain and runs no \
         queued round (circuit `{}`, request {})",
        round.manifest.circuit, req.request_id
    )))
}

/// The `serve` subcommand: load, start, and run until interrupted.
pub async fn run(config: NodeConfig) -> eyre::Result<()> {
    let tls = crate::tls::server_config(&config.tls)?;
    let app = Arc::new(tokio::task::block_in_place(|| load(&config))?);
    let loaded = app.node.keys();
    let keys = loaded.public_keys();
    tracing::info!(
        party = config.party,
        enc = %serde_json::to_string(&keys.enc)?,
        sig = %serde_json::to_string(&keys.sig)?,
        "node keys loaded"
    );
    if let (Some(id), Some(ends)) = (
        loaded.previous_key_id(),
        loaded.grace_ends_at(config.enc_grace_secs()),
    ) {
        tracing::info!(
            previous_key_id = %crate::rotation::key_id_hex(&id),
            retires_at = ends,
            "a previous enc key is kept for its grace window"
        );
    }
    let mut running = start(
        app,
        StartOptions {
            api_listen: config.api_listen,
            tls,
            admin_socket: config.admin_socket(),
            prune_interval: config.prune_interval(),
        },
    )
    .await?;
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {
        _ = tokio::signal::ctrl_c() => tracing::info!("interrupted; stopping"),
        _ = terminate.recv() => tracing::info!("terminated; stopping"),
        _ = running.wait() => tracing::warn!("the API listener stopped"),
    }
    Ok(())
}

#[cfg(test)]
mod own_thread_tests {
    use super::*;

    /// With the blocking pool's one thread held, a blocking task waits and
    /// work on its own thread runs at once.
    #[test]
    fn own_thread_runs_while_the_blocking_pool_is_full() {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .max_blocking_threads(1)
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let (release, wait) = std::sync::mpsc::channel::<()>();
            let held = tokio::task::spawn_blocking(move || wait.recv().ok());
            let queued = tokio::task::spawn_blocking(|| 1);
            let ran = tokio::time::timeout(Duration::from_secs(5), own_thread("test", || 7))
                .await
                .expect("its own thread waited for the pool");
            assert_eq!(ran, Ok(7));
            assert!(!queued.is_finished());
            release.send(()).unwrap();
            held.await.unwrap();
            assert_eq!(queued.await.unwrap(), 1);
            let panicked = own_thread("test", || panic!("boom")).await;
            assert_eq!(
                panicked,
                Err::<(), _>("the test thread panicked".to_string())
            );
        });
    }
}
