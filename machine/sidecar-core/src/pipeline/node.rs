//! The node context: its hooks, its locks, its circuit cache, and its
//! REGISTER and DISABLE under those locks.

use super::*;

// ---------------------------------------------------------------------------
// The node context
// ---------------------------------------------------------------------------

/// The step 2 hook: refuse a request before the namespace lock (fees, quotas,
/// further authentication). [`crate::admit::admit`] admits everything.
pub type AdmitHook = Box<dyn Fn(&NodeRequest) -> Result<(), Refusal> + Send + Sync>;

// The chain-verifier hook, the second hook the node injects
// (after `admit`). It runs at step 4 in place of the requester signature
// check, before the replay check, for packages whose manifest has a queued
// intake (the tip), and only for those: a chain-held record has no requester
// (its owner is enc_pk_i) and a queued manifest gives no key the state mode
// client, so there is no signature to check. It receives the request and
// the manifest with the package's shape and vk_hash, which is what
// re-deriving the chain request id and the machine request id needs
// (sidecar-tip `check_request_ids`), and a read-only view of this node's own
// rows ([`VerifierRows`]: its latest result per chain request id, for a
// pipelined request's state, and its stored receipts, for receipt-intake
// inputs).
// A refusal joins the session's handshake as this node's verdict
// (`refuse_in_session`, as every refusal at steps 2 to 9 does): the
// orchestrator runs no chain verifier, so it
// cannot refuse the request before fan-out, and one node whose view
// differs then refuses the round at all three within the handshake instead
// of leaving the other two to wait out the mesh connect timeout. The tip's
// node installs sidecar-tip's `verifier::ChainVerifier`, which re-reads the
// chain through its own Aztec node and refuses (400) a request whose head,
// inputs, ids, slot commitments or pinned values differ from its view; it
// may only refuse, never change the request, and it must not read anything
// the round's soundness depends on (invariant 13: a lying chain view can
// only delay). Default: [`chain_verifier_not_built`], which refuses every
// queued round 400, so a node that was not given a verifier never runs a
// queued round unchecked; in-process tests of the lifecycle alone inject an
// accepting stub. Moving it later than step 4 would let a request the chain
// does not hold load and open state first; giving it the power to rewrite a
// request would make the chain reader part of the trusted path.
/// What the step 4 hook is given about a queued package besides the
/// request: its manifest (the tip fields) and its queued intake, its shape
/// (the public-input indices of the commitments and pinned reads), its
/// vk_hash, and this node's own rows.
pub struct ChainRound<'a> {
    pub manifest: &'a Manifest,
    /// The manifest's intake: a round reaches the hook only under a queued one.
    pub intake: QueuedIntake,
    pub shape: &'a CircuitShape,
    pub vk_hash: Fr,
    /// The contract manifest version the package was resolved in: the one
    /// the request names, else the newest. The chain verifier refuses a
    /// round whose version the contract's pins do not name.
    pub manifest_hash: Fr,
    /// The namespace's stale period, from its contract manifest (`None`:
    /// a head is never skipped).
    pub stale_blocks: Option<u64>,
    /// This node's own rows, read-only.
    pub rows: &'a dyn VerifierRows,
}

/// What the step 4 hook may read of this node's store: the rows the chain
/// verifier compares a request with. Every [`Store`] is one.
pub trait VerifierRows {
    /// The latest `requests` row carrying `chain_request_id`
    /// ([`StoreRead::chain_request`]).
    fn chain_request(
        &self,
        namespace: Fr,
        chain_request_id: Fr,
    ) -> Result<Option<RequestRow>, Refusal>;

    /// The `receipts` row of the chain request ([`Store::receipt`]).
    fn receipt(&self, namespace: Fr, chain_request_id: Fr) -> Result<Option<ReceiptRow>, Refusal>;

    /// Every `tip_versions` row of a node-held tip key
    /// ([`StoreRead::tip_versions`]).
    fn tip_versions(&self, namespace: Fr, key: &str) -> Result<Vec<TipVersion>, Refusal>;

    /// One node of a tree-valued key's clear tree ([`StoreRead::tip_node`]).
    fn tip_node(&self, namespace: Fr, key: &str, hash: Fr) -> Result<Option<TreeNode>, Refusal>;

    /// The namespace's newest contract manifest ([`StoreRead::contract_manifest`]).
    fn contract_manifest(&self, namespace: Fr) -> Result<Option<ManifestRow>, Refusal>;

    /// Every contract manifest version the namespace holds, newest first
    /// ([`StoreRead::contract_manifests`]).
    fn contract_manifests(&self, namespace: Fr) -> Result<Vec<ManifestRow>, Refusal>;
}

impl<S: Store> VerifierRows for S {
    fn chain_request(
        &self,
        namespace: Fr,
        chain_request_id: Fr,
    ) -> Result<Option<RequestRow>, Refusal> {
        StoreRead::chain_request(self, namespace, chain_request_id)
    }

    fn receipt(&self, namespace: Fr, chain_request_id: Fr) -> Result<Option<ReceiptRow>, Refusal> {
        Store::receipt(self, namespace, chain_request_id)
    }

    fn tip_versions(&self, namespace: Fr, key: &str) -> Result<Vec<TipVersion>, Refusal> {
        StoreRead::tip_versions(self, namespace, key)
    }

    fn tip_node(&self, namespace: Fr, key: &str, hash: Fr) -> Result<Option<TreeNode>, Refusal> {
        Ok(StoreRead::tip_node(self, namespace, key, hash)?.map(|n| n.node))
    }

    fn contract_manifest(&self, namespace: Fr) -> Result<Option<ManifestRow>, Refusal> {
        StoreRead::contract_manifest(self, namespace)
    }

    fn contract_manifests(&self, namespace: Fr) -> Result<Vec<ManifestRow>, Refusal> {
        StoreRead::contract_manifests(self, namespace)
    }
}

/// The step 4 hook under a queued intake: the node's chain verifier, which
/// re-reads the chain through the node's own Aztec node and refuses (400) a
/// synthesised request that differs from its view; it returns what it read
/// (the block, the head, the entry's index and each slot with the old
/// commitment the round runs on), which the tip's holders load and commit
/// against.
pub type ChainVerifier =
    Box<dyn Fn(&NodeRequest, &ChainRound<'_>) -> Result<QueueRead, Refusal> + Send + Sync>;

/// What the default chain verifier answers.
pub const CHAIN_VERIFIER_NOT_BUILT: &str = "chain verifier not built";

/// The default step 4 hook: refuses every queued round (400,
/// [`CHAIN_VERIFIER_NOT_BUILT`]), so a node without a chain verifier runs no
/// queued round. Nothing is loaded or stored before it.
pub fn chain_verifier_not_built(
    req: &NodeRequest,
    round: &ChainRound<'_>,
) -> Result<QueueRead, Refusal> {
    Err(Refusal::bad_request(format!(
        "circuit `{}` has a queued intake: {CHAIN_VERIFIER_NOT_BUILT} on this node, \
         so it cannot check request {} against the chain and runs no queued round",
        round.manifest.circuit, req.request_id
    )))
}

/// Persists the mark of a store that holds an import whose checks have not
/// passed ([`Node::mark_unverified`]): `Some(why)` before a resync imports,
/// `None` once its checks passed. The default persists nothing.
pub type UnverifiedHook = Box<dyn Fn(Option<&str>) -> Result<(), Refusal> + Send + Sync>;

/// One per-namespace lock set, the node-wide mesh lock and the maintenance
/// sessions running at the node.
#[derive(Default)]
struct Locks {
    held: Mutex<BTreeSet<Fr>>,
    released: Condvar,
    mesh: MeshLock,
    maintenance: Mutex<Vec<&'static str>>,
}

impl Locks {
    fn namespace(&self, namespace: Fr) -> NamespaceGuard<'_> {
        let mut held = self.held.lock().unwrap_or_else(PoisonError::into_inner);
        while held.contains(&namespace) {
            held = self
                .released
                .wait(held)
                .unwrap_or_else(PoisonError::into_inner);
        }
        held.insert(namespace);
        NamespaceGuard {
            locks: self,
            namespace,
        }
    }

    /// Every lock of `namespaces`, taken one at a time in ascending order:
    /// two takers of several locks never wait on each other in a cycle.
    fn namespaces(&self, namespaces: impl IntoIterator<Item = Fr>) -> NamespacesGuard<'_> {
        let sorted: BTreeSet<Fr> = namespaces.into_iter().collect();
        NamespacesGuard {
            held: sorted
                .into_iter()
                .map(|ns| (ns, self.namespace(ns)))
                .collect(),
        }
    }

    fn mesh(&self) -> MeshHeld<'_> {
        self.mesh.acquire()
    }

    fn maintain(&self, what: &'static str, namespaces: Vec<Fr>) -> Maintenance<'_> {
        self.maintenance
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(what);
        let flag = MaintenanceFlag { locks: self, what };
        let namespaces = self.namespaces(namespaces);
        Maintenance {
            mesh: self.mesh(),
            namespaces,
            _flag: flag,
        }
    }

    fn maintenance(&self) -> Option<&'static str> {
        self.maintenance
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .first()
            .copied()
    }
}

/// A held namespace lock; dropping it releases the namespace.
pub struct NamespaceGuard<'a> {
    locks: &'a Locks,
    namespace: Fr,
}

impl Drop for NamespaceGuard<'_> {
    fn drop(&mut self) {
        let mut held = self
            .locks
            .held
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        held.remove(&self.namespace);
        self.locks.released.notify_all();
    }
}

/// Several held namespace locks ([`Node::lock_namespaces`]); dropping it
/// releases them all.
pub struct NamespacesGuard<'a> {
    held: BTreeMap<Fr, NamespaceGuard<'a>>,
}

impl NamespacesGuard<'_> {
    /// 500 unless this guard holds `namespace`'s lock: a namespace
    /// registered after the locks were taken is refused, not read unlocked.
    pub fn require(&self, namespace: Fr) -> Result<(), Refusal> {
        if self.held.contains_key(&namespace) {
            Ok(())
        } else {
            Err(Refusal::mpc_failure(format!(
                "namespace {} was not locked when this session started (registered since?); \
                 run it again",
                fr_to_hex(namespace)
            )))
        }
    }
}

/// A maintenance session's mark at the node; dropping it removes the mark.
struct MaintenanceFlag<'a> {
    locks: &'a Locks,
    what: &'static str,
}

impl Drop for MaintenanceFlag<'_> {
    fn drop(&mut self) {
        let mut running = self
            .locks
            .maintenance
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(at) = running.iter().position(|w| *w == self.what) {
            running.remove(at);
        }
    }
}

/// What a node holds while it runs a maintenance session (a resync or a
/// replacement, [`Node::maintain`]): the maintenance mark, which refuses new
/// rounds, every lock of the namespaces the session reads or writes, and the
/// mesh lock. Dropping it releases the mesh, then the namespaces, then the
/// mark.
pub struct Maintenance<'a> {
    // field order is drop order
    mesh: MeshHeld<'a>,
    namespaces: NamespacesGuard<'a>,
    _flag: MaintenanceFlag<'a>,
}

impl<'a> Maintenance<'a> {
    /// The mesh lock this session holds, which opening its mesh takes.
    pub fn mesh(&self) -> &MeshHeld<'a> {
        &self.mesh
    }

    /// The namespace locks this session holds.
    pub fn namespaces(&self) -> &NamespacesGuard<'a> {
        &self.namespaces
    }
}

/// A registered circuit as a round runs it: the parsed manifest, its shape,
/// and the circuit with its vk.
pub struct LoadedPackage {
    /// The manifest the round runs.
    pub manifest: Manifest,
    pub shape: CircuitShape,
    /// The holder of each key the manifest loads or stores.
    pub holding: Holding,
    pub circuit: Arc<Circuit>,
    /// The `seq` of the `packages` row it was loaded from.
    pub seq: u64,
}

/// Everything one node brings to the lifecycle besides the request: its index,
/// keys, master share (for the registration circuit only), store, CRS, the
/// state modes it serves, the circuits it has loaded, its locks and its hooks.
pub struct Node<S> {
    /// This node's index (0, 1, 2): its party id on the mesh and the `i` it signs.
    pub index: usize,
    // The node keys; replaced whole by an enc rotation or a retirement
    // ([`Node::set_keys`]), read once per request ([`Node::keys`]).
    keys: RwLock<Arc<NodeKeys>>,
    // This node's master nullifier share; the registration circuit is the
    // only circuit that reads it. Replaced whole by a node replacement's share refresh or
    // a newcomer's import ([`Node::set_master`]), read per use
    // ([`Node::master`]).
    master: RwLock<Share>,
    pub store: S,
    pub crs: Crs,
    /// The embedded registration circuit under `crs`.
    pub registration: Circuit,
    /// How long `requests` rows are kept, in seconds ([`Node::prune_requests`]).
    pub retention_secs: u64,
    pub(super) admit: AdmitHook,
    pub(super) chain_verifier: ChainVerifier,
    register_check: RegisterHook,
    // Which receipt rows a resync sends and how it keeps copied ones.
    receipt_resync: ReceiptResyncHook,
    // The state modes this node serves: REGISTER refuses any other, and each
    // loaded package keeps the holder of each of its keys.
    holders: StateHolders,
    // Circuits loaded from `packages` rows, by (namespace, name), each with the
    // seq and vk_hash of the row it was loaded from; a re-registered name is
    // reloaded (see the comment at `Node::loaded`).
    pub(super) circuits: Mutex<BTreeMap<(Fr, Fr, String), Arc<LoadedPackage>>>,
    locks: Locks,
    // Why this node's store is not to be served: it holds a resync import
    // whose checks have not passed (`mark_unverified`).
    unverified: Mutex<Option<String>>,
    unverified_hook: UnverifiedHook,
}

impl<S: Store> Node<S> {
    /// A node with the default hooks (`admit` admits everything; the chain
    /// verifier refuses every queued round, [`chain_verifier_not_built`];
    /// REGISTER adds no check of the node's own; a resync carries no receipt
    /// row, [`NoReceiptResync`]),
    /// the core state holders ([`StateHolders::core`]: client- and node-held
    /// state on the sidecar path) and the default retention. Builds the
    /// registration circuit's vk under `crs`.
    pub fn new(
        index: usize,
        keys: NodeKeys,
        master: Share,
        store: S,
        crs: Crs,
    ) -> eyre::Result<Self> {
        assert!(index < NODES, "node index {index} out of range");
        let registration = registry::registration_circuit(&crs)?;
        Ok(Node {
            index,
            keys: RwLock::new(Arc::new(keys)),
            master: RwLock::new(master),
            store,
            crs,
            registration,
            retention_secs: DEFAULT_REQUESTS_RETENTION_SECS,
            admit: Box::new(crate::admit::admit::<ForNode>),
            chain_verifier: Box::new(chain_verifier_not_built),
            register_check: Box::new(registry::no_register_check),
            receipt_resync: Arc::new(NoReceiptResync),
            holders: StateHolders::core(),
            circuits: Mutex::new(BTreeMap::new()),
            locks: Locks::default(),
            unverified: Mutex::new(None),
            unverified_hook: Box::new(|_| Ok(())),
        })
    }

    /// Persist the unverified-store mark with `hook`, and start with the mark
    /// `persisted` (what an earlier run left).
    pub fn with_unverified_store(
        mut self,
        hook: UnverifiedHook,
        persisted: Option<String>,
    ) -> Self {
        self.unverified_hook = hook;
        self.unverified = Mutex::new(persisted);
        self
    }

    /// Share the node-wide mesh session lock `lock` with the mesh this node
    /// connects (sidecar-node's `Mesh`), whose sessions take it.
    pub fn with_mesh_lock(mut self, lock: MeshLock) -> Self {
        self.locks.mesh = lock;
        self
    }

    /// Replace the step 2 admission hook.
    pub fn with_admit(mut self, hook: AdmitHook) -> Self {
        self.admit = hook;
        self
    }

    /// Replace the step 4 chain verifier, run for queued manifests.
    pub fn with_chain_verifier(mut self, hook: ChainVerifier) -> Self {
        self.chain_verifier = hook;
        self
    }

    /// Replace the node's own REGISTER check ([`RegisterHook`]).
    pub fn with_register_check(mut self, hook: RegisterHook) -> Self {
        self.register_check = hook;
        self
    }

    /// Replace how a resync carries this node's receipt rows
    /// ([`crate::resync::ReceiptResync`]; sidecar-tip's `receipt_resync()` carries receipt
    /// intake's rows).
    pub fn with_receipt_resync(mut self, hook: ReceiptResyncHook) -> Self {
        self.receipt_resync = hook;
        self
    }

    /// How a resync carries this node's receipt rows.
    pub fn receipt_resync(&self) -> ReceiptResyncHook {
        self.receipt_resync.clone()
    }

    /// Replace the state modes this node serves (sidecar-tip's `holders()`
    /// adds the tip's node-held and chain-held state to the core ones).
    pub fn with_state_holders(mut self, holders: StateHolders) -> Self {
        self.holders = holders;
        self
    }

    /// The state modes this node serves.
    pub fn holders(&self) -> StateHolders {
        self.holders.clone()
    }

    // The lock scope. A node holds one lock per namespace for the
    // whole of a request (execute from step 3 to the end of step 15, every
    // registry body, a rollback), so no two rounds of one namespace interleave
    // their reads and commit, and one node-wide mesh lock from connecting the
    // mesh (step 10) to the end of the round, because the mesh has one session
    // port per node and a second concurrent session cannot connect. The
    // namespace lock is always taken first, so the two never deadlock; a round
    // refused at step 1 never holds the mesh, and one answered from its row at
    // step 5 or refused at steps 2 to 9 holds it for the handshake only
    // (see `replay_in_session` and `refuse_in_session`). Requests of two
    // namespaces run concurrently up to the mesh and then one at a time; the
    // orchestrator serialises sessions globally anyway. More parallel rounds
    // need one mesh port per concurrent session; per-queue locks at the tip
    // would come with sharding. A session that needs several namespaces (a
    // resync, a replacement, a registry resync) takes all their locks in
    // ascending order before the mesh lock ([`Node::lock_namespaces`],
    // [`Node::maintain`]), never one under the mesh.
    /// Take the namespace lock, waiting while another request holds it.
    pub fn lock_namespace(&self, namespace: Fr) -> NamespaceGuard<'_> {
        self.locks.namespace(namespace)
    }

    /// Take the locks of every namespace of `namespaces`, in ascending order
    /// (the only order in which a holder of one namespace lock and a taker of
    /// several cannot deadlock). Take them before the mesh lock.
    pub fn lock_namespaces(&self, namespaces: impl IntoIterator<Item = Fr>) -> NamespacesGuard<'_> {
        self.locks.namespaces(namespaces)
    }

    /// Take the node-wide mesh session lock ([`MeshLock`]).
    pub fn lock_mesh(&self) -> MeshHeld<'_> {
        self.locks.mesh()
    }

    // A maintenance session (a resync, a node replacement) reads and writes
    // every namespace it names over one mesh session, so it holds their
    // locks and the mesh lock for the whole session, taken in the lock
    // order (the namespaces ascending, then the mesh). It first marks the
    // node, and a round that arrives while the mark is set is refused at
    // once (500, retry later; see `check_serving`) instead of queueing on a
    // namespace lock until the session ends. A round already past that
    // check finishes or fails before the session takes its namespace.
    /// Mark this node as running the maintenance session `what` (a resync or
    /// a replacement), then take every lock of `namespaces` (ascending) and
    /// the mesh lock. Rounds are refused while the result is held.
    pub fn maintain(&self, what: &'static str, namespaces: Vec<Fr>) -> Maintenance<'_> {
        self.locks.maintain(what, namespaces)
    }

    /// 500 while a maintenance session runs at this node ([`Node::maintain`]),
    /// and while its store is marked unverified ([`Node::mark_unverified`]):
    /// checked by every call that writes the store or signs (a round,
    /// REGISTER, DISABLE, a receipt).
    pub fn check_serving(&self) -> Result<(), Refusal> {
        if let Some(what) = self.locks.maintenance() {
            return Err(Refusal::mpc_failure(format!(
                "node {} is running a {what}; rounds resume when it ends",
                self.index
            )));
        }
        match &*self
            .unverified
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
        {
            None => Ok(()),
            Some(why) => Err(Refusal::mpc_failure(format!(
                "node {}'s store holds {why} whose checks have not passed; it serves no round \
                 until a resync's checks pass",
                self.index
            ))),
        }
    }

    // A resync imports before it checks (the checks read the imported rows),
    // so the importing node marks its store first, persisted through the
    // hook (sidecar-node: a file in the key directory), and clears the mark
    // only when every check passed. A failed check, or a crash in between,
    // leaves a node that refuses every round, after a restart too, until a
    // resync passes.
    /// Mark this node's store as holding `why` (an import whose checks have
    /// not passed), or clear the mark with `None`: persisted first, then
    /// kept for [`Node::check_serving`].
    pub fn mark_unverified(&self, why: Option<&str>) -> Result<(), Refusal> {
        (self.unverified_hook)(why)?;
        *self
            .unverified
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = why.map(str::to_string);
        Ok(())
    }

    // How a running node changes its keys. The keys sit behind a
    // lock as one immutable value; an enc rotation or the retirement of the
    // previous enc key replaces the whole value (`set_keys`), and every
    // request, registry body and rollback takes one snapshot (`keys`) when it
    // starts and uses it to the end. So the two binds of a round, its opens
    // and its seals all see the same keys even when a rotation or a
    // retirement lands mid-round; the next request sees the new keys. The
    // lock is held only to clone or swap one pointer, never during a round.
    // Persisting the keys is the caller's job (sidecar-node writes the key
    // files before it calls `set_keys`).
    /// This node's keys as they are now: one snapshot, for one request.
    pub fn keys(&self) -> Arc<NodeKeys> {
        self.keys
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Replace this node's keys (an enc rotation, or the end of its grace
    /// window). Requests already running keep the keys they started with.
    pub fn set_keys(&self, keys: NodeKeys) {
        *self.keys.write().unwrap_or_else(PoisonError::into_inner) = Arc::new(keys);
    }

    /// This node's master nullifier share as it is now.
    pub fn master(&self) -> Share {
        *self.master.read().unwrap_or_else(PoisonError::into_inner)
    }

    /// Replace this node's master share: the share refresh of a node
    /// replacement at a remaining node, or the newcomer's imported pair.
    /// Persisting it is the caller's job (sidecar-node writes
    /// `master.share` before it calls this).
    pub fn set_master(&self, master: Share) {
        *self.master.write().unwrap_or_else(PoisonError::into_inner) = master;
    }

    /// What the registry functions need from this node, with `keys` its
    /// snapshot of the node keys ([`Node::keys`]).
    pub fn registry_node<'a>(&'a self, keys: &'a NodeKeys) -> RegistryNode<'a> {
        RegistryNode {
            index: self.index,
            keys,
            master: self.master(),
            crs: &self.crs,
            registration: &self.registration,
            holders: self.holders.clone(),
            register_check: &*self.register_check,
        }
    }

    // The order of a REGISTER on a node, as in the request
    // lifecycle: every check that needs no mesh runs first, under the
    // namespace lock (section 4 steps 2 and 3: owner, seq, manifest, name; and
    // step 4's vk and vk_hash), then, for a `seq` 0 body only, the session:
    // the mesh lock, the handshake, the registration circuit, and last the
    // commit. A `seq` 0 body this node refuses at those checks still joins
    // the session's handshake, with its refusal as its verdict: the other two
    // nodes, which may have passed their checks (their stores or their copies
    // of the body differ from this one's), then refuse 400 at the handshake,
    // naming this node and its reason, instead of running a registration
    // round this node never joins and failing with a 500 after the mesh
    // times out. The refusing node runs no circuit and stores nothing; if it
    // cannot reach the mesh it answers its own refusal anyway. Running the
    // checks after the handshake would let one node's 403 or 409 strand the
    // other two in the circuit.
    /// REGISTER on this node under its locks: the namespace lock, the checks
    /// that need no mesh ([`registry::check_register`]), and for a `seq` 0
    /// body then the mesh lock, `connect`, the handshake and the registration
    /// round ([`registry::finish_register`]).
    pub fn register<N, R>(
        &self,
        body: &Signed<ManifestMessage>,
        connect: impl FnOnce(&MeshHeld) -> Result<N, Refusal>,
        rng: &mut R,
    ) -> Result<ManifestAnswer, Refusal>
    where
        N: Network,
        R: RngCore + CryptoRng,
    {
        let _namespace = self.lock_namespace(body.body.namespace.fr());
        let keys = self.keys();
        let node = self.registry_node(&keys);
        let checked = self
            .check_serving()
            .and_then(|()| registry::check_register(&self.store, &node, body));
        if body.body.seq != 0 {
            return registry::finish_register(&self.store, &node, checked?, None::<&N>, rng);
        }
        // The registration session opens with the same handshake as a round's
        // step 10: no shared summands (the master shares are the nodes' own),
        // the namespace in place of a request id and the REGISTER body's
        // signed message as its body hash, so the three nodes run one body.
        let handshake =
            Handshake::build(RequestId(body.body.namespace.fr()), body.message, &[], &[]);
        let mesh = self.lock_mesh();
        match checked {
            Ok(checked) => {
                let net = connect(&mesh)?;
                handshake::exchange(&net, &handshake)?;
                registry::finish_register(&self.store, &node, checked, Some(&net), rng)
            }
            Err(refusal) => Err(match connect(&mesh) {
                Ok(net) => handshake::exchange_refusing(&net, &handshake, refusal),
                Err(_) => refusal,
            }),
        }
    }

    /// DISABLE on this node under its namespace lock ([`registry::disable`]),
    /// which every registry body takes (ARCHITECTURE.md section 4).
    pub fn disable<R: RngCore + CryptoRng>(
        &self,
        body: &Signed<DisableRequest>,
        rng: &mut R,
    ) -> Result<DisableAnswer, Refusal> {
        let _namespace = self.lock_namespace(body.body.namespace.fr());
        self.check_serving()?;
        let keys = self.keys();
        registry::disable(&self.store, &self.registry_node(&keys), body, rng)
    }

    // Operator knob: DESIGN.md, "Configuration reference" (sidecar-node
    // `requests_retention_days`, which sets `retention_secs`). The node's
    // pruning job calls this with the current time; the consumed set is never
    // pruned.
    /// Delete the `requests` rows older than the retention window at `now`
    /// (unix seconds); returns how many.
    pub fn prune_requests(&self, now: u64) -> Result<usize, Refusal> {
        self.store
            .prune_requests(now.saturating_sub(self.retention_secs))
    }

    // The per-namespace circuit cache. A node keeps, per
    // (namespace, contract manifest version, circuit name), what a round needs of a registered circuit
    // besides its proving key: the parsed manifest and shape, the ACIR program
    // and constraint system, and the verification key. An entry is filled from
    // the `packages` row alone on the first request that names the circuit
    // after the node starts, and is reused only while the row has the seq and
    // vk_hash the entry was loaded from, so the next round after any registry
    // body rewrote the row reloads it. The key is the row's seq, not the
    // vk_hash alone: a REGISTER of a disabled name may bring the same circuit
    // with another manifest (the same vk_hash at the next seq), and the
    // manifest carries the state modes, consume policies and witness sources
    // every round runs under. Every write of the row (REGISTER, DISABLE)
    // stores the body's seq, which the namespace advances, whereas a hash of
    // the manifest would miss a changed circuit JSON (its ABI) under the same
    // vk. The vk is decoded from the bytes REGISTER stored and checked against
    // the row's vk_hash, never rebuilt, so the first round after a start or a
    // re-registration pays parsing only, not the vk build (an MSM over the
    // whole circuit, seconds for a large one). The proving key is not cached:
    // co-noir builds it from each round's shared witness inside the round
    // (step 11). Memory: per circuit used since the start, the program and
    // constraint system (a few times the circuit JSON) plus a 3.7 kB vk;
    // entries are never evicted (a re-registered name replaces its own, a
    // disabled one stays until restart). The stored vk is trusted as REGISTER
    // wrote it: a damaged key that still hashes to its vk_hash cannot exist,
    // and a damaged circuit JSON fails self-verification (step 11) instead of
    // committing. Tests rebuild every stored vk once to check that REGISTER
    // stored what the circuit computes.
    /// The package a request names, with its circuit: from the cache when the
    /// stored package has the seq and vk_hash the cached one was loaded from,
    /// else loaded from the row with its stored vk (500 if the row's vk does not
    /// decode or hash to its vk_hash).
    pub(super) fn loaded(
        &self,
        namespace: Fr,
        pkg: &PackageRow,
    ) -> Result<Arc<LoadedPackage>, Refusal> {
        let key = (namespace, pkg.manifest_hash, pkg.name.clone());
        let mut cache = self.circuits.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(hit) = cache.get(&key)
            && hit.seq == pkg.seq
            && hit.circuit.vk_hash == pkg.vk_hash
        {
            return Ok(hit.clone());
        }
        let (manifest, shape) = pkg.parse()?;
        let holding = self.holders.choose(&manifest)?;
        let artifact = Artifact::from_json(&pkg.name, &pkg.circuit_json).map_err(|e| {
            Refusal::mpc_failure(format!(
                "store: circuit `{}` does not load: {e:#}",
                pkg.name
            ))
        })?;
        let circuit = Circuit::with_stored_vk(artifact, &pkg.vk, pkg.vk_hash)
            .map_err(|e| Refusal::mpc_failure(format!("store: {e:#}")))?;
        let loaded = Arc::new(LoadedPackage {
            manifest,
            shape,
            holding,
            circuit: Arc::new(circuit),
            seq: pkg.seq,
        });
        cache.insert(key, loaded.clone());
        Ok(loaded)
    }
}

/// The current time in unix seconds, as the `requests` row's created_at.
pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use std::sync::{Arc, Barrier};

    /// A round holds namespace 1's lock and then waits for the mesh, while a
    /// maintenance session over namespaces 2 and 1 starts: the session takes
    /// its namespace locks before the mesh, so it waits for the round, and
    /// both finish. A session that took the mesh first would wait on
    /// namespace 1 under the mesh, and the round on the mesh, for ever.
    #[test]
    fn a_maintenance_session_and_a_round_never_deadlock() {
        let locks = Arc::new(Locks::default());
        let start = Arc::new(Barrier::new(2));
        let (done, finished) = mpsc::channel();
        let round = {
            let (locks, start, done) = (locks.clone(), start.clone(), done.clone());
            std::thread::spawn(move || {
                let _ns = locks.namespace(Fr::from(1u64));
                start.wait();
                // let the session reach its first lock
                std::thread::sleep(Duration::from_millis(200));
                let _mesh = locks.mesh();
                done.send("round").unwrap();
            })
        };
        let session = std::thread::spawn(move || {
            start.wait();
            let held = locks.maintain("replacement", vec![Fr::from(2u64), Fr::from(1u64)]);
            assert_eq!(locks.maintenance(), Some("replacement"));
            held.namespaces().require(Fr::from(1u64)).unwrap();
            assert!(held.namespaces().require(Fr::from(3u64)).is_err());
            drop(held);
            assert_eq!(locks.maintenance(), None);
            done.send("session").unwrap();
        });
        let mut seen = Vec::new();
        for _ in 0..2 {
            seen.push(
                finished
                    .recv_timeout(Duration::from_secs(10))
                    .expect("the round and the session deadlocked"),
            );
        }
        assert_eq!(seen, ["round", "session"]);
        round.join().unwrap();
        session.join().unwrap();
    }
}
