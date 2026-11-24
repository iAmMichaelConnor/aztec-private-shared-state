//! What the tip suites share: three real nodes, each with its real chain
//! verifier (counting what it accepts, recording what it receives) and its
//! receipt signer over its own view of sidecar-tip's in-memory Aztec node,
//! and the orchestrator over them; a test namespace's description
//! ([`TipEntry`]: the mock contract's slots and each package's request
//! keys), from which its contract manifest is generated, so the scheduler
//! and each node's verifier read it from the registered manifest as in
//! production; the mock contract's clock, queue, intake, `apply` and
//! `skip()`; a result's public inputs read by name through its circuit's
//! shape; and the scheduler's step.

use std::collections::BTreeMap;
use std::ops::Deref;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use serde_json::{Value, json};
use sidecar_core::abi::CircuitShape;
use sidecar_core::bind::Elem;
use sidecar_core::field::{FieldHex, Fr, RequestId, fr_from_hex, fr_to_hex};
use sidecar_core::grumpkin::{Point, point_from_wire};
use sidecar_core::pipeline::result_message;
use sidecar_core::register::{ManifestMessage, ManifestResponse};
use sidecar_core::request::{Request, StateKeys};
use sidecar_core::response::ExecuteResponse;
use sidecar_core::store::{MemorySnapshot, StoreRead, TipVersion, VersionStatus, VersionTree};
use sidecar_core::{ErrorClass, schnorr};
use sidecar_http::client::Answer;
use sidecar_node::admin::{AdminRequest, AdminResponse};
use sidecar_node::receipt::{ReceiptConfig, Receipts};
use sidecar_orchestrator::answer::check_chain_attempt;
use sidecar_orchestrator::scheduler::registered_layout;
use sidecar_orchestrator::scheduler::{Attempt, InitStep, Schedule, Scheduler, StepReport};
use sidecar_tip::chain::layout::request_log_tag;
use sidecar_tip::testing::MemoryChain;
use sidecar_tip::{
    ChainReader, ChainVerifier, QueueLayout, ReceiptChainView, SharedOnchainLayout, Snapshot,
    TipPackage, Transport, chain_request_id,
};

use super::*;

/// Where every mock contract keeps its queue.
pub const QUEUE_SLOT: u64 = 12;
/// Where every mock contract keeps `TipConfig.stale_blocks` (its flag, then
/// the period).
pub const STALE_SLOT: u64 = 1;
/// The manifests' `stale_blocks`, which every mock contract stores.
pub const STALE_BLOCKS: u64 = 50;
/// How far the mock chain's proven tip runs behind its proposed tip.
pub const PROVING_LAG: u64 = 64;

pub fn fr(v: u64) -> Fr {
    Fr::from(v)
}

pub fn frs(values: &[u64]) -> Vec<Fr> {
    values.iter().copied().map(Fr::from).collect()
}

// ---------------------------------------------------------------------------
// The namespace's configuration entry
// ---------------------------------------------------------------------------

pub fn keys(reads: &[&str], writes: &[&str]) -> StateKeys {
    StateKeys {
        reads: reads.iter().map(|k| k.to_string()).collect(),
        writes: writes.iter().map(|k| k.to_string()).collect(),
    }
}

/// A test namespace: the mock contract's slots and each package's request
/// keys, from which its contract manifest is generated ([`tip_manifest`]);
/// the operator lists `contract` alone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TipEntry {
    pub contract: FieldHex,
    pub queue_slot: FieldHex,
    pub shared_onchain_slot: Option<FieldHex>,
    pub stale_blocks_slot: FieldHex,
    /// Each package's request keys (each key the slot, as `fr_to_hex`
    /// writes it).
    pub circuits: BTreeMap<String, StateKeys>,
    pub plain_reads: BTreeMap<String, FieldHex>,
    pub init: Option<TipInit>,
}

/// The init round of a [`TipEntry`]: its package, the mock contract's
/// `configured` slot and its init inputs' slots.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TipInit {
    pub circuit: String,
    pub configured_slot: FieldHex,
    pub input_slots: Vec<FieldHex>,
}

/// A request key as the contract manifest gives it: the slot `key` names,
/// as `fr_to_hex` writes it.
pub fn slot_key(key: &str) -> String {
    fr_to_hex(fr_from_hex(key).unwrap())
}

/// The test namespace `contract` with the mock contract's queue and stale
/// period slots: every circuit of `circuits` writes `key` and reads it
/// unless it is one of `creates` (an init round's). No init round; set
/// `init` for one.
pub fn tip_namespace(contract: Fr, key: &str, circuits: &[&str], creates: &[&str]) -> TipEntry {
    let key = slot_key(key);
    TipEntry {
        contract: FieldHex(contract),
        queue_slot: FieldHex::from(QUEUE_SLOT),
        shared_onchain_slot: None,
        stale_blocks_slot: FieldHex::from(STALE_SLOT),
        circuits: circuits
            .iter()
            .map(|c| {
                let reads: &[&str] = if creates.contains(c) { &[] } else { &[&key] };
                (c.to_string(), keys(reads, &[&key]))
            })
            .collect(),
        plain_reads: BTreeMap::new(),
        init: None,
    }
}

/// The init round `circuit`, sent once the contract's `configured` flag (at
/// `configured_slot`) is set, its inputs read from `input_slots`.
pub fn tip_init(circuit: &str, configured_slot: u64, inputs: &[u64]) -> TipInit {
    TipInit {
        circuit: circuit.into(),
        configured_slot: FieldHex::from(configured_slot),
        input_slots: inputs.iter().copied().map(FieldHex::from).collect(),
    }
}

/// The mock contract's facts of the test namespace `entry` for `packages`:
/// its queue, stale period slot, `shared_onchain` slot, init round (its
/// `configured` slot and input slots) and each request key the packages
/// name (the key's name is the key itself, its slot the key read as a
/// field), under the stale period `stale_blocks`, with room for `capacity`
/// packages.
pub fn facts(
    entry: &TipEntry,
    packages: &[TestPackage],
    capacity: usize,
    stale_blocks: Option<u64>,
) -> TipFacts {
    let state_keys: Vec<(&str, Fr)> = packages
        .iter()
        .filter_map(|p| p.state_keys.as_ref())
        .flat_map(|k| k.reads.iter().chain(&k.writes))
        .map(|k| (k.as_str(), fr_from_hex(k).unwrap()))
        .collect();
    let mut tip = TipFacts {
        stale_blocks,
        stale_blocks_slot: entry.stale_blocks_slot.fr(),
        shared_onchain_slot: entry.shared_onchain_slot.map(FieldHex::fr),
        plain_reads: entry
            .plain_reads
            .iter()
            .map(|(k, v)| (k.clone(), v.fr()))
            .collect(),
        ..TipFacts::new(entry.queue_slot.fr(), capacity, &state_keys)
    };
    if let Some(init) = &entry.init {
        tip.configured_slot = init.configured_slot.fr();
        tip.init = Some((
            init.circuit.clone(),
            init.input_slots.iter().map(|s| s.fr()).collect(),
        ));
    }
    tip
}

/// A package of the tip namespace `entry`: `name` on the compiled circuit
/// `circuit` with `manifest`, its request keys `entry`'s circuits table
/// names for it (none for a package of intake direct).
pub fn tip_package(entry: &TipEntry, name: &str, circuit: &str, manifest: Value) -> TestPackage {
    let package = TestPackage::on(name, circuit, manifest);
    match entry.circuits.get(name) {
        Some(k) => package.keys(
            &k.reads.iter().map(String::as_str).collect::<Vec<_>>(),
            &k.writes.iter().map(String::as_str).collect::<Vec<_>>(),
        ),
        None => package,
    }
}

/// The contract manifest of `packages` under the tip namespace `entry`
/// ([`facts`], room for the listed packages).
pub fn tip_manifest(
    entry: &TipEntry,
    packages: &[TestPackage],
    stale_blocks: Option<u64>,
) -> Value {
    let listed = packages.iter().filter(|p| p.alias_of.is_none()).count();
    let tip = facts(entry, packages, listed, stale_blocks);
    contract_manifest("tip", packages, Some(&tip), vk_hash)
}

/// The scheduler's schedule of `ns` from the contract manifest the
/// orchestrator's registry copy holds: the head and one pipelined request.
pub fn schedule(net: &Net, ns: &TipEntry) -> Schedule {
    let layout = registered_layout(&net.orch.app, ns.contract.fr())
        .unwrap()
        .expect("the namespace is registered");
    Schedule::new(layout, 1)
}

// ---------------------------------------------------------------------------
// The chain, written as the contract would write it
// ---------------------------------------------------------------------------

/// The chain's clock, shared by every contract on it.
pub struct Clock {
    pub mem: Arc<MemoryChain>,
    pub block: u64,
    pub proven: u64,
}

impl Clock {
    pub fn new(block: u64, mem: Arc<MemoryChain>) -> Self {
        mem.set_tip(block);
        Clock {
            mem,
            block,
            proven: 0,
        }
    }

    /// `blocks` proposed blocks later, as a snapshot. The proven tip runs
    /// [`PROVING_LAG`] blocks behind (never moving back from where
    /// [`Self::prove_to`] put it), and the finalized tip one proof behind
    /// it, so a node keeps an orphaned version while the settled block, as
    /// its reads saw it, has not passed the block it turned orphan at.
    pub fn later(&mut self, blocks: u64) -> Snapshot {
        self.block += blocks;
        self.mem.set_tip(self.block);
        self.proven = self.proven.max(self.block.saturating_sub(PROVING_LAG));
        self.mem.node().set_proven(self.proven);
        Snapshot::at(self.block)
    }

    pub fn next(&mut self) -> Snapshot {
        self.later(1)
    }

    /// The proven tip moves to `block`.
    pub fn prove_to(&mut self, block: u64) {
        self.proven = block;
        self.mem.node().set_proven(self.proven);
    }

    /// The proven tip catches up with the proposed tip.
    pub fn prove(&mut self) {
        self.prove_to(self.block);
    }
}

/// One app contract's queue and its one state slot on the in-memory node.
pub struct Chain {
    pub mem: Arc<MemoryChain>,
    pub ns: Fr,
    pub layout: QueueLayout,
    /// The library's `SharedOnchain`, when the contract declares it.
    pub shared_onchain: Option<SharedOnchainLayout>,
    pub state_slot: Fr,
    pub ids: Vec<Fr>,
    pub head: u64,
    pub since: u64,
    pub slot: Fr,
    pub sig_pks: [Point; 3],
}

impl Chain {
    /// The contract `ns` with its state at `state_slot`, its stored stale
    /// period the manifests' and the nodes' `sig_pks` as its key epoch 0.
    pub fn new(clock: &Clock, ns: Fr, state_slot: Fr, sig_pks: [Point; 3]) -> Self {
        let mem = clock.mem.clone();
        mem.set_storage(ns, fr(STALE_SLOT), fr(1));
        mem.set_storage(ns, fr(STALE_SLOT + 1), fr(STALE_BLOCKS));
        pin_epoch0(&mem, ns, fr(STALE_SLOT), sig_pks.map(|p| (p.x, p.y)));
        let chain = Chain {
            mem,
            ns,
            layout: QueueLayout::new(fr(QUEUE_SLOT)),
            shared_onchain: None,
            state_slot,
            ids: vec![],
            head: 0,
            since: clock.block,
            slot: fr(0),
            sig_pks,
        };
        chain.write();
        chain
    }

    pub fn write(&self) {
        self.mem
            .write_queue(self.ns, self.layout, &self.ids, self.head, self.since);
        self.mem.set_storage(self.ns, self.state_slot, self.slot);
    }

    pub fn seen(&self, id: Fr) -> bool {
        self.ids.contains(&id)
    }

    /// `append`: `seen`, `requests[tail]`, `tail`, and `head_since` when the
    /// queue was empty.
    pub fn append(&mut self, clock: &Clock, id: Fr) {
        assert!(!self.seen(id), "request already seen");
        self.mem.set_storage(self.ns, self.layout.seen(id), fr(1));
        if self.head as usize == self.ids.len() {
            self.since = clock.block;
        }
        self.ids.push(id);
        self.write();
    }

    /// On-chain intake: the request log holds the inputs and the nonce.
    pub fn intake_onchain(&mut self, clock: &Clock, vk_hash: Fr, inputs: &[Fr], nonce: u64) -> Fr {
        let nonce = fr(nonce);
        let id = chain_request_id(self.ns, vk_hash, inputs, nonce);
        self.append(clock, id);
        let mut fields = inputs.to_vec();
        fields.push(nonce);
        self.mem
            .push_log(self.ns, clock.block, request_log_tag(id), &fields);
        id
    }

    /// [`Self::intake_onchain`] of small inputs.
    pub fn intake(&mut self, clock: &Clock, vk_hash: Fr, inputs: &[u64], nonce: u64) -> Fr {
        self.intake_onchain(clock, vk_hash, &frs(inputs), nonce)
    }

    pub fn head_id(&self) -> Option<Fr> {
        self.ids.get(self.head as usize).copied()
    }

    /// The head is done (`done` 1 for applied, 2 for skipped) and the head
    /// moves; `slot`, when given, is written.
    pub fn advance(&mut self, clock: &Clock, done: u64, slot: Option<Fr>) {
        assert!(self.head_id().is_some(), "an empty queue");
        if let Some(slot) = slot {
            self.slot = slot;
        }
        self.mem
            .set_storage(self.ns, self.layout.done(self.head), fr(done));
        self.head += 1;
        self.since = clock.block;
        self.write();
    }

    /// `apply` of a result for the head that names chain request `request`
    /// and moves the slot from `old_c` to `new_c`: refused (a revert, which
    /// changes nothing) unless the request is the head's and the slot holds
    /// `old_c`; the three result signatures over the new commitment and
    /// `H(sealed_i) = 0` must verify. `ok` (a non-secret-shared round's
    /// public `ok`; always true under private outcomes, whose apply writes
    /// the new commitment whatever the outcome) writes the slot.
    pub fn apply(
        &mut self,
        clock: &Clock,
        result: &ExecuteResponse,
        request: Fr,
        old_c: Fr,
        new_c: Fr,
        ok: bool,
    ) -> Result<(), &'static str> {
        assert!(
            result.records.is_empty(),
            "node-held state returns no records"
        );
        for i in 0..3 {
            let message = result_message(self.ns, result.request_id, &[new_c], i, fr(0));
            assert!(
                schnorr::verify(self.sig_pks[i], result.signatures[i], message),
                "result signature {i} does not verify"
            );
        }
        if self.head_id() != Some(request) {
            return Err("not the head");
        }
        if old_c != self.slot {
            return Err("state moved");
        }
        self.advance(clock, 1, ok.then_some(new_c));
        Ok(())
    }

    /// `init` of the state (the app's init function landing the init
    /// round): the slot must be empty.
    pub fn init(&mut self, new_c: Fr) {
        assert_eq!(self.slot, fr(0), "already initialised");
        self.slot = new_c;
        self.write();
    }

    /// `skip()` of the head once it is `stale_blocks` old.
    pub fn skip(&mut self, clock: &Clock) {
        assert!(
            clock.block >= self.since + STALE_BLOCKS,
            "head is not stale"
        );
        self.advance(clock, 2, None);
    }
}

// ---------------------------------------------------------------------------
// A result's public inputs, by name
// ---------------------------------------------------------------------------

/// A result's public inputs with its circuit's shape, read by name.
pub struct Outputs {
    pub shape: CircuitShape,
    pub pi: Vec<Fr>,
}

impl Outputs {
    /// The public return element at `path` (`ok`, `new_c`,
    /// `app.amount_out`), if the circuit returns one.
    pub fn find(&self, path: &str) -> Option<Fr> {
        self.shape.return_index(path).map(|i| self.pi[i])
    }

    pub fn get(&self, path: &str) -> Fr {
        self.find(path)
            .unwrap_or_else(|| panic!("the circuit returns no public `{path}`"))
    }

    pub fn small(&self, path: &str) -> u64 {
        small(self.get(path))
    }

    /// The public parameter `name`, its first element.
    pub fn param(&self, name: &str) -> Fr {
        let at = self
            .shape
            .param(name)
            .and_then(|p| p.public_index)
            .unwrap_or_else(|| panic!("the circuit has no public parameter `{name}`"));
        self.pi[at]
    }

    /// The round's public `ok`; a round without one (an init) succeeds.
    pub fn ok(&self) -> bool {
        self.find("ok").is_none_or(|ok| ok == fr(1))
    }
}

// ---------------------------------------------------------------------------
// The network
// ---------------------------------------------------------------------------

pub struct Net {
    pub real: RealNodes,
    pub orch: Started,
    pub certs: std::path::PathBuf,
    pub enc_pks: [Point; 3],
    pub sig_pks: [Point; 3],
    /// Every request a node's step 4 received, by node, as JSON.
    pub received: Arc<Mutex<Vec<(usize, Value)>>>,
    /// Chain verifier calls that accepted, over the three nodes.
    pub verified: Arc<AtomicUsize>,
}

/// Three real nodes, each with its chain verifier and its receipt signer
/// over `mem` for every namespace of `namespaces`, and the orchestrator over
/// them.
pub async fn start(
    tmp: &TempDir,
    mem: Arc<MemoryChain>,
    circuits: &[&str],
    namespaces: &[TipEntry],
) -> Net {
    start_viewing(tmp, &mem, circuits, namespaces, |_| mem.clone()).await
}

/// [`start`], node i's chain verifier reading the chain through `view(i)`.
pub async fn start_viewing<T: Transport + 'static>(
    tmp: &TempDir,
    mem: &Arc<MemoryChain>,
    circuits: &[&str],
    namespaces: &[TipEntry],
    view: impl Fn(usize) -> T,
) -> Net {
    let crs = require_crs(circuits);
    let certs = dev_certs(tmp.path());
    let received = Arc::new(Mutex::new(Vec::new()));
    let verified = Arc::new(AtomicUsize::new(0));
    let listed: Vec<Fr> = namespaces.iter().map(|n| n.contract.fr()).collect();
    let verifying = listed.clone();
    let (seen, calls) = (received.clone(), verified.clone());
    let real = start_real_nodes_signing(
        tmp.path(),
        &certs,
        crs.clone(),
        move |i| {
            let verifier = ChainVerifier::new(i, view(i), verifying.clone())
                .unwrap()
                .into_hook();
            let (seen, calls) = (seen.clone(), calls.clone());
            Box::new(move |req, round| {
                seen.lock()
                    .unwrap()
                    .push((i, serde_json::to_value(req).unwrap()));
                let accepted = verifier(req, round)?;
                calls.fetch_add(1, Ordering::SeqCst);
                Ok(accepted)
            })
        },
        |_| {
            let view = ReceiptChainView::new(mem.clone(), listed.clone()).unwrap();
            Receipts::with_chain(ReceiptConfig::default(), Arc::new(view))
        },
    )
    .await;
    let orch = start_orchestrator(
        &certs,
        real.addrs(),
        real.pins(),
        &tmp.path().join("registry"),
        crs,
    )
    .await;
    let pins = real.pins();
    Net {
        enc_pks: pins.nodes.map(|k| point_from_wire(&k.enc).unwrap()),
        sig_pks: pins.nodes.map(|k| point_from_wire(&k.sig).unwrap()),
        real,
        orch,
        certs,
        received,
        verified,
    }
}

impl Net {
    /// REGISTER `body` at the orchestrator; its answer, or the refusal.
    pub async fn post_register(&self, body: &ManifestMessage) -> Answer {
        self.orch.post_json("/v1/register", body).await
    }

    /// REGISTER `body` at the orchestrator, which must answer.
    pub async fn register_body(&self, body: &ManifestMessage) -> ManifestResponse {
        self.post_register(body)
            .await
            .json::<ManifestResponse>()
            .unwrap()
            .unwrap_or_else(|e| panic!("register: {e}"))
    }

    /// REGISTER the contract manifest of `packages` under the tip namespace
    /// `entry` in one manifest message at seq 0, the mock contract's facts
    /// from `entry` with the stale period `stale_blocks`; the vk hash of
    /// every package, by name.
    pub async fn register_tip(
        &self,
        entry: &TipEntry,
        packages: &[TestPackage],
        stale_blocks: Option<u64>,
    ) -> BTreeMap<String, Fr> {
        let document = tip_manifest(entry, packages, stale_blocks);
        let body = signed_register(entry.contract.fr(), document, 0);
        self.register_body(&body).await;
        packages
            .iter()
            .map(|p| (p.name.clone(), vk_hash(&p.circuit)))
            .collect()
    }

    /// REGISTER pss_seed and `packages` (each its name, compiled circuit and
    /// manifest) of the tip namespace `entry` in one manifest message at seq
    /// 0, under the stale period [`STALE_BLOCKS`]; the vk hash of every
    /// package, by name.
    pub async fn register_entry(
        &self,
        entry: &TipEntry,
        packages: &[(&str, &str, Value)],
    ) -> BTreeMap<String, Fr> {
        let mut all = vec![TestPackage::new("pss_seed", manifest("amm", "pss_seed"))];
        all.extend(
            packages
                .iter()
                .map(|(name, circuit, m)| tip_package(entry, name, circuit, m.clone())),
        );
        self.register_tip(entry, &all, Some(STALE_BLOCKS)).await
    }

    /// The relayer's read: FETCH by chain request id at the orchestrator.
    pub async fn fetch_chain(&self, ns: Fr, chain: Fr) -> Answer {
        self.orch
            .post_json(
                "/v1/fetch/chain",
                &json!({"namespace": FieldHex(ns), "chain_request_id": FieldHex(chain)}),
            )
            .await
    }

    /// The latest attempt of chain request `chain`, as the relayer fetches
    /// it.
    pub async fn latest(&self, ns: Fr, chain: Fr) -> ExecuteResponse {
        let label = format!("FETCH {}", fr_to_hex(chain));
        self.latest_as(&label, ns, chain).await
    }

    async fn latest_as(&self, label: &str, ns: Fr, chain: Fr) -> ExecuteResponse {
        self.fetch_chain(ns, chain)
            .await
            .json::<ExecuteResponse>()
            .unwrap()
            .unwrap_or_else(|e| panic!("{label}: {e}"))
    }

    /// The registered queued package `name` of `ns`, as the scheduler reads
    /// it.
    pub fn package(&self, ns: Fr, name: &str) -> TipPackage {
        let row = self
            .orch
            .registry()
            .packages(ns)
            .into_iter()
            .find(|p| p.name == name)
            .unwrap_or_else(|| panic!("no package `{name}`"));
        let stale = sidecar_tip::stale_blocks_of(self.orch.registry().store(), ns).unwrap();
        TipPackage::from_row(&row, stale).unwrap().unwrap()
    }

    /// `result`'s public inputs, read through the shape of the package of
    /// `ns` whose vk_hash it carries.
    pub fn outputs(&self, ns: Fr, result: &ExecuteResponse) -> Outputs {
        let registry = self.orch.registry();
        let row = registry
            .packages(ns)
            .into_iter()
            .find(|p| p.vk_hash == result.vk_hash.fr())
            .unwrap_or_else(|| panic!("no package carries vk_hash {}", result.vk_hash));
        Outputs {
            shape: registry.shape(&row).unwrap(),
            pi: result.public_inputs.iter().map(|f| f.fr()).collect(),
        }
    }

    /// `apply` of `result` on `chain`, the request id, the old commitment
    /// (the slot's for a round that returns none), the new commitment and
    /// `ok` read from its public inputs.
    pub fn apply(
        &self,
        clock: &Clock,
        chain: &mut Chain,
        result: &ExecuteResponse,
    ) -> Result<(), &'static str> {
        let o = self.outputs(chain.ns, result);
        let old_c = o.find("old_c").unwrap_or(chain.slot);
        // The round's public request id is its machine request id: an
        // attempt at the head's chain request id when the orchestrator's
        // own check says so.
        let request = match chain.head_id() {
            Some(head)
                if check_chain_attempt(self.orch.registry(), chain.ns, head, result).is_ok() =>
            {
                head
            }
            _ => o.get("request_id"),
        };
        chain.apply(clock, result, request, old_c, o.get("new_c"), o.ok())
    }

    /// FETCH the latest result for `chain`'s head and land it.
    pub async fn land(&self, clock: &Clock, chain: &mut Chain, label: &str) -> ExecuteResponse {
        let head = chain.head_id().expect("a queued head");
        let result = self.latest_as(label, chain.ns, head).await;
        self.apply(clock, chain, &result)
            .unwrap_or_else(|e| panic!("{label}: apply reverts: {e}"));
        result
    }

    /// Whether any node holds a `requests` row carrying `chain`.
    pub fn has_row(&self, ns: Fr, chain: Fr) -> bool {
        self.real
            .apps
            .iter()
            .any(|app| app.node.store.chain_request(ns, chain).unwrap().is_some())
    }

    /// Node `i`'s versions of `key`, in commitment order.
    pub fn versions(&self, i: usize, ns: Fr, key: &str) -> Vec<TipVersion> {
        self.real.apps[i].node.store.tip_versions(ns, key).unwrap()
    }

    /// The three nodes' versions of `key`, which agree on everything but
    /// the pairs.
    pub fn agreed(&self, ns: Fr, key: &str) -> Vec<TipVersion> {
        let all: Vec<Vec<TipVersion>> = (0..3).map(|i| self.versions(i, ns, key)).collect();
        let strip = |v: &[TipVersion]| -> Vec<_> { v.iter().map(stripped).collect() };
        for other in &all[1..] {
            assert_eq!(strip(&all[0]), strip(other));
        }
        all[0].clone()
    }

    /// The version of `key` under `commitment`, which the three nodes hold
    /// alike but for the pairs (a resynced node holds no orphans, so their
    /// lists may differ).
    pub fn version(&self, ns: Fr, key: &str, commitment: Fr) -> TipVersion {
        let all: Vec<TipVersion> = (0..3)
            .map(|i| {
                self.real.apps[i]
                    .node
                    .store
                    .tip_version(ns, key, commitment)
                    .unwrap()
                    .unwrap_or_else(|| panic!("node {i}: no version {}", fr_to_hex(commitment)))
            })
            .collect();
        assert!(
            all.iter().all(|v| stripped(v) == stripped(&all[0])),
            "{all:?}"
        );
        all[0].clone()
    }

    pub fn holds(&self, ns: Fr, key: &str, commitment: Fr) -> bool {
        self.agreed(ns, key)
            .iter()
            .any(|v| v.commitment == commitment)
    }

    /// The first two elements of the version of `key` under `commitment`
    /// (a pool's reserves), opened from the three nodes' pairs.
    pub fn reserves(&self, ns: Fr, key: &str, commitment: Fr) -> [u64; 2] {
        let parts: Vec<Vec<Elem>> = (0..3)
            .map(|i| {
                self.real.apps[i]
                    .node
                    .store
                    .tip_version(ns, key, commitment)
                    .unwrap()
                    .expect("the version is held")
                    .vec
            })
            .collect();
        [0, 1].map(|k| {
            let v = match [&parts[0][k], &parts[1][k], &parts[2][k]] {
                [Elem::Shared(a), Elem::Shared(b), Elem::Shared(c)] => a.a + b.a + c.a,
                [Elem::Public(a), ..] => *a,
                _ => panic!("the nodes disagree on the element's kind"),
            };
            small(v)
        })
    }

    pub fn snapshots(&self) -> Vec<MemorySnapshot> {
        self.real
            .apps
            .iter()
            .map(|a| a.node.store.snapshot())
            .collect()
    }

    /// POST `req` to the orchestrator: refused 400 naming every needle,
    /// within the session handshake (well under the mesh connect timeout of
    /// 30 s), and no node's tables changed.
    pub async fn refused(&self, label: &str, req: &Request, needles: &[&str]) {
        let before = self.snapshots();
        let started = Instant::now();
        let answer = self.orch.post_json("/v1/execute", req).await;
        let refusal = answer.json::<Value>().unwrap().unwrap_err();
        eprintln!("REFUSED {label}: {refusal}");
        assert_eq!(refusal.class, ErrorClass::BadRequest, "{label}: {refusal}");
        for needle in needles {
            assert!(
                refusal.message.contains(needle),
                "{label}: `{needle}` not in {refusal}"
            );
        }
        let took = started.elapsed();
        assert!(took.as_secs() < 15, "{label}: refused after {took:?}");
        assert!(
            before == self.snapshots(),
            "{label}: a refused request changed a table"
        );
    }

    /// Run the pruning job at the three nodes.
    pub async fn prune(&self) -> Vec<AdminResponse> {
        let mut out = vec![];
        for (i, running) in self.real.running.iter().enumerate() {
            let answer =
                sidecar_node::admin::call_async(running.admin_socket.clone(), AdminRequest::Prune)
                    .await
                    .unwrap();
            assert!(answer.ok, "prune at node {i}: {answer:?}");
            out.push(answer);
        }
        out
    }

    /// Move every node's settled block (the finalized tip, as its own chain
    /// view reads it), where receipt pruning and the `enc` retirement
    /// decide, to the clock's block: the proven tip moves there and each
    /// view reads it, then the clock moves one block and proves again,
    /// which finalizes the block before, and the next read sees it.
    pub fn settle(&self, clock: &mut Clock) {
        clock.prove();
        for (i, app) in self.real.apps.iter().enumerate() {
            let settled = app.receipts.chain.settled();
            assert!(settled.is_ok(), "node {i}: {settled:?}");
        }
        clock.later(1);
        clock.prove();
    }

    /// The versions each node's pruning job deleted.
    pub async fn prune_versions(&self) -> Vec<usize> {
        self.prune()
            .await
            .into_iter()
            .map(|a| a.pruned_versions.unwrap())
            .collect()
    }

    /// The requests the nodes received for chain request `chain`, by node,
    /// in the order they arrived.
    pub fn received_for(&self, chain: Fr) -> Vec<(usize, Value)> {
        self.received
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, r)| {
                r["chain_request_id"]
                    .as_str()
                    .and_then(|s| fr_from_hex(s).ok())
                    == Some(chain)
            })
            .cloned()
            .collect()
    }

    pub fn verified(&self) -> usize {
        self.verified.load(Ordering::SeqCst)
    }
}

/// A version as the three nodes hold it alike: all but its pairs and the
/// block each node marked it at.
type Stripped = (Fr, Fr, u64, RequestId, Option<VersionTree>, VersionStatus);

fn stripped(v: &TipVersion) -> Stripped {
    (
        v.commitment,
        v.parent,
        v.index,
        v.request_id,
        v.tree,
        v.status,
    )
}

// ---------------------------------------------------------------------------
// One namespace on its own network
// ---------------------------------------------------------------------------

/// One package a suite registers: its name, its compiled circuit and its
/// manifest.
pub struct Package {
    pub name: &'static str,
    pub circuit: &'static str,
    pub manifest: Value,
}

impl Package {
    pub fn new(name: &'static str, manifest: Value) -> Self {
        Self::on(name, name, manifest)
    }

    pub fn on(name: &'static str, circuit: &'static str, manifest: Value) -> Self {
        Package {
            name,
            circuit,
            manifest,
        }
    }
}

/// A network serving one namespace with one state key, and the vk_hash of
/// every package it registered.
pub struct World {
    pub net: Net,
    pub ns: Fr,
    pub key: String,
    pub vk: BTreeMap<&'static str, Fr>,
}

impl Deref for World {
    type Target = Net;

    fn deref(&self) -> &Net {
        &self.net
    }
}

/// [`start`] serving `ns`, then pss_seed and `packages` in one manifest
/// message at seq 0, in order.
pub async fn setup(
    tmp: &TempDir,
    mem: &Arc<MemoryChain>,
    ns: &TipEntry,
    packages: Vec<Package>,
) -> World {
    setup_viewing(tmp, mem, ns, packages, |_| mem.clone()).await
}

/// [`setup`], node i's chain verifier reading the chain through `view(i)`.
pub async fn setup_viewing<T: Transport + 'static>(
    tmp: &TempDir,
    mem: &Arc<MemoryChain>,
    ns: &TipEntry,
    packages: Vec<Package>,
    view: impl Fn(usize) -> T,
) -> World {
    let mut circuits = vec!["pss_seed"];
    for p in &packages {
        if !circuits.contains(&p.circuit) {
            circuits.push(p.circuit);
        }
    }
    let net = start_viewing(tmp, mem, &circuits, std::slice::from_ref(ns), view).await;
    let contract = ns.contract.fr();
    let mut listed = vec![TestPackage::new("pss_seed", manifest("amm", "pss_seed"))];
    listed.extend(
        packages
            .iter()
            .map(|p| tip_package(ns, p.name, p.circuit, p.manifest.clone())),
    );
    let registered = net.register_tip(ns, &listed, Some(STALE_BLOCKS)).await;
    let mut vk = BTreeMap::new();
    for name in std::iter::once("pss_seed").chain(packages.iter().map(|p| p.name)) {
        vk.insert(name, registered[name]);
    }
    let key = ns
        .circuits
        .values()
        .next()
        .and_then(|k| k.writes.first())
        .expect("a circuit writes the key")
        .clone();
    World {
        net,
        ns: contract,
        key,
        vk,
    }
}

impl World {
    pub fn vk(&self, name: &str) -> Fr {
        *self
            .vk
            .get(name)
            .unwrap_or_else(|| panic!("`{name}` is not registered"))
    }

    pub async fn latest(&self, label: &str, chain: Fr) -> ExecuteResponse {
        self.net.latest_as(label, self.ns, chain).await
    }

    pub fn versions(&self, i: usize) -> Vec<TipVersion> {
        self.net.versions(i, self.ns, &self.key)
    }

    pub fn agreed(&self) -> Vec<TipVersion> {
        self.net.agreed(self.ns, &self.key)
    }

    pub fn version(&self, commitment: Fr) -> TipVersion {
        self.net.version(self.ns, &self.key, commitment)
    }

    pub fn holds(&self, commitment: Fr) -> bool {
        self.net.holds(self.ns, &self.key, commitment)
    }

    pub fn reserves(&self, commitment: Fr) -> [u64; 2] {
        self.net.reserves(self.ns, &self.key, commitment)
    }

    pub fn package(&self, name: &str) -> TipPackage {
        self.net.package(self.ns, name)
    }

    pub fn outputs(&self, result: &ExecuteResponse) -> Outputs {
        self.net.outputs(self.ns, result)
    }

    pub fn has_row(&self, chain: Fr) -> bool {
        self.net.has_row(self.ns, chain)
    }
}

// ---------------------------------------------------------------------------
// The scheduler
// ---------------------------------------------------------------------------

pub fn scheduler(net: &Net, mem: &Arc<MemoryChain>, ns: &TipEntry) -> Scheduler<Arc<MemoryChain>> {
    Scheduler::new(
        net.orch.app.clone(),
        ChainReader::new(mem.clone()),
        schedule(net, ns),
    )
}

/// One step, which must not fail.
pub async fn step(s: &mut Scheduler<Arc<MemoryChain>>, snap: Snapshot, label: &str) -> StepReport {
    let started = Instant::now();
    let report = s
        .step(snap)
        .await
        .unwrap_or_else(|e| panic!("{label}: {e}"));
    eprintln!(
        "STEP {label} (block {}, head {}, tail {}): init {:?}, reloaded {}, stale {}, \
         repriced {}, computed {:?}, error {:?}: {:.3}s",
        report.block,
        report.head,
        report.tail,
        report.init.as_ref().map(InitStep::name),
        report.reloaded,
        report.stale,
        report.repriced,
        report
            .computed
            .iter()
            .map(|a| (a.index, a.circuit.as_str()))
            .collect::<Vec<_>>(),
        report.error,
        started.elapsed().as_secs_f64()
    );
    report
}

pub fn computed(report: &StepReport) -> Vec<u64> {
    report.computed.iter().map(|a| a.index).collect()
}

/// The attempt a step computed for entry `index`.
pub fn attempt(report: &StepReport, index: u64) -> &Attempt {
    report
        .computed
        .iter()
        .find(|a| a.index == index)
        .unwrap_or_else(|| panic!("entry {index} was not computed: {report:?}"))
}

/// The new commitment an attempt left for its one key.
pub fn new_c(report: &StepReport, index: u64) -> Fr {
    attempt(report, index).new[0].commitment
}
