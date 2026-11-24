//! The three-node test harness of the request lifecycle (feature `testing`):
//! three in-process nodes on mpc_net's local network, one thread per node,
//! each with its own MemoryStore and keys, over compiled circuits with real
//! MPC proofs. [`Network`] is a small orchestrator: it runs the stateless
//! prefix, projects each request to the three node views, checks that the
//! three answers agree, verifies the proof against its own vk and the three
//! result signatures against the pinned sig keys, and assembles the records.
//! sidecar-core's `tests/lifecycle.rs` runs the core rounds on it, and
//! sidecar-tip's `tests/lifecycle.rs` the queued (chain-held) rounds, with
//! sidecar-tip's state holders.
//!
//! The circuits and the CRS come from `scripts/prepare-data.sh` (under
//! machine/data, or DATA_DIR); [`fixture`] prints why and answers `None` if
//! they are missing, and the tests then pass, and panics naming the circuit
//! and `scripts/prepare-data.sh` if one is older than its source
//! ([`artifacts::require_prepared_fresh`]). Run with `--release`.
//!
//! The tests of a binary run their networks in parallel;
//! `PSS_SERIAL_ROUNDS=1` runs them one at a time ([`serial`]), for clean
//! ROUND timings.

pub mod artifacts;
pub use artifacts::{data_dir, repo};
pub mod manifests;

pub use manifests::{TestPackage, TipFacts, contract_manifest, manifest_message, sign_message};

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Condvar, Mutex, OnceLock};
use std::time::{Duration, Instant};

use ark_ff::{BigInteger, PrimeField, UniformRand};
use ark_std::rand::rngs::StdRng;
use ark_std::rand::{RngCore, SeedableRng};
use mpc_net::local::LocalNetwork;
use serde_json::Value;

use crate::abi::CircuitShape;
use crate::bind::{Elem, Share};
use crate::crs::{self, Artifact, Circuit, Crs};
use crate::envelope::{EnvelopeAd, seal_envelope};
use crate::error::{ErrorClass, Refusal};
use crate::field::{FieldHex, Fr, HexBytes, RequestId, fr_to_hex};
use crate::grumpkin::{Fq, Point, point_to_wire};
use crate::keys::NodeKeys;
use crate::pipeline::{self, Node};
use crate::record::{self, record_hash};
use crate::register::{DisableAnswer, DisableRequest, ManifestAnswer, ManifestMessage, Signature};
use crate::registry::{self, Signed};
use crate::request::{
    NODES, NodeRequest, PublicValue, Request, SharedInput, StateKeys, StateRecord,
};
use crate::response::{NodeResult, NodesResponse};
use crate::schnorr::{self, public_key};
use crate::state::StateHolders;
use crate::store::{MemorySnapshot, MemoryStore, StoreRead};

/// The master nullifier secret the three nodes hold shares of.
const MASTER: u64 = 0x6d6173746572;

/// The environment variable that runs the three-node networks of a test
/// binary one at a time: `PSS_SERIAL_ROUNDS=1`.
pub const SERIAL_ROUNDS_VAR: &str = "PSS_SERIAL_ROUNDS";

// The networks share nothing (each has its own stores, keys and in-process
// mesh; the fixture is read-only), so the tests of a binary run in parallel.
// The lock only keeps the printed ROUND and REGISTER timings clean of a
// second network proving beside them, for whoever measures rounds.
static SERIAL: Mutex<()> = Mutex::new(());

/// Whether `PSS_SERIAL_ROUNDS=1` asks for one network at a time.
pub fn serial_rounds() -> bool {
    std::env::var(SERIAL_ROUNDS_VAR).as_deref() == Ok("1")
}

/// Hold while a test runs its network. With `PSS_SERIAL_ROUNDS=1` the tests
/// of a binary hold it in turn, one three-node network at a time, so the
/// timings they print are those of an unloaded machine; otherwise it holds
/// nothing and the tests run in parallel.
pub fn serial() -> Option<std::sync::MutexGuard<'static, ()>> {
    serial_rounds().then(|| {
        SERIAL
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    })
}

/// How long an in-process node waits at `connect` for both peers to connect
/// before it fails the session, as the TLS mesh's connect timeout (30 s by
/// default) bounds a node whose peers never open the session. The same 30 s:
/// the work a node does before `connect` (a REGISTER's vk build among it)
/// runs beside other tests' networks, and a node delayed by them must not
/// read as a stranded one. A test that asserts a refusal comes at once
/// bounds its own wait.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// One in-process mesh session for the three nodes of a request. Each node's
/// channel ends are handed out at `connect` only once all three nodes have
/// connected, as the TLS mesh opens only when all three reach it; a node
/// whose peers do not all connect within [`CONNECT_TIMEOUT`] fails with 500,
/// as on the real mesh, and so does every node once one has given up. Channel
/// ends a node never takes stay open until the session is dropped, after all
/// three threads end, so a node that never connects reads to its peers as a
/// node that never arrives, not as a closed connection.
struct Mesh {
    state: Mutex<MeshState>,
    changed: Condvar,
}

struct MeshState {
    nets: [Option<LocalNetwork>; NODES],
    connected: usize,
    failed: bool,
}

impl Mesh {
    fn new() -> Self {
        Mesh {
            state: Mutex::new(MeshState {
                nets: LocalNetwork::new_3_parties().map(Some),
                connected: 0,
                failed: false,
            }),
            changed: Condvar::new(),
        }
    }

    /// Node `party` connects: its channel ends once all three have connected.
    fn connect(&self, party: usize) -> Result<LocalNetwork, Refusal> {
        let deadline = Instant::now() + CONNECT_TIMEOUT;
        let mut state = self.state.lock().unwrap();
        state.connected += 1;
        self.changed.notify_all();
        while state.failed || state.connected < NODES {
            let now = Instant::now();
            if now >= deadline {
                state.failed = true;
                self.changed.notify_all();
                return Err(Refusal::mpc_failure(format!(
                    "MPC session: the mesh did not open: node {party}'s peers did not connect \
                     within {CONNECT_TIMEOUT:?}"
                )));
            }
            state = self.changed.wait_timeout(state, deadline - now).unwrap().0;
        }
        Ok(state.nets[party].take().expect("each node connects once"))
    }
}

/// The compiled round circuits of a test binary and the CRS they prove under.
pub struct Fixture {
    pub crs: Crs,
    /// nargo artifacts by circuit name, as REGISTER bodies carry them.
    pub circuits: BTreeMap<String, Value>,
    /// The orchestrator's own circuits, for verifying proofs.
    pub verifiers: BTreeMap<String, Circuit>,
}

/// The round circuits `names` from the data directory's circuits/ and a CRS
/// sized for the largest (and the registration circuit), read once per test
/// binary, or `None` with a message when any of them is missing. Panics when
/// one is older than its source. Every call in one test binary names the same
/// circuits.
pub fn fixture(names: &[&str]) -> Option<&'static Fixture> {
    static FIXTURE: OnceLock<(Vec<String>, Option<Fixture>)> = OnceLock::new();
    let (loaded, fixture) = FIXTURE.get_or_init(|| {
        let names: Vec<String> = names.iter().map(|n| n.to_string()).collect();
        let fixture = load_fixture(&names);
        (names, fixture)
    });
    assert!(
        loaded.iter().eq(names),
        "one test binary reads one set of circuits: {loaded:?}, then {names:?}"
    );
    fixture.as_ref()
}

fn load_fixture(names: &[String]) -> Option<Fixture> {
    let dir = data_dir();
    let paths: Vec<PathBuf> = names
        .iter()
        .map(|c| dir.join("circuits").join(format!("{c}.json")))
        .collect();
    let g1 = dir.join("bn254_g1.dat");
    let g2 = dir.join("bn254_g2.dat");
    if let Some(missing) = paths.iter().chain([&g1, &g2]).find(|p| !p.exists()) {
        crate::testing::artifacts::missing(format!(
            "{} is missing; run scripts/prepare-data.sh (or set DATA_DIR)",
            missing.display()
        ));
        return None;
    }
    for (name, path) in names.iter().zip(&paths) {
        artifacts::require_prepared_fresh(path, name);
    }
    let artifacts: Vec<Artifact> = paths.iter().map(|p| Artifact::read(p).unwrap()).collect();
    let machine = registry::machine_artifacts().unwrap();
    let size = crs::crs_circuit_size(artifacts.iter().chain(&machine));
    eprintln!(
        "circuit sizes {:?}; reading {} G1 points",
        artifacts
            .iter()
            .map(|a| (&a.name, a.circuit_size))
            .collect::<Vec<_>>(),
        crs::crs_points(size)
    );
    let start = Instant::now();
    let crs = Crs::read(&g1, &g2, size).unwrap();
    let circuits = names
        .iter()
        .zip(&paths)
        .map(|(n, p)| {
            let json: Value = serde_json::from_slice(&std::fs::read(p).unwrap()).unwrap();
            (n.clone(), json)
        })
        .collect();
    let verifiers: BTreeMap<String, Circuit> = artifacts
        .into_iter()
        .map(|a| {
            let c = Circuit::new(a, &crs.prover).unwrap();
            (c.name.clone(), c)
        })
        .collect();
    eprintln!(
        "FIXTURE: the CRS and {} verifiers in {:.3}s",
        verifiers.len(),
        start.elapsed().as_secs_f64()
    );
    Some(Fixture {
        crs,
        circuits,
        verifiers,
    })
}

/// The manifest `name` of examples/`example`.
pub fn manifest(example: &str, name: &str) -> Value {
    let path = repo().join(format!("examples/{example}/manifests/{name}.json"));
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

/// A seeded rng, so every run draws the same keys and blindings.
pub fn rng(seed: u64) -> StdRng {
    StdRng::seed_from_u64(seed)
}

/// The namespace owner's secret key; it signs every registry body.
pub fn owner_secret() -> Fq {
    Fq::from(0x0123_4567_89ab_cdefu64)
}

/// Dealer-known replicated shares of `value`: node i holds `(a_i, a_{i-1})`.
fn dealer_shares(value: Fr) -> [Share; NODES] {
    let a = [Fr::from(11u64), Fr::from(22u64), value - Fr::from(33u64)];
    [0, 1, 2].map(|i| Share::new(a[i], a[(i + 2) % 3]))
}

/// Open one element from the three nodes' copies, checking that the
/// replicated shares are consistent.
pub fn open(parts: [&Elem; NODES]) -> Fr {
    match parts {
        [Elem::Public(a), Elem::Public(b), Elem::Public(c)] => {
            assert!(a == b && b == c, "a public element differs between nodes");
            *a
        }
        [Elem::Shared(s0), Elem::Shared(s1), Elem::Shared(s2)] => {
            assert_eq!(s1.b, s0.a);
            assert_eq!(s2.b, s1.a);
            assert_eq!(s0.b, s2.a);
            s0.a + s1.a + s2.a
        }
        _ => panic!("the nodes disagree on whether an element is shared"),
    }
}

/// Open a vector element by element ([`open`]).
pub fn open_vec(vecs: [&[Elem]; NODES]) -> Vec<Fr> {
    assert!(vecs[0].len() == vecs[1].len() && vecs[1].len() == vecs[2].len());
    (0..vecs[0].len())
        .map(|k| open([&vecs[0][k], &vecs[1][k], &vecs[2][k]]))
        .collect()
}

/// `value` as a u64; panics if it does not fit.
pub fn small(value: Fr) -> u64 {
    let big = value.into_bigint();
    assert!(big.num_bits() <= 64, "{} is not a u64", fr_to_hex(value));
    big.as_ref()[0]
}

/// A random request id.
fn random_id(rng: &mut StdRng) -> RequestId {
    let mut bytes = [0u8; 16];
    rng.fill_bytes(&mut bytes);
    RequestId::from_u128_bytes(bytes)
}

/// A request with no shared inputs, records or signature.
pub fn request(
    namespace: u64,
    circuit: &str,
    id: RequestId,
    public: &[(&str, Fr)],
    reads: &[&str],
    writes: &[&str],
) -> Request {
    Request {
        namespace: FieldHex(Fr::from(namespace)),
        circuit: circuit.to_string(),
        request_id: id,
        public: public
            .iter()
            .map(|(k, v)| (k.to_string(), PublicValue::One(FieldHex(*v))))
            .collect(),
        state_keys: StateKeys {
            reads: reads.iter().map(|k| k.to_string()).collect(),
            writes: writes.iter().map(|k| k.to_string()).collect(),
        },
        shared_inputs: vec![],
        records: vec![],
        requester: None,
        signature: None,
        chain_request_id: None,
        shared_log: None,
        manifest_hash: None,
    }
}

/// Name `secret`'s key as the requester and sign the body with it.
pub fn sign_as(req: &mut Request, requester: Fq, signer: Fq) {
    req.requester = Some(point_to_wire(public_key(requester)));
    req.signature = Some(schnorr::sign(signer, req.signed_message(), &mut rng(99)));
}

/// The three node views of `req`.
pub fn views(req: &Request) -> [NodeRequest; NODES] {
    [0, 1, 2].map(|i| req.project(i))
}

/// A committed round as the orchestrator assembles it.
pub struct Answer {
    pub results: [NodeResult; NODES],
    pub public_inputs: Vec<Fr>,
    pub records: Vec<StateRecord>,
    pub shape: CircuitShape,
}

impl Answer {
    /// The public output at `path` of the circuit's return value.
    pub fn output(&self, path: &str) -> Fr {
        self.public_inputs[self.shape.return_index(path).unwrap()]
    }
}

/// A node's MemoryStore whose next commit can be made to fail, as when a
/// node's database refuses (or the node stops) at step 15 while the other two
/// commit.
pub type TestStore = crate::store::testing::Flaky<MemoryStore>;

/// Three nodes and the orchestrator's view of them: their pinned keys, and
/// an rng for request ids, sharings and registry signatures.
pub struct Network {
    pub nodes: Vec<Node<TestStore>>,
    pub sig_pks: [Point; NODES],
    pub enc_pks: [Point; NODES],
    pub rng: StdRng,
    /// Circuits registered under another name, by that name: the
    /// orchestrator verifies their proofs with the original's vk.
    pub aliases: BTreeMap<String, String>,
    /// How many verification keys each node built during the last `run`.
    pub vk_builds: Mutex<[u64; NODES]>,
}

impl Network {
    /// Three nodes with keys drawn from `seed`, empty stores, shares of one
    /// master secret and the core state holders.
    pub fn new(fx: &Fixture, seed: u64) -> Self {
        let masters = dealer_shares(Fr::from(MASTER));
        let nodes: Vec<Node<TestStore>> = (0..NODES)
            .map(|i| {
                let keys = NodeKeys::generate(&mut rng(seed * 10 + i as u64));
                Node::new(i, keys, masters[i], TestStore::default(), fx.crs.clone()).unwrap()
            })
            .collect();
        let sig_pks = [0, 1, 2].map(|i| nodes[i].keys().sig_pk());
        let enc_pks = [0, 1, 2].map(|i| nodes[i].keys().enc_pk());
        Network {
            nodes,
            sig_pks,
            enc_pks,
            rng: rng(seed),
            aliases: BTreeMap::new(),
            vk_builds: Mutex::new([0; NODES]),
        }
    }

    /// Give every node the state holders `holders` (a node starts with
    /// [`StateHolders::core`]).
    pub fn with_state_holders(&mut self, holders: StateHolders) {
        self.nodes = std::mem::take(&mut self.nodes)
            .into_iter()
            .map(|n| n.with_state_holders(holders.clone()))
            .collect();
    }

    /// Give every node the receipt resync hook `hook` (a node starts with
    /// [`crate::resync::NoReceiptResync`]).
    pub fn with_receipt_resync(&mut self, hook: crate::resync::ReceiptResyncHook) {
        self.nodes = std::mem::take(&mut self.nodes)
            .into_iter()
            .map(|n| n.with_receipt_resync(hook.clone()))
            .collect();
    }

    /// Give every node the step 4 chain verifier `make(i)` returns.
    pub fn with_chain_verifier(&mut self, make: impl Fn(usize) -> pipeline::ChainVerifier) {
        self.nodes = std::mem::take(&mut self.nodes)
            .into_iter()
            .map(|n| {
                let hook = make(n.index);
                n.with_chain_verifier(hook)
            })
            .collect();
    }

    /// Restart the three nodes: fresh `Node`s, with empty circuit caches, over
    /// the same stores, keys and master shares.
    pub fn restart(&mut self, fx: &Fixture) {
        let old = std::mem::take(&mut self.nodes);
        self.nodes = old
            .into_iter()
            .map(|n| {
                let keys = n.keys().as_ref().clone();
                let (holders, receipts) = (n.holders(), n.receipt_resync());
                Node::new(n.index, keys, n.master(), n.store, fx.crs.clone())
                    .unwrap()
                    .with_state_holders(holders)
                    .with_receipt_resync(receipts)
            })
            .collect();
    }

    /// A fresh request id.
    pub fn id(&mut self) -> RequestId {
        random_id(&mut self.rng)
    }

    /// Every node's tables.
    pub fn snapshots(&self) -> Vec<MemorySnapshot> {
        self.nodes.iter().map(|n| n.store.snapshot()).collect()
    }

    /// Panics when `err`, node `i`'s answer to request `own`, names another
    /// request's id held in any node's `requests` table: a request id scopes
    /// FETCH, so a refusal must never hand one to another requester.
    fn names_no_other_request(
        label: &str,
        i: usize,
        own: RequestId,
        before: &[MemorySnapshot],
        err: &Refusal,
    ) {
        for snapshot in before {
            for (_, id) in snapshot.0.requests.keys() {
                assert!(
                    *id == own || !err.message.contains(&id.to_string()),
                    "{label}: node {i} names request {id} in a refusal of {own}: {}",
                    err.message
                );
            }
        }
    }

    /// Register `circuits` of `example` (sidecar-path manifests, each
    /// package named after its circuit) under `namespace` in one manifest
    /// message at seq 0, which runs the registration circuit on the three
    /// nodes. Returns the npk_app_hash the three nodes signed.
    pub fn register(
        &mut self,
        fx: &Fixture,
        namespace: u64,
        example: &str,
        circuits: &[&str],
    ) -> Fr {
        let packages: Vec<TestPackage> = circuits
            .iter()
            .map(|name| TestPackage::new(name, manifest(example, name)))
            .collect();
        let mut npk_app_hash = None;
        let mut body = Self::manifest_message(fx, namespace, example, &packages, None, 0);
        self.register_body(&mut body, &mut npk_app_hash);
        npk_app_hash.unwrap()
    }

    /// Sign `body` with the namespace owner key, run it on the three nodes
    /// and check their answers as the orchestrator does; `npk_app_hash`, if
    /// set, must be the one they sign, and is set to it.
    pub fn register_body(&mut self, body: &mut ManifestMessage, npk_app_hash: &mut Option<Fr>) {
        let signed = sign_message(body.clone(), owner_secret(), &mut self.rng);
        *body = signed.body.clone();
        let start = Instant::now();
        let mesh = Mesh::new();
        let answers: Vec<_> = std::thread::scope(|s| {
            let handles: Vec<_> = self
                .nodes
                .iter()
                .map(|node| {
                    let (signed, mesh) = (&signed, &mesh);
                    s.spawn(move || {
                        node.register(
                            signed,
                            |_| mesh.connect(node.index),
                            &mut rng(node.index as u64),
                        )
                    })
                })
                .collect();
            handles.into_iter().map(|h| h.join().unwrap()).collect()
        });
        let answers: [_; NODES] = answers
            .into_iter()
            .map(|a| a.unwrap_or_else(|e| panic!("REGISTER (seq {}): {e}", body.seq)))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        let checked = body.contract_manifest().unwrap();
        let hash = crate::manifest::contract::manifest_hash(&body.manifest).unwrap();
        let response = registry::check_manifest_answers(
            body,
            &registry::ManifestFacts::of(&checked, hash),
            &answers,
            &self.sig_pks,
            &self.nodes[0].registration.vk,
            self.nodes[0].crs.g2,
        )
        .unwrap();
        eprintln!(
            "REGISTER of {} package(s) (seq {}): {:.3}s",
            checked.document.packages.len(),
            body.seq,
            start.elapsed().as_secs_f64()
        );
        if let Some(npk) = npk_app_hash {
            assert_eq!(response.npk_app_hash.fr(), *npk);
        }
        *npk_app_hash = Some(response.npk_app_hash.fr());
    }

    /// An unsigned manifest message of `packages` (of `example`'s compiled
    /// circuits) under `namespace` at `seq`, with the contract facts `tip`
    /// (none on the sidecar path), owned by the namespace owner key
    /// ([`Self::register_body`] signs and runs it).
    pub fn manifest_message(
        fx: &Fixture,
        namespace: u64,
        example: &str,
        packages: &[TestPackage],
        tip: Option<&TipFacts>,
        seq: u64,
    ) -> ManifestMessage {
        let document = contract_manifest(example, packages, tip, |c| fx.verifiers[c].vk_hash);
        manifest_message(
            Fr::from(namespace),
            document,
            &fx.circuits,
            owner_secret(),
            seq,
        )
    }

    /// A manifest message of `names` of `example` (sidecar-path manifests)
    /// under `namespace` at seq 0, naming `owner` and signed by the namespace
    /// owner key.
    pub fn signed_register(
        &mut self,
        fx: &Fixture,
        namespace: u64,
        example: &str,
        names: &[&str],
        owner: Fq,
    ) -> Signed<ManifestMessage> {
        let packages: Vec<TestPackage> = names
            .iter()
            .map(|name| TestPackage::new(name, manifest(example, name)))
            .collect();
        let document = contract_manifest(example, &packages, None, |c| fx.verifiers[c].vk_hash);
        let body = manifest_message(Fr::from(namespace), document, &fx.circuits, owner, 0);
        sign_message(body, owner_secret(), &mut self.rng)
    }

    /// Node i handles `bodies[i]` (`Node::register`), one thread each, over
    /// one in-process mesh.
    pub fn register_each(
        &self,
        bodies: [&Signed<ManifestMessage>; NODES],
    ) -> Vec<Result<ManifestAnswer, Refusal>> {
        let mesh = Mesh::new();
        std::thread::scope(|s| {
            let handles: Vec<_> = self
                .nodes
                .iter()
                .zip(bodies)
                .map(|(node, body)| {
                    let mesh = &mesh;
                    s.spawn(move || {
                        node.register(
                            body,
                            |_| mesh.connect(node.index),
                            &mut rng(node.index as u64),
                        )
                    })
                })
                .collect();
            handles.into_iter().map(|h| h.join().unwrap()).collect()
        })
    }

    /// DISABLE `circuit` under `namespace` on every node.
    pub fn disable(&mut self, namespace: u64, circuit: &str, seq: u64) {
        let signed = self.signed_disable(namespace, circuit, seq);
        for (i, answer) in self.disable_each(&signed).into_iter().enumerate() {
            answer.unwrap_or_else(|e| panic!("DISABLE {circuit}: node {i}: {e}"));
        }
    }

    /// A DISABLE body for `circuit` under `namespace` with `seq`, signed by
    /// the namespace owner key.
    pub fn signed_disable(
        &mut self,
        namespace: u64,
        circuit: &str,
        seq: u64,
    ) -> Signed<DisableRequest> {
        let mut body = DisableRequest {
            namespace: FieldHex(Fr::from(namespace)),
            circuit: circuit.to_string(),
            owner_pubkey: point_to_wire(public_key(owner_secret())),
            seq,
            signature: Signature::default(),
        };
        let message = schnorr::message_for(
            schnorr::DISABLE_DOMAIN,
            &serde_json::to_value(&body).unwrap(),
        )
        .unwrap();
        body.signature = schnorr::sign(owner_secret(), message, &mut self.rng);
        Signed::new(body).unwrap()
    }

    /// Every node handles `body` (`registry::disable`), in node order.
    pub fn disable_each(
        &self,
        body: &Signed<DisableRequest>,
    ) -> Vec<Result<DisableAnswer, Refusal>> {
        self.nodes
            .iter()
            .map(|node| {
                registry::disable(
                    &node.store,
                    &node.registry_node(&node.keys()),
                    body,
                    &mut rng(1),
                )
            })
            .collect()
    }

    /// Give node `i` the step 2 admission hook `hook` (every node starts with
    /// [`crate::admit::admit`]).
    pub fn with_admit(&mut self, i: usize, hook: pipeline::AdmitHook) {
        let node = self.nodes.remove(i);
        self.nodes.insert(i, node.with_admit(hook));
    }

    /// Compare the three nodes' registry rows of `namespace` (or of every
    /// namespace) over one in-process mesh ([`crate::registry_check::check`]),
    /// one thread each.
    pub fn check_registry(
        &self,
        namespace: Option<Fr>,
    ) -> Vec<Result<crate::registry_check::RegistryCheck, Refusal>> {
        let mesh = Mesh::new();
        std::thread::scope(|s| {
            let handles: Vec<_> = self
                .nodes
                .iter()
                .map(|node| {
                    let mesh = &mesh;
                    s.spawn(move || {
                        crate::registry_check::check(node, namespace, |_| mesh.connect(node.index))
                    })
                })
                .collect();
            handles.into_iter().map(|h| h.join().unwrap()).collect()
        })
    }

    /// Resync node `lost`'s registry rows from node `from` over one in-process
    /// mesh ([`crate::resync::resync_registry`]), one thread each.
    pub fn resync_registry(
        &self,
        lost: usize,
        from: usize,
    ) -> Vec<Result<crate::resync::RegistryResync, Refusal>> {
        let mesh = Mesh::new();
        std::thread::scope(|s| {
            let handles: Vec<_> = self
                .nodes
                .iter()
                .map(|node| {
                    let mesh = &mesh;
                    s.spawn(move || {
                        crate::resync::resync_registry(node, lost, from, |_| {
                            mesh.connect(node.index)
                        })
                    })
                })
                .collect();
            handles.into_iter().map(|h| h.join().unwrap()).collect()
        })
    }

    /// The three nodes' current keys, as a resync pins them.
    pub fn pins(&self) -> NodesResponse {
        NodesResponse {
            nodes: [0, 1, 2].map(|i| self.nodes[i].keys().public_keys()),
        }
    }

    /// Replace node `i` by a node with the same keys, master share and hooks
    /// and an empty store: its store was deleted, its key directory kept.
    pub fn lose_store(&mut self, fx: &Fixture, i: usize) {
        let old = &self.nodes[i];
        self.nodes[i] = Node::new(
            i,
            old.keys().as_ref().clone(),
            old.master(),
            TestStore::default(),
            fx.crs.clone(),
        )
        .unwrap()
        .with_state_holders(old.holders())
        .with_receipt_resync(old.receipt_resync());
    }

    /// The resync of `scope` of node `lost` as a node's admin socket runs it
    /// ([`crate::resync::run`]), one thread each over a local mesh: each
    /// neighbour collects its bundle under the scope's namespace locks with
    /// the chain view `views` and applies `tamper` to it before it seals
    /// it; the lost node restores `backup` (a delta resync).
    pub fn resync(
        &self,
        audit_circuit: &Circuit,
        lost: usize,
        scope: &crate::resync::Scope,
        backup: Option<&crate::backup::StoreExport>,
        views: &crate::state::VersionViews<'_>,
        tamper: impl Fn(usize, &mut crate::resync::Contents) + Sync,
    ) -> Vec<Result<crate::resync::ResyncReport, Refusal>> {
        use crate::resync;
        let pins = self.pins();
        let started = Instant::now();
        let out = std::thread::scope(|s| {
            let handles: Vec<_> = self
                .nodes
                .iter()
                .zip(LocalNetwork::new_3_parties())
                .map(|(node, mesh)| {
                    let (pins, tamper) = (&pins, &tamper);
                    s.spawn(move || {
                        let sent = (node.index != lost).then(|| {
                            let held = node.lock_namespaces(scope.namespaces(&node.store).unwrap());
                            let mut c = resync::collect(node, &held, lost, scope, views).unwrap();
                            tamper(node.index, &mut c);
                            c
                        });
                        let hs = crate::handshake::Handshake::build(
                            resync::session_id(),
                            resync::session_body(lost, scope, pins),
                            &[],
                            &[],
                        );
                        crate::handshake::exchange(&mesh, &hs)?;
                        resync::run(
                            node,
                            audit_circuit,
                            &mesh,
                            lost,
                            scope,
                            pins,
                            sent,
                            backup.filter(|_| node.index == lost),
                            &mut rng(node.index as u64),
                        )
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|h| h.join().unwrap())
                .collect::<Vec<_>>()
        });
        eprintln!(
            "RESYNC: {:.3}s on three nodes",
            started.elapsed().as_secs_f64()
        );
        out
    }

    /// Run the three node views on the three nodes, one thread each, over one
    /// in-process mesh.
    pub fn run(&self, views: [NodeRequest; NODES]) -> Vec<Result<NodeResult, Refusal>> {
        let mesh = Mesh::new();
        std::thread::scope(|s| {
            let handles: Vec<_> = self
                .nodes
                .iter()
                .zip(views)
                .map(|(node, view)| {
                    let mesh = &mesh;
                    s.spawn(move || {
                        let before = crs::vk_builds_on_this_thread();
                        let result =
                            pipeline::run_request(node, view, |_| mesh.connect(node.index));
                        (result, crs::vk_builds_on_this_thread() - before)
                    })
                })
                .collect();
            let mut builds = [0; NODES];
            let mut results = Vec::with_capacity(NODES);
            for (i, h) in handles.into_iter().enumerate() {
                let (result, built) = h.join().unwrap();
                builds[i] = built;
                results.push(result);
            }
            *self.vk_builds.lock().unwrap() = builds;
            results
        })
    }

    /// The orchestrator's half for a request that must commit: the stateless
    /// prefix, fan-out, agreement, the proof against its own vk, the
    /// namespace public input, the three result signatures, and the records.
    pub fn execute(&self, fx: &Fixture, label: &str, req: &Request) -> Answer {
        let (_, shape) = pipeline::stateless_prefix(req, &self.nodes[0].store)
            .unwrap_or_else(|e| panic!("{label}: the stateless prefix refused: {e}"));
        let start = Instant::now();
        let results = self.run(views(req));
        let elapsed = start.elapsed();
        let results: [NodeResult; NODES] = results
            .into_iter()
            .enumerate()
            .map(|(i, r)| r.unwrap_or_else(|e| panic!("{label}: node {i}: {e}")))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        let answer = self.check(fx, label, req, shape, results);
        eprintln!(
            "ROUND {label} ({}): {:.3}s on three nodes",
            req.circuit,
            elapsed.as_secs_f64()
        );
        answer
    }

    /// The orchestrator's checks of three committed answers (an execute or a
    /// FETCH).
    pub fn check(
        &self,
        fx: &Fixture,
        label: &str,
        req: &Request,
        shape: CircuitShape,
        results: [NodeResult; NODES],
    ) -> Answer {
        let [a, b, c] = &results;
        for other in [b, c] {
            assert_eq!(a.request_id, other.request_id, "{label}: request_id");
            assert_eq!(a.proof, other.proof, "{label}: proof");
            assert_eq!(
                a.public_inputs, other.public_inputs,
                "{label}: public inputs"
            );
            assert_eq!(a.stored, other.stored, "{label}: stored");
            let same: Vec<_> = a.records.iter().map(|r| (&r.key, r.note_hash)).collect();
            let theirs: Vec<_> = other
                .records
                .iter()
                .map(|r| (&r.key, r.note_hash))
                .collect();
            assert_eq!(same, theirs, "{label}: records");
        }
        assert_eq!(a.request_id, req.request_id);
        let public_inputs: Vec<Fr> = a.public_inputs.iter().map(|f| f.fr()).collect();
        let circuit = self.aliases.get(&req.circuit).unwrap_or(&req.circuit);
        let verifier = &fx.verifiers[circuit];
        assert!(
            verifier
                .verify(fx.crs.g2, a.proof.as_slice(), &public_inputs)
                .unwrap(),
            "{label}: the proof does not verify against the orchestrator's vk"
        );
        assert_eq!(
            public_inputs[shape.namespace_index],
            req.namespace.fr(),
            "{label}: namespace public input"
        );
        for (i, result) in results.iter().enumerate() {
            assert!(
                pipeline::verify_result_signature(
                    self.sig_pks[i],
                    req.namespace.fr(),
                    &shape,
                    result,
                    i
                )
                .unwrap(),
                "{label}: node {i}'s result signature"
            );
            // Not under another node's key, nor for another node index.
            assert!(
                !pipeline::verify_result_signature(
                    self.sig_pks[(i + 1) % NODES],
                    req.namespace.fr(),
                    &shape,
                    result,
                    i
                )
                .unwrap()
            );
            assert!(
                !pipeline::verify_result_signature(
                    self.sig_pks[i],
                    req.namespace.fr(),
                    &shape,
                    result,
                    (i + 1) % NODES
                )
                .unwrap()
            );
        }
        let records = (0..a.records.len())
            .map(|k| {
                let c: [HexBytes; NODES] = [0, 1, 2].map(|i| results[i].records[k].c_i.clone());
                let record_hashes = c
                    .clone()
                    .map(|c_i| FieldHex(record_hash(c_i.as_slice()).unwrap()));
                StateRecord {
                    key: a.records[k].key.clone(),
                    note_hash: a.records[k].note_hash,
                    c,
                    record_hashes,
                }
            })
            .collect();
        Answer {
            results,
            public_inputs,
            records,
            shape,
        }
    }

    /// FETCH on the three nodes, checked like an execute answer. Each answer
    /// carries the vk_hash of the package the round ran under, which an
    /// execute answer leaves out; it is checked and taken off here.
    pub fn fetch(&self, fx: &Fixture, label: &str, req: &Request) -> Answer {
        let (_, shape) = pipeline::stateless_prefix(req, &self.nodes[0].store).unwrap();
        let ns = req.namespace.fr();
        let results: [NodeResult; NODES] = self
            .nodes
            .iter()
            .map(|n| {
                let mut r = pipeline::fetch(n, ns, req.request_id).unwrap();
                let pkg = n.store.package(ns, &req.circuit).unwrap().unwrap();
                assert_eq!(r.vk_hash.take(), Some(FieldHex(pkg.vk_hash)), "{label}");
                r
            })
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        self.check(fx, label, req, shape, results)
    }

    /// Run node views that every node must refuse with `class`, naming
    /// `needle`, and check that no table changed on any node.
    pub fn refused(
        &self,
        label: &str,
        views: [NodeRequest; NODES],
        class: ErrorClass,
        needle: &str,
    ) {
        self.refused_at(label, views, &[0, 1, 2], class, needle);
    }

    /// As [`Self::refused`], but only the nodes in `at` must answer `class`
    /// (the others refuse too, with whatever their session saw).
    pub fn refused_at(
        &self,
        label: &str,
        views: [NodeRequest; NODES],
        at: &[usize],
        class: ErrorClass,
        needle: &str,
    ) {
        let before = self.snapshots();
        let own = views[0].request_id;
        let start = Instant::now();
        let results = self.run(views);
        for (i, result) in results.into_iter().enumerate() {
            let err = match result {
                Ok(_) => panic!("{label}: node {i} committed"),
                Err(e) => e,
            };
            Self::names_no_other_request(label, i, own, &before, &err);
            if at.contains(&i) {
                assert_eq!(err.class, class, "{label}: node {i}: {err}");
                assert!(
                    err.message.contains(needle),
                    "{label}: node {i}: `{}` lacks `{needle}`",
                    err.message
                );
            }
            eprintln!("REFUSED {label}: node {i}: {err}");
        }
        assert!(
            before == self.snapshots(),
            "{label}: a refused request changed a table"
        );
        eprintln!(
            "REFUSED {label}: {:.3}s on three nodes",
            start.elapsed().as_secs_f64()
        );
    }

    /// Run node views that each node refuses as `expected[i]` says (its
    /// class and every needle), check that no table changed on any node, and
    /// return how long the three answers took.
    pub fn refused_each(
        &self,
        label: &str,
        views: [NodeRequest; NODES],
        expected: [(ErrorClass, &[&str]); NODES],
    ) -> std::time::Duration {
        let before = self.snapshots();
        let own = views[0].request_id;
        let start = Instant::now();
        let results = self.run(views);
        let took = start.elapsed();
        eprintln!("REFUSED {label}: {:.3}s on three nodes", took.as_secs_f64());
        for (i, (result, (class, needles))) in results.into_iter().zip(expected).enumerate() {
            let err = match result {
                Ok(_) => panic!("{label}: node {i} committed"),
                Err(e) => e,
            };
            Self::names_no_other_request(label, i, own, &before, &err);
            eprintln!("REFUSED {label}: node {i}: {err}");
            assert_eq!(err.class, class, "{label}: node {i}: {err}");
            for needle in needles {
                assert!(
                    err.message.contains(needle),
                    "{label}: node {i}: `{}` lacks `{needle}`",
                    err.message
                );
            }
        }
        assert!(
            before == self.snapshots(),
            "{label}: a refused request changed a table"
        );
        took
    }

    /// The node-held vector at `key`, opened from the three nodes' rows.
    pub fn opened_value(&self, namespace: u64, key: &str) -> Vec<Fr> {
        let rows: Vec<_> = self
            .nodes
            .iter()
            .map(|n| {
                n.store
                    .value(Fr::from(namespace), key)
                    .unwrap()
                    .unwrap()
                    .vec
            })
            .collect();
        open_vec([&rows[0], &rows[1], &rows[2]])
    }

    /// A client-held record opened from its three thirds for `owner`.
    pub fn opened_record(&self, namespace: u64, record: &StateRecord, owner: Point) -> Vec<Fr> {
        let vecs: Vec<Vec<Elem>> = self
            .nodes
            .iter()
            .enumerate()
            .map(|(i, n)| {
                record::open(
                    &n.keys(),
                    Fr::from(namespace),
                    &record.key,
                    record.note_hash.fr(),
                    owner,
                    record.c[i].as_slice(),
                )
                .unwrap()
            })
            .collect();
        open_vec([&vecs[0], &vecs[1], &vecs[2]])
    }

    /// Seal `inputs` as INPUT_SHARED envelopes to the three nodes: a fresh
    /// replicated sharing of each value, node i's pair to its enc key.
    /// `tamper` replaces node 1's pair of the first input with an
    /// inconsistent one.
    pub fn seal_inputs(&mut self, req: &mut Request, inputs: &[(&str, Fr)], tamper: bool) {
        for (k, (name, value)) in inputs.iter().enumerate() {
            let x0 = Fr::rand(&mut self.rng);
            let x1 = Fr::rand(&mut self.rng);
            let sharing = [x0, x1, *value - x0 - x1];
            let ad = EnvelopeAd::for_input(req, name);
            let shares = [0, 1, 2].map(|i| {
                let mut pair = [sharing[i], sharing[(i + 2) % 3]];
                if tamper && k == 0 && i == 1 {
                    pair[0] += Fr::from(1u64);
                }
                seal_envelope(self.enc_pks[i], i, &ad, pair, &mut self.rng)
            });
            let share_hashes = shares.map(|s| FieldHex(s.hash()));
            req.shared_inputs.push(SharedInput {
                name: name.to_string(),
                shares,
                share_hashes,
            });
        }
    }
}
