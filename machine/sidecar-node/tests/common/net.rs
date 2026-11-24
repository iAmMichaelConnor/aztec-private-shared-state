//! The orchestrator's half over three started nodes, as the node tests drive
//! it: sign registry bodies and check the three signed answers; run the
//! stateless prefix, project each execute request to the three node views,
//! post them at once and check that the answers agree, that the proof
//! verifies against the test's own vk, that the namespace public input is the
//! request's and that every result signature verifies under its node's pinned
//! sig key (and under no other key or index); assemble the records from the
//! three thirds; FETCH; the admin sockets. A refused request is checked to
//! leave every table of every node unchanged when the network was given a
//! way to read its tables (`Tables`).

use std::collections::BTreeMap;
use std::time::Instant;

use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};
use serde::Serialize;
use serde_json::Value;
use sidecar_core::abi::CircuitShape;
use sidecar_core::bind::Elem;
use sidecar_core::crs::{Artifact, Circuit, Crs};
use sidecar_core::field::{FieldHex, Fr, HexBytes, RequestId};
use sidecar_core::grumpkin::{Point, point_from_wire, point_to_wire};
use sidecar_core::manifest::contract::manifest_hash;
use sidecar_core::pipeline::{self, Node};
use sidecar_core::record::{self, record_hash};
use sidecar_core::register::{
    DisableAnswer, DisableRequest, ManifestAnswer, ManifestMessage, ManifestResponse, Signature,
};
use sidecar_core::registry;
use sidecar_core::request::{NODES, NodeRequest, Request, StateRecord};
use sidecar_core::response::{NodePublicKeys, NodeResult};
use sidecar_core::schnorr::{self, public_key};
use sidecar_core::store::Store;
use sidecar_core::testing::{TestPackage, contract_manifest, manifest_message, sign_message};
use sidecar_core::{ErrorClass, Refusal};
use sidecar_node::admin::{self, AdminRequest, AdminResponse};
use sidecar_node::client::{Answer, ApiClient};

use super::*;

/// A committed round as the orchestrator checked and assembled it.
pub struct Round {
    pub results: [NodeResult; NODES],
    pub public_inputs: Vec<Fr>,
    pub records: Vec<StateRecord>,
    pub shape: CircuitShape,
}

impl Round {
    pub fn output(&self, path: &str) -> Fr {
        self.public_inputs[self.shape.return_index(path).unwrap()]
    }
}

/// What a node's tables hold, as (table, digest) pairs: two equal dumps mean
/// no row was written, changed or deleted.
pub type Dump = Vec<(String, String)>;

/// How a test reads its nodes' tables, by node index; `None` on a network
/// whose refusals are not compared.
pub type Tables = Option<Box<dyn Fn(usize) -> Dump + Send + Sync>>;

/// Three started nodes and the orchestrator's state.
pub struct Net<S: Store + 'static> {
    pub nodes: Vec<Started<S>>,
    pub clients: Vec<ApiClient>,
    pub sig_pks: [Point; NODES],
    pub crs: Crs,
    /// nargo artifacts by circuit name, as REGISTER bodies carry them.
    pub circuits: BTreeMap<String, Value>,
    /// The orchestrator's own circuits, for verifying proofs.
    pub verifiers: BTreeMap<String, Circuit>,
    pub rng: StdRng,
    pub tables: Tables,
    // Last, so the nodes (and their stores) are gone before the directory.
    pub tmp: TempDir,
}

/// Start three nodes on `stores` with the development dealer's keys and
/// master sharing, under `tmp`: the API with the dev certificates, the admin
/// sockets, the mesh on fresh loopback ports. `configure` adjusts each node
/// before it is served (a retention window, for instance). The test's own
/// verifiers are built for `circuits`.
pub async fn start_net<S: Store + 'static>(
    tmp: TempDir,
    crs: Crs,
    circuits: &[&str],
    stores: [S; NODES],
    tables: Tables,
    configure: impl Fn(&mut Node<S>),
) -> Net<S> {
    let certs = dev_certs(tmp.path());
    let nodes = sidecar_test_fixtures::nodes::start_three(
        tmp.path(),
        &certs,
        crs.clone(),
        stores,
        |_, mut node, mesh, rotation| {
            configure(&mut node);
            App::new(node, mesh, rotation)
        },
    )
    .await
    .nodes;
    let clients: Vec<ApiClient> = nodes.iter().map(|n| orchestrator(&certs, n)).collect();
    // The orchestrator pins the keys; GET /v1/nodes must match them.
    let mut sig_pks = Vec::new();
    for (i, client) in clients.iter().enumerate() {
        let served: NodePublicKeys = client
            .get("/v1/nodes")
            .await
            .unwrap()
            .json()
            .unwrap()
            .unwrap();
        assert_eq!(served, nodes[i].app.node.keys().public_keys());
        sig_pks.push(point_from_wire(&served.sig).unwrap());
    }
    let mut jsons = BTreeMap::new();
    let mut verifiers = BTreeMap::new();
    for name in circuits {
        jsons.insert(name.to_string(), circuit_json(name));
        let artifact = Artifact::read(&circuit_path(name)).unwrap();
        verifiers.insert(
            name.to_string(),
            Circuit::new(artifact, &crs.prover).unwrap(),
        );
    }
    Net {
        nodes,
        clients,
        sig_pks: sig_pks.try_into().unwrap(),
        crs,
        circuits: jsons,
        verifiers,
        rng: StdRng::seed_from_u64(0x7e57),
        tables,
        tmp,
    }
}

impl<S: Store + 'static> Net<S> {
    /// A fresh 128-bit request id.
    pub fn id(&mut self) -> RequestId {
        let mut bytes = [0u8; 16];
        self.rng.fill_bytes(&mut bytes);
        RequestId::from_u128_bytes(bytes)
    }

    /// The same path on the three nodes at once, each with its own body.
    pub async fn post3(&self, path: &str, bodies: [Vec<u8>; NODES]) -> [Answer; NODES] {
        post_each(&self.clients, path, bodies).await
    }

    /// The same JSON body on the three nodes at once.
    pub async fn post_same<T: Serialize>(&self, path: &str, body: &T) -> [Answer; NODES] {
        post_same(&self.clients, path, &serde_json::to_vec(body).unwrap()).await
    }

    /// Sign a manifest message of `names` of `example` (each package named
    /// after its circuit, the example's sidecar-path manifests) under
    /// `namespace` at `seq` and post it to the three nodes; the answers must
    /// agree, carry valid signatures and, for `seq` 0, a registration proof
    /// that verifies.
    pub async fn register(
        &mut self,
        namespace: u64,
        example: &str,
        names: &[&str],
        seq: u64,
    ) -> ManifestResponse {
        let start = Instant::now();
        let (body, answers) = self.register_answers(namespace, example, names, seq).await;
        let answers: [ManifestAnswer; NODES] =
            answers.map(|a| a.unwrap_or_else(|e| panic!("REGISTER {names:?}: {e}")));
        let checked = body.contract_manifest().unwrap();
        let hash = manifest_hash(&body.manifest).unwrap();
        let response = registry::check_manifest_answers(
            &body,
            &registry::ManifestFacts::of(&checked, hash),
            &answers,
            &self.sig_pks,
            &self.nodes[0].app.node.registration.vk,
            self.crs.g2,
        )
        .unwrap();
        eprintln!(
            "REGISTER {names:?} under {namespace:#x} (seq {seq}) over HTTPS: {:.3}s",
            start.elapsed().as_secs_f64()
        );
        response
    }

    /// Sign a manifest message of `names` of `example` under `namespace` at
    /// `seq` and post it to the three nodes; returns the body and each
    /// node's answer.
    pub async fn register_answers(
        &mut self,
        namespace: u64,
        example: &str,
        names: &[&str],
        seq: u64,
    ) -> (ManifestMessage, [Result<ManifestAnswer, Refusal>; NODES]) {
        let packages: Vec<TestPackage> = names
            .iter()
            .map(|name| TestPackage::new(name, manifest(example, name)))
            .collect();
        let verifiers = &self.verifiers;
        let document = contract_manifest(example, &packages, None, |c| verifiers[c].vk_hash);
        let body = manifest_message(
            Fr::from(namespace),
            document,
            &self.circuits,
            owner_secret(),
            seq,
        );
        let body = sign_message(body, owner_secret(), &mut self.rng).body;
        let answers = self.post_same("/v1/register", &body).await;
        let answers = answers.map(|a| a.json::<ManifestAnswer>().unwrap());
        (body, answers)
    }

    /// REGISTER `circuits` of `example` under `namespace` in one manifest
    /// message at seq 0; returns the npk_app_hash the nodes signed.
    pub async fn register_all(&mut self, namespace: u64, example: &str, circuits: &[&str]) -> Fr {
        let response = self.register(namespace, example, circuits, 0).await;
        assert_eq!(response.seq, 0);
        response.npk_app_hash.fr()
    }

    /// DISABLE `circuit` under `namespace` with `seq`, checked like REGISTER.
    pub async fn disable(&mut self, namespace: u64, circuit: &str, seq: u64) {
        let mut body = DisableRequest {
            namespace: FieldHex(Fr::from(namespace)),
            circuit: circuit.into(),
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
        let answers = self
            .post_same("/v1/disable", &body)
            .await
            .map(|a| a.json::<DisableAnswer>().unwrap().unwrap());
        let disabled = registry::check_disable_answers(&body, &answers, &self.sig_pks).unwrap();
        assert!(disabled.disabled);
    }

    /// Post three node views, one to each node, and return each node's
    /// answer.
    pub async fn run(&self, views: [NodeRequest; NODES]) -> [Result<NodeResult, Refusal>; NODES] {
        let bodies = views.map(|v| serde_json::to_vec(&v).unwrap());
        self.post3("/v1/execute", bodies)
            .await
            .map(|a| a.json::<NodeResult>().unwrap())
    }

    /// Execute a request that must commit, and check the three answers as
    /// the orchestrator does.
    pub async fn execute(&self, label: &str, req: &Request) -> Round {
        let (_, shape) = pipeline::stateless_prefix(req, &self.nodes[0].app.node.store)
            .unwrap_or_else(|e| panic!("{label}: the stateless prefix refused: {e}"));
        req.check_ciphertext_hashes().unwrap();
        let start = Instant::now();
        let answers = self.run(views(req)).await;
        let elapsed = start.elapsed();
        let mut results = Vec::new();
        for (i, a) in answers.into_iter().enumerate() {
            results.push(a.unwrap_or_else(|e| panic!("{label}: node {i}: {e}")));
        }
        let round = self.check(label, req, shape, results.try_into().unwrap());
        eprintln!(
            "ROUND {label} ({}) over HTTPS: {:.3}s",
            req.circuit,
            elapsed.as_secs_f64()
        );
        round
    }

    /// The orchestrator's checks of three committed answers (an execute or a
    /// FETCH), and the records assembled from their thirds.
    pub fn check(
        &self,
        label: &str,
        req: &Request,
        shape: CircuitShape,
        results: [NodeResult; NODES],
    ) -> Round {
        let [a, b, c] = &results;
        for other in [b, c] {
            assert_eq!(a.request_id, other.request_id, "{label}: request_id");
            assert_eq!(a.proof, other.proof, "{label}: proof");
            assert_eq!(
                a.public_inputs, other.public_inputs,
                "{label}: public inputs"
            );
            assert_eq!(a.stored, other.stored, "{label}: stored");
            let ours: Vec<_> = a.records.iter().map(|r| (&r.key, r.note_hash)).collect();
            let theirs: Vec<_> = other
                .records
                .iter()
                .map(|r| (&r.key, r.note_hash))
                .collect();
            assert_eq!(ours, theirs, "{label}: records");
        }
        assert_eq!(a.request_id, req.request_id);
        let public_inputs: Vec<Fr> = a.public_inputs.iter().map(|f| f.fr()).collect();
        assert!(
            self.verifiers[&req.circuit]
                .verify(self.crs.g2, a.proof.as_slice(), &public_inputs)
                .unwrap(),
            "{label}: the proof does not verify against the orchestrator's vk"
        );
        assert_eq!(
            public_inputs[shape.namespace_index],
            req.namespace.fr(),
            "{label}: namespace public input"
        );
        let ns = req.namespace.fr();
        for (i, result) in results.iter().enumerate() {
            // The step-14 message rebuilt from the namespace, the request id,
            // the new commitments of the public inputs, the node index and
            // H(sealed_i) of the node's thirds, under node i's pinned sig key.
            assert!(
                pipeline::verify_result_signature(self.sig_pks[i], ns, &shape, result, i).unwrap(),
                "{label}: node {i}'s result signature"
            );
            let next = (i + 1) % NODES;
            assert!(
                !pipeline::verify_result_signature(self.sig_pks[next], ns, &shape, result, i)
                    .unwrap(),
                "{label}: node {i}'s signature verifies under node {next}'s key"
            );
            assert!(
                !pipeline::verify_result_signature(self.sig_pks[i], ns, &shape, result, next)
                    .unwrap(),
                "{label}: node {i}'s signature verifies for index {next}"
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
        Round {
            results,
            public_inputs,
            records,
            shape,
        }
    }

    /// FETCH on the three nodes. Each answer carries the vk_hash its row
    /// stores, which an execute answer leaves out: it is checked against the
    /// package `req` names (as the nodes hold it now) and taken off, so a FETCH
    /// answer compares equal to the execute answer.
    pub async fn fetch(&self, req: &Request) -> [Result<NodeResult, Refusal>; NODES] {
        let body = serde_json::json!({"namespace": req.namespace, "request_id": req.request_id});
        let answers = self.post_same("/v1/fetch", &body).await;
        let mut out = Vec::with_capacity(NODES);
        for (i, a) in answers.into_iter().enumerate() {
            out.push(a.json::<NodeResult>().unwrap().map(|mut r| {
                let pkg = sidecar_core::store::StoreRead::package(
                    &self.nodes[i].app.node.store,
                    req.namespace.fr(),
                    &req.circuit,
                )
                .unwrap()
                .expect("the package of a fetched round");
                assert_eq!(
                    r.vk_hash.take(),
                    Some(FieldHex(pkg.vk_hash)),
                    "node {i}'s FETCH answer carries the row's vk_hash"
                );
                r
            }));
        }
        out.try_into().unwrap_or_else(|_| unreachable!())
    }

    /// FETCH of a committed request, checked like an execute answer.
    pub async fn fetch_checked(&self, label: &str, req: &Request) -> Round {
        let (_, shape) = pipeline::stateless_prefix(req, &self.nodes[0].app.node.store).unwrap();
        let mut results = Vec::new();
        for (i, r) in self.fetch(req).await.into_iter().enumerate() {
            results.push(r.unwrap_or_else(|e| panic!("{label}: FETCH at node {i}: {e}")));
        }
        self.check(label, req, shape, results.try_into().unwrap())
    }

    /// Every node's FETCH of `req` is refused with `class`.
    pub async fn fetch_refused(&self, label: &str, req: &Request, class: ErrorClass) {
        for (i, r) in self.fetch(req).await.into_iter().enumerate() {
            let err = r.expect_err(label);
            assert_eq!(err.class, class, "{label}: node {i}: {err}");
            eprintln!("FETCH {label}: node {i}: {err}");
        }
    }

    /// Every node's tables, or nothing when the network has no reader.
    pub fn dump(&self) -> Option<Vec<Dump>> {
        self.tables.as_ref().map(|t| (0..NODES).map(t).collect())
    }

    /// Assert that every table of every node equals `before`.
    pub fn unchanged(&self, label: &str, before: &Option<Vec<Dump>>) {
        let (Some(before), Some(after)) = (before, self.dump()) else {
            return;
        };
        for (i, (b, a)) in before.iter().zip(&after).enumerate() {
            for ((table, x), (_, y)) in b.iter().zip(a) {
                assert_eq!(x, y, "{label}: node {i}'s table `{table}` changed");
            }
        }
    }

    /// Post `req`'s views; every node must refuse with `class`, naming
    /// `needle`, and no table of any node may change.
    pub async fn refused(&self, label: &str, req: &Request, class: ErrorClass, needle: &str) {
        self.refused_views(label, views(req), class, [needle; NODES])
            .await;
    }

    /// As [`Self::refused`] for views built by the test, with a needle per
    /// node.
    pub async fn refused_views(
        &self,
        label: &str,
        views: [NodeRequest; NODES],
        class: ErrorClass,
        needles: [&str; NODES],
    ) {
        let before = self.dump();
        let start = Instant::now();
        let answers = self.run(views).await;
        for (i, answer) in answers.into_iter().enumerate() {
            let err = match answer {
                Ok(_) => panic!("{label}: node {i} committed"),
                Err(e) => e,
            };
            eprintln!("REFUSED {label}: node {i}: {err}");
            assert_eq!(err.class, class, "{label}: node {i}: {err}");
            assert!(
                err.message.contains(needles[i]),
                "{label}: node {i}: `{}` lacks `{}`",
                err.message,
                needles[i]
            );
        }
        eprintln!(
            "REFUSED {label}: {:.3}s on three nodes",
            start.elapsed().as_secs_f64()
        );
        self.unchanged(label, &before);
    }

    pub async fn admin(&self, i: usize, req: AdminRequest) -> AdminResponse {
        admin::call_async(self.nodes[i].running.admin_socket.clone(), req)
            .await
            .unwrap()
    }

    /// `restore(namespace, request_id)` on the three admin sockets.
    pub async fn restore(&self, namespace: u64, request_id: RequestId) -> [AdminResponse; NODES] {
        let mut out = Vec::new();
        for i in 0..NODES {
            out.push(
                self.admin(
                    i,
                    AdminRequest::Restore {
                        namespace: FieldHex(Fr::from(namespace)),
                        request_id,
                    },
                )
                .await,
            );
        }
        out.try_into().unwrap()
    }

    /// A client-held record opened from its three thirds for `owner`.
    pub fn opened_record(&self, namespace: u64, record: &StateRecord, owner: Point) -> Vec<Fr> {
        let vecs: Vec<Vec<Elem>> = self
            .nodes
            .iter()
            .enumerate()
            .map(|(i, n)| {
                record::open(
                    &n.app.node.keys(),
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
}
