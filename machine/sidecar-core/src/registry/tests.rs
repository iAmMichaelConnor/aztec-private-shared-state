use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;
use ark_std::rand::SeedableRng;
use ark_std::rand::rngs::StdRng;
use mpc_net::local::LocalNetwork;
use serde_json::json;

use super::*;
use crate::error::ErrorClass;
use crate::field::fr_from_hex;
use crate::grumpkin::{Fq, point_to_wire};
use crate::manifest::QueuedIntake;
use crate::schnorr::public_key;
use crate::store::MemoryStore;
use crate::store::testing::Flaky;
use crate::testing::manifests::manifest_message as message_body;
use crate::testing::{TestPackage, TipFacts, contract_manifest};

// ---- fixtures ----

const MASTER: u64 = 0x6d6173746572;
const KAT_NAMESPACE: u64 = 0xc0ffee;
const KAT_NSK_APP: &str = "0x02ae8d3b9b6a6b6e9e5b20349f68cedb428409d2884aa23c0d98bf4d13e04eda";
const KAT_NPK_APP_HASH: &str = "0x1f21c078530872675c230b247bed26ffce80c76ab6eeb360895ca8cbd8b92e16";

fn hex(s: &str) -> Fr {
    fr_from_hex(s).unwrap()
}

/// Node i's keys. The one place a node key constructor is named.
fn node_keys(i: usize) -> NodeKeys {
    NodeKeys::generate(&mut StdRng::seed_from_u64(0x5e9 + i as u64))
}

fn pinned() -> [Point; NODES] {
    [0, 1, 2].map(|i| node_keys(i).sig_pk())
}

/// Dealer-known replicated shares of `value`: party i holds
/// `(a_i, a_{i-1})` with `a_0 + a_1 + a_2 = value`.
fn dealer_shares(value: Fr) -> [Share; NODES] {
    let a = [Fr::from(11u64), Fr::from(22u64), value - Fr::from(33u64)];
    [0, 1, 2].map(|i| Share::new(a[i], a[(i + 2) % 3]))
}

/// Open three replicated shares, checking they are consistent.
fn open(shares: [Share; NODES]) -> Fr {
    assert_eq!(shares[1].b, shares[0].a);
    assert_eq!(shares[2].b, shares[1].a);
    assert_eq!(shares[0].b, shares[2].a);
    shares[0].a + shares[1].a + shares[2].a
}

fn owner_secret() -> Fq {
    Fq::from(0x0123_4567_89ab_cdefu64)
}

fn other_secret() -> Fq {
    Fq::from(0x0bad_0bad_0badu64)
}

use sidecar_test_fixtures::dirs::{data_dir, repo};

struct Fixture {
    crs: Crs,
    registration: Circuit,
    /// nargo's output, by circuit id.
    circuits: BTreeMap<String, Value>,
    /// Each circuit's vk hash under `crs`.
    vk_hashes: BTreeMap<String, Fr>,
    manifests: BTreeMap<&'static str, Value>,
}

const APPS: [&str; 2] = ["pss_seed", "amm_init"];

/// The CRS and the compiled AMM circuits of scripts/prepare-data.sh, or
/// `None` (with a message) when they are missing.
fn fixture() -> Option<&'static Fixture> {
    static FIXTURE: OnceLock<Option<Fixture>> = OnceLock::new();
    FIXTURE
        .get_or_init(|| {
            let dir = data_dir();
            let g1 = dir.join("bn254_g1.dat");
            let g2 = dir.join("bn254_g2.dat");
            let paths: Vec<PathBuf> = APPS
                .iter()
                .map(|c| dir.join("circuits").join(format!("{c}.json")))
                .collect();
            if let Some(missing) = paths.iter().chain([&g1, &g2]).find(|p| !p.exists()) {
                crate::testing::artifacts::missing(format!(
                    "{} is missing; run scripts/prepare-data.sh (or set DATA_DIR)",
                    missing.display()
                ));
                return None;
            }
            let read =
                |p: &Path| -> Value { serde_json::from_slice(&std::fs::read(p).unwrap()).unwrap() };
            let mut sizes = vec![registration_artifact().unwrap().circuit_size];
            let mut artifacts = Vec::new();
            let mut circuits = BTreeMap::new();
            let mut manifests = BTreeMap::new();
            for (name, path) in APPS.iter().zip(&paths) {
                let artifact = Artifact::read(path).unwrap();
                sizes.push(artifact.circuit_size);
                artifacts.push(artifact);
                circuits.insert(name.to_string(), read(path));
                let manifest = repo().join(format!("examples/amm/manifests/{name}.json"));
                manifests.insert(*name, read(&manifest));
            }
            let crs = Crs::read(&g1, &g2, sizes.into_iter().max().unwrap()).unwrap();
            let registration = registration_circuit(&crs).unwrap();
            let vk_hashes = artifacts
                .into_iter()
                .map(|a| {
                    let c = Circuit::new(a, &crs.prover).unwrap();
                    (c.name.clone(), c.vk_hash)
                })
                .collect();
            Some(Fixture {
                crs,
                registration,
                circuits,
                vk_hashes,
                manifests,
            })
        })
        .as_ref()
}

fn node<'a>(fx: &'a Fixture, keys: &'a NodeKeys, i: usize, master: Share) -> RegistryNode<'a> {
    RegistryNode {
        index: i,
        keys,
        master,
        crs: &fx.crs,
        registration: &fx.registration,
        holders: StateHolders::core(),
        register_check: &no_register_check,
    }
}

fn rng(seed: u64) -> StdRng {
    StdRng::seed_from_u64(seed)
}

/// The AMM packages `packages` (name, circuit) with the AMM example's
/// manifests (each renamed to its package), on the sidecar path.
fn amm_packages(fx: &Fixture, packages: &[(&str, &str)]) -> Vec<TestPackage> {
    packages
        .iter()
        .map(|(name, circuit)| {
            let mut manifest = fx.manifests[circuit].clone();
            manifest["circuit"] = json!(name);
            TestPackage::on(name, circuit, manifest)
        })
        .collect()
}

/// An unsigned manifest message of `packages` under `namespace` at `seq`,
/// with the contract facts `tip`, naming `owner`.
fn message_of(
    fx: &Fixture,
    owner: Fq,
    namespace: Fr,
    packages: &[TestPackage],
    tip: Option<&TipFacts>,
    seq: u64,
) -> ManifestMessage {
    let document = contract_manifest("amm", packages, tip, |c| fx.vk_hashes[c]);
    message_body(namespace, document, &fx.circuits, owner, seq)
}

/// A manifest message of the AMM packages `packages` (name, circuit) on the
/// sidecar path, signed by `secret`.
fn register_body(
    fx: &Fixture,
    secret: Fq,
    namespace: Fr,
    packages: &[(&str, &str)],
    seq: u64,
) -> Signed<ManifestMessage> {
    let mut req = message_of(
        fx,
        secret,
        namespace,
        &amm_packages(fx, packages),
        None,
        seq,
    );
    resign(&mut req, secret);
    Signed::from_json(&serde_json::to_string(&req).unwrap()).unwrap()
}

/// The contract facts of a test tip namespace holding the packages
/// `packages`, whose request keys are named `r<i>` and `w<j>`.
fn tip_facts(packages: &[TestPackage]) -> TipFacts {
    let names: std::collections::BTreeSet<String> = packages
        .iter()
        .filter_map(|p| p.state_keys.as_ref())
        .flat_map(|k| k.reads.iter().chain(&k.writes).cloned())
        .collect();
    let slots: Vec<(String, Fr)> = names
        .into_iter()
        .enumerate()
        .map(|(k, n)| (n, Fr::from(0x10 + k as u64)))
        .collect();
    let slots: Vec<(&str, Fr)> = slots.iter().map(|(n, s)| (n.as_str(), *s)).collect();
    TipFacts::new(Fr::from(0x0cu64), packages.len(), &slots)
}

/// One package `name` on circuit `circuit` whose circuit manifest is
/// `manifest`, queued or not: a queued one names its request keys `r<i>`
/// and `w<j>`.
fn package_of(name: &str, circuit: &str, manifest: &Value) -> TestPackage {
    let p = TestPackage::on(name, circuit, manifest.clone());
    let Ok(m) = Manifest::parse(manifest) else {
        return p;
    };
    if !m.queued() {
        return p;
    }
    let reads: Vec<String> = (0..m.state_keys.reads).map(|i| format!("r{i}")).collect();
    let writes: Vec<String> = (0..m.state_keys.writes).map(|j| format!("w{j}")).collect();
    let reads: Vec<&str> = reads.iter().map(String::as_str).collect();
    let writes: Vec<&str> = writes.iter().map(String::as_str).collect();
    p.keys(&reads, &writes)
}

/// A manifest message of the one package `pss_seed` on circuit `circuit`
/// with the circuit manifest `manifest` at seq 1, with tip facts when the
/// manifest is queued.
fn single(fx: &Fixture, ns: Fr, circuit: &str, manifest: &Value) -> ManifestMessage {
    let packages = vec![package_of("pss_seed", circuit, manifest)];
    let queued = Manifest::parse(manifest).is_ok_and(|m| m.queued());
    let tip = queued.then(|| tip_facts(&packages));
    message_of(fx, owner_secret(), ns, &packages, tip.as_ref(), 1)
}

fn resign<T: RegistryBody + HasSignature>(body: &mut T, secret: Fq) {
    let message = Signed::new_unchecked(body);
    body.set_signature(sign(secret, message, &mut rng(7)));
}

trait HasSignature {
    fn set_signature(&mut self, s: Signature);
}
impl HasSignature for ManifestMessage {
    fn set_signature(&mut self, s: Signature) {
        self.signature = s;
    }
}
impl HasSignature for DisableRequest {
    fn set_signature(&mut self, s: Signature) {
        self.signature = s;
    }
}

impl<T: RegistryBody> Signed<T> {
    fn new_unchecked(body: &T) -> Fr {
        message_for(T::DOMAIN, &serde_json::to_value(body).unwrap()).unwrap()
    }
}

fn disable_body(secret: Fq, namespace: Fr, circuit: &str, seq: u64) -> Signed<DisableRequest> {
    let mut req = DisableRequest {
        namespace: FieldHex(namespace),
        circuit: circuit.into(),
        owner_pubkey: point_to_wire(public_key(secret)),
        seq,
        signature: Signature::default(),
    };
    resign(&mut req, secret);
    Signed::new(req).unwrap()
}

/// The namespace row a dealer would leave after a first REGISTER: node
/// i's share of the KAT nsk_app, the KAT npk_app_hash, seq 0, and no
/// contract manifest yet (a later body registers one).
fn dealer_namespace<S: Store + ?Sized>(store: &S, i: usize, namespace: Fr) {
    let mut txn = store.begin(namespace);
    txn.register_namespace(NamespaceRow {
        owner_pubkey: public_key(owner_secret()),
        nsk_app: dealer_shares(hex(KAT_NSK_APP))[i],
        npk_app_hash: hex(KAT_NPK_APP_HASH),
        seq: 0,
    });
    store.commit(txn).unwrap();
}

fn no_mesh() -> Option<&'static LocalNetwork> {
    None
}

fn refused<T: std::fmt::Debug>(result: Result<T, Refusal>, class: ErrorClass, needle: &str) {
    let err = result.unwrap_err();
    assert_eq!(err.class, class, "{err}");
    assert!(
        err.message.contains(needle),
        "`{}` lacks `{needle}`",
        err.message
    );
}

/// One REGISTER on three nodes; a `seq` 0 body runs over an in-process mesh.
fn register_on_three<S: Store>(
    fx: &Fixture,
    stores: &[S; NODES],
    masters: [Share; NODES],
    body: &Signed<ManifestMessage>,
) -> Vec<Result<ManifestAnswer, Refusal>> {
    let keys: Vec<NodeKeys> = (0..NODES).map(node_keys).collect();
    if body.body.seq != 0 {
        return (0..NODES)
            .map(|i| {
                let node = node(fx, &keys[i], i, masters[i]);
                register(&stores[i], &node, no_mesh(), body, &mut rng(i as u64))
            })
            .collect();
    }
    let start = std::time::Instant::now();
    let out = std::thread::scope(|s| {
        let handles: Vec<_> = LocalNetwork::new_3_parties()
            .into_iter()
            .map(|net| {
                let keys = &keys;
                s.spawn(move || {
                    let i = net.id();
                    let node = node(fx, &keys[i], i, masters[i]);
                    let answer = register(&stores[i], &node, Some(&net), body, &mut rng(i as u64));
                    (i, answer)
                })
            })
            .collect();
        let mut out: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        out.sort_by_key(|(i, _)| *i);
        out.into_iter().map(|(_, a)| a).collect::<Vec<_>>()
    });
    eprintln!(
        "seq 0 REGISTER on three nodes: {:.3}s",
        start.elapsed().as_secs_f64()
    );
    out
}

fn all_ok(answers: Vec<Result<ManifestAnswer, Refusal>>) -> [ManifestAnswer; NODES] {
    let answers: Vec<ManifestAnswer> = answers
        .into_iter()
        .map(|a| a.unwrap_or_else(|e| panic!("{e}")))
        .collect();
    answers.try_into().unwrap()
}

/// What the orchestrator checks the three answers to `body` against.
fn facts(body: &ManifestMessage) -> ManifestFacts {
    let checked = body.contract_manifest().unwrap();
    ManifestFacts::of(&checked, manifest_hash(&body.manifest).unwrap())
}

/// The orchestrator's check of the three answers to `body`.
fn check_answers(
    fx: &Fixture,
    body: &ManifestMessage,
    answers: &[ManifestAnswer; NODES],
    pinned: &[Point; NODES],
) -> Result<ManifestResponse, Refusal> {
    check_manifest_answers(
        body,
        &facts(body),
        answers,
        pinned,
        &fx.registration.vk,
        fx.crs.g2,
    )
}

fn shares_of<S: StoreRead>(stores: &[S; NODES], namespace: Fr) -> [Share; NODES] {
    [0, 1, 2].map(|i| stores[i].namespace(namespace).unwrap().unwrap().nsk_app)
}

fn share_bytes(share: Share) -> Vec<u8> {
    let mut out = Vec::new();
    share.serialize_uncompressed(&mut out).unwrap();
    out
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

// ---- the registration circuit ----

#[test]
fn embedded_artifact_has_the_registration_shape() {
    let artifact = registration_artifact().unwrap();
    let abi = &artifact.program.abi;
    let params: Vec<_> = abi
        .parameters
        .iter()
        .map(|p| (p.name.as_str(), p.visibility))
        .collect();
    assert_eq!(
        params,
        [
            ("master", noirc_abi::AbiVisibility::Private),
            ("namespace", noirc_abi::AbiVisibility::Public)
        ]
    );
    assert!(abi.return_type.is_some());
    eprintln!("registration circuit size {}", artifact.circuit_size);
}

#[test]
fn registration_witness_holds_the_master_only_under_master() {
    let master = Share::new(Fr::from(5u64), Fr::from(6u64));
    let input = registration_input(master, Fr::from(KAT_NAMESPACE));
    assert_eq!(input.keys().collect::<Vec<_>>(), ["master", "namespace"]);
    assert_eq!(input["master"], Rep3Type::Shared(master));
    assert_eq!(
        input["namespace"],
        Rep3Type::Public(Fr::from(KAT_NAMESPACE))
    );
    let elsewhere = input
        .iter()
        .filter(|(name, _)| name.as_str() != "master")
        .any(|(_, v)| *v == Rep3Type::Shared(master) || *v == Rep3Type::Public(master.a));
    assert!(!elsewhere);
}

/// The embedded artifact is the prepared data directory's copy, compiled
/// from the current source, and its vk has the registration circuit's
/// public inputs.
#[test]
fn embedded_artifact_is_fresh_with_the_registration_public_inputs() {
    crate::testing::artifacts::require_prepared_fresh(
        Path::new(env!("PSS_REGISTRATION_ARTIFACT")),
        REGISTRATION_CIRCUIT,
    );
    let Some(fx) = fixture() else { return };
    eprintln!(
        "registration vk hash {} ({} public inputs)",
        fr_to_hex(fx.registration.vk_hash),
        fx.registration.public_input_count()
    );
    assert_eq!(
        fx.registration.public_input_count(),
        REGISTRATION_PUBLIC_INPUTS
    );
}

// ---- the first REGISTER, three-party ----

/// A first REGISTER on three nodes derives the KAT nsk_app (as shares) and
/// npk_app_hash, records the owner at seq 0 with the contract manifest and
/// every package in one commit, and the orchestrator's check accepts the
/// proof and the three signatures. Another namespace under the same master
/// gets another npk_app_hash.
#[test]
fn first_register_derives_the_kat_on_three_nodes() {
    let Some(fx) = fixture() else { return };
    let stores: [MemoryStore; NODES] = Default::default();
    let masters = dealer_shares(Fr::from(MASTER));
    let ns = Fr::from(KAT_NAMESPACE);
    let body = register_body(
        fx,
        owner_secret(),
        ns,
        &[("pss_seed", "pss_seed"), ("amm_init", "amm_init")],
        0,
    );
    let answers = all_ok(register_on_three(fx, &stores, masters, &body));
    let want = facts(&body.body);
    for a in &answers {
        assert_eq!(a.npk_app_hash.fr(), hex(KAT_NPK_APP_HASH));
        assert_eq!(a.seq, 0);
        assert_eq!(
            (a.manifest_hash.fr(), a.packages_hash.fr()),
            (want.manifest_hash, want.packages_hash)
        );
        let reg = a.registration.as_ref().unwrap();
        assert_eq!(reg.public_inputs, [FieldHex(ns), a.npk_app_hash]);
    }
    let response = check_answers(fx, &body.body, &answers, &pinned()).unwrap();
    assert_eq!(response.npk_app_hash.fr(), hex(KAT_NPK_APP_HASH));
    assert_eq!(
        response.packages_hash.fr(),
        crate::manifest::contract::packages_hash([
            ("pss_seed", fx.vk_hashes["pss_seed"]),
            ("amm_init", fx.vk_hashes["amm_init"]),
        ])
    );
    assert_eq!(open(shares_of(&stores, ns)), hex(KAT_NSK_APP));
    for (i, store) in stores.iter().enumerate() {
        let row = store.namespace(ns).unwrap().unwrap();
        assert_eq!(row.owner_pubkey, public_key(owner_secret()));
        assert_eq!(row.seq, 0);
        assert_ne!(row.nsk_app, masters[i]);
        let manifest = store.contract_manifest(ns).unwrap().unwrap();
        assert_eq!(
            (manifest.manifest_hash, manifest.seq, &manifest.document),
            (want.manifest_hash, 0, &body.body.manifest)
        );
        for name in ["pss_seed", "amm_init"] {
            let pkg = resolve(store, ns, name, None).unwrap();
            assert_eq!((pkg.seq, pkg.manifest_hash), (0, want.manifest_hash));
            assert_eq!(pkg.vk_hash, fx.vk_hashes[name]);
            for bytes in [
                &pkg.circuit_json,
                &pkg.vk,
                &serde_json::to_vec(&pkg.manifest).unwrap(),
            ] {
                assert!(!contains(bytes, &share_bytes(masters[i])[..32]));
            }
        }
    }

    // a proof is bound to its public inputs and to the built-in vk
    let mut forged = answers.clone();
    for a in &mut forged {
        a.npk_app_hash = FieldHex(Fr::from(1u64));
        a.registration.as_mut().unwrap().public_inputs[1] = FieldHex(Fr::from(1u64));
    }
    refused(
        check_answers(fx, &body.body, &forged, &pinned()),
        ErrorClass::MpcFailure,
        "does not verify against the built-in vk",
    );
    let mut without = answers.clone();
    for a in &mut without {
        a.registration = None;
    }
    refused(
        check_answers(fx, &body.body, &without, &pinned()),
        ErrorClass::MpcFailure,
        "carries no registration proof",
    );

    // another namespace, the same master
    let other = Fr::from(KAT_NAMESPACE + 1);
    let body = register_body(fx, owner_secret(), other, &[("pss_seed", "pss_seed")], 0);
    let answers = all_ok(register_on_three(fx, &stores, masters, &body));
    let response = check_answers(fx, &body.body, &answers, &pinned()).unwrap();
    assert_ne!(response.npk_app_hash.fr(), hex(KAT_NPK_APP_HASH));
    let nsk_app = open(shares_of(&stores, other));
    assert_eq!(
        crate::grumpkin::nsk_app_derive_public(Fr::from(MASTER), other),
        nsk_app
    );
    assert_eq!(
        crate::grumpkin::npk_app_hash(crate::grumpkin::npk_app(nsk_app)),
        response.npk_app_hash.fr()
    );
}

/// A first REGISTER that committed on two nodes only is repaired by
/// resending it: all three rerun the circuit, the two that hold the rows
/// replace their shares, the third writes its rows, and every node ends
/// with seq 0, the same npk_app_hash, the contract manifest and a
/// consistent sharing. A seq 0 body of another contract manifest is refused.
#[test]
fn a_partial_first_register_is_repaired_by_resending() {
    let Some(fx) = fixture() else { return };
    let stores: [Flaky; NODES] = Default::default();
    let masters = dealer_shares(Fr::from(MASTER));
    let ns = Fr::from(KAT_NAMESPACE);
    let body = register_body(fx, owner_secret(), ns, &[("pss_seed", "pss_seed")], 0);
    stores[2].fail_next_commit();
    let first = register_on_three(fx, &stores, masters, &body);
    assert!(first[0].is_ok() && first[1].is_ok());
    refused(
        first[2].clone(),
        ErrorClass::MpcFailure,
        "stopped before commit",
    );
    assert!(stores[2].namespace(ns).unwrap().is_none());
    assert!(stores[2].contract_manifest(ns).unwrap().is_none());
    // a node without the row refuses any later body: seq cannot advance
    let later = register_body(fx, owner_secret(), ns, &[("amm_init", "amm_init")], 1);
    let keys = node_keys(2);
    refused(
        register(
            &stores[2],
            &node(fx, &keys, 2, masters[2]),
            no_mesh(),
            &later,
            &mut rng(1),
        ),
        ErrorClass::Forbidden,
        "has no owner here",
    );
    // a seq 0 body of another contract manifest at a node holding one
    let keys0 = node_keys(0);
    let other = register_body(fx, owner_secret(), ns, &[("amm_init", "amm_init")], 0);
    refused(
        check_register(&stores[0], &node(fx, &keys0, 0, masters[0]), &other).map(drop),
        ErrorClass::Conflict,
        "a resent first REGISTER carries the same one",
    );
    let shares_before = [0, 1].map(|i| stores[i].namespace(ns).unwrap().unwrap().nsk_app);

    let again = all_ok(register_on_three(fx, &stores, masters, &body));
    let response = check_answers(fx, &body.body, &again, &pinned()).unwrap();
    assert_eq!(response.npk_app_hash.fr(), hex(KAT_NPK_APP_HASH));
    assert_eq!(response.seq, 0);
    assert_eq!(
        first[0].as_ref().unwrap().npk_app_hash,
        response.npk_app_hash
    );
    let shares = shares_of(&stores, ns);
    assert_eq!(open(shares), hex(KAT_NSK_APP));
    assert_ne!(
        [shares[0], shares[1]],
        shares_before,
        "a repair replaces the share"
    );
    for store in &stores {
        assert_eq!(store.namespace(ns).unwrap().unwrap().seq, 0);
        assert_eq!(store.package(ns, "pss_seed").unwrap().unwrap().seq, 0);
        assert_eq!(
            store.contract_manifest(ns).unwrap().unwrap().manifest_hash,
            response.manifest_hash.fr()
        );
    }
}

// ---- later bodies on one node ----

fn one_node() -> (MemoryStore, NodeKeys) {
    let store = MemoryStore::new();
    dealer_namespace(&store, 0, Fr::from(KAT_NAMESPACE));
    (store, node_keys(0))
}

/// A later body needs the owner's signature and the next seq. On the
/// sidecar path the stored contract manifest again re-enables, another one
/// replaces the whole manifest in one commit, and a body resent with its
/// seq, nothing committed since, is answered from the rows.
#[test]
fn later_bodies_need_the_owner_and_the_next_seq() {
    let Some(fx) = fixture() else { return };
    let ns = Fr::from(KAT_NAMESPACE);
    let (store, keys) = one_node();
    let master = dealer_shares(Fr::from(MASTER))[0];
    let node = node(fx, &keys, 0, master);
    let run =
        |body: &Signed<ManifestMessage>| register(&store, &node, no_mesh(), body, &mut rng(3));
    let seed = [("pss_seed", "pss_seed")];

    // unsigned, wrongly signed, signed by another key
    let good = register_body(fx, owner_secret(), ns, &seed, 1);
    let mut unsigned = good.clone();
    unsigned.body.signature = Signature::default();
    refused(run(&unsigned), ErrorClass::Forbidden, "does not verify");
    let mut wrong = good.clone();
    wrong.body.signature = sign(other_secret(), good.message, &mut rng(4));
    refused(run(&wrong), ErrorClass::Forbidden, "does not verify");
    let other_owner = register_body(fx, other_secret(), ns, &seed, 1);
    refused(run(&other_owner), ErrorClass::Forbidden, "is not the owner");
    // a body changed after signing
    let mut tampered = good.clone();
    tampered.body.seq = 2;
    tampered.message = Signed::new_unchecked(&tampered.body);
    refused(run(&tampered), ErrorClass::Forbidden, "does not verify");

    // wrong seq
    let skip = register_body(fx, owner_secret(), ns, &seed, 2);
    refused(
        run(&skip),
        ErrorClass::Conflict,
        "is not the namespace's next (1)",
    );
    assert!(store.package(ns, "pss_seed").unwrap().is_none());

    // seq 1 registers
    let first = run(&good).unwrap();
    assert_eq!(first.seq, 1);
    assert_eq!(first.npk_app_hash.fr(), hex(KAT_NPK_APP_HASH));
    assert!(first.registration.is_none());
    // the same body again: the stored values, seq unchanged
    let again = run(&good).unwrap();
    assert_eq!(
        (again.manifest_hash, again.npk_app_hash, again.seq),
        (first.manifest_hash, first.npk_app_hash, 1)
    );
    assert_eq!(store.namespace(ns).unwrap().unwrap().seq, 1);
    // the same contract manifest at seq 2 (a re-enable, nothing disabled)
    let same = register_body(fx, owner_secret(), ns, &seed, 2);
    let same_answer = run(&same).unwrap();
    assert_eq!(
        (same_answer.manifest_hash, same_answer.seq),
        (first.manifest_hash, 2)
    );
    // the body of seq 1 is no resend any more
    refused(
        run(&good),
        ErrorClass::Conflict,
        "is not the namespace's next (3)",
    );
    // another contract manifest replaces the stored one on the sidecar path
    let both = register_body(
        fx,
        owner_secret(),
        ns,
        &[("pss_seed", "pss_seed"), ("amm_init", "amm_init")],
        3,
    );
    let replaced = run(&both).unwrap();
    assert_ne!(replaced.manifest_hash, first.manifest_hash);
    assert_eq!(store.package_names(ns).unwrap(), ["amm_init", "pss_seed"]);
    for name in ["amm_init", "pss_seed"] {
        let pkg = store.package(ns, name).unwrap().unwrap();
        assert_eq!(
            (pkg.seq, pkg.manifest_hash),
            (3, replaced.manifest_hash.fr())
        );
    }
    let init_only = register_body(fx, owner_secret(), ns, &[("amm_init", "amm_init")], 4);
    run(&init_only).unwrap();
    assert_eq!(store.package_names(ns).unwrap(), ["amm_init"]);
    // a replayed seq 0 body once seq has advanced
    let zero = register_body(fx, owner_secret(), ns, &seed, 0);
    refused(
        run(&zero),
        ErrorClass::Conflict,
        "only while the namespace's seq is 0",
    );
    assert_eq!(store.namespace(ns).unwrap().unwrap().seq, 4);
}

/// DISABLE stops one package; the same contract manifest at the next seq
/// re-enables every package and changes nothing else.
#[test]
fn disable_and_re_enable() {
    let Some(fx) = fixture() else { return };
    let ns = Fr::from(KAT_NAMESPACE);
    let (store, keys) = one_node();
    let node = node(fx, &keys, 0, dealer_shares(Fr::from(MASTER))[0]);
    let run =
        |body: &Signed<ManifestMessage>| register(&store, &node, no_mesh(), body, &mut rng(5));
    let packages = [("pss_seed", "pss_seed"), ("amm_init", "amm_init")];
    let original = run(&register_body(fx, owner_secret(), ns, &packages, 1)).unwrap();

    // DISABLE, then resolution refuses
    let off = disable_body(owner_secret(), ns, "pss_seed", 2);
    let answer = disable(&store, &node, &off, &mut rng(6)).unwrap();
    assert_eq!((answer.disabled, answer.seq), (true, 2));
    assert_eq!(answer.vk_hash.fr(), fx.vk_hashes["pss_seed"]);
    refused(
        resolve(&store, ns, "pss_seed", None),
        ErrorClass::BadRequest,
        "`pss_seed` is disabled",
    );
    resolve(&store, ns, "amm_init", None).unwrap();
    refused(
        resolve(&store, ns, "amm_swap", None),
        ErrorClass::BadRequest,
        "not registered",
    );
    let info = package_info(&store, ns, "pss_seed").unwrap();
    assert!(info.disabled);
    assert_eq!(info.manifest_hash, original.manifest_hash);
    assert_eq!(
        info.circuit,
        crate::register::stripped_circuit(&fx.circuits["pss_seed"])
    );
    // the same DISABLE again is answered unchanged
    let again = disable(&store, &node, &off, &mut rng(7)).unwrap();
    assert_eq!((again.seq, again.vk_hash), (2, answer.vk_hash));
    assert_eq!(store.namespace(ns).unwrap().unwrap().seq, 2);
    // DISABLE of an unregistered circuit; of a circuit by another key
    refused(
        disable(
            &store,
            &node,
            &disable_body(owner_secret(), ns, "nope", 3),
            &mut rng(8),
        ),
        ErrorClass::NotFound,
        "no circuit `nope`",
    );
    refused(
        disable(
            &store,
            &node,
            &disable_body(other_secret(), ns, "pss_seed", 3),
            &mut rng(8),
        ),
        ErrorClass::Forbidden,
        "is not the owner",
    );
    refused(
        disable(
            &store,
            &node,
            &disable_body(owner_secret(), ns, "pss_seed", 5),
            &mut rng(8),
        ),
        ErrorClass::Conflict,
        "not the namespace's next (3)",
    );

    // the same contract manifest at seq 3 re-enables, under the same vks
    let back = run(&register_body(fx, owner_secret(), ns, &packages, 3)).unwrap();
    assert_eq!(back.manifest_hash, original.manifest_hash);
    for name in ["pss_seed", "amm_init"] {
        let pkg = resolve(&store, ns, name, None).unwrap();
        assert_eq!((pkg.seq, pkg.disabled), (3, false));
        assert_eq!(pkg.vk_hash, fx.vk_hashes[name]);
    }
    assert_eq!(store.contract_manifest(ns).unwrap().unwrap().seq, 3);

    // the GET lookups
    let info = namespace_info(&store, ns).unwrap();
    assert_eq!(info.seq, 3);
    assert_eq!(info.owner_pubkey, point_to_wire(public_key(owner_secret())));
    assert_eq!(info.npk_app_hash.fr(), hex(KAT_NPK_APP_HASH));
    assert_eq!(info.manifest_hash, original.manifest_hash);
    let manifest = manifest_info(&store, ns).unwrap();
    assert_eq!(
        manifest_hash(&manifest.manifest).unwrap(),
        manifest.manifest_hash.fr()
    );
    assert_eq!(manifest.seq, 3);
    refused(
        namespace_info(&store, Fr::from(9u64)),
        ErrorClass::NotFound,
        "no namespace",
    );
    refused(
        manifest_info(&store, Fr::from(9u64)),
        ErrorClass::NotFound,
        "no namespace",
    );
    refused(
        package_info(&store, ns, "nope"),
        ErrorClass::NotFound,
        "no circuit `nope`",
    );
}

/// A tip namespace's contract manifest under `upgrades: fixed` is fixed: a
/// later REGISTER of another one is refused (400) before anything is
/// built; on the sidecar path a manifest with a queue does not replace one
/// without.
#[test]
fn a_tip_namespaces_contract_manifest_is_fixed() {
    let Some(fx) = fixture() else { return };
    let ns = Fr::from(KAT_NAMESPACE);
    let (store, keys) = one_node();
    let node = node(fx, &keys, 0, dealer_shares(Fr::from(MASTER))[0]);
    // a stored tip contract manifest, as a REGISTER on a tip node leaves it
    let swap = crate::manifest::tests::amm_swap_tip();
    let packages = vec![package_of("amm_swap_tip", "pss_seed", &swap)];
    let document = contract_manifest("amm", &packages, Some(&tip_facts(&packages)), |c| {
        fx.vk_hashes[c]
    });
    let mut txn = store.begin(ns);
    txn.put_manifest(ManifestRow {
        manifest_hash: manifest_hash(&document).unwrap(),
        document,
        seq: 0,
    });
    store.commit(txn).unwrap();
    let body = register_body(fx, owner_secret(), ns, &[("pss_seed", "pss_seed")], 1);
    refused(
        register(&store, &node, no_mesh(), &body, &mut rng(9)),
        ErrorClass::BadRequest,
        "field `manifest.upgrades`: the namespace's contract manifest says upgrades `fixed`",
    );
    assert_eq!(store.namespace(ns).unwrap().unwrap().seq, 0);
}

/// A tip node (node-held keys served at the tip, by the core holder, which
/// REGISTER only consults for the mode) and the AMM tip's init round, a
/// queued package that creates its key, with its vk hash; `None` (with a
/// message) without the compiled circuit.
struct UpgradableTip {
    circuits: BTreeMap<String, Value>,
    packages: Vec<TestPackage>,
    vk_hash: Fr,
}

impl UpgradableTip {
    fn load(fx: &Fixture) -> Option<Self> {
        let path = data_dir().join("circuits/amm_init_tip.json");
        let Ok(bytes) = std::fs::read(&path) else {
            crate::testing::artifacts::missing(format!(
                "{} is missing; run scripts/prepare-data.sh examples/amm-tip",
                path.display()
            ));
            return None;
        };
        let circuit: Value = serde_json::from_slice(&bytes).unwrap();
        let artifact = Artifact::from_json("amm_init_tip", &bytes).unwrap();
        let vk_hash = Circuit::new(artifact, &fx.crs.prover).unwrap().vk_hash;
        let manifest: Value = serde_json::from_slice(
            &std::fs::read(repo().join("examples/amm-tip/manifests/amm_init_tip.json")).unwrap(),
        )
        .unwrap();
        Some(UpgradableTip {
            circuits: BTreeMap::from([("amm_init_tip".to_string(), circuit)]),
            packages: vec![TestPackage::new("amm_init_tip", manifest).keys(&[], &["pool"])],
            vk_hash,
        })
    }

    fn node<'a>(fx: &'a Fixture, keys: &'a NodeKeys) -> RegistryNode<'a> {
        fn node_held(
            _: &Manifest,
            _: crate::manifest::KeyRef,
        ) -> std::sync::Arc<dyn crate::state::StateHolder> {
            std::sync::Arc::new(crate::state::NodeRow)
        }
        RegistryNode {
            holders: StateHolders::core().with(crate::state::HolderEntry {
                mode: crate::manifest::StateMode::Node,
                path: crate::state::Path::Tip,
                make: node_held,
            }),
            ..node(fx, keys, 0, dealer_shares(Fr::from(MASTER))[0])
        }
    }

    fn facts(&self) -> TipFacts {
        tip_facts(&self.packages).upgradable()
    }

    /// The REGISTER body of the contract manifest `name` under `tip` at `seq`.
    fn body(&self, ns: Fr, name: &str, tip: &TipFacts, seq: u64) -> Signed<ManifestMessage> {
        let document = contract_manifest(name, &self.packages, Some(tip), |_| self.vk_hash);
        let mut req = message_body(ns, document, &self.circuits, owner_secret(), seq);
        resign(&mut req, owner_secret());
        Signed::new(req).unwrap()
    }
}

/// Under `upgrades: circuits` a later REGISTER of another contract manifest
/// that keeps the contract's facts is committed beside the held version: a
/// circuit whose bytes a held package stores keeps its vk (none built), the
/// answer signs the new manifest hash, and both versions stay readable by
/// hash. One that moves a contract-level fact is refused, naming it.
#[test]
fn an_upgradable_tip_namespace_takes_a_replacement() {
    let Some(fx) = fixture() else { return };
    let ns = Fr::from(KAT_NAMESPACE);
    let (store, keys) = one_node();
    let node = UpgradableTip::node(fx, &keys);
    let Some(app) = UpgradableTip::load(fx) else {
        return;
    };
    let tip = app.facts();
    let first = register(
        &store,
        &node,
        no_mesh(),
        &app.body(ns, "amm", &tip, 1),
        &mut rng(9),
    )
    .unwrap();
    let before = crate::crs::vk_builds_on_this_thread();
    let next = register(
        &store,
        &node,
        no_mesh(),
        &app.body(ns, "amm next", &tip, 2),
        &mut rng(9),
    )
    .unwrap();
    assert_eq!(
        crate::crs::vk_builds_on_this_thread(),
        before,
        "the held vk is reused"
    );
    assert_ne!(next.manifest_hash, first.manifest_hash);
    assert_eq!(next.npk_app_hash, first.npk_app_hash);
    let held: Vec<Fr> = store
        .contract_manifests(ns)
        .unwrap()
        .iter()
        .map(|m| m.manifest_hash)
        .collect();
    assert_eq!(held, [next.manifest_hash.fr(), first.manifest_hash.fr()]);
    let older = manifest_version_info(&store, ns, first.manifest_hash.fr()).unwrap();
    assert_eq!(older.seq, 1);
    let mut moved = tip.clone();
    moved.queue_slot = Fr::from(0x0du64);
    refused(
        register(
            &store,
            &node,
            no_mesh(),
            &app.body(ns, "amm moved", &moved, 3),
            &mut rng(9),
        ),
        ErrorClass::BadRequest,
        "field `manifest.queue`: differs from the held contract manifest's",
    );
}

/// With two versions held, a DISABLE stops the circuit under both: a round
/// under the older version, the one a contract's pins may still name, is
/// refused at resolution like one under the newest. A later REGISTER
/// re-enables only the version it writes.
#[test]
fn disable_reaches_every_held_version() {
    let Some(fx) = fixture() else { return };
    let ns = Fr::from(KAT_NAMESPACE);
    let (store, keys) = one_node();
    let node = UpgradableTip::node(fx, &keys);
    let Some(app) = UpgradableTip::load(fx) else {
        return;
    };
    let tip = app.facts();
    let first = register(
        &store,
        &node,
        no_mesh(),
        &app.body(ns, "amm", &tip, 1),
        &mut rng(9),
    )
    .unwrap()
    .manifest_hash
    .fr();
    let next = app.body(ns, "amm next", &tip, 2);
    let second = register(&store, &node, no_mesh(), &next, &mut rng(9))
        .unwrap()
        .manifest_hash
        .fr();

    let off = disable_body(owner_secret(), ns, "amm_init_tip", 3);
    let answer = disable(&store, &node, &off, &mut rng(6)).unwrap();
    assert_eq!((answer.disabled, answer.seq), (true, 3));
    assert_eq!(answer.vk_hash.fr(), app.vk_hash);
    for version in [None, Some(first), Some(second)] {
        refused(
            resolve(&store, ns, "amm_init_tip", version),
            ErrorClass::BadRequest,
            "`amm_init_tip` is disabled",
        );
    }
    // the same DISABLE again is answered unchanged
    let again = disable(&store, &node, &off, &mut rng(7)).unwrap();
    assert_eq!((again.seq, again.vk_hash), (3, answer.vk_hash));
    assert_eq!(store.namespace(ns).unwrap().unwrap().seq, 3);

    // the newest version again at seq 4 re-enables it, and only it
    let mut req = next.body.clone();
    req.seq = 4;
    resign(&mut req, owner_secret());
    register(
        &store,
        &node,
        no_mesh(),
        &Signed::new(req).unwrap(),
        &mut rng(9),
    )
    .unwrap();
    resolve(&store, ns, "amm_init_tip", Some(second)).unwrap();
    refused(
        resolve(&store, ns, "amm_init_tip", Some(first)),
        ErrorClass::BadRequest,
        "`amm_init_tip` is disabled",
    );
}

#[test]
fn manifests_and_circuits_are_checked() {
    let Some(fx) = fixture() else { return };
    let ns = Fr::from(KAT_NAMESPACE);
    let (store, keys) = one_node();
    let node = node(fx, &keys, 0, dealer_shares(Fr::from(MASTER))[0]);
    let run = |mut body: ManifestMessage| {
        resign(&mut body, owner_secret());
        Signed::new(body).and_then(|b| register(&store, &node, no_mesh(), &b, &mut rng(9)))
    };
    let seed = fx.manifests["pss_seed"].clone();
    let at = "field `manifest.packages[0].manifest";

    let mut queued = seed.clone();
    queued["intake"] = json!("onchain");
    queued["outcome"] = json!("none");
    queued.as_object_mut().unwrap().remove("consume");
    let base_queued = queued.clone();
    queued["binding"] = json!("exact");
    refused(
        run(single(fx, ns, "pss_seed", &queued)),
        ErrorClass::BadRequest,
        &format!("{at}.binding`"),
    );
    let mut queued = base_queued;
    queued["state"] = json!({"$state_keys.writes[0]": "chain"});
    queued["consume"] = json!([{"key": "$state_keys.writes[0]"}]);
    refused(
        run(single(fx, ns, "pss_seed", &queued)),
        ErrorClass::BadRequest,
        &format!("{at}.consume`"),
    );
    queued.as_object_mut().unwrap().remove("consume");
    let source = queued["witness"][4]["from"].clone();
    queued["witness"][4]["from"] = json!({"INPUT_SHARED": "seed"});
    queued["intake"] = json!("receipt");
    refused(
        run(single(fx, ns, "pss_seed", &queued)),
        ErrorClass::BadRequest,
        &format!("{at}.witness[4].from.INPUT_SHARED`: receipt intake"),
    );
    queued["intake"] = json!("onchain");
    refused(
        run(single(fx, ns, "pss_seed", &queued)),
        ErrorClass::BadRequest,
        "on-chain intake takes no INPUT_SHARED source; shared inputs take secret-shared receipt intake or secret-shared on-chain intake",
    );
    queued["witness"][4]["from"] = source;
    // a queued circuit's public parameters follow the contract library's
    // layout: pss_seed's public `owner` (a constant) sits where every tip
    // round has `$vk_hash`
    refused(
        run(single(fx, ns, "pss_seed", &queued)),
        ErrorClass::BadRequest,
        &format!(
            "{at}.witness`: under `onchain` intake the circuit's public parameters must be [$namespace, $vk_hash, $state_keys.reads[0..R], $state_keys.writes[0..W], the pinned values in `public_reads` order (each value, then an epoch read's epoch)], the app inputs private, the contract library's public-input layout; public element 1 is a constant where the layout has `$vk_hash`"
        ),
    );
    // with `owner` filled by `$vk_hash` the layout holds, and a node with
    // sidecar-core's holders alone serves no tip key, chain-held or
    // node-held (sidecar-tip's `holders()` adds both)
    let mut laid_out = queued.clone();
    laid_out["witness"][1]["from"] = json!({"PUBLIC": "$vk_hash"});
    refused(
        run(single(fx, ns, "pss_seed", &laid_out)),
        ErrorClass::BadRequest,
        "field `manifest.packages[0].manifest.state.$state_keys.writes[0]`: the state mode `chain` is not served by this node at the tip",
    );
    laid_out["state"] = json!({"$state_keys.writes[0]": "node"});
    refused(
        run(single(fx, ns, "pss_seed", &laid_out)),
        ErrorClass::BadRequest,
        "the state mode `node` is not served by this node at the tip",
    );
    queued["public_reads"] =
        json!([{"contract": "0x2a", "function": "get_price", "args": [], "param": "owner"}]);
    refused(
        run(single(fx, ns, "pss_seed", &queued)),
        ErrorClass::BadRequest,
        &format!(
            "{at}.public_reads[0].param`: `owner` (witness[1]) must be filled by PUBLIC with a request public name"
        ),
    );
    // a read naming the namespace by its address
    let mut own = laid_out.clone();
    own["public_reads"] = json!([{"contract": FieldHex(ns), "function": "get_price", "args": [],
                                  "param": "owner"}]);
    own["witness"][1]["from"] = json!({"PUBLIC": "owner"});
    let refusal = run(single(fx, ns, "pss_seed", &own)).unwrap_err();
    assert_eq!(refusal.class, ErrorClass::BadRequest, "{refusal}");
    // the ABI checks run on a queued manifest as on a direct one
    queued["public_reads"] = json!([]);
    queued["outputs"][0]["note_hash"] = json!("nullifiers[0]");
    refused(
        run(single(fx, ns, "pss_seed", &queued)),
        ErrorClass::BadRequest,
        &format!("{at}.outputs[0].note_hash`"),
    );

    // the manifest against the ABI
    let mut wrong = seed.clone();
    wrong["witness"][3]["from"] = json!({"SAMPLE": 2});
    refused(
        run(single(fx, ns, "pss_seed", &wrong)),
        ErrorClass::BadRequest,
        &format!("{at}.witness[3]"),
    );
    // an ABI that is not the bytecode's
    let mut mismatch = single(fx, ns, "pss_seed", &seed);
    mismatch.circuits.get_mut("pss_seed").unwrap()["abi"] = fx.circuits["amm_init"]["abi"].clone();
    let mut init = fx.manifests["amm_init"].clone();
    init["circuit"] = json!("pss_seed");
    mismatch.manifest["packages"][0]["manifest"] = init;
    refused(
        run(mismatch),
        ErrorClass::BadRequest,
        "field `circuits.pss_seed`",
    );
    // bytecode that is not a circuit
    let mut junk = single(fx, ns, "pss_seed", &seed);
    junk.circuits.get_mut("pss_seed").unwrap()["bytecode"] = json!("H4sIAAAAAAAA/wMAAAAAAAAAAAA=");
    refused(
        run(junk),
        ErrorClass::BadRequest,
        "field `circuits.pss_seed`",
    );
    // a vk hash that is not the circuit's
    let mut lying = single(fx, ns, "pss_seed", &seed);
    lying.manifest["circuits"]["pss_seed"]["vk_hash"] = json!(FieldHex(Fr::from(7u64)));
    refused(
        run(lying),
        ErrorClass::BadRequest,
        "field `manifest.circuits.pss_seed.vk_hash`",
    );
    // a circuit in its full nargo form
    let mut full = single(fx, ns, "pss_seed", &seed);
    full.circuits
        .insert("pss_seed".into(), fx.circuits["pss_seed"].clone());
    refused(
        run(full),
        ErrorClass::BadRequest,
        "field `circuits.pss_seed`",
    );
    assert!(store.package(ns, "pss_seed").unwrap().is_none());
    assert_eq!(store.namespace(ns).unwrap().unwrap().seq, 0);
}

/// On a store that holds no `values`, REGISTER refuses (400, step 3) a
/// manifest with a node-held key, naming it, and registers the same
/// circuit with the key client-held.
#[test]
fn a_node_held_key_is_refused_on_a_store_without_values() {
    let Some(fx) = fixture() else { return };
    let ns = Fr::from(KAT_NAMESPACE);
    let store = Flaky::without_values(MemoryStore::new());
    dealer_namespace(&store, 0, ns);
    let keys = node_keys(0);
    let node = node(fx, &keys, 0, dealer_shares(Fr::from(MASTER))[0]);
    let run = |mut body: ManifestMessage| {
        resign(&mut body, owner_secret());
        Signed::new(body).and_then(|b| register(&store, &node, no_mesh(), &b, &mut rng(11)))
    };
    let node_held = fx.manifests["pss_seed"].clone();
    assert_eq!(node_held["state"]["$state_keys.writes[0]"], json!("node"));
    refused(
        run(single(fx, ns, "pss_seed", &node_held)),
        ErrorClass::BadRequest,
        "$state_keys.writes[0] has the state mode `node`, and this node's store backend holds \
         no `values` table",
    );
    assert!(store.package(ns, "pss_seed").unwrap().is_none());
    assert_eq!(store.namespace(ns).unwrap().unwrap().seq, 0);
    // The same circuit with the key client-held registers.
    let mut client_held = node_held;
    client_held["state"] = json!({"$state_keys.writes[0]": "client"});
    let answer = run(single(fx, ns, "pss_seed", &client_held)).unwrap();
    assert_eq!(answer.seq, 1);
    assert!(store.package(ns, "pss_seed").unwrap().is_some());
}

/// REGISTER runs the node's own check after the manifest and state checks,
/// once per package, with the whole contract manifest: its refusal (400) is
/// the answer and nothing is stored; the same body registers on a node
/// without one.
#[test]
fn the_nodes_register_check_refuses_after_the_manifest_checks() {
    let Some(fx) = fixture() else { return };
    let ns = Fr::from(KAT_NAMESPACE);
    let (store, keys) = one_node();
    let master = dealer_shares(Fr::from(MASTER))[0];
    let body = register_body(
        fx,
        owner_secret(),
        ns,
        &[("pss_seed", "pss_seed"), ("amm_init", "amm_init")],
        1,
    );
    let refuse = |v: &RegisterView| -> Result<(), Refusal> {
        assert_eq!(v.contract.document.packages.len(), 2);
        if v.name == "amm_init" {
            return Err(Refusal::bad_request(format!(
                "field `manifest.circuit`: `{}` is refused by this node",
                v.manifest.circuit
            )));
        }
        Ok(())
    };
    let strict = RegistryNode {
        register_check: &refuse,
        ..node(fx, &keys, 0, master)
    };
    refused(
        register(&store, &strict, no_mesh(), &body, &mut rng(17)),
        ErrorClass::BadRequest,
        "field `manifest.circuit`: `amm_init` is refused by this node",
    );
    assert!(store.package(ns, "pss_seed").unwrap().is_none());
    assert!(store.contract_manifest(ns).unwrap().is_none());
    assert_eq!(store.namespace(ns).unwrap().unwrap().seq, 0);
    let answer = register(
        &store,
        &node(fx, &keys, 0, master),
        no_mesh(),
        &body,
        &mut rng(17),
    )
    .unwrap();
    assert_eq!(answer.seq, 1);
}

/// REGISTER refuses an `outcome` field under intake direct, an outcome
/// value it does not know, and a queued on-chain intake package that
/// neither completes a partial note nor says `none`, after the ABI and
/// public-layout checks and before the node's holders; with `none`
/// written out, the outcome checks pass.
#[test]
fn an_outcome_is_refused_where_the_intake_does_not_take_it() {
    let Some(fx) = fixture() else { return };
    let ns = Fr::from(KAT_NAMESPACE);
    let (store, keys) = one_node();
    let node = node(fx, &keys, 0, dealer_shares(Fr::from(MASTER))[0]);
    let run = |mut body: ManifestMessage| {
        resign(&mut body, owner_secret());
        Signed::new(body).and_then(|b| register(&store, &node, no_mesh(), &b, &mut rng(9)))
    };
    let base = fx.manifests["pss_seed"].clone();
    let mut queued = base.clone();
    queued["intake"] = json!("onchain");
    queued.as_object_mut().unwrap().remove("consume");
    queued["state"] = json!({"$state_keys.writes[0]": "chain"});
    // `owner` filled by `$vk_hash`, so the library's layout holds
    queued["witness"][1]["from"] = json!({"PUBLIC": "$vk_hash"});
    let with = |manifest: &Value, outcome: Option<&str>| {
        let mut manifest = manifest.clone();
        if let Some(form) = outcome {
            manifest["outcome"] = json!(form);
        }
        manifest
    };
    let cases = [
        (
            with(&base, Some("none")),
            "outcome`: only with a queued intake; this manifest has intake direct",
        ),
        (with(&queued, Some("claim")), "unknown variant `claim`"),
        (with(&queued, Some("call")), "unknown variant `call`"),
        (
            with(&queued, None),
            "intake onchain: no parameter takes PUBLIC `$partial_note`",
        ),
    ];
    for (manifest, want) in cases {
        refused(
            run(single(fx, ns, "pss_seed", &manifest)),
            ErrorClass::BadRequest,
            want,
        );
        assert!(store.package(ns, "pss_seed").unwrap().is_none(), "{want}");
    }
    let mut call_values = with(&queued, Some("none"));
    call_values["call_values"] = json!(["new_note_hashes[0]"]);
    refused(
        run(single(fx, ns, "pss_seed", &call_values)),
        ErrorClass::BadRequest,
        "unknown field `call_values`",
    );
    // with `none` written out the outcome checks pass and the node's
    // holders decide (sidecar-core's alone serve no tip key)
    refused(
        run(single(fx, ns, "pss_seed", &with(&queued, Some("none")))),
        ErrorClass::BadRequest,
        "the state mode `chain` is not served by this node at the tip",
    );
}

/// The secret-shared receipt round's manifest (testvectors/manifests/
/// shared_receipt_round.json) over an ABI that returns `old_c` and
/// `new_c`, in the form `outcome`.
fn shared_round(outcome: Option<&str>) -> (Manifest, CircuitShape) {
    use crate::abi::tests::{abi, array, field};
    let mut manifest = crate::manifest::tests::shared_receipt_round();
    if let Some(form) = outcome {
        manifest["outcome"] = json!(form);
        if form == "none" {
            // no partial note outside the partial form
            manifest["witness"][7]["from"] = json!({"INPUT_SHARED": "recipient"});
        }
    }
    let mut params = vec![
        ("namespace", "public", field()),
        ("vk_hash", "public", field()),
        ("in_slots", "public", array(1, field())),
        ("out_slots", "public", array(1, field())),
    ];
    for name in [
        "inputs_hash",
        "amount",
        "position",
        "partial_note",
        "outcome_key",
        "blinding",
        "outcome_tag",
    ] {
        params.push((name, "private", field()));
    }
    params.push(("pool", "private", array(2, field())));
    for name in ["r_old", "r_new", "nsk_app"] {
        params.push((name, "private", field()));
    }
    let ret = json!({"kind": "struct", "path": "Bound", "fields": [
        {"name": "old_c", "type": field()},
        {"name": "new_c", "type": field()}
    ]});
    check_manifest_value(&manifest, &abi(&params, Some(ret))).unwrap()
}

/// The value delivery axis per intake family: `none` is refused under a
/// secret-shared intake; a non-secret-shared round under `partial`
/// returns `partial_note` right after `ok`.
#[test]
fn the_partial_form_returns_its_partial_note_after_ok() {
    use crate::abi::tests::{abi, array, field};
    for outcome in [None, Some("partial")] {
        let (manifest, shape) = shared_round(outcome);
        check_outcome(&manifest, &shape).unwrap();
    }
    let (manifest, shape) = shared_round(Some("none"));
    refused(
        check_outcome(&manifest, &shape),
        ErrorClass::BadRequest,
        "field `outcome`: `none` is refused under intake shared_receipt",
    );
    let m = crate::manifest::tests::amm_swap_tip();
    let params = [
        ("namespace", "public", field()),
        ("vk_hash", "public", field()),
        ("in_slots", "public", array(1, field())),
        ("out_slots", "public", array(1, field())),
        ("amount_in", "private", field()),
        ("direction", "private", field()),
        ("min_out", "private", field()),
        ("partial_note", "private", field()),
        ("user_nonce", "private", field()),
        ("pool", "private", array(2, field())),
        ("r_old", "private", field()),
        ("r_new", "private", field()),
        ("nsk_app", "private", field()),
    ];
    let out = |names: &[&str]| {
        let fields: Vec<Value> = names
            .iter()
            .map(|n| json!({"name": n, "type": field()}))
            .collect();
        json!({"kind": "struct", "path": "pss_core::tip::outputs::BoundPartial", "fields": fields})
    };
    let good = out(&[
        "request_id",
        "old_c",
        "new_c",
        "npk_app_hash",
        "ok",
        "partial_note",
        "code",
    ]);
    let (manifest, shape) = check_manifest_value(&m, &abi(&params, Some(good))).unwrap();
    check_outcome(&manifest, &shape).unwrap();
    let late = out(&[
        "request_id",
        "old_c",
        "new_c",
        "npk_app_hash",
        "ok",
        "code",
        "partial_note",
    ]);
    let (manifest, shape) = check_manifest_value(&m, &abi(&params, Some(late))).unwrap();
    refused(
        check_outcome(&manifest, &shape),
        ErrorClass::BadRequest,
        "the round returns its `$partial_note` as the public output `partial_note` right after `ok`",
    );
    // a round that completes no note says `none`
    let mut none = crate::manifest::tests::amm_swap_tip();
    none["outcome"] = json!("none");
    none["witness"]
        .as_array_mut()
        .unwrap()
        .retain(|w| w["param"] != "partial_note");
    let params: Vec<_> = params
        .into_iter()
        .filter(|(name, ..)| *name != "partial_note")
        .collect();
    let plain = out(&["request_id", "old_c", "new_c", "npk_app_hash", "ok", "code"]);
    let (manifest, shape) = check_manifest_value(&none, &abi(&params, Some(plain))).unwrap();
    check_outcome(&manifest, &shape).unwrap();
}

/// One intake family per namespace: the rule between two packages both
/// ways (a non-secret-shared package that reads keys, a secret-shared one
/// that writes keys), the init round beside secret-shared rounds, and the
/// refusal of a manifest message that puts both families in one namespace,
/// before any node is asked.
#[test]
fn one_intake_family_per_namespace() {
    let read = |p: &str| -> Value {
        serde_json::from_str(&std::fs::read_to_string(repo().join(p)).unwrap()).unwrap()
    };
    let init = read("examples/amm-tip/manifests/amm_init_tip.json");
    let plain = read("examples/amm-tip/manifests/amm_swap_tip.json");
    let receipt = read("examples/amm-tip/manifests/amm_swap_tip_receipt.json");
    let shared = read("testvectors/manifests/shared_receipt_round.json");
    let parsed = |v: &Value| {
        let m = Manifest::parse(v).unwrap();
        let intake = m.queued_intake().unwrap();
        (m, intake)
    };
    let clash = |a: &(Manifest, QueuedIntake), b: &(Manifest, QueuedIntake)| {
        intake_families_clash((&a.0, a.1), (&b.0, b.1))
    };
    let (plain, receipt, shared, init) = (
        parsed(&plain),
        parsed(&receipt),
        parsed(&shared),
        parsed(&init),
    );
    // a secret-shared writer clashes with both non-secret-shared readers,
    // both ways round; a family with itself does not
    for reader in [&plain, &receipt] {
        assert!(clash(reader, &shared) && clash(&shared, reader));
    }
    assert!(!clash(&plain, &receipt) && !clash(&shared, &shared));
    // the init reads no key: it sits beside secret-shared rounds
    assert_eq!(init.0.state_keys.reads, 0);
    assert!(!clash(&init, &shared) && !clash(&shared, &init));
    // a non-secret-shared reader that writes nothing still clashes; a
    // secret-shared package that writes nothing does not
    let mut viewer = plain.clone();
    viewer.0.state_keys.writes = 0;
    assert!(clash(&viewer, &shared));
    let mut shared_viewer = shared.clone();
    shared_viewer.0.state_keys.writes = 0;
    assert!(!clash(&plain, &shared_viewer));
}

// ---- signed answers ----

/// Every node signs the manifest result message; the orchestrator checks
/// the three answers
/// agree, name the body's contract manifest and verify under the pinned
/// keys. A node that failed to commit is brought level by the resent body.
#[test]
fn answers_are_signed_and_checked_by_the_orchestrator() {
    let Some(fx) = fixture() else { return };
    let ns = Fr::from(KAT_NAMESPACE);
    let stores: [Flaky; NODES] = Default::default();
    for (i, store) in stores.iter().enumerate() {
        dealer_namespace(store, i, ns);
    }
    let masters = dealer_shares(Fr::from(MASTER));
    let body = register_body(
        fx,
        owner_secret(),
        ns,
        &[("pss_seed", "pss_seed"), ("amm_init", "amm_init")],
        1,
    );
    // node 2 fails to commit; the resent body brings all three registries level
    stores[2].fail_next_commit();
    let first = register_on_three(fx, &stores, masters, &body);
    assert!(first[2].is_err());
    let answers = all_ok(register_on_three(fx, &stores, masters, &body));
    for store in &stores {
        assert_eq!(store.namespace(ns).unwrap().unwrap().seq, 1);
    }
    let packages: Vec<_> = stores
        .iter()
        .map(|s| s.package(ns, "pss_seed").unwrap().unwrap())
        .collect();
    assert!(packages[1..].iter().all(|p| *p == packages[0]));

    let want = facts(&body.body);
    for (i, a) in answers.iter().enumerate() {
        let message = manifest_message(
            ns,
            want.manifest_hash,
            want.packages_hash,
            a.npk_app_hash.fr(),
            1,
            i,
        );
        assert!(crate::schnorr::verify(
            node_keys(i).sig_pk(),
            a.signature,
            message
        ));
    }
    let check = |answers: &[ManifestAnswer; NODES], pinned: &[Point; NODES]| {
        check_answers(fx, &body.body, answers, pinned)
    };
    let response = check(&answers, &pinned()).unwrap();
    assert_eq!(response.seq, 1);
    assert_eq!(response.signatures, [0, 1, 2].map(|i| answers[i].signature));

    let mut disagreeing = answers.clone();
    disagreeing[1].manifest_hash = FieldHex(Fr::from(5u64));
    refused(
        check(&disagreeing, &pinned()),
        ErrorClass::MpcFailure,
        "node 1's answer",
    );
    let mut elsewhere = answers.clone();
    for a in &mut elsewhere {
        a.packages_hash = FieldHex(Fr::from(5u64));
    }
    refused(
        check(&elsewhere, &pinned()),
        ErrorClass::MpcFailure,
        "names another contract manifest than the body's",
    );
    let mut swapped = answers.clone();
    swapped.swap(0, 2);
    refused(
        check(&swapped, &pinned()),
        ErrorClass::MpcFailure,
        "node 0's registry answer signature",
    );
    let mut wrong_pins = pinned();
    wrong_pins[2] = public_key(other_secret());
    refused(
        check(&answers, &wrong_pins),
        ErrorClass::MpcFailure,
        "node 2's registry answer signature",
    );
    let mut bad_signature = answers.clone();
    bad_signature[1].signature = answers[2].signature;
    refused(
        check(&bad_signature, &pinned()),
        ErrorClass::MpcFailure,
        "node 1's registry answer signature",
    );
    let mut with_proof = answers.clone();
    for a in &mut with_proof {
        a.registration = Some(Registration {
            proof: HexBytes(vec![]),
            public_inputs: vec![],
        });
    }
    refused(
        check(&with_proof, &pinned()),
        ErrorClass::MpcFailure,
        "later REGISTER answer carries",
    );

    // DISABLE answers
    let keys: Vec<NodeKeys> = (0..NODES).map(node_keys).collect();
    let off = disable_body(owner_secret(), ns, "pss_seed", 2);
    let disabled: Vec<DisableAnswer> = (0..NODES)
        .map(|i| {
            disable(
                &stores[i],
                &node(fx, &keys[i], i, masters[i]),
                &off,
                &mut rng(i as u64),
            )
            .unwrap()
        })
        .collect();
    let disabled: [DisableAnswer; NODES] = disabled.try_into().unwrap();
    let response = check_disable_answers(&off.body, &disabled, &pinned()).unwrap();
    assert_eq!((response.disabled, response.seq), (true, 2));
    let mut bad = disabled.clone();
    bad[0].signature = disabled[1].signature;
    refused(
        check_disable_answers(&off.body, &bad, &pinned()),
        ErrorClass::MpcFailure,
        "node 0's",
    );
    let mut other = disabled;
    other[2].vk_hash = FieldHex(Fr::from(1u64));
    refused(
        check_disable_answers(&off.body, &other, &pinned()),
        ErrorClass::MpcFailure,
        "node 2's answer",
    );
}

#[test]
fn the_manifest_message_binds_every_field() {
    let f = |n: u64| Fr::from(n);
    let base = manifest_message(f(1), f(2), f(3), f(4), 5, 0);
    for other in [
        manifest_message(f(9), f(2), f(3), f(4), 5, 0),
        manifest_message(f(1), f(9), f(3), f(4), 5, 0),
        manifest_message(f(1), f(2), f(9), f(4), 5, 0),
        manifest_message(f(1), f(2), f(3), f(9), 5, 0),
        manifest_message(f(1), f(2), f(3), f(4), 9, 0),
        manifest_message(f(1), f(2), f(3), f(4), 5, 1),
    ] {
        assert_ne!(base, other);
    }
    // never a package's REGISTER or DISABLE answer over the same fields
    assert_ne!(
        base,
        poseidon2_hash(&[
            Fr::from(REGISTRY_DOMAIN),
            f(1),
            f(2),
            f(3),
            f(4),
            f(5),
            f(0),
            f(0)
        ])
    );
    assert_eq!(
        Fr::from(MANIFEST_DOMAIN),
        Fr::from_be_bytes_mod_order(b"sidecar.manifest")
    );
}

#[test]
fn the_registry_message_binds_every_field() {
    let base = registry_message(
        Fr::from(1u64),
        "c",
        Fr::from(2u64),
        Fr::from(3u64),
        4,
        false,
        0,
    );
    for other in [
        registry_message(
            Fr::from(9u64),
            "c",
            Fr::from(2u64),
            Fr::from(3u64),
            4,
            false,
            0,
        ),
        registry_message(
            Fr::from(1u64),
            "d",
            Fr::from(2u64),
            Fr::from(3u64),
            4,
            false,
            0,
        ),
        registry_message(
            Fr::from(1u64),
            "c",
            Fr::from(9u64),
            Fr::from(3u64),
            4,
            false,
            0,
        ),
        registry_message(
            Fr::from(1u64),
            "c",
            Fr::from(2u64),
            Fr::from(9u64),
            4,
            false,
            0,
        ),
        registry_message(
            Fr::from(1u64),
            "c",
            Fr::from(2u64),
            Fr::from(3u64),
            5,
            false,
            0,
        ),
        registry_message(
            Fr::from(1u64),
            "c",
            Fr::from(2u64),
            Fr::from(3u64),
            4,
            true,
            0,
        ),
        registry_message(
            Fr::from(1u64),
            "c",
            Fr::from(2u64),
            Fr::from(3u64),
            4,
            false,
            1,
        ),
    ] {
        assert_ne!(base, other);
    }
    assert_eq!(
        Fr::from(REGISTRY_DOMAIN),
        Fr::from_be_bytes_mod_order(b"sidecar.registry")
    );
}

#[test]
fn the_message_is_over_the_received_body() {
    let mut v = json!({
        "namespace": "0xc0ffee",
        "circuit": "pss_seed",
        "owner_pubkey": point_to_wire(public_key(owner_secret())),
        "seq": 1,
        "signature": {"s": ["0x0", "0x0"], "e": ["0x0", "0x0"]}
    });
    let short = message_for(DISABLE_DOMAIN, &v).unwrap();
    let signature = sign(owner_secret(), short, &mut rng(1));
    v["signature"] = serde_json::to_value(signature).unwrap();
    let signed = Signed::<DisableRequest>::from_json(&v.to_string()).unwrap();
    assert_eq!(signed.message, short);
    // the typed body writes the namespace in 64 digits: another message
    assert_ne!(Signed::new(signed.body.clone()).unwrap().message, short);
    refused(
        Signed::<DisableRequest>::from_json(&json!({"namespace": "0x1"}).to_string()),
        ErrorClass::BadRequest,
        "",
    );
}

// ---- test vectors ----

const VECTORS: &str = "testvectors/registry.json";

fn sample_sig_secret(i: usize) -> Fq {
    Fq::from(0x5160_0000u64 + i as u64)
}

fn sig_secret_hex(secret: Fq) -> FieldHex {
    FieldHex(Fr::from_le_bytes_mod_order(&{
        let mut b = Vec::new();
        secret.serialize_uncompressed(&mut b).unwrap();
        b
    }))
}

/// The manifest message of the vectors: pss_seed alone on the sidecar path,
/// its circuit the register tests' (stripped), vk hash 0xabcd.
fn vector_message(ns: Fr) -> ManifestMessage {
    let circuit = crate::register::tests::circuit();
    let packages = [TestPackage::new(
        "pss_seed",
        crate::manifest::tests::pss_seed(),
    )];
    let document = contract_manifest("pss_seed", &packages, None, |_| Fr::from(0xabcdu64));
    message_body(
        ns,
        document,
        &BTreeMap::from([("pss_seed".to_string(), circuit)]),
        owner_secret(),
        0,
    )
}

fn vectors() -> Value {
    let ns = Fr::from(0x1f2ea9c0u64);
    let mut register_req = vector_message(ns);
    let register_message = Signed::new_unchecked(&register_req);
    register_req.signature = sign(owner_secret(), register_message, &mut rng(21));
    let mut disable_req = DisableRequest {
        namespace: FieldHex(ns),
        circuit: "pss_seed".into(),
        owner_pubkey: point_to_wire(public_key(owner_secret())),
        seq: 1,
        signature: Signature::default(),
    };
    let disable_message = Signed::new_unchecked(&disable_req);
    disable_req.signature = sign(owner_secret(), disable_message, &mut rng(22));
    let (vk_hash, npk_app_hash) = (Fr::from(0xabcdu64), hex(KAT_NPK_APP_HASH));
    let mut results = Vec::new();
    for (seq, disabled) in [(0, false), (1, true)] {
        for i in 0..NODES {
            let message = registry_message(ns, "pss_seed", vk_hash, npk_app_hash, seq, disabled, i);
            let secret = sample_sig_secret(i);
            results.push(json!({
                "namespace": FieldHex(ns),
                "name": "pss_seed",
                "vk_hash": FieldHex(vk_hash),
                "npk_app_hash": FieldHex(npk_app_hash),
                "seq": seq,
                "disabled": disabled,
                "node": i,
                "message": FieldHex(message),
                "sig_secret": sig_secret_hex(secret),
                "sig_pubkey": point_to_wire(public_key(secret)),
                "signature": sign(secret, message, &mut rng(30 + i as u64 + seq * 3)),
            }));
        }
    }
    let checked = register_req.contract_manifest().unwrap();
    let hash = manifest_hash(&register_req.manifest).unwrap();
    let packages_hash = checked.packages_hash();
    let manifest_results: Vec<Value> = (0..NODES)
        .map(|i| {
            let message = manifest_message(ns, hash, packages_hash, npk_app_hash, 0, i);
            let secret = sample_sig_secret(i);
            json!({
                "node": i,
                "message": FieldHex(message),
                "sig_pubkey": point_to_wire(public_key(secret)),
                "signature": sign(secret, message, &mut rng(40 + i as u64)),
            })
        })
        .collect();
    json!({
        "registry_message_rule": "poseidon2([REGISTRY_DOMAIN, namespace, poseidon2_hash_bytes(name), vk_hash, npk_app_hash, seq, disabled, i]); REGISTRY_DOMAIN = ASCII \"sidecar.registry\" as a big-endian integer; disabled 1 for a DISABLE answer, the only answer signed under this domain (the seq 0 entries with disabled 0 fix the message rule only); i the node index 0, 1, 2",
        "registry_domain": FieldHex(Fr::from(REGISTRY_DOMAIN)),
        "body_message_rule": "poseidon2_hash_bytes(domain || RFC 8785 JCS(body without signature)), domain cosnark-sidecar/v1/register or cosnark-sidecar/v1/disable, computed over the body as sent",
        "owner_pubkey": point_to_wire(public_key(owner_secret())),
        "register": {"body": register_req, "message": FieldHex(register_message)},
        "disable": {"body": disable_req, "message": FieldHex(disable_message)},
        "results": results,
        "manifest": {
            "manifest_message_rule": "poseidon2([MANIFEST_DOMAIN, namespace, manifest_hash, packages_hash, npk_app_hash, seq, 0, i]); MANIFEST_DOMAIN = ASCII \"sidecar.manifest\" as a big-endian integer; manifest_hash and packages_hash of the register body's contract manifest (testvectors/contract_manifest.json has the rules); npk_app_hash and the node keys those of `results`",
            "manifest_domain": FieldHex(Fr::from(MANIFEST_DOMAIN)),
            "namespace": FieldHex(ns),
            "manifest_hash": FieldHex(hash),
            "packages_hash": FieldHex(packages_hash),
            "npk_app_hash": FieldHex(npk_app_hash),
            "seq": 0,
            "results": manifest_results,
        },
    })
}

/// The committed vectors are what this code computes (tests/vectors.rs
/// checks every signature in them from the file's own values).
#[test]
fn registry_vectors_match() {
    let text = std::fs::read_to_string(repo().join(VECTORS)).unwrap();
    let committed: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(committed, vectors(), "rerun write_registry_vectors");
}

/// `cargo test -p sidecar-core write_registry_vectors -- --ignored`.
#[test]
#[ignore = "writes testvectors/; run on purpose"]
fn write_registry_vectors() {
    let text = serde_json::to_string_pretty(&vectors()).unwrap() + "\n";
    std::fs::write(repo().join(VECTORS), text).unwrap();
}
