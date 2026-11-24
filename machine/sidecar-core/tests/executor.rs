//! EXECUTE and VERIFY on three in-process parties (mpc_net's local network, one
//! thread per party) with the compiled AMM circuits of examples/amm.
//!
//! Needs `scripts/prepare-data.sh` (the circuits and the CRS under machine/data, or
//! DATA_DIR); every test prints why and passes if they are missing. The vk-hash
//! check also needs bb 6.0.0 (BB_BIN, default from toolchain.json). Run with
//! `--release`: MPC proving in a debug build is very slow.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use ark_ff::Zero;
use co_noir_types::{Rep3SharedInput, Rep3Type};
use mpc_core::protocols::rep3::arithmetic::promote_to_trivial_share;
use mpc_core::protocols::rep3::id::PartyID;
use mpc_net::local::LocalNetwork;
use sidecar_core::crs::{self, Artifact, Circuit, Crs};
use sidecar_core::error::{ErrorClass, Refusal};
use sidecar_core::executor::{self, Elem, NamespaceCheck, Rep3State, RoundOutput, sample_share};
use sidecar_core::field::{Fr, fr_from_hex, fr_to_hex};
use sidecar_core::hash::poseidon2_hash;
use sidecar_test_fixtures::dirs::data_dir;

const CONTRACT: u64 = 0xc0ffee;
const OWNER: u64 = 0x1234;
const SEED_SLOT: u64 = 0xa001;
const POOL_SLOT: u64 = 0xa002;
// The pool and nonce of examples/amm/circuits/amm_swap/Prover.toml: selling 25000
// x gives 33450 y and leaves the pool at [1384373, 1818881].
const POOL: [u64; 2] = [1359373, 1852331];
const POOL_NONCE: &str = "0x17bad57eb7869a9ec5c83647e40b5332e91091d9c5622c32286b2170177bffae";
const CIRCUITS: [&str; 3] = ["pss_seed", "amm_init", "amm_swap"];
// The namespace parameter of every AMM manifest is namespace, the first
// public input.
const NAMESPACE_INDEX: usize = 0;

// Where this test keeps its scratch files: a unique subdirectory (process id
// and a counter) of the tests' scratch root (sidecar_test_fixtures::dirs),
// never the system temp directory. The test removes its directory at the end.
fn tmp_root() -> PathBuf {
    static COUNTER: AtomicUsize = AtomicUsize::new(0);
    let root = sidecar_test_fixtures::dirs::tmp_root();
    let dir = root.join(format!(
        "executor.{}.{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

struct Fixture {
    circuits: BTreeMap<String, Circuit>,
    crs: Crs,
}

/// The three AMM circuits and a CRS sized for the largest, or `None` (with a
/// message) when scripts/prepare-data.sh has not been run.
fn fixture() -> Option<&'static Fixture> {
    static FIXTURE: OnceLock<Option<Fixture>> = OnceLock::new();
    FIXTURE
        .get_or_init(|| {
            let dir = data_dir();
            let paths: Vec<PathBuf> = CIRCUITS
                .iter()
                .map(|c| dir.join("circuits").join(format!("{c}.json")))
                .collect();
            let g1 = dir.join("bn254_g1.dat");
            let g2 = dir.join("bn254_g2.dat");
            if let Some(missing) = paths.iter().chain([&g1, &g2]).find(|p| !p.exists()) {
                sidecar_core::testing::artifacts::missing(format!(
                    "{} is missing; run scripts/prepare-data.sh (or set DATA_DIR)",
                    missing.display()
                ));
                return None;
            }
            let artifacts: Vec<Artifact> =
                paths.iter().map(|p| Artifact::read(p).unwrap()).collect();
            let size = crs::crs_circuit_size(&artifacts);
            eprintln!(
                "circuit sizes {:?}; reading {} G1 points",
                artifacts
                    .iter()
                    .map(|a| (&a.name, a.circuit_size))
                    .collect::<Vec<_>>(),
                crs::crs_points(size)
            );
            let crs = Crs::read(&g1, &g2, size).unwrap();
            let circuits = artifacts
                .into_iter()
                .map(|a| {
                    let c = Circuit::new(a, &crs.prover).unwrap();
                    (c.name.clone(), c)
                })
                .collect();
            Some(Fixture { circuits, crs })
        })
        .as_ref()
}

fn namespace_check(namespace: u64) -> NamespaceCheck {
    NamespaceCheck {
        index: NAMESPACE_INDEX,
        namespace: Fr::from(namespace),
    }
}

/// One round on three parties: each sets up its round state, binds its witness
/// with `bind` (drawing samples in parameter order) and executes.
fn run_round(
    circuit: &Circuit,
    crs: &Crs,
    namespace: NamespaceCheck,
    bind: impl Fn(&mut Rep3State, PartyID) -> Rep3SharedInput<Fr> + Sync,
) -> Vec<Result<RoundOutput, Refusal>> {
    let start = Instant::now();
    let results: Vec<_> = std::thread::scope(|s| {
        let handles: Vec<_> = LocalNetwork::new_3_parties()
            .into_iter()
            .map(|net| {
                let bind = &bind;
                s.spawn(move || {
                    let mut state = executor::round_state(&net)?;
                    let id = state.id;
                    let input = bind(&mut state, id);
                    executor::execute(circuit, crs, input, namespace, &net)
                })
            })
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });
    eprintln!(
        "{}: three-party round {:.3}s",
        circuit.name,
        start.elapsed().as_secs_f64()
    );
    results
}

/// All three parties succeeded and agree on the proof and public inputs.
fn agreed(circuit: &Circuit, results: Vec<Result<RoundOutput, Refusal>>) -> Vec<RoundOutput> {
    let outputs: Vec<RoundOutput> = results
        .into_iter()
        .map(|r| r.unwrap_or_else(|e| panic!("{}: {e}", circuit.name)))
        .collect();
    for other in &outputs[1..] {
        assert_eq!(
            outputs[0].proof, other.proof,
            "{} proofs diverged",
            circuit.name
        );
        assert_eq!(outputs[0].public_inputs, other.public_inputs);
    }
    let t = outputs[0].timings;
    eprintln!(
        "{}: witness extension {:.3}s, proving key {:.3}s, ZK proof {:.3}s, verify {:.3}s",
        circuit.name,
        t.witness_extension.as_secs_f64(),
        t.proving_key.as_secs_f64(),
        t.proof.as_secs_f64(),
        t.verify.as_secs_f64()
    );
    outputs
}

/// Open one stored element from the three parties' copies, checking that the
/// replicated shares are consistent (party i's `b` is party i-1's `a`).
fn open(parts: [&Elem; 3]) -> Fr {
    match parts {
        [
            Rep3Type::Public(a),
            Rep3Type::Public(b),
            Rep3Type::Public(c),
        ] => {
            assert!(a == b && b == c, "public element differs between parties");
            *a
        }
        [
            Rep3Type::Shared(s0),
            Rep3Type::Shared(s1),
            Rep3Type::Shared(s2),
        ] => {
            assert_eq!(s1.b, s0.a);
            assert_eq!(s2.b, s1.a);
            assert_eq!(s0.b, s2.a);
            s0.a + s1.a + s2.a
        }
        _ => panic!("parties disagree on whether an element is shared"),
    }
}

fn opened_store(outputs: &[RoundOutput], name: &str) -> Vec<Fr> {
    let len = outputs[0].stores[name].len();
    (0..len)
        .map(|k| {
            open([
                &outputs[0].stores[name][k],
                &outputs[1].stores[name][k],
                &outputs[2].stores[name][k],
            ])
        })
        .collect()
}

fn public(v: u64) -> Elem {
    Rep3Type::Public(Fr::from(v))
}

/// pss_seed's witness, as the binder builds it from examples/amm/manifests:
/// namespace, owner, out_slots public; out0_randomness and rand_seed
/// sampled, in that (parameter) order.
fn seed_input(state: &mut Rep3State, contract: u64) -> Rep3SharedInput<Fr> {
    let mut input = BTreeMap::new();
    input.insert("namespace".into(), public(contract));
    input.insert("owner".into(), public(OWNER));
    input.insert("out_slots".into(), public(SEED_SLOT));
    input.insert(
        "out0_randomness".into(),
        Rep3Type::Shared(sample_share(state)),
    );
    input.insert("rand_seed".into(), Rep3Type::Shared(sample_share(state)));
    input
}

/// amm_swap's witness against the Prover.toml pool, held as trivial shares as a
/// LOADed node-held pool would be held as shares.
fn swap_input(state: &mut Rep3State, id: PartyID, amount_in: u64) -> Rep3SharedInput<Fr> {
    let shared = |v: u64| Rep3Type::Shared(promote_to_trivial_share(id, Fr::from(v)));
    let mut input = BTreeMap::new();
    input.insert("namespace".into(), public(CONTRACT));
    input.insert("owner".into(), public(OWNER));
    input.insert("in_slots".into(), public(POOL_SLOT));
    input.insert("out_slots".into(), public(POOL_SLOT));
    input.insert("amount_in".into(), public(amount_in));
    input.insert("direction".into(), public(0));
    input.insert("in0_fields[0]".into(), shared(POOL[0]));
    input.insert("in0_fields[1]".into(), shared(POOL[1]));
    input.insert("in0_randomness".into(), shared(333));
    input.insert(
        "in0_nonce".into(),
        Rep3Type::Public(fr_from_hex(POOL_NONCE).unwrap()),
    );
    input.insert(
        "out0_randomness".into(),
        Rep3Type::Shared(sample_share(state)),
    );
    input.insert("nsk_app".into(), shared(777));
    input
}

/// bb's verification key fields and hash for a compiled circuit, or `None` (with
/// a message) when bb is not installed.
fn bb_vk(circuit: &str) -> Option<(Vec<Fr>, Fr)> {
    let bb = std::env::var_os("BB_BIN")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            // The pinned bb's place under TOOLS_DIR (default .tools in the
            // repository), as toolchain.json names it.
            let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
            let json: serde_json::Value = serde_json::from_str(
                &std::fs::read_to_string(repo.join("toolchain.json")).unwrap(),
            )
            .unwrap();
            let tools = std::env::var_os("TOOLS_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|| repo.join(".tools"));
            tools.join(json["tools"]["BB_BIN"]["path"].as_str().unwrap())
        });
    if !bb.exists() {
        eprintln!(
            "SKIPPED the bb vk-hash cross-check: no bb at {} (set BB_BIN)",
            bb.display()
        );
        return None;
    }
    let out = tmp_root();
    let artifact = data_dir().join("circuits").join(format!("{circuit}.json"));
    let status = std::process::Command::new(&bb)
        .args([
            "write_vk",
            "--scheme",
            "ultra_honk",
            "--oracle_hash",
            "poseidon2",
        ])
        .args(["--output_format", "json", "-b"])
        .arg(&artifact)
        .arg("-o")
        .arg(&out)
        .stdout(std::process::Stdio::null())
        .status()
        .unwrap();
    assert!(status.success(), "bb write_vk failed for {circuit}");
    let json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(out.join("vk.json")).unwrap()).unwrap();
    std::fs::remove_dir_all(&out).unwrap();
    let field = |v: &serde_json::Value| fr_from_hex(v.as_str().unwrap()).unwrap();
    let fields = json["vk"].as_array().unwrap().iter().map(field).collect();
    Some((fields, field(&json["hash"])))
}

/// The node's verification key of every AMM circuit is bb's, field for field, and
/// its hash is poseidon2 over those fields, as aztec.js computes the pin.
#[test]
fn vk_hashes_match_bb() {
    let Some(fx) = fixture() else { return };
    for name in CIRCUITS {
        let circuit = &fx.circuits[name];
        eprintln!(
            "{name}: node vk hash {}, {} public inputs",
            fr_to_hex(circuit.vk_hash),
            circuit.public_input_count()
        );
        let Some((fields, bb_hash)) = bb_vk(name) else {
            return;
        };
        eprintln!("{name}: bb vk hash   {}", fr_to_hex(bb_hash));
        assert_eq!(circuit.vk.to_field_elements(), fields, "{name} vk fields");
        assert_eq!(poseidon2_hash(&fields), bb_hash, "{name}: bb's hash");
        assert_eq!(circuit.vk_hash, bb_hash, "{name}: node vk hash");
    }
    let counts: Vec<usize> = CIRCUITS
        .iter()
        .map(|c| fx.circuits[*c].public_input_count())
        .collect();
    assert_eq!(counts, [5, 8, 11]);
}

/// pss_seed proves on three parties, self-verifies, verifies again from its bytes
/// as the orchestrator would, and hands back the seed note as shares.
#[test]
fn proves_pss_seed() {
    let Some(fx) = fixture() else { return };
    let circuit = &fx.circuits["pss_seed"];
    let results = run_round(circuit, &fx.crs, namespace_check(CONTRACT), |state, _| {
        seed_input(state, CONTRACT)
    });
    let outputs = agreed(circuit, results);
    let out = &outputs[0];
    assert_eq!(
        out.public_inputs[..3],
        [CONTRACT, OWNER, SEED_SLOT].map(Fr::from)
    );
    // pss_seed nullifies nothing, so its npk_app_hash output is 0
    assert!(out.public_inputs[4].is_zero());
    assert!(
        circuit
            .verify(fx.crs.g2, &out.proof, &out.public_inputs)
            .unwrap()
    );

    // the seed note: [rand_seed, out0_randomness], both shares
    for o in &outputs {
        assert_eq!(o.stores.keys().collect::<Vec<_>>(), ["out0"]);
        assert!(
            o.stores["out0"]
                .iter()
                .all(|e| matches!(e, Rep3Type::Shared(_)))
        );
    }
    let seed = opened_store(&outputs, "out0");
    assert_eq!(seed.len(), 2);
    assert!(!seed[0].is_zero() && seed[0] != seed[1]);

    // a public input changed after the fact does not verify
    let mut tampered = out.public_inputs.clone();
    tampered[0] = Fr::from(0xbeefu64);
    assert!(!circuit.verify(fx.crs.g2, &out.proof, &tampered).unwrap());
    // nor does a flipped proof byte (or it fails canonical decoding)
    let mut bytes = out.proof.clone();
    bytes[100] ^= 0xab;
    assert!(
        !circuit
            .verify(fx.crs.g2, &bytes, &out.public_inputs)
            .unwrap_or(false)
    );
}

/// A valid pss_seed proof whose namespace public input is not the request's
/// namespace is refused (422) on every party.
#[test]
fn refuses_a_namespace_mismatch() {
    let Some(fx) = fixture() else { return };
    let circuit = &fx.circuits["pss_seed"];
    // the request says namespace 0xbeef, the witness binds 0xc0ffee
    let results = run_round(circuit, &fx.crs, namespace_check(0xbeef), |state, _| {
        seed_input(state, CONTRACT)
    });
    for result in results {
        let err = result.err().expect("must be refused");
        assert_eq!(err.class, ErrorClass::Unsatisfied, "{err}");
        assert_eq!(err.status(), 422);
        assert!(
            err.message.contains("is for namespace 0x")
                && err
                    .message
                    .contains("c0ffee (public input 0), not the request's namespace")
                && err.message.contains("beef; nothing was stored"),
            "{err}"
        );
    }
}

/// amm_swap with a pool held as shares proves and returns the new pool; with
/// amount_in = 0, which fails the swap's assertion, MPC witness extension still
/// runs and proves, and every party refuses the round at self-verification.
#[test]
fn amm_swap_proves_and_amount_zero_is_unsatisfied() {
    let Some(fx) = fixture() else { return };
    let circuit = &fx.circuits["amm_swap"];
    let check = namespace_check(CONTRACT);

    let outputs = agreed(
        circuit,
        run_round(circuit, &fx.crs, check, |state, id| {
            swap_input(state, id, 25000)
        }),
    );
    let out = &outputs[0];
    assert_eq!(out.public_inputs.len(), 11);
    assert_eq!(
        out.public_inputs[..6],
        [CONTRACT, OWNER, POOL_SLOT, POOL_SLOT, 25000, 0].map(Fr::from)
    );
    assert_eq!(out.public_inputs[10], Fr::from(33450u64), "amount_out");
    assert!(
        circuit
            .verify(fx.crs.g2, &out.proof, &out.public_inputs)
            .unwrap()
    );
    let pool = opened_store(&outputs, "out0");
    assert_eq!(pool[..2], [Fr::from(1384373u64), Fr::from(1818881u64)]);

    let results = run_round(circuit, &fx.crs, check, |state, id| {
        swap_input(state, id, 0)
    });
    for result in results {
        let err = result.err().expect("must be refused");
        assert_eq!(err.class, ErrorClass::Unsatisfied, "{err}");
        assert_eq!(err.status(), 422);
        assert_eq!(
            err.message,
            "the `amm_swap` proof does not verify: the circuit's constraints do not hold \
             for this request; nothing was stored"
        );
    }
}
