//! The AMM tip's swap (examples/amm-tip's `amm_swap_tip`, one compiled
//! circuit for both non-secret-shared intakes) on three in-process parties: co-noir witness
//! extension, the proof and its self-verification, with the witness of the
//! circuit's Prover.toml (the reserves held as shares, as a loaded pool is).
//! The circuit outputs the chain request id it computes in-circuit, which
//! must be the requester-free id the contract and the nodes compute
//! (`poseidon2([namespace, vk_hash, inputs_hash, user_nonce])`, the hidden
//! requester), and no public input may be an account address.
//!
//! Needs `scripts/prepare-data.sh` (the compiled circuit and the CRS under
//! machine/data, or DATA_DIR); the test prints why and passes if they are
//! missing (fails under `PSS_REQUIRE_DATA=1`), and fails naming the command
//! if the compiled circuit is older than its source. Run with `--release`.

use sidecar_test_fixtures::dirs::data_dir;
use std::collections::BTreeMap;

use co_noir_types::{Rep3SharedInput, Rep3Type};
use mpc_core::protocols::rep3::arithmetic::promote_to_trivial_share;
use mpc_core::protocols::rep3::id::PartyID;
use mpc_net::local::LocalNetwork;
use sidecar_core::crs::{self, Artifact, Circuit, Crs};
use sidecar_core::executor::{self, Elem, NamespaceCheck, Rep3State, RoundOutput, sample_share};
use sidecar_core::field::Fr;
use sidecar_core::testing::artifacts;
use sidecar_tip::audit::Requesters;

// examples/amm-tip/circuits/amm_swap_tip/Prover.toml: sell 25000 x
// for y with min_out 33000 on the pool [1359373, 1852331] under blinding
// 333, with user_nonce 3 under the stand-in vk hash 0x5a5a, into the
// stand-in partial note 0x5eed (the round echoes it; it checks nothing of it).
const NAMESPACE: u64 = 0xc0ffee;
const VK_HASH: u64 = 0x5a5a;
const POOL_KEY: u64 = 0xa002;
const INPUTS: [u64; 4] = [25000, 0, 33000, 0x5eed];
const USER_NONCE: u64 = 3;
const POOL: [u64; 2] = [1359373, 1852331];

fn public(v: u64) -> Elem {
    Rep3Type::Public(Fr::from(v))
}

// The witness as the binder builds it from the manifest (co-noir keys: a
// one-field parameter by its bare name, abi::witness_keys): the prefix, the
// app inputs (the partial note among them) and the nonce public to the round
// (private parameters of the circuit), the pool and its blinding LOADed as
// shares, r_new SAMPLEd.
fn input(state: &mut Rep3State, id: PartyID) -> Rep3SharedInput<Fr> {
    let shared = |v: u64| Rep3Type::Shared(promote_to_trivial_share(id, Fr::from(v)));
    let mut input = BTreeMap::new();
    input.insert("namespace".into(), public(NAMESPACE));
    input.insert("vk_hash".into(), public(VK_HASH));
    input.insert("in_slots".into(), public(POOL_KEY));
    input.insert("out_slots".into(), public(POOL_KEY));
    input.insert("amount_in".into(), public(INPUTS[0]));
    input.insert("direction".into(), public(INPUTS[1]));
    input.insert("min_out".into(), public(INPUTS[2]));
    input.insert("partial_note".into(), public(INPUTS[3]));
    input.insert("user_nonce".into(), public(USER_NONCE));
    input.insert("pool[0]".into(), shared(POOL[0]));
    input.insert("pool[1]".into(), shared(POOL[1]));
    input.insert("r_old".into(), shared(333));
    input.insert("r_new".into(), Rep3Type::Shared(sample_share(state)));
    input.insert("nsk_app".into(), shared(777));
    input
}

#[test]
fn the_swap_extends_its_witness_on_three_parties_over_the_requester_free_id() {
    let dir = data_dir();
    let path = dir.join("circuits/amm_swap_tip.json");
    let refresh = "scripts/prepare-data.sh (or set DATA_DIR)";
    if !artifacts::usable(
        &path,
        &artifacts::package("amm-tip", "amm_swap_tip"),
        refresh,
    ) {
        return;
    }
    let (g1, g2) = (dir.join("bn254_g1.dat"), dir.join("bn254_g2.dat"));
    if let Some(missing) = [&g1, &g2].into_iter().find(|p| !p.exists()) {
        return artifacts::missing(format!("{} is missing; run {refresh}", missing.display()));
    }
    let artifact = Artifact::read(&path).unwrap();
    let crs = Crs::read(
        &g1,
        &g2,
        crs::crs_circuit_size(std::slice::from_ref(&artifact)),
    )
    .unwrap();
    let circuit = Circuit::new(artifact, &crs.prover).unwrap();
    let namespace = NamespaceCheck {
        index: 0,
        namespace: Fr::from(NAMESPACE),
    };
    let results: Vec<RoundOutput> = std::thread::scope(|s| {
        let handles: Vec<_> = LocalNetwork::new_3_parties()
            .into_iter()
            .map(|net| {
                let (circuit, crs) = (&circuit, &crs);
                s.spawn(move || {
                    let mut state = executor::round_state(&net)?;
                    let id = state.id;
                    let input = input(&mut state, id);
                    executor::execute(circuit, crs, input, namespace, &net)
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().unwrap().unwrap_or_else(|e| panic!("{e}")))
            .collect()
    });
    for other in &results[1..] {
        assert_eq!(results[0].public_inputs, other.public_inputs);
        assert_eq!(results[0].proof, other.proof);
    }
    let t = results[0].timings;
    eprintln!(
        "amm_swap_tip: witness extension {:.3}s, proving key {:.3}s, ZK proof {:.3}s, verify {:.3}s",
        t.witness_extension.as_secs_f64(),
        t.proving_key.as_secs_f64(),
        t.proof.as_secs_f64(),
        t.verify.as_secs_f64()
    );

    // [namespace, vk_hash, in_slots[0], out_slots[0], request_id, old_c,
    //  new_c, npk_app_hash, ok, partial_note, code, amount_out]
    let pi = &results[0].public_inputs;
    assert_eq!(pi.len(), 12);
    assert_eq!(
        pi[..4],
        [NAMESPACE, VK_HASH, POOL_KEY, POOL_KEY].map(Fr::from)
    );
    let inputs = INPUTS.map(Fr::from);
    let id = sidecar_tip::chain_request_id(
        Fr::from(NAMESPACE),
        Fr::from(VK_HASH),
        &inputs,
        Fr::from(USER_NONCE),
    );
    assert_eq!(
        pi[4], id,
        "the proof's request id is the requester-free chain request id"
    );
    assert_eq!(
        pi[8..],
        [1u64, 0x5eed, 0, 33450].map(Fr::from),
        "ok, the partial note, code 0, amount_out 33450"
    );
    // the hidden requester: the id is the requester-free one, and no public
    // input is the Prover.toml's former requester or another account
    let accounts = Requesters::new([Fr::from(0x1234u64), Fr::from(0xbeefu64)]);
    accounts.assert_plain_id(
        id,
        Fr::from(NAMESPACE),
        Fr::from(VK_HASH),
        &inputs,
        Fr::from(USER_NONCE),
    );
    accounts.assert_call_args("the proof's public inputs", pi);
}
