//! EXECUTE and VERIFY on one node: co-noir witness extension, the proving key and a
//! collaborative ZK UltraHonk proof over the party mesh, then self-verification and
//! the namespace check. Also the round's correlated randomness, from which the
//! binder draws SAMPLE values.
//!
//! A round runs inside one MPC session: the caller connects the mesh, builds the
//! round state with [`round_state`], binds the witness (drawing samples with
//! [`sample_share`]) and calls [`execute`] with the same network. Nothing here
//! touches a store; the caller commits [`RoundOutput::stores`] only after
//! [`execute`] returned `Ok`.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use co_noir::{Poseidon2Sponge, Rep3AcvmType, Rep3CoUltraHonk};
use co_noir_types::{Rep3SharedInput, Rep3Type};
use mpc_core::protocols::rep3::Rep3PrimeFieldShare;
use mpc_core::protocols::rep3::arithmetic;
use mpc_core::protocols::rep3::conversion::A2BType;
use mpc_core::protocols::rep3::id::PartyID;
use mpc_net::Network;

pub use mpc_core::protocols::rep3::Rep3State;

use crate::crs::{self, Circuit, Crs, ZK};
use crate::error::Refusal;
use crate::field::{Fr, fr_to_hex};

/// This node's replicated share of one field element: its own summand and the
/// previous party's.
pub type Share = Rep3PrimeFieldShare<Fr>;

/// One element of a witness value or a stored vector: public, or this node's share.
pub type Elem = Rep3Type<Fr>;

// Thread and session behaviour. Everything in this module blocks:
// the MPC protocol does synchronous network I/O and the proving is CPU-bound
// (co-noir parallelises it internally with rayon). The node calls it on a blocking
// thread (tokio::task::spawn_blocking), never on the async runtime, and runs one
// session at a time per mesh port: each session binds the node's fixed mesh port,
// so a second concurrent session fails to connect (EADDRINUSE). The per-namespace
// lock does not prevent that for two different namespaces, so the node also holds
// one node-wide session lock from connecting the mesh to the end of the round.
// More parallel rounds need one mesh port (and one party connection set) per
// concurrent session, agreed between the three nodes.
/// Set up a round's correlated randomness: each party seeds a fresh PRNG from
/// local entropy and exchanges one seed with its neighbours (`reshare`), so the
/// three parties' streams are pairwise correlated. That one exchange is all the
/// communication sampling needs. Call once per round, after the mesh is up, and
/// never reuse the state for another round.
pub fn round_state<N: Network>(net: &N) -> Result<Rep3State, Refusal> {
    // The arithmetic-to-binary conversion of the round state is
    // co-snarks' default, `A2BType::Yao` (garbled-circuit conversions: few
    // communication rounds, more bytes), rather than `Direct` (bit
    // decomposition: more rounds, fewer bytes). This state only draws the
    // round's SAMPLEs, which convert nothing, so the choice costs nothing;
    // witness extension and proving build their own states inside co-noir,
    // with the same default. It becomes a performance knob if this state is
    // ever handed to code that converts shares: Yao suits a mesh with high
    // latency, Direct one with little bandwidth. All three nodes must use the
    // same type, or their conversions stop matching and the round fails.
    Rep3State::new(net, A2BType::default()).map_err(|e| {
        Refusal::mpc_failure(format!(
            "MPC session failed setting up the round's randomness: {e:#}"
        ))
    })
}

/// A fresh replicated share of a uniform value no single party knows, drawn
/// without any message. All three parties must draw in the same order (the
/// manifest's parameter order) or their shares stop matching.
pub fn sample_share(state: &mut Rep3State) -> Share {
    let (a, b) = state.rngs.rand.random_fes::<Fr>();
    Rep3PrimeFieldShare::new(a, b)
}

/// Which public input carries the namespace, and the request's namespace.
#[derive(Clone, Copy, Debug)]
pub struct NamespaceCheck {
    /// The public-input index of the manifest's `namespace_param` (the manifest
    /// check computes it from the ABI: the fields of the public parameters before it).
    pub index: usize,
    pub namespace: Fr,
}

/// Wall-clock time of each stage of a round, for the node's log.
#[derive(Clone, Copy, Debug, Default)]
pub struct Timings {
    pub witness_extension: Duration,
    pub proving_key: Duration,
    pub proof: Duration,
    pub verify: Duration,
}

/// A round that proved, verified and carries the request's namespace.
pub struct RoundOutput {
    /// The bb-format proof: 32-byte big-endian fields, no length prefix.
    pub proof: Vec<u8>,
    /// The public inputs in ACIR order (parameters, then the return value).
    pub public_inputs: Vec<Fr>,
    /// Every `TACEO_store(name, vector)` the circuit made, by name. Each vector is
    /// `[fields..., randomness]`; the last element is always a share.
    pub stores: BTreeMap<String, Vec<Elem>>,
    pub timings: Timings,
}

/// The `unsatisfied` refusal for a proof that does not verify.
pub fn unsatisfied(circuit: &str) -> Refusal {
    Refusal::unsatisfied(format!(
        "the `{circuit}` proof does not verify: the circuit's constraints do not hold \
         for this request; nothing was stored"
    ))
}

fn mpc_failure(stage: &str, e: eyre::Report) -> Refusal {
    Refusal::mpc_failure(format!("MPC session failed during {stage}: {e:#}"))
}

/// EXECUTE and VERIFY: witness extension, proving key, ZK proof, self-verification
/// against the circuit's key and `crs.g2`, then the namespace check. `input` maps
/// every co-noir witness key (`name`, or `name[i]` for wider parameters) to its
/// value. Every party calls this with the same circuit, the same public values and
/// its own shares, over the session's network.
///
/// Refusals: `unsatisfied` (422) when the proof does not verify or its namespace
/// public input is not the request's; `mpc_failure` (500) for a mesh, witness
/// extension or proving failure, or a malformed `TACEO_store` output. Either way the
/// caller stores nothing.
pub fn execute<N: Network>(
    circuit: &Circuit,
    crs: &Crs,
    input: Rep3SharedInput<Fr>,
    namespace: NamespaceCheck,
    net: &N,
) -> Result<RoundOutput, Refusal> {
    let id = PartyID::try_from(net.id()).map_err(|e| mpc_failure("set-up", e.into()))?;
    let start = Instant::now();

    let (witness, store) = co_noir::execute_circuit_rep3(input, circuit.program.clone(), net)
        .map_err(|e| mpc_failure("witness extension", e))?;
    let stores = take_stores(store.get_stored(), id)?;
    let witness_done = Instant::now();

    let proving_key =
        co_noir::generate_proving_key_rep3(&circuit.constraint_system, witness, net, &crs.prover)
            .map_err(|e| mpc_failure("the proving key build", e))?;
    let key_done = Instant::now();

    let (proof, public_inputs) = Rep3CoUltraHonk::<_, Poseidon2Sponge>::prove(
        net,
        proving_key,
        &crs.prover,
        ZK,
        &circuit.vk,
    )
    .map_err(|e| mpc_failure("proving", e))?;
    let proof_done = Instant::now();

    let expected = circuit.public_input_count();
    if public_inputs.len() != expected {
        return Err(Refusal::mpc_failure(format!(
            "the `{}` proof has {} public inputs, its verification key {expected}",
            circuit.name,
            public_inputs.len()
        )));
    }

    // Self-verification before commit. MPC witness extension does
    // not evaluate the circuit's assertions on shared values, so a request the
    // circuit rejects still yields a proof; it just does not verify. Each node
    // therefore verifies its own proof before anything is stored, and the
    // orchestrator verifies again. Skipping this would let an unsatisfiable round
    // replace stored shares with values no valid proof commits to.
    let verified = crs::verify_proof(&circuit.vk, crs.g2, proof.clone(), &public_inputs)
        .map_err(|e| mpc_failure("self-verification", e))?;
    let verify_done = Instant::now();
    if !verified {
        return Err(unsatisfied(&circuit.name));
    }

    // The namespace check. The machine binds only the namespace into
    // the proof: the manifest's namespace_param is filled by PUBLIC $namespace, and
    // a round whose proof carries any other value there is refused, so a proof
    // made under one namespace can never be presented as another's. Everything
    // else a round touches (keys, stored values) is bound by the circuit itself.
    check_namespace(&circuit.name, &public_inputs, namespace)?;

    Ok(RoundOutput {
        proof: proof.to_buffer(),
        public_inputs,
        stores,
        timings: Timings {
            witness_extension: witness_done - start,
            proving_key: key_done - witness_done,
            proof: proof_done - key_done,
            verify: verify_done - proof_done,
        },
    })
}

/// Refuse (422) unless the public input at `namespace.index` is the namespace.
pub fn check_namespace(
    circuit: &str,
    public_inputs: &[Fr],
    namespace: NamespaceCheck,
) -> Result<(), Refusal> {
    match public_inputs.get(namespace.index) {
        Some(value) if *value == namespace.namespace => Ok(()),
        Some(value) => Err(Refusal::unsatisfied(format!(
            "the `{circuit}` proof is for namespace {} (public input {}), not the request's \
             namespace {}; nothing was stored",
            fr_to_hex(*value),
            namespace.index,
            fr_to_hex(namespace.namespace)
        ))),
        None => Err(Refusal::unsatisfied(format!(
            "the `{circuit}` proof has {} public inputs, so none at the namespace index {}; \
             nothing was stored",
            public_inputs.len(),
            namespace.index
        ))),
    }
}

/// The circuit's `TACEO_store` outputs. co-brillig intercepts the oracle and keeps
/// its arguments by name; the last element of each vector is the value's blinding
/// and is promoted to a trivial share if it came out public, so a stored blinding is
/// always a share. The other elements stay as they are (public or shared).
fn take_stores(
    stored: std::collections::HashMap<String, Vec<Rep3AcvmType<Fr>>>,
    id: PartyID,
) -> Result<BTreeMap<String, Vec<Elem>>, Refusal> {
    let mut out = BTreeMap::new();
    for (name, values) in stored {
        let mut values: Vec<Elem> = values.into_iter().map(acvm_to_rep3).collect();
        match values.pop() {
            Some(Rep3Type::Public(value)) => values.push(Rep3Type::Shared(
                arithmetic::promote_to_trivial_share(id, value),
            )),
            Some(shared) => values.push(shared),
            None => {
                return Err(Refusal::mpc_failure(format!(
                    "the circuit stored an empty `{name}`"
                )));
            }
        }
        out.insert(name, values);
    }
    Ok(out)
}

fn acvm_to_rep3(value: Rep3AcvmType<Fr>) -> Elem {
    match value {
        Rep3AcvmType::Public(f) => Rep3Type::Public(f),
        Rep3AcvmType::Shared(s) => Rep3Type::Shared(s),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn namespace_mismatch_is_unsatisfied() {
        let pis = [Fr::from(0xc0ffeeu64), Fr::from(1u64)];
        let ok = NamespaceCheck {
            index: 0,
            namespace: Fr::from(0xc0ffeeu64),
        };
        check_namespace("c", &pis, ok).unwrap();
        let wrong = NamespaceCheck {
            namespace: Fr::from(0xbeefu64),
            ..ok
        };
        let err = check_namespace("c", &pis, wrong).unwrap_err();
        assert_eq!(err.status(), 422);
        assert!(err.message.contains("not the request's namespace"), "{err}");
        let out_of_range = NamespaceCheck { index: 2, ..ok };
        assert_eq!(
            check_namespace("c", &pis, out_of_range)
                .unwrap_err()
                .status(),
            422
        );
    }

    #[test]
    fn stores_promote_a_public_blinding() {
        let share = Rep3PrimeFieldShare::new(Fr::from(5u64), Fr::from(6u64));
        let stored = std::collections::HashMap::from([
            (
                "out0".to_string(),
                vec![
                    Rep3AcvmType::Public(Fr::from(7u64)),
                    Rep3AcvmType::Public(Fr::from(9u64)),
                ],
            ),
            ("out1".to_string(), vec![Rep3AcvmType::Shared(share)]),
        ]);
        let stores = take_stores(stored, PartyID::ID1).unwrap();
        assert_eq!(
            stores["out0"],
            vec![
                Rep3Type::Public(Fr::from(7u64)),
                Rep3Type::Shared(arithmetic::promote_to_trivial_share(
                    PartyID::ID1,
                    Fr::from(9u64)
                ))
            ]
        );
        assert_eq!(stores["out1"], vec![Rep3Type::Shared(share)]);
        let empty = std::collections::HashMap::from([("out0".to_string(), vec![])]);
        let err = take_stores(empty, PartyID::ID0).unwrap_err();
        assert_eq!(err.status(), 500);
        assert!(err.message.contains("empty `out0`"), "{err}");
    }
}
