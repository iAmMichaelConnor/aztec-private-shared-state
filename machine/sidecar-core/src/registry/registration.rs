//! The registration circuit compiled into the machine: its artifact, its
//! witness and the round that derives a namespace's nsk_app share.

use super::*;

// ---------------------------------------------------------------------------
// The registration circuit
// ---------------------------------------------------------------------------

/// The registration circuit's name, as the executor reports it.
pub const REGISTRATION_CIRCUIT: &str = "sidecar_register";

// The registration circuit is compiled into the machine. Its nargo artifact
// (machine/circuits/sidecar_register, compiled with Noir 1.0.0 into the
// prepared data directory by scripts/prepare-data.sh) is embedded by the build
// script (build.rs), so a node needs no compiler at run time; its vk is
// computed from this artifact and the node's CRS at start, like any circuit's,
// and the orchestrator computes the same vk from the same bytes. It has no
// namespace row and no package row, so it cannot be registered or disabled,
// and it is the only circuit that ever receives the master share (bound as
// `master`). A change to the circuit changes its vk.
/// The registration circuit's nargo artifact.
pub const REGISTRATION_ARTIFACT: &[u8] = include_bytes!(env!("PSS_REGISTRATION_ARTIFACT"));

/// The registration circuit's public inputs, in ACIR order: `[namespace,
/// npk_app_hash]`.
pub const REGISTRATION_PUBLIC_INPUTS: usize = 2;
/// The public-input index of the namespace.
pub const REGISTRATION_NAMESPACE_INDEX: usize = 0;
/// The public-input index of the proven `npk_app_hash`.
pub const REGISTRATION_NPK_APP_HASH_INDEX: usize = 1;
/// The `TACEO_store` name under which the circuit hands over the nsk_app share.
pub const NSK_APP_STORE: &str = "nsk_app";

/// The embedded registration circuit, parsed.
pub fn registration_artifact() -> eyre::Result<Artifact> {
    Artifact::from_json(REGISTRATION_CIRCUIT, REGISTRATION_ARTIFACT)
}

/// The circuits compiled into the machine, which every node's CRS must
/// cover: the registration circuit and the audit circuit
/// ([`crate::audit`]).
pub fn machine_artifacts() -> eyre::Result<Vec<Artifact>> {
    Ok(vec![
        registration_artifact()?,
        crate::audit::audit_artifact()?,
    ])
}

/// The registration circuit with its vk under `crs` (sized for it or larger).
pub fn registration_circuit(crs: &Crs) -> eyre::Result<Circuit> {
    Circuit::new(registration_artifact()?, &crs.prover)
}

/// The registration circuit's witness: the master share under `master` and the
/// public namespace under `namespace`, and nothing else.
pub fn registration_input(master: Share, namespace: Fr) -> Rep3SharedInput<Fr> {
    BTreeMap::from([
        ("master".to_string(), Rep3Type::Shared(master)),
        ("namespace".to_string(), Rep3Type::Public(namespace)),
    ])
}

/// What one node keeps from a registration round.
#[derive(Clone, Debug)]
pub struct Derived {
    /// This node's share of the namespace's nsk_app.
    pub nsk_app: Share,
    /// The proven public output.
    pub npk_app_hash: Fr,
    /// The proof and its public inputs, for the orchestrator.
    pub registration: Registration,
}

/// Run the registration circuit for `namespace` over the mesh: the executor's
/// witness extension, proof and self-verification (section 3 steps 10 and 11),
/// then the one `TACEO_store("nsk_app", [share])` output. 422 or 500 as the
/// executor refuses; 500 for any other set of outputs.
pub fn derive<N: Network>(
    circuit: &Circuit,
    crs: &Crs,
    master: Share,
    namespace: Fr,
    net: &N,
) -> Result<Derived, Refusal> {
    let check = NamespaceCheck {
        index: REGISTRATION_NAMESPACE_INDEX,
        namespace,
    };
    let out = executor::execute(
        circuit,
        crs,
        registration_input(master, namespace),
        check,
        net,
    )?;
    if out.public_inputs.len() != REGISTRATION_PUBLIC_INPUTS {
        return Err(Refusal::mpc_failure(format!(
            "the registration proof has {} public inputs, not {REGISTRATION_PUBLIC_INPUTS}",
            out.public_inputs.len()
        )));
    }
    let nsk_app = match (
        out.stores.len(),
        out.stores.get(NSK_APP_STORE).map(Vec::as_slice),
    ) {
        (1, Some([Elem::Shared(share)])) => *share,
        _ => {
            return Err(Refusal::mpc_failure(format!(
                "the registration circuit stored {:?}, not one `{NSK_APP_STORE}` share",
                out.stores.keys().collect::<Vec<_>>()
            )));
        }
    };
    Ok(Derived {
        nsk_app,
        npk_app_hash: out.public_inputs[REGISTRATION_NPK_APP_HASH_INDEX],
        registration: Registration {
            proof: HexBytes(out.proof),
            public_inputs: out.public_inputs.into_iter().map(FieldHex).collect(),
        },
    })
}
