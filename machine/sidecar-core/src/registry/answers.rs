//! The registry result message every node signs, and the orchestrator's
//! check of the three nodes' answers.

use super::*;

// ---------------------------------------------------------------------------
// The registry result message
// ---------------------------------------------------------------------------

// The registry answer signature. Every node signs its answer to a DISABLE
// with its `sig` key over poseidon2(REGISTRY_DOMAIN, namespace,
// poseidon2_hash_bytes(name), vk_hash, npk_app_hash, seq, disabled, i), where
// `i` is the node's index (0, 1, 2), `disabled` is 1 (no node signs this
// message with 0, so the field keeps a DISABLE answer from reading as any
// other), and REGISTRY_DOMAIN is ASCII "sidecar.registry" read as a
// big-endian integer. A client checks, against its own pinned `sig` keys
// (not the keys a server reports), that all three signatures verify over the
// message it rebuilds from the namespace and name it sent and the values it
// received, and that `seq` is the one it sent. One node's word is not
// enough: a lone signature binds that node only. The domain keeps a registry
// signature from being read as a manifest answer, a round result or a
// receipt signed by the same key; changing it invalidates every client
// check.
/// ASCII "sidecar.registry".
pub const REGISTRY_DOMAIN: u128 = 0x736964656361722e7265676973747279;

// The manifest answer signature. Every node signs its answer to a
// manifest message with its `sig` key over poseidon2(MANIFEST_DOMAIN,
// namespace, manifest_hash, packages_hash, npk_app_hash, seq, 0, i): the
// registry message's eight-field shape with the manifest hash in the place of
// the name hash and the packages hash in the place of the vk hash, under a
// domain of its own so it is never read as a DISABLE answer. A developer
// checks the three signatures against its own pinned `sig` keys over the
// message it rebuilds from the namespace and the contract manifest it sent,
// and `seq` is the one it sent. A tip contract's `configure` checks the same
// three signatures over the message it rebuilds from its own address, its
// pinned manifest hash and the packages hash of its own package list
// (pss_public_contract `configure`, its `MANIFEST_DOMAIN`).
/// ASCII "sidecar.manifest".
pub const MANIFEST_DOMAIN: u128 = 0x736964656361722e6d616e6966657374;

/// The manifest result message node `node` signs for a manifest message.
pub fn manifest_message(
    namespace: Fr,
    manifest_hash: Fr,
    packages_hash: Fr,
    npk_app_hash: Fr,
    seq: u64,
    node: usize,
) -> Fr {
    poseidon2_hash(&[
        Fr::from(MANIFEST_DOMAIN),
        namespace,
        manifest_hash,
        packages_hash,
        npk_app_hash,
        Fr::from(seq),
        Fr::from(0u64),
        Fr::from(node as u64),
    ])
}

/// The registry result message node `node` signs.
pub fn registry_message(
    namespace: Fr,
    name: &str,
    vk_hash: Fr,
    npk_app_hash: Fr,
    seq: u64,
    disabled: bool,
    node: usize,
) -> Fr {
    poseidon2_hash(&[
        Fr::from(REGISTRY_DOMAIN),
        namespace,
        poseidon2_hash_bytes(name.as_bytes()),
        vk_hash,
        npk_app_hash,
        Fr::from(seq),
        Fr::from(disabled as u64),
        Fr::from(node as u64),
    ])
}

// ---------------------------------------------------------------------------
// The orchestrator's checks
// ---------------------------------------------------------------------------

fn disagree(what: &str, node: usize) -> Refusal {
    Refusal::mpc_failure(format!(
        "the nodes disagree on the registry answer: node {node}'s {what} differs from node 0's"
    ))
}

fn check_signatures(
    pinned_sig_pks: &[Point; NODES],
    signatures: [Signature; NODES],
    message: impl Fn(usize) -> Fr,
) -> Result<(), Refusal> {
    for (i, (pk, signature)) in pinned_sig_pks.iter().zip(signatures).enumerate() {
        if !crate::schnorr::verify(*pk, signature, message(i)) {
            return Err(Refusal::mpc_failure(format!(
                "node {i}'s registry answer signature does not verify under its pinned sig key"
            )));
        }
    }
    Ok(())
}

/// The orchestrator's check of the three nodes' answers to one REGISTER body
/// (section 4 step 6): they agree on every value but the signatures; the
/// manifest hash and the packages hash are the body's document's (`facts`);
/// `seq` is the body's; on a `seq` 0 body all
/// three carry the same registration proof, its public inputs are the
/// namespace and the agreed `npk_app_hash`, and it verifies against the
/// built-in vk (`registration_vk`, from [`registration_circuit`]); on a later
/// body none carries one; and node i's signatures verify under
/// `pinned_sig_pks[i]` over the manifest result message. Returns the client's response,
/// without the proof. Any failure is 500: some node answered wrongly.
pub fn check_manifest_answers(
    body: &ManifestMessage,
    facts: &ManifestFacts,
    answers: &[ManifestAnswer; NODES],
    pinned_sig_pks: &[Point; NODES],
    registration_vk: &BbVerifyingKey,
    g2: G2,
) -> Result<ManifestResponse, Refusal> {
    let first = &answers[0];
    let values = |a: &ManifestAnswer| (a.manifest_hash, a.packages_hash, a.npk_app_hash, a.seq);
    for (i, a) in answers.iter().enumerate().skip(1) {
        if values(a) != values(first) {
            return Err(disagree("answer", i));
        }
        if a.registration != first.registration {
            return Err(disagree("registration proof", i));
        }
    }
    if first.manifest_hash.fr() != facts.manifest_hash
        || first.packages_hash.fr() != facts.packages_hash
    {
        return Err(Refusal::mpc_failure(
            "the nodes' answer names another contract manifest than the body's",
        ));
    }
    if first.seq != body.seq {
        return Err(Refusal::mpc_failure(format!(
            "the nodes answered seq {} to a REGISTER with seq {}",
            first.seq, body.seq
        )));
    }
    match (&first.registration, body.seq) {
        (Some(reg), 0) => {
            let expected = [body.namespace, first.npk_app_hash];
            if reg.public_inputs != expected {
                return Err(Refusal::mpc_failure(
                    "the registration proof's public inputs are not [namespace, npk_app_hash]",
                ));
            }
            let public_inputs: Vec<Fr> = expected.iter().map(|f| f.fr()).collect();
            let verified = crs::verify(registration_vk, g2, reg.proof.as_slice(), &public_inputs)
                .unwrap_or(false);
            if !verified {
                return Err(Refusal::mpc_failure(
                    "the registration proof does not verify against the built-in vk",
                ));
            }
        }
        (None, 0) => {
            return Err(Refusal::mpc_failure(
                "a seq 0 REGISTER answer carries no registration proof",
            ));
        }
        (Some(_), _) => {
            return Err(Refusal::mpc_failure(
                "a later REGISTER answer carries a registration proof",
            ));
        }
        (None, _) => {}
    }
    let (namespace, npk_app_hash) = (body.namespace.fr(), first.npk_app_hash.fr());
    let signatures = [0, 1, 2].map(|i| answers[i].signature);
    check_signatures(pinned_sig_pks, signatures, |i| {
        manifest_message(
            namespace,
            facts.manifest_hash,
            facts.packages_hash,
            npk_app_hash,
            first.seq,
            i,
        )
    })?;
    Ok(ManifestResponse {
        manifest_hash: first.manifest_hash,
        packages_hash: first.packages_hash,
        npk_app_hash: first.npk_app_hash,
        seq: first.seq,
        signatures,
    })
}

/// The orchestrator's check of the three answers to one DISABLE body: they
/// agree on every value, name the body's namespace, circuit and `seq`, say
/// `disabled: true`, and node i's signature verifies under `pinned_sig_pks[i]`
/// over the registry result message with `disabled` = 1. 500 otherwise.
pub fn check_disable_answers(
    body: &DisableRequest,
    answers: &[DisableAnswer; NODES],
    pinned_sig_pks: &[Point; NODES],
) -> Result<DisableResponse, Refusal> {
    let first = &answers[0];
    let values = |a: &DisableAnswer| {
        (
            a.namespace,
            a.circuit.clone(),
            a.vk_hash,
            a.npk_app_hash,
            a.disabled,
            a.seq,
        )
    };
    for (i, a) in answers.iter().enumerate().skip(1) {
        if values(a) != values(first) {
            return Err(disagree("answer", i));
        }
    }
    if first.namespace != body.namespace
        || first.circuit != body.circuit
        || first.seq != body.seq
        || !first.disabled
    {
        return Err(Refusal::mpc_failure(
            "the nodes' DISABLE answer does not match the body",
        ));
    }
    let signatures = [0, 1, 2].map(|i| answers[i].signature);
    check_signatures(pinned_sig_pks, signatures, |i| {
        registry_message(
            body.namespace.fr(),
            &body.circuit,
            first.vk_hash.fr(),
            first.npk_app_hash.fr(),
            first.seq,
            true,
            i,
        )
    })?;
    Ok(DisableResponse {
        namespace: first.namespace,
        circuit: first.circuit.clone(),
        vk_hash: first.vk_hash,
        npk_app_hash: first.npk_app_hash,
        disabled: true,
        seq: first.seq,
        signatures,
    })
}
