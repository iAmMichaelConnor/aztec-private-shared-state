//! The orchestrator's checks of the three nodes' answers to an execute
//! request or a FETCH (ARCHITECTURE.md section 3, "The orchestrator's half"),
//! and the response it assembles from them: agreement, the proof under the
//! orchestrator's own vk, the namespace public input, the three result
//! signatures under the pinned `sig` keys, and each record from its three
//! thirds; and the checks of their answers to a receipt request.

use std::sync::Arc;

use sidecar_core::Refusal;
use sidecar_core::field::{FieldHex, Fr, RequestId, fr_to_hex};
use sidecar_core::grumpkin::Point;
use sidecar_core::pipeline::verify_result_signature;
use sidecar_core::request::NODES;
use sidecar_core::response::{ExecuteResponse, NodeResult};

use crate::registry::{Registry, Verifier};

// The checks of the three receipt answers. They must agree on
// `request_id`, `inputs_hash` and `expiry_block`, and each must equal what
// the orchestrator computed itself from the request and its registry copy
// (the ids) and set (the expiry): a contract checks all three receipts over
// one message, so receipts over different messages are useless to the user.
// Then node i's signature must verify under the pinned `sig_i` over that
// message (under secret-shared receipt intake the one over `C` and the
// request's sharing digest). Any failure is 500 naming the node and the
// field, like a result signature: a node that answers 200 with something
// else is a node fault. The three signatures are returned node 0 first, the
// order of the request function's `receipts: [Receipt; 3]` and of
// `TipConfig.node_sig_keys`. Each node checks its own envelopes against the
// request's summand commitments before it signs.
/// The response to a receipt request from the three nodes' answers, for
/// the request `checked` (the orchestrator's own check of it) at
/// `expiry_block`.
pub fn check_receipt(
    sig_pks: &[Point; NODES],
    checked: &sidecar_tip::CheckedReceipt,
    expiry_block: u32,
    answers: [sidecar_tip::ReceiptAnswer; NODES],
) -> Result<sidecar_tip::ReceiptResponse, Refusal> {
    let (request_id, inputs_hash) = (checked.request_id, checked.inputs_hash);
    let message = checked.message(expiry_block);
    for (i, a) in answers.iter().enumerate() {
        let differs = |field: &str, got: String, want: String| {
            Refusal::mpc_failure(format!(
                "node {i} answered the receipt with {field} {got}, the orchestrator computes {want}"
            ))
        };
        if a.request_id.fr() != request_id {
            return Err(differs(
                "request_id",
                a.request_id.to_string(),
                fr_to_hex(request_id),
            ));
        }
        if a.inputs_hash.fr() != inputs_hash {
            return Err(differs(
                "inputs_hash",
                a.inputs_hash.to_string(),
                fr_to_hex(inputs_hash),
            ));
        }
        if a.expiry_block != expiry_block {
            return Err(differs(
                "expiry_block",
                a.expiry_block.to_string(),
                expiry_block.to_string(),
            ));
        }
        if !sidecar_core::schnorr::verify(sig_pks[i], a.signature, message) {
            return Err(Refusal::mpc_failure(format!(
                "node {i}'s receipt signature does not verify under its pinned sig key"
            )));
        }
    }
    Ok(sidecar_tip::ReceiptResponse {
        request_id: FieldHex(request_id),
        inputs_hash: FieldHex(inputs_hash),
        expiry_block,
        signatures: answers.map(|a| a.signature),
    })
}

// The order and the classes of the answer checks. The three
// answers must first agree (`ExecuteResponse::assemble`: request id, proof,
// public inputs, stored keys, each record's key and note hash; 500 naming the
// field), because everything after reads the agreed values once. Then the
// proof must verify under the vk the orchestrator computed itself from the
// registered circuit and its CRS, never a vk a node sent: a proof three nodes
// agreed on that does not verify is a node fault, not the request's, so it is
// 500 (`mpc_failure`), the class that tells a client to retry or FETCH. Then
// the namespace public input must be the request's: 422 (`unsatisfied`), as
// at the node's own step 11. Last, node i's signature over the result message
// it signed at step 14, rebuilt from the agreed public inputs and node i's own
// thirds, must verify under the pinned `sig_i`; a signature that fails, or an
// answer without one (it does not parse), is 500 naming the node. Nothing is
// returned unless every check passes, and nothing the orchestrator stores
// changes either way: the nodes' rows are the record.
/// An answer the three nodes agree on, with the vk_hash still unset.
fn agree(request_id: RequestId, results: &[NodeResult; NODES]) -> Result<ExecuteResponse, Refusal> {
    ExecuteResponse::assemble(request_id, FieldHex::from(0), results.clone())
}

fn fields(values: &[FieldHex]) -> Vec<Fr> {
    values.iter().map(|f| f.fr()).collect()
}

/// The namespace public input, then the three signatures; the response with
/// the package's vk_hash.
fn finish(
    verifier: &Verifier,
    namespace: Fr,
    sig_pks: &[Point; NODES],
    results: &[NodeResult; NODES],
    mut response: ExecuteResponse,
) -> Result<ExecuteResponse, Refusal> {
    let index = verifier.shape.namespace_index;
    let got = response.public_inputs.get(index).map(|f| f.fr());
    if got != Some(namespace) {
        return Err(Refusal::unsatisfied(format!(
            "the proof's namespace public input (index {index}) is {}, not the request's {}",
            got.map(fr_to_hex).unwrap_or_else(|| "missing".into()),
            fr_to_hex(namespace)
        )));
    }
    for (i, result) in results.iter().enumerate() {
        let valid = verify_result_signature(sig_pks[i], namespace, &verifier.shape, result, i)
            .map_err(|e| {
                Refusal::mpc_failure(format!("node {i}'s result signature: {}", e.message))
            })?;
        if !valid {
            return Err(Refusal::mpc_failure(format!(
                "node {i}'s result signature does not verify under its pinned sig key"
            )));
        }
    }
    response.vk_hash = FieldHex(verifier.vk_hash);
    Ok(response)
}

/// The response to an execute request of the circuit `verifier` checks,
/// from the three nodes' answers.
pub fn check_execute(
    registry: &Registry,
    verifier: &Verifier,
    sig_pks: &[Point; NODES],
    namespace: Fr,
    request_id: RequestId,
    results: [NodeResult; NODES],
) -> Result<ExecuteResponse, Refusal> {
    let response = agree(request_id, &results)?;
    let public_inputs = fields(&response.public_inputs);
    if !verifier.verifies(registry.g2(), response.proof.as_slice(), &public_inputs) {
        return Err(Refusal::mpc_failure(format!(
            "the proof the three nodes agree on does not verify under the orchestrator's vk \
             of `{}`",
            verifier.name
        )));
    }
    finish(verifier, namespace, sig_pks, &results, response)
}

/// The vk_hash the three FETCH answers carry: every answer must carry one
/// (a node's row always stores it) and the three must agree, 500 otherwise.
fn fetched_vk_hash(results: &[NodeResult; NODES]) -> Result<Fr, Refusal> {
    let mut agreed: Option<FieldHex> = None;
    for (i, result) in results.iter().enumerate() {
        let vk_hash = result.vk_hash.ok_or_else(|| {
            Refusal::mpc_failure(format!("node {i}'s FETCH answer carries no vk_hash"))
        })?;
        match agreed {
            Some(first) if first != vk_hash => {
                return Err(Refusal::mpc_failure("the nodes disagree on `vk_hash`"));
            }
            _ => agreed = Some(vk_hash),
        }
    }
    Ok(agreed.expect("three answers").fr())
}

// How FETCH finds the round's circuit. The FETCH body names no
// circuit, so each node's answer carries the vk_hash its `requests` row
// stores; the three must agree on it (500 otherwise), and the orchestrator
// takes the package of the namespace whose row in its registry copy carries
// that vk_hash, disabled packages included (a round stays fetchable after
// its circuit is disabled), and verifies the proof once, under the vk it
// computed itself from that package's circuit. A vk_hash no package of the
// namespace carries means the circuit was registered again under another vk
// since the round: 409, the round's circuit is no longer registered (the
// nodes still hold the row, but the orchestrator has no vk to check it
// with). Two names registered with the same circuit share the vk but may
// have different manifests, so the namespace public input and the result
// signatures are checked under each such package's shape in name order, and
// the first that passes answers; when none does, the first package's refusal
// is returned.
/// The response to a FETCH, from the three nodes' rows: the same checks as
/// [`check_execute`], under the package whose vk_hash the rows carry.
pub fn check_fetch(
    registry: &Registry,
    sig_pks: &[Point; NODES],
    namespace: Fr,
    request_id: RequestId,
    results: [NodeResult; NODES],
) -> Result<ExecuteResponse, Refusal> {
    let response = agree(request_id, &results)?;
    let vk_hash = fetched_vk_hash(&results)?;
    let verifiers = fetch_verifiers(registry, namespace, vk_hash)?;
    let public_inputs = fields(&response.public_inputs);
    let first = &verifiers[0];
    if !first.verifies(registry.g2(), response.proof.as_slice(), &public_inputs) {
        return Err(Refusal::mpc_failure(format!(
            "the proof the three nodes agree on does not verify under the orchestrator's vk \
             of `{}` (vk_hash {}), the circuit their rows name",
            first.name,
            fr_to_hex(vk_hash)
        )));
    }
    let mut refused = None;
    for verifier in &verifiers {
        match finish(verifier, namespace, sig_pks, &results, response.clone()) {
            Ok(response) => return Ok(response),
            Err(refusal) => {
                refused.get_or_insert(refusal);
            }
        }
    }
    Err(refused.expect("at least one package"))
}

/// That `response`, a checked FETCH answer, is an attempt at chain request
/// `chain`: its request id must be `machine_request_id(chain, the old
/// commitments and the pinned values of its own public inputs)` under the
/// queued package whose vk_hash it carries, or, for a package that loads no
/// key (an init round), `machine_request_id(chain, one 0 per created key)`
/// (500 otherwise, or when no queued package of the namespace carries it).
pub fn check_chain_attempt(
    registry: &Registry,
    namespace: Fr,
    chain: Fr,
    response: &ExecuteResponse,
) -> Result<(), Refusal> {
    let public_inputs = fields(&response.public_inputs);
    // A row that does not parse is skipped, as the scheduler skips it, and
    // named if no other package matches.
    let mut unparsed = Vec::new();
    let stale = sidecar_tip::stale_blocks_of(registry.store(), namespace)?;
    for pkg in registry.packages(namespace) {
        if pkg.vk_hash != response.vk_hash.fr() {
            continue;
        }
        let tip = match sidecar_tip::TipPackage::from_row(&pkg, stale) {
            Ok(Some(tip)) => tip,
            Ok(None) => continue,
            Err(r) => {
                unparsed.push(format!("`{}` ({})", pkg.name, r.message));
                continue;
            }
        };
        let old = tip.old_commitments_of(&public_inputs)?;
        let reads = tip.reads_of(&public_inputs)?;
        let id = response.request_id.fr();
        if sidecar_tip::machine_request_id(chain, &old, &reads) == id
            || tip
                .init_commitments()
                .is_some_and(|empty| sidecar_tip::machine_request_id(chain, &empty, &[]) == id)
        {
            return Ok(());
        }
    }
    let skipped = if unparsed.is_empty() {
        String::new()
    } else {
        format!(
            "; the copy's package rows {} do not parse",
            unparsed.join(", ")
        )
    };
    Err(Refusal::mpc_failure(format!(
        "the nodes answered request {} for chain request {}, and it is not a machine request \
         id of that chain request under a queued package with vk_hash {}{skipped}",
        response.request_id,
        fr_to_hex(chain),
        response.vk_hash
    )))
}

/// The registered packages of `namespace` whose vk_hash is `vk_hash`, in
/// name order, disabled ones included; 409 when there is none.
pub fn fetch_verifiers(
    registry: &Registry,
    namespace: Fr,
    vk_hash: Fr,
) -> Result<Vec<Arc<Verifier>>, Refusal> {
    let mut verifiers = Vec::new();
    for pkg in registry.packages(namespace) {
        if pkg.vk_hash == vk_hash {
            verifiers.push(registry.verifier(namespace, &pkg)?);
        }
    }
    if verifiers.is_empty() {
        return Err(Refusal::conflict(format!(
            "the round's circuit is no longer registered: no package of namespace {} has \
             vk_hash {}, the vk_hash the nodes' rows name (the circuit was registered again \
             under another vk since the round)",
            fr_to_hex(namespace),
            fr_to_hex(vk_hash)
        )));
    }
    Ok(verifiers)
}
