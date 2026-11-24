//! The repository's shared test vectors (testvectors/), read from their
//! files, and the field and key helpers every vector test needs.

use serde_json::{Value, json};
use sidecar_core::field::{Fr, fr_from_hex};
use sidecar_core::keys::{NodeKeys, scalar_from_hex};
use sidecar_core::register::Signature;
use sidecar_core::request::GrumpkinPoint;

use crate::dirs::repo;

/// The JSON file at `path` from the repository root.
pub fn read(path: &str) -> Value {
    let full = repo().join(path);
    let text = std::fs::read_to_string(&full).unwrap_or_else(|e| panic!("{path}: {e}"));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("{path}: {e}"))
}

/// The vector file testvectors/`name`.
pub fn vector(name: &str) -> Value {
    read(&format!("testvectors/{name}"))
}

/// The field element a `0x` hex string writes.
pub fn hex(s: &str) -> Fr {
    fr_from_hex(s).unwrap_or_else(|e| panic!("{s}: {e}"))
}

/// The field element a vector's `0x` hex string value writes.
pub fn hex_value(v: &Value) -> Fr {
    hex(v
        .as_str()
        .unwrap_or_else(|| panic!("{v} is not a hex string")))
}

/// The field elements of a vector's list of `0x` hex strings.
pub fn fields(v: &Value) -> Vec<Fr> {
    v.as_array()
        .unwrap_or_else(|| panic!("{v} is not a list"))
        .iter()
        .map(hex_value)
        .collect()
}

/// A vector's point, as the wire writes it.
pub fn point(v: &Value) -> GrumpkinPoint {
    serde_json::from_value(v.clone()).unwrap_or_else(|e| panic!("{v}: {e}"))
}

/// A vector's signature, as the wire writes it.
pub fn signature(v: &Value) -> Signature {
    serde_json::from_value(v.clone()).unwrap_or_else(|e| panic!("{v}: {e}"))
}

/// The sample deployment's node keys (testvectors/keys.json), node 0 first.
pub fn node_keys() -> Vec<NodeKeys> {
    vector("keys.json")["nodes"]
        .as_array()
        .expect("keys.json lists the nodes")
        .iter()
        .map(|n| {
            let scalar = |k: &str| scalar_from_hex(n[k].as_str().unwrap()).unwrap();
            NodeKeys::from_scalars(scalar("enc"), scalar("sig")).unwrap()
        })
        .collect()
}

/// testvectors/shared_intake.json: a secret-shared receipt intake request on
/// testvectors/manifests/shared_receipt_round.json, sealed to the nodes of
/// testvectors/keys.json, with the receipt the three sign.
pub fn shared_intake() -> Value {
    vector("shared_intake.json")
}

/// The client's body of [`shared_intake`]'s request, as it asks the
/// orchestrator's receipt route: the clear input, C, all three envelopes of
/// every shared input and of the summand salts, the summand commitments and
/// the sharing digest; no expiry (the orchestrator sets it).
pub fn shared_receipt_client() -> Value {
    let v = shared_intake();
    let node0 = &v["receipt_body_node0"];
    json!({
        "namespace": v["namespace"],
        "circuit": v["circuit"],
        "inputs": node0["inputs"],
        "inputs_hash": v["inputs_commitment"],
        "shared_inputs": v["shared_inputs"],
        "summand_commitments": v["summand_commitments"],
        "sharing_digest": v["sharing_digest"],
        "current_block": node0["current_block"],
    })
}
