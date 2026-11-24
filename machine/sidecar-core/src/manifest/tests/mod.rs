//! The manifest tests' fixtures and helpers: the AMM, tip, tree and
//! secret-shared manifests every test file parses.

use super::*;
use crate::error::{ErrorClass, parse_json};
use serde_json::{Value, json};

mod reads;
mod schema;
mod shared;
mod trees;

// The AMM example's three manifests (examples/amm/manifests).
pub(crate) fn pss_seed() -> Value {
    json!({
      "manifest": 1,
      "circuit": "pss_seed",
      "namespace_param": "namespace",
      "state_keys": { "reads": 0, "writes": 1 },
      "witness": [
        { "param": "namespace", "from": { "PUBLIC": "$namespace" } },
        { "param": "owner",            "from": { "PUBLIC": { "const": "0xafafaf" } } },
        { "param": "out_slots",        "from": { "PUBLIC": ["$state_keys.writes[0]"] } },
        { "param": "out0_randomness",  "from": { "SAMPLE": 1 } },
        { "param": "rand_seed",        "from": { "SAMPLE": 1 } }
      ],
      "outputs": [ { "TACEO_store": "out0", "STORE": "$state_keys.writes[0]", "len": 2,
                     "note_hash": "new_note_hashes[0]" } ],
      "state": { "$state_keys.writes[0]": "node" },
      "consume": []
    })
}

fn amm_init() -> Value {
    json!({
      "manifest": 1,
      "circuit": "amm_init",
      "namespace_param": "namespace",
      "state_keys": { "reads": 1, "writes": 1 },
      "witness": [
        { "param": "namespace", "from": { "PUBLIC": "$namespace" } },
        { "param": "owner",            "from": { "PUBLIC": { "const": "0xafafaf" } } },
        { "param": "in_slots",         "from": { "PUBLIC": ["$state_keys.reads[0]"] } },
        { "param": "out_slots",        "from": { "PUBLIC": ["$state_keys.writes[0]"] } },
        { "param": "in0_fields",       "from": { "LOAD": "$state_keys.reads[0]", "slice": [0, 1], "len": 2 } },
        { "param": "in0_randomness",   "from": { "LOAD": "$state_keys.reads[0]", "slice": [1, 2], "len": 2 } },
        { "param": "in0_nonce",        "from": { "PUBLIC": "in0_nonce" } },
        { "param": "out0_randomness",  "from": { "SAMPLE": 1 } },
        { "param": "nsk_app",          "from": { "LOAD": "nsk_app", "slice": [0, 1], "len": 1 } }
      ],
      "outputs": [ { "TACEO_store": "out0", "STORE": "$state_keys.writes[0]", "len": 3,
                     "note_hash": "new_note_hashes[0]" } ],
      "state": { "$state_keys.reads[0]": "node", "$state_keys.writes[0]": "node" },
      "consume": [ { "key": "$state_keys.reads[0]", "policy": "once" } ]
    })
}

fn amm_swap() -> Value {
    json!({
      "manifest": 1,
      "circuit": "amm_swap",
      "namespace_param": "namespace",
      "state_keys": { "reads": 1, "writes": 1 },
      "witness": [
        { "param": "namespace", "from": { "PUBLIC": "$namespace" } },
        { "param": "owner",            "from": { "PUBLIC": { "const": "0xafafaf" } } },
        { "param": "in_slots",         "from": { "PUBLIC": ["$state_keys.reads[0]"] } },
        { "param": "out_slots",        "from": { "PUBLIC": ["$state_keys.writes[0]"] } },
        { "param": "amount_in",        "from": { "PUBLIC": "amount_in" } },
        { "param": "direction",        "from": { "PUBLIC": "direction" } },
        { "param": "in0_fields",       "from": { "LOAD": "$state_keys.reads[0]", "slice": [0, 2], "len": 3 } },
        { "param": "in0_randomness",   "from": { "LOAD": "$state_keys.reads[0]", "slice": [2, 3], "len": 3 } },
        { "param": "in0_nonce",        "from": { "PUBLIC": "in0_nonce" } },
        { "param": "out0_randomness",  "from": { "SAMPLE": 1 } },
        { "param": "nsk_app",          "from": { "LOAD": "nsk_app", "slice": [0, 1], "len": 1 } }
      ],
      "outputs": [ { "TACEO_store": "out0", "STORE": "$state_keys.writes[0]", "len": 3,
                     "note_hash": "new_note_hashes[0]" } ],
      "state": { "$state_keys.reads[0]": "node", "$state_keys.writes[0]": "node" },
      "consume": [ { "key": "$state_keys.reads[0]", "policy": "once" } ]
    })
}

// A client-held game round in the style of Monty Hall, with INPUT_SHARED and a
// consume entry that leaves the policy to the default.
fn client_round() -> Value {
    json!({
      "manifest": 1,
      "circuit": "open_door",
      "namespace_param": "namespace",
      "state_keys": { "reads": 1, "writes": 1 },
      "witness": [
        { "param": "namespace", "from": { "PUBLIC": "$namespace" } },
        { "param": "in0_fields",       "from": { "LOAD": "$state_keys.reads[0]", "slice": [0, 9], "len": 10 } },
        { "param": "in0_randomness",   "from": { "LOAD": "$state_keys.reads[0]", "slice": [9, 10], "len": 10 } },
        { "param": "door",             "from": { "INPUT_SHARED": "door" } },
        { "param": "out0_randomness",  "from": { "SAMPLE": 1 } },
        { "param": "nsk_app",          "from": { "LOAD": "nsk_app", "slice": [0, 1], "len": 1 } }
      ],
      "outputs": [ { "TACEO_store": "out0", "STORE": "$state_keys.writes[0]", "len": 10,
                     "note_hash": "new_note_hashes[0]" } ],
      "state": { "$state_keys.reads[0]": "client", "$state_keys.writes[0]": "client" },
      "consume": [ { "key": "$state_keys.reads[0]" } ]
    })
}

// An in-place edit of a manifest under test.
type Edit = fn(&mut Value);

fn parse(v: &Value) -> Result<Manifest, Refusal> {
    Manifest::parse(v)
}

// A manifest JSON text, parsed and checked.
fn parse_text(text: &str) -> Result<Manifest, Refusal> {
    Manifest::parse(&parse_json(text)?)
}

fn refused(v: Value, needle: &str) {
    crate::error::assert_refused(parse(&v), ErrorClass::BadRequest, &[needle]);
}

fn tip_tree() -> Value {
    serde_json::from_str(include_str!(
        "../../../../../machine/circuits/manifests/tip_tree.json"
    ))
    .unwrap()
}

// The AMM tip's swap manifest with the pool chain-held
// (testvectors/manifests/amm_swap_tip.json).
pub(crate) fn amm_swap_tip() -> Value {
    serde_json::from_str(include_str!(
        "../../../../../testvectors/manifests/amm_swap_tip.json"
    ))
    .unwrap()
}

fn tip(v: &Value) -> Manifest {
    let m = parse(v).unwrap();
    assert!(m.queued(), "intake {}", m.intake.as_str());
    m
}

// The AMM tip's receipt-intake manifest (examples/amm-tip/manifests), which fills
// vk_hash and user_nonce by the reserved operands.
fn amm_swap_tip_receipt() -> Value {
    serde_json::from_str(include_str!(
        "../../../../../examples/amm-tip/manifests/amm_swap_tip_receipt.json"
    ))
    .unwrap()
}

// The generic secret-shared receipt intake round of the vectors
// (testvectors/manifests/shared_receipt_round.json): two INPUT_SHARED app
// inputs around one clear one, the three reserved shared values and
// PUBLIC `$inputs_hash`.
pub(crate) fn shared_receipt_round() -> Value {
    serde_json::from_str(include_str!(
        "../../../../../testvectors/manifests/shared_receipt_round.json"
    ))
    .unwrap()
}
