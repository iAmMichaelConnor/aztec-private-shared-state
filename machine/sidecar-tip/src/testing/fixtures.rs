//! The fixtures the tip's tests share, its own and the integration tests'
//! (feature `test-util`): the AMM swap manifest and its ABI, and the round of
//! secret-shared receipt intake's vectors (testvectors/shared_intake.json)
//! with its package, values and summand salts.

use serde_json::{Value, json};
use sidecar_core::error::parse_json;
use sidecar_core::field::{Fr, fr_from_hex};
use sidecar_core::hash::poseidon2_hash;
use sidecar_core::request::NODES;
use sidecar_core::store::PackageRow;

// The AMM tip's swap manifest with the pool chain-held (the example's is
// node-held).
pub const AMM_SWAP_TIP: &str = include_str!("../../../../testvectors/manifests/amm_swap_tip.json");

// The ABI the manifest fits (examples/amm-tip/circuits/amm_swap_tip):
// the namespace, the vk hash and the key binding public, the inputs, the
// partial note, the nonce, the pool and its blinding private, and a
// public return with the request id, the old and new commitments and the
// partial note right after `ok`.
pub const AMM_SWAP_TIP_ABI: &str = r#"{
  "parameters": [
    {"name": "namespace", "type": {"kind": "field"}, "visibility": "public"},
    {"name": "vk_hash", "type": {"kind": "field"}, "visibility": "public"},
    {"name": "in_slots", "type": {"kind": "array", "length": 1, "type": {"kind": "field"}}, "visibility": "public"},
    {"name": "out_slots", "type": {"kind": "array", "length": 1, "type": {"kind": "field"}}, "visibility": "public"},
    {"name": "amount_in", "type": {"kind": "field"}, "visibility": "private"},
    {"name": "direction", "type": {"kind": "field"}, "visibility": "private"},
    {"name": "min_out", "type": {"kind": "field"}, "visibility": "private"},
    {"name": "partial_note", "type": {"kind": "field"}, "visibility": "private"},
    {"name": "user_nonce", "type": {"kind": "field"}, "visibility": "private"},
    {"name": "pool", "type": {"kind": "array", "length": 2, "type": {"kind": "field"}}, "visibility": "private"},
    {"name": "r_old", "type": {"kind": "field"}, "visibility": "private"},
    {"name": "r_new", "type": {"kind": "field"}, "visibility": "private"},
    {"name": "nsk_app", "type": {"kind": "field"}, "visibility": "private"}
  ],
  "return_type": {"abi_type": {"kind": "struct", "path": "AmmTipOut", "fields": [
    {"name": "request_id", "type": {"kind": "field"}},
    {"name": "old_c", "type": {"kind": "field"}},
    {"name": "new_c", "type": {"kind": "field"}},
    {"name": "npk_app_hash", "type": {"kind": "field"}},
    {"name": "ok", "type": {"kind": "field"}},
    {"name": "partial_note", "type": {"kind": "field"}},
    {"name": "code", "type": {"kind": "field"}},
    {"name": "amount_out", "type": {"kind": "field"}}
  ]}, "visibility": "public"},
  "error_types": {}
}"#;

/// The ABI with the parameters `pinned` public: a variant of the swap
/// whose pinned reads fill them (a pinned value is a public input, an
/// app input never is). `direction` and `min_out` follow the key slots
/// in the public inputs, as the library's layout puts pinned values.
pub fn amm_swap_tip_abi(pinned: &[&str]) -> Value {
    let mut abi: Value = parse_json(AMM_SWAP_TIP_ABI).unwrap();
    for p in abi["parameters"].as_array_mut().unwrap() {
        if pinned.iter().any(|name| p["name"] == *name) {
            p["visibility"] = serde_json::json!("public");
        }
    }
    abi
}

/// testvectors/manifests/shared_receipt_round.json.
pub const SHARED_RECEIPT_ROUND: &str =
    include_str!("../../../../testvectors/manifests/shared_receipt_round.json");

fn hex(s: &str) -> Fr {
    fr_from_hex(s).unwrap()
}

// A replicated sharing of `x`, drawn as the record vectors draw theirs
// (sidecar-core tests/write_vectors.rs): x_0 and x_1 from the seed, x_2 = x -
// x_0 - x_1; node i holds (x_i, x_{i-1}).
pub fn sharing(x: Fr, seed: u64) -> [Fr; 3] {
    let x0 = poseidon2_hash(&[Fr::from(seed), Fr::from(0u64)]);
    let x1 = poseidon2_hash(&[Fr::from(seed), Fr::from(1u64)]);
    [x0, x1, x - x0 - x1]
}

/// The ABI of a round on testvectors/manifests/shared_receipt_round.json:
/// receipt intake's proved layout (`namespace`, `vk_hash` and the slots
/// public, every app input private) with the inputs commitment, two shared
/// app inputs around a clear one, and the three reserved shared values.
pub fn shared_circuit_abi() -> Value {
    let field = json!({"kind": "field"});
    let one = json!({"kind": "array", "length": 1, "type": {"kind": "field"}});
    let two = json!({"kind": "array", "length": 2, "type": {"kind": "field"}});
    let param = |name: &str, typ: &Value, public: bool| {
        json!({"name": name, "type": typ,
               "visibility": if public { "public" } else { "private" }})
    };
    let named = |names: &[&str]| -> Vec<Value> {
        names
            .iter()
            .map(|n| json!({"name": n, "type": field}))
            .collect()
    };
    let mut fields = named(&["request_id", "old_c", "new_c", "npk_app_hash", "ok"]);
    fields.push(json!({"name": "app", "type": {"kind": "struct",
        "path": "shared_receipt_round::Outputs", "fields": named(&["code"])}}));
    json!({
      "parameters": [
        param("namespace", &field, true),
        param("vk_hash", &field, true),
        param("in_slots", &one, true),
        param("out_slots", &one, true),
        param("inputs_hash", &field, false),
        param("amount", &field, false),
        param("position", &json!({"kind": "integer", "sign": "unsigned", "width": 32}), false),
        param("partial_note", &field, false),
        param("outcome_key", &field, false),
        param("blinding", &field, false),
        param("outcome_tag", &field, false),
        param("pool", &two, false),
        param("r_old", &field, false),
        param("r_new", &field, false),
        param("nsk_app", &field, false),
      ],
      "return_type": {"abi_type": {"kind": "struct",
        "path": "pss_core::tip::outputs::Bound", "fields": fields},
        "visibility": "public"},
      "error_types": {}
    })
}

/// The registered package of shared_receipt_round.json and its ABI.
pub fn shared_package() -> PackageRow {
    PackageRow {
        name: "shared_receipt_round".into(),
        manifest_hash: Fr::from(0u64),
        circuit_json: serde_json::to_vec(&json!({"abi": shared_circuit_abi()})).unwrap(),
        manifest: parse_json(SHARED_RECEIPT_ROUND).unwrap(),
        vk: vec![],
        vk_hash: hex("0x2a8f1c0e9b7d6a5f4e3c2b1a09f8e7d6c5b4a39281706f5e4d3c2b1a09f8e7d6"),
        disabled: false,
        seq: 1,
    }
}

/// The request of the vectors: every value by name (clear and shared), a
/// position of 7, and the seed of each shared value's sharing.
pub fn shared_values() -> Vec<(&'static str, Fr, Option<u64>)> {
    vec![
        ("amount", Fr::from(5000u64), Some(101)),
        ("position", Fr::from(7u64), None),
        (
            "$partial_note",
            hex("0x0b7e3a1f00c0ffee00000000000000000000000000000000000000000000beef"),
            Some(102),
        ),
        (
            "$outcome_key",
            hex("0x1d0c5e7a9b3f24681357acebdf0246813579bdf02468ace13579bdf02468ace1"),
            Some(103),
        ),
        (
            "$blinding",
            hex("0x0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0"),
            Some(104),
        ),
        (
            "$outcome_tag",
            hex("0x2468ace02468ace02468ace02468ace02468ace02468ace02468ace02468ace0"),
            Some(105),
        ),
    ]
}

/// The vectors' summand salts `[salt_0, salt_1, salt_2]`, sealed as the
/// `$summand_salt` envelopes: the sharing (seed 106) of a value nothing
/// reads, so node i's envelope opens to `[salt_i, salt_(i-1)]` as every
/// other shared value's does.
pub fn summand_salts() -> [Fr; NODES] {
    sharing(Fr::from(0x7361_6c74u64), SUMMAND_SALT_SEED)
}

/// The seed of [`summand_salts`]' sharing.
pub const SUMMAND_SALT_SEED: u64 = 106;
