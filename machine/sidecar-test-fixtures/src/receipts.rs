//! The receipt route's package, as the orchestrator's and the node's receipt
//! suites write it into a store directly (no REGISTER and no proof: the route
//! reads only the manifest and the ABI): the AMM tip's swap under on-chain or
//! receipt intake, after the checks REGISTER runs on it.

use serde_json::{Value, json};
use sidecar_core::field::Fr;
use sidecar_core::manifest::contract::manifest_hash;
use sidecar_core::store::{ManifestRow, PackageRow};
use sidecar_core::testing::{TestPackage, TipFacts, contract_manifest};

use crate::dirs::repo;

/// The namespace the receipt suites register their package under.
pub const NS: u64 = 0x1a2b;

/// The vk hash the package row carries (no vk is built).
pub const VK_HASH: u64 = 0xc1c1;

// The AMM tip's manifests under the given intake (on-chain:
// testvectors/manifests/amm_swap_tip.json; receipt:
// examples/amm-tip/manifests/amm_swap_tip_receipt.json) and the ABI both fit
// in the contract library's public-input layout, whose `direction` is a bool
// (a typed range check).
/// The AMM tip swap's manifest under `intake` (`onchain` or `receipt`).
pub fn manifest(intake: &str) -> Value {
    let path = match intake {
        "onchain" => "testvectors/manifests/amm_swap_tip.json",
        "receipt" => "examples/amm-tip/manifests/amm_swap_tip_receipt.json",
        other => panic!("no AMM tip manifest under intake {other}"),
    };
    serde_json::from_str(&std::fs::read_to_string(repo().join(path)).unwrap()).unwrap()
}

/// The one compiled swap's ABI, whatever the intake: [namespace, vk_hash,
/// in_slots, out_slots] public, the app inputs, the partial note and
/// user_nonce private; the return value leads with the request id and
/// returns the partial note right after `ok`.
pub fn abi() -> Value {
    let field = |name: &str, visibility: &str| json!({"name": name, "type": {"kind": "field"}, "visibility": visibility});
    let slots = |name: &str| json!({"name": name, "type": {"kind": "array", "length": 1, "type": {"kind": "field"}}, "visibility": "public"});
    json!({
      "parameters": [
        field("namespace", "public"),
        field("vk_hash", "public"),
        slots("in_slots"),
        slots("out_slots"),
        field("amount_in", "private"),
        {"name": "direction", "type": {"kind": "boolean"}, "visibility": "private"},
        field("min_out", "private"),
        field("partial_note", "private"),
        field("user_nonce", "private"),
        {"name": "pool", "type": {"kind": "array", "length": 2, "type": {"kind": "field"}}, "visibility": "private"},
        field("r_old", "private"),
        field("r_new", "private"),
        field("nsk_app", "private")
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
    })
}

/// The contract manifest row of a receipt suite's namespace: the
/// `packages` (name and circuit manifest, each on a circuit of its own name,
/// its manifest's `circuit` set to the name, its request keys one state key
/// of its own: the packages need not agree on a key's layout), under the
/// stale period `stale_blocks`. A package row's vk hash stands in for every
/// circuit's.
pub fn manifest_row(packages: &[(&str, Value)], stale_blocks: Option<u64>) -> ManifestRow {
    let packages: Vec<TestPackage> = packages
        .iter()
        .map(|(name, m)| {
            let mut m = m.clone();
            m["circuit"] = json!(name);
            let count = |side: &str| m["state_keys"][side].as_u64().unwrap_or(0) as usize;
            let (reads, writes) = (vec![*name; count("reads")], vec![*name; count("writes")]);
            TestPackage::new(name, m).keys(&reads, &writes)
        })
        .collect();
    let keys: Vec<(&str, Fr)> = packages
        .iter()
        .enumerate()
        .map(|(k, p)| (p.name.as_str(), Fr::from(0x10 + k as u64)))
        .collect();
    let tip = TipFacts {
        stale_blocks,
        ..TipFacts::new(Fr::from(0x0cu64), packages.len(), &keys)
    };
    let document = contract_manifest("receipts", &packages, Some(&tip), |_| Fr::from(VK_HASH));
    ManifestRow {
        manifest_hash: manifest_hash(&document).unwrap(),
        document,
        seq: 0,
    }
}

/// A package row of `manifest` over `abi`, after the checks REGISTER runs on
/// them (the ABI checks and the contract library's layout), so the store
/// holds only what REGISTER would have written; it belongs to the contract
/// manifest `of` ([`manifest_row`]).
pub fn package(
    name: &str,
    manifest: Value,
    abi: Value,
    disabled: bool,
    of: &ManifestRow,
) -> PackageRow {
    let parsed = sidecar_core::error::parse_value(&abi).unwrap();
    let (m, shape) = sidecar_core::abi::check_manifest_value(&manifest, &parsed).unwrap();
    sidecar_core::abi::check_tip_public_prefix(&m, &shape).unwrap();
    PackageRow {
        name: name.into(),
        manifest_hash: of.manifest_hash,
        circuit_json: serde_json::to_vec(&json!({"abi": abi})).unwrap(),
        manifest,
        vk: vec![],
        vk_hash: Fr::from(VK_HASH),
        disabled,
        seq: 0,
    }
}
