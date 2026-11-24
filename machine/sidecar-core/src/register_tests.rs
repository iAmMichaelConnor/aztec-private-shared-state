use super::*;
use crate::error::ErrorClass;
use crate::field::Fr;
use crate::testing::{TestPackage, TipFacts, contract_manifest};
use serde_json::{Value, json};

// The ABI of pss_seed as nargo writes it, with the npk_app_hash effects
// field, in nargo's full form (its `file_map` and `debug_symbols` as a
// build writes them).
pub(crate) fn circuit() -> Value {
    json!({
        "noir_version": "1.0.0",
        "hash": 1234,
        "bytecode": "H4sIAAAAAAAA/wMAAAAAAAAAAAA=",
        "abi": {
            "abi_version": 1,
            "parameters": [
                {"name": "namespace", "type": {"kind": "field"}, "visibility": "public"},
                {"name": "owner", "type": {"kind": "field"}, "visibility": "public"},
                {"name": "out_slots", "type": {"kind": "array", "length": 1, "type": {"kind": "field"}}, "visibility": "public"},
                {"name": "out0_randomness", "type": {"kind": "field"}, "visibility": "private"},
                {"name": "rand_seed", "type": {"kind": "field"}, "visibility": "private"}
            ],
            "return_type": {"abi_type": {"kind": "struct", "path": "pss_core::effects::PssEffects", "fields": [
                {"name": "read_leaves", "type": {"kind": "array", "length": 0, "type": {"kind": "field"}}},
                {"name": "nullifiers", "type": {"kind": "array", "length": 0, "type": {"kind": "field"}}},
                {"name": "new_note_hashes", "type": {"kind": "array", "length": 1, "type": {"kind": "field"}}},
                {"name": "npk_app_hash", "type": {"kind": "field"}},
                {"name": "app_outputs", "type": {"kind": "array", "length": 0, "type": {"kind": "field"}}}
            ]}, "visibility": "public"},
            "error_types": {"12469291177396340830": {"error_kind": "string", "string": "call to assert_max_bit_size"}}
        },
        "debug_symbols": "H4sIAAAAAAAA/6tWSkksSVSyUqhWSs7PS8tMh7AA",
        "file_map": {"1": {"source": "fn main() {}", "path": "/build/src/main.nr"}}
    })
}

/// A manifest message of `packages` (each on the pss_seed circuit) with the
/// contract facts `tip`.
fn message(packages: &[TestPackage], tip: Option<&TipFacts>) -> Value {
    json!({
        "namespace": "0x1f2ea9c0",
        "manifest": contract_manifest("pss_seed", packages, tip, |_| Fr::from(0xabcdu64)),
        "circuits": {"pss_seed": stripped_circuit(&circuit())},
        "owner_pubkey": {"x": "0x1", "y": "0x2"},
        "seq": 0,
        "signature": {"s": ["0x3", "0x4"], "e": ["0x5", "0x6"]}
    })
}

fn body() -> Value {
    message(
        &[TestPackage::new(
            "pss_seed",
            crate::manifest::tests::pss_seed(),
        )],
        None,
    )
}

fn refused(v: Value, needle: &str) {
    crate::error::assert_refused(
        ManifestMessage::from_json(&v.to_string()),
        ErrorClass::BadRequest,
        &[needle],
    );
}

#[test]
fn a_manifest_message_parses_with_typed_views() {
    let req = ManifestMessage::from_json(&body().to_string()).unwrap();
    let abi = req.abi("pss_seed").unwrap();
    assert_eq!(abi.parameters.len(), 5);
    assert_eq!(abi.parameters[0].name, "namespace");
    let checked = req.contract_manifest().unwrap();
    assert_eq!(checked.manifests[0].circuit, "pss_seed");
    assert_eq!(req.signature.e[1], FieldHex::from(6));
    let text = serde_json::to_string(&req).unwrap();
    assert_eq!(ManifestMessage::from_json(&text).unwrap(), req);
}

// The stripped circuit keeps nargo's six members that the machine and
// co-noir need, the debug symbols and file map emptied; every other member,
// a missing one, other debug symbols or a file map is refused.
#[test]
fn a_circuit_is_carried_stripped() {
    let full = circuit();
    let stripped = stripped_circuit(&full);
    assert_eq!(
        stripped.as_object().unwrap().keys().collect::<Vec<_>>(),
        [
            "abi",
            "bytecode",
            "debug_symbols",
            "file_map",
            "hash",
            "noir_version"
        ]
    );
    assert_eq!(stripped["debug_symbols"], STRIPPED_DEBUG_SYMBOLS);
    assert_eq!(stripped["file_map"], json!({}));
    assert_eq!(
        (&stripped["abi"], &stripped["hash"]),
        (&full["abi"], &full["hash"])
    );
    check_stripped_circuit("c", &stripped).unwrap();

    let mut v = body();
    v["circuits"]["pss_seed"] = full;
    refused(
        v,
        "field `circuits.pss_seed`: `debug_symbols` of a stripped circuit is",
    );
    let mut v = body();
    v["circuits"]["pss_seed"]["artifact_version"] = json!(1);
    refused(v, "field `circuits.pss_seed`: member `artifact_version`");
    let mut v = body();
    v["circuits"]["pss_seed"]
        .as_object_mut()
        .unwrap()
        .remove("hash");
    refused(v, "field `circuits.pss_seed`: member `hash` is missing");
    let mut v = body();
    v["circuits"]["pss_seed"]["debug_symbols"] = json!("");
    refused(v, "field `circuits.pss_seed`: `debug_symbols`");
    let mut v = body();
    v["circuits"]["pss_seed"]["file_map"] = json!({"1": {}});
    refused(v, "field `circuits.pss_seed`: `file_map`");
}

#[test]
fn manifest_message_refusals_name_the_field() {
    let mut v = body();
    v["signature"]["s"] = json!(["0x3"]);
    refused(v, "signature.s");
    let mut v = body();
    v["signature"]["r"] = json!("0x1");
    refused(v, "signature");
    let mut v = body();
    v["owner_pubkey"]["y"] = json!("0xzz");
    refused(v, "owner_pubkey.y");
    let mut v = body();
    v["fee"] = json!(1);
    refused(v, "fee");
    let mut v = body();
    v.as_object_mut().unwrap().remove("seq");
    refused(v, "seq");
    let mut v = body();
    v["seq"] = json!(-1);
    refused(v, "field `seq`");
    // a per-package body (a `name` field) is no manifest message
    let mut v = body();
    v["name"] = json!("pss_seed");
    refused(v, "name");
    // the contract manifest and each circuit manifest, by their place
    let mut v = body();
    v["manifest"]["contract_manifest"] = json!(2);
    refused(
        v,
        "field `manifest.contract_manifest`: contract manifest schema version 2 is not supported",
    );
    let mut v = body();
    v["manifest"]["packages"][0]["manifest"]["manifest"] = json!(2);
    refused(
        v,
        "field `manifest.packages[0].manifest.manifest`: manifest schema version 2 is not supported",
    );
    let mut v = body();
    v["manifest"]["packages"][0]["name"] = json!("pss_seed\0");
    v["manifest"]["packages"][0]["manifest"]["circuit"] = json!("pss_seed\0");
    refused(v, "field `manifest.packages[0].name`: package name");
    let mut v = body();
    v["manifest"]["packages"][0]["manifest"]["intake"] = json!("onchain");
    refused(
        v,
        "field `manifest.packages[0].manifest.consume`: only with intake direct; this manifest has intake onchain",
    );
    let mut v = body();
    v["manifest"]["packages"][0]["manifest"]["witness"][3]["from"]["SAMPLE"] = json!(0);
    refused(
        v,
        "field `manifest.packages[0].manifest.witness[3].from.SAMPLE`",
    );
    // the circuits are exactly the manifest's
    let mut v = body();
    v["circuits"]["other"] = v["circuits"]["pss_seed"].clone();
    refused(
        v,
        "field `circuits.other`: not an entry of `manifest.circuits`",
    );
    let mut v = body();
    v["circuits"] = json!({});
    refused(
        v,
        "field `circuits`: `pss_seed` of `manifest.circuits` is missing",
    );
    let mut v = body();
    v["circuits"]["pss_seed"]
        .as_object_mut()
        .unwrap()
        .remove("abi");
    refused(v, "field `circuits.pss_seed`: member `abi` is missing");
    let mut v = body();
    v["circuits"]["pss_seed"]["abi"]["parameters"][0]["type"] = json!({"kind": "matrix"});
    refused(v, "field `circuits.pss_seed.abi.parameters[0]");
    // a pinned read under intake direct is deferred
    let mut v = body();
    v["manifest"]["packages"][0]["manifest"]["public_reads"] =
        json!([{"contract": "0x1", "function": "f", "args": [], "param": "owner"}]);
    v["manifest"]["packages"][0]["manifest"]["witness"][1]["from"] = json!({"PUBLIC": "owner"});
    refused(
        v,
        "field `manifest.packages[0].manifest.public_reads`: a pinned public read under intake direct is deferred",
    );
}

fn sig(n: u64) -> Signature {
    Signature {
        s: [FieldHex::from(n), FieldHex::from(n + 1)],
        e: [FieldHex::from(n + 2), FieldHex::from(n + 3)],
    }
}

#[test]
fn disable_body_parses() {
    let v = json!({
        "namespace": "0x1f2ea9c0",
        "circuit": "pss_seed",
        "owner_pubkey": {"x": "0x1", "y": "0x2"},
        "seq": 3,
        "signature": {"s": ["0x3", "0x4"], "e": ["0x5", "0x6"]}
    });
    let req = DisableRequest::from_json(&v.to_string()).unwrap();
    assert_eq!((req.circuit.as_str(), req.seq), ("pss_seed", 3));
    let mut empty = v.clone();
    empty["circuit"] = json!("");
    let err = DisableRequest::from_json(&empty.to_string()).unwrap_err();
    assert!(err.message.contains("field `circuit`"), "{err}");
    let mut nul = v.clone();
    nul["circuit"] = json!("pss_seed\0");
    let err = DisableRequest::from_json(&nul.to_string()).unwrap_err();
    assert!(
        err.message.contains("field `circuit`: circuit name"),
        "{err}"
    );
    let mut extra = v;
    extra["name"] = json!("pss_seed");
    assert!(DisableRequest::from_json(&extra.to_string()).is_err());
}

#[test]
fn registry_answers_and_responses() {
    let answer = ManifestAnswer {
        manifest_hash: FieldHex::from(1),
        packages_hash: FieldHex::from(7),
        npk_app_hash: FieldHex::from(2),
        seq: 0,
        signature: sig(3),
        registration: None,
    };
    let v = serde_json::to_value(&answer).unwrap();
    assert!(v.get("registration").is_none());
    assert_eq!(serde_json::from_value::<ManifestAnswer>(v).unwrap(), answer);
    let with_proof = ManifestAnswer {
        registration: Some(Registration {
            proof: HexBytes(vec![1, 2]),
            public_inputs: vec![FieldHex::from(5), FieldHex::from(2)],
        }),
        ..answer.clone()
    };
    let v = serde_json::to_value(&with_proof).unwrap();
    assert_eq!(v["registration"]["proof"], "0x0102");
    assert_eq!(
        serde_json::from_value::<ManifestAnswer>(v).unwrap(),
        with_proof
    );

    let r = ManifestResponse {
        manifest_hash: FieldHex::from(1),
        packages_hash: FieldHex::from(7),
        npk_app_hash: FieldHex::from(2),
        seq: 4,
        signatures: [sig(1), sig(5), sig(9)],
    };
    let v = serde_json::to_value(&r).unwrap();
    assert_eq!(
        v["manifest_hash"],
        "0x0000000000000000000000000000000000000000000000000000000000000001"
    );
    assert_eq!(v["signatures"].as_array().unwrap().len(), 3);
    assert_eq!(serde_json::from_value::<ManifestResponse>(v).unwrap(), r);
    assert!(
        serde_json::from_value::<ManifestResponse>(
            json!({"manifest_hash": "0x1", "npk_app_hash": "0x2"})
        )
        .is_err()
    );
    let mut proof_forwarded = serde_json::to_value(&r).unwrap();
    proof_forwarded["registration"] = json!({"proof": "0x", "public_inputs": []});
    assert!(serde_json::from_value::<ManifestResponse>(proof_forwarded).is_err());
}

#[test]
fn get_answers_round_trip() {
    let p = PackageResponse {
        namespace: FieldHex::from(1),
        name: "pss_seed".into(),
        manifest_hash: FieldHex::from(4),
        circuit: stripped_circuit(&circuit()),
        manifest: crate::manifest::tests::pss_seed(),
        vk: HexBytes(vec![1, 2, 3]),
        vk_hash: FieldHex::from(9),
        disabled: false,
        seq: 2,
    };
    let back: PackageResponse = serde_json::from_str(&serde_json::to_string(&p).unwrap()).unwrap();
    assert_eq!(back, p);
    let n = NamespaceResponse {
        namespace: FieldHex::from(1),
        owner_pubkey: GrumpkinPoint {
            x: FieldHex::from(1),
            y: FieldHex::from(2),
        },
        seq: 7,
        npk_app_hash: FieldHex::from(3),
        manifest_hash: FieldHex::from(4),
    };
    let back: NamespaceResponse =
        serde_json::from_str(&serde_json::to_string(&n).unwrap()).unwrap();
    assert_eq!(back, n);
    let m = ContractManifestResponse {
        namespace: FieldHex::from(1),
        manifest_hash: FieldHex::from(4),
        seq: 7,
        manifest: body()["manifest"].clone(),
    };
    let back: ContractManifestResponse =
        serde_json::from_str(&serde_json::to_string(&m).unwrap()).unwrap();
    assert_eq!(back, m);
}

/// A manifest message of the AMM tip's swap (testvectors/manifests/
/// amm_swap_tip.json) under the contract facts its queue needs.
fn tip_body(manifest: Value) -> Value {
    let packages =
        [TestPackage::on("amm_swap_tip", "pss_seed", manifest).keys(&["pool"], &["pool"])];
    let tip = TipFacts::new(Fr::from(12u64), 1, &[("pool", Fr::from(16u64))]);
    message(&packages, Some(&tip))
}

/// A manifest message refuses the queued-intake options the tip has not
/// built and the state modes and fields of the other path (400); the
/// holders a node serves decide the state modes they serve.
#[test]
fn a_queued_body_refuses_the_options_not_built() {
    let swap = crate::manifest::tests::amm_swap_tip();
    let req = ManifestMessage::from_json(&tip_body(swap.clone()).to_string()).unwrap();
    assert!(req.contract_manifest().unwrap().manifests[0].queued());
    let at = "field `manifest.packages[0].manifest";

    let mut m = swap.clone();
    m["binding"] = json!("exact");
    refused(
        tip_body(m),
        &format!("{at}.binding`: `exact` is deferred; a queued intake runs `turn`"),
    );
    let mut m = swap.clone();
    m["state"] = json!({"$state_keys.reads[0]": "node", "$state_keys.writes[0]": "node"});
    let req = ManifestMessage::from_json(&tip_body(m).to_string()).unwrap();
    let err = req.check_state(&StateHolders::core()).unwrap_err();
    assert!(
        err.message.contains(&format!(
            "{at}.state.$state_keys.reads[0]`: the state mode `node` is not served by this node \
             at the tip"
        )),
        "{err}"
    );
    let mut m = swap.clone();
    m["state"] = json!({"$state_keys.reads[0]": "client", "$state_keys.writes[0]": "client"});
    refused(
        tip_body(m),
        &format!("{at}.state.$state_keys.reads[0]`: the state mode `client` needs intake direct"),
    );
    let mut m = swap.clone();
    m["consume"] = json!([{"key": "$state_keys.reads[0]"}]);
    refused(
        tip_body(m),
        &format!("{at}.consume`: only with intake direct; this manifest has intake onchain"),
    );
    // stale_blocks is the contract manifest's, not a circuit manifest's
    let mut m = swap.clone();
    m["stale_blocks"] = json!(50);
    refused(tip_body(m), at);
    // an INPUT_SHARED source under either non-secret-shared intake
    let mut m = swap.clone();
    m["witness"][1]["from"] = json!({"INPUT_SHARED": "amount_in"});
    refused(
        tip_body(m.clone()),
        "on-chain intake takes no INPUT_SHARED source; shared inputs take secret-shared receipt intake or secret-shared on-chain intake",
    );
    m["intake"] = json!("receipt");
    refused(
        tip_body(m),
        "receipt intake takes no INPUT_SHARED source; shared inputs take secret-shared receipt intake or secret-shared on-chain intake",
    );
    // either intake with clear (PUBLIC) inputs parses
    let mut m = swap;
    m["intake"] = json!("receipt");
    ManifestMessage::from_json(&tip_body(m).to_string()).unwrap();
    // a secret-shared intake's manifest passes its rules
    let mut shared = crate::manifest::tests::shared_receipt_round();
    shared["circuit"] = json!("amm_swap_tip");
    ManifestMessage::from_json(&tip_body(shared.clone()).to_string()).unwrap();
    shared["intake"] = json!("shared_onchain");
    let packages = [TestPackage::on("amm_swap_tip", "pss_seed", shared).keys(&["pool"], &["pool"])];
    let mut tip = TipFacts::new(Fr::from(12u64), 1, &[("pool", Fr::from(16u64))]);
    tip.shared_onchain_slot = Some(Fr::from(14u64));
    ManifestMessage::from_json(&message(&packages, Some(&tip)).to_string()).unwrap();
}
