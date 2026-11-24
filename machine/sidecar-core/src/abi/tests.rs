//! The ABI check tests and the shared ABI builders other tests use.

use super::*;
use crate::error::ErrorClass;
use serde_json::{Value, json};

// ABI type builders, in the JSON form nargo writes.
pub(crate) fn field() -> Value {
    json!({"kind": "field"})
}
pub(crate) fn array(length: u32, typ: Value) -> Value {
    json!({"kind": "array", "length": length, "type": typ})
}
pub(crate) fn uint(width: u32) -> Value {
    json!({"kind": "integer", "sign": "unsigned", "width": width})
}
pub(crate) fn boolean() -> Value {
    json!({"kind": "boolean"})
}
pub(crate) fn effects(r: u32, w: u32, a: u32) -> Value {
    json!({"kind": "struct", "path": "pss_core::effects::PssEffects", "fields": [
        {"name": "read_leaves", "type": array(r, field())},
        {"name": "nullifiers", "type": array(r, field())},
        {"name": "new_note_hashes", "type": array(w, field())},
        {"name": "npk_app_hash", "type": field()},
        {"name": "app_outputs", "type": array(a, field())}
    ]})
}

/// An ABI from `(name, visibility, type)` triples and a public return type.
pub(crate) fn abi(params: &[(&str, &str, Value)], ret: Option<Value>) -> Abi {
    let parameters: Vec<Value> = params
        .iter()
        .map(|(n, v, t)| json!({"name": n, "type": t, "visibility": v}))
        .collect();
    let return_type = ret.map(|t| json!({"abi_type": t, "visibility": "public"}));
    serde_json::from_value(json!({
        "parameters": parameters, "return_type": return_type, "error_types": {}
    }))
    .unwrap()
}

// The ABIs of the three AMM round circuits, as nargo compiles them.
pub(crate) fn pss_seed_abi() -> Abi {
    abi(
        &[
            ("namespace", "public", field()),
            ("owner", "public", field()),
            ("out_slots", "public", array(1, field())),
            ("out0_randomness", "private", field()),
            ("rand_seed", "private", field()),
        ],
        Some(effects(0, 1, 0)),
    )
}

pub(crate) fn amm_init_abi() -> Abi {
    abi(
        &[
            ("namespace", "public", field()),
            ("owner", "public", field()),
            ("in_slots", "public", array(1, field())),
            ("out_slots", "public", array(1, field())),
            ("in0_fields", "private", array(1, field())),
            ("in0_randomness", "private", field()),
            ("in0_nonce", "private", field()),
            ("out0_randomness", "private", field()),
            ("nsk_app", "private", field()),
        ],
        Some(effects(1, 1, 0)),
    )
}

pub(crate) fn amm_swap_abi() -> Abi {
    abi(
        &[
            ("namespace", "public", field()),
            ("owner", "public", field()),
            ("in_slots", "public", array(1, field())),
            ("out_slots", "public", array(1, field())),
            ("amount_in", "public", uint(64)),
            ("direction", "public", boolean()),
            ("in0_fields", "private", array(2, field())),
            ("in0_randomness", "private", field()),
            ("in0_nonce", "private", field()),
            ("out0_randomness", "private", field()),
            ("nsk_app", "private", field()),
        ],
        Some(effects(1, 1, 1)),
    )
}

/// An example's manifest, read from `examples/<example>/manifests/<name>.json`.
pub(crate) use crate::testing::manifest as example_manifest;

/// An AMM manifest.
pub(crate) fn manifest_json(name: &str) -> Value {
    example_manifest("amm", name)
}

/// The ABI of a compiled example circuit, or `None` (with a message) when
/// `scripts/check-noir.sh examples/<example>` has not been run; panics
/// naming the artifact and that command when it is older than its source.
pub(crate) fn compiled_abi(example: &str, name: &str) -> Option<Abi> {
    use crate::testing::artifacts;
    let path = artifacts::compiled(example, name);
    let refresh = format!("scripts/check-noir.sh examples/{example}");
    if !artifacts::usable(&path, &artifacts::package(example, name), &refresh) {
        return None;
    }
    let text = std::fs::read_to_string(&path).unwrap();
    let artifact: Value = serde_json::from_str(&text).unwrap();
    Some(serde_json::from_value(artifact["abi"].clone()).unwrap())
}

fn refused(manifest: &Value, abi: &Abi, needles: &[&str]) {
    crate::error::assert_refused(
        check_manifest_value(manifest, abi),
        ErrorClass::BadRequest,
        needles,
    );
}

fn witness(m: &mut Value) -> &mut Vec<Value> {
    m["witness"].as_array_mut().unwrap()
}

#[test]
fn the_amm_manifests_match_their_abis() {
    let cases = [
        ("pss_seed", pss_seed_abi(), 5, vec![3]),
        ("amm_init", amm_init_abi(), 8, vec![6]),
        ("amm_swap", amm_swap_abi(), 11, vec![8]),
    ];
    for (name, abi, count, note_hashes) in cases {
        let (_, shape) = check_manifest_value(&manifest_json(name), &abi).unwrap();
        assert_eq!(shape.public_input_count, count, "{name}");
        assert_eq!(shape.namespace_index, 0, "{name}");
        let idx: Vec<usize> = shape.outputs.iter().map(|o| o.note_hash_index).collect();
        assert_eq!(idx, note_hashes, "{name}");
    }
}

#[test]
fn the_swap_shape_lists_keys_widths_and_public_indices() {
    let (_, shape) = check_manifest_value(&manifest_json("amm_swap"), &amm_swap_abi()).unwrap();
    let summary: Vec<(&str, Vec<&str>, Option<usize>)> = shape
        .params
        .iter()
        .map(|p| {
            (
                p.name.as_str(),
                p.keys.iter().map(String::as_str).collect(),
                p.public_index,
            )
        })
        .collect();
    assert_eq!(
        summary,
        vec![
            ("namespace", vec!["namespace"], Some(0)),
            ("owner", vec!["owner"], Some(1)),
            ("in_slots", vec!["in_slots"], Some(2)),
            ("out_slots", vec!["out_slots"], Some(3)),
            ("amount_in", vec!["amount_in"], Some(4)),
            ("direction", vec!["direction"], Some(5)),
            ("in0_fields", vec!["in0_fields[0]", "in0_fields[1]"], None),
            ("in0_randomness", vec!["in0_randomness"], None),
            ("in0_nonce", vec!["in0_nonce"], None),
            ("out0_randomness", vec!["out0_randomness"], None),
            ("nsk_app", vec!["nsk_app"], None),
        ]
    );
    assert_eq!(
        shape.param("amount_in").unwrap().leaves,
        vec![Leaf::Bits(64)]
    );
    assert_eq!(
        shape.param("direction").unwrap().leaves,
        vec![Leaf::Bits(1)]
    );
    assert_eq!(shape.public_param_fields, 6);
    assert_eq!(
        shape.return_paths,
        vec![
            "read_leaves[0]",
            "nullifiers[0]",
            "new_note_hashes[0]",
            "npk_app_hash",
            "app_outputs[0]"
        ]
    );
    assert_eq!(shape.return_index("npk_app_hash"), Some(9));
    assert_eq!(shape.return_index("app_outputs[0]"), Some(10));
}

#[test]
fn a_missing_parameter_is_refused() {
    let mut m = manifest_json("amm_swap");
    witness(&mut m).remove(5);
    refused(
        &m,
        &amm_swap_abi(),
        &["parameter `direction`", "no witness entry"],
    );
}

#[test]
fn an_extra_parameter_is_refused() {
    let mut m = manifest_json("amm_swap");
    witness(&mut m).push(json!({"param": "rand_extra", "from": {"SAMPLE": 1}}));
    refused(
        &m,
        &amm_swap_abi(),
        &["parameter `rand_extra`", "not a parameter"],
    );
}

#[test]
fn a_parameter_out_of_order_is_refused() {
    let mut m = manifest_json("amm_swap");
    witness(&mut m).swap(4, 5);
    refused(
        &m,
        &amm_swap_abi(),
        &[
            "parameter `direction`",
            "out of order",
            "`amount_in` at position 4",
        ],
    );
}

#[test]
fn wrong_widths_are_refused_for_every_source() {
    let abi = amm_swap_abi();
    let cases: [(usize, Value, &str); 5] = [
        (
            6,
            json!({"LOAD": "$state_keys.reads[0]", "slice": [0, 1], "len": 3}),
            "slice [0, 1] has 1 element(s), the parameter has 2",
        ),
        (
            9,
            json!({"SAMPLE": 2}),
            "SAMPLE 2 draws 2, the parameter has 1",
        ),
        (
            2,
            json!({"PUBLIC": ["$state_keys.reads[0]", "$state_keys.reads[0]"]}),
            "PUBLIC lists 2 operand(s), the parameter has 1",
        ),
        (
            6,
            json!({"PUBLIC": {"const": "0x1"}}),
            "one PUBLIC operand fills one field, the parameter has 2",
        ),
        (
            6,
            json!({"INPUT_SHARED": "fields"}),
            "INPUT_SHARED `fields` fills one field, the parameter has 2",
        ),
    ];
    for (k, from, needle) in cases {
        let mut m = manifest_json("amm_swap");
        witness(&mut m)[k]["from"] = from;
        // A LOAD replaced by something else leaves the other slice alone; fine.
        let name = m["witness"][k]["param"].as_str().unwrap().to_string();
        refused(&m, &abi, &[&format!("parameter `{name}`"), needle]);
    }
}

#[test]
fn only_public_fills_a_public_parameter() {
    let abi = amm_swap_abi();
    for (from, opcode) in [
        (json!({"SAMPLE": 1}), "SAMPLE"),
        (
            json!({"LOAD": "$state_keys.reads[0]", "slice": [0, 1], "len": 3}),
            "LOAD",
        ),
        (json!({"INPUT_SHARED": "amount"}), "INPUT_SHARED"),
    ] {
        let mut m = manifest_json("amm_swap");
        witness(&mut m)[4]["from"] = from;
        refused(
            &m,
            &abi,
            &[
                "parameter `amount_in`",
                opcode,
                "only PUBLIC fills a public parameter",
            ],
        );
    }
    // PUBLIC into a private parameter is fine: in0_nonce already is one.
    let (_, shape) = check_manifest_value(&manifest_json("amm_swap"), &abi).unwrap();
    assert_eq!(
        shape.param("in0_nonce").unwrap().visibility,
        Visibility::Private
    );
}

#[test]
fn the_namespace_param_must_be_a_public_field_filled_by_namespace() {
    let m = manifest_json("amm_swap");
    // Private in the ABI.
    let mut private = amm_swap_abi();
    private.parameters[0].visibility = AbiVisibility::Private;
    refused(&m, &private, &["namespace_param", "`namespace` is private"]);
    // Not a Field.
    let mut typed = amm_swap_abi();
    typed.parameters[0].typ = AbiType::Integer {
        sign: noirc_abi::Sign::Unsigned,
        width: 64,
    };
    refused(&m, &typed, &["namespace_param", "not a Field"]);
    // Filled by something other than PUBLIC $namespace: the manifest parser
    // already refuses it.
    let mut m2 = manifest_json("amm_swap");
    witness(&mut m2)[0]["from"] = json!({"PUBLIC": {"const": "0x1"}});
    refused(&m2, &amm_swap_abi(), &["namespace_param", "$namespace"]);
    // Naming another public Field that is not filled by $namespace.
    let mut m3 = manifest_json("amm_swap");
    m3["namespace_param"] = json!("owner");
    refused(&m3, &amm_swap_abi(), &["namespace_param", "$namespace"]);
}

#[test]
fn a_note_hash_must_name_one_public_field_output() {
    let abi = amm_swap_abi();
    for (path, needle) in [
        ("new_note_hashes[1]", "not an output of the circuit"),
        ("note_hashes[0]", "not an output of the circuit"),
        ("new_note_hashes", "not one field element"),
    ] {
        let mut m = manifest_json("amm_swap");
        m["outputs"][0]["note_hash"] = json!(path);
        refused(&m, &abi, &["outputs[0].note_hash", needle]);
    }
    // A private return value.
    let mut private = amm_swap_abi();
    private.return_type.as_mut().unwrap().visibility = AbiVisibility::Private;
    refused(
        &manifest_json("amm_swap"),
        &private,
        &["outputs[0].note_hash", "private output"],
    );
    // No return value at all.
    let mut none = amm_swap_abi();
    none.return_type = None;
    refused(
        &manifest_json("amm_swap"),
        &none,
        &["outputs[0].note_hash", "not an output"],
    );
}

#[test]
fn databus_visibility_is_refused() {
    let mut abi = amm_swap_abi();
    abi.parameters[7].visibility = AbiVisibility::DataBus;
    refused(
        &manifest_json("amm_swap"),
        &abi,
        &["parameter `in0_randomness`", "databus"],
    );
    let mut abi = amm_swap_abi();
    abi.return_type.as_mut().unwrap().visibility = AbiVisibility::DataBus;
    refused(
        &manifest_json("amm_swap"),
        &abi,
        &["return value", "databus"],
    );
}

#[test]
fn queue_and_load_create_are_refused_at_register() {
    let abi = amm_swap_abi();
    let mut m = manifest_json("amm_swap");
    m["queue"] = json!("pool");
    refused(&m, &abi, &["`queue`", "unknown field"]);
    let mut m = manifest_json("amm_swap");
    m["commitment_slot"] = json!({});
    refused(
        &m,
        &abi,
        &["`commitment_slot`", "only with a queued intake"],
    );
    let mut m = manifest_json("amm_swap");
    witness(&mut m)[6]["from"]["create"] = json!("SAMPLE");
    refused(&m, &abi, &["create", "SAMPLE parameter and STORE"]);
}

#[test]
fn a_constant_out_of_its_type_range_is_refused() {
    let abi = amm_swap_abi();
    let mut m = manifest_json("amm_swap");
    witness(&mut m)[5]["from"] = json!({"PUBLIC": {"const": "0x2"}});
    refused(
        &m,
        &abi,
        &["parameter `direction`", "does not fit its 1-bit type"],
    );
    witness(&mut m)[5]["from"] = json!({"PUBLIC": {"const": "0x1"}});
    check_manifest_value(&m, &abi).unwrap();
}

#[test]
fn an_oversized_abi_is_refused_without_panicking() {
    let huge = array(1 << 16, array(1 << 16, array(1 << 16, field())));
    let abi = abi(&[("namespace", "public", huge)], None);
    refused(
        &manifest_json("amm_swap"),
        &abi,
        &["past", "field elements"],
    );
}

#[test]
fn the_field_bound_counts_every_parameter_together() {
    let half = array((1 << 19) + 1, field());
    let abi = abi(
        &[
            ("namespace", "public", half.clone()),
            ("owner", "public", half),
        ],
        None,
    );
    refused(
        &manifest_json("amm_swap"),
        &abi,
        &["parameter `owner`", "past", "field elements"],
    );
}

// noirc_abi deserialises an empty tuple, so an array of them has no field
// elements at any length: the walk refuses it rather than looping.
#[test]
fn an_array_of_zero_width_elements_is_refused_without_walking_it() {
    let empty = json!({"kind": "tuple", "fields": []});
    for typ in [
        array(u32::MAX, empty.clone()),
        array(u32::MAX, array(u32::MAX, empty.clone())),
        array(3, json!({"kind": "struct", "path": "E", "fields": []})),
        array(u32::MAX, json!({"kind": "string", "length": 0})),
    ] {
        let abi = abi(
            &[("namespace", "public", field()), ("x", "private", typ)],
            None,
        );
        refused(
            &manifest_json("amm_swap"),
            &abi,
            &["parameter `x`", "no field elements"],
        );
    }
    let abi = abi(
        &[("namespace", "public", field())],
        Some(array(u32::MAX, empty)),
    );
    refused(
        &manifest_json("amm_swap"),
        &abi,
        &["the return value", "no field elements"],
    );
}

// Within MAX_ABI_FIELDS, long struct field names repeated by an array would
// make gigabytes of paths: the walk bound refuses them.
#[test]
fn a_walk_past_its_bound_is_refused_within_the_field_bound() {
    let long = "x".repeat(1000);
    let wide = array(
        1 << 20,
        json!({"kind": "struct", "path": "S", "fields": [{"name": long, "type": field()}]}),
    );
    let abi = abi(&[("namespace", "public", wide)], None);
    refused(
        &manifest_json("amm_swap"),
        &abi,
        &["parameter `namespace`", "path bytes"],
    );
}

#[test]
fn struct_tuple_and_string_parameters_flatten_like_co_noir() {
    let point = json!({"kind": "struct", "path": "P", "fields": [
        {"name": "x", "type": field()}, {"name": "y", "type": uint(8)}
    ]});
    let pair = json!({"kind": "tuple", "fields": [boolean(), field()]});
    let text = json!({"kind": "string", "length": 2});
    let abi = abi(
        &[
            ("namespace", "public", field()),
            ("point", "public", point),
            ("pair", "private", pair),
            ("label", "public", text),
        ],
        Some(json!({"kind": "tuple", "fields": [field(), array(2, field())]})),
    );
    let m = json!({
        "manifest": 1, "circuit": "c", "namespace_param": "namespace",
        "state_keys": {"reads": 0, "writes": 0},
        "witness": [
            {"param": "namespace", "from": {"PUBLIC": "$namespace"}},
            {"param": "point", "from": {"PUBLIC": "point"}},
            {"param": "pair", "from": {"SAMPLE": 2}},
            {"param": "label", "from": {"PUBLIC": [{"const": "0x61"}, {"const": "0x62"}]}}
        ],
        "outputs": [], "state": {}
    });
    let (_, shape) = check_manifest_value(&m, &abi).unwrap();
    let point = shape.param("point").unwrap();
    assert_eq!(point.keys, vec!["point[0]", "point[1]"]);
    assert_eq!(point.leaves, vec![Leaf::Field, Leaf::Bits(8)]);
    assert_eq!(shape.param("label").unwrap().leaves, vec![Leaf::Bits(8); 2]);
    assert_eq!(shape.param("label").unwrap().public_index, Some(3));
    assert_eq!(
        shape.return_paths,
        vec!["return.0", "return.1[0]", "return.1[1]"]
    );
    assert_eq!(shape.public_input_count, 8);
}

// The ABI the AMM tip manifest (testvectors/manifests/amm_swap_tip.json,
// the example's) fits: the namespace, the vk hash and the key slots
// public, the swap inputs, the partial note, the nonce, the pool and its
// blindings private, and a public return carrying the request id, the
// old and new commitments and the partial note right after `ok`.
pub(crate) fn amm_swap_tip_abi() -> Abi {
    abi(
        &[
            ("namespace", "public", field()),
            ("vk_hash", "public", field()),
            ("in_slots", "public", array(1, field())),
            ("out_slots", "public", array(1, field())),
            ("amount_in", "private", field()),
            ("direction", "private", field()),
            ("min_out", "private", field()),
            ("partial_note", "private", field()),
            ("user_nonce", "private", field()),
            ("pool", "private", array(2, field())),
            ("r_old", "private", field()),
            ("r_new", "private", field()),
            ("nsk_app", "private", field()),
        ],
        Some(tip_out(field())),
    )
}

fn tip_out(old_c: Value) -> Value {
    json!({"kind": "struct", "path": "amm_tip::AmmTipOut", "fields": [
        {"name": "request_id", "type": field()},
        {"name": "old_c", "type": old_c},
        {"name": "new_c", "type": field()},
        {"name": "npk_app_hash", "type": field()},
        {"name": "ok", "type": field()},
        {"name": "partial_note", "type": field()},
        {"name": "code", "type": field()},
        {"name": "amount_out", "type": field()}
    ]})
}

fn tip_refused(manifest: &Value, abi: &Abi, needles: &[&str]) {
    let err = check_manifest_value(manifest, abi).unwrap_err();
    assert_eq!(err.class, ErrorClass::BadRequest, "{err}");
    for needle in needles {
        assert!(
            err.message.contains(needle),
            "`{}` lacks `{needle}`",
            err.message
        );
    }
}

/// The ABI of machine/circuits/tip_tree (depth 16, three slots of three).
pub(crate) fn tip_tree_abi() -> Abi {
    abi(
        &[
            ("namespace", "public", field()),
            ("vk_hash", "public", field()),
            ("in_slots", "public", array(1, field())),
            ("out_slots", "public", array(1, field())),
            ("amount", "private", field()),
            ("p1", "private", field()),
            ("p2", "private", field()),
            ("count", "private", field()),
            ("user_nonce", "private", field()),
            ("leaves", "private", array(3, array(3, field()))),
            ("old_hashes", "private", array(3, field())),
            ("siblings", "private", array(3, array(16, field()))),
            ("indices", "private", array(3, field())),
            ("new_leaf", "private", field()),
            ("r_new", "private", array(3, field())),
        ],
        Some(
            json!({"kind": "struct", "path": "tip_tree::TreeOutputs", "fields": [
                {"name": "request_id", "type": field()},
                {"name": "old_c", "type": field()},
                {"name": "new_c", "type": field()},
                {"name": "new_hashes", "type": array(3, field())},
                {"name": "ok", "type": field()},
                {"name": "code", "type": field()},
                {"name": "position", "type": field()}
            ]}),
        ),
    )
}

// A tree key's parameters against the ABI: widths, private, and the new
// hashes one public array of probe Fields; its parameters are not app
// inputs, so the library's layout holds.
#[test]
fn a_tree_manifest_matches_its_abi() {
    let m: Value = serde_json::from_str(include_str!(
        "../../../../machine/circuits/manifests/tip_tree.json"
    ))
    .unwrap();
    let abi = tip_tree_abi();
    let (manifest, shape) = check_manifest_value(&m, &abi).unwrap();
    check_tip_public_prefix(&manifest, &shape).unwrap();
    // public inputs: namespace, vk_hash, in_slots, out_slots, then
    // request_id, old_c, new_c, new_hashes[3], ok, code, position
    assert_eq!(shape.public_input_count, 13);
    assert_eq!(shape.return_index("new_hashes[0]"), Some(7));
    assert_eq!(shape.param("siblings").unwrap().width, 48);

    let mut wrong = abi.clone();
    wrong.parameters[11].typ = serde_json::from_value(array(3, array(15, field()))).unwrap();
    tip_refused(
        &m,
        &wrong,
        &[
            "tree.$state_keys.reads[0].params.siblings",
            "the layout gives 48",
        ],
    );
    let mut public = abi.clone();
    public.parameters[10].visibility = AbiVisibility::Public;
    tip_refused(&m, &public, &["params.old_hashes", "is public"]);
    let mut short = m.clone();
    short["tree"]["$state_keys.reads[0]"]["new_hashes"] = json!("old_c");
    tip_refused(&short, &abi, &["new_hashes", "`old_c[0]` is not an output"]);
}

#[test]
fn the_amm_tip_manifest_matches_its_abi() {
    let m = crate::manifest::tests::amm_swap_tip();
    let abi = amm_swap_tip_abi();
    let (manifest, shape) = check_manifest_value(&m, &abi).unwrap();
    assert!(manifest.queued());
    // public inputs: namespace, vk_hash, in_slots, out_slots, then the
    // eight returns
    assert_eq!(shape.public_input_count, 12);
    assert_eq!(shape.namespace_index, 0);
    assert_eq!(shape.return_index("old_c"), Some(5));
    assert_eq!(shape.outputs[0].note_hash_index, 6);
}

// Every package of every example deployment descriptor
// (examples/*/deployments/*.json: a manifest of the example's manifests/
// and the compiled circuit it registers, an alias's included) against its
// compiled circuit (`scripts/check-noir.sh examples/<example>` writes
// them): REGISTER's checks of the manifest against the ABI, the
// deferred-option refusals, the one public-input layout of a tip round and
// the outcome checks. A circuit not compiled is skipped (a failure under
// PSS_REQUIRE_DATA=1). The positions each contract builds its verifier
// inputs from are pinned by test-support's ABI fixtures and the contracts'
// own tests.
#[test]
fn every_example_deployment_registers_against_its_compiled_circuits() {
    let examples = crate::testing::artifacts::repo().join("examples");
    let mut descriptors: Vec<_> = std::fs::read_dir(&examples)
        .unwrap()
        .filter_map(|e| std::fs::read_dir(e.unwrap().path().join("deployments")).ok())
        .flatten()
        .map(|e| e.unwrap().path())
        .collect();
    descriptors.sort();
    assert!(
        !descriptors.is_empty(),
        "no deployment descriptor under {examples:?}"
    );
    let mut checked = std::collections::BTreeSet::new();
    for path in descriptors {
        let example = path
            .parent()
            .and_then(|d| d.parent())
            .and_then(|d| d.file_name())
            .unwrap()
            .to_string_lossy()
            .into_owned();
        let descriptor: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap())
            .unwrap_or_else(|e| panic!("{path:?}: {e}"));
        for package in descriptor["packages"].as_array().unwrap() {
            let (name, circuit) = (
                package["name"].as_str().unwrap(),
                package["circuit"].as_str().unwrap(),
            );
            if !checked.insert((example.clone(), name.to_string(), circuit.to_string())) {
                continue;
            }
            let Some(abi) = compiled_abi(&example, circuit) else {
                continue;
            };
            let what = format!("{example}: {name} on {circuit}");
            let m = example_manifest(&example, name);
            let (manifest, shape) =
                check_manifest_value(&m, &abi).unwrap_or_else(|e| panic!("{what}: {e}"));
            crate::registry::refuse_deferred_options(&manifest)
                .unwrap_or_else(|e| panic!("{what}: {e}"));
            check_tip_public_prefix(&manifest, &shape).unwrap_or_else(|e| panic!("{what}: {e}"));
            crate::registry::check_outcome(&manifest, &shape)
                .unwrap_or_else(|e| panic!("{what}: {e}"));
        }
    }
    eprintln!("example packages checked: {}", checked.len());
}

#[test]
fn a_commitment_slot_must_name_a_public_field_output() {
    let abi = amm_swap_tip_abi();
    let with_old = |old: &str| {
        let mut m = crate::manifest::tests::amm_swap_tip();
        m["commitment_slot"]["$state_keys.reads[0]"]["old"] = json!(old);
        m
    };
    tip_refused(
        &with_old("old_commitment"),
        &abi,
        &[
            "field `commitment_slot.$state_keys.reads[0].old`",
            "`old_commitment` is not an output of the circuit",
        ],
    );
    // a parameter is not an output
    tip_refused(
        &with_old("r_old"),
        &abi,
        &["`r_old` is not an output of the circuit"],
    );
    // one element of the return value, of type Field, in a public return
    let wide = abi_with_return(tip_out(array(2, field())), "public");
    tip_refused(
        &with_old("old_c"),
        &wide,
        &["`old_c` is not one field element; name one, such as `old_c[0]`"],
    );
    check_manifest_value(&with_old("old_c[1]"), &wide).unwrap();
    let narrow = abi_with_return(tip_out(uint(8)), "public");
    tip_refused(
        &with_old("old_c"),
        &narrow,
        &["`old_c` is a 8-bit value, not a Field"],
    );
    // (a private return makes the note hash refused first)
    let private = abi_with_return(tip_out(field()), "private");
    tip_refused(
        &with_old("old_c"),
        &private,
        &["is a private output; a commitment must be a public input"],
    );
    // the checks every manifest shares run on a queued one too
    let mut m = crate::manifest::tests::amm_swap_tip();
    witness(&mut m)[11]["from"] = json!({"SAMPLE": 2});
    tip_refused(
        &m,
        &abi,
        &["field `witness[11]`, parameter `r_new`", "SAMPLE 2"],
    );
    let mut m = crate::manifest::tests::amm_swap_tip();
    m["outputs"][0]["note_hash"] = json!("amount_in");
    tip_refused(&m, &abi, &["field `outputs[0].note_hash`", "not an output"]);
}

fn abi_with_return(ret: Value, visibility: &str) -> Abi {
    let mut abi = serde_json::to_value(amm_swap_tip_abi()).unwrap();
    abi["return_type"] = json!({"abi_type": ret, "visibility": visibility});
    serde_json::from_value(abi).unwrap()
}

// A reserved operand fills one Field parameter, public or private.
#[test]
fn a_reserved_operand_fills_a_field_parameter() {
    let m = crate::manifest::tests::amm_swap_tip();
    let (_, shape) = check_manifest_value(&m, &amm_swap_tip_abi()).unwrap();
    assert_eq!(
        shape.param("user_nonce").unwrap().source,
        Source::Public(PublicSource::One(PublicOperand::Reserved(
            crate::manifest::ReservedOperand::UserNonce
        )))
    );
    let mut public = serde_json::to_value(amm_swap_tip_abi()).unwrap();
    public["parameters"][8]["visibility"] = json!("public");
    check_manifest_value(&m, &serde_json::from_value(public).unwrap()).unwrap();
    let mut narrow = serde_json::to_value(amm_swap_tip_abi()).unwrap();
    narrow["parameters"][8]["type"] = uint(64);
    tip_refused(
        &m,
        &serde_json::from_value(narrow).unwrap(),
        &[
            "field `witness[8]`, parameter `user_nonce`",
            "`$user_nonce` is a full field element and fills a Field parameter, not a 64-bit one",
        ],
    );
    let mut wide = serde_json::to_value(amm_swap_tip_abi()).unwrap();
    wide["parameters"][8]["type"] = array(2, field());
    tip_refused(
        &m,
        &serde_json::from_value(wide).unwrap(),
        &["one PUBLIC operand fills one field, the parameter has 2"],
    );
}

#[test]
fn a_public_read_must_fill_a_public_parameter() {
    let read = |param: &str| {
        let mut m = crate::manifest::tests::amm_swap_tip();
        m["public_reads"] = json!([{"contract": "0x2a", "function": "get_price",
                                    "args": ["0x01"], "param": param}]);
        m
    };
    // the swap's ABI with amount_in (4) and direction (5) public
    let public = |widen_direction: bool| {
        let mut abi = serde_json::to_value(amm_swap_tip_abi()).unwrap();
        abi["parameters"][4]["visibility"] = json!("public");
        abi["parameters"][5]["visibility"] = json!("public");
        if widen_direction {
            abi["parameters"][5]["type"] =
                json!({"kind": "array", "length": 2, "type": {"kind": "field"}});
        }
        serde_json::from_value::<Abi>(abi).unwrap()
    };
    let (_, shape) = check_manifest_value(&read("amount_in"), &public(false)).unwrap();
    assert_eq!(shape.param("amount_in").unwrap().public_index, Some(4));
    // PUBLIC may fill a private parameter, but a public read may not.
    let private = amm_swap_tip_abi();
    check_manifest_value(&crate::manifest::tests::amm_swap_tip(), &private).unwrap();
    tip_refused(
        &read("amount_in"),
        &private,
        &[
            "field `public_reads[0].param`",
            "`amount_in` is a private parameter; a public read fills a public input",
        ],
    );
    // an epoch read's epoch is public too, and each is one Field
    let mut m = read("direction");
    m["public_reads"][0]["freshness"] = json!("epoch");
    m["public_reads"][0]["epoch_param"] = json!("amount_in");
    check_manifest_value(&m, &public(false)).unwrap();
    let mut only_direction = serde_json::to_value(amm_swap_tip_abi()).unwrap();
    only_direction["parameters"][5]["visibility"] = json!("public");
    tip_refused(
        &m,
        &serde_json::from_value(only_direction).unwrap(),
        &[
            "field `public_reads[0].epoch_param`",
            "`amount_in` is a private parameter",
        ],
    );
    let mut exact = read("direction");
    exact["witness"].as_array_mut().unwrap()[5]["from"] = json!({"PUBLIC": "direction"});
    let mut tolerance = exact.clone();
    tolerance["public_reads"][0]["freshness"] = json!("tolerance");
    tolerance["public_reads"][0]["band"] = json!({"absolute": "5"});
    tip_refused(
        &tolerance,
        &public(true),
        &[
            "field `public_reads[0].param`: `direction` has 2 elements; a read under freshness tolerance fills one Field",
        ],
    );
}

// The contract library's layout check: the checks of a manifest that
// passes REGISTER's, then `check_tip_public_prefix` (400 naming the first
// public element out of place).
fn layout_refused(manifest: &Value, abi: &Abi, needles: &[&str]) {
    let (m, shape) = check_manifest_value(manifest, abi).unwrap();
    let err = check_tip_public_prefix(&m, &shape).unwrap_err();
    assert_eq!(err.class, ErrorClass::BadRequest, "{err}");
    for needle in needles {
        assert!(
            err.message.contains(needle),
            "`{}` lacks `{needle}`",
            err.message
        );
    }
}

fn layout_holds(manifest: &Value, abi: &Abi) {
    let (m, shape) = check_manifest_value(manifest, abi).unwrap();
    check_tip_public_prefix(&m, &shape).unwrap();
}

// Every tip round takes one layout, whatever its intake: `$namespace`,
// `$vk_hash`, the key slots and the pinned reads public, every app input
// and reserved operand but `$vk_hash` private. The compiled example tip
// circuits follow it (every_example_deployment_registers_against_its_compiled_circuits).
#[test]
fn the_public_parameters_follow_the_contract_librarys_layout() {
    let abi = amm_swap_tip_abi();
    layout_holds(&crate::manifest::tests::amm_swap_tip(), &abi);
    // the same circuit under receipt intake: the same layout
    let mut receipt = crate::manifest::tests::amm_swap_tip();
    receipt["intake"] = json!("receipt");
    layout_holds(&receipt, &abi);
    // a public app input is out of place
    let mut public = serde_json::to_value(amm_swap_tip_abi()).unwrap();
    public["parameters"][4]["visibility"] = json!("public");
    let public: Abi = serde_json::from_value(public).unwrap();
    layout_refused(
        &crate::manifest::tests::amm_swap_tip(),
        &public,
        &[
            "field `witness`: under `onchain` intake the circuit's public parameters must be",
            "public element 4 is an app input where the layout has nothing",
        ],
    );
    layout_refused(
        &receipt,
        &public,
        &["under `receipt` intake", "public element 4 is an app input"],
    );
    // a public `$user_nonce`
    let mut nonce = serde_json::to_value(amm_swap_tip_abi()).unwrap();
    nonce["parameters"][8]["visibility"] = json!("public");
    layout_refused(
        &crate::manifest::tests::amm_swap_tip(),
        &serde_json::from_value(nonce).unwrap(),
        &["public element 4 is `$user_nonce` where the layout has nothing"],
    );
    // a private `$vk_hash`
    let mut vk = serde_json::to_value(amm_swap_tip_abi()).unwrap();
    vk["parameters"][1]["visibility"] = json!("private");
    layout_refused(
        &crate::manifest::tests::amm_swap_tip(),
        &serde_json::from_value(vk).unwrap(),
        &["public element 1 is `$state_keys.reads[0]` where the layout has `$vk_hash`"],
    );
    // the pinned reads follow the key slots: amount_in and direction
    // public, each filled by a read
    let read = |params: &[&str], epoch: bool| {
        let mut m = crate::manifest::tests::amm_swap_tip();
        m["public_reads"] = if epoch {
            json!([{"contract": "0x2a", "function": "get_price", "args": [],
                    "param": params[0], "freshness": "epoch", "epoch_param": params[1]}])
        } else {
            json!([{"contract": "0x2a", "function": "get_price", "args": ["0x01"],
                    "param": params[0]}])
        };
        m
    };
    let mut reads = serde_json::to_value(amm_swap_tip_abi()).unwrap();
    reads["parameters"][4]["visibility"] = json!("public");
    let one_read: Abi = serde_json::from_value(reads.clone()).unwrap();
    layout_holds(&read(&["amount_in"], false), &one_read);
    reads["parameters"][5]["visibility"] = json!("public");
    let two: Abi = serde_json::from_value(reads).unwrap();
    // an epoch read's epoch follows its value
    layout_holds(&read(&["amount_in", "direction"], true), &two);
    layout_refused(
        &read(&["direction", "amount_in"], true),
        &two,
        &[
            "public element 4 is the epoch of `public_reads[0]` where the layout has the value of `public_reads[0]`",
        ],
    );
    // a read of one public input with another app input public after it
    layout_refused(
        &read(&["amount_in"], false),
        &two,
        &["public element 5 is an app input where the layout has nothing"],
    );
}
