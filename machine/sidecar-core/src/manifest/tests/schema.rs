//! Schema tests: parsing, round trips, unknown fields, key references and the
//! per-path fields, reserved operands and defaults.

use crate::field::FieldHex;

use super::*;

/// Each intake's row names where a node's shares come from: envelopes
/// bound to the body under `direct` and the non-secret-shared intakes, to the chain
/// request id under secret-shared receipt intake, the request log under secret-shared
/// on-chain intake.
#[test]
fn each_intake_row_names_its_share_source() {
    use EnvelopeBinding::{Body, ChainRequest};
    for (intake, want) in [
        (Intake::Direct, ShareSource::Envelopes(Body)),
        (Intake::Onchain, ShareSource::Envelopes(Body)),
        (Intake::Receipt, ShareSource::Envelopes(Body)),
        (Intake::SharedReceipt, ShareSource::Envelopes(ChainRequest)),
        (Intake::SharedOnchain, ShareSource::DerivedLog),
    ] {
        assert_eq!(intake.share_source(), want, "{}", intake.as_str());
    }
}

#[test]
fn the_amm_manifests_parse_and_round_trip() {
    for v in [pss_seed(), amm_init(), amm_swap(), client_round()] {
        let m = parse(&v).unwrap();
        assert!(!m.queued());
        // Re-serialising gives the same JSON up to the spelling of constants,
        // which come back as 0x + 64 digits, and the intake written out
        // (consume [] is kept, a missing policy stays missing).
        let mut want = v.clone();
        want["intake"] = json!("direct");
        for entry in want["witness"].as_array_mut().unwrap() {
            if let Some(c) = entry["from"]
                .get_mut("PUBLIC")
                .and_then(|p| p.get_mut("const"))
            {
                *c = json!(c.as_str().unwrap().parse::<FieldHex>().unwrap().to_string());
            }
        }
        let again = serde_json::to_value(&m).unwrap();
        assert_eq!(again, want);
        assert_eq!(Manifest::parse(&again).unwrap(), m);
    }
    let swap = parse(&amm_swap()).unwrap();
    let direct = &swap;
    assert_eq!(swap.circuit, "amm_swap");
    let loads: Vec<_> = direct.loads().map(|(p, l)| (p, l.key, l.slice)).collect();
    assert_eq!(
        loads,
        [
            ("in0_fields", KeyRef::Read(0), [0, 2]),
            ("in0_randomness", KeyRef::Read(0), [2, 3]),
            ("nsk_app", KeyRef::Fixed(FixedKey::NskApp), [0, 1]),
        ]
    );
    assert_eq!(
        direct.witness[1].from,
        Source::Public(PublicSource::One(PublicOperand::Const(FieldHex::from(
            0xafafaf
        ))))
    );
    assert_eq!(
        direct.witness[2].from,
        Source::Public(PublicSource::List(vec![PublicOperand::Key(KeyRef::Read(
            0
        ))]))
    );
}

#[test]
fn default_consume_policy_is_once() {
    let client = parse(&client_round()).unwrap();
    assert_eq!(client.consume_policies(), [(KeyRef::Read(0), Policy::Once)]);
    let mut node = client_round();
    node["state"] = json!({ "$state_keys.reads[0]": "node", "$state_keys.writes[0]": "node" });
    let node = parse(&node).unwrap();
    assert_eq!(node.consume_policies(), [(KeyRef::Read(0), Policy::Once)]);
    let mut never = client_round();
    never["consume"][0]["policy"] = json!("never");
    let never = parse(&never).unwrap();
    assert_eq!(never.consume_policies(), [(KeyRef::Read(0), Policy::Never)]);
    assert_eq!(Policy::default(), Policy::Once);
    // once_per_inputs is not a policy (DECISIONS.md, "CONSUME is `once` or `never`").
    let mut gone = client_round();
    gone["consume"][0]["policy"] = json!("once_per_inputs");
    let err = parse(&gone).unwrap_err();
    assert!(err.message.contains("consume[0].policy"), "{}", err.message);
}

// A policy given as null is refused, as the schema and pss-client refuse it;
// only a missing policy defaults to `once`.
#[test]
fn a_null_consume_policy_is_refused() {
    let mut v = client_round();
    v["consume"][0]["policy"] = Value::Null;
    let err = parse(&v).unwrap_err();
    assert_eq!(err.class, ErrorClass::BadRequest);
    assert!(err.message.contains("consume[0].policy"), "{}", err.message);
}

#[test]
fn other_schema_versions_are_refused_naming_the_version() {
    for n in [0, 2, 3] {
        let mut v = amm_swap();
        v["manifest"] = json!(n);
        refused(
            v,
            &format!(
                "field `manifest`: manifest schema version {n} is not supported; this machine reads version 1"
            ),
        );
    }
    let mut v = amm_swap();
    v["manifest"] = json!("1");
    refused(v, "field `manifest`");
    let mut v = amm_swap();
    v.as_object_mut().unwrap().remove("manifest");
    refused(v, "field `manifest`: missing");
    refused(json!([1]), "not a JSON object");
}

#[test]
fn the_other_paths_fields_and_create_are_refused() {
    // Under intake direct, each queued-intake field, even with a valid value.
    let tip = amm_swap_tip();
    for field in ["binding", "commitment_slot"] {
        let mut v = amm_swap();
        v[field] = tip[field].clone();
        refused(
            v,
            &format!("field `{field}`: only with a queued intake; this manifest has intake direct"),
        );
    }
    // The state mode `chain`.
    let mut v = amm_swap();
    v["state"]["$state_keys.writes[0]"] = json!("chain");
    refused(
        v,
        "field `state.$state_keys.writes[0]`: the state mode `chain` needs a queued intake; this manifest has intake direct",
    );
    // Under a queued intake, `consume` (even empty) and the mode `client`.
    let mut v = amm_swap_tip();
    v["consume"] = json!([]);
    refused(
        v,
        "field `consume`: only with intake direct; this manifest has intake onchain",
    );
    let mut v = amm_swap_tip();
    v["state"]["$state_keys.writes[0]"] = json!("client");
    refused(
        v,
        "field `state.$state_keys.writes[0]`: the state mode `client` needs intake direct",
    );
    // `intake: direct` written out is the default.
    let mut v = amm_swap();
    v["intake"] = json!("direct");
    assert_eq!(parse(&v).unwrap(), parse(&amm_swap()).unwrap());
    // `queue` belongs to no path.
    let mut v = amm_swap();
    v["queue"] = json!("pool");
    refused(v, "field `queue`: unknown field `queue`");
    let mut v = amm_init();
    v["witness"][4]["from"]["create"] = json!("SAMPLE");
    let err = parse(&v).unwrap_err();
    assert_eq!(err.class, ErrorClass::BadRequest);
    for needle in [
        "witness[4].from",
        "LOAD `create` is not part of the manifest",
    ] {
        assert!(
            err.message.contains(needle),
            "`{}` lacks `{needle}`",
            err.message
        );
    }
}

#[test]
fn unknown_fields_are_refused_at_every_level() {
    let paths: [(&str, Edit); 6] = [
        ("extra", |v| v["extra"] = json!(1)),
        ("state_keys", |v| v["state_keys"]["deletes"] = json!(0)),
        ("witness[0]", |v| v["witness"][0]["note"] = json!("x")),
        ("witness[4].from", |v| {
            v["witness"][4]["from"]["offset"] = json!(0)
        }),
        ("outputs[0]", |v| v["outputs"][0]["shape"] = json!(1)),
        ("consume[0]", |v| v["consume"][0]["polcy"] = json!("once")),
    ];
    for (needle, edit) in paths {
        let mut v = amm_init();
        edit(&mut v);
        refused(v, needle);
    }
    let mut v = amm_init();
    v["witness"][1]["from"]["PUBLIC"]["value"] = json!("0x1");
    refused(v, "witness[1].from.PUBLIC");
}

#[test]
fn keyrefs_parse_and_bad_ones_are_refused() {
    assert_eq!(
        "$state_keys.reads[3]".parse::<KeyRef>().unwrap(),
        KeyRef::Read(3)
    );
    assert_eq!(
        "$state_keys.writes[0]".parse::<KeyRef>().unwrap(),
        KeyRef::Write(0)
    );
    assert_eq!(
        "nsk_app".parse::<KeyRef>().unwrap(),
        KeyRef::Fixed(FixedKey::NskApp)
    );
    for (bad, why) in [
        ("$state_keys.reads[]", "not a key reference"),
        ("$state_keys.reads[-1]", "not a key reference"),
        ("$state_keys.deletes[0]", "not a key reference"),
        ("$state_keys.reads[0", "not a key reference"),
        ("Nsk_app", "not a key reference"),
        ("master", "only fixed key is nsk_app"),
        ("nullifier-key", "only fixed key is nsk_app"),
    ] {
        let err = bad.parse::<KeyRef>().unwrap_err();
        assert!(err.contains(why), "{bad}: {err}");
    }
    for key in [
        KeyRef::Read(2),
        KeyRef::Write(11),
        KeyRef::Fixed(FixedKey::NskApp),
    ] {
        assert_eq!(key.to_string().parse::<KeyRef>().unwrap(), key);
    }

    let mut v = amm_init();
    v["witness"][8]["from"]["LOAD"] = json!("master");
    refused(v, "only fixed key is nsk_app");
    let mut v = amm_init();
    v["witness"][4]["from"]["LOAD"] = json!("$state_keys.reads[1]");
    refused(v, "out of range");
    let mut v = amm_init();
    v["state"]["$state_keys.reads[x]"] = json!("node");
    refused(v, "field `state.$state_keys.reads[x]`");
    let mut v = amm_init();
    v["witness"][2]["from"]["PUBLIC"] = json!(["nsk_app"]);
    // a bare name is a public value name, which a request may supply
    assert!(parse(&v).is_ok());
    let mut v = amm_init();
    v["witness"][2]["from"]["PUBLIC"] = json!(["$nsk_app"]);
    refused(v, "not a request reference");
}

#[test]
fn structural_refusals_name_the_field() {
    let cases: Vec<(Edit, &str)> = vec![
        (
            |v| v["witness"][0]["from"] = json!({"PUBLIC": "contract"}),
            "must be filled by PUBLIC \"$namespace\"",
        ),
        (
            |v| v["namespace_param"] = json!("addr"),
            "field `namespace_param`",
        ),
        (
            |v| v["witness"][1]["param"] = json!("namespace"),
            "witness[1].param",
        ),
        (
            |v| v["witness"][7]["from"] = json!({"SAMPLE": 0}),
            "witness[7].from.SAMPLE",
        ),
        (
            |v| v["witness"][7]["from"] = json!({"SAMPLE": 1, "PUBLIC": "x"}),
            "more than one opcode",
        ),
        (|v| v["witness"][7]["from"] = json!({}), "no opcode"),
        (
            |v| v["witness"][7]["from"] = json!({"SAMPLE": 1, "len": 1}),
            "belong to LOAD only",
        ),
        (
            |v| v["witness"][4]["from"] = json!({"LOAD": "$state_keys.reads[0]", "slice": [0, 1]}),
            "LOAD needs",
        ),
        (
            |v| v["witness"][4]["from"]["slice"] = json!([1, 1]),
            "witness[4].from.slice",
        ),
        (
            |v| v["witness"][4]["from"]["slice"] = json!([0, 3]),
            "witness[4].from.slice",
        ),
        (
            |v| v["witness"][5]["from"]["len"] = json!(3),
            "loaded with lengths 2 and 3",
        ),
        (
            |v| v["witness"][8]["from"]["len"] = json!(2),
            "fixed key nsk_app has length 1",
        ),
        (
            |v| v["witness"][4]["from"]["LOAD"] = json!("$state_keys.writes[0]"),
            "LOAD reads a $state_keys.reads[i] key",
        ),
        (
            |v| v["outputs"][0]["STORE"] = json!("$state_keys.reads[0]"),
            "outputs[0].STORE",
        ),
        (
            |v| v["outputs"][0]["STORE"] = json!("nsk_app"),
            "outputs[0].STORE",
        ),
        (|v| v["outputs"][0]["len"] = json!(0), "outputs[0].len"),
        (|v| v["state"]["nsk_app"] = json!("node"), "state.nsk_app"),
        (
            |v| v["state"]["$state_keys.reads[0]"] = json!("both"),
            "field `state.$state_keys.reads[0]`",
        ),
        (
            |v| v["consume"][0]["key"] = json!("nsk_app"),
            "never consumed",
        ),
        (
            |v| v["consume"][0]["key"] = json!("$state_keys.writes[0]"),
            "is not loaded",
        ),
        (
            |v| v["consume"][0]["policy"] = json!("never"),
            "client-held keys only",
        ),
        (
            |v| v["consume"][0]["policy"] = json!("twice"),
            "consume[0].policy",
        ),
        (
            |v| {
                let c = v["consume"][0].clone();
                v["consume"] = json!([c.clone(), c]);
            },
            "listed twice",
        ),
        (
            |v| v["state_keys"]["reads"] = json!(-1),
            "field `state_keys.reads`",
        ),
        (|v| v["consume"] = Value::Null, "field `consume`"),
    ];
    for (edit, needle) in cases {
        let mut v = amm_init();
        edit(&mut v);
        refused(v, needle);
    }
    let mut v = pss_seed();
    v["state"]["$state_keys.reads[0]"] = json!("node");
    refused(v, "out of range");
    let mut v = client_round();
    v["consume"] = json!([]);
    refused(
        v,
        "client-held key $state_keys.reads[0] is loaded but not listed",
    );
    // a key left out of `state` is node-held
    let mut v = amm_init();
    v["state"]
        .as_object_mut()
        .unwrap()
        .remove("$state_keys.reads[0]");
    let m = parse(&v).unwrap();
    assert_eq!(m.state_mode(KeyRef::Read(0)), Some(StateMode::Node));
    v.as_object_mut().unwrap().remove("state");
    assert_eq!(
        parse(&v).unwrap().state_modes().collect::<Vec<_>>(),
        [
            (KeyRef::Read(0), StateMode::Node),
            (KeyRef::Write(0), StateMode::Node)
        ]
    );
    let mut v = client_round();
    v["witness"][4]["from"] = json!({"INPUT_SHARED": "door"});
    refused(v, "fills two parameters");
}

#[test]
fn a_state_key_given_twice_is_refused() {
    let text = amm_init().to_string().replacen(
        "\"$state_keys.reads[0]\":\"node\"",
        "\"$state_keys.reads[0]\":\"node\",\"$state_keys.reads[0]\":\"client\"",
        1,
    );
    let err = parse_json::<Manifest>(&text).unwrap_err();
    assert!(err.message.contains("appears twice"), "{}", err.message);
}

// Every manifest the repository ships (examples/*/manifests,
// machine/circuits/manifests and testvectors/manifests) parses under the one
// schema.
#[test]
fn the_shipped_manifests_parse() {
    let paths = crate::testing::artifacts::shipped_manifests();
    for path in &paths {
        let text = std::fs::read_to_string(path).unwrap();
        if let Err(e) = parse_text(&text) {
            panic!("{}: {e}", path.display());
        }
    }
    assert!(paths.len() >= 17, "{} manifests", paths.len());
}

/// A queued manifest takes the default state mode `node` for a key it
/// leaves out, as a direct one does; `chain` must be written.
#[test]
fn a_queued_manifest_defaults_a_key_to_node() {
    let m = tip(&amm_swap_tip());
    assert_eq!(
        m.state_modes().collect::<Vec<_>>(),
        [
            (KeyRef::Read(0), StateMode::Chain),
            (KeyRef::Write(0), StateMode::Chain)
        ]
    );
    let mut v = amm_swap_tip();
    v["state"]
        .as_object_mut()
        .unwrap()
        .remove("$state_keys.writes[0]");
    let m = tip(&v);
    assert_eq!(m.state_mode(KeyRef::Write(0)), Some(StateMode::Node));
    assert_eq!(m.state_mode(KeyRef::Fixed(FixedKey::NskApp)), None);
    assert_eq!(
        serde_json::from_value::<StateMode>(json!("chain")).unwrap(),
        StateMode::Chain
    );
}

#[test]
fn the_amm_tip_manifest_parses_and_round_trips() {
    let v = amm_swap_tip();
    let text = include_str!("../../../../../testvectors/manifests/amm_swap_tip.json");
    let m = parse_text(text).unwrap();
    assert_eq!(m, parse(&v).unwrap());
    assert!(m.queued());
    assert_eq!(m.circuit, "amm_swap_tip");
    // re-serialising leaves out only the empty `public_reads`
    let mut want = v.clone();
    assert_eq!(
        want.as_object_mut().unwrap().remove("public_reads"),
        Some(json!([]))
    );
    assert_eq!(serde_json::to_value(&m).unwrap(), want);

    assert_eq!(m.intake, Intake::Onchain);
    assert_eq!(m.binding(), Binding::Turn);
    assert_eq!(m.state_mode(KeyRef::Read(0)), Some(StateMode::Chain));
    assert_eq!(m.state_mode(KeyRef::Write(0)), Some(StateMode::Chain));
    assert_eq!(m.state_mode(KeyRef::Fixed(FixedKey::NskApp)), None);
    assert_eq!(
        m.commitment_slots().collect::<Vec<_>>(),
        [(
            &KeyRef::Read(0),
            &CommitmentSlot {
                old: "old_c".into()
            }
        )]
    );
    assert!(m.public_reads.is_empty() && m.consume().is_empty());
}

#[test]
fn a_queued_intake_reads_the_reserved_operands_and_direct_refuses_them() {
    let v = amm_swap_tip_receipt();
    let m = tip(&v);
    assert_eq!(
        m.reserved().collect::<Vec<_>>(),
        [
            ("vk_hash", ReservedOperand::VkHash),
            ("partial_note", ReservedOperand::PartialNote),
            ("user_nonce", ReservedOperand::UserNonce),
        ]
    );
    assert_eq!(
        m.witness_entry("user_nonce").unwrap().1.from,
        Source::Public(PublicSource::One(PublicOperand::Reserved(
            ReservedOperand::UserNonce
        )))
    );
    // they round-trip as written
    assert_eq!(
        Manifest::parse(&serde_json::to_value(&m).unwrap()).unwrap(),
        m
    );
    // the amm-tip on-chain intake manifest names the same three: one
    // circuit serves both non-secret-shared intakes
    assert_eq!(
        tip(&amm_swap_tip()).reserved().collect::<Vec<_>>(),
        m.reserved().collect::<Vec<_>>()
    );

    // intake direct refuses each, naming the entry and the intake
    for op in ["$vk_hash", "$user_nonce"] {
        let mut direct = amm_swap();
        direct["witness"][1]["from"] = json!({"PUBLIC": op});
        refused(
            direct,
            &format!(
                "field `witness[1].from.PUBLIC`: the reserved operand `{op}` needs a queued intake"
            ),
        );
    }
    let mut direct = amm_swap();
    direct["witness"][1]["from"] = json!({"PUBLIC": ["$user_nonce"]});
    refused(
        direct,
        "the reserved operand `$user_nonce` needs a queued intake",
    );
    // `$user` is refused under every intake (the hidden requester)
    for mut v in [amm_swap(), amm_swap_tip(), amm_swap_tip_receipt()] {
        v["witness"][1]["from"] = json!({"PUBLIC": "$user"});
        refused(v, "`$user` is refused under every intake");
    }
    // an unknown `$` name is still no reference
    let mut queued = amm_swap_tip_receipt();
    queued["witness"][7]["from"] = json!({"PUBLIC": "$sender"});
    refused(queued, "`$sender` is not a request reference");
}

#[test]
fn a_reserved_operand_fills_one_whole_parameter_once_under_its_own_name() {
    let cases: Vec<(Edit, &str)> = vec![
        // never an element of a list
        (
            |v| v["witness"][2]["from"] = json!({"PUBLIC": ["$user_nonce"]}),
            "field `witness[2].from.PUBLIC`: the reserved operand `$user_nonce` fills a whole parameter",
        ),
        // at most once
        (
            |v| v["witness"][9]["from"] = json!({"PUBLIC": "$user_nonce"}),
            "field `witness[9].from.PUBLIC`: `$user_nonce` fills two parameters",
        ),
        // the parameter's name is no request public name of the manifest
        (
            |v| v["witness"][5]["from"] = json!({"PUBLIC": "user_nonce"}),
            "parameter `user_nonce` is filled by `$user_nonce`, and `user_nonce` is also a request public name",
        ),
        // a pinned read fills a public name, never a reserved operand
        (
            |v| {
                v["public_reads"] = json!([{"contract": "0x1", "function": "f", "args": [],
                                            "param": "vk_hash"}])
            },
            "`vk_hash` (witness[1]) must be filled by PUBLIC with a request public name",
        ),
    ];
    for (edit, needle) in cases {
        let mut v = amm_swap_tip_receipt();
        edit(&mut v);
        refused(v, needle);
    }
}

#[test]
fn the_queued_defaults_apply_to_fields_left_out() {
    let mut v = amm_swap_tip();
    for field in ["binding", "state", "public_reads"] {
        v.as_object_mut().unwrap().remove(field);
    }
    let m = tip(&v);
    assert_eq!(m.binding(), Binding::Turn);
    assert!(m.state.is_empty());
    assert_eq!(m.state_mode(KeyRef::Read(0)), Some(StateMode::Node));
    assert_eq!(m.state_mode(KeyRef::Write(0)), Some(StateMode::Node));
    assert_eq!(m.state_mode(KeyRef::Read(1)), None);

    // the stale period is the contract manifest's: a circuit manifest
    // naming one is refused
    let mut v = amm_swap_tip();
    v["stale_blocks"] = json!(50);
    assert!(parse(&v).is_err());

    // the options REGISTER refuses still parse, so the schema keeps them
    let mut v = amm_swap_tip();
    v["binding"] = json!("exact");
    v["intake"] = json!("receipt");
    v["state"]["$state_keys.reads[0]"] = json!("node");
    let m = tip(&v);
    assert_eq!(m.binding(), Binding::Exact);
    assert_eq!(m.state_mode(KeyRef::Read(0)), Some(StateMode::Node));
    // and so do public reads under intake direct
    let mut v = amm_swap();
    v["public_reads"] = json!([{"contract": "0x1", "function": "get_price", "args": [],
                                "param": "amount_in"}]);
    assert_eq!(parse(&v).unwrap().public_reads.len(), 1);
}

#[test]
fn a_queued_manifest_refuses_malformed_and_unknown_fields() {
    let cases: Vec<(Edit, &str)> = vec![
        // unknown fields, at every level
        (
            |v| v["queue"] = json!("pool"),
            "field `queue`: unknown field `queue`",
        ),
        (|v| v["extra"] = json!(1), "unknown field `extra`"),
        (
            |v| v["commitment_slot"]["$state_keys.reads[0]"]["new"] = json!("new_c"),
            "field `commitment_slot.$state_keys.reads[0].new`: unknown field `new`",
        ),
        (
            |v| {
                v["public_reads"] = json!([{"contract": "0x1", "function": "f", "args": [],
                                            "param": "amount_in", "gas": 1}])
            },
            "unknown field `gas`",
        ),
        (
            |v| v["state_keys"]["deletes"] = json!(0),
            "field `state_keys.deletes`",
        ),
        (
            |v| v["outputs"][0]["shape"] = json!(1),
            "field `outputs[0].shape`: unknown field",
        ),
        (
            |v| v["witness"][3]["from"]["offset"] = json!(0),
            "field `witness[3].from.offset`: unknown field",
        ),
        // intake
        (|v| v["intake"] = json!("mempool"), "field `intake`"),
        (
            |v| {
                v.as_object_mut().unwrap().remove("intake");
            },
            "field `binding`: only with a queued intake; this manifest has intake direct",
        ),
        // binding
        (|v| v["binding"] = json!("loose"), "field `binding`"),
        (|v| v["binding"] = Value::Null, "field `binding`"),
        (
            |v| v["commitment_slot"] = Value::Null,
            "field `commitment_slot`",
        ),
        // stale_blocks is the contract manifest's
        (
            |v| v["stale_blocks"] = json!(50),
            "field `stale_blocks`: unknown field `stale_blocks`",
        ),
        // state
        (
            |v| v["state"]["$state_keys.reads[0]"] = json!("both"),
            "field `state.$state_keys.reads[0]`",
        ),
        (
            |v| v["state"]["nsk_app"] = json!("chain"),
            "field `state.nsk_app`",
        ),
        (
            |v| v["state"]["$state_keys.reads[1]"] = json!("chain"),
            "field `state.$state_keys.reads[1]`: $state_keys.reads[1] is out of range",
        ),
        // commitment_slot
        (
            |v| v["commitment_slot"]["$state_keys.reads[0]"] = json!("old_c"),
            "field `commitment_slot.$state_keys.reads[0]`",
        ),
        (
            |v| v["commitment_slot"]["$state_keys.reads[0]"] = json!({}),
            "missing field `old`",
        ),
        (
            |v| v["commitment_slot"]["$state_keys.reads[0]"]["old"] = json!(""),
            "field `commitment_slot.$state_keys.reads[0].old`: empty output name",
        ),
        (
            |v| v["commitment_slot"]["$state_keys.reads[0]"]["old"] = json!("new_c"),
            "field `commitment_slot.$state_keys.reads[0].old`: `new_c` is the new commitment of outputs[0]",
        ),
        (
            |v| v["commitment_slot"] = json!({"$state_keys.writes[0]": {"old": "old_c"}}),
            "field `commitment_slot.$state_keys.writes[0]`: $state_keys.writes[0] is not loaded",
        ),
        (
            |v| v["commitment_slot"]["nsk_app"] = json!({"old": "x"}),
            "field `commitment_slot.nsk_app`: the fixed key nsk_app has no commitment slot",
        ),
        (
            |v| v["commitment_slot"]["$state_keys.reads[2]"] = json!({"old": "x"}),
            "field `commitment_slot.$state_keys.reads[2]`: $state_keys.reads[2] is out of range",
        ),
        (
            |v| v["commitment_slot"]["$state_keys.read[0]"] = json!({"old": "x"}),
            "field `commitment_slot.$state_keys.read[0]`",
        ),
        (
            |v| v["commitment_slot"] = json!({}),
            "field `commitment_slot`: the chain-held key $state_keys.reads[0] is loaded but has no commitment slot",
        ),
        // public_reads
        (|v| v["public_reads"] = json!({}), "field `public_reads`"),
        (
            |v| {
                v["public_reads"] =
                    json!([{"contract": "0x1", "function": "get_price", "param": "amount_in"}])
            },
            "field `public_reads[0]`: missing field `args`",
        ),
        (
            |v| {
                v["public_reads"] = json!([{"contract": "0xzz", "function": "get_price",
                                            "args": [], "param": "amount_in"}])
            },
            "field `public_reads[0].contract`",
        ),
        (
            |v| {
                v["public_reads"] = json!([{"contract": "0x1", "function": "get_price",
                                            "args": ["price"], "param": "amount_in"}])
            },
            "field `public_reads[0].args[0]`",
        ),
        (
            |v| {
                v["public_reads"] = json!([{"contract": "0x1", "function": "get-price",
                                            "args": [], "param": "amount_in"}])
            },
            "field `public_reads[0].function`: `get-price` is not a function name",
        ),
        (
            |v| {
                v["public_reads"] = json!([{"contract": "0x1", "function": "get_price",
                                            "args": [], "param": "price"}])
            },
            "field `public_reads[0].param`: `price` is not a witness parameter",
        ),
        (
            |v| {
                v["public_reads"] = json!([{"contract": "0x1", "function": "get_price",
                                            "args": [], "param": "namespace"}])
            },
            "field `public_reads[0].param`: `namespace` is the namespace parameter",
        ),
        (
            |v| {
                v["public_reads"] = json!([{"contract": "0x1", "function": "get_price",
                                            "args": [], "param": "pool"}])
            },
            "field `public_reads[0].param`: `pool` (witness[9]) must be filled by PUBLIC with a request public name",
        ),
        (
            |v| {
                let read = json!({"contract": "0x1", "function": "get_price",
                                  "args": [], "param": "amount_in"});
                v["public_reads"] = json!([read.clone(), read]);
            },
            "field `public_reads[1].param`: `amount_in` is filled by two reads",
        ),
        // consume entries are a direct-intake field
        (
            |v| v["consume"] = json!([{"key": "$state_keys.reads[0]"}]),
            "field `consume`: only with intake direct",
        ),
        (
            |v| v["consume"] = json!([{"key": "$state_keys.reads[0]", "polcy": "once"}]),
            "field `consume[0].polcy`: unknown field",
        ),
        // the rules every manifest shares
        (
            |v| v["witness"][5]["from"] = json!({"SAMPLE": 0}),
            "field `witness[5].from.SAMPLE`",
        ),
        (
            |v| v["witness"][0]["from"] = json!({"PUBLIC": "ns"}),
            "must be filled by PUBLIC \"$namespace\"",
        ),
        (
            |v| v["outputs"][0]["STORE"] = json!("$state_keys.reads[0]"),
            "field `outputs[0].STORE`",
        ),
        (
            |v| v["witness"][4]["from"]["create"] = json!("SAMPLE"),
            "LOAD `create`",
        ),
        (|v| v["manifest"] = json!("1"), "field `manifest`"),
    ];
    let mut missed = Vec::new();
    for (edit, needle) in cases {
        let mut v = amm_swap_tip();
        edit(&mut v);
        match parse(&v) {
            Ok(_) => missed.push(format!("accepted, wanted `{needle}`")),
            Err(e) if e.class != ErrorClass::BadRequest || !e.message.contains(needle) => {
                missed.push(format!("`{}` lacks `{needle}`", e.message))
            }
            Err(_) => {}
        }
    }
    assert!(missed.is_empty(), "{}", missed.join("\n"));
    // A map key given twice, in the text.
    let text = include_str!("../../../../../testvectors/manifests/amm_swap_tip.json");
    for (map, once, twice) in [
        (
            "state",
            "\"$state_keys.reads[0]\": \"chain\"",
            "\"$state_keys.reads[0]\": \"chain\", \"$state_keys.reads[0]\": \"node\"",
        ),
        (
            "commitment_slot",
            "\"$state_keys.reads[0]\": { \"old\": \"old_c\" }",
            "\"$state_keys.reads[0]\": { \"old\": \"old_c\" }, \"$state_keys.reads[0]\": { \"old\": \"x\" }",
        ),
    ] {
        assert_eq!(text.matches(once).count(), 1, "{map}");
        let err = parse_json::<Manifest>(&text.replacen(once, twice, 1)).unwrap_err();
        assert!(
            err.message.contains(map) && err.message.contains("appears twice"),
            "{}",
            err.message
        );
    }
}
