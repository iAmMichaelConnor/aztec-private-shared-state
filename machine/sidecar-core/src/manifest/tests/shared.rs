//! Secret-shared intake and outcome tests: the reserved shared values and the
//! partial note.

use super::*;

/// `outcome` defaults to `partial` under every queued intake and is not
/// written back when left out; `none` round-trips; any other value, and
/// a `call_values` field, are refused by name.
#[test]
fn the_outcome_form_defaults_to_partial_under_every_queued_intake() {
    let m = tip(&shared_receipt_round());
    assert_eq!((m.outcome, m.outcome()), (None, Outcome::Partial));
    assert!(serde_json::to_value(&m).unwrap().get("outcome").is_none());
    let m = tip(&amm_swap_tip());
    assert_eq!((m.outcome, m.outcome()), (None, Outcome::Partial));
    // a round that completes no note says so
    let m = tip(&tip_tree());
    assert_eq!(m.outcome(), Outcome::None);
    assert_eq!(serde_json::to_value(&m).unwrap()["outcome"], json!("none"));
    for form in ["claim", "call", "push"] {
        let mut v = shared_receipt_round();
        v["outcome"] = json!(form);
        let err = Manifest::parse(&v).unwrap_err();
        assert!(
            err.message.contains("outcome") && err.message.contains(form),
            "{form}: {}",
            err.message
        );
    }
    let mut v = shared_receipt_round();
    v["call_values"] = json!(["call_values[0]"]);
    let err = Manifest::parse(&v).unwrap_err();
    assert!(
        err.message.contains("unknown field `call_values`"),
        "{}",
        err.message
    );
}

/// Under a non-secret-shared intake the default `partial` needs a
/// parameter filled by PUBLIC `$partial_note`: a manifest with neither
/// that parameter nor an `outcome` is refused, under the on-chain intake
/// and the receipt intake alike.
#[test]
fn a_non_secret_shared_manifest_without_a_partial_note_names_its_outcome() {
    for intake in ["onchain", "receipt"] {
        let mut v = tip_tree();
        v["intake"] = json!(intake);
        v.as_object_mut().unwrap().remove("outcome");
        refused(
            v.clone(),
            &format!("field `witness`: intake {intake}: no parameter takes PUBLIC `$partial_note`"),
        );
        v["outcome"] = json!("none");
        assert_eq!(tip(&v).outcome(), Outcome::None, "{intake}");
    }
}

/// The partial note's rules: `$partial_note` exactly once under a
/// secret-shared intake's partial form, INPUT_SHARED; no
/// `recipient`; a clear `$partial_note`
/// under a non-secret-shared intake, and none under `outcome: none`.
#[test]
fn the_partial_notes_come_with_the_partial_form() {
    let cases: Vec<(Edit, &str)> = vec![
        (
            |v| v["witness"][7]["from"] = json!({"INPUT_SHARED": "share"}),
            "field `witness`: intake shared_receipt: no parameter takes INPUT_SHARED `$partial_note`",
        ),
        (
            |v| v["witness"][6]["from"] = json!({"INPUT_SHARED": "$partial_note"}),
            "`$partial_note` fills two parameters",
        ),
        (
            |v| v["witness"][5]["from"] = json!({"INPUT_SHARED": "recipient"}),
            "field `witness[5].from.INPUT_SHARED`: `recipient` is refused under `outcome: partial`",
        ),
        (
            |v| v["witness"][6]["from"] = json!({"PUBLIC": "recipient"}),
            "field `witness[6].from.PUBLIC`: `recipient` is refused under `outcome: partial`",
        ),
        (
            |v| v["witness"][6]["from"] = json!({"PUBLIC": "$partial_note"}),
            "`$partial_note` is INPUT_SHARED under intake shared_receipt",
        ),
    ];
    for (edit, needle) in cases {
        let mut v = shared_receipt_round();
        edit(&mut v);
        refused(v, needle);
    }
    // `$refund_note` is no reserved name, shared or clear
    let mut v = shared_receipt_round();
    v["witness"][6]["from"] = json!({"INPUT_SHARED": "$refund_note"});
    refused(
        v,
        "field `witness[6].from.INPUT_SHARED`: `$refund_note` is not a reserved shared name",
    );
    let mut v = amm_swap_tip();
    v["witness"][6]["from"] = json!({"PUBLIC": "$refund_note"});
    refused(v, "`$refund_note` is not a request reference");
    // a non-secret-shared intake: a clear `$partial_note` under partial
    let mut v = amm_swap_tip();
    let m = tip(&v);
    assert_eq!(m.outcome(), Outcome::Partial);
    assert!(
        m.reserved()
            .any(|(p, r)| p == "partial_note" && r == ReservedOperand::PartialNote)
    );
    assert!(ReservedOperand::PartialNote.app_input() && !ReservedOperand::UserNonce.app_input());
    v["witness"][7] = json!({"param": "partial_note", "from": {"PUBLIC": "partial_note"}});
    refused(
        v.clone(),
        "field `witness`: intake onchain: no parameter takes PUBLIC `$partial_note`",
    );
    // and none under `outcome: none`
    let mut v = amm_swap_tip();
    v["outcome"] = json!("none");
    refused(
        v,
        "`$partial_note` belongs to `outcome: partial`; this manifest takes `outcome: none`",
    );
}

#[test]
fn a_shared_intake_manifest_parses_with_its_reserved_values() {
    for intake in ["shared_receipt", "shared_onchain"] {
        let mut v = shared_receipt_round();
        v["intake"] = json!(intake);
        let m = tip(&v);
        assert!(m.queued_intake().unwrap().shared(), "{intake}");
        assert_eq!(m.intake.as_str(), intake);
        assert_eq!(
            m.reserved().collect::<Vec<_>>(),
            [
                ("vk_hash", ReservedOperand::VkHash),
                ("inputs_hash", ReservedOperand::InputsHash),
            ]
        );
        // it round-trips as written
        assert_eq!(
            Manifest::parse(&serde_json::to_value(&m).unwrap()).unwrap(),
            m
        );
    }
    assert_eq!(
        SharedReserved::ALL.map(SharedReserved::as_str),
        ["$blinding", "$outcome_key", "$outcome_tag", "$partial_note"]
    );
    assert!(!SharedReserved::Blinding.committed());
    assert!(SharedReserved::OutcomeKey.committed() && SharedReserved::OutcomeTag.committed());
    assert!(!QueuedIntake::Onchain.shared() && !QueuedIntake::Receipt.shared());
}

#[test]
fn a_shared_intake_manifest_refuses_what_its_rules_exclude() {
    let cases: Vec<(Edit, &str)> = vec![
        // at least one INPUT_SHARED app input or a shared partial note:
        // `outcome: none` (which REGISTER refuses) with every app input
        // clear
        (
            |v| {
                v["witness"][5]["from"] = json!({"PUBLIC": "amount"});
                v["witness"][7] = json!({"param": "partial_note", "from": {"PUBLIC": "recipient"}});
                v["outcome"] = json!("none");
            },
            "field `witness`: intake shared_receipt needs at least one INPUT_SHARED app input or a shared `$partial_note`",
        ),
        // each reserved shared value exactly once
        (
            |v| v["witness"][9]["from"] = json!({"INPUT_SHARED": "blinding"}),
            "field `witness`: intake shared_receipt: no parameter takes INPUT_SHARED `$blinding`",
        ),
        (
            |v| v["witness"][8]["from"] = json!({"INPUT_SHARED": "key"}),
            "no parameter takes INPUT_SHARED `$outcome_key`",
        ),
        (
            |v| v["witness"][10]["from"] = json!({"INPUT_SHARED": "tag"}),
            "no parameter takes INPUT_SHARED `$outcome_tag`",
        ),
        (
            |v| v["witness"][7]["from"] = json!({"INPUT_SHARED": "$outcome_tag"}),
            "field `witness[10].from.INPUT_SHARED`: `$outcome_tag` fills two parameters",
        ),
        // PUBLIC `$inputs_hash`, once, as a whole parameter
        (
            |v| v["witness"][4]["from"] = json!({"PUBLIC": "c"}),
            "field `witness`: intake shared_receipt: no parameter takes PUBLIC `$inputs_hash`",
        ),
        (
            |v| v["witness"][6]["from"] = json!({"PUBLIC": "$inputs_hash"}),
            "field `witness[6].from.PUBLIC`: `$inputs_hash` fills two parameters",
        ),
        (
            |v| v["witness"][4]["from"] = json!({"PUBLIC": ["$inputs_hash"]}),
            "the reserved operand `$inputs_hash` fills a whole parameter",
        ),
        // no requester and no nonce
        (
            |v| v["witness"][6]["from"] = json!({"PUBLIC": "$user"}),
            "`$user` is refused under every intake",
        ),
        (
            |v| v["witness"][6]["from"] = json!({"PUBLIC": "$user_nonce"}),
            "field `witness[6].from.PUBLIC`: `$user_nonce` is refused under intake shared_receipt",
        ),
        // a `$` name under INPUT_SHARED is a reserved shared value or refused
        (
            |v| v["witness"][5]["from"] = json!({"INPUT_SHARED": "$amount"}),
            "field `witness[5].from.INPUT_SHARED`: `$amount` is not a reserved shared name",
        ),
        (
            |v| v["witness"][5]["from"] = json!({"INPUT_SHARED": "$inputs_hash"}),
            "`$inputs_hash` is not a reserved shared name",
        ),
    ];
    for (edit, needle) in cases {
        let mut v = shared_receipt_round();
        edit(&mut v);
        refused(v, needle);
    }
}

/// A round whose app inputs are all clear takes a secret-shared intake
/// when it completes a shared partial note (lending's view and scan):
/// the note's owner and the outcome stay hidden.
#[test]
fn a_shared_partial_note_is_enough_for_a_shared_intake() {
    let mut v = shared_receipt_round();
    v["witness"][5]["from"] = json!({"PUBLIC": "amount"});
    let m = tip(&v);
    assert_eq!(m.outcome(), Outcome::Partial);
}

#[test]
fn the_plain_intakes_and_direct_refuse_the_shared_values() {
    for intake in ["onchain", "receipt"] {
        let name = if intake == "onchain" {
            "on-chain intake"
        } else {
            "receipt intake"
        };
        let mut v = amm_swap_tip_receipt();
        v["intake"] = json!(intake);
        v["witness"][4]["from"] = json!({"INPUT_SHARED": "amount_in"});
        refused(
            v,
            &format!(
                "field `witness[4].from.INPUT_SHARED`: {name} takes no INPUT_SHARED source; shared inputs take secret-shared receipt intake or secret-shared on-chain intake"
            ),
        );
        for reserved in ["$blinding", "$outcome_key", "$outcome_tag"] {
            let mut v = amm_swap_tip_receipt();
            v["intake"] = json!(intake);
            v["witness"][4]["from"] = json!({"INPUT_SHARED": reserved});
            refused(
                v,
                &format!(
                    "field `witness[4].from.INPUT_SHARED`: `{reserved}` needs a secret-shared intake (shared_receipt or shared_onchain); this manifest has intake {intake}"
                ),
            );
        }
        let mut v = amm_swap_tip_receipt();
        v["intake"] = json!(intake);
        v["witness"][4]["from"] = json!({"PUBLIC": "$inputs_hash"});
        refused(
            v,
            &format!(
                "field `witness[4].from.PUBLIC`: `$inputs_hash` needs a secret-shared intake (shared_receipt or shared_onchain); this manifest has intake {intake}"
            ),
        );
    }
    // intake direct takes INPUT_SHARED app inputs (the sidecar path), but
    // none of the reserved shared values
    let m = parse(&amm_swap()).unwrap();
    assert_eq!(m.intake, Intake::Direct);
    let mut v = amm_swap();
    v["witness"][1]["from"] = json!({"INPUT_SHARED": "$blinding"});
    refused(
        v,
        "`$blinding` needs a secret-shared intake (shared_receipt or shared_onchain); this manifest has intake direct",
    );
}

/// The circuit name and every INPUT_SHARED name reach an envelope's
/// associated data by `poseidon2_hash_bytes`, which ignores zero bytes at the
/// end: each is 1 to 256 bytes of visible ASCII
/// ([`crate::schnorr::check_name`]), so `door` and `door\0` cannot be two
/// inputs that bind alike.
#[test]
fn the_names_a_binding_hashes_are_visible_ascii() {
    let long = "a".repeat(257);
    for (name, needle) in [
        ("door\0", "byte 0x00"),
        ("do or", "byte 0x20"),
        ("", "empty input name"),
        (long.as_str(), "longer than 256 bytes"),
    ] {
        let mut v = shared_receipt_round();
        v["witness"][5]["from"] = json!({"INPUT_SHARED": name});
        refused(v.clone(), "field `witness[5].from.INPUT_SHARED`: ");
        refused(v, needle);
        let mut v = shared_receipt_round();
        v["circuit"] = json!(name);
        refused(v, "field `circuit`: ");
    }
    let mut v = shared_receipt_round();
    v["witness"][5]["from"] = json!({"INPUT_SHARED": "a".repeat(256)});
    tip(&v);
}
