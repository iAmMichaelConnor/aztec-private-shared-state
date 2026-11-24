//! Secret-shared on-chain intake's vectors: testvectors/shared_onchain.json
//! and the Prover.toml of testvectors/noir/tip_onchain_vectors, which
//! pss-client's test/shared-onchain.test.ts and the Noir program read too;
//! and the check of testvectors/onchain_layouts.json, the kinds of every
//! secret-shared example round that `scripts/gen-intake.py --layouts` writes
//! from the manifests with each example's generated `layouts.nr`, against
//! what sidecar-tip derives from the compiled circuits.
//!
//! ```sh
//! cargo test -p sidecar-tip --test write_vectors write_shared_onchain_vectors -- --ignored
//! scripts/check-vectors.sh tip_onchain_vectors
//! ```

use std::fmt::Write as _;

use ark_std::rand::SeedableRng;
use ark_std::rand::rngs::StdRng;
use serde_json::{Value, json};
use sidecar_core::derived::{self, DerivedInput, Kind, node_share};
use sidecar_core::field::{FieldHex, Fr};
use sidecar_core::grumpkin::coordinates;
use sidecar_core::keys::{NodeKeys, label_field, scalar_to_hex};
use sidecar_core::manifest::QueuedIntake;
use sidecar_core::register::Signature;
use sidecar_core::request::NODES;
use sidecar_core::schnorr::verify;
use sidecar_core::store::PackageRow;
use sidecar_test_fixtures::dirs::repo;
use sidecar_test_fixtures::vectors::{hex, node_keys, read};
use sidecar_tip::TipPackage;
use sidecar_tip::chain::layout::siloed_private_log_tag;
use sidecar_tip::intake::shared_onchain::PSS_ENC_ROTATE_LABEL;
use sidecar_tip::testing::shared_onchain::{
    EPH, EPOCHS, enc_pks, node_with, rotation_scalar, the_request, values,
};
use sidecar_tip::{enc_rotation_message, onchain_layout, rotate_into};

const VECTORS: &str = "testvectors/shared_onchain.json";
const NOIR: &str = "testvectors/noir/tip_onchain_vectors";

fn fh(v: Fr) -> Value {
    json!(FieldHex(v))
}

fn fhs(v: &[Fr]) -> Value {
    json!(v.iter().copied().map(FieldHex).collect::<Vec<_>>())
}

fn shared_onchain_vectors() -> Value {
    let keys = node_keys();
    let r = the_request(&node_keys());
    let (secrets, _) = derived::key_exchange(hex(EPH), enc_pks(&keys));
    let log = r.shared_log();
    let pairs: Vec<Value> = (0..NODES)
        .map(|i| {
            let mut k = node_with(&node_keys()[i], r.ns, &[(EPOCHS[i], keys[i].enc_scalar())]);
            k = k.retire_previous_enc();
            json!(
                log.shared
                    .iter()
                    .map(|s| {
                        let p = node_share(&k, i, r.ns, &log, &s.name).unwrap();
                        json!({"name": s.name, "pair": fhs(&[p.a, p.b])})
                    })
                    .collect::<Vec<_>>()
            )
        })
        .collect();
    // node 1's rotation to epoch 3, signed as the node signs it
    let mut node1 = NodeKeys::from_scalars(rotation_scalar(), keys[1].sig_scalar()).unwrap();
    let signature = rotate_into(&mut node1, 1, r.ns, 3, &mut StdRng::seed_from_u64(31)).unwrap();
    let (pk_x, pk_y) = coordinates(node1.enc_pk());
    let kinds: Vec<Value> = r
        .layout
        .commitment
        .kinds
        .iter()
        .map(|(n, k)| {
            json!({"name": n, "kind": match k {
                Kind::Clear => "clear",
                Kind::Chosen => "chosen",
            }})
        })
        .collect();
    let vals = values();
    json!({
        "comment": "Secret-shared on-chain intake (docs/ARCHITECTURE.md section 6): the derived intake shares of one request of testvectors/manifests/shared_onchain_round.json under the nodes' enc keys of testvectors/keys.json at epochs [2, 2, 1], its request log and data hash, each node's pair of every shared value, and node 1's signed enc key rotation to epoch 3. Written by sidecar-tip tests/write_vectors (write_shared_onchain_vectors); read by sidecar-tip, pss-client test/shared-onchain.test.ts and testvectors/noir/tip_onchain_vectors.",
        "sidecar_intake_prf": fh(derived::sidecar_intake_prf()),
        "pss_enc_rotate": fh(label_field(PSS_ENC_ROTATE_LABEL)),
        "namespace": fh(r.ns),
        "vk_hash": fh(r.pkg.vk_hash),
        "kinds": kinds,
        "values": vals.iter().map(|(n, v)| json!({"name": n, "value": fh(*v)})).collect::<Vec<_>>(),
        "eph": fh(hex(EPH)),
        "node_enc": keys.iter().map(|k| json!(scalar_to_hex(k.enc_scalar()))).collect::<Vec<_>>(),
        "node_enc_pk": keys.iter().map(|k| {
            let (x, y) = coordinates(k.enc_pk());
            json!({"x": FieldHex(x), "y": FieldHex(y)})
        }).collect::<Vec<_>>(),
        "epochs": EPOCHS,
        "epochs_packed": fh(derived::pack_epochs(EPOCHS)),
        "secrets": fhs(&secrets),
        "eph_x": fh(r.encoding.eph_x),
        "wraps": fhs(&r.encoding.wraps),
        "blinding": fh(r.encoding.blinding),
        "clear": fhs(&r.encoding.clear),
        "corrections": fhs(&r.encoding.corrections),
        "inputs_commitment": fh(r.c),
        "chain_request_id": fh(r.id),
        "tag": fh(r.tag),
        "siloed_tag": fh(siloed_private_log_tag(r.ns, r.tag)),
        "log": fhs(&r.log),
        "data_hash": fh(derived::data_hash(&r.log)),
        "shared": json!(r.layout.shared),
        "pairs": pairs,
        "rotation": {
            "node": 1,
            "pk": {"x": FieldHex(pk_x), "y": FieldHex(pk_y)},
            "epoch": 3,
            "message": fh(enc_rotation_message(r.ns, 1, (pk_x, pk_y), 3)),
            "signature": signature,
        },
    })
}

fn s(v: &Value) -> String {
    format!(
        "\"{}\"",
        v.as_str().unwrap_or_else(|| panic!("{v} is not a string"))
    )
}

fn list(v: &Value) -> String {
    let items: Vec<String> = v.as_array().unwrap().iter().map(s).collect();
    format!("[{}]", items.join(", "))
}

/// Prover.toml of testvectors/noir/tip_onchain_vectors.
fn prover_toml(v: &Value) -> String {
    let mut out = String::from(
        "# Written by sidecar-tip tests/write_vectors (write_shared_onchain_vectors) from testvectors/shared_onchain.json and keys.json.\n",
    );
    let kind = |k: &Value| match k["kind"].as_str().unwrap() {
        "clear" => 0,
        "chosen" => 1,
        other => panic!("kind {other}"),
    };
    let kinds: Vec<String> = v["kinds"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| kind(k).to_string())
        .collect();
    writeln!(out, "kinds = [{}]", kinds.join(", ")).unwrap();
    let values: Vec<Value> = v["values"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x["value"].clone())
        .collect();
    writeln!(out, "values = {}", list(&json!(values))).unwrap();
    for f in [
        "sidecar_intake_prf",
        "pss_enc_rotate",
        "namespace",
        "vk_hash",
        "eph",
        "epochs_packed",
        "eph_x",
        "blinding",
        "inputs_commitment",
        "chain_request_id",
        "tag",
        "siloed_tag",
        "data_hash",
    ] {
        writeln!(out, "{f} = {}", s(&v[f])).unwrap();
    }
    writeln!(out, "node_enc = {}", list(&v["node_enc"])).unwrap();
    let epochs: Vec<String> = v["epochs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e.to_string())
        .collect();
    writeln!(out, "epochs = [{}]", epochs.join(", ")).unwrap();
    for f in ["secrets", "wraps", "clear", "corrections", "log"] {
        writeln!(out, "{f} = {}", list(&v[f])).unwrap();
    }
    // pairs[i][j] flattened node by node: [a, b] per shared value
    let mut pairs = Vec::new();
    for node in v["pairs"].as_array().unwrap() {
        for p in node.as_array().unwrap() {
            pairs.extend(p["pair"].as_array().unwrap().iter().cloned());
        }
    }
    writeln!(out, "pairs = {}", list(&json!(pairs))).unwrap();
    let corr: Vec<String> = v["shared"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| d["correction"].as_u64().unwrap_or(0).to_string())
        .collect();
    writeln!(out, "correction_at = [{}]", corr.join(", ")).unwrap();
    let rot = &v["rotation"];
    writeln!(out, "\n[rotation]").unwrap();
    writeln!(out, "node = {}", rot["node"]).unwrap();
    writeln!(
        out,
        "x = {}\ny = {}",
        s(&rot["pk"]["x"]),
        s(&rot["pk"]["y"])
    )
    .unwrap();
    writeln!(out, "epoch = {}", rot["epoch"]).unwrap();
    writeln!(out, "message = {}", s(&rot["message"])).unwrap();
    let sig = &rot["signature"];
    writeln!(
        out,
        "signature = [{}, {}, {}, {}]",
        s(&sig["s"][0]),
        s(&sig["s"][1]),
        s(&sig["e"][0]),
        s(&sig["e"][1])
    )
    .unwrap();
    let pk = &read("testvectors/keys.json")["nodes"][1]["sig_pk"];
    writeln!(out, "sig_x = {}\nsig_y = {}", s(&pk["x"]), s(&pk["y"])).unwrap();
    out
}

/// `cargo test -p sidecar-tip write_shared_onchain_vectors -- --ignored`:
/// rewrites testvectors/shared_onchain.json and the Noir program's
/// Prover.toml.
#[test]
#[ignore = "writes testvectors/; run on purpose"]
fn write_shared_onchain_vectors() {
    let v = shared_onchain_vectors();
    std::fs::write(
        repo().join(VECTORS),
        serde_json::to_string_pretty(&v).unwrap() + "\n",
    )
    .unwrap();
    std::fs::create_dir_all(repo().join(NOIR)).unwrap();
    std::fs::write(repo().join(NOIR).join("Prover.toml"), prover_toml(&v)).unwrap();
}

/// The committed vectors and Prover.toml are what this code computes; the
/// signed rotation verifies under node 1's `sig` key; the layout is the
/// manifest's.
#[test]
fn the_vector_files_match() {
    let committed = read(VECTORS);
    assert_eq!(
        committed,
        shared_onchain_vectors(),
        "rerun write_shared_onchain_vectors"
    );
    let toml = std::fs::read_to_string(repo().join(NOIR).join("Prover.toml")).unwrap();
    assert_eq!(
        toml,
        prover_toml(&committed),
        "rerun write_shared_onchain_vectors"
    );
    let rot = &committed["rotation"];
    let sig: Signature = serde_json::from_value(rot["signature"].clone()).unwrap();
    assert!(verify(
        node_keys()[1].sig_pk(),
        sig,
        hex(rot["message"].as_str().unwrap())
    ));
    let r = the_request(&node_keys());
    assert_eq!(
        r.layout.shared,
        [
            DerivedInput {
                name: "amount".into(),
                correction: Some(7)
            },
            DerivedInput {
                name: "$partial_note".into(),
                correction: Some(8)
            },
            DerivedInput {
                name: "$outcome_key".into(),
                correction: Some(9)
            },
            DerivedInput {
                name: "$outcome_tag".into(),
                correction: Some(10)
            },
            DerivedInput {
                name: "$blinding".into(),
                correction: None
            },
        ]
    );
    assert_eq!(r.layout.commitment.clear(), 1);
    // every shared value is the user's, one correction each
    assert_eq!(r.encoding.corrections.len(), 4);
}

// ---- the IntakeSource ----

const LAYOUTS: &str = "testvectors/onchain_layouts.json";

/// One round of testvectors/onchain_layouts.json, which
/// `scripts/gen-intake.py --layouts` writes from every example manifest
/// under a secret-shared intake: its example, its manifest, the compiled
/// circuit it registers, the contract global its request function passes
/// (`layout`, declared in the generated file `layouts`) and the committed
/// entry.
struct ExampleRound {
    example: String,
    manifest: String,
    circuit: String,
    layout: String,
    layouts: String,
    entry: Value,
}

/// Every round of the committed testvectors/onchain_layouts.json, in its
/// order.
fn example_rounds() -> Vec<ExampleRound> {
    let field = |entry: &Value, key: &str| -> String {
        entry[key]
            .as_str()
            .unwrap_or_else(|| panic!("{LAYOUTS}: a round without `{key}`: {entry}"))
            .to_string()
    };
    read(LAYOUTS)["rounds"]
        .as_array()
        .unwrap_or_else(|| panic!("{LAYOUTS}: no rounds"))
        .iter()
        .map(|entry| ExampleRound {
            example: field(entry, "example"),
            manifest: field(entry, "manifest"),
            circuit: field(entry, "circuit"),
            layout: field(entry, "layout"),
            layouts: field(entry, "layouts"),
            entry: entry.clone(),
        })
        .collect()
}

/// The encoding's number of each kind, as the Noir `Layout` writes it.
fn kind_code(kind: Kind) -> u8 {
    match kind {
        Kind::Clear => 0,
        Kind::Chosen => 1,
    }
}

/// The package of `round` on its compiled circuit, or `None` (with a
/// message) when `scripts/check-noir.sh examples/<example>` has not been run;
/// panics naming the artifact when it is older than its source.
fn example_package(round: &ExampleRound) -> Option<TipPackage> {
    use sidecar_core::testing::artifacts;
    let path = artifacts::compiled(&round.example, &round.circuit);
    let package = artifacts::package(&round.example, &round.circuit);
    let refresh = format!("scripts/check-noir.sh examples/{}", round.example);
    if !artifacts::usable(&path, &package, &refresh) {
        return None;
    }
    let manifest = read(&round.manifest);
    let row = PackageRow {
        name: manifest["circuit"].as_str().unwrap().into(),
        manifest_hash: Fr::from(0u64),
        circuit_json: std::fs::read(&path).unwrap(),
        manifest,
        vk: vec![],
        vk_hash: Fr::from(0x7e57u64),
        disabled: false,
        seq: 1,
    };
    Some(TipPackage::from_row(&row, Some(50)).unwrap().unwrap())
}

/// The layout of `round` as `onchain_layout` derives it from its manifest
/// and its compiled circuit's ABI, in the vector's fields (names, kinds,
/// clear count, corrections). The layout is the same under both
/// secret-shared intakes: under receipt intake it is the order of the
/// sharing's summand vectors (`summand_names`).
fn derived_layout(round: &ExampleRound, pkg: &TipPackage) -> Value {
    let layout = onchain_layout(&pkg.shape, &pkg.tip);
    assert!(
        matches!(
            pkg.tip.intake(),
            QueuedIntake::SharedReceipt | QueuedIntake::SharedOnchain
        ),
        "{} is not under a secret-shared intake",
        round.manifest
    );
    json!({
        "names": layout.commitment.kinds.iter().map(|(n, _)| n.clone()).collect::<Vec<_>>(),
        "kinds": layout.commitment.kinds.iter().map(|(_, k)| kind_code(*k)).collect::<Vec<_>>(),
        "clear": layout.commitment.clear(),
        "corrections": layout.corrections(),
    })
}

/// The `*_LAYOUT` globals each function of `path` (an example contract's
/// `main.nr`) names in its body, comments left out, by function name.
fn function_layouts(path: &str) -> Vec<(String, Vec<String>)> {
    let text = std::fs::read_to_string(repo().join(path)).unwrap_or_else(|e| panic!("{path}: {e}"));
    let mut out = Vec::new();
    for chunk in text.split("\n    fn ").skip(1) {
        let name = chunk.split('(').next().unwrap().trim().to_string();
        let body = &chunk[..chunk.find("\n    }\n").unwrap_or(chunk.len())];
        let code: String = body
            .lines()
            .map(|l| l.split("//").next().unwrap())
            .collect::<Vec<_>>()
            .join("\n");
        let mut layouts: Vec<String> = code
            .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .filter(|w| w.ends_with("_LAYOUT") && !w.chars().any(|c| c.is_ascii_lowercase()))
            .map(String::from)
            .collect();
        layouts.sort();
        layouts.dedup();
        out.push((name, layouts));
    }
    out
}

/// The `src/main.nr` of every contract package of the example whose
/// layouts file is `layouts` (`examples/<example>/contract/<package>/src/layouts.nr`,
/// the one app contract's or the library its contracts share), by
/// repository path.
fn contract_mains(layouts: &str) -> Vec<String> {
    let at = layouts
        .find("/contract/")
        .unwrap_or_else(|| panic!("{layouts}: not under an example's contract/"));
    let dir = &layouts[..at + "/contract/".len()];
    let mut mains: Vec<String> = std::fs::read_dir(repo().join(dir))
        .unwrap_or_else(|e| panic!("{dir}: {e}"))
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .filter(|pkg| {
            std::fs::read_to_string(repo().join(dir).join(pkg).join("Nargo.toml"))
                .is_ok_and(|t| t.contains("type = \"contract\""))
        })
        .map(|pkg| format!("{dir}{pkg}/src/main.nr"))
        .collect();
    mains.sort();
    mains
}

/// Each example contract's request functions pass one generated `Layout`
/// global each, a round's: a function that named two could hand a request
/// the layout of another round of the same length.
#[test]
fn each_request_function_passes_one_rounds_layout() {
    let rounds = example_rounds();
    let mut contracts: Vec<&str> = rounds.iter().map(|r| r.layouts.as_str()).collect();
    contracts.sort();
    contracts.dedup();
    assert!(!contracts.is_empty(), "{LAYOUTS}: no example round");
    for layouts in contracts {
        let known: Vec<&str> = rounds
            .iter()
            .filter(|r| r.layouts == layouts)
            .map(|r| r.layout.as_str())
            .collect();
        let mut passed = 0;
        for main in contract_mains(layouts) {
            for (name, named) in function_layouts(&main) {
                assert!(
                    named.len() <= 1,
                    "{main}: `fn {name}` names the Layout globals {named:?}"
                );
                for layout in &named {
                    assert!(
                        known.contains(&layout.as_str()),
                        "{main}: `fn {name}` names {layout}, no round's layout in {layouts}"
                    );
                    passed += 1;
                }
            }
        }
        assert!(
            passed > 0,
            "{layouts}: no contract function passes a round's layout"
        );
    }
}

/// The committed layouts are what `onchain_layout` derives from each
/// example round's manifest and compiled circuit (when compiled), every
/// example manifest under a secret-shared intake has its round, and each
/// round's global is declared in its generated file; the AMM swap's six
/// shared values are chosen (its outcome key and tag derived per request),
/// the opening deposit's position clear and the rest chosen.
#[test]
fn the_example_rounds_layouts_match() {
    let committed = read(LAYOUTS);
    let rounds = committed["rounds"].as_array().unwrap();
    let expected = example_rounds();
    for round in &expected {
        if let Some(pkg) = example_package(round) {
            let derived = derived_layout(round, &pkg);
            for key in ["names", "kinds", "clear", "corrections"] {
                assert_eq!(
                    round.entry[key], derived[key],
                    "{}: `{key}` is not what onchain_layout derives from the compiled circuit; \
                     rerun scripts/gen-intake.py --layouts",
                    round.manifest
                );
            }
        }
        let text = std::fs::read_to_string(repo().join(&round.layouts))
            .unwrap_or_else(|e| panic!("{}: {e}", round.layouts));
        let declared = format!("pub global {}: Layout<", round.layout);
        assert_eq!(
            text.matches(&declared).count(),
            1,
            "{} does not declare `{}` exactly once ({})",
            round.layouts,
            round.layout,
            round.manifest
        );
    }
    // every example manifest under a secret-shared intake is a round here
    let mut shared: Vec<String> = Vec::new();
    for example in std::fs::read_dir(repo().join("examples")).unwrap() {
        let example = example.unwrap().file_name().into_string().unwrap();
        let Ok(manifests) =
            std::fs::read_dir(repo().join("examples").join(&example).join("manifests"))
        else {
            continue;
        };
        for m in manifests {
            let name = m.unwrap().file_name().into_string().unwrap();
            if !name.ends_with(".json") {
                continue;
            }
            let path = format!("examples/{example}/manifests/{name}");
            if matches!(
                read(&path)["intake"].as_str(),
                Some("shared_receipt" | "shared_onchain")
            ) {
                shared.push(path);
            }
        }
    }
    shared.sort();
    let mut listed: Vec<String> = expected.iter().map(|r| r.manifest.clone()).collect();
    listed.sort();
    assert_eq!(listed, shared, "rerun scripts/gen-intake.py --layouts");
    let round = |manifest: &str| -> &Value {
        rounds
            .iter()
            .find(|r| r["manifest"].as_str().unwrap().ends_with(manifest))
            .unwrap_or_else(|| panic!("no round of {manifest}"))
    };
    let kinds = |r: &Value| -> Vec<u64> {
        r["kinds"]
            .as_array()
            .unwrap()
            .iter()
            .map(|k| k.as_u64().unwrap())
            .collect()
    };
    let swap = round("/amm_swap_tip_shared_onchain.json");
    assert_eq!(kinds(swap), [1, 1, 1, 1, 1, 1]);
    assert_eq!(
        (swap["clear"].as_u64(), swap["corrections"].as_u64()),
        (Some(0), Some(6))
    );
    // lending's deposit: the clear position, then the amount, the owner's
    // delivery handle (two values) and the reserved three, chosen
    let deposit = round("/deposit_shared_onchain.json");
    assert_eq!(kinds(deposit), [0, 1, 1, 1, 1, 1, 1]);
    assert_eq!(
        (deposit["clear"].as_u64(), deposit["corrections"].as_u64()),
        (Some(1), Some(6))
    );
    // a round under both intakes has one layout
    assert_eq!(kinds(round("/amm_swap_tip_shared.json")), kinds(swap));
    assert_eq!(kinds(round("/deposit_shared.json")), kinds(deposit));
    assert_eq!(
        committed["kinds"],
        json!({"clear": kind_code(Kind::Clear), "chosen": kind_code(Kind::Chosen)})
    );
}
