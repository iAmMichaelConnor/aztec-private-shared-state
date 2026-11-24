//! Reads the files of testvectors/ and checks them against sidecar-core: the
//! values a client and a node exchange (AE, keys, envelopes, records, signed
//! bodies, result and registry messages, field-hex spellings) are the bytes
//! these functions produce and accept, and the example circuits' note-hash
//! indices and vk hashes (shapes.json) are the ones REGISTER computes.
//! pss-client's tests read the same files. tip_results.json, the chain-held
//! results, is read against sidecar-tip by its `tests/vectors.rs`.
//! The files are written by tests/write_vectors.rs and the ignored writer
//! tests of the ae, keys, envelope and registry modules, and of sidecar-tip's ids,
//! receipt and vectors modules (chain_request_id.json, receipts.json,
//! receipt_route.json, tip_results.json, slot_commitment.json), and of
//! sidecar-core's tree module (tip_tree.json).
//!
//! ```sh
//! cargo test --release -p sidecar-core --test vectors
//! ```

use std::collections::BTreeMap;
use std::path::PathBuf;

use ark_ff::{BigInteger, One, PrimeField};
use noirc_abi::Abi;
use serde_json::Value;
use sidecar_core::abi::check_manifest_value;
use sidecar_core::ae;
use sidecar_core::bind::{Elem, Share};
use sidecar_core::crs::{self, Artifact, Circuit, Crs};
use sidecar_core::envelope::{EnvelopeAd, open_envelope, seal_envelope_with};
use sidecar_core::field::{FieldHex, Fr, HexBytes, RequestId, fr_from_hex, fr_to_hex};
use sidecar_core::grumpkin::{
    coordinates, npk_app, npk_app_hash, nsk_app_derive_public, point_from_wire, point_to_wire,
    scalar_from_field, scalar_to_limbs,
};
use sidecar_core::hash::{poseidon2_hash, poseidon2_hash_with_separator};
use sidecar_core::keys::{SIDECAR_SEAL_KEY, key_id, label_field, record_key, scalar_from_hex};
use sidecar_core::manifest::contract::manifest_hash;
use sidecar_core::pipeline::{RESULT_DOMAIN, result_message, sealed_hash};
use sidecar_core::record::{
    self, SIDECAR_RECORD_AD, associated_data, encode_elements, key_hash, record_hash,
};
use sidecar_core::register::{
    DisableRequest, DisableResponse, ManifestMessage, ManifestResponse, NamespaceResponse,
};
use sidecar_core::registry::{
    MANIFEST_DOMAIN, REGISTRY_DOMAIN, Signed, manifest_message, registry_message,
};
use sidecar_core::request::{Full, NODES, Request, canonical_body};
use sidecar_core::response::NodesResponse;
use sidecar_core::schnorr::{
    DISABLE_DOMAIN, EXECUTE_DOMAIN, REGISTER_DOMAIN, canonical_json, message_for,
    poseidon2_hash_bytes, public_key, signature_from_bytes, verify_wire,
};
use sidecar_test_fixtures::dirs::repo;
use sidecar_test_fixtures::vectors::{fields, hex_value, node_keys, point, signature, vector};

fn hex(value: Fr) -> Value {
    Value::String(fr_to_hex(value))
}

/// Every vector file has a reader here; a new file must get one.
#[test]
fn every_vector_file_is_read() {
    let mut names: Vec<String> = std::fs::read_dir(repo().join("testvectors"))
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .filter(|n| n.ends_with(".json"))
        .collect();
    names.sort();
    assert_eq!(
        names,
        [
            "ae.json",
            "bodies.json",
            "chain_request_id.json",
            // read by sidecar-core's manifest::contract tests (pss-client and
            // scripts/check-manifests.py read it too)
            "contract_manifest.json",
            "envelope.json",
            // read by pss_core and pss-client (the machine's library never
            // computes an exit tag; the orchestrator's lending tests check theirs)
            "exit_tag.json",
            "field_hex.json",
            "keys.json",
            "log_tags.json",
            // written and read by sidecar-oblivious's layout tests (pss-client
            // reads it too)
            "manifest_limits.json",
            "npk_app_hash.json",
            // written and read by sidecar-tip's intake_shared_onchain tests (the
            // examples' Noir tests and pss-client read it too)
            "onchain_layouts.json",
            // read by pss_core and pss-client (the machine's library never
            // opens an outcome; the orchestrator's tip tests check their opener)
            "outcome.json",
            // written by sidecar-tip's layout.rs (pss-client and the Noir
            // intake program read it too)
            "queue.json",
            "receipt_route.json",
            "receipts.json",
            "records.json",
            "registry.json",
            "results.json",
            "schnorr.json",
            "secret_store.json",
            "shapes.json",
            "shared_intake.json",
            "shared_onchain.json",
            "slot_commitment.json",
            // read by sidecar-tip's tests/vectors.rs (and pss-client)
            "tip_results.json",
            "tip_tree.json",
        ],
        "add a reader for the new vector file to this test suite and to pss-client's"
    );
}

/// The compiled circuits of shapes.json and a CRS for the largest, when
/// scripts/prepare-data.sh has put them under DATA_DIR (default machine/data);
/// `None` when it has not, a failure under `PSS_REQUIRE_DATA=1`.
fn compiled_circuits(names: &[&str]) -> Option<BTreeMap<String, Circuit>> {
    let data = sidecar_test_fixtures::dirs::data_dir();
    let paths: Vec<PathBuf> = names
        .iter()
        .map(|n| data.join("circuits").join(format!("{n}.json")))
        .collect();
    let (g1, g2) = (data.join("bn254_g1.dat"), data.join("bn254_g2.dat"));
    if let Some(missing) = paths.iter().chain([&g1, &g2]).find(|p| !p.exists()) {
        sidecar_core::testing::artifacts::missing(format!(
            "shapes.json: {} is missing, so the vk fields are checked against their hash \
             only; run scripts/prepare-data.sh (or set DATA_DIR)",
            missing.display()
        ));
        return None;
    }
    let artifacts: Vec<Artifact> = paths.iter().map(|p| Artifact::read(p).unwrap()).collect();
    let crs = Crs::read(&g1, &g2, crs::crs_circuit_size(&artifacts)).unwrap();
    Some(
        artifacts
            .into_iter()
            .map(|a| {
                let c = Circuit::new(a, &crs.prover).unwrap();
                (c.name.clone(), c)
            })
            .collect(),
    )
}

/// Every example circuit's note-hash indices are what REGISTER's manifest
/// check computes from the ABI and manifest, and its vk hash is poseidon2 over
/// the vk fields; with the compiled circuits at hand, the fields and the hash
/// are also the ones the node derives from the artifact with the CRS.
#[test]
fn shapes_json() {
    let file = vector("shapes.json");
    let entries = file["circuits"].as_array().unwrap();
    let listed: Vec<(&str, &str)> = entries
        .iter()
        .map(|e| {
            (
                e["example"].as_str().unwrap(),
                e["circuit"].as_str().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        listed,
        [
            ("examples/amm", "pss_seed"),
            ("examples/amm", "amm_init"),
            ("examples/amm", "amm_swap"),
            ("examples/monty-hall", "pss_seed"),
            ("examples/monty-hall", "monty_hall_init"),
            ("examples/monty-hall", "monty_hall_open_door"),
            ("examples/monty-hall", "monty_hall_finish"),
        ]
    );
    let mut names: Vec<&str> = listed.iter().map(|(_, n)| *n).collect();
    names.sort();
    names.dedup();
    let compiled = compiled_circuits(&names);
    for e in entries {
        let name = e["circuit"].as_str().unwrap();
        let manifest_path = e["manifest"].as_str().unwrap();
        assert_eq!(
            manifest_path,
            format!("{}/manifests/{name}.json", e["example"].as_str().unwrap())
        );
        let abi: Abi = serde_json::from_value(e["abi"].clone()).unwrap();
        let (_, shape) =
            check_manifest_value(&sidecar_test_fixtures::vectors::read(manifest_path), &abi)
                .unwrap_or_else(|err| panic!("{manifest_path}: {err}"));
        let outputs: Vec<(String, usize)> = shape
            .outputs
            .iter()
            .map(|o| (o.note_hash.clone(), o.note_hash_index))
            .collect();
        let want: Vec<(String, usize)> = e["outputs"]
            .as_array()
            .unwrap()
            .iter()
            .map(|o| {
                (
                    o["note_hash"].as_str().unwrap().to_string(),
                    o["note_hash_index"].as_u64().unwrap() as usize,
                )
            })
            .collect();
        assert_eq!(outputs, want, "{name}: note-hash indices");
        assert_eq!(
            shape.public_param_fields as u64,
            e["public_param_fields"].as_u64().unwrap(),
            "{name}"
        );
        assert_eq!(
            shape.public_input_count as u64,
            e["public_input_count"].as_u64().unwrap(),
            "{name}"
        );
        let vk_fields = fields(&e["vk_fields"]);
        assert_eq!(vk_fields.len(), 115, "{name}: vk fields");
        assert_eq!(
            poseidon2_hash(&vk_fields),
            hex_value(&e["vk_hash"]),
            "{name}: vk hash"
        );
        if let Some(compiled) = &compiled {
            let circuit = &compiled[name];
            // the artifact as prepared under DATA_DIR (shapes.json names its
            // place under the default machine/data)
            assert_eq!(
                e["artifact"].as_str().unwrap(),
                format!("machine/data/circuits/{name}.json")
            );
            let artifact = sidecar_test_fixtures::data::circuit_json(name);
            assert_eq!(artifact["abi"], e["abi"], "{name}: the artifact's ABI");
            assert_eq!(
                circuit.vk.to_field_elements(),
                vk_fields,
                "{name}: vk fields"
            );
            assert_eq!(
                sidecar_core::hash::vk_hash(&circuit.vk),
                hex_value(&e["vk_hash"]),
                "{name}: vk hash"
            );
            assert_eq!(
                circuit.public_input_count(),
                shape.public_input_count,
                "{name}"
            );
        }
    }
    // pss-client's vk fixture (ts/test-support/fixtures/pss_seed.vk.json) is
    // bb's key for the same pss_seed
    let pss_seed = &entries[0];
    assert_eq!(
        pss_seed["vk_hash"],
        "0x255a24297767ccd4fea94c6bfcc2aec6057adb3433a6fc6d16da2883e2b5a3d6"
    );
}

#[test]
fn ae_json() {
    let file = vector("ae.json");
    let vectors = file["vectors"].as_array().unwrap();
    let lengths: Vec<u64> = vectors.iter().map(|v| v["n"].as_u64().unwrap()).collect();
    assert_eq!(lengths, [1, 2, 3, 4, 7, 10]);
    for v in vectors {
        let n = v["n"].as_u64().unwrap() as usize;
        let (key, nonce, plaintext) = (
            hex_value(&v["key"]),
            hex_value(&v["nonce"]),
            fields(&v["plaintext"]),
        );
        assert_eq!(plaintext.len(), n);
        if n > 1 {
            // The inputs rule of the file.
            let n_f = Fr::from(n as u64);
            assert_eq!(key, poseidon2_hash(&[Fr::from(1u64), n_f]));
            assert_eq!(nonce, poseidon2_hash(&[Fr::from(2u64), n_f]));
            for (j, p) in plaintext.iter().enumerate() {
                assert_eq!(
                    *p,
                    poseidon2_hash(&[Fr::from(3u64), n_f, Fr::from(j as u64)])
                );
            }
        }
        assert_eq!(hex(ae::pattern_tag(n)), v["pattern_tag"], "n = {n}");
        let (ct, tag) = ae::encrypt(key, nonce, &plaintext);
        assert_eq!(ct, fields(&v["ciphertext"]), "n = {n}");
        assert_eq!(hex(tag), v["tag"], "n = {n}");
        assert_eq!(ae::decrypt(key, nonce, &ct, tag).unwrap(), plaintext);
        assert!(ae::decrypt(key, nonce + Fr::one(), &ct, tag).is_err());
        assert!(ae::decrypt(key, nonce, &ct, tag + Fr::one()).is_err());
    }
}

#[test]
fn keys_json() {
    let file = vector("keys.json");
    assert_eq!(hex(label_field(SIDECAR_SEAL_KEY)), file["sidecar_seal_key"]);
    for (i, (n, keys)) in file["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .zip(node_keys())
        .enumerate()
    {
        assert_eq!(n["node"], i);
        let (lo, hi) = scalar_to_limbs(keys.enc_scalar());
        assert_eq!(
            (hex(lo), hex(hi)),
            (n["enc_limbs"]["lo"].clone(), n["enc_limbs"]["hi"].clone())
        );
        assert_eq!(point_to_wire(keys.enc_pk()), point(&n["enc_pk"]));
        assert_eq!(point_to_wire(keys.sig_pk()), point(&n["sig_pk"]));
        assert_eq!(hex(record_key(keys.enc_scalar())), n["record_key"]);
        let id: String = key_id(keys.enc_pk())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(format!("0x{id}"), n["key_id"]);
    }
}

#[test]
fn envelope_json() {
    let file = vector("envelope.json");
    let keys = node_keys();
    let req = Request::<Full>::from_json(&file["request"].to_string()).unwrap();
    assert_eq!(serde_json::to_value(&req).unwrap(), file["request"]);
    // The request id is one field element, written with 64 digits.
    assert_eq!(file["request_id"], file["request"]["request_id"]);
    assert_eq!(file["request_id"].as_str().unwrap().len(), 66);
    assert_eq!(hex(req.request_id.fr()), file["request_id"]);
    assert_eq!(
        serde_json::to_value(req.namespace).unwrap(),
        file["namespace"]
    );
    assert_eq!(
        hex(poseidon2_hash_bytes(req.circuit.as_bytes())),
        file["circuit_hash"]
    );
    for (name, h) in file["names"]
        .as_array()
        .unwrap()
        .iter()
        .zip(file["name_hashes"].as_array().unwrap())
    {
        assert_eq!(
            hex(poseidon2_hash_bytes(name.as_str().unwrap().as_bytes())),
            *h
        );
    }
    assert_eq!(
        canonical_json(&canonical_body(&req)).unwrap(),
        file["canonical_body"]
    );
    assert_eq!(hex(req.body_hash()), file["body_hash"]);
    assert_eq!(hex(req.input_body_hash()), file["input_body_hash"]);
    assert_eq!(
        poseidon2_hash_bytes(file["input_body"].as_str().unwrap().as_bytes()),
        req.input_body_hash()
    );
    req.check_ciphertext_hashes().unwrap();
    for v in file["envelopes"].as_array().unwrap() {
        let name = v["name"].as_str().unwrap();
        let i = v["i"].as_u64().unwrap() as usize;
        let k = &keys[i];
        assert_eq!(point_to_wire(k.enc_pk()), point(&v["enc_pk"]));
        let ad = EnvelopeAd::for_input(&req, name);
        assert_eq!(ad.request_id, req.request_id.fr());
        // The AD's parts, hashed as the file's rule says.
        let nonce = poseidon2_hash(&[
            hex_value(&file["namespace"]),
            hex_value(&file["request_id"]),
            hex_value(&file["circuit_hash"]),
            poseidon2_hash_bytes(name.as_bytes()),
            Fr::from(i as u64),
            hex_value(&file["input_body_hash"]),
        ]);
        assert_eq!(ad.nonce(i), nonce);
        assert_eq!(hex(nonce), v["nonce"]);
        let pair = [hex_value(&v["pair"][0]), hex_value(&v["pair"][1])];
        let envelope = seal_envelope_with(k.enc_pk(), i, &ad, pair, hex_value(&v["eph"]));
        assert_eq!(envelope.eph, point(&v["E"]));
        assert_eq!(
            hex(k.shared_secret(point_from_wire(&envelope.eph).unwrap())),
            v["shared_secret"]
        );
        let (ct, tag) = ae::encrypt(hex_value(&v["shared_secret"]), nonce, &pair);
        assert_eq!(ct, fields(&v["ct"]));
        assert_eq!(hex(tag), v["tag"]);
        assert_eq!(serde_json::to_value(envelope.ct).unwrap(), v["ct"]);
        assert_eq!(hex(envelope.hash()), v["share_hash"]);
        let input = req.shared_inputs.iter().find(|s| s.name == name).unwrap();
        assert_eq!(input.shares[i], envelope);
        assert_eq!(open_envelope(k, i, &ad, &envelope).unwrap(), pair);
        // Another node's key does not open it.
        assert!(open_envelope(&keys[(i + 1) % NODES], i, &ad, &envelope).is_err());
    }
}

#[test]
fn npk_app_hash_json() {
    let file = vector("npk_app_hash.json");
    let vectors = file["vectors"].as_array().unwrap();
    assert!(vectors.len() >= 3);
    for v in vectors {
        let nsk = nsk_app_derive_public(hex_value(&v["master"]), hex_value(&v["namespace"]));
        assert_eq!(hex(nsk), v["nsk_app"], "{}", v["name"]);
        let npk = npk_app(nsk);
        assert_eq!(point_to_wire(npk), point(&v["npk_app"]));
        assert_eq!(hex(npk_app_hash(npk)), v["npk_app_hash"]);
    }
}

/// The tip's content-derived ids (sidecar-tip's `ids` module writes the file;
/// the Noir intake helpers and pss-client check against it): recomputed here
/// from the preimages with the machine's Poseidon2 alone.
#[test]
fn chain_request_id_json() {
    let file = vector("chain_request_id.json");
    let pss_attempt = label_field(b"sidecar.attempt");
    assert_eq!(hex(pss_attempt), file["pss_attempt"]);
    let vectors = file["vectors"].as_array().unwrap();
    assert!(!vectors.is_empty());
    for v in vectors {
        let inputs_hash = poseidon2_hash(&fields(&v["inputs"]));
        assert_eq!(hex(inputs_hash), v["inputs_hash"], "{}", v["name"]);
        let chain = poseidon2_hash(&[
            hex_value(&v["namespace"]),
            hex_value(&v["vk_hash"]),
            inputs_hash,
            hex_value(&v["user_nonce"]),
        ]);
        assert_eq!(hex(chain), v["chain_request_id"], "{}", v["name"]);
        // the old commitments, then the pinned read values (none for a
        // circuit without pinned reads)
        let mut attempt = vec![pss_attempt, chain];
        attempt.extend(fields(&v["old_commitments"]));
        attempt.extend(fields(&v["pinned_reads"]));
        assert_eq!(
            hex(poseidon2_hash(&attempt)),
            v["machine_request_id"],
            "{}",
            v["name"]
        );
        // the on-chain intake request log: compute_log_tag(chain,
        // REQUEST_DOMAIN = ASCII "psrq"), the inputs, user_nonce
        let mut log = vec![poseidon2_hash_with_separator(&[chain], 0x7073_7271)];
        log.extend(fields(&v["inputs"]));
        log.push(hex_value(&v["user_nonce"]));
        assert_eq!(fields(&v["request_log"]), log, "{}", v["name"]);
    }
}

/// The tip queue's storage slots (sidecar-tip's `layout` module writes the
/// file; pss-client's queue.ts and pss_public_contract's queue.nr check
/// against it): recomputed here from the base slot with the map-slot rule.
#[test]
fn queue_json() {
    let file = vector("queue.json");
    let domain = file["map_slot_domain"].as_u64().unwrap() as u32;
    assert_eq!(
        domain, 4_015_149_901,
        "DOM_SEP__PUBLIC_STORAGE_MAP_SLOT of protocol_types v6.0.0"
    );
    assert_eq!(
        file["done"],
        serde_json::json!({"pending": 0, "applied": 1, "skipped": 2})
    );
    let index = |v: &Value| {
        Fr::from(u64::from_str_radix(v.as_str().unwrap().trim_start_matches("0x"), 16).unwrap())
    };
    for v in file["vectors"].as_array().unwrap() {
        let base = hex_value(&v["base"]);
        let at = |offset: u64| base + Fr::from(offset);
        let map = |offset: u64, key: Fr| poseidon2_hash_with_separator(&[at(offset), key], domain);
        assert_eq!(
            [
                hex_value(&v["tail"]),
                hex_value(&v["head_index"]),
                hex_value(&v["head_since"])
            ],
            [at(1), at(2), at(3)],
            "{}",
            v["name"]
        );
        for e in v["requests"].as_array().unwrap() {
            assert_eq!(
                hex_value(&e["slot"]),
                map(0, index(&e["index"])),
                "{}",
                v["name"]
            );
        }
        for e in v["seen"].as_array().unwrap() {
            assert_eq!(
                hex_value(&e["slot"]),
                map(4, hex_value(&e["request_id"])),
                "{}",
                v["name"]
            );
        }
        for e in v["done"].as_array().unwrap() {
            assert_eq!(
                hex_value(&e["slot"]),
                map(5, index(&e["index"])),
                "{}",
                v["name"]
            );
        }
    }
}

/// The slot commitment of a chain-held tip key (sidecar-tip's tests/write_vectors
/// writes the file; pss_core's tip::slot::commitment and pss-client
/// check against it): recomputed here from the preimage with the machine's
/// Poseidon2 alone.
#[test]
fn slot_commitment_json() {
    let file = vector("slot_commitment.json");
    let sep = label_field(b"pss.tip.state");
    assert_eq!(hex(sep), file["tip_state_sep"]);
    let vectors = file["vectors"].as_array().unwrap();
    assert!(!vectors.is_empty());
    for v in vectors {
        let mut preimage = vec![sep, hex_value(&v["namespace"]), hex_value(&v["slot"])];
        preimage.extend(fields(&v["fields"]));
        preimage.push(hex_value(&v["blinding"]));
        assert_eq!(
            hex(poseidon2_hash(&preimage)),
            v["commitment"],
            "{}",
            v["name"]
        );
        // the blinding is bound: another one is another commitment
        *preimage.last_mut().unwrap() += Fr::one();
        assert_ne!(
            hex(poseidon2_hash(&preimage)),
            v["commitment"],
            "{}",
            v["name"]
        );
    }
}

/// The receipt route on the AMM tip's receipt-intake manifest (sidecar-tip's
/// `receipt` module writes the file): the manifest registers against the
/// vector's ABI with vk_hash, partial_note and user_nonce as reserved
/// operands, the app inputs are the three request public names and the
/// partial note (keyed by its parameter's name) in ABI order, the ids and
/// the message follow from the machine's Poseidon2 alone, and each node's
/// signature verifies under its `sig` key of keys.json.
#[test]
fn receipt_route_json() {
    use sidecar_core::manifest::{PublicOperand, PublicSource, ReservedOperand, Source};
    let file = vector("receipt_route.json");
    let manifest = sidecar_test_fixtures::vectors::read(file["manifest"].as_str().unwrap());
    let abi: Abi = serde_json::from_value(file["abi"].clone()).unwrap();
    let (m, shape) = sidecar_core::abi::check_manifest_value(&manifest, &abi).unwrap();
    assert!(m.queued());
    assert_eq!(
        m.reserved().collect::<Vec<_>>(),
        [
            ("vk_hash", ReservedOperand::VkHash),
            ("partial_note", ReservedOperand::PartialNote),
            ("user_nonce", ReservedOperand::UserNonce),
        ]
    );
    let names: Vec<&str> = shape
        .params
        .iter()
        .filter_map(|p| match &p.source {
            Source::Public(PublicSource::One(PublicOperand::Name(n))) => Some(n.as_str()),
            Source::Public(PublicSource::One(PublicOperand::Reserved(r))) if r.app_input() => {
                Some(p.name.as_str())
            }
            _ => None,
        })
        .collect();
    assert_eq!(names, ["amount_in", "direction", "min_out", "partial_note"]);
    let body = &file["body"];
    let inputs: Vec<Fr> = names
        .iter()
        .map(|n| hex_value(&body["inputs"][*n]))
        .collect();
    assert_eq!(fields(&file["inputs"]), inputs);
    let inputs_hash = poseidon2_hash(&inputs);
    assert_eq!(hex(inputs_hash), file["inputs_hash"]);
    let request_id = poseidon2_hash(&[
        hex_value(&body["namespace"]),
        hex_value(&file["vk_hash"]),
        inputs_hash,
        hex_value(&body["user_nonce"]),
    ]);
    assert_eq!(hex(request_id), file["request_id"]);
    let expiry = body["expiry_block"].as_u64().unwrap();
    let message = poseidon2_hash(&[
        label_field(b"sidecar.receipt"),
        request_id,
        inputs_hash,
        Fr::from(expiry),
    ]);
    assert_eq!(hex(message), file["message"]);
    let keys = node_keys();
    let signatures = file["signatures"].as_array().unwrap();
    assert_eq!(signatures.len(), NODES);
    for (i, s) in signatures.iter().enumerate() {
        assert!(
            verify_wire(&point_to_wire(keys[i].sig_pk()), signature(s), message),
            "node {i}"
        );
    }
}

/// Secret-shared receipt intake (sidecar-tip's tests/write_vectors writes the
/// file and checks its hashes; pss-client checks against it), what the core
/// owns of it: the manifest registers against the vector's ABI with
/// `$vk_hash` and `$inputs_hash` as its reserved operands, every node opens
/// its own envelope of every shared value and of the salts under the intake
/// associated data and nobody else's, and each node's receipt verifies under
/// its `sig` key of keys.json.
#[test]
fn shared_intake_json() {
    use sidecar_core::envelope::sidecar_intake_ad;
    use sidecar_core::manifest::ReservedOperand;
    use sidecar_core::request::SharedInput;
    let file = vector("shared_intake.json");
    let manifest = sidecar_test_fixtures::vectors::read(file["manifest"].as_str().unwrap());
    let abi: Abi = serde_json::from_value(file["abi"].clone()).unwrap();
    let (m, _) = check_manifest_value(&manifest, &abi).unwrap();
    assert_eq!(m.intake.as_str(), "shared_receipt");
    assert_eq!(
        m.reserved().collect::<Vec<_>>(),
        [
            ("vk_hash", ReservedOperand::VkHash),
            ("inputs_hash", ReservedOperand::InputsHash),
        ]
    );
    assert_eq!(hex(label_field(b"sidecar.intake")), file["intake_ad"]);
    assert_eq!(label_field(b"sidecar.intake"), sidecar_intake_ad());
    assert_eq!(file["intake_ad_ascii"], "sidecar.intake");

    // the envelopes: node i's pair of each sharing under the intake
    // associated data (C, the summand commitments, the digest and the
    // receipt message are sidecar-tip's, checked by its write_vectors)
    let (namespace, id) = (
        hex_value(&file["namespace"]),
        hex_value(&file["chain_request_id"]),
    );
    let keys = node_keys();
    let circuit = file["circuit"].as_str().unwrap();
    let shared: Vec<SharedInput> = serde_json::from_value(file["shared_inputs"].clone()).unwrap();
    let detail = file["envelopes"].as_array().unwrap();
    assert_eq!(shared.len(), detail.len());
    for (s, d) in shared.iter().zip(detail) {
        assert_eq!(d["name"], s.name);
        let sharing = fields(&d["sharing"]);
        let ad = EnvelopeAd::for_intake(namespace, id, circuit, &s.name);
        for i in 0..NODES {
            let nonce = poseidon2_hash(&[
                namespace,
                id,
                poseidon2_hash_bytes(circuit.as_bytes()),
                poseidon2_hash_bytes(s.name.as_bytes()),
                Fr::from(i as u64),
                label_field(b"sidecar.intake"),
            ]);
            assert_eq!(hex(nonce), d["nodes"][i]["nonce"], "{}: node {i}", s.name);
            assert_eq!(ad.nonce(i), nonce);
            let pair = open_envelope(&keys[i], i, &ad, &s.shares[i]).unwrap();
            assert_eq!(pair, [sharing[i], sharing[(i + NODES - 1) % NODES]]);
            assert_eq!(fields(&d["nodes"][i]["pair"]), pair);
            assert_eq!(s.share_hashes[i].fr(), s.shares[i].hash());
            assert!(open_envelope(&keys[(i + 1) % NODES], i, &ad, &s.shares[i]).is_err());
        }
    }

    // the three receipts verify under the nodes' sig keys
    let receipt = &file["receipt"];
    let message = hex_value(&receipt["message"]);
    for (i, s) in receipt["signatures"].as_array().unwrap().iter().enumerate() {
        let pk = point_to_wire(keys[i].sig_pk());
        assert!(verify_wire(&pk, signature(s), message), "node {i}");
    }
}

/// The tip's receipts (sidecar-tip's `receipt` module writes the
/// file; the Noir intake library and pss-client check against it): the ids
/// and the message recomputed from the preimages with the machine's Poseidon2
/// alone, and each signature verified under its node's `sig` key of
/// keys.json, in both encodings.
#[test]
fn receipts_json() {
    let file = vector("receipts.json");
    let domain = label_field(b"sidecar.receipt");
    assert_eq!(hex(domain), file["receipt_domain"]);
    let keys = node_keys();
    for (i, node) in file["nodes"].as_array().unwrap().iter().enumerate() {
        assert_eq!(node["node"], i);
        assert_eq!(point(&node["sig_pk"]), point_to_wire(keys[i].sig_pk()));
    }
    let vectors = file["vectors"].as_array().unwrap();
    assert_eq!(vectors.len(), 2);
    for v in vectors {
        let name = &v["name"];
        let inputs_hash = poseidon2_hash(&fields(&v["inputs"]));
        assert_eq!(hex(inputs_hash), v["inputs_hash"], "{name}");
        let request_id = poseidon2_hash(&[
            hex_value(&v["namespace"]),
            hex_value(&v["vk_hash"]),
            inputs_hash,
            hex_value(&v["user_nonce"]),
        ]);
        assert_eq!(hex(request_id), v["request_id"], "{name}");
        let expiry = v["expiry_block"].as_u64().unwrap();
        assert!(
            expiry <= u64::from(u32::MAX),
            "{name}: expiry_block is a u32"
        );
        let preimage = [domain, request_id, inputs_hash, Fr::from(expiry)];
        assert_eq!(fields(&v["message_preimage"]), preimage, "{name}");
        let message = poseidon2_hash(&preimage);
        assert_eq!(hex(message), v["message"], "{name}");
        let signatures = v["signatures"].as_array().unwrap();
        let bytes = v["signature_bytes"].as_array().unwrap();
        assert_eq!((signatures.len(), bytes.len()), (NODES, NODES));
        for i in 0..NODES {
            let sig = signature(&signatures[i]);
            let pk = point_to_wire(keys[i].sig_pk());
            assert!(verify_wire(&pk, sig, message), "{name}: node {i}");
            // a receipt is node i's alone
            let other = point_to_wire(keys[(i + 1) % NODES].sig_pk());
            assert!(!verify_wire(&other, sig, message), "{name}: node {i}");
            let raw: HexBytes = bytes[i].as_str().unwrap().parse().unwrap();
            let raw: [u8; 64] = raw.as_slice().try_into().unwrap();
            assert_eq!(signature_from_bytes(&raw), sig, "{name}: node {i}");
        }
    }
    // the first case is chain_request_id.json's first under receipt intake
    let ids = vector("chain_request_id.json");
    assert_eq!(
        vectors[0]["request_id"],
        ids["vectors"][0]["chain_request_id"]
    );
}

#[test]
fn registry_json() {
    let file = vector("registry.json");
    assert_eq!(hex(Fr::from(REGISTRY_DOMAIN)), file["registry_domain"]);
    let register =
        Signed::<ManifestMessage>::from_json(&file["register"]["body"].to_string()).unwrap();
    assert_eq!(hex(register.message), file["register"]["message"]);
    assert!(verify_wire(
        &register.body.owner_pubkey,
        register.body.signature,
        register.message
    ));
    let disable =
        Signed::<DisableRequest>::from_json(&file["disable"]["body"].to_string()).unwrap();
    assert_eq!(hex(disable.message), file["disable"]["message"]);
    assert!(verify_wire(
        &disable.body.owner_pubkey,
        disable.body.signature,
        disable.message
    ));
    // the manifest message's answers: its hashes from the register body
    let m = &file["manifest"];
    assert_eq!(hex(Fr::from(MANIFEST_DOMAIN)), m["manifest_domain"]);
    let checked = register.body.contract_manifest().unwrap();
    assert_eq!(
        hex(manifest_hash(&register.body.manifest).unwrap()),
        m["manifest_hash"]
    );
    assert_eq!(hex(checked.packages_hash()), m["packages_hash"]);
    for r in m["results"].as_array().unwrap() {
        let message = manifest_message(
            hex_value(&m["namespace"]),
            hex_value(&m["manifest_hash"]),
            hex_value(&m["packages_hash"]),
            hex_value(&m["npk_app_hash"]),
            m["seq"].as_u64().unwrap(),
            r["node"].as_u64().unwrap() as usize,
        );
        assert_eq!(hex(message), r["message"]);
        assert!(verify_wire(
            &point(&r["sig_pubkey"]),
            signature(&r["signature"]),
            message
        ));
    }
    for r in file["results"].as_array().unwrap() {
        let message = registry_message(
            hex_value(&r["namespace"]),
            r["name"].as_str().unwrap(),
            hex_value(&r["vk_hash"]),
            hex_value(&r["npk_app_hash"]),
            r["seq"].as_u64().unwrap(),
            r["disabled"].as_bool().unwrap(),
            r["node"].as_u64().unwrap() as usize,
        );
        assert_eq!(hex(message), r["message"]);
        let secret = scalar_from_field(hex_value(&r["sig_secret"]));
        assert_eq!(point_to_wire(public_key(secret)), point(&r["sig_pubkey"]));
        assert!(verify_wire(
            &point(&r["sig_pubkey"]),
            signature(&r["signature"]),
            message
        ));
        assert!(!verify_wire(
            &point(&r["sig_pubkey"]),
            signature(&r["signature"]),
            message + Fr::one()
        ));
    }
}

#[test]
fn schnorr_json() {
    let file = vector("schnorr.json");
    assert_eq!(file["ts_signer_compatible"], true);
    let vectors = file["vectors"].as_array().unwrap();
    let valid = vectors.iter().filter(|v| v["expected"] == true).count();
    assert!(
        valid >= 6 && vectors.len() - valid >= 4,
        "{valid} of {}",
        vectors.len()
    );
    for v in vectors {
        assert_eq!(
            verify_wire(
                &point(&v["pubkey"]),
                signature(&v["signature"]),
                hex_value(&v["message"])
            ),
            v["expected"].as_bool().unwrap(),
            "{}",
            v["name"]
        );
    }
    for m in file["signed_messages"].as_array().unwrap() {
        let domain = m["domain"].as_str().unwrap();
        let body = &m["body_without_signature"];
        assert_eq!(
            canonical_json(body).unwrap(),
            m["canonical"],
            "{}",
            m["name"]
        );
        assert_eq!(
            hex(message_for(domain, body).unwrap()),
            m["message"],
            "{}",
            m["name"]
        );
    }
}

fn elements(v: &Value) -> Vec<Elem> {
    v.as_array()
        .unwrap()
        .iter()
        .map(|e| match (e.get("public"), e.get("shared")) {
            (Some(p), None) => Elem::Public(hex_value(p)),
            (None, Some(s)) => Elem::Shared(Share::new(hex_value(&s[0]), hex_value(&s[1]))),
            _ => panic!("{e} is not an element"),
        })
        .collect()
}

#[test]
fn records_json() {
    let file = vector("records.json");
    let keys = node_keys();
    let keys_file = vector("keys.json");
    assert_eq!(hex(label_field(SIDECAR_SEAL_KEY)), file["sidecar_seal_key"]);
    assert_eq!(
        hex(label_field(SIDECAR_RECORD_AD)),
        file["sidecar_record_ad"]
    );
    let requester = point_from_wire(&point(&file["requester"]["pubkey"])).unwrap();
    assert_eq!(
        public_key(scalar_from_field(hex_value(&file["requester"]["secret"]))),
        requester
    );
    for (i, n) in file["nodes"].as_array().unwrap().iter().enumerate() {
        let k = &keys[i];
        let kf = &keys_file["nodes"][i];
        for field in ["enc", "enc_limbs", "enc_pk", "record_key", "key_id"] {
            assert_eq!(
                n[field], kf[field],
                "node {i} {field} differs from keys.json"
            );
        }
        assert_eq!(hex(record_key(k.enc_scalar())), n["record_key"]);
        let (x, y) = coordinates(k.enc_pk());
        let id_hash = poseidon2_hash(&[x, y]);
        assert_eq!(hex(id_hash), n["key_id_hash"]);
        let id: String = key_id(k.enc_pk())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(format!("0x{id}"), n["key_id"]);
        assert_eq!(&fr_to_hex(id_hash)[..18], n["key_id"].as_str().unwrap());
    }
    let mut machine_cases = 0;
    for r in file["records"].as_array().unwrap() {
        let name = r["name"].as_str().unwrap();
        let (ns, key, note_hash) = (
            hex_value(&r["namespace"]),
            r["key"].as_str().unwrap(),
            hex_value(&r["note_hash"]),
        );
        assert_eq!(hex(key_hash(key)), r["key_hash"], "{name}");
        assert_eq!(hex(poseidon2_hash_bytes(key.as_bytes())), r["key_hash"]);
        let machine = r["owner_kind"] == "machine";
        machine_cases += machine as usize;
        let clear = r["value"].as_array().unwrap();
        let thirds = r["thirds"].as_array().unwrap();
        assert_eq!(thirds.len(), NODES);
        for (i, t) in thirds.iter().enumerate() {
            assert_eq!(t["node"], i);
            let k = &keys[i];
            let owner = point_from_wire(&point(&t["owner"])).unwrap();
            assert_eq!(
                owner,
                if machine { k.enc_pk() } else { requester },
                "{name} node {i}"
            );
            let elems = elements(&t["elements"]);
            assert_eq!(elems.len(), clear.len());
            let mut plaintext = vec![ns, key_hash(key), note_hash];
            plaintext.extend(encode_elements(&elems));
            assert_eq!(fields(&t["plaintext"]), plaintext, "{name} node {i}");
            let nonce = associated_data(ns, key, note_hash, owner);
            let (ox, oy) = coordinates(owner);
            assert_eq!(
                nonce,
                poseidon2_hash(&[
                    ns,
                    key_hash(key),
                    note_hash,
                    ox,
                    oy,
                    label_field(SIDECAR_RECORD_AD)
                ])
            );
            assert_eq!(hex(nonce), t["nonce"]);
            let (ct, tag) = ae::encrypt(k.seal_key(), nonce, &plaintext);
            assert_eq!(ct, fields(&t["ciphertext"]), "{name} node {i}");
            assert_eq!(hex(tag), t["tag"]);
            let c: HexBytes = serde_json::from_value(t["c"].clone()).unwrap();
            assert_eq!(
                record::seal(k, ns, key, note_hash, owner, &elems),
                c.0,
                "{name} node {i}"
            );
            assert_eq!(c.0[..8], key_id(k.enc_pk()));
            assert_eq!(hex(record_hash(&c.0).unwrap()), t["record_hash"]);
            let mut hashed = vec![Fr::from_be_bytes_mod_order(&c.0[..8])];
            hashed.extend(&ct);
            hashed.push(tag);
            assert_eq!(hex(poseidon2_hash(&hashed)), t["record_hash"]);
            assert_eq!(
                record::open(k, ns, key, note_hash, owner, &c.0).unwrap(),
                elems
            );
            // The AD binds: another owner, note hash or key, or another node's
            // key does not open the third.
            let other = if machine { requester } else { k.enc_pk() };
            assert!(record::open(k, ns, key, note_hash, other, &c.0).is_err());
            assert!(record::open(k, ns, key, note_hash + Fr::one(), owner, &c.0).is_err());
            assert!(record::open(k, ns, "0xb003", note_hash, owner, &c.0).is_err());
            assert!(record::open(&keys[(i + 1) % NODES], ns, key, note_hash, owner, &c.0).is_err());
        }
        // The shared elements' pairs are one replicated sharing of the clear value.
        for (j, e) in clear.iter().enumerate() {
            let pairs: Vec<Elem> = thirds
                .iter()
                .map(|t| elements(&t["elements"]).swap_remove(j))
                .collect();
            match (e.get("public"), e.get("shared")) {
                (Some(v), None) => assert!(pairs.iter().all(|p| *p == Elem::Public(hex_value(v)))),
                (None, Some(x)) => {
                    let s: Vec<Share> = pairs
                        .iter()
                        .map(|p| match p {
                            Elem::Shared(s) => *s,
                            _ => panic!("{name}: element {j} is not shared at every node"),
                        })
                        .collect();
                    assert_eq!(s[0].a + s[1].a + s[2].a, hex_value(x), "{name}");
                    for i in 0..NODES {
                        assert_eq!(s[i].b, s[(i + 2) % NODES].a, "{name}: x_(i-1)");
                    }
                }
                _ => panic!("{e} is not a clear element"),
            }
        }
    }
    assert_eq!(machine_cases, 1);
    // client_b001 is envelope.json's record.
    let envelope = vector("envelope.json");
    let b001 = &file["records"][0];
    assert_eq!(b001["name"], "client_b001");
    let record = &envelope["request"]["records"][0];
    assert_eq!(b001["key"], record["key"]);
    assert_eq!(b001["note_hash"], record["note_hash"]);
    for i in 0..NODES {
        assert_eq!(b001["thirds"][i]["c"], record["c"][i]);
        assert_eq!(b001["thirds"][i]["record_hash"], record["record_hashes"][i]);
    }
    assert_eq!(
        file["requester"]["pubkey"],
        envelope["request"]["requester"]
    );
}

#[test]
fn bodies_json() {
    let file = vector("bodies.json");
    let bodies = file["bodies"].as_array().unwrap();
    let domains: Vec<&str> = bodies
        .iter()
        .map(|b| b["domain"].as_str().unwrap())
        .collect();
    assert_eq!(domains, [REGISTER_DOMAIN, DISABLE_DOMAIN, EXECUTE_DOMAIN]);
    for b in bodies {
        let name = b["name"].as_str().unwrap();
        let domain = b["domain"].as_str().unwrap();
        let canonical = b["canonical"].as_str().unwrap();
        let message = hex_value(&b["message"]);
        assert_eq!(
            message,
            poseidon2_hash_bytes(format!("{domain}{canonical}").as_bytes()),
            "{name}"
        );
        let pubkey = point(&b["pubkey"]);
        assert_eq!(
            point_to_wire(public_key(
                scalar_from_hex(b["secret"].as_str().unwrap()).unwrap()
            )),
            pubkey,
            "{name}"
        );
        let text = b["body"].to_string();
        let (signed_by, sig, computed) = match domain {
            REGISTER_DOMAIN | DISABLE_DOMAIN => {
                let mut unsigned = b["body"].clone();
                unsigned.as_object_mut().unwrap().remove("signature");
                assert_eq!(canonical_json(&unsigned).unwrap(), canonical, "{name}");
                assert!(
                    unsigned["seq"].is_u64(),
                    "{name}: a registry body carries seq"
                );
                if domain == REGISTER_DOMAIN {
                    let s = Signed::<ManifestMessage>::from_json(&text).unwrap();
                    (s.body.owner_pubkey, s.body.signature, s.message)
                } else {
                    let s = Signed::<DisableRequest>::from_json(&text).unwrap();
                    (s.body.owner_pubkey, s.body.signature, s.message)
                }
            }
            _ => {
                let req = Request::<Full>::from_json(&text).unwrap();
                assert!(
                    !req.records.is_empty(),
                    "the execute body supplies a record"
                );
                assert_eq!(canonical_json(&canonical_body(&req)).unwrap(), canonical);
                (
                    req.requester.unwrap(),
                    req.signature.unwrap(),
                    req.signed_message(),
                )
            }
        };
        assert_eq!(computed, message, "{name}");
        assert_eq!(signed_by, pubkey, "{name}");
        assert!(verify_wire(&pubkey, sig, message), "{name}");
        assert!(!verify_wire(&pubkey, sig, message + Fr::one()), "{name}");
    }
    // The execute body is envelope.json's request, signed.
    let mut execute = bodies[2]["body"].clone();
    execute.as_object_mut().unwrap().remove("signature");
    assert_eq!(execute, vector("envelope.json")["request"]);
}

#[test]
fn results_json() {
    let file = vector("results.json");
    let keys = node_keys();
    let records = vector("records.json");
    assert_eq!(hex(Fr::from(RESULT_DOMAIN)), file["result_domain"]);
    assert_eq!(hex(label_field(b"sidecar.result")), file["result_domain"]);
    let ns = hex_value(&file["namespace"]);
    let mut zero_cases = 0;
    for case in file["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let id: RequestId = serde_json::from_value(case["request_id"].clone()).unwrap();
        assert!(
            id.fr().into_bigint() < (Fr::from(1u128 << 64) * Fr::from(1u128 << 64)).into_bigint()
        );
        let outputs = case["outputs"].as_array().unwrap();
        let commitments = fields(&case["commitments"]);
        assert_eq!(
            commitments,
            outputs
                .iter()
                .map(|o| hex_value(&o["note_hash"]))
                .collect::<Vec<_>>(),
            "{name}"
        );
        for (i, n) in case["nodes"].as_array().unwrap().iter().enumerate() {
            assert_eq!(n["node"], i);
            let k = &keys[i];
            assert_eq!(point_to_wire(k.sig_pk()), point(&n["sig_pubkey"]));
            // The record hashes are those of the client-held outputs' thirds.
            let expected: Vec<Value> = outputs
                .iter()
                .filter(|o| o["state"] == "client")
                .map(|o| {
                    let r = records["records"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .find(|r| r["name"] == o["record"])
                        .unwrap();
                    assert_eq!(r["key"], o["key"]);
                    assert_eq!(r["note_hash"], o["note_hash"]);
                    r["thirds"][i]["record_hash"].clone()
                })
                .collect();
            assert_eq!(n["record_hashes"].as_array().unwrap(), &expected, "{name}");
            let hashes = fields(&n["record_hashes"]);
            let sealed = sealed_hash(&hashes);
            assert_eq!(hex(sealed), n["sealed_hash"], "{name}");
            if hashes.is_empty() {
                assert_eq!(sealed, Fr::from(0u64));
                zero_cases += 1;
            } else {
                assert_eq!(sealed, poseidon2_hash(&hashes));
            }
            let message = result_message(ns, id, &commitments, i, sealed);
            let mut inputs = vec![Fr::from(RESULT_DOMAIN), ns, id.fr()];
            inputs.extend(&commitments);
            inputs.extend([Fr::from(i as u64), sealed]);
            assert_eq!(message, poseidon2_hash(&inputs));
            assert_eq!(hex(message), n["message"], "{name} node {i}");
            let sig = signature(&n["signature"]);
            assert!(
                verify_wire(&point(&n["sig_pubkey"]), sig, message),
                "{name} node {i}"
            );
            // Signed for node i only, and only over this sealed hash.
            let other = result_message(ns, id, &commitments, (i + 1) % NODES, sealed);
            assert!(!verify_wire(&point(&n["sig_pubkey"]), sig, other));
            let unsealed = result_message(ns, id, &commitments, i, sealed + Fr::one());
            assert!(!verify_wire(&point(&n["sig_pubkey"]), sig, unsealed));
        }
    }
    assert_eq!(zero_cases, NODES, "one round makes no thirds");
}

#[test]
fn field_hex_json() {
    let file = vector("field_hex.json");
    let modulus = file["modulus"].as_str().unwrap();
    assert!(fr_from_hex(modulus).is_err());
    let bytes = <Fr as PrimeField>::MODULUS.to_bytes_be();
    let digits: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(modulus, format!("0x{digits}"));
    for v in file["field_elements"]["accepted"].as_array().unwrap() {
        let text = v["text"].as_str().unwrap();
        let value = fr_from_hex(text).unwrap();
        assert_eq!(hex(value), v["value"], "{text}");
        let parsed: FieldHex = serde_json::from_value(v["text"].clone()).unwrap();
        assert_eq!(serde_json::to_value(parsed).unwrap(), v["value"]);
    }
    for v in file["field_elements"]["refused"].as_array().unwrap() {
        assert!(fr_from_hex(v["text"].as_str().unwrap()).is_err(), "{v}");
        assert!(
            serde_json::from_value::<FieldHex>(v["text"].clone()).is_err(),
            "{v}"
        );
    }
    for v in file["request_ids"]["accepted"].as_array().unwrap() {
        let id: RequestId = serde_json::from_value(v["text"].clone()).unwrap();
        assert_eq!(serde_json::to_value(id).unwrap(), v["value"]);
        assert_eq!(v["value"].as_str().unwrap().len(), 66);
    }
    for v in file["request_ids"]["refused"].as_array().unwrap() {
        assert!(
            serde_json::from_value::<RequestId>(v["text"].clone()).is_err(),
            "{v}"
        );
    }
    let mut refused = 0;
    for d in file["documents"].as_array().unwrap() {
        let json = d["json"].clone();
        let ok = match d["type"].as_str().unwrap() {
            "NamespaceResponse" => serde_json::from_value::<NamespaceResponse>(json).is_ok(),
            "ManifestResponse" => serde_json::from_value::<ManifestResponse>(json).is_ok(),
            "DisableResponse" => serde_json::from_value::<DisableResponse>(json).is_ok(),
            "NodesResponse" => NodesResponse::from_json(&json.to_string()).is_ok(),
            other => panic!("no reader for document type {other}"),
        };
        assert_eq!(ok, d["accepted"].as_bool().unwrap(), "{}", d["name"]);
        refused += !ok as usize;
    }
    assert!(refused >= 8);
}

/// The tags of the tip's request and sealed-thirds logs are
/// `poseidon2_hash_with_separator([chain_request_id], domain)` under the
/// file's two u32 domains (sidecar-tip's layout and chain_state tests check
/// that its `REQUEST_DOMAIN` and `PSS_STATE` are these).
#[test]
fn log_tags_json() {
    let file = vector("log_tags.json");
    for (domain, ascii) in [
        ("request_domain", "request_domain_ascii"),
        ("pss_state", "pss_state_ascii"),
    ] {
        let value = u32::try_from(file[domain].as_u64().unwrap()).unwrap();
        assert_eq!(
            &value.to_be_bytes(),
            file[ascii].as_str().unwrap().as_bytes()
        );
    }
    let request = u32::try_from(file["request_domain"].as_u64().unwrap()).unwrap();
    let sealed = u32::try_from(file["pss_state"].as_u64().unwrap()).unwrap();
    let vectors = file["vectors"].as_array().unwrap();
    assert!(!vectors.is_empty());
    for v in vectors {
        let id = hex_value(&v["chain_request_id"]);
        assert_eq!(
            hex(poseidon2_hash_with_separator(&[id], request)),
            v["request_tag"]
        );
        assert_eq!(
            hex(poseidon2_hash_with_separator(&[id], sealed)),
            v["sealed_tag"]
        );
    }
}

/// testvectors/secret_store.json: the client's per-request secrets, each
/// `poseidon2([label, wallet_secret, namespace, n])`, every label its ASCII
/// bytes read big-endian, and the request's partial note and completion log
/// tag (aztec-nr v6's separators 568912195 and 3372669888).
#[test]
fn secret_store_json() {
    let v = vector("secret_store.json");
    let label = |key: &str, ascii: &str| {
        let value = hex_value(&v[key]);
        assert_eq!(value, label_field(ascii.as_bytes()), "{key}");
        value
    };
    let rho = label("pss_partial_randomness", "pss.partial_randomness");
    let key = label("pss_outcome_key", "pss.outcome_key");
    let tag = label("pss_outcome_tag", "pss.outcome_tag");
    let (w, ns, owner) = (
        hex_value(&v["wallet_secret"]),
        hex_value(&v["namespace"]),
        hex_value(&v["owner"]),
    );
    let vectors = v["vectors"].as_array().unwrap();
    assert!(!vectors.is_empty());
    for c in vectors {
        let n = Fr::from(c["n"].as_u64().unwrap());
        assert_eq!(poseidon2_hash(&[rho, w, ns, n]), hex_value(&c["rho"]));
        assert_eq!(
            poseidon2_hash(&[key, w, ns, n]),
            hex_value(&c["outcome_key"])
        );
        assert_eq!(
            poseidon2_hash(&[tag, w, ns, n]),
            hex_value(&c["outcome_tag"])
        );
        let p = poseidon2_hash_with_separator(&[owner, hex_value(&c["rho"])], 568912195);
        assert_eq!(p, hex_value(&c["partial_note"]));
        assert_eq!(
            poseidon2_hash_with_separator(&[p], 3372669888),
            hex_value(&c["completion_log_tag"])
        );
    }
}

/// testvectors/tip_tree.json: the tree hashes, the empty subtrees, and each
/// update case's old paths and new root, through sidecar-core's `tree`
/// module (the clear tree each node keeps).
#[test]
fn tree_vectors() {
    use sidecar_core::tree;
    let v = vector("tip_tree.json");
    let depth = v["depth"].as_u64().unwrap() as u32;
    for (sep, label) in [
        ("leaf", tree::PSS_TIP_LEAF),
        ("node", tree::PSS_TIP_NODE),
        ("tree", tree::PSS_TIP_TREE),
    ] {
        assert_eq!(hex_value(&v["separators"][sep]), label_field(label));
    }
    assert_eq!(fields(&v["zeros"]), tree::zeros(depth));
    for group in ["leaves2", "leaves4"] {
        for c in v[group].as_array().unwrap() {
            let index = tree::fr_u64(hex_value(&c["index"])).unwrap();
            let h = tree::leaf_hash(
                hex_value(&c["namespace"]),
                hex_value(&c["key"]),
                index,
                &fields(&c["leaf"]),
            );
            assert_eq!(h, hex_value(&c["hash"]), "{group}");
        }
    }
    for c in v["nodes"].as_array().unwrap() {
        assert_eq!(
            tree::node(hex_value(&c["left"]), hex_value(&c["right"])),
            hex_value(&c["hash"])
        );
    }
    for c in v["commitments"].as_array().unwrap() {
        let got = tree::commitment(
            hex_value(&c["namespace"]),
            hex_value(&c["key"]),
            hex_value(&c["root"]),
        );
        assert_eq!(got, hex_value(&c["commitment"]));
    }
    for c in v["updates"].as_array().unwrap() {
        let name = c["name"].as_str().unwrap();
        let (ns, key) = (hex_value(&c["namespace"]), hex_value(&c["key"]));
        let indices: Vec<u64> = fields(&c["indices"])
            .into_iter()
            .map(|i| tree::fr_u64(i).unwrap())
            .collect();
        let old_hashes = fields(&c["old_hashes"]);
        let new_hashes = fields(&c["new_hashes"]);
        let n_used = tree::fr_u64(hex_value(&c["n_used"])).unwrap() as usize;
        let ok = c["ok"].as_bool().unwrap();
        for (k, i) in indices.iter().enumerate() {
            let siblings = fields(&c["siblings"][k]);
            assert_eq!(
                tree::root_of(old_hashes[k], &siblings, *i),
                hex_value(&c["old_root"]),
                "{name}"
            );
            let written = ok && c["writes"][k].as_bool().unwrap() && k < n_used;
            let want = if written {
                tree::leaf_hash(ns, key, *i, &fields(&c["new_leaves"][k]))
            } else {
                old_hashes[k]
            };
            assert_eq!(new_hashes[k], want, "{name}: slot {k}");
        }
        // the new root from the old paths alone: write each used slot's new
        // hash slot after slot into a tree that holds only those paths
        let mut store: BTreeMap<Fr, tree::TreeNode> = BTreeMap::new();
        for (k, i) in indices.iter().enumerate() {
            let siblings = fields(&c["siblings"][k]);
            let mut h = old_hashes[k];
            for (level, s) in siblings.iter().enumerate() {
                let (l, r) = if (i >> level) & 1 == 1 {
                    (*s, h)
                } else {
                    (h, *s)
                };
                h = tree::node(l, r);
                store.insert(h, tree::TreeNode::Inner { left: l, right: r });
            }
        }
        let nodes = |h: Fr| Ok(store.get(&h).cloned());
        let touch = tree::Touch {
            indices: indices.clone(),
            used: (0..indices.len()).map(|k| k < n_used).collect(),
        };
        let rebuilt = tree::rebuild(
            &nodes,
            &tree::zeros(depth),
            hex_value(&c["old_root"]),
            &touch.changes(&new_hashes),
        )
        .unwrap();
        assert_eq!(rebuilt.root, hex_value(&c["new_root"]), "{name}");
        assert_eq!(
            tree::commitment(ns, key, rebuilt.root),
            hex_value(&c["new_c"]),
            "{name}"
        );
        assert_eq!(
            tree::commitment(ns, key, hex_value(&c["old_root"])),
            hex_value(&c["old_c"]),
            "{name}"
        );
    }
    for c in v["windows"].as_array().unwrap() {
        let name = c["name"].as_str().unwrap();
        let (ns, key) = (hex_value(&c["namespace"]), hex_value(&c["key"]));
        let width = c["width"].as_u64().unwrap();
        let old_root = hex_value(&c["old_root"]);
        // the window a scan round of this width reads from the request's start
        let layout: sidecar_core::manifest::TreeLayout =
            serde_json::from_value(serde_json::json!({
                "depth": depth, "leaf_len": 2, "probe": 1, "header": true,
                "window": {"width": width, "start": "start",
                           "params": {"leaves": "wl", "old_hashes": "wh", "siblings": "ws"}}
            }))
            .unwrap();
        let public = BTreeMap::from([("start".to_string(), hex_value(&c["start"]))]);
        let at = tree::fr_u64(hex_value(&c["effective_start"])).unwrap();
        assert_eq!(
            tree::window(&layout, &public),
            (at..at + width).collect::<Vec<_>>(),
            "{name}"
        );
        let start = tree::fr_u64(hex_value(&c["start"])).unwrap();
        let aligned = start < 1 << depth && start.is_multiple_of(width);
        assert_eq!(c["aligned"].as_bool().unwrap(), aligned, "{name}");
        // the header slot's path gives the old root
        let slot_hash = hex_value(&c["slot_hash"]);
        assert_eq!(
            tree::leaf_hash(ns, key, 0, &fields(&c["slot_leaf"])),
            slot_hash,
            "{name}"
        );
        assert_eq!(
            tree::root_of(slot_hash, &fields(&c["slot_siblings"]), 0),
            old_root,
            "{name}"
        );
        // each window leaf has its old hash (0 for an empty leaf), and the
        // window's subtree root goes up the siblings to the old root
        let mut level = fields(&c["old_hashes"]);
        assert_eq!(level.len() as u64, width, "{name}");
        for (j, h) in level.iter().enumerate() {
            let leaf = fields(&c["leaves"][j]);
            let want = if leaf.iter().all(|x| *x == Fr::from(0u64)) {
                Fr::from(0u64)
            } else {
                tree::leaf_hash(ns, key, at + j as u64, &leaf)
            };
            assert_eq!(*h, want, "{name}: window leaf {j}");
        }
        while level.len() > 1 {
            level = level.chunks(2).map(|p| tree::node(p[0], p[1])).collect();
        }
        let siblings = fields(&c["siblings"]);
        assert_eq!(
            siblings.len() as u64,
            depth as u64 - width.trailing_zeros() as u64
        );
        assert_eq!(
            tree::root_of(level[0], &siblings, at >> width.trailing_zeros()),
            old_root,
            "{name}"
        );
    }
}

/// shared_onchain.json: each node's pair of every shared value derives from
/// the request log with its enc scalar, and the log hashes to the data hash.
#[test]
fn shared_onchain_json() {
    use sidecar_core::derived::{SharedLog, data_hash, derived_share, pack_epochs};
    let v = vector("shared_onchain.json");
    let log: SharedLog = serde_json::from_value(serde_json::json!({
        "fields": v["log"], "shared": v["shared"]
    }))
    .unwrap();
    log.check().unwrap();
    assert_eq!(hex(data_hash(&log.frs())), v["data_hash"]);
    let epochs: [u32; 3] = serde_json::from_value(v["epochs"].clone()).unwrap();
    assert_eq!(hex(pack_epochs(epochs)), v["epochs_packed"]);
    for (i, keys) in node_keys().iter().enumerate() {
        for (j, input) in log.shared.iter().enumerate() {
            let share = derived_share(keys.enc_scalar(), i, &log, &input.name).unwrap();
            let want = &v["pairs"][i][j];
            assert_eq!(want["name"], input.name.as_str());
            assert_eq!(
                want["pair"],
                serde_json::json!([hex(share.a), hex(share.b)])
            );
        }
    }
}
