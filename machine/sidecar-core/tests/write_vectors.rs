//! Writes the test vectors that sidecar-core and pss-client share, and the
//! Noir vector programs' inputs. Deterministic: rerunning rewrites the same
//! files.
//!
//! Written here: schnorr.json, npk_app_hash.json, records.json (sealed record
//! thirds), bodies.json (signed REGISTER, DISABLE and execute bodies),
//! results.json (result-signature messages), field_hex.json (field-element
//! and request-id spellings, documents with unknown fields), shapes.json
//! (each example circuit's ABI, the public-input index of every manifest
//! output's note hash, and its verification key fields and vk hash; needs the
//! compiled circuits and the CRS of scripts/prepare-data.sh), and the
//! Prover.toml of noir/schnorr_vectors and noir/ae_vectors. ae.json,
//! keys.json, envelope.json and registry.json are written by the ignored
//! tests of sidecar-core's ae, keys, envelope and registry modules; this
//! generator reads them. tests/vectors.rs and pss-client's tests read every
//! file.
//!
//! ```sh
//! cargo test -p sidecar-core --test write_vectors -- --ignored
//! cargo test --release -p sidecar-core --test vectors
//! scripts/check-vectors.sh schnorr_vectors   # noir-lang/schnorr checks every signature
//! scripts/check-vectors.sh ae_vectors        # pss_utils' AE checks every AE vector and record third
//! ```

use std::collections::BTreeMap;
use std::fmt::Write as _;

use ark_ff::{One, PrimeField};
use ark_std::rand::SeedableRng;
use ark_std::rand::rngs::StdRng;
use noirc_abi::Abi;
use serde_json::{Value, json};
use sidecar_core::abi::check_manifest_value;
use sidecar_core::bind::{Elem, Share};
use sidecar_core::crs::{self, Artifact, Circuit, Crs};
use sidecar_core::field::{
    FieldHex, Fr, HexBytes, RequestId, fr_from_hex, fr_to_be_bytes, fr_to_hex,
};
use sidecar_core::grumpkin::{
    Fq, coordinates, npk_app, npk_app_hash, nsk_app_derive_public, point_to_wire,
    scalar_from_field, scalar_to_limbs,
};
use sidecar_core::hash::poseidon2_hash;
use sidecar_core::keys::{
    NodeKeys, SIDECAR_SEAL_KEY, key_id, label_field, record_key, scalar_to_hex,
};
use sidecar_core::pipeline::{RESULT_DOMAIN, RESULT_NONCE_LABEL, result_message, sealed_hash};
use sidecar_core::record::{
    SIDECAR_RECORD_AD, associated_data, encode_elements, key_hash, record_hash,
};
use sidecar_core::register::{
    DisableRequest, DisableResponse, ManifestMessage, ManifestResponse, NamespaceResponse,
    Signature,
};
use sidecar_core::request::{Full, GrumpkinPoint, Request, canonical_body};
use sidecar_core::response::NodesResponse;
use sidecar_core::schnorr::{
    DISABLE_DOMAIN, EXECUTE_DOMAIN, REGISTER_DOMAIN, canonical_json, message_for, public_key,
    register_message, sign, sign_derived, signature_from_bytes, verify, verify_wire,
};
use sidecar_test_fixtures::dirs::{data_dir, repo};
use sidecar_test_fixtures::vectors::{hex, node_keys, vector};

fn point(x: &str, y: &str) -> GrumpkinPoint {
    GrumpkinPoint {
        x: FieldHex(hex(x)),
        y: FieldHex(hex(y)),
    }
}

fn sig(s: [&str; 2], e: [&str; 2]) -> Signature {
    Signature {
        s: [FieldHex(hex(s[0])), FieldHex(hex(s[1]))],
        e: [FieldHex(hex(e[0])), FieldHex(hex(e[1]))],
    }
}

struct Vector {
    name: String,
    source: &'static str,
    pubkey: GrumpkinPoint,
    signature: Signature,
    message: Fr,
    expected: bool,
}

fn register_like_body(owner: GrumpkinPoint) -> Value {
    json!({
        "namespace": "0x1f2ea9c0",
        "name": "pss_seed",
        "circuit": {
            "noir_version": "1.0.0+275d3ab1a5c916c6ea73e8d6b943f685f574500c",
            "hash": "8492969876084869796",
            "abi": {"abi_version": 1, "parameters": [
                {"name": "namespace", "type": {"kind": "field"}, "visibility": "public"}
            ], "return_type": null, "error_types": {}},
            "bytecode": "H4sIAAAAAAAA/wMAAAAAAAAAAAA="
        },
        "manifest": {"manifest": 1, "circuit": "pss_seed"},
        "owner_pubkey": owner
    })
}

#[test]
#[ignore = "writes testvectors/; run on purpose"]
fn write_vector_files() {
    let mut rng = StdRng::seed_from_u64(0x5c4e_0001);
    let mut vectors = Vec::new();

    // noir-lang/schnorr v0.4.0 pinned_vector_small and pinned_vector_large
    vectors.push(Vector {
        name: "library_pinned_small".into(),
        source: "noir-lang/schnorr v0.4.0 test pinned_vector_small",
        pubkey: point(
            "0x2c39bbbde2d0ffcb5c4317dcbfa1771cf554a2f33c647446632fa707a5bf5f3f",
            "0x2b9c81935298af5ebe22f1a7279bb76781e6cadba3fb6c5c41ed942392dc687c",
        ),
        signature: sig(
            [
                "0x5fd1ac0ad411110674830c54cb506212",
                "0x281906862cdb4e0efec7226d757fe803",
            ],
            [
                "0x6c368959f958e525d761d06c47fd2ad6",
                "0x013f6a902c6c0efafdadbd4de409690d",
            ],
        ),
        message: Fr::from(0x2bcu64),
        expected: true,
    });
    vectors.push(Vector {
        name: "library_pinned_large".into(),
        source: "noir-lang/schnorr v0.4.0 test pinned_vector_large",
        pubkey: point(
            "0x065812e335a97c2108ea8cf4ccfe2f9dd6b117a0714f5e18461575be93f61da6",
            "0x1a915003e8ec534f9a15d926a7ded478e178468ccc4f28e236e67450a55ac622",
        ),
        signature: sig(
            [
                "0xf3bc3b7147acb9c621fd9f72dbf15ffa",
                "0x08599f379f0301dfefdbd0272554454d",
            ],
            [
                "0x97065383ebbbd76620398792bd259bc2",
                "0x2ceaee87f45b7a417f0ffb05451a8c92",
            ],
        ),
        message: hex("0x0123456789abcdef0fedcba9876543210123456789abcdef0fedcba987654321"),
        expected: true,
    });

    // The Rust signer: a small secret, a secret near q, and an owner signing a
    // REGISTER-shaped body.
    let small_secret = Fq::from(0x5ec2e7u64);
    let large_secret = -Fq::from(12345u64);
    let owner_secret = scalar_from_field(hex(
        "0x1d6b9c2f0a4e8d7c6b5a49382716f5e4d3c2b1a09f8e7d6c5b4a392817060504",
    ));
    let owner = point_to_wire(public_key(owner_secret));
    let body = register_like_body(owner);
    let register_msg = register_message(&body).unwrap();
    for (name, secret, message) in [
        ("rust_small_secret", small_secret, Fr::from(0x2bcu64)),
        ("rust_large_secret_max_message", large_secret, -Fr::one()),
        ("rust_register_body", owner_secret, register_msg),
    ] {
        vectors.push(Vector {
            name: name.into(),
            source: "sidecar-core schnorr::sign",
            pubkey: point_to_wire(public_key(secret)),
            signature: sign(secret, message, &mut rng),
            message,
            expected: true,
        });
    }

    // @aztec-labs/foundation 6.0.0 Schnorr.constructSignature(msg, sk) with
    // sk = 0x0123…cdef over the register message of the "small" body below.
    let ts_bytes: [u8; 64] = "0x297cda4c102742d5d8e78340925d705e7ba4c6f530a1f8c829c613261349f14615bb6481d37caa2c2cc38b092009ce8fa62153463a6cb796d88e45b8092d29f0"
        .parse::<sidecar_core::field::HexBytes>()
        .unwrap()
        .0
        .try_into()
        .unwrap();
    let small_body = json!({"b": "x", "a": 1, "c": [true, false, null, -7]});
    vectors.push(Vector {
        name: "typescript_signer".into(),
        source: "@aztec-labs/foundation 6.0.0 Schnorr.constructSignature (barretenberg 6.0.0)",
        pubkey: point(
            "0x1e80aee3834e1297b47c859a4a26339b5c7c4c4096342b360e2b7ba402d1873e",
            "0x0e3faf018f2e20f0811785d35bd8491f32e42833ede83ca1a5f3e1975ce7e25e",
        ),
        signature: signature_from_bytes(&ts_bytes),
        message: register_message(&small_body).unwrap(),
        expected: true,
    });

    // Refusals, all of which noir-lang/schnorr executes and answers false.
    vectors.push(Vector {
        name: "zero_signature".into(),
        source: "noir-lang/schnorr v0.4.0 test zero_signature",
        pubkey: point_to_wire(sidecar_core::grumpkin::generator()),
        signature: Signature::default(),
        message: Fr::from(0x1234u64),
        expected: false,
    });
    let base = vectors
        .iter()
        .find(|v| v.name == "rust_register_body")
        .map(|v| (v.pubkey, v.signature, v.message))
        .unwrap();
    let bump = |limb: FieldHex| {
        assert!(limb.fr().into_bigint() < hex("0xffffffffffffffffffffffffffffffff").into_bigint());
        FieldHex(limb.fr() + Fr::one())
    };
    let mut tampered = |name: &str, pubkey, signature, message| {
        vectors.push(Vector {
            name: format!("tampered_{name}"),
            source: "rust_register_body with one value changed",
            pubkey,
            signature,
            message,
            expected: false,
        })
    };
    let (pk, s, m) = base;
    tampered("message", pk, s, m + Fr::one());
    tampered(
        "key",
        point_to_wire(public_key(owner_secret + Fq::one())),
        s,
        m,
    );
    let mut bad = s;
    bad.s[0] = bump(bad.s[0]);
    tampered("s_lo", pk, bad, m);
    let mut bad = s;
    bad.e[0] = bump(bad.e[0]);
    tampered("e_lo", pk, bad, m);
    let bad = Signature { s: s.e, e: s.s };
    tampered("s_e_swapped", pk, bad, m);

    for v in &vectors {
        assert_eq!(
            verify_wire(&v.pubkey, v.signature, v.message),
            v.expected,
            "{}",
            v.name
        );
    }

    let signed_messages: Vec<Value> = [
        ("register_small", REGISTER_DOMAIN, small_body.clone()),
        (
            "register_unicode",
            REGISTER_DOMAIN,
            json!({
                "\u{20ac}": "\u{e9}\n\t\"\\\u{1}\u{1f}\u{7f}\u{2028}",
                "a": {"z": 0, "\u{1f600}": 1, "\u{ffff}": 2, "B": 3}
            }),
        ),
        ("register_like", REGISTER_DOMAIN, body.clone()),
        (
            "disable",
            DISABLE_DOMAIN,
            json!({"namespace": "0x1f2ea9c0", "circuit": "amm_swap"}),
        ),
        ("execute_small", EXECUTE_DOMAIN, small_body.clone()),
    ]
    .into_iter()
    .map(|(name, domain, body)| {
        json!({
            "name": name,
            "domain": domain,
            "body_without_signature": body,
            "canonical": canonical_json(&body).unwrap(),
            "message": fr_to_hex(message_for(domain, &body).unwrap()),
        })
    })
    .collect();

    let schnorr = json!({
        "scheme": "Schnorr over Grumpkin, noir-lang/schnorr v0.4.0: R = s*G + e*pk; accept iff pk on curve, s != 0, e != 0, R != infinity and poseidon2([DST, R.x, pk.x, pk.y, message]) == e.lo + e.hi*2^128; DST = poseidon2_hash_bytes(\"schnorr_grumpkin_poseidon2\") = 0x024c76938ed06b8ec1d9094b1013d190baa4011372f0604643bda812a63b832e",
        "encoding": "s and e as [lo, hi]: the low and high 128 bits of each scalar. The 64-byte SchnorrSignature of aztec.js/barretenberg is s || e, each 32 bytes big-endian: s.hi = bytes 0..16, s.lo = 16..32, e.hi = 32..48, e.lo = 48..64 (toLimbFields() = [s.lo, s.hi, e.lo, e.hi]).",
        "message_rule": "message = poseidon2_hash_bytes(domain || RFC 8785 JCS(body without its top-level signature field)); domain cosnark-sidecar/v1/register (REGISTER, owner), cosnark-sidecar/v1/disable (DISABLE, owner) or cosnark-sidecar/v1/execute (execute body supplying client-held records, requester); poseidon2_hash_bytes uses the aztec.js/protocol_types packing: 31-byte chunks, each read little-endian, then the Poseidon2 sponge over the chunks",
        "ts_signer_compatible": true,
        "ts_signer_compatible_note": "@aztec-labs/foundation 6.0.0 Schnorr.constructSignature (barretenberg 6.0.0 schnorrConstructSignature) produces signatures that this verifier and noir-lang/schnorr v0.4.0 accept (vector typescript_signer), and barretenberg 6.0.0 schnorrVerifySignature gives the expected answer on every vector here. Map its 64 bytes to limbs as in `encoding`.",
        "vectors": vectors.iter().map(|v| json!({
            "name": v.name,
            "source": v.source,
            "pubkey": v.pubkey,
            "signature": v.signature,
            "message": fr_to_hex(v.message),
            "expected": v.expected,
        })).collect::<Vec<_>>(),
        "signed_messages": signed_messages,
    });

    let npk_inputs = [
        (
            "pss_core_kat_register_derivation",
            hex("0x6d6173746572"),
            hex("0xc0ffee"),
        ),
        (
            "amm_like_namespace",
            hex("0x0b0e5a1f6c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b"),
            hex("0x1f2ea9c0d1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f6071829304a5b"),
        ),
        ("max_master_zero_namespace", -Fr::one(), Fr::from(0u64)),
    ];
    let npk_vectors: Vec<Value> = npk_inputs
        .iter()
        .map(|(name, master, namespace)| {
            let nsk = nsk_app_derive_public(*master, *namespace);
            let npk = npk_app(nsk);
            json!({
                "name": name,
                "master": fr_to_hex(*master),
                "namespace": fr_to_hex(*namespace),
                "nsk_app": fr_to_hex(nsk),
                "npk_app": point_to_wire(npk),
                "npk_app_hash": fr_to_hex(npk_app_hash(npk)),
            })
        })
        .collect();
    let npk = json!({
        "rule": "nsk_app = poseidon2([SIDECAR_NSK_APP, master, namespace]); npk_app = EmbeddedCurveScalar::from_field(nsk_app) * G; npk_app_hash = poseidon2([SIDECAR_NPK_APP, npk_app.x, npk_app.y]); SIDECAR_NSK_APP = 0x736964656361722e6e736b5f617070 (ASCII \"sidecar.nsk_app\"), SIDECAR_NPK_APP = 0x736964656361722e6e706b5f617070 (ASCII \"sidecar.npk_app\")",
        "vectors": npk_vectors,
    });

    let dir = repo().join("testvectors");
    std::fs::write(
        dir.join("schnorr.json"),
        serde_json::to_string_pretty(&schnorr).unwrap() + "\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("npk_app_hash.json"),
        serde_json::to_string_pretty(&npk).unwrap() + "\n",
    )
    .unwrap();

    // The shared client-node vectors.
    let keys = node_keys();
    let (records, thirds) = records_json(&keys);
    write_json("records.json", &records);
    let bodies = bodies_json(owner_secret, &mut StdRng::seed_from_u64(0x5c4e_0002));
    write_json("bodies.json", &bodies);
    let results = results_json(&keys, &thirds);
    write_json("results.json", &results);
    write_json("field_hex.json", &field_hex_json());

    // The Noir programs' inputs, from the vector files just written.
    std::fs::write(
        repo().join(SCHNORR_NOIR).join("Prover.toml"),
        schnorr_prover_toml(&schnorr, &npk, &bodies, &results, &vector("registry.json")),
    )
    .unwrap();
    std::fs::write(
        repo().join(AE_NOIR).join("Prover.toml"),
        ae_prover_toml(&vector("ae.json"), &records),
    )
    .unwrap();
}

/// The two Noir vector programs whose Prover.toml this file writes.
const SCHNORR_NOIR: &str = "testvectors/noir/schnorr_vectors";
const AE_NOIR: &str = "testvectors/noir/ae_vectors";

/// The committed Prover.toml of schnorr_vectors and ae_vectors are what the
/// committed vector files give: a vector file regenerated without its Noir
/// inputs fails here.
#[test]
fn noir_vector_inputs_match_the_vector_files() {
    let committed = |dir: &str| {
        std::fs::read_to_string(repo().join(dir).join("Prover.toml"))
            .unwrap_or_else(|e| panic!("{dir}/Prover.toml: {e}"))
    };
    let schnorr = schnorr_prover_toml(
        &vector("schnorr.json"),
        &vector("npk_app_hash.json"),
        &vector("bodies.json"),
        &vector("results.json"),
        &vector("registry.json"),
    );
    assert!(
        committed(SCHNORR_NOIR) == schnorr,
        "{SCHNORR_NOIR}/Prover.toml differs from the vector files: run write_vector_files"
    );
    let ae = ae_prover_toml(&vector("ae.json"), &vector("records.json"));
    assert!(
        committed(AE_NOIR) == ae,
        "{AE_NOIR}/Prover.toml differs from the vector files: run write_vector_files"
    );
}

// Prover.toml of testvectors/noir/schnorr_vectors: every Schnorr vector and
// every npk vector, then every signed body, result message and registry
// answer.
fn schnorr_prover_toml(
    schnorr: &Value,
    npk: &Value,
    bodies: &Value,
    results: &Value,
    registry: &Value,
) -> String {
    let signature_toml = |toml: &mut String, pk: &Value, sig: &Value| {
        let s = |v: &Value| v.as_str().unwrap().to_string();
        writeln!(
            toml,
            "pk_x = \"{}\"\npk_y = \"{}\"",
            s(&pk["x"]),
            s(&pk["y"])
        )
        .unwrap();
        writeln!(
            toml,
            "s_lo = \"{}\"\ns_hi = \"{}\"",
            s(&sig["s"][0]),
            s(&sig["s"][1])
        )
        .unwrap();
        writeln!(
            toml,
            "e_lo = \"{}\"\ne_hi = \"{}\"",
            s(&sig["e"][0]),
            s(&sig["e"][1])
        )
        .unwrap();
    };
    let mut toml =
        String::from("# Written by sidecar-core tests/write_vectors.rs from testvectors/*.json.\n");
    let vectors = schnorr["vectors"].as_array().unwrap();
    for v in vectors {
        writeln!(toml, "\n[[schnorr]]").unwrap();
        signature_toml(&mut toml, &v["pubkey"], &v["signature"]);
        writeln!(
            toml,
            "message = \"{}\"\nexpected = {}",
            v["message"].as_str().unwrap(),
            v["expected"].as_bool().unwrap()
        )
        .unwrap();
    }
    let npk_vectors = npk["vectors"].as_array().unwrap();
    for v in npk_vectors {
        writeln!(toml, "\n[[npk]]").unwrap();
        for key in ["master", "namespace", "nsk_app", "npk_app_hash"] {
            writeln!(toml, "{key} = \"{}\"", v[key].as_str().unwrap()).unwrap();
        }
    }
    let bodies_list = bodies["bodies"].as_array().unwrap();
    for b in bodies_list {
        writeln!(toml, "\n[[bodies]]").unwrap();
        signature_toml(&mut toml, &b["pubkey"], &b["body"]["signature"]);
        writeln!(
            toml,
            "message = \"{}\"\nexpected = true",
            b["message"].as_str().unwrap()
        )
        .unwrap();
    }
    let mut result_count = 0;
    for case in results["cases"].as_array().unwrap() {
        let commitments = case["commitments"].as_array().unwrap();
        assert_eq!(
            commitments.len(),
            2,
            "src/main.nr takes two commitments per round"
        );
        for n in case["nodes"].as_array().unwrap() {
            result_count += 1;
            let hashes = n["record_hashes"].as_array().unwrap();
            let mut padded: Vec<String> = hashes
                .iter()
                .map(|h| format!("\"{}\"", h.as_str().unwrap()))
                .collect();
            padded.resize(2, format!("\"{}\"", fr_to_hex(Fr::from(0u64))));
            writeln!(toml, "\n[[results]]").unwrap();
            writeln!(
                toml,
                "namespace = \"{}\"",
                results["namespace"].as_str().unwrap()
            )
            .unwrap();
            writeln!(
                toml,
                "request_id = \"{}\"",
                case["request_id"].as_str().unwrap()
            )
            .unwrap();
            writeln!(
                toml,
                "commitments = [\"{}\", \"{}\"]",
                commitments[0].as_str().unwrap(),
                commitments[1].as_str().unwrap()
            )
            .unwrap();
            writeln!(toml, "i = {}", n["node"]).unwrap();
            writeln!(
                toml,
                "thirds = {}\nrecord_hashes = [{}]",
                hashes.len(),
                padded.join(", ")
            )
            .unwrap();
            writeln!(
                toml,
                "sealed_hash = \"{}\"",
                n["sealed_hash"].as_str().unwrap()
            )
            .unwrap();
            writeln!(toml, "message = \"{}\"", n["message"].as_str().unwrap()).unwrap();
            signature_toml(&mut toml, &n["sig_pubkey"], &n["signature"]);
        }
    }
    let registry_results = registry["results"].as_array().unwrap();
    for r in registry_results {
        writeln!(toml, "\n[[registry]]").unwrap();
        for key in ["namespace", "vk_hash", "npk_app_hash", "message"] {
            writeln!(toml, "{key} = \"{}\"", r[key].as_str().unwrap()).unwrap();
        }
        let name = r["name"].as_str().unwrap();
        writeln!(
            toml,
            "name_hash = \"{}\"",
            fr_to_hex(sidecar_core::schnorr::poseidon2_hash_bytes(name.as_bytes()))
        )
        .unwrap();
        writeln!(
            toml,
            "seq = {}\ndisabled = {}\ni = {}",
            r["seq"], r["disabled"], r["node"]
        )
        .unwrap();
        signature_toml(&mut toml, &r["sig_pubkey"], &r["signature"]);
    }
    let main = std::fs::read_to_string(repo().join(SCHNORR_NOIR).join("src/main.nr")).unwrap();
    for (name, count) in [
        ("SCHNORR_VECTORS", vectors.len()),
        ("NPK_VECTORS", npk_vectors.len()),
        ("BODY_VECTORS", bodies_list.len()),
        ("RESULT_VECTORS", result_count),
        ("REGISTRY_VECTORS", registry_results.len()),
    ] {
        assert!(
            main.contains(&format!("global {name}: u32 = {count};")),
            "update {name} in schnorr_vectors/src/main.nr to {count}"
        );
    }

    toml
}

// Prover.toml of testvectors/noir/ae_vectors: one table per AE length
// (`ae1`, `ae2`, ...) and one array per record plaintext length (`rec6`, ...).
fn ae_prover_toml(ae: &Value, records: &Value) -> String {
    let s = |v: &Value| format!("\"{}\"", v.as_str().unwrap());
    let list = |v: &Value| {
        let items: Vec<String> = v.as_array().unwrap().iter().map(s).collect();
        format!("[{}]", items.join(", "))
    };
    let mut toml = String::from(
        "# Written by sidecar-core tests/write_vectors.rs from testvectors/ae.json and records.json.\n",
    );
    let lengths: Vec<u64> = ae["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v["n"].as_u64().unwrap())
        .collect();
    assert_eq!(
        lengths,
        [1, 2, 3, 4, 7, 10],
        "ae_vectors/src/main.nr takes these lengths"
    );
    for v in ae["vectors"].as_array().unwrap() {
        writeln!(toml, "\n[ae{}]", v["n"]).unwrap();
        for key in ["key", "nonce", "pattern_tag", "tag"] {
            writeln!(toml, "{key} = {}", s(&v[key])).unwrap();
        }
        writeln!(
            toml,
            "plaintext = {}\nciphertext = {}",
            list(&v["plaintext"]),
            list(&v["ciphertext"])
        )
        .unwrap();
    }
    let nodes = records["nodes"].as_array().unwrap();
    let mut by_len: std::collections::BTreeMap<usize, Vec<String>> = Default::default();
    for r in records["records"].as_array().unwrap() {
        for t in r["thirds"].as_array().unwrap() {
            let n = &nodes[t["node"].as_u64().unwrap() as usize];
            let mut entry = String::new();
            writeln!(
                entry,
                "enc_lo = {}\nenc_hi = {}",
                s(&n["enc_limbs"]["lo"]),
                s(&n["enc_limbs"]["hi"])
            )
            .unwrap();
            writeln!(
                entry,
                "enc_pk_x = {}\nenc_pk_y = {}",
                s(&n["enc_pk"]["x"]),
                s(&n["enc_pk"]["y"])
            )
            .unwrap();
            writeln!(
                entry,
                "record_key = {}\nkey_id_hash = {}",
                s(&n["record_key"]),
                s(&n["key_id_hash"])
            )
            .unwrap();
            writeln!(
                entry,
                "key_id = \"{}\"",
                fr_to_hex(hex(n["key_id"].as_str().unwrap()))
            )
            .unwrap();
            writeln!(entry, "machine = {}", r["owner_kind"] == "machine").unwrap();
            writeln!(
                entry,
                "owner_x = {}\nowner_y = {}",
                s(&t["owner"]["x"]),
                s(&t["owner"]["y"])
            )
            .unwrap();
            for key in ["namespace", "key_hash", "note_hash"] {
                writeln!(entry, "{key} = {}", s(&r[key])).unwrap();
            }
            writeln!(
                entry,
                "plaintext = {}\nnonce = {}",
                list(&t["plaintext"]),
                s(&t["nonce"])
            )
            .unwrap();
            writeln!(
                entry,
                "ciphertext = {}\ntag = {}",
                list(&t["ciphertext"]),
                s(&t["tag"])
            )
            .unwrap();
            writeln!(entry, "record_hash = {}", s(&t["record_hash"])).unwrap();
            by_len
                .entry(t["plaintext"].as_array().unwrap().len())
                .or_default()
                .push(entry);
        }
    }
    let shape: Vec<(usize, usize)> = by_len.iter().map(|(n, v)| (*n, v.len())).collect();
    assert_eq!(
        shape,
        [(6, 3), (8, 6)],
        "ae_vectors/src/main.nr takes rec6: [_; 3] and rec8: [_; 6]"
    );
    for (n, entries) in by_len {
        for entry in entries {
            writeln!(toml, "\n[[rec{n}]]\n{}", entry.trim_end()).unwrap();
        }
    }
    toml
}

// ---------------------------------------------------------------------------
// The shared client-node vectors: records, signed bodies, result messages and
// field-hex edge cases. Every value is computed with sidecar-core's own
// functions; the reader tests (tests/vectors.rs, pss-client
// test/vectors.test.ts) recompute them.
// ---------------------------------------------------------------------------

const NAMESPACE: u64 = 0x1f2ea9c0;

// ---------------------------------------------------------------------------
// shapes.json: the note-hash index rule and the vk hash of every example
// circuit, as REGISTER computes them. pss-client derives the same indices from
// the ABI and manifest (results.ts noteHashIndices) and the same hash from the
// vk fields (capsule.ts vkHashFromFields); tests/vectors.rs and
// test/vectors.test.ts check both against this file.
// ---------------------------------------------------------------------------

/// Every round circuit of the two examples, by example directory and name, in
/// the order shapes.json lists them. pss_seed is one compiled circuit with a
/// manifest per example (node-held in the AMM, client-held in Monty Hall).
const EXAMPLE_CIRCUITS: [(&str, &str); 7] = [
    ("examples/amm", "pss_seed"),
    ("examples/amm", "amm_init"),
    ("examples/amm", "amm_swap"),
    ("examples/monty-hall", "pss_seed"),
    ("examples/monty-hall", "monty_hall_init"),
    ("examples/monty-hall", "monty_hall_open_door"),
    ("examples/monty-hall", "monty_hall_finish"),
];

#[test]
#[ignore = "writes testvectors/shapes.json; needs scripts/prepare-data.sh; run on purpose"]
fn write_shapes_file() {
    let data = data_dir();
    let mut names: Vec<&str> = EXAMPLE_CIRCUITS.iter().map(|(_, n)| *n).collect();
    names.sort();
    names.dedup();
    let artifacts: Vec<Artifact> = names
        .iter()
        .map(|n| Artifact::read(&data.join("circuits").join(format!("{n}.json"))).unwrap())
        .collect();
    let crs = Crs::read(
        &data.join("bn254_g1.dat"),
        &data.join("bn254_g2.dat"),
        crs::crs_circuit_size(&artifacts),
    )
    .unwrap();
    let compiled: BTreeMap<String, Circuit> = artifacts
        .into_iter()
        .map(|a| {
            let c = Circuit::new(a, &crs.prover).unwrap();
            (c.name.clone(), c)
        })
        .collect();
    let circuits: Vec<Value> = EXAMPLE_CIRCUITS
        .iter()
        .map(|(example, name)| {
            let artifact = format!("machine/data/circuits/{name}.json");
            let abi_json = sidecar_test_fixtures::data::circuit_json(name)["abi"].clone();
            let abi: Abi = serde_json::from_value(abi_json.clone()).unwrap();
            let manifest = format!("{example}/manifests/{name}.json");
            let (_, shape) =
                check_manifest_value(&sidecar_test_fixtures::vectors::read(&manifest), &abi)
                    .unwrap_or_else(|e| panic!("{manifest}: {e}"));
            let circuit = &compiled[*name];
            assert_eq!(
                shape.public_input_count,
                circuit.public_input_count(),
                "{name}"
            );
            let vk_fields: Vec<Value> = circuit
                .vk
                .to_field_elements()
                .into_iter()
                .map(|x| Value::String(fr_to_hex(x)))
                .collect();
            json!({
                "example": example,
                "circuit": name,
                "artifact": artifact,
                "manifest": manifest,
                "abi": abi_json,
                "public_param_fields": shape.public_param_fields,
                "public_input_count": shape.public_input_count,
                "outputs": shape.outputs.iter().map(|o| json!({
                    "note_hash": o.note_hash,
                    "note_hash_index": o.note_hash_index,
                })).collect::<Vec<_>>(),
                "vk_fields": vk_fields,
                "vk_hash": fr_to_hex(circuit.vk_hash),
            })
        })
        .collect();
    write_json(
        "shapes.json",
        &json!({
            "description": "Per example circuit: the ABI of the compiled artifact, the manifest, the public-input index of each manifest output's note hash (public parameter fields first, then the output's place among the public return value's fields), and the bb verification key fields with their vk hash (poseidon2 over the fields), as sidecar-core computes them at REGISTER with the CRS. Written by sidecar-core tests/write_vectors.rs.",
            "circuits": circuits,
        }),
    );
}

fn write_json(name: &str, value: &Value) {
    std::fs::write(
        repo().join("testvectors").join(name),
        serde_json::to_string_pretty(value).unwrap() + "\n",
    )
    .unwrap();
}

/// The requester of the record vectors and of envelope.json: the key 5·G.
fn requester_secret() -> Fq {
    scalar_from_field(Fr::from(5u64))
}

// A replicated sharing of `x`, as envelope.rs's vectors draw it: x_0 and x_1
// from the seed, x_2 = x - x_0 - x_1.
fn sharing(x: Fr, seed: u64) -> [Fr; 3] {
    let x0 = poseidon2_hash(&[Fr::from(seed), Fr::from(0u64)]);
    let x1 = poseidon2_hash(&[Fr::from(seed), Fr::from(1u64)]);
    [x0, x1, x - x0 - x1]
}

/// One element of a stored vector in the clear.
#[derive(Clone, Copy)]
enum Spec {
    Public(Fr),
    /// The value and the seed of its sharing.
    Shared(Fr, u64),
}

impl Spec {
    fn third(self, i: usize) -> Elem {
        match self {
            Spec::Public(v) => Elem::Public(v),
            Spec::Shared(x, seed) => {
                let s = sharing(x, seed);
                Elem::Shared(Share::new(s[i], s[(i + 2) % 3]))
            }
        }
    }
    fn clear(self) -> Value {
        match self {
            Spec::Public(v) => json!({"public": fr_to_hex(v)}),
            Spec::Shared(x, _) => json!({"shared": fr_to_hex(x)}),
        }
    }
}

fn elem_json(e: &Elem) -> Value {
    match e {
        Elem::Public(v) => json!({"public": fr_to_hex(*v)}),
        Elem::Shared(s) => json!({"shared": [fr_to_hex(s.a), fr_to_hex(s.b)]}),
        #[allow(unreachable_patterns)]
        _ => panic!("a record element is public or shared"),
    }
}

struct RecordCase {
    name: &'static str,
    key: &'static str,
    note_hash: Fr,
    /// Machine-owned (owner = node i's own enc_pk) instead of the requester.
    machine: bool,
    value: Vec<Spec>,
}

fn record_cases() -> Vec<RecordCase> {
    vec![
        // envelope.json's Monty Hall game state: its thirds are that request's `c`.
        RecordCase {
            name: "client_b001",
            key: "0xb001",
            note_hash: Fr::from(0x77u64),
            machine: false,
            value: vec![Spec::Shared(Fr::from(42u64), 30)],
        },
        RecordCase {
            name: "client_b002",
            key: "0xb002",
            note_hash: Fr::from(0x78u64),
            machine: false,
            value: vec![
                Spec::Shared(Fr::from(7u64), 31),
                Spec::Public(Fr::from(0x2au64)),
            ],
        },
        // A sealed replaced vector of a node-held key, or a tip chain-held state.
        RecordCase {
            name: "machine_pool",
            key: "pool",
            note_hash: Fr::from(0x7au64),
            machine: true,
            value: vec![
                Spec::Public(Fr::from(1000u64)),
                Spec::Shared(Fr::from(0xdeadu64), 32),
            ],
        },
    ]
}

/// records.json, and each case's thirds by node (for the result vectors).
fn records_json(keys: &[NodeKeys]) -> (Value, Vec<Vec<Vec<u8>>>) {
    let ns = Fr::from(NAMESPACE);
    let requester = public_key(requester_secret());
    let nodes: Vec<Value> = keys
        .iter()
        .enumerate()
        .map(|(i, k)| {
            let (lo, hi) = scalar_to_limbs(k.enc_scalar());
            let (x, y) = coordinates(k.enc_pk());
            let id: String = k.key_id().iter().map(|b| format!("{b:02x}")).collect();
            assert_eq!(k.seal_key(), record_key(k.enc_scalar()));
            assert_eq!(k.key_id(), key_id(k.enc_pk()));
            json!({
                "node": i,
                "enc": scalar_to_hex(k.enc_scalar()),
                "enc_limbs": {"lo": fr_to_hex(lo), "hi": fr_to_hex(hi)},
                "enc_pk": point_to_wire(k.enc_pk()),
                "record_key": fr_to_hex(k.seal_key()),
                "key_id_hash": fr_to_hex(poseidon2_hash(&[x, y])),
                "key_id": format!("0x{id}"),
            })
        })
        .collect();
    let mut all_thirds = Vec::new();
    let records: Vec<Value> = record_cases()
        .iter()
        .map(|case| {
            let mut case_thirds = Vec::new();
            let thirds: Vec<Value> = keys
                .iter()
                .enumerate()
                .map(|(i, k)| {
                    let owner = if case.machine { k.enc_pk() } else { requester };
                    let elems: Vec<Elem> = case.value.iter().map(|s| s.third(i)).collect();
                    let mut plaintext = vec![ns, key_hash(case.key), case.note_hash];
                    plaintext.extend(encode_elements(&elems));
                    let nonce = associated_data(ns, case.key, case.note_hash, owner);
                    let (ct, tag) = sidecar_core::ae::encrypt(k.seal_key(), nonce, &plaintext);
                    let c =
                        sidecar_core::record::seal(k, ns, case.key, case.note_hash, owner, &elems);
                    let mut expected = k.key_id().to_vec();
                    for f in ct.iter().chain(std::iter::once(&tag)) {
                        expected.extend(fr_to_be_bytes(*f));
                    }
                    assert_eq!(c, expected, "{} node {i}", case.name);
                    let opened =
                        sidecar_core::record::open(k, ns, case.key, case.note_hash, owner, &c)
                            .unwrap();
                    assert_eq!(opened, elems);
                    let hash = record_hash(&c).unwrap();
                    case_thirds.push(c.clone());
                    json!({
                        "node": i,
                        "owner": point_to_wire(owner),
                        "elements": elems.iter().map(elem_json).collect::<Vec<_>>(),
                        "plaintext": plaintext.iter().map(|f| fr_to_hex(*f)).collect::<Vec<_>>(),
                        "nonce": fr_to_hex(nonce),
                        "ciphertext": ct.iter().map(|f| fr_to_hex(*f)).collect::<Vec<_>>(),
                        "tag": fr_to_hex(tag),
                        "c": HexBytes(c).to_string(),
                        "record_hash": fr_to_hex(hash),
                    })
                })
                .collect();
            all_thirds.push(case_thirds);
            json!({
                "name": case.name,
                "owner_kind": if case.machine { "machine" } else { "requester" },
                "namespace": fr_to_hex(ns),
                "key": case.key,
                "key_hash": fr_to_hex(key_hash(case.key)),
                "note_hash": fr_to_hex(case.note_hash),
                "value": case.value.iter().map(|s| s.clear()).collect::<Vec<_>>(),
                "thirds": thirds,
            })
        })
        .collect();
    // The Monty Hall record of envelope.json is the first case.
    let envelope = vector("envelope.json");
    let c: Vec<String> = all_thirds[0]
        .iter()
        .map(|c| HexBytes(c.clone()).to_string())
        .collect();
    assert_eq!(
        serde_json::to_value(&c).unwrap(),
        envelope["request"]["records"][0]["c"],
        "client_b001 is envelope.json's record"
    );
    let file = json!({
        "rules": {
            "record_key": "K_i = poseidon2([enc.lo, enc.hi, SIDECAR_SEAL_KEY]), enc.lo and enc.hi the low and high 128 bits of node i's enc scalar (testvectors/keys.json)",
            "key_id": "the first 8 bytes of key_id_hash = poseidon2([enc_pk.x, enc_pk.y]) written as 32 bytes big-endian",
            "key_hash": "poseidon2_hash_bytes(key), the aztec.js packing of the key string's UTF-8 bytes",
            "elements": "a stored vector's elements: {public: v} the same at every node, {shared: [x_i, x_(i-1)]} node i's pair of a replicated sharing; value lists the vector in the clear",
            "plaintext": "[namespace, key_hash, note_hash, then per element [0, v] (public) or [1, x_i, x_(i-1)] (shared)]",
            "nonce": "the record AD: poseidon2([namespace, key_hash, note_hash, owner.x, owner.y, SIDECAR_RECORD_AD])",
            "owner": "owner_kind requester: the requester key that created the record (5·G here); owner_kind machine: node i's own enc_pk (sealed replaced vectors, the tip's chain-held state)",
            "cipher": "(ciphertext, tag) = the Poseidon2 duplex AE of testvectors/ae.json with key K_i, the nonce and the plaintext",
            "c": "the sealed third: key_id (8 bytes) || ciphertext || tag, each field 32 bytes big-endian",
            "record_hash": "poseidon2([key_id as a big-endian integer, ciphertext..., tag]), the entry of record_hashes[i]",
            "client_b001": "the record of testvectors/envelope.json's request: its thirds are that request's c",
        },
        "sidecar_seal_key": fr_to_hex(label_field(SIDECAR_SEAL_KEY)),
        "sidecar_record_ad": fr_to_hex(label_field(SIDECAR_RECORD_AD)),
        "requester": {
            "secret": fr_to_hex(Fr::from(5u64)),
            "pubkey": point_to_wire(requester),
        },
        "nodes": nodes,
        "records": records,
    });
    (file, all_thirds)
}

/// bodies.json: one signed body per domain, with its canonical JCS form.
fn bodies_json(owner_secret: Fq, rng: &mut StdRng) -> Value {
    let owner = point_to_wire(public_key(owner_secret));
    // REGISTER: registry.json's pss_seed body (a real circuit and manifest),
    // under this owner, at seq 2.
    let mut register = vector("registry.json")["register"]["body"].clone();
    {
        let o = register.as_object_mut().unwrap();
        o.remove("signature");
        o.insert("owner_pubkey".into(), serde_json::to_value(owner).unwrap());
        o.insert("seq".into(), json!(2));
    }
    let mut disable = json!({
        "namespace": fr_to_hex(Fr::from(NAMESPACE)),
        "circuit": "pss_seed",
        "owner_pubkey": owner,
        "seq": 3,
    });
    let mut out = Vec::new();
    for (name, domain, body) in [
        ("register", REGISTER_DOMAIN, &mut register),
        ("disable", DISABLE_DOMAIN, &mut disable),
    ] {
        let canonical = canonical_json(body).unwrap();
        let message = message_for(domain, body).unwrap();
        assert_eq!(
            message,
            sidecar_core::schnorr::poseidon2_hash_bytes(format!("{domain}{canonical}").as_bytes())
        );
        let signature = sign(owner_secret, message, rng);
        body.as_object_mut()
            .unwrap()
            .insert("signature".into(), serde_json::to_value(signature).unwrap());
        out.push(json!({
            "name": name,
            "domain": domain,
            "signer": "owner",
            "secret": scalar_to_hex(owner_secret),
            "pubkey": owner,
            "body": body.clone(),
            "canonical": canonical,
            "message": fr_to_hex(message),
        }));
    }
    assert!(ManifestMessage::from_json(&register.to_string()).is_ok());
    assert!(DisableRequest::from_json(&disable.to_string()).is_ok());
    // EXECUTE: envelope.json's request (requester and a supplied record),
    // signed by its requester.
    let mut req: Request<Full> =
        Request::from_json(&vector("envelope.json")["request"].to_string()).unwrap();
    let canonical = canonical_json(&canonical_body(&req)).unwrap();
    let message = req.signed_message();
    assert_eq!(
        message,
        sidecar_core::schnorr::poseidon2_hash_bytes(
            format!("{EXECUTE_DOMAIN}{canonical}").as_bytes()
        )
    );
    let requester = point_to_wire(public_key(requester_secret()));
    assert_eq!(req.requester, Some(requester));
    req.signature = Some(sign(requester_secret(), message, rng));
    let body = serde_json::to_value(&req).unwrap();
    assert_eq!(Request::<Full>::from_json(&body.to_string()).unwrap(), req);
    out.push(json!({
        "name": "execute",
        "domain": EXECUTE_DOMAIN,
        "signer": "requester",
        "secret": fr_to_hex(Fr::from(5u64)),
        "pubkey": requester,
        "body": body,
        "canonical": canonical,
        "message": fr_to_hex(message),
    }));
    json!({
        "rules": {
            "message": "poseidon2_hash_bytes(domain || canonical), the aztec.js packing of the UTF-8 bytes",
            "canonical_registry": "REGISTER and DISABLE: RFC 8785 JCS of the body without its top-level signature",
            "canonical_execute": "execute: RFC 8785 JCS of the canonical body, the request without shares, c and signature (share_hashes and record_hashes stand in for them)",
            "signature": "Schnorr over Grumpkin (testvectors/schnorr.json) by pubkey = secret·G over message; REGISTER and DISABLE by the namespace owner, execute by the requester",
            "sources": "register is testvectors/registry.json's REGISTER body under another owner at seq 2; execute is testvectors/envelope.json's request with its signature",
        },
        "bodies": out,
    })
}

// The node's result signature, with the nonce derived as the pipeline
// derives it.
fn result_signature(keys: &NodeKeys, message: Fr) -> Signature {
    sign_derived(keys.sig_scalar(), RESULT_NONCE_LABEL, message)
}

/// One output of a result vector's round: key, state mode, note hash, and the
/// index of its records.json case when it is client-held.
type Output = (&'static str, &'static str, u64, Option<usize>);

/// results.json: the result-signature message of three rounds at every node.
fn results_json(keys: &[NodeKeys], thirds: &[Vec<Vec<u8>>]) -> Value {
    let ns = Fr::from(NAMESPACE);
    // (case, request id, outputs)
    let cases: [(&str, &str, [Output; 2]); 3] = [
        (
            "two_client_held_outputs",
            "0x5e1f0c2a9b7d4e3f8a6b1c0d2e4f6a8b",
            [
                ("0xb001", "client", 0x77, Some(0)),
                ("0xb002", "client", 0x78, Some(1)),
            ],
        ),
        (
            "one_client_held_output",
            "0x0f1e2d3c4b5a69788796a5b4c3d2e1f0",
            [
                ("0xb001", "client", 0x77, Some(0)),
                ("pool_total", "node", 0x7b, None),
            ],
        ),
        (
            "node_held_outputs",
            "0x7c6b5a4938271605f4e3d2c1b0a99887",
            [
                ("pool", "node", 0x7a, None),
                ("pool_total", "node", 0x7b, None),
            ],
        ),
    ];
    let out: Vec<Value> = cases
        .iter()
        .map(|(name, id, outputs)| {
            let request_id: RequestId = id.parse().unwrap();
            let commitments: Vec<Fr> = outputs.iter().map(|o| Fr::from(o.2)).collect();
            let nodes: Vec<Value> = keys
                .iter()
                .enumerate()
                .map(|(i, k)| {
                    let hashes: Vec<Fr> = outputs
                        .iter()
                        .filter_map(|o| o.3)
                        .map(|r| record_hash(&thirds[r][i]).unwrap())
                        .collect();
                    let sealed = sealed_hash(&hashes);
                    let message = result_message(ns, request_id, &commitments, i, sealed);
                    let signature = result_signature(k, message);
                    assert!(verify(k.sig_pk(), signature, message));
                    json!({
                        "node": i,
                        "sig_pubkey": point_to_wire(k.sig_pk()),
                        "record_hashes": hashes.iter().map(|h| fr_to_hex(*h)).collect::<Vec<_>>(),
                        "sealed_hash": fr_to_hex(sealed),
                        "message": fr_to_hex(message),
                        "signature": signature,
                    })
                })
                .collect();
            json!({
                "name": name,
                "request_id": request_id,
                "outputs": outputs.iter().map(|o| json!({
                    "key": o.0,
                    "state": o.1,
                    "note_hash": fr_to_hex(Fr::from(o.2)),
                    "record": o.3.map(|r| record_cases()[r].name),
                })).collect::<Vec<_>>(),
                "commitments": commitments.iter().map(|c| fr_to_hex(*c)).collect::<Vec<_>>(),
                "nodes": nodes,
            })
        })
        .collect();
    json!({
        "rules": {
            "message": "poseidon2([RESULT_DOMAIN, namespace, request_id, commitments..., i, sealed_hash]); RESULT_DOMAIN = ASCII \"sidecar.result\" as a big-endian integer",
            "commitments": "the note hashes of the round's outputs in manifest order",
            "sealed_hash": "H(sealed_i) = poseidon2(record_hashes), the record hashes of node i's new thirds in manifest order (a one-element list for one third), 0 when the round makes none; node-held outputs and sealed replaced vectors are not signed",
            "record_hashes": "the record_hash of the named case's third i in testvectors/records.json",
            "signature": "Schnorr over Grumpkin by node i's sig key (testvectors/keys.json), its nonce derived from the key and the message: StdRng (rand 0.8) seeded with the 32 big-endian bytes of poseidon2([ASCII \"sidecar.result_nonce\", sig.lo, sig.hi, message]), so a node signs one message one way; any valid signature verifies",
            "request_id": "a note-mode id: 128 bits, one field element",
        },
        "result_domain": fr_to_hex(Fr::from(RESULT_DOMAIN)),
        "namespace": fr_to_hex(ns),
        "cases": out,
    })
}

/// field_hex.json: the field-element and request-id spellings both sides
/// accept and refuse, and response documents with unknown fields.
fn field_hex_json() -> Value {
    const MODULUS: &str = "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001";
    const MAX: &str = "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000";
    let accepted = |texts: &[String]| -> Vec<Value> {
        texts
            .iter()
            .map(|t| json!({"text": t, "value": fr_to_hex(fr_from_hex(t).unwrap())}))
            .collect()
    };
    let field_ok: Vec<String> = [
        "0x1",
        "1",
        "0x0",
        "0xA002",
        "a002",
        "0x41d3000000000000000000000000beef",
    ]
    .iter()
    .map(|s| s.to_string())
    .chain([
        format!("0x{}", "0".repeat(64)),
        format!("0x{}1", "0".repeat(63)),
        format!("0x1{}", "0".repeat(63)),
        format!("0x{MAX}"),
        MAX.to_uppercase(),
    ])
    .collect();
    let field_refused: Vec<(String, &str)> = vec![
        ("".into(), "empty"),
        ("0x".into(), "no digits"),
        ("0X1".into(), "the prefix is 0x, lowercase"),
        ("0xzz".into(), "not hex"),
        ("0x-1".into(), "a sign"),
        ("-1".into(), "a sign"),
        ("+1".into(), "a sign"),
        (" 0x1".into(), "whitespace"),
        ("0x1 ".into(), "whitespace"),
        ("0x1_0".into(), "a separator"),
        (format!("0x{}", "0".repeat(65)), "65 digits"),
        (format!("0x0{MAX}"), "65 digits"),
        (format!("0x{MODULUS}"), "the modulus"),
        (
            "0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000002".into(),
            "the modulus plus one",
        ),
        (format!("0x{}", "f".repeat(64)), "2^256 - 1"),
    ];
    for (t, why) in &field_refused {
        assert!(fr_from_hex(t).is_err(), "{t:?} ({why})");
    }
    let id_ok: Vec<String> = vec![
        "0x41d3000000000000000000000000beef".into(),
        "0x41D3000000000000000000000000BEEF".into(),
        "0x1".into(),
        format!("0x{}5e1f0c2a9b7d4e3f8a6b1c0d2e4f6a8b", "0".repeat(32)),
        format!("0x{MAX}"),
    ];
    let id_refused: Vec<(String, &str)> = vec![
        (format!("0x{MODULUS}"), "the modulus"),
        (format!("0x{}", "f".repeat(64)), "2^256 - 1"),
        ("0x".into(), "no digits"),
        (format!("0x{}", "1".repeat(65)), "65 digits"),
        ("swap-41d3".into(), "not hex"),
    ];
    for (t, why) in &id_refused {
        assert!(t.parse::<RequestId>().is_err(), "{t:?} ({why})");
    }
    for t in &id_ok {
        let id: RequestId = t.parse().unwrap();
        assert_eq!(id.fr(), fr_from_hex(t).unwrap());
    }

    // Response documents both sides parse, each as the other side writes it.
    let registry = vector("registry.json");
    let keys = vector("keys.json");
    let sig = registry["results"][0]["signature"].clone();
    let sigs = json!([sig, sig, sig]);
    let owner = registry["owner_pubkey"].clone();
    let npk = "0x1f21c078530872675c230b247bed26ffce80c76ab6eeb360895ca8cbd8b92e16";
    let namespace = json!({
        "namespace": "0x1f2ea9c0",
        "owner_pubkey": owner,
        "seq": 2,
        "npk_app_hash": npk.to_uppercase().replace("0X", "0x"),
        "manifest_hash": registry["manifest"]["manifest_hash"],
    });
    let register = json!({
        "manifest_hash": registry["manifest"]["manifest_hash"],
        "packages_hash": registry["manifest"]["packages_hash"],
        "npk_app_hash": npk, "seq": 0, "signatures": sigs,
    });
    let disable = json!({
        "namespace": fr_to_hex(Fr::from(NAMESPACE)), "circuit": "pss_seed", "vk_hash": "0xabcd",
        "npk_app_hash": npk, "disabled": true, "seq": 1, "signatures": sigs,
    });
    let nodes = json!({"nodes": keys["nodes"].as_array().unwrap().iter()
        .map(|n| json!({"enc": n["enc_pk"], "sig": n["sig_pk"]})).collect::<Vec<_>>()});
    let with = |doc: &Value, path: &[&str], key: &str, value: Value| -> Value {
        let mut doc = doc.clone();
        let mut at = &mut doc;
        for p in path {
            at = match p.parse::<usize>() {
                Ok(i) => &mut at[i],
                Err(_) => &mut at[*p],
            };
        }
        at.as_object_mut().unwrap().insert(key.into(), value);
        doc
    };
    let documents: Vec<(&str, &str, Value, Option<&str>)> = vec![
        ("namespace_ok", "NamespaceResponse", namespace.clone(), None),
        (
            "namespace_unknown_field",
            "NamespaceResponse",
            with(&namespace, &[], "note", json!("x")),
            Some("unknown field `note`"),
        ),
        (
            "namespace_unknown_nested_field",
            "NamespaceResponse",
            with(&namespace, &["owner_pubkey"], "z", json!("0x1")),
            Some("unknown field `owner_pubkey.z`"),
        ),
        (
            "namespace_field_as_number",
            "NamespaceResponse",
            with(&namespace, &[], "namespace", json!(7)),
            Some("a field element is a hex string"),
        ),
        (
            "namespace_field_at_modulus",
            "NamespaceResponse",
            with(
                &namespace,
                &[],
                "npk_app_hash",
                json!(format!("0x{MODULUS}")),
            ),
            Some("at the modulus"),
        ),
        (
            "namespace_field_65_digits",
            "NamespaceResponse",
            with(
                &namespace,
                &[],
                "npk_app_hash",
                json!(format!("0x0{}", &npk[2..])),
            ),
            Some("65 digits"),
        ),
        (
            "namespace_seq_negative",
            "NamespaceResponse",
            with(&namespace, &[], "seq", json!(-1)),
            Some("seq is a non-negative integer"),
        ),
        (
            "namespace_seq_fraction",
            "NamespaceResponse",
            with(&namespace, &[], "seq", json!(1.5)),
            Some("seq is an integer"),
        ),
        ("register_ok", "ManifestResponse", register.clone(), None),
        (
            "register_unknown_field",
            "ManifestResponse",
            with(
                &register,
                &[],
                "registration",
                json!({"proof": "0x", "public_inputs": []}),
            ),
            Some(
                "unknown field `registration` (a node answer's, which the orchestrator does not forward)",
            ),
        ),
        (
            "register_unknown_signature_field",
            "ManifestResponse",
            with(&register, &["signatures", "1"], "r", json!("0x1")),
            Some("unknown field `signatures[1].r`"),
        ),
        (
            "register_packages_field",
            "ManifestResponse",
            with(&register, &[], "packages", json!([])),
            Some("unknown field `packages`"),
        ),
        ("disable_ok", "DisableResponse", disable.clone(), None),
        (
            "disable_unknown_field",
            "DisableResponse",
            with(&disable, &[], "name", json!("pss_seed")),
            Some("unknown field `name`"),
        ),
        ("nodes_ok", "NodesResponse", nodes.clone(), None),
        (
            "nodes_unknown_field",
            "NodesResponse",
            with(&nodes, &["nodes", "2"], "tls", json!("0x00")),
            Some("unknown field `nodes[2].tls`"),
        ),
    ];
    for (name, ty, doc, why) in &documents {
        let ok = match *ty {
            "NamespaceResponse" => serde_json::from_value::<NamespaceResponse>(doc.clone()).is_ok(),
            "ManifestResponse" => serde_json::from_value::<ManifestResponse>(doc.clone()).is_ok(),
            "DisableResponse" => serde_json::from_value::<DisableResponse>(doc.clone()).is_ok(),
            "NodesResponse" => NodesResponse::from_json(&doc.to_string()).is_ok(),
            _ => unreachable!(),
        };
        assert_eq!(ok, why.is_none(), "{name}");
    }
    json!({
        "rules": {
            "field": "a field element in JSON is a string: an optional 0x (lowercase), then 1 to 64 hex digits of either case, big-endian; refused at or above the BN254 scalar modulus, never reduced; written 0x + 64 lowercase digits (value)",
            "request_id": "the request id is one field element under the same rule",
            "documents": "response bodies both sides parse; accepted false means the parser refuses the whole body; unknown fields are refused at every level",
        },
        "modulus": format!("0x{MODULUS}"),
        "field_elements": {
            "accepted": accepted(&field_ok),
            "refused": field_refused.iter().map(|(t, why)| json!({"text": t, "why": why})).collect::<Vec<_>>(),
        },
        "request_ids": {
            "accepted": accepted(&id_ok),
            "refused": id_refused.iter().map(|(t, why)| json!({"text": t, "why": why})).collect::<Vec<_>>(),
        },
        "documents": documents.iter().map(|(name, ty, doc, why)| {
            let mut v = json!({"name": name, "type": ty, "json": doc, "accepted": why.is_none()});
            if let Some(why) = why {
                v.as_object_mut().unwrap().insert("why".into(), json!(why));
            }
            v
        }).collect::<Vec<_>>(),
    })
}
