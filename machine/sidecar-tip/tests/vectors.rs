//! Reads testvectors/tip_results.json (written by this crate's `vectors`
//! module) and checks it against sidecar-core and sidecar-tip: the ids of
//! each chain-held round, each node's third sealed for itself, the result
//! messages and signatures, the sealed-thirds log as `SealedLog` encodes and
//! decodes it, and REGISTER's size bound. sidecar-core's `tests/vectors.rs`
//! reads every other file of testvectors/.
//!
//! ```sh
//! cargo test --release -p sidecar-tip --test vectors
//! ```

use ark_ff::{One, PrimeField};
use serde_json::Value;
use sidecar_core::ae;
use sidecar_core::bind::{Elem, Share};
use sidecar_core::field::{Fr, HexBytes, RequestId, fr_to_hex};
use sidecar_core::grumpkin::point_to_wire;
use sidecar_core::hash::{poseidon2_hash, poseidon2_hash_with_separator};
use sidecar_core::keys::label_field;
use sidecar_core::pipeline::{RESULT_DOMAIN, result_message, sealed_hash};
use sidecar_core::record::{
    self, associated_data, encode_elements, key_hash, record_hash, third_fields, third_fields_len,
};
use sidecar_core::request::NODES;
use sidecar_core::schnorr::verify_wire;
use sidecar_test_fixtures::vectors::{fields, hex_value, node_keys, point, signature, vector};
use sidecar_tip::state::chain::{
    FLAT_PUBLIC_LOGS_PAYLOAD_LENGTH, MAX_PUBLIC_LOG_SIZE_IN_FIELDS, PUBLIC_LOG_HEADER_LENGTH,
    SealedLog, apply_log_fields, sealed_thirds_fields, third_from_fields,
};

fn hex(value: Fr) -> Value {
    Value::String(fr_to_hex(value))
}

/// The tip's chain-held results (sidecar-tip's tests/write_vectors writes the
/// file; pss-client and testvectors/noir/tip_result_vectors check against
/// it): per round the ids, each node's third sealed for itself and opened
/// by it alone, H(sealed_i), the result message over the machine request id
/// and node i's signature, the sealed-thirds log body as `SealedLog` encodes
/// and decodes it, and REGISTER's size count and verdict.
#[test]
fn tip_results_json() {
    let file = vector("tip_results.json");
    let keys = node_keys();
    let pss_attempt = label_field(b"sidecar.attempt");
    assert_eq!(hex(pss_attempt), file["pss_attempt"]);
    assert_eq!(hex(Fr::from(RESULT_DOMAIN)), file["result_domain"]);
    let pss_state = u32::try_from(file["pss_state"].as_u64().unwrap()).unwrap();
    assert_eq!(&pss_state.to_be_bytes(), b"PSS\x02");
    assert_eq!(file["pss_state"], vector("log_tags.json")["pss_state"]);
    let public_log = &file["public_log"];
    assert_eq!(
        public_log["payload_fields"],
        FLAT_PUBLIC_LOGS_PAYLOAD_LENGTH
    );
    assert_eq!(public_log["header_fields"], PUBLIC_LOG_HEADER_LENGTH);
    assert_eq!(public_log["max_log_fields"], MAX_PUBLIC_LOG_SIZE_IN_FIELDS);
    assert_eq!(MAX_PUBLIC_LOG_SIZE_IN_FIELDS, 4096 - 2);
    let rounds = file["rounds"].as_array().unwrap();
    assert_eq!(rounds.len(), 2);
    for r in rounds {
        let name = r["name"].as_str().unwrap();
        let ns = hex_value(&r["namespace"]);
        let key = r["key"].as_str().unwrap();
        assert_eq!(hex(key_hash(key)), r["key_hash"], "{name}");
        // the ids
        let inputs_hash = poseidon2_hash(&fields(&r["inputs"]));
        assert_eq!(hex(inputs_hash), r["inputs_hash"], "{name}");
        let chain = poseidon2_hash(&[
            ns,
            hex_value(&r["vk_hash"]),
            inputs_hash,
            hex_value(&r["user_nonce"]),
        ]);
        assert_eq!(hex(chain), r["chain_request_id"], "{name}");
        let mut attempt = vec![pss_attempt, chain];
        attempt.extend(fields(&r["old_commitments"]));
        attempt.extend(fields(&r["reads"]));
        let machine = poseidon2_hash(&attempt);
        assert_eq!(hex(machine), r["machine_request_id"], "{name}");
        let new_commitments = fields(&r["new_commitments"]);
        assert_eq!(new_commitments.len(), 1);
        let note_hash = new_commitments[0];
        let len = r["len"].as_u64().unwrap() as usize;
        let clear = fields(
            &r["value"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v["shared"].clone())
                .collect::<Value>(),
        );
        assert_eq!(clear.len(), len);

        // the thirds: sealed by node i for itself, opened by it alone
        let thirds = r["thirds"].as_array().unwrap();
        assert_eq!(thirds.len(), NODES);
        let mut cs: Vec<Vec<u8>> = Vec::new();
        let mut sums = vec![Fr::from(0u64); len];
        for (i, t) in thirds.iter().enumerate() {
            assert_eq!(t["node"], i);
            let k = &keys[i];
            assert_eq!(
                point(&t["owner"]),
                point_to_wire(k.enc_pk()),
                "{name} node {i}"
            );
            let elems: Vec<Elem> = t["elements"]
                .as_array()
                .unwrap()
                .iter()
                .map(|p| Elem::Shared(Share::new(hex_value(&p[0]), hex_value(&p[1]))))
                .collect();
            let mut plaintext = vec![ns, key_hash(key), note_hash];
            plaintext.extend(encode_elements(&elems));
            assert_eq!(fields(&t["plaintext"]), plaintext, "{name} node {i}");
            let nonce = associated_data(ns, key, note_hash, k.enc_pk());
            assert_eq!(hex(nonce), t["nonce"]);
            let (ct, tag) = ae::encrypt(k.seal_key(), nonce, &plaintext);
            assert_eq!(ct, fields(&t["ciphertext"]), "{name} node {i}");
            assert_eq!(hex(tag), t["tag"]);
            let c: HexBytes = serde_json::from_value(t["c"].clone()).unwrap();
            assert_eq!(
                record::seal(k, ns, key, note_hash, k.enc_pk(), &elems),
                c.0,
                "{name} node {i}"
            );
            let third = third_fields(&c.0).unwrap();
            assert_eq!(third, fields(&t["fields"]), "{name} node {i}");
            assert_eq!(third.len(), third_fields_len(len));
            assert_eq!(third_from_fields(&third).unwrap(), c.0);
            assert_eq!(third[0], Fr::from_be_bytes_mod_order(&k.key_id()));
            assert_eq!(hex(record_hash(&c.0).unwrap()), t["record_hash"]);
            assert_eq!(hex(poseidon2_hash(&third)), t["record_hash"]);
            assert_eq!(
                record::open_own(k, ns, key, note_hash, &c.0).unwrap(),
                elems
            );
            assert!(record::open_own(&keys[(i + 1) % NODES], ns, key, note_hash, &c.0).is_err());
            assert!(record::open_own(k, ns, key, note_hash + Fr::one(), &c.0).is_err());
            for (j, e) in elems.iter().enumerate() {
                let Elem::Shared(s) = e else { unreachable!() };
                sums[j] += s.a;
            }
            cs.push(c.0);
        }
        assert_eq!(sums, clear, "{name}: one replicated sharing of the value");
        for j in 0..len {
            for i in 0..NODES {
                assert_eq!(
                    thirds[i]["elements"][j][1],
                    thirds[(i + 2) % NODES]["elements"][j][0],
                    "{name}: x_(i-1)"
                );
            }
        }

        // H(sealed_i), the messages and the signatures
        for (i, n) in r["nodes"].as_array().unwrap().iter().enumerate() {
            assert_eq!(n["node"], i);
            assert_eq!(point(&n["sig_pk"]), point_to_wire(keys[i].sig_pk()));
            let hashes = fields(&n["record_hashes"]);
            assert_eq!(hashes, [record_hash(&cs[i]).unwrap()], "{name} node {i}");
            let sealed = sealed_hash(&hashes);
            assert_eq!(sealed, poseidon2_hash(&hashes));
            assert_eq!(hex(sealed), n["sealed_hash"], "{name} node {i}");
            let mut preimage = vec![Fr::from(RESULT_DOMAIN), ns, machine];
            preimage.extend(&new_commitments);
            preimage.extend([Fr::from(i as u64), sealed]);
            assert_eq!(fields(&n["message_preimage"]), preimage, "{name} node {i}");
            let message = result_message(ns, RequestId(machine), &new_commitments, i, sealed);
            assert_eq!(message, poseidon2_hash(&preimage));
            assert_eq!(hex(message), n["message"], "{name} node {i}");
            let sig = signature(&n["signature"]);
            let pk = point_to_wire(keys[i].sig_pk());
            assert!(verify_wire(&pk, sig, message), "{name} node {i}");
            let other = point_to_wire(keys[(i + 1) % NODES].sig_pk());
            assert!(!verify_wire(&other, sig, message), "{name} node {i}");
            let over_chain = result_message(ns, RequestId(chain), &new_commitments, i, sealed);
            assert!(!verify_wire(&pk, sig, over_chain), "{name} node {i}");
        }

        // the sealed-thirds log
        let log = &r["sealed_log"];
        assert_eq!(
            hex(poseidon2_hash_with_separator(&[chain], pss_state)),
            log["tag"],
            "{name}"
        );
        assert_eq!(
            (log["writes"].as_u64(), log["chain_outputs"].as_u64()),
            (Some(1), Some(1))
        );
        let third_len = log["third_len"].as_u64().unwrap() as usize;
        assert_eq!(third_len, 3 * len + 5);
        assert_eq!(third_len, third_fields_len(len));
        let body = fields(&log["body"]);
        assert_eq!(body.len(), 1 + 3 * third_len, "{name}: W + 3·T·L");
        let mut expected = new_commitments.clone();
        for c in &cs {
            expected.extend(third_fields(c).unwrap());
        }
        assert_eq!(body, expected, "{name}: commitments, then node by node");
        let sealed_log = SealedLog {
            new_commitments: new_commitments.clone(),
            thirds: vec![cs.clone().try_into().unwrap()],
        };
        assert_eq!(sealed_log.to_fields().unwrap(), body);
        assert_eq!(SealedLog::from_fields(&body, 1, 1).unwrap(), sealed_log);

        // REGISTER's count
        let reg = &r["register"];
        assert_eq!(reg["len"], len);
        let size = sealed_thirds_fields(len);
        assert_eq!(size, 9 * len + 15);
        assert_eq!(size, 3 * third_len);
        assert_eq!(reg["sealed_thirds_fields"], size);
        assert_eq!(reg["chain_outputs"], 1);
        assert_eq!(reg["writes"], 1);
        let log_fields = apply_log_fields(1, [len]);
        assert_eq!(log_fields, 1 + body.len(), "{name}: the tag, then the body");
        assert_eq!(reg["log_fields"], log_fields);
        assert_eq!(reg["accepted"], log_fields <= MAX_PUBLIC_LOG_SIZE_IN_FIELDS);
    }
    let bound: Vec<(usize, usize, usize, bool)> = file["register_bound"]
        .as_array()
        .unwrap()
        .iter()
        .map(|b| {
            let len = b["len"].as_u64().unwrap() as usize;
            let t = b["chain_outputs"].as_u64().unwrap() as usize;
            assert_eq!(b["writes"], t);
            let size = t * sealed_thirds_fields(len);
            assert_eq!(b["sealed_thirds_fields"], size);
            let log_fields = apply_log_fields(t, vec![len; t]);
            assert_eq!(log_fields, 1 + t + 9 * t * len + 15 * t);
            assert_eq!(b["log_fields"], log_fields);
            assert_eq!(b["accepted"], log_fields <= MAX_PUBLIC_LOG_SIZE_IN_FIELDS);
            (len, t, log_fields, b["accepted"].as_bool().unwrap())
        })
        .collect();
    // one output: 453 elements fill a log exactly; three of 150 have their
    // thirds (4,095) under 4,096 but not their log (4,099) under 4,094
    assert_eq!(
        bound,
        [
            (453, 1, 4094, true),
            (454, 1, 4103, false),
            (149, 3, 4072, true),
            (150, 3, 4099, false)
        ]
    );
}
