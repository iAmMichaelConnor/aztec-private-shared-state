//! Execute and FETCH responses, the FETCH request, and `GET /v1/nodes`.

use serde::{Deserialize, Serialize};

use crate::error::{Refusal, parse_json};
use crate::field::{FieldHex, HexBytes, RequestId};
use crate::register::Signature;
use crate::request::{GrumpkinPoint, NODES};

/// A new state record as the orchestrator returns it to the client: the key,
/// the note hash and the three sealed thirds, node 0's first. The client
/// computes `record_hashes` itself when it presents the record again.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResultRecord {
    pub key: String,
    pub note_hash: FieldHex,
    pub c: [HexBytes; NODES],
}

/// A new state record as node i returns it: the key, the note hash and node
/// i's own sealed third.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeResultRecord {
    pub key: String,
    pub note_hash: FieldHex,
    pub c_i: HexBytes,
}

/// A committed round as the orchestrator returns it to the client, from
/// `POST /v1/execute` and again from `POST /v1/fetch`. It is the three nodes'
/// [`NodeResult`]s put together by [`Self::assemble`]: the parts they agree on
/// once, each record's three thirds side by side, and the three result
/// signatures in node order, so the client can check every node's signature
/// itself against the keys it pinned.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecuteResponse {
    pub request_id: RequestId,
    /// Poseidon2 of the bb verification-key fields; what a contract pins. The
    /// orchestrator takes it from its own package row: the package it resolved
    /// for an execute request, the package whose vk_hash the nodes' rows carry
    /// for a FETCH.
    pub vk_hash: FieldHex,
    /// The bb-format proof.
    pub proof: HexBytes,
    /// The raw public inputs, in circuit order. Splitting them into effects is the
    /// client's job (pss-client `splitEffects`).
    pub public_inputs: Vec<FieldHex>,
    /// The node-held keys this round stored.
    #[serde(default)]
    pub stored: Vec<String>,
    /// The new state records of client-held keys this round stored, in manifest
    /// output order, each with its three thirds.
    #[serde(default)]
    pub records: Vec<ResultRecord>,
    /// Node i's Schnorr signature over its result message
    /// ([`crate::pipeline::result_message`]) at index i. The three differ: each
    /// message names its node and covers that node's own thirds.
    pub signatures: [Signature; NODES],
}

impl ExecuteResponse {
    pub fn from_json(text: &str) -> Result<Self, Refusal> {
        parse_json(text)
    }

    /// Put the three nodes' answers together, node 0's first. They must agree
    /// on `request_id`, `proof`, `public_inputs`, `stored`, the number of
    /// records and each record's `key` and `note_hash`; any disagreement is
    /// `mpc_failure` (500) naming the field. Node i's `c_i` becomes `c[i]` of
    /// each record and node i's `signature` becomes `signatures[i]`.
    ///
    /// This checks agreement only. Verifying the proof and checking each
    /// signature against the pinned keys is the caller's job, before or after.
    pub fn assemble(
        request_id: RequestId,
        vk_hash: FieldHex,
        nodes: [NodeResult; NODES],
    ) -> Result<Self, Refusal> {
        let differ = |field: &str| Refusal::mpc_failure(format!("the nodes disagree on `{field}`"));
        if nodes.iter().any(|n| n.request_id != request_id) {
            return Err(differ("request_id"));
        }
        let [a, b, c] = &nodes;
        if a.proof != b.proof || a.proof != c.proof {
            return Err(differ("proof"));
        }
        if a.public_inputs != b.public_inputs || a.public_inputs != c.public_inputs {
            return Err(differ("public_inputs"));
        }
        if a.stored != b.stored || a.stored != c.stored {
            return Err(differ("stored"));
        }
        if a.records.len() != b.records.len() || a.records.len() != c.records.len() {
            return Err(differ("records"));
        }
        let mut records = Vec::with_capacity(a.records.len());
        for (k, ((ra, rb), rc)) in a.records.iter().zip(&b.records).zip(&c.records).enumerate() {
            for (name, same) in [
                ("key", ra.key == rb.key && ra.key == rc.key),
                (
                    "note_hash",
                    ra.note_hash == rb.note_hash && ra.note_hash == rc.note_hash,
                ),
            ] {
                if !same {
                    return Err(differ(&format!("records[{k}].{name}")));
                }
            }
            records.push(ResultRecord {
                key: ra.key.clone(),
                note_hash: ra.note_hash,
                c: [ra.c_i.clone(), rb.c_i.clone(), rc.c_i.clone()],
            });
        }
        let signatures = [a.signature, b.signature, c.signature];
        let [a, _, _] = nodes;
        Ok(ExecuteResponse {
            request_id,
            vk_hash,
            proof: a.proof,
            public_inputs: a.public_inputs,
            stored: a.stored,
            records,
            signatures,
        })
    }
}

/// Node i's answer to an execute request, and to a FETCH of a committed one:
/// what the request lifecycle returns ([`crate::pipeline::run_request`]).
/// The three nodes' answers agree on everything except each record's `c_i`
/// and `signature`; `signature` is node i's Schnorr signature with its `sig`
/// key over the result message ([`crate::pipeline::result_message`]).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeResult {
    pub request_id: RequestId,
    // The FETCH answer names the round's circuit by the vk_hash
    // its `requests` row stores, in this optional field, rather than in a
    // second answer type: an execute answer leaves it out (the orchestrator
    // resolved the package before it fanned out, and answers with that
    // package's vk_hash), and a FETCH answer always carries it, because the
    // FETCH body names no circuit and the package may have been disabled or
    // registered again under another vk since the round. The orchestrator
    // requires the three FETCH answers to carry the same vk_hash, picks the
    // package of the namespace with that vk_hash and verifies the proof under
    // it; a vk_hash no package of the namespace carries is 409.
    /// The vk_hash of the circuit the round ran under, from the node's
    /// `requests` row: present in a FETCH answer, absent from an execute
    /// answer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vk_hash: Option<FieldHex>,
    /// The bb-format proof.
    pub proof: HexBytes,
    /// The raw public inputs, in circuit order.
    pub public_inputs: Vec<FieldHex>,
    /// The node-held keys this round stored.
    #[serde(default)]
    pub stored: Vec<String>,
    /// This node's thirds of the round's new client-held records, in manifest
    /// output order.
    #[serde(default)]
    pub records: Vec<NodeResultRecord>,
    pub signature: Signature,
}

impl NodeResult {
    #[cfg(test)]
    pub fn from_json(text: &str) -> Result<Self, Refusal> {
        parse_json(text)
    }
}

/// `POST /v1/fetch`: a committed result again, looked up under `namespace` only.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FetchRequest {
    pub namespace: FieldHex,
    pub request_id: RequestId,
}

impl FetchRequest {
    pub fn from_json(text: &str) -> Result<Self, Refusal> {
        parse_json(text)
    }
}

// FETCH by chain request id is its own route,
// `POST /v1/fetch/chain` with `{namespace, chain_request_id}`, on the node
// and on the orchestrator, rather than an optional field of the FETCH body:
// a body names one lookup, so neither side has to rule on a body that names
// both, and the plain FETCH body stays one lookup by request id. It
// answers the latest committed attempt at the chain request (the requests
// row with the greatest created_at carrying it), 404 when none, 409 when the
// latest was rolled back: the relayer and clients read the result to land
// this way, and re-fetch after a revert.
/// `POST /v1/fetch/chain`: the latest committed attempt at a queued request,
/// looked up by its chain request id under `namespace`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChainFetchRequest {
    pub namespace: FieldHex,
    pub chain_request_id: FieldHex,
}

impl ChainFetchRequest {
    pub fn from_json(text: &str) -> Result<Self, Refusal> {
        parse_json(text)
    }
}

/// One node's two published public keys: `enc` for envelopes and record key
/// ids, `sig` for result, registry and receipt signatures.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodePublicKeys {
    pub enc: GrumpkinPoint,
    pub sig: GrumpkinPoint,
}

/// `GET /v1/nodes`: the three nodes' public keys, node 0 first.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodesResponse {
    pub nodes: [NodePublicKeys; NODES],
}

impl NodesResponse {
    pub fn from_json(text: &str) -> Result<Self, Refusal> {
        parse_json(text)
    }

    // Key pinning. Both public keys of every node are part of the
    // deployment's published identity and live in the client's and the
    // orchestrator's own configuration, beside the orchestrator URL and the vk
    // hashes; `GET /v1/nodes` is a convenience that a client checks against
    // those pins and never a source of keys. A client that took enc keys from
    // the orchestrator would let it substitute its own three, open every
    // envelope and re-encrypt to the real nodes unnoticed; taking sig keys
    // from it would let it forge results. During an enc rotation the pins must
    // be updated to the new enc key before the node's grace window closes.
    /// Refuse an answer that differs from the pinned keys (`mpc_failure`, naming
    /// the first node and key that differ): the client must not use it.
    pub fn check_pins(&self, pinned: &NodesResponse) -> Result<(), Refusal> {
        for (i, (got, want)) in self.nodes.iter().zip(&pinned.nodes).enumerate() {
            for (name, a, b) in [("enc", got.enc, want.enc), ("sig", got.sig, want.sig)] {
                if a != b {
                    return Err(Refusal::mpc_failure(format!(
                        "node {i}'s {name} key differs from the pinned key"
                    )));
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ErrorClass;
    use serde_json::json;

    const ID: &str = "0x0000000000000000000000000000000041d3000000000000000000000000beef";

    fn id() -> RequestId {
        serde_json::from_value(json!(ID)).unwrap()
    }

    fn sig(n: u64) -> Signature {
        Signature {
            s: [FieldHex::from(n), FieldHex::from(n + 1)],
            e: [FieldHex::from(n + 2), FieldHex::from(n + 3)],
        }
    }

    /// Node i's answer: the shared parts, its own third `0x0i` and its own
    /// signature.
    fn node_result(i: u8) -> NodeResult {
        serde_json::from_value(json!({
            "request_id": ID,
            "proof": "0xabcdef",
            "public_inputs": ["0x1f2ea9c0", "0xafafaf", "0xa002"],
            "stored": ["0xa002"],
            "records": [{"key": "0xb001", "note_hash": "0x99", "c_i": format!("0x0{i}")}],
            "signature": sig(10 * u64::from(i) + 1),
        }))
        .unwrap()
    }

    fn nodes() -> [NodeResult; NODES] {
        [node_result(0), node_result(1), node_result(2)]
    }

    #[test]
    fn the_design_page_response_parses_with_defaults() {
        let r = ExecuteResponse::from_json(
            &json!({
                "request_id": ID,
                "vk_hash": "0x1",
                "proof": "0x00",
                "public_inputs": ["0x1f2ea9c0", "0xafafaf"],
                "stored": ["0xa002"],
                "signatures": [sig(1), sig(2), sig(3)],
            })
            .to_string(),
        )
        .unwrap();
        assert!(r.records.is_empty());
        let text = serde_json::to_string(&r).unwrap();
        assert_eq!(ExecuteResponse::from_json(&text).unwrap(), r);
        let mut v: serde_json::Value = serde_json::from_str(&text).unwrap();
        v["effects"] = json!({});
        let err = ExecuteResponse::from_json(&v.to_string()).unwrap_err();
        assert_eq!(err.class, ErrorClass::BadRequest);
        // The signatures are required, and there are exactly three.
        let mut v: serde_json::Value = serde_json::from_str(&text).unwrap();
        v.as_object_mut().unwrap().remove("signatures");
        assert!(ExecuteResponse::from_json(&v.to_string()).is_err());
        v["signatures"] = json!([sig(1), sig(2)]);
        assert!(ExecuteResponse::from_json(&v.to_string()).is_err());
    }

    #[test]
    fn assembly_puts_each_third_and_signature_in_its_place() {
        let full = ExecuteResponse::assemble(id(), FieldHex::from(0x1234), nodes()).unwrap();
        assert_eq!(full.request_id, id());
        assert_eq!(full.vk_hash, FieldHex::from(0x1234));
        for i in 0..NODES {
            assert_eq!(full.records[0].c[i].0, vec![i as u8]);
            assert_eq!(full.signatures[i], sig(10 * i as u64 + 1));
        }
        assert_ne!(full.records[0].c[0], full.records[0].c[1]);
        assert_ne!(full.signatures[1], full.signatures[2]);
        assert_eq!(full.stored, ["0xa002"]);
        assert_eq!(full.public_inputs.len(), 3);
        let text = serde_json::to_string(&full).unwrap();
        let value: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(value["records"][0]["c"].as_array().unwrap().len(), NODES);
        assert_eq!(value["signatures"].as_array().unwrap().len(), NODES);
        assert_eq!(ExecuteResponse::from_json(&text).unwrap(), full);
        // A node answer round-trips in its own format.
        let node = node_result(1);
        let text = serde_json::to_string(&node).unwrap();
        assert_eq!(NodeResult::from_json(&text).unwrap(), node);
    }

    #[test]
    fn a_fetch_answer_carries_the_vk_hash_and_an_execute_answer_omits_it() {
        let execute = node_result(0);
        assert_eq!(execute.vk_hash, None);
        let text = serde_json::to_string(&execute).unwrap();
        assert!(!text.contains("vk_hash"), "{text}");
        let mut fetched = execute.clone();
        fetched.vk_hash = Some(FieldHex::from(0x77));
        let text = serde_json::to_string(&fetched).unwrap();
        let value: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(value["vk_hash"], json!(FieldHex::from(0x77)));
        assert_eq!(NodeResult::from_json(&text).unwrap(), fetched);
    }

    #[test]
    fn disagreement_is_an_mpc_failure_naming_the_field() {
        let refuse = |nodes: [NodeResult; NODES], field: &str| {
            let err = ExecuteResponse::assemble(id(), FieldHex::from(0x1234), nodes).unwrap_err();
            assert_eq!(err.class, ErrorClass::MpcFailure);
            assert_eq!(err.status(), 500);
            assert!(err.message.contains(field), "{err}");
        };
        let mut n = nodes();
        n[2].records[0].note_hash = FieldHex::from(1);
        refuse(n, "records[0].note_hash");
        let mut n = nodes();
        n[1].records[0].key = "0xb002".into();
        refuse(n, "records[0].key");
        let mut n = nodes();
        n[0].records.clear();
        refuse(n, "records");
        let mut n = nodes();
        n[1].proof = HexBytes(vec![1]);
        refuse(n, "proof");
        let mut n = nodes();
        n[0].public_inputs.pop();
        refuse(n, "public_inputs");
        let mut n = nodes();
        n[2].stored.clear();
        refuse(n, "stored");
        let mut n = nodes();
        n[1].request_id = serde_json::from_value(json!("0x41d3")).unwrap();
        refuse(n, "request_id");
        // The three agreeing with each other but not with the request is refused too.
        let other: RequestId = serde_json::from_value(json!("0x41d3")).unwrap();
        let err = ExecuteResponse::assemble(other, FieldHex::from(0x1234), nodes()).unwrap_err();
        assert!(err.message.contains("request_id"), "{err}");
    }

    #[test]
    fn fetch_and_nodes_bodies() {
        let f =
            FetchRequest::from_json(&json!({"namespace": "0x1f2e", "request_id": ID}).to_string())
                .unwrap();
        assert_eq!(f.request_id.to_string(), ID);
        assert!(
            FetchRequest::from_json(
                &json!({"namespace": "0x1f2e", "request_id": "0x41d3zz"}).to_string()
            )
            .is_err()
        );
        assert!(
            FetchRequest::from_json(
                &json!({"namespace": "0x1f2e", "request_id": ID, "circuit": "x"}).to_string()
            )
            .is_err()
        );
    }

    #[test]
    fn nodes_response_round_trips_with_enc_and_sig_per_node() {
        let pinned = NodesResponse {
            nodes: [0, 1, 2].map(|i| crate::keys::tests::sample_keys(i).public_keys()),
        };
        let text = serde_json::to_string(&pinned).unwrap();
        let value: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(value["nodes"].as_array().unwrap().len(), 3);
        assert_eq!(
            value["nodes"][1]["sig"],
            serde_json::to_value(crate::grumpkin::point_to_wire(
                crate::keys::tests::sample_keys(1).sig_pk()
            ))
            .unwrap()
        );
        let back = NodesResponse::from_json(&text).unwrap();
        assert_eq!(back, pinned);
        back.check_pins(&pinned).unwrap();
        // An answer with one substituted key is refused, naming it.
        let mut swapped = pinned;
        swapped.nodes[2].enc = crate::keys::tests::sample_keys(0).public_keys().enc;
        let err = swapped.check_pins(&pinned).unwrap_err();
        assert!(err.message.contains("node 2's enc"), "{err}");
        let mut swapped = pinned;
        swapped.nodes[0].sig = swapped.nodes[0].enc;
        assert!(
            swapped
                .check_pins(&pinned)
                .unwrap_err()
                .message
                .contains("node 0's sig")
        );

        let p = json!({"x": "0x1", "y": "0x2"});
        let k = json!({"enc": p, "sig": p});
        assert!(NodesResponse::from_json(&json!({"nodes": [k, k, k]}).to_string()).is_ok());
        for bad in [
            json!({"nodes": [k, k]}),
            json!({"nodes": [p, p, p]}),
            json!({"nodes": [k, k, {"enc": p}]}),
            json!({"nodes": [k, k, {"enc": p, "sig": p, "tls": p}]}),
        ] {
            let err = NodesResponse::from_json(&bad.to_string()).unwrap_err();
            assert_eq!(err.class, ErrorClass::BadRequest);
        }
    }
}
