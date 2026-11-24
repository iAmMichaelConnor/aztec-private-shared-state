//! The orchestrator's receipt route over node stubs: it fixes
//! `expiry_block = current_block + receipt_ttl_blocks`, forwards the body
//! with it to the three nodes, and returns the three signatures only when
//! the answers agree with each other and with its own ids and each verifies
//! under the node's pinned `sig` key (500 naming the node otherwise); a
//! client-set expiry, invalid inputs or a package that takes no receipts are
//! refused (400) before any node is called. Under secret-shared receipt intake
//! (testvectors/shared_intake.json) it checks every envelope against its
//! share hash and the summand commitments, the layout and the clear inputs
//! against the sharing digest before
//! any node is called (400), sends node i only its own envelope of each
//! shared input and of the salts with the three hashes, the commitments and
//! the digest, and returns the receipts only when each verifies over C and
//! the digest (500 naming the node otherwise).
//!
//! The stubs sign with the keys the orchestrator pins (`stub_keys`), on
//! sidecar-tip's signer; the registry copy holds an `intake:
//! receipt` package written directly. Needs the CRS of
//! `scripts/prepare-data.sh` (a test fails naming what is missing). Run with
//! `--release`.

mod common;

use std::sync::Arc;

use axum::http::Method;
use common::*;
use serde_json::{Value, json};
use sidecar_core::field::{FieldHex, Fr};
use sidecar_core::grumpkin::Fq;
use sidecar_core::store::{NamespaceRow, PackageRow, Store};
use sidecar_core::{ErrorClass, Refusal};
use sidecar_http::client::Answer;
use sidecar_test_fixtures::receipts::{NS, VK_HASH, abi, manifest, manifest_row, package};
use sidecar_test_fixtures::vectors::{hex_value, shared_intake, shared_receipt_client};
use sidecar_tip::{
    ReceiptAnswer, ReceiptRequest, ReceiptResponse, chain_request_id, inputs_hash,
    shared_chain_request_id, shared_receipt_message, sign_receipt, sign_receipt_message,
    verify_receipt,
};

/// How the stubs answer a receipt: node i signs honestly with its own key,
/// then `tamper` may change node i's answer.
type Tamper = fn(usize, &mut ReceiptAnswer);

fn honest(_: usize, _: &mut ReceiptAnswer) {}

fn stub_receipts(tamper: Tamper) -> Respond {
    let keys = stub_keys();
    let pins = pins_of(&keys).nodes;
    let fallback = default_respond(pins);
    Arc::new(move |i, method, path, body| {
        if method != Method::POST || path != "/v1/receipt" {
            return fallback(i, method, path, body);
        }
        let req = ReceiptRequest::from_json(std::str::from_utf8(body).unwrap()).unwrap();
        let expiry = req.expiry_block.expect("the orchestrator sets the expiry");
        let (id, ih, message) = match req.inputs_hash {
            // secret-shared receipt intake: the id commits to C, the receipt
            // to C and the sharing digest
            Some(c) => {
                let id = shared_chain_request_id(req.namespace.fr(), shared_vk_hash(), c.fr());
                let d = req.sharing_digest.expect("a shared request carries D").fr();
                (id, c.fr(), shared_receipt_message(id, c.fr(), expiry, d))
            }
            None => {
                let inputs: Vec<Fr> = ["amount_in", "direction", "min_out", "partial_note"]
                    .iter()
                    .map(|n| match &req.inputs[*n] {
                        sidecar_core::request::PublicValue::One(v) => v.fr(),
                        other => panic!("{other:?}"),
                    })
                    .collect();
                let id = chain_request_id(
                    req.namespace.fr(),
                    Fr::from(VK_HASH),
                    &inputs,
                    req.user_nonce.unwrap().fr(),
                );
                let ih = inputs_hash(&inputs);
                (id, ih, sidecar_tip::receipt_message(id, ih, expiry))
            }
        };
        let mut answer = ReceiptAnswer {
            request_id: FieldHex(id),
            inputs_hash: FieldHex(ih),
            expiry_block: expiry,
            signature: sign_receipt_message(keys[i].sig_scalar(), message),
        };
        tamper(i, &mut answer);
        ok_json(&answer)
    })
}

struct Net {
    _tmp: TempDir,
    stubs: Stubs,
    orch: Started,
}

async fn network(label: &str) -> Net {
    let crs = require_crs(&[]);
    let tmp = TempDir::new(label);
    let certs = dev_certs(tmp.path());
    let keys = stub_keys();
    let pins = pins_of(&keys);
    let stubs = Stubs::start(&certs, stub_receipts(honest)).await;
    let orch =
        start_orchestrator(&certs, stubs.addrs, pins, &tmp.path().join("registry"), crs).await;
    let store = orch.registry().store();
    let mut txn = store.begin(Fr::from(NS));
    txn.register_namespace(NamespaceRow {
        owner_pubkey: sidecar_core::schnorr::public_key(Fq::from(9u64)),
        nsk_app: Default::default(),
        npk_app_hash: Fr::from(1u64),
        seq: 0,
    });
    let swaps = [
        ("swap", manifest("receipt")),
        ("swap_onchain", manifest("onchain")),
    ];
    let row = manifest_row(&swaps, Some(50));
    for (name, m) in swaps {
        txn.put_package(package(name, m, abi(), false, &row));
    }
    txn.put_manifest(row);
    store.commit(txn).unwrap();
    // the secret-shared intake vector's namespace and package, as REGISTER would
    // write them
    let v = shared_intake();
    let mut txn = store.begin(hex_value(&v["namespace"]));
    txn.register_namespace(NamespaceRow {
        owner_pubkey: sidecar_core::schnorr::public_key(Fq::from(9u64)),
        nsk_app: Default::default(),
        npk_app_hash: Fr::from(1u64),
        seq: 0,
    });
    let text = std::fs::read_to_string(repo().join(v["manifest"].as_str().unwrap())).unwrap();
    let shared: Value = serde_json::from_str(&text).unwrap();
    let row = manifest_row(&[(v["circuit"].as_str().unwrap(), shared)], Some(50));
    let manifest_hash = row.manifest_hash;
    txn.put_manifest(row);
    txn.put_package(PackageRow {
        name: v["circuit"].as_str().unwrap().into(),
        manifest_hash,
        circuit_json: serde_json::to_vec(&json!({"abi": v["abi"]})).unwrap(),
        manifest: serde_json::from_str(&text).unwrap(),
        vk: vec![],
        vk_hash: shared_vk_hash(),
        disabled: false,
        seq: 0,
    });
    store.commit(txn).unwrap();
    Net {
        _tmp: tmp,
        stubs,
        orch,
    }
}

fn body(circuit: &str, direction: &str) -> Value {
    json!({
        "namespace": FieldHex::from(NS),
        "circuit": circuit,
        "inputs": {"amount_in": "0x1388", "direction": direction, "min_out": "0x0fa0",
                   "partial_note": "0x9a"},
        "user_nonce": "0x01",
        "current_block": 1000,
    })
}

fn shared_vk_hash() -> Fr {
    hex_value(&shared_intake()["vk_hash"])
}

fn refusal_of(answer: &Answer) -> Refusal {
    answer.json::<Value>().unwrap().unwrap_err()
}

/// Three honest nodes: the orchestrator's expiry reaches every node, the
/// answer carries the agreed ids and the three signatures, each verifying
/// under its pinned key in its own position.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn three_agreeing_receipts_are_returned_with_their_signatures() {
    let net = network("rcpt-ok").await;
    let response: ReceiptResponse = net
        .orch
        .post_json("/v1/receipt", &body("swap", "0x1"))
        .await
        .json()
        .unwrap()
        .unwrap();
    assert_eq!(response.expiry_block, 1300);
    let inputs = [
        Fr::from(5000u64),
        Fr::from(1u64),
        Fr::from(4000u64),
        Fr::from(0x9au64),
    ];
    let id = chain_request_id(Fr::from(NS), Fr::from(VK_HASH), &inputs, Fr::from(1u64));
    assert_eq!(response.request_id.fr(), id);
    assert_eq!(response.inputs_hash.fr(), inputs_hash(&inputs));
    let keys = stub_keys();
    for (i, key) in keys.iter().enumerate() {
        assert!(verify_receipt(
            key.sig_pk(),
            response.signatures[i],
            id,
            response.inputs_hash.fr(),
            1300
        ));
        let calls = net.stubs.net.calls(i);
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].json()["expiry_block"], 1300);
        assert_eq!(calls[0].json()["current_block"], 1000);
    }
}

/// A node that answers other ids, another expiry or a signature that does
/// not verify under its pin is a 500 naming it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn disagreeing_or_badly_signed_receipts_are_refused_naming_the_node() {
    let net = network("rcpt-bad").await;
    let cases: [(Tamper, &str); 5] = [
        (
            |i, a| {
                if i == 1 {
                    a.expiry_block += 1;
                }
            },
            "node 1 answered the receipt with expiry_block 1301",
        ),
        (
            |i, a| {
                if i == 0 {
                    a.request_id = FieldHex::from(7);
                }
            },
            "node 0 answered the receipt with request_id",
        ),
        (
            |i, a| {
                if i == 2 {
                    a.inputs_hash = FieldHex::from(7);
                }
            },
            "node 2 answered the receipt with inputs_hash",
        ),
        (
            // node 2 signs with node 0's key
            |i, a| {
                if i == 2 {
                    let k = stub_keys();
                    a.signature = sign_receipt(
                        k[0].sig_scalar(),
                        a.request_id.fr(),
                        a.inputs_hash.fr(),
                        a.expiry_block,
                    );
                }
            },
            "node 2's receipt signature does not verify",
        ),
        (
            // node 1 signs another expiry than it reports
            |i, a| {
                if i == 1 {
                    let k = stub_keys();
                    a.signature = sign_receipt(
                        k[1].sig_scalar(),
                        a.request_id.fr(),
                        a.inputs_hash.fr(),
                        a.expiry_block + 1,
                    );
                }
            },
            "node 1's receipt signature does not verify",
        ),
    ];
    for (tamper, needle) in cases {
        net.stubs.net.set(stub_receipts(tamper));
        let answer = net
            .orch
            .post_json("/v1/receipt", &body("swap", "0x1"))
            .await;
        assert_eq!(answer.status, 500, "{needle}");
        let r = refusal_of(&answer);
        assert_eq!(r.class, ErrorClass::MpcFailure);
        assert!(r.message.contains(needle), "`{r}` lacks `{needle}`");
    }
    // a node's own refusal is passed on
    net.stubs.net.set(Arc::new(|_, _, _, _| {
        refused(ErrorClass::BadRequest, "field `expiry_block`: too far")
    }));
    let answer = net
        .orch
        .post_json("/v1/receipt", &body("swap", "0x1"))
        .await;
    assert_eq!(refusal_of(&answer).class, ErrorClass::BadRequest);
}

/// The orchestrator's own checks refuse before any node is called.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_bad_receipt_request_never_reaches_a_node() {
    let net = network("rcpt-pre").await;
    let mut with_expiry = body("swap", "0x1");
    with_expiry["expiry_block"] = 2000.into();
    let mut late = body("swap", "0x1");
    late["current_block"] = u32::MAX.into();
    let cases: Vec<(Value, &str)> = vec![
        (with_expiry, "set by the orchestrator"),
        (body("swap", "0x2"), "does not fit in 1 bit"),
        (body("swap_onchain", "0x1"), "`intake: onchain`"),
        (body("nope", "0x1"), "is not registered"),
        (late, "past the largest block number"),
        (json!({"namespace": "0x1"}), "missing field"),
    ];
    for (body, needle) in cases {
        let answer = net.orch.post_json("/v1/receipt", &body).await;
        let r = refusal_of(&answer);
        assert_eq!(r.class, ErrorClass::BadRequest, "{r}");
        assert!(r.message.contains(needle), "`{r}` lacks `{needle}`");
    }
    assert_eq!(net.stubs.net.total_calls(), 0);
}

/// A secret-shared receipt request: node i receives the body with only its own
/// envelope of each shared input and of the salts, all three hashes, the
/// summand commitments and the digest; the response carries the vector's
/// chain request id and C with the three signatures over C and the digest.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_shared_receipt_request_is_projected_per_node() {
    let net = network("rcpt-shared").await;
    let v = shared_intake();
    let response: ReceiptResponse = net
        .orch
        .post_json("/v1/receipt", &shared_receipt_client())
        .await
        .json()
        .unwrap()
        .unwrap();
    let id = hex_value(&v["chain_request_id"]);
    let c = hex_value(&v["inputs_commitment"]);
    let d = hex_value(&v["sharing_digest"]);
    assert_eq!(response.request_id.fr(), id);
    assert_eq!(response.inputs_hash.fr(), c);
    assert_eq!(response.expiry_block, 1300);
    for (i, key) in stub_keys().iter().enumerate() {
        assert!(sidecar_core::schnorr::verify(
            key.sig_pk(),
            response.signatures[i],
            shared_receipt_message(id, c, 1300, d)
        ));
        let calls = net.stubs.net.calls(i);
        assert_eq!(calls.len(), 1);
        let sent = calls[0].json();
        assert_eq!(sent["expiry_block"], 1300);
        assert_eq!(sent["inputs_hash"], v["inputs_commitment"]);
        assert_eq!(sent["summand_commitments"], v["summand_commitments"]);
        assert_eq!(sent["sharing_digest"], v["sharing_digest"]);
        for (k, input) in v["shared_inputs"].as_array().unwrap().iter().enumerate() {
            let got = &sent["shared_inputs"][k];
            assert_eq!(got["name"], input["name"]);
            assert_eq!(got["share"], input["shares"][i], "node {i}, input {k}");
            assert_eq!(got["share_hashes"], input["share_hashes"]);
            assert!(got.get("shares").is_none());
        }
    }
}

/// A node's receipt over C alone (the four-element message), or over
/// another sharing digest, is a node fault (500 naming the node), and a
/// digest that is not over the summand commitments, the layout and the
/// clear inputs (a clear input other than the one it covers among them) is
/// refused (400) before any node is called.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_shared_receipt_must_sign_the_sharing_digest() {
    let net = network("rcpt-digest").await;
    let cases: [Tamper; 2] = [
        |i, a| {
            if i == 2 {
                a.signature = sign_receipt(
                    stub_keys()[2].sig_scalar(),
                    a.request_id.fr(),
                    a.inputs_hash.fr(),
                    a.expiry_block,
                );
            }
        },
        |i, a| {
            if i == 0 {
                let message = shared_receipt_message(
                    a.request_id.fr(),
                    a.inputs_hash.fr(),
                    a.expiry_block,
                    Fr::from(7u64),
                );
                a.signature = sign_receipt_message(stub_keys()[0].sig_scalar(), message);
            }
        },
    ];
    for (tamper, node) in cases.into_iter().zip([2, 0]) {
        net.stubs.net.set(stub_receipts(tamper));
        let answer = net
            .orch
            .post_json("/v1/receipt", &shared_receipt_client())
            .await;
        assert_eq!(answer.status, 500);
        let r = refusal_of(&answer);
        let needle = format!("node {node}'s receipt signature does not verify");
        assert!(r.message.contains(&needle), "`{r}` lacks `{needle}`");
    }
    net.stubs.net.set(stub_receipts(honest));
    let calls = net.stubs.net.total_calls();
    // the orchestrator's own check of the request refuses before any node
    // is called (its cases are sidecar-tip's `intake::route`)
    let mut wrong = shared_receipt_client();
    wrong["sharing_digest"] = json!("0x01");
    let answer = net.orch.post_json("/v1/receipt", &wrong).await;
    let r = refusal_of(&answer);
    assert_eq!(r.class, ErrorClass::BadRequest, "{r}");
    assert!(r.message.contains("field `sharing_digest`"), "{r}");
    assert_eq!(net.stubs.net.total_calls(), calls);
}

/// An envelope that does not hash to its share hash is refused (400, naming
/// the input and the node) before any node is called, and so is a body in
/// the node's form.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_wrong_share_hash_never_reaches_a_node() {
    let net = network("rcpt-shared-hash").await;
    let mut wrong = shared_receipt_client();
    wrong["shared_inputs"][1]["share_hashes"][2] = json!("0x01");
    let mut swapped = shared_receipt_client();
    let first = swapped["shared_inputs"][0]["shares"][0].clone();
    swapped["shared_inputs"][0]["shares"][0] = swapped["shared_inputs"][0]["shares"][1].clone();
    swapped["shared_inputs"][0]["shares"][1] = first;
    let mut node_form = shared_receipt_client();
    node_form["shared_inputs"] = json!([{
        "name": "amount",
        "share": shared_intake()["shared_inputs"][0]["shares"][0],
        "share_hashes": shared_intake()["shared_inputs"][0]["share_hashes"],
    }]);
    let cases: Vec<(Value, &str)> = vec![
        (
            wrong,
            "field `shared_inputs[1]` (`$partial_note`): the envelope to node 2 does not hash to share_hashes[2]",
        ),
        (
            swapped,
            "field `shared_inputs[0]` (`amount`): the envelope to node 0 does not hash to share_hashes[0]",
        ),
        (node_form, "unknown field `share`"),
    ];
    for (body, needle) in cases {
        let answer = net.orch.post_json("/v1/receipt", &body).await;
        assert_eq!(answer.status, 400, "{needle}");
        let r = refusal_of(&answer);
        assert_eq!(r.class, ErrorClass::BadRequest);
        assert!(r.message.contains(needle), "`{r}` lacks `{needle}`");
    }
    assert_eq!(net.stubs.net.total_calls(), 0);
}
