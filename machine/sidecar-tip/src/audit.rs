//! The requester audit (docs/ARCHITECTURE.md section 6, "The hidden
//! requester"), for the in-process suites: no requester address appears in
//! a chain request id, a receipt body or row, a synthesised request's public
//! map, an intake transaction's public call arguments or a proof's public
//! inputs. A suite names the addresses it must not find (the accounts its
//! requests came from) and audits each place; a failure panics naming the
//! place and the field. The contract suites audit the chain side with
//! pss_tip_test's `audit` module and the e2e drivers with pss-client's
//! `assertNoRequester`.
//!
//! A value names an address when it equals one as a field element; JSON is
//! walked whole, and every string or number in it that parses as a field
//! element counts, whatever its key.

use serde::Serialize;
use serde_json::Value;
use sidecar_core::field::{Fr, fr_from_hex, fr_to_hex};
use sidecar_core::request::{Full, Request};
use sidecar_core::store::ReceiptRow;

use crate::intake::route::{ReceiptRequest, StoredReceipt};
use crate::receipt::chain_request_id;

/// The addresses a suite must not find, as field elements.
#[derive(Clone, Debug, Default)]
pub struct Requesters(pub Vec<Fr>);

impl Requesters {
    pub fn new(addresses: impl IntoIterator<Item = Fr>) -> Self {
        Requesters(addresses.into_iter().collect())
    }

    /// Panic when one of `fields` is a requester address, naming `what` and
    /// the field's position.
    pub fn assert_absent(&self, what: &str, fields: impl IntoIterator<Item = Fr>) {
        for (k, f) in fields.into_iter().enumerate() {
            assert!(
                !self.0.contains(&f),
                "{what}: field {k} is the requester address {}",
                fr_to_hex(f)
            );
        }
    }

    /// Panic when any field element in `value`, serialised as JSON, is a
    /// requester address, naming `what` and the JSON path.
    pub fn assert_absent_in<T: Serialize>(&self, what: &str, value: &T) {
        let json = serde_json::to_value(value).expect("an audited value serialises");
        for (path, f) in json_fields(&json, String::new()) {
            assert!(
                !self.0.contains(&f),
                "{what}: `{path}` is the requester address {}",
                fr_to_hex(f)
            );
        }
    }

    /// A non-secret-shared intake's chain request id: it must be the requester-free id
    /// of the given parts, `poseidon2([namespace, vk_hash, inputs_hash,
    /// user_nonce])`, and none of the parts may be a requester address.
    pub fn assert_plain_id(
        &self,
        id: Fr,
        namespace: Fr,
        vk_hash: Fr,
        inputs: &[Fr],
        user_nonce: Fr,
    ) {
        assert_eq!(
            id,
            chain_request_id(namespace, vk_hash, inputs, user_nonce),
            "chain request id {}: not the requester-free id of its inputs and nonce",
            fr_to_hex(id)
        );
        self.assert_absent("chain request id inputs", inputs.iter().copied());
        self.assert_absent("chain request id", [id, user_nonce]);
    }

    /// A receipt body, as the client sends it.
    pub fn assert_receipt_body(&self, body: &ReceiptRequest) {
        self.assert_absent_in("receipt body", body);
    }

    /// A node's `receipts` row, and the stored receipt it serves.
    pub fn assert_receipt_row(&self, namespace: Fr, row: &ReceiptRow) {
        self.assert_absent_in("receipts row", &StoredReceipt::new(namespace, row));
        self.assert_absent(
            "receipts row",
            row.inputs
                .iter()
                .copied()
                .chain([row.request_id, row.inputs_hash])
                .chain(row.user_nonce),
        );
    }

    /// A synthesised request: its public map and its ids (a queued round has
    /// no requester key either).
    pub fn assert_synthesised(&self, request: &Request<Full>) {
        assert!(
            request.requester.is_none(),
            "synthesised request: it names a requester key"
        );
        self.assert_absent_in("synthesised request public map", &request.public);
        self.assert_absent(
            "synthesised request ids",
            [request.request_id.fr()]
                .into_iter()
                .chain(request.chain_request_id.map(|c| c.0)),
        );
    }

    /// An intake transaction's public call arguments, or a proof's public
    /// inputs, as field elements.
    pub fn assert_call_args(&self, what: &str, args: &[Fr]) {
        self.assert_absent(what, args.iter().copied());
    }
}

/// Every field element in a JSON value, with its path.
fn json_fields(v: &Value, path: String) -> Vec<(String, Fr)> {
    match v {
        Value::String(s) => fr_from_hex(s).map(|f| vec![(path, f)]).unwrap_or_default(),
        Value::Number(n) => n
            .as_u64()
            .map(|u| vec![(path, Fr::from(u))])
            .unwrap_or_default(),
        Value::Array(items) => items
            .iter()
            .enumerate()
            .flat_map(|(i, x)| json_fields(x, format!("{path}[{i}]")))
            .collect(),
        Value::Object(map) => map
            .iter()
            .flat_map(|(k, x)| {
                let p = if path.is_empty() {
                    k.clone()
                } else {
                    format!("{path}.{k}")
                };
                json_fields(x, p)
            })
            .collect(),
        _ => vec![],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const USER: &str = "0x0b7e3a1f00c0ffee00000000000000000000000000000000000000000000beef";

    fn requesters() -> Requesters {
        Requesters::new([fr_from_hex(USER).unwrap()])
    }

    #[test]
    fn json_fields_walk_every_value() {
        let v = json!({"a": "0x01", "b": [2, {"c": USER}], "d": "not a field"});
        let fields = json_fields(&v, String::new());
        assert_eq!(
            fields,
            [
                ("a".to_string(), Fr::from(1u64)),
                ("b[0]".to_string(), Fr::from(2u64)),
                ("b[1].c".to_string(), fr_from_hex(USER).unwrap()),
            ]
        );
    }

    #[test]
    #[should_panic(expected = "receipt body: `user_nonce` is the requester address")]
    fn an_address_in_a_body_is_found() {
        let body = ReceiptRequest::from_json(
            &json!({"namespace": "0x1", "circuit": "c", "inputs": {}, "user_nonce": USER,
                    "current_block": 1})
            .to_string(),
        )
        .unwrap();
        requesters().assert_receipt_body(&body);
    }

    #[test]
    #[should_panic(expected = "not the requester-free id")]
    fn an_id_over_an_address_is_found() {
        let user = fr_from_hex(USER).unwrap();
        let (ns, vk, nonce) = (Fr::from(1u64), Fr::from(2u64), Fr::from(3u64));
        let with_user =
            sidecar_core::hash::poseidon2_hash(&[ns, vk, crate::inputs_hash(&[]), user, nonce]);
        requesters().assert_plain_id(with_user, ns, vk, &[], nonce);
    }
}
