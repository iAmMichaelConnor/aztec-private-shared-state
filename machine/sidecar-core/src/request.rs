//! The execute request (`POST /v1/execute`), in the client's full form and in the
//! form node i receives.
//!
//! The orchestrator receives the full [`Request`] and sends node i its
//! [`NodeRequest`]: the same body, except that each shared input and each state
//! record carries only node i's ciphertext. Both forms are the one generic type
//! [`Request`], parameterised by a [`View`], so every check on the common fields is
//! written once.
//!
//! The canonical body ([`canonical_body`]) is the part of a request every party
//! sees alike: both views reduce to it, so the client, the orchestrator and
//! every node compute the same `body_hash`, signed message and envelope
//! associated data.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Debug;

use serde::de::{self, DeserializeOwned, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;

use crate::derived::SharedLog;
use crate::error::{Refusal, parse_json, unique_map};
use crate::field::{FieldHex, Fr, HexBytes, RequestId};
use crate::hash::poseidon2_hash;
use crate::manifest::FixedKey;
use crate::record::record_hash;
use crate::register::Signature;
use crate::schnorr::{EXECUTE_DOMAIN, canonical_json, check_name, poseidon2_hash_bytes};

/// The number of MPC nodes (Rep3): the parties of the mesh, the answers the
/// orchestrator checks, the receipts and result signatures of a round.
pub const NODES: usize = 3;

/// The node after node `i` around the ring, `(i + 1) mod NODES`: the
/// neighbour that shares node `i`'s second replicated component.
pub fn next(i: usize) -> usize {
    (i + 1) % NODES
}

/// The node before node `i` around the ring, `(i - 1) mod NODES`: the
/// neighbour that shares node `i`'s first replicated component.
pub fn prev(i: usize) -> usize {
    (i + NODES - 1) % NODES
}

/// A Grumpkin point in affine coordinates. Grumpkin's base field is the BN254
/// scalar field, so both coordinates are field elements. Used for node keys,
/// ephemeral keys and namespace owner keys alike (one key type everywhere).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrumpkinPoint {
    pub x: FieldHex,
    pub y: FieldHex,
}

/// One node's INPUT_SHARED envelope: ECIES over Grumpkin with the Poseidon2
/// SAFE-sponge authenticated encryption of `pss_utils/ae.nr`, over the pair
/// `[x_i, x_{i-1}]`. `eph` is the ephemeral public key, `ct` the two encrypted
/// elements and `tag` the authentication tag. [`crate::envelope`] seals and
/// opens it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShareCiphertext {
    pub eph: GrumpkinPoint,
    pub ct: [FieldHex; 2],
    pub tag: FieldHex,
}

impl ShareCiphertext {
    /// The hash a request body carries for this ciphertext in `share_hashes`: the
    /// Poseidon2 hash of its five field elements in the order
    /// `[eph.x, eph.y, ct[0], ct[1], tag]`.
    pub fn hash(&self) -> Fr {
        poseidon2_hash(&[
            self.eph.x.0,
            self.eph.y.0,
            self.ct[0].0,
            self.ct[1].0,
            self.tag.0,
        ])
    }
}

/// A secret input as the client sends it: one ciphertext per node and the hashes
/// of all three. Node i receives only `shares[i]` but all three hashes, so every
/// node computes the same inputs hash.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SharedInput {
    pub name: String,
    pub shares: [ShareCiphertext; NODES],
    pub share_hashes: [FieldHex; NODES],
}

/// A secret input as node i receives it: its own ciphertext and all three hashes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeSharedInput {
    pub name: String,
    pub share: ShareCiphertext,
    pub share_hashes: [FieldHex; NODES],
}

impl NodeSharedInput {
    /// Node `node`'s check that its envelope hashes to `share_hashes[node]`,
    /// the input being the `k`-th of its body's `shared_inputs`: 400 naming
    /// both otherwise. An envelope sent to the wrong node fails here.
    pub fn check_hash(&self, node: usize, k: usize) -> Result<(), Refusal> {
        if self.share.hash() != self.share_hashes[node].0 {
            return Err(Refusal::bad_request(format!(
                "field `shared_inputs[{k}]` (`{}`): the envelope to node {node} does not hash to \
                 share_hashes[{node}]",
                self.name
            )));
        }
        Ok(())
    }
}

/// A client-held state record: the key, the note hash the proof output for it,
/// the three per-node sealed thirds (opaque bytes; only node i opens `c[i]`) and
/// their hashes ([`crate::record::record_hash`]), which stand in for the thirds
/// in the canonical body.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StateRecord {
    pub key: String,
    pub note_hash: FieldHex,
    pub c: [HexBytes; NODES],
    pub record_hashes: [FieldHex; NODES],
}

/// A state record as node i sees it: its own sealed third and all three hashes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeStateRecord {
    pub key: String,
    pub note_hash: FieldHex,
    pub c_i: HexBytes,
    pub record_hashes: [FieldHex; NODES],
}

/// Which parties' ciphertexts a request or response carries: all three (the
/// client and orchestrator view) or one node's (the node view).
pub trait View: Clone + Debug + PartialEq {
    type SharedInput: Clone + Debug + PartialEq + Serialize + DeserializeOwned;
    type Record: Clone + Debug + PartialEq + Serialize + DeserializeOwned;
    /// The name of a shared input, for duplicate checks and error messages.
    fn shared_input_name(input: &Self::SharedInput) -> &str;
    /// The key of a state record.
    fn record_key(record: &Self::Record) -> &str;
}

/// The client and orchestrator view: all three ciphertexts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Full;

/// Node i's view: only its own ciphertexts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ForNode;

impl View for Full {
    type SharedInput = SharedInput;
    type Record = StateRecord;
    fn shared_input_name(input: &SharedInput) -> &str {
        &input.name
    }
    fn record_key(record: &StateRecord) -> &str {
        &record.key
    }
}

impl View for ForNode {
    type SharedInput = NodeSharedInput;
    type Record = NodeStateRecord;
    fn shared_input_name(input: &NodeSharedInput) -> &str {
        &input.name
    }
    fn record_key(record: &NodeStateRecord) -> &str {
        &record.key
    }
}

/// A public value in the request's `public` map: one field element, or a list for
/// an array parameter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PublicValue {
    One(FieldHex),
    Many(Vec<FieldHex>),
}

impl Serialize for PublicValue {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            PublicValue::One(v) => v.serialize(serializer),
            PublicValue::Many(list) => list.serialize(serializer),
        }
    }
}

// Written by hand rather than `#[serde(untagged)]`, so a bad element reports its
// own error and index instead of "did not match any variant".
impl<'de> Deserialize<'de> for PublicValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct PublicVisitor;
        impl<'de> Visitor<'de> for PublicVisitor {
            type Value = PublicValue;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a hex field element or a list of them")
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<PublicValue, E> {
                v.parse().map(PublicValue::One).map_err(E::custom)
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<PublicValue, A::Error> {
                let mut list = Vec::new();
                while let Some(v) = seq.next_element::<FieldHex>()? {
                    list.push(v);
                }
                if list.is_empty() {
                    return Err(de::Error::custom("an empty list fills no parameter"));
                }
                Ok(PublicValue::Many(list))
            }
        }
        deserializer.deserialize_any(PublicVisitor)
    }
}

/// The state keys a request touches, in order: `reads[i]` is `$state_keys.reads[i]` in the
/// manifest, `writes[j]` is `$state_keys.writes[j]`. Keys are opaque strings of
/// visible ASCII ([`check_name`]); a key the manifest also feeds into PUBLIC
/// must parse as a field element, and under intake direct be spelled `0x` and
/// lowercase hex digits without leading zeros (`0x0` for zero), which is checked
/// when the witness is bound, not here.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StateKeys {
    #[serde(default)]
    pub reads: Vec<String>,
    #[serde(default)]
    pub writes: Vec<String>,
}

/// `POST /v1/execute`. `Request` (the default, [`Full`]) is what the client sends;
/// [`NodeRequest`] is what node i receives. Unknown fields are refused at every
/// level; `public`, `state_keys`, `shared_inputs` and `records` default to empty;
/// `requester` and `signature` may be absent.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, bound(serialize = "", deserialize = ""))]
pub struct Request<V: View = Full> {
    /// The namespace: on Aztec, the contract address.
    pub namespace: FieldHex,
    /// The circuit name, resolved under `namespace` only.
    pub circuit: String,
    pub request_id: RequestId,
    #[serde(default, deserialize_with = "unique_map")]
    pub public: BTreeMap<String, PublicValue>,
    #[serde(default)]
    pub state_keys: StateKeys,
    #[serde(default)]
    pub shared_inputs: Vec<V::SharedInput>,
    /// One state record per loaded client-held key.
    #[serde(default)]
    pub records: Vec<V::Record>,
    /// The requester's Grumpkin public key: the owner of the records this
    /// request supplies and of those it creates.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requester: Option<GrumpkinPoint>,
    /// The requester's Schnorr signature over [`Request::signed_message`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<Signature>,
    // `chain_request_id` is an optional field of the execute
    // request, for the tip only: the scheduler's synthesised request names
    // the chain request id its machine request id was derived from, and each
    // node keeps it in the round's `requests` row, so FETCH by chain request
    // id finds the round. Step 3 refuses it (400) on a circuit whose manifest
    // has intake direct and requires it under a queued intake, so every direct row
    // has none. When present it is
    // part of the canonical body (body hash, requester signature, handshake);
    // when absent it is left out, so a direct body and its hash do not
    // depend on the field. Accepting it under intake direct would let any
    // client file rows under a chain request id the chain never issued.
    /// At the tip, the chain request id this request answers (queued
    /// intakes only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain_request_id: Option<FieldHex>,
    /// Under secret-shared on-chain intake, the request log the shares derive from
    /// ([`crate::derived::SharedLog`]), the same in every view; absent under
    /// every other intake, so their bodies are unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shared_log: Option<SharedLog>,
    // At the tip, a namespace under `upgrades` `circuits` or `contract`
    // holds several contract manifest versions, and a round runs only under
    // the one the contract's pins name. The scheduler reads the pins on its
    // chain view and names that version here; resolution takes the package
    // of that version, and each node's chain verifier refuses (400) a round
    // whose version is not the one the pins name on its own view, so all
    // three run the same circuit or none does. Part of the canonical body
    // when present; left out when absent, so every other body is unchanged.
    /// At the tip, the hash of the contract manifest version this round
    /// runs under; absent: the namespace's newest version.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest_hash: Option<FieldHex>,
}

// The canonical body is computed from the parsed request, not
// from the received bytes: the request re-serialised in its wire form (field
// elements, the request id among them, as 0x + 64 lowercase digits, `public`,
// `state_keys.reads`, `state_keys.writes`, `shared_inputs` and `records` always present,
// empty when absent; `requester` only when present), with `signature`, every
// `shares`/`share` and every `c`/`c_i` removed, then RFC 8785 (JCS). Both views
// reduce to the same body, so the orchestrator may re-serialise a projection
// and every node still agrees on `body_hash`. A client must build exactly this
// object, not hash its own formatting; testvectors/envelope.json carries a
// worked example. Keeping `share_hashes` and `record_hashes` binds every node's
// ciphertext into the hash without giving any node the others'.
/// The canonical body of a request in either view: the full request without
/// `shares`, `c` and `signature`.
pub fn canonical_body<V: View>(request: &Request<V>) -> Value {
    let mut body = serde_json::to_value(request).expect("a request serialises");
    let object = body.as_object_mut().expect("a request is an object");
    object.remove("signature");
    for (list, drop) in [
        ("shared_inputs", ["shares", "share"]),
        ("records", ["c", "c_i"]),
    ] {
        for item in object[list].as_array_mut().expect("a list").iter_mut() {
            let item = item.as_object_mut().expect("an object");
            for field in drop {
                item.remove(field);
            }
        }
    }
    body
}

// A request holds strings (hex, names, keys) and one kind of number,
// `shared_log`'s correction positions, which `validate` bounds far below the
// 2^53 JCS admits. A body JCS refuses (a position past 2^53, before
// `validate` or in a request built in code) hashes as its plain
// serialisation instead of panicking: two equal strings parse to one value,
// so it cannot collide with the JCS of a valid body, and `validate` refuses
// it anyway.
fn jcs(value: &Value) -> String {
    canonical_json(value).unwrap_or_else(|_| value.to_string())
}

/// The execute request as node i receives it.
pub type NodeRequest = Request<ForNode>;

impl<V: View> Request<V> {
    /// Parse and check a JSON body. Every refusal is `bad_request` and names the
    /// field.
    pub fn from_json(text: &str) -> Result<Self, Refusal> {
        let req: Self = parse_json(text)?;
        req.validate()?;
        Ok(req)
    }

    /// The checks that need no manifest: the circuit name, every key and every
    /// shared input name pass [`check_name`], no key listed twice in
    /// `reads` or in `writes`, no request key equal to a fixed key, no duplicate
    /// shared-input names or record keys, and a public map that flattens without
    /// collisions.
    pub fn validate(&self) -> Result<(), Refusal> {
        check_name("circuit", "circuit name", &self.circuit)?;
        for (list, keys) in [
            ("reads", &self.state_keys.reads),
            ("writes", &self.state_keys.writes),
        ] {
            let mut seen = BTreeSet::new();
            for (i, key) in keys.iter().enumerate() {
                check_name(&format!("state_keys.{list}[{i}]"), "key", key)?;
                // One key twice in one list would bind two parameters to one
                // stored value (or store one key twice); a key may appear once
                // in `reads` and once in `writes`.
                if !seen.insert(key.as_str()) {
                    return Err(Refusal::bad_request(format!(
                        "field `state_keys.{list}[{i}]`: `{key}` is listed twice"
                    )));
                }
                // A request may not aim a fixed key (the namespace's nsk_app) at
                // one of its own parameters.
                if FixedKey::from_name(key).is_some() {
                    return Err(Refusal::bad_request(format!(
                        "field `state_keys.{list}[{i}]`: `{key}` is a fixed key"
                    )));
                }
            }
        }
        let mut names = BTreeSet::new();
        for (k, input) in self.shared_inputs.iter().enumerate() {
            let name = V::shared_input_name(input);
            check_name(&format!("shared_inputs[{k}].name"), "input name", name)?;
            if !names.insert(name) {
                return Err(Refusal::bad_request(format!(
                    "field `shared_inputs[{k}].name`: `{name}` is duplicated"
                )));
            }
        }
        if let Some(log) = &self.shared_log {
            log.check()?;
        }
        let mut keys = BTreeSet::new();
        for (k, record) in self.records.iter().enumerate() {
            let key = V::record_key(record);
            check_name(&format!("records[{k}].key"), "key", key)?;
            if !keys.insert(key) {
                return Err(Refusal::bad_request(format!(
                    "field `records[{k}].key`: `{key}` is duplicated"
                )));
            }
        }
        self.flatten_public().map(|_| ())
    }

    /// The public map flattened to co-noir witness names
    /// ([`flatten_public_map`] under the field `public`).
    pub fn flatten_public(&self) -> Result<Vec<(String, Fr)>, Refusal> {
        flatten_public_map(&self.public, "public")
    }

    /// `poseidon2_hash_bytes(JCS(canonical body))`: the replay check, the
    /// session handshake and the `requests` row.
    pub fn body_hash(&self) -> Fr {
        poseidon2_hash_bytes(jcs(&canonical_body(self)).as_bytes())
    }

    /// The hash of the canonical body without the whole `shared_inputs` array,
    /// which every envelope's associated data covers (the envelopes cannot
    /// cover their own hashes).
    pub fn input_body_hash(&self) -> Fr {
        let mut body = canonical_body(self);
        body.as_object_mut()
            .expect("a request is an object")
            .remove("shared_inputs");
        poseidon2_hash_bytes(jcs(&body).as_bytes())
    }

    /// The field element `requester` signs:
    /// `poseidon2_hash_bytes("cosnark-sidecar/v1/execute" ‖ JCS(canonical body))`,
    /// [`crate::schnorr::message_for`]'s rule (the canonical body has no `signature`) over
    /// the request's JCS, which does not panic.
    pub fn signed_message(&self) -> Fr {
        let canonical = jcs(&canonical_body(self));
        poseidon2_hash_bytes(format!("{EXECUTE_DOMAIN}{canonical}").as_bytes())
    }

    fn map_view<W: View>(
        &self,
        shared: impl Fn(&V::SharedInput) -> W::SharedInput,
        record: impl Fn(&V::Record) -> W::Record,
    ) -> Request<W> {
        Request {
            namespace: self.namespace,
            circuit: self.circuit.clone(),
            request_id: self.request_id,
            public: self.public.clone(),
            state_keys: self.state_keys.clone(),
            shared_inputs: self.shared_inputs.iter().map(shared).collect(),
            records: self.records.iter().map(record).collect(),
            requester: self.requester,
            signature: self.signature,
            chain_request_id: self.chain_request_id,
            shared_log: self.shared_log.clone(),
            manifest_hash: self.manifest_hash,
        }
    }
}

/// A public map flattened to co-noir witness names: a single value or a
/// list of one is the bare `name`; a list of two or more becomes `name[0]`,
/// `name[1]`, .... Ordered by name, then by index. A name that is empty or
/// reserved (`$...`), and a flattened name that collides with another
/// (`a[0]` given both directly and from a list `a`), are refused (400)
/// under `field` (`field `<field>.<name>``).
pub fn flatten_public_map(
    map: &BTreeMap<String, PublicValue>,
    field: &str,
) -> Result<Vec<(String, Fr)>, Refusal> {
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    let mut push = |key: String, value: Fr| {
        if !seen.insert(key.clone()) {
            return Err(Refusal::bad_request(format!(
                "field `{field}.{key}`: duplicated after flattening lists"
            )));
        }
        out.push((key, value));
        Ok(())
    };
    for (name, value) in map {
        if name.is_empty() || name.starts_with('$') {
            return Err(Refusal::bad_request(format!(
                "field `{field}.{name}`: not a public value name"
            )));
        }
        match value {
            PublicValue::One(v) => push(name.clone(), v.0)?,
            PublicValue::Many(list) if list.len() == 1 => push(name.clone(), list[0].0)?,
            PublicValue::Many(list) => {
                for (i, v) in list.iter().enumerate() {
                    push(format!("{name}[{i}]"), v.0)?;
                }
            }
        }
    }
    Ok(out)
}

impl Request<Full> {
    /// Node `node`'s view of this request: the same body with only its own
    /// ciphertext of each shared input and each state record.
    ///
    /// Panics if `node` is not 0, 1 or 2.
    pub fn project(&self, node: usize) -> NodeRequest {
        assert!(node < NODES, "node index {node} out of range");
        self.map_view(
            |s| NodeSharedInput {
                name: s.name.clone(),
                share: s.shares[node],
                share_hashes: s.share_hashes,
            },
            |r| NodeStateRecord {
                key: r.key.clone(),
                note_hash: r.note_hash,
                c_i: r.c[node].clone(),
                record_hashes: r.record_hashes,
            },
        )
    }

    /// Check that every `share_hashes[i]` is the hash of `shares[i]` and every
    /// `record_hashes[i]` the hash of `c[i]`. The client and the orchestrator
    /// can check all three; each node checks its own with
    /// [`NodeRequest::check_own_ciphertexts`].
    pub fn check_ciphertext_hashes(&self) -> Result<(), Refusal> {
        for i in 0..NODES {
            self.project(i).check_own_ciphertexts(i)?;
        }
        Ok(())
    }
}

impl NodeRequest {
    /// Step 6, node `node`'s check of its own ciphertexts before anything is
    /// opened or bound: the envelope of every shared input hashes to
    /// `share_hashes[node]` and the third of every record to
    /// `record_hashes[node]`. A ciphertext sent to the wrong node fails here.
    /// Refusals are `bad_request` naming the field.
    pub fn check_own_ciphertexts(&self, node: usize) -> Result<(), Refusal> {
        assert!(node < NODES, "node index {node} out of range");
        for (k, input) in self.shared_inputs.iter().enumerate() {
            input.check_hash(node, k)?;
        }
        for (k, record) in self.records.iter().enumerate() {
            let hash = record_hash(record.c_i.as_slice()).map_err(|e| {
                Refusal::bad_request(format!(
                    "field `records[{k}].c_i` (key `{}`): {}",
                    record.key, e.message
                ))
            })?;
            if hash != record.record_hashes[node].0 {
                return Err(Refusal::bad_request(format!(
                    "field `records[{k}].c_i` (key `{}`): does not hash to record_hashes[{node}]",
                    record.key
                )));
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

    const ID: &str = "0x41d3000000000000000000000000beef";

    fn ct(seed: u64) -> serde_json::Value {
        let f = |k: u64| FieldHex::from(seed * 10 + k).to_string();
        json!({"eph": {"x": f(1), "y": f(2)}, "ct": [f(3), f(4)], "tag": f(5)})
    }

    fn ciphertext(seed: u64) -> ShareCiphertext {
        serde_json::from_value(ct(seed)).unwrap()
    }

    // Three real sealed thirds of one record, so the record hashes check.
    fn thirds() -> (Vec<String>, Vec<String>) {
        use crate::bind::{Elem, Share};
        use crate::grumpkin::{fixed_base_mul, scalar_from_field};
        let owner = fixed_base_mul(scalar_from_field(Fr::from(5u64)));
        (0..NODES)
            .map(|i| {
                let keys = crate::keys::tests::sample_keys(i);
                let vec = [Elem::Shared(Share::new(Fr::from(i as u64), Fr::from(9u64)))];
                let c = crate::record::seal(
                    &keys,
                    Fr::from(0x1f2ea9c0u64),
                    "0xa002",
                    Fr::from(0x77u64),
                    owner,
                    &vec,
                );
                let hash = FieldHex(record_hash(&c).unwrap()).to_string();
                (HexBytes(c).to_string(), hash)
            })
            .unzip()
    }

    fn full_body() -> serde_json::Value {
        let hashes: Vec<String> = (0..3)
            .map(|i| FieldHex(ciphertext(i).hash()).to_string())
            .collect();
        let (c, record_hashes) = thirds();
        json!({
            "namespace": "0x1f2ea9c0",
            "circuit": "monty_hall_open_door",
            "request_id": ID,
            "public": {"amount_in": "0x2710", "limbs": ["0x1", "0x2", "0x3"], "single": ["0x4"]},
            "state_keys": {"reads": ["0xa002"], "writes": ["0xa002"]},
            "shared_inputs": [{"name": "door", "shares": [ct(0), ct(1), ct(2)], "share_hashes": hashes}],
            "records": [{"key": "0xa002", "note_hash": "0x77", "c": c, "record_hashes": record_hashes}],
            "requester": {"x": "0x1", "y": "0x2"},
            "signature": {"s": ["0x3", "0x4"], "e": ["0x5", "0x6"]}
        })
    }

    fn parse(body: serde_json::Value) -> Result<Request, Refusal> {
        Request::from_json(&body.to_string())
    }

    fn refused(body: serde_json::Value, needle: &str) {
        crate::error::assert_refused(parse(body), ErrorClass::BadRequest, &[needle]);
    }

    // A correction position past 2^53 is refused by validate, and hashing
    // the body first does not panic.
    #[test]
    fn a_body_jcs_refuses_hashes_without_panicking() {
        let mut body = full_body();
        body["shared_inputs"] = json!([]);
        body["shared_log"] = json!({
            "fields": vec!["0x0"; crate::derived::REQUEST_LOG_LEN],
            "shared": [{"name": "door", "correction": u64::MAX}]
        });
        let req: Request = serde_json::from_value(body).unwrap();
        assert_ne!(req.body_hash(), req.input_body_hash());
        let _ = req.signed_message();
        let err = req.validate().unwrap_err();
        assert!(
            err.message.contains("shared_log.shared[0].correction"),
            "{err}"
        );
    }

    // Every name the request binds by poseidon2_hash_bytes passes check_name:
    // with a trailing NUL it would hash as the name without it.
    #[test]
    fn a_name_with_a_nul_is_refused_at_every_field() {
        let cases = [
            ("circuit", "/circuit"),
            ("state_keys.reads[0]", "/state_keys/reads/0"),
            ("state_keys.writes[0]", "/state_keys/writes/0"),
            ("shared_inputs[0].name", "/shared_inputs/0/name"),
            ("records[0].key", "/records/0/key"),
        ];
        parse(full_body()).unwrap();
        for (field, pointer) in cases {
            let mut body = full_body();
            let name = body.pointer_mut(pointer).unwrap();
            *name = json!(format!("{}\0", name.as_str().unwrap()));
            refused(body, &format!("field `{field}`: "));
        }
        let mut body = full_body();
        body["state_keys"]["reads"][0] = json!("pool total");
        refused(body, "byte 0x20");
    }

    #[test]
    fn the_design_page_swap_parses_with_defaults() {
        let req = parse(json!({
            "namespace": "0x1f2ea9c0",
            "circuit": "amm_swap",
            "request_id": ID,
            "public": {"amount_in": "0x2710", "direction": "0x0", "in0_nonce": "0x0d935b18"},
            "state_keys": {"reads": ["0xa002"], "writes": ["0xa002"]},
            "shared_inputs": []
        }))
        .unwrap();
        assert!(req.records.is_empty());
        assert_eq!(req.state_keys.reads, ["0xa002"]);
        let minimal =
            parse(json!({"namespace": "0x1", "circuit": "pss_seed", "request_id": ID})).unwrap();
        assert!(minimal.public.is_empty() && minimal.state_keys.writes.is_empty());
    }

    #[test]
    fn full_request_round_trips() {
        let req = parse(full_body()).unwrap();
        let text = serde_json::to_string(&req).unwrap();
        assert_eq!(Request::from_json(&text).unwrap(), req);
        req.check_ciphertext_hashes().unwrap();
        assert!(req.requester.is_some() && req.signature.is_some());
        // Absent requester and signature stay absent on the wire.
        let mut b = full_body();
        let object = b.as_object_mut().unwrap();
        object.remove("requester");
        object.remove("signature");
        let bare = parse(b).unwrap();
        let text = serde_json::to_string(&bare).unwrap();
        assert!(!text.contains("requester") && !text.contains("signature"));
    }

    #[test]
    fn public_lists_flatten_to_witness_names() {
        let req = parse(full_body()).unwrap();
        let names: Vec<String> = req
            .flatten_public()
            .unwrap()
            .into_iter()
            .map(|(n, _)| n)
            .collect();
        assert_eq!(
            names,
            ["amount_in", "limbs[0]", "limbs[1]", "limbs[2]", "single"]
        );
        let mut body = full_body();
        body["public"] = json!({"a": ["0x1", "0x2"], "a[1]": "0x3"});
        refused(body, "public.a[1]");
        let text = full_body().to_string().replacen(
            "\"amount_in\":\"0x2710\"",
            "\"amount_in\":\"0x2710\",\"amount_in\":\"0x1\"",
            1,
        );
        let err = Request::<Full>::from_json(&text).unwrap_err();
        assert!(
            err.message.contains("`amount_in` appears twice"),
            "{}",
            err.message
        );
        let mut body = full_body();
        body["public"] = json!({"a": []});
        refused(body, "empty list");
    }

    #[test]
    fn unknown_fields_are_refused_at_every_level() {
        let mut b = full_body();
        b["extra"] = json!(1);
        refused(b, "extra");
        let mut b = full_body();
        b["state_keys"]["deletes"] = json!([]);
        refused(b, "deletes");
        let mut b = full_body();
        b["shared_inputs"][0]["shares"][1]["nonce"] = json!("0x1");
        refused(b, "shared_inputs[0].shares[1]");
        let mut b = full_body();
        b["shared_inputs"][0]["shares"][2]["eph"]["z"] = json!("0x1");
        refused(b, "shared_inputs[0].shares[2].eph");
        let mut b = full_body();
        b["records"][0]["c_i"] = json!("0x00");
        refused(b, "records[0]");
        let mut b = full_body();
        b["requester"]["z"] = json!("0x1");
        refused(b, "requester");
        let mut b = full_body();
        b["signature"]["r"] = json!("0x1");
        refused(b, "signature");
        let mut b = full_body();
        b["records"][0]
            .as_object_mut()
            .unwrap()
            .remove("record_hashes");
        refused(b, "record_hashes");
    }

    #[test]
    fn bad_fields_name_their_path() {
        let mut b = full_body();
        b["public"]["limbs"][1] = json!("zz");
        refused(b, "public.limbs[1]");
        let mut b = full_body();
        b["namespace"] =
            json!("0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001");
        refused(b, "namespace");
        let mut b = full_body();
        b["records"][0]["c"][1] = json!("0x123");
        refused(b, "records[0].c[1]");
        let mut b = full_body();
        b["records"][0]["c"] = json!(["0x00", "0x01"]);
        refused(b, "records[0].c");
        let mut b = full_body();
        b["shared_inputs"][0]["share_hashes"][2] = json!(7);
        refused(b, "shared_inputs[0].share_hashes[2]");
    }

    #[test]
    fn request_id_must_be_a_field_element() {
        for bad in [
            "swap-41d3",
            "0x",
            "0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001",
        ] {
            let mut b = full_body();
            b["request_id"] = json!(bad);
            refused(b, "request_id");
        }
    }

    #[test]
    fn structural_refusals() {
        let mut b = full_body();
        b["state_keys"]["reads"] = json!(["nsk_app"]);
        refused(b, "state_keys.reads[0]");
        let mut b = full_body();
        b["state_keys"]["writes"] = json!([""]);
        refused(b, "state_keys.writes[0]");
        let mut b = full_body();
        b["state_keys"]["reads"] = json!(["0xa002", "0xa002"]);
        refused(b, "state_keys.reads[1]`: `0xa002` is listed twice");
        let mut b = full_body();
        b["state_keys"]["writes"] = json!(["0xa002", "0xa003", "0xa002"]);
        refused(b, "state_keys.writes[2]");
        let mut b = full_body();
        b["circuit"] = json!("");
        refused(b, "circuit");
        let mut b = full_body();
        let input = b["shared_inputs"][0].clone();
        b["shared_inputs"] = json!([input.clone(), input]);
        refused(b, "shared_inputs[1].name");
        let mut b = full_body();
        let record = b["records"][0].clone();
        b["records"] = json!([record.clone(), record]);
        refused(b, "records[1].key");
    }

    #[test]
    fn projection_gives_each_node_its_third() {
        let req = parse(full_body()).unwrap();
        for i in 0..NODES {
            let node = req.project(i);
            assert_eq!(node.shared_inputs[0].share, req.shared_inputs[0].shares[i]);
            assert_eq!(
                node.shared_inputs[0].share_hashes,
                req.shared_inputs[0].share_hashes
            );
            assert_eq!(node.records[0].c_i, req.records[0].c[i]);
            assert_eq!(node.records[0].record_hashes, req.records[0].record_hashes);
            assert_eq!(node.public, req.public);
            assert_eq!(node.requester, req.requester);
            assert_eq!(node.signature, req.signature);
            node.check_own_ciphertexts(i).unwrap();
            // the node view is its own wire format and round-trips
            let text = serde_json::to_string(&node).unwrap();
            assert_eq!(NodeRequest::from_json(&text).unwrap(), node);
            // a full body is not a node body
            assert!(NodeRequest::from_json(&full_body().to_string()).is_err());
        }
        // node 0's ciphertexts presented as node 1's fail the hash check
        let wrong = req.project(0);
        let err = wrong.check_own_ciphertexts(1).unwrap_err();
        assert!(err.message.contains("share_hashes[1]"), "{err}");
        let mut only_records = wrong.clone();
        only_records.shared_inputs.clear();
        let err = only_records.check_own_ciphertexts(1).unwrap_err();
        assert!(err.message.contains("record_hashes[1]"), "{err}");
    }

    #[test]
    fn a_wrong_share_hash_is_caught() {
        let mut b = full_body();
        b["shared_inputs"][0]["share_hashes"][1] = json!("0x1");
        let req = parse(b).unwrap();
        let err = req.check_ciphertext_hashes().unwrap_err();
        assert!(err.message.contains("share_hashes[1]"));
        assert!(req.project(1).check_own_ciphertexts(1).is_err());
        req.project(0).check_own_ciphertexts(0).unwrap();
    }

    #[test]
    fn a_record_third_whose_hash_differs_is_refused() {
        let mut b = full_body();
        let (c, _) = thirds();
        // node 2's third under node 1's slot: a valid record, the wrong hash
        b["records"][0]["c"][1] = json!(c[2]);
        let req = parse(b).unwrap();
        let err = req.project(1).check_own_ciphertexts(1).unwrap_err();
        assert_eq!(err.class, ErrorClass::BadRequest);
        assert!(
            err.message.contains("records[0].c_i") && err.message.contains("record_hashes[1]"),
            "{err}"
        );
        req.project(0).check_own_ciphertexts(0).unwrap();
        // bytes that are not a sealed third at all
        let mut b = full_body();
        b["records"][0]["c"][0] = json!("0x0101");
        let err = parse(b)
            .unwrap()
            .project(0)
            .check_own_ciphertexts(0)
            .unwrap_err();
        assert!(err.message.contains("not a sealed state record"), "{err}");
    }

    #[test]
    fn every_view_has_one_canonical_body() {
        let req = parse(full_body()).unwrap();
        let body = canonical_body(&req);
        assert!(body.get("signature").is_none());
        assert!(body["shared_inputs"][0].get("shares").is_none());
        assert!(body["records"][0].get("c").is_none());
        assert_eq!(
            body["records"][0]["record_hashes"],
            full_body()["records"][0]["record_hashes"]
        );
        assert_eq!(
            body["shared_inputs"][0]["share_hashes"]
                .as_array()
                .unwrap()
                .len(),
            3
        );
        assert_eq!(
            body["requester"],
            json!({"x": FieldHex::from(1).to_string(), "y": FieldHex::from(2).to_string()})
        );
        for i in 0..NODES {
            let node = req.project(i);
            assert_eq!(canonical_body(&node), body);
            assert_eq!(node.body_hash(), req.body_hash());
            assert_eq!(node.input_body_hash(), req.input_body_hash());
            assert_eq!(node.signed_message(), req.signed_message());
        }
        assert_eq!(
            req.body_hash(),
            poseidon2_hash_bytes(canonical_json(&body).unwrap().as_bytes())
        );
        assert_eq!(
            req.signed_message(),
            crate::schnorr::message_for(EXECUTE_DOMAIN, &body).unwrap()
        );
        // The signature and the ciphertexts themselves are not covered.
        let mut other = req.clone();
        other.signature = None;
        other.shared_inputs[0].shares[0].tag = FieldHex::from(9);
        other.records[0].c[2] = HexBytes(vec![1, 2, 3]);
        assert_eq!(other.body_hash(), req.body_hash());
        // Their hashes, public values, keys and the requester are.
        let mut other = req.clone();
        other.shared_inputs[0].share_hashes[0] = FieldHex::from(9);
        assert_ne!(other.body_hash(), req.body_hash());
        assert_eq!(other.input_body_hash(), req.input_body_hash());
        let mut other = req.clone();
        other.records[0].record_hashes[0] = FieldHex::from(9);
        assert_ne!(other.body_hash(), req.body_hash());
        assert_ne!(other.input_body_hash(), req.input_body_hash());
        let mut other = req.clone();
        other.requester = None;
        assert_ne!(other.body_hash(), req.body_hash());
        assert_ne!(other.input_body_hash(), req.input_body_hash());
        // So is a chain request id when present; absent, the body has no
        // such field, and parsing it back keeps it.
        assert!(body.get("chain_request_id").is_none());
        let mut other = req.clone();
        other.chain_request_id = Some(FieldHex::from(0xc4a1));
        assert_eq!(
            canonical_body(&other)["chain_request_id"],
            json!(FieldHex::from(0xc4a1).to_string())
        );
        assert_ne!(other.body_hash(), req.body_hash());
        assert_ne!(other.signed_message(), req.signed_message());
        assert_eq!(other.project(1).chain_request_id, other.chain_request_id);
        let text = serde_json::to_string(&other).unwrap();
        assert_eq!(Request::<Full>::from_json(&text).unwrap(), other);
        let mut other = req.clone();
        other
            .public
            .insert("amount_in".into(), PublicValue::One(FieldHex::from(1)));
        assert_ne!(other.input_body_hash(), req.input_body_hash());
        // A body written with other hex spellings has the same canonical body.
        let text = full_body().to_string().replace(
            "\"0x2710\"",
            "\"0x0000000000000000000000000000000000000000000000000000000000002710\"",
        );
        assert_eq!(
            Request::<Full>::from_json(&text).unwrap().body_hash(),
            req.body_hash()
        );
    }
}
