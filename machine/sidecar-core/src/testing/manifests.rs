//! Contract manifests and manifest messages for the tests (feature
//! `testing`): what pss-client's generator writes from a contract artifact,
//! built here from the facts a test fixes (the mock contract's slots, or none
//! on the sidecar path).

use std::collections::BTreeMap;

use serde_json::{Value, json};

use crate::field::{FieldHex, Fr};
use crate::grumpkin::{Fq, point_to_wire};
use crate::manifest::contract::NamedKeys;
use crate::register::{ManifestMessage, Signature, stripped_circuit};
use crate::registry::Signed;
use crate::schnorr::{self, public_key};

/// One package of a test's contract manifest.
#[derive(Clone, Debug)]
pub struct TestPackage {
    pub name: String,
    /// The compiled circuit that backs it.
    pub circuit: String,
    pub manifest: Value,
    /// A queued package's request keys, by name.
    pub state_keys: Option<NamedKeys>,
    /// The listed package it is another intake of.
    pub alias_of: Option<String>,
}

impl TestPackage {
    /// A package named after its circuit.
    pub fn new(name: &str, manifest: Value) -> Self {
        Self::on(name, name, manifest)
    }

    /// A package `name` on circuit `circuit`.
    pub fn on(name: &str, circuit: &str, manifest: Value) -> Self {
        TestPackage {
            name: name.to_string(),
            circuit: circuit.to_string(),
            manifest,
            state_keys: None,
            alias_of: None,
        }
    }

    /// With request keys named `reads` and `writes`.
    pub fn keys(mut self, reads: &[&str], writes: &[&str]) -> Self {
        self.state_keys = Some(NamedKeys {
            reads: reads.iter().map(|k| k.to_string()).collect(),
            writes: writes.iter().map(|k| k.to_string()).collect(),
        });
        self
    }

    /// As another intake of the listed package `of`.
    pub fn alias_of(mut self, of: &str) -> Self {
        self.alias_of = Some(of.to_string());
        self
    }
}

/// The contract facts of a tip namespace in a test: the mock contract's
/// slots, its stale period and its package capacity.
#[derive(Clone, Debug)]
pub struct TipFacts {
    pub class_id: Fr,
    pub capacity: usize,
    pub node_keys: &'static str,
    /// `upgrades`: `fixed`, or `circuits` / `contract` with the circuit
    /// pins' slot in `circuit_pins_slot`.
    pub upgrades: &'static str,
    pub circuit_pins_slot: Option<Fr>,
    pub queue_slot: Fr,
    pub stale_blocks: Option<u64>,
    pub stale_blocks_slot: Fr,
    pub configured_slot: Fr,
    pub shared_onchain_slot: Option<Fr>,
    /// Each state key's commitment slot, by name.
    pub state_keys: BTreeMap<String, Fr>,
    pub plain_reads: BTreeMap<String, Fr>,
    /// The init package and its input slots.
    pub init: Option<(String, Vec<Fr>)>,
}

impl TipFacts {
    /// The facts of a mock contract with its queue at `queue_slot`, its
    /// stale period (`Some(50)` by the examples) at slot 1, its configured
    /// flag at slot 2, room for `capacity` packages and the state keys
    /// `state_keys`.
    pub fn new(queue_slot: Fr, capacity: usize, state_keys: &[(&str, Fr)]) -> Self {
        TipFacts {
            // the class every instance of sidecar-tip's in-memory chain runs
            // (`testing::MEMORY_CLASS_ID`)
            class_id: Fr::from(0xc1a55u64),
            capacity,
            node_keys: "fixed",
            upgrades: "fixed",
            circuit_pins_slot: None,
            queue_slot,
            stale_blocks: Some(crate::manifest::DEFAULT_STALE_BLOCKS),
            stale_blocks_slot: Fr::from(1u64),
            configured_slot: Fr::from(2u64),
            shared_onchain_slot: None,
            state_keys: state_keys
                .iter()
                .map(|(k, slot)| (k.to_string(), *slot))
                .collect(),
            plain_reads: BTreeMap::new(),
            init: None,
        }
    }

    /// The same contract with upgradable circuits (`upgrades: circuits`),
    /// its pins at slot 0x20.
    pub fn upgradable(mut self) -> Self {
        self.upgrades = "circuits";
        self.circuit_pins_slot = Some(Fr::from(0x20u64));
        self
    }
}

/// The contract manifest of `packages` under `tip` (or of the sidecar path,
/// `None`), each circuit's vk hash given by `vk_hash`.
pub fn contract_manifest(
    name: &str,
    packages: &[TestPackage],
    tip: Option<&TipFacts>,
    vk_hash: impl Fn(&str) -> Fr,
) -> Value {
    let mut circuits = serde_json::Map::new();
    for p in packages {
        circuits
            .entry(p.circuit.clone())
            .or_insert_with(|| json!({ "vk_hash": FieldHex(vk_hash(&p.circuit)) }));
    }
    let packages: Vec<Value> = packages
        .iter()
        .map(|p| {
            let mut v = json!({ "name": p.name, "circuit": p.circuit, "manifest": p.manifest });
            if let Some(of) = &p.alias_of {
                v["alias_of"] = json!(of);
            }
            if let Some(keys) = &p.state_keys {
                v["state_keys"] = json!(keys);
            }
            v
        })
        .collect();
    let mut m = json!({
        "contract_manifest": 1,
        "name": name,
        "node_keys": tip.map_or("fixed", |t| t.node_keys),
        "upgrades": tip.map_or("fixed", |t| t.upgrades),
        "circuits": circuits,
        "packages": packages,
    });
    if let Some(t) = tip {
        let slots = |map: &BTreeMap<String, Fr>| -> serde_json::Map<String, Value> {
            map.iter()
                .map(|(k, v)| (k.clone(), json!(FieldHex(*v))))
                .collect()
        };
        m["contract"] = json!({ "class_id": FieldHex(t.class_id), "package_capacity": t.capacity });
        m["queue"] = json!({
            "slot": FieldHex(t.queue_slot),
            "stale_blocks": t.stale_blocks,
            "stale_blocks_slot": FieldHex(t.stale_blocks_slot),
        });
        m["storage"] = json!({ "configured": FieldHex(t.configured_slot) });
        if let Some(slot) = t.shared_onchain_slot {
            m["storage"]["shared_onchain"] = json!(FieldHex(slot));
        }
        if let Some(slot) = t.circuit_pins_slot {
            m["storage"]["circuit_pins"] = json!(FieldHex(slot));
        }
        m["state_keys"] = Value::Object(slots(&t.state_keys));
        if !t.plain_reads.is_empty() {
            m["plain_reads"] = Value::Object(slots(&t.plain_reads));
        }
        if let Some((package, inputs)) = &t.init {
            m["init"] = json!({
                "package": package,
                "input_slots": inputs.iter().map(|s| FieldHex(*s)).collect::<Vec<_>>(),
            });
        }
    }
    m
}

/// An unsigned manifest message of `document` under `namespace` at `seq`,
/// owned by `owner`, carrying each circuit the document names stripped
/// from `circuits` (nargo's output by circuit id).
pub fn manifest_message(
    namespace: Fr,
    document: Value,
    circuits: &BTreeMap<String, Value>,
    owner: Fq,
    seq: u64,
) -> ManifestMessage {
    let ids: Vec<String> = document["circuits"]
        .as_object()
        .map(|m| m.keys().cloned().collect())
        .unwrap_or_default();
    ManifestMessage {
        namespace: FieldHex(namespace),
        circuits: ids
            .into_iter()
            .map(|id| {
                let full = circuits
                    .get(&id)
                    .unwrap_or_else(|| panic!("no compiled circuit {id}"));
                (id, stripped_circuit(full))
            })
            .collect(),
        manifest: document,
        owner_pubkey: point_to_wire(public_key(owner)),
        seq,
        signature: Signature::default(),
    }
}

/// `body` signed by `signer` (the namespace owner key, or another to test
/// a refusal), checked as a node parses it.
pub fn sign_message<R: ark_std::rand::RngCore + ark_std::rand::CryptoRng>(
    mut body: ManifestMessage,
    signer: Fq,
    rng: &mut R,
) -> Signed<ManifestMessage> {
    let message = schnorr::message_for(
        schnorr::REGISTER_DOMAIN,
        &serde_json::to_value(&body).unwrap(),
    )
    .unwrap();
    body.signature = schnorr::sign(signer, message, rng);
    Signed::new(body).unwrap()
}
