//! The audit of node-held tip state (docs/ARCHITECTURE.md section 6,
//! "Node-held state", the audit): over one MPC session, the three nodes
//! recompute from their pairs the commitment of each key's canonical
//! version (a flat key) or the hash of each of its leaves (a tree-valued
//! key), with the machine's audit circuit (machine/circuits/sidecar_audit),
//! [`AUDIT_ITEMS`] hashes per audit round, so a tree of more stored leaves
//! is audited in chunks of that many leaves, one round each, in leaf order,
//! and compare them with the commitment the version is named by and the
//! leaf hashes of the clear tree; the clear tree itself is checked against
//! the root by hashing in the clear ([`crate::tree::walk`]). Live versions
//! are not audited: the scheduler recomputes their entries. A tree held in
//! its holder's blobs (the oblivious tree) is reported not audited
//! ([`Outcome::NotAudited`]): no round runs for it, and it neither passes
//! nor fails.
//!
//! ```text
//! targets  each node, from its own store: per tip key, its canonical version as
//!          the circuit's items (one for a flat key, one per stored leaf of a tree)
//! agree    each node sends both neighbours its (key, commitment) list; the keys
//!          all three hold are audited in key order, the others fail
//! round    per key, per chunk of at most AUDIT_ITEMS hashes: the session handshake
//!          over the chunk's pairs (a component two nodes hold differently refuses,
//!          naming the element), then the audit circuit; a digest that differs
//!          from its hash fails the key, and its later chunks are not run
//! ```
//!
//! A version whose two copies of a component differ (a neighbour that sent a
//! wrong component in a resync, or a store damaged since) fails at the
//! handshake; one whose components agree but open to another value fails at
//! the circuit. Either way the key is named and nothing is written: the
//! audit only reads.

use std::collections::BTreeSet;

use co_noir_types::{Rep3SharedInput, Rep3Type};
use mpc_net::Network;
use serde::{Deserialize, Serialize};

use crate::bind::Elem;
use crate::crs::{Artifact, Circuit, Crs};
use crate::error::Refusal;
use crate::executor::{self, NamespaceCheck};
use crate::field::{FieldHex, Fr, RequestId, fr_from_hex, fr_to_hex};
use crate::handshake::{self, Handshake, recv_json, send_json};
use crate::hash::poseidon2_hash;
use crate::keys::label_field;
use crate::pipeline::Node;
use crate::record::key_hash;
use crate::request::{next, prev};
use crate::state::{NodeVersions, VersionViews};
use crate::store::{Store, StoreRead, TipVersion, VersionStatus, VersionTree};
use crate::tree::{self, PSS_TIP_LEAF, TreeNode};

/// The audit circuit's name, as the executor reports it.
pub const AUDIT_CIRCUIT: &str = "sidecar_audit";

// The audit circuit is compiled into the machine, like the
// registration circuit (registry.rs): its nargo artifact
// (machine/circuits/sidecar_audit, Noir 1.0.0, prepared by
// scripts/prepare-data.sh) is embedded by the build script, so a node needs
// no compiler, and its vk is built from it under
// the node's CRS when an audit starts. It has no package row: it cannot be
// registered or disabled. Its shape is fixed: AUDIT_ITEMS hashes of at most
// AUDIT_FIELDS fields per round, so a flat key's vector may hold at most
// AUDIT_FIELDS - 3 elements and a tree's leaf AUDIT_FIELDS - 4, and a tree
// with more than AUDIT_ITEMS stored leaves is audited in chunks, one round
// per AUDIT_ITEMS leaves (the chunk size is the circuit's, not a setting: a
// larger round is a new circuit and a new vk). A change to the circuit
// changes its vk.
/// The audit circuit's nargo artifact.
pub const AUDIT_ARTIFACT: &[u8] = include_bytes!(env!("PSS_AUDIT_ARTIFACT"));

/// The hashes one audit round computes (the circuit's `ITEMS`).
pub const AUDIT_ITEMS: usize = 16;
/// The fields of one hash's preimage (the circuit's `FIELDS`).
pub const AUDIT_FIELDS: usize = 16;

/// The flat slot commitment's label, `pss.tip.state` (pss_core tip::slot).
pub const PSS_TIP_STATE: &[u8] = b"pss.tip.state";

/// The embedded audit circuit, parsed.
pub fn audit_artifact() -> eyre::Result<Artifact> {
    Artifact::from_json(AUDIT_CIRCUIT, AUDIT_ARTIFACT)
}

/// The audit circuit with its vk under `crs` (sized for it or larger).
pub fn audit_circuit(crs: &Crs) -> eyre::Result<Circuit> {
    Circuit::new(audit_artifact()?, &crs.prover)
}

/// The commitment of a flat node-held key's vector (fields, then the
/// blinding) at `slot`: `poseidon2([pss.tip.state, namespace, slot,
/// vector...])`, pss_core's `tip::slot::commitment`.
pub fn flat_commitment(namespace: Fr, slot: Fr, vec: &[Fr]) -> Fr {
    let mut preimage = vec![label_field(PSS_TIP_STATE), namespace, slot];
    preimage.extend_from_slice(vec);
    poseidon2_hash(&preimage)
}

/// One hash an audit round recomputes: its preimage (public fields, then
/// the stored elements) and the hash it must give.
#[derive(Clone, Debug)]
struct Item {
    label: String,
    preimage: Vec<Elem>,
    /// How many of the preimage's first fields are public labels and names.
    prefix: usize,
    expected: Fr,
}

/// A key's canonical version as this node's store holds it, laid out for
/// the audit circuit: its items, or none when the audit does not cover the
/// key (a tree held in its holder's blobs).
#[derive(Clone, Debug)]
pub struct Target {
    pub key: String,
    pub commitment: Fr,
    items: Option<Vec<Item>>,
}

/// Why a key held in its holder's blobs is not audited.
pub const NOT_AUDITED_BLOBS: &str = "the tree is held in its holder's blobs and the oblivious \
                                     audit is not built; a resync compares the blobs' components";

/// What the audit found for one key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// Every hash the audit recomputed matched.
    Passed,
    /// The key failed, and why.
    Failed(String),
    /// The audit does not cover the key, and why: nothing was checked, and
    /// nothing failed.
    NotAudited(String),
}

/// What the audit found for one key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyAudit {
    pub namespace: FieldHex,
    pub key: String,
    /// The audited version's commitment.
    pub commitment: FieldHex,
    /// How many hashes the audit recomputed: 1 for a flat key, the stored
    /// leaves for a tree.
    pub hashes: usize,
    /// How many audit rounds it took: one per chunk of at most
    /// [`AUDIT_ITEMS`] hashes (fewer when a chunk failed).
    #[serde(default)]
    pub rounds: usize,
    pub outcome: Outcome,
}

impl KeyAudit {
    fn new(namespace: Fr, key: &str, commitment: Fr, hashes: usize) -> Self {
        KeyAudit {
            namespace: FieldHex(namespace),
            key: key.to_string(),
            commitment: FieldHex(commitment),
            hashes,
            rounds: 0,
            outcome: Outcome::Passed,
        }
    }

    fn failed(mut self, why: impl Into<String>) -> Self {
        self.outcome = Outcome::Failed(why.into());
        self
    }

    /// Whether the key was audited and passed.
    pub fn passed(&self) -> bool {
        self.outcome == Outcome::Passed
    }

    /// Whether the key failed the audit (a key not audited did not).
    pub fn failed_audit(&self) -> bool {
        self.failure().is_some()
    }

    /// Why the key failed the audit.
    pub fn failure(&self) -> Option<&str> {
        match &self.outcome {
            Outcome::Failed(why) => Some(why),
            _ => None,
        }
    }
}

/// A key as a field (its slot): 400 for a key that is not one.
fn key_field(key: &str) -> Result<Fr, Refusal> {
    fr_from_hex(key).map_err(|e| {
        Refusal::bad_request(format!(
            "key `{key}`: a node-held tip key is a field element ({e})"
        ))
    })
}

/// Lay out `version` of `key` under `namespace` for the audit circuit:
/// one item for a flat key, one per stored leaf of a tree, after checking
/// the clear tree against the root and the root against the commitment;
/// `None` for a tree held in its holder's blobs, which the audit does not
/// cover.
fn layout<R: StoreRead + ?Sized>(
    store: &R,
    namespace: Fr,
    version: &TipVersion,
) -> Result<Option<Vec<Item>>, Refusal> {
    let key = &version.key;
    let slot = key_field(key)?;
    let refuse = |why: String| Refusal::bad_request(format!("key `{key}`: {why}"));
    let root = match version.tree {
        Some(VersionTree::Clear(root)) => root,
        // the tree lives in its holder's blobs: no clear tree to recompute
        // (the oblivious audit, docs/ARCHITECTURE.md section 6, "Persistence,
        // resync, share refresh, audit", is not built); a recovery compares the
        // blobs' components instead (crate::resync::check_blobs)
        Some(VersionTree::Blobs { .. }) => return Ok(None),
        None => {
            let len = 3 + version.vec.len();
            if len > AUDIT_FIELDS {
                return Err(refuse(format!(
                    "a vector of {} elements is longer than the audit circuit takes ({})",
                    version.vec.len(),
                    AUDIT_FIELDS - 3
                )));
            }
            let mut preimage = vec![
                Elem::Public(label_field(PSS_TIP_STATE)),
                Elem::Public(namespace),
                Elem::Public(slot),
            ];
            preimage.extend(version.vec.iter().cloned());
            return Ok(Some(vec![Item {
                label: format!("key `{key}`"),
                preimage,
                prefix: 3,
                expected: version.commitment,
            }]));
        }
    };
    if tree::commitment(namespace, slot, root.root) != version.commitment {
        return Err(Refusal::mpc_failure(format!(
            "key `{key}`: the clear tree's root {} does not give the version's commitment {}",
            fr_to_hex(root.root),
            fr_to_hex(version.commitment)
        )));
    }
    let nodes = |h: Fr| -> Result<Option<TreeNode>, Refusal> {
        Ok(store.tip_node(namespace, key, h)?.map(|n| n.node))
    };
    let walked = tree::walk(&nodes, root.root)?;
    walked
        .leaves
        .into_iter()
        .map(|leaf| {
            if 4 + leaf.vec.len() > AUDIT_FIELDS {
                return Err(refuse(format!(
                    "a leaf of {} elements is longer than the audit circuit takes ({})",
                    leaf.vec.len(),
                    AUDIT_FIELDS - 4
                )));
            }
            let mut preimage = vec![
                Elem::Public(label_field(PSS_TIP_LEAF)),
                Elem::Public(namespace),
                Elem::Public(slot),
                Elem::Public(Fr::from(leaf.index)),
            ];
            preimage.extend(leaf.vec);
            Ok(Item {
                label: format!("key `{key}` leaf {}", leaf.index),
                preimage,
                prefix: 4,
                expected: leaf.hash,
            })
        })
        .collect::<Result<_, _>>()
        .map(Some)
}

/// The keys an audit takes, each with the commitment of its canonical
/// version and the version laid out for the circuit, or this node's
/// refusal of it.
pub type Targets = Vec<(String, Fr, Result<Target, Refusal>)>;

/// Every tip key of `namespace` with its canonical version, laid out for an
/// audit round, in key order: a key with no canonical version (only live
/// ones, which the scheduler recomputes) is left out; a key whose version
/// cannot be laid out (its clear tree fails, or a vector is longer than the
/// circuit takes)
/// carries the refusal, which fails the key at all three nodes. A tree of
/// any number of stored leaves is laid out whole; the round splits it into
/// chunks.
pub fn targets<S: Store + ?Sized>(store: &S, namespace: Fr) -> Result<Targets, Refusal> {
    let mut out = Vec::new();
    for key in store.tip_keys(namespace)? {
        let canonical: Vec<TipVersion> = store
            .tip_versions(namespace, &key)?
            .into_iter()
            .filter(|v| v.status == VersionStatus::Canonical)
            .collect();
        let version = match canonical.as_slice() {
            [] => continue,
            [v] => v,
            [v, ..] => {
                out.push((
                    key.clone(),
                    v.commitment,
                    Err(Refusal::mpc_failure(format!(
                        "key `{key}`: {} versions are marked canonical",
                        canonical.len()
                    ))),
                ));
                continue;
            }
        };
        let target = layout(store, namespace, version).map(|items| Target {
            key: key.clone(),
            commitment: version.commitment,
            items,
        });
        out.push((key, version.commitment, target));
    }
    Ok(out)
}

/// [`targets`] of `namespace` at `node`, read under the namespace lock
/// right after the prune pass marks its versions against the node's own
/// chain view `views` ([`NodeVersions::mark`]), so the three nodes audit
/// the version their current chain views name canonical, whenever each last
/// pruned.
pub fn marked_targets<S: Store>(
    node: &Node<S>,
    namespace: Fr,
    views: &VersionViews<'_>,
) -> Result<Targets, Refusal> {
    let _lock = node.lock_namespace(namespace);
    NodeVersions::mark(&node.store, namespace, views)?;
    targets(&node.store, namespace)
}

/// The label of the audit session's rounds, `sidecar.audit`.
pub const AUDIT_LABEL: &[u8] = b"sidecar.audit";

/// The handshake of one round of a key: the request id and body hash name
/// the namespace, the key, the version and the chunk (its index and the
/// key's number of hashes), the summands are the chunk's pairs.
fn round_handshake(
    namespace: Fr,
    key: &str,
    commitment: Fr,
    chunk: usize,
    hashes: usize,
    items: &[Item],
) -> Handshake {
    let id = poseidon2_hash(&[
        label_field(AUDIT_LABEL),
        namespace,
        key_hash(key),
        commitment,
        Fr::from(chunk as u64),
    ]);
    let body = poseidon2_hash(&[id, Fr::from(hashes as u64), Fr::from(items.len() as u64)]);
    let values: Vec<(String, &[Elem])> = items
        .iter()
        .map(|it| (it.label.clone(), &it.preimage[it.prefix..]))
        .collect();
    Handshake::of_values(RequestId(id), body, &values)
}

/// The audit circuit's witness for `items` (one chunk, at most
/// [`AUDIT_ITEMS`]): the namespace, each item's length and its preimage,
/// padded with zeros.
fn witness(namespace: Fr, items: &[Item]) -> Rep3SharedInput<Fr> {
    let mut input: Rep3SharedInput<Fr> = Rep3SharedInput::new();
    input.insert("namespace".into(), Rep3Type::Public(namespace));
    for k in 0..AUDIT_ITEMS {
        let item = items.get(k);
        let len = item.map_or(0, |it| it.preimage.len());
        input.insert(format!("len[{k}]"), Rep3Type::Public(Fr::from(len as u64)));
        for j in 0..AUDIT_FIELDS {
            let elem = item
                .and_then(|it| it.preimage.get(j).cloned())
                .unwrap_or(Elem::Public(Fr::from(0u64)));
            input.insert(format!("preimage[{}]", k * AUDIT_FIELDS + j), elem);
        }
    }
    input
}

/// One key's rounds over the open session `net`, one per chunk of at most
/// [`AUDIT_ITEMS`] hashes in leaf order: the handshake, then the circuit,
/// then the comparison. The first chunk that fails fails the key at all
/// three nodes (the handshake's verdicts tell each node of a refusal, and
/// every node compares the same digests with the same hashes), and its
/// later chunks are not run. A refusal of this node's own (`target` is an
/// error) joins the first handshake as its verdict. Errors only when the
/// mesh fails (500); a key that fails the audit is a [`KeyAudit`] with
/// [`Outcome::Failed`], a key held in its holder's blobs one with
/// [`Outcome::NotAudited`] (no round runs for it at any node).
fn audit_key<N: Network>(
    namespace: Fr,
    key: &str,
    commitment: Fr,
    target: Result<Target, Refusal>,
    net: &N,
    round: &mut impl FnMut(&[Item]) -> Result<Option<String>, Refusal>,
) -> Result<KeyAudit, Refusal> {
    let target = match target {
        Ok(t) => t,
        Err(refusal) => {
            let hs = round_handshake(namespace, key, commitment, 0, 0, &[]);
            handshake::exchange_refusing(net, &hs, refusal.clone());
            return Ok(KeyAudit::new(namespace, key, commitment, 0).failed(refusal.message));
        }
    };
    let Some(all) = target.items else {
        return Ok(KeyAudit {
            outcome: Outcome::NotAudited(NOT_AUDITED_BLOBS.into()),
            ..KeyAudit::new(namespace, key, commitment, 0)
        });
    };
    let hashes = all.len();
    let mut report = KeyAudit::new(namespace, key, commitment, hashes);
    for (chunk, items) in all.chunks(AUDIT_ITEMS).enumerate() {
        report.rounds += 1;
        let hs = round_handshake(namespace, key, commitment, chunk, hashes, items);
        if let Err(refusal) = handshake::exchange(net, &hs) {
            if refusal.status() == 500 {
                return Err(refusal);
            }
            return Ok(report.failed(refusal.message));
        }
        if let Some(why) = round(items)? {
            return Ok(report.failed(why));
        }
    }
    Ok(report)
}

/// One audit round over `items` (at most [`AUDIT_ITEMS`]): the circuit,
/// then each digest against its hash. Why the first that differs fails, or
/// `None` when all agree; 500 when the mesh or the circuit fails.
fn audit_chunk<N: Network>(
    circuit: &Circuit,
    crs: &Crs,
    namespace: Fr,
    items: &[Item],
    net: &N,
) -> Result<Option<String>, Refusal> {
    let out = executor::execute(
        circuit,
        crs,
        witness(namespace, items),
        NamespaceCheck {
            index: 0,
            namespace,
        },
        net,
    )?;
    let digests = out
        .public_inputs
        .get(1 + AUDIT_ITEMS..1 + 2 * AUDIT_ITEMS)
        .ok_or_else(|| {
            Refusal::mpc_failure(format!(
                "the audit proof has {} public inputs, not {}",
                out.public_inputs.len(),
                1 + 2 * AUDIT_ITEMS
            ))
        })?;
    for (item, digest) in items.iter().zip(digests) {
        if *digest != item.expected {
            let what = if item.prefix == 3 {
                "the version's commitment"
            } else {
                "the clear tree's leaf hash"
            };
            return Ok(Some(format!(
                "{}: the pairs hash to {}, not {what} {}",
                item.label,
                fr_to_hex(*digest),
                fr_to_hex(item.expected)
            )));
        }
    }
    Ok(None)
}

/// The audit of `namespace` over the open session `net`, from this node's
/// `targets` ([`targets`]): the three nodes agree on the keys, then audit
/// each one all three hold at the same version, in key order. Every
/// node answers the same findings for the keys audited; a key a neighbour
/// does not hold at this version fails at this node. 500 when the mesh or
/// the circuit fails.
pub fn audit<N: Network>(
    circuit: &Circuit,
    crs: &Crs,
    namespace: Fr,
    targets: Targets,
    net: &N,
) -> Result<Vec<KeyAudit>, Refusal> {
    audit_with(namespace, targets, net, |items| {
        audit_chunk(circuit, crs, namespace, items, net)
    })
}

/// [`audit`] with `round` running one audit round ([`audit_chunk`] in the
/// node).
fn audit_with<N: Network>(
    namespace: Fr,
    targets: Targets,
    net: &N,
    mut round: impl FnMut(&[Item]) -> Result<Option<String>, Refusal>,
) -> Result<Vec<KeyAudit>, Refusal> {
    let me = net.id();
    let mine: Vec<(String, FieldHex)> = targets
        .iter()
        .map(|(k, c, _)| (k.clone(), FieldHex(*c)))
        .collect();
    let peers = [next(me), prev(me)];
    for peer in peers {
        send_json(net, peer, "audit key list", &mine)?;
    }
    let mut held: Vec<BTreeSet<(String, FieldHex)>> = Vec::new();
    for peer in peers {
        let theirs: Vec<(String, FieldHex)> = recv_json(net, peer, "audit key list")?;
        held.push(theirs.into_iter().collect());
    }
    let mut out = Vec::new();
    for (key, commitment, target) in targets {
        let entry = (key.clone(), FieldHex(commitment));
        if let Some(i) = held.iter().position(|set| !set.contains(&entry)) {
            out.push(
                KeyAudit::new(namespace, &key, commitment, 0).failed(format!(
                    "node {} holds no canonical version of key `{key}` under commitment {}",
                    peers[i],
                    fr_to_hex(commitment)
                )),
            );
            continue;
        }
        out.push(audit_key(
            namespace, &key, commitment, target, net, &mut round,
        )?);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::MemoryStore;
    use serde_json::Value;

    /// A tree held in its holder's blobs (no clear tree) is laid out as no
    /// items, and the audit reports it not audited, at all three nodes,
    /// without running a round for it; the report counts it as no failure.
    #[test]
    fn a_tree_held_in_blobs_is_not_audited() {
        let namespace = Fr::from(7u64);
        let version = TipVersion {
            key: "0x0a".into(),
            commitment: Fr::from(99u64),
            parent: Fr::from(0u64),
            index: 0,
            request_id: RequestId(Fr::from(1u64)),
            vec: vec![],
            tree: Some(VersionTree::Blobs { next: 0 }),
            status: VersionStatus::Canonical,
            block: 0,
            block_hash: Fr::from(0u64),
        };
        let items = layout(&MemoryStore::default(), namespace, &version).unwrap();
        assert!(items.is_none());
        let nets = mpc_net::local::LocalNetwork::new_3_parties();
        let found: Vec<Vec<KeyAudit>> = std::thread::scope(|s| {
            let runs: Vec<_> = nets
                .iter()
                .map(|net| {
                    let target = Target {
                        key: version.key.clone(),
                        commitment: version.commitment,
                        items: None,
                    };
                    let targets = vec![(target.key.clone(), target.commitment, Ok(target))];
                    s.spawn(move || {
                        audit_with(namespace, targets, net, |_| {
                            panic!("a round ran for a key held in blobs")
                        })
                        .unwrap()
                    })
                })
                .collect();
            runs.into_iter().map(|r| r.join().unwrap()).collect()
        });
        for keys in found {
            assert_eq!(keys.len(), 1);
            let k = &keys[0];
            assert_eq!(k.outcome, Outcome::NotAudited(NOT_AUDITED_BLOBS.into()));
            assert!(!k.passed() && !k.failed_audit());
            assert_eq!((k.hashes, k.rounds), (0, 0));
        }
    }

    /// The embedded artifact is the prepared copy compiled from the current
    /// source, with the parameters and public inputs the node reads.
    #[test]
    fn embedded_audit_artifact_has_the_audit_shape() {
        crate::testing::artifacts::require_prepared_fresh(
            std::path::Path::new(env!("PSS_AUDIT_ARTIFACT")),
            AUDIT_CIRCUIT,
        );
        audit_artifact().unwrap();
        let embedded: Value = serde_json::from_slice(AUDIT_ARTIFACT).unwrap();
        let abi = &embedded["abi"];
        let params: Vec<(&str, &str)> = abi["parameters"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| {
                (
                    p["name"].as_str().unwrap(),
                    p["visibility"].as_str().unwrap(),
                )
            })
            .collect();
        assert_eq!(
            params,
            [
                ("namespace", "public"),
                ("len", "public"),
                ("preimage", "private")
            ]
        );
        assert_eq!(abi["parameters"][1]["type"]["length"], AUDIT_ITEMS);
        assert_eq!(
            abi["parameters"][2]["type"]["length"],
            AUDIT_ITEMS * AUDIT_FIELDS
        );
        assert_eq!(abi["return_type"]["abi_type"]["length"], AUDIT_ITEMS);
    }

    /// The flat commitment is pss_core's tip::slot::commitment, whose known
    /// answers testvectors/slot_commitment.json holds.
    #[test]
    fn the_flat_commitment_is_the_slot_commitment() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../testvectors/slot_commitment.json");
        let Ok(text) = std::fs::read_to_string(&path) else {
            panic!("{} is missing", path.display());
        };
        let v: Value = serde_json::from_str(&text).unwrap();
        let f = |x: &Value| fr_from_hex(x.as_str().unwrap()).unwrap();
        assert_eq!(f(&v["tip_state_sep"]), label_field(PSS_TIP_STATE));
        let cases = v["vectors"].as_array().unwrap();
        assert!(!cases.is_empty());
        for case in cases {
            let mut vec: Vec<Fr> = case["fields"].as_array().unwrap().iter().map(f).collect();
            vec.push(f(&case["blinding"]));
            assert_eq!(
                flat_commitment(f(&case["namespace"]), f(&case["slot"]), &vec),
                f(&case["commitment"])
            );
        }
    }
}
