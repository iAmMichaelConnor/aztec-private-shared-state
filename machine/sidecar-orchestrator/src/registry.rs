//! The orchestrator's copy of the registry: the `namespaces`, `manifests` and
//! `packages` rows the nodes hold, written from the REGISTER and DISABLE answers it
//! relays, persisted in the local append-only store; and the verification
//! keys it computes itself from each registered circuit and the CRS.
//!
//! It holds nothing a node does not hold: no `nsk_app` share (the column is
//! a zero placeholder), no `consumed`, `requests` or `values` rows.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use serde::de::DeserializeOwned;
use serde_json::Value;
use sidecar_core::abi::CircuitShape;
use sidecar_core::bind::Share;
use sidecar_core::crs::{self, Artifact, BbVerifyingKey, Circuit, Crs, G2};
use sidecar_core::field::{Fr, fr_to_hex};
use sidecar_core::grumpkin::point_from_wire;
use sidecar_core::local::LocalStore;
use sidecar_core::manifest::contract::{CheckedContractManifest, manifest_hash};
use sidecar_core::register::{DisableRequest, DisableResponse, ManifestMessage, ManifestResponse};
use sidecar_core::registry::{self, ManifestFacts, RegisterRows};
use sidecar_core::request::NODES;
use sidecar_core::store::{ManifestRow, NamespaceRow, PackageRow, Store, StoreRead};
use sidecar_core::{Refusal, crs::public_input_count};

use crate::nodes::{Reply, best_of, each_answer};
use crate::status::RegistryReport;

// The orchestrator's registry copy lives in sidecar-core's
// local append-only store (`[registry] path`, one directory, `store.log`),
// the backend a node with only client-held keys runs on, so a restart keeps
// every namespace and package. The orchestrator needs the copy for steps 1 to
// 4 (resolution and the manifest) and for its own verification keys, and
// fills it only from REGISTER and DISABLE bodies the three nodes answered and
// signed, in the same transaction shapes the nodes commit, so every row it
// holds the nodes hold too (invariant 12); its `nsk_app` column is a zero
// placeholder, because the orchestrator holds no share. It writes no
// `consumed`, `requests` or `values` rows: FETCH reads the nodes. A copy one
// body behind (a crash between the nodes' commit and the orchestrator's) is
// brought level by resending that signed body, which the nodes answer
// idempotently. A body only some nodes committed (another node refused it or
// failed to commit it) leaves the copy unchanged, since the copy records only
// what all three hold, and is answered 500 naming the divergence
// ([`committed_answers`]); resending it repairs the nodes and the copy at
// once. A copy further behind, lost, or opened under the wrong path
// cannot be repaired by resending (the nodes refuse a seq 0 body once the
// namespace is past seq 0, and the copy refuses a later one without its
// namespace row); it is rebuilt from the three nodes with `sidecar-orchestrator
// sync-registry` or `--sync-registry` at start (`crate::sync`), so backing up
// the directory is a convenience, not a necessity.
/// The orchestrator's registry copy and its verification keys.
pub struct Registry {
    store: LocalStore,
    crs: Crs,
    registration_vk: BbVerifyingKey,
    // The verifier cache is unbounded and never evicts. It
    // holds one entry per (namespace, contract manifest version, name) the
    // orchestrator has served or registered since it started, each a bb
    // verification key (115 fields) and the manifest's shape, a few KiB, so
    // the versions an upgradable namespace holds each keep their own. An
    // entry is reused only while the copy's `packages` row has the seq and
    // vk_hash it was built from. Every registry body that writes the row
    // (REGISTER, DISABLE) stores its own seq, so a re-registered name gets a
    // new entry on its next use even when the circuit, and so the vk_hash,
    // is unchanged and only the manifest differs (a sidecar-path namespace's
    // contract manifest may be replaced), and the answer checks read the new
    // manifest's shape. A hash of the manifest would miss a changed circuit
    // JSON under the same vk. An entry is built from the row alone: the vk
    // the row stores, decoded and checked against its vk_hash (the copy's
    // every vk is one the orchestrator computed itself, at REGISTER or at a
    // sync), and the shape parsed from its manifest and ABI. So it grows with
    // the registry, not with traffic, and only a namespace owner can grow it
    // (a REGISTER is signed and committed by the three nodes first).
    verifiers: Mutex<BTreeMap<(Fr, Fr, String), Arc<Verifier>>>,
    /// The latest comparison of the three nodes' registry rows with each
    /// other and with this copy, for `GET /v1/status` and the admin socket,
    /// with the ticket of
    /// the run that made it ([`Registry::begin_check`]).
    agreement: Mutex<Option<(u64, RegistryReport)>>,
    /// The last ticket handed out.
    checks: AtomicU64,
}

/// A registered circuit as the orchestrator checks its proofs: the vk it
/// computed from the circuit at REGISTER or sync, the vk's hash, and the
/// manifest's shape.
pub struct Verifier {
    pub name: String,
    pub vk: BbVerifyingKey,
    pub vk_hash: Fr,
    pub shape: CircuitShape,
    /// The `seq` of the `packages` row it was built from.
    pub seq: u64,
}

impl Verifier {
    /// Whether `proof` verifies under this circuit's vk with `public_inputs`
    /// (a public-input count that does not match the vk does not verify).
    pub fn verifies(&self, g2: G2, proof: &[u8], public_inputs: &[Fr]) -> bool {
        public_inputs.len() == public_input_count(&self.vk)
            && crs::verify(&self.vk, g2, proof, public_inputs).unwrap_or(false)
    }
}

/// A manifest message as the orchestrator checked and computed it before
/// forwarding: its contract manifest, the facts the nodes sign, and each
/// circuit's vk, built here (none when the copy holds the body's contract
/// manifest already: a resend or a re-enable, which builds nothing).
pub struct ComputedMessage {
    pub contract: CheckedContractManifest,
    pub facts: ManifestFacts,
    /// By circuit id.
    pub circuits: BTreeMap<String, Computed>,
}

/// A circuit as the orchestrator computed it before forwarding.
pub struct Computed {
    /// The circuit JSON as the nodes store it.
    pub circuit_json: Vec<u8>,
    pub vk: BbVerifyingKey,
    pub vk_hash: Fr,
}

impl Registry {
    /// Open (or create) the registry store in `dir`, under `crs`, after
    /// settling a sync's swap a crash interrupted
    /// ([`crate::sync::settle_interrupted_swap`]).
    pub fn open(dir: &Path, crs: Crs) -> eyre::Result<Self> {
        crate::sync::settle_interrupted_swap(dir)?;
        let store = LocalStore::open(dir)?;
        let registration_vk = registry::registration_circuit(&crs)?.vk;
        Ok(Registry {
            store,
            crs,
            registration_vk,
            verifiers: Mutex::new(BTreeMap::new()),
            agreement: Mutex::new(None),
            checks: AtomicU64::new(0),
        })
    }

    /// A ticket for a run of the registry check (`crate::status::check_registry`)
    /// that begins now: a later run gets a larger one.
    pub fn begin_check(&self) -> u64 {
        self.checks.fetch_add(1, Ordering::Relaxed) + 1
    }

    /// Record what the run holding `ticket` found, unless a run that began
    /// later has recorded already: runs overlap (one at start or on the
    /// timer, one after each registry body), and the one that began last
    /// read the rows last.
    pub fn record_agreement(&self, ticket: u64, status: RegistryReport) {
        let mut held = self
            .agreement
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if held.as_ref().is_none_or(|(recorded, _)| *recorded < ticket) {
            *held = Some((ticket, status));
        }
    }

    /// The latest registry check recorded; `None` before the first.
    pub fn agreement(&self) -> Option<RegistryReport> {
        self.agreement
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .map(|(_, status)| status.clone())
    }

    /// The registry rows, for the stateless prefix and the GET routes.
    pub fn store(&self) -> &LocalStore {
        &self.store
    }

    /// The verifier's G2 point.
    pub fn g2(&self) -> G2 {
        self.crs.g2
    }

    /// The built-in registration circuit's vk, computed at open.
    pub fn registration_vk(&self) -> &BbVerifyingKey {
        &self.registration_vk
    }

    /// A manifest message's contract manifest, its facts and the vk of each
    /// of its circuits, built in parallel as the nodes build them at their
    /// step 4 (400 for a circuit that does not compile to a vk under this
    /// CRS, or whose vk hash is not the manifest's). Nothing is built when
    /// the copy holds the body's contract manifest already.
    pub fn compute(&self, body: &ManifestMessage) -> Result<ComputedMessage, Refusal> {
        let contract = body.contract_manifest()?;
        let hash = manifest_hash(&body.manifest).map_err(|r| under(r, "manifest"))?;
        let facts = ManifestFacts::of(&contract, hash);
        let held = self.store.contract_manifest(body.namespace.fr())?;
        if held.is_some_and(|m| m.manifest_hash == hash) {
            return Ok(ComputedMessage {
                contract,
                facts,
                circuits: BTreeMap::new(),
            });
        }
        // a circuit a held version stores byte for byte keeps its vk, as at
        // the nodes (sidecar-core `registry::held_vks`)
        let held = registry::held_vks(&self.store, body.namespace.fr())?;
        let built: Vec<(String, Result<Computed, Refusal>)> = std::thread::scope(|s| {
            let handles: Vec<_> = body
                .circuits
                .iter()
                .map(|(id, circuit)| {
                    let crs = &self.crs;
                    let held = &held;
                    (
                        id.clone(),
                        s.spawn(move || reuse_or_compute(crs, held, id, circuit)),
                    )
                })
                .collect();
            handles
                .into_iter()
                .map(|(id, h)| {
                    let result = h.join().unwrap_or_else(|_| {
                        Err(Refusal::mpc_failure(format!(
                            "the vk build of `{id}` panicked"
                        )))
                    });
                    (id, result)
                })
                .collect()
        });
        let mut circuits = BTreeMap::new();
        for (id, result) in built {
            let computed = result.map_err(|r| under(r, &format!("circuits.{id}")))?;
            let declared = contract.document.circuits[&id].vk_hash.fr();
            if computed.vk_hash != declared {
                return Err(Refusal::bad_request(format!(
                    "field `manifest.circuits.{id}.vk_hash`: {}, but the circuit's vk hash is {}",
                    fr_to_hex(declared),
                    fr_to_hex(computed.vk_hash)
                )));
            }
            circuits.insert(id, computed);
        }
        Ok(ComputedMessage {
            contract,
            facts,
            circuits,
        })
    }

    /// The verifier of a stored package: from the cache when it was built from
    /// a row of this version with this row's seq and vk_hash, else built from
    /// the row's stored vk and manifest (500 if the stored vk does not decode
    /// or hash to its vk_hash).
    pub fn verifier(&self, namespace: Fr, pkg: &PackageRow) -> Result<Arc<Verifier>, Refusal> {
        let key = (namespace, pkg.manifest_hash, pkg.name.clone());
        if let Some(hit) = self
            .cache()
            .get(&key)
            .filter(|hit| hit.seq == pkg.seq && hit.vk_hash == pkg.vk_hash)
        {
            return Ok(hit.clone());
        }
        let shape = self.shape(pkg)?;
        let vk = crs::stored_vk(&pkg.name, &pkg.vk, pkg.vk_hash).map_err(|e| {
            Refusal::mpc_failure(format!("registry copy: package `{}`: {e:#}", pkg.name))
        })?;
        let verifier = Arc::new(Verifier {
            name: pkg.name.clone(),
            vk,
            vk_hash: pkg.vk_hash,
            shape,
            seq: pkg.seq,
        });
        self.cache().insert(key, verifier.clone());
        Ok(verifier)
    }

    /// The manifest's shape of a stored package, direct or queued (500 if
    /// the stored row no longer parses: the nodes checked it at REGISTER).
    pub fn shape(&self, pkg: &PackageRow) -> Result<CircuitShape, Refusal> {
        pkg.parse().map(|(_, shape)| shape)
    }

    fn cache(&self) -> std::sync::MutexGuard<'_, BTreeMap<(Fr, Fr, String), Arc<Verifier>>> {
        self.verifiers
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Every package of `namespace`, of every version the copy holds,
    /// disabled ones included.
    pub fn packages(&self, namespace: Fr) -> Vec<PackageRow> {
        self.store.packages(namespace)
    }

    /// The packages of `namespace`'s contract manifest version
    /// `manifest_hash`, disabled ones included.
    pub fn packages_in(&self, namespace: Fr, manifest_hash: Fr) -> Vec<PackageRow> {
        self.store.packages_in(namespace, manifest_hash)
    }

    /// Record a REGISTER the three nodes answered and signed, as the nodes
    /// committed it, in one transaction: a `seq` 0 body writes (or repairs)
    /// the namespace row, the contract manifest and every package; a later
    /// body advances `seq` and writes them, or, for the contract manifest the
    /// copy holds, clears every package's `disabled` flag (a re-enable);
    /// the idempotent resend of the stored body writes nothing.
    pub fn record_register(
        &self,
        body: &ManifestMessage,
        response: &ManifestResponse,
        computed: ComputedMessage,
    ) -> Result<(), Refusal> {
        let namespace = body.namespace.fr();
        let owner = point_from_wire(&body.owner_pubkey).map_err(Refusal::forbidden)?;
        let stored = self.store.namespace(namespace)?;
        let held = self.store.contract_manifest(namespace)?;
        let hash = computed.facts.manifest_hash;
        let same = held.as_ref().is_some_and(|m| m.manifest_hash == hash);
        let rows = if body.seq == 0 {
            let row = NamespaceRow {
                owner_pubkey: owner,
                nsk_app: Share::default(),
                npk_app_hash: response.npk_app_hash.fr(),
                seq: 0,
            };
            RegisterRows::First {
                row,
                stored: stored.is_some(),
            }
        } else if stored
            .as_ref()
            .is_some_and(|row| registry::register_resent(row, held.as_ref(), hash, body.seq))
        {
            return Ok(());
        } else {
            RegisterRows::Later(body.seq)
        };
        let packages = if same {
            // the stored rows, enabled at this seq
            self.store
                .packages_in(namespace, hash)
                .into_iter()
                .map(|pkg| PackageRow {
                    disabled: false,
                    seq: body.seq,
                    ..pkg
                })
                .collect()
        } else {
            let mut rows = Vec::with_capacity(computed.contract.document.packages.len());
            for (entry, _) in computed.contract.packages() {
                let built = computed.circuits.get(&entry.circuit).ok_or_else(|| {
                    out_of_step(Refusal::mpc_failure(format!(
                        "the copy built no vk of circuit `{}`",
                        entry.circuit
                    )))
                })?;
                rows.push(PackageRow {
                    name: entry.name.clone(),
                    manifest_hash: hash,
                    circuit_json: built.circuit_json.clone(),
                    manifest: entry.manifest.clone(),
                    vk: built.vk.to_buffer(),
                    vk_hash: built.vk_hash,
                    disabled: false,
                    seq: body.seq,
                });
            }
            rows
        };
        let mut txn = self.store.begin(namespace);
        registry::stage_register(
            &mut txn,
            rows,
            ManifestRow {
                manifest_hash: hash,
                document: body.manifest.clone(),
                seq: body.seq,
            },
            packages,
        );
        self.store.commit(txn).map_err(out_of_step)
    }

    /// Record a DISABLE the three nodes answered and signed: the `disabled`
    /// flag and `seq` of the package of that name in every version the copy
    /// holds, and the namespace's `seq`, unless it is the idempotent resend.
    pub fn record_disable(
        &self,
        body: &DisableRequest,
        response: &DisableResponse,
    ) -> Result<(), Refusal> {
        let namespace = body.namespace.fr();
        let held = registry::held_packages(&self.store, namespace, &body.circuit)?;
        if held.is_empty() {
            return Err(out_of_step(Refusal::not_found(format!(
                "the nodes disabled `{}`, which this copy does not hold",
                body.circuit
            ))));
        }
        if registry::disable_resent(&held, response.seq) {
            return Ok(());
        }
        let mut txn = self.store.begin(namespace);
        registry::stage_disable(&mut txn, held, response.seq);
        self.store.commit(txn).map_err(out_of_step)
    }
}

/// Whether every node refused a registry body (answered other than 200), so
/// none wrote a row. A node that gave no answer may still have committed the
/// body, so a transport failure does not count as a refusal.
pub fn all_refused(replies: &[Reply; NODES]) -> bool {
    replies
        .iter()
        .all(|r| r.as_ref().is_ok_and(|a| a.status != 200))
}

/// The three nodes' answers to a registry body (`what`: REGISTER or DISABLE).
/// A node answers only once it holds the body committed, so when some nodes
/// answer and the others refuse or give no answer, the nodes' registries
/// diverged: 500 naming the nodes on each side, the refusals, and the repair,
/// and the registry copy records nothing. Otherwise the three answers, or the
/// most specific refusal ([`crate::nodes::all_answers`]).
pub fn committed_answers<T: DeserializeOwned>(
    what: &str,
    replies: [Reply; NODES],
) -> Result<[T; NODES], Refusal> {
    let each = each_answer::<T>(replies);
    let (committed, refused): (Vec<usize>, Vec<usize>) = (0..NODES).partition(|&i| each[i].is_ok());
    if committed.is_empty() || refused.is_empty() {
        return best_of(each);
    }
    let reasons: Vec<&str> = each
        .iter()
        .filter_map(|a| a.as_ref().err())
        .map(|r| r.message.as_str())
        .collect();
    let divergence = Refusal::mpc_failure(format!(
        "the nodes' registries diverged: {} committed this {what} body and {} did not ({}); \
         the orchestrator's registry copy is unchanged. Resend the same signed body: the \
         nodes that hold it answer it unchanged and the others commit it (a seq 0 REGISTER \
         while the namespace's seq is still 0 is repaired the same way); a node that \
         refuses it again holds other registry rows than the other two",
        named(&committed),
        named(&refused),
        reasons.join("; ")
    ));
    tracing::warn!(error = %divergence.message, "a registry body diverged the nodes");
    Err(divergence)
}

/// "node 0", "nodes 0 and 2".
fn named(nodes: &[usize]) -> String {
    match nodes {
        [one] => format!("node {one}"),
        [first, second] => format!("nodes {first} and {second}"),
        _ => format!("nodes {nodes:?}"),
    }
}

/// The vk of the circuit `name` (a compiled circuit's JSON), as the nodes
/// compute it at their REGISTER step 4, with the circuit JSON as they store
/// it (400 for a circuit that does not compile to a vk under `crs`; the
/// caller names the field).
pub fn compute(crs: &Crs, name: &str, circuit: &Value) -> Result<Computed, Refusal> {
    let circuit_json =
        serde_json::to_vec(circuit).map_err(|e| Refusal::bad_request(format!("body: {e}")))?;
    let artifact = Artifact::from_json(name, &circuit_json)
        .map_err(|e| Refusal::bad_request(format!("body: not a compiled Noir circuit: {e:#}")))?;
    let needed = crs::crs_points(artifact.circuit_size);
    let held = crs.prover.monomials.len();
    if needed > held {
        return Err(Refusal::bad_request(format!(
            "body: `{name}` needs {needed} CRS points; this network holds {held}"
        )));
    }
    let circuit = Circuit::new(artifact, &crs.prover)
        .map_err(|e| Refusal::bad_request(format!("body: no verification key: {e:#}")))?;
    Ok(Computed {
        circuit_json,
        vk: circuit.vk,
        vk_hash: circuit.vk_hash,
    })
}

/// The vk of the circuit `name` taken from a held version's package whose
/// stored bytes are equal (`held`, by bytes), else [`compute`]d.
fn reuse_or_compute(
    crs: &Crs,
    held: &registry::HeldVks,
    name: &str,
    circuit: &Value,
) -> Result<Computed, Refusal> {
    let circuit_json =
        serde_json::to_vec(circuit).map_err(|e| Refusal::bad_request(format!("body: {e}")))?;
    match held.get(&circuit_json) {
        Some((vk, vk_hash)) => Ok(Computed {
            vk: crs::stored_vk(name, vk, *vk_hash)
                .map_err(|e| Refusal::mpc_failure(format!("registry copy: {e:#}")))?,
            vk_hash: *vk_hash,
            circuit_json,
        }),
        None => compute(crs, name, circuit),
    }
}

/// `refusal` (a "body: ..." message of [`compute`] or the manifest hash)
/// naming `field` of the manifest message.
fn under(refusal: Refusal, field: &str) -> Refusal {
    let why = refusal
        .message
        .strip_prefix("body: ")
        .unwrap_or(&refusal.message);
    Refusal::new(refusal.class, format!("field `{field}`: {why}"))
}

/// A copy that refuses what the three nodes committed has fallen out of step
/// with them: 500, telling the operator how to bring it level.
fn out_of_step(refusal: Refusal) -> Refusal {
    Refusal::mpc_failure(format!(
        "the nodes committed the registry body, but the orchestrator's registry copy \
         refused it ({}); if this is the only body the copy missed, resend it, else \
         rebuild the copy from the nodes with `sidecar-orchestrator sync-registry`",
        refusal.message
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use sidecar_core::ErrorClass;
    use sidecar_http::client::Answer;
    use sidecar_test_fixtures::data::require_crs;
    use sidecar_test_fixtures::dirs::TempDir;

    fn ok(value: u64) -> Reply {
        Ok(Answer {
            status: 200,
            body: value.to_string().into_bytes(),
        })
    }

    fn says(class: ErrorClass, message: &str) -> Reply {
        Ok(Answer {
            status: class.status(),
            body: Refusal::new(class, message).to_json().into_bytes(),
        })
    }

    /// The registry check reruns after a body unless every node refused it:
    /// a node that answered 200, or gave no answer, may have committed it.
    #[test]
    fn only_three_refusals_skip_the_recheck() {
        let refusals = || {
            [
                says(ErrorClass::Conflict, "wrong seq"),
                says(ErrorClass::Forbidden, "not the owner"),
                says(ErrorClass::MpcFailure, "store: disk full"),
            ]
        };
        assert!(all_refused(&refusals()));
        let [a, _, c] = refusals();
        assert!(!all_refused(&[a, ok(1), c]));
        let [a, _, c] = refusals();
        assert!(!all_refused(&[a, Err(eyre::eyre!("connection reset")), c]));
    }

    /// A registry body that some nodes answered (committed) and the others
    /// refused, failed to commit or did not answer is 500 naming the
    /// divergence and the resend; all three answering, or all three refusing,
    /// is as `all_answers` has it.
    #[test]
    fn a_body_only_some_nodes_committed_is_a_named_divergence() {
        let err = committed_answers::<u64>(
            "DISABLE",
            [
                ok(1),
                ok(1),
                says(ErrorClass::MpcFailure, "store: disk full"),
            ],
        )
        .unwrap_err();
        assert_eq!(err.class, ErrorClass::MpcFailure);
        assert!(
            err.message.starts_with(
                "the nodes' registries diverged: nodes 0 and 1 committed this DISABLE body \
                 and node 2 did not (node 2: store: disk full); the orchestrator's registry \
                 copy is unchanged. Resend the same signed body"
            ),
            "{err}"
        );

        let err = committed_answers::<u64>(
            "REGISTER",
            [
                Err(eyre::eyre!("connection reset")),
                ok(1),
                says(ErrorClass::Conflict, "wrong seq"),
            ],
        )
        .unwrap_err();
        assert_eq!(err.class, ErrorClass::MpcFailure);
        assert!(
            err.message.contains(
                "node 1 committed this REGISTER body and nodes 0 and 2 did not (node 0: no \
                 answer: connection reset; node 2: wrong seq)"
            ),
            "{err}"
        );

        assert_eq!(
            committed_answers::<u64>("DISABLE", [ok(1), ok(2), ok(3)]).unwrap(),
            [1, 2, 3]
        );
        let err = committed_answers::<u64>(
            "DISABLE",
            [
                says(ErrorClass::Forbidden, "not the owner"),
                says(ErrorClass::Conflict, "wrong seq"),
                Err(eyre::eyre!("reset")),
            ],
        )
        .unwrap_err();
        assert_eq!(err.class, ErrorClass::Forbidden);
        assert_eq!(err.message, "node 0: not the owner");
    }

    // A package row of the AMM tip manifest (testvectors/manifests) over an ABI
    // it fits; the shape reads only the circuit's ABI.
    fn tip_row() -> PackageRow {
        let field = json!({"kind": "field"});
        let abi = json!({
            "parameters": [
                {"name": "namespace", "type": field, "visibility": "public"},
                {"name": "vk_hash", "type": field, "visibility": "public"},
                {"name": "in_slots", "type": {"kind": "array", "length": 1, "type": field}, "visibility": "public"},
                {"name": "out_slots", "type": {"kind": "array", "length": 1, "type": field}, "visibility": "public"},
                {"name": "amount_in", "type": field, "visibility": "private"},
                {"name": "direction", "type": field, "visibility": "private"},
                {"name": "min_out", "type": field, "visibility": "private"},
                {"name": "partial_note", "type": field, "visibility": "private"},
                {"name": "user_nonce", "type": field, "visibility": "private"},
                {"name": "pool", "type": {"kind": "array", "length": 2, "type": field}, "visibility": "private"},
                {"name": "r_old", "type": field, "visibility": "private"},
                {"name": "r_new", "type": field, "visibility": "private"},
                {"name": "nsk_app", "type": field, "visibility": "private"}
            ],
            "return_type": {"abi_type": {"kind": "struct", "path": "AmmTipOut", "fields": [
                {"name": "request_id", "type": field},
                {"name": "old_c", "type": field},
                {"name": "new_c", "type": field}
            ]}, "visibility": "public"},
            "error_types": {}
        });
        let manifest: Value = serde_json::from_str(include_str!(
            "../../../testvectors/manifests/amm_swap_tip.json"
        ))
        .unwrap();
        PackageRow {
            name: "amm_swap_tip".into(),
            manifest_hash: Fr::from(2u64),
            circuit_json: serde_json::to_vec(&json!({"abi": abi})).unwrap(),
            manifest,
            vk: vec![],
            vk_hash: Fr::from(1u64),
            disabled: false,
            seq: 1,
        }
    }

    /// Each held version of a name keeps its own verifier, built from the
    /// row's stored vk: two versions sharing a vk (an upgrade that left the
    /// circuit unchanged) are served from the cache in turn. A stored vk that
    /// does not hash to its row's vk_hash is refused.
    #[test]
    fn each_held_version_keeps_its_verifier() {
        let tmp = TempDir::new("verifiers");
        let registry = Registry::open(tmp.path(), require_crs(&[])).unwrap();
        let vk = registry.registration_vk().to_buffer();
        let vk_hash = sidecar_core::hash::vk_hash(registry.registration_vk());
        let ns = Fr::from(9u64);
        let row = |hash: u64, seq: u64| PackageRow {
            manifest_hash: Fr::from(hash),
            vk: vk.clone(),
            vk_hash,
            seq,
            ..tip_row()
        };
        let (older, newer) = (row(2, 1), row(3, 2));
        let first = registry.verifier(ns, &older).unwrap();
        let second = registry.verifier(ns, &newer).unwrap();
        assert!(!Arc::ptr_eq(&first, &second));
        assert_eq!(first.vk_hash, vk_hash);
        assert!(Arc::ptr_eq(&first, &registry.verifier(ns, &older).unwrap()));
        assert!(Arc::ptr_eq(
            &second,
            &registry.verifier(ns, &newer).unwrap()
        ));
        let damaged = PackageRow {
            vk_hash: vk_hash + Fr::from(1u64),
            ..row(4, 3)
        };
        let err = registry.verifier(ns, &damaged).err().unwrap();
        assert_eq!(err.class, ErrorClass::MpcFailure);
        assert!(err.message.contains("hashes to"), "{err}");
    }

    /// The registry copy reads a queued package the nodes registered, so
    /// `sync-registry` keeps it and the answer checks of its rounds read its
    /// shape.
    #[test]
    fn the_copy_reads_a_queued_package() {
        let (_, shape) = tip_row().parse().unwrap();
        assert_eq!(shape.public_input_count, 7);
        assert_eq!(shape.return_index("old_c"), Some(5));
        assert_eq!(shape.outputs[0].note_hash_index, 6);
        let mut broken = tip_row();
        broken.manifest["commitment_slot"]["$state_keys.reads[0]"]["old"] = json!("gone");
        let err = broken.parse().unwrap_err();
        assert!(
            err.message
                .contains("store: package `amm_swap_tip`: the manifest"),
            "{err}"
        );
    }
}
