//! The registry lifecycle (ARCHITECTURE.md section 4): signed REGISTER (the
//! manifest message) and DISABLE bodies with the namespace's sequence number, the registration
//! circuit that derives each namespace's nullifier key, the node's signed
//! answers, the orchestrator's check of the three answers, and the lookups the
//! request lifecycle and the GET routes use.
//!
//! Every function here runs on one node (or in the orchestrator) and leaves
//! the locking to its caller: the node takes the namespace lock for every
//! registry body, and for a `seq` 0 REGISTER also the node-wide mesh session
//! lock (the orchestrator its global session lock), because a `seq` 0 body runs
//! the registration circuit over the mesh.
//!
//! The steps of [`register`] and [`disable`] are those of the section 4 table:
//! 1 parse ([`Signed::from_json`]), 2 owner and seq, 3 checks, 4 keys, 5 commit,
//! 6 respond.

use std::collections::BTreeMap;

use ark_std::rand::{CryptoRng, RngCore};
use co_noir_types::{Rep3SharedInput, Rep3Type};
use mpc_net::Network;
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::abi::{CircuitShape, check_manifest_value, check_tip_public_prefix};
use crate::crs::{self, Artifact, BbVerifyingKey, Circuit, Crs, G2};
use crate::error::{Refusal, parse_json, parse_value};
use crate::executor::{self, Elem, NamespaceCheck, Share};
use crate::field::{FieldHex, Fr, HexBytes, fr_to_hex};
use crate::grumpkin::{Point, point_from_wire};
use crate::hash::poseidon2_hash;
use crate::keys::NodeKeys;
use crate::manifest::contract::{
    CheckedContractManifest, ContractManifest, check_upgradable, check_upgrade, manifest_hash,
};
use crate::manifest::{Manifest, refuse_own_address};
use crate::register::{
    ContractManifestResponse, DisableAnswer, DisableRequest, DisableResponse, ManifestAnswer,
    ManifestMessage, ManifestResponse, NamespaceResponse, NamespacesResponse, PackageNamesResponse,
    PackageResponse, Registration, Signature, prefix_field,
};
use crate::request::{GrumpkinPoint, NODES};
use crate::schnorr::{DISABLE_DOMAIN, REGISTER_DOMAIN, message_for, poseidon2_hash_bytes, sign};
use crate::state::StateHolders;
use crate::store::{
    ManifestRow, NamespaceRow, PackageRow, Store, StoreRead, Txn, held_versions, rules,
};

mod answers;
mod register_rules;
mod registration;

pub use answers::*;
pub use register_rules::*;
pub use registration::*;

// ---------------------------------------------------------------------------
// Signed bodies
// ---------------------------------------------------------------------------

/// A registry body type: its signing domain and its own checks.
pub trait RegistryBody: Serialize + DeserializeOwned {
    /// The domain of [`message_for`] for this kind of body.
    const DOMAIN: &'static str;
    /// The parse-time checks beyond the JSON shape.
    fn check(&self) -> Result<(), Refusal>;
}

impl RegistryBody for ManifestMessage {
    const DOMAIN: &'static str = REGISTER_DOMAIN;
    fn check(&self) -> Result<(), Refusal> {
        ManifestMessage::check(self)
    }
}

impl RegistryBody for DisableRequest {
    const DOMAIN: &'static str = DISABLE_DOMAIN;
    fn check(&self) -> Result<(), Refusal> {
        DisableRequest::check(self)
    }
}

/// A parsed registry body with the message its signature must cover.
///
/// The message is computed over the body as received (its JSON value, before
/// the typed parse normalises any field), so a client that signs exactly what
/// it sends, in whatever hex form, is checked against what it signed.
#[derive(Clone, Debug, PartialEq)]
pub struct Signed<T> {
    pub body: T,
    /// `poseidon2_hash_bytes(domain ‖ JCS(body without signature))`.
    pub message: Fr,
}

impl<T: RegistryBody> Signed<T> {
    /// Parse a received body: the JSON, the typed fields and their checks
    /// (400, naming the field), and the signed message over the received JSON.
    pub fn from_json(text: &str) -> Result<Self, Refusal> {
        let value: Value = parse_json(text)?;
        let body: T = parse_value(&value)?;
        body.check()?;
        Self::with_value(body, &value)
    }

    /// A body built in code: the message is over its serialisation, which is
    /// also what the orchestrator forwards.
    pub fn new(body: T) -> Result<Self, Refusal> {
        body.check()?;
        let value =
            serde_json::to_value(&body).map_err(|e| Refusal::bad_request(format!("body: {e}")))?;
        Self::with_value(body, &value)
    }

    fn with_value(body: T, value: &Value) -> Result<Self, Refusal> {
        let message = message_for(T::DOMAIN, value)
            .map_err(|e| Refusal::bad_request(format!("body: {e}")))?;
        Ok(Signed { body, message })
    }
}

// ---------------------------------------------------------------------------
// One node's registry
// ---------------------------------------------------------------------------

/// A node's own REGISTER check of one package (400), run after the manifest
/// and state checks: a rule that reads the node's configuration, which the
/// three nodes may hold differently (sidecar-node checks a secret-shared
/// receipt package's stale period against its `enc` grace window), and the
/// tip's per-intake rules on the circuit's shape (sidecar-tip's
/// `IntakeSource::check_register`: secret-shared on-chain intake's request log
/// bound). Like every check that needs no mesh, a refusal of a `seq` 0 body
/// still joins the session's handshake, so the other two nodes refuse it too
/// ([`crate::Node::register`]).
pub type RegisterHook = Box<dyn Fn(&RegisterView) -> Result<(), Refusal> + Send + Sync>;

/// What REGISTER hands the node's own check ([`RegisterHook`]) for each
/// package: the body's namespace, the package's name, checked circuit
/// manifest and its circuit's shape, and the whole checked contract manifest
/// (its queue's stale period, the other packages).
pub struct RegisterView<'a> {
    pub namespace: Fr,
    pub name: &'a str,
    pub manifest: &'a Manifest,
    pub shape: &'a CircuitShape,
    pub contract: &'a CheckedContractManifest,
}

/// The default REGISTER hook: the node adds no check of its own.
pub fn no_register_check(_: &RegisterView) -> Result<(), Refusal> {
    Ok(())
}

/// What a node brings to a registry body besides its store.
pub struct RegistryNode<'a> {
    /// This node's index (0, 1, 2): its party id and the `i` it signs.
    pub index: usize,
    pub keys: &'a NodeKeys,
    /// This node's master nullifier share. Only the registration circuit reads it.
    pub master: Share,
    /// The CRS every vk is computed under.
    pub crs: &'a Crs,
    /// The registration circuit under `crs` ([`registration_circuit`]).
    pub registration: &'a Circuit,
    /// The state modes this node serves: REGISTER refuses any other.
    pub holders: StateHolders,
    /// The node's own REGISTER check ([`RegisterHook`]).
    pub register_check: &'a (dyn Fn(&RegisterView) -> Result<(), Refusal> + Send + Sync),
}

impl RegistryNode<'_> {
    fn sign<R: RngCore + CryptoRng>(&self, message: Fr, rng: &mut R) -> Signature {
        sign(self.keys.sig_scalar(), message, rng)
    }
}

/// The owner signature first (403): the key must be a Grumpkin point and the
/// signature must verify over the received body's message.
fn verify_owner<T>(
    body: &Signed<T>,
    owner: &GrumpkinPoint,
    signature: Signature,
    kind: &str,
) -> Result<Point, Refusal> {
    if !crate::schnorr::verify_wire(owner, signature, body.message) {
        return Err(Refusal::forbidden(format!(
            "the {kind} signature does not verify under `owner_pubkey`"
        )));
    }
    point_from_wire(owner).map_err(Refusal::forbidden)
}

/// A later body's owner and namespace row (403 without either).
fn stored_owner<S: StoreRead + ?Sized>(
    store: &S,
    namespace: Fr,
    owner: Point,
) -> Result<NamespaceRow, Refusal> {
    let row = store.namespace(namespace)?.ok_or_else(|| {
        Refusal::forbidden(format!(
            "namespace {} has no owner here; its first REGISTER carries seq 0",
            fr_to_hex(namespace)
        ))
    })?;
    if row.owner_pubkey != owner {
        return Err(Refusal::forbidden(format!(
            "`owner_pubkey` is not the owner of namespace {}",
            fr_to_hex(namespace)
        )));
    }
    Ok(row)
}

/// Whether a later REGISTER body is the resend of the last registry body the
/// namespace committed: the stored contract manifest has the body's hash and
/// was written at the body's `seq`, and nothing was committed since. It is
/// answered again and commits nothing.
pub fn register_resent(
    row: &NamespaceRow,
    stored: Option<&ManifestRow>,
    manifest_hash: Fr,
    seq: u64,
) -> bool {
    row.seq == seq && stored.is_some_and(|m| m.manifest_hash == manifest_hash && m.seq == seq)
}

/// The packages named `name` in every contract manifest version
/// `namespace` holds, newest version first: the rows a DISABLE writes, so a
/// round under any held version, the one in force included, is refused.
pub fn held_packages<S: StoreRead + ?Sized>(
    store: &S,
    namespace: Fr,
    name: &str,
) -> Result<Vec<PackageRow>, Refusal> {
    let mut out = Vec::new();
    for m in store.contract_manifests(namespace)? {
        out.extend(store.package_in(namespace, m.manifest_hash, name)?);
    }
    Ok(out)
}

/// Whether the stored packages `held` ([`held_packages`]) are what a
/// DISABLE at `seq` left: it is answered again and commits nothing.
pub fn disable_resent(held: &[PackageRow], seq: u64) -> bool {
    !held.is_empty() && held.iter().all(|pkg| pkg.disabled && pkg.seq == seq)
}

/// The namespace rows a committed REGISTER writes besides its manifest and
/// packages.
pub enum RegisterRows {
    /// A `seq` 0 body: the namespace row, a repair of the stored one when
    /// `stored`.
    First { row: NamespaceRow, stored: bool },
    /// A later body: the namespace's `seq` advances to the body's.
    Later(u64),
}

/// Stage a committed REGISTER: its namespace rows, the contract manifest
/// and every package (enabled, at the body's `seq`), in one transaction.
pub fn stage_register(
    txn: &mut Txn,
    rows: RegisterRows,
    manifest: ManifestRow,
    packages: Vec<PackageRow>,
) {
    match rows {
        RegisterRows::First { row, stored: true } => txn.repair_namespace(row),
        RegisterRows::First { row, stored: false } => txn.register_namespace(row),
        RegisterRows::Later(seq) => txn.advance_seq(seq),
    }
    txn.put_manifest(manifest);
    for package in packages {
        txn.put_package(package);
    }
}

/// Stage a committed DISABLE at `seq` of the stored packages `held`
/// ([`held_packages`]): each one's `disabled` flag and `seq`, and the
/// namespace's `seq`. Returns the rows written.
pub fn stage_disable(txn: &mut Txn, held: Vec<PackageRow>, seq: u64) -> Vec<PackageRow> {
    txn.advance_seq(seq);
    held.into_iter()
        .map(|pkg| {
            let pkg = PackageRow {
                disabled: true,
                seq,
                ..pkg
            };
            txn.put_package(pkg.clone());
            pkg
        })
        .collect()
}

/// What a node signs for one manifest message: the manifest hash and the
/// packages hash.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ManifestFacts {
    pub manifest_hash: Fr,
    pub packages_hash: Fr,
}

impl ManifestFacts {
    /// The facts of a checked contract manifest whose document hashes to
    /// `manifest_hash`.
    pub fn of(checked: &CheckedContractManifest, manifest_hash: Fr) -> Self {
        ManifestFacts {
            manifest_hash,
            packages_hash: checked.packages_hash(),
        }
    }
}

fn register_answer<R: RngCore + CryptoRng>(
    node: &RegistryNode,
    namespace: Fr,
    facts: &ManifestFacts,
    npk_app_hash: Fr,
    seq: u64,
    registration: Option<Registration>,
    rng: &mut R,
) -> ManifestAnswer {
    let message = manifest_message(
        namespace,
        facts.manifest_hash,
        facts.packages_hash,
        npk_app_hash,
        seq,
        node.index,
    );
    ManifestAnswer {
        manifest_hash: FieldHex(facts.manifest_hash),
        packages_hash: FieldHex(facts.packages_hash),
        npk_app_hash: FieldHex(npk_app_hash),
        seq,
        signature: node.sign(message, rng),
        registration,
    }
}

// The namespace owner key is the namespace's root of trust. The first
// REGISTER of a namespace (seq 0) records the key that signed it; from then
// on every REGISTER and DISABLE must be signed by that key and carry the
// stored seq plus one, so a replayed or reordered body changes nothing (409),
// and nobody but the owner registers or disables (403). There is no key
// rotation and no recovery: a lost owner key freezes the namespace's
// registry (its packages keep running), a leaked one lets whoever holds it
// disable packages and, on the sidecar path, replace the contract manifest.
// A seq 0 body is accepted only while the stored seq is 0 and always reruns
// the registration circuit, so a first REGISTER that committed on some
// nodes only is repaired by resending it; its answer always carries seq 0.
// A body resent with the seq it was registered with, nothing committed
// since, gets the stored values back (a client retry after a lost answer).
//
// The unit is the whole manifest message. A later REGISTER of the stored
// contract manifest (the same manifest hash) re-enables every package and
// changes nothing else. A later REGISTER of another contract manifest
// replaces the stored one on the sidecar path (no queue in either). A tip
// namespace's contract commits to its first contract manifest by the
// address: under `upgrades: fixed` the nodes refuse another (400); under
// `circuits` or `contract` they accept a replacement that passes
// `check_upgrade` against the newest held version and keep it beside the
// versions before it (`store::retained_versions`), and each round runs under
// the version the contract's pins name on the node's own chain view. The
// owner key alone can upload a version, never make it run: only the upgrade
// authority's call on chain changes the pins.
/// REGISTER on one node (section 4, steps 2 to 6). `net` is the mesh session
/// a `seq` 0 body runs the registration circuit over; a later body ignores it.
/// The same as [`check_register`] then [`finish_register`].
///
/// Refusals: 403 (signature, owner), 409 (seq, another contract manifest at
/// seq 0), 400 (manifest, ABI, circuit, vk hash, another contract manifest of
/// a tip namespace), 422 or 500 (the registration round), 500 (store; a
/// repair whose proven npk_app_hash differs from the stored one).
pub fn register<S, N, R>(
    store: &S,
    node: &RegistryNode,
    net: Option<&N>,
    body: &Signed<ManifestMessage>,
    rng: &mut R,
) -> Result<ManifestAnswer, Refusal>
where
    S: Store + ?Sized,
    N: Network,
    R: RngCore + CryptoRng,
{
    let checked = check_register(store, node, body)?;
    finish_register(store, node, checked, net, rng)
}

/// A REGISTER body that passed every check that needs no mesh: what
/// [`finish_register`] has left to do.
pub struct CheckedRegister<'b> {
    body: &'b ManifestMessage,
    owner: Point,
    stored: Option<NamespaceRow>,
    facts: ManifestFacts,
    plan: Plan,
}

enum Plan {
    /// A resent body: answer the stored values, change nothing.
    Stored { npk_app_hash: Fr },
    /// The stored contract manifest again at the next seq: clear every
    /// `disabled` flag.
    Reenable { packages: Vec<PackageRow> },
    /// A contract manifest to commit, after the registration circuit for a
    /// seq 0 body.
    Commit {
        document: Value,
        packages: Vec<PackageRow>,
    },
}

/// Section 4 steps 2 and 3 and the local half of step 4 (each circuit's vk
/// and vk hash from its bytes and the CRS) on one node: everything a
/// REGISTER needs that is not the mesh. Reads the store, writes nothing.
///
/// Refusals: 403 (signature, owner), 409 (seq, another contract manifest at
/// seq 0), 400 (the contract manifest and its checks across packages; per
/// package the manifest against its ABI, the public-input layout, the
/// outcome, a read naming the namespace's own address, a state mode this
/// node does not serve or that its holder refuses, the node's own check,
/// [`RegisterHook`]; a circuit whose vk hash is not the manifest's; another
/// contract manifest of a tip namespace).
pub fn check_register<'b, S>(
    store: &S,
    node: &RegistryNode,
    body: &'b Signed<ManifestMessage>,
) -> Result<CheckedRegister<'b>, Refusal>
where
    S: Store + ?Sized,
{
    let req = &body.body;
    let namespace = req.namespace.fr();
    // the body's own checks ran when it was parsed (`Signed`); this is the
    // typed view
    let contract = req.contract_manifest()?;
    let manifest_hash = manifest_hash(&req.manifest).map_err(|r| prefix_field(r, "manifest"))?;
    let facts = ManifestFacts::of(&contract, manifest_hash);

    // 2. owner and seq
    let owner = verify_owner(body, &req.owner_pubkey, req.signature, "REGISTER")?;
    let stored = store.namespace(namespace)?;
    let held = store.contract_manifest(namespace)?;
    if req.seq == 0 {
        if let Some(row) = &stored {
            if row.owner_pubkey != owner {
                return Err(Refusal::forbidden(format!(
                    "`owner_pubkey` is not the owner of namespace {}",
                    fr_to_hex(namespace)
                )));
            }
            if row.seq != 0 {
                return Err(Refusal::conflict(format!(
                    "a seq 0 REGISTER is accepted only while the namespace's seq is 0; it is {}",
                    row.seq
                )));
            }
        }
        if let Some(m) = &held
            && m.manifest_hash != manifest_hash
        {
            return Err(Refusal::conflict(format!(
                "namespace {} registered contract manifest {} at seq 0; a resent first \
                 REGISTER carries the same one",
                fr_to_hex(namespace),
                fr_to_hex(m.manifest_hash)
            )));
        }
    } else {
        let row = stored_owner(store, namespace, owner)?;
        if register_resent(&row, held.as_ref(), manifest_hash, req.seq) {
            return Ok(CheckedRegister {
                body: req,
                owner,
                plan: Plan::Stored {
                    npk_app_hash: row.npk_app_hash,
                },
                stored: Some(row),
                facts,
            });
        }
        rules::check_next_seq(row.seq, req.seq)?;
        if let Some(m) = &held {
            if m.manifest_hash == manifest_hash {
                let packages = store
                    .package_names(namespace)?
                    .into_iter()
                    .map(|name| store.package(namespace, &name))
                    .collect::<Result<Vec<_>, _>>()?
                    .into_iter()
                    .flatten()
                    .map(|pkg| PackageRow {
                        disabled: false,
                        seq: req.seq,
                        ..pkg
                    })
                    .collect();
                return Ok(CheckedRegister {
                    body: req,
                    owner,
                    plan: Plan::Reenable { packages },
                    stored: Some(row),
                    facts,
                });
            }
            let queued = |document: &Value| document.get("queue").is_some();
            if queued(&m.document) || queued(&req.manifest) {
                let held_upgrades = ContractManifest::parse(&m.document)
                    .map_err(|e| {
                        Refusal::mpc_failure(format!(
                            "store: contract manifest {}: {}",
                            fr_to_hex(m.manifest_hash),
                            e.message
                        ))
                    })?
                    .upgrades;
                check_upgradable(held_upgrades)
                    .and_then(|()| check_upgrade(&m.parse()?, &contract))
                    .map_err(|r| {
                        prefix_field(
                            Refusal::bad_request(format!(
                                "{} (namespace {} holds contract manifest {})",
                                r.message,
                                fr_to_hex(namespace),
                                fr_to_hex(m.manifest_hash)
                            )),
                            "manifest",
                        )
                    })?;
            }
        }
    }

    // 3. checks, per package
    let mut shapes = Vec::with_capacity(contract.manifests.len());
    for (p, (entry, _)) in contract.packages().enumerate() {
        let at = format!("manifest.packages[{p}].manifest");
        let abi = req.abi(&entry.circuit)?;
        let (manifest, shape) =
            check_manifest_value(&entry.manifest, &abi).map_err(|r| prefix_field(r, &at))?;
        check_tip_public_prefix(&manifest, &shape).map_err(|r| prefix_field(r, &at))?;
        check_outcome(&manifest, &shape).map_err(|r| prefix_field(r, &at))?;
        refuse_own_address(&manifest, namespace).map_err(|r| prefix_field(r, &at))?;
        let at = format!("manifest.packages[{p}]");
        node.holders
            .check_register(&manifest)
            .map_err(|r| prefix_field(r, &at))?
            .check_store(store.holds_values())
            .map_err(|r| prefix_field(r, &at))?;
        (node.register_check)(&RegisterView {
            namespace,
            name: &entry.name,
            manifest: &manifest,
            shape: &shape,
            contract: &contract,
        })?;
        shapes.push(shape);
    }

    // 4. keys, the local half: each circuit's vk and vk hash, built, or
    // taken from a held version's package whose circuit bytes are equal
    let held = held_vks(store, namespace)?;
    let mut built: BTreeMap<&str, (Vec<u8>, Circuit)> = BTreeMap::new();
    for (id, entry) in &contract.document.circuits {
        let circuit_json = serde_json::to_vec(&req.circuits[id])
            .map_err(|e| Refusal::bad_request(format!("field `circuits.{id}`: {e}")))?;
        let circuit = match held.get(&circuit_json) {
            Some((vk, vk_hash)) => reuse_circuit(id, &circuit_json, vk, *vk_hash)?,
            None => build_circuit(node, id, &circuit_json)?,
        };
        if circuit.vk_hash != entry.vk_hash.fr() {
            return Err(Refusal::bad_request(format!(
                "field `manifest.circuits.{id}.vk_hash`: {}, but the circuit's vk hash is {}",
                fr_to_hex(entry.vk_hash.fr()),
                fr_to_hex(circuit.vk_hash)
            )));
        }
        built.insert(id.as_str(), (circuit_json, circuit));
    }
    let mut packages = Vec::with_capacity(shapes.len());
    for ((entry, _), shape) in contract.packages().zip(&shapes) {
        let (circuit_json, circuit) = &built[entry.circuit.as_str()];
        if circuit.public_input_count() != shape.public_input_count {
            return Err(Refusal::bad_request(format!(
                "field `circuits.{}`: the bytecode has {} public inputs, the ABI {}",
                entry.circuit,
                circuit.public_input_count(),
                shape.public_input_count
            )));
        }
        packages.push(PackageRow {
            name: entry.name.clone(),
            manifest_hash,
            circuit_json: circuit_json.clone(),
            manifest: entry.manifest.clone(),
            vk: circuit.vk.to_buffer(),
            vk_hash: circuit.vk_hash,
            disabled: false,
            seq: req.seq,
        });
    }
    Ok(CheckedRegister {
        body: req,
        owner,
        stored,
        facts,
        plan: Plan::Commit {
            document: req.manifest.clone(),
            packages,
        },
    })
}

/// One compiled circuit with its vk under the node's CRS (400 for bytes that
/// are no compiled Noir circuit, a circuit larger than the CRS, no vk).
// A replacement contract manifest usually changes one circuit and keeps the
// others byte for byte. Building a vk is the expensive part of REGISTER, so
// a circuit whose stored bytes equal a package's of a version the namespace
// holds keeps that package's vk and vk hash (checked against each other, as
// every stored vk is); a byte that differs builds the vk afresh. The bytes
// are the JSON the owner sent, as stored, so a resend compares equal.
/// A stored vk and its vk hash, by the stored bytes of their circuit.
pub type HeldVks = BTreeMap<Vec<u8>, (Vec<u8>, Fr)>;

/// The vk and vk hash of every circuit the namespace's held versions store,
/// by the circuit's stored bytes.
pub fn held_vks<S: StoreRead + ?Sized>(store: &S, namespace: Fr) -> Result<HeldVks, Refusal> {
    Ok(held_versions(store, namespace)?
        .into_iter()
        .flat_map(|(_, packages)| packages)
        .map(|pkg| (pkg.circuit_json, (pkg.vk, pkg.vk_hash)))
        .collect())
}

/// A circuit whose vk a held package already stores ([`held_vks`]).
fn reuse_circuit(
    id: &str,
    circuit_json: &[u8],
    vk: &[u8],
    vk_hash: Fr,
) -> Result<Circuit, Refusal> {
    let artifact = Artifact::from_json(id, circuit_json).map_err(|e| {
        Refusal::bad_request(format!(
            "field `circuits.{id}`: not a compiled Noir circuit: {e:#}"
        ))
    })?;
    Circuit::with_stored_vk(artifact, vk, vk_hash)
        .map_err(|e| Refusal::mpc_failure(format!("store: {e:#}")))
}

fn build_circuit(node: &RegistryNode, id: &str, circuit_json: &[u8]) -> Result<Circuit, Refusal> {
    let artifact = Artifact::from_json(id, circuit_json).map_err(|e| {
        Refusal::bad_request(format!(
            "field `circuits.{id}`: not a compiled Noir circuit: {e:#}"
        ))
    })?;
    let needed = crs::crs_points(artifact.circuit_size);
    let held = node.crs.prover.monomials.len();
    if needed > held {
        return Err(Refusal::bad_request(format!(
            "field `circuits.{id}`: needs {needed} CRS points; this network holds {held}"
        )));
    }
    Circuit::new(artifact, &node.crs.prover).map_err(|e| {
        Refusal::bad_request(format!("field `circuits.{id}`: no verification key: {e:#}"))
    })
}

/// The rest of a checked REGISTER (section 4 steps 4 to 6): for a `seq` 0
/// body the registration circuit over `net`, then the commit and the signed
/// answer. Call it under the same namespace lock as [`check_register`].
///
/// Refusals: 422 or 500 (the registration round), 500 (no mesh for a `seq` 0
/// body; store; a repair whose proven npk_app_hash differs from the stored
/// one).
pub fn finish_register<S, N, R>(
    store: &S,
    node: &RegistryNode,
    checked: CheckedRegister,
    net: Option<&N>,
    rng: &mut R,
) -> Result<ManifestAnswer, Refusal>
where
    S: Store + ?Sized,
    N: Network,
    R: RngCore + CryptoRng,
{
    let CheckedRegister {
        body: req,
        owner,
        stored,
        facts,
        plan,
    } = checked;
    let namespace = req.namespace.fr();
    let manifest_row = |document: Value| ManifestRow {
        manifest_hash: facts.manifest_hash,
        document,
        seq: req.seq,
    };
    let (document, packages) = match plan {
        Plan::Stored { npk_app_hash } => {
            return Ok(register_answer(
                node,
                namespace,
                &facts,
                npk_app_hash,
                req.seq,
                None,
                rng,
            ));
        }
        Plan::Reenable { packages } => {
            let row = stored.expect("a later body has a namespace row");
            let mut txn = store.begin(namespace);
            stage_register(
                &mut txn,
                RegisterRows::Later(req.seq),
                manifest_row(req.manifest.clone()),
                packages,
            );
            store.commit(txn)?;
            return Ok(register_answer(
                node,
                namespace,
                &facts,
                row.npk_app_hash,
                req.seq,
                None,
                rng,
            ));
        }
        Plan::Commit { document, packages } => (document, packages),
    };

    // 4. keys, the mesh half: the registration circuit of a seq 0 body.
    let derived = if req.seq == 0 {
        let net = net.ok_or_else(|| {
            Refusal::mpc_failure(
                "a seq 0 REGISTER runs the registration circuit and needs the mesh",
            )
        })?;
        let derived = derive(node.registration, node.crs, node.master, namespace, net)?;
        if let Some(row) = &stored
            && row.npk_app_hash != derived.npk_app_hash
        {
            return Err(Refusal::mpc_failure(format!(
                "the registration circuit proved npk_app_hash {} for namespace {}, but this \
                 node holds {}; nothing was stored",
                fr_to_hex(derived.npk_app_hash),
                fr_to_hex(namespace),
                fr_to_hex(row.npk_app_hash)
            )));
        }
        Some(derived)
    } else {
        None
    };

    // 5. commit, in one transaction
    let (rows, npk_app_hash) = match (&derived, &stored) {
        (Some(d), stored) => {
            let row = NamespaceRow {
                owner_pubkey: owner,
                nsk_app: d.nsk_app,
                npk_app_hash: d.npk_app_hash,
                seq: 0,
            };
            let stored = stored.is_some();
            (RegisterRows::First { row, stored }, d.npk_app_hash)
        }
        (None, Some(row)) => (RegisterRows::Later(req.seq), row.npk_app_hash),
        (None, None) => unreachable!("a later body has a namespace row"),
    };
    let mut txn = store.begin(namespace);
    stage_register(&mut txn, rows, manifest_row(document), packages);
    store.commit(txn)?;

    // 6. respond
    Ok(register_answer(
        node,
        namespace,
        &facts,
        npk_app_hash,
        req.seq,
        derived.map(|d| d.registration),
        rng,
    ))
}

// `DISABLE(namespace, circuit)`, signed by the owner with
// the next seq, sets the `disabled` flag of the package of that name in every
// contract manifest version the namespace holds: from its commit on, a
// request naming the circuit is refused at resolution (400), before any value
// is loaded, whichever version it runs under (a tip round runs under the
// version its contract's pins name, which may be older than the newest), so a
// buggy or compromised circuit stops receiving the namespace's values. The
// answer signs the newest version's package that has the name. It does not delete anything: the package row (circuit, manifest, vk)
// stays for audit and for GET, and the consumed set, request rows and values
// the circuit wrote stay as they are. It does not revoke proofs already
// returned (a contract that pinned the vk still accepts them; unpinning is the
// contract's business), and it does not change npk_app_hash. A later REGISTER
// of the same contract manifest re-enables every package. A DISABLE of an
// already disabled circuit with its recorded seq is answered again unchanged.
// A later REGISTER re-enables only the packages of the version it writes.
/// DISABLE on one node (section 4, steps 2 to 6). Refusals: 403 (signature,
/// owner), 409 (seq), 404 (no such circuit), 500 (store).
pub fn disable<S, R>(
    store: &S,
    node: &RegistryNode,
    body: &Signed<DisableRequest>,
    rng: &mut R,
) -> Result<DisableAnswer, Refusal>
where
    S: Store + ?Sized,
    R: RngCore + CryptoRng,
{
    let req = &body.body;
    let namespace = req.namespace.fr();
    let owner = verify_owner(body, &req.owner_pubkey, req.signature, "DISABLE")?;
    let row = stored_owner(store, namespace, owner)?;
    let held = held_packages(store, namespace, &req.circuit)?;
    let answer = |pkg: &PackageRow, rng: &mut R| {
        let message = registry_message(
            namespace,
            &req.circuit,
            pkg.vk_hash,
            row.npk_app_hash,
            pkg.seq,
            true,
            node.index,
        );
        DisableAnswer {
            namespace: req.namespace,
            circuit: req.circuit.clone(),
            vk_hash: FieldHex(pkg.vk_hash),
            npk_app_hash: FieldHex(row.npk_app_hash),
            disabled: true,
            seq: pkg.seq,
            signature: node.sign(message, rng),
        }
    };
    if disable_resent(&held, req.seq) {
        return Ok(answer(&held[0], rng));
    }
    rules::check_next_seq(row.seq, req.seq)?;
    req.check()?;
    if held.is_empty() {
        return Err(Refusal::not_found(format!(
            "no circuit `{}` under namespace {}",
            req.circuit,
            fr_to_hex(namespace)
        )));
    }
    let mut txn = store.begin(namespace);
    let written = stage_disable(&mut txn, held, req.seq);
    store.commit(txn)?;
    Ok(answer(&written[0], rng))
}

// The orchestrator's pre-check of a registry body. Before it spends
// anything on a REGISTER or DISABLE body (a REGISTER costs a vk build per
// circuit), the orchestrator runs section 4 step 2 against its registry copy:
// the owner signature (403), and, when the copy holds the namespace row, the
// stored owner (403) and the `seq` rule (409: a seq 0 body only while the
// stored seq is 0; a later body is the resend of the stored contract
// manifest at its seq, or carries the stored seq plus one), in the nodes'
// own words. A namespace the copy does not hold passes: only a seq 0 body can
// create one, and the nodes decide. The nodes run the same rules again on
// their own rows and remain authoritative; a copy that is behind the nodes
// refuses a body the nodes would accept (409) until it is rebuilt from them
// (`sidecar-orchestrator sync-registry`).
/// Section 4 step 2 of a REGISTER body against a registry copy that may hold
/// fewer rows than the nodes: the signature, then, when the copy holds the
/// namespace row, the owner and `seq`. Reads the store, writes nothing.
pub fn precheck_register<S: StoreRead + ?Sized>(
    store: &S,
    body: &Signed<ManifestMessage>,
) -> Result<(), Refusal> {
    let req = &body.body;
    let namespace = req.namespace.fr();
    let owner = verify_owner(body, &req.owner_pubkey, req.signature, "REGISTER")?;
    if store.namespace(namespace)?.is_none() {
        return Ok(());
    }
    let row = stored_owner(store, namespace, owner)?;
    if req.seq == 0 {
        if row.seq != 0 {
            return Err(Refusal::conflict(format!(
                "a seq 0 REGISTER is accepted only while the namespace's seq is 0; it is {}",
                row.seq
            )));
        }
        return Ok(());
    }
    let hash = manifest_hash(&req.manifest).map_err(|r| prefix_field(r, "manifest"))?;
    if register_resent(
        &row,
        store.contract_manifest(namespace)?.as_ref(),
        hash,
        req.seq,
    ) {
        return Ok(());
    }
    rules::check_next_seq(row.seq, req.seq)
}

/// [`precheck_register`] for a DISABLE body: the signature, then, when the
/// copy holds the namespace row, the owner and `seq` (the idempotent case is
/// the stored disabled package with its seq).
pub fn precheck_disable<S: StoreRead + ?Sized>(
    store: &S,
    body: &Signed<DisableRequest>,
) -> Result<(), Refusal> {
    let req = &body.body;
    let namespace = req.namespace.fr();
    let owner = verify_owner(body, &req.owner_pubkey, req.signature, "DISABLE")?;
    if store.namespace(namespace)?.is_none() {
        return Ok(());
    }
    let row = stored_owner(store, namespace, owner)?;
    if disable_resent(&held_packages(store, namespace, &req.circuit)?, req.seq) {
        return Ok(());
    }
    rules::check_next_seq(row.seq, req.seq)
}

/// Resolution (section 3 step 3): the package a request names, in the
/// contract manifest version `version` names (the newest when `None`),
/// refused (400, naming the circuit) when it is absent or disabled, before
/// anything is loaded.
pub fn resolve<S: StoreRead + ?Sized>(
    store: &S,
    namespace: Fr,
    name: &str,
    version: Option<Fr>,
) -> Result<PackageRow, Refusal> {
    let found = match version {
        Some(hash) => store.package_in(namespace, hash, name)?,
        None => store.package(namespace, name)?,
    };
    match found {
        None => Err(Refusal::bad_request(format!(
            "field `circuit`: `{name}` is not registered under namespace {}{}",
            fr_to_hex(namespace),
            version.map_or(String::new(), |h| format!(
                " in contract manifest {}",
                fr_to_hex(h)
            ))
        ))),
        Some(pkg) if pkg.disabled => Err(Refusal::bad_request(format!(
            "field `circuit`: `{name}` is disabled under namespace {}",
            fr_to_hex(namespace)
        ))),
        Some(pkg) => Ok(pkg),
    }
}

/// `GET /v1/packages/{namespace}/{name}`: the stored package, disabled or not;
/// 404 when unknown.
pub fn package_info<S: StoreRead + ?Sized>(
    store: &S,
    namespace: Fr,
    name: &str,
) -> Result<PackageResponse, Refusal> {
    let pkg = store.package(namespace, name)?.ok_or_else(|| {
        Refusal::not_found(format!(
            "no circuit `{name}` under namespace {}",
            fr_to_hex(namespace)
        ))
    })?;
    let circuit = serde_json::from_slice(&pkg.circuit_json).map_err(|e| {
        Refusal::mpc_failure(format!(
            "store: the circuit of `{name}` does not parse: {e}"
        ))
    })?;
    Ok(PackageResponse {
        namespace: FieldHex(namespace),
        name: pkg.name,
        manifest_hash: FieldHex(pkg.manifest_hash),
        circuit,
        manifest: pkg.manifest,
        vk: HexBytes(pkg.vk),
        vk_hash: FieldHex(pkg.vk_hash),
        disabled: pkg.disabled,
        seq: pkg.seq,
    })
}

/// `GET /v1/namespaces/{namespace}`: the owner, `seq`, `npk_app_hash` and
/// manifest hash; 404 when unknown.
pub fn namespace_info<S: StoreRead + ?Sized>(
    store: &S,
    namespace: Fr,
) -> Result<NamespaceResponse, Refusal> {
    let row = store
        .namespace(namespace)?
        .ok_or_else(|| Refusal::not_found(format!("no namespace {}", fr_to_hex(namespace))))?;
    let manifest = held_manifest(store, namespace)?;
    Ok(NamespaceResponse {
        namespace: FieldHex(namespace),
        owner_pubkey: crate::grumpkin::point_to_wire(row.owner_pubkey),
        seq: row.seq,
        npk_app_hash: FieldHex(row.npk_app_hash),
        manifest_hash: FieldHex(manifest.manifest_hash),
    })
}

/// The contract manifest a namespace holds; 404 for an unknown namespace,
/// 500 for a namespace row without one (REGISTER writes both together).
fn held_manifest<S: StoreRead + ?Sized>(store: &S, namespace: Fr) -> Result<ManifestRow, Refusal> {
    match store.contract_manifest(namespace)? {
        Some(m) => Ok(m),
        None if store.namespace(namespace)?.is_some() => Err(Refusal::mpc_failure(format!(
            "store: namespace {} holds no contract manifest",
            fr_to_hex(namespace)
        ))),
        None => Err(Refusal::not_found(format!(
            "no namespace {}",
            fr_to_hex(namespace)
        ))),
    }
}

/// `GET /v1/namespaces/{namespace}/manifest`: the newest contract manifest
/// version as registered, its hash and the `seq` that wrote it; 404 when
/// unknown.
pub fn manifest_info<S: StoreRead + ?Sized>(
    store: &S,
    namespace: Fr,
) -> Result<ContractManifestResponse, Refusal> {
    let m = held_manifest(store, namespace)?;
    Ok(ContractManifestResponse {
        namespace: FieldHex(namespace),
        manifest_hash: FieldHex(m.manifest_hash),
        seq: m.seq,
        manifest: m.document,
    })
}

/// `GET /v1/namespaces/{namespace}/manifests/{manifest_hash}`: the contract
/// manifest version of that hash, as registered, and the `seq` that wrote
/// it; 404 when the namespace holds no such version. Under upgrades a
/// client fetches the version the contract's pins name by its hash.
pub fn manifest_version_info<S: StoreRead + ?Sized>(
    store: &S,
    namespace: Fr,
    manifest_hash: Fr,
) -> Result<ContractManifestResponse, Refusal> {
    let m = store
        .contract_manifests(namespace)?
        .into_iter()
        .find(|m| m.manifest_hash == manifest_hash)
        .ok_or_else(|| {
            Refusal::not_found(format!(
                "namespace {} holds no contract manifest {}",
                fr_to_hex(namespace),
                fr_to_hex(manifest_hash)
            ))
        })?;
    Ok(ContractManifestResponse {
        namespace: FieldHex(namespace),
        manifest_hash: FieldHex(m.manifest_hash),
        seq: m.seq,
        manifest: m.document,
    })
}

/// `GET /v1/namespaces` (a node's mutual-TLS leg): every namespace the store
/// holds, ascending.
pub fn namespace_list<S: Store + ?Sized>(store: &S) -> Result<NamespacesResponse, Refusal> {
    Ok(NamespacesResponse {
        namespaces: store.namespaces()?.into_iter().map(FieldHex).collect(),
    })
}

/// `GET /v1/packages/{namespace}` (a node's mutual-TLS leg): the names of the
/// namespace's packages, disabled ones included, in byte order; 404 when the
/// namespace is unknown.
pub fn package_names<S: Store + ?Sized>(
    store: &S,
    namespace: Fr,
) -> Result<PackageNamesResponse, Refusal> {
    if store.namespace(namespace)?.is_none() {
        return Err(Refusal::not_found(format!(
            "no namespace {}",
            fr_to_hex(namespace)
        )));
    }
    Ok(PackageNamesResponse {
        namespace: FieldHex(namespace),
        packages: store.package_names(namespace)?,
    })
}

#[cfg(test)]
pub(crate) mod tests;
