//! The contract manifest: one JSON document per namespace (one deployment of
//! one contract) that holds the contract-level facts and every package's
//! circuit manifest (`docs/contract-manifest.schema.json`, ARCHITECTURE.md
//! section 7). pss-client generates it from the compiled contract artifact,
//! the compiled circuits and a hand-written descriptor, so no slot is copied
//! by hand.
//!
//! Here: the typed document, its hash and the hash of its package list, and
//! the checks across its packages, which need only the document (the checks
//! of each circuit manifest against its circuit's ABI, and of each vk hash
//! against the circuit's bytes, are REGISTER's). They are pure functions, so
//! the nodes and the orchestrator run the same code.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::*;
use crate::field::{FieldHex, Fr};
use crate::hash::poseidon2_hash;
use crate::schnorr::{canonical_json, check_name, poseidon2_hash_bytes};

/// The most packages one contract manifest holds, aliases included.
pub const MAX_PACKAGES: usize = 32;

/// The most public storage writes one Aztec transaction makes
/// (`MAX_PUBLIC_DATA_UPDATE_REQUESTS_PER_TX`).
pub const MAX_PUBLIC_WRITES_PER_TX: usize = 63;

/// The `contract_manifest` field: the schema version, always the integer 1.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ContractManifestVersion;

impl Serialize for ContractManifestVersion {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u64(1)
    }
}

impl<'de> Deserialize<'de> for ContractManifestVersion {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        match u64::deserialize(deserializer)? {
            1 => Ok(ContractManifestVersion),
            n => Err(de::Error::custom(format!(
                "contract manifest schema version {n} is not supported; this machine reads \
                 version 1"
            ))),
        }
    }
}

/// `node_keys`: whether the contract can change its node key set (the
/// design guide's node keys axis). Generated: `rotating` exactly when the
/// contract artifact has a `rotate_keys` function.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeKeysAxis {
    /// `KeyEpochs`: the contract can rotate to a new node key set.
    Rotating,
    /// `FixedKeys`: the constructor's node keys, for the life of the contract.
    Fixed,
}

impl NodeKeysAxis {
    pub fn as_str(self) -> &'static str {
        match self {
            NodeKeysAxis::Rotating => "rotating",
            NodeKeysAxis::Fixed => "fixed",
        }
    }
}

/// `upgrades`: what about a deployed app may change. Generated: `contract`
/// when the artifact has `upgrade_contract`, `circuits` when it has
/// `upgrade_circuits`, else `fixed`. Under `circuits` and `contract` the
/// contract keeps its circuit pins at `storage.circuit_pins`, REGISTER bounds
/// the package list ([`max_upgradable_packages`]) and accepts a replacement
/// contract manifest ([`check_upgrade`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Upgrades {
    /// The circuits and the contract's code never change.
    Fixed,
    /// An authority the app names can replace the circuit pins after a delay.
    Circuits,
    /// As `circuits`, and the authority can also upgrade the contract's class.
    Contract,
}

impl Upgrades {
    /// Whether the contract's circuit pins can change after deployment.
    pub fn upgradable(self) -> bool {
        self != Upgrades::Fixed
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Upgrades::Fixed => "fixed",
            Upgrades::Circuits => "circuits",
            Upgrades::Contract => "contract",
        }
    }
}

// The bound on an upgradable package list. An upgrade rewrites the circuit
// pins in one public transaction: a delayed value of N fields occupies
// 2N + 2 storage slots, and the pins are the package list's name hashes and
// vk hashes (2P), the manifest hash and the class id they belong to, so
// N = 2P + 2 and one schedule writes 4P + 6 slots. A class upgrade also
// schedules the new class id in the protocol's registry (a delayed value of
// one field: 4 slots) in the same transaction. One transaction writes at most
// MAX_PUBLIC_WRITES_PER_TX slots, so `circuits` holds at most 14 packages
// and `contract` at most 13, before whatever the fee payment writes.
/// The public storage writes of one upgrade of a list of `packages`
/// packages under `upgrades`; `None` under `fixed`, which has no upgrade.
pub fn upgrade_writes(upgrades: Upgrades, packages: usize) -> Option<usize> {
    let pins = 4 * packages + 6;
    match upgrades {
        Upgrades::Fixed => None,
        Upgrades::Circuits => Some(pins),
        Upgrades::Contract => Some(pins + 4),
    }
}

/// The longest package list whose upgrade fits one transaction's public
/// writes under `upgrades` ([`upgrade_writes`]); `None` under `fixed`, whose
/// bound is [`MAX_PACKAGES`].
pub fn max_upgradable_packages(upgrades: Upgrades) -> Option<usize> {
    upgrade_writes(upgrades, 0)?;
    (0..=MAX_PACKAGES)
        .take_while(|&p| upgrade_writes(upgrades, p).is_some_and(|w| w <= MAX_PUBLIC_WRITES_PER_TX))
        .last()
}

/// `contract`: the contract this manifest was built for.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContractFacts {
    /// The contract class id, from the artifact.
    pub class_id: FieldHex,
    /// The length of the contract's package list (its constructor's
    /// `Config.tip.packages`); a tip contract only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub package_capacity: Option<usize>,
}

/// `queue`: where the app's queue and its stale period live.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueueFacts {
    /// The storage slot of the app's `Queue`.
    pub slot: FieldHex,
    // DEV DECISION: `stale_blocks`, the descriptor's (the examples state
    // DEFAULT_STALE_BLOCKS, 50 L2 blocks, about five minutes at one proposed
    // block every 6 s); shorter periods free a stuck queue
    // sooner and skip slow rounds more often, longer ones the reverse.
    // Design guide: "stale_blocks". Once the head has waited that long,
    // anyone may `skip()` it, the scheduler stops working on it, and a
    // receipt whose request never entered the queue (or is done) is pruned
    // no earlier than this long after its expiry. `null` disables skipping,
    // so a head the network never serves blocks the queue until it is
    // served. The contract stores the same value (a constructor argument),
    // so changing it means redeploying.
    /// The stale period in L2 blocks, `None` (JSON `null`) when a head is
    /// never skipped.
    #[serde(deserialize_with = "nullable")]
    pub stale_blocks: Option<u64>,
    /// The slot of the stored stale period (`TipConfig.stale_blocks`).
    pub stale_blocks_slot: FieldHex,
}

/// A field that must be given and may be `null`.
fn nullable<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

/// `storage`: the slots of the contract library's own storage the machine
/// reads.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageFacts {
    /// The slot of `Configured.configured`.
    pub configured: FieldHex,
    /// The slot of `SharedOnchain`; exactly when a package takes secret-shared
    /// on-chain intake.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shared_onchain: Option<FieldHex>,
    /// The slot of the upgradable circuit pins (pss_public_contract
    /// `CircuitUpgrades`: the scheduled pins in a delayed value, then the
    /// upgrade authority); exactly when `upgrades` is not `fixed`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub circuit_pins: Option<FieldHex>,
}

/// `init`: the init round and where its inputs sit in the contract's
/// `Config`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InitFacts {
    /// The init package: listed, reads no key, writes at least one.
    pub package: String,
    /// The slot of each init input, in order.
    pub input_slots: Vec<FieldHex>,
}

/// `circuits.<id>`: one compiled circuit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CircuitEntry {
    /// The circuit's vk hash, which REGISTER recomputes from its bytes.
    pub vk_hash: FieldHex,
}

/// `packages[].state_keys`: a queued package's request keys, by name: the
/// key behind `$state_keys.reads[i]` is `reads[i]`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamedKeys {
    pub reads: Vec<String>,
    pub writes: Vec<String>,
}

impl NamedKeys {
    /// The name a key reference stands for; `None` for a fixed key or one
    /// out of range.
    pub fn name(&self, key: KeyRef) -> Option<&str> {
        match key {
            KeyRef::Read(i) => self.reads.get(i).map(String::as_str),
            KeyRef::Write(j) => self.writes.get(j).map(String::as_str),
            KeyRef::Fixed(_) => None,
        }
    }
}

/// One entry of `packages`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageEntry {
    /// The package name, which the contract's list hashes and requests name.
    pub name: String,
    /// The entry of `circuits` that backs it.
    pub circuit: String,
    /// Another intake of the listed package of this name: the same circuit,
    /// verified by the contract under that package's pin, and not in the
    /// contract's list.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alias_of: Option<String>,
    /// A queued package's request keys, by name (none under intake direct).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_keys: Option<NamedKeys>,
    /// The circuit manifest, as the JSON the document holds.
    pub manifest: Value,
}

impl PackageEntry {
    /// Whether the contract's list names this package (it is no alias).
    pub fn listed(&self) -> bool {
        self.alias_of.is_none()
    }
}

/// A parsed contract manifest. Construct it with [`ContractManifest::parse`],
/// then run [`ContractManifest::check`], which parses every circuit manifest
/// and runs the checks across them.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContractManifest {
    pub contract_manifest: ContractManifestVersion,
    /// A label for logs and status pages.
    pub name: String,
    pub node_keys: NodeKeysAxis,
    pub upgrades: Upgrades,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contract: Option<ContractFacts>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub queue: Option<QueueFacts>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage: Option<StorageFacts>,
    /// Every state key the rounds touch: its name and commitment slot.
    #[serde(
        default,
        deserialize_with = "unique_map",
        skip_serializing_if = "BTreeMap::is_empty"
    )]
    pub state_keys: BTreeMap<String, FieldHex>,
    /// A pinned read's parameter to the slot behind its plain getter: the
    /// machine reads the slot instead of simulating the call.
    #[serde(
        default,
        deserialize_with = "unique_map",
        skip_serializing_if = "BTreeMap::is_empty"
    )]
    pub plain_reads: BTreeMap<String, FieldHex>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub init: Option<InitFacts>,
    #[serde(deserialize_with = "unique_map")]
    pub circuits: BTreeMap<String, CircuitEntry>,
    pub packages: Vec<PackageEntry>,
}

/// A contract manifest that passed [`ContractManifest::check`], with its
/// circuit manifests parsed, in package order.
#[derive(Clone, Debug, PartialEq)]
pub struct CheckedContractManifest {
    pub document: ContractManifest,
    pub manifests: Vec<Manifest>,
}

impl CheckedContractManifest {
    /// Each package with its parsed circuit manifest, in package order.
    pub fn packages(&self) -> impl Iterator<Item = (&PackageEntry, &Manifest)> {
        self.document.packages.iter().zip(&self.manifests)
    }

    /// The package of this name and its circuit manifest.
    pub fn package(&self, name: &str) -> Option<(&PackageEntry, &Manifest)> {
        self.packages().find(|(p, _)| p.name == name)
    }

    /// The vk hash of a package's circuit.
    pub fn vk_hash(&self, package: &PackageEntry) -> Fr {
        self.document.circuits[&package.circuit].vk_hash.fr()
    }

    /// The stale period of the queue, `None` when a head is never skipped or
    /// the document has no queue.
    pub fn stale_blocks(&self) -> Option<u64> {
        self.document.queue.as_ref().and_then(|q| q.stale_blocks)
    }

    /// The packages hash over the listed packages ([`packages_hash`]).
    pub fn packages_hash(&self) -> Fr {
        packages_hash(
            self.document
                .packages
                .iter()
                .filter(|p| p.listed())
                .map(|p| (p.name.as_str(), self.vk_hash(p))),
        )
    }
}

/// The manifest hash: `poseidon2_hash_bytes(JCS(contract manifest))`, over
/// the JSON as given. The contract pins it, the nodes sign it and anyone who
/// fetches the document can recompute it.
pub fn manifest_hash(document: &Value) -> Result<Fr, Refusal> {
    let canonical =
        canonical_json(document).map_err(|e| Refusal::bad_request(format!("body: {e}")))?;
    Ok(poseidon2_hash_bytes(canonical.as_bytes()))
}

/// The packages hash: `h = 0`, then for each listed package in order
/// `h = poseidon2([h, poseidon2_hash_bytes(name), vk_hash])`. A running hash
/// over the listed entries only, so a contract of any capacity recomputes it
/// from its own stored list.
pub fn packages_hash<'a>(listed: impl IntoIterator<Item = (&'a str, Fr)>) -> Fr {
    listed
        .into_iter()
        .fold(Fr::from(0u64), |h, (name, vk_hash)| {
            poseidon2_hash(&[h, poseidon2_hash_bytes(name.as_bytes()), vk_hash])
        })
}

fn bad<T>(field: impl fmt::Display, why: impl fmt::Display) -> Result<T, Refusal> {
    Err(Refusal::bad_request(format!("field `{field}`: {why}")))
}

impl ContractManifest {
    /// Parse a contract manifest (400, naming the field).
    pub fn parse(document: &Value) -> Result<Self, Refusal> {
        parse_value(document)
    }

    /// The index of the package of this name.
    fn package_index(&self, name: &str) -> Option<usize> {
        self.packages.iter().position(|p| p.name == name)
    }

    /// The checks across the document (400, naming the field): every circuit
    /// manifest parses and names its package; the references between
    /// packages and circuits; the package bounds; the sections the packages
    /// need and no others; every state key agrees across the packages that
    /// touch it; and one intake family. Returns the parsed circuit manifests.
    pub fn check(self) -> Result<CheckedContractManifest, Refusal> {
        let manifests = self.parse_packages()?;
        self.check_bounds()?;
        self.check_references()?;
        let checked = CheckedContractManifest {
            document: self,
            manifests,
        };
        check_sections(&checked)?;
        key_layouts(&checked)?;
        check_intake_families(&checked)?;
        Ok(checked)
    }

    fn parse_packages(&self) -> Result<Vec<Manifest>, Refusal> {
        let mut out = Vec::with_capacity(self.packages.len());
        for (p, entry) in self.packages.iter().enumerate() {
            let at = format!("packages[{p}]");
            check_name(&format!("{at}.name"), "package name", &entry.name)?;
            let manifest = Manifest::parse(&entry.manifest)
                .map_err(|r| crate::register::prefix_field(r, &format!("{at}.manifest")))?;
            if manifest.circuit != entry.name {
                return bad(
                    format!("{at}.manifest.circuit"),
                    format!(
                        "`{}` is not the package name `{}`",
                        manifest.circuit, entry.name
                    ),
                );
            }
            out.push(manifest);
        }
        Ok(out)
    }

    fn check_references(&self) -> Result<(), Refusal> {
        let mut names = BTreeSet::new();
        for (p, entry) in self.packages.iter().enumerate() {
            let at = format!("packages[{p}]");
            if !names.insert(entry.name.as_str()) {
                return bad(
                    format!("{at}.name"),
                    format!("`{}` appears twice", entry.name),
                );
            }
            if !self.circuits.contains_key(&entry.circuit) {
                return bad(
                    format!("{at}.circuit"),
                    format!("`{}` is not an entry of `circuits`", entry.circuit),
                );
            }
            if let Some(of) = &entry.alias_of {
                let target = self.package_index(of).map(|q| &self.packages[q]);
                match target {
                    Some(t) if t.listed() && t.circuit == entry.circuit => {}
                    Some(t) if t.listed() => {
                        return bad(
                            format!("{at}.alias_of"),
                            format!(
                                "`{of}` runs circuit `{}`, not `{}`; an alias runs the circuit \
                                 of the package it names",
                                t.circuit, entry.circuit
                            ),
                        );
                    }
                    _ => {
                        return bad(
                            format!("{at}.alias_of"),
                            format!("`{of}` is not a listed package (one without `alias_of`)"),
                        );
                    }
                }
            }
        }
        for id in self.circuits.keys() {
            if !self.packages.iter().any(|p| &p.circuit == id) {
                return bad(
                    format!("circuits.{id}"),
                    "no package runs this circuit".to_string(),
                );
            }
        }
        Ok(())
    }

    fn check_bounds(&self) -> Result<(), Refusal> {
        if self.packages.is_empty() {
            return bad("packages", "a contract manifest holds at least one package");
        }
        if self.packages.len() > MAX_PACKAGES {
            return bad(
                "packages",
                format!(
                    "{} packages; a contract manifest holds at most {MAX_PACKAGES}",
                    self.packages.len()
                ),
            );
        }
        let listed = self.packages.iter().filter(|p| p.listed()).count();
        let capacity = self.contract.as_ref().and_then(|c| c.package_capacity);
        if let Some(capacity) = capacity
            && listed > capacity
        {
            return bad(
                "packages",
                format!(
                    "{listed} listed packages; the contract's list holds {capacity} \
                     (`contract.package_capacity`)"
                ),
            );
        }
        if let Some(max) = max_upgradable_packages(self.upgrades) {
            let length = capacity.unwrap_or(listed);
            if length > max {
                return bad(
                    "upgrades",
                    format!(
                        "`{}` with a package list of {length}: one upgrade writes {} public \
                         slots ({} at {max} packages), and a transaction writes at most \
                         {MAX_PUBLIC_WRITES_PER_TX}",
                        self.upgrades.as_str(),
                        upgrade_writes(self.upgrades, length).unwrap_or_default(),
                        upgrade_writes(self.upgrades, max).unwrap_or_default(),
                    ),
                );
            }
        }
        Ok(())
    }
}

/// The sections the packages need, and no others.
fn check_sections(cm: &CheckedContractManifest) -> Result<(), Refusal> {
    let doc = &cm.document;
    let queued = cm.manifests.iter().any(Manifest::queued);
    let shared_onchain = cm
        .manifests
        .iter()
        .any(|m| m.queued_intake() == Some(QueuedIntake::SharedOnchain));
    if queued {
        let what = "a contract manifest with a queued package";
        if doc.queue.is_none() {
            return bad("queue", format!("missing; {what} names its queue"));
        }
        if doc.storage.is_none() {
            return bad("storage", format!("missing; {what} names its storage"));
        }
        match &doc.contract {
            Some(ContractFacts {
                package_capacity: Some(_),
                ..
            }) => {}
            _ => {
                return bad(
                    "contract.package_capacity",
                    format!("missing; {what} names its contract's package capacity"),
                );
            }
        }
    } else {
        let what = "only with a queued package; every package here takes intake direct";
        for (field, given) in [
            ("queue", doc.queue.is_some()),
            ("storage", doc.storage.is_some()),
            ("state_keys", !doc.state_keys.is_empty()),
            ("plain_reads", !doc.plain_reads.is_empty()),
            ("init", doc.init.is_some()),
            // No contract pins a version on the sidecar path, so no reader
            // could run a round under any but the newest.
            ("upgrades", doc.upgrades.upgradable()),
        ] {
            if given {
                return bad(field, what);
            }
        }
    }
    if let Some(storage) = &doc.storage {
        match (storage.circuit_pins.is_some(), doc.upgrades.upgradable()) {
            (true, false) => {
                return bad(
                    "storage.circuit_pins",
                    "only under upgrades `circuits` or `contract`; a `fixed` contract keeps the \
                     constructor's pins",
                );
            }
            (false, true) => {
                return bad(
                    "storage.circuit_pins",
                    format!(
                        "missing; under upgrades `{}` the nodes read the circuit pins in force there",
                        doc.upgrades.as_str()
                    ),
                );
            }
            _ => {}
        }
        match (storage.shared_onchain.is_some(), shared_onchain) {
            (true, false) => {
                return bad(
                    "storage.shared_onchain",
                    "only with a package of secret-shared on-chain intake",
                );
            }
            (false, true) => {
                return bad(
                    "storage.shared_onchain",
                    "missing; a package takes secret-shared on-chain intake, whose requests \
                     the nodes find through it",
                );
            }
            _ => {}
        }
    }
    if let Some(queue) = &doc.queue {
        if queue.stale_blocks == Some(0) {
            return bad(
                "queue.stale_blocks",
                "0 would make every head skippable at once; null disables skipping",
            );
        }
        if queue.stale_blocks.is_none() && doc.upgrades != Upgrades::Fixed {
            return bad(
                "queue.stale_blocks",
                format!(
                    "null under upgrades `{}`: a request queued under a replaced circuit is \
                     never answered, so without a stale period it would block the queue for ever",
                    doc.upgrades.as_str()
                ),
            );
        }
        if let Some(n) = queue.stale_blocks
            && n > u64::from(u32::MAX)
        {
            return bad(
                "queue.stale_blocks",
                format!("{n} is above {} (the contract stores a u32)", u32::MAX),
            );
        }
    }
    for (p, (entry, m)) in cm.packages().enumerate() {
        let at = format!("packages[{p}].state_keys");
        match (&entry.state_keys, m.queued()) {
            (None, false) => {}
            (Some(_), false) => return bad(at, "only for a package of a queued intake"),
            (None, true) => {
                return bad(at, "missing; a queued package names its request keys");
            }
            (Some(keys), true) => {
                if keys.reads.len() != m.state_keys.reads
                    || keys.writes.len() != m.state_keys.writes
                {
                    return bad(
                        at,
                        format!(
                            "{} reads and {} writes; the circuit manifest takes {} and {}",
                            keys.reads.len(),
                            keys.writes.len(),
                            m.state_keys.reads,
                            m.state_keys.writes
                        ),
                    );
                }
                for name in keys.reads.iter().chain(&keys.writes) {
                    if !doc.state_keys.contains_key(name) {
                        return bad(
                            at,
                            format!("`{name}` is not a key of the top-level `state_keys`"),
                        );
                    }
                }
            }
        }
    }
    for name in doc.state_keys.keys() {
        let used = doc
            .packages
            .iter()
            .filter_map(|p| p.state_keys.as_ref())
            .any(|k| k.reads.contains(name) || k.writes.contains(name));
        if !used {
            return bad(
                format!("state_keys.{name}"),
                "no package reads or writes this key",
            );
        }
    }
    let written: BTreeSet<&str> = doc
        .packages
        .iter()
        .filter_map(|p| p.state_keys.as_ref())
        .flat_map(|k| k.writes.iter().map(String::as_str))
        .collect();
    for (p, entry) in doc.packages.iter().enumerate() {
        for name in entry.state_keys.iter().flat_map(|k| &k.reads) {
            if !written.contains(name.as_str()) {
                return bad(
                    format!("packages[{p}].state_keys.reads"),
                    format!("`{name}` is written by no package, so no round could create it"),
                );
            }
        }
    }
    for param in doc.plain_reads.keys() {
        if !cm
            .manifests
            .iter()
            .any(|m| m.public_reads.iter().any(|r| &r.param == param))
        {
            return bad(
                format!("plain_reads.{param}"),
                "no package has a pinned read filling this parameter",
            );
        }
    }
    if let Some(init) = &doc.init {
        let Some((entry, m)) = cm.package(&init.package) else {
            return bad(
                "init.package",
                format!("`{}` is not a package", init.package),
            );
        };
        if !entry.listed() {
            return bad(
                "init.package",
                format!("`{}` is an alias; the init round is listed", init.package),
            );
        }
        if !m.queued() || m.state_keys.reads != 0 || m.state_keys.writes == 0 {
            return bad(
                "init.package",
                format!(
                    "`{}` must take a queued intake, read no key and write at least one",
                    init.package
                ),
            );
        }
    }
    Ok(())
}

/// The length a manifest gives a flat key reference on every LOAD and
/// STORE of it, each one.
fn flat_lens(manifest: &Manifest, key: KeyRef) -> BTreeSet<usize> {
    manifest
        .loads()
        .filter(|(_, l)| l.key == key)
        .map(|(_, l)| l.len)
        .chain(
            manifest
                .outputs
                .iter()
                .filter(|o| o.store == key)
                .map(|o| o.len),
        )
        .collect()
}

/// One state key's layout as the packages give it: its state mode and tree
/// shape, and for a flat key the length every LOAD and STORE gives it
/// (`None` when no package loads or stores it flat).
pub type KeyLayoutOf = (KeyLayout, Option<usize>);

/// State key agreement and shared trees: for each named key, every package
/// that loads or stores it gives it the same state mode, flat or tree, the
/// same tree shape (depth, leaf length, header, access, keyed, capacity) and,
/// for a flat key, the same length on every LOAD and STORE; and a tree a
/// round loads is stored back at the key it is loaded from. Returns each
/// key's layout, by name.
pub fn key_layouts(cm: &CheckedContractManifest) -> Result<BTreeMap<String, KeyLayoutOf>, Refusal> {
    // the first package to give each key its layout (and its flat length)
    let mut seen: BTreeMap<&str, (&str, KeyLayout, Option<usize>)> = BTreeMap::new();
    for (p, (entry, m)) in cm.packages().enumerate() {
        let Some(keys) = &entry.state_keys else {
            continue;
        };
        for (&loaded, tree) in m.trees() {
            if let Some(store) = tree.store
                && keys.name(loaded) != keys.name(store)
            {
                return bad(
                    format!("packages[{p}].manifest.tree"),
                    format!(
                        "the tree loaded at {loaded} (key `{}`) is stored back at {store} \
                         (key `{}`); a tree's new version extends the loaded one, so it is \
                         stored back at the key it is loaded from",
                        keys.name(loaded).unwrap_or_default(),
                        keys.name(store).unwrap_or_default()
                    ),
                );
            }
        }
        for (keyref, _) in m.state_modes() {
            let (Some(name), Some(layout)) = (keys.name(keyref), m.key_layout(keyref)) else {
                continue;
            };
            let lens = flat_lens(m, keyref);
            if layout.tree.is_none() && lens.len() > 1 {
                return bad(
                    format!("packages[{p}].manifest"),
                    format!("key `{name}` ({keyref}) is loaded or stored at lengths {lens:?}"),
                );
            }
            let len = layout
                .tree
                .is_none()
                .then(|| lens.first().copied())
                .flatten();
            match seen.get(name) {
                None => {
                    seen.insert(name, (entry.name.as_str(), layout, len));
                }
                Some((first, theirs, _)) if *theirs != layout => {
                    return bad(
                        format!("packages[{p}].manifest"),
                        format!(
                            "key `{name}`: package `{}` gives it {layout}, package `{first}` \
                             {theirs}; every round on a key reads the state the others leave",
                            entry.name
                        ),
                    );
                }
                Some((first, _, Some(theirs))) if len.is_some_and(|l| l != *theirs) => {
                    return bad(
                        format!("packages[{p}].manifest"),
                        format!(
                            "key `{name}`: package `{}` loads or stores it at length {}, \
                             package `{first}` at {theirs}",
                            entry.name,
                            len.unwrap_or_default()
                        ),
                    );
                }
                Some((first, theirs, None)) if len.is_some() => {
                    let first = *first;
                    let theirs = *theirs;
                    seen.insert(name, (first, theirs, len));
                }
                Some(_) => {}
            }
        }
    }
    Ok(seen
        .into_iter()
        .map(|(name, (_, layout, len))| (name.to_string(), (layout, len)))
        .collect())
}

/// One intake family per namespace, over the whole document
/// ([`crate::registry::intake_families_clash`]).
fn check_intake_families(cm: &CheckedContractManifest) -> Result<(), Refusal> {
    let queued: Vec<(&str, &Manifest, QueuedIntake)> = cm
        .packages()
        .filter_map(|(e, m)| Some((e.name.as_str(), m, m.queued_intake()?)))
        .collect();
    for (k, &(name, m, intake)) in queued.iter().enumerate() {
        for &(other, theirs, their_intake) in &queued[k + 1..] {
            if crate::registry::intake_families_clash((m, intake), (theirs, their_intake)) {
                return bad(
                    "packages",
                    format!(
                        "package `{name}` ({} `{}`) and package `{other}` ({} `{}`): in one \
                         namespace no non-secret-shared-intake package reads keys while a \
                         secret-shared-intake package writes them (a non-secret-shared round's \
                         public outputs would publish state that shared inputs touched; a \
                         non-secret-shared package that reads no key, such as an init round, \
                         may stay); register the other family under a namespace of its own",
                        intake.name(),
                        intake.as_str(),
                        their_intake.name(),
                        their_intake.as_str(),
                    ),
                );
            }
        }
    }
    Ok(())
}

#[path = "upgrade.rs"]
mod upgrade;
pub use upgrade::*;

#[cfg(test)]
#[path = "tests/contract.rs"]
mod tests;
