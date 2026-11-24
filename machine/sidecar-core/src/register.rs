//! The registry's wire types: the signed bodies `POST /v1/register` (the
//! manifest message) and `POST /v1/disable`, each node's signed answer to
//! them, the client's response, and the GET answers
//! `/v1/packages/{namespace}/{name}`, `/v1/namespaces/{namespace}` and
//! `/v1/namespaces/{namespace}/manifest`. The rules that use them are in
//! `registry`.

use std::collections::BTreeMap;

use noirc_abi::Abi;
use serde::{Deserialize, Serialize};

use crate::error::{Refusal, parse_value};
use crate::field::{FieldHex, HexBytes};
use crate::manifest::contract::{CheckedContractManifest, ContractManifest};
use crate::request::{GrumpkinPoint, NODES};
use crate::schnorr::check_name;
use crate::state::StateHolders;

/// A Schnorr signature over Grumpkin in the encoding of noir-lang/schnorr v0.4.0:
/// `s` and `e` are embedded-curve scalars, each written as two field elements
/// `[lo, hi]` (the low and high 128 bits). Verification lives elsewhere.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Signature {
    pub s: [FieldHex; 2],
    pub e: [FieldHex; 2],
}

// The REGISTER body is the contract manifest registration message (short: the
// manifest message): one namespace's whole contract manifest and each of its
// compiled circuits once, stripped. The nodes commit it in one store
// transaction each, so a namespace never holds part of an app.
/// `POST /v1/register`: the manifest message. Every body is signed by
/// `owner_pubkey` (403 otherwise); the first REGISTER of a namespace carries
/// `seq` 0 and records the key as the owner, and every later registry body
/// carries the owner's key and the stored `seq` plus one (409 otherwise).
///
/// `manifest` and `circuits` are kept as the JSON the client sent, because
/// the signed message is the canonical (RFC 8785) serialisation of the body
/// without `signature`, the manifest hash is over the document as sent, and
/// the nodes store both as given. [`Self::check`] parses them.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestMessage {
    pub namespace: FieldHex,
    /// The contract manifest (`docs/contract-manifest.schema.json`).
    pub manifest: serde_json::Value,
    /// Each entry of the manifest's `circuits`, by id: the compiled circuit
    /// stripped to its six members ([`check_stripped_circuit`]).
    pub circuits: BTreeMap<String, serde_json::Value>,
    pub owner_pubkey: GrumpkinPoint,
    /// The namespace's registry sequence number this body claims.
    pub seq: u64,
    pub signature: Signature,
}

/// The `debug_symbols` member of a stripped circuit: the base64 of the raw
/// deflate of `{"debug_infos":[]}`. co-noir's `ProgramArtifact` refuses a
/// circuit without the member, and an empty string.
pub const STRIPPED_DEBUG_SYMBOLS: &str = "q1ZKSU0qTY/PzEvLL1ayio6tBQA=";

/// The members of a stripped circuit.
pub const STRIPPED_MEMBERS: [&str; 6] = [
    "noir_version",
    "hash",
    "abi",
    "bytecode",
    "debug_symbols",
    "file_map",
];

// The client strips each compiled circuit to one fixed form before signing:
// `noir_version` and `hash` as nargo wrote them, `abi`, `bytecode`,
// `debug_symbols` the constant above and an empty `file_map`. The vk, the
// circuit size and the public input count come from `bytecode` alone, and
// nothing reads the other members after parsing, so the stripped circuit
// proves as the full one; it is about 3% of nargo's file (the embedded Noir
// sources are most of it) and it carries no build machine paths. One fixed
// form lets a resend and a resync compare the stored bytes.
/// Refuse (400, naming `circuits.<id>`) a circuit not in the stripped form:
/// a member other than [`STRIPPED_MEMBERS`] or one missing, a
/// `debug_symbols` other than [`STRIPPED_DEBUG_SYMBOLS`], a non-empty
/// `file_map`.
pub fn check_stripped_circuit(id: &str, circuit: &serde_json::Value) -> Result<(), Refusal> {
    let at = format!("circuits.{id}");
    let bad = |why: String| Err(Refusal::bad_request(format!("field `{at}`: {why}")));
    let Some(members) = circuit.as_object() else {
        return bad("not a JSON object".into());
    };
    if let Some(extra) = members
        .keys()
        .find(|k| !STRIPPED_MEMBERS.contains(&k.as_str()))
    {
        return bad(format!(
            "member `{extra}`; a registered circuit is stripped to {}",
            STRIPPED_MEMBERS.join(", ")
        ));
    }
    if let Some(missing) = STRIPPED_MEMBERS.iter().find(|k| !members.contains_key(**k)) {
        return bad(format!("member `{missing}` is missing"));
    }
    if members["debug_symbols"] != STRIPPED_DEBUG_SYMBOLS {
        return bad(format!(
            "`debug_symbols` of a stripped circuit is `{STRIPPED_DEBUG_SYMBOLS}`"
        ));
    }
    if members["file_map"]
        .as_object()
        .is_none_or(|m| !m.is_empty())
    {
        return bad("`file_map` of a stripped circuit is `{}`".into());
    }
    Ok(())
}

/// A compiled circuit (nargo's output) in the stripped form
/// ([`check_stripped_circuit`]): what a client sends in a manifest message.
pub fn stripped_circuit(full: &serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "noir_version": full["noir_version"],
        "hash": full["hash"],
        "abi": full["abi"],
        "bytecode": full["bytecode"],
        "debug_symbols": STRIPPED_DEBUG_SYMBOLS,
        "file_map": {},
    })
}

impl ManifestMessage {
    /// Parse and check a JSON body ([`Self::check`]). The APIs parse the
    /// body and run [`Self::check`].
    #[cfg(any(test, feature = "testing"))]
    pub fn from_json(text: &str) -> Result<Self, Refusal> {
        let req: Self = crate::error::parse_json(text)?;
        req.check()?;
        Ok(req)
    }

    /// The checks of a parsed body that need no node: the contract manifest
    /// and its checks across packages ([`ContractManifest::check`]), every
    /// circuit in the stripped form, exactly the manifest's circuits, each
    /// package's options built for its intake and its ABI parsing.
    pub fn check(&self) -> Result<(), Refusal> {
        self.contract_manifest().map(|_| ())
    }

    /// The checked contract manifest ([`Self::check`]). Refusals name the
    /// field as `manifest.<path>` or `circuits.<id>`.
    pub fn contract_manifest(&self) -> Result<CheckedContractManifest, Refusal> {
        let checked = ContractManifest::parse(&self.manifest)
            .and_then(ContractManifest::check)
            .map_err(|r| prefix_field(r, "manifest"))?;
        for (id, circuit) in &self.circuits {
            if !checked.document.circuits.contains_key(id) {
                return Err(Refusal::bad_request(format!(
                    "field `circuits.{id}`: not an entry of `manifest.circuits`"
                )));
            }
            check_stripped_circuit(id, circuit)?;
        }
        if let Some(id) = checked
            .document
            .circuits
            .keys()
            .find(|id| !self.circuits.contains_key(*id))
        {
            return Err(Refusal::bad_request(format!(
                "field `circuits`: `{id}` of `manifest.circuits` is missing"
            )));
        }
        for (p, m) in checked.manifests.iter().enumerate() {
            crate::registry::refuse_deferred_options(m)
                .map_err(|r| prefix_field(r, &format!("manifest.packages[{p}]")))?;
        }
        for id in self.circuits.keys() {
            self.abi(id)?;
        }
        Ok(checked)
    }

    /// The ABI of circuit `id`, parsed from its `abi` member.
    pub fn abi(&self, id: &str) -> Result<Abi, Refusal> {
        let at = format!("circuits.{id}.abi");
        let abi = self
            .circuits
            .get(id)
            .and_then(|c| c.get("abi"))
            .ok_or_else(|| Refusal::bad_request(format!("field `{at}`: missing")))?;
        parse_value(abi).map_err(|r| prefix_field(r, &at))
    }

    /// The state checks of every package against the state modes `holders`
    /// serve ([`StateHolders::check_register`]): an orchestrator or node API
    /// runs them on a parsed body before anything else, as REGISTER on a
    /// node runs them again with its store's check.
    pub fn check_state(&self, holders: &StateHolders) -> Result<(), Refusal> {
        let checked = self.contract_manifest()?;
        for (p, m) in checked.manifests.iter().enumerate() {
            holders
                .check_register(m)
                .map_err(|r| prefix_field(r, &format!("manifest.packages[{p}]")))?;
        }
        Ok(())
    }
}

// Re-root a refusal's "field `x`" path under `prefix`, so errors in a nested
// document name their place in the whole body.
pub(crate) fn prefix_field(refusal: Refusal, prefix: &str) -> Refusal {
    let message = if let Some(rest) = refusal.message.strip_prefix("field `") {
        format!("field `{prefix}.{rest}")
    } else if let Some(rest) = refusal.message.strip_prefix("body: ") {
        format!("field `{prefix}`: {rest}")
    } else {
        format!("field `{prefix}`: {}", refusal.message)
    };
    Refusal::new(refusal.class, message)
}

/// `POST /v1/disable`: the namespace owner disables one registered package.
/// A disabled package is refused at resolution and keeps its row; a later
/// REGISTER of the same contract manifest re-enables every package.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DisableRequest {
    pub namespace: FieldHex,
    /// The registered name of the circuit to disable.
    pub circuit: String,
    pub owner_pubkey: GrumpkinPoint,
    pub seq: u64,
    pub signature: Signature,
}

impl DisableRequest {
    /// Parse and check a JSON body.
    #[cfg(any(test, feature = "testing"))]
    pub fn from_json(text: &str) -> Result<Self, Refusal> {
        let req: Self = crate::error::parse_json(text)?;
        req.check()?;
        Ok(req)
    }

    /// The checks of a parsed body: the circuit name.
    pub fn check(&self) -> Result<(), Refusal> {
        check_name("circuit", "circuit name", &self.circuit)
    }
}

/// The registration circuit's proof from a node's answer to a `seq` 0 REGISTER:
/// the bb-format proof and its public inputs `[namespace, npk_app_hash]`. The
/// orchestrator verifies it against the built-in vk and does not forward it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Registration {
    pub proof: HexBytes,
    pub public_inputs: Vec<FieldHex>,
}

// What the nodes sign for a manifest message: one answer per node over
// `manifest_message` (the manifest hash, the packages hash, the namespace's
// npk_app_hash and the seq). A tip contract configures from the three
// answers (`configure(npk_app_hash, answer)`): it rebuilds the message from
// its own address, its pinned manifest hash and the packages hash of its own
// package list.
/// Node i's answer to REGISTER: the manifest hash, the packages hash, the
/// namespace's `npk_app_hash`, the `seq` the manifest is registered with,
/// node i's signature over the manifest result message
/// ([`crate::registry::manifest_message`]) and, on a `seq` 0 body, the
/// registration proof.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestAnswer {
    pub manifest_hash: FieldHex,
    pub packages_hash: FieldHex,
    pub npk_app_hash: FieldHex,
    pub seq: u64,
    pub signature: Signature,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registration: Option<Registration>,
}

/// The answer to REGISTER, as the orchestrator returns it once the three nodes
/// agree, the registration proof (on `seq` 0) verifies and every node
/// signature verifies: `signatures[i]` is node i's over the manifest result
/// message. A developer checks the signatures against its own pinned node
/// keys before it pins `npk_app_hash` in a contract.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestResponse {
    pub manifest_hash: FieldHex,
    pub packages_hash: FieldHex,
    pub npk_app_hash: FieldHex,
    pub seq: u64,
    pub signatures: [Signature; NODES],
}

/// Node i's answer to DISABLE: the circuit named, its vk hash, the namespace's
/// `npk_app_hash`, `disabled: true`, the DISABLE's `seq` and node i's signature
/// over the registry result message with `disabled` = 1.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DisableAnswer {
    pub namespace: FieldHex,
    pub circuit: String,
    pub vk_hash: FieldHex,
    pub npk_app_hash: FieldHex,
    pub disabled: bool,
    pub seq: u64,
    pub signature: Signature,
}

/// The answer to DISABLE as the orchestrator returns it: the agreed values and
/// the three node signatures.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DisableResponse {
    pub namespace: FieldHex,
    pub circuit: String,
    pub vk_hash: FieldHex,
    pub npk_app_hash: FieldHex,
    pub disabled: bool,
    pub seq: u64,
    pub signatures: [Signature; NODES],
}

/// `GET /v1/packages/{namespace}/{name}`: a registered package, so anyone can
/// check what the nodes run against the hash a contract pins.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageResponse {
    pub namespace: FieldHex,
    pub name: String,
    /// The hash of the contract manifest the package belongs to.
    pub manifest_hash: FieldHex,
    pub circuit: serde_json::Value,
    pub manifest: serde_json::Value,
    /// The bb verification key.
    pub vk: HexBytes,
    pub vk_hash: FieldHex,
    pub disabled: bool,
    /// The `seq` of the registry body that last wrote the package.
    pub seq: u64,
}

/// `GET /v1/namespaces/{namespace}`: the namespace's owner, its registry
/// sequence number, its `npk_app_hash` and the hash of its contract manifest.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamespaceResponse {
    pub namespace: FieldHex,
    pub owner_pubkey: GrumpkinPoint,
    pub seq: u64,
    pub npk_app_hash: FieldHex,
    pub manifest_hash: FieldHex,
}

/// `GET /v1/namespaces/{namespace}/manifest`: the namespace's contract
/// manifest as registered, its hash and the `seq` of the REGISTER that
/// wrote it. A reader recomputes the hash from `manifest`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContractManifestResponse {
    pub namespace: FieldHex,
    pub manifest_hash: FieldHex,
    pub seq: u64,
    pub manifest: serde_json::Value,
}

/// `GET /v1/namespaces` at a node (the mutual-TLS leg only): every namespace
/// the node holds, ascending.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamespacesResponse {
    pub namespaces: Vec<FieldHex>,
}

/// `GET /v1/packages/{namespace}` at a node (the mutual-TLS leg only): the
/// names of the namespace's packages, disabled ones included, in byte order.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageNamesResponse {
    pub namespace: FieldHex,
    pub packages: Vec<String>,
}

#[cfg(test)]
#[path = "register_tests.rs"]
pub(crate) mod tests;
