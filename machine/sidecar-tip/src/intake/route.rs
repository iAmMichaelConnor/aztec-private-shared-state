//! The receipt (docs/ARCHITECTURE.md section 1, the hash table's
//! receipt message; section 2, `sig_i`; section 6, the receipts row).
//!
//! ```text
//! inputs_hash = poseidon2(inputs)                                       inputs_hash
//! request_id  = poseidon2([namespace, vk_hash, inputs_hash, user_nonce])         chain_request_id
//! message     = poseidon2([RECEIPT_DOMAIN, request_id, inputs_hash, expiry_block])
//! signature   = Schnorr over Grumpkin (noir-lang/schnorr v0.4.0) by node i's `sig` key
//!
//! secret-shared receipt intake:
//! C           = poseidon2([v_1, ..., v_m, blinding])                    ids::inputs_commitment
//! request_id  = poseidon2([namespace, vk_hash, C])                      ids::shared_chain_request_id
//! S_j         = poseidon2([SUMMANDS_DOMAIN, s_j..., salt_j])            ids::summand_commitment
//! D           = poseidon2([SHARING_DOMAIN, S_0, S_1, S_2, kinds..., clear values...])
//!                                                                       ids::sharing_digest
//! message     = poseidon2([RECEIPT_DOMAIN, request_id, C, expiry_block, D])
//! ```
//!
//! A user sends the inputs of a request whose manifest says `intake:
//! receipt` to the network (the orchestrator proxies it to the three nodes'
//! `POST /v1/receipt`). Each node resolves the package, runs the
//! static-validity check ([`intake_inputs`]: the typed range checks of every
//! PUBLIC value the user supplies), recomputes both hashes itself, stores the
//! inputs and signs the message above. The contract's `receipt_request`
//! (pss_public_contract, `receipt.nr`) recomputes the same two hashes from the
//! private function's arguments and checks the three signatures with
//! `schnorr::verify_signature` against the pinned `sig` keys; `expiry_block`
//! is a `u32` block number there, taken into the message as one field
//! element, which is why it is a `u32` here. Under secret-shared receipt intake the
//! user computes `C` over the values [`commitment_names`] lists, splits the
//! shared values and the blinding into three Rep3 summand vectors `s_0 +
//! s_1 + s_2` ([`CommitmentLayout::summand_names`] order) with a salt each, and sends `C`, the
//! three summand commitments `S_j`, the sharing digest `D`, the clear
//! inputs, one envelope per INPUT_SHARED value and node, and the envelopes
//! of the salts ([`SUMMAND_SALT`]); `D` covers the `S_j`, the kind of each
//! of C's values ([`commitment_layout`]) and the clear inputs. The
//! orchestrator checks the three share hashes of every envelope and that
//! `D` is the digest of the `S_j`, the layout and the clear inputs, and
//! sends node i its own envelopes ([`ReceiptRequest::project`]); node i
//! range-checks the clear inputs, checks `D` the same way, computes the
//! chain request id from `C`, checks that each of its envelopes hashes to
//! its share hash and opens under its current `enc` key, and that the pairs
//! it opened are `s_i` and `s_{i-1}` with their salts, hashing to `S_i` and
//! `S_{i-1}` ([`CheckedReceipt::check_own_envelopes`]), alone, and signs
//! the message over `C` and `D`, never keeping a shared value in the clear.
//! Each `S_j` is checked by both nodes that hold `s_j`, so three receipts
//! over one `D` mean the nodes hold one sharing and one set of clear
//! inputs; the user's request function proves that the sharing opens `C`
//! and computes `D` over C's own clear values (pss_public_contract
//! `shared_intake`), so a request whose shares or clear inputs do not open
//! `C` is never queued.
//!
//! This module holds what node and orchestrator share: the signer and the
//! verifier (crate::receipt, re-exported at the crate root; receipt
//! intake's resync hook re-signs copied rows with them), the wire types of the two routes and
//! their projection, the static-validity check, the commitment layout, the
//! checked receipt and the expiry bound. The message a receipt signs and
//! the envelope check before it are its intake's own ([`ReceiptSigning`]). The node keeps the rows
//! (sidecar-node's `receipt` module); the store trait's `receipts` table is
//! sidecar-core's.
//!
//! The known answers are in `testvectors/receipts.json`: three signatures by
//! the sample deployment's `sig` keys (`testvectors/keys.json`) over two
//! cases, with the message preimage, for the Noir intake library and
//! pss-client to check against; `testvectors/shared_intake.json` holds a
//! receipt over `C` (crate::vectors).

use std::any::Any;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use sidecar_core::abi::{CircuitShape, Leaf};
use sidecar_core::derived::Kind;
use sidecar_core::error::Refusal;
use sidecar_core::field::{FieldHex, Fr};
use sidecar_core::keys::NodeKeys;
use sidecar_core::manifest::{Intake, PublicOperand, PublicSource, SharedReserved, Source};
use sidecar_core::register::Signature;
use sidecar_core::request::{
    ForNode, Full, NODES, NodeSharedInput, PublicValue, View, flatten_public_map,
};
use sidecar_core::store::{PackageRow, ReceiptRow};

use crate::TipManifest;
use crate::intake::not_for_receipts;
use crate::synth::TipPackage;

// ---------------------------------------------------------------------------
// The wire types
// ---------------------------------------------------------------------------

/// `POST /v1/receipt`: the request's clear inputs by public name, as an
/// execute request's `public` map spells them, and the block the expiry
/// counts from; under receipt intake the nonce (never a requester: a body
/// naming `user` is refused as an unknown field); under secret-shared receipt
/// intake the inputs commitment `C` and, per shared input, the envelopes and
/// the three share hashes. `ReceiptRequest<Full>` is what the client sends
/// the orchestrator (all three envelopes of each shared input);
/// `ReceiptRequest` (the default, [`ForNode`]) is what node i receives, its
/// own envelope of each ([`ReceiptRequest::project`]). `expiry_block` is the
/// one field the client leaves out (the orchestrator refuses it): the
/// orchestrator sets it for the nodes, and a node requires it. Under
/// secret-shared receipt intake `shared_inputs` holds, after the circuit's
/// INPUT_SHARED values, the envelopes of the three summand salts
/// ([`SUMMAND_SALT`]), and the request carries the summand commitments and
/// the sharing digest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, bound(serialize = "", deserialize = ""))]
pub struct ReceiptRequest<V: View = ForNode> {
    pub namespace: FieldHex,
    pub circuit: String,
    /// The clear app inputs by public name; a list fills an array parameter.
    #[serde(default)]
    pub inputs: BTreeMap<String, PublicValue>,
    /// Receipt intake: the request's random salt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_nonce: Option<FieldHex>,
    /// Secret-shared receipt intake: the inputs commitment `C`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inputs_hash: Option<FieldHex>,
    /// Secret-shared receipt intake: every INPUT_SHARED value, its envelopes under
    /// the intake associated data (all three, or this node's) and the three
    /// share hashes, then the salts' ([`SUMMAND_SALT`]).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub shared_inputs: Vec<V::SharedInput>,
    /// Secret-shared receipt intake: the three summand commitments `S_j`
    /// ([`crate::summand_commitment`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summand_commitments: Option<[FieldHex; NODES]>,
    /// Secret-shared receipt intake: the sharing digest `D` over them
    /// ([`crate::sharing_digest`]), which the receipts sign.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sharing_digest: Option<FieldHex>,
    /// The current proposed L2 block the orchestrator fixes the expiry from
    /// (see the orchestrator's receipt route); a node checks the expiry
    /// against its own chain view's block instead.
    pub current_block: u32,
    /// The expiry the three nodes sign; set by the orchestrator only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expiry_block: Option<u32>,
    /// Under `upgrades` `circuits` or `contract`: the contract manifest
    /// version the client built the request under, the one the contract's
    /// pins name in force (the request id binds that version's vk hash). The
    /// orchestrator resolves the package in it; a node refuses a version its
    /// own chain view's pins do not name. Absent: the newest version at the
    /// orchestrator, the version in force at each node.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest_hash: Option<FieldHex>,
}

impl ReceiptRequest {
    /// Parse a node's body (400 naming the field); the client's body parses
    /// with `sidecar_core::error::parse_json::<ReceiptRequest<Full>>`.
    pub fn from_json(text: &str) -> Result<Self, Refusal> {
        sidecar_core::error::parse_json(text)
    }
}

impl ReceiptRequest<Full> {
    /// Check that every `share_hashes[i]` is the hash of `shares[i]` (400
    /// naming the input and the node), as the orchestrator does for an
    /// execute request before it projects.
    pub fn check_share_hashes(&self) -> Result<(), Refusal> {
        for i in 0..NODES {
            for (k, input) in self.project(i).shared_inputs.iter().enumerate() {
                input.check_hash(i, k)?;
            }
        }
        Ok(())
    }

    /// Node `node`'s view: the same body with only its own envelope of each
    /// shared input.
    ///
    /// Panics if `node` is not 0, 1 or 2.
    pub fn project(&self, node: usize) -> ReceiptRequest {
        assert!(node < NODES, "node index {node} out of range");
        ReceiptRequest {
            namespace: self.namespace,
            circuit: self.circuit.clone(),
            inputs: self.inputs.clone(),
            user_nonce: self.user_nonce,
            inputs_hash: self.inputs_hash,
            shared_inputs: self
                .shared_inputs
                .iter()
                .map(|s| NodeSharedInput {
                    name: s.name.clone(),
                    share: s.shares[node],
                    share_hashes: s.share_hashes,
                })
                .collect(),
            summand_commitments: self.summand_commitments,
            sharing_digest: self.sharing_digest,
            current_block: self.current_block,
            expiry_block: self.expiry_block,
            manifest_hash: self.manifest_hash,
        }
    }
}

/// One node's answer to `POST /v1/receipt`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptAnswer {
    /// The chain request id the node computed.
    pub request_id: FieldHex,
    pub inputs_hash: FieldHex,
    pub expiry_block: u32,
    /// The node's Schnorr signature over the receipt message.
    pub signature: Signature,
}

/// The name of the envelope of a secret-shared receipt request's summand
/// salts, the last entry of its `shared_inputs`: node i's envelope opens to
/// `[salt_i, salt_{i-1}]`, the salts of the summand vectors it holds, under
/// the intake associated data with this name. Not a circuit input: a node
/// checks it and drops it, and it never reaches a round.
pub const SUMMAND_SALT: &str = "$summand_salt";

/// The orchestrator's answer to `POST /v1/receipt`: the three nodes'
/// agreed values and their signatures, node 0 first, as the request
/// function's `receipts: [Receipt; 3]` takes them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptResponse {
    pub request_id: FieldHex,
    pub inputs_hash: FieldHex,
    pub expiry_block: u32,
    pub signatures: [Signature; NODES],
}

/// `GET /v1/receipt/{namespace}/{request_id}` on a node: the stored row, the
/// inputs the scheduler synthesises the head's request from and the chain
/// verifier recomputes the ids from. It names no requester; under secret-shared
/// receipt intake it carries no nonce and, per shared input, this node's own envelope and the
/// three share hashes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredReceipt {
    pub namespace: FieldHex,
    pub request_id: FieldHex,
    pub circuit: String,
    pub vk_hash: FieldHex,
    /// The clear app inputs in ABI order ([`intake_inputs`]);
    /// [`public_inputs`] turns them back into the `public` map.
    pub inputs: Vec<FieldHex>,
    /// The commitment the receipt signs: `inputs_hash`, or `C`.
    pub inputs_hash: FieldHex,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_nonce: Option<FieldHex>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub shared_inputs: Vec<NodeSharedInput>,
    pub expiry_block: u64,
    pub stale_blocks: Option<u64>,
    pub signature: Signature,
}

impl StoredReceipt {
    pub fn new(namespace: Fr, row: &ReceiptRow) -> Self {
        StoredReceipt {
            namespace: FieldHex(namespace),
            request_id: FieldHex(row.request_id),
            circuit: row.circuit.clone(),
            vk_hash: FieldHex(row.vk_hash),
            inputs: row.inputs.iter().copied().map(FieldHex).collect(),
            inputs_hash: FieldHex(row.inputs_hash),
            user_nonce: row.user_nonce.map(FieldHex),
            shared_inputs: row.shares.clone(),
            expiry_block: row.expiry_block,
            stale_blocks: row.stale_blocks,
            signature: row.signature,
        }
    }
}

// ---------------------------------------------------------------------------
// The static-validity check
// ---------------------------------------------------------------------------

// One app input as the ABI walk meets it: the request public name and, for a
// name that fills a wider parameter, the element index (`name[i]`).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct InputKey {
    name: String,
    index: Option<usize>,
}

impl InputKey {
    fn flat(&self) -> String {
        match self.index {
            Some(i) => format!("{}[{i}]", self.name),
            None => self.name.clone(),
        }
    }
}

// One input the ABI walk meets: a clear app input element (the request
// public name, the parameter and its leaf type), or an INPUT_SHARED value
// by name (an app input or a reserved shared name).
enum Walked {
    Clear(InputKey, String, Leaf),
    Shared(String),
}

// Every input the ABI walk meets, in walk order: each request public name
// element with the parameter and leaf type of each use, skipping the
// parameters a pinned public read fills and those a tree key's paths fill
// (the scheduler places both), and each INPUT_SHARED value. A clear partial
// note (PUBLIC `$partial_note`, a non-secret-shared intake under
// `outcome: partial`) is an app input the user supplies, keyed
// by the name of the parameter it fills (where bind looks a reserved operand
// up). Other operands (`$namespace`, request keys, the reserved `$vk_hash`,
// `$user`, `$user_nonce`, `$new_leaf`, `$inputs_hash`, constants) are not
// app inputs and are skipped. REGISTER admits an INPUT_SHARED source under
// intake direct and the secret-shared intakes only.
fn walk(shape: &CircuitShape, tip: &TipManifest) -> Vec<Walked> {
    let read_params: BTreeSet<&str> = tip
        .public_reads()
        .iter()
        .flat_map(|r| r.params())
        .chain(tip.manifest().tree_params())
        .collect();
    let mut out = Vec::new();
    for param in &shape.params {
        let operands: Vec<(&PublicOperand, Option<usize>)> = match &param.source {
            _ if read_params.contains(param.name.as_str()) => continue,
            Source::Public(PublicSource::One(op)) if param.width == 1 => vec![(op, None)],
            Source::Public(PublicSource::One(op)) => {
                (0..param.width).map(|i| (op, Some(i))).collect()
            }
            Source::Public(PublicSource::List(ops)) => ops.iter().map(|op| (op, None)).collect(),
            Source::InputShared(name) => {
                out.push(Walked::Shared(name.clone()));
                continue;
            }
            _ => continue,
        };
        for ((op, index), leaf) in operands.into_iter().zip(&param.leaves) {
            let name = match op {
                PublicOperand::Name(name) => name,
                PublicOperand::Reserved(r) if r.app_input() => &param.name,
                _ => continue,
            };
            let key = InputKey {
                name: name.clone(),
                index,
            };
            out.push(Walked::Clear(key, param.name.clone(), *leaf));
        }
    }
    out
}

// The clear app inputs of the walk, each with the parameter and leaf type of
// each use.
fn clear_walk(shape: &CircuitShape, tip: &TipManifest) -> Vec<(InputKey, String, Leaf)> {
    walk(shape, tip)
        .into_iter()
        .filter_map(|w| match w {
            Walked::Clear(key, param, leaf) => Some((key, param, leaf)),
            Walked::Shared(_) => None,
        })
        .collect()
}

/// The values the inputs commitment `C` commits to before the blinding, by
/// name, in the order the ABI walk first meets each: every clear app input
/// element (`name` or `name[i]`), every INPUT_SHARED app input, and the
/// reserved `$partial_note`, `$outcome_key` and `$outcome_tag` the round
/// takes; `$blinding` is not one of them
/// (`C = poseidon2([v_1, ..., v_m, blinding])`, [`crate::inputs_commitment`]).
/// A client and the round circuit commit to these values in this order.
pub fn commitment_names(shape: &CircuitShape, tip: &TipManifest) -> Vec<String> {
    let mut seen = BTreeSet::new();
    walk(shape, tip)
        .into_iter()
        .filter_map(|w| match w {
            Walked::Clear(key, _, _) => Some(key.flat()),
            Walked::Shared(name) => SharedReserved::from_name(&name)
                .is_none_or(SharedReserved::committed)
                .then_some(name),
        })
        .filter(|name| seen.insert(name.clone()))
        .collect()
}

/// The values the inputs commitment `C` of a secret-shared intake takes,
/// as both secret-shared intakes read them: each value's name
/// ([`commitment_names`]) and kind, in C's order. A value is chosen when it
/// is shared (an INPUT_SHARED app input or reserved value) and clear
/// otherwise.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitmentLayout {
    pub kinds: Vec<(String, Kind)>,
}

impl CommitmentLayout {
    /// The kind of each of C's values, in C's order: what the sharing
    /// digest takes ([`crate::sharing_digest`]).
    pub fn value_kinds(&self) -> Vec<Kind> {
        self.kinds.iter().map(|(_, k)| *k).collect()
    }

    /// How many of C's values are clear.
    pub fn clear(&self) -> usize {
        self.kinds.iter().filter(|(_, k)| *k == Kind::Clear).count()
    }

    /// The names of a sharing's summand vectors' elements, in order: every
    /// chosen value in C's order, then `$blinding`. The k-th element of
    /// `s_j` is the j-th summand of the k-th name: the order the user's
    /// request function matches against C's values, the order a node opens
    /// its envelopes in under secret-shared receipt intake, and the order
    /// of the request log's encoded values under secret-shared on-chain
    /// intake ([`crate::onchain_layout`]).
    pub fn summand_names(&self) -> Vec<String> {
        self.kinds
            .iter()
            .filter(|(_, k)| *k == Kind::Chosen)
            .map(|(name, _)| name.clone())
            .chain([SharedReserved::Blinding.as_str().to_string()])
            .collect()
    }
}

/// The commitment layout of a round of `shape` under the queued manifest
/// `tip`.
pub fn commitment_layout(shape: &CircuitShape, tip: &TipManifest) -> CommitmentLayout {
    let shared: BTreeSet<String> = shared_names(shape, tip).into_iter().collect();
    let kinds = commitment_names(shape, tip)
        .into_iter()
        .map(|name| {
            let kind = if shared.contains(&name) {
                Kind::Chosen
            } else {
                Kind::Clear
            };
            (name, kind)
        })
        .collect();
    CommitmentLayout { kinds }
}

/// Every INPUT_SHARED name of the circuit in ABI order, the reserved ones
/// included: the shared inputs a secret-shared-intake request carries.
pub fn shared_names(shape: &CircuitShape, tip: &TipManifest) -> Vec<String> {
    walk(shape, tip)
        .into_iter()
        .filter_map(|w| match w {
            Walked::Shared(name) => Some(name),
            Walked::Clear(..) => None,
        })
        .collect()
}

// The app inputs of a receipt, and their order. They are the
// values of the request public names the manifest's PUBLIC sources take,
// in the order the ABI walk first meets each name element (parameters in
// declaration order; `name[i]` in index order for a name that fills a wider
// parameter); a name used twice counts once. Values the user does not supply
// as inputs are not app inputs: `$namespace`, request keys, manifest
// constants, the reserved operands `$vk_hash` (the package's, which the node
// takes from its store, never from a body), `$user` and `$user_nonce` (the
// body's own fields beside `inputs`), and the parameters a pinned public
// read fills (the scheduler simulates those). Under secret-shared receipt intake the clear app
// inputs are the same walk with the INPUT_SHARED values left out (the nodes
// range-check only those), and the inputs commitment `C` takes every app
// input, clear or shared, with `$outcome_key` and `$outcome_tag`, in walk
// order ([`commitment_names`]). This is the
// list `inputs_hash` hashes, so a client building the `[Field; N]` of its
// request function, the node signing it and the scheduler rebuilding the
// public map must all walk it the same way: one function here does. The
// checks are those of the execute path's step 9 for the same values
// (sidecar-core's `bind::check_request`): every name present, none extra,
// each value in its ABI leaf's typed range (bool 1 bit, u<N>/i<N> N bits, a
// string byte 8 bits; a Field unchecked). They are the static validity a
// node checks before it signs; it never signs inputs that fail them. An
// app's own `is_valid` (the contract's) can be stricter; a node does not run
// it, and an `ok = false` round is still a round.
/// The static-validity check of a receipt request's inputs against the
/// queued manifest `tip` and the package's `shape`: the app inputs in ABI
/// order, each range-checked, or 400 naming the input.
pub fn intake_inputs(
    shape: &CircuitShape,
    tip: &TipManifest,
    inputs: &BTreeMap<String, PublicValue>,
) -> Result<Vec<Fr>, Refusal> {
    let given: BTreeMap<String, Fr> = flatten_public_map(inputs, "inputs")?.into_iter().collect();
    let mut used: BTreeSet<String> = BTreeSet::new();
    let mut out = Vec::new();
    for (key, param, leaf) in clear_walk(shape, tip) {
        let flat = key.flat();
        let Some(value) = given.get(&flat).copied() else {
            return Err(Refusal::bad_request(format!(
                "field `inputs.{flat}`: missing (parameter `{param}`)"
            )));
        };
        if !leaf.admits(value) {
            let Leaf::Bits(bits) = leaf else {
                unreachable!("a Field admits every value")
            };
            return Err(Refusal::bad_request(format!(
                "parameter `{param}`: `inputs.{flat}` does not fit in {bits} bit(s)"
            )));
        }
        if used.insert(flat) {
            out.push(value);
        }
    }
    if let Some(extra) = given.keys().find(|k| !used.contains(*k)) {
        return Err(Refusal::bad_request(format!(
            "field `inputs.{extra}`: unexpected; circuit `{}` takes {:?}",
            tip.circuit(),
            used.iter().collect::<Vec<_>>()
        )));
    }
    Ok(out)
}

/// The inverse of [`intake_inputs`]: the `public` map of the head's
/// request from stored inputs in ABI order (500 when their count is not the
/// manifest's: the row was stored under another circuit).
pub fn public_inputs(
    shape: &CircuitShape,
    tip: &TipManifest,
    inputs: &[Fr],
) -> Result<BTreeMap<String, PublicValue>, Refusal> {
    let mut seen = BTreeSet::new();
    let keys: Vec<InputKey> = clear_walk(shape, tip)
        .into_iter()
        .map(|(key, _, _)| key)
        .filter(|key| seen.insert(key.flat()))
        .collect();
    if keys.len() != inputs.len() {
        return Err(Refusal::mpc_failure(format!(
            "stored receipt: {} inputs, circuit `{}` takes {}",
            inputs.len(),
            tip.circuit(),
            keys.len()
        )));
    }
    let mut lists: BTreeMap<String, BTreeMap<usize, FieldHex>> = BTreeMap::new();
    let mut out = BTreeMap::new();
    for (key, value) in keys.into_iter().zip(inputs) {
        match key.index {
            None => {
                out.insert(key.name, PublicValue::One(FieldHex(*value)));
            }
            Some(i) => {
                lists
                    .entry(key.name)
                    .or_default()
                    .insert(i, FieldHex(*value));
            }
        }
    }
    for (name, elements) in lists {
        out.insert(name, PublicValue::Many(elements.into_values().collect()));
    }
    Ok(out)
}

/// What a receipt request comes to once its intake checked it against its
/// package: the values the receipt signs (the chain request id and the
/// inputs commitment), the rest of the `receipts` row the node stores, and
/// the intake's own part of signing it ([`ReceiptSigning`]).
#[derive(Clone, Debug)]
pub struct CheckedReceipt {
    pub request_id: Fr,
    /// The commitment the receipt message names: `inputs_hash`, or `C`
    /// under secret-shared receipt intake.
    pub inputs_hash: Fr,
    /// The clear app inputs in ABI order.
    pub inputs: Vec<Fr>,
    /// Receipt intake: the request's nonce.
    pub user_nonce: Option<Fr>,
    /// Secret-shared receipt intake: this node's envelopes and the share
    /// hashes of the circuit's shared inputs, the ones the node stores.
    pub shares: Vec<NodeSharedInput>,
    pub vk_hash: Fr,
    pub stale_blocks: Option<u64>,
    /// The message the receipt signs and the envelope check before it, the
    /// intake's own.
    pub signing: Arc<dyn ReceiptSigning>,
}

/// An intake's own part of signing a receipt it checked: the message the
/// receipt signs, and what a node checks of the envelopes it is about to
/// keep before it stores or signs anything. Each intake that takes
/// receipts supplies one from [`crate::IntakeSource::check_receipt`].
pub trait ReceiptSigning: Any + std::fmt::Debug + Send + Sync {
    /// The message `receipt` signs at `expiry_block`.
    fn message(&self, receipt: &CheckedReceipt, expiry_block: u32) -> Fr;

    /// Node `node`'s check of the envelopes `receipt` keeps, under its keys
    /// `keys`, for `circuit` under `namespace` (400 naming the field); none
    /// by default, for an intake whose inputs are all clear.
    fn check_own_envelopes(
        &self,
        _receipt: &CheckedReceipt,
        _keys: &NodeKeys,
        _node: usize,
        _namespace: Fr,
        _circuit: &str,
    ) -> Result<(), Refusal> {
        Ok(())
    }
}

impl CheckedReceipt {
    /// The `receipts` row of this receipt, signed for `circuit` with
    /// `signature` over `expiry_block`.
    pub fn into_row(self, circuit: String, expiry_block: u32, signature: Signature) -> ReceiptRow {
        ReceiptRow {
            request_id: self.request_id,
            circuit,
            vk_hash: self.vk_hash,
            inputs: self.inputs,
            inputs_hash: self.inputs_hash,
            user_nonce: self.user_nonce,
            shares: self.shares,
            expiry_block: u64::from(expiry_block),
            stale_blocks: self.stale_blocks,
            signature,
        }
    }

    /// The message the receipt signs at `expiry_block`
    /// ([`ReceiptSigning::message`]).
    pub fn message(&self, expiry_block: u32) -> Fr {
        self.signing.message(self, expiry_block)
    }

    /// Node `node`'s check of the envelopes it is about to keep
    /// ([`ReceiptSigning::check_own_envelopes`]).
    pub fn check_own_envelopes(
        &self,
        keys: &NodeKeys,
        node: usize,
        namespace: Fr,
        circuit: &str,
    ) -> Result<(), Refusal> {
        self.signing
            .check_own_envelopes(self, keys, node, namespace, circuit)
    }
}

/// Check `req` against `pkg`, the package it names (already resolved: present
/// and not disabled): a queued manifest whose intake takes receipts (400
/// otherwise), then that intake's check ([`crate::IntakeSource::check_receipt`]:
/// under receipt intake the static-validity check, [`intake_inputs`], then
/// `inputs_hash` and the chain request id recomputed with [`crate::ids`]);
/// `stale_blocks` is the namespace's stale period, from its contract
/// manifest ([`crate::stale_blocks_of`]). A stored package that no longer
/// parses is 500 (REGISTER checked it).
pub fn check_receipt_request(
    pkg: &PackageRow,
    stale_blocks: Option<u64>,
    req: &ReceiptRequest,
) -> Result<CheckedReceipt, Refusal> {
    match TipPackage::from_row(pkg, stale_blocks)? {
        Some(package) => package.intake.check_receipt(&package, req),
        None => Err(not_for_receipts(&pkg.name, Intake::Direct.as_str())),
    }
}

/// The expiry bound a node holds an `expiry_block` to: after `current_block`
/// (an expired receipt is useless) and at most `max_ahead` blocks after it
/// (400 otherwise, naming both).
pub fn check_expiry(current_block: u32, expiry_block: u32, max_ahead: u32) -> Result<(), Refusal> {
    if expiry_block <= current_block {
        return Err(Refusal::bad_request(format!(
            "field `expiry_block`: {expiry_block} is not after the current block {current_block}"
        )));
    }
    let ahead = expiry_block - current_block;
    if ahead > max_ahead {
        return Err(Refusal::bad_request(format!(
            "field `expiry_block`: {expiry_block} is {ahead} blocks after the current block \
             {current_block}; this node signs at most {max_ahead} ahead"
        )));
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::intake::shared_receipt::SharingCheck;
    use crate::receipt::{RECEIPT_DOMAIN, receipt_message, sign_receipt, verify_receipt};
    use crate::receipt::{chain_request_id, inputs_hash};
    use serde_json::{Value, json};
    use sidecar_core::abi::check_manifest_value;
    use sidecar_core::envelope::EnvelopeAd;
    use sidecar_core::error::parse_value;
    use sidecar_core::error::{ErrorClass, parse_json};
    use sidecar_core::grumpkin::{Fq, point_to_wire};
    use sidecar_core::hash::poseidon2_hash;
    use sidecar_core::keys::label_field;
    use sidecar_core::schnorr::{public_key, signature_to_bytes, verify};
    use sidecar_test_fixtures::dirs::repo;
    use sidecar_test_fixtures::vectors::{hex, node_keys, shared_intake, shared_receipt_client};

    const VECTORS: &str = "testvectors/receipts.json";

    /// The sample deployment's `sig` scalars (testvectors/keys.json).
    fn sig_scalars() -> Vec<Fq> {
        node_keys().iter().map(NodeKeys::sig_scalar).collect()
    }

    #[test]
    fn the_domain_is_ascii_sidecar_receipt() {
        assert_eq!(Fr::from(RECEIPT_DOMAIN), label_field(b"sidecar.receipt"));
        // the value of pss_public_contract's domains.nr
        assert_eq!(
            Fr::from(RECEIPT_DOMAIN),
            hex("0x736964656361722e72656365697074")
        );
    }

    #[test]
    fn the_message_is_the_stated_sponge() {
        let (id, ih) = (Fr::from(11u64), Fr::from(22u64));
        assert_eq!(
            receipt_message(id, ih, 300),
            poseidon2_hash(&[Fr::from(RECEIPT_DOMAIN), id, ih, Fr::from(300u64)])
        );
        // every part is bound
        let m = receipt_message(id, ih, 300);
        assert_ne!(m, receipt_message(id, ih, 301));
        assert_ne!(m, receipt_message(id + Fr::from(1u64), ih, 300));
        assert_ne!(m, receipt_message(id, ih + Fr::from(1u64), 300));
        // the largest u32 expiry is one field element below 2^32
        assert_eq!(
            receipt_message(id, ih, u32::MAX),
            poseidon2_hash(&[Fr::from(RECEIPT_DOMAIN), id, ih, Fr::from(0xffff_ffffu64)])
        );
    }

    #[test]
    fn a_receipt_round_trips_on_the_machine_signer() {
        for sig in sig_scalars() {
            let pk = public_key(sig);
            let (id, ih) = (-Fr::from(5u64), Fr::from(0x1234u64));
            let s = sign_receipt(sig, id, ih, 1000);
            assert!(verify_receipt(pk, s, id, ih, 1000));
            // the plain verifier over the stated message accepts it too
            assert!(verify(pk, s, receipt_message(id, ih, 1000)));
            // a derived nonce: equal messages, equal signatures
            assert_eq!(s, sign_receipt(sig, id, ih, 1000));
            // another expiry, id, hash or key does not verify
            assert!(!verify_receipt(pk, s, id, ih, 1001));
            assert!(!verify_receipt(pk, s, id + Fr::from(1u64), ih, 1000));
            assert!(!verify_receipt(pk, s, id, ih + Fr::from(1u64), 1000));
            assert!(!verify_receipt(
                public_key(sig + Fq::from(1u64)),
                s,
                id,
                ih,
                1000
            ));
            // a receipt is not a signature over the bare chain request id
            assert!(!verify(pk, s, id));
            assert_ne!(s, sign_receipt(sig, id, ih, 1001));
        }
    }

    // The AMM tip manifest with receipt intake, and the one swap ABI it fits
    // (both non-secret-shared intakes), whose `direction` is a bool (a typed range check).
    fn amm_receipt_manifest() -> Value {
        let text = include_str!("../../../../testvectors/manifests/amm_swap_tip.json")
            .replace("\"intake\": \"onchain\"", "\"intake\": \"receipt\"");
        parse_json(&text).unwrap()
    }

    const ABI: &str = r#"{
      "parameters": [
        {"name": "namespace", "type": {"kind": "field"}, "visibility": "public"},
        {"name": "vk_hash", "type": {"kind": "field"}, "visibility": "public"},
        {"name": "in_slots", "type": {"kind": "array", "length": 1, "type": {"kind": "field"}}, "visibility": "public"},
        {"name": "out_slots", "type": {"kind": "array", "length": 1, "type": {"kind": "field"}}, "visibility": "public"},
        {"name": "amount_in", "type": {"kind": "field"}, "visibility": "private"},
        {"name": "direction", "type": {"kind": "boolean"}, "visibility": "private"},
        {"name": "min_out", "type": {"kind": "field"}, "visibility": "private"},
        {"name": "partial_note", "type": {"kind": "field"}, "visibility": "private"},
        {"name": "user_nonce", "type": {"kind": "field"}, "visibility": "private"},
        {"name": "pool", "type": {"kind": "array", "length": 2, "type": {"kind": "field"}}, "visibility": "private"},
        {"name": "r_old", "type": {"kind": "field"}, "visibility": "private"},
        {"name": "r_new", "type": {"kind": "field"}, "visibility": "private"},
        {"name": "nsk_app", "type": {"kind": "field"}, "visibility": "private"}
      ],
      "return_type": {"abi_type": {"kind": "struct", "path": "AmmTipOut", "fields": [
        {"name": "request_id", "type": {"kind": "field"}},
        {"name": "old_c", "type": {"kind": "field"}},
        {"name": "new_c", "type": {"kind": "field"}},
        {"name": "npk_app_hash", "type": {"kind": "field"}},
        {"name": "ok", "type": {"kind": "field"}},
        {"name": "partial_note", "type": {"kind": "field"}},
        {"name": "code", "type": {"kind": "field"}},
        {"name": "amount_out", "type": {"kind": "field"}}
      ]}, "visibility": "public"},
      "error_types": {}
    }"#;

    fn package(manifest: Value) -> PackageRow {
        PackageRow {
            name: "amm_swap_tip".into(),
            manifest_hash: Fr::from(0u64),
            circuit_json: serde_json::to_vec(&json!({"abi": parse_json::<Value>(ABI).unwrap()}))
                .unwrap(),
            manifest,
            vk: vec![],
            vk_hash: hex("0x2a8f1c0e9b7d6a5f4e3c2b1a09f8e7d6c5b4a39281706f5e4d3c2b1a09f8e7d6"),
            disabled: false,
            seq: 1,
        }
    }

    fn request(inputs: Value) -> ReceiptRequest {
        ReceiptRequest::from_json(
            &json!({
                "namespace": "0x1a2b",
                "circuit": "amm_swap_tip",
                "inputs": inputs,
                "user_nonce": "0x01",
                "current_block": 100,
            })
            .to_string(),
        )
        .unwrap()
    }

    /// The sharing a secret-shared receipt intake check signs over; `None`
    /// under another intake.
    fn sharing_of(checked: &CheckedReceipt) -> Option<&SharingCheck> {
        (checked.signing.as_ref() as &dyn Any).downcast_ref()
    }

    fn refused(result: Result<CheckedReceipt, Refusal>, class: ErrorClass, needle: &str) {
        let err = result.unwrap_err();
        assert_eq!(err.class, class, "{err}");
        assert!(err.message.contains(needle), "`{err}` lacks `{needle}`");
    }

    #[test]
    fn a_receipt_request_is_checked_and_hashed() {
        let pkg = package(amm_receipt_manifest());
        let req = request(
            json!({"amount_in": "0x1388", "direction": "0x0", "min_out": "0x0fa0", "partial_note": "0x9a"}),
        );
        let checked = check_receipt_request(&pkg, Some(50), &req).unwrap();
        // ABI order: amount_in, direction, min_out, partial_note
        assert_eq!(
            checked.inputs,
            [
                Fr::from(5000u64),
                Fr::from(0u64),
                Fr::from(4000u64),
                Fr::from(0x9au64)
            ]
        );
        assert_eq!(checked.inputs_hash, inputs_hash(&checked.inputs));
        assert_eq!(
            checked.request_id,
            chain_request_id(hex("0x1a2b"), pkg.vk_hash, &checked.inputs, Fr::from(1u64))
        );
        assert_eq!(checked.vk_hash, pkg.vk_hash);
        assert_eq!(checked.stale_blocks, Some(50));
        // the same inputs, the same id; another nonce, another id
        let again = check_receipt_request(&pkg, Some(50), &req).unwrap();
        assert_eq!(
            (again.request_id, again.inputs_hash, again.message(1300)),
            (
                checked.request_id,
                checked.inputs_hash,
                checked.message(1300)
            )
        );
        let mut other = req.clone();
        other.user_nonce = Some(FieldHex::from(2));
        assert_ne!(
            check_receipt_request(&pkg, Some(50), &other)
                .unwrap()
                .request_id,
            checked.request_id
        );
    }

    #[test]
    fn invalid_inputs_are_refused_naming_the_input() {
        let pkg = package(amm_receipt_manifest());
        let bad = BadRequestCases::new(&pkg);
        bad.refused(
            json!({"amount_in": "0x1388", "direction": "0x2", "min_out": "0x0", "partial_note": "0x9a"}),
            "does not fit in 1 bit",
        );
        bad.refused(
            json!({"amount_in": "0x1388", "min_out": "0x0", "partial_note": "0x9a"}),
            "field `inputs.direction`: missing",
        );
        bad.refused(
            json!({"amount_in": "0x1388", "direction": "0x0", "min_out": "0x0", "partial_note": "0x9a", "x": "0x1"}),
            "field `inputs.x`: unexpected",
        );
        bad.refused(
            json!({"amount_in": "0x1388", "direction": "0x0", "$namespace": "0x1"}),
            "not a public value name",
        );
        bad.refused(
            json!({"amount_in": ["0x1", "0x2"], "direction": "0x0", "min_out": "0x0", "partial_note": "0x9a"}),
            "field `inputs.amount_in`: missing",
        );
    }

    struct BadRequestCases<'a>(&'a PackageRow);

    impl<'a> BadRequestCases<'a> {
        fn new(pkg: &'a PackageRow) -> Self {
            Self(pkg)
        }
        fn refused(&self, inputs: Value, needle: &str) {
            refused(
                check_receipt_request(self.0, Some(50), &request(inputs)),
                ErrorClass::BadRequest,
                needle,
            );
        }
    }

    #[test]
    fn only_a_receipt_intake_package_is_signed_for() {
        let req = request(
            json!({"amount_in": "0x1388", "direction": "0x0", "min_out": "0x0fa0", "partial_note": "0x9a"}),
        );
        // intake: onchain
        let onchain: Value = parse_json(include_str!(
            "../../../../testvectors/manifests/amm_swap_tip.json"
        ))
        .unwrap();
        refused(
            check_receipt_request(&package(onchain), Some(50), &req),
            ErrorClass::BadRequest,
            "`intake: onchain`",
        );
        // intake direct
        let direct = json!({"manifest": 1, "circuit": "amm_swap_tip", "namespace_param": "namespace",
          "state_keys": {"reads": 0, "writes": 0},
          "witness": [
            {"param": "namespace", "from": {"PUBLIC": "$namespace"}},
            {"param": "vk_hash", "from": {"PUBLIC": "vk_hash"}},
            {"param": "in_slots", "from": {"PUBLIC": "in_slots"}},
            {"param": "out_slots", "from": {"PUBLIC": "out_slots"}},
            {"param": "amount_in", "from": {"PUBLIC": "amount_in"}},
            {"param": "direction", "from": {"PUBLIC": "direction"}},
            {"param": "min_out", "from": {"PUBLIC": "min_out"}},
            {"param": "partial_note", "from": {"PUBLIC": "partial_note"}},
            {"param": "user_nonce", "from": {"PUBLIC": "user_nonce"}},
            {"param": "pool", "from": {"SAMPLE": 2}},
            {"param": "r_old", "from": {"SAMPLE": 1}},
            {"param": "r_new", "from": {"SAMPLE": 1}},
            {"param": "nsk_app", "from": {"LOAD": "nsk_app", "slice": [0, 1], "len": 1}}
          ],
          "outputs": [], "state": {}});
        refused(
            check_receipt_request(&package(direct), Some(50), &req),
            ErrorClass::BadRequest,
            "`intake: direct`",
        );
        // a stored package that no longer parses is the node's fault
        let mut broken = package(amm_receipt_manifest());
        broken.circuit_json = b"not json".to_vec();
        refused(
            check_receipt_request(&broken, Some(50), &req),
            ErrorClass::MpcFailure,
            "the circuit",
        );
    }

    /// A public read's parameter is the scheduler's, not an app input; the
    /// inverse rebuilds the `public` map, a wide parameter as a list.
    #[test]
    fn public_reads_are_not_app_inputs_and_the_map_round_trips() {
        let abi = r#"{
          "parameters": [
            {"name": "namespace", "type": {"kind": "field"}, "visibility": "public"},
            {"name": "amounts", "type": {"kind": "array", "length": 2, "type": {"kind": "integer", "sign": "unsigned", "width": 8}}, "visibility": "public"},
            {"name": "price", "type": {"kind": "field"}, "visibility": "public"},
            {"name": "side", "type": {"kind": "field"}, "visibility": "public"},
            {"name": "pool", "type": {"kind": "array", "length": 2, "type": {"kind": "field"}}, "visibility": "private"},
            {"name": "r_old", "type": {"kind": "field"}, "visibility": "private"},
            {"name": "r_new", "type": {"kind": "field"}, "visibility": "private"},
            {"name": "nsk_app", "type": {"kind": "field"}, "visibility": "private"}
          ],
          "return_type": {"abi_type": {"kind": "struct", "path": "Out", "fields": [
            {"name": "old_c", "type": {"kind": "field"}},
            {"name": "new_c", "type": {"kind": "field"}},
            {"name": "npk_app_hash", "type": {"kind": "field"}}
          ]}, "visibility": "public"},
          "error_types": {}
        }"#;
        let manifest = json!({
          "manifest": 1, "circuit": "lend", "namespace_param": "namespace",
          "state_keys": {"reads": 1, "writes": 1}, "intake": "receipt", "outcome": "none",
          "state": {"$state_keys.reads[0]": "chain", "$state_keys.writes[0]": "chain"},
          "witness": [
            {"param": "namespace", "from": {"PUBLIC": "$namespace"}},
            {"param": "amounts", "from": {"PUBLIC": "amounts"}},
            {"param": "price", "from": {"PUBLIC": "price"}},
            {"param": "side", "from": {"PUBLIC": "side"}},
            {"param": "pool", "from": {"LOAD": "$state_keys.reads[0]", "slice": [0, 2], "len": 3}},
            {"param": "r_old", "from": {"LOAD": "$state_keys.reads[0]", "slice": [2, 3], "len": 3}},
            {"param": "r_new", "from": {"SAMPLE": 1}},
            {"param": "nsk_app", "from": {"LOAD": "nsk_app", "slice": [0, 1], "len": 1}}
          ],
          "outputs": [{"TACEO_store": "out0", "STORE": "$state_keys.writes[0]", "len": 3, "note_hash": "new_c"}],
          "commitment_slot": {"$state_keys.reads[0]": {"old": "old_c"}},
          "public_reads": [{"contract": "0x1234", "function": "get_price", "args": [], "param": "price"}]
        });
        let (m, shape) = check_manifest_value(&manifest, &parse_json(abi).unwrap()).unwrap();
        let tip = TipManifest::from_manifest(&m, Some(50)).unwrap();
        let given: BTreeMap<String, PublicValue> = parse_value(&json!({
            "amounts": ["0x07", "0xff"], "side": "0x03"
        }))
        .unwrap();
        let inputs = intake_inputs(&shape, &tip, &given).unwrap();
        assert_eq!(inputs, [7u64, 255, 3].map(Fr::from));
        assert_eq!(public_inputs(&shape, &tip, &inputs).unwrap(), given);
        // the price is the read's: supplying it is refused
        let mut with_price = given.clone();
        with_price.insert("price".into(), PublicValue::One(FieldHex::from(9)));
        let err = intake_inputs(&shape, &tip, &with_price).unwrap_err();
        assert!(err.message.contains("`inputs.price`: unexpected"), "{err}");
        // a u8 element out of range, naming the element
        let wide: BTreeMap<String, PublicValue> =
            parse_value(&json!({"amounts": ["0x07", "0x100"], "side": "0x03"})).unwrap();
        let err = intake_inputs(&shape, &tip, &wide).unwrap_err();
        assert!(
            err.message
                .contains("`inputs.amounts[1]` does not fit in 8 bit(s)"),
            "{err}"
        );
        // a stored row of another length
        assert_eq!(
            public_inputs(&shape, &tip, &inputs[..2]).unwrap_err().class,
            ErrorClass::MpcFailure
        );
    }

    #[test]
    fn the_expiry_is_after_the_block_and_within_the_bound() {
        check_expiry(100, 101, 300).unwrap();
        check_expiry(100, 400, 300).unwrap();
        for (current, expiry, needle) in [
            (100, 100, "not after"),
            (100, 99, "not after"),
            (100, 401, "at most 300 ahead"),
        ] {
            let err = check_expiry(current, expiry, 300).unwrap_err();
            assert_eq!(err.class, ErrorClass::BadRequest);
            assert!(err.message.contains(needle), "{err}");
        }
        check_expiry(u32::MAX - 1, u32::MAX, 1).unwrap();
    }

    #[test]
    fn the_wire_types_refuse_unknown_fields() {
        let body = json!({"namespace": "0x1", "circuit": "c", "inputs": {},
            "user_nonce": "0x3", "current_block": 5, "extra": 1});
        assert!(ReceiptRequest::from_json(&body.to_string()).is_err());
        let over = json!({"namespace": "0x1", "circuit": "c", "inputs": {},
            "user_nonce": "0x3", "current_block": 4294967296u64});
        assert!(ReceiptRequest::from_json(&over.to_string()).is_err());
        // a client body has no expiry; serialising leaves it out
        let req = request(json!({}));
        assert!(
            !serde_json::to_string(&req)
                .unwrap()
                .contains("expiry_block")
        );
    }

    // ---- the receipt route on amm_swap_tip_receipt (testvectors/receipt_route.json) ----

    const ROUTE_VECTORS: &str = "testvectors/receipt_route.json";
    const RECEIPT_MANIFEST: &str = "examples/amm-tip/manifests/amm_swap_tip_receipt.json";
    const RECEIPT_CONTRACT_TEST: &str =
        "examples/amm-tip/contract/amm_tip_test/src/test_receipt_vector.nr";

    // The ABI of examples/amm-tip/circuits/amm_swap_tip, the circuit the
    // receipt-intake manifest registers, as nargo writes it (checked against
    // the compiled artifact when it is present).
    pub(crate) fn receipt_circuit_abi() -> Value {
        let field = json!({"kind": "field"});
        let one = json!({"kind": "array", "length": 1, "type": {"kind": "field"}});
        let two = json!({"kind": "array", "length": 2, "type": {"kind": "field"}});
        let param = |name: &str, typ: &Value, public: bool| {
            json!({"name": name, "type": typ,
                   "visibility": if public { "public" } else { "private" }})
        };
        let named = |names: &[&str]| -> Vec<Value> {
            names
                .iter()
                .map(|n| json!({"name": n, "type": field}))
                .collect()
        };
        // pss_core's tip::outputs::BoundPartial, the app's outputs nested as `app`
        let mut fields = named(&[
            "request_id",
            "old_c",
            "new_c",
            "npk_app_hash",
            "ok",
            "partial_note",
        ]);
        fields.push(json!({"name": "app", "type": {"kind": "struct",
            "path": "amm_tip::tip::SwapOutputs",
            "fields": named(&["code", "amount_out"])}}));
        json!({
          "parameters": [
            param("namespace", &field, true),
            param("vk_hash", &field, true),
            param("in_slots", &one, true),
            param("out_slots", &one, true),
            param("amount_in", &field, false),
            param("direction", &field, false),
            param("min_out", &field, false),
            param("partial_note", &field, false),
            param("user_nonce", &field, false),
            param("pool", &two, false),
            param("r_old", &field, false),
            param("r_new", &field, false),
            param("nsk_app", &field, false),
          ],
          "return_type": {"abi_type": {"kind": "struct",
            "path": "pss_core::tip::outputs::BoundPartial",
            "fields": fields},
            "visibility": "public"},
          "error_types": {}
        })
    }

    pub(crate) fn receipt_package() -> PackageRow {
        let text = std::fs::read_to_string(repo().join(RECEIPT_MANIFEST)).unwrap();
        PackageRow {
            name: "amm_swap_tip_receipt".into(),
            manifest_hash: Fr::from(0u64),
            circuit_json: serde_json::to_vec(&json!({"abi": receipt_circuit_abi()})).unwrap(),
            manifest: parse_json(&text).unwrap(),
            vk: vec![],
            vk_hash: hex("0x2a8f1c0e9b7d6a5f4e3c2b1a09f8e7d6c5b4a39281706f5e4d3c2b1a09f8e7d6"),
            disabled: false,
            seq: 1,
        }
    }

    // A swap of 5000 in direction 1 with a minimum output of 4000 into the
    // partial note 0x5eed, signed at block 1000 to expire 300 blocks later.
    fn route_body() -> Value {
        json!({
            "namespace": "0x1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f809",
            "circuit": "amm_swap_tip_receipt",
            "inputs": {"amount_in": "0x1388", "direction": "0x01", "min_out": "0x0fa0",
                       "partial_note": "0x5eed"},
            "user_nonce": "0x2a2a2a",
            "current_block": 1000,
            "expiry_block": 1300,
        })
    }

    fn route_vectors() -> Value {
        let pkg = receipt_package();
        let body = route_body();
        let req = ReceiptRequest::from_json(&body.to_string()).unwrap();
        let checked = check_receipt_request(&pkg, Some(50), &req).unwrap();
        let expiry = req.expiry_block.unwrap();
        let (id, ih) = (checked.request_id, checked.inputs_hash);
        let signatures: Vec<Signature> = sig_scalars()
            .iter()
            .map(|s| sign_receipt(*s, id, ih, expiry))
            .collect();
        json!({
            "rule": "POST /v1/receipt on a node for the circuit amm_swap_tip_receipt, registered with examples/amm-tip/manifests/amm_swap_tip_receipt.json, the ABI below and vk_hash: inputs = the app inputs in ABI order (vk_hash and user_nonce are the reserved operands $vk_hash and $user_nonce, not app inputs; partial_note, filled by $partial_note, is an app input named by its parameter; the body names no requester), inputs_hash = poseidon2(inputs), request_id = poseidon2([namespace, vk_hash, inputs_hash, user_nonce]) with vk_hash the registered package's (never the body's), message and signatures as receipts.json",
            "manifest": RECEIPT_MANIFEST,
            "abi": receipt_circuit_abi(),
            "vk_hash": FieldHex(pkg.vk_hash),
            "body": body,
            "inputs": checked.inputs.iter().copied().map(FieldHex).collect::<Vec<_>>(),
            "inputs_hash": FieldHex(ih),
            "request_id": FieldHex(id),
            "message": FieldHex(receipt_message(id, ih, expiry)),
            "signatures": signatures,
        })
    }

    /// The route on the AMM tip's receipt-intake manifest hashes the four app
    /// inputs only (the swap's three and the partial note), as the
    /// contract's `swap_with_receipts` does; the vector
    /// is what this code computes, each signature verifies, and the Noir
    /// test contract's copy of it is the committed one.
    #[test]
    fn the_receipt_route_on_amm_swap_tip_receipt_hashes_the_app_inputs_only() {
        let pkg = receipt_package();
        let req = ReceiptRequest::from_json(&route_body().to_string()).unwrap();
        let checked = check_receipt_request(&pkg, Some(50), &req).unwrap();
        let app = [
            Fr::from(5000u64),
            Fr::from(1u64),
            Fr::from(4000u64),
            Fr::from(0x5eedu64),
        ];
        assert_eq!(checked.inputs, app);
        assert_eq!(checked.inputs_hash, poseidon2_hash(&app));
        assert_eq!(
            checked.request_id,
            poseidon2_hash(&[
                req.namespace.fr(),
                pkg.vk_hash,
                poseidon2_hash(&app),
                req.user_nonce.unwrap().fr(),
            ])
        );
        // the hidden requester: no address in the body, the id or the row
        let audit = crate::audit::Requesters::new([sidecar_core::field::fr_from_hex(
            "0x0b7e3a1f00c0ffee00000000000000000000000000000000000000000000beef",
        )
        .unwrap()]);
        audit.assert_receipt_body(&req);
        audit.assert_plain_id(
            checked.request_id,
            req.namespace.fr(),
            pkg.vk_hash,
            &checked.inputs,
            req.user_nonce.unwrap().fr(),
        );
        audit.assert_receipt_row(
            req.namespace.fr(),
            &checked
                .clone()
                .into_row(pkg.name.clone(), 1300, Signature::default()),
        );
        // the stored inputs give the map back without the reserved operands
        let (m, shape) =
            check_manifest_value(&pkg.manifest, &parse_value(&receipt_circuit_abi()).unwrap())
                .unwrap();
        let tip = TipManifest::from_manifest(&m, Some(50)).unwrap();
        assert_eq!(
            public_inputs(&shape, &tip, &checked.inputs).unwrap(),
            req.inputs
        );

        let text = std::fs::read_to_string(repo().join(ROUTE_VECTORS)).unwrap();
        let committed: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(committed, route_vectors(), "rerun write_receipt_vectors");
        let sigs = sig_scalars();
        for (i, s) in committed["signatures"]
            .as_array()
            .unwrap()
            .iter()
            .enumerate()
        {
            let s: Signature = serde_json::from_value(s.clone()).unwrap();
            assert!(verify_receipt(
                public_key(sigs[i]),
                s,
                checked.request_id,
                checked.inputs_hash,
                1300
            ));
        }
        // the Noir test contract checks the same values in-circuit
        let noir = std::fs::read_to_string(repo().join(RECEIPT_CONTRACT_TEST)).unwrap();
        let mut values: Vec<String> = ["request_id", "inputs_hash", "vk_hash"]
            .iter()
            .map(|k| committed[*k].as_str().unwrap().to_string())
            .collect();
        for k in ["namespace", "user_nonce"] {
            values.push(committed["body"][k].as_str().unwrap().to_string());
        }
        for s in committed["signatures"].as_array().unwrap() {
            for part in ["s", "e"] {
                for limb in s[part].as_array().unwrap() {
                    values.push(limb.as_str().unwrap().to_string());
                }
            }
        }
        for v in values {
            assert!(noir.contains(&v), "{RECEIPT_CONTRACT_TEST} lacks {v}");
        }
    }

    /// The hand-written ABI is the compiled circuit's (when
    /// `scripts/check-noir.sh examples/amm-tip` has written it from the
    /// current source).
    #[test]
    fn the_route_vector_abi_is_the_compiled_circuits() {
        use sidecar_core::testing::artifacts;
        let path = artifacts::compiled("amm-tip", "amm_swap_tip");
        let package = artifacts::package("amm-tip", "amm_swap_tip");
        if !artifacts::usable(&path, &package, "scripts/check-noir.sh examples/amm-tip") {
            return;
        }
        let text = std::fs::read_to_string(&path).unwrap();
        let compiled: Value = serde_json::from_str(&text).unwrap();
        let ours = receipt_circuit_abi();
        assert_eq!(compiled["abi"]["parameters"], ours["parameters"]);
        let fields = |abi: &Value| -> Vec<(Value, Value)> {
            abi["return_type"]["abi_type"]["fields"]
                .as_array()
                .unwrap()
                .iter()
                .map(|f| (f["name"].clone(), f["type"].clone()))
                .collect()
        };
        assert_eq!(fields(&compiled["abi"]), fields(&ours));
        assert_eq!(
            compiled["abi"]["return_type"]["visibility"],
            ours["return_type"]["visibility"]
        );
    }

    /// A body cannot supply what the node fills: `vk_hash` is no body field
    /// (the node takes the package's), no body names a requester (`user` is
    /// no body field), and neither `vk_hash` nor `user_nonce` is an app
    /// input of a manifest that fills them by the reserved operands.
    #[test]
    fn a_receipt_body_cannot_supply_the_reserved_values() {
        let pkg = receipt_package();
        let mut body = route_body();
        body["vk_hash"] = json!("0x01");
        let err = ReceiptRequest::from_json(&body.to_string()).unwrap_err();
        assert_eq!(err.class, ErrorClass::BadRequest);
        assert!(err.message.contains("unknown field `vk_hash`"), "{err}");
        let mut body = route_body();
        body["user"] = json!("0x0b7e3a1f00c0ffee00000000000000000000000000000000000000000000beef");
        let err = ReceiptRequest::from_json(&body.to_string()).unwrap_err();
        assert_eq!(err.class, ErrorClass::BadRequest);
        assert!(err.message.contains("unknown field `user`"), "{err}");
        for name in ["vk_hash", "user", "user_nonce"] {
            let mut body = route_body();
            body["inputs"][name] = json!("0x01");
            let req = ReceiptRequest::from_json(&body.to_string()).unwrap();
            refused(
                check_receipt_request(&pkg, Some(50), &req),
                ErrorClass::BadRequest,
                &format!("field `inputs.{name}`: unexpected"),
            );
        }
        // the package's vk_hash is the one the id commits to
        let req = ReceiptRequest::from_json(&route_body().to_string()).unwrap();
        let mut other = receipt_package();
        other.vk_hash = Fr::from(7u64);
        let a = check_receipt_request(&pkg, Some(50), &req).unwrap();
        let b = check_receipt_request(&other, Some(50), &req).unwrap();
        assert_eq!(
            (a.inputs.clone(), a.inputs_hash),
            (b.inputs.clone(), b.inputs_hash)
        );
        assert_ne!(a.request_id, b.request_id);
        assert_eq!(b.vk_hash, Fr::from(7u64));
    }

    // ---- testvectors/receipts.json ----

    struct Case {
        name: &'static str,
        namespace: Fr,
        vk_hash: Fr,
        inputs: Vec<Fr>,
        user_nonce: Fr,
        expiry_block: u32,
    }

    fn cases() -> Vec<Case> {
        let minus_one = -Fr::from(1u64);
        vec![
            Case {
                // the AMM tip's swap under receipt intake,
                // the first chain_request_id.json case
                name: "amm_swap_tip: two inputs, expiry 300 blocks after block 1000",
                namespace: hex(
                    "0x1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f809",
                ),
                vk_hash: hex("0x2a8f1c0e9b7d6a5f4e3c2b1a09f8e7d6c5b4a39281706f5e4d3c2b1a09f8e7d6"),
                inputs: vec![Fr::from(5000u64), Fr::from(0u64)],
                user_nonce: Fr::from(1u64),
                expiry_block: 1300,
            },
            Case {
                name: "field-sized values (p - 1), the largest u32 expiry",
                namespace: minus_one,
                vk_hash: minus_one,
                inputs: vec![minus_one, Fr::from(7u64), minus_one],
                user_nonce: minus_one,
                expiry_block: u32::MAX,
            },
        ]
    }

    fn vectors() -> Value {
        let sigs = sig_scalars();
        let nodes: Vec<Value> = sigs
            .iter()
            .enumerate()
            .map(|(i, s)| json!({"node": i, "sig_pk": point_to_wire(public_key(*s))}))
            .collect();
        let vectors: Vec<Value> = cases()
            .iter()
            .map(|c| {
                let ih = inputs_hash(&c.inputs);
                let id = chain_request_id(c.namespace, c.vk_hash, &c.inputs, c.user_nonce);
                let signatures: Vec<Signature> = sigs
                    .iter()
                    .map(|s| sign_receipt(*s, id, ih, c.expiry_block))
                    .collect();
                let bytes: Vec<String> = signatures
                    .iter()
                    .map(|s| {
                        let b = signature_to_bytes(s).unwrap();
                        format!(
                            "0x{}",
                            b.iter().map(|x| format!("{x:02x}")).collect::<String>()
                        )
                    })
                    .collect();
                json!({
                    "name": c.name,
                    "namespace": FieldHex(c.namespace),
                    "vk_hash": FieldHex(c.vk_hash),
                    "inputs": c.inputs.iter().copied().map(FieldHex).collect::<Vec<_>>(),
                    "inputs_hash": FieldHex(ih),
                    "user_nonce": FieldHex(c.user_nonce),
                    "request_id": FieldHex(id),
                    "expiry_block": c.expiry_block,
                    "message_preimage": [
                        FieldHex(Fr::from(RECEIPT_DOMAIN)),
                        FieldHex(id),
                        FieldHex(ih),
                        FieldHex(Fr::from(u64::from(c.expiry_block))),
                    ],
                    "message": FieldHex(receipt_message(id, ih, c.expiry_block)),
                    "signatures": signatures,
                    "signature_bytes": bytes,
                })
            })
            .collect();
        json!({
            "message_rule": "message = poseidon2([RECEIPT_DOMAIN, request_id, inputs_hash, expiry_block]); request_id = poseidon2([namespace, vk_hash, inputs_hash, user_nonce]) (chain_request_id.json), inputs_hash = poseidon2(inputs), the app inputs in ABI order; expiry_block a u32 block number as one field element",
            "receipt_domain": FieldHex(Fr::from(RECEIPT_DOMAIN)),
            "receipt_domain_ascii": "sidecar.receipt",
            "scheme": "Schnorr over Grumpkin as noir-lang/schnorr v0.4.0 verify_signature checks it (schnorr.json); signatures[i] is node i's, by the sig scalar of keys.json node i, and verifies under nodes[i].sig_pk",
            "nonce_rule": "derived: the nonce generator (rand StdRng, ChaCha12) is seeded with the 32 big-endian bytes of poseidon2([ASCII \"sidecar.receipt_nonce\", sig.lo, sig.hi, message]); a verifier needs only the signature",
            "encoding": "signatures[i] = {s: [lo, hi], e: [lo, hi]}, sidecar-core's Signature and pss_public_contract's Receipt; signature_bytes[i] = the 64-byte s || e of aztec.js/barretenberg SchnorrSignature, each 32 bytes big-endian",
            "nodes": nodes,
            "vectors": vectors,
        })
    }

    /// The committed vectors are what this code computes, and every
    /// signature verifies under its node's key.
    #[test]
    fn receipt_vectors_match() {
        let text = std::fs::read_to_string(repo().join(VECTORS)).unwrap();
        let committed: Value = serde_json::from_str(&text).unwrap();
        let sigs = sig_scalars();
        for v in committed["vectors"].as_array().unwrap() {
            let f = |k: &str| hex(v[k].as_str().unwrap());
            let id = f("request_id");
            let ih = f("inputs_hash");
            let expiry = u32::try_from(v["expiry_block"].as_u64().unwrap()).unwrap();
            for (i, s) in v["signatures"].as_array().unwrap().iter().enumerate() {
                let s: Signature = serde_json::from_value(s.clone()).unwrap();
                assert!(verify_receipt(public_key(sigs[i]), s, id, ih, expiry));
            }
        }
        assert_eq!(committed, vectors(), "rerun write_receipt_vectors");
    }

    // ---- secret-shared receipt intake ----

    // Node 0's receipt request on shared_receipt_round: the clear input, C and
    // node 0's envelope of every shared value (testvectors/shared_intake.json).
    fn shared_body() -> Value {
        shared_intake()["receipt_body_node0"].clone()
    }

    /// The vector's client body, with node 0's expiry.
    fn shared_client() -> ReceiptRequest<Full> {
        let mut client = shared_receipt_client();
        client["expiry_block"] = shared_body()["expiry_block"].clone();
        parse_json(&client.to_string()).unwrap()
    }

    /// The walk takes the INPUT_SHARED values into the inputs commitment in
    /// ABI order, `$blinding` left out; the clear inputs are the rest.
    #[test]
    fn the_shared_walk_orders_the_commitment_and_the_shares() {
        let pkg = crate::testing::shared_package();
        let package = TipPackage::from_row(&pkg, Some(50)).unwrap().unwrap();
        assert_eq!(
            commitment_names(&package.shape, &package.tip),
            [
                "amount",
                "position",
                "$partial_note",
                "$outcome_key",
                "$outcome_tag"
            ]
        );
        assert_eq!(
            shared_names(&package.shape, &package.tip),
            [
                "amount",
                "$partial_note",
                "$outcome_key",
                "$blinding",
                "$outcome_tag"
            ]
        );
        let clear = BTreeMap::from([("position".to_string(), PublicValue::One(FieldHex::from(7)))]);
        assert_eq!(
            intake_inputs(&package.shape, &package.tip, &clear).unwrap(),
            [Fr::from(7u64)]
        );
        assert_eq!(
            public_inputs(&package.shape, &package.tip, &[Fr::from(7u64)]).unwrap(),
            clear
        );
        // the non-secret-shared intakes' commitment names are their clear
        // inputs, the partial note under its parameter's name
        let plain = receipt_package();
        let plain = TipPackage::from_row(&plain, Some(50)).unwrap().unwrap();
        assert_eq!(
            commitment_names(&plain.shape, &plain.tip),
            ["amount_in", "direction", "min_out", "partial_note"]
        );
        assert!(shared_names(&plain.shape, &plain.tip).is_empty());
    }

    /// Under `outcome: partial` a non-secret-shared round's PUBLIC
    /// `$partial_note` is a clear app input keyed by its parameter's name: it
    /// is hashed with the request public names in ABI order and fills its
    /// parameter from the public map.
    #[test]
    fn a_clear_partial_note_is_an_app_input_under_its_parameter() {
        let pkg = receipt_package();
        let package = TipPackage::from_row(&pkg, Some(50)).unwrap().unwrap();
        let p = Fr::from(0x9au64);
        let public = public_inputs(
            &package.shape,
            &package.tip,
            &[Fr::from(5000u64), Fr::from(1u64), Fr::from(4000u64), p],
        )
        .unwrap();
        assert_eq!(
            public.get("partial_note"),
            Some(&PublicValue::One(FieldHex(p)))
        );
        assert_eq!(
            intake_inputs(&package.shape, &package.tip, &public).unwrap(),
            [Fr::from(5000u64), Fr::from(1u64), Fr::from(4000u64), p]
        );
    }

    /// A secret-shared receipt request signs C: the id commits to the namespace, the
    /// registered vk hash and C alone, and the row keeps node 0's envelopes
    /// and no requester.
    #[test]
    fn a_shared_receipt_request_is_checked_over_its_commitment() {
        let pkg = crate::testing::shared_package();
        let body = shared_body();
        let req = ReceiptRequest::from_json(&body.to_string()).unwrap();
        let checked = check_receipt_request(&pkg, Some(50), &req).unwrap();
        let c = req.inputs_hash.unwrap().fr();
        assert_eq!(checked.inputs_hash, c);
        assert_eq!(
            checked.request_id,
            crate::shared_chain_request_id(req.namespace.fr(), pkg.vk_hash, c)
        );
        assert_eq!(checked.inputs, [Fr::from(7u64)]);
        assert_eq!(checked.user_nonce, None);
        // the circuit's shared inputs are kept; the salts' envelope is checked
        // and dropped
        assert_eq!(checked.shares, req.shared_inputs[..5]);
        let sharing = sharing_of(&checked).unwrap();
        assert_eq!((sharing.salt_at, &sharing.salt), (5, &req.shared_inputs[5]));
        assert_eq!(sharing.salt.name, SUMMAND_SALT);
        assert_eq!(
            sharing.order,
            [
                "amount",
                "$partial_note",
                "$outcome_key",
                "$outcome_tag",
                "$blinding"
            ]
        );
        let d = req.sharing_digest.unwrap().fr();
        assert_eq!(sharing.digest, d);
        // D covers the summand commitments, the layout and the clear inputs
        let package = TipPackage::from_row(&pkg, Some(50)).unwrap().unwrap();
        let layout = commitment_layout(&package.shape, &package.tip);
        assert_eq!(
            d,
            crate::sharing_digest(&sharing.commitments, &layout.value_kinds(), &checked.inputs)
        );
        // the receipt signs C and D
        assert_eq!(
            checked.message(1300),
            crate::shared_receipt_message(checked.request_id, c, 1300, d)
        );
        assert_ne!(
            checked.message(1300),
            receipt_message(checked.request_id, c, 1300)
        );
        let row =
            checked
                .clone()
                .into_row("shared_receipt_round".into(), 1300, Signature::default());
        assert_eq!(row.user_nonce, None);
        assert_eq!(row.shares.len(), 5);
        let stored = StoredReceipt::new(req.namespace.fr(), &row);
        assert_eq!(stored.shared_inputs, req.shared_inputs[..5]);
        assert!(stored.user_nonce.is_none());

        type Edit = fn(&mut Value);
        let cases: Vec<(Edit, &str)> = vec![
            (
                |v| v["user_nonce"] = json!("0x01"),
                "field `user_nonce`: secret-shared receipt intake takes none",
            ),
            (
                |v| {
                    v.as_object_mut().unwrap().remove("inputs_hash");
                },
                "field `inputs_hash`: missing; secret-shared receipt intake signs the inputs commitment C",
            ),
            (
                |v| {
                    v["shared_inputs"].as_array_mut().unwrap().remove(1);
                },
                "field `shared_inputs`: missing `$partial_note`",
            ),
            (
                |v| v["shared_inputs"][1]["name"] = json!("amount"),
                "field `shared_inputs[1].name`: `amount` is duplicated",
            ),
            (
                |v| v["shared_inputs"][1]["name"] = json!("position"),
                "field `shared_inputs[1].name`: `position` is not a shared input of circuit `shared_receipt_round`",
            ),
            (
                |v| {
                    v["shared_inputs"].as_array_mut().unwrap().pop();
                },
                "field `shared_inputs`: missing `$summand_salt`",
            ),
            (
                |v| v["shared_inputs"][1]["name"] = json!("$summand_salt"),
                "field `shared_inputs[5].name`: `$summand_salt` is not a shared input",
            ),
            (
                |v| {
                    v.as_object_mut().unwrap().remove("summand_commitments");
                },
                "field `summand_commitments`: missing",
            ),
            (
                |v| {
                    v.as_object_mut().unwrap().remove("sharing_digest");
                },
                "field `sharing_digest`: missing",
            ),
            (
                |v| v["sharing_digest"] = json!("0x01"),
                "field `sharing_digest`: not poseidon2([SHARING_DOMAIN, S_0, S_1, S_2, kinds..., \
                 clear values...])",
            ),
            (
                |v| v["summand_commitments"][2] = json!("0x01"),
                "field `sharing_digest`: not poseidon2([SHARING_DOMAIN, S_0, S_1, S_2, kinds..., \
                 clear values...])",
            ),
            // a clear input other than the one D covers (C's): refused before
            // anything is stored, so a request whose clear inputs do not open
            // C gets no receipt over C's D
            (
                |v| v["inputs"]["position"] = json!("0x08"),
                "field `sharing_digest`: not poseidon2([SHARING_DOMAIN, S_0, S_1, S_2, kinds..., \
                 clear values...]) of `summand_commitments`, the circuit's layout and the clear \
                 `inputs`",
            ),
            (|v| v["inputs"]["amount"] = json!("0x01"), "inputs.amount"),
            (
                |v| v["inputs"]["position"] = json!("0x100000000"),
                "position",
            ),
        ];
        for (edit, needle) in cases {
            let mut v = shared_body();
            edit(&mut v);
            let req = ReceiptRequest::from_json(&v.to_string()).unwrap();
            refused(
                check_receipt_request(&pkg, Some(50), &req),
                ErrorClass::BadRequest,
                needle,
            );
        }
        // receipt intake refuses the shared fields
        let plain = receipt_package();
        let mut v = route_body();
        v["inputs_hash"] = json!("0x01");
        let req = ReceiptRequest::from_json(&v.to_string()).unwrap();
        refused(
            check_receipt_request(&plain, Some(50), &req),
            ErrorClass::BadRequest,
            "field `inputs_hash`: receipt intake takes none",
        );
        let mut v = route_body();
        v["shared_inputs"] = shared_body()["shared_inputs"].clone();
        let req = ReceiptRequest::from_json(&v.to_string()).unwrap();
        refused(
            check_receipt_request(&plain, Some(50), &req),
            ErrorClass::BadRequest,
            "field `shared_inputs`: receipt intake takes none",
        );
        for field in ["summand_commitments", "sharing_digest"] {
            let mut v = route_body();
            v[field] = shared_body()[field].clone();
            let req = ReceiptRequest::from_json(&v.to_string()).unwrap();
            refused(
                check_receipt_request(&plain, Some(50), &req),
                ErrorClass::BadRequest,
                &format!("field `{field}`: receipt intake takes none"),
            );
        }
        let checked = check_receipt_request(
            &plain,
            Some(50),
            &ReceiptRequest::from_json(&route_body().to_string()).unwrap(),
        )
        .unwrap();
        assert!(sharing_of(&checked).is_none());
        assert_eq!(
            checked.message(1300),
            receipt_message(checked.request_id, checked.inputs_hash, 1300)
        );
        let mut v = route_body();
        v.as_object_mut().unwrap().remove("user_nonce");
        let req = ReceiptRequest::from_json(&v.to_string()).unwrap();
        refused(
            check_receipt_request(&plain, Some(50), &req),
            ErrorClass::BadRequest,
            "field `user_nonce`: missing",
        );
    }

    /// The client's body projects to the vector's node 0 body; each node's
    /// envelopes pass its own check under keys.json's keys (its pairs and
    /// salts hash to its two summand commitments) and fail another node's;
    /// a wrong share hash is named.
    #[test]
    fn a_shared_body_projects_per_node_and_each_node_opens_its_own() {
        let client = shared_client();
        client.check_share_hashes().unwrap();
        assert_eq!(
            serde_json::to_value(client.project(0)).unwrap(),
            shared_body()
        );
        let pkg = crate::testing::shared_package();
        for i in 0..NODES {
            let req = client.project(i);
            let checked = check_receipt_request(&pkg, Some(50), &req).unwrap();
            let ns = req.namespace.fr();
            checked
                .check_own_envelopes(&node_keys()[i], i, ns, &req.circuit)
                .unwrap();
            let other = (i + 1) % NODES;
            let err = checked
                .check_own_envelopes(&node_keys()[other], other, ns, &req.circuit)
                .unwrap_err();
            assert!(err.message.contains("does not hash"), "{err}");
        }
        let mut wrong = client.clone();
        wrong.shared_inputs[3].share_hashes[1] = FieldHex::from(1);
        let err = wrong.check_share_hashes().unwrap_err();
        assert_eq!(err.class, ErrorClass::BadRequest);
        assert!(
            err.message.contains(
                "field `shared_inputs[3]` (`$blinding`): the envelope to node 1 does not hash"
            ),
            "{err}"
        );
        // a node names the salts' envelope at its index in the body, wherever
        // the client put it
        let salt = SUMMAND_SALT;
        for at in [5, 0] {
            let mut req = client.project(1);
            let moved = req.shared_inputs.remove(5);
            req.shared_inputs.insert(at, moved);
            req.shared_inputs[at].share_hashes[1] = FieldHex::from(1);
            let checked = check_receipt_request(&pkg, Some(50), &req).unwrap();
            let err = checked
                .check_own_envelopes(&node_keys()[1], 1, req.namespace.fr(), &req.circuit)
                .unwrap_err();
            assert!(
                err.message.contains(&format!(
                    "field `shared_inputs[{at}]` (`{salt}`): the envelope to node 1 does not hash"
                )),
                "{err}"
            );
        }
    }

    /// Each summand commitment `S_j` is checked by both nodes that hold
    /// `s_j` (nodes j and j+1), each alone: a request whose `S_j` does not
    /// match the vector its envelopes seal (with `D` recomputed so the
    /// orchestrator's check passes) is refused by exactly those two nodes,
    /// and the third, which does not hold `s_j`, signs. So no pair of
    /// neighbours can disagree on a summand and still give three receipts
    /// over one `D`.
    #[test]
    fn each_summand_commitment_is_checked_by_both_its_holders() {
        let pkg = crate::testing::shared_package();
        let package = TipPackage::from_row(&pkg, Some(50)).unwrap().unwrap();
        let kinds = commitment_layout(&package.shape, &package.tip).value_kinds();
        for j in 0..NODES {
            let mut client = shared_client();
            let clear = intake_inputs(&package.shape, &package.tip, &client.inputs).unwrap();
            let mut commitments = client.summand_commitments.unwrap().map(|f| f.fr());
            commitments[j] += Fr::from(1u64);
            client.summand_commitments = Some(commitments.map(FieldHex));
            client.sharing_digest = Some(FieldHex(crate::sharing_digest(
                &commitments,
                &kinds,
                &clear,
            )));
            for i in 0..NODES {
                let req = client.project(i);
                let checked = check_receipt_request(&pkg, Some(50), &req).unwrap();
                let got = checked.check_own_envelopes(
                    &node_keys()[i],
                    i,
                    req.namespace.fr(),
                    &req.circuit,
                );
                let holds = i == j || i == (j + 1) % NODES;
                if holds {
                    let err = got.unwrap_err();
                    assert_eq!(err.class, ErrorClass::BadRequest);
                    assert!(
                        err.message
                            .contains(&format!("field `summand_commitments[{j}]`")),
                        "{err}"
                    );
                } else {
                    got.unwrap();
                }
            }
        }
    }

    /// A sharing the nodes do not hold alike gets no third receipt: the
    /// client reseals node 0's envelope of `amount` over `[x_0 + 1, x_2]`
    /// (a pair that is not the sharing the commitments are over), so node 0
    /// refuses (its `s_0` misses `S_0`), node 1, whose envelopes are
    /// unchanged, signs, and so does node 2.
    #[test]
    fn a_node_refuses_a_pair_that_misses_its_summand_commitment() {
        use sidecar_core::envelope::{open_envelope, seal_envelope_with};
        let pkg = crate::testing::shared_package();
        let mut client = shared_client();
        let req = client.project(0);
        let ns = req.namespace.fr();
        let checked = check_receipt_request(&pkg, Some(50), &req).unwrap();
        let ad = EnvelopeAd::for_intake(ns, checked.request_id, &req.circuit, "amount");
        let keys = node_keys()[0].clone();
        let [x0, x2] = open_envelope(&keys, 0, &ad, &client.shared_inputs[0].shares[0]).unwrap();
        let resealed = seal_envelope_with(
            keys.enc_pk(),
            0,
            &ad,
            [x0 + Fr::from(1u64), x2],
            Fr::from(0x5eedu64),
        );
        client.shared_inputs[0].shares[0] = resealed;
        client.shared_inputs[0].share_hashes[0] = FieldHex(resealed.hash());
        client.check_share_hashes().unwrap();
        for i in 0..NODES {
            let req = client.project(i);
            let checked = check_receipt_request(&pkg, Some(50), &req).unwrap();
            let got = checked.check_own_envelopes(&node_keys()[i], i, ns, &req.circuit);
            if i == 0 {
                let err = got.unwrap_err();
                assert_eq!(err.class, ErrorClass::BadRequest);
                assert!(
                    err.message.contains("field `summand_commitments[0]`"),
                    "{err}"
                );
            } else {
                got.unwrap();
            }
        }
    }

    /// `cargo test -p sidecar-tip write_receipt_vectors -- --ignored`.
    #[test]
    #[ignore = "writes testvectors/; run on purpose"]
    fn write_receipt_vectors() {
        let text = serde_json::to_string_pretty(&vectors()).unwrap() + "\n";
        std::fs::write(repo().join(VECTORS), text).unwrap();
        let text = serde_json::to_string_pretty(&route_vectors()).unwrap() + "\n";
        std::fs::write(repo().join(ROUTE_VECTORS), text).unwrap();
    }
}
