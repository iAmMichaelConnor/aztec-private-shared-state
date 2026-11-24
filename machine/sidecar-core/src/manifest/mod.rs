//! The manifest: the JSON registered beside a compiled circuit that names the source
//! of every witness parameter, where each TACEO_store output goes, the state mode of
//! every key, how a request reaches the network, and what the round consumes
//! (ARCHITECTURE.md section 7, `docs/manifest.schema.json`).
//!
//! One schema serves both paths. `intake` selects the path: `direct` (the
//! default) is the sidecar path, every other intake queues the request at the
//! tip. The fields of the other path are refused, as are the state modes it
//! does not allow; everything else is shared. `manifest` is the schema version.
//!
//! The checks here need only the manifest. The checks against the circuit's ABI
//! (every parameter once, in order, with matching widths; the namespace parameter
//! is a public Field; only PUBLIC fills a public parameter; a commitment slot
//! names a public output, a public read a public parameter, a partial note
//! is returned right after `ok`) run at REGISTER, as do the refusals of the
//! options not yet built ([`crate::registry::refuse_deferred_options`]) and of
//! an `outcome` the intake does not take ([`crate::registry::check_outcome`]).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::de;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::error::{Refusal, parse_value, unique_map};

pub mod contract;
mod intake;
mod keyref;
mod reads;
mod source;
mod tree;
mod validate;

pub use intake::*;
pub use keyref::*;
pub use reads::*;
pub use source::*;
pub use tree::*;
use validate::reserved_uses;

/// The `manifest` field: the schema version, always the integer 1.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SchemaVersion;

impl Serialize for SchemaVersion {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u64(1)
    }
}

impl<'de> Deserialize<'de> for SchemaVersion {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        match u64::deserialize(deserializer)? {
            1 => Ok(SchemaVersion),
            n => Err(de::Error::custom(format!(
                "manifest schema version {n} is not supported; this machine reads version 1"
            ))),
        }
    }
}

// The manifest refuses every field it does not define, at every
// level (top level, state_keys, witness entries, sources, outputs, consume entries,
// commitment slots, public reads), and every field of the path its intake does
// not select. A typo such as `"polcy"` or a tip field on a sidecar manifest is
// an error at REGISTER, never silently ignored, because an ignored security
// field (a consume policy, a state mode) would register a circuit that behaves
// differently from what its author wrote. New fields extend the one schema.
/// A parsed and checked manifest. Construct it with [`Manifest::parse`], which
/// also runs [`Manifest::validate`]. The fields
/// of one path are `None` (or empty) under the other; the accessors
/// ([`Manifest::binding`], [`Manifest::state_mode`])
/// apply the defaults.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub manifest: SchemaVersion,
    /// The registered circuit name.
    pub circuit: String,
    /// The public Field parameter filled by PUBLIC `$namespace`; VERIFY checks it.
    pub namespace_param: String,
    /// How many state keys a request supplies.
    pub state_keys: KeyCounts,
    // DEV DECISION: the intake, default `direct` when the manifest names none
    // (the examples use `shared_receipt`); it selects the path and what the
    // chain and the nodes see of the inputs, and picks which intake function
    // the contract library generates, so changing it changes the contract.
    // Design guide: "intake".
    // `direct` is the sidecar path: the client sends POST /v1/execute and the
    // user's own private function lands the result. Every other intake queues
    // the request at the tip. `onchain` (on-chain intake): the intake
    // transaction logs the inputs in the clear and the scheduler reads them from the
    // request log; nothing is hidden from the chain. `receipt` (receipt
    // intake): the user first gets three node receipts over the inputs (sent
    // to the nodes in the clear over TLS), and the intake function verifies
    // them in-circuit, so the inputs never appear on chain. Neither takes an
    // INPUT_SHARED source.
    // `shared_receipt` (secret-shared receipt intake, the examples' default): each
    // node receives one Rep3 pair of every INPUT_SHARED value in an envelope
    // and signs a receipt over the hiding commitment `C` of the inputs, so no
    // party but the user holds an input. `shared_onchain` (secret-shared on-chain
    // intake): the user's private function logs the shares in an encoded
    // form only the nodes open, and stores its hash beside the queue entry.
    /// How a request reaches the network; `direct` when left out.
    #[serde(default)]
    pub intake: Intake,
    /// One entry per ABI parameter, in declaration order.
    pub witness: Vec<WitnessEntry>,
    pub outputs: Vec<Output>,
    // DEV DECISION: the state mode of each key, default `node`; `client` needs
    // no state database but makes its users responsible for not losing
    // records, and `chain` is bounded by the transaction's public-log
    // capacity. Design guide: "state mode".
    // `node`: one row per key in each node's store (at the tip, one version
    // per attempt); right for shared state many users transition (an AMM
    // pool), and the default under every intake. `client` (intake direct
    // only): the nodes seal each new value into a state record the user
    // carries and presents on the next round; right for single-owner state (a
    // player's game), and cannot diverge from the chain (the user keeps the
    // old record if the tx never lands); a queued round has no owner to sign
    // for it. `chain` (queued intakes only): a record the nodes seal to their
    // own `enc` keys (owner `enc_pk_i`), logged by `apply` and handed back to
    // the next round by the scheduler, bounded by the transaction's
    // public-log capacity (sidecar-tip `state::chain::sealed_thirds_fields`).
    /// The state mode of the keys the manifest loads or stores (not `nsk_app`);
    /// a key not listed is `node`.
    #[serde(default, deserialize_with = "unique_map")]
    pub state: BTreeMap<KeyRef, StateMode>,
    // DEV DECISION: what a direct round consumes, and under which policy,
    // default `once` for every consumed key; `never` allows unlimited
    // evaluations, so it is safe only when the outputs reveal nothing that
    // depends on the state. Design guide: "consume policy".
    // `once` (client-held or node-held): the loaded state may be transitioned
    // once, ever; any second request on it is 409 whatever its circuit or
    // inputs, and a retry of the same round uses FETCH. `never` (client-held
    // keys only): untracked. The rule for choosing: whoever holds a state gets
    // one evaluation of the round's public outputs, with inputs of their
    // choice, so ask what one evaluation reveals. This machine also requires
    // every loaded client-held key to be listed here (use `never` to opt out
    // explicitly), so a forgotten entry cannot silently allow replay. A
    // queued round lists nothing: its slot write is the spend.
    /// Intake direct only: the keys whose loaded value this round spends.
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub consume: Option<Vec<Consume>>,
    // DEV DECISION: `binding` (queued intakes only), default `turn`: a queued
    // request runs against the state current when it reaches the head, so
    // requests never fail for being behind one another and the scheduler can
    // pipeline them, but the user cannot bind a request to the state they saw
    // (an AMM swap protects itself with a minimum output instead). Design
    // guide: "binding". `exact`, which runs a request only against the state
    // it names and fails it otherwise, is deferred and refused at REGISTER.
    /// Queued intakes only: which state a request runs against.
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub binding: Option<Binding>,
    /// Queued intakes only: per loaded key (node-held or chain-held), the
    /// public output carrying its old commitment.
    #[serde(
        default,
        deserialize_with = "present_map",
        skip_serializing_if = "Option::is_none"
    )]
    pub commitment_slot: Option<BTreeMap<KeyRef, CommitmentSlot>>,
    // DEV DECISION: `public_reads`, the public calls whose results a round
    // takes as public inputs (an oracle price), default none; each read adds
    // a public call to `apply` and a value the result must still match under
    // the read's freshness policy. Design guide: "pinned-read freshness".
    // The scheduler simulates each call and fills `param`, a public parameter
    // the witness fills with PUBLIC by a request public name (and, for an
    // epoch read, `epoch_param` with the value's epoch); each node's chain
    // verifier repeats the call and refuses a request whose value its
    // freshness policy does not admit (step 4); `apply` makes the call again
    // before its writes and fails on a value the policy does not admit
    // (`Freshness`), so a stale price never lands. The contract, function and
    // arguments are constants of the manifest, so a request cannot choose
    // what is read. Under intake direct REGISTER refuses a read: no scheduler
    // fills it.
    /// The pinned public calls whose returned values fill public parameters.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub public_reads: Vec<PublicRead>,
    /// Queued intakes only: the layout of each tree-valued node-held key,
    /// declared once: under the key reference that loads it (naming in
    /// `store` the reference it is stored back at), or under the one that
    /// stores it when the round creates the tree.
    #[serde(
        default,
        deserialize_with = "present_map",
        skip_serializing_if = "Option::is_none"
    )]
    pub tree: Option<BTreeMap<KeyRef, TreeLayout>>,
    /// Queued intakes only (REGISTER): how the round's value reaches the
    /// user (the design guide's value delivery axis). `partial` (the
    /// default): the request commits a partial note (`$partial_note`) that
    /// the round completes, inside the co-SNARK for a private result or in
    /// the app's `apply` for a public one. `none` (non-secret-shared intakes
    /// only, written out): the round completes no note and its public
    /// outputs go to the app's hook.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<Outcome>,
}

/// A field given in the JSON, even as `null`: `Some` of its value.
fn present<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

/// As [`present`], for a map read with [`unique_map`].
fn present_map<'de, D, K, V>(deserializer: D) -> Result<Option<BTreeMap<K, V>>, D::Error>
where
    D: Deserializer<'de>,
    K: Deserialize<'de> + Ord + fmt::Display,
    V: Deserialize<'de>,
{
    unique_map(deserializer).map(Some)
}

/// `state_keys`: how many state keys a request supplies in `state_keys.reads` and `state_keys.writes`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyCounts {
    pub reads: usize,
    pub writes: usize,
}

/// `{"param": ..., "from": ...}`: the source of one ABI parameter.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessEntry {
    pub param: String,
    pub from: Source,
}

/// A TACEO_store output and the key it is stored under.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Output {
    /// The name the circuit passes to `TACEO_store`.
    #[serde(rename = "TACEO_store")]
    pub taceo_store: String,
    /// The key the vector is stored under.
    #[serde(rename = "STORE")]
    pub store: KeyRef,
    /// The stored vector's length.
    pub len: usize,
    /// The public output that commits to the stored vector, e.g. `new_note_hashes[0]`.
    pub note_hash: String,
}

/// `{"key": ..., "policy": ...}`: a consumed key; the policy defaults to `once`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Consume {
    pub key: KeyRef,
    /// The policy, when given (`null` is refused, as the schema does).
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub policy: Option<Policy>,
}

impl Consume {
    /// The effective policy: the entry's own, or `once`.
    pub fn policy(&self) -> Policy {
        self.policy.unwrap_or_default()
    }
}

/// Where a key's value lives between rounds.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StateMode {
    /// Sealed state records the user carries (intake direct only).
    Client,
    /// One row per key at each node (the default).
    #[default]
    Node,
    /// A record the nodes seal to their own `enc` keys (owner `enc_pk_i`),
    /// carried by the chain (queued intakes only).
    Chain,
}

impl StateMode {
    pub fn as_str(self) -> &'static str {
        match self {
            StateMode::Client => "client",
            StateMode::Node => "node",
            StateMode::Chain => "chain",
        }
    }

    /// The path rule of the mode: whether a manifest whose intake is queued
    /// (`queued`) or direct may give a key this mode.
    pub fn allowed(self, queued: bool) -> bool {
        match self {
            StateMode::Node => true,
            StateMode::Client => !queued,
            StateMode::Chain => queued,
        }
    }
}

/// A CONSUME policy: `once` or `never` (DECISIONS.md, "CONSUME is `once` or
/// `never`").
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Policy {
    /// The state may be transitioned once; any second request on it is 409
    /// (the default).
    #[default]
    Once,
    /// Untracked: the round adds nothing to the consumed set.
    Never,
}

impl Policy {
    /// The wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            Policy::Once => "once",
            Policy::Never => "never",
        }
    }

    /// Whether the policy applies to keys of this mode. `never` is a client-held
    /// policy; a node-held key is consumed `once` or not listed at all.
    pub fn allowed_for(self, mode: StateMode) -> bool {
        matches!((self, mode), (Policy::Once, _) | (_, StateMode::Client))
    }
}

impl Manifest {
    /// Parse and check a manifest from JSON (for instance the `manifest` field of
    /// a REGISTER body). Every refusal is `bad_request` and names the field.
    pub fn parse(value: &serde_json::Value) -> Result<Self, Refusal> {
        let object = value
            .as_object()
            .ok_or_else(|| Refusal::bad_request("manifest: not a JSON object"))?;
        if !object.contains_key("manifest") {
            return Err(Refusal::bad_request(
                "field `manifest`: missing (the schema version, 1)",
            ));
        }
        let manifest: Manifest = parse_value(value)?;
        manifest.validate()?;
        Ok(manifest)
    }

    /// Whether the intake queues the request at the tip (every intake but
    /// `direct`).
    pub fn queued(&self) -> bool {
        self.queued_intake().is_some()
    }

    /// The queued intake, or `None` under intake direct (the sidecar path).
    pub fn queued_intake(&self) -> Option<QueuedIntake> {
        self.intake.queued()
    }

    /// The state mode of a key the manifest loads or stores: its `state`
    /// entry, or `node`. `None` for a key it does not use and for the fixed
    /// keys.
    pub fn state_mode(&self, key: KeyRef) -> Option<StateMode> {
        if let Some(mode) = self.state.get(&key) {
            return Some(*mode);
        }
        self.uses(key).then_some(StateMode::Node)
    }

    /// Every key the manifest loads or stores (not a fixed key), in key
    /// reference order, with its state mode.
    pub fn state_modes(&self) -> impl Iterator<Item = (KeyRef, StateMode)> + '_ {
        self.used_keys()
            .into_iter()
            .map(|key| (key, self.state_mode(key).unwrap_or_default()))
    }

    /// The consume entries (none under a queued intake).
    pub fn consume(&self) -> &[Consume] {
        self.consume.as_deref().unwrap_or_default()
    }

    /// Every consumed key with its effective policy, in manifest order.
    pub fn consume_policies(&self) -> Vec<(KeyRef, Policy)> {
        self.consume().iter().map(|c| (c.key, c.policy())).collect()
    }

    /// Which state a queued request runs against: `binding`, or `turn`.
    pub fn binding(&self) -> Binding {
        self.binding.unwrap_or_default()
    }

    /// How the round's value reaches the user: `outcome`, or the intake's
    /// default ([`crate::intake::IntakeRules::default_outcome`]).
    pub fn outcome(&self) -> Outcome {
        self.outcome
            .unwrap_or_else(|| self.intake.rules().default_outcome())
    }

    /// The commitment slots, in key reference order (none under intake direct).
    pub fn commitment_slots(&self) -> impl Iterator<Item = (&KeyRef, &CommitmentSlot)> {
        self.commitment_slot.iter().flatten()
    }

    /// The layout of a tree-valued key reference, or `None` for a flat one:
    /// its own entry, or for a reference a loaded tree is stored back at,
    /// the loaded entry whose `store` names it.
    pub fn tree_of(&self, key: KeyRef) -> Option<&TreeLayout> {
        let trees = self.tree.as_ref()?;
        trees
            .get(&key)
            .or_else(|| trees.values().find(|t| t.store == Some(key)))
    }

    /// The key reference whose holder serves `key`: a reference a loaded
    /// tree is stored back at names the loaded reference's key, so it is
    /// served by the loaded reference's holder; every other reference is
    /// its own.
    pub fn holder_ref(&self, key: KeyRef) -> KeyRef {
        self.trees()
            .find(|(_, t)| t.store == Some(key))
            .map_or(key, |(loaded, _)| *loaded)
    }

    /// How the manifest holds a key it loads or stores: its state mode and,
    /// for a tree-valued key, its tree's shape. `None` for a key it does not
    /// use and for the fixed keys.
    pub fn key_layout(&self, key: KeyRef) -> Option<KeyLayout> {
        Some(KeyLayout {
            mode: self.state_mode(key)?,
            tree: self.tree_of(key).map(TreeLayout::shape),
        })
    }

    /// The declared tree layouts, one per tree, in key reference order (none
    /// for a manifest without tree-valued keys).
    pub fn trees(&self) -> impl Iterator<Item = (&KeyRef, &TreeLayout)> {
        self.tree.iter().flatten()
    }

    /// The parameters the scheduler fills from the nodes' clear trees (every
    /// loaded tree's `old_hashes`, `siblings` and `indices`, and a window's
    /// `old_hashes` and `siblings`): not app inputs.
    pub fn tree_params(&self) -> impl Iterator<Item = &str> {
        let slots = self
            .trees()
            .filter_map(|(_, t)| t.params.as_ref())
            .flat_map(|p| {
                [
                    Some(p.old_hashes.as_str()),
                    Some(p.siblings.as_str()),
                    p.indices.as_deref(),
                ]
            })
            .flatten();
        let windows = self
            .trees()
            .filter_map(|(_, t)| t.window.as_ref())
            .flat_map(|w| [w.params.old_hashes.as_str(), w.params.siblings.as_str()]);
        slots.chain(windows)
    }

    /// The LOAD sources, with their parameter names, in witness order.
    pub fn loads(&self) -> impl Iterator<Item = (&str, &Load)> {
        self.witness.iter().filter_map(|w| match &w.from {
            Source::Load(l) => Some((w.param.as_str(), l)),
            _ => None,
        })
    }

    /// Whether the witness loads or the outputs store `key` (not a fixed key).
    fn uses(&self, key: KeyRef) -> bool {
        !key.is_fixed()
            && (self.loads().any(|(_, l)| l.key == key)
                || self.outputs.iter().any(|o| o.store == key))
    }

    /// Every key loaded or stored, other than the fixed keys.
    fn used_keys(&self) -> BTreeSet<KeyRef> {
        self.loads()
            .map(|(_, l)| l.key)
            .chain(self.outputs.iter().map(|o| o.store))
            .filter(|k| !k.is_fixed())
            .collect()
    }

    /// The parameters filled by a reserved operand (`$vk_hash`,
    /// `$user_nonce`, `$new_leaf`, `$inputs_hash`), in witness order: the scheduler's synthesis puts each
    /// value in the request's `public` map under the parameter's name.
    pub fn reserved(&self) -> impl Iterator<Item = (&str, ReservedOperand)> {
        reserved_uses(&self.witness).map(|(_, w, r, _)| (w.param.as_str(), r))
    }

    /// The parameter `$new_leaf` fills, if any (a tree that opens leaves).
    pub fn new_leaf_param(&self) -> Option<&str> {
        self.reserved()
            .find(|(_, r)| *r == ReservedOperand::NewLeaf)
            .map(|(param, _)| param)
    }

    /// The witness entry of a parameter.
    pub fn witness_entry(&self, param: &str) -> Option<(usize, &WitnessEntry)> {
        self.witness
            .iter()
            .enumerate()
            .find(|(_, w)| w.param == param)
    }
}

/// Which state a queued request runs against.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Binding {
    /// The state current when the request reaches the head of the queue.
    #[default]
    Turn,
    /// The state the user saw when submitting (deferred; refused at REGISTER).
    Exact,
}

impl Binding {
    pub fn as_str(self) -> &'static str {
        match self {
            Binding::Turn => "turn",
            Binding::Exact => "exact",
        }
    }
}

/// How a round's value reaches the user (the value delivery axis).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// The request commits a partial note (`$partial_note`) that the round
    /// completes: inside the co-SNARK for a private result, in the app's
    /// `apply` for a public one (the default under every queued intake).
    Partial,
    /// No library delivery: the round completes no note and its public
    /// outputs go to the app's hook (non-secret-shared intakes only).
    None,
}

impl Outcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Outcome::Partial => "partial",
            Outcome::None => "none",
        }
    }
}

/// `{"old": <public output>}`: the public output that carries the commitment
/// of the key's state the circuit read. The new commitment is the
/// `outputs[].note_hash` of the output stored under the key's slot.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommitmentSlot {
    pub old: String,
}

#[cfg(test)]
pub(crate) mod tests;
