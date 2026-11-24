//! The request synthesiser (docs/ARCHITECTURE.md section 6, "The scheduler"):
//! one queued request turned into the ordinary `Request<Full>` the
//! orchestrator fans out, built only from what the chain and the nodes hold.
//! The scheduler calls it for the head and for each pipelined request; each
//! node's chain verifier can call it again with its own view and compare,
//! because the same inputs give the same request byte for byte.
//!
//! ```text
//! public            the clear app inputs (as the package's intake found
//!                   them, crate::intake) by name, each reserved operand's
//!                   value under the name of the parameter it fills
//!                   ($vk_hash the package's, $new_leaf the nodes',
//!                   $user_nonce and $inputs_hash the intake's), the nodes'
//!                   values of a tree key, and each pinned read's value
//!                   under its parameter's name
//! shared_inputs,    what the intake's found inputs carry besides
//! shared_log        (FoundInputs::fill: the envelopes under secret-shared
//!                   receipt intake, the request log under secret-shared
//!                   on-chain intake, nothing under the non-secret-shared
//!                   intakes)
//! state_keys        the app's request keys for the circuit (key = storage slot)
//! records           what the state of each key the circuit loads carries
//!                   (crate::state::KeyState), one per key
//! chain_request_id  the queue entry's
//! request_id        machine_request_id(chain_request_id, the keys' old
//!                   commitments in commitment_slot order, the pinned values
//!                   in public_reads order)
//! ```
//!
//! No requester: the state of a queued round has no owner to sign for it.

use std::collections::BTreeMap;

use sidecar_core::abi::CircuitShape;
use sidecar_core::error::Refusal;
use sidecar_core::field::{FieldHex, Fr, RequestId, fr_to_hex};
use sidecar_core::manifest::{PublicOperand, PublicRead, PublicSource, ReservedOperand, Source};
use sidecar_core::pipeline::ChainRound;
use sidecar_core::request::{Full, PublicValue, Request, StateKeys, StateRecord};
use sidecar_core::store::{PackageRow, StoreRead};

use crate::chain::{PinnedValue, PinnedValues, QueueEntry};
use crate::intake::route::public_inputs;
use crate::intake::{FoundInputs, IntakeSource, intake_source};
use crate::state::tree::PublicMap;
use crate::state::{KeyState, KeyTipStates, request_key, tip_states};
use crate::{TipManifest, check_request_ids, machine_request_id};

/// The stale period of `namespace`, from the contract manifest `store`
/// holds for it (`None`: a head is never skipped, or no queue). 500 for a
/// namespace without one, or one that no longer parses (REGISTER writes and
/// checks it).
pub fn stale_blocks_of<S: StoreRead + ?Sized>(
    store: &S,
    namespace: Fr,
) -> Result<Option<u64>, Refusal> {
    let row = store.contract_manifest(namespace)?.ok_or_else(|| {
        Refusal::mpc_failure(format!(
            "store: namespace {} holds no contract manifest",
            fr_to_hex(namespace)
        ))
    })?;
    Ok(row.parse()?.stale_blocks())
}

/// A registered queued package as synthesis reads it: its name, the
/// vk_hash the chain request id commits to, the manifest's tip view, the
/// shape of its circuit, and the implementations its manifest picks, once:
/// its intake's and each key's tip state.
#[derive(Clone)]
pub struct TipPackage {
    pub name: String,
    pub vk_hash: Fr,
    pub tip: TipManifest,
    pub shape: CircuitShape,
    /// Where its requests' inputs come from: the implementation of the
    /// manifest's intake.
    pub intake: &'static dyn IntakeSource,
    /// The tip state of every key the manifest loads or stores, in key
    /// reference order, by the key's state mode.
    pub(crate) states: KeyTipStates,
    /// Under upgrades, the contract manifest version its requests name
    /// (the request's `manifest_hash`); `None` names none.
    pub version: Option<Fr>,
}

impl std::fmt::Debug for TipPackage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TipPackage")
            .field("name", &self.name)
            .field("vk_hash", &fr_to_hex(self.vk_hash))
            .field("intake", &self.tip.intake())
            .finish_non_exhaustive()
    }
}

impl TipPackage {
    /// The package of `tip` with the implementations it picks; 400 for a key
    /// whose state mode no tip state serves or an intake not built (REGISTER
    /// refuses such a manifest).
    pub fn new(
        name: String,
        vk_hash: Fr,
        tip: TipManifest,
        shape: CircuitShape,
    ) -> Result<TipPackage, Refusal> {
        Ok(TipPackage {
            states: tip_states(&tip)?,
            intake: intake_source(tip.intake())?,
            name,
            vk_hash,
            tip,
            shape,
            version: None,
        })
    }

    /// The same package, its requests naming the contract manifest version
    /// `version`.
    pub fn with_version(mut self, version: Option<Fr>) -> Self {
        self.version = version;
        self
    }

    /// The tip view of a stored package row of a namespace whose contract
    /// manifest states the stale period `stale_blocks` ([`stale_blocks_of`]),
    /// or `None` for a package of intake direct. 500 for a row that no longer
    /// parses or names a state mode no tip state serves (REGISTER checked
    /// both).
    pub fn from_row(
        pkg: &PackageRow,
        stale_blocks: Option<u64>,
    ) -> Result<Option<TipPackage>, Refusal> {
        let (manifest, shape) = pkg.parse()?;
        let Some(tip) = TipManifest::new(manifest, stale_blocks) else {
            return Ok(None);
        };
        TipPackage::new(pkg.name.clone(), pkg.vk_hash, tip, shape)
            .map(Some)
            .map_err(|e| {
                Refusal::mpc_failure(format!(
                    "store: package `{}`: the intake or the state modes: {}",
                    pkg.name, e.message
                ))
            })
    }

    /// The package of a queued round as the step 4 hook receives it; 400 as
    /// [`Self::new`].
    pub fn from_round(round: &ChainRound<'_>) -> Result<TipPackage, Refusal> {
        TipPackage::new(
            round.manifest.circuit.clone(),
            round.vk_hash,
            TipManifest::queued(round.manifest.clone(), round.intake, round.stale_blocks),
            round.shape.clone(),
        )
    }

    /// The request keys of the keys this circuit loads, in
    /// `commitment_slot` order (the order of the machine request id's old
    /// commitments): `state_keys.reads[i]` for each `$state_keys.reads[i]`. 400 for a
    /// key the request keys do not name.
    pub fn state_keys<'k>(&self, state_keys: &'k StateKeys) -> Result<Vec<&'k str>, Refusal> {
        self.tip
            .old_commitments()
            .map(|old| {
                request_key(state_keys, old.key).ok_or_else(|| {
                    Refusal::bad_request(format!(
                        "circuit `{}`: the request keys name no {} (its commitment slot)",
                        self.name, old.key
                    ))
                })
            })
            .collect()
    }

    /// The old commitments of a round's public inputs, in `commitment_slot`
    /// order: what the machine request id of the round was derived from. 500
    /// when the public inputs are shorter than the shape says.
    pub fn old_commitments_of(&self, public_inputs: &[Fr]) -> Result<Vec<Fr>, Refusal> {
        self.tip
            .old_commitments()
            .map(|old| {
                self.tip
                    .output_index(&self.shape, old.output)
                    .and_then(|i| public_inputs.get(i).copied())
                    .ok_or_else(|| {
                        Refusal::mpc_failure(format!(
                            "circuit `{}`: the round's public inputs carry no `{}`",
                            self.name, old.output
                        ))
                    })
            })
            .collect()
    }

    /// The pinned values of a round's public inputs, in `public_reads` order
    /// (every field of each read's parameter, then an epoch read's epoch):
    /// what the machine request id of the round was derived from after the
    /// old commitments. 500 when the public inputs are shorter than the
    /// shape says.
    pub fn reads_of(&self, public_inputs: &[Fr]) -> Result<Vec<Fr>, Refusal> {
        let mut out = Vec::new();
        for read in self.tip.public_reads() {
            for param in read.params() {
                let fields = self
                    .shape
                    .param(param)
                    .and_then(|p| Some((p.public_index?, p.width)))
                    .and_then(|(i, w)| public_inputs.get(i..i + w))
                    .ok_or_else(|| {
                        Refusal::mpc_failure(format!(
                            "circuit `{}`: the round's public inputs carry no `{param}` (the \
                             pinned read `{}`)",
                            self.name, read.function
                        ))
                    })?;
                out.extend_from_slice(fields);
            }
        }
        Ok(out)
    }

    /// The old commitments the machine request id of this package's init
    /// round covers: one 0 per key it creates, as pss_public_contract's
    /// `process_init` derives it. `None` for a package that loads a key or
    /// takes a pinned read, which is no init round.
    pub fn init_commitments(&self) -> Option<Vec<Fr>> {
        (self.tip.old_commitments().next().is_none() && self.tip.public_reads().is_empty())
            .then(|| vec![Fr::from(0u64); self.tip.manifest().state_keys.writes])
    }

    /// The pinned values a view holds for this circuit, in `public_reads`
    /// order (every field of each): the machine request id's pinned part, as
    /// [`synthesise`] derives it. 400 for a missing value or one whose length
    /// is not its parameters' width, as synthesis refuses them.
    pub fn pinned_fields(&self, pinned: &PinnedValues) -> Result<Vec<Fr>, Refusal> {
        let mut out = Vec::new();
        for read in self.tip.public_reads() {
            let value = pinned_value(&self.shape, read, pinned)?;
            out.extend_from_slice(&value.values);
        }
        Ok(out)
    }

    /// Whether `used`, the pinned values an attempt ran at (as
    /// [`TipPackage::pinned_fields`] gives them), still count against
    /// `pinned`, the values read now: every read's freshness policy admits
    /// its part ([`PublicRead::admits`]), so `apply` would accept them. The
    /// scheduler keeps a held attempt while this holds.
    pub fn pinned_admitted(&self, pinned: &PinnedValues, used: &[Fr]) -> Result<bool, Refusal> {
        let mut rest = used;
        for read in self.tip.public_reads() {
            let now = pinned_value(&self.shape, read, pinned)?;
            let Some((part, after)) = rest.split_at_checked(now.values.len()) else {
                return Ok(false);
            };
            if !read.admits(&now.values, now.previous, part) {
                return Ok(false);
            }
            rest = after;
        }
        Ok(rest.is_empty())
    }

    /// The clear app inputs of `inputs` by request public name: what a
    /// synthesised request's `public` holds of them, and what the
    /// scheduler's node values read before synthesis. 500 when they do not
    /// fit the package (a row stored under another circuit).
    pub fn app_public(&self, inputs: &dyn FoundInputs) -> Result<PublicMap, Refusal> {
        public_inputs(&self.shape, &self.tip, inputs.clear_inputs())
    }

    /// The pinned values `public` (a request's public map) carries for
    /// `read`, in public-input order: under its parameters' request public
    /// names. `None` when one is missing.
    pub fn pinned_in(&self, read: &PublicRead, public: &PublicMap) -> Option<Vec<Fr>> {
        let mut out = Vec::new();
        for param in read.params() {
            let (name, _) = pinned_name(&self.shape, param).ok()?;
            match public.get(name)? {
                PublicValue::One(v) => out.push(v.fr()),
                PublicValue::Many(vs) => out.extend(vs.iter().map(|v| v.fr())),
            }
        }
        Some(out)
    }
}

/// The pinned value of `read` in `pinned`, checked against its parameters'
/// width (the value's, plus one for an epoch read's epoch).
fn pinned_value<'v>(
    shape: &CircuitShape,
    read: &PublicRead,
    pinned: &'v PinnedValues,
) -> Result<&'v PinnedValue, Refusal> {
    let value = pinned.get(&read.param).ok_or_else(|| {
        Refusal::bad_request(format!(
            "public read `{}`: no pinned value for parameter `{}`",
            read.function, read.param
        ))
    })?;
    let mut width = 0;
    for param in read.params() {
        width += pinned_name(shape, param)?.1;
    }
    if value.values.len() != width {
        return Err(Refusal::bad_request(format!(
            "public read `{}`: {} value(s) for parameter(s) `{}` of width {width}",
            value.function,
            value.values.len(),
            read.params().collect::<Vec<_>>().join("`, `")
        )));
    }
    Ok(value)
}

/// What the synthesis of one queued request reads besides the package and
/// the inputs: the namespace, the queue entry, the app's request keys for
/// the circuit, the pinned values read at one block, and the state the round
/// runs on.
#[derive(Clone, Copy, Debug)]
pub struct SynthesisView<'a> {
    /// The namespace contract.
    pub namespace: Fr,
    /// The head, or a pipelined entry after it.
    pub entry: QueueEntry,
    /// `state_keys.reads` and `state_keys.writes` of the circuit: each key with state is
    /// its commitment slot (`chain::commitment_slots`), as the app's
    /// configuration names them.
    pub state_keys: &'a StateKeys,
    /// The filled `public_reads` of the package, read at the snapshot
    /// ([`crate::ChainReader::pinned_values`]).
    pub pinned: &'a PinnedValues,
    /// The state: one [`KeyState`] per key the circuit loads, under its
    /// request key, as the key's tip state gives it (the slot's, or, when
    /// pipelining, the previous request's result). States of other keys are
    /// ignored.
    pub state: &'a [KeyState],
    /// The node-sourced public values of the keys the circuit loads, by
    /// request public name (a tree key's paths and `$new_leaf`, under its
    /// parameter's name; [`crate::TipState::node_values`]).
    pub node_values: &'a PublicMap,
}

/// A synthesised request with the old commitment of each key it loads, by
/// request key: what the scheduler records of the attempt.
#[derive(Clone, Debug, PartialEq)]
pub struct Synthesised {
    pub request: Request<Full>,
    pub old: BTreeMap<String, Fr>,
}

// What synthesis refuses. Inputs whose chain request id under
// the package is not the queue entry's (the log or receipt belongs to
// another request or circuit; the intake drops a stored receipt naming
// another circuit, vk_hash or namespace before synthesis), a reserved
// operand the intake does not fill, a missing pinned value or one whose
// length is not its parameter's width, and a key without state are 400: the
// request cannot be built from this view, and retrying with a fresh
// snapshot is the caller's move. The synthesised request is then checked with
// `check_request_ids`, the check every chain verifier runs, so the scheduler
// never sends a request a correct verifier refuses on its ids. The public
// map has no other entries than the app inputs, the reserved operands'
// values and the pinned values (`$namespace` and `$state_keys` references are
// filled by the binder from the request itself).
/// Synthesise the execute request of `view.entry` under `package` from
/// `inputs`, as the package's intake found them: see the module
/// documentation.
pub fn synthesise(
    view: &SynthesisView<'_>,
    package: &TipPackage,
    inputs: &dyn FoundInputs,
) -> Result<Synthesised, Refusal> {
    build(view, package, inputs, None)
}

/// Synthesise the init round's request (docs/ARCHITECTURE.md section 6,
/// "Deployment, configure and the init round"): as [`synthesise`], from the
/// init's inputs under `view.entry`'s chain request id (the fixed init id,
/// [`crate::init`]), with one difference: the machine request id covers one
/// old commitment of 0 per key the round creates, `machine_request_id(init
/// id, [0; W], [])`, the id pss_public_contract's `process_init` checks the
/// three result signatures under. 400 for a package that loads a key or
/// takes a pinned read: an init round runs on empty slots only.
pub(crate) fn synthesise_init(
    view: &SynthesisView<'_>,
    package: &TipPackage,
    inputs: &dyn FoundInputs,
) -> Result<Synthesised, Refusal> {
    let empty = package.init_commitments().ok_or_else(|| {
        Refusal::bad_request(format!(
            "circuit `{}` loads a key or takes a pinned read, so it is no init round (an init \
             round creates its keys on empty slots)",
            package.name
        ))
    })?;
    build(view, package, inputs, Some(&empty))
}

/// [`synthesise`], with the old commitments the machine request id covers
/// given by `created` (the init round's empty slots) instead of the loaded
/// keys' states.
fn build(
    view: &SynthesisView<'_>,
    package: &TipPackage,
    inputs: &dyn FoundInputs,
    created: Option<&[Fr]>,
) -> Result<Synthesised, Refusal> {
    let ns = view.namespace;
    let chain = view.entry.chain_request_id;
    let derived = package.chain_request_id(ns, inputs);
    if derived != chain {
        return Err(Refusal::bad_request(format!(
            "the inputs give chain request id {} under circuit `{}`, not the queue entry's {} \
             (index {})",
            fr_to_hex(derived),
            package.name,
            fr_to_hex(chain),
            view.entry.index
        )));
    }
    let mut public = package.app_public(inputs)?;
    // a clear partial note is an app input, placed already
    for (param, reserved) in package
        .tip
        .manifest()
        .reserved()
        .filter(|(_, r)| !r.app_input())
    {
        let value = match reserved {
            ReservedOperand::VkHash => Some(package.vk_hash),
            ReservedOperand::NewLeaf => match view.node_values.get(param) {
                Some(PublicValue::One(v)) => Some(v.fr()),
                _ => None,
            },
            operand => inputs.reserved(operand),
        }
        .ok_or_else(|| {
            Refusal::bad_request(format!(
                "circuit `{}`: parameter `{param}` takes `{reserved}`, which {} does not fill",
                package.name,
                package.tip.intake().name()
            ))
        })?;
        public.insert(param.to_string(), PublicValue::One(FieldHex(value)));
    }
    for (name, value) in view.node_values {
        public.entry(name.clone()).or_insert_with(|| value.clone());
    }
    let mut pinned = Vec::new();
    for read in package.tip.public_reads() {
        let value = pinned_value(&package.shape, read, view.pinned)?;
        pinned.extend_from_slice(&value.values);
        // the value fills `param`, an epoch read's epoch `epoch_param`
        let mut rest = value.values.as_slice();
        for param in read.params() {
            let (name, width) = pinned_name(&package.shape, param)?;
            let (part, after) = rest.split_at(width);
            rest = after;
            let filled = match part {
                [one] => PublicValue::One(FieldHex(*one)),
                many => PublicValue::Many(many.iter().copied().map(FieldHex).collect()),
            };
            public.insert(name.to_string(), filled);
        }
    }
    let mut records = Vec::new();
    let mut old_commitments = Vec::new();
    let mut old = BTreeMap::new();
    for key in package.state_keys(view.state_keys)? {
        let held = view.state.iter().find(|s| s.key == key).ok_or_else(|| {
            Refusal::bad_request(format!(
                "circuit `{}` loads `{key}`, and the view holds no state for it",
                package.name
            ))
        })?;
        old_commitments.push(held.commitment);
        old.insert(key.to_string(), held.commitment);
        if let Some(record) = &held.record
            && !records.iter().any(|r: &StateRecord| r.key == key)
        {
            records.push(record.clone());
        }
    }
    let id_commitments = created.unwrap_or(&old_commitments);
    let mut request = Request {
        namespace: FieldHex(ns),
        circuit: package.name.clone(),
        request_id: RequestId(machine_request_id(chain, id_commitments, &pinned)),
        public,
        state_keys: view.state_keys.clone(),
        shared_inputs: vec![],
        records,
        requester: None,
        signature: None,
        chain_request_id: Some(FieldHex(chain)),
        shared_log: None,
        manifest_hash: package.version.map(FieldHex),
    };
    inputs.fill(&mut request);
    check_request_ids(derived, ns, id_commitments, &pinned, &request)?;
    Ok(Synthesised { request, old })
}

/// The request public name a pinned read's parameter is filled from (its
/// one PUBLIC operand; REGISTER checked that it is a name used once) and the
/// parameter's width.
fn pinned_name<'s>(shape: &'s CircuitShape, param: &str) -> Result<(&'s str, usize), Refusal> {
    let p = shape
        .param(param)
        .ok_or_else(|| Refusal::mpc_failure(format!("the shape has no parameter `{param}`")))?;
    match &p.source {
        Source::Public(PublicSource::One(PublicOperand::Name(name))) => Ok((name, p.width)),
        _ => Err(Refusal::mpc_failure(format!(
            "parameter `{param}` is not filled by one PUBLIC name (REGISTER checks it)"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::{PinnedSource, PinnedValue};
    use crate::chain_request_id;
    use crate::intake::onchain::PlainInputs;
    use crate::intake::route::StoredReceipt;
    use crate::intake::{PlainFound, SharedReceiptFound};
    use sidecar_core::error::{ErrorClass, parse_json};
    use sidecar_core::field::HexBytes;
    use sidecar_core::register::Signature;

    use crate::testing::AMM_SWAP_TIP;

    const POOL: &str = "0x12";

    /// Inputs in the clear, as the non-secret-shared intakes give them.
    trait AsInputs {
        fn intake_inputs(&self) -> PlainFound;
    }

    impl AsInputs for PlainInputs<'_> {
        fn intake_inputs(&self) -> PlainFound {
            PlainFound::new(self.inputs.to_vec(), self.user_nonce)
        }
    }

    impl AsInputs for &StoredReceipt {
        fn intake_inputs(&self) -> PlainFound {
            PlainFound::new(
                self.inputs.iter().map(|f| f.fr()).collect(),
                self.user_nonce.unwrap().fr(),
            )
        }
    }

    // Synthesis from inputs as an intake gives them, the request alone.
    fn synth<I: AsInputs>(
        view: &SynthesisView<'_>,
        pkg: &TipPackage,
        inputs: I,
    ) -> Result<Request<Full>, Refusal> {
        synthesise(view, pkg, &inputs.intake_inputs()).map(|s| s.request)
    }

    fn manifest_text(intake: &str, reads: &str) -> String {
        AMM_SWAP_TIP
            .replace("\"onchain\"", &format!("\"{intake}\""))
            .replace(
                "\"public_reads\": []",
                &format!("\"public_reads\": {reads}"),
            )
    }

    /// The amm-tip package (examples/amm-tip/circuits/amm_swap_tip) under
    /// `intake` with the pinned reads `reads`, whose parameters `pinned` are
    /// public (`crate::testing::amm_swap_tip_abi`).
    fn package(intake: &str, reads: &str, pinned: &[&str]) -> TipPackage {
        let row = PackageRow {
            name: "amm_swap_tip".into(),
            manifest_hash: Fr::from(0u64),
            circuit_json: serde_json::to_vec(&serde_json::json!({
                "abi": crate::testing::amm_swap_tip_abi(pinned)
            }))
            .unwrap(),
            manifest: parse_json(&manifest_text(intake, reads)).unwrap(),
            vk: vec![],
            vk_hash: Fr::from(0x7e57u64),
            disabled: false,
            seq: 1,
        };
        TipPackage::from_row(&row, Some(50)).unwrap().unwrap()
    }

    fn state_keys() -> StateKeys {
        StateKeys {
            reads: vec![POOL.into()],
            writes: vec![POOL.into()],
        }
    }

    fn state(note_hash: u64) -> KeyState {
        crate::state::chain::key_state(record(note_hash))
    }

    fn record(note_hash: u64) -> StateRecord {
        StateRecord {
            key: POOL.into(),
            note_hash: FieldHex(Fr::from(note_hash)),
            c: [0, 1, 2].map(|i| HexBytes(vec![i; 4])),
            record_hashes: [0, 1, 2].map(|i| FieldHex(Fr::from(i as u64))),
        }
    }

    const NS: u64 = 0x5e;
    const NONCE: u64 = 9;

    fn entry(pkg: &TipPackage, inputs: &[Fr]) -> QueueEntry {
        QueueEntry {
            index: 3,
            chain_request_id: chain_request_id(Fr::from(NS), pkg.vk_hash, inputs, Fr::from(NONCE)),
        }
    }

    #[test]
    fn an_on_chain_intake_head_becomes_an_ordinary_request() {
        let pkg = package("onchain", "[]", &[]);
        let inputs = [
            Fr::from(5000u64),
            Fr::from(1u64),
            Fr::from(4000u64),
            Fr::from(0x9au64),
        ];
        let log = PlainInputs {
            inputs: &inputs,
            user_nonce: Fr::from(NONCE),
        };
        let state_keys = state_keys();
        let pinned = PinnedValues::default();
        let records = [state(0xc0)];
        let view = SynthesisView {
            namespace: Fr::from(NS),
            entry: entry(&pkg, &inputs),
            state_keys: &state_keys,
            pinned: &pinned,
            state: &records,
            node_values: &PublicMap::new(),
        };
        let req = synth(&view, &pkg, log).unwrap();
        assert_eq!(req.circuit, "amm_swap_tip");
        assert_eq!(req.state_keys, state_keys);
        // the app inputs, and the reserved operands synthesis places under
        // their parameters' names
        assert_eq!(
            req.public.keys().collect::<Vec<_>>(),
            [
                "amount_in",
                "direction",
                "min_out",
                "partial_note",
                "user_nonce",
                "vk_hash"
            ]
        );
        assert_eq!(
            req.public["vk_hash"],
            PublicValue::One(FieldHex(pkg.vk_hash))
        );
        assert_eq!(
            req.public["user_nonce"],
            PublicValue::One(FieldHex::from(NONCE))
        );
        assert_eq!(
            req.public["amount_in"],
            PublicValue::One(FieldHex::from(5000))
        );
        assert_eq!(req.records, [record(0xc0)]);
        assert!(req.shared_inputs.is_empty() && req.requester.is_none());
        assert_eq!(
            req.chain_request_id,
            Some(FieldHex(view.entry.chain_request_id))
        );
        assert_eq!(
            req.request_id.fr(),
            machine_request_id(view.entry.chain_request_id, &[Fr::from(0xc0u64)], &[])
        );
        req.validate().unwrap();
        // the same view gives the same request: what a chain verifier rebuilds
        assert_eq!(synth(&view, &pkg, log).unwrap(), req);
        // another state is another attempt
        let other = [state(0xc1)];
        let moved = SynthesisView {
            state: &other,
            ..view
        };
        let again = synth(&moved, &pkg, log).unwrap();
        assert_ne!(again.request_id, req.request_id);
        assert_eq!(again.chain_request_id, req.chain_request_id);
        // [namespace, vk_hash, in_slots, out_slots, request_id, old_c]
        assert_eq!(
            pkg.old_commitments_of(&[
                Fr::from(NS),
                pkg.vk_hash,
                Fr::from(0x12u64),
                Fr::from(0x12u64),
                view.entry.chain_request_id,
                Fr::from(0xc0u64),
            ])
            .unwrap(),
            [Fr::from(0xc0u64)]
        );
        // no pinned reads: nothing after the old commitments
        assert!(pkg.reads_of(&[]).unwrap().is_empty());
        assert!(pkg.pinned_fields(&pinned).unwrap().is_empty());
    }

    #[test]
    fn synthesis_refuses_what_does_not_belong_to_the_entry() {
        let pkg = package("onchain", "[]", &[]);
        let inputs = [
            Fr::from(5000u64),
            Fr::from(1u64),
            Fr::from(4000u64),
            Fr::from(0x9au64),
        ];
        let state_keys = state_keys();
        let pinned = PinnedValues::default();
        let records = [state(0xc0)];
        let view = SynthesisView {
            namespace: Fr::from(NS),
            entry: entry(&pkg, &inputs),
            state_keys: &state_keys,
            pinned: &pinned,
            state: &records,
            node_values: &PublicMap::new(),
        };
        let refused = |view: &SynthesisView<'_>, inputs: &[Fr], needle: &str| {
            let log = PlainInputs {
                inputs,
                user_nonce: Fr::from(NONCE),
            };
            let err = synth(view, &pkg, log).unwrap_err();
            assert_eq!(err.class, ErrorClass::BadRequest, "{err}");
            assert!(err.message.contains(needle), "{err}");
        };
        refused(
            &view,
            &[
                Fr::from(5001u64),
                Fr::from(1u64),
                Fr::from(4000u64),
                Fr::from(0x9au64),
            ],
            "not the queue entry's",
        );
        let wrong_ns = SynthesisView {
            namespace: Fr::from(NS + 1),
            ..view
        };
        refused(&wrong_ns, &inputs, "not the queue entry's");
        let empty: [KeyState; 0] = [];
        let stateless = SynthesisView {
            state: &empty,
            ..view
        };
        refused(&stateless, &inputs, "holds no state for it");
        let no_state_keys = StateKeys::default();
        let keyless = SynthesisView {
            state_keys: &no_state_keys,
            ..view
        };
        refused(&keyless, &inputs, "name no $state_keys.reads[0]");
    }

    /// The AMM tip's receipt-intake manifest fills vk_hash and user_nonce by the
    /// reserved operands: synthesis places the package's vk hash and the
    /// receipt's nonce under those parameters' names, and the
    /// binder fills the parameters from there.
    #[test]
    fn a_receipt_intake_head_places_the_reserved_operands_for_the_binder() {
        let pkg = TipPackage::from_row(&crate::intake::route::tests::receipt_package(), Some(50))
            .unwrap()
            .unwrap();
        let inputs = [
            Fr::from(5000u64),
            Fr::from(1u64),
            Fr::from(4000u64),
            Fr::from(0x9au64),
        ];
        let receipt = StoredReceipt {
            namespace: FieldHex(Fr::from(NS)),
            request_id: FieldHex(entry(&pkg, &inputs).chain_request_id),
            circuit: pkg.name.clone(),
            vk_hash: FieldHex(pkg.vk_hash),
            inputs: inputs.iter().copied().map(FieldHex).collect(),
            inputs_hash: FieldHex(crate::inputs_hash(&inputs)),
            user_nonce: Some(FieldHex(Fr::from(NONCE))),
            shared_inputs: vec![],
            expiry_block: 400,
            stale_blocks: Some(50),
            signature: Signature::default(),
        };
        let state_keys = state_keys();
        let pinned = PinnedValues::default();
        let records = [state(0xc0)];
        let view = SynthesisView {
            namespace: Fr::from(NS),
            entry: entry(&pkg, &inputs),
            state_keys: &state_keys,
            pinned: &pinned,
            state: &records,
            node_values: &PublicMap::new(),
        };
        let req = synth(&view, &pkg, &receipt).unwrap();
        let one = |v: Fr| PublicValue::One(FieldHex(v));
        assert_eq!(
            req.public,
            [
                ("amount_in", one(Fr::from(5000u64))),
                ("direction", one(Fr::from(1u64))),
                ("min_out", one(Fr::from(4000u64))),
                ("partial_note", one(Fr::from(0x9au64))),
                ("vk_hash", one(pkg.vk_hash)),
                ("user_nonce", one(Fr::from(NONCE))),
            ]
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect()
        );
        req.validate().unwrap();
        // the hidden requester: the synthesised request names no address
        crate::audit::Requesters::new([Fr::from(0xbeefu64)]).assert_synthesised(&req);

        // the binder of step 9 fills each parameter from the map
        let bound =
            sidecar_core::bind::check_request(&pkg.shape, pkg.tip.manifest(), &req).unwrap();
        let value_of = |param: &str| {
            let k = pkg
                .shape
                .params
                .iter()
                .position(|p| p.name == param)
                .unwrap();
            bound.per_param[k].clone().unwrap()
        };
        assert_eq!(value_of("vk_hash"), [pkg.vk_hash]);
        assert_eq!(value_of("user_nonce"), [Fr::from(NONCE)]);
        assert_eq!(value_of("namespace"), [Fr::from(NS)]);
        assert_eq!(value_of("min_out"), [Fr::from(4000u64)]);
        // a request without one is refused, naming the operand
        let mut short = req.clone();
        short.public.remove("user_nonce");
        let err =
            sidecar_core::bind::check_request(&pkg.shape, pkg.tip.manifest(), &short).unwrap_err();
        assert_eq!(err.class, ErrorClass::BadRequest);
        assert!(
            err.message.contains("field `public.user_nonce`: missing")
                && err.message.contains("`$user_nonce`"),
            "{err}"
        );
        // the request-log path places them the same way
        let log = PlainInputs {
            inputs: &inputs,
            user_nonce: Fr::from(NONCE),
        };
        assert_eq!(synth(&view, &pkg, log).unwrap(), req);
    }

    #[test]
    fn a_receipt_intake_head_takes_the_stored_receipt_and_its_pinned_reads() {
        let reads = r#"[{"contract": "0x1234", "function": "get_price", "args": [], "param": "direction"}]"#;
        let pkg = package("receipt", reads, &["direction"]);
        // `direction` is filled by the pinned read, so it is no app input
        let inputs = [Fr::from(5000u64), Fr::from(4000u64), Fr::from(0x9au64)];
        let receipt = StoredReceipt {
            namespace: FieldHex(Fr::from(NS)),
            request_id: FieldHex(entry(&pkg, &inputs).chain_request_id),
            circuit: pkg.name.clone(),
            vk_hash: FieldHex(pkg.vk_hash),
            inputs: inputs.iter().copied().map(FieldHex).collect(),
            inputs_hash: FieldHex(crate::inputs_hash(&inputs)),
            user_nonce: Some(FieldHex(Fr::from(NONCE))),
            shared_inputs: vec![],
            expiry_block: 400,
            stale_blocks: Some(50),
            signature: Signature::default(),
        };
        let state_keys = state_keys();
        let price = |values: Vec<Fr>| {
            PinnedValues(vec![PinnedValue {
                param: "direction".into(),
                contract: Fr::from(0x1234u64),
                function: "get_price()".into(),
                args: vec![],
                values,
                previous: None,
                block: 77,
                source: PinnedSource::Simulated,
            }])
        };
        let pinned = price(vec![Fr::from(1u64)]);
        let records = [state(0xc0)];
        let view = SynthesisView {
            namespace: Fr::from(NS),
            entry: entry(&pkg, &inputs),
            state_keys: &state_keys,
            pinned: &pinned,
            state: &records,
            node_values: &PublicMap::new(),
        };
        let req = synth(&view, &pkg, &receipt).unwrap();
        assert_eq!(
            req.public["amount_in"],
            PublicValue::One(FieldHex::from(5000))
        );
        assert_eq!(req.public["direction"], PublicValue::One(FieldHex::from(1)));
        assert_eq!(
            req.public["min_out"],
            PublicValue::One(FieldHex::from(4000))
        );
        // with the partial note and the reserved operands, `user_nonce` and
        // `vk_hash`
        assert_eq!(req.public.len(), 6);
        // the machine request id covers the pinned value after the old
        // commitment; the same state at a moved value is another attempt
        let chain = view.entry.chain_request_id;
        assert_eq!(pkg.pinned_fields(&pinned).unwrap(), [Fr::from(1u64)]);
        assert_eq!(
            req.request_id.fr(),
            machine_request_id(chain, &[Fr::from(0xc0u64)], &[Fr::from(1u64)])
        );
        let moved = price(vec![Fr::from(2u64)]);
        let at_moved = SynthesisView {
            pinned: &moved,
            ..view
        };
        let again = synth(&at_moved, &pkg, &receipt).unwrap();
        assert_ne!(again.request_id, req.request_id);
        assert_eq!(again.records, req.records);
        assert_eq!(
            again.request_id.fr(),
            machine_request_id(chain, &[Fr::from(0xc0u64)], &[Fr::from(2u64)])
        );
        // what the orchestrator reads back from the round's public inputs:
        // namespace, in_slots, out_slots, amount_in, direction (the pinned
        // read), min_out, then old_c
        let public_inputs = [
            Fr::from(NS),
            Fr::from(0x12u64),
            Fr::from(0x12u64),
            Fr::from(5000u64),
            Fr::from(1u64),
            Fr::from(4000u64),
            Fr::from(0xc0u64),
        ];
        assert_eq!(
            pkg.old_commitments_of(&public_inputs).unwrap(),
            [Fr::from(0xc0u64)]
        );
        assert_eq!(pkg.reads_of(&public_inputs).unwrap(), [Fr::from(1u64)]);
        let err = pkg.reads_of(&public_inputs[..4]).unwrap_err();
        assert!(err.message.contains("carry no `direction`"), "{err}");

        let none = PinnedValues::default();
        let unpinned = SynthesisView {
            pinned: &none,
            ..view
        };
        let err = synth(&unpinned, &pkg, &receipt).unwrap_err();
        assert!(err.message.contains("no pinned value"), "{err}");
        let err = pkg.pinned_fields(&none).unwrap_err();
        assert!(err.message.contains("no pinned value"), "{err}");
        let two = price(vec![Fr::from(1u64), Fr::from(2u64)]);
        let wide = SynthesisView {
            pinned: &two,
            ..view
        };
        let err = synth(&wide, &pkg, &receipt).unwrap_err();
        assert!(err.message.contains("of width 1"), "{err}");
        let err = pkg.pinned_fields(&two).unwrap_err();
        assert!(err.message.contains("of width 1"), "{err}");
    }

    #[test]
    fn an_epoch_read_fills_its_value_and_epoch_and_keeps_an_attempt_one_epoch_on() {
        let reads = r#"[{"contract": "0x1234", "function": "get_price_epoch", "args": [],
                         "param": "direction", "freshness": "epoch", "epoch_param": "min_out"}]"#;
        let pkg = package("receipt", reads, &["direction", "min_out"]);
        // `direction` and `min_out` are filled by the read: one app input
        // and the partial note
        let inputs = [Fr::from(5000u64), Fr::from(0x9au64)];
        let receipt = StoredReceipt {
            namespace: FieldHex(Fr::from(NS)),
            request_id: FieldHex(entry(&pkg, &inputs).chain_request_id),
            circuit: pkg.name.clone(),
            vk_hash: FieldHex(pkg.vk_hash),
            inputs: inputs.iter().copied().map(FieldHex).collect(),
            inputs_hash: FieldHex(crate::inputs_hash(&inputs)),
            user_nonce: Some(FieldHex(Fr::from(NONCE))),
            shared_inputs: vec![],
            expiry_block: 400,
            stale_blocks: Some(50),
            signature: Signature::default(),
        };
        let state_keys = state_keys();
        // the source's [value, epoch, previous] as the reader keeps it
        let at = |value: u64, epoch: u64, previous: u64| {
            PinnedValues(vec![PinnedValue {
                param: "direction".into(),
                contract: Fr::from(0x1234u64),
                function: "get_price_epoch()".into(),
                args: vec![],
                values: vec![Fr::from(value), Fr::from(epoch)],
                previous: Some(Fr::from(previous)),
                block: 77,
                source: PinnedSource::Simulated,
            }])
        };
        let pinned = at(7, 3, 6);
        let records = [state(0xc0)];
        let view = SynthesisView {
            namespace: Fr::from(NS),
            entry: entry(&pkg, &inputs),
            state_keys: &state_keys,
            pinned: &pinned,
            state: &records,
            node_values: &PublicMap::new(),
        };
        let req = synth(&view, &pkg, &receipt).unwrap();
        assert_eq!(req.public["direction"], PublicValue::One(FieldHex::from(7)));
        assert_eq!(req.public["min_out"], PublicValue::One(FieldHex::from(3)));
        // with the partial note and the reserved operands, `user_nonce` and
        // `vk_hash`
        assert_eq!(req.public.len(), 6);
        // the machine request id covers the value, then its epoch
        let used = pkg.pinned_fields(&pinned).unwrap();
        assert_eq!(used, [Fr::from(7u64), Fr::from(3u64)]);
        assert_eq!(
            req.request_id.fr(),
            machine_request_id(view.entry.chain_request_id, &[Fr::from(0xc0u64)], &used)
        );
        // read back from the public inputs (the ABI's: namespace, in_slots,
        // out_slots, amount_in, direction, min_out, old_c)
        let public_inputs = [
            Fr::from(NS),
            Fr::from(0x12u64),
            Fr::from(0x12u64),
            Fr::from(5000u64),
            Fr::from(7u64),
            Fr::from(3u64),
            Fr::from(0xc0u64),
        ];
        assert_eq!(pkg.reads_of(&public_inputs).unwrap(), used);
        // the request's own values, as the chain verifier reads them
        let read = &pkg.tip.public_reads()[0];
        assert_eq!(pkg.pinned_in(read, &req.public).unwrap(), used);

        // the attempt stays admitted at the next epoch, not at the one after
        assert!(pkg.pinned_admitted(&pinned, &used).unwrap());
        assert!(pkg.pinned_admitted(&at(9, 4, 7), &used).unwrap());
        assert!(!pkg.pinned_admitted(&at(11, 5, 9), &used).unwrap());
        // a recomputed price two epochs on is a new attempt
        assert!(
            !pkg.pinned_admitted(&at(9, 4, 8), &used).unwrap(),
            "not the previous value"
        );
        assert!(!pkg.pinned_admitted(&pinned, &used[..1]).unwrap());

        // a value without its epoch is refused at synthesis
        let short = PinnedValues(vec![PinnedValue {
            values: vec![Fr::from(7u64)],
            ..pinned.0[0].clone()
        }]);
        let err = synth(
            &SynthesisView {
                pinned: &short,
                ..view
            },
            &pkg,
            &receipt,
        )
        .unwrap_err();
        assert!(
            err.message.contains("`direction`, `min_out` of width 2"),
            "{err}"
        );
    }

    /// A secret-shared receipt intake head: `public` holds the clear app inputs,
    /// the reserved values ($vk_hash, $inputs_hash = C) and the pinned
    /// values under their parameters' names, and nothing else (no shared
    /// value, no requester); `shared_inputs` are the three nodes'
    /// envelopes; a node-held key carries no record.
    #[test]
    fn a_shared_receipt_head_holds_only_clear_inputs_reserved_values_and_pinned_values() {
        use crate::intake::tests::SharedFixture;
        let f = SharedFixture::new();
        // the round with a pinned read `price` after the slots
        let mut row = crate::testing::shared_package();
        let mut abi = crate::testing::shared_circuit_abi();
        abi["parameters"].as_array_mut().unwrap().insert(
            4,
            serde_json::json!({"name": "price", "type": {"kind": "field"}, "visibility": "public"}),
        );
        row.circuit_json = serde_json::to_vec(&serde_json::json!({ "abi": abi })).unwrap();
        row.manifest["witness"].as_array_mut().unwrap().insert(
            4,
            serde_json::json!({"param": "price", "from": {"PUBLIC": "price"}}),
        );
        row.manifest["public_reads"] = serde_json::json!([
            {"contract": "0x1234", "function": "get_price", "args": [], "param": "price"}
        ]);
        let priced = TipPackage::from_row(&row, Some(50)).unwrap().unwrap();
        let state_keys = state_keys();
        let state = [KeyState {
            key: POOL.into(),
            commitment: Fr::from(0xc0u64),
            record: None,
        }];
        let inputs = SharedReceiptFound::new(vec![Fr::from(7u64)], f.c, f.shared.clone());
        let entry = QueueEntry {
            index: 0,
            chain_request_id: f.chain,
        };
        let price = PinnedValue {
            param: "price".into(),
            contract: Fr::from(0x1234u64),
            function: "get_price()".into(),
            args: vec![],
            values: vec![Fr::from(0x99u64)],
            previous: None,
            block: 60,
            source: PinnedSource::Simulated,
        };
        let one = |v: Fr| PublicValue::One(FieldHex(v));
        for (pkg, pinned) in [
            (&f.pkg, PinnedValues::default()),
            (&priced, PinnedValues(vec![price])),
        ] {
            let view = SynthesisView {
                namespace: f.ns,
                entry,
                state_keys: &state_keys,
                pinned: &pinned,
                state: &state,
                node_values: &PublicMap::new(),
            };
            let req = synthesise(&view, pkg, &inputs).unwrap().request;
            let mut want = BTreeMap::from([
                ("position".to_string(), one(Fr::from(7u64))),
                ("vk_hash".to_string(), one(pkg.vk_hash)),
                ("inputs_hash".to_string(), one(f.c)),
            ]);
            let fields = pkg.pinned_fields(&pinned).unwrap();
            if !fields.is_empty() {
                want.insert("price".into(), one(Fr::from(0x99u64)));
            }
            assert_eq!(req.public, want, "{}", pkg.tip.public_reads().len());
            assert_eq!(req.shared_inputs, f.shared);
            assert!(req.records.is_empty() && req.requester.is_none() && req.signature.is_none());
            assert_eq!(req.chain_request_id, Some(FieldHex(f.chain)));
            assert_eq!(
                req.request_id.fr(),
                machine_request_id(f.chain, &[Fr::from(0xc0u64)], &fields)
            );
            // another C gives another chain request
            let other =
                SharedReceiptFound::new(vec![Fr::from(7u64)], Fr::from(1u64), f.shared.clone());
            let err = synthesise(&view, pkg, &other).unwrap_err();
            assert_eq!(err.class, ErrorClass::BadRequest);
            assert!(err.message.contains("not the queue entry's"), "{err}");
        }
    }
}
