//! Where a queued round's state comes from, as the scheduler, the
//! synthesiser and the chain verifier see it: the [`TipState`] trait, with
//! one implementation per state mode a queued intake serves: node-held state
//! ([`NodeVersions`], the default) and chain-held state
//! ([`crate::state::chain::ChainTip`]). Each node's own side of a key (step 8
//! and step 15) is sidecar-core's state holder. [`TIP_MODES`] is the one
//! table of the tip's state modes, pairing each mode's holder with its tip
//! state: the holders a node or orchestrator serving queued intakes installs
//! ([`holders`], from which REGISTER's tip check follows) and the tip states
//! packages pick both come from it.
//!
//! The manifest picks one implementation per key, once per package
//! ([`TipPackage::new`], by the key's state mode, built per key from the
//! manifest; a node-held key's flat-or-tree choice is [`TIP_MODES`]' one
//! `node` row). The scheduler, the synthesiser and the verifier hold each
//! key's state as a [`KeyState`] and never compare a state mode; the one
//! check across packages, that every queued package giving a request key
//! gives it one layout, is [`one_layout`], which the scheduler applies
//! through [`key_tip_state`] and each node's REGISTER through
//! [`check_register_keys`]:
//!
//! ```text
//! scheduler   reload     a slot's state when the speculative state is
//!                        discarded (TipState::reload, over a TipHistory)
//!             advance    the state a computed result leaves for each key it
//!                        wrote (TipState::advance)
//! synthesis   the round's old commitment of each key it loads, and what the
//!             request carries for it (KeyState)
//! verifier    the state a received request runs on, checked against this
//!             node's own view (TipState::check)
//! ```
//!
//! [`version_views`] is the node-held prune pass's chain view: between
//! rounds the node's pruning job marks every node-held key's versions
//! against it (sidecar-core's `NodeVersions::prune`).

pub mod chain;
mod node;
pub mod oblivious;
pub mod tree;

pub(crate) use node::SNAPSHOT_HASH;
pub use node::{TreeValues, replaced_marks, version_views};

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use sidecar_core::error::Refusal;
use sidecar_core::field::{Fr, fr_from_hex, fr_to_hex};
use sidecar_core::manifest::{KeyLayout, KeyRef, Manifest, StateMode, TreeAccess};
use sidecar_core::pipeline::{VerifierRows, result_commitments};
use sidecar_core::request::{NodeRequest, StateKeys, StateRecord};
use sidecar_core::response::ExecuteResponse;
use sidecar_core::state::{
    HolderEntry, MakeHolder, NodeTree, NodeVersions, Path, StateHolder, StateHolders,
};
use sidecar_core::store::rules::{VersionView, version_statuses};
use sidecar_core::store::{RequestRow, TipVersion, VersionStatus};
use sidecar_oblivious::{ObliviousMap, ObliviousTree};

use crate::TipManifest;
use crate::chain::rpc::Transport;
use crate::chain::{ChainReader, QueueTarget, ReadError, Snapshot, TaggedLogs};
use crate::state::tree::{PublicMap, TreeSource};
use crate::synth::TipPackage;
use crate::verifier::{Previous, SlotRead, refused};

/// A future a [`TipState`] or [`TipHistory`] method returns (the trait is
/// used as `dyn`, over any chain transport).
pub type TipFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// One key's state as a queued round runs on it: the old commitment the
/// round reads under (the slot's, or the new commitment of the attempt before
/// it) and what the synthesised request carries for the key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyState {
    /// The request key.
    pub key: String,
    /// The old commitment: what the machine request id covers and the chain
    /// verifier checks.
    pub commitment: Fr,
    /// The record the request carries for the key in `records`; `None` where
    /// the request carries nothing for it.
    pub record: Option<StateRecord>,
}

/// What a [`TipState`] reads while the scheduler reloads the live state:
/// the queue and the namespace contract's logs at the step's snapshot, and
/// the registered package an applied chain request ran under.
pub trait TipHistory: Sync {
    /// The queue's head at the snapshot.
    fn head(&self) -> u64;

    /// The chain request id of queue entry `index` when its `done` is
    /// applied (1); `None` while it is pending or after a skip.
    fn applied(&self, index: u64) -> TipFuture<'_, Result<Option<Fr>, ReadError>>;

    /// Every log the namespace contract emitted under `tag`, its fields after
    /// the tag, in chain order.
    fn logs(&self, tag: Fr) -> TipFuture<'_, Result<TaggedLogs, ReadError>>;

    /// The package an applied chain request (or the init round) ran under,
    /// with the schedule's request keys for it; `None` when neither is
    /// found.
    fn package(&self, chain_request_id: Fr) -> TipFuture<'_, Option<(TipPackage, StateKeys)>>;

    /// The init round's chain request id, when the namespace has one and the
    /// contract is configured ([`crate::init`]): a slot the init wrote, with
    /// no apply since, holds the state the init logged.
    fn init(&self) -> Option<Fr>;
}

/// Why a reload found no state for a slot.
#[derive(Clone, Debug, PartialEq)]
pub enum ReloadError {
    Read(ReadError),
    /// Nothing the implementation reads holds the state the slot commits to:
    /// why, completing "slot `key` holds c, and ...".
    Missing(String),
}

impl From<ReadError> for ReloadError {
    fn from(e: ReadError) -> Self {
        ReloadError::Read(e)
    }
}

/// What the chain verifier checks one commitment slot of a received request
/// against: this node's projection of the request, the package, the slot and
/// the queue's head as this node read them, the entry before a pipelined
/// request with this node's latest committed result for it while it is live,
/// and this node's rows.
pub struct TipCheck<'a> {
    /// This node's index (the request is its own projection).
    pub node: usize,
    pub req: &'a NodeRequest,
    pub package: &'a TipPackage,
    pub slot: &'a SlotRead,
    /// The block the verifier read the chain at.
    pub block: u64,
    /// The queue's head at `block`.
    pub head: u64,
    /// The queue entry before the request's, when it is not the head.
    pub previous: Option<Previous>,
    /// This node's latest committed result for `previous`, while that entry
    /// is live (the verifier's latest-attempt rule).
    pub pending: Option<&'a RequestRow>,
    /// This node's own rows, read-only.
    pub rows: &'a dyn VerifierRows,
}

/// One state mode at the tip: what the scheduler holds for a key between
/// rounds, how a result advances it, and how the chain verifier checks a
/// received request's state. No method changes anything.
pub trait TipState: Send + Sync {
    /// Scheduler: the state of `key`, whose slot holds `commitment` (not 0),
    /// at the head of `history`.
    fn reload<'a>(
        &'a self,
        history: &'a dyn TipHistory,
        key: &'a str,
        commitment: Fr,
    ) -> TipFuture<'a, Result<KeyState, ReloadError>>;

    /// Scheduler: the state `response`, the result of a round of `package`,
    /// leaves for the request key `key`, which the round stored under
    /// `store`; `None` when it leaves none.
    fn advance(
        &self,
        package: &TipPackage,
        store: KeyRef,
        key: &str,
        response: &ExecuteResponse,
    ) -> Result<Option<KeyState>, Refusal>;

    /// Chain verifier: the state the request runs `at.slot` on, refused (400)
    /// when it is not this node's view of the slot or of the live result
    /// before it.
    fn check(&self, at: &TipCheck<'_>) -> Result<KeyState, Refusal>;

    /// Chain verifier: the public values a request on `state` carries for
    /// the key besides its state, from this node's own store (a tree key's
    /// paths); the verifier refuses (400, naming the key) a request that
    /// carries others. None by default.
    fn round_values(&self, _at: &TipCheck<'_>, _state: &KeyState) -> Result<PublicMap, Refusal> {
        Ok(PublicMap::new())
    }

    /// Chain verifier: this node's versions of the key among `versions`
    /// whose orphan mark below `settled` the chain no longer holds
    /// (sidecar-core `VersionView::replaced`), checked against the block
    /// hashes `chain` reads; none by default (a key with no orphan marks).
    fn replaced<'a>(
        &'a self,
        _versions: &'a [TipVersion],
        _settled: u64,
        _chain: &'a dyn SettledHashes,
    ) -> TipFuture<'a, Vec<Fr>> {
        Box::pin(async { Vec::new() })
    }

    /// Scheduler: the public values the request synthesised for a round on
    /// `state` carries for `key` besides its state, given the app inputs
    /// `public`, read from the nodes (`trees`). None by default.
    fn node_values<'a>(
        &'a self,
        _package: &'a TipPackage,
        _key: &'a str,
        _state: &'a KeyState,
        _public: &'a PublicMap,
        _trees: &'a dyn TreeSource,
    ) -> TipFuture<'a, Result<PublicMap, Refusal>> {
        Box::pin(async { Ok(PublicMap::new()) })
    }
}

/// The chain's block hashes below the settled block, where no replacement
/// reaches: what a node-held key's orphan marks are confirmed against
/// ([`TipState::replaced`]). The chain reader answers them
/// ([`ChainReader::hash_at_settled`]).
pub trait SettledHashes: Sync {
    /// The hash block `block` (below the settled block) has on the chain;
    /// `None` when the chain has no such block or the node does not answer.
    fn hash_at_settled(&self, block: u64) -> TipFuture<'_, Option<Fr>>;
}

impl<T: Transport> SettledHashes for ChainReader<T> {
    fn hash_at_settled(&self, block: u64) -> TipFuture<'_, Option<Fr>> {
        Box::pin(ChainReader::hash_at_settled(self, block))
    }
}

/// Builds the tip state of one key from the manifest (a key's layout, flat
/// or tree, picks the implementation).
pub type MakeTipState = fn(&TipManifest, KeyRef) -> Arc<dyn TipState>;

/// One state mode at the tip: its node-side holder (sidecar-core's
/// [`sidecar_core::state::StateHolder`]) and its [`TipState`], each built
/// per key.
#[derive(Clone, Copy)]
pub struct TipMode {
    pub mode: StateMode,
    pub holder: MakeHolder,
    pub state: MakeTipState,
}

/// A node-held key's implementation, which serves both seams: its holder at
/// each node and its tip state.
trait NodeHeld: StateHolder + TipState {}

impl<T: StateHolder + TipState> NodeHeld for T {}

/// A node-held key's implementation by its layout, the one place the
/// flat-or-tree choice is made: sidecar-core's `NodeTree` for a key with a
/// `tree` entry ([`crate::state::tree`]), the oblivious tree brick's
/// `ObliviousTree` for one with `access: oblivious`
/// ([`crate::state::oblivious`]), else `NodeVersions`. Its holder and its tip
/// state are this one value.
fn node_held(manifest: &Manifest, key: KeyRef) -> Arc<dyn NodeHeld> {
    match manifest.tree_of(key) {
        Some(layout) if layout.access == TreeAccess::Oblivious && layout.keyed => {
            Arc::new(ObliviousMap::new(layout.clone()))
        }
        Some(layout) if layout.access == TreeAccess::Oblivious => {
            Arc::new(ObliviousTree::new(layout.clone()))
        }
        Some(layout) => Arc::new(NodeTree::new(layout.clone())),
        None => Arc::new(NodeVersions),
    }
}

fn node_held_holder(manifest: &Manifest, key: KeyRef) -> Arc<dyn StateHolder> {
    node_held(manifest, key)
}

fn node_held_tip(tip: &TipManifest, key: KeyRef) -> Arc<dyn TipState> {
    node_held(tip.manifest(), key)
}

/// The tip's state modes: node-held state (the default) and chain-held state
/// (the option for small fixed-size states).
pub const TIP_MODES: &[TipMode] = &[
    TipMode {
        mode: StateMode::Node,
        holder: node_held_holder,
        state: node_held_tip,
    },
    TipMode {
        mode: StateMode::Chain,
        holder: chain::chain_sealed,
        state: chain::chain_tip,
    },
];

/// The state modes of a machine that serves queued intakes: sidecar-core's
/// on the sidecar path ([`StateHolders::core`]) and every [`TIP_MODES`]
/// holder at the tip. A manifest naming a mode no entry serves is refused at
/// REGISTER.
pub fn holders() -> StateHolders {
    TIP_MODES.iter().fold(StateHolders::core(), |held, m| {
        held.with(HolderEntry {
            mode: m.mode,
            path: Path::Tip,
            make: m.holder,
        })
    })
}

/// Each key a package loads or stores with its tip state.
pub(crate) type KeyTipStates = Vec<(KeyRef, Arc<dyn TipState>)>;

/// The tip state of every key `tip` loads or stores, in key reference order,
/// built by its state mode's [`TIP_MODES`] entry; 400 for a mode no entry
/// serves (REGISTER refuses such a manifest).
pub(crate) fn tip_states(tip: &TipManifest) -> Result<KeyTipStates, Refusal> {
    tip.manifest()
        .state_modes()
        .map(|(key, mode)| {
            TIP_MODES
                .iter()
                .find(|m| m.mode == mode)
                .map(|m| (key, (m.state)(tip, key)))
                .ok_or_else(|| {
                    Refusal::bad_request(format!(
                        "circuit `{}`: {key} has the state mode `{}`, which no queued round serves",
                        tip.circuit(),
                        mode.as_str()
                    ))
                })
        })
        .collect()
}

/// The tip state of the request key `key` as the queued `packages` of one
/// namespace, each with its request keys, give it; why not, otherwise: no
/// package loads or stores it, or two give it different layouts
/// ([`one_layout`]). The scheduler's one check of a key across packages,
/// over the request keys of its schedule.
pub fn key_tip_state<'p>(
    packages: impl IntoIterator<Item = (&'p TipPackage, &'p StateKeys)>,
    key: &str,
) -> Result<&'p dyn TipState, String> {
    let packages: Vec<_> = packages.into_iter().collect();
    one_layout(
        packages
            .iter()
            .map(|(pkg, state_keys)| (pkg.name.as_str(), pkg.tip.manifest(), *state_keys)),
        key,
    )?;
    packages
        .into_iter()
        .find_map(|(pkg, state_keys)| pkg.tip_state_of(state_keys, key))
        .ok_or_else(|| "no registered queued package loads or stores it".into())
}

/// The one layout ([`KeyLayout`]: state mode, flat or tree, the tree's
/// shape) that the `packages` (each a name, its manifest and its request
/// keys) that load or store the request key `key` give it; `None` when none
/// does; why not, when two give it different layouts, since every round on
/// the key reads the state the others leave. The one rule of a key across
/// the queued packages of a namespace, which the scheduler
/// ([`key_tip_state`]) and each node's REGISTER ([`check_register_keys`])
/// apply: REGISTER in sidecar-core sees a manifest's keys by position only,
/// and the request keys come from the `[tip.namespaces.circuits]` table.
pub(crate) fn one_layout<'p>(
    packages: impl IntoIterator<Item = (&'p str, &'p Manifest, &'p StateKeys)>,
    key: &str,
) -> Result<Option<KeyLayout>, String> {
    let mut found: Option<(&str, KeyLayout)> = None;
    for (name, manifest, state_keys) in packages {
        let Some(layout) = layout_under(manifest, state_keys, key) else {
            continue;
        };
        match found {
            None => found = Some((name, layout)),
            Some((first, theirs)) if theirs != layout => {
                return Err(format!(
                    "the queued packages `{first}` and `{name}` give it different layouts \
                     ({theirs} and {layout})"
                ));
            }
            Some(_) => {}
        }
    }
    Ok(found.map(|(_, layout)| layout))
}

/// The layout `manifest` gives the request key `key` under `state_keys`, its
/// request keys, when it loads or stores it.
fn layout_under(manifest: &Manifest, state_keys: &StateKeys, key: &str) -> Option<KeyLayout> {
    manifest
        .state_modes()
        .find(|(keyref, _)| request_key(state_keys, *keyref) == Some(key))
        .and_then(|(keyref, _)| manifest.key_layout(keyref))
}

impl TipPackage {
    /// The tip state of `key`; 400 for a key the manifest does not load or
    /// store.
    pub fn tip_state(&self, key: KeyRef) -> Result<&dyn TipState, Refusal> {
        self.states
            .iter()
            .find(|(k, _)| *k == key)
            .map(|(_, state)| state.as_ref())
            .ok_or_else(|| {
                Refusal::bad_request(format!(
                    "circuit `{}`: {key} is not a key the manifest loads or stores",
                    self.name
                ))
            })
    }

    /// The tip state of the request key `key` under `state_keys`, this circuit's
    /// request keys, when the circuit loads or stores it.
    pub fn tip_state_of(&self, state_keys: &StateKeys, key: &str) -> Option<&dyn TipState> {
        self.states
            .iter()
            .find(|(keyref, _)| request_key(state_keys, *keyref) == Some(key))
            .map(|(_, state)| state.as_ref())
    }

    /// Every request key under `state_keys` the circuit loads or stores, in key
    /// reference order.
    pub fn request_keys<'k>(&self, state_keys: &'k StateKeys) -> impl Iterator<Item = &'k str> {
        self.states
            .iter()
            .filter_map(move |(keyref, _)| request_key(state_keys, *keyref))
    }

    /// The state `response`, this circuit's result under `state_keys`, leaves for
    /// each key it stored, in manifest output order.
    pub fn advance(
        &self,
        state_keys: &StateKeys,
        response: &ExecuteResponse,
    ) -> Result<Vec<KeyState>, Refusal> {
        let mut out = Vec::new();
        for output in &self.tip.manifest().outputs {
            let Some(key) = request_key(state_keys, output.store) else {
                continue;
            };
            if out.iter().any(|s: &KeyState| s.key == key) {
                continue;
            }
            if let Some(state) =
                self.tip_state(output.store)?
                    .advance(self, output.store, key, response)?
            {
                out.push(state);
            }
        }
        Ok(out)
    }
}

/// The request key a key reference names under `state_keys`.
pub(crate) fn request_key(state_keys: &StateKeys, key: KeyRef) -> Option<&str> {
    match key {
        KeyRef::Read(i) => state_keys.reads.get(i),
        KeyRef::Write(j) => state_keys.writes.get(j),
        KeyRef::Fixed(_) => None,
    }
    .map(String::as_str)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::Rows;
    use crate::testing::{AMM_SWAP_TIP, AMM_SWAP_TIP_ABI};
    use sidecar_core::abi::check_manifest_value;
    use sidecar_core::error::{ErrorClass, parse_json};
    use sidecar_core::field::{FieldHex, RequestId};
    use sidecar_core::manifest::Manifest;
    use sidecar_core::request::Request;
    use sidecar_core::store::{RequestStatus, TipVersion, VersionStatus};

    const POOL: &str = "0xa002";

    /// The AMM swap manifest with its pool node-held, as text.
    fn node_held() -> String {
        AMM_SWAP_TIP.replace("\"chain\"", "\"node\"")
    }

    fn package() -> TipPackage {
        let value = parse_json(&node_held()).unwrap();
        let abi = parse_json(AMM_SWAP_TIP_ABI).unwrap();
        let (manifest, shape) = check_manifest_value(&value, &abi).unwrap();
        TipPackage::new(
            "amm_swap_tip".into(),
            Fr::from(0x5ab1u64),
            TipManifest::new(manifest, Some(50)).unwrap(),
            shape,
        )
        .unwrap()
    }

    /// Round `n`'s version under `commitment`, built on `parent`.
    fn version(commitment: u64, parent: u64, n: u8) -> TipVersion {
        TipVersion {
            key: POOL.into(),
            commitment: Fr::from(commitment),
            parent: Fr::from(parent),
            index: 1,
            request_id: RequestId::from_u128_bytes([n; 16]),
            vec: vec![],
            tree: None,
            status: VersionStatus::Live,
            block: 5,
            block_hash: Fr::from(0u64),
        }
    }

    /// This node's latest result for the entry before, made by round `n`.
    fn row(n: u8) -> RequestRow {
        RequestRow {
            request_id: RequestId::from_u128_bytes([n; 16]),
            body_hash: Fr::from(0u64),
            vk_hash: Fr::from(0x5ab1u64),
            proof: vec![],
            public_inputs: vec![],
            stored_keys: vec![],
            created_keys: vec![],
            sealed: vec![],
            signature: None,
            status: RequestStatus::Committed,
            created_at: 1,
            chain_request_id: Some(Fr::from(0xc4u64)),
        }
    }

    /// The check of a request whose entry before has this node's latest
    /// result `pending`, with the slot at `slot` and the queue's head at
    /// `head`.
    fn check(
        rows: &Rows,
        slot: u64,
        head: u64,
        pending: Option<&RequestRow>,
    ) -> Result<KeyState, Refusal> {
        check_in(rows, 0x7195, slot, head, pending)
    }

    /// [`check`] of a request under `namespace`.
    fn check_in(
        rows: &dyn VerifierRows,
        namespace: u64,
        slot: u64,
        head: u64,
        pending: Option<&RequestRow>,
    ) -> Result<KeyState, Refusal> {
        let pkg = package();
        let req = Request {
            namespace: FieldHex(Fr::from(namespace)),
            circuit: "amm_swap_tip".into(),
            request_id: RequestId::from_u128_bytes([9; 16]),
            public: Default::default(),
            state_keys: StateKeys {
                reads: vec![POOL.into()],
                writes: vec![POOL.into()],
            },
            shared_inputs: vec![],
            records: vec![],
            requester: None,
            signature: None,
            chain_request_id: Some(FieldHex(Fr::from(0xc5u64))),
            shared_log: None,
            manifest_hash: None,
        }
        .project(0);
        let slot = SlotRead {
            at: KeyRef::Read(0),
            key: POOL.into(),
            slot: Fr::from(0xa002u64),
            commitment: Fr::from(slot),
        };
        let at = TipCheck {
            node: 0,
            req: &req,
            package: &pkg,
            slot: &slot,
            block: 7,
            head,
            previous: None,
            pending,
            rows,
        };
        pkg.tip_state(KeyRef::Read(0)).unwrap().check(&at)
    }

    /// The chain verifier derives one old commitment for a node-held key:
    /// the new commitment of this node's latest attempt for the live entry
    /// before (when that attempt created a version), else the slot's; an
    /// attempt whose parent chain does not reach the slot (an orphan) is
    /// refused; a slot at a commitment this node holds no version of is
    /// refused as a fault; an empty slot (0) is no state and no fault.
    #[test]
    fn a_node_held_key_runs_on_one_expected_commitment() {
        let rows = Rows::with_versions(vec![
            version(0x51, 1, 1),
            version(0x52, 0x51, 2),
            version(0x53, 0x51, 3),
            version(0x55, 0x53, 5),
            version(0x56, 0x50, 6),
        ]);
        let at = |c: u64| KeyState {
            key: POOL.into(),
            commitment: Fr::from(c),
            record: None,
        };
        assert_eq!(check(&rows, 0x51, 1, None).unwrap(), at(0x51));
        // pipelined on round 3's version, not the older attempt's (round 2)
        assert_eq!(check(&rows, 0x51, 1, Some(&row(3))).unwrap(), at(0x53));
        // the latest attempt created no version (an equal commitment): the slot
        assert_eq!(check(&rows, 0x51, 1, Some(&row(4))).unwrap(), at(0x51));
        // an attempt on a live attempt reaches the slot through it
        assert_eq!(check(&rows, 0x51, 1, Some(&row(5))).unwrap(), at(0x55));
        // an attempt on a version the chain left behind is an orphan, as is
        // every attempt once the slot moved to another commitment
        for (slot, n) in [(0x51, 6), (0x52, 3)] {
            let err = check(&rows, slot, 1, Some(&row(n))).unwrap_err();
            assert_eq!(err.class, ErrorClass::BadRequest);
            assert!(err.message.contains("does not build on it"), "{err}");
        }
        // a slot at a commitment this node does not hold stops the key
        let err = check(&rows, 0x99, 1, None).unwrap_err();
        assert_eq!(err.class, ErrorClass::BadRequest);
        assert!(
            err.message.contains("holds no version of: a fault"),
            "{err}"
        );
        assert_eq!(
            check(&Rows::with_versions(vec![]), 0, 1, None).unwrap(),
            at(0)
        );
    }

    /// The pipelined check reads the queue's head as well as the slot: an
    /// attempt whose parent chain passes a version of an entry behind the
    /// head that the slot does not hold (an applied or skipped entry's other
    /// attempt) is refused by index, though its parent chain reaches the
    /// slot; a version behind the head that the slot holds is a parent like
    /// any other.
    #[test]
    fn a_pipelined_attempt_on_an_entry_behind_the_head_is_refused_by_index() {
        let at_index = |commitment, parent, n, index| TipVersion {
            index,
            ..version(commitment, parent, n)
        };
        // entry 0 applied under 0x51; entry 1's attempt 0x52; entry 2's
        // attempts 0x53 on 0x52 and 0x54 on the slot, and 0x56 on a version
        // this node does not hold
        let rows = Rows::with_versions(vec![
            at_index(0x51, 1, 1, 0),
            at_index(0x52, 0x51, 2, 1),
            at_index(0x53, 0x52, 3, 2),
            at_index(0x54, 0x51, 4, 2),
            at_index(0x56, 0x50, 6, 2),
        ]);
        let at = |c: u64| KeyState {
            key: POOL.into(),
            commitment: Fr::from(c),
            record: None,
        };
        // entry 1 still live (head 1): 0x53 reaches the slot through it
        assert_eq!(check(&rows, 0x51, 1, Some(&row(3))).unwrap(), at(0x53));
        // entry 1 skipped (head 2, the slot unchanged): 0x53 is refused by
        // index; 0x54, on the slot's version of entry 0, is accepted
        let err = check(&rows, 0x51, 2, Some(&row(3))).unwrap_err();
        assert_eq!(err.class, ErrorClass::BadRequest);
        assert!(
            err.message
                .contains("builds on a version of an entry behind the head 2"),
            "{err}"
        );
        assert_eq!(check(&rows, 0x51, 2, Some(&row(4))).unwrap(), at(0x54));
        // entry 1 applied under 0x52 (head 2): 0x53 builds on the slot
        assert_eq!(check(&rows, 0x52, 2, Some(&row(3))).unwrap(), at(0x53));
        // the parent-chain rule still refuses first
        let err = check(&rows, 0x51, 2, Some(&row(6))).unwrap_err();
        assert!(err.message.contains("does not build on it"), "{err}");
    }

    /// The index rule on the shape of the AMM's three-party flow: one pool
    /// key in two deployments, the first's non-secret-shared round landed (its head 1),
    /// then the second's rounds from its own head 0. An init version carries
    /// the head's index without a queue entry of its own; the head's own
    /// entry's attempt, and the slot's version behind the head, are parents
    /// like any other; only an attempt on a skipped entry's version is
    /// refused by index, after a recompute as before it.
    #[test]
    fn the_index_rule_accepts_every_attempt_of_a_two_deployment_flow() {
        const PLAIN: u64 = 0x7a50;
        const SHARED: u64 = 0x7a5a;
        let at_index = |commitment, parent, n, index| TipVersion {
            index,
            ..version(commitment, parent, n)
        };
        let rows = Rows::namespaced(vec![
            // the non-secret-shared deployment: init at head 0; its entry 0, an ok =
            // false round, landed with no version (head 1, the slot 0xa0)
            (Fr::from(PLAIN), at_index(0xa0, 0, 0xa0, 0)),
            // the secret-shared deployment: init at its head 0, then entries 0 to
            // 2 on it; entry 3 (0xb4) and entry 4's first attempt (0xb5) on
            // it, then entry 4's recompute (0xb6) on the slot once 3 is
            // skipped
            (Fr::from(SHARED), at_index(0xb0, 0, 0xb0, 0)),
            (Fr::from(SHARED), at_index(0xb1, 0xb0, 0xb1, 0)),
            (Fr::from(SHARED), at_index(0xb2, 0xb1, 0xb2, 1)),
            (Fr::from(SHARED), at_index(0xb3, 0xb2, 0xb3, 2)),
            (Fr::from(SHARED), at_index(0xb4, 0xb3, 0xb4, 3)),
            (Fr::from(SHARED), at_index(0xb5, 0xb4, 0xb5, 4)),
            (Fr::from(SHARED), at_index(0xb6, 0xb3, 0xb6, 4)),
        ]);
        let at = |c: u64| KeyState {
            key: POOL.into(),
            commitment: Fr::from(c),
            record: None,
        };
        let shared = |slot, head, pending: Option<u8>| {
            check_in(&rows, SHARED, slot, head, pending.map(row).as_ref())
        };
        // the non-secret-shared deployment's next round: the init version behind its
        // head is the slot's
        assert_eq!(check_in(&rows, PLAIN, 0xa0, 1, None).unwrap(), at(0xa0));
        // the secret-shared deployment's head 0 runs on its init version, and entry
        // 1 pipelines on entry 0's attempt, whose index is the head's
        assert_eq!(shared(0xb0, 0, None).unwrap(), at(0xb0));
        assert_eq!(shared(0xb0, 0, Some(0xb1)).unwrap(), at(0xb1));
        // entry 0 landed (head 1): entry 2 on entry 1's attempt
        assert_eq!(shared(0xb1, 1, Some(0xb2)).unwrap(), at(0xb2));
        // entries 1 and 2 landed (head 3): entry 5 on entry 4's attempt on
        // the head's
        assert_eq!(shared(0xb3, 3, Some(0xb5)).unwrap(), at(0xb5));
        // entry 3 skipped (head 4, the slot 0xb3): entry 5 on the recompute
        // is accepted, on the first attempt refused by index
        assert_eq!(shared(0xb3, 4, Some(0xb6)).unwrap(), at(0xb6));
        let err = shared(0xb3, 4, Some(0xb5)).unwrap_err();
        assert_eq!(err.class, ErrorClass::BadRequest);
        assert!(
            err.message
                .contains("builds on a version of an entry behind the head 4"),
            "{err}"
        );
        // entry 4's recompute landed (head 5): entry 6 at the head runs on it
        assert_eq!(shared(0xb6, 5, None).unwrap(), at(0xb6));
    }

    /// The scheduler's side: a reload is the slot's commitment with no
    /// record, and a result advances the key to the new commitment its public
    /// inputs carry.
    #[tokio::test]
    async fn a_node_held_key_reloads_and_advances_by_commitment() {
        struct NoHistory;
        impl TipHistory for NoHistory {
            fn head(&self) -> u64 {
                0
            }
            fn applied(&self, _: u64) -> TipFuture<'_, Result<Option<Fr>, ReadError>> {
                unreachable!("a node-held reload reads no history")
            }
            fn logs(&self, _: Fr) -> TipFuture<'_, Result<TaggedLogs, ReadError>> {
                unreachable!("a node-held reload reads no history")
            }
            fn package(&self, _: Fr) -> TipFuture<'_, Option<(TipPackage, StateKeys)>> {
                unreachable!("a node-held reload reads no history")
            }
            fn init(&self) -> Option<Fr> {
                unreachable!("a node-held reload reads no history")
            }
        }
        let pkg = package();
        let state = pkg.tip_state(KeyRef::Read(0)).unwrap();
        let reloaded = state.reload(&NoHistory, POOL, Fr::from(0x51u64)).await;
        assert_eq!(
            reloaded.unwrap(),
            KeyState {
                key: POOL.into(),
                commitment: Fr::from(0x51u64),
                record: None
            }
        );
        // public inputs: namespace, vk_hash, in_slots, out_slots, request_id,
        // old_c, new_c, npk_app_hash, ok, amount_out
        let public_inputs = [
            0x7195u64, 0x5ab1, 0xa002, 0xa002, 0x1d, 0x51, 0x61, 0x99, 1, 9,
        ]
        .map(|x| FieldHex(Fr::from(x)))
        .to_vec();
        let response = ExecuteResponse {
            request_id: RequestId::from_u128_bytes([1; 16]),
            vk_hash: FieldHex(Fr::from(0x5ab1u64)),
            proof: Default::default(),
            public_inputs,
            stored: vec![],
            records: vec![],
            signatures: Default::default(),
        };
        let state_keys = StateKeys {
            reads: vec![POOL.into()],
            writes: vec![POOL.into()],
        };
        assert_eq!(
            pkg.advance(&state_keys, &response).unwrap(),
            [KeyState {
                key: POOL.into(),
                commitment: Fr::from(0x61u64),
                record: None
            }]
        );
    }

    /// The prune pass's chain view: each node-held key's slot commitment
    /// (0 for an empty slot) and the queue's head, at one block, with the
    /// settled block as the reader read it
    /// (`ChainReader::settled`); a key that is not a field is
    /// refused.
    #[tokio::test]
    async fn the_prune_pass_reads_each_slot_and_the_head_at_one_block() {
        use crate::chain::layout::QueueLayout;
        use crate::testing::MemoryChain;
        let chain = std::sync::Arc::new(MemoryChain::new(90));
        let target = QueueTarget {
            contract: Fr::from(0x7195u64),
            layout: QueueLayout::new(Fr::from(12u64)),
        };
        let ids: Vec<Fr> = (1..=5u64).map(Fr::from).collect();
        chain.write_queue(target.contract, target.layout, &ids, 3, 80);
        chain.set_storage(target.contract, Fr::from(0xa002u64), Fr::from(0x51u64));
        chain.node().set_proven(26);
        let reader = ChainReader::new(chain.clone());
        reader.snapshot().await.unwrap();
        chain.node().set_proven(31);
        let snap = reader.snapshot().await.unwrap();
        assert_eq!(
            (reader.held().await.proven, reader.settled().await),
            (31, 26)
        );
        let keys = [POOL, "0xa003"].map(|k| (k.to_string(), Vec::new()));
        let views = version_views(&reader, snap, &target, &keys).await.unwrap();
        let at = |slot: u64| VersionView {
            slot: Fr::from(slot),
            head: 3,
            block: 90,
            block_hash: chain.node().hash(90),
            settled: 26,
            replaced: Vec::new(),
        };
        assert_eq!(views, [at(0x51), at(0)]);
        let err = version_views(&reader, snap, &target, &[("pool".to_string(), Vec::new())])
            .await
            .unwrap_err();
        assert!(matches!(err, ReadError::BadKey { .. }), "{err}");
    }

    /// REGISTER at a tip machine accepts a node-held key on a store with
    /// `values` and refuses it on one without; the tip's holders serve every
    /// mode of the tip-mode table at the tip, sidecar-core's none.
    #[test]
    fn register_accepts_a_node_held_tip_key_on_a_store_with_values() {
        let manifest = Manifest::parse(&parse_json(&node_held()).unwrap()).unwrap();
        let holding = holders().check_register(&manifest).unwrap();
        holding.check_store(true).unwrap();
        let err = holding.check_store(false).unwrap_err();
        assert!(err.message.contains("holds no `values` table"), "{err}");
        for m in TIP_MODES {
            assert!(holders().get(m.mode, Path::Tip).is_some());
        }
        assert!(
            StateHolders::core()
                .get(StateMode::Node, Path::Tip)
                .is_none()
        );
    }

    /// The tree package (machine/circuits/manifests/tip_tree.json) with its tree
    /// `depth` deep: the manifest's entry and the ABI's siblings.
    fn tree_package(depth: u32) -> TipPackage {
        let mut value: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../machine/circuits/manifests/tip_tree.json"
        ))
        .unwrap();
        value["tree"]["$state_keys.reads[0]"]["depth"] = depth.into();
        let mut abi = crate::state::tree::tests::abi();
        let siblings = abi["parameters"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|p| p["name"] == "siblings")
            .unwrap();
        siblings["type"]["type"]["length"] = depth.into();
        let abi = parse_json(&abi.to_string()).unwrap();
        let value = parse_json(&value.to_string()).unwrap();
        let (manifest, shape) = check_manifest_value(&value, &abi).unwrap();
        TipPackage::new(
            format!("tip_tree_{depth}"),
            Fr::from(0x7e57u64),
            TipManifest::new(manifest, Some(50)).unwrap(),
            shape,
        )
        .unwrap()
    }

    /// One request key read and written.
    fn one_key(key: &str) -> StateKeys {
        StateKeys {
            reads: vec![key.into()],
            writes: vec![key.into()],
        }
    }

    /// Two queued packages that give one request key different layouts are
    /// refused, naming both and the layouts: a flat and a tree-valued key of
    /// one state mode (`node`), and two trees of different depths. Packages
    /// that agree, or that give the key under different request keys, pass.
    #[test]
    fn two_packages_that_give_one_key_different_layouts_are_refused() {
        let flat = package();
        let tree = tree_package(16);
        let deeper = tree_package(20);
        let book = one_key(POOL);

        let err = key_tip_state([(&flat, &book), (&tree, &book)], POOL)
            .err()
            .unwrap();
        assert_eq!(
            err,
            "the queued packages `amm_swap_tip` and `tip_tree_16` give it different layouts \
             (`node` flat and `node` tree of depth 16, leaf_len 3, with a header)"
        );
        let err = key_tip_state([(&tree, &book), (&deeper, &book)], POOL)
            .err()
            .unwrap();
        assert!(
            err.contains(
                "(`node` tree of depth 16, leaf_len 3, with a header and `node` tree of depth 20"
            ),
            "{err}"
        );

        key_tip_state([(&tree, &book), (&tree_package(16), &book)], POOL).unwrap();
        let other = one_key("0xa003");
        key_tip_state([(&flat, &book), (&tree, &other)], POOL).unwrap();
        key_tip_state([(&flat, &book), (&tree, &other)], "0xa003").unwrap();
        assert_eq!(
            key_tip_state([(&flat, &book)], "0xa004").err().unwrap(),
            "no registered queued package loads or stores it"
        );
    }
}
