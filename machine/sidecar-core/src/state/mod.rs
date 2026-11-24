//! Where a key's state lives between rounds, as one interface: the
//! [`StateHolder`] trait, with one implementation per state mode and path.
//! The ones here are [`ClientRecord`] (`client`, the sidecar path: a sealed
//! record the requester carries), [`NodeRow`] (`node`, the sidecar path: one
//! `values` row per key at each node) and [`NodeVersions`] (`node`, the tip:
//! versions anchored to the chain's slot, the `tip_versions` table); the
//! chain-held one (`chain`, the tip) is sidecar-tip's `chain_state`. A node
//! that serves queued intakes installs the tip's holders, sidecar-tip's
//! `holders()` ([`crate::pipeline::Node::with_state_holders`]).
//!
//! A node serves the (mode, path) pairs of its [`StateHolders`]. REGISTER
//! refuses a manifest that gives a key a mode the node does not serve on the
//! manifest's path, or one a holder cannot serve
//! ([`StateHolders::check_register`]); loading a package builds one holder
//! per key from the manifest ([`StateHolders::choose`], kept as the
//! package's [`Holding`]). The request lifecycle then asks the holders what
//! each step needs (steps 4, 7, 8, 10, 12 and 13); holders record what the
//! request row takes in the round's [`RoundEntries`]. The lifecycle never
//! asks a holder which mode it is.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use crate::abi::CircuitShape;
use crate::bind::Elem;
use crate::dead::check_dead;
use crate::error::Refusal;
pub use crate::executor::Rep3State;
use crate::field::Fr;
use crate::grumpkin::Point;
use crate::keys::NodeKeys;
use crate::manifest::{KeyRef, Manifest, StateMode};
use crate::register::prefix_field;
use crate::request::{NodeRequest, NodeStateRecord};
use crate::store::rules::VersionView;
use crate::store::{StoreRead, Txn};
use mpc_net::Network;

mod client;
mod row;
mod tree;
mod versions;

pub use client::ClientRecord;
pub use row::NodeRow;
pub use tree::NodeTree;
pub use versions::{NodeVersions, VersionViews};

/// The two paths a manifest's intake picks: `direct` is the sidecar path,
/// every queued intake the tip.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Path {
    Sidecar,
    Tip,
}

impl Path {
    /// The path of `manifest`, its intake's
    /// ([`crate::intake::IntakeRules::path`]).
    pub fn of(manifest: &Manifest) -> Path {
        manifest.intake.rules().path()
    }

    /// How refusals name it.
    pub fn describe(self) -> &'static str {
        match self {
            Path::Sidecar => "on the sidecar path",
            Path::Tip => "at the tip",
        }
    }
}

/// One commitment slot of a queued round as this node's chain verifier read
/// it: the request key, the commitment the slot holds, and the old
/// commitment the round runs on (the slot's, or the new commitment of this
/// node's latest attempt for the live entry before it).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ChainKey {
    pub key: String,
    pub slot: Fr,
    pub old: Fr,
    /// This node's versions of a node-held key whose orphan mark the chain
    /// no longer holds (`store::rules::VersionView::replaced`), as the
    /// chain verifier checked them; empty for any other key.
    pub replaced: Vec<Fr>,
}

/// What step 4's chain verifier read for a queued round, which the tip's
/// holders load and commit against: the block it read the chain at, the
/// settled block read with it, the queue's head, the queue index of the
/// request's entry, and every commitment slot of the circuit.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct QueueRead {
    pub block: u64,
    /// The hash of `block` as the chain verifier read it
    /// ([`crate::store::TipVersion::block_hash`]).
    pub block_hash: Fr,
    /// The settled block (the node's finalized tip), at or below `block`:
    /// the floor of the node-held versions' retention; 0 where the reader
    /// has not seen the finalized tip move.
    pub settled: u64,
    pub head: u64,
    pub index: u64,
    pub keys: Vec<ChainKey>,
}

impl QueueRead {
    /// The view a round's commit marks `slot`'s key's versions against: the
    /// slot's commitment and replaced marks under this read's block, hash,
    /// head and settled block.
    pub fn view(&self, slot: &ChainKey) -> VersionView {
        VersionView {
            slot: slot.slot,
            head: self.head,
            block: self.block,
            block_hash: self.block_hash,
            settled: self.settled,
            replaced: slot.replaced.clone(),
        }
    }

    /// The slot of the request key `key`, if the circuit has one for it.
    pub fn key(&self, key: &str) -> Option<&ChainKey> {
        self.keys.iter().find(|k| k.key == key)
    }
}

/// What a holder reads for one request at one node: the node's own rows, its
/// keys (a snapshot for the whole request), the namespace, the manifest and
/// the circuit's shape, the request (its supplied records), the requester
/// step 4 authenticated, if the manifest needed one, under a queued intake
/// what the chain verifier read, and from step 12 on the round's public
/// inputs (empty before).
pub struct StateCtx<'a> {
    pub store: &'a dyn StoreRead,
    pub keys: &'a NodeKeys,
    /// This node's index (its party id on the mesh).
    pub node: usize,
    pub namespace: Fr,
    pub manifest: &'a Manifest,
    pub shape: &'a CircuitShape,
    pub req: &'a NodeRequest,
    pub requester: Option<Point>,
    pub chain: Option<&'a QueueRead>,
    pub public_inputs: &'a [Fr],
}

impl StateCtx<'_> {
    /// The record the request supplies under the request key `key`, if any.
    pub fn supplied(&self, key: &str) -> Option<&NodeStateRecord> {
        self.req.records.iter().find(|r| r.key == key)
    }

    /// Step 7 for a key whose state the request supplies: refuse (400) the
    /// record supplied for `key` when a rolled-back round created it
    /// ([`check_dead`]).
    pub fn check_supplied_dead(&self, key: &str) -> Result<(), Refusal> {
        match self.supplied(key) {
            Some(record) => check_dead(self.store, self.namespace, key, record.note_hash.fr()),
            None => Ok(()),
        }
    }
}

/// A state step 8 (or step 10, in the session) loaded: its vector and the
/// note hash it is held under.
pub struct Held {
    pub vec: Vec<Elem>,
    pub note_hash: Fr,
}

/// What one round's holders record for the lifecycle: the supplied records
/// step 8 opened, and the request row's entries of steps 12 and 13 (the
/// keys written to this node's `values` rows, those of them the round
/// created, and this node's third of each sealed record, which the answer
/// carries too). The lifecycle owns one per round and hands it to every
/// holder; a holder records only what its key leaves.
#[derive(Default)]
pub struct RoundEntries {
    opened: BTreeSet<String>,
    stored_keys: Vec<String>,
    created_keys: Vec<String>,
    records: Vec<(String, Fr, Vec<u8>)>,
}

impl RoundEntries {
    /// Step 8: the record the request supplies for `keyref` = `key`, which
    /// the holder opens (409 when the request supplies none).
    pub fn open_record<'a>(
        &mut self,
        at: &StateCtx<'a>,
        keyref: KeyRef,
        key: &str,
    ) -> Result<&'a NodeStateRecord, Refusal> {
        let record = at
            .req
            .records
            .iter()
            .find(|r| r.key == key)
            .ok_or_else(|| {
                Refusal::conflict(format!(
                    "field `records`: no state record for {keyref} = `{key}`"
                ))
            })?;
        self.opened.insert(key.to_string());
        Ok(record)
    }

    /// Step 8, after every load: refuse (400) the first supplied record no
    /// holder opened, as one no `noun` key of the circuit loads.
    pub fn refuse_unopened(&self, at: &StateCtx<'_>, noun: &str) -> Result<(), Refusal> {
        match at
            .req
            .records
            .iter()
            .enumerate()
            .find(|(_, r)| !self.opened.contains(r.key.as_str()))
        {
            Some((k, extra)) => Err(Refusal::bad_request(format!(
                "field `records[{k}]`: circuit `{}` loads no {noun} key `{}`",
                at.manifest.circuit, extra.key
            ))),
            None => Ok(()),
        }
    }

    /// Step 12: `key` was written to this node's `values` row; `created`
    /// when the key had none.
    pub fn stored(&mut self, key: &str, created: bool) {
        if created {
            self.created_keys.push(key.to_string());
        }
        self.stored_keys.push(key.to_string());
    }

    /// Step 13: this node's third `c_i` of the record of `key` it sealed
    /// under `note_hash`.
    pub fn sealed(&mut self, key: &str, note_hash: Fr, c_i: Vec<u8>) {
        self.records.push((key.to_string(), note_hash, c_i));
    }

    /// The keys written to `values` rows, in output order.
    pub fn stored_keys(&self) -> &[String] {
        &self.stored_keys
    }

    /// The keys among [`Self::stored_keys`] the round created.
    pub fn created_keys(&self) -> &[String] {
        &self.created_keys
    }

    /// Each sealed record's key, note hash and this node's third, in output
    /// order.
    pub fn records(&self) -> &[(String, Fr, Vec<u8>)] {
        &self.records
    }
}

/// One state mode: how a key's state is checked at REGISTER, read at steps 7,
/// 8 and 10, and written at steps 12 and 13. Every method but
/// [`Self::stage`] changes nothing in the store; refusals at REGISTER name
/// the field relative to the manifest.
pub trait StateHolder: Send + Sync {
    /// How refusals name a key held here ("client-held").
    fn noun(&self) -> &'static str;

    /// Step 4: whether a request that supplies a record of, or stores, a key
    /// held here must be signed by its requester.
    fn needs_requester(&self) -> bool {
        false
    }

    /// REGISTER, from the manifest alone: refuse (400) a manifest this holder
    /// cannot serve for `keys`, the keys it holds (every holder instance is
    /// asked).
    fn check_manifest(&self, _manifest: &Manifest, _keys: &[KeyRef]) -> Result<(), Refusal> {
        Ok(())
    }

    /// REGISTER on a node: refuse (400) when the node's store backend cannot
    /// serve `keys` ([`crate::store::Store::holds_values`]).
    fn check_store(&self, _keys: &[KeyRef], _holds_values: bool) -> Result<(), Refusal> {
        Ok(())
    }

    /// Step 7: the note hash of the state a round on `key` would spend, or
    /// `None` when there is none (step 8 then refuses 409).
    fn note_hash(&self, at: &StateCtx<'_>, key: &str) -> Result<Option<Fr>, Refusal>;

    /// Step 7, for every key held here: refuse (400) a state of `key` that a
    /// rolled-back round created. A node-held state needs no check (the
    /// rollback restored its row); a supplied record is checked against the
    /// dead records ([`StateCtx::check_supplied_dead`]).
    fn check_dead(&self, _at: &StateCtx<'_>, _key: &str) -> Result<(), Refusal> {
        Ok(())
    }

    /// Step 8: the state of `keyref` = `key` (409 when absent; 400 for a
    /// record that does not open). A holder that opens a supplied record
    /// takes it with [`RoundEntries::open_record`]. A holder that reads the
    /// state inside the session ([`Self::load_in_session`]) returns zeros of
    /// the loaded length here, the step 9 check bind's placeholder.
    fn load(
        &self,
        at: &StateCtx<'_>,
        keyref: KeyRef,
        key: &str,
        round: &mut RoundEntries,
    ) -> Result<Held, Refusal>;

    /// Step 8, after every key loaded: refuse (400) a supplied record that
    /// no holder opened ([`RoundEntries::refuse_unopened`], naming this
    /// holder's keys). A holder that opens no record leaves the check to
    /// the holders that do ([`Holding::check_supplied`]).
    fn check_supplied(&self, _at: &StateCtx<'_>, _round: &RoundEntries) -> Result<(), Refusal> {
        Ok(())
    }

    /// Step 10, the handshake: how the summands of the loaded `key` are
    /// labelled in a refusal ("record `key`", "value `key`"), or `None` when
    /// the handshake carries none for the key because its state is read in
    /// the session ([`Self::load_in_session`]).
    fn summand(&self, key: &str) -> Option<String>;

    /// Step 10, after the handshake: the state of `keyref` = `key` read in
    /// the open session by a joint protocol of the three nodes (the
    /// oblivious tree brick, docs/ARCHITECTURE.md section 6, "The oblivious
    /// tree", "The round"), in place of step 8's placeholder; `None` for a
    /// state step 8 loaded.
    fn load_in_session(
        &self,
        _at: &StateCtx<'_>,
        _keyref: KeyRef,
        _key: &str,
        _net: &dyn Network,
        _state: &mut Rep3State,
    ) -> Result<Option<Held>, Refusal> {
        Ok(None)
    }

    /// Step 12, for a key step 8 loaded: what the transaction records of
    /// the load (the node-held write rule reads it).
    fn mark_loaded(&self, _txn: &mut Txn, _key: &str) {}

    /// Steps 12 and 13: stage the round's new value of `key`, held under
    /// `note_hash`, in `txn`, and record in `round` what the request row
    /// takes of it ([`RoundEntries::stored`], [`RoundEntries::sealed`]).
    fn stage(
        &self,
        at: &StateCtx<'_>,
        txn: &mut Txn,
        key: &str,
        vec: Vec<Elem>,
        note_hash: Fr,
        round: &mut RoundEntries,
    ) -> Result<(), Refusal>;
}

/// Builds the holder of one key from the manifest (a key's layout, flat or
/// tree, picks the implementation).
pub type MakeHolder = fn(&Manifest, KeyRef) -> Arc<dyn StateHolder>;

/// One state mode on one path, with the holder it builds per key.
#[derive(Clone, Copy)]
pub struct HolderEntry {
    pub mode: StateMode,
    pub path: Path,
    pub make: MakeHolder,
}

fn client_record(_: &Manifest, _: KeyRef) -> Arc<dyn StateHolder> {
    Arc::new(ClientRecord)
}

fn node_row(_: &Manifest, _: KeyRef) -> Arc<dyn StateHolder> {
    Arc::new(NodeRow)
}

/// The (mode, path) pairs a node (or an orchestrator) serves, one holder
/// entry per pair. [`StateHolders::core`] serves `client` and `node` on the
/// sidecar path; sidecar-tip's `holders()` adds the tip's modes.
#[derive(Clone)]
pub struct StateHolders {
    held: Vec<HolderEntry>,
}

impl StateHolders {
    /// The holders of sidecar-core on the sidecar path: [`ClientRecord`] and
    /// [`NodeRow`].
    pub fn core() -> StateHolders {
        StateHolders {
            held: vec![
                HolderEntry {
                    mode: StateMode::Client,
                    path: Path::Sidecar,
                    make: client_record,
                },
                HolderEntry {
                    mode: StateMode::Node,
                    path: Path::Sidecar,
                    make: node_row,
                },
            ],
        }
    }

    /// These holders with `entry` serving its (mode, path), replacing any
    /// other.
    pub fn with(mut self, entry: HolderEntry) -> Self {
        self.held
            .retain(|e| (e.mode, e.path) != (entry.mode, entry.path));
        self.held.push(entry);
        self
    }

    /// The entry of `mode` on `path`, if served.
    pub fn get(&self, mode: StateMode, path: Path) -> Option<&HolderEntry> {
        self.held.iter().find(|e| (e.mode, e.path) == (mode, path))
    }

    /// The holder of every key reference the manifest loads or stores, or
    /// the first reference whose mode is not served on the manifest's path.
    /// One holder per key: the references that name one key (a loaded tree
    /// and the reference it is stored back at, [`Manifest::holder_ref`])
    /// share one instance, so what a holder keeps between its load and its
    /// stage within one request is seen by both.
    fn pick(&self, manifest: &Manifest) -> Result<Holding, (KeyRef, StateMode)> {
        let path = Path::of(manifest);
        let mut held: BTreeMap<KeyRef, (StateMode, Arc<dyn StateHolder>)> = BTreeMap::new();
        for (key, mode) in manifest.state_modes() {
            let entry = self.get(mode, path).ok_or((key, mode))?;
            let owner = manifest.holder_ref(key);
            let holder = match held.get(&owner) {
                Some((m, h)) if *m == mode => h.clone(),
                _ => (entry.make)(manifest, owner),
            };
            held.insert(key, (mode, holder));
        }
        Ok(Holding { held })
    }

    /// The holders of a registered manifest's keys (500 for a mode this node
    /// does not serve: REGISTER checked it).
    pub fn choose(&self, manifest: &Manifest) -> Result<Holding, Refusal> {
        self.pick(manifest).map_err(|(key, mode)| {
            Refusal::mpc_failure(format!(
                "circuit `{}`: {key} has the state mode `{}`, which this node does not serve {}",
                manifest.circuit,
                mode.as_str(),
                Path::of(manifest).describe()
            ))
        })
    }

    /// REGISTER's state checks of a manifest (400, naming the field under
    /// `manifest`): every key's mode is served on the manifest's path, and
    /// every holder accepts the keys it holds
    /// ([`StateHolder::check_manifest`]). Returns the holders, for the store
    /// check ([`Holding::check_store`]).
    pub fn check_register(&self, manifest: &Manifest) -> Result<Holding, Refusal> {
        let holding = self.pick(manifest).map_err(|(key, mode)| {
            Refusal::bad_request(format!(
                "field `manifest.state.{key}`: the state mode `{}` is not served by this node {}",
                mode.as_str(),
                Path::of(manifest).describe()
            ))
        })?;
        for (holder, keys) in holding.by_holder() {
            holder
                .check_manifest(manifest, &keys)
                .map_err(|r| prefix_field(r, "manifest"))?;
        }
        Ok(holding)
    }
}

impl Default for StateHolders {
    fn default() -> Self {
        Self::core()
    }
}

/// The holder of every key a manifest loads or stores (not the fixed keys),
/// built once per package.
#[derive(Clone)]
pub struct Holding {
    held: BTreeMap<KeyRef, (StateMode, Arc<dyn StateHolder>)>,
}

impl Holding {
    /// The holder of `key`; `None` for a key the manifest does not use and for
    /// the fixed keys.
    pub fn get(&self, key: KeyRef) -> Option<&dyn StateHolder> {
        self.held.get(&key).map(|(_, h)| h.as_ref())
    }

    /// Every key with its holder, in key reference order.
    pub fn iter(&self) -> impl Iterator<Item = (KeyRef, &dyn StateHolder)> + '_ {
        self.held.iter().map(|(k, (_, h))| (*k, h.as_ref()))
    }

    /// Step 8, after every key loaded: each holder's check of the supplied
    /// records ([`StateHolder::check_supplied`]), in the order of their
    /// first key; a record left unopened where no holder opens records is
    /// refused as one no client-held key loads.
    pub fn check_supplied(&self, at: &StateCtx<'_>, round: &RoundEntries) -> Result<(), Refusal> {
        for (holder, _) in self.by_holder() {
            holder.check_supplied(at, round)?;
        }
        round.refuse_unopened(at, ClientRecord.noun())
    }

    /// Every holder with the keys it holds, in the order of their first
    /// key: one entry per instance (a loaded tree and the reference it is
    /// stored back at share one).
    fn by_holder(&self) -> Vec<(&dyn StateHolder, Vec<KeyRef>)> {
        let mut out: Vec<(&Arc<dyn StateHolder>, Vec<KeyRef>)> = Vec::new();
        for (key, (_, holder)) in &self.held {
            match out.iter_mut().find(|(h, _)| Arc::ptr_eq(h, holder)) {
                Some((_, keys)) => keys.push(*key),
                None => out.push((holder, vec![*key])),
            }
        }
        out.into_iter()
            .map(|(h, keys)| (h.as_ref(), keys))
            .collect()
    }

    /// The keys of each mode with the holder of its first key, in key
    /// reference order, modes in the order of their first key.
    fn by_mode(&self) -> Vec<(&dyn StateHolder, Vec<KeyRef>)> {
        let mut out: Vec<(StateMode, &dyn StateHolder, Vec<KeyRef>)> = Vec::new();
        for (key, (mode, holder)) in &self.held {
            match out.iter_mut().find(|(m, _, _)| m == mode) {
                Some((_, _, keys)) => keys.push(*key),
                None => out.push((*mode, holder.as_ref(), vec![*key])),
            }
        }
        out.into_iter().map(|(_, h, keys)| (h, keys)).collect()
    }

    /// REGISTER on a node: each holder accepts this node's store backend
    /// ([`StateHolder::check_store`]; 400, naming the field under `manifest`).
    pub fn check_store(&self, holds_values: bool) -> Result<(), Refusal> {
        for (holder, keys) in self.by_mode() {
            holder
                .check_store(&keys, holds_values)
                .map_err(|r| prefix_field(r, "manifest"))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
