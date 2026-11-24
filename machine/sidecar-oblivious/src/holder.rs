//! The state holder of a tree-valued node-held key with `access: oblivious`
//! (docs/ARCHITECTURE.md section 6, "The oblivious tree": "The round",
//! "Versions, rollback and pipelining" and "Persistence, resync, share refresh,
//! audit"; the keyed map, "The oblivious sparse map", is the same holder over
//! its own [`Layout`]): versions as sidecar-core's `NodeVersions` keeps them,
//! the key's DORAM and the journal of every attempt in the store's `tip_blobs`,
//! and the loads, which run inside the mesh session.
//!
//! The holder is stateless between requests: the DORAM is read from the
//! store at the session's start and written back at the commit. Inside one
//! request (steps 10b to 15, under the namespace lock) the DORAM's blob
//! writes, the sync's result and the round's journal wait in [`Holder`]'s
//! `pending` slot for `stage`; the next session drops what a failed round
//! left there.
//!
//! Blobs of a key (`StoreRead::blob`), each in sidecar-core's blob format
//! (`store::blob`: public bytes, this party's XOR components, copies), so
//! node replacement refreshes them, resync rebuilds them from the
//! neighbours and a backup carries them without knowing this holder:
//!
//! ```text
//! oram            this party's DORAM head (doram::state): configuration, level counters,
//!                 each live level's stamp and query bookkeeping, the speed cache; written
//!                 at every commit that ran a session
//! oram.level.<l>  level l's part (what its build made); written only at the commit after
//!                 a rebuild replaced the level (its stamp moved), deleted when it is gone
//! applied         the commitments whose writes the DORAM holds, oldest first (public)
//! journal.<c>     the attempt c's journal: per slot its read addresses, the raw values they
//!                 held before the round, its write addresses and, once applied, the raw
//!                 values those held before the apply (crate::oram::Journal); kept while
//!                 version c is held or c is applied (see APPLIED)
//! fill            a keyed map's public fill bound: the DORAM's fill count at its last bottom
//!                 rebuild and the accesses since (crate::fill, public)
//! ```
//!
//! A version's DORAM state is the head and levels as committed plus the
//! journals: the sync of the next session undoes and applies journals until
//! the DORAM holds exactly the loaded version's ancestry.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;

use mpc_core::protocols::rep3::id::PartyID;
use mpc_net::Network;
use primitives::{X, XShare, promote_public};
use sha2::{Digest, Sha256};
use sidecar_core::bind::{Elem, Share};
use sidecar_core::codec::{fr_bytes, fr_from_bytes};
use sidecar_core::error::Refusal;
use sidecar_core::field::{Fr, RequestId, fr_to_hex};
use sidecar_core::hash::poseidon2_hash;
use sidecar_core::manifest::{KeyRef, Manifest, TreeAccess, TreeLayout};
use sidecar_core::state::{Held, NodeVersions, Rep3State, RoundEntries, StateCtx, StateHolder};
use sidecar_core::store::blob::Blob;
use sidecar_core::store::{StoreRead, TipVersion, Txn, VersionTree};
use sidecar_core::tree::{self, Touch, fr_u64};

use crate::fill::Bound;
use crate::layout::{Addressing, Layout, MapAddressing, check_shape};
use crate::oram::{
    BlobWrite, Doram, Journal, SlotJournal, field_to_values, indices_to_xor, public_y, share_of,
    values_to_field, window_vector,
};

/// The applied list. Every entry the sync may undo or apply has its
/// journal: a journal lives as long as its version or as long as its
/// entry is on this list, whichever is longer. Every commit of a session
/// deletes each journal whose version is gone and whose entry is off the
/// list ([`Holder::stale_journals`]); sidecar-core's retention deletes
/// versions and leaves their journals to this holder. So an applied orphan
/// keeps its journal after its version until the key's next session undoes
/// it, and every entry on the list has its journal. The entries before the
/// parent of the loaded version's oldest held ancestor are the pruned
/// canonical history the sync takes as the DORAM's base, never undoes and
/// drops from the list.
pub const APPLIED: &str = "applied";

/// The name of the `tip_blobs` row of the journal of the attempt that made
/// the version under `commitment`: `journal.<commitment>`.
pub fn journal_blob(commitment: Fr) -> String {
    format!("{JOURNAL}{}", fr_to_hex(commitment))
}

const JOURNAL: &str = "journal.";

/// Whether `name` is a [`journal_blob`]'s name.
pub fn is_journal_blob(name: &str) -> bool {
    name.starts_with(JOURNAL)
}

/// An applied list's [`APPLIED`] bytes: public bytes only, 32 per
/// commitment.
pub fn encode_applied(list: &[Fr]) -> Vec<u8> {
    Blob::public(list.iter().flat_map(|c| fr_bytes(*c)).collect()).to_bytes()
}

/// The applied list of `key` in its [`APPLIED`] bytes.
pub fn decode_applied(key: &str, bytes: &[u8]) -> Result<Vec<Fr>, Refusal> {
    let blob = Blob::from_bytes(bytes)?;
    if blob.public.len() % 32 != 0 || blob.len() != blob.public.len() {
        return Err(Refusal::mpc_failure(format!(
            "key `{key}`: the applied list is malformed"
        )));
    }
    blob.public
        .chunks(32)
        .map(|c| {
            fr_from_bytes(c)
                .map_err(|e| Refusal::mpc_failure(format!("key `{key}`: the applied list: {e}")))
        })
        .collect()
}

/// The leaf a creating round writes, at a public path in every slot: the
/// header of a tree that has one (docs/ARCHITECTURE.md section 6, "Openings,
/// the append index and the window").
const CREATED_LEAF: u64 = 0;

/// A created tree's append index: one past the leaf its creating round
/// writes, as the clear tree counts it (`tree::next_after`). A headed
/// tree's init writes its header at leaf 0 with `next_index` 1, so the two
/// agree by construction; every later round's public `next_index` is
/// checked against it ([`Holder::next_after`]).
const CREATED_NEXT: u64 = CREATED_LEAF + 1;

/// The default capacity of a keyed map, log2 of its distinct addresses.
pub const DEFAULT_MAP_CAPACITY_LOG2: usize = 18;

fn party(node: usize) -> Result<PartyID, Refusal> {
    PartyID::try_from(node)
        .map_err(|_| Refusal::mpc_failure(format!("oblivious tree: node index {node} is no party")))
}

/// The sync's plan (section 8): the applied attempts to undo, newest
/// first, and the loaded version's ancestors to apply, oldest first, each
/// with its journal; the applied entries kept.
struct Plan {
    kept: Vec<Fr>,
    undo: Vec<(Fr, Journal)>,
    apply: Vec<(Fr, Journal, Vec<Elem>)>,
}

impl Plan {
    /// What the three nodes compare: the two lists of commitments.
    fn hash(&self) -> Fr {
        let mut plan = vec![Fr::from(self.undo.len() as u64)];
        plan.extend(self.undo.iter().map(|(c, _)| *c));
        plan.push(Fr::from(self.apply.len() as u64));
        plan.extend(self.apply.iter().map(|(c, _, _)| *c));
        poseidon2_hash(&plan)
    }

    /// The DORAM accesses the sync makes: every write of every slot it
    /// undoes or applies.
    fn accesses(&self) -> u64 {
        let undo = self.undo.iter().flat_map(|(_, j)| &j.slots);
        let apply = self.apply.iter().flat_map(|(_, j, _)| &j.slots);
        undo.chain(apply).map(|s| s.writes.len() as u64).sum()
    }
}

/// What the sync leaves: the applied list after it, the journals it applied
/// with their old write values, and the session's DORAM accesses so far
/// counted for the fill bound (the sync's and the reads it was told of).
struct Synced {
    applied: Vec<Fr>,
    journals: Vec<(Fr, Journal)>,
    accesses: u64,
}

/// What a session's load leaves for the commit: the DORAM's blob writes
/// (not the DORAM itself, which can be large), the sync's result, the
/// round's journal and the fill bound after the session.
struct Pending<B> {
    request_id: RequestId,
    writes: Vec<BlobWrite>,
    applied: Vec<Fr>,
    journal: Journal,
    /// The journals the sync applied, with their old write values filled in.
    applied_journals: Vec<(Fr, Journal)>,
    fill: B,
}

/// The state mode `node` at the tip for a tree-valued key with `access:
/// oblivious`, over the layout `L`: [`ObliviousTree`] for a dense tree,
/// [`ObliviousMap`] for a keyed map.
pub struct Holder<L: Layout> {
    layout: TreeLayout,
    addressing: L,
    pending: Mutex<Option<Pending<L::Bound>>>,
}

/// The dense oblivious tree's holder.
pub type ObliviousTree = Holder<Addressing>;
/// The keyed map's holder.
pub type ObliviousMap = Holder<MapAddressing>;

impl ObliviousTree {
    /// The holder of a dense tree key with `layout` (`access: oblivious`);
    /// REGISTER checks the shape ([`StateHolder::check_manifest`]).
    pub fn new(layout: TreeLayout) -> Self {
        debug_assert_eq!(layout.access, TreeAccess::Oblivious);
        debug_assert!(!layout.keyed);
        let addressing = Addressing::new(layout.depth, layout.leaf_len);
        Holder::over(layout, addressing)
    }
}

impl ObliviousMap {
    /// The holder of a keyed map with `layout` (`access: oblivious, keyed:
    /// true`); REGISTER checks the shape ([`StateHolder::check_manifest`]).
    pub fn new(layout: TreeLayout) -> Self {
        debug_assert_eq!(layout.access, TreeAccess::Oblivious);
        debug_assert!(layout.keyed);
        let addressing = MapAddressing::new(
            layout.depth,
            layout.leaf_len,
            layout.capacity.unwrap_or(DEFAULT_MAP_CAPACITY_LOG2),
        );
        Holder::over(layout, addressing)
    }
}

impl<L: Layout> Holder<L> {
    fn over(layout: TreeLayout, addressing: L) -> Self {
        Holder {
            layout,
            addressing,
            pending: Mutex::new(None),
        }
    }

    pub fn layout(&self) -> &TreeLayout {
        &self.layout
    }

    pub fn addressing(&self) -> &L {
        &self.addressing
    }

    /// The commitments applied to the DORAM, oldest first.
    fn applied(store: &dyn StoreRead, ns: Fr, key: &str) -> Result<Vec<Fr>, Refusal> {
        match store.blob(ns, key, APPLIED)? {
            Some(bytes) => decode_applied(key, &bytes),
            None => Ok(vec![]),
        }
    }

    /// The journals of `key` a commit whose applied list is `applied` and
    /// whose new version (or kept parent) is `new` deletes: those whose
    /// version is not held and whose entry is off the list (undone, never
    /// applied, or dropped as the pruned base), so nothing is left for them
    /// to undo.
    fn stale_journals(
        store: &dyn StoreRead,
        ns: Fr,
        key: &str,
        applied: &[Fr],
        new: Fr,
    ) -> Result<Vec<String>, Refusal> {
        let mut keep: BTreeSet<String> = store
            .tip_versions(ns, key)?
            .iter()
            .map(|v| journal_blob(v.commitment))
            .collect();
        keep.extend(applied.iter().map(|c| journal_blob(*c)));
        keep.insert(journal_blob(new));
        Ok(store
            .blob_names(ns, key)?
            .into_iter()
            .filter(|name| is_journal_blob(name) && !keep.contains(name))
            .collect())
    }

    /// The ancestry of `old` among the held versions, oldest first, `old` last.
    fn ancestry(versions: &BTreeMap<Fr, TipVersion>, old: Fr) -> Vec<Fr> {
        let mut out = vec![];
        let mut at = old;
        let mut seen = BTreeSet::new();
        while at != Fr::from(0u64) && seen.insert(at) {
            let Some(v) = versions.get(&at) else { break };
            out.push(at);
            at = v.parent;
        }
        out.reverse();
        out
    }

    fn journal_of(
        store: &dyn StoreRead,
        ns: Fr,
        key: &str,
        c: Fr,
        verb: &str,
    ) -> Result<Journal, Refusal> {
        let bytes = store.blob(ns, key, &journal_blob(c))?.ok_or_else(|| {
            Refusal::mpc_failure(format!(
                "key `{key}`: no journal of attempt {} to {verb} (resync this node)",
                fr_to_hex(c)
            ))
        })?;
        Journal::from_bytes(&bytes)
    }

    /// The sync's plan for the version `old` the round loads (section 8):
    /// undo the applied attempts that are not `old`'s ancestors, newest
    /// first; apply `old`'s ancestors not yet applied, oldest first. `store`
    /// is this node's, read under namespace `ns`.
    fn plan(&self, store: &dyn StoreRead, ns: Fr, key: &str, old: Fr) -> Result<Plan, Refusal> {
        let versions: BTreeMap<Fr, TipVersion> = store
            .tip_versions(ns, key)?
            .into_iter()
            .map(|v| (v.commitment, v))
            .collect();
        let ancestry = Self::ancestry(&versions, old);
        let applied = Self::applied(store, ns, key)?;
        // the applied entries up to the parent of the oldest held ancestor
        // are the pruned canonical history: the DORAM's base (an applied
        // orphan after it is undone whether or not its version is held: a
        // resynced node holds no orphaned versions, only their journals)
        let base = ancestry
            .first()
            .and_then(|a| versions.get(a))
            .and_then(|a| applied.iter().position(|c| *c == a.parent))
            .map_or(0, |p| p + 1);
        let applied = &applied[base..];
        let common = applied
            .iter()
            .zip(&ancestry)
            .take_while(|(a, b)| a == b)
            .count();
        let per_slot = self.addressing.reads_per_slot();
        let undo = applied[common..]
            .iter()
            .rev()
            .map(|c| Ok((*c, Self::journal_of(store, ns, key, *c, "undo")?)))
            .collect::<Result<Vec<_>, Refusal>>()?;
        let apply = ancestry[common..]
            .iter()
            .map(|c| {
                let version = versions.get(c).expect("an ancestor is held");
                let journal = Self::journal_of(store, ns, key, *c, "apply")?;
                if version.vec.len() != journal.slots.len() * per_slot
                    || journal.slots.iter().any(|s| s.writes.len() != per_slot)
                {
                    return Err(Refusal::mpc_failure(format!(
                        "key `{key}`: attempt {} stores {} elements for {} slots",
                        fr_to_hex(*c),
                        version.vec.len(),
                        journal.slots.len()
                    )));
                }
                Ok((*c, journal, version.vec.clone()))
            })
            .collect::<Result<Vec<_>, Refusal>>()?;
        Ok(Plan {
            kept: applied[..common].to_vec(),
            undo,
            apply,
        })
    }

    /// The sync of the DORAM to the version `old` the round loads, for a
    /// session that then makes `reads` more DORAM accesses: the plan
    /// ([`Self::plan`]); the three nodes' agreement on it and on the
    /// DORAM's public state ([`agree`]); the fill bound's admission of the
    /// session's accesses, before the first ([`Bound::admit`]); then the
    /// undos and applies. `store` is node `node`'s, read under namespace
    /// `ns`.
    #[allow(clippy::too_many_arguments)]
    fn sync(
        &self,
        store: &dyn StoreRead,
        ns: Fr,
        node: usize,
        key: &str,
        doram: &mut Doram<L>,
        fill: &L::Bound,
        reads: u64,
        old: Fr,
        net: &dyn Network,
        state: &mut Rep3State,
    ) -> Result<Synced, Refusal> {
        let plan = self.plan(store, ns, key, old)?;
        let accesses = plan.accesses() + reads;
        let public = state_digest(doram, fill, accesses);
        agree(net, node, key, plan.hash(), public)?;
        fill.admit(doram.schedule(), accesses, key)?;

        for (_, journal) in &plan.undo {
            doram.undo(journal, net, state)?;
        }
        let per_slot = self.addressing.reads_per_slot();
        let mut applied_journals = Vec::with_capacity(plan.apply.len());
        let mut after = plan.kept;
        for (c, mut journal, vec) in plan.apply {
            let shares: Vec<Share> = vec.iter().map(|e| share_of(state.id, e)).collect();
            let values = field_to_values(&shares, net, state)?;
            for (k, slot) in journal.slots.iter_mut().enumerate() {
                slot.old_writes = doram.write_slot(
                    &slot.writes,
                    &values[k * per_slot..(k + 1) * per_slot],
                    net,
                    state,
                )?;
            }
            after.push(c);
            applied_journals.push((c, journal));
        }
        Ok(Synced {
            applied: after,
            journals: applied_journals,
            accesses,
        })
    }

    /// The public values of the request, flattened.
    fn public(at: &StateCtx<'_>) -> Result<BTreeMap<String, Fr>, Refusal> {
        Ok(at.req.flatten_public()?.into_iter().collect())
    }

    /// `$new_leaf`'s value in the request (0 when the layout opens nothing).
    fn new_leaf(at: &StateCtx<'_>, public: &BTreeMap<String, Fr>) -> u64 {
        at.manifest
            .new_leaf_param()
            .and_then(|param| public.get(param).copied())
            .and_then(fr_u64)
            .unwrap_or(0)
    }

    /// Whether the round's public opening flag (`open`) is 1.
    fn opens(&self, public: &BTreeMap<String, Fr>) -> bool {
        self.layout
            .open
            .as_deref()
            .and_then(|o| public.get(o))
            .is_some_and(|v| *v == Fr::from(1u64))
    }

    /// The header's append index after the round, from the public output the
    /// layout names; `base`, the nodes' append index before it, when it names
    /// none. The header and the nodes agree: the output is `base`, or
    /// `base + 1` on an opening round (500 otherwise, nothing stored).
    fn next_after(&self, at: &StateCtx<'_>, base: u64, opens: bool) -> Result<u64, Refusal> {
        let Some(name) = &self.layout.next_index else {
            return Ok(base);
        };
        let next = at
            .shape
            .return_index(name)
            .and_then(|i| at.public_inputs.get(i).copied())
            .and_then(fr_u64)
            .ok_or_else(|| {
                Refusal::mpc_failure(format!(
                    "the round's public inputs carry no `{name}` (the header's append index)"
                ))
            })?;
        if next_agrees(base, next, opens) {
            Ok(next)
        } else {
            Err(Refusal::mpc_failure(format!(
                "the round's `{name}` is {next} and the nodes' append index is {base}{}: the \
                 header and the nodes disagree, nothing was stored",
                if opens { " (an opening round)" } else { "" }
            )))
        }
    }

    /// The journal of a creating round: every slot at the public path 0, the
    /// empty tree's values as the old ones (so undoing the creation restores
    /// the empty tree), already applied in form.
    fn public_journal_empty(&self, id: PartyID, slots: usize) -> Journal {
        let old: Vec<_> = self
            .addressing
            .empty_reads()
            .iter()
            .map(|v| public_y(id, *v))
            .collect();
        let old_writes: Vec<_> = self
            .addressing
            .empty_writes()
            .iter()
            .map(|v| public_y(id, *v))
            .collect();
        let path = promote_public(id, CREATED_LEAF as X);
        let slot = SlotJournal {
            reads: self.addressing.slot_reads(id, &path),
            old,
            writes: self.addressing.slot_writes(id, &path),
            old_writes,
        };
        Journal {
            slots: vec![slot; slots],
        }
    }
}

/// Whether a round's public append index `next` agrees with the nodes'
/// `base`: unchanged, or one more on an opening round.
fn next_agrees(base: u64, next: u64, opens: bool) -> bool {
    next == base || (opens && next == base + 1)
}

/// The digest of what is public about a key's DORAM at a session's start
/// and equal at the three nodes by design: the head's public bytes (the
/// configuration, the level counters and stamps, each live level's query
/// count, touched slots and last query, the speed cache's fill; every one
/// opened to all three or computed from what is), the fill bound's bytes
/// and the session's DORAM access count. No share byte enters it.
fn state_digest<L: Layout>(doram: &Doram<L>, fill: &L::Bound, accesses: u64) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"pss oblivious state\0");
    for part in [doram.head_public(), fill.public()] {
        h.update((part.len() as u64).to_le_bytes());
        h.update(&part);
    }
    h.update(accesses.to_le_bytes());
    h.finalize().into()
}

/// The three nodes' agreement before a session touches the joint DORAM:
/// each sends its plan's hash and its [`state_digest`] to both neighbours
/// and compares theirs. Another plan is a diverged applied list; another
/// digest a diverged DORAM (one node committed a session the others did
/// not), which would otherwise run the joint protocol over different
/// states and fail deep in it. Either way the operator resyncs the
/// diverged node from its neighbours. A node takes both neighbours'
/// messages before it judges them, so a node that refuses has received
/// every message sent to it and leaves no neighbour's send to it failing.
fn agree(
    net: &dyn Network,
    node: usize,
    key: &str,
    plan: Fr,
    public: [u8; 32],
) -> Result<(), Refusal> {
    let mut own = fr_bytes(plan).to_vec();
    own.extend_from_slice(&public);
    let bytes = mpc_net::bytes::Bytes::from(own.clone());
    let (next, prev) = ((node + 1) % 3, (node + 2) % 3);
    let failed = |e: eyre::Report| {
        Refusal::mpc_failure(format!("oblivious tree: the sync exchange failed: {e}"))
    };
    net.send(next, bytes.clone())
        .and_then(|_| net.send(prev, bytes))
        .map_err(failed)?;
    let received = [prev, next].map(|from| net.recv(from).map(|theirs| (from, theirs)));
    for got in received {
        let (from, theirs) = got.map_err(failed)?;
        if theirs.len() != own.len() || theirs[..32] != own[..32] {
            return Err(Refusal::bad_request(format!(
                "key `{key}`: node {from} plans another sync of the oblivious state (a diverged \
                 DORAM at one node: the operator resyncs it from its neighbours)"
            )));
        }
        if theirs[32..] != own[32..] {
            return Err(Refusal::mpc_failure(format!(
                "key `{key}`: diverged oblivious state: resync (node {from}'s DORAM head or fill \
                 bound differs from this node's; the operator resyncs the diverged node from its \
                 neighbours)"
            )));
        }
    }
    Ok(())
}

impl<L: Layout> Holder<L> {
    /// Stage what a session left in `txn` (a commit at all three nodes,
    /// with or without a new version): the DORAM's blob writes, the applied
    /// list, the applied journals' old write values, the fill bound, and the
    /// deletion of the journals left with nothing to undo (`new` is the
    /// round's new version, or the parent it keeps).
    fn stage_session(
        at: &StateCtx<'_>,
        txn: &mut Txn,
        key: &str,
        p: Pending<L::Bound>,
        new: Fr,
    ) -> Result<(), Refusal> {
        for (name, bytes) in p.writes {
            txn.blob(key, &name, bytes);
        }
        txn.blob(key, APPLIED, Some(encode_applied(&p.applied)));
        for (c, j) in &p.applied_journals {
            txn.blob(key, &journal_blob(*c), Some(j.to_bytes()));
        }
        if let Some((name, bytes)) = p.fill.write() {
            txn.blob(key, &name, bytes);
        }
        for name in Self::stale_journals(at.store, at.namespace, key, &p.applied, new)? {
            txn.blob(key, &name, None);
        }
        Ok(())
    }
}

impl<L: Layout> StateHolder for Holder<L> {
    fn noun(&self) -> &'static str {
        "node-held"
    }

    /// REGISTER: the tree entry of the key held here (this holder's layout,
    /// built from that entry) has a shape its brick can serve
    /// ([`check_shape`]: depth, leaf length, capacity and probe within the
    /// bricks' bounds, a DORAM hierarchy the vendored DORAM takes). Checked
    /// before any DORAM exists, so a shape the brick cannot serve is a 400
    /// at REGISTER, never a failure at the first session.
    fn check_manifest(&self, _manifest: &Manifest, keys: &[KeyRef]) -> Result<(), Refusal> {
        for key in keys {
            check_shape(&self.layout).map_err(|e| {
                Refusal::bad_request(format!("field `tree.{key}.{}", e.trim_start_matches('`')))
            })?;
        }
        Ok(())
    }

    fn check_store(&self, keys: &[KeyRef], holds_values: bool) -> Result<(), Refusal> {
        NodeVersions.check_store(keys, holds_values)
    }

    fn note_hash(&self, _at: &StateCtx<'_>, _key: &str) -> Result<Option<Fr>, Refusal> {
        Ok(None)
    }

    /// Step 8: the version the round loads exists; its vector is the zero
    /// placeholder of the loaded length (the real values come in the
    /// session, [`Self::load_in_session`]).
    fn load(
        &self,
        at: &StateCtx<'_>,
        keyref: KeyRef,
        key: &str,
        _round: &mut RoundEntries,
    ) -> Result<Held, Refusal> {
        let version = NodeVersions::loaded(at, keyref, key)?;
        Ok(Held {
            vec: vec![Elem::Public(Fr::from(0u64)); self.layout.loaded_len()],
            note_hash: version.commitment,
        })
    }

    /// The handshake carries no summand of the key: its values are read in
    /// the session.
    fn summand(&self, _key: &str) -> Option<String> {
        None
    }

    /// Step 10b (docs/ARCHITECTURE.md section 6, "The oblivious tree", "The
    /// round"): everything that can refuse from this node's own data first (the
    /// version, the shared index or key inputs, the stored DORAM and fill
    /// bound), then the sync with the three nodes' agreement and the fill
    /// bound's admission, all before the first DORAM access; then the indices
    /// or keys to XOR-shared paths, one batched read per slot and per window,
    /// the values back to arithmetic shares in the loaded vector's layout.
    fn load_in_session(
        &self,
        at: &StateCtx<'_>,
        keyref: KeyRef,
        key: &str,
        net: &dyn Network,
        state: &mut Rep3State,
    ) -> Result<Option<Held>, Refusal> {
        // a failed round's leftovers go now
        drop(self.pending.lock().expect("the pending slot").take());
        let id = party(at.node)?;
        let version = NodeVersions::loaded(at, keyref, key)?;
        let old = version.commitment;

        // the slots' paths: the header's and an unused slot's leaf 0, an
        // opening's $new_leaf, else the shared index or key input
        let layout = &self.layout;
        let public = Self::public(at)?;
        let used = Touch::used_inputs(layout, &public);
        let opens = self.opens(&public);
        let new_leaf = Self::new_leaf(at, &public);
        let mut shared: Vec<(usize, Share)> = Vec::new();
        let mut paths: Vec<XShare> = Vec::with_capacity(layout.probe);
        for k in 0..layout.probe {
            let position = k.checked_sub(layout.first_position());
            let path = match position {
                None => promote_public(id, 0 as X),
                Some(j) if j >= used => promote_public(id, 0 as X),
                Some(0) if opens => promote_public(id, new_leaf as X),
                Some(j) => {
                    let share = at.manifest.intake.share_source().share(
                        at.keys,
                        at.node,
                        at.req,
                        &layout.index[j],
                    )?;
                    shared.push((k, share));
                    promote_public(id, 0 as X)
                }
            };
            paths.push(self.addressing.mask_path(&path));
        }
        let window = tree::window(layout, &public);
        let window_reads = match (&layout.window, window.first()) {
            (Some(w), Some(start)) => self.addressing.window_reads(id, *start, w.width),
            _ => vec![],
        };
        let per = self.addressing.reads_per_slot();
        let reads = (layout.probe * per + window_reads.len()) as u64;

        let mut doram = match Doram::load(self.addressing, id, at.store, at.namespace, key)? {
            Some(doram) => doram,
            None => Doram::build_empty(self.addressing, net, state)?,
        };
        let fill = L::Bound::load(at.store, at.namespace, key)?;
        let bottom = doram.bottom_stamp();
        let synced = self.sync(
            at.store,
            at.namespace,
            at.node,
            key,
            &mut doram,
            &fill,
            reads,
            old,
            net,
            state,
        )?;

        let converted = indices_to_xor(
            &self.addressing,
            &shared.iter().map(|(_, s)| *s).collect::<Vec<_>>(),
            net,
            state,
        )?;
        for ((k, _), x) in shared.iter().zip(converted) {
            paths[*k] = x;
        }

        // the reads: one batch per slot, then one per window leaf block
        let mut journal = Journal::default();
        let mut raw = Vec::new();
        for path in &paths {
            let read = doram.read_slot(path, net, state)?;
            raw.extend(read.values.iter().copied());
            journal.slots.push(SlotJournal {
                reads: read.reads,
                old: read.raw,
                writes: self.addressing.slot_writes(id, path),
                old_writes: vec![],
            });
        }
        raw.extend(doram.read_raw(&window_reads, net, state)?);
        let values = values_to_field(&raw, net, state)?;

        // the loaded vector: leaves, old hashes, siblings, then the window
        let (d, k) = (layout.depth as usize, layout.probe);
        let mut vec: Vec<Elem> = Vec::with_capacity(layout.loaded_len());
        for slot in 0..k {
            vec.extend(
                values[slot * per + d + 1..(slot + 1) * per]
                    .iter()
                    .map(|s| Elem::Shared(*s)),
            );
        }
        for slot in 0..k {
            vec.push(Elem::Shared(values[slot * per + d]));
        }
        for slot in 0..k {
            vec.extend(
                values[slot * per..slot * per + d]
                    .iter()
                    .map(|s| Elem::Shared(*s)),
            );
        }
        if let Some(wd) = &layout.window {
            vec.extend(window_vector(
                &self.addressing,
                wd.width,
                &values[k * per..],
            ));
        }
        debug_assert_eq!(vec.len(), layout.loaded_len());

        let rebuilt = doram.bottom_stamp() != bottom;
        let fill = fill.after(rebuilt, doram.fill_count(), synced.accesses);
        *self.pending.lock().expect("the pending slot") = Some(Pending {
            request_id: at.req.request_id,
            writes: doram.writes()?,
            applied: synced.applied,
            journal,
            applied_journals: synced.journals,
            fill,
        });
        Ok(Some(Held {
            vec,
            note_hash: old,
        }))
    }

    /// Step 15: the version (its vector the round's stored leaves, hashes
    /// and path nodes) and its journal, with what the session left
    /// ([`Self::stage_session`]). A round that leaves the commitment
    /// unchanged (or 0) stages no version but still what its session left,
    /// so the DORAM the session advanced is the one the next session loads
    /// and no query is repeated under the same level keys (persisted at the
    /// commit, the step at which all three nodes persist a version; a
    /// partial commit is the divergence the sync's [`agree`] catches). A
    /// creating round (no session load) journals the public path 0 with the
    /// empty tree's values; the DORAM itself is built at the first session
    /// that loads the key.
    fn stage(
        &self,
        at: &StateCtx<'_>,
        txn: &mut Txn,
        key: &str,
        vec: Vec<Elem>,
        note_hash: Fr,
        _round: &mut RoundEntries,
    ) -> Result<(), Refusal> {
        let parent = NodeVersions::old(at, key)?;
        let pending = self
            .pending
            .lock()
            .expect("the pending slot")
            .take()
            .filter(|p| p.request_id == at.req.request_id);
        if note_hash == Fr::from(0u64) || note_hash == parent {
            if let Some(p) = pending {
                Self::stage_session(at, txn, key, p, parent)?;
            }
            return NodeVersions::stage_version(at, txn, key, None);
        }
        if vec.len() != self.layout.vector_len() {
            return Err(Refusal::mpc_failure(format!(
                "key `{key}`: the round stored {} elements, the layout gives {}",
                vec.len(),
                self.layout.vector_len()
            )));
        }
        let id = party(at.node)?;
        let base_next = if parent == Fr::from(0u64) {
            CREATED_NEXT
        } else {
            at.store
                .tip_version(at.namespace, key, parent)?
                .and_then(|v| v.tree)
                .map_or(0, |t| t.next())
        };
        let next = self.next_after(at, base_next, self.opens(&Self::public(at)?))?;
        let journal = match &pending {
            Some(p) => p.journal.clone(),
            None if parent == Fr::from(0u64) => self.public_journal_empty(id, self.layout.probe),
            None => {
                return Err(Refusal::mpc_failure(format!(
                    "key `{key}`: the round loaded the key outside the session"
                )));
            }
        };
        txn.blob(key, &journal_blob(note_hash), Some(journal.to_bytes()));
        if let Some(p) = pending {
            Self::stage_session(at, txn, key, p, note_hash)?;
        }
        let tree = VersionTree::Blobs { next };
        let new = NodeVersions::version(at, key, parent, note_hash, vec, Some(tree));
        NodeVersions::stage_version(at, txn, key, new)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fill::{FILL, Fill, Unbounded};
    use ark_ff::PrimeField;
    use mpc_core::protocols::rep3::conversion::A2BType;
    use primitives::{open_many_y, run_parties};
    use sidecar_core::error::ErrorClass;
    use sidecar_core::field::FieldHex;
    use sidecar_core::state::{ChainKey, NodeVersions, QueueRead};
    use sidecar_core::store::rules::VersionView;
    use sidecar_core::store::testing::node_keys;
    use sidecar_core::store::testing::{id, ns, tip_round};
    use sidecar_core::store::{MemoryStore, Store, VersionStatus};
    use sidecar_core::tree::{leaf_hash, node};

    const D: u32 = 4;
    const W: usize = 2;
    const KEY: &str = "0xa003";

    /// The clear tree of depth 4 with `leaves` set, level by level.
    fn levels(leaves: &[(u64, [u64; W])]) -> Vec<Vec<Fr>> {
        let mut level = vec![Fr::from(0u64); 1 << D];
        for (i, leaf) in leaves {
            let leaf: Vec<Fr> = leaf.iter().map(|x| Fr::from(*x)).collect();
            level[*i as usize] = leaf_hash(ns(), Fr::from(0xa003u64), *i, &leaf);
        }
        let mut out = vec![level.clone()];
        for _ in 0..D {
            level = (0..level.len() / 2)
                .map(|p| node(level[2 * p], level[2 * p + 1]))
                .collect();
            out.push(level.clone());
        }
        out
    }

    /// What a slot read of leaf `i` returns: siblings bottom up, the leaf
    /// hash, the elements.
    fn read_of(leaves: &[(u64, [u64; W])], i: u64) -> Vec<Fr> {
        let t = levels(leaves);
        let mut out: Vec<Fr> = (0..D as usize)
            .map(|h| t[h][((i >> h) ^ 1) as usize])
            .collect();
        out.push(t[0][i as usize]);
        let leaf = leaves.iter().find(|(j, _)| *j == i).map_or([0; W], |l| l.1);
        out.extend(leaf.iter().map(|x| Fr::from(*x)));
        out
    }

    /// The vector a round that leaves `leaves` stores for its one slot at
    /// leaf `i`: the elements, the leaf hash, the path nodes of heights 1
    /// to D.
    fn stored(leaves: &[(u64, [u64; W])], i: u64) -> Vec<Elem> {
        let t = levels(leaves);
        let leaf = leaves.iter().find(|(j, _)| *j == i).map_or([0; W], |l| l.1);
        let mut out: Vec<Fr> = leaf.iter().map(|x| Fr::from(*x)).collect();
        out.push(t[0][i as usize]);
        out.extend((1..=D as usize).map(|h| t[h][(i >> h) as usize]));
        out.into_iter().map(Elem::Public).collect()
    }

    fn version(c: u64, parent: u64, index: u64, vec: Vec<Elem>) -> TipVersion {
        TipVersion {
            key: KEY.into(),
            commitment: Fr::from(c),
            parent: Fr::from(parent),
            index,
            request_id: id(c as u8),
            vec,
            tree: None,
            status: VersionStatus::Live,
            block: 0,
            block_hash: Fr::from(0u64),
        }
    }

    /// The sync across a fork, and the retention of journals under the
    /// per-level persistence, three parties on one store each. Versions:
    /// c1 (entry 0) writes leaf 3 on the empty tree; c2 (entry 1) writes
    /// leaf 5 on c1; f2 (entry 1, an orphaned attempt) writes leaf 5
    /// otherwise on c1. A round on f2 applies c1 then f2; a round on c2
    /// then undoes f2 and applies c2, and the DORAM reads exactly c2's tree;
    /// once retention deletes c1 and f2, both journals stay (retention
    /// leaves journals to the holder) until the key's next commit, a round
    /// on c2, which deletes undone f2's and, taking c1 as the DORAM's base,
    /// drops c1's. Then c3 (entry 2) writes leaf 6 on c2 and g3
    /// (entry 2, an orphaned attempt) writes leaf 6 otherwise on c2; a
    /// round on g3 applies g3 and no round touches the key while c3 lands
    /// and retention deletes c2 and g3: g3, an applied orphan, keeps its
    /// journal past its version, the next round on c3 undoes it and
    /// applies c3, and its commit deletes the journal. Throughout, every
    /// applied entry keeps its journal; after every commit every journal
    /// belongs to a held version or an applied entry; and retention leaves
    /// the persisted head and levels, which load to c2's tree.
    #[test]
    fn the_sync_undoes_a_fork_and_an_applied_orphan_whose_version_is_gone() {
        let (c1, c2, f2) = (0xc1u64, 0xc2u64, 0xf2u64);
        let one = [(3u64, [30u64, 7u64])];
        let two = [(3u64, [30u64, 7u64]), (5, [50, 8])];
        let fork = [(3u64, [30u64, 7u64]), (5, [99, 1])];
        let layout: TreeLayout = serde_json::from_value(serde_json::json!({
            "depth": D, "leaf_len": W, "probe": 1, "access": "oblivious"
        }))
        .unwrap();
        let holder = ObliviousTree::new(layout);
        let a = *holder.addressing();
        let frs = |v: Vec<Fr>| v.iter().map(|x| x.into_bigint()).collect::<Vec<_>>();
        run_parties(|net| {
            let mut state = Rep3State::new(&net, A2BType::Direct).unwrap();
            let id = state.id;
            let node = usize::from(id);
            let store = MemoryStore::default();
            let journal = |leaf: u64| Journal {
                slots: vec![SlotJournal {
                    reads: a.slot_reads(id, &promote_public(id, leaf as X)),
                    old: vec![],
                    writes: a.slot_writes(id, &promote_public(id, leaf as X)),
                    old_writes: vec![],
                }],
            };
            let view = |slot: u64, head: u64, block: u64, settled: u64| VersionView {
                slot: Fr::from(slot),
                head,
                block,
                settled,
                ..Default::default()
            };
            for (n, v, leaf) in [
                (1, version(c1, 0, 0, stored(&one, 3)), 3),
                (2, version(c2, c1, 1, stored(&two, 5)), 5),
                (3, version(f2, c1, 1, stored(&fork, 5)), 5),
            ] {
                let c = v.commitment;
                tip_round(&store, n, KEY, Some(v), view(0, 0, 1, 0)).unwrap();
                let mut txn = store.begin(ns());
                txn.blob(KEY, &journal_blob(c), Some(journal(leaf).to_bytes()));
                store.commit(txn).unwrap();
            }
            // what a commit keeps of a sync: the applied list and journals,
            // less the journals left with nothing to undo (no new version)
            let keep = |synced: &Synced| {
                let mut txn = store.begin(ns());
                txn.blob(KEY, APPLIED, Some(encode_applied(&synced.applied)));
                for (c, j) in &synced.journals {
                    txn.blob(KEY, &journal_blob(*c), Some(j.to_bytes()));
                }
                let stale =
                    ObliviousTree::stale_journals(&store, ns(), KEY, &synced.applied, Fr::from(0))
                        .unwrap();
                for name in stale {
                    txn.blob(KEY, &name, None);
                }
                store.commit(txn).unwrap();
            };
            let journal_of = |c: u64| store.blob(ns(), KEY, &journal_blob(Fr::from(c))).unwrap();
            let mut doram = Doram::build_empty(a, &net, &mut state).unwrap();
            let mut sync = |doram: &mut Doram<Addressing>, old: u64| {
                let synced = holder
                    .sync(
                        &store,
                        ns(),
                        node,
                        KEY,
                        doram,
                        &Unbounded,
                        0,
                        Fr::from(old),
                        &net,
                        &mut state,
                    )
                    .unwrap();
                keep(&synced);
                synced
            };
            let synced = sync(&mut doram, f2);
            assert_eq!(synced.applied, [Fr::from(c1), Fr::from(f2)]);
            assert_eq!(synced.accesses, 2 * a.reads_per_slot() as u64);

            let synced = sync(&mut doram, c2);
            assert_eq!(synced.applied, [Fr::from(c1), Fr::from(c2)]);
            assert_eq!(synced.journals.len(), 1, "only c2 is applied");
            let mut state2 = Rep3State::new(&net, A2BType::Direct).unwrap();
            for leaf in [3u64, 5, 6] {
                let path = a.mask_path(&promote_public(id, leaf as X));
                let read = doram.read_slot(&path, &net, &mut state2).unwrap();
                assert_eq!(
                    open_many_y(&read.values, &net),
                    frs(read_of(&two, leaf)),
                    "leaf {leaf}"
                );
            }

            // the DORAM as a commit persists it: its head and live levels
            let mut txn = store.begin(ns());
            for (name, bytes) in doram.writes().unwrap() {
                txn.blob(KEY, &name, bytes);
            }
            store.commit(txn).unwrap();
            doram.persisted();
            let state_blobs: Vec<String> = store
                .blob_names(ns(), KEY)
                .unwrap()
                .into_iter()
                .filter(|n| !is_journal_blob(n))
                .collect();

            // every applied entry keeps its journal; after a commit of the
            // holder's (`committed`), a journal outlives its version only
            // while its entry is applied
            let invariant = |store: &MemoryStore, committed: bool| {
                let held: Vec<Fr> = store
                    .tip_versions(ns(), KEY)
                    .unwrap()
                    .iter()
                    .map(|v| v.commitment)
                    .collect();
                let applied = ObliviousTree::applied(store, ns(), KEY).unwrap();
                for c in &applied {
                    assert!(
                        store.blob(ns(), KEY, &journal_blob(*c)).unwrap().is_some(),
                        "applied {c} keeps its journal"
                    );
                }
                for name in store.blob_names(ns(), KEY).unwrap() {
                    if committed && is_journal_blob(&name) {
                        assert!(
                            held.iter()
                                .chain(&applied)
                                .any(|c| journal_blob(*c) == name),
                            "{name} outlived its version and its entry"
                        );
                    }
                }
            };
            invariant(&store, true);

            // c2 lands; c1 is superseded and f2 orphaned, then both are
            // deleted behind the settled block, their journals and the
            // DORAM's head and levels kept
            for settled in [0, 11] {
                NodeVersions::prune(&store, ns(), &[(KEY.into(), view(c2, 2, 10, settled))])
                    .unwrap();
                invariant(&store, false);
            }
            for name in &state_blobs {
                assert!(store.blob(ns(), KEY, name).unwrap().is_some(), "{name}");
            }
            let mut loaded = Doram::load(a, id, &store, ns(), KEY).unwrap().unwrap();
            let path = a.mask_path(&promote_public(id, 5 as X));
            let read = loaded.read_slot(&path, &net, &mut state2).unwrap();
            assert_eq!(open_many_y(&read.values, &net), frs(read_of(&two, 5)));
            let held: Vec<Fr> = store
                .tip_versions(ns(), KEY)
                .unwrap()
                .iter()
                .map(|v| v.commitment)
                .collect();
            assert_eq!(held, [Fr::from(c2)]);
            assert!(journal_of(f2).is_some(), "retention leaves journals");
            assert!(journal_of(c1).is_some(), "applied c1 keeps its journal");
            let synced = sync(&mut doram, c2);
            assert_eq!(synced.applied, [Fr::from(c2)], "c1 is the base");
            assert!(synced.journals.is_empty());
            assert_eq!(
                journal_of(f2),
                None,
                "undone f2's journal goes at the commit"
            );
            assert_eq!(journal_of(c1), None, "c1 is off the list");
            invariant(&store, true);

            // c3 and g3 on c2; a round on g3 applies g3, then no round on
            // the key while c3 lands and retention passes c2 and g3
            let (c3, g3) = (0xc3u64, 0x93u64);
            let three = [(3u64, [30u64, 7u64]), (5, [50, 8]), (6, [60, 9])];
            let other = [(3u64, [30u64, 7u64]), (5, [50, 8]), (6, [11, 2])];
            for (n, v) in [
                (4, version(c3, c2, 2, stored(&three, 6))),
                (5, version(g3, c2, 2, stored(&other, 6))),
            ] {
                let c = v.commitment;
                tip_round(&store, n, KEY, Some(v), view(c2, 2, 12, 11)).unwrap();
                let mut txn = store.begin(ns());
                txn.blob(KEY, &journal_blob(c), Some(journal(6).to_bytes()));
                store.commit(txn).unwrap();
            }
            let synced = sync(&mut doram, g3);
            assert_eq!(synced.applied, [Fr::from(c2), Fr::from(g3)]);
            invariant(&store, true);
            for settled in [11, 21] {
                NodeVersions::prune(&store, ns(), &[(KEY.into(), view(c3, 3, 20, settled))])
                    .unwrap();
                invariant(&store, false);
            }
            let held: Vec<Fr> = store
                .tip_versions(ns(), KEY)
                .unwrap()
                .iter()
                .map(|v| v.commitment)
                .collect();
            assert_eq!(held, [Fr::from(c3)], "c2 and g3 are gone");
            assert!(
                journal_of(g3).is_some(),
                "applied orphan g3 keeps its journal"
            );

            // the key's next round undoes g3 from its journal and applies c3;
            // its commit deletes the journals of c2 and g3
            let synced = sync(&mut doram, c3);
            assert_eq!(synced.applied, [Fr::from(c3)], "c2 is the base, g3 undone");
            for leaf in [3u64, 5, 6] {
                let path = a.mask_path(&promote_public(id, leaf as X));
                let read = doram.read_slot(&path, &net, &mut state2).unwrap();
                assert_eq!(
                    open_many_y(&read.values, &net),
                    frs(read_of(&three, leaf)),
                    "leaf {leaf}"
                );
            }
            assert_eq!((journal_of(c2), journal_of(g3)), (None, None));
            assert!(journal_of(c3).is_some());
            invariant(&store, true);
        })
        .unwrap();
    }

    /// A keyed map of capacity 2^8 with one slot, depth 32 and leaves of 3.
    fn map_holder() -> ObliviousMap {
        let layout: TreeLayout = serde_json::from_value(serde_json::json!({
            "depth": 32, "leaf_len": 3, "probe": 1, "access": "oblivious", "keyed": true,
            "capacity": 8, "index": ["key"]
        }))
        .unwrap();
        ObliviousMap::new(layout)
    }

    /// The sync's agreement covers the DORAM's public state: three parties
    /// of one DORAM agree; when party 0 holds the DORAM as it was before a
    /// session the other two committed (its head behind theirs, the plans
    /// alike), every party refuses, "diverged oblivious state: resync",
    /// before any access.
    #[test]
    fn a_diverged_doram_head_is_refused_before_the_session_touches_it() {
        let holder = map_holder();
        let m = *holder.addressing();
        let results = run_parties(|net| {
            let mut state = Rep3State::new(&net, A2BType::Direct).unwrap();
            let id = state.id;
            let node = usize::from(id);
            let store = MemoryStore::default();
            let fill = Fill::default();
            let mut behind = Doram::build_empty(m, &net, &mut state).unwrap();
            let mut ahead = Doram::build_empty(m, &net, &mut state).unwrap();
            ahead
                .read_raw(&[promote_public(id, 5 as X)], &net, &mut state)
                .unwrap();
            let mut sync = |doram: &mut Doram<MapAddressing>| {
                holder.sync(
                    &store,
                    ns(),
                    node,
                    KEY,
                    doram,
                    &fill,
                    1,
                    Fr::from(0u64),
                    &net,
                    &mut state,
                )
            };
            let agreed = sync(&mut ahead).map(|s| s.accesses);
            let refused = sync(if node == 0 { &mut behind } else { &mut ahead })
                .err()
                .unwrap();
            (agreed, refused, behind.head_public() != ahead.head_public())
        })
        .unwrap();
        for (agreed, refused, differ) in results {
            assert_eq!(agreed, Ok(1), "one DORAM: the three agree");
            assert!(differ);
            assert_eq!(refused.class, ErrorClass::MpcFailure, "{refused}");
            assert!(
                refused.message.contains("diverged oblivious state: resync"),
                "{refused}"
            );
        }
    }

    /// A round that leaves the key's commitment unchanged stages no
    /// version, and still stages what its session left: the advanced
    /// DORAM's head, the applied list and the fill bound, so the next
    /// session queries from where this one stopped rather than repeating
    /// its queries under the same level keys. The pending slot is emptied.
    #[test]
    fn an_unchanged_commitment_still_persists_the_session() {
        let holder = map_holder();
        let manifest = Manifest::parse(
            &serde_json::from_str(include_str!(
                "../../../examples/credits-tip/manifests/move.json"
            ))
            .unwrap(),
        )
        .unwrap();
        let shape = sidecar_core::abi::CircuitShape {
            params: vec![],
            public_param_fields: 0,
            return_paths: vec![],
            public_input_count: 0,
            namespace_index: 0,
            outputs: vec![],
        };
        let keys = node_keys();
        let req = sidecar_core::request::Request {
            namespace: FieldHex(ns()),
            circuit: "move".into(),
            request_id: id(7),
            public: Default::default(),
            state_keys: sidecar_core::request::StateKeys {
                reads: vec![KEY.into()],
                writes: vec![KEY.into()],
            },
            shared_inputs: vec![],
            records: vec![],
            requester: None,
            signature: None,
            chain_request_id: Some(FieldHex(Fr::from(0xc0u64))),
            shared_log: None,
            manifest_hash: None,
        }
        .project(0);
        let parent = Fr::from(0xc1u64);
        let chain = QueueRead {
            block: 5,
            block_hash: Fr::from(0u64),
            settled: 0,
            head: 0,
            index: 0,
            keys: vec![ChainKey {
                key: KEY.into(),
                slot: parent,
                old: parent,
                ..Default::default()
            }],
        };
        let store = MemoryStore::default();
        let at = StateCtx {
            store: &store,
            keys: &keys,
            node: 0,
            namespace: ns(),
            manifest: &manifest,
            shape: &shape,
            req: &req,
            requester: None,
            chain: Some(&chain),
            public_inputs: &[],
        };
        let fill = Fill {
            at_rebuild: 0,
            accesses_since: 36,
        };
        let head = b"the advanced head".to_vec();
        *holder.pending.lock().unwrap() = Some(Pending {
            request_id: req.request_id,
            writes: vec![("oram".into(), Some(head.clone()))],
            applied: vec![parent],
            journal: Journal::default(),
            applied_journals: vec![],
            fill,
        });
        let mut txn = store.begin(ns());
        holder
            .stage(
                &at,
                &mut txn,
                KEY,
                vec![],
                parent,
                &mut RoundEntries::default(),
            )
            .unwrap();
        store.commit(txn).unwrap();
        assert_eq!(store.blob(ns(), KEY, "oram").unwrap(), Some(head));
        assert_eq!(ObliviousMap::applied(&store, ns(), KEY).unwrap(), [parent]);
        assert_eq!(
            Fill::from_bytes(&store.blob(ns(), KEY, FILL).unwrap().unwrap()).unwrap(),
            fill
        );
        assert!(
            store.tip_versions(ns(), KEY).unwrap().is_empty(),
            "no version"
        );
        assert!(holder.pending.lock().unwrap().is_none());
    }

    #[test]
    fn a_created_tree_appends_after_its_header() {
        // the init writes the header at leaf 0 with next_index 1
        assert_eq!((CREATED_LEAF, CREATED_NEXT), (0, 1));
        assert_eq!(
            tree::next_after(0, &[(CREATED_LEAF, Fr::from(1u64))]),
            CREATED_NEXT,
            "the clear tree's count"
        );
        assert!(next_agrees(1, 1, false));
        assert!(next_agrees(1, 1, true), "an opening that failed");
        assert!(next_agrees(1, 2, true));
        assert!(!next_agrees(1, 2, false));
        assert!(!next_agrees(0, 2, true));
        assert!(!next_agrees(2, 1, true));
    }
}
