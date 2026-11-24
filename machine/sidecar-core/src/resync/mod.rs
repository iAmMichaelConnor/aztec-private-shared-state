//! Resync of a node from its two neighbours (docs/ARCHITECTURE.md section 6,
//! "Node-held state", recovery): Rep3 gives every component of a value to
//! two nodes, so the node's two neighbours together hold everything it held
//! of the node-held state. A resync has a [`Scope`]: a lost store (its key
//! directory intact), rebuilt whole into an empty store; a restored store,
//! rebuilt whole into an empty store from the node's backup and, for what
//! the backup does not hold, its neighbours (the delta resync); or one tip
//! key of a namespace the node holds (a slot at a commitment it does not
//! hold, a diverged clear tree), whose versions and clear tree replace the
//! node's. Over one MPC session of the three nodes:
//!
//! ```text
//! held      a delta resync only: node i sends both neighbours what its backup
//!           holds (crate::backup::Held: its versions, leaves and `values` rows
//!           by name)
//! send      each neighbour j sends node i its bundle: in the clear, every
//!           namespaces row (without the share), every held contract manifest
//!           version with its packages, every canonical
//!           and live version of every tip key and every tree node those reach,
//!           every `values` row of the sidecar path (without its shared
//!           elements), every `consumed` row, every dead record and every
//!           receipt row its receipt hook sends (crate::resync::ReceiptResync:
//!           sidecar-tip sends receipt intake's rows, with j's own receipt
//!           signature); sealed to node i's
//!           pinned enc key, the component of each shared value it shares with
//!           node i (node i+1 its b, x_i; node i-1 its a, x_{i-1}): the master
//!           share, each nsk_app share, each version's, leaf's and value's
//!           pairs, and of every holder blob (crate::store::blob: the oblivious
//!           tree's DORAM levels, applied list and journals) the public bytes
//!           in the clear and the components it shares with node i sealed;
//!           all signed with j's sig key. A key resync sends the namespace's
//!           row and the key's versions, tree nodes and blobs only; a delta
//!           resync sends what a store resync does, without the components
//!           of what node i's backup holds.
//! rebuild   node i checks both signatures against the pinned sig keys, opens
//!           both, requires the two bodies to agree (the dead records
//!           included), rebuilds each pair (a from i+1, b from i-1; a delta
//!           resync takes the pairs its backup holds from the backup), requires
//!           the master pair to equal its key directory's, keeps each receipt
//!           row both neighbours send alike that its receipt hook checks (the
//!           two signatures and the ids) and signs again with its own sig key,
//!           and imports every namespace
//!           into its empty store (a delta resync: with its backup's `requests`
//!           rows and the receipt rows the neighbours did not bring back; a key
//!           resync: the key into its store, whose namespace row must be the
//!           rebuilt one)
//! npk       per namespace, the registration circuit on the master, whose
//!           npk_app_hash must be the registered one, and the rebuilt nsk_app
//!           pairs against the circuit's fresh sharing (their difference opens
//!           to 0); the session handshake first compares the nsk_app pairs; then
//!           a handshake compares every `values` row's pairs (not run by a key
//!           resync)
//! blobs     a handshake over every holder blob: each node sends node i+1 the
//!           digest of its `a` components (with the public bytes and copies)
//!           and node i-1 that of its `b`, and each compares them with its own
//!           (a component sent wrongly differs from the one the neighbour
//!           holds); a key resync checks its key's
//! audit     the audit round over every canonical version (crate::audit); a key
//!           resync audits its key
//! ```
//!
//! A delta resync checks what it takes from the backup as a store resync
//! checks what it takes from the neighbours: the body is the neighbours'
//! (the backup supplies pairs only, each checked against the body's public
//! elements), the master and every nsk_app component still come from both
//! neighbours, and the npk check, the `values` handshake and the audit run
//! over the result.
//!
//! The registry rows alone (every `namespaces` row's owner, `seq` and
//! `npk_app_hash`, and every `packages` row) have a scope of their own,
//! [`resync_registry`]: a node several registry bodies behind takes them
//! from one named neighbour once the other two are seen to agree, keeping
//! its own nsk_app shares and building each vk itself. Its rows are public,
//! so nothing is sealed and no pair is rebuilt.
//!
//! A receipt row the hook does not send is not carried (sidecar-tip: a
//! secret-shared receipt intake row, whose envelope is sealed to the lost
//! node alone, which no neighbour can rebuild), so a queued request whose
//! receipt the lost store held cannot run at that node and its head is
//! skipped after `stale_blocks`, as any head no node runs; so is a request
//! whose row the neighbours do not both hold alike. The `requests` rows and
//! orphaned versions are not sent either.

use std::collections::BTreeMap;

use ark_ff::{UniformRand, Zero};
use ark_std::rand::{CryptoRng, RngCore};
use mpc_core::protocols::rep3::arithmetic;
use mpc_net::Network;
use serde::{Deserialize, Serialize};

use crate::ae;
use crate::audit::{self, KeyAudit};
use crate::backup::{Held, Own, own_parts, part_digest};
use crate::bind::{Elem, Share};
use crate::crs::{self, Artifact, Circuit};
use crate::dead::DeadRecord;
use crate::error::Refusal;
use crate::field::{FieldHex, Fr, HexBytes, RequestId, fr_to_hex};
use crate::grumpkin::{
    Point, coordinates, fixed_base_mul, mul, point_from_wire, point_to_wire, scalar_from_field,
};
use crate::handshake::{self, Handshake, Verdict, recv_json, send_json};
use crate::hash::poseidon2_hash;
use crate::keys::{NodeKeys, label_field};
use crate::manifest::contract::{ContractManifest, manifest_hash};
use crate::pipeline::{NamespacesGuard, Node};
use crate::record::key_hash;
use crate::register::Signature;
use crate::registry_check::{self, Divergence, ManifestRows, NamespaceRows, PackageRows};
use crate::request::{GrumpkinPoint, NODES, next, prev};
use crate::response::{NodePublicKeys, NodesResponse};
use crate::schnorr::{self, poseidon2_hash_bytes};
use crate::state::{NodeVersions, VersionViews};
use crate::store::blob::{Blob, Part};
use crate::store::rules::TreeNodes;
use crate::store::{
    ConsumedRow, ManifestRow, MemoryStore, NamespaceRow, PackageRow, ReceiptRow, RequestRow,
    RestoredValue, Store, StoreRead, TipVersion, VersionStatus, VersionTree, held_versions,
    tip_rows,
};
use crate::tree::{self, TreeNode};

mod bundle;
mod checks;
mod import;
mod rebuild;
mod receipts;
mod registry;
mod session;

pub use bundle::{
    Body, Bundle, ConsumedBody, Contents, DeadBody, ManifestBody, NamespaceBody, NodeBody,
    PackageBody, ReceiptBody, TreeBody, ValueBody, VecBody, VersionBody, collect, omit, open, seal,
};
pub use checks::{check_blobs, check_npk_app, check_values};
pub use import::{Imported, import};
pub use rebuild::{Rebuilt, RebuiltNamespace, rebuild};
pub use receipts::{NoReceiptResync, ReceiptResync, ReceiptResyncHook};
pub use registry::{
    REGISTRY_LABEL, RegistryCircuit, RegistryPlan, RegistryResync, registry_plan,
    registry_session_body, resync_registry,
};
pub use session::{ResyncReport, run};

/// The resync's label, `sidecar.resync`: the session's request id, and the
/// domain of the bundle signature and nonce.
pub const RESYNC_LABEL: &[u8] = b"sidecar.resync";

/// The label of the npk_app_hash check, `sidecar.npk_check`.
pub const NPK_CHECK_LABEL: &[u8] = b"sidecar.npk_check";

/// The label of the `values` pairs check, `sidecar.values_check`.
pub const VALUES_CHECK_LABEL: &[u8] = b"sidecar.values_check";

/// What a resync brings back.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Scope {
    /// A lost store: every namespace, imported into an empty store.
    Store,
    /// A restored store: every namespace, imported into an empty store, the
    /// pairs the node's backup holds taken from it and the rest (the
    /// versions, leaves and `values` rows written since the backup) from the
    /// neighbours.
    Delta,
    /// One tip key of one namespace, into a store that holds the namespace:
    /// the neighbours' canonical and live versions of the key and their clear
    /// trees replace the node's versions and tree of it.
    Key { namespace: FieldHex, key: String },
    /// A newcomer in a departed node's place (crate::replace): every
    /// namespace, imported into an empty store, as a lost store's, with the
    /// master pair installed from the two bundles (the newcomer has no
    /// master share to compare it with).
    Replace,
}

impl Scope {
    /// The scope as one field element of the session body: 0 for a store,
    /// 1 for a restored store, 2 for a newcomer, `poseidon2([namespace,
    /// key_hash(key)])` for a key.
    fn field(&self) -> Fr {
        match self {
            Scope::Store => Fr::from(0u64),
            Scope::Delta => Fr::from(1u64),
            Scope::Replace => Fr::from(2u64),
            Scope::Key { namespace, key } => poseidon2_hash(&[namespace.fr(), key_hash(key)]),
        }
    }

    /// What the lost node's store holds once it imported under this scope,
    /// as the unverified-store mark names it ([`Node::mark_unverified`]).
    pub fn import_name(&self) -> String {
        match self {
            Scope::Store => "a store resync's import".into(),
            Scope::Delta => "a restored backup's import".into(),
            Scope::Replace => "a newcomer's import".into(),
            Scope::Key { namespace, key } => {
                format!("a key resync's import of {namespace} `{key}`")
            }
        }
    }

    /// The one key a key resync brings back, with its namespace; `None`
    /// for a scope of the whole store.
    pub fn key(&self) -> Option<(Fr, &str)> {
        match self {
            Scope::Key { namespace, key } => Some((namespace.fr(), key)),
            Scope::Store | Scope::Delta | Scope::Replace => None,
        }
    }

    /// Whether the lost node restores its own backup and the neighbours send
    /// only what it lacks (a delta resync).
    pub fn restores_backup(&self) -> bool {
        matches!(self, Scope::Delta)
    }

    /// Whether the lost node installs the master pair the bundles rebuild
    /// instead of comparing it with its own (a newcomer, which has none).
    pub fn installs_master(&self) -> bool {
        matches!(self, Scope::Replace)
    }

    /// The namespaces a session of this scope reads or writes at `store`,
    /// whose locks it holds from before its mesh lock to its end
    /// ([`Node::maintain`]): every namespace of the store, or the key's.
    pub fn namespaces<S: Store + ?Sized>(&self, store: &S) -> Result<Vec<Fr>, Refusal> {
        match self.key() {
            None => store.namespaces(),
            Some((namespace, _)) => Ok(vec![namespace]),
        }
    }

    /// The keys of a namespace this scope covers: the key's, or `all`.
    fn keys(
        &self,
        all: impl FnOnce() -> Result<Vec<String>, Refusal>,
    ) -> Result<Vec<String>, Refusal> {
        match self.key() {
            None => all(),
            Some((_, key)) => Ok(vec![key.to_string()]),
        }
    }
}

/// The session's request id.
pub fn session_id() -> RequestId {
    RequestId(label_field(RESYNC_LABEL))
}

/// The session's body hash, which all three nodes must agree on: the node
/// resynced, the scope and the pinned keys of all three.
pub fn session_body(lost: usize, scope: &Scope, pins: &NodesResponse) -> Fr {
    let mut fields = vec![
        label_field(RESYNC_LABEL),
        Fr::from(lost as u64),
        scope.field(),
    ];
    for keys in &pins.nodes {
        fields.extend([
            keys.enc.x.fr(),
            keys.enc.y.fr(),
            keys.sig.x.fr(),
            keys.sig.y.fr(),
        ]);
    }
    poseidon2_hash(&fields)
}

/// Refuse (400) pins whose entry for `me` is not this node's own keys: the
/// operator gave the wrong file.
pub fn check_own_pins(keys: &NodeKeys, me: usize, pins: &NodesResponse) -> Result<(), Refusal> {
    if pins.nodes[me] != keys.public_keys() {
        return Err(Refusal::bad_request(format!(
            "resync: the pinned keys of node {me} are not this node's (pin the current keys \
             of all three nodes, as GET /v1/nodes answers them)"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
