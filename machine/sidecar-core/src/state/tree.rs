//! The state mode `node` at the tip for a tree-valued key: [`NodeTree`].

use std::collections::BTreeMap;

use super::row::refuse_without_values;
use super::*;
use crate::bind::Elem;
use crate::error::Refusal;
use crate::field::{Fr, fr_from_hex, fr_to_hex};
use crate::manifest::{KeyRef, ReservedOperand, TreeLayout};
use crate::store::rules::TreeNodes;
use crate::store::{TipVersion, TreeRoot, Txn, VersionTree};
use crate::tree::{self, Touch, TreeNode};

/// The state mode `node` at the tip for a tree-valued key (docs/ARCHITECTURE.md
/// section 6, "Tree-valued keys"): versions as [`NodeVersions`] keeps them,
/// each naming the root of its clear tree, whose nodes (leaves with this
/// node's pairs, internal hashes in the clear) the store keeps
/// content-addressed and counted (`tip_nodes`). Step 8 loads the touched
/// leaves ([`Touch`]) of the version the old commitment names, slot after
/// slot, then the leaves of a window ([`tree::window`]), zero pairs for an
/// empty leaf; a key the round creates starts from
/// the empty tree. Step 15 writes the round's new leaf hashes (its
/// `new_hashes` output) into the parent's clear tree, refuses (500) a root
/// whose commitment is not the round's new commitment, and stores the new
/// version with the leaves and internal nodes it added.
pub struct NodeTree {
    layout: TreeLayout,
}

impl NodeTree {
    /// The holder of a key with `layout`.
    pub fn new(layout: TreeLayout) -> Self {
        NodeTree { layout }
    }

    /// The key's layout.
    pub fn layout(&self) -> &TreeLayout {
        &self.layout
    }

    /// The key as the field its hashes take.
    fn key_field(key: &str) -> Result<Fr, Refusal> {
        fr_from_hex(key).map_err(|e| {
            Refusal::bad_request(format!(
                "key `{key}`: a tree-valued key is a field element ({e})"
            ))
        })
    }

    /// The touched leaves of the round, from its public values, and the
    /// leaves of its window (none without one).
    fn touch(&self, at: &StateCtx<'_>) -> Result<(Touch, Vec<u64>), Refusal> {
        let public: BTreeMap<String, Fr> = at.req.flatten_public()?.into_iter().collect();
        let new_leaf = at
            .manifest
            .reserved()
            .find(|(_, r)| *r == ReservedOperand::NewLeaf)
            .and_then(|(param, _)| public.get(param).copied())
            .unwrap_or(Fr::from(0u64));
        let window = tree::window(&self.layout, &public);
        Ok((Touch::of(&self.layout, &public, new_leaf), window))
    }

    /// The clear tree under the parent `commitment`: the version's, or the
    /// empty tree for 0 (a key the round creates).
    fn base(&self, at: &StateCtx<'_>, key: &str, commitment: Fr) -> Result<TreeRoot, Refusal> {
        if commitment == Fr::from(0u64) {
            return Ok(TreeRoot {
                root: tree::zeros(self.layout.depth)[self.layout.depth as usize],
                next: 0,
            });
        }
        let version = at
            .store
            .tip_version(at.namespace, key, commitment)?
            .ok_or_else(|| {
                Refusal::conflict(format!(
                    "key `{key}`: this node holds no version under commitment {}",
                    fr_to_hex(commitment)
                ))
            })?;
        tree_of(key, &version)
    }

    /// The round's new leaf hashes, one per slot, from its public inputs.
    fn new_hashes(&self, at: &StateCtx<'_>, key: &str) -> Result<Vec<Fr>, Refusal> {
        let name = self.layout.new_hashes.as_deref().unwrap_or_default();
        let first = at.shape.return_index(&format!("{name}[0]"));
        first
            .and_then(|i| at.public_inputs.get(i..i + self.layout.probe))
            .map(<[Fr]>::to_vec)
            .ok_or_else(|| {
                Refusal::mpc_failure(format!(
                    "key `{key}`: the round's public inputs carry no `{name}` of {} hashes",
                    self.layout.probe
                ))
            })
    }
}

/// The clear tree of a tree-valued version (500 for a flat one, or one
/// whose tree is held in blobs).
fn tree_of(key: &str, version: &TipVersion) -> Result<TreeRoot, Refusal> {
    version.tree.and_then(VersionTree::clear).ok_or_else(|| {
        Refusal::mpc_failure(format!(
            "key `{key}`: the version under {} holds no clear tree",
            fr_to_hex(version.commitment)
        ))
    })
}

impl StateHolder for NodeTree {
    fn noun(&self) -> &'static str {
        "node-held"
    }

    fn check_store(&self, keys: &[KeyRef], holds_values: bool) -> Result<(), Refusal> {
        refuse_without_values(keys, holds_values)
    }

    fn note_hash(&self, _at: &StateCtx<'_>, _key: &str) -> Result<Option<Fr>, Refusal> {
        Ok(None)
    }

    fn load(
        &self,
        at: &StateCtx<'_>,
        keyref: KeyRef,
        key: &str,
        _round: &mut RoundEntries,
    ) -> Result<Held, Refusal> {
        let version = NodeVersions::loaded(at, keyref, key)?;
        let base = tree_of(key, &version)?;
        let (touch, window) = self.touch(at)?;
        let nodes = |h: Fr| {
            at.store
                .tip_node(at.namespace, key, h)
                .map(|n| n.map(|n| n.node))
        };
        let zeros = tree::zeros(self.layout.depth);
        let indices = [touch.indices, window].concat();
        let vec = tree::leaves(&nodes, &zeros, base.root, self.layout.leaf_len, &indices)?;
        Ok(Held {
            vec,
            note_hash: version.commitment,
        })
    }

    fn summand(&self, key: &str) -> Option<String> {
        Some(format!("value `{key}`"))
    }

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
        if note_hash == Fr::from(0u64) || note_hash == parent {
            return NodeVersions::stage_version(at, txn, key, None);
        }
        let base = self.base(at, key, parent)?;
        let (touch, _) = self.touch(at)?;
        let new_hashes = self.new_hashes(at, key)?;
        let changes = touch.changes(&new_hashes);
        let nodes = TreeNodes {
            read: at.store,
            key,
        };
        let zeros = tree::zeros(self.layout.depth);
        let rebuilt = {
            let read = |h: Fr| nodes.get(txn, h).map(|n| n.map(|n| n.node));
            tree::rebuild(&read, &zeros, base.root, &changes)?
        };
        let key_field = Self::key_field(key)?;
        if tree::commitment(at.namespace, key_field, rebuilt.root) != note_hash {
            return Err(Refusal::mpc_failure(format!(
                "key `{key}`: the new leaf hashes give root {}, whose commitment is not the \
                 round's new commitment {}; nothing was stored",
                fr_to_hex(rebuilt.root),
                fr_to_hex(note_hash)
            )));
        }
        let w = self.layout.leaf_len;
        let mut added: Vec<(Fr, TreeNode)> = touch
            .written(&new_hashes)
            .into_iter()
            .map(|(k, index, h)| {
                let leaf = TreeNode::Leaf {
                    index,
                    vec: vec[k * w..(k + 1) * w].to_vec(),
                };
                (h, leaf)
            })
            .collect();
        added.extend(rebuilt.added.into_iter().map(|(h, _, n)| (h, n)));
        nodes.add_version(txn, rebuilt.root, added)?;
        let tree = TreeRoot {
            root: rebuilt.root,
            next: tree::next_after(base.next, &changes),
        };
        let new = NodeVersions::version(at, key, parent, note_hash, vec![], Some(tree.into()));
        NodeVersions::stage_version(at, txn, key, new)
    }
}
