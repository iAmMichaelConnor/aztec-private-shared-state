//! The scheduler's tree query and a node's answer from its store.

use super::*;
use crate::error::Refusal;
use crate::field::{Fr, fr_to_hex};

/// What the nodes' clear trees give for a round's touched leaves: each
/// slot's old hash and siblings, and the version's append index.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TreePaths {
    pub old_hashes: Vec<crate::field::FieldHex>,
    /// Slot after slot, each bottom up.
    pub siblings: Vec<crate::field::FieldHex>,
    pub next: u64,
}

/// The most slots a [`TreeQuery`] names.
pub const MAX_QUERY_SLOTS: usize = 64;

/// What the scheduler asks each node for a round on a tree-valued key: the
/// paths of `indices` in the version under `commitment`, a tree of depth
/// `depth`. Under `open` (a round that opens a leaf) each node places its
/// version's `$new_leaf` ([`new_leaf`]) in that slot, whatever `indices`
/// names there, so the scheduler learns the assigned index and its path in
/// one read; the three answers agree only when the three append indices do.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TreeQuery {
    pub namespace: crate::field::FieldHex,
    pub key: String,
    pub commitment: crate::field::FieldHex,
    pub depth: u32,
    pub indices: Vec<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub open: Option<usize>,
}

/// A node's answer to `q` from its store: 400 for a query out of bounds or
/// whose depth is not the depth of the version's tree ([`depth_of`]), 404 for
/// a commitment this node holds no version of, 500 for a flat version or a
/// damaged tree.
pub fn answer(read: &dyn crate::store::StoreRead, q: &TreeQuery) -> Result<TreePaths, Refusal> {
    if q.depth == 0
        || q.depth > crate::manifest::MAX_TREE_DEPTH
        || q.indices.len() > MAX_QUERY_SLOTS
        || q.indices.iter().any(|i| *i >> q.depth != 0)
        || q.open.is_some_and(|k| k >= q.indices.len())
    {
        return Err(Refusal::bad_request(format!(
            "tree query: depth {}, {} indices and open slot {:?} are out of bounds",
            q.depth,
            q.indices.len(),
            q.open
        )));
    }
    let ns = q.namespace.fr();
    let version = read
        .tip_version(ns, &q.key, q.commitment.fr())?
        .ok_or_else(|| {
            Refusal::not_found(format!(
                "key `{}`: no version under commitment {}",
                q.key,
                fr_to_hex(q.commitment.fr())
            ))
        })?;
    let tree = version.tree.ok_or_else(|| {
        Refusal::mpc_failure(format!("key `{}`: the version holds no tree", q.key))
    })?;
    if q.indices.is_empty() {
        // the append index alone (an oblivious tree, whose paths no node
        // reads outside the session: docs/ARCHITECTURE.md section 6, "The
        // oblivious tree", "The scheduler and the chain verifier")
        return Ok(TreePaths {
            old_hashes: vec![],
            siblings: vec![],
            next: tree.next(),
        });
    }
    let Some(tree) = tree.clear() else {
        return Err(Refusal::bad_request(format!(
            "tree query: key `{}` under commitment {} holds its tree in its holder's blobs, \
             whose paths no node reads outside the session",
            q.key,
            fr_to_hex(q.commitment.fr())
        )));
    };
    let nodes = |h: Fr| Ok(read.tip_node(ns, &q.key, h)?.map(|n| n.node));
    let depth = depth_of(&nodes, tree.root)?;
    if depth != q.depth {
        return Err(Refusal::bad_request(format!(
            "tree query: key `{}` under commitment {} is a tree of depth {depth}, not {}",
            q.key,
            fr_to_hex(q.commitment.fr()),
            q.depth
        )));
    }
    let mut indices = q.indices.clone();
    if let Some(k) = q.open {
        indices[k] = new_leaf(tree.next, depth);
    }
    paths(&nodes, &zeros(depth), tree.root, tree.next, &indices)
}
