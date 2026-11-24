//! The clear tree a node keeps: paths, rebuilds after a round's changes, the
//! depth, the leaves and the whole-tree walk.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use super::*;
use crate::bind::{Elem, Share};
use crate::error::Refusal;
use crate::field::{Fr, fr_to_hex};

/// The path of one leaf: its hash (0 when empty) and its siblings, bottom
/// up.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Path {
    pub leaf: Fr,
    pub siblings: Vec<Fr>,
}

/// A diverged or damaged clear tree: a node a root reaches is not held.
fn missing(hash: Fr, level: usize) -> Refusal {
    Refusal::mpc_failure(format!(
        "the clear tree holds no node {} at height {level} (a diverged store: the operator \
         resyncs this node from its neighbours)",
        fr_to_hex(hash)
    ))
}

/// The path of leaf `index` in the tree under `root`, of the depth `zeros`
/// was made for.
pub fn path(nodes: &dyn Nodes, zeros: &[Fr], root: Fr, index: u64) -> Result<Path, Refusal> {
    let depth = zeros.len() - 1;
    let mut siblings = vec![Fr::from(0u64); depth];
    let mut at = root;
    for level in (1..=depth).rev() {
        if at == zeros[level] {
            siblings[..level].copy_from_slice(&zeros[..level]);
            return Ok(Path {
                leaf: Fr::from(0u64),
                siblings,
            });
        }
        let Some(TreeNode::Inner { left, right }) = nodes.get(at)? else {
            return Err(missing(at, level));
        };
        let right_child = (index >> (level - 1)) & 1 == 1;
        let (child, sibling) = if right_child {
            (right, left)
        } else {
            (left, right)
        };
        siblings[level - 1] = sibling;
        at = child;
    }
    Ok(Path { leaf: at, siblings })
}

/// The root a leaf hash gives at `index` under `siblings` (bottom up).
pub fn root_of(leaf: Fr, siblings: &[Fr], index: u64) -> Fr {
    siblings
        .iter()
        .enumerate()
        .fold(leaf, |at, (level, sibling)| {
            if (index >> level) & 1 == 1 {
                node(*sibling, at)
            } else {
                node(at, *sibling)
            }
        })
}

/// A tree after a round's changes: its root and the internal nodes it holds
/// that the tree before it did not, each with its height, lowest first.
#[derive(Clone, Debug, PartialEq)]
pub struct Rebuilt {
    pub root: Fr,
    pub added: Vec<(Fr, usize, TreeNode)>,
}

/// The tree under `root` with each `(index, leaf hash)` of `changes` written
/// in order (a later change of one index wins), in the clear: the new root
/// and the internal nodes on the changed paths.
pub fn rebuild(
    nodes: &dyn Nodes,
    zeros: &[Fr],
    root: Fr,
    changes: &[(u64, Fr)],
) -> Result<Rebuilt, Refusal> {
    let depth = zeros.len() - 1;
    let mut overlay: BTreeMap<Fr, TreeNode> = BTreeMap::new();
    let mut at = root;
    for (index, leaf) in changes {
        let lookup = |h: Fr| -> Result<Option<TreeNode>, Refusal> {
            match overlay.get(&h) {
                Some(n) => Ok(Some(n.clone())),
                None => nodes.get(h),
            }
        };
        let p = path(&lookup, zeros, at, *index)?;
        let mut h = *leaf;
        for (level, sibling) in p.siblings.iter().enumerate() {
            let (left, right) = if (index >> level) & 1 == 1 {
                (*sibling, h)
            } else {
                (h, *sibling)
            };
            h = node(left, right);
            overlay.insert(h, TreeNode::Inner { left, right });
        }
        at = h;
    }
    // keep only the nodes the final tree reaches on the changed paths
    let mut added = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for (index, _) in changes {
        let mut h = at;
        for level in (1..=depth).rev() {
            let Some(TreeNode::Inner { left, right }) = overlay.get(&h).cloned() else {
                break;
            };
            if seen.insert(h) {
                added.push((h, level, TreeNode::Inner { left, right }));
            }
            h = if (index >> (level - 1)) & 1 == 1 {
                right
            } else {
                left
            };
        }
    }
    added.sort_by_key(|(_, level, _)| *level);
    Ok(Rebuilt { root: at, added })
}

/// The depth of the clear tree under `root`, read down its leftmost path:
/// the internal nodes above the first hash that is a stored leaf (height 0)
/// or an empty subtree `Z_l` (height `l`). A tree's stored nodes fix its
/// depth, so a query of another depth is refused rather than answered with
/// the wrong paths. 500 for a node the path reaches and the store does not
/// hold, or a path deeper than [`crate::manifest::MAX_TREE_DEPTH`].
pub fn depth_of(nodes: &dyn Nodes, root: Fr) -> Result<u32, Refusal> {
    static ZEROS: OnceLock<Vec<Fr>> = OnceLock::new();
    let max = crate::manifest::MAX_TREE_DEPTH;
    let z = ZEROS.get_or_init(|| zeros(max));
    let mut at = root;
    for down in 0..=max {
        if let Some(height) = z.iter().position(|h| *h == at) {
            return Ok(down + height as u32);
        }
        match nodes.get(at)? {
            Some(TreeNode::Inner { left, .. }) => at = left,
            Some(TreeNode::Leaf { .. }) => return Ok(down),
            None => break,
        }
    }
    Err(Refusal::mpc_failure(format!(
        "the clear tree under root {} holds no node {} on its leftmost path, or is deeper \
         than {max} (a diverged store: the operator resyncs this node from its neighbours)",
        fr_to_hex(root),
        fr_to_hex(at)
    )))
}

/// The paths of `indices` in the tree under `root` with append index `next`.
pub fn paths(
    nodes: &dyn Nodes,
    zeros: &[Fr],
    root: Fr,
    next: u64,
    indices: &[u64],
) -> Result<TreePaths, Refusal> {
    let mut old_hashes = Vec::with_capacity(indices.len());
    let mut siblings = Vec::new();
    for i in indices {
        let p = path(nodes, zeros, root, *i)?;
        old_hashes.push(crate::field::FieldHex(p.leaf));
        siblings.extend(p.siblings.into_iter().map(crate::field::FieldHex));
    }
    Ok(TreePaths {
        old_hashes,
        siblings,
        next,
    })
}

/// This node's pairs of the leaves at `indices` in the tree under `root`,
/// slot after slot: zero pairs for an empty leaf. 500 for a leaf the tree
/// names and the store does not hold.
pub fn leaves(
    nodes: &dyn Nodes,
    zeros: &[Fr],
    root: Fr,
    leaf_len: usize,
    indices: &[u64],
) -> Result<Vec<Elem>, Refusal> {
    let mut out = Vec::with_capacity(indices.len() * leaf_len);
    for i in indices {
        let p = path(nodes, zeros, root, *i)?;
        if p.leaf == Fr::from(0u64) {
            out.extend(std::iter::repeat_n(
                Elem::Shared(Share::new(Fr::from(0u64), Fr::from(0u64))),
                leaf_len,
            ));
            continue;
        }
        match nodes.get(p.leaf)? {
            Some(TreeNode::Leaf { index, vec }) if index == *i && vec.len() == leaf_len => {
                out.extend(vec)
            }
            _ => return Err(missing(p.leaf, 0)),
        }
    }
    Ok(out)
}

/// One stored leaf of a clear tree, as [`walk`] found it.
#[derive(Clone, Debug, PartialEq)]
pub struct WalkedLeaf {
    pub index: u64,
    /// The leaf hash, the node's address.
    pub hash: Fr,
    /// This node's pairs of the leaf.
    pub vec: Vec<Elem>,
}

/// A clear tree read whole from its root: its depth, its stored leaves in
/// index order and its stored internal nodes (hash, left, right), top down.
#[derive(Clone, Debug, PartialEq)]
pub struct Walked {
    pub depth: u32,
    pub leaves: Vec<WalkedLeaf>,
    pub inner: Vec<(Fr, Fr, Fr)>,
}

/// The deepest tree [`walk`] reads.
pub const MAX_DEPTH: u32 = 64;

/// Read the clear tree under `root` whole and check it in the clear: every
/// stored internal node hashes to its address (`node(left, right)`), every
/// child the store does not hold is the empty subtree of its height, every
/// stored leaf sits at the depth of the others and at the index its path
/// spells. The leaves' own hashes are of their pairs and are not checked
/// here (that is the audit round's). 500 naming the first node that fails.
pub fn walk(nodes: &dyn Nodes, root: Fr) -> Result<Walked, Refusal> {
    let bad = |hash: Fr, why: String| {
        Refusal::mpc_failure(format!(
            "the clear tree under root {}: node {}: {why} (a diverged store: the operator \
             resyncs this node from its neighbours)",
            fr_to_hex(root),
            fr_to_hex(hash)
        ))
    };
    let mut inner = Vec::new();
    let mut leaves: Vec<(u32, u64, WalkedLeaf)> = Vec::new();
    let mut empty: Vec<(Fr, u32)> = Vec::new();
    // (hash, depth from the root, position at that depth)
    let mut pending = vec![(root, 0u32, 0u64)];
    while let Some((hash, at, position)) = pending.pop() {
        match nodes.get(hash)? {
            Some(TreeNode::Inner { left, right }) => {
                if node(left, right) != hash {
                    return Err(bad(hash, "its children do not hash to it".into()));
                }
                if at >= MAX_DEPTH {
                    return Err(bad(hash, format!("deeper than {MAX_DEPTH}")));
                }
                inner.push((hash, left, right));
                pending.push((right, at + 1, (position << 1) | 1));
                pending.push((left, at + 1, position << 1));
            }
            Some(TreeNode::Leaf { index, vec }) => {
                leaves.push((at, position, WalkedLeaf { index, hash, vec }));
            }
            None => empty.push((hash, at)),
        }
    }
    let depth = match leaves.first() {
        Some((d, _, _)) => *d,
        None => {
            // no leaf: the root is an empty tree of some depth
            let z = zeros(MAX_DEPTH);
            let d = z
                .iter()
                .position(|h| *h == root)
                .ok_or_else(|| bad(root, "neither stored nor an empty tree".into()))?;
            return Ok(Walked {
                depth: d as u32,
                leaves: vec![],
                inner,
            });
        }
    };
    let z = zeros(depth);
    for (at, position, leaf) in &leaves {
        if *at != depth {
            return Err(bad(
                leaf.hash,
                format!("a leaf at depth {at}, another at {depth}"),
            ));
        }
        if leaf.index != *position {
            return Err(bad(
                leaf.hash,
                format!("leaf {} at position {position}", leaf.index),
            ));
        }
    }
    for (hash, at) in empty {
        if at > depth || z[(depth - at) as usize] != hash {
            return Err(bad(hash, format!("not held at depth {at}, and not empty")));
        }
    }
    let mut leaves: Vec<WalkedLeaf> = leaves.into_iter().map(|(_, _, l)| l).collect();
    leaves.sort_by_key(|l| l.index);
    Ok(Walked {
        depth,
        leaves,
        inner,
    })
}
