//! Tree-valued node-held keys (docs/ARCHITECTURE.md section 6, "Tree-valued
//! keys"): the hashes, the clear tree each node keeps, and the touched leaves
//! of a round.
//!
//! ```text
//! leaf_hash(i, leaf) = poseidon2([PSS_TIP_LEAF, namespace, key, i, leaf...])   (0: an empty leaf)
//! node(l, r)         = poseidon2([PSS_TIP_NODE, l, r])
//! commitment         = poseidon2([PSS_TIP_TREE, namespace, key, root])
//! Z_0 = 0, Z_{l+1} = node(Z_l, Z_l): the empty subtree of height l; an empty tree's root is Z_D
//! ```
//!
//! The labels are the bytes `pss.tip.leaf`, `pss.tip.node` and
//! `pss.tip.tree` read big-endian, the dotted scheme of the flat slot
//! commitment (`pss.tip.state`). pss_core's `tip::tree` and test-support's
//! `tree.ts` compute the same hashes; testvectors/tip_tree.json holds the
//! known answers ([`vectors::write_tree_vectors`] writes it).
//!
//! Every leaf carries a fresh blinding each time a round writes it, so leaf
//! and internal hashes are public data: each node holds the tree of hashes
//! in the clear ([`TreeNode`], content-addressed by hash in the store) and
//! the leaves as its Rep3 pairs. A round names its touched leaves by index in
//! the clear ([`Touch`]).

use std::sync::OnceLock;

use ark_ff::PrimeField;

use crate::bind::Elem;
use crate::error::Refusal;
use crate::field::Fr;
use crate::hash::poseidon2_hash;
use crate::keys::label_field;

mod clear;
mod query;
#[cfg(test)]
pub(crate) mod tests;
mod touch;
#[cfg(test)]
mod vectors;

pub use clear::*;
pub use query::*;
pub use touch::*;

/// The leaf-hash label, `pss.tip.leaf`.
pub const PSS_TIP_LEAF: &[u8] = b"pss.tip.leaf";
/// The internal-node label, `pss.tip.node`.
pub const PSS_TIP_NODE: &[u8] = b"pss.tip.node";
/// The tree-commitment label, `pss.tip.tree`.
pub const PSS_TIP_TREE: &[u8] = b"pss.tip.tree";

fn label(cell: &'static OnceLock<Fr>, bytes: &[u8]) -> Fr {
    *cell.get_or_init(|| label_field(bytes))
}

/// The hash of leaf `index` of the tree of `key` under `namespace`.
pub fn leaf_hash(namespace: Fr, key: Fr, index: u64, leaf: &[Fr]) -> Fr {
    static SEP: OnceLock<Fr> = OnceLock::new();
    let mut preimage = vec![label(&SEP, PSS_TIP_LEAF), namespace, key, Fr::from(index)];
    preimage.extend_from_slice(leaf);
    poseidon2_hash(&preimage)
}

/// The hash of an internal node over its two children.
pub fn node(left: Fr, right: Fr) -> Fr {
    static SEP: OnceLock<Fr> = OnceLock::new();
    poseidon2_hash(&[label(&SEP, PSS_TIP_NODE), left, right])
}

/// The commitment of a tree under its root: what the key's slot holds.
pub fn commitment(namespace: Fr, key: Fr, root: Fr) -> Fr {
    static SEP: OnceLock<Fr> = OnceLock::new();
    poseidon2_hash(&[label(&SEP, PSS_TIP_TREE), namespace, key, root])
}

/// `Z_0 ..= Z_depth`, the hashes of the empty subtrees of each height.
pub fn zeros(depth: u32) -> Vec<Fr> {
    let mut out = vec![Fr::from(0u64)];
    for l in 0..depth as usize {
        out.push(node(out[l], out[l]));
    }
    out
}

/// A field element as a `u64`, if it is one.
pub fn fr_u64(value: Fr) -> Option<u64> {
    let limbs = value.into_bigint();
    let words = limbs.as_ref();
    words[1..].iter().all(|w| *w == 0).then_some(words[0])
}

/// One stored node of a clear tree, content-addressed by its hash: an
/// internal node's two children, or a leaf with this node's pairs of it.
/// An empty subtree (`Z_l`) and an empty leaf (0) are never stored.
#[derive(Clone, Debug, PartialEq)]
pub enum TreeNode {
    Inner { left: Fr, right: Fr },
    Leaf { index: u64, vec: Vec<Elem> },
}

/// A stored node with the number of stored nodes and versions that point
/// to it.
#[derive(Clone, Debug, PartialEq)]
pub struct StoredNode {
    pub node: TreeNode,
    pub refs: u64,
}

/// What reads a key's clear tree: the stored node under a hash.
pub trait Nodes {
    fn get(&self, hash: Fr) -> Result<Option<TreeNode>, Refusal>;
}

impl<F: Fn(Fr) -> Result<Option<TreeNode>, Refusal>> Nodes for F {
    fn get(&self, hash: Fr) -> Result<Option<TreeNode>, Refusal> {
        self(hash)
    }
}
