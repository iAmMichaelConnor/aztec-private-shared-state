//! A node-held tip key's versions as a commit stages them: their statuses
//! against the chain, and the counted nodes of a tree-valued key's clear tree.

use super::*;
use crate::tree::TreeNode;

/// What a node-held tip round's commit knows of the chain for one key:
/// the commitment its slot holds, the queue's head and the block this
/// node read them at, with the settled block as the reader read it with
/// that block, the floor of the retention
/// (docs/ARCHITECTURE.md section 6, "Node-held state", retention).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VersionView {
    pub slot: Fr,
    pub head: u64,
    pub block: u64,
    /// The hash of `block` as the view read it, stamped with `block` on the
    /// marks this view makes ([`crate::store::TipVersion::block_hash`]).
    pub block_hash: Fr,
    /// The settled block, at or below `block` (`ChainReader::settled`:
    /// the node's finalized tip, below which no replacement reaches): an
    /// orphaned or superseded version first marked orphan below it is
    /// deleted. The chain reader keeps block hashes back to the same
    /// block, so a replacement above it, an epoch prune or an L1 reorg
    /// included, finds every version it restores. 0 where the reader has
    /// not seen the finalized tip move (no version is then old enough to
    /// delete).
    pub settled: u64,
    /// The versions of the key whose orphan mark the chain does not
    /// confirm: marked below `settled` at a block whose hash the chain at
    /// that height is not (the mark was made on a chain a replacement
    /// undid), or whose hash the reader could not confirm, or with no hash.
    /// Their marks are ignored: each is marked again under this view, as if
    /// first seen so now. The view's reader checks every orphan marked below
    /// `settled` (`sidecar-tip` `state::replaced_marks`).
    pub replaced: Vec<Fr>,
}

impl VersionView {
    /// The later of a version's `(block, block_hash)` and this view's: the
    /// view's when it is at or past the version's block.
    fn later(&self, v: &TipVersion) -> (u64, Fr) {
        if self.block >= v.block {
            (self.block, self.block_hash)
        } else {
            (v.block, v.block_hash)
        }
    }
}

/// The status of every version of a key under `view`: canonical when the
/// slot holds its commitment; live when its entry is at or after the head
/// (`done` unwritten) and its parent is canonical (the slot's commitment,
/// 0 for an empty slot) or live; else orphan.
pub fn version_statuses(versions: &[TipVersion], view: &VersionView) -> Vec<VersionStatus> {
    fn status(
        i: usize,
        versions: &[TipVersion],
        view: &VersionView,
        memo: &mut Vec<Option<VersionStatus>>,
        depth: usize,
    ) -> VersionStatus {
        if let Some(s) = memo[i] {
            return s;
        }
        let v = &versions[i];
        let s = if v.commitment == view.slot {
            VersionStatus::Canonical
        } else if v.index < view.head || depth > versions.len() {
            VersionStatus::Orphan
        } else if v.parent == view.slot {
            VersionStatus::Live
        } else {
            match versions.iter().position(|p| p.commitment == v.parent) {
                Some(p) => match status(p, versions, view, memo, depth + 1) {
                    VersionStatus::Orphan => VersionStatus::Orphan,
                    _ => VersionStatus::Live,
                },
                None => VersionStatus::Orphan,
            }
        };
        memo[i] = Some(s);
        s
    }
    let mut memo = vec![None; versions.len()];
    (0..versions.len())
        .map(|i| status(i, versions, view, &mut memo, 0))
        .collect()
}

/// Stage the `tip_versions` writes of a node-held tip round for `key`:
/// `new`, the version the round created (none when its new commitment is
/// 0 or equals its old one), then every held version of the key marked
/// with its status under `view`. Canonical and live versions are marked
/// at `view.block`; a version that turns orphan here is marked at
/// `view.block`, the first block known to have orphaned or superseded it
/// (at its own block when that is later: a view read behind a commit's,
/// as the prune pass's can be, never shortens its retention), and keeps
/// that block while it stays orphan, unless the chain has since replaced
/// that block (`view.replaced`): then it is marked again at `view.block`.
/// Every mark carries the hash of its block. Orphans marked below the
/// settled block `view.settled` are deleted, however far ahead of
/// it `view.block` is, each with its tree's nodes. A holder's blobs of the
/// version (the oblivious holder's journal) are the holder's to delete, at
/// the key's next commit through it. The prune pass between rounds stages
/// the same writes with no `new` ([`crate::state::NodeVersions::prune`]).
pub fn stage_versions<R: StoreRead + ?Sized>(
    read: &R,
    txn: &mut Txn,
    key: &str,
    new: Option<TipVersion>,
    view: &VersionView,
) -> Result<(), Refusal> {
    let mut all = read.tip_versions(txn.namespace, key)?;
    let held = all.len();
    all.extend(new);
    let statuses = version_statuses(&all, view);
    for (i, (v, status)) in all.into_iter().zip(statuses).enumerate() {
        let kept =
            i < held && v.status == VersionStatus::Orphan && !view.replaced.contains(&v.commitment);
        let (block, block_hash) = match status {
            VersionStatus::Orphan if kept => (v.block, v.block_hash),
            _ => view.later(&v),
        };
        if i == held {
            txn.version(VersionWrite::Put(TipVersion {
                status,
                block,
                block_hash,
                ..v
            }));
        } else if status == VersionStatus::Orphan && block < view.settled {
            if let Some(tree) = v.tree.and_then(VersionTree::clear) {
                TreeNodes { read, key }.drop_version(txn, tree.root)?;
            }
            txn.version(VersionWrite::Delete {
                key: v.key,
                commitment: v.commitment,
            });
        } else if status != v.status || block != v.block || block_hash != v.block_hash {
            txn.version(VersionWrite::Mark {
                key: v.key,
                commitment: v.commitment,
                status,
                block,
                block_hash,
            });
        }
    }
    Ok(())
}

/// A key's clear tree as a commit stages it: reads see the transaction's
/// staged `tip_nodes` writes over the store's rows. Nodes are counted:
/// each stored node knows how many stored nodes and versions point to
/// it, so a version's delete removes exactly the nodes no kept version
/// reaches (reachability from the kept roots).
pub struct TreeNodes<'a, R: ?Sized> {
    pub read: &'a R,
    pub key: &'a str,
}

impl<R: StoreRead + ?Sized> TreeNodes<'_, R> {
    /// The node under `hash`, as the commit leaves it so far.
    pub fn get(&self, txn: &Txn, hash: Fr) -> Result<Option<StoredNode>, Refusal> {
        match txn.nodes.get(&(self.key.to_string(), hash)) {
            Some(staged) => Ok(staged.clone()),
            None => self.read.tip_node(txn.namespace, self.key, hash),
        }
    }

    /// Add one to the count of a held node; a hash no node is stored
    /// under (an empty subtree, an empty leaf) is not counted.
    fn retain(&self, txn: &mut Txn, hash: Fr) -> Result<(), Refusal> {
        if let Some(mut n) = self.get(txn, hash)? {
            n.refs += 1;
            txn.node(self.key, hash, Some(n));
        }
        Ok(())
    }

    /// Stage the delete of a version whose tree has `root`: take one from
    /// the count of that held node; at 0 delete it and do the same to its
    /// children.
    pub fn drop_version(&self, txn: &mut Txn, root: Fr) -> Result<(), Refusal> {
        let mut pending = vec![root];
        while let Some(h) = pending.pop() {
            let Some(mut n) = self.get(txn, h)? else {
                continue;
            };
            n.refs = n.refs.saturating_sub(1);
            if n.refs > 0 {
                txn.node(self.key, h, Some(n));
                continue;
            }
            txn.node(self.key, h, None);
            if let TreeNode::Inner { left, right } = n.node {
                pending.extend([left, right]);
            }
        }
        Ok(())
    }

    /// Stage a new version's nodes: each node the store does not hold
    /// (leaves and internal nodes, children before parents, as
    /// `added` lists them bottom up), each counting its children, then
    /// one reference to `root` for the version.
    pub fn add_version(
        &self,
        txn: &mut Txn,
        root: Fr,
        added: Vec<(Fr, TreeNode)>,
    ) -> Result<(), Refusal> {
        for (hash, node) in added {
            if self.get(txn, hash)?.is_some() {
                continue;
            }
            if let TreeNode::Inner { left, right } = &node {
                self.retain(txn, *left)?;
                self.retain(txn, *right)?;
            }
            txn.node(self.key, hash, Some(StoredNode { node, refs: 0 }));
        }
        self.retain(txn, root)
    }
}

/// What tip keys hold: their versions and every node their clear trees
/// reach.
pub struct TipRows {
    /// The versions, key after key, each key's in the store's order.
    pub versions: Vec<TipVersion>,
    /// Every node a kept version's clear tree reaches, once, by (key, hash).
    pub nodes: BTreeMap<(String, Fr), TreeNode>,
}

/// The versions of `keys` under `namespace` that `keep` keeps, and every
/// node their clear trees reach, each tree read whole and checked in the
/// clear ([`crate::tree::walk`]; 500 naming a node that fails). A tree held in
/// blobs reaches no node here.
pub fn tip_rows<R: StoreRead + ?Sized>(
    store: &R,
    namespace: Fr,
    keys: &[String],
    keep: impl Fn(&TipVersion) -> bool,
) -> Result<TipRows, Refusal> {
    let mut versions = Vec::new();
    let mut nodes = BTreeMap::new();
    for key in keys {
        for v in store.tip_versions(namespace, key)? {
            if !keep(&v) {
                continue;
            }
            if let Some(t) = v.tree.and_then(VersionTree::clear) {
                let get = |h: Fr| -> Result<Option<TreeNode>, Refusal> {
                    Ok(store.tip_node(namespace, key, h)?.map(|n| n.node))
                };
                let walked = crate::tree::walk(&get, t.root)?;
                for (hash, left, right) in walked.inner {
                    nodes.insert((key.clone(), hash), TreeNode::Inner { left, right });
                }
                for leaf in walked.leaves {
                    let node = TreeNode::Leaf {
                        index: leaf.index,
                        vec: leaf.vec,
                    };
                    nodes.insert((key.clone(), leaf.hash), node);
                }
            }
            versions.push(v);
        }
    }
    Ok(TipRows { versions, nodes })
}
