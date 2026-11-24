//! A round's touched leaves of a tree key: the slots, the window, and the
//! append index after the round.

use std::collections::BTreeMap;

use super::*;
use crate::error::Refusal;
use crate::field::Fr;
use crate::manifest::TreeLayout;

/// A round's touched leaves of one tree key: the effective index of each
/// slot and whether the round uses it. Slot 0 is leaf 0 when the layout has
/// a header; then one slot per `index` input. An unused slot (past the
/// count) has index 0 and is never written; the scheduler still places leaf
/// 0's path there, so every slot's path is a path of the loaded tree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Touch {
    pub indices: Vec<u64>,
    pub used: Vec<bool>,
}

impl Touch {
    /// The touched leaves of a round of `layout`, from the request's public
    /// values (`public`, flattened) and the assigned `$new_leaf` (0 when the
    /// layout opens nothing). The effective index of a slot: leaf 0 in a
    /// header's slot; an index input's value when it is below 2^D;
    /// `$new_leaf` for the open input at 0; 0 for an unused slot (past the
    /// count) and for a value the tree cannot hold (2^D or more, or not an
    /// integer); a count above the number of index inputs uses none of them.
    /// Each node, the scheduler and every chain verifier derive the same
    /// indices from the request, so a request that breaks the index rules
    /// still loads and checks real leaves (the old-leaf check cannot fire on
    /// a bad request, only on a diverged store) and the circuit flags it: it
    /// compares the placed indices with the ones its inputs give, and checks
    /// range, distinctness, the count and a full tree itself.
    pub fn of(layout: &TreeLayout, public: &BTreeMap<String, Fr>, new_leaf: Fr) -> Touch {
        let limit = 1u64.checked_shl(layout.depth).unwrap_or(u64::MAX);
        let index = |v: Fr| fr_u64(v).filter(|i| *i < limit).unwrap_or(0);
        let value = |name: &str| public.get(name).copied().unwrap_or(Fr::from(0u64));
        let n = Self::used_inputs(layout, public);
        let open = Self::opening(layout, public);
        let mut indices = Vec::with_capacity(layout.probe);
        let mut used = Vec::with_capacity(layout.probe);
        if layout.header {
            indices.push(0);
            used.push(true);
        }
        for (k, name) in layout.index.iter().enumerate() {
            let slot = layout.first_position() + k;
            indices.push(if k >= n {
                0
            } else if open == Some(slot) {
                index(new_leaf)
            } else {
                index(value(name))
            });
            used.push(k < n);
        }
        Touch { indices, used }
    }

    /// The slot that opens a new leaf in a round of `layout` (the `open`
    /// input, used and 0), whose index is `$new_leaf`; `None` when the round
    /// opens nothing.
    pub fn opening(layout: &TreeLayout, public: &BTreeMap<String, Fr>) -> Option<usize> {
        let open = layout.open.as_deref()?;
        let k = layout.index.iter().position(|name| name == open)?;
        let zero = public.get(open).copied().unwrap_or(Fr::from(0u64)) == Fr::from(0u64);
        (k < Self::used_inputs(layout, public) && zero).then_some(layout.first_position() + k)
    }

    /// How many `index` inputs a round uses: the count's value (none when it
    /// exceeds the inputs), or all of them without a count.
    pub fn used_inputs(layout: &TreeLayout, public: &BTreeMap<String, Fr>) -> usize {
        match &layout.count {
            Some(count) => fr_u64(public.get(count).copied().unwrap_or(Fr::from(0u64)))
                .filter(|n| *n as usize <= layout.index.len())
                .unwrap_or(0) as usize,
            None => layout.index.len(),
        }
    }

    /// The changes a round's new leaf hashes make, in slot order: one per
    /// used slot.
    pub fn changes(&self, new_hashes: &[Fr]) -> Vec<(u64, Fr)> {
        self.indices
            .iter()
            .zip(&self.used)
            .zip(new_hashes)
            .filter(|((_, used), _)| **used)
            .map(|((i, _), h)| (*i, *h))
            .collect()
    }

    /// The leaves a round's new leaf hashes leave in the tree, as (slot,
    /// index, hash) in slot order: of the used slots naming one index, the
    /// last, whose change wins in [`rebuild`], and only when its hash is not
    /// 0 (an emptied leaf). These are the leaves the rebuilt tree reaches
    /// among those the round writes, so step 15 stores exactly them: a slot
    /// that repeats an index (a request the app's round flags) leaves no
    /// unreachable leaf behind.
    pub fn written(&self, new_hashes: &[Fr]) -> Vec<(usize, u64, Fr)> {
        let mut last: BTreeMap<u64, (usize, Fr)> = BTreeMap::new();
        let slots = self.indices.iter().zip(&self.used).zip(new_hashes);
        for (slot, ((index, used), hash)) in slots.enumerate() {
            if *used {
                last.insert(*index, (slot, *hash));
            }
        }
        let mut out: Vec<(usize, u64, Fr)> = last
            .into_iter()
            .filter(|(_, (_, hash))| *hash != Fr::from(0u64))
            .map(|(index, (slot, hash))| (slot, index, hash))
            .collect();
        out.sort_by_key(|(slot, _, _)| *slot);
        out
    }
}

/// The leaves a round of `layout` reads in its window (the layout's
/// `window`), from the request's public values (`public`, flattened): the
/// `width` consecutive indices from the `start` input's value when it is
/// below 2^D and a multiple of the width, else from 0 (the round flags the
/// request's start); none when the layout has no window. Each node, the
/// scheduler and every chain verifier derive the same window from the
/// request, so a bad start still loads real leaves.
pub fn window(layout: &TreeLayout, public: &BTreeMap<String, Fr>) -> Vec<u64> {
    let Some(w) = &layout.window else {
        return vec![];
    };
    let width = w.width as u64;
    let limit = 1u64.checked_shl(layout.depth).unwrap_or(u64::MAX);
    let start = public
        .get(&w.start)
        .copied()
        .and_then(fr_u64)
        .filter(|s| *s < limit && width != 0 && s % width == 0)
        .unwrap_or(0);
    (start..start + width).collect()
}

/// The values the nodes' clear trees give for a round's window, from the
/// paths of its loaded leaves (`paths`: the `slots` slots, then the
/// window's leaves in order): each window leaf's old hash, and the window
/// root's siblings, those of its first leaf from height log2 width up. 500
/// for paths that hold fewer leaves.
pub fn window_values(
    paths: &TreePaths,
    slots: usize,
    width: usize,
    depth: u32,
) -> Result<(Vec<Fr>, Vec<Fr>), Refusal> {
    let d = depth as usize;
    let height = width.trailing_zeros() as usize;
    let hashes = paths.old_hashes.get(slots..slots + width);
    let first = paths.siblings.get(slots * d..(slots + 1) * d);
    match (hashes, first) {
        (Some(hashes), Some(first)) if width > 0 && height <= d => Ok((
            hashes.iter().map(|h| h.fr()).collect(),
            first[height..].iter().map(|h| h.fr()).collect(),
        )),
        _ => Err(Refusal::mpc_failure(format!(
            "tree paths of {} leaves hold no window of {width} after {slots} slots",
            paths.old_hashes.len()
        ))),
    }
}

/// The append index after a round: one past the highest written leaf, at
/// least `next`.
pub fn next_after(next: u64, changes: &[(u64, Fr)]) -> u64 {
    changes
        .iter()
        .filter(|(_, h)| *h != Fr::from(0u64))
        .map(|(i, _)| i + 1)
        .fold(next, u64::max)
}

/// `$new_leaf` for a version whose append index is `next`: `next`, or 0
/// when the tree of depth `depth` is full.
pub fn new_leaf(next: u64, depth: u32) -> u64 {
    if next < 1u64.checked_shl(depth).unwrap_or(u64::MAX) {
        next
    } else {
        0
    }
}
