//! The suite's cases for the tip tables: versions, tree nodes and blobs.

use super::*;

/// A tree-valued key's versions share the nodes they do not change; a
/// pruned version takes exactly the nodes no kept version reaches,
/// leaves included, also when versions are pruned out of order of the
/// nodes they introduced; the kept version's paths and leaves still
/// read.
pub fn tree_nodes_are_shared_by_versions_and_pruned_by_reachability<S: Store>(store: &S) {
    use crate::tree::{self, TreeNode};
    let depth = 4;
    let z = tree::zeros(depth);
    let key = "book";
    let node_of =
        |h: Fr| -> Option<TreeNode> { store.tip_node(ns(), key, h).unwrap().map(|n| n.node) };
    // three rounds: leaves 0 and 5; leaf 7; leaf 5 again
    let rounds: [(u64, &[(u64, u64)]); 3] = [
        (0xb1, &[(0, 10), (5, 50)]),
        (0xb2, &[(7, 70)]),
        (0xb3, &[(5, 51)]),
    ];
    let mut root = z[depth as usize];
    let mut parent = 0u64;
    let mut roots = Vec::new();
    for (n, (commitment, writes)) in rounds.iter().enumerate() {
        let changes: Vec<(u64, Fr)> = writes
            .iter()
            .map(|(i, v)| (*i, Fr::from(1000 + v)))
            .collect();
        let mut txn = store.begin(ns());
        let rebuilt = {
            let nodes = rules::TreeNodes { read: store, key };
            let read = |h: Fr| nodes.get(&txn, h).map(|n| n.map(|n| n.node));
            tree::rebuild(&read, &z, root, &changes).unwrap()
        };
        let mut added: Vec<(Fr, TreeNode)> = changes
            .iter()
            .map(|(i, h)| {
                (
                    *h,
                    TreeNode::Leaf {
                        index: *i,
                        vec: vec![shared(crate::tree::fr_u64(*h).unwrap())],
                    },
                )
            })
            .collect();
        added.extend(rebuilt.added.into_iter().map(|(h, _, n)| (h, n)));
        rules::TreeNodes { read: store, key }
            .add_version(&mut txn, rebuilt.root, added)
            .unwrap();
        let v = TipVersion {
            tree: Some(VersionTree::Clear(TreeRoot {
                root: rebuilt.root,
                next: tree::next_after(0, &changes),
            })),
            vec: vec![],
            ..version(key, *commitment, parent, n as u64, n as u8 + 1)
        };
        rules::stage_versions(
            store,
            &mut txn,
            key,
            Some(v),
            &view(*commitment, n as u64, 10),
        )
        .unwrap();
        txn.put_request(new_request(n as u8 + 1, 1000 + n as u64));
        store.commit(txn).unwrap();
        root = rebuilt.root;
        roots.push(root);
        parent = *commitment;
    }
    let [r1, r2, r3] = [roots[0], roots[1], roots[2]];
    // v1's leaf 5 is still reached from v2; v3 replaced it
    let old_leaf5 = Fr::from(1050u64);
    assert!(node_of(old_leaf5).is_some());
    assert_eq!(store.tip_node(ns(), key, r1).unwrap().unwrap().refs, 1);
    // prune v1 and v2 (orphans once the slot holds v3, past the depth)
    let late = 10 + PROVING_LAG + 1;
    tip_round(store, 9, key, None, view(0xb3, 3, late)).unwrap();
    let held: Vec<Fr> = store
        .tip_versions(ns(), key)
        .unwrap()
        .iter()
        .map(|v| v.commitment)
        .collect();
    assert_eq!(held, [Fr::from(0xb3u64)]);
    for gone in [r1, r2, old_leaf5] {
        assert!(node_of(gone).is_none(), "{gone} kept");
    }
    // every path of v3 reads, every leaf it reaches is held, and nothing
    // else of the key is
    let nodes = |h: Fr| store.tip_node(ns(), key, h).map(|n| n.map(|n| n.node));
    for (i, want) in [(0u64, 1010u64), (5, 1051), (7, 1070), (3, 0)] {
        let p = tree::path(&nodes, &z, r3, i).unwrap();
        assert_eq!(p.leaf, Fr::from(want));
        assert_eq!(tree::root_of(p.leaf, &p.siblings, i), r3);
        if want != 0 {
            assert!(matches!(node_of(p.leaf), Some(TreeNode::Leaf { index, .. }) if index == i));
        }
    }
    // v3 turns orphan at late + 100; pruning it once that is past the
    // depth empties the key's tree
    let orphaned = late + 100;
    tip_round(store, 10, key, None, view(0xbb, 9, orphaned)).unwrap();
    assert!(node_of(r3).is_some());
    let past = orphaned + PROVING_LAG + 1;
    tip_round(store, 11, key, None, view(0xbb, 9, past)).unwrap();
    for gone in [r3, Fr::from(1010u64), Fr::from(1051u64), Fr::from(1070u64)] {
        assert!(node_of(gone).is_none(), "{gone} kept");
    }
}

/// A version is stored with every field, read back by its commitment and
/// listed under its key; a second version under the same commitment is
/// refused (409), one under 0 is a store error (500), and a version of
/// another key or namespace is not listed.
pub fn a_tip_version_is_written_once_and_never_overwritten<S: Store>(store: &S) {
    let v1 = version("pool", 0xa1, 0, 0, 1);
    tip_round(store, 1, "pool", Some(v1.clone()), view(0, 0, 10)).unwrap();
    let held = store.tip_version(ns(), "pool", Fr::from(0xa1u64)).unwrap();
    assert_eq!(
        held,
        Some(TipVersion {
            block: 10,
            ..v1.clone()
        })
    );
    assert_eq!(store.tip_versions(ns(), "pool").unwrap().len(), 1);
    assert!(store.tip_versions(ns(), "other").unwrap().is_empty());
    assert!(
        store
            .tip_versions(Fr::from(7u64), "pool")
            .unwrap()
            .is_empty()
    );
    assert!(
        store
            .tip_version(ns(), "pool", Fr::from(0xa2u64))
            .unwrap()
            .is_none()
    );

    let again = TipVersion {
        parent: Fr::from(0xffu64),
        ..version("pool", 0xa1, 0, 1, 2)
    };
    conflict(
        tip_round(store, 2, "pool", Some(again), view(0xa1, 1, 11)),
        "is never overwritten",
    );
    let zero = version("pool", 0, 0xa1, 1, 3);
    let err = tip_round(store, 3, "pool", Some(zero), view(0xa1, 1, 11)).unwrap_err();
    assert_eq!(err.class, ErrorClass::MpcFailure, "{err}");
    assert!(err.message.contains("0 is no state"), "{err}");
    // neither refused round changed the version
    assert_eq!(
        store.tip_version(ns(), "pool", Fr::from(0xa1u64)).unwrap(),
        Some(TipVersion { block: 10, ..v1 })
    );
    assert!(store.request(ns(), id(2)).unwrap().is_none());
}

/// Liveness by queue entry and retention by block. Entry 0 (the init)
/// leaves A; entry 1 is computed twice on A (B, then the recompute B'),
/// and entry 2 is pipelined on B'. The older attempt B lands: A is
/// superseded, B' and C (built on B') are orphans, the recompute C2 on B
/// is live. A replaced proposed block that puts B' back in the slot finds
/// it still held. Every orphan is deleted only once the block it turned
/// orphan at is more than the retention depth behind.
pub fn tip_versions_follow_the_chain_and_are_pruned_after_the_retention_depth<S: Store>(store: &S) {
    use VersionStatus::{Canonical, Live, Orphan};
    let (a, b, b2, c, c2) = (0xa0, 0xb0, 0xb2, 0xc0, 0xc2);
    let statuses = || -> Vec<(u64, VersionStatus, u64)> {
        store
            .tip_versions(ns(), "pool")
            .unwrap()
            .into_iter()
            .map(|v| {
                let named = [a, b, b2, c, c2]
                    .into_iter()
                    .find(|x| Fr::from(*x) == v.commitment)
                    .unwrap();
                (named, v.status, v.block)
            })
            .collect()
    };
    tip_round(
        store,
        1,
        "pool",
        Some(version("pool", a, 0, 0, 1)),
        view(0, 0, 10),
    )
    .unwrap();
    // A landed: head 1
    tip_round(
        store,
        2,
        "pool",
        Some(version("pool", b, a, 1, 2)),
        view(a, 1, 11),
    )
    .unwrap();
    tip_round(
        store,
        3,
        "pool",
        Some(version("pool", b2, a, 1, 3)),
        view(a, 1, 12),
    )
    .unwrap();
    tip_round(
        store,
        4,
        "pool",
        Some(version("pool", c, b2, 2, 4)),
        view(a, 1, 12),
    )
    .unwrap();
    assert_eq!(
        statuses(),
        [
            (a, Canonical, 12),
            (b, Live, 12),
            (b2, Live, 12),
            (c, Live, 12)
        ]
    );

    // the older attempt B lands at block 13 (head 2); entry 2 is
    // recomputed on it. A is superseded and B', C orphaned at 13.
    tip_round(
        store,
        5,
        "pool",
        Some(version("pool", c2, b, 2, 5)),
        view(b, 2, 13),
    )
    .unwrap();
    assert_eq!(
        statuses(),
        [
            (a, Orphan, 13),
            (b, Canonical, 13),
            (b2, Orphan, 13),
            (c, Orphan, 13),
            (c2, Live, 13)
        ]
    );

    // a replaced proposed block puts B' in the slot: it is still held,
    // and canonical again, with C live on it; B and C2 turn orphan at
    // 14, A keeps its block
    tip_round(store, 6, "pool", None, view(b2, 2, 14)).unwrap();
    assert_eq!(
        statuses(),
        [
            (a, Orphan, 13),
            (b, Orphan, 14),
            (b2, Canonical, 14),
            (c, Live, 14),
            (c2, Orphan, 14)
        ]
    );

    // B wins again at 13 + depth: B' and C turn orphan there; A,
    // orphaned at 13, is at the retention depth and kept
    let depth = PROVING_LAG;
    tip_round(store, 7, "pool", None, view(b, 2, 13 + depth)).unwrap();
    assert_eq!(
        statuses(),
        [
            (a, Orphan, 13),
            (b, Canonical, 13 + depth),
            (b2, Orphan, 13 + depth),
            (c, Orphan, 13 + depth),
            (c2, Live, 13 + depth)
        ]
    );
    // one block later A goes
    tip_round(store, 8, "pool", None, view(b, 2, 14 + depth)).unwrap();
    assert_eq!(
        statuses(),
        [
            (b, Canonical, 14 + depth),
            (b2, Orphan, 13 + depth),
            (c, Orphan, 13 + depth),
            (c2, Live, 14 + depth)
        ]
    );
    // entry 2 is skipped (head 3): C2 turns orphan at 15 + depth
    tip_round(store, 9, "pool", None, view(b, 3, 15 + depth)).unwrap();
    assert_eq!(
        statuses(),
        [
            (b, Canonical, 15 + depth),
            (b2, Orphan, 13 + depth),
            (c, Orphan, 13 + depth),
            (c2, Orphan, 15 + depth)
        ]
    );
    tip_round(store, 10, "pool", None, view(b, 3, 14 + 2 * depth)).unwrap();
    assert_eq!(
        statuses(),
        [(b, Canonical, 14 + 2 * depth), (c2, Orphan, 15 + depth)]
    );
    tip_round(store, 11, "pool", None, view(b, 3, 16 + 2 * depth)).unwrap();
    assert_eq!(statuses(), [(b, Canonical, 16 + 2 * depth)]);
}

/// The statuses and blocks of `key`'s held versions, by commitment.
fn version_blocks<S: Store>(store: &S, key: &str) -> Vec<(Fr, VersionStatus, u64)> {
    store
        .tip_versions(ns(), key)
        .unwrap()
        .into_iter()
        .map(|v| (v.commitment, v.status, v.block))
        .collect()
}

/// Two commits on one key 70 blocks apart. The first, at block 10,
/// leaves A canonical and B and B' live on it; on the chain B' lands
/// and B's entry is done at block 79, and the next commit on the key
/// is at block 80. B is orphaned 1 block before that commit and is
/// marked orphan at 80, the first block a commit saw it: it survives
/// the commit 70 blocks after it was last live, and is deleted only
/// once 80 is more than the retention depth behind the view.
pub fn an_orphan_is_kept_for_the_retention_depth_after_it_turned_orphan<S: Store>(store: &S) {
    use VersionStatus::{Canonical, Live, Orphan};
    let (a, b, b2) = (0xa0, 0xb0, 0xb2);
    let f = |x: u64| Fr::from(x);
    let depth = PROVING_LAG;
    tip_round(
        store,
        1,
        "pool",
        Some(version("pool", a, 0, 0, 1)),
        view(0, 0, 9),
    )
    .unwrap();
    tip_round(
        store,
        2,
        "pool",
        Some(version("pool", b, a, 1, 2)),
        view(a, 1, 10),
    )
    .unwrap();
    tip_round(
        store,
        3,
        "pool",
        Some(version("pool", b2, a, 1, 3)),
        view(a, 1, 10),
    )
    .unwrap();
    assert_eq!(
        version_blocks(store, "pool"),
        [(f(a), Canonical, 10), (f(b), Live, 10), (f(b2), Live, 10)]
    );

    tip_round(store, 4, "pool", None, view(b2, 2, 80)).unwrap();
    assert_eq!(
        version_blocks(store, "pool"),
        [
            (f(a), Orphan, 80),
            (f(b), Orphan, 80),
            (f(b2), Canonical, 80)
        ]
    );
    tip_round(store, 5, "pool", None, view(b2, 2, 80 + depth)).unwrap();
    assert_eq!(version_blocks(store, "pool").len(), 3);
    tip_round(store, 6, "pool", None, view(b2, 2, 81 + depth)).unwrap();
    assert_eq!(
        version_blocks(store, "pool"),
        [(f(b2), Canonical, 81 + depth)]
    );
}

/// Every mark carries the hash of its block, and a mark the view names as
/// replaced (`VersionView::replaced`: its block's hash is no longer the
/// chain's) is ignored: the version is marked again under the view, not
/// deleted, while a mark below the settled block that stands is deleted.
pub fn a_mark_on_a_replaced_block_is_marked_again<S: Store>(store: &S) {
    use VersionStatus::{Canonical, Orphan};
    let view =
        |slot: u64, head: u64, block: u64, settled: u64, replaced: &[u64]| rules::VersionView {
            slot: Fr::from(slot),
            head,
            block,
            block_hash: Fr::from(0xb000 + block),
            settled,
            replaced: replaced.iter().map(|c| Fr::from(*c)).collect(),
        };
    let (a, b, b2) = (0xa0, 0xb0, 0xb2);
    let marks = || -> Vec<(Fr, VersionStatus, u64, Fr)> {
        store
            .tip_versions(ns(), "pool")
            .unwrap()
            .into_iter()
            .map(|v| (v.commitment, v.status, v.block, v.block_hash))
            .collect()
    };
    let f = |x: u64| Fr::from(x);
    for (n, new, at) in [
        (1, version("pool", a, 0, 0, 1), view(0, 0, 10, 0, &[])),
        (2, version("pool", b, a, 1, 2), view(a, 1, 10, 0, &[])),
        (3, version("pool", b2, a, 1, 3), view(b2, 2, 20, 0, &[])),
    ] {
        tip_round(store, n, "pool", Some(new), at).unwrap();
    }
    assert_eq!(
        marks(),
        [
            (f(a), Orphan, 20, f(0xb000 + 20)),
            (f(b), Orphan, 20, f(0xb000 + 20)),
            (f(b2), Canonical, 20, f(0xb000 + 20))
        ]
    );
    // the settled block passes both marks; A's block was replaced
    tip_round(store, 4, "pool", None, view(b2, 2, 30, 25, &[a])).unwrap();
    assert_eq!(
        marks(),
        [
            (f(a), Orphan, 30, f(0xb000 + 30)),
            (f(b2), Canonical, 30, f(0xb000 + 30))
        ],
        "B deleted; A marked again under the view"
    );
}

/// The retention counts from the settled block, not from the block the
/// view was read at. A and B, orphaned at 80 when B' lands, survive a
/// commit whose view is far ahead (80 + 10 * PROVING_LAG) while its
/// settled block is at most 80, or was not read (0); the prune pass at the
/// same proposed block deletes them once the settled block is 81.
pub fn retention_counts_from_the_settled_block<S: Store>(store: &S) {
    use crate::state::NodeVersions;
    use VersionStatus::{Canonical, Orphan};
    let view = |slot: u64, head: u64, block: u64, settled: u64| rules::VersionView {
        slot: Fr::from(slot),
        head,
        block,
        settled,
        ..Default::default()
    };
    let (a, b, b2) = (0xa0, 0xb0, 0xb2);
    let f = |x: u64| Fr::from(x);
    let far = 80 + 10 * PROVING_LAG;
    for (n, new, at) in [
        (1, version("pool", a, 0, 0, 1), view(0, 0, 10, 10)),
        (2, version("pool", b, a, 1, 2), view(a, 1, 10, 10)),
        (3, version("pool", b2, a, 1, 3), view(b2, 2, 80, 70)),
    ] {
        tip_round(store, n, "pool", Some(new), at).unwrap();
    }
    assert_eq!(
        version_blocks(store, "pool"),
        [
            (f(a), Orphan, 80),
            (f(b), Orphan, 80),
            (f(b2), Canonical, 80)
        ]
    );
    for (n, settled) in [(4, 0), (5, 70), (6, 80)] {
        tip_round(store, n, "pool", None, view(b2, 2, far, settled)).unwrap();
        assert_eq!(
            version_blocks(store, "pool"),
            [
                (f(a), Orphan, 80),
                (f(b), Orphan, 80),
                (f(b2), Canonical, far)
            ],
            "settled block {settled}"
        );
    }
    let views = |_: Fr, keys: &[String]| -> Result<Option<Vec<rules::VersionView>>, Refusal> {
        Ok(Some(keys.iter().map(|_| view(b2, 2, far, 81)).collect()))
    };
    assert_eq!(NodeVersions::mark(store, ns(), &views).unwrap(), 2);
    assert_eq!(version_blocks(store, "pool"), [(f(b2), Canonical, far)]);
}

/// A version's block is set when a commit first marks it orphan and
/// does not move at later commits while it stays orphan; a new version
/// that is orphan when created is marked at its commit's block.
pub fn an_orphan_keeps_the_block_it_was_first_marked_orphan_at<S: Store>(store: &S) {
    use VersionStatus::{Canonical, Orphan};
    let (a, b, b2, c) = (0xa0, 0xb0, 0xb2, 0xc0);
    let f = |x: u64| Fr::from(x);
    tip_round(
        store,
        1,
        "pool",
        Some(version("pool", a, 0, 0, 1)),
        view(0, 0, 10),
    )
    .unwrap();
    tip_round(
        store,
        2,
        "pool",
        Some(version("pool", b, a, 1, 2)),
        view(a, 1, 11),
    )
    .unwrap();
    // B' lands at 20; B is orphan from then on
    tip_round(
        store,
        3,
        "pool",
        Some(version("pool", b2, a, 1, 3)),
        view(b2, 2, 20),
    )
    .unwrap();
    let at_20 = [
        (f(a), Orphan, 20),
        (f(b), Orphan, 20),
        (f(b2), Canonical, 20),
    ];
    assert_eq!(version_blocks(store, "pool"), at_20);
    for (n, block) in [(4, 30), (5, 45), (6, 60)] {
        tip_round(store, n, "pool", None, view(b2, 2, block)).unwrap();
        let blocks = version_blocks(store, "pool");
        assert_eq!(blocks[..2], at_20[..2], "at block {block}");
        assert_eq!(blocks[2], (f(b2), Canonical, block));
    }
    // a version computed on B, which is orphan, is orphan when created
    tip_round(
        store,
        7,
        "pool",
        Some(version("pool", c, b, 2, 7)),
        view(b2, 2, 61),
    )
    .unwrap();
    assert_eq!(version_blocks(store, "pool")[3], (f(c), Orphan, 61));
    tip_round(store, 8, "pool", None, view(b2, 2, 62)).unwrap();
    assert_eq!(version_blocks(store, "pool")[3], (f(c), Orphan, 61));
}

/// The prune pass between rounds. Rounds at block 10 leave, on `pool`,
/// A canonical with B and B' live on it, and on `book` X canonical with
/// Y live; then no round runs on either key. On the chain B' lands and
/// Y's entry is skipped. The pass at block 80 marks both keys against
/// their views, the orphans at 80, in one commit with no request row;
/// the pass at 80 + depth deletes nothing and the one a block later
/// deletes the three orphans and leaves the key's blobs, which are its
/// holder's to delete. A view read behind a version's block marks the
/// orphan at the version's own block; a pass with nothing to change
/// commits nothing; a key the pass has no view of is untouched; and a new
/// version is still refused without its request row.
pub fn the_prune_pass_marks_and_prunes_keys_without_a_round<S: Store>(store: &S) {
    use crate::state::NodeVersions;
    use VersionStatus::{Canonical, Orphan};
    let (a, b, b2, x, y) = (0xa0, 0xb0, 0xb2, 0xd0, 0xd1);
    let f = |x: u64| Fr::from(x);
    let depth = PROVING_LAG;
    for (n, key, new, at) in [
        (1, "pool", version("pool", a, 0, 0, 1), view(0, 0, 10)),
        (2, "pool", version("pool", b, a, 1, 2), view(a, 1, 10)),
        (3, "pool", version("pool", b2, a, 1, 3), view(a, 1, 10)),
        (4, "book", version("book", x, 0, 0, 4), view(0, 0, 10)),
        (5, "book", version("book", y, x, 1, 5), view(x, 1, 10)),
    ] {
        tip_round(store, n, key, Some(new), at).unwrap();
    }
    let pass = |pool: rules::VersionView, book: rules::VersionView| {
        NodeVersions::prune(
            store,
            ns(),
            &[("pool".to_string(), pool), ("book".to_string(), book)],
        )
        .unwrap()
    };
    // a holder blob per pool version, which the pass leaves to the holder
    let blob = |c: u64| format!("journal.{c}");
    let mut txn = store.begin(ns());
    for c in [a, b, b2] {
        txn.blob("pool", &blob(c), Some(vec![c as u8]));
    }
    store.commit(txn).unwrap();
    let journal = |c: u64| store.blob(ns(), "pool", &blob(c)).unwrap();
    assert_eq!(pass(view(b2, 2, 80), view(x, 2, 80)), 0);
    assert_eq!(
        version_blocks(store, "pool"),
        [
            (f(a), Orphan, 80),
            (f(b), Orphan, 80),
            (f(b2), Canonical, 80)
        ]
    );
    assert_eq!(
        version_blocks(store, "book"),
        [(f(x), Canonical, 80), (f(y), Orphan, 80)]
    );
    assert_eq!(pass(view(b2, 2, 80 + depth), view(x, 2, 80 + depth)), 0);
    assert_eq!(version_blocks(store, "pool").len(), 3);
    assert_eq!(journal(a), Some(vec![a as u8]));
    assert_eq!(pass(view(b2, 2, 81 + depth), view(x, 2, 81 + depth)), 3);
    assert_eq!(
        version_blocks(store, "pool"),
        [(f(b2), Canonical, 81 + depth)]
    );
    for c in [a, b, b2] {
        assert_eq!(journal(c), Some(vec![c as u8]), "the holder's blob stays");
    }
    assert_eq!(
        version_blocks(store, "book"),
        [(f(x), Canonical, 81 + depth)]
    );
    // nothing to change: nothing committed, nothing moved
    assert_eq!(pass(view(b2, 2, 81 + depth), view(x, 2, 81 + depth)), 0);

    // a view behind the version's block: the orphan keeps its own block
    tip_round(
        store,
        6,
        "pool",
        Some(version("pool", 0xc0, b2, 2, 6)),
        view(b2, 2, 200),
    )
    .unwrap();
    NodeVersions::prune(store, ns(), &[("pool".to_string(), view(b2, 3, 190))]).unwrap();
    assert_eq!(version_blocks(store, "pool")[1], (f(0xc0), Orphan, 200));
    assert_eq!(
        version_blocks(store, "book"),
        [(f(x), Canonical, 81 + depth)]
    );

    // the pass never puts a version; a put without a request is refused
    let mut txn = store.begin(ns());
    rules::stage_versions(
        store,
        &mut txn,
        "book",
        Some(version("book", 0xd2, x, 2, 7)),
        &view(x, 2, 300),
    )
    .unwrap();
    let err = store.commit(txn).unwrap_err();
    assert_eq!(err.class, ErrorClass::MpcFailure, "{err}");
    assert!(err.message.contains("need its request row"), "{err}");
    assert_eq!(version_blocks(store, "book").len(), 1);
}

/// A blob of an oblivious key's size class (a DORAM's state is tens to
/// hundreds of MiB) is written, read back whole, replaced and deleted.
pub fn a_large_blob_round_trips<S: Store>(store: &S) {
    let big: Vec<u8> = (0..64 * 1024 * 1024 + 7)
        .map(|i: usize| (i.wrapping_mul(31) ^ (i >> 13)) as u8)
        .collect();
    let mut txn = store.begin(ns());
    txn.blob("tree", "oram", Some(big.clone()));
    store.commit(txn).unwrap();
    let back = store.blob(ns(), "tree", "oram").unwrap().unwrap();
    assert_eq!(back.len(), big.len());
    assert!(back == big, "the blob reads back byte for byte");

    let mut replaced = big;
    replaced.truncate(1024 * 1024);
    replaced[0] ^= 0xff;
    let mut txn = store.begin(ns());
    txn.blob("tree", "oram", Some(replaced.clone()));
    store.commit(txn).unwrap();
    assert_eq!(store.blob(ns(), "tree", "oram").unwrap(), Some(replaced));

    let mut txn = store.begin(ns());
    txn.blob("tree", "oram", None);
    store.commit(txn).unwrap();
    assert_eq!(store.blob(ns(), "tree", "oram").unwrap(), None);
}

pub fn blobs_are_written_listed_and_deleted<S: Store>(store: &S) {
    let other = Fr::from(0xbeefu64);
    let mut txn = store.begin(ns());
    txn.blob("tree", "doram", Some(vec![1, 2]));
    txn.blob("tree", "fill", Some(vec![3]));
    txn.blob("map", "doram", Some(vec![4]));
    store.commit(txn).unwrap();
    let mut txn = store.begin(other);
    txn.blob("elsewhere", "doram", Some(vec![5]));
    store.commit(txn).unwrap();

    assert_eq!(store.blob(ns(), "tree", "doram").unwrap(), Some(vec![1, 2]));
    assert_eq!(store.blob(ns(), "map", "fill").unwrap(), None);
    assert_eq!(store.blob(other, "tree", "doram").unwrap(), None);
    assert_eq!(store.blob_keys(ns()).unwrap(), ["map", "tree"]);
    assert_eq!(store.blob_keys(other).unwrap(), ["elsewhere"]);
    assert_eq!(store.blob_names(ns(), "tree").unwrap(), ["doram", "fill"]);
    assert_eq!(store.blob_names(ns(), "map").unwrap(), ["doram"]);
    assert!(store.blob_names(other, "tree").unwrap().is_empty());

    let mut txn = store.begin(ns());
    txn.blob("tree", "doram", Some(vec![6]));
    txn.blob("tree", "fill", None);
    txn.blob("map", "doram", None);
    store.commit(txn).unwrap();
    assert_eq!(store.blob(ns(), "tree", "doram").unwrap(), Some(vec![6]));
    assert_eq!(store.blob(ns(), "tree", "fill").unwrap(), None);
    assert_eq!(store.blob_keys(ns()).unwrap(), ["tree"]);
    assert_eq!(store.blob_names(ns(), "tree").unwrap(), ["doram"]);
    assert!(store.blob_names(ns(), "map").unwrap().is_empty());
}

/// Commit attempt `n` at the queued request `0xc0 + n`: each version of
/// `writes` with the clear tree nodes it adds, every key marked against
/// `view` of its slot (head 1, no retention floor).
fn tip_attempt<S: Store>(
    store: &S,
    n: u8,
    writes: Vec<(TipVersion, Vec<(Fr, crate::tree::TreeNode)>)>,
    slots: &[(&str, u64)],
) {
    let mut txn = store.begin(ns());
    for (v, added) in writes {
        let key = v.key.clone();
        if let Some(t) = v.tree.and_then(VersionTree::clear) {
            rules::TreeNodes {
                read: store,
                key: &key,
            }
            .add_version(&mut txn, t.root, added)
            .unwrap();
        }
        let slot = slots.iter().find(|(k, _)| *k == key).map_or(0, |s| s.1);
        let view = rules::VersionView {
            slot: Fr::from(slot),
            head: 1,
            block: 10,
            settled: 0,
            ..Default::default()
        };
        rules::stage_versions(store, &mut txn, &key, Some(v), &view).unwrap();
    }
    txn.put_request(NewRequest {
        chain_request_id: Some(Fr::from(0xc0 + n as u64)),
        ..new_request(n, 1000 + n as u64)
    });
    store.commit(txn).unwrap();
}

/// The rollback of a tip attempt deletes every version its request wrote
/// and releases the tree nodes only those versions reached, and keeps the
/// row as `rolled_back`. Refused (409), changing nothing: an attempt a kept
/// version builds on (until that one is rolled back), and a canonical
/// version (the attempt landed).
pub fn a_tip_attempt_s_rollback_deletes_its_versions<S: Store>(store: &S) {
    use crate::tree::TreeNode;
    let leaf = |index: u64| TreeNode::Leaf {
        index,
        vec: vec![shared(index)],
    };
    let inner = |left: u64, right: u64| TreeNode::Inner {
        left: Fr::from(left),
        right: Fr::from(right),
    };
    let book = |commitment: u64, parent: u64, index: u64, n: u8, root: u64| TipVersion {
        tree: Some(VersionTree::Clear(TreeRoot {
            root: Fr::from(root),
            next: index + 1,
        })),
        vec: vec![],
        ..version("book", commitment, parent, index, n)
    };
    let slots = [("pool", 0x11), ("book", 0xb1)];
    // attempt 1 (canonical): pool 0x11, book 0xb1 over leaf 0x501
    tip_attempt(
        store,
        1,
        vec![
            (version("pool", 0x11, 0, 0, 1), vec![]),
            (
                book(0xb1, 0, 0, 1, 0x510),
                vec![
                    (Fr::from(0x501u64), leaf(0)),
                    (Fr::from(0x510u64), inner(0x501, 0x5ff)),
                ],
            ),
        ],
        &slots,
    );
    // attempt 2 (live): pool 0x12, book 0xb2 adding leaf 0x502
    tip_attempt(
        store,
        2,
        vec![
            (version("pool", 0x12, 0x11, 1, 2), vec![]),
            (
                book(0xb2, 0xb1, 1, 2, 0x520),
                vec![
                    (Fr::from(0x502u64), leaf(1)),
                    (Fr::from(0x520u64), inner(0x501, 0x502)),
                ],
            ),
        ],
        &slots,
    );
    // attempt 3 (live), built on attempt 2's pool version
    tip_attempt(
        store,
        3,
        vec![(version("pool", 0x13, 0x12, 2, 3), vec![])],
        &slots,
    );
    let commitments = |key: &str| -> Vec<u64> {
        store
            .tip_versions(ns(), key)
            .unwrap()
            .iter()
            .map(|v| crate::tree::fr_u64(v.commitment).unwrap())
            .collect()
    };
    let refs = |hash: u64| {
        store
            .tip_node(ns(), "book", Fr::from(hash))
            .unwrap()
            .map(|n| n.refs)
    };
    let status = |n: u8| store.request(ns(), id(n)).unwrap().unwrap().status;
    assert_eq!(refs(0x501), Some(2));

    let keys = node_keys();
    conflict(
        rules::restore(store, &keys, ns(), id(2)),
        &format!(
            "was built on version {} after request {} (by request {})",
            fr_to_hex(Fr::from(0x12u64)),
            id(2),
            id(3)
        ),
    );
    assert_eq!(status(2), RequestStatus::Committed);
    rules::restore(store, &keys, ns(), id(3)).unwrap();
    assert_eq!(commitments("pool"), [0x11, 0x12]);
    rules::restore(store, &keys, ns(), id(2)).unwrap();
    assert_eq!(commitments("pool"), [0x11]);
    assert_eq!(commitments("book"), [0xb1]);
    assert_eq!((refs(0x520), refs(0x502)), (None, None));
    assert_eq!((refs(0x510), refs(0x501)), (Some(1), Some(1)));
    assert_eq!(
        (status(2), status(3)),
        (RequestStatus::RolledBack, RequestStatus::RolledBack)
    );
    conflict(
        store
            .fetch_by_chain_request_id(ns(), Fr::from(0xc2u64))
            .map(drop),
        "rolled back",
    );

    conflict(
        rules::restore(store, &keys, ns(), id(1)),
        "the attempt landed",
    );
    assert_eq!(status(1), RequestStatus::Committed);
    assert_eq!(
        (commitments("pool"), commitments("book")),
        (vec![0x11], vec![0xb1])
    );
}

/// A tip attempt that wrote a version held in blobs (an oblivious tree) is
/// not rolled back (409): its row stays committed and its version held.
pub fn an_oblivious_version_is_not_rolled_back<S: Store>(store: &S) {
    let v = TipVersion {
        tree: Some(VersionTree::Blobs { next: 1 }),
        vec: vec![],
        ..version("tree", 0x21, 0, 0, 1)
    };
    tip_attempt(store, 1, vec![(v, vec![])], &[]);
    conflict(
        rules::restore(store, &node_keys(), ns(), id(1)),
        "held in blobs",
    );
    let row = store.request(ns(), id(1)).unwrap().unwrap();
    assert_eq!(row.status, RequestStatus::Committed);
    assert!(
        store
            .tip_version(ns(), "tree", Fr::from(0x21u64))
            .unwrap()
            .is_some()
    );
}
