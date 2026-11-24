//! The tree vectors test: testvectors/tip_tree.json and tip_tree_vectors'
//! Prover.toml, checked against this code and rewritten on purpose.

use super::tests::{Map, fr};
use super::*;
use crate::manifest::TreeLayout;
use std::collections::BTreeMap;

// -----------------------------------------------------------------
// testvectors/tip_tree.json and testvectors/noir/tip_tree_vectors
// -----------------------------------------------------------------

use crate::field::FieldHex;
use serde_json::{Value, json};
use std::fmt::Write as _;

const TREE_VECTORS: &str = "testvectors/tip_tree.json";
const TREE_NOIR: &str = "testvectors/noir/tip_tree_vectors";
/// The depth of the update cases, the machine's test tree's.
const DEPTH: u32 = 16;
const NS: u64 = 0x7196;
const KEY: u64 = 0xa003;

use sidecar_test_fixtures::dirs::repo;

fn h(v: Fr) -> Value {
    json!(FieldHex(v))
}

fn hs(v: &[Fr]) -> Value {
    Value::Array(v.iter().map(|x| h(*x)).collect())
}

/// One update case: an old tree, three slots (the header and two
/// positions), the new leaves and which slots the round writes.
struct Update {
    name: &'static str,
    old: &'static [(u64, [u64; 2])],
    indices: [u64; 3],
    n_used: u64,
    new_leaves: [[u64; 2]; 3],
    writes: [bool; 3],
    ok: bool,
}

/// The old tree of the update and window cases: leaves of 2 elements.
const BOOK: &[(u64, [u64; 2])] = &[
    (0, [100, 7]),
    (1, [10, 8]),
    (2, [20, 9]),
    (7, [70, 10]),
    (40001, [5, 11]),
];

fn updates() -> Vec<Update> {
    let book = BOOK;
    vec![
        Update {
            name: "slots 0, 1, 2: path 2's sibling at height 1 is on paths 0 and 1; only the latest (1) gives the root",
            old: book,
            indices: [0, 1, 2],
            n_used: 3,
            new_leaves: [[130, 21], [11, 22], [21, 23]],
            writes: [true, true, true],
            ok: true,
        },
        Update {
            name: "an opening deposit: slot 1 takes the empty leaf 3, slot 2 unused (index 0)",
            old: book,
            indices: [0, 3, 0],
            n_used: 2,
            new_leaves: [[105, 24], [5, 25], [0, 0]],
            writes: [true, true, false],
            ok: true,
        },
        Update {
            name: "ok = false: nothing is written and the root stays",
            old: book,
            indices: [0, 1, 7],
            n_used: 3,
            new_leaves: [[1, 1], [2, 2], [3, 3]],
            writes: [true, true, true],
            ok: false,
        },
        Update {
            name: "positions 40000 and 40001 meet below the root's child; slot 1 opens 40000",
            old: book,
            indices: [0, 40000, 40001],
            n_used: 3,
            new_leaves: [[110, 26], [6, 27], [4, 28]],
            writes: [true, true, true],
            ok: true,
        },
        Update {
            name: "a skipped probe: slot 1 is not written, slots 0 and 2 are",
            old: book,
            indices: [0, 2, 7],
            n_used: 3,
            new_leaves: [[90, 29], [0, 0], [60, 30]],
            writes: [true, false, true],
            ok: true,
        },
    ]
}

fn fr_leaf(v: &[u64]) -> Vec<Fr> {
    v.iter().map(|x| fr(*x)).collect()
}

#[allow(clippy::needless_range_loop)] // slot k indexes five arrays
fn update_json(u: &Update) -> Value {
    let (ns, key) = (fr(NS), fr(KEY));
    let z = zeros(DEPTH);
    let mut store = Map::default();
    let changes: Vec<(u64, Fr)> = u
        .old
        .iter()
        .map(|(i, leaf)| (*i, leaf_hash(ns, key, *i, &fr_leaf(leaf))))
        .collect();
    let old = rebuild(&store, &z, z[DEPTH as usize], &changes).unwrap();
    store.add(&old);
    let old_leaf = |i: u64| -> [u64; 2] {
        u.old
            .iter()
            .find(|(j, _)| *j == i)
            .map_or([0, 0], |(_, l)| *l)
    };
    let mut old_hashes = Vec::new();
    let mut siblings = Vec::new();
    for i in u.indices {
        let p = path(&store, &z, old.root, i).unwrap();
        assert_eq!(root_of(p.leaf, &p.siblings, i), old.root);
        old_hashes.push(p.leaf);
        siblings.push(hs(&p.siblings));
    }
    let mut new_hashes = old_hashes.clone();
    let mut stored = Vec::new();
    for k in 0..3 {
        let write = u.ok && u.writes[k] && (k as u64) < u.n_used;
        if write {
            new_hashes[k] = leaf_hash(ns, key, u.indices[k], &fr_leaf(&u.new_leaves[k]));
        }
        let leaf = if write {
            u.new_leaves[k]
        } else {
            old_leaf(u.indices[k])
        };
        stored.push(hs(&fr_leaf(&leaf)));
    }
    let touch = Touch {
        indices: u.indices.to_vec(),
        used: (0..3).map(|k| k < u.n_used).collect(),
    };
    let new = rebuild(&store, &z, old.root, &touch.changes(&new_hashes)).unwrap();
    let new_root = if u.ok { new.root } else { old.root };
    json!({
        "name": u.name,
        "namespace": h(ns),
        "key": h(key),
        "leaves": u.indices.iter().map(|i| hs(&fr_leaf(&old_leaf(*i)))).collect::<Vec<_>>(),
        "old_hashes": hs(&old_hashes),
        "siblings": siblings,
        "indices": u.indices.iter().map(|i| h(fr(*i))).collect::<Vec<_>>(),
        "n_used": h(fr(u.n_used)),
        "ok": u.ok,
        "writes": u.writes,
        "new_leaves": u.new_leaves.iter().map(|l| hs(&fr_leaf(l))).collect::<Vec<_>>(),
        "old_root": h(old.root),
        "old_c": h(commitment(ns, key, old.root)),
        "new_hashes": hs(&new_hashes),
        "stored": stored,
        "new_root": h(new_root),
        "new_c": h(commitment(ns, key, new_root)),
    })
}

/// One window case: the window of `width` leaves a scan round reads
/// from the request's `start` in [`BOOK`] (from leaf 0 when the start is
/// not below 2^D or not a multiple of the width), with the header slot
/// the round loads.
struct WindowCase {
    name: &'static str,
    width: usize,
    start: u64,
}

fn window_cases() -> Vec<WindowCase> {
    let case = |name, width, start| WindowCase { name, width, start };
    vec![
        case("leaves 4 .. 7 of width 4: leaf 7 occupied", 4, 4),
        case("start 6 is not a multiple of 4: window 0", 4, 6),
        case("start 2^16 is out of range: window 0", 4, 1 << DEPTH),
        case("window 0 of width 8: the header and leaves 1, 2, 7", 8, 0),
        case(
            "leaves 40000 .. 40007 of width 8: leaf 40001 occupied",
            8,
            40000,
        ),
        case(
            "the tree's last window of width 8: empty",
            8,
            (1 << DEPTH) - 8,
        ),
    ]
}

fn window_json(c: &WindowCase) -> Value {
    let (ns, key) = (fr(NS), fr(KEY));
    let z = zeros(DEPTH);
    let mut store = Map::default();
    let changes: Vec<(u64, Fr)> = BOOK
        .iter()
        .map(|(i, leaf)| (*i, leaf_hash(ns, key, *i, &fr_leaf(leaf))))
        .collect();
    let old = rebuild(&store, &z, z[DEPTH as usize], &changes).unwrap();
    store.add(&old);
    let leaf = |i: u64| -> Vec<Fr> {
        fr_leaf(
            &BOOK
                .iter()
                .find(|(j, _)| *j == i)
                .map_or([0, 0], |(_, l)| *l),
        )
    };
    let layout: TreeLayout = serde_json::from_value(json!({
        "depth": DEPTH, "leaf_len": 2, "probe": 1, "header": true,
        "window": {"width": c.width, "start": "start",
                   "params": {"leaves": "wl", "old_hashes": "wh", "siblings": "ws"}}
    }))
    .unwrap();
    let public = BTreeMap::from([("start".to_string(), fr(c.start))]);
    let indices = window(&layout, &public);
    let loads = [vec![0], indices.clone()].concat();
    let p = paths(&store, &z, old.root, 40002, &loads).unwrap();
    let (hashes, siblings) = window_values(&p, 1, c.width, DEPTH).unwrap();
    let slot = path(&store, &z, old.root, 0).unwrap();
    let aligned = c.start < (1 << DEPTH) && c.start.is_multiple_of(c.width as u64);
    json!({
        "name": c.name,
        "namespace": h(ns),
        "key": h(key),
        "width": c.width,
        "start": h(fr(c.start)),
        "effective_start": h(fr(indices[0])),
        "aligned": aligned,
        "slot_leaf": hs(&leaf(0)),
        "slot_hash": h(slot.leaf),
        "slot_siblings": hs(&slot.siblings),
        "leaves": indices.iter().map(|i| hs(&leaf(*i))).collect::<Vec<_>>(),
        "old_hashes": hs(&hashes),
        "siblings": hs(&siblings),
        "old_root": h(old.root),
    })
}

fn tree_vectors() -> Value {
    let (ns, key) = (fr(NS), fr(KEY));
    let leaf2: Vec<Value> = [(0u64, [100u64, 7u64]), (3, [5, 25]), (65535, [1, 2])]
        .iter()
        .map(|(i, l)| {
            json!({"namespace": h(ns), "key": h(key), "index": h(fr(*i)),
                   "leaf": hs(&fr_leaf(l)), "hash": h(leaf_hash(ns, key, *i, &fr_leaf(l)))})
        })
        .collect();
    let leaf4: Vec<Value> = [(1u64, [0x5e11u64, 1000, 400, 77]), (2, [0, 0, 0, 1])]
        .iter()
        .map(|(i, l)| {
            json!({"namespace": h(ns), "key": h(fr(0xa004)), "index": h(fr(*i)),
                   "leaf": hs(&fr_leaf(l)), "hash": h(leaf_hash(ns, fr(0xa004), *i, &fr_leaf(l)))})
        })
        .collect();
    let nodes: Vec<Value> = [(0u64, 0u64), (1, 2), (0xdead, 0xbeef)]
        .iter()
        .map(|(l, r)| json!({"left": h(fr(*l)), "right": h(fr(*r)), "hash": h(node(fr(*l), fr(*r)))}))
        .collect();
    let z = zeros(DEPTH);
    let commitments: Vec<Value> = [(NS, KEY, z[DEPTH as usize]), (NS + 1, KEY, fr(0x1234))]
        .iter()
        .map(|(n, k, r)| {
            json!({"namespace": h(fr(*n)), "key": h(fr(*k)), "root": h(*r),
                   "commitment": h(commitment(fr(*n), fr(*k), *r))})
        })
        .collect();
    json!({
        "description": "The hashes of a tree-valued node-held key (docs/ARCHITECTURE.md section 6, \"Tree-valued keys\"), K = 3 multi-leaf updates of a depth-16 tree, and the windows a window round reads (\"A read-only window on a tree key\"). Written by sidecar-core src/tree/vectors.rs (write_tree_vectors); read by sidecar-core tests/vectors.rs, pss-client test/tree.test.ts and testvectors/noir/tip_tree_vectors (pss_core tip::tree).",
        "rule": "leaf_hash(i, leaf) = poseidon2([PSS_TIP_LEAF, namespace, key, i, leaf...]) (0 for an empty leaf); node(l, r) = poseidon2([PSS_TIP_NODE, l, r]); commitment = poseidon2([PSS_TIP_TREE, namespace, key, root]); Z_0 = 0, Z_{l+1} = node(Z_l, Z_l); an update writes each used slot's new leaf hash when ok and the slot is written, and rebuilds the root slot after slot; a window of width 2^H is the leaves from start when start < 2^D and start mod 2^H = 0, else from 0, its subtree root built from its leaves' old hashes and taken up its first leaf's D - H siblings above height H to the old root",
        "separators": {
            "leaf": h(label_field(PSS_TIP_LEAF)),
            "node": h(label_field(PSS_TIP_NODE)),
            "tree": h(label_field(PSS_TIP_TREE)),
        },
        "depth": DEPTH,
        "zeros": hs(&z),
        "leaves2": leaf2,
        "leaves4": leaf4,
        "nodes": nodes,
        "commitments": commitments,
        "updates": updates().iter().map(update_json).collect::<Vec<_>>(),
        "windows": window_cases().iter().map(window_json).collect::<Vec<_>>(),
    })
}

fn s(v: &Value) -> String {
    match v {
        Value::Bool(b) => b.to_string(),
        Value::String(x) => format!("\"{x}\""),
        Value::Array(a) => format!("[{}]", a.iter().map(s).collect::<Vec<_>>().join(", ")),
        other => panic!("unexpected {other}"),
    }
}

fn tree_prover_toml(v: &Value) -> String {
    let mut out = String::from(
        "# Written by sidecar-core tree::vectors::write_tree_vectors from testvectors/tip_tree.json.\n",
    );
    writeln!(out, "zeros = {}", s(&v["zeros"])).unwrap();
    let mut table = |name: &str, entries: &Value, fields: &[&str]| {
        for (k, e) in entries.as_array().unwrap().iter().enumerate() {
            writeln!(out, "\n[{name}{k}]").unwrap();
            for f in fields {
                writeln!(out, "{f} = {}", s(&e[*f])).unwrap();
            }
        }
    };
    let leaf = ["namespace", "key", "index", "leaf", "hash"];
    table("leaf2_", &v["leaves2"], &leaf);
    table("leaf4_", &v["leaves4"], &leaf);
    table("node", &v["nodes"], &["left", "right", "hash"]);
    table(
        "commitment",
        &v["commitments"],
        &["namespace", "key", "root", "commitment"],
    );
    table(
        "update",
        &v["updates"],
        &[
            "namespace",
            "key",
            "leaves",
            "old_hashes",
            "siblings",
            "indices",
            "n_used",
            "ok",
            "writes",
            "new_leaves",
            "old_root",
            "old_c",
            "new_hashes",
            "stored",
            "new_root",
            "new_c",
        ],
    );
    // one table per width, as the Noir program's window parameters
    for width in [4, 8] {
        let of_width: Vec<Value> = v["windows"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|w| w["width"] == width)
            .cloned()
            .collect();
        table(
            &format!("window{width}_"),
            &Value::Array(of_width),
            &[
                "namespace",
                "key",
                "start",
                "effective_start",
                "aligned",
                "slot_leaf",
                "slot_hash",
                "slot_siblings",
                "leaves",
                "old_hashes",
                "siblings",
                "old_root",
            ],
        );
    }
    out
}

/// The committed tip_tree.json and tip_tree_vectors' Prover.toml are what
/// this code computes.
#[test]
fn tree_vector_files_match() {
    let v = tree_vectors();
    let committed: Value = serde_json::from_str(
        &std::fs::read_to_string(repo().join(TREE_VECTORS)).expect(TREE_VECTORS),
    )
    .unwrap();
    assert_eq!(committed, v, "rerun write_tree_vectors");
    assert_eq!(
        std::fs::read_to_string(repo().join(TREE_NOIR).join("Prover.toml")).unwrap(),
        tree_prover_toml(&v),
        "rerun write_tree_vectors"
    );
}

/// `cargo test -p sidecar-core write_tree_vectors -- --ignored`: rewrites
/// testvectors/tip_tree.json and tip_tree_vectors' Prover.toml.
#[test]
#[ignore = "writes testvectors/; run on purpose"]
fn write_tree_vectors() {
    let v = tree_vectors();
    std::fs::write(
        repo().join(TREE_VECTORS),
        serde_json::to_string_pretty(&v).unwrap() + "\n",
    )
    .unwrap();
    std::fs::create_dir_all(repo().join(TREE_NOIR)).unwrap();
    std::fs::write(
        repo().join(TREE_NOIR).join("Prover.toml"),
        tree_prover_toml(&v),
    )
    .unwrap();
}
