//! Tree tests: clear and oblivious tree entries, windows and `$new_leaf`.

use super::*;

/// A parse fixture: an oblivious tree round (`tip_tree_oblivious`, no
/// circuit) under secret-shared receipt intake: the positions INPUT_SHARED,
/// the opening flag and the count PUBLIC, the slots' leaves, old hashes and
/// siblings the three LOAD slices, the stored vector 3 · (3 + 1 + 16)
/// elements.
fn tip_tree_oblivious() -> Value {
    json!({
        "manifest": 1,
        "circuit": "tip_tree_oblivious",
        "namespace_param": "namespace",
        "state_keys": {"reads": 1, "writes": 1},
        "intake": "shared_receipt",
        "binding": "turn",
        "witness": [
            {"param": "namespace", "from": {"PUBLIC": "$namespace"}},
            {"param": "vk_hash", "from": {"PUBLIC": "$vk_hash"}},
            {"param": "in_slots", "from": {"PUBLIC": ["$state_keys.reads[0]"]}},
            {"param": "out_slots", "from": {"PUBLIC": ["$state_keys.writes[0]"]}},
            {"param": "inputs_hash", "from": {"PUBLIC": "$inputs_hash"}},
            {"param": "amount", "from": {"INPUT_SHARED": "amount"}},
            {"param": "p1", "from": {"INPUT_SHARED": "p1"}},
            {"param": "p2", "from": {"INPUT_SHARED": "p2"}},
            {"param": "count", "from": {"PUBLIC": "count"}},
            {"param": "opens", "from": {"PUBLIC": "opens"}},
            {"param": "partial_note", "from": {"INPUT_SHARED": "$partial_note"}},
            {"param": "outcome_key", "from": {"INPUT_SHARED": "$outcome_key"}},
            {"param": "blinding", "from": {"INPUT_SHARED": "$blinding"}},
            {"param": "outcome_tag", "from": {"INPUT_SHARED": "$outcome_tag"}},
            {"param": "leaves", "from": {"LOAD": "$state_keys.reads[0]", "slice": [0, 9], "len": 60}},
            {"param": "old_hashes", "from": {"LOAD": "$state_keys.reads[0]", "slice": [9, 12], "len": 60}},
            {"param": "siblings", "from": {"LOAD": "$state_keys.reads[0]", "slice": [12, 60], "len": 60}},
            {"param": "new_leaf", "from": {"PUBLIC": "$new_leaf"}},
            {"param": "r_new", "from": {"SAMPLE": 3}},
            {"param": "nsk_app", "from": {"LOAD": "nsk_app", "slice": [0, 1], "len": 1}}
        ],
        "outputs": [{"TACEO_store": "out0", "STORE": "$state_keys.writes[0]", "len": 60, "note_hash": "new_c"}],
        "state": {"$state_keys.reads[0]": "node", "$state_keys.writes[0]": "node"},
        "commitment_slot": {"$state_keys.reads[0]": {"old": "old_c"}},
        "tree": {
            "$state_keys.reads[0]": {
                "depth": 16, "leaf_len": 3, "probe": 3, "header": true, "access": "oblivious",
                "index": ["p1", "p2"], "count": "count", "open": "opens",
                "params": {"leaves": "leaves", "old_hashes": "old_hashes", "siblings": "siblings"},
                "store": "$state_keys.writes[0]", "next_index": "next_index"
            }
        }
    })
}

// An oblivious tree entry (docs/ARCHITECTURE.md section 6, "The state-holder
// value"): shared index inputs, a public opening flag, the three LOAD slices,
// no placed indices and no leaf-hash output, the append index output.
#[test]
fn an_oblivious_tree_entry_parses_and_names_its_slices() {
    let m = parse(&tip_tree_oblivious()).unwrap();
    let t = m.tree_of(KeyRef::Read(0)).unwrap();
    assert_eq!(t.access, TreeAccess::Oblivious);
    assert_eq!(t.vector_len(), 60);
    assert_eq!(t.loaded_len(), 60);
    assert_eq!(t.oblivious_slices(), [[0, 9], [9, 12], [12, 60]]);
    assert_eq!(t.shape().access, TreeAccess::Oblivious);
    const R0: &str = "$state_keys.reads[0]";
    type Tamper = Box<dyn Fn(&mut Value) + 'static>;
    let cases: Vec<(Tamper, &str)> = vec![
        (
            Box::new(|v| v["witness"][6]["from"] = json!({"PUBLIC": "p1"})),
            "is not an INPUT_SHARED name",
        ),
        (
            Box::new(|v| v["tree"][R0]["open"] = json!("p1")),
            "the opening flag is a public 0/1 input",
        ),
        (
            Box::new(|v| v["tree"][R0]["params"]["indices"] = json!("count")),
            "no placed indices",
        ),
        (
            Box::new(|v| v["tree"][R0]["new_hashes"] = json!("new_hashes")),
            "outputs no leaf hashes",
        ),
        (
            Box::new(|v| v["witness"][16]["from"]["slice"] = json!([12, 59])),
            "must be filled by LOAD $state_keys.reads[0] slice [12, 60]",
        ),
        (
            Box::new(|v| {
                v["tree"][R0].as_object_mut().unwrap().remove("next_index");
            }),
            "missing: an oblivious tree that opens leaves",
        ),
        (
            Box::new(|v| {
                v["tree"][R0].as_object_mut().unwrap().remove("store");
            }),
            "stores it back",
        ),
        (
            Box::new(|v| v["outputs"][0]["len"] = json!(9)),
            "probe * (leaf_len + 1 + depth) = 60",
        ),
        (
            Box::new(|v| v["tree"][R0]["depth"] = json!(0)),
            "field `tree.$state_keys.reads[0].depth`: a tree is at least 1 deep",
        ),
    ];
    for (tamper, needle) in cases {
        let mut v = tip_tree_oblivious();
        tamper(&mut v);
        refused(v, needle);
    }
    // the clear tree refuses the oblivious-only field
    let mut clear = tip_tree();
    clear["tree"][R0]["next_index"] = json!("next_index");
    refused(clear, "only under `access: oblivious`");
}

fn scan_shared() -> Value {
    serde_json::from_str(include_str!(
        "../../../../../examples/lending-tip/manifests/scan_shared.json"
    ))
    .unwrap()
}

// A tree entry's window (the lending keeper round, scan_shared): read
// after the slots, its two node-filled parameters not app inputs, its
// width a power of two within the network's bound, so a round one leaf
// wider (W + 1) or twice as wide is refused at REGISTER.
#[test]
fn a_window_is_loaded_after_the_slots_within_the_bound() {
    let m = parse(&scan_shared()).unwrap();
    let read = m.tree_of(KeyRef::Read(0)).unwrap();
    let w = read.window.as_ref().unwrap();
    assert_eq!((w.width, w.height(), w.start.as_str()), (8, 3, "start"));
    assert_eq!((read.vector_len(), read.loaded_len()), (8, 72));
    assert_eq!(
        m.tree_params().collect::<Vec<_>>(),
        [
            "old_hashes",
            "siblings",
            "indices",
            "window_hashes",
            "window_siblings"
        ]
    );
    let r0 = "$state_keys.reads[0]";
    let window = |v: &mut Value, field: &str, value: Value| {
        v["tree"][r0]["window"][field] = value;
    };
    // the witness entry filling `param`
    fn entry<'v>(v: &'v mut Value, param: &str) -> &'v mut Value {
        v["witness"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|e| e["param"] == param)
            .unwrap()
    }
    type Mutate<'a> = Box<dyn Fn(&mut Value) + 'a>;
    let cases: Vec<(Mutate, &str)> = vec![
        (
            Box::new(|v| window(v, "width", json!(MAX_TREE_WINDOW + 1))),
            "is not a power of two in 1 ..= 8",
        ),
        (
            Box::new(|v| window(v, "width", json!(2 * MAX_TREE_WINDOW))),
            "is not a power of two in 1 ..= 8",
        ),
        (
            Box::new(|v| window(v, "width", json!(0))),
            "is not a power of two",
        ),
        (
            Box::new(|v| window(v, "start", json!("nope"))),
            "is not a request public name",
        ),
        (
            Box::new(|v| entry(v, "window_leaves")["from"]["slice"] = json!([0, 72])),
            "slice [8, 72] (the window's leaves)",
        ),
        (
            Box::new(|v| {
                entry(v, "leaves")["from"]["len"] = json!(80);
                entry(v, "window_leaves")["from"]["len"] = json!(80);
            }),
            "loads (probe + window width) * leaf_len = 72",
        ),
        (
            Box::new(|v| entry(v, "window_siblings")["from"] = json!({"PUBLIC": "start"})),
            "also used elsewhere",
        ),
        (
            Box::new(|v| entry(v, "window_hashes")["from"] = json!({"PUBLIC": "old_hashes"})),
            "also used elsewhere",
        ),
        (
            Box::new(|v| v["tree"][r0]["window"]["params"]["siblings"] = json!("window_hashes")),
            "is named twice",
        ),
        (
            Box::new(|v| v["tree"][r0]["window"]["extra"] = json!(1)),
            "unknown field",
        ),
    ];
    for (edit, needle) in cases {
        let mut v = scan_shared();
        edit(&mut v);
        refused(v, needle);
    }
}

// The tree field: the layout of a tree-valued key, declared once (the
// stored reference's derived from the loaded entry's `store`), its index
// rules and parameters, and `$new_leaf`.
#[test]
fn a_tree_manifest_names_its_layout_parameters_and_new_leaf() {
    let m = parse(&tip_tree()).unwrap();
    let read = m.tree_of(KeyRef::Read(0)).unwrap();
    assert_eq!(
        (read.depth, read.leaf_len, read.probe, read.vector_len()),
        (16, 3, 3, 9)
    );
    assert_eq!(read.first_position(), 1);
    assert_eq!(read.open.as_deref(), Some("p1"));
    assert!(std::ptr::eq(m.tree_of(KeyRef::Write(0)).unwrap(), read));
    assert_eq!(read.store, Some(KeyRef::Write(0)));
    assert!(read.new_hashes.is_some());
    assert_eq!(m.trees().count(), 1);
    assert_eq!(
        m.tree_params().collect::<Vec<_>>(),
        ["old_hashes", "siblings", "indices"]
    );
    assert_eq!(
        m.reserved().collect::<Vec<_>>(),
        [
            ("vk_hash", ReservedOperand::VkHash),
            ("user_nonce", ReservedOperand::UserNonce),
            ("new_leaf", ReservedOperand::NewLeaf)
        ]
    );
    let init: Value = serde_json::from_str(include_str!(
        "../../../../../machine/circuits/manifests/tip_tree_init.json"
    ))
    .unwrap();
    assert!(parse(&init).unwrap().tree_of(KeyRef::Write(0)).is_some());

    let r0 = "$state_keys.reads[0]";
    let w0 = "$state_keys.writes[0]";
    type Mutate<'a> = Box<dyn Fn(&mut Value) + 'a>;
    let cases: Vec<(Mutate, &str)> = vec![
        (
            Box::new(|v| v["intake"] = json!("direct")),
            "only with a queued intake",
        ),
        (
            Box::new(|v| v["tree"][r0]["probe"] = json!(2)),
            "is not the header plus one slot",
        ),
        (
            Box::new(|v| v["tree"][r0]["depth"] = json!(33)),
            "is not in 1 ..= 32",
        ),
        (
            Box::new(|v| v["tree"][r0]["leaf_len"] = json!(0)),
            "at least 1 element",
        ),
        (
            Box::new(|v| v["tree"][r0]["index"][1] = json!("p9")),
            "not a request public name",
        ),
        (
            Box::new(|v| v["tree"][r0]["index"][1] = json!("p1")),
            "is listed twice",
        ),
        (
            Box::new(|v| v["tree"][r0]["count"] = json!("p2")),
            "other than the index inputs",
        ),
        (
            Box::new(|v| v["tree"][r0]["open"] = json!("count")),
            "is not an index input",
        ),
        (
            Box::new(|v| v["tree"][r0]["params"]["leaves"] = json!("r_new")),
            "must be filled by LOAD",
        ),
        (
            Box::new(|v| v["tree"][r0]["params"]["siblings"] = json!("old_hashes")),
            "is named twice",
        ),
        (
            Box::new(|v| v["tree"][r0]["params"]["indices"] = json!("p2")),
            "is also used elsewhere",
        ),
        (
            Box::new(|v| v["tree"][r0]["params"]["indices"] = json!("in_slots")),
            "one request public name",
        ),
        (
            Box::new(|v| {
                v["tree"][r0]
                    .as_object_mut()
                    .unwrap()
                    .remove("params")
                    .map(drop)
                    .unwrap()
            }),
            "missing: the loaded tree key",
        ),
        (
            Box::new(|v| {
                v["tree"][r0].as_object_mut().unwrap().remove("store");
            }),
            "names both the reference it is stored at",
        ),
        (
            Box::new(|v| {
                v["tree"][r0].as_object_mut().unwrap().remove("new_hashes");
            }),
            "names both the reference it is stored at",
        ),
        (
            Box::new(|v| v["tree"][r0]["store"] = json!("$state_keys.writes[1]")),
            "is not stored by an output",
        ),
        (
            Box::new(|v| v["state"][w0] = json!("chain")),
            "has another state mode",
        ),
        // the stored tree declared a second time under its own reference
        (
            Box::new(|v| {
                let mut stored = v["tree"][r0].clone();
                let stored_map = stored.as_object_mut().unwrap();
                stored_map.remove("params");
                stored_map.remove("store");
                v["tree"][w0] = stored;
            }),
            "declared twice",
        ),
        // a stored entry beside a loaded tree that is not stored back:
        // the round would load one tree and create another
        (
            Box::new(|v| {
                let mut stored = v["tree"][r0].clone();
                let stored_map = stored.as_object_mut().unwrap();
                stored_map.remove("params");
                stored_map.remove("store");
                v["tree"][w0] = stored;
                let loaded = v["tree"][r0].as_object_mut().unwrap();
                loaded.remove("store");
                loaded.remove("new_hashes");
            }),
            "stores each tree it loads (`store`) and creates none",
        ),
        (
            Box::new(|v| v["outputs"][0]["len"] = json!(4)),
            "stores probe * leaf_len = 9",
        ),
        (
            Box::new(|v| {
                v["tree"][r0].as_object_mut().unwrap().remove("open");
            }),
            "`$new_leaf` is used, and no tree opens",
        ),
        (
            Box::new(|v| v["state"][r0] = json!("chain")),
            "a tree-valued key is node-held",
        ),
        (
            Box::new(|v| {
                let mut second = v["tree"][r0].clone();
                let fields = second.as_object_mut().unwrap();
                fields.remove("store");
                fields.remove("new_hashes");
                v["tree"]["$state_keys.reads[1]"] = second;
            }),
            "out of range",
        ),
    ];
    for (mutate, needle) in cases {
        let mut v = tip_tree();
        mutate(&mut v);
        refused(v, needle);
    }
    // the open input without $new_leaf
    let mut v = tip_tree();
    v["witness"][13]["from"] = json!({"PUBLIC": "new_leaf"});
    refused(v, "no parameter takes `$new_leaf`");
}

// A tree that opens leaves keeps its append index in the header leaf, so
// `open` without `header` is refused under either access.
#[test]
fn a_tree_that_opens_leaves_has_a_header() {
    const R0: &str = "$state_keys.reads[0]";
    for mut v in [tip_tree(), tip_tree_oblivious()] {
        v["tree"][R0]["header"] = json!(false);
        v["tree"][R0]["probe"] = json!(2);
        refused(v, "a tree that opens leaves has a header");
    }
}
