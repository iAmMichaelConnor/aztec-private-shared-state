//! Tree-valued keys: the `tree` entry's layout, shape, parameters and window,
//! and the checks of the `tree` field.

use super::validate::{bad, in_range};
use super::*;

/// The checks of `tree` (queued intakes only; the other path's refusal
/// runs first): each entry names a node-held key the round loads or stores,
/// a depth of at least 1 (at most [`MAX_TREE_DEPTH`] for a clear tree; an
/// oblivious tree's shape is its holder's to check at REGISTER, sidecar-oblivious's
/// `check_shape`), a leaf of 1 to [`MAX_TREE_LEAF_LEN`] elements, a probe of
/// the header plus one slot per `index` input, at most [`MAX_TREE_PROBE`], index,
/// count and open inputs among the request public names, `open` only
/// with a header (the header leaf keeps the append index); `params` exactly under a loaded key (each a distinct
/// parameter: `leaves` filled by the LOAD of the key over its whole
/// length, the other three by PUBLIC with a request public name used
/// nowhere else); `store` only under a loaded key, naming a node-held key
/// the round stores that no other entry declares or stores at; `new_hashes`
/// exactly where the tree is stored (with `store`, or under a stored key);
/// every LOAD and output of a tree key has the length `probe * leaf_len`; a
/// round that loads and stores trees stores each tree it loads and creates
/// none; and `$new_leaf` is used exactly when a tree has an `open` input.
/// A `window` has a power-of-two width within [`MAX_TREE_WINDOW`] and 2^depth
/// and its own checks (`validate_window`); its leaves lengthen every LOAD of
/// the key to `(probe + width) * leaf_len`.
/// The widths against the ABI are REGISTER's
/// ([`crate::abi::check_manifest`]).
pub(super) fn validate_trees(
    m: &Manifest,
    used: &BTreeSet<KeyRef>,
    loaded: &BTreeSet<KeyRef>,
    names: &BTreeSet<&str>,
    reserved: &BTreeSet<ReservedOperand>,
) -> Result<(), Refusal> {
    let mut filled: BTreeSet<&str> = BTreeSet::new();
    let mut opens = false;
    for (key, tree) in m.trees() {
        let at = format!("tree.{key}");
        if key.is_fixed() {
            return bad(at, format!("the fixed key {key} is not a tree"));
        }
        in_range(m.state_keys, *key).or_else(|e| bad(at.clone(), e))?;
        if !used.contains(key) {
            return bad(at, format!("{key} is neither loaded nor stored"));
        }
        if m.state_mode(*key) != Some(StateMode::Node) {
            return bad(
                at,
                format!("a tree-valued key is node-held; {key} has another state mode"),
            );
        }
        if tree.keyed {
            validate_keyed(tree, &at)?;
        }
        if tree.depth == 0 {
            return bad(format!("{at}.depth"), "a tree is at least 1 deep".into());
        }
        if tree.access == TreeAccess::Clear && tree.depth > MAX_TREE_DEPTH {
            return bad(
                format!("{at}.depth"),
                format!("{} is not in 1 ..= {MAX_TREE_DEPTH}", tree.depth),
            );
        }
        if tree.leaf_len == 0 {
            return bad(
                format!("{at}.leaf_len"),
                "a leaf has at least 1 element".into(),
            );
        }
        if tree.leaf_len > MAX_TREE_LEAF_LEN {
            return bad(
                format!("{at}.leaf_len"),
                format!(
                    "{} is over {MAX_TREE_LEAF_LEN} (a leaf's elements)",
                    tree.leaf_len
                ),
            );
        }
        if tree.probe > MAX_TREE_PROBE {
            return bad(
                format!("{at}.probe"),
                format!(
                    "{} is over {MAX_TREE_PROBE} (the leaves a round touches)",
                    tree.probe
                ),
            );
        }
        if !tree.keyed && tree.capacity.is_some() {
            return bad(
                format!("{at}.capacity"),
                "only a keyed map has a capacity (a dense tree's DORAM holds every address)".into(),
            );
        }
        if let Some(window) = &tree.window {
            let w = window.width;
            if !w.is_power_of_two() || w > MAX_TREE_WINDOW || window.height() > tree.depth {
                return bad(
                    format!("{at}.window.width"),
                    format!(
                        "{w} is not a power of two in 1 ..= {MAX_TREE_WINDOW} (the network's \
                         bound) within 2^depth"
                    ),
                );
            }
        }
        let slots = tree.first_position() + tree.index.len();
        // a keyed map a round creates has no key input: its one slot is the
        // unused path 0, which the creating round leaves empty
        let created_map = tree.keyed && !loaded.contains(key) && tree.index.is_empty();
        if created_map && tree.probe != 1 {
            return bad(
                format!("{at}.probe"),
                format!(
                    "{} is not 1: a keyed map is created with one unused slot",
                    tree.probe
                ),
            );
        }
        if !created_map && (tree.probe != slots || slots == 0) {
            return bad(
                format!("{at}.probe"),
                format!(
                    "{} is not the header plus one slot per index input ({slots}, at least 1)",
                    tree.probe
                ),
            );
        }
        let shared: BTreeSet<&str> = m
            .witness
            .iter()
            .filter_map(|w| match &w.from {
                Source::InputShared(name) => Some(name.as_str()),
                _ => None,
            })
            .collect();
        let oblivious = tree.access == TreeAccess::Oblivious;
        let mut inputs = BTreeSet::new();
        for (k, name) in tree.index.iter().enumerate() {
            if !oblivious && !names.contains(name.as_str()) {
                return bad(
                    format!("{at}.index[{k}]"),
                    format!("`{name}` is not a request public name of the witness"),
                );
            }
            if oblivious && !shared.contains(name.as_str()) {
                return bad(
                    format!("{at}.index[{k}]"),
                    format!(
                        "`{name}` is not an INPUT_SHARED name: under `access: oblivious` every \
                         index input is shared (a clear index would show the nodes the leaf)"
                    ),
                );
            }
            if !inputs.insert(name.as_str()) {
                return bad(
                    format!("{at}.index[{k}]"),
                    format!("`{name}` is listed twice"),
                );
            }
        }
        if let Some(count) = &tree.count
            && (!names.contains(count.as_str()) || inputs.contains(count.as_str()))
        {
            {
                return bad(
                    format!("{at}.count"),
                    format!("`{count}` is not a request public name other than the index inputs"),
                );
            }
        }
        if let Some(open) = &tree.open {
            if !tree.header {
                return bad(
                    format!("{at}.open"),
                    "a tree that opens leaves has a header (`header: true`): the header leaf \
                     keeps the append index that a new leaf's position is checked against"
                        .into(),
                );
            }
            if !oblivious && !inputs.contains(open.as_str()) {
                return bad(
                    format!("{at}.open"),
                    format!("`{open}` is not an index input"),
                );
            }
            if oblivious
                && (!names.contains(open.as_str())
                    || inputs.contains(open.as_str())
                    || tree.count.as_deref() == Some(open.as_str()))
            {
                return bad(
                    format!("{at}.open"),
                    format!(
                        "`{open}` is not a request public name other than the index and count \
                         inputs: under `access: oblivious` the opening flag is a public 0/1 input"
                    ),
                );
            }
            opens = true;
        }
        if oblivious && tree.open.is_some() != tree.next_index.is_some() {
            return bad(
                format!("{at}.next_index"),
                if tree.next_index.is_some() {
                    "names the append index output, and the tree opens no leaves (`open`)".into()
                } else {
                    "missing: an oblivious tree that opens leaves names the public output of the header's append index after the round".into()
                },
            );
        }
        if !oblivious && tree.next_index.is_some() {
            return bad(
                format!("{at}.next_index"),
                "only under `access: oblivious` (the clear tree's nodes read the append index from the written hashes)".into(),
            );
        }
        let len = tree.vector_len();
        let loaded_len = tree.loaded_len();
        for (k, w) in m.witness.iter().enumerate() {
            if let Source::Load(load) = &w.from
                && load.key == *key
                && load.len != loaded_len
            {
                return bad(
                    format!("witness[{k}].from.len"),
                    format!(
                        "the tree key {key} loads (probe + window width) * leaf_len = \
                         {loaded_len} elements"
                    ),
                );
            }
        }
        if let Some(store) = tree.store {
            let at = format!("{at}.store");
            if !loaded.contains(key) {
                return bad(
                    at,
                    format!("only under the key reference that loads the tree, not {key}"),
                );
            }
            if !m.outputs.iter().any(|o| o.store == store) {
                return bad(at, format!("{store} is not stored by an output"));
            }
            if m.state_mode(store) != Some(StateMode::Node) {
                return bad(
                    at,
                    format!("a tree-valued key is node-held; {store} has another state mode"),
                );
            }
            if m.trees()
                .any(|(k, t)| *k == store || (k != key && t.store == Some(store)))
            {
                return bad(
                    at,
                    format!("the tree stored at {store} is declared twice; declare it once"),
                );
            }
        }
        for stored in [Some(*key), tree.store].into_iter().flatten() {
            if let Some((k, out)) = m
                .outputs
                .iter()
                .enumerate()
                .find(|(_, o)| o.store == stored)
                && out.len != len
            {
                return bad(
                    format!("outputs[{k}].len"),
                    format!(
                        "the tree key {stored} stores {} = {len} elements",
                        match tree.access {
                            TreeAccess::Clear => "probe * leaf_len",
                            TreeAccess::Oblivious => "probe * (leaf_len + 1 + depth)",
                        }
                    ),
                );
            }
        }
        if oblivious {
            validate_oblivious(m, key, tree, loaded, &mut filled)?;
        } else {
            validate_clear(m, key, tree, loaded, &inputs, &mut filled)?;
        }
        if let Some(window) = &tree.window {
            validate_window(m, key, tree, window, loaded, names, &mut filled)?;
        }
    }
    let loads = m.trees().filter(|(key, _)| loaded.contains(key)).count();
    let creates = m.trees().count() - loads;
    let stores_back = m.trees().filter(|(_, t)| t.store.is_some()).count();
    if loads > 0 && (creates > 0 || (stores_back > 0 && stores_back != loads)) {
        return bad(
            "tree".into(),
            format!(
                "the round loads {loads} tree key(s), stores {stores_back} of them back and \
                 creates {creates}; a round that loads and stores tree-valued keys stores each \
                 tree it loads (`store`) and creates none"
            ),
        );
    }
    if opens != reserved.contains(&ReservedOperand::NewLeaf) {
        return bad(
            "tree".into(),
            if opens {
                "a tree opens leaves (`open`), and no parameter takes `$new_leaf`".into()
            } else {
                "`$new_leaf` is used, and no tree opens leaves (`open`)".into()
            },
        );
    }
    Ok(())
}

/// The checks of a `keyed: true` tree entry's structure
/// (docs/ARCHITECTURE.md section 6, "The keyed map's manifest entry and
/// REGISTER"): `access: oblivious`, no header, `open`, `next_index` or
/// `window`. Its depth, leaf length and capacity are the oblivious holder's to
/// check at REGISTER, with the DORAM's own bounds (sidecar-oblivious's
/// `check_shape`).
fn validate_keyed(tree: &TreeLayout, at: &str) -> Result<(), Refusal> {
    if tree.access != TreeAccess::Oblivious {
        return bad(
            format!("{at}.keyed"),
            "a keyed map is `access: oblivious` (a keyed clear tree would show the nodes the keys)"
                .into(),
        );
    }
    if tree.header {
        return bad(
            format!("{at}.header"),
            "a keyed map has no header (a pool-level entry is a leaf at a key of the app's)".into(),
        );
    }
    if tree.open.is_some() {
        return bad(
            format!("{at}.open"),
            "a keyed map opens nothing: the first write to a key inserts it".into(),
        );
    }
    if tree.next_index.is_some() {
        return bad(
            format!("{at}.next_index"),
            "a keyed map has no append index".into(),
        );
    }
    if tree.window.is_some() {
        return bad(
            format!("{at}.window"),
            "a keyed map has no windows: its leaves have no order anyone can scan".into(),
        );
    }
    Ok(())
}

/// The checks of an `access: oblivious` tree entry's parameters
/// (docs/ARCHITECTURE.md section 6, "The state-holder value"): a loaded tree is
/// stored back and names no `new_hashes`; `leaves`, `old_hashes` and `siblings`
/// are the three LOAD slices of the key's loaded vector, in that order; no
/// `indices` (the circuit takes the index inputs); a created tree names nothing
/// but its layout.
fn validate_oblivious<'m>(
    m: &'m Manifest,
    key: &KeyRef,
    tree: &'m TreeLayout,
    loaded: &BTreeSet<KeyRef>,
    filled: &mut BTreeSet<&'m str>,
) -> Result<(), Refusal> {
    let at = format!("tree.{key}");
    if tree.new_hashes.is_some() {
        return bad(
            format!("{at}.new_hashes"),
            "an oblivious tree outputs no leaf hashes (they would show which leaves changed); \
             the nodes take the new path from the round's stored vector"
                .into(),
        );
    }
    if !loaded.contains(key) {
        if tree.params.is_some() {
            return bad(
                format!("{at}.params"),
                format!("only under the key reference that loads the tree, not {key}"),
            );
        }
        return Ok(());
    }
    let Some(params) = &tree.params else {
        return bad(
            format!("{at}.params"),
            format!("missing: the loaded tree key {key} names its parameters"),
        );
    };
    if tree.store.is_none() {
        return bad(
            format!("{at}.store"),
            "missing: a round on an oblivious tree stores it back (every slot is written, new \
             value or old)"
                .into(),
        );
    }
    if let Some(indices) = &params.indices {
        return bad(
            format!("{at}.params.indices"),
            format!(
                "`{indices}`: under `access: oblivious` the circuit takes the index inputs; no placed indices"
            ),
        );
    }
    let slices = tree.oblivious_slices();
    for ((field, name), slice) in [
        ("leaves", &params.leaves),
        ("old_hashes", &params.old_hashes),
        ("siblings", &params.siblings),
    ]
    .into_iter()
    .zip(slices)
    {
        let at = format!("{at}.params.{field}");
        let Some((_, entry)) = m.witness_entry(name) else {
            return bad(at, format!("`{name}` is not a witness parameter"));
        };
        if !filled.insert(entry.param.as_str()) {
            return bad(at, format!("`{name}` is named twice"));
        }
        if !matches!(&entry.from, Source::Load(l) if l.key == *key && l.slice == slice) {
            return bad(
                at,
                format!(
                    "`{name}` must be filled by LOAD {key} slice [{}, {}] (the nodes read the \
                     slots' {field} in the session)",
                    slice[0], slice[1]
                ),
            );
        }
    }
    Ok(())
}

/// The checks of an `access: clear` tree entry's parameters and outputs.
fn validate_clear<'m>(
    m: &'m Manifest,
    key: &KeyRef,
    tree: &'m TreeLayout,
    loaded: &BTreeSet<KeyRef>,
    inputs: &BTreeSet<&str>,
    filled: &mut BTreeSet<&'m str>,
) -> Result<(), Refusal> {
    let at = format!("tree.{key}");
    let len = tree.vector_len();
    {
        match (loaded.contains(key), &tree.params, &tree.new_hashes) {
            (true, Some(params), new_hashes) => {
                if tree.store.is_some() != new_hashes.is_some() {
                    let missing = if new_hashes.is_some() {
                        "store"
                    } else {
                        "new_hashes"
                    };
                    return bad(
                        format!("{at}.{missing}"),
                        format!(
                            "a loaded tree the round stores back names both the reference it \
                             is stored at (`store`) and the output of its new leaf hashes \
                             (`new_hashes`); {key} names one"
                        ),
                    );
                }
                let mut param = |field: &str, name: &str| -> Result<&WitnessEntry, Refusal> {
                    let at = format!("{at}.params.{field}");
                    let Some((_, entry)) = m.witness_entry(name) else {
                        return bad(at, format!("`{name}` is not a witness parameter"));
                    };
                    if !filled.insert(entry.param.as_str()) {
                        return bad(at, format!("`{name}` is named twice"));
                    }
                    Ok(entry)
                };
                let leaves = param("leaves", &params.leaves)?;
                if !matches!(&leaves.from, Source::Load(l) if l.key == *key && l.slice == [0, len])
                {
                    return bad(
                        format!("{at}.params.leaves"),
                        format!(
                            "`{}` must be filled by LOAD {key} slice [0, {len}] (the touched leaves)",
                            params.leaves
                        ),
                    );
                }
                let Some(indices) = &params.indices else {
                    return bad(
                        format!("{at}.params.indices"),
                        "missing: the nodes place the effective indices under `access: clear`"
                            .into(),
                    );
                };
                for (field, name) in [
                    ("old_hashes", &params.old_hashes),
                    ("siblings", &params.siblings),
                    ("indices", indices),
                ] {
                    let entry = param(field, name)?;
                    let Source::Public(PublicSource::One(PublicOperand::Name(public))) =
                        &entry.from
                    else {
                        return bad(
                            format!("{at}.params.{field}"),
                            format!(
                                "`{name}` must be filled by PUBLIC with one request public name, \
                                 which the scheduler fills from the nodes' trees"
                            ),
                        );
                    };
                    let shared = m.witness.iter().filter(|w| w.param != *name).any(|w| {
                        matches!(&w.from, Source::Public(p)
                            if p.operands().iter().any(|op| matches!(op, PublicOperand::Name(n) if n == public)))
                    });
                    if shared
                        || inputs.contains(public.as_str())
                        || tree.count.as_ref() == Some(public)
                    {
                        return bad(
                            format!("{at}.params.{field}"),
                            format!("the request public name `{public}` is also used elsewhere"),
                        );
                    }
                }
            }
            (true, None, _) => {
                return bad(
                    format!("{at}.params"),
                    format!("missing: the loaded tree key {key} names its parameters"),
                );
            }
            (false, None, Some(new_hashes)) if !new_hashes.is_empty() => {}
            (false, Some(_), _) => {
                return bad(
                    format!("{at}.params"),
                    format!("only under the key reference that loads the tree, not {key}"),
                );
            }
            (false, None, _) => {
                return bad(
                    format!("{at}.new_hashes"),
                    format!(
                        "missing: the stored tree key {key} names the output of its new leaf hashes"
                    ),
                );
            }
        }
    }
    Ok(())
}

/// The checks of a tree entry's `window` (its width is checked first, in
/// `validate_trees`): under a key the round loads; a `start` input among the request public names other than the
/// index and count inputs; `leaves` filled by the LOAD of the key after the
/// slots, the other two by PUBLIC with a request public name used nowhere
/// else.
fn validate_window<'m>(
    m: &'m Manifest,
    key: &KeyRef,
    tree: &TreeLayout,
    window: &'m TreeWindow,
    loaded: &BTreeSet<KeyRef>,
    names: &BTreeSet<&str>,
    filled: &mut BTreeSet<&'m str>,
) -> Result<(), Refusal> {
    let at = format!("tree.{key}.window");
    if !loaded.contains(key) || tree.params.is_none() {
        return bad(
            at,
            format!("only under the key reference that loads the tree, not {key}"),
        );
    }
    let start = window.start.as_str();
    if !names.contains(start)
        || tree.index.iter().any(|n| n == start)
        || tree.count.as_deref() == Some(start)
    {
        return bad(
            format!("{at}.start"),
            format!("`{start}` is not a request public name other than the index inputs"),
        );
    }
    let mut param = |field: &str, name: &'m str| -> Result<&'m WitnessEntry, Refusal> {
        let at = format!("{at}.params.{field}");
        let Some((_, entry)) = m.witness_entry(name) else {
            return bad(at, format!("`{name}` is not a witness parameter"));
        };
        if !filled.insert(entry.param.as_str()) {
            return bad(at, format!("`{name}` is named twice"));
        }
        Ok(entry)
    };
    if let Some(slices) = tree.oblivious_window_slices() {
        for ((field, name), slice) in [
            ("leaves", &window.params.leaves),
            ("old_hashes", &window.params.old_hashes),
            ("siblings", &window.params.siblings),
        ]
        .into_iter()
        .zip(slices)
        {
            let entry = param(field, name)?;
            if !matches!(&entry.from, Source::Load(l) if l.key == *key && l.slice == slice) {
                return bad(
                    format!("{at}.params.{field}"),
                    format!(
                        "`{name}` must be filled by LOAD {key} slice [{}, {}] (the window's \
                         {field}, read in the session)",
                        slice[0], slice[1]
                    ),
                );
            }
        }
        return Ok(());
    }
    let (from, to) = (tree.vector_len(), tree.loaded_len());
    let leaves = param("leaves", &window.params.leaves)?;
    if !matches!(&leaves.from, Source::Load(l) if l.key == *key && l.slice == [from, to]) {
        return bad(
            format!("{at}.params.leaves"),
            format!(
                "`{}` must be filled by LOAD {key} slice [{from}, {to}] (the window's leaves)",
                window.params.leaves
            ),
        );
    }
    for (field, name) in [
        ("old_hashes", &window.params.old_hashes),
        ("siblings", &window.params.siblings),
    ] {
        let entry = param(field, name)?;
        let Source::Public(PublicSource::One(PublicOperand::Name(public))) = &entry.from else {
            return bad(
                format!("{at}.params.{field}"),
                format!(
                    "`{name}` must be filled by PUBLIC with one request public name, which the \
                     scheduler fills from the nodes' trees"
                ),
            );
        };
        let shared = m.witness.iter().filter(|w| w.param != *name).any(|w| {
            matches!(&w.from, Source::Public(p)
                if p.operands().iter().any(|op| matches!(op, PublicOperand::Name(n) if n == public)))
        });
        if shared || public == start {
            return bad(
                format!("{at}.params.{field}"),
                format!("the request public name `{public}` is also used elsewhere"),
            );
        }
    }
    Ok(())
}

/// The deepest clear tree a key may have: indices are below 2^32.
pub const MAX_TREE_DEPTH: u32 = 32;

/// The longest leaf and the widest probe of any tree: a tree's vectors are
/// ABI parameters, which REGISTER bounds by [`crate::abi::MAX_ABI_FIELDS`],
/// and bounding each factor first keeps every length the checks compute
/// (`probe * (leaf_len + 1 + depth)`, the window's) far inside `usize`. An
/// oblivious tree's own, smaller bounds are its holder's.
pub const MAX_TREE_LEAF_LEN: usize = crate::abi::MAX_ABI_FIELDS as usize;
pub const MAX_TREE_PROBE: usize = crate::abi::MAX_ABI_FIELDS as usize;

// DEV DECISION: a tree-valued key's layout (depth D, leaf length, probe
// width K), the app's choice per key, no default (a manifest without `tree`
// has only flat keys); a larger D costs D more shared permutations per slot,
// a larger K a wider circuit. Design guide: "state shape", parameter "depth
// D, leaf_len, probe width K".
// The depth D bounds the leaves at 2^D (positions 1 .. 2^D - 1 under a header);
// a new leaf takes the append index and a closed one is never reclaimed, so
// 2^D - 1 bounds the positions opened over the key's lifetime. The probe
// width K (the header plus one slot per index input) sets what a round
// costs: K·D Poseidon2 permutations over shared values, sequential in depth,
// whose communication rounds set witness-extension time under network
// latency; a round naming fewer positions carries a count and skips the rest.
// The index inputs are clear to the nodes, which see which leaves a request
// touches.
/// `tree.<keyref>`: the layout of a tree-valued node-held key
/// (docs/ARCHITECTURE.md section 6, "Tree-valued keys"), declared once per
/// tree: under the reference that loads it, or under the one that stores it
/// when the round creates it. The round touches `probe` leaves in slot
/// order: leaf 0 in slot 0 when `header`, then one slot per `index` input.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TreeLayout {
    /// The tree's depth D: leaves 0 .. 2^D - 1; at most [`MAX_TREE_DEPTH`]
    /// for a clear tree (an oblivious tree's bound is its holder's).
    pub depth: u32,
    /// The elements of one leaf, its blinding included.
    pub leaf_len: usize,
    /// The most leaves a round touches, the header included: `header` plus
    /// one per `index` input.
    pub probe: usize,
    /// Leaf 0 is a fixed touch in slot 0 (default false).
    #[serde(default)]
    pub header: bool,
    /// The app inputs (request public names) that name position indices, in
    /// slot order.
    #[serde(default)]
    pub index: Vec<String>,
    /// The app input that says how many `index` inputs the round uses; all
    /// of them when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub count: Option<String>,
    /// The `index` input whose value 0 opens a new leaf at `$new_leaf`; only
    /// with `header` (the header leaf keeps the append index).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub open: Option<String>,
    /// Under a key reference the round loads: the parameters the binder
    /// fills with the touched leaves, their old hashes, their siblings and
    /// the effective indices.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<TreeParams>,
    /// Under a key reference the round loads, when it stores the tree back:
    /// the `$state_keys.writes[j]` reference it stores it at, whose layout is this
    /// entry's ([`Manifest::tree_of`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub store: Option<KeyRef>,
    /// Wherever the round stores the tree: the public output that carries
    /// the new leaf hashes, one per slot.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_hashes: Option<String>,
    /// Under a key reference the round loads: a window of consecutive leaves
    /// the round reads after its slots and never writes (a scan round).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub window: Option<TreeWindow>,
    /// How the nodes reach the touched leaves: `clear` (the default: the
    /// nodes see the indices and keep the tree of hashes in the clear) or
    /// `oblivious` (the index inputs are shared, the leaves and hashes live
    /// in a distributed oblivious RAM and the paths reach the circuit as
    /// shared witnesses: docs/ARCHITECTURE.md section 6, "The oblivious tree").
    /// Every round on a key gives it one access, as one depth.
    #[serde(default)]
    pub access: TreeAccess,
    /// Under `access: oblivious`, when the tree opens leaves (`open`): the
    /// public output that carries the header's append index after the round,
    /// from which the nodes keep their append index.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_index: Option<String>,
    /// Under `access: oblivious`: the tree is a sparse keyed map
    /// (docs/ARCHITECTURE.md section 6, "The oblivious sparse map"): each
    /// `index` input is a key whose low `depth` bits are its leaf's path, the
    /// leaf's first element is the key, and an empty leaf at the key's path
    /// proves its absence. No header, `open`, `next_index` or `window`; its
    /// depth, leaf length and capacity are checked by the oblivious holder at
    /// REGISTER.
    #[serde(default)]
    pub keyed: bool,
    /// Under `keyed`: log2 of the distinct DORAM addresses the map may ever
    /// hold (default 18; the bounds are the oblivious holder's).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capacity: Option<usize>,
}

/// How a tree-valued key's nodes reach its leaves ([`TreeLayout::access`]).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TreeAccess {
    /// The nodes see the indices and keep the tree of hashes in the clear.
    #[default]
    Clear,
    /// The index inputs are shared; the leaves and hashes live in a
    /// distributed oblivious RAM the three nodes hold.
    Oblivious,
}

impl TreeAccess {
    pub fn as_str(self) -> &'static str {
        match self {
            TreeAccess::Clear => "clear",
            TreeAccess::Oblivious => "oblivious",
        }
    }
}

impl TreeLayout {
    /// The length of the vector a round stores for the key: every slot's
    /// leaf; under `access: oblivious` every slot's leaf, new leaf hash and
    /// `depth` new path nodes, block after block.
    pub fn vector_len(&self) -> usize {
        match self.access {
            TreeAccess::Clear => self.probe * self.leaf_len,
            TreeAccess::Oblivious => self.probe * (self.leaf_len + 1 + self.depth as usize),
        }
    }

    /// The length of the vector a round loads for the key: every slot's
    /// leaf, then every window leaf; under `access: oblivious` the slots'
    /// leaves, old hashes and siblings, then the window's leaves, old hashes
    /// and root siblings.
    pub fn loaded_len(&self) -> usize {
        let width = self.window.as_ref().map_or(0, |w| w.width);
        match self.access {
            TreeAccess::Clear => (self.probe + width) * self.leaf_len,
            TreeAccess::Oblivious => {
                let window = self.window.as_ref().map_or(0, |w| {
                    w.width * (self.leaf_len + 1) + (self.depth - w.height()) as usize
                });
                self.vector_len() + window
            }
        }
    }

    /// Under `access: oblivious`: the slices of the loaded vector that the
    /// slots' leaves, old hashes and siblings fill, in that order.
    pub fn oblivious_slices(&self) -> [[usize; 2]; 3] {
        let leaves = self.probe * self.leaf_len;
        let hashes = leaves + self.probe;
        [
            [0, leaves],
            [leaves, hashes],
            [hashes, hashes + self.probe * self.depth as usize],
        ]
    }

    /// Under `access: oblivious` with a window: the slices of the loaded
    /// vector that the window's leaves, old hashes and root siblings fill.
    pub fn oblivious_window_slices(&self) -> Option<[[usize; 2]; 3]> {
        if self.access != TreeAccess::Oblivious {
            return None;
        }
        let w = self.window.as_ref()?;
        let from = self.vector_len();
        let leaves = from + w.width * self.leaf_len;
        let hashes = leaves + w.width;
        Some([
            [from, leaves],
            [leaves, hashes],
            [hashes, hashes + (self.depth - w.height()) as usize],
        ])
    }

    /// The first slot an `index` input fills (1 with a header, else 0).
    pub fn first_position(&self) -> usize {
        usize::from(self.header)
    }

    /// The stored tree's shape: what every round on the key reads alike.
    pub fn shape(&self) -> TreeShape {
        TreeShape {
            depth: self.depth,
            leaf_len: self.leaf_len,
            header: self.header,
            access: self.access,
            keyed: self.keyed,
            capacity: self.capacity,
        }
    }
}

/// A tree-valued key's stored tree: its depth, its leaf length, whether
/// leaf 0 is a header, its access and whether it is a keyed map (with its
/// capacity). The rest of a `tree` entry (`probe`, `index`, `count`,
/// `open`, `params`, `store`, `new_hashes`) says which leaves one round touches and
/// where its values go, which each round chooses for itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TreeShape {
    pub depth: u32,
    pub leaf_len: usize,
    pub header: bool,
    pub access: TreeAccess,
    pub keyed: bool,
    pub capacity: Option<usize>,
}

/// How a manifest holds a key ([`Manifest::key_layout`]): its state mode
/// and, for a tree-valued key, its tree's shape (`None` for a flat key).
/// Every queued package of a namespace that loads or stores one request key
/// must give it one layout, since each reads the state the others leave.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyLayout {
    pub mode: StateMode,
    pub tree: Option<TreeShape>,
}

impl fmt::Display for KeyLayout {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "`{}`", self.mode.as_str())?;
        match self.tree {
            None => write!(f, " flat"),
            Some(t) => write!(
                f,
                " tree of depth {}, leaf_len {}, {}",
                t.depth,
                t.leaf_len,
                if t.header {
                    "with a header"
                } else {
                    "no header"
                }
            ),
        }
    }
}

/// `tree.<keyref>.params`: the ABI parameters of a loaded tree key. The
/// binder fills `leaves` by the LOAD of the key (the touched leaves, slot
/// after slot, `[[Field; leaf_len]; probe]`), and `old_hashes` (`[Field;
/// probe]`), `siblings` (`[[Field; depth]; probe]`, bottom up) and
/// `indices` (`[Field; probe]`, 0 in an unused slot) by PUBLIC request
/// names that the scheduler fills from the nodes' clear trees.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TreeParams {
    pub leaves: String,
    pub old_hashes: String,
    pub siblings: String,
    /// The effective indices the nodes place (`access: clear`; absent under
    /// `access: oblivious`, where the circuit takes the index inputs).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub indices: Option<String>,
}

/// The widest window a round may read: REGISTER refuses a wider one.
// Every round must fit a 2^14 circuit, and a window is paid per leaf (a leaf
// hash and the app's per-leaf work over the shared leaf, plus the window's
// subtree), so the network bounds its width rather than any app: 8, so no
// app registers a window round past the circuit size every round keeps (a
// gate budget of a window round's own would break that rule). A wider window
// reads more leaves per round (fewer rounds per pass) and costs gates. The
// measured example is the lending keeper's scan: 15,795 gates at width 8,
// depth 16 and eight-element leaves, and past 2^14 at width 16
// (examples/lending-tip/README.md, "Keeper round"). docs/ARCHITECTURE.md
// section 6, "A read-only window on a tree key".
pub const MAX_TREE_WINDOW: usize = 8;

/// `tree.<keyref>.window`: a window of `width` consecutive leaves a round
/// reads (docs/ARCHITECTURE.md section 6, "A read-only window on a tree
/// key"), from the leaf the app input `start` names: `start` when it is
/// below 2^D and a multiple of `width`, else leaf 0 (the round flags it).
/// The window is loaded after the slots and never written.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TreeWindow {
    /// The leaves the window holds: a power of two, at most
    /// [`MAX_TREE_WINDOW`] and at most 2^D.
    pub width: usize,
    /// The app input (a request public name) that names the first leaf.
    pub start: String,
    pub params: WindowParams,
}

/// `tree.<keyref>.window.params`: the binder fills `leaves` by the LOAD of
/// the key after the slots (`[[Field; leaf_len]; width]`), and `old_hashes`
/// (`[Field; width]`) and `siblings` (the window root's `depth - log2
/// width` siblings, bottom up) by PUBLIC request names that the scheduler
/// fills from the nodes' clear trees.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowParams {
    pub leaves: String,
    pub old_hashes: String,
    pub siblings: String,
}

impl TreeWindow {
    /// log2 of the width: the window's subtree height.
    pub fn height(&self) -> u32 {
        self.width.trailing_zeros()
    }
}
