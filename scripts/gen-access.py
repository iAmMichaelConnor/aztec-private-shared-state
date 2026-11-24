#!/usr/bin/env python3
"""Derive a tree round's oblivious-access twin from its clear one.

Run as `python3 -I scripts/gen-access.py ...` (stdlib only):

  gen-access.py <example> <round> [--dry-run]
  gen-access.py --check [<example>]

A round over a Merkle tree under the clear access (the nodes place the
indices and see which leaves a round touches) and the same round under
`access: oblivious` (docs/ARCHITECTURE.md section 6, "The oblivious tree": the index inputs shared,
the slots read from the nodes' oblivious RAM, zero leaf hashes out) are one
round of the app library over two entries; their mains and manifests differ
by fixed rules, so the oblivious ones are derived here and never written by
hand. <round> is the clear round's package name: a round under secret-shared
receipt intake, `<base>_shared` (twin `<base>_oblivious`), or an init that
creates the tree, `<name>` (twin `<name>_oblivious`).

The twin of a clear round is three files, each derived from the clear
round's own (never from the file it derives):

- `manifests/<twin>.json`: `circuit` the twin; the tree's index inputs
  INPUT_SHARED; an opening round (its tree names `open`) takes the public
  flag `opens` after the opened input, which becomes the tree's `open`, and
  outputs the book's append index as `next_index` (the app value after the
  round's exit tag); the slots' leaves, hashes and paths are LOAD slices of
  the oblivious form (per slot the leaf, its hash and its DEPTH path nodes,
  then a window's leaves, hashes and the nodes above it), the placed indices
  gone; the STORE is the slots' oblivious form; the tree entry says `access:
  oblivious` and outputs no `new_hashes`.
- `circuits/<twin>/src/main.nr`: the clear main under a generated header,
  the app library entry `Clear { indices, .. }` replaced by `Oblivious { .. }`
  (`Opening { opens, .. }` for an opening round, with the `opens` parameter
  after the opened one), the `indices` parameter gone; an init's book
  constructor `<f>` replaced by `<f>_oblivious`. The parameter order, and so
  the witness and the ACIR, follows the clear main's.
- `circuits/<twin>/Nargo.toml`: the clear package's, under the twin's name.

The fixtures (Prover*.toml) and outputs are the example's gen-fixtures.py's.

`<example> <round>` writes the twin, or says it is committed. `--check` (run
by scripts/check-manifests.py, and with the example's name by
scripts/check-noir.sh) checks every committed twin, one whose manifest or
circuit directory exists, against its derivation, and validates every
derived manifest against the schema.
"""

import argparse
import copy
import importlib.util
import json
import re
import sys
from pathlib import Path

sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parent.parent
GEN_INTAKE = ROOT / "scripts" / "gen-intake.py"
# the app value the oblivious opening round outputs its append index as: the
# one after its exit tag (pss_public_contract outcome::Private's app values)
NEXT_INDEX = "app_values[1]"
# the opening flag an oblivious opening round takes beside its shared index
OPENS = "opens"
# the slot parameters a tree entry names, and a window's
SLOT_PARAMS = ("leaves", "old_hashes", "siblings")
# a tree entry's keys in the order the derived entry writes them
TREE_ORDER = ("depth", "leaf_len", "probe", "header", "access", "index", "count", "open", "params",
              "store", "window", "next_index")


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


GI = _load("gen_intake", GEN_INTAKE)


def fail(msg):
    raise SystemExit(f"gen-access: {msg}")


# ---- names -------------------------------------------------------------------

def twin_name(clear):
    return clear[: -len("_shared")] + "_oblivious" if clear.endswith("_shared") else f"{clear}_oblivious"


def clear_rounds(ex):
    """The rounds that can have a twin: every manifest under secret-shared
    receipt intake and every init (no state read), whose tree is a clear
    Merkle tree, by package name."""
    out = []
    for f in sorted((GI.example_dir(ex) / "manifests").glob("*.json")):
        m = json.loads(f.read_text())
        trees = list(m.get("tree", {}).values())
        if not trees or any(t.get("access", "clear") != "clear" or "depth" not in t for t in trees):
            continue
        queued = m.get("intake") == "shared_receipt" and f.stem.endswith("_shared")
        init = m.get("state_keys", {}).get("reads") == 0
        if queued or init:
            out.append(f.stem)
    return out


def twins(ex):
    """The committed twins: (clear, twin) for each clear round whose twin's
    manifest or circuit directory exists."""
    d = GI.example_dir(ex)
    return [(c, twin_name(c)) for c in clear_rounds(ex)
            if (d / "manifests" / f"{twin_name(c)}.json").exists() or (d / "circuits" / twin_name(c)).is_dir()]


# ---- the manifest --------------------------------------------------------------

def oblivious_load(tree):
    """The oblivious form a round loads (module doc): each slot parameter's
    [start, end) and the total length."""
    depth, leaf, probe = tree["depth"], tree["leaf_len"], tree["probe"]
    spans, at = {}, 0
    for name, n in zip(SLOT_PARAMS, (probe * leaf, probe, probe * depth)):
        spans[tree["params"][name]] = (at, at + n)
        at += n
    win = tree.get("window")
    if win:
        w = win["width"]
        if w & (w - 1):
            fail(f"window width {w} is not a power of two")
        above = depth - (w.bit_length() - 1)
        for name, n in zip(SLOT_PARAMS, (w * leaf, w, above)):
            spans[win["params"][name]] = (at, at + n)
            at += n
    return spans, at


def derive_manifest(clear, twin):
    m = copy.deepcopy(clear)
    m["circuit"] = twin
    if len(m.get("tree", {})) != 1:
        fail(f"{clear['circuit']}: a twin is derived for one tree key, not {len(m.get('tree', {}))}")
    (key, tree), = m["tree"].items()
    store_len = tree["probe"] * (tree["leaf_len"] + 1 + tree["depth"])
    index = set(tree.get("index", []))
    spans, total = oblivious_load(tree) if "params" in tree else ({}, 0)
    placed = tree.get("params", {}).get("indices")
    witness = []
    for e in m["witness"]:
        kind, name = GI.source(e)
        if e["param"] == placed:
            continue
        if e["param"] in spans:
            a, b = spans[e["param"]]
            witness.append({"param": e["param"], "from": {"LOAD": key, "slice": [a, b], "len": total}})
            continue
        if kind == "PUBLIC" and isinstance(name, str) and name in index:
            witness.append({"param": e["param"], "from": {"INPUT_SHARED": name}})
        else:
            witness.append(e)
        if kind == "PUBLIC" and isinstance(name, str) and name == tree.get("open"):
            witness.append({"param": OPENS, "from": {"PUBLIC": OPENS}})
    m["witness"] = witness
    for out in m.get("outputs", []):
        if out.get("STORE") in (key, tree.get("store")):
            out["len"] = store_len
    t = dict(tree)
    t["access"] = "oblivious"
    t.pop("new_hashes", None)
    if "params" in t:
        t["params"] = {k: v for k, v in t["params"].items() if k != "indices"}
    if "open" in t:
        t["open"] = OPENS
        t["next_index"] = NEXT_INDEX
    extra = set(t) - set(TREE_ORDER)
    if extra:
        fail(f"{clear['circuit']}: tree keys {sorted(extra)} have no rule here")
    m["tree"] = {key: {k: t[k] for k in TREE_ORDER if k in t}}
    return m


# ---- the main ------------------------------------------------------------------

def header(ex, clear, twin, m):
    tree = next(iter(m["tree"].values()))
    lines = [
        f"//! Generated by scripts/gen-access.py from ../{clear}/src/main.nr; do not edit",
        f"//! (`python3 -I scripts/gen-access.py {ex} {clear}` rewrites it, `--check` compares).",
        f"//! `{clear}` over the oblivious book (`access: oblivious`, manifests/{twin}.json;",
        '//! docs/ARCHITECTURE.md section 6, "The oblivious tree"): the same round of the app library with the',
    ]
    if "params" not in tree:
        lines += [
            "//! book's constructor that also keeps the header's path nodes, which the nodes",
            "//! write into the oblivious RAM they build; `new_hashes[0]` is 0. The public",
            "//! inputs and the total-lint justification are the clear init's.",
        ]
    else:
        lines += [
            "//! indices composed in the circuit from the request's positions, which are",
            "//! shared too, the slots read from the nodes' oblivious RAM and no leaf hash",
            "//! out." + (" The request also takes the public opening flag `opens`." if "open" in tree else ""),
            "//! The public inputs are the clear round's.",
        ]
    return lines


def derive_main(ex, clear, twin, m, opened):
    """The twin's main.nr from the clear main's text (module doc); `opened`
    is the clear tree's opened input (its `open`), or None."""
    src = (GI.example_dir(ex) / "circuits" / clear / "src" / "main.nr").read_text().split("\n")
    i = 0
    while i < len(src) and src[i].startswith("//"):
        i += 1
    while i < len(src) and src[i] == "":
        i += 1
    body = src[i:]
    tree = next(iter(m["tree"].values()))
    opening = "open" in tree
    entry = "Opening" if opening else "Oblivious"
    out = []
    skip = 0
    for line in body:
        if skip:
            skip -= 1
            continue
        if "params" not in tree:
            out.append(re.sub(r"\b(empty_book)\b", r"\1_oblivious", line))
            continue
        use = re.fullmatch(r"use (\w+)::entry::\{self, (.*)\};", line)
        if use:
            names = [n.strip() for n in use.group(2).split(",")]
            if "Clear" not in names:
                fail(f"{clear}: its entry import names no `Clear`")
            names = sorted(n for n in names if n != "Clear") + [entry]
            out.append(f"use {use.group(1)}::entry::{{self, {', '.join(sorted(names))}}};")
            continue
        if line.strip() == "// the indices the nodes placed":
            skip = 1
            continue
        if line.strip() == "// ---- the book's slots, from the nodes ----":
            out.append(line.replace("from the nodes", "the nodes' oblivious RAM reads"))
            continue
        if "Clear { indices, " in line:
            out.append(line.replace("Clear { indices, ", f"Opening {{ {OPENS}, " if opening else "Oblivious { "))
            continue
        out.append(line)
        if opening and re.fullmatch(rf"\s*{re.escape(opened)}: Field,", line):
            out += ["    // 1 when the request opens a position", f"    {OPENS}: Field,"]
    if opening and f"    {OPENS}: Field," not in out:
        fail(f"{clear}: no `{opened}: Field,` parameter to put `{OPENS}` after")
    text = "\n".join(header(ex, clear, twin, m) + [""] + out)
    if "params" in tree:
        for marker in ("Clear", "indices"):
            if re.search(rf"\b{marker}\b", re.sub(r"//[^\n]*", "", text)):
                fail(f"{clear}: `{marker}` is left in the derived main; its rule does not cover this main")
    return text


def derive_nargo(ex, clear, twin):
    text = (GI.example_dir(ex) / "circuits" / clear / "Nargo.toml").read_text()
    new, n = re.subn(rf'(?m)^name = "{re.escape(clear)}"$', f'name = "{twin}"', text)
    if n != 1:
        fail(f"circuits/{clear}/Nargo.toml: no `name = \"{clear}\"` line")
    return new


def derive(ex, clear):
    """The twin's files of clear round `clear`: {path: text}, and the manifest."""
    d = GI.example_dir(ex)
    twin = twin_name(clear)
    source = json.loads((d / "manifests" / f"{clear}.json").read_text())
    m = derive_manifest(source, twin)
    opened = next(iter(source["tree"].values())).get("open")
    return {
        d / "manifests" / f"{twin}.json": GI.dump_manifest(m),
        d / "circuits" / twin / "src" / "main.nr": derive_main(ex, clear, twin, m, opened),
        d / "circuits" / twin / "Nargo.toml": derive_nargo(ex, clear, twin),
    }, m


# ---- the commands ------------------------------------------------------------

def generate(ex, clear, dry):
    if clear not in clear_rounds(ex):
        fail(f"{ex} has no clear round {clear} (rounds: {', '.join(clear_rounds(ex)) or 'none'})")
    files, m = derive(ex, clear)
    problems = GI.schema_errors(m)
    if problems:
        fail(f"the derived manifests/{twin_name(clear)}.json fails the schema:\n  " + "\n  ".join(problems))
    wrote = 0
    for path, text in files.items():
        rel = path.relative_to(ROOT)
        if path.exists() and path.read_text() == text:
            continue
        wrote += 1
        if not dry:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
        print(f"{'would write' if dry else 'wrote'} {rel}")
    if not wrote:
        print(f"gen-access: {ex} {clear}'s twin {twin_name(clear)} is committed; nothing to write")
    return 0


def check(only=None):
    """Every committed twin is its derivation; every derived manifest
    validates against the schema. `only` limits the check to one example."""
    bad = 0
    for ex in GI.examples():
        if only and ex != only:
            continue
        for clear, twin in twins(ex):
            files, m = derive(ex, clear)
            problems = GI.schema_errors(m)
            if problems:
                bad += 1
                print(f"FAIL derived manifests/{twin}.json: " + "; ".join(problems))
            for path, text in files.items():
                rel = path.relative_to(ROOT)
                if not path.exists() or path.read_text() != text:
                    bad += 1
                    print(f"FAIL {rel} is not the derivation from {clear} "
                          f"(scripts/gen-access.py {ex} {clear} rewrites it)")
                else:
                    print(f"ok   {rel} (derived from {clear})")
    print(f"gen-access --check: {'PASS' if not bad else 'FAIL'}")
    return 1 if bad else 0


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("example", nargs="?")
    ap.add_argument("round", nargs="?")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--check", action="store_true")
    a = ap.parse_args(argv)
    if a.check:
        if a.example and a.example not in GI.examples():
            print(f"gen-access: {a.example} has no manifests; nothing to check")
            return 0
        return check(a.example)
    if not (a.example and a.round):
        ap.error("give <example> <round>, or --check")
    return generate(a.example, a.round, a.dry_run)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
