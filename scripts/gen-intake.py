#!/usr/bin/env python3
"""Derive a tip round's manifests under each intake from its secret-shared one.

Run as `python3 -I scripts/gen-intake.py ...` (stdlib only):

  gen-intake.py <example> <round> <intake> [--dry-run]
  gen-intake.py --layouts
  gen-intake.py --check [<example>]

<example> is a tip example directory name (`lending-tip`, `amm-tip`), <round>
a round's base name (lending's `deposit`, the AMM's `amm_swap_tip`: its
secret-shared manifest is `manifests/<round>_shared.json` under secret-shared
receipt intake), <intake> one of `onchain` (on-chain intake), `receipt`
(receipt intake), `shared_receipt` (secret-shared receipt intake) and
`shared_onchain` (secret-shared on-chain intake). The design guide's "Running
a round under another intake" (docs/design-guide/README.md) is the recipe;
this script does its manifest step.

A round has one compiled circuit per intake family: `<round>_shared` serves
both secret-shared intakes, `<round>` both non-secret-shared intakes, each a
main that names its family (pss_core `tip::family`) and calls the round's one
function in the app's library. Within a family the manifests differ in
`circuit` and `intake` alone. Across families the non-secret-shared manifest
follows from the secret-shared one and the non-secret-shared main's
parameters (`circuits/<round>/src/main.nr`): the app inputs PUBLIC, the
request's `user_nonce` after the partial note, no C, outcome key, tag or
blinding, no value the main does not take (a value C carries only for the
private outcome, such as a delivery handle), and the non-secret-shared
outputs' names (pss_core `Bound`: `old_c`, `new_c`, `app.*`). A round without
a non-secret-shared main has no non-secret-shared manifest to derive.

`<example> <round> <intake>` writes `manifests/<name>.json` (`<name>` is
`<round>`, `<round>_receipt`, `<round>_shared` or `<round>_shared_onchain`),
validated against docs/manifest.schema.json, or says it is committed. The
main, the contract's request function and the client's request are the
app's (the recipe).

`--layouts` writes each secret-shared round's layout, the kind of each value
of the inputs commitment C in C's order (CHOSEN for an INPUT_SHARED value,
CLEAR for any other), which follows from its manifest and its main's
parameter order alone (sidecar-tip `commitment_layout` is the rule):

- `examples/<example>/contract/<package>/src/layouts.nr`, one global
  `<PACKAGE>_LAYOUT` per secret-shared manifest, which the round's request
  function hands `outcome_request` (`<package>` is the one contract package,
  or the library the example's contracts share, that holds the file:
  lending's `lending_market`);
- `testvectors/onchain_layouts.json`, every example round's names, kinds,
  clear count and corrections, which sidecar-tip and pss-client check
  against their own derivations from the compiled circuit's ABI.

`--check` (run by scripts/check-manifests.py, and with the example's name by
scripts/check-noir.sh) checks every committed manifest of a round under an
intake against its derivation and validates every derivation against the
schema, and, without an example, that the layout files are what `--layouts`
writes. An absent `outcome` is the schema's default, `partial`.
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
INTAKES = ("onchain", "receipt", "shared_receipt", "shared_onchain")
PLAIN = ("onchain", "receipt")
PROSE = {
    "onchain": "on-chain intake",
    "receipt": "receipt intake",
    "shared_receipt": "secret-shared receipt intake",
    "shared_onchain": "secret-shared on-chain intake",
}
# the reserved operands only a secret-shared intake has
SHARED_RESERVED = {"$inputs_hash", "$outcome_key", "$outcome_tag", "$blinding"}
# the manifest schema's default value delivery
DEFAULT_OUTCOME = "partial"
CHECK_MANIFESTS = ROOT / "scripts" / "check-manifests.py"


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def fail(msg):
    raise SystemExit(f"gen-intake: {msg}")


# ---- names -------------------------------------------------------------------

def manifest_name(rnd, intake):
    return {"onchain": rnd, "receipt": f"{rnd}_receipt",
            "shared_receipt": f"{rnd}_shared", "shared_onchain": f"{rnd}_shared_onchain"}[intake]


def example_dir(ex):
    d = ROOT / "examples" / ex
    if not (d / "manifests").is_dir():
        fail(f"no tip example at examples/{ex}")
    return d


def examples():
    """Every example with manifests, by directory name."""
    return sorted(p.parent.name for p in (ROOT / "examples").glob("*/manifests") if p.is_dir())


def rounds_of(ex):
    """The rounds: every manifest under secret-shared receipt intake, by base name."""
    out = []
    for f in sorted((example_dir(ex) / "manifests").glob("*_shared.json")):
        if json.loads(f.read_text()).get("intake") == "shared_receipt":
            out.append(f.name[: -len("_shared.json")])
    return out


def plain_main(ex, rnd):
    """The non-secret-shared main of `rnd` (`circuits/<round>/src/main.nr`)."""
    return example_dir(ex) / "circuits" / rnd / "src" / "main.nr"


def main_params(path):
    """The parameter names of the `main` in `path`, in ABI order."""
    src = re.sub(r"//[^\n]*", "", path.read_text())
    m = re.search(r"\bfn main\s*\((.*?)\)\s*->", src, re.S)
    if not m:
        fail(f"no `fn main(...) ->` in {path.relative_to(ROOT)}")
    names, depth, cur = [], 0, ""
    for ch in m.group(1) + ",":
        depth += ch in "([{<"
        depth -= ch in ")]}>"
        if ch == "," and depth == 0:
            if cur.strip():
                names.append(cur.split(":")[0].strip())
            cur = ""
        else:
            cur += ch
    return names


# ---- manifests ---------------------------------------------------------------

def dump_manifest(m):
    """The examples' manifest layout: one line per top-level field, one per
    witness, output and read entry, one per tree key."""
    lines = ["{"]
    items = list(m.items())
    for i, (k, v) in enumerate(items):
        comma = "," if i < len(items) - 1 else ""
        key = json.dumps(k)
        if isinstance(v, list) and v and all(isinstance(x, dict) for x in v):
            lines.append(f"  {key}: [")
            lines += [f"    {json.dumps(x)}" + ("," if j < len(v) - 1 else "") for j, x in enumerate(v)]
            lines.append(f"  ]{comma}")
        elif k == "tree" and isinstance(v, dict):
            lines.append(f"  {key}: {{")
            ks = list(v.items())
            lines += [f"    {json.dumps(a)}: {json.dumps(b)}" + ("," if j < len(ks) - 1 else "")
                      for j, (a, b) in enumerate(ks)]
            lines.append(f"  }}{comma}")
        else:
            lines.append(f"  {key}: {json.dumps(v)}{comma}")
    return "\n".join(lines + ["}"]) + "\n"


def source(entry):
    f = entry["from"]
    for kind in ("PUBLIC", "INPUT_SHARED"):
        if kind in f:
            return kind, f[kind]
    return None, None


def to_plain(shared, params, rnd):
    """The non-secret-shared manifest of a round from its secret-shared one
    and its non-secret-shared main's parameters (module doc)."""
    m = copy.deepcopy(shared)
    m["circuit"] = rnd
    m["intake"] = "onchain"
    witness, in_app = [], False
    for e in shared["witness"]:
        kind, name = source(e)
        name = name if isinstance(name, str) else None
        if name in SHARED_RESERVED:
            in_app = in_app or name == "$inputs_hash"
            continue
        if e["param"] not in params:
            continue
        if kind == "INPUT_SHARED":
            witness.append({"param": e["param"], "from": {"PUBLIC": name}})
        else:
            witness.append(copy.deepcopy(e))
        if in_app and name == "$partial_note":
            witness.append({"param": "user_nonce", "from": {"PUBLIC": "$user_nonce"}})
            in_app = False
    m["witness"] = witness
    for out in m.get("outputs", []):
        if "note_hash" in out:
            if not out["note_hash"].endswith("new_commitments[0]"):
                fail(f"{rnd}: output note hash {out['note_hash']} has no non-secret-shared name")
            out["note_hash"] = "new_c"
    for slot in m.get("commitment_slot", {}).values():
        if not slot.get("old", "").endswith("old_commitments[0]"):
            fail(f"{rnd}: commitment slot {slot} has no non-secret-shared name")
        slot["old"] = "old_c"
    for tree in m.get("tree", {}).values():
        if "new_hashes" in tree:
            tree["new_hashes"] = f"app.{tree['new_hashes'].split('.')[-1]}"
    return m


def shared_manifest(ex, rnd):
    f = example_dir(ex) / "manifests" / f"{rnd}_shared.json"
    if not f.exists():
        fail(f"{ex}: no secret-shared manifest manifests/{rnd}_shared.json for round {rnd}")
    return json.loads(f.read_text())


def derive(ex, rnd, intake):
    """The manifest of `rnd` under `intake`, from the round's secret-shared
    manifest (never from the file it derives), or None for a
    non-secret-shared intake when the round has no non-secret-shared main."""
    shared = shared_manifest(ex, rnd)
    if intake == "shared_receipt":
        return shared
    if intake == "shared_onchain":
        m = copy.deepcopy(shared)
        m["circuit"] = manifest_name(rnd, intake)
        m["intake"] = "shared_onchain"
        return m
    main = plain_main(ex, rnd)
    if not main.exists():
        return None
    m = to_plain(shared, set(main_params(main)), rnd)
    m["circuit"] = manifest_name(rnd, intake)
    m["intake"] = intake
    return m


def same(a, b):
    """Two manifests are the same, an absent `outcome` read as the default."""
    def norm(m):
        return {"outcome": DEFAULT_OUTCOME, **m}
    return norm(a) == norm(b)


def schema_errors(manifest):
    cm = _load("check_manifests", CHECK_MANIFESTS)
    return cm.validate(manifest, json.loads(cm.SCHEMA.read_text()))


# ---- layouts ------------------------------------------------------------------

LAYOUTS_JSON = ROOT / "testvectors" / "onchain_layouts.json"
SHARED_INTAKES = ("shared_receipt", "shared_onchain")
# the leaf width of a main parameter's scalar types
SCALARS = {"Field", "bool", "u8", "u16", "u32", "u64", "u128", "i8", "i16", "i32", "i64"}


def main_signature(path):
    """The `(name, type)` of each parameter of the `main` in `path`, in ABI
    order (`main_params`' split, types kept)."""
    src = re.sub(r"//[^\n]*", "", path.read_text())
    m = re.search(r"\bfn main\s*\((.*?)\)\s*->", src, re.S)
    if not m:
        fail(f"no `fn main(...) ->` in {path.relative_to(ROOT)}")
    out, depth, cur = [], 0, ""
    for ch in m.group(1) + ",":
        depth += ch in "([{<"
        depth -= ch in ")]}>"
        if ch == "," and depth == 0:
            if cur.strip():
                name, ty = cur.split(":", 1)
                out.append((name.strip(), re.sub(r"^\s*pub\s+", "", ty).strip()))
            cur = ""
        else:
            cur += ch
    return out


def width(ty):
    """How many fields a parameter type flattens to, or None when the type
    names a length this script cannot read (a global)."""
    ty = ty.strip()
    if ty in SCALARS:
        return 1
    m = re.fullmatch(r"\[(.*);\s*(\d+)\s*\]", ty, re.S)
    if m:
        inner = width(m.group(1))
        return None if inner is None else inner * int(m.group(2))
    return None


def deployments(ex):
    return [json.loads(f.read_text()) for f in sorted((example_dir(ex) / "deployments").glob("*.json"))]




def circuit_of(ex, package):
    """The compiled circuit of `package`: the deployments' `circuit`, else
    the package's own name."""
    for d in deployments(ex):
        for p in d["packages"]:
            if p["name"] == package:
                return p["circuit"]
    return package


def shared_rounds(ex):
    """The example's manifests under a secret-shared intake, by file name."""
    out = []
    for f in sorted((example_dir(ex) / "manifests").glob("*.json")):
        m = json.loads(f.read_text())
        if m.get("intake") in SHARED_INTAKES:
            out.append((f, m))
    return out


def layout(ex, f, m):
    """The commitment layout of the round of manifest `m` (file `f`): C's
    values before the blinding, by name, in the order the main's ABI walk
    first meets each, and each value's kind (sidecar-tip `commitment_names`
    and `commitment_layout`): every clear app input element (a PUBLIC
    request name, `name[i]` for each element of a wider parameter), every
    INPUT_SHARED value but `$blinding`; the parameters a pinned public read
    or a tree key's paths fill are skipped."""
    circuit = circuit_of(ex, m["circuit"])
    main = example_dir(ex) / "circuits" / circuit / "src" / "main.nr"
    if not main.exists():
        fail(f"{f.relative_to(ROOT)}: no main at {main.relative_to(ROOT)}")
    skip = set()
    for r in m.get("public_reads", []):
        skip.add(r["param"])
        if r.get("epoch_param"):
            skip.add(r["epoch_param"])
    for tree in m.get("tree", {}).values():
        params = tree.get("params") or {}
        skip.update(params[k] for k in ("old_hashes", "siblings", "indices") if k in params)
        win = (tree.get("window") or {}).get("params") or {}
        skip.update(win[k] for k in ("old_hashes", "siblings") if k in win)
    sources = {w["param"]: w["from"] for w in m["witness"]}
    names, shared = [], set()
    for param, ty in main_signature(main):
        if param in skip or param not in sources:
            continue
        src = sources[param]
        if "INPUT_SHARED" in src:
            name = src["INPUT_SHARED"]
            shared.add(name)
            if name != "$blinding":
                names.append(name)
        elif "PUBLIC" in src:
            op = src["PUBLIC"]
            if isinstance(op, list):
                names += [o for o in op if isinstance(o, str) and not o.startswith("$")]
            elif isinstance(op, str) and not op.startswith("$"):
                w = width(ty)
                if w is None:
                    fail(f"{f.relative_to(ROOT)}: the clear app input {param}: {ty} has a length "
                         f"this script cannot read; write it as a number")
                names += [op] if w == 1 else [f"{op}[{i}]" for i in range(w)]
    seen, ordered = set(), []
    for n in names:
        if n not in seen:
            seen.add(n)
            ordered.append(n)
    return circuit, [(n, n in shared) for n in ordered]


def layout_global(package):
    return f"{package.upper()}_LAYOUT"


def layouts_file(ex):
    """The example's layouts file: the one `contract/<package>/src/layouts.nr`
    (the app contract's, or the library its contracts share)."""
    found = sorted((example_dir(ex) / "contract").glob("*/src/layouts.nr"))
    if len(found) != 1:
        fail(f"{ex}: {len(found)} contract/*/src/layouts.nr files; expected one (create it empty for a new example)")
    return found[0]


def render_layouts(ex, rounds):
    """The example's generated `layouts.nr`."""
    used = sorted({"CHOSEN" if c else "CLEAR" for _, _, kinds in rounds for _, c in kinds})
    lines = [
        "//! Generated by scripts/gen-intake.py from the example's manifests; do not edit",
        "//! (`python3 -I scripts/gen-intake.py --layouts` rewrites it, `--check` compares).",
        "//! One global per round under a secret-shared intake: the kind of each value of",
        "//! the inputs commitment C in C's order, CHOSEN for an INPUT_SHARED value and",
        "//! CLEAR for any other, which the round's request function hands",
        "//! `outcome_request`. A layout the machine does not derive gives shares that",
        "//! miss C (secret-shared on-chain intake) or receipts that do not verify",
        "//! (secret-shared receipt intake).",
        f"use pss_public_contract::{{{', '.join(used + ['Layout'])}}};",
    ]
    for f, package, kinds in rounds:
        q = sum(1 for _, c in kinds if not c)
        x = len(kinds) - q
        body = ", ".join("CHOSEN" if c else "CLEAR" for _, c in kinds)
        lines += [
            "",
            f"/// {f.relative_to(example_dir(ex)).as_posix()}: `[{', '.join(n for n, _ in kinds)}]`.",
            f"pub global {layout_global(package)}: Layout<{len(kinds)}, {q}, {x}> =",
            f"    Layout {{ kinds: [{body}] }};",
        ]
    return "\n".join(lines) + "\n"


def all_layouts():
    """Every example's secret-shared rounds: (example, manifest file,
    package, circuit, kinds)."""
    out = []
    for ex in examples():
        for f, m in shared_rounds(ex):
            circuit, kinds = layout(ex, f, m)
            out.append((ex, f, m["circuit"], circuit, kinds))
    return out


def render_vector(rounds):
    entries = []
    for ex, f, package, circuit, kinds in rounds:
        q = sum(1 for _, c in kinds if not c)
        entries.append({
            "example": ex,
            "manifest": f.relative_to(ROOT).as_posix(),
            "circuit": circuit,
            "names": [n for n, _ in kinds],
            "kinds": [int(c) for _, c in kinds],
            "clear": q,
            "corrections": len(kinds) - q,
            "layout": layout_global(package),
            "layouts": layouts_file(ex).relative_to(ROOT).as_posix(),
        })
    doc = {
        "rule": "Each example round's layout under a secret-shared intake (receipt or on-chain): the kind of "
                "each value of C in its order (clear 0, chosen 1; an INPUT_SHARED value is chosen, any other "
                "clear), the clear count and the corrections a request log carries (one per chosen value). "
                "Written by scripts/gen-intake.py --layouts from the manifest and the main's parameter order, "
                "with the contract global (layout, in the generated file layouts) the request function passes; "
                "sidecar-tip's onchain_layout and pss-client's onchainLayout derive the same from the compiled "
                "circuit's ABI. Under receipt intake the chosen values are the sharing's summand order.",
        "kinds": {"chosen": 1, "clear": 0},
        "rounds": entries,
    }
    return json.dumps(doc, indent=2, sort_keys=True) + "\n"


def layout_outputs():
    """Every layout file and its text."""
    rounds = all_layouts()
    out = {}
    for ex in sorted({r[0] for r in rounds}):
        mine = [(f, package, kinds) for e, f, package, _, kinds in rounds if e == ex]
        out[layouts_file(ex)] = render_layouts(ex, mine)
    out[LAYOUTS_JSON] = render_vector(rounds)
    return out


def write_layouts():
    for path, text in layout_outputs().items():
        path.write_text(text)
        print(f"wrote {path.relative_to(ROOT)}")
    return 0


def check_layouts():
    """The number of layout files that are not what `--layouts` writes."""
    bad = 0
    for path, text in layout_outputs().items():
        rel = path.relative_to(ROOT)
        if not path.exists() or path.read_text() != text:
            bad += 1
            print(f"FAIL {rel} is not what scripts/gen-intake.py --layouts writes")
        else:
            print(f"ok   {rel} (layouts)")
    return bad


# ---- the commands ------------------------------------------------------------

def generate(ex, rnd, intake, dry):
    d = example_dir(ex)
    if rnd not in rounds_of(ex):
        fail(f"{ex} has no round {rnd} (rounds: {', '.join(rounds_of(ex)) or 'none'})")
    name = manifest_name(rnd, intake)
    manifest = derive(ex, rnd, intake)
    if manifest is None:
        fail(f"{ex}: round {rnd} has no non-secret-shared main (circuits/{rnd}/src/main.nr); "
             f"write it first, the round's function under pss_core's family::Plain (the recipe)")
    problems = schema_errors(manifest)
    if problems:
        fail(f"the derived manifests/{name}.json fails the schema:\n  " + "\n  ".join(problems))
    path = d / "manifests" / f"{name}.json"
    rel = path.relative_to(ROOT)
    if path.exists() and same(json.loads(path.read_text()), manifest):
        print(f"gen-intake: {ex} {rnd} under {PROSE[intake]} is committed ({rel}); nothing to write")
        return 0
    if not dry:
        path.write_text(dump_manifest(manifest))
    print(f"{'would write' if dry else 'wrote'} {rel}")
    return 0


def check(only=None):
    """Every committed manifest of a round under an intake is its derivation;
    every derivation validates against the schema. `only` limits the check
    to one example."""
    bad = 0
    for ex in examples():
        if only and ex != only:
            continue
        d = example_dir(ex)
        for rnd in rounds_of(ex):
            for intake in INTAKES:
                name = manifest_name(rnd, intake)
                f = d / "manifests" / f"{name}.json"
                rel = f.relative_to(ROOT)
                m = derive(ex, rnd, intake)
                if m is None:
                    if f.exists():
                        bad += 1
                        print(f"FAIL {rel}: round {rnd} has no non-secret-shared main (circuits/{rnd})")
                    else:
                        print(f"ok   {rel}: no non-secret-shared main, nothing to derive")
                    continue
                problems = schema_errors(m)
                if problems:
                    bad += 1
                    print(f"FAIL derived {rel}: " + "; ".join(problems))
                elif f.exists() and intake != "shared_receipt":
                    if not same(json.loads(f.read_text()), m):
                        bad += 1
                        print(f"FAIL {rel} is not the derivation from {rnd}_shared.json "
                              f"(scripts/gen-intake.py {ex} {rnd} {intake} rewrites it)")
                    else:
                        print(f"ok   {rel} (derived)")
                else:
                    print(f"ok   derived {rel}{'' if f.exists() else ' (not committed)'}")
    if not only:
        bad += check_layouts()
    print(f"gen-intake --check: {'PASS' if not bad else 'FAIL'}")
    return 1 if bad else 0


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("example", nargs="?")
    ap.add_argument("round", nargs="?")
    ap.add_argument("intake", nargs="?", choices=INTAKES)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--layouts", action="store_true")
    a = ap.parse_args(argv)
    if a.layouts:
        return write_layouts()
    if a.check:
        if a.example and a.example not in examples():
            print(f"gen-intake: {a.example} has no manifests; nothing to check")
            return 0
        return check(a.example)
    if not (a.example and a.round and a.intake):
        ap.error("give <example> <round> <intake>, or --check")
    return generate(a.example, a.round, a.intake, a.dry_run)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
