#!/usr/bin/env python3
"""Check docs/design-guide/design-space.json for internal consistency.

Run as `python3 -I scripts/check-design-space.py [path]` (stdlib only);
`--plan <blueprint id>` prints one blueprint's values, bricks with their paths
and statuses, example, files to start from and allowed deviations with the bricks each
one adds and drops. It checks
that every reference resolves (axes, values, statuses, bricks, examples,
blueprints), that every built brick's paths exist (deps/ links excepted: bootstrap.sh
makes them), that every condition names real axes and values, that each
blueprint and each example's as-built permutation passes every error-level
constraint, that a blueprint uses no deferred or not-offered value and lists every
brick its values need, and that each blueprint deviation is itself a valid
permutation. It also checks the compatibility rules (every constraint belongs to
exactly one rule, every link resolves) and the parties table, and that the design
guide's generated blocks (`<!-- generated: <id> -->` ... `<!-- end generated -->`
in docs/design-guide/README.md) match what this file renders from the design
space.

Every decision axis is set by some design question, and every axis has its row
in the guide's "Where each choice lives" table.

Bricks: every brick's `api` (the library items an app calls, by where it calls
them, or `internal`) names symbols that exist in their files; the generated brick
reference docs/design-guide/BRICKS.md matches; every `// BRICK` marker under
examples/ sits at a seam where another option could be chosen: it names a real
axis, the value(s) plugged in, a symbol in the `api` of that value's bricks that
the code below it uses (or the manifest field that picks it) and its
alternatives, or it names a brick in no axis option (an "other brick") and says
it has no alternative; a marker for an always-present brick is refused. Each
example README's generated "Bricks this example uses" block
(`<!-- bricks:begin -->` ... `<!-- bricks:end -->`) matches its markers.

The api lists are complete (`apiCheck`): every brick-library item the examples'
non-test code uses is in some brick's api or in `apiCheck.common`, every name an
example's client code imports from pss-client is in some brick's client api, and
every pss-client name the e2e driver imports is in one or in `apiCheck.harness`
(which names no stale or brick-listed entry). Exit status 0 when clean, 1 with
one line per problem otherwise.

    python3 -I scripts/check-design-space.py                  # validate, and check every generated page and block
    python3 -I scripts/check-design-space.py --plan tip-tree  # one blueprint as a starting plan
    python3 -I scripts/check-design-space.py --plan intake=shared_onchain shape=tree   # any choices: checked, then the bricks and what to call
    python3 -I scripts/check-design-space.py --compat         # the derived compatibility of every value pair
    python3 -I scripts/check-design-space.py --write-readme   # rewrite the guide's generated blocks
    python3 -I scripts/check-design-space.py --write-bricks   # rewrite BRICKS.md and the examples' brick tables
"""
import itertools
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
DEFAULT = ROOT / "docs" / "design-guide" / "design-space.json"
README = ROOT / "docs" / "design-guide" / "README.md"
BRICKS_MD = ROOT / "docs" / "design-guide" / "BRICKS.md"
EXAMPLES = ROOT / "examples"
UNROBUST = {"deferred", "not-offered", "experimental"}
GENERATED = re.compile(r"(<!-- generated: (?P<id>[a-z-]+) -->\n)(?P<body>.*?)(<!-- end generated -->)", re.S)
BRICKS_BLOCK = re.compile(r"(<!-- bricks:begin -->\n)(?P<body>.*?)(<!-- bricks:end -->)", re.S)
# Where an app calls a brick's library items, in the order BRICKS.md lists them.
API_PLACES = [
    ("contract", "the Noir contract library (`noir/pss_public_contract`, `noir/pss_contract`), called from the app's Aztec contract"),
    ("circuit", "`noir/pss_core`, called from the app's round circuits"),
    ("client", "`ts/pss-client` (and the e2e driver), called from the app's client code"),
    ("machine", "what an operator configures"),
]
API_KEYS = [k for k, _ in API_PLACES]
INTERNAL = "an app does not call this"  # the plain internal note, shown beside the brick's name


def as_list(x):
    return x if isinstance(x, list) else [x]


def match(cond, sel):
    """The condition semantics (see the design space's 'about')."""
    if not cond:
        return True
    for k, v in cond.items():
        if k == "any":
            if not any(match(c, sel) for c in v):
                return False
        elif k == "not":
            if match(v, sel):
                return False
        elif sel.get(k) not in v:
            return False
    return True


def validate(ds):
    errs = []
    err = errs.append

    for key in ("statuses", "coreBricks", "axes", "constraints", "compatibility", "bricks",
                "examples", "blueprints", "questions", "leakage", "parties", "properties",
                "parameters", "devDecisionClasses", "apiCheck", "reservedNames"):
        if key not in ds:
            err(f"missing top-level key {key!r}")
    if errs:
        return errs

    statuses = set(ds["statuses"])

    def check_status(st, where):
        for s in as_list(st):
            if s not in statuses:
                err(f"{where}: unknown status {s!r}")

    def unique(items, where):
        seen = set()
        for it in items:
            i = it.get("id")
            if i in seen:
                err(f"{where}: duplicate id {i!r}")
            seen.add(i)
        return seen

    # Axes and values.
    axes = {}
    unique(ds["axes"], "axes")
    for a in ds["axes"]:
        vals = {}
        unique(a["values"], f"axis {a['id']}")
        for v in a["values"]:
            vals[v["id"]] = v
            check_status(v.get("status"), f"axis {a['id']} value {v['id']}")
            for f in ("label", "note"):
                if not v.get(f):
                    err(f"axis {a['id']} value {v['id']}: missing {f}")
        axes[a["id"]] = vals
        if a.get("default") not in vals:
            err(f"axis {a['id']}: default {a.get('default')!r} is not one of its values")
    for a in ds["axes"]:
        if a.get("derivedFrom") and a["derivedFrom"] not in axes:
            err(f"axis {a['id']}: derivedFrom {a['derivedFrom']!r} is not an axis")

    examples = {e["id"]: e for e in ds["examples"]}
    unique(ds["examples"], "examples")
    picker = {"example": examples}

    def check_cond(cond, where, allow_example=False):
        if cond is None:
            return
        if not isinstance(cond, dict):
            err(f"{where}: condition is not an object")
            return
        for k, v in cond.items():
            if k == "any":
                for c in v:
                    check_cond(c, where, allow_example)
            elif k == "not":
                check_cond(v, where, allow_example)
            elif k in axes or (allow_example and k in picker):
                known = axes.get(k) or picker[k]
                if not isinstance(v, list) or not v:
                    err(f"{where}: {k} must map to a non-empty list")
                    continue
                for val in v:
                    if val not in known:
                        err(f"{where}: {k} has no value {val!r}")
            else:
                err(f"{where}: unknown axis {k!r}")

    def check_choice(choice, where, complete):
        for k, v in choice.items():
            if k not in axes:
                err(f"{where}: unknown axis {k!r}")
            elif v not in axes[k]:
                err(f"{where}: axis {k} has no value {v!r}")
        if complete:
            missing = [a for a in axes if a not in choice]
            if missing:
                err(f"{where}: no value for {', '.join(missing)}")

    # Constraints.
    unique(ds["constraints"], "constraints")
    constraints = ds["constraints"]
    for c in constraints:
        where = f"constraint {c.get('id')}"
        if c.get("level") not in ("error", "warn"):
            err(f"{where}: level must be error or warn")
        if not c.get("msg"):
            err(f"{where}: missing msg (the reason)")
        check_cond(c.get("if"), where)
        check_cond(c.get("require"), where)
        if "fix" in c:
            check_choice(c["fix"], where + " fix", complete=False)

    def failing(sel, extra=()):
        rules = list(constraints) + list(extra)
        return [r for r in rules if r.get("level") == "error"
                and match(r.get("if"), sel) and not match(r.get("require"), sel)]

    # Bricks.
    bricks = {b["id"]: b for b in ds["bricks"]}
    unique(ds["bricks"], "bricks")
    for b in ds["bricks"]:
        where = f"brick {b['id']}"
        check_status(b.get("status"), where)
        if b.get("kind") not in ("interface", "implementation"):
            err(f"{where}: kind must be interface or implementation")
        if b.get("kind") == "implementation" and b.get("implements") not in bricks:
            err(f"{where}: implements {b.get('implements')!r}, not a brick")
        if not isinstance(b.get("path"), list):
            err(f"{where}: path must be a list")
        elif b.get("status") != "not-offered" and not b["path"]:
            err(f"{where}: no path")
        elif set(as_list(b.get("status"))) == {"built"}:
            for p in b["path"]:
                if not p.startswith("deps/") and not (ROOT / p).exists():
                    err(f"{where}: built, but its path {p!r} does not exist")
        for p in api_problems(b):
            err(f"{where}: {p}")
    for c in ds["coreBricks"]:
        if c not in bricks:
            err(f"coreBricks: {c!r} is not a brick")

    # What the api completeness check reads (completeness_problems).
    chk = ds["apiCheck"]
    missing = [k for k in ("libraries", "common", "harness") if k not in chk]
    if missing:
        err(f"apiCheck: missing {', '.join(missing)}")
    else:
        for lib, src in chk["libraries"].get("noir", {}).items():
            if not (ROOT / src).is_dir():
                err(f"apiCheck.libraries.noir: {lib}'s {src!r} is not a directory")
        if not isinstance(chk["libraries"].get("client"), str):
            err("apiCheck.libraries.client: the client package's name")
        for k in API_KEYS:
            for it in chk["common"].get(k, []):
                if not isinstance(it, dict) or set(it) != {"symbol", "path"}:
                    err(f"apiCheck.common {k}: an item is {{symbol, path}}, not {it!r}")
                elif symbol_problem(it["symbol"], it["path"]):
                    err(f"apiCheck.common {k} {it['symbol']}: {symbol_problem(it['symbol'], it['path'])}")
        for k in set(chk["common"]) - set(API_KEYS) - {"note"}:
            err(f"apiCheck.common: unknown key {k!r}")
        for h in chk["harness"].get("paths", []):
            if not (ROOT / h).is_dir():
                err(f"apiCheck.harness: {h!r} is not a directory")

    def value_bricks(axis, value):
        return value_brick_entries(axes[axis][value])

    used = set(ds["coreBricks"])
    for a, vals in axes.items():
        for v in vals:
            for bid, when in value_bricks(a, v):
                if bid not in bricks:
                    err(f"axis {a} value {v}: brick {bid!r} does not exist")
                check_cond(when, f"axis {a} value {v} brick {bid}")
                used.add(bid)

    def needed_bricks(sel):
        return needed(ds, sel)

    # Examples.
    for e in ds["examples"]:
        where = f"example {e['id']}"
        check_status(e.get("status"), where)
        if e.get("blueprint") not in {b["id"] for b in ds["blueprints"]}:
            err(f"{where}: blueprint {e.get('blueprint')!r} does not exist")
        if not (ROOT / e.get("path", "")).is_dir():
            err(f"{where}: path {e.get('path')!r} is not a directory")
        check_choice(e.get("asBuilt", {}), where + " asBuilt", complete=True)
        for i, r in enumerate(e.get("rules", [])):
            check_cond(r.get("if"), f"{where} rule {i}", allow_example=True)
            check_cond(r.get("require"), f"{where} rule {i}", allow_example=True)
            if r.get("level") not in ("error", "warn"):
                err(f"{where} rule {i}: level must be error or warn")
        for r in failing(dict(e.get("asBuilt", {}), example=e["id"]), as_example_rules(e)):
            err(f"{where} asBuilt: fails {r.get('id', 'its own rule')}: {r['msg']}")

    # Blueprints.
    bp_ids = unique(ds["blueprints"], "blueprints")
    for bp in ds["blueprints"]:
        where = f"blueprint {bp['id']}"
        check_status(bp.get("status"), where)
        sel = bp.get("values", {})
        check_choice(sel, where, complete=True)
        ex_id = (bp.get("example") or {}).get("id")
        if ex_id is not None and ex_id not in examples:
            err(f"{where}: example {ex_id!r} does not exist")
        ex_extra = as_example_rules(examples[ex_id]) if ex_id in examples else []
        for r in failing(dict(sel, example=ex_id), ex_extra):
            err(f"{where}: fails {r.get('id', 'an example rule')}: {r['msg']}")
        for a, v in sel.items():
            if a in axes and v in axes[a] and set(as_list(axes[a][v].get("status"))) & UNROBUST:
                err(f"{where}: uses {a}={v}, which is {axes[a][v]['status']}")
        listed = set(bp.get("bricks", []))
        for bid in listed:
            if bid not in bricks:
                err(f"{where}: brick {bid!r} does not exist")
        for bid in sorted(needed_bricks(sel) - listed):
            err(f"{where}: its values need brick {bid!r}, which it does not list")
        used |= listed
        for f in ("suits", "pros", "cons", "startFrom"):
            if not bp.get(f):
                err(f"{where}: missing {f}")
        for p in bp.get("startFrom", []):
            first = p.split(" ")[0]
            if not (ROOT / first).exists():
                err(f"{where}: startFrom {first!r} does not exist")
        for i, d in enumerate(bp.get("deviations", [])):
            dw = f"{where} deviation {i}"
            check_choice(d.get("set", {}), dw, complete=False)
            dsel = dict(sel, **d.get("set", {}))
            for r in failing(dsel):
                err(f"{dw}: fails {r['id']}: {r['msg']}")
            if d.get("blueprint") and d["blueprint"] not in bp_ids:
                err(f"{dw}: blueprint {d['blueprint']!r} does not exist")
            if d.get("example") and d["example"] not in examples:
                err(f"{dw}: example {d['example']!r} does not exist")

    for b in ds["bricks"]:
        if b["id"] not in used and not any(x.get("implements") == b["id"] for x in ds["bricks"]):
            err(f"brick {b['id']}: used by no value, blueprint or implementation")

    # Questions.
    unique(ds["questions"], "questions")
    for q in ds["questions"]:
        for i, ans in enumerate(q.get("answers", [])):
            where = f"question {q['id']} answer {i}"
            check_cond(ans.get("sets"), where)
            if ans.get("blueprint") and ans["blueprint"] not in bp_ids:
                err(f"{where}: blueprint {ans['blueprint']!r} does not exist")

    # Every decision axis is set by at least one design question.
    asked = {a for q in ds["questions"] for ans in q.get("answers", []) for a in (ans.get("sets") or {})}
    for a in ds["compatibility"].get("decisionAxes", []):
        if a not in asked:
            err(f"axis {a}: a decision axis that no question's answer sets")

    # Compatibility rules: every constraint in exactly one rule; links resolve.
    comp = ds["compatibility"]
    for a in comp.get("decisionAxes", []):
        if a not in axes:
            err(f"compatibility: decision axis {a!r} is not an axis")
    unique(comp.get("rules", []), "compatibility rules")
    owner = {}
    cids = {c["id"]: c for c in constraints}
    for r in comp.get("rules", []):
        where = f"compatibility rule {r.get('id')}"
        if r.get("scope") not in ("permutation", "namespace"):
            err(f"{where}: scope must be permutation or namespace")
        if r.get("level") not in ("error", "warn"):
            err(f"{where}: level must be error or warn")
        for f in ("label", "enforcedBy", "link", "text"):
            if not r.get(f):
                err(f"{where}: missing {f}")
        for cid in r.get("constraints", []):
            if cid not in cids:
                err(f"{where}: constraint {cid!r} does not exist")
            elif cid in owner:
                err(f"{where}: constraint {cid!r} already belongs to rule {owner[cid]!r}")
            else:
                owner[cid] = r["id"]
                if cids[cid]["level"] != r.get("level"):
                    err(f"{where}: constraint {cid!r} is {cids[cid]['level']}, the rule {r.get('level')}")
        if r.get("scope") == "namespace" and r.get("constraints"):
            err(f"{where}: a namespace rule covers no permutation constraint")
        link_problem = check_link(r.get("link", ""))
        if link_problem:
            err(f"{where}: {link_problem}")
    for cid in cids:
        if cid not in owner:
            err(f"constraint {cid}: belongs to no compatibility rule")

    # Reserved names: each is named by every file said to rely on it, and
    # the list is pss-client's RESERVED_NAMES, entry for entry.
    unique(ds["reservedNames"]["items"], "reservedNames")
    client = reserved_names_of_client()
    if client is None:
        err(f"reservedNames: {RESERVED_SOURCE} has no RESERVED_NAMES list")
    else:
        listed = {(it.get("name"), it.get("kind")) for it in ds["reservedNames"]["items"]}
        for name, kind in sorted(client - listed):
            err(f"reservedNames: {RESERVED_SOURCE} reserves {name!r} ({kind}), which design-space.json does not list with that kind")
        for name, kind in sorted(listed - client):
            err(f"reservedNames: {name!r} ({kind}) is not in {RESERVED_SOURCE}'s RESERVED_NAMES")
    for it in ds["reservedNames"]["items"]:
        where = f"reservedNames {it.get('id')}"
        for f in RESERVED_COLUMNS:
            if not it.get(f[0]):
                err(f"{where}: missing {f[0]}")
        for rel in it.get("where", []):
            text = file_text(rel)
            if text is None:
                err(f"{where}: no such file {rel!r}")
            elif it.get("name") and it["name"] not in text:
                err(f"{where}: {rel} does not name {it['name']!r}")

    # Leakage and parties tables.
    for row in ds["leakage"]:
        if row.get("intake") not in axes["intake"]:
            err(f"leakage {row.get('id')}: intake {row.get('intake')!r} is not an intake")
        for f in LEAKAGE_COLUMNS:
            if not row.get(f[0]):
                err(f"leakage {row.get('id')}: missing {f[0]}")
    unique(ds["parties"], "parties")
    for row in ds["parties"]:
        for f in PARTY_COLUMNS:
            if not row.get(f[0]):
                err(f"parties {row.get('id')}: missing {f[0]}")

    # The design space is the current spec: no plan ids and no dated log in it.
    def no_history(o, where):
        if isinstance(o, dict):
            for k, v in o.items():
                if k in ("tasks", "date"):
                    err(f"{where}: {k!r} is not a design-space field (DECISIONS.md holds that)")
                no_history(v, f"{where}.{k}")
        elif isinstance(o, list):
            for n, v in enumerate(o):
                no_history(v, f"{where}[{v.get('id', n) if isinstance(v, dict) else n}]")
    no_history(ds, "design space")

    for key in ("properties", "parameters", "devDecisionClasses"):
        unique(ds.get(key, []), key)
        for it in ds.get(key, []):
            if "status" in it:
                check_status(it["status"], f"{key} {it['id']}")
    return errs


LEAKAGE_COLUMNS = [("inputs", "Inputs in the clear"), ("requester", "Requester"),
                   ("onChain", "On chain"), ("state", "State in the clear"),
                   ("outcome", "Outcome in the clear"),
                   ("funds", "Funds at risk if all three nodes leak"),
                   ("worth", "What the nodes' knowledge is worth")]
# The one list of reserved names: pss-client's RESERVED_NAMES, whose
# entries read `<role>: { name: "<name>", kind: "<kind>" }`.
RESERVED_SOURCE = "ts/pss-client/src/bricks.ts"
RESERVED_ENTRY = re.compile(r'^\s*\w+: \{ name: "([^"]+)", kind: "([^"]+)" \},$')


def reserved_names_of_client():
    """The (name, kind) pairs of pss-client's RESERVED_NAMES, or None when the
    file has no such list."""
    text = file_text(RESERVED_SOURCE)
    if text is None:
        return None
    m = re.search(r"^export const RESERVED_NAMES = \{\n(.*?)^\} as const", text, re.M | re.S)
    if not m:
        return None
    pairs = set()
    for line in m.group(1).splitlines():
        e = RESERVED_ENTRY.match(line)
        if not e:
            return None
        pairs.add((e.group(1), e.group(2)))
    return pairs


RESERVED_COLUMNS = [("name", "Name"), ("kind", "Kind"), ("when", "When"),
                    ("must", "What the app must do"), ("by", "Relied on by")]
PARTY_COLUMNS = [("party", "Party"), ("sees", "Sees, under the recommended design"),
                 ("interim", "Adds under a deviation"),
                 ("funds", "Can do to funds"), ("worth", "What its knowledge is worth")]


def slug(text):
    """A Markdown heading's anchor as GitHub forms it (check-docs-links.py's rule)."""
    text = re.sub(r"(`+)(.+?)\1", lambda c: c.group(2), text)
    text = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", text)
    return re.sub(r"[^\w\- ]", "", text.strip().lower()).replace(" ", "-")


def check_link(link):
    """None when a repository link (path or path#anchor) resolves, else the problem."""
    target, _, frag = link.partition("#")
    path = ROOT / target
    if not target or not path.exists():
        return f"link {link!r}: no such file"
    if frag and path.suffix == ".md":
        found, seen = set(), {}
        fence = False
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.lstrip().startswith(("```", "~~~")):
                fence = not fence
                continue
            m = re.match(r"^#{1,6}\s+(.*?)\s*#*\s*$", line)
            if m and not fence:
                s = slug(m.group(1))
                k = seen.get(s, 0)
                seen[s] = k + 1
                found.add(s if k == 0 else f"{s}-{k}")
        if frag not in found:
            return f"link {link!r}: no such heading"
    return None


def compatibility(ds):
    """Derive pairwise compatibility from the error and warn constraints.

    Enumerates every permutation of the axes. A pair of values (on two axes) is
    forbidden when no permutation free of error constraints contains it; its reason
    is the union of the error constraints of the permutations containing it with the
    fewest failures. A pair warns when every valid permutation containing it fires a
    warn constraint that neither value fires on its own. Returns (never, single,
    forbidden, warned): the values no valid permutation contains, each value's own
    warnings, {pair: rule ids} and {pair: rule ids}, a pair being
    ((axis, value), (axis, value)) in axis order."""
    axes = [(a["id"], [v["id"] for v in a["values"]]) for a in ds["axes"]]
    errs = [r for r in ds["constraints"] if r["level"] == "error"]
    warns = [r for r in ds["constraints"] if r["level"] == "warn"]
    ids = [a for a, _ in axes]
    best, valid, wall, single, swarn = {}, set(), {}, set(), {}
    for combo in itertools.product(*[v for _, v in axes]):
        sel = dict(zip(ids, combo))
        fails = frozenset(r["id"] for r in errs if match(r.get("if"), sel) and not match(r.get("require"), sel))
        ws = frozenset(r["id"] for r in warns if match(r.get("if"), sel) and not match(r.get("require"), sel))
        items = list(sel.items())
        if not fails:
            for x in items:
                single.add(x)
                swarn[x] = swarn.get(x, ws) & ws
        for p in itertools.combinations(items, 2):
            if not fails:
                valid.add(p)
                wall[p] = wall.get(p, ws) & ws
            else:
                b = best.get(p)
                if b is None or len(fails) < b[0]:
                    best[p] = (len(fails), set(fails))
                elif len(fails) == b[0]:
                    b[1].update(fails)
    never = [(a, v) for a, vals in axes for v in vals if (a, v) not in single]
    forbidden = {p: sorted(b[1]) for p, b in best.items()
                 if p not in valid and p[0] in single and p[1] in single}
    warned = {}
    for p, w in wall.items():
        extra = w - swarn.get(p[0], frozenset()) - swarn.get(p[1], frozenset())
        if extra:
            warned[p] = sorted(extra)
    return never, {x: sorted(w) for x, w in swarn.items() if w}, forbidden, warned


def cell(text):
    return str(text).replace("|", "\\|").replace("\n", " ").replace("<", "&lt;").replace(">", "&gt;")


def render_blocks(ds):
    """The design guide's generated blocks, by id."""
    axes = {a["id"]: a for a in ds["axes"]}
    vlabel = {a["id"]: {v["id"]: v["label"] for v in a["values"]} for a in ds["axes"]}
    rule_of = {c: r for r in ds["compatibility"]["rules"] for c in r["constraints"]}
    out = {}

    rows = ["| Intake | " + " | ".join(h for _, h in LEAKAGE_COLUMNS) + " |",
            "| --- " * (len(LEAKAGE_COLUMNS) + 1) + "|"]
    for r in ds["leakage"]:
        rows.append("| " + cell(vlabel["intake"][r["intake"]]) + " | "
                    + " | ".join(cell(r[k]) for k, _ in LEAKAGE_COLUMNS) + " |")
    out["leakage"] = "\n".join(rows)

    rows = ["| " + " | ".join(h for _, h in PARTY_COLUMNS) + " |", "| --- " * len(PARTY_COLUMNS) + "|"]
    for r in ds["parties"]:
        rows.append("| " + " | ".join(cell(r[k]) for k, _ in PARTY_COLUMNS) + " |")
    out["parties"] = "\n".join(rows)

    rows = ["| " + " | ".join(h for _, h in RESERVED_COLUMNS) + " |", "| --- " * len(RESERVED_COLUMNS) + "|"]
    for r in ds["reservedNames"]["items"]:
        rows.append(f"| `{cell(r['name'])}` | " + " | ".join(cell(r[k]) for k, _ in RESERVED_COLUMNS[1:]) + " |")
    out["reserved-names"] = "\n".join(rows)

    expath = {e["id"]: e["path"] for e in ds["examples"]}
    groups = [("Path, state, shape", ("path", "state", "shape")), ("Intake", ("intake",)),
              ("Outputs, value, delivery", ("outputs", "value", "delivery")),
              ("Submission", ("submission",)), ("Node keys, upgrades", ("node_keys", "upgrades"))]
    rows = ["| Blueprint | " + " | ".join(h for h, _ in groups) + " | Example | Status |",
            "| --- " * (len(groups) + 3) + "|"]
    for bp in ds["blueprints"]:
        ex = bp["example"].get("id")
        rows.append(f"| `{bp['id']}` {cell(bp['label'])} | "
                    + " | ".join(", ".join(f"`{bp['values'][a]}`" for a in axs) for _, axs in groups)
                    + f" | {'`' + expath[ex] + '`' if ex else 'none'} | {status_label(ds, bp['status'])} |")
    out["blueprints"] = "\n".join(rows)

    rows = ["| Rule | Scope | Level | Forbids or warns | Enforced by | Constraints | Stated in |",
            "| --- | --- | --- | --- | --- | --- | --- |"]
    for r in ds["compatibility"]["rules"]:
        target = r["link"]
        rel = target[len("docs/design-guide/"):] if target.startswith("docs/design-guide/") else "../" + target[len("docs/"):]
        rows.append(f"| `{r['id']}` {cell(r['label'])} | {r['scope']} | {r['level']} | {cell(r['text'])} | "
                    f"{cell(r['enforcedBy'])} | {', '.join('`' + c + '`' for c in r['constraints']) or '—'} | "
                    f"[{cell(target.split('/')[-1])}]({rel}) |")
    out["compat-rules"] = "\n".join(rows)

    never, single, forbidden, warned = compatibility(ds)
    dec = ds["compatibility"]["decisionAxes"]
    cols = [(a, v["id"]) for a in dec for v in axes[a]["values"]]

    def key(x, y):
        order = [a["id"] for a in ds["axes"]]
        return (x, y) if order.index(x[0]) < order.index(y[0]) else (y, x)

    head = "| | " + " | ".join(f"`{v}`" for _, v in cols) + " |"
    rows = [head, "| --- " * (len(cols) + 1) + "|"]
    for a in dec:
        for v in axes[a]["values"]:
            x = (a, v["id"])
            cells = []
            for y in cols:
                if y[0] == a:
                    cells.append(" ")
                elif x in never or y in never:
                    cells.append("✗")
                else:
                    p = key(x, y)
                    cells.append("✗" if p in forbidden else "!" if p in warned else "·")
            rows.append(f"| {axes[a]['label'].lower()} `{v['id']}` | " + " | ".join(cells) + " |")
    grid = "\n".join(rows)

    def rules_text(ids):
        named = []
        for cid in ids:
            rid = rule_of[cid]["id"]
            if rid not in named:
                named.append(rid)
        return ", ".join(f"`{rid}`" for rid in named)

    lines = []
    groups = {}
    for p, ids in forbidden.items():
        if p[0][0] in dec and p[1][0] in dec:
            groups.setdefault((p[0], p[1][0], rules_text(ids)), []).append(p[1][1])
    order = [a["id"] for a in ds["axes"]]
    for (x, ax, why), vals in sorted(groups.items(), key=lambda g: (order.index(g[0][0][0]),
                                     [v["id"] for v in axes[g[0][0][0]]["values"]].index(g[0][0][1]),
                                     order.index(g[0][1]))):
        names = ", ".join(vlabel[ax][v] for v in vals)
        lines.append(f"- {axes[x[0]]['label'].lower()} **{vlabel[x[0]][x[1]]}** never with {axes[ax]['label'].lower()} "
                     f"{names}: {why}.")
    wl = []
    for p, ids in sorted(warned.items(), key=lambda q: (order.index(q[0][0][0]), order.index(q[0][1][0]))):
        if p[0][0] in dec and p[1][0] in dec:
            wl.append(f"- {axes[p[0][0]]['label'].lower()} **{vlabel[p[0][0]][p[0][1]]}** with "
                      f"{axes[p[1][0]]['label'].lower()} **{vlabel[p[1][0]][p[1][1]]}**: {rules_text(ids)}.")
    sl = [f"- {axes[a]['label'].lower()} **{vlabel[a][v]}**: {rules_text(ids)}."
          for (a, v), ids in sorted(single.items(), key=lambda q: (order.index(q[0][0]),
                                    [x["id"] for x in axes[q[0][0]]["values"]].index(q[0][1])))]
    nv = [f"- {axes[a]['label'].lower()} **{vlabel[a][v]}**: in no valid permutation." for a, v in never]
    out["compat-pairs"] = "\n".join(
        [grid, "", "`·` combines, `!` combines with a warning, `✗` never combines. The forbidden pairs, with the rules that forbid them:", ""]
        + lines + ["", "The pairs that combine with a warning:", ""] + wl
        + ["", "The values that warn on their own, whatever they are paired with:", ""] + sl
        + ([""] + nv if nv else []))
    return out


def readme_problems(ds, text):
    want = render_blocks(ds)
    found = {m.group("id"): m.group("body") for m in GENERATED.finditer(text)}
    probs = []
    for bid, body in want.items():
        if bid not in found:
            probs.append(f"README.md: no generated block {bid!r}")
        elif found[bid] != body + "\n":
            probs.append(f"README.md: generated block {bid!r} differs; run python3 -I scripts/check-design-space.py --write-readme")
    for bid in found:
        if bid not in want:
            probs.append(f"README.md: unknown generated block {bid!r}")
    rows = choice_rows(text)
    for a in ds["axes"]:
        if a["label"].lower() not in rows:
            probs.append(f"README.md: \"Where each choice lives\" has no row {a['label'].lower()!r} for axis {a['id']}")
    return probs


def choice_rows(text):
    """The first cells of the guide's "Where each choice lives" table."""
    m = re.search(r"^## Where each choice lives\n(?P<body>.*?)(?=^## )", text, re.S | re.M)
    if not m:
        return set()
    return {line.split("|")[1].strip() for line in m.group("body").splitlines()
            if line.startswith("|") and not line.startswith("| ---")}


def write_readme(ds):
    want = render_blocks(ds)
    text = README.read_text()
    text = GENERATED.sub(lambda m: m.group(1) + want.get(m.group("id"), m.group("body").rstrip("\n")) + "\n" + m.group(4), text)
    README.write_text(text)


def value_brick_entries(value):
    """A value's bricks as (id, condition) pairs."""
    out = []
    for entry in value.get("bricks", []):
        if isinstance(entry, str):
            out.append((entry, None))
        else:
            out.append((entry.get("id"), entry.get("when")))
    return out


def needed(ds, sel):
    """The bricks a permutation needs: the core bricks plus each chosen value's."""
    axes = {a["id"]: {v["id"]: v for v in a["values"]} for a in ds["axes"]}
    need = set(ds["coreBricks"])
    for a, v in sel.items():
        if a in axes and v in axes[a]:
            for bid, when in value_brick_entries(axes[a][v]):
                if match(when, sel):
                    need.add(bid)
    return need


def as_example_rules(ex):
    """An example's rules apply only when that example is picked."""
    out = []
    for r in ex.get("rules", []):
        cond = dict(r.get("if") or {})
        cond["example"] = [ex["id"]]
        out.append(dict(r, **{"if": cond}))
    return out


# ---------------------------------------------------------------------------
# Bricks: the api of each brick, the BRICK markers, BRICKS.md and the examples'
# brick tables
# ---------------------------------------------------------------------------

_TEXTS = {}


def file_text(rel):
    """A repository file's text, or None when it is not a file."""
    if rel not in _TEXTS:
        p = ROOT / rel
        _TEXTS[rel] = p.read_text(encoding="utf-8") if p.is_file() else None
    return _TEXTS[rel]


def segments(symbol):
    return [s for s in re.split(r"::|\.", symbol) if s]


def defines(text, name, ts, member=False, owner=False):
    """Whether a source text defines `name` (a function, type, trait, global or
    export; a method or member when `member`; also an `impl` block's type when
    `owner`)."""
    n = re.escape(name)
    if ts:
        pats = [rf"\bexport\s+(?:declare\s+)?(?:abstract\s+)?(?:async\s+)?(?:function\*?|class|interface|type|const|let|enum)\s+{n}\b",
                rf"\bexport\s*\{{[^}}]*\b{n}\b[^}}]*\}}"]
        if member:
            pats.append(rf"^\s+(?:(?:public|private|protected|static|readonly)\s+)*(?:async\s+)?{n}\s*[<(:]")
    else:
        pats = [rf"\b(?:fn|struct|trait|type|global|enum|mod|const|static)\s+{n}\b",
                rf"\bpub\s+use\s+[^;]*\b{n}\b[^;]*;"]  # a re-export
        if owner:
            pats.append(rf"^\s*impl\b[^{{\n]*\b{n}\b")
    return any(re.search(p, text, re.M) for p in pats)


def symbol_problem(symbol, rel):
    """None when `symbol` is defined in the file `rel`, else the problem.

    The last segment must be defined there; a capitalised segment before it (a
    type, trait or class) must be defined there too, and a lower-case one (a
    crate or module) must name a directory or the file's stem on its path."""
    text = file_text(rel)
    if text is None:
        return f"no such file {rel!r}"
    ts = rel.endswith((".ts", ".mts"))
    segs = segments(symbol)
    if not segs:
        return "empty symbol"
    parts = pathlib.PurePosixPath(rel)
    names = set(parts.parts[:-1]) | {parts.stem}
    for s in segs[:-1]:
        if s[0].isupper():
            if not defines(text, s, ts, owner=True):
                return f"{s!r} is not defined in {rel}"
        elif s not in names:
            return f"module {s!r} is not on the path {rel}"
    qualified = len(segs) > 1 and segs[-2][0].isupper()
    if not defines(text, segs[-1], ts, member=qualified):
        return f"{segs[-1]!r} is not defined in {rel}"
    return None


def api_problems(b):
    api = b.get("api")
    if not isinstance(api, dict):
        return ["no api: list the library items an app calls, or say it is internal"]
    probs = []
    unknown = sorted(set(api) - set(API_KEYS) - {"note", "internal"})
    if unknown:
        probs.append(f"api: unknown keys {', '.join(unknown)}")
    listed = [k for k in API_KEYS if api.get(k)]
    if "internal" in api:
        if not isinstance(api["internal"], str) or not api["internal"]:
            probs.append("api: internal must say why an app does not call it")
        if listed:
            probs.append("api: internal, yet it lists items")
    elif not listed:
        probs.append("api: lists no item and is not internal")
    for k in API_KEYS:
        v = api.get(k, [])
        if not isinstance(v, list):
            probs.append(f"api {k}: must be a list")
            continue
        for it in v:
            if not isinstance(it, dict) or set(it) != {"symbol", "path"}:
                probs.append(f"api {k}: an item is {{symbol, path}}, not {it!r}")
                continue
            p = symbol_problem(it["symbol"], it["path"])
            if p:
                probs.append(f"api {k} {it['symbol']}: {p}")
    return probs


def api_symbols(brick):
    api = brick.get("api") or {}
    return {it["symbol"] for k in API_KEYS for it in api.get(k, [])}


def value_bricks_any(value):
    """Every brick a value can need, whatever its conditions."""
    return [bid for bid, _ in value_brick_entries(value)]


def sentences(text, n=1):
    """The first n sentences of a text (a period followed by a space or the end,
    outside parentheses)."""
    out, depth, start = [], 0, 0
    for i, ch in enumerate(text):
        if ch in "([":
            depth += 1
        elif ch in ")]":
            depth = max(0, depth - 1)
        elif ch == "." and depth == 0 and (i + 1 == len(text) or text[i + 1] == " "):
            if text[max(0, i - 3):i + 1] in ("e.g.", "i.e."):
                continue
            out.append(text[start:i + 1].strip())
            start = i + 1
            if len(out) == n:
                return " ".join(out)
    rest = text[start:].strip()
    return " ".join(out + ([rest] if rest else []))


def clause(text, limit=180):
    """A long sentence cut at its first semicolon (or, past its opening words,
    colon) outside parentheses."""
    if len(text) <= limit:
        return text
    depth = 0
    for i, ch in enumerate(text):
        if ch in "([":
            depth += 1
        elif ch in ")]":
            depth = max(0, depth - 1)
        elif depth == 0 and (ch == ";" or (ch == ":" and i > 60)):
            return text[:i] + "."
    t = text.rstrip(".")
    if t.endswith(")"):
        depth = 0
        for i in range(len(t) - 1, -1, -1):
            depth += {")": 1, "(": -1}.get(t[i], 0)
            if depth == 0:
                return t[:i].rstrip() + "." if i > 40 else text
    return text


def summary(text):
    """One sentence, or two when the first is too short to say what a thing is."""
    first = sentences(text, 1)
    return sentences(text, 2) if len(first) < 60 else first


# BRICK markers. A marker sits only where another option could have been
# chosen. It is one comment line and the comment lines after it up to the one
# that carries the BRICKS.md link (at most four lines):
#   // BRICK <axis> = <value>[, <value>] (<symbol>)[ ...]. Alternatives: <value>, ... docs/design-guide/BRICKS.md#<axis>
#   // BRICK <axis> = <value>[, <value>]: <text naming the manifest field that picks it>. Alternatives: ... docs/...
#   // BRICK <brick id> (<symbol>). No alternative; <when an app leaves it out>. docs/design-guide/BRICKS.md#other-bricks
# The last form is for a brick in no axis option (BRICKS.md "Other bricks");
# a brick every path has is never marked.
MARKER = re.compile(r"^\s*// BRICK (?P<text>.*?)\s*$")
MARKER_HEAD = re.compile(r"^(?P<what>[a-z][a-z_-]*)(?:\s*=\s*(?P<vals>[a-z_]+(?:\s*,\s*[a-z_]+)*))?(?:\s*\((?P<sym>[^()\s]+)\))?(?P<rest>.*)$")
MARKER_LINK = re.compile(r"docs/design-guide/BRICKS\.md#(?P<anchor>[\w-]+)")
MARKER_ALTS = re.compile(r"Alternatives:\s*(?P<list>[^.]*)")
MARKER_NONE = "No alternative"
MARKER_LINES = 4
COMMENT = re.compile(r"^\s*//\s?(?P<text>.*?)\s*$")
FN_DECL = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:unconstrained\s+)?(?:comptime\s+)?fn\s+(?P<name>\w+)")
ITEM_DECL = re.compile(r"^\s*(?:pub\s+)?(?:struct|type|global|trait)\s+(?P<name>\w+)|^\s*(?P<field>\w+)\s*:(?!:)")
IMPL_DECL = re.compile(r"^\s*impl\b(?:<[^>]*>)?\s+(?:(?P<trait>\w+)(?:<[^>]*>)?\s+for\s+)?(?P<type>\w+)")
MARKER_REACH = 12  # the symbol must appear within this many code lines after the marker


def code_after(lines, end):
    """The code lines after line `end`: comments and blank lines skipped."""
    return [line for line in lines[end + 1:] if line.strip() and not COMMENT.match(line)]


def marker_name(lines, end):
    """Where a marker sits: the item declared right below it, or the function
    it is inside."""
    for line in [c for c in code_after(lines, end) if not c.lstrip().startswith("#[")][:1]:
        i = IMPL_DECL.match(line)
        if i:
            return f"{i.group('trait')} for {i.group('type')}" if i.group("trait") else i.group("type")
        m = FN_DECL.match(line) or ITEM_DECL.match(line)
        if m:
            return m.group("name") or m.group("field")
    for line in reversed(lines[:end]):
        m = FN_DECL.match(line)
        if m:
            return m.group("name")
    return None


def scan_markers():
    """Every BRICK marker under examples/, by example directory name:
    {example: [marker]} with each marker a dict."""
    found = {}
    for exdir in sorted(p for p in EXAMPLES.iterdir() if p.is_dir()):
        out = found.setdefault(exdir.name, [])
        files = sorted(p for suf in (".nr", ".ts", ".rs") for p in exdir.rglob("*" + suf)
                       if not {"target", "node_modules"} & set(p.relative_to(exdir).parts))
        for f in files:
            lines = f.read_text(encoding="utf-8").splitlines()
            for i, line in enumerate(lines):
                m = MARKER.match(line)
                if not m:
                    continue
                text, end = m.group("text"), i
                while not MARKER_LINK.search(text) and end + 1 < min(len(lines), i + MARKER_LINES):
                    c = COMMENT.match(lines[end + 1])
                    if not c or MARKER.match(lines[end + 1]):
                        break
                    text, end = text + " " + c.group("text"), end + 1
                out.append({"example": exdir.name, "file": f.relative_to(exdir).as_posix(), "line": i + 1,
                            "text": text, "name": marker_name(lines, end),
                            "below": "\n".join(code_after(lines, end)[:MARKER_REACH])})
    return found


def parse_marker(ds, mk):
    """Fill a marker's axis or brick, values, symbol and alternatives; return its problems."""
    axes = {a["id"]: {v["id"]: v for v in a["values"]} for a in ds["axes"]}
    axis_of = {a["id"]: a for a in ds["axes"]}
    bricks = {b["id"]: b for b in ds["bricks"]}
    h = MARKER_HEAD.match(mk["text"])
    if not h:
        return ["not of the form 'BRICK <axis> = <value> (<symbol>)' or 'BRICK <brick id> (<symbol>)'"]
    what, sym, rest = h.group("what"), h.group("sym"), h.group("rest")
    vals = [v.strip() for v in h.group("vals").split(",")] if h.group("vals") else []
    mk.update(what=what, values=vals, symbol=sym, others=None, anchor=None)
    probs = []
    alts = MARKER_ALTS.search(rest)
    if what in axes:
        mk["kind"] = "axis"
        if not vals:
            probs.append(f"axis {what}: name the value(s) plugged in here ('{what} = <value>')")
        field = axis_of[what].get("manifestField")
        if sym is None and not (field and "manifest" in rest):
            probs.append(f"name the library item in parentheses, or the manifest field that picks the option")
        for v in vals:
            if v not in axes[what]:
                probs.append(f"axis {what} has no value {v!r}")
                continue
            if sym and not any(sym in api_symbols(bricks[b]) for b in value_bricks_any(axes[what][v]) if b in bricks):
                probs.append(f"{sym} is in the api of no brick of {what} {v}")
        words = []
        if alts:
            words = [w.strip().split(" ")[0] for w in re.sub(r"\([^)]*\)", "", alts.group("list")).split(",")]
            words = [w for w in words if w]
        mk["others"] = words
        if not words:
            probs.append("names no alternatives ('Alternatives: <value>, ...'): a marker sits only where another option could be chosen")
        for w in words:
            if w not in axes[what]:
                probs.append(f"alternative {w!r} is not a value of {what}")
            elif w in vals:
                probs.append(f"alternative {w!r} is the value plugged in here")
    elif what in bricks:
        mk["kind"] = "brick"
        if vals:
            probs.append(f"{what} is a brick, not an axis: no '= value'")
        if brick_anchor(ds, what) != "other-bricks":
            probs.append(f"{what} is always present or chosen at an axis: mark the axis option ('<axis> = <value>'), never an always-present brick")
        if sym is None:
            probs.append("name the library item in parentheses")
        elif sym not in api_symbols(bricks[what]):
            probs.append(f"{sym} is not in the api of brick {what}")
        if alts or MARKER_NONE not in rest:
            probs.append(f"a marker of a brick in no axis says '{MARKER_NONE}' and when an app leaves it out")
    else:
        return [f"{what!r} is neither an axis nor a brick"]
    link = MARKER_LINK.search(mk["text"])
    if not link:
        probs.append(f"no docs/design-guide/BRICKS.md link within {MARKER_LINES} comment lines")
    else:
        mk["anchor"] = link.group("anchor")
        ok = {what} | {f"{what}-{v}" for v in vals} if mk["kind"] == "axis" else {brick_anchor(ds, what)}
        if mk["anchor"] not in ok:
            probs.append(f"link #{mk['anchor']}: expected #{sorted(ok)[0]}")
    if sym:
        last = segments(sym)[-1]
        if not re.search(rf"\b{re.escape(last)}\b", mk["below"]):
            probs.append(f"{last!r} is not used within {MARKER_REACH} code lines below the marker")
    return probs


def marker_problems(ds, found):
    probs = []
    for ex, mks in found.items():
        for mk in mks:
            for p in parse_marker(ds, mk):
                probs.append(f"examples/{ex}/{mk['file']}:{mk['line']}: BRICK marker: {p}")
    return probs


def brick_anchor(ds, bid):
    """The BRICKS.md section that lists a brick."""
    if bid in ds["coreBricks"]:
        return "always-present"
    for a in ds["axes"]:
        for v in a["values"]:
            if bid in value_bricks_any(v):
                return f"{a['id']}-{v['id']}"
    return "other-bricks"


def status_label(ds, st):
    return "/".join(ds["statuses"][s]["label"] for s in as_list(st))


def render_brick(ds, b, rel, indent=""):
    """One brick of BRICKS.md: name, id, status, what it does, and its api by
    location, each item linked to its file (`rel`: the path from the page to the
    repository root)."""
    api = b.get("api") or {}
    head = f"{indent}- **{b['name']}** (`{b['id']}`, {status_label(ds, b['status'])}"
    if b.get("implements"):
        head += f", implements `{b['implements']}`"
    plain = api.get("internal") == INTERNAL
    if plain:
        head += ", *internal*"
    out = [head + f"): {clause(sentences(b['does'], 1))}"]
    if "internal" in api and not plain:
        out.append(f"{indent}  - *internal:* {api['internal']}.")
    for k in API_KEYS:
        if api.get(k):
            out.append(f"{indent}  - {k}: " + ", ".join(f"[`{it['symbol']}`]({rel}{it['path']})" for it in api[k]))
    if api.get("note"):
        out.append(f"{indent}  - *note:* {api['note']}.")
    return out


def choose_when(ds, axis, value):
    """The design questions' answers that pick this value (those that pick it
    alone first)."""
    hits = []
    for q in ds["questions"]:
        for ans in q.get("answers", []):
            sets = ans.get("sets") or {}
            picks = sets.get(axis, [])
            if value in picks:
                hits.append(((len(picks), len(sets)), f"*{q['ask']}* {clause(sentences(ans['answer'], 1), 200)}"))
    hits.sort(key=lambda h: h[0])
    return hits[0][1] if hits else None


def render_bricks_md(ds):
    """docs/design-guide/BRICKS.md, the generated brick reference."""
    rel = "../../"
    axes = {a["id"]: a for a in ds["axes"]}
    bricks = {b["id"]: b for b in ds["bricks"]}
    never, single, forbidden, warned = compatibility(ds)
    rule_label = {c: r["label"] for r in ds["compatibility"]["rules"] for c in r["constraints"]}
    dec = set(ds["compatibility"]["decisionAxes"])
    L = ["# Bricks", "",
         "<!-- Generated by python3 -I scripts/check-design-space.py --write-bricks from design-space.json: edit the JSON, not this page. -->",
         "",
         "What exists and what you call. A brick is one library module with one job. At each axis below an app picks "
         "one option, and each option is a set of bricks. The shape of your contract, circuits and client is yours, "
         "but for the names the library and the client rely on ([README](README.md#reserved-names), \"Reserved names\"); "
         "what is fixed is which library items of which brick you call. Any option of one axis combines with any "
         "option of another unless its \"Never with\" line says otherwise. Every example's combination is one choice "
         "among the options listed here.",
         "",
         "Each brick lists the library items an app calls, by where it calls them:", ""]
    L += [f"- **{k}**: {d};" if i < len(API_PLACES) - 1 else f"- **{k}**: {d}." for i, (k, d) in enumerate(API_PLACES)]
    L += ["",
          "A brick marked *internal* is machine or library plumbing behind those items: an app does not call it. "
          "Each example's README has a \"Bricks this example uses\" table, and in its code a `// BRICK` comment "
          "marks each seam where another option could have been chosen and names the alternatives there "
          "([README](README.md#brick-markers), \"BRICK markers\"). "
          "`python3 -I scripts/check-design-space.py --plan <axis>=<value> ...` checks any combination and prints "
          "its bricks and what to call.",
          "",
          "Statuses: " + "; ".join(f"*{s['label']}*: {s['desc'][0].lower() + s['desc'][1:].rstrip('.')}"
                                   for s in ds["statuses"].values()) + ".",
          "",
          "Sections: [Always present](#always-present), "
          + ", ".join(f"[{a['id']}](#{a['id']})" for a in ds["axes"]) + ", [Other bricks](#other-bricks), "
          "[Common items](#common-items).",
          "", "## Always present", "",
          "On every path, whatever the options.", ""]
    for bid in ds["coreBricks"]:
        L += render_brick(ds, bricks[bid], rel)
    in_values = set(ds["coreBricks"])
    for a in ds["axes"]:
        follows = (f"Follows from `{a['derivedFrom']}`; not chosen on its own." if a.get("derivedFrom")
                   else "Follows from the other choices; not chosen on its own." if a["id"] not in dec else "")
        field = f" Manifest field `{a['manifestField']}`." if a.get("manifestField") else ""
        # a human heading; an id the heading's own anchor would not keep (node_keys)
        # gets an explicit one, which the `// BRICK` markers and the links name
        heading = a["id"].replace("_", " ").capitalize()
        anchor = [] if heading.lower() == a["id"] else [f'<a id="{a["id"]}"></a>', ""]
        L += ["", *anchor, f"## {heading}", "",
              f"*{a['label']}.* {a['question']}{field} Default `{a['default']}`. {follows}".rstrip()]
        for v in a["values"]:
            x = (a["id"], v["id"])
            others = [w["id"] for w in a["values"] if w["id"] != v["id"]]
            default = "; the default" if v["id"] == a["default"] else ""
            L += ["", f"### {a['id']}: {v['id']}", "",
                  f"**{v['label']}** ({status_label(ds, v['status'])}{default}). {summary(v['note'])}", ""]
            when = choose_when(ds, a["id"], v["id"])
            if when:
                L.append(f"- **Choose it when:** {when}")
            elif v.get("pros"):
                L.append(f"- **Gains:** {v['pros'][0]}.")
            L.append("- **Alternatives:** " + ", ".join(f"[`{w}`](#{a['id']}-{w})" for w in others))
            if x in never:
                L.append("- **Never with:** anything; no valid combination contains it.")
            else:
                partners = {}
                for p in forbidden:
                    if x in p:
                        y = p[1] if p[0] == x else p[0]
                        partners.setdefault(y[0], []).append(y[1])
                if partners:
                    order = [b["id"] for b in ds["axes"]]
                    L.append("- **Never with:** " + "; ".join(
                        f"{ax} " + ", ".join(f"`{w}`" for w in sorted(ws, key=[u["id"] for u in axes[ax]["values"]].index))
                        for ax, ws in sorted(partners.items(), key=lambda kv: order.index(kv[0]))) + ".")
                alone = list(dict.fromkeys(rule_label[c] for c in single.get(x, [])))
                paired = {}
                for p in sorted(warned, key=lambda p: [b["id"] for b in ds["axes"]].index((p[1] if p[0] == x else p[0])[0])):
                    if x in p:
                        y = p[1] if p[0] == x else p[0]
                        for c in warned[p]:
                            paired.setdefault(rule_label[c], []).append(f"{y[0]} `{y[1]}`")
                warns = [lab + (f" (also with {', '.join(paired[lab])})" if lab in paired else "") for lab in alone]
                warns += [f"{lab} (with {', '.join(ys)})" for lab, ys in paired.items() if lab not in alone]
                if warns:
                    L.append("- **Warns:** " + "; ".join(warns) + ".")
            entries = value_brick_entries(v)
            if not entries:
                L.append("- **Bricks:** none of its own.")
                continue
            L.append("- **Bricks:**")
            for bid, cond in entries:
                in_values.add(bid)
                lines = render_brick(ds, bricks[bid], rel, "  ")
                if cond:
                    lines[0] += " *Only when " + "; ".join(f"{k} = {', '.join(vs)}" for k, vs in cond.items()) + ".*"
                L += lines
    L += ["", "## Other bricks", "",
          "In no axis option: an app adds them when it needs them (the blueprints that list them say where they are used).", ""]
    for b in ds["bricks"]:
        if b["id"] in in_values:
            continue
        lines = render_brick(ds, b, rel)
        used = [bp["id"] for bp in ds["blueprints"] if b["id"] in bp.get("bricks", [])]
        impl = [x["id"] for x in ds["bricks"] if x.get("implements") == b["id"]]
        tail = []
        if used:
            tail.append("in " + ", ".join(f"`{u}`" for u in used))
        if impl:
            tail.append("implemented by " + ", ".join(f"`{i}`" for i in impl))
        if tail:
            lines[0] += " *(" + "; ".join(tail) + ".)*"
        L += lines
    common = ds["apiCheck"]["common"]
    L += ["", "## Common items", "",
          f"Library items an app may call that belong to no one brick: {common['note']}.", ""]
    for k in API_KEYS:
        if common.get(k):
            L.append(f"- {k}: " + ", ".join(f"[`{it['symbol']}`]({rel}{it['path']})" for it in common[k]))
    L += ["",
          "An app builds with the items listed on this page: `check-design-space.py` fails when an example uses "
          "a library item no brick lists. The e2e driver is held to the client lists too, except for the "
          f"{len(ds['apiCheck']['harness']['client'])} names of its own harness (`design-space.json` `apiCheck.harness`)."]
    return "\n".join(L) + "\n"


def example_of(ds, exname):
    return next((e for e in ds["examples"] if e.get("path") == f"examples/{exname}"), None)


def render_example_block(ds, exname, mks):
    """The generated "Bricks this example uses" block of an example's README:
    one row per axis, from the example's BRICK markers and its as-built
    choice, then the bricks it has whatever it chooses (always present) and
    the bricks in no axis it adds (no alternative)."""
    B = "../../docs/design-guide/BRICKS.md"
    ex = example_of(ds, exname) or {}
    built = ex.get("asBuilt", {})
    bricks = {b["id"]: b for b in ds["bricks"]}

    def where(ms):
        files = {}
        for m in ms:
            names = files.setdefault(m["file"], [])
            if m["name"] and m["name"] not in names:
                names.append(m["name"])
        return "; ".join(f"[`{f}`]({f})" + (": " + ", ".join(f"`{n}`" for n in ns) if ns else "") for f, ns in files.items())

    def calls(ms, field=None):
        out = [f"`{s}`" for s in dict.fromkeys(m["symbol"] for m in ms if m["symbol"])]
        if field and any(not m["symbol"] for m in ms):
            out.append(f"the manifest's `{field}` field")
        return ", ".join(out)

    def link(bid):
        return f"[{bricks[bid]['name']}]({B}#{brick_anchor(ds, bid)})"

    L = ["## Bricks this example uses", "",
         "Generated from the `// BRICK` markers in this example's code and `docs/design-guide/design-space.json` "
         "(`python3 -I scripts/check-design-space.py --write-bricks`). One row per axis: the option this example "
         "plugs in, the library items it calls for it, where, and the alternatives. "
         "**Bold**: the example's as-built choice. The combination is this example's; any alternative "
         f"combines with the rest as [BRICKS.md]({B}) says.", "",
         "| Axis | This example uses | Library calls | Where in this example | Alternatives |",
         "| --- | --- | --- | --- | --- |"]
    for a in ds["axes"]:
        ms = [m for m in mks if m.get("kind") == "axis" and m["what"] == a["id"]]
        order = [v["id"] for v in a["values"]]
        vals = {v["id"]: v for v in a["values"]}
        used = sorted({v for m in ms for v in m["values"]}, key=order.index)
        if not used and a["id"] in built:
            used = [built[a["id"]]]
        cell = ", ".join((f"**[`{v}`]({B}#{a['id']}-{v})**" if built.get(a["id"]) == v else f"[`{v}`]({B}#{a['id']}-{v})")
                         for v in used) or "—"
        own = [bid for v in used for bid, when in value_brick_entries(vals[v]) if match(when, built)]
        if ms:
            c, w = calls(ms, a.get("manifestField")), where(ms)
        elif a.get("derivedFrom"):
            # the path's bricks are the "always present" row's
            called = [b for b in own if a["id"] != "path" and "internal" not in (bricks[b].get("api") or {})]
            c = (f"follows from `{a['derivedFrom']}`; not marked in this example's code" if called
                 else f"none: follows from `{a['derivedFrom']}`")
            w = "—"
        elif a.get("manifestField"):
            c, w = f"none: manifest only (`{a['manifestField']}`)", "—"
        elif not own:
            c, w = "none: no brick of its own here", "—"
        elif all("internal" in (bricks[b].get("api") or {}) for b in own):
            c, w = "none: an app calls nothing of it", "—"
        else:
            c, w = "none in this example's code", "—"
        rest = [v for v in order if v not in used]
        L.append(f"| [{a['id']}]({B}#{a['id']}) | {cell} | {c} | {w} | "
                 + (", ".join(f"[`{v}`]({B}#{a['id']}-{v})" for v in rest) or "—") + " |")
    marked = {m["what"] for m in mks if m.get("kind") == "brick"}
    sym_owner = {m["symbol"] for m in mks if m.get("symbol")}
    path_axis = next((a for a in ds["axes"] if a["id"] == "path"), None)
    always = list(ds["coreBricks"])
    if path_axis and built.get("path"):
        pv = next(v for v in path_axis["values"] if v["id"] == built["path"])
        always += [bid for bid, when in value_brick_entries(pv) if match(when, built)]
    others = {bid for a in ds["axes"] if a["id"] != "path" for v in a["values"] for bid in value_bricks_any(v)}
    always = [b for b in dict.fromkeys(always)
              if (bricks[b].get("api") or {}).get("internal") is None and b not in others
              and not (api_symbols(bricks[b]) & sym_owner)]
    if always:
        L.append(f"| always present | {', '.join(link(b) for b in always)} | on every {built.get('path', '')} path: "
                 f"[BRICKS.md]({B}#{brick_anchor(ds, always[-1])}) lists what to call | — | — |")
    ms = [m for m in mks if m.get("kind") == "brick"]
    if ms:
        names = ", ".join(link(b) for b in dict.fromkeys(m["what"] for m in ms))
        L.append(f"| no alternative | {names} | {calls(ms)} | {where(ms)} | — |")
    return "\n".join(L) + "\n"


def bricks_problems(ds, found):
    """BRICKS.md and every example README's bricks block against what this
    file renders."""
    probs = []
    want = render_bricks_md(ds)
    have = BRICKS_MD.read_text(encoding="utf-8") if BRICKS_MD.exists() else None
    if have != want:
        probs.append(f"{BRICKS_MD.relative_to(ROOT)}: differs from design-space.json; run python3 -I scripts/check-design-space.py --write-bricks")
    for ex, mks in found.items():
        readme = EXAMPLES / ex / "README.md"
        text = readme.read_text(encoding="utf-8") if readme.exists() else ""
        m = BRICKS_BLOCK.search(text)
        if mks and not m:
            probs.append(f"examples/{ex}/README.md: has BRICK markers but no <!-- bricks:begin --> block")
        elif m and m.group("body") != render_example_block(ds, ex, mks):
            probs.append(f"examples/{ex}/README.md: the bricks block differs; run python3 -I scripts/check-design-space.py --write-bricks")
    return probs


def write_bricks(ds, found):
    BRICKS_MD.write_text(render_bricks_md(ds), encoding="utf-8")
    print(f"{BRICKS_MD.relative_to(ROOT)}: written")
    for ex, mks in found.items():
        readme = EXAMPLES / ex / "README.md"
        if not readme.exists():
            continue
        text = readme.read_text(encoding="utf-8")
        if BRICKS_BLOCK.search(text):
            readme.write_text(BRICKS_BLOCK.sub(lambda m: m.group(1) + render_example_block(ds, ex, mks) + m.group(3), text), encoding="utf-8")
            print(f"examples/{ex}/README.md: bricks block written ({len(mks)} markers)")


def plan_choices(ds, args):
    """Check an arbitrary choice (`axis=value` pairs; unspecified decision axes
    take their defaults, the derived axes the valid values nearest their
    defaults), then print its bricks and the library items to call."""
    axes = {a["id"]: a for a in ds["axes"]}
    vals = {a["id"]: [v["id"] for v in a["values"]] for a in ds["axes"]}
    sel, how = {}, {}
    for arg in args:
        k, _, v = arg.partition("=")
        if k not in axes:
            print(f"no axis {k!r}; axes: {', '.join(axes)}")
            return 1
        if v not in vals[k]:
            print(f"axis {k} has no value {v!r}; values: {', '.join(vals[k])}")
            return 1
        sel[k], how[k] = v, "chosen"
    for a in ds["compatibility"]["decisionAxes"]:
        if a not in sel:
            sel[a], how[a] = axes[a]["default"], "default"
    free = [a for a in axes if a not in sel]
    errs = [r for r in ds["constraints"] if r["level"] == "error"]

    def fails(s):
        return [r for r in errs if match(r.get("if"), s) and not match(r.get("require"), s)]

    best = None
    for combo in itertools.product(*[vals[a] for a in free]):
        s = dict(sel, **dict(zip(free, combo)))
        score = (len(fails(s)), sum(s[a] != axes[a]["default"] for a in free),
                 [vals[a].index(s[a]) for a in free])
        if best is None or score < best[0]:
            best = (score, s)
    sel = {a: best[1][a] for a in axes}
    for a in free:
        how[a] = "derived"
    labels = {a["id"]: {v["id"]: v["label"] for v in a["values"]} for a in ds["axes"]}
    print("Plan: " + ", ".join(f"{a} {sel[a]}" + ("" if how[a] == "chosen" else f" ({how[a]})") for a in axes))
    bad = fails(sel)
    for r in bad:
        fix = ", ".join(f"{k}={v}" for k, v in (r.get("fix") or {}).items())
        print(f"  error {r['id']}: {r['msg']}" + (f" Fix: {fix}." if fix else ""))
    if bad:
        print(f"{len(bad)} violated rule(s); no plan.")
        return 1
    for r in ds["constraints"]:
        if r["level"] == "warn" and match(r.get("if"), sel) and not match(r.get("require"), sel):
            print(f"  warn {r['id']}: {r['msg']}")
    for a in axes:
        st = next(v for v in axes[a]["values"] if v["id"] == sel[a])["status"]
        if set(as_list(st)) & (UNROBUST | {"to-build"}):
            print(f"  note: {a} {sel[a]} ({labels[a][sel[a]]}) is {status_label(ds, st)}")
    same = [bp["id"] for bp in ds["blueprints"] if bp["values"] == sel]
    near = min(ds["blueprints"], key=lambda bp: sum(bp["values"][a] != sel[a] for a in axes))
    if same:
        print(f"  blueprint: {same[0]}")
    else:
        diff = ", ".join(f"{a} {near['values'][a]}" for a in axes if near["values"][a] != sel[a])
        print(f"  nearest blueprint: {near['id']} (it has {diff})")
    bricks = {b["id"]: b for b in ds["bricks"]}
    need = needed(ds, sel)
    extra = [bricks[b]["name"] for b in (same and next(bp for bp in ds["blueprints"] if bp["id"] == same[0]) or near)["bricks"]
             if b not in need and not any(b in value_bricks_any(v) for x in ds["axes"] for v in x["values"])]
    if extra:
        print(f"  that blueprint also lists, in no axis (add them when the app needs them): {', '.join(extra)}")
    ex = [e["path"] for e in ds["examples"] if e.get("asBuilt") == sel]
    if ex:
        print(f"  example: {', '.join(ex)}")
    order = [b["id"] for b in ds["bricks"]]
    print(f"  bricks ({len(need)}):")
    for bid in sorted(need, key=order.index):
        b = bricks[bid]
        api = b.get("api") or {}
        print(f"    {b['name']} ({bid}) [{status_label(ds, b['status'])}]" + (f" internal: {api['internal']}" if "internal" in api else ""))
        for k in API_KEYS:
            for it in api.get(k, []):
                print(f"      {k:<8} {it['symbol']:<56} {it['path']}")
    return 0


def plan(ds, bp_id):
    """Print one blueprint as a starting plan: values, bricks, example, files, deviations."""
    bps = {b["id"]: b for b in ds["blueprints"]}
    if bp_id not in bps:
        print(f"no blueprint {bp_id!r}; blueprints: {', '.join(bps)}")
        return 1
    bp = bps[bp_id]
    labels = {a["id"]: (a["label"], {v["id"]: v["label"] for v in a["values"]}) for a in ds["axes"]}
    bricks = {b["id"]: b for b in ds["bricks"]}
    print(f"{bp['label']} [{', '.join(as_list(bp['status']))}]")
    print(f"  suits: {bp['suits']}")
    for a, v in bp["values"].items():
        print(f"  {labels[a][0]}: {labels[a][1][v]}")
    print("  bricks:")
    for bid in bp["bricks"]:
        b = bricks[bid]
        print(f"    {b['name']:<28} {'/'.join(as_list(b['status'])):<10} {', '.join(b['path']) or '-'}")
    ex = bp.get("example") or {}
    exe = next((e for e in ds["examples"] if e["id"] == ex.get("id")), None)
    print(f"  example: {exe['path'] if exe else '-'} [{ex.get('status')}] {ex.get('note', '')}".rstrip())
    print("  start from: " + "; ".join(bp["startFrom"]))
    base = needed(ds, bp["values"])
    for d in bp.get("deviations", []):
        what = ", ".join(f"{labels[k][0].lower()} {labels[k][1][v]}" for k, v in d["set"].items())
        print(f"  deviation: {what}: {d['use']} (cost: {d['cost']})")
        dev = needed(ds, dict(bp["values"], **d["set"]))
        name = lambda ids: ", ".join(bricks[i]["name"] for i in sorted(ids)) or "none"
        print(f"    adds: {name(dev - base)}; drops: {name(base - dev)}")
    return 0


# ---------------------------------------------------------------------------
# api completeness: every brick-library item an example uses is in some
# brick's api (or the common list), and every pss-client name the e2e driver
# imports is in some brick's client api (or the harness list)
# ---------------------------------------------------------------------------

USE_DECL = re.compile(r"\b(?P<pub>pub(?:\([^)]*\))?\s+)?use\s+(?:dep::)?(?P<tree>[^;]+);")
TEST_BLOCK = re.compile(r"(?:#\[[^\]]*\]\s*)*\bmod\s+tests?\s*\{"
                        r"|#\[test\b[^\]]*\]\s*(?:#\[[^\]]*\]\s*)*(?:pub\s+)?(?:unconstrained\s+)?fn\b[^{]*\{")
TS_IMPORT = re.compile(r"\bimport\s+(?:type\s+)?\{(?P<names>[^}]*)\}\s*from\s*\"(?P<from>[^\"]+)\"", re.S)


def without_tests(code):
    """A Noir source without its test modules and #[test] functions."""
    out, i = [], 0
    for m in TEST_BLOCK.finditer(code):
        if m.start() < i:
            continue
        out.append(code[i:m.start()])
        depth, j = 0, m.end() - 1
        while j < len(code):
            depth += {"{": 1, "}": -1}.get(code[j], 0)
            if depth == 0:
                break
            j += 1
        i = j + 1
    return "".join(out) + code[i:]


def use_tree(prefix, tree):
    """A use tree as (path segments, the name it binds) pairs."""
    tree = tree.strip()
    m = re.match(r"^([\w:]*?)(?:::)?\{(.*)\}$", tree, re.S)
    if m:
        base = prefix + [s for s in m.group(1).split("::") if s]
        parts, depth, cur = [], 0, ""
        for ch in m.group(2):
            depth += {"{": 1, "}": -1}.get(ch, 0)
            if ch == "," and depth == 0:
                parts.append(cur)
                cur = ""
            else:
                cur += ch
        return [x for p in parts + [cur] if p.strip() for x in use_tree(base, p)]
    alias = None
    a = re.match(r"^(.*?)\s+as\s+(\w+)$", tree)
    if a:
        tree, alias = a.group(1), a.group(2)
    segs = prefix + [s for s in tree.split("::") if s]
    if segs and segs[-1] == "self":
        segs = segs[:-1]
    return [(segs, alias or segs[-1])] if segs else []


def noir_uses(text, libs):
    """The brick-library paths a Noir source's non-test code uses: each item
    it imports and uses, each `module::item` path through an imported
    module, and each fully qualified path. Methods called on a value are not
    seen."""
    code = without_tests(re.sub(r"//[^\n]*", "", text))
    body = USE_DECL.sub("", code)
    found = set()
    for lib in libs:
        found |= {lib + u.group(1) for u in re.finditer(rf"(?<![\w:]){lib}((?:::\w+)+)", body)}
    for m in USE_DECL.finditer(code):
        for segs, alias in use_tree([], m.group("tree")):
            if segs[0] not in libs:
                continue
            here = ROOT / libs[segs[0]] / pathlib.PurePosixPath(*segs[1:]) if len(segs) > 1 else None
            if here is not None and (here.is_dir() or here.with_suffix(".nr").is_file()):
                found |= {"::".join(segs) + u.group(1)
                          for u in re.finditer(rf"(?<![\w:.]){re.escape(alias)}((?:::\w+)+)", body)}
            elif m.group("pub") or re.search(rf"(?<![\w:.]){re.escape(alias)}\b", body):
                found.add("::".join(segs))
    return found


def client_imports(text, package):
    """The names a TypeScript source imports from `package`."""
    names = set()
    for m in TS_IMPORT.finditer(text):
        if m.group("from") == package:
            for n in m.group("names").split(","):
                n = re.sub(r"^\s*type\s+", "", n).split(" as ")[0].strip()
                if n:
                    names.add(n)
    return names


def api_item(symbol):
    """The item a library path names: up to its first capitalised segment (a
    type or trait owns its methods and associated functions), else the whole path."""
    segs = segments(symbol)
    k = next((i for i, s in enumerate(segs) if s[:1].isupper()), len(segs) - 1)
    return "::".join(segs[:k + 1])


def source_files(top, suffixes):
    return sorted(p for suf in suffixes for p in (ROOT / top).rglob("*" + suf)
                  if not {"target", "node_modules"} & set(p.relative_to(ROOT).parts))


def completeness_problems(ds):
    chk = ds["apiCheck"]
    libs, package = chk["libraries"]["noir"], chk["libraries"]["client"]
    items, client = {}, {}
    for b in ds["bricks"]:
        api = b.get("api") or {}
        for k in ("contract", "circuit"):
            for it in api.get(k, []):
                items[api_item(it["symbol"])] = b["id"]
        for it in api.get("client", []):
            client[it["symbol"].split(".")[0]] = b["id"]
    for k in ("contract", "circuit"):
        for it in chk["common"].get(k, []):
            items[api_item(it["symbol"])] = "common"
    # a type re-exported at its crate's root is the same item
    types = {(i.split("::")[0], i.split("::")[-1]) for i in items if i.split("::")[-1][:1].isupper()}

    def listed(path):
        item = api_item(path)
        segs = item.split("::")
        return item in items or (segs[-1][:1].isupper() and (segs[0], segs[-1]) in types)

    probs, missing = [], {}
    for f in source_files("examples", (".nr",)):
        rel = f.relative_to(ROOT)
        if any(part.endswith("_test") for part in rel.parts):
            continue
        for path in noir_uses(f.read_text(encoding="utf-8"), libs):
            if not listed(path):
                missing.setdefault(api_item(path), []).append(rel.as_posix())
    for item, files in sorted(missing.items()):
        more = f" (and {len(files) - 1} more)" if len(files) > 1 else ""
        probs.append(f"{files[0]}{more}: uses {item}, which no brick's api lists; add it to the brick it belongs to, or to apiCheck.common")
    harness = chk["harness"]
    allowed, seen, missing = set(harness["client"]), set(), {}
    for top, allow in [("examples", set())] + [(h, allowed) for h in harness["paths"]]:
        for f in source_files(top, (".ts", ".mts")):
            rel = f.relative_to(ROOT).as_posix()
            for n in client_imports(f.read_text(encoding="utf-8"), package):
                if n in allow:
                    seen.add(n)
                elif n not in client:
                    missing.setdefault(n, []).append(rel)
    for n, files in sorted(missing.items()):
        more = f" (and {len(files) - 1} more)" if len(files) > 1 else ""
        probs.append(f"{files[0]}{more}: imports {n} from {package}, which no brick's client api lists; "
                     + ("add it to the brick it belongs to, or to apiCheck.harness.client"
                        if not files[0].startswith("examples/") else "add it to the brick it belongs to"))
    for n in sorted(allowed):
        if n in client:
            probs.append(f"apiCheck.harness.client: {n} is in brick {client[n]}'s client api; drop it here")
        elif n not in seen:
            probs.append(f"apiCheck.harness.client: {n} is imported by no file under {', '.join(harness['paths'])}; drop it")
    return probs


def main(argv):
    if len(argv) > 1 and argv[1] in ("--compat", "--write-readme", "--write-bricks"):
        ds = json.loads(DEFAULT.read_text())
        errs = validate(ds)
        found = scan_markers() if argv[1] == "--write-bricks" else {}
        errs += marker_problems(ds, found)
        for e in errs:
            print(f"design-space.json: {e}")
        if errs:
            return 1
        if argv[1] == "--write-readme":
            write_readme(ds)
            print(f"{README.name}: generated blocks updated")
        elif argv[1] == "--write-bricks":
            write_bricks(ds, found)
        else:
            print(render_blocks(ds)["compat-pairs"])
        return 0
    if len(argv) > 2 and argv[1] == "--plan":
        ds = json.loads(DEFAULT.read_text())
        errs = validate(ds)
        for e in errs:
            print(f"design-space.json: {e}")
        if errs:
            return 1
        if len(argv) == 3 and "=" not in argv[2]:
            return plan(ds, argv[2])
        return plan_choices(ds, argv[2:])
    path = pathlib.Path(argv[1]) if len(argv) > 1 else DEFAULT
    try:
        ds = json.loads(path.read_text())
    except (OSError, ValueError) as e:
        print(f"{path}: {e}")
        return 1
    errs = validate(ds)
    found = {}
    if not errs and path.resolve() == DEFAULT:
        found = scan_markers()
        errs = readme_problems(ds, README.read_text()) + marker_problems(ds, found)
        if not errs:
            errs = bricks_problems(ds, found) + completeness_problems(ds)
    for e in errs:
        print(f"{path.name}: {e}")
    if not errs:
        filled = sum(1 for b in ds["bricks"] if "internal" not in b.get("api", {}))
        print(f"{path.name}: ok ({len(ds['axes'])} axes, {len(ds['constraints'])} constraints, "
              f"{len(ds['bricks'])} bricks ({filled} with an api, {len(ds['bricks']) - filled} internal), "
              f"{len(ds['blueprints'])} blueprints)")
        if found:
            print("BRICK markers: " + ", ".join(f"{ex} {len(m)}" for ex, m in found.items()))
    return 1 if errs else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
