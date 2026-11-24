#!/usr/bin/env python3
"""Check the demo's scenarios and write the single-file page.

    python3 -I demo/build.py            # check, then write demo/dist/index.html
    python3 -I demo/build.py --check    # check only

Standard library only. Reads, never writes, anything outside demo/: the
design space comes from ../docs/design-guide/design-space.json. The page in
demo/dist/ inlines the stylesheet, the scripts, every scenario, the tab list,
the add-ons and the parts of the design space the brick panel uses, so it
opens from file:// and publishes as one page. See demo/README.md.
"""
import json
import re
import sys
from pathlib import Path

DEMO = Path(__file__).resolve().parent
REPO = DEMO.parent
DESIGN_SPACE = REPO / "docs" / "design-guide" / "design-space.json"

READERS = {"public", "user", "shared", "operator"}
FORMS = {"clear", "part", "sealed"}
SOURCES = {"PUBLIC", "INPUT_SHARED", "LOAD", "SAMPLE"}
FN_KINDS = {"public", "private", "utility", "view"}
LOGIC_KINDS = {"assert", "flag", "read", "load", "compute", "write", "push", "emit",
               "enqueue", "seal", "complete", "store"}
FLOW_KINDS = {"read", "send", "push", "submit", "call", "write", "emit"}
EFFECT_OPS = {"create", "update", "spend", "move", "remove"}
ENTITY_KINDS = {"orchestrator", "node", "relayer", "user", "developer"}
SECTIONS = {"code", "long_lived", "interaction"}
CALL_KINDS = {"private_to_public_enqueue", "public_to_public", "private_to_private"}
REF = re.compile(r"\[\[([^\]|]+)(?:\|[^\]]*)?\]\]")


class Checker:
    def __init__(self, name):
        self.name = name
        self.errors = []

    def err(self, where, msg):
        self.errors.append(f"{self.name}: {where}: {msg}")


def walk_items(item, out):
    """Every struct node with an id, the item and its nested fields."""
    out.append(item)
    for f in item.get("fields", []):
        walk_items(f, out)


def check_item(c, where, item, is_field=False):
    if not isinstance(item, dict):
        c.err(where, "an item must be an object")
        return
    if not is_field:
        for k in ("id", "label", "reader"):
            if k not in item:
                c.err(where, f"item lacks '{k}'")
    else:
        if "k" not in item:
            c.err(where, "a field lacks 'k'")
    if "reader" in item and item["reader"] not in READERS:
        c.err(where, f"reader '{item['reader']}' is not one of {sorted(READERS)}")
    if "form" in item and item["form"] not in FORMS:
        c.err(where, f"form '{item['form']}' is not one of {sorted(FORMS)}")
    if "to_reader" in item and item["to_reader"] not in READERS:
        c.err(where, f"to_reader '{item['to_reader']}' unknown")
    if "to_form" in item and item["to_form"] not in FORMS:
        c.err(where, f"to_form '{item['to_form']}' unknown")
    if "src" in item and item["src"] not in SOURCES:
        c.err(where, f"src '{item['src']}' is not a manifest source")
    for i, f in enumerate(item.get("fields", [])):
        check_item(c, f"{where}.fields[{i}]", f, is_field=True)


def texts(obj):
    """Every string in obj, for the reference check."""
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for v in obj.values():
            yield from texts(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from texts(v)


def check_scenario(path):
    c = Checker(path.name)
    try:
        s = json.loads(path.read_text())
    except json.JSONDecodeError as e:
        c.err("json", str(e))
        return None, c
    for k in ("id", "label", "path", "phases", "entities", "contracts", "steps"):
        if k not in s:
            c.err("top", f"lacks '{k}'")
    if c.errors:
        return s, c

    ids = {}

    def reg(i, kind, where):
        if i in ids:
            c.err(where, f"id '{i}' is used twice (first as {ids[i]})")
        ids[i] = kind

    phases = {p["id"] for p in s["phases"]}
    places = set()
    for e in s["entities"]:
        if e.get("kind") not in ENTITY_KINDS:
            c.err(f"entity {e.get('id')}", f"kind '{e.get('kind')}' unknown")
        reg(e["id"], "entity", f"entity {e['id']}")
        for sec in SECTIONS:
            reg(f"{e['id']}.{sec}", "section", f"entity {e['id']}")
            places.add((e["id"], sec, None))
        for cx in e.get("circuits", []):
            reg(cx["id"], "circuit", f"circuit {cx['id']}")
            for k in ("params", "outputs"):
                if k in cx:
                    check_item(c, f"circuit {cx['id']}.{k}", cx[k])
                    for it in [cx[k]]:
                        reg(it["id"], "cxitem", f"circuit {cx['id']}.{k}")
            for n, line in enumerate(cx.get("logic", [])):
                if line.get("kind") not in LOGIC_KINDS:
                    c.err(f"circuit {cx['id']}.logic[{n}]", f"kind '{line.get('kind')}' unknown")
                if "id" in line:
                    reg(line["id"], "logic", f"circuit {cx['id']}.logic[{n}]")
    fn_names = set()
    for k in s["contracts"]:
        reg(k["id"], "contract", f"contract {k['id']}")
        for side in ("public", "private"):
            reg(f"{k['id']}.{side}", "zone", f"contract {k['id']}")
            for g in k.get("groups", {}).get(side, []):
                places.add((k["id"], side, g["id"]))
        for f in k.get("functions", []):
            reg(f["id"], "function", f"function {f['id']}")
            fn_names.add(f["id"])
            if f.get("kind") not in FN_KINDS:
                c.err(f"function {f['id']}", f"kind '{f.get('kind')}' unknown")
            for n, line in enumerate(f.get("logic", [])):
                if line.get("kind") not in LOGIC_KINDS:
                    c.err(f"function {f['id']}.logic[{n}]", f"kind '{line.get('kind')}' unknown")
                if "id" in line:
                    reg(line["id"], "logic", f"function {f['id']}.logic[{n}]")
    for k in s["contracts"]:
        for f in k.get("functions", []):
            for q in f.get("enqueues", []):
                if q not in fn_names:
                    c.err(f"function {f['id']}", f"enqueues unknown '{q}'")
            v = f.get("verifies")
            if v and v.get("circuit") not in ids:
                c.err(f"function {f['id']}", f"verifies unknown circuit '{v.get('circuit')}'")
    for e in s["entities"]:
        for cx in e.get("circuits", []):
            if cx.get("verified_by") and cx["verified_by"] not in fn_names:
                c.err(f"circuit {cx['id']}", f"verified_by unknown '{cx['verified_by']}'")
    reg("tx", "tx", "the transaction object")

    def check_place(where, p):
        key = (p.get("in"), p.get("sec"), p.get("group"))
        if key not in places:
            c.err(where, f"no place {key}")

    # replay: which items exist after each step
    live = {}
    for n, eff in enumerate(s.get("initial", [])):
        if eff.get("op") != "create":
            c.err(f"initial[{n}]", "initial effects only create")
            continue
        check_place(f"initial[{n}]", eff["at"])
        check_item(c, f"initial[{n}].item", eff["item"])
        for it in [eff["item"]]:
            reg(it["id"], "item", f"initial[{n}]")
        live[eff["item"]["id"]] = 0
    for i, st in enumerate(s["steps"], start=1):
        w = f"step {i}"
        if st.get("n") != i:
            c.err(w, f"n is {st.get('n')}, expected {i}")
        for k in ("phase", "title", "text", "acts"):
            if k not in st:
                c.err(w, f"lacks '{k}'")
        if st.get("phase") not in phases:
            c.err(w, f"phase '{st.get('phase')}' not in phases")
        for n, eff in enumerate(st.get("effects", [])):
            ww = f"{w}.effects[{n}]"
            op = eff.get("op")
            if op not in EFFECT_OPS:
                c.err(ww, f"op '{op}' unknown")
                continue
            if op == "create":
                check_place(ww, eff.get("at", {}))
                check_item(c, f"{ww}.item", eff.get("item", {}))
                iid = eff.get("item", {}).get("id")
                if iid:
                    reg(iid, "item", ww)
                    live[iid] = i
            else:
                if eff.get("ref") not in live:
                    c.err(ww, f"{op} of '{eff.get('ref')}', which no earlier step made")
                if op == "move":
                    check_place(ww, eff.get("to", {}))
                if op == "update":
                    check_item(c, f"{ww}.set", dict({"id": "x", "label": "x", "reader": "public"}, **eff.get("set", {})))
        if "tx" in st:
            tx = st["tx"]
            if tx.get("entry") not in fn_names:
                c.err(w, f"tx enters unknown function '{tx.get('entry')}'")
            for k in ("item", "args"):
                if k in tx:
                    check_item(c, f"{w}.tx.{k}", tx[k])
        for n, call in enumerate(st.get("calls", [])):
            if call.get("kind") not in CALL_KINDS:
                c.err(f"{w}.calls[{n}]", f"kind '{call.get('kind')}' unknown")
            for k in ("caller", "callee"):
                if call.get(k) not in fn_names:
                    c.err(f"{w}.calls[{n}]", f"{k} '{call.get(k)}' is no function")
            if "args" in call:
                check_item(c, f"{w}.calls[{n}].args", call["args"])
        for n, v in enumerate(st.get("verifies", [])):
            if v.get("function") not in fn_names:
                c.err(f"{w}.verifies[{n}]", f"function '{v.get('function')}' unknown")
            if "public_inputs" in v:
                check_item(c, f"{w}.verifies[{n}].public_inputs", v["public_inputs"])
        for n, r in enumerate(st.get("runs", [])):
            if ids.get(r.get("circuit")) != "circuit":
                c.err(f"{w}.runs[{n}]", f"'{r.get('circuit')}' is no circuit")
        st["_live"] = set(live)
    # second pass: endpoints and references against every id (items made later
    # are fine in text: the page shows them unlinked until they exist)
    for i, st in enumerate(s["steps"], start=1):
        w = f"step {i}"
        for a in st.get("acts", []):
            if ids.get(a) not in ("entity", "function", "circuit"):
                c.err(w, f"acts names '{a}', which is no entity, function or circuit")
        for n, fl in enumerate(st.get("flows", [])):
            ww = f"{w}.flows[{n}]"
            if fl.get("kind") not in FLOW_KINDS:
                c.err(ww, f"kind '{fl.get('kind')}' unknown")
            if fl.get("reader") not in READERS:
                c.err(ww, f"reader '{fl.get('reader')}' unknown")
            for end in [fl.get("from")] + list(fl.get("to", [])):
                if end not in ids:
                    c.err(ww, f"endpoint '{end}' is no id")
                elif ids[end] == "item" and end not in st["_live"]:
                    c.err(ww, f"endpoint '{end}' does not exist at this step")
            if "text" not in fl:
                c.err(ww, "lacks 'text' (the list line and the hover)")
        if st.get("pick") and st["pick"] not in st["_live"]:
            c.err(w, f"pick '{st['pick']}' does not exist at this step")
        for o in st.get("open", []):
            if o not in ids:
                c.err(w, f"open names unknown '{o}'")
        del st["_live"]
    for t in texts(s):
        for m in REF.finditer(t):
            if m.group(1) not in ids:
                c.err("text", f"reference [[{m.group(1)}]] names no id (in: {t[:80]}…)")
    return s, c


def brick_data(ds):
    """The parts of design-space.json the brick panel reads."""
    return {
        "statuses": {k: v.get("label", k) for k, v in ds.get("statuses", {}).items()},
        "axes": [
            {
                "id": a["id"], "label": a.get("label", a["id"]), "question": a.get("question", ""),
                "derivedFrom": a.get("derivedFrom"),
                "values": [{"id": v["id"], "label": v.get("label", v["id"]), "status": v.get("status", ""),
                            "note": v.get("note", "")} for v in a.get("values", [])],
            }
            for a in ds.get("axes", [])
        ],
        "constraints": [
            {k: c[k] for k in ("id", "level", "if", "require", "msg", "fix") if k in c}
            for c in ds.get("constraints", [])
        ],
        "examples": [
            {"id": e["id"], "label": e.get("label", e["id"]), "path": e.get("path", ""),
             "status": e.get("status", ""), "blueprint": e.get("blueprint", ""), "asBuilt": e.get("asBuilt", {})}
            for e in ds.get("examples", [])
        ],
        "bricks": {b["id"]: {"name": b.get("name", b["id"]), "status": b.get("status", "")}
                   for b in ds.get("bricks", [])},
    }


def main(argv):
    check_only = "--check" in argv
    failures = []
    scenarios = {}
    for p in sorted((DEMO / "scenarios").glob("*.json")):
        s, c = check_scenario(p)
        failures += c.errors
        if s is not None:
            scenarios[s.get("id", p.stem)] = s
    tabs = json.loads((DEMO / "data" / "tabs.json").read_text())
    addons = json.loads((DEMO / "data" / "addons.json").read_text())
    for t in tabs:
        if t.get("scenario") and t["scenario"] not in scenarios:
            failures.append(f"tabs.json: tab '{t['id']}' names scenario '{t['scenario']}', which has no file")
    ds = json.loads(DESIGN_SPACE.read_text())
    bricks = brick_data(ds)
    axis_ids = {a["id"] for a in bricks["axes"]}
    ex_ids = {e["id"] for e in bricks["examples"]}
    statuses = set(bricks["statuses"])
    for a in bricks["axes"]:
        for v in a["values"]:
            if v["status"] not in statuses:
                failures.append(f"design-space.json: axis {a['id']} value {v['id']}: status '{v['status']}' is not in statuses")
    for b in addons.get("bricks", []):
        if b not in bricks["bricks"]:
            failures.append(f"addons.json: '{b}' is not a brick of design-space.json")
    for sid, s in scenarios.items():
        for b in s.get("addons", []):
            if b not in addons.get("bricks", []):
                failures.append(f"{sid}: add-on '{b}' is not in addons.json")
        if s.get("example") and s["example"] not in ex_ids:
            failures.append(f"{sid}: example '{s['example']}' is not in design-space.json")
        for i, st in enumerate(s.get("steps", []), start=1):
            for b in st.get("bricks", []):
                if b not in axis_ids:
                    failures.append(f"{sid}: step {i}: brick axis '{b}' is not in design-space.json")
    if failures:
        print("\n".join(failures), file=sys.stderr)
        print(f"{len(failures)} problem(s)", file=sys.stderr)
        return 1
    print(f"ok: {len(scenarios)} scenario(s), " + ", ".join(f"{k} {len(v['steps'])} steps" for k, v in scenarios.items()))
    if check_only:
        return 0

    data = {"scenarios": scenarios, "tabs": tabs, "addons": addons, "bricks": bricks}
    html = (DEMO / "index.html").read_text()
    css = (DEMO / "src" / "demo.css").read_text()
    html = html.replace('<link rel="stylesheet" href="src/demo.css">', "<style>\n" + css + "\n</style>")
    payload = json.dumps(data, ensure_ascii=False, separators=(",", ":")).replace("</", "<\\/")
    html = html.replace("<!-- DATA -->", "<script>window.PSS_DEMO = " + payload + ";</script>")

    def inline(m):
        js = (DEMO / m.group(1)).read_text().replace("</script", "<\\/script")
        return "<script>\n" + js + "\n</script>"
    html = re.sub(r'<script src="([^"]+)"></script>', inline, html)
    out = DEMO / "dist" / "index.html"
    out.parent.mkdir(exist_ok=True)
    out.write_text(html)
    print(f"wrote {out.relative_to(REPO)} ({len(html) // 1024} KiB)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
