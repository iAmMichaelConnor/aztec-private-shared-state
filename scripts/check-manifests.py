#!/usr/bin/env python3
"""Validate manifests against the manifest schema, docs/manifest.schema.json
(one schema for both paths; its `intake` selects the path), and the contract
manifest side: the deployment descriptors and the contract manifest vector.

Usage: python3 -I scripts/check-manifests.py [manifest.json ...]
With no arguments, checks every examples/*/manifests/*.json,
machine/circuits/manifests/*.json and testvectors/manifests/*.json; every
deployment descriptor, examples/*/deployments/*.json (the hand-written input
of pss-client's contract manifest generator: each package's circuit manifest
and compiled circuit exist, its request keys match the circuit manifest's
counts, an alias names a listed package on its circuit, the init round is
listed, the stale period is given exactly for a queued deployment); and
testvectors/contract_manifest.json (its manifest passes
docs/contract-manifest.schema.json and each circuit manifest the manifest
schema, and its jcs, manifest hash and packages hash are recomputed here,
the hash rule's third implementation beside Rust and TypeScript). Uses the
`jsonschema` package when it is installed; otherwise a built-in validator
for the keywords the schema uses (type, const, enum, required, properties,
patternProperties, additionalProperties, propertyNames, dependentRequired,
pattern, oneOf, allOf, if/then/else, items, minItems, maxItems, minimum,
$ref to #/$defs, and the boolean schemas true and false). With no arguments
it also runs scripts/gen-intake.py's check: every committed manifest of a
tip round under an intake must be the derivation from the round's
secret-shared manifest (and its non-secret-shared main's parameters), and
every derived manifest must pass the schema; and scripts/gen-access.py's:
every committed oblivious twin of a tree round (its manifest, main and
Nargo.toml) must be the derivation from the clear round. Exit status 1 if
any manifest fails.
"""

import importlib.util
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCHEMA = ROOT / "docs" / "manifest.schema.json"
CONTRACT_SCHEMA = ROOT / "docs" / "contract-manifest.schema.json"
VECTOR = ROOT / "testvectors" / "contract_manifest.json"
# annotation keywords: no effect on validity
IGNORED = {"$schema", "$comment", "title", "default", "$defs", "description"}
TYPES = {
    "object": lambda v: isinstance(v, dict),
    "array": lambda v: isinstance(v, list),
    "string": lambda v: isinstance(v, str),
    "integer": lambda v: isinstance(v, int) and not isinstance(v, bool),
}


def errors(value, schema, root, path="$"):
    """Yield one message per violation of `schema` by `value`."""
    if schema is True:
        return
    if schema is False:
        yield f"{path}: not allowed here"
        return
    unknown = set(schema) - IGNORED - SUPPORTED
    if unknown:
        raise ValueError(f"unsupported schema keywords {sorted(unknown)}")
    if "$ref" in schema:
        ref = schema["$ref"]
        if not ref.startswith("#/$defs/"):
            raise ValueError(f"unsupported $ref {ref}")
        yield from errors(value, root["$defs"][ref[len("#/$defs/"):]], root, path)
    for key, check in SCALAR_KEYWORDS.items():
        if key in schema:
            yield from check(value, schema, root, path)
    for branch in schema.get("allOf", []):
        yield from errors(value, branch, root, path)
    if "if" in schema:
        holds = not any(True for _ in errors(value, schema["if"], root, path))
        branch = schema.get("then" if holds else "else")
        if branch is not None:
            yield from errors(value, branch, root, path)
    if any(k in schema for k in OBJECT_KEYS):
        yield from k_object(value, schema, root, path)
    if any(k in schema for k in ARRAY_KEYS):
        yield from k_array(value, schema, root, path)


def k_type(v, s, root, path):
    if not TYPES[s["type"]](v):
        yield f"{path}: expected {s['type']}"


def k_const(v, s, root, path):
    if v != s["const"] or type(v) is not type(s["const"]):
        yield f"{path}: expected {json.dumps(s['const'])}"


def k_enum(v, s, root, path):
    if v not in s["enum"]:
        yield f"{path}: {v!r} not one of {s['enum']}"


def k_object(v, s, root, path):
    if not isinstance(v, dict):
        return
    for name in s.get("required", []):
        if name not in v:
            yield f"{path}: missing {name!r}"
    for name, needs in s.get("dependentRequired", {}).items():
        for need in needs:
            if name in v and need not in v:
                yield f"{path}: {name!r} requires {need!r}"
    props = s.get("properties", {})
    patterns = s.get("patternProperties", {})
    extra = s.get("additionalProperties", True)
    for name, item in v.items():
        if "propertyNames" in s:
            yield from errors(name, s["propertyNames"], root, f"{path}.{name} (name)")
        matched = [p for p in patterns if re.search(p, name)]
        for p in matched:
            yield from errors(item, patterns[p], root, f"{path}.{name}")
        if name in props:
            yield from errors(item, props[name], root, f"{path}.{name}")
        elif matched:
            pass
        elif extra is False:
            yield f"{path}: unexpected field {name!r}"
        elif isinstance(extra, dict):
            yield from errors(item, extra, root, f"{path}.{name}")


def k_pattern(v, s, root, path):
    if isinstance(v, str) and not re.search(s["pattern"], v):
        yield f"{path}: {v!r} does not match {s['pattern']}"


def k_one_of(v, s, root, path):
    matches = [b for b in s["oneOf"] if not any(True for _ in errors(v, b, root, path))]
    if len(matches) != 1:
        yield f"{path}: matches {len(matches)} of the oneOf branches, not exactly 1"


def k_array(v, s, root, path):
    if not isinstance(v, list):
        return
    if "minItems" in s and len(v) < s["minItems"]:
        yield f"{path}: fewer than {s['minItems']} items"
    if "maxItems" in s and len(v) > s["maxItems"]:
        yield f"{path}: more than {s['maxItems']} items"
    for i, item in enumerate(v):
        if "items" in s:
            yield from errors(item, s["items"], root, f"{path}[{i}]")


def k_minimum(v, s, root, path):
    if TYPES["integer"](v) and v < s["minimum"]:
        yield f"{path}: below {s['minimum']}"


def k_maximum(v, s, root, path):
    if TYPES["integer"](v) and v > s["maximum"]:
        yield f"{path}: above {s['maximum']}"


SCALAR_KEYWORDS = {"type": k_type, "const": k_const, "enum": k_enum, "pattern": k_pattern,
                   "oneOf": k_one_of, "minimum": k_minimum, "maximum": k_maximum}
OBJECT_KEYS = ("required", "properties", "patternProperties", "additionalProperties",
               "propertyNames", "dependentRequired")
ARRAY_KEYS = ("items", "minItems", "maxItems")
SUPPORTED = {"$ref", "allOf", "if", "then", "else", *SCALAR_KEYWORDS, *OBJECT_KEYS, *ARRAY_KEYS}


def validate(manifest, schema):
    try:
        import jsonschema
    except ImportError:
        return list(errors(manifest, schema, schema))
    validator = jsonschema.Draft202012Validator(schema)
    return [f"$.{'.'.join(map(str, e.path))}: {e.message}" for e in validator.iter_errors(manifest)]


def main(argv):
    schema = json.loads(SCHEMA.read_text())
    files = [Path(a) for a in argv] or sorted(
        [*ROOT.glob("examples/*/manifests/*.json"), *ROOT.glob("machine/circuits/manifests/*.json"),
         *ROOT.glob("testvectors/manifests/*.json")])
    if not files:
        print("check-manifests: no manifests found")
        return 1
    bad = 0
    for f in files:
        manifest = json.loads(f.read_text())
        problems = validate(manifest, schema)
        name = f.resolve().relative_to(ROOT) if f.resolve().is_relative_to(ROOT) else f
        print(f"{'ok  ' if not problems else 'FAIL'} {name}")
        for p in problems:
            print(f"     {p}")
        bad += bool(problems)
    print(f"check-manifests: {'PASS' if not bad else 'FAIL'} ({len(files)} manifests)")
    if not argv:
        bad += descriptors(schema)
        bad += contract_vector(schema)
        bad += derivations()
    return 1 if bad else 0


def load(path, name):
    """A sibling script as a module, without writing bytecode."""
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def descriptor_problems(path):
    """The problems of one deployment descriptor."""
    example = path.parent.parent
    d = json.loads(path.read_text())
    problems = []
    known = {"descriptor", "name", "contract", "stale_blocks", "packages", "init", "plain_reads", "read_contracts"}
    problems += [f"unknown field {k!r}" for k in d if k not in known]
    if d.get("descriptor") != 1:
        problems.append("descriptor: expected 1")
    if not isinstance(d.get("name"), str):
        problems.append("name: missing")
    if "contract" in d and not (example / "contract" / d["contract"]).is_dir():
        problems.append(f"contract: no {example.name}/contract/{d['contract']}")
    packages = d.get("packages") or []
    if not packages:
        problems.append("packages: none")
    listed, queued, names = {}, False, set()
    for i, p in enumerate(packages):
        at = f"packages[{i}]"
        extra = set(p) - {"name", "circuit", "alias_of", "state_keys"}
        problems += [f"{at}: unknown field {k!r}" for k in sorted(extra)]
        name, circuit = p.get("name"), p.get("circuit")
        if name in names:
            problems.append(f"{at}.name: {name!r} appears twice")
        names.add(name)
        mpath = example / "manifests" / f"{name}.json"
        if not mpath.is_file():
            problems.append(f"{at}: no circuit manifest {example.name}/manifests/{name}.json")
            continue
        if not (example / "circuits" / str(circuit)).is_dir():
            problems.append(f"{at}.circuit: no {example.name}/circuits/{circuit}")
        m = json.loads(mpath.read_text())
        intake = m.get("intake", "direct")
        keys = p.get("state_keys")
        if intake == "direct":
            if keys is not None:
                problems.append(f"{at}.state_keys: only for a queued package")
        else:
            queued = True
            counts = m.get("state_keys", {})
            if keys is None or len(keys.get("reads", [])) != counts.get("reads") or len(keys.get("writes", [])) != counts.get("writes"):
                problems.append(f"{at}.state_keys: the circuit manifest takes {counts.get('reads')} reads and {counts.get('writes')} writes")
        if "alias_of" in p:
            target = listed.get(p["alias_of"])
            if target is None:
                problems.append(f"{at}.alias_of: {p['alias_of']!r} is no listed package before it")
            elif target != circuit:
                problems.append(f"{at}.alias_of: {p['alias_of']!r} runs {target!r}, not {circuit!r}")
        else:
            listed[name] = circuit
    if queued != ("stale_blocks" in d):
        problems.append("stale_blocks: given exactly for a deployment with a queued package")
    stale = d.get("stale_blocks")
    if stale is not None and not (isinstance(stale, int) and not isinstance(stale, bool) and stale >= 1):
        problems.append("stale_blocks: a block count of at least 1, or null")
    init = d.get("init")
    if init is not None:
        if init.get("package") not in listed:
            problems.append(f"init.package: {init.get('package')!r} is not a listed package")
        if not isinstance(init.get("inputs"), list):
            problems.append("init.inputs: a list of Config member names")
    for k in ("plain_reads", "read_contracts"):
        if k in d and not isinstance(d[k], dict):
            problems.append(f"{k}: an object")
    return problems


def descriptors(schema):
    """Every deployment descriptor, examples/*/deployments/*.json."""
    files = sorted(ROOT.glob("examples/*/deployments/*.json"))
    bad = 0
    for f in files:
        problems = descriptor_problems(f)
        print(f"{'ok  ' if not problems else 'FAIL'} {f.relative_to(ROOT)}")
        for p in problems:
            print(f"     {p}")
        bad += bool(problems)
    print(f"check-manifests: descriptors {'PASS' if not bad else 'FAIL'} ({len(files)} descriptors)")
    return bad


def jcs(value):
    """RFC 8785 for the values a contract manifest holds (objects, arrays,
    ASCII strings, integers, booleans, null)."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def contract_vector(schema):
    """testvectors/contract_manifest.json: the schemas, then the hash rule."""
    p2 = load("poseidon2.py", "poseidon2")
    v = json.loads(VECTOR.read_text())
    m = v["manifest"]
    problems = validate(m, json.loads(CONTRACT_SCHEMA.read_text()))
    for i, pkg in enumerate(m.get("packages", [])):
        problems += [f"packages[{i}].manifest{e[1:]}" for e in validate(pkg["manifest"], schema)]
    text = jcs(m)
    if text != v["jcs"]:
        problems.append("jcs: not the canonical serialisation of manifest")
    if p2.hash_bytes(text.encode()) != int(v["manifest_hash"], 16):
        problems.append("manifest_hash: not poseidon2_hash_bytes(jcs)")
    h = 0
    for pkg in m["packages"]:
        if "alias_of" in pkg:
            continue
        name_hash = p2.hash_bytes(pkg["name"].encode())
        if name_hash != int(v["name_hashes"][pkg["name"]], 16):
            problems.append(f"name_hashes.{pkg['name']}: not poseidon2_hash_bytes(name)")
        h = p2.hash([h, name_hash, int(m["circuits"][pkg["circuit"]]["vk_hash"], 16)])
    if h != int(v["packages_hash"], 16):
        problems.append("packages_hash: not the running hash over the listed packages")
    print(f"{'ok  ' if not problems else 'FAIL'} {VECTOR.relative_to(ROOT)}")
    for p in problems:
        print(f"     {p}")
    return bool(problems)


def derivations():
    """scripts/gen-intake.py --check (each round under each intake) and
    scripts/gen-access.py --check (each tree round's oblivious twin)."""
    return load("gen-intake.py", "gen_intake").check() + load("gen-access.py", "gen_access").check()


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
