#!/usr/bin/env python3
"""Write the Noir tests' copies of the shared vectors from testvectors/.

    python3 -I scripts/gen-noir-vectors.py          # rewrite every block
    python3 -I scripts/gen-noir-vectors.py --check  # fail if any block differs, change nothing

A Noir test cannot read a JSON file, so each value a Noir test holds from a
vector file sits between a BEGIN and an END marker line in that test's source
and is written here from the file, so a regenerated vector changes it or
fails --check (scripts/check-vectors.sh runs --check). The blocks:

- noir/pss_public_contract/src/configure.nr, from registry.json: the
  constants of configure's REGISTER answer check (the namespace,
  npk_app_hash, the one package's vk hash, the contract manifest's hash and
  packages hash, node 0's manifest result message, the three nodes' signing
  keys, their manifest signatures and their DISABLE signatures). A signature
  is four limbs, the low 128 bits of s[0], s[1], e[0], e[1] in that order, as
  `result_signature_verifies` takes it.
- noir/pss_tip_test/src/nodes.nr, from keys.json: the three nodes'
  `sig` scalars and public keys the test signer signs with.
- noir/pss_public_contract_test/src/test_partial.nr, from
  outcome.json `partial_note`: the partial note's preimage, the completed
  note's fields, its hash and its completion tag, which the test contract's
  two-step note type is checked against.
- noir/pss_utils/src/ae.nr, from ae.json: one known-answer test per
  vector.
- examples/amm-tip/circuits/amm_tip/src/tip.nr and shared.nr, from
  slot_commitment.json's first vector: the fixture pool's namespace, slot,
  reserves and blinding, whose commitment the vector holds.

stdlib only.
"""
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
VECTORS = ROOT / "testvectors"
SCRIPT = "scripts/gen-noir-vectors.py"


def short(hex_str):
    """A field as the shortest hex literal."""
    return hex(int(hex_str, 16))


def field(hex_str):
    """A field as a 64-digit hex literal."""
    return "0x%064x" % int(hex_str, 16)


def limb(hex_str):
    """A 128-bit signature limb as a 32-digit hex literal."""
    value = int(hex_str, 16)
    if value >> 128:
        raise SystemExit(f"registry.json: signature limb {hex_str} exceeds 128 bits")
    return "0x%032x" % value


def answers(results, disabled):
    """The three nodes' answers with the given `disabled`, in node order."""
    chosen = sorted((r for r in results if r["disabled"] == disabled), key=lambda r: r["node"])
    if [r["node"] for r in chosen] != [0, 1, 2]:
        raise SystemExit(f"registry.json: want one {'DISABLE' if disabled else 'REGISTER'} answer per node 0, 1, 2")
    return chosen


def sigs(name, chosen):
    lines = [f"global {name}: [[Field; 4]; 3] = ["]
    for r in chosen:
        s, e = r["signature"]["s"], r["signature"]["e"]
        lines.append("    [")
        lines.extend(f"        {limb(x)}," for x in (s[0], s[1], e[0], e[1]))
        lines.append("    ],")
    lines.append("];")
    return lines


def configure_block(vectors):
    results = vectors["results"]
    register, disable = answers(results, False), answers(results, True)
    first = register[0]
    for r in register + disable:
        for k in ("namespace", "npk_app_hash", "vk_hash", "name"):
            if r[k] != first[k]:
                raise SystemExit(f"registry.json: answers differ in {k}")
        if r["sig_pubkey"] != register[r["node"]]["sig_pubkey"]:
            raise SystemExit(f"registry.json: node {r['node']}'s answers name two keys")
    if first["name"] != "pss_seed" or disable[0]["seq"] != 1:
        raise SystemExit("registry.json: want pss_seed's DISABLE at seq 1")
    m = vectors["manifest"]
    manifest = sorted(m["results"], key=lambda r: r["node"])
    if [r["node"] for r in manifest] != [0, 1, 2]:
        raise SystemExit("registry.json: want one manifest answer per node 0, 1, 2")
    for r in manifest:
        if r["sig_pubkey"] != register[r["node"]]["sig_pubkey"]:
            raise SystemExit(f"registry.json: node {r['node']}'s manifest answer names another key")
    if (m["namespace"], m["npk_app_hash"], m["seq"]) != (first["namespace"], first["npk_app_hash"], 0):
        raise SystemExit("registry.json: want the manifest answer at seq 0 under the results' namespace and npk_app_hash")
    lines = [
        "// testvectors/registry.json: the three nodes' answers to the first",
        f"// REGISTER (seq 0) of the contract manifest listing pss_seed alone, vk hash {short(first['vk_hash'])},",
        f"// under namespace {short(first['namespace'])}, and to pss_seed's DISABLE (seq 1)",
        f"global NAMESPACE: Field = {short(first['namespace'])};",
        f"global NPK_APP_HASH: Field = {field(first['npk_app_hash'])};",
        f"global VK_HASH: Field = {short(first['vk_hash'])};",
        f"global MANIFEST_HASH: Field = {field(m['manifest_hash'])};",
        f"global PACKAGES_HASH: Field = {field(m['packages_hash'])};",
        "// manifest.results[0].message: node 0's manifest answer",
        f"global MESSAGE: Field = {field(manifest[0]['message'])};",
        "// node i's sig key (results[i].sig_pubkey)",
        "global KEYS: [EmbeddedCurvePoint; 3] = [",
    ]
    for r in register:
        key = r["sig_pubkey"]
        lines += [
            "    EmbeddedCurvePoint {",
            f"        x: {field(key['x'])},",
            f"        y: {field(key['y'])},",
            "    },",
        ]
    lines.append("];")
    lines += sigs("MANIFEST_SIGS", manifest)
    lines += sigs("DISABLE_SIGS", disable)
    return lines


def nodes_block(keys):
    nodes = keys["nodes"]
    if [n["node"] for n in nodes] != [0, 1, 2]:
        raise SystemExit("keys.json: want nodes 0, 1, 2 in order")
    lines = [
        "/// Node i's `sig` scalar (testvectors/keys.json `nodes[i].sig`).",
        "pub global NODE_SIG: [Field; NODES] = [",
    ]
    lines += [f"    {field(n['sig'])}," for n in nodes]
    lines += [
        "];",
        "",
        "/// Node i's `sig` public key (testvectors/keys.json `nodes[i].sig_pk`).",
        "pub global NODE_SIG_PK: [EmbeddedCurvePoint; NODES] = [",
    ]
    for n in nodes:
        lines += [
            "    EmbeddedCurvePoint {",
            f"        x: {field(n['sig_pk']['x'])},",
            f"        y: {field(n['sig_pk']['y'])},",
            "    },",
        ]
    lines.append("];")
    return lines


def partial_block(outcome):
    v = outcome["partial_note"]
    fields = ", ".join(short(x) for x in v["plaintext"])
    return [
        "// testvectors/outcome.json `partial_note`: the completed note [PARTIAL_FIELDS…,",
        "// PARTIAL_REQUEST_ID] of the partial note of PARTIAL_OWNER under PARTIAL_RHO at",
        "// slot PARTIAL_SLOT, as pss_core and pss-client compute it",
        f"global PARTIAL_OWNER: Field = {short(v['owner'])};",
        f"global PARTIAL_RHO: Field = {short(v['rho'])};",
        f"global PARTIAL_SLOT: Field = {short(v['storage_slot'])};",
        f"global PARTIAL_FIELDS: [Field; {len(v['plaintext'])}] = [{fields}];",
        f"global PARTIAL_REQUEST_ID: Field = {short(v['request_id'])};",
        f"global PARTIAL_NOTE: Field = {field(v['partial_note'])};",
        f"global PARTIAL_NOTE_HASH: Field = {field(v['note_hash'])};",
        f"global PARTIAL_COMPLETION_TAG: Field = {field(v['completion_log_tag'])};",
    ]


def ae_block(ae):
    lines = []
    for v in ae["vectors"]:
        n = v["n"]
        if not len(v["plaintext"]) == len(v["ciphertext"]) == n:
            raise SystemExit(f"ae.json: vector n = {n} does not hold n plaintext and ciphertext fields")
        if lines:
            lines.append("")
        lines += [
            "#[test]",
            f"fn kat_encrypt_n{n}() {{",
            f"    let key = {field(v['key'])};",
            f"    let nonce = {field(v['nonce'])};",
            f"    let plaintext: [Field; {n}] = [",
        ]
        lines += [f"        {field(x)}," for x in v["plaintext"]]
        lines += ["    ];", f"    let expected: [Field; {n}] = ["]
        lines += [f"        {field(x)}," for x in v["ciphertext"]]
        lines += [
            "    ];",
            "    let (ciphertext, tag) = AE::encrypt(plaintext, key, nonce);",
            "    assert_eq(",
            f"        AE::pattern_tag::<{n}>(),",
            f"        {field(v['pattern_tag'])},",
            "    );",
            "    assert_eq(ciphertext, expected);",
            f"    assert_eq(tag, {field(v['tag'])});",
            "    assert_eq(AE::decrypt(ciphertext, tag, key, nonce), plaintext);",
            "}",
        ]
    return lines


def amm_pool_block(doc):
    v = doc["vectors"][0]
    if not v["name"].startswith("amm-tip fixture"):
        raise SystemExit("slot_commitment.json: want the amm-tip fixture pool as vectors[0]")
    pool = ", ".join(str(int(x, 16)) for x in v["fields"])
    return [
        "// testvectors/slot_commitment.json vectors[0]: the pool amm_init_tip's",
        "// Prover.toml creates, Pool::from_seed(111), under blinding R_OLD in",
        "// namespace NS at slot SLOT",
        f"global NS: Field = {short(v['namespace'])};",
        f"global SLOT: Field = {short(v['slot'])};",
        f"global POOL: [Field; {len(v['fields'])}] = [{pool}];",
        f"global R_OLD: Field = {int(v['blinding'], 16)};",
    ]


# (target source, vector file, block writer, marker indent)
TARGETS = [
    ("noir/pss_public_contract/src/configure.nr", "registry.json", configure_block, "    "),
    ("noir/pss_tip_test/src/nodes.nr", "keys.json", nodes_block, ""),
    ("noir/pss_public_contract_test/src/test_partial.nr", "outcome.json", partial_block, ""),
    ("noir/pss_utils/src/ae.nr", "ae.json", ae_block, ""),
    ("examples/amm-tip/circuits/amm_tip/src/tip.nr", "slot_commitment.json", amm_pool_block, "    "),
    ("examples/amm-tip/circuits/amm_tip/src/shared.nr", "slot_commitment.json", amm_pool_block, "    "),
]


def markers(vectors, indent):
    begin = f"{indent}// BEGIN written by {SCRIPT} from testvectors/{vectors}\n"
    end = f"{indent}// END written by {SCRIPT}\n"
    return begin, end


def render(lines, indent):
    """The block's lines at the markers' indent (blank lines stay empty)."""
    return "".join((indent + line if line else "") + "\n" for line in lines)


def main(argv):
    check = "--check" in argv[1:]
    fail = 0
    for target, vectors, writer, indent in TARGETS:
        path = ROOT / target
        begin, end = markers(vectors, indent)
        text = path.read_text()
        if text.count(begin) != 1 or text.count(end) != 1 or text.index(begin) > text.index(end):
            print(f"{target}: want one BEGIN and one END marker line for testvectors/{vectors}", file=sys.stderr)
            fail = 1
            continue
        head, rest = text.split(begin)
        old, tail = rest.split(end)
        new = render(writer(json.loads((VECTORS / vectors).read_text())), indent)
        if old == new:
            print(f"ok: {target} matches testvectors/{vectors}")
        elif check:
            print(f"{target}: differs from testvectors/{vectors}; run python3 -I {SCRIPT}", file=sys.stderr)
            fail = 1
        else:
            path.write_text(head + begin + new + end + tail)
            print(f"wrote {target}")
    return fail


if __name__ == "__main__":
    sys.exit(main(sys.argv))
