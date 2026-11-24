"""The tip tree's and the partial note's hashes as pss_core computes them
(tip/tree.nr, tip/outcome.nr), over scripts/poseidon2.py, for the examples'
gen-fixtures.py, which load this module by path (`load`, also for
scripts/generated.py) and call `check_vectors` before they write anything.
"""

import importlib.util
import json
import os
import sys

SCRIPTS = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(SCRIPTS)
sys.dont_write_bytecode = True


def load(name):
    """The module scripts/<name>.py, loaded by path (the generators run with
    python3 -I, so scripts/ is not on the import path)."""
    spec = importlib.util.spec_from_file_location(name, os.path.join(SCRIPTS, name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


p2 = load("poseidon2")

# ASCII "pss.tip.leaf", "pss.tip.node", "pss.tip.tree" (pss_core tip/tree.nr)
TIP_LEAF = 0x7073732E7469702E6C656166
TIP_NODE = 0x7073732E7469702E6E6F6465
TIP_TREE = 0x7073732E7469702E74726565
# aztec-nr v6's DOM_SEP__PARTIAL_NOTE_COMMITMENT (pss_core tip/outcome.nr)
PARTIAL_NOTE_COMMITMENT = 568912195


def partial_note(owner, rho):
    """The partial note a request function commits: aztec-nr's
    partial_commitment(owner, rho)."""
    return p2.hash_sep([owner, rho], PARTIAL_NOTE_COMMITMENT)


def leaf_hash(namespace, key, index, leaf):
    """A leaf's hash at `index` (a keyed map's: its path) of the tree at
    `namespace` and `key`."""
    return p2.hash_sep([namespace, key, index] + list(leaf), TIP_LEAF)


def node(a, b):
    return p2.hash_sep([a, b], TIP_NODE)


def commitment(namespace, key, root):
    """The tree's commitment, what its contract slot holds."""
    return p2.hash_sep([namespace, key, root], TIP_TREE)


def zeros(depth):
    """The empty subtree's hash at each height 0 .. depth."""
    out = [0]
    for _ in range(depth):
        out.append(node(out[-1], out[-1]))
    return out


def check_vectors():
    """The leaf hashes against testvectors/tip_tree.json."""
    v = json.load(open(os.path.join(REPO, "testvectors", "tip_tree.json")))
    for case in v["leaves2"] + v["leaves4"]:
        got = leaf_hash(
            int(case["namespace"], 16),
            int(case["key"], 16),
            int(case["index"], 16),
            [int(x, 16) for x in case["leaf"]],
        )
        assert got == int(case["hash"], 16), "poseidon2.py disagrees with testvectors/tip_tree.json"
