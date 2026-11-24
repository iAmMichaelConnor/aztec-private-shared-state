#!/usr/bin/env python3
"""Write every Prover*.toml of the credits rounds, and outputs.txt.

The ledger is a keyed map of depth DEPTH over the key's low bits
(credits_tip/src/ledger.nr: DEPTH, LEAF_LEN), and every fixture carries the
touched slots with their old hashes and DEPTH siblings as the nodes' oblivious
RAM reads them, so the fixtures are generated: this script reads the layout
from ledger.nr, builds the scenario's ledgers (a sparse tree over Poseidon2,
scripts/tip_hashes.py), writes one Prover.toml per round
and one Prover-<case>.toml per code, and writes outputs.txt, whose rows check
each case's old and new commitments as the circuit computes them against this
script's tree. scripts/check-noir.sh solves each case. Rerun after changing
the layout or the scenario; --check compares instead of writing
(scripts/generated.py):
    python3 -I examples/credits-tip/circuits/gen-fixtures.py [--check]

The scenario. Namespace 0xc0ffee, map key 0xa004, nsk_app 777, vk_hash 0x7e57
(a stand-in: the circuit takes it as an input). Two keys, KA and KB, are
Poseidon2 outputs, as every key the contract's request functions compute is
(`map_key`); KA2 has KA's low 64 bits under other high bits (a collision in
the path, which only a raw caller-chosen key could reach on purpose). Every request carries the
partial note its request function commits, partial_commitment(owner, rho).
  S0  credits_init/Prover.toml: the empty map.
  S1  pay/Prover on S0: 5,000 to KA (an insert).
  S2  pay/Prover-top-up on S1: 250 more to KA (an addition); the failures on S2:
      Prover-taken (KA2: the path holds KA, code 3), Prover-zero (code 2),
      Prover-mismatch (C does not open, code 1: KA's leaf re-blinded),
      Prover-mismatch-absent (C does not open, the shares carry KB, absent:
      no key enters, KB's path takes a vacant leaf).
  S3  claim/Prover on S2: 1,200 from KA (4,050 left); Prover-absent (KB, code
      4, the non-membership outcome), Prover-over (100,000, code 5).
      view/Prover on S3: KA present with 4,050; Prover-absent: KB absent.
  S4  move/Prover on S3: 1,000 from KA to KB (3,050 and 1,000); Prover-same
      (KA to KA, code 7: one path twice, nothing written), Prover-absent (from
      KB, code 4).
"""

import importlib.util
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(os.path.dirname(HERE)))
sys.dont_write_bytecode = True
_spec = importlib.util.spec_from_file_location("tip_hashes", os.path.join(REPO, "scripts", "tip_hashes.py"))
tip = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(tip)
p2 = tip.p2
generated = tip.load("generated")
OUT = generated.Output(sys.argv[1:], HERE, ["*/Prover*.toml", "outputs.txt"])

src = open(os.path.join(HERE, "credits_tip", "src", "ledger.nr")).read()
DEPTH = int(re.search(r"pub global DEPTH: u32 = (\d+);", src).group(1))
LEAF_LEN = int(re.search(r"pub global LEAF_LEN: u32 = (\d+);", src).group(1))
assert LEAF_LEN == 3

NS, KEY, NSK, VK = 0xC0FFEE, 0xA004, 777, 0x7E57
MASK = (1 << DEPTH) - 1

ZEROS = tip.zeros(DEPTH)
partial_note, node = tip.partial_note, tip.node


def leaf_hash(path, leaf):
    return tip.leaf_hash(NS, KEY, path, leaf)


class Ledger:
    """A keyed map: path -> [key, balance, blinding]."""

    def __init__(self, leaves=None):
        self.leaves = dict(leaves or {})
        self.memo = {}

    def with_leaf(self, key, balance, r, path=None):
        out = Ledger(self.leaves)
        out.leaves[key & MASK if path is None else path] = [key, balance, r]
        return out

    def node_at(self, h, prefix):
        at = (h, prefix)
        if at in self.memo:
            return self.memo[at]
        below = [p for p in self.leaves if (p >> h) == prefix]
        if not below:
            v = ZEROS[h]
        elif h == 0:
            v = leaf_hash(prefix, self.leaves[prefix])
        else:
            v = node(self.node_at(h - 1, prefix << 1), self.node_at(h - 1, (prefix << 1) | 1))
        self.memo[at] = v
        return v

    def root(self):
        return self.node_at(DEPTH, 0)

    def commitment(self):
        return tip.commitment(NS, KEY, self.root())

    def slots(self, keys):
        leaves, hashes, siblings = [], [], []
        for k in keys:
            path = k & MASK
            leaves.append(self.leaves.get(path, [0, 0, 0]))
            hashes.append(self.node_at(0, path))
            siblings.append([self.node_at(l, (path >> l) ^ 1) for l in range(DEPTH)])
        return leaves, hashes, siblings


def fmt(v):
    return f'"0x{v:x}"'


def out(v):
    """A value as check-noir prints it: hex of its minimal whole bytes."""
    h = f"{v:x}"
    return "0x" + ("0" + h if len(h) % 2 else h)


def arr(vs):
    return "[" + ", ".join(fmt(v) for v in vs) + "]"


ALICE, BOB = 0xA11CE5, 0xB0B5
KA = p2.hash([ALICE, 0x5EED1])
KB = p2.hash([BOB, 0x5EED2])
KA2 = (KA + (1 << DEPTH)) % p2.P
assert KA2 & MASK == KA & MASK and KA2 != KA

n_request = 0
rows = []


def request(owner):
    global n_request
    n_request += 1
    n = n_request
    return partial_note(owner, 0x9A00 + n), 0x6B00 + n, 0x7A00 + n, 0xB100 + n


def write_case(circuit, name, comment, ledger, inputs, keys, r_new, after, owner=ALICE, good=True):
    """One Prover-<case>.toml and its outputs row: `inputs` the app inputs in
    C's order, `keys` the slots' keys, `after` the ledger the round leaves."""
    partial, okey, tag, blinding = request(owner)
    values = [v for _, v in inputs] + [partial, okey, tag]
    c = p2.hash(values + [blinding])
    leaves, hashes, siblings = ledger.slots(keys)
    lines = [f"# {line}".rstrip() for line in comment.strip().splitlines()]
    lines.append("# generated by gen-fixtures.py; edit the script, not this file")
    lines += [f"namespace = {fmt(NS)}", f"vk_hash = {fmt(VK)}", f"in_slots = [{fmt(KEY)}]", f"out_slots = [{fmt(KEY)}]"]
    lines.append(f"inputs_hash = {fmt(c if good else (c + 1) % p2.P)}")
    lines += [f"{k} = {fmt(v)}" for k, v in inputs]
    lines += [f"partial_note = {fmt(partial)}", f"outcome_key = {fmt(okey)}", f"outcome_tag = {fmt(tag)}", f"blinding = {fmt(blinding)}"]
    lines.append("leaves = [" + ", ".join(arr(l) for l in leaves) + "]")
    lines.append(f"old_hashes = {arr(hashes)}")
    lines.append("siblings = [" + ", ".join(arr(s) for s in siblings) + "]")
    lines.append(f"r_new = {arr(r_new)}")
    lines.append(f"nsk_app = {fmt(NSK)}")
    OUT.write(os.path.join(HERE, circuit, f"{name}.toml"), "\n".join(lines) + "\n")
    rows.append(
        f"{circuit:<13} {name:<18} -  -  old_commitments=[{out(ledger.commitment())}] "
        f"new_commitments=[{out(after.commitment())}] outcome_tag={out(tag)}"
    )


def reblind(ledger, keys, r_new, opened=True):
    """The ledger a round that writes no new value leaves: every slot written
    under its fresh blinding (shared.nr `finish`), a present leaf keeping its
    key and balance; an absent key entered with a zero balance when the
    shares open C, a vacant leaf [0, 0, r] (no key) when they do not."""
    out = ledger
    for k, r in zip(keys, r_new):
        leaf = ledger.leaves.get(k & MASK)
        if leaf is not None:
            out = out.with_leaf(leaf[0], leaf[1], r)
        elif opened:
            out = out.with_leaf(k, 0, r)
        else:
            out = out.with_leaf(0, 0, r, path=k & MASK)
    return out


def main():
    tip.check_vectors()
    s0 = Ledger()
    OUT.write(
            os.path.join(HERE, "credits_init", "Prover.toml"),
            "# the empty map: state S0, the old commitment of pay/Prover.toml\n"
            "# generated by gen-fixtures.py; edit the script, not this file\n"
            f"namespace = {fmt(NS)}\nvk_hash = {fmt(VK)}\nout_slots = [{fmt(KEY)}]\n"
            f"r_new = {fmt(333)}\nnsk_app = {fmt(NSK)}\n",
    )
    init_row = f"credits_init  Prover             0x00  S0  new_c={out(s0.commitment())}"

    # S1: 5,000 to KA, an insert
    s1 = s0.with_leaf(KA, 5000, 444)
    write_case("pay", "Prover", "pay 5,000 to KA on the empty map S0: an insert; state S1", s0, [("key", KA), ("amount", 5000)], [KA], [444], s1)
    # S2: 250 more
    s2 = s1.with_leaf(KA, 5250, 445)
    write_case("pay", "Prover-top-up", "pay 250 more to KA on S1: an addition to the present entry; state S2", s1, [("key", KA), ("amount", 250)], [KA], [445], s2)
    write_case("pay", "Prover-taken", "pay to KA2, whose path is KA's: the leaf holds another key, code 3; KA's leaf re-blinded", s2, [("key", KA2), ("amount", 1)], [KA2], [446], reblind(s2, [KA2], [446]))
    write_case("pay", "Prover-zero", "pay 0 to KA on S2: code 2; KA's leaf re-blinded", s2, [("key", KA), ("amount", 0)], [KA], [447], reblind(s2, [KA], [447]))
    write_case("pay", "Prover-mismatch", "pay whose shares do not open to C (another blinding): code 1 first; KA's leaf re-blinded", s2, [("key", KA), ("amount", 7)], [KA], [448], reblind(s2, [KA], [448], opened=False), good=False)
    # S3: claim 1,200
    s3 = s2.with_leaf(KA, 4050, 449)
    write_case("claim", "Prover", "claim 1,200 from KA on S2: 4,050 left; state S3", s2, [("key", KA), ("amount", 1200)], [KA], [449], s3)
    write_case("claim", "Prover-absent", "claim from KB on S2, which is not in the map: code 4, the non-membership outcome; KB entered with a zero balance", s2, [("key", KB), ("amount", 1)], [KB], [450], reblind(s2, [KB], [450]), owner=BOB)
    write_case("claim", "Prover-over", "claim 100,000 from KA on S2: code 5; KA's leaf re-blinded", s2, [("key", KA), ("amount", 100000)], [KA], [451], reblind(s2, [KA], [451]))
    # views on S3
    write_case("view", "Prover", "view KA on S3: present with 4,050; the leaf re-blinded", s3, [("key", KA)], [KA], [452], reblind(s3, [KA], [452]))
    write_case("view", "Prover-absent", "view KB on S3: absent, proven on its path; KB entered with a zero balance", s3, [("key", KB)], [KB], [453], reblind(s3, [KB], [453]), owner=BOB)
    # S4: move 1,000 KA -> KB
    s4 = s3.with_leaf(KA, 3050, 454).with_leaf(KB, 1000, 455)
    write_case("move", "Prover", "move 1,000 from KA to KB on S3: KB inserted; state S4", s3, [("from", KA), ("to", KB), ("amount", 1000)], [KA, KB], [454, 455], s4)
    write_case("move", "Prover-same", "move from KA to KA on S3: one key twice, code 7; two slots on one path, so nothing is written", s3, [("from", KA), ("to", KA), ("amount", 1)], [KA, KA], [456, 457], s3)
    write_case("move", "Prover-absent", "move from KB, absent on S3: code 4; KB entered with a zero balance, KA's leaf (the destination) re-blinded", s3, [("from", KB), ("to", KA), ("amount", 1)], [KB, KA], [458, 459], reblind(s3, [KB, KA], [458, 459]), owner=BOB)
    write_case("pay", "Prover-mismatch-absent", "pay on S2 whose shares carry KB, absent, and do not open to C: code 1; no key enters the map, KB's path takes a vacant leaf", s2, [("key", KB), ("amount", 7)], [KB], [460], reblind(s2, [KB], [460], opened=False), good=False)

    header = f"""# Expected outputs of every credits-tip case, checked by
#   scripts/check-noir.sh examples/credits-tip --outputs examples/credits-tip/circuits/outputs.txt
# (the format is in check-noir.sh's header). Written by circuits/gen-fixtures.py,
# whose sparse tree the circuits' commitments are checked against: every row's
# old_commitments is the ledger the case loads and new_commitments the ledger it
# leaves. Every round writes every slot it touches under a fresh blinding, so
# every new commitment differs from its old one: a round that writes no new
# value keeps a present leaf's key and balance and enters an absent key with a
# zero balance, which every round reads as absent (a vacant leaf, no key, when
# the shares do not open C). Only a round whose slots are not placed (move's
# Prover-same: one path twice) writes nothing and keeps the commitment.
# The outputs are pss_core Private: no leaf hash, no code or amount in public.
state old_c new_c

# circuit     prover             from  to  outputs
{init_row}
"""
    OUT.write(os.path.join(HERE, "outputs.txt"), header + "\n".join(rows) + "\n")
    OUT.finish(f"credits-tip gen-fixtures.py: {len(rows) + 1} cases")
    if not OUT.check:
        print(f"wrote {len(rows) + 1} cases; S0 0x{s0.commitment():x}")


if __name__ == "__main__":
    main()
