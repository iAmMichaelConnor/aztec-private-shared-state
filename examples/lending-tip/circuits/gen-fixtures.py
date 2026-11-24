#!/usr/bin/env python3
"""Write every Prover*.toml of the lending rounds.

The book is a depth-D Merkle tree (lending_tip/src/market.nr: DEPTH, PROBES,
WINDOW),
and every fixture carries the touched leaves with their old hashes and D
siblings, as the nodes place them, so the fixtures are generated: this script
reads DEPTH and PROBES from market.nr, builds the scenario's books (a sparse
tree over Poseidon2, scripts/tip_hashes.py, and the race of a repayment and a
liquidation on one position), and writes the non-secret-shared deposit's
Prover.toml and one Prover-<case>.toml per code, and the same for the secret-shared
entries (the *_shared circuits, every round under secret-shared receipt intake: the
clear position indices, the shared amount, C and the reserved values, the
user's partial note among them), and each secret-shared case again for its
oblivious twin (the *_oblivious circuits: no placed indices, an opening round's
public `opens` after the position in C, the slots read where the oblivious
deployment's nodes read them, a position's low DEPTH bits), plus the cases
only that deployment can express. scripts/check-noir.sh solves each one and, with --outputs
examples/lending-tip/circuits/outputs.txt, checks its outputs and that each live
state's commitment as the circuit leaves it is the old_c of the rounds on it,
whose slots this script places, so the circuits' tree update is checked
against this script's tree. Rerun after changing DEPTH,
PROBES or the scenario; --check compares instead of writing (scripts/generated.py):

    python3 -I examples/lending-tip/circuits/gen-fixtures.py [--check]

The scenario. Namespace 0xc0ffee, market key 0xa003, nsk_app 777, vk_hash
0x7e57 (a stand-in: the circuit takes it as an input). The book records no
owner: a leaf's first element is its kind (1 a borrower's, 2 a lender's).
The header is [total_debt, liquidity, total_shares, borrow_index,
last_accrual, next_index, 0, blinding], a borrower leaf [1, collateral,
debt, index_at_touch, handle_partial, handle_key, exit_tag, blinding]
(index_at_touch INDEX_ONE; the owner's delivery handle, 0s for none), a
lender leaf [2, shares, 0, 0, 0, 0, exit_tag, blinding]. The books below
hold exit tag 0, as the non-secret-shared deposit writes it; the
secret-shared fixtures read each book with every entry leaf holding the tag
a tagged deployment's leaf holds (`tagged`: pss_core tip::exit's exit_tag
of the note of the round that last wrote it, a stand-in earlier request),
so a round that writes a leaf outputs that tag as its exit value, as the
landing requires (never 0). Every request carries the
partial note its request function commits, partial_commitment(owner, rho),
Alice's from her address 0xa11ce5, Bob's from 0xb0b5, the liquidator's,
the keeper's and the lender's from theirs; an owner round on a borrower
position (deposit, withdraw, borrow, repay, view) also carries the owner's
next delivery handle, its partial commitment from the owner's address too.
From S2 on, Alice's position holds a handle of hers (ALICE_HANDLE), which
the race's liquidation completes.
  S0  lending_init/Prover.toml: the empty book with 1,000,000 liquidity and
      as many protocol-owned shares, header blinding 333.
  S1  deposit/Prover.toml on S0: Alice opens a position (position 0; the
      scheduler assigns $new_leaf 1, the header's append index, which
      becomes 2) with 1,000 collateral.
  S2  S1 after Alice borrows 1,700 at price 2.50 (250) (borrow_shared/Prover
      on S1). At the race's price 2.00 her health is 9,411 bps.
  S3  deposit/Prover-second.toml on S2: Bob opens position 2 with 1,000.
  S4  S3 after race (a), Alice repays 400 (12,307 bps; repay_shared/Prover on
      S3); liquidate_shared/Prover-healthy on S4 probes positions 1 and 2 at
      2.00: ok, mask 0.
The race's liquidation first runs on S3 (liquidate_shared/Prover) with a
budget of 1,000: position 1 (Alice) is liquidated, seize 446, repay 850, 150
of the budget unused: mask 0b1 (one probe: K = 2).
The clock (the market's clock(), the block number the round accrues to) is
block 0, the books' last accrual, so nothing accrues, except in the
Prover-accrued cases, which run on KK and CB (below) at blocks 100 to 20,000.
The price's epoch (price_epoch, which only apply checks): 1 for the deposits,
the borrows and the first repay, the oracle's first price, and 2 after the
price moved to 2.00. Every fixture names its base state in its comment (a
live state S0 to S4, or its own state). The shared fixtures run on these
books; the opening deposit of deposit_shared/Prover.toml takes the partial
note, outcome key and tag of the client's first request
(testvectors/secret_store.json, n = 0, owner 0xa11ce: the client's
SecretStore.next()). The keeper's scan (scan_shared) runs on a book of its
own, KB: positions 1 .. 9, those at 1, 3 and 9 unhealthy at 2.00; each scan
fixture carries the window the nodes place (WINDOW leaves, their old hashes
and the window root's D - log2 W siblings). The lenders' rounds run on LB, a
pool whose value has moved past its shares as accrued interest moves it:
100,000 of debt beside 1,000,000 of liquidity, 1,002,000 shares of which a
lender holds 2,000 at position 1, each share worth 1.1. The interest cases
run on KK, a pool at the kink (800,000 lent of 1,000,000: rate(u) = 46 per
10^9 per block, so B' = 10^9 + 46 * dt) with Alice's position 1 (2,000,000
collateral, 800,000 debt) and a lender's 10,000 shares at position 2, and on
CB, the same pool with a borrower of 1,000 collateral and 1,599 debt at
position 1, healthy at 2.00 until interest carries the debt past 1,600.
"""
import json
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
OUT = generated.Output(sys.argv[1:], HERE, ["*/Prover*.toml"])

src = open(os.path.join(HERE, "lending_tip", "src", "market.nr")).read()
DEPTH = int(re.search(r"pub global DEPTH: u32 = (\d+);", src).group(1))
PROBES = int(re.search(r"pub global PROBES: u32 = (\d+);", src).group(1))
WINDOW = int(re.search(r"pub global WINDOW: u32 = (\d+);", src).group(1))
WINDOW_HEIGHT = int(re.search(r"pub global WINDOW_HEIGHT: u32 = (\d+);", src).group(1))
assert WINDOW == 1 << WINDOW_HEIGHT
LEAF_LEN = int(re.search(r"pub global LEAF_LEN: u32 = (\d+);", src).group(1))
INDEX_ONE = int(re.search(r"pub global INDEX_ONE: Field = (\d+);", src).group(1))

NS, KEY, NSK, VK = 0xC0FFEE, 0xA003, 777, 0x7E57
LIQ = 1_000_000
TWO_128 = 2**128
P_MINUS_1 = p2.P - 1


partial_note, node = tip.partial_note, tip.node


# ASCII "pss.exit_tag" (pss_core tip/exit.nr PSS_EXIT_TAG)
PSS_EXIT_TAG = 0x7073732E657869745F746167


def exit_tag(partial, request_id, entry):
    """pss_core tip::exit's exit_tag(P, request_id, entry): the tag an entry
    leaf holds for the note that completes P in that request's round."""
    return p2.hash([PSS_EXIT_TAG + TWO_128 * entry, partial, request_id])


def check_exit_tags():
    """exit_tag against testvectors/exit_tag.json, before writing anything."""
    v = json.load(open(os.path.join(REPO, "testvectors", "exit_tag.json")))
    assert int(v["pss_exit_tag"], 16) == PSS_EXIT_TAG
    for case in v["tags"]:
        got = exit_tag(int(case["partial"], 16), int(case["request_id"], 16), int(case["entry"], 16))
        assert got == int(case["tag"], 16), "exit_tag disagrees with testvectors/exit_tag.json"


# the stand-in owner whose earlier note each tagged leaf's tag is for
EARLIER_OWNER = 0xE0E0


def held_tag(index):
    """The tag entry leaf `index` holds on a tagged deployment: that of the
    note of the round that last wrote it, a stand-in earlier request
    0xE000 + index whose partial note is EARLIER_OWNER's."""
    return exit_tag(partial_note(EARLIER_OWNER, 0xE000 + index), 0xE000 + index, index)


def tagged(book):
    """`book` as a tagged deployment holds it: every entry leaf (any index
    but the header's 0) whose exit tag is 0 holds held_tag(index)."""
    out = {}
    for i, leaf in book.leaves.items():
        leaf = list(leaf)
        if i != 0 and leaf[LEAF_LEN - 2] == 0:
            leaf[LEAF_LEN - 2] = held_tag(i)
        out[i] = leaf
    return Book(out)


ZEROS = tip.zeros(DEPTH)


class Book:
    """A sparse book: {index: leaf of LEAF_LEN elements}, every other leaf empty."""

    def __init__(self, leaves):
        self.leaves = {i: list(l) for i, l in leaves.items()}
        self.memo = {}

    def with_leaves(self, changes):
        out = dict(self.leaves)
        out.update(changes)
        return Book(out)

    def leaf(self, i):
        return self.leaves.get(i, [0] * LEAF_LEN)

    def hash(self, i):
        leaf = self.leaves.get(i)
        return 0 if leaf is None else tip.leaf_hash(NS, KEY, i, leaf)

    def sub(self, level, pos):
        """The hash of the subtree of height `level` at position `pos`."""
        lo, hi = pos << level, (pos + 1) << level
        if not any(lo <= i < hi for i in self.leaves):
            return ZEROS[level]
        if level == 0:
            return self.hash(pos)
        key = (level, pos)
        if key not in self.memo:
            self.memo[key] = node(self.sub(level - 1, 2 * pos), self.sub(level - 1, 2 * pos + 1))
        return self.memo[key]

    def root(self):
        return self.sub(DEPTH, 0)

    def commitment(self):
        return tip.commitment(NS, KEY, self.root())

    def siblings(self, i):
        return [self.sub(l, (i >> l) ^ 1) for l in range(DEPTH)]

    def slots(self, indices):
        """The nodes' placement of `indices` (each below 2^D)."""
        return (
            [self.leaf(i) for i in indices],
            [self.hash(i) for i in indices],
            [self.siblings(i) for i in indices],
            list(indices),
        )


def placed(index):
    """The index the scheduler places for a request's value: 0 for one the
    tree cannot hold."""
    return index if 0 <= index < 2**DEPTH else 0


def fmt(v):
    return f'"{v:#x}"' if v >= 2**32 or v in (NS, KEY, VK) else f'"{v}"'


def arr(vs):
    return "[" + ", ".join(arr(v) if isinstance(v, list) else fmt(v) for v in vs) + "]"


def write_round(circuit, name, comment, book, price, epoch, inputs, at, tail, clock=0):
    """One Prover-<case>.toml: the public prefix, the app inputs, the slots
    the nodes place for the effective indices `at`, then `tail`."""
    leaves, hashes, siblings, indices = book.slots(at)
    lines = [f"# {line}".rstrip() for line in comment.strip().splitlines()]
    lines.append("# generated by gen-fixtures.py; edit the script, not this file")
    lines += [f"namespace = {fmt(NS)}", f"vk_hash = {fmt(VK)}"]
    lines += [f"in_slots = [{fmt(KEY)}]", f"out_slots = [{fmt(KEY)}]"]
    lines += [f"price = {fmt(price)}", f"price_epoch = {fmt(epoch)}", f"clock = {fmt(clock)}"]
    lines += [f"{k} = {fmt(v)}" for k, v in inputs]
    lines.append("leaves = [" + ", ".join(arr(l) for l in leaves) + "]")
    lines.append(f"old_hashes = {arr(hashes)}")
    lines.append("siblings = [" + ", ".join(arr(s) for s in siblings) + "]")
    lines.append(f"indices = {arr(indices)}")
    lines += [f"{k} = {arr(v) if isinstance(v, list) else fmt(v)}" for k, v in tail]
    lines.append(f"nsk_app = {fmt(NSK)}")
    OUT.write(os.path.join(HERE, circuit, f"{name}.toml"), "\n".join(lines) + "\n")


# ---- the scenario's books ----

def header(td, liq, shares, next_index, r, index=INDEX_ONE, last=0):
    """The header leaf: total_debt, the liquidity, total_shares, the borrow
    index (INDEX_ONE), last_accrual (block 0), the append index (the first
    leaf never written), 0 and the blinding."""
    return [td, liq, shares, index, last, next_index, 0, r]


def position(collateral, debt, r, index=INDEX_ONE, handle=(0, 0)):
    """A borrower's leaf: kind 1, its index at touch (INDEX_ONE), the owner's
    delivery handle (none)."""
    return [1, collateral, debt, index, handle[0], handle[1], 0, r]


def lender(shares, r):
    """A lender's leaf: kind 2."""
    return [2, shares, 0, 0, 0, 0, 0, r]


ALICE = 0xA11CE5
# a delivery handle of Alice's in her position from S2 on (an owner round of
# hers wrote it): its partial commitment from her address, and its key
ALICE_HANDLE = (partial_note(ALICE, 0xAA01), 0x6C01)

S0 = Book({0: header(0, LIQ, LIQ, 1, 333)})
S1 = S0.with_leaves({0: header(0, LIQ, LIQ, 2, 444), 1: position(1000, 0, 445)})
S2 = S1.with_leaves({0: header(1700, LIQ - 1700, LIQ, 2, 555), 1: position(1000, 1700, 556, handle=ALICE_HANDLE)})
S3 = S2.with_leaves({0: header(1700, LIQ - 1700, LIQ, 3, 557), 2: position(1000, 0, 558)})
S4 = S3.with_leaves({0: header(1300, LIQ - 1300, LIQ, 3, 666), 1: position(1000, 1300, 667, handle=ALICE_HANDLE)})
# the lenders' pool: 1.1 per share
LB = Book({0: header(100000, 1000000, 1002000, 2, 880), 1: lender(2000, 881)})
# interest: a pool at the kink (80% lent out: rate(u) = 46 per 10^9 per
# block), Alice's position 1 with 2,000,000 collateral and the 800,000 debt,
# a lender's 10,000 shares at position 2, accrued last at block 0; and the
# creeping book, the same pool with a borrower of 1,000 collateral and 1,599
# debt at position 1 (healthy at 2.00 until interest carries its debt past
# 1,600, after about 13,600 blocks) beside Bob's 1,000 without debt
KK = Book({0: header(800000, 200000, 1000000, 3, 1100), 1: position(2000000, 800000, 1101), 2: lender(10000, 1102)})
CB = Book({0: header(800000, 200000, 1000000, 3, 1200), 1: position(1000, 1599, 1201), 2: position(1000, 0, 1202)})


def own(leaves):
    """A failure fixture's own book."""
    return Book(leaves)


NONCE = iter(range(0x100, 0x1000))


BOB = 0xB0B5
LIQUIDATOR, KEEPER, LENDER = 0xB0B5, 0x6EE9E5, 0x1E9DE5


def dep(name, comment, book, amount, owner=ALICE, position=1, new_leaf=3, r=(444, 445), epoch=1, clock=0):
    """A non-secret-shared deposit fixture: position 0 opens the leaf
    $new_leaf names; the request's partial note is `owner`'s."""
    index = placed(new_leaf) if position == 0 else placed(position)
    n = next(NONCE)
    inputs = [("position", position), ("amount", amount), ("partial_note", partial_note(owner, 0x9A00 + n)), ("user_nonce", n)]
    tail = [("new_leaf", new_leaf), ("r_new", list(r))]
    write_round("deposit", name, comment, book, 250, epoch, inputs, [0, index], tail, clock)


# ---- the secret-shared entries ----

# the client's first request (testvectors/secret_store.json, wallet
# 0xa11ce5ec in namespace 0xc0ffee, owner 0xa11ce, n = 0): its partial note
# and outcome key and tag, the opening deposit's
_STORE = json.load(open(os.path.join(REPO, "testvectors", "secret_store.json")))
_FIRST = _STORE["vectors"][0]
assert int(_STORE["namespace"], 16) == NS and _FIRST["n"] == 0
OPEN_PARTIAL = int(_FIRST["partial_note"], 16)
assert OPEN_PARTIAL == partial_note(int(_STORE["owner"], 16), int(_FIRST["rho"], 16))
OPEN_KEY = int(_FIRST["outcome_key"], 16)
OPEN_TAG = int(_FIRST["outcome_tag"], 16)
SHARED_N = iter(range(1, 0x100))


def write_shared(circuit, name, comment, book, price, epoch, inputs, at, tail, owner, good=True, key=None, tag=None, partial=None, clock=0, twin=None):
    """One shared Prover-<case>.toml: the public prefix, C over the app
    inputs, the request's partial note (`owner`'s, or `partial`) and the
    outcome key and tag under the blinding (C + 1, which they do not open,
    when not `good`), the app inputs, the reserved values, then the slots
    and `tail` as write_round. When the circuit has an oblivious twin
    (<round>_oblivious beside it), the same case is written there too:
    `twin` is its (inputs, at), the app inputs C commits to on that
    deployment and the slots its nodes read (default: the shared ones)."""
    n = next(SHARED_N)
    request = shared_request(n, owner, key, tag, partial)
    write_shared_file(circuit, name, comment, book, price, epoch, inputs, at, tail, good, request, clock, True)
    oblivious = circuit.replace("_shared", "_oblivious")
    if os.path.isdir(os.path.join(HERE, oblivious)):
        o_inputs, o_at = twin or (inputs, at)
        o_comment = f"{comment}\n(the oblivious deployment's twin of {circuit}/{name}.toml)"
        write_shared_file(oblivious, name, o_comment, book, price, epoch, o_inputs, o_at, tail, good, request, clock, False)


def shared_request(n, owner, key=None, tag=None, partial=None):
    """The reserved values of the n-th secret-shared request: (partial note,
    outcome key, outcome tag, blinding, delivery handle), the handle
    `owner`'s next, (partial commitment, key), which only an owner round on a
    borrower position commits (HANDLE_ROUNDS)."""
    key = 0x6B00 + n if key is None else key
    tag = 0x7A00 + n if tag is None else tag
    partial = partial_note(owner, 0x9A00 + n) if partial is None else partial
    return partial, key, tag, 0xB100 + n, (partial_note(owner, 0xAA00 + n), 0x6C00 + n)


# the rounds whose request carries the owner's delivery handle after the app
# inputs (the mains' `handle_partial` and `handle_key`), both deployments
HANDLE_ROUNDS = {f"{r}_{d}" for r in ("deposit", "withdraw", "borrow", "repay", "view") for d in ("shared", "oblivious")}


def write_shared_file(circuit, name, comment, book, price, epoch, inputs, at, tail, good, request, clock, placed_indices):
    """The file write_shared describes, for `circuit`; `placed_indices`: the
    clear deployment's `indices` parameter (the oblivious circuits compose
    their slots' indices from their own inputs and take none)."""
    partial, key, tag, blinding, handle = request
    handled = [("handle_partial", handle[0]), ("handle_key", handle[1])] if circuit in HANDLE_ROUNDS else []
    values = [v for _, v in inputs + handled] + [partial, key, tag]
    c = p2.hash(values + [blinding])
    leaves, hashes, siblings, indices = tagged(book).slots(at)
    lines = [f"# {line}".rstrip() for line in comment.strip().splitlines()]
    lines.append("# generated by gen-fixtures.py; edit the script, not this file")
    lines += [f"namespace = {fmt(NS)}", f"vk_hash = {fmt(VK)}"]
    lines += [f"in_slots = [{fmt(KEY)}]", f"out_slots = [{fmt(KEY)}]"]
    lines += [f"price = {fmt(price)}", f"price_epoch = {fmt(epoch)}", f"clock = {fmt(clock)}"]
    lines.append(f"inputs_hash = {fmt(c if good else (c + 1) % p2.P)}")
    lines += [f"{k} = {fmt(v)}" for k, v in inputs + handled]
    lines += [f"partial_note = {fmt(partial)}", f"outcome_key = {fmt(key)}"]
    lines += [f"outcome_tag = {fmt(tag)}", f"blinding = {fmt(blinding)}"]
    lines.append("leaves = [" + ", ".join(arr(l) for l in leaves) + "]")
    lines.append(f"old_hashes = {arr(hashes)}")
    lines.append("siblings = [" + ", ".join(arr(s) for s in siblings) + "]")
    if placed_indices:
        lines.append(f"indices = {arr(indices)}")
    lines += [f"{k} = {arr(v) if isinstance(v, list) else fmt(v)}" for k, v in tail]
    lines.append(f"nsk_app = {fmt(NSK)}")
    OUT.write(os.path.join(HERE, circuit, f"{name}.toml"), "\n".join(lines) + "\n")


def read_at(index):
    """The leaf an oblivious deployment's nodes read for a shared position
    input: its low DEPTH bits (pss_core tree::slot_indices composes the
    same index in the circuit)."""
    return index % 2**DEPTH


OPENING = ("deposit_shared", "supply_shared")


def shared_owner_round(circuit, name, comment, book, position, amount, owner, r, price=250, epoch=1, new_leaf=None, good=True, key=None, tag=None, partial=None, amount_name="amount", clock=0, opens=None):
    """An owner round's case, and its oblivious twin: there an opening
    round's public `opens` follows the position in C (1 for position 0
    unless `opens` says otherwise), and the nodes read `$new_leaf` when it
    is 1, else the position's low bits."""
    if circuit in OPENING and position == 0:
        index = placed(new_leaf)
    else:
        index = placed(position)
    inputs = [("position", position)]
    o_inputs = list(inputs)
    o_index = read_at(position)
    if circuit in OPENING:
        o_opens = int(position == 0) if opens is None else opens
        o_inputs.append(("opens", o_opens))
        o_index = new_leaf if o_opens else o_index
    if amount is not None:
        inputs.append((amount_name, amount))
        o_inputs.append((amount_name, amount))
    tail = ([("new_leaf", new_leaf)] if circuit in OPENING else []) + [("r_new", list(r))]
    write_shared(circuit, name, comment, book, price, epoch, inputs, [0, index], tail, owner, good, key, tag, partial, clock,
                 twin=(o_inputs, [0, o_index]))


def oblivious_owner_round(circuit, name, comment, book, position, amount, owner, r, price=250, epoch=1, new_leaf=None, opens=None):
    """A case of an oblivious circuit alone (a request the clear deployment
    cannot express): written as shared_owner_round's twin, with the shared
    circuit's own case not written."""
    n = next(SHARED_N)
    o_inputs = [("position", position)]
    o_index = read_at(position)
    tail = [("r_new", list(r))]
    if circuit in OPENING:
        o_opens = int(position == 0) if opens is None else opens
        o_inputs.append(("opens", o_opens))
        o_index = new_leaf if o_opens else o_index
        tail = [("new_leaf", new_leaf)] + tail
    o_inputs.append(("amount", amount))
    write_shared_file(circuit.replace("_shared", "_oblivious"), name, comment, book, price, epoch, o_inputs,
                      [0, o_index], tail, True, shared_request(n, owner), 0, False)


def shared_liq(name, comment, book, price, positions, count, budget=1000, r=None, epoch=2, good=True, clock=0):
    probes = list(positions) + [0] * (PROBES - 1 - len(positions))
    used = count if 1 <= count <= PROBES - 1 else 0
    at = [0] + [placed(probes[k]) if k < used else 0 for k in range(PROBES - 1)]
    o_at = [0] + [read_at(probes[k]) if k < used else 0 for k in range(PROBES - 1)]
    inputs = [(f"p{k + 1}", probes[k]) for k in range(PROBES - 1)] + [("count", count), ("budget", budget)]
    r = list(r) if r else [777 + k for k in range(PROBES)]
    write_shared("liquidate_shared", name, comment, book, price, epoch, inputs, at, [("r_new", r)], LIQUIDATOR, good, clock=clock,
                 twin=(inputs, o_at))


def window(start):
    """The window start the nodes place for a scan's start: the start when it
    is below 2^D and a multiple of WINDOW, else 0."""
    return start if 0 <= start < 2**DEPTH and start % WINDOW == 0 else 0


def shared_quote(name, comment, book, good=True, clock=0):
    write_shared("quote_shared", name, comment, book, 200, 2, [], [0], [("r_new", [995])], LENDER, good, clock=clock)


def shared_scan(name, comment, book, price, start, epoch=2, good=True, clock=0):
    book = tagged(book)
    at = window(start)
    indices = [at + j for j in range(WINDOW)]
    tail = [
        ("window_leaves", [book.leaf(i) for i in indices]),
        ("window_hashes", [book.hash(i) for i in indices]),
        ("window_siblings", book.siblings(at)[WINDOW_HEIGHT:]),
        ("r_new", [999]),
    ]
    write_shared("scan_shared", name, comment, book, price, epoch, [("start", start)], [0], tail, KEEPER, good, clock=clock)


# the keeper's book: positions 1 .. 9 of 1,000 collateral each, those at 1,
# 3 and 9 with 1,700 debt (unhealthy at 2.00), the others 1,000 (healthy),
# but position 5, a lender's (occupied, never unhealthy)
UNHEALTHY = (1, 3, 9)
KB = Book(
    {0: header(3 * 1700 + 5 * 1000, LIQ - 11100, LIQ + 500, 10, 900)}
    | {i: position(1000, 1700 if i in UNHEALTHY else 1000, 900 + i) for i in range(1, 10) if i != 5}
    | {5: lender(500, 905)}
)


A = 2**128  # the payout's asset bit: amount + A is an amount of the collateral asset


def shared_cases():
    """The secret-shared entries' fixtures (ONE is INDEX_ONE, a borrower note's
    mask; a lender's note has mask 0): each outcome is
    [code, position, mask, x, y, payout, leaf_hash] inside the ciphertext,
    and the request's partial note completed with it; leaf_hash is the
    position's leaf hash after an owner-bound round that names its position
    (h(i) in the comments: it applied, or failed after the position's own
    checks, which re-blinds the leaf), else 0 (a scan's last field is its
    occupied count). payout is amount + 2^128 * asset (A + amount for the
    collateral asset). A round that does not apply returns its escrow in
    payout (a deposit's amount in the collateral asset, a repayment's amount
    or a liquidation's budget in the borrowed asset) unless its shares do not
    open C, when its inputs-opened bit (the last public output) is 0 and the
    contract refunds the escrow. New cases go at the end: each case's
    outcome tag is its place in this order."""
    d = lambda name, comment, book, amount, position=1, new_leaf=3, r=(444, 445), **kw: shared_owner_round(
        "deposit_shared", name, comment, book, position, amount, kw.pop("owner", ALICE), r, new_leaf=new_leaf, **kw)
    d("Prover", "S0: Alice opens her first position (the client's n = 0 partial note, outcome key and tag),\n"
      "position 0, $new_leaf 1, with 1,000: outcome [0, 1, ONE, 1000, 0, 0, h(1)]",
      S0, 1000, position=0, new_leaf=1, key=OPEN_KEY, tag=OPEN_TAG, partial=OPEN_PARTIAL)
    d("Prover-owned", "on S1: Alice adds 10 to her position 1: outcome [0, 1, ONE, 1010, 0, 0, h(1)]", S1, 10)
    d("Prover-not-open", "on S1: a deposit into the empty leaf 3 (no note of it exists): outcome [5, 0, 0, 0, 0, A + 10, 0]", S1, 10, position=3)
    d("Prover-full", "on S1: an opening with the book full ($new_leaf 0): outcome [16, 0, 0, 0, 0, A + 10, 0], nothing written", S1, 10, position=0, new_leaf=0)
    d("Prover-mismatch", "on S1: shares that do not open C: outcome [14, 0, 0, 0, 0, 0, 0], inputs-opened bit 0", S1, 10, good=False)
    d("Prover-gap", "on S1: an opening at the empty leaf 5, past the header's append index 2:\n"
      "outcome [17, 0, 0, 0, 0, A + 10, 0], the header re-blinded, leaf 5 left empty, no position named", S1, 10, position=0, new_leaf=5)

    b = lambda name, comment, book, amount, price, position=1, **kw: shared_owner_round(
        "borrow_shared", name, comment, book, position, amount, kw.pop("owner", ALICE), (555, 556), price=price, **kw)
    b("Prover", "on S1: Alice borrows 1,700 at 2.50: outcome [0, 1, ONE, 1000, 1700, 1700, h(1)]", S1, 1700, 250)
    b("Prover-not-open", "on S1: a borrow against the empty leaf 3: outcome [5, 0, 0, 0, 0, 0, 0]", S1, 1700, 250, position=3)
    b("Prover-limit", "on S1: 1,700 at 2.00, past the borrow limit of 1,500 (75% of 2,000): outcome [9, 1, ONE, 1000, 0, 0, h(1)]", S1, 1700, 200, epoch=2)
    b("Prover-at-limit", "on S1: 1,500 at 2.00, exactly the borrow limit: outcome [0, 1, ONE, 1000, 1500, 1500, h(1)]", S1, 1500, 200, epoch=2)
    b("Prover-lender", "on LB: a borrow against the lender's position 1: outcome [5, 0, 0, 0, 0, 0, 0]", LB, 10, 250)
    b("Prover-mismatch", "on S1: shares that do not open C: outcome [14, 0, 0, 0, 0, 0, 0], inputs-opened bit 0", S1, 1700, 250, good=False)

    w = lambda name, comment, book, amount, **kw: shared_owner_round(
        "withdraw_shared", name, comment, book, 1, amount, ALICE, (771, 772), **kw)
    w("Prover", "on S2: Alice withdraws 93 at 2.50, leaving 907, at the borrow limit (907 * 250 * 7500 >=\n"
      "1700 * 100 * 10000): outcome [0, 1, ONE, 907, 1700, A + 93, h(1)]", S2, 93)
    w("Prover-limit", "on S2: 94 at 2.50 leaves 906, below the limit: outcome [9, 1, ONE, 1000, 1700, 0, h(1)]", S2, 94)
    w("Prover-over", "on S2: 1,001 against 1,000 collateral: outcome [19, 1, ONE, 1000, 1700, 0, h(1)]", S2, 1001)
    w("Prover-mismatch", "on S2: shares that do not open C: outcome [14, 0, 0, 0, 0, 0, 0], inputs-opened bit 0", S2, 93, good=False)

    rp = lambda name, comment, book, amount, **kw: shared_owner_round(
        "repay_shared", name, comment, book, 1, amount, ALICE, (666, 667), **kw)
    rp("Prover", "on S3: race (a), Alice repays 400: outcome [0, 1, ONE, 1000, 1300, 0, h(1)]", S3, 400)
    rp("Prover-excess", "on S3: 1,701 against 1,700: the debt repaid, 1 back: outcome [0, 1, ONE, 1000, 0, 1, h(1)]", S3, 1701)
    rp("Prover-mismatch", "on S3: shares that do not open C: outcome [14, 0, 0, 0, 0, 0, 0], inputs-opened bit 0", S3, 400, good=False)

    sp = lambda name, comment, book, amount, position=1, new_leaf=None, **kw: shared_owner_round(
        "supply_shared", name, comment, book, position, amount, LENDER, (881, 882), new_leaf=new_leaf, price=200, epoch=2, **kw)
    sp("Prover", "S0: a lender opens position 1 with 5,000, the first supply after the seed (one share per\n"
       "unit): outcome [0, 1, 0, 5000, 5000, 0, h(1)]", S0, 5000, position=0, new_leaf=1)
    sp("Prover-moved", "on LB: the lender supplies 1,100 into position 1 at 1.1 per share: floor(1100 * 1002000 /\n"
       "1100000) = 1,002 shares, 3,002 worth 3,295: outcome [0, 1, 0, 3002, 3295, 0, h(1)]", LB, 1100, new_leaf=0)
    sp("Prover-zero", "on LB: 1 at 1.1 per share mints no share: outcome [20, 1, 0, 2000, 2195, 1, h(1)], the amount back",
       LB, 1, new_leaf=0)
    sp("Prover-borrower", "on S1: a supply into Alice's borrower position 1: outcome [5, 0, 0, 0, 0, 10, 0]", S1, 10, new_leaf=0)
    sp("Prover-mismatch", "on LB: shares that do not open C: outcome [14, 0, 0, 0, 0, 0, 0], inputs-opened bit 0", LB, 1100, new_leaf=0, good=False)

    ws = lambda name, comment, book, shares, position=1, **kw: shared_owner_round(
        "withdraw_supply_shared", name, comment, book, position, shares, LENDER, (883, 884), price=200, epoch=2, amount_name="shares", **kw)
    ws("Prover", "on LB: the lender burns 1,000 of its 2,000 shares for floor(1000 * 1100000 / 1002000) = 1,097:\n"
       "outcome [0, 1, 0, 1000, 1097, 1097, h(1)]", LB, 1000)
    ws("Prover-shares", "on LB: 2,001 shares against the leaf's 2,000: outcome [18, 1, 0, 2000, 2195, 0, h(1)]", LB, 2001)
    ws("Prover-liquidity", "own book: 2,000 shares worth 2,195 against 1,000 of liquidity (the rest lent out):\n"
       "outcome [8, 1, 0, 2000, 2195, 0, h(1)]", own({0: header(1099000, 1000, 1002000, 2, 885), 1: lender(2000, 886)}), 2000)
    ws("Prover-mismatch", "on LB: shares that do not open C: outcome [14, 0, 0, 0, 0, 0, 0], inputs-opened bit 0", LB, 1000, good=False)

    v = lambda name, comment, book, position=1, **kw: shared_owner_round(
        "view_shared", name, comment, book, position, None, ALICE, (991, 992), **kw)
    v("Prover", "on S2: Alice views position 1 after her deposit and borrow: outcome [0, 1, ONE, 1000, 1700, 0, h(1)]", S2)
    v("Prover-not-open", "on S2: a view of the empty leaf 3: outcome [5, 0, 0, 0, 0, 0, 0]", S2, position=3)
    v("Prover-position", "on S2: position 0: outcome [3, 0, 0, 0, 0, 0, 0], nothing written", S2, position=0)
    v("Prover-lender", "on LB: a view of the lender's position 1: its shares and their value at 1.1:\n"
      "outcome [0, 1, 0, 2000, 2195, 0, h(1)]", LB)

    shared_quote("Prover", "on LB: the quote [0, 0, borrow_index, 0, supply_index, 0, utilisation]:\n"
                 "outcome [0, 0, ONE, 0, 1097804391, 0, 909], the header re-blinded", LB)
    shared_quote("Prover-mismatch", "on LB: shares that do not open C: outcome [14, 0, 0, 0, 0, 0, 0], inputs-opened bit 0", LB, good=False)

    shared_liq("Prover", "on S3: race (b), budget 1,000, position 1 liquidated:\n"
               "outcome [0, 0, 1, 446, 850, 150, 0]; Alice's handle completed with [0, 1, ONE, 554, 850, 0, h(1)]\n"
               "and cleared", S3, 200, [1], 1)
    shared_liq("Prover-healthy", "on S4: race (a), the probe healthy: outcome [0, 0, 0, 0, 0, 1000, 0], the probe left (its leaf hash\n"
               "unchanged, not logged, its handle kept), no notice", S4, 200, [1], 1)
    shared_liq("Prover-count", "on S3: a count of 0: outcome [3, 0, 0, 0, 0, 1000, 0], nothing written", S3, 200, [1], 0)
    shared_liq("Prover-mismatch", "on S3: shares that do not open C: outcome [14, 0, 0, 0, 0, 0, 0], inputs-opened bit 0", S3, 200, [1], 1, good=False)
    shared_liq("Prover-budget", "on S3: position 1 with a budget of 425, half its close-factor repay of 850:\n"
               "repay 425, seize 223 (scaled with the repay): outcome [0, 0, 1, 223, 425, 0, 0]", S3, 200, [1], 1, budget=425)

    kb = "the keeper's book (positions 1 .. 9, 1, 3 and 9 unhealthy at 2.00, 5 a lender's)"
    shared_scan("Prover", f"on {kb}: window 0 reports positions 1 and 3 (0b1010) and 7 occupied:\n"
                "outcome [0, 0, 10, 0, 0, 0, 7] ([code, 0, report, 0, start, 0, occupied]), the header re-blinded", KB, 200, 0)
    shared_scan("Prover-second-window", f"on {kb}: window 8 reports position 9 (0b10), 2 occupied:\n"
                "outcome [0, 0, 2, 0, 8, 0, 2]", KB, 200, 8)
    shared_scan("Prover-past-end", f"on {kb}: window 16, past the book's end: outcome [0, 0, 0, 0, 16, 0, 0]", KB, 200, 16)
    shared_scan("Prover-empty", "on S0: window 0 of a book with no position: outcome [0, 0, 0, 0, 0, 0, 0]", S0, 200, 0)
    shared_scan("Prover-position", f"on {kb}: start 4, not a multiple of W (the nodes place window 0):\n"
                "outcome [3, 0, 0, 0, 0, 0, 0], nothing written", KB, 200, 4)
    shared_scan("Prover-out-of-range", f"on {kb}: start 2^D: outcome [3, 0, 0, 0, 0, 0, 0], nothing written", KB, 200, 2**DEPTH)
    shared_scan("Prover-price-zero", f"on {kb}: price 0: outcome [6, 0, 0, 0, 0, 0, 0], the header re-blinded", KB, 0, 0)
    shared_scan("Prover-bad-state", "own book: position 2's debt is 2^128: outcome [4, 0, 0, 0, 0, 0, 0]",
                own({0: header(1700, LIQ, LIQ, 3, 990), 1: position(1000, 1700, 991), 2: position(1000, TWO_128, 992)}), 200, 0)
    shared_scan("Prover-mismatch", f"on {kb}: shares that do not open C: outcome [14, 0, 0, 0, 0, 0, 0]", KB, 200, 0, good=False)

    # interest, at a second clock: the rounds accrue the header first
    # (B' = 10^9 + 46 * dt at the kink; total_debt' rounds up) and bring a
    # written position to the index (its debt rounds up)
    v("Prover-accrued", "on KK at block 100: Alice's debt at the index B' = 1,000,004,600: ceil(800,000 * 1.0000046)\n"
      "= 800,004: outcome [0, 1, 1000004600, 2000000, 800004, 0, h(1)], the header and the position accrued", KK, clock=100)
    rp("Prover-accrued", "on KK at block 100: Alice repays the 800,000 her note said; the 4 of interest remain:\n"
       "outcome [0, 1, 1000004600, 2000000, 4, 0, h(1)]", KK, 800000, clock=100)
    shared_quote("Prover-accrued", "on KK at block 10,000: B' = 1,000,460,000, total_debt 800,368, the supply index\n"
                 "1,000,368 * 10^9 / 10^6: outcome [0, 0, 1000460000, 0, 1000368000, 0, 8000]", KK, clock=10000)
    ws("Prover-accrued", "on KK at block 10,000: the lender's 10,000 shares (position 2) pay floor(10000 * 1000368 /\n"
       "1000000) = 10,003: outcome [0, 2, 0, 0, 0, 10003, h(2)]", KK, 10000, position=2, clock=10000)
    shared_scan("Prover-accrued", "on CB at block 20,000: position 1's debt 1,599 * 1.00092 = 1,600.47 is past the\n"
                "threshold with no round touching it: outcome [0, 0, 2, 0, 0, 0, 2]", CB, 200, 0, clock=20000)
    shared_scan("Prover-not-yet", "on CB at block 0: position 1 healthy: outcome [0, 0, 0, 0, 0, 0, 2]", CB, 200, 0)
    shared_liq("Prover-accrued", "on CB at block 20,000: position 1 brought to the index, ceil(1,600.47) = 1,601,\n"
               "repay 800, seize floor(800 * 1.05 / 2) = 420: outcome [0, 0, 1, 420, 800, 200, 0]; the position holds\n"
               "no handle: no notice", CB, 200, [1], 1, clock=20000)

    # the oblivious deployment's own cases: its public opening flag against
    # the committed position, and a position input past the tree, which its
    # nodes read at the low bits (the clear deployment's nodes place leaf 0)
    oblivious_owner_round("deposit_shared", "Prover-opens", "on S1: Alice's position 1 with the opening flag 1 (a flag the nodes could flip): outcome\n"
                          "[4, 0, 0, 0, 0, A + 10, 0], nothing written", S1, 1, 10, ALICE, (444, 445), new_leaf=2, opens=1)
    oblivious_owner_round("deposit_shared", "Prover-position", "on S1: position 2^D + 1, read at leaf 1 (its low bits): outcome [3, 0, 0, 0, 0, A + 10, 0],\n"
                          "nothing written", S1, 2**DEPTH + 1, 10, ALICE, (444, 445), new_leaf=2)
    oblivious_owner_round("borrow_shared", "Prover-position", "on S1: position 2^D + 1, read at leaf 1 (its low bits): outcome [3, 0, 0, 0, 0, 0, 0],\n"
                          "nothing written", S1, 2**DEPTH + 1, 1700, ALICE, (555, 556))


def main():
    tip.check_vectors()
    check_exit_tags()
    # ---- lending_init (and the oblivious deployment's): S0 ----
    for init in ("lending_init", "lending_init_oblivious"):
        OUT.write(
                os.path.join(HERE, init, "Prover.toml"),
                "# the empty book with 1,000,000 liquidity and as many shares under header blinding 333: state S0,\n"
                "# the old_c of deposit/Prover.toml (gen-fixtures.py has the scenario)\n"
                "# generated by gen-fixtures.py; edit the script, not this file\n"
                f"namespace = {fmt(NS)}\nvk_hash = {fmt(VK)}\nout_slots = [{fmt(KEY)}]\n"
                f"liquidity = {fmt(LIQ)}\nr_new = \"333\"\nnsk_app = {fmt(NSK)}\n",
        )

    # ---- deposit ----
    dep("Prover", "S0 -> S1: Alice opens a position (position 0, $new_leaf 1) with 1,000: ok", S0, 1000, position=0, new_leaf=1)
    dep("Prover-second", "S2 -> S3: Bob opens position 2 with 1,000: ok", S2, 1000, owner=BOB, position=0, new_leaf=2, r=(557, 558))
    dep("Prover-oversize", "on S1: amount 2^128: ok = 0, code 1", S1, TWO_128)
    dep("Prover-zero", "on S1: amount 0: ok = 0, code 2", S1, 0)
    dep("Prover-position", "on S1: position 2^D: ok = 0, code 3", S1, 10, position=2**DEPTH)
    dep("Prover-full", "on S1: an opening deposit with the book full ($new_leaf 0): ok = 0, code 16", S1, 10, position=0, new_leaf=0)
    dep("Prover-gap", "on S1: an opening deposit at the empty leaf 5, past the header's append index 2\n"
        "(a scheduler opening a position the keeper's scan never reaches): ok = 0, code 17", S1, 10, position=0, new_leaf=5)
    dep(
        "Prover-bad-state",
        "own book: position 1's collateral is 2^128: ok = 0, code 4",
        own({0: header(0, LIQ, LIQ, 2, 990), 1: position(TWO_128, 0, 991)}),
        10,
    )
    dep("Prover-not-open", "on S1: a deposit into the empty leaf 4, which only an opening (position 0)\n"
        "writes: ok = 0, code 5", S1, 10, position=4)
    dep("Prover-overflow", "on S1: 1,000 + (2^128 - 1000) collateral: ok = 0, code 7", S1, TWO_128 - 1000)
    dep("Prover-lender", "on LB: a deposit into the lender's position 1: ok = 0, code 5", LB, 10)
    dep("Prover-accrued", "on KK at block 100: Alice adds 10 to position 1, brought to the index first (debt\n"
        "800,004 at B' = 1,000,004,600): ok", KK, 10, clock=100)

    shared_cases()

    OUT.finish(f"gen-fixtures.py: DEPTH = {DEPTH}, PROBES = {PROBES}, WINDOW = {WINDOW}")
    if not OUT.check:
        print(f"gen-fixtures.py: DEPTH = {DEPTH}, PROBES = {PROBES}, WINDOW = {WINDOW}: written", file=sys.stderr)


main()
