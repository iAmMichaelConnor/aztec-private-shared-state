#!/usr/bin/env python3
"""Fail when a pin copied outside toolchain.json disagrees with it.

toolchain.json is the one place the pins live, but some files cannot read it
and carry a copy: the workflows and their local actions (the Rust toolchain,
Node, cargo-nextest, the Postgres image), machine/rust-toolchain.toml and machine/Cargo.toml (Rust, the
co-snarks rev), every package.json (the @aztec-labs version, Node in
`engines`) and the machine's Postgres test fixture. This script finds each
copy in the tracked files and compares it with toolchain.json, and the Aztec
packages of scripts/txe's own lockfile with the root lockfile's:

    python3 -I scripts/check-pins.py

Exit status 1 names every disagreement.
"""

import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PINS = json.loads((ROOT / "toolchain.json").read_text())
RUST = PINS["rust"]
NODE = str(PINS["node_major"])
NEXTEST = PINS["cargo_nextest"]
POSTGRES = PINS["postgres"]["image"]
LABS = PINS["labs"]["sdk_version"]
LABS_SCOPE = PINS["labs"]["scope"] + "/"
CO_SNARKS = PINS["co_noir"]

errors = []
checked = 0


def tracked(*patterns):
    out = subprocess.run(["git", "ls-files", "-z", "--", *patterns], cwd=ROOT, capture_output=True, check=True)
    return [ROOT / p for p in out.stdout.decode().split("\0") if p]


def expect(where, what, got, want, source="toolchain.json pins"):
    global checked
    checked += 1
    if got != want:
        errors.append(f"{where}: {what} is {got!r}, {source} {want!r}")


def lines(path):
    return enumerate(path.read_text().splitlines(), 1)


# The workflows and their local actions: each Rust toolchain (the input and
# the action's version comment), Node version and cargo-nextest install.
for wf in tracked(".github/workflows/*.yml", ".github/workflows/*.yaml", ".github/actions/*/action.yml"):
    rel = wf.relative_to(ROOT)
    for n, line in lines(wf):
        where = f"{rel}:{n}"
        if m := re.match(r'\s*toolchain:\s*"?([^"\s#]+)', line):
            expect(where, "the Rust toolchain", m.group(1), RUST)
        if m := re.search(r"dtolnay/rust-toolchain@[0-9a-f]{40}\s*#\s*(\S+)", line):
            expect(where, "the rust-toolchain action's version comment", m.group(1), RUST)
        if m := re.match(r'\s*node-version:\s*"?([^"\s#]+)', line):
            expect(where, "the Node version", m.group(1), NODE)
        if m := re.match(r"\s*tool:\s*cargo-nextest(@\S+)?", line):
            expect(where, "the cargo-nextest version", (m.group(1) or "@(none)")[1:], NEXTEST)

# The Postgres image, wherever a tracked file names one by tag.
grep = subprocess.run(
    ["git", "grep", "-n", "-I", "-o", "-E", r"postgres:[0-9][[:alnum:]_.-]*(@sha256:[0-9a-f]{64})?", "--", "."],
    cwd=ROOT,
    capture_output=True,
    text=True,
)
for hit in grep.stdout.splitlines():
    path, n, image = hit.split(":", 2)
    expect(f"{path}:{n}", "the Postgres image", image, POSTGRES)

# Rust in the machine workspace.
toolchain_toml = ROOT / "machine/rust-toolchain.toml"
m = re.search(r'^channel\s*=\s*"([^"]+)"', toolchain_toml.read_text(), re.M)
expect("machine/rust-toolchain.toml", "channel", m and m.group(1), RUST)
cargo_toml = ROOT / "machine/Cargo.toml"
for n, line in lines(cargo_toml):
    where = f"machine/Cargo.toml:{n}"
    if m := re.match(r'\s*rust-version\s*=\s*"([^"]+)"', line):
        expect(where, "rust-version", m.group(1), ".".join(RUST.split(".")[:2]))
    if "co-snarks" in line and (m := re.search(r'git\s*=\s*"([^"]+)".*rev\s*=\s*"([^"]+)"', line)):
        expect(where, "the co-snarks repository", m.group(1), CO_SNARKS["repository"])
        expect(where, "the co-snarks rev", m.group(2), CO_SNARKS["git_commit"])

# Every package.json: the @aztec-labs packages at the SDK version, and Node in
# engines.
for pkg in tracked("package.json", "*/package.json"):
    rel = pkg.relative_to(ROOT)
    data = json.loads(pkg.read_text())
    for field in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
        for name, version in data.get(field, {}).items():
            if name.startswith(LABS_SCOPE):
                expect(rel, f"{field}.{name}", version, LABS)
    expect(rel, "engines.node", data.get("engines", {}).get("node"), f">={NODE}")

# scripts/txe keeps a lockfile of its own, so the nightly TXE job installs the
# TXE without the workspace. Its third-party transitive versions drift from
# the root lockfile's (each was resolved on its own day), which changes no
# behaviour the gates rely on; its Aztec packages, which decide what the TXE
# executes, must be the root lockfile's exactly.
root_lock = json.loads((ROOT / "package-lock.json").read_text())["packages"]
txe_lock = json.loads((ROOT / "scripts/txe/package-lock.json").read_text())["packages"]
for path, entry in txe_lock.items():
    if path.removeprefix("node_modules/").startswith(("@aztec-labs/", "@aztec-foundation/")):
        root = root_lock.get(path, {})
        for key in ("version", "integrity"):
            expect(f"scripts/txe/package-lock.json {path}", key, entry.get(key), root.get(key), "the root package-lock.json has")

if errors:
    print("\n".join(errors), file=sys.stderr)
    sys.exit(f"check-pins.py: {len(errors)} of {checked} copied pins disagree")
print(f"check-pins.py: {checked} copied pins agree with toolchain.json and the root lockfile")
