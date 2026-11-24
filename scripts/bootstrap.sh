#!/usr/bin/env bash
# Prepare a checkout of this repository: check that every pinned tool is
# present at its exact version, create the gitignored deps/ links that the
# Nargo.toml files here point at, and check that the Nargo git dependencies
# (total-noir's total and, through it, noir-lang/sha256 and keccak256;
# noir-lang/schnorr, noir-lang/poseidon) are named at their pins and resolve
# there. Idempotent; runs from any directory; writes only deps/ inside the
# repository. Exit status 1 if a required tool or dependency source is
# wrong; missing Foundry tools only warn.
#
# The pinned tools and source trees default to TOOLS_DIR (.tools/ here),
# which scripts/install-toolchain.sh fills; every path can be overridden by
# its environment variable (named in each message). The pinned versions are
# in toolchain.json, which scripts/toolchain.sh reads.
set -euo pipefail

# shellcheck source=toolchain.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/toolchain.sh"

# The pinned versions live in toolchain.json only, and scripts/toolchain.sh
# reads them from there. The co-snarks rev in toolchain.json
# fixes the Noir crate versions the nodes read circuits with: at the pinned
# rev that is Noir 1.0.0, so NARGO_BIN must be nargo 1.0.0 and any direct
# noirc_abi or acir dependency must use noir-lang/noir tag v1.0.0. Moving the
# co-snarks rev means re-checking which Noir tag it depends on and moving
# NARGO_VERSION, those crate tags and RUST_VERSION with it.

fail=0
ok()   { printf 'ok    %s\n' "$*"; }
bad()  { printf 'FAIL  %s\n' "$*" >&2; fail=1; }
warn() { printf 'warn  %s\n' "$*" >&2; }

echo "== repository: $REPO_ROOT"
if [[ ! -d $TOOLS_DIR ]]; then
  echo "note  TOOLS_DIR=$TOOLS_DIR does not exist; run scripts/install-toolchain.sh to fetch the pinned tools there" >&2
fi

# ---- tools ------------------------------------------------------------------
# first_line <cmd...>: first line of the command's output, empty if it fails.
first_line() { { "$@" 2>/dev/null || true; } | head -n 1; }

# check_nargo <binary> <version> <role> <variable>
# Exact match: a prefix match on "1.0.0" would also accept 1.0.0-rc.3.
check_nargo() {
  local bin=$1 want=$2 role=$3 var=$4 got
  if [[ ! -x $bin ]]; then
    bad "nargo for $role: $bin is not an executable; run scripts/install-toolchain.sh or set $var to nargo $want"
    return
  fi
  got="$(first_line "$bin" --version)"
  if [[ $got == "nargo version = $want" ]]; then
    ok "nargo $want for $role ($var=$bin)"
  else
    bad "nargo for $role must be $want, $bin reports '${got:-nothing}'; set $var"
  fi
}
check_nargo "$NARGO_BIN" "$NARGO_VERSION" "round circuits" NARGO_BIN
check_nargo "$CONTRACT_NARGO_BIN" "$CONTRACT_NARGO_VERSION" "contracts and TXE" CONTRACT_NARGO_BIN

if [[ ! -x $BB_BIN ]]; then
  bad "bb: $BB_BIN is not an executable; run scripts/install-toolchain.sh or set BB_BIN to bb $BB_VERSION"
else
  got="$(first_line "$BB_BIN" --version)"
  if [[ $got == "$BB_VERSION" ]]; then
    ok "bb $BB_VERSION (BB_BIN=$BB_BIN)"
  else
    bad "bb must be $BB_VERSION, $BB_BIN reports '${got:-nothing}'; set BB_BIN"
  fi
fi

# Rust: the pinned toolchain through rustup when rustup is installed (the
# machine workspace selects it with rust-toolchain.toml), else rustc/cargo on
# PATH. RUSTC_BIN and CARGO_BIN override both.
for tool in rustc cargo; do
  var="$(tr '[:lower:]' '[:upper:]' <<<"$tool")_BIN"
  bin="${!var:-}"
  if [[ -z $bin ]]; then
    if command -v rustup >/dev/null; then
      bin="$(rustup which --toolchain "$RUST_VERSION" "$tool" 2>/dev/null || true)"
    else
      bin="$(command -v "$tool" || true)"
    fi
  fi
  if [[ -z $bin || ! -x $bin ]]; then
    bad "$tool $RUST_VERSION not found; run 'rustup toolchain install $RUST_VERSION' or set $var"
    continue
  fi
  got="$(first_line "$bin" --version)"
  if [[ $got == "$tool $RUST_VERSION "* ]]; then
    ok "$tool $RUST_VERSION ($bin)"
  else
    bad "$tool must be $RUST_VERSION, $bin reports '${got:-nothing}'; set $var"
  fi
done

NODE_BIN="${NODE_BIN:-$(command -v node || true)}"
if [[ -z $NODE_BIN || ! -x $NODE_BIN ]]; then
  bad "node $NODE_MAJOR not found; install it or set NODE_BIN"
else
  got="$(first_line "$NODE_BIN" --version)"
  major="${got#v}"; major="${major%%.*}"
  if [[ $major =~ ^[0-9]+$ ]] && (( major >= NODE_MAJOR )); then
    ok "node $got ($NODE_BIN)"
  else
    bad "node must be $NODE_MAJOR or later (the packages' engines), $NODE_BIN reports '${got:-nothing}'; set NODE_BIN"
  fi
fi

# Docker runs the per-node Postgres containers.
DOCKER_BIN="${DOCKER_BIN:-$(command -v docker || true)}"
if [[ -n $DOCKER_BIN && -x $DOCKER_BIN ]]; then
  ok "docker ($DOCKER_BIN)"
else
  bad "docker not found (runs the nodes' Postgres); install it or set DOCKER_BIN"
fi

# Foundry is only needed by the e2e (the @aztec-labs CLI deploys the L1
# contracts with it), so a missing or wrong Foundry warns instead of failing.
# find_foundry (scripts/toolchain.sh) takes ANVIL_BIN/FORGE_BIN/CAST_BIN,
# else searches FOUNDRY_DIR, ~/.aztec, ~/.foundry/bin, then PATH.
for tool in anvil forge cast; do
  if bin="$(find_foundry "$tool")"; then
    ok "$tool $FOUNDRY_VERSION ($bin)"
  else
    var="$(tr '[:lower:]' '[:upper:]' <<<"$tool")_BIN"
    warn "$tool $FOUNDRY_VERSION not found (needed by the e2e only); run scripts/install-toolchain.sh --with-foundry or set $var"
  fi
done

# total-lint from total-noir at total_noir.commit (scripts/check-noir.sh runs
# it on every round circuit). cargo install records the source revision in
# the install root's .crates.toml, which the default place has; a
# TOTAL_LINT_BIN set elsewhere is taken on the caller's word.
want="$(pin total_noir.commit)"
if [[ ! -x $TOTAL_LINT_BIN ]]; then
  bad "total-lint: $TOTAL_LINT_BIN is not an executable; run scripts/install-toolchain.sh or set TOTAL_LINT_BIN"
elif [[ $TOTAL_LINT_BIN == "$TOOLS_DIR/total-lint/$want/bin/total-lint" ]]; then
  if grep -qs "rev=$want#" "$TOOLS_DIR/total-lint/$want/.crates.toml"; then
    ok "total-lint from total-noir $want (TOTAL_LINT_BIN=$TOTAL_LINT_BIN)"
  else
    bad "total-lint: $TOOLS_DIR/total-lint/$want/.crates.toml does not name total-noir $want; rerun scripts/install-toolchain.sh"
  fi
else
  ok "total-lint (TOTAL_LINT_BIN=$TOTAL_LINT_BIN, taken as built from total-noir $want)"
fi

# ---- deps/ links ------------------------------------------------------------
# link_world <link name> <target> <variable> <Nargo.toml inside target> <package name>
link_world() {
  local name=$1 target=$2 var=$3 manifest=$4 pkg=$5 link="$REPO_ROOT/deps/$1"
  if [[ ! -d $target ]]; then
    bad "deps/$name: $target does not exist; run scripts/install-toolchain.sh or set $var"
    return
  fi
  if ! grep -qs "^name = \"$pkg\"" "$target/$manifest"; then
    bad "deps/$name: $target/$manifest is missing or is not package '$pkg'; set $var"
    return
  fi
  target="$(cd "$target" && pwd)"
  if [[ -e $link && ! -L $link ]]; then
    bad "deps/$name exists and is not a symlink; remove it and rerun"
    return
  fi
  if [[ -L $link && "$(readlink "$link")" == "$target" ]]; then
    ok "deps/$name -> $target (unchanged)"
  else
    mkdir -p "$REPO_ROOT/deps"
    ln -sfn "$target" "$link"
    ok "deps/$name -> $target (linked)"
  fi
}
AZTEC_PKG=noir-projects/aztec-nr/aztec
TYPES_PKG=noir-projects/fnd/noir-protocol-circuits/crates/types
link_world aztec-world "$AZTEC_WORLD_DIR" AZTEC_WORLD_DIR "$AZTEC_PKG/Nargo.toml" noir_aztec
link_world foundation-world "$FOUNDATION_WORLD_DIR" FOUNDATION_WORLD_DIR "$TYPES_PKG/Nargo.toml" types

# aztec-nr reaches protocol_types by a relative path. Resolved lexically from
# deps/, as Nargo resolves it, it must land on the foundation world's types.
rel="$(sed -n 's/^protocol_types = { *path = "\([^"]*\)".*/\1/p' \
  "$REPO_ROOT/deps/aztec-world/$AZTEC_PKG/Nargo.toml" 2>/dev/null || true)"
if [[ -n $rel ]]; then
  lexical="$(python3 -c 'import os, sys; print(os.path.normpath(os.path.join(*sys.argv[1:])))' \
    "$REPO_ROOT/deps/aztec-world/$AZTEC_PKG" "$rel")"
  if [[ $lexical == "$REPO_ROOT/deps/foundation-world/$TYPES_PKG" ]]; then
    ok "aztec-nr's protocol_types path resolves to deps/foundation-world"
  else
    bad "aztec-nr's protocol_types path ($rel) resolves to $lexical, not deps/foundation-world/$TYPES_PKG"
  fi
fi

# ---- the Nargo git dependencies resolve --------------------------------------
# The tip packages take total-noir's total (which takes noir-lang/sha256 and
# noir-lang/keccak256), pss_public_contract noir-lang/schnorr, and
# sidecar_register noir-lang/poseidon, as Nargo git dependencies at their
# tags. Nargo pins a git dependency by tag (or branch) only: it clones it
# into $HOME/nargo/<host>/<owner>/<repo>/<tag> on first use and reuses that
# copy without checking it again. So, for each, toolchain.json records the
# commit the tag named: a cached copy must be at it (a copy at another commit
# fails, since Nargo would build with it, and a moved tag is noticed); with no
# cached copy, the tag must be reachable on the remote and name it, and Nargo
# fetches it at the first nargo check. This script only reads the cache; it
# never writes it.
git_dep() { # git_dep <toolchain.json key> <package name> [<package directory>]
  local key=$1 package=$2 dir=${3:-.} repo tag want cache got refs
  repo="$(pin "$key.repository")" tag="$(pin "$key.tag")" want="$(pin "$key.commit")"
  if [[ -z $repo || -z $tag || -z $want ]]; then
    bad "toolchain.json lacks $key.repository, $key.tag or $key.commit"
    return
  fi
  cache="$(nargo_git_dir "$key")"
  if [[ -d $cache ]]; then
    got="$(git -C "$cache" rev-parse 'HEAD^{commit}' 2>/dev/null || true)"
    if ! grep -qs "^name = \"$package\"" "$cache/$dir/Nargo.toml"; then
      bad "$package $tag: $cache/$dir/Nargo.toml is missing or is not package '$package'"
    elif [[ $got == "$want" ]]; then
      ok "$package $tag at $want (nargo's cache, $cache)"
    else
      bad "$package $tag: nargo's cached copy $cache is at '${got:-unknown}', not the pinned $want"
    fi
  elif ! command -v git >/dev/null; then
    bad "$package $tag: no cached copy at $cache and git not found to fetch it"
  else
    refs="$(timeout 60 git ls-remote "$repo" "refs/tags/$tag" "refs/tags/$tag^{}" "refs/heads/$tag" 2>/dev/null || true)"
    got="$(awk -v t="refs/tags/$tag" -v h="refs/heads/$tag" '$2 == t "^{}" {p = $1} $2 == t || $2 == h {l = $1} END {print (p != "" ? p : l)}' <<<"$refs")"
    if [[ $got == "$want" ]]; then
      ok "$package $tag at $want (reachable at $repo; nargo fetches it on first use)"
    else
      bad "$package $tag: no cached copy at $cache, and $repo gives '${got:-nothing}' for the tag, not the pinned $want"
    fi
  fi
}
git_dep total_noir total "$(pin total_noir.package)"
git_dep sha256 sha256
git_dep keccak256 keccak256
git_dep schnorr schnorr
git_dep poseidon poseidon

# Every Nargo.toml here that takes one of those repositories names it at the
# pinned tag (and total at its package directory), so toolchain.json holds
# the one pin: a package at another tag would build against another copy.
if out="$(python3 -I - "$REPO_ROOT" <<'EOF' 2>&1
import json, os, sys, tomllib
root = sys.argv[1]
pins = json.load(open(os.path.join(root, "toolchain.json")))
want, by_name = {}, {}
for name, key in (("total", "total_noir"), ("sha256", "sha256"), ("keccak256", "keccak256"),
                  ("schnorr", "schnorr"), ("poseidon", "poseidon")):
    pin = (pins[key]["repository"].rstrip("/"), pins[key]["tag"], pins[key].get("package"))
    want[pin[0]] = by_name[name] = pin
skip = {".git", "deps", "target", "node_modules", ".tools", ".runs"}
bad, seen = [], 0
for d, dirs, files in os.walk(root):
    dirs[:] = [x for x in dirs if x not in skip]
    if "Nargo.toml" not in files:
        continue
    path = os.path.join(d, "Nargo.toml")
    with open(path, "rb") as f:
        deps = tomllib.load(f).get("dependencies", {})
    for name, spec in deps.items():
        spec = spec if isinstance(spec, dict) else {}
        repo = spec.get("git", "").rstrip("/")
        if repo not in want and name not in by_name:
            continue
        seen += 1
        pinned_repo, tag, package = want.get(repo) or by_name[name]
        rel = os.path.relpath(path, root)
        if repo != pinned_repo:
            bad.append(f"{rel}: {name} is not the git dependency {pinned_repo}")
        elif spec.get("tag") != tag:
            bad.append(f"{rel}: {name} at tag {spec.get('tag')!r}, not the pinned {tag!r}")
        elif package and spec.get("directory") != package:
            bad.append(f"{rel}: {name} at directory {spec.get('directory')!r}, not {package!r}")
print("\n".join(bad) if bad else f"{seen} dependencies, each at its pinned tag")
sys.exit(1 if bad else 0)
EOF
)"; then
  ok "Nargo.toml git dependencies: $out"
else
  bad "Nargo.toml git dependencies off their pins in toolchain.json:"$'\n'"$out"
fi

if (( fail )); then
  echo "bootstrap.sh: FAIL" >&2
  exit 1
fi
echo "bootstrap.sh: PASS"
