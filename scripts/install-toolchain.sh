#!/usr/bin/env bash
# Fetch every pinned tool and source tree of toolchain.json into TOOLS_DIR
# (default .tools/ in this repository, gitignored):
#
#   noir-1.0.0/nargo             nargo 1.0.0, the round circuits' compiler
#   noir-1.0.0-rc.3/nargo        nargo 1.0.0-rc.3, the contracts' and the TXE's
#   bb-6.0.0/bb                  bb 6.0.0, the binary bb.js 6.0.0 bundles
#   worlds/aztec-world           aztec-labs-eng/aztec-node at worlds.AZTEC_WORLD_DIR.commit (noir-projects only)
#   worlds/foundation-world      AztecProtocol/aztec-packages at v6.0.0 (noir-projects only)
#   total-lint/<commit>/bin/total-lint  total-lint from total-noir at
#                                total_noir.commit (cargo install --git --rev)
#   foundry-1.8.5/{anvil,forge,cast}  with --with-foundry (the e2e only)
#
# Each download is checked against the sha256 in toolchain.json (the archive,
# then the binary taken from it), total-lint is built by cargo from the
# pinned commit with its Cargo.lock (--locked), and each source tree is a git
# checkout of the pinned commit (shallow, blobs fetched on demand, sparse where
# toolchain.json says). Idempotent: a binary with the pinned hash and a tree
# at the pinned commit are kept. Writes only under TOOLS_DIR; then
# scripts/bootstrap.sh checks the versions and links deps/. Linux x86_64 only.
#
# total-noir's `total` package itself is not fetched here: it is a Nargo git
# dependency, which nargo clones into its cache on first use.
#
# Usage: scripts/install-toolchain.sh [--with-foundry]
# Environment (all optional): TOOLS_DIR, CARGO_BIN (the cargo that builds
# total-lint; default `rustup run <rust pin> cargo`, else cargo on PATH).
set -euo pipefail

SCRIPTS="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Only for REPO_ROOT, TOOLS_DIR and pin: the destinations below are the
# default places under TOOLS_DIR, whatever *_BIN or *_DIR the caller set.
# shellcheck source=toolchain.sh
source "$SCRIPTS/toolchain.sh"

with_foundry=0
while (($#)); do
  case $1 in
    --with-foundry) with_foundry=1 ;;
    -h|--help) sed -n '2,/^set -euo/{/^set -euo/d;s/^# \{0,1\}//;p}' "$0"; exit 0 ;;
    *) echo "usage: scripts/install-toolchain.sh [--with-foundry]" >&2; exit 2 ;;
  esac
  shift
done

[[ "$(uname -s)-$(uname -m)" == Linux-x86_64 ]] \
  || { echo "install-toolchain.sh: toolchain.json pins x86_64 Linux builds only (this is $(uname -s) $(uname -m))" >&2; exit 1; }
for cmd in curl tar sha256sum git python3; do
  command -v "$cmd" >/dev/null || { echo "install-toolchain.sh: $cmd not found" >&2; exit 1; }
done

mkdir -p "$TOOLS_DIR"
TOOLS_DIR="$(cd "$TOOLS_DIR" && pwd)"
DOWNLOADS="$TOOLS_DIR/.download"
cleanup() { rm -rf "$DOWNLOADS"; }
trap cleanup EXIT

sha256_of() { sha256sum "$1" | cut -d ' ' -f 1; }

# download <url> <sha256> <dest>: fetches the file and fails unless its
# sha256 is the pinned one.
download() {
  local url=$1 want=$2 dest=$3 got
  echo "   download $url"
  curl -fsSL --retry 3 --retry-delay 2 -o "$dest" "$url" \
    || { echo "install-toolchain.sh: cannot download $url" >&2; return 1; }
  got="$(sha256_of "$dest")"
  [[ $got == "$want" ]] \
    || { echo "install-toolchain.sh: $url has sha256 $got, not the pinned $want" >&2; return 1; }
}

# install_binary <key under tools>: one binary taken from a pinned archive.
install_binary() {
  local key=$1 url sha member member_sha dest work got
  url="$(pin "tools.$key.url")" sha="$(pin "tools.$key.sha256")"
  member="$(pin "tools.$key.member")" member_sha="$(pin "tools.$key.member_sha256")"
  dest="$TOOLS_DIR/$(pin "tools.$key.path")"
  echo "== $key $(pin "tools.$key.version") -> $dest"
  if [[ -f $dest && "$(sha256_of "$dest")" == "$member_sha" ]]; then
    echo "   present with the pinned sha256; kept"
    return 0
  fi
  work="$DOWNLOADS/$key"
  rm -rf "$work"
  mkdir -p "$work/x" "${dest%/*}"
  download "$url" "$sha" "$work/archive"
  # The whole archive: members are stored as ./nargo in one and package/... in another.
  tar -xzf "$work/archive" -C "$work/x"
  got="$(sha256_of "$work/x/$member")"
  [[ $got == "$member_sha" ]] \
    || { echo "install-toolchain.sh: $member in $url has sha256 $got, not the pinned $member_sha" >&2; return 1; }
  install -m 0755 "$work/x/$member" "$dest.new"
  mv -f "$dest.new" "$dest"
  rm -rf "$work"
  echo "   installed: $("$dest" --version 2>&1 | head -n 1)"
}

# install_foundry: anvil, forge and cast from the pinned Foundry archive.
install_foundry() {
  local url sha dest work version members tool
  url="$(pin tools.FOUNDRY_DIR.url)" sha="$(pin tools.FOUNDRY_DIR.sha256)"
  version="$(pin tools.FOUNDRY_DIR.version)" dest="$TOOLS_DIR/$(pin tools.FOUNDRY_DIR.path)"
  read -r -a members <<<"$(python3 -I -c 'import json, sys; print(" ".join(json.load(open(sys.argv[1]))["tools"]["FOUNDRY_DIR"]["members"]))' "$REPO_ROOT/toolchain.json")"
  echo "== Foundry $version -> $dest"
  if [[ -f $dest/.archive-sha256 && "$(cat "$dest/.archive-sha256")" == "$sha" ]]; then
    echo "   present from the pinned archive; kept"
    return 0
  fi
  work="$DOWNLOADS/foundry"
  rm -rf "$work"
  mkdir -p "$work/x" "$dest"
  download "$url" "$sha" "$work/archive"
  tar -xzf "$work/archive" -C "$work/x"
  for tool in "${members[@]}"; do
    install -m 0755 "$work/x/$tool" "$dest/$tool"
    [[ "$("$dest/$tool" --version 2>/dev/null | head -n 1)" == *"Version: $version"* ]] \
      || { echo "install-toolchain.sh: $dest/$tool does not report Version: $version" >&2; return 1; }
  done
  echo "$sha" >"$dest/.archive-sha256"
  rm -rf "$work"
  echo "   installed: ${members[*]}"
}

# install_total_lint: total-lint from total-noir at total_noir.commit, with
# cargo install --git --rev --locked into TOOLS_DIR/total-lint/<commit> (the
# place scripts/toolchain.sh's TOTAL_LINT_BIN defaults to). cargo records the
# source and revision in <root>/.crates.toml; an install that names the
# pinned commit is kept.
install_total_lint() {
  local repo commit root cargo=() got
  repo="$(pin total_noir.repository)" commit="$(pin total_noir.commit)"
  root="$TOOLS_DIR/total-lint/$commit"
  echo "== total-lint from $repo at $commit -> $root"
  if [[ -x $root/bin/total-lint ]] && grep -qs "rev=$commit#" "$root/.crates.toml"; then
    echo "   present from the pinned commit; kept"
    return 0
  fi
  if [[ -n ${CARGO_BIN:-} ]]; then
    cargo=("$CARGO_BIN")
  elif command -v rustup >/dev/null; then
    cargo=(rustup run "$(pin rust)" cargo)
  else
    cargo=(cargo)
  fi
  got="$("${cargo[@]}" --version 2>/dev/null | head -n 1 || true)"
  [[ $got == "cargo $(pin rust) "* ]] \
    || { echo "install-toolchain.sh: total-lint needs cargo $(pin rust) (got: ${got:-none}); set CARGO_BIN" >&2; return 1; }
  "${cargo[@]}" install --quiet --locked --force --git "$repo" --rev "$commit" \
    --root "$root" --target-dir "$DOWNLOADS/total-lint" total-lint
  echo "   installed with $got"
}

# clone_tree <key under worlds> <repository>: a git checkout of the pinned
# commit at the default place, shallow, sparse to the listed paths (cone
# mode) with blobs fetched on demand when the key lists sparse paths, then
# the key's patch applied.
clone_tree() {
  local key=$1 repo=$2 commit dest sparse=() head start=$SECONDS
  commit="$(pin "worlds.$key.commit")" dest="$TOOLS_DIR/$(pin "worlds.$key.path")"
  read -r -a sparse <<<"$(python3 -I -c 'import json, sys; print(" ".join(json.load(open(sys.argv[1]))["worlds"][sys.argv[2]].get("sparse", [])))' "$REPO_ROOT/toolchain.json" "$key")"
  echo "== $key: $repo at $commit -> $dest"
  if [[ -e $dest && ! -d $dest/.git ]]; then
    echo "install-toolchain.sh: $dest exists and is not a git checkout; move it away and rerun" >&2
    return 1
  fi
  if [[ ! -d $dest/.git ]]; then
    mkdir -p "$dest"
    git -C "$dest" init -q
    git -C "$dest" remote add origin "$repo"
    if ((${#sparse[@]})); then
      git -C "$dest" config remote.origin.promisor true
      git -C "$dest" config remote.origin.partialclonefilter blob:none
      git -C "$dest" sparse-checkout set --cone "${sparse[@]}"
    fi
  else
    git -C "$dest" remote set-url origin "$repo"
  fi
  head="$(git -C "$dest" rev-parse -q --verify 'HEAD^{commit}' 2>/dev/null || true)"
  if [[ $head == "$commit" ]]; then
    echo "   at the pinned commit; kept"
  else
    local filter=()
    ((${#sparse[@]})) && filter=(--filter=blob:none)
    git -C "$dest" fetch -q --depth 1 "${filter[@]}" origin "$commit"
    git -C "$dest" -c advice.detachedHead=false checkout -q --force FETCH_HEAD
    [[ "$(git -C "$dest" rev-parse 'HEAD^{commit}')" == "$commit" ]] \
      || { echo "install-toolchain.sh: $dest is not at $commit after the checkout" >&2; return 1; }
    echo "   checked out in $((SECONDS - start)) s"
  fi
  apply_patch "$key" "$dest"
  echo "   $(du -sh "$dest" | cut -f 1) on disk"
}

# apply_patch <key under worlds> <dest>: the key's one-line patch (a line
# matching "replace" becomes "with" in "file"), idempotent; fails unless the
# file then holds the replacement exactly once.
apply_patch() {
  python3 -I - "$REPO_ROOT/toolchain.json" "$1" "$2" <<'PY'
import json, pathlib, re, sys
spec = json.load(open(sys.argv[1]))["worlds"][sys.argv[2]].get("patch")
if spec:
    path = pathlib.Path(sys.argv[3]) / spec["file"]
    text = path.read_text()
    new, n = re.subn(spec["replace"], lambda _: spec["with"], text, flags=re.M)
    if n != 1 or new.splitlines().count(spec["with"]) != 1:
        sys.exit(f"install-toolchain.sh: cannot apply the patch to {path} ({n} matches)")
    if new != text:
        path.write_text(new)
        print(f"   patched {spec['file']}: {spec['why']}")
    else:
        print(f"   {spec['file']} already patched")
PY
}

total_start=$SECONDS
install_binary NARGO_BIN
install_binary CONTRACT_NARGO_BIN
install_binary BB_BIN
((with_foundry)) && install_foundry
clone_tree AZTEC_WORLD_DIR "$(pin worlds.AZTEC_WORLD_DIR.repository)"
clone_tree FOUNDATION_WORLD_DIR "$(pin worlds.FOUNDATION_WORLD_DIR.repository)"
install_total_lint
echo "install-toolchain.sh: done in $((SECONDS - total_start)) s ($TOOLS_DIR, $(du -sh "$TOOLS_DIR" | cut -f 1)); next: scripts/bootstrap.sh"
