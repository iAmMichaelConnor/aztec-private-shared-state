# shellcheck shell=bash
# Pinned tool paths and versions for this repository, and the helpers the
# scripts share. Source it from bash:
#
#   source "$(dirname "${BASH_SOURCE[0]}")/../scripts/toolchain.sh"
#
# Every version, download and repository pin comes from toolchain.json, the
# one place the pins live; it holds no machine paths. Every tool and source
# tree defaults to a place under TOOLS_DIR (default .tools/ in this
# repository, gitignored), where scripts/install-toolchain.sh puts them, and
# every default is overridden by the variable of the same name in the
# caller's environment. scripts/bootstrap.sh checks that the tools match.

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# pin <dotted key>: one value of toolchain.json (`pin total_noir.commit`),
# empty if it is missing.
pin() {
  python3 -I - "$REPO_ROOT/toolchain.json" "$1" <<'PY' 2>/dev/null || true
import json, sys
v = json.load(open(sys.argv[1]))
for k in sys.argv[2].split("."):
    v = v[k]
print(v)
PY
}

# nargo_git_dir <toolchain.json key>: where nargo caches the git dependency
# that key pins, $HOME/nargo/<host>/<owner>/<repo>/<tag>.
nargo_git_dir() {
  local repo
  repo="$(pin "$1.repository")"
  echo "$HOME/nargo/${repo#https://}/$(pin "$1.tag")"
}

# need_nargo <binary> <version>: fails unless the binary is that nargo.
# Exact match: a prefix match on "1.0.0" would also accept 1.0.0-rc.3.
need_nargo() {
  local got
  got="$("$1" --version 2>/dev/null | head -1 || true)"
  [[ $got == "nargo version = $2" ]] || { echo "need nargo $2 at $1 (got: ${got:-none})" >&2; return 1; }
}

# need_bb <binary> <version>: fails unless the binary is that bb.
need_bb() {
  local got
  got="$("$1" --version 2>/dev/null | head -1 || true)"
  [[ $got == "$2" ]] || { echo "need bb $2 at $1 (got: ${got:-none})" >&2; return 1; }
}

# The pins, read once: versions, and each tool's and source tree's place
# relative to TOOLS_DIR.
_pins="$(python3 -I - "$REPO_ROOT/toolchain.json" <<'PY'
import json, shlex, sys
t = json.load(open(sys.argv[1]))
values = {
    "_PIN_NARGO_BIN": t["tools"]["NARGO_BIN"]["path"],
    "_PIN_CONTRACT_NARGO_BIN": t["tools"]["CONTRACT_NARGO_BIN"]["path"],
    "_PIN_BB_BIN": t["tools"]["BB_BIN"]["path"],
    "_PIN_FOUNDRY_DIR": t["tools"]["FOUNDRY_DIR"]["path"],
    "_PIN_AZTEC_WORLD_DIR": t["worlds"]["AZTEC_WORLD_DIR"]["path"],
    "_PIN_FOUNDATION_WORLD_DIR": t["worlds"]["FOUNDATION_WORLD_DIR"]["path"],
    "_PIN_TOTAL_NOIR_COMMIT": t["total_noir"]["commit"],
    "NARGO_VERSION": t["noir"]["version"],
    "CONTRACT_NARGO_VERSION": t["contract_noir"]["version"],
    "BB_VERSION": t["co_noir"]["barretenberg"]["version"],
    "RUST_VERSION": t["rust"],
    "FOUNDRY_VERSION": t["foundry"],
    "NODE_MAJOR": t["node_major"],
}
for name, value in values.items():
    print(f"{name}={shlex.quote(str(value))}")
PY
)" || { echo "scripts/toolchain.sh: cannot read $REPO_ROOT/toolchain.json" >&2; return 1; }
eval "$_pins"

# TOOLS_DIR holds the pinned binaries, total-lint and the source trees
# (worlds/aztec-world, worlds/foundation-world) in the layout
# scripts/install-toolchain.sh writes. Point it at another directory of the
# same layout to share one install between checkouts; the single *_BIN and
# *_DIR variables below still override one entry each.
TOOLS_DIR="${TOOLS_DIR:-$REPO_ROOT/.tools}"

# Two Noir compilers, on purpose. NARGO_BIN (released Noir 1.0.0) compiles the
# round circuits, because the co-Noir nodes read the compiled ACIR with the
# Noir 1.0.0 crates; a circuit built by another compiler may not deserialize
# or may differ in opcodes. CONTRACT_NARGO_BIN (1.0.0-rc.3) compiles the Aztec
# contracts and runs the TXE, because aztec-nr v6.0.0 is released for it.
# Swapping either one breaks the side that depends on it.
NARGO_BIN="${NARGO_BIN:-$TOOLS_DIR/$_PIN_NARGO_BIN}"
CONTRACT_NARGO_BIN="${CONTRACT_NARGO_BIN:-$TOOLS_DIR/$_PIN_CONTRACT_NARGO_BIN}"

# BB_BIN is Barretenberg 6.0.0, the prover/verifier of the Aztec v6 release
# (verification keys, CRS reads, contract-side proof verification), the
# binary the @aztec-foundation/bb.js 6.0.0 package bundles. Another bb
# version produces keys and proofs the v6 contracts and nodes reject.
BB_BIN="${BB_BIN:-$TOOLS_DIR/$_PIN_BB_BIN}"

# FOUNDRY_DIR holds anvil, forge and cast 1.8.5 when install-toolchain.sh
# was run with --with-foundry; find_foundry also searches the usual places.
FOUNDRY_DIR="${FOUNDRY_DIR:-$TOOLS_DIR/$_PIN_FOUNDRY_DIR}"

# Rust 1.90.0 is the toolchain of the pinned co-snarks rev; the machine
# workspace builds with it. Foundry 1.8.5 is what the @aztec-labs 6.0.0 CLI
# deploys L1 contracts with (older forge rejects its flags); only the e2e
# needs it. Node 24 is the major bootstrap.sh requires, CI runs and every
# package.json declares in engines.

# deps/ links the two Aztec source worlds, not single packages: Nargo
# resolves dependency paths lexically, so the relative paths inside aztec-nr
# (to ../../../../foundation-world/...) only work if the worlds sit
# side by side under their own names. Nargo.toml files here point at
# deps/aztec-world/noir-projects/aztec-nr/aztec and
# deps/foundation-world/noir-projects/fnd/noir-protocol-circuits/crates/types.
# Another Aztec release means pointing both at that release's worlds
# together, moving CONTRACT_NARGO_BIN and BB_BIN to its compiler and prover,
# and accepting new contract ABIs and verification keys; mixing worlds from
# two releases breaks type identity.
AZTEC_WORLD_DIR="${AZTEC_WORLD_DIR:-$TOOLS_DIR/$_PIN_AZTEC_WORLD_DIR}"
FOUNDATION_WORLD_DIR="${FOUNDATION_WORLD_DIR:-$TOOLS_DIR/$_PIN_FOUNDATION_WORLD_DIR}"

# total-noir's `total` package is a Nargo git dependency of the tip
# packages, at the tag toolchain.json pins (total_noir.tag); nargo resolves it
# with no script run, and scripts/bootstrap.sh checks that every Nargo.toml
# names that tag and that nargo's cached copy is at total_noir.commit.
# TOTAL_LINT_BIN is total-lint from the same commit, which
# scripts/install-toolchain.sh installs (cargo install --git --rev) under
# TOOLS_DIR/total-lint/<commit>; scripts/check-noir.sh runs it on the round
# circuits. A binary set here is the caller's word that it was built from
# the pinned commit (the lint has no version flag).
TOTAL_LINT_BIN="${TOTAL_LINT_BIN:-$TOOLS_DIR/total-lint/$_PIN_TOTAL_NOIR_COMMIT/bin/total-lint}"

export REPO_ROOT TOOLS_DIR
export NARGO_BIN CONTRACT_NARGO_BIN BB_BIN TOTAL_LINT_BIN FOUNDRY_DIR AZTEC_WORLD_DIR FOUNDATION_WORLD_DIR
export NARGO_VERSION CONTRACT_NARGO_VERSION BB_VERSION RUST_VERSION FOUNDRY_VERSION NODE_MAJOR
unset _pins "${!_PIN_@}"

# find_foundry <tool>: the path of the first anvil, forge or cast at
# FOUNDRY_VERSION, from <TOOL>_BIN, else FOUNDRY_DIR, the @aztec-labs
# install, ~/.foundry/bin and PATH (the search order of @aztec-labs/ethereum
# after FOUNDRY_DIR); prints nothing and returns 1 if there is none.
find_foundry() {
  local tool=$1 var candidate candidates
  var="$(tr '[:lower:]' '[:upper:]' <<<"$tool")_BIN"
  if [[ -n ${!var:-} ]]; then
    # An explicit <TOOL>_BIN is the only candidate.
    candidates=("${!var}")
  else
    candidates=("$FOUNDRY_DIR/$tool" "$HOME/.aztec/current/internal-bin/$tool" \
      "$HOME/.foundry/bin/$tool" "$(command -v "$tool" 2>/dev/null || true)")
  fi
  for candidate in "${candidates[@]}"; do
    [[ -n $candidate && -x $candidate ]] || continue
    if [[ "$("$candidate" --version 2>/dev/null | head -n 1 || true)" == *"Version: $FOUNDRY_VERSION"* ]]; then
      echo "$candidate"
      return 0
    fi
  done
  return 1
}

# scratch_dir <variable> <prefix> [--sockets]: makes a new directory under
# the scratch root TXE_TMP_ROOT (default .runs/tmp in this repository,
# gitignored), stores its path in <variable>, and exports TXE_TMP_ROOT for
# the processes started later. Scripts point TMPDIR at their scratch
# directory, so nothing they or their children write lands in the system
# temp directory. With --sockets (the TXE, the local network and the e2e
# nodes bind Unix sockets below it) a root longer than 60 bytes warns: a
# socket path is limited to 107 bytes, so a deep root breaks them; set
# TXE_TMP_ROOT to a short directory then.
scratch_dir() {
  local var=$1 prefix=$2 sockets=${3:-} dir
  TXE_TMP_ROOT="${TXE_TMP_ROOT:-$REPO_ROOT/.runs/tmp}"
  mkdir -p "$TXE_TMP_ROOT" || return 1
  TXE_TMP_ROOT="$(cd "$TXE_TMP_ROOT" && pwd)"
  export TXE_TMP_ROOT
  if [[ $sockets == --sockets && ${#TXE_TMP_ROOT} -gt 60 ]]; then
    echo "warning: TXE_TMP_ROOT=$TXE_TMP_ROOT is ${#TXE_TMP_ROOT} bytes long; Unix sockets below it may exceed the 107-byte limit (set TXE_TMP_ROOT to a short directory)" >&2
  fi
  dir="$(mktemp -d "$TXE_TMP_ROOT/$prefix.XXXXXX")" || return 1
  printf -v "$var" '%s' "$dir"
}

# start_oracle_stub <dir>: starts scripts/oracle-stub.py (the TACEO_store
# oracle answered for `nargo execute`) on ORACLE_PORT (default: a free port),
# waits up to 5 s for it to write its URL to <dir>/oracle.url, and sets
# ORACLE_URL and ORACLE_PID. Returns 1 if it did not start. The caller kills
# ORACLE_PID when done (its EXIT trap).
start_oracle_stub() {
  local dir=$1
  python3 -I "$REPO_ROOT/scripts/oracle-stub.py" "${ORACLE_PORT:-0}" >"$dir/oracle.url" &
  ORACLE_PID=$!
  for _ in $(seq 50); do [[ -s $dir/oracle.url ]] && break; sleep 0.1; done
  ORACLE_URL="$(head -n 1 "$dir/oracle.url")"
  [[ $ORACLE_URL == http://* ]] || { echo "the oracle stub did not start" >&2; return 1; }
}

# load_circuits_env <example dir>: sources <example>/circuits/circuits.env
# (the packages an example declares; scripts/check-noir.sh documents the
# variables; machine/circuits/circuits.env also sets EMBEDDED) with every
# variable reset first, and splits them into the arrays circuits, libs,
# total_circuits, total_lib_src_extra and embedded.
load_circuits_env() {
  CIRCUITS="" LIBS="" TOTAL_CIRCUITS="" TOTAL_LIB_SRC="" EMBEDDED=""
  # shellcheck disable=SC1091
  source "$1/circuits/circuits.env"
  read -r -a circuits <<<"$CIRCUITS"
  read -r -a libs <<<"$LIBS"
  read -r -a total_circuits <<<"$TOTAL_CIRCUITS"
  read -r -a total_lib_src_extra <<<"$TOTAL_LIB_SRC"
  read -r -a embedded <<<"$EMBEDDED"
}
