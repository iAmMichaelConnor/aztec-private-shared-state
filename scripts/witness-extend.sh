#!/usr/bin/env bash
# Run a co-noir three-party (REP3) witness extension of every fixture of an
# example's round circuits and report pass or fail per fixture: the check
# that a round runs in the network's MPC solver, which scripts/check-noir.sh
# (plain nargo, and total-lint's --brillig-ops report) does not make.
#
#   scripts/witness-extend.sh [--shard <k>/<n>] <example dir>     e.g. examples/lending-tip
#
# --shard <k>/<n> runs the k-th of n parts: of the example's fixtures, in the
# order below, every n-th from the k-th, so the n shards together run each
# fixture once (CI splits lending-tip's this way, docs/TESTING.md).
#
# For every circuit of <example>/circuits/circuits.env (CIRCUITS) and every
# Prover*.toml beside it:
#   1. nargo execute solves the fixture in the clear (the TACEO_store oracle
#      answered by scripts/oracle-stub.py), writing the circuit's artifact
#      and nargo's witness;
#   2. machine/sidecar-core/examples/witness_extend.rs deals the fixture's
#      inputs to three in-process co-noir parties and runs
#      co_noir::execute_circuit_rep3, the nodes' witness extension, then
#      opens the parties' witness and compares it with nargo's, element by
#      element.
# The split is the network's: the parameters the round's manifest
# (<example>/manifests/<circuit>.json) fills from the nodes (LOAD, SAMPLE,
# INPUT_SHARED) are secret-shared, the PUBLIC ones public. A circuit with no
# manifest shares its ABI's private parameters (co-noir split-input's
# split). The circuits run as committed: a tree round's depth and probe
# width are the ones its source and manifest hold, printed per circuit.
#
# Nargo is NARGO_BIN from scripts/toolchain.sh (Noir 1.0.0, checked
# exactly); the checker is built with cargo (release, the worktree's
# machine/target). Temporary files go to a scratch directory under
# TXE_TMP_ROOT (default .runs/tmp), removed on exit; nargo's
# witnesses are written to each circuit's target/ and removed after use.
# Exit 0 only if every fixture passes.
set -euo pipefail

SCRIPTS="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=toolchain.sh
source "$SCRIPTS/toolchain.sh"

usage() { echo "usage: scripts/witness-extend.sh [--shard <k>/<n>] <example dir>" >&2; exit 2; }
shard_k=1 shard_n=1
if [[ ${1:-} == --shard ]]; then
  [[ ${2:-} =~ ^([1-9][0-9]*)/([1-9][0-9]*)$ ]] && ((BASH_REMATCH[1] <= BASH_REMATCH[2])) || usage
  shard_k=${BASH_REMATCH[1]} shard_n=${BASH_REMATCH[2]}
  shift 2
fi
(($# == 1)) || usage
EXAMPLE="$(cd "$1" && pwd)"
[[ -f $EXAMPLE/circuits/circuits.env ]] || { echo "no $EXAMPLE/circuits/circuits.env" >&2; exit 2; }

need_nargo "$NARGO_BIN" "$NARGO_VERSION" || exit 1
command -v jq >/dev/null || { echo "need jq" >&2; exit 1; }

scratch_dir WORK witness-extend
export TMPDIR="$WORK"
ORACLE_PID=""
cleanup() { [[ -n $ORACLE_PID ]] && kill "$ORACLE_PID" 2>/dev/null; rm -rf "$WORK"; }
trap cleanup EXIT

echo "== the checker (cargo build --release -p sidecar-core --example witness_extend)"
(cd "$REPO_ROOT/machine" && nice -n 19 ionice -c 3 timeout 3600 \
  cargo build --release -p sidecar-core --example witness_extend) >"$WORK/build.log" 2>&1 \
  || { tail -n 30 "$WORK/build.log" >&2; echo "the checker did not build" >&2; exit 1; }
CHECK="$REPO_ROOT/machine/target/release/examples/witness_extend"

start_oracle_stub "$WORK"
URL=$ORACLE_URL

load_circuits_env "$EXAMPLE"

pass=0
fail=0
index=0   # the fixture's place in the example's order, for --shard
for c in "${circuits[@]}"; do
  dir="$EXAMPLE/circuits/$c"
  manifest="$EXAMPLE/manifests/$c.json"
  if [[ -f $manifest ]]; then
    shared="$(jq -r '[.witness[] | select((.from | keys[0]) != "PUBLIC") | .param] | join(",")' "$manifest")"
    split="manifest: shared ${shared:-none}"
    tree="$(jq -r '[.tree // {} | to_entries[] | "\(.key) depth \(.value.depth) probe \(.value.probe)"] | unique | join("; ")' "$manifest")"
    [[ -n $tree ]] && split="$split; tree $tree"
  else
    shared=""
    split="no manifest: the ABI's private parameters shared"
  fi
  echo "== $c ($split)"
  shopt -s nullglob
  fixtures=("$dir"/Prover*.toml)
  shopt -u nullglob
  ((${#fixtures[@]})) || { echo "$c: no Prover*.toml"; fail=$((fail + 1)); continue; }
  for f in "${fixtures[@]}"; do
    index=$((index + 1))
    (((index - 1) % shard_n == shard_k - 1)) || continue
    p="$(basename "$f" .toml)"
    witness="witness-extend-$p"
    if ! (cd "$dir" && nice -n 19 timeout 600 "$NARGO_BIN" execute --silence-warnings \
          --oracle-resolver "$URL" --prover-name "$p" "$witness") >"$WORK/$c.$p.nargo.log" 2>&1; then
      echo "$c/$p: FAIL (nargo execute: $(tail -n 1 "$WORK/$c.$p.nargo.log"))"
      fail=$((fail + 1))
      continue
    fi
    [[ -f $manifest ]] \
      || shared="$(jq -r '[.abi.parameters[] | select(.visibility == "private") | .name] | join(",")' "$dir/target/$c.json")"
    if out="$(nice -n 19 timeout 1800 "$CHECK" "$dir/target/$c.json" "$f" "$dir/target/$witness.gz" --shared "$shared" 2>&1)"; then
      echo "$c/$p: PASS ($(tail -n 1 <<<"$out" | sed "s/^$c: //"))"
      pass=$((pass + 1))
    else
      echo "$c/$p: FAIL ($(head -n 1 <<<"$out"))"
      fail=$((fail + 1))
    fi
    rm -f "$dir/target/$witness.gz"
  done
done

shard=""
((shard_n > 1)) && shard=", shard $shard_k/$shard_n"
echo "witness-extend: $pass passed, $fail failed (${EXAMPLE#"$REPO_ROOT"/}$shard)"
((fail == 0))
