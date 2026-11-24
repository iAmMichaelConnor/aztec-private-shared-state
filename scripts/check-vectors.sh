#!/usr/bin/env bash
# Gate for the Noir side of the shared test vectors: execute every vector
# program under testvectors/noir/ on its Prover.toml (`nargo execute`, the
# build output removed afterwards), and check that the vector values the Noir
# tests hold (configure's registry constants, the test network's node keys,
# the outcome note hash, the AE known answers) are the ones
# scripts/gen-noir-vectors.py writes from the vector files.
# Rust and TypeScript read the same vector files in their own tests, and the
# Rust tests check that each Prover.toml is the one written from them; a
# failing assertion here means a vector file disagrees with the Noir
# libraries. What each program checks is in its src/main.nr.
#
# The compiler follows from the program's dependencies: a program on aztec-nr
# (the tip contract library's: tip_intake_vectors, tip_onchain_vectors,
# tip_result_vectors and outcome_layout_vectors) builds with the contract
# compiler, CONTRACT_NARGO_BIN (nargo 1.0.0-rc.3,
# which aztec-nr v6.0.0 is released for); every other program, over the round
# circuits' libraries, with NARGO_BIN (Noir 1.0.0).
#
# Usage: scripts/check-vectors.sh              every program
#        scripts/check-vectors.sh <name> ...   the named programs (e.g. tip_tree_vectors)
#
# Exit status is non-zero if any program fails, a named program does not
# exist, or a Noir test's vector values differ. Environment overrides: NARGO_BIN,
# CONTRACT_NARGO_BIN (scripts/toolchain.sh).
# No -e: every case runs and each failure is counted, so one run reports them all.
set -uo pipefail

SCRIPTS="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# REPO_ROOT, NARGO_BIN, NARGO_VERSION, CONTRACT_NARGO_BIN, CONTRACT_NARGO_VERSION
# shellcheck source=toolchain.sh
source "$SCRIPTS/toolchain.sh"
VECTORS="$REPO_ROOT/testvectors/noir"

need_nargo "$NARGO_BIN" "$NARGO_VERSION" || exit 1
need_nargo "$CONTRACT_NARGO_BIN" "$CONTRACT_NARGO_VERSION" || exit 1

if (($#)); then
  programs=("$@")
else
  programs=()
  for dir in "$VECTORS"/*/; do programs+=("$(basename "$dir")"); done
fi

fail=0
for p in "${programs[@]}"; do
  dir="$VECTORS/$p"
  if [[ ! -f $dir/Nargo.toml ]]; then
    echo "!! $p: no testvectors/noir/$p/Nargo.toml"
    fail=1
    continue
  fi
  bin=$NARGO_BIN version=$NARGO_VERSION
  if grep -q 'aztec-world/noir-projects/aztec-nr/' "$dir/Nargo.toml"; then
    bin=$CONTRACT_NARGO_BIN version=$CONTRACT_NARGO_VERSION
  fi
  echo "== $p (nargo $version)"
  start=$SECONDS
  (cd "$dir" && nice -n 19 "$bin" execute)
  rc=$?
  rm -rf "$dir/target"
  if ((rc == 0)); then
    echo "ok: $p ($((SECONDS - start)) s)"
  else
    echo "!! $p failed"
    fail=1
  fi
done

echo "== Noir tests' vector values"
python3 -I "$SCRIPTS/gen-noir-vectors.py" --check || fail=1

if ((fail)); then
  echo "check-vectors: FAILED"
  exit 1
fi
echo "check-vectors: ${#programs[@]} programs and the Noir tests' vector values pass"
