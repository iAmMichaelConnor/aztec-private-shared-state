#!/usr/bin/env bash
# Gate for the Aztec contract side, compile only: every Noir package of type
# "contract" is compiled with CONTRACT_NARGO_BIN (nargo 1.0.0-rc.3, which
# aztec-nr v6.0.0 is released for), and every library package on aztec-nr
# (the contract libraries under noir/ and the TXE test packages) is
# type-checked with `nargo check`. No TXE, no bb, no proofs: scripts/txe.sh
# runs the contracts' tests, and the vector programs on aztec-nr are
# scripts/check-vectors.sh's.
#
# Usage: scripts/check-contracts.sh [dir ...]          default: the whole repository
#        scripts/check-contracts.sh --list [dir ...]   print each job ("compile <dir>"
#                                                      or "check <dir>") and run nothing
#
# Packages are found from the tracked Nargo.toml files under the given
# directories. Two packages are checked first, one at a time, to fill
# Nargo's git-dependency cache: pss_public_contract takes noir-lang/schnorr,
# and both reach noir-lang/poseidon and sha256 through aztec-nr. When the
# directories hold neither (one example's packages, as a CI shard checks
# them), the first job runs alone instead. The rest run
# CONTRACT_JOBS at a time (default 8), each compile into its own scratch
# target directory, so nothing is written into the source tree. Environment: CONTRACT_NARGO_BIN, CONTRACT_JOBS,
# TXE_TMP_ROOT (the scratch root). Needs scripts/bootstrap.sh to have made
# deps/.
set -euo pipefail

SCRIPTS="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=toolchain.sh
source "$SCRIPTS/toolchain.sh"

list=0
[[ ${1:-} == --list ]] && { list=1; shift; }
((list)) || need_nargo "$CONTRACT_NARGO_BIN" "$CONTRACT_NARGO_VERSION" || exit 1
JOBS="${CONTRACT_JOBS:-8}"
[[ $JOBS =~ ^[1-9][0-9]*$ ]] || { echo "CONTRACT_JOBS must be a positive integer (got: $JOBS)" >&2; exit 2; }

scratch_dir WORK check-contracts
trap 'rm -rf "$WORK"' EXIT

cd "$REPO_ROOT"
(($#)) || set -- .
jobs_list="$WORK/jobs"
: >"$jobs_list"
while IFS= read -r manifest; do
  grep -q '^\[package\]' "$manifest" || continue
  dir="${manifest%/Nargo.toml}"
  kind="$(sed -n 's/^type *= *"\([a-z]*\)".*/\1/p' "$manifest" | head -n 1)"
  if [[ $kind == contract ]]; then
    echo "compile $dir" >>"$jobs_list"
  elif [[ $kind == lib ]] && grep -q 'aztec-nr/aztec' "$manifest"; then
    echo "check $dir" >>"$jobs_list"
  fi
done < <(git ls-files -- "$@" | grep -E '(^|/)Nargo\.toml$' | sort -u)
[[ -s $jobs_list ]] || { echo "check-contracts: no contract or aztec-nr library package under $*" >&2; exit 2; }
((list)) && { cat "$jobs_list"; exit 0; }

# run_job <compile|check> <dir>: one package, its output in $WORK/logs/.
run_job() {
  local action=$1 dir=$2 log
  log="$WORK/logs/${dir//\//_}.log"
  if [[ $action == compile ]]; then
    nice -n 19 "$CONTRACT_NARGO_BIN" compile --silence-warnings --program-dir "$dir" \
      --target-dir "$WORK/target/${dir//\//_}" >"$log" 2>&1
  else
    nice -n 19 "$CONTRACT_NARGO_BIN" check --silence-warnings --program-dir "$dir" >"$log" 2>&1
  fi
}
mkdir -p "$WORK/logs"

fail=0
# Nargo's git-dependency cache first, one package at a time: the two
# libraries when they are listed, else the first job.
warm_jobs=()
for warm in noir/pss_public_contract noir/pss_contract; do
  grep -qx "check $warm" "$jobs_list" && warm_jobs+=("check $warm")
done
((${#warm_jobs[@]})) || warm_jobs=("$(head -n 1 "$jobs_list")")
for job in "${warm_jobs[@]}"; do
  read -r action dir <<<"$job"
  echo "== $job (dependency cache warm-up)"
  run_job "$action" "$dir" || { cat "$WORK/logs/${dir//\//_}.log"; echo "!! $job failed"; fail=1; }
  grep -vxF "$job" "$jobs_list" >"$jobs_list.rest" || true
  mv "$jobs_list.rest" "$jobs_list"
done

declare -A PID_OF=()
running=0
report() { # report <action> <dir> <status>
  if (($3 == 0)); then
    echo "ok: $1 $2"
  else
    cat "$WORK/logs/${2//\//_}.log"
    echo "!! $1 $2 failed"
    fail=1
  fi
}
reap_one() {
  local job status=0
  wait -n -p done_pid || status=$?
  for job in "${!PID_OF[@]}"; do
    if [[ ${PID_OF[$job]} == "$done_pid" ]]; then
      unset "PID_OF[$job]"
      report "${job%% *}" "${job#* }" "$status"
      break
    fi
  done
  running=$((running - 1))
}
while read -r action dir; do
  ((running < JOBS)) || reap_one
  run_job "$action" "$dir" </dev/null &
  PID_OF["$action $dir"]=$!
  running=$((running + 1))
done <"$jobs_list"
while ((running > 0)); do reap_one; done

if ((fail)); then
  echo "check-contracts: FAIL"
  exit 1
fi
echo "check-contracts: PASS"
