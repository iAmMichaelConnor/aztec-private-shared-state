#!/usr/bin/env bash
# Gate for an example's round circuits: check the example's manifests of a
# round under each intake against their derivation (scripts/gen-intake.py
# --check; an example without such rounds has nothing to compare) and its
# oblivious twins of the tree rounds against theirs (scripts/gen-access.py
# --check), compile
# every round circuit with
# the pinned Noir 1.0.0 (NARGO_BIN), run the Noir tests (the shared pss_core
# and pss_utils, the example's own libraries, and every circuit package,
# round or EMBEDDED, that has a #[test] of its own), lint the
# circuits the example declares total with total-noir's total-lint, check
# every round circuit with the lint's --brillig-ops report (no Brillig op
# co-noir's MPC VM cannot execute), then execute each circuit's Prover.toml
# (and every Prover-<case>.toml beside it) with the TACEO_store oracle stubbed
# (scripts/oracle-stub.py). No proving here, and no co-noir: the nodes extend
# the witnesses and prove with co-Noir, and the contract verifies.
# The machine examples (examples/amm, examples/monty-hall), the tip examples
# and the machine's own test circuits (machine/circuits) go through the same
# steps.
#
# Usage: scripts/check-noir.sh <example dir> [--outputs <file>]
#          e.g. scripts/check-noir.sh examples/amm
#        scripts/check-noir.sh machine           the machine's test circuits (machine/circuits)
#
# --outputs <file> also checks what each case outputs, against the expected
# outputs in <file> (examples/amm-tip/circuits/outputs.txt, for example). One row per
# case, whitespace-separated, # starts a comment:
#   <circuit>[,<circuit>...] <prover name> <from> <to> [<field>=<value> ...]
# Each <field>=<value> must equal that field of the case's "Circuit output:"
# line: a hex scalar, or a list written without spaces ([0x01,0x00]). <from>
# and <to> check the state commitment the line carries in the fields named by
# a `state <old field> <new field>` line: <from> is the expected old value, a
# literal (0x00) or the name of a value an earlier row recorded; <to> is `=`
# (the new value equals the old), or a name (the new value differs from the
# old and is recorded under that name); `-` checks nothing. Rows run in file
# order, so a chain of states reads top to bottom. Every Prover*.toml of a
# circuit the file names must have a row, so a new case cannot go unchecked.
#
# An example without a circuits/ directory has nothing to check: the script
# says so and exits 0.
#
# The example names its packages in <example>/circuits/circuits.env, a
# bash file sourced by this script that sets these variables:
#   CIRCUITS="pss_seed amm_init amm_swap"   # bin packages under circuits/, in round order
#   LIBS="amm"                              # lib packages under circuits/ whose tests run
#   TOTAL_CIRCUITS="amm_swap"               # optional: the circuits that are total (linted)
#   TOTAL_LIB_SRC=""                        # optional: extra --lib-src entries for the lint
# Each circuit package has a Prover.toml; it may also have Prover-<case>.toml
# fixtures (a total circuit has one per failure case), each executed as its
# own witness. Environment overrides: NARGO_BIN, ORACLE_PORT
# (default: a free port), TXE_TMP_ROOT (the scratch root, default .runs/tmp),
# and for the lint TOTAL_LINT_BIN (see the comments below).
# No -e: every case runs and each failure is counted, so one run reports them all.
set -uo pipefail

SCRIPTS="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# REPO_ROOT, NARGO_VERSION, NARGO_BIN, TOTAL_LINT_BIN, pin, need_nargo,
# scratch_dir, start_oracle_stub and load_circuits_env.
# shellcheck source=toolchain.sh
source "$SCRIPTS/toolchain.sh"

usage() { echo "usage: $0 <example dir> [--outputs <file>]" >&2; exit 2; }
example="" OUTPUTS=""
while (($#)); do
  case $1 in
    --outputs) (($# > 1)) || usage; OUTPUTS=$2; shift 2 ;;
    -*) usage ;;
    *) [[ -z $example ]] || usage; example=$1; shift ;;
  esac
done
[[ -n $example ]] || usage
EXAMPLE="$(cd "$example" 2>/dev/null && pwd)" || { echo "no such directory: $example" >&2; exit 2; }
[[ -z $OUTPUTS || -f $OUTPUTS ]] || { echo "no outputs file at $OUTPUTS" >&2; exit 2; }
CIRCUITS_DIR="$EXAMPLE/circuits"
# An example with no circuits/ (a contract-only package such as the token
# example) has no round circuit to check: say so and pass, running nothing.
[[ -d $CIRCUITS_DIR ]] || { echo "no round circuits in $example; nothing to check"; exit 0; }
[[ -f $CIRCUITS_DIR/circuits.env ]] || { echo "missing $CIRCUITS_DIR/circuits.env" >&2; exit 2; }
load_circuits_env "$EXAMPLE"
((${#circuits[@]})) || { echo "circuits.env names no CIRCUITS" >&2; exit 2; }

# An example declares itself total by listing its total circuits in
# TOTAL_CIRCUITS in circuits.env (a subset of CIRCUITS, by package directory
# name). For each one this script runs total-lint on the compiled artifact and
# fails unless the lint exits 0, which it does only when every reported item
# (input-falsifiable, library-input-falsifiable, hint-unreviewed,
# unsolvable) is justified by a
# `// total-lint: allow <reason>` marker. A list rather than one flag per
# example, because an example may mix queued total rounds with rounds that are
# not queued (a seed or init round that keeps its asserts). Unset or empty: the
# example is not total and no lint runs (the machine examples). The lint gates
# this script only; REGISTER does not gate on it and the machine records no
# verdict (DECISIONS.md, "Total circuits").
for t in "${total_circuits[@]}"; do
  [[ " ${circuits[*]} " == *" $t "* ]] \
    || { echo "circuits.env: TOTAL_CIRCUITS names $t, which is not in CIRCUITS" >&2; exit 2; }
done

fail=0
say() { echo "== $*"; }
die_case() { echo "!! $*"; fail=1; }
nargo() { nice -n 19 "$NARGO_BIN" "$@"; }

need_nargo "$NARGO_BIN" "$NARGO_VERSION" || exit 1


# ---- the outputs file (--outputs), read before anything runs ----------------
out_rows=() out_state=()
declare -A OUT_COVERED=()
if [[ -n $OUTPUTS ]]; then
  while IFS= read -r l; do
    read -r -a w <<<"${l%%#*}"
    ((${#w[@]})) || continue
    case ${w[0]} in
      state) ((${#w[@]} == 3)) || { echo "$OUTPUTS: state takes two field names" >&2; exit 2; }
             out_state=("${w[1]}" "${w[2]}") ;;
      *) ((${#w[@]} >= 4)) || { echo "$OUTPUTS: short row: ${w[*]}" >&2; exit 2; }
         [[ ${w[2]}${w[3]} == -- || ${#out_state[@]} -eq 2 ]] \
           || { echo "$OUTPUTS: a row checks state before a state line: ${w[*]}" >&2; exit 2; }
         out_rows+=("${w[*]}")
         IFS=, read -r -a cs <<<"${w[0]}"
         for c in "${cs[@]}"; do
           [[ " ${circuits[*]} " == *" $c "* ]] || { echo "$OUTPUTS: $c is not in CIRCUITS" >&2; exit 2; }
           OUT_COVERED[$c]=1 OUT_COVERED[$c/${w[1]}]=1
         done ;;
    esac
  done <"$OUTPUTS"
fi

# Every temporary file of this script and of the processes it starts goes
# into one scratch directory (scratch_dir, scripts/toolchain.sh), removed on exit.
scratch_dir LOGS check-noir || { echo "cannot make a scratch directory" >&2; exit 1; }
export TMPDIR="$LOGS"
ORACLE_PID=""
cleanup() { [[ -n $ORACLE_PID ]] && kill "$ORACLE_PID" 2>/dev/null; rm -rf "$LOGS"; }
trap cleanup EXIT

# The example's manifests of a round under each intake: scripts/gen-intake.py
# --check fails when a committed one is not its derivation from the round's
# secret-shared manifest (and its non-secret-shared main's parameters), or a
# derivation fails the schema. An example without such rounds has nothing to
# compare.
say "derived manifests (scripts/gen-intake.py --check $(basename "$EXAMPLE"))"
if ! python3 -I "$SCRIPTS/gen-intake.py" --check "$(basename "$EXAMPLE")" >"$LOGS/gen-intake" 2>&1; then
  grep -v '^ok ' "$LOGS/gen-intake"
  die_case "the committed manifests are not what scripts/gen-intake.py derives"
else
  tail -1 "$LOGS/gen-intake"
fi

# The oblivious twins of the example's tree rounds (main, Nargo.toml and
# manifest): scripts/gen-access.py --check fails when a committed twin is not
# its derivation from the clear round. An example without twins has nothing
# to compare.
say "derived oblivious twins (scripts/gen-access.py --check $(basename "$EXAMPLE"))"
if ! python3 -I "$SCRIPTS/gen-access.py" --check "$(basename "$EXAMPLE")" >"$LOGS/gen-access" 2>&1; then
  grep -v '^ok ' "$LOGS/gen-access"
  die_case "the committed oblivious twins are not what scripts/gen-access.py derives"
else
  tail -1 "$LOGS/gen-access"
fi

# ---- total-lint binary (for the lint on TOTAL_CIRCUITS and --brillig-ops) ---

# Which total-lint runs: TOTAL_LINT_BIN (scripts/toolchain.sh), by default
# the total-lint scripts/install-toolchain.sh installs from total-noir at the
# commit pinned in toolchain.json (total_noir.commit), the commit of the
# `total` package the circuits compile against (scripts/bootstrap.sh checks
# both).

# The co-noir step: for every circuit in CIRCUITS (every round the network
# proves, not only the TOTAL_CIRCUITS) this script runs
# `total-lint <artifact> --brillig-ops --summary` and fails unless it exits 0,
# printing the full report (each op with its Brillig function and source
# location) on failure. The report lists
# the Brillig opcodes co-noir's MPC VM (co-brillig at the co-snarks rev in
# toolchain.json) cannot execute: integer And, Or, Xor, Shl, Shr and
# ConditionalMov, and Brillig black-box calls other than ToRadix; it exits 1
# when any is reachable. Why every circuit: each round's witness is extended
# by the nodes in co-noir, so every Brillig function a round reaches (a
# total-noir hint, a pss_core or std hint, an oracle wrapper, the example's
# own unconstrained helpers) must run in co-brillig, whether or not the round
# is total; nargo and the TXE never run co-noir, so such a hint passes every
# other step here and the TXE and fails only at the nodes, at witness
# extension (mpc_failure, 500) on every request. A circuit the network proves
# calls only total-noir entries whose hints co-noir runs (docs/ARCHITECTURE.md
# section 6), and this step checks that statically. The lint therefore runs
# for every example, even one with no TOTAL_CIRCUITS. A clean report is
# necessary, not sufficient: it does not run co-noir (an ACIR black box
# co-noir lacks, such as ECDSA, is not a Brillig op), so the e2e, the
# machine's three-party tests or total-noir's scripts/mpc-check.sh remain the
# proof that a round extends.
[[ -x $TOTAL_LINT_BIN ]] \
  || { echo "TOTAL_LINT_BIN=$TOTAL_LINT_BIN is not an executable (run scripts/install-toolchain.sh)"; echo "check-noir.sh: FAIL (no total-lint)"; exit 1; }
TOTAL_LINT="$TOTAL_LINT_BIN"
say "total-lint binary: $TOTAL_LINT"

# The first compile runs alone to fill the shared git-dependency cache;
# the remaining compiles and the Noir tests run in parallel.
declare -A COMPILED   # the circuits whose compile succeeded in this run
say "compile ${circuits[0]} (dependency cache warm-up)"
if (cd "$CIRCUITS_DIR/${circuits[0]}" && nargo compile --silence-warnings); then
  COMPILED[${circuits[0]}]=1
else
  die_case "${circuits[0]} does not compile"
fi

say "compile remaining circuits and run the Noir tests (parallel)"
declare -A JOB_PID JOB_SHOW
start() { # start <job name> <dir> <show: always|fail> <nargo args...>
  local job=$1 dir=$2 show=$3; shift 3
  (cd "$dir" && nargo "$@" --silence-warnings) >"$LOGS/${job// /_}" 2>&1 &
  JOB_PID[$job]=$! JOB_SHOW[$job]=$show
}
for c in "${circuits[@]:1}"; do start "compile $c" "$CIRCUITS_DIR/$c" fail compile; done
for lib in pss_core pss_utils; do start "test $lib" "$REPO_ROOT/noir/$lib" always test; done
for lib in "${libs[@]}"; do start "test $lib" "$CIRCUITS_DIR/$lib" always test; done
for c in "${circuits[@]}" "${embedded[@]}"; do
  grep -rqs '#\[test' "$CIRCUITS_DIR/$c/src" && start "test $c" "$CIRCUITS_DIR/$c" always test
done
for job in "${!JOB_PID[@]}"; do
  log="$LOGS/${job// /_}"
  if wait "${JOB_PID[$job]}"; then
    [[ $job == "compile "* ]] && COMPILED[${job#compile }]=1
    [[ ${JOB_SHOW[$job]} == always ]] && { say "$job"; tail -1 "$log"; }
  else
    say "$job"; cat "$log"
    die_case "$job failed"
  fi
done

# artifact_of <circuit dir name>: the compiled artifact, named after the package.
artifact_of() {
  local name
  name="$(sed -n 's/^name *= *"\([^"]*\)".*/\1/p' "$CIRCUITS_DIR/$1/Nargo.toml" | head -n 1)"
  echo "$CIRCUITS_DIR/$1/target/${name:-$1}.json"
}

# nargo leaves an artifact whose compiled program did not change as it was,
# with its old mtime. The Rust tests that read these artifacts fail when one
# is older than a source file of its circuit, so every round that compiled in
# this run is marked as compiled from the current source. A round whose
# compile failed keeps its old artifact's mtime (still stale to those tests),
# and a missing artifact stays missing.
for c in "${circuits[@]}"; do
  artifact="$(artifact_of "$c")"
  if [[ -n ${COMPILED[$c]:-} && -f $artifact ]]; then touch "$artifact"; fi
done

if ((${#total_circuits[@]})); then
  say "total-lint on the circuits declared total (${total_circuits[*]})"
  # The lint's library whitelist (--lib-src, source directories matched by
  # absolute path prefix): total's src and noir-lang/schnorr's src (which
  # total's schnorr module builds on) in nargo's git-dependency cache, at the
  # tags toolchain.json pins (nargo_git_dir): the libraries total-noir
  # reviewed hint by hint. A hint-class constraint from one of them is
  # whitelisted; one from anywhere else (std, aztec-nr, pss_core, the
  # example) is reported and needs a justification. A listed library that a
  # circuit does not use changes nothing, and one nargo has not fetched is
  # left out. TOTAL_LIB_SRC in circuits.env adds directories (absolute, or
  # relative to the repository root; for example a reviewed total-noir
  # package the example calls); each entry is trusted unreviewed here, so add
  # only libraries reviewed as total.
  #
  # Where a justification marker counts: in the circuit package's own src
  # (the lint's default entry package), in the src of each of the
  # example's own LIBS packages, which are the example's code and reviewed
  # with it, and in pss_core's src, the shared round library, reviewed
  # with this repository: its markers justify, once and at the line that
  # makes it, each node-supplied assert and hint-satisfiable std
  # decomposition every round inherits (tree::load's old-leaf check, the
  # index and key bit splits, npk_app_hash's scalar decomposition), so a
  # main carries no marker for them. A marker in any other dependency
  # (total-noir, aztec-nr, std) never counts.
  lint_args=(--allow-src "$REPO_ROOT/noir/pss_core/src")
  for l in "$(nargo_git_dir total_noir)/$(pin total_noir.package)/src" "$(nargo_git_dir schnorr)/src"; do
    [[ -d $l ]] && lint_args+=(--lib-src "$l")
  done
  for l in "${total_lib_src_extra[@]}"; do
    [[ $l == /* ]] || l="$REPO_ROOT/$l"
    lint_args+=(--lib-src "$l")
  done
  for lib in "${libs[@]}"; do lint_args+=(--allow-src "$CIRCUITS_DIR/$lib/src"); done
  for c in "${total_circuits[@]}"; do
    artifact="$(artifact_of "$c")"
    if [[ ! -f $artifact ]]; then
      die_case "$c: no compiled artifact at $artifact to lint"
      continue
    fi
    if timeout 300 nice -n 19 "$TOTAL_LINT" "$artifact" --summary "${lint_args[@]}" >"$LOGS/lint_$c" 2>&1; then
      echo "-- $c: total-lint exit 0, no unjustified item"
      sed 's/^/   /' "$LOGS/lint_$c"
    else
      echo "-- $c: total-lint FAILED"
      sed 's/^/   /' "$LOGS/lint_$c"
      # The unjustified items and abort sites only; the full report is the command below with --explain.
      timeout 300 nice -n 19 "$TOTAL_LINT" "$artifact" --json "${lint_args[@]}" >"$LOGS/lint_$c.json" 2>/dev/null
      python3 -I - "$LOGS/lint_$c.json" <<'PY' 2>/dev/null | sed 's/^/   /'
import json, sys
for f in json.load(open(sys.argv[1]))["functions"]:
    for i in f["items"]:
        if i["counts"]:
            loc = i["attributed_location"] or i["location"] or {}
            print(f"unjustified {i['class']} {i['label']} at {loc.get('file')}:{loc.get('line')}: {i['message']}")
    for s in f["brillig_abort_sites"]:
        if s["counts"]:
            loc = s["location"] or {}
            print(f"unjustified {s['kind']} abort site in {s['name']} at {loc.get('file')}:{loc.get('line')}: {s['detail']}")
PY
      echo "   full report: $TOTAL_LINT $artifact --explain ${lint_args[*]}"
      die_case "$c: total-lint reports unjustified items (or could not read the artifact)"
    fi
  done
fi

say "total-lint --brillig-ops on every circuit (${circuits[*]})"
for c in "${circuits[@]}"; do
  artifact="$(artifact_of "$c")"
  if [[ ! -f $artifact ]]; then
    die_case "$c: no compiled artifact at $artifact for --brillig-ops"
    continue
  fi
  if timeout 300 nice -n 19 "$TOTAL_LINT" "$artifact" --brillig-ops --summary >"$LOGS/ops_$c" 2>&1; then
    echo "-- $c: total-lint --brillig-ops exit 0, no unsupported op reachable"
    sed 's/^/   /' "$LOGS/ops_$c"
  else
    echo "-- $c: total-lint --brillig-ops FAILED (a Brillig op co-noir's MPC VM cannot execute is reachable)"
    timeout 300 nice -n 19 "$TOTAL_LINT" "$artifact" --brillig-ops >"$LOGS/ops_$c.full" 2>&1
    sed 's/^/   /' "$LOGS/ops_$c.full"
    die_case "$c: total-lint --brillig-ops reports ops co-noir cannot execute (or could not read the artifact)"
  fi
done

say "witness execution (TACEO_store stubbed)"
start_oracle_stub "$LOGS" || exit 1
URL=$ORACLE_URL
# Each case's output is kept in $LOGS/out_<circuit>_<prover name> for --outputs.
for c in "${circuits[@]}"; do
  (cd "$CIRCUITS_DIR/$c" && nargo execute --oracle-resolver "$URL" witness --silence-warnings) 2>&1 \
    | tee "$LOGS/out_${c}_Prover" || die_case "$c witness execution failed"
  # Every Prover-<case>.toml beside Prover.toml must solve too (a total
  # circuit has one per failure case); each writes target/Prover-<case>.gz.
  for f in "$CIRCUITS_DIR/$c"/Prover-*.toml; do
    [[ -f $f ]] || continue
    p="$(basename "$f" .toml)"
    (cd "$CIRCUITS_DIR/$c" && nargo execute --oracle-resolver "$URL" --prover-name "$p" "$p" --silence-warnings) 2>&1 \
      | tee "$LOGS/out_${c}_$p" || die_case "$c witness execution failed for $p.toml"
  done
done

if [[ -n $OUTPUTS ]]; then
  say "outputs against $OUTPUTS"
  for c in "${circuits[@]}"; do
    [[ -n ${OUT_COVERED[$c]:-} ]] || continue
    for f in "$CIRCUITS_DIR/$c"/Prover*.toml; do
      p="$(basename "$f" .toml)"
      [[ -n ${OUT_COVERED[$c/$p]:-} ]] || die_case "$c/$p: no expected outputs in $OUTPUTS"
    done
  done
  # out_field <field> <output line>: the field's value, a hex scalar or a
  # [list] with its spaces removed; empty if the line has no such field.
  out_field() { sed -n "s/.*[{ ]$1: \(\[[^]]*\]\|0x[0-9a-f]*\).*/\1/p" <<<"$2" | tr -d ' '; }
  declare -A STATE=()
  for row in "${out_rows[@]}"; do
    read -r cs p from to checks <<<"$row"
    IFS=, read -r -a cs <<<"$cs"
    for c in "${cs[@]}"; do
      line="$(grep -h 'Circuit output:' "$LOGS/out_${c}_$p" 2>/dev/null || true)"
      verdict=ok got=()
      for check in $checks; do
        v="$(out_field "${check%%=*}" "$line")"
        got+=("${check%%=*}=$v")
        [[ $v == "${check#*=}" ]] || verdict="MISMATCH (want $check)"
      done
      if [[ $from$to != -- ]]; then
        old="$(out_field "${out_state[0]}" "$line")" new="$(out_field "${out_state[1]}" "$line")"
        case $from in
          -) ;;
          0x*) [[ $old == "$from" ]] || verdict="MISMATCH (${out_state[0]} is not $from)" ;;
          *) [[ $old == "${STATE[$from]:-unset}" ]] || verdict="MISMATCH (${out_state[0]} is not $from's commitment)" ;;
        esac
        case $to in
          -) ;;
          =) [[ $new == "$old" ]] || verdict="MISMATCH (${out_state[1]} differs from ${out_state[0]})" ;;
          *) [[ $new != "$old" ]] || verdict="MISMATCH (${out_state[1]} = ${out_state[0]} on an applied case)"
             STATE[$to]=$new ;;
        esac
        [[ -n $old ]] || verdict="EXECUTION FAILED"
      fi
      [[ -n $line ]] || verdict="EXECUTION FAILED"
      [[ $verdict == ok ]] || fail=1
      echo "-- $c/$p ($from -> $to)${got[*]:+ ${got[*]}}: $verdict"
    done
  done
fi

if [[ $fail -eq 0 ]]; then echo "check-noir.sh: PASS"; else echo "check-noir.sh: FAIL"; exit 1; fi
