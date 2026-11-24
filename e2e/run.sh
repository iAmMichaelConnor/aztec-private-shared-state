#!/usr/bin/env bash
# The local-network end-to-end harness. It runs the whole machine on one host:
# three sidecar-node processes, each on its own Postgres container, the
# sidecar-orchestrator, and a local Aztec 6.0.0 network whose node verifies
# client-side transaction proofs. Then it runs the harness's own smoke check
# (harness/smoke.ts: the node keys, a first REGISTER, one transaction) and
# the driver (driver.ts) once per scenario named on the command line
# (scenarios/<name>.ts; at least one), and tears every service down on exit, also when
# something fails. With E2E_TIP=1 it also runs the tip-of-chain services
# (docs/ARCHITECTURE.md section 6): each node with its chain verifier and
# receipt route and the orchestrator with its chain reader and scheduler
# (the [tip] section of every config), the wFJ fee setup, the tip
# deployments and one pss-relayer per deployment.
#
#   e2e/run.sh scenario [scenario ...]
#   E2E_TIP=1 E2E_TIP_DEPLOYMENTS="deployment ..." e2e/run.sh scenario [scenario ...]
#   E2E_REORG=1 E2E_TIP=1 E2E_TIP_DEPLOYMENTS="counter-tip" e2e/run.sh reorg-<scenario>
#
# What it does, in order:
#   1. checks the tool identities: nargo 1.0.0 (circuits) and 1.0.0-rc.3
#      (contracts), bb 6.0.0, every @aztec-labs package 6.0.0 in the root
#      lockfile and in node_modules, the CLI version and bb.js's bundled bb,
#      Foundry 1.8.5, docker, node >= 24;
#   2. builds the sidecar binaries and pss-client, type-checks the harness;
#   3. compiles the examples' round circuits and copies the CRS into the run
#      directory (scripts/prepare-data.sh), writes the dev TLS planes there
#      (scripts/gen-dev-certs.sh) and the vk.json of every circuit (bb);
#   4. writes the three node configs, their mesh configs and the
#      orchestrator config into the run directory, and runs
#      `sidecar-node setup` for the three nodes, keeping the printed keys;
#   5. writes harness.json and the ready pss-client configurations
#      (harness/prepare.ts); a tip run then plans its deployments
#      (harness/tip.ts plan: the contracts, their salts and addresses) and
#      adds the [tip] section, one set of namespace entries, to the three
#      node configs and the orchestrator's;
#   6. starts the Postgres containers, the three nodes, the orchestrator,
#      and checks GET /v1/nodes through the orchestrator against the keys
#      setup printed (refuses on a mismatch); a tip run also requires each
#      node's chain verifier and the orchestrator's schedulers;
#   7. starts the local network and, with EXPECT_REAL_PROOFS=1, builds and
#      confirms the node's proof verifier (harness/enable-real-proofs.ts);
#      a tip run then funds the payers through wFJ (harness/fees.ts),
#      deploys and configures every deployment (harness/tip.ts deploy),
#      starts its relayers and waits until each has landed its deployment's
#      init round (harness/tip.ts init);
#   8. runs harness/smoke.ts, then the driver on each scenario; a tip run
#      ends with the fee-payer check (harness/fee-payers.ts).
#
# Everything a run writes (keys, configs, artifact copies, logs, the
# registry, bb's scratch, the contract builds) is under E2E_LOG_DIR; the network's short-lived
# state (sockets, world state) is under a scratch directory of TXE_TMP_ROOT
# that is removed on exit. Nothing goes to /tmp. The run directory is kept
# for the caller to read and remove.
#
# This script proves, generates verification keys, reads the CRS, starts
# services and may install npm packages. It is never part of default CI.
# No -e: each step checks its own status and names it (|| die).
set -uo pipefail

E2E_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Expensive work runs at nice 19 with idle I/O priority;
# every process started below inherits both.
if [[ -z ${PSS_E2E_NICED:-} ]]; then
  export PSS_E2E_NICED=1
  exec nice -n 19 ionice -c 3 "$E2E_DIR/run.sh" "$@"
fi

# shellcheck source=../scripts/toolchain.sh
source "$E2E_DIR/../scripts/toolchain.sh"
cd "$E2E_DIR" || exit 1

die() { echo "!! $*" >&2; exit 1; }

# One line per phase in timings.txt: "<phase> <seconds>".
phase_start=$SECONDS
phase_name=""
phase() {
  [[ -n $phase_name && -n ${RUN_DIR:-} ]] && echo "$phase_name $((SECONDS - phase_start))" >>"$RUN_DIR/timings.txt"
  phase_name="${1:-}"
  phase_start=$SECONDS
  [[ -n $phase_name ]] && echo "== $phase_name${2:+ ($2)}"
}

PG_CONTAINERS=()
SERVICE_PIDS=()
NETWORK_PID=""
NETWORK_TMP=""

# ---- teardown -----------------------------------------------------------------
# Stops every process and container this run started, by PID and by name
# only (a pattern kill would stop a concurrent run), waits for them, then
# removes the scratch directory. Runs on every exit.
stop_pids() {                        # stop_pids <pid...>: TERM, wait, then KILL
  local pid alive
  # CONT after TERM: a relayer a driver suspended (SIGSTOP) acts on the TERM.
  for pid in "$@"; do kill "$pid" 2>/dev/null; kill -CONT "$pid" 2>/dev/null; done
  for _ in $(seq 1 40); do
    alive=0
    for pid in "$@"; do kill -0 "$pid" 2>/dev/null && alive=1; done
    ((alive)) || return 0
    sleep 0.5
  done
  for pid in "$@"; do kill -9 "$pid" 2>/dev/null; done
}
# What teardown counts as left over. A live process,
# other than the scanner and its ancestors (run.sh and whatever launched it:
# a shell, bash -c, nice, timeout), that carries this run's PSS_E2E_RUN
# marker in its environment (every program the run executed, also one
# reparented away from run.sh), descends from run.sh, or has its cwd or
# executable under the run directory; plus anything in the network's
# process group and our containers. By default any such process fails the run
# (exit 1) after the report. These identify the run's own processes,
# while a match on command lines (pgrep -f "$RUN_DIR") also hits every
# launcher whose command line names the path, such as
# `E2E_LOG_DIR=/path e2e/run.sh` or a wrapper around it, and fails a passing
# run, yet misses a leak that names the path only in its cwd. Consequences:
# an unrelated process that only names the run directory (a `tail -f` of a
# log) does not count; a caller's shell whose cwd is inside the run
# directory does, so leave it before the run ends; a process that clears
# its environment, or a forked subshell of run.sh that never executes a
# program (its environment is run.sh's, from before the marker), is not
# seen once it has left run.sh's tree and works outside the run directory.
# So the check never matches command lines.
run_leftovers() {                    # run_leftovers: print "pid:name" of each leftover
  python3 - "$RUN_DIR" "$$" <<'LEFTOVERS'
import os, sys
run, top = os.path.realpath(sys.argv[1]), int(sys.argv[2])
marker = b"PSS_E2E_RUN=" + os.fsencode(sys.argv[1])
def under(link):
    try:
        path = os.path.realpath(os.readlink(link))
    except OSError:
        return False
    return path == run or path.startswith(run + "/")
parent = {}
for entry in os.listdir("/proc"):
    if entry.isdigit():
        try:
            stat = open(f"/proc/{entry}/stat").read()
        except OSError:
            continue
        parent[int(entry)] = int(stat.rsplit(")", 1)[1].split()[1])
skip, pid = set(), os.getpid()
while pid > 0 and pid not in skip:   # the scanner, run.sh and their ancestors
    skip.add(pid)
    pid = parent.get(pid, 0)
def descends(pid):
    seen = set()
    while pid > 1 and pid not in seen:
        if pid == top:
            return True
        seen.add(pid)
        pid = parent.get(pid, 0)
    return False
left = []
for pid in sorted(parent):
    if pid in skip:
        continue
    try:
        tagged = marker in open(f"/proc/{pid}/environ", "rb").read().split(b"\0")
    except OSError:
        tagged = False
    if tagged or descends(pid) or under(f"/proc/{pid}/cwd") or under(f"/proc/{pid}/exe"):
        try:
            name = open(f"/proc/{pid}/comm").read().strip()
        except OSError:
            continue                 # exited while we looked
        left.append(f"{pid}:{name}")
print(" ".join(left))
LEFTOVERS
}
cleanup() {
  local status=$?
  trap - EXIT INT TERM
  phase "teardown"
  ((${#SERVICE_PIDS[@]})) && stop_pids "${SERVICE_PIDS[@]}"
  # Services a scenario started in the run's place (a node replacement's
  # newcomer and the restarted orchestrator, steps/tip-replace-node.ts): one
  # pid per line in $E2E_PIDS/extra.
  if [[ -n ${E2E_PIDS:-} && -s $E2E_PIDS/extra ]]; then
    mapfile -t extra <"$E2E_PIDS/extra"
    stop_pids "${extra[@]}"
  fi
  if [[ -n $NETWORK_PID ]]; then
    # The CLI, anvil and the world-state processes share the process group
    # that setsid created; stop the whole group.
    kill -- -"$NETWORK_PID" 2>/dev/null
    for _ in $(seq 1 40); do
      pgrep -g "$NETWORK_PID" >/dev/null || break
      sleep 0.5
    done
    kill -9 -- -"$NETWORK_PID" 2>/dev/null
  fi
  for c in "${PG_CONTAINERS[@]}"; do
    docker stop -t 5 "$c" >/dev/null 2>&1 || docker rm -f "$c" >/dev/null 2>&1
  done
  # Reap what this run started, by PID: a bare `wait` would also block on any
  # other live child, which the leftover check below must report instead.
  local pid
  for pid in "${SERVICE_PIDS[@]}" $NETWORK_PID; do wait "$pid" 2>/dev/null; done
  [[ -n $NETWORK_TMP ]] && rm -rf "$NETWORK_TMP"
  # Nothing of this run may be left: no process of the run (the comment at
  # run_leftovers), none in the network's group, no container of ours.
  local left=""
  [[ -n ${RUN_DIR:-} ]] && left+="$(run_leftovers) "
  [[ -n $NETWORK_PID ]] && left+="$(pgrep -g "$NETWORK_PID" | tr '\n' ' ')"
  for c in "${PG_CONTAINERS[@]}"; do
    [[ -n "$(docker ps -aq --filter "name=^$c\$")" ]] && left+="container:$c "
  done
  if [[ -n ${left// /} ]]; then
    echo "!! teardown left: $left" >&2
    status=1
  else
    echo "   every process and container of this run is stopped"
  fi
  phase
  [[ -n ${RUN_DIR:-} ]] && echo "== logs and timings in $RUN_DIR"
  exit "$status"
}
trap cleanup EXIT
trap 'exit 143' TERM
trap 'exit 130' INT

# ---- scenarios named on the command line ------------------------------------
# At least one: a run with none would start everything, run the smoke only and
# report PASS for scenarios it never ran.
SCENARIOS=("$@")
((${#SCENARIOS[@]})) \
  || die "name at least one scenario (e2e/scenarios/<name>.ts, without .ts); docs/TESTING.md, \"End to end\", lists them with the deployments each takes"
for d in "${SCENARIOS[@]}"; do
  [[ $d =~ ^[a-z0-9_-]+$ && -f $E2E_DIR/scenarios/$d.ts ]] \
    || die "no scenario e2e/scenarios/$d.ts (scenarios are named by file, without .ts)"
done

# ---- the reorg network ----------------------------------------------------------
# E2E_REORG=1 starts the local network through harness/reorg-network.ts in
# place of `aztec start --local-network`: the same network, with its own
# proving loop and anvil's finality 64 L1 blocks behind, plus test calls
# (pause and resume the sequencer, revert to a checkpoint, proving on or
# off) on 127.0.0.1:REORG_PORT (default AZTEC_ADMIN_PORT + 1), behind the
# run's admin key. The reorg scenarios (scenarios/reorg-*.ts) revert the
# chain: they run only on that network, in a tip run, and are never part of
# the full gate (docs/TESTING.md, "End to end").
export E2E_REORG=${E2E_REORG:-0}
[[ $E2E_REORG == 0 || $E2E_REORG == 1 ]] || die "E2E_REORG must be 0 or 1"
for d in "${SCENARIOS[@]}"; do
  [[ $d != reorg-* || ($E2E_REORG == 1 && ${E2E_TIP:-0} == 1) ]] \
    || die "scenario $d reverts the chain: it runs only with E2E_REORG=1 E2E_TIP=1 (docs/TESTING.md, \"End to end\")"
done

# ---- run directory and scratch root -----------------------------------------
# The scratch root. TXE_TMP_ROOT (default .runs/tmp in this
# repository) holds the default run directory (E2E_LOG_DIR), the
# network's scratch directory and TMPDIR for every child process (nargo, bb,
# cargo, the CLI, anvil, the drivers). Nothing a run writes
# (node-compile-cache, wsdb-*, avm-*, bb scratch, L1 deployment files) may
# land in /tmp, and the network binds Unix sockets under TMPDIR, whose path
# is limited to 107 bytes, so the root must stay short. Consequences: set
# TXE_TMP_ROOT to relocate everything; an E2E_LOG_DIR given by the caller
# must be new or empty and short enough for the nodes' admin sockets
# (<run>/run/node<i>/admin.sock).
if [[ -z ${E2E_LOG_DIR:-} ]]; then
  scratch_dir E2E_LOG_DIR e2e --sockets || die "cannot create a run directory under TXE_TMP_ROOT=${TXE_TMP_ROOT:-}"
fi
[[ ! -e $E2E_LOG_DIR || -z "$(ls -A "$E2E_LOG_DIR")" ]] || die "E2E_LOG_DIR must be new or empty"
mkdir -p "$E2E_LOG_DIR"
RUN_DIR="$(cd "$E2E_LOG_DIR" && pwd)"
# Every process started from here on carries this marker in its
# environment; teardown uses it to find what the run left (run_leftovers).
export PSS_E2E_RUN="$RUN_DIR"
LOGS="$RUN_DIR/logs"
mkdir -p "$LOGS" "$RUN_DIR/config" "$RUN_DIR/run"
echo "== run directory: $RUN_DIR"
# Every child keeps its scratch files and sockets under TMPDIR: a short
# private directory under the scratch root keeps socket paths within the
# Unix limit; teardown removes it.
scratch_dir NETWORK_TMP n --sockets || die "cannot create a scratch directory under $TXE_TMP_ROOT"
export TMPDIR="$NETWORK_TMP"

# ---- the tip-of-chain services --------------------------------------------------
# E2E_TIP=1 adds the tip services (ARCHITECTURE.md section 6) to the
# machine's and moves every default port to the tip harness's range
# (e2e/README.md, "Ports"), so a tip run and a sidecar run can
# share the host. E2E_TIP_DEPLOYMENTS (default "amm-tip-shared amm-tip
# amm-tip-stale", what the amm-tip scenario takes) names the tip
# deployments, each e2e/tip/<name>.json (harness/tip.ts says what one
# holds); every one becomes a [[tip.namespaces]] entry of the four configs
# and gets its own relayer. E2E_EXAMPLES then defaults to the deployments'
# examples, and the smoke registers the first deployment's first package.
# A tip run stops at start-up, naming what is missing, when no deployment
# is named (the nodes and the orchestrator would have no [tip] section)
# and when the fee setup is incomplete (harness/fees.ts).
E2E_TIP=${E2E_TIP:-0}
[[ $E2E_TIP == 0 || $E2E_TIP == 1 ]] || die "E2E_TIP must be 0 or 1"
TIP_DEPLOYMENTS=()
if [[ $E2E_TIP == 1 ]]; then
  read -r -a TIP_DEPLOYMENTS <<<"${E2E_TIP_DEPLOYMENTS-amm-tip-shared amm-tip amm-tip-stale}"
  ((${#TIP_DEPLOYMENTS[@]})) \
    || die "missing [tip] section: E2E_TIP=1 and E2E_TIP_DEPLOYMENTS names no deployment (e2e/tip/<name>.json), so the nodes and the orchestrator would start with no [tip] namespace"
  for d in "${TIP_DEPLOYMENTS[@]}"; do
    [[ $d =~ ^[a-z0-9_-]+$ && -f $E2E_DIR/tip/$d.json ]] \
      || die "missing [tip] section: no tip deployment e2e/tip/$d.json (E2E_TIP_DEPLOYMENTS names deployments by file, without .json)"
  done
  # The deployments' examples, and the smoke's circuit: the first package of the first.
  read -r TIP_EXAMPLES TIP_SMOKE < <(python3 - "$E2E_DIR/tip" "${TIP_DEPLOYMENTS[@]}" <<'PY'
import json, sys
specs = [json.load(open(f"{sys.argv[1]}/{d}.json")) for d in sys.argv[2:]]
examples = list(dict.fromkeys(f"examples/{s['example']}" for s in specs))
first = json.load(open(f"{sys.argv[1]}/../../examples/{specs[0]['example']}/deployments/{specs[0]['descriptor']}.json"))
print(",".join(examples), f"{specs[0]['example']}/{first['packages'][0]['circuit']}")
PY
  )
  : "${E2E_EXAMPLES:=${TIP_EXAMPLES//,/ }}" "${SMOKE_CIRCUIT:=$TIP_SMOKE}"
  : "${NODE_API_BASE_PORT:=8300}" "${MESH_BASE_PORT:=10300}" "${PG_BASE_PORT:=15732}" "${ORCH_PORT:=3300}"
  : "${AZTEC_PORT:=8380}" "${AZTEC_ADMIN_PORT:=9180}" "${ANVIL_PORT:=8845}" "${PG_PREFIX:=sidecar-tip-e2e-pg}"
fi
export SMOKE_CIRCUIT="${SMOKE_CIRCUIT:-amm/pss_seed}"
# The relayers' status ports: RELAYER_PORT (default 3301) for the first
# deployment, one more for each next.
export RELAYER_PORT=${RELAYER_PORT:-3301}

# ---- ports, names, timeouts --------------------------------------------------
# The harness ports (e2e/README.md, "Ports"): node
# HTTPS API 8200-8202 (NODE_API_BASE_PORT), MPC mesh 10200-10202
# (MESH_BASE_PORT), Postgres 15632-15634 (PG_BASE_PORT), orchestrator 3200
# (ORCH_PORT), Aztec node 8280 (AZTEC_PORT), Aztec admin 9080
# (AZTEC_ADMIN_PORT), anvil 8745 (ANVIL_PORT). Each base names node 0's port
# and node i uses base + i. Every service binds 127.0.0.1 only (the local
# network through harness/loopback.mjs, checked after its start).
# Consequences: move any of them with its variable; the script refuses to start when a port is taken or leased by
# another run (the port leases below), so two runs of this harness need
# disjoint ports and a different PG_PREFIX. A tip run (E2E_TIP=1) moves
# every default to the 8300 range and the relayers from 3301 (above).
NODE_API_BASE_PORT=${NODE_API_BASE_PORT:-8200}
MESH_BASE_PORT=${MESH_BASE_PORT:-10200}
PG_BASE_PORT=${PG_BASE_PORT:-15632}
ORCH_PORT=${ORCH_PORT:-3200}
export AZTEC_PORT=${AZTEC_PORT:-8280}
export AZTEC_ADMIN_PORT=${AZTEC_ADMIN_PORT:-9080}
export ANVIL_PORT=${ANVIL_PORT:-8745}
export REORG_PORT=${REORG_PORT:-$((AZTEC_ADMIN_PORT + 1))}
AZTEC_NODE_URL="http://127.0.0.1:$AZTEC_PORT"
ORCHESTRATOR_URL="https://127.0.0.1:$ORCH_PORT"
# The Postgres containers are named $PG_PREFIX0..2 (default
# sidecar-e2e-pg), run PG_IMAGE (toolchain.json postgres.image, pinned by digest) with the
# development password "postgres", keep their data inside the container and
# are started with --rm, so stopping them deletes every node's tables. A run
# starts from empty stores, and a leftover container with the same name is
# refused rather than reused. Consequences: nothing a run stored survives it; a
# different PG_PREFIX lets a second run (on other ports) coexist.
PG_PREFIX=${PG_PREFIX:-sidecar-e2e-pg}
PG_IMAGE="$(pin postgres.image)"
[[ -n $PG_IMAGE ]] || die "toolchain.json names no postgres.image"
# EXPECT_REAL_PROOFS, default 1. With 1 the PXE proves every
# transaction client-side and the node verifies it (the node-side recipe
# below); the smoke and the drivers then require the node's verifier lines.
# With 0 the network starts with simulated proofs, nothing is proved
# client-side, transactions take seconds instead of minutes, and a run
# establishes only that the machine and the contracts' logic work, not that
# any proof is checked by the node.
EXPECT_REAL_PROOFS=${EXPECT_REAL_PROOFS:-1}
[[ $EXPECT_REAL_PROOFS == 0 || $EXPECT_REAL_PROOFS == 1 ]] || die "EXPECT_REAL_PROOFS must be 0 or 1"
export EXPECT_REAL_PROOFS
# Timeouts, all in seconds and overridable: service start-up
# polls (START_TIMEOUT, default 120, for Postgres, each node and the
# orchestrator), the network's readiness (AZTEC_START_TIMEOUT, default 360),
# setup over the mesh (SETUP_TIMEOUT, default 120), the smoke
# (SMOKE_TIMEOUT, default 1800) and each scenario (DRIVER_TIMEOUT, default
# 10800). Real client-side proving of one transaction takes minutes and
# a scenario sends several; the start-up bounds only catch a service that
# will never come up. Consequences: a timeout fails the run and tears it
# down; raising one only delays that failure.
START_TIMEOUT=${START_TIMEOUT:-120}
AZTEC_START_TIMEOUT=${AZTEC_START_TIMEOUT:-360}
SETUP_TIMEOUT=${SETUP_TIMEOUT:-120}
SMOKE_TIMEOUT=${SMOKE_TIMEOUT:-1800}
DRIVER_TIMEOUT=${DRIVER_TIMEOUT:-10800}
# The examples whose round circuits the run compiles, copies
# and configures (E2E_EXAMPLES, default "examples/amm examples/monty-hall",
# repository-relative). The driver finds a scenario's circuits, manifests,
# vk hashes and ready pss-client configuration in harness.json under the
# example's directory name. Consequences: a scenario of an example left out
# finds nothing; the CRS is sized for the largest circuit of the list.
read -r -a EXAMPLES <<<"${E2E_EXAMPLES:-examples/amm examples/monty-hall}"

# ---- port leases ------------------------------------------------------------------
# Every port of the run is leased for the run's whole life: an flock on
# $TXE_TMP_ROOT/port-leases/<port>, taken on a descriptor this shell and every
# child it starts keep open, so the kernel releases it when the last of them
# exits (also after kill -9; a process the run leaves behind keeps it). A run
# whose ports overlap one a running run leased stops here and names the
# holder. The bind check before the services start cannot see this on its
# own: a node binds its mesh port only while a session opens, so a running
# run's mesh ports look free between sessions and another run's service
# could take them, failing the next session with "Address already in use".
# Runs coordinate through one TXE_TMP_ROOT (the default is shared).
RUN_PORTS=()
for base in "$NODE_API_BASE_PORT" "$MESH_BASE_PORT" "$PG_BASE_PORT"; do
  [[ $base =~ ^[0-9]+$ ]] || die "port $base is not a number"
  RUN_PORTS+=("$base" $((base + 1)) $((base + 2)))
done
RUN_PORTS+=("$ORCH_PORT" "$AZTEC_PORT" "$AZTEC_ADMIN_PORT" "$ANVIL_PORT")
[[ $E2E_REORG == 1 ]] && RUN_PORTS+=("$REORG_PORT")
for i in "${!TIP_DEPLOYMENTS[@]}"; do RUN_PORTS+=($((RELAYER_PORT + i))); done
PORT_LEASES="$TXE_TMP_ROOT/port-leases"
mkdir -p "$PORT_LEASES" || die "cannot create $PORT_LEASES"
declare -A leased=()
for port in "${RUN_PORTS[@]}"; do
  [[ $port =~ ^[0-9]+$ ]] || die "port $port is not a number"
  [[ -z ${leased[$port]:-} ]] || die "service ports overlap (port $port twice)"
  exec {lease}>>"$PORT_LEASES/$port" || die "cannot open the lease file of port $port"
  flock -n "$lease" || die "port $port is leased by another e2e run ($(cat "$PORT_LEASES/$port" 2>/dev/null))"
  echo "pid $$, run directory $RUN_DIR" >"$PORT_LEASES/$port"
  leased[$port]=1
done
echo "   ports leased: ${RUN_PORTS[*]}"

# wait_for <seconds> <pid or ""> <log> <what> <command...>: poll the command
# every half second until it succeeds; fail when the process dies or time runs out.
wait_for() {
  local limit=$1 pid=$2 log=$3 what=$4
  shift 4
  for _ in $(seq 1 $((limit * 2))); do
    "$@" >/dev/null 2>&1 && return 0
    if [[ -n $pid ]] && ! kill -0 "$pid" 2>/dev/null; then
      tail -30 "$log" >&2
      die "$what exited during start-up ($log)"
    fi
    sleep 0.5
  done
  tail -30 "$log" >&2
  die "$what did not come up within ${limit}s ($log)"
}
listening() { ss -ltnH "sport = :$1" | grep -q LISTEN; }
# Every harness script gets harness.json (E2E_HARNESS), the dev CA
# (NODE_EXTRA_CA_CERTS), the workspaces' sources (--conditions=source) and the
# JSON-import hook (register.mjs: @aztec-labs/accounts and the kernel
# artifacts import JSON without the import attribute).
run_ts() {                           # run_ts <label> <timeout> <script.ts> [argument ...]
  local label=$1 limit=$2 script=$3
  shift 3
  timeout "$limit" node --conditions=source --import "$REPO_ROOT/ts/hooks/register.mjs" "$script" "$@" > >(tee "$LOGS/$label.log") 2>&1 &
  local pid=$!
  SERVICE_PIDS+=("$pid")
  wait "$pid"
}

# ---- tool identities ------------------------------------------------------------
phase "tool identities"
"$REPO_ROOT/scripts/bootstrap.sh" >"$LOGS/bootstrap.log" 2>&1 \
  || { cat "$LOGS/bootstrap.log" >&2; die "scripts/bootstrap.sh failed (nargo, bb, Rust, node or docker)"; }
# Foundry: ANVIL_BIN/FORGE_BIN/CAST_BIN, or the first candidate with the
# pinned version (find_foundry, scripts/toolchain.sh: FOUNDRY_DIR, then the
# search order of @aztec-labs/ethereum). The CLI deploys the L1 contracts with
# forge flags older releases reject.
for tool in anvil forge cast; do
  var="$(tr '[:lower:]' '[:upper:]' <<<"$tool")_BIN"
  printf -v "$var" '%s' "$(find_foundry "$tool" || true)"
  [[ -n ${!var} ]] || die "$tool $FOUNDRY_VERSION not found; run scripts/install-toolchain.sh --with-foundry or set $var"
  export "${var?}"
done
for cmd in docker node npm curl ss python3 pgrep; do command -v "$cmd" >/dev/null || die "$cmd not found"; done
node_major="$(node --version)"; node_major="${node_major#v}"; node_major="${node_major%%.*}"
((node_major >= NODE_MAJOR)) || die "node $NODE_MAJOR or later required, found $(node --version)"
docker info >/dev/null 2>&1 || die "docker does not answer (docker info)"

# The @aztec-labs release: every package in the root lockfile and every
# installed one must be the pinned version.
LABS_VERSION="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["labs"]["sdk_version"])' "$REPO_ROOT/toolchain.json")"
python3 - "$REPO_ROOT/package-lock.json" "$LABS_VERSION" <<'PY' || die "the root package-lock.json does not pin every @aztec-labs package to $LABS_VERSION"
import json, re, sys
lock, want = json.load(open(sys.argv[1])), sys.argv[2]
labs = {k: v.get("version") for k, v in lock["packages"].items() if re.search(r"(^|/)node_modules/@aztec-labs/[^/]+$", k)}
bad = {k: v for k, v in labs.items() if v != want}
if not labs or bad:
    sys.exit(f"@aztec-labs packages not at {want}: {bad or 'none locked'}")
PY

phase "npm workspace" "root package-lock.json"
# A tree already installed from the root lockfile is kept (npm ls checks it
# against the workspace's package.json files); otherwise npm ci reinstalls.
if [[ -f $REPO_ROOT/node_modules/.package-lock.json ]] && (cd "$REPO_ROOT" && npm ls --all >"$LOGS/npm-ls.log" 2>&1); then
  echo "   node_modules matches the lockfile"
else
  (cd "$REPO_ROOT" && timeout 1200 npm ci --no-audit --no-fund) >"$LOGS/npm-ci.log" 2>&1 \
    || die "npm ci failed ($LOGS/npm-ci.log)"
fi
python3 - "$REPO_ROOT/node_modules/@aztec-labs" "$LABS_VERSION" <<'PY' || die "installed @aztec-labs packages differ from $LABS_VERSION"
import json, pathlib, sys
root, want = pathlib.Path(sys.argv[1]), sys.argv[2]
bad = {p.name: json.loads((p / "package.json").read_text())["version"] for p in root.iterdir() if (p / "package.json").exists()}
bad = {k: v for k, v in bad.items() if v != want}
if bad:
    sys.exit(f"installed @aztec-labs packages not at {want}: {bad}")
PY
AZTEC_CLI="${AZTEC_CLI:-$REPO_ROOT/node_modules/.bin/aztec}"
cli_version="$("$AZTEC_CLI" --version)" || die "aztec CLI version check failed"
[[ ${cli_version#v} == "$LABS_VERSION" ]] || die "need the @aztec-labs CLI $LABS_VERSION (got: $cli_version)"
# Client-side proving uses the bb shipped in bb.js; it must be the pinned bb.
BUNDLED_BB="$REPO_ROOT/node_modules/@aztec-foundation/bb.js/build/amd64-linux/bb"
if [[ "$(uname -s)-$(uname -m)" == Linux-x86_64 ]]; then
  cmp -s "$BUNDLED_BB" "$BB_BIN" || die "bb.js's bundled bb ($BUNDLED_BB) differs from the pinned bb ($BB_BIN)"
fi

phase "build" "sidecar binaries, pss-client, harness type check"
# The sidecar binaries. By default run.sh builds sidecar-node and
# sidecar-orchestrator from the working tree (cargo build --release --locked,
# a no-op when they are fresh) and runs them from the release directory of
# the target directory cargo metadata names (machine/target, or wherever
# CARGO_TARGET_DIR or a cargo config puts it). A run
# must exercise the sources it is run from, and a stale binary is the usual
# cause of a confusing failure. SIDECAR_BIN_DIR names a directory of
# prebuilt binaries instead, and then nothing is built; their versions are
# whatever that directory holds.
if [[ -n ${SIDECAR_BIN_DIR:-} ]]; then
  BIN_DIR="$(cd "$SIDECAR_BIN_DIR" && pwd)" || die "SIDECAR_BIN_DIR=$SIDECAR_BIN_DIR does not exist"
else
  (cd "$REPO_ROOT/machine" && timeout 3600 cargo build --release --locked -p sidecar-node -p sidecar-orchestrator) \
    >"$LOGS/cargo-build.log" 2>&1 || die "cargo build failed ($LOGS/cargo-build.log)"
  TARGET_DIR="$(cd "$REPO_ROOT/machine" && cargo metadata --format-version 1 --no-deps --locked 2>>"$LOGS/cargo-build.log" \
    | python3 -c 'import json, sys; print(json.load(sys.stdin)["target_directory"])')" \
    || die "cargo metadata names no target directory ($LOGS/cargo-build.log)"
  BIN_DIR="$TARGET_DIR/release"
fi
NODE_BIN="$BIN_DIR/sidecar-node"
ORCH_BIN="$BIN_DIR/sidecar-orchestrator"
[[ -x $NODE_BIN && -x $ORCH_BIN ]] || die "no sidecar-node and sidecar-orchestrator in $BIN_DIR"
# The harness runs pss-client from source (--conditions=source); its build
# is the type check of the package.
"$REPO_ROOT/node_modules/.bin/tsc" -p "$REPO_ROOT/ts/pss-client/tsconfig.json" >"$LOGS/pss-client-build.log" 2>&1 \
  || die "pss-client does not build ($LOGS/pss-client-build.log)"
"$REPO_ROOT/node_modules/.bin/tsc" -p "$E2E_DIR/tsconfig.json" >"$LOGS/harness-typecheck.log" 2>&1 \
  || die "the harness does not type-check ($LOGS/harness-typecheck.log)"
{
  echo "aztec CLI: $cli_version ($AZTEC_CLI)"
  echo "bb: $("$BB_BIN" --version) $(sha256sum "$BB_BIN")"
  echo "nargo (circuits): $("$NARGO_BIN" --version | tr '\n' ' ')"
  echo "nargo (contracts): $("$CONTRACT_NARGO_BIN" --version | tr '\n' ' ')"
  echo "anvil: $("$ANVIL_BIN" --version | head -1) ($ANVIL_BIN)"
  echo "node: $(node --version)"
  echo "docker: $(docker version --format '{{.Server.Version}}' 2>/dev/null)"
  echo "sidecar binaries: $BIN_DIR $(sha256sum "$NODE_BIN" "$ORCH_BIN" | cut -c1-16 | tr '\n' ' ')"
  echo "repository: $(git -C "$REPO_ROOT" rev-parse --short HEAD 2>/dev/null)$(git -C "$REPO_ROOT" diff --quiet HEAD 2>/dev/null || echo ' (with uncommitted changes)')"
} | tee "$RUN_DIR/tools.txt"

# ---- ports and container names are free ------------------------------------------
# Refuse occupied ports before creating any service: a readiness check must
# never mistake another invocation's listener for one of ours.
python3 - "${RUN_PORTS[@]}" <<'PORT_CHECK' || die "a required service port is occupied"
import socket, sys
for port in map(int, sys.argv[1:]):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(("127.0.0.1", port))
        except OSError as error:
            raise SystemExit(f"port {port}: {error}")
PORT_CHECK
for i in 0 1 2; do
  [[ -z "$(docker ps -aq --filter "name=^$PG_PREFIX$i\$")" ]] \
    || die "container $PG_PREFIX$i already exists (another run, or a leftover: docker rm -f $PG_PREFIX$i)"
done

# ---- circuits, CRS, TLS planes, vks ----------------------------------------------
DATA_DIR="$RUN_DIR/data"
KEYS="$RUN_DIR/keys"
VK_DIR="$RUN_DIR/vks"
phase "circuits and CRS" "scripts/prepare-data.sh into $DATA_DIR"
example_dirs=()
for e in "${EXAMPLES[@]}"; do example_dirs+=("$REPO_ROOT/$e"); done
DATA_DIR="$DATA_DIR" timeout 1800 "$REPO_ROOT/scripts/prepare-data.sh" "${example_dirs[@]}" >"$LOGS/prepare-data.log" 2>&1 \
  || die "prepare-data.sh failed ($LOGS/prepare-data.log)"
phase "dev TLS planes" "scripts/gen-dev-certs.sh into $KEYS"
timeout 1800 "$REPO_ROOT/scripts/gen-dev-certs.sh" "$KEYS" >"$LOGS/gen-dev-certs.log" 2>&1 \
  || die "gen-dev-certs.sh failed ($LOGS/gen-dev-certs.log)"
phase "verification keys" "bb write_vk, JSON fields for the drivers and the vk hashes"
mkdir -p "$VK_DIR"
for circuit in "$DATA_DIR"/circuits/*.json; do
  c="$(basename "$circuit" .json)"
  mkdir -p "$VK_DIR/$c"
  timeout 600 "$BB_BIN" write_vk --scheme ultra_honk --oracle_hash poseidon2 --output_format json \
    -b "$circuit" -o "$VK_DIR/$c" >>"$LOGS/write-vk.log" 2>&1 || die "bb write_vk failed for $c ($LOGS/write-vk.log)"
  mv "$VK_DIR/$c/vk.json" "$VK_DIR/$c.vk.json" && rmdir "$VK_DIR/$c"
done

# ---- configs ------------------------------------------------------------------------
phase "configs" "$RUN_DIR/config"
CFG="$RUN_DIR/config"
for i in 0 1 2; do
  {
    echo "# Mesh config of node $i for this run (written by e2e/run.sh)."
    echo "my_id = $i"
    echo "bind_addr = \"127.0.0.1:$((MESH_BASE_PORT + i))\""
    echo 'connect_timeout = "30s"'
    echo 'timeout = "10m"'
    for j in 0 1 2; do
      printf '\n[[parties]]\nid = %d\ndns_name = "127.0.0.1:%d"\n' "$j" "$((MESH_BASE_PORT + j))"
    done
    printf '\n[tls]\nkey = "%s/mesh-key%d.der"\n' "$KEYS" "$i"
    printf 'certs = ["%s/mesh-cert0.der", "%s/mesh-cert1.der", "%s/mesh-cert2.der"]\n' "$KEYS" "$KEYS" "$KEYS"
  } >"$CFG/party$i.toml"
  # The Postgres URL carries the development password; the file is as
  # private as the key directory.
  cat >"$CFG/node$i.toml" <<EOF
# Node config of node $i for this run (written by e2e/run.sh).
party = $i
api_listen = "127.0.0.1:$((NODE_API_BASE_PORT + i))"
mesh_config = "$CFG/party$i.toml"
key_dir = "$KEYS/node$i"
run_dir = "$RUN_DIR/run/node$i"
requests_retention_days = 30
prune_interval_secs = 3600

[tls]
ca = "$KEYS/https-ca.pem"
cert = "$KEYS/https-node$i.pem"
key = "$KEYS/https-node$i-key.pem"

[store]
backend = "postgres"
url = "postgresql://postgres:postgres@127.0.0.1:$((PG_BASE_PORT + i))/postgres"

[crs]
g1 = "$DATA_DIR/bn254_g1.dat"
g2 = "$DATA_DIR/bn254_g2.dat"
circuits_dir = "$DATA_DIR/circuits"
EOF
done
chmod 600 "$CFG"/node*.toml

# ---- node setup -----------------------------------------------------------------------
# How the nodes' keys are made. Default E2E_SETUP=mesh: the
# three `sidecar-node setup` processes run at once, each draws its own enc
# and sig scalars and the three sample the master nullifier share over one
# mesh session, as a deployment does, so the run also exercises the TLS mesh
# before any request. E2E_SETUP=dealer runs `setup --dealer` instead: one
# process writes all three nodes' keys and a sharing of a master it saw,
# with no mesh; faster to debug, never a deployment. Either way the printed
# public keys are what the orchestrator config and pss-client pin and what
# GET /v1/nodes is checked against.
E2E_SETUP=${E2E_SETUP:-mesh}
phase "node setup" "$E2E_SETUP"
export NO_COLOR=1
case $E2E_SETUP in
  mesh)
    setup_pids=()
    for i in 0 1 2; do
      RUST_LOG=info timeout "$SETUP_TIMEOUT" "$NODE_BIN" setup --config "$CFG/node$i.toml" \
        >"$LOGS/setup$i.log" 2>&1 &
      setup_pids+=($!)
      SERVICE_PIDS+=($!)
    done
    for i in 0 1 2; do
      wait "${setup_pids[$i]}" || { tail -20 "$LOGS/setup$i.log" >&2; die "setup of node $i failed ($LOGS/setup$i.log)"; }
    done
    SERVICE_PIDS=()
    for i in 0 1 2; do grep '^{' "$LOGS/setup$i.log"; done >"$KEYS/setup-keys.jsonl"
    ;;
  dealer)
    RUST_LOG=info timeout "$SETUP_TIMEOUT" "$NODE_BIN" setup --dealer \
      --config "$CFG/node0.toml" --config "$CFG/node1.toml" --config "$CFG/node2.toml" \
      >"$LOGS/setup.log" 2>&1 || die "setup --dealer failed ($LOGS/setup.log)"
    grep '^{' "$LOGS/setup.log" >"$KEYS/setup-keys.jsonl"
    ;;
  *) die "E2E_SETUP must be mesh or dealer" ;;
esac
NODE_KEYS="$KEYS/setup-keys.json"
python3 - "$KEYS/setup-keys.jsonl" "$NODE_KEYS" <<'PY' || die "setup did not print the three nodes' keys"
import json, sys
lines = [json.loads(l) for l in open(sys.argv[1]) if l.strip()]
lines.sort(key=lambda k: k["party"])
if [k["party"] for k in lines] != [0, 1, 2]:
    sys.exit(f"setup printed keys for parties {[k['party'] for k in lines]}")
json.dump(lines, open(sys.argv[2], "w"), indent=1)
for k in lines:
    print(f"   node {k['party']}: enc.x {k['enc']['x'][:18]}..  sig.x {k['sig']['x'][:18]}..")
PY

# The orchestrator's public certificate. The development TLS
# set has no certificate of its own for the public listener, so the
# orchestrator serves node 0's development server certificate, which names
# localhost and 127.0.0.1 under the dev CA (as the orchestrator's tests do);
# the drivers trust that CA through NODE_EXTRA_CA_CERTS and reach
# https://127.0.0.1:$ORCH_PORT, so pss-client runs with TLS and never with
# allowInsecureHttp. A deployment gives the public listener a certificate of
# its own, from any CA its clients trust.
python3 - "$NODE_KEYS" "$CFG/orchestrator.toml" "$ORCH_PORT" "$NODE_API_BASE_PORT" "$KEYS" "$RUN_DIR" "$DATA_DIR" <<'PY' || die "could not write the orchestrator config"
import json, sys
keys_file, out, orch, api, keys, run, data = sys.argv[1:]
nodes = json.load(open(keys_file))
point = lambda p: f'{{ x = "{p["x"]}", y = "{p["y"]}" }}'
lines = [
    "# Orchestrator config for this run (written by e2e/run.sh); the node keys",
    "# are the ones `sidecar-node setup` printed.",
    f'listen = "127.0.0.1:{orch}"',
    "",
    "[tls]",
    f'cert = "{keys}/https-node0.pem"',
    f'key = "{keys}/https-node0-key.pem"',
    "",
    "[node_tls]",
    f'ca = "{keys}/https-ca.pem"',
    f'cert = "{keys}/https-orchestrator.pem"',
    f'key = "{keys}/https-orchestrator-key.pem"',
    "",
    "[registry]",
    f'path = "{run}/run/orchestrator/registry"',
    "",
    "[crs]",
    f'g1 = "{data}/bn254_g1.dat"',
    f'g2 = "{data}/bn254_g2.dat"',
    f'circuits_dir = "{data}/circuits"',
]
for k in nodes:
    lines += ["", "[[nodes]]", f'url = "https://127.0.0.1:{int(api) + k["party"]}"',
              f"enc = {point(k['enc'])}", f"sig = {point(k['sig'])}"]
open(out, "w").write("\n".join(lines) + "\n")
PY
mkdir -p "$RUN_DIR/run/orchestrator"

# ---- harness.json and the pss-client configurations --------------------------------------
NETWORK_LOG="$LOGS/network.log"
export E2E_HARNESS="$RUN_DIR/harness.json"
export NODE_EXTRA_CA_CERTS="$KEYS/https-ca.pem"
E2E_RUN_DIR="$RUN_DIR" REPO_ROOT="$REPO_ROOT" DATA_DIR="$DATA_DIR" VK_DIR="$VK_DIR" NODE_KEYS="$NODE_KEYS" \
  ORCHESTRATOR_URL="$ORCHESTRATOR_URL" CA_CERT="$KEYS/https-ca.pem" AZTEC_NODE_URL="$AZTEC_NODE_URL" \
  NETWORK_LOG="$NETWORK_LOG" BB_BIN="$BB_BIN" CONTRACT_NARGO_BIN="$CONTRACT_NARGO_BIN" \
  node --conditions=source "$E2E_DIR/harness/prepare.ts" "${example_dirs[@]}" >"$LOGS/prepare-harness.log" 2>&1 \
  || { cat "$LOGS/prepare-harness.log" >&2; die "harness/prepare.ts failed"; }
sed 's/^/   /' "$LOGS/prepare-harness.log"

# ---- the tip sections --------------------------------------------------------------------
# A tip run plans its deployments (harness/tip.ts plan: each contract built,
# its salt drawn, its address computed from the pins with the sig keys setup
# printed), then gives the three nodes and the orchestrator their [tip]
# section: each its Aztec node (the one local network: every node's chain
# verifier reads the same view here, where a deployment gives each node
# its own) and the same [[tip.namespaces]] entries, <run>/config/tip.toml.
# setup ran on the configs without it, before any address was known. The
# node-held tip state lives in the nodes' Postgres stores, which the run
# keeps from here to teardown (no reset between drivers); stopping the
# containers deletes them.
if [[ $E2E_TIP == 1 ]]; then
  phase "tip plan" "${TIP_DEPLOYMENTS[*]}: contracts, salts, addresses"
  run_ts tip-plan 3600 "$E2E_DIR/harness/tip.ts" plan "${TIP_DEPLOYMENTS[@]}" \
    || die "harness/tip.ts plan failed ($LOGS/tip-plan.log)"
  for i in 0 1 2; do
    printf '\n[tip]\naztec_node = "%s"\n\n' "$AZTEC_NODE_URL" >>"$CFG/node$i.toml"
    cat "$CFG/tip.toml" >>"$CFG/node$i.toml"
  done
  printf '\n[tip]\naztec_node = "%s"\npoll_interval_ms = 1000\npipeline_depth = 1\n\n' "$AZTEC_NODE_URL" >>"$CFG/orchestrator.toml"
  cat "$CFG/tip.toml" >>"$CFG/orchestrator.toml"
  # The named start-up failure: every one of the four configs carries [tip]
  # with the run's namespaces, or nothing starts.
  python3 - "$CFG/tip.toml" "$CFG"/node{0,1,2}.toml "$CFG/orchestrator.toml" <<'PY' \
    || die "missing [tip] section: a node or the orchestrator config lacks the run's [tip] namespaces"
import sys, tomllib
want = tomllib.load(open(sys.argv[1], "rb"))["tip"]["namespaces"]
bad = []
for path in sys.argv[2:]:
    tip = tomllib.load(open(path, "rb")).get("tip")
    if tip is None:
        bad.append(f"{path}: no [tip] section")
    elif tip.get("namespaces") != want:
        bad.append(f"{path}: [tip] namespaces differ from {sys.argv[1]}")
if bad:
    sys.exit("\n".join(bad))
print(f"   [tip] with {len(want)} namespace(s) in the three node configs and the orchestrator's")
PY
fi

# ---- Postgres, nodes, orchestrator --------------------------------------------------------
phase "postgres" "$PG_IMAGE on 127.0.0.1:$PG_BASE_PORT..$((PG_BASE_PORT + 2))"
for i in 0 1 2; do
  docker run -d --rm --name "$PG_PREFIX$i" -e POSTGRES_PASSWORD=postgres \
    -p "127.0.0.1:$((PG_BASE_PORT + i)):5432" "$PG_IMAGE" >"$LOGS/postgres$i.id" 2>&1 \
    || { cat "$LOGS/postgres$i.id" >&2; die "could not start $PG_PREFIX$i"; }
  PG_CONTAINERS+=("$PG_PREFIX$i")
done
# Over TCP inside the container: the image's first-start server listens on
# the Unix socket only, so a TCP answer means the real server is up.
for i in 0 1 2; do
  wait_for "$START_TIMEOUT" "" "$LOGS/postgres$i.id" "$PG_PREFIX$i" \
    docker exec "$PG_PREFIX$i" pg_isready -h 127.0.0.1 -U postgres
done

# What a scenario that replaces a node needs of the run (steps/tip-replace-node.ts):
# the binaries, the configs, the logs, the Postgres containers and the
# services' pid files (node<i>, orchestrator, and `extra` for what the step
# starts, which the teardown stops too).
export E2E_PIDS="$RUN_DIR/pids" E2E_NODE_BIN="$NODE_BIN" E2E_ORCH_BIN="$ORCH_BIN" E2E_CFG="$CFG" \
  E2E_LOGS="$LOGS" E2E_PG_PREFIX="$PG_PREFIX"
mkdir -p "$E2E_PIDS"

phase "nodes" "sidecar-node serve, API $NODE_API_BASE_PORT..$((NODE_API_BASE_PORT + 2)), mesh $MESH_BASE_PORT..$((MESH_BASE_PORT + 2))"
for i in 0 1 2; do
  RUST_LOG=info "$NODE_BIN" serve --config "$CFG/node$i.toml" >"$LOGS/node$i.log" 2>&1 &
  SERVICE_PIDS+=($!)
  node_pids[i]=$!
  echo "$!" >"$E2E_PIDS/node$i"
done
for i in 0 1 2; do
  wait_for "$START_TIMEOUT" "${node_pids[$i]}" "$LOGS/node$i.log" "node $i" \
    grep -q "node serving" "$LOGS/node$i.log"
  listening $((NODE_API_BASE_PORT + i)) || die "node $i logged 'node serving' but nothing listens on $((NODE_API_BASE_PORT + i))"
done

phase "orchestrator" "https://127.0.0.1:$ORCH_PORT"
RUST_LOG=info "$ORCH_BIN" --config "$CFG/orchestrator.toml" >"$LOGS/orchestrator.log" 2>&1 &
SERVICE_PIDS+=($!)
orch_pid=$!
echo "$orch_pid" >"$E2E_PIDS/orchestrator"
wait_for "$START_TIMEOUT" "$orch_pid" "$LOGS/orchestrator.log" "the orchestrator" listening "$ORCH_PORT"
if [[ $E2E_TIP == 1 ]]; then
  # What each binary logs when it loaded its [tip] section: a node its chain
  # verifier (the receipt signer reads the same section), the orchestrator
  # one scheduler per namespace.
  for i in 0 1 2; do
    grep -q "chain verifier configured" "$LOGS/node$i.log" \
      || die "missing [tip] section: node $i started without its chain verifier (no 'chain verifier configured' in $LOGS/node$i.log)"
  done
  schedulers="$(grep -c "scheduler started" "$LOGS/orchestrator.log")"
  ((schedulers == ${#TIP_DEPLOYMENTS[@]})) \
    || die "missing [tip] section: the orchestrator started $schedulers scheduler(s) for ${#TIP_DEPLOYMENTS[@]} namespace(s) ($LOGS/orchestrator.log)"
  echo "   each node's chain verifier and receipt route, and ${schedulers} scheduler(s) with their chain readers, are up"
fi

# GET /v1/nodes through the orchestrator (which reads every node's keys and
# compares them with its pins) must equal what setup printed.
curl -fsS --cacert "$KEYS/https-ca.pem" "$ORCHESTRATOR_URL/v1/nodes" >"$RUN_DIR/nodes.json" 2>"$LOGS/nodes-check.log" \
  || { cat "$LOGS/nodes-check.log" >&2; die "GET /v1/nodes through the orchestrator failed"; }
python3 - "$RUN_DIR/nodes.json" "$NODE_KEYS" <<'PY' || die "GET /v1/nodes does not match the keys setup printed; refusing to run"
import json, sys
got = json.load(open(sys.argv[1]))["nodes"]
want = json.load(open(sys.argv[2]))
norm = lambda p: {c: int(p[c], 16) for c in ("x", "y")}
for i, (g, w) in enumerate(zip(got, want)):
    for key in ("enc", "sig"):
        if norm(g[key]) != norm(w[key]):
            sys.exit(f"node {i} {key}: GET /v1/nodes answers {g[key]}, setup printed {w[key]}")
if len(got) != 3:
    sys.exit(f"GET /v1/nodes answered {len(got)} nodes")
print("   GET /v1/nodes matches the keys setup printed")
PY

# ---- the local Aztec network -----------------------------------------------------------------
# A run-local credential for the network's authenticated admin endpoint.
E2E_ADMIN_API_KEY="$(node -e 'process.stdout.write(require("node:crypto").randomBytes(32).toString("hex"))')"
AZTEC_ADMIN_API_KEY_HASH="$(E2E_ADMIN_API_KEY=$E2E_ADMIN_API_KEY node -e 'process.stdout.write(require("node:crypto").createHash("sha256").update(process.env.E2E_ADMIN_API_KEY).digest("hex"))')"
export E2E_ADMIN_API_KEY AZTEC_ADMIN_API_KEY_HASH
if [[ $E2E_REORG == 1 ]]; then
  phase "network start" "harness/reorg-network.ts, node $AZTEC_PORT, admin $AZTEC_ADMIN_PORT, anvil $ANVIL_PORT, test calls $REORG_PORT"
else
  phase "network start" "aztec start --local-network, node $AZTEC_PORT, admin $AZTEC_ADMIN_PORT, anvil $ANVIL_PORT"
fi
# Node-side proof verification. With EXPECT_REAL_PROOFS=1
# the network starts with BB_WORKING_DIRECTORY (a fresh directory in the run
# directory) and BB_BINARY_PATH (the pinned bb 6.0.0 of scripts/toolchain.sh,
# checked above to be byte-identical to bb.js's bundled bb), with debug
# logging for bb-prover:verifier; after bootstrap
# harness/enable-real-proofs.ts sets the node's realProofs false and then
# true and requires the node log line "Starting QueuedIVCVerifier". The
# v6 local network always starts with simulated proofs (it ignores
# PROVER_REAL_PROOFS) and builds its proof verifier only when realProofs
# changes through nodeAdmin_setConfig. The first such call after start is
# not seen as a change: the node merges the new values into a config object
# it shares with the automine sequencer before comparing old and new, so
# old and new are the same object (the setConfig aliasing bug), and only a
# second call that flips the value again builds the verifier. The build
# needs BB_WORKING_DIRECTORY (the call fails without it) and BB_BINARY_PATH
# (otherwise bb.js's bundled bb is used). Setting the flag alone makes
# getNodeInfo().realProofs read true while the node still accepts any proof
# bytes. The bb-prover:verifier debug logging prints one "Chonk verification
# successful" per verified proof, and the p2p:tx_validator:proof trace
# logging one "Accepted <tx hash> with valid proof" per accepted transaction,
# by which harness/node-verification.ts ties each transaction a driver sends
# to its own verification.
# Consequences: the smoke and every driver fail when either log line is
# missing, and each sends one transaction a second time with a changed
# proof field that the node must refuse with "Invalid proof". With
# EXPECT_REAL_PROOFS=0 none of this happens and the node accepts any proof.
# Epoch settlement stays synthetic either way.
# Loopback only: the CLI starts the node RPC and admin servers with no host
# and has no option for one, so harness/loopback.mjs, loaded into every Node
# process of the network, binds each listen that names no host to
# 127.0.0.1; anvil gets its host from ANVIL_IP_ADDR.
NETWORK_ENV=(
  NODE_OPTIONS="${NODE_OPTIONS:+$NODE_OPTIONS }--import=$E2E_DIR/harness/loopback.mjs"
  ANVIL_IP_ADDR=127.0.0.1
)
if [[ $EXPECT_REAL_PROOFS == 1 ]]; then
  mkdir -p "$RUN_DIR/bb"
  NETWORK_ENV+=(
    BB_WORKING_DIRECTORY="$RUN_DIR/bb"
    BB_BINARY_PATH="$BB_BIN"
    LOG_LEVEL="${LOG_LEVEL:-info};debug:bb-prover:verifier;trace:p2p:tx_validator:proof"
  )
fi
if [[ $E2E_REORG == 1 ]]; then
  # the reorg network: the same network through its own launcher, which
  # starts anvil itself (the comment at E2E_REORG)
  env "${NETWORK_ENV[@]}" setsid node --conditions=source --import "$REPO_ROOT/ts/hooks/register.mjs" \
    "$E2E_DIR/harness/reorg-network.ts" >"$NETWORK_LOG" 2>&1 &
else
  env "${NETWORK_ENV[@]}" setsid "$AZTEC_CLI" start --local-network >"$NETWORK_LOG" 2>&1 &
fi
NETWORK_PID=$!
node_info_ok() {
  curl -fsS -X POST -H 'content-type: application/json' \
    -d '{"jsonrpc":"2.0","method":"node_getNodeInfo","id":1}' "$AZTEC_NODE_URL" 2>/dev/null \
    | python3 -c 'import json,sys; r=json.load(sys.stdin); assert "result" in r and "error" not in r'
}
wait_for "$AZTEC_START_TIMEOUT" "$NETWORK_PID" "$NETWORK_LOG" "the local network" node_info_ok
# Refuse a network port that listens beyond loopback (the kernel's listening
# sockets: 127.0.0.0/8 and ::1 pass).
network_ports=("$AZTEC_PORT" "$AZTEC_ADMIN_PORT" "$ANVIL_PORT")
[[ $E2E_REORG == 1 ]] && network_ports+=("$REORG_PORT")
wide="$(python3 -I - "${network_ports[@]}" <<'PY'
import sys
ports = {int(p) for p in sys.argv[1:]}
for table in ("/proc/net/tcp", "/proc/net/tcp6"):
    for row in open(table).read().splitlines()[1:]:
        local, state = row.split()[1], row.split()[3]
        addr, port = local.split(":")
        if state != "0A" or int(port, 16) not in ports:
            continue
        loopback = addr.endswith("7F") if len(addr) == 8 else addr == "00000000000000000000000001000000"
        if not loopback:
            print(f"{int(port, 16)} ({table} {addr})")
PY
)"
[[ -z $wide ]] || die "the local network listens beyond 127.0.0.1 on: $wide"
if [[ $EXPECT_REAL_PROOFS == 1 ]]; then
  # Build the node's verifier and confirm it from the node log (the comment above).
  AZTEC_NODE_URL="$AZTEC_NODE_URL" NETWORK_LOG="$NETWORK_LOG" timeout 120 \
    node "$E2E_DIR/harness/enable-real-proofs.ts" 2>&1 | tee "$LOGS/enable-real-proofs.log"
  ((PIPESTATUS[0] == 0)) || die "could not enable the node's transaction proof verification"
fi

# ---- fees, tip deployments, relayers ---------------------------------------------------------
# A tip run funds every payer through wFJ before any tip transaction
# (harness/fees.ts, which stops the run naming what is missing), deploys and
# configures each deployment through pss-client deployTip (harness/tip.ts
# deploy; the scheduler then sends the init round), and starts one
# pss-relayer per deployment on its status port, then waits until each
# relayer has landed its deployment's init round (harness/tip.ts init: every
# slot the init creates written, by the relayer's own transaction).
# FEE_TIMEOUT (default 1800 s), DEPLOY_TIMEOUT (default 3600 s) and
# INIT_TIMEOUT (default 1800 s) bound the three scripts.
if [[ $E2E_TIP == 1 ]]; then
  phase "fee setup" "wFJ registered, every payer bridged and funded"
  run_ts fee-setup "${FEE_TIMEOUT:-1800}" "$E2E_DIR/harness/fees.ts"
  fee_status=$?
  if ((fee_status == 2)); then
    die "$(grep -o 'fee setup: .*' "$LOGS/fee-setup.log" | head -1)"
  fi
  ((fee_status == 0)) || die "harness/fees.ts failed ($LOGS/fee-setup.log)"
  phase "tip deploy" "deployTip: REGISTER, deploy, configure"
  run_ts tip-deploy "${DEPLOY_TIMEOUT:-3600}" "$E2E_DIR/harness/tip.ts" deploy \
    || die "harness/tip.ts deploy failed ($LOGS/tip-deploy.log)"
  phase "relayers" "pss-relayer, status on 127.0.0.1:$RELAYER_PORT.."
  for i in "${!TIP_DEPLOYMENTS[@]}"; do
    d="${TIP_DEPLOYMENTS[$i]}"
    node --conditions=source --import "$REPO_ROOT/ts/hooks/register.mjs" "$REPO_ROOT/ts/pss-relayer/src/main.ts" "$RUN_DIR/config/relayer-$d.json" \
      >"$LOGS/relayer-$d.log" 2>&1 &
    relayer_pid=$!
    SERVICE_PIDS+=("$relayer_pid")
    # A driver suspends and resumes the relayer by this pid (steps/relayer.ts).
    echo "$relayer_pid" >"$RUN_DIR/run/relayer-$d.pid"
    wait_for "$START_TIMEOUT" "$relayer_pid" "$LOGS/relayer-$d.log" "the relayer of $d" \
      curl -fsS "http://127.0.0.1:$((RELAYER_PORT + i))/status"
    echo "   relayer of $d: $(grep -o 'relaying for .*' "$LOGS/relayer-$d.log" | head -1)"
  done
  export INIT_TIMEOUT=${INIT_TIMEOUT:-1800}
  phase "init round" "each relayer lands its deployment's init round, timeout ${INIT_TIMEOUT}s"
  run_ts tip-init "$((INIT_TIMEOUT + 120))" "$E2E_DIR/harness/tip.ts" init \
    || die "the init round did not land ($LOGS/tip-init.log)"
  grep -o 'init round landed by the relayer .*' "$LOGS/tip-init.log" | sed 's/^/   /'
fi

# ---- smoke and drivers ----------------------------------------------------------------------
phase "smoke" "harness/smoke.ts, timeout ${SMOKE_TIMEOUT}s"
run_ts smoke "$SMOKE_TIMEOUT" "$E2E_DIR/harness/smoke.ts" || die "the smoke failed ($LOGS/smoke.log)"
grep -o '\[timing\] .*' "$LOGS/smoke.log" | tee -a "$RUN_DIR/timings.txt" | sed 's/^/   /'
for d in "${SCENARIOS[@]}"; do
  phase "scenario $d" "driver.ts $d, timeout ${DRIVER_TIMEOUT}s"
  run_ts "driver-$d" "$DRIVER_TIMEOUT" "$E2E_DIR/driver.ts" "$d" || die "scenario $d failed ($LOGS/driver-$d.log)"
done
# A tip run ends with the fee-payer check (harness/fee-payers.ts): every
# transaction from the fee setup on paid through wFJ, and FeeJuice was
# claimed in the funding transactions only. The record is
# <run>/fee-payers.json.
if [[ $E2E_TIP == 1 ]]; then
  phase "fee payers" "every transaction since the fee setup paid through wFJ"
  run_ts fee-payers 600 "$E2E_DIR/harness/fee-payers.ts" || die "the fee-payer check failed ($LOGS/fee-payers.log)"
  grep -o 'fee payers: PASS.*' "$LOGS/fee-payers.log" | sed 's/^/   /'
fi
if [[ $EXPECT_REAL_PROOFS == 1 ]]; then
  echo "== node verifier lines ($NETWORK_LOG)"
  grep -c "Chonk verification successful" "$NETWORK_LOG" | sed 's/^/   Chonk verification successful: /'
  grep -m1 "Starting QueuedIVCVerifier" "$NETWORK_LOG" | sed 's/^/   /'
fi
echo "== local-network e2e: PASS"
