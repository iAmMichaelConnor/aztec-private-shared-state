#!/usr/bin/env bash
# The relayer's local-network check (test/local-network.ts): starts a local
# Aztec 6.0.0 network (`aztec start --local-network`, simulated proofs) on its
# own ports, compiles pss_public_contract_test with `aztec compile` when its
# artifact is missing, runs the check, and stops the network on exit, also on
# failure. Nothing goes to /tmp: the network's scratch directory is under
# TXE_TMP_ROOT and removed on exit.
#
#   ts/pss-relayer/test/local-network.sh
#
# The check's ports, AZTEC_PORT 11280, AZTEC_ADMIN_PORT 12080
# and ANVIL_PORT 11745: the e2e harness's defaults (8280, 9080, 8745) plus
# 3000, so the check runs beside a harness run. Each is overridable; the
# script refuses to start when one is taken. Timeouts: NETWORK_TIMEOUT 360 s
# for the network to answer, CHECK_TIMEOUT 900 s for the check.
set -uo pipefail
# No -e: the polls and the teardown expect commands to fail (curl, kill, ss);
# every real failure exits through die, and the script exits with the check's.
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../../.." && pwd)"
# shellcheck source=../../../scripts/toolchain.sh
source "$REPO/scripts/toolchain.sh"

if [[ -z ${PSS_RELAYER_NICED:-} ]]; then
  export PSS_RELAYER_NICED=1
  exec nice -n 19 ionice -c 3 "$0" "$@"
fi

export AZTEC_PORT=${AZTEC_PORT:-11280}
export AZTEC_ADMIN_PORT=${AZTEC_ADMIN_PORT:-12080}
export ANVIL_PORT=${ANVIL_PORT:-11745}
NETWORK_TIMEOUT=${NETWORK_TIMEOUT:-360}
CHECK_TIMEOUT=${CHECK_TIMEOUT:-900}
AZTEC_CLI="$REPO/node_modules/.bin/aztec"
ARTIFACT="$REPO/noir/pss_public_contract_test/target/pss_public_contract_test-PssPublicTest.json"
scratch_dir SCRATCH r --sockets || exit 1
export TMPDIR="$SCRATCH"
LOG="$SCRATCH/network.log"
NETWORK_PID=""

die() { echo "!! $*" >&2; exit 1; }
teardown() {
  if [[ -n $NETWORK_PID ]]; then
    kill -TERM -- "-$NETWORK_PID" 2>/dev/null
    for _ in $(seq 1 40); do kill -0 "$NETWORK_PID" 2>/dev/null || break; sleep 0.5; done
    kill -KILL -- "-$NETWORK_PID" 2>/dev/null
  fi
  rm -rf "$SCRATCH"
}
trap teardown EXIT

# Foundry: ANVIL_BIN/FORGE_BIN/CAST_BIN, or the first candidate with the
# pinned version, as e2e/run.sh finds them (the CLI deploys the L1 contracts
# with forge flags older releases reject).
for tool in anvil forge cast; do
  var="$(tr '[:lower:]' '[:upper:]' <<<"$tool")_BIN"
  printf -v "$var" '%s' "$(find_foundry "$tool" || true)"
  [[ -n ${!var} ]] || die "$tool $FOUNDRY_VERSION not found; run scripts/install-toolchain.sh --with-foundry or set $var"
  export "${var?}"
done

for p in "$AZTEC_PORT" "$AZTEC_ADMIN_PORT" "$ANVIL_PORT"; do
  ss -ltnH "sport = :$p" | grep -q LISTEN && die "port $p is taken"
done

if [[ ! -f $ARTIFACT ]]; then
  echo "== aztec compile pss_public_contract_test"
  (cd "$REPO/noir/pss_public_contract_test" && NARGO="$CONTRACT_NARGO_BIN" BB="$BB_BIN" timeout 1800 "$AZTEC_CLI" compile) \
    || die "aztec compile failed"
fi

echo "== aztec start --local-network (node $AZTEC_PORT, admin $AZTEC_ADMIN_PORT, anvil $ANVIL_PORT)"
setsid "$AZTEC_CLI" start --local-network >"$LOG" 2>&1 &
NETWORK_PID=$!
start=$SECONDS
until curl -fsS -X POST -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","method":"node_getNodeInfo","id":1}' "http://127.0.0.1:$AZTEC_PORT" 2>/dev/null | grep -q '"result"'; do
  kill -0 "$NETWORK_PID" 2>/dev/null || { tail -n 30 "$LOG" >&2; die "the network exited"; }
  ((SECONDS - start < NETWORK_TIMEOUT)) || { tail -n 30 "$LOG" >&2; die "the network did not answer within ${NETWORK_TIMEOUT}s"; }
  sleep 1
done
echo "== network up after $((SECONDS - start)) s"

cd "$HERE/.." || exit 1
AZTEC_NODE_URL="http://127.0.0.1:$AZTEC_PORT" ARTIFACT="$ARTIFACT" timeout "$CHECK_TIMEOUT" \
  node --conditions=source --import "$REPO/ts/hooks/register.mjs" test/local-network.ts
