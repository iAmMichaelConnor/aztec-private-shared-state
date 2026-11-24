#!/usr/bin/env bash
# Starts a local Aztec 6.0.0 network the way e2e/run.sh's "network start"
# phase does, runs the chain reader's integration test (tests/chain.rs)
# against it, and stops every process of the network on exit. With
# --record it instead records tests/fixtures/logs.json on the fresh network
# (record-logs.ts; the file is rewritten only when the recording differs in
# more than each log's blockHash, blockTimestamp and txHash) and runs the
# unit test that replays it.
#
#   machine/sidecar-tip/tests/chain/run.sh [--record]
#
# Environment (all optional): AZTEC_PORT, AZTEC_ADMIN_PORT, ANVIL_PORT,
# ANVIL_BIN/FORGE_BIN/CAST_BIN (Foundry 1.8.5), TXE_TMP_ROOT (the scratch
# root, default .runs/tmp in the repository), CARGO_TARGET_DIR, START_TIMEOUT (s).
set -euo pipefail
case "${1:-}" in
  "") MODE=test ;;
  --record) MODE=record ;;
  *) echo "usage: $0 [--record]" >&2; exit 2 ;;
esac
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../../../.." && pwd)"
source "$REPO_ROOT/scripts/toolchain.sh"

# The ports: Aztec node 10280, admin 11081, anvil 10745 (e2e/run.sh's 8280,
# 9080 and 8745 plus 2000; admin 11081, because Node's fetch refuses 11080 as
# a bad port), so this test and the e2e harness can run side by side. Move
# them with the variables; the script refuses to start when one is taken.
export AZTEC_PORT=${AZTEC_PORT:-10280}
export AZTEC_ADMIN_PORT=${AZTEC_ADMIN_PORT:-11081}
export ANVIL_PORT=${ANVIL_PORT:-10745}
START_TIMEOUT=${START_TIMEOUT:-300}
NODE_URL="http://127.0.0.1:$AZTEC_PORT"

for port in "$AZTEC_PORT" "$AZTEC_ADMIN_PORT" "$ANVIL_PORT"; do
  if ss -ltn | awk '{print $4}' | grep -qE "[:.]$port\$"; then
    echo "port $port is taken" >&2
    exit 1
  fi
done
# Foundry: the first candidate with the pinned version (find_foundry), as e2e/run.sh picks it.
for tool in anvil forge cast; do
  var="$(tr '[:lower:]' '[:upper:]' <<<"$tool")_BIN"
  printf -v "$var" '%s' "$(find_foundry "$tool" || true)"
  [[ -n ${!var} ]] || { echo "$tool $FOUNDRY_VERSION not found; run scripts/install-toolchain.sh --with-foundry or set $var" >&2; exit 1; }
  export "${var?}"
done

scratch_dir NETWORK_TMP c --sockets
export TMPDIR="$NETWORK_TMP"
NETWORK_LOG="$NETWORK_TMP/network.log"
NETWORK_PID=""
cleanup() {
  local status=$?
  if [[ -n $NETWORK_PID ]]; then
    # the CLI, anvil and the world-state processes share the group setsid made
    kill -- -"$NETWORK_PID" 2>/dev/null || true
    for _ in $(seq 1 40); do
      pgrep -g "$NETWORK_PID" >/dev/null || break
      sleep 0.5
    done
    kill -9 -- -"$NETWORK_PID" 2>/dev/null || true
    if pgrep -g "$NETWORK_PID" >/dev/null; then
      echo "!! network processes left: $(pgrep -g "$NETWORK_PID" | tr '\n' ' ')" >&2
      status=1
    fi
  fi
  ((status == 0)) || { echo "== network log tail ($NETWORK_LOG)"; tail -20 "$NETWORK_LOG" 2>/dev/null || true; }
  rm -rf "$NETWORK_TMP"
  exit "$status"
}
trap cleanup EXIT

echo "== network start: node $AZTEC_PORT, admin $AZTEC_ADMIN_PORT, anvil $ANVIL_PORT"
setsid "$REPO_ROOT/node_modules/.bin/aztec" start --local-network >"$NETWORK_LOG" 2>&1 &
NETWORK_PID=$!
for ((i = 0; ; i++)); do
  if curl -fsS -X POST -H 'content-type: application/json' \
    -d '{"jsonrpc":"2.0","method":"node_getNodeInfo","id":1}' "$NODE_URL" >/dev/null 2>&1; then
    break
  fi
  kill -0 "$NETWORK_PID" 2>/dev/null || { echo "the network exited" >&2; exit 1; }
  ((i < START_TIMEOUT)) || { echo "the network did not answer within ${START_TIMEOUT}s" >&2; exit 1; }
  sleep 1
done
echo "== network up at $NODE_URL"
if [[ $MODE == record ]]; then
  # the recording needs the network's first blocks after its own setup, so
  # it runs before anything else touches the network
  (cd "$REPO_ROOT" && AZTEC_NODE_URL="$NODE_URL" node --import ./ts/hooks/register.mjs machine/sidecar-tip/tests/chain/record-logs.ts)
  cd "$REPO_ROOT/machine"
  cargo test --release -p sidecar-tip --lib the_recorded_logs -- --nocapture
else
  cd "$REPO_ROOT/machine"
  PSS_TIP_NODE_URL="$NODE_URL" cargo test --release -p sidecar-tip --test chain -- --nocapture
fi
