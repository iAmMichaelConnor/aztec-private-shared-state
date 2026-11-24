#!/usr/bin/env bash
# Write the development TLS material into a keys directory (default
# machine/data/keys, gitignored; key material is never committed). The
# certificates come from `sidecar-node gen-certs` (rcgen).
#
#   mesh (node <-> node, DER)     mesh-key{0,1,2}.der, mesh-cert{0,1,2}.der
#                                 the party configs in machine/sidecar-node/data/configs pin all three
#   HTTPS (orchestrator -> node, PEM, mutual TLS under one dev CA)
#                                 https-ca.pem, https-ca-key.pem,
#                                 https-node{0,1,2}.pem, https-node{0,1,2}-key.pem,
#                                 https-orchestrator.pem, https-orchestrator-key.pem
#   provenance.txt                what wrote the set, when, from which commit
#
# Development material only, never deployment credentials (see the DEV
# DECISION in machine/sidecar-node/src/certs.rs). Idempotent: a complete
# plane is kept; a plane with a missing file is regenerated as a whole;
# FORCE=1 regenerates both.
#
# Usage: scripts/gen-dev-certs.sh [keys dir]
# Environment (all optional): KEYS_DIR, FORCE, CARGO.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MACHINE="$REPO_ROOT/machine"
OUT="${1:-${KEYS_DIR:-$MACHINE/data/keys}}"
FORCE="${FORCE:-0}"
CARGO="${CARGO:-cargo}"

# Builds into cargo's target directory (CARGO_TARGET_DIR, else the
# workspace's own); a no-op when it is fresh.
echo "== building sidecar-node"
(cd "$MACHINE" && nice -n 19 "$CARGO" build --release --locked -q -p sidecar-node)
BIN="${CARGO_TARGET_DIR:-$MACHINE/target}/release/sidecar-node"

args=(gen-certs --out "$OUT")
[[ $FORCE == 1 ]] && args+=(--force)
echo "== dev TLS material into $OUT"
log="$("$BIN" "${args[@]}")"
printf '%s\n' "$log"

if grep -q '^wrote ' <<<"$log" || [[ ! -f $OUT/provenance.txt ]]; then
  rev="$(git -C "$REPO_ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)"
  {
    echo "Development TLS material; never deployment credentials."
    echo "written by scripts/gen-dev-certs.sh (sidecar-node gen-certs, rcgen)"
    echo "at $(date -u +%Y-%m-%dT%H:%M:%SZ) from commit $rev"
    grep '^wrote ' <<<"$log" | sed "s|$OUT/||" || true
  } >"$OUT/provenance.txt"
fi
echo "gen-dev-certs: done ($OUT)"
