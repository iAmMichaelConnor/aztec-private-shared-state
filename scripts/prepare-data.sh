#!/usr/bin/env bash
# Prepare the generated inputs the machine's tests and nodes read from a data
# directory (default machine/data). Nothing it writes is committed (see
# .gitignore: machine/data/, *.dat):
#
#   $DATA_DIR/circuits/<name>.json  every round circuit of the example, compiled with
#                                   the pinned Noir 1.0.0 (NARGO_BIN), and the
#                                   machine's registration and audit circuits,
#                                   which sidecar-core embeds at build time
#   $DATA_DIR/bn254_g1.dat          the first crs.g1_points (toolchain.json) points of the BN254 G1 CRS
#   $DATA_DIR/bn254_g2.dat          the BN254 G2 point (128 bytes)
#
# Dev TLS material is made by scripts/gen-dev-certs.sh, not here.
# Idempotent: existing outputs are kept unless FORCE=1.
#
# Usage: scripts/prepare-data.sh [example dir ...]
#        default: examples/amm examples/monty-hall examples/amm-tip examples/lending-tip
#                 examples/credits-tip machine
#        (machine: the machine's own test circuits, machine/circuits/circuits.env;
#        examples/amm-tip: the tip rounds the orchestrator's node-held state test runs;
#        examples/lending-tip: the tree rounds its epoch-read test runs;
#        examples/credits-tip: the keyed map rounds its credits_map test runs)
#
# Each example names its round circuits in <example>/circuits/circuits.env
# (CIRCUITS="pss_seed amm_init amm_swap"), as scripts/check-noir.sh reads it;
# machine/circuits/circuits.env also names EMBEDDED circuits, compiled here the
# same way. sidecar-core's build script reads sidecar_register.json and
# sidecar_audit.json from $DATA_DIR/circuits, so `cargo build` of the machine
# needs this script to have run (at least `scripts/prepare-data.sh machine`);
# both must compile to the bytecode machine/sidecar-core/embedded.sha256 pins.
# Two examples may both have a circuit of the same name only if both compile
# to the same ABI and bytecode (the generic pss_seed, which examples/monty-hall
# links from examples/amm); the first example's artifact is kept. Any other
# clash is refused.
#
# Environment (all optional): DATA_DIR, NARGO_BIN, NARGO_VERSION, BB_CRS_PATH,
# FORCE.
set -euo pipefail

SCRIPTS="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=toolchain.sh
source "$SCRIPTS/toolchain.sh"
DATA="${DATA_DIR:-$REPO_ROOT/machine/data}"
FORCE="${FORCE:-0}"

need_nargo "$NARGO_BIN" "$NARGO_VERSION" || exit 1
# The compiler commit, as nargo writes it into every artifact's noir_version.
NARGO_COMMIT="$("$NARGO_BIN" --version | sed -n 's/^noirc version = .*+\([0-9a-f]*\).*/\1/p' | head -1)"

mkdir -p "$DATA/circuits"

# The embedded circuits' bytecode against machine/sidecar-core/embedded.sha256,
# the pin sidecar-core's build script checks too: a circuit it names must
# compile to the pinned bytecode.
PINS="$REPO_ROOT/machine/sidecar-core/embedded.sha256"
check_pin() {                                  # check_pin <circuit>
  local c=$1 pinned got
  pinned="$(awk -v c="$c" '$1 == c { print $2 }' "$PINS")"
  [[ -n $pinned ]] || return 0
  got="$(jq -j .bytecode "$DATA/circuits/$c.json" | sha256sum | cut -d' ' -f1)"
  if [[ $got != "$pinned" ]]; then
    echo "$c: the compiled bytecode hashes to $got; ${PINS#"$REPO_ROOT"/} pins $pinned." >&2
    echo "   If machine/circuits/$c changed on purpose, put $got on its line there and commit it" >&2
    echo "   (every node embeds this circuit and must embed the same one); otherwise the" >&2
    echo "   compiler or deps/ is not at its pin (scripts/bootstrap.sh)." >&2
    exit 1
  fi
}

(($#)) || set -- "$REPO_ROOT/examples/amm" "$REPO_ROOT/examples/monty-hall" \
  "$REPO_ROOT/examples/amm-tip" "$REPO_ROOT/examples/lending-tip" \
  "$REPO_ROOT/examples/credits-tip" "$REPO_ROOT/machine"
declare -A FROM
for example in "$@"; do
  EXAMPLE="$(cd "$example" && pwd)"
  load_circuits_env "$EXAMPLE"
  circuits+=("${embedded[@]}")
  echo "== circuits of ${EXAMPLE#"$REPO_ROOT"/} ($NARGO_VERSION)"
  for c in "${circuits[@]}"; do
    if [[ -n ${FROM[$c]:-} ]]; then
      # A circuit name shared by two examples is accepted only when both
      # copies compile to the same ABI and bytecode, compared on the nargo
      # artifacts; the data directory then holds the first example's
      # artifact and each example registers it under its own manifest. Two
      # different circuits of one name would make the data directory
      # ambiguous, so they are refused and need different DATA_DIRs.
      (cd "$EXAMPLE/circuits/$c" && nice -n 19 "$NARGO_BIN" compile --silence-warnings)
      other="$EXAMPLE/circuits/$c/target/$c.json"
      if ! python3 -I -c 'import json, sys; a, b = (json.load(open(p)) for p in sys.argv[1:]); sys.exit((a["abi"], a["bytecode"]) != (b["abi"], b["bytecode"]))' \
             "$other" "$DATA/circuits/$c.json"; then
        echo "circuit $c is in both ${FROM[$c]} and $EXAMPLE and they differ; prepare them into different DATA_DIRs" >&2
        exit 1
      fi
      echo "   $c.json is the same circuit as ${FROM[$c]#"$REPO_ROOT"/}'s; kept"
      continue
    fi
    FROM[$c]=$EXAMPLE
    out="$DATA/circuits/$c.json"
    # Reuse an artifact only if this compiler wrote it (its noir_version field)
    # and no circuit or profile source is newer, so any change recompiles.
    # The search covers every example, not only this one: a round may be a
    # link to another example's package (examples/amm's amm_swap_total) or
    # depend on another example's library (amm_total), and find does not
    # follow the link.
    if [[ $FORCE != 1 && -f $out && -n $NARGO_COMMIT \
          && "$(head -c 200 "$out")" == *"\"noir_version\":\"$NARGO_VERSION+$NARGO_COMMIT\""* \
          && -z "$(find "$REPO_ROOT/examples" "$REPO_ROOT/noir" "$REPO_ROOT/machine/circuits" \
                     \( -name target -o -name node_modules \) -prune -o \
                     \( -name '*.nr' -o -name Nargo.toml -o -name Nargo.lock \) -newer "$out" -print -quit)" ]]; then
      echo "   $c.json up to date"
      check_pin "$c"
      continue
    fi
    (cd "$EXAMPLE/circuits/$c" && nice -n 19 "$NARGO_BIN" compile --silence-warnings)
    cp "$EXAMPLE/circuits/$c/target/$c.json" "$out"
    echo "   $c.json written"
    check_pin "$c"
  done
done

echo "== CRS"
# The CRS is the public Aztec BN254 ceremony output, read from BB_CRS_PATH
# (default ~/.bb-crs, where bb keeps its copy) and only fetched from the Aztec
# CRS hosts when that copy is missing or too short; that range request is the
# only network access this script makes besides nargo resolving git
# dependencies. The G1 file holds exactly toolchain.json's crs.g1_points
# points (32768, 2 MiB), which must cover the largest registered circuit: the
# node sizes its prover CRS from the circuits and refuses to start if the file
# is shorter. A different CRS is a different trusted setup, and proofs made
# with it do not verify against verification keys bb computes, so both files
# are checked whole against the sha256 values in toolchain.json; a mismatch
# fails. A larger circuit needs crs.g1_points and crs.g1_sha256 moved together
# in toolchain.json.
CRS_DIR="${BB_CRS_PATH:-$HOME/.bb-crs}"
G1_POINTS="$(pin crs.g1_points)"
[[ $G1_POINTS =~ ^[1-9][0-9]*$ ]] || { echo "toolchain.json crs.g1_points is not a number: $G1_POINTS" >&2; exit 1; }
G1_BYTES=$((G1_POINTS * 64))
HOSTS=(https://crs.aztec-cdn.foundation https://crs.aztec-labs.com)
fetch() {                                      # fetch <remote file> <dest> [range]
  local f=$1 out=$2 range=${3:-} h
  for h in "${HOSTS[@]}"; do
    if curl -sf ${range:+-r "$range"} -o "$out.part" "$h/$f"; then mv "$out.part" "$out"; return 0; fi
  done
  rm -f "$out.part"; echo "could not download $f" >&2; return 1
}
if [[ $FORCE == 1 || ! -f $DATA/bn254_g1.dat || $(stat -c%s "$DATA/bn254_g1.dat") -ne $G1_BYTES ]]; then
  if [[ -f $CRS_DIR/bn254_g1.dat && $(stat -c%s "$CRS_DIR/bn254_g1.dat") -ge $G1_BYTES ]]; then
    head -c "$G1_BYTES" "$CRS_DIR/bn254_g1.dat" > "$DATA/bn254_g1.dat"
  else
    fetch g1.dat "$DATA/bn254_g1.dat" "0-$((G1_BYTES - 1))"
  fi
  echo "   bn254_g1.dat written ($G1_BYTES bytes)"
else
  echo "   bn254_g1.dat up to date"
fi
if [[ $FORCE == 1 || ! -f $DATA/bn254_g2.dat ]]; then
  if [[ -f $CRS_DIR/bn254_g2.dat ]]; then cp "$CRS_DIR/bn254_g2.dat" "$DATA/bn254_g2.dat"
  else fetch g2.dat "$DATA/bn254_g2.dat"; fi
  echo "   bn254_g2.dat written"
else
  echo "   bn254_g2.dat up to date"
fi
# check_sha <file> <toolchain.json key>: the whole file's sha256.
check_sha() {
  local got want
  want="$(pin "$2")"
  got="$(sha256sum <"$1")"
  got="${got%% *}"
  [[ -n $want && $got == "$want" ]] \
    || { echo "$1 has sha256 $got, not the pinned ${want:-(none)} ($2 in toolchain.json); remove it and rerun" >&2; exit 1; }
}
check_sha "$DATA/bn254_g1.dat" crs.g1_sha256
check_sha "$DATA/bn254_g2.dat" crs.g2_sha256
echo "   sha256 of both match toolchain.json"
echo "ok: $DATA"
