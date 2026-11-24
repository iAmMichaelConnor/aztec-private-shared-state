#!/usr/bin/env bash
# Run Aztec contract test suites (TestEnvironment / TXE) with the pinned tools.
#
#   scripts/txe.sh [--contracts] [--only <dir>] [--shard <k>/<n>] [config]
#
# config defaults to txe.json at the repository root; any other config works
# the same, and its package paths are relative to the repository root.
# "deploys" maps a test package to the contract packages its tests deploy
# (`env.deploy("../amm_tip@amm_tip/AmmTip")`); the contracts the run builds
# are those of the packages it runs, with any "deployed_contracts" of the
# config. --only <dir> runs the part of the config under <dir> (a path from
# the repository root): the packages at or below it, the contracts they
# deploy wherever those live, and the config's own contracts and deployed
# contracts at or below it; for example
# `scripts/txe.sh --contracts --only examples/lending-tip/contract/lending_tip_test`
# runs the lending suite with lending_tip, lending_tip_oblivious,
# lending_oracle, token and pss_probe built. --shard <k>/<n> runs the k-th
# of n parts of the package's tests: the package's tests as `nargo test
# --list-tests` names them, sorted, every n-th from the k-th; the others go
# to the config's "exclude_tests". It
# takes one package (--only), and the n shards together run each of its
# tests once, each building the contracts it deploys; CI splits a long
# package this way (docs/TESTING.md). --contracts compiles the run's
# contracts and generates their verification keys with bb aztec_process,
# which reads the SRS; without it a config that deploys contracts is refused.
# The runner is scripts/txe/noir_txe.py; it copies the packages into
# .runs/txe/<id>/workspace and writes logs and report.json next to it, so
# nothing in the source tree is written. Exit status is non-zero if any step
# or test fails. Needs scripts/bootstrap.sh to have made deps/ and
# scripts/txe/node_modules to hold the locked TXE packages.
#
# txe.json is the repository's whole TestEnvironment suite, the machine's and
# the tip's in one config with one pinned TXE: the note-mode library
# (noir/pss_contract) and the machine examples' contracts, the tip's
# contract library (noir/pss_public_contract), and each tip example's
# contract: its test package under "packages" and, with the contracts its
# tests deploy, under "deploys". One
# config means one run (and one TXE start) covers everything and no suite can
# be left out by running the wrong config. A shorter loop over one example or
# package runs a part of it with --only, never a copy of its entries.
set -euo pipefail

# shellcheck source=toolchain.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/toolchain.sh"

usage() { echo "usage: scripts/txe.sh [--contracts] [--only <dir>] [--shard <k>/<n>] [config]" >&2; exit 2; }

contracts=()
config="" only="" shard=""
while (($#)); do
  case $1 in
    --contracts) contracts=(--contracts) ;;
    --only) (($# > 1)) || usage; only=${2%/}; shift ;;
    --shard) (($# > 1)) || usage; shard=$2; shift ;;
    -h|--help) usage ;;
    -*) echo "txe.sh: unknown option $1" >&2; usage ;;
    *) [[ -z $config ]] || usage; config=$1 ;;
  esac
  shift
done
config="${config:-$REPO_ROOT/txe.json}"
[[ -f $config ]] || { echo "txe.sh: no config at $config" >&2; exit 2; }
if [[ -n $shard ]]; then
  [[ $shard =~ ^([1-9][0-9]*)/([1-9][0-9]*)$ ]] && ((BASH_REMATCH[1] <= BASH_REMATCH[2])) \
    || { echo "txe.sh: --shard takes <k>/<n> with 1 <= k <= n (got: $shard)" >&2; exit 2; }
  need_nargo "$CONTRACT_NARGO_BIN" "$CONTRACT_NARGO_VERSION" || exit 1
fi

if [[ ! -d $REPO_ROOT/scripts/txe/node_modules/@aztec-labs/txe ]]; then
  echo "txe.sh: scripts/txe/node_modules is missing; run" \
    "npm ci --prefix scripts/txe --no-audit --no-fund" >&2
  exit 1
fi

# The runner and everything it starts (nargo, bb, the TXE server) run at
# nice 19, so a long suite yields the CPU to interactive work and to other
# builds; it is not a cap and the run takes the same time on
# an idle host. Set TXE_NICE=0 to run at normal priority.
nice_level="${TXE_NICE:-19}"

# Every temporary file of this script and of the processes it starts goes
# into one scratch directory under TXE_TMP_ROOT (scratch_dir,
# scripts/toolchain.sh), removed on exit. The runner and its children (nargo,
# the TXE server, world state) keep their scratch files and Unix sockets under
# TMPDIR, so the root must stay short.
scratch_dir work txe.sh --sockets
trap 'rm -rf "$work"' EXIT
export TMPDIR="$work"
# The runner's config: the packages to run (all, or those under --only),
# as "deployed_contracts" the contracts they deploy ("deploys") with the
# config's own deployed contracts (under --only, those below the directory),
# and under --shard the other shards' tests in "exclude_tests".
python3 -I - "$config" "$only" "$work/txe.json" "$shard" "$CONTRACT_NARGO_BIN" "$REPO_ROOT" <<'PY' || exit 2
import json, subprocess, sys
path, prefix, out, shard, nargo, root = sys.argv[1:7]
config = json.load(open(path))
def name(entry):
    return entry if isinstance(entry, str) else entry["path"]
def under(entry):
    return not prefix or name(entry) == prefix or name(entry).startswith(prefix + "/")
deploys = config.pop("deploys", {})
unknown = sorted(set(deploys) - {name(p) for p in config["packages"]})
if unknown:
    sys.exit(f"txe.sh: {path}: deploys names no listed package: {', '.join(unknown)}")
for key in ("packages", "contracts", "deployed_contracts", "keyless_contracts"):
    if key in config:
        config[key] = [e for e in config[key] if under(e)]
if not config["packages"]:
    sys.exit(f"txe.sh: no package of {path} is under {prefix}")
deployed = list(config.get("deployed_contracts", []))
for package in config["packages"]:
    for contract in deploys.get(name(package), []):
        if contract not in [name(e) for e in deployed]:
            deployed.append(contract)
if deployed:
    config["deployed_contracts"] = deployed
if shard:
    # "exclude_tests" names tests without their package, so a shard runs one package.
    if len(config["packages"]) != 1:
        sys.exit("txe.sh: --shard runs one package; name it with --only")
    k, n = map(int, shard.split("/"))
    package = name(config["packages"][0])
    listing = subprocess.run(
        [nargo, "test", "--list-tests", "--silence-warnings", "--program-dir", package],
        cwd=root, capture_output=True, text=True,
    )
    if listing.returncode:
        sys.exit(f"txe.sh: nargo test --list-tests failed for {package}:\n{listing.stderr}")
    tests = sorted(line.split()[1] for line in listing.stdout.splitlines() if len(line.split()) == 2)
    if not tests:
        sys.exit(f"txe.sh: nargo test --list-tests found no test in {package}")
    others = [t for i, t in enumerate(tests) if i % n != k - 1]
    print(f"txe.sh: shard {shard} of {package}: {len(tests) - len(others)} of {len(tests)} tests", flush=True)
    config["exclude_tests"] = list(config.get("exclude_tests", [])) + others
json.dump(config, open(out, "w"), indent=2)
PY
config="$work/txe.json"
out="$work/runner.out"
status=0
nice -n "$nice_level" python3 "$REPO_ROOT/scripts/txe/noir_txe.py" \
  --config "$config" "${contracts[@]}" | tee "$out" || status=$?

# The runner's last line names this run's directory; print its summary.
run="$(sed -n 's/^Run directory: //p' "$out" | tail -n 1)"
if [[ -n $run && -f $run/report.json ]]; then
  python3 - "$run/report.json" <<'PY'
import json, sys
r = json.load(open(sys.argv[1]))
mib = (r.get("peak_rss_kib") or 0) / 1024
print(
    f"{'PASS' if r['passed'] else 'FAIL'}: {r.get('tests_passed', 0)} tests passed, "
    f"{r.get('seconds', 0):.0f} s, peak RSS {mib:.0f} MiB"
)
for c in r["commands"]:
    if c.get("exit_code"):
        print(f"  failed: {' '.join(c['command'][:2])} (log {c.get('log')})")
PY
fi
exit "$status"
