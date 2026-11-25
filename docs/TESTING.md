# Testing

This page covers the gates: their commands, what each suite proves, what it costs, and
when it runs.

## Tiers

- **After every change: the fast checks.** Nothing is compiled, and all of them take about
  half a minute: `npm test` (pss-client and pss-relayer from their sources), the python
  checkers (`check-manifests.py`, `check-design-space.py`, `gen-noir-vectors.py --check`,
  every `gen-fixtures.py --check`, `check-pins.py`, `check-docs-links.py`), `cargo fmt
  --check` and `bash -n` on the scripts. The README's "Build and test" lists them as one
  block. Work with these for as long as you can.
- **When a change is one the fast checks cannot see: the cheapest slow check that covers
  it.** `cargo clippy --release -p <crate> --all-targets -- -D warnings` (and `cargo
  nextest run --release --profile quick -p <crate>`) for each crate it touches; for a Noir
  package, `scripts/check-noir.sh <example>` for circuits and `scripts/check-contracts.sh
  <dir>` for contract and test packages (with the contract compiler), then `scripts/txe.sh
  --contracts --only <package>` for a contract's behaviour; `npm run build` to type-check
  TypeScript. The proving suites (the full `cargo nextest run`, `witness-extend.sh`, the
  e2e) wait for the full gate.
- **The full gate: every command below, once.** The suites run
  in the background and side by side, and the gate is the time of the longest one: the TXE
  config (about 10 minutes), `cargo nextest run --release` (about 5 minutes with the
  build), `npm test`, every `check-noir.sh`, `witness-extend.sh` on the AMM tip and lending,
  `check-vectors.sh`, the docs and manifest checks, and the e2e gate's two runs ("End to
  end": `amm` and `monty` on the sidecar path, `amm-tip` and `lending-tip` at the tip;
  about 6 minutes for the AMM and Monty Hall, 17 for lending).

## Commands

Heavy gates run under `nice -n 19` (and `ionice -c3` for cargo) with a `timeout`.

### The machine (Rust)

```sh
cd machine
cargo fmt --all -- --check
cargo clippy --release --workspace --all-targets -- -D warnings
cargo nextest run --release              # or one crate: cargo nextest run --release -p sidecar-tip
```

`cargo nextest run` (cargo-nextest at `toolchain.json`'s `cargo_nextest`, configured in
`machine/.config/nextest.toml`) runs every test in its own process and every test binary at
once; each three-party proving test counts as eight test threads. `--profile quick` leaves
out the proving binaries and the depth-16 DORAM build over a TCP mesh. Without
cargo-nextest, `cargo test --release` runs the same tests, the binaries one after another.
Within a binary the in-process three-node networks run in parallel either way (they share
no store, key or mesh); `PSS_SERIAL_ROUNDS=1` runs them one at a time, for clean ROUND
timings. The suites run in release: a three-party round in a debug build takes many times
as long, and the workspace sets no profile of its own.

Every cargo build needs `scripts/prepare-data.sh` first: sidecar-core's build script
embeds the registration and audit circuits from the data directory and refuses one whose
bytecode differs from its line in `machine/sidecar-core/embedded.sha256`. The workspace's
default members leave out `sidecar-test-fixtures`; `--workspace` includes it.

The Postgres tests start a container through docker, or use the server named by
`SIDECAR_TEST_POSTGRES_URL`; without either they print `SKIPPED` and pass, and
`PSS_REQUIRE_POSTGRES=1` makes that a failure. The same holds for prepared data:
the tests that read the data directory `scripts/prepare-data.sh` writes, or an example's
compiled circuits, print `SKIPPED` and pass without them, and `PSS_REQUIRE_DATA=1` makes
that a failure. It covers sidecar-core's tests on compiled circuits and the CRS, and
sidecar-tip's lifecycle, receipt round and receipt resync tests. The orchestrator suites fail naming the
missing files whatever it says.

### Noir circuits, vectors and manifests

```sh
scripts/check-noir.sh examples/amm --outputs examples/amm/circuits/outputs.txt
scripts/check-noir.sh examples/monty-hall --outputs examples/monty-hall/circuits/outputs.txt
scripts/check-noir.sh examples/amm-swap-total --outputs examples/amm-swap-total/circuits/outputs.txt
scripts/check-noir.sh examples/amm-tip --outputs examples/amm-tip/circuits/outputs.txt
scripts/check-noir.sh examples/lending-tip --outputs examples/lending-tip/circuits/outputs.txt
scripts/check-noir.sh examples/credits-tip --outputs examples/credits-tip/circuits/outputs.txt
scripts/check-noir.sh examples/counter-tip --outputs examples/counter-tip/circuits/outputs.txt
scripts/check-noir.sh machine                       # the machine's test circuits
scripts/witness-extend.sh examples/amm-tip          # co-noir three-party witness extension of every fixture
scripts/witness-extend.sh examples/lending-tip
scripts/check-vectors.sh                            # every testvectors/noir program, and the Noir tests' vector values
python3 -I scripts/gen-noir-vectors.py --check      # the Noir tests' copies of the shared vectors match testvectors/ (check-vectors.sh also runs it)
python3 -I examples/lending-tip/circuits/gen-fixtures.py --check   # the committed Prover*.toml are the generator's (also credits-tip's)
python3 -I scripts/check-manifests.py               # every examples/*/manifests/*.json against the schema, and each tip round's manifests against their derivation (scripts/gen-intake.py --check) and each tree round's oblivious twin against its (scripts/gen-access.py --check)
python3 -I scripts/check-design-space.py            # docs/design-guide/design-space.json is consistent
python3 -I scripts/check-pins.py                    # every pin copied outside toolchain.json (workflows, Cargo.toml, package.json, the Postgres image) agrees with it
python3 -I scripts/check-docs-links.py              # README, AGENTS, docs/, e2e and example READMEs: relative links and repository paths resolve
```

To build against a local total-noir checkout for a while, edit the `total` line of the
packages concerned to a path dependency (`total = { path = "<checkout>/noir/total" }`) and
do not commit it; `bootstrap.sh` fails while a `Nargo.toml` names anything but the pinned tag.

Every `testvectors/noir` program's `Prover.toml` is compared with the vector files it is
written from by a test the gate runs: pss-client's `outcome.test.ts` for the two outcome
programs, pss-client's `hatch.test.ts` for `exit_tag_vectors` (it writes and reads
`testvectors/exit_tag.json`, the exit tag and the exit filler of pss_core `tip::exit`, and
writes the program's `Prover.toml` from it), and a Rust test for the others (`schnorr_vectors` and `ae_vectors` in
sidecar-core's `write_vectors`), so a vector file regenerated without its Noir inputs
fails `npm test` or `cargo nextest run`. The two
`gen-fixtures.py` generators (lending-tip, credits-tip) take `--check`, which fails on a
committed fixture that differs from their output, is missing, or is no longer generated.

`check-noir.sh` compiles every round circuit of the example, runs its library tests,
lints the total circuits with total-lint, checks every round circuit for Brillig ops
co-noir cannot run (`--brillig-ops`), executes each `Prover*.toml`, and with `--outputs`
checks each case's outputs against the file. It runs neither co-noir nor bb;
`witness-extend.sh` (any example with a `circuits/circuits.env`) is the check that a round
runs in the network's MPC solver.

### Contracts (TXE)

```sh
scripts/check-contracts.sh                                                            # compile only: every contract package with nargo 1.0.0-rc.3, every aztec-nr library type-checked
scripts/txe.sh --contracts txe.json                                                   # every suite in txe.json
scripts/txe.sh --contracts --only noir/pss_public_contract_test                       # one package: the contract library's suite
scripts/txe.sh --contracts --only examples/lending-tip/contract/lending_tip_test      # one example's suite, its deployed contracts built
scripts/txe.sh --contracts --only examples/lending-tip                                # the same: every suite under a directory
```

The TXE is Aztec's test execution environment: it runs a contract package's `nargo test`
against a simulated chain. The TXE runner's npm packages have a lockfile of their own (`npm ci --prefix scripts/txe`),
so the nightly TXE job installs them without the workspace. Its third-party transitive
versions drift from the root lockfile's, since each was resolved on its own day; its
`@aztec-labs` and `@aztec-foundation` packages must equal the root lockfile's, version and
integrity, which `check-pins.py` checks.

`txe.json` lists every suite under `packages`: `pss_contract`, `pss_public_contract` and
its TXE suite `pss_public_contract_test`, `pss_tip_test`, and each example's contract test
package. The escape hatch has a suite in each of two of them:
`noir/pss_public_contract_test/src/test_hatch.nr` (the library brick: the starving clock,
the opening, a landing's exit tags and the refusals once open, the private exit and its
refusals) and `examples/lending-tip/contract/lending_tip_test/src/test_hatch.nr` (lending's
exits as a borrower and a lender, after a liquidation, and the refusals, on the clear, the
oblivious and the non-secret-shared deployments). Under
`deploys` it maps each test package to the contract packages its tests deploy (`env.deploy`;
the lending suite deploys `lending_tip`, `lending_tip_oblivious`, `lending_oracle`,
`examples/token`'s `token` and `noir/pss_probe`), so a new suite adds one `packages` line and, when it deploys contracts,
one `deploys` entry. The run builds the contracts of the packages it runs, and no others.
`--only <dir>` runs the part of a config under one directory: its packages, wherever the
contracts they deploy live. Any other config file of the same form works too; a config may
also list `deployed_contracts` (paths, or objects with compiler flags and timeouts:
`scripts/txe/noir_txe.py`), built whenever they are under the `--only` directory.
`test_timeout_seconds` (2700) bounds one package's `nargo test`, and a timeout counts as a
failed run. A contract's compile is bounded by its entry's `timeout_seconds` (default 360;
the lending market's two contracts' entries say 1200, since each compile reaches 600 s on a loaded host). `--contracts` compiles the deployed contracts, side by side, and generates
their verification keys first. Every listed package then runs at once against the run's
one TXE server, eight tests at a time each (`test_threads`, `package_jobs`;
`TXE_TEST_THREADS=1 TXE_PACKAGE_JOBS=1` runs serially). Each test is its own TXE session:
nargo gives it a fresh session id, and the TXE runs each session on one of its worker
threads (at most 16) with its own world state, so tests never share chain state and their
order does not matter. The limit is the one TXE process per run: more threads cost memory
in that process, and CPU; a run at eight threads peaks at about 7 GB, the same as a serial
run. The runner works in `.runs/txe/<id>/` (gitignored), records each test's own seconds in
`report.json` (slowest first; a thread's first test also includes compiling the package for
that thread), and prints its summary. Runs may go in parallel: each picks a free port, and
each takes its own `TXE_TMP_ROOT` scratch directory. The TXE skips recursive
proof verification, so the suites stage a dummy vk and a zero proof; the real proof
check is the e2e with `EXPECT_REAL_PROOFS=1` (below).

### TypeScript

At the root:

```sh
BB_BIN="$PWD/.tools/bb-6.0.0/bb" npm test
npm run build
```

`BB_BIN` must be an absolute path: each workspace's tests run from that workspace's
directory, where a relative path does not resolve.

`npm test` runs pss-client's and pss-relayer's tests (`node --conditions=source --test`,
the packages' sources); one package's alone with `npm test --workspace
ts/pss-client` or `npm test --workspace ts/pss-relayer`, after
`npm ci --no-audit --no-fund`. What both share (the signed answer fixtures, the fixture
files, the mock orchestrator) is the test-only workspace `ts/test-support`. The tests that
compute a vk hash with bb need `BB_BIN` (the pinned path, the default of
`scripts/toolchain.sh`) and skip without it; one also needs `scripts/prepare-data.sh`.

`ts/test-support/fixtures/` keeps small compiled artifacts on purpose, as cross-language
pins: the ABIs of round circuits and of three contracts (`AmmTip`, `LendingTip`,
`PssPublicTest`), `pss_seed.circuit.json` and `pss_seed.vk.json`. pss-client's
`fixtures.test.ts` compares each with a fresh build and skips without one; CI's
`abi-fixtures` job runs it with `FIXTURES_REQUIRE_BUILT=1`, after `noir-circuits` has
compiled every circuit and it has built the contracts (`node --conditions=source
ts/test-support/contract-fixture.ts build`). After a circuit or contract change,
`contract-fixture.ts circuits` recompiles the fixtures' circuits and rewrites their fixtures,
and `contract-fixture.ts write` rewrites the contract fixtures from their build.
`vk.test.ts` checks the vk with bb.
`npm run build` type-checks every workspace (pss-client, pss-relayer, test-support, the
e2e harness and the counter-tip client, over one `tsconfig.base.json`) and the scripts of
sidecar-tip's live-network suite (below), and emits pss-client's and pss-relayer's `dist/`.

sidecar-tip's live-network suite runs the chain reader against a local Aztec network, by
hand: `machine/sidecar-tip/tests/chain/run.sh` starts the network, runs `tests/chain.rs`
against it and stops it; `--record` re-records `tests/fixtures/logs.json` instead. Without
the network (`PSS_TIP_NODE_URL` unset) `tests/chain.rs` prints `SKIPPED`.

### End to end

Real proofs, node-side verification; minutes per transaction, never part
of a workflow ("Continuous integration" says why); needs Foundry 1.8.5 and
docker. `e2e/run.sh` runs the scenarios named on
its command line and refuses to start with none. The full gate is these two runs; a
sidecar run and a tip run use disjoint ports, so both can run at once:

```sh
export TXE_TMP_ROOT="$PWD/.runs/tmp"; mkdir -p "$TXE_TMP_ROOT"
E2E_LOG_DIR=$(mktemp -d -p "$TXE_TMP_ROOT") EXPECT_REAL_PROOFS=1 e2e/run.sh amm monty   # the sidecar path
E2E_TIP=1 E2E_TIP_DEPLOYMENTS="amm-tip-shared amm-tip amm-tip-stale lending-tip lending-tip-plain" \
  E2E_LOG_DIR=$(mktemp -d -p "$TXE_TMP_ROOT") e2e/run.sh amm-tip lending-tip            # the tip services
```

The eleven on-demand scenarios run when a change touches what they cover, each with
the command below (`E2E_TIP=1 E2E_TIP_DEPLOYMENTS="<deployments>" e2e/run.sh <scenario>`
for a tip scenario). A tip deployment serves one scenario per run: its first step
requires the init round's empty queue, `lending-tip` leaves its hatch open (it also runs
the landing atomicity tests: a landing whose public part reverts leaves none of its exit
tags, note hashes or state changes behind), and
`amm-tip-replace-node` rewrites the orchestrator's configuration, so it runs alone.

| Scenario | Gate | Run with |
|---|---|---|
| `amm` | full gate | `e2e/run.sh amm monty` |
| `monty` | full gate | `e2e/run.sh amm monty` |
| `amm-tip` | full gate | deployments `amm-tip-shared amm-tip amm-tip-stale` |
| `lending-tip` | full gate | deployments `lending-tip lending-tip-plain` |
| `monty-two-wallets` | on demand | `e2e/run.sh monty-two-wallets monty-registered-sender monty-late-sender` |
| `monty-registered-sender` | on demand | the same run (fresh accounts: order does not matter) |
| `monty-late-sender` | on demand | the same run (fresh accounts) |
| `amm-tip-shared-onchain` | on demand | deployment `amm-tip-shared-onchain` |
| `amm-tip-upgrade-circuits` | on demand | deployment `amm-tip-upgrade` |
| `amm-tip-upgrade-contract` | on demand | deployment `amm-tip-class` |
| `amm-tip-replace-node` | on demand | deployment `amm-tip`, alone |
| `credits-tip` | on demand | deployment `credits-tip` |
| `counter-tip` | on demand | deployment `counter-tip` |
| `lending-tip-oblivious` | on demand | deployment `lending-tip-oblivious` |
| `lending-tip-shared-onchain` | on demand | deployment `lending-tip-shared-onchain` |
| `reorg-result-again` | on request, by hand | the reorg network, deployment `counter-tip`, alone |
| `reorg-request-removed` | on request, by hand | the reorg network, deployment `counter-tip`, alone |
| `reorg-reorder` | on request, by hand | the reorg network, deployment `counter-tip`, alone |
| `reorg-epoch-prune` | on request, by hand | the reorg network, deployment `counter-tip`, alone |
| `reorg-below-settled` | on request, by hand | the reorg network, deployment `counter-tip`, alone |
| `reorg-init` | on request, by hand | the reorg network, deployment `counter-tip`, alone |

The six reorg scenarios revert the chain under the machine. They run only on the reorg
network (`E2E_REORG=1`: the local network with test calls to pause the sequencer, revert to a
checkpoint and stop proving), which `run.sh` requires for every `reorg-*` scenario, each alone
on its own deployment, and never in the full gate:

```sh
E2E_REORG=1 E2E_TIP=1 E2E_TIP_DEPLOYMENTS="counter-tip" EXPECT_REAL_PROOFS=0 \
  E2E_LOG_DIR=$(mktemp -d -p "$TXE_TMP_ROOT") e2e/run.sh reorg-result-again
```

[e2e/README.md](../e2e/README.md) has the harness and its environment;
[e2e/scenarios/README.md](../e2e/scenarios/README.md) says what each scenario checks.

## Continuous integration

`.github/workflows/ci.yml` runs on every push to main and every pull request;
`.github/workflows/nightly.yml` runs the heavy suites once a night and on demand. Both run
on GitHub-hosted ubuntu-24.04 runners (4 cores, 16 GB).

**The budget: every job finishes within 30 minutes**, and no job's `timeout-minutes` is
above 30. Work that does not fit one job is split into matrix shards; a suite that cannot
be made to fit does not run on hosted runners. The minutes below were measured on 4 cores
of a many-core host (`taskset -c` to four cores, `-j4`, four test threads), from a cold
cargo target and nargo build, and are the work of the job's main step; checkout, cache
restore and the toolchain's setup add a minute or two.

| Workflow | Job | Shards | Minutes (4 cores) | Cap |
|---|---|---|---|---|
| ci | `checks`: rustfmt, `check-manifests.py`, `check-design-space.py`, `check-docs-links.py`, `gen-noir-vectors.py --check`, `check-pins.py`, every `gen-fixtures.py --check`, `bash -n` and shellcheck's errors, no machine-specific paths | 1 | about 1 (estimated) | 15 |
| ci | `toolchain`: `scripts/install-toolchain.sh`, cached per `toolchain.json` | 1 | total-lint's build 0.7, plus downloads; nothing on a cache hit | 20 |
| ci | `shards`: the matrices of the next jobs, read from the repository | 1 | seconds | 5 |
| ci | `noir-circuits`: `scripts/check-noir.sh <dir> --outputs <dir>/circuits/outputs.txt` | one per directory with `circuits/circuits.env` | under 1 each; lending-tip 6.5 | 20 |
| ci | `abi-fixtures`: the tracked ABI fixtures against the circuits `noir-circuits` compiled and three contracts built here (`FIXTURES_REQUIRE_BUILT=1`) | 1 | lending_tip's build 4.5, the others under 1 | 25 |
| ci | `noir-vectors`: `scripts/check-vectors.sh` | 1 | 0.9 | 15 |
| ci | `contracts`: `scripts/check-contracts.sh <group>` | one per example with a contract package, plus `noir` and `machine` | lending-tip's the longest: `lending_tip`'s compile 4.5 and `lending_tip_oblivious`'s beside it, about as long (estimated: on the reference host it takes 0.8 of `lending_tip`'s); all of lending-tip in one job about 6 (estimated) | 20 |
| ci | `rust-clippy`: `prepare-data.sh machine`, `cargo clippy --release --workspace --all-targets -D warnings` | 1 | clippy 2.3 | 20 |
| ci | `rust-test`: `prepare-data.sh`, `gen-dev-certs.sh`, `cargo nextest run --release --profile quick` with Postgres | two package groups: `sidecar-orchestrator`, the rest | build 14.6 and 12.5, prepare-data 2.3, the tests under 1 | 30 |
| ci | `typescript`: `npm run build`, `npm test` | 1 | a few (estimated) | 15 |
| nightly | `toolchain` and `shards` | 1 each | as in ci | 20, 5 |
| nightly | `txe`: `scripts/txe.sh --contracts --only <package> [--shard k/n]`, four test threads | one per test package of `txe.json`; `lending_tip_test` two | 0.3-4.4 per package; `lending_tip_test` whole about 19 (its two contracts side by side, about 4.5 each, estimated from `lending_tip`'s; its tests 14.2), so about 12 per shard | 25 |
| nightly | `witness-extend`: `scripts/witness-extend.sh --shard k/n <example>` | amm-tip 1, lending-tip 2 | the checker's build 3.5, then about 8 s per fixture: amm-tip 17 fixtures, lending-tip 127 (17 whole, about 8.5 per shard) | 25 |
| nightly | `nextest-build`: `prepare-data.sh`, `cargo nextest archive --release` | the two `rust-test` groups | 14.6 and 12.5 | 30 |
| nightly | `nextest-full`: `cargo nextest run --archive-file … --partition …` with Postgres, every test | orchestrator in two partitions, the rest in one | every test 16.6 in one run (orchestrator 11.7 of test time, the rest 6.2) | 20 |

How the shards are made:

- `noir-circuits` uploads each directory's compiled circuits; `abi-fixtures` unpacks them
  all (with the time of unpacking, so they are newer than its checkout) before
  `fixtures.test.ts`.
- `scripts/check-contracts.sh --list` prints its jobs; `shards` groups them by
  `examples/<name>` or by top directory. A group without `noir/pss_public_contract` or
  `noir/pss_contract` warms nargo's dependency cache with its first job.
- The release build of the machine's test binaries is the long pole: 20 minutes cold for
  the whole workspace (77 minutes of CPU), so CI builds it in two groups, each in its own
  job with its own `Swatinem/rust-cache` key: `-p sidecar-orchestrator` (its 15 test
  binaries) and `--workspace --exclude sidecar-orchestrator`. The quick profile's tests
  take 25 s, so `rust-test` builds and runs each group in one job. Nightly, each group's
  binaries go to its `nextest-full` shards as a `cargo nextest archive` with the prepared
  data beside it.
- Release only: a debug target (22 GB) is larger than a hosted runner's free disk (about
  14 GB), and the quick profile's tests take 16 minutes in it instead of 25 s.
- `scripts/txe.sh --shard k/n` lists one package's tests (`nargo test --list-tests`),
  sorts them and runs every n-th from the k-th; each shard builds the contracts the package
  deploys. `nightly.yml`'s `TXE_SPLIT` names the packages that run as more than one shard.
- `scripts/witness-extend.sh --shard k/n` runs every n-th fixture of the example from the
  k-th.

Other notes:

- Two composite actions hold the setup: the `toolchain` job runs
  `.github/actions/install-toolchain` (`scripts/install-toolchain.sh` into `.tools`, cached
  per `toolchain.json`), and every job that builds with the pinned tools runs
  `.github/actions/pinned-setup` after its checkout (`.tools` from that cache, Rust, the
  job's Rust cache, the nargo and CRS caches, Node 24, `scripts/bootstrap.sh`).
- The `toolchain` job also installs total-lint (`cargo install --git` at total-noir's
  pinned commit) into the cached `.tools`; nargo fetches total-noir's `total` library as a
  git dependency, kept between runs in the `~/nargo` cache.
- **Not on hosted runners: the e2e gate** ("End to end"). It runs by hand or on a
  self-hosted runner with docker and Foundry. On a large many-core machine the AMM and
  Monty Hall run takes about 6 minutes and lending about 17; on 4 cores client-side proving
  takes it from minutes to hours, and a tip run's deployments alone are budgeted at up to an
  hour there.
- Repository caches are limited to 10 GB in all: the toolchain, nargo's dependencies, the
  CRS and four Rust caches (`machine-clippy`, `machine-orchestrator`, `machine-rest`,
  `machine-witness-extend`). A Rust cache that is evicted makes its next job cold, which the
  minutes above already are.
- **Node.** Node 24 is pinned everywhere: `toolchain.json` (`node_major`), every package's
  `engines` (`>=24`), `scripts/bootstrap.sh` and every CI job.

## Costs

Measured on one host; `report.json` of a TXE run and nextest's summary give the current
figures and the test counts.

### TXE packages

| Package | Time at eight threads |
|---|---|
| lending_tip_test | about 250 s |
| pss_public_contract_test | about 90 s |
| amm_tip_test | about 280 s |
| amm_test | 49 s |
| montyhall_test | 31 s |
| counter_tip_test | about 50 s, one thread |
| pss_public_contract (no deployment) | 19 s |
| pss_contract | 12 s |
| pss_tip_test (no deployment: the requester audit's address scan) | seconds |
| Deployed contract builds | about 120 s side by side (the longest build) |
| **Whole config** | **about 6-10 min** |

The cost of a TXE test is its setup. A lending test deploys the oracle, two tokens and the
market, mints four private balances and configures the market (about 15 s). A library test
deploys and configures the test contract (about 3 s). A test therefore covers one setup's
worth of assertions, and hash and layout checks that need no contract are plain tests of
`pss_public_contract`. The slowest single tests are Monty Hall's four
`finish_game_rejects_*` refusals and `choose_door_rejects_second_call`, about 11 s each.

### Rust test binaries

| Binary | Time |
|---|---|
| sidecar-core lifecycle | 31 s |
| sidecar-core recovery | 37 s |
| sidecar-oblivious three_party (the depth-16 build over a TCP mesh most of it; not under `--profile quick`) | 16 s |
| sidecar-oblivious recovery | 15 s |
| sidecar-core registry_resync | 4 s |
| sidecar-tip lifecycle | 5 s |
| sidecar-tip receipt_resync | 11 s |
| sidecar-node three_party | 17 s |
| orchestrator lending_tip_shared | about 148 s |
| orchestrator lending_keeper_shared | about 69 s |
| orchestrator amm_tip_shared | about 53 s |
| orchestrator tree_keys, end_to_end, lending_epoch | 33-39 s each |
| **every binary under nextest** | **about 150 s** (the longest test), plus the build |

Every orchestrator suite runs a three-node network that proves its rounds: these are the
machine's end-to-end coverage, and none is ignored. Reading a binary's fixture (the CRS and
the verifiers) takes at most 1.2 s, so nextest reading it once per test costs little.

### Other suites

- **pss-client** (`npm test`): about 4 s.
- **e2e lending** (the tip run of "End to end"): about 17 min, of which about 170 s builds
  each contract package once, side by side.
- **e2e AMM and Monty Hall**: about 6 min.
