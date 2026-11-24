# End-to-end harness

Paths are relative to the repository root. This page covers the harness and its
environment. [docs/TESTING.md](../docs/TESTING.md), "End to end", has the commands, which
deployments each scenario takes and which runs make up the gate;
[scenarios/README.md](scenarios/README.md) says what each scenario checks.

`e2e/run.sh scenario [scenario ...]` runs the whole machine on one host and refuses to
start with no scenario. It checks the pinned tools, builds the sidecar binaries and
pss-client, compiles the examples' circuits and writes the dev TLS planes into a fresh run
directory, runs `sidecar-node setup` for the three nodes over the mesh (`E2E_SETUP=dealer`
for the development shortcut), starts three Postgres containers, the three nodes, the
orchestrator and a local Aztec 6.0.0 network, checks `GET /v1/nodes` against the keys setup
printed, and then runs `e2e/harness/smoke.ts` (a first REGISTER of a contract manifest and
one transaction) and the driver on each named scenario (`e2e/scenarios/<name>.ts`). Every
service and container is stopped on exit, also on failure.

Everything a run writes is in `E2E_LOG_DIR` (default a new directory under
`TXE_TMP_ROOT`): `logs/` (one file per service and step), `config/`, `keys/`, `data/`,
`vks/`, `run/node<i>/admin.sock` (the nodes' admin sockets), `timings.txt`, and
`harness.json` with `pss-client/<example>.json`, which a driver reads through
`e2e/harness/harness.ts` (`loadHarness`, `pssClient`, `circuitPackage`, `connectNode`).
The run directory is kept for you to read and remove.

**Ports.** Each default has a variable (the rule: `docs/DECISIONS.md`, "Harness ports"); a base
names node 0's port and node i uses base + i:

| Variable | Default | Tip run (`E2E_TIP=1`) | Service |
| --- | --- | --- | --- |
| `NODE_API_BASE_PORT` | 8200 | 8300 | node HTTPS APIs (base to base + 2) |
| `MESH_BASE_PORT` | 10200 | 10300 | MPC mesh |
| `PG_BASE_PORT` | 15632 | 15732 | Postgres containers |
| `ORCH_PORT` | 3200 | 3300 | orchestrator |
| `AZTEC_PORT` | 8280 | 8380 | Aztec node |
| `AZTEC_ADMIN_PORT` | 9080 | 9180 | Aztec node admin |
| `ANVIL_PORT` | 8745 | 8845 | anvil |
| `RELAYER_PORT` | | 3301 | the first relayer's status port, one more per deployment |
| `REORG_PORT` | `AZTEC_ADMIN_PORT` + 1 | the same | the reorg network's test calls (`E2E_REORG=1` only) |

Every service binds 127.0.0.1 only. The pinned Aztec CLI has no host option for its node
RPC and admin servers, so the network's Node processes load `e2e/harness/loopback.mjs`,
which binds every listen that names no host to 127.0.0.1, and the run stops when a
network port listens beyond loopback.

The script refuses to start when a port is taken, so a second run on the same host needs
other ports and another `PG_PREFIX` (the containers' name prefix, default
`sidecar-e2e-pg`, `sidecar-tip-e2e-pg` in a tip run). It leases every port of the run for
the run's whole life (an flock on `$TXE_TMP_ROOT/port-leases/<port>`) and refuses a port
another run holds; this matters for the mesh ports, which a node binds only while a session
opens. A sidecar run and a tip run use disjoint defaults, so both can run at once. Further
runs need disjoint port sets: with +1000 per run the third run's node APIs (10200 to 10202)
would be the first run's mesh, while +100 per run (+10 for the admin port) keeps up to
eight runs apart. The harness reaches the Aztec admin port, the orchestrator and the Aztec
node with Node's `fetch`, which refuses every port on the WHATWG "bad ports" list (10080 is
one, and a +1000 offset of the admin port lands on it). A +1000 offset that works, with the
admin port at 10081:

```sh
NODE_API_BASE_PORT=9200 MESH_BASE_PORT=11200 PG_BASE_PORT=16632 ORCH_PORT=4200 \
AZTEC_PORT=9280 AZTEC_ADMIN_PORT=10081 ANVIL_PORT=9745 PG_PREFIX=sidecar-e2e-pg-b \
e2e/run.sh amm monty
```

Run `npm ci --no-audit --no-fund` once at the root before starting runs in parallel: a run
reinstalls when `node_modules` does not match the lockfile, and two runs reinstalling at
once wipe each other's `node_modules`.

**Path lengths.** A Unix socket path holds at most 107 bytes. The TXE server and the
network's world state bind sockets under a scratch directory of `TXE_TMP_ROOT`, and each
node binds its admin socket at `<run>/run/node<i>/admin.sock`; a node refuses to start
when that path is longer. Keep `TXE_TMP_ROOT` and any `E2E_LOG_DIR` short.

The other knobs, documented in `e2e/run.sh`:

| Variable | Default | What it sets |
| --- | --- | --- |
| `E2E_LOG_DIR` | a new directory under `TXE_TMP_ROOT` | the run directory; a given one must be new or empty, and short |
| `TXE_TMP_ROOT` | `.runs/tmp` in the repository | the scratch root: the default run directory, the network's sockets, every child's `TMPDIR` |
| `EXPECT_REAL_PROOFS` | 1 | 1: client-side proving and node-side verification; 0: simulated proofs, the logic only |
| `E2E_TIP` | 0 | 1 adds the tip services and moves every default port to the tip range |
| `E2E_REORG` | 0 | 1 starts the local network through `harness/reorg-network.ts` (the reorg scenarios need it; `scenarios/README.md`, "The reorg scenarios") |
| `E2E_TIP_DEPLOYMENTS` | `amm-tip-shared amm-tip amm-tip-stale` | the tip deployments, each `e2e/tip/<name>.json` |
| `E2E_EXAMPLES` | `examples/amm examples/monty-hall` (a tip run: the deployments' examples) | the examples whose circuits the run compiles and configures |
| `E2E_SETUP` | `mesh` | `dealer`: the development shortcut of `sidecar-node setup` |
| `SMOKE_CIRCUIT` | `amm/pss_seed` (a tip run: the first deployment's first package) | the circuit the smoke registers |
| `SIDECAR_BIN_DIR` | the release directory of the cargo target | prebuilt `sidecar-node` and `sidecar-orchestrator` |
| `START_TIMEOUT`, `AZTEC_START_TIMEOUT`, `SETUP_TIMEOUT` | 120, 360, 120 s | service start-up, the network's readiness, setup over the mesh |
| `SMOKE_TIMEOUT`, `DRIVER_TIMEOUT` | 1800, 10800 s | the smoke; each scenario |
| `FEE_TIMEOUT`, `DEPLOY_TIMEOUT`, `INIT_TIMEOUT` | 1800, 3600, 1800 s | a tip run's fee setup, deployments, and wait for the init rounds |

The sidecar binaries run from the release directory of the target directory
`cargo metadata` names, so `CARGO_TARGET_DIR` moves the build and the binaries together.

**Node-side proof verification.** With `EXPECT_REAL_PROOFS=1` (the default) the PXE proves
every transaction client-side, and the harness makes the local network's node verify it:
the network starts with `BB_WORKING_DIRECTORY` and `BB_BINARY_PATH` set, and
`e2e/harness/enable-real-proofs.ts` sets the node's `realProofs` false and then true,
because the first change after start is lost to a config object the node shares with its
sequencer and the verifier is built only on a change. Setting the flag alone makes
`getNodeInfo().realProofs` read true while the node still accepts any proof bytes, so the
harness trusts only the node's log: it requires `Starting QueuedIVCVerifier` before
anything is sent, for each transaction a driver sends one `Accepted <tx hash> with valid
proof` after a `Chonk verification successful` line of its own, and, through
`e2e/harness/node-verification.ts`, a copy of one client-proved transaction with one Chonk
proof field changed that the node refuses with `Invalid proof`. The smoke does this for
its deployment and every scenario for one of its transactions (`connectNode` arms the
checks; a `nodeTamper` step calls `checks.rejectTamperedCopyOfNextTx(label)` before its
send, and the driver calls `checks.finish()` at the end). With `EXPECT_REAL_PROOFS=0`
nothing is proved or verified and a run only shows that the machine and the contracts'
logic work.

**The tip services.** `E2E_TIP=1` adds the tip of the chain to the same harness.
`E2E_TIP_DEPLOYMENTS` names the deployments, each `e2e/tip/<name>.json`, which holds the
test-only facts: the example, its deployment descriptor (`descriptor`:
`examples/<example>/deployments/<descriptor>.json`, the app's part: its contract package,
the package list in REGISTER order with each package's circuit and state key names, the
aliases (`alias_of`: another intake of a listed round, such as `amm-tip`'s receipt intake
manifest of the swap), the init round, the stale period and the contract each placeholder
pinned read calls), the contracts it deploys first (`contracts`: lending's tokens and its
oracle, whose address goes into every round manifest's price read), a stale period in place
of the descriptor's (`staleBlocks`: `amm-tip-stale` registers with 4), the app's own Config
members (`$<name>` for a first contract's address), the init function and the result
function of each package whose results do not land through `process_result`, with the
arguments it takes first (`methods`: `{ "name": "process_shared", "args": [<ROUND_* index>] }`
for lending's secret-shared rounds), the app's fee setting (`fee`, a name in
`harness/fee-settings.ts`) and, for an app that keeps credits, how (`credit`: its funding
function, its credit read and each token's asset; lending's `fund`, `credit_balance`). On
top of the sidecar run it

1. plans each deployment after `sidecar-node setup` (`e2e/harness/tip.ts plan`): builds
   the contract and the contracts it deploys first and fixes their addresses (a salt each,
   a universal deployment of their constructor arguments, `$operator` the local network's
   first account), generates the deployment's contract manifest (pss-client
   `buildContractManifest`: the slots from the artifact, each placeholder pinned read's
   `contract` the first contract the descriptor names for its function) and writes it and the
   circuit manifests it registers (`manifests/tip-<name>/`) and the
   pss-client configurations of them (`pss-client/tip-<name>.json` for the drivers,
   `tip-<name>-relayer.json` of the package list for the relayer, both with the contract
   manifest's stale period), draws a salt, computes the constructor's pins (pss-client
   `tipPins` over the contract manifest's listed packages and their vk hashes) and
   the address, which is the namespace, and writes the `[[tip.namespaces]]` allowlist (each
   deployment's address; the machine reads the slots from the registered contract manifest);
2. gives the three node configs and the orchestrator's the same `[tip]` section, every one
   reading the local network, and after start-up requires each node's chain verifier and
   one scheduler per namespace;
3. sets up the fees (`e2e/harness/fees.ts`): registers wFJ (the `PrivateFPC` of
   `@alejoamiras/private-fee-juice` at its canonical address), and funds each local-network
   account and each relayer's own account (one per deployment, since each relayer's PXE
   spends its own private balance) through an L1 deposit claimed in a funding
   transaction of its own;
4. deploys every deployment's first contracts at their planned addresses, then the
   deployment through pss-client `deployTip` (`e2e/harness/tip.ts deploy`):
   one REGISTER of the contract manifest (every package, the aliases included) at seq 0 by
   a fresh owner key, then the constructor and `configure` paid through wFJ; the scheduler
   then sends the init round;
5. starts one `pss-relayer` per deployment (`config/relayer-<name>.json`, FETCHing on the
   orchestrator's public listener; its process id in
   `run/relayer-<name>.pid`, by which a scenario stops and starts it) and waits for its
   `GET /status`;
6. waits until each relayer has landed its deployment's init round
   (`e2e/harness/tip.ts init`), then runs the smoke and the scenarios, and ends with the
   fee-payer check (`e2e/harness/fee-payers.ts`: wFJ paid every transaction of the run).

`harness.json` records the deployments (address, salt, slots, owner key, relayer config),
wFJ and the funded payers under `tip`. A tip run stops at start-up with a message that
names what is missing when no deployment is named (the nodes and the orchestrator would
have no `[tip]` section) and when the fee setup is incomplete. Every transaction pays under
the fixed gas setting per transaction kind its deployments name (`fee`;
`harness/fee-settings.ts`: `AMM_TIP_FEE_SETTING`, `LENDING_TIP_FEE_SETTING`), and the
driver records each one's gas (`<run>/gas-<scenario>.json`; the measured table is
`e2e/scenarios/README.md`, "Gas per transaction kind").

**The tip's result path with a real proof.** With `EXPECT_REAL_PROOFS=1` the tip scenarios
land the nodes' co-noir proofs through `process_result` and `process_result_shared` on a
network with client-side proving and node-side verification. A result the user lands with
`clientTamper` is first sent twice changed, with a proof field changed and with its last
public input changed under the honest proof (an app output, or the outcome's last
ciphertext or call value, none covered by a node signature), and client-side proving
refuses both (`Failed to verify the generated proof`); a request step with `nodeTamper`
has the node refuse a copy of its transaction with a Chonk proof field changed.
