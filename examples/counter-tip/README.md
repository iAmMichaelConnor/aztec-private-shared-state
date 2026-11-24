# Counter tip

> **A minimal example.** A private running total that many users add to. It moves no
> token: an add's completed note is its requester's record of the round, and nothing spends
> it. It is here to show the smallest complete app on the default blueprint.

The default blueprint is `tip-flat` (`docs/design-guide/README.md`, "Blueprints";
`python3 -I scripts/check-design-space.py --plan tip-flat`): node-held state, one flat key,
secret-shared receipt intake, private outcomes delivered by partial-note completion, the
relayer, key epochs and fixed circuits. This example takes every default. Copy it first;
`examples/amm-tip` builds the same blueprint with every intake, circuit upgrades and a redeem.

<!-- bricks:begin -->
## Bricks this example uses

Generated from the `// BRICK` markers in this example's code and `docs/design-guide/design-space.json` (`python3 -I scripts/check-design-space.py --write-bricks`). One row per axis: the option this example plugs in, the library items it calls for it, where, and the alternatives. **Bold**: the example's as-built choice. The combination is this example's; any alternative combines with the rest as [BRICKS.md](../../docs/design-guide/BRICKS.md) says.

| Axis | This example uses | Library calls | Where in this example | Alternatives |
| --- | --- | --- | --- | --- |
| [path](../../docs/design-guide/BRICKS.md#path) | **[`tip`](../../docs/design-guide/BRICKS.md#path-tip)** | none: follows from `intake` | — | [`sidecar`](../../docs/design-guide/BRICKS.md#path-sidecar) |
| [state](../../docs/design-guide/BRICKS.md#state) | **[`node`](../../docs/design-guide/BRICKS.md#state-node)** | `pss_public_contract::NodeHeld` | [`contract/counter_tip/src/main.nr`](contract/counter_tip/src/main.nr): `init_counter` | [`client`](../../docs/design-guide/BRICKS.md#state-client), [`chain`](../../docs/design-guide/BRICKS.md#state-chain) |
| [shape](../../docs/design-guide/BRICKS.md#shape) | **[`flat`](../../docs/design-guide/BRICKS.md#shape-flat)** | `pss_core::tip::slot::load`, `pss_core::tip::slot::create` | [`circuits/counter_add/src/main.nr`](circuits/counter_add/src/main.nr): `main`; [`circuits/counter_init/src/main.nr`](circuits/counter_init/src/main.nr): `main` | [`tree`](../../docs/design-guide/BRICKS.md#shape-tree), [`tree_oblivious`](../../docs/design-guide/BRICKS.md#shape-tree_oblivious), [`map_oblivious`](../../docs/design-guide/BRICKS.md#shape-map_oblivious) |
| [intake](../../docs/design-guide/BRICKS.md#intake) | **[`shared_receipt`](../../docs/design-guide/BRICKS.md#intake-shared_receipt)**, [`shared_onchain`](../../docs/design-guide/BRICKS.md#intake-shared_onchain) | `pss_core::tip::intake::SharedIntake`, `pss_public_contract::outcome_request` | [`circuits/counter_add/src/main.nr`](circuits/counter_add/src/main.nr): `main`; [`contract/counter_tip/src/main.nr`](contract/counter_tip/src/main.nr): `add` | [`direct`](../../docs/design-guide/BRICKS.md#intake-direct), [`onchain`](../../docs/design-guide/BRICKS.md#intake-onchain), [`receipt`](../../docs/design-guide/BRICKS.md#intake-receipt), [`relayed`](../../docs/design-guide/BRICKS.md#intake-relayed) |
| [binding](../../docs/design-guide/BRICKS.md#binding) | **[`turn`](../../docs/design-guide/BRICKS.md#binding-turn)** | none: manifest only (`binding`) | — | [`none`](../../docs/design-guide/BRICKS.md#binding-none), [`exact`](../../docs/design-guide/BRICKS.md#binding-exact) |
| [outputs](../../docs/design-guide/BRICKS.md#outputs) | **[`private`](../../docs/design-guide/BRICKS.md#outputs-private)** | follows from `intake`; not marked in this example's code | — | [`public`](../../docs/design-guide/BRICKS.md#outputs-public) |
| [value](../../docs/design-guide/BRICKS.md#value) | **[`partial`](../../docs/design-guide/BRICKS.md#value-partial)** | follows from `intake`; not marked in this example's code | — | [`none`](../../docs/design-guide/BRICKS.md#value-none) |
| [delivery](../../docs/design-guide/BRICKS.md#delivery) | **[`constrained`](../../docs/design-guide/BRICKS.md#delivery-constrained)** | none: follows from `outputs` | — | [`clear`](../../docs/design-guide/BRICKS.md#delivery-clear), [`node_sealed`](../../docs/design-guide/BRICKS.md#delivery-node_sealed) |
| [submission](../../docs/design-guide/BRICKS.md#submission) | **[`relayer`](../../docs/design-guide/BRICKS.md#submission-relayer)** | none: an app calls nothing of it | — | [`user`](../../docs/design-guide/BRICKS.md#submission-user) |
| [node_keys](../../docs/design-guide/BRICKS.md#node_keys) | **[`rotating`](../../docs/design-guide/BRICKS.md#node_keys-rotating)** | `pss_public_contract::KeyEpochs` | [`contract/counter_tip/src/app.nr`](contract/counter_tip/src/app.nr): `Keys` | [`fixed`](../../docs/design-guide/BRICKS.md#node_keys-fixed) |
| [upgrades](../../docs/design-guide/BRICKS.md#upgrades) | **[`fixed`](../../docs/design-guide/BRICKS.md#upgrades-fixed)** | `pss_public_contract::FixedCircuits` | [`contract/counter_tip/src/main.nr`](contract/counter_tip/src/main.nr): `configured_in_force` | [`circuits`](../../docs/design-guide/BRICKS.md#upgrades-circuits), [`contract`](../../docs/design-guide/BRICKS.md#upgrades-contract) |
| always present | [Client core](../../docs/design-guide/BRICKS.md#always-present), [Generic e2e driver](../../docs/design-guide/BRICKS.md#always-present), [TipNamespace](../../docs/design-guide/BRICKS.md#path-tip), [Queue](../../docs/design-guide/BRICKS.md#path-tip), [Intake functions](../../docs/design-guide/BRICKS.md#path-tip), [Result](../../docs/design-guide/BRICKS.md#path-tip), [Pinned public reads](../../docs/design-guide/BRICKS.md#path-tip), [App skeleton](../../docs/design-guide/BRICKS.md#path-tip), [Configure once](../../docs/design-guide/BRICKS.md#path-tip), [Tip round helpers](../../docs/design-guide/BRICKS.md#path-tip), [IntakeModule](../../docs/design-guide/BRICKS.md#path-tip), [ResultReader](../../docs/design-guide/BRICKS.md#path-tip), [Discovery](../../docs/design-guide/BRICKS.md#path-tip), [Fee payment](../../docs/design-guide/BRICKS.md#path-tip) | on every tip path: [BRICKS.md](../../docs/design-guide/BRICKS.md#path-tip) lists what to call | — | — |
<!-- bricks:end -->

## The counter

One node-held flat key, `[total, blinding]` (the manifests' `len` 2), whose commitment lives
in the contract's public slot `counter`.

| Round | What it does | Outcome `[code, total]` |
| --- | --- | --- |
| `counter_init` | creates the key with the total 0 (the operator's deployment; never queued) | none (`Init<0>`) |
| `counter_add` | adds the shared `amount` when the sum fits in a u64 | `[0, total after the add]`, or `[code, 0]` |

Codes (`circuits/counter_tip/src/counter.nr`): 1 the shares do not open to `C`; 2 the sum
is not a u64. Every add is total: a request that cannot apply proves and lands as a no-op,
the total re-blinded under a fresh blinding, so the chain cannot tell an add from a failure.
An add of 0 is a private read of the total. The amount is `INPUT_SHARED` and bound through
`C`; no node, the orchestrator or the relayer sees it or the total. The public outputs are
pss_core's `Private<1, 1, 0, 1, 3>`: two commitments, one note hash, a three-field ciphertext.

## What you write, and what is plumbing

Non-comment, non-blank lines, tests left out. "App" is what differs from app to app; the
rest is the same in every tip app on this blueprint and is copied as it is.

| File | App | Plumbing | What the plumbing is |
| --- | --- | --- | --- |
| `circuits/counter_tip/src/counter.nr` | 17 | 0 | |
| `circuits/counter_tip/src/shared.nr`, `lib.nr` | 2 | 16 | the intake family's three calls around `counter::add` (`check`, `write`, `finish`), `OUTCOME_SLOT`, the output types |
| `circuits/counter_init`, `counter_add` (`main.nr`) | 0 | 28 | each main's ABI and one call |
| `manifests/*.json` | 0 | 48 | each parameter's source, mirroring the mains |
| `contract/counter_tip/src/main.nr` | 26 | 122 | the request function `add` is the app's; 18 wrappers of one library call each |
| `contract/counter_tip/src/app.nr` | 10 | 32 | `valid_add` and the note are the app's; the package names, the `Keys` alias, the pins, the round table and the result types are not |
| `deployments/counter-tip.json` | 0 | 11 | |
| **Total** | **55 (18%)** | **257 (82%)** | |
| `client/counter.ts` | about 8 | 53 | the build type, the deployment and the reach (`deployTipApp`, `tipAppAt`), the three request steps |

The mains and their manifests (76 lines) state each parameter twice, once as the
circuit's ABI and once as its source. The wrappers stay one per function: an
`#[external]` function cannot be generic, and a macro that inserts them does not resolve
under aztec-nr v6.

## Files

- `circuits/counter_tip`: the app library, `counter.nr` (the rule and its outcome fields)
  and `shared.nr` (what a secret-shared intake adds to it); `counter_init` and `counter_add`,
  one bin package per round, each with its `Prover*.toml` cases; `circuits.env`;
  `outputs.txt`, every case's expected outputs.
- `manifests/counter_init.json` (intake `onchain`, never queued) and
  `manifests/counter_add.json` (intake `shared_receipt`, outcome `partial`).
- `deployments/counter-tip.json`: the deployment descriptor, from which pss-client's
  `buildContractManifest` makes the contract manifest.
- `contract/`: a Nargo workspace of `counter_tip` (the `CounterTip` contract; the app part
  in `src/app.nr`) and `counter_tip_test` (its TXE suite).
- `client/counter.ts`: the client flow, a workspace of the root `package.json`.

## Contract

| Function | What it does |
| --- | --- |
| `add(amount, rho, outcome_key, outcome_tag, sharing, expiry_block, receipts)` | the request: the library commits the sender's partial note from `rho`, checks `valid_add` (an amount that is no u64 is refused in the PXE), proves that `sharing` opens `C` under `COUNTER_ADD_LAYOUT` (every value shared), computes the request id, checks the three receipts over `C` and the sharing's digest, and enqueues `append_receipt(request_id, expiry_block)` |
| `init_counter(new_c, signatures)` | lands `counter_init` once, outside the queue |
| `process_result(result, signatures)` | checks that the outcome notes' slot is the circuits' `OUTCOME_SLOT` (`Private::of`), verifies the add's proof and signatures, lands the completed note and the outcome log, enqueues `apply_result` |
| `deliver_outcome(owner, rho, packed, tx)` | the requester's client hands its PXE the completed note `[code, total, request_id]` (`deliver_outcome_into`, which takes `packed` at the note type's packed length) |

The rest (`configure`, `skip`, `rotate_keys`, `set_node_keys`, `assert_key_epoch`,
`get_node_keys`, `get_state`, `request_at`, `done_at` and the public halves) is the
library's, one call each; `append_receipt` is `Queue::append_receipt`, which refuses
before `configure` and before the init ("state not initialised"). The outcome notes come first in storage, so their slot is the
circuits' `OUTCOME_SLOT` (1). The public bytecode is 16,370 bytes (bb 6.0.0
`aztec_process`, its `public_dispatch`).

## Gate counts

bb 6.0.0 `gates`, circuit size: `counter_init` 3,764; `counter_add` 4,602.

## Client

`client/counter.ts` is the flow an app's client runs, in pss-client calls:

1. `deployCounter`: `deployTipApp` makes the contract manifest from the descriptor, the two
   circuit manifests, the vk hashes and the artifact (`buildContractManifest`), REGISTERs it
   under the address the constructor's pins give (`deployTip`, through a pss-client with no
   namespace), deploys and configures through `aztecDeployer` (the operator, once), and
   configures the namespace's pss-client (its circuits from `circuitPackages`, its stale
   period the descriptor's). `counterAt` reaches a deployed counter from a user's wallet
   (`tipAppAt`). The network then runs `counter_init` and its relayer lands it.
2. `requestAdd`: `requestOutcome` takes the requester's next request secrets
   (`SecretStore.nextPartial`: the partial note, `rho`, the derived outcome key and tag),
   secret-shares the amount to the nodes for their receipts over `C`, sends `add` and
   returns what the requester keeps (`OutcomeRequest`).
3. `waitForAdd`: `waitForRequest` polls the queue (`pollResult`, at the artifact's queue
   slot) until it has finished the request (applied, or skipped when stale).
4. `readAdd`: pss-client's `readAndDeliverOutcome` finds and opens the outcome log, at the
   slot the state view reports and with the plaintext length the circuit outputs, and hands
   the completed note to the owner's PXE through `deliver_outcome` (`outcomeDeliveryArgs`)
   when it is the logged note.

The root `npm run build` type-checks it; no suite runs it.

## Running it

Use a source checkout on x86_64 Linux with Rust 1.90.0, Node 24 or later, Python 3.11
or later, a running Docker daemon, bash, curl, tar, sha256sum, git, jq, `ss`, `pgrep`,
and util-linux's `flock` and `setsid`. Install the pinned tools, including Foundry, and
run the scenario from the repository root. See [Setup](../../docs/DESIGN.md#setup).

```sh
rustup toolchain install 1.90.0
scripts/install-toolchain.sh --with-foundry
npm ci --no-audit --no-fund
E2E_TIP=1 E2E_TIP_DEPLOYMENTS="counter-tip" e2e/run.sh counter-tip
```

The harness builds the circuits and services, starts a local Aztec network with three
PSS nodes and a relayer, and deploys the counter. The init round sets the total to 0.
Alice adds 5 and opens her private outcome `[0, 5]`. Bob adds 7 and opens `[0, 12]`.
Each receives a completed note. The harness stops the services on exit and keeps the
logs in its run directory. See the [scenario](../../e2e/scenarios/counter-tip.ts),
[deployment](../../e2e/tip/counter-tip.json), and [harness guide](../../e2e/README.md).

### Checking it

```sh
scripts/check-noir.sh examples/counter-tip --outputs examples/counter-tip/circuits/outputs.txt
scripts/check-contracts.sh examples/counter-tip
scripts/txe.sh --contracts --only examples/counter-tip/contract/counter_tip_test
npm run build --workspace examples/counter-tip/client
```

The TXE suite computes the add with the circuit's own `add_shared`: the init lands the
first commitment, one add lands and its requester opens `[0, 5]` and takes the note, a
replayed result is refused (`not the head`), an add before the init is refused (`state
not initialised`), and an amount over a u64 is refused in the PXE. The add's layout,
`COUNTER_ADD_LAYOUT` (`contract/counter_tip/src/layouts.nr`), is generated from its manifest
(`scripts/gen-intake.py --layouts`).
