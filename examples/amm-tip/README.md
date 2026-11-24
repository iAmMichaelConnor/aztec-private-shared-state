# AMM at the tip of the chain

> **A simple example.** A minimal constant-product pool that shows the tip bricks, not a
> design for a private AMM. Under the secret-shared intakes the reserves stay off chain and
> no single node can open them, but a trader learns its own swaps' outcomes, and two
> outcomes of a constant-product pool determine both reserves: any participant can infer
> the reserves from its own trades. No token moves: `swap` collects nothing for
> `amount_in`, and `redeem` spends the trader's note and returns its `amount_out` as a
> number (`contract/amm_tip/src/main.nr`).

A constant-product pool whose reserves are private shared state held by the network, with
requests queued on chain and applied in queue order
([ARCHITECTURE section 6, "The examples on node-held state"](../../docs/ARCHITECTURE.md#the-examples-on-node-held-state)).
The state mode is `node`: the pool is one small key, no tree, whose stored vector is
`[reserve_x, reserve_y, blinding]`; the three nodes hold it as Rep3 pairs, one version per
commitment, and the chain holds only the commitment, in the contract's public slot `pool`.
`apply` writes the new commitment and logs nothing. The swap circuits are total, so a
request that cannot trade still proves and lands, and the queue moves on.

> **How to read this example.** The contract carries every intake on purpose, so each
> option can be seen and run from one place; a deployment's manifests select which it uses.
> That is a property of the example, not a pattern to copy. Your app picks one intake
> ([the design guide](../../docs/design-guide/README.md) walks the choice), and its
> contract declares only the entry points of the bricks it picked. No combination here is
> "the" way to build on private shared state.

<!-- bricks:begin -->
## Bricks this example uses

Generated from the `// BRICK` markers in this example's code and `docs/design-guide/design-space.json` (`python3 -I scripts/check-design-space.py --write-bricks`). One row per axis: the option this example plugs in, the library items it calls for it, where, and the alternatives. **Bold**: the example's as-built choice. The combination is this example's; any alternative combines with the rest as [BRICKS.md](../../docs/design-guide/BRICKS.md) says.

| Axis | This example uses | Library calls | Where in this example | Alternatives |
| --- | --- | --- | --- | --- |
| [path](../../docs/design-guide/BRICKS.md#path) | **[`tip`](../../docs/design-guide/BRICKS.md#path-tip)** | none: follows from `intake` | — | [`sidecar`](../../docs/design-guide/BRICKS.md#path-sidecar) |
| [state](../../docs/design-guide/BRICKS.md#state) | **[`node`](../../docs/design-guide/BRICKS.md#state-node)** | `pss_public_contract::NodeHeld` | [`contract/amm_tip/src/main.nr`](contract/amm_tip/src/main.nr): `init_pool` | [`client`](../../docs/design-guide/BRICKS.md#state-client), [`chain`](../../docs/design-guide/BRICKS.md#state-chain) |
| [shape](../../docs/design-guide/BRICKS.md#shape) | **[`flat`](../../docs/design-guide/BRICKS.md#shape-flat)** | `pss_core::tip::slot::create`, `pss_core::tip::slot::load` | [`circuits/amm_init_tip/src/main.nr`](circuits/amm_init_tip/src/main.nr): `main`; [`circuits/amm_swap_tip/src/main.nr`](circuits/amm_swap_tip/src/main.nr): `main`; [`circuits/amm_swap_tip_shared/src/main.nr`](circuits/amm_swap_tip_shared/src/main.nr): `main` | [`tree`](../../docs/design-guide/BRICKS.md#shape-tree), [`tree_oblivious`](../../docs/design-guide/BRICKS.md#shape-tree_oblivious), [`map_oblivious`](../../docs/design-guide/BRICKS.md#shape-map_oblivious) |
| [intake](../../docs/design-guide/BRICKS.md#intake) | [`onchain`](../../docs/design-guide/BRICKS.md#intake-onchain), [`receipt`](../../docs/design-guide/BRICKS.md#intake-receipt), **[`shared_receipt`](../../docs/design-guide/BRICKS.md#intake-shared_receipt)**, [`shared_onchain`](../../docs/design-guide/BRICKS.md#intake-shared_onchain) | `pss_core::tip::family::Plain`, `pss_core::tip::intake::SharedIntake`, `pss_public_contract::SharedOnchain`, `pss_public_contract::onchain_request`, `pss_public_contract::receipt_request`, `pss_public_contract::outcome_request`, `pss_public_contract::SharedOnchainArgs`, `pss_public_contract::check_enc_rotation` | [`circuits/amm_swap_tip/src/main.nr`](circuits/amm_swap_tip/src/main.nr): `main`; [`circuits/amm_swap_tip_shared/src/main.nr`](circuits/amm_swap_tip_shared/src/main.nr): `main`; [`contract/amm_tip/src/app.nr`](contract/amm_tip/src/app.nr): `Keys`; [`contract/amm_tip/src/main.nr`](contract/amm_tip/src/main.nr): `swap`, `swap_with_receipts`, `swap_shared`, `swap_shared_onchain`, `rotate_enc_key` | [`direct`](../../docs/design-guide/BRICKS.md#intake-direct), [`relayed`](../../docs/design-guide/BRICKS.md#intake-relayed) |
| [binding](../../docs/design-guide/BRICKS.md#binding) | **[`turn`](../../docs/design-guide/BRICKS.md#binding-turn)** | none: manifest only (`binding`) | — | [`none`](../../docs/design-guide/BRICKS.md#binding-none), [`exact`](../../docs/design-guide/BRICKS.md#binding-exact) |
| [outputs](../../docs/design-guide/BRICKS.md#outputs) | [`public`](../../docs/design-guide/BRICKS.md#outputs-public), **[`private`](../../docs/design-guide/BRICKS.md#outputs-private)** | `pss_public_contract::result::PartialResult`, `pss_public_contract::outcome::OutcomeResult`, `pss_public_contract::outcome::Private` | [`contract/amm_tip/src/app.nr`](contract/amm_tip/src/app.nr): `SwapResult`, `SwapSharedResult`; [`contract/amm_tip/src/main.nr`](contract/amm_tip/src/main.nr): `process_result_shared` | — |
| [value](../../docs/design-guide/BRICKS.md#value) | **[`partial`](../../docs/design-guide/BRICKS.md#value-partial)** | `pss_core::tip::family::Plain`, `pss_public_contract::partial_note::commit`, `pss_public_contract::result::PartialResult::completing` | [`circuits/amm_swap_tip/src/main.nr`](circuits/amm_swap_tip/src/main.nr): `main`; [`contract/amm_tip/src/main.nr`](contract/amm_tip/src/main.nr): `commit_partial`, `apply` | [`none`](../../docs/design-guide/BRICKS.md#value-none) |
| [delivery](../../docs/design-guide/BRICKS.md#delivery) | **[`constrained`](../../docs/design-guide/BRICKS.md#delivery-constrained)** | none: follows from `outputs` | — | [`clear`](../../docs/design-guide/BRICKS.md#delivery-clear), [`node_sealed`](../../docs/design-guide/BRICKS.md#delivery-node_sealed) |
| [submission](../../docs/design-guide/BRICKS.md#submission) | **[`relayer`](../../docs/design-guide/BRICKS.md#submission-relayer)** | none: an app calls nothing of it | — | [`user`](../../docs/design-guide/BRICKS.md#submission-user) |
| [node_keys](../../docs/design-guide/BRICKS.md#node_keys) | **[`rotating`](../../docs/design-guide/BRICKS.md#node_keys-rotating)** | `pss_public_contract::KeyEpochs`, `pss_public_contract::key_epoch::check_rotation` | [`contract/amm_tip/src/app.nr`](contract/amm_tip/src/app.nr): `Keys`; [`contract/amm_tip/src/main.nr`](contract/amm_tip/src/main.nr): `rotate_keys` | [`fixed`](../../docs/design-guide/BRICKS.md#node_keys-fixed) |
| [upgrades](../../docs/design-guide/BRICKS.md#upgrades) | **[`contract`](../../docs/design-guide/BRICKS.md#upgrades-contract)** | `pss_public_contract::CircuitUpgrades::in_force` | [`contract/amm_tip/src/main.nr`](contract/amm_tip/src/main.nr): `configured_in_force` | [`fixed`](../../docs/design-guide/BRICKS.md#upgrades-fixed), [`circuits`](../../docs/design-guide/BRICKS.md#upgrades-circuits) |
| always present | [Client core](../../docs/design-guide/BRICKS.md#always-present), [Generic e2e driver](../../docs/design-guide/BRICKS.md#always-present), [TipNamespace](../../docs/design-guide/BRICKS.md#path-tip), [Queue](../../docs/design-guide/BRICKS.md#path-tip), [Intake functions](../../docs/design-guide/BRICKS.md#path-tip), [Result](../../docs/design-guide/BRICKS.md#path-tip), [Pinned public reads](../../docs/design-guide/BRICKS.md#path-tip), [App skeleton](../../docs/design-guide/BRICKS.md#path-tip), [Configure once](../../docs/design-guide/BRICKS.md#path-tip), [Tip round helpers](../../docs/design-guide/BRICKS.md#path-tip), [IntakeModule](../../docs/design-guide/BRICKS.md#path-tip), [ResultReader](../../docs/design-guide/BRICKS.md#path-tip), [Discovery](../../docs/design-guide/BRICKS.md#path-tip), [Fee payment](../../docs/design-guide/BRICKS.md#path-tip) | on every tip path: [BRICKS.md](../../docs/design-guide/BRICKS.md#path-tip) lists what to call | — | — |
<!-- bricks:end -->

The swap round is written once (`amm_tip::tip::swap_round`) and has two entries, one
compiled circuit each:

- **Non-secret-shared** (`amm_swap_tip`; on-chain intake and receipt intake): the inputs
  reach the nodes in the clear and the outputs `[ok, partial_note, code, amount_out]` are
  public; a swap that cannot trade applies as a no-op with `ok = 0` and a code. The request
  commits the trader's partial note `P = partial_commitment(msg_sender, rho)` as a clear
  input, the round echoes it, and `apply` completes the note `[code, amount_out,
  request_id]` in public ([Completion in a public function](../../docs/ARCHITECTURE.md#completion-in-a-public-function)): the world
  sees the amount and `P`, never the owner.
- **Secret-shared** (`amm_swap_tip_shared`; secret-shared receipt intake and secret-shared
  on-chain intake, [Secret-shared intake](../../docs/ARCHITECTURE.md#secret-shared-intake)):
  every input is secret-shared and bound by the inputs commitment C. The round completes
  the trader's partial note inside the co-SNARK (`amount_out` 0 when the swap failed); the
  result transaction lands the completed note and an encrypted outcome log, and the trader
  spends the note with `redeem`. No amount or owner reaches the nodes, the orchestrator or
  the relayer. Under secret-shared on-chain intake the user's private function encodes the
  shares under the nodes' `enc` keys stored in the contract, in one private log; the client
  derives the outcome key and tag per request from its wallet secret and request counter,
  so a trader who loses its state finds its outcome again by rescanning.

A deployment lists the init and one of the two entries (one intake family per namespace).
`scripts/gen-intake.py --check` holds the four swap manifests to their derivation from
`amm_swap_tip_shared.json`; the recipe is the design guide's
[Running a round under another intake](../../docs/design-guide/README.md#running-a-round-under-another-intake).

## Circuits

Under `circuits/`, on `noir/pss_core`'s `tip` round helpers. The swap is `amm_total`'s
`swap_total` (`examples/amm-swap-total`) and the starting reserves are `examples/amm`'s
`Pool::from_seed`, both used by path. Each main.nr starts with the manifest mapping it
expects.

| Package | Kind | What it does |
| --- | --- | --- |
| `amm_tip` | library | `tip.nr`: `swap` (the swap and the `min_out` limit) and `swap_round` over `pss_core::tip::family` (`Plain`, `SharedIntake`); `shared.nr`: the secret-shared outcome's code, layout and note slot; 16 tests |
| `amm_init_tip` | round, not queued | samples a seed, stores the first pool vector, outputs its commitment and the init request id; not total (never queued, keeps `Pool::from_seed`'s native u64 arithmetic; its main.nr says why) |
| `amm_swap_tip` | round, total | `swap_round` under `Plain`; `tip::outputs::BoundPartial` outputs: the request id and `P` echoed after `ok` |
| `amm_swap_tip_shared` | round, total | `swap_round` under `SharedIntake`; `tip::outcome::Private` outputs: the request id over C, the ciphertext, the completed note's hash |
| `amm_swap_tip_next` | round, total | the upgraded swap ([Upgrades](#upgrades)): `swap_round_min_trade` |

The slot commitment is `pss_core::tip::slot::commitment`, `p2_hash_sep([namespace, slot,
reserve_x, reserve_y, blinding], "pss.tip.state")` (`testvectors/slot_commitment.json`). On
`ok = 0` the non-secret-shared swap stores the loaded vector with its old blinding, so
`new_c = old_c` and the nodes create no version (the equal-commitment rule,
[Node-held state](../../docs/ARCHITECTURE.md#node-held-state)). The secret-shared swap writes
the pool under a fresh blinding on every outcome (`Loaded::finish_private`), so the slot
write tells nothing.

Public inputs, in ACIR order:

| Circuit | Public inputs |
| --- | --- |
| `amm_init_tip` (7) | `namespace, vk_hash, out_slots[0], request_id, old_c (= 0), new_c, npk_app_hash` |
| `amm_swap_tip` (12) | `namespace, vk_hash, in_slots[0], out_slots[0], request_id, old_c, new_c, npk_app_hash, ok, partial_note, code, amount_out` |
| `amm_swap_tip_shared` (14) | `namespace, vk_hash, in_slots[0], out_slots[0], request_id, machine_request_id, old_commitments[0], new_commitments[0], npk_app_hash, outcome_tag, note_hashes[0], ciphertext[3]` |

Request ids: non-secret-shared `poseidon2(namespace, vk_hash, inputs_hash, user_nonce)` with
`inputs_hash = poseidon2(amount_in, direction, min_out, partial_note)` (no requester);
secret-shared `poseidon2(namespace, vk_hash, C)` with `C = poseidon2([amount_in, direction,
min_out, partial_note, outcome_key, outcome_tag, blinding])`. Every circuit takes `nsk_app`
by `LOAD nsk_app` only to output `npk_app_hash`.

Codes, first failure wins: 9 (secret-shared only: the shares do not open to C; a flag, so
the request lands as a no-op); then `amm_total`'s in its order: 2 `amount_in` not a u64,
3 `direction` not 0 or 1, 7 a loaded reserve not a u64, 1 zero `amount_in`, 4 the new
input reserve overflows 64 bits, 5 the output rounds to zero, 6 the output drains the pool;
then 8, the output below `min_out` (`min_out = 0` sets no limit). The upgraded swap adds 10,
`amount_in` below `MIN_TRADE`.

The secret-shared outcome `[code, amount_out]` is encrypted under `$outcome_key` with the
completed note's hash as nonce, and the note is completed at the contract's swap-note slot
(`OUTCOME_SLOT` = 1): `poseidon2_hash_with_separator([OUTCOME_SLOT, P, code, amount_out,
request_id], DOM_SEP__NOTE_HASH)` (`pss_core::tip::family::Checked::finish`), the hash of the
contract's `SwapOutcomeNote` owned by whoever committed `P`. The round sees no owner.

Gate counts (bb 6.0.0 `gates`): `amm_swap_tip` 4,450 (238 ACIR opcodes),
`amm_swap_tip_shared` 4,909 (263; C, the outcome's AEAD, the note hash and the machine
request id).

## Checks

`scripts/check-noir.sh examples/amm-tip --outputs examples/amm-tip/circuits/outputs.txt`
compiles, runs the `amm_tip` tests, lints the total circuits and checks every fixture's
outputs against `outputs.txt`. The fixtures use the partial note of owner `0xa11ce` under
`rho` `0x5eed` and the init's pool `Pool::from_seed(111)` = `[1359373, 1852331]` (blinding
333):

- `amm_swap_tip`: `Prover.toml` (sell 25000 x, `min_out = 33000`: `[1, P, 0, 33450]`) and
  one `Prover-<case>.toml` per code, each `[0, P, code, 0]` with `new_c = old_c`: `zero`
  (1), `oversize` (2), `direction2` and `direction-neg` (3), `overflow` (4), `dust` (5),
  `drain` (6, own pool), `bad-reserve` (7, own pool), `min-out` (8).
- `amm_swap_tip_shared`: `Prover.toml` (the same trade, the note `[0, 33450, request_id]`),
  `Prover-mismatch.toml` (code 9), `Prover-min-out.toml` (8), `Prover-zero.toml` (1).
- `amm_swap_tip_next`: `Prover.toml` trades as `amm_swap_tip`'s; `Prover-small.toml`
  (`amount_in` 50) gets code 10.

Lint (total-lint at the total-noir pin):

```
amm_swap_tip  1 ACIR function(s), 238 opcodes; 9 Brillig function(s)
              definition 163, hint-compiler 14, hint-library 56, hint-unreviewed 5, input-falsifiable 0
              brillig abort sites 1 reachable (0 unjustified outside the library), 1 guarded
              reported (unjustified) 0 (+5 justified), exit code 0
```

The five justified items are std's scalar decomposition in `npk_app_hash` (as in
`amm_swap_total`), and the abort site is `pss_core`'s `TACEO_store` oracle call.
`amm_swap_tip_shared` lints the same way (262 opcodes). The swap arithmetic uses only
total-noir entries whose hints co-noir runs, so `total-lint --brillig-ops` reports 0
unsupported ops and a three-party REP3 witness extension of every case succeeds
(`scripts/witness-extend.sh examples/amm-tip`).

## Contract

`contract/` is a Nargo workspace: `amm_tip` (the `AmmTip` contract; the app's types and
functions in `src/app.nr`) and `amm_tip_test` (its TXE suite). Every function is one call
into the library's app skeleton over the round table (`app::rounds`: `init`, `swap`,
`swap_shared`); each is written out in `main.nr` because an Aztec entry point cannot be
generic or added by a library macro.

Storage, in order: `outcome_notes` (the completed `SwapOutcomeNote`s by owner; first, so
its slot stays `OUTCOME_SLOT` = 1 whatever the Config's size), `config`, `configured`,
`queue`, `pool` (the commitment, 0 until init), `shared_onchain` (the nodes' `enc` keys and
epochs, each request's log hash) and `circuit_upgrades`. The pool key in every manifest is
the storage slot of `pool`, passed as both `in_slots` and `out_slots`.

`Config` is the library's `TipPins<2>`: `stale_blocks`, the three node `sig` keys and the
circuit pins (the contract manifest's hash, the package list, each vk hash). The list is the
init and one swap entry: `PLAIN_PACKAGES` (`amm_init_tip`, `amm_swap_tip`) or
`SHARED_PACKAGES` (`amm_init_tip`, `amm_swap_tip_shared`). `configure` adds `npk_app_hash`.
No `enc` key is pinned: each node rotates its own in `shared_onchain`.

| Function | What it does |
| --- | --- |
| `constructor` | checks the package list, writes the Config, pins the upgrade authority |
| `configure` (+ `set_configured`) | checks the three nodes' REGISTER signatures over the constructor's pins; once; until then every request, init, result and `skip()` reverts |
| `init_pool` (+ `apply_init`) | open; lands `amm_init_tip` once, outside the queue, under the fixed init request id, while `pool == 0` |
| `swap` (+ `append_onchain`) | on-chain intake: commits the sender's partial note (`commit_partial`), tells the sender's PXE, queues `[amount_in, direction, min_out, P]` in the request log |
| `swap_with_receipts` (+ `append_receipt`) | receipt intake: the same, with three node receipts and the inputs off chain |
| `swap_shared` | secret-shared receipt intake: the partial note, `sharing` proved to open C, receipts over C; enqueues `append_receipt` with the request id and expiry only |
| `swap_shared_onchain` (+ `append_onchain_shared`) | secret-shared on-chain intake: reads the three `enc` keys at the anchor, emits the request log (13 fields padded to 16), queues the id beside the log's hash and epochs |
| `rotate_enc_key` (+ `set_enc_key`) | node i's `enc` key, signed under its current `sig` key, at the stored epoch + 1 |
| `rotate_keys`, `set_node_keys`, `assert_key_epoch`, `get_node_keys` | [key epochs](../../docs/ARCHITECTURE.md#node-replacement-and-key-epochs); a replaced node's `enc` key is voided |
| `process_result` (+ `apply`) | non-secret-shared result; `apply` writes the slot when ok and completes the trader's note in public on every round |
| `process_result_shared` (+ `apply_shared`) | secret-shared result: pushes the completed note's hash, emits the 16-field outcome log; `apply_shared` writes the new commitment |
| `skip()` | open; drops a head older than `stale_blocks` |
| `redeem(request_id)` | spends the sender's completed note once, returns `amount_out`; refused for no note or amount 0 |
| `upgrade_circuits`, `upgrade_contract`, `assert_upgrade_class`, `get_class_version` | [Upgrades](#upgrades) |
| `get_state`, `request_at`, `done_at`, `get_enc_key`, `get_data_hash` | views |
| `log_in_tx`, `deliver_outcome`, `swap_notes` | utilities: a request or completion log in one transaction; hand the PXE a rebuilt outcome note; the swap notes an owner holds |

`valid_swap`, the static check every intake function asserts: non-zero `amount_in` below
2^64, `direction` 0 or 1, `min_out` below 2^64 (under a secret-shared intake, in the user's
PXE, the only check of a shared input before a round). Codes 4 to 8 depend on the secret
pool and stay the circuit's.

The trader's client takes each request's `rho`, `$outcome_key` and `$outcome_tag` from
pss-client's `SecretStore`; under a secret-shared intake it opens the outcome log
(`OutcomeReader`), rebuilds the note under `rho` and hands it over through
`deliver_outcome`.

The app's choices (each with its reasons in `amm_tip/src`):

- **The init lands outside the queue, through an open `init_pool`**: only a result the
  three nodes signed for this namespace and key verifies, once, so an operator-only init
  would add a liveness dependency and no safety. Its request id is fixed,
  `chain_request_id(namespace, init_vk_hash, inputs_hash([]), 0)`.
- **Intake refuses while the pool is uninitialised**, so no request is queued that could
  only be skipped.
- **The completed note is the trader's credit**: a deployment with a real token pays the
  redeemed amount from the AMM's public balance into a token partial note (`redeem`'s DEV
  DECISION).
- **The note belongs to the request's sender** (`swap_shared`'s DEV DECISION): `P` is
  computed from `msg_sender` and `rho`, and its use nullifier refuses a second request with
  the same `P`.

## What the world learns per round type

Under secret-shared receipt intake the world never sees the inputs, the trader or the
outcome ([Secret-shared intake](../../docs/ARCHITECTURE.md#secret-shared-intake), "What the
world learns: not the round type"). `amm_tip_test/src/test_round_shape.nr` compares four
swaps (a sale of x missing its `min_out`, code 8; shares that do not open to C, code 9; a
sale of x; a sale of y). Every row is the same in all four:

| Seen by the world | Request | Result |
|---|---|---|
| Public call | `append_receipt(request_id, expiry_block)` | `apply_shared(apply)`: request id, old and new commitment |
| Pinned reads | none | none |
| Note hashes | 0 | 1 (the completed note) |
| Nullifiers | 2 (the transaction's and the partial note's use nullifier) | 1 |
| Private logs, length | none | 1, 16 fields |
| Public data writes | 5 | 4 |
| Public logs, L2-to-L1 messages | none | none |
| Metered gas, DA / L2 | 480 / 621,600 | 960 / 612,575 |
| TXE gas setting (`lib.nr` `REQUEST_GAS`, `RESULT_GAS`), DA / L2 | 2,500 / 1,200,000 | 2,000 / 1,300,000 |

The TXE reports no AVM gas and no enqueued calls, so calls are compared as the contract's
interface builds them; the request's call is receipt intake's own wrapper, so it does not
tell a secret-shared request from a non-secret-shared one. The e2e measures gas used with
the AVM's part ([e2e scenarios, "Gas per transaction kind"](../../e2e/scenarios/README.md#gas-per-transaction-kind)):
a filled and a failed secret-shared swap use the same gas, so the fee tells no outcome apart.
Not tested, a stated residual: timing.

What the nodes' knowledge is worth. One node sees C, the circuit and the commitments.
Two colluding nodes open every swap's inputs before it is queued and the reserves, so they
can trade ahead of a victim up to the victim's `min_out`; C binds the victim's inputs and
the queue is FIFO, so `min_out` bounds the loss. All three with every secret also open each
`amount_out` and partial note, but not its owner (hidden behind `rho`). The orchestrator
sees the trader's network address beside C, and no value; the relayer sees ciphertext,
hashes and commitments. No funds are at risk from the nodes' secrets: the circuit is pinned
by the constructor and the note's owner is fixed by the trader's own request function.

## Deployment

The order is [Deployment, configure and the init round](../../docs/ARCHITECTURE.md#deployment-configure-and-the-init-round)'s;
pss-client's `deployTip` runs it: compile and compute each vk hash, build the contract
manifest from a descriptor in `deployments/`, compute the address from a secret salt and the
Config (`stale_blocks` 50), REGISTER at seq 0, deploy, `configure`, then the init round.

| Descriptor | Packages |
| --- | --- |
| `amm-tip.json` | `amm_init_tip`, `amm_swap_tip`, `amm_swap_tip_receipt` (`alias_of` the swap, for receipt intake) |
| `amm-tip-onchain.json` | `amm_init_tip`, `amm_swap_tip` |
| `amm-tip-shared.json` | `amm_init_tip`, `amm_swap_tip_shared` |
| `amm-tip-shared-onchain.json` | as `amm-tip-shared.json`, plus `amm_swap_tip_shared_onchain` (`alias_of`; the contract manifest states `storage.shared_onchain`) |
| `amm-tip-next.json` | as `amm-tip.json`, both swap names on `amm_swap_tip_next` |

A function whose package is not listed refuses ("package not in this deployment"). Under
secret-shared on-chain intake each node keys the contract before the first request:
pss-relayer's `rotate-enc-key` signs the node's `enc` key at epoch 1 and submits
`rotate_enc_key` (`sidecar-node sign-enc-key --namespace <address> --epoch 1` only prints
the arguments).

## Upgrades

`upgrades: contract` ([ARCHITECTURE, "Upgrades"](../../docs/ARCHITECTURE.md#upgrades)):
`circuit_upgrades` ends the storage, the constructor pins an upgrade authority, every round
function takes its row from `configured_in_force`, and `UPGRADE_DELAY` is one day. The
authority can replace all of the contract's code after the delay, `skip()` and `redeem`
included, and a circuit upgrade alone can change the pool's rules: the delay is the users'
only protection (in the e2e the authority is the local network's first account). The nodes
cannot upgrade.

**A circuit upgrade.** `circuits/amm_swap_tip_next`, registered under `amm_swap_tip` (and
its receipt alias) by `deployments/amm-tip-next.json`, lands a swap below `MIN_TRADE` (100)
as a no-op with code 10 and trades every other swap exactly as `amm_swap_tip`. A swap queued under the old
circuit and not run by the switch goes stale and is skipped; the trader only asks again.
`test_upgrade.nr` runs it in the TXE, `e2e/scenarios/amm-tip-upgrade-circuits.ts` end to
end.

**A class upgrade.** The second class is this contract with `class::CLASS_VERSION = 2`
(`contract/amm_tip/src/class.nr`), staged and published by
`e2e/scenarios/amm-tip-upgrade-contract.ts`; after `upgrade_contract` and the delay,
`get_class_version()` answers 2 and the address, the pool and every node-held version stay.

Cost: every round function reads the delayed pins and enqueues the class guard
(`process_result` 27,724 gates, `process_result_shared` 28,019, `init_pool` 27,602, `swap`
10,340, `swap_with_receipts` 16,331, `swap_shared` 16,335, `swap_shared_onchain` 30,004,
against 25,705, 25,999, 25,583, 8,321, 14,312, 14,315 and 27,985 with fixed circuits;
`configure` is 12,095 either way; bb 6.0.0 `gates`, chonk, on nargo 1.0.0-rc.3 output); the
public bytecode is 29,651 bytes, 1,889 more than without `upgrade_contract` (27,762; 21,880
with fixed circuits).

## Manifests

Each manifest in `manifests/` passes `scripts/check-manifests.py` and REGISTER's checks
against the compiled circuit (`cargo test --release -p sidecar-core amm_tip`).

| Manifest | circuit | intake, outcome | old commitment | public inputs |
| --- | --- | --- | --- | --- |
| `amm_swap_tip.json` | `amm_swap_tip` | `onchain`, `partial` (default) | `old_c` | 12 |
| `amm_swap_tip_receipt.json` | `amm_swap_tip` | `receipt`, `partial` (default) | `old_c` | 12 |
| `amm_swap_tip_shared.json` | `amm_swap_tip_shared` | `shared_receipt`, `partial` | `old_commitments[0]` | 14 |
| `amm_swap_tip_shared_onchain.json` | `amm_swap_tip_shared` | `shared_onchain`, `partial` | `old_commitments[0]` | 14 |
| `amm_init_tip.json` | `amm_init_tip` | `onchain` (never enqueued), `none` | none (reads no key) | 7 |

Manifests that share a circuit differ only in name and `intake`. The non-secret-shared ones
fill `partial_note` by PUBLIC `$partial_note`; the secret-shared ones fill `inputs_hash` by
PUBLIC `$inputs_hash`, the three swap inputs by INPUT_SHARED, and `partial_note`,
`outcome_key`, `outcome_tag`, `blinding` by the reserved INPUT_SHARED operands
(`contract/amm_tip/src/layouts.nr` is generated from them, `scripts/gen-intake.py
--layouts`). `vk_hash` and `user_nonce` are machine-filled (PUBLIC `$vk_hash`,
`$user_nonce`). All five: `binding: turn`, `state` node, one output `TACEO_store out0, STORE
$state_keys.writes[0], len 3`, no `consume`, no `public_reads`.

The knobs, with their DEV DECISIONs in each circuit's main.nr:

- `intake`: the inputs public in the request log (on-chain), in the clear to the nodes over
  TLS (receipt), secret-shared (secret-shared receipt), or secret-shared in a private log
  kept on chain for good (secret-shared on-chain).
- `binding: turn`: a swap runs against the pool as it is at the head and protects itself
  with `min_out`; `exact` is deferred.
- `stale_blocks: 50` (about five minutes): the Config takes it from the contract manifest;
  the relayer skips, the scheduler gives up and the nodes prune unqueued receipts by it.
- `state` node: the chain holds only the commitment. `chain` would log the sealed thirds of
  every new state (42 fields here). Recovery needs the nodes' keys, the package that decodes
  the log, and a matching log from the last 64 queue entries or the init round.
- `outcome: partial` everywhere queued (`none` is refused under a secret-shared intake, and
  under a non-secret-shared one would leave the trader no note to redeem); the init
  delivers nothing (`none`).

## Running the checks

[docs/TESTING.md](../../docs/TESTING.md) has every command and its cost; for this example:

```sh
scripts/check-noir.sh examples/amm-tip --outputs examples/amm-tip/circuits/outputs.txt   # compiles (and writes the ABIs the next lines read)
scripts/witness-extend.sh examples/amm-tip              # co-noir three-party witness extension of every case
(cd machine && cargo test --release -p sidecar-core amm_tip)
scripts/txe.sh --contracts --only examples/amm-tip/contract/amm_tip_test   # with the contracts it deploys (amm_tip, pss_probe)
E2E_TIP=1 E2E_TIP_DEPLOYMENTS="amm-tip-shared amm-tip amm-tip-stale" \
  EXPECT_REAL_PROOFS=1 e2e/run.sh amm-tip
```

The TXE suite (`stale_blocks` 4, the keys of `testvectors/keys.json`) computes every round
with the circuits' own `swap_round`; it skips recursive verification (a dummy vk per
circuit, a zero proof) but runs the vk pins. The library's own rules are
`pss_public_contract_test`'s.

| File | Covers |
| --- | --- |
| `test_configure.nr` | the constructor's pins, `configure` once, every entry point refused before it, a list without the swap |
| `test_init.nr` | `init_pool` once while the slot is empty, and its refusals |
| `test_intake.nr` | on-chain and receipt intake: the partial note, no account in the transaction, `valid_swap` |
| `test_receipt_vector.nr` | the node's receipt vector (`testvectors/receipt_route.json`) under `swap_with_receipts` |
| `test_result.nr` | `apply`'s public completion, a failed swap's equal commitment, `redeem` once, `skip()` |
| `test_refusals.nr` | the swap's vk pin against the init's, init replays |
| `test_table.nr` | three swaps on 1,000,000 / 1,500,000 by both intakes: A sells 10,000 x (14,851 y), B sells 7,000 y (4,738 x), A sells 1 y (code 5, a no-op that moves the head) |
| `test_shared.nr` | secret-shared receipt intake: the outcome `[0, 33450]`, delivery under `rho`, codes 9 and 8, `redeem` |
| `test_shared_onchain.nr` | secret-shared on-chain intake: signed rotations, the request log, swaps across a rotation, a layout mismatch (code 9) |
| `test_round_shape.nr` | [What the world learns per round type](#what-the-world-learns-per-round-type) |
| `test_upgrade.nr` | [Upgrades](#upgrades) |

The e2e ([`amm-tip.ts`](../../e2e/scenarios/README.md#amm-tipts)) lands real co-noir proofs
of all three circuits on three deployments: a secret-shared swap and a failed one (code 8),
audited for any address, input, partial note, outcome key or outcome in a public call, log
or write; both non-secret-shared intakes; the stale skip; a tampered proof refused.
`amm-tip-shared-onchain`, `amm-tip-upgrade-circuits`, `amm-tip-upgrade-contract` and
`amm-tip-replace-node` run on demand ([TESTING, "End to end"](../../docs/TESTING.md#end-to-end)).
