# Credits paid to a key

> **A simple example.** `pay` credits the payee with an amount the payer names and takes
> nothing from the payer: the credit is unbacked, and no token moves on `pay` or on a
> claim. The ledger is here to show the oblivious keyed map, not as a payment design.

Experimental: the example of the oblivious sparse map
([ARCHITECTURE.md, "The oblivious sparse map"](../../docs/ARCHITECTURE.md#the-oblivious-sparse-map),
which describes the keyed map, its store and its limits). The clear-index tree stays the
recommended tree for a book (`docs/DECISIONS.md` section 7); this example shows what a keyed map
does that a position-indexed tree cannot: insert, update, look up and prove absent an entry
named by a key no node ever sees.

The use: credits anyone pays to a payee before it ever acts. A payee hands out a handle (the
contract's `payee_handle`, a Poseidon2 hash of its address and a secret under a separator of
the app's), a payer credits it, and the payee claims later, naming its handle by the secret
only it knows. No partial note of the payee exists when the payer pays, so the credit cannot be
delivered as a note; it lives in shared state until claimed, addressed by the key. That is the
one thing that must be shared: the unclaimed balance per key.

<!-- bricks:begin -->
## Bricks this example uses

Generated from the `// BRICK` markers in this example's code and `docs/design-guide/design-space.json` (`python3 -I scripts/check-design-space.py --write-bricks`). One row per axis: the option this example plugs in, the library items it calls for it, where, and the alternatives. **Bold**: the example's as-built choice. The combination is this example's; any alternative combines with the rest as [BRICKS.md](../../docs/design-guide/BRICKS.md) says.

| Axis | This example uses | Library calls | Where in this example | Alternatives |
| --- | --- | --- | --- | --- |
| [path](../../docs/design-guide/BRICKS.md#path) | **[`tip`](../../docs/design-guide/BRICKS.md#path-tip)** | none: follows from `intake` | — | [`sidecar`](../../docs/design-guide/BRICKS.md#path-sidecar) |
| [state](../../docs/design-guide/BRICKS.md#state) | **[`node`](../../docs/design-guide/BRICKS.md#state-node)** | none: manifest only (`state`) | — | [`client`](../../docs/design-guide/BRICKS.md#state-client), [`chain`](../../docs/design-guide/BRICKS.md#state-chain) |
| [shape](../../docs/design-guide/BRICKS.md#shape) | **[`map_oblivious`](../../docs/design-guide/BRICKS.md#shape-map_oblivious)** | `pss_core::tip::map::load` | [`circuits/credits_tip/src/shared.nr`](circuits/credits_tip/src/shared.nr): `run` | [`flat`](../../docs/design-guide/BRICKS.md#shape-flat), [`tree`](../../docs/design-guide/BRICKS.md#shape-tree), [`tree_oblivious`](../../docs/design-guide/BRICKS.md#shape-tree_oblivious) |
| [intake](../../docs/design-guide/BRICKS.md#intake) | **[`shared_receipt`](../../docs/design-guide/BRICKS.md#intake-shared_receipt)** | `pss_core::tip::intake::SharedIntake`, `pss_public_contract::SharedReceiptArgs` | [`circuits/credits_tip/src/shared.nr`](circuits/credits_tip/src/shared.nr): `run`; [`contract/credits_tip/src/main.nr`](contract/credits_tip/src/main.nr): `pay` | [`direct`](../../docs/design-guide/BRICKS.md#intake-direct), [`onchain`](../../docs/design-guide/BRICKS.md#intake-onchain), [`receipt`](../../docs/design-guide/BRICKS.md#intake-receipt), [`shared_onchain`](../../docs/design-guide/BRICKS.md#intake-shared_onchain), [`relayed`](../../docs/design-guide/BRICKS.md#intake-relayed) |
| [binding](../../docs/design-guide/BRICKS.md#binding) | **[`turn`](../../docs/design-guide/BRICKS.md#binding-turn)** | none: manifest only (`binding`) | — | [`none`](../../docs/design-guide/BRICKS.md#binding-none), [`exact`](../../docs/design-guide/BRICKS.md#binding-exact) |
| [outputs](../../docs/design-guide/BRICKS.md#outputs) | **[`private`](../../docs/design-guide/BRICKS.md#outputs-private)** | follows from `intake`; not marked in this example's code | — | [`public`](../../docs/design-guide/BRICKS.md#outputs-public) |
| [value](../../docs/design-guide/BRICKS.md#value) | **[`partial`](../../docs/design-guide/BRICKS.md#value-partial)** | follows from `intake`; not marked in this example's code | — | [`none`](../../docs/design-guide/BRICKS.md#value-none) |
| [delivery](../../docs/design-guide/BRICKS.md#delivery) | **[`constrained`](../../docs/design-guide/BRICKS.md#delivery-constrained)** | none: follows from `outputs` | — | [`clear`](../../docs/design-guide/BRICKS.md#delivery-clear), [`node_sealed`](../../docs/design-guide/BRICKS.md#delivery-node_sealed) |
| [submission](../../docs/design-guide/BRICKS.md#submission) | **[`relayer`](../../docs/design-guide/BRICKS.md#submission-relayer)** | none: an app calls nothing of it | — | [`user`](../../docs/design-guide/BRICKS.md#submission-user) |
| [node_keys](../../docs/design-guide/BRICKS.md#node_keys) | **[`fixed`](../../docs/design-guide/BRICKS.md#node_keys-fixed)** | `pss_public_contract::FixedKeys` | [`contract/credits_tip/src/app.nr`](contract/credits_tip/src/app.nr): `Keys` | [`rotating`](../../docs/design-guide/BRICKS.md#node_keys-rotating) |
| [upgrades](../../docs/design-guide/BRICKS.md#upgrades) | **[`fixed`](../../docs/design-guide/BRICKS.md#upgrades-fixed)** | `pss_public_contract::FixedCircuits` | [`contract/credits_tip/src/main.nr`](contract/credits_tip/src/main.nr): `configured_in_force` | [`circuits`](../../docs/design-guide/BRICKS.md#upgrades-circuits), [`contract`](../../docs/design-guide/BRICKS.md#upgrades-contract) |
| always present | [Client core](../../docs/design-guide/BRICKS.md#always-present), [Generic e2e driver](../../docs/design-guide/BRICKS.md#always-present), [TipNamespace](../../docs/design-guide/BRICKS.md#path-tip), [Queue](../../docs/design-guide/BRICKS.md#path-tip), [Intake functions](../../docs/design-guide/BRICKS.md#path-tip), [Result](../../docs/design-guide/BRICKS.md#path-tip), [Pinned public reads](../../docs/design-guide/BRICKS.md#path-tip), [App skeleton](../../docs/design-guide/BRICKS.md#path-tip), [Configure once](../../docs/design-guide/BRICKS.md#path-tip), [Tip round helpers](../../docs/design-guide/BRICKS.md#path-tip), [IntakeModule](../../docs/design-guide/BRICKS.md#path-tip), [ResultReader](../../docs/design-guide/BRICKS.md#path-tip), [Discovery](../../docs/design-guide/BRICKS.md#path-tip), [Fee payment](../../docs/design-guide/BRICKS.md#path-tip) | on every tip path: [BRICKS.md](../../docs/design-guide/BRICKS.md#path-tip) lists what to call | — | — |
<!-- bricks:end -->

## The ledger

One tree-valued node-held key, the map, of depth 64 with leaves `[key, balance, blinding]`
(`circuits/credits_tip/src/ledger.nr`: `DEPTH`, `LEAF_LEN`). Keys must be hash outputs: every
request function computes each key it sends as `map_key(handle)`, a domain-separated Poseidon2
of a handle (`contract/credits_tip/src/app.nr`), so no caller-chosen field reaches the map and a
collision in the low 64 bits costs a `2^64` search. A key taken raw would let anyone block a
known key `K` with one request (`pay(K + 2^64, 1)` lands on `K`'s path and takes it);
`map_key(K + 2^64)` lands on an unrelated path. A collision costs liveness for one key, never a
wrong value (the map's `taken` rule).

| Round | Slots | What it does | Outcome fields `[code, round, a, b]` |
| --- | --- | --- | --- |
| `credits_init` | 1, unused | creates the key with the empty map (the operator's deployment; never queued) | none (`Init<0>`) |
| `pay(key, amount)` | 1 | an insert where the key is absent, an addition where present; the circuit selects, nobody else learns which | `[code, 1, amount, 0]`: the payer learns nothing of the payee's balance |
| `claim(key, amount)` | 1 | requires the key held (present with a nonzero balance) with the balance; writes `balance - amount` | `[code, 2, amount, balance left]` |
| `view(key)` | 1 | the prove-absent round: writes no new value | `[code, 3, present, balance]` |
| `move(from, to, amount)` | 2 | the source held with the balance, the destination inserted when absent, the two keys distinct | `[code, 4, amount, source balance left]` |

`round` is the round's place in the package list (`ROUND_PAY` 1 to `ROUND_MOVE` 4, `ledger.nr`,
which the contract's round table reuses), so a note says which round it answers. A round whose
shares do not open `C` seals the code alone, `[1, 0, 0, 0]`.

Codes (`ledger.nr`): 1 the shares do not open to `C`; 2 the amount is zero or not a u64; 3 a
slot's leaf holds another key; 4 the key is absent; 5 the balance is below the amount; 6 the new
balance is not a u64; 7 a move names one key twice; 8 the nodes' reads do not form paths to one
root. Every round is total: a request that cannot apply lands as a flagged no-op whose private
outcome carries the code.

Every round runs under secret-shared receipt intake with a private outcome (REGISTER accepts
`access: oblivious` under the secret-shared intakes alone); the keys and the amount are
`INPUT_SHARED` and bound through `C`. Every round writes every slot on every outcome under a
fresh blinding (a present leaf keeps its key and balance, an absent key is entered with a zero
balance, which reads as absent to every round), so the chain cannot tell an effect from a no-op
or a present key from an absent one. A request whose shares do not open `C` enters no key:
pss_core's map turns an absent slot into a vacant leaf, so nobody can take another user's key's
path with shares of a field the request did not commit. The public outputs are pss_core's
`Private<1, 1, 0, 1, 5>` (two commitments, a note hash, a five-field ciphertext; no leaf hash),
and the outcome completes the requester's partial note at `OUTCOME_SLOT`.

## What each party sees

| Party | sees |
| --- | --- |
| one node | `C`, the round type, the count of slots, timing; the map's fill count at each DORAM bottom rebuild (about 120 addresses per key at a few hundred keys); never a key, a path, a hash, whether a key was present, or whether a round inserted |
| two or three nodes | everything shared, every key included; invariant 0 holds: a key authorises nothing, the contract's request function does |
| the orchestrator | `C`, the count and the network address |
| the world | the commitments and the completed notes; no count of entries, no log, no escape hatch |

## Costs

Per slot 68 DORAM reads and, next session, 68 writes (lending's: 25); per round `2 · K · 64`
shared Poseidon2 permutations (256 for `move`, 128 for the others). Gate counts (bb 6.0.0
`gates`): `credits_init` 3,984, `pay` 15,125, `claim` 15,139, `view` 15,027, `move` 26,489.
The map's capacity is `2^18` distinct addresses by default (the manifest's `capacity`), 430 MB
per node, which keeps about 285 keys working at depth 64; a round that could pass it is refused
(409, "the keyed map is full"), and a full map stays full, so a deployment that expects more
keys sets a larger capacity before it registers the map.

## Files

- `circuits/credits_tip` (`ledger.nr` the rounds, `shared.nr` the secret-shared entry and the
  finisher, with tests against a two-leaf sparse tree), one bin package per round,
  `circuits.env`.
- `circuits/gen-fixtures.py` writes every `Prover*.toml` and `outputs.txt` from a sparse tree
  over `scripts/poseidon2.py`, so each case's commitments are checked against the script's tree;
  its header states the scenario (an insert, an addition, the collision, the absent claim, the
  views, the move).
- `manifests/`: `credits_init.json` (`probe` 1, no index) and `pay.json`, `claim.json`,
  `view.json`, `move.json` (the keys `INPUT_SHARED`, three LOAD slices of 68 or 136 elements,
  `keyed: true`, depth 64).

## Contract

`contract/` is a Nargo workspace of two packages on `noir/pss_public_contract`: `credits_tip`
(the `CreditsTip` contract; its pins, key derivation, validity checks and outcome note in
`src/app.nr`) and `credits_tip_test` (its TXE suite). One deployment lists the five packages in
`circuits.env`'s order (`CREDITS_PACKAGES`). The ledger key is the storage slot of `ledger`;
the outcome notes come first in storage, so their slot is the circuits' `OUTCOME_SLOT` (1).

| Function | What it does |
| --- | --- |
| `init_ledger(new_c, signatures)` | lands `credits_init` once, outside the queue |
| `pay(handle, amount, rho, outcome_key, outcome_tag, sharing, expiry_block, receipts)` | anyone pays any handle; the key is `map_key(handle)`; `sharing` proved to open `C` under `PAY_LAYOUT` and the receipts checked; refused in the PXE for the handle 0 or an amount that is not a nonzero u64 |
| `claim(secret, amount, ...)` | the key is `own_map_key(sender, secret)` = `map_key(payee_handle(sender, secret))`: only its owner names it |
| `view_balance(secret, ...)` | the prove-absent round on the sender's key |
| `move_credit(secret, to, amount, ...)` | from the sender's key to `map_key(to)` |
| `process_result(round, result, signatures)` | one round's private outcome under its row's vk pin; lands the completed note and the outcome log and enqueues `apply_result`, the one apply of every round type |
| `deliver_outcome`, `credit_notes` | the client hands its PXE the completed note `[code, round, a, b, request_id]`; the notes an owner holds |

Each request commits the sender's partial note from `rho` and enqueues the same public call,
`append_receipt(request_id, expiry_block)`, so the chain sees neither the round type nor a key.
`configure`, `skip()`, `get_state`, `request_at` and `done_at` are the library's. Each round's
layout global (`src/layouts.nr`) is generated from its manifest (`scripts/gen-intake.py
--layouts`).

The node keys are fixed (the `node_keys` axis): `Keys` is `FixedKeys`, so every signature is
checked under the constructor's `sig` keys for the contract's life and it declares no key-epoch
entry point; its public bytecode is 13,250 bytes, 4,958 fewer than with `KeyEpochs<NoEncKeys>`.
A node replacement names it for redeployment under a new salt
([Node replacement and key epochs](../../docs/ARCHITECTURE.md#node-replacement-and-key-epochs)).
Its circuits are fixed too (the `upgrades` axis): a new circuit is a new deployment. Every round
type's request uses the same gas, and so does every result (measured in the tip e2e:
[`credits-tip.ts`](../../e2e/scenarios/README.md#credits-tipts)). No token moves: an app that pays a token out on a claim reads the note's `round` to tell it from a pay.

## Running it

```sh
scripts/check-noir.sh examples/credits-tip --outputs examples/credits-tip/circuits/outputs.txt
scripts/check-contracts.sh                       # the contract under the Aztec compiler
scripts/txe.sh --contracts --only examples/credits-tip/contract/credits_tip_test   # the TXE suite
E2E_TIP=1 E2E_TIP_DEPLOYMENTS="credits-tip" EXPECT_REAL_PROOFS=1 e2e/run.sh credits-tip
```

The TXE suite computes every round with the circuits' own functions over a clear model of the
map: the init, a pay inserting the key and completing the payer's note, the owner's claim and
move, a view finding a key present and one proving a key absent, a claim under another sender
naming that sender's own (absent) key, a pay to `K + 2^64` that leaves `K` free, and one refusal
per app rule. The e2e scenario (`e2e/scenarios/credits-tip.ts`, deployment
`e2e/tip/credits-tip.json`) runs a pay, a claim, an absent view, a move and a view with real
proofs on a local network.
