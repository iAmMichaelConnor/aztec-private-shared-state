# AMM on the PSS machine

> **A simple example.** A minimal constant-product pool that shows how the bricks fit
> together, not a design for a private AMM. Here every swap's `amount_in`, `direction`
> and `amount_out` are public, so anyone who sees two consecutive swaps can solve both
> reserves ("What one evaluation reveals"). No token moves: the contract's `swap` is
> where transfers would go.

The node-held example. A constant-product pool is shared state that many traders
transition, so every key it uses is node-held: between rounds the pool's reserves
exist only as one row per key at each node (that node's Rep3 shares), and no single
node can open them. On chain the pool is a note hash; each swap shows its
`amount_out`, which with the public `amount_in` gives the reserves away over two swaps.

A swap comes in two forms over the same pool note. `amm_swap` asserts: a bad request
(a zero amount, a trade that rounds to zero) has no proof, and the nodes refuse it 422
with nothing stored. `amm_swap_total` is total (no input makes it unsatisfiable): the
same request proves with `ok = 0` and a failure code, and lands through the contract's
`swap_total` as a no-op that spends the pool note and re-creates it, with the old
reserves, under a fresh blinding.

<!-- bricks:begin -->
## Bricks this example uses

Generated from the `// BRICK` markers in this example's code and `docs/design-guide/design-space.json` (`python3 -I scripts/check-design-space.py --write-bricks`). One row per axis: the option this example plugs in, the library items it calls for it, where, and the alternatives. **Bold**: the example's as-built choice. The combination is this example's; any alternative combines with the rest as [BRICKS.md](../../docs/design-guide/BRICKS.md) says.

| Axis | This example uses | Library calls | Where in this example | Alternatives |
| --- | --- | --- | --- | --- |
| [path](../../docs/design-guide/BRICKS.md#path) | **[`sidecar`](../../docs/design-guide/BRICKS.md#path-sidecar)** | `pss_core::effects::consume_note`, `pss_contract::apply` | [`circuits/amm_swap/src/main.nr`](circuits/amm_swap/src/main.nr): `main`; [`contract/amm/src/main.nr`](contract/amm/src/main.nr): `apply_swap` | [`tip`](../../docs/design-guide/BRICKS.md#path-tip) |
| [state](../../docs/design-guide/BRICKS.md#state) | **[`node`](../../docs/design-guide/BRICKS.md#state-node)** | none: manifest only (`state`) | — | [`client`](../../docs/design-guide/BRICKS.md#state-client), [`chain`](../../docs/design-guide/BRICKS.md#state-chain) |
| [shape](../../docs/design-guide/BRICKS.md#shape) | **[`flat`](../../docs/design-guide/BRICKS.md#shape-flat)** | none: manifest only (`tree`) | — | [`tree`](../../docs/design-guide/BRICKS.md#shape-tree), [`tree_oblivious`](../../docs/design-guide/BRICKS.md#shape-tree_oblivious), [`map_oblivious`](../../docs/design-guide/BRICKS.md#shape-map_oblivious) |
| [intake](../../docs/design-guide/BRICKS.md#intake) | **[`direct`](../../docs/design-guide/BRICKS.md#intake-direct)** | none: manifest only (`intake`) | — | [`onchain`](../../docs/design-guide/BRICKS.md#intake-onchain), [`receipt`](../../docs/design-guide/BRICKS.md#intake-receipt), [`shared_receipt`](../../docs/design-guide/BRICKS.md#intake-shared_receipt), [`shared_onchain`](../../docs/design-guide/BRICKS.md#intake-shared_onchain), [`relayed`](../../docs/design-guide/BRICKS.md#intake-relayed) |
| [binding](../../docs/design-guide/BRICKS.md#binding) | **[`none`](../../docs/design-guide/BRICKS.md#binding-none)** | none: manifest only (`binding`) | — | [`turn`](../../docs/design-guide/BRICKS.md#binding-turn), [`exact`](../../docs/design-guide/BRICKS.md#binding-exact) |
| [outputs](../../docs/design-guide/BRICKS.md#outputs) | **[`public`](../../docs/design-guide/BRICKS.md#outputs-public)** | none: follows from `intake` | — | [`private`](../../docs/design-guide/BRICKS.md#outputs-private) |
| [value](../../docs/design-guide/BRICKS.md#value) | **[`none`](../../docs/design-guide/BRICKS.md#value-none)** | none: follows from `intake` | — | [`partial`](../../docs/design-guide/BRICKS.md#value-partial) |
| [delivery](../../docs/design-guide/BRICKS.md#delivery) | **[`clear`](../../docs/design-guide/BRICKS.md#delivery-clear)** | none: follows from `outputs` | — | [`constrained`](../../docs/design-guide/BRICKS.md#delivery-constrained), [`node_sealed`](../../docs/design-guide/BRICKS.md#delivery-node_sealed) |
| [submission](../../docs/design-guide/BRICKS.md#submission) | **[`user`](../../docs/design-guide/BRICKS.md#submission-user)** | none in this example's code | — | [`relayer`](../../docs/design-guide/BRICKS.md#submission-relayer) |
| [node_keys](../../docs/design-guide/BRICKS.md#node_keys) | **[`rotating`](../../docs/design-guide/BRICKS.md#node_keys-rotating)** | none: no brick of its own here | — | [`fixed`](../../docs/design-guide/BRICKS.md#node_keys-fixed) |
| [upgrades](../../docs/design-guide/BRICKS.md#upgrades) | **[`fixed`](../../docs/design-guide/BRICKS.md#upgrades-fixed)** | none: no brick of its own here | — | [`circuits`](../../docs/design-guide/BRICKS.md#upgrades-circuits), [`contract`](../../docs/design-guide/BRICKS.md#upgrades-contract) |
| always present | [Client core](../../docs/design-guide/BRICKS.md#always-present), [Generic e2e driver](../../docs/design-guide/BRICKS.md#always-present) | on every sidecar path: [BRICKS.md](../../docs/design-guide/BRICKS.md#always-present) lists what to call | — | — |
<!-- bricks:end -->

## Rounds

The circuits are under `circuits/` on `noir/pss_core`, with the pool logic in
the `amm` library (`amm/src/pool.nr`). Each has the canonical public prefix
(`namespace`, `owner`, `in_slots`, `out_slots`) and returns
`PssEffects<R, W, A>`, so it has 3 + 3R + 2W + P + A public inputs.

| Round | R | W | P | A | PIs | Reads → writes |
| --- | --- | --- | --- | --- | --- | --- |
| `pss_seed` | 0 | 1 | 0 | 0 | 5 | → seed `[s, blinding]` |
| `amm_init` | 1 | 1 | 0 | 0 | 8 | seed → pool `[reserve_x, reserve_y, blinding]` |
| `amm_swap` | 1 | 1 | 2 (`amount_in`, `direction`) | 1 (`amount_out`) | 11 | pool → pool |
| `amm_swap_total` | 1 | 1 | 2 (`amount_in`, `direction`) | 3 (`ok`, `code`, `amount_out`) | 13 | pool → pool |

`pss_seed` is the generic seed circuit (the network samples the seed and its blinding,
so nobody knows it); it nullifies nothing, takes no key and outputs 0 as
`npk_app_hash`. `amm_init` consumes the seed note and derives the starting reserves from
it (`Pool::from_seed`: each in [1 000 000, 2 000 000), so the starting price is one
nobody chose). `amm_swap` consumes the pool note, applies the trade
(`out = r_out · in / (r_in + in)`, rounded down; refused for a zero input, an output
that rounds to zero or one that drains the pool) and stores the new pool. `amount_in`
(a `u64`) and `direction` (a `bool`: false sells x for y) are public, because the
contract binds them to the trade the caller asked for.

`amm_swap_total` is the same round in total form, and it is not a package of this
example: `circuits/amm_swap_total` is a link to `examples/amm-swap-total`'s round
circuit, which already has this interface, so there is one circuit and one vk (the
comment in `circuits/circuits.env`). Its library `amm_total`, its failure codes, its
Prover cases, its lint report and why co-noir can run its hints are in
[`examples/amm-swap-total/README.md`](../amm-swap-total/README.md). On failure the round
consumes the pool note, writes the old reserves under the blinding the network sampled,
pays out 0 and reports the first failing check as a code (0 is the trade `amm_swap`
makes; 1 to 7 name the failed check). `app_outputs` is `[ok, code, amount_out]`. The e2e
driver lands the total swaps through the nodes.

### Why the total swap lives here

Both swaps read and write the same pool note under the same slot, owner, network pin
and anchor, so the total swap is one more round, one more manifest, one more vk pin in
the `Config` and one more contract function, not a second example. A separate
contract (an amm-total example) would repeat the `Config`, the anchor, the seed and
the init rounds and differ only in its swap. Both entrypoints stay open; a deployment
that wants only the total swap pins `swap_vk_hash` to 0 (the comment at the top
of `contract/amm/src/main.nr`).

## What one evaluation reveals

| Round | One evaluation reveals | CONSUME on the key it reads |
| --- | --- | --- |
| `pss_seed` | a note hash, hidden by the sampled blinding | none (reads nothing) |
| `amm_init` | the seed's leaf and nullifier and the pool's note hash; not the reserves | `once` |
| `amm_swap` | `amount_out`, which with `amount_in` gives the pool's marginal price | `once` |
| `amm_swap_total` | `ok`, `code` and `amount_out` (0 unless `ok`); see below | `once` |

- **init, `once`.** Without it the seed could be loaded again and a second pool derived
  from it.
- **swap, `once`.** Each pool state answers one swap. Two quotes solve both reserves up
  to rounding; `once` refuses two quotes against one state, but two consecutive swaps
  still reveal them, since each swap's change to the reserves is public. Hiding the
  reserves needs a coarser output or a private trade size (the `DEV DECISION:` marker in
  `amm_swap/src/main.nr`).
- **Anyone may swap.** A swap carries no state record, so the request is
  unauthenticated in the research prototype (`docs/DESIGN.md`, "The operator-run trust rule"), and the contract's `swap`
  is open to any caller. A swap the nodes commit whose transaction never lands leaves
  the pool row ahead of the chain; anyone holding the request id can FETCH the result
  and land it, and otherwise the operator rolls the round back (`docs/DESIGN.md`, "Operator procedures").
- **What the nodes' knowledge is worth.** The nodes see each swap's PUBLIC inputs and its
  outputs; two colluding nodes open the reserves, so they know the price impact of every
  swap before it lands and can trade ahead of it up to its slippage bound. No funds are at
  risk from the nodes' secrets: the user's own private function verifies the proof.

### The total swap: what one evaluation reveals

`ok` and the code are public outputs, as public as `amount_out`: they are in the
proof's public inputs, the contract reads them, and they are on chain once the swap
lands. With `amount_in` and `direction` public too, one evaluation tells everyone:

| Outcome | What it says about the pool |
| --- | --- |
| `ok = 1` | `amount_out`, as for `amm_swap`: with `amount_in`, the marginal price |
| code 1, 2 or 3 | nothing: the request alone decides them (zero amount, amount or direction out of range) |
| code 4 | `r_in >= 2^64 - amount_in`: a lower bound on the input reserve |
| code 5 | `r_out * amount_in < r_in + amount_in`: a bound on the price |
| code 6 | `r_in = 0`: the input reserve is empty |
| code 7 | a reserve in the note is not a u64 (no proven round writes one) |

- **`once` still holds.** A failed swap consumes the pool state like a trade, and the
  note it stores holds the old reserves under a new blinding, so its note hash is new
  (the re-store rule, `docs/DECISIONS.md` section 6) and each pool state answers one
  evaluation.
- **A failure leaves the reserves unchanged**, so consecutive failed swaps question the
  same reserves: code-4 probes binary-search `r_in` (about 20 for a reserve near its
  starting range, at most 64; each a committed round that consumes the state), and
  code-5 probes do the same for `r_in / (r_out - 1)`. The asserting
  `amm_swap` gives the same bit through its 422 and without consuming anything, since a
  refused request stores nothing; the total swap makes each probe a committed round,
  not a free one. Dropping the code (ok only) hides which bound failed, and leaves the
  contract unable to tell a bad request from a dust trade (the reveal comment in
  `examples/amm-swap-total/circuits/amm_swap_total/src/main.nr`).
- **The no-op must land.** The nodes commit a failed swap like a trade (its row
  replaces the pool row), so its transaction must land, or the pool row is ahead of the
  chain until someone FETCHes and lands it or the operator rolls it back; this is why
  `swap_total` checks neither `amount_in` nor `direction` and reverts on no outcome a
  valid proof can carry.

## Manifests

`manifests/` holds one manifest (intake `direct`, the default) per circuit; `python3 -I
scripts/check-manifests.py` validates them against `docs/manifest.schema.json`. The
circuits' `main.nr` files open with a comment naming each manifest's settings; the
app developer's choices among them carry a `DEV DECISION:` marker.

- **State: node-held** for every key (`"node"`), so the deployment needs a store that
  holds `values` (Postgres); a node on the local store refuses these manifests at
  REGISTER. A client-held pool would make every trader depend on the last one
  publishing the latest record.
- **Keys.** The contract passes `SEED_SLOT` (`0xa001`) and `POOL_SLOT` (`0xa002`) as
  `in_slots`/`out_slots`, and the request names the same values as `$state_keys.reads` and
  `$state_keys.writes`; `amm_swap` and `amm_swap_total` read and write `POOL_SLOT`. A request naming other keys
  gives a proof the contract rejects.
- **nsk_app** is the fixed `LOAD nsk_app` (slice [0, 1], len 1) in `amm_init`,
  `amm_swap` and `amm_swap_total`; each outputs `npk_app_hash` for the contract's pin.
- **`amm_swap_total.json`** is `amm_swap.json` with the circuit's name: the same
  witness map (its `amount_in` and `direction` are Fields, so the node's bind step
  range-checks nothing and a bad value reaches the circuit), the same pool output and
  the same `once`. Its settings are named in the comment at the top of the
  linked `main.nr`.
- **Lengths:** seed `len` 2 (slices [0, 1] and [1, 2]); pool `len` 3 (slices [0, 2] and
  [2, 3]).
- **owner** is the const `0xafafaf`, which the contract's `Config` must pin.

## Contract

`contract/amm` (`AmmPss`) has no storage and no public functions. Its `Config`
(operator, owner, `npk_app_hash` and the four vk hashes) is anchored as a raw note hash
and passed by every caller:

- `init_pool(config, seed_note_hash)`: operator only, once; applies `pss_seed` and
  anchors the `Config`;
- `start_pool(...)`: operator only; applies `amm_init` (spends the seed, creates the
  pool note);
- `swap(config, anchor_nonce, amount_in, direction, effects)`: any caller; applies
  `amm_swap` (and refuses a zero amount or a bad direction first);
- `swap_total(config, anchor_nonce, amount_in, direction, effects)`: any caller;
  applies `amm_swap_total` whatever `ok` says (the nullifier and the new pool note),
  checks the outcome encoding, and returns `SwapOutcome { ok, code, amount_out }`. A
  token transfer would go after `apply`, only when `ok`; on `ok = 0` nothing moves.

`contract/amm_test` is its TXE suite; for the total swap it lands `ok = 1` and each
code 1 to 7, spends a no-op's note with a trade, refuses the spent note again, refuses
each swap's proof at the other entrypoint, and checks the outcome encoding.

## Checks

```sh
scripts/check-noir.sh examples/amm --outputs examples/amm/circuits/outputs.txt   # compile, library tests, execute and check each Prover.toml
python3 -I scripts/check-manifests.py
scripts/txe.sh --contracts --only examples/amm/contract/amm_test   # this example's TXE suite
```

The `Prover.toml` fixtures are one scenario: seed 111 gives the pool
[1 359 373, 1 852 331]; selling 25 000 x for y pays out 33 450 and leaves
[1 384 373, 1 818 881]. `amm_swap_total`'s `Prover.toml` is the same trade (`[1, 0,
33450]`); its eight `Prover-<case>.toml` give codes 1 to 7.

The end-to-end scenario is `e2e/scenarios/amm.ts` (see `e2e/scenarios/README.md`),
which the generic driver `e2e/driver.ts` runs: it registers the four circuits, runs the pool through real proofs on a local network,
checks every refusal, rolls a swap back over the nodes' admin sockets, recovers a
dropped transaction by FETCH, and refuses `amm_swap` with a zero amount (422). It
then lands a total swap with `ok = 0` on that zero amount and one with `ok = 1` after
it.

```sh
EXPECT_REAL_PROOFS=1 e2e/run.sh amm
```
