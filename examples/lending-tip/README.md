# Lending at the tip of the chain

A lending market whose positions are private shared state held by the network. Lenders supply
the borrowed asset and earn interest; borrowers deposit collateral, borrow up to a limit below
the liquidation threshold, repay and withdraw; liquidators with a budget liquidate unhealthy
positions with a bonus, finding them through the keeper's scan. Interest accrues by time
through a borrow index and a supply index in the book's header. Requests are queued on chain
and applied in queue order ([the tip](../../docs/ARCHITECTURE.md#6-the-tip-as-an-extension)).

The book is one tree-valued node-held key
([Tree-valued keys](../../docs/ARCHITECTURE.md#tree-valued-keys)): a binary Poseidon2 Merkle
tree of depth `D = 16` whose leaf 0 is the market's header and whose other leaves are
positions. The nodes hold the leaves as Rep3 pairs and the tree of hashes in the clear; the
contract holds one commitment to the root in one public slot. A round touches the leaves it
needs, at a cost set by the depth and the probe width `K = 2`, never by the number of
positions. Every circuit is total: a request that cannot apply still proves and lands with a
nonzero code, and the queue moves on.

Every user action starts in the user's own private function, and the round does only what
needs the shared book. Ownership is a user-owned note, never a shared secret: the book records
no owner, and value reaches users as completed partial notes
([partial-note delivery](../../docs/ARCHITECTURE.md#partial-note-delivery)). A leak of all three
nodes' secrets costs privacy and can freeze funds, never take them
([invariant 0](../../docs/ARCHITECTURE.md#5-invariants)); a frozen market is exited through the
escape hatch. The blueprint is `tip-tree`; the market adds interest and the clock read, the
lender kind and the private app balance, and uses the escape hatch and the tree's per-slot
write policy. The settled choices are in [DECISIONS.md](../../docs/DECISIONS.md#13-examples).

> **How to read this example.** The contract carries every intake and both tree-access
> modes on purpose, so each option can be seen and run from one place; a deployment's
> manifests select which it uses. That is a property of the example, not a pattern to
> copy. Your app picks one intake and one access mode
> ([the design guide](../../docs/design-guide/README.md) walks the choice), and its
> contract declares only the entry points of the bricks it picked. No combination here is
> "the" way to build on private shared state.

<!-- bricks:begin -->
## Bricks this example uses

Generated from the `// BRICK` markers in this example's code and `docs/design-guide/design-space.json` (`python3 -I scripts/check-design-space.py --write-bricks`). One row per axis: the option this example plugs in, the library items it calls for it, where, and the alternatives. **Bold**: the example's as-built choice. The combination is this example's; any alternative combines with the rest as [BRICKS.md](../../docs/design-guide/BRICKS.md) says.

| Axis | This example uses | Library calls | Where in this example | Alternatives |
| --- | --- | --- | --- | --- |
| [path](../../docs/design-guide/BRICKS.md#path) | **[`tip`](../../docs/design-guide/BRICKS.md#path-tip)** | none: follows from `intake` | — | [`sidecar`](../../docs/design-guide/BRICKS.md#path-sidecar) |
| [state](../../docs/design-guide/BRICKS.md#state) | **[`node`](../../docs/design-guide/BRICKS.md#state-node)** | none: manifest only (`state`) | — | [`client`](../../docs/design-guide/BRICKS.md#state-client), [`chain`](../../docs/design-guide/BRICKS.md#state-chain) |
| [shape](../../docs/design-guide/BRICKS.md#shape) | **[`tree`](../../docs/design-guide/BRICKS.md#shape-tree)**, [`tree_oblivious`](../../docs/design-guide/BRICKS.md#shape-tree_oblivious) | `pss_core::tip::tree::slot_indices`, `pss_core::tip::tree::load`, `pss_core::tip::tree::Updated`, `pss_core::tip::tree::Oblivious`, the manifest's `tree` field | [`circuits/lending_tip/src/entry.nr`](circuits/lending_tip/src/entry.nr): `oblivious_indices`; [`circuits/lending_tip/src/rounds.nr`](circuits/lending_tip/src/rounds.nr): `book`; [`circuits/lending_tip/src/shared.nr`](circuits/lending_tip/src/shared.nr): `AppendIndex for Updated`, `AppendIndex for Oblivious`; [`contract/lending_market/src/app.nr`](contract/lending_market/src/app.nr): `RoundTable` | [`flat`](../../docs/design-guide/BRICKS.md#shape-flat), [`map_oblivious`](../../docs/design-guide/BRICKS.md#shape-map_oblivious) |
| [intake](../../docs/design-guide/BRICKS.md#intake) | [`onchain`](../../docs/design-guide/BRICKS.md#intake-onchain), [`receipt`](../../docs/design-guide/BRICKS.md#intake-receipt), **[`shared_receipt`](../../docs/design-guide/BRICKS.md#intake-shared_receipt)**, [`shared_onchain`](../../docs/design-guide/BRICKS.md#intake-shared_onchain) | `pss_core::tip::family::Plain`, `pss_core::tip::intake::SharedIntake`, `pss_public_contract::outcome_request`, `pss_public_contract::SharedOnchain`, `pss_public_contract::onchain_request`, `pss_public_contract::receipt_request`, `pss_public_contract::check_enc_rotation` | [`circuits/lending_tip/src/entry.nr`](circuits/lending_tip/src/entry.nr): `finish`; [`circuits/lending_tip/src/shared.nr`](circuits/lending_tip/src/shared.nr): `finish`; [`contract/lending_market/src/storage.nr`](contract/lending_market/src/storage.nr): `request`; [`contract/lending_tip/src/main.nr`](contract/lending_tip/src/main.nr): `Keys`, `deposit`, `deposit_with_receipts`, `rotate_enc_key` | [`direct`](../../docs/design-guide/BRICKS.md#intake-direct), [`relayed`](../../docs/design-guide/BRICKS.md#intake-relayed) |
| [binding](../../docs/design-guide/BRICKS.md#binding) | **[`turn`](../../docs/design-guide/BRICKS.md#binding-turn)** | none: manifest only (`binding`) | — | [`none`](../../docs/design-guide/BRICKS.md#binding-none), [`exact`](../../docs/design-guide/BRICKS.md#binding-exact) |
| [outputs](../../docs/design-guide/BRICKS.md#outputs) | [`public`](../../docs/design-guide/BRICKS.md#outputs-public), **[`private`](../../docs/design-guide/BRICKS.md#outputs-private)** | `pss_public_contract::result::PartialResult`, `pss_public_contract::outcome::OutcomeResult` | [`contract/lending_market/src/app.nr`](contract/lending_market/src/app.nr): `OwnerResult`, `SharedResult` | — |
| [value](../../docs/design-guide/BRICKS.md#value) | **[`partial`](../../docs/design-guide/BRICKS.md#value-partial)** | `pss_core::tip::family::Plain`, `pss_public_contract::partial_note::commit`, `pss_public_contract::partial_note::complete_in_public` | [`circuits/lending_tip/src/entry.nr`](circuits/lending_tip/src/entry.nr): `finish`; [`contract/lending_tip/src/main.nr`](contract/lending_tip/src/main.nr): `commit_plain_partial`, `apply` | [`none`](../../docs/design-guide/BRICKS.md#value-none) |
| [delivery](../../docs/design-guide/BRICKS.md#delivery) | **[`constrained`](../../docs/design-guide/BRICKS.md#delivery-constrained)** | none: follows from `outputs` | — | [`clear`](../../docs/design-guide/BRICKS.md#delivery-clear), [`node_sealed`](../../docs/design-guide/BRICKS.md#delivery-node_sealed) |
| [submission](../../docs/design-guide/BRICKS.md#submission) | **[`relayer`](../../docs/design-guide/BRICKS.md#submission-relayer)** | none: an app calls nothing of it | — | [`user`](../../docs/design-guide/BRICKS.md#submission-user) |
| [node_keys](../../docs/design-guide/BRICKS.md#node_keys) | **[`rotating`](../../docs/design-guide/BRICKS.md#node_keys-rotating)** | `pss_public_contract::KeyEpochs`, `pss_public_contract::key_epoch::check_rotation` | [`contract/lending_tip/src/main.nr`](contract/lending_tip/src/main.nr): `Keys`, `rotate_keys`; [`contract/lending_tip_oblivious/src/main.nr`](contract/lending_tip_oblivious/src/main.nr): `Keys`, `rotate_keys` | [`fixed`](../../docs/design-guide/BRICKS.md#node_keys-fixed) |
| [upgrades](../../docs/design-guide/BRICKS.md#upgrades) | **[`fixed`](../../docs/design-guide/BRICKS.md#upgrades-fixed)** | `pss_public_contract::FixedCircuits` | [`contract/lending_tip/src/main.nr`](contract/lending_tip/src/main.nr): `configured_in_force`; [`contract/lending_tip_oblivious/src/main.nr`](contract/lending_tip_oblivious/src/main.nr): `configured_in_force` | [`circuits`](../../docs/design-guide/BRICKS.md#upgrades-circuits), [`contract`](../../docs/design-guide/BRICKS.md#upgrades-contract) |
| always present | [Client core](../../docs/design-guide/BRICKS.md#always-present), [Generic e2e driver](../../docs/design-guide/BRICKS.md#always-present), [TipNamespace](../../docs/design-guide/BRICKS.md#path-tip), [Queue](../../docs/design-guide/BRICKS.md#path-tip), [Intake functions](../../docs/design-guide/BRICKS.md#path-tip), [Result](../../docs/design-guide/BRICKS.md#path-tip), [Pinned public reads](../../docs/design-guide/BRICKS.md#path-tip), [App skeleton](../../docs/design-guide/BRICKS.md#path-tip), [Configure once](../../docs/design-guide/BRICKS.md#path-tip), [Tip round helpers](../../docs/design-guide/BRICKS.md#path-tip), [IntakeModule](../../docs/design-guide/BRICKS.md#path-tip), [ResultReader](../../docs/design-guide/BRICKS.md#path-tip), [Discovery](../../docs/design-guide/BRICKS.md#path-tip), [Fee payment](../../docs/design-guide/BRICKS.md#path-tip) | on every tip path: [BRICKS.md](../../docs/design-guide/BRICKS.md#path-tip) lists what to call | — | — |
| no alternative | [Escape hatch](../../docs/design-guide/BRICKS.md#other-bricks), [Standing delivery handle](../../docs/design-guide/BRICKS.md#other-bricks), [Note ownership](../../docs/design-guide/BRICKS.md#other-bricks), [Tokens and escrow](../../docs/design-guide/BRICKS.md#other-bricks) | `pss_core::tip::exit::Tree::change_tagged`, `pss_core::tip::handle::deliver`, `pss_public_contract::handle::commit`, `pss_public_contract::partial_note::assert_owned`, `pss_public_contract::token::commit_refunds`, `pss_public_contract::hatch::Hatch::exit`, `pss_public_contract::hatch::Hatch::landed` | [`circuits/lending_tip/src/rounds.nr`](circuits/lending_tip/src/rounds.nr): `change`; [`circuits/lending_tip/src/shared.nr`](circuits/lending_tip/src/shared.nr): `deliveries`; [`contract/lending_market/src/request.nr`](contract/lending_market/src/request.nr): `with_handle`; [`contract/lending_market/src/storage.nr`](contract/lending_market/src/storage.nr): `assert_holds`, `escrow`, `exit`, `apply_shared` | — |
<!-- bricks:end -->

## The market

One pair: the **collateral asset** (`Config::collateral`) and the **borrowed asset**
(`Config::borrowed`), two reference tokens (`examples/token`) held in the market's public
balances. A deployment per pair is the generalisation. Three roles, none of them an address
anywhere on chain or at the nodes:

- a **lender** supplies the borrowed asset and holds shares of the pool; it withdraws its
  shares' value, interest included, while the pool has liquidity;
- a **borrower** deposits collateral, borrows up to the borrow limit, repays, and withdraws
  collateral while the position stays at or above the limit;
- a **liquidator** repays part of an unhealthy borrower's debt out of a budget and takes
  collateral worth the repayment plus a bonus; a **keeper** (any liquidator, or anyone) scans
  the book for unhealthy positions.

The deployer's role ends at deployment; the oracle's owner is a separate trust assumption
([Oracle](#oracle)). The protocol's revenue is the usage deposit ([Tokens](#tokens)).

Each round is one source (`circuits/lending_tip/src/rounds.nr`) with an entry per intake
family it runs under:

| Round | Who | Slots | What it does | Settlement (the completed note's payout) |
| --- | --- | --- | --- | --- |
| `deposit(position, amount)` | a borrower; `position = 0` opens | header + 1 | adds `amount` collateral | none; a failed deposit returns `amount` in the collateral asset |
| `withdraw(position, amount)` | the borrower | header + 1 | removes `amount` collateral if the position stays at or above the borrow limit at the pinned price | `amount` in the collateral asset |
| `borrow(position, amount)` | the borrower | header + 1 | adds `amount` debt if liquidity covers it and the position stays at or above the borrow limit | `amount` in the borrowed asset |
| `repay(position, amount)` | the borrower | header + 1 | reduces the accrued debt by `min(amount, debt)` | the excess over the debt, borrowed asset |
| `view(position)` | the owner | header + 1 | reports the position (either kind) after accrual; changes only the header's accrual, a borrower position brought to the current index, and the blindings | none |
| `supply(position, amount)` | a lender; `position = 0` opens | header + 1 | mints shares for `amount` of the borrowed asset | none; a failed supply returns `amount` |
| `withdraw_supply(position, shares)` | the lender | header + 1 | burns `shares` for their value if liquidity covers it | the value, borrowed asset |
| `quote()` | anyone | header | reports the borrow index, the supply index and the utilisation; changes only the header's accrual and blinding | none |
| `liquidate(p, budget)` | anyone | header + `K - 1` | liquidates the probe if unhealthy at the liquidation threshold, repaying up to `budget` | the unused budget (borrowed asset) and the seize (collateral asset) |
| `scan(start)` | anyone | header + window `W` | reports the health bit and the occupancy of each position in the window ([Keeper round](#keeper-round)) | none |

The escrow (a deposit's, repayment's or supply's `amount`, a liquidation's `budget`) is drawn
at request from the user's credit note. The owner rounds all touch two slots, so they prove
in the same time and look the same to every party; `quote` touches one, like the scan's own
slot. A liquidation writes only the probes it liquidates and notifies each liquidated owner
through the delivery handle the owner's last request left in the leaf
([Notes](#notes-ownership-the-owners-view-and-value)).

## Deployment

Three deployments run the market, each with its own package list (one intake family per
namespace):

- **The secret-shared deployment** (the default, contract `lending_tip`): the ten rounds
  under secret-shared receipt intake (`deposit_shared`, `withdraw_shared`, `borrow_shared`,
  `repay_shared`, `supply_shared`, `withdraw_supply_shared`, `view_shared`, `quote_shared`,
  `liquidate_shared`, `scan_shared`). Position indices are clear to the nodes; amounts and the
  sender's partial note are shared and bound through `C`. The outcome is private: the round
  completes the partial note inside the co-SNARK and encrypts it into a 16-field log. The round
  type is hidden. The deposit also runs under secret-shared on-chain intake
  (`deposit_shared_onchain`, [Secret-shared intake](../../docs/ARCHITECTURE.md#secret-shared-intake));
  such a request shows that it is a deposit (its DEV DECISION).
  Package list `SHARED_PACKAGES`: `lending_init`, `deposit_shared`, `borrow_shared`,
  `repay_shared`, `view_shared`, `liquidate_shared`, `scan_shared`, `withdraw_shared`,
  `supply_shared`, `withdraw_supply_shared`, `quote_shared`.
- **The non-secret-shared deployment** (contract `lending_tip`, the test path,
  [DECISIONS.md section 9](../../docs/DECISIONS.md#9-tip-intake)): the deposit alone, one
  compiled circuit (`deposit`) under on-chain intake (`deposit`, the inputs in the request log)
  and receipt intake (`deposit_with_receipts`, three node receipts, the inputs off the chain).
  The request carries the sender's partial note as a clear input (`P` hides its owner behind
  `rho`); the outputs are public, and `apply` completes the note in public (the completion log
  `[slot, code, position, mask, 0, 0, payout, 0, request_id]` under the note's completion tag),
  which the sender's PXE finds once its client hands it the request's offchain partial-note
  message (`offchain_receive`). Package list `PLAIN_PACKAGES`: `lending_init`, `deposit`.
- **The oblivious deployment** (contract `lending_tip_oblivious`, experimental): every
  position index is a shared input and the book lives in a distributed oblivious RAM
  ([The oblivious deployment](#the-oblivious-deployment)). Package list `OBLIVIOUS_PACKAGES`:
  `lending_init_oblivious`, then each round's `<round>_oblivious` in the secret-shared order.

Both contracts are thin over one library, `lending_market`
([DECISIONS.md, "Lending's two tree accesses"](../../docs/DECISIONS.md#13-examples)). Every
round makes the pinned price read and the pinned clock read.

The network also registers the deposit's artifact under `deposit_receipt.json` (the same
circuit and vk hash; the descriptor `deployments/lending-tip-plain.json` lists it with
`alias_of`), and the secret-shared deployment may register `deposit_shared`'s again under
`deposit_shared_onchain.json` (the contract manifest then states `storage.shared_onchain`, and
each node keys the contract with pss-relayer's `rotate-enc-key` before the first such request).
A function whose package the deployment does not list refuses ("package not in this
deployment").

The order follows [Deployment, configure and the init round](../../docs/ARCHITECTURE.md#deployment-configure-and-the-init-round)
(pss-client's `deployTip`): deploy the oracle (`previous_blocks` set to the market's stale
period); compile, compute the vk hashes and build the contract manifest with the oracle's
address (pss-client `buildContractManifest`); compute the market's address from a secret salt
and the constructor's `Config`; REGISTER under it; deploy; fund the market's public balance of
the borrowed asset with `init_liquidity`; `configure`; the init round (`init_market`). Until
`configure` has landed every request, init, result and `skip()` reverts.

## The book

```text
leaf 0 (the header)    [total_debt, liquidity, total_shares, borrow_index, last_accrual, next_index, 0, blinding]
borrower leaf i        [1, collateral, debt, index_at_touch, handle_partial, handle_key, exit_tag, blinding]
lender leaf i          [2, shares, 0, 0, 0, 0, exit_tag, blinding]
empty leaf             zero vector (leaf hash 0)
leaf_hash(i, leaf)     = poseidon2_with_separator([namespace, key, i, leaf...], PSS_TIP_LEAF)
commitment             = poseidon2_with_separator([namespace, key, root], PSS_TIP_TREE)
```

A leaf's first element is its kind (`market.nr` `KIND_BORROWER`, `KIND_LENDER`; 0 while
empty), written by the opening deposit or supply and never changed. A round of one kind on a
leaf of the other flags code 5; a liquidation or a scan treats a lender leaf as a position
with no debt (never unhealthy, counted as occupied). `handle_partial` and `handle_key` are the
owner's standing delivery handle ([Notes](#notes-ownership-the-owners-view-and-value)) and
`exit_tag` the exit tag of the position's newest note ([The escape hatch](#the-escape-hatch)).
The header has no `total_collateral`: no round computes on it.

The pool's value is `liquidity + total_debt`, and a lender's shares are its part of it; the
supply index is never stored. `borrow_index` and `last_accrual` are the interest's
([Interest](#interest)); a borrower leaf's `index_at_touch` is the borrow index at its last
touch, and its owner's note carries it in `mask` (never 0 for a borrower, 0 for a lender: the
kind marker). `total_debt` and `total_shares` are aggregates, never an authority over a
position: a subtraction from one saturates at 0, an addition or accrual at `2^128 - 1`, and no
round requires a total to cover a position's part.

Every written leaf takes a fresh blinding (SAMPLE, one per slot). A deposit or supply that
opens a position names position 0; the scheduler assigns the append index of the version it
computes on (`$new_leaf`; 0 when the book is full), and the round requires it to equal the
header's `next_index` (code 17) and writes it incremented (pss_core `tip::tree::append`). So
the opened positions are the prefix the keeper's scan walks even if every node were
compromised. Positions are never reclaimed and an index is never reassigned, because every
note ever completed for a position keeps authorising requests on it: `2^16 - 1` bounds the
positions a market opens over its life, and a position is not transferable.

## Rules and constants

Health and limits are decided without dividing (`market.nr` `unhealthy_accrued`,
`within_limit_at_price`), on the accrued debt ([Interest](#interest)):

```text
value(c)       = c * price / PRICE_SCALE                                         (price a u64 at scale 100)
at the limit   : collateral * price * LTV_BPS >= debt * PRICE_SCALE * BPS        (borrow, withdraw)
unhealthy      : collateral * price * LT_BPS * index_at_touch < debt * B' * PRICE_SCALE * BPS   (liquidate, scan)
```

| Constant | Default | Where used |
| --- | --- | --- |
| `LTV_BPS` | 7,500 | the borrow limit: a borrow or withdrawal must leave the position at or above it (code 9) |
| `LT_BPS` | 8,000 | the liquidation threshold: only the liquidation and the scan use it |
| `CLOSE_BPS` | 5,000 | a liquidation repays at most half the accrued debt |
| `BONUS_BPS` | 500 | the liquidator seizes collateral worth 105% of what it repays, capped at the collateral |
| `INDEX_ONE` | 10^9 | the fixed point of the borrow index and the supply index |
| `R0`, `R1`, `R2`, `U_OPT` | 0, 46, 690, 8,000 | the per-block rate model ([Interest](#interest)) |
| `CLOCK_BAND` | 128 blocks | the clock read's tolerance |
| `T_LIVE` | 20,000 blocks | the escape hatch's liveness period (`Config::t_live`) |

All but `T_LIVE` are `market.nr` constants with a DEV DECISION each; they are in every vk, so a
change is a new deployment. `T_LIVE` is a Config pin, since the contract checks it and no
circuit does. A position borrowed to the limit survives a price fall of `1 - LTV/LT` (6.25%)
before it can be liquidated.

**The liquidation** (`rounds.nr` `liquidate`), with `debt` the accrued debt: `close =
floor(debt * CLOSE_BPS / BPS)`, `repay = min(close, budget)`, `want = floor(repay *
PRICE_SCALE * (BPS + BONUS_BPS) / (price * BPS))`, `seize = min(want, collateral)`. A probe
whose repayment rounds to zero (debt 1) is skipped and keeps its debt. The budget caps the
repay probe by probe.

**Bad debt** is written off in the liquidation that leaves it. When the seize takes the whole
collateral (`want >= collateral`) and debt remains:

```text
written     = debt' - repay        when want >= collateral, else 0
debt''      = debt' - repay - written
total_debt  = sub_sat(total_debt', repay + written)       once per liquidated probe
```

`debt'` is at the accrued index and rounds up, so the write-off is never below the position's
exact residual: it errs toward a lower supply index. Liquidity grows by the repay alone. The
liquidation writes its header in the same round, so every later supply, withdrawal of supply
and quote values a share on the reduced total: the loss falls on the lenders pro rata, at
once, not on whoever withdraws last. The circuit selects between the two debts on the seize's
comparison (3 gates).

## Interest

**The model.** A borrow index `B` in the header grows with time at a rate set by the pool's
utilisation. Each borrower leaf stores its debt as of its last touch and the index at that
touch, so its accrued debt is `debt * B / index_at_touch`. The supply index is the pool's
value per share, `S = (liquidity + total_debt) * INDEX_ONE / total_shares` (`INDEX_ONE` with no
shares), so it rises as `total_debt` accrues and needs no accrual of its own.

**Accrual, once per applying round** (`market.nr` `accrue`), first, at the pinned clock `t`:

```text
dt            = max(0, t - last_accrual)
u             = floor(total_debt * BPS / (total_debt + liquidity))        (0 for an empty pool)
rate(u)       = R0 + R1 * min(u, U_OPT) / U_OPT + R2 * max(0, u - U_OPT) / (BPS - U_OPT)   per block, in 10^-9
B'            = B + ceil(B * rate(u) * dt / INDEX_ONE)                    (saturating at 2^48 - 1)
total_debt'   = ceil(total_debt * B' / B)                                 (saturating at 2^128 - 1)
last_accrual' = max(last_accrual, t)
```

The defaults give about 4% a year at the 80% kink and 64% at full utilisation, at a 36-second
block. `rate(u)` is never rounded on its own: the growth is one quotient over the rate's common
denominator. A long idle period is one large `dt`, inside the multiply-divide's operands. A round that does not apply writes nothing
and accrues nothing; the next applying round accrues the whole interval. The init seeds
`B = INDEX_ONE` and `last_accrual = 0`: no debt exists before the first accrual, which runs at
utilisation 0. A position an owner round or a liquidation writes is brought to the current
index first, `debt' = ceil(debt * B' / index_at_touch)`, `index_at_touch' = B'` (code 7 past
u128), then the round makes its change; a `view` does the same, so an owner's note always
equals its leaf.

**`last_accrual` never moves back.** The clock read admits any `t` within `CLOCK_BAND` of the
block `apply` lands in, ahead included; a later round whose `t` is below `last_accrual`
accrues nothing. So the interest the market ever accrues is bounded by the true elapsed blocks
plus `CLOCK_BAND`, once. With `last_accrual' = t`, rounds landed alternately at the top and the
bottom of the band would re-accrue the same interval without bound.

**Health on the accrued debt, without dividing.** The scan and a liquidation's decision fold
the index into the comparison (the `unhealthy` rule above): two field products and one
comparison, exact while the left product stays below the field modulus, which with
`collateral < 2^128`, `price < 2^64`, `LT_BPS < 2^13` needs `index_at_touch` (so `B`) below
2^48. Every decode of the header and of a position checks it (code 4), and the accrual
saturates `B` at `2^48 - 1` instead of passing it (about nineteen years at full utilisation
from `INDEX_ONE`), so interest stops there rather than every later round failing. A position
becomes liquidatable by interest alone, and the keeper's bits are never stale by interest.

**The rounding rule.** Every quotient goes through `mul_div_wide` (total's fused u128
multiply-divide) and rounds toward zero, except a debt brought to the current index and the
accrual, which round up. So interest never rounds in the borrower's favour, and shares minted
and value withdrawn round in the pool's favour. `total_debt` gains at most one unit per
accrual and each position's debt at most one per touch, so the totals drift from the sum of
the positions by dust that the last lender finds or leaves. An accrual that would exceed u128
saturates rather than flags, since a flag would fail every later round and freeze the market.

**The clock** is the L2 block number, read by a pinned public read like the price: the
market's own `clock()` view returning `context.block_number()`, under `tolerance {absolute:
CLOCK_BAND}` ([Pinned reads](../../docs/ARCHITECTURE.md#pinned-reads)); the manifests name it
`"contract": "$self"`. The read is on the market, not the oracle, so the oracle's owner cannot
move time. The orchestrator chooses the clock within the band and the sequencer chooses the
block, so between them they can shift up to `rate * CLOCK_BAND` of interest between adjacent
rounds' parties and bring forward at most `CLOCK_BAND` blocks of interest in total, once.

**Supply and withdrawal of supply.** `supply(amount)` mints `shares = floor(amount *
total_shares / (liquidity + total_debt))`, or `amount` when `total_shares = 0`;
`withdraw_supply(shares)` pays `value = floor(shares * (liquidity + total_debt) /
total_shares)` if `value <= liquidity` (code 8) and `shares` does not exceed the leaf's (code
18). A zero quotient either way is code 20. The init's
`init_liquidity` is protocol-owned liquidity with as many shares, never withdrawable; a
realistic deployment sets it to 0, and the e2e keeps a seed so the first borrow has liquidity.

**Withdrawal, borrow and repayment.** `withdraw(amount)` requires `amount <= collateral` (code
19) and the limit after it (code 9); a withdrawal from a position without debt needs no price.
`borrow` requires liquidity (code 8) and the limit after the new debt (code 9). `repay(amount)`
repays `min(amount, debt')` and returns the excess, so "repay everything" works without knowing
the accrued debt to the unit.

## Oracle

`LendingOracle` holds one price, a u64 at scale 100 (`250` is 2.50), published in epochs, and
its owner. `constructor(owner, price, epoch_blocks, previous_blocks)` opens epoch 1;
`set_price(price)` (owner only) opens the next epoch, keeping the old price as `previous`, and
refuses while the current epoch is younger than `epoch_blocks` ("the price epoch is younger
than epoch_blocks"; 0: no minimum). `get_price_epoch()` returns `[price, epoch, previous]`, the
pinned read's target; `previous` reads as the current price once the epoch is more than
`previous_blocks` old (a DEV DECISION, default the market's stale period). `get_price()` and
`get_owner()` are views.

Every round reads it under `epoch` freshness: `apply` accepts the current epoch and price, or
the epoch before and its price while `previous` is still offered. A round that lands after two
new epochs reverts ("pinned epoch too old"), and one at a price the epoch never had ("pinned
read changed"); either is recomputed, a deposit or a repayment included. The window bounds the
network's choice between two prices to `previous_blocks` after each new price. The oracle
refuses no price: the circuits answer a zero or over-wide price with code 6.

It is a stand-in. A real source is a public contract fed by a signed feed (Pyth- or
Chainlink-style, signatures verified in public, epochs no closer than `epoch_blocks`) or an
on-chain AMM's time-weighted average; either keeps the read's shape and changes nothing in
the rounds. Either way whoever controls the feed controls every liquidation, a funds risk
outside the nodes' secrets and outside invariant 0.

## What is a note, what is shared

The test for each value: does any round need it together with another user's value, or must
a liquidator or keeper probe it? If not, it is a note.

| Value | Where | Why |
| --- | --- | --- |
| who owns a position | the owner's completed notes, proven in its private function | nothing the nodes hold may authorise a move; the leaf has no owner element |
| the owner's view: collateral, debt, index at touch; a lender's shares and their value | the owner's latest completed note | refreshed by the owner's next round or a `view` |
| a payout, a failed round's returned escrow | the completed note's `payout` and `x`; `redeem` credits it | only the owner sees the amount |
| a user's balance, its escrows and usage deposits, their refunds | the user's `Credit` notes and two refund notes per request | no value waits on a round, and no request shows a class or an amount |
| the market's aggregates | PSS: the header leaf | every round computes on them |
| each borrower's `[collateral, debt, index_at_touch]` | PSS: a leaf | a liquidator probes it, a keeper scans it, and it is the authority over the owner's stale view |
| each lender's `shares` | PSS: a leaf | below |
| the price, the clock | public, pinned per round | public by nature |
| the clear tree of leaf hashes | the nodes; new hashes reach the relayer and FETCH readers, the chain holds the commitment | hashes hide the leaves |

**Lenders' shares: a leaf, not a note.** A lender's share count changes only when it acts, so
a share note would never be stale and could be the authority, with no lender leaf for two
colluding nodes to read. The escape hatch decides for the leaf: a lender's exit must pay at
most what it is owed and at most once, and the leaf's exit tag gives both, where share notes
alone would need the frozen header to price the shares and a nullifier over notes the lender
may have split and merged. A lender leaf costs what a borrower leaf costs and is the authority
in the same way (two requests from one note land in queue order, the second failing code 18).
Two colluding nodes learn a lender's shares as they learn a borrower's collateral.

## Requests and rounds

Each round has one private request function per contract, under the same name on both, each
one call of `LendingStorage::request` (`contract/lending_market/src/storage.nr`). It commits
`P` and pushes its use nullifier, asserts the round's static validity over the plaintext,
proves that the sharing opens `C`, checks the receipts and enqueues the one public wrapper
`append_receipt(request_id, expiry_block, refunds)`
([Secret-shared intake](../../docs/ARCHITECTURE.md#secret-shared-intake)); `owner` and
`msg_sender` enter nothing public. The escrow and the
usage deposit are drawn from one credit note ([Tokens](#tokens)); a user whose credit does not
cover them reverts before anything is queued.

| Round | Reads and proves privately | Draws from credit |
| --- | --- | --- |
| `deposit` or `supply` opening | nothing: anyone may open | `amount` (collateral, or borrowed) |
| `deposit`, `withdraw`, `borrow`, `repay`, `view` | the owner's note of the position (`assert_holds`), a borrower note; hints that save a wasted round (`amount <= note.collateral` for a withdrawal) | repay: `amount` |
| `supply` into a leaf, `withdraw_supply` | the owner's lender note; `shares <= note.shares` (exact: a lender note is never stale) | supply: `amount` |
| `quote`, `scan` | nothing | the usage deposit only |
| `liquidate` | nothing | `budget` |
| `redeem(request_id)` | the owner's note of that request; the redeem nullifier | nothing; credits the settlement |
| `exit(position, request_id)` | the sender's newest note of the position; the hatch open at the anchor block | a borrower's debt `y` |

Every request also pays the usage deposit and commits two refund notes. The note read is
aztec-nr's `get_notes` with its inclusion check (thousands of gates in the user's circuit). No
note is nullified by a request: every completed note of a position proves its ownership for
as long as the book lives, so a skipped request costs the owner nothing. Because a position
note is a standard note of the market, the owner can also prove facts about it (`collateral >=
X`) to another contract through a private call, with the caveat that it is the position as of
the owner's last round; the example adds no such function.

The round sees the clear position index, `C`, the price and the clock, and the shared amount
(or `shares`, or `budget`), `P`, `$outcome_key`, `$outcome_tag` and `$blinding`. It checks that
`C` opens (code 14) and that the leaf is of its kind (code 5), accrues the header and the
position, applies the rule, writes the header and the leaf with fresh blindings, and reports
the position after the round and the settlement in the completed note. Nothing it holds
authorises anything: a request reaches it only through a private function that proved
ownership, and its outputs land only with the proof.

## Notes: ownership, the owner's view and value

Every round completes the request's partial note into a lending note, the contract's
`LendingOutcome` (a `#[custom_note]` at `outcome_notes`, slot `OUTCOME_SLOT` = 1): the outcome
`[code, position, mask, x, y, payout, aux]` and the chain request id, eight packed fields. One
note type serves every round, so what a note confers is in its fields
([Circuits](#circuits) has each field by round).

- **Ownership: the naming rule.** A note with `position != 0` is an owner note of that
  position. A round names a position exactly when it vouches for the requester's leaf: the
  request named an open leaf of the round's kind (the shares opened `C`, the placement held),
  or the round opened the leaf. So a borrow refused at the limit (9) or for liquidity (8), or a
  repayment refused for overflow (7), still returns a current view, because the private
  function proved the requester owns the leaf. A note reports `position = 0` on code 14, 3, 4
  and 5, and on every failed opening (16, 17, or 1 and 2): an opening that fails writes no
  leaf, and a note naming `$new_leaf` would let its holder act on whoever opens that index
  next, since notes are never nullified. The round names the index the tagged write wrote
  (`Step::named`), so a note names a position only where its leaf holds the note's exit tag.
  Every request on an open position first reads one of the sender's notes that names it
  (`assert_holds`: owner `msg_sender`, never nullified) and checks its kind as a hint; the
  circuit's code 5 is the backstop. An opening, a liquidation, a scan and a quote are open to
  anyone.
- **The owner's view.** An owner round's note that names its position reports a borrower's
  collateral `x` and debt `y`, or a lender's shares `x` and their value `y`. Any note of the
  position, an older one included, still opens a request: the leaf is the authority, and the
  round's checks hold at its turn.
- **The liquidated owner's notice** (the standing delivery handle: pss_core `tip::handle`,
  pss_public_contract `handle`;
  [The standing delivery handle](../../docs/ARCHITECTURE.md#the-standing-delivery-handle)).
  Every request on a borrower position (`deposit_shared`, `deposit_shared_onchain`,
  `withdraw_shared`, `borrow_shared`, `repay_shared`, `view_shared`, on both contracts) takes
  `handle_rho` and `handle_key` and commits the owner's next handle in `C` after the app inputs:
  `handle_partial = handle::commit(msg_sender, handle_rho)` and `handle_key` (pss-client
  `SecretStore.handle`). The round writes them into the leaf's places 4 and 5 (`P_HANDLE`) on
  every outcome that writes or re-blinds a borrower leaf. Every liquidation that writes a probe
  completes the handle with `[0, position, index_at_touch, collateral, debt, 0, 0]` after the
  liquidation (shared.nr `deliveries`): an owner note that pays nothing, encrypted to the
  handle's key and logged under `poseidon2([handle_key, PSS_HANDLE_TAG, request_id])`, the
  liquidation's chain request id. The probe keeps the handle and stores the notice's exit tag,
  so the notice is the position's newest note and a later liquidation notifies the owner again
  under another tag. Every other round outputs a filler of the same shape. The owner learns of
  a liquidation from its newest note's spent exit tag, reads the notice in the transaction that
  spent it (pss-client `exitTagSpender`, `DeliveryReader.readIn(keys, tx)`; the walk is
  `recoverExitNote`) and hands it to `deliver_outcome` under `handle_rho`. Lender rounds carry
  no handle. Cost: the liquidation 780 gates, every other round 536 (the
  filler) to 628 (the filler and the handle in `C`).
- **Value.** `redeem(request_id)` spends a note's settlement once: it pushes the note's redeem
  nullifier, so the note stays readable and keeps conferring its position, and credits
  `payout`'s amount in the asset its bit names and, for a note that names no position, `x` in
  the collateral asset (`LendingOutcome::settlement`) to a credit note of the owner's. A note
  that pays nothing is refused.

A user who loses its local state rescans its request secrets (pss-client `SecretStore`) and
finds its notes again: the opening's note names the assigned index, and every later note of
the position names it.

## Tokens

Two tokens held in the market's public balances (pss_public_contract `token`;
[Tokens and escrow](../../docs/ARCHITECTURE.md#tokens-and-escrow)); each user's claim on them is
a private balance of the market, its credit notes (`app::Credit`, both assets in one note,
hash `compute_note_hash(slot, [partial_commitment_with(owner, randomness, [collateral,
borrowed]), request_id])`). The token is `examples/token`, aztec-nr v6.0.0's reference token.
The init refuses while the public balance of the borrowed asset holds less than
`init_liquidity` ("the seeded liquidity is not in the public balance"), and `fund` refuses
before the init, so no user's credit stands in for the seed.

- **Funding.** `fund(collateral, borrowed, nonces)` moves tokens from the sender's private
  balances into the market's (under its authwits) and credits it one note for both, in a
  transaction of its own: its amounts are public and linked to no request.
- **In, at request.** Every request draws the usage deposit (`Config::deposit`, in the borrowed
  asset) and its escrow from one credit note (`escrow`), inserts the change and commits two
  refund notes, the escrow's and the deposit's, whose commitments bind their amounts
  (`token::commit_refunds`, randomness derived from the request's `rho`). The public wrapper
  records the two commitments by queue index (`refunds_at(index)`): no token call, no amount,
  the same for every round type. No round reads a refund note, so none is in `C`.
- **Settled by the round.** `payout = amount + 2^128 * asset` (asset 0 the borrowed asset, 1 the
  collateral asset; `market.nr` `payout`). A borrow pays its amount; a withdrawal its amount in
  collateral; a repayment its excess; a liquidation its seize (`x`) and unused budget
  (`payout`); every refund of a round that does not apply travels in `payout`.
- **The inputs-opened bit.** A round whose shares do not open `C` (code 14) cannot settle its
  escrow in a note: the note's owner comes from those shares. Every secret-shared round outputs
  `opened` as its last app value; `apply_shared` completes the escrow's refund note when it is
  0, and the usage deposit's too, since the round served nobody (`token::settle_applied`'s
  `served`). Only nodes that change their shares make such a round; no amount or class leaks.
- **Refunds by public functions.** `skip()` completes both refund notes of a skipped request
  with the request id as the only public field and no token call; the non-secret-shared
  deposit's `apply` completes the escrow's when the deposit does not apply. The request
  delivers both refund notes' messages and its change note on chain, so a client restored from
  its keys alone finds each pending refund (the DEV DECISION on `escrow`).
- **Out.** `withdraw_funds(collateral, borrowed)` spends one credit note, returns the change and
  pays token notes (amounts public, owner hidden) within `borrowed + kept <= balance`;
  `merge_credits()` folds up to four notes into one; `credit_balance(owner, asset)` is the
  client's read.
- **The usage deposit** is kept on every round that serves its request (`kept = true`, the DEV
  DECISION on `Config::deposit`; `get_kept_deposits()`), refunded on skip and on a code-14
  round, and paid to the Config's `treasury` by `sweep_deposits()`, which anyone may call,
  within `kept <= balance`. It pays the network: the nodes, the orchestrator, the relayer and
  the price feed, from the market's own usage in its own asset.

## Keeper round

Nobody sees a position in the clear, so liquidators sweep, and many keepers sweeping at once
is the intended market: whoever's liquidation reaches the head first takes the bonus
([DECISIONS.md section 7](../../docs/DECISIONS.md#7-tip-state)). Probing alone costs about
`2^D / (K - 1)` rounds per pass (65,536). The keeper round `scan_shared` is the brick
[A read-only window on a tree key](../../docs/ARCHITECTURE.md#a-read-only-window-on-a-tree-key)
used for health, with `liquidate_shared` as its act round.

**The round.** `scan(start)` under secret-shared receipt intake, by anyone: it reads the window
of `W = 8` consecutive positions from `start` (below `2^D` and a multiple of `W`: the request
function checks both, and the nodes range-check `start` at the receipt route) from the nodes' own leaves inside the MPC,
binds them to the book through the window's old leaf hashes and the `D - 3` siblings of its
subtree root (the manifest's `window`), checks each leaf's collateral and debt as u128 and its
index at touch below 2^48, and evaluates `unhealthy_accrued` at the pinned price on the accrued
debt. Bit `j` of `report` is set when position `start + j` is unhealthy; `occupied` counts the
window's opened positions (a lender's counts, and is never unhealthy; index 0, the header,
counts for neither). The outcome `[code, 0, report, 0, start, 0, occupied]` completes the
keeper's partial note and pays nothing. The round re-blinds the header (about 3,700 gates, the
price of the hidden round type) and writes nothing else. Codes: 14, 3 (`start` out of range or
unaligned), 4 (the nodes' window, or a leaf not u128s), 6 (no price).

**Report, then liquidate.** The keeper's loop is pss-client's `keeperPass` (`src/keeper.ts`):
it advances `start` by `W`, hands each window's unhealthy indices to `liquidate_shared`, one
per round (`K = 2`), and stops at the first window that is not full (`W` occupied, `W - 1` in
window 0), since positions are appended and never reclaimed: a pass over `n` positions is about
`ceil(n / W)` rounds (125 at `n = 1,000`, at most 8,192). Liquidating inside the scan would
cost a liquidate round on top of the scan's and need a funded keeper. A position made healthy
before the liquidation's turn lands `ok` with a 0 bit (`binding: turn`). `start` is the keeper's choice: the lottery is the
mechanism, and a keeper that favours a region only lowers its own odds elsewhere. A scan costs
a usage deposit and a queue turn like every request.

**Cost.** 15,795 gates, 589 under the 2^14 bound: a fixed part every round pays, the header
slot, and per window leaf its hash, its health check, a 48-bit check and the report and
occupancy bits (about 540 marginal per leaf, 810 per position with the fixed part amortised).
`W = 16` would not fit.

**What it leaks.** To the keeper: `W` health bits at the pinned price and the window's
occupancy (the book's size to within `W`). The bit is the one a liquidation probe reveals, and
a full pass by either route reveals the same set; repeated scans across price epochs bracket a
position's collateral-to-debt ratio, which is inherent to any health bit. The report is
private to the keeper: a public report would hand the list to every liquidator at once. No
degree of unhealthiness, amount or owner leaks.

## The escape hatch

If the network vanishes, owners exit without it, on every deployment. Three absent or
compromised nodes freeze the book: every head is skipped and every escrow comes back through
`skip()`, but collateral and supply sit in the contract with no round to release them. The
market uses the library's brick ([The escape hatch](../../docs/ARCHITECTURE.md#the-escape-hatch):
the clock, the opening, the exit tag and its rules, finding the newest note, who can compute a
tag) through pss_core `tip::exit`, pss_public_contract `hatch` and pss-client `hatch.ts`. What
lending does with it:

**The exit tag at place 6.** Every position leaf holds its exit tag at `market.nr`
`P_EXIT_TAG` (the header holds 0). Every secret-shared round writes the book with pss_core's
tagged write (`Tree::change_tagged` from `rounds.nr` `Step::change`), storing
`exit_tag(P_k, request_id, position)` where `P_k` is the partial commitment of the note the
round issues for that position (shared.nr `issued_partials`): the requester's `P` for an owner
round's position; for a probe a liquidation writes, the partial commitment of the handle the
leaf holds (the notice's tag), or the delivery's seed for a leaf with no handle, which no note
opens. The round outputs `EXIT_TAGS = PROBES - 1 = 1` exit value, first among its app values,
and `apply_shared` passes it to `Hatch::landed`. So the one unspent tag of a position is its
newest note's: the note of the owner's last round, or the notice of the last liquidation after
it. The tag fills a place a leaf otherwise leaves 0, so it costs no leaf-hash permutation.

**The liquidation's write rule.** A round that re-blinded every leaf it holds would write a
probe it found healthy and spend its exit tag; for a leaf with no handle no note would hold the
new tag, so anyone could, for a usage deposit per round, take an owner's exit away. So a
liquidation writes exactly the probes it liquidates: the tagged write takes the write policy
per slot (`rounds.nr` `probe_policy`), and unliquidated probes keep their tags. A probe left
unwritten keeps its old hash in `new_hashes`, so one node, which already sees the probe's
index, learns it was healthy at the pinned price; the liquidator learns that bit anyway. Owner
rounds re-blind the position they name on every outcome, except code 14, whose position is an
unbound witness: such a round writes no position slot and re-blinds the header alone (the
brick's rule 4, with `opened` as the tagged write's flag).

**The non-secret-shared deployment.** Its deposit writes through `Tree::update`: its leaves hold
no tag, its `apply` calls `Hatch::landed` with no tags, and its notes report no amounts, so
`exit` refuses them ("the note has nothing to exit"). It still has the clock, `poke()` and
`open_hatch()`. `Config::assert_valid` refuses the non-secret-shared deposit beside a
secret-shared round ("the plain deposit is listed beside a secret-shared round").

**The trigger.** The market is frozen once it has starved for `T_LIVE` blocks: demand and no
landed round that served its request since. Every request wrapper and `poke()` call
`Hatch::queued`, `apply` and `apply_shared` call `Hatch::landed`, and `open_hatch()` calls
`Hatch::open`; `apply_init` does not touch the clock. Once open, `poke()` refuses ("the app is
frozen: the escape hatch is open") and a market that comes back is a new deployment. A keeper's
scan within `T_LIVE` keeps a quiet market open. A count of consecutive skips is not the trigger: skips need only the
relayer to withhold, and a few hours of relayer outage would close the market for good.
`get_hatch()` is the keeper-side read (pss-client `hatchReady`).

**The exit rule.** `exit(position, request_id)` is a private function with no public call. It
reads the sender's note of that position and request ("the sender holds no note of this
position and request"), refuses a note that pays nothing, and calls `Hatch::exit` with
`LendingOutcome` as its `ExitNote`. It succeeds once, and only on the position's newest note;
the request id picks the note (a self-liquidator holds its liquidation's note and the notice).
What the note is owed is credited to the sender's credit note (`app.nr` `exit_amounts`):

- a **borrower** repays its note's debt `y` from its credit and is credited its collateral `x`;
- a **lender** is credited its note's value `y`.

Interest since each party's last round is neither charged nor paid: the index at the freeze is
in the frozen header, which nobody can open. An exit moves no token, and `withdraw_funds` pays
within `balance - kept`. No public total separates the book's custody from the credits, so a
book that cannot pay its exits (interest since last rounds, debt nobody exited, a lender's note
newer than a borrower's) is paid from other users' credits and falls on whoever withdraws
credit last. The exit transaction shows the tag's nullifier, a credit's nullifier when it
repays a debt, a note hash and an on-chain message: no position, no amount.

**Residuals.** An owner round refused on the leaf's own state or kind (codes 4 and 5) re-blinds
the leaf and names no position, so the owner's earlier note does not exit until its next round;
only the owner's own request can do this, and the note check stops the kind case before it is
queued. No public log says a round touched a position: an owner learns it from its notice or
its tag. A borrower who never exits leaves its debt to the lenders who withdraw last.

## Invariant 0 and leakage

The adversary holds every node's secrets and stores, the orchestrator and the relayer
([DESIGN.md, "The trust boundary"](../../docs/DESIGN.md#the-trust-boundary)): it opens every
shared value, proves any pinned circuit on any inputs and withholds, but cannot change what a
pinned circuit computes or make a user's note or nullifier.

| Round | What the adversary can do | Funds |
| --- | --- | --- |
| any owner round | nothing on anyone's position: the private function required the owner's note; a fabricated request has no queue entry; a result lands only for `requests[head]`, whose `C` the owner fixed; the note's owner is fixed by `P` | none |
| liquidate | with every leaf in the clear, liquidate first every unhealthy position (the liquidation edge), paying deposit and budget like anyone; never a healthy position, never more than the rule gives | none |
| scan, quote, an opening | learn what it already knows; it cannot open at a gap (the circuit enforces `next_index`) | none |
| interest, the price | choose the clock within `CLOCK_BAND` and, for `previous_blocks` after a new price, either of two prices | bounded by the bands ([Interest](#interest), [Oracle](#oracle)) |
| the result | refuse, withhold, skip every head | none: `skip()` refunds; a frozen book exits through the hatch |
| code 14 | force it on any request | none: `apply` refunds escrow and deposit, and the round writes no position |
| `redeem`, `exit`, `sweep_deposits`, `withdraw_funds` | nothing: user notes, `msg_sender` and a Config pin, no node signature | none |

Who sees what, under secret-shared receipt intake with the private app balance and the hatch
(the general picture: [DESIGN.md, "Who sees what"](../../docs/DESIGN.md#who-sees-what)):

| Party | Sees | What the knowledge is worth |
| --- | --- | --- |
| one node | the position index of each request and a scan's `start`, `C`, the round type, the leaves a round touches, the commitments and leaf hashes, its own pair of every shared value, whether a liquidation wrote its probe; never an amount, an owner, `P` or an outcome | which positions are active and how often (an index links a position's requests); one health bit per liquidation attempt |
| two colluding nodes, or all three | every shared value: every amount, every leaf, the header, `P`, the outcome keys and outcomes, every handle and so every exit tag (which landing replaced which leaf, which position an exit left); never the owner behind `P` | the liquidation edge; the rate path and utilisation; a user's amounts before they are queued |
| the orchestrator | the user's network address beside `C` and the request id | who acts and when, by address (a relay or mixnet hides it) |
| the relayer, a FETCH reader | the queue and each result's public inputs: `vk_hash`, ciphertext, new leaf hashes (an unwritten probe keeps an earlier hash), commitments, price, clock, exit value | only whether a liquidation wrote its probe |
| the liquidator | its mask; for a probe with no handle, the exit tag its liquidation stores (from its own seed), so it recognises the landing that next writes that position | when that position is next written; it cannot spend the tag |
| the keeper | `W` health bits and the occupancy per scan | the opportunity for one queue turn |
| the world | requests joined and resolved, all with the same effects; per result a commitment, two note hashes, two 16-field logs and one exit value; the price and clock; timing; a fund's and a withdrawal's amounts, unlinked; an exit as one nullifier, a credit note and a message | when rounds land; never which position a round wrote or an exit left, nor who holds what |

Not hidden, a stated residual: timing (proving time differs by circuit) and whether a redeem
follows. Someone watching the pool who sees two landings of one request sees whether the exit
value changed between them, which happens only when a liquidation's probe changed health with
the price.

## What the world learns per round type

`lending_tip_test/src/test_round_shape.nr` runs a deposit, a borrow, a repayment, a view, a
liquidation, a withdrawal, a supply, a withdrawal of supply and a quote on the secret-shared
deployment and compares what each transaction shows
([What the world learns: not the round type](../../docs/ARCHITECTURE.md#what-the-world-learns-not-the-round-type)):

| Seen by the world | Request | Result | Redeem |
|---|---|---|---|
| Public call | `append_receipt(request_id, expiry_block, refunds)`, one shape, no amount | `apply_shared(apply, opened, tags)`: request id, old and new commitment, price, epoch, clock, the inputs-opened bit and the exit value (8 fields) | none |
| Token calls | none | none | none (`withdraw_funds`, the user's own transaction, pays tokens) |
| Pinned reads | none | the oracle's `get_price_epoch()` and the market's `clock()` | none |
| Note hashes, nullifiers, private logs | the partial note's use nullifier, one credit note spent and its change, two refund notes (their messages and the change's on chain); an owner request also reads a note (nothing public) | 2 note hashes (the outcome and the delivery), the transaction's nullifier and the exit value's, 2 private logs of 16 fields | the redeem nullifier and the credit note |
| Public data writes | the queue's and the refund record | the same on every round type | only the fee payer's balance |
| Public logs, L2-to-L1 messages | none | none | none |

Every round type's request uses the same gas, and so does every result and every redeem: the
tip e2e measures every transaction kind with real proofs, and its table is
[Gas per transaction kind](../../e2e/scenarios/README.md#gas-per-transaction-kind). The gas
settings are one per transaction kind (`LENDING_TIP_FEE_SETTING` in
`e2e/harness/fee-settings.ts`), never estimated per transaction.

## Circuits

Under `circuits/`, on `noir/pss_core` and total-noir's `total`.

- `lending_tip`, the library. `market.nr`: the layout, the capacity (`DEPTH`, `PROBES`,
  `WINDOW`), the constants, the codes, the payout's asset bit, the accrual, the debt at the
  current index, the health test. `rounds.nr`: the ten rounds over the loaded tree as steps,
  each step's write (`Step::change`), the non-secret-shared outputs, the init's book.
  `shared.nr`: the book's two accesses (`Book`) and the secret-shared finisher over pss_core's
  `SharedIntake` (the `C` check, the tagged writes, the exit values, the private outcome, the
  inputs-opened bit, the deliveries). `entry.nr`: one entry per round, generic over the main's
  entry (`Plain`, `Clear`, `Oblivious`, `Opening`).
- `lending_init`, not queued: the empty tree with the header `[0, liquidity, liquidity,
  INDEX_ONE, 0, 1, 0, r_new]`.
- One total main per round and intake family: `deposit` (the non-secret-shared deposit, which
  echoes the partial note for apply's public completion) and the ten `<round>_shared`
  ([The market](#the-market)); `deposit_shared` serves both secret-shared intakes.

Each main is its ABI and one call into `lending_tip::entry`. The entry loads the book's slots
(`rounds::book` over `tip::tree::load`: the leaves, their old hashes, their `D` siblings and the
effective indices), runs the round, hands the stored leaves to the machine
(`TACEO_store("out0")`) and outputs its layout. The non-secret-shared deposit outputs
`[request_id, old_c, new_c, npk_app_hash, ok, partial_note, code, position, mask, payout,
new_hashes[2]]` (`OwnerNoteOutputs`); on `ok = 0` nothing is written.

A secret-shared main (`shared.nr` `finish`) checks `C` first (code 14), then writes the step
with `Tree::update_private_tagged` under the step's write policy (`Step::reblind`): every
outcome re-blinds the header and an owner round's position, so the new commitment and leaf
hashes tell nothing of `ok`; a liquidation writes a probe only when it liquidates it. A
placement failure (codes 3, 15, 16, and the nodes' data under 4), which the nodes can tell from
public data, writes nothing, and a failed opening leaves its slot empty. The round then seals
the outcome under `$outcome_key` and outputs pss_core's `Valued`: the new leaf hashes, the app
values (the exit value, the append index, 0 on a clear deployment, and `opened` last), then the
delivery. The note hash is `poseidon2_hash_with_separator([OUTCOME_SLOT, P, outcome...,
request_id], DOM_SEP__NOTE_HASH)`.

Public inputs, in ACIR order (`price`, `price_epoch` the epoch read's pinned values, `clock` the
clock read's; the app inputs and `user_nonce` are private witnesses, and the round outputs the
chain request id over them, so one compiled circuit serves both non-secret-shared intakes):

| Circuit | Public inputs |
| --- | --- |
| `lending_init` (8) | `namespace, vk_hash, out_slots[0], request_id, old_c (= 0), new_c, npk_app_hash, new_hashes[0]` |
| `deposit` (19) | `namespace, vk_hash, in_slots[0], out_slots[0], price, price_epoch, clock, request_id, old_c, new_c, npk_app_hash, ok, partial_note, code, position, mask, payout, new_hashes[0..2]` |
| the secret-shared owner rounds and `liquidate_shared` (38) | `namespace, vk_hash, in_slots[0], out_slots[0], price, price_epoch, clock, request_id, machine_request_id, old_commitments[0], new_commitments[0], npk_app_hash, new_hashes[0..2], outcome_tag, note_hashes[0], ciphertext[0..8], app_values[0..3], tag, delivery_note_hash, delivery_ciphertext[0..9]` |
| `quote_shared`, `scan_shared` (36) | as above with `new_hashes[0..1]` (the header's) and `app_values[0..2]` (the exit value, then `opened`) |

A secret-shared entry takes, in `C`'s order, the clear indices (`position`, or `p1, count`, or
`start`; a quote none), the shared amount (`shares` for a withdrawal of supply, `budget` for a
liquidation; none for a view, a quote, a scan), the handle where the round has one,
`$partial_note`, `$outcome_key`, `$outcome_tag`, then `$blinding`; `C` (`$inputs_hash`) is a
private witness. The non-secret-shared deposit's app inputs are `position, amount,
partial_note` (PUBLIC `$partial_note`).

The outcome, `OUTCOME_FIELDS = 7`, one shape for every round type:

| Field | owner round, borrower leaf | owner round, lender leaf | liquidate | scan | quote |
| --- | --- | --- | --- | --- | --- |
| `code` | 0 or the first failing check | same | same | same | same |
| `position` | `i` when the round vouches for the leaf, else 0 | same | 0 | 0 | 0 |
| `mask` | `index_at_touch` (never 0) | 0 | bit `k - 1` set when probe `k` was liquidated | the report | `borrow_index` |
| `x` | collateral (0 when `position = 0`) | shares | the seize (collateral) | 0 | 0 |
| `y` | debt | the shares' value | the repay | `start` | `supply_index` |
| `payout` | `amount + 2^128 * asset`: a borrow's amount (0), a withdrawal's (1), a repayment's excess (0), a failed round's returned escrow | a withdraw_supply's value or a failed supply's amount (0) | the unused budget (0) | 0 | 0 |
| `aux` | 0 | 0 | 0 | occupied | utilisation (bps) |

`redeem` pays `x` only when the note names no position, so a note that names none keeps its
counts and rates out of `x`: the circuits build every report through `rounds::Report`, whose
only constructor with no position and an `x` is the liquidation's. The non-secret-shared
deposit's note is `[code, position, mask, 0, 0, payout, 0]`.

Amounts, collateral, debt, totals and liquidity are u128; the price a nonzero u64 at scale 100.
Health over the field stays below 2^253 and the limit test below 2^197, so both are exact. Every
division goes through `mul_div_wide` (`mul_div_wide_to_or::<135>`); the rounds use total entries
whose hints co-noir runs (`to_u128_or`, `TotalArith`'s `add_or` and `sub_or`, `clamp_bits_or`,
`fits_bits`).

Codes (`market.nr` has the table and the order; each round's doc comment in `rounds.nr` gives
its own), first failure wins:

| Code | Meaning |
| --- | --- |
| 1, 2 | the amount (budget) is not a u128, or zero |
| 3 | a position not below 2^16, position 0 outside an opening, a liquidation count outside `1 .. K - 1`, or a scan's `start` out of range or unaligned |
| 4 | the loaded state is not well formed (a borrow index not in `1 .. 2^48 - 1`, a last accrual not a u32, an index at touch not below 2^48) or the nodes' paths and indices are not the request's |
| 5 | the position is not of the round's kind (a backstop: the note check keeps an honest request from it) |
| 6 | the price is zero or not a u64 |
| 7 | a result overflows u128 (a borrower's debt at the current index, never a total), or a multiply-divide refuses |
| 8 | liquidity below the amount (a withdrawal of supply: its value) |
| 9 | the borrow or withdrawal would leave the position below the borrow limit |
| 14 | a secret-shared request's shares do not open its `C` (checked first) |
| 15 | a position named twice (needs `K > 2`) |
| 16 | the book is full |
| 17 | an opening's `$new_leaf` is not the header's append index (after 4, before 5; not a placement failure, so the header is re-blinded and the leaf stays empty) |
| 18 | shares above the lender's |
| 19 | a withdrawal above the collateral |
| 20 | a supply's shares or a withdrawal of supply's value rounds to zero |

11 (healthy) and 12 (repayment rounds to zero, or the budget is spent) are a probe's skips,
reported in the mask, never a round's code; 10 and 13 are reserved. The library checks static
validity at intake (codes 1, 2, 3 and 15); 6, 16 and 17 cannot be decided there.

## Capacity

`market.nr`'s capacity DEV DECISION. Gate counts (bb 6.0.0 `gates`) at `D = 16`, `K = 2`,
`W = 8`, eight-element leaves:

| lending_init | deposit | deposit_shared | withdraw_shared | borrow_shared | repay_shared | supply_shared | withdraw_supply_shared | view_shared | quote_shared | liquidate_shared | scan_shared |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 5,566 | 12,627 | 14,305 | 14,428 | 14,491 | 14,376 | 14,516 | 14,465 | 14,413 | 10,798 | 15,129 | 15,795 |

Every round is below the 2^14 rule (16,384 gates); the scan has 589 to spare and the liquidation
1,255. `K` is the largest width at which every round fits, so `K = 2`: one position per
liquidation. At `K = 3` the secret-shared liquidation measured 16,571 without interest, which
adds about 1,850; a probe slot costs about 3,715 gates at `D = 16`. A leaf of eight elements
costs four Poseidon2 permutations per hash against three for five (`ceil((LEAF_LEN + 4) / 3)`);
packing `borrow_index`, `last_accrual` and `next_index` into one field would give `LEAF_LEN =
5` at one decomposition per round, and is not needed.

Interest costs an owner round about 2,400 gates and the scan about 2,700: the accrual's three
`mul_div_wide` (189 to 190 gates each, measured alone once a circuit has its range tables: a
circuit of one costs 3,111, of two 3,300, of four 3,680), one more for the position brought to
the index, and the range checks of the clock, the elapsed blocks, the kink, the index's width
and the saturations, with a 48-bit check of every loaded position's index at touch (eight in
the scan's window). A secret-shared entry costs about 900 gates more than its
non-secret-shared round (`C`, the machine request id, the outcome's encryption and note hash).
The exit tag costs every secret-shared round 75 to 83 gates (one permutation per entry slot
and its selects); the write-off of bad debt costs the liquidation 3.

## Contract

`contract/` is a Nargo workspace of five packages on `noir/pss_public_contract` and `deps/`:
`lending_market` (the contract library: the plain types and the round table in `src/app.nr`,
the request helpers in `src/request.nr`, the bodies over the storage both contracts declare in
`src/storage.nr`, the generated layouts in `src/layouts.nr`), `lending_tip` (`LendingTip`, the
clear tree), `lending_tip_oblivious` (`LendingTipOblivious`), `lending_oracle`
(`LendingOracle`) and `lending_tip_test` (the TXE suite). Each contract declares its own
storage and entry points, each one call into `lending_market`; an Aztec entry point cannot be
generic or added by a library macro, so each is a thin wrapper written out in each contract
([DECISIONS.md section 13](../../docs/DECISIONS.md#13-examples)). `lending_tip` has 56
`#[external]` functions over a round table of twelve rows; `lending_tip_oblivious` has 45,
without the non-secret-shared deposit's five and secret-shared on-chain intake's six. The
circuits are fixed (the `upgrades` axis: every row takes the constructor's pins through
`configured_in_force`), on bytecode grounds: the public bytecode is 36,923 bytes transpiled,
`lending_tip_oblivious`'s 29,668 (bb 6.0.0 `aztec_process`). Every secret-shared round's layout
global is generated from its manifest (`scripts/gen-intake.py --layouts`).

Storage: `config`, `configured` (written once by `configure`), the library's `queue`, the
`market` commitment slot (0 until init; its storage slot is the market key,
`$state_keys.reads[0]` and `$state_keys.writes[0]` in every manifest), `outcome_notes` (slot
`OUTCOME_SLOT` = 1, the first field), `shared_onchain` (not in `lending_tip_oblivious`),
`refunds` (each queued request's two refund notes, by index), `kept_deposits`, `credits` and
`hatch` (`open` and `starving_since` in one slot).

`Config` pins `init_liquidity`, `oracle`, the tokens, the usage `deposit` (in the borrowed
asset), `treasury`, `t_live` (at least the stale period, with skipping enabled, since once the
hatch opens `skip()` is the only way a queued escrow comes back), and last the library's
`TipPins` (`stale_blocks`, the node `sig` keys, the contract manifest's hash, the package list,
room for eleven, and each package's vk hash, so the address commits to the circuits).
`configure` adds the namespace's `npk_app_hash`, checked against the nodes' signatures of the
REGISTER answer. The public functions read only record heads (`ConfigPublic`, the members
before `tip`: nine storage reads where the whole `Config` is 39; `Configured`'s first four
fields), which keeps the class's first deployment under the per-transaction DA gas limit.

| Function | What it does |
| --- | --- |
| `constructor`, `configure`, `set_configured` | the package list and the Config; the library's `configure` |
| `init_market`, `apply_init` | the init row over `[init_liquidity]`, outside the queue; refused without the seeded liquidity; writes `new_c` only while `market == 0` |
| `deposit`, `deposit_with_receipts`; `process_result`, `apply` | the non-secret-shared deposit under on-chain intake (request log `[tag, position, amount, partial_note, user_nonce]`) and receipt intake (no log); its result (`OwnerResult`): the reads, the write when ok, `Hatch::landed` with no tags, the public completion (`owner_note_fields`), `token::settle_applied` |
| `deposit_shared`, `withdraw_shared`, `borrow_shared`, `repay_shared`, `view_shared`, `supply_shared`, `withdraw_supply_shared`, `quote_shared`, `liquidate_shared`, `scan_shared` | the request functions ([Requests and rounds](#requests-and-rounds)): `outcome_request` over a `SharedReceiptArgs` under the round's generated layout, with `valid_deposit`, `valid_owner_request`, `valid_view`, `valid_quote`, `valid_liquidation` or `valid_scan` |
| `deposit_shared_onchain`, `append_onchain_shared` | secret-shared on-chain intake: the three `enc` keys read at the anchor block, a 16-field private request log |
| `append_onchain`, `append_receipt` | the public request wrappers: refuse before `configure` and the init, `Hatch::queued`, append, record the refund notes |
| `process_shared` (owner rounds, liquidation), `process_header_shared` (scan, quote) | one result function per public-input shape: `check_round` over `handle::Delivered` (`SharedResult = OutcomeResult<1, 1, 3, 1, 8>`, the leaf hashes, the app values, `SharedDeliveries`), the two note hashes and logs; enqueue `apply_shared` |
| `apply_shared(apply, opened, tags)` | the one apply of every secret-shared round: the reads, the new commitment whatever the outcome, `done`, `Hatch::landed`, the usage deposit kept or, when `opened` is 0, escrow and deposit refunded |
| `rotate_enc_key`, `set_enc_key`, `rotate_keys`, `set_node_keys`, `assert_key_epoch`, `get_node_keys` | the `enc` keys and key epochs ([Node replacement and key epochs](../../docs/ARCHITECTURE.md#node-replacement-and-key-epochs)) |
| `redeem`, `fund`, `withdraw_funds`, `pay_withdrawal`, `merge_credits`, `credit_balance` | [Notes](#notes-ownership-the-owners-view-and-value), [Tokens](#tokens) |
| `poke`, `open_hatch`, `exit`, `get_hatch` | [The escape hatch](#the-escape-hatch) |
| `skip`, `sweep_deposits` | the library's skip and the two refund notes; the kept deposits to the treasury |
| `deliver_outcome`, `outcome_notes`, `log_in_tx`; `get_state`, `request_at`, `done_at`, `refunds_at`, `get_kept_deposits`, `get_enc_key`, `get_data_hash` | utilities and views (`offchain_receive` is injected by aztec-nr) |

DEV DECISIONs in the contracts: ownership by note with owner `msg_sender` (on `assert_holds`;
the partial note is computed inside the request function, and `$user` is refused under every
intake); the non-secret-shared deposit's public completion (on `apply`); the escrow's recovery
route (on `escrow`); the usage deposit and the treasury (on `Config::deposit`,
`Config::treasury`); `T_LIVE` (on `Config::t_live`).

## Manifests

`manifests/` holds each circuit's manifest, all with `outcome: partial`, state `node` and a
`tree` entry for the market key. Each passes `scripts/check-manifests.py` and REGISTER's checks
against the compiled circuit.

Every round's manifest reads and writes the market key; the init's only writes it.

| Manifest | app inputs (PUBLIC names) | tree (probe, index, count, open) |
| --- | --- | --- |
| `lending_init.json` | `liquidity` | 1 (the header) |
| `deposit.json` (on-chain), `deposit_receipt.json` (receipt; circuit `deposit`) | `position, amount`; PUBLIC `$partial_note` | 2, `position`, -, `position` |
| `deposit_shared.json`, `deposit_shared_onchain.json` (circuit `deposit_shared`), `supply_shared.json` | `position`; INPUT_SHARED `amount`, `$partial_note` | 2, `position`, -, `position` |
| `withdraw_shared.json`, `borrow_shared.json`, `repay_shared.json`, `withdraw_supply_shared.json` | `position`; INPUT_SHARED `amount` (`shares`), `$partial_note` | 2, `position`, -, - |
| `view_shared.json` | `position`; INPUT_SHARED `$partial_note` | 2, `position`, -, - |
| `quote_shared.json` | INPUT_SHARED `$partial_note` | 1 (the header) |
| `liquidate_shared.json` | `p1, count`; INPUT_SHARED `budget`, `$partial_note` | 2, `p1`, `count`, - |
| `scan_shared.json` | `start`; INPUT_SHARED `$partial_note` | 1 (the header), window 8 from `start` |
| `lending_init_oblivious.json`, `<round>_oblivious.json` | the position INPUT_SHARED, an opening's PUBLIC `opens` after it | as the clear ones, `access: oblivious` |

A view, a quote and a scan take no shared app input; their shared partial note is what REGISTER
requires of a secret-shared round.

Each manifest declares the book's tree once, under `$state_keys.reads[0]` with `store
$state_keys.writes[0]` (the init under `$state_keys.writes[0]`): depth 16, leaf length 8, a
header; `params` `leaves` (LOAD over `probe * 8`), `old_hashes`, `siblings` and `indices`
(PUBLIC request names the scheduler fills from the nodes' clear trees); `new_hashes`
`app.new_hashes`. The rounds take `vk_hash` by `$vk_hash`, an opening's index by `$new_leaf`,
the new blindings by SAMPLE `probe` and `nsk_app` by the fixed LOAD; one output `TACEO_store
out0, STORE $state_keys.writes[0], len probe * 8, note_hash new_c`. The secret-shared entries
take `C` by `$inputs_hash`, the reserved shared values by INPUT_SHARED, and name `note_hash
new_commitments[0]`, `commitment_slot old old_commitments[0]`. `scan_shared.json`'s `window`:
`width` 8, `start` the app input, `params` `window_leaves` (LOAD slice `[8, 72]`),
`window_hashes` and `window_siblings` (13); REGISTER refuses a width that is not a power of two
at most 8 (`MAX_TREE_WINDOW`). Every round names both pinned reads: `{contract: <oracle>,
function: get_price_epoch, freshness: epoch}` and `{contract: $self, function: clock,
freshness: tolerance, band: {absolute: "128"}}`. The knobs (JSON has no comments):

- The oracle's address in `public_reads[].contract` is `"0x0"` in the repository; pss-client
  `buildContractManifest` replaces it with the deployed oracle's (the descriptor's
  `read_contracts`). A manifest registered with `0x0` fails closed: no round runs.
- DEV DECISION: `intake`. `onchain` for `deposit.json` (the inputs and nonce public in the log,
  no address); `receipt` for `deposit_receipt.json` (the inputs off the chain); `shared_receipt`
  for every secret-shared entry. The init's `onchain` only satisfies the schema.
- DEV DECISION: `binding: turn`. A request runs against the book as it is at the head; a
  liquidation queued behind a repayment finds the position healthy and lands with an empty mask.
- DEV DECISION: `stale_blocks: 50`, the descriptors' and so the contract manifest's
  `queue.stale_blocks`, equal to the Config's `tip.stale_blocks`.

## The oblivious deployment

Experimental ([The oblivious tree](../../docs/ARCHITECTURE.md#the-oblivious-tree)); the clear
deployments stay the recommended default. The book's `tree` entry says `access: oblivious`, so
its leaves and hashes live in a distributed oblivious RAM the nodes hold as shares
(`machine/sidecar-oblivious`), and every position index, an owner's and a liquidation's probe,
is a shared input: no node learns which leaf a request touches, nor whether a liquidation wrote
its probe.

- **Circuits**: `<round>_oblivious` and `lending_init_oblivious`, thin mains over the same
  rounds and `finish`. The slots arrive as the nodes' oblivious RAM reads (three LOAD slices);
  the circuit composes the indices from its own inputs (`tree::slot_indices`: a position's low
  16 bits, so a position past the tree is code 3) and verifies every path; no leaf hash is
  output, and the app value after the exit value is the append index after the round
  (`next_index`, which the nodes keep). The stored vector per slot is the leaf, its new hash and
  its 16 path nodes (`Updated::store_oblivious`), 50 elements at `K = 2`.
- **Openings and the scan stay public**: a deposit or supply names the public flag `opens` (1
  exactly when the position is 0; code 4 otherwise) and the scheduler assigns `$new_leaf` from
  the nodes' public append index (hiding the opening needs the brick's two-step read, not
  built: [DECISIONS.md](../../docs/DECISIONS.md#7-tip-state), "An opening on the oblivious tree
  is public"); the scan's `start` is public.
- **Static validity at intake**: the request function asserts it on the plaintext before `C` is
  formed, so a position at or past 2^16 is refused before anything is queued; code 3 is the
  backstop for a request no intake checked.
- **Contract**: `lending_tip_oblivious`, without `shared_onchain` and the two families above,
  its round table `RoundTable::oblivious`. Its request functions take a sharing that covers the
  shared position, and `deposit_shared` and `supply_shared` take `opens`. Its node-keys brick is
  `KeyEpochs<NoEncKeys>`; the escape hatch is the same (an exit tag needs no index).
- **Generated**: the mains, their Nargo.toml files and the manifests come from the clear rounds'
  (`python3 -I scripts/gen-access.py lending-tip <round>`; `--check` runs in
  `scripts/check-manifests.py` and `scripts/check-noir.sh`). The fixtures are every
  secret-shared case again plus an opening flag the position contradicts and a position past
  the tree. The client needs nothing per round; `e2e/scenarios/lending-tip-oblivious.ts` is
  the scenario, `e2e/tip/lending-tip-oblivious.json` the deployment.

**Gates**, measured (bb 6.0.0 `gates`):

| | lending_init | deposit | withdraw | borrow | repay | supply | withdraw_supply | view | quote | liquidate | scan |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| secret-shared (`*_shared`) | 5,566 | 14,305 | 14,428 | 14,491 | 14,376 | 14,516 | 14,465 | 14,413 | 10,798 | 15,129 | 15,795 |
| oblivious (`*_oblivious`) | 5,566 | 14,120 | 14,225 | 14,288 | 14,173 | 14,405 | 14,262 | 14,210 | 10,612 | 14,926 | 15,610 |

Fewer gates by 111 to 203 per round (no placed-index comparisons). The cost is elsewhere: the
tree's shared permutations double (`2·K·D`, 64), and each round pays the oblivious RAM: two
batched path reads of 25 addresses and the previous round's two writes, about 200 sequential
communication steps and 55 ms of compute in process, plus one `a2b` and one `b2a` batch.
**Round time, estimated**: about 0.1 to 0.3 s more per round on a co-located mesh, about 2 s at
a 10 ms round trip. Memory: a 2^20-address DORAM, about 1.7 GB per node and a 12 s bottom-level
rebuild about every 40 rounds. The e2e scenario with real proofs measured 26 to 41 s per round,
request queued to result landed on one host (the init 6 s).

Where each party's view differs, measured by `test_round_shape.nr`, `test_oblivious.nr` and the
e2e scenario: one node sees per request `C`, its shares, the round type and the clear inputs a
receipt records (the opening flag, a liquidation's count, a scan's start); per round the public
outputs, the append index among them (so whether an opening applied); the oblivious RAM's access
count (fixed per round type) and timing. Its store holds no clear tree, only its DORAM shares
and journals (about 370 MB at node 0 after the run). The orchestrator sees no index (`$new_leaf`
on an opening), the relayer zero leaf hashes and no position. The world sees every request as
the same transaction and every result with the same effects and gas
([Gas per transaction kind](../../e2e/scenarios/README.md#gas-per-transaction-kind)), with no
index, append index or hash. Two nodes
still open everything, every index included.

## Rounds under other intakes

The design guide's
[Running a round under another intake](../../docs/design-guide/README.md#running-a-round-under-another-intake)
lists the artifacts and the rules. Here the deposit runs under all four intakes and every other
round under secret-shared receipt intake; `python3 -I scripts/gen-intake.py --check` derives and
checks every round's manifests. Another combination takes:

- **The non-secret-shared main.** `circuits/<round>/` calls the round's entry with the `Plain`
  entry, as `circuits/deposit` does; then `gen-intake.py lending-tip <round> onchain` (or
  `receipt`) writes its manifest.
- **The request functions**, written by hand: the note check, the partial note, the escrow and
  the usage deposit around `onchain_request` or `receipt_request`, or `shared_request` with a
  `SharedOnchainArgs` and the round's generated layout.
- **The result.** An owner round's public result completes the requester's note in public
  through the deposit's `apply` and `OwnerResult`, with the note `[code, position, mask, 0, 0,
  payout, 0]`: it reports no collateral or debt, which the public completion log would publish.
- **Liquidate, scan and quote** need an entry and outputs of their own under the
  non-secret-shared family: `Plain` carries the owner rounds' book (`OWNER_SLOTS`) and outputs
  (`OwnerNoteOutputs`).

## Choices and limits

Lending's own trade-offs (the rationale of the shared choices is
[DECISIONS.md](../../docs/DECISIONS.md#13-examples)):

- **The exit by tag**: the hatch publishes no index, so the chain never learns which position a
  round wrote or which left, and the hatch works on the oblivious deployment; an owner learns of
  a write only from its notice or its spent tag.
- **The quote round**: a market whose rates nobody can learn has no lenders. The indices are not
  published per round: a per-round utilisation change would tell a borrow from a deposit and
  break the hidden round type.
- **Kept deposits go to a treasury**, swept in public. Crediting them to lenders through
  liquidity would need the deposit amount as a public input in every round and a destination for
  failed rounds, which write nothing. A reserve factor on interest is not built.
- **The scan reports occupancy, not `next_index`**, and its deposit is the namespace's.
- **The two oracle prices.** Within `previous_blocks` of a new price the network picks either
  epoch's price, worth one price move to a party the nodes favour. Evaluating borrows and
  withdrawals at the lower price and liquidations at the higher would close that choice at a
  second price in every round's public inputs; not built.

What stays unrealistic: the price source (an owner-set epoch price, a funds trust assumption of
its own); one asset pair per deployment (a multi-asset position would widen the leaf by two
elements per asset and make health a sum of values); bad debt written off only by the
liquidation that leaves it; no supply or borrow caps; parameters fixed in the vks, a change
being a new deployment with no migration of positions; one liquidation per round and minutes
per round with real proofs; interest at a clock the network chooses within the band; the
orchestrator seeing requesters' network addresses; and in a frozen market no interest since
each party's last round and no public liabilities total, so whoever withdraws credit last may
be short (a solvency bound would need the public total that private escrow removes).

## Running the checks

```sh
scripts/bootstrap.sh && npm ci --prefix scripts/txe     # once per checkout
scripts/check-noir.sh examples/lending-tip --outputs examples/lending-tip/circuits/outputs.txt
                                               # compile, lending_tip tests, total-lint, solve every case,
                                               # each case's outputs, the chain of commitments and the race
scripts/witness-extend.sh examples/lending-tip   # a co-noir three-party witness extension of every case
(cd machine && cargo test --release -p sidecar-core every_example_deployment_registers_against_its_compiled_circuits)
python3 -I scripts/check-manifests.py
(source scripts/toolchain.sh && cd examples/lending-tip/contract && "$CONTRACT_NARGO_BIN" check --workspace)
scripts/txe.sh --contracts --only examples/lending-tip/contract/lending_tip_test
E2E_TIP=1 E2E_TIP_DEPLOYMENTS="lending-tip lending-tip-plain" EXPECT_REAL_PROOFS=1 e2e/run.sh lending-tip
```

### Fixtures

Generated by `python3 -I examples/lending-tip/circuits/gen-fixtures.py` (it reads `DEPTH` and
`PROBES` and builds each fixture's slots from a sparse tree over `scripts/poseidon2.py`, checked
against `testvectors/tip_tree.json`). Alice opens position 1 with 1,000 and borrows 1,700 at
2.50; Bob opens position 2 with 1,000; at 2.00 Alice's health is 9,411 bps. **The race** is
Alice's repayment and a liquidation of her position at 2.00, queued in either order: (a) the
repayment first (400, to 12,307 bps), so the liquidation behind it finds her healthy; (b) the
liquidation first, which seizes 446 and repays 850, and the repayment lands on what it left.

The non-secret-shared deposit has `Prover.toml` (the opening, index 1), `Prover-second.toml`
(index 2) and one `Prover-<case>.toml` per code it can report (1, 2, 3, 4, 7, `not-open` 5,
`full` 16, `gap` 17). The secret-shared entries run on the same books with the client's first
request's secrets (`testvectors/secret_store.json`, n = 0): openings and deposits, codes 5, 14,
16, 17, a borrow past the limit (9) and one at it (`Prover-at-limit`, 1,500), the race's
repayment and one over the debt (`Prover-excess`), a withdrawal to the limit at 2.50 and one
past it (9), one above the collateral (19), the lenders' rounds on a pool worth 1.1 per share
(codes 20, 5, 18, 8, 14), views, a quote, the race's liquidation, a healthy probe, a count of 0
(3) and half a budget (`Prover-budget`: repay 425, seize 223). Interest runs at a second clock
(`Prover-accrued`, a pool at the 80% kink last accrued at block 0: at block 100 the debt
800,004 at the index 1,000,004,600; at block 10,000 the supply index 1,000,368,000; at block
20,000 a scan and a liquidation of a position healthy at block 0 and unhealthy by interest
alone, `scan_shared/Prover-not-yet`). `scan_shared/Prover*.toml` run on a book of nine positions,
three unhealthy at 2.00 and one a lender's. Each fixture's comment states its outcome, which its
ciphertext opens to; `outputs.txt` checks each one's outputs and that every non-secret-shared
fixture on a live book has, as `old_c`, the commitment the round that made the book left. The
remaining codes and u128-width cases are the library's tests (`rounds.nr` `borrow_codes`,
`repay_codes`, `liquidate_codes`), which also run the secret-shared rounds on the race (from
`[0, 1, 0, 1000, 0, 0, 0]` for the opening deposit to `[0, 0, 1, 446, 850, 150, 0]` for race
(b)) and check that under codes 15, 16 and 3 the new commitment is the nodes' clear tree's after
the round's new leaf hashes (sidecar-core `tree/clear.rs` `rebuild`). Its interest tests
check the accrual against its closed form, the band's edges accruing once, a long idle period,
saturation and health flipping by interest alone.

### TXE suite

`lending_tip_test` deploys the oracle, the two tokens and the market (`lending_tip`, or
`lending_tip_oblivious`) and configures it. The proofs are dummy vks and zero proofs (recursive
verification is a no-op in the TXE); the node signatures are real (`testvectors/keys.json`). By
module:

- `test_configure.nr`, `test_init.nr`, `test_intake.nr`, `test_result.nr`, `test_oracle.nr`,
  `test_followon.nr`: the Config pins (skipping required, `t_live` at least the stale period);
  `configure` (once; a wrong signature, an unpinned circuit, a DISABLE answer or another
  namespace refused; everything reverting before it); the init (refused without the seeded
  liquidity in the balance; `fund` refused before it); the non-secret-shared deposit under both intakes (one request id, the same partial note under the
  other intake refused, no address anywhere) and its public completion; the epoch read (one
  epoch behind lands within the window, two behind or a price the epoch never had reverts, a
  recompute lands, and the oracle's `previous` expires `previous_blocks` after a new epoch); a
  failed round is a no-op and the next runs on the kept commitment; `skip()` from
  `stale_blocks` on (not before: `pss_public_contract_test`).
- `test_ownership.nr`: a request by an account without a note of the position is refused; a
  failed opening's note, another position's note and a liquidation's note confer nothing; a note
  naming its position confers it whatever its code; one `rho` used twice is refused; a redeemed
  note still opens a request; a second or a stranger's redeem is refused.
- `test_notice.nr`: the liquidation's result carries the owner's notice, which the owner finds
  under its handle's tag and holds as an owner note; another account rebuilding it stores
  nothing; a round that notifies nobody lands a filler.
- `test_shared.nr`, `test_cases.nr`, `test_tokens.nr`: the race in both orders, its outcomes
  opening to the non-secret-shared race's; the epoch read on secret-shared rounds; redeems paying
  a borrow, a liquidation's seize and budget, a withdrawal in collateral, a repayment's excess;
  a code-14 round's escrow and deposit returned by `apply`; a stale request skipped.
- `test_lenders.nr`: supply, withdrawal of supply, code 18 on a second withdrawal from one note,
  cross-kind requests refused, a quote, `sweep_deposits` and a withdrawal never drawing on the
  kept deposits.
- `test_interest.nr`: the clock is the block number; rounds at the band's top and bottom land
  and deliver the accrual; clocks past either edge are refused.
- `test_keeper.nr`: the scan is in the shared list, reports to the keeper only and lands
  whatever the window; an unaligned start is refused at intake; a scan has the effects of every
  secret-shared round.
- `test_hatch.nr` (the brick's own cases are `noir/pss_public_contract_test`'s): the starving
  clock on the secret-shared and oblivious deployments; a borrower, a lender and a liquidated
  owner exiting once on their newest notes, and the whole flow on the oblivious deployment; a
  second exit, an older note, a replaced note, another sender, an exit before the opening and a
  non-secret-shared deposit's note refused; an owner liquidated two or three times exiting on its
  newest notice; a self-liquidator exiting on its notice and redeeming its liquidation's note;
  redeem and exit once each in either order; a landing and the opening in one block, in both
  orders; nothing queued or landed after the opening while `skip()` and `redeem` work; a landing
  whose exit tag is 0 refused.
- `test_shared_onchain.nr`: the deposit under secret-shared on-chain intake, with rotations, a
  retired key and an anchor before a rotation; a layout with the outcome key and tag swapped
  flags code 14.
- `test_round_shape.nr`, `test_oblivious.nr`: equal effects and gas for every round type, the
  exit tags counted, no field naming a position on the oblivious deployment.

### e2e

`e2e/scenarios/lending-tip.ts` (`e2e/scenarios/README.md`, "lending-tip.ts") runs the
secret-shared deployment first (`e2e/tip/lending-tip.json`): an opening deposit; a borrow opened
by its owner's note, redeemed once, its intake and result transactions audited (no address,
amount, partial note or outcome value in a public call, log or write); a view of another's
position refused and the owner's view; the keeper's scan and liquidation, its note redeemed; the
liquidated owner's notice opened; a repayment the notice opens; withdrawals that hold and break
the limit; a lender's supply and withdrawal; a quote; the sweep; the landing atomicity tests (a
landing whose apply or teardown reverts leaves its exit tag unspent; of two landings of one
result in one block, the first reverting, the second lands); a position liquidated twice; and the
escape hatch (the relayer paused past `t_live`, owners exiting on their newest notes, the
twice-liquidated owner after recovering both notices). Then the non-secret-shared cases on
`e2e/tip/lending-tip-plain.json`: openings under both intakes, the same receipts again, a deposit
into another's position and a zero deposit refused, and the epoch window.

### total-lint per circuit

`scripts/check-noir.sh examples/lending-tip` lints the 23 circuits `circuits.env` declares total
(the init, the eleven queued rounds and the oblivious twins of the init and the ten
secret-shared rounds) with `--lib-src` total's and noir-lang/schnorr's src, honouring markers in
each circuit's src, `lending_tip/src` and `noir/pss_core/src`. Every reported item is
`hint-unreviewed` (the init's liquidity assert `hint-pinned`), each justified by a `//
total-lint: allow` marker in `pss_core`, as is the one reachable Brillig abort site, the
`TACEO_store` oracle call (`mpc_store.nr`):

- `tree`: `tip::tree::load`'s assertion of each loaded leaf against its old hash and the bit
  decompositions of its clamped indices; both are node-supplied, so a failure means a diverged
  store, and a clamped index always decomposes.
- `npk`: std's scalar decomposition and generator MSM in `npk_app_hash` (`aztec_note.nr`), which
  has a solution for every Field.

`lending_init` keeps one assert, that the liquidity is a u128: the init is never queued, so a
liquidity that does not fit stops the deployment, never a queue.

| Circuit | Exit | Unjustified | Justified (tree + npk) |
| --- | --- | --- | --- |
| lending_init, lending_init_oblivious | 0 | 0 | 6 (1 liquidity assert + 5) |
| deposit, the seven secret-shared owner rounds, liquidate_shared | 0 | 0 | 57 (52 + 5) each |
| quote_shared | 0 | 0 | 31 (26 + 5) |
| scan_shared | 0 | 0 | 120 (115 + 5) |
| the seven `*_oblivious` owner rounds and liquidate_oblivious | 0 | 0 | 43 (38 + 5) each |
| quote_oblivious | 0 | 0 | 14 (9 + 5) |
| scan_oblivious | 0 | 0 | 103 (98 + 5) |

`total-lint --brillig-ops` reports no unsupported op on any of the 23 circuits.
