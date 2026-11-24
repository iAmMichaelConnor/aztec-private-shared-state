# Scenarios

One driver (`../driver.ts`) runs every example end to end; a scenario, one module in this
directory, says what it runs. `e2e/run.sh <scenario>...` runs the driver once per scenario
named, after the harness's smoke check; a scenario's log is `<run>/logs/driver-<scenario>.log`.
Which gate runs which scenario, on which deployments, with which command and at what cost is
in [docs/TESTING.md](../../docs/TESTING.md), "End to end". The harness, its environment and
what a tip run (`E2E_TIP=1`) sets up before the first scenario (funded accounts, deployed and
configured deployments, minted tokens, one relayer per deployment, landed init rounds) are in
[e2e/README.md](../README.md). The scenario files are the source of truth for every value
below.

## The engine

`driver.ts` checks the scenario against the step registry, builds and deploys its contracts,
registers the tip deployments the harness made (and the contracts each deployed first) in every
wallet, runs the steps and makes the final checks. It knows no step kind by name.
`steps/index.ts` is the registry: one module per kind, each exporting its step type and a kind
with a `check` (the fields the step takes, the names it binds) and a `run(ctx, step)`. Each
module's header comment documents its step's fields.

A step sees only the run context (`engine/context.ts`): the scope, the run's keys, accounts,
contracts and namespaces, a pss-client per namespace, the REGISTER pins, the network and the
machine's side doors (`engine/machine.ts`: the lossy fetch, a POST past the client, the admin
sockets). Steps share `engine/answer.ts` (answered rounds), `engine/tip.ts`, `engine/reorg.ts`
and `engine/gas.ts`. A new kind is a new module in the registry and a member of `Step` in
`../scenario.ts`.

## The format

A scenario exports `scenario: Scenario` (`../scenario.ts`, which documents each field). It is
data: constants and pure helpers that build steps, no calls of its own. It names the `example`,
the `accounts` (the local network's initial accounts, or with `freshAccounts` new ones paying
through the SponsoredFPC, which a tip run refuses), optionally `wallets` (each its own PXE
holding only its accounts' keys, so a note between them crosses PXEs), `senders`, `tagging`
(`address-derived`; a wallet without it tags through a handshake), the run's `keys` (`owner`
keys sign REGISTER and DISABLE, `requester` keys sign rounds and own their records), `signer`,
`values`, the `contracts` to build and deploy, the `namespaces`, the `tip` deployments
(`e2e/tip/<deployment>.json`; each a contract and namespace of that name, and the contracts it
deployed first named `<tip name>.<name>`), `aliases` and the `steps`.

Before anything runs, the driver checks every step: exactly one kind field, no field its
variant does not take, only declared keys, accounts, contracts and namespaces, and no bound name
among `accounts`, `contracts`, `namespaces`, `pins`. Every step may carry `what` (its log label)
and `hint` (appended to a failure). In a step, `$a.b[0]` is a reference into the scope
(accounts, contract addresses, namespaces, `pins.<namespace>.vk.<name>` and
`pins.<namespace>.npk_app_hash`, `let` values, named rounds, notes, requests and results), a
string containing `${a.b}` a template, `$$` a literal `$`; everything else is passed as written.
Each contract is built into `<run>/contracts/<package>` (log
`<run>/logs/<scenario>-contract-build-<package>.log`) and deployed in order before the steps run.

| Step | What it does and checks |
| --- | --- |
| `register` | REGISTER a contract manifest; pss-client checks its hashes, vk hashes and node signatures; binds the pins. `refused`: `seq` unchanged. The same list at the next `seq` re-enables what DISABLE stopped. |
| `disable` | DISABLE: disabled at `seq` under the pinned vk hash. |
| `round` | Build, optionally `tamper`, send a request. `refused`: the machine refuses with that class, status and substrings (`clientRefuses`: pss-client first). Answered: the pinned vk hash, three signatures, the public-input prefix, records and consumed leaves, then `expect`. `answer: "lost"`: FETCH, a second FETCH and a resend all return it. |
| `tx` | Call a contract with a round's proof as capsule; the round's nullifiers and note hashes must be in it. `nodeTamper`: a copy with a Chonk proof field changed is refused by the node first. `clientTamper`: capsule proof field 100 changed, refused by the PXE's proving. `drop`: lost before the node. `simulationRefused`: only simulated, refused. |
| `fetch` | FETCH by request id (`fresh`: a new client); equal to the round's answer. |
| `restore` | Restore a committed round on every node; FETCH then answers 409 `rolled back`. |
| `sender` | A wallet registers a sender: its PXE rescans that sender's tags from index 0. |
| `tipInit` | The init round landed by the relayer, its slots set, the queue empty. |
| `tipEncKey` | Each node signs its `enc` key at `epoch`; `rotate_enc_key` lands per node; `get_enc_key` reads each back. |
| `tipRequest` | A tip request through the package's intake (pss-client `obtainIntake`, `requestIntake`), queued once under the client's chain request id with the public logs its intake gives. `refused`: refused by the request function, queue unchanged. `again`: an earlier request's exact arguments, refused. |
| `sameBlock` | Several requests sent together: all land in one block, bound in queue order. |
| `tipResult` | Waits for the request's index and checks the transaction that finished it: the relayer's, or the user's own with `by: user` (`clientTamper`: tampered copies refused first). Applied: read keys held the old commitments, written keys hold the new; no public log but a public completion's. `skipped`: keys unchanged. `again`: the landed result again is refused. |
| `tipAttempt` | The scheduler's attempt before anyone lands it; `after` waits for a recompute, `recomputed` counts them. |
| `tipOutcome` | The sender opens its private outcome (pss-client `OutcomeReader`), checks it is the landed result's and hands the note to its PXE. |
| `tipAudit` | No public call, log or write of the intake and result transactions names the sender or carries a private value (values below 1000 not scanned); no public log; both paid through wFJ. |
| `tipNotice` | The owner opens a delivery to its handle by another party's round (pss-client `DeliveryReader`). |
| `tipLand` | A held attempt landed with no simulation and mined reverted in `apply` or in `teardown` (the probe); nothing of it remains on the chain. |
| `tipOutbid` | Two landings of one attempt in one block: an outsider's reverted copy first, then the ordinary landing. |
| `tipRecover` | The owner recovers, from the chain alone, the notices of rounds that spent its notes' exit tags (pss-client `recoverExitNote`). |
| `tipExit` | An escape-hatch exit on the newest note with an unspent exit tag: the credit moves by `pays` and `repays`; `refused` at simulation. |
| `tipFund` | Fund a private credit; the credit grows by each amount. |
| `tipPause` | The orchestrator's `pause` or `resume`; a resume is refused while the nodes' registries differ. |
| `tipReplaceNode` | Node replacement with the orchestrator paused (`amm-tip-replace-node.ts`). |
| `tipUpgrade` | One upgrade action: `register`, `schedule`, `follow`, `publishClass`, `followClass`. |
| `redeem` | Redeem a completed note; a second redeem is refused; `pays` checks the balance or credit. |
| `view` | Simulate a view or utility; `grew` waits until it moved by `by`. |
| `keeper` | A keeper's pass (pss-client `keeperPass`) from opened scan outcomes; binds the act rounds. |
| `relayer` | Suspend or resume the deployment's relayer. |
| `advance` | Empty blocks: `n`, `until-stale`, or `{warp: s}` of L2 time. |
| `reorg` | The reorg network's operations and reads ("The reorg scenarios"). |
| `let`, `log` | Computed values (`poseidon2`, `random`) and log lines. |

At the end every transaction the driver sent must have one `Accepted <tx hash> with valid proof`
line in the node log, each after its own `Chonk verification successful` line
(`harness/node-verification.ts`), and the node-side refusal must be there. With
`EXPECT_REAL_PROOFS=0` nothing is proved client-side and the client-side tamper is skipped;
every machine case still runs.

## `amm.ts`

The node-held AMM of `examples/amm` on the sidecar path (docs/ARCHITECTURE.md sections 3, 4
and 8): contract `AmmPss`, deployed without an initializer, its address the namespace `main`;
`foreign` is a random namespace with its own owner.

- **Happy path.** REGISTER of `pss_seed`, `amm_init`, `amm_swap`, `amm_swap_total`; `pss_seed`,
  `init_pool` (anchors the `Config`: the four vk hashes, `npk_app_hash`, the `owner` const, the
  operator), `amm_init`, `start_pool`, then swaps of 10 000 x and 7 000 y.
- **Refusals:**

  | Case | Class | HTTP |
  | --- | --- | --- |
  | REGISTER signed by a non-owner key; `seq` unchanged | forbidden | 403 |
  | a second `amm_init` on the consumed seed | conflict | 409 |
  | `amm_swap` on the consumed seed; names the consumer's vk hash (`amm_init`) | conflict | 409 |
  | `foreign_seed`, registered only under `foreign` | bad_request | 400 |
  | a swap after DISABLE of `amm_swap`; REGISTER at `seq` 2 re-enables it | bad_request | 400 |
  | `amm_swap` with `amount_in` 0: the proof does not verify, nothing stored | unsatisfied | 422 |
  | FETCH of the restored swap | conflict | 409 |
  | swap 2's transaction with capsule proof field 100 changed: the PXE refuses | — | — |
  | swap 1's transaction with one Chonk proof field changed: the node refuses, then accepts the honest one | — | — |

- **Rollback.** A swap with swap 2's inputs is committed and never sent, then restored on
  every node; swap 2 must return the same `amount_out`.
- **A dropped transaction.** Swap 2's transaction is lost; a fresh client knowing only the
  request id FETCHes the same answer, and that proof lands (ARCHITECTURE.md section 8).
- **The total swap.** The zero-amount request `amm_swap` refuses goes to `amm_swap_total`:
  `[ok, code, amount_out] = [0, 1, 0]`, a new pool note hash (the old reserves re-blinded), and
  `swap_total` lands it; a total swap of 5 000 x (`ok = 1`) then spends the note the no-op
  re-created. The nodes can run `amm_swap_total` because its total-noir entries avoid the
  Brillig ops co-noir lacks (`scripts/check-noir.sh`, `total-lint --brillig-ops`).

Accepted transactions: deploy, `init_pool`, `start_pool`, two swaps, two total swaps.

## `monty.ts`

The client-held Monty Hall game of `examples/monty-hall` on the record path (docs/ARCHITECTURE.md
section 3; section 5, invariants 6 to 9; section 8): contract `MontyHall`, its address the
namespace `main`; `other` is a random namespace. Operator and player share one wallet.

- **Happy path.** REGISTER of `pss_seed`, `monty_hall_init`, `monty_hall_open_door`,
  `monty_hall_finish`. Every round is signed by the player's requester key, so every record is
  the player's. `pss_seed`, `init_game`, `monty_hall_init`, `start_game`, `choose_door`,
  `monty_hall_open_door` (door and randomness as INPUT_SHARED inputs), `open_door`,
  `switch_door`, `monty_hall_finish`, `finish_game`. `init_game` and `start_game` each push
  exactly two note hashes; the opened door is another than the player's. A second game (seed
  and init) supplies a record for the mixed-record case.
- **Refusals** (step numbers are the record path's checks):

  | Case | Class | HTTP |
  | --- | --- | --- |
  | `open_door` with the door shared inconsistently between nodes: the session handshake (step 10) | bad_request | 400 |
  | `open_door` with a record whose node-0 third is the other game's: pss-client refuses; past it, the own-ciphertext check (step 6) | bad_request | 400 |
  | `monty_hall_finish` on the record `open_door` consumed; names `monty_hall_open_door`'s vk hash | conflict | 409 |
  | `monty_hall_finish` with the record under another namespace: the thirds do not open (step 8) | bad_request | 400 |
  | the operator signs the player's finish: pss-client refuses; past it, the signature check (step 4) | forbidden | 403 |
  | the same under the operator's own requester key: the thirds do not open (step 8) | bad_request | 400 |
  | `monty_hall_finish` replayed under a new request id on the consumed record | conflict | 409 |
  | `finish_game` with capsule proof field 100 changed: the PXE refuses | — | — |
  | `open_door` with one Chonk proof field changed: the node refuses, then accepts the honest one | — | — |

- **A lost answer.** The finish answer is dropped; FETCH, a second FETCH and a resend of the
  saved body return the first result byte for byte, with no second round; `finish_game` lands
  it.

Accepted transactions: deploy, `init_game`, `start_game`, `choose_door`, `open_door`,
`switch_door`, `finish_game`.

## `monty-two-wallets.ts`

`monty.ts` with the operator and the player in two wallets, so the `Game` note `start_game`
sends crosses PXEs (`examples/monty-hall/README.md`, "The contract's state"). No sender is
registered: the operator's PXE tags the delivery through a handshake, so `start_game` pushes
three note hashes (the game-state note, the `Game` note, the handshake note), and the player's
PXE finds the note at `choose_door`. The operator's wallet never learns the player's keys.

## `monty-registered-sender.ts`

`monty-two-wallets.ts` with `tagging: {operator: address-derived}`: no handshake, so
`start_game` pushes two note hashes, and the player's wallet registers the operator as a sender
just before `start_game`. Fresh accounts, so no handshake an earlier scenario left lets the
player's PXE find the note without the registration.

## `monty-late-sender.ts`

`monty-registered-sender.ts` with the operator registered only after `start_game` is mined: a
simulated `choose_door` must first be refused with `Failed to get a note` (no `Game` note, so
no handshake was made); after the registration the PXE rescans from index 0 and the real
`choose_door` finds it. Fresh accounts, as above.

## `amm-tip.ts`

The AMM at the tip (docs/ARCHITECTURE.md section 6; `examples/amm-tip`) on three deployments:
`shared` (`e2e/tip/amm-tip-shared.json`: the swap `amm_swap_tip_shared` under secret-shared
receipt intake, landed through `process_result_shared`), `main` (`amm-tip.json`: stale period
50; on-chain intake and the receipt-intake alias `amm_swap_tip_receipt`) and `stale`
(`amm-tip-stale.json`: stale period 4). `alice` and `bob` have wallets of their own. Every
non-secret-shared request commits its sender's partial note, and `apply`'s completion log
`[tag, slot, code, amount_out, request_id]` must carry FETCH's `[code, amount_out]`.

- **A secret-shared swap.** `bob` sells 31 337 x, `min_out` 1 234: the pool gets a new
  commitment and the result one completed note hash; `bob` opens `[0, amount_out]` and his PXE
  holds one more swap note. `tipAudit`: neither transaction shows `bob` or a private value.
- **A failed secret-shared swap.** `alice`'s `min_out` 1 000 000: the outcome opens to `[8, 0]`
  and the pool is re-blinded all the same; audited.
- **On-chain intake.** `alice` sells 10 000 x (with the node-side negative): `ok`, code 0, a
  positive `amount_out`, the note completed in public.
- **The repeated intake and result.** The same arguments again are refused (the partial note's
  use nullifier); the landed result sent again by `bob` is refused (`queue is empty` or `not
  the head`).
- **Receipt intake.** `bob` sells 7 000 y with three receipts; the same receipts again are
  refused.
- **A failed swap.** `ok = false`, code 8, `amount_out` 0, the pool unchanged.
- **Two traders in one block.** Two 20 000 x swaps in one block: the second runs on the first's
  commitment and gets less.
- **The relayer stopped.** `alice` lands her own result (after the tampered copies are refused);
  the restarted relayer lands the next swap on it.
- **A stale head.** On `stale`, a swap waits until the head is stale and the relayer `skip()`s
  it; the next swap runs on the init's commitment.

## `lending-tip.ts`

Lending at the tip (docs/ARCHITECTURE.md section 6; `examples/lending-tip/README.md`) on two deployments of `LendingTip`, each with its own two tokens
(`collateral`, `borrowed`) and `LendingOracle` at 2.50 deployed first: `shared`
(`e2e/tip/lending-tip.json`: `lending_init` and the ten secret-shared entries under
secret-shared receipt intake, landed through `process_shared` and, for scan and quote,
`process_header_shared`) and `plain` (`lending-tip-plain.json`: `lending_init`, `deposit` and
its receipt-intake alias `deposit_receipt`, landed through `process_result`). Usage deposit 5
borrowed tokens per round, kept by the market; `t_live` 60 blocks; treasury `0x7ea5`. The
harness mints 100,000 of each token to every account and 1,000,000 borrowed tokens of liquidity.
`operator` owns the oracle and tokens and is lender, liquidator and keeper; `alice` shares its
wallet, `bob` has his own. Outcome notes read `[code, position, mask, x, y, payout, aux]`; `B`
is the borrow index, above 10^9 (`INDEX_ONE`) once interest accrued.

- **Funding.** Every account funds a credit of 20,000 of each token on each deployment
  (`tipFund`). Every request draws its escrow and usage deposit from it; every redeem and exit
  credits it.
- **Secret-shared rounds.** `alice` opens position 1 with 1,000 (`[0, 1, 10^9, 1000, 0, 0, 0]`);
  `operator` supplies 5,000 (`[0, 2, 0, 5000, 5000, 0, 0]`); `alice` borrows 1,700
  (`[0, 1, 10^9, 1000, 1700, 1700, 0]`), audited, and redeems 1,700 borrowed tokens once (the
  second redeem is refused). `bob`'s view of position 1 is refused in the private function.
  After two blocks `alice`'s view reports `[0, 1, B, 1000, 1701, 0, 0]`: interest by block
  clock, rounded up.
- **Non-secret-shared deposits.** `alice` (on-chain intake, node-side negative) and `bob`
  (receipt intake) open positions 1 and 2, each on the previous commitment, completed in public;
  `bob`'s receipts again are refused. `bob`'s deposit into position 1 is refused (`the sender
  holds no note of this position`) and his credit does not move; a deposit of 0 is refused at
  intake (`invalid inputs`).
- **The epoch window.** With the relayer stopped, `bob`'s deposit pinned at epoch 1 lands as
  computed after one epoch opens; `operator`'s deposit pinned at epoch 2 is recomputed exactly
  once after two epochs open, and lands at epoch 4. `get_kept_deposits` reads 20.
- **The keeper.** `bob` opens a healthy position 3; the price falls to 2.00, where `alice`'s
  1,000 / 1,701 is unhealthy. `operator`'s scan of window 0 opens `[0, 0, 2, 0, 0, 0, 3]`
  (position 1 reported, three occupied); the `keeper` step yields one liquidate round and no
  further scan. The liquidation, budget 1,000, opens `[0, 0, 1, 446, 851, 149, 0]`; its redeem
  pays 446 collateral and 149 borrowed tokens. `alice` opens her notice from the same result
  (`[0, 1, B, 554, 851, 0, 0]`), and after two more blocks repays 400
  (`[0, 1, B, 554, 452, 0, 0]`).
- **The borrow limit** (75% of collateral value; liquidation at 80%). `alice` withdraws 54
  (`[0, 1, B, 500, 453, 2^128 + 54, 0]`, paid in collateral), borrows 296 to the limit
  (`[0, 1, B, 500, 750, 296, 0]`), and a withdrawal of 1 more fails with code 9, its redeem
  refused.
- **Lender exit, quote, treasury.** `operator` withdraws its 5,000 shares
  (`[0, 2, 0, 0, 0, 5000, 0]`, redeemed); `bob`'s quote opens `[0, 0, B, 0, S, 0, 7]` (both
  indices above par, 7 bps utilisation). `get_kept_deposits` reads 65 (thirteen rounds);
  `sweep_deposits` pays them to the treasury.
- **Landing atomicity.** On held attempts: `bob`'s view landed after two epochs opened reverts
  in apply (`pinned epoch too old`), leaves nothing, and the recompute lands with the same exit
  tag; `bob`'s borrow of 1,400 landed through a reverting teardown leaves nothing, then
  `operator` lands it with the same tag; `alice`'s view landed twice in one block (`tipOutbid`)
  lands once.
- **Two liquidations in a row.** At 1.70 and again at 1.50 `operator` liquidates `bob`'s
  position 3 with no round of `bob`'s between, redeeming each.
- **The escape hatch.** `bob` supplies at position 4; the relayer stops; `alice`'s view waits
  at the head; after 62 blocks `bob` calls `open_hatch()`, and landing the held view reverts
  (`the escape hatch is open`). `alice` exits as a borrower on the note whose tag that landing
  would have spent (repaying its debt, taking its collateral); `bob` exits as a lender, and his
  second exit is refused. `bob`'s exit on his borrow's note is refused (a liquidation spent its
  tag); he recovers both notices from the chain and exits on the second. `alice` then turns 500
  of credit into collateral tokens (`withdraw_funds`).

A full book (code 16) is not run end to end; `scripts/check-noir.sh` covers it with
`Prover-full.toml`.

## `amm-tip-shared-onchain.ts`

Secret-shared on-chain intake in the AMM tip (docs/ARCHITECTURE.md section 6, "Secret-shared
on-chain intake") on `e2e/tip/amm-tip-shared-onchain.json`: the secret-shared deployment with
its swap also registered as `amm_swap_tip_shared_onchain` (an alias, intake `shared_onchain`).

- The init lands; the nodes key the contract at epoch 1 (`tipEncKey`).
- `bob` sells 31 337 x, `min_out` 1 234 (`swap_shared_onchain`): his inputs, partial note and
  outcome key and tag encoded under the three stored keys; the node refuses a tampered copy
  first; the transaction emits one private log and no public log. The relayer lands the result
  through `process_result_shared`; `bob` opens `[0, amount_out]` and takes the note; audited.

## `lending-tip-oblivious.ts`

Lending on the oblivious tree (docs/ARCHITECTURE.md section 6, "The oblivious tree"), experimental, on
`e2e/tip/lending-tip-oblivious.json`: `LendingTipOblivious` with `lending_init_oblivious` and
the ten `<round>_oblivious` entries. Every position index and a liquidation's probe are shared
inputs; an opening names the public flag `opens`; the scan keeps its public window. It runs
`lending-tip.ts`'s secret-shared book without the repayment and the second borrow, so the same
outcomes except the quote's utilisation (8 bps) and nine kept deposits. Then a second
liquidation of `alice`'s position at 1.80, whose notice she does not open; her view gives her a
note with an unspent exit tag. Then the escape hatch: `bob` pokes the idle market's starving
clock, `open_hatch()` 62 blocks later, `alice`'s exit on her first notice is refused (`Existing
nullifier`), she exits on her view's note, and her second exit is refused.

## `credits-tip.ts`

Credits paid to a key (`examples/credits-tip`; docs/ARCHITECTURE.md section 6, "The oblivious sparse map") on
`e2e/tip/credits-tip.json`: `credits_init` and `pay`, `claim`, `view`, `move` under secret-shared
receipt intake, landed through `process_result(<round index>, ...)`. The ledger is a keyed
oblivious map: every key is a shared input. `let` steps compute each handle
(`poseidon2([address, secret])`) and map key (`poseidon2([handle])`) as the contract does.
Notes read `[code, round, a, b]`:

- `bob` pays `alice`'s handle 31 337 (`[0, 1, 31337, 0]`; audited);
- `alice` claims 1 000 (`[0, 2, 1000, 30337]`);
- `bob`'s view of his unpaid key proves it absent (`[0, 3, 0, 0]`);
- `alice` moves 2 000 to `bob`'s handle, inserting his key (`[0, 4, 2000, 28337]`);
- `bob`'s view finds it (`[0, 3, 1, 2000]`).

Each result lands on the previous commitment with one completed note hash. The contract has a
fixed key set, so no transaction reads a key epoch. Gas in the real-proof run, DA / L2 (of it
AVM): the first deployment 16,608 / 1,618,466 (837,991), `configure` 2,176 / 1,446,086
(802,711), the init round 800 / 680,286 (36,911); every round type's request 1,088 / 854,827
(180,652) and result 1,568 / 809,581 (144,431), the same for all four.

## `counter-tip.ts`

The minimal example (`examples/counter-tip`) on `e2e/tip/counter-tip.json`: the init creates
the total 0; `alice` adds 5 (with the node-side negative) and `bob` adds 7, each `counter_add`
under secret-shared receipt intake landed through `process_result`, each on the previous
commitment with one completed note hash; they open `[0, 5]` and `[0, 12]`. The reorg scenarios
run on this deployment.

## `lending-tip-shared-onchain.ts`

Secret-shared on-chain intake in lending on `e2e/tip/lending-tip-shared-onchain.json`: the
secret-shared deployment with `deposit_shared` also registered as `deposit_shared_onchain` (an
alias, intake `shared_onchain`). After the init, `alice`'s funding and the nodes keying the
contract at epoch 1, `alice` deposits 1,500 at position 0 (with the node-side negative): the
amount, her partial note and the outcome key and tag encoded under the stored keys, the escrow
and usage deposit drawn from her credit. The relayer lands it through
`process_shared(ROUND_DEPOSIT, ...)`; she opens `[0, 1, 10^9, 1500, 0, 0, 0]`; audited, the
amount included; `get_kept_deposits` reads 5.

## `amm-tip-replace-node.ts`

Node replacement under load (docs/ARCHITECTURE.md section 6, "Node replacement and key epochs")
on `amm-tip`. A swap lands under key epoch 0; the orchestrator pauses; two swaps queue; node 2
is stopped and a newcomer takes its index (`tipReplaceNode`: its own database, `sidecar-node
setup --newcomer`, `replace-node` on all three, `rotate_keys` landed, the orchestrator
restarted paused on the new keys and resumed, its registry check passing). Both queued swaps
then land in queue order, each on the previous commitment. The newcomer reuses node 2's mesh
certificate and ports (a harness shortcut). The step refuses, before stopping any node, a
deployment whose contract manifest says `node_keys: fixed` (pss-client `assertKeyRotation`).

## `amm-tip-upgrade-circuits.ts`

A circuit upgrade (`examples/amm-tip/README.md`, "Upgrades") on `e2e/tip/amm-tip-upgrade.json`:
the non-secret-shared AMM tip with stale period 4, its upgraded contract manifest
`deployments/amm-tip-next.json` (the swap on `amm_swap_tip_next`, which lands a trade below 100
as a no-op with code 10), the operator the upgrade authority.

- A swap lands; `upgrade_circuits` from another account is refused (`not the upgrade
  authority`); the owner registers the upgraded manifest; the operator schedules it, in force
  one day later; a swap still lands under the deployed circuit.
- With the relayer stopped, one more swap's result is computed under the deployed circuit; L2
  time moves 86,460 s ahead.
- That result is refused (`unexpected verification key`); the client follows the version in
  force; the old request goes stale and is skipped; a swap under `amm_swap_tip_next` lands on
  the last pre-switch commitment, and a swap of 50 lands with code 10. The relayer knows both
  versions (`amm_swap_tip@upgrade`).

## `amm-tip-upgrade-contract.ts`

A class upgrade (`examples/amm-tip/README.md`, "Upgrades") on `e2e/tip/amm-tip-class.json`: the
non-secret-shared AMM tip with stale period 4 and a second class (`CLASS_VERSION` 2 in
`src/class.nr`, built from a staged copy by `engine/contracts.ts`).

- A swap lands; `upgrade_contract` from another account is refused; the operator publishes the
  second class, the owner registers its contract manifest, and the operator schedules the class
  change and its pins, in force one day later; a swap still lands under the deployed class.
- With the relayer stopped, one more swap's result is computed; L2 time moves 86,460 s ahead.
- Every wallet registers the instance with the second class (`get_class_version` answers 2); the
  client follows the new manifest; the relayer, which follows the class itself, lands the
  request queued before the switch (the circuits did not change), then a fresh swap, each on the
  previous commitment.

## The reorg scenarios

Six scenarios revert the chain under the machine, each on the reorg network (`E2E_REORG=1`,
`harness/reorg-network.ts`) and a `counter-tip` deployment of its own; every `reorg` step
refuses the standard network. The reorg network is the CLI's local network with test calls
(pause the sequencer, revert to a checkpoint, its own proving loop on or off) and anvil at
`--slots-in-an-epoch 32`, so the finalized tip trails the latest block by 64 L1 blocks. A revert
is an L1 reorg: the node, its world state and its pool roll back. Blocks are checkpointed at once
and all three nodes read one Aztec node, so a proposed block replaced before its checkpoint and
nodes on different chains are covered by the tip's Rust tests instead.

| Scenario | What it checks |
| --- | --- |
| `reorg-result-again` | A landed result removed: the slot holds the old commitment, `done[index]` unset, the orchestrator logs the replacement, the owner's PXE drops the note; the same result lands again exactly once with no new round at the nodes, and the outcome is delivered again. |
| `reorg-request-removed` | A queued request removed while the pool holds its transaction: the queue is empty, the scheduler drops its attempt, FETCH still serves the signed result; the same request is queued again at the same index and its result lands with no new round. |
| `reorg-reorder` | The replacement chain orders two requests the other way: the first (secret-shared receipt intake) is dropped with its anchor block, another lands first, the first is sent again with the same receipts, recomputed on the new state under a new machine request id, and the outcomes follow the new order. `pollResult`, started before the reorg, reports the first request's own fate at its new index. |
| `reorg-epoch-prune` | Three rounds landed unproven, then an epoch prune: the tips drop to the proven checkpoint, the slot holds that commitment, no node faults; each request is queued again (by the pool or resent) and lands. |
| `reorg-below-settled` | With proving on, a reorg below the proven tip and above the finalized one, after every node's prune pass: no node deleted a version the reorg makes current, both requests land again on the init's state, no node faults. |
| `reorg-init` | The init round removed: the relayer sends it again on its own, the init's slots are written again, and a request runs on them. |

## Gas per transaction kind

A tip run records the gas of every transaction its steps send or land, and of the harness's
deployments, `configure` and init rounds (`engine/gas.ts`: `[gas]` lines in the driver's log and
`<run>/gas-<scenario>.json`; a transaction a reorg dropped is not measured). The L2 gas is the
fee over the block's fee per L2 gas (DA gas costs nothing on the local network and wFJ runs no
teardown); the AVM's part is that less the private part the transaction declares; the DA gas is
metered from the effects. Each app's fee setting (`harness/fee-settings.ts`) fixes one limit per
kind: the kind's largest measurement plus 25%, rounded up to the next 50,000 L2 and 500 DA.
Measured on Aztec 6.0.0, the `amm-tip` rows in the real-proof runs of `amm-tip`,
`amm-tip-shared-onchain`, `amm-tip-replace-node` and `amm-tip-upgrade-circuits`, the
`lending-tip` rows in those of `lending-tip`, `lending-tip-shared-onchain` and
`lending-tip-oblivious` (gas used does not depend on proving):

| App | Kind | Transactions | L2 gas used | of it AVM | DA gas used | Limits, DA / L2 | L2 headroom |
|---|---|---|---|---|---|---|---|
| amm-tip | deploy | `AmmTip`, first (publishes its class) / later | 1,539,937 / 1,436,137 | 759,462 | 33,376 / 2,496 | 42,000 / 1,950,000 | 1.27x |
| amm-tip | configure | each deployment; a key-set rotation (`rotate_keys`, in `amm-tip-replace-node`) | 1,238,639; 1,476,933 | 595,264; 833,558 | 1,792; 2,144 | 3,000 / 1,850,000 | 1.25x |
| amm-tip | request | secret-shared swap, and a swap under receipt intake; secret-shared on-chain swap (`amm-tip-shared-onchain`); on-chain intake; queued behind another | 926,801; 926,801; 949,311; 897,027; 830,675 | 212,626; 212,626; 252,636; 202,852; 136,500 | 1,088; 1,088; 1,696; 1,344; 1,216 | 2,500 / 1,250,000 (receipt checks: one more public call) | 1.32x |
| amm-tip | result | secret-shared swap, filled or failed; non-secret-shared filled; non-secret-shared failed; the init round | 884,054; 886,201; 853,034; 752,050 | 178,904; 202,826; 169,659; 68,675 | 1,568; 1,248; 1,184; 800 | 2,000 / 1,200,000 | 1.35x |
| amm-tip | skip | the stale head | 766,186 | 122,811 | 928 | 1,500 / 1,000,000 | 1.31x |
| lending-tip | deploy | `LendingTip`, first (publishes its class) / later (`LendingTipOblivious`, first: 2,431,124 L2, 1,650,649 AVM, 34,912 DA); a token, first / later; `LendingOracle`, first / later; the harness's mints (`fund`, one transaction per token) | 2,431,205 / 2,308,625; 1,393,008 / 1,289,208; 1,295,791 / 1,191,991; 982,073..1,081,562 | 1,650,730 / 1,631,950; 612,533; 515,316; 198,798..278,287 | 42,400 / 4,000; 17,792 / 1,952; 7,296 / 2,080; 3,104..3,168 | 55,000 / 3,050,000 (DA under the network's per-transaction 55,836) | 1.25x |
| lending-tip | configure | each deployment (`Configured` and the tree access) | 1,886,312 | 1,242,937 | 2,944 | 4,000 / 2,500,000 | 1.33x |
| lending-tip | request | every secret-shared round type, and a deposit under receipt intake, each drawing its escrow and usage deposit from the sender's credit note; a deposit under secret-shared on-chain intake (`lending-tip-shared-onchain`); every round type on the oblivious tree (`lending-tip-oblivious`); a deposit under on-chain intake | 1,107,582; 1,131,835; 1,106,829; 1,079,452 | 294,232; 335,985; 293,479; 286,102 | 3,040; 3,648; 3,040; 3,264 | 6,000 / 1,500,000 | 1.33x |
| lending-tip | result | every secret-shared round type (the delivery handle's note hash and log included); non-secret-shared deposit, its note completed in public by apply; every round type on the oblivious tree; the init round | 1,041,973; 993,903; 1,038,352; 746,192..746,630 | 335,048; 330,528; 331,427; 82,817..83,255 | 2,304; 1,536; 2,304; 800 | 3,500 / 1,400,000 | 1.34x |
| lending-tip | redeem | every round type's note (a borrow's, a withdrawal's, a withdrawal of supply's, a liquidation's), credited privately | 511,400 | 0 | 1,408 | 2,000 / 650,000 | 1.27x |
| lending-tip | skip | none in the run: the AMM's library `skip()` (766,186 L2), two token refunds (about 78,000 L2 of AVM each) and the holdings write, estimated | | | | 3,000 / 1,300,000 | |
| lending-tip | (request) | a credit funding (`fund`, secret-shared deployment / non-secret-shared); `withdraw_funds`; `open_hatch`; the treasury's `sweep_deposits`; a node's `rotate_enc_key`; the oracle's `set_price`; the keeper's `poke` (`lending-tip-oblivious`): what `tx` steps and the harness send under the request kind | 1,074,407 / 1,069,407; 849,219; 701,643; 814,387; 782,127; 791,862; 686,568 | 83,332; 119,969; 58,268; 171,012; 118,752; 148,487; 43,193 | 4,480 / 3,392; 2,176; 800; 928; 928; 992; 800 | 6,000 / 1,500,000 | 1.40x |
| lending-tip | exit | an escape-hatch exit (a borrower's note, which also spends the credit note its repayment draws on; a lender's): private only, no public call | 527,400; 511,400 | 0 | 1,440; 1,408 | 2,000 / 700,000 | 1.33x |

The fee is L2 gas used times the block's fee per L2 gas, which the local network's fee market
moved from about 21,600,000,000 at the first deployments to 10,200,000 by the later rounds of
the lending run (a secret-shared repayment's request paid 11,297,336,400,000 FJ base units, an
escape-hatch exit of a borrower's note 5,379,480,000,000). wFJ's charge, which `pay_fee()` takes
from the sender's private balance with no refund, is the declared limits at the declared max
fees per gas, the wallet's padded estimate: 25,909,096,500,000 for that request under a
1,500,000 L2 limit, about 2.3 times its fee; 12,090,911,700,000 for each exit under 700,000 L2.

A landing mined reverted (`lending-tip`'s atomicity and outbid steps) is not a row: a view's
landing reverted in apply used 768,386 L2, a borrow's reverted in teardown 1,261,973 (under its
own 1,600,000 L2 limit) and the outbidder's reverted copy 933,538, each with DA 736.

What varies inside a kind follows public chain state, never a hidden round type: a first
deployment publishes its class; a request queued behind a pending one uses 66,352 L2 gas less; a
non-secret-shared result that fails writes less, or more when it returns an escrow. Under
secret-shared receipt intake every round type's request and result used the same gas, and so did
the AMM's filled and failed secret-shared swaps (each example's README, "What the world learns
per round type").
