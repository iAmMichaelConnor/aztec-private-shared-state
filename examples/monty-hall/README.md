# Monty Hall on the PSS machine

The client-held example. A per-player game is single-owner state, so every key
it uses is client-held: between rounds the state exists only as a state record
(one sealed third per node) that the user carries and presents at the next round,
and the nodes keep no state rows. The player's door is an INPUT_SHARED secret:
the player sends it as three encrypted replicated shares, and nobody but the
player sees it in the clear.

<!-- bricks:begin -->
## Bricks this example uses

Generated from the `// BRICK` markers in this example's code and `docs/design-guide/design-space.json` (`python3 -I scripts/check-design-space.py --write-bricks`). One row per axis: the option this example plugs in, the library items it calls for it, where, and the alternatives. **Bold**: the example's as-built choice. The combination is this example's; any alternative combines with the rest as [BRICKS.md](../../docs/design-guide/BRICKS.md) says.

| Axis | This example uses | Library calls | Where in this example | Alternatives |
| --- | --- | --- | --- | --- |
| [path](../../docs/design-guide/BRICKS.md#path) | **[`sidecar`](../../docs/design-guide/BRICKS.md#path-sidecar)** | `pss_core::effects::consume_note`, `pss_contract::apply` | [`circuits/monty_hall_open_door/src/main.nr`](circuits/monty_hall_open_door/src/main.nr): `main`; [`contract/montyhall/src/main.nr`](contract/montyhall/src/main.nr): `open_door` | [`tip`](../../docs/design-guide/BRICKS.md#path-tip) |
| [state](../../docs/design-guide/BRICKS.md#state) | **[`client`](../../docs/design-guide/BRICKS.md#state-client)** | none: manifest only (`state`) | — | [`node`](../../docs/design-guide/BRICKS.md#state-node), [`chain`](../../docs/design-guide/BRICKS.md#state-chain) |
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

The circuits are under `circuits/` on `noir/pss_core`, with the game
logic in the `monty_hall` library. Each has the canonical public prefix
(`namespace`, `owner`, `in_slots`, `out_slots`) and returns
`PssEffects<R, W, A>`, so it has 3 + 3R + 2W + P + A public inputs.

| Round | R | W | P | A | PIs | Reads → writes |
| --- | --- | --- | --- | --- | --- | --- |
| `pss_seed` | 0 | 1 | 0 | 0 | 5 | → seed `[s, blinding]` |
| `monty_hall_init` | 1 | 1 | 0 | 0 | 8 | seed → game state (phase initialized) |
| `monty_hall_open_door` | 1 | 1 | 0 | 2 (`opened_door`, `door_commitment`) | 10 | game state → game state (phase opened) |
| `monty_hall_finish` | 1 | 0 | 1 (`switch`) | 1 (`win`) | 8 | game state → nothing (finished) |

`pss_seed` is the generic seed circuit, `examples/amm`'s package reached through the
link `circuits/pss_seed`.
`monty_hall_init` derives the winning door and an in-state PRNG from the seed.
`monty_hall_open_door` takes `door` and `door_randomness` as private INPUT_SHARED
parameters, checks the door is 0, 1 or 2 on shares, and opens a door that is
neither the player's nor the winner. It outputs
`door_commitment(door, door_randomness)` (`monty_hall::door`, the same hash and
separator as the contract's `choose_door`) so the contract can pin it to the
door the player committed. `monty_hall_finish` applies stick or switch and
reveals `win`. The circuits assert the phase stored in the state, so no round can
be proven out of order. The game state is 9 fields plus the blinding (stored
length 10).

## What one evaluation reveals

A user who holds a state gets one evaluation of a round's public outputs (the
consumed set stops a second one, not the first). So the
question for each round is what one evaluation reveals.

| Round | One evaluation reveals | CONSUME on the key it reads |
| --- | --- | --- |
| `pss_seed` | a note hash, hidden by the sampled blinding | none (reads nothing) |
| `monty_hall_init` | the seed's leaf and nullifier and a new note hash; nothing about the winning door | `once` |
| `monty_hall_open_door` | `opened_door`, which rules out one door other than the player's: the game's own reveal. `door_commitment` is hidden by `door_randomness` | `once` |
| `monty_hall_finish` | `win`; with the player's door, the opened door and `switch` it names the winner, and the game is over | `once` |

- **init, `once`.** A second init from the same seed record would make a
  second game with the same winning door. `once` refuses it, and a retry is FETCH
  by request id.
- **open_door, `once`.** Two evaluations with different doors would reveal the
  winning door, and every second request on the state is refused, whatever its
  door or randomness. A retry is FETCH by request id.
- **finish, `once`.** Without it the player could evaluate stick and switch on one
  state and land only the winner. `once` refuses every second request on the
  state; a retry is FETCH by request id.
- **Records are owner-bound.** A game record's associated data names the
  requester's Grumpkin key, and a request that presents it carries that key and a
  signature, so the operator cannot play the player's round. The orchestrator
  sees ciphertext only. The player still gets one evaluation with inputs of their
  choice. The contract refuses a proof whose `door_commitment` is not the
  player's committed door, but the requester has already seen `opened_door`.
- **What the nodes' knowledge is worth.** The game's stake is the hidden information
  itself: two colluding nodes (or all three with every secret) open every game record,
  so they know every winning door, and a player who colludes with them wins every game.
  No funds move through the network (the player's own private function verifies the proof
  over notes it reads itself), so a wager on this game is only as safe as two of the three
  operators are honest.

## Manifests

`manifests/` holds one manifest (intake `direct`, the default) per circuit; `python3 -I
scripts/check-manifests.py` validates them against `docs/manifest.schema.json`.
The circuits' `main.nr` files open with a comment naming each manifest's
settings; the app developer's choices among them (the state mode, the consume policy,
the init strategy, the door's visibility) carry a `DEV DECISION:` marker.

- **Game state: client-held.** Only this game's rounds transition it. The player,
  as the requester of `monty_hall_init`, receives the record that round returns,
  presents it to `open_door` and then presents that round's record to `finish`.
  The request names the game-state key as both `reads[0]` and `writes[0]` in
  `open_door`.
- **Seed: client-held.** The player runs `pss_seed` as the requester, keeps the
  seed's record and presents it to `monty_hall_init`; nobody else needs it.
  Records are owner-bound, so the key that will hold the game record signs the
  seed round too. The operator holds no record: it sends the `init_game` and
  `start_game` transactions that land those two rounds' proofs. With every key
  client-held, the deployment is database-free for state: the nodes keep
  packages, owner keys, the consumed set and past requests, but no values table.
  Node-held would spare the player the seed record at the cost of a row per game.
- **nsk_app** is the fixed `LOAD nsk_app` (slice [0, 1], len 1) in `init`,
  `open_door` and `finish`; `pss_seed` nullifies nothing and takes no key. Every
  round that consumes outputs `npk_app_hash` for the contract's pin.
- **Lengths:** seed `len` 2 (slices [0, 1] and [1, 2]); game state `len` 10 (slices
  [0, 9] and [9, 10]).
- **owner** is the const `0xafafaf`, which the contract must pin.

## The contract's state

The contract (`contract/montyhall`, `MontyHall`) follows the rule for where
state lives (`docs/DECISIONS.md` section 6, "Where state lives on Aztec"; `noir/pss_contract/README.md`):
every value with a single reader is an ordinary PXE note owned by that reader, and the
state nobody may see is in the sidecar. Nothing in this game has two readers, so the
contract anchors nothing and no call takes a preimage or a nonce as an argument.

| State | Kind | Owner | Created in | Read in |
| --- | --- | --- | --- | --- |
| `Config` (player, `owner` const, `npk_app_hash`, four vk hashes) | `PrivateImmutable` note | operator (the caller of `init_game`) | `init_game` | `start_game` |
| `Game` (`owner` const, `npk_app_hash`, open and finish vk hashes) | note at a `PrivateImmutable` slot | player | `start_game`, delivered to the player | `choose_door`, `open_door`, `switch_door`, `finish_game` |
| door choice (`DoorNote`, hash = the door commitment) | `PrivateImmutable` note | player | `choose_door` | `open_door` |
| switch choice (`SwitchNote`) | `PrivateImmutable` note | player | `switch_door` | `finish_game` |
| seed, game state | network-held raw note hashes; client-held records | the player's requester key | `init_game`, `start_game`, `open_door` | the next round; nonces mined from the tx's effects |

Every call reads its caller's own note, so the note is the access control: only the
operator holds a `Config` and only the player a `Game`. Three points are
commented in `main.nr`:

- **The Game has no initialisation nullifier.** `PrivateImmutable::initialize` derives
  it from the owner's nullifier key, which the operator does not hold for the player,
  so `start_game` creates the note at the slot directly. It is created once because
  `start_game` spends the one seed note.
- **The once-nullifier stays in `init_game`.** The Config's initialisation nullifier is
  per owner and would not stop a second account from seeding a second game, and so a
  second `Game` note, on the deployment. The constant once-nullifier makes the
  deployment single-game.
- **Delivery of the Game note.** `start_game` runs in the operator's PXE and delivers
  the player's note on chain, unconstrained. What the two wallets need, read from the
  pinned PXE and aztec-nr; the e2e's two-wallet scenarios (operator and player in
  separate PXEs, `e2e/scenarios/README.md`) confirm each point: `monty-two-wallets` the
  first and the last, `monty-registered-sender` and `monty-late-sender` the second:
  - the player's PXE must find the note's tag. An operator wallet without a tagging
    hook (the `EmbeddedWallet` default) does not hold the player's keys, so its PXE
    tags the delivery through a non-interactive handshake with the standard handshake
    registry, inside `start_game` (which then pushes a third note hash, the
    operator's handshake note). The player's PXE discovers the handshake in its sync
    and finds the note at its next call; the player's wallet registers nothing;
  - an operator wallet whose tagging hook (`resolveTaggingSecretStrategy`) picks the
    address-derived (operator, player) secret instead makes no handshake, so
    `start_game` pushes two note hashes, and the note is found only by a PXE that
    knows the operator as a sender: the player's wallet registers it
    (`registerSender`), best when it learns the deployment. Registering it after
    `start_game` is mined still finds the note: until then the player's PXE finds
    no `Game` note, and the registration makes it scan the operator's tags from
    index 0 and re-sync the contract at the player's next call. When both
    accounts are in one wallet (the `monty` scenario), the delivery is a self-send,
    tagged with this secret whatever the hook, and the PXE scans its own accounts;
  - the operator's PXE needs only the player's address, not its keys or complete
    address: the note hash takes the owner as a field, the encryption and the tag use
    the point derived from the address, and aztec-nr's `get_public_keys` (which fails
    for an account the PXE has not registered) is reached only by a nullifier and by
    `PrivateImmutable::initialize`, which `start_game` does not run.

The reads use aztec-nr's `get_note`, which fails the caller's own call when its note is
missing. No other party can create or remove these notes, so no other party can make a
read fail, and the flagged reads of total-noir's `total_aztec` are not needed here.

## Checks

```sh
scripts/check-noir.sh examples/monty-hall --outputs examples/monty-hall/circuits/outputs.txt   # compile, library tests, execute and check each Prover.toml
python3 -I scripts/check-manifests.py
```

The `Prover.toml` fixtures are one scenario: seed 111 (winning door 1), the
player plays door 2, the host opens door 0, and the player switches and wins.

The contract is on these circuits: `init_game` applies `pss_seed`, `start_game`
`monty_hall_init`, `open_door` `monty_hall_open_door` and `finish_game`
`monty_hall_finish`, with `choose_door` and `switch_door` between them. Its TXE suite (`contract/montyhall_test`) runs with
`scripts/txe.sh --contracts --only examples/monty-hall`.

The end-to-end scenario is `e2e/scenarios/monty.ts` (see `e2e/scenarios/README.md`),
which the generic driver `e2e/driver.ts` runs: it registers the four circuits, plays a full game with real proofs on a local network,
the player carrying every record and signing every round, and checks each refusal of
the record path.

```sh
EXPECT_REAL_PROOFS=1 e2e/run.sh monty
```

`LICENSE` is the licence of TaceoLabs' application this example derives from,
[TaceoLabs/monty-hall-aztec](https://github.com/TaceoLabs/monty-hall-aztec) (the root `NOTICE`
lists it; `docs/PROVENANCE.md` says what changed).
