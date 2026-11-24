# PSS design guide

For an app developer designing an app on private shared state (PSS): the questions to
answer, in order of consequence, what each answer costs and leaks, which choices combine,
the blueprint the answers land on, and the example and code to start from. The mechanism is
[ARCHITECTURE.md](../ARCHITECTURE.md) (the tip is its section 6, the manifest section 7);
trust, operation and the configuration reference are [DESIGN.md](../DESIGN.md); the reasons
for each settled choice are [DECISIONS.md](../DECISIONS.md).

- `design-space.json` (this directory) is the source: axes and values, constraints and
  compatibility rules, bricks (paths, statuses, the library items an app calls), examples,
  blueprints, the party and leakage tables, parameters. The blocks marked generated below are
  rendered from it by `python3 -I scripts/check-design-space.py --write-readme`; the check
  fails when they drift, and where this page and the JSON differ, the JSON wins.
- `python3 -I scripts/check-design-space.py --plan <blueprint>` prints a blueprint as a
  starting plan (values, bricks with paths and statuses, example, files to start from, allowed
  deviations with the bricks each adds and drops); `--plan <axis>=<value> ...` checks any
  other combination; `--compat` prints the compatibility of every value pair.
- [BRICKS.md](BRICKS.md), generated from the JSON, gives for each option what it is, when to
  choose it, its alternatives, what it never combines with, and the library items an app
  calls, by contract, circuit and client.

## How to read this guide

**Terms** are [GLOSSARY.md](../GLOSSARY.md)'s, used exactly. A PSS app is one value per
axis, its round circuits (a total transition function with its validity checks and outcome
fields), a contract on the contract library and a client on pss-client.

**Statuses.** built; to build (designed, not built); kept option; deferred (REGISTER refuses
it); experimental (offered for trial, never a default); not offered (a constraint forbids
it). Everything this guide recommends is built; [Not built, or
experimental](#not-built-or-experimental) lists the rest.

**Two judges for every answer**: invariant 0 (a leak of all three nodes' secrets may cost
privacy and freeze funds, never take or lose them) and minimal PSS (only the essential shared
state is PSS; everything else is user-owned notes). Both are [fixed
properties](#fixed-properties).

## The decision tree

| # | Question | Default | Sets |
| --- | --- | --- | --- |
| 1 | [What must be shared at all?](#1-what-must-be-shared-at-all) | minimal PSS: notes for everything else | whether PSS is needed; what the state vector holds |
| 2 | [Where does the shared state live?](#2-where-does-the-shared-state-live) | node-held; flat, or a clear-index tree for a book | state mode, state shape |
| 3 | [Which path: the sidecar path or the tip?](#3-which-path-the-sidecar-path-or-the-tip) | the tip for state many users share | path, submission |
| 4 | [Who may request, and the usage deposit](#4-who-may-request-and-the-usage-deposit) | open; a usage deposit drawn from the user's private balance in the app | access control, usage deposit |
| 5 | [Intake: how do the inputs reach the network?](#5-intake-how-do-the-inputs-reach-the-network) | secret-shared receipt intake | intake |
| 6 | [Outputs: public or private?](#6-outputs-public-or-private) | follows the intake family | outputs, delivery |
| 7 | [Value delivery: how does value reach the user?](#7-value-delivery-how-does-value-reach-the-user) | partial-note completion, the one form | value delivery, the spend (`redeem`) |
| 8 | [Ownership: who may act on an entry?](#8-ownership-who-may-act-on-an-entry) | a user-owned note, proven in the user's private function | the request function, the leaf |
| 9 | [Outcome delivery and keys](#9-outcome-delivery-and-keys) | constrained in the circuit, one-time keys derived by the client | delivery, the client's derivations |
| 10 | [Who lands the result?](#10-who-lands-the-result) | the relayer at the tip; the user on the sidecar path | submission |
| 11 | [Binding and pinned reads](#11-binding-and-pinned-reads) | turn; `exact` freshness | binding, freshness |
| 12 | [Fees](#12-fees) | the private fee-payment contract | the fee method |
| 13 | [Keeper rounds and discovery](#13-keeper-rounds-and-discovery) | a clock-gated round when the targets are known; else a read-only window round, then act rounds | the keeper round, `W` |
| 14 | [Node replacement, recovery and liveness](#14-node-replacement-recovery-and-liveness) | key epochs; an escape hatch for a tree | node keys; `stale_blocks`; state mode; the hatch's liveness period |
| 15 | [Upgrades: may the circuits change?](#15-upgrades-may-the-circuits-change) | fixed | upgrades; the upgrade authority and delay |

Each question gives the options with their statuses, the default and why, the cost, what it
leaks and to whom, the code to start from and the compatibility rules that apply.

### 1. What must be shared at all?

**Question.** Which values must the network compute on together with other users' values,
with nobody seeing them? Only those go on PSS; everything else stays Aztec notes the user's
PXE holds.

| Answer | Then | Status |
| --- | --- | --- |
| Nothing: every value belongs to one user, and no hidden rule must be enforced on it by others | no PSS: plain Aztec notes, private functions and partial notes | outside this design |
| One user's state must stay hidden from that user too, with the network enforcing the rule (a game against the house, a sealed commitment, a credential whose use is enforced) | the sidecar path with client-held state, blueprint `note-client` | built |
| Some state is computed on by many users and must be seen by none (a pool's reserves, a book's positions, a sealed auction's bids), or drawn on under rules the network enforces while its owner is offline (a treasury its members claim from) | the essential part on PSS, the rest as notes; continue with question 2 | built |

**Default: minimal PSS.** The test for each value: does any round need it together with
another user's value, or must another user's round probe or scan it (a liquidator's, a
keeper's)? If not, it is a note: ownership, a user's balances and view of its entries,
outcomes and payouts, its balance in the app, escrow, deposits and refunds. Ask also who must
be paid or told something by each round: a round delivers value to its requester only
(question 7), so every other such party (an auction's winner, an employee) needs an entry and
a round of its own. Lending's split, value by value, is in `examples/lending-tip/README.md`,
"What is a note, what is shared"; the AMM's is the pool's reserves on PSS and everything else as notes.

**Cost and leaks.** A value on PSS costs MPC work in every round that touches it (about 80
gates per shared Poseidon2 permutation, inside a 2^14-gate budget per round); one node learns
nothing of it, two colluding nodes everything. A note costs nothing in the MPC and leaks
nothing to anyone but the user. The app's leakage statement says what the shared part is
worth to two colluding nodes (front-running a trade within its `min_out`, the first
liquidation of every unhealthy position, a game's hidden answer).

**Start from.** The app library's state vector:
`examples/lending-tip/circuits/lending_tip/src/market.nr` (the leaf and the header),
`examples/amm-swap-total` (the pool).

### 2. Where does the shared state live?

**Question.** Between rounds, where is each key's state, and is it a small fixed vector or a
large, growing book?

| Option | Status | Lives | On chain | For |
| --- | --- | --- | --- | --- |
| client-held | built | the user carries a sealed record (one third per node) and presents it in its next request | the user's own note hashes and nullifiers | state that belongs to one user; sidecar path only |
| node-held, flat (default) | built | the three nodes' stores, as Rep3 pairs, one version per commitment | one commitment per key | a small fixed vector: a pool's reserves, a counter, a best bid |
| node-held, tree with a clear index (recommended for a book) | built | the leaves as Rep3 pairs, the tree of hashes in the clear | one commitment to the root | a large or growing book where each round touches a few entries |
| chain-held | kept option | every apply logs the whole new state sealed to the nodes' keys | the commitment and the sealed state, every apply | a small fixed state recoverable from the logs with the nodes' keys and the package |
| node-held, tree with an oblivious index | experimental | as the tree, in a distributed oblivious RAM the nodes hold as shares, the index a shared input (`access: oblivious`) | one commitment to the root | a book whose touched indices must be hidden from the nodes too |
| node-held, keyed map (oblivious) | experimental | a sparse tree over a key's low 32 to 120 bits in the same DORAM, bounded by a capacity (`access: oblivious, keyed: true`) | one commitment to the root | state addressed by a key, never enumerated: credits paid to an owner commitment before its owner acts, a registry, a spent-identifier set |

**Default.** Node-held: flat for a small fixed vector, a clear-index tree for a book. The
nodes see which leaves a clear-index round touches, but under partial-note completion the
owner's address never enters the circuit, so a node learns that position 41 moved, not whose
it is. The oblivious tree hides the index from the nodes too.

**Cost.**

- Flat: every round loads and rewrites the whole vector (the AMM's three-element pool: 4,450
  gates under a non-secret-shared intake, 4,910 under a secret-shared one).
- Tree: `K·D` shared Poseidon2 permutations per round for probe width `K` and depth `D`,
  sequential in depth, so the link latency between the nodes sets the round time; capacity
  `2^D - 1`. Lending at `D = 16`, `K = 2`, eight-element leaves: 10,798 to 15,795 gates per
  round (`examples/lending-tip/README.md`, "Capacity"). Pick `K` as the largest width at which
  every round fits 2^14 (16,384) gates.
- Chain-held: the whole sealed state in every apply's public log, at most 4,094 fields per
  transaction (453 elements for one output).
- Client-held: the user keeps its record (FETCH recovers a lost one) and signs every request
  that presents one; the nodes keep no rows.
- Oblivious tree: fewer gates than the clear index (111 to 203 per lending round), but about
  200 sequential DORAM communication steps per round on the link, and about 1.7 GB per node
  for a 2^20-address DORAM (`docs/ARCHITECTURE.md` section 6, "The DORAM and its
measurements").

**Leaks.** Node-held: a commitment on chain; one node nothing; two nodes the whole state.
Clear-index tree: the nodes see which leaves each request touches, so they can link the
requests on one position and tell which are active. Chain-held: the sealed states stay on
chain for good, so a later break of two nodes' `enc` scalars, or of the Grumpkin key exchange,
opens every past state. Client-held: a full compromise opens every record. Oblivious tree:
hides the index from the nodes only; one node still sees the round type, the probe count, the
public opening flag and the append index.

**Start from.** The manifest's `state {key: client | node | chain}` and `tree {key: {depth,
leaf_len, probe, header, index, open, window, ...}}` (`docs/manifest.schema.json`); the round
helpers in `noir/pss_core/src/tip/tree.nr`. Examples: client-held `examples/monty-hall`; flat
`examples/counter-tip`, `examples/amm-tip`, `examples/amm` (sidecar path); tree
`examples/lending-tip`, with its oblivious deployment; keyed map `examples/credits-tip`;
chain-held `machine/circuits/tip_counter`. The mechanism: `docs/ARCHITECTURE.md` section 6,
"State modes at the tip", "Tree-valued keys", "The oblivious tree".

**Rules.** `state-mode-follows-path`, `tree-is-node-held-tip`, `one-layout-per-key`,
`oblivious-index-is-shared`. A tree with an `open` input has a header (`header: true`) and
takes its new index from the header's `next_index`.

### 3. Which path: the sidecar path or the tip?

**Question.** Does the result land in the requester's own private function, or through a
public queue that many users share?

| | Sidecar path | Tip |
| --- | --- | --- |
| Intake | `direct`: the client POSTs `/v1/execute` to the orchestrator | any queued intake (question 5) |
| Who lands the result | the user, in its own transaction, after verifying the co-SNARK in its private function | the relayer (or anyone) sends `process_result`; the contract verifies the co-SNARK and the node signatures |
| State | client-held, or node-held rows | node-held (flat or tree) or chain-held |
| Composability | one transaction, composable with any other private call | the result lands one queue turn later, never inside the user's transaction |

**Default.** The tip for state many users transition concurrently; the sidecar path for
per-user state. A node row on the sidecar path suits shared state with little contention whose
result must land inside the user's own transaction.

**Cost.** Sidecar: one user transaction; a node row commits at the nodes before its
transaction lands, so concurrent users wait on each other, and a transaction that never lands
needs the operator's rollback. Tip: a request transaction and a result transaction; latency one
queue turn (minutes with real proofs); the operator runs the scheduler, the chain reader and
the relayer.

**Leaks.** Sidecar: the nodes and the orchestrator see the PUBLIC inputs and the outputs, and a
record-presenting request is signed by its owner's key. Tip: the requester is hidden from the
chain and the nodes on every intake; on the receipt routes the orchestrator sees the user's
network address.

**Start from.** Sidecar: `noir/pss_contract/src`, `noir/pss_core/src/effects.nr`,
`examples/monty-hall`. Tip: `noir/pss_public_contract/src`, `examples/counter-tip`.

**Rules.** `path-follows-intake`, `binding-follows-path`, `sidecar-user-lands`,
`sidecar-node-contention`.

### 4. Who may request, and the usage deposit

**Question.** Who may put a request in the queue, and what stops a stranger from filling it
with junk under a hidden requester?

| Option | Status | How |
| --- | --- | --- |
| open (default) | built | the machine admits every request; the request wrapper checks static validity (`is_valid`) |
| credentialed | built (the app's own check) | the private request function reads a credential note of the app's own type (with its inclusion check, never nullified, as lending's `assert_holds` reads a position note) or checks an issuer's signature; never a shared input, which the nodes could forge |
| usage deposit (the queue's anti-spam) | built (`pss_public_contract` `token`) | the private request function draws a pinned amount of a pinned token from the user's credit note and commits a refund note that binds the amount; the public wrapper records only the commitment |
| who may call `skip()` | built | anyone by default; the app's `skip()` wrapper may restrict it |

**Default.** Open requests, open `skip()`, and the usage deposit. The token, the amount and
whether a served round keeps the deposit are the app's pins (`UsageDeposit` in its Config,
`kept` a `DEV DECISION`, refunded by default); lending keeps it, in its borrowed asset, and
sweeps it to a treasury (`sweep_deposits()`). Refunds follow [the refund
rule](../ARCHITECTURE.md#the-refund-rule):
a refund note that public `skip()` or `apply` completes, never a round. `skip()` always
refunds, and so does `apply` for a round whose shares did not open `C`: a kept deposit on
either is forbidden, since a network must never earn from skipping heads (invariant 0). An app
that takes value in at request (lending's deposit, repayment, supply, liquidation budget) draws
that escrow from the same credit note with a second refund note (`token::commit_refunds`). The
user funds its credit in a transaction of its own (lending's `fund`) and withdraws with
`withdraw_funds`.

**Why.** A hidden requester has no identity to rate-limit; only a payment the request makes
prices the queue. A round that opens a note or a credential is already priced by it, so an app
with no open round may set the deposit to 0. A declared gas maximum is not a payment.

**Cost and leaks.** Every request spends one credit note and commits two refund notes, the same
on every round type, so no request shows its deposit, escrow, class or amount. A fund and a
withdrawal show their amounts, linked to no request except by timing and amount (fund in
advance and in round amounts). A junk head holds the queue for at most `stale_blocks` (50 L2
blocks in the examples). The mechanism: `docs/ARCHITECTURE.md` section 6, "Tokens and escrow".

**Start from.** `noir/pss_public_contract/src/token.nr`; lending's `Credit` note and Config
(`examples/lending-tip/contract/lending_market/src/app.nr`) and its `fund`, `escrow`,
`withdraw_funds`, `skip()`, `apply_shared` and `sweep_deposits` (`storage.nr`). The AMM tip
moves no token and takes no deposit.

### 5. Intake: how do the inputs reach the network?

**Question.** Who may see a request's inputs, and may the request need an off-chain step?

| Intake (manifest) | Family | Status | Inputs reach the network | Use |
| --- | --- | --- | --- | --- |
| direct (`direct`) | sidecar path | built | the client POSTs to the orchestrator; PUBLIC inputs clear, INPUT_SHARED inputs one Rep3 pair per node | the sidecar path |
| secret-shared receipt intake (`shared_receipt`) | secret-shared | built, the default | the client sends each node its Rep3 pairs and a hiding commitment `C`; each node signs a receipt; the request function proves the sharing opens `C`; only the request id and expiry reach the chain | every tip app |
| secret-shared on-chain intake (`shared_onchain`) | secret-shared | built | the user's private function writes the shares into one private log only the nodes can open | no off-chain step; `tip-chain` |
| receipt intake (`receipt`) | non-secret-shared | built (a test path) | the inputs reach the nodes in the clear over TLS; three receipts | tests, trusted-operator deployments |
| on-chain intake (`onchain`) | non-secret-shared | built (a test path) | the inputs and a random `user_nonce` in a public request log | tests; inputs that may be public |
| relayed intake (`relayed`) | — | deferred | the network would submit the request transaction; REGISTER refuses it | — |

**Default.** Secret-shared receipt intake: nobody but the user holds an input or a touched state
value in the clear, no ciphertext of an input reaches the chain, and the round type can be
hidden. Choose secret-shared on-chain intake only when the request transaction must be the
whole intake. Every queued round binds its inputs through `C = poseidon2(inputs, blinding)`; a
round whose shares do not open `C` (only nodes that changed their shares make one) lands as an
`ok = 0` no-op with the app's mismatch code (`docs/ARCHITECTURE.md` section 6, "Secret-shared
intake").

**Cost.** A secret-shared round adds about 460 gates (the AMM swap, 4,910 against 4,450) to 900
(lending); the user's private proof checks the sharing in about ten Poseidon2 permutations.
Secret-shared receipt intake adds one round trip to the orchestrator before the request
transaction. Gas (tip e2e, real proofs): a secret-shared receipt request 1,088 DA / 929,961 L2;
a secret-shared on-chain request 1,696 / 908,542.

**Leaks.** See [what each party sees](#what-each-party-sees). On-chain intake shows every input
to the world, receipt intake to the nodes and the orchestrator, the secret-shared intakes to
nobody but the user, except the clear app inputs (lending's position indices) and `C`. On the
receipt routes the orchestrator links the user's network address to the request; a relay or a
mixnet (outside the build) hides it. Secret-shared on-chain intake keeps the encoded shares on
chain for good.

**Start from.** The manifest's `intake`; `noir/pss_public_contract/src/shared_intake.nr`,
`shared_onchain.nr`, `receipt.nr`, `intake.nr`; `ts/pss-client/src/intake-shared-receipt.ts`,
`intake-shared-onchain.ts`. Which inputs are INPUT_SHARED is a `DEV DECISION` in
`ts/pss-client/src/request.ts` and the round's main. Every round of `examples/amm-tip` and
`examples/lending-tip` runs under secret-shared receipt intake; the AMM's swap and lending's
deposit also under the other three. Another intake for a round: [Running a round under
another intake](#running-a-round-under-another-intake).

**Rules.** `outputs-follow-family`, `one-intake-family-per-namespace`,
`one-circuit-per-round-per-family`, `package-list-is-the-address`, `register-bounds`.

### 6. Outputs: public or private?

**Question.** Who may learn the round's outcome?

| Option | Status | What lands |
| --- | --- | --- |
| private outcomes | built | the outcome note hashes the circuit computed and one 16-field private log `[outcome_tag, note_hash, ciphertext]`; `apply` marks the request done and writes the commitments |
| public outputs | built | proof public inputs; at the tip `apply` completes the user's partial note with them (`outcome: partial`, the owner hidden) or the app's hook stores them (`outcome: none`) |

**Default.** It follows the intake family: private under a secret-shared intake, public under
the non-secret-shared intakes and on the sidecar path. A secret-shared app cannot choose public
outputs, even for a result public by nature (an auction's clearing price reaches each party in
its own note).

**Cost and leaks.** Private: an AEAD and a note hash inside the MPC; the outcome reaches the
user only, and every round draws a fresh blinding, so the slot write reveals nothing about `ok`
(a tree round that fails to place keeps its commitment). Public: no cost, but the world learns
the outcome and often the state.

**App values.** A round under private outcomes may output public values for its contract
(`pss_core` `Finished::valued`, `pss_public_contract` `outcome::Private::valued`, the
manifest's `app_values`): never an amount, an owner or anything of the outcome. An app that
escrows puts the public inputs-opened bit last and passes it to `token::settle_applied`, so
`apply` refunds the escrow and the deposit when the shares did not open `C`.

**Start from.** `noir/pss_public_contract/src/outcome.nr`, `noir/pss_core/src/tip/outcome.nr`,
`ts/pss-client/src/discovery.ts` (`OutcomeReader`).

**Rules.** `outputs-follow-family`, `delivery-follows-outputs`, `value-follows-intake`.

### 7. Value delivery: how does value reach the user?

**Question.** Does the round move value to the user, and in which transaction?

| Option | Status | How | Who sees the value |
| --- | --- | --- | --- |
| partial-note completion (`outcome: partial`) | built; the default under every queued intake | the request function commits a partial note `P` of its sender (`partial_note::commit`), the reserved value `$partial_note`; the network completes it in the co-SNARK (private result) or in `apply` (public result) | nobody but the user; under a public result the amount is public, the owner hidden |
| none (`outcome: none`) | built | no note: the public outputs go to the app's hook in `apply`; an init round; always on the sidecar path; refused under a secret-shared intake | everyone who reads the outputs |

**Default.** Partial-note completion, the one form of value delivery: the value lands with the
result as the user's own note of the app contract, and the user's address never enters the
circuit. The result transaction calls no other contract and shows the relayer nothing
value-bearing, so any user can FETCH and land its own result. A refund is a second partial note
that public functions complete (question 4).

**Who receives.** The requester, and the holder of a delivery handle. A request commits one
partial note, of an owner the sender's PXE holds, and the round completes that one note.
Another party is reached only through a handle it left itself (`pss_core` `tip::handle`,
`pss_public_contract` `handle`, pss-client `handle.ts`): its own request writes a partial
commitment and an outcome key into its entry, and any round another party requests that writes
the entry completes it, each completion another note, until its next request writes a new one.
The handle authorises nothing. Every round of an app that uses it outputs the same number of
deliveries (a filler where nothing is delivered), so the round type and whether anyone was
notified stay hidden. Lending's liquidation completes the liquidated owner's handle. Without a
handle, every other party gets its value through a round of its own on a note of its own (an
auction's winner claims on its bid note).

**The spend.** A completed note is spent once by the app's `redeem(request_id)`. The AMM's
nullifies the note and returns its `amount_out` (a real token's payout is `redeem`'s
`DEV DECISION`). Lending's pushes a redeem nullifier, so the note stays readable and keeps
conferring its position, and credits the settlement to the user's credit note.

**Cost.** Completion in the co-SNARK: the AMM's secret-shared swap 4,910 gates, lending's rounds
10,798 to 15,795 (handle and exit tag included); one note hash and the 16-field outcome log,
one more of each per delivery. Completion in `apply`: one more public input (`P` after `ok`),
one note hash and one public completion log. The private circuit adds one Poseidon2 for `P` and
its use nullifier either way.

**Start from.** `docs/ARCHITECTURE.md` section 6, "Partial-note delivery";
`noir/pss_public_contract/src/partial_note.nr`, `handle.nr`, `result.nr`;
`noir/pss_core/src/tip/outcome.nr`, `tip/handle.nr`; `ts/pss-client/src/secrets.ts`,
`outcome.ts`, `handle.ts`. BRICKS.md, "Other bricks", lists what to call.

**Rules.** `value-follows-intake`, `delivery-follows-outputs`.

### 8. Ownership: who may act on an entry?

**Question.** When an app has per-user entries in shared state, how does a round know the
requester may act on one, with no requester address anywhere?

| Option | Status | How |
| --- | --- | --- |
| a user-owned note, proven in the user's private function | built (lending); the default | the owner opens a completed note of the entry (lending's `assert_holds`: owner `msg_sender`, read with its inclusion check, never nullified) and commits the next partial note to itself; the round has no owner check and the leaf no owner |
| none | built | rounds anyone may make: an opening deposit, a liquidation, a scan, a quote |

**Default.** The note. A position note is never nullified (it is the owner's proof and view);
its payout is spent once through a redeem nullifier. A round names a position in its note
exactly when it vouches for the requester's leaf. A delegate acting by the owner's authwit is
not built.

**Cost and leaks.** One note read in the request function; no owner check in the MPC. A full
compromise acts on nobody's entry: the nodes never see an owner. An index is never reassigned
and a position is not transferable. Another party's round reaches the owner through its
delivery handle (question 7), or the owner sees its newest note's exit tag spent (pss-client
`liveExitNote`, `exitTagSpentAt`). Residual: an entry another party's round wrote twice after
its owner's last request cannot exit a frozen app.

**Start from.** `examples/lending-tip` (`assert_holds`, `redeem`, the request functions, the
`LendingOutcome` note); `noir/pss_public_contract/src/partial_note.nr` (`commit`,
`assert_owned`, `redeem`); `docs/ARCHITECTURE.md` section 6, "Ownership by note".

### 9. Outcome delivery and keys

**Question.** How does data for the user reach it in a form a misbehaving node cannot spoil?

**Options** (the delivery axis). `constrained` (built, the default for private outcomes: the
circuit encrypts with the Poseidon2 duplex AEAD under a key the recipient supplied and exposes
the ciphertext as public outputs, so a result lands only if its recipient can open it);
`clear` (built: public outputs); node-sealed to a user (not offered).

**Keys.** The user's one-time `$outcome_key` and `$outcome_tag` travel as shared inputs inside
`C`, so no key exchange runs in the MPC. `rho`, the outcome key and the tag derive from the
wallet secret and a per-namespace request counter (pss-client `SecretStore`), so a client that
loses its state recovers by rescanning tags (gap limit 20). The nodes' `enc` keys (envelopes)
and `sig` keys (receipts, result signatures) are checked by the client and, at the tip, by the
contract (question 14).

**Cost and leaks.** The AEAD and note hash cost shared permutations in every private round; the
log is 16 fields on every round type, and the world sees nothing beyond it and a note hash. The
client finds the log by tag (`OutcomeReader`) and hands its PXE the note. Withholding a result
is a liveness question (`skip()` bounds it).

**Start from.** `noir/pss_core/src/tip/outcome.nr` (`encrypt_outcome`),
`noir/pss_utils/src/ae.nr`, `ts/pss-client/src/discovery.ts`, `secrets.ts`.

### 10. Who lands the result?

The relayer (`ts/pss-relayer/src/relayer.ts`, operator-run, tip only: FETCHes the head's
result, sends `process_result`, sends `skip()` on a stale head, lands the init round), or the
user (or anyone: `process_result` is open; pss-client's `submitResult`). On the sidecar path it
is always the user. **Default:** the relayer at the tip. **Cost:** an operator service to run
and fund; a user who lands its own result watches the queue and pays. **Leaks:** the relayer
sees the result's public inputs (ciphertext, hashes, commitments; under public outputs the
outputs and `P`).

### 11. Binding and pinned reads

**Binding.** `turn` (built, the default: the state as it is when the request's turn comes; a
total circuit turns a request the state no longer allows into an `ok = 0` no-op) or `exact`
(deferred). Under `turn` slippage limits belong in the inputs (`min_out`).

**Pinned reads.** A public call the manifest fixes (an oracle's price), simulated by the
scheduler, re-read by each node and made again by `apply`, which admits the value under the
read's freshness:

| Freshness | `apply` accepts | Use |
| --- | --- | --- |
| `exact` (default) | the current value | values a trusted party moves rarely; a value that moves faster than a round lands starves the head until `skip()` |
| `epoch` | the current epoch or the one before; the source offers the previous value only within a window of blocks after each new epoch | a feed that publishes epochs at least `L` blocks apart (lending's oracle, `previous_blocks`) |
| `tolerance` | a value within an absolute or relative band | a value that drifts |

**Leaks and worth.** The network may land an attempt at any value the policy admits, the one
that suits it; the app states what that is worth (a liquidation at the older of two epochs'
prices). The oracle's owner is a trust assumption of its own, outside invariant 0.

**Start from.** The manifest's `binding` and `public_reads[].freshness`;
`noir/pss_public_contract/src/result.nr` (`Freshness`);
`examples/lending-tip/contract/lending_oracle`; `docs/ARCHITECTURE.md` section 6, "Pinned
reads".

### 12. Fees

The fee method is a `DEV DECISION` in `ts/pss-client/src/fee.ts`: Wonderland's private
fee-payment contract (wFJ, the default: every tip transaction shows the same fee payer), an
app-sponsored fee-payment contract, or the sender's own account (which names the sender). Each
payer funds a private balance in a dedicated transaction. One gas setting per app and
transaction kind, equal across round types (the e2e's largest measurement plus 25%), so the fee
tells no round type apart; timing, gas and L1 deposits stay public. The fee is not the
anti-spam; the usage deposit is.

### 13. Keeper rounds and discovery

**Question.** When nobody can see the state in the clear, how does maintenance (a liquidation,
an expiry, a match) find its targets?

| Option | Status | Cost per pass over `n` entries | Leaks |
| --- | --- | --- | --- |
| a clock-gated round: clear inputs name the target, a pinned clock read gates the effect | built (the round is the app's, in no example) | one round per target | the target to whoever sees the clear inputs |
| sweeping by probing rounds | built | about `2^D / (K - 1)` rounds | one bit of the app's predicate per probed entry to the prober |
| a read-only window round, then act rounds | built (the manifest's `tree` `window`, `W` at most 8; pss-client's keeper loop) | about `ceil(n / W)` rounds, then one act round per `K - 1` reported indices | `W` bits and the window's occupancy to the requester; the window to the nodes |

**Default.** For targets known by clear inputs or time, the clock-gated round (an auction's
close after its end block). For targets hidden in the state, the window round reports the
indices the app's predicate names and act rounds act on them; both stay total and under 2^14,
and the act round re-checks its own condition, since the state may move in between. Lending's
scan (`W = 8`, 15,795 gates) reports unhealthy positions and its liquidation is the act round;
its discovery is open, a lottery among keepers (`../DECISIONS.md` section 7).

**Leaks and worth.** The reported bits are the requester's edge for one queue turn. A window
round that touches the header should re-blind it. An act round that leaves unchanged slots
unwritten shows one node which probes it skipped.

**Start from.** `docs/ARCHITECTURE.md` section 6, "A read-only window on a tree key";
`noir/pss_core/src/tip/tree.nr` (`Tree::window`); `ts/pss-client/src/keeper.ts`;
`examples/lending-tip/circuits/scan_shared`, `liquidate_shared`.

### 14. Node replacement, recovery and liveness

**Facts every app inherits.** Under key epochs two of the three current nodes sign a new key
set, the old one accepted for `stale_blocks` blocks, and the remaining nodes refresh every
sharing before the newcomer imports its pairs; what was sealed to the departed node alone
(client-held and chain-held record thirds, secret-shared receipt envelopes) is lost. Node-held
state survives one lost store (resync, encrypted backups), not two. Chain-held recovery
needs the nodes' keys, the package, and a matching log in the 64 queue entries before
the head or the init round. Chain-held state does not survive a node replacement.
Three absent nodes freeze every namespace at its last commitments. For apps that take
escrow or usage deposits, the public skip wrapper can refund them without the nodes
when the stale period is enabled and the wrapper calls `token::refund_skipped`.

**The escape hatch** (a tree-valued key). Each owner of an entry leaves a frozen app on its
newest note, privately, with no node. The app's part:

- every round that writes an entry stores the exit tag of the note it issues for it in the leaf
  (`Tree::update_private_tagged`), so each entry has one unspent tag, its newest note's;
- a round that names another owner's entry writes only the slots it changes and issues the
  owner a note through its delivery handle;
- the contract keeps a `Hatch` (`pss_public_contract` `hatch`): request wrappers and a
  permissionless `poke()` call `Hatch::queued`, every apply `Hatch::landed`, `open_hatch()`
  `Hatch::open` once the queue has starved for the app's liveness period, and the app's private
  exit `Hatch::exit`; the outcome note implements `ExitNote`;
- an exit pays what a field of the app's own note says (lending: a borrower repays its debt
  from credit and is credited its collateral; a lender is credited its shares' value).

The chain sees one nullifier per landing and per exit, never an entry. A keyed map has no hatch.
The mechanism: `docs/ARCHITECTURE.md` section 6, "The escape hatch".

**Node keys** (the `node_keys` axis; tip only).

| Option | Status | What | Cost and risk |
| --- | --- | --- | --- |
| rotating: key epochs (`KeyEpochs`) | built; the default | a numbered key set (epoch 0 the constructor's); two of the three current nodes sign the next (`rotate_keys`); a lost or compromised node is replaced in place, same address and state | more public bytecode (lending: about 5,450 of 36,923 bytes; credits: 18,208 against 13,250 with a fixed key set); every signature-checking private function enqueues a public epoch check; two colluding nodes can rotate the set (they already learn every shared value, and no key authorises a move) |
| fixed: the constructor's keys (`FixedKeys`) | built (`examples/credits-tip`) | no key-epoch slot and no rotation; a node's `enc` key for secret-shared on-chain intake still rotates | a lost node halts every round for good and a compromised `sig` key stays: the fix is a new deployment (a new address, an empty state; a tree's owners exit through the hatch) |

The app names its brick in one type alias its round table rows take as their last type
parameter (`pub type Keys = KeyEpochs<SharedOnchain<PublicContext>>;`, `KeyEpochs<NoEncKeys>`
without secret-shared on-chain intake, or `FixedKeys`). Under key epochs it also declares
`rotate_keys`, `set_node_keys`, `assert_key_epoch` and `get_node_keys` (`examples/amm-tip`).
The contract manifest's `node_keys` is generated from the brick the app's state view reports.
Rule: `fixed-keys-no-replacement`.

**App choices here.** The node keys; `stale_blocks`; the state mode (chain-held for recovery without
the nodes' state stores); for a tree, the hatch's liveness period (lending's
`Config::t_live`, a `DEV DECISION`, default 20,000 blocks), which round writes which leaves,
and what an exit pays. Start from `noir/pss_core/src/tip/exit.nr`,
`noir/pss_public_contract/src/hatch.nr`, `ts/pss-client/src/hatch.ts` and lending's
`open_hatch`, `poke`, `exit` and `get_hatch` (`examples/lending-tip/README.md`, "The escape
hatch").

### 15. Upgrades: may the circuits change?

**Question.** May the app's circuits, or its contract's code, change after deployment? Who may
change them, and how much warning do users get? (The `upgrades` axis; tip only.)

| Option | Status | What | Cost and risk |
| --- | --- | --- | --- |
| fixed (`FixedCircuits`) | built; the default (`examples/credits-tip`, `examples/lending-tip`) | the constructor's circuit pins (manifest hash, package list, vk hashes) for the life of the contract | a circuit bug is fixed only by a new deployment (a new address, an empty state) |
| circuits (`CircuitUpgrades`) | built (in `examples/amm-tip`) | an upgrade authority the constructor pins schedules new pins (`upgrade_circuits`), in force after a delay (the examples: one day; aztec-nr's floor: one hour); the code cannot change | the authority can change the rules of the shared state, so it can take the value the shared state controls, in public and after the delay; each round function 2,019 gates more (the AMM tip); public bytecode 27,762 bytes against 21,880; at most 14 packages; `stale_blocks` not null |
| contract (`CircuitUpgrades::upgrade_contract`) | built (`examples/amm-tip`) | as `circuits`, and the authority can move the instance to another contract class with its pins, after the same delay | the authority can replace every function, the escape hatch included: the delay is the users' only protection; a wallet registers the upgraded instance again; at most 13 packages |

An upgrade is two steps: the namespace owner key registers the new contract manifest as a new
version (accepted only when the contract's facts, every state key's layout and the intake
family are unchanged), then the authority schedules its pins. The change is public from then
on. A request queued under a replaced circuit is never answered: it waits out `stale_blocks`
and is skipped, which refunds its escrow. The mechanism: `docs/ARCHITECTURE.md` section 7,
"Upgrades"; the operator's steps: `docs/DESIGN.md`, "Upgrading an app's circuits" and
"Upgrading an app's contract code".

The app names its brick in the one function its round functions take their rows from (the
examples' `configured_in_force`): `CircuitUpgrades::in_force` or `FixedCircuits {}.in_force`.
Upgradable, it declares `CircuitUpgrades<P, DELAY, Context>` last in its storage, pins the
authority in its constructor and declares `upgrade_circuits` and `assert_upgrade_class` (and
`upgrade_contract` under `contract`). pss-client: `upgradeCircuits`, `upgradeContract`,
`readCircuitPins`, `PssClient.adoptManifest`, `followContractClass`, `pss-manifest verify`.
Rule: `upgradable-trusts-an-authority`.

**App choices here.** Whether to upgrade at all; the upgrade authority (a `DEV DECISION`: in
practice a multisig or a governance contract, never a node or a key the nodes hold); the delay
(`DEFAULT_UPGRADE_DELAY`, a `DEV DECISION`, one day). Tell users who the authority is and how
long the delay is.

## What each party sees

The recommended design (secret-shared receipt intake, node-held state, partial-note
completion), what each party adds under a deviation, what it can do to funds and what its
knowledge is worth. Generated from `design-space.json` `parties`.

<!-- generated: parties -->
| Party | Sees, under the recommended design | Adds under a deviation | Can do to funds | What its knowledge is worth |
| --- | --- | --- | --- | --- |
| one node | the clear app inputs (a position index, a liquidation's probes, a scan's start), C, the circuit and so the round type, which leaves a round touches and whether a liquidation wrote its probe (one health bit per liquidation attempt), the commitments and leaf hashes, its own Rep3 pair of every shared value, the result's public inputs (note hashes, ciphertext); never an amount, an owner, P or an outcome | under the non-secret-shared intakes every input in the clear, hence the whole state | none: it can only refuse, which halts rounds (liveness) | which positions are active and how often (the index links a position's requests); nothing a trade can use |
| two colluding nodes, or all three with every secret | every shared value: every input before its request is queued, every outcome, the whole state (the pool's reserves, every position's collateral and debt), $outcome_key, $outcome_tag and P; not the owner behind P, and no network address but those the orchestrator passes on | nothing more: under the non-secret-shared intakes there are no shares, every input and output being in the clear | none: nothing the nodes hold authorises a move (ownership is the user's note, proven in its private function), and the address commits to the circuits. Nodes that deviate can make a round flag its shares as not opening C. Where the app takes escrow or a usage deposit, token::settle_applied refunds them on that flag (lending's code 14). If the stale period is enabled and the skip wrapper calls token::refund_skipped, skipping refunds both in full. Nodes that vanish freeze the book, and owners exit through the escape hatch | front-running: a trade seen before it is queued can be front-run within its min_out (C binds the queued inputs and the queue is FIFO, so the victim's trade itself cannot change); the liquidation edge: every position's health at any price, so the first liquidation of every unhealthy position; the reserves, so the price impact of every pending trade; an app whose stake is the hidden information (a game's door) loses that stake |
| the orchestrator | on the receipt routes the user's network address beside C and the chain request id, so it links that address to the request on chain, the outcome tag and the result's timing; C and the clear app inputs; the three envelopes, which it cannot open. Under secret-shared on-chain intake the user never meets it | under receipt intake every input in the clear | none | who trades or borrows, linked to their requests and timing; a relay or a mixnet to the orchestrator (outside the build) hides the address |
| the relayer | the queue and each result's public inputs: ciphertext, note hashes, commitments, pinned values; no owner, amount or P | under public outputs every output and the partial note P, as the world sees them | none: the proof binds whatever it lands; it can withhold, and skip() moves the head after stale_blocks | nothing under the recommended design |
| the world | a request joined and resolved (request id, expiry, done[index]), the new commitments, one note hash and one 16-field private log per result (and one more of each per delivery of an app with the delivery handle: lending's every result two), the pinned reads, timing and gas (equal across round types); no request's class or amount (escrow and the usage deposit are drawn from the user's private balance in the app); a fund's and a token withdrawal's amounts, linked to no request except by timing and amount (fund in advance and in round amounts); under an escape hatch one exit-tag nullifier per result and one per exit, which name no entry; under secret-shared on-chain intake the clear app inputs and the encoded shares, for good; under a public completion the amount, never the owner | under on-chain intake every input; under the non-secret-shared intakes every output, with the partial note P each completion names | none | activity and timing only; under secret-shared on-chain intake (and chain-held state) a later break of two nodes' enc keys or of the Grumpkin key exchange opens every past request (or state) |
| the user | its own inputs, notes, outcomes and keys | none | its own: a user-owned note is at risk only from the user's own device | not applicable |
<!-- end generated -->

Per intake (`design-space.json` `leakage`):

<!-- generated: leakage -->
| Intake | Inputs in the clear | Requester | On chain | State in the clear | Outcome in the clear | Funds at risk if all three nodes leak | What the nodes' knowledge is worth |
| --- | --- | --- | --- | --- | --- | --- | --- |
| on-chain intake | the world (the request log) | nobody (the fee through wFJ) | the request id; the inputs and user_nonce in the request log | the world, whenever the initial state and the inputs determine it (lending); otherwise whoever can solve it from public inputs and outputs (the AMM's reserves, by probing) | the world (public outputs) | the AMM: no (the circuit is pinned and the inputs are the user's); lending: no (the deposit's completed note, the depositor's partial note completed in apply, is its only ownership); the circuits and configure: no for every deployment (the constructor pins the vk hashes) | the world reads every input in the request log before the round runs: a trade can be front-run or sandwiched within its min_out, and a state the inputs determine (lending's book) is public, so every position's health, and the first liquidation of it, is anyone's |
| receipt intake | the three nodes and the orchestrator (over TLS) | nobody; the orchestrator sees the network address unless a relay or mixnet hides it | the request id and the expiry block | the nodes and the orchestrator, from the inputs they see and the public outputs | the world (public outputs) | as on-chain intake | the nodes and the orchestrator read every input before its request transaction lands and follow the whole state: a node can queue its own trade first, within the victim's min_out, and knows every position's health at every price (the liquidation edge) |
| secret-shared receipt intake | the shared inputs: the user only (node i holds one pair, the orchestrator the three envelopes); the clear app inputs (lending's position indices) and C: the nodes and the orchestrator | nobody (the fee through wFJ); the orchestrator sees the network address unless a relay or mixnet hides it | the request id and the expiry block; at the result the new commitments, one note hash and one 16-field log, one more of each per delivery (and, for lending's book, one exit-tag nullifier per result, which names no index); no class or amount (escrow is drawn from a private balance) | nobody | the user only (partial-note completion) | no for the AMM and lending (no shared value authorises anything: a request on a lending position needs its owner's note in the private function; a frozen book is exited through the escape hatch with no node); the circuits and configure: no for every deployment (the constructor pins the vk hashes); a tree-valued key's append index: no, the circuit enforces it against the header's next_index | one node: the clear app inputs only (a position index links the requests on that position). Two colluding nodes, or a full compromise: every input before it is queued (front-running a trade within its min_out), the pool's reserves (the price impact of every pending trade) and every position's health (the liquidation edge). The orchestrator links network addresses to requests and outcome tags |
| secret-shared on-chain intake | the shared inputs: the user only (a private log holds them encoded); the clear app inputs: the world, in that log | nobody (the fee through wFJ); the user never meets the orchestrator | the request id, the hash of the request data; C, the clear app inputs and the encoded shares in a private log, permanently | nobody | as secret-shared receipt intake | as secret-shared receipt intake | as secret-shared receipt intake, plus the clear app inputs public in the log for anyone (a position index links its requests); the encoded shares open to whoever later learns two nodes' enc scalars, so the window outlives the round |
| direct execute | PUBLIC inputs: the nodes and the orchestrator; INPUT_SHARED inputs: the user only | the nodes (a record-supplying request is signed by its owner key) | the user's own transaction: note hashes and nullifiers | client-held: the user (the thirds open only at the nodes); node-held: the nodes | the user, the orchestrator and the nodes (public outputs of the proof) | no: the user's own private function verifies the proof over notes it reads itself, and a nullifier lands only through the pinned circuit's proof; an app whose stake is the hidden information itself states what the nodes' knowledge is worth | the nodes see PUBLIC inputs and the outputs; a full compromise opens every record, so an app whose stake is the hidden information itself (a game's door, a sealed bid) loses that stake: the app's leakage statement says what the hidden value is worth |
<!-- end generated -->

Frozen value is a liveness failure, not a funds failure; the escape hatch bounds it.

## Fixed properties

These hold in every design. `docs/ARCHITECTURE.md` section 5 checks every brick against them;
`docs/DESIGN.md` states the trust model.

- **Invariant 0.** If all three nodes' secrets leak, only privacy may be at risk, never funds:
  no value a circuit trusts as an authorisation is a shared input or a node-held value, the
  circuits a contract pins are committed by its address, escrow and refunds are user-owned
  notes that public functions complete, and a frozen book has an exit that needs no node.
- **Minimal PSS** (question 1). **Value lands with the requester** (question 7).
- **Trust.** Three operator-run nodes, Rep3, honest majority: one node learns nothing and can
  only halt; two colluding nodes learn every shared value. Count and threshold are fixed.
- **The requester is hidden from the chain and the nodes** on every intake: no `msg_sender` in
  an intake function, no address in a request id, log or receipt (`$user` is refused at
  REGISTER). On the receipt routes the orchestrator sees the network address.
- **Total, co-noir-compatible round circuits**: a bad request lands as an `ok = 0` no-op with
  a code; no ECDSA inside the co-SNARK, no total-noir entry its page "co-noir compatibility of the library's hints" excludes
  (`scripts/check-noir.sh` gates both).
- **One compiled circuit per round per intake family**, its inputs bound through `C`.
- **The round type is hidden** under a secret-shared intake: one request wrapper and one
  `apply` per app with the same arguments, pinned reads and effect counts, logs padded to 16
  fields (each example's `test_round_shape.nr`). Timing stays visible.
- **Ordering**: one FIFO queue and one lock per namespace.
- **Deployment**: a secret salt, the contract manifest REGISTERed before deployment, a once-only
  `configure`; new circuits are a new deployment unless the circuits are upgradable.
- **Public activity is accepted**: the queue, the slots, the pinned reads and timing.

## Compatibility

Any value of one axis combines with any value of another unless a rule below forbids the pair.
The permutation rules cover every constraint in `design-space.json`; the namespace rules govern
the rounds of one deployment. Generated from `design-space.json` `compatibility`.

<!-- generated: compat-rules -->
| Rule | Scope | Level | Forbids or warns | Enforced by | Constraints | Stated in |
| --- | --- | --- | --- | --- | --- | --- |
| `path-follows-intake` The path follows the intake | permutation | error | direct is the sidecar path and nothing else is; every queued intake is the tip. | the manifest: intake direct is the sidecar path, every other intake queues at the tip; REGISTER refuses a field of the other path | `sidecar-direct`, `tip-queued` | [ARCHITECTURE.md#7-the-manifest](../ARCHITECTURE.md#7-the-manifest) |
| `binding-follows-path` Binding is a queue notion | permutation | error | A sidecar-path request names the record or row it loads (binding none); a queued request binds to its turn (exact is deferred). | the manifest's binding field, queued intakes only | `sidecar-binding`, `tip-binding` | [ARCHITECTURE.md#7-the-manifest](../ARCHITECTURE.md#7-the-manifest) |
| `state-mode-follows-path` Client-held is the sidecar path's, chain-held the tip's | permutation | error | A client-held record is presented by its owner in its own request; chain-held state is sealed into a queued result's apply log. | REGISTER refuses a state mode the intake does not allow | `client-needs-direct`, `chain-needs-queue` | [ARCHITECTURE.md#state-modes-at-the-tip](../ARCHITECTURE.md#state-modes-at-the-tip) |
| `tree-is-node-held-tip` A tree is node-held at the tip | permutation | error | The nodes keep the clear tree of hashes and the leaves as versions anchored to the queue. | REGISTER (a tree entry only under a node-held queued key) | `tree-needs-node-tip` | [ARCHITECTURE.md#tree-valued-keys](../ARCHITECTURE.md#tree-valued-keys) |
| `oblivious-index-is-shared` An oblivious index is a shared input | permutation | error | The oblivious tree and the keyed map run under the secret-shared intakes alone: a clear index would show the nodes the leaf. | REGISTER: every index input of an access: oblivious tree is INPUT_SHARED (sidecar-core manifest/tree.rs), and a non-secret-shared intake refuses INPUT_SHARED (manifest/validate.rs) | `oblivious-needs-shared` | [ARCHITECTURE.md#the-oblivious-tree](../ARCHITECTURE.md#the-oblivious-tree) |
| `sidecar-user-lands` The user lands a sidecar-path result | permutation | error | Off-chain delivery belongs to the sidecar path: the user receives, verifies and submits. | the design: pss-relayer serves the queue only | `sidecar-user-lands` | [DECISIONS.md#10-tip-outcomes-and-delivery](../DECISIONS.md#10-tip-outcomes-and-delivery) |
| `outputs-follow-family` Private outcomes if and only if a secret-shared intake | permutation | error | Public outputs would publish what the shares hide; the outcome key and tag travel as shared inputs. A public-by-nature result (an auction's clearing price) reaches each party in its own note. | REGISTER: the reserved $outcome_key, $outcome_tag and $blinding only under a secret-shared intake, INPUT_SHARED refused under a non-secret-shared one | `shared-private`, `private-needs-shared` | [DECISIONS.md#10-tip-outcomes-and-delivery](../DECISIONS.md#10-tip-outcomes-and-delivery) |
| `value-follows-intake` Value delivery follows the intake | permutation | error | A secret-shared intake delivers by partial-note completion only; the sidecar path's own transaction lands its result, so the library delivers nothing there. | REGISTER (sidecar-core registry::check_outcome): outcome none refused under a secret-shared intake, an outcome field refused under intake direct, and under outcome partial at a non-secret-shared intake the round's partial_note output required right after ok | `shared-needs-partial`, `sidecar-no-delivery` | [ARCHITECTURE.md#7-the-manifest](../ARCHITECTURE.md#7-the-manifest) |
| `delivery-follows-outputs` Public is clear, private is constrained | permutation | error | Public outputs need no encryption; a private, value-bearing outcome is encrypted inside the circuit so a result lands only if its recipient can open it. | the design (verifiable delivery): the round circuit computes the ciphertext | `public-is-clear`, `private-needs-encryption`, `value-is-constrained` | [DECISIONS.md#1-principles](../DECISIONS.md#1-principles) |
| `no-node-sealed-delivery` No node-sealed delivery to users | permutation | error | A node could hand the user garbage that still lands. | the design; no brick exists | `node-sealed-not-offered` | [DECISIONS.md#10-tip-outcomes-and-delivery](../DECISIONS.md#10-tip-outcomes-and-delivery) |
| `deferred-options` Deferred options | permutation | warn | Not built; REGISTER refuses both. | REGISTER refuses intake relayed and binding exact | `relayed-deferred`, `exact-deferred` | [ARCHITECTURE.md#4-the-registry-lifecycle](../ARCHITECTURE.md#4-the-registry-lifecycle) |
| `experimental-options` Experimental options | permutation | warn | The oblivious tree and the keyed map; the clear-index tree is recommended. | the design guide and the manifest's access field (REGISTER accepts it) | `oblivious-experimental` | [README.md#2-where-does-the-shared-state-live](README.md#2-where-does-the-shared-state-live) |
| `non-secret-shared-test-paths` The non-secret-shared intakes are test paths | permutation | warn | Inputs clear to the world or the nodes, outputs public, the round type visible. | the design; one-intake-family-per-namespace puts them on a deployment of their own | `plain-test-path` | [DECISIONS.md#9-tip-intake](../DECISIONS.md#9-tip-intake) |
| `chain-held-costs` Chain-held state is for small fixed states | permutation | warn | The whole state is broadcast sealed on every apply and stays on chain for good; it undoes secret-shared receipt intake's off-chain inputs. | REGISTER bounds a chain-held key by the apply log | `chain-small-fixed`, `chain-undoes-receipt` | [ARCHITECTURE.md#state-modes-at-the-tip](../ARCHITECTURE.md#state-modes-at-the-tip) |
| `shared-onchain-forever` Secret-shared on-chain intake keeps shares on chain | permutation | warn | Harvest now, decrypt later: a later break of two nodes' enc keys opens every past request. | the design | `shared-onchain-forever` | [DECISIONS.md#9-tip-intake](../DECISIONS.md#9-tip-intake) |
| `sidecar-node-contention` A node row on the sidecar path serialises users | permutation | warn | For shared state under contention use the tip. | the design; the operator's rollback | `sidecar-node-contention` | [ARCHITECTURE.md#5-invariants](../ARCHITECTURE.md#5-invariants) |
| `fixed-keys-no-replacement` A fixed key set replaces no node | permutation | warn | A lost or compromised node means a new deployment. | the design: the contract library's signature check | `fixed-keys-no-replacement` | [README.md#14-node-replacement-recovery-and-liveness](README.md#14-node-replacement-recovery-and-liveness) |
| `upgradable-trusts-an-authority` Upgradable circuits trust an authority | permutation | warn | The authority can change what the shared state does; the delay is the users' warning. | the contract library: upgrade_circuits checks the constructor's authority; REGISTER refuses an upgradable contract manifest whose stale_blocks is null | `upgradable-trusts-an-authority` | [README.md#15-upgrades-may-the-circuits-change](README.md#15-upgrades-may-the-circuits-change) |
| `one-intake-family-per-namespace` One intake family per namespace | namespace | error | A non-secret-shared-intake package that reads a key may not sit beside a secret-shared-intake package that writes one; the init round, which reads none, sits beside either. Per key, not per namespace, is the future enhancement for a multi-book namespace. | REGISTER: sidecar-core registry::intake_families_clash, also run by the orchestrator against its registry copy | — | [DECISIONS.md#9-tip-intake](../DECISIONS.md#9-tip-intake) |
| `one-layout-per-key` One state mode and shape per key | namespace | error | Every queued package of a namespace gives a request key one layout: node-held or chain-held, and for a tree one depth, leaf length and shape. Different keys of one app may differ. | REGISTER: sidecar_tip::one_layout; the scheduler computes nothing while two packages disagree | — | [ARCHITECTURE.md#state-modes-at-the-tip](../ARCHITECTURE.md#state-modes-at-the-tip) |
| `one-circuit-per-round-per-family` One compiled circuit per round per intake family | namespace | error | &lt;round&gt;_shared serves both secret-shared intakes, &lt;round&gt; both non-secret-shared intakes; another intake for a round is glue, never circuit logic. | the manifests and scripts/gen-intake.py --check (run by check-manifests.py) | — | [README.md#running-a-round-under-another-intake](README.md#running-a-round-under-another-intake) |
| `package-list-is-the-address` The package list is in the address | namespace | error | A new round, intake or circuit for a deployed tip contract is a new deployment with a new salt. | the constructor (the package list and each package's vk hash) | — | [DECISIONS.md#11-tip-deployment](../DECISIONS.md#11-tip-deployment) |
| `register-bounds` REGISTER's bounds | namespace | error | A tree round within its probe width K, depth D (1 to 32) and window W (at most 8); the round's chain-held outputs within the apply log's 4,094 fields; secret-shared on-chain intake within 9 clear and chosen values; secret-shared receipt intake with a stale period inside the enc grace window; no pinned public read or reserved tip operand under direct; no node-held key on a store without values. | REGISTER step 3 and each node's own check | — | [ARCHITECTURE.md#4-the-registry-lifecycle](../ARCHITECTURE.md#4-the-registry-lifecycle) |
<!-- end generated -->

The grid over the decision axes: a pair is forbidden when no permutation that breaks no error
rule contains it. The other axes follow from these: a secret-shared intake gives private
outcomes, partial-note completion and constrained delivery; a non-secret-shared intake gives
public outputs and clear delivery; the sidecar path's direct intake gives public outputs, no
value delivery and clear.

<!-- generated: compat-pairs -->
| | `client` | `node` | `chain` | `flat` | `tree` | `tree_oblivious` | `map_oblivious` | `direct` | `onchain` | `receipt` | `shared_receipt` | `shared_onchain` | `relayed` | `user` | `relayer` | `rotating` | `fixed` | `fixed` | `circuits` | `contract` |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| state mode `client` |   |   |   | · | ✗ | ✗ | ✗ | · | ✗ | ✗ | ✗ | ✗ | ✗ | · | ✗ | · | · | · | · | · |
| state mode `node` |   |   |   | · | · | · | · | ! | · | · | · | · | · | · | · | · | · | · | · | · |
| state mode `chain` |   |   |   | · | ✗ | ✗ | ✗ | ✗ | · | · | ! | · | · | · | · | · | · | · | · | · |
| state shape `flat` | · | · | · |   |   |   |   | · | · | · | · | · | · | · | · | · | · | · | · | · |
| state shape `tree` | ✗ | · | ✗ |   |   |   |   | ✗ | · | · | · | · | · | · | · | · | · | · | · | · |
| state shape `tree_oblivious` | ✗ | · | ✗ |   |   |   |   | ✗ | ✗ | ✗ | · | · | ✗ | · | · | · | · | · | · | · |
| state shape `map_oblivious` | ✗ | · | ✗ |   |   |   |   | ✗ | ✗ | ✗ | · | · | ✗ | · | · | · | · | · | · | · |
| intake `direct` | · | ! | ✗ | · | ✗ | ✗ | ✗ |   |   |   |   |   |   | · | ✗ | · | · | · | · | · |
| intake `onchain` | ✗ | · | · | · | · | ✗ | ✗ |   |   |   |   |   |   | · | · | · | · | · | · | · |
| intake `receipt` | ✗ | · | · | · | · | ✗ | ✗ |   |   |   |   |   |   | · | · | · | · | · | · | · |
| intake `shared_receipt` | ✗ | · | ! | · | · | · | · |   |   |   |   |   |   | · | · | · | · | · | · | · |
| intake `shared_onchain` | ✗ | · | · | · | · | · | · |   |   |   |   |   |   | · | · | · | · | · | · | · |
| intake `relayed` | ✗ | · | · | · | · | ✗ | ✗ |   |   |   |   |   |   | · | · | · | · | · | · | · |
| submission `user` | · | · | · | · | · | · | · | · | · | · | · | · | · |   |   | · | · | · | · | · |
| submission `relayer` | ✗ | · | · | · | · | · | · | ✗ | · | · | · | · | · |   |   | · | · | · | · | · |
| node keys `rotating` | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · |   |   | · | · | · |
| node keys `fixed` | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · |   |   | · | · | · |
| upgrades `fixed` | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · |   |   |   |
| upgrades `circuits` | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · |   |   |   |
| upgrades `contract` | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · |   |   |   |

`·` combines, `!` combines with a warning, `✗` never combines. The forbidden pairs, with the rules that forbid them:

- state mode **client-held records** never with state shape Merkle tree, clear index: `tree-is-node-held-tip`.
- state mode **client-held records** never with state shape Merkle tree, oblivious index, Keyed map, oblivious (sparse Merkle tree): `state-mode-follows-path`, `oblivious-index-is-shared`, `tree-is-node-held-tip`.
- state mode **client-held records** never with intake on-chain intake, receipt intake, relayed intake: `state-mode-follows-path`, `path-follows-intake`.
- state mode **client-held records** never with intake secret-shared receipt intake, secret-shared on-chain intake: `state-mode-follows-path`.
- state mode **client-held records** never with submission pss-relayer: `state-mode-follows-path`, `sidecar-user-lands`.
- state mode **chain-held (sealed in every apply)** never with state shape Merkle tree, clear index, Merkle tree, oblivious index, Keyed map, oblivious (sparse Merkle tree): `tree-is-node-held-tip`.
- state mode **chain-held (sealed in every apply)** never with intake direct execute: `state-mode-follows-path`, `path-follows-intake`.
- state shape **Merkle tree, clear index** never with intake direct execute: `path-follows-intake`, `tree-is-node-held-tip`.
- state shape **Merkle tree, oblivious index** never with intake direct execute: `oblivious-index-is-shared`, `path-follows-intake`, `tree-is-node-held-tip`.
- state shape **Merkle tree, oblivious index** never with intake on-chain intake, receipt intake, relayed intake: `oblivious-index-is-shared`.
- state shape **Keyed map, oblivious (sparse Merkle tree)** never with intake direct execute: `oblivious-index-is-shared`, `path-follows-intake`, `tree-is-node-held-tip`.
- state shape **Keyed map, oblivious (sparse Merkle tree)** never with intake on-chain intake, receipt intake, relayed intake: `oblivious-index-is-shared`.
- intake **direct execute** never with submission pss-relayer: `sidecar-user-lands`, `path-follows-intake`.

The pairs that combine with a warning:

- state mode **node-held** with intake **direct execute**: `sidecar-node-contention`.
- state mode **chain-held (sealed in every apply)** with intake **secret-shared receipt intake**: `chain-held-costs`.

The values that warn on their own, whatever they are paired with:

- state mode **chain-held (sealed in every apply)**: `chain-held-costs`.
- state shape **Merkle tree, oblivious index**: `experimental-options`.
- state shape **Keyed map, oblivious (sparse Merkle tree)**: `experimental-options`.
- intake **on-chain intake**: `non-secret-shared-test-paths`.
- intake **receipt intake**: `non-secret-shared-test-paths`.
- intake **secret-shared on-chain intake**: `shared-onchain-forever`.
- intake **relayed intake**: `deferred-options`.
- binding **exact**: `deferred-options`.
- node keys **fixed key set**: `fixed-keys-no-replacement`.
- upgrades **upgradable circuits**: `upgradable-trusts-an-authority`.
- upgrades **upgradable circuits and contract code**: `upgradable-trusts-an-authority`.

- delivery **sealed by the nodes**: in no valid permutation.
<!-- end generated -->

## Blueprints

The robust combinations, each a path through the tree ending in the files to start from.
`--plan <id>` prints each with its bricks and paths. Generated from `design-space.json`
`blueprints`.

<!-- generated: blueprints -->
| Blueprint | Path, state, shape | Intake | Outputs, value, delivery | Submission | Node keys, upgrades | Example | Status |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `note-client` Sidecar path, client-held state | `sidecar`, `client`, `flat` | `direct` | `public`, `none`, `clear` | `user` | `rotating`, `fixed` | `examples/monty-hall` | built |
| `tip-flat` Tip, node-held state, secret-shared receipt intake | `tip`, `node`, `flat` | `shared_receipt` | `private`, `partial`, `constrained` | `relayer` | `rotating`, `fixed` | `examples/counter-tip` | built |
| `tip-tree` Tip, node-held tree state (large books) | `tip`, `node`, `tree` | `shared_receipt` | `private`, `partial`, `constrained` | `relayer` | `rotating`, `fixed` | `examples/lending-tip` | built |
| `tip-chain` Tip, small fixed chain-held state | `tip`, `chain`, `flat` | `shared_onchain` | `private`, `partial`, `constrained` | `relayer` | `rotating`, `fixed` | none | to build |
<!-- end generated -->

### Sidecar path, client-held state (`note-client`)

**Suits** state that belongs to one user and is hidden from everyone, the user's own future
moves included: games against the house, sealed commitments, private counters and allowances,
credentials whose use the network enforces.

**The path.** 2: client-held, flat. 3: the sidecar path. 5: direct; mark each input PUBLIC or
INPUT_SHARED (the player's door is INPUT_SHARED). 6: public outputs. 7: none. 9: clear. 10: the
user. 11: no binding; the consume policy `once` gives each state one evaluation, so each round's
single reveal must be safe (Monty Hall's README, "What one evaluation reveals").

**Leaks.** The nodes see PUBLIC inputs and outputs; a full compromise opens every record, so
the app states what its hidden value is worth. Funds: none.

**Deviations.** A node row (`examples/amm`) for shared state with little contention.

**Start from** `examples/monty-hall` and `e2e/scenarios/monty.ts`. **You write** one total round
circuit per move over `noir/pss_core/src/effects.nr`, its manifest, the contract over
`noir/pss_contract/src`, the client calls through pss-client, an e2e scenario.

### Tip, node-held state, secret-shared receipt intake (`tip-flat`)

**Suits** a small fixed shared state that many users transition and nobody may see, where
every round pays nobody but its requester: AMM pools, a counter or rate limiter, a treasury
whose rules bind the requesters, a sealed-bid auction's best bid when it settles to each
requester only (one that pays its winner needs a leaf per bid: `tip-tree`).

**The path.** 1: only the pool is shared. 2: node-held, flat. 4: open; a usage deposit once the
app takes a token. 5: secret-shared receipt intake. 6: private outcomes. 7: partial-note
completion in the co-SNARK, spent with `redeem`. 9: constrained. 10: the relayer. 11: `turn`,
slippage as `min_out`. 12: wFJ.

**Leaks.** One node: `C`, the circuit, the commitments. Two colluding nodes: every swap before
it is queued and the reserves (front-running within `min_out`). The orchestrator: the trader's
network address. The world: a request joined and resolved, one note hash, one 16-field log.
Funds: none.

**Deviations.** Secret-shared on-chain intake; receipt intake with public outputs as a test
path on a deployment of its own; user submission; chain-held state (`tip-chain`).

**Start from** `examples/counter-tip`, the minimal app (one round, its contract, its TXE suite,
a client flow, and the split of app lines and plumbing in its README), then
`examples/amm-swap-total` (a total app library) and `examples/amm-tip` (every intake,
upgrades, a redeem). **You write** the app library, the init round and one secret-shared main
per round, their manifests, the contract (round table, pins, request wrapper, result function,
`apply`, `redeem`, outcome note), its TXE suite with `test_round_shape.nr`, the client entry,
the fee setting (`e2e/harness/fee-settings.ts`), an e2e scenario.

### Tip, node-held tree state (`tip-tree`)

**Suits** a large or growing book of per-user entries under one root: lending markets, order
books, a sealed-bid auction that pays its winner (a leaf per bid), a payroll or treasury with
per-member entitlements, registries, membership or voting rolls.

**The path**, as lending answers it (an app of this shape keeps the bricks and changes its own
answers). 1: the positions and the header's aggregates are shared; ownership, payouts and
balances are notes. 2: a clear-index tree, `D = 16`, `K = 2`, `LEAF_LEN` 8, a header leaf. 4:
open, with the usage deposit and every escrow from the credit note. 5: secret-shared receipt
intake; position indices clear app inputs, amounts shared. 6: private outcomes. 7: partial-note
completion; `redeem` credits, `withdraw_funds` pays tokens. 8: a user-owned note. 11: `turn`;
the price under `epoch`, the clock under `tolerance`. 13: a window round at `W = 8`, then act
rounds. 14: the escape hatch.

**Leaks.** One node: which positions a round touches, the round type, whether a liquidation
wrote its probe. Two colluding nodes: every position, so its health at any price, and every
input before it is queued. A prober: one health bit per probed position. The world: no index
and no leaf; one exit-tag nullifier per landing; fund and withdrawal amounts. Funds: none.

**Deviations.** Secret-shared on-chain intake (the position index then public in the log);
on-chain intake for one round as a test path; the oblivious tree (experimental: lending's
oblivious deployment).

**Start from** `examples/lending-tip` (`circuits/lending_tip`, `circuits/deposit_shared`,
`contract/lending_tip` over `contract/lending_market`). **You write** the library (leaf and
header, codes, one function per round, the shared finisher with the write policy, the tagged
write and the deliveries), the init and one secret-shared main per round, the manifests with
their `tree` entries, the contract (request functions, result functions, `apply_shared`, the
note check, `redeem`, the credit functions, `skip()`, the hatch's entry points, the outcome
note with `ExitNote`), an oracle if you pin a price, the TXE suite, the keeper loop if needed,
an e2e scenario. The market in detail: `examples/lending-tip/README.md`.

### Tip, small fixed chain-held state (`tip-chain`)

**Suits** a small fixed shared state that operators recover without the nodes' state stores.
Recovery needs the nodes' keys and the package that decodes the log. The scheduler searches
the 64 queue entries before the head and the init round for a matching sealed-thirds log.

**The path.** As `tip-flat`, but 2: chain-held, within the apply log's bound; 5: secret-shared
on-chain intake (the state history is on chain anyway).

**Leaks.** As `tip-flat`, plus: the sealed states and encoded inputs stay on chain for good.

**Deviations.** A non-secret-shared intake with public outputs (the built combination);
secret-shared receipt intake.

**Start from** `machine/circuits/tip_counter`, `noir/pss_public_contract_test` and the
chain-held modules (`noir/pss_public_contract/src/chain_state.nr`,
`ts/pss-client/src/chain-state.ts`): the app hands the library's entry points its
`chain_state` thirds in place of `NodeHeld {}`. **You write** as `tip-flat`, with the sealed
thirds as one more argument of the result and init wrappers.

## Not built, or experimental

`note-client`, `tip-flat` and `tip-tree` build end to end with their examples. `tip-chain` has
no example in its form; its bricks are built, and chain-held state runs with a
non-secret-shared intake on test deployments. State each item below as such, never as built.

| Work | Status | What runs instead |
| --- | --- | --- |
| The oblivious tree and the oblivious keyed map (non-membership proofs), the index or key a shared input | experimental (`docs/ARCHITECTURE.md` section 6, "The oblivious tree" and "The oblivious sparse map"); their examples run end to end (lending's oblivious deployment, with the escape hatch, and `examples/credits-tip`); their audit not built; a keyed map has no escape hatch; never a default or in a blueprint | the clear-index tree (`DECISIONS.md` section 7) |
| Relayed intake, `binding: exact` | deferred; REGISTER refuses them | secret-shared receipt intake; `binding: turn` |
| A delegate acting on an entry by the owner's authwit | not built | the owner acts itself |

## Where each choice lives

| Axis or choice | Chosen in | Default |
| --- | --- | --- |
| path | follows from `intake` | tip |
| state mode | manifest `state {key: client \| node \| chain}` | node |
| state shape | manifest `tree {key: {depth, leaf_len, probe, ...}}` | flat |
| intake | manifest `intake`; the contract's intake function; the client's intake module | secret-shared receipt intake; a manifest that names no intake takes `direct` |
| binding | manifest `binding` | turn |
| outputs | follows from the intake | private under a secret-shared intake |
| value delivery | follows from the intake; under a non-secret-shared intake each manifest's `outcome: partial \| none`; the app's note type | partial; none on the sidecar path |
| delivery | follows from the outputs | constrained |
| submission | the deployment: pss-relayer, or the client's lander | relayer |
| node keys | the contract's `Keys` alias and, under key epochs, its four entry points | rotating |
| upgrades | where the contract's round functions take their pins, and its upgrade entry points, authority and delay | fixed |
| access control | the app's request and `skip()` wrappers | open |
| usage deposit | the app's Config (`UsageDeposit`) and the request function (`token::commit_refunds`) | per app; lending: its borrowed asset, kept |
| fee method | `ts/pss-client/src/fee.ts` | wFJ |

App parameters with defaults (`design-space.json` `parameters`): `stale_blocks` (the contract
manifest's `queue.stale_blocks`; 50 L2 blocks in the examples), the tree's depth, leaf length
and probe width, the consume policy (sidecar path, `once`), the init strategy, the outcome
fields (one shape for every round of an app), each pinned read's freshness (`exact`), the usage
deposit, and the escape hatch's liveness period. Operator knobs: `docs/DESIGN.md`,
"Configuration reference".

## Reserved names

Most names in an app's contract are its own. These are not: the contract library calls two app
functions by selector, and pss-client, pss-relayer and the node read storage fields and call
some functions by name. The contract manifest's `node_keys` and `upgrades` are not names but
the bricks the app's state view (`TipState`) reports. A misnaming fails when the contract
manifest is generated (pss-client `brickProblems`). The list is pss-client's `RESERVED_NAMES`
(`ts/pss-client/src/bricks.ts`), which `check-design-space.py` checks this table against.

<!-- generated: reserved-names -->
| Name | Kind | When | What the app must do | Relied on by |
| --- | --- | --- | --- | --- |
| `config` | storage field | every tip contract | the constructor takes the Config as a parameter named config with the member tip (TipPins), and stores it in the storage field config | pss-client's contract manifest generator and pss-manifest verify: the package capacity from the constructor's ABI, the stale period's slot from the field's |
| `queue` | storage field | every tip contract | the Queue's storage field is named queue | the contract manifest generator and verify (queue.slot), and pss-client's queue reader by default |
| `configured` | storage field | every tip contract | the stored Configured's field is named configured | the contract manifest generator and verify (storage.configured) |
| `shared_onchain` | storage field | a package takes secret-shared on-chain intake | the SharedOnchain storage field is named shared_onchain | the contract manifest generator and verify (storage.shared_onchain) |
| `circuit_upgrades` | storage field | upgrades circuits or contract | the CircuitUpgrades storage field is named circuit_upgrades | the contract manifest generator and verify (storage.circuit_pins) |
| `assert_key_epoch(u32,bool)` | function the library calls | node_keys rotating | an #[only_self] public function of exactly this signature whose body is key_epoch::assert_epoch: every signature check under KeyEpochs enqueues it by selector, so the grace window rests on that body; the contract manifest generator refuses an artifact whose state view reports KeyEpochs without a public function of exactly this signature | pss_public_contract key_epoch; pss-client's artifact lint (brickProblems) |
| `assert_upgrade_class(Field)` | function the library calls | upgrades circuits or contract | an #[only_self] public function of exactly this signature whose body is CircuitUpgrades::assert_class: CircuitUpgrades::in_force enqueues it by selector from every round function; the contract manifest generator refuses an artifact whose state view reports UpgradesCircuits or UpgradesContract without a public function of exactly this signature | pss_public_contract upgrades; pss-client's artifact lint (brickProblems) |
| `rotate_keys` | function the client calls | node_keys rotating | the key rotation entry point is named rotate_keys: sidecar-node replace-node prints a rotate_keys line for each namespace whose contract manifest says node_keys rotating; the axis value itself is the brick the state view reports, and the generator refuses an artifact that declares rotate_keys under FixedKeys or lacks it under KeyEpochs | sidecar-node replace-node; pss-client's artifact lint (brickProblems) |
| `upgrade_circuits` | function the client calls | upgrades circuits or contract | the upgrade entry point is named upgrade_circuits: pss-client's upgradeCircuits calls it; the axis value itself is the brick the state view reports, and the generator refuses an artifact that declares it under FixedCircuits or lacks it under UpgradesCircuits or UpgradesContract | pss-client (upgradeCircuits; the artifact lint, brickProblems) |
| `upgrade_contract` | function the client calls | upgrades contract | the class upgrade entry point is named upgrade_contract: pss-client's upgradeContract calls it; the generator refuses an artifact that declares it unless the state view reports UpgradesContract, or lacks it then | pss-client (upgradeContract; the artifact lint, brickProblems) |
| `get_enc_key` | function the client calls | a package takes secret-shared on-chain intake | a view get_enc_key(i) over SharedOnchain::enc_key; the generator refuses an artifact without it when a package takes secret-shared on-chain intake | pss-client (storedEncKey) and pss-relayer's enc key rotation |
| `rotate_enc_key` | function the client calls | a package takes secret-shared on-chain intake | a private rotate_enc_key(i, key, signature) over check_enc_rotation and SharedOnchain::rotate; the generator refuses an artifact without it when a package takes secret-shared on-chain intake | pss-relayer's enc key rotation |
| `process_result` | default function name | every tip contract | the result function is named process_result, unless the deployment's methods map names another per circuit | pss-client (DEFAULT_RESULT_METHOD) and pss-relayer |
| `skip` | default function name | every tip contract | the queue's skip function is named skip, unless the relayer is configured with skipMethod | pss-relayer |
<!-- end generated -->

## BRICK markers

A `// BRICK` comment marks a seam in an example's code where another option could have been
chosen: the axis, the option plugged in, the library item the code calls, the alternatives.

```
// BRICK intake = shared_receipt (pss_public_contract::outcome_request). Alternatives:
// onchain, receipt, shared_onchain (the entry points above and below). docs/design-guide/BRICKS.md#intake
```

Where one circuit serves two options the marker names both (`intake = onchain, receipt`); where
the manifest picks the option, it names the manifest field. A brick in no axis (BRICKS.md,
"Other bricks": token escrow, note ownership, the delivery handle, the escape hatch) is marked
where the example adds it, with what an app does without it:

```
// BRICK token-escrow (pss_public_contract::token::commit_refunds), ... No alternative;
// an app that moves no token leaves it out (examples/amm-tip). docs/design-guide/BRICKS.md#other-bricks
```

A brick every app on a path has is never marked. One marker per seam, not per call. A BRICK
marker says which brick is plugged in and what else could be; a DEV DECISION marker states a
choice within a brick. Neither fixes the shape of an app's contract, but for the [reserved
names](#reserved-names). `scripts/check-design-space.py` checks every marker under `examples/`
and fails when an example uses a library item no brick's `api` lists; each example README's
"Bricks this example uses" table is generated from the markers (`--write-bricks`).

## DEV DECISION markers

A `DEV DECISION` marker names a choice an app developer makes at that line: what it is, its
default, why, its consequences and the alternative. Class a only; an open design question is
never a marker.

| Class | What | Marker | Where it lives |
| --- | --- | --- | --- |
| a | a choice an app developer makes | yes | at the line that makes the choice, pointing at its axis or parameter here |
| b | a module parameter with a sensible default | no | a doc comment with its default and range, listed in the module's README (`ts/pss-client/README.md`, "Parameters") or crate docs |
| c | an operator or deployment knob | no | `docs/DESIGN.md`, "Configuration reference", with a one-line pointer in the code |
| d | a settled constant, invariant, cross-reference or test-only knob | no | an ordinary comment, or nothing; a constant mirrored across languages gets a shared test vector |
| e | a design question still open | no | never a marker; once decided, an ordinary comment pointing at `DECISIONS.md` |

List every marker with `git grep -n "DEV DECISION" -- '*.rs' '*.nr' '*.ts' '*.sh' '*.mjs'
'*.py' '*.toml'`.

## Running a round under another intake

Every tip example runs every round but its init round under secret-shared receipt intake; the
AMM tip and lending also run one round under the other intakes. Any round runs under any
intake by adding glue, never circuit logic: `<round>_shared` serves both secret-shared intakes,
`<round>` both non-secret-shared intakes, each a main over the round's one library function
under pss_core's intake family (`tip::family`: `Plain`, `SharedIntake`). The manifest, the
request function and the client's intake module pick the intake within the family.

| Artifact | Secret-shared on-chain intake (`<round>_shared_onchain`) | On-chain or receipt intake (`<round>`, `<round>_receipt`) |
| --- | --- | --- |
| Circuit | none: `<round>_shared`'s | `circuits/<round>/` once for both (Nargo package, main, `Prover.toml`, `circuits.env` `CIRCUITS` and `TOTAL_CIRCUITS`): the ABI and one call under `pss_core::tip::family::Plain` |
| Manifest | the secret-shared manifest under `shared_onchain` | `<round>.json` and `<round>_receipt.json`: app inputs PUBLIC, `$partial_note` PUBLIC, `$user_nonce` after it, no `C`, outcome key, tag or blinding, `outcome: partial`, outputs `new_c`, `old_c`, `app.*` |
| Request id | `poseidon2(namespace, vk_hash, C)` | `poseidon2(namespace, vk_hash, inputs_hash, user_nonce)` |
| Request function | the secret-shared one's checks and partial note, `outcome_request` over a `SharedOnchainArgs` with the round's layout global (`layouts.nr`), into a public append wrapper | `<round>` and `<round>_with_receipts`: the same checks, `partial_note::commit`, then `onchain_request` into `append_onchain` or `receipt_request` into `append_receipt` |
| Contract state and keys (first such round) | storage `shared_onchain: SharedOnchain<Context>`; `rotate_enc_key`, `set_enc_key`, `get_enc_key`, `get_data_hash`; under key epochs `Keys = KeyEpochs<SharedOnchain<PublicContext>>` and `set_node_keys` handing `Keys::install` the `SharedOnchain` | none |
| Package, row, vk pin | none: `<round>_shared`'s vk registered again under the new name, outside the package list | the package name hash, a round-table row and a place in the non-secret-shared package list (`TipPins.vk_hashes`) |
| Result function | the secret-shared round's | one over `check_round` and the row, then an `apply` that completes the partial note (`PartialResult`) |
| Client | `requestIntake` with the partial note, outcome key and tag from `SecretStore.nextPartial`, and the nodes' enc keys | the same with the clear `partial_note` and no outcome key, tag or enc keys |
| Tests and deployment | a TXE case beside the secret-shared on-chain cases; the e2e deployment's `extra` and `stateKeys` | a TXE case with the round's dummy vk pinned; `outputs.txt` rows; the non-secret-shared deployment's `packages` or `extra`, `stateKeys`, `methods` |
| Layout | the round's global in `layouts.nr` and `testvectors/onchain_layouts.json` (`scripts/gen-intake.py --layouts`) | — |

`scripts/gen-intake.py` derives a round's manifests under the other intakes and holds the
committed ones to that derivation (`--check` runs in `scripts/check-manifests.py` and
`scripts/check-noir.sh`):

```sh
python3 -I scripts/gen-intake.py <example> <round> <intake> --dry-run   # the manifest it would write
python3 -I scripts/gen-intake.py --layouts                              # every layout global and testvectors/onchain_layouts.json
python3 -I scripts/gen-intake.py --check                                # committed manifests match their derivation
```

It writes manifests and layouts only; the main, the request function, the client's builder and
the TXE case are written by hand (a non-secret-shared manifest needs its main first). A
non-secret-shared round goes on the example's non-secret-shared deployment; a new package is a
new deployment, and a new result function adds public bytecode to check against the network's
per-transaction DA limit (a TXE case does not measure it). A round under secret-shared on-chain
intake has a request function and public call of its own, so it shows its round type unless
every round gets one. Lending's rounds under other intakes:
[examples/lending-tip/README.md](../../examples/lending-tip/README.md#rounds-under-other-intakes).

## Changing the design space

Edit `design-space.json`, then:

```sh
python3 -I scripts/check-design-space.py --write-readme   # re-render this page's generated blocks
python3 -I scripts/check-design-space.py --write-bricks   # re-render BRICKS.md and the examples' brick tables
python3 -I scripts/check-design-space.py                  # every reference, constraint, api symbol, reserved name, marker and generated block
```

A new decision axis needs a question in `questions` that sets it and a row in "Where each
choice lives" (the check fails without them). A new brick needs its `api` (the library items an
app calls, under `contract`, `circuit`, `client` or `machine`, each a symbol and its file) or
`internal` with the reason. A new axis value needs its bricks, pros and cons and constraints,
each new constraint in exactly one compatibility rule. A new blueprint must pass every error
constraint, use no deferred, not-offered or experimental value, list every brick its values
need and name its example or say "to build".
