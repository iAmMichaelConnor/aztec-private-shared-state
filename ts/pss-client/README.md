# pss-client

The user side of private shared state on Aztec: building and sending sidecar
requests, tip requests under every intake, receipts, results and outcomes. The module map
is the header of `src/index.ts`; the design is `docs/ARCHITECTURE.md`. The package entry
(`src/index.ts`) is the public API; `@aztec-pss/pss-client/internal` re-exports every module
for this package's tests and `@aztec-pss/test-support`. Tests: `npm test` at the repository
root; `npm run build` type-checks and emits `dist/`.

## The hidden requester

No request names the account that sends it (`docs/ARCHITECTURE.md` section 6, "The hidden
requester"). The non-secret-shared intakes' chain request id is `poseidon2([namespace, vk_hash,
inputs_hash, user_nonce])`, with `user_nonce` 128 random bits per request (`newUserNonce`;
never a counter, which would make ids guessable and link a user's requests). The app's
request function reads no `msg_sender`, so `submitIntake` sends the same arguments from
any account; on-chain intake's request log carries the inputs and the nonce only, and a
receipt body (`POST /v1/receipt`) carries the clear inputs and the nonce only.
`assertNoRequester` (`src/audit.ts`) checks a set of places (non-secret-shared ids, receipt bodies and
rows, public maps, call arguments, logs, public inputs) for given addresses; the e2e
drivers use it.

What the client does not hide:

- **The fee payer.** Every transaction pays through the private fee-payment contract;
  paying from the user's own account names it.
- **The network address on the receipt route.** Receipt requests go to the orchestrator,
  which sees the client's IP address and the time of each request and could link them to
  the request id it returns; the nodes see only the orchestrator. A user who must hide its
  network address from the orchestrator reaches it through a mixnet or a relay (Tor, a
  VPN, an operator-independent proxy). That is outside this client: point
  `orchestratorUrl` at the relay's entry, and keep the pinned node keys, which the client
  checks whatever path the answers take.

## Request secrets and ownership by note

Since no request names its requester, an entry of a shared tree can be owned by note
(`docs/ARCHITECTURE.md` section 6, "Ownership by note"; a lending position is the worked
example): the user's request commits a partial note of its own address, and a request on
an open entry opens one of the user's notes of it in the app's private function.
`SecretStore` (`src/secrets.ts`) derives each request's `rho`, `$outcome_key` and `$outcome_tag` from a wallet secret the app keeps and a
per-namespace request counter `n`; `nextPartial(owner)` takes the next `n`, saves the
counter before it returns (a request that fails or is never sent still uses up its `n`),
and returns the partial note `partialCommitment(owner, rho)` under `$partial_note`, the
request function's `rho` in its place and the derived key and tag as
`buildSharedReceiptRequest`'s `randomness.secrets`. A secret-shared round's completed note
is rebuilt with `OutcomeKeys`' `rho` and `requestId` (the chain request id); a non-secret-shared
round's is completed in public by the app's `apply`, once the client has handed the
request's offchain partial-note message to the app's `offchain_receive`
(`offchainReceiveArgs`). A round whose C takes a standing delivery handle (`src/handle.ts`;
lending's requests on a borrower position) takes `SecretStore.handle(owner, n)` of the
same `n`: `handle_partial` and `handle_key` among the inputs, the handle's randomness in
the commitment's place among the request function's arguments. A round another party
requested may complete that handle: `DeliveryReader` finds the delivery under the
handle's tag, opens it with its key and rebuilds the note (its packed fields carry the
delivering request's id; a rebuild that is not the logged note hash is refused), which the client hands to the app's outcome-note utility under
the handle's randomness (`outcomeDeliveryArgs`). An owner on an app with exit tags
(`src/hatch.ts`) that does not know which round delivered reads the transaction that spent
its newest note's exit tag (`exitTagSpender`: the block the nullifier tree names, read by
its hash) and the delivery among its private logs (`DeliveryReader.readIn`); no old public
state is read, so a node with the default world-state history serves it however long the
app has been frozen. `recoverExitNote` walks this from the newest note it holds, through
every notice in a row, to the note an exit takes, or says the tag was spent with no
delivery (the owner's own exit, or a round of its own whose note this client lacks). A user who loses its local state calls `recover` with the wallet
secret alone: it looks for each request's outcome for `n = 0, 1, …` and stops after
`DEFAULT_GAP_LIMIT` (20) consecutive `n` with none; the opening request's note names the
assigned index, and every later note of an entry names it. Run it while no request is
still in flight. The counter lives in any `RequestStore`; give it a file of its own
(`JsonFileRequestStore`) when it must survive the process.

## The keeper's loop

A keeper sweeps a tree-valued key through two rounds (`docs/ARCHITECTURE.md` section 6, "A
read-only window on a tree key"): a scan round reads the window of `W` leaves from `start`
and reports, to the keeper alone, a bit per leaf (the app's predicate) and the window's
occupied count; an act round then acts on the reported indices. `keeperPass`
(`src/keeper.ts`) sweeps the tree once. `keeperShape` reads `W`, the depth, the scan's
`start` input and the act round's index and count inputs from the two manifests. The
caller's `scan(start)` requests a scan and resolves to its opened outcome (`scanReport`);
the pass hands each window's reported indices (`reportedIndices`) to the caller's `act`,
`K - 1` per round with the last round's count the number used (`actRounds`), before it
requests the next window. It stops at the first window that is not full (`W` occupied,
`W - 1` in window 0, whose index 0 is the header): leaves are appended and never
reclaimed, so the tree ends there. It also stops at the tree's last window, or at a scan
that is not ok (its code returned, for the next pass to retry). The lending example is the
worked case: its scan reports unhealthy positions at the pinned price and its liquidate
round is the act round ([Keeper round](../../examples/lending-tip/README.md#keeper-round)).

## The contract manifest

A deployment's contract manifest (`docs/contract-manifest.schema.json`) is generated, never
written by hand: `src/contract-manifest.ts` (`buildContractManifest`) takes the slots from
the compiled contract artifact, the vk hashes from the compiled circuits, and the rest from
the deployment's descriptor (`examples/<example>/deployments/<deployment>.json`: the package
list with each package's circuit and state key names, the init inputs as Config members, the
stale period, the contract each placeholder pinned read calls). `contractManifestHash` and
`packagesHash` are the hash rules `testvectors/contract_manifest.json` fixes. The command:

```sh
pss-manifest build --descriptor <file> --example <dir> [--artifact <contract.json>] \
  [--circuits <dir>] [--contract <name>=<address> ...] [--stale-blocks <n>|null] [--out <file>]
```

`--circuits` holds the compiled circuits (default `$DATA_DIR/circuits`, else
`machine/data/circuits`, where `scripts/prepare-data.sh` writes them); each vk hash is
computed with bb (`localVkHash`, `BB_BIN`). It prints the manifest hash. Without the
package build, run it as `node --conditions=source src/bin/pss-manifest.ts build ...`.

## REGISTER

REGISTER sends one contract manifest registration message (the manifest message) per
namespace: the contract manifest and each circuit it names once, stripped to `noir_version`,
`hash`, `abi`, `bytecode`, a fixed `debug_symbols` and an empty `file_map` (`stripCircuit`).
`registerManifest` reads the next `seq`, strips the circuits, signs with the owner key and
checks the answer (`verifyManifestResponse`): the manifest hash and the packages hash it
computes itself and every node signature under the contract's key set, over the manifest
result message. `deployTip` puts the manifest hash into the constructor's pins (`tipPins`),
registers a tip app's contract manifest once at seq 0, between the address and the
deployment, and builds `configure`'s one answer (its seq and the three manifest signatures)
from the response (`configureArgs`). The same contract manifest at the next seq re-enables every
package a DISABLE stopped; another one replaces the stored one on the sidecar path only (the
nodes refuse it for a tip namespace). A REGISTER may take long (a vk build per circuit, and
at seq 0 the registration round): `REGISTER_TIMEOUT_MS`, 1,060 s by default (the orchestrator's node call bound plus 60 s).

The configuration's `staleBlocks` is the namespace's stale period, the contract manifest's
`queue.stale_blocks` (null: a head is never skipped); pss-relayer skips a stale head by it.

## Replaced blocks

Every transaction the library sends (requests, result and init landings, `skip`,
`configure`, `rotate_enc_key`, upgrades) returns once it is in a proposed block (`SEND_WAIT`,
`waitForStatus: proposed`, in place of aztec.js's default `checkpointed`); where a call
takes the caller's send options (`requestIntake`, the Lander's `sendOptions`, the
upgrades), a `wait` there replaces it. A replaced block (a proposer's block that never reached a checkpoint,
an epoch prune, an L1 reorg) can then still take a request transaction or the
transaction carrying an outcome off the chain; pss-relayer lands a result again when it
reads the head still queued. `pollResult` checks its request's queue index again on every poll and
does not report another request's fate (barring a replacement of the block it reads
between the reads of one poll, which are by block number). Two helpers in `src/watch.ts` are opt-in, for an
app that wants the library to act on such a replacement: `watchRequest` reads a request
transaction's receipt until it reaches `until` and sends the request again (the app's
`resend`, at most three times) once two reads in a row say the node's pool dropped it;
`watchOutcome` delivers an outcome note again each time the block that carried it is
replaced (the receipt is no longer mined, or names another block) and the outcome lands
again. Nothing calls them unless the app does.

## Parameters

Module parameters with defaults, each documented where it is read. The deployment's
configuration (`PssClientConfig` in `src/config.ts`: node keys, vk hashes, timeouts, the
receipt TTL and margin, the request and record stores) is in `docs/DESIGN.md`,
"Configuration reference".

| Parameter | Where | Default |
| --- | --- | --- |
| intake parameter names of the request function | `src/intake.ts` (`layIntakeArgs`) | the names of `pss_public_contract`'s examples and both tip apps |
| `resultFunction`, the app's result function per circuit and its leading arguments (`resultFunctions` from a map) | `src/lander.ts` | `{ name: "process_result" }` (`DEFAULT_RESULT_METHOD`) |
| `attempts`, `refetchDelayMs` of `submitResult` | `src/lander.ts` | 3 transactions, 2,000 ms |
| process_result encoder | `src/tip-result.ts` (`defaultProcessResultEncoder`) | `[result, ...stateArgs, signatures]` |
| init encoder | `src/init-result.ts` (`defaultInitEncoder`) | `[...new_c, (new_hashes,) ...stateArgs, signatures]` |
| `fromIndex`, `intervalMs`, `timeoutMs` of `pollResult` | `src/outcome.ts` | 0, 2,000 ms, none |
| `until`, `intervalMs` of `watchRequest` and `watchOutcome` | `src/watch.ts` | `proven`, 2,000 ms |
| `isValid`, the app's static check | `src/tip.ts` | none |
| namespace owner key | `src/signing.ts` (`OwnerKey.generate`, `save`) | 64 CSPRNG bytes mod the Grumpkin order, saved mode 0600 in a 0700 directory; or any `SchnorrSigner` |
| `DEFAULT_GAP_LIMIT` of `SecretStore.recover` | `src/secrets.ts` | 20 |
