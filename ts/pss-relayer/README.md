# pss-relayer

The operator-run relayer at the tip of the chain. It reads the app contract's queue, FETCHes
the head's latest result from the orchestrator through `pss-client`, and lands it with
`process_result` (or the result function the configuration names for its circuit). It sends
`skip()` once the head is stale, and lands the app's init round before anything is queued
(again, without a restart, when a replaced block takes the landed init off the chain while
nothing is queued). When the chain goes back it sends results it held for their reverts
again.
It trusts the orchestrator for liveness only: every result passes pss-client's checks before
it is sent. The module map is the header of `src/index.ts`; the design is
`docs/ARCHITECTURE.md` section 6, row "relayer".

The package also holds a node operator's tool: `rotate-enc-key` signs the node's `enc` key on
its admin socket and submits it to each secret-shared on-chain intake contract
(`src/enc-key.ts`).

## Running the relayer

```sh
npm run start --workspace ts/pss-relayer -- /path/to/relayer.json
# the same, from the repository root:
# node --conditions=source --import ./ts/hooks/register.mjs ts/pss-relayer/src/main.ts relayer.json
```

`ts/hooks/register.mjs` is the JSON-import hook the `@aztec-labs` packages need. npm runs the
script in `ts/pss-relayer`, so give it an absolute path. The configuration is one JSON file;
relative paths inside it are read from its directory. The full format
is the header of `src/main.ts`.

| Key | What | Default |
| --- | --- | --- |
| `aztecNodeUrl` | the Aztec node's JSON-RPC URL | `http://127.0.0.1:8380` |
| `client` | the pss-client configuration (a file or the object): orchestrator, pinned node keys, vk hashes, the tip circuits and manifests. A circuit's optional `aliasOf` names the target result reader and requires a matching vk hash. Client construction refuses two result readers for one vk hash. | required |
| `contractAddress`, `artifact` | the app contract and its `aztec compile` output | required |
| `vk` | each circuit's `vk.json` (`bb write_vk --output_format json`) | required |
| `account` | the sending account: `{ "keyFile": "<path>" }`, a JSON file `{ "secretKey", "signingKey", "salt" }` of mode 0600; or the same keys inline; or `"local-network"` for the local network's public test account | required |
| `fee` | the app's fee setting (pss-client `FeeSetting`); the relayer sends the `result` and `skip` kinds | wFJ, no fixed gas |
| `init` | the init round: `{ "circuit", "method", "inputs" }` | none |
| `methods` | the result function per circuit that does not land through `process_result` | none |
| `proverEnabled` | real client-side proofs | `true` |
| `pollIntervalMs` | the period between ticks | 2000 |
| `statusPort` | `GET /status` on 127.0.0.1; 0 turns it off | 3301 |
| `encoder` | a module exporting `encode` and `resultFunction`, for an app whose result call does not take the library's `TipResult` | none |

Keep the account's keys in a key file: the tools refuse a key file that group or others have
access to, and warn when the keys sit inline in a configuration file that others can read. A
key string is hex, with or without `0x`; an error names the key, never its value.

The stale period is not configured here: the relayer reads it from its client
configuration's `staleBlocks`, the registered contract manifest's `queue.stale_blocks`. A failed `skip()` is sent again after a backoff that doubles per failure, up to
`MAX_SKIP_BACKOFF_TICKS` ticks. `test/local-network.ts` embeds the relayer with `createAztecRelayer`, as
main.ts runs it.

## Rotating a node's enc key

```sh
npm run rotate-enc-key --workspace ts/pss-relayer -- /path/to/rotate.json
```

The configuration format (`aztecNodeUrl`, `adminSocket`, `party`, `contracts`, `account`,
`fee`, `proverEnabled`; `account` required as above) is the header of
`src/rotate-enc-key.ts`.

## Tests

`npm test --workspace ts/pss-relayer` runs the unit tests (`test/*.test.ts`) against a mock
orchestrator and an in-memory queue. `test/local-network.sh` is a manual check against a
real local Aztec network: it starts `aztec start --local-network` on its own ports, deploys
`pss_public_contract_test`, and checks that the relayer stays idle on an empty queue and
sends `skip()` for a stale head and only then. It needs the pinned toolchain
(`scripts/install-toolchain.sh --with-foundry`); its ports and timeouts are in its header.
