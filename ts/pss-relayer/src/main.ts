// The relayer as an operator runs it:
//
//   node --conditions=source --import <repo>/ts/hooks/register.mjs ts/pss-relayer/src/main.ts relayer.json
//
// (register.mjs is the JSON-import hook the @aztec-labs packages need). The
// configuration file is JSON:
//
//   {
//     "aztecNodeUrl": "http://127.0.0.1:8380",
//     "client": "<a pss-client configuration JSON file, or the object>",
//     "contractAddress": "0x...",
//     "artifact": "<the app contract's aztec compile output>",
//     "upgradeArtifacts": ["<another class's aztec compile output>"],  (optional; upgrades: contract)
//     "vk": { "<circuit>": "<its vk.json from bb write_vk --output_format json>" },
//     "init": { "circuit": "<the init circuit>", "method": "<the app's init function>", "inputs": ["0x.."] },
//     "methods": { "<circuit>": { "name": "<the app's result function>", "args": [<its arguments before the library's>] } },
//     "account": { "keyFile": "<a mode 0600 JSON file: { secretKey, signingKey, salt }>" } | { "secretKey": "0x..", "signingKey": "0x..", "salt": "0x.." } | "local-network",
//     "fee": { "method": "wfj" | "account", "gas": { "result": { "gasLimits": { "daGas": <n>, "l2Gas": <n> } }, "skip": { ... } } },
//     "proverEnabled": true,
//     "pollIntervalMs": 2000,
//     "statusPort": 3301,
//     "encoder": "<optional module exporting encode and resultFunction>"
//   }
//
// The stale period is not configured here: the relayer reads it from its
// client configuration's `staleBlocks` (staleBlocksOfClient), the value of the
// registered contract manifest that the contract's constructor took. Relative
// paths inside the file are read from its directory (config-file.ts). It serves
// GET /status on 127.0.0.1:statusPort (the last tick, as JSON) and stops on
// SIGINT or SIGTERM. `init` (optional) is the app's init round, which the
// relayer lands before the queue runs: the init circuit (one of the client's
// circuits, with its vk under `vk`), its inputs (the constants the app's
// Config pins; default none) and the app's init function; GET /status then
// also says where it stands (`init`: pending, landed with its transaction,
// or written). `methods` (optional) names the result function of each
// circuit whose results do not land through `process_result`, with the
// arguments it takes before the library's (a client circuit each, a function
// of the artifact each; examples/lending-tip's secret-shared rounds,
// `{ "name": "process_shared", "args": [1] }` for the deposit and so on, the
// round's `ROUND_*` index); every other circuit's results land through
// `process_result`. A result transaction calls no
// other contract privately, so the relayer's PXE registers the app contract
// alone. `fee` is the app's fee setting
// (pss-client's FeeSetting: `method` "wfj" or "account", `gas` per
// transaction kind, of which the relayer sends `result` and `skip`; default
// wFJ with no fixed gas); under "wfj" the account must hold a private
// balance in wFJ before the relayer starts.

import { createServer } from "node:http";
import { pathToFileURL } from "node:url";

import { loadContractArtifact } from "@aztec-labs/stdlib/abi";
import { vkFieldsFromBbJson, type FeeSetting, type PssClientConfig, type ResultFunction } from "@aztec-pss/pss-client";

import { createAztecRelayer, type RelayerAccount } from "./aztec.ts";
import { configAccount, parseJson, readConfigFile } from "./config-file.ts";

// Operator knob: DESIGN.md, "Configuration reference" (pss-relayer
// aztecNodeUrl, statusPort). Defaults http://127.0.0.1:8380 and 3301, the tip
// harness's ports; the status endpoint binds loopback only, and 0 turns it off.
export const DEFAULT_AZTEC_NODE_URL = "http://127.0.0.1:8380";
export const DEFAULT_STATUS_PORT = 3301;

interface FileConfig {
  aztecNodeUrl?: string;
  client: string | PssClientConfig;
  contractAddress: string;
  artifact: string;
  /** Under upgrades: contract, the artifacts of the classes the app may move to. */
  upgradeArtifacts?: string[];
  vk: Record<string, string>;
  init?: { circuit: string; method: string; inputs?: string[] };
  methods?: Record<string, ResultFunction>;
  account: RelayerAccount | { keyFile: string };
  fee?: FeeSetting;
  proverEnabled?: boolean;
  pollIntervalMs?: number;
  statusPort?: number;
  encoder?: string;
}

const replacer = (_k: string, v: unknown) => (typeof v === "bigint" ? v.toString() : v instanceof Error ? v.message : v);

async function main(path: string | undefined) {
  const file = readConfigFile<FileConfig>(path, "usage: main.ts <relayer.json>");
  const { cfg, at, read } = file;
  const client = (typeof cfg.client === "string" ? parseJson(read(cfg.client), at(cfg.client)) : cfg.client) as PssClientConfig;
  const encoder = cfg.encoder ? ((await import(pathToFileURL(at(cfg.encoder)).href)) as { encode?: never; resultFunction?: never }) : {};
  const log = { info: (m: string) => console.log(`[relayer] ${m}`), warn: (m: string) => console.warn(`[relayer] ${m}`) };
  const r = await createAztecRelayer({
    aztecNodeUrl: cfg.aztecNodeUrl ?? DEFAULT_AZTEC_NODE_URL,
    client,
    contract: { address: cfg.contractAddress, artifact: loadContractArtifact(JSON.parse(read(cfg.artifact))) },
    upgradeArtifacts: (cfg.upgradeArtifacts ?? []).map((p) => loadContractArtifact(JSON.parse(read(p)))),
    vkFields: Object.fromEntries(Object.entries(cfg.vk).map(([name, p]) => [name, vkFieldsFromBbJson(read(p))])),
    init: cfg.init,
    methods: cfg.methods,
    account: configAccount(cfg.account, file, log),
    fee: cfg.fee,
    proverEnabled: cfg.proverEnabled,
    pollIntervalMs: cfg.pollIntervalMs,
    encode: encoder.encode,
    resultFunction: encoder.resultFunction,
    log,
  });
  const port = cfg.statusPort ?? DEFAULT_STATUS_PORT;
  const server =
    port === 0
      ? undefined
      : createServer((req, res) => {
          if (req.method === "GET" && req.url === "/status") {
            res.writeHead(200, { "content-type": "application/json" });
            res.end(JSON.stringify({ from: r.from.toString(), last: r.relayer.last ?? null, init: r.relayer.initStatus ?? null }, replacer));
          } else {
            res.writeHead(404).end();
          }
        }).listen(port, "127.0.0.1");
  log.info(
    `relaying for ${cfg.contractAddress} from ${r.from}, stale period ${r.relayer.staleBlocks ?? "disabled"}` +
      `${cfg.init ? `, init round ${cfg.init.circuit} through ${cfg.init.method}` : ""}${server ? `; status on 127.0.0.1:${port}` : ""}`,
  );
  r.relayer.start();
  const shutdown = async () => {
    server?.close();
    await r.close();
    process.exit(0);
  };
  process.on("SIGINT", () => void shutdown());
  process.on("SIGTERM", () => void shutdown());
}

main(process.argv[2]).catch((e) => {
  console.error(`[relayer] ${e?.stack ?? e}`);
  process.exit(1);
});
