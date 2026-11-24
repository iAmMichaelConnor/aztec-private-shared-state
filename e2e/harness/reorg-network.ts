// The local network of a reorg run (E2E_REORG=1; run.sh starts it in place
// of `aztec start --local-network`). It does what the CLI does for a local
// network (@aztec-labs/aztec's scripts/aztec.sh environment and anvil, then
// createLocalNetwork and the node's RPC and admin servers, as its
// cli/aztec_start_action.js does) and keeps the node object, so it can
// serve the test calls the node's RPC does not have:
//
//   pause, resume          the automine sequencer stops and starts mining
//                          the pool (explicit warps and builds still run)
//   revertToCheckpoint [n] an L1 reorg back to checkpoint n: the node, its
//                          world state and its pool roll back with it, and
//                          empty L1 blocks replace the removed ones up to
//                          the height L1 had
//   proving [on]           the proving loop on or off
//   status                 {paused, proving}
//
// on 127.0.0.1:REORG_PORT, as JSON {"method", "params"}, authenticated by
// the run's admin key (x-api-key, the key whose SHA-256 is
// AZTEC_ADMIN_API_KEY_HASH). The debug RPC's `prove`, `mineBlock` and
// warps, and anvil's own RPC, serve the rest.
//
// Proving. The network starts with the sequencer's own proving loop off
// (automineEnableProveEpoch false) and runs its own in its place: every
// 200 ms it proves up to the latest checkpoint, as the standard network
// does, until a scenario turns it off (`proving [false]`). Then checkpoints
// stay unproven, the proven and finalized tips stay behind, and an epoch
// prune can happen. Anvil runs with --slots-in-an-epoch 32, so its
// finalized block, and with it the node's finalized tip, trails the latest
// by 64 L1 blocks.
//
// Environment: AZTEC_PORT, AZTEC_ADMIN_PORT, AZTEC_ADMIN_API_KEY_HASH,
// ANVIL_PORT, ANVIL_BIN, REORG_PORT (all set by run.sh).
import { spawn } from "node:child_process";
import { createHash, timingSafeEqual } from "node:crypto";
import { createServer } from "node:http";

import { anvilRpcAt, type ReorgCall } from "./reorg-calls.ts";

const env = (name: string): string => {
  const v = process.env[name];
  if (!v) throw new Error(`reorg network: ${name} is not set`);
  return v;
};
const [aztecPort, adminPort, anvilPort, reorgPort] = ["AZTEC_PORT", "AZTEC_ADMIN_PORT", "ANVIL_PORT", "REORG_PORT"].map((n) => Number(env(n)));
const keyHash = Buffer.from(env("AZTEC_ADMIN_API_KEY_HASH"), "hex");
const anvilUrl = `http://127.0.0.1:${anvilPort}`;

// @aztec-labs/aztec's scripts/aztec.sh environment for `start
// --local-network`, before any @aztec-labs module reads it
const defaults: Record<string, string> = {
  ARCHIVER_POLLING_INTERVAL_MS: "500",
  P2P_BLOCK_CHECK_INTERVAL_MS: "500",
  SEQ_TX_POLLING_INTERVAL_MS: "500",
  WS_BLOCK_CHECK_INTERVAL_MS: "500",
  ARCHIVER_VIEM_POLLING_INTERVAL_MS: "500",
  TEST_ACCOUNTS: "true",
  LOG_LEVEL: "info;silent:sequencer;verbose:debug_log",
  DEPLOY_AZTEC_CONTRACTS_SALT: String(Math.floor(Math.random() * 32768)),
  L1_CHAIN_ID: "31337",
  ETHEREUM_HOSTS: anvilUrl,
};
for (const [k, v] of Object.entries(defaults)) process.env[k] ??= v;

const anvil = spawn(env("ANVIL_BIN"), ["--silent", "--port", String(anvilPort), "--slots-in-an-epoch", "32"], { stdio: "inherit" });
process.on("exit", () => anvil.kill());
for (const signal of ["SIGINT", "SIGTERM"] as const) process.once(signal, () => process.exit(0));

for (let i = 0; ; i++) {
  try {
    await anvilRpcAt(anvilUrl, "eth_chainId");
    break;
  } catch (e) {
    if (i >= 100) throw new Error(`reorg network: anvil did not answer on ${anvilUrl}: ${(e as Error).message}`);
    await new Promise((r) => setTimeout(r, 200));
  }
}

const { createLocalNetwork } = await import("@aztec-labs/aztec");
const { registerAztecNodeRpcHandlers } = await import("@aztec-labs/aztec-node");
const { createNamespacedSafeJsonRpcServer, getApiKeyAuthMiddleware, startHttpRpcServer } = await import("@aztec-labs/foundation/json-rpc/server");
const { createConsoleLogger, createLogger } = await import("@aztec-labs/foundation/log");
const { getVKTreeRoot } = await import("@aztec-labs/noir-protocol-circuits-types/vk-tree");
const { protocolContractsHash } = await import("@aztec-labs/protocol-contracts");
const { getPackageVersion } = await import("@aztec-labs/stdlib/update-checker");
const { getVersioningMiddleware } = await import("@aztec-labs/stdlib/versioning");

const userLog = createConsoleLogger();
const log = createLogger("reorg-network");
const { node } = await createLocalNetwork({ l1RpcUrls: [anvilUrl], testAccounts: true, automineEnableProveEpoch: false }, userLog);
const sequencer = node.getAutomineSequencer();
if (sequencer === undefined) throw new Error("reorg network: the node runs no automine sequencer");

// the node's RPC and admin servers, as the CLI starts them
const services = {};
const adminServices = {};
registerAztecNodeRpcHandlers(node, services, adminServices, { debug: true });
const { BarretenbergSync } = await import("@aztec-foundation/bb.js");
await BarretenbergSync.initSingleton();
const versions = { l2CircuitsVkTreeRoot: getVKTreeRoot().toString(), l2ProtocolContractsHash: protocolContractsHash.toString() };
const versioning = getVersioningMiddleware(versions, { packageVersion: getPackageVersion() });
await startHttpRpcServer(createNamespacedSafeJsonRpcServer(services, { http200OnError: false, log, middlewares: [versioning] }), { host: "127.0.0.1", port: aztecPort });
await startHttpRpcServer(createNamespacedSafeJsonRpcServer(adminServices, { http200OnError: false, log, middlewares: [getApiKeyAuthMiddleware(keyHash), versioning] }), {
  host: "127.0.0.1",
  port: adminPort,
});
log.info(`Aztec Server listening on port ${aztecPort}, admin API on ${adminPort}`);

// the proving loop
let proving = true;
let paused = false;
void (async () => {
  for (;;) {
    if (proving) await sequencer.prove().catch((e: unknown) => log.warn(`reorg network: proving failed: ${(e as Error).message}`));
    await new Promise((r) => setTimeout(r, 200));
  }
})();

// the test calls
type CallFn = (params: unknown[]) => Promise<unknown>;
const calls: Record<string, CallFn> = {
  pause: async () => {
    sequencer.pause();
    paused = true;
    await sequencer.syncPoint();
    return { paused };
  },
  resume: async () => {
    sequencer.resume();
    paused = false;
    return { paused };
  },
  revertToCheckpoint: async ([n]) => {
    if (!Number.isInteger(n) || (n as number) < 0) throw new Error(`revertToCheckpoint takes a checkpoint number, not ${JSON.stringify(n)}`);
    // The replacement chain is as long as the one it replaces, as on L1.
    // The node's epoch cache refreshes an entry by reading again the L1
    // block it last read by number; on a shorter chain that block does not
    // exist, and the archiver fails every pass until L1 grows back to it.
    const height = async () => Number(BigInt((await anvilRpcAt(anvilUrl, "eth_blockNumber")) as string));
    const before = await height();
    await sequencer.revertToCheckpoint(n as number);
    for (let h = await height(); h < before; h++) await anvilRpcAt(anvilUrl, "evm_mine");
    return node.getChainTips();
  },
  proving: async ([on]) => {
    if (typeof on !== "boolean") throw new Error(`proving takes true or false, not ${JSON.stringify(on)}`);
    proving = on;
    await sequencer.syncPoint();
    return { proving };
  },
  status: async () => ({ paused, proving }),
} satisfies Record<ReorgCall, CallFn>;
const authorised = (key: string | undefined) => key !== undefined && timingSafeEqual(createHash("sha256").update(key).digest(), keyHash);
createServer((req, res) => {
  let body = "";
  req.on("data", (chunk: string) => (body += chunk));
  req.on("end", () => {
    const answer = (status: number, value: object) => {
      res.writeHead(status, { "content-type": "application/json" });
      res.end(JSON.stringify(value));
    };
    if (!authorised(req.headers["x-api-key"] as string | undefined)) return answer(401, { error: "unauthorised" });
    let call: { method?: string; params?: unknown[] };
    try {
      call = JSON.parse(body) as typeof call;
    } catch {
      return answer(400, { error: "not JSON" });
    }
    const f = call.method === undefined ? undefined : calls[call.method];
    if (f === undefined) return answer(400, { error: `no call ${call.method}; the calls: ${Object.keys(calls).join(", ")}` });
    f(call.params ?? []).then(
      (result) => {
        log.info(`reorg network: ${call.method}(${JSON.stringify(call.params ?? [])}) done`);
        answer(200, { result });
      },
      (e: unknown) => answer(500, { error: (e as Error).message }),
    );
  });
}).listen(reorgPort, "127.0.0.1", () => log.info(`reorg network: test calls on 127.0.0.1:${reorgPort}`));
