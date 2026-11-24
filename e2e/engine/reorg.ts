// What the reorg steps share: the reorg network's test calls
// (harness/reorg-network.ts, E2E_REORG=1), the node's four chain tips,
// anvil's own RPC, and the services' log lines.
import { readFileSync } from "node:fs";
import { join } from "node:path";

import { anvilRpcAt, type ReorgCall } from "../harness/reorg-calls.ts";
import type { RunContext } from "./context.ts";
import { check } from "./scope.ts";

/** One test call of the reorg network on 127.0.0.1:REORG_PORT. Fails, naming
 * E2E_REORG, when the run's network is not the reorg network. */
export async function reorgCall(method: ReorgCall, params: unknown[] = []): Promise<unknown> {
  const { REORG_PORT, E2E_ADMIN_API_KEY } = process.env;
  check(process.env.E2E_REORG === "1" && REORG_PORT !== undefined && E2E_ADMIN_API_KEY !== undefined, "a reorg step runs only on the reorg network (E2E_REORG=1, which run.sh exports with REORG_PORT)");
  const res = await fetch(`http://127.0.0.1:${REORG_PORT}`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-api-key": E2E_ADMIN_API_KEY },
    body: JSON.stringify({ method, params }),
    signal: AbortSignal.timeout(600_000),
  });
  const body = (await res.json()) as { result?: unknown; error?: string };
  check(res.ok && body.error === undefined, `reorg network ${method}: HTTP ${res.status}: ${body.error ?? ""}`);
  return body.result;
}

/** The node's four tips by block number, and the checkpointed tip's checkpoint. */
export interface Tips {
  proposed: number;
  checkpointed: number;
  proven: number;
  finalized: number;
  checkpoint: number;
}

export async function chainTips(ctx: RunContext): Promise<Tips> {
  const t = await ctx.network.node.getChainTips();
  return {
    proposed: Number(t.proposed.number),
    checkpointed: Number(t.checkpointed.block.number),
    proven: Number(t.proven.block.number),
    finalized: Number(t.finalized.block.number),
    checkpoint: Number(t.checkpointed.checkpoint.number),
  };
}

/** One call of anvil's JSON-RPC (ANVIL_PORT). */
export async function anvilRpc(method: string, params: unknown[] = []): Promise<unknown> {
  const port = process.env.ANVIL_PORT;
  check(port !== undefined, "ANVIL_PORT is not set (run.sh exports it)");
  return anvilRpcAt(`http://127.0.0.1:${port}`, method, params);
}

/** The services whose logs a step counts lines of. */
export type LogOf = "node" | "orchestrator" | "relayer";

/** How many lines holding `match` the service's logs have: the three nodes'
 * together, the orchestrator's, or the deployment's relayer's. */
export function logLines(ctx: RunContext, of: LogOf, match: string, deployment: string): number {
  const files = of === "node" ? [0, 1, 2].map((i) => `node${i}.log`) : of === "orchestrator" ? ["orchestrator.log"] : [`relayer-${deployment}.log`];
  return files.reduce((n, f) => n + readFileSync(join(ctx.harness.runDir, "logs", f), "utf8").split("\n").filter((l) => l.includes(match)).length, 0);
}
