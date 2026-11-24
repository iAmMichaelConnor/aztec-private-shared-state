// What the reorg network's launcher (reorg-network.ts) and the reorg steps
// (engine/reorg.ts) share: the test calls the launcher serves, and one call
// of anvil's JSON-RPC. No imports, so the launcher loads it before it sets
// the environment the @aztec-labs modules read.

/** The reorg network's test calls (reorg-network.ts). */
export type ReorgCall = "pause" | "resume" | "revertToCheckpoint" | "proving" | "status";

/** One call of anvil's JSON-RPC at `url`; an Error naming the method when
 * anvil answers an error. */
export async function anvilRpcAt(url: string, method: string, params: unknown[] = []): Promise<unknown> {
  const res = await fetch(url, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }) });
  const body = (await res.json()) as { result?: unknown; error?: unknown };
  if (body.error !== undefined) throw new Error(`anvil ${method}: ${JSON.stringify(body.error)}`);
  return body.result;
}
