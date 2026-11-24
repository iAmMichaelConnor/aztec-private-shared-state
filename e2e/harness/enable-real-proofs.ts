// Switches the local network's node to real transaction proof verification
// and confirms from the node's log that the verifier was built. The v6 local
// network always starts with simulated proofs (it ignores PROVER_REAL_PROOFS),
// so run.sh runs this after bootstrap and before anything sends a
// transaction. See the comment on node-side proof verification in run.sh
// for why it sets the flag false and then true, and which environment the
// network needs.
//
// Environment (run.sh sets all four): AZTEC_NODE_URL, AZTEC_ADMIN_PORT,
// E2E_ADMIN_API_KEY (the run-local admin key whose hash the network was
// started with) and NETWORK_LOG (the network's log file).
import { readFileSync } from "node:fs";

import { VERIFIER_STARTED } from "./node-verification.ts";

const { AZTEC_NODE_URL, AZTEC_ADMIN_PORT, E2E_ADMIN_API_KEY, NETWORK_LOG } = process.env;
if (!AZTEC_NODE_URL || !AZTEC_ADMIN_PORT || !E2E_ADMIN_API_KEY || !NETWORK_LOG) {
  throw new Error("missing AZTEC_NODE_URL, AZTEC_ADMIN_PORT, E2E_ADMIN_API_KEY or NETWORK_LOG");
}
const networkLog = NETWORK_LOG;

async function rpc(url: string, method: string, params: unknown[], headers: Record<string, string> = {}): Promise<any> {
  const response = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
  if (!response.ok) throw new Error(`${method}: HTTP ${response.status}`);
  const body = (await response.json()) as { result?: unknown; error?: unknown };
  if (body.error) throw new Error(`${method}: ${JSON.stringify(body.error)}`);
  return body.result;
}
const setRealProofs = (realProofs: boolean) =>
  rpc(`http://127.0.0.1:${AZTEC_ADMIN_PORT}`, "nodeAdmin_setConfig", [{ realProofs }], {
    "x-api-key": E2E_ADMIN_API_KEY,
  });
const verifierLines = () =>
  readFileSync(networkLog, "utf8")
    .split("\n")
    .filter((line) => line.includes(VERIFIER_STARTED));

if (verifierLines().length !== 0) {
  throw new Error("the node log already shows a transaction verifier before the switch");
}
// On the first setConfig after start the node merges the new values into a
// config object it shares with the local network's sequencer before it
// compares old and new, so it sees no change and keeps its accept-anything
// verifier. Setting false first spends that call harmlessly; setting true
// is then a change, on which the node builds its real verifiers.
await setRealProofs(false);
await setRealProofs(true);

const info = await rpc(AZTEC_NODE_URL, "node_getNodeInfo", []);
if (info.realProofs !== true) throw new Error("node still reports simulated proofs");
// The flag alone proves nothing: require the node's own log line.
let lines: string[] = [];
for (let i = 0; i < 100 && lines.length === 0; i++) {
  await new Promise((resolve) => setTimeout(resolve, 200));
  lines = verifierLines();
}
if (lines.length === 0) {
  throw new Error(`node reports realProofs but its log lacks "${VERIFIER_STARTED}"`);
}
console.log(`Node transaction proof verification enabled; node log: ${lines[0]!.trim()}`);
