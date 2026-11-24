// The counter tip's client (examples/counter-tip): the calls an app's client
// makes on the default blueprint, each a pss-client brick call. A minimal
// example that moves no token. The root build type-checks it (npm run
// build); no suite runs it.
//
// The flow: deploy (the operator, once), then per request: request an add
// (requestOutcome), wait until the queue has finished it (waitForRequest),
// read the private outcome and hand the completed note to the requester's
// PXE (readAndDeliverOutcome). The network's relayer lands the
// init round and every result; the client never lands anything.
//
// Before a request a wallet registers the fee payment (pss-client
// registerWfj): every request pays under wFJ, so the requester's account
// never shows as the fee payer.
import type { AztecAddress } from "@aztec-labs/aztec.js/addresses";
import type { AztecNode } from "@aztec-labs/aztec.js/node";
import type { Wallet } from "@aztec-labs/aztec.js/wallet";
import type { ContractArtifact } from "@aztec-labs/stdlib/abi";
import {
  type DeployedTipApp,
  type Descriptor,
  deployTipApp,
  type OutcomeRequest,
  OwnerKey,
  readAndDeliverOutcome,
  requestOutcome,
  SecretStore,
  tipAppAt,
  type TipNetwork,
  waitForRequest,
} from "@aztec-pss/pss-client";
import { readFileSync } from "node:fs";

/** A file of this example, parsed. */
function exampleJson(path: string): unknown {
  return JSON.parse(readFileSync(new URL(`../${path}`, import.meta.url), "utf8"));
}

/** The app: its deployment descriptor and its circuit manifests, by package. */
const APP = {
  descriptor: exampleJson("deployments/counter-tip.json") as Descriptor,
  manifests: { counter_init: exampleJson("manifests/counter_init.json"), counter_add: exampleJson("manifests/counter_add.json") },
};

/** What the network's operator publishes: where its orchestrator listens and
 * each node's keys, node 0 first. */
export type Network = TipNetwork;

/** The app's build: the compiled contract, and per circuit its nargo output
 * and vk hash (`bb write_vk`). */
export interface Build {
  artifact: ContractArtifact;
  circuits: { counter_init: unknown; counter_add: unknown };
  vkHashes: { counter_init: string; counter_add: string };
}

/** A deployed counter as its clients see it: the node, the contract and the
 * namespace's pss-client. */
export type Counter = DeployedTipApp<AztecNode>;

/** Deploy the counter (the operator, once): deployTipApp generates the
 * contract manifest from the deployment descriptor and the circuit manifests,
 * REGISTERs it under the address the constructor's pins give, deploys and
 * configures. The network then runs counter_init and its relayer lands it.
 * `owner` is the namespace owner's key: keep it, it signs every later
 * REGISTER and DISABLE. */
export async function deployCounter(
  node: AztecNode,
  wallet: Wallet,
  operator: AztecAddress,
  network: Network,
  build: Build,
  owner: OwnerKey,
): Promise<Counter> {
  return deployTipApp({ ...APP, node, wallet, operator, network, build, owner });
}

/** A deployed counter, from a user's wallet: the contract at `address` and the
 * namespace's pss-client. */
export function counterAt(node: AztecNode, wallet: Wallet, network: Network, build: Build, address: AztecAddress): Counter {
  return tipAppAt({ ...APP, node, wallet, network, build, address });
}

/** Request an add of `amount` from `from`: the next request secrets of the
 * requester's store, the amount secret-shared among the nodes for their
 * receipts over C, and the request function `add` sent. Keep what it returns
 * until the outcome is read, and the secrets store per wallet and namespace:
 * a lost store is rebuilt from the wallet secret (SecretStore.recover). */
export async function requestAdd(c: Counter, secrets: SecretStore, from: AztecAddress, amount: bigint): Promise<OutcomeRequest> {
  return (await requestOutcome(c, { circuit: "counter_add", method: "add", inputs: { amount }, secrets }, { from })).request;
}

/** Wait until the queue has finished the request: true when its result
 * landed, false when it was skipped (stale: request again). */
export async function waitForAdd(c: Counter, r: OutcomeRequest, timeoutMs = 600_000): Promise<boolean> {
  return (await waitForRequest(c, r, { timeoutMs })).status === "applied";
}

/** Read the landed add's private outcome and hand the completed note to
 * `owner`'s PXE through the contract's `deliver_outcome` when it is the
 * logged note (a round whose shares did not open C may have completed
 * another partial note). Returns `[code, total]`: code 0 and the total
 * after this add, or a failure code and 0. */
export async function readAdd(c: Counter, r: OutcomeRequest, owner: AztecAddress): Promise<{ code: bigint; total: bigint }> {
  const found = await readAndDeliverOutcome(c, r, owner);
  if (found === undefined) throw new Error(`no outcome of request ${r.chainRequestId} on chain yet`);
  const [code, total] = found.plaintext;
  return { code: code!, total: total! };
}

/** The whole round trip for one user: request, wait, read. */
export async function add(c: Counter, secrets: SecretStore, from: AztecAddress, amount: bigint): Promise<{ code: bigint; total: bigint } | "skipped"> {
  const r = await requestAdd(c, secrets, from, amount);
  return (await waitForAdd(c, r)) ? readAdd(c, r, from) : "skipped";
}
