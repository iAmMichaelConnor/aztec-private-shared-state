// The counter tip (scenarios/README.md, "counter-tip.ts"; examples/counter-tip):
// one deployment of CounterTip (E2E_TIP=1, E2E_TIP_DEPLOYMENTS="counter-tip"),
// its counter created by the init round with the total 0. alice adds 5 and
// bob adds 7, each under secret-shared receipt intake with a private outcome
// completing the requester's partial note: each opens [0, total after the
// add] and takes the completed note. alice's request carries the node-side
// negative.
import type { Scenario, Step } from "../scenario.ts";

/** `from` adds `amount`: queued, landed on the commitment `previous` with
 * one completed note hash, and its outcome `[0, total]` opened and delivered.
 * `nodeTamper`: the request first goes out as a copy with one Chonk proof
 * field changed, which the node must refuse. */
function add(from: string, amount: number, name: string, previous: string, total: number, nodeTamper = false): Step[] {
  const out = `${name}Out`;
  const outcome = `${name}Outcome`;
  return [
    { tipRequest: "counter_add", namespace: "counter", from, method: "add", inputs: { amount }, name, ...(nodeTamper ? { nodeTamper } : {}) },
    { tipResult: name, name: out, expect: [["eq", `$${out}.oldCommitments[0]`, previous], ["len", `$${out}.noteHashes`, 1]] },
    { tipOutcome: name, owner: from, name: outcome, expect: [["eq", `$${outcome}.plaintext[0]`, 0], ["eq", `$${outcome}.plaintext[1]`, total]] },
  ] as Step[];
}

export const scenario: Scenario = {
  example: "counter-tip",
  accounts: ["operator", "alice", "bob"],
  wallets: { alice: ["operator", "alice"], bob: ["bob"] },
  keys: {},
  contracts: {},
  namespaces: {},
  tip: { counter: "counter-tip" },
  steps: [
    { tipInit: "counter", name: "counterInit" },
    ...add("alice", 5, "aliceAdd", "$counterInit.newCommitments[0]", 5, true),
    ...add("bob", 7, "bobAdd", "$aliceAddOut.newCommitments[0]", 12),
  ],
};
