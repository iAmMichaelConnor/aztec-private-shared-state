// Node 3 (index 2) replaced under load (scenarios/README.md,
// "amm-tip-replace-node.ts"; docs/ARCHITECTURE.md section 6, "Node
// replacement and key epochs"): on the non-secret-shared AMM tip deployment
// (E2E_TIP=1, E2E_TIP_DEPLOYMENTS="amm-tip"), one swap lands under key epoch
// 0; the orchestrator pauses; two swaps are queued and wait; node 2 is
// stopped and a newcomer with fresh keys and an empty store takes its place
// (the share refresh by nodes 0 and 1, the newcomer's import, the audit, the
// two signatures of the new key set, rotate_keys landed, the orchestrator
// restarted on the new key set and resumed); both queued swaps then run at
// nodes 0, 1 and the newcomer and land, the relayer's and the driver's
// clients checking the results under the contract's key epoch 1.
import type { Expect, Scenario, Step } from "../scenario.ts";
import { result } from "./amm-tip.ts";

const swap = (from: string, inputs: { amount_in: number; direction: 0 | 1; min_out: number }, name: string): Step =>
  ({ tipRequest: "amm_swap_tip", namespace: "main", from, method: "swap", inputs, name }) as Step;

const traded = (request: string): Expect[] => [
  ["eq", `$${request}Out.ok`, 1],
  ["eq", `$${request}Out.appOutputs[0]`, 0],
  ["gt", `$${request}Out.appOutputs[1]`, 0],
];

export const scenario: Scenario = {
  example: "amm-tip",
  accounts: ["operator", "alice", "bob"],
  keys: {},
  contracts: {},
  namespaces: {},
  tip: { main: "amm-tip" },
  steps: [
    { tipInit: "main", name: "mainInit" },
    // under key epoch 0, the constructor's keys
    // (the run's node-side negative: a tampered copy of this request's transaction is refused by the node)
    { ...swap("alice", { amount_in: 10_000, direction: 0, min_out: 1 }, "before"), nodeTamper: true } as Step,
    result("before", [...traded("before"), ["eq", "$beforeOut.oldCommitments[0]", "$mainInit.newCommitments[0]"]]),

    // paused between rounds: the two swaps queue and wait
    { tipPause: "pause" },
    swap("alice", { amount_in: 4_000, direction: 1, min_out: 1 }, "queuedA"),
    swap("bob", { amount_in: 3_000, direction: 0, min_out: 1 }, "queuedB"),

    // node 2 replaced: refresh, import, audit, declare, resume
    { tipReplaceNode: 2, deployments: ["main"], from: "operator", name: "newKeys" },

    // both queued swaps run at the new network and land, in queue order
    result("queuedA", [...traded("queuedA"), ["eq", "$queuedAOut.oldCommitments[0]", "$beforeOut.newCommitments[0]"]]),
    result("queuedB", [...traded("queuedB"), ["eq", "$queuedBOut.oldCommitments[0]", "$queuedAOut.newCommitments[0]"]]),
  ],
};
