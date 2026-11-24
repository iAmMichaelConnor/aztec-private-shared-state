// A landed result removed by a reorg and landed again (scenarios/README.md,
// "The reorg scenarios"; E2E_REORG=1 E2E_TIP=1
// E2E_TIP_DEPLOYMENTS="counter-tip"). alice's add lands and she takes her
// outcome note; an L1 reorg then removes the result's block: the counter
// holds the init's commitment again, done[0] is unset, the orchestrator
// sees the replacement and alice's PXE drops the note. The result lands
// again under the same machine request id with no new round at the nodes,
// exactly once, and alice's outcome is delivered again.
import type { Scenario, Step } from "../scenario.ts";

/** The reorg scenarios' deployment: one counter-tip, its two traders in
 * wallets of their own. */
export function counterReorg(steps: Step[]): Scenario {
  return {
    example: "counter-tip",
    accounts: ["operator", "alice", "bob"],
    wallets: { alice: ["operator", "alice"], bob: ["bob"] },
    keys: {},
    contracts: {},
    namespaces: {},
    tip: { counter: "counter-tip" },
    steps,
  };
}

/** `from` adds `amount` to the counter, bound as `name`. */
export const add = (from: string, amount: number, name: string): Step => ({ tipRequest: "counter_add", namespace: "counter", from, method: "add", inputs: { amount }, name });

/** The nodes' line for each round they run (sidecar-core lifecycle); a
 * request answered from the nodes' stored rows logs none. */
export const ROUND = "round committed";
/** The orchestrator's line for each replacement its scheduler follows. */
export const REPLACED = "scheduler: blocks were replaced";

export const scenario: Scenario = counterReorg([
  { tipInit: "counter", name: "counterInit" },
  add("alice", 5, "first"),
  { tipResult: "first", name: "firstOut", expect: [["eq", "$firstOut.oldCommitments[0]", "$counterInit.newCommitments[0]"]] },
  { tipOutcome: "first", owner: "alice", name: "firstOutcome", expect: [["eq", "$firstOutcome.plaintext[1]", 5]] },
  { reorg: "notes", request: "first", owner: "alice", name: "notesBefore" },
  { reorg: "count", of: "node", match: ROUND, name: "roundsBefore" },
  { reorg: "count", of: "orchestrator", match: REPLACED, name: "replacedBefore" },

  // the reorg: everything from the result's block on is gone
  { reorg: "pause" },
  { reorg: "revert", before: "$firstOut.block", name: "reverted", expect: [["gt", "$firstOut.block", "$reverted.proposed"]] },
  { reorg: "state", request: "first", name: "afterRevert", expect: [["eq", "$afterRevert.commitment", "$counterInit.newCommitments[0]"], ["eq", "$afterRevert.done", 0], ["eq", "$afterRevert.landings", 0]] },
  { reorg: "count", of: "orchestrator", match: REPLACED, name: "replacedAfter", expect: [["gt", "$replacedAfter", "$replacedBefore"]] },
  { what: "alice's PXE dropped the note of the removed block", reorg: "notes", request: "first", owner: "alice", name: "notesGone", expect: [["gt", "$notesBefore", "$notesGone"]] },

  // the chain goes on: the same result lands again, once, with no new round
  { reorg: "rebuild" },
  {
    tipResult: "first",
    name: "againOut",
    expect: [
      ["eq", "$againOut.machineRequestId", "$firstOut.machineRequestId"],
      ["eq", "$againOut.newCommitments[0]", "$firstOut.newCommitments[0]"],
    ],
  },
  { reorg: "state", request: "first", name: "landed", expect: [["eq", "$landed.commitment", "$firstOut.newCommitments[0]"], ["eq", "$landed.landings", 1]] },
  { reorg: "count", of: "node", match: ROUND, name: "roundsAfter", expect: [["eq", "$roundsAfter", "$roundsBefore"]] },
  { reorg: "redeliver", request: "first", owner: "alice", name: "redelivered", expect: [["gt", "$redelivered.deliveries", 0]] },
  { reorg: "notes", request: "first", owner: "alice", name: "notesBack", expect: [["eq", "$notesBack", "$notesBefore"]] },
  { reorg: "no-fault" },
]);
