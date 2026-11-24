// A queued request removed by a reorg (scenarios/README.md, "The reorg
// scenarios"). With the relayer stopped, alice's add is queued and the
// scheduler's attempt computed; an L1 reorg then removes the request's
// block, with the sequencer paused so the pool holds the transaction back.
// The queue is empty again and the scheduler drops its attempt, while FETCH
// still serves the signed result (signed before the reorg). Once the sequencer runs again the pool mines the same
// transaction: the same request id, and its result lands with no new round.
import type { Scenario } from "../scenario.ts";
import { add, counterReorg, REPLACED, ROUND } from "./reorg-result-again.ts";

export const scenario: Scenario = counterReorg([
  { tipInit: "counter", name: "counterInit" },
  { relayer: "stop", namespace: "counter" },
  add("alice", 5, "req"),
  { tipAttempt: "req", name: "attempt", expect: [["eq", "$attempt.oldCommitments[0]", "$counterInit.newCommitments[0]"]] },
  { reorg: "count", of: "node", match: ROUND, name: "roundsBefore" },
  { reorg: "count", of: "orchestrator", match: REPLACED, name: "replacedBefore" },

  { reorg: "pause" },
  { reorg: "revert", before: "$req.block", name: "reverted" },
  { reorg: "state", request: "req", name: "removed", expect: [["eq", "$removed.tail", 0], ["eq", "$removed.queued", false]] },
  { reorg: "count", of: "orchestrator", match: REPLACED, name: "replacedAfter", expect: [["gt", "$replacedAfter", "$replacedBefore"]] },
  { what: "FETCH still serves the signed result", tipAttempt: "req", name: "stillServed", expect: [["eq", "$stillServed.machineRequestId", "$attempt.machineRequestId"]] },

  // the pool releases the transaction: queued again at index 0
  { reorg: "rebuild" },
  { reorg: "requeue", request: "req", name: "requeued", expect: [["eq", "$requeued.index", 0]] },
  { relayer: "start", namespace: "counter" },
  { tipResult: "req", name: "reqOut", expect: [["eq", "$reqOut.machineRequestId", "$attempt.machineRequestId"]] },
  { reorg: "count", of: "node", match: ROUND, name: "roundsAfter", expect: [["eq", "$roundsAfter", "$roundsBefore"]] },
  { tipOutcome: "req", owner: "alice", name: "reqOutcome", expect: [["eq", "$reqOutcome.plaintext[1]", 5]] },
  { reorg: "no-fault" },
]);
