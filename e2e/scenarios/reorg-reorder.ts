// The replacement chain orders two requests the other way (scenarios/README.md,
// "The reorg scenarios"). alice's add, under secret-shared receipt intake,
// is queued and computed with the relayer stopped, and pss-client
// pollResult starts waiting for it; an L1 reorg then removes every block
// from her transaction's anchor block on, so the pool drops it and the
// queue is empty. bob's add is queued first on the new chain, and alice's
// is sent again with the same arguments, the same receipts (pss-client
// watchRequest): the nodes still hold its inputs and the contract accepts
// the receipts (block numbers went back with the chain, so the expiry is
// still ahead). It lands second, recomputed on bob's state under a new
// machine request id, and the counter ends as running bob's add, then
// alice's. pollResult, which first found alice's request at index 0 where
// bob's now sits, reports her request's own fate at index 1.
import type { Scenario } from "../scenario.ts";
import { add, counterReorg, ROUND } from "./reorg-result-again.ts";

export const scenario: Scenario = counterReorg([
  { tipInit: "counter", name: "counterInit" },
  { relayer: "stop", namespace: "counter" },
  // empty blocks after the init, so alice's anchor block is one of them
  { advance: 2 },
  add("alice", 5, "a"),
  { tipAttempt: "a", name: "aAttempt" },
  { reorg: "poll-start", request: "a" },
  { reorg: "count", of: "node", match: ROUND, name: "roundsBefore" },

  { reorg: "pause" },
  { reorg: "revert", anchorOf: "a" },
  { reorg: "state", request: "a", name: "removed", expect: [["eq", "$removed.tail", 0]] },
  { reorg: "rebuild" },
  add("bob", 7, "b"),
  { reorg: "requeue", request: "a", resend: true, name: "aAgain", expect: [["eq", "$aAgain.index", 1], ["gt", "$aAgain.resends", 0]] },
  { relayer: "start", namespace: "counter" },

  { tipResult: "b", name: "bOut", expect: [["eq", "$bOut.oldCommitments[0]", "$counterInit.newCommitments[0]"]] },
  {
    tipResult: "a",
    name: "aOut",
    expect: [
      ["eq", "$aOut.oldCommitments[0]", "$bOut.newCommitments[0]"],
      ["ne", "$aOut.machineRequestId", "$aAttempt.machineRequestId"],
    ],
  },
  { reorg: "poll-end", request: "a", name: "polled", expect: [["eq", "$polled.applied", true], ["eq", "$polled.index", 1], ["eq", "$polled.index", "$a.index"]] },
  { tipOutcome: "b", owner: "bob", name: "bOutcome", expect: [["eq", "$bOutcome.plaintext[1]", 7]] },
  { tipOutcome: "a", owner: "alice", name: "aOutcome", expect: [["eq", "$aOutcome.plaintext[1]", 12]] },
  { reorg: "count", of: "node", match: ROUND, name: "roundsAfter", expect: [["gt", "$roundsAfter", "$roundsBefore"]] },
  { reorg: "no-fault" },
]);
