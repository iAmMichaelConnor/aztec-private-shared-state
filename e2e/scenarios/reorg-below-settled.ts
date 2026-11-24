// A reorg below the previous proven tip, above the finalized one
// (scenarios/README.md, "The reorg scenarios"). With proving on, every
// checkpoint is proven at once, while L1 finality (anvil, 64 L1 blocks)
// keeps the finalized tip behind. Two adds land, every node runs its prune
// pass, and an L1 reorg removes both requests' blocks: the counter holds
// the init's commitment again. The nodes deleted no version above the
// finalized tip, so the requests land again on the init's state and no
// node finds a commitment it holds no version of.
import type { Scenario } from "../scenario.ts";
import { add, counterReorg } from "./reorg-result-again.ts";

export const scenario: Scenario = counterReorg([
  { tipInit: "counter", name: "counterInit" },
  add("alice", 5, "first"),
  { tipResult: "first", name: "firstOut", expect: [["eq", "$firstOut.oldCommitments[0]", "$counterInit.newCommitments[0]"]] },
  add("bob", 7, "second"),
  { tipResult: "second", name: "secondOut", expect: [["eq", "$secondOut.oldCommitments[0]", "$firstOut.newCommitments[0]"]] },
  // the reorg reaches below the proven tip and stays above the finalized one
  { reorg: "tips", name: "t", expect: [["gt", "$t.proven", "$first.block"], ["gt", "$first.block", "$t.finalized"]] },
  { reorg: "node-prune", name: "pruned" },

  { reorg: "pause" },
  { reorg: "revert", before: "$first.block", name: "reverted" },
  { reorg: "state", request: "first", name: "back", expect: [["eq", "$back.commitment", "$counterInit.newCommitments[0]"], ["eq", "$back.tail", 0]] },
  { reorg: "no-fault" },
  { reorg: "rebuild" },
  { reorg: "requeue", request: "first", resend: true, name: "firstAgain" },
  { reorg: "requeue", request: "second", resend: true, name: "secondAgain" },
  { tipResult: "first", name: "firstLanded", expect: [["eq", "$firstLanded.oldCommitments[0]", "$counterInit.newCommitments[0]"]] },
  { tipResult: "second", name: "secondLanded", expect: [["eq", "$secondLanded.oldCommitments[0]", "$firstLanded.newCommitments[0]"]] },
  { reorg: "no-fault" },
]);
