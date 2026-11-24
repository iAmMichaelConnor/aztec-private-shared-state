// An epoch prune of three landed rounds (scenarios/README.md, "The reorg
// scenarios"). Proving is turned off once every checkpoint is proven, three
// adds land unproven, and L1 time moves past their proof deadline: the
// node prunes every unproven checkpoint, the tips drop to the proven one,
// and the counter holds the init's commitment, a version every node still
// holds. Each request is then watched (pss-client watchRequest): the pool
// mines it again, or it is sent again when the pool dropped it (the log
// says which); every round lands again.
import type { Scenario, Step } from "../scenario.ts";
import { add, counterReorg } from "./reorg-result-again.ts";

const landed = (name: string): Step => ({ tipResult: name, name: `${name}Out` });

export const scenario: Scenario = counterReorg([
  { tipInit: "counter", name: "counterInit" },
  { reorg: "prove" },
  { reorg: "proving", on: false },
  { reorg: "tips", name: "k" },
  add("alice", 1, "r1"),
  landed("r1"),
  add("bob", 2, "r2"),
  landed("r2"),
  add("alice", 3, "r3"),
  landed("r3"),
  { reorg: "tips", name: "unproven", expect: [["gt", "$unproven.checkpointed", "$k.proven"], ["eq", "$unproven.proven", "$k.proven"]] },

  { reorg: "pause" },
  { reorg: "epoch-prune", name: "pruned", expect: [["eq", "$pruned.checkpointed", "$k.proven"]] },
  { reorg: "state", request: "r1", name: "atK", expect: [["eq", "$atK.commitment", "$counterInit.newCommitments[0]"], ["eq", "$atK.tail", 0]] },
  { reorg: "proving", on: true },
  { reorg: "resume" },

  // each request back in the queue, by the pool or sent again
  { reorg: "requeue", request: "r1", resend: true, name: "r1Again" },
  { reorg: "requeue", request: "r2", resend: true, name: "r2Again" },
  { reorg: "requeue", request: "r3", resend: true, name: "r3Again" },
  { tipResult: "r1", name: "r1Landed" },
  { tipResult: "r2", name: "r2Landed" },
  { tipResult: "r3", name: "r3Landed" },
  { reorg: "no-fault" },
]);
