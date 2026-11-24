// The init round removed by a reorg (scenarios/README.md, "The reorg
// scenarios"). An L1 reorg removes the init's block with the sequencer
// paused: every slot the init created is empty again and nothing is queued.
// The relayer, still running, sees the init missing and sends it again on
// its own (no restart) while the chain is held; once the sequencer runs,
// the init's slots are written again (by its transaction or by the old one
// the pool restored, whichever is mined first) and a request runs on them.
import type { Scenario } from "../scenario.ts";
import { add, counterReorg } from "./reorg-result-again.ts";

/** The relayer's line for each init it sends (pss-relayer relayer.ts). */
const LANDING_INIT = "landing the init round";

export const scenario: Scenario = counterReorg([
  { tipInit: "counter", name: "counterInit" },
  { reorg: "count", of: "relayer", match: LANDING_INIT, name: "initSends" },
  { reorg: "pause" },
  { reorg: "revert", before: "$counterInit.block", name: "reverted" },
  { reorg: "state", name: "removed", expect: [["eq", "$removed.tail", 0], ["eq", "$removed.initSlots[0]", 0]] },
  { what: "the relayer sends the init again", reorg: "count", of: "relayer", match: LANDING_INIT, name: "initSendsAfter", expect: [["gt", "$initSendsAfter", "$initSends"]] },
  { reorg: "rebuild" },
  { reorg: "state", name: "written", expect: [["eq", "$written.initSlots[0]", "$counterInit.newCommitments[0]"]] },
  add("alice", 5, "req"),
  { tipResult: "req", name: "reqOut", expect: [["eq", "$reqOut.oldCommitments[0]", "$counterInit.newCommitments[0]"]] },
  { reorg: "no-fault" },
]);
