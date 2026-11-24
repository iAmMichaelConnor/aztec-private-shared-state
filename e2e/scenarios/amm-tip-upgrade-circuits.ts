// A circuit upgrade of the AMM tip (scenarios/README.md,
// "amm-tip-upgrade-circuits.ts"; pss_public_contract `upgrades`): on the
// non-secret-shared deployment of examples/amm-tip (E2E_TIP=1,
// E2E_TIP_DEPLOYMENTS="amm-tip-upgrade"), whose contract has upgradable
// circuits and whose harness spec names the upgraded contract manifest
// (examples/amm-tip/deployments/amm-tip-next.json: the swap on
// amm_swap_tip_next, which lands a trade below 100 as a no-op with code 10).
// A swap lands under the deployed circuits; the namespace owner registers
// the upgraded manifest at the next seq and the upgrade authority (the
// operator, which the constructor pinned) schedules its pins, one day
// ahead; a swap still lands under the deployed circuit; one more swap is
// queued with the relayer stopped and the network computes its result under
// the deployed circuit; the chain's time is warped past the day. Then the
// result computed before the switch is refused (the contract verifies under
// the upgraded pins), its request, which binds the replaced circuit's vk
// hash, waits out the stale period and is skipped, a swap proven under
// amm_swap_tip_next lands on the pool the last swap before the switch left,
// and a small swap lands with the upgraded circuit's code 10.
import type { Expect, Scenario, Step } from "../scenario.ts";
import { result } from "./amm-tip.ts";

const swap = (from: string, inputs: { amount_in: number; direction: 0 | 1; min_out: number }, name: string): Step =>
  ({ tipRequest: "amm_swap_tip", namespace: "main", from, method: "swap", inputs, name }) as Step;

const traded = (request: string): Expect[] => [
  ["eq", `$${request}Out.ok`, 1],
  ["eq", `$${request}Out.appOutputs[0]`, 0],
  ["gt", `$${request}Out.appOutputs[1]`, 0],
];

/** One day, the contract's upgrade delay (amm_tip UPGRADE_DELAY), and a
 * minute more. */
const PAST_THE_DELAY = 86_400 + 60;

export const scenario: Scenario = {
  example: "amm-tip",
  accounts: ["operator", "alice", "bob"],
  keys: {},
  contracts: {},
  namespaces: {},
  tip: { main: "amm-tip-upgrade" },
  steps: [
    { tipInit: "main", name: "mainInit" },
    { ...swap("alice", { amount_in: 10_000, direction: 0, min_out: 1 }, "before"), nodeTamper: true } as Step,
    result("before", [...traded("before"), ["eq", "$beforeOut.oldCommitments[0]", "$mainInit.newCommitments[0]"]]),

    // only the authority the constructor pinned schedules pins
    { what: "upgrade_circuits from another account", tipUpgrade: "schedule", namespace: "main", from: "alice", refused: ["not the upgrade authority"] },
    // the owner registers the upgraded contract manifest at the next seq; the nodes hold both versions
    { tipUpgrade: "register", namespace: "main", name: "registered" },
    // the authority schedules its pins, in force one day later
    { tipUpgrade: "schedule", namespace: "main", from: "operator", name: "scheduled", expect: [["eq", "$scheduled.manifestHash", "$registered.manifestHash"]] },

    // scheduled, not in force: the deployed circuit still serves the queue
    swap("bob", { amount_in: 5_000, direction: 1, min_out: 1 }, "beforeSwitch"),
    result("beforeSwitch", [...traded("beforeSwitch"), ["eq", "$beforeSwitchOut.oldCommitments[0]", "$beforeOut.newCommitments[0]"]]),

    // a request under the deployed pins, its result computed but not landed
    { relayer: "stop", namespace: "main" },
    swap("alice", { amount_in: 7_000, direction: 0, min_out: 1 }, "queuedOld"),
    { tipAttempt: "queuedOld", name: "oldAttempt" },

    // past the switch
    { advance: { warp: PAST_THE_DELAY } },

    // the result computed under the replaced circuit: the contract now verifies under the upgraded pins
    { what: "the result computed before the switch", tipResult: "queuedOld", again: true, from: "alice", refused: ["unexpected verification key"] },

    // the client follows the contract's pins to the upgraded version
    { tipUpgrade: "follow", namespace: "main", name: "followed", expect: [["eq", "$followed.manifestHash", "$registered.manifestHash"]] },

    // the old request binds the replaced vk hash: no circuit answers it, so it goes stale and the relayer skips it
    { relayer: "start", namespace: "main" },
    { advance: "until-stale", namespace: "main" },
    { tipResult: "queuedOld", skipped: true, name: "queuedOldOut" },

    // a swap proven under amm_swap_tip_next, on the pool the last swap before the switch left
    swap("bob", { amount_in: 6_000, direction: 0, min_out: 1 }, "after"),
    result("after", [...traded("after"), ["eq", "$afterOut.oldCommitments[0]", "$beforeSwitchOut.newCommitments[0]"]]),
    // the upgraded circuit's visible difference: a trade below 100 lands as a no-op with code 10
    swap("alice", { amount_in: 50, direction: 0, min_out: 0 }, "small"),
    result("small", [
      ["eq", "$smallOut.ok", 0],
      ["eq", "$smallOut.appOutputs[0]", 10],
      ["eq", "$smallOut.appOutputs[1]", 0],
      ["eq", "$smallOut.newCommitments[0]", "$smallOut.oldCommitments[0]"],
      ["eq", "$smallOut.oldCommitments[0]", "$afterOut.newCommitments[0]"],
    ]),
  ],
};
