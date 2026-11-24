// A class upgrade of the AMM tip (scenarios/README.md,
// "amm-tip-upgrade-contract.ts"; pss_public_contract `upgrades`,
// `upgrade_contract`): on the non-secret-shared deployment of
// examples/amm-tip (E2E_TIP=1, E2E_TIP_DEPLOYMENTS="amm-tip-class"), whose
// harness spec names the contract's second class (the same sources with
// `CLASS_VERSION = 2` in src/class.nr, built by the harness) and generates
// its contract manifest (the same circuits, the new class id). A swap lands
// under the deployed class; only the authority may call upgrade_contract;
// the operator publishes the second class, the namespace owner registers
// its contract manifest at the next seq and the authority (the operator)
// schedules the class change and its pins together, one day ahead; a swap
// still lands under the deployed class; one more swap is queued with the
// relayer stopped and the network computes its result; the chain's time is
// warped past the day. Then every wallet registers the instance again with
// the second class's artifact, the new code answers (get_class_version 2),
// the client follows the pins to the new contract manifest, and with the
// relayer back the request queued before the switch lands through the new
// class (the circuits did not change, so it is still answerable), then a
// fresh swap, each on the pool the one before left.
import type { Expect, Scenario, Step } from "../scenario.ts";
import { result } from "./amm-tip.ts";

const swap = (from: string, inputs: { amount_in: number; direction: 0 | 1; min_out: number }, name: string): Step =>
  ({ tipRequest: "amm_swap_tip", namespace: "main", from, method: "swap", inputs, name }) as Step;

const traded = (request: string): Expect[] => [
  ["eq", `$${request}Out.ok`, 1],
  ["eq", `$${request}Out.appOutputs[0]`, 0],
  ["gt", `$${request}Out.appOutputs[1]`, 0],
];

/** One day, the pins' delay and the instance's class-update delay (Aztec's
 * default), and a minute more. */
const PAST_THE_DELAY = 86_400 + 60;

export const scenario: Scenario = {
  example: "amm-tip",
  accounts: ["operator", "alice", "bob"],
  keys: {},
  contracts: {},
  namespaces: {},
  tip: { main: "amm-tip-class" },
  steps: [
    { tipInit: "main", name: "mainInit" },
    { ...swap("alice", { amount_in: 10_000, direction: 0, min_out: 1 }, "before"), nodeTamper: true } as Step,
    result("before", [...traded("before"), ["eq", "$beforeOut.oldCommitments[0]", "$mainInit.newCommitments[0]"]]),

    // only the authority the constructor pinned moves the instance
    { what: "upgrade_contract from another account", tipUpgrade: "schedule", kind: "contract", namespace: "main", from: "alice", refused: ["not the upgrade authority"] },
    // the second class published, its contract manifest registered at the next seq
    { tipUpgrade: "publishClass", namespace: "main", name: "published" },
    { tipUpgrade: "register", kind: "contract", namespace: "main", name: "registered" },
    // the class change and its pins scheduled together, in force one day later
    {
      tipUpgrade: "schedule",
      kind: "contract",
      namespace: "main",
      from: "operator",
      name: "scheduled",
      expect: [["eq", "$scheduled.manifestHash", "$registered.manifestHash"]],
    },

    // scheduled, not in force: the deployed class still runs
    swap("bob", { amount_in: 5_000, direction: 1, min_out: 1 }, "beforeSwitch"),
    result("beforeSwitch", [...traded("beforeSwitch"), ["eq", "$beforeSwitchOut.oldCommitments[0]", "$beforeOut.newCommitments[0]"]]),

    // a request whose result the network computes before the switch
    { relayer: "stop", namespace: "main" },
    swap("alice", { amount_in: 7_000, direction: 0, min_out: 1 }, "acrossSwitch"),
    { tipAttempt: "acrossSwitch", name: "acrossAttempt" },

    // past the switch: the instance runs the second class
    { advance: { warp: PAST_THE_DELAY } },
    {
      tipUpgrade: "followClass",
      namespace: "main",
      classVersion: "get_class_version",
      name: "followed",
      expect: [
        ["eq", "$followed.classId", "$published.classId"],
        ["eq", "$followed.version", 2],
      ],
    },
    { tipUpgrade: "follow", namespace: "main", name: "inForce", expect: [["eq", "$inForce.manifestHash", "$registered.manifestHash"]] },

    // the request queued before the switch is still answerable (the same circuits): it lands through the new class
    { relayer: "start", namespace: "main" },
    result("acrossSwitch", [...traded("acrossSwitch"), ["eq", "$acrossSwitchOut.oldCommitments[0]", "$beforeSwitchOut.newCommitments[0]"]]),
    swap("bob", { amount_in: 6_000, direction: 0, min_out: 1 }, "after"),
    result("after", [...traded("after"), ["eq", "$afterOut.oldCommitments[0]", "$acrossSwitchOut.newCommitments[0]"]]),
  ],
};
