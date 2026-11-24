// The AMM at the tip of the chain (scenarios/README.md, "amm-tip.ts"): three
// deployments the harness made of examples/amm-tip's AmmTip (E2E_TIP=1,
// E2E_TIP_DEPLOYMENTS="amm-tip-shared amm-tip amm-tip-stale"), each with its
// init round landed by its relayer. On the secret-shared deployment, the default
// (secret-shared receipt intake, private outcomes with partial-note
// delivery): a swap whose request commits the trader's partial note, whose
// result completes it in the round, and whose outcome and completed note the
// trader opens and holds, audited for what its transactions show (no amount
// and no owner anywhere the nodes, the orchestrator or the relayer look),
// and a failed swap whose note carries zero. On the non-secret-shared ones:
// swaps under on-chain intake and receipt intake, each request committing
// the sender's partial note, landed by the relayer, whose apply completes
// the note in public; a failed swap, two traders in one block, the repeated
// intake and the repeated result, a result the user lands with the relayer
// stopped, and a stale head skipped under a small stale_blocks.
import type { Expect, Scenario, Step } from "../scenario.ts";

/** A non-secret-shared swap's end, bound as `<request>Out`: its public
 * outputs [ok, code, amount_out], and apply completed the request's partial
 * note in public: the completion log [tag, slot, code, amount_out,
 * request_id] carries what FETCH answered. */
export function result(request: string, expect: Expect[], extra: Partial<Step> = {}): Step {
  const out = `${request}Out`;
  return {
    tipResult: request,
    name: out,
    expect: [
      ["len", `$${out}.completion`, 5],
      ["eq", `$${out}.completion[2]`, `$${out}.appOutputs[0]`],
      ["eq", `$${out}.completion[3]`, `$${out}.appOutputs[1]`],
      ...expect,
    ],
    ...extra,
  } as Step;
}
const traded = (request: string): Expect[] => [
  ["eq", `$${request}Out.ok`, 1],
  ["eq", `$${request}Out.appOutputs[0]`, 0],
  ["gt", `$${request}Out.appOutputs[1]`, 0],
];
/** A swap under on-chain intake: the request holds the sender's partial
 * note (its clear input `partial_note`), the request function takes the
 * sender's rho in its place and tells the sender's PXE of the note
 * offchain. */
const swap = (from: string, inputs: { amount_in: number; direction: 0 | 1; min_out: number }, name?: string, namespace = "main") =>
  ({ tipRequest: "amm_swap_tip", namespace, from, method: "swap", inputs, ...(name && { name }) }) as const;

/** A secret-shared swap: every input secret-shared to the nodes, and the
 * sender's partial note (the request step takes its next request secrets). */
const sharedSwap = (from: string, inputs: { amount_in: number; direction: 0 | 1; min_out: number }, name: string): Step => ({
  tipRequest: "amm_swap_tip_shared",
  namespace: "shared",
  from,
  method: "swap_shared",
  inputs,
  name,
});
/** A secret-shared swap's end: the pool re-blinded on the previous commitment
 * whatever the outcome; one completed note hash. */
export function sharedResult(request: string, previous: string): Step {
  const out = `${request}Out`;
  return {
    tipResult: request,
    name: out,
    expect: [
      ["eq", `$${out}.oldCommitments[0]`, previous],
      ["ne", `$${out}.newCommitments[0]`, `$${out}.oldCommitments[0]`],
      ["len", `$${out}.noteHashes`, 1],
    ],
  };
}
/** The trader opens the outcome [code, amount_out] and takes the completed
 * note [code, amount_out, request_id], which its PXE then holds
 * (`swap_notes`). */
export function sharedOutcome(request: string, trader: string, expect: Expect[]): Step {
  const name = `${request}Outcome`;
  return {
    tipOutcome: request,
    owner: trader,
    notes: "swap_notes",
    name,
    expect: [["len", `$${name}.plaintext`, 2], ["len", `$${name}.note.packed`, 3], ...expect],
  };
}

export const scenario: Scenario = {
  example: "amm-tip",
  accounts: ["operator", "alice", "bob"],
  // two traders, each in a PXE of its own
  wallets: { alice: ["operator", "alice"], bob: ["bob"] },
  keys: {},
  contracts: {},
  namespaces: {},
  tip: { shared: "amm-tip-shared", main: "amm-tip", stale: "amm-tip-stale" },
  steps: [
    { tipInit: "shared", name: "sharedInit" },
    { tipInit: "main", name: "mainInit" },
    { tipInit: "stale", name: "staleInit" },

    // ---- the secret-shared deployment: secret-shared receipt intake, partial-note delivery ----
    // bob's swap with distinctive inputs: the chain sees the request id and the expiry; the relayer lands the
    // result through process_result_shared, which pushes bob's completed note and the outcome log
    sharedSwap("bob", { amount_in: 31_337, direction: 0, min_out: 1_234 }, "sharedSwap"),
    sharedResult("sharedSwap", "$sharedInit.newCommitments[0]"),
    sharedOutcome("sharedSwap", "bob", [
      ["eq", "$sharedSwapOutcome.plaintext[0]", 0],
      ["gt", "$sharedSwapOutcome.plaintext[1]", 1_234],
    ]),
    { tipAudit: "sharedSwap", outcome: "sharedSwapOutcome" },
    // a secret-shared swap that fails (its output is below min_out): code 8, alice's note carries 0, the pool re-blinded all the same
    sharedSwap("alice", { amount_in: 5_432, direction: 1, min_out: 1_000_000 }, "sharedFailed"),
    sharedResult("sharedFailed", "$sharedSwapOut.newCommitments[0]"),
    sharedOutcome("sharedFailed", "alice", [["eq", "$sharedFailedOutcome.plaintext[0]", 8], ["eq", "$sharedFailedOutcome.plaintext[1]", 0]]),
    { tipAudit: "sharedFailed", outcome: "sharedFailedOutcome" },

    // ---- the non-secret-shared deployments: on-chain intake and receipt intake, public outputs, the note completed in public by apply ----

    // on-chain intake, landed by the relayer; the request id names no requester, only the partial note
    { ...swap("alice", { amount_in: 10_000, direction: 0, min_out: 1 }, "onchain"), nodeTamper: true },
    result("onchain", [...traded("onchain"), ["eq", "$onchainOut.oldCommitments[0]", "$mainInit.newCommitments[0]"]]),
    // the same arguments again from alice: the partial note's use nullifier (and the request id) were seen
    { what: "the same request again", tipRequest: "amm_swap_tip", namespace: "main", again: "onchain", from: "alice", method: "swap", refused: ["ullifier"] },
    { what: "the landed result again", tipResult: "onchain", again: true, from: "bob", refused: ["queue is empty", "not the head"] },

    // receipt intake: the inputs reach the nodes only, the chain sees the id and the expiry
    { tipRequest: "amm_swap_tip_receipt", namespace: "main", from: "bob", method: "swap_with_receipts", inputs: { amount_in: 7_000, direction: 1, min_out: 1 }, name: "receipt" },
    result("receipt", [...traded("receipt"), ["eq", "$receiptOut.oldCommitments[0]", "$onchainOut.newCommitments[0]"]]),
    { what: "the same receipts again", tipRequest: "amm_swap_tip_receipt", namespace: "main", again: "receipt", from: "bob", method: "swap_with_receipts", refused: ["ullifier"] },

    // a swap that fails against the pool (its output is below min_out): ok = false, code 8, the pool kept
    swap("alice", { amount_in: 5_000, direction: 0, min_out: 1_000_000 }, "failed"),
    result("failed", [
      ["eq", "$failedOut.ok", 0],
      ["eq", "$failedOut.appOutputs[0]", 8],
      ["eq", "$failedOut.appOutputs[1]", 0],
      ["eq", "$failedOut.newCommitments[0]", "$failedOut.oldCommitments[0]"],
    ]),

    // two traders in one block, the same trade: the queue order decides who trades on which pool
    { sameBlock: [swap("alice", { amount_in: 20_000, direction: 0, min_out: 1 }), swap("bob", { amount_in: 20_000, direction: 0, min_out: 1 })], as: ["first", "second"] },
    result("first", [...traded("first"), ["eq", "$firstOut.oldCommitments[0]", "$failedOut.oldCommitments[0]"]]),
    result("second", [...traded("second"), ["eq", "$secondOut.oldCommitments[0]", "$firstOut.newCommitments[0]"], ["gt", "$firstOut.appOutputs[1]", "$secondOut.appOutputs[1]"]]),

    // the relayer stopped: the user lands the result
    { relayer: "stop", namespace: "main" },
    swap("alice", { amount_in: 3_000, direction: 1, min_out: 1 }, "byUser"),
    result("byUser", [...traded("byUser"), ["eq", "$byUserOut.oldCommitments[0]", "$secondOut.newCommitments[0]"]], { by: "user", from: "alice", clientTamper: true }),
    { relayer: "start", namespace: "main" },
    swap("bob", { amount_in: 4_000, direction: 0, min_out: 1 }, "afterRestart"),
    result("afterRestart", [...traded("afterRestart"), ["eq", "$afterRestartOut.oldCommitments[0]", "$byUserOut.newCommitments[0]"]]),

    // a stale head (stale_blocks 4 on this deployment) skipped by the relayer; the next swap runs on the pool the skipped one never moved
    { relayer: "stop", namespace: "stale" },
    swap("bob", { amount_in: 6_000, direction: 0, min_out: 1 }, "stale", "stale"),
    { advance: "until-stale", namespace: "stale" },
    { relayer: "start", namespace: "stale" },
    { tipResult: "stale", skipped: true, name: "staleOut" },
    swap("alice", { amount_in: 6_000, direction: 0, min_out: 1 }, "afterSkip", "stale"),
    result("afterSkip", [...traded("afterSkip"), ["eq", "$afterSkipOut.oldCommitments[0]", "$staleInit.newCommitments[0]"]]),
  ],
};
