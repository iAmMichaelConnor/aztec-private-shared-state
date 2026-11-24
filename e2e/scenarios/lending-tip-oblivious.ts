// Lending on the oblivious tree (scenarios/README.md, "lending-tip-oblivious.ts";
// docs/ARCHITECTURE.md section 6, "The oblivious tree"): one deployment the harness made of
// examples/lending-tip's LendingTipOblivious with its two tokens and LendingOracle
// deployed first (E2E_TIP=1, E2E_TIP_DEPLOYMENTS="lending-tip-oblivious"), its
// package list the oblivious family (e2e/tip/lending-tip-oblivious.json:
// `lending_init_oblivious` and the ten `<round>_oblivious` entries, landed
// through the secret-shared rounds' `process_shared` and
// `process_header_shared`). The book's tree
// has `access: oblivious`: every position index, an owner's and a
// liquidation's probe, travels as a shared input, so no node learns which
// leaf a request touches, and every round on a position goes through its
// request function with the position shared (the contract's `<round>_shared`,
// the name LendingTip gives it); an opening (deposit, supply) names the public
// flag `opens` beside its shared position 0; the keeper's scan keeps its
// public window. The same book as lending-tip.ts's
// secret-shared half, so the same outcomes: alice opens a position and
// borrows, the operator supplies, a view of someone else's position is
// refused in the private function, interest accrues, the keeper finds and
// liquidates alice's position after a price fall (alice opens its notice
// from the liquidation's result), and the lender withdraws. Then a second
// liquidation of alice's position after another price fall, which she does
// not open: her view on the live market (its private function opens any
// note of hers of the position) gives her a note whose exit tag is unspent.
// Last, the escape hatch, which an exit by exit tag gives this deployment as
// well (a tag names no index): anyone pokes the idle market's starving clock,
// T_LIVE blocks later anyone opens the hatch, alice's exit on her notice
// (whose tag the second liquidation spent) is refused, she exits on her
// view's note, and her second exit is refused.
import type { Scenario, Step, Value } from "../scenario.ts";
import { ACCRUED, EXIT, funded, notice, ONE, SCAN_LAYOUT, USAGE_DEPOSIT, outcome, sharedResult } from "./lending-tip.ts";

/** A request on the oblivious deployment: the position (and a liquidation's
 * probe) is a shared input by the manifest, the clear ones the opening flag,
 * a count and a scan's start. Every round goes through LendingTipOblivious's
 * `<round>_shared` request function, whose sharing covers the shared
 * position (an opening's also commits the flag), on the round's
 * `<round>_oblivious` package. */
function oblivious(
  round: "deposit" | "withdraw" | "borrow" | "repay" | "supply" | "withdraw_supply" | "view" | "quote" | "scan" | "liquidate",
  from: string,
  inputs: Record<string, Value>,
  name: string,
): Step {
  const opening = round === "deposit" || round === "supply";
  const method = `${round}_shared`;
  const withFlag: Record<string, Value> = opening ? { position: inputs.position as Value, opens: inputs.position === 0 ? 1 : 0, ...inputs } : inputs;
  return { tipRequest: `${round}_oblivious`, namespace: "oblivious", from, method, inputs: withFlag, name };
}

/** The usage deposits the deployment's rounds kept: `rounds` of them. */
function kept(rounds: number): Step {
  return { view: "get_kept_deposits", contract: "oblivious", from: "operator", name: "obliviousKept", expect: [["eq", "$obliviousKept", rounds * USAGE_DEPOSIT]] };
}

export const scenario: Scenario = {
  example: "lending-tip",
  accounts: ["operator", "alice", "bob"],
  wallets: { alice: ["operator", "alice"], bob: ["bob"] },
  senders: ["operator"],
  keys: {},
  values: {},
  contracts: {},
  namespaces: {},
  tip: { oblivious: "lending-tip-oblivious" },
  steps: [
    { tipInit: "oblivious", name: "obliviousInit" },
    ...funded("oblivious", ["operator", "alice", "bob"]),

    // alice opens a position: position 0 shared, the flag public; the nodes read the header and $new_leaf's path
    // a real-proof run's node-side negative: a copy of the request with one Chonk proof field changed, refused
    { ...oblivious("deposit", "alice", { position: 0, amount: 1_000 }, "open"), nodeTamper: true } as Step,
    sharedResult("open", "$obliviousInit.newCommitments[0]"),
    outcome("open", "alice", [0, 1, ONE, 1_000, 0, 0]),
    // the operator supplies before the first borrow: a lender position at the next index
    oblivious("supply", "operator", { position: 0, amount: 5_000 }, "supply"),
    sharedResult("supply", "$openOut.newCommitments[0]"),
    outcome("supply", "operator", [0, 2, 0, 5_000, 5_000, 0]),
    // alice borrows against position 1: the position is a shared input, so no node sees it
    oblivious("borrow", "alice", { position: "$openOutcome.plaintext[1]", amount: 1_700 }, "borrow"),
    sharedResult("borrow", "$supplyOut.newCommitments[0]"),
    outcome("borrow", "alice", [0, 1, ONE, 1_000, 1_700, 1_700]),
    // what the borrow's intake and result transactions show: no amount, no position, no owner, no outcome value
    { tipAudit: "borrow", outcome: "borrowOutcome" },
    { redeem: "borrowOutcome", from: "alice", pays: { "oblivious.borrowed": "$borrowOutcome.plaintext[5]", "oblivious.collateral": 0 } },
    // bob holds no note of position 1: his view is refused in the private function, nothing queued
    {
      tipRequest: "view_oblivious",
      namespace: "oblivious",
      from: "bob",
      method: "view_shared",
      inputs: { position: 1 },
      refused: ["the sender holds no note of this position"],
      what: "bob's view of alice's position",
    },
    { advance: 2, what: "two blocks of interest" },
    oblivious("view", "alice", { position: 1 }, "view"),
    sharedResult("view", "$borrowOut.newCommitments[0]"),
    outcome("view", "alice", [0, 1, ACCRUED, 1_000, 1_701, 0]),

    // ---- the keeper: the scan's window is public, the liquidation's probe is a shared input ----
    oblivious("deposit", "bob", { position: 0, amount: 1_000 }, "bobOpen"),
    sharedResult("bobOpen", "$viewOut.newCommitments[0]"),
    outcome("bobOpen", "bob", [0, 3, ACCRUED, 1_000, 0, 0]),
    { tx: "set_price", contract: "oblivious.oracle", from: "operator", args: [200], what: "the oracle opens epoch 2 at 2.00" },
    oblivious("scan", "operator", { start: 0 }, "scan"),
    sharedResult("scan", "$bobOpenOut.newCommitments[0]"),
    outcome("scan", "operator", [0, 0, 0b10, 0, 0, 0], 3),
    {
      keeper: { 0: "scanOutcome" },
      namespace: "oblivious",
      scan: "scan_oblivious",
      act: "liquidate_oblivious",
      layout: SCAN_LAYOUT,
      name: "keeperPass",
      expect: [["len", "$keeperPass.scanned", 1], ["len", "$keeperPass.reported", 1], ["eq", "$keeperPass.reported[0]", 1], ["len", "$keeperPass.acts", 1]],
    },
    oblivious(
      "liquidate",
      "operator",
      { p1: "$keeperPass.acts[0].inputs.p1", count: "$keeperPass.acts[0].inputs.count", budget: 1_000 },
      "liquidate",
    ),
    sharedResult("liquidate", "$scanOut.newCommitments[0]"),
    outcome("liquidate", "operator", [0, 0, 1, 446, 851, 149], 0),
    { redeem: "liquidateOutcome", from: "operator", pays: { "oblivious.collateral": "$liquidateOutcome.plaintext[3]", "oblivious.borrowed": "$liquidateOutcome.plaintext[5]" } },
    // alice opens her notice from the liquidation's result: her view's delivery handle, completed
    notice("view", "liquidate", "alice", 1, 554, 851),

    // the lender withdraws, and a quote by bob: [0, 0, borrow index, 0, supply index, 0, utilisation]: alice's debt
    // after the liquidation's repayment, about 851, over a pool of about 1,000,000 once the lender's 5,000 left:
    // 8 bps (lending-tip.ts's quote follows a repayment of 400 and a borrow of 296 that this book does not have,
    // hence its 7)
    oblivious("withdraw_supply", "operator", { position: 2, shares: 5_000 }, "exit"),
    sharedResult("exit", "$liquidateOut.newCommitments[0]"),
    outcome("exit", "operator", [0, 2, 0, 0, 0, 5_000]),
    { redeem: "exitOutcome", from: "operator", pays: { "oblivious.borrowed": 5_000, "oblivious.collateral": 0 } },
    oblivious("quote", "bob", {}, "quote"),
    sharedResult("quote", "$exitOut.newCommitments[0]"),
    outcome("quote", "bob", [0, 0, ACCRUED, 0, ACCRUED, 0], 8),
    kept(9),

    // ---- a second liquidation, then the owner's view on the live market ----
    // at 1.80 what the first liquidation left (554 collateral, a debt of about 851) is unhealthy again (554 * 1.80 *
    // 80% = 798); the operator liquidates position 1 again, and redeems the seize and the unused budget
    { tx: "set_price", contract: "oblivious.oracle", from: "operator", args: [180], what: "the oracle opens epoch 3 at 1.80" },
    oblivious("liquidate", "operator", { p1: 1, count: 1, budget: 1_000 }, "liquidateAgain"),
    sharedResult("liquidateAgain", "$quoteOut.newCommitments[0]"),
    outcome("liquidateAgain", "operator", [0, 0, 1, { above: 0 }, { above: 0 }, { above: 0 }]),
    {
      redeem: "liquidateAgainOutcome",
      from: "operator",
      pays: { "oblivious.collateral": "$liquidateAgainOutcome.plaintext[3]", "oblivious.borrowed": "$liquidateAgainOutcome.plaintext[5]" },
    },
    // alice does not open that notice: her view opens one of her older notes of the position, and its note reports
    // what the second liquidation left
    oblivious("view", "alice", { position: 1 }, "viewAgain"),
    sharedResult("viewAgain", "$liquidateAgainOut.newCommitments[0]"),
    outcome("viewAgain", "alice", [0, 1, ACCRUED, { above: 0 }, { above: 0 }, 0]),

    // ---- the escape hatch ----
    // the queue is idle, so nothing starts the clock but a poke; T_LIVE (60 blocks) later anyone opens the hatch
    { tx: "poke", contract: "oblivious", from: "bob", args: [], what: "anyone starts the idle market's starving clock" },
    { advance: 62, what: "T_LIVE blocks of starving: a poke and no round landing" },
    { tx: "open_hatch", contract: "oblivious", from: "bob", args: [], what: "anyone opens the escape hatch" },
    // her notice of the first liquidation is stale: the second spent its tag, so its exit pushes an existing
    // nullifier, which the node's validation refuses at simulation (stdlib TX_ERROR_EXISTING_NULLIFIER)
    { tipExit: "oblivious", ...EXIT, from: "alice", position: 1, note: "$liquidateNotice", refused: ["Existing nullifier"], what: "alice's exit on her stale notice" },
    // her view's note is her newest with an unspent tag: she repays its debt from her credit and takes its collateral
    {
      tipExit: "oblivious", ...EXIT,
      from: "alice",
      position: 1,
      pays: { "oblivious.collateral": "$viewAgainOutcome.plaintext[3]" },
      repays: { "oblivious.borrowed": "$viewAgainOutcome.plaintext[4]" },
      what: "alice's exit as a borrower",
    },
    { tipExit: "oblivious", ...EXIT, from: "alice", position: 1, refused: ["Existing nullifier"], what: "alice's second exit" },
  ],
};
