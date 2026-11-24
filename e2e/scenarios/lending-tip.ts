// Lending at the tip of the chain (scenarios/README.md, "lending-tip.ts"):
// two deployments the harness made of examples/lending-tip's LendingTip
// (E2E_TIP=1, E2E_TIP_DEPLOYMENTS="lending-tip lending-tip-plain"), each with
// its own two tokens (the collateral and the borrowed asset; every account
// holds both privately, the market the seeded liquidity publicly) and
// LendingOracle deployed first (their addresses in the Config, the oracle's
// in every round manifest's price read) and its init round landed by its
// relayer. Every account funds a credit on each deployment (its private
// balance in the market, in a transaction of its own); every request draws
// the usage deposit, which the market keeps, and a deposit, a repayment, a
// supply and a liquidation their escrow, from it, with no token call; redeems
// and exits credit it, and withdraw_funds turns it into tokens. Ownership is by note: every request commits
// its sender's partial note, the round completes it, and a request on an
// open position must open one of the sender's notes of it in the private
// function; no round sees an owner. On the secret-shared deployment, the
// default (secret-shared receipt intake, private outcomes completing the
// sender's partial note in the co-SNARK): an opening deposit, a borrow
// whose note the user opens and redeems in borrowed tokens (once),
// audited for what its transactions show, a view of someone else's
// position refused in the private function, and the owner's view from its
// redeemed note. On the non-secret-shared deployment (the deposit under both
// non-secret-shared intakes, public outputs, the note completed in public by
// apply): opening deposits at the scheduler's index under on-chain intake
// and receipt intake, the same receipts refused again, a deposit into
// another's position refused in the private function, a zero deposit
// refused at intake, and a price move during a deposit into the owner's own
// position (its note found from the public completion) inside the epoch
// window (lands as computed) and past it (recomputed exactly once). Then
// the keeper on the secret-shared deployment: after the price falls a scan
// reports the unhealthy position, pss-client's keeper loop hands it to the
// liquidate round and stops at the book's end, the liquidation lands under
// a budget and its redeem pays the seize and the unused budget; the
// liquidated owner opens its notice from the same result (the delivery
// handle its view left, completed by the liquidation), and the notice opens
// its repayment; then the borrow limit on what
// is left: a withdrawal that holds (redeemed in collateral tokens), a borrow
// to the limit (redeemed), and a withdrawal past it (code 9, nothing to
// redeem). Interest accrues by time throughout (every round's pinned clock,
// the market's block number): after advances of empty blocks, the view and
// the repayment report the debt at the current index and the borrow index
// above par, and the quote both indices above par. Then a landing's exit
// tags and its commitment move land together or not at all, each on a held
// attempt: a landing whose apply reverts (a pinned epoch too old), one whose
// teardown reverts after its apply succeeded (paying through the test
// probe), each mined reverted with nothing of it on the chain and then
// landed again with the same exit tag, and two landings of one result in one
// block, an outsider's first with a priority fee and a reverting call, then
// the ordinary one, which lands. Then bob's position is liquidated twice
// with no round of his between. Last, the escape hatch: bob supplies, the
// relayer stops (the network gone), a view waits at the head past the
// deployments' t_live, anyone opens the hatch, the held view's landing then
// reverts, and alice (a borrower: she repays her note's debt and takes its
// collateral) and bob (a lender) exit on their newest notes with no node, by
// their unspent exit tags, bob's second exit refused; bob's exit on his
// liquidated position's old note is refused, he recovers the two notices
// from the chain through his spent tags and exits on the second.
import type { Expect, Scenario, Step, Value } from "../scenario.ts";

/** The usage deposit every request pays in the borrowed token (the
 * deployments' Config `deposit.amount`; kept by every round that runs). */
export const USAGE_DEPOSIT = 5;

/** A note's payout of `amount` in the collateral asset: the amount with the
 * asset bit 2^128 (lending_tip market.nr `payout`); a payout in the borrowed
 * asset is the amount alone. */
export const collateralPayout = (amount: number): bigint => (1n << 128n) + BigInt(amount);

/** INDEX_ONE (lending_tip market.nr): a borrower note's mask, the index at
 * its position's last touch (the borrower kind's marker; a lender's note
 * has mask 0). */
export const ONE = 1_000_000_000;

/** The treasury the shared deployment's Config pins (e2e/tip/lending-tip.json),
 * which `sweep_deposits` pays the kept usage deposits to. */
export const TREASURY = "0x0000000000000000000000000000000000000000000000000000000000007ea5";

/** What each account funds its credit with on each deployment, of each
 * token (`tipFund`): every request draws its escrow and the usage deposit
 * from it, and redeems and exits credit it. */
export const FUNDED = 20_000;

/** The funding steps of `tip`: each account credits FUNDED of both tokens. */
export function funded(tip: string, accounts: string[]): Step[] {
  return accounts.map((from) => ({ tipFund: tip, from, amounts: { collateral: FUNDED, borrowed: FUNDED } }));
}

/** A non-secret-shared deposit, under on-chain intake (`deposit`) or receipt
 * intake (`deposit_receipt`): the request holds the sender's partial note
 * (its clear input `partial_note`), the request function takes the sender's
 * rho in its place and tells the sender's PXE of the note offchain. */
function plain(round: "deposit" | "deposit_receipt", from: string, position: Value, amount: number, name: string): Step {
  const method = round === "deposit" ? "deposit" : "deposit_with_receipts";
  return { tipRequest: round, namespace: "plain", from, method, inputs: { position, amount }, name };
}

/** A non-secret-shared deposit's end, bound as `<request>Out`: its app
 * outputs are the owner layout [code, position, mask, payout, new leaf
 * hashes...], and apply completed the request's partial note in public: the
 * completion log [tag, slot, code, position, mask, 0, 0, payout, aux,
 * request_id], its aux 0. */
function plainResult(request: string, expect: Expect[]): Step {
  const out = `${request}Out`;
  return {
    tipResult: request,
    name: out,
    expect: [
      ["len", `$${out}.completion`, 10],
      ["eq", `$${out}.completion[2]`, `$${out}.appOutputs[0]`],
      ["eq", `$${out}.completion[3]`, `$${out}.appOutputs[1]`],
      ["eq", `$${out}.completion[4]`, `$${out}.appOutputs[2]`],
      ["eq", `$${out}.completion[7]`, `$${out}.appOutputs[3]`],
      ["eq", `$${out}.completion[8]`, 0],
      ...expect,
    ],
  };
}
const ok = (request: string, position?: number): Expect[] => [
  ["eq", `$${request}Out.ok`, 1],
  ["eq", `$${request}Out.appOutputs[0]`, 0],
  ...(position === undefined ? [] : ([["eq", `$${request}Out.appOutputs[1]`, position]] as Expect[])),
];
/** Ran on the book the previous round left. */
const after = (request: string, previous: string): Expect => ["eq", `$${request}Out.oldCommitments[0]`, previous];

/** A secret-shared request: the amount and the sender's partial note are
 * shared, the position clear. A deposit escrows its amount of the
 * collateral token, a repayment its amount and a liquidation its budget of
 * the borrowed token. */
function shared(
  round: "deposit" | "withdraw" | "borrow" | "repay" | "supply" | "withdraw_supply" | "view" | "quote" | "scan" | "liquidate",
  from: string,
  inputs: Record<string, Value>,
  name: string,
): Step {
  return { tipRequest: `${round}_shared`, namespace: "shared", from, method: `${round}_shared`, inputs, name };
}
/** A secret-shared round's end: the book re-blinded whatever the outcome;
 * `more` checks the bound result further. */
export function sharedResult(request: string, previous: string, more: Expect[] = []): Step {
  const out = `${request}Out`;
  return {
    tipResult: request,
    name: out,
    expect: [["eq", `$${out}.oldCommitments[0]`, previous], ["ne", `$${out}.newCommitments[0]`, `$${out}.oldCommitments[0]`], ...more],
  };
}
/** An outcome field that must be above a value (`outcome` checks it with
 * `gt`). */
export type Above = { above: Value };
const isAbove = (v: Value | Above): v is Above => typeof v === "object" && v !== null && !Array.isArray(v) && "above" in v;
/** A field of an outcome that interest moves: the borrow index (a borrower
 * note's mask, the quote's borrow index) or the supply index, above
 * INDEX_ONE once the book has accrued. */
export const ACCRUED: Above = { above: ONE };

/** The field of lending's note plaintext `[code, position, mask, x, y,
 * payout, aux]` that names its position: the entry of its exit tag (the
 * tipExit and tipRecover steps' `entry`). */
export const ENTRY = 1;

/** Lending's exit through the escape hatch: its `exit(position,
 * request_id)` on the notes whose ENTRY field is the position (spread into a
 * tipExit step). */
export const EXIT = { exit: "exit", entry: ENTRY };

/** The landing a tipLand or tipOutbid step sends: `apply_shared(apply, opened,
 * tags)`, whose `tags` are the round's exit tags. */
export const LANDING = { landing: "apply_shared", tags: "tags" };

/** Where lending's scan outcome `[code, 0, report, 0, start, 0, occupied]`
 * holds its report (the keeper step's `layout`, a pss-client ScanLayout): the position, x and payout
 * fields are 0, so a scan's note names no position and pays nothing. */
export const SCAN_LAYOUT = { fields: 7, code: 0, report: 2, start: 4, occupied: 6, zero: [1, 3, 5] };

/** The sender opens the outcome [code, position, mask, x, y, payout, aux]
 * and takes its note: `want` the first six (a payout in the collateral
 * asset `collateralPayout(amount)`; `{ above }` for a field that must be
 * above a value, `ACCRUED` for an index above INDEX_ONE), `aux` the seventh
 * (a scan's occupied count, a quote's utilisation, else 0). */
export function outcome(request: string, owner: string, want: (Value | Above)[], aux: Value = 0): Step {
  const name = `${request}Outcome`;
  return {
    tipOutcome: request,
    owner,
    notes: "outcome_notes",
    name,
    expect: [
      ["len", `$${name}.plaintext`, 7],
      ...want.map((v, i): Expect => (isAbove(v) ? ["gt", `$${name}.plaintext[${i}]`, v.above] : ["eq", `$${name}.plaintext[${i}]`, v])),
      ["eq", `$${name}.plaintext[6]`, aux],
    ],
  };
}

/** The liquidated owner's notice: `owner`'s request `handle` (its last on
 * the position) left a delivery handle in the position, and the liquidation
 * `by` completed it, so the owner opens, from the liquidator's result, an
 * owner note of the position after the liquidation `[0, position, index at
 * touch, collateral, debt, 0, 0]` (the index accrued, above INDEX_ONE),
 * which pays nothing. */
export function notice(handle: string, by: string, owner: string, position: number, collateral: number, debt: number): Step {
  const name = `${by}Notice`;
  return {
    tipNotice: handle,
    by,
    owner,
    notes: "outcome_notes",
    name,
    expect: [
      ["len", `$${name}.plaintext`, 7],
      ["eq", `$${name}.plaintext[0]`, 0],
      ["eq", `$${name}.plaintext[1]`, position],
      ["gt", `$${name}.plaintext[2]`, ONE],
      ["eq", `$${name}.plaintext[3]`, collateral],
      ["eq", `$${name}.plaintext[4]`, debt],
      ["eq", `$${name}.plaintext[5]`, 0],
      ["eq", `$${name}.plaintext[6]`, 0],
      ["eq", `$${name}.requestId`, `$${by}.chainRequestId`],
    ],
  };
}

/** The keeper on the secret-shared deployment, after its last view: `bob` opens a
 * healthy position 3 (1,000, no debt; its index at touch the borrow index
 * the book has accrued to); the oracle opens epoch 2 at 2.00, where
 * `alice`'s 1,000 / 1,701 is unhealthy; `operator`, the keeper, scans
 * window 0 and opens `[0, 0, report, 0, start, 0, occupied]`: bit 1 (position
 * 1) of the window's three occupied positions (the lender's position 2
 * among them, never unhealthy), a note that names no position and pays
 * nothing. pss-client's keeper loop (keeperPass, the `keeper` step) reads the
 * outcome: one liquidate round of position 1, and no further window (three
 * occupied of seven: the book ends there). The liquidation it hands over
 * lands under the keeper's budget of 1,000 (escrowed in the borrowed token):
 * alice's debt brought to the current index (1,702: interest since her view,
 * below a unit at the book's 17 bps utilisation, rounds up by one), repay
 * 851, seize 446, 149 of the budget unused; its redeem pays the keeper 446
 * collateral tokens and 149 borrowed ones. `alice` learns of it privately
 * from the same result: her view left a delivery handle in position 1,
 * which the liquidation completed, and she opens its notice, 554 / 851. */
const keeper: Step[] = [
  shared("deposit", "bob", { position: 0, amount: 1_000 }, "keeperBobOpen"),
  sharedResult("keeperBobOpen", "$sharedViewOut.newCommitments[0]"),
  outcome("keeperBobOpen", "bob", [0, 3, ACCRUED, 1_000, 0, 0]),
  { tx: "set_price", contract: "shared.oracle", from: "operator", args: [200], what: "the shared market's oracle opens epoch 2 at 2.00" },
  shared("scan", "operator", { start: 0 }, "keeperScan"),
  sharedResult("keeperScan", "$keeperBobOpenOut.newCommitments[0]"),
  outcome("keeperScan", "operator", [0, 0, 0b10, 0, 0, 0], 3),
  {
    keeper: { 0: "keeperScanOutcome" },
    namespace: "shared",
    scan: "scan_shared",
    act: "liquidate_shared",
    layout: SCAN_LAYOUT,
    name: "keeperPass",
    expect: [
      ["len", "$keeperPass.scanned", 1],
      ["len", "$keeperPass.reported", 1],
      ["eq", "$keeperPass.reported[0]", 1],
      ["len", "$keeperPass.acts", 1],
    ],
  },
  shared(
    "liquidate",
    "operator",
    { p1: "$keeperPass.acts[0].inputs.p1", count: "$keeperPass.acts[0].inputs.count", budget: 1_000 },
    "keeperLiquidate",
  ),
  sharedResult("keeperLiquidate", "$keeperScanOut.newCommitments[0]"),
  outcome("keeperLiquidate", "operator", [0, 0, 1, 446, 851, 149], 0),
  // the note names no position: its redeem pays the seize in collateral and the unused budget in the borrowed token
  { redeem: "keeperLiquidateOutcome", from: "operator", pays: { "shared.collateral": "$keeperLiquidateOutcome.plaintext[3]", "shared.borrowed": "$keeperLiquidateOutcome.plaintext[5]" } },
  notice("sharedView", "keeperLiquidate", "alice", 1, 554, 851),
];

/** `account`'s private balance of a deployment's token, bound as `name`;
 * with `since`, it must be that earlier read's plus `by`. */
function balance(tip: string, token: "collateral" | "borrowed", account: string, name: string, since?: [string, number]): Step {
  return {
    view: "balance_of_private",
    contract: `${tip}.${token}`,
    from: account,
    args: [`$accounts.${account}`],
    name,
    ...(since && { grew: { since: since[0], by: since[1] } }),
  };
}

/** `account`'s credit in a deployment, of the collateral asset (asset 1) or
 * the borrowed asset (asset 0; the usage deposits come from it), bound as
 * `name`; with `since`, it must be that earlier read's plus `by`. A request's
 * escrow and usage deposit come from the credit, never from a token balance. */
function credit(tip: string, asset: "collateral" | "borrowed", account: string, name: string, since?: [string, number]): Step {
  return {
    view: "credit_balance",
    contract: tip,
    from: account,
    args: [`$accounts.${account}`, asset === "collateral" ? 1 : 0],
    name,
    ...(since && { grew: { since: since[0], by: since[1] } }),
  };
}

/** The usage deposits a deployment's rounds kept: `rounds` of them. */
function kept(tip: string, rounds: number): Step {
  const name = `${tip}Kept`;
  return { view: "get_kept_deposits", contract: tip, from: "operator", name, expect: [["eq", `$${name}`, rounds * USAGE_DEPOSIT]] };
}

/** The test probe (noir/pss_probe), deployed by the scenario: its
 * `revert_in_teardown()` makes a transaction's teardown revert, its
 * `always_revert()` its app logic. */
const PROBE = "probe";

/** A landing's exit tags and its commitment move land together or not at
 * all (pss_public_contract hatch.nr), on the shared deployment, each case on
 * a held attempt (the relayer stopped, the nodes' result taken before
 * anything moves; `tipLand`, `tipOutbid`). Bob's view of his position 3,
 * computed at oracle epoch 2, is landed by the operator after the oracle
 * opened epochs 3 and 4: its apply reverts ("pinned epoch too old"), mined,
 * with nothing of it on the chain (its exit tag, the tag of bob's note of
 * position 3, unspent); the nodes recompute it and the relayer lands that
 * attempt, whose exit tag is the same (a tag depends on the request, never
 * on the attempt). Bob's borrow of 1,400 against it (the limit: 75% of
 * 1,000 at 2.00 is 1,500) is landed by the operator paying through the
 * probe's reverting teardown: mined reverted after its apply succeeded,
 * nothing on the chain; then the operator lands the same attempt
 * ordinarily. Alice's view of her position 1 is landed twice in one block:
 * by bob, in a transaction that then calls the probe's `always_revert()`,
 * with a priority fee, and by the operator for the relayer: bob's is first
 * and reverts, the operator's lands. */
const atomicity: Step[] = [
  { relayer: "stop", namespace: "shared" },
  shared("view", "bob", { position: 3 }, "heldView"),
  { tipAttempt: "heldView", name: "heldViewAttempt" },
  { tx: "set_price", contract: "shared.oracle", from: "operator", args: [220], what: "the shared market's oracle opens epoch 3 at 2.20" },
  { tx: "set_price", contract: "shared.oracle", from: "operator", args: [200], what: "the shared market's oracle opens epoch 4 at 2.00" },
  { tipLand: "heldView", ...LANDING, attempt: "heldViewAttempt", from: "operator", reverts: "apply", reason: ["pinned epoch too old"], name: "heldViewLanding" },
  { tipAttempt: "heldView", after: "$heldViewAttempt.machineRequestId", recomputed: 1, name: "heldViewRecomputed" },
  { relayer: "start", namespace: "shared" },
  sharedResult("heldView", "$sharedQuoteOut.newCommitments[0]", [
    ["eq", "$heldViewOut.machineRequestId", "$heldViewRecomputed.machineRequestId"],
    ["eq", "$heldViewOut.appValues[0]", "$heldViewLanding.exitTags[0]"],
  ]),
  outcome("heldView", "bob", [0, 3, ACCRUED, 1_000, 0, 0]),

  { relayer: "stop", namespace: "shared" },
  shared("borrow", "bob", { position: 3, amount: 1_400 }, "heldBorrow"),
  { tipAttempt: "heldBorrow", name: "heldBorrowAttempt" },
  { tipLand: "heldBorrow", ...LANDING, attempt: "heldBorrowAttempt", from: "operator", reverts: "teardown", probe: PROBE, reason: ["the probe reverts"], name: "heldBorrowLanding" },
  {
    tipResult: "heldBorrow",
    by: "user",
    from: "operator",
    name: "heldBorrowOut",
    expect: [
      ["eq", "$heldBorrowOut.oldCommitments[0]", "$heldViewOut.newCommitments[0]"],
      ["eq", "$heldBorrowOut.machineRequestId", "$heldBorrowAttempt.machineRequestId"],
      ["eq", "$heldBorrowOut.appValues[0]", "$heldBorrowLanding.exitTags[0]"],
    ],
  },
  outcome("heldBorrow", "bob", [0, 3, ACCRUED, 1_000, 1_400, 1_400]),
  { redeem: "heldBorrowOutcome", from: "bob", pays: { "shared.borrowed": 1_400, "shared.collateral": 0 } },

  shared("view", "alice", { position: 1 }, "outbidView"),
  { tipAttempt: "outbidView", name: "outbidViewAttempt" },
  { tipOutbid: "outbidView", ...LANDING, attempt: "outbidViewAttempt", from: "bob", lander: "operator", probe: PROBE, name: "outbidLanding" },
  { relayer: "start", namespace: "shared" },
  // her note: 500 collateral, the debt of 750 accrued to the view's index
  outcome("outbidView", "alice", [0, 1, ACCRUED, 500, { above: 749 }, 0]),
];

/** Bob's position 3 (1,000 collateral, 1,400 debt) liquidated twice by the
 * operator with no round of bob's between, each after a price fall (the
 * liquidation repays half the debt, under a budget of 1,000, and seizes its
 * value at the price plus the bonus): at 1.70 the position is unhealthy
 * (1,000 * 1.70 * 80% = 1,360 < 1,400); at 1.50 what the first left is
 * unhealthy again (about 568 * 1.50 * 80% = 682 < 700). The operator's note
 * of each names no position and redeems the seize and the unused budget.
 * Bob opens neither notice here: he recovers both from the chain once the
 * market is frozen. */
const twiceLiquidated: Step[] = [
  { tx: "set_price", contract: "shared.oracle", from: "operator", args: [170], what: "the shared market's oracle opens epoch 5 at 1.70" },
  shared("liquidate", "operator", { p1: 3, count: 1, budget: 1_000 }, "liquidated"),
  sharedResult("liquidated", "$outbidLanding.newCommitments[0]"),
  outcome("liquidated", "operator", [0, 0, 1, { above: 0 }, { above: 0 }, { above: 0 }]),
  { redeem: "liquidatedOutcome", from: "operator", pays: { "shared.collateral": "$liquidatedOutcome.plaintext[3]", "shared.borrowed": "$liquidatedOutcome.plaintext[5]" } },
  { tx: "set_price", contract: "shared.oracle", from: "operator", args: [150], what: "the shared market's oracle opens epoch 6 at 1.50" },
  shared("liquidate", "operator", { p1: 3, count: 1, budget: 1_000 }, "liquidatedAgain"),
  sharedResult("liquidatedAgain", "$liquidatedOut.newCommitments[0]"),
  outcome("liquidatedAgain", "operator", [0, 0, 1, { above: 0 }, { above: 0 }, { above: 0 }]),
  { redeem: "liquidatedAgainOutcome", from: "operator", pays: { "shared.collateral": "$liquidatedAgainOutcome.plaintext[3]", "shared.borrowed": "$liquidatedAgainOutcome.plaintext[5]" } },
];

export const scenario: Scenario = {
  example: "lending-tip",
  // the local network's three accounts: the oracles' and the tokens' owner (the harness deployed them from the
  // first), who also opens a third position, and two owners
  accounts: ["operator", "alice", "bob"],
  wallets: { alice: ["operator", "alice"], bob: ["bob"] },
  // the tokens the harness minted from the operator reach bob's wallet under the operator's tags
  senders: ["operator"],
  keys: {},
  values: {},
  // the test probe, deployed with no initializer: the reverted landings' teardown and reverting call
  contracts: { [PROBE]: { package: "pss_probe", dir: "noir", from: "operator" } },
  namespaces: {},
  tip: { shared: "lending-tip", plain: "lending-tip-plain" },
  steps: [
    { tipInit: "shared", name: "sharedInit" },
    { tipInit: "plain", name: "plainInit" },
    // every account funds its credit on both deployments, in transactions of their own: the requests below draw
    // their escrows and usage deposits from it (no token call, no amount in any request), redeems credit it
    ...funded("shared", ["operator", "alice", "bob"]),
    ...funded("plain", ["operator", "alice", "bob"]),

    // ---- the secret-shared deployment: secret-shared receipt intake, the sender's partial note completed in the co-SNARK ----
    shared("deposit", "alice", { position: 0, amount: 1_000 }, "sharedOpen"),
    sharedResult("sharedOpen", "$sharedInit.newCommitments[0]"),
    outcome("sharedOpen", "alice", [0, 1, ONE, 1_000, 0, 0]),
    // a lender, `operator`, supplies 5,000 of the borrowed token before the first borrow: a lender position at
    // the next index (mask 0), one share per unit while the pool is worth its shares
    shared("supply", "operator", { position: 0, amount: 5_000 }, "sharedSupply"),
    sharedResult("sharedSupply", "$sharedOpenOut.newCommitments[0]"),
    outcome("sharedSupply", "operator", [0, 2, 0, 5_000, 5_000, 0]),
    // alice's note of position 1 opens her borrow in its private function
    shared("borrow", "alice", { position: "$sharedOpenOutcome.plaintext[1]", amount: 1_700 }, "sharedBorrow"),
    sharedResult("sharedBorrow", "$sharedSupplyOut.newCommitments[0]"),
    outcome("sharedBorrow", "alice", [0, 1, ONE, 1_000, 1_700, 1_700]),
    // what the borrow's intake and result transactions show: no amount, partial note, owner or outcome value
    { tipAudit: "sharedBorrow", outcome: "sharedBorrowOutcome" },
    // the note names its position: the redeem pays the payout, 1,700 borrowed tokens, and no collateral
    { redeem: "sharedBorrowOutcome", from: "alice", pays: { "shared.borrowed": "$sharedBorrowOutcome.plaintext[5]", "shared.collateral": 0 } },
    // the same redeem again pushes the same redeem nullifier: refused (a nullifier collision)
    { redeem: "sharedBorrowOutcome", from: "alice", refused: ["ullifier"], what: "the same redeem again" },
    // bob holds no note of position 1: his view is refused in the private function, nothing queued
    {
      tipRequest: "view_shared",
      namespace: "shared",
      from: "bob",
      method: "view_shared",
      inputs: { position: 1 },
      refused: ["the sender holds no note of this position"],
      what: "bob's view of alice's position",
    },
    // interest accrues by time: two empty blocks (every round's clock moves anyway), then alice's view (her notes stay readable after the redeem
    // and still confer the position) reports her debt at the current index and the borrow index in mask, above
    // INDEX_ONE. At the book's utilisation (1,700 of 1,005,000, 16 bps; about 0.09 per 10^9 per block) the
    // interest is far below a unit, so the debt shows the rounding rule's one unit (a debt brought to the index
    // rounds up): 1,701
    { advance: 2, what: "two blocks of interest" },
    shared("view", "alice", { position: 1 }, "sharedView"),
    sharedResult("sharedView", "$sharedBorrowOut.newCommitments[0]"),
    outcome("sharedView", "alice", [0, 1, ACCRUED, 1_000, 1_701, 0]),

    // ---- the non-secret-shared deployment: the deposit under both non-secret-shared intakes, at 2.50 (oracle epoch 1) ----
    // on-chain intake: position 0 opens a position at the scheduler's index; apply completes alice's note in public
    { ...plain("deposit", "alice", 0, 1_000, "aliceOpen"), nodeTamper: true } as Step,
    plainResult("aliceOpen", [...ok("aliceOpen", 1), after("aliceOpen", "$plainInit.newCommitments[0]")]),
    // receipt intake: the inputs reach the nodes only, the chain sees the id and the expiry
    plain("deposit_receipt", "bob", 0, 1_000, "bobOpen"),
    plainResult("bobOpen", [...ok("bobOpen", 2), after("bobOpen", "$aliceOpenOut.newCommitments[0]")]),
    // the same arguments again: the partial note's use nullifier (and the request id) were seen
    {
      what: "the same receipts again",
      tipRequest: "deposit_receipt",
      namespace: "plain",
      again: "bobOpen",
      from: "bob",
      method: "deposit_with_receipts",
      refused: ["ullifier"],
    },
    // bob holds no note of alice's position 1: refused in the private function, nothing escrowed from his
    // credit (no collateral, no usage deposit)
    credit("plain", "collateral", "bob", "bobCreditCollateral"),
    credit("plain", "borrowed", "bob", "bobCreditBorrowed"),
    {
      tipRequest: "deposit",
      namespace: "plain",
      from: "bob",
      method: "deposit",
      inputs: { position: 1, amount: 100 },
      refused: ["the sender holds no note of this position"],
      what: "bob's deposit into alice's position",
    },
    credit("plain", "collateral", "bob", "bobNotEscrowed", ["bobCreditCollateral", 0]),
    credit("plain", "borrowed", "bob", "bobNoDeposit", ["bobCreditBorrowed", 0]),
    // a deposit of 0 (code 2) is refused at intake: nothing queued
    {
      tipRequest: "deposit",
      namespace: "plain",
      from: "alice",
      method: "deposit",
      inputs: { position: 0, amount: 0 },
      refused: ["invalid inputs"],
      what: "a deposit of 0",
    },

    // a price move inside the epoch window: bob's deposit into his own position 2 (his note from the public
    // completion, found by his PXE) computed at 2.50 (epoch 1) lands after the oracle opens epoch 2 at 2.00
    { relayer: "stop", namespace: "plain" },
    plain("deposit", "bob", 2, 500, "inWindow"),
    { tipAttempt: "inWindow", name: "inWindowAttempt", recomputed: 0, expect: [["eq", "$inWindowAttempt.reads[0]", 250], ["eq", "$inWindowAttempt.reads[1]", 1]] },
    { tx: "set_price", contract: "plain.oracle", from: "operator", args: [200], what: "the oracle opens epoch 2 at 2.00" },
    { relayer: "start", namespace: "plain" },
    plainResult("inWindow", [
      ...ok("inWindow", 2),
      ["eq", "$inWindowOut.machineRequestId", "$inWindowAttempt.machineRequestId"],
      ["eq", "$inWindowOut.reads[1]", 1],
    ]),
    { log: "[bound] one epoch opened between the scheduler's read and apply: the attempt ${inWindowOut.machineRequestId} landed as computed (pinned epoch 1, oracle at epoch 2)" },

    // past the window: the operator's opening deposit computed at epoch 2 is recomputed once the oracle opens epochs 3 and 4
    { relayer: "stop", namespace: "plain" },
    plain("deposit", "operator", 0, 500, "pastWindow"),
    { tipAttempt: "pastWindow", name: "pastFirst", recomputed: 0, expect: [["eq", "$pastFirst.reads[0]", 200], ["eq", "$pastFirst.reads[1]", 2]] },
    { tx: "set_price", contract: "plain.oracle", from: "operator", args: [220], what: "the oracle opens epoch 3 at 2.20" },
    { tx: "set_price", contract: "plain.oracle", from: "operator", args: [200], what: "the oracle opens epoch 4 at 2.00" },
    { tipAttempt: "pastWindow", after: "$pastFirst.machineRequestId", recomputed: 1, name: "pastSecond", expect: [["eq", "$pastSecond.reads[0]", 200], ["eq", "$pastSecond.reads[1]", 4]] },
    { relayer: "start", namespace: "plain" },
    plainResult("pastWindow", [
      ...ok("pastWindow", 3),
      ["eq", "$pastWindowOut.machineRequestId", "$pastSecond.machineRequestId"],
      ["ne", "$pastWindowOut.machineRequestId", "$pastFirst.machineRequestId"],
      ["eq", "$pastWindowOut.reads[1]", 4],
    ]),
    { log: "[bound] two epochs opened between the scheduler's read and apply: one recompute (${pastFirst.machineRequestId} -> ${pastSecond.machineRequestId}), landed at epoch 4" },
    // the four rounds that ran kept their usage deposits
    kept("plain", 4),

    // ---- the keeper on the secret-shared deployment ----
    ...keeper,
    // the accrual step: two more blocks, then alice repays 400 of the 851 the liquidation left; her notice
    // (554 / 851) opens the request, and the repayment's note reports
    // the position as the leaf holds it after the round, its debt accrued to the current index first (852, the
    // interest again below a unit and rounded up) and 400 repaid: 452
    { advance: 2, what: "two more blocks of interest" },
    shared("repay", "alice", { position: 1, amount: 400 }, "sharedRepay"),
    sharedResult("sharedRepay", "$keeperLiquidateOut.newCommitments[0]"),
    outcome("sharedRepay", "alice", [0, 1, ACCRUED, 554, 452, 0]),
    // the borrow limit (75% of the collateral's value; the liquidation threshold is 80%) at 2.00, on what is left:
    // 554 collateral, 452 debt (453 at this round's index). A withdrawal of 54 holds (500 * 2.00 * 75% = 750 >=
    // 453): its note pays 54 collateral tokens
    shared("withdraw", "alice", { position: 1, amount: 54 }, "sharedWithdraw"),
    sharedResult("sharedWithdraw", "$sharedRepayOut.newCommitments[0]"),
    outcome("sharedWithdraw", "alice", [0, 1, ACCRUED, 500, 453, collateralPayout(54)]),
    { redeem: "sharedWithdrawOutcome", from: "alice", pays: { "shared.collateral": 54, "shared.borrowed": 0 } },
    // a borrow to the limit, 750, lands: the debt at the index is 454, so 296 more
    shared("borrow", "alice", { position: 1, amount: 296 }, "sharedBorrowLimit"),
    sharedResult("sharedBorrowLimit", "$sharedWithdrawOut.newCommitments[0]"),
    outcome("sharedBorrowLimit", "alice", [0, 1, ACCRUED, 500, 750, 296]),
    { redeem: "sharedBorrowLimitOutcome", from: "alice", pays: { "shared.borrowed": 296, "shared.collateral": 0 } },
    // one collateral token more out breaks the limit: code 9, the note names the position as the leaf holds it
    // (750 at the borrow's index) and pays nothing (refused at redeem)
    shared("withdraw", "alice", { position: 1, amount: 1 }, "sharedWithdrawPast"),
    sharedResult("sharedWithdrawPast", "$sharedBorrowLimitOut.newCommitments[0]"),
    outcome("sharedWithdrawPast", "alice", [9, 1, "$sharedBorrowLimitOutcome.plaintext[2]", 500, 750, 0]),
    { redeem: "sharedWithdrawPastOutcome", from: "alice", refused: ["the note has nothing to redeem"], what: "the redeem of a withdrawal past the limit" },
    // the lender withdraws all its shares after the repayment: their value, 5,000 (the interest the pool earned in
    // these minutes, a few units over 1,005,000 shares, is below a unit per 5,000 shares), paid through the note
    shared("withdraw_supply", "operator", { position: 2, shares: 5_000 }, "sharedExit"),
    sharedResult("sharedExit", "$sharedWithdrawPastOut.newCommitments[0]"),
    outcome("sharedExit", "operator", [0, 2, 0, 0, 0, 5_000]),
    { redeem: "sharedExitOutcome", from: "operator", pays: { "shared.borrowed": 5_000, "shared.collateral": 0 } },
    // a quote by bob: [0, 0, borrow index, 0, supply index, 0, utilisation]: both indices above par (the borrow
    // index by the accruals, the supply index by the interest they added to the pool), about 750 of debt over a
    // pool of 1,000,000 (7 bps); the note names no position and pays nothing
    shared("quote", "bob", {}, "sharedQuote"),
    sharedResult("sharedQuote", "$sharedExitOut.newCommitments[0]"),
    outcome("sharedQuote", "bob", [0, 0, ACCRUED, 0, ACCRUED, 0], 7),
    // every one of the thirteen secret-shared rounds kept its usage deposit
    kept("shared", 13),
    // the kept deposits go to the treasury pin: anyone sweeps them
    { tx: "sweep_deposits", contract: "shared", from: "bob", args: [], what: "the sweep of the kept usage deposits to the treasury" },
    { view: "balance_of_public", contract: "shared.borrowed", from: "operator", args: [TREASURY], name: "sharedTreasury", expect: [["eq", "$sharedTreasury", 13 * USAGE_DEPOSIT]] },
    { view: "get_kept_deposits", contract: "shared", from: "operator", name: "sharedSwept", expect: [["eq", "$sharedSwept", 0]] },

    // ---- a landing's exit tags and its commitment move land together or not at all ----
    ...atomicity,
    // ---- a position liquidated twice with no round of its owner's between ----
    ...twiceLiquidated,

    // ---- the escape hatch on the secret-shared deployment (examples/lending-tip/README.md, "The escape hatch") ----
    // bob supplies 1,000 at the next index, 4: a lender whose shares are worth its note's y
    shared("supply", "bob", { position: 0, amount: 1_000 }, "hatchSupply"),
    sharedResult("hatchSupply", "$liquidatedAgainOut.newCommitments[0]"),
    {
      tipOutcome: "hatchSupply",
      owner: "bob",
      notes: "outcome_notes",
      name: "hatchSupplyOutcome",
      expect: [["eq", "$hatchSupplyOutcome.plaintext[0]", 0], ["eq", "$hatchSupplyOutcome.plaintext[1]", 4], ["eq", "$hatchSupplyOutcome.plaintext[2]", 0], ["gt", "$hatchSupplyOutcome.plaintext[4]", 0]],
    },
    // the network vanishes: nothing lands from here on (the relayer stopped on an idle queue), and alice's view
    // waits at the head, never landed; the nodes' result of it is held
    { relayer: "stop", namespace: "shared" },
    shared("view", "alice", { position: 1 }, "hatchView"),
    { tipAttempt: "hatchView", name: "hatchViewAttempt" },
    // her request started the market's starving clock (the queue was empty): T_LIVE (the deployments' Config
    // t_live, 60 blocks) with no round landing, and anyone opens the hatch, for good
    { advance: 62, what: "T_LIVE blocks of starving: a request waiting and no round landing" },
    { tx: "open_hatch", contract: "shared", from: "bob", args: [], what: "anyone opens the escape hatch" },
    // the held view landed after the opening, by bob: its apply refuses (no round lands once the hatch is open),
    // mined reverted, and the exit tag it outputs, the tag of alice's newest note of position 1, stays unspent
    {
      tipLand: "hatchView",
      ...LANDING,
      attempt: "hatchViewAttempt",
      from: "bob",
      reverts: "apply",
      reason: ["the escape hatch is open"],
      name: "hatchViewLanding",
      what: "the held view landed after the opening",
    },
    // alice exits on her newest note of position 1, the outbid view's (its collateral and its debt, accrued), with
    // no node: her client finds it by its unspent tag, the one the refused landing would have spent; she repays the
    // note's debt from her credit and takes its collateral
    {
      tipExit: "shared", ...EXIT,
      from: "alice",
      position: 1,
      pays: { "shared.collateral": "$outbidViewOutcome.plaintext[3]" },
      repays: { "shared.borrowed": "$outbidViewOutcome.plaintext[4]" },
      name: "aliceExit",
      expect: [["eq", "$aliceExit.tag", "$hatchViewLanding.exitTags[0]"]],
      what: "alice's exit as a borrower",
    },
    // bob exits as a lender on his supply's note: its shares' value, once; a second exit pushes the spent tag
    // again, which the node's validation refuses at simulation (stdlib TX_ERROR_EXISTING_NULLIFIER)
    { tipExit: "shared", ...EXIT, from: "bob", position: 4, pays: { "shared.borrowed": "$hatchSupplyOutcome.plaintext[4]" }, what: "bob's exit as a lender" },
    { tipExit: "shared", ...EXIT, from: "bob", position: 4, refused: ["Existing nullifier"], what: "bob's second exit" },
    // bob's position 3, liquidated twice since his borrow: the first liquidation spent his borrow note's tag, so
    // an exit on that note is refused; his client recovers the two notices from the chain alone (the block each
    // tag was spent in names the liquidation, whose delivery to his borrow's handle it reads) and exits on the
    // second, repaying its debt and taking its collateral
    {
      tipExit: "shared", ...EXIT,
      from: "bob",
      position: 3,
      note: "$heldBorrowOutcome",
      refused: ["Existing nullifier"],
      what: "bob's exit on his borrow's note, which a liquidation replaced",
    },
    {
      tipRecover: "shared",
      owner: "bob",
      position: 3,
      entry: ENTRY,
      notes: "outcome_notes",
      name: "bobRecovered",
      expect: [
        ["len", "$bobRecovered.notices", 2],
        ["eq", "$bobRecovered.notices[0].requestId", "$liquidated.chainRequestId"],
        ["eq", "$bobRecovered.notices[1].requestId", "$liquidatedAgain.chainRequestId"],
        ["eq", "$bobRecovered.notices[1].plaintext[0]", 0],
        ["eq", "$bobRecovered.notices[1].plaintext[1]", 3],
        ["gt", "$bobRecovered.notices[1].plaintext[2]", ONE],
        ["gt", "$bobRecovered.notices[0].plaintext[3]", "$bobRecovered.notices[1].plaintext[3]"],
        ["gt", "$bobRecovered.notices[0].plaintext[4]", "$bobRecovered.notices[1].plaintext[4]"],
        ["gt", "$bobRecovered.notices[1].plaintext[4]", 0],
        ["eq", "$bobRecovered.notices[1].plaintext[5]", 0],
      ],
      what: "bob's recovery of position 3's notices",
    },
    {
      tipExit: "shared", ...EXIT,
      from: "bob",
      position: 3,
      pays: { "shared.collateral": "$bobRecovered.notices[1].plaintext[3]" },
      repays: { "shared.borrowed": "$bobRecovered.notices[1].plaintext[4]" },
      what: "bob's exit on the second notice",
    },
    // alice turns the collateral her exit credited into tokens: withdraw_funds pays from the market's public balance
    balance("shared", "collateral", "alice", "aliceCollateralBefore"),
    { tx: "withdraw_funds", contract: "shared", from: "alice", args: [500, 0], what: "alice withdraws her exit's collateral" },
    balance("shared", "collateral", "alice", "aliceCollateralAfter", ["aliceCollateralBefore", 500]),
  ],
};
