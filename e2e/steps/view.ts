// A read of a contract's state: a view or utility function simulated from an
// account's wallet (a public view such as lending's `get_kept_deposits`, a
// token's `balance_of_private` of an account its wallet holds), its result
// bound and checked. `grew` compares a number with an earlier read of the
// same function (a private balance after an escrow or a refund) and waits,
// at most BALANCE_WAIT_MS, for the wallet's PXE to find the notes of the
// latest blocks before it fails.
import { Contract } from "@aztec-labs/aztec.js/contracts";

import { defineKind, refs, type Common } from "../engine/kind.ts";
import { big, check, poll, type Expect, type Value } from "../engine/scope.ts";
import { methodsOf } from "../engine/tip.ts";
import { BALANCE_WAIT_MS } from "./redeem.ts";

export interface ViewStep extends Common {
  /** The function, a view or a utility. */
  view: string;
  /** One of the scenario's contracts, a tip deployment or a contract it
   * deployed first (`<tip name>.<name>`). */
  contract: string;
  /** The account whose wallet simulates it (and its `from`). */
  from: string;
  args?: Value[];
  /** Binds the result. */
  name?: string;
  /** The result, a number, must be an earlier read's (`since`, a `view`
   * step's name) plus `by` (negative: less). */
  grew?: { since: string; by: Value };
  expect?: Expect[];
}


export default defineKind<ViewStep>({
  key: "view",
  check(step, s) {
    refs.account(s, step.from);
    refs.contract(s, step.contract);
    check(step.grew === undefined || (typeof step.grew.since === "string" && step.grew.by !== undefined), "grew takes an earlier read (since) and the change (by)");
    return { fields: ["view", "contract", "from", "args", "name", "grew", "expect"], binds: [step.name] };
  },
  async run(ctx, step) {
    const label = step.what ?? step.name ?? `${step.contract}.${step.view}`;
    const { address, artifact } = ctx.contract(step.contract);
    const f = methodsOf(Contract.at(address, artifact, ctx.network.walletOf(step.from)))[step.view];
    check(f !== undefined, `${label}: ${step.contract} has no function ${step.view}`);
    const args = (step.args ?? []).map((a) => ctx.scope.resolve(a));
    const read = async () => (await f(...args).simulate({ from: ctx.account(step.from) })).result;
    let result = await read();
    if (step.grew) {
      const want = big(ctx.scope.lookup(step.grew.since)) + big(ctx.scope.resolve(step.grew.by));
      if (big(result) !== want) result = (await poll(read, (r) => big(r) === want, BALANCE_WAIT_MS)).value;
      check(big(result) === want, `${label}: ${step.view} reads ${big(result)}, not ${want} (${step.grew.since}, ${big(ctx.scope.lookup(step.grew.since))}, changed by ${big(ctx.scope.resolve(step.grew.by))})`);
    }
    ctx.logger.info(`${label}: ${step.contract}.${step.view}(${args.map(String).join(", ")}) from ${step.from}: ${typeof result === "object" ? JSON.stringify(result, (_, v) => (typeof v === "bigint" ? v.toString() : v)) : String(result)}`);
    if (step.name) ctx.scope.set(step.name, result);
    if (step.expect) ctx.scope.expectAll(label, step.expect);
  },
});
