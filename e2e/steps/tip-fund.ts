// An account funds its private credit in a tip deployment that keeps
// credits (its deployment file's `credit`; lending's `fund(collateral,
// borrowed, nonces)`, examples/lending-tip/README.md, "Tokens"): one token
// transfer per asset from the account's private balance into the app's
// public one, under the account's authwits (each the token's
// `transfer_to_public(from, app, amount, nonce)` with the app as caller), in
// a transaction of its own whose amounts are public and linked to no
// request; the app credits a note of the account's for them, which its
// requests draw on. The account's credit of each asset (the credit's
// `balance` utility) must grow by its amount.
import type { AuthWitness } from "@aztec-labs/stdlib/auth-witness";
import { Contract } from "@aztec-labs/aztec.js/contracts";
import { Fr } from "@aztec-labs/aztec.js/fields";

import type { RunContext } from "../engine/context.ts";
import { defineKind, refs, type Common } from "../engine/kind.ts";
import { big, check, poll } from "../engine/scope.ts";
import { tipContract, tipOf, type Tip, methodsOf } from "../engine/tip.ts";
import { timed, type CreditSpec } from "../harness/harness.ts";

export interface TipFundStep extends Common {
  /** The tip deployment (one whose deployment file names its `credit`). */
  tipFund: string;
  from: string;
  /** By token (`<tip>.<name>`, each asset of the credit named once), the
   * amount funded; not all 0. */
  amounts: Record<string, number>;
}

/** The deployment's credit (its deployment file's `credit`). */
export function creditOf(tip: Tip): CreditSpec {
  check(tip.d.credit !== undefined, `${tip.name} keeps no credits (its deployment file names no credit)`);
  return tip.d.credit;
}

/** Whether the deployment keeps credits. */
export function keepsCredits(tip: Tip): boolean {
  return tip.d.credit !== undefined;
}

/** The asset in the credit of the token contract `token` (`<tip>.<name>`). */
export function assetOf(tip: Tip, token: string): number {
  const asset = token.startsWith(`${tip.name}.`) ? creditOf(tip).assets[token.slice(tip.name.length + 1)] : undefined;
  check(asset !== undefined, `${token} is not a token of ${tip.name}'s credit (${Object.keys(creditOf(tip).assets).join(", ")})`);
  return asset;
}

/** `account`'s credit of `asset` in the deployment: the credit's `balance`
 * utility, `(owner, asset)`. */
export async function creditBalance(ctx: RunContext, tip: Tip, account: string, asset: number): Promise<bigint> {
  const { balance } = creditOf(tip);
  const f = methodsOf(tipContract(ctx, tip, account))[balance];
  check(f !== undefined, `${tip.name} has no ${balance}`);
  const owner = ctx.account(account);
  return big((await f(owner, asset).simulate({ from: owner })).result);
}

/** Waits until `account`'s credit of `asset` is `want` (the PXE finds a new
 * credit note once it has synced the block that made it), at most 60 s;
 * returns the last value read. */
export async function awaitCredit(ctx: RunContext, tip: Tip, account: string, asset: number, want: bigint): Promise<bigint> {
  return (await poll(() => creditBalance(ctx, tip, account, asset), (got) => got === want, 60_000)).value;
}

export default defineKind<TipFundStep>({
  key: "tipFund",
  check(step, s) {
    refs.tip(s, step.tipFund);
    refs.account(s, step.from);
    const amounts = Object.values(step.amounts ?? {});
    check(amounts.length > 0 && amounts.every((a) => Number.isInteger(a) && a >= 0) && amounts.some((a) => a > 0), "tipFund takes whole amounts by token, not all 0");
    return { fields: ["tipFund", "from", "amounts"] };
  },
  async run(ctx, step) {
    const tip = tipOf(ctx, step.tipFund);
    const credit = creditOf(tip);
    const assets = Object.keys(credit.assets);
    const named = Object.keys(step.amounts);
    check(named.length === assets.length && assets.every((a) => named.includes(a)), `tipFund ${tip.name}: amounts names ${named.join(", ")}, the credit's assets are ${assets.join(", ")}`);
    const amounts = assets.map((a) => BigInt(step.amounts[a]!));
    const label = step.what ?? `${step.from} funds ${tip.name}`;
    const owner = ctx.account(step.from);
    const wallet = ctx.network.walletOf(step.from);
    const nonces = Object.fromEntries(assets.map((a) => [a, Fr.random()]));
    const authWitnesses: AuthWitness[] = [];
    for (const [i, a] of assets.entries()) {
      if (amounts[i] === 0n) continue;
      const token = ctx.contract(`${tip.name}.${a}`);
      const transfer = methodsOf(Contract.at(token.address, token.artifact, wallet)).transfer_to_public!;
      const call = await transfer(owner, tip.address, amounts[i]!, nonces[a]).getFunctionCall();
      authWitnesses.push(await wallet.createAuthWit(owner, { caller: tip.address, call }));
    }
    const before: bigint[] = [];
    for (const a of assets) before.push(await creditBalance(ctx, tip, step.from, credit.assets[a]!));
    const fund = methodsOf(tipContract(ctx, tip, step.from))[credit.fund];
    check(fund !== undefined, `${tip.name} has no ${credit.fund}`);
    const fee = await ctx.network.fee("request");
    const { receipt } = await timed(ctx.logger, `tx ${label}`, () => fund(...amounts, nonces).send({ ...fee, from: owner, authWitnesses }));
    const after: bigint[] = [];
    for (const [i, a] of assets.entries()) after.push(await awaitCredit(ctx, tip, step.from, credit.assets[a]!, before[i]! + amounts[i]!));
    check(
      assets.every((_, i) => after[i]! - before[i]! === amounts[i]),
      `${label}: the credit moved ${before} -> ${after}`,
    );
    ctx.logger.info(`${label}: tx ${receipt.txHash}, credit [${assets.join(", ")}] ${before} -> ${after}`);
  },
  txs(ctx, step, sent) {
    const tip = tipOf(ctx, step.tipFund);
    return sent.map((txHash) => ({ kind: "other", txHash, round: creditOf(tip).fund, deployment: tip.deployment }));
  },
});
