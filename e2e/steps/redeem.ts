// A completed note's value redeemed (docs/ARCHITECTURE.md section 6,
// "What the completed note is worth" and "Tokens and escrow"): the
// note's owner calls the app's `redeem(request_id)` in its own transaction,
// which reads its note of that request (a tipOutcome step delivered it),
// pushes the note's redeem nullifier (the note stays readable: a lending
// position note keeps conferring its position; the same redeem simulated
// again must be refused for that nullifier) and pays the note's
// settlement from the app's public balances into token notes of the owner's
// (the token's partial notes, which the owner's PXE finds from the token's
// own logs); the owner's private balance of each token (`balance_of_private`)
// must grow by its amount (`pays`). In a deployment that keeps credits (its
// deployment file's `credit`, lending's), the redeem credits the settlement
// to a note of the owner's instead, privately, and `pays` names the credit's
// growth, by the token (`<tip>.<name>`) whose asset it is. Or the redeem
// refused (a second redeem of the same note, or a note that pays nothing),
// nothing sent.
import { Contract } from "@aztec-labs/aztec.js/contracts";
import { Fr } from "@aztec-labs/aztec.js/fields";
import { txEffectFrom } from "@aztec-pss/pss-client";

import type { RunContext } from "../engine/context.ts";
import { expectRefused } from "../engine/machine.ts";
import { defineKind, refs, type Common } from "../engine/kind.ts";
import { big, check, poll, type Value } from "../engine/scope.ts";
import { tipContract, tipOf, methodsOf } from "../engine/tip.ts";
import { timed } from "../harness/harness.ts";
import { assetOf, awaitCredit, creditBalance, keepsCredits } from "./tip-fund.ts";
import type { OutcomeRecord } from "./tip-outcome.ts";

export interface RedeemStep extends Common {
  /** The opened outcome (a `tipOutcome` step's name): its note's last field
   * is the chain request id `redeem` takes. */
  redeem: string;
  /** The redeeming account: the note's owner. */
  from: string;
  /** By token contract (`<tip name>.<name>`), the amount the redeem pays
   * into the owner's private balance of it (0: the balance must not move). */
  pays?: Record<string, Value>;
  /** The redeem must be refused with a message holding every substring
   * (a second redeem of the same note), nothing sent. */
  refused?: string[];
}

/** The app's redeem function: `redeem(request_id)`. */
const REDEEM = "redeem";

/** What a transaction that repeats a nullifier already in the tree is
 * refused with: a substring of the node's and the PXE's messages. */
export const NULLIFIER_SEEN = "ullifier";

/** How long a token balance may lag the redeem's block in the owner's PXE. */
export const BALANCE_WAIT_MS = 60_000;


/** `account`'s private balance of the token contract `token` (its
 * `balance_of_private` utility, in the account's wallet). */
export async function privateBalance(ctx: RunContext, token: string, account: string): Promise<bigint> {
  const t = ctx.contract(token);
  const f = methodsOf(Contract.at(t.address, t.artifact, ctx.network.walletOf(account))).balance_of_private;
  check(f !== undefined, `${token} has no balance_of_private`);
  const owner = ctx.account(account);
  return big((await f(owner).simulate({ from: owner })).result);
}

/** Waits until `account`'s private balance of `token` is `want` (the PXE
 * finds a completed partial note once it has synced the block that
 * completed it), at most BALANCE_WAIT_MS; returns the last balance read. */
export async function awaitPrivateBalance(ctx: RunContext, token: string, account: string, want: bigint): Promise<bigint> {
  return (await poll(() => privateBalance(ctx, token, account), (got) => got === want, BALANCE_WAIT_MS)).value;
}

export default defineKind<RedeemStep>({
  key: "redeem",
  check(step, s) {
    refs.account(s, step.from);
    for (const t of Object.keys(step.pays ?? {})) refs.contract(s, t);
    check((step.pays === undefined) !== (step.refused === undefined), "a redeem takes what it pays (pays), or the substrings of its refusal (refused)");
    return { fields: ["redeem", "from", "pays", "refused"] };
  },
  async run(ctx, step) {
    const outcome = ctx.scope.lookup(step.redeem) as OutcomeRecord;
    const tip = tipOf(ctx, outcome.namespace);
    const label = step.what ?? `${step.redeem} redeem`;
    const owner = ctx.account(step.from);
    const app = tipContract(ctx, tip, step.from);
    const requestId = new Fr(big(outcome.note.packed.at(-1)!));
    const call = () => methodsOf(app)[REDEEM]!(requestId);
    const fee = await ctx.network.fee("redeem");
    if (step.refused) {
      const refusal = await expectRefused(label, step.refused, () => timed(ctx.logger, `tx ${label} (simulated)`, () => call().simulate({ ...fee, from: owner })), {
        accepted: "the redeem was accepted",
      });
      ctx.logger.info(`[refused] ${label}: ${step.from}'s PXE refused the redeem, nothing sent: ${refusal.split("\n")[0]}`);
      return;
    }
    const pays = Object.entries(step.pays!).map(([token, v]) => ({ token, amount: big(ctx.scope.resolve(v)) }));
    const credits = keepsCredits(tip);
    const read = (token: string) => (credits ? creditBalance(ctx, tip, step.from, assetOf(tip, token)) : privateBalance(ctx, token, step.from));
    const before = new Map<string, bigint>();
    for (const p of pays) before.set(p.token, await read(p.token));
    const { receipt } = await timed(ctx.logger, `tx ${label}: ${REDEEM}(${requestId}) from ${step.from}`, () => call().send({ ...fee, from: owner }));
    const effect = txEffectFrom(await ctx.network.node.getTxEffect(receipt.txHash as never));
    // the redeem pushed the note's redeem nullifier: the same redeem, simulated again on the block that
    // holds it, is refused for that nullifier (the note stays readable, so nothing else refuses it)
    await expectRefused(`${label}, simulated again`, [NULLIFIER_SEEN], () => call().simulate({ ...fee, from: owner }), {
      accepted: "the same redeem simulated again was accepted: the redeem pushed no redeem nullifier",
    });
    const moved: string[] = [];
    for (const p of pays) {
      const was = before.get(p.token)!;
      const now = credits ? await awaitCredit(ctx, tip, step.from, assetOf(tip, p.token), was + p.amount) : await awaitPrivateBalance(ctx, p.token, step.from, was + p.amount);
      check(now - was === p.amount, `${label}: ${step.from}'s private balance of ${p.token} moved ${was} -> ${now}, not by ${p.amount}`);
      moved.push(`${p.token} ${was} -> ${now}`);
    }
    ctx.logger.info(`${label}: ${step.from} redeemed its note of request ${requestId} in tx ${receipt.txHash} (${effect.nullifiers.length} nullifiers, ${effect.noteHashes.length} note hashes); private balances ${moved.join(", ")}`);
  },
  txs(ctx, step, sent) {
    const outcome = ctx.scope.lookup(step.redeem) as OutcomeRecord;
    return sent.map((txHash) => ({ kind: "redeem", txHash, round: outcome.circuit, deployment: outcome.namespace }));
  },
});
