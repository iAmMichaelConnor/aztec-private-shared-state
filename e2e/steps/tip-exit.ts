// An owner's exit from a frozen market through the escape hatch
// (pss_public_contract hatch.nr; examples/lending-tip/README.md, "The escape hatch"),
// privately and with no node: the owner's client takes its notes of the
// position, newest first (the outcomes and notices its tipOutcome,
// tipNotice and tipRecover steps opened), finds the newest whose exit tag is
// unspent in the node's nullifier tree (pss-client liveExitNote) and calls
// the app's exit function (the step's `exit`, `(position, request_id)`)
// with that note's request id, a private-only transaction that spends the
// tag. The notes of the position are those whose plaintext field `entry`
// (the app's: pss-client ExitNote's entry field) is the position. What the note is owed is
// settled in the owner's credit, privately (a borrower note repays its debt
// y from the credit and is credited its collateral x, a lender note is
// credited its value y): by token (`<tip>.<name>`, an asset of the
// deployment's credit), the credit must grow by `pays` and fall by `repays`. Or the exit refused,
// nothing sent: on the named `note` (a stale note, whose tag a later round
// spent), or else on the live note (an exit before the hatch opened), or
// with no live note on the newest (a second exit). Binds {tag, requestId,
// position}.
import { Fr } from "@aztec-labs/aztec.js/fields";
import { exitTagOf, exitTagSpentAt, fieldHex, liveExitNote } from "@aztec-pss/pss-client";

import { expectRefused } from "../engine/machine.ts";
import { defineKind, refs, type Common } from "../engine/kind.ts";
import { big, check, type Expect, type Value } from "../engine/scope.ts";
import { exitNoteOf, notesOf, tipContract, tipOf, methodsOf, type HeldNote } from "../engine/tip.ts";
import { timed } from "../harness/harness.ts";
import { assetOf, awaitCredit, creditBalance } from "./tip-fund.ts";

export interface TipExitStep extends Common {
  /** The tip deployment. */
  tipExit: string;
  /** The exiting account: the notes' owner. */
  from: string;
  /** The position it exits. */
  position: Value;
  /** The app's exit function, called as `(position, request_id)`. */
  exit: string;
  /** The field of the app's note plaintext that names its position (its
   * ExitNote entry). */
  entry: number;
  /** Exit on this note (a tipOutcome or tipNotice step's name, or a
   * tipRecover step's `$<name>.notices[k]`) instead of the newest live one:
   * the exit must be refused. */
  note?: Value;
  /** By token, how much the owner's credit of its asset grows. */
  pays?: Record<string, Value>;
  /** By token, how much it falls (a borrower note's debt repaid). */
  repays?: Record<string, Value>;
  /** The exit must be refused with a message holding every substring. */
  refused?: string[];
  /** Binds {tag, requestId, position}: the exit tag the exit pushes (or
   * would push), the note's request id and the position. */
  name?: string;
  /** Checked after the binding, before the exit is sent. */
  expect?: Expect[];
}

export default defineKind<TipExitStep>({
  key: "tipExit",
  check(step, s) {
    refs.tip(s, step.tipExit);
    refs.account(s, step.from);
    for (const t of [...Object.keys(step.pays ?? {}), ...Object.keys(step.repays ?? {})]) refs.contract(s, t);
    const paying = step.pays !== undefined || step.repays !== undefined;
    check(paying !== (step.refused !== undefined), "an exit takes what it pays (pays, repays), or the substrings of its refusal (refused)");
    check(step.note === undefined || step.refused !== undefined, "an exit on a named note is a refused one");
    check(Number.isSafeInteger(step.entry) && step.entry >= 0, `entry: ${step.entry} is not a plaintext field`);
    return { fields: ["tipExit", "from", "position", "exit", "entry", "note", "pays", "repays", "refused", "name", "expect"], binds: [step.name] };
  },
  async run(ctx, step) {
    const tip = tipOf(ctx, step.tipExit);
    const position = big(ctx.scope.resolve(step.position));
    const label = step.what ?? `${step.from}'s exit of position ${position}`;
    const owner = ctx.account(step.from);
    const node = ctx.network.node;
    // the client side, with none of the PSS nodes: its notes of the position, newest first, and the live one
    const notes = (await notesOf(ctx, tip, step.from, step.entry, position)).map((n) => exitNoteOf(ctx, n, position));
    check(notes.length > 0, `${label}: ${step.from} keeps no note of position ${position} in ${tip.name}`);
    const live = await liveExitNote(node, tip.address, notes);
    const named = step.note === undefined ? undefined : (ctx.scope.resolve(step.note) as HeldNote);
    if (named !== undefined) check(named.namespace === tip.name && named.owner === step.from, `${label}: the named note is not ${step.from}'s in ${tip.name}`);
    const note = named !== undefined ? exitNoteOf(ctx, named, position) : (live ?? notes[0]!);
    const tag = await exitTagOf(note);
    const spentAt = await exitTagSpentAt(node, tip.address, tag);
    ctx.logger.info(
      `${label}: ${notes.length} note(s) of the position; ${live ? `the live one is request ${live.requestId}'s` : "every tag is spent"}; ` +
        `exiting on request ${note.requestId}'s note, its tag ${tag} ${spentAt === undefined ? "unspent" : `spent in block ${spentAt}`}`,
    );
    if (step.name) ctx.scope.set(step.name, { tag: fieldHex(tag.toBigInt()), requestId: note.requestId, position });
    if (step.expect) ctx.scope.expectAll(label, step.expect);
    const app = tipContract(ctx, tip, step.from);
    const exit = methodsOf(app)[step.exit];
    check(exit !== undefined, `${label}: ${tip.name} has no method ${step.exit}`);
    const call = () => exit(new Fr(position), new Fr(big(note.requestId)));
    const fee = await ctx.network.fee("exit");
    if (step.refused) {
      const refusal = await expectRefused(label, step.refused, () => timed(ctx.logger, `tx ${label} (simulated)`, () => call().simulate({ ...fee, from: owner })), {
        accepted: "the exit was accepted",
      });
      ctx.logger.info(`[refused] ${label}: refused, nothing sent: ${refusal.split("\n")[0]}`);
      return;
    }
    check(live !== undefined, `${label}: every tag of ${step.from}'s ${notes.length} note(s) of the position is spent (a round it did not request replaced the newest: recover its notice first)`);
    const moves = new Map<string, bigint>();
    for (const [token, v] of Object.entries(step.pays ?? {})) moves.set(token, (moves.get(token) ?? 0n) + big(ctx.scope.resolve(v)));
    for (const [token, v] of Object.entries(step.repays ?? {})) moves.set(token, (moves.get(token) ?? 0n) - big(ctx.scope.resolve(v)));
    const before = new Map<string, bigint>();
    for (const token of moves.keys()) before.set(token, await creditBalance(ctx, tip, step.from, assetOf(tip, token)));
    const { receipt } = await timed(ctx.logger, `tx ${label}: ${step.exit}(${position}, ${note.requestId})`, () => call().send({ ...fee, from: owner }));
    const at = await exitTagSpentAt(node, tip.address, tag);
    check(at === receipt.blockNumber, `${label}: the exit's block is ${receipt.blockNumber}, the note's tag ${at === undefined ? "is unspent" : `was spent in block ${at}`}`);
    const moved: string[] = [];
    for (const [token, amount] of moves) {
      const was = before.get(token)!;
      const now = await awaitCredit(ctx, tip, step.from, assetOf(tip, token), was + amount);
      check(now - was === amount, `${label}: ${step.from}'s credit of ${token} moved ${was} -> ${now}, not by ${amount}`);
      moved.push(`${token} ${was} -> ${now}`);
    }
    ctx.logger.info(`${label}: exited in tx ${receipt.txHash}, which spent the note's tag; its credit ${moved.join(", ")}`);
  },
  txs(ctx, step, sent) {
    return sent.map((txHash) => ({ kind: "exit", txHash, round: "exit", deployment: tipOf(ctx, step.tipExit).name }));
  },
});
