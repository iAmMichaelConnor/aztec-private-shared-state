// A secret-shared intake's private outcome as its user reads it (docs/ARCHITECTURE.md
// section 6, "Private outcomes"): the note's owner finds the outcome log by
// the request's outcome tag (pss-client OutcomeReader), opens it with the
// request's outcome key, checks it is the landed round's (the note hash it
// carries the result's, the note rebuilt from it that hash, its transaction
// the one that finished the queue index) and hands its PXE the note through the app's outcome-note utility (pss-client
// outcomeDeliveryArgs; the library's `deliver_outcome`), which must then
// hold one more note of the owner's at the app's outcome slot. The note is
// the completion of the request's partial note, rebuilt with the request's
// rho and chain request id; its owner is the request's sender, behind the
// partial note. The owner's client keeps the note (engine/tip.ts keepNote)
// with the delivery handle the request left, if any. Binds the plaintext,
// the note and the transaction; `expect` checks the plaintext.
import type { AztecAddress } from "@aztec-labs/aztec.js/addresses";
import { Fr } from "@aztec-labs/aztec.js/fields";
import type { PXE } from "@aztec-labs/pxe/server";
import { OutcomeReader, outcomeDeliveryArgs, outcomeSlot, resultSummary, type FoundDelivery, type FoundOutcome } from "@aztec-pss/pss-client";

import type { RunContext } from "../engine/context.ts";
import { defineKind, refs, type Common } from "../engine/kind.ts";
import { big, check, type Expect } from "../engine/scope.ts";
import { finishing, keepNote, tipContract, tipOf, methodsOf, type HeldNote, type Tip } from "../engine/tip.ts";
import { timed } from "../harness/harness.ts";
import type { TipRequestRecord } from "./tip-request.ts";
import { fetchResult } from "./tip-result.ts";

export interface TipOutcomeStep extends Common {
  /** The secret-shared request's bound name (a `tipRequest` step's); its result
   * has landed (a `tipResult` step before). */
  tipOutcome: string;
  /** The note's owner: the request's sender, whose partial note it
   * committed. */
  owner: string;
  /** The app's view of an owner's notes, which must count one more after
   * the delivery (the AMM's `swap_notes(owner)`, lending's
   * `outcome_notes(owner)`, `{count, first}`). */
  notes?: string;
  /** Binds an OutcomeRecord. */
  name?: string;
  expect?: Expect[];
}

/** What a tipOutcome step binds: the kept note (its randomness the
 * request's rho), the note as rebuilt, and the round type. */
export interface OutcomeRecord extends HeldNote {
  note: FoundOutcome["note"];
  /** The request's circuit: the round type. */
  circuit: string;
}

/** The library's outcome-note utility. */
export const DELIVER = "deliver_outcome";

export default defineKind<TipOutcomeStep>({
  key: "tipOutcome",
  check(step, s) {
    refs.account(s, step.owner);
    check(typeof step.tipOutcome === "string", "tipOutcome names a request");
    return { fields: ["tipOutcome", "owner", "notes", "name", "expect"], binds: [step.name] };
  },
  async run(ctx, step) {
    const req = ctx.scope.lookup(step.tipOutcome) as TipRequestRecord;
    const label = step.what ?? `${step.tipOutcome} outcome`;
    const { tip, result, storageSlot, keys } = await outcomeAccess(ctx, req, step.owner, label);
    const found = await timed(ctx.logger, `${label}: find and open the outcome log (tag ${req.outcomeTag})`, () => new OutcomeReader(ctx.network.node, tip.address).read(req.outcomeTag!, keys));
    check(found !== undefined, `${label}: no outcome log under tag ${req.outcomeTag} on the chain`);
    // the log carries the completed note's hash, the landed result's, and
    // the note rebuilt from the request's keys is that note
    check(
      result.noteHashes !== undefined && BigInt(found.loggedNoteHash) === BigInt(result.noteHashes[0]!),
      `${label}: the outcome log carries note hash ${found.loggedNoteHash}, the landed result's is ${result.noteHashes?.[0]}`,
    );
    check(found.noteMatches, `${label}: the note rebuilt from the request's keys is ${found.note.noteHash}, the log's ${found.loggedNoteHash}`);
    const landing = await finishing(ctx, tip, req.index, req.block);
    check(BigInt(found.tx.txHash) === BigInt(landing.txHash), `${label}: the outcome log is in tx ${found.tx.txHash}, the result landed in ${landing.txHash}`);
    const { held: [heldBefore, heldAfter], counted: [before, after] } = await deliverAndCount(ctx, tip, step.owner, found, storageSlot, label, step.notes);
    ctx.logger.info(
      `${label}: ${step.owner} opened the outcome of ${req.chainRequestId} (machine request ${result.machineRequestId}, tx ${found.tx.txHash}) with its outcome key: ` +
        `[${found.plaintext.join(", ")}]; completed note ${found.note.noteHash} delivered, ${step.owner}'s PXE holds ${heldBefore} -> ${heldAfter} outcome notes${step.notes ? ` (${step.notes}: ${before} -> ${after})` : ""}`,
    );
    const record: OutcomeRecord = {
      plaintext: found.plaintext,
      note: found.note,
      tx: found.tx,
      namespace: tip.name,
      circuit: req.circuit,
      owner: step.owner,
      rho: keys.rho,
      requestId: req.chainRequestId,
      ...(req.handleKey !== undefined && req.handleRho !== undefined && { handle: { handleKey: req.handleKey, handleRho: req.handleRho } }),
    };
    keepNote(ctx, record);
    if (step.name) ctx.scope.set(step.name, record);
    if (step.expect) ctx.scope.expectAll(label, step.expect);
  },
});

/** What reading a secret-shared request's outcome takes, as `owner` (the
 * request's sender): its result (FETCH), the owner's address and app
 * contract, the app's outcome slot, the keys that open the outcome log, and
 * the delivery of its note through the app's outcome-note utility. */
export async function outcomeAccess(ctx: RunContext, req: TipRequestRecord, ownerName: string, label: string) {
  const tip = tipOf(ctx, req.namespace);
  check(req.outcomeKey !== undefined && req.outcomeTag !== undefined, `${label}: the request is not a secret-shared intake's (no outcome key)`);
  check(req.rho !== undefined, `${label}: the request committed no partial note`);
  check(req.from === ownerName, `${label}: the partial note is ${req.from}'s, not ${ownerName}'s`);
  const result = resultSummary((await fetchResult(ctx, tip, req, 60)).result);
  check(result.ciphertextLength !== undefined, `${label}: ${req.circuit}'s result is a ${result.form} result, not a private outcome`);
  const owner = ctx.account(ownerName);
  const app = tipContract(ctx, tip, ownerName);
  const view = async (f: string, ...args: unknown[]) => (await methodsOf(app)[f]!(...args).simulate({ from: owner })).result;
  // the app's slot of its notes, from its state view (`TipState.outcome_slot`)
  const storageSlot = await outcomeSlot(app, owner);
  const keys = {
    outcomeKey: req.outcomeKey,
    owner: owner.toField(),
    rho: req.rho,
    requestId: req.chainRequestId,
    storageSlot,
    plaintextLength: result.ciphertextLength - 1,
  };
  const deliver = async (found: FoundOutcome): Promise<void> => void (await view(DELIVER, ...outcomeDeliveryArgs(found)));
  return { tip, result, owner, view, storageSlot, keys, deliver };
}

/** Hands `found`'s note to `ownerName`'s PXE through the app's outcome-note
 * utility and checks the PXE (and the app's view `notes`, when given) holds
 * one more of the owner's notes at the outcome slot `storageSlot` after it;
 * returns the PXE's counts and the view's, before and after. */
export async function deliverAndCount(
  ctx: RunContext,
  tip: Tip,
  ownerName: string,
  found: FoundOutcome | FoundDelivery,
  storageSlot: bigint,
  label: string,
  notes?: string,
): Promise<{ held: [number, number]; counted: [number | undefined, number | undefined] }> {
  const owner = ctx.account(ownerName);
  const app = methodsOf(tipContract(ctx, tip, ownerName));
  const view = async (f: string, ...args: unknown[]) => (await app[f]!(...args).simulate({ from: owner })).result;
  const count = async () => (notes ? Number(big(((await view(notes, owner)) as { count: unknown }).count)) : undefined);
  const held = () => heldNotes(ctx, ownerName, tip.address, owner, storageSlot);
  const [before, heldBefore] = [await count(), await held()];
  await timed(ctx.logger, `${label}: ${DELIVER} into ${ownerName}'s PXE`, () => view(DELIVER, ...outcomeDeliveryArgs(found)));
  const [after, heldAfter] = [await count(), await held()];
  if (notes) check(after === before! + 1, `${label}: ${notes}(${ownerName}) counts ${after} notes after the delivery, ${before} before`);
  check(heldAfter === heldBefore + 1, `${label}: ${ownerName}'s PXE holds ${heldAfter} of its notes at ${tip.name}'s outcome slot after the delivery, ${heldBefore} before`);
  return { held: [heldBefore, heldAfter], counted: [before, after] };
}

/** How many active notes `owner`'s PXE holds at the app's outcome slot (the
 * PXE's debug note query; the app need not have a view of its own). */
export async function heldNotes(ctx: RunContext, account: string, app: AztecAddress, owner: AztecAddress, storageSlot: bigint): Promise<number> {
  const pxe = (ctx.network.walletOf(account) as unknown as { pxe: PXE }).pxe;
  return (await pxe.debug.getNotes({ contractAddress: app, owner, storageSlot: new Fr(storageSlot), scopes: [owner] })).length;
}
