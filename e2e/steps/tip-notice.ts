// A delivery to a standing handle, as its recipient reads it (the delivery
// handle brick: pss-client handle.ts; docs/ARCHITECTURE.md section 6, "The
// standing delivery handle"): an earlier request of the recipient's left a handle in its
// entry (its C committed `handle_partial` and `handle_key`), and a round
// another party requested completed it. The recipient computes the
// delivery's log tag from the handle's key and the delivering round's chain
// request id, finds the log under it (pss-client DeliveryReader), opens it
// with the handle's key, checks it is the delivering round's (its note hash
// among that result's deliveries, its transaction the one that finished
// that request's queue index, its request id that request's) and hands its
// PXE the note through the app's outcome-note utility under the handle's
// randomness, which must then hold one more note of the recipient's; its
// client keeps the note with the handle (engine/tip.ts keepNote). Binds the
// note's fields, its request id, the note and the transaction; `expect`
// checks them.
import { DeliveryReader, outcomeSlot, type FoundDelivery } from "@aztec-pss/pss-client";

import type { RunContext } from "../engine/context.ts";
import { defineKind, refs, type Common } from "../engine/kind.ts";
import { check, type Expect } from "../engine/scope.ts";
import { finishing, keepNote, tipContract, tipOf, type HeldNote, type Tip } from "../engine/tip.ts";
import { timed } from "../harness/harness.ts";
import type { TipRequestRecord } from "./tip-request.ts";
import { DELIVER, deliverAndCount } from "./tip-outcome.ts";
import { fetchResult } from "./tip-result.ts";

export interface TipNoticeStep extends Common {
  /** The recipient's earlier request (a `tipRequest` step's bound name)
   * whose handle the delivery completed. */
  tipNotice: string;
  /** The request (a bound name) whose landed result delivered it. */
  by: string;
  /** The recipient: the handle request's sender. */
  owner: string;
  /** The app's view of an owner's notes, which must count one more after
   * the delivery (lending's `outcome_notes(owner)`, `{count, first}`). */
  notes?: string;
  /** Binds a NoticeRecord. */
  name?: string;
  expect?: Expect[];
}

/** What a tipNotice (or tipRecover) step binds for a notice: the kept note
 * (its randomness the handle's) and the note as rebuilt. */
export interface NoticeRecord extends HeldNote {
  note: FoundDelivery["note"];
}

/** The outcome-note utility's argument of the packed note fields. */
const PACKED = "packed";

/** The handle's keys a delivery to `owner` is read with: the handle, the
 * app's outcome slot (its state view's), and the length of the packed note fields the app's
 * outcome-note utility takes (the request id last). */
export async function deliveryKeys(ctx: RunContext, tip: Tip, owner: string, handle: { handleKey: string; handleRho: string }) {
  const account = ctx.account(owner);
  const storageSlot = await outcomeSlot(tipContract(ctx, tip, owner), account);
  const deliver = ctx.contract(tip.name).artifact.functions.find((f) => f.name === DELIVER);
  const packed = deliver?.parameters.find((p) => p.name === PACKED)?.type;
  check(packed?.kind === "array", `${tip.name}: no ${DELIVER} with an array argument ${PACKED}`);
  return { handleKey: handle.handleKey, owner: account.toField(), handleRho: handle.handleRho, storageSlot, packedLength: packed.length };
}

/** Hands `owner`'s PXE the opened delivery `found` through the app's
 * outcome-note utility (deliverAndCount, at the keys' outcome slot) and
 * keeps the note with the handle it came under (the keys'). */
export async function deliverNotice(
  ctx: RunContext,
  tip: Tip,
  owner: string,
  found: FoundDelivery,
  keys: Awaited<ReturnType<typeof deliveryKeys>>,
  label: string,
  notes?: string,
): Promise<NoticeRecord> {
  const handle = { handleKey: keys.handleKey, handleRho: keys.handleRho };
  const { held: [heldBefore, heldAfter] } = await deliverAndCount(ctx, tip, owner, found, keys.storageSlot, label, notes);
  ctx.logger.info(
    `${label}: ${owner} opened the delivery of ${found.requestId} to its handle (tx ${found.tx.txHash}): [${found.plaintext.join(", ")}]; ` +
      `note ${found.note.noteHash} delivered, ${owner}'s PXE holds ${heldBefore} -> ${heldAfter} outcome notes`,
  );
  const record: NoticeRecord = {
    namespace: tip.name,
    owner,
    plaintext: found.plaintext,
    rho: handle.handleRho,
    requestId: found.requestId,
    tx: found.tx,
    handle,
    note: found.note,
  };
  keepNote(ctx, record);
  return record;
}

export default defineKind<TipNoticeStep>({
  key: "tipNotice",
  check(step, s) {
    refs.account(s, step.owner);
    check(typeof step.tipNotice === "string" && typeof step.by === "string", "tipNotice names the handle's request and `by` the delivering one");
    return { fields: ["tipNotice", "by", "owner", "notes", "name", "expect"], binds: [step.name] };
  },
  async run(ctx, step) {
    const req = ctx.scope.lookup(step.tipNotice) as TipRequestRecord;
    const by = ctx.scope.lookup(step.by) as TipRequestRecord;
    const tip = tipOf(ctx, req.namespace);
    const label = step.what ?? `${step.tipNotice}'s notice from ${step.by}`;
    check(req.handleKey !== undefined && req.handleRho !== undefined, `${label}: ${step.tipNotice} left no delivery handle`);
    check(req.from === step.owner, `${label}: the handle is ${req.from}'s, not ${step.owner}'s`);
    check(by.namespace === req.namespace, `${label}: ${step.by} is another deployment's request`);
    const fetched = (await fetchResult(ctx, tip, by, 60)).result;
    check(fetched.form === "outcome" && fetched.parts.deliveries.length > 0, `${label}: ${by.circuit}'s result carries no delivery`);
    const deliveries = fetched.form === "outcome" ? fetched.parts.deliveries : [];
    const handle = { handleKey: req.handleKey, handleRho: req.handleRho };
    const keys = await deliveryKeys(ctx, tip, step.owner, handle);
    const found = await timed(ctx.logger, `${label}: find and open the delivery log`, () => new DeliveryReader(ctx.network.node, tip.address).read(keys, by.chainRequestId));
    check(found !== undefined, `${label}: no delivery of ${step.by} under ${step.tipNotice}'s handle on the chain`);
    check(
      deliveries.some((d) => BigInt(d.noteHash) === BigInt(found.note.noteHash)),
      `${label}: the rebuilt note ${found.note.noteHash} is not among ${step.by}'s deliveries`,
    );
    check(BigInt(found.requestId) === BigInt(by.chainRequestId), `${label}: the note answers request ${found.requestId}, not ${step.by}'s ${by.chainRequestId}`);
    const landing = await finishing(ctx, tip, by.index, by.block);
    check(BigInt(found.tx.txHash) === BigInt(landing.txHash), `${label}: the delivery is in tx ${found.tx.txHash}, ${step.by}'s result landed in ${landing.txHash}`);
    const record = await deliverNotice(ctx, tip, step.owner, found, keys, label, step.notes);
    if (step.name) ctx.scope.set(step.name, record);
    if (step.expect) ctx.scope.expectAll(label, step.expect);
  },
});
