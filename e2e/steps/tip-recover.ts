// An owner's recovery of the notices of rounds it did not request (the
// escape hatch's client side, pss-client hatch.ts recoverExitNote;
// docs/ARCHITECTURE.md section 6, "The escape hatch"), from the chain
// alone, with no node and no old state: from the owner's newest note of the
// position, while its exit tag is spent by a round that delivered to the
// position's handle, the library takes that delivery (a notice) as the
// newest note and goes on. The step hands each notice to the owner's PXE
// (deliver_outcome, as tipNotice does) and keeps it, and requires the walk
// to recover at least one notice and to end on a note whose tag is
// unspent: the note an exit takes. Binds {notices}, oldest first.
import { recoverExitNote } from "@aztec-pss/pss-client";

import { defineKind, refs, type Common } from "../engine/kind.ts";
import { big, check, type Expect, type Value } from "../engine/scope.ts";
import { exitNoteOf, notesOf, tipOf } from "../engine/tip.ts";
import { timed } from "../harness/harness.ts";
import { deliverNotice, deliveryKeys, type NoticeRecord } from "./tip-notice.ts";

export interface TipRecoverStep extends Common {
  /** The tip deployment. */
  tipRecover: string;
  /** The owner. */
  owner: string;
  /** The position whose notices it recovers. */
  position: Value;
  /** The field of the app's note plaintext that names its position (its
   * ExitNote entry). */
  entry: number;
  /** The app's view of an owner's notes, which must count one more after
   * each notice (lending's `outcome_notes(owner)`). */
  notes?: string;
  /** Binds {notices: NoticeRecord[]}, oldest first. */
  name?: string;
  expect?: Expect[];
}

export default defineKind<TipRecoverStep>({
  key: "tipRecover",
  check(step, s) {
    refs.tip(s, step.tipRecover);
    refs.account(s, step.owner);
    check(Number.isSafeInteger(step.entry) && step.entry >= 0, `entry: ${step.entry} is not a plaintext field`);
    return { fields: ["tipRecover", "owner", "position", "entry", "notes", "name", "expect"], binds: [step.name] };
  },
  async run(ctx, step) {
    const tip = tipOf(ctx, step.tipRecover);
    const position = big(ctx.scope.resolve(step.position));
    const label = step.what ?? `${step.owner}'s recovery of position ${position}`;
    let [newest] = await notesOf(ctx, tip, step.owner, step.entry, position);
    check(newest !== undefined, `${label}: ${step.owner} keeps no note of position ${position} in ${tip.name}`);
    const handle = newest.handle;
    const keys = handle && (await deliveryKeys(ctx, tip, step.owner, handle));
    const notices: NoticeRecord[] = [];
    const walked = await timed(ctx.logger, `${label}: recoverExitNote from the note of request ${newest.requestId}`, () =>
      recoverExitNote({
        node: ctx.network.node,
        app: tip.address,
        note: exitNoteOf(ctx, newest!, position),
        handle: keys,
        entryField: step.entry,
        onNotice: async (found) => {
          ctx.logger.info(`${label}: the tag of ${step.owner}'s note of request ${newest!.requestId} was spent by tx ${found.tx.txHash}, the landing of request ${found.requestId}`);
          const notice = await deliverNotice(ctx, tip, step.owner, found, keys!, `${label}: notice of ${found.requestId}`, step.notes);
          notices.push(notice);
          newest = notice;
        },
      }),
    );
    if (walked.status === "spent-by-owner") {
      const { note, spent } = walked;
      check(false, `${label}: the tag of the note of request ${note.requestId} was spent in block ${spent.block} by tx ${spent.tx.txHash}, which holds no delivery to its handle (an exit or a round of ${step.owner}'s own)`);
    }
    check(notices.length > 0, `${label}: the tag of ${step.owner}'s newest note of position ${position} (request ${newest.requestId}) is unspent: nothing to recover`);
    ctx.logger.info(`${label}: ${notices.length} notice(s) recovered from the spent tags, the newest of request ${newest.requestId} live: [${newest.plaintext.join(", ")}]`);
    if (step.name) ctx.scope.set(step.name, { notices });
    if (step.expect) ctx.scope.expectAll(label, step.expect);
  },
});
