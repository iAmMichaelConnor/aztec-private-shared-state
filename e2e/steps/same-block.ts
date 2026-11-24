// Tip requests that land in one block: each is built and proved as a
// `tipRequest` step would, one after another, the wallets' submissions are
// held until every one is proved and then sent to the node together, with the local network's
// sequencer set to build no block of fewer transactions for that moment.
// The queue order inside the block is the chain's, and decides which
// request runs on which state.
import { defineKind, type Common } from "../engine/kind.ts";
import { check } from "../engine/scope.ts";
import { minTxsPerBlock, setMinTxsPerBlock } from "../engine/tip.ts";
import { checkRequest, checkRequestStep, sendRequest, type NewTipRequest } from "./tip-request.ts";

export interface SameBlockStep extends Common {
  /** The requests, new ones only (no `again`). */
  sameBlock: NewTipRequest[];
  /** Names bound to the requests in queue order, the first queued first. */
  as?: string[];
}

// How two requests are put in one block: the driver holds the
// wallets' submissions until all are proved, sets the sequencer's
// minTxsPerBlock (the local network's admin API) to their number, submits
// them at once and restores the old value when all are mined, also on a
// failure. Why: the node verifies each proof on submission, so two
// transactions sent together reach the pool apart, and the local network's
// automine sequencer builds a block as soon as one transaction is ready.
// Consequences: no other transaction may be sent meanwhile (a relayer's
// would make up the count and leave a request alone in the pool until the
// value is restored), so the step runs on idle queues only. The requests
// are proved one at a time (each starts once the one before it is held):
// the wallets of one driver process share bb.js's backend, and two client
// proofs at once interleave on it ("No circuit loaded. Call ChonkLoad
// first").
export default defineKind<SameBlockStep>({
  key: "sameBlock",
  check(step, s) {
    check(step.sameBlock.length >= 2, "sameBlock takes at least two requests");
    const binds: (string | undefined)[] = [...(step.as ?? [])];
    for (const r of step.sameBlock) {
      check(r.again === undefined, "sameBlock takes new requests only");
      binds.push(...(checkRequestStep(r, s).binds ?? []));
    }
    if (step.as) check(step.as.length === step.sameBlock.length, `as names ${step.as.length} requests, sameBlock has ${step.sameBlock.length}`);
    return { fields: ["sameBlock", "as"], binds };
  },
  async run(ctx, step) {
    const label = step.what ?? "sameBlock";
    const n = step.sameBlock.length;
    const restore = await minTxsPerBlock();
    const held = ctx.network.holdNextTxs(n, async () => {
      await setMinTxsPerBlock(n);
      ctx.logger.info(`${label}: ${n} requests proved; sequencer minTxsPerBlock ${restore} -> ${n}, submitting them together`);
    });
    let sent;
    try {
      const pending = [];
      for (const [k, r] of step.sameBlock.entries()) {
        const p = sendRequest(ctx, r);
        pending.push(p);
        if (k < n - 1) await Promise.race([held(k + 1), p]);
      }
      sent = await Promise.all(pending);
    } finally {
      await setMinTxsPerBlock(restore);
    }
    const blocks = new Set(sent.map((s) => s.block));
    check(blocks.size === 1, `${label}: the requests landed in blocks ${[...blocks].join(", ")}, not one`);
    const records = [];
    for (const s of sent) records.push(await checkRequest(ctx, s));
    records.sort((a, b) => a.index - b.index);
    for (const [k, name] of (step.as ?? []).entries()) ctx.scope.set(name, records[k]);
    ctx.logger.info(`${label}: ${n} requests in block ${sent[0]!.block}, queued in the order ${records.map((r) => `${r.from} (index ${r.index})`).join(", ")}`);
  },
  // submitted in the order proved, the steps' order
  txs: (ctx, step, sent) => sent.map((txHash, k) => ({ kind: "request", txHash, round: step.sameBlock[k]?.tipRequest, deployment: ctx.namespace(step.sameBlock[k]?.namespace) })),
});
