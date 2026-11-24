// The scheduler's attempt at a queued request before anyone lands it
// (docs/ARCHITECTURE.md section 6, the scheduler): FETCH by chain request id
// answers the latest attempt the nodes committed; with `after`, the step
// waits for one under another machine request id, the recompute (a pinned
// value no longer admitted makes the scheduler discard the attempt and run
// the round again). `recomputed` checks how many recomputes of the request
// the orchestrator logged so far. Run it with the deployment's relayer
// stopped, or the attempt may land meanwhile. The bound attempt keeps the
// result FETCH answered, so a later step can land that very attempt (a held
// result) after the nodes have moved on to another.
import { sleep, type QueuedResult } from "@aztec-pss/pss-client";

import { readFileSync } from "node:fs";
import { join } from "node:path";

import { defineKind, type Common } from "../engine/kind.ts";
import { big, check, type Expect, type Value } from "../engine/scope.ts";
import { tipOf } from "../engine/tip.ts";
import { timed } from "../harness/harness.ts";
import type { TipRequestRecord } from "./tip-request.ts";
import { fetchResult } from "./tip-result.ts";

export interface TipAttemptStep extends Common {
  /** The request's bound name (a `tipRequest` step's). */
  tipAttempt: string;
  /** Wait for an attempt under another machine request id than this one. */
  after?: Value;
  /** How many recomputes of the request the orchestrator has logged. */
  recomputed?: number;
  /** Binds an AttemptRecord. */
  name?: string;
  expect?: Expect[];
  /** How long to wait; default 1800 s. */
  timeoutS?: number;
}

/** What a tipAttempt step binds. */
export interface AttemptRecord {
  machineRequestId: string;
  reads: string[];
  oldCommitments: string[];
  recomputed: number;
  /** The answer itself: the attempt's result, as a lander sends it. */
  result: QueuedResult;
}

/** The orchestrator's line for a held attempt it discards and recomputes
 * (sidecar-orchestrator scheduler.rs). */
const RECOMPUTING = "a pinned value is no longer admitted; recomputing";

/** How many recomputes of chain request `id` the orchestrator logged. */
function recomputes(runDir: string, id: string): number {
  const log = readFileSync(join(runDir, "logs", "orchestrator.log"), "utf8");
  return log.split("\n").filter((l) => l.includes(RECOMPUTING) && /chain_request_id=(0x[0-9a-fA-F]+)/.test(l) && BigInt(l.match(/chain_request_id=(0x[0-9a-fA-F]+)/)![1]!) === BigInt(id)).length;
}

export default defineKind<TipAttemptStep>({
  key: "tipAttempt",
  check(step) {
    check(step.recomputed === undefined || (Number.isInteger(step.recomputed) && step.recomputed >= 0), "recomputed is a count");
    return { fields: ["tipAttempt", "after", "recomputed", "name", "expect", "timeoutS"], binds: [step.name] };
  },
  async run(ctx, step) {
    const req = ctx.scope.lookup(step.tipAttempt) as TipRequestRecord;
    const tip = tipOf(ctx, req.namespace);
    const label = step.what ?? `${step.tipAttempt} attempt`;
    const timeoutS = step.timeoutS ?? 1800;
    const after = step.after === undefined ? undefined : big(ctx.scope.resolve(step.after));
    const deadline = Date.now() + timeoutS * 1000;
    const result = await timed(ctx.logger, `${label}: FETCH until the scheduler's ${after === undefined ? "attempt" : "recompute"} answers`, async () => {
      for (;;) {
        const { result: r } = await fetchResult(ctx, tip, req, timeoutS);
        if (after === undefined || BigInt(r.parts.machineRequestId) !== after) return r;
        check(Date.now() < deadline, `${label}: FETCH still answers machine request ${r.parts.machineRequestId} after ${timeoutS} s`);
        await sleep(2_000);
      }
    });
    const head = (await tip.queue.snapshot()).head;
    check(head <= req.index, `${label}: index ${req.index} is already finished (head ${head}); stop the relayer first`);
    const count = recomputes(ctx.harness.runDir, req.chainRequestId);
    if (step.recomputed !== undefined) check(count === step.recomputed, `${label}: the orchestrator logged ${count} recomputes of ${req.chainRequestId}, expected ${step.recomputed}`);
    const p = result.parts;
    ctx.logger.info(`${label}: the scheduler's attempt at index ${req.index} is machine request ${p.machineRequestId}, pinned [${p.reads.join(", ")}], on ${p.oldCommitments.join(", ")}; ${count} recompute(s) logged`);
    const record: AttemptRecord = { machineRequestId: p.machineRequestId, reads: p.reads, oldCommitments: p.oldCommitments, recomputed: count, result };
    if (step.name) ctx.scope.set(step.name, record);
    if (step.expect) ctx.scope.expectAll(label, step.expect);
  },
});
