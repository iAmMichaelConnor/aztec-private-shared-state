// DISABLE a registered circuit.
import type { OwnerKey } from "@aztec-pss/pss-client";

import { defineKind, refs, type Common } from "../engine/kind.ts";
import { check } from "../engine/scope.ts";
import { timed } from "../harness/harness.ts";

export interface DisableStep extends Common {
  disable: string;
  /** The seq the DISABLE must answer. */
  seq: number;
  /** The owner key (default `owner`). */
  by?: string;
  /** One of the scenario's namespaces (default: its first). */
  namespace?: string;
}

export default defineKind<DisableStep>({
  key: "disable",
  check(step, s) {
    refs.key(s, step.by ?? "owner", "owner");
    refs.namespace(s, step.namespace);
    return { fields: ["disable", "seq", "by", "namespace"] };
  },
  async run(ctx, step) {
    const ns = ctx.namespace(step.namespace);
    const answer = await timed(ctx.logger, `DISABLE ${step.disable}`, () => ctx.client(ns).disable(ctx.nsValue(ns), step.disable, ctx.key<OwnerKey>(step.by ?? "owner")));
    const pinned = ctx.pins(ns).vk[step.disable];
    check(answer.disabled && answer.seq === step.seq && answer.vk_hash === pinned, `DISABLE answered ${JSON.stringify({ ...answer, signatures: undefined })}`);
    ctx.logger.info(`DISABLE ${step.disable}: seq ${answer.seq}, disabled, 3 node signatures verified`);
  },
});
