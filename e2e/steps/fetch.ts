// FETCH a round by request id; the answer must equal the round's.
import { checkAnswer, roundOf, same, type Round } from "../engine/answer.ts";
import { defineKind, type Common } from "../engine/kind.ts";
import { check, type Value } from "../engine/scope.ts";
import { timed } from "../harness/harness.ts";

export interface FetchStep extends Common {
  /** The round (a reference). */
  fetch: Value;
  /** The scope name of the fetched round. */
  name?: string;
  /** From a fresh client that knows only the request id. */
  fresh?: boolean;
}

export default defineKind<FetchStep>({
  key: "fetch",
  check: (step) => ({ fields: ["fetch", "name", "fresh"], binds: [step.name] }),
  async run(ctx, step) {
    const r = ctx.scope.resolve(step.fetch) as Round;
    const label = step.what ?? step.name ?? `FETCH ${r.circuit}`;
    const response = await timed(ctx.logger, `FETCH ${label} by request id${step.fresh ? " (a fresh client)" : ""}`, () =>
      ctx.client(r.namespace, step.fresh).fetch(r.requestId, { circuit: r.circuit }),
    );
    check(same(response, r.response), `${label}: FETCH returned another result than the round's`);
    const effects = await checkAnswer(ctx, label, r.circuit, r.namespace, r.input, r.requestId, response);
    ctx.logger.info(`${label}: FETCH returned the same proof, public inputs and result signatures`);
    if (step.name) ctx.scope.set(step.name, roundOf(r.circuit, r.namespace, r.input, r.requestId, response, effects));
  },
});
