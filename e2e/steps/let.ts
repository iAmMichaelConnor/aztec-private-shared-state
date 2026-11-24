// Computed values, bound in the scope in order.
import { defineKind, type Common } from "../engine/kind.ts";
import type { Expr } from "../engine/scope.ts";

export interface LetStep extends Common {
  let: Record<string, Expr>;
}

export default defineKind<LetStep>({
  key: "let",
  check: (step) => ({ fields: ["let"], binds: Object.keys(step.let) }),
  async run(ctx, step) {
    for (const [k, e] of Object.entries(step.let)) ctx.scope.set(k, await ctx.scope.evaluate(e));
  },
});
