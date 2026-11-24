// A log line (references and templates allowed).
import { defineKind, type Common } from "../engine/kind.ts";

export interface LogStep extends Common {
  log: string;
}

export default defineKind<LogStep>({
  key: "log",
  check: () => ({ fields: ["log"] }),
  async run(ctx, step) {
    ctx.logger.info(String(ctx.scope.resolve(step.log)));
  },
});
