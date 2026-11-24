// A keeper's pass over a tip deployment's tree key (docs/ARCHITECTURE.md
// section 6, "A read-only window on a tree key"), planned by pss-client's
// keeperPass from scan outcomes the scenario opened: the loop's shape from
// the deployment's scan and act manifests (keeperShape), each scan the pass
// asks for answered by the opened outcome of the scan at that start (a
// `tipOutcome` step's binding) and read at the app's scan layout (the
// step's `layout`, pss-client's ScanLayout), and the act rounds it hands over recorded
// rather than sent, so the scenario sends them as its own requests
// (`$<name>.acts[i].inputs.<input>`). A pass that asks for a window no
// outcome answers fails, naming the start. Binds {scanned, reported, acts,
// stop, code}; `expect` checks it.
import { isQueued, keeperPass, keeperShape, scanReport, type ActRound, type KeeperPass, type ScanLayout } from "@aztec-pss/pss-client";

import { defineKind, refs, type Common } from "../engine/kind.ts";
import { check, type Expect } from "../engine/scope.ts";
import type { Scenario } from "../scenario.ts";
import type { OutcomeRecord } from "./tip-outcome.ts";

export interface KeeperStep extends Common {
  /** By window start, the bound name of that scan's opened outcome. */
  keeper: Record<string, string>;
  /** The tip deployment (default: the scenario's first). */
  namespace?: string;
  /** The scan round's package and the act round's. */
  scan: string;
  act: string;
  /** Where the app's scan outcome holds its report (pss-client `ScanLayout`). */
  layout: ScanLayout;
  /** The first window's start (default 0). */
  from?: number;
  /** Binds the pass (pss-client `KeeperPass`). */
  name?: string;
  expect?: Expect[];
}

export default defineKind<KeeperStep>({
  key: "keeper",
  check(step: KeeperStep, s: Scenario) {
    refs.tip(s, step.namespace);
    check(Object.keys(step.keeper).length > 0, "a keeper step takes at least one scan outcome");
    for (const k of Object.keys(step.keeper)) check(/^(0|[1-9][0-9]*)$/.test(k), `keeper.${k}: not a window start`);
    return { fields: ["keeper", "namespace", "scan", "act", "layout", "from", "name", "expect"], binds: [step.name] };
  },
  async run(ctx, step) {
    const label = step.what ?? step.name ?? "keeper pass";
    const config = ctx.client(ctx.namespace(step.namespace)).config;
    const [scan, act] = [config.manifests[step.scan], config.manifests[step.act]];
    check(scan !== undefined && isQueued(scan) && act !== undefined && isQueued(act), `${label}: ${step.scan} and ${step.act} are not tip packages of the deployment`);
    const shape = keeperShape(scan, act);
    const sent: ActRound[] = [];
    const pass: KeeperPass = await keeperPass({
      shape,
      from: step.from,
      async scan(start) {
        const name = step.keeper[String(start)];
        check(name !== undefined, `${label}: the pass asks for the scan at ${start}, which no outcome answers`);
        return scanReport((ctx.scope.lookup(name) as OutcomeRecord).plaintext, step.layout);
      },
      async act(round) {
        sent.push(round);
      },
    });
    ctx.logger.info(
      `${label}: windows ${pass.scanned.join(", ")} of ${shape.width} scanned, reported [${pass.reported.join(", ")}], ` +
        `${sent.length} act rounds (${sent.map((round) => `[${round.indices.join(", ")}]`).join(" ") || "none"}), stopped at the ${pass.stop}${pass.code === undefined ? "" : ` (code ${pass.code})`}`,
    );
    if (step.name) ctx.scope.set(step.name, pass);
    if (step.expect) ctx.scope.expectAll(label, step.expect);
  },
});
