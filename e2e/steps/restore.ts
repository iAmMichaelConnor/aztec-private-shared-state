// Roll a committed round back on every node over the admin sockets; its FETCH then answers 409.
import type { Round } from "../engine/answer.ts";
import { defineKind, type Common } from "../engine/kind.ts";
import { check, type Value } from "../engine/scope.ts";
import { timed } from "../harness/harness.ts";

export interface RestoreStep extends Common {
  /** The round (a reference). */
  restore: Value;
}

// The rollback demonstration. A committed round whose
// transaction is never sent leaves the node-held row ahead of the chain; the
// operator runs `restore` for that request id on all three nodes (node 0
// first; each node restores independently and the order between nodes does
// not matter, only the reverse commit order between requests). The driver
// reaches the admin sockets because it runs as the nodes' OS user on their
// host; a deployment runs `sidecar-node restore` on each host.
export default defineKind<RestoreStep>({
  key: "restore",
  check: () => ({ fields: ["restore"] }),
  async run(ctx, step) {
    const r = ctx.scope.resolve(step.restore) as Round;
    const label = step.what ?? `the ${r.circuit} round ${r.requestId}`;
    const client = ctx.client(r.namespace);
    check((await client.fetch(r.requestId)).proof === r.response.proof, `${label}: FETCH returned another proof`);
    ctx.logger.info(`${label}: committed at the nodes (FETCH answers it); its transaction is never sent`);
    for (let i = 0; i < 3; i++) {
      const answer = await timed(ctx.logger, `admin restore on node ${i}`, () => ctx.machine.admin(i, { op: "restore", namespace: ctx.nsValue(r.namespace), request_id: r.requestId }));
      check(answer.ok === true, `node ${i} refused the restore: ${JSON.stringify(answer.refusal)}`);
      ctx.logger.info(`node ${i}: request ${r.requestId} rolled back`);
    }
    await ctx.machine.expectRefusal(`FETCH of ${label}, rolled back`, { class: "conflict", status: 409, mentions: ["rolled back"] }, () => client.fetch(r.requestId));
  },
});
