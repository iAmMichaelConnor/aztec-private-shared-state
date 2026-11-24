// Empty blocks mined on the local network (its debug API): a number of
// them, or until the head of a tip deployment's queue is stale, at or past
// head_since + stale_blocks, so a skip() sent next lands; or a warp of its
// L2 time by at least a number of seconds (one empty block at the later
// time), past a delayed change such as a circuit upgrade's.
import { defineKind, refs, type Common } from "../engine/kind.ts";
import { check } from "../engine/scope.ts";
import { mineBlock, tipOf, warpL2Time } from "../engine/tip.ts";

export interface AdvanceStep extends Common {
  advance: number | "until-stale" | { warp: number };
  /** With `until-stale`: the tip deployment (default: the scenario's first). */
  namespace?: string;
}

export default defineKind<AdvanceStep>({
  key: "advance",
  check(step, s) {
    const warp = typeof step.advance === "object" ? step.advance.warp : undefined;
    check(
      step.advance === "until-stale" || (Number.isInteger(step.advance) && (step.advance as number) > 0) || (Number.isInteger(warp) && warp! > 0),
      "advance takes a positive number of blocks, until-stale or {warp: seconds}",
    );
    if (step.advance === "until-stale") refs.tip(s, step.namespace);
    else check(step.namespace === undefined, "a number of blocks or a warp takes no namespace");
    return { fields: ["advance", "namespace"] };
  },
  async run(ctx, step) {
    const start = await ctx.network.node.getBlockNumber();
    if (typeof step.advance === "object") {
      const time = async () => (await ctx.network.node.getBlockData("latest" as never))?.header.globalVariables.timestamp ?? 0n;
      const before = await time();
      await warpL2Time(ctx, step.advance.warp);
      const after = await time();
      check(after >= before + BigInt(step.advance.warp), `${step.what ?? "warp"}: L2 time ${before} -> ${after}, less than ${step.advance.warp} s`);
      ctx.logger.info(`${step.what ?? "warp"}: L2 time ${before} -> ${after} (at least ${step.advance.warp} s), block ${start} -> ${await ctx.network.node.getBlockNumber()}`);
      return;
    }
    if (step.advance !== "until-stale") {
      for (let i = 0; i < step.advance; i++) await mineBlock(ctx);
      ctx.logger.info(`${step.what ?? "advance"}: ${step.advance} empty blocks, ${start} -> ${await ctx.network.node.getBlockNumber()}`);
      return;
    }
    const tip = tipOf(ctx, step.namespace);
    const stale = tip.d.staleBlocks;
    check(stale !== null, `${tip.name}: skipping is disabled (stale_blocks null)`);
    for (let mined = 0; ; mined++) {
      const s = await tip.queue.snapshot();
      check(s.head < s.tail, `${tip.name}: the queue is empty, no head to go stale`);
      if (s.block >= s.headSince + stale) {
        ctx.logger.info(`${step.what ?? "mine"}: ${mined} empty blocks; ${tip.name}'s head ${s.head} (since block ${s.headSince}) is stale at block ${s.block} (stale_blocks ${stale})`);
        return;
      }
      check(mined <= stale + 10, `${tip.name}: the head is not stale after ${mined} empty blocks`);
      await mineBlock(ctx);
    }
  },
});
