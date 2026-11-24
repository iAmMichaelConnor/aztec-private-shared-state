// A tip deployment's init round, which the scheduler sent once configure
// landed and the relayer landed before anything was queued (harness/tip.ts
// init waited for it): the client's FETCH by the init's fixed chain request
// id answers the round, every slot it creates holds its new commitment, the
// relayer's own transaction (its GET /status names it) wrote them and logged
// nothing, and the queue is empty.
import { defineKind, refs, type Common } from "../engine/kind.ts";
import { check } from "../engine/scope.ts";
import { leafOf, minedTx, relayerInit, relayerStatus, storageAt, tipOf } from "../engine/tip.ts";

export interface TipInitStep extends Common {
  /** The tip deployment. */
  tipInit: string;
  /** Binds {txHash, block, newCommitments}. */
  name?: string;
}

export default defineKind<TipInitStep>({
  key: "tipInit",
  check(step, s) {
    refs.tip(s, step.tipInit);
    return { fields: ["tipInit", "name"], binds: [step.name] };
  },
  async run(ctx, step) {
    const tip = tipOf(ctx, step.tipInit);
    const label = step.what ?? `${tip.name} init`;
    const init = relayerInit(tip);
    check(init !== undefined, `${label}: the deployment has no init round`);
    const txHash = tip.d.initTx;
    check(txHash !== undefined, `${label}: harness.json records no init transaction of the relayer`);
    // the relayer reports the landing as its own transaction (GET /status), the one harness.json records
    const { init: landed } = await relayerStatus(tip);
    check(landed?.state === "landed" && landed.tx !== undefined && BigInt(landed.tx) === BigInt(txHash), `${label}: the relayer reports ${JSON.stringify(landed)}, not landing init tx ${txHash}`);
    const { parts, chainRequestId } = await ctx.client(tip.name).fetchInitResult({ circuit: init.circuit, inputs: init.inputs });
    const receipt = await ctx.network.node.getTxReceipt(txHash as never);
    check(receipt.blockNumber !== undefined && receipt.hasExecutionSucceeded(), `${label}: init tx ${txHash} is not mined and successful (${receipt.status})`);
    const block = Number(receipt.blockNumber);
    const tx = await minedTx(ctx, tip, txHash, block);
    check(tx.logs.length === 0, `${label}: the init logged ${tx.logs.length} public logs; node-held state logs nothing`);
    for (const [k, slot] of parts.slots.entries()) {
      const want = parts.newCommitments[k]!;
      check((await storageAt(ctx, tip, slot)) === want, `${label}: slot ${slot} does not hold the init's commitment ${want}`);
      check(tx.writes.get(await leafOf(tip, slot)) === BigInt(want), `${label}: init tx ${txHash} did not write slot ${slot}`);
    }
    const q = await tip.queue.snapshot();
    check(q.head === 0 && q.tail === 0, `${label}: the queue is not empty (head ${q.head}, tail ${q.tail})`);
    ctx.logger.info(
      `${label}: ${init.circuit} (init id ${chainRequestId}) landed by the relayer through ${init.method} in tx ${txHash} (block ${block}): ` +
        `${parts.slots.map((s, k) => `slot ${s} = ${parts.newCommitments[k]}`).join(", ")}, no log, queue empty`,
    );
    if (step.name) ctx.scope.set(step.name, { txHash, block, newCommitments: parts.newCommitments });
  },
  txs(ctx, step) {
    const tip = tipOf(ctx, step.tipInit);
    return tip.d.initTx ? [{ kind: "init", txHash: tip.d.initTx, round: relayerInit(tip)?.circuit, deployment: tip.name }] : [];
  },
});
