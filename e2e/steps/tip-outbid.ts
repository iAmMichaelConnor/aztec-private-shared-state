// Two landings of one result in one block, the first an outsider's that
// reverts (pss_public_contract hatch.nr, "The landing's exit tags": the
// tags are emitted in the public landing, so two landings of one result
// share no nullifier and the transaction pool keeps both). With the
// deployment's relayer stopped, the outsider sends `[the result call, the
// test probe's always_revert()]` with a priority fee and no simulation
// (engine/tip.ts sendUnsimulated), and `lander`, standing in for the
// relayer (the harness holds only the driver's own transactions), sends the
// ordinary landing of the same held attempt; both are held until proved and
// submitted together with the sequencer set to build no block of fewer (as
// sameBlock does). The block must hold both, the outsider's first and
// reverted, then the ordinary landing, which finishes the request's index
// and spends its exit tags. Binds {outsider, landing, block,
// newCommitments}: the two transactions, the block and the landed result's
// new commitments.
import { BatchCall, Contract, type ContractFunctionInteraction } from "@aztec-labs/aztec.js/contracts";
import { DONE_APPLIED, exitTagSpentAt } from "@aztec-pss/pss-client";

import type { RunContext } from "../engine/context.ts";
import { defineKind, refs, type Common } from "../engine/kind.ts";
import { check } from "../engine/scope.ts";
import { finishing, minTxsPerBlock, processState, relayerPid, sendUnsimulated, setMinTxsPerBlock, tipOf } from "../engine/tip.ts";
import { timed } from "../harness/harness.ts";
import type { AttemptRecord } from "./tip-attempt.ts";
import { exitTagCount, landingCall, type Landing } from "./tip-land.ts";
import type { TipRequestRecord } from "./tip-request.ts";

export interface TipOutbidStep extends Common, Landing {
  /** The request (a `tipRequest` step's bound name). */
  tipOutbid: string;
  /** Its held attempt (a `tipAttempt` step's bound name). */
  attempt: string;
  /** The outsider. */
  from: string;
  /** The account that sends the ordinary landing, for the relayer. */
  lander: string;
  /** The scenario's PssProbe contract (noir/pss_probe). */
  probe: string;
  name?: string;
}

/** The outsider's priority fee per L2 gas: any above the ordinary
 * landing's 0 orders it first. */
const PRIORITY_FEE = 1n;

/** The outsiders' transactions of a run: left out of its gas record, which
 * reads the L2 gas as the fee over the block's fee per L2 gas, true only
 * with no priority fee (engine/gas.ts). */
const outsiders = new WeakMap<RunContext, Set<string>>();

export default defineKind<TipOutbidStep>({
  key: "tipOutbid",
  check(step, s) {
    refs.account(s, step.from);
    refs.account(s, step.lander);
    refs.contract(s, step.probe);
    check(step.from !== step.lander, "the outsider and the lander are two accounts (one account's fee notes would make the two transactions share a nullifier)");
    check(typeof step.landing === "string" && typeof step.tags === "string", "tipOutbid names the app's landing function and its exit tags argument (landing, tags)");
    return { fields: ["tipOutbid", "attempt", "from", "lander", "probe", "landing", "tags", "name"], binds: [step.name] };
  },
  async run(ctx, step) {
    const req = ctx.scope.lookup(step.tipOutbid) as TipRequestRecord;
    const { result } = ctx.scope.lookup(step.attempt) as AttemptRecord;
    const tip = tipOf(ctx, req.namespace);
    const label = step.what ?? `${step.from}'s reverting landing of ${step.tipOutbid} outbidding ${step.lander}'s`;
    check(processState(relayerPid(ctx, tip)) === "T", `${label}: the relayer of ${tip.name} must be stopped`);
    check(result.form === "outcome", `${label}: ${req.circuit}'s result is not a private outcome`);
    const exitTags = result.parts.appValues.slice(0, exitTagCount(ctx, tip, step));
    const probe = ctx.contract(step.probe);
    const revert = (Contract.at(probe.address, probe.artifact, ctx.network.walletOf(step.from)).methods as unknown as Record<string, () => ContractFunctionInteraction>).always_revert!();
    const outsider = new BatchCall(ctx.network.walletOf(step.from), [await landingCall(ctx, tip, result, step.from), revert]);
    const ordinary = await landingCall(ctx, tip, result, step.lander);
    const fee = await ctx.network.fee("result");
    const restore = await minTxsPerBlock();
    const held = ctx.network.holdNextTxs(2, async () => {
      await setMinTxsPerBlock(2);
      ctx.logger.info(`${label}: both landings proved; sequencer minTxsPerBlock ${restore} -> 2, submitting them together`);
    });
    let receipts;
    try {
      const first = timed(ctx.logger, `tx ${label}: the outsider's [${req.circuit} landing, always_revert()] with priority fee ${PRIORITY_FEE}`, () =>
        sendUnsimulated(ctx, step.from, outsider, fee, PRIORITY_FEE),
      );
      await Promise.race([held(1), first]);
      const second = timed(ctx.logger, `tx ${label}: ${step.lander}'s ordinary landing`, () => ordinary.send({ ...fee, from: ctx.account(step.lander) }));
      receipts = [await first, (await second).receipt];
    } finally {
      await setMinTxsPerBlock(restore);
    }
    const [bid, landed] = receipts as [(typeof receipts)[0], (typeof receipts)[1]];
    check(landed.isMined() && bid.blockNumber === landed.blockNumber, `${label}: the landings are in blocks ${bid.blockNumber} and ${landed.blockNumber}, not one`);
    const block = Number(landed.blockNumber);
    if (!outsiders.has(ctx)) outsiders.set(ctx, new Set());
    outsiders.get(ctx)!.add(bid.txHash.toString());
    check(bid.hasExecutionReverted(), `${label}: the outsider's tx ${bid.txHash} did not revert`);
    check(landed.hasExecutionSucceeded(), `${label}: ${step.lander}'s landing ${landed.txHash} reverted`);
    check((bid.txIndexInBlock ?? 0) < (landed.txIndexInBlock ?? 0), `${label}: the block holds ${step.lander}'s landing at ${landed.txIndexInBlock} before the outsider's at ${bid.txIndexInBlock}`);
    const tx = await finishing(ctx, tip, req.index, req.block);
    check(tx.txHash === landed.txHash.toString(), `${label}: index ${req.index} was finished by tx ${tx.txHash}, not ${step.lander}'s ${landed.txHash}`);
    check((await tip.queue.doneAt(req.index, block)) === DONE_APPLIED, `${label}: done[${req.index}] is not applied`);
    for (const t of exitTags) {
      const at = await exitTagSpentAt(ctx.network.node, tip.address, t);
      check(at === block, `${label}: exit tag ${t} ${at === undefined ? "is unspent" : `was spent in block ${at}`}, not by the landing in block ${block}`);
    }
    ctx.logger.info(
      `${label}: block ${block} holds the outsider's tx ${bid.txHash} (index ${bid.txIndexInBlock}, reverted) and ${step.lander}'s landing ${landed.txHash} (index ${landed.txIndexInBlock}), ` +
        `which finished index ${req.index} and spent its ${exitTags.length} exit tag(s)`,
    );
    if (step.name) ctx.scope.set(step.name, { outsider: bid.txHash.toString(), landing: landed.txHash.toString(), block, newCommitments: result.parts.newCommitments });
  },
  txs(ctx, step, sent) {
    const req = ctx.scope.lookup(step.tipOutbid) as TipRequestRecord;
    const outsider = outsiders.get(ctx);
    return sent.filter((txHash) => !outsider?.has(txHash)).map((txHash) => ({ kind: "result", txHash, round: req.circuit, deployment: req.namespace }));
  },
});
