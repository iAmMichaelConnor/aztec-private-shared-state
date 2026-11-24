// A chain reorg and what a scenario reads around it, on the reorg network
// (harness/reorg-network.ts, E2E_REORG=1; every op refuses to run on the
// standard network). The ops:
//
//   pause, resume    the sequencer stops and starts mining the pool; a
//                    transaction sent while it is paused waits in the pool
//   proving          the reorg network's proving loop `on` or off
//   prove            the debug API's prove: every checkpoint proven
//   revert           an L1 reorg (revertToCheckpoint) that removes block
//                    `before` and every block after it, or every block from
//                    the anchor block of a request's transaction
//                    (`anchorOf`), which makes the pool drop that
//                    transaction; the sequencer must be paused first
//   rebuild          one empty block at a later slot (the debug API's warp:
//                    the block at the replaced height hashes differently),
//                    then resume
//   epoch-prune      L1 time moved past the proof deadline of every
//                    unproven checkpoint (anvil's evm_setNextBlockTimestamp
//                    and evm_mine); waits until the node pruned them
//   tips             the node's four tips {proposed, checkpointed, proven,
//                    finalized, checkpoint}
//   state            the queue at the latest block {block, head, tail}, with
//                    `request` its entry {queued, done, commitment (the
//                    first key the round writes), landings (transactions
//                    since the request's block that wrote done[index])}, and
//                    the init's slots {initSlots}
//   count            lines holding `match` in the log `of` the three nodes
//                    (`node`), the orchestrator or the relayer
//   notes            the outcome notes `owner`'s PXE holds at the app's slot
//   requeue          waits until the request is queued again (pss-client
//                    watchRequest: with `resend`, sent again with the same
//                    arguments when the pool dropped it) and updates its
//                    record (index, block, transaction); binds {index,
//                    block, txHash, resends}
//   redeliver        pss-client watchOutcome: the request's outcome found
//                    and its note delivered again; binds {deliveries}
//   poll-start, poll-end
//                    pss-client pollResult for the request, started and
//                    awaited later; poll-end binds {status, applied, index}
//   node-prune       each node's admin `prune` once; binds {versions}
//   no-fault         no node logged that it holds no version of a slot's
//                    commitment
//
// A read op (tips, state, count, notes) with `expect` reads again until the
// expectations hold, up to `timeoutS` (default 120 s).
import { TxHash } from "@aztec-labs/aztec.js/tx";
import { BlockNumber } from "@aztec-labs/foundation/branded-types";
import { OutcomeReader, pollResult, watchOutcome, watchRequest, type IntakeSendOptions, type IntakeTarget } from "@aztec-pss/pss-client";

import type { RunContext } from "../engine/context.ts";
import { defineKind, refs, type Common } from "../engine/kind.ts";
import { anvilRpc, chainTips, logLines, reorgCall, type LogOf } from "../engine/reorg.ts";
import { big, check, poll, type Expect, type Value } from "../engine/scope.ts";
import { keySlots, leafOf, minedSince, queueIndexOf, relayerInit, storageAt, tipContract, tipOf, warpL2Time, type Tip } from "../engine/tip.ts";
import { timed } from "../harness/harness.ts";
import { heldNotes, outcomeAccess } from "./tip-outcome.ts";
import type { TipRequestRecord } from "./tip-request.ts";

type Op =
  | "pause"
  | "resume"
  | "proving"
  | "prove"
  | "revert"
  | "rebuild"
  | "epoch-prune"
  | "tips"
  | "state"
  | "count"
  | "notes"
  | "requeue"
  | "redeliver"
  | "poll-start"
  | "poll-end"
  | "node-prune"
  | "no-fault";

export interface ReorgStep extends Common {
  reorg: Op;
  /** The tip deployment (default: the request's, else the scenario's first). */
  namespace?: string;
  /** A request's bound name (a `tipRequest` step's). */
  request?: string;
  /** revert: the first block removed. */
  before?: Value;
  /** revert: remove every block from this request's anchor block on. */
  anchorOf?: string;
  /** proving: on or off. */
  on?: boolean;
  /** requeue: send the request again when the pool dropped it. */
  resend?: boolean;
  /** notes, redeliver: the outcome's owner, the request's sender. */
  owner?: string;
  /** count: whose log, and the text a line holds. */
  of?: LogOf;
  match?: string;
  name?: string;
  expect?: Expect[];
  timeoutS?: number;
}

/** The fields each op takes besides `reorg` and `namespace`; `name` and
 * `expect` where it binds. */
const FIELDS: Record<Op, string[]> = {
  pause: [],
  resume: [],
  proving: ["on"],
  prove: [],
  revert: ["before", "anchorOf", "name", "expect"],
  rebuild: [],
  "epoch-prune": ["name", "expect", "timeoutS"],
  tips: ["name", "expect", "timeoutS"],
  state: ["request", "name", "expect", "timeoutS"],
  count: ["of", "match", "name", "expect", "timeoutS"],
  notes: ["request", "owner", "name", "expect", "timeoutS"],
  requeue: ["request", "resend", "name", "expect", "timeoutS"],
  redeliver: ["request", "owner", "name", "expect", "timeoutS"],
  "poll-start": ["request"],
  "poll-end": ["request", "name", "expect", "timeoutS"],
  "node-prune": ["name", "expect"],
  "no-fault": [],
};

/** The nodes' line for a slot at a commitment they hold no version of
 * (sidecar-core state versions). */
const NO_VERSION = "holds no version";

/** The pollResult runs poll-start started, by request name. */
const polls = new WeakMap<RunContext, Map<string, ReturnType<typeof pollResult>>>();

export default defineKind<ReorgStep>({
  key: "reorg",
  check(step, s) {
    check(Object.hasOwn(FIELDS, step.reorg), `reorg: one of ${Object.keys(FIELDS).join(", ")}, not ${step.reorg}`);
    refs.tip(s, step.namespace);
    const fields = FIELDS[step.reorg];
    if (fields.includes("request") && step.reorg !== "state") check(typeof step.request === "string", `reorg ${step.reorg} takes the request`);
    if (step.reorg === "revert") check((step.before === undefined) !== (step.anchorOf === undefined), "reorg revert takes exactly one of before, anchorOf");
    if (step.reorg === "proving") check(typeof step.on === "boolean", "reorg proving takes on: true or false");
    if (step.reorg === "count") check(["node", "orchestrator", "relayer"].includes(step.of ?? "") && typeof step.match === "string", "reorg count takes of (node, orchestrator or relayer) and a match");
    if (step.owner !== undefined) refs.account(s, step.owner);
    if (fields.includes("owner")) check(step.owner !== undefined, `reorg ${step.reorg} takes the owner`);
    return { fields: ["reorg", "namespace", ...fields], binds: [step.name] };
  },
  async run(ctx, step) {
    const label = step.what ?? `reorg ${step.reorg}${step.request ? ` ${step.request}` : ""}`;
    const req = step.request === undefined ? undefined : (ctx.scope.lookup(step.request) as TipRequestRecord);
    const tip = tipOf(ctx, step.namespace ?? req?.namespace);
    const bind = (value: unknown) => {
      if (step.name) ctx.scope.set(step.name, value);
      if (step.expect) ctx.scope.expectAll(label, step.expect);
    };
    /** Read, bind and check; again every second until the expectations
     * hold, or throw the last failed expectation past the limit. */
    const read = async (what: () => Promise<unknown>) => {
      let failed: unknown;
      const bound = (value: unknown) => {
        try {
          bind(value);
          return true;
        } catch (e) {
          failed = e;
          return false;
        }
      };
      const { value, done } = await poll(what, bound, (step.timeoutS ?? 120) * 1000, 1_000);
      if (!done) throw failed;
      ctx.logger.info(`${label}: ${JSON.stringify(value, (_, v) => (typeof v === "bigint" ? `0x${v.toString(16)}` : v))}`);
    };
    switch (step.reorg) {
      case "pause":
      case "resume":
        await reorgCall(step.reorg);
        ctx.logger.info(`${label}: the sequencer ${step.reorg === "pause" ? "mines nothing" : "mines the pool again"} (proposed tip ${(await chainTips(ctx)).proposed})`);
        return;
      case "proving":
        await reorgCall("proving", [step.on]);
        ctx.logger.info(`${label}: the reorg network's proving loop is ${step.on ? "on" : "off"}`);
        return;
      case "prove": {
        const { createAztecNodeDebugClient } = await import("@aztec-labs/stdlib/interfaces/client");
        const proven = await createAztecNodeDebugClient(ctx.harness.aztecNodeUrl).prove();
        ctx.logger.info(`${label}: proven up to checkpoint ${proven}`);
        return;
      }
      case "revert":
        return revert(ctx, step, label, bind);
      case "rebuild": {
        const { slotDuration } = await ctx.network.node.getL1Constants();
        const before = await chainTips(ctx);
        await warpL2Time(ctx, slotDuration);
        await reorgCall("resume");
        ctx.logger.info(`${label}: one empty block at a later slot (proposed ${before.proposed} -> ${(await chainTips(ctx)).proposed}), the sequencer mines the pool again`);
        return;
      }
      case "epoch-prune":
        return epochPrune(ctx, label, (step.timeoutS ?? 120) * 1000, read);
      case "tips":
        return read(() => chainTips(ctx));
      case "state":
        return read(() => queueState(ctx, tip, req));
      case "count":
        return read(async () => logLines(ctx, step.of!, step.match!, tip.deployment));
      case "notes": {
        const { owner, storageSlot } = await outcomeAccess(ctx, req!, step.owner!, label);
        return read(() => heldNotes(ctx, step.owner!, tip.address, owner, storageSlot));
      }
      case "requeue":
        return requeue(ctx, tip, req!, step, label, read);
      case "redeliver": {
        const { keys, deliver } = await outcomeAccess(ctx, req!, step.owner!, label);
        const found = await timed(ctx.logger, `${label}: pss-client watchOutcome until the outcome's transaction is checkpointed`, () =>
          watchOutcome({
            reader: new OutcomeReader(ctx.network.node, tip.address),
            outcomeTag: req!.outcomeTag!,
            keys,
            deliver,
            node: ctx.network.node,
            until: "checkpointed",
            intervalMs: 1_000,
            signal: AbortSignal.timeout((step.timeoutS ?? 120) * 1000),
          }),
        );
        return read(async () => ({ deliveries: found.deliveries, txHash: found.tx.txHash }));
      }
      case "poll-start": {
        let byName = polls.get(ctx);
        if (!byName) polls.set(ctx, (byName = new Map()));
        const started = pollResult({ queue: tip.queue, chainRequestId: req!.chainRequestId, fromIndex: req!.index, intervalMs: 1_000 });
        started.catch(() => undefined);
        byName.set(step.request!, started);
        ctx.logger.info(`${label}: pss-client pollResult for ${req!.chainRequestId} from index ${req!.index}, running`);
        return;
      }
      case "poll-end": {
        const started = polls.get(ctx)?.get(step.request!);
        check(started !== undefined, `${label}: no poll-start of ${step.request} before`);
        const limit = (step.timeoutS ?? 1800) * 1000;
        const polled = await Promise.race([started, new Promise<never>((_, reject) => setTimeout(() => reject(new Error(`${label}: pollResult did not end within ${limit} ms`)), limit).unref())]);
        return read(async () => ({ status: polled.status, applied: polled.status === "applied", index: polled.index }));
      }
      case "node-prune": {
        let versions = 0;
        for (const i of [0, 1, 2]) {
          const answer = await ctx.machine.admin(i, { op: "prune" });
          check(answer.ok, `${label}: node ${i} refused the prune: ${JSON.stringify(answer.refusal)}`);
          versions += Number(answer.pruned_versions ?? 0);
        }
        ctx.logger.info(`${label}: every node pruned once; ${versions} node-held version(s) deleted in all`);
        return bind({ versions });
      }
      case "no-fault": {
        const n = logLines(ctx, "node", NO_VERSION, tip.deployment);
        check(n === 0, `${label}: the nodes logged ${n} line(s) holding "${NO_VERSION}": a slot holds a commitment whose version is gone`);
        ctx.logger.info(`${label}: no node logged "${NO_VERSION}"`);
        return;
      }
    }
  },
});

/** revert: pause first, then the L1 reorg; the tips must have gone below the
 * first block removed. */
async function revert(ctx: RunContext, step: ReorgStep, label: string, bind: (value: unknown) => void): Promise<void> {
  const { paused } = (await reorgCall("status")) as { paused: boolean };
  check(paused, `${label}: pause the sequencer first, or it mines the restored transactions at once`);
  const first = step.anchorOf === undefined ? Number(big(ctx.scope.resolve(step.before!))) : anchorBlock(ctx, step.anchorOf);
  check(first > 1, `${label}: block ${first} cannot be removed`);
  const kept = await ctx.network.node.getBlockData(BlockNumber(first - 1));
  check(kept !== undefined, `${label}: the node has no block ${first - 1}`);
  const before = await chainTips(ctx);
  await timed(ctx.logger, `${label}: revertToCheckpoint(${kept.checkpointNumber}), removing block ${first} on`, () => reorgCall("revertToCheckpoint", [Number(kept.checkpointNumber)]));
  const after = await chainTips(ctx);
  check(after.proposed < first, `${label}: the proposed tip is ${after.proposed} after the revert, not below block ${first} (checkpoint ${kept.checkpointNumber} holds it)`);
  ctx.logger.info(`${label}: tips ${JSON.stringify(before)} -> ${JSON.stringify(after)}`);
  bind(after);
}

/** The block a request's transaction was proven against (its anchor), from
 * the transaction as the wallet sent it. */
function anchorBlock(ctx: RunContext, request: string): number {
  const req = ctx.scope.lookup(request) as TipRequestRecord;
  const tx = ctx.network.sentTxs.get(req.txHash);
  check(tx !== undefined, `the driver sent no transaction ${req.txHash} (${request})`);
  return Number(tx.data.constants.anchorBlockHeader.globalVariables.blockNumber);
}

/** epoch-prune: L1 time past every proof deadline, then the node prunes its
 * unproven checkpoints. */
async function epochPrune(ctx: RunContext, label: string, limitMs: number, read: (what: () => Promise<unknown>) => Promise<void>): Promise<void> {
  const c = await ctx.network.node.getL1Constants();
  const before = await chainTips(ctx);
  check(before.checkpointed > before.proven, `${label}: nothing to prune: every checkpointed block is proven (${JSON.stringify(before)}); turn proving off first`);
  const latest = (await anvilRpc("eth_getBlockByNumber", ["latest", false])) as { timestamp: string };
  const target = Number(BigInt(latest.timestamp)) + (c.proofSubmissionEpochs + 1) * c.epochDuration * c.slotDuration + c.slotDuration;
  await anvilRpc("evm_setNextBlockTimestamp", [target]);
  await anvilRpc("evm_mine");
  ctx.logger.info(`${label}: L1 time moved to ${target} (${c.proofSubmissionEpochs} proof submission epoch(s) of ${c.epochDuration} slots of ${c.slotDuration} s, and one more)`);
  // the node prunes on a later sync of L1: wait for it, then read the tips
  // and check the step's expectations
  const { value, done } = await poll(() => chainTips(ctx), (t) => t.checkpointed === t.proven, limitMs, 1_000);
  check(done, `${label}: the node did not prune within ${limitMs / 1000} s (tips ${JSON.stringify(value)})`);
  await read(() => chainTips(ctx));
}

/** The queue at the latest block, a request's entry, and the init's slots. */
async function queueState(ctx: RunContext, tip: Tip, req: TipRequestRecord | undefined): Promise<Record<string, unknown>> {
  const s = await tip.queue.snapshot();
  const out: Record<string, unknown> = { block: s.block, head: s.head, tail: s.tail };
  if (req !== undefined) {
    out.queued = req.index < s.tail && (await tip.queue.requestAt(req.index, s.block)) === req.chainRequestId;
    out.done = await tip.queue.doneAt(req.index, s.block);
    out.commitment = await storageAt(ctx, tip, keySlots(tip, req.circuit).writes[0]!, s.block);
    const leaf = await leafOf(tip, (await tip.queue.slots.done(req.index)).toBigInt());
    out.landings = (await minedSince(ctx, tip, req.block)).filter((t) => t.writes.has(leaf)).length;
  }
  const init = relayerInit(tip);
  if (init !== undefined) {
    const { parts } = await ctx.client(tip.name).fetchInitResult({ circuit: init.circuit, inputs: init.inputs });
    out.initSlots = await Promise.all(parts.slots.map((slot) => storageAt(ctx, tip, slot, s.block)));
  }
  return out;
}

/** requeue: the request queued again, by the pool or by sending it again;
 * its record follows it to its new index and block. */
async function requeue(ctx: RunContext, tip: Tip, req: TipRequestRecord, step: ReorgStep, label: string, read: (what: () => Promise<unknown>) => Promise<void>): Promise<void> {
  const target = { contract: tipContract(ctx, tip, req.from), method: req.method } as unknown as IntakeTarget<{ receipt: { txHash: { toString(): string } } }>;
  const sendOptions: IntakeSendOptions = { from: ctx.account(req.from) };
  const watched = await timed(ctx.logger, `${label}: pss-client watchRequest on tx ${req.txHash}${step.resend ? ", sent again when dropped" : ""}`, () =>
    watchRequest({
      node: ctx.network.node,
      txHash: req.txHash,
      resend: step.resend
        ? async () => {
            const { sent } = await ctx.client(tip.name).requestIntake(target, { args: req.args }, sendOptions, { fee: ctx.network.feeSetting });
            return sent.receipt.txHash.toString();
          }
        : undefined,
      until: "checkpointed",
      intervalMs: 1_000,
      signal: AbortSignal.timeout((step.timeoutS ?? 600) * 1000),
    }),
  );
  const receipt = await ctx.network.node.getTxReceipt(TxHash.fromString(watched.txHash));
  check(receipt.blockNumber !== undefined, `${label}: tx ${watched.txHash} has no block`);
  const block = Number(receipt.blockNumber);
  const { index } = await queueIndexOf(tip, req.chainRequestId, block);
  check(index !== undefined, `${label}: chain request ${req.chainRequestId} is not queued at block ${block}`);
  ctx.logger.info(
    `${label}: ${req.chainRequestId} queued again at index ${index} (was ${req.index}) in block ${block}, tx ${watched.txHash}: ` +
      `${watched.resends ? `sent again ${watched.resends} time(s), the pool dropped it` : "the pool kept and mined it"}`,
  );
  Object.assign(req, { index, block, txHash: watched.txHash });
  await read(async () => ({ index, block, txHash: watched.txHash, resends: watched.resends }));
}
