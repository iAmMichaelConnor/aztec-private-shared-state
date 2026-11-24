// A landing that reverts, sent by anyone (pss_public_contract hatch.nr,
// "The landing's exit tags": the exit tags a landing emits and its
// commitment move land together or not at all). A held attempt's result (a
// tipAttempt step's bound attempt, taken with the deployment's relayer
// stopped) is sent through its result function with no simulation first
// (engine/tip.ts sendUnsimulated), so the transaction is mined with its
// public part reverted: `apply` where the app's landing refuses (a pinned
// read the chain no longer admits, or the escape hatch open), `teardown`
// where the landing succeeds and the transaction's teardown reverts (it
// pays through RevertingTeardown: the network's fee payment with the test
// probe's `revert_in_teardown()` before it). The PXE's simulation of the
// same transaction must first refuse it with every substring of `reason`
// (the revert's message); under `teardown` the same landing with the
// network's ordinary fee payment is simulated before that and must be
// accepted, so the landing itself succeeds and the refusal is the
// teardown's (a receipt says only "reverted", not which phase). Then nothing the landing would have done is on
// the chain: every exit tag it outputs (its first app values, as many as the
// app's landing, `landing`, takes in its array argument `tags`) unspent, none of its note hashes (the outcome's and
// the deliveries') in the transaction, and the queue's head and tail, the
// request's done flag and the request keys' slots as before. Binds {txHash,
// block, machineRequestId, exitTags}.
import type { AztecAddress } from "@aztec-labs/aztec.js/addresses";
import { Contract, type ContractFunctionInteraction } from "@aztec-labs/aztec.js/contracts";
import type { FeePaymentMethod } from "@aztec-labs/aztec.js/fee";
import { Fr } from "@aztec-labs/aztec.js/fields";
import { getAllFunctionAbis } from "@aztec-labs/stdlib/abi";
import { Gas } from "@aztec-labs/stdlib/gas";
import { mergeExecutionPayloads, type ExecutionPayload } from "@aztec-labs/stdlib/tx";
import { exitTagSpentAt, prepareResult, txEffectFrom, type FeeSendOptions, type QueuedResult, type ResultContract } from "@aztec-pss/pss-client";

import type { RunContext } from "../engine/context.ts";
import { expectRefused } from "../engine/machine.ts";
import { defineKind, refs, type Common } from "../engine/kind.ts";
import { check } from "../engine/scope.ts";
import { landingState, sendUnsimulated, tipContract, tipOf, tipResultFunction, tipVkFields, type Requestable, type Tip } from "../engine/tip.ts";
import { timed } from "../harness/harness.ts";
import type { AttemptRecord } from "./tip-attempt.ts";
import type { TipRequestRecord } from "./tip-request.ts";
import { noteIn } from "./tx.ts";

/** The app's landing function and its array argument that takes the
 * round's exit tags, its first app values (lending's `apply_shared(apply,
 * opened, tags)`). */
export interface Landing {
  landing: string;
  tags: string;
}

export interface TipLandStep extends Common, Landing {
  /** The request (a `tipRequest` step's bound name). */
  tipLand: string;
  /** Its held attempt (a `tipAttempt` step's bound name). */
  attempt: string;
  /** The sender: any account. */
  from: string;
  /** Where the landing reverts: in the app's landing, or in the
   * transaction's teardown after the landing succeeded. */
  reverts: "apply" | "teardown";
  /** With `teardown`: the scenario's PssProbe contract (noir/pss_probe). */
  probe?: string;
  /** The PXE's simulation must refuse the transaction with a message
   * holding every substring. */
  reason: string[];
  name?: string;
}

/** What a tipLand step binds. */
export interface LandingRecord {
  txHash: string;
  block: number;
  machineRequestId: string;
  /** The exit tags the landing outputs (unspent after its revert). */
  exitTags: string[];
}

/** The gas the reverting teardown declares, added to the result's limits:
 * a public call that reverts at once uses a few thousand L2 gas. */
const TEARDOWN_GAS = { daGas: 1_000, l2Gas: 200_000 };

/** How many exit tags the deployment's landing takes. */
export function exitTagCount(ctx: RunContext, tip: Tip, { landing, tags }: Landing): number {
  const apply = getAllFunctionAbis(ctx.contract(tip.name).artifact).find((f) => f.name === landing);
  const type = apply?.parameters.find((p) => p.name === tags)?.type;
  check(type?.kind === "array", `${tip.name}: no landing ${landing} with an array argument ${tags}`);
  return type.length;
}

/** A private outcome's result call from `from`, as a lander builds it
 * (pss-client prepareResult), as an aztec.js interaction. */
export async function landingCall(ctx: RunContext, tip: Tip, result: QueuedResult, from: string): Promise<ContractFunctionInteraction> {
  const contract = tipContract(ctx, tip, from);
  const call = await prepareResult(result, {
    contract: contract as unknown as ResultContract,
    address: tip.address,
    from: ctx.account(from),
    vkFields: { [result.circuit]: tipVkFields(tip, result.circuit) },
    resultFunction: tipResultFunction(tip),
  });
  const method = (contract.methods as unknown as Record<string, ((...args: unknown[]) => ContractFunctionInteraction) | undefined>)[call.method];
  check(method !== undefined, `${tip.name}: no result function ${call.method}`);
  return method(...call.args).with({ capsules: [call.capsule] });
}

/** The network's fee payment with the test probe's `revert_in_teardown()`
 * before it: the network's payer still pays (the probe's call pays
 * nothing), and the transaction's teardown reverts. */
class RevertingTeardown implements FeePaymentMethod {
  private readonly payment: FeePaymentMethod;
  private readonly probe: Requestable;
  constructor(payment: FeePaymentMethod, probe: Requestable) {
    this.payment = payment;
    this.probe = probe;
  }
  getAsset(): Promise<AztecAddress> {
    return this.payment.getAsset();
  }
  getFeePayer(): Promise<AztecAddress> {
    return this.payment.getFeePayer();
  }
  getGasSettings() {
    return this.payment.getGasSettings();
  }
  async getExecutionPayload(): Promise<ExecutionPayload> {
    return mergeExecutionPayloads([await this.probe.request(), await this.payment.getExecutionPayload()]);
  }
}

/** The fee options of a landing whose teardown reverts. */
async function revertingTeardownFee(ctx: RunContext, probe: string, from: string): Promise<FeeSendOptions> {
  const base = await ctx.network.fee("result");
  const payment = base.fee?.paymentMethod;
  const limits = base.fee?.gasSettings?.gasLimits;
  check(payment !== undefined && limits !== undefined, "a landing whose teardown reverts pays through the run's fee payment method under its fixed gas");
  const p = ctx.contract(probe);
  const call = (Contract.at(p.address, p.artifact, ctx.network.walletOf(from)).methods as unknown as Record<string, () => Requestable>).revert_in_teardown!();
  return {
    fee: {
      paymentMethod: new RevertingTeardown(payment, call),
      gasSettings: { gasLimits: new Gas(limits.daGas + TEARDOWN_GAS.daGas, limits.l2Gas + TEARDOWN_GAS.l2Gas), teardownGasLimits: Gas.from(TEARDOWN_GAS) },
    },
  };
}

export default defineKind<TipLandStep>({
  key: "tipLand",
  check(step, s) {
    refs.account(s, step.from);
    check(step.reverts === "apply" || step.reverts === "teardown", `tipLand reverts in apply or teardown, not ${step.reverts}`);
    check((step.reverts === "teardown") === (step.probe !== undefined), "a landing whose teardown reverts names the probe, one that reverts in apply none");
    refs.contract(s, step.probe);
    check(step.reason.length > 0, "tipLand takes the substrings of the revert's message");
    check(typeof step.landing === "string" && typeof step.tags === "string", "tipLand names the app's landing function and its exit tags argument (landing, tags)");
    return { fields: ["tipLand", "attempt", "from", "reverts", "probe", "reason", "landing", "tags", "name"], binds: [step.name] };
  },
  async run(ctx, step) {
    const req = ctx.scope.lookup(step.tipLand) as TipRequestRecord;
    const held = ctx.scope.lookup(step.attempt) as AttemptRecord;
    const tip = tipOf(ctx, req.namespace);
    const label = step.what ?? `${step.from}'s landing of ${step.tipLand}'s held attempt (reverting in ${step.reverts})`;
    const { result } = held;
    check(result.form === "outcome", `${label}: ${req.circuit}'s result is not a private outcome`);
    const parts = result.parts;
    const exitTags = parts.appValues.slice(0, exitTagCount(ctx, tip, step));
    const noteHashes = [...parts.noteHashes, ...parts.deliveries.map((d) => d.noteHash)];
    const call = await landingCall(ctx, tip, result, step.from);
    const fee = step.reverts === "teardown" ? await revertingTeardownFee(ctx, step.probe!, step.from) : await ctx.network.fee("result");
    const from = ctx.account(step.from);
    if (step.reverts === "teardown") {
      const ordinary = await ctx.network.fee("result");
      await timed(ctx.logger, `tx ${label}: the same landing with the ordinary fee payment (simulated, accepted)`, () => call.simulate({ ...ordinary, from }));
    }
    const refusal = await expectRefused(label, step.reason, () => timed(ctx.logger, `tx ${label} (simulated)`, () => call.simulate({ ...fee, from })), {
      accepted: "the PXE's simulation accepted the landing",
    });
    ctx.logger.info(`${label}: the PXE's simulation refuses it: ${refusal.split("\n")[0]}`);
    for (const t of exitTags) check((await exitTagSpentAt(ctx.network.node, tip.address, t)) === undefined, `${label}: exit tag ${t} is spent before the landing`);
    const before = await landingState(ctx, tip, req);
    const receipt = await timed(ctx.logger, `tx ${label}: sent with no simulation`, () => sendUnsimulated(ctx, step.from, call, fee));
    check(receipt.hasExecutionReverted(), `${label}: tx ${receipt.txHash} was mined without a revert`);
    const block = Number(receipt.blockNumber);
    const effects = txEffectFrom(await ctx.network.node.getTxEffect(receipt.txHash));
    for (const t of exitTags) {
      const at = await exitTagSpentAt(ctx.network.node, tip.address, t);
      check(at === undefined, `${label}: the reverted landing left exit tag ${t} spent (block ${at})`);
    }
    for (const h of noteHashes) {
      const found = await noteIn(effects, tip.address, new Fr(BigInt(h)));
      check(found === undefined, `${label}: the reverted landing left note hash ${h} at index ${found?.index}`);
    }
    const after = await landingState(ctx, tip, req, block);
    check(after === before, `${label}: the queue's head or tail, done[${req.index}] or the request keys moved: ${before} -> ${after}`);
    ctx.logger.info(
      `${label}: tx ${receipt.txHash} mined reverted in block ${block}: its ${exitTags.length} exit tag(s) unspent, none of its ${noteHashes.length} note hashes ` +
        `among the transaction's ${effects.noteHashes.length}, the queue's head and tail, done[${req.index}] and the request keys unchanged`,
    );
    const record: LandingRecord = { txHash: receipt.txHash.toString(), block, machineRequestId: parts.machineRequestId, exitTags };
    if (step.name) ctx.scope.set(step.name, record);
  },
  txs(ctx, step, sent) {
    const req = ctx.scope.lookup(step.tipLand) as TipRequestRecord;
    return sent.map((txHash) => ({ kind: "result", txHash, round: req.circuit, deployment: req.namespace }));
  },
});
