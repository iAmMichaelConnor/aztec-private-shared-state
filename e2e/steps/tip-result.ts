// The end of a tip request (docs/ARCHITECTURE.md section 6, rows "result",
// "relayer" and "outputs"): its result landed through its result function by
// the relayer or, with the relayer stopped, by the user (pss-client
// submitResult), or the head skipped by the relayer once stale; or a landed
// result sent again, which apply must refuse. Each is checked on the chain
// (the transaction that finished the queue index, done[index], the request
// keys' commitments before and after it, no public log under node-held
// state but a public completion's: a non-secret-shared round under
// partial-note delivery completes the request's partial note in apply, one
// log under its completion tag carrying the note's fields and the request
// id) and on what the client decodes (pollResult, and the result FETCH by
// chain request id answers on the orchestrator's public listener, read
// through pss-client's result reader of its circuit: a non-secret-shared
// intake's public outputs, or a secret-shared intake's private outcome,
// which re-blinds the state whatever it holds; tipOutcome opens it).
import {
  SidecarError,
  completionLogTag,
  fieldHex,
  sleep,
  stageCapsule,
  feeOptions,
  pollResult,
  prepareResult,
  resultSummary,
  sendResultCall,
  submitResult,
  type PreparedCall,
  type ResultReader,
  DONE_APPLIED,
  DONE_SKIPPED,
  type PssClient,
  type QueuedResult,
  type ResultContract,
} from "@aztec-pss/pss-client";

import type { RunContext } from "../engine/context.ts";
import { defineKind, refs, type Common } from "../engine/kind.ts";
import { expectRefused } from "../engine/machine.ts";
import { check, type Expect } from "../engine/scope.ts";
import { finishing, keySlots, landingState, processState, relayerPid, storageAt, tipContract, tipOf, tipResultFunction, tipVkFields, type Tip } from "../engine/tip.ts";
import { timed } from "../harness/harness.ts";
import type { TipRequestRecord } from "./tip-request.ts";
import { TAMPER_FIELD, TAMPER_MESSAGE, tamperedProof } from "./tx.ts";

interface ResultOf extends Common {
  /** The request's bound name (a `tipRequest` step's). */
  tipResult: string;
}
/** The request finished: applied (default) or, with `skipped`, skipped. */
export interface FinishedResult extends ResultOf {
  /** Who lands it: the relayer (default) or the user from `from`, which
   * requires the deployment's relayer stopped. */
  by?: "relayer" | "user";
  from?: string;
  /** By the user, in a real-proof run: the result is first sent with
   * capsule proof field 100 changed, and the PXE's proving must refuse it. */
  clientTamper?: true;
  /** The relayer skips the head instead (it must be stale by then). */
  skipped?: true;
  name?: string;
  /** Checked after the binding; may name it. */
  expect?: Expect[];
  /** How long to wait for the finish; default 1800 s. */
  timeoutS?: number;
  again?: never;
  refused?: never;
}
/** The landed result sent again from `from`: refused with a message holding
 * one of the substrings, with nothing changed. */
export interface RepeatedResult extends ResultOf {
  again: true;
  from: string;
  refused: string[];
  by?: never;
  clientTamper?: never;
  skipped?: never;
  name?: never;
  expect?: never;
  timeoutS?: never;
}
export type TipResultStep = FinishedResult | RepeatedResult;

/** What a finished result binds. */
export interface TipResultRecord {
  status: "applied" | "skipped";
  index: number;
  /** The landing (or skip) transaction and its block. */
  txHash: string;
  block: number;
  /** Applied: the result's form, the request keys' commitments, the
   * pinned values the round used and the machine request id, as FETCH
   * answers them; a non-secret-shared intake's ok (1 or 0) and app outputs, a secret-shared
   * intake's outcome tag and ciphertext length (its outcome is private). */
  form?: "public" | "outcome";
  ok?: number;
  /** A public result under partial-note delivery: the request's partial
   * note, which apply completed (the completion log checked). */
  partialNote?: string;
  /** Its completion log: the tag, the outcome slot, the note's fields and
   * the chain request id. */
  completion?: string[];
  appOutputs?: string[];
  oldCommitments?: string[];
  newCommitments?: string[];
  reads?: string[];
  machineRequestId?: string;
  outcomeTag?: string;
  ciphertextLength?: number;
  /** A private outcome's note hashes: the completed note's. */
  noteHashes?: string[];
  /** A private outcome's app values, the proof's values for the app's
   * apply (lending's: the exit tags first). */
  appValues?: string[];
}

const DEFAULT_TIMEOUT_S = 1800;

/** A result as FETCH by chain request id answered it, and the client that
 * answered. */
export interface FetchedResult {
  result: QueuedResult;
  client: PssClient;
}

/** FETCH by chain request id on the orchestrator's public listener, waiting
 * while the nodes have no result yet. */
export async function fetchResult(ctx: RunContext, tip: Tip, req: TipRequestRecord, timeoutS: number): Promise<FetchedResult> {
  const deadline = Date.now() + timeoutS * 1000;
  const client = ctx.client(tip.name);
  for (;;) {
    try {
      return { result: await client.fetchChainResult(req.chainRequestId, { circuit: req.circuit }), client };
    } catch (e) {
      if (!(e instanceof SidecarError && e.class === "not_found") || Date.now() > deadline) throw e;
    }
    await sleep(2_000);
  }
}

const relayerStopped = (ctx: RunContext, tip: Tip) => processState(relayerPid(ctx, tip)) === "T";

async function finished(ctx: RunContext, step: FinishedResult): Promise<void> {
  const req = ctx.scope.lookup(step.tipResult) as TipRequestRecord;
  const tip = tipOf(ctx, req.namespace);
  const label = step.what ?? `${step.tipResult} ${step.skipped ? "skipped" : "result"}`;
  const by = step.by ?? "relayer";
  const timeoutS = step.timeoutS ?? DEFAULT_TIMEOUT_S;
  let userTx: string | undefined;
  if (by === "user") {
    check(relayerStopped(ctx, tip), `${label}: the user lands the result only while the relayer of ${tip.name} is stopped`);
    const from = step.from!;
    const { result, client } = await timed(ctx.logger, `${label}: FETCH by chain request id`, () => fetchResult(ctx, tip, req, timeoutS));
    const s = resultSummary(result);
    ctx.logger.info(`${label}: the nodes' ${s.form} result ${s.machineRequestId}${s.ok === undefined ? "" : ` (ok ${s.ok})`}`);
    if (step.clientTamper && ctx.harness.expectRealProofs) await clientTamper(ctx, tip, req, result, from, label);
    const submitted = await timed(ctx.logger, `tx ${label}: its result call from ${from} (pss-client submitResult)`, () =>
      submitResult({
        client,
        chainRequestId: req.chainRequestId,
        fetch: { circuit: req.circuit },
        contract: tipContract(ctx, tip, from) as unknown as ResultContract,
        address: tip.address,
        from: ctx.account(from),
        vkFields: { [result.circuit]: tipVkFields(tip, result.circuit) },
        resultFunction: tipResultFunction(tip),
        fee: ctx.network.feeSetting,
      }),
    );
    userTx = String((submitted.sent as { receipt: { txHash: unknown } }).receipt.txHash);
    ctx.logger.info(`${label}: ${from} landed it in tx ${userTx} (${submitted.attempts} transaction(s))`);
  }
  const polled = await timed(ctx.logger, `${label}: pollResult until index ${req.index} is finished`, () =>
    pollResult({ queue: tip.queue, chainRequestId: req.chainRequestId, fromIndex: req.index, timeoutMs: timeoutS * 1000 }),
  );
  check(polled.index === req.index, `${label}: pollResult found the request at index ${polled.index}, not ${req.index}`);
  check(polled.status === (step.skipped ? "skipped" : "applied"), `${label}: the request was ${polled.status}, expected ${step.skipped ? "skipped" : "applied"}`);

  // the transaction that finished the index, and the chain around it
  const tx = await finishing(ctx, tip, req.index, req.block);
  const done = await tip.queue.doneAt(req.index, tx.block);
  const head = (await tip.queue.snapshot(tx.block)).head;
  check(head > req.index, `${label}: head ${head} at block ${tx.block}, not past index ${req.index}`);
  // node-held state logs nothing; a public completion logs its note
  const completions = polled.status === "applied" ? await completionLogs(ctx, tip, req, timeoutS) : [];
  const logged = tx.logs;
  check(
    logged.length === completions.length,
    `${label}: tx ${tx.txHash} logged ${logged.length} public logs; node-held state logs nothing${completions.length ? ", a public completion its one log" : ""}`,
  );
  for (const [k, want] of completions.entries()) {
    const got = logged[k]!.map((f) => fieldHex(f.toBigInt()));
    check(JSON.stringify(got) === JSON.stringify(want), `${label}: the completion log is ${JSON.stringify(got)}, expected ${JSON.stringify(want)}`);
  }
  if (by === "user") check(tx.txHash === userTx, `${label}: index ${req.index} was finished by tx ${tx.txHash}, not the user's ${userTx}`);
  else check(!ctx.network.sentTxs.has(tx.txHash), `${label}: index ${req.index} was finished by tx ${tx.txHash}, which this driver sent; expected the relayer's`);
  const keys = keySlots(tip, req.circuit);
  const record: TipResultRecord = { status: polled.status, index: req.index, txHash: tx.txHash, block: tx.block };
  if (polled.status === "skipped") {
    check(done === DONE_SKIPPED, `${label}: done[${req.index}] is ${done}, not skipped`);
    for (const slot of keys.writes) {
      check((await storageAt(ctx, tip, slot, tx.block)) === (await storageAt(ctx, tip, slot, tx.block - 1)), `${label}: the skip moved key ${slot}`);
    }
    ctx.logger.info(`${label}: index ${req.index} skipped by the relayer in tx ${tx.txHash} (block ${tx.block}): done[${req.index}] = skipped, head ${head}, every key unchanged`);
  } else {
    check(done === DONE_APPLIED, `${label}: done[${req.index}] is ${done}, not applied`);
    const { result } = await fetchResult(ctx, tip, req, timeoutS);
    const s = resultSummary(result);
    for (const [k, slot] of keys.reads.entries()) {
      const before = await storageAt(ctx, tip, slot, tx.block - 1);
      check(before === s.oldCommitments[k], `${label}: key ${slot} held ${before} before the result, which ran on ${s.oldCommitments[k]}`);
    }
    // a public result moves the keys when ok; a private outcome re-blinds
    // the state whatever the outcome
    for (const [k, slot] of keys.writes.entries()) {
      const [before, after] = [await storageAt(ctx, tip, slot, tx.block - 1), await storageAt(ctx, tip, slot, tx.block)];
      const want = s.moves ? s.newCommitments[k]! : before;
      check(after === want, `${label}: key ${slot} holds ${after} after the result, expected ${want} (${s.moves ? "the round's new commitment" : "unchanged: the round failed"})`);
      if (!s.moves) check(s.newCommitments[k] === s.oldCommitments[k], `${label}: a failed round changed its commitment`);
    }
    const fields = {
      form: s.form,
      ok: s.ok === undefined ? undefined : s.ok ? 1 : 0,
      partialNote: s.partialNote,
      completion: completions[0],
      appOutputs: s.appOutputs,
      reads: s.reads,
      oldCommitments: s.oldCommitments,
      newCommitments: s.newCommitments,
      machineRequestId: s.machineRequestId,
      outcomeTag: s.outcomeTag,
      ciphertextLength: s.ciphertextLength,
      noteHashes: s.noteHashes,
      appValues: result.form === "outcome" ? result.parts.appValues : undefined,
    };
    Object.assign(record, Object.fromEntries(Object.entries(fields).filter(([, v]) => v !== undefined)));
    const what = [
      `machine request ${s.machineRequestId}`,
      ...(s.ok === undefined ? [] : [`ok ${record.ok}`]),
      ...(s.appOutputs === undefined ? [] : [`app outputs [${s.appOutputs.join(", ")}]`]),
      ...(s.outcomeTag === undefined ? [] : [`${s.noteHashes?.length ?? 0} completed note hash(es), a ${s.ciphertextLength}-field ciphertext under tag ${s.outcomeTag}`]),
      ...(completions.length ? [`the completion log under ${completions[0]![0]}`] : []),
      `pinned [${s.reads.join(", ")}]`,
    ];
    ctx.logger.info(
      `${label}: index ${req.index} applied by ${by === "user" ? step.from : "the relayer"} in tx ${tx.txHash} (block ${tx.block}): a ${s.form} result (${what.join(", ")})` +
        `; keys ${s.moves ? "moved to the new commitments" : "unchanged"}; head ${head}; ${completions.length ? "the completion log its one public log" : "no public log"}`,
    );
  }
  if (step.name) ctx.scope.set(step.name, record);
  if (step.expect) ctx.scope.expectAll(label, step.expect);
}

/** The public log a non-secret-shared result under partial-note delivery
 * makes apply emit: under the partial note's completion tag, the outcome
 * slot, the note's fields (the app's own, read from the log itself after
 * the slot) and the chain request id last; none for any other result. */
async function completionLogs(ctx: RunContext, tip: Tip, req: TipRequestRecord, timeoutS: number): Promise<string[][]> {
  const s = resultSummary((await fetchResult(ctx, tip, req, timeoutS)).result);
  if (s.partialNote === undefined) return [];
  const tag = fieldHex(await completionLogTag(s.partialNote));
  const tx = await finishing(ctx, tip, req.index, req.block);
  const log = tx.logs.find((l) => fieldHex(l[0]!.toBigInt()) === tag);
  check(log !== undefined, `${tip.name}: no completion log under ${tag} (the partial note ${s.partialNote}) in tx ${tx.txHash}`);
  const fields = log.map((f) => fieldHex(f.toBigInt()));
  check(BigInt(fields.at(-1)!) === BigInt(req.chainRequestId), `${tip.name}: the completion log ends in ${fields.at(-1)}, not the request id ${req.chainRequestId}`);
  return [fields];
}

/** The result sent from `from` twice, changed, each refused by the PXE's
 * proving of the result function: once with capsule proof field
 * TAMPER_FIELD changed, once with the last public input (an app output, or
 * the outcome's last ciphertext or call value, none covered by a node
 * signature) changed in the call under the honest proof. */
async function clientTamper(ctx: RunContext, tip: Tip, req: TipRequestRecord, result: QueuedResult, from: string, label: string): Promise<void> {
  const contract = tipContract(ctx, tip, from) as unknown as ResultContract;
  const vk = tipVkFields(tip, result.circuit);
  const call = await prepareResult(result, { contract, address: tip.address, from: ctx.account(from), vkFields: { [result.circuit]: vk }, resultFunction: tipResultFunction(tip) });
  const send = (changed: PreparedCall) => async () => sendResultCall(contract, changed, { ...(await feeOptions(ctx.network.feeSetting, "result")) });
  const proofRefusal = await expectRefused(
    label,
    [TAMPER_MESSAGE],
    () => timed(ctx.logger, `tx ${label} with a tampered proof (client-side proving)`, send({ ...call, capsule: stageCapsule(tip.address, ctx.account(from), vk, tamperedProof(result.parts.proof)) })),
    { accepted: "a TAMPERED result proof was accepted" },
  );
  ctx.logger.info(`[client tamper] ${label} with proof field ${TAMPER_FIELD} changed: client-side proving refused it, nothing sent: ${proofRefusal.split("\n")[0]}`);
  const inputs = result.response.public_inputs;
  const last = inputs.length - 1;
  const changed = { ...result.response, public_inputs: inputs.map((x, k) => (k === last ? fieldHex(BigInt(x) ^ 1n) : x)) };
  const reader = result.reader as ResultReader;
  const fn = tipResultFunction(tip)(result);
  const args = [...(fn.args ?? []), ...reader.callArgs(await reader.parts(tip.address.toString(), req.chainRequestId, changed))];
  const outputRefusal = await expectRefused(label, [TAMPER_MESSAGE], () => timed(ctx.logger, `tx ${label} with public input ${last} changed (client-side proving)`, send({ ...call, args })), {
    accepted: `a result with public input ${last} changed was accepted`,
  });
  ctx.logger.info(`[client tamper] ${label} with public input ${last} changed under the honest proof: client-side proving refused it, nothing sent: ${outputRefusal.split("\n")[0]}`);
}

async function repeated(ctx: RunContext, step: RepeatedResult): Promise<void> {
  const req = ctx.scope.lookup(step.tipResult) as TipRequestRecord;
  const tip = tipOf(ctx, req.namespace);
  const label = step.what ?? `${step.tipResult} result again`;
  const { result } = await fetchResult(ctx, tip, req, 60);
  const contract = tipContract(ctx, tip, step.from) as unknown as ResultContract;
  const call = await prepareResult(result, { contract, address: tip.address, from: ctx.account(step.from), vkFields: { [result.circuit]: tipVkFields(tip, result.circuit) }, resultFunction: tipResultFunction(tip) });
  const before = await landingState(ctx, tip, req);
  const refusal = await expectRefused(
    label,
    step.refused,
    () => timed(ctx.logger, `tx ${label}: ${call.method} from ${step.from}`, async () => sendResultCall(contract, call, { ...(await feeOptions(ctx.network.feeSetting, "result")) })),
    { accepted: "the landed result was accepted a second time", any: true },
  );
  const after = await landingState(ctx, tip, req);
  check(after === before, `${label}: the state moved: ${before} -> ${after}`);
  ctx.logger.info(`[refused] ${label}: result ${result.parts.machineRequestId} sent again from ${step.from}, refused; queue, done and keys unchanged: ${refusal.split("\n")[0]}`);
}

export default defineKind<TipResultStep>({
  key: "tipResult",
  check(step, s) {
    if (step.again) {
      refs.account(s, step.from);
      check(step.refused.length > 0, "a repeated result takes the substrings of its refusal");
      return { fields: ["tipResult", "again", "from", "refused"] };
    }
    check((step.by === "user") === (step.from !== undefined), "a result the user lands names its sender (from), one the relayer lands none");
    if (step.from !== undefined) refs.account(s, step.from);
    check(!(step.skipped && step.by === "user"), "the relayer skips a stale head");
    check(!step.clientTamper || step.by === "user", "clientTamper is for a result the user lands");
    return { fields: ["tipResult", "by", "from", "clientTamper", "skipped", "name", "expect", "timeoutS"], binds: [step.name] };
  },
  run: (ctx, step) => (step.again ? repeated(ctx, step) : finished(ctx, step)),
  // the transaction that finished the index (a named result's), or any the
  // driver sent (a repeated result's, refused, so none)
  txs(ctx, step, sent) {
    const req = ctx.scope.lookup(step.tipResult) as TipRequestRecord;
    const at = { round: req.circuit, deployment: req.namespace };
    if (step.again || step.name === undefined) return sent.map((txHash) => ({ kind: "result" as const, txHash, ...at }));
    const r = ctx.scope.lookup(step.name) as TipResultRecord;
    return [{ kind: r.status === "skipped" ? ("skip" as const) : ("result" as const), txHash: r.txHash, ...at }];
  },
});
