// A tip request (docs/ARCHITECTURE.md section 6): its intake obtained by the
// namespace's pss-client from named inputs through the module of the intake
// its circuit's manifest names (obtainIntake: on-chain intake's tip request;
// receipt intake's three receipts through the orchestrator; secret-shared receipt
// intake's shared inputs sealed to the nodes and their receipts over the
// inputs commitment C; secret-shared on-chain intake's encoded shares under the
// nodes' enc keys the contract stores, read here from its `get_enc_key`
// view as the request function reads them at its anchor block) and sent through the app's request function from any
// account (requestIntake). A round under partial-note delivery (its C commits
// `$partial_note`, or a non-secret-shared round takes it as a clear input)
// takes the sender's next request secrets from a SecretStore of the sender's
// in the deployment (SecretStore.nextPartial): the partial note of the
// sender's address as the input, `rho` in its place among the request
// function's arguments (which computes the partial note itself), and under
// secret-shared receipt intake the derived outcome key and tag; a round whose
// C commits a delivery handle takes the sender's handle of the same request
// counter (SecretStore.handle), its randomness in the partial commitment's
// place. Under the
// public completion (a non-secret-shared round) the request function tells
// the sender's PXE of the partial note offchain, and the step hands the send
// result's offchain messages to the app's `offchain_receive`, as a client
// does, so the PXE completes the note when the result lands. Or an earlier
// request's arguments sent again exactly, or a new
// request the contract's intake refuses, either of which must leave the
// queue unchanged.
import { Fr } from "@aztec-labs/aztec.js/fields";
import {
  SecretStore,
  fieldHex,
  HANDLE_PARTIAL_NAME,
  intakeRequestLogs,
  intakeSummary,
  offchainReceiveArgs,
  PARTIAL_NOTE_NAME,
  storedEncKeys,
  type EncKeyReader,
  type SentOffchainMessage,
  type FieldLike,
  type IntakeRequest,
  type IntakeSendOptions,
  type IntakeTarget,
  type NextHandle,
  type NextPartialRequest,
  type RequestIntake,
  type RequestIntakeOptions,
} from "@aztec-pss/pss-client";

import type { RunContext } from "../engine/context.ts";
import { expectRefused } from "../engine/machine.ts";
import { defineKind, refs, type Common } from "../engine/kind.ts";
import { big, check, fieldLike, type Value } from "../engine/scope.ts";
import { minedTx, queueIndexOf, tipContract, tipOf, type Tip, methodsOf } from "../engine/tip.ts";
import { timed } from "../harness/harness.ts";
import type { Scenario } from "../scenario.ts";

interface RequestCall extends Common {
  /** The package (circuit name) the request is for. */
  tipRequest: string;
  /** The tip deployment (default: the scenario's first). */
  namespace?: string;
  /** The sending account; no request names it. */
  from: string;
  /** The app's request function for the circuit's intake. */
  method: string;
}

/** A new request from named app inputs, which must be queued at the tail,
 * or, with `refused`, be refused by the request function. */
export interface NewTipRequest extends RequestCall {
  inputs: Record<string, Value>;
  /** A request function that takes a private value in place of an app
   * input it derives from it gets that value at the input's place: by
   * input name (lending's non-secret-shared rounds take `owner_secret` where the
   * request holds the input `owner`, its owner commitment). */
  privateArgs?: Record<string, Value>;
  /** Binds the request (`TipRequestRecord`). */
  name?: string;
  /** A copy with one Chonk proof field changed is sent first; the node
   * must refuse it (a real-proof run's node-side negative). */
  nodeTamper?: true;
  /** The request function must refuse the request with a message holding
   * every substring, the queue unchanged (the contract's static checks). */
  refused?: string[];
  again?: never;
}
/** The intake of an earlier request sent again: the transaction must be
 * refused with a message containing every substring, the queue unchanged. */
export interface RepeatedTipRequest extends RequestCall {
  again: string;
  refused: string[];
  inputs?: never;
  privateArgs?: never;
  name?: never;
  nodeTamper?: never;
}
export type TipRequestStep = NewTipRequest | RepeatedTipRequest;

/** What a request step binds. */
export interface TipRequestRecord {
  circuit: string;
  namespace: string;
  /** The chain request id: no requester, so any account sending the same
   * inputs and nonce (or C) sends the same request. */
  chainRequestId: string;
  /** The non-secret-shared intakes' user nonce; undefined under a secret-shared intake. */
  userNonce?: string;
  intake: RequestIntake;
  /** The request function's arguments as sent. */
  args: unknown[];
  method: string;
  from: string;
  index: number;
  block: number;
  txHash: string;
  /** Under a secret-shared intake: the outcome key and tag the client drew, which
   * open and find the request's outcome log. */
  outcomeKey?: string;
  outcomeTag?: string;
  /** Under partial-note delivery: the request's rho, from which the
   * completed note is rebuilt (its owner is `from`). */
  rho?: string;
  /** A request that leaves a delivery handle (its C commits `handle_partial`
   * and `handle_key`): the handle's randomness and key, under which a later
   * round's delivery to `from` is found, opened and rebuilt. */
  handleRho?: string;
  handleKey?: string;
}

/** A sent request, before its checks. */
export interface SentRequest {
  step: NewTipRequest;
  tip: Tip;
  intake: RequestIntake;
  partial?: NextPartialRequest;
  handle?: NextHandle;
  args: unknown[];
  chainRequestId: string;
  tailBefore: number;
  block: number;
  txHash: string;
}

/** Sends `request` through the app's request function `method` from
 * `from` with pss-client's requestIntake, paying the run's fee setting's
 * request fee. */
async function send(ctx: RunContext, tip: Tip, from: string, method: string, request: IntakeRequest, options: RequestIntakeOptions = {}) {
  const target = { contract: tipContract(ctx, tip, from), method } as unknown as IntakeTarget<{ receipt: { txHash: { toString(): string }; blockNumber?: number } }>;
  const sendOptions: IntakeSendOptions = { from: ctx.account(from) };
  return ctx.client(tip.name).requestIntake(target, request, sendOptions, { fee: ctx.network.feeSetting, ...options });
}

const CALL = ["tipRequest", "namespace", "from", "method"];

export function checkRequestStep(step: TipRequestStep, s: Scenario): { fields: readonly string[]; binds?: (string | undefined)[] } {
  refs.tip(s, step.namespace);
  refs.account(s, step.from);
  if (step.again !== undefined) {
    check(step.refused?.length, "an `again` request takes the substrings of its refusal (refused)");
    return { fields: [...CALL, "again", "refused"] };
  }
  check(step.inputs !== undefined, "a new request takes its inputs");
  if (step.refused !== undefined) {
    check(step.refused.length > 0 && step.name === undefined && !step.nodeTamper, "a refused request takes the substrings of its refusal, and no name or nodeTamper");
    return { fields: [...CALL, "inputs", "privateArgs", "refused"] };
  }
  return { fields: [...CALL, "inputs", "privateArgs", "name", "nodeTamper"], binds: [step.name] };
}

// The request secrets of each sender in each deployment: one SecretStore per
// (run, deployment, account), its wallet secret drawn for the run, as a
// wallet keeps one per app.
const stores = new WeakMap<RunContext, Map<string, SecretStore>>();
function secretStore(ctx: RunContext, tip: Tip, from: string): SecretStore {
  let byKey = stores.get(ctx);
  if (!byKey) stores.set(ctx, (byKey = new Map()));
  const key = `${tip.name}/${from}`;
  let store = byKey.get(key);
  if (!store) byKey.set(key, (store = new SecretStore(Fr.random().toBigInt(), tip.address.toBigInt())));
  return store;
}

/** The request's intake through its circuit's manifest, obtained. */
async function obtain(
  ctx: RunContext,
  step: NewTipRequest,
  tip: Tip,
  label: string,
): Promise<{ intake: RequestIntake; currentBlock: number; partial?: NextPartialRequest; handle?: NextHandle }> {
  const client = ctx.client(tip.name);
  check(Object.hasOwn(client.config.intakeLayouts, step.tipRequest), `${label}: ${step.tipRequest} is not a tip package of ${tip.name}`);
  const layout = client.config.intakeLayouts[step.tipRequest]!;
  // under partial-note delivery the sender's next request secrets: its
  // partial note (a shared `$partial_note`, or the clear input
  // layout.partialNote of a non-secret-shared round), and the derived outcome
  // key and tag (taken by the secret-shared intakes)
  const takes = layout.commitment.includes(PARTIAL_NOTE_NAME) || layout.partialNote !== undefined;
  const next = takes ? await secretStore(ctx, tip, step.from).nextPartial(ctx.account(step.from).toBigInt()) : undefined;
  const partial = next && layout.partialNote !== undefined ? clearPartial(next, layout.partialNote) : next;
  // a round whose C commits a delivery handle: the handle of the same
  // request counter, the sender's (the request function takes its
  // randomness in the partial commitment's place)
  const handle =
    next !== undefined && layout.commitment.includes(HANDLE_PARTIAL_NAME)
      ? await secretStore(ctx, tip, step.from).handle(ctx.account(step.from).toBigInt(), next.n)
      : undefined;
  // an account's address is the field of its address
  const inputs = Object.fromEntries(
    Object.entries({ ...(ctx.scope.resolve(step.inputs) as Record<string, unknown>), ...partial?.inputs, ...handle?.inputs }).map(([k, v]) => [k, Array.isArray(v) ? v.map(fieldLike) : fieldLike(v)]),
  ) as Record<string, FieldLike | FieldLike[]>;
  const currentBlock = await ctx.network.node.getBlockNumber();
  // the stored enc keys, read only by an intake that encodes under them
  const keys = async () => {
    // read at the latest block: what the request function reads at the anchor
    // block it is proven against, unless a rotation lands meanwhile (the
    // contract then still takes the epoch before the stored one)
    const k = await storedEncKeys(tipContract(ctx, tip, step.from) as unknown as EncKeyReader, ctx.account(step.from));
    ctx.logger.info(`${label}: the nodes' enc keys in ${tip.name} at epochs [${k.map((e) => e.epoch).join(", ")}]`);
    return k;
  };
  if (partial) ctx.logger.info(`${label}: ${step.from}'s request ${partial.n} in ${tip.name}, its partial note ${partial.partialNote}`);
  if (handle) ctx.logger.info(`${label}: ${step.from}'s delivery handle ${handle.handlePartial}`);
  const intake = await timed(ctx.logger, `${label}: the intake of ${step.tipRequest}`, () =>
    client.obtainIntake({ circuit: step.tipRequest, inputs, currentBlock, encKeys: keys, ...(partial && { secrets: partial.secrets }) }),
  );
  const s = intakeSummary(intake);
  ctx.logger.info(
    `${label}: ${intake.intake} intake of request ${s.chainRequestId}` +
      (s.expiryBlock === undefined ? "" : `, three receipts expiring at block ${s.expiryBlock} (current ${currentBlock})`) +
      (s.outcomeTag === undefined ? "" : `, its outcome under tag ${s.outcomeTag}`),
  );
  return { intake, currentBlock, partial, handle };
}

/** A partial note as a non-secret-shared round's clear input `name`: the
 * request holds the partial note under that name, the request function
 * takes `rho` in its place. */
function clearPartial(next: NextPartialRequest, name: string): NextPartialRequest {
  return { ...next, inputs: { [name]: next.partialNote } as never, values: { [name]: next.rho } as never };
}

/** Hands the send result's offchain messages for `from` to the app's
 * `offchain_receive` (the public completion's partial-note message). */
async function receiveOffchain(ctx: RunContext, tip: Tip, from: string, sent: unknown, txHash: string, label: string): Promise<void> {
  const messages = (sent as { offchainMessages?: SentOffchainMessage[] }).offchainMessages ?? [];
  const args = offchainReceiveArgs(messages, tip.address, ctx.account(from), txHash);
  check(args.length === 1, `${label}: the request emitted ${args.length} offchain messages for ${from}, not its partial note's one`);
  const app = methodsOf(tipContract(ctx, tip, from));
  await timed(ctx.logger, `${label}: offchain_receive of ${from}'s partial-note message`, () => app.offchain_receive!(args).simulate({ from: ctx.account(from) }));
}

/** The values a request function takes in place of the intake's
 * (`privateArgs`, the partial note's rho and the handle's randomness), by
 * name. */
function privateValues(ctx: RunContext, step: NewTipRequest, partial?: NextPartialRequest, handle?: NextHandle): Record<string, FieldLike> | undefined {
  if (step.privateArgs === undefined && partial === undefined && handle === undefined) return undefined;
  return {
    ...Object.fromEntries(Object.entries((ctx.scope.resolve(step.privateArgs ?? {}) as Record<string, unknown>)).map(([k, v]) => [k, big(v)])),
    ...partial?.values,
    ...handle?.values,
  };
}

/** The request's intake through its circuit's manifest, sent; returns once
 * the transaction is mined. */
export async function sendRequest(ctx: RunContext, step: NewTipRequest): Promise<SentRequest> {
  const tip = tipOf(ctx, step.namespace);
  const label = step.what ?? step.name ?? step.tipRequest;
  const tailBefore = (await tip.queue.snapshot()).tail;
  const { intake, currentBlock, partial, handle } = await obtain(ctx, step, tip, label);
  if (step.nodeTamper) ctx.network.checks?.rejectTamperedCopyOfNextTx(label);
  const { args, sent } = await timed(ctx.logger, `tx ${label} (${step.method}, ${intake.intake} intake)${step.nodeTamper ? " (with the node-side negative)" : ""}`, () =>
    send(ctx, tip, step.from, step.method, { circuit: step.tipRequest, intake }, { currentBlock, values: privateValues(ctx, step, partial, handle) }),
  );
  check(sent.receipt.blockNumber !== undefined, `${label}: the request has no block`);
  const txHash = sent.receipt.txHash.toString();
  if (partial !== undefined && ctx.client(tip.name).config.intakeLayouts[step.tipRequest]!.partialNote !== undefined) await receiveOffchain(ctx, tip, step.from, sent, txHash, label);
  return { step, tip, intake, partial, handle, args, chainRequestId: intakeSummary(intake).chainRequestId, tailBefore, block: Number(sent.receipt.blockNumber), txHash };
}

/** The checks of a mined request: queued once at the tail under the id the
 * client computed, and what the intake put on the chain; binds `name`. */
export async function checkRequest(ctx: RunContext, sent: SentRequest): Promise<TipRequestRecord> {
  const { step, tip } = sent;
  const label = step.what ?? step.name ?? step.tipRequest;
  const { index, tail } = await queueIndexOf(tip, sent.chainRequestId, sent.block, sent.tailBefore);
  check(index !== undefined, `${label}: chain request ${sent.chainRequestId} is not in the queue at block ${sent.block} (tail ${tail})`);
  const tx = await minedTx(ctx, tip, sent.txHash, sent.block);
  // the public logs the request function emits under its intake (on-chain
  // intake: [tag, inputs..., user_nonce], no address; the others none: only
  // the request id and the expiry reach the chain)
  const logs = await intakeRequestLogs(sent.intake);
  const got = tx.logs.map((l) => l.map((f) => fieldHex(f.toBigInt())));
  check(JSON.stringify(got) === JSON.stringify(logs), `${label}: the request logged ${JSON.stringify(got)}; its ${sent.intake.intake} intake logs ${JSON.stringify(logs)}`);
  ctx.logger.info(
    `${label}: ${step.tipRequest} request ${sent.chainRequestId} queued at index ${index} of ${tip.name} in block ${sent.block} (tx ${sent.txHash}); ` +
      `${logs.length} public log(s), as its ${sent.intake.intake} intake gives them`,
  );
  const s = intakeSummary(sent.intake);
  const record: TipRequestRecord = {
    circuit: step.tipRequest,
    namespace: tip.name,
    chainRequestId: sent.chainRequestId,
    userNonce: s.userNonce,
    intake: sent.intake,
    args: sent.args,
    method: step.method,
    from: step.from,
    index,
    block: sent.block,
    txHash: sent.txHash,
    outcomeKey: s.outcomeKey,
    outcomeTag: s.outcomeTag,
    rho: sent.partial?.rho,
    handleRho: sent.handle?.handleRho,
    handleKey: sent.handle?.handleKey,
  };
  if (step.name) ctx.scope.set(step.name, record);
  return record;
}

/** A request the contract must refuse: sent (or simulated, where the
 * wallet's simulation refuses it first) with the refusal holding every
 * substring, the queue unchanged. */
async function refusedSend(ctx: RunContext, tip: Tip, label: string, what: string, refused: string[], send: () => Promise<unknown>): Promise<void> {
  const before = await tip.queue.snapshot();
  const sentBefore = ctx.network.sentTxs.size;
  const refusal = await expectRefused(label, refused, () => timed(ctx.logger, `tx ${label} (${what})`, send), { accepted: "the request was accepted" });
  const after = await tip.queue.snapshot();
  check(after.tail === before.tail && after.head === before.head, `${label}: the queue moved (head ${before.head} -> ${after.head}, tail ${before.tail} -> ${after.tail})`);
  const mined = ctx.network.sentTxs.size > sentBefore;
  ctx.logger.info(
    `[refused] ${label}: ${mined ? "mined and reverted" : "refused in the wallet's simulation, nothing sent"}; queue unchanged (head ${after.head}, tail ${after.tail}): ${refusal.split("\n")[0]}`,
  );
}

async function repeated(ctx: RunContext, step: RepeatedTipRequest): Promise<void> {
  const label = step.what ?? `${step.again} again`;
  const earlier = ctx.scope.lookup(step.again) as TipRequestRecord;
  const tip = tipOf(ctx, earlier.namespace);
  await refusedSend(ctx, tip, label, `${step.method}, ${earlier.intake.intake} intake, request ${fieldHex(earlier.chainRequestId)} from ${step.from}`, step.refused, () =>
    send(ctx, tip, step.from, step.method, { args: earlier.args }, {}),
  );
}

async function refusedNew(ctx: RunContext, step: NewTipRequest & { refused: string[] }): Promise<void> {
  const tip = tipOf(ctx, step.namespace);
  const label = step.what ?? step.tipRequest;
  const { intake, currentBlock, partial, handle } = await obtain(ctx, step, tip, label);
  await refusedSend(ctx, tip, label, `${step.method}, ${intake.intake} intake, from ${step.from}`, step.refused, () =>
    send(ctx, tip, step.from, step.method, { circuit: step.tipRequest, intake }, { currentBlock, values: privateValues(ctx, step, partial, handle) }),
  );
}

export default defineKind<TipRequestStep>({
  key: "tipRequest",
  check: checkRequestStep,
  async run(ctx, step) {
    if (step.again !== undefined) return repeated(ctx, step);
    if (step.refused !== undefined) return refusedNew(ctx, step as NewTipRequest & { refused: string[] });
    await checkRequest(ctx, await sendRequest(ctx, step));
  },
  txs: (ctx, step, sent) => sent.map((txHash) => ({ kind: "request", txHash, round: step.tipRequest, deployment: ctx.namespace(step.namespace) })),
});
