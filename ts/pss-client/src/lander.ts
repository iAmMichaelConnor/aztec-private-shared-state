// The Lander (docs/ARCHITECTURE.md section 6, rows "result" and "relayer"):
// the one way a queued request's result is landed. One attempt FETCHes the
// latest result by chain request id, builds its result call through the
// circuit's result reader (result.ts: a non-secret-shared intake's public outputs or a
// secret-shared intake's private outcome; capsule, arguments, signatures; the call
// carries no request input) and sends it through the app's result function
// for that circuit (ResultCallSettings.resultFunction); a RetryPolicy says how often
// one result is sent and how a run of attempts is bounded. submitResult (a
// user landing their own result) runs attempts until one lands; pss-relayer
// runs one attempt per tick, between its skip checks. The same lander lands
// the init round (attemptInit): FETCH by the init's fixed chain request id,
// nothing sent once a slot the init creates is written, the app's init
// function otherwise. Every result and init pays its fee under the caller's
// fee setting (fee.ts; default wFJ), as a "result".

import { AztecAddress } from "@aztec-labs/aztec.js/addresses";
import type { Capsule } from "@aztec-labs/aztec.js/tx";

import { stageCapsule, vkHashFromFields } from "./capsule.ts";
import { txSendOptions, type FeeSetting } from "./fee.ts";
import { fieldAddress, fieldHex, type FieldHexString, type FieldLike } from "./field.ts";
import { defaultInitEncoder, initCallContext, type InitCallEncoder } from "./init-result.ts";
import { sleep } from "./sleep.ts";
import { queuedResultKey, resultCallArgs, type QueuedResult } from "./result.ts";
import type { ChainFetchOptions, InitFetchOptions, InitResult } from "./tip-client.ts";
import { DEFAULT_RESULT_METHOD, type ProcessResultEncoder } from "./tip-result.ts";

// ---- one process_result call ----

/** One result or init call, ready to send: the method, its arguments and
 * the (vk, proof) capsule staged under the sender. */
export interface PreparedCall {
  method: string;
  args: unknown[];
  capsule: Capsule;
  from: AztecAddress;
}

/** The (vk, proof) capsule of a result (or the init) staged under the
 * sender, once the vk fields hash to the answer's vk hash (RangeError
 * otherwise). */
async function checkedCapsule(parts: { vkHash: string; proof: string }, settings: ResultCallSettings, circuit: string, what = "the result") {
  const vkFields = Object.hasOwn(settings.vkFields, circuit) ? settings.vkFields[circuit] : undefined;
  if (vkFields === undefined) throw new RangeError(`no vk fields for circuit ${circuit}`);
  const vkHash = fieldHex((await vkHashFromFields([...vkFields])).toBigInt());
  if (vkHash !== parts.vkHash) throw new RangeError(`vk fields hash to ${vkHash}, ${what} was proved under ${parts.vkHash}`);
  const from = fieldAddress(settings.from, "from");
  return { capsule: stageCapsule(settings.address, from, [...vkFields], parts.proof), from };
}

/** What an aztec.js Contract offers for a result call: `methods[name](...args)
 * .with({ capsules }).send(options)`. */
export interface ResultContract {
  methods: Record<string, (...args: never[]) => { with(extra: { capsules: Capsule[] }): { send(options: never): Promise<unknown> } }>;
}

/** Send a prepared call from its `from`, with `sendOptions` (the fee
 * options, wait options) merged in. Returns what send returns; throws what send throws
 * (a private-side refusal at simulation, or a revert of `apply`). */
export async function sendResultCall(contract: ResultContract, call: PreparedCall, sendOptions: Record<string, unknown> = {}): Promise<unknown> {
  const m = contract.methods[call.method];
  if (typeof m !== "function") throw new RangeError(`the contract has no method ${call.method}`);
  const interaction = (m as (...a: unknown[]) => ReturnType<NonNullable<typeof m>>)(...call.args);
  return interaction.with({ capsules: [call.capsule] }).send({ ...sendOptions, from: call.from } as never);
}

/** The app function a result lands through: its name, and the arguments it
 * takes before the library's (examples/lending-tip's secret-shared rounds
 * land through `process_shared(round, ...)` and `process_header_shared(round,
 * ...)`, `args: [round]`, the round's `ROUND_*` index). */
export interface ResultFunction {
  name: string;
  args?: readonly unknown[];
}

/** The result function per circuit (ResultCallSettings.resultFunction)
 * from a map of circuit names to the app's result functions: the listed
 * function for a listed circuit, DEFAULT_RESULT_METHOD (`process_result`)
 * for any other. examples/amm-tip names `process_result_shared` for its
 * secret-shared swap; examples/lending-tip names `process_shared` or
 * `process_header_shared` with the round's `ROUND_*` index for each
 * secret-shared round (e2e/tip/<deployment>.json `methods`). */
export function resultFunctions(methods: Readonly<Record<string, ResultFunction>>): (result: QueuedResult) => ResultFunction {
  return (result) => (Object.hasOwn(methods, result.circuit) ? methods[result.circuit]! : { name: DEFAULT_RESULT_METHOD });
}

/** The process_result call settings shared by submitResult and the relayer. */
export interface ResultCallSettings {
  /** The app contract (aztec.js Contract, or anything with its `methods`). */
  contract: ResultContract;
  /** The app contract's address: the namespace. */
  address: FieldLike | AztecAddress;
  /** The sending account (any account: submission is permissionless). */
  from: FieldLike | AztecAddress;
  /** The 115 vk fields keyed by the circuit name used for landing.
   * An alias's result lands under its target circuit's name. */
  vkFields: Record<string, readonly FieldLike[]>;
  /** The app's argument shape of a public result; default the library's
   * TipResult form. A private outcome takes the library's order. */
  encode?: ProcessResultEncoder;
  /** The app's result function for a result, chosen by its circuit;
   * default `{ name: DEFAULT_RESULT_METHOD }`, `process_result`, for every
   * circuit. */
  resultFunction?: (result: QueuedResult) => ResultFunction;
  /** The fee setting; default DEFAULT_FEE_SETTING (wFJ). The Lander sends
   * every result as its "result" kind. */
  fee?: FeeSetting;
  /** Merged into send() under the fee setting: wait options, which replace
   * SEND_WAIT (`proposed`). */
  sendOptions?: Record<string, unknown>;
}

/** Build the result call of a fetched result of any queued round, through
 * its circuit's result reader: check the circuit's vk fields against the
 * answer's vk hash (RangeError), stage the capsule, and take the circuit's
 * result function with its own arguments, then the reader's call arguments
 * (the public form under `settings.encode`). */
export async function prepareResult(result: QueuedResult, settings: ResultCallSettings): Promise<PreparedCall> {
  const { capsule, from } = await checkedCapsule(result.parts, settings, result.circuit);
  const fn = settings.resultFunction?.(result) ?? { name: DEFAULT_RESULT_METHOD };
  return { method: fn.name, args: [...(fn.args ?? []), ...resultCallArgs(result, settings.encode)], capsule, from };
}

// ---- the lander ----

/** Where a lander FETCHes results: PssClient.fetchChainResult, and for
 * attemptInit PssClient.fetchInitResult. */
export interface ResultSource {
  fetchChainResult(chainRequestId: FieldLike, options?: ChainFetchOptions): Promise<QueuedResult>;
  fetchInitResult?(options: InitFetchOptions): Promise<InitResult>;
}

/** The init round a lander lands (attemptInit). */
export interface InitCallSettings {
  /** The init circuit; its vk fields are `calls.vkFields[circuit]`. */
  circuit: string;
  /** Its app inputs, the constants the app's Config pins; default none. */
  inputs?: readonly FieldLike[];
  /** The app's init function: examples/amm-tip `init_pool`,
   * examples/lending-tip `init_market`. */
  method: string;
  /** The init function's argument shape; default defaultInitEncoder. */
  encode?: InitCallEncoder;
  /** Whether a slot the init creates already holds a commitment (the init
   * landed), read at the latest block; the lander sends nothing then. */
  written(slots: readonly FieldHexString[]): Promise<boolean>;
}

/** How a lander retries. */
export interface RetryPolicy {
  /** How many times one result (its reader's key: the attempt and its
   * outcome) is sent and reverts (isRevert) before the lander holds it and
   * waits for a newer one. Other send failures use a separate retry count. */
  sendsPerResult: number;
  /** land(): the most transactions one run sends. */
  transactions: number;
  /** land(): the wait before FETCHing again after a failed send. */
  refetchDelayMs: number;
}

export interface LanderOptions {
  client: ResultSource;
  /** The process_result call: contract, address, sending account, vk fields
   * per circuit, encoder, method names, fee setting. */
  calls: ResultCallSettings;
  policy: RetryPolicy;
}

/** What one attempt did. FETCH's own refusals and the client's checks are
 * thrown, not returned. */
export type LandAttempt<R = QueuedResult> =
  | { status: "landed"; result: R; sent: unknown }
  /** The send failed; `failures` counts this result's reverts so far. */
  | { status: "failed"; result: R; error: unknown; failures: number }
  /** The same result reverted sendsPerResult times; not sent again. */
  | { status: "held"; result: R; failures: number }
  /** Identical send failures other than reverts delay the next send.
   * `attempted` is false on a tick that only waits. */
  | { status: "backoff"; result: R; error: unknown; failures: number; retryInTicks: number; attempted: boolean };

/** What one init attempt did: as a result attempt, or nothing sent because
 * a slot the init creates is written. */
export type InitLandAttempt = LandAttempt<InitResult> | { status: "written"; result: InitResult };

export interface AttemptOptions<R = QueuedResult> {
  fetch?: ChainFetchOptions;
  /** Called with the result just before its transaction is sent. */
  onSend?: (result: R) => void;
}

// Only mined reverts count toward a hold. A revert costs a proof and a fee,
// and the same result would revert again. Other send failures can clear on
// retry without a mined transaction or fee. Identical failures back off.
/** Whether Aztec reports a mined revert of the landing transaction. */
export function isRevert(error: unknown): boolean {
  return error instanceof Error && /^Transaction (\S+ )?reverted\b/.test(error.message);
}

/** The maximum number of attempts to wait between identical send failures. */
const MAX_SEND_BACKOFF_TICKS = 32;

/** Holds reverted results and backs off after repeated send failures. */
export class Lander {
  private readonly o: LanderOptions;
  private readonly failures = new Map<string, number>();
  private sendRetry?: { key: string; message: string; error: unknown; failures: number; wait: number };

  constructor(options: LanderOptions) {
    const p = options.policy;
    if (!Number.isInteger(p.sendsPerResult) || p.sendsPerResult < 1) throw new RangeError("policy.sendsPerResult: at least 1");
    if (!(p.transactions >= 1)) throw new RangeError("policy.transactions: at least 1");
    this.o = options;
  }

  /** One attempt at chain request `chainRequestId` of any queued round:
   * FETCH its latest result, hold it when it has failed sendsPerResult
   * times, build its result call (prepareResult) and send it. */
  async attempt(chainRequestId: FieldLike, options: AttemptOptions = {}): Promise<LandAttempt> {
    const result = await this.o.client.fetchChainResult(chainRequestId, options.fetch);
    return this.send(queuedResultKey(result), result, () => prepareResult(result, this.o.calls), () => options.onSend?.(result));
  }

  /** One attempt at the init round of `init.circuit`: FETCH its result by
   * the init's fixed chain request id, send nothing when a slot it creates
   * is written (`written`), hold it when it has failed sendsPerResult
   * times, and otherwise build the app's init function call (the (vk,
   * proof) capsule staged as for a result) and send it. */
  async attemptInit(init: InitCallSettings, options: { onSend?: (result: InitResult) => void } = {}): Promise<InitLandAttempt> {
    const source = this.o.client;
    if (source.fetchInitResult === undefined) throw new RangeError("the lander's client has no fetchInitResult");
    const result = await source.fetchInitResult({ circuit: init.circuit, inputs: init.inputs });
    if (await init.written(result.parts.slots)) return { status: "written", result };
    const { parts } = result;
    const key = [parts.machineRequestId, ...parts.newCommitments, ...parts.newHashes].join(",");
    return this.send(key, result, () => this.prepareInit(init, result), () => options.onSend?.(result));
  }

  private async prepareInit(init: InitCallSettings, result: InitResult): Promise<PreparedCall> {
    const { capsule, from } = await checkedCapsule(result.parts, this.o.calls, init.circuit, "the init");
    return { method: init.method, args: (init.encode ?? defaultInitEncoder)(initCallContext(result.parts)), capsule, from };
  }

  /** Send one fetched result's call unless it is held or in backoff. */
  private async send<R>(key: string, result: R, prepare: () => Promise<PreparedCall>, onSend: () => void): Promise<LandAttempt<R>> {
    const failures = this.failures.get(key) ?? 0;
    if (failures >= this.o.policy.sendsPerResult) return { status: "held", result, failures };
    const retry = this.sendRetry?.key === key ? this.sendRetry : undefined;
    if (retry !== undefined && retry.wait > 0) {
      retry.wait--;
      return { status: "backoff", result, error: retry.error, failures: retry.failures, retryInTicks: retry.wait + 1, attempted: false };
    }
    const call = await prepare();
    const { wait, ...fee } = await txSendOptions(this.o.calls.fee, "result");
    const sendOptions = { wait, ...this.o.calls.sendOptions, ...fee };
    onSend();
    try {
      const sent = await sendResultCall(this.o.calls.contract, call, sendOptions);
      this.release();
      return { status: "landed", result, sent };
    } catch (error) {
      if (isRevert(error)) {
        this.sendRetry = undefined;
        this.failures.set(key, failures + 1);
        return { status: "failed", result, error, failures: failures + 1 };
      }
      const message = error instanceof Error ? `${error.name}: ${error.message}` : String(error);
      const repeats = retry?.message === message ? retry.failures + 1 : 1;
      const wait = repeats > 1 ? Math.min(2 ** (repeats - 2), MAX_SEND_BACKOFF_TICKS) : 0;
      this.sendRetry = { key, message, error, failures: repeats, wait };
      if (wait === 0) return { status: "failed", result, error, failures };
      return { status: "backoff", result, error, failures: repeats, retryInTicks: wait + 1, attempted: true };
    }
  }

  /** Clear retry counts after a landing or a chain replacement. */
  release(): void {
    this.failures.clear();
    this.sendRetry = undefined;
  }

  /** Attempts until one lands, waiting refetchDelayMs after each failed
   * send, at most policy.transactions sends. SubmitResultError when the last
   * send failed and FETCH answers no newer result (or the bound is reached). */
  async land(chainRequestId: FieldLike, options: AttemptOptions & { signal?: AbortSignal } = {}): Promise<SubmittedResult> {
    const chain = fieldHex(chainRequestId, "chain_request_id");
    const { transactions, refetchDelayMs } = this.o.policy;
    let lastError: unknown;
    let sent = 0;
    while (sent < transactions) {
      const a = await this.attempt(chain, options);
      if (a.status === "held") break;
      if (a.status !== "backoff" || a.attempted) sent++;
      if (a.status === "landed") return { result: a.result, sent: a.sent, attempts: sent };
      lastError = a.error;
      if (sent < transactions) await sleep(refetchDelayMs, options.signal);
    }
    throw new SubmitResultError(chain, sent, lastError);
  }
}

// ---- submitResult: the user's lander ----

export interface SubmitResultOptions extends ResultCallSettings {
  client: ResultSource;
  chainRequestId: FieldLike;
  fetch?: ChainFetchOptions;
  /** How many results to try; default DEFAULT_SUBMIT_ATTEMPTS. */
  attempts?: number;
  /** Delay before re-fetching after a failed submission; default
   * DEFAULT_REFETCH_DELAY_MS. */
  refetchDelayMs?: number;
  signal?: AbortSignal;
}

export interface SubmittedResult {
  result: QueuedResult;
  /** What send returned (by default the mined transaction's receipt). */
  sent: unknown;
  /** The number of transactions sent, the landed one included. */
  attempts: number;
}

/** A result submission failed and FETCH has no other result to try. */
export class SubmitResultError extends Error {
  readonly chainRequestId: string;
  readonly attempts: number;
  constructor(chainRequestId: string, attempts: number, cause: unknown) {
    super(`chain request ${chainRequestId}: the result transaction failed after ${attempts} attempt(s), and FETCH answers no newer result`, { cause });
    this.name = "SubmitResultError";
    this.chainRequestId = chainRequestId;
    this.attempts = attempts;
  }
}

// submitResult's retry rule. After a failed submission (the private part
// refused at simulation, or `apply` reverted: the head moved, the state
// moved, a pinned read changed, a duplicate) it waits refetchDelayMs
// (default 2,000 ms, a third of a proposed block) and FETCHes the chain
// request again, which answers the latest attempt; it sends again only when
// that is another result (its reader's key: another machine request id or
// outcome), at most `attempts` transactions in all (default 3). The
// scheduler recomputes against the new state after a revert, so the newest
// attempt is the one that can land; re-sending the same result after a
// revert would only revert again and cost another client-side proving run.
// Other send failures (a dropped transaction, an unreachable node) are
// retried within the same transaction bound. Identical failures back off.
// The user's RetryPolicy allows one revert per result. A submission whose
// request was already finished (by the relayer, or skipped) reverts at apply
// with "not the head" and is harmless.
const DEFAULT_SUBMIT_ATTEMPTS = 3;
const DEFAULT_REFETCH_DELAY_MS = 2_000;

/** The user's retry policy (the comment above). */
export const USER_RETRY_POLICY: RetryPolicy = {
  sendsPerResult: 1,
  transactions: DEFAULT_SUBMIT_ATTEMPTS,
  refetchDelayMs: DEFAULT_REFETCH_DELAY_MS,
};

/** FETCH the latest result of a queued request by chain request id, build
 * process_result (capsule, arguments, the state module's arguments, the three
 * signatures) and send it from `from`; after a failure, re-fetch and send a newer result
 * (a Lander under USER_RETRY_POLICY). Throws SubmitResultError when the last
 * attempt failed and FETCH answers no newer result; FETCH's own refusals (404
 * none yet, 409 rolled back) and the client's checks propagate as thrown. */
export async function submitResult(options: SubmitResultOptions): Promise<SubmittedResult> {
  const attempts = options.attempts ?? DEFAULT_SUBMIT_ATTEMPTS;
  if (!Number.isInteger(attempts) || attempts < 1) throw new RangeError("attempts: at least 1");
  const lander = new Lander({
    client: options.client,
    calls: options,
    policy: { ...USER_RETRY_POLICY, transactions: attempts, refetchDelayMs: options.refetchDelayMs ?? DEFAULT_REFETCH_DELAY_MS },
  });
  return lander.land(options.chainRequestId, { fetch: options.fetch, signal: options.signal });
}
