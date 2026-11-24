// The relayer's loop (docs/ARCHITECTURE.md section 6, row "relayer"): read
// the queue at one block; before anything was ever queued, land the init
// round (FETCH by the init's fixed chain request id, the app's init function,
// which enqueues apply_init) until a slot it creates is written; for a
// non-empty queue either send skip() for a stale head or FETCH the head's
// latest result by chain request id and land it through the result function
// of its circuit (process_result by default; it enqueues apply), a non-secret-shared
// intake's public outputs or a secret-shared intake's private outcome, all through
// pss-client's Lander, one attempt per tick.
// Everything chain- or network-specific comes in through interfaces (a
// QueueReader, a PssClient, a ResultContract, a skip sender, the init's slot
// reader), so the loop is unit-tested without a network and an embedder
// builds it the same way main.ts does.

import {
  Lander,
  SidecarError,
  TransportError,
  isQueued,
  sleep,
  type InitCallSettings,
  type InitResult,
  type LandAttempt,
  type PssClient,
  type QueueReader,
  type QueueSnapshot,
  type QueuedResult,
  type ResolvedConfig,
  type ResultCallSettings,
} from "@aztec-pss/pss-client";

/** What one tick did. */
export type TickOutcome =
  | { action: "idle"; snapshot: QueueSnapshot }
  | { action: "skipped"; snapshot: QueueSnapshot; sent: unknown }
  | { action: "skip-failed"; snapshot: QueueSnapshot; error: unknown }
  | { action: "landed"; snapshot: QueueSnapshot; result: QueuedResult; sent: unknown }
  | { action: "submit-failed"; snapshot: QueueSnapshot; result: QueuedResult; error: unknown; failures: number }
  | { action: "init-landed"; snapshot: QueueSnapshot; result: InitResult; sent: unknown }
  | { action: "init-failed"; snapshot: QueueSnapshot; result: InitResult; error: unknown; failures: number }
  | { action: "submit-backoff"; snapshot: QueueSnapshot; result: QueuedResult | InitResult; error: unknown; failures: number; retryInTicks: number }
  | { action: "waiting"; snapshot: QueueSnapshot; reason: string };

/** A tick that threw (a refused FETCH answer, a failed queue read): the
 * error, also thrown to the caller. */
export interface TickError {
  action: "error";
  error: unknown;
}

/** Where the init round stands for the relayer: still to land, landed by
 * its own transaction, or found written (landed by anyone). */
export type InitStatus = { state: "pending" } | { state: "landed"; tx: string | undefined } | { state: "written" };

export interface RelayerLog {
  info(msg: string): void;
  warn(msg: string): void;
}

export interface RelayerOptions {
  /** The pss-client of the queue's tip circuits; their registered manifests
   * give the stale period (staleBlocksOfClient). */
  client: PssClient;
  queue: QueueReader;
  /** The result call: contract, address, sending account, vk fields per
   * circuit, encoder, the result function per circuit (resultFunctions), fee
   * payment. */
  calls: ResultCallSettings;
  /** Send `skip()` on the app contract and wait for it (to `proposed`,
   * pss-client's SEND_WAIT). */
  skip: () => Promise<unknown>;
  /** The app's init round, which the relayer lands before the queue runs
   * (the init circuit and inputs, the app's init function, the slot
   * reader); none for a deployment whose init is landed otherwise. */
  init?: InitCallSettings;
  /** Default DEFAULT_MAX_SAME_RESULT_SENDS. */
  maxSameResultSends?: number;
  /** Default DEFAULT_RELAYER_POLL_INTERVAL_MS; a whole number of ms, at least 1. */
  pollIntervalMs?: number;
  log?: RelayerLog;
}

// Operator knob: DESIGN.md, "Configuration reference" (pss-relayer
// pollIntervalMs). The queue is read once per period, default 2,000 ms; ticks
// never overlap, each starting one period after the last one ends.
export const DEFAULT_RELAYER_POLL_INTERVAL_MS = 2_000;

// The Lander holds a result after maxSameResultSends mined reverts.
// Each tick checks FETCH for a newer attempt. Identical send failures
// other than reverts delay retries of the same result and appear in
// GET /status as submit-backoff. A replaced block releases held results
// and clears the retry counts.
const DEFAULT_MAX_SAME_RESULT_SENDS = 2;

// The skip rule. The relayer sends skip() exactly when the queue is not
// empty (head < tail) and the latest block it read is at or after
// head_since + stale_blocks; never for an empty queue, never before the
// period, never when the manifests disable skipping (stale_blocks null). The
// transaction lands in a later block than the one read, so the contract's
// check (block_number - head_since >= stale_blocks) holds when it lands. When
// the head is stale the relayer skips it rather than landing a result for it,
// as the scheduler stops working on a head older than stale_blocks.
// Re-sending skip(). A skip() that fails (a dropped transaction, an empty
// fee balance) is sent again after a backoff: after the k-th failure in a row
// for one head the relayer lets min(2^(k-1), MAX_SKIP_BACKOFF_TICKS) ticks
// pass before the next send, so a skip that keeps failing costs a send about
// once a minute at the default period, not every tick. A skip that lands, or
// a head that moves, starts the count again.
export const MAX_SKIP_BACKOFF_TICKS = 32;

/** Whether the relayer skips the head of `s` with this stale period. */
export function shouldSkip(s: QueueSnapshot, staleBlocks: number | null): boolean {
  return staleBlocks !== null && s.head < s.tail && s.block >= s.headSince + staleBlocks;
}

/** The stale period of a pss-client configuration (`staleBlocks`): the
 * namespace's contract manifest's `queue.stale_blocks`, in L2 blocks, or
 * null when a head is never skipped. It is the value the contract's
 * constructor took from the same contract manifest (staleBlocksOf) and the
 * nodes check the stored value against, so the relayer skips at the block
 * the contract allows. RangeError when the configuration gives none or has
 * no tip circuit (queued intake). */
export function staleBlocksOfClient(config: ResolvedConfig): number | null {
  if (!Object.values(config.manifests).some(isQueued)) throw new RangeError("circuits: no tip circuit (queued intake), so no stale period");
  if (config.staleBlocks === undefined) {
    throw new RangeError("staleBlocks: missing; give the stale period of the namespace's contract manifest (queue.stale_blocks, or null)");
  }
  return config.staleBlocks;
}

/** The operator's relayer: `tick()` once, or `run()` until stopped. */
export class Relayer {
  private readonly o: RelayerOptions;
  private readonly lander: Lander;
  private controller: AbortController | undefined;
  private running: Promise<void> | undefined;
  /** The stale period it skips by (staleBlocksOfClient of its client). */
  readonly staleBlocks: number | null;
  /** The last tick's outcome, for the status endpoint and tests. */
  last: TickOutcome | TickError | undefined;
  /** The init round's status, with `options.init`. */
  initStatus: InitStatus | undefined;
  /** The failed skip() sends of one head in a row, and the ticks left
   * before the next send. */
  private skipBackoff: { head: number; failures: number; wait: number } | undefined;
  /** The last tick's queue snapshot, for detecting replaced blocks. */
  private lastSnapshot: QueueSnapshot | undefined;
  /** The slots the init round creates, from its last fetched result. */
  private initSlots: InitResult["parts"]["slots"] | undefined;

  constructor(options: RelayerOptions) {
    this.staleBlocks = staleBlocksOfClient(options.client.config);
    this.o = options;
    this.initStatus = options.init && { state: "pending" };
    const period = options.pollIntervalMs ?? DEFAULT_RELAYER_POLL_INTERVAL_MS;
    if (!Number.isInteger(period) || period < 1) throw new RangeError(`pollIntervalMs: a whole number of ms, at least 1, not ${period}`);
    this.lander = new Lander({
      client: options.client,
      calls: options.calls,
      policy: { sendsPerResult: options.maxSameResultSends ?? DEFAULT_MAX_SAME_RESULT_SENDS, transactions: Infinity, refetchDelayMs: period },
    });
  }

  private get log(): RelayerLog {
    return this.o.log ?? { info: () => {}, warn: () => {} };
  }

  /** One pass: read the queue, then skip, land, or wait. A tick that
   * throws is recorded as `last` and rethrown. */
  async tick(): Promise<TickOutcome> {
    try {
      const outcome = await this.step();
      this.last = outcome;
      return outcome;
    } catch (error) {
      this.last = { action: "error", error };
      throw error;
    }
  }

  private async step(): Promise<TickOutcome> {
    const snapshot = await this.o.queue.snapshot();
    const last = this.lastSnapshot;
    this.lastSnapshot = snapshot;
    if (last !== undefined && (
      snapshot.block < last.block ||
      snapshot.head < last.head ||
      (snapshot.block === last.block && snapshot.blockHash !== last.blockHash)
    )) {
      this.log.warn(`the chain view changed (block ${last.block} -> ${snapshot.block}, head ${last.head} -> ${snapshot.head}): held results are sent again`);
      this.lander.release();
      this.skipBackoff = undefined;
    }
    if (this.o.init !== undefined) {
      if (snapshot.tail > 0) {
        // a request was queued, so the init landed (every request function
        // asserts the slot initialised)
        if (this.initStatus?.state === "pending") this.initStatus = { state: "written" };
      } else if (this.initStatus?.state !== "pending") {
        const written = await this.initStillWritten();
        if (written !== true) {
          // nothing is queued and the init's slots are empty again (a
          // replaced block took the landed init with it), or this relayer
          // never read them: the init step fetches the init and checks
          this.log.warn(
            written === false
              ? "the init round is no longer on the chain (its slots are empty): landing it again"
              : "nothing is queued and this relayer has not read the init round's slots: fetching the init to check them",
          );
          this.initStatus = { state: "pending" };
          this.lander.release();
        }
      }
      if (this.initStatus?.state === "pending") return this.initStep(snapshot);
    }
    if (snapshot.head >= snapshot.tail) return { action: "idle", snapshot };
    if (shouldSkip(snapshot, this.staleBlocks)) {
      const backoff = this.skipBackoff?.head === snapshot.head ? this.skipBackoff : undefined;
      if (backoff !== undefined && backoff.wait > 0) {
        backoff.wait--;
        return { action: "waiting", snapshot, reason: `skip() failed ${backoff.failures} time(s); next send in ${backoff.wait + 1} tick(s)` };
      }
      this.log.info(`head ${snapshot.head} stale since block ${snapshot.headSince} (now ${snapshot.block}): skip()`);
      try {
        const sent = await this.o.skip();
        this.skipBackoff = undefined;
        return { action: "skipped", snapshot, sent };
      } catch (error) {
        const failures = (backoff?.failures ?? 0) + 1;
        this.skipBackoff = { head: snapshot.head, failures, wait: Math.min(2 ** (failures - 1), MAX_SKIP_BACKOFF_TICKS) };
        this.log.warn(`skip() failed (${failures} time(s) in a row): ${(error as Error).message}`);
        return { action: "skip-failed", snapshot, error };
      }
    }
    const id = snapshot.headRequest!;
    const fetched = await this.fetched(snapshot, "", () =>
      this.lander.attempt(id, {
        onSend: (result) => this.log.info(`landing ${result.circuit} result for queue index ${snapshot.head} (attempt ${result.parts.machineRequestId})`),
      }),
    );
    if ("wait" in fetched) return fetched.wait;
    const { attempt } = fetched;
    const { result } = attempt;
    switch (attempt.status) {
      case "backoff":
        return this.submitBackoff(snapshot, attempt);
      case "held":
        return { action: "waiting", snapshot, reason: `result ${result.parts.machineRequestId} reverted ${attempt.failures} time(s); waiting for a newer attempt or the stale period` };
      case "landed":
        return { action: "landed", snapshot, result, sent: attempt.sent };
      case "failed":
        this.log.warn(`the ${result.circuit} result failed (${attempt.failures} revert(s) of this result): ${(attempt.error as Error).message}`);
        return { action: "submit-failed", snapshot, result, error: attempt.error, failures: attempt.failures };
    }
  }

  // The init round uses the same retry policy as a queued result. While the
  // queue is empty, the relayer checks that its slots are still written and
  // lands it again if a replaced block removed it.
  private async initStep(snapshot: QueueSnapshot): Promise<TickOutcome> {
    const init = this.o.init!;
    const fetched = await this.fetched(snapshot, "init ", () =>
      this.lander.attemptInit(init, {
        onSend: (result) => this.log.info(`landing the init round: ${init.method} with the ${result.circuit} result (init id ${result.chainRequestId})`),
      }),
    );
    if ("wait" in fetched) return fetched.wait;
    const { attempt } = fetched;
    const { result } = attempt;
    this.initSlots = result.parts.slots;
    switch (attempt.status) {
      case "backoff":
        return this.submitBackoff(snapshot, attempt);
      case "written":
        this.initStatus = { state: "written" };
        this.log.info(`init round: slot ${result.parts.slots.join(", ")} already written; the queue runs`);
        return { action: "idle", snapshot };
      case "landed": {
        const tx = txHashOf(attempt.sent);
        this.initStatus = { state: "landed", tx };
        this.log.info(`init round landed${tx ? ` in ${tx}` : ""}: slot ${result.parts.slots.join(", ")} = ${result.parts.newCommitments.join(", ")}`);
        return { action: "init-landed", snapshot, result, sent: attempt.sent };
      }
      case "held":
        return { action: "waiting", snapshot, reason: `init result reverted ${attempt.failures} time(s); waiting for a newer attempt` };
      case "failed":
        this.log.warn(`${init.method} failed (${attempt.failures} revert(s) of this result): ${(attempt.error as Error).message}`);
        return { action: "init-failed", snapshot, result, error: attempt.error, failures: attempt.failures };
    }
  }

  private submitBackoff(snapshot: QueueSnapshot, attempt: Extract<LandAttempt<QueuedResult | InitResult>, { status: "backoff" }>): TickOutcome {
    const { result, error, failures, retryInTicks } = attempt;
    if (attempt.attempted) {
      this.log.warn(`${result.circuit} sends failed ${failures} times with the same error (retry in ${retryInTicks} ticks): ${error instanceof Error ? error.message : String(error)}`);
    }
    return { action: "submit-backoff", snapshot, result, error, failures, retryInTicks };
  }

  /** Whether a slot the init creates is still written; undefined when the
   * relayer never fetched the init (it learned the init landed from a
   * queued request), so the next tick fetches it and checks. */
  private async initStillWritten(): Promise<boolean | undefined> {
    if (this.initSlots === undefined) return undefined;
    return this.o.init!.written(this.initSlots);
  }

  /** One lander attempt at a result (`round` "") or the init round
   * ("init "), or a wait while FETCH has no committed attempt (404
   * not_found), the latest attempt was rolled back (409 conflict) or the
   * orchestrator is unreachable. */
  private async fetched<A>(snapshot: QueueSnapshot, round: string, attempt: () => Promise<A>): Promise<{ attempt: A } | { wait: TickOutcome }> {
    try {
      return { attempt: await attempt() };
    } catch (e) {
      if (e instanceof SidecarError && (e.class === "not_found" || e.class === "conflict")) {
        return { wait: { action: "waiting", snapshot, reason: e.class === "not_found" ? `no ${round}result yet` : `the latest ${round}attempt was rolled back` } };
      }
      if (e instanceof TransportError) return { wait: { action: "waiting", snapshot, reason: `orchestrator unreachable: ${e.message}` } };
      throw e;
    }
  }

  /** Tick every pollIntervalMs until stop(); a tick that throws is logged and
   * the loop goes on. */
  start(): void {
    if (this.running) return;
    const controller = new AbortController();
    this.controller = controller;
    const period = this.o.pollIntervalMs ?? DEFAULT_RELAYER_POLL_INTERVAL_MS;
    this.running = (async () => {
      while (!controller.signal.aborted) {
        try {
          await this.tick();
        } catch (e) {
          this.log.warn(`tick failed: ${(e as Error).stack ?? e}`);
        }
        await sleep(period, controller.signal).catch(() => undefined);
      }
    })();
  }

  /** Stop the loop and wait for the current tick to end. */
  async stop(): Promise<void> {
    this.controller?.abort();
    await this.running;
    this.running = undefined;
  }
}

/** The transaction hash of what send() returned (aztec.js: `{ receipt }`,
 * the mined transaction's receipt), when it carries one. */
function txHashOf(sent: unknown): string | undefined {
  const h = (sent as { receipt?: { txHash?: unknown } } | null | undefined)?.receipt?.txHash;
  return h === undefined || h === null ? undefined : String(h);
}
