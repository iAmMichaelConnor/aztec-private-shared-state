// The driver's ways into the machine besides pss-client: a fetch that can
// lose one answer, a POST past the client's checks, the nodes' admin sockets,
// and the refusal expectations every step shares.
import type { Logger } from "@aztec-labs/aztec.js/log";
import { SidecarError, adminSocket, parseExecuteResponse, sidecarError, type AdminAnswer, type ExecuteResponse } from "@aztec-pss/pss-client";

import { join } from "node:path";

import type { Harness } from "../harness/harness.ts";
import { check, type Scope } from "./scope.ts";

// The client's request timeout, 600 s instead of pss-client's
// 120 s default. A round is witness extension and proving over the mesh,
// seconds on an idle host, but a concurrent run and client-side transaction
// proving share the CPU; a round that outlived 120 s would go through the
// FETCH path (harmless, but it would fail the `via execute` check and make a
// lost-answer step indistinguishable from a slow round). A longer value only
// delays the failure of a dead orchestrator.
export const REQUEST_TIMEOUT_MS = 600_000;

/** A refusal the machine must answer: its class, HTTP status, and substrings
 * (references and templates allowed) its message must contain. */
export interface Refusal {
  class: string;
  status: number;
  mentions?: string[];
}

/** Runs `step`, which must throw (`accepted` says what was wrong
 * otherwise), with a message that mentions every one of `mentions` (at
 * least one, so that not every throw passes), or with `any` one of them;
 * returns the message. */
export async function expectRefused(
  label: string,
  mentions: readonly string[],
  step: () => Promise<unknown>,
  o: { accepted: string; any?: boolean },
): Promise<string> {
  check(mentions.length > 0 && mentions.every((m) => m.length > 0), `${label}: an expected refusal names what its message mentions`);
  let refusal: string | undefined;
  try {
    await step();
  } catch (error) {
    refusal = String((error as Error).message ?? error);
  }
  check(refusal !== undefined, `${label}: ${o.accepted}`);
  const missing = mentions.filter((m) => !refusal.includes(m));
  const ok = o.any ? missing.length < mentions.length : missing.length === 0;
  check(ok, `${label}: refused without mentioning ${o.any ? mentions.join(" or ") : missing.join(", ")}: ${refusal}`);
  return refusal;
}

export class Machine {
  #dropNext = false;
  #dropped: string | undefined;

  readonly harness: Harness;
  readonly logger: Logger;
  readonly scope: Scope;

  constructor(harness: Harness, logger: Logger, scope: Scope) {
    this.harness = harness;
    this.logger = logger;
    this.scope = scope;
  }

  /** The fetch every client uses. When armed (`dropNextAnswer`), the round
   * runs and commits, the orchestrator answers, and the answer is dropped, as
   * a connection cut after the reply would; the client then has nothing but
   * the request id. */
  readonly fetch: typeof fetch = async (input, init) => {
    const res = await globalThis.fetch(input, init);
    const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    if (this.#dropNext && url.endsWith("/v1/execute")) {
      this.#dropNext = false;
      this.#dropped = await res.text();
      throw new TypeError(`the driver dropped the answer (HTTP ${res.status}) to simulate a lost response`);
    }
    return res;
  };

  /** Arms the loss of the next execute answer. */
  dropNextAnswer(): void {
    this.#dropNext = true;
    this.#dropped = undefined;
  }

  /** The answer last dropped, as the orchestrator sent it. */
  get droppedAnswer(): string | undefined {
    return this.#dropped;
  }

  /** POST a hand-built execute body straight to the orchestrator, past the
   * client's checks; a refusal is thrown as pss-client's SidecarError. */
  async postRaw(json: string): Promise<ExecuteResponse> {
    const res = await globalThis.fetch(`${this.harness.orchestratorUrl}/v1/execute`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: json,
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
    const text = await res.text();
    if (!res.ok) throw sidecarError(res.status, text);
    return parseExecuteResponse(JSON.parse(text));
  }

  /** One admin command on node i's socket (<run>/run/node<i>/admin.sock). */
  admin(i: number, command: object): Promise<AdminAnswer> {
    return adminSocket(join(this.harness.runDir, "run", `node${i}`, "admin.sock"), 60_000)(command);
  }

  /** Requires `step` to be refused by the machine as `want`. Logs the refusal. */
  async expectRefusal(label: string, want: Refusal, step: () => Promise<unknown>): Promise<SidecarError> {
    let error: unknown;
    try {
      await step();
    } catch (e) {
      error = e;
    }
    if (error === undefined) throw new Error(`${label}: ACCEPTED, expected ${want.class} ${want.status}`);
    if (!(error instanceof SidecarError) || error.class !== want.class || error.status !== want.status) {
      const got = error instanceof SidecarError ? `${error.class} ${error.status}: ${error.message}` : ((error as Error)?.stack ?? String(error));
      throw new Error(`${label}: expected ${want.class} ${want.status}, got ${got}`);
    }
    for (const m of want.mentions ?? []) {
      const needle = String(this.scope.resolve(m));
      if (!error.message.includes(needle)) throw new Error(`${label}: the ${want.class} refusal does not mention ${needle}: ${error.message}`);
    }
    this.logger.info(`[refusal] ${label}: ${error.class} ${error.status}: ${error.message}`);
    return error;
  }

  /** Requires pss-client to refuse a body before anything is sent (a RangeError). */
  async expectClientRefusal(label: string, mentions: string[], step: () => Promise<unknown>): Promise<void> {
    try {
      await step();
    } catch (e) {
      if (e instanceof RangeError && mentions.every((m) => e.message.includes(String(this.scope.resolve(m))))) {
        this.logger.info(`[client refusal] ${label}: ${e.message}`);
        return;
      }
      throw new Error(`${label}: the client refused it for another reason: ${String(e)}`);
    }
    throw new Error(`${label}: the client would send it`);
  }
}
