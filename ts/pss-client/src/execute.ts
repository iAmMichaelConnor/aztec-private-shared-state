// The sidecar path (intake direct) on the client side: build a request, send
// it with FETCH on failure, resend the saved bytes after an unknown outcome,
// FETCH a committed round again, and keep the state records every checked
// answer returns.

import type { ClientCore } from "./core.ts";
import { ConfigError, SidecarError, TransportError, UnknownOutcomeError } from "./errors.ts";
import { fieldHex, requestIdHex, type FieldLike } from "./field.ts";
import { recordsFromResponse, type RecordStore } from "./records.ts";
import {
  buildExecuteRequest,
  checkCiphertextHashes,
  checkRequestSignature,
  type BuildRequestInput,
  type PreparedRequest,
} from "./request.ts";
import { sleep } from "./sleep.ts";
import type { RequestStore } from "./store.ts";
import { parseExecuteResponse, type ExecuteRequest, type ExecuteResponse, type StateKeys } from "./wire.ts";

/** A committed round, and whether it came from execute or from FETCH. The
 * response's `signatures` are the three nodes' result signatures, already
 * checked against the pinned sig keys, for the contract call that hands the
 * round to the tip's `process_result`. */
export interface ExecuteOutcome {
  response: ExecuteResponse;
  via: "execute" | "fetch";
}

/** Which round a fetch() is for. */
export interface FetchOptions {
  /** The circuit the request was built for. Needed for an id this client did
   * not send (none saved in its request store); for a saved id it is read
   * from the saved body and, when given, must name the same circuit. */
  circuit?: string;
  /** Default: the saved body's namespace, else the configured contract
   * address. For a saved id, when given, it must be the saved one. */
  namespace?: FieldLike;
  /** Default: the configured request timeout. */
  timeoutMs?: number;
}

/** The sidecar path of one client: its requests go out through the shared
 * core, its sent bodies are kept in `store` and its records in
 * `recordStore`. */
export class Executor {
  private readonly core: ClientCore;
  private readonly store: RequestStore;
  private readonly recordStore: RecordStore;

  constructor(core: ClientCore, store: RequestStore, recordStore: RecordStore) {
    this.core = core;
    this.store = store;
    this.recordStore = recordStore;
  }

  /** Build a request in this client's namespace (the contract address). The
   * circuit must have a pinned vk hash and its registered circuit and manifest
   * in the configuration (`circuits`), without which its answers' signatures
   * cannot be checked. The configured manifest decides whether the request
   * must be signed (it supplies a record, stores a client-held key or
   * carries a shared input) and
   * which reads may be supplied as records (buildExecuteRequest). Shared
   * inputs are sealed to the pinned enc keys of the configuration. */
  async buildRequest(input: BuildRequestInput): Promise<PreparedRequest> {
    const manifest = this.core.manifest(input.circuit);
    return buildExecuteRequest(this.core.namespace(), input, this.core.encKeys(), manifest);
  }

  /** Save the request, POST /v1/execute, and on a timeout or transport error
   * FETCH the same id instead of resending. See resend() for an unknown
   * outcome. The body is checked first (checkBeforeSend), the answer after
   * (checkResponse), and the round's new records are kept in the record
   * store. */
  async execute(prepared: PreparedRequest): Promise<ExecuteOutcome> {
    const id = requestIdHex(prepared.requestId);
    if (prepared.json !== JSON.stringify(prepared.body)) {
      throw new RangeError(`request ${id}: the prepared json is not the prepared body; build the request again`);
    }
    const body = await this.checkBeforeSend(id, prepared.json);
    await this.store.save(id, prepared.json);
    return this.send(id, prepared.json, body);
  }

  /** The checks every send of a body runs first, on the exact JSON that is
   * sent: execute() before saving it and resend() before any FETCH or send of
   * the saved bytes. The body is an execute request for `requestId` in a
   * circuit the configuration pins and describes; every share_hashes[i] and
   * record_hashes[i] is the hash of its ciphertext (checkCiphertextHashes);
   * and a body that supplies a record, whose configured manifest stores a
   * client-held key, or that carries a shared input names its requester and
   * carries the requester's signature over its canonical body
   * (checkRequestSignature). A RangeError
   * naming the field otherwise, or a ConfigError for an unconfigured circuit;
   * nothing is sent then. Returns the parsed body. */
  async checkBeforeSend(requestId: string, json: string): Promise<ExecuteRequest> {
    const id = requestIdHex(requestId);
    const body = savedBody(id, json);
    if (requestIdHex(body.request_id) !== id) throw new RangeError(`request ${id}: the body carries request_id ${body.request_id}`);
    const manifest = this.core.manifest(body.circuit);
    await checkCiphertextHashes(body);
    await checkRequestSignature(body, manifest);
    return body;
  }

  // The resend rule. A request is shared, sealed and signed once, and the
  // exact JSON (shares, envelopes, records, signature) is saved under its id
  // before the first send. The only retry is FETCH by that id and, when the
  // nodes do not hold it, a resend of the saved bytes; nothing re-shares,
  // re-encrypts or re-signs for a retry, and there is no API that does. New
  // envelopes change share_hashes and so the body hash, and the nodes refuse
  // another body under a used id (409); a rebuilt request under a new id is a
  // second round, which on a consumed state is refused and elsewhere runs
  // again with fresh randomness.
  /** After UnknownOutcomeError: FETCH the id once and, if the nodes do not
   * hold it, send the saved body again, byte for byte. The nodes answer a
   * committed id from their requests table and run an uncommitted one once. */
  async resend(requestId: string): Promise<ExecuteOutcome> {
    const id = requestIdHex(requestId);
    const json = await this.store.load(id);
    if (json === undefined) throw new ConfigError(`request ${id}: no saved body`);
    const body = await this.checkBeforeSend(id, json);
    try {
      const response = await this.fetchAnswer(id, body.namespace);
      return { response: await this.accept(body, id, response), via: "fetch" };
    } catch (e) {
      if (!(e instanceof SidecarError && e.class === "not_found")) throw e;
    }
    return this.send(id, json, body);
  }

  /** Forget a request once its transaction is mined and its new notes'
   * nonces are mined from it (nonces.ts). */
  async discard(requestId: string): Promise<void> {
    await this.store.delete(requestIdHex(requestId));
  }

  private async send(requestId: string, json: string, body: ExecuteRequest): Promise<ExecuteOutcome> {
    let res: Response;
    try {
      res = await this.core.transport.http("POST", "/v1/execute", json, this.core.config.timeoutMs);
    } catch (e) {
      return this.recover(requestId, body, json, e);
    }
    let value: unknown;
    try {
      value = await this.core.transport.read(res, "POST /v1/execute");
    } catch (e) {
      // A gateway error or a body cut off in transit says nothing about
      // whether the round committed: FETCH. A sidecar refusal is definite.
      const unknown = e instanceof TransportError || (e instanceof SidecarError && e.class === "unknown" && e.status >= 500);
      if (unknown) return this.recover(requestId, body, json, e);
      throw e;
    }
    return { response: await this.accept(body, requestId, parseExecuteResponse(value)), via: "execute" };
  }

  // Check an answer, its records' labels against the body's state keys included,
  // and keep its new records.
  private async accept(body: ExecuteRequest, requestId: string, response: ExecuteResponse): Promise<ExecuteResponse> {
    const checked = await this.core.checkResponse(body.circuit, requestId, response, body.namespace, body.state_keys);
    for (const record of recordsFromResponse(body.namespace, checked)) await this.recordStore.put(record);
    return checked;
  }

  // Which failures go to FETCH, and which FETCH failures are retried. On
  // POST /v1/execute, a TransportError (no connection, a timeout, a body cut
  // off) and a reply that is not a sidecar refusal with status 500 or above
  // (class "unknown": a gateway or proxy error page) say nothing about
  // whether the round committed, so they go to FETCH; every sidecar refusal,
  // mpc_failure included, is definite (section 8 of the architecture: nothing
  // was stored) and is thrown, as is a non-sidecar reply below 500.
  // During the FETCH window recover() retries, up to fetchRetry.attempts:
  // TransportError; not_found (404: the nodes hold no row yet, because the
  // round is still queued or running, or the execute never arrived); unknown
  // (any reply that is not a sidecar refusal); and mpc_failure (500: while a
  // round commits, the nodes can disagree or one can be unreachable). It
  // stops at once on bad_request, forbidden, conflict (409: a rolled-back id,
  // which never comes back), unsatisfied, and on an answer that fails the
  // client's own checks (ProtocolError, VkHashMismatchError,
  // ResultSignatureError), since FETCH returns the same stored row again.
  // fetchRetry (config.ts) sets the bound and the backoff: retry what can
  // change, fail fast on what cannot. After the bound the caller gets
  // UnknownOutcomeError and resend(); a retried class that is in fact
  // permanent only delays the error by the bound (about a minute by
  // default).
  private async recover(requestId: string, body: ExecuteRequest, json: string, cause: unknown): Promise<ExecuteOutcome> {
    const r = this.core.config.fetchRetry;
    let last: unknown = cause;
    let delay = r.initialDelayMs;
    for (let attempt = 0; attempt < r.attempts; attempt++) {
      await sleep(delay);
      delay = Math.min(delay * 2, r.maxDelayMs);
      try {
        const response = await this.fetchAnswer(requestId, body.namespace, r.timeoutMs);
        return { response: await this.accept(body, requestId, response), via: "fetch" };
      } catch (e) {
        last = e;
        const retry =
          e instanceof TransportError ||
          (e instanceof SidecarError && (e.class === "not_found" || e.class === "unknown" || e.class === "mpc_failure"));
        if (!retry) throw e;
      }
    }
    throw new UnknownOutcomeError(requestId, json, last);
  }

  /** POST /v1/fetch: a committed result again (404 not_found if unknown),
   * checked as an execute answer is (checkResponse) against the pinned vk
   * hash and note-hash indices of the request's circuit. The circuit comes
   * from the saved body when this client sent the id, else from
   * `options.circuit`; never from the answer, whose vk_hash no node signs. An
   * id with neither is a ConfigError, sent nowhere. The returned records'
   * keys are checked against the saved body's write keys when there is one;
   * fetch() keeps no record either way. */
  async fetch(requestId: string, options: FetchOptions = {}): Promise<ExecuteResponse> {
    const id = requestIdHex(requestId);
    const saved = await this.store.load(id);
    let circuit: string;
    let namespace: string;
    let stateKeys: StateKeys | undefined;
    if (saved !== undefined) {
      const body = savedBody(id, saved);
      if (options.circuit !== undefined && options.circuit !== body.circuit) {
        throw new ConfigError(`request ${id}: sent for circuit ${body.circuit}, not ${options.circuit}`);
      }
      if (options.namespace !== undefined && fieldHex(options.namespace, "namespace") !== fieldHex(body.namespace, "namespace")) {
        throw new ConfigError(`request ${id}: sent in namespace ${body.namespace}, not ${fieldHex(options.namespace)}`);
      }
      circuit = body.circuit;
      namespace = body.namespace;
      stateKeys = body.state_keys;
    } else {
      if (options.circuit === undefined) {
        throw new ConfigError(`request ${id}: no saved body, so fetch() needs the circuit it was built for (options.circuit)`);
      }
      circuit = options.circuit;
      namespace = this.core.namespace(options.namespace);
    }
    // Refuse an unconfigured circuit before the network call.
    this.core.vkHash(circuit);
    this.core.noteHashIndices(circuit);
    const response = await this.fetchAnswer(id, namespace, options.timeoutMs ?? this.core.config.timeoutMs);
    return this.core.checkResponse(circuit, id, response, namespace, stateKeys);
  }

  // POST /v1/fetch, parsed but not yet checked.
  private async fetchAnswer(requestId: string, namespace: FieldLike, timeoutMs = this.core.config.timeoutMs): Promise<ExecuteResponse> {
    const body = JSON.stringify({ namespace: fieldHex(namespace, "namespace"), request_id: requestIdHex(requestId) });
    return parseExecuteResponse(await this.core.transport.call("POST", "/v1/fetch", body, timeoutMs));
  }
}

// A body about to be sent or resent, parsed. It is the client's own (built
// here or kept in its request store), so a malformed one is a local error.
function savedBody(requestId: string, json: string): ExecuteRequest {
  let body: unknown;
  try {
    body = JSON.parse(json);
  } catch {
    throw new RangeError(`request ${requestId}: the body is not JSON`);
  }
  const b = body as Partial<ExecuteRequest> | null;
  if (typeof b !== "object" || b === null || typeof b.circuit !== "string" || typeof b.namespace !== "string" || !Array.isArray(b.shared_inputs) || !Array.isArray(b.records)) {
    throw new RangeError(`request ${requestId}: the body is not an execute request`);
  }
  return body as ExecuteRequest;
}
