// The HTTP transport to the orchestrator, shared by every part of the client:
// one request with a timeout, the reply read as JSON on 2xx and as a typed
// SidecarError otherwise, and a failure to connect or to read the body as a
// TransportError.

import { ProtocolError, SidecarError, TransportError, isErrorClass } from "./errors.ts";

/** The largest reply body read, 8 MiB: many times an answer with a 458-field
 * proof, its public inputs and its records. A longer reply is refused
 * (ProtocolError) before it is all held in memory. */
export const MAX_RESPONSE_BYTES = 8 * 1024 * 1024;

class ResponseTooLarge extends Error {}

/** The body as text, refused past `max` bytes. */
async function cappedText(res: Response, max: number): Promise<string> {
  if (Number(res.headers.get("content-length") ?? 0) > max) throw new ResponseTooLarge();
  if (res.body === null) return "";
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let length = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    length += value.byteLength;
    if (length > max) {
      await reader.cancel();
      throw new ResponseTooLarge();
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks).toString("utf8");
}

export class Transport {
  private readonly baseUrl: string;
  private readonly fetchImpl: typeof fetch;
  private readonly timeoutMs: number;

  /** `baseUrl` without a trailing slash; `timeoutMs` the default of call(). */
  constructor(baseUrl: string, fetchImpl: typeof fetch, timeoutMs: number) {
    this.baseUrl = baseUrl;
    this.fetchImpl = fetchImpl;
    this.timeoutMs = timeoutMs;
  }

  /** Send one request; a TransportError when it cannot be sent or times out. */
  async http(method: "GET" | "POST", path: string, body: string | undefined, timeoutMs: number): Promise<Response> {
    try {
      return await this.fetchImpl(this.baseUrl + path, {
        method,
        headers: body === undefined ? {} : { "content-type": "application/json" },
        body,
        signal: AbortSignal.timeout(timeoutMs),
      });
    } catch (e) {
      throw new TransportError(`${method} ${path}: ${(e as Error).message}`, e);
    }
  }

  /** Read a response: the parsed JSON on 2xx, a SidecarError otherwise. A
   * body that cannot be read in time is a transport failure; one over
   * MAX_RESPONSE_BYTES a ProtocolError. */
  async read(res: Response, what: string): Promise<unknown> {
    let text: string;
    try {
      text = await cappedText(res, MAX_RESPONSE_BYTES);
    } catch (e) {
      if (e instanceof ResponseTooLarge) throw new ProtocolError(`${what}: the response is over ${MAX_RESPONSE_BYTES} bytes`);
      throw new TransportError(`${what}: reading the response: ${(e as Error).message}`, e);
    }
    if (!res.ok) throw sidecarError(res.status, text);
    try {
      return JSON.parse(text);
    } catch {
      throw new ProtocolError(`${what}: response is not JSON`);
    }
  }

  /** http() then read(). */
  async call(method: "GET" | "POST", path: string, body?: string, timeoutMs = this.timeoutMs): Promise<unknown> {
    const res = await this.http(method, path, body, timeoutMs);
    return this.read(res, `${method} ${path}`);
  }
}

/** Map an error response to a SidecarError: the server's class when the body
 * is `{"error", "class"}`, "unknown" otherwise. */
export function sidecarError(status: number, text: string): SidecarError {
  try {
    const v = JSON.parse(text) as { error?: unknown; class?: unknown };
    if (typeof v === "object" && v !== null && typeof v.error === "string" && isErrorClass(v.class)) {
      return new SidecarError(status, v.class, v.error);
    }
  } catch {
    // not JSON: fall through
  }
  return new SidecarError(status, "unknown", `HTTP ${status}: ${text.slice(0, 200)}`);
}
