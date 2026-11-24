// The errors the client throws. A refusal from the sidecar becomes a
// SidecarError carrying the server's class; every other failure has its own type
// so callers can tell "the request is wrong" from "the outcome is unknown".

/** The error classes of sidecar-core (error.rs), with their HTTP codes. */
const ERROR_CLASSES = {
  bad_request: 400,
  forbidden: 403,
  not_found: 404,
  conflict: 409,
  unsatisfied: 422,
  mpc_failure: 500,
} as const;

export type ErrorClass = keyof typeof ERROR_CLASSES;

export function isErrorClass(x: unknown): x is ErrorClass {
  return typeof x === "string" && Object.hasOwn(ERROR_CLASSES, x);
}

/** A refusal answered by the orchestrator as `{"error": "...", "class": "..."}`.
 * `class` is `"unknown"` when the body is not a sidecar refusal (a proxy's error
 * page, for example); `status` is the HTTP status either way. */
export class SidecarError extends Error {
  readonly status: number;
  readonly class: ErrorClass | "unknown";
  constructor(status: number, cls: ErrorClass | "unknown", message: string) {
    super(message);
    this.name = "SidecarError";
    this.status = status;
    this.class = cls;
  }
}

/** The request may or may not have committed: the execute call failed in
 * transport and FETCH did not find a result within its retry bound. `body` is
 * the exact JSON that was saved before sending. Resend that same body (never a
 * rebuilt or re-encrypted one) with `PssClient.resend(requestId)`. */
export class UnknownOutcomeError extends Error {
  readonly requestId: string;
  readonly body: string;
  constructor(requestId: string, body: string, cause: unknown) {
    super(
      `unknown outcome for request ${requestId}: the execute call failed in transport and FETCH found no result; ` +
        `resend the saved body unchanged`,
      { cause },
    );
    this.name = "UnknownOutcomeError";
    this.requestId = requestId;
    this.body = body;
  }
}

/** The connection failed, timed out, or the response could not be read. */
export class TransportError extends Error {
  constructor(message: string, cause?: unknown) {
    super(message, { cause });
    this.name = "TransportError";
  }
}

/** A response that does not have the wire format of sidecar-core. */
export class ProtocolError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ProtocolError";
  }
}

/** GET /v1/nodes answered keys other than the pinned ones. */
export class NodeKeyMismatchError extends Error {
  readonly index: number;
  readonly key: "enc" | "sig";
  constructor(index: number, key: "enc" | "sig", expected: unknown, got: unknown) {
    super(
      `node ${index}: the orchestrator reports ${key} key ${JSON.stringify(got)}, ` +
        `the configuration pins ${JSON.stringify(expected)}; refusing to use this network`,
    );
    this.name = "NodeKeyMismatchError";
    this.index = index;
    this.key = key;
  }
}

/** The sidecar proved under a verification key other than the pinned one. */
export class VkHashMismatchError extends Error {
  readonly circuit: string;
  constructor(circuit: string, expected: string, got: string) {
    super(`${circuit}: the sidecar's vk hash ${got} differs from the pinned ${expected}`);
    this.name = "VkHashMismatchError";
    this.circuit = circuit;
  }
}

/** Configuration that cannot be used. */
export class ConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ConfigError";
  }
}

/** A node's result signature on an execute or FETCH answer does not verify
 * under the sig key the configuration pins for that node. The client's own
 * check, not a sidecar refusal: the round may well have committed, but the
 * answer cannot be shown to come from all three nodes, and the tip's
 * process_result would refuse it the same way. `node` is the node index. */
export class ResultSignatureError extends Error {
  readonly node: number;
  readonly requestId: string;
  constructor(node: number, requestId: string) {
    super(`request ${requestId}: node ${node}'s result signature does not verify under its pinned sig key`);
    this.name = "ResultSignatureError";
    this.node = node;
    this.requestId = requestId;
  }
}

/** A node's receipt does not verify under the sig key the
 * configuration pins for that node, over the receipt message the client
 * rebuilt from its own request id, inputs hash and the answer's expiry. The
 * contract's check_receipts would refuse the same receipts in the user's
 * private function, after client-side proving. `node` is the node index. */
export class ReceiptSignatureError extends Error {
  readonly node: number;
  readonly requestId: string;
  constructor(node: number, requestId: string) {
    super(`request ${requestId}: node ${node}'s receipt does not verify under its pinned sig key`);
    this.name = "ReceiptSignatureError";
    this.node = node;
    this.requestId = requestId;
  }
}
