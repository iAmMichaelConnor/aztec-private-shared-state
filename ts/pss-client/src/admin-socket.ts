// A sidecar node's admin socket (sidecar-node `admin_socket`, default
// `<run_dir>/admin.sock`): one JSON command per connection, one JSON object
// per line each way. pss-relayer's enc key rotation and the e2e harness speak
// it; the node answers `ok`, a refusal, and the op's own fields.

import { createConnection } from "node:net";

/** An admin socket's answer: `ok`, a refusal, and the op's own fields. */
export interface AdminAnswer {
  ok: boolean;
  refusal?: { class: string; error: string };
  [field: string]: unknown;
}

/** One command on a node's admin socket. */
export type AdminCall = (command: object) => Promise<AdminAnswer>;

/** The signed rotation `sign_enc_key` answers (sidecar-node `EncKeySigned`). */
export interface EncKeySigned {
  index: number;
  namespace: string;
  enc: { x: string; y: string };
  epoch: number;
  signature: { s: [string, string]; e: [string, string] };
}

/** The node's admin socket at `path`; a command fails after `timeoutMs`
 * without an answer, or when the node closes the connection before a full
 * answer line. */
export function adminSocket(path: string, timeoutMs: number): AdminCall {
  return (command) =>
    new Promise((resolve, reject) => {
      const socket = createConnection(path);
      let buffer = "";
      socket.setEncoding("utf8");
      socket.setTimeout(timeoutMs, () => socket.destroy(new Error(`admin socket ${path}: no answer within ${timeoutMs} ms`)));
      socket.on("connect", () => socket.write(`${JSON.stringify(command)}\n`));
      socket.on("data", (chunk: string) => {
        buffer += chunk;
        const end = buffer.indexOf("\n");
        if (end < 0) return;
        socket.end();
        try {
          resolve(JSON.parse(buffer.slice(0, end)) as AdminAnswer);
        } catch {
          reject(new Error(`admin socket ${path}: the answer is not JSON: ${buffer.slice(0, end)}`));
        }
      });
      socket.on("error", (e) => reject(new Error(`admin socket ${path}: ${e.message}`)));
      // a clean close emits no error; once answered (or refused) this changes nothing
      socket.on("close", () => reject(new Error(`admin socket ${path}: closed without a full answer`)));
    });
}
