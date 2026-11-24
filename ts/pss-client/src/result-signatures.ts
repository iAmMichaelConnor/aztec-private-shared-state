// Result signatures: every node signs each committed round with its `sig` key,
// and the client checks all three against the keys it pinned before it hands
// the round to the app. The message is the one machine/sidecar-core/src/
// pipeline.rs defines (result_message, sealed_hash, result_commitments):
//
//   H(sealed_i) = poseidon2(record_hashes of node i's new thirds, in manifest output order), 0 when none
//   message_i   = poseidon2([RESULT_DOMAIN, namespace, request_id, commitments..., i, H(sealed_i)])
//
// The client reads the thirds in the order the answer's `records` lists them,
// which is manifest output order: the nodes write their records in that order
// and the orchestrator keeps it when it assembles each record from the three
// thirds. A list the orchestrator reordered fails the check, as it should.
// The commitments are the public inputs at the manifest outputs' note-hash
// indices, in manifest order. The client finds those indices the way REGISTER
// does: it flattens the circuit's ABI (public parameters first, then the public
// return value) and looks up the return-value path each manifest output names
// as its `note_hash`.

import { poseidon2Hash } from "@aztec-labs/foundation/crypto/poseidon";
import { Fr } from "@aztec-labs/foundation/curves/bn254";

import { abiOf, outputNoteHashIndices } from "./abi.ts";
import { ProtocolError, ResultSignatureError } from "./errors.ts";
import { fieldBigInt, requestIdHex, type FieldLike } from "./field.ts";
import { parseManifest } from "./manifest.ts";
import { recordHash } from "./records.ts";
import { failingNode } from "./signing.ts";
import { NODES, nodeIndex, type ExecuteResponse, type Triple } from "./wire.ts";
import { asciiLabel } from "./labels.ts";

// The result domain: ASCII "sidecar.result" read as a big-endian integer,
// sidecar-core's RESULT_DOMAIN. It keeps a result signature from being read
// as a registry answer or a receipt signed by the same node key. Changing it
// here without the nodes (and the tip's process_result) makes every result
// fail the client's check.
export const RESULT_DOMAIN = asciiLabel("sidecar.result");

/** `H(sealed_i)`: Poseidon2 over the record hashes of node i's new thirds, in
 * the order the response lists the records; 0 when the round makes none. */
export async function sealedHash(recordHashes: FieldLike[]): Promise<Fr> {
  if (recordHashes.length === 0) return new Fr(0n);
  return poseidon2Hash(recordHashes.map((h, k) => new Fr(fieldBigInt(h, `record_hashes[${k}]`))));
}

/** The result message node `i` signs:
 * `poseidon2([RESULT_DOMAIN, namespace, request_id, commitments..., i, H(sealed_i)])`. */
export async function resultMessage(
  namespace: FieldLike,
  requestId: FieldLike,
  commitments: FieldLike[],
  i: number,
  sealed: FieldLike,
): Promise<Fr> {
  nodeIndex(i);
  return poseidon2Hash([
    new Fr(RESULT_DOMAIN),
    new Fr(fieldBigInt(namespace, "namespace")),
    new Fr(BigInt(requestIdHex(requestId))),
    ...commitments.map((c, k) => new Fr(fieldBigInt(c, `commitments[${k}]`))),
    new Fr(BigInt(i)),
    new Fr(fieldBigInt(sealed, "sealed")),
  ]);
}

// ---- the note-hash indices ----

/** The public-input index of each manifest output's note hash, in manifest
 * order (abi.ts outputNoteHashIndices, the rule REGISTER applies). `circuit`
 * is the nargo output JSON or its `abi`; `manifest` the manifest JSON, both as
 * sent to REGISTER. RangeError when the manifest does not parse
 * (parseManifest) or an output's note hash is not a public Field of the
 * return value. */
export function noteHashIndices(circuit: unknown, manifest: unknown): number[] {
  return outputNoteHashIndices(abiOf(circuit), parseManifest(manifest).outputs);
}

/** The new commitments of a round: the public inputs at `indices`, in order.
 * A ProtocolError when the answer has too few public inputs for them. */
export function resultCommitments(publicInputs: string[], indices: number[]): string[] {
  return indices.map((i) => {
    const v = publicInputs[i];
    if (v === undefined) {
      throw new ProtocolError(`the answer has ${publicInputs.length} public inputs, none at the note-hash index ${i}`);
    }
    return v;
  });
}

/** The three result messages of an answer, node 0's first, rebuilt from the
 * namespace the client asked for, the answer's request id and public inputs,
 * and the record hashes of node i's third of every returned record. */
export async function resultMessages(namespace: FieldLike, response: ExecuteResponse, indices: number[]): Promise<Triple<Fr>> {
  const commitments = resultCommitments(response.public_inputs, indices);
  const out: Fr[] = [];
  for (let i = 0; i < NODES; i++) {
    const hashes = await Promise.all(response.records.map((r) => recordHash(r.c[i]!)));
    out.push(await resultMessage(namespace, response.request_id, commitments, i, await sealedHash(hashes)));
  }
  return out as Triple<Fr>;
}

// The result-signature check. Every execute and FETCH answer is checked
// before the client returns it or keeps its records: node i's signature must
// verify under node i's sig key in the contract's key set (key-epoch.ts:
// the pinned constructor keys at epoch 0; never a key a server reports) over the message rebuilt by the client
// itself. There is no switch to turn it off. The orchestrator alone
// assembles the answer; the signatures are what show that each of the three
// nodes committed this exact round (these commitments, these thirds), and
// the tip's process_result requires the same three, so an answer that fails
// here would also fail on chain. A failure is a ResultSignatureError naming
// the first node whose signature does not verify; the client keeps none of
// that answer's records.
/** Check the three result signatures of an answer; throws ResultSignatureError
 * naming the first node whose signature does not verify. `sigKeySets` are
 * the key sets accepted, the current first (key-epoch.ts signatureKeySets:
 * a contract's current key epoch and, inside its grace window, the previous
 * one): the three signatures must all verify under one of them, and a
 * failure names the first node failing under the first set. */
export async function verifyResultSignatures(
  namespace: FieldLike,
  response: ExecuteResponse,
  indices: number[],
  sigKeySets: readonly Triple<{ x: FieldLike; y: FieldLike }>[],
): Promise<void> {
  const messages = await resultMessages(namespace, response, indices);
  const failed = await failingNode(messages.map((m) => m.toBigInt()), response.signatures, sigKeySets);
  if (failed !== undefined) throw new ResultSignatureError(failed, response.request_id);
}
