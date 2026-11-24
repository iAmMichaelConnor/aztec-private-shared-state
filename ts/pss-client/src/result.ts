// The result axis on the client side: one ResultReader per form a queued
// round's result takes, chosen once per circuit at configuration
// (resolveConfig) from its intake's module (IntakeModule.results):
//
//   public    tip-result.ts publicResults     the non-secret-shared intakes' rounds: the
//                                              library's TipResult, public outputs
//   outcome   outcome.ts privateOutcomes      the secret-shared intakes' rounds: the
//                                              library's OutcomeResult, a private
//                                              outcome
//
// A reader splits a checked FETCH answer into its parts, gives the result
// call's arguments and the key a lander counts its sends under, and
// summarises the result for whoever watches it. FETCH by chain request id
// (PssClient.fetchChainResult), the Lander (lander.ts) and pss-relayer ask the
// circuit's reader and never compare the form.

import type { FieldHexString, FieldLike } from "./field.ts";
import type { QueuedManifest } from "./manifest.ts";
import type { OutcomeResultParts } from "./outcome.ts";
import type { ProcessResultEncoder, TipResultParts } from "./tip-result.ts";
import type { ExecuteResponse } from "./wire.ts";

/** The forms a queued round's result takes. */
export type ResultFormName = "public" | "outcome";

// What vouches for each part of a result. The client checks every FETCH
// answer before a reader sees it, but the three node signatures cover only
// part of it (result-signatures.ts: the namespace, the machine request id,
// the new commitments and the returned records' thirds):
//
//   bound by the signatures   machineRequestId, newCommitments, the records
//                             (a public result's state arguments), and
//                             oldCommitments and reads, which the client
//                             recomputes into the signed machine request id
//   checked by the client     the namespace (in the signed message too),
//                             the vk hash (pinned) and the chain request id
//                             (the one asked for)
//   bound by the proof only   everything else: ok, moves, appOutputs and
//                             partialNote of a public result; outcomeTag,
//                             noteHashes, the ciphertext, the app values and
//                             the deliveries of a private outcome
//
// The proof is checked by the chain when the result lands, and by the client
// only when its configuration supplies `verifyProof`. Without it, a
// proof-only part comes from the orchestrator alone until the result lands:
// a UI that shows such a part before landing shows what the orchestrator
// says, and a result whose proof-only parts were altered costs its sender a
// proving run and a fee, then reverts. The chain is never fooled.
/** What a result is, whatever its form. Which fields the node signatures
 * bind and which only the proof binds: the comment above. */
export interface ResultSummary {
  form: ResultFormName;
  /** The attempt the nodes signed under. Signature-bound. */
  machineRequestId: FieldHexString;
  /** The request keys' commitments the round ran on, in commitment_slot key
   * order, and the new commitments of the keys it writes. Signature-bound
   * (the old ones through the machine request id). */
  oldCommitments: FieldHexString[];
  newCommitments: FieldHexString[];
  /** The pinned values the round used. Signature-bound, through the machine
   * request id. */
  reads: FieldHexString[];
  /** Whether landing the result writes the new commitments: a public
   * result's ok (a failed round leaves its keys as they were); always for a
   * private outcome, which re-blinds the state whatever the outcome.
   * Proof-bound only. */
  moves: boolean;
  /** A public result: ok and the app outputs, and under partial-note
   * delivery the request's partial note, which the app's apply completes in
   * public (its completion log under completionLogTag(partialNote)).
   * Proof-bound only: checked before landing only under `verifyProof`. */
  ok?: boolean;
  partialNote?: FieldHexString;
  appOutputs?: FieldHexString[];
  /** A private outcome: its tag, its completed note hashes and its
   * ciphertext's length. Proof-bound only: checked before landing only
   * under `verifyProof`. */
  outcomeTag?: FieldHexString;
  noteHashes?: FieldHexString[];
  ciphertextLength?: number;
}

/** The reader of one circuit's results, in its form. */
export interface ResultReader<P = TipResultParts | OutcomeResultParts> {
  readonly form: ResultFormName;
  readonly circuit: string;
  /** A private outcome's number of plaintext fields, which its outcome log
   * is opened with (outcomePlaintextLength); undefined for a public
   * result. */
  readonly plaintextLength?: number;
  /** The parts of a checked answer to FETCH by chain request id, bound to
   * the chain request asked for (ProtocolError otherwise). The result
   * signatures are checked by the caller (PssClient). They bind the machine
   * request id (and through it the old commitments and the reads), the new
   * commitments and the state arguments; every other part (ok, the app
   * outputs, the partial note; a private outcome's tag, note hashes,
   * ciphertext, app values and deliveries) is bound by the proof alone,
   * which the client checks only under `verifyProof` (the comment above
   * ResultSummary). */
  parts(namespace: FieldLike, chainRequestId: FieldLike, response: ExecuteResponse): Promise<P>;
  /** The result call's arguments; `encode`, an app's argument shape of a
   * public result, defaults to the library's (a private outcome takes the
   * library's order). */
  callArgs(parts: P, encode?: ProcessResultEncoder): unknown[];
  /** Two answers are the same result when their keys are equal: the same
   * attempt with the same outcome. A lander re-sends an answer only when the
   * key changes. */
  key(parts: P): string;
  summary(parts: P): ResultSummary;
}

/** One form: the reader of a circuit under it, from its compiled circuit
 * (the nargo output JSON or its `abi`) and its parsed manifest. RangeError
 * when the circuit does not follow the form's layout. */
export interface ResultForm<P = TipResultParts | OutcomeResultParts> {
  readonly form: ResultFormName;
  reader(circuit: unknown, manifest: QueuedManifest): ResultReader<P>;
}

/** A checked answer of FETCH by chain request id, its parts and its reader. */
interface ResultOf<F extends ResultFormName, P> {
  form: F;
  circuit: string;
  response: ExecuteResponse;
  parts: P;
  reader: ResultReader<P>;
}

/** A non-secret-shared intake's round, whose outputs are public (the library's TipResult). */
export type ChainResult = ResultOf<"public", TipResultParts>;

/** A secret-shared intake's round: its private outcome (the library's OutcomeResult). */
export type OutcomeChainResult = ResultOf<"outcome", OutcomeResultParts>;

/** The result of any queued round, in the form its circuit's reader gives. */
export type QueuedResult = ChainResult | OutcomeChainResult;

/** The result call's arguments of `result` (its reader's). */
export function resultCallArgs(result: QueuedResult, encode?: ProcessResultEncoder): unknown[] {
  return (result.reader as ResultReader).callArgs(result.parts, encode);
}

/** The send-count key of `result` (its reader's). */
export function queuedResultKey(result: QueuedResult): string {
  return (result.reader as ResultReader).key(result.parts);
}

/** What `result` is (its reader's summary). */
export function resultSummary(result: QueuedResult): ResultSummary {
  return (result.reader as ResultReader).summary(result.parts);
}
