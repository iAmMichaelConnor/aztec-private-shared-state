// Discovery: the client's one way to read logs from the chain. A LogNode (an
// Aztec node, or a test's stand-in) answers tag queries; taggedLogs reads
// every log under one tag and findTaggedLog returns the first that a reader
// parses and checks. Each kind
// of log has one reader over it: the on-chain request log (readRequestLog,
// checked as the chain reader checks it) and the outcome log of a private
// outcome (OutcomeReader, for the user, over a PrivateLogNode).

import { AztecAddress } from "@aztec-labs/aztec.js/addresses";
import { Fr } from "@aztec-labs/aztec.js/fields";
import { SiloedTag, Tag, type LogResultBase, type PublicLogsQuery } from "@aztec-labs/stdlib/logs";

import { TagMismatchError } from "./ae.ts";
import { fieldAddress, fieldFr, fieldHex, type FieldHexString, type FieldLike } from "./field.ts";
import { computeRequestLogTag, parsePlainRequestLog, type PlainRequestLog } from "./intake-onchain.ts";
import type { FoundDelivery } from "./handle.ts";
import { NoteMismatchError, openOutcomeLog, outcomeLogTag, type OpenedOutcome, type OutcomeKeys } from "./outcome.ts";

/** One log of a tag query: its fields. */
export type TaggedLog = Pick<LogResultBase, "logData">;

/** The Aztec node method discovery uses. */
export interface LogNode {
  getPublicLogsByTags(query: PublicLogsQuery): Promise<TaggedLog[][]>;
}

/** Every public log `contract` emitted under `tag`, in chain order, each as
 * its fields: one query, as the node answers it. The request log's tag
 * holds at most one log (append() refuses a repeated request id), far
 * below the node's MAX_LOGS_PER_TAG per answer. */
export async function taggedLogs(node: LogNode, contract: FieldLike | AztecAddress, tag: Fr): Promise<Fr[][]> {
  const [logs = []] = await node.getPublicLogsByTags({ contractAddress: fieldAddress(contract, "contract"), tags: [new Tag(tag)] });
  return logs.map((log) => log.logData);
}

/** The first log under `tag` that `read` accepts (returns a value for);
 * undefined when there is none. When logs carry the tag but none is
 * accepted, the last reader error is thrown. */
async function findTaggedLog<T>(
  node: LogNode,
  contract: FieldLike | AztecAddress,
  tag: Fr,
  read: (fields: Fr[]) => Promise<T | undefined>,
): Promise<T | undefined> {
  const logs = await taggedLogs(node, contract, tag);
  let last: unknown;
  for (const fields of logs) {
    try {
      const value = await read(fields);
      if (value !== undefined) return value;
    } catch (e) {
      last = e;
    }
  }
  if (last !== undefined && logs.length > 0) throw last;
  return undefined;
}

/** The on-chain request log of `chainRequestId` that `contract` emitted
 * (`[tag, inputs..., user_nonce]`), checked as the chain reader checks it
 * (parsePlainRequestLog with the namespace and vk hash: the inputs and nonce
 * must recompute the id). Undefined when there is none yet; the
 * first log that checks when several carry the tag. */
export async function readRequestLog(
  node: LogNode,
  contract: FieldLike | AztecAddress,
  chainRequestIdValue: FieldLike,
  vkHash: FieldLike,
): Promise<PlainRequestLog | undefined> {
  const namespace = fieldAddress(contract, "contract").toBigInt();
  const id = fieldHex(chainRequestIdValue, "chain_request_id");
  return findTaggedLog(node, contract, await computeRequestLogTag(chainRequestIdValue), async (fields) => {
    const parsed = await parsePlainRequestLog(fields, { namespace, vkHash });
    return parsed.requestId === id ? parsed : undefined;
  });
}

// ---- the outcome log (private outcomes) ----

/** One private log as the node answers it with its transaction's effects
 * (`includeEffects`). The effects are optional in the type, as aztec.js
 * types the node's answer (an aztec.js AztecNode is a PrivateLogNode);
 * `logTx` refuses a log without them. */
export interface EffectLog {
  logData: Fr[];
  txHash: { toString(): string };
  noteHashes?: Fr[];
  nullifiers?: Fr[];
}

/** The Aztec node method the outcome reader uses: private logs by siloed
 * tag, with each log's transaction effects (`includeEffects`). */
export interface PrivateLogNode {
  getPrivateLogsByTags(query: { tags: SiloedTag[]; includeEffects: true }): Promise<EffectLog[][]>;
}

/** The transaction that carried an outcome, as the outcome-note utility
 * takes it (pss_public_contract `OutcomeTx`). */
export interface OutcomeTx {
  txHash: FieldHexString;
  uniqueNoteHashes: FieldHexString[];
  firstNullifier: FieldHexString;
}

/** A transaction's effects as a block's body carries them (an aztec.js
 * TxEffect is one): its hash, unique note hashes, nullifiers and private
 * logs, each log its fields and how many of them it emitted. */
export interface TxEffects {
  txHash: { toString(): string };
  noteHashes: Fr[];
  nullifiers: Fr[];
  privateLogs: { fields: Fr[]; emittedLength: number }[];
}

/** The transaction that carried `log`, from the effects the node answered
 * with it (or from the transaction's own effects): its hash, its unique
 * note hashes and its first nullifier. RangeError when the log came without
 * effects or the transaction has no nullifier. */
export function logTx(log: Pick<EffectLog, "txHash" | "noteHashes" | "nullifiers">): OutcomeTx {
  const first = log.nullifiers?.[0];
  if (log.noteHashes === undefined || first === undefined) throw new RangeError("the log's transaction effects are missing or have no nullifier");
  return {
    txHash: fieldHex(BigInt(log.txHash.toString()), "tx_hash"),
    uniqueNoteHashes: log.noteHashes.map((h) => fieldHex(h.toBigInt())),
    firstNullifier: fieldHex(first.toBigInt()),
  };
}

/** An outcome found on the chain: the opened outcome and its transaction. */
export interface FoundOutcome extends OpenedOutcome {
  tx: OutcomeTx;
}

/** What delivers a rebuilt outcome note to the user's PXE: the app's
 * outcome-note utility, called through the user's wallet. */
export type OutcomeDelivery = (outcome: FoundOutcome) => Promise<void>;

// How the user reads its outcome. OutcomeReader computes the
// siloed tag from `$outcome_tag` and the contract address, asks the node for
// the private logs under it with their transaction effects (one
// getPrivateLogsByTags call, at most 20 logs per tag), and returns the first
// that opens under the outcome key; a log that does not open (another log
// under the same tag) is passed over. The outcome note must then reach the
// PXE: `deliver` hands it to the app's outcome-note utility with the
// transaction's hash, unique note hashes and first nullifier, when the
// rebuilt note is the logged one. Default: no
// paging, since one tag carries one outcome (every derived tag is used once:
// SecretStore advances its counter on every request).
/** Finds a request's outcome log, opens it and delivers its note. */
export class OutcomeReader {
  private readonly node: PrivateLogNode;
  private readonly contract: AztecAddress;

  constructor(node: PrivateLogNode, contract: FieldLike | AztecAddress) {
    this.node = node;
    this.contract = fieldAddress(contract, "contract");
  }

  /** The outcome under `outcomeTag` that opens with `keys`, with its
   * transaction; undefined when there is none yet. When logs carry the tag
   * but none opens, the last TagMismatchError is thrown. */
  async read(outcomeTag: FieldLike, keys: OutcomeKeys): Promise<FoundOutcome | undefined> {
    const tag = new SiloedTag(await outcomeLogTag(this.contract, outcomeTag));
    const [logs] = await this.node.getPrivateLogsByTags({ tags: [tag], includeEffects: true });
    let last: unknown;
    for (const log of logs ?? []) {
      try {
        const opened = await openOutcomeLog(log.logData, keys);
        return { ...opened, tx: logTx(log) };
      } catch (e) {
        if (!(e instanceof TagMismatchError) && !(e instanceof RangeError)) throw e;
        last = e;
      }
    }
    if (last !== undefined) throw last;
    return undefined;
  }

  /** read, then deliver the note when an outcome is found and its note is
   * the logged one (`noteMatches`); returns it. */
  async readAndDeliver(outcomeTag: FieldLike, keys: OutcomeKeys, deliver: OutcomeDelivery): Promise<FoundOutcome | undefined> {
    const found = await this.read(outcomeTag, keys);
    if (found?.noteMatches) await deliver(found);
    return found;
  }
}

/** The outcome-note utility's arguments in the library's order (the apps'
 * `deliver_outcome(owner, randomness, packed, tx)`, the randomness the
 * request's `rho`), with the
 * transaction's unique note hashes as the list aztec.js encodes as aztec-nr's
 * BoundedVec of MAX_NOTE_HASHES_PER_TX = 64. NoteMismatchError for an
 * outcome whose rebuilt note is not the logged one (`noteMatches` false),
 * which the PXE would drop. */
export function outcomeDeliveryArgs(found: FoundOutcome | FoundDelivery): unknown[] {
  if ("noteMatches" in found && !found.noteMatches) throw new NoteMismatchError(found.loggedNoteHash, found.note.noteHash);
  return [fieldAddress(found.note.owner), fieldFr(found.note.randomness), found.note.packed.map((x) => fieldFr(x)), outcomeTxArg(found.tx)];
}

/** An OutcomeTx as the library's `OutcomeTx` struct. The transaction's
 * unique note hashes, aztec-nr's BoundedVec of MAX_NOTE_HASHES_PER_TX, are
 * the non-secret-shared list: aztec.js encodes a BoundedVec argument from an array of
 * at most its capacity, padding the storage and writing `len` itself. */
function outcomeTxArg(tx: OutcomeTx): unknown {
  if (tx.uniqueNoteHashes.length > MAX_NOTE_HASHES_PER_TX) throw new RangeError("more note hashes than a transaction holds");
  return { tx_hash: fieldFr(tx.txHash), unique_note_hashes: tx.uniqueNoteHashes.map((x) => fieldFr(x)), first_nullifier: fieldFr(tx.firstNullifier) };
}

/** aztec-nr v6's MAX_NOTE_HASHES_PER_TX. */
export const MAX_NOTE_HASHES_PER_TX = 64;
