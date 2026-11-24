// Watching a request and its outcome across replaced blocks (opt-in; nothing
// in the library calls these). The pss-client README's "Replaced blocks"
// says which blocks can be replaced after a send returns (SEND_WAIT) and
// what the library does about it. A request transaction in a replaced block
// goes back to the node's pool, which mines it again while it is still
// valid and drops it otherwise (for one, when the block it was proven
// against was replaced too); the user's PXE deletes an outcome note
// delivered from a replaced block. The two helpers:
//
//   watchRequest   reads the request transaction's receipt every interval
//                  until it reaches `until`; once two reads in a row say
//                  `dropped` (one could be a node that is still handling a
//                  replacement), it sends the request again (the app's
//                  `resend`, the same arguments: requestIntake with the laid
//                  `args`) and watches the new transaction, at most three
//                  times, then throws; without `resend` it throws at once.
//                  A request whose receipts expired reverts when sent
//                  again; the app asks for new receipts instead.
//   watchOutcome   finds the outcome log and delivers its note (as
//                  OutcomeReader.readAndDeliver does), then reads the
//                  receipt of the transaction that carried it every
//                  interval until it reaches `until`; when that receipt
//                  is no longer mined, or is mined in another block than
//                  the one the note was delivered from (its block was
//                  replaced and the transaction mined again between two
//                  reads), the PXE has deleted the note with the replaced
//                  block: it finds the outcome again, in whichever
//                  transaction lands it next, and delivers it again.
//
// Each holds state for the length of one call only (the transaction it
// watches) and runs until it ends or `signal` aborts (give it
// `AbortSignal.timeout(ms)` to bound it). `until` defaults to `proven`: a
// proposer can replace a block before its checkpoint, and an epoch prune or
// an L1 reorg can still replace a checkpointed one.

import { TxHash } from "@aztec-labs/aztec.js/tx";

import type { FoundOutcome, OutcomeDelivery, OutcomeReader } from "./discovery.ts";
import type { FieldLike } from "./field.ts";
import { DEFAULT_POLL_INTERVAL_MS, type OutcomeKeys } from "./outcome.ts";
import { sleep } from "./sleep.ts";

/** The Aztec node method the watchers read (aztec.js AztecNode). */
export interface TxReceiptNode {
  getTxReceipt(txHash: TxHash): Promise<{ status: string; blockHash?: { toString(): string } }>;
}

/** The receipt statuses a watch can end at, in the order a block reaches
 * them. */
export type WatchedStatus = "checkpointed" | "proven" | "finalized";

/** The mined statuses in order (stdlib TxStatus). */
const MINED = ["proposed", "checkpointed", "proven", "finalized"] as const;

/** Whether `status` is mined and at or past `until`. */
function reached(status: string, until: WatchedStatus): boolean {
  const at = MINED.indexOf(status as (typeof MINED)[number]);
  return at >= 0 && at >= MINED.indexOf(until);
}

/** Whether `status` is a mined one (the transaction is in a block). */
function mined(status: string): boolean {
  return (MINED as readonly string[]).includes(status);
}

/** How many times watchRequest sends a dropped request again. */
const MAX_RESENDS = 3;
/** How many reads in a row must say `dropped` before a resend. */
const DROPPED_READS = 2;

interface WatchTiming {
  /** Default `proven`. */
  until?: WatchedStatus;
  /** How often a watcher reads; default DEFAULT_POLL_INTERVAL_MS. */
  intervalMs?: number;
  signal?: AbortSignal;
}

export interface WatchRequestOptions extends WatchTiming {
  node: TxReceiptNode;
  /** The request transaction's hash. */
  txHash: string;
  /** Send the request again (the same arguments) and return the new
   * transaction's hash; without it a dropped request throws. */
  resend?: () => Promise<string>;
}

/** Where a watched request ended. */
export interface WatchedRequest {
  /** The transaction that reached `until`: the first one, or the last one
   * sent again. */
  txHash: string;
  status: string;
  /** How many times the request was sent again. */
  resends: number;
}

/** Read a request transaction's receipt until it reaches `until`, sending
 * the request again when it is dropped (the comment at the top). */
export async function watchRequest(o: WatchRequestOptions): Promise<WatchedRequest> {
  const until = o.until ?? "proven";
  let txHash = o.txHash;
  let resends = 0;
  let dropped = 0;
  for (;;) {
    const { status } = await o.node.getTxReceipt(TxHash.fromString(txHash));
    if (reached(status, until)) return { txHash, status, resends };
    dropped = status === "dropped" ? dropped + 1 : 0;
    if (dropped >= DROPPED_READS) {
      if (o.resend === undefined || resends >= MAX_RESENDS) {
        throw new Error(`request transaction ${txHash} was dropped${o.resend === undefined ? "" : `, and it was sent again ${resends} time(s)`}`);
      }
      txHash = await o.resend();
      resends++;
      dropped = 0;
      continue;
    }
    await sleep(o.intervalMs ?? DEFAULT_POLL_INTERVAL_MS, o.signal);
  }
}

export interface WatchOutcomeOptions extends WatchTiming {
  /** Finds the outcome (an OutcomeReader). */
  reader: Pick<OutcomeReader, "read">;
  outcomeTag: FieldLike;
  keys: OutcomeKeys;
  deliver: OutcomeDelivery;
  node: TxReceiptNode;
}

/** Find and deliver an outcome, and deliver it again each time the block
 * that carried it is replaced and it lands again, until the transaction
 * that carries it reaches `until` (the comment at the top). Returns the
 * outcome last delivered and how many times it was delivered. */
export async function watchOutcome(o: WatchOutcomeOptions): Promise<FoundOutcome & { deliveries: number }> {
  const until = o.until ?? "proven";
  /** The outcome delivered, and the block hash it was delivered from. */
  let delivered: { found: FoundOutcome; block: string } | undefined;
  let deliveries = 0;
  const receipt = (found: FoundOutcome) => o.node.getTxReceipt(TxHash.fromString(found.tx.txHash));
  for (;;) {
    if (delivered === undefined) {
      const found = await o.reader.read(o.outcomeTag, o.keys);
      const at = found === undefined ? undefined : await receipt(found);
      if (found !== undefined && at !== undefined && mined(at.status)) {
        await o.deliver(found);
        delivered = { found, block: String(at.blockHash) };
        deliveries++;
      }
    }
    if (delivered !== undefined) {
      const at = await receipt(delivered.found);
      // its block was replaced: the PXE deleted the note with it
      if (!mined(at.status) || String(at.blockHash) !== delivered.block) delivered = undefined;
      else if (reached(at.status, until)) return { ...delivered.found, deliveries };
    }
    await sleep(o.intervalMs ?? DEFAULT_POLL_INTERVAL_MS, o.signal);
  }
}
