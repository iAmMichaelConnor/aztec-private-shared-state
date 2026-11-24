// Node-side proof verification checks for a real-proof run.
//
// A local network reports realProofs from a config flag, and the flag can
// read true while the node still accepts any proof bytes (see the
// comment on node-side proof verification in run.sh). So a run does not
// trust the flag: it reads the node's own log (harness.json's networkLog) and
// requires
//   - "Starting QueuedIVCVerifier": the node built its transaction verifier;
//   - for every transaction this driver sends, the proof validator's
//     "Accepted <tx hash> with valid proof", preceded in the log by a
//     "Chonk verification successful" that no other acceptance claims;
//   - for one transaction, a copy whose proof bytes are corrupted after the
//     client proved it, refused by the node with "Invalid proof" while the
//     honest transaction is then accepted.
//
// The verifier's success line names no transaction, so the hash comes from
// the proof validator's line (run.sh starts the node with trace logging for
// p2p:tx_validator:proof). Both lines are written by the same validation, the
// Chonk line first, so walking the log in order and letting each acceptance
// claim one earlier unclaimed Chonk line ties every acceptance to its own
// verification even while other senders (a relayer) submit transactions to
// the same node.
//
// A driver calls requireNodeVerifier once, wraps its node client with
// enforceNodeVerification before the wallet sends anything, arms the
// negative with rejectTamperedCopyOfNextTx(label) right before one send, and
// calls finish() at the end.
import { Fr } from "@aztec-labs/aztec.js/fields";
import { ChonkProof } from "@aztec-labs/stdlib/proofs";
import { Tx } from "@aztec-labs/stdlib/tx";

import { readFileSync } from "node:fs";

export const VERIFIER_STARTED = "Starting QueuedIVCVerifier";
export const PROOF_VERIFIED = "Chonk verification successful";
export const PROOF_FAILED = "Failed to verify Chonk proof";
/** The proof validator's line for a transaction whose proof the node verified. */
export const proofAccepted = (txHash: string) => `Accepted ${txHash} with valid proof`;
const PROOF_ACCEPTED = /Accepted (0x[0-9a-f]+) with valid proof/;

/** The one call of the node client these checks wrap. */
export interface TxSender {
  sendTx(tx: Tx): Promise<void>;
}

/** What the checks log through. */
export interface InfoLogger {
  info(message: string): void;
}

/** The handle enforceNodeVerification returns. */
export interface NodeVerification {
  /** Arms the node-side negative for the next transaction the wallet sends. */
  rejectTamperedCopyOfNextTx(label: string): void;
  /** How many transactions the node accepted, each with its own verification line. */
  accepted(): number;
  /** Checks the run: the negative ran (unless `requireNegative` is false),
   * and every transaction this handle sent has exactly one acceptance line in
   * the node log, each tied to its own verification line. */
  finish(options?: { requireNegative?: boolean }): void;
}

/** The node log lines that contain `text`. */
function linesWith(logPath: string, text: string): string[] {
  return readFileSync(logPath, "utf8")
    .split("\n")
    .filter((line) => line.includes(text));
}

// How long a check waits for a node log line. The node writes
// its log asynchronously, so a line can trail the RPC reply that caused it;
// every check polls the log every 200 ms, 100 times (20 s), before it fails.
// Default 20 s: the lines appear within a second on an idle machine. A longer
// wait only delays the failure of a run whose node really never verified; a
// much shorter one can fail an honest run on a loaded host.
const POLLS = 100;
const POLL_MS = 200;

/** Waits until the node log holds at least `count` lines containing `text`.
 * Returns the matching lines. */
async function waitForLines(logPath: string, text: string, count: number, what: string): Promise<string[]> {
  for (let i = 0; i < POLLS; i++) {
    const lines = linesWith(logPath, text);
    if (lines.length >= count) return lines;
    await new Promise((resolve) => setTimeout(resolve, POLL_MS));
  }
  throw new Error(
    `node log ${logPath} lacks ${what}: wanted ${count} "${text}" lines, found ${linesWith(logPath, text).length}`,
  );
}

/** Ties each proof acceptance after the last verifier start to an earlier
 * unclaimed verification line. Returns how often each hash was accepted and
 * the hashes accepted without a verification of their own. */
function matchAcceptances(logPath: string): { acceptances: Map<string, number>; unverified: string[] } {
  const lines = readFileSync(logPath, "utf8").split("\n");
  const start = lines.findLastIndex((line) => line.includes(VERIFIER_STARTED));
  const acceptances = new Map<string, number>();
  const unverified: string[] = [];
  let unclaimed = 0;
  for (const line of lines.slice(start + 1)) {
    if (line.includes(PROOF_VERIFIED)) {
      unclaimed++;
      continue;
    }
    const hash = PROOF_ACCEPTED.exec(line)?.[1];
    if (hash === undefined) continue;
    acceptances.set(hash, (acceptances.get(hash) ?? 0) + 1);
    if (unclaimed > 0) unclaimed--;
    else unverified.push(hash);
  }
  return { acceptances, unverified };
}

/** Fails unless the node log shows the transaction verifier was built. */
export async function requireNodeVerifier(logPath: string, logger: InfoLogger): Promise<string> {
  const [line = ""] = await waitForLines(logPath, VERIFIER_STARTED, 1, "the transaction verifier");
  logger.info(`node verifier confirmed from its log: ${line.trim()}`);
  return line.trim();
}

/**
 * Wraps `node.sendTx` (the one call through which the wallet submits a
 * proved transaction) so that every accepted transaction must add its own
 * "Accepted <tx hash> with valid proof" line to the node log. Pass the same node
 * client object the wallet is created with. Returns a handle whose
 * `rejectTamperedCopyOfNextTx` arms the node-side negative for the next
 * submission and whose `finish()` checks the totals at the end of the run.
 */
export function enforceNodeVerification(node: TxSender, logPath: string, logger: InfoLogger): NodeVerification {
  const send = node.sendTx.bind(node);
  // Verification lines already present belong to nothing this driver sent.
  const baseline = linesWith(logPath, PROOF_VERIFIED).length;
  const sent: string[] = [];
  let tamperLabel: string | undefined;
  let tamperRejected = false;

  node.sendTx = async (tx: Tx) => {
    const txHash = tx.getTxHash().toString();
    if (tamperLabel !== undefined) {
      const label = tamperLabel;
      tamperLabel = undefined;
      await submitTamperedCopy(tx, txHash, label);
      tamperRejected = true;
    }
    await send(tx);
    await waitForLines(logPath, proofAccepted(txHash), 1, `the acceptance of tx ${txHash}`);
    sent.push(txHash);
    logger.info(`node verified the proof of tx ${txHash} ("${proofAccepted(txHash)}")`);
  };

  /** Sends `tx` with one proof field changed and requires the node to refuse it. */
  async function submitTamperedCopy(tx: Tx, txHash: string, label: string): Promise<void> {
    const fields = [...tx.chonkProof.fields];
    const at = Math.floor(fields.length / 2);
    fields[at] = new Fr(fields[at]!.toBigInt() ^ 0xabn);
    // A ChonkProof built from fields alone carries no compressed bytes, so
    // the changed fields are what goes over the wire (the honest proof
    // travels compressed). Everything else, the tx hash included, is the
    // honest transaction's.
    const tamperedProof = new ChonkProof(fields);
    const onWire = ChonkProof.fromBuffer(tamperedProof.toBuffer());
    if (onWire.fields[at]!.equals(tx.chonkProof.fields[at]!)) {
      throw new Error("the corrupted proof field did not survive serialization");
    }
    const tampered = new Tx(tx.txHash, tx.data, tamperedProof, tx.contractClassLogFields, tx.publicFunctionCalldata);
    logger.info(`node-side negative: submitting ${label} (tx ${txHash}) with proof field ${at} corrupted after client proving`);
    const failedBefore = linesWith(logPath, PROOF_FAILED).length;
    let message: string | undefined;
    try {
      await send(tampered);
    } catch (error) {
      message = String((error as Error).message ?? error);
    }
    if (message === undefined) {
      throw new Error(`the node ACCEPTED ${label} with corrupted proof bytes`);
    }
    // The node's own reason. A transport, fee or other validation error
    // must not satisfy the negative.
    if (!message.includes("Invalid proof")) {
      throw new Error(`the node refused the corrupted ${label} for another reason: ${message}`);
    }
    await waitForLines(logPath, PROOF_FAILED, failedBefore + 1, "the failed verification");
    const [refusal = ""] = await waitForLines(logPath, `Received invalid tx ${txHash}: Invalid proof`, 1, "the node's refusal");
    logger.info(`node refused the corrupted ${label}: "${message}"; node log: ${refusal.trim()}`);
  }

  return {
    rejectTamperedCopyOfNextTx(label: string) {
      tamperLabel = label;
    },
    accepted: () => sent.length,
    finish({ requireNegative = true } = {}) {
      if (requireNegative && !tamperRejected) throw new Error("the node-side negative never ran");
      if (tamperLabel !== undefined) throw new Error(`the node-side negative was armed for ${tamperLabel} but no transaction followed`);
      const { acceptances, unverified } = matchAcceptances(logPath);
      for (const txHash of sent) {
        const count = acceptances.get(txHash) ?? 0;
        if (count !== 1) throw new Error(`node log has ${count} "${proofAccepted(txHash)}" lines, wanted 1`);
        if (unverified.includes(txHash)) {
          throw new Error(`node log accepts tx ${txHash} with no "${PROOF_VERIFIED}" line of its own before it`);
        }
      }
      const verified = linesWith(logPath, PROOF_VERIFIED).length - baseline;
      logger.info(
        `node-side verification: ${sent.length} transactions accepted, each by hash after its own "${PROOF_VERIFIED}" line` +
          ` (${verified} such lines since this client connected)` +
          (tamperRejected ? `, 1 corrupted proof refused with "Invalid proof"` : ""),
      );
    },
  };
}
