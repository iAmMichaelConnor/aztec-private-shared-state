// The privacy audit of a request whose intake keeps values off the chain, a
// secret-shared intake request in the scenarios (docs/ARCHITECTURE.md
// section 6, "Secret-shared intake", "The hidden requester" and "Fee payment"):
// what its intake transaction and the result transaction that finished its
// queue index put where everyone reads, checked against what the request
// keeps private. Each transaction's public places are its public calls (the
// contract, the sender and the calldata of each; pss-client's
// assertNoRequester `callArgs`), its public logs (any contract's) and its
// public data writes; note hashes, nullifiers and private logs are not
// scanned (they are commitments and ciphertexts). The checks: no requester
// address (assertNoRequester), no distinctive private value (what pss-client's
// intakeSummary names: under secret-shared receipt intake every value C commits to,
// the blinding and the outcome key; and the opened outcome's plaintext), no public log at all (the apply under node-held state logs no
// state; the intake none either), and each fee payer wFJ, never the user's
// account.
import { AztecAddress } from "@aztec-labs/aztec.js/addresses";
import { TxHash, type Tx } from "@aztec-labs/stdlib/tx";
import { assertNoRequester, auditFields, fieldHex, intakeSummary } from "@aztec-pss/pss-client";

import type { RunContext } from "../engine/context.ts";
import { defineKind, type Common } from "../engine/kind.ts";
import { big, check } from "../engine/scope.ts";
import { finishing, tipOf } from "../engine/tip.ts";
import type { OutcomeRecord } from "./tip-outcome.ts";
import type { TipRequestRecord } from "./tip-request.ts";

export interface TipAuditStep extends Common {
  /** The secret-shared request's bound name (a `tipRequest` step's); its result has
   * landed. */
  tipAudit: string;
  /** Its opened outcome (a `tipOutcome` step's name): the plaintext's values
   * join the scan. */
  outcome?: string;
}

/** The smallest value the scan looks for. A smaller one (a direction, a
 * code, an ok flag, a position) also counts heads, tails, flags and block
 * numbers, so finding it would say nothing; scenarios give the audited
 * request inputs at or above it. */
export const DISTINCTIVE = 1000n;

/** A transaction's public places. */
interface PublicPlaces {
  txHash: string;
  feePayer: string;
  /** Per public call: [contract, msgSender, ...calldata]. */
  calls: unknown[][];
  logs: unknown[][];
  writes: unknown[];
}

async function places(ctx: RunContext, txHash: string, what: string): Promise<PublicPlaces> {
  const hash = TxHash.fromString(txHash);
  const tx: Tx | undefined = ctx.network.sentTxs.get(txHash) ?? (await ctx.network.node.getTxByHash(hash));
  check(tx !== undefined, `${what}: the node no longer holds tx ${txHash}, whose public calls the audit reads`);
  const effect = await ctx.network.node.getTxEffect(hash);
  check(effect !== undefined, `${what}: no effect of tx ${txHash}`);
  return {
    txHash,
    feePayer: fieldHex(tx.data.feePayer.toBigInt()),
    calls: tx.getPublicCallRequestsWithCalldata().map((c) => [c.request.contractAddress, c.request.msgSender, ...c.calldata]),
    logs: effect.data.publicLogs.map((l) => [l.contractAddress, ...l.getEmittedFields()]),
    writes: effect.data.publicDataWrites.map((w) => w.value),
  };
}

export default defineKind<TipAuditStep>({
  key: "tipAudit",
  check(step) {
    check(typeof step.tipAudit === "string", "tipAudit names a request");
    return { fields: ["tipAudit", "outcome"] };
  },
  async run(ctx, step) {
    const req = ctx.scope.lookup(step.tipAudit) as TipRequestRecord;
    const tip = tipOf(ctx, req.namespace);
    const label = step.what ?? `${step.tipAudit} audit`;
    const { privateValues } = intakeSummary(req.intake);
    check(privateValues.length > 0, `${label}: ${step.tipAudit}'s ${req.intake.intake} intake keeps nothing off the chain`);
    const wfj = ctx.harness.tip?.wfj?.address;
    check(wfj !== undefined, `${label}: harness.json names no wFJ`);

    // the private values (under secret-shared receipt intake C's values, the
    // outcome key among them, and the blinding), and the outcome
    const named: [string, bigint][] = privateValues.map(([n, v]): [string, bigint] => [n, big(v)]);
    if (step.outcome) {
      const outcome = ctx.scope.lookup(step.outcome) as OutcomeRecord;
      named.push(...outcome.plaintext.map((v, k): [string, bigint] => [`outcome[${k}]`, v]));
    }
    const banned = new Map<bigint, string>();
    for (const [n, v] of named) if (v >= DISTINCTIVE) banned.set(v, banned.has(v) ? `${banned.get(v)}, ${n}` : n);
    const small = named.filter(([, v]) => v < DISTINCTIVE).map(([n]) => n);
    const requester = ctx.account(req.from);
    // a public write is scanned for the requester's address as well
    const writeBanned = new Map([...banned, [requester.toBigInt(), `address of ${req.from}`]]);

    const landing = await finishing(ctx, tip, req.index, req.block);
    const txs = [await places(ctx, req.txHash, `${label}: the intake`), await places(ctx, landing.txHash, `${label}: the result`)];
    for (const [k, p] of txs.entries()) {
      const what = `${label}: the ${k === 0 ? "intake" : "result"} tx ${p.txHash}`;
      check(BigInt(p.feePayer) === BigInt(wfj), `${what} paid through ${p.feePayer}, not wFJ ${wfj}`);
      check(BigInt(p.feePayer) !== requester.toBigInt(), `${what} paid from the requester's own account`);
      // a log here is [contract, ...fields]
      check(p.logs.length === 0, `${what} emitted ${p.logs.length} public logs: ${JSON.stringify(p.logs.map((l) => fieldHex(big(l[1]))))}`);
      await assertNoRequester([requester], { callArgs: p.calls, logs: p.logs });
      for (const [place, values, ban] of [["public call", p.calls, banned], ["public log", p.logs, banned], ["public write", p.writes, writeBanned]] as const) {
        for (const [path, f] of auditFields(values)) {
          check(!ban.has(f), `${what}: ${place} ${path} is the private ${ban.get(f)} ${fieldHex(f)}`);
        }
      }
    }
    const calls = (p: PublicPlaces) => p.calls.map((c) => `${fieldHex(AztecAddress.fromBigIntUnsafe(big(c[0])).toBigInt()).slice(0, 10)}..(${c.length - 2} fields)`).join(", ");
    ctx.logger.info(
      `[privacy] ${label}: intake tx ${txs[0]!.txHash} (public calls ${calls(txs[0]!)}; ${txs[0]!.writes.length} public writes) and result tx ${txs[1]!.txHash} ` +
        `(public calls ${calls(txs[1]!)}; ${txs[1]!.writes.length} public writes): both paid through wFJ, no public log, ` +
        `no requester address (${req.from}) and none of the ${banned.size} private values (${[...banned.values()].join("; ")}) ` +
        `in their public calls, logs or writes; not scanned, below ${DISTINCTIVE}: ${small.join(", ") || "none"}`,
    );
  },
});
