// The gas every transaction of a run used and the fee it paid
// (docs/ARCHITECTURE.md section 6, "Fee payment"; scenarios/README.md, "Gas
// per transaction kind"). A step kind that sends or lands a transaction
// names it and its kind (StepKind.txs), and the driver reads what the
// transaction declared while the node still holds it; tip.ts deploy
// recorded its deployment and configure transactions' (harness.json
// tip.declaredGas). Once the steps passed, the driver reads each
// transaction's receipt, block and effect, logs one line per transaction
// and one per kind and round type, and writes <run>/gas-<scenario>.json.
// On the reorg network (E2E_REORG=1) a transaction a reorg dropped has no
// receipt to read: it is logged as dropped and left out of the record.
//
// What is read, and how:
// - The L2 gas billed: the fee over the block's fee per L2 gas. The protocol
//   charges billed gas times fees per gas; DA gas costs nothing on this
//   network (the sequencer's fees per gas are GasFees(0, mana fee)) and the
//   senders set no priority fee. With no teardown (wFJ runs none) the
//   billed gas is the gas used: the private part with the transaction
//   overhead, and the AVM's execution of the enqueued public calls.
// - The AVM's execution gas: the L2 gas billed less the private part the
//   transaction declares (its kernel's gas used), the part the TXE cannot
//   meter (examples' READMEs, "What the world learns per round type").
// - The DA gas used: from the effect, as the private kernel and the AVM
//   meter it: TX_DA_GAS_OVERHEAD, then DA_GAS_PER_FIELD per published field
//   (note hashes, nullifiers, L2-to-L1 messages, each private log's fields
//   and its length, each public data write's two fields, each public log's
//   fields and header, each contract class log's fields and its address),
//   where the fee payer's balance write is metered for a private-only
//   transaction only. The fee cannot tell it, its price being 0.
// - The declared gas: the gas limits and max fees per gas, and wFJ's charge,
//   their maximum gas cost (pss-client maxGasCost), which wFJ's pay_fee()
//   takes from the sender's private balance with no refund.
import { DA_GAS_PER_FIELD, PUBLIC_DATA_WRITE_LENGTH, PUBLIC_LOG_HEADER_LENGTH, TX_DA_GAS_OVERHEAD } from "@aztec-labs/constants";
import { BlockNumber } from "@aztec-labs/foundation/branded-types";
import { TxHash, TxStatus, type TxEffect } from "@aztec-labs/stdlib/tx";
import { maxGasCost, type FeeTxKind } from "@aztec-pss/pss-client";

import { writeFileSync } from "node:fs";
import { join } from "node:path";

import { declaredGas, type DeclaredGas } from "../harness/harness.ts";
import type { RunContext } from "./context.ts";
import { check } from "./scope.ts";


/** A transaction kind as the gas record names it: a fee setting's kind,
 * the init round's landing, or another call (an oracle's set_price). */
export type GasKind = FeeTxKind | "init" | "other";

/** One transaction a step sent or landed. */
export interface TxOfStep {
  kind: GasKind;
  txHash: string;
  /** The round type: the circuit of a request, of the result or skip that
   * finished it, of the outcome a redeem spends; the contract of a deploy;
   * the function of another call. */
  round?: string;
  /** The tip deployment it belongs to (a scenario's name). */
  deployment?: string;
}

/** One transaction as the record keeps it. */
export interface GasRecord extends TxOfStep {
  block: number;
  /** The L2 gas billed (fee / fee per L2 gas), the AVM's part of it, and
   * the DA gas used; the AVM's part and the DA need what the transaction
   * declared (without it the DA counts the fee payer's write, at most 64 high). */
  l2Gas: number;
  avmL2Gas?: number;
  daGas: number;
  /** The protocol's fee (paid from wFJ's public balance), in FJ base units. */
  fee: string;
  feePerL2Gas: string;
  /** The declared gas limits and wFJ's charge (their maximum gas cost);
   * undefined when the node no longer held the transaction. */
  limits?: { daGas: number; l2Gas: number };
  charge?: string;
}

/** Every transaction the run's steps named, in order, with what each declared. */
export class GasLedger {
  readonly txs: TxOfStep[] = [];
  readonly #declared = new Map<string, DeclaredGas>();

  /** Adds transactions and reads what each declared, while the node holds it. */
  async add(ctx: RunContext, txs: TxOfStep[]): Promise<void> {
    for (const t of txs) {
      if (this.txs.some((k) => k.txHash === t.txHash)) continue;
      this.txs.push(t);
      const recorded = ctx.harness.tip?.declaredGas?.[t.txHash];
      const tx = recorded ? undefined : (ctx.network.sentTxs.get(t.txHash) ?? (await ctx.network.node.getTxByHash(TxHash.fromString(t.txHash))));
      const declared = recorded ?? (tx && declaredGas(tx));
      if (declared) this.#declared.set(t.txHash, declared);
      else ctx.logger.warn(`gas: the node no longer holds tx ${t.txHash} (${t.kind}); its gas settings are not recorded`);
    }
  }

  /** The scenario's tip deployments' deployment (the first contracts' too),
   * funding (a first contract's `fund` mints, kind "other") and configure
   * transactions (the init is the tipInit step's). */
  async addHarness(ctx: RunContext): Promise<void> {
    for (const [name, deployment] of Object.entries(ctx.scenario.tip ?? {})) {
      const d = ctx.harness.tip?.deployments[deployment];
      if (!d) continue;
      for (const [k, c] of Object.entries(d.contracts ?? {})) if (c.deployTx) await this.add(ctx, [{ kind: "deploy", txHash: c.deployTx, round: k, deployment: name }]);
      for (const [k, c] of Object.entries(d.contracts ?? {})) if (c.fundTx) await this.add(ctx, [{ kind: "other", txHash: c.fundTx, round: `fund ${k}`, deployment: name }]);
      if (d.deployTx) await this.add(ctx, [{ kind: "deploy", txHash: d.deployTx, round: d.contract, deployment: name }]);
      if (d.configureTx) await this.add(ctx, [{ kind: "configure", txHash: d.configureTx, deployment: name }]);
    }
  }

  declared(txHash: string): DeclaredGas | undefined {
    return this.#declared.get(txHash);
  }
}

/** The DA gas a transaction's effect used (see the header). */
export function effectDaGas(e: TxEffect, publicCalls: boolean): number {
  let fields = e.noteHashes.length + e.nullifiers.length + e.l2ToL1Msgs.length + PUBLIC_DATA_WRITE_LENGTH * (e.publicDataWrites.length - (publicCalls ? 1 : 0));
  for (const log of e.privateLogs) fields += log.emittedLength + 1;
  for (const log of e.publicLogs) fields += log.fields.length + PUBLIC_LOG_HEADER_LENGTH;
  for (const log of e.contractClassLogs) fields += log.emittedLength + 1;
  return TX_DA_GAS_OVERHEAD + fields * DA_GAS_PER_FIELD;
}

/** The transaction's record; undefined for one a reorg dropped, on the
 * reorg network only. */
async function measure(ctx: RunContext, t: TxOfStep, declared: DeclaredGas | undefined): Promise<GasRecord | undefined> {
  const node = ctx.network.node;
  const hash = TxHash.fromString(t.txHash);
  const receipt = await node.getTxReceipt(hash);
  if (receipt.status === TxStatus.DROPPED && process.env.E2E_REORG === "1") return undefined;
  check(receipt.blockNumber !== undefined && receipt.transactionFee !== undefined, `gas: tx ${t.txHash} (${t.kind}) is not mined (${receipt.status})`);
  const block = Number(receipt.blockNumber);
  const header = (await node.getBlock(BlockNumber(block)))?.header;
  check(header !== undefined, `gas: no block ${block}`);
  const { feePerDaGas, feePerL2Gas } = header.globalVariables.gasFees;
  check(feePerDaGas === 0n && feePerL2Gas > 0n, `gas: block ${block} prices DA gas at ${feePerDaGas} and L2 gas at ${feePerL2Gas}; the L2 gas is read as fee / fee per L2 gas only with DA gas at 0`);
  const fee = receipt.transactionFee;
  check(fee % feePerL2Gas === 0n, `gas: tx ${t.txHash}'s fee ${fee} is not a multiple of block ${block}'s fee per L2 gas ${feePerL2Gas} (a priority fee?)`);
  const effect = (await node.getTxEffect(hash))?.data;
  check(effect !== undefined, `gas: no effect of tx ${t.txHash}`);
  const l2Gas = Number(fee / feePerL2Gas);
  const record: GasRecord = { ...t, block, l2Gas, daGas: effectDaGas(effect, declared?.publicCalls ?? false), fee: fee.toString(), feePerL2Gas: feePerL2Gas.toString() };
  if (declared) {
    const maxFees = { feePerDaGas: BigInt(declared.maxFeesPerGas.feePerDaGas), feePerL2Gas: BigInt(declared.maxFeesPerGas.feePerL2Gas) };
    Object.assign(record, { avmL2Gas: l2Gas - declared.privateGas.l2Gas, limits: declared.limits, charge: maxGasCost(declared.limits, maxFees).toString() });
  }
  return record;
}

const n = (x: number) => x.toLocaleString("en-US");
const span = (xs: number[]) => (Math.min(...xs) === Math.max(...xs) ? n(xs[0]!) : `${n(Math.min(...xs))}..${n(Math.max(...xs))}`);

/** Reads every transaction of the ledger, logs it and writes <run>/gas-<scenario>.json. */
export async function gasReport(ctx: RunContext, ledger: GasLedger): Promise<GasRecord[]> {
  const records: GasRecord[] = [];
  for (const t of ledger.txs) {
    const record = await measure(ctx, t, ledger.declared(t.txHash));
    if (record) records.push(record);
    else ctx.logger.info(`[gas] ${t.kind}${t.round ? ` ${t.round}` : ""}${t.deployment ? ` (${t.deployment})` : ""} tx ${t.txHash}: dropped by a reorg, not measured`);
  }
  for (const r of records) {
    ctx.logger.info(
      `[gas] ${r.kind}${r.round ? ` ${r.round}` : ""}${r.deployment ? ` (${r.deployment})` : ""} tx ${r.txHash} block ${r.block}: ` +
        `L2 ${n(r.l2Gas)}${r.avmL2Gas === undefined ? "" : ` (AVM ${n(r.avmL2Gas)})`}, DA ${n(r.daGas)}; fee ${r.fee} at ${r.feePerL2Gas} per L2 gas; ` +
        `${r.limits ? `limits DA ${n(r.limits.daGas)} / L2 ${n(r.limits.l2Gas)}, wFJ charge ${r.charge}` : "limits not recorded"}`,
    );
  }
  // one line per kind and round type
  const groups = new Map<string, GasRecord[]>();
  for (const r of records) {
    const key = `${r.kind}${r.round ? ` ${r.round}` : ""}`;
    groups.set(key, [...(groups.get(key) ?? []), r]);
  }
  for (const [key, rs] of groups) {
    const known = rs.filter((r) => r.limits !== undefined);
    const limits = [...new Set(known.map((r) => `${n(r.limits!.daGas)} / ${n(r.limits!.l2Gas)}`))];
    const avm = known.map((r) => r.avmL2Gas!);
    ctx.logger.info(
      `[gas] ${key}: ${rs.length} tx, L2 ${span(rs.map((r) => r.l2Gas))}${avm.length ? ` (AVM ${span(avm)})` : ""}, DA ${span(rs.map((r) => r.daGas))}` +
        `${known.length ? `; limits DA / L2 ${limits.join(", ")}, L2 headroom ${Math.min(...known.map((r) => r.limits!.l2Gas / r.l2Gas)).toFixed(2)}x` : ""}` +
        `${known.length < rs.length ? `; ${rs.length - known.length} without recorded limits` : ""}`,
    );
  }
  writeFileSync(join(ctx.harness.runDir, `gas-${ctx.name}.json`), JSON.stringify(records, null, 2) + "\n");
  return records;
}
