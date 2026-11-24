// The fee-payer check of a tip run (docs/ARCHITECTURE.md section 6, "Fee
// payment"). run.sh calls it after the smoke and the drivers, while the
// network is still up:
//
//   node harness/fee-payers.ts
//
// It reads every transaction mined from the fee setup's first block on
// (harness.json tip.fees.fromBlock) and finds its fee payer in its effect:
// the protocol takes a transaction's fee from its fee payer's FeeJuice
// balance, a public data write at that balance's leaf. A transaction that
// paid through wFJ writes wFJ's leaf with the value before it less exactly
// its fee; a higher value means FeeJuice was credited to wFJ in the same
// transaction, which only a claim does. A transaction that does not write
// wFJ's leaf is recorded under the funded payer whose own FeeJuice balance
// it moved, or as another payer.
//
// The check passes when every transaction paid through wFJ, each funding
// transaction of harness/fees.ts carries its claim, and no other transaction
// (a request, a result, a deployment, configure, a skip, the relayer's init
// round, the smoke's) does, when no funded payer's own FeeJuice balance
// moved, and when every init transaction harness/tip.ts init recorded is
// among the checked ones. It writes
// <run>/fee-payers.json, one record per transaction, and logs one line per
// transaction. Environment: E2E_HARNESS, NODE_EXTRA_CA_CERTS.
import { AztecAddress } from "@aztec-labs/aztec.js/addresses";
import { Fr } from "@aztec-labs/aztec.js/fields";
import { ProtocolContractAddress } from "@aztec-labs/aztec.js/protocol";
import { BlockNumber } from "@aztec-labs/foundation/branded-types";
import { computePublicDataTreeLeafSlot, deriveStorageSlotInMap } from "@aztec-labs/stdlib/hash";

import { writeFileSync } from "node:fs";
import { join } from "node:path";

import { connectNode, harnessLogger, loadHarness } from "./harness.ts";

const logger = harnessLogger("fee-payers");

/** The FeeJuice contract's `balances` map (aztec.js getFeeJuiceBalance). */
const BALANCES_SLOT = new Fr(1n);
/** Blocks read per call. */
const PAGE = 50;

/** One transaction as the record keeps it. */
interface FeeRecord {
  block: number;
  tx: string;
  /** "wFJ", a funded payer's name, or "another payer". */
  payer: string;
  fee: string;
  /** FeeJuice credited to wFJ in this transaction (a claim). */
  claim: boolean;
  /** One of harness/fees.ts's funding transactions. */
  funding?: string;
  /** The relayer's init transaction of this deployment (harness/tip.ts init). */
  init?: string;
}

async function balanceLeaf(owner: AztecAddress): Promise<string> {
  return (await computePublicDataTreeLeafSlot(ProtocolContractAddress.FeeJuice, await deriveStorageSlotInMap(BALANCES_SLOT, owner))).toString();
}

async function main() {
  const h = loadHarness();
  const fees = h.tip?.fees;
  const wfjHex = h.tip?.wfj?.address;
  if (!fees || !wfjHex || !h.tip?.payers) throw new Error("harness.json has no tip.fees, tip.wfj or tip.payers: harness/fees.ts did not run");
  const { node } = await connectNode(h, logger);
  const wfj = AztecAddress.fromBigIntUnsafe(BigInt(wfjHex));
  const wfjLeaf = await balanceLeaf(wfj);
  const payerLeaves = new Map<string, string>();
  for (const [name, address] of Object.entries(h.tip.payers)) payerLeaves.set(await balanceLeaf(AztecAddress.fromBigIntUnsafe(BigInt(address))), name);
  const fundingOf = new Map(Object.entries(fees.funding).map(([payer, tx]) => [tx, payer]));
  const initOf = new Map(Object.entries(h.tip.deployments).flatMap(([name, d]) => (d.initTx ? [[d.initTx, name] as const] : [])));

  // wFJ's public FeeJuice balance before the fee setup, as harness/fees.ts
  // read it (or read here, while the node still holds that block's state).
  let balance =
    fees.wfjBalanceBefore !== undefined
      ? BigInt(fees.wfjBalanceBefore)
      : fees.fromBlock > 1
        ? (await node.getPublicStorageAt(BlockNumber(fees.fromBlock - 1), ProtocolContractAddress.FeeJuice, await deriveStorageSlotInMap(BALANCES_SLOT, wfj))).toBigInt()
        : 0n;
  const latest = await node.getBlockNumber();
  const records: FeeRecord[] = [];
  const failures: string[] = [];
  for (let from = fees.fromBlock; from <= latest; from += PAGE) {
    const blocks = await node.getBlocks(BlockNumber(from), Math.min(PAGE, latest - from + 1), { includeTransactions: true });
    for (const block of blocks) {
      const number = Number(block.header.globalVariables.blockNumber);
      for (const effect of block.body.txEffects) {
        const tx = effect.txHash.toString();
        const fee = effect.transactionFee.toBigInt();
        const funding = fundingOf.get(tx);
        const init = initOf.get(tx);
        const writes = new Map<string, bigint>(effect.publicDataWrites.map((w) => [w.leafSlot.toString(), w.value.toBigInt()]));
        const own = [...payerLeaves].filter(([leaf]) => writes.has(leaf)).map(([, name]) => name);
        let payer = "another payer";
        let claim = false;
        const after = writes.get(wfjLeaf);
        if (after !== undefined) {
          payer = "wFJ";
          claim = after !== balance - fee;
          balance = after;
        } else if (own.length) {
          payer = own.join(", ");
        }
        const record: FeeRecord = { block: number, tx, payer, fee: fee.toString(), claim, ...(funding && { funding }), ...(init && { init }) };
        records.push(record);
        logger.info(
          `block ${number} tx ${tx}: fee payer ${payer}${payer === "wFJ" ? ` (${wfj})` : ""}, fee ${fee}${claim ? ", FeeJuice claimed to wFJ" : ""}` +
            `${funding ? `, funding transaction of ${funding}` : ""}${init ? `, the relayer's init round of ${init}` : ""}`,
        );
        if (payer !== "wFJ") failures.push(`${tx} (block ${number}) paid through ${payer}, not wFJ`);
        if (funding && !claim) failures.push(`${tx}: the funding transaction of ${funding} carries no claim`);
        if (!funding && claim) failures.push(`${tx} (block ${number}) carries a FeeJuice claim and is no funding transaction`);
        if (own.length) failures.push(`${tx} (block ${number}) moved the own FeeJuice balance of ${own.join(", ")}`);
      }
    }
  }
  const missing = [...fundingOf].filter(([tx]) => !records.some((r) => r.tx === tx)).map(([, payer]) => payer);
  if (missing.length) failures.push(`funding transactions not found from block ${fees.fromBlock}: ${missing.join(", ")}`);
  const missingInit = [...initOf].filter(([tx]) => !records.some((r) => r.tx === tx)).map(([tx, name]) => `${name} (${tx})`);
  if (missingInit.length) failures.push(`the relayer's init transactions not found from block ${fees.fromBlock}: ${missingInit.join(", ")}`);
  if (records.length === fundingOf.size) failures.push("no transaction besides the funding transactions: nothing was checked");
  writeFileSync(join(h.runDir, "fee-payers.json"), JSON.stringify(records, null, 2) + "\n");
  if (failures.length) {
    for (const f of failures) logger.error(`fee payer: ${f}`);
    throw new Error(`${failures.length} fee-payer failure(s) in ${records.length} transactions (fee-payers.json)`);
  }
  const claims = records.filter((r) => r.claim).length;
  const inits = records.filter((r) => r.init).map((r) => `${r.init} ${r.tx}`);
  logger.info(
    `fee payers: PASS: ${records.length} transactions in blocks ${fees.fromBlock}..${latest}, every one paid through wFJ (${wfj}); ` +
      `${claims} FeeJuice claims, each in its payer's funding transaction, none in any other transaction` +
      `${inits.length ? `; the relayer's init transaction(s) among them: ${inits.join(", ")}` : ""}`,
  );
}

main().catch((err) => {
  logger.error(`fee-payers: FAIL: ${err?.stack ?? err}`);
  process.exit(1);
});
