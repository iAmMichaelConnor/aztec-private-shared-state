// The opt-in watchers (src/watch.ts) against a node whose receipts a test
// scripts: a dropped request sent again until it reaches the status asked
// for, only after two dropped reads, a bound on the sends, and an outcome
// delivered again after the block that carried it was replaced, also when
// its transaction is mined again between two reads.

import assert from "node:assert/strict";
import { describe, test } from "node:test";

import type { TxHash } from "@aztec-labs/aztec.js/tx";

import type { FoundOutcome } from "../src/discovery.ts";
import { watchOutcome, watchRequest, type TxReceiptNode } from "../src/watch.ts";

const tx = (n: number) => `0x${n.toString(16).padStart(64, "0")}`;

/** A node answering each transaction's receipts in the order given, the
 * last one repeating; `status@hash` names the block a mined one is in. */
function node(statuses: Record<string, string[]>): TxReceiptNode & { reads: string[] } {
  const reads: string[] = [];
  return {
    reads,
    async getTxReceipt(txHash: TxHash) {
      const hash = txHash.toString();
      reads.push(hash);
      const list = statuses[hash] ?? ["dropped"];
      const [status, blockHash] = (list.length > 1 ? list.shift()! : list[0]!).split("@");
      return { status: status!, blockHash };
    },
  };
}

describe("watchRequest", () => {
  test("a dropped request is sent again and watched until it is proven", async () => {
    const n = node({ [tx(1)]: ["proposed", "dropped"], [tx(2)]: ["pending", "checkpointed", "proven"] });
    const sent: string[] = [];
    const r = await watchRequest({
      node: n,
      txHash: tx(1),
      resend: async () => {
        sent.push("again");
        return tx(2);
      },
      intervalMs: 1,
    });
    assert.deepEqual(r, { txHash: tx(2), status: "proven", resends: 1 });
    assert.deepEqual(sent, ["again"]);
  });

  test("one dropped read between mined ones sends nothing", async () => {
    const n = node({ [tx(1)]: ["proposed", "dropped", "pending", "proven"] });
    const r = await watchRequest({ node: n, txHash: tx(1), resend: async () => assert.fail("sent again"), intervalMs: 1 });
    assert.deepEqual(r, { txHash: tx(1), status: "proven", resends: 0 });
  });

  test("ends at the status asked for; a dropped request without resend, or past three resends, throws", async () => {
    const n = node({ [tx(1)]: ["pending", "checkpointed"] });
    const r = await watchRequest({ node: n, txHash: tx(1), resend: async () => tx(9), until: "checkpointed", intervalMs: 1 });
    assert.deepEqual(r, { txHash: tx(1), status: "checkpointed", resends: 0 });
    await assert.rejects(watchRequest({ node: node({}), txHash: tx(3), intervalMs: 1 }), /was dropped$/);
    let next = 3;
    await assert.rejects(watchRequest({ node: node({}), txHash: tx(3), resend: async () => tx(++next), intervalMs: 1 }), /sent again 3 time/);
    await assert.rejects(watchRequest({ node: node({ [tx(5)]: ["pending"] }), txHash: tx(5), intervalMs: 5, signal: AbortSignal.timeout(20) }), { name: "TimeoutError" });
  });
});

describe("watchOutcome", () => {
  const outcome = (hash: string) => ({ tx: { txHash: hash, uniqueNoteHashes: [], firstNullifier: tx(0) } }) as unknown as FoundOutcome;
  const watch = async (finds: (FoundOutcome | undefined)[], n: TxReceiptNode) => {
    const reader = { read: async () => (finds.length > 1 ? finds.shift() : finds[0]) };
    const delivered: string[] = [];
    const found = await watchOutcome({
      reader,
      outcomeTag: 1n,
      keys: {} as never,
      deliver: async (f) => {
        delivered.push(f.tx.txHash);
      },
      node: n,
      intervalMs: 1,
    });
    return { found, delivered };
  };

  test("an outcome whose block was replaced is delivered again when it lands again", async () => {
    // the outcome lands in tx 1, whose block is replaced; the result lands
    // again in tx 2
    const n = node({ [tx(1)]: ["proposed@0xb1", "proposed@0xb1", "pending"], [tx(2)]: ["checkpointed@0xb2", "checkpointed@0xb2", "proven@0xb2"] });
    const { found, delivered } = await watch([outcome(tx(1)), undefined, outcome(tx(2))], n);
    assert.deepEqual(delivered, [tx(1), tx(2)]);
    assert.equal(found.deliveries, 2);
    assert.equal(found.tx.txHash, tx(2));
  });

  test("a transaction mined again in another block between two reads is delivered again", async () => {
    // every read says mined, but the block hash changes: the block was
    // replaced and the pool mined the transaction again
    const n = node({ [tx(1)]: ["proposed@0xb1", "proposed@0xb1", "checkpointed@0xb2", "proven@0xb2"] });
    const { found, delivered } = await watch([outcome(tx(1))], n);
    assert.deepEqual(delivered, [tx(1), tx(1)]);
    assert.equal(found.deliveries, 2);
  });
});
