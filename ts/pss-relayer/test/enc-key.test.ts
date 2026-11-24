// A node operator's enc key rotation into a secret-shared on-chain intake contract
// (src/enc-key.ts) against a fake node admin socket and a fake contract: the
// epoch taken from the stored one, the node's signature submitted and the
// stored key checked, the node asked to record it; a wrong expected epoch, a
// refusal, a node of another party and a stored key that is not the signed
// one each stop the rotation; a rerun sends nothing to a contract that
// already stores the node's key; a node whose Aztec node is behind, or whose
// prune fails, records later; and the admin socket client over a real Unix socket, including a
// node that closes the connection without an answer.

import assert from "node:assert/strict";
import { rmSync } from "node:fs";
import { createServer } from "node:net";
import { join } from "node:path";
import { describe, test } from "node:test";

import type { Fr } from "@aztec-labs/aztec.js/fields";

import type { AdminAnswer, StoredEncKey } from "@aztec-pss/pss-client";
import { scratchDir } from "@aztec-pss/test-support";

import { adminSocket, rotateEncKey, type EncKeyContract } from "../src/enc-key.ts";

const ADDRESS = "0x000000000000000000000000000000000000000000000000000000000000a11c";
const FROM = "0x00000000000000000000000000000000000000000000000000000000000c0ffe";
const FEE = { method: "account" as const };

/** The contract's `enc_keys` and the transactions sent to it. */
class FakeContract implements EncKeyContract {
  stored: StoredEncKey[] = [0, 1, 2].map(() => ({ x: 0n, y: 0n, epoch: 0 }));
  sent: { i: number; key: { x: bigint; y: bigint; epoch: number }; options: object }[] = [];
  /** When false the transaction lands but stores nothing (a stale view). */
  stores = true;
  methods = {
    rotate_enc_key: (i: number, key: { x: Fr; y: Fr; epoch: number }, signature: { s: Fr[]; e: Fr[] }) => ({
      send: async (options: object) => {
        assert.equal(signature.s.length, 2);
        assert.equal(signature.e.length, 2);
        assert.equal(key.epoch, this.stored[i]!.epoch + 1, "the contract takes the stored epoch + 1");
        const k = { x: key.x.toBigInt(), y: key.y.toBigInt(), epoch: key.epoch };
        this.sent.push({ i, key: k, options });
        if (this.stores) this.stored[i] = k;
        return { receipt: { txHash: { toString: () => "0x7a" } } };
      },
    }),
    get_enc_key: (i: number) => ({
      simulate: async (_options: object) => ({ result: { x: this.stored[i]!.x, y: this.stored[i]!.y, epoch: BigInt(this.stored[i]!.epoch) } }),
    }),
  };
}

/** Node `party`'s admin socket: signs at any epoch under its current key,
 * and its prune reports the stored epoch it reads (`view`, default the
 * contract's). */
class FakeNode {
  commands: Record<string, unknown>[] = [];
  enc = { x: "0x51", y: "0x52" };
  refuse?: string;
  index: number;
  view?: () => number;
  contract: FakeContract;
  constructor(party: number, contract: FakeContract) {
    this.index = party;
    this.contract = contract;
  }
  call = async (command: object): Promise<AdminAnswer> => {
    const c = command as Record<string, unknown>;
    this.commands.push(c);
    if (c.op === "sign_enc_key") {
      if (this.refuse) return { ok: false, refusal: { class: "conflict", error: this.refuse } };
      return {
        ok: true,
        enc_key: { index: this.index, namespace: c.namespace, enc: this.enc, epoch: c.epoch, signature: { s: ["0x1", "0x2"], e: ["0x3", "0x4"] } },
      };
    }
    if (c.op === "prune") {
      const stored = this.view ? this.view() : this.contract.stored[this.index]!.epoch;
      return { ok: true, pruned: 0, enc_epochs: [{ namespace: ADDRESS, stored_epoch: stored, recorded: [stored], retired: [] }] };
    }
    return { ok: false, refusal: { class: "bad_request", error: `unknown op ${String(c.op)}` } };
  };
}

function quietLog() {
  const lines: string[] = [];
  return { lines, info: (m: string) => lines.push(m), warn: (m: string) => lines.push(`warning: ${m}`) };
}

describe("rotateEncKey", () => {
  test("a node's first key takes epoch 1, is submitted, checked and recorded", async () => {
    const contract = new FakeContract();
    const node = new FakeNode(1, contract);
    const done = await rotateEncKey({ admin: node.call, contract, address: ADDRESS, party: 1, from: FROM, fee: FEE });
    assert.deepEqual(done, { namespace: ADDRESS, index: 1, epoch: 1, rotated: true, txHash: "0x7a", recorded: true });
    assert.deepEqual(
      node.commands.map((c) => [c.op, c.epoch]),
      [
        ["sign_enc_key", 1],
        ["prune", undefined],
      ],
    );
    assert.equal(node.commands[0]!.namespace, ADDRESS);
    assert.deepEqual(contract.stored[1], { x: 0x51n, y: 0x52n, epoch: 1 });
    assert.equal((contract.sent[0]!.options as { from: unknown }).from, FROM);
    // the next rotation takes epoch 2
    node.enc = { x: "0x61", y: "0x62" };
    const next = await rotateEncKey({ admin: node.call, contract, address: ADDRESS, party: 1, from: FROM, fee: FEE, epoch: 2 });
    assert.equal(next.epoch, 2);
    assert.deepEqual(contract.stored[1], { x: 0x61n, y: 0x62n, epoch: 2 });
  });

  test("an expected epoch other than the stored one + 1 is refused, before signing unless it is the stored one", async () => {
    const contract = new FakeContract();
    contract.stored[0] = { x: 1n, y: 2n, epoch: 3 };
    const node = new FakeNode(0, contract);
    for (const epoch of [2, 5]) {
      await assert.rejects(rotateEncKey({ admin: node.call, contract, address: ADDRESS, party: 0, from: FROM, fee: FEE, epoch }), /stores epoch 3, so it takes epoch 4, not/);
    }
    assert.equal(node.commands.length, 0);
    // the stored epoch: refused once the node's signed key shows the
    // contract does not store it
    await assert.rejects(rotateEncKey({ admin: node.call, contract, address: ADDRESS, party: 0, from: FROM, fee: FEE, epoch: 3 }), /stores epoch 3, so it takes epoch 4, not 3/);
    assert.deepEqual(node.commands.map((c) => c.op), ["sign_enc_key"]);
    assert.equal(contract.sent.length, 0);
  });

  test("a rerun sends nothing to a contract that already stores the node's current key", async () => {
    const contract = new FakeContract();
    const node = new FakeNode(0, contract);
    const first = await rotateEncKey({ admin: node.call, contract, address: ADDRESS, party: 0, from: FROM, fee: FEE, epoch: 1 });
    assert.equal(first.rotated, true);
    // the same configuration again, with and without its expected epoch
    for (const epoch of [1, undefined]) {
      const again = await rotateEncKey({ admin: node.call, contract, address: ADDRESS, party: 0, from: FROM, fee: FEE, epoch });
      assert.deepEqual(again, { namespace: ADDRESS, index: 0, epoch: 1, rotated: false, recorded: true });
    }
    assert.equal(contract.sent.length, 1);
    assert.deepEqual(contract.stored[0], { x: 0x51n, y: 0x52n, epoch: 1 });
    // a new scalar at the node: the next run rotates again
    node.enc = { x: "0x61", y: "0x62" };
    const next = await rotateEncKey({ admin: node.call, contract, address: ADDRESS, party: 0, from: FROM, fee: FEE });
    assert.deepEqual([next.rotated, next.epoch, contract.sent.length], [true, 2, 2]);
  });

  test("a prune that fails after the rotation landed is not fatal", async () => {
    const contract = new FakeContract();
    const node = new FakeNode(0, contract);
    const admin = async (command: object) => {
      if ((command as { op: string }).op === "prune") throw new Error("admin socket admin.sock: closed without a full answer");
      return node.call(command);
    };
    const log = quietLog();
    const done = await rotateEncKey({ admin, contract, address: ADDRESS, party: 0, from: FROM, fee: FEE, log });
    assert.deepEqual([done.rotated, done.recorded], [true, false]);
    assert.ok(log.lines.some((l) => l.includes("prune failed")), log.lines.join("\n"));
  });

  test("a refusal or a node of another party sends nothing", async () => {
    const contract = new FakeContract();
    const node = new FakeNode(2, contract);
    node.refuse = "epoch 1 of contract 0xa11c landed under another key";
    await assert.rejects(rotateEncKey({ admin: node.call, contract, address: ADDRESS, party: 2, from: FROM, fee: FEE }), /refused to sign epoch 1: conflict: epoch 1/);
    node.refuse = undefined;
    await assert.rejects(rotateEncKey({ admin: node.call, contract, address: ADDRESS, party: 0, from: FROM, fee: FEE }), /the node is party 2, not 0/);
    assert.equal(contract.sent.length, 0);
  });

  test("a stored key that is not the signed one after the transaction stops the rotation", async () => {
    const contract = new FakeContract();
    contract.stores = false;
    const node = new FakeNode(0, contract);
    await assert.rejects(rotateEncKey({ admin: node.call, contract, address: ADDRESS, party: 0, from: FROM, fee: FEE }), /stores epoch 0 .* not the signed key at epoch 1/);
    // the node is not asked to record anything
    assert.deepEqual(
      node.commands.map((c) => c.op),
      ["sign_enc_key"],
    );
  });

  test("a node whose Aztec node does not show the rotation yet records it later", async () => {
    const contract = new FakeContract();
    const node = new FakeNode(0, contract);
    node.view = () => 0;
    const log = quietLog();
    const done = await rotateEncKey({ admin: node.call, contract, address: ADDRESS, party: 0, from: FROM, fee: FEE, log });
    assert.equal(done.recorded, false);
    assert.ok(log.lines.some((l) => l.includes("records the scalar once it does")), log.lines.join("\n"));
  });
});

describe("adminSocket", () => {
  test("one JSON line each way over the node's Unix socket", async () => {
    const dir = scratchDir();
    const path = join(dir, "admin.sock");
    const got: unknown[] = [];
    const server = createServer((socket) => {
      socket.setEncoding("utf8");
      let buffer = "";
      socket.on("data", (chunk: string) => {
        buffer += chunk;
        const end = buffer.indexOf("\n");
        if (end < 0) return;
        const command = JSON.parse(buffer.slice(0, end)) as { op: string };
        got.push(command);
        socket.end(command.op === "prune" ? `${JSON.stringify({ ok: true, pruned: 2 })}\n` : "not json\n");
      });
    });
    await new Promise<void>((resolve) => server.listen(path, resolve));
    try {
      const admin = adminSocket(path, 5_000);
      assert.deepEqual(await admin({ op: "prune" }), { ok: true, pruned: 2 });
      await assert.rejects(admin({ op: "other" }), /the answer is not JSON: not json/);
      assert.deepEqual(got, [{ op: "prune" }, { op: "other" }]);
      await assert.rejects(adminSocket(join(dir, "missing.sock"), 5_000)({ op: "prune" }), /missing\.sock/);
    } finally {
      await new Promise((resolve) => server.close(resolve));
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("a node that closes the connection without a full answer line fails the command", async () => {
    const dir = scratchDir();
    const path = join(dir, "admin.sock");
    // the first connection gets half a line, the second nothing
    let n = 0;
    const server = createServer((socket) => {
      socket.once("data", () => (n++ === 0 ? socket.end('{"ok": tr') : socket.end()));
    });
    await new Promise<void>((resolve) => server.listen(path, resolve));
    try {
      const admin = adminSocket(path, 60_000);
      await assert.rejects(admin({ op: "prune" }), /admin\.sock: closed without a full answer/);
      await assert.rejects(admin({ op: "prune" }), /closed without a full answer/);
    } finally {
      await new Promise((resolve) => server.close(resolve));
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
