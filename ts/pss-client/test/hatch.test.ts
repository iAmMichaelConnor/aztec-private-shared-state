// The escape hatch's client side (src/hatch.ts): the exit tag and the
// filler, poseidon2 of their labelled preimages, against
// testvectors/exit_tag.json; a note's tag from its owner and randomness;
// whether a tag is spent and in which block, as a nullifier of the app;
// the note an exit takes; the transaction that spent a tag, read from the
// block the nullifier tree names by its hash; and the trigger's rule (the
// app has starved for T_LIVE blocks).
//
// The file and the Noir program's Prover.toml (exit_tag_vectors, pss_core's
// functions) are written from `vectorFile()`; this test requires them to
// equal it, so client, file and circuit cannot drift apart. Regenerate them
// with `PSS_WRITE_VECTORS=1 node --conditions=source --test
// test/hatch.test.ts`.

import assert from "node:assert/strict";
import { describe, test } from "node:test";

import { AztecAddress } from "@aztec-labs/aztec.js/addresses";
import type { AztecNode } from "@aztec-labs/aztec.js/node";
import { Fr } from "@aztec-labs/foundation/curves/bn254";
import { siloNullifier } from "@aztec-labs/stdlib/hash";
import type { BlockParameter } from "@aztec-labs/stdlib/block";
import { MerkleTreeId } from "@aztec-labs/stdlib/trees";

import {
  exitFiller,
  exitTag,
  exitTagOf,
  exitTagSpentAt,
  exitTagSpender,
  hatchReady,
  liveExitNote,
  PSS_EXIT_FILLER,
  PSS_EXIT_TAG,
  type ExitNote,
  type NullifierNode,
  type SpenderNode,
} from "../src/hatch.ts";
import { partialCommitment } from "../src/internal.ts";
import { blockHashOf, checkOrWrite, hex, spenderNode, tomlString, txWith } from "@aztec-pss/test-support";

const VECTORS = new URL("../../../testvectors/exit_tag.json", import.meta.url);
const PROVER = new URL("../../../testvectors/noir/exit_tag_vectors/Prover.toml", import.meta.url);

const TWO_POW_120 = 1n << 120n;
const TWO_POW_128 = 1n << 128n;

async function tagCase(partial: bigint, requestId: bigint, entry: bigint) {
  return { partial: hex(partial), request_id: hex(requestId), entry: hex(entry), tag: hex(await exitTag(partial, requestId, entry)) };
}

async function fillerCase(partial: bigint, requestId: bigint, j: number) {
  return { partial: hex(partial), request_id: hex(requestId), j, filler: hex(await exitFiller(partial, requestId, j)) };
}

async function vectorFile() {
  const owner = 0xa11cen;
  const rho = 0x5eedn;
  const requestId = 0x2dn;
  const entry = 7n;
  return {
    description:
      "The exit tag and the filler of pss_core tip/exit.nr: exit_tag(P, request_id, entry) = poseidon2([PSS_EXIT_TAG + 2^128 * entry, P, request_id]) and exit_filler(P, request_id, j) = poseidon2([PSS_EXIT_FILLER + 2^128 * j, P, request_id]), and a note's tag from its owner and randomness (P = partial_commitment(owner, rho)). Written and read by pss-client test/hatch.test.ts, which also writes testvectors/noir/exit_tag_vectors/Prover.toml from it; the Noir program checks it with pss_core's functions. The machine never computes a tag.",
    pss_exit_tag: hex(PSS_EXIT_TAG),
    pss_exit_filler: hex(PSS_EXIT_FILLER),
    tags: [await tagCase(0xa1n, 0x1dn, 1n), await tagCase(0xa1n, 0x1dn, 0xffffn), await tagCase(0xa2n, 0x1en, TWO_POW_120 - 1n)],
    fillers: [await fillerCase(0x9an, 0x1dn, 0), await fillerCase(0x9an, 0x1dn, 1)],
    note: {
      owner: hex(owner),
      rho: hex(rho),
      partial: hex(await partialCommitment(owner, rho)),
      request_id: hex(requestId),
      entry: hex(entry),
      tag: hex(await exitTagOf({ owner, rho, requestId, entry })),
    },
  };
}

const q = tomlString;

function proverToml(file: Awaited<ReturnType<typeof vectorFile>>): string {
  const lines = ["# Written by pss-client test/hatch.test.ts from testvectors/exit_tag.json.", `pss_exit_tag = ${q(file.pss_exit_tag)}`, `pss_exit_filler = ${q(file.pss_exit_filler)}`, ""];
  file.tags.forEach((t, i) => {
    lines.push(`[tag_${i}]`);
    for (const k of ["partial", "request_id", "entry", "tag"] as const) lines.push(`${k} = ${q(t[k])}`);
    lines.push("");
  });
  file.fillers.forEach((f, i) => {
    lines.push(`[filler_${i}]`);
    for (const k of ["partial", "request_id", "j", "filler"] as const) lines.push(`${k} = ${q(f[k])}`);
    lines.push("");
  });
  lines.push("[note]");
  for (const k of ["owner", "rho", "partial", "request_id", "entry", "tag"] as const) lines.push(`${k} = ${q(file.note[k])}`);
  return lines.join("\n") + "\n";
}

const P = 0xa1n;
const REQUEST = 0x1dn;

describe("the exit tag vectors (testvectors/exit_tag.json)", () => {
  test("the file and the Noir program's Prover.toml are what the client computes", async () => {
    const file = await vectorFile();
    const json = JSON.stringify(file, null, 2) + "\n";
    const toml = proverToml(file);
    checkOrWrite(VECTORS, json);
    checkOrWrite(PROVER, toml);
  });
});

describe("the exit tag and the filler", () => {
  test("every input changes a tag, and an entry never takes a filler's place", async () => {
    const tag = (await exitTag(P, REQUEST, 3n)).toBigInt();
    assert.notEqual((await exitTag(P + 1n, REQUEST, 3n)).toBigInt(), tag);
    assert.notEqual((await exitTag(P, REQUEST + 1n, 3n)).toBigInt(), tag);
    assert.notEqual((await exitTag(P, REQUEST, 4n)).toBigInt(), tag);
    const filler = (await exitFiller(P, REQUEST, 0)).toBigInt();
    assert.notEqual((await exitFiller(P + 1n, REQUEST, 0)).toBigInt(), filler);
    assert.notEqual((await exitFiller(P, REQUEST + 1n, 0)).toBigInt(), filler);
    assert.notEqual((await exitFiller(P, REQUEST, 1)).toBigInt(), filler);
    // entry k and the k-th filler of one round differ in their domain
    for (const k of [0, 1, 2]) {
      assert.notEqual((await exitTag(P, REQUEST, BigInt(k))).toBigInt(), (await exitFiller(P, REQUEST, k)).toBigInt());
    }
  });

  test("an entry or a filler's place at or past 2^120 is refused", async () => {
    await exitTag(P, REQUEST, TWO_POW_120 - 1n);
    await assert.rejects(exitTag(P, REQUEST, TWO_POW_120), RangeError);
    await assert.rejects(exitTag(P, REQUEST, TWO_POW_128), RangeError);
    assert.throws(() => exitFiller(P, REQUEST, -1), RangeError);
    assert.throws(() => exitFiller(P, REQUEST, 0.5), RangeError);
  });

  test("a note's tag is exitTag(partialCommitment(owner, rho), requestId, entry)", async () => {
    const note: ExitNote = { owner: 0xa11cen, rho: 0x5eedn, requestId: 0x2dn, entry: 7n };
    const want = await exitTag(await partialCommitment(0xa11cen, 0x5eedn), 0x2dn, 7n);
    assert.ok((await exitTagOf(note)).equals(want));
    assert.ok((await exitTagOf({ ...note, owner: AztecAddress.fromBigIntUnsafe(0xa11cen) })).equals(want));
    assert.ok(!(await exitTagOf({ ...note, rho: 0x5eeen })).equals(want));
  });
});

const APP = 0xc0ffeen;

/** A node whose nullifier tree holds `spent`: each a tag spent by an app
 * at a block, indexed by the tag siloed with the app's address. `trees`
 * keeps each query's tree. */
async function nullifierNode(spent: { app: bigint; tag: Fr; block: number }[]): Promise<NullifierNode & { trees: MerkleTreeId[]; at: BlockParameter[] }> {
  const held = new Map<bigint, number>();
  for (const s of spent) held.set((await siloNullifier(AztecAddress.fromBigIntUnsafe(s.app), s.tag)).toBigInt(), s.block);
  const n = {
    trees: [] as MerkleTreeId[],
    at: [] as BlockParameter[],
    async findLeavesIndexes(block: BlockParameter, treeId: MerkleTreeId, values: Fr[]) {
      n.trees.push(treeId);
      n.at.push(block);
      return values.map((v) => {
        const block = held.get(v.toBigInt());
        return block === undefined ? undefined : { l2BlockNumber: BigInt(block) };
      });
    },
  };
  return n;
}

describe("spent exit tags", () => {
  test("exitTagSpentAt names the block a tag was spent in as the app's nullifier", async () => {
    const tag = await exitTag(P, REQUEST, 3n);
    const other = await exitTag(P, REQUEST, 4n);
    const node = await nullifierNode([{ app: APP, tag, block: 17 }, { app: APP + 1n, tag: other, block: 18 }]);
    assert.equal(await exitTagSpentAt(node, APP, tag), 17);
    assert.equal(await exitTagSpentAt(node, AztecAddress.fromBigIntUnsafe(APP), tag.toBigInt()), 17);
    // unspent, and spent by another app only
    assert.equal(await exitTagSpentAt(node, APP, await exitTag(P, REQUEST, 5n)), undefined);
    assert.equal(await exitTagSpentAt(node, APP, other), undefined);
    assert.equal(await exitTagSpentAt(node, APP + 1n, other), 18);
    assert.ok(node.trees.every((t) => t === MerkleTreeId.NULLIFIER_TREE));
    // read at the proposed tip unless the caller names a deeper block
    assert.ok(node.at.every((b) => b === "proposed"));
    assert.equal(await exitTagSpentAt(node, APP, tag, "checkpointed"), 17);
    assert.equal(node.at.at(-1), "checkpointed");
  });

  test("liveExitNote takes the first note whose tag is unspent", async () => {
    // newest first
    const notes: ExitNote[] = [
      { owner: 0xa11cen, rho: 0x5eed3n, requestId: 0x3dn, entry: 7n },
      { owner: 0xa11cen, rho: 0x5eed2n, requestId: 0x2dn, entry: 7n },
      { owner: 0xa11cen, rho: 0x5eed1n, requestId: 0x1dn, entry: 7n },
    ];
    const spend = async (k: number[]) => nullifierNode(await Promise.all(k.map(async (i) => ({ app: APP, tag: await exitTagOf(notes[i]!), block: 10 + i }))));
    assert.equal(await liveExitNote(await spend([]), APP, notes), notes[0]);
    assert.equal(await liveExitNote(await spend([0]), APP, notes), notes[1]);
    assert.equal(await liveExitNote(await spend([0, 1]), APP, notes), notes[2]);
    assert.equal(await liveExitNote(await spend([0, 1, 2]), APP, notes), undefined);
    assert.equal(await liveExitNote(await spend([]), APP, []), undefined);
  });
});

describe("the transaction that spent a tag", () => {
  test("an aztec.js node is a SpenderNode", () => {
    const asNode = (n: AztecNode): SpenderNode => n;
    void asNode;
  });

  test("is the one of the named block that holds the tag as the app's nullifier", async () => {
    const tag = await exitTag(P, REQUEST, 3n);
    const siloed = await siloNullifier(AztecAddress.fromBigIntUnsafe(APP), tag);
    const spender = txWith(0x5bn, [new Fr(0x1n), siloed]);
    const node = spenderNode([{ number: 40, txs: [txWith(0x5an, [new Fr(0x2n)]), spender] }]);
    assert.deepEqual(await exitTagSpender(node, APP, tag), { block: 40, tx: spender });
    // the block was read by the hash the nullifier tree named
    assert.ok(node.asked.length === 1 && node.asked[0]!.equals(blockHashOf(40)));
    // unspent, and spent by another app only
    assert.equal(await exitTagSpender(node, APP, await exitTag(P, REQUEST, 4n)), undefined);
    assert.equal(await exitTagSpender(node, APP + 1n, tag), undefined);
    assert.equal(node.asked.length, 1);
  });

  test("refuses a block the node does not serve and a block with no such transaction", async () => {
    const tag = await exitTag(P, REQUEST, 3n);
    const siloed = await siloNullifier(AztecAddress.fromBigIntUnsafe(APP), tag);
    // replaced between the lookup and the read: the hash names no block the node serves
    await assert.rejects(exitTagSpender(spenderNode([{ number: 40, txs: [txWith(0x5bn, [siloed])] }], [40]), APP, tag), /does not serve it/);
    // a node whose tree and blocks disagree
    const node = spenderNode([{ number: 40, txs: [txWith(0x5bn, [siloed])] }]);
    node.getBlock = async () => ({ body: { txEffects: [txWith(0x5an, [new Fr(0x2n)])] } });
    await assert.rejects(exitTagSpender(node, APP, tag), /no transaction of block 40/);
  });
});

describe("the trigger", () => {
  const base = { open: false, starvingSince: 100, tLive: 50, block: 149 };
  test("opens once the app has starved for T_LIVE blocks", () => {
    assert.deepEqual(hatchReady(base), { open: false, openable: false, reason: "the app has starved for under T_LIVE blocks", blocksLeft: 1 });
    assert.deepEqual(hatchReady({ ...base, block: 150 }), { open: false, openable: true });
    assert.match(hatchReady({ ...base, starvingSince: 0, block: 500 }).reason!, /not starving/);
    assert.equal(hatchReady({ ...base, open: true }).open, true);
  });
});
