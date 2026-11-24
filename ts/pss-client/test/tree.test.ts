// The hashes of a tree-valued node-held key (test-support tree.ts) against
// testvectors/tip_tree.json, which sidecar-core's src/tree/vectors.rs writes and
// testvectors/noir/tip_tree_vectors checks with pss_core's tip::tree: every
// leaf, node, commitment and empty-subtree case, and for each K = 3 update
// that every slot's old path gives the old root and that each written slot's
// new hash is its new leaf's hash (an unwritten slot keeps its old hash);
// and for each window a scan round reads, its first leaf from the request's
// start, its leaves' old hashes, and that its subtree root goes up its
// siblings to the old root the header slot's path gives.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { describe, test } from "node:test";

import { fieldHex } from "../src/field.ts";
import { PSS_TIP_LEAF, PSS_TIP_NODE, PSS_TIP_TREE, hex, leafHash, node, rootOf, treeCommitment, windowAt, windowRoot, zeros } from "@aztec-pss/test-support";
import { asciiLabel } from "../src/internal.ts";

interface LeafCase {
  namespace: string;
  key: string;
  index: string;
  leaf: string[];
  hash: string;
}
interface UpdateCase {
  name: string;
  namespace: string;
  key: string;
  leaves: string[][];
  old_hashes: string[];
  siblings: string[][];
  indices: string[];
  n_used: string;
  ok: boolean;
  writes: boolean[];
  new_leaves: string[][];
  old_root: string;
  old_c: string;
  new_hashes: string[];
  stored: string[][];
  new_root: string;
  new_c: string;
}
interface WindowCase {
  name: string;
  namespace: string;
  key: string;
  width: number;
  start: string;
  effective_start: string;
  aligned: boolean;
  slot_leaf: string[];
  slot_hash: string;
  slot_siblings: string[];
  leaves: string[][];
  old_hashes: string[];
  siblings: string[];
  old_root: string;
}

const V = JSON.parse(readFileSync(new URL("../../../testvectors/tip_tree.json", import.meta.url), "utf8")) as {
  separators: { leaf: string; node: string; tree: string };
  depth: number;
  zeros: string[];
  leaves2: LeafCase[];
  leaves4: LeafCase[];
  nodes: { left: string; right: string; hash: string }[];
  commitments: { namespace: string; key: string; root: string; commitment: string }[];
  updates: UpdateCase[];
  windows: WindowCase[];
};


describe("tree-valued key hashes (testvectors/tip_tree.json)", () => {
  test("the labels are the dotted ASCII bytes", () => {
    assert.equal(PSS_TIP_LEAF, asciiLabel("pss.tip.leaf"));
    assert.equal(PSS_TIP_NODE, asciiLabel("pss.tip.node"));
    assert.equal(PSS_TIP_TREE, asciiLabel("pss.tip.tree"));
    assert.equal(fieldHex(PSS_TIP_LEAF), V.separators.leaf);
    assert.equal(fieldHex(PSS_TIP_NODE), V.separators.node);
    assert.equal(fieldHex(PSS_TIP_TREE), V.separators.tree);
  });

  test("zeros", async () => {
    assert.deepEqual((await zeros(V.depth)).map(hex), V.zeros);
  });

  for (const [set, cases] of [["leaves2", V.leaves2], ["leaves4", V.leaves4]] as const) {
    for (const [k, c] of cases.entries()) {
      test(`${set}[${k}]: leaf ${BigInt(c.index)}`, async () => {
        assert.equal(hex(await leafHash(c.namespace, c.key, c.index, c.leaf)), c.hash);
      });
    }
  }

  for (const [k, c] of V.nodes.entries()) {
    test(`nodes[${k}]`, async () => {
      assert.equal(hex(await node(c.left, c.right)), c.hash);
    });
  }

  for (const [k, c] of V.commitments.entries()) {
    test(`commitments[${k}]`, async () => {
      assert.equal(hex(await treeCommitment(c.namespace, c.key, c.root)), c.commitment);
    });
  }

  for (const u of V.updates) {
    test(`update: ${u.name}`, async () => {
      for (const [k, siblings] of u.siblings.entries()) {
        assert.equal(hex(await rootOf(u.old_hashes[k]!, siblings, u.indices[k]!)), u.old_root, `slot ${k}'s old path`);
      }
      assert.equal(hex(await treeCommitment(u.namespace, u.key, u.old_root)), u.old_c);
      assert.equal(hex(await treeCommitment(u.namespace, u.key, u.new_root)), u.new_c);
      for (const k of u.indices.keys()) {
        const written = u.ok && u.writes[k] && k < Number(BigInt(u.n_used));
        const expected = written ? hex(await leafHash(u.namespace, u.key, u.indices[k]!, u.new_leaves[k]!)) : u.old_hashes[k];
        assert.equal(u.new_hashes[k], expected, `slot ${k}'s new hash`);
      }
      if (!u.ok) assert.equal(u.new_root, u.old_root);
    });
  }

  for (const w of V.windows) {
    test(`window: ${w.name}`, async () => {
      const at = windowAt(w.start, w.width, V.depth);
      assert.equal(fieldHex(at), w.effective_start);
      assert.equal(w.aligned, at === BigInt(w.start));
      assert.equal(hex(await leafHash(w.namespace, w.key, 0, w.slot_leaf)), w.slot_hash);
      assert.equal(hex(await rootOf(w.slot_hash, w.slot_siblings, 0)), w.old_root, "the header's path");
      assert.equal(w.old_hashes.length, w.width);
      for (const [j, leaf] of w.leaves.entries()) {
        const empty = leaf.every((x) => BigInt(x) === 0n);
        assert.equal(w.old_hashes[j], empty ? fieldHex(0n) : hex(await leafHash(w.namespace, w.key, at + BigInt(j), leaf)), `window leaf ${j}`);
      }
      assert.equal(w.siblings.length, V.depth - Math.log2(w.width));
      assert.equal(hex(await windowRoot(w.old_hashes, w.siblings, at)), w.old_root, "the window's root");
    });
  }

  test("windowAt and windowRoot refuse a width that is not a power of two or a misaligned start", async () => {
    assert.throws(() => windowAt(0, 3, 16), RangeError);
    await assert.rejects(windowRoot([0, 0, 0], [], 0), RangeError);
    await assert.rejects(windowRoot([0, 0], [0], 1), RangeError);
  });

  test("rootOf refuses an index the depth cannot hold", async () => {
    await assert.rejects(rootOf(0, [0, 0], 4), RangeError);
  });
});
