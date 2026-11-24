// The hashes of a tree-valued node-held key (docs/ARCHITECTURE.md section 6,
// "Tree-valued keys"), as machine/sidecar-core src/tree/ and pss_core's
// tip::tree compute them:
//
//   leaf_hash(i, leaf) = poseidon2([PSS_TIP_LEAF, namespace, key, i, leaf...])   (0: an empty leaf)
//   node(l, r)         = poseidon2([PSS_TIP_NODE, l, r])
//   commitment         = poseidon2([PSS_TIP_TREE, namespace, key, root])
//   Z_0 = 0, Z_{l+1} = node(Z_l, Z_l): the empty subtree of height l; an empty tree's root is Z_D
//
// with poseidon2 the width-4 sponge of ARCHITECTURE section 1 (aztec.js
// poseidon2Hash) and the labels the bytes `pss.tip.leaf`, `pss.tip.node` and
// `pss.tip.tree` read big-endian. Leaf and internal hashes are public data
// (every leaf carries a fresh blinding), so a tree's paths and commitment
// check from hashes alone. A scan round's window (windowAt, windowRoot) is
// bound to the root through its leaves' hashes and its subtree root's
// siblings alone. This is the TypeScript check of testvectors/tip_tree.json
// (pss-client's test/tree.test.ts); no client calls it.

import { poseidon2Hash } from "@aztec-labs/foundation/crypto/poseidon";
import { Fr } from "@aztec-labs/foundation/curves/bn254";

import { asciiLabel, fieldBigInt, fieldFr, type FieldLike } from "@aztec-pss/pss-client/internal";

/** The leaf-hash label, ASCII `pss.tip.leaf` as a big-endian integer. */
export const PSS_TIP_LEAF = asciiLabel("pss.tip.leaf");
/** The internal-node label, ASCII `pss.tip.node`. */
export const PSS_TIP_NODE = asciiLabel("pss.tip.node");
/** The tree-commitment label, ASCII `pss.tip.tree`. */
export const PSS_TIP_TREE = asciiLabel("pss.tip.tree");

/** The hash of leaf `index` of the tree of `key` under `namespace`. An empty
 * leaf's hash is 0 by definition, never this function's output. */
export async function leafHash(namespace: FieldLike, key: FieldLike, index: FieldLike, leaf: readonly FieldLike[]): Promise<Fr> {
  return poseidon2Hash([
    new Fr(PSS_TIP_LEAF),
    fieldFr(namespace, "namespace"),
    fieldFr(key, "key"),
    fieldFr(index, "index"),
    ...leaf.map((x, i) => fieldFr(x, `leaf[${i}]`)),
  ]);
}

/** The hash of an internal node over its two children. */
export async function node(left: FieldLike, right: FieldLike): Promise<Fr> {
  return poseidon2Hash([new Fr(PSS_TIP_NODE), fieldFr(left, "left"), fieldFr(right, "right")]);
}

/** The commitment of a tree under its root: what the key's slot holds. */
export async function treeCommitment(namespace: FieldLike, key: FieldLike, root: FieldLike): Promise<Fr> {
  return poseidon2Hash([new Fr(PSS_TIP_TREE), fieldFr(namespace, "namespace"), fieldFr(key, "key"), fieldFr(root, "root")]);
}

/** `[Z_0, ..., Z_depth]`, the hashes of the empty subtrees of each height. */
export async function zeros(depth: number): Promise<Fr[]> {
  const out = [Fr.ZERO];
  for (let z = Fr.ZERO, l = 0; l < depth; l++) out.push((z = await node(z, z)));
  return out;
}

/** The root a leaf hash gives at leaf `index` under `siblings` (bottom up);
 * the tree's depth is the number of siblings. Refuses an index the depth
 * cannot hold. */
export async function rootOf(leafHash: FieldLike, siblings: readonly FieldLike[], index: FieldLike): Promise<Fr> {
  const i = fieldBigInt(index, "index");
  if (i >> BigInt(siblings.length) !== 0n) throw new RangeError(`index: not below 2^${siblings.length}`);
  let at = fieldFr(leafHash, "leafHash");
  for (const [l, s] of siblings.entries()) {
    const sibling = fieldFr(s, `siblings[${l}]`);
    at = (i >> BigInt(l)) & 1n ? await node(sibling, at) : await node(at, sibling);
  }
  return at;
}

/** The first leaf of the window of `width` leaves (a power of two) that a
 * window round reads from the request's `start` in a tree of `depth`
 * (docs/ARCHITECTURE.md section 6, "A read-only window on a tree key"): `start` when it is below 2^depth and a multiple of `width`, else
 * 0, which the round flags (sidecar-core `tree::window`, pss_core
 * `Tree::window`). */
export function windowAt(start: FieldLike, width: number, depth: number): bigint {
  if (!Number.isSafeInteger(width) || width < 1 || (width & (width - 1)) !== 0) throw new RangeError(`width: ${width} is not a power of two`);
  const s = fieldBigInt(start, "start");
  return s < 1n << BigInt(depth) && s % BigInt(width) === 0n ? s : 0n;
}

/** The root a window's leaf hashes give: their subtree root (the window's
 * old hashes, in leaf order, a power of two of them) taken up the window
 * root's `siblings` (bottom up, depth - log2 width of them) from the
 * window's first leaf `at`, a multiple of the width. */
export async function windowRoot(oldHashes: readonly FieldLike[], siblings: readonly FieldLike[], at: FieldLike): Promise<Fr> {
  const width = oldHashes.length;
  if (width < 1 || (width & (width - 1)) !== 0) throw new RangeError(`oldHashes: ${width} hashes are not a power of two`);
  const first = fieldBigInt(at, "at");
  const height = BigInt(Math.log2(width));
  if (first % BigInt(width) !== 0n) throw new RangeError(`at: ${first} is not a multiple of the width ${width}`);
  let level = oldHashes.map((h, j) => fieldFr(h, `oldHashes[${j}]`));
  while (level.length > 1) {
    const up: Fr[] = [];
    for (let p = 0; p < level.length; p += 2) up.push(await node(level[p]!, level[p + 1]!));
    level = up;
  }
  return rootOf(level[0]!, siblings, first >> height);
}
