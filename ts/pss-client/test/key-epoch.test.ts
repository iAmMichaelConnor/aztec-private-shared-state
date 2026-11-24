// The key epoch a client reads from an app contract (key-epoch.ts): the
// layout of pss_public_contract `NodeKeys` at its own slot, the key sets
// signatures are accepted under inside and after the grace window, and the
// keys a client acts under.

import assert from "node:assert/strict";
import { test } from "node:test";

import { Fr } from "@aztec-labs/foundation/curves/bn254";

import { NODE_KEYS_LEN, NODE_KEYS_SLOT, assertKeyRotation, currentKeys, readKeyEpoch, signatureKeySets, unpackKeyEpoch } from "../src/key-epoch.ts";
import type { NodeKeys, Triple } from "../src/wire.ts";
import { hex } from "@aztec-pss/test-support";

const point = (k: bigint) => ({ x: hex(k), y: hex(k + 1n) });
const PINNED = [0n, 1n, 2n].map((i) => ({ sig: point(100n + 2n * i), enc: point(200n + 2n * i) })) as Triple<NodeKeys>;

/** The stored fields of an epoch: rotated_at 40, grace 10, sig keys 3.., enc keys 9.., previous 15... */
function stored(epoch: bigint): bigint[] {
  const f = Array.from({ length: NODE_KEYS_LEN }, (_, k) => BigInt(k));
  f[0] = epoch;
  f[1] = 40n;
  f[2] = 10n;
  return f;
}

test("the slot is ASCII pss.node_keys, and the 21 fields unpack in the contract's order", () => {
  assert.equal(NODE_KEYS_SLOT, BigInt(`0x${Buffer.from("pss.node_keys").toString("hex")}`));
  const k = unpackKeyEpoch(stored(1n));
  assert.equal(k.epoch, 1);
  assert.deepEqual(k.keys[0], { sig: point(3n), enc: point(9n) });
  assert.deepEqual(k.keys[2], { sig: point(7n), enc: point(13n) });
  assert.deepEqual(k.previous[1], point(17n));
  assert.equal(k.rotatedAt, 40);
  assert.equal(k.grace, 10);
  assert.throws(() => unpackKeyEpoch(stored(1n).slice(1)));
});

test("epoch 0 is the pinned keys; after a rotation the current set, and the previous one inside its window", () => {
  const zero = unpackKeyEpoch(new Array(NODE_KEYS_LEN).fill(0n));
  assert.deepEqual(signatureKeySets(zero, PINNED, 1000), [PINNED.map((k) => k.sig)]);
  assert.deepEqual(currentKeys(zero, PINNED), PINNED);
  assert.deepEqual(currentKeys(undefined, PINNED), PINNED);
  const one = unpackKeyEpoch(stored(1n));
  assert.deepEqual(currentKeys(one, PINNED), one.keys);
  assert.deepEqual(signatureKeySets(one, PINNED, 50), [one.keys.map((k) => k.sig), one.previous]);
  assert.deepEqual(signatureKeySets(one, PINNED, 51), [one.keys.map((k) => k.sig)]);
});

test("readKeyEpoch reads the 21 slots at one block", async () => {
  const fields = stored(2n);
  const seen: [number, bigint][] = [];
  const node = {
    getBlockNumber: async () => 77,
    getPublicStorageAt: async (block: never, _contract: unknown, slot: Fr) => {
      seen.push([block as unknown as number, slot.toBigInt()]);
      return new Fr(fields[Number(slot.toBigInt() - NODE_KEYS_SLOT)]!);
    },
  };
  const { block, keyEpoch } = await readKeyEpoch(node, hex(0x2an));
  assert.equal(block, 77);
  assert.equal(keyEpoch.epoch, 2);
  assert.equal(seen.length, NODE_KEYS_LEN);
  assert.ok(seen.every(([b]) => b === 77));
});

test("a manifest saying node_keys fixed is refused by name before a replacement", () => {
  assertKeyRotation({ node_keys: "rotating" }, "amm");
  assert.throws(() => assertKeyRotation({ node_keys: "fixed" }, "credits"), {
    name: "ProtocolError",
    message: "credits's contract manifest says node_keys fixed (its node-keys brick is FixedKeys), so no rotation can land in its contract: its app is redeployed instead",
  });
});
