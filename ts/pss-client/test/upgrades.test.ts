// Circuit upgrades: the stored pins' layout (pss_public_contract upgrades.nr
// UpgradedPins in aztec-nr's DelayedPublicMutable packing), the pins and
// the manifest hash in force at a timestamp, the read through an Aztec node,
// and the circuit pins of a contract manifest.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { describe, test } from "node:test";

import { Fr } from "@aztec-labs/foundation/curves/bn254";

import {
  circuitPinsOf,
  CONSTRUCTOR_MANIFEST_HASH_OFFSET,
  contractManifestHash,
  fieldHex,
  manifestHashAt,
  packageNameHash,
  pendingUpgrade,
  pinsAt,
  readCircuitPins,
  unpackCircuitPins,
  upgradedPinsLength,
  vkHashesOf,
  type CircuitPinsNode,
  type ContractManifest,
} from "../src/internal.ts";

const VECTOR = JSON.parse(readFileSync(new URL("../../../testvectors/contract_manifest.json", import.meta.url), "utf8")) as { manifest: ContractManifest };
const CAPACITY = 2;
const PINS_SLOT = 0x20n;

/** An upgradable copy of the vector's manifest (capacity 2). */
function upgradable(): ContractManifest {
  const m = structuredClone(VECTOR.manifest);
  m.upgrades = "circuits";
  m.storage!.circuit_pins = fieldHex(PINS_SLOT);
  return m;
}

/** The 2N + 1 stored fields: metadata (time of change in the low 32 bits,
 * other delay-change bits above it), then each half [class, manifest hash,
 * packages, vk hashes]. */
function stored(timeOfChange: bigint, before: bigint[], after: bigint[]): bigint[] {
  const meta = timeOfChange + (7n << 32n) + (1n << 64n);
  return [meta, ...before, ...after];
}
const half = (classId: bigint, manifestHash: bigint) => [classId, manifestHash, 0x11n, 0x12n, 0x21n, 0x22n];

describe("the stored pins", () => {
  test("N is 2P + 2 and the halves unpack in their packing order", () => {
    assert.equal(upgradedPinsLength(CAPACITY), 6);
    const s = unpackCircuitPins(stored(1_000n, half(0xc1n, 0xa1n), half(0xc2n, 0xa2n)), CAPACITY);
    assert.equal(s.timeOfChange, 1_000n);
    assert.deepEqual(s.before, { classId: 0xc1n, manifestHash: 0xa1n, packages: [0x11n, 0x12n], vkHashes: [0x21n, 0x22n] });
    assert.equal(s.after.manifestHash, 0xa2n);
    assert.throws(() => unpackCircuitPins([0n], CAPACITY), /13 fields, not 1/);
  });

  test("the after half from the time of change on; a never-written value is the constructor's", () => {
    const s = unpackCircuitPins(stored(1_000n, half(0n, 0n), half(0xc1n, 0xa2n)), CAPACITY);
    assert.equal(pinsAt(s, 999n).manifestHash, 0n);
    assert.equal(manifestHashAt(s, 999n, 0xa1n), 0xa1n);
    assert.equal(manifestHashAt(s, 1_000n, 0xa1n), 0xa2n);
    assert.deepEqual(pendingUpgrade(s, 999n), { manifestHash: 0xa2n, timeOfChange: 1_000n });
    assert.equal(pendingUpgrade(s, 1_000n), undefined);
    const never = unpackCircuitPins(new Array(13).fill(0n), CAPACITY);
    assert.equal(manifestHashAt(never, 5n, 0xa1n), 0xa1n);
    assert.equal(pendingUpgrade(never, 5n), undefined);
  });

  test("readCircuitPins reads the slots from storage.circuit_pins and the constructor's manifest hash at the given block", async () => {
    const m = upgradable();
    const staleSlot = BigInt(m.queue!.stale_blocks_slot);
    const storage = new Map<bigint, bigint>();
    stored(1_000n, half(0n, 0n), half(0xc1n, 0xa2n)).forEach((v, k) => storage.set(PINS_SLOT + BigInt(k), v));
    storage.set(staleSlot + CONSTRUCTOR_MANIFEST_HASH_OFFSET, 0xa1n);
    const reads: number[] = [];
    const node = (timestamp: bigint): CircuitPinsNode => ({
      getBlockNumber: async () => 9,
      getPublicStorageAt: async (block: never, _contract, slot) => {
        reads.push(block as number);
        return new Fr(storage.get(slot.toBigInt()) ?? 0n);
      },
      getBlockData: async () => ({ header: { globalVariables: { timestamp } } }),
    });
    const before = await readCircuitPins(node(999n), "0x7195", m);
    assert.equal(before.block, 9);
    assert.equal(before.manifestHash, fieldHex(0xa1n));
    assert.ok(reads.every((b) => b === 9));
    const after = await readCircuitPins(node(1_500n), "0x7195", m, 4);
    assert.equal(after.block, 4);
    assert.equal(after.manifestHash, fieldHex(0xa2n));
    await assert.rejects(readCircuitPins(node(0n), "0x7195", VECTOR.manifest), /upgrades `fixed`: no upgradable circuit pins/);
  });
});

describe("a contract manifest's circuit pins", () => {
  test("circuitPinsOf: the manifest hash, the listed packages' name hashes and vk hashes, padded to the capacity", async () => {
    const m = upgradable();
    const pins = await circuitPinsOf(m);
    assert.ok(pins.manifest_hash.equals(await contractManifestHash(m)));
    assert.equal(pins.packages.length, CAPACITY);
    assert.ok(pins.packages[0]!.equals(await packageNameHash("amm_init_tip")));
    assert.ok(pins.packages[1]!.equals(await packageNameHash("amm_swap_tip")));
    assert.deepEqual(
      pins.vk_hashes.map((f) => f.toBigInt()),
      [0xa1n, 0xa2n],
    );
  });

  test("vkHashesOf: every package at its circuit's vk hash, the aliases included", () => {
    const m = upgradable();
    const vks = vkHashesOf(m);
    assert.equal(vks.amm_swap_tip, fieldHex(0xa2n));
    for (const p of m.packages) assert.equal(vks[p.name], fieldHex(BigInt(m.circuits[p.circuit]!.vk_hash)));
  });
});
