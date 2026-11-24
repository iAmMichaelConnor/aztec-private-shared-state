// Checking a deployed contract against a contract manifest (verify.ts): the
// class, fact and pins comparisons, the pins in force as read through a
// node, and a class upgrade's re-registration of the instance.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { describe, test } from "node:test";

import { Fr } from "@aztec-labs/foundation/curves/bn254";

import {
  CONSTRUCTOR_MANIFEST_HASH_OFFSET,
  SEND_WAIT,
  compareClass,
  compareFacts,
  comparePins,
  fieldHex,
  followContractClass,
  readPinsInForce,
  statedPins,
  upgradeContract,
  type CircuitPinsNode,
  type ContractManifest,
} from "../src/internal.ts";

const VECTOR = JSON.parse(readFileSync(new URL("../../../testvectors/contract_manifest.json", import.meta.url), "utf8")) as { manifest: ContractManifest };
const PINS_SLOT = 0x20n;

function upgradable(): ContractManifest {
  const m = structuredClone(VECTOR.manifest);
  m.upgrades = "contract";
  m.storage!.circuit_pins = fieldHex(PINS_SLOT);
  return m;
}

/** A node whose storage is `storage` at every block, at `timestamp`. */
function nodeOf(storage: Map<bigint, bigint>, timestamp = 1_000n): CircuitPinsNode {
  return {
    getBlockNumber: async () => 7,
    getPublicStorageAt: async (_b: never, _c, slot) => new Fr(storage.get(slot.toBigInt()) ?? 0n),
    getBlockData: async () => ({ header: { globalVariables: { timestamp } } }),
  };
}

/** The constructor's pins of `m` written into the Config's slots. */
async function constructorStorage(m: ContractManifest): Promise<Map<bigint, bigint>> {
  const p = await statedPins(m);
  const base = BigInt(m.queue!.stale_blocks_slot) + CONSTRUCTOR_MANIFEST_HASH_OFFSET;
  const storage = new Map<bigint, bigint>();
  [p.manifestHash, ...p.packages, ...p.vkHashes].forEach((v, k) => storage.set(base + BigInt(k), v));
  return storage;
}

describe("the comparisons", () => {
  test("the class: the manifest's against the artifact's and the instance's", () => {
    assert.ok(compareClass(5n, 5n, 5n).every((l) => l.ok));
    const [art, inst] = compareClass(5n, 6n, undefined);
    assert.equal(art!.ok, false);
    assert.match(art!.detail, /the artifact builds/);
    assert.equal(inst!.ok, false);
    assert.match(inst!.detail, /no contract instance/);
  });

  test("the facts: each derived path against the manifest's value, fields compared as numbers", () => {
    const m = VECTOR.manifest;
    const lines = compareFacts({ upgrades: "fixed", "queue.slot": BigInt(m.queue!.slot), "state_keys.pool": 0x99n }, m);
    assert.deepEqual(
      lines.map((l) => [l.check, l.ok]),
      [
        ["upgrades", true],
        ["queue.slot", true],
        ["state_keys.pool", false],
      ],
    );
    assert.match(lines[2]!.detail, /the artifact gives 0x0+99/);
  });

  test("the pins: hash, packages and vk hashes, each its own line", async () => {
    const stated = await statedPins(VECTOR.manifest);
    assert.ok(comparePins(stated, stated, "constructor").every((l) => l.ok));
    const lines = comparePins(stated, { ...stated, vkHashes: [stated.vkHashes[0]!, 0x77n] }, "upgraded");
    assert.deepEqual(
      lines.map((l) => l.ok),
      [true, true, false],
    );
    assert.match(lines[2]!.detail, /the contract's upgraded pins hold/);
  });
});

describe("the pins in force on chain", () => {
  test("under fixed: the constructor's, from the Config", async () => {
    const m = VECTOR.manifest;
    const chain = await readPinsInForce(nodeOf(await constructorStorage(m)), "0x7195", m);
    assert.equal(chain.source, "constructor");
    assert.deepEqual({ ...chain, source: undefined }, { ...(await statedPins(m)), source: undefined });
  });

  test("upgradable: the constructor's while nothing was scheduled, then the scheduled half in force", async () => {
    const m = upgradable();
    const storage = await constructorStorage(m);
    assert.equal((await readPinsInForce(nodeOf(storage), "0x7195", m)).source, "constructor");
    // scheduled at 900: [class, manifest hash, packages, vk hashes] after the change
    const after = [0xc2n, 0xa9n, 0x11n, 0x12n, 0x21n, 0x22n];
    storage.set(PINS_SLOT, 900n);
    after.forEach((v, k) => storage.set(PINS_SLOT + 7n + BigInt(k), v));
    const chain = await readPinsInForce(nodeOf(storage, 1_000n), "0x7195", m);
    assert.deepEqual(chain, { manifestHash: 0xa9n, packages: [0x11n, 0x12n], vkHashes: [0x21n, 0x22n], source: "upgraded" });
    assert.equal((await readPinsInForce(nodeOf(storage, 899n), "0x7195", m)).source, "constructor");
  });
});

describe("a class upgrade", () => {
  test("upgradeContract sends the manifest's class id and pins; only under upgrades: contract", async () => {
    const m = upgradable();
    let sent: unknown[] = [];
    const contract = {
      methods: {
        upgrade_contract: (classId: Fr, pins: unknown) => {
          sent = [classId, pins];
          return { send: async (o: object) => o };
        },
      },
    };
    assert.deepEqual(await upgradeContract(contract, m, { from: 1 }), { wait: SEND_WAIT, from: 1 });
    assert.ok((sent[0] as Fr).equals(new Fr(BigInt(m.contract!.class_id))));
    await assert.rejects(upgradeContract(contract, VECTOR.manifest, {}), /upgrades `fixed`: no class upgrade/);
  });

  test("followContractClass registers the artifact of the class the instance runs, once", async () => {
    const registered: unknown[] = [];
    const wallet = { registerContract: async (_i: unknown, a: unknown) => void registered.push(a) };
    const instance = (id: bigint) => ({ currentContractClassId: new Fr(id) }) as never;
    const node = (id: bigint) => ({ getContract: async () => instance(id) });
    // no artifact builds the class: refused before anything is registered
    await assert.rejects(followContractClass(wallet, node(0x55n), "0x7195", []), /none of the 0 artifact/);
    // the class registered already: nothing to do
    assert.deepEqual(await followContractClass(wallet, node(0x55n), "0x7195", [], 0x55n), { classId: 0x55n, registered: false });
    assert.equal(registered.length, 0);
    await assert.rejects(followContractClass(wallet, { getContract: async () => undefined }, "0x7195", []), /no contract instance/);
  });
});
