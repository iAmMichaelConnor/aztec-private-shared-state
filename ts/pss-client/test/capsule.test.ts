// pss_seed.vk.json was written by bb 6.0.0 (`write_vk --scheme ultra_honk
// --oracle_hash poseidon2 --output_format json`) from
// examples/amm/circuits/pss_seed compiled with Noir 1.0.0. Its `hash` field is
// bb's own vk hash, so it checks vkHashFromFields independently of this
// package. sidecar-core checks the same value (tests/vectors.rs).

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { describe, test } from "node:test";

import { AztecAddress } from "@aztec-labs/aztec.js/addresses";
import { Fr } from "@aztec-labs/aztec.js/fields";

import {
  CAPSULE_SLOT_PROOF,
  PROOF_FIELDS,
  VK_FIELDS,
  proofToFields,
  stageCapsule,
  vkFieldsFromBbJson,
  vkHashFromFields,
} from "../src/internal.ts";
import { fixturePath } from "@aztec-pss/test-support";

const VK_JSON = readFileSync(fixturePath("pss_seed.vk.json"), "utf8");
const PSS_SEED_VK_HASH = "0x255a24297767ccd4fea94c6bfcc2aec6057adb3433a6fc6d16da2883e2b5a3d6";

function proofHex(n = PROOF_FIELDS): string {
  let s = "0x";
  for (let i = 0; i < n; i++) s += (i + 1).toString(16).padStart(64, "0");
  return s;
}

describe("capsule", () => {
  test("vk hash of a bb vk.json equals bb's own hash", async () => {
    const fields = vkFieldsFromBbJson(VK_JSON);
    assert.equal(fields.length, VK_FIELDS);
    const h = await vkHashFromFields(fields);
    assert.equal(h.toString(), JSON.parse(VK_JSON).hash);
    assert.equal(h.toString(), PSS_SEED_VK_HASH);
    assert.throws(() => vkFieldsFromBbJson({ vk: ["0x1"] }), /1 fields, expected 115/);
    assert.throws(() => vkFieldsFromBbJson("{}"), /no `vk` array/);
  });

  test("proofToFields splits 458 big-endian 32-byte fields", () => {
    const fields = proofToFields(proofHex());
    assert.equal(fields.length, PROOF_FIELDS);
    assert.equal(fields[0]!.toBigInt(), 1n);
    assert.equal(fields[457]!.toBigInt(), 458n);
    assert.throws(() => proofToFields(proofHex(457)), /14624 bytes, expected 458 fields/);
    assert.throws(() => proofToFields("0x" + "ff".repeat(32 * PROOF_FIELDS)), /modulus/);
    assert.throws(() => proofToFields("abcd"), /does not start with 0x/);
  });

  test("stageCapsule builds the proof capsule pss_contract reads", () => {
    const contract = AztecAddress.fromBigIntUnsafe(0xc0ffeen);
    const scope = "0x" + "07".repeat(32).slice(0, 63) + "1";
    const vk = vkFieldsFromBbJson(VK_JSON);
    const cap = stageCapsule(contract, scope, vk, proofHex());
    assert.ok(cap.contractAddress.equals(contract));
    assert.ok(cap.storageSlot.equals(new Fr(CAPSULE_SLOT_PROOF)));
    assert.equal(CAPSULE_SLOT_PROOF, 0x10);
    assert.equal(cap.data.length, VK_FIELDS + PROOF_FIELDS);
    assert.ok(cap.data[0]!.equals(vk[0]!));
    assert.equal(cap.data[VK_FIELDS]!.toBigInt(), 1n);
    assert.equal(cap.scope!.toString(), scope);
    // the proof may also come as fields
    const again = stageCapsule(contract, scope, vk, proofToFields(proofHex()));
    assert.deepEqual(again.data.map(String), cap.data.map(String));
    assert.throws(() => stageCapsule(contract, scope, vk.slice(1), proofHex()), /vk: 114 fields/);
    assert.throws(() => stageCapsule(contract, scope, vk, proofToFields(proofHex()).slice(1)), /proof: 457 fields/);
  });
});
