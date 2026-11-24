// The local vk hash. pss_seed.circuit.json is examples/amm/circuits/pss_seed
// compiled with Noir 1.0.0, the circuit pss_seed.vk.json was written from. With
// BB_BIN set (bb 6.0.0), localVkHash runs bb on it; without, only the hashing
// path is tested.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { describe, test } from "node:test";

import { localVkHash, vkHashFromBbJson } from "../src/internal.ts";
import { fixturePath } from "@aztec-pss/test-support";

const VK_JSON = readFileSync(fixturePath("pss_seed.vk.json"), "utf8");
const CIRCUIT = fixturePath("pss_seed.circuit.json");
const PSS_SEED_VK_HASH = "0x255a24297767ccd4fea94c6bfcc2aec6057adb3433a6fc6d16da2883e2b5a3d6";
const BB_BIN = process.env.BB_BIN;

describe("local vk hash", () => {
  test("vkHashFromBbJson hashes the fields and checks bb's own hash", async () => {
    assert.equal(await vkHashFromBbJson(VK_JSON), PSS_SEED_VK_HASH);
    const { hash: _h, ...noHash } = JSON.parse(VK_JSON);
    assert.equal(await vkHashFromBbJson(noHash), PSS_SEED_VK_HASH);
    await assert.rejects(vkHashFromBbJson({ ...JSON.parse(VK_JSON), hash: "0x1" }), /not the Poseidon2 hash of its fields/);
  });

  test("localVkHash reports a bb that cannot run", async () => {
    await assert.rejects(localVkHash(CIRCUIT, "/nonexistent/bb"), /\/nonexistent\/bb write_vk/);
  });

  test("localVkHash with bb equals the fixture's hash", { skip: BB_BIN === undefined ? "BB_BIN is not set" : false }, async () => {
    assert.equal(await localVkHash(CIRCUIT, BB_BIN), PSS_SEED_VK_HASH);
    await assert.rejects(localVkHash("/nonexistent/circuit.json", BB_BIN), /write_vk/);
  });
});
