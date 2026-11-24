// The contract manifest: the hash rule against testvectors/contract_manifest.json
// (shared with sidecar-core and scripts/check-manifests.py), the generator on a
// deployment without a contract, and the structural refusals.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { describe, test } from "node:test";

import {
  buildContractManifest,
  canonicalJson,
  checkContractManifest,
  contractManifestHash,
  fieldHex,
  listedPackages,
  packageNameHash,
  packagesHash,
  parseManifest,
  readContract,
  refuseOwnAddress,
  stripCircuit,
  STRIPPED_DEBUG_SYMBOLS,
  type ContractManifest,
  type Descriptor,
} from "../src/internal.ts";

const DIR = new URL("../../../testvectors/", import.meta.url);
const VECTOR = JSON.parse(readFileSync(new URL("contract_manifest.json", DIR), "utf8")) as {
  manifest: ContractManifest;
  jcs: string;
  name_hashes: Record<string, string>;
  manifest_hash: string;
  packages_hash: string;
};
const EXAMPLE = new URL("../../../examples/monty-hall/manifests/", import.meta.url);
const monty = (name: string) => JSON.parse(readFileSync(new URL(`${name}.json`, EXAMPLE), "utf8")) as Record<string, unknown>;

const hex = (f: { toBigInt(): bigint }) => fieldHex(f.toBigInt());
const vector = (): ContractManifest => structuredClone(VECTOR.manifest);

describe("the hashes (testvectors/contract_manifest.json)", () => {
  test("the canonical JSON, the name hashes, the manifest hash and the packages hash", async () => {
    assert.equal(canonicalJson(VECTOR.manifest), VECTOR.jcs);
    for (const [name, h] of Object.entries(VECTOR.name_hashes)) assert.equal(hex(await packageNameHash(name)), h, name);
    assert.equal(hex(await contractManifestHash(VECTOR.manifest)), VECTOR.manifest_hash);
    assert.equal(hex(await packagesHash(VECTOR.manifest)), VECTOR.packages_hash);
  });

  test("the vector passes the structural check; its aliases are not listed", () => {
    checkContractManifest(vector());
    const m = vector();
    assert.deepEqual(
      listedPackages(m).map((p) => p.name),
      m.packages.filter((p) => p.alias_of === undefined).map((p) => p.name),
    );
  });

  test("any change moves the manifest hash; an alias does not move the packages hash", async () => {
    const m = vector();
    m.name = `${m.name}x`;
    assert.notEqual(hex(await contractManifestHash(m)), VECTOR.manifest_hash);
    assert.equal(hex(await packagesHash(m)), VECTOR.packages_hash);
    const reordered = vector();
    reordered.packages.reverse();
    assert.notEqual(hex(await contractManifestHash(reordered)), VECTOR.manifest_hash);
  });
});

describe("the generator", () => {
  const descriptor: Descriptor = {
    descriptor: 1,
    name: "monty-hall",
    packages: [
      { name: "pss_seed", circuit: "pss_seed" },
      { name: "monty_hall_init", circuit: "monty_hall_init" },
    ],
  };
  const input = () => ({
    descriptor,
    manifests: { pss_seed: monty("pss_seed"), monty_hall_init: monty("monty_hall_init") },
    vkHashes: { pss_seed: "0xa1", monty_hall_init: "0xa2" },
  });

  test("a deployment without a contract: packages and circuits only", async () => {
    const m = await buildContractManifest(input());
    assert.deepEqual(Object.keys(m), ["contract_manifest", "name", "node_keys", "upgrades", "circuits", "packages"]);
    assert.equal(m.node_keys, "fixed");
    assert.equal(m.upgrades, "fixed");
    assert.equal(m.circuits.pss_seed!.vk_hash, fieldHex(0xa1n));
    assert.deepEqual(m.packages.map((p) => [p.name, p.circuit, p.state_keys]), [
      ["pss_seed", "pss_seed", undefined],
      ["monty_hall_init", "monty_hall_init", undefined],
    ]);
    assert.deepEqual(m.packages[0]!.manifest, monty("pss_seed"));
  });

  test("refusals: a missing manifest or vk hash, queued sections without a queued package, a queued package without the artifact", async () => {
    await assert.rejects(buildContractManifest({ ...input(), manifests: { pss_seed: monty("pss_seed") } }), /package monty_hall_init: no circuit manifest/);
    await assert.rejects(buildContractManifest({ ...input(), vkHashes: { pss_seed: "0xa1" } }), /no vk hash of circuit monty_hall_init/);
    await assert.rejects(buildContractManifest({ ...input(), descriptor: { ...descriptor, stale_blocks: 50 } }), /belong to a deployment with a queued package/);
    const queued = VECTOR.manifest.packages[0]!.manifest;
    await assert.rejects(
      buildContractManifest({
        descriptor: { descriptor: 1, name: "q", stale_blocks: 50, packages: [{ name: "amm_init_tip", circuit: "amm_init_tip", state_keys: { reads: [], writes: ["pool"] } }] },
        manifests: { amm_init_tip: queued },
        vkHashes: { amm_init_tip: "0x1" },
      }),
      /needs its contract artifact/,
    );
  });
});

describe("the structural check", () => {
  const refused = (change: (m: ContractManifest) => void, needle: RegExp) => {
    const m = vector();
    change(m);
    assert.throws(() => checkContractManifest(m), needle);
  };
  const swap = (m: ContractManifest) => m.packages.find((p) => p.name === "amm_swap_tip")!;
  const alias = (m: ContractManifest) => m.packages.find((p) => p.alias_of !== undefined)!;

  test("circuits and names", () => {
    refused((m) => (swap(m).circuit = "nope"), /circuit `nope` is not an entry of circuits/);
    refused((m) => (m.circuits.unused = { vk_hash: "0x1" }), /circuits\.unused: no package uses it/);
    refused((m) => m.packages.push(structuredClone(m.packages[0]!)), /listed twice/);
    refused((m) => (swap(m).manifest.circuit = "other"), /its manifest names circuit `other`/);
  });

  test("aliases and the capacity", () => {
    refused((m) => (alias(m).alias_of = "nope"), /alias_of `nope` is not a listed package/);
    refused((m) => (alias(m).circuit = "amm_init_tip"), /an alias of `amm_swap_tip` runs its circuit `amm_swap_tip`/);
    refused((m) => (m.contract!.package_capacity = 1), /2 listed packages, the contract has room for 1/);
  });

  test("the sections follow the packages", () => {
    refused((m) => delete m.queue, /queue: missing/);
    refused((m) => delete m.contract!.package_capacity, /package_capacity: missing/);
    refused((m) => (m.storage!.shared_onchain = "0x5"), /storage\.shared_onchain: present/);
    refused((m) => (m.queue!.stale_blocks = 0), /queue\.stale_blocks: 0/);
    refused((m) => (m.queue!.stale_blocks = 2 ** 32), /queue\.stale_blocks: 4294967296/);
  });

  test("storage.circuit_pins exactly under an upgradable value", () => {
    refused((m) => (m.storage!.circuit_pins = "0x20"), /storage\.circuit_pins: present under upgrades `fixed`/);
    refused((m) => (m.upgrades = "circuits"), /storage\.circuit_pins: missing under upgrades `circuits`/);
    refused((m) => (m.upgrades = "contract"), /storage\.circuit_pins: missing under upgrades `contract`/);
    for (const upgrades of ["circuits", "contract"] as const) {
      const m = vector();
      m.upgrades = upgrades;
      m.storage!.circuit_pins = "0x20";
      checkContractManifest(m);
    }
  });

  test("state keys and the init round", () => {
    refused((m) => (swap(m).state_keys = { reads: [], writes: ["pool"] }), /state_keys\.reads names 0 keys, its manifest takes 1/);
    refused((m) => (m.state_keys!.other = "0x9"), /state_keys\.other: no package names it/);
    refused((m) => delete swap(m).state_keys, /state_keys missing for a queued package/);
    refused((m) => (m.init!.package = "amm_swap_tip"), /must read no key and write at least one/);
    refused((m) => (m.init!.package = alias(m).name), /is not a listed package/);
    refused((m) => (m.plain_reads = { price: "0x1" }), /plain_reads\.price: no package's pinned read fills it/);
  });
});

describe("pinned reads of the contract itself", () => {
  test("$self resolves to the namespace and the address is refused written out", () => {
    const m = vector();
    const manifest = swap(m).manifest;
    manifest.public_reads = [{ contract: "$self", function: "clock", args: [], param: "clock" }];
    const read = parseManifest(manifest).publicReads[0]!;
    assert.equal(readContract(read, "0x1234"), fieldHex(0x1234n));
    refuseOwnAddress(m, "0x1234");
    manifest.public_reads = [{ contract: "0x1234", function: "clock", args: [], param: "clock" }];
    assert.throws(() => refuseOwnAddress(m, "0x1234"), /names the contract's own address .*; write `\$self`/);
    assert.throws(() => parseManifest({ ...manifest, public_reads: [{ contract: "self", function: "f", args: [], param: "clock" }] }), /public_reads\[0\]\.contract/);
  });
  function swap(m: ContractManifest) {
    return m.packages.find((p) => p.name === "amm_swap_tip")!;
  }
});

describe("the stripped circuit", () => {
  test("stripCircuit keeps noir_version, hash, abi and bytecode, with the fixed debug_symbols and an empty file_map", () => {
    const full = { noir_version: "1.0.0", hash: "123", abi: { parameters: [] }, bytecode: "H4s", debug_symbols: "long", file_map: { 1: { path: "/build/src/main.nr", source: "fn main() {}" } }, names: ["main"] };
    const stripped = stripCircuit(full);
    assert.deepEqual(stripped, { noir_version: "1.0.0", hash: "123", abi: { parameters: [] }, bytecode: "H4s", debug_symbols: STRIPPED_DEBUG_SYMBOLS, file_map: {} });
    assert.deepEqual(stripCircuit(stripped), stripped);
    assert.equal(STRIPPED_DEBUG_SYMBOLS, "q1ZKSU0qTY/PzEvLL1ayio6tBQA=");
    const { hash: _h, ...noHash } = full;
    assert.throws(() => stripCircuit(noHash), /member `hash` is missing/);
    assert.throws(() => stripCircuit([]), /not a JSON object/);
  });
});
