// Checking a deployed tip contract against a contract manifest (pss-manifest
// verify): the nodes never rerun the generator, but anyone holding the
// contract's artifact can, and a manifest is a statement about a named piece
// of code, so a wrong one is checkable and attributable.
//
// Three groups of checks, each one line:
//
// - the class: the instance's current class on chain, the class the
//   artifact builds and the manifest's `contract.class_id` are one;
// - the facts: every fact the generator derives from the artifact (the
//   package capacity, `node_keys`, `upgrades`, the queue's and the stale
//   period's slots, `storage.*`, each state key's slot), against the
//   manifest; with the deployment's descriptor the whole manifest is
//   generated again and its hash compared;
// - the pins: the manifest's hash, its listed packages' name hashes and vk
//   hashes against the circuit pins the contract holds in force (under
//   `fixed` the constructor's, in the Config; under `circuits` or `contract`
//   the scheduled pins in force, the constructor's while none was ever
//   scheduled).
//
// The comparisons are pure functions over what was read; the reads go
// through an Aztec node.

import type { AztecAddress } from "@aztec-labs/aztec.js/addresses";
import { Fr } from "@aztec-labs/foundation/curves/bn254";
import type { ContractArtifact } from "@aztec-labs/stdlib/abi";

import { checkedBricks, RESERVED_NAMES } from "./bricks.ts";
import {
  CIRCUIT_UPGRADES_FIELD,
  contractManifestHash,
  packageCapacity,
  staleBlocksSlot,
  storageSlot,
  type ContractManifest,
} from "./contract-manifest.ts";
import { circuitPinsOf } from "./deployment.ts";
import { fieldAddress, fieldBigInt, fieldHex, type FieldLike } from "./field.ts";
import { CONSTRUCTOR_MANIFEST_HASH_OFFSET, classIdOf, pinsAt, readCircuitPins, type CircuitPinsNode, type ClassFollowNode } from "./upgrades.ts";

/** One check of a verification: what was compared, whether it held, and
 * the values. */
export interface VerifyLine {
  check: string;
  ok: boolean;
  detail: string;
}

const show = (v: unknown): string =>
  typeof v === "bigint" ? fieldHex(v) : Array.isArray(v) ? `[${v.map(show).join(", ")}]` : JSON.stringify(v);

function line(check: string, stated: unknown, found: unknown, source: string): VerifyLine {
  const ok = show(stated) === show(found);
  return { check, ok, detail: ok ? show(stated) : `the manifest says ${show(stated)}, ${source} ${show(found)}` };
}

/** The class checks: the manifest's class id against the class the artifact
 * builds and the instance's current class (undefined: no instance at the
 * address). */
export function compareClass(stated: bigint | undefined, artifactClass: bigint, chainClass: bigint | undefined): VerifyLine[] {
  return [
    line("contract.class_id: the artifact", stated, artifactClass, "the artifact builds"),
    chainClass === undefined
      ? { check: "contract.class_id: the instance", ok: false, detail: "no contract instance is published at the address" }
      : line("contract.class_id: the instance", stated, chainClass, "the instance runs"),
  ];
}

/** The facts the generator derives from the artifact alone, by their path
 * in the manifest, for the manifest `m`'s sections (its state key names, a
 * shared on-chain slot only where `m` has one). Refuses an artifact whose
 * functions disagree with the bricks its state view reports (`checkedBricks`). */
export function artifactFacts(artifact: ContractArtifact, m: ContractManifest): Record<string, unknown> {
  const bricks = checkedBricks(artifact, { sharedOnchain: m.storage?.shared_onchain !== undefined });
  const facts: Record<string, unknown> = { node_keys: bricks.node_keys, upgrades: bricks.upgrades };
  if (m.queue === undefined) return facts;
  facts["contract.package_capacity"] = packageCapacity(artifact);
  facts["queue.slot"] = storageSlot(artifact, RESERVED_NAMES.queue.name);
  facts["queue.stale_blocks_slot"] = staleBlocksSlot(artifact);
  facts["storage.configured"] = storageSlot(artifact, RESERVED_NAMES.configured.name);
  if (m.storage?.shared_onchain !== undefined) facts["storage.shared_onchain"] = storageSlot(artifact, RESERVED_NAMES.sharedOnchain.name);
  if (bricks.upgrades !== "fixed") facts["storage.circuit_pins"] = storageSlot(artifact, CIRCUIT_UPGRADES_FIELD);
  for (const name of Object.keys(m.state_keys ?? {})) facts[`state_keys.${name}`] = storageSlot(artifact, name);
  return facts;
}

/** The value at a dotted path of the manifest (a field as a bigint). */
function at(m: ContractManifest, path: string): unknown {
  let v: unknown = m;
  for (const k of path.split(".")) v = v === undefined || v === null ? undefined : (v as Record<string, unknown>)[k];
  return typeof v === "string" && v.startsWith("0x") ? fieldBigInt(v, path) : v;
}

/** The fact checks: each derived fact against the manifest's. */
export function compareFacts(derived: Record<string, unknown>, m: ContractManifest): VerifyLine[] {
  return Object.entries(derived).map(([path, value]) => line(path, at(m, path), value, "the artifact gives"));
}

/** Circuit pins as numbers: the manifest's hash, the package name hashes
 * and the vk hashes, each list padded to the capacity. */
export interface PinsValues {
  manifestHash: bigint;
  packages: bigint[];
  vkHashes: bigint[];
}

/** The pins contract manifest `m` stands for (circuitPinsOf). */
export async function statedPins(m: ContractManifest): Promise<PinsValues> {
  const p = await circuitPinsOf(m);
  return { manifestHash: p.manifest_hash.toBigInt(), packages: p.packages.map((f) => f.toBigInt()), vkHashes: p.vk_hashes.map((f) => f.toBigInt()) };
}

/** The pins checks: the manifest's against the pins in force on chain. */
export function comparePins(stated: PinsValues, chain: PinsValues, source: string): VerifyLine[] {
  const by = `the contract's ${source} pins hold`;
  return [
    line("pins: manifest hash", stated.manifestHash, chain.manifestHash, by),
    line("pins: packages", stated.packages, chain.packages, by),
    line("pins: vk hashes", stated.vkHashes, chain.vkHashes, by),
  ];
}

/** The circuit pins `contract` holds in force on the node's latest block,
 * under the slots of its manifest `m`, and where they come from: the
 * constructor's (the Config's `tip.circuits`, after the stale period and the
 * three sig keys) under `fixed` or while no upgrade was ever scheduled, else
 * the scheduled pins in force. */
export async function readPinsInForce(node: CircuitPinsNode, contract: FieldLike | AztecAddress, m: ContractManifest): Promise<PinsValues & { source: "constructor" | "upgraded" }> {
  const capacity = m.contract?.package_capacity;
  if (capacity === undefined || m.queue === undefined) throw new RangeError(`${m.name}: not a tip contract manifest (no queue or no package capacity)`);
  const address = fieldAddress(contract, "contract");
  const block = Number(await node.getBlockNumber());
  if (m.upgrades !== "fixed") {
    const read = await readCircuitPins(node, address, m, block);
    const pins = pinsAt(read.stored, read.timestamp);
    if (pins.manifestHash !== 0n) return { manifestHash: pins.manifestHash, packages: pins.packages, vkHashes: pins.vkHashes, source: "upgraded" };
  }
  const base = fieldBigInt(m.queue.stale_blocks_slot, "queue.stale_blocks_slot") + CONSTRUCTOR_MANIFEST_HASH_OFFSET;
  const fields = await Promise.all(
    Array.from({ length: 2 * capacity + 1 }, (_, k) => node.getPublicStorageAt(block as never, address, new Fr(base + BigInt(k))).then((f) => f.toBigInt())),
  );
  return { manifestHash: fields[0]!, packages: fields.slice(1, 1 + capacity), vkHashes: fields.slice(1 + capacity), source: "constructor" };
}

/** Every check of `m` against the contract at `contract` built from
 * `artifact`, read through `node`; with `regenerated` (the manifest the
 * generator writes from the deployment's descriptor) also its hash. */
export async function verifyDeployment(
  node: CircuitPinsNode & ClassFollowNode,
  contract: FieldLike | AztecAddress,
  artifact: ContractArtifact,
  m: ContractManifest,
  regenerated?: ContractManifest,
): Promise<VerifyLine[]> {
  const address = fieldAddress(contract, "contract");
  const instance = await node.getContract(address);
  const stated = m.contract?.class_id === undefined ? undefined : fieldBigInt(m.contract.class_id, "contract.class_id");
  const lines = compareClass(stated, await classIdOf(artifact), instance?.currentContractClassId.toBigInt());
  lines.push(...compareFacts(artifactFacts(artifact, m), m));
  if (regenerated !== undefined) {
    lines.push(line("the manifest generated again", (await contractManifestHash(m)).toBigInt(), (await contractManifestHash(regenerated)).toBigInt(), "the descriptor generates"));
  }
  if (m.queue !== undefined) {
    const chain = await readPinsInForce(node, address, m);
    lines.push(...comparePins(await statedPins(m), chain, chain.source));
  }
  return lines;
}
