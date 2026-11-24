// Circuit upgrades (pss_public_contract `upgrades`, the contract manifest's
// `upgrades: circuits` or `contract`): the app's upgrade authority schedules
// new circuit pins, which take effect after a delay, and from that moment
// the contract verifies every round under them and the nodes run the
// contract manifest whose hash they name.
//
// The pins live in the app's `CircuitUpgrades` storage (the contract
// manifest's `storage.circuit_pins` slot S), aztec-nr's DelayedPublicMutable
// of `UpgradedPins` (N = 2P + 2 fields: the class id, the manifest hash, the
// P package name hashes and the P vk hashes, P the contract's capacity):
//
//   S + 0                 metadata: the time of change in its low 32 bits
//   S + 1 .. S + N        the pins before the change
//   S + N + 1 .. S + 2N   the pins after it
//   S + 2N + 1            the hash of the three
//
// At a block of timestamp t the pins in force are the "after" half when
// t >= the time of change, else the "before" half. Never written, every
// field reads 0: the constructor's pins are in force, whose manifest hash
// the Config holds right after the stale period and the three node sig keys
// (queue.stale_blocks_slot + 8).
//
// What a client does with it: before it builds a request it reads which
// contract manifest is in force (manifestHashInForce), fetches that version
// from the network by its hash when it is not the one it holds
// (getManifestVersion, which checks the hash) and takes the vk hashes from
// it (PssClient.adoptManifest), because a request id binds its package's vk
// hash: a request built under replaced pins can never be answered. The
// upgrade authority schedules new pins with upgradeCircuits, after the
// namespace owner has registered the new contract manifest at the next seq.
//
// Under `upgrades: contract` the authority can also move the instance to
// another contract class (upgradeContract): the new class must be published
// first, its contract manifest (generated from the new class's artifact, so
// it names the new class id) registered at the next seq, and the class
// change and the new pins then take effect together after the delay. From
// then on a wallet that registered the instance with the old artifact
// proves its private calls under the wrong class; followContractClass
// registers the instance again with the artifact of the class it runs.

import type { AztecAddress } from "@aztec-labs/aztec.js/addresses";
import { Fr } from "@aztec-labs/foundation/curves/bn254";
import type { ContractArtifact } from "@aztec-labs/stdlib/abi";
import { type ContractInstanceWithAddress, getContractClassFromArtifact } from "@aztec-labs/stdlib/contract";

import type { ContractManifest } from "./contract-manifest.ts";
import { circuitPinsOf, type CircuitPinsArgs } from "./deployment.ts";
import { ProtocolError } from "./errors.ts";
import { SEND_WAIT } from "./fee.ts";
import { fieldAddress, fieldBigInt, fieldHex, type FieldHexString, type FieldLike } from "./field.ts";

/** The index of the class id in each half of the stored pins. */
export const UPGRADED_PINS_CLASS_ID = 0;
/** The index of the manifest hash in each half of the stored pins. */
export const UPGRADED_PINS_MANIFEST_HASH = 1;
/** The offset of the constructor's manifest hash from the stale period's
 * slot: TipPins packs `stale_blocks` (2 fields) and the three node sig keys
 * (6 fields) before `circuits.manifest_hash`. */
export const CONSTRUCTOR_MANIFEST_HASH_OFFSET = 8n;

/** One half of the stored pins (pss_public_contract UpgradedPins). */
export interface UpgradedPins {
  classId: bigint;
  manifestHash: bigint;
  /** The package name hashes, the list's order, zeros past its end. */
  packages: bigint[];
  /** Each listed package's vk hash, zeros past the end of the list. */
  vkHashes: bigint[];
}

/** The stored pins of a contract with upgradable circuits. */
export interface StoredCircuitPins {
  /** The scheduled time of change (seconds); 0 when never written. */
  timeOfChange: bigint;
  before: UpgradedPins;
  after: UpgradedPins;
}

/** The packed length N of UpgradedPins for a capacity of `capacity`. */
export function upgradedPinsLength(capacity: number): number {
  if (!Number.isSafeInteger(capacity) || capacity < 1) throw new RangeError(`package capacity ${capacity}: not a positive count`);
  return 2 * capacity + 2;
}

function unpackHalf(fields: bigint[], capacity: number): UpgradedPins {
  return {
    classId: fields[UPGRADED_PINS_CLASS_ID]!,
    manifestHash: fields[UPGRADED_PINS_MANIFEST_HASH]!,
    packages: fields.slice(2, 2 + capacity),
    vkHashes: fields.slice(2 + capacity, 2 + 2 * capacity),
  };
}

/** Unpack the 2N + 1 fields read from `storage.circuit_pins` on (the
 * metadata, then both halves; the hash after them is not needed). */
export function unpackCircuitPins(fields: bigint[], capacity: number): StoredCircuitPins {
  const n = upgradedPinsLength(capacity);
  if (fields.length !== 2 * n + 1) throw new ProtocolError(`the stored circuit pins of capacity ${capacity} are ${2 * n + 1} fields, not ${fields.length}`);
  return {
    timeOfChange: fields[0]! & 0xffffffffn,
    before: unpackHalf(fields.slice(1, 1 + n), capacity),
    after: unpackHalf(fields.slice(1 + n, 1 + 2 * n), capacity),
  };
}

/** The pins in force at a block of timestamp `timestamp`: the "after" half
 * from the time of change on, the "before" half until then. A half with
 * manifest hash 0 is the never-written value: the constructor's pins. */
export function pinsAt(stored: StoredCircuitPins, timestamp: bigint): UpgradedPins {
  return timestamp >= stored.timeOfChange ? stored.after : stored.before;
}

/** The manifest hash in force at `timestamp`: the stored pins' when an
 * upgrade has taken effect, `constructorManifestHash` while none has. */
export function manifestHashAt(stored: StoredCircuitPins, timestamp: bigint, constructorManifestHash: bigint): bigint {
  const pins = pinsAt(stored, timestamp);
  return pins.manifestHash === 0n ? constructorManifestHash : pins.manifestHash;
}

/** A scheduled upgrade the stored pins carry: the new manifest hash and
 * when it takes effect; undefined when none is pending at `timestamp`. */
export function pendingUpgrade(stored: StoredCircuitPins, timestamp: bigint): { manifestHash: bigint; timeOfChange: bigint } | undefined {
  if (timestamp >= stored.timeOfChange || stored.after.manifestHash === 0n) return undefined;
  return { manifestHash: stored.after.manifestHash, timeOfChange: stored.timeOfChange };
}

/** The Aztec node methods the reads use (aztec.js AztecNode). */
export interface CircuitPinsNode {
  getBlockNumber(): Promise<number>;
  getPublicStorageAt(block: never, contract: AztecAddress, slot: Fr): Promise<Fr>;
  getBlockData(block: never): Promise<{ header: { globalVariables: { timestamp: bigint | number } } } | undefined>;
}

/** What the reads need of a contract manifest: the pins' slot, the
 * capacity and the stale period's slot. */
export type UpgradableManifest = Pick<ContractManifest, "name" | "upgrades" | "contract" | "queue" | "storage">;

function pinsLayout(m: UpgradableManifest): { slot: bigint; capacity: number; staleBlocksSlot: bigint } {
  const slot = m.storage?.circuit_pins;
  const capacity = m.contract?.package_capacity;
  if (m.upgrades === "fixed" || slot === undefined) throw new RangeError(`${m.name}: upgrades \`${m.upgrades}\`: no upgradable circuit pins (storage.circuit_pins)`);
  if (capacity === undefined || m.queue === undefined) throw new RangeError(`${m.name}: not a tip contract manifest (no queue or no package capacity)`);
  return { slot: fieldBigInt(slot, "storage.circuit_pins"), capacity, staleBlocksSlot: fieldBigInt(m.queue.stale_blocks_slot, "queue.stale_blocks_slot") };
}

/** What a read of the pins found at one block. */
export interface PinsRead {
  block: number;
  timestamp: bigint;
  stored: StoredCircuitPins;
  /** The constructor's manifest hash (the Config's). */
  constructorManifestHash: bigint;
  /** The manifest hash in force at the block (manifestHashAt). */
  manifestHash: FieldHexString;
}

/** `contract`'s circuit pins at `block` (the node's latest when not given),
 * under the slots of its contract manifest `m` (any version: an upgrade
 * changes no slot). */
export async function readCircuitPins(node: CircuitPinsNode, contract: FieldLike | AztecAddress, m: UpgradableManifest, block?: number): Promise<PinsRead> {
  const { slot, capacity, staleBlocksSlot } = pinsLayout(m);
  const at = fieldAddress(contract, "contract");
  const b = block ?? Number(await node.getBlockNumber());
  const n = upgradedPinsLength(capacity);
  const read = (s: bigint) => node.getPublicStorageAt(b as never, at, new Fr(s)).then((f) => f.toBigInt());
  const fields = await Promise.all(Array.from({ length: 2 * n + 1 }, (_, k) => read(slot + BigInt(k))));
  const constructorManifestHash = await read(staleBlocksSlot + CONSTRUCTOR_MANIFEST_HASH_OFFSET);
  const data = await node.getBlockData(b as never);
  if (data === undefined) throw new ProtocolError(`the Aztec node has no block ${b}`);
  const timestamp = BigInt(data.header.globalVariables.timestamp);
  const stored = unpackCircuitPins(fields, capacity);
  return { block: b, timestamp, stored, constructorManifestHash, manifestHash: fieldHex(manifestHashAt(stored, timestamp, constructorManifestHash)) };
}

/** The app's `upgrade_circuits` as aztec.js gives it. */
export interface UpgradeCircuitsContract {
  methods: { upgrade_circuits(pins: CircuitPinsArgs): { send(options: object): Promise<unknown> } };
}

/** The upgrade authority's call: schedule the circuit pins of `m` (the new
 * contract manifest, registered at the namespace's next seq first), in
 * force after the contract's upgrade delay. `options` are aztec.js send
 * options (`from`, which must be the authority the constructor pinned, and
 * the fee; the wait is SEND_WAIT unless they give one). The contract
 * refuses any other sender ("not the upgrade authority") and a package list
 * its constructor would refuse. */
export async function upgradeCircuits<R>(contract: UpgradeCircuitsContract, m: ContractManifest, options: object): Promise<R> {
  return (await contract.methods.upgrade_circuits(await circuitPinsOf(m)).send({ wait: SEND_WAIT, ...options })) as R;
}

/** Each package's vk hash in contract manifest `m`, by package name (its
 * circuit's), the aliases included: what a client pins for requests and
 * results under the version `m` is. */
export function vkHashesOf(m: Pick<ContractManifest, "packages" | "circuits">): Record<string, FieldHexString> {
  const out: Record<string, FieldHexString> = {};
  for (const p of m.packages) {
    const vk = m.circuits[p.circuit];
    if (vk === undefined) throw new RangeError(`package ${p.name}: circuit \`${p.circuit}\` is not an entry of circuits`);
    out[p.name] = fieldHex(vk.vk_hash, `circuits.${p.circuit}.vk_hash`);
  }
  return out;
}

/** The app's `upgrade_contract` as aztec.js gives it (`upgrades: contract`). */
export interface UpgradeContractContract {
  methods: { upgrade_contract(newClassId: Fr, pins: CircuitPinsArgs): { send(options: object): Promise<unknown> } };
}

/** The upgrade authority's class upgrade: schedule the instance's move to
 * the class `m` names (`contract.class_id`; `m` is the contract manifest
 * generated from the new class's artifact, registered at the namespace's
 * next seq first) and `m`'s circuit pins, both in force after the delay.
 * The new class must be published (the protocol's registry refuses an
 * unregistered one); the contract refuses another sender ("not the upgrade
 * authority") and an instance whose class-update delay differs from the
 * pins' ("the class-update delay is not the pins' delay"). */
export async function upgradeContract<R>(contract: UpgradeContractContract, m: ContractManifest, options: object): Promise<R> {
  if (m.upgrades !== "contract") throw new RangeError(`${m.name}: upgrades \`${m.upgrades}\`: no class upgrade (upgrade_contract)`);
  const classId = m.contract?.class_id;
  if (classId === undefined) throw new RangeError(`${m.name}: the contract manifest names no contract.class_id`);
  return (await contract.methods.upgrade_contract(new Fr(fieldBigInt(classId, "contract.class_id")), await circuitPinsOf(m)).send({ wait: SEND_WAIT, ...options })) as R;
}

/** What followContractClass needs of a wallet and an Aztec node. */
export interface ClassFollowWallet {
  registerContract(instance: ContractInstanceWithAddress, artifact: ContractArtifact): Promise<unknown>;
}
export interface ClassFollowNode {
  getContract(address: AztecAddress): Promise<ContractInstanceWithAddress | undefined>;
}

const classIds = new WeakMap<ContractArtifact, Promise<bigint>>();

/** The class id of an artifact (computed once per artifact object). */
export function classIdOf(artifact: ContractArtifact): Promise<bigint> {
  let id = classIds.get(artifact);
  if (id === undefined) {
    id = getContractClassFromArtifact(artifact).then((c) => c.id.toBigInt());
    classIds.set(artifact, id);
  }
  return id;
}

/** Register the instance at `address` in `wallet` again, with the artifact
 * among `artifacts` of the class it runs on the node's latest block, when
 * that is not `registered` (the class last registered; undefined: register
 * in any case). Returns the class now registered and whether this call
 * registered it. ProtocolError for an address the node holds no instance
 * at, or a class none of `artifacts` builds. */
export async function followContractClass(
  wallet: ClassFollowWallet,
  node: ClassFollowNode,
  address: FieldLike | AztecAddress,
  artifacts: readonly ContractArtifact[],
  registered?: bigint,
): Promise<{ classId: bigint; registered: boolean }> {
  const at = fieldAddress(address, "contract");
  const instance = await node.getContract(at);
  if (instance === undefined) throw new ProtocolError(`the Aztec node holds no contract instance at ${at}`);
  const classId = instance.currentContractClassId.toBigInt();
  if (classId === registered) return { classId, registered: false };
  for (const artifact of artifacts) {
    if ((await classIdOf(artifact)) === classId) {
      await wallet.registerContract(instance, artifact);
      return { classId, registered: true };
    }
  }
  throw new ProtocolError(`the instance at ${at} runs class ${fieldHex(classId)}, which none of the ${artifacts.length} artifact(s) given builds`);
}
