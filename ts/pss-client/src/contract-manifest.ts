// The contract manifest (docs/contract-manifest.schema.json): one JSON per
// namespace that holds the facts about the contract the machine reads and
// every package's circuit manifest. It is generated here, never written by
// hand: the slots come from the compiled contract artifact (its storage
// layout and the constructor's Config), the vk hashes from the compiled
// circuits, and the rest from a small hand-written descriptor per deployment
// (examples/<example>/deployments/<deployment>.json): the package list in
// order, each package's circuit and state key names, the init inputs as
// Config members, the plain reads, the stale period, and which other
// contract each placeholder read calls.
//
// The manifest never holds the contract's own address, since the address
// is computed from constructor arguments that will include the manifest's
// hash: a read of the contract itself is written `"contract": "$self"`
// (SELF_CONTRACT) in the circuit manifest, and refuseOwnAddress refuses a
// manifest whose reads name the address once it is known.
//
// The manifest hash is poseidon2_hash_bytes of the manifest's canonical JSON
// (RFC 8785, as the signed bodies); the packages hash runs over the listed
// packages in order, h = poseidon2([h, name_hash, vk_hash]) from h = 0, so a
// contract recomputes it from its own list. testvectors/contract_manifest.json
// fixes both for sidecar-core (manifest::contract), this client and Python.

import { poseidon2Hash, poseidon2HashBytes } from "@aztec-labs/foundation/crypto/poseidon";
import { Fr } from "@aztec-labs/foundation/curves/bn254";
import type { AbiType, ContractArtifact } from "@aztec-labs/stdlib/abi";
import { getContractClassFromArtifact } from "@aztec-labs/stdlib/contract";

import { abiMembers } from "./abi.ts";
import { checkedBricks, RESERVED_NAMES, type Bricks } from "./bricks.ts";
import { packageNameHash } from "./deployment.ts";
import { fieldBigInt, fieldHex, type FieldHexString, type FieldLike } from "./field.ts";
import { isQueued, parseManifest, publicReadParams, readContract, SELF_CONTRACT, usesStoredEncKeys, type Manifest } from "./manifest.ts";
import { canonicalJson } from "./wire.ts";

/** A package's request keys, by state key name (`state_keys.reads[i]` names
 * the key `$state_keys.reads[i]` loads). */
export interface NamedStateKeys {
  reads: string[];
  writes: string[];
}

/** One package of a descriptor: its name (the circuit manifest is
 * `<example>/manifests/<name>.json`), its compiled circuit, the listed
 * package it is another intake of (`alias_of`), and, for a queued package,
 * its state key names. */
export interface DescriptorPackage {
  name: string;
  circuit: string;
  alias_of?: string;
  state_keys?: NamedStateKeys;
}

/** A deployment descriptor (examples/<example>/deployments/<deployment>.json). */
export interface Descriptor {
  descriptor: 1;
  /** The contract manifest's name. */
  name: string;
  /** The contract package under `<example>/contract/`; absent without a contract. */
  contract?: string;
  /** Queued deployments: the stale period in L2 blocks, null never skipped. */
  stale_blocks?: number | null;
  packages: DescriptorPackage[];
  /** The init round's package and its inputs as Config members, in order. */
  init?: { package: string; inputs: string[] };
  /** Pinned-read parameter to the storage field its plain getter returns. */
  plain_reads?: Record<string, string>;
  /** Pinned-read function to the name of the contract it calls, whose
   * address the generator is given; such reads are `0x0` in the circuit manifests. */
  read_contracts?: Record<string, string>;
}

/** One package of a contract manifest. */
export interface ContractManifestPackage {
  name: string;
  circuit: string;
  alias_of?: string;
  state_keys?: NamedStateKeys;
  manifest: Record<string, unknown>;
}

/** The contract manifest. */
export interface ContractManifest {
  contract_manifest: 1;
  name: string;
  /** Whether the contract can change its node key set: the node-keys
   * brick its state view reports (bricks.ts). */
  node_keys: Bricks["node_keys"];
  /** What about a deployed app may change: the upgrades brick its state
   * view reports (bricks.ts). */
  upgrades: Bricks["upgrades"];
  contract?: { class_id: FieldHexString; package_capacity?: number };
  queue?: { slot: FieldHexString; stale_blocks: number | null; stale_blocks_slot: FieldHexString };
  /** The library's storage the machine reads: Configured, SharedOnchain
   * (secret-shared on-chain intake), and CircuitUpgrades (`circuit_pins`,
   * exactly when `upgrades` is not `fixed`). */
  storage?: { configured: FieldHexString; shared_onchain?: FieldHexString; circuit_pins?: FieldHexString };
  state_keys?: Record<string, FieldHexString>;
  plain_reads?: Record<string, FieldHexString>;
  init?: { package: string; input_slots: FieldHexString[] };
  circuits: Record<string, { vk_hash: FieldHexString }>;
  packages: ContractManifestPackage[];
}

/** What buildContractManifest takes. */
export interface BuildContractManifestInput {
  descriptor: Descriptor;
  /** Each package's circuit manifest, by package name. */
  manifests: Record<string, unknown>;
  /** Each compiled circuit's vk hash (localVkHash), by circuit id. */
  vkHashes: Record<string, FieldLike>;
  /** The compiled contract; required for a deployment with a queued package. */
  artifact?: ContractArtifact;
  /** The address of each contract `read_contracts` names. */
  contracts?: Record<string, FieldLike>;
  /** A stale period in place of the descriptor's. */
  staleBlocks?: number | null;
}

// ---- the contract artifact's slots ----

type Members = Map<string, { offset: number; type: AbiType }>;

/** A storage field's slot from the artifact's storage layout. */
export function storageSlot(artifact: ContractArtifact, field: string): bigint {
  const entry = (artifact.storageLayout as Record<string, { slot: Fr }>)[field];
  if (entry === undefined) throw new RangeError(`${artifact.name} has no storage field \`${field}\``);
  return entry.slot.toBigInt();
}

/** Whether the artifact declares the storage field `field`. */
function hasStorage(artifact: ContractArtifact, field: string): boolean {
  return Object.hasOwn(artifact.storageLayout as object, field);
}

/** The packed offset and type of each member of a struct type (abiMembers). */
function members(type: AbiType, what: string): Members {
  if (type.kind !== "struct") throw new RangeError(`${what} is not a struct`);
  return abiMembers(type) as Members;
}

function member(map: Members, name: string, what: string): { offset: number; type: AbiType } {
  const m = map.get(name);
  if (m === undefined) throw new RangeError(`${what} has no member \`${name}\``);
  return m;
}

/** The members of the constructor's `config` argument (the app's Config).
 * The constructor is a public function, listed outside the dispatch. */
export function constructorConfig(artifact: ContractArtifact): Members {
  const ctor = [...artifact.functions, ...artifact.nonDispatchPublicFunctions].find((f) => f.name === "constructor");
  if (ctor === undefined) throw new RangeError(`${artifact.name} has no constructor`);
  const configType = ctor.parameters.find((p) => p.name === RESERVED_NAMES.config.name)?.type;
  if (configType === undefined) throw new RangeError(`${artifact.name}'s constructor takes no \`${RESERVED_NAMES.config.name}\``);
  return members(configType as AbiType, "the constructor's Config");
}

/** Config.tip and its members (pss_public_contract TipPins). */
function tipPinsOf(artifact: ContractArtifact): { offset: number; pins: Members } {
  const tip = member(constructorConfig(artifact), "tip", "the constructor's Config");
  return { offset: tip.offset, pins: members(tip.type, "Config.tip") };
}

/** Config.tip.circuits and its members (pss_public_contract CircuitPins). */
function circuitPinsOf(artifact: ContractArtifact): { offset: number; pins: Members } {
  const tip = tipPinsOf(artifact);
  const circuits = member(tip.pins, "circuits", "Config.tip");
  return { offset: tip.offset + circuits.offset, pins: members(circuits.type, "Config.tip.circuits") };
}

/** The slot of the stored stale period (`TipConfig.stale_blocks`): the
 * Config's slot plus the offset of `tip.stale_blocks` in its packing. */
export function staleBlocksSlot(artifact: ContractArtifact): bigint {
  const { offset, pins } = tipPinsOf(artifact);
  return storageSlot(artifact, RESERVED_NAMES.config.name) + BigInt(offset + member(pins, "stale_blocks", "Config.tip").offset);
}

/** The package capacity: the length of Config.tip.circuits.packages in the constructor's ABI. */
export function packageCapacity(artifact: ContractArtifact): number {
  const packages = member(circuitPinsOf(artifact).pins, "packages", "Config.tip.circuits").type;
  if (packages.kind !== "array") throw new RangeError("Config.tip.circuits.packages is not an array");
  return packages.length;
}

/** The storage field of an upgradable app's CircuitUpgrades (pss_public_contract
 * `upgrades`): the contract manifest's `storage.circuit_pins` is its slot. */
export const CIRCUIT_UPGRADES_FIELD = RESERVED_NAMES.circuitUpgrades.name;

// ---- the generator ----

const at = (pkg: string) => `package ${pkg}`;

/** The packages of a manifest the contract's list names (those without
 * `alias_of`), in order. */
export function listedPackages(m: Pick<ContractManifest, "packages">): ContractManifestPackage[] {
  return m.packages.filter((p) => p.alias_of === undefined);
}

/** A circuit manifest with each placeholder read (`0x0`) given the address
 * of the contract the descriptor names for its function. */
function placeReads(pkg: string, manifest: Record<string, unknown>, d: Descriptor, contracts: Record<string, FieldLike>): void {
  const reads = (manifest.public_reads ?? []) as { contract: string; function: string }[];
  for (const read of reads) {
    if (read.contract === SELF_CONTRACT || fieldBigInt(read.contract, `${at(pkg)}: ${read.function} read`) !== 0n) continue;
    const name = d.read_contracts?.[read.function];
    if (name === undefined) throw new RangeError(`${at(pkg)}: the ${read.function} read names no contract (0x0) and the descriptor's read_contracts names none for it`);
    const address = contracts[name];
    if (address === undefined) throw new RangeError(`${at(pkg)}: the ${read.function} read calls contract \`${name}\`, whose address was not given`);
    read.contract = fieldHex(address, `contract ${name}`);
  }
}

/** The contract manifest of a deployment (see the file's opening). The
 * result passes checkContractManifest. */
export async function buildContractManifest(input: BuildContractManifestInput): Promise<ContractManifest> {
  const { descriptor: d, artifact } = input;
  if (d.descriptor !== 1) throw new RangeError(`descriptor ${d.name}: descriptor version ${String(d.descriptor)} is not 1`);
  const packages: ContractManifestPackage[] = d.packages.map((p) => {
    const raw = input.manifests[p.name];
    if (raw === undefined) throw new RangeError(`${at(p.name)}: no circuit manifest`);
    const manifest = structuredClone(raw) as Record<string, unknown>;
    placeReads(p.name, manifest, d, input.contracts ?? {});
    return {
      name: p.name,
      circuit: p.circuit,
      ...(p.alias_of !== undefined && { alias_of: p.alias_of }),
      ...(p.state_keys !== undefined && { state_keys: { reads: [...p.state_keys.reads], writes: [...p.state_keys.writes] } }),
      manifest,
    };
  });
  const parsed = packages.map((p) => parseManifest(p.manifest));
  const queued = parsed.some(isQueued);
  const sharedOnchain = usesStoredEncKeys(parsed);
  // the axis values the bricks report, the artifact refused where its
  // functions disagree with them; a deployment without a contract has none
  const bricks: Bricks = artifact !== undefined ? checkedBricks(artifact, { sharedOnchain }) : { node_keys: "fixed", upgrades: "fixed" };

  const circuits: ContractManifest["circuits"] = {};
  for (const p of packages) {
    if (Object.hasOwn(circuits, p.circuit)) continue;
    const vk = input.vkHashes[p.circuit];
    if (vk === undefined) throw new RangeError(`${at(p.name)}: no vk hash of circuit ${p.circuit}`);
    circuits[p.circuit] = { vk_hash: fieldHex(vk, `circuit ${p.circuit}: vk hash`) };
  }

  const m: ContractManifest = {
    contract_manifest: 1,
    name: d.name,
    node_keys: bricks.node_keys,
    upgrades: bricks.upgrades,
    circuits,
    packages,
  };
  if (artifact !== undefined) {
    const classId = (await getContractClassFromArtifact(artifact)).id;
    m.contract = { class_id: fieldHex(classId.toBigInt()), ...(queued && { package_capacity: packageCapacity(artifact) }) };
  }
  if (queued) {
    if (artifact === undefined) throw new RangeError(`${d.name}: a deployment with a queued package needs its contract artifact (the slots)`);
    const stale = input.staleBlocks !== undefined ? input.staleBlocks : d.stale_blocks;
    if (stale === undefined) throw new RangeError(`${d.name}: a queued deployment states stale_blocks (a block count or null)`);
    if (stale !== null && (!Number.isSafeInteger(stale) || stale < 1)) throw new RangeError(`${d.name}: stale_blocks ${stale}: not a block count or null`);
    const configSlot = storageSlot(artifact, RESERVED_NAMES.config.name);
    const config = constructorConfig(artifact);
    m.queue = {
      slot: fieldHex(storageSlot(artifact, RESERVED_NAMES.queue.name)),
      stale_blocks: stale,
      stale_blocks_slot: fieldHex(staleBlocksSlot(artifact)),
    };
    m.storage = {
      configured: fieldHex(storageSlot(artifact, RESERVED_NAMES.configured.name)),
      ...(sharedOnchain && { shared_onchain: fieldHex(storageSlot(artifact, RESERVED_NAMES.sharedOnchain.name)) }),
      ...(m.upgrades !== "fixed" && { circuit_pins: fieldHex(storageSlot(artifact, CIRCUIT_UPGRADES_FIELD)) }),
    };
    const stateKeys: Record<string, FieldHexString> = {};
    for (const p of packages) {
      for (const name of [...(p.state_keys?.reads ?? []), ...(p.state_keys?.writes ?? [])]) {
        if (!hasStorage(artifact, name)) throw new RangeError(`${at(p.name)}: state key \`${name}\` is no storage field of ${artifact.name}`);
        stateKeys[name] = fieldHex(storageSlot(artifact, name));
      }
    }
    m.state_keys = stateKeys;
    if (d.plain_reads !== undefined && Object.keys(d.plain_reads).length > 0) {
      m.plain_reads = Object.fromEntries(Object.entries(d.plain_reads).map(([param, field]) => [param, fieldHex(storageSlot(artifact, field))]));
    }
    if (d.init !== undefined) {
      m.init = {
        package: d.init.package,
        input_slots: d.init.inputs.map((name) => fieldHex(configSlot + BigInt(member(config, name, "the constructor's Config").offset))),
      };
    }
  } else if (d.stale_blocks !== undefined || d.init !== undefined || d.plain_reads !== undefined) {
    throw new RangeError(`${d.name}: stale_blocks, init and plain_reads belong to a deployment with a queued package`);
  }
  checkContractManifest(m);
  return m;
}

// ---- the structural check ----

/** Refuse (RangeError, naming the place) a contract manifest whose parts do
 * not fit together: every package's circuit is an entry of `circuits` and
 * every entry is used; names are unique; an alias names a listed package
 * and has its circuit; the listed packages fit the contract's capacity; the
 * contract sections are there exactly when a package is queued (and
 * `storage.shared_onchain` exactly when a package takes secret-shared
 * on-chain intake); a queued package names as many state keys as its
 * manifest takes, each with a slot, and every slot is named; the init package
 * is listed, reads no key and writes one; every plain read is a pinned
 * read of some package; the queue's stale period is a block count or null.
 * The machine checks the same
 * and more at REGISTER (state key agreement, shared trees, the intake
 * families). */
export function checkContractManifest(m: ContractManifest): void {
  const names = new Set<string>();
  const parsed = new Map<string, Manifest>();
  for (const p of m.packages) {
    if (names.has(p.name)) throw new RangeError(`packages: \`${p.name}\` is listed twice`);
    names.add(p.name);
    if (!Object.hasOwn(m.circuits, p.circuit)) throw new RangeError(`${at(p.name)}: circuit \`${p.circuit}\` is not an entry of circuits`);
    const manifest = parseManifest(p.manifest);
    if (manifest.circuit !== p.name) throw new RangeError(`${at(p.name)}: its manifest names circuit \`${manifest.circuit}\``);
    parsed.set(p.name, manifest);
  }
  for (const c of Object.keys(m.circuits)) {
    if (!m.packages.some((p) => p.circuit === c)) throw new RangeError(`circuits.${c}: no package uses it`);
  }
  for (const p of m.packages) {
    if (p.alias_of === undefined) continue;
    const of = m.packages.find((o) => o.name === p.alias_of);
    if (of === undefined || of.alias_of !== undefined) throw new RangeError(`${at(p.name)}: alias_of \`${p.alias_of}\` is not a listed package`);
    if (of.circuit !== p.circuit) throw new RangeError(`${at(p.name)}: an alias of \`${of.name}\` runs its circuit \`${of.circuit}\`, not \`${p.circuit}\``);
  }
  const listed = listedPackages(m);
  const capacity = m.contract?.package_capacity;
  if (capacity !== undefined && listed.length > capacity) throw new RangeError(`packages: ${listed.length} listed packages, the contract has room for ${capacity}`);

  const queued = [...parsed.values()].some(isQueued);
  if (queued) {
    for (const s of ["contract", "queue", "storage", "state_keys"] as const) {
      if (m[s] === undefined) throw new RangeError(`${s}: missing; the manifest has a queued package`);
    }
    if (capacity === undefined) throw new RangeError("contract.package_capacity: missing; the manifest has a queued package");
    const stale = m.queue!.stale_blocks;
    if (stale !== null && (!Number.isSafeInteger(stale) || stale < 1 || stale > 0xffffffff)) {
      throw new RangeError(`queue.stale_blocks: ${stale}: not a block count (1 to 2^32 - 1) or null`);
    }
    const sharedOnchain = usesStoredEncKeys(parsed.values());
    if (sharedOnchain !== (m.storage!.shared_onchain !== undefined)) {
      throw new RangeError(`storage.shared_onchain: ${sharedOnchain ? "missing; a package takes" : "present; no package takes"} secret-shared on-chain intake`);
    }
    const upgradable = m.upgrades !== "fixed";
    if (upgradable !== (m.storage!.circuit_pins !== undefined)) {
      throw new RangeError(`storage.circuit_pins: ${upgradable ? `missing under upgrades \`${m.upgrades}\`, whose pins the nodes read there` : "present under upgrades `fixed`, which has no upgradable pins"}`);
    }
  } else {
    for (const s of ["queue", "storage", "state_keys", "plain_reads", "init"] as const) {
      if (m[s] !== undefined) throw new RangeError(`${s}: only with a queued package`);
    }
  }

  const used = new Set<string>();
  for (const p of m.packages) {
    const manifest = parsed.get(p.name)!;
    if (!isQueued(manifest)) {
      if (p.state_keys !== undefined) throw new RangeError(`${at(p.name)}: state_keys under intake direct (its keys come with each request)`);
      continue;
    }
    if (p.state_keys === undefined) throw new RangeError(`${at(p.name)}: state_keys missing for a queued package`);
    for (const side of ["reads", "writes"] as const) {
      if (p.state_keys[side].length !== manifest.stateKeys[side]) {
        throw new RangeError(`${at(p.name)}: state_keys.${side} names ${p.state_keys[side].length} keys, its manifest takes ${manifest.stateKeys[side]}`);
      }
      for (const key of p.state_keys[side]) {
        if (!Object.hasOwn(m.state_keys!, key)) throw new RangeError(`${at(p.name)}: state key \`${key}\` has no slot in state_keys`);
        used.add(key);
      }
    }
  }
  for (const key of Object.keys(m.state_keys ?? {})) {
    if (!used.has(key)) throw new RangeError(`state_keys.${key}: no package names it`);
  }
  if (m.init !== undefined) {
    const p = m.packages.find((o) => o.name === m.init!.package);
    if (p === undefined || p.alias_of !== undefined) throw new RangeError(`init.package: \`${m.init.package}\` is not a listed package`);
    if (!isQueued(parsed.get(p.name)!)) throw new RangeError(`init.package: \`${p.name}\` is not queued`);
    if (p.state_keys!.reads.length > 0 || p.state_keys!.writes.length === 0) throw new RangeError(`init.package: \`${p.name}\` must read no key and write at least one`);
  }
  const pinned = new Set([...parsed.values()].flatMap((p) => p.publicReads.flatMap(publicReadParams)));
  for (const param of Object.keys(m.plain_reads ?? {})) {
    if (!pinned.has(param)) throw new RangeError(`plain_reads.${param}: no package's pinned read fills it`);
  }
}

/** Refuse a manifest whose pinned reads name `address`, the contract's own
 * address: the manifest must not hold it (its hash is an input of the
 * address), so such a read is written `$self`. */
export function refuseOwnAddress(m: ContractManifest, address: FieldLike): void {
  const own = fieldHex(address, "address");
  for (const p of m.packages) {
    for (const read of parseManifest(p.manifest).publicReads) {
      if (read.contract !== SELF_CONTRACT && readContract(read, own) === own) {
        throw new RangeError(`${at(p.name)}: the ${read.function} read names the contract's own address ${own}; write \`${SELF_CONTRACT}\``);
      }
    }
  }
}

// ---- the stripped circuit ----

/** The `debug_symbols` member of a stripped circuit: the base64 of the raw
 * deflate of `{"debug_infos":[]}` (sidecar-core STRIPPED_DEBUG_SYMBOLS). */
export const STRIPPED_DEBUG_SYMBOLS = "q1ZKSU0qTY/PzEvLL1ayio6tBQA=";

/** A compiled circuit (nargo's output) in the one form a manifest message
 * carries: `noir_version` and `hash` as nargo wrote them, `abi`, `bytecode`,
 * the fixed `debug_symbols` and an empty `file_map`. The vk comes from the
 * bytecode alone, so the stripped circuit proves as the full one; the nodes
 * refuse any other member. Throws for a circuit missing one of the four it
 * keeps. */
export function stripCircuit(full: unknown): Record<string, unknown> {
  if (full === null || typeof full !== "object" || Array.isArray(full)) throw new RangeError("circuit: not a JSON object");
  const c = full as Record<string, unknown>;
  for (const k of ["noir_version", "hash", "abi", "bytecode"]) {
    if (c[k] === undefined) throw new RangeError(`circuit: member \`${k}\` is missing`);
  }
  return { noir_version: c.noir_version, hash: c.hash, abi: c.abi, bytecode: c.bytecode, debug_symbols: STRIPPED_DEBUG_SYMBOLS, file_map: {} };
}

// ---- the hashes ----

/** The manifest hash: poseidon2_hash_bytes of the manifest's canonical JSON. */
export async function contractManifestHash(m: ContractManifest): Promise<Fr> {
  const sent: unknown = JSON.parse(JSON.stringify(m));
  return poseidon2HashBytes(Buffer.from(canonicalJson(sent), "utf8"));
}

/** The packages hash over the listed packages in order: from h = 0,
 * h = poseidon2([h, poseidon2_hash_bytes(name), vk_hash]). */
export async function packagesHash(m: Pick<ContractManifest, "packages" | "circuits">): Promise<Fr> {
  let h = Fr.ZERO;
  for (const p of listedPackages(m)) {
    const vk = m.circuits[p.circuit];
    if (vk === undefined) throw new RangeError(`${at(p.name)}: circuit \`${p.circuit}\` is not an entry of circuits`);
    h = await poseidon2Hash([h, await packageNameHash(p.name), new Fr(fieldBigInt(vk.vk_hash, `circuits.${p.circuit}.vk_hash`))]);
  }
  return h;
}
