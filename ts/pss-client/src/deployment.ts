// The deployment of a tip app (docs/ARCHITECTURE.md section 6, "Deployment,
// configure and the init round"): the constructor's pins, the arguments of the
// once-only configure, and the order the two calls take around REGISTER.
//
// The namespace is the app contract's address, which Aztec derives from the
// constructor's arguments and a salt, and REGISTER derives npk_app_hash from the
// namespace. So a deployment is: compile every package and compute each one's
// vk hash locally (localVkHash, bb on the developer's machine); generate the
// contract manifest (contract-manifest.ts: the slots from the artifact, the
// vk hashes, the descriptor); draw a secret random salt; compute the address
// from the constructor's pins (tipPins: the contract manifest's stale period,
// the three node sig keys and the circuit pins: the manifest's hash, its
// listed packages' name hashes and vk hashes) and the app's own constants, so
// the address commits to the circuits and the manifest;
// REGISTER the contract manifest once against that address, at seq 0 (REGISTER
// reads no chain, so this happens before the address is public); deploy;
// configure with the answer (configureArgs). deployTip runs the steps after
// the compile and the generation over a TipDeployer, the caller's chain side
// (aztec.js), which knows the contract's artifact and its app constants
// (aztecDeployer, for an app whose deployment needs nothing more).
//
// The contract's side is pss_public_contract's configure module: TipPins is the
// constructor's struct, RegistryAnswer configure's answer, and configure
// checks the answer's three node signatures over the manifest result message
// with namespace = its own address, its pinned manifest hash and the packages
// hash of its own list, and stores npk_app_hash.

import type { AztecAddress } from "@aztec-labs/aztec.js/addresses";
import { Contract } from "@aztec-labs/aztec.js/contracts";
import type { Wallet } from "@aztec-labs/aztec.js/wallet";
import { poseidon2HashBytes } from "@aztec-labs/foundation/crypto/poseidon";
import { Fr } from "@aztec-labs/foundation/curves/bn254";
import type { ContractArtifact } from "@aztec-labs/stdlib/abi";

import { contractManifestHash, listedPackages, refuseOwnAddress, type ContractManifest } from "./contract-manifest.ts";
import { ProtocolError } from "./errors.ts";
import { DEFAULT_FEE_SETTING, txSendOptions, type FeeSetting } from "./fee.ts";
import { fieldBigInt, fieldHex, randomField, type FieldLike } from "./field.ts";
import { verifyManifestResponse, type ManifestBodyInput, type RegisterOptions } from "./registry.ts";
import type { SchnorrSigner } from "./signing.ts";
import { signatureLimbs } from "./proved.ts";
import type { ManifestResponse, NamespaceResponse, Triple } from "./wire.ts";

/** A point as the deployment takes a node's sig key. */
export interface SigKeyLike {
  x: FieldLike;
  y: FieldLike;
}

/** The constructor's `TipPins` (pss_public_contract configure.nr), as aztec.js
 * encodes a struct argument: field names as the Noir struct names them. */
export interface TipPinsArgs {
  stale_blocks: { enabled: boolean; blocks: number };
  node_sig_keys: { x: Fr; y: Fr }[];
  circuits: CircuitPinsArgs;
}

/** The circuit pins (`CircuitPins`): the contract manifest's hash, the
 * package list and its vk hashes. */
export interface CircuitPinsArgs {
  manifest_hash: Fr;
  /** Package p's name hash at index p, then zeros up to the capacity. */
  packages: Fr[];
  /** Package p's vk hash at index p, then zeros up to the capacity. */
  vk_hashes: Fr[];
}

/** configure's `answer` (`RegistryAnswer`): the answer's seq and the three
 * manifest signatures; its manifest hash and packages hash are the
 * constructor's. */
export interface RegistryAnswerArgs {
  seq: Fr;
  /** Node i's signature as `[s.lo, s.hi, e.lo, e.hi]`. */
  signatures: [Fr, Fr, Fr, Fr][];
}

/** configure's two arguments, in order. */
export interface ConfigureArgs {
  npk_app_hash: Fr;
  answer: RegistryAnswerArgs;
}

/** A package's name hash: `poseidon2_hash_bytes` of its manifest name, the
 * value the registry result message hashes and the contract lists. */
export async function packageNameHash(name: string): Promise<Fr> {
  return poseidon2HashBytes(Buffer.from(name, "utf8"));
}

/** The listed packages of a tip contract manifest (name and vk hash, in list
 * order) and its contract's capacity. RangeError for a manifest without a
 * queue or a capacity, or one whose list does not fit. */
function tipList(m: ContractManifest): { names: string[]; vkHashes: bigint[]; capacity: number } {
  const capacity = m.contract?.package_capacity;
  if (m.queue === undefined || capacity === undefined) throw new RangeError(`${m.name}: not a tip contract manifest (no queue or no package capacity)`);
  const listed = listedPackages(m);
  if (listed.length === 0) throw new RangeError("the package list is empty");
  if (listed.length > capacity) throw new RangeError(`${listed.length} packages, the contract has room for ${capacity}`);
  const vkHashes = listed.map((p) => {
    const v = fieldBigInt(m.circuits[p.circuit]?.vk_hash ?? "", `${p.name}: vk hash`);
    if (v === 0n) throw new RangeError(`${p.name}: vk hash 0 (no circuit has it)`);
    return v;
  });
  return { names: listed.map((p) => p.name), vkHashes, capacity };
}

/** The stale period of a tip contract manifest (`queue.stale_blocks`) as
 * the contract stores it: `{enabled: false, blocks: 0}` when a head is never
 * skipped. RangeError for a manifest without a queue. */
export function staleBlocksOf(m: Pick<ContractManifest, "name" | "queue">): { enabled: boolean; blocks: number } {
  if (m.queue === undefined) throw new RangeError(`${m.name}: no queue, so no stale period`);
  const stale = m.queue.stale_blocks;
  return stale === null ? { enabled: false, blocks: 0 } : { enabled: true, blocks: stale };
}

/** The constructor's pins of a deployment of the contract manifest `m`: its
 * stale period, the three node sig keys and the circuit pins: the manifest's
 * hash, its listed packages' name hashes and each one's vk hash
 * (pss_public_contract TipPins), padded to the contract's capacity, so the
 * address commits to the circuits and the manifest. */
export async function tipPins(m: ContractManifest, sigKeys: Triple<SigKeyLike>): Promise<TipPinsArgs> {
  const circuits = await circuitPinsOf(m);
  return {
    stale_blocks: staleBlocksOf(m),
    node_sig_keys: sigKeys.map((k, i) => ({ x: new Fr(fieldBigInt(k.x, `sig key ${i}.x`)), y: new Fr(fieldBigInt(k.y, `sig key ${i}.y`)) })),
    circuits,
  };
}

/** The circuit pins of a tip contract manifest (pss_public_contract
 * CircuitPins), as the constructor pins them and an upgrade authority's
 * `upgrade_circuits` schedules them (upgrades.ts): the manifest's hash, its
 * listed packages' name hashes and each one's vk hash, padded to the
 * contract's capacity. */
export async function circuitPinsOf(m: ContractManifest): Promise<CircuitPinsArgs> {
  const { names, vkHashes, capacity } = tipList(m);
  const nameHashes = await Promise.all(names.map(packageNameHash));
  const pad = () => Array.from({ length: capacity - names.length }, () => Fr.ZERO);
  return {
    manifest_hash: await contractManifestHash(m),
    packages: [...nameHashes, ...pad()],
    vk_hashes: [...vkHashes.map((v) => new Fr(v)), ...pad()],
  };
}

/** configure's arguments from the answer to the manifest message of `m`
 * under `namespace`: npk_app_hash, the answer's seq and its three manifest
 * signatures. Checks what the contract checks, so a deployment that cannot
 * be configured fails here and not in a transaction (verifyManifestResponse
 * under the pinned sig keys: the manifest hash, the packages hash, every
 * signature; ProtocolError otherwise). The contract has no rule on seq. */
export async function configureArgs(
  namespace: FieldLike,
  m: ContractManifest,
  response: ManifestResponse,
  sigKeys: Triple<SigKeyLike>,
): Promise<ConfigureArgs> {
  tipList(m);
  await verifyManifestResponse(response, { namespace, manifest: m, seq: response.seq }, [sigKeys]);
  return {
    npk_app_hash: new Fr(fieldBigInt(response.npk_app_hash, "npk_app_hash")),
    answer: { seq: new Fr(BigInt(response.seq)), signatures: response.signatures.map(signatureLimbs) },
  };
}

/** The registry calls a deployment makes: PssClient has both. */
export interface TipRegistrar {
  getNamespace(namespace: FieldLike): Promise<NamespaceResponse | undefined>;
  registerManifest(input: ManifestBodyInput, owner: SchnorrSigner, options?: RegisterOptions): Promise<ManifestResponse>;
}

/** The chain side of a deployment, the caller's: aztec.js with the app's
 * artifact, which adds the app's own constants (e.g. lending's oracle and
 * seeded liquidity) to the pins. */
export interface TipDeployer {
  /** The address the contract will have, deployed with `salt` and these pins:
   * the namespace the contract manifest is registered under. */
  address(salt: Fr, pins: TipPinsArgs): Promise<FieldLike>;
  /** Deploy it: the public constructor with these pins, under `salt`. */
  deploy(salt: Fr, pins: TipPinsArgs): Promise<void>;
  /** Send configure(npk_app_hash, answer) to the deployed contract. */
  configure(args: ConfigureArgs): Promise<void>;
}

// The chain side most apps need: aztec.js's Contract.deploy of the app's
// artifact with its public constructor, universally deployed (the address
// depends on the artifact, the arguments and the salt alone, so it is the
// same before and after the deployment), and configure sent to the deployed
// contract, each under the fee setting's kind. The constructor's arguments
// default to the examples' `constructor(config)` with `Config { tip }`; an
// app with constants of its own (lending's oracle, an upgrade authority)
// passes its own `constructorArgs`. An app whose deployment does more
// (checks, logging) writes its TipDeployer itself, as the e2e harness does.

/** What aztecDeployer takes. */
export interface AztecDeployerOptions {
  wallet: Wallet;
  artifact: ContractArtifact;
  /** The account that sends the deployment and configure. */
  from: AztecAddress;
  /** The constructor's arguments from the pins; default `[{ tip: pins }]`. */
  constructorArgs?: (pins: TipPinsArgs) => unknown[];
  /** Default DEFAULT_FEE_SETTING (each transaction under its kind, "deploy"
   * and "configure"). */
  fee?: FeeSetting;
  /** aztec.js's Contract; a stand-in for tests. */
  contracts?: Pick<typeof Contract, "deploy">;
}

/** A TipDeployer over aztec.js (see above), and the deployed contract once
 * `deploy` has run. */
export interface AztecDeployer extends TipDeployer {
  /** The deployed contract; throws before `deploy`. */
  contract(): Contract;
}

/** The TipDeployer of an app deployed with aztec.js (see above). */
export function aztecDeployer(options: AztecDeployerOptions): AztecDeployer {
  const contracts = options.contracts ?? Contract;
  const args = options.constructorArgs ?? ((pins: TipPinsArgs) => [{ tip: pins }]);
  const fee = options.fee ?? DEFAULT_FEE_SETTING;
  const method = (salt: Fr, pins: TipPinsArgs) => contracts.deploy(options.wallet, options.artifact, args(pins), "constructor", { salt, universalDeploy: true });
  let deployed: Contract | undefined;
  return {
    address: async (salt, pins) => (await method(salt, pins).getInstance()).address.toBigInt(),
    deploy: async (salt, pins) => {
      deployed = (await method(salt, pins).send({ ...(await txSendOptions(fee, "deploy")), from: options.from })).contract;
    },
    configure: async (configure) => {
      if (deployed === undefined) throw new ProtocolError("configure before the deployment");
      await deployed.methods.configure!(configure.npk_app_hash, configure.answer).send({ ...(await txSendOptions(fee, "configure")), from: options.from });
    },
    contract: () => {
      if (deployed === undefined) throw new ProtocolError("the contract is not deployed yet");
      return deployed;
    },
  };
}

export interface DeployTipOptions {
  registry: TipRegistrar;
  /** The namespace owner's key: the first REGISTER makes it the owner. */
  owner: SchnorrSigner;
  /** The deployment's contract manifest (contract-manifest.ts, generated). */
  manifest: ContractManifest;
  /** The compiled circuits by id: every entry of the manifest's `circuits`. */
  circuits: Record<string, unknown>;
  /** The network's pinned sig keys, node 0 first. */
  sigKeys: Triple<SigKeyLike>;
  deployer: TipDeployer;
  /** Default: randomField(). */
  salt?: Fr;
}

export interface TipDeployment {
  salt: Fr;
  address: string;
  pins: TipPinsArgs;
  answer: ManifestResponse;
  configure: ConfigureArgs;
}

// Operator knob: DESIGN.md, "Configuration reference" (deployTip salt). A
// fresh secret randomField() per deployment; options.salt is for reproducible
// test deployments only.
/** Deploy a tip app in the only safe order, its packages compiled and its
 * contract manifest generated: salt, address (the constructor's pins with the
 * vk hashes), the address checked absent from the manifest
 * (refuseOwnAddress), REGISTER the contract manifest at seq 0, deploy,
 * configure. Refuses before any call when the namespace already has a
 * registration (another salt is needed), and checks the answer as configure
 * will before the deployment is sent. */
export async function deployTip(options: DeployTipOptions): Promise<TipDeployment> {
  const salt = options.salt ?? new Fr(randomField());
  const pins = await tipPins(options.manifest, options.sigKeys);
  const address = fieldHex(await options.deployer.address(salt, pins), "address");
  refuseOwnAddress(options.manifest, address);
  if ((await options.registry.getNamespace(address)) !== undefined) {
    throw new ProtocolError(`namespace ${address} already has a registration: draw a new salt`);
  }
  const answer = await options.registry.registerManifest({ manifest: options.manifest, circuits: options.circuits, namespace: address, seq: 0 }, options.owner);
  const args = await configureArgs(address, options.manifest, answer, options.sigKeys);
  await options.deployer.deploy(salt, pins);
  await options.deployer.configure(args);
  return { salt, address, pins, answer, configure: args };
}
