// Registry answers. Every node signs its answer to a REGISTER (the contract
// manifest registration message, short the manifest message) with its `sig`
// key over the manifest result message, as
// machine/sidecar-core/src/registry/answers.rs defines it:
//
//   poseidon2([MANIFEST_DOMAIN, namespace, manifest_hash, packages_hash,
//              npk_app_hash, seq, 0, i])
//
// which a tip contract's configure checks, and its answer to a DISABLE over
// the registry result message:
//
//   poseidon2([REGISTRY_DOMAIN, namespace, poseidon2_hash_bytes(name), vk_hash,
//              npk_app_hash, seq, disabled, i])
//
// with `disabled` 1 (no node signs it with 0); i is the node index. The client checks every signature under the contract's key
// set (the pinned keys at epoch 0, the stored set after a node replacement)
// before it pins npk_app_hash anywhere. RegistryClient makes the
// owner-signed calls: REGISTER, DISABLE, and the reads of a namespace, its
// contract manifest and a package.

import { poseidon2Hash, poseidon2HashBytes } from "@aztec-labs/foundation/crypto/poseidon";
import { Fr } from "@aztec-labs/foundation/curves/bn254";

import { checkContractManifest, contractManifestHash, packagesHash, stripCircuit, type ContractManifest } from "./contract-manifest.ts";
import type { ClientCore } from "./core.ts";
import { ProtocolError, SidecarError } from "./errors.ts";
import { fieldBigInt, fieldHex, type FieldLike } from "./field.ts";
import {
  checkSeq,
  disableBody,
  disableMessage,
  registerMessage,
  signDisable,
  signManifest,
  failingNode,
  verifySignature,
  type SchnorrSigner,
} from "./signing.ts";
import {
  NODES,
  nodeIndex,
  canonicalJson,
  normaliseSignature,
  parseContractManifestResponse,
  parseDisableResponse,
  parseManifestResponse,
  parseNamespaceResponse,
  parsePackageResponse,
  type ContractManifestResponse,
  type DisableRequest,
  type DisableResponse,
  type GrumpkinPoint,
  type ManifestBody,
  type ManifestMessage,
  type ManifestResponse,
  type NamespaceResponse,
  type PackageResponse,
  type Signature,
  type Triple,
} from "./wire.ts";
import { asciiLabel } from "./labels.ts";

// The registry answer domain: ASCII "sidecar.registry" read as a big-endian
// integer, sidecar-core's REGISTRY_DOMAIN. It keeps a registry signature from
// being read as a round result or a receipt signed by the same node key;
// changing it on one side makes every registry answer fail the client's
// check.
export const REGISTRY_DOMAIN = asciiLabel("sidecar.registry");

// The manifest answer domain: ASCII "sidecar.manifest" read as a big-endian
// integer, sidecar-core's MANIFEST_DOMAIN, so a manifest answer is never read
// as a package's REGISTER or DISABLE answer.
export const MANIFEST_DOMAIN = asciiLabel("sidecar.manifest");

/** The manifest result message node `i` signs for a manifest message. */
export async function manifestMessage(
  namespace: FieldLike,
  manifestHash: FieldLike,
  packagesHash: FieldLike,
  npkAppHash: FieldLike,
  seq: number,
  i: number,
): Promise<Fr> {
  nodeIndex(i);
  return poseidon2Hash([
    new Fr(MANIFEST_DOMAIN),
    new Fr(fieldBigInt(namespace, "namespace")),
    new Fr(fieldBigInt(manifestHash, "manifest_hash")),
    new Fr(fieldBigInt(packagesHash, "packages_hash")),
    new Fr(fieldBigInt(npkAppHash, "npk_app_hash")),
    new Fr(BigInt(seq)),
    Fr.ZERO,
    new Fr(BigInt(i)),
  ]);
}

/** The registry result message node `i` signs. */
export async function registryMessage(
  namespace: FieldLike,
  name: string,
  vkHash: FieldLike,
  npkAppHash: FieldLike,
  seq: number,
  disabled: boolean,
  i: number,
): Promise<Fr> {
  nodeIndex(i);
  return poseidon2Hash([
    new Fr(REGISTRY_DOMAIN),
    new Fr(fieldBigInt(namespace, "namespace")),
    await poseidon2HashBytes(Buffer.from(name, "utf8")),
    new Fr(fieldBigInt(vkHash, "vk_hash")),
    new Fr(fieldBigInt(npkAppHash, "npk_app_hash")),
    new Fr(BigInt(seq)),
    new Fr(disabled ? 1n : 0n),
    new Fr(BigInt(i)),
  ]);
}

/** A registry answer under the registry result message: a DISABLE answer. */
export interface RegistryAnswer {
  vk_hash: string;
  npk_app_hash: string;
  seq: number;
  disabled: boolean;
  signatures: Triple<Signature>;
}

/** What the client sent and expects back. */
export interface RegistryExpectation {
  namespace: FieldLike;
  /** The package's name (DISABLE `circuit`). */
  name: string;
  /** The `seq` of the body sent. */
  seq: number;
  disabled: boolean;
}

/** Check a registry answer: `seq` and `disabled` are the ones the body asked
 * for, and the three signatures verify over the message rebuilt from the
 * namespace and name the client sent and the values it received, node i's
 * under node i's key in one of `sigKeySets` (signing.ts failingNode: the
 * contract's key sets, the current first; never keys a server reports).
 * Throws ProtocolError naming the first thing that differs. */
export async function verifyRegistryAnswer(
  answer: RegistryAnswer,
  expected: RegistryExpectation,
  sigKeySets: readonly Triple<{ x: FieldLike; y: FieldLike }>[],
): Promise<void> {
  if (answer.seq !== expected.seq) throw new ProtocolError(`registry answer: seq ${answer.seq}, the body sent seq ${expected.seq}`);
  if (answer.disabled !== expected.disabled) throw new ProtocolError(`registry answer: disabled ${answer.disabled}, expected ${expected.disabled}`);
  const namespace = fieldHex(expected.namespace, "namespace");
  const messages: bigint[] = [];
  for (let i = 0; i < NODES; i++) {
    messages.push((await registryMessage(namespace, expected.name, answer.vk_hash, answer.npk_app_hash, answer.seq, answer.disabled, i)).toBigInt());
  }
  const failed = await failingNode(messages, answer.signatures, sigKeySets);
  if (failed !== undefined) throw new ProtocolError(`registry answer: node ${failed}'s signature does not verify under its sig key`);
}

/** What the client sent in a manifest message and expects back. */
export interface ManifestExpectation {
  namespace: FieldLike;
  /** The contract manifest sent. */
  manifest: ContractManifest;
  /** The `seq` of the body sent. */
  seq: number;
}

/** Check the answer to a manifest message: `seq` is the body's; the
 * manifest hash and packages hash are the ones the client computes from the
 * contract manifest it sent; node i's signature verifies under node i's key
 * in one of `sigKeySets` (signing.ts failingNode: the contract's key sets,
 * the current first; never keys a server reports) over the manifest result
 * message. Throws ProtocolError naming the first thing that differs. */
export async function verifyManifestResponse(
  response: ManifestResponse,
  expected: ManifestExpectation,
  sigKeySets: readonly Triple<{ x: FieldLike; y: FieldLike }>[],
): Promise<void> {
  if (response.seq !== expected.seq) throw new ProtocolError(`REGISTER answer: seq ${response.seq}, the body sent seq ${expected.seq}`);
  const manifestHash = fieldHex((await contractManifestHash(expected.manifest)).toBigInt());
  if (response.manifest_hash !== manifestHash) throw new ProtocolError(`REGISTER answer: manifest hash ${response.manifest_hash}, the contract manifest sent hashes to ${manifestHash}`);
  const listedHash = fieldHex((await packagesHash(expected.manifest)).toBigInt());
  if (response.packages_hash !== listedHash) throw new ProtocolError(`REGISTER answer: packages hash ${response.packages_hash}, the contract manifest sent gives ${listedHash}`);
  const namespace = fieldHex(expected.namespace, "namespace");
  const messages: bigint[] = [];
  for (let i = 0; i < NODES; i++) {
    messages.push((await manifestMessage(namespace, response.manifest_hash, response.packages_hash, response.npk_app_hash, response.seq, i)).toBigInt());
  }
  const failed = await failingNode(messages, response.signatures, sigKeySets);
  if (failed !== undefined) throw new ProtocolError(`REGISTER answer: node ${failed}'s manifest signature does not verify under its sig key`);
}

// ---- the registry calls ----

export interface ManifestBodyInput {
  /** The contract manifest (contract-manifest.ts, generated). */
  manifest: ContractManifest;
  /** The compiled circuits by id (nargo's output, or already stripped):
   * every entry of the manifest's `circuits`, sent stripped. */
  circuits: Record<string, unknown>;
  /** Default: the configured contract address. */
  namespace?: FieldLike;
  /** Default: nextSeq() of the namespace. */
  seq?: number;
}

// The time a REGISTER may take: each node builds one vk per circuit (seconds
// each) and, at seq 0, runs the registration round, and the orchestrator
// gives each node call up to 1,000 s (its node-call timeout); the client waits
// 60 s longer than that.
/** The default timeout of a REGISTER call, in milliseconds. */
export const REGISTER_TIMEOUT_MS = 1_060_000;

export interface RegisterOptions {
  /** How long the REGISTER call may take; default REGISTER_TIMEOUT_MS. */
  timeoutMs?: number;
}

/** The registry part of one client (REGISTER, DISABLE and their reads),
 * over the shared core. */
export class RegistryClient {
  private readonly core: ClientCore;
  private readonly seqs = new Map<string, number>();

  constructor(core: ClientCore) {
    this.core = core;
  }

  /** GET /v1/packages/{namespace}/{name}. */
  async getPackage(namespace: FieldLike, name: string): Promise<PackageResponse> {
    const ns = fieldHex(namespace, "namespace");
    return parsePackageResponse(await this.core.transport.call("GET", `/v1/packages/${ns}/${encodeURIComponent(name)}`));
  }

  /** GET /v1/namespaces/{namespace}: the owner, seq, npk_app_hash and
   * manifest hash, or undefined when the namespace has no registration yet
   * (404). */
  async getNamespace(namespace: FieldLike): Promise<NamespaceResponse | undefined> {
    const ns = fieldHex(namespace, "namespace");
    try {
      return parseNamespaceResponse(await this.core.transport.call("GET", `/v1/namespaces/${ns}`));
    } catch (e) {
      if (e instanceof SidecarError && e.status === 404) return undefined;
      throw e;
    }
  }

  /** GET /v1/namespaces/{namespace}/manifest: the contract manifest as
   * registered. Checks that it hashes to the manifest hash the answer
   * names (ProtocolError otherwise); a caller compares that hash with the
   * one it trusts (a contract's pin, its own generated manifest). */
  async getContractManifest(namespace: FieldLike): Promise<ContractManifestResponse> {
    const ns = fieldHex(namespace, "namespace");
    const r = parseContractManifestResponse(await this.core.transport.call("GET", `/v1/namespaces/${ns}/manifest`));
    const hash = fieldHex((await contractManifestHash(r.manifest as ContractManifest)).toBigInt());
    if (hash !== r.manifest_hash) throw new ProtocolError(`GET /v1/namespaces/${ns}/manifest: the manifest hashes to ${hash}, not the ${r.manifest_hash} answered`);
    return r;
  }

  /** GET /v1/namespaces/{namespace}/manifests/{manifest_hash}: a version
   * of the namespace's contract manifest the network holds, by its hash
   * (under upgradable circuits a namespace holds the version its contract's
   * pins name and the one registered after it). Checks that it hashes to
   * the hash asked for (ProtocolError otherwise); a SidecarError 404 when
   * the network holds no such version. */
  async getManifestVersion(namespace: FieldLike, manifestHash: FieldLike): Promise<ContractManifestResponse> {
    const ns = fieldHex(namespace, "namespace");
    const want = fieldHex(manifestHash, "manifest_hash");
    const path = `/v1/namespaces/${ns}/manifests/${want}`;
    const r = parseContractManifestResponse(await this.core.transport.call("GET", path));
    const hash = fieldHex((await contractManifestHash(r.manifest as ContractManifest)).toBigInt());
    if (hash !== want || r.manifest_hash !== want) throw new ProtocolError(`GET ${path}: the manifest hashes to ${hash} and is answered as ${r.manifest_hash}, not the ${want} asked for`);
    return r;
  }

  // Seq handling. Every REGISTER and DISABLE body carries the namespace's
  // registry sequence number, and the owner's signature covers it, so a body
  // that was seen once can never register, re-enable or disable anything
  // again (the nodes answer 409 to a wrong seq). Before building a body the
  // client reads the current value from GET /v1/namespaces/{namespace} and
  // uses 0 when the namespace answers 404, the stored value plus one
  // otherwise; it records the seq every answer returns (lastSeq). A body
  // built with an explicit seq is sent as given. Two owners' tools racing on
  // one namespace both read the same value and one of them gets 409; build
  // again from a fresh read. A first REGISTER that failed part way is
  // repaired by resending the same seq 0 body, which the nodes accept while
  // the stored seq is 0.
  /** The seq the next registry body of `namespace` carries. */
  async nextSeq(namespace?: FieldLike): Promise<number> {
    const info = await this.getNamespace(this.core.namespace(namespace));
    return info === undefined ? 0 : info.seq + 1;
  }

  /** The seq of the last registry answer this client received for
   * `namespace`, if any. */
  lastSeq(namespace?: FieldLike): number | undefined {
    return this.seqs.get(this.core.namespace(namespace));
  }

  /** The manifest message before signing, in this client's namespace unless
   * another is given, with `seq` from nextSeq() unless given: the contract
   * manifest (checked: checkContractManifest) and each circuit it names,
   * stripped (stripCircuit). Sign it with signManifest(). */
  async manifestBody(input: ManifestBodyInput): Promise<ManifestBody> {
    checkContractManifest(input.manifest);
    const namespace = this.core.namespace(input.namespace);
    const circuits: Record<string, unknown> = {};
    for (const id of Object.keys(input.manifest.circuits)) {
      const full = input.circuits[id];
      if (full === undefined) throw new RangeError(`circuits.${id}: the contract manifest names it, and no compiled circuit was given`);
      circuits[id] = stripCircuit(full);
    }
    return {
      namespace,
      manifest: input.manifest,
      circuits,
      seq: input.seq === undefined ? await this.nextSeq(namespace) : checkSeq(input.seq),
    };
  }

  // The unit of REGISTER is the whole contract manifest. The first one of a
  // namespace (seq 0) makes the signer its owner and runs the registration
  // round. A later REGISTER of the same contract manifest re-enables every
  // package a DISABLE stopped. Another contract manifest replaces the stored
  // one on the sidecar path only: a tip namespace's contract commits to its
  // contract manifest, so the nodes refuse another (400).
  /** POST /v1/register with a manifest message signed by signManifest().
   * Checks the answer (verifyManifestResponse) under the namespace's key set
   * (ClientCore.signatureKeySetsNow), then returns it: its npk_app_hash
   * goes into the contract's configure, with each listed package's
   * signatures (configureArgs). A later REGISTER by another key is refused
   * with 403 (SidecarError, class forbidden), a stale or replayed seq with
   * 409 (class conflict). */
  async register(body: ManifestMessage, options: RegisterOptions = {}): Promise<ManifestResponse> {
    await checkSigned("REGISTER", body, registerMessage);
    const manifest = body.manifest as ContractManifest;
    checkContractManifest(manifest);
    const response = parseManifestResponse(
      await this.core.transport.call("POST", "/v1/register", JSON.stringify(body), options.timeoutMs ?? REGISTER_TIMEOUT_MS),
    );
    await verifyManifestResponse(response, { namespace: body.namespace, manifest, seq: body.seq }, await this.core.signatureKeySetsNow(body.namespace));
    this.seqs.set(body.namespace, response.seq);
    return response;
  }

  /** Read seq, strip the circuits, sign and send a manifest message in one
   * call. */
  async registerManifest(input: ManifestBodyInput, owner: SchnorrSigner, options: RegisterOptions = {}): Promise<ManifestResponse> {
    return this.register(await signManifest(await this.manifestBody(input), owner), options);
  }

  // DISABLE semantics. disable(namespace, circuit, owner) sends
  // POST /v1/disable {namespace, circuit, owner_pubkey, seq, signature}, signed
  // by the namespace owner under the DISABLE domain, with seq read as for
  // REGISTER. The nodes then refuse the package at resolution, before any LOAD,
  // and keep its registration record; a REGISTER of the same contract manifest
  // re-enables every package. Disabling a disabled circuit with its
  // recorded seq answers the same. Refusals: 403 when the signature is missing
  // or not by the owner, 404 when the circuit is not registered, 409 for a
  // wrong seq. The client never disables anything on its own. The owner can
  // stop a circuit that turns out to be wrong without replacing it, and
  // nothing it stored is lost.
  /** POST /v1/disable: disable a registered circuit, signed by the owner. */
  async disable(namespace: FieldLike, circuit: string, owner: SchnorrSigner, seq?: number): Promise<DisableResponse> {
    const ns = fieldHex(namespace, "namespace");
    const s = seq === undefined ? await this.nextSeq(ns) : seq;
    return this.sendDisable(await signDisable(disableBody(ns, circuit, s), owner));
  }

  /** POST /v1/disable with a body signed by signDisable(). Checks the answer
   * names the body's circuit and seq and carries three node signatures that
   * verify under the namespace's key set (ClientCore.signatureKeySetsNow). */
  async sendDisable(body: DisableRequest): Promise<DisableResponse> {
    await checkSigned("DISABLE", body, disableMessage);
    const response = parseDisableResponse(await this.core.transport.call("POST", "/v1/disable", JSON.stringify(body)));
    if (response.namespace !== body.namespace || response.circuit !== body.circuit) {
      throw new ProtocolError(`DISABLE answered for ${response.namespace}/${response.circuit}, expected ${body.namespace}/${body.circuit}`);
    }
    await verifyRegistryAnswer(response, { namespace: body.namespace, name: body.circuit, seq: body.seq, disabled: true }, await this.core.signatureKeySetsNow(body.namespace));
    this.seqs.set(body.namespace, response.seq);
    return response;
  }
}

// A signed body is sent exactly as it was signed. Check before sending that its
// field elements are in the wire's normal form (so the nodes read the same
// values the signature covers) and that the signature verifies under
// owner_pubkey, so a wrong key or an edited body fails here rather than as a
// 403 after a round trip.
async function checkSigned(
  what: "REGISTER" | "DISABLE",
  body: { namespace: string; owner_pubkey: GrumpkinPoint; seq: number; signature: Signature },
  message: (b: object) => Promise<{ toBigInt(): bigint }>,
): Promise<void> {
  const normal =
    body.namespace === fieldHex(body.namespace, "namespace") &&
    body.owner_pubkey.x === fieldHex(body.owner_pubkey.x, "owner_pubkey.x") &&
    body.owner_pubkey.y === fieldHex(body.owner_pubkey.y, "owner_pubkey.y") &&
    Number.isSafeInteger(body.seq) &&
    body.seq >= 0 &&
    canonicalJson(normaliseSignature(body.signature)) === canonicalJson(body.signature);
  const signer = what === "REGISTER" ? "signManifest" : "signDisable";
  if (!normal) throw new RangeError(`${what}: the body is not in the wire's normal form; build and sign it with ${signer}()`);
  if (!(await verifySignature((await message(body)).toBigInt(), body.owner_pubkey, body.signature))) {
    throw new RangeError(`${what}: the signature does not verify under owner_pubkey`);
  }
}
