// What every part of the client shares (execute.ts, tip-client.ts,
// registry.ts): the resolved configuration and the lookups of a configured
// circuit in it, the transport, the node key check, and the checks of every
// execute and FETCH answer.

import { landingCircuitsOf, type ResolvedConfig } from "./config.ts";
import { ConfigError, NodeKeyMismatchError, ProtocolError, VkHashMismatchError } from "./errors.ts";
import { fieldHex, requestIdHex, type FieldLike } from "./field.ts";
import { currentKeys, readKeyEpoch, signatureKeySets, type KeyEpoch } from "./key-epoch.ts";
import { isQueued, type Manifest } from "./manifest.ts";
import { checkReturnedRecords } from "./records.ts";
import { verifyResultSignatures } from "./result-signatures.ts";
import type { InitResultLayout } from "./init-result.ts";
import type { ResultReader } from "./result.ts";
import type { IntakeLayout } from "./tip.ts";
import type { Transport } from "./transport.ts";
import { parseNodesResponse, type ExecuteResponse, type GrumpkinPoint, type NodeKeys, type NodesResponse, type StateKeys, type Triple } from "./wire.ts";

export class ClientCore {
  readonly config: ResolvedConfig;
  readonly transport: Transport;

  constructor(config: ResolvedConfig, transport: Transport) {
    this.config = config;
    this.transport = transport;
  }

  // ---- the configured circuits ----

  /** The pinned vk hash of a circuit (see `vkHashes` in config.ts). */
  vkHash(circuit: string): string {
    if (!Object.hasOwn(this.config.vkHashes, circuit)) {
      throw new ConfigError(`circuit ${circuit}: no vk hash pinned in the configuration`);
    }
    return this.config.vkHashes[circuit]!;
  }

  /** Pin every package of a contract manifest version (of hash
   * `manifestHash`, which receipt requests then name) at its circuit's
   * vk hash (upgrades.ts vkHashesOf): the version an upgradable app's pins
   * name, which every later request binds and every result is checked
   * under. Only packages already configured (with a circuit and manifest)
   * are re-pinned; ConfigError for a package of the version the
   * configuration does not know. */
  adoptVkHashes(manifestHash: string, vkHashes: Record<string, string>): void {
    for (const name of Object.keys(vkHashes)) {
      if (!Object.hasOwn(this.config.vkHashes, name)) throw new ConfigError(`package ${name}: not configured, so its vk hash cannot be re-pinned`);
    }
    const merged = { ...this.config.vkHashes, ...vkHashes };
    const landingCircuits = landingCircuitsOf(merged, this.config.resultReaders, this.config.resultAliases);
    Object.assign(this.config.vkHashes, vkHashes);
    this.config.landingCircuits = landingCircuits;
    this.config.manifestHash = manifestHash;
  }

  /** The configured note-hash indices of a circuit (see `circuits` in config.ts). */
  noteHashIndices(circuit: string): number[] {
    const indices = Object.hasOwn(this.config.noteHashIndices, circuit) ? this.config.noteHashIndices[circuit] : undefined;
    if (indices === undefined) {
      throw new ConfigError(`circuit ${circuit}: no circuit and manifest in the configuration (circuits), so its result signatures cannot be checked`);
    }
    return indices;
  }

  /** The registered manifest of a circuit with a pinned vk hash and configured
   * note-hash indices: what every request needs before it is built or sent. */
  manifest(circuit: string): Manifest {
    this.vkHash(circuit);
    this.noteHashIndices(circuit);
    return this.config.manifests[circuit]!;
  }

  /** The intake layout of a configured tip circuit with a pinned vk hash. */
  intakeLayout(circuit: string): IntakeLayout {
    this.vkHash(circuit);
    const layout = Object.hasOwn(this.config.intakeLayouts, circuit) ? this.config.intakeLayouts[circuit] : undefined;
    if (layout === undefined) {
      throw new ConfigError(`circuit ${circuit}: no tip circuit and manifest in the configuration (circuits), so its intake inputs are unknown`);
    }
    return layout;
  }

  /** The result reader of a configured tip circuit with a pinned vk hash. */
  resultReader(circuit: string): ResultReader {
    this.vkHash(circuit);
    const target = this.config.resultAliases.get(circuit) ?? circuit;
    const reader = Object.hasOwn(this.config.resultReaders, target) ? this.config.resultReaders[target] : undefined;
    if (reader === undefined) {
      const why = Object.hasOwn(this.config.resultReaderErrors, target) ? this.config.resultReaderErrors[target] : undefined;
      if (why !== undefined) throw new ConfigError(`circuit ${circuit}: its results cannot be read: ${why}`);
      throw new ConfigError(`circuit ${circuit}: no tip circuit and manifest in the configuration (circuits), so its results cannot be read`);
    }
    return reader;
  }

  /** The init result layout of a configured init circuit with a pinned vk hash. */
  initLayout(circuit: string): InitResultLayout {
    this.vkHash(circuit);
    const layout = Object.hasOwn(this.config.initResultLayouts, circuit) ? this.config.initResultLayouts[circuit] : undefined;
    if (layout === undefined) {
      const why = Object.hasOwn(this.config.initResultLayoutErrors, circuit) ? this.config.initResultLayoutErrors[circuit] : undefined;
      if (why !== undefined) throw new ConfigError(`circuit ${circuit}: its init results cannot be read: ${why}`);
      throw new ConfigError(`circuit ${circuit}: no init round in the configuration (a tip circuit that reads no key), so its init results cannot be read`);
    }
    return layout;
  }

  /** The pinned enc keys, node 0 first. */
  encKeys(): Triple<GrumpkinPoint> {
    return this.config.nodeKeys.map((k) => k.enc) as Triple<GrumpkinPoint>;
  }

  // ---- key epochs (key-epoch.ts) ----
  //
  // The key set every signature is checked under is the contract's: epoch 0
  // is the constructor's keys the configuration pins (`nodeKeys`, which the
  // contract address commits to), a later epoch the set the contract stores,
  // read through keyEpochNode. GET /v1/nodes is discovery only: it is compared
  // with the contract's set (checkNodes) and never supplies a key.

  /** The namespace a call acts in: `given`, else the configured
   * contractAddress. ConfigError when neither is there (a client configured
   * only to REGISTER). */
  namespace(given?: FieldLike): string {
    const namespace = given ?? this.config.contractAddress;
    if (namespace === undefined) throw new ConfigError("no namespace: the configuration names no contractAddress and the call names none");
    return fieldHex(namespace, "namespace");
  }

  /** `namespace`'s key epoch through the configured keyEpochNode, with the
   * block read; undefined without one. */
  async keyEpoch(namespace?: FieldLike): Promise<{ block: number; keyEpoch: KeyEpoch } | undefined> {
    const node = this.config.keyEpochNode;
    return node === undefined ? undefined : readKeyEpoch(node, this.namespace(namespace));
  }

  /** The node keys to act under in `namespace` and the epoch they are: the
   * contract's current set after a rotation, the pinned keys otherwise (or
   * without a keyEpochNode, epoch 0). */
  async nodeKeysNow(namespace?: FieldLike): Promise<{ epoch: number; keys: Triple<NodeKeys> }> {
    const read = (await this.keyEpoch(namespace))?.keyEpoch;
    return { epoch: read?.epoch ?? 0, keys: currentKeys(read, this.config.nodeKeys) };
  }

  /** The `sig` key sets the nodes' result signatures and registry answers
   * in `namespace` are accepted under, the current first (signatureKeySets). */
  async signatureKeySetsNow(namespace?: FieldLike): Promise<Triple<GrumpkinPoint>[]> {
    const read = await this.keyEpoch(namespace);
    return signatureKeySets(read?.keyEpoch, this.config.nodeKeys, read?.block ?? 0);
  }

  // ---- node keys ----

  /** GET /v1/nodes, parsed. */
  async nodes(): Promise<NodesResponse> {
    return parseNodesResponse(await this.transport.call("GET", "/v1/nodes"));
  }

  /** Compare GET /v1/nodes with `keys` (default the contract's current set in
   * the configured namespace); throw NodeKeyMismatchError naming the first
   * node whose key differs. */
  async checkNodes(keys?: Triple<NodeKeys>): Promise<void> {
    const { nodes } = await this.nodes();
    const want = keys ?? (await this.nodeKeysNow()).keys;
    nodes.forEach((got: NodeKeys, i: number) => {
      const node = want[i]!;
      for (const key of ["enc", "sig"] as const) {
        if (got[key].x !== node[key].x || got[key].y !== node[key].y) {
          throw new NodeKeyMismatchError(i, key, node[key], got[key]);
        }
      }
    });
  }

  // ---- answers ----

  /** The checks of every execute and FETCH answer: the request id, the
   * pinned vk hash, the three nodes' result signatures (made at step 14,
   * sign, of the request lifecycle in ARCHITECTURE section 3) under the
   * contract's key sets (signatureKeySetsNow; the pinned keys without a
   * keyEpochNode) (a ResultSignatureError naming the node otherwise), on
   * the sidecar path the labels of the returned records (records.ts
   * checkReturnedRecords; their keys only when the request's `state_keys` are
   * given), and the optional local verification. `namespace` is the one the
   * request was sent in. A tip circuit's records are its state module's to
   * check (tipResultParts). */
  async checkResponse(
    circuit: string,
    requestId: string,
    response: ExecuteResponse,
    given?: FieldLike,
    stateKeys?: StateKeys,
  ): Promise<ExecuteResponse> {
    const namespace = this.namespace(given);
    if (response.request_id !== requestIdHex(requestId)) {
      throw new ProtocolError(`answer for request ${response.request_id}, expected ${requestId}`);
    }
    const pinned = this.vkHash(circuit);
    if (response.vk_hash !== pinned) throw new VkHashMismatchError(circuit, pinned, response.vk_hash);
    const indices = this.noteHashIndices(circuit);
    await verifyResultSignatures(namespace, response, indices, await this.signatureKeySetsNow(namespace));
    const manifest = this.config.manifests[circuit]!;
    if (!isQueued(manifest)) checkReturnedRecords(circuit, manifest, indices, response, stateKeys);
    if (this.config.verifyProof) {
      const ok = await this.config.verifyProof({
        circuit,
        vkHash: response.vk_hash,
        proof: response.proof,
        publicInputs: response.public_inputs,
      });
      if (ok === false) throw new ProtocolError(`${circuit}: the local verifier refused the proof`);
    }
    return response;
  }
}
