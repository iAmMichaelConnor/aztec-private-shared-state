// PssClient: one client of the orchestrator for an app, made of three parts
// over one shared core (core.ts: the configuration, the transport, the node
// key check and the answer checks):
//
//   execute.ts      the sidecar path: execute with FETCH on failure, resend, fetch
//   tip-client.ts   the tip: tip requests, intakes, FETCH by chain request id
//   registry.ts     REGISTER, DISABLE and the namespace and package reads
//
// Each method below is the part's; its documentation is there.

import { resolveConfig, type PssClientConfig, type ResolvedConfig } from "./config.ts";
import { contractManifestHash, type ContractManifest } from "./contract-manifest.ts";
import { ClientCore } from "./core.ts";
import { Executor, type ExecuteOutcome, type FetchOptions } from "./execute.ts";
import { fieldHex, type FieldLike } from "./field.ts";
import type { IntakeAsk, IntakeSendOptions, IntakeTarget, RequestIntake } from "./intake.ts";
import { MemoryRecordStore, type RecordStore } from "./records.ts";
import { RegistryClient, type ManifestBodyInput, type RegisterOptions } from "./registry.ts";
import type { QueuedResult, ResultReader } from "./result.ts";
import type { BuildRequestInput, PreparedRequest } from "./request.ts";
import type { SchnorrSigner } from "./signing.ts";
import { MemoryRequestStore, type RequestStore } from "./store.ts";
import type { TipRequest } from "./tip.ts";
import {
  TipClient,
  type ChainFetchOptions,
  type InitFetchOptions,
  type InitResult,
  type IntakeRequest,
  type RequestIntakeOptions,
  type RequestedIntake,
  type TipRequestOptions,
} from "./tip-client.ts";
import { Transport } from "./transport.ts";
import { vkHashesOf } from "./upgrades.ts";
import type {
  DisableRequest,
  DisableResponse,
  ExecuteRequest,
  ExecuteResponse,
  NamespaceResponse,
  NodesResponse,
  PackageResponse,
  ContractManifestResponse,
  ManifestBody,
  ManifestMessage,
  ManifestResponse,
  StateKeys,
} from "./wire.ts";

export interface PssClientOptions {
  /** Where sent request ids and bodies are kept. Default: in memory. */
  store?: RequestStore;
  /** Where the state records rounds return are kept. Default: in memory. */
  recordStore?: RecordStore;
  /** The fetch implementation. Default: globalThis.fetch. */
  fetch?: typeof fetch;
}

export class PssClient {
  readonly config: ResolvedConfig;
  readonly store: RequestStore;
  readonly recordStore: RecordStore;
  private readonly core: ClientCore;
  private readonly executor: Executor;
  private readonly tip: TipClient;
  private readonly registry: RegistryClient;

  constructor(config: PssClientConfig, options: PssClientOptions = {}) {
    this.config = resolveConfig(config);
    this.store = options.store ?? new MemoryRequestStore();
    this.recordStore = options.recordStore ?? new MemoryRecordStore();
    const transport = new Transport(this.config.orchestratorUrl, options.fetch ?? globalThis.fetch.bind(globalThis), this.config.timeoutMs);
    this.core = new ClientCore(this.config, transport);
    this.executor = new Executor(this.core, this.store, this.recordStore);
    this.tip = new TipClient(this.core);
    this.registry = new RegistryClient(this.core);
  }

  // ---- node keys and answers (core.ts) ----

  nodes(): Promise<NodesResponse> {
    return this.core.nodes();
  }
  checkNodes(): Promise<void> {
    return this.core.checkNodes();
  }
  checkResponse(circuit: string, requestId: string, response: ExecuteResponse, namespace?: FieldLike, stateKeys?: StateKeys): Promise<ExecuteResponse> {
    return this.core.checkResponse(circuit, requestId, response, namespace, stateKeys);
  }

  // ---- the sidecar path (execute.ts) ----

  buildRequest(input: BuildRequestInput): Promise<PreparedRequest> {
    return this.executor.buildRequest(input);
  }
  execute(prepared: PreparedRequest): Promise<ExecuteOutcome> {
    return this.executor.execute(prepared);
  }
  checkBeforeSend(requestId: string, json: string): Promise<ExecuteRequest> {
    return this.executor.checkBeforeSend(requestId, json);
  }
  resend(requestId: string): Promise<ExecuteOutcome> {
    return this.executor.resend(requestId);
  }
  discard(requestId: string): Promise<void> {
    return this.executor.discard(requestId);
  }
  fetch(requestId: string, options?: FetchOptions): Promise<ExecuteResponse> {
    return this.executor.fetch(requestId, options);
  }

  // ---- the tip (tip-client.ts) ----

  tipRequest(input: TipRequestOptions): Promise<TipRequest> {
    return this.tip.tipRequest(input);
  }
  obtainIntake(ask: IntakeAsk): Promise<RequestIntake> {
    return this.tip.obtainIntake(ask);
  }
  requestIntake<R>(target: IntakeTarget<R>, request: IntakeRequest, sendOptions: IntakeSendOptions, options?: RequestIntakeOptions): Promise<RequestedIntake<R>> {
    return this.tip.requestIntake(target, request, sendOptions, options);
  }
  fetchChainResult(chainRequestId: FieldLike, options?: ChainFetchOptions): Promise<QueuedResult> {
    return this.tip.fetchChainResult(chainRequestId, options);
  }
  fetchInitResult(options: InitFetchOptions): Promise<InitResult> {
    return this.tip.fetchInitResult(options);
  }
  /** The result reader of a configured tip circuit (result.ts). */
  resultReader(circuit: string): ResultReader {
    return this.core.resultReader(circuit);
  }

  // ---- the registry (registry.ts) ----

  getPackage(namespace: FieldLike, name: string): Promise<PackageResponse> {
    return this.registry.getPackage(namespace, name);
  }
  getNamespace(namespace: FieldLike): Promise<NamespaceResponse | undefined> {
    return this.registry.getNamespace(namespace);
  }
  nextSeq(namespace?: FieldLike): Promise<number> {
    return this.registry.nextSeq(namespace);
  }
  lastSeq(namespace?: FieldLike): number | undefined {
    return this.registry.lastSeq(namespace);
  }
  getContractManifest(namespace: FieldLike): Promise<ContractManifestResponse> {
    return this.registry.getContractManifest(namespace);
  }
  getManifestVersion(namespace: FieldLike, manifestHash: FieldLike): Promise<ContractManifestResponse> {
    return this.registry.getManifestVersion(namespace, manifestHash);
  }
  /** Take the vk hashes of contract manifest version `m` for every package
   * it names (upgrades.ts): after an upgrade of the app's circuits took
   * effect, requests bind and results are checked under the new circuits,
   * and receipt requests name the version. `m` must be the version the
   * contract's pins name: read them (readCircuitPins), fetch that version
   * by its hash (getManifestVersion, which checks the hash) and adopt it.
   * Nothing here ties `m` to the chain: a manifest the orchestrator alone
   * vouches for (getContractManifest) may name vk hashes the contract does
   * not hold, and every result is then checked under those. */
  async adoptManifest(m: ContractManifest): Promise<void> {
    this.core.adoptVkHashes(fieldHex((await contractManifestHash(m)).toBigInt()), vkHashesOf(m));
  }
  manifestBody(input: ManifestBodyInput): Promise<ManifestBody> {
    return this.registry.manifestBody(input);
  }
  register(body: ManifestMessage, options?: RegisterOptions): Promise<ManifestResponse> {
    return this.registry.register(body, options);
  }
  registerManifest(input: ManifestBodyInput, owner: SchnorrSigner, options?: RegisterOptions): Promise<ManifestResponse> {
    return this.registry.registerManifest(input, owner, options);
  }
  disable(namespace: FieldLike, circuit: string, owner: SchnorrSigner, seq?: number): Promise<DisableResponse> {
    return this.registry.disable(namespace, circuit, owner, seq);
  }
  sendDisable(body: DisableRequest): Promise<DisableResponse> {
    return this.registry.sendDisable(body);
  }
}
