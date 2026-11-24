// The client's configuration: the deployment's published identity (orchestrator
// URL, the three node keys, the vk hashes the contract pins, the contract
// address), the registered circuits' note-hash layout, and the transport knobs.

import type { DescriptorPackage } from "./contract-manifest.ts";
import type { KeyEpochNode } from "./key-epoch.ts";
import { abiOf, outputNoteHashIndices } from "./abi.ts";
import { ConfigError } from "./errors.ts";
import { fieldHex, u32, type FieldLike } from "./field.ts";
import { intakeModule } from "./intake.ts";
import { isQueued, parseManifest, type Manifest } from "./manifest.ts";
import type { ResultReader } from "./result.ts";
import { intakeLayout, type IntakeLayout } from "./tip.ts";
import { initResultLayout, type InitResultLayout } from "./init-result.ts";
import type { NodeKeys, Triple } from "./wire.ts";
import { NODES } from "./wire.ts";

/** A point as the caller may give it: coordinates in any FieldLike form. */
export interface PointLike {
  x: FieldLike;
  y: FieldLike;
}

/** One node's two keys as the caller may give them. */
export interface NodeKeysLike {
  enc: PointLike;
  sig: PointLike;
}

/** Bounded retry of POST /v1/fetch after a failed execute call. */
export interface FetchRetry {
  /** How many FETCH calls to make before reporting an unknown outcome. */
  attempts: number;
  /** Delay before the first FETCH; doubled after each attempt. */
  initialDelayMs: number;
  /** Cap on a single delay. */
  maxDelayMs: number;
  /** Timeout of one FETCH call. */
  timeoutMs: number;
}

/** What the client hands a local verifier before a transaction is spent on a proof. */
export interface LocalVerifyInput {
  circuit: string;
  vkHash: string;
  proof: string;
  publicInputs: string[];
}

export interface PssClientConfig {
  /** Base URL of the orchestrator, for example `https://pss.example:3200`. */
  orchestratorUrl: string;
  // Operator knob: DESIGN.md, "Configuration reference" (pss-client
  // allowInsecureHttp). Default false: a plain `http:` orchestratorUrl is
  // refused with ConfigError; true is for local tests only.
  allowInsecureHttp?: boolean;
  // Operator knob: DESIGN.md, "Configuration reference" (pss-client nodeKeys).
  // Each node's `enc` and `sig` keys, node 0 first; checkNodes() refuses any
  // difference from GET /v1/nodes. No default.
  nodeKeys: Triple<NodeKeysLike>;
  // Operator knob: DESIGN.md, "Configuration reference" (pss-client vkHashes).
  // The contract's vk hash per circuit name; an unpinned circuit or another
  // vk_hash is refused before any transaction is built. No default.
  vkHashes: Record<string, FieldLike>;
  // Operator knob: DESIGN.md, "Configuration reference" (pss-client circuits).
  // Per circuit name, the nargo output and manifest sent to REGISTER; the
  // client reads its note-hash indices and state modes from them. No default.
  circuits?: Record<string, CircuitPackage>;
  // Operator knob: DESIGN.md, "Configuration reference" (pss-client
  // staleBlocks). The namespace's stale period, as its registered contract
  // manifest states it (`queue.stale_blocks`; null: a head is never
  // skipped); the relayer skips a stale head by it. Default none: a client
  // of a sidecar-path app, or one that sends no skip().
  staleBlocks?: number | null;
  // Operator knob: DESIGN.md, "Configuration reference" (pss-client
  // manifestHash). Under upgradable circuits (the contract manifest's
  // `upgrades` circuits or contract), the hash of the contract manifest
  // version `vkHashes` are taken from, which every receipt request names
  // (`manifest_hash`); PssClient.adoptManifest moves both to the version
  // the contract's pins name after an upgrade (upgrades.ts). Default none:
  // fixed circuits, whose receipt requests name no version.
  manifestHash?: FieldLike;
  // Operator knob: DESIGN.md, "Configuration reference" (pss-client
  // contractAddress). The namespace of every request. Default none: a
  // client that only REGISTERs a new namespace (deployTip's registry), which
  // names the namespace in each call; a request, FETCH or key read that
  // names none is then refused.
  contractAddress?: FieldLike;
  // Operator knob: DESIGN.md, "Configuration reference" (pss-client
  // timeoutMs). How long one POST /v1/execute may take before the client
  // switches to FETCH; default 120 000 ms.
  timeoutMs?: number;
  // Operator knob: DESIGN.md, "Configuration reference" (pss-client
  // fetchRetry). The FETCH window after a failed execute (recover() in
  // execute.ts); default 6 attempts, 1 s doubling to 16 s, 15 s per call.
  fetchRetry?: Partial<FetchRetry>;
  // Operator knob: DESIGN.md, "Configuration reference" (pss-client
  // verifyProof). An optional check of the returned proof before a
  // transaction is spent on it; throw or resolve false to refuse. Default off.
  verifyProof?: (input: LocalVerifyInput) => Promise<boolean | void>;
  // Operator knob: DESIGN.md, "Configuration reference" (pss-client
  // receiptTtlBlocks). obtainIntake refuses a receipt that expires more than
  // this many blocks after its current_block; default 300, the orchestrator's.
  receiptTtlBlocks?: number;
  // Operator knob: DESIGN.md, "Configuration reference" (pss-client
  // receiptMarginBlocks). TipReceipts.expiresSoon at block b when
  // b + receiptMarginBlocks >= expiry_block; default 20 blocks.
  receiptMarginBlocks?: number;
  // Operator knob: DESIGN.md, "Configuration reference" (pss-client
  // keyEpochNode). An Aztec node to read the app contract's key epoch from
  // (key-epoch.ts): result signatures, receipts and GET /v1/nodes are then
  // checked under the contract's current key set (and, for signatures, the
  // previous one inside its grace window), and envelopes are sealed to its
  // enc keys, so the client follows a node replacement without a new
  // configuration. The node joins the trust base: its storage read decides
  // the key set after a rotation (GET /v1/nodes is compared with it, never
  // trusted), so a lying node can make the client seal to and accept the
  // signatures of keys the contract does not hold. Default none: the pinned
  // nodeKeys, right until a replacement.
  keyEpochNode?: KeyEpochNode;
}

/** A circuit as the app registered it: the nargo output JSON (or its `abi`)
 * and the manifest JSON, both as sent to REGISTER. */
export interface CircuitPackage {
  circuit: unknown;
  manifest: unknown;
  /** Its target package from the deployment's `alias_of`, if given. */
  aliasOf?: string;
}

/** The configuration's `circuits` from an app's compiled circuits and their
 * manifests, both by circuit name (the names its deployment descriptor and
 * buildContractManifest use). ConfigError when a name has one and not the
 * other. The deployment's packages supply the alias targets. */
export function circuitPackages(
  circuits: Record<string, unknown>,
  manifests: Record<string, unknown>,
  packages: readonly Pick<DescriptorPackage, "name" | "alias_of">[] = [],
): Record<string, CircuitPackage> {
  const aliases = new Map(packages.map((p) => [p.name, p.alias_of]));
  const names = Object.keys(circuits);
  for (const name of [...names, ...Object.keys(manifests)]) {
    if (!Object.hasOwn(circuits, name) || !Object.hasOwn(manifests, name)) {
      throw new ConfigError(`circuits.${name}: a compiled circuit and a manifest are both needed, and only one is given`);
    }
  }
  return Object.fromEntries(names.map((name) => {
    const aliasOf = aliases.get(name);
    return [name, { circuit: circuits[name], manifest: manifests[name], ...(aliasOf !== undefined && { aliasOf }) }];
  }));
}

/** The configuration after normalisation: every field element as 0x + 64 hex. */
export interface ResolvedConfig {
  orchestratorUrl: string;
  nodeKeys: Triple<NodeKeys>;
  vkHashes: Record<string, string>;
  /** Per circuit name, the public-input indices of its outputs' note hashes,
   * in manifest order. */
  noteHashIndices: Record<string, number[]>;
  /** Per circuit name, its registered manifest, parsed. */
  manifests: Record<string, Manifest>;
  /** Per tip circuit name (a queued intake), its app inputs and their order (intakeLayout). */
  intakeLayouts: Record<string, IntakeLayout>;
  /** Per tip circuit name, the reader of its results in the form its
   * intake's module names (result.ts: public results under a non-secret-shared intake,
   * private outcomes under a secret-shared one). */
  resultReaders: Record<string, ResultReader>;
  /** Alias packages use their target's result reader and landing function. */
  resultAliases: ReadonlyMap<string, string>;
  /** Each pinned vk hash with a result reader names one landing circuit. */
  landingCircuits: ReadonlyMap<string, string>;
  /** Per tip circuit name whose results are private outcomes: the number
   * of outcome plaintext fields (outcomePlaintextLength), which its outcome
   * log is opened with. */
  plaintextLengths: Record<string, number>;
  /** Per tip circuit name whose results do not follow its form's layout:
   * why. Intake works for it; reading its results is refused with this
   * reason. */
  resultReaderErrors: Record<string, string>;
  /** Per tip circuit name that is an init round (it reads no key and
   * follows init.nr's init layout), where its result's parts sit
   * (initResultLayout). */
  initResultLayouts: Record<string, InitResultLayout>;
  /** Per tip circuit name that reads no key but is no init round: why. */
  initResultLayoutErrors: Record<string, string>;
  contractAddress?: string;
  /** The contract manifest version of `vkHashes` (upgradable circuits). */
  manifestHash?: string;
  /** The namespace's stale period (staleBlocks), undefined when not given. */
  staleBlocks?: number | null;
  timeoutMs: number;
  fetchRetry: FetchRetry;
  verifyProof?: (input: LocalVerifyInput) => Promise<boolean | void>;
  receiptTtlBlocks: number;
  receiptMarginBlocks: number;
  keyEpochNode?: KeyEpochNode;
}

const DEFAULT_TIMEOUT_MS = 120_000;
export const DEFAULT_RECEIPT_TTL_BLOCKS = 300;
const DEFAULT_RECEIPT_MARGIN_BLOCKS = 20;
const DEFAULT_FETCH_RETRY: FetchRetry = {
  attempts: 6,
  initialDelayMs: 1_000,
  maxDelayMs: 16_000,
  timeoutMs: 15_000,
};

function nonNegative(n: unknown, what: string): number {
  if (typeof n !== "number" || !Number.isFinite(n) || n < 0) throw new ConfigError(`${what}: not a non-negative number`);
  return n;
}

// A timeout of 0 would abort every call at once (AbortSignal.timeout(0)).
function positive(n: unknown, what: string): number {
  if (typeof n !== "number" || !Number.isFinite(n) || n <= 0) throw new ConfigError(`${what}: not a positive number`);
  return n;
}

const blocks = (n: unknown, what: string): number => u32(n, what, "block count", ConfigError);

export function landingCircuitsOf(
  vkHashes: Record<string, string>,
  resultReaders: Record<string, ResultReader>,
  aliases: ReadonlyMap<string, string>,
): ReadonlyMap<string, string> {
  for (const [name, target] of aliases) {
    if (!Object.hasOwn(vkHashes, name) || !Object.hasOwn(vkHashes, target) || vkHashes[name] !== vkHashes[target]) {
      throw new ConfigError(`circuits.${name}: alias of ${target} needs the same pinned vk hash`);
    }
  }
  const circuits = new Map<string, string>();
  for (const name of Object.keys(resultReaders)) {
    if (!Object.hasOwn(vkHashes, name)) continue;
    const hash = vkHashes[name]!;
    const other = circuits.get(hash);
    if (other !== undefined) throw new ConfigError(`vkHashes: ${name} and ${other} have result readers for the same vk hash ${hash}`);
    circuits.set(hash, name);
  }
  return circuits;
}

export function resolveConfig(c: PssClientConfig): ResolvedConfig {
  let url: URL;
  try {
    url = new URL(c.orchestratorUrl);
  } catch {
    throw new ConfigError(`orchestratorUrl: \`${c.orchestratorUrl}\` is not a URL`);
  }
  if (url.protocol === "http:") {
    if (c.allowInsecureHttp !== true) {
      throw new ConfigError("orchestratorUrl: plain http is refused; use https, or set allowInsecureHttp for a local test");
    }
  } else if (url.protocol !== "https:") {
    throw new ConfigError(`orchestratorUrl: protocol ${url.protocol} is not https`);
  }
  if (!Array.isArray(c.nodeKeys) || c.nodeKeys.length !== NODES) {
    throw new ConfigError(`nodeKeys: expected ${NODES} keys, node 0 first`);
  }
  const conv = <T>(what: string, f: () => T): T => {
    try {
      return f();
    } catch (e) {
      throw new ConfigError(`${what}: ${(e as Error).message}`);
    }
  };
  const point = (p: PointLike | undefined, what: string) =>
    conv(what, () => {
      if (!p) throw new Error("missing");
      return { x: fieldHex(p.x, "x"), y: fieldHex(p.y, "y") };
    });
  const nodeKeys = c.nodeKeys.map((k, i) => ({
    enc: point(k?.enc, `nodeKeys[${i}].enc`),
    sig: point(k?.sig, `nodeKeys[${i}].sig`),
  })) as Triple<NodeKeys>;
  const vkHashes: Record<string, string> = {};
  for (const [name, h] of Object.entries(c.vkHashes ?? {})) {
    vkHashes[name] = conv(`vkHashes.${name}`, () => fieldHex(h));
  }
  const noteHashes: Record<string, number[]> = {};
  const manifests: Record<string, Manifest> = {};
  const intakeLayouts: Record<string, IntakeLayout> = {};
  const resultReaders: Record<string, ResultReader> = {};
  const resultAliases = new Map<string, string>();
  const resultReaderErrors: Record<string, string> = {};
  const plaintextLengths: Record<string, number> = {};
  const initResultLayouts: Record<string, InitResultLayout> = {};
  const initResultLayoutErrors: Record<string, string> = {};
  for (const [name, pkg] of Object.entries(c.circuits ?? {})) {
    const manifest = conv(`circuits.${name}`, () => parseManifest(structuredClone(pkg?.manifest)));
    noteHashes[name] = conv(`circuits.${name}`, () => outputNoteHashIndices(abiOf(pkg.circuit), manifest.outputs));
    manifests[name] = manifest;
    if (isQueued(manifest)) {
      intakeLayouts[name] = conv(`circuits.${name}`, () => intakeLayout(pkg.circuit, manifest));
      if (pkg.aliasOf !== undefined) {
        resultAliases.set(name, pkg.aliasOf);
      } else {
        try {
          const reader = intakeModule(manifest.intake).results.reader(pkg.circuit, manifest);
          if (reader.plaintextLength !== undefined) plaintextLengths[name] = reader.plaintextLength;
          resultReaders[name] = reader;
        } catch (e) {
          resultReaderErrors[name] = (e as Error).message;
        }
      }
      if (manifest.stateKeys.reads === 0) {
        try {
          initResultLayouts[name] = initResultLayout(pkg.circuit, manifest);
        } catch (e) {
          initResultLayoutErrors[name] = (e as Error).message;
        }
      }
    }
  }
  for (const [name, target] of resultAliases) {
    if (!Object.hasOwn(intakeLayouts, target) || resultAliases.has(target)) {
      throw new ConfigError(`circuits.${name}: alias target ${target} must be a configured tip circuit without an alias target`);
    }
    const length = resultReaders[target]?.plaintextLength;
    if (length !== undefined) plaintextLengths[name] = length;
  }
  const landingCircuits = landingCircuitsOf(vkHashes, resultReaders, resultAliases);
  const r = { ...DEFAULT_FETCH_RETRY, ...(c.fetchRetry ?? {}) };
  if (!Number.isInteger(r.attempts) || r.attempts < 1) throw new ConfigError("fetchRetry.attempts: at least 1");
  return {
    orchestratorUrl: url.toString().replace(/\/+$/, ""),
    nodeKeys,
    vkHashes,
    noteHashIndices: noteHashes,
    manifests,
    intakeLayouts,
    resultReaders,
    resultAliases,
    landingCircuits,
    resultReaderErrors,
    plaintextLengths,
    initResultLayouts,
    initResultLayoutErrors,
    ...(c.contractAddress !== undefined && { contractAddress: conv("contractAddress", () => fieldHex(c.contractAddress!)) }),
    ...(c.manifestHash !== undefined && { manifestHash: conv("manifestHash", () => fieldHex(c.manifestHash!)) }),
    ...(c.staleBlocks !== undefined && { staleBlocks: c.staleBlocks === null ? null : blocks(c.staleBlocks, "staleBlocks") }),
    timeoutMs: positive(c.timeoutMs ?? DEFAULT_TIMEOUT_MS, "timeoutMs"),
    fetchRetry: {
      attempts: r.attempts,
      initialDelayMs: nonNegative(r.initialDelayMs, "fetchRetry.initialDelayMs"),
      maxDelayMs: nonNegative(r.maxDelayMs, "fetchRetry.maxDelayMs"),
      timeoutMs: positive(r.timeoutMs, "fetchRetry.timeoutMs"),
    },
    verifyProof: c.verifyProof,
    keyEpochNode: c.keyEpochNode,
    receiptTtlBlocks: blocks(c.receiptTtlBlocks ?? DEFAULT_RECEIPT_TTL_BLOCKS, "receiptTtlBlocks"),
    receiptMarginBlocks: blocks(c.receiptMarginBlocks ?? DEFAULT_RECEIPT_MARGIN_BLOCKS, "receiptMarginBlocks"),
  };
}
