// The manifest (docs/manifest.schema.json) as a typed view: one schema for
// both paths, `intake` selecting the path. `direct` (the default) is the
// sidecar path; `onchain` (on-chain intake) and `receipt` (receipt intake),
// the non-secret-shared intakes, and `shared_receipt` (secret-shared receipt intake) and
// `shared_onchain` (secret-shared on-chain intake), the secret-shared intakes, queue the
// request at the tip. parseManifest applies the schema's defaults
// to fields left out (a field given as null is refused, as the machine and
// the schema refuse it) and refuses what is structurally wrong; the full check, against the
// circuit's ABI and across fields, is the machine's at REGISTER.

import { fieldHex, type FieldHexString, type FieldLike } from "./field.ts";

/** The path a manifest's requests take. */
export type ManifestIntake = "direct" | "onchain" | "receipt" | "shared_receipt" | "shared_onchain";
/** The intakes that queue a request at the tip. */
export type QueuedIntake = Exclude<ManifestIntake, "direct">;
/** The secret-shared intakes: their requests take INPUT_SHARED app inputs and the
 * reserved shared values, and their chain request id commits to the inputs
 * commitment C. */
export type SharedIntake = "shared_receipt" | "shared_onchain";

/** The reserved manifest name of the request's partial note under
 * partial-note delivery (`outcome: partial`): an INPUT_SHARED value under a
 * secret-shared intake, a PUBLIC operand under a non-secret-shared one. The
 * caller passes it in `inputs` like an app input (partialCommitment over the
 * owner and the `rho` SecretStore derives); the app's request function
 * recomputes it from the same preimage. */
export const PARTIAL_NOTE_NAME = "$partial_note";

const INTAKES: readonly ManifestIntake[] = ["direct", "onchain", "receipt", "shared_receipt", "shared_onchain"];

/** Whether a queued intake is a secret-shared one (isSharedIntake("receipt") is false). */
export function isSharedIntake(intake: QueuedIntake): intake is SharedIntake {
  return intake === "shared_receipt" || intake === "shared_onchain";
}

/** Whether any of `manifests` encodes its requests under the node enc keys
 * the app contract stores (secret-shared on-chain intake), so the contract
 * has `storage.shared_onchain`. */
export function usesStoredEncKeys(manifests: Iterable<Manifest>): boolean {
  for (const m of manifests) if (m.intake === "shared_onchain") return true;
  return false;
}
/** Who holds a key's state: the requester (`client`, intake direct only), the
 * nodes (`node`) or the chain (`chain`, queued intakes only). */
export type StateHolder = "client" | "node" | "chain";

/** A witness entry: the ABI parameter and its source (`PUBLIC`, `SAMPLE`,
 * `LOAD` with `slice` and `len`, or `INPUT_SHARED`), as written. */
export interface WitnessEntry {
  param: string;
  from: Readonly<Record<string, unknown>>;
}

/** An output: the TACEO store it comes from, the key it is stored under, its
 * length and the return-value path of its note hash. */
export interface ManifestOutput {
  TACEO_store: string;
  STORE: string;
  len: number;
  note_hash: string;
}

/** When a pinned value read earlier still lets a result land
 * (docs/ARCHITECTURE.md section 6, "Pinned reads"): `exact` the value
 * itself, `epoch` the source's current epoch or the one before it,
 * `tolerance` a value within `band` of the current one. */
export type Freshness = "exact" | "epoch" | "tolerance";

/** A tolerance read's band: an absolute amount (a u128) or basis points of
 * the current value (1 to 10,000). */
export type Band = { absolute: bigint } | { relativeBps: number };

/** A pinned public read: the contract, its function and arguments, the
 * public parameter its value fills, and its freshness policy (`epochParam`,
 * the parameter its epoch fills, under `epoch` only; `band` under
 * `tolerance` only). */
export interface PublicRead {
  /** The called contract: a field element, or {@link SELF_CONTRACT} for the
   * namespace's own contract ({@link readContract} resolves it). */
  contract: string;
  function: string;
  args: string[];
  param: string;
  freshness: Freshness;
  epochParam?: string;
  band?: Band;
}

/** A pinned read's `contract` that names the namespace's own contract. The
 * address depends on the contract manifest's hash, so the manifest never
 * holds it; the machine and this client put in the namespace. */
export const SELF_CONTRACT = "$self";

/** The address a pinned read calls: `namespace` for {@link SELF_CONTRACT},
 * else the read's own contract. */
export function readContract(r: PublicRead, namespace: FieldLike): FieldHexString {
  return r.contract === SELF_CONTRACT ? fieldHex(namespace, "namespace") : fieldHex(r.contract, "public read contract");
}

/** The public parameters a read fills, in public-input order: its value's,
 * then an epoch read's epoch's. */
export function publicReadParams(r: PublicRead): string[] {
  return r.epochParam === undefined ? [r.param] : [r.param, r.epochParam];
}

const FRESHNESS: readonly Freshness[] = ["exact", "epoch", "tolerance"];
const U128_MAX = (1n << 128n) - 1n;

// One `public_reads` entry, with the freshness fields its policy takes and
// no other policy's (as sidecar-core's Manifest::validate refuses them).
function publicRead(r: unknown, q: number): PublicRead {
  const at = `manifest.public_reads[${q}]`;
  const e = obj(r, at);
  const read: PublicRead = {
    contract: readContractField(e.contract, `${at}.contract`),
    function: str(e.function, `${at}.function`),
    args: list(e.args, `${at}.args`).map((a, i) => str(a, `${at}.args[${i}]`)),
    param: str(e.param, `${at}.param`),
    freshness: "exact",
  };
  const freshness = e.freshness === undefined ? "exact" : e.freshness;
  if (!FRESHNESS.includes(freshness as Freshness)) {
    throw new RangeError(`${at}.freshness: expected ${FRESHNESS.join(", ")}`);
  }
  read.freshness = freshness as Freshness;
  if (e.epoch_param !== undefined && read.freshness !== "epoch") {
    throw new RangeError(`${at}.epoch_param: only under freshness epoch, not ${read.freshness}`);
  }
  if (e.band !== undefined && read.freshness !== "tolerance") {
    throw new RangeError(`${at}.band: only under freshness tolerance, not ${read.freshness}`);
  }
  if (read.freshness === "epoch") {
    if (e.epoch_param === undefined) throw new RangeError(`${at}.epoch_param: missing: an epoch read names the parameter its epoch fills`);
    read.epochParam = str(e.epoch_param, `${at}.epoch_param`);
    if (read.epochParam === read.param) throw new RangeError(`${at}.epoch_param: \`${read.param}\` is filled by two reads`);
  }
  if (read.freshness === "tolerance") {
    if (e.band === undefined) throw new RangeError(`${at}.band: missing: a tolerance read needs a band (absolute or relative_bps)`);
    read.band = band(e.band, `${at}.band`);
  }
  return read;
}

// A read's `contract`: `$self` or a field element, kept as written.
function readContractField(v: unknown, at: string): string {
  const text = str(v, at);
  if (text !== SELF_CONTRACT) fieldHex(text, at);
  return text;
}

function band(v: unknown, at: string): Band {
  const b = obj(v, at);
  const keys = Object.keys(b);
  if (keys.length !== 1 || (keys[0] !== "absolute" && keys[0] !== "relative_bps")) {
    throw new RangeError(`${at}: expected exactly one of absolute or relative_bps`);
  }
  if (keys[0] === "absolute") {
    const text = b.absolute;
    if (typeof text !== "string" || !/^[0-9]+$/.test(text)) throw new RangeError(`${at}.absolute: not a decimal integer string`);
    const absolute = BigInt(text);
    if (absolute > U128_MAX) throw new RangeError(`${at}.absolute: does not fit 128 bits`);
    if (absolute === 0n) throw new RangeError(`${at}.absolute: 0 is no band; use freshness exact`);
    return { absolute };
  }
  const bps = b.relative_bps;
  if (typeof bps !== "number" || !Number.isInteger(bps) || bps < 1 || bps > 10_000) {
    throw new RangeError(`${at}.relative_bps: expected an integer in 1 ..= 10000 basis points`);
  }
  return { relativeBps: bps };
}

interface ManifestCommon {
  circuit: string;
  namespaceParam: string;
  stateKeys: { reads: number; writes: number };
  witness: WitnessEntry[];
  outputs: ManifestOutput[];
  /** The listed state holders; stateOf applies the `node` default. */
  state: Readonly<Record<string, StateHolder>>;
  publicReads: PublicRead[];
}

/** A manifest of the sidecar path (`intake: direct`). */
export interface DirectManifest extends ManifestCommon {
  intake: "direct";
  /** The keys whose state a round spends; `policy` defaults to once. */
  consume: { key: string; policy: "once" | "never" }[];
}

/** A manifest of a tip circuit (a queued intake). */
export interface QueuedManifest extends ManifestCommon {
  intake: QueuedIntake;
  binding: "turn" | "exact";
  /** Per loaded key, the public output carrying its old commitment. */
  commitmentSlot: Readonly<Record<string, { old: string }>>;
  /** How the round's value reaches the user: `partial` by default, `none`
   * written out (a non-secret-shared round that completes no note). */
  outcome: OutcomeForm;
  /** The layout of each tree-valued node-held key, declared once: under the
   * key reference that loads it, or under the one that stores it when the
   * round creates the tree ({@link treeOf} resolves a stored-back reference). */
  tree: Readonly<Record<string, TreeLayout>>;
}

// ---- tree-valued keys ------------------------------------------------------

/** The most a tree's depth may be (REGISTER's bound). */
export const MAX_TREE_DEPTH = 32;

/** The parameters a loaded tree key's slots fill: the touched leaves (by
 * LOAD of the key), and their old hashes, siblings and effective indices (by
 * PUBLIC request names the scheduler fills from the nodes' clear trees). */
export interface TreeParams {
  leaves: string;
  oldHashes: string;
  siblings: string;
  /** The effective indices the nodes place (`access: clear`); absent under
   * `access: oblivious`, where the circuit takes the index inputs. */
  indices?: string;
}

/** How a tree's nodes reach its leaves (docs/ARCHITECTURE.md section 6, "The oblivious tree"):
 * `clear` (the default), or `oblivious` (the index inputs are shared, the
 * leaves and hashes live in a distributed oblivious RAM, the paths reach the
 * circuit as LOAD slices and no leaf hash is output). */
export type TreeAccess = "clear" | "oblivious";

/** The widest window a round may read (REGISTER's bound, sidecar-core's
 * `MAX_TREE_WINDOW`). */
export const MAX_TREE_WINDOW = 8;

/** A window of `width` consecutive leaves a round reads after its slots and
 * never writes (docs/ARCHITECTURE.md section 6, "A read-only window on a
 * tree key"), from the leaf the app input `start` names:
 * its leaves (by LOAD of the key after the slots), their old hashes and the
 * window root's siblings (by PUBLIC request names the scheduler fills). */
export interface TreeWindow {
  width: number;
  start: string;
  params: { leaves: string; oldHashes: string; siblings: string };
}

/** The layout of a tree-valued key, declared once
 * (docs/ARCHITECTURE.md section 6, "Tree-valued keys"): a binary Poseidon2
 * Merkle tree of `depth` whose leaves are `leafLen` fields, of which a round
 * touches `probe` (the header, then one slot per `index` input; `count`
 * says how many index inputs the round uses, `open` is the index input whose
 * 0 opens the leaf the scheduler assigns as `$new_leaf`). Under the
 * reference the round loads: `params`, and when the round stores the tree
 * back, `store` (the `$state_keys.writes[j]` reference it is stored at, which takes
 * this layout) with `newHashes` (the public output of the new leaf hashes).
 * Under the reference that stores a tree the round creates: `newHashes`. */
export interface TreeLayout {
  depth: number;
  leafLen: number;
  probe: number;
  header: boolean;
  access: TreeAccess;
  index: string[];
  count?: string;
  open?: string;
  params?: TreeParams;
  store?: string;
  newHashes?: string;
  /** `access: oblivious` with `open`: the public output of the header's
   * append index after the round. */
  nextIndex?: string;
  window?: TreeWindow;
  /** `access: oblivious`: the tree is a sparse keyed map
   * (docs/ARCHITECTURE.md section 6, "The keyed map's manifest entry and
   * REGISTER"): each index input is a key whose low `depth` bits are its leaf's
   * path; depth 32 to 120, no header, open, next_index or window. */
  keyed: boolean;
  /** `keyed`: log2 of the distinct DORAM addresses the map may hold. */
  capacity?: number;
}

/** The shallowest and the deepest keyed map (sidecar-oblivious's
 * `MIN_MAP_DEPTH` and `MAX_MAP_DEPTH`, machine/sidecar-oblivious/src/layout.rs). */
export const MIN_MAP_DEPTH = 32;
export const MAX_MAP_DEPTH = 120;

/** The layout of the tree-valued key reference `key`, or undefined for a
 * flat one: its own entry, or for a reference a loaded tree is stored back
 * at, the loaded entry whose `store` names it (sidecar-core's
 * `Manifest::tree_of`). */
export function treeOf(m: QueuedManifest, key: string): TreeLayout | undefined {
  return Object.hasOwn(m.tree, key) ? m.tree[key] : Object.values(m.tree).find((t) => t.store === key);
}

/** The parameters the scheduler fills from the nodes' trees (every loaded
 * tree's old hashes, siblings and indices, and a window's old hashes and
 * siblings): request public names that are not app inputs, as sidecar-core's
 * `Manifest::tree_params`. */
export function treeParams(m: QueuedManifest): string[] {
  const trees = Object.values(m.tree);
  // under access: oblivious the parameters are LOAD slices, not names the scheduler fills
  const clear = trees.filter((t) => t.access === "clear");
  const slots = clear.flatMap((t) => (t.params === undefined ? [] : [t.params.oldHashes, t.params.siblings, ...(t.params.indices === undefined ? [] : [t.params.indices])]));
  const windows = clear.flatMap((t) => (t.window === undefined ? [] : [t.window.params.oldHashes, t.window.params.siblings]));
  return [...slots, ...windows];
}

const LOADED_REF = /^\$state_keys\.reads\[(0|[1-9][0-9]*)\]$/;
const STORED_REF = /^\$state_keys\.writes\[(0|[1-9][0-9]*)\]$/;

// One `tree` entry, structurally, under a loaded or a stored key reference
// (sidecar-core's Manifest::validate makes the cross-field checks: the keys,
// the LOAD and output lengths, `$new_leaf` exactly when a tree opens leaves).
function treeLayout(v: unknown, at: string, loaded: boolean): TreeLayout {
  const e = obj(v, at);
  for (const k of Object.keys(e)) {
    if (!["depth", "leaf_len", "probe", "header", "access", "keyed", "capacity", "index", "count", "open", "params", "store", "new_hashes", "next_index", "window"].includes(k)) {
      throw new RangeError(`${at}.${k}: not a field of a tree layout`);
    }
  }
  const keyed = e.keyed === undefined ? false : e.keyed;
  if (typeof keyed !== "boolean") throw new RangeError(`${at}.keyed: not a boolean`);
  const depth = count(e.depth, `${at}.depth`);
  if (keyed) {
    if (depth < MIN_MAP_DEPTH || depth > MAX_MAP_DEPTH) throw new RangeError(`${at}.depth: ${depth} is not in ${MIN_MAP_DEPTH} ..= ${MAX_MAP_DEPTH} (a keyed map)`);
  } else if (depth < 1 || depth > MAX_TREE_DEPTH) {
    throw new RangeError(`${at}.depth: ${depth} is not in 1 ..= ${MAX_TREE_DEPTH}`);
  }
  const leafLen = count(e.leaf_len, `${at}.leaf_len`);
  if (leafLen < 1) throw new RangeError(`${at}.leaf_len: a leaf has at least 1 element`);
  if (keyed && leafLen < 3) throw new RangeError(`${at}.leaf_len: a keyed map's leaf holds the key, a value and the blinding: at least 3 elements`);
  const header = e.header === undefined ? false : e.header;
  if (typeof header !== "boolean") throw new RangeError(`${at}.header: not a boolean`);
  const index = list(e.index === undefined ? [] : e.index, `${at}.index`).map((n, k) => str(n, `${at}.index[${k}]`));
  if (new Set(index).size !== index.length) throw new RangeError(`${at}.index: an input is listed twice`);
  const probe = count(e.probe, `${at}.probe`);
  const slots = (header ? 1 : 0) + index.length;
  // a keyed map a round creates has no key input: its one slot is the unused
  // path 0, which the creating round leaves empty (sidecar-core's rule)
  const createdMap = keyed && !loaded && index.length === 0;
  if (createdMap && probe !== 1) throw new RangeError(`${at}.probe: ${probe} is not 1: a keyed map is created with one unused slot`);
  if (!createdMap && (probe !== slots || slots === 0)) {
    throw new RangeError(`${at}.probe: ${probe} is not the header plus one slot per index input (${slots}, at least 1)`);
  }
  const access = e.access === undefined ? "clear" : e.access;
  if (access !== "clear" && access !== "oblivious") throw new RangeError(`${at}.access: not clear or oblivious`);
  if (keyed && access !== "oblivious") throw new RangeError(`${at}.keyed: a keyed map is access: oblivious`);
  if (keyed && header) throw new RangeError(`${at}.header: a keyed map has no header`);
  if (keyed && (e.open !== undefined || e.next_index !== undefined || e.window !== undefined)) {
    throw new RangeError(`${at}: a keyed map has no open, next_index or window`);
  }
  const t: TreeLayout = { depth, leafLen, probe, header, access, keyed, index };
  if (e.capacity !== undefined) {
    if (!keyed) throw new RangeError(`${at}.capacity: only a keyed map has a capacity`);
    t.capacity = count(e.capacity, `${at}.capacity`);
  }
  if (e.count !== undefined) {
    t.count = str(e.count, `${at}.count`);
    if (index.includes(t.count)) throw new RangeError(`${at}.count: \`${t.count}\` is an index input`);
  }
  if (e.open !== undefined) {
    t.open = str(e.open, `${at}.open`);
    // the header leaf keeps the append index a new leaf's position is checked against
    if (!header) throw new RangeError(`${at}.open: a tree that opens leaves has a header (header: true)`);
    // under access: oblivious the opening flag is a public input of its own
    if (access === "clear" && !index.includes(t.open)) throw new RangeError(`${at}.open: \`${t.open}\` is not an index input`);
    if (access === "oblivious" && index.includes(t.open)) throw new RangeError(`${at}.open: \`${t.open}\` is an index input; an oblivious tree's opening flag is a public input of its own`);
  }
  if (e.params !== undefined) {
    const p = obj(e.params, `${at}.params`);
    t.params = {
      leaves: str(p.leaves, `${at}.params.leaves`),
      oldHashes: str(p.old_hashes, `${at}.params.old_hashes`),
      siblings: str(p.siblings, `${at}.params.siblings`),
    };
    if (access === "clear") t.params.indices = str(p.indices, `${at}.params.indices`);
    else if (p.indices !== undefined) throw new RangeError(`${at}.params.indices: an oblivious tree places no indices`);
  }
  if (e.next_index !== undefined) {
    if (access === "clear") throw new RangeError(`${at}.next_index: only under access: oblivious`);
    t.nextIndex = str(e.next_index, `${at}.next_index`);
  }
  if (e.store !== undefined) {
    t.store = str(e.store, `${at}.store`);
    if (!STORED_REF.test(t.store)) throw new RangeError(`${at}.store: \`${t.store}\` is not a $state_keys.writes[j] reference`);
  }
  if (e.new_hashes !== undefined) t.newHashes = str(e.new_hashes, `${at}.new_hashes`);
  if (e.window !== undefined) t.window = treeWindow(e.window, `${at}.window`, t);
  if (access === "oblivious" && t.newHashes !== undefined) {
    throw new RangeError(`${at}.new_hashes: an oblivious tree outputs no leaf hashes`);
  }
  if (loaded) {
    if (t.params === undefined) throw new RangeError(`${at}.params: missing: a loaded tree names its parameters`);
    if (access === "clear" && (t.store === undefined) !== (t.newHashes === undefined)) {
      throw new RangeError(`${at}: a loaded tree the round stores back names both store and new_hashes`);
    }
    if (access === "oblivious" && t.store === undefined) throw new RangeError(`${at}.store: missing: a round on an oblivious tree stores it back`);
  } else {
    if (t.params !== undefined || t.store !== undefined) {
      throw new RangeError(`${at}: params and store only under the key reference that loads the tree`);
    }
    if (t.window !== undefined) throw new RangeError(`${at}.window: only under the key reference that loads the tree`);
    if (access === "clear" && t.newHashes === undefined) throw new RangeError(`${at}.new_hashes: missing: a created tree names the output of its new leaf hashes`);
  }
  return t;
}

// A tree entry's window, structurally: a power-of-two width within
// MAX_TREE_WINDOW and 2^depth, a start input other than the index and count
// inputs, and its three parameters (sidecar-core's validate_window checks
// them against the witness).
function treeWindow(v: unknown, at: string, t: TreeLayout): TreeWindow {
  const e = obj(v, at);
  for (const k of Object.keys(e)) {
    if (!["width", "start", "params"].includes(k)) throw new RangeError(`${at}.${k}: not a field of a tree window`);
  }
  const width = count(e.width, `${at}.width`);
  if (width < 1 || width > MAX_TREE_WINDOW || (width & (width - 1)) !== 0 || Math.log2(width) > t.depth) {
    throw new RangeError(`${at}.width: ${width} is not a power of two in 1 ..= ${MAX_TREE_WINDOW} (the network's bound) within 2^depth`);
  }
  const start = str(e.start, `${at}.start`);
  if (t.index.includes(start) || t.count === start) throw new RangeError(`${at}.start: \`${start}\` is an index or count input`);
  const p = obj(e.params, `${at}.params`);
  for (const k of Object.keys(p)) {
    if (!["leaves", "old_hashes", "siblings"].includes(k)) throw new RangeError(`${at}.params.${k}: not a parameter of a tree window`);
  }
  const params = {
    leaves: str(p.leaves, `${at}.params.leaves`),
    oldHashes: str(p.old_hashes, `${at}.params.old_hashes`),
    siblings: str(p.siblings, `${at}.params.siblings`),
  };
  return { width, start, params };
}

/** Whether a PUBLIC source takes the reserved operand `$new_leaf` (the append
 * index of a tree that opens leaves, which the scheduler assigns). */
function takesNewLeaf(from: Readonly<Record<string, unknown>>): boolean {
  return from.PUBLIC === "$new_leaf";
}

export type Manifest = DirectManifest | QueuedManifest;

/** Whether the manifest queues its requests at the tip (any intake but direct). */
export function isQueued(m: Manifest): m is QueuedManifest {
  return m.intake !== "direct";
}

/** The state holder of `key`: as listed in `state`, otherwise `node`. */
export function stateOf(m: Manifest, key: string): StateHolder {
  return Object.hasOwn(m.state, key) ? m.state[key]! : "node";
}

const DIRECT_ONLY = ["consume"] as const;
const QUEUED_ONLY = ["binding", "commitment_slot", "tree"] as const;

/** The typed view of a manifest JSON, with the schema's defaults applied.
 * RangeError when it is not an object, `manifest` is not 1, the intake is
 * unknown, a field of the other path is present, a state value is one the
 * path does not allow, or a field has the wrong shape. */
export function parseManifest(manifest: unknown): Manifest {
  const m = obj(manifest, "manifest");
  if (m.manifest !== 1) throw new RangeError("manifest.manifest: expected 1, the schema version");
  const intake = m.intake === undefined ? "direct" : m.intake;
  if (!INTAKES.includes(intake as ManifestIntake)) {
    throw new RangeError(`manifest.intake: expected ${INTAKES.join(", ")}`);
  }
  const queued = intake !== "direct";
  const outcome = outcomeForm(m, intake as ManifestIntake);
  for (const f of queued ? DIRECT_ONLY : QUEUED_ONLY) {
    if (Object.hasOwn(m, f)) {
      throw new RangeError(`manifest.${f}: ${queued ? "intake direct only" : `a queued intake (${INTAKES.slice(1).join(", ")}) only`}; this manifest takes intake ${intake}`);
    }
  }

  const stateKeys = obj(m.state_keys, "manifest.state_keys");
  const common: ManifestCommon = {
    circuit: str(m.circuit, "manifest.circuit"),
    namespaceParam: str(m.namespace_param, "manifest.namespace_param"),
    stateKeys: { reads: count(stateKeys.reads, "manifest.state_keys.reads"), writes: count(stateKeys.writes, "manifest.state_keys.writes") },
    witness: list(m.witness, "manifest.witness").map((w, k) => {
      const e = w as { param?: unknown; from?: unknown } | null;
      if (typeof e?.param !== "string" || typeof e.from !== "object" || e.from === null || Array.isArray(e.from)) {
        throw new RangeError(`manifest.witness[${k}]: expected {param, from}`);
      }
      const pub = (e.from as Record<string, unknown>).PUBLIC;
      if (pub === "$user" || (Array.isArray(pub) && pub.includes("$user"))) {
        throw new RangeError(
          `manifest.witness[${k}].from.PUBLIC: \`$user\` is refused under every intake: no request names its requester (the hidden requester)`,
        );
      }
      return { param: e.param, from: e.from as Record<string, unknown> };
    }),
    outputs: list(m.outputs, "manifest.outputs").map((o, k) => {
      const at = `manifest.outputs[${k}]`;
      const e = obj(o, at);
      return {
        TACEO_store: str(e.TACEO_store, `${at}.TACEO_store`),
        STORE: str(e.STORE, `${at}.STORE`),
        len: count(e.len, `${at}.len`),
        note_hash: str(e.note_hash, `${at}.note_hash`),
      };
    }),
    state: {},
    publicReads: list(m.public_reads === undefined ? [] : m.public_reads, "manifest.public_reads").map(publicRead),
  };
  const allowed: readonly StateHolder[] = queued ? ["node", "chain"] : ["client", "node"];
  const state: Record<string, StateHolder> = {};
  for (const [key, v] of Object.entries(obj(m.state === undefined ? {} : m.state, "manifest.state"))) {
    if (!allowed.includes(v as StateHolder)) {
      throw new RangeError(`manifest.state.${key}: expected ${allowed.join(" or ")} under intake ${intake}`);
    }
    state[key] = v as StateHolder;
  }
  common.state = state;

  if (!queued) {
    const consume = list(m.consume === undefined ? [] : m.consume, "manifest.consume").map((c, k) => {
      const at = `manifest.consume[${k}]`;
      const e = obj(c, at);
      const policy = e.policy === undefined ? "once" : e.policy;
      if (policy !== "once" && policy !== "never") throw new RangeError(`${at}.policy: expected once or never`);
      return { key: str(e.key, `${at}.key`), policy: policy as "once" | "never" };
    });
    return { ...common, intake: "direct", consume };
  }
  const binding = m.binding === undefined ? "turn" : m.binding;
  if (binding !== "turn" && binding !== "exact") throw new RangeError("manifest.binding: expected turn or exact");
  const commitmentSlot: Record<string, { old: string }> = {};
  for (const [key, v] of Object.entries(obj(m.commitment_slot === undefined ? {} : m.commitment_slot, "manifest.commitment_slot"))) {
    commitmentSlot[key] = { old: str((v as { old?: unknown } | null)?.old, `manifest.commitment_slot.${key}.old`) };
  }
  const tree: Record<string, TreeLayout> = {};
  const nodeHeld = (key: string) => (Object.hasOwn(state, key) ? state[key] : "node") === "node";
  for (const [key, v] of Object.entries(obj(m.tree === undefined ? {} : m.tree, "manifest.tree"))) {
    const loaded = LOADED_REF.test(key);
    if (!loaded && !STORED_REF.test(key)) throw new RangeError(`manifest.tree.${key}: not a $state_keys.reads[i] or $state_keys.writes[j] reference`);
    tree[key] = treeLayout(v, `manifest.tree.${key}`, loaded);
    if (!nodeHeld(key)) throw new RangeError(`manifest.tree.${key}: a tree-valued key is node-held`);
  }
  const stores = Object.entries(tree).flatMap(([key, t]) => (t.store === undefined ? [] : [[key, t.store] as const]));
  for (const [key, store] of stores) {
    if (Object.hasOwn(tree, store) || stores.filter(([, s]) => s === store).length > 1) {
      throw new RangeError(`manifest.tree.${key}.store: the tree stored at ${store} is declared twice; declare it once`);
    }
    if (!nodeHeld(store)) throw new RangeError(`manifest.tree.${key}.store: a tree-valued key is node-held`);
  }
  const loads = Object.keys(tree).filter((k) => LOADED_REF.test(k)).length;
  const creates = Object.keys(tree).length - loads;
  if (loads > 0 && (creates > 0 || (stores.length > 0 && stores.length !== loads))) {
    throw new RangeError(
      `manifest.tree: the round loads ${loads} tree key(s), stores ${stores.length} of them back and creates ${creates}; a round that loads and stores tree-valued keys stores each tree it loads (\`store\`) and creates none`,
    );
  }
  const opens = Object.values(tree).some((t) => t.open !== undefined);
  const newLeaf = common.witness.some((w) => takesNewLeaf(w.from));
  if (opens !== newLeaf) {
    throw new RangeError(
      opens
        ? "manifest.tree: a tree opens leaves (`open`), and no parameter takes `$new_leaf`"
        : "manifest.witness: `$new_leaf` is used, and no tree opens leaves (`open`)",
    );
  }
  checkPartialNotes(common.witness, intake as QueuedIntake, outcome);
  return { ...common, intake: intake as QueuedIntake, binding, commitmentSlot, tree, outcome };
}

// ---- the outcome form ----

/** How a round's value reaches the user (the value delivery axis):
 * `partial`, the request commits a partial note (`$partial_note`) that the
 * round completes, inside the co-SNARK for a private result or in the app's
 * `apply` for a public one (the default under every queued intake); `none`,
 * the round completes no note and its public outputs go to the app's hook
 * (non-secret-shared intakes only, written out: an init round, a test
 * counter). */
export type OutcomeForm = "partial" | "none";

/** The outcome form of a manifest JSON with the checks REGISTER makes
 * without the ABI (sidecar-core manifest.rs): `outcome` only under a queued
 * intake, `partial` by default, `none` under a non-secret-shared intake
 * only; `call_values` is not a manifest field. */
function outcomeForm(m: Record<string, unknown>, intake: ManifestIntake): OutcomeForm {
  if (Object.hasOwn(m, "outcome") && intake === "direct") {
    throw new RangeError("manifest.outcome: only with a queued intake; this manifest takes intake direct");
  }
  if (Object.hasOwn(m, "call_values")) throw new RangeError("manifest.call_values: not a manifest field; a round's value reaches the user through its partial note (`outcome: partial`)");
  const shared = intake !== "direct" && isSharedIntake(intake);
  const outcome = m.outcome === undefined ? "partial" : m.outcome;
  const allowed: readonly OutcomeForm[] = shared ? ["partial"] : ["partial", "none"];
  if (!allowed.includes(outcome as OutcomeForm)) {
    throw new RangeError(`manifest.outcome: expected ${allowed.join(" or ")} under intake ${intake}`);
  }
  return outcome as OutcomeForm;
}

/** The partial note's rules that need only the manifest (sidecar-core
 * manifest.rs validate_partial): under `outcome: partial` a
 * non-secret-shared round fills a parameter with PUBLIC `$partial_note`
 * (a secret-shared one shares it, which intakeLayout and the secret-shared
 * intakes check); under `none` no parameter takes a partial note. */
function checkPartialNotes(witness: readonly { param: string; from: Readonly<Record<string, unknown>> }[], intake: QueuedIntake, outcome: OutcomeForm): void {
  const operands = (from: Readonly<Record<string, unknown>>) => [from.PUBLIC, from.INPUT_SHARED].flatMap((v) => (Array.isArray(v) ? v : [v]));
  if (outcome === "none") {
    const k = witness.findIndex((w) => operands(w.from).some((op) => op === PARTIAL_NOTE_NAME));
    if (k >= 0) throw new RangeError(`manifest.witness[${k}]: a partial note belongs to \`outcome: partial\`; this manifest takes \`outcome: none\``);
    return;
  }
  if (isSharedIntake(intake)) return;
  const clear = witness.filter((w) => (Array.isArray(w.from.PUBLIC) ? w.from.PUBLIC : [w.from.PUBLIC]).includes(PARTIAL_NOTE_NAME));
  if (clear.length === 0) {
    throw new RangeError(
      `manifest.witness: intake ${intake}: no parameter takes PUBLIC \`$partial_note\` (\`outcome: partial\`, the default, completes the request's partial note; a round that completes none says \`"outcome": "none"\`)`,
    );
  }
}

function obj(v: unknown, at: string): Record<string, unknown> {
  if (typeof v !== "object" || v === null || Array.isArray(v)) throw new RangeError(`${at}: not an object`);
  return v as Record<string, unknown>;
}

function list(v: unknown, at: string): unknown[] {
  if (!Array.isArray(v)) throw new RangeError(`${at}: missing`);
  return v;
}

function str(v: unknown, at: string): string {
  if (typeof v !== "string") throw new RangeError(`${at}: missing`);
  return v;
}

function count(v: unknown, at: string): number {
  if (typeof v !== "number" || !Number.isInteger(v) || v < 0) throw new RangeError(`${at}: not a count`);
  return v;
}
