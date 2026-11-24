// The JSON bodies of the sidecar's HTTP API, mirroring the Rust types of
// machine/sidecar-core (request.rs, response.rs, register.rs) field for field.
// Field elements, the request id among them, are `0x` + 64 lowercase hex
// digits; opaque bytes are `0x` hex. The parsers below check responses as
// strictly as sidecar-core parses requests: unknown fields are refused.

import { ProtocolError } from "./errors.ts";
import { fieldHex, hexBytes, requestIdHex, u32 } from "./field.ts";

/** The number of MPC nodes (Rep3). */
export const NODES = 3;

/** `i` when it is a node index (0, 1 or 2); RangeError otherwise. */
export function nodeIndex(i: number): number {
  if (!Number.isInteger(i) || i < 0 || i >= NODES) throw new RangeError(`node index ${i} out of range`);
  return i;
}

export type Triple<T> = [T, T, T];

/** The longest name checkName admits, in bytes (sidecar-core's MAX_NAME_BYTES). */
export const MAX_NAME_BYTES = 256;

// The names a binding hashes with poseidon2HashBytes (a request or record key,
// a circuit or package name, a shared input name) are 1 to MAX_NAME_BYTES
// bytes of visible ASCII, 0x21 to 0x7E, as sidecar-core's schnorr::check_name
// requires. The hash ignores zero bytes at the end, so `k` and `k\0` would
// bind as one name; with no zero byte a name's hash fixes its bytes. The nodes
// refuse any other name (400); the client refuses it before sending.
/** `name` when it is 1 to MAX_NAME_BYTES bytes of visible ASCII; a RangeError
 * naming `field` and the kind of name (`what`, "key") otherwise. */
export function checkName(field: string, what: string, name: unknown): string {
  if (typeof name !== "string") throw new RangeError(`${field}: expected a ${what}`);
  const bytes = Buffer.from(name, "utf8");
  if (bytes.length === 0) throw new RangeError(`${field}: empty ${what}`);
  if (bytes.length > MAX_NAME_BYTES) throw new RangeError(`${field}: ${what} longer than ${MAX_NAME_BYTES} bytes`);
  const bad = bytes.find((b) => b < 0x21 || b > 0x7e);
  if (bad !== undefined) {
    throw new RangeError(`${field}: ${what} ${JSON.stringify(name)} has byte 0x${bad.toString(16).padStart(2, "0")}; a ${what} is visible ASCII (0x21 to 0x7E)`);
  }
  return name;
}

/** A Grumpkin point in affine coordinates (node keys, ephemeral keys, owner keys). */
export interface GrumpkinPoint {
  x: string;
  y: string;
}

/** One node's INPUT_SHARED ciphertext `{eph, ct[2], tag}`. */
export interface ShareCiphertext {
  eph: GrumpkinPoint;
  ct: [string, string];
  tag: string;
}

/** A secret input: one ciphertext per node and the hashes of all three. */
export interface SharedInput {
  name: string;
  shares: Triple<ShareCiphertext>;
  share_hashes: Triple<string>;
}

/** A client-held state record as a request supplies it: key, note hash, the
 * three sealed thirds and their hashes (recordHash), which stand in for the
 * thirds in the canonical body. */
export interface StateRecord {
  key: string;
  note_hash: string;
  c: Triple<string>;
  record_hashes: Triple<string>;
}

/** A new state record as a round returns it: key, note hash and the three
 * sealed thirds. The client computes `record_hashes` when it presents the
 * record again. */
export interface ResultRecord {
  key: string;
  note_hash: string;
  c: Triple<string>;
}

/** A value of the request's public map: one field element or a list. */
export type PublicValue = string | string[];

export interface StateKeys {
  reads: string[];
  writes: string[];
}

/** `POST /v1/execute`. */
export interface ExecuteRequest {
  namespace: string;
  circuit: string;
  request_id: string;
  public: Record<string, PublicValue>;
  state_keys: StateKeys;
  shared_inputs: SharedInput[];
  records: StateRecord[];
  /** The requester's Grumpkin public key: the owner of the records the
   * request supplies and of those it creates. Required when the request
   * supplies a record, stores a client-held key or carries a shared input. */
  requester?: GrumpkinPoint;
  /** Schnorr signature by `requester` over the canonical body under the
   * EXECUTE domain. Required whenever `requester` is. */
  signature?: Signature;
}

/** The answer to `POST /v1/execute` and `POST /v1/fetch`. */
export interface ExecuteResponse {
  request_id: string;
  vk_hash: string;
  proof: string;
  public_inputs: string[];
  stored: string[];
  records: ResultRecord[];
  /** Node i's Schnorr signature over its result message (result-signatures.ts
   * resultMessage) at index i, node 0's first. The client checks all three
   * before it returns the answer; a contract call passes them on to the tip's
   * `process_result`, which checks them again. */
  signatures: Triple<Signature>;
}

/** One node's two published Grumpkin public keys: `enc` for ECDH (INPUT_SHARED
 * envelopes and state records) and `sig` for Schnorr (receipts, result
 * signatures and registry answers). */
export interface NodeKeys {
  enc: GrumpkinPoint;
  sig: GrumpkinPoint;
}

/** `GET /v1/nodes`: node 0 first. */
export interface NodesResponse {
  nodes: Triple<NodeKeys>;
}

/** A Schnorr signature over Grumpkin (noir-lang/schnorr v0.4.0 encoding):
 * `s` and `e` as `[lo, hi]` 128-bit halves. */
export interface Signature {
  s: [string, string];
  e: [string, string];
}

/** A manifest message (the REGISTER body) before signing: the namespace,
 * its contract manifest, each circuit the manifest names in the stripped
 * form (stripCircuit), by id, and the registry sequence number this body
 * claims: 0 on the first REGISTER of a namespace, the stored value plus one
 * after that. signManifest() adds the owner's key and signature. */
export interface ManifestBody {
  namespace: string;
  manifest: unknown;
  circuits: Record<string, unknown>;
  seq: number;
}

/** `POST /v1/register`: the contract manifest registration message. The
 * signature covers every other member, owner_pubkey included, under the
 * REGISTER domain. */
export interface ManifestMessage extends ManifestBody {
  owner_pubkey: GrumpkinPoint;
  signature: Signature;
}

/** A DISABLE body before signing: the namespace, the circuit's name and the
 * registry sequence number (the stored value plus one). */
export interface DisableBody {
  namespace: string;
  circuit: string;
  seq: number;
}

/** `POST /v1/disable`. The signature covers namespace, circuit, seq and
 * owner_pubkey under the DISABLE domain. */
export interface DisableRequest extends DisableBody {
  owner_pubkey: GrumpkinPoint;
  signature: Signature;
}

/** The answer to DISABLE: the circuit named, its vk hash, the namespace's
 * npk_app_hash, the disabled mark (always true), the body's `seq`, and node
 * i's signature over the registry result message with `disabled` = 1 in
 * `signatures[i]`. */
export interface DisableResponse {
  namespace: string;
  circuit: string;
  vk_hash: string;
  npk_app_hash: string;
  disabled: true;
  seq: number;
  signatures: Triple<Signature>;
}

/** The answer to REGISTER: the manifest hash, the packages hash, the
 * namespace's npk_app_hash, the `seq` the contract manifest is registered
 * with and node i's signature over the manifest result message in
 * `signatures[i]`, which a tip contract's configure checks. */
export interface ManifestResponse {
  manifest_hash: string;
  packages_hash: string;
  npk_app_hash: string;
  seq: number;
  signatures: Triple<Signature>;
}

/** `GET /v1/namespaces/{namespace}`: the owner, the registry sequence number,
 * npk_app_hash and the hash of the namespace's contract manifest. */
export interface NamespaceResponse {
  namespace: string;
  owner_pubkey: GrumpkinPoint;
  seq: number;
  npk_app_hash: string;
  manifest_hash: string;
}

/** `GET /v1/namespaces/{namespace}/manifest`: the contract manifest as
 * registered, its hash and the `seq` of the REGISTER that wrote it. */
export interface ContractManifestResponse {
  namespace: string;
  manifest_hash: string;
  seq: number;
  manifest: unknown;
}

/** `GET /v1/packages/{namespace}/{name}`. */
export interface PackageResponse {
  namespace: string;
  name: string;
  /** The hash of the contract manifest the package belongs to. */
  manifest_hash: string;
  circuit: unknown;
  manifest: unknown;
  vk: string;
  vk_hash: string;
  disabled: boolean;
  /** The `seq` of the registry body that last wrote the package. */
  seq: number;
}

/** `POST /v1/receipt` as the client sends it to the orchestrator (sidecar-tip
 * receipt.rs ReceiptRequest): the app inputs by public name, the requester,
 * the nonce and the block the expiry counts from. The client never sets
 * `expiry_block`: the orchestrator fixes it (400 otherwise). */
export interface ReceiptRequestBody {
  namespace: string;
  circuit: string;
  inputs: Record<string, PublicValue>;
  user_nonce: string;
  current_block: number;
  /** The contract manifest version the request was built under (its vk
   * hash is that version's): set under upgradable circuits, absent under
   * fixed ones. The nodes refuse a version their chain view's pins do not
   * name. */
  manifest_hash?: string;
}

/** The orchestrator's answer to `POST /v1/receipt`: the values the three
 * nodes agreed on and their signatures, node 0 first. */
export interface ReceiptResponse {
  request_id: string;
  inputs_hash: string;
  expiry_block: number;
  signatures: Triple<Signature>;
}

// ---- strict response parsing ----

type Json = Record<string, unknown>;

function object(v: unknown, path: string, required: string[], optional: string[] = []): Json {
  if (typeof v !== "object" || v === null || Array.isArray(v)) {
    throw new ProtocolError(`field \`${path}\`: not an object`);
  }
  const o = v as Json;
  for (const k of Object.keys(o)) {
    if (!required.includes(k) && !optional.includes(k)) {
      throw new ProtocolError(`field \`${path ? path + "." : ""}${k}\`: unknown field`);
    }
  }
  for (const k of required) {
    if (!(k in o)) throw new ProtocolError(`field \`${path ? path + "." : ""}${k}\`: missing`);
  }
  return o;
}

function wrap<T>(path: string, f: () => T): T {
  try {
    return f();
  } catch (e) {
    if (e instanceof ProtocolError) throw e;
    throw new ProtocolError(`field \`${path}\`: ${(e as Error).message}`);
  }
}

function str(v: unknown, path: string): string {
  if (typeof v !== "string") throw new ProtocolError(`field \`${path}\`: not a string`);
  return v;
}

function field(v: unknown, path: string): string {
  return wrap(path, () => fieldHex(str(v, path), path));
}

function bytes(v: unknown, path: string): string {
  return wrap(path, () => hexBytes(str(v, path), path));
}

function array(v: unknown, path: string, len?: number): unknown[] {
  if (!Array.isArray(v)) throw new ProtocolError(`field \`${path}\`: not an array`);
  if (len !== undefined && v.length !== len) {
    throw new ProtocolError(`field \`${path}\`: ${v.length} entries, expected ${len}`);
  }
  return v;
}

function parsePoint(v: unknown, path: string): GrumpkinPoint {
  const o = object(v, path, ["x", "y"]);
  return { x: field(o.x, `${path}.x`), y: field(o.y, `${path}.y`) };
}

function parseResultRecord(v: unknown, path: string): ResultRecord {
  const o = object(v, path, ["key", "note_hash", "c"]);
  const c = array(o.c, `${path}.c`, NODES).map((x, i) => bytes(x, `${path}.c[${i}]`));
  return {
    key: str(o.key, `${path}.key`),
    note_hash: field(o.note_hash, `${path}.note_hash`),
    c: c as Triple<string>,
  };
}

export function parseExecuteResponse(v: unknown): ExecuteResponse {
  const o = object(v, "", ["request_id", "vk_hash", "proof", "public_inputs", "signatures"], ["stored", "records"]);
  return {
    request_id: wrap("request_id", () => requestIdHex(str(o.request_id, "request_id"))),
    vk_hash: field(o.vk_hash, "vk_hash"),
    proof: bytes(o.proof, "proof"),
    public_inputs: array(o.public_inputs, "public_inputs").map((x, i) => field(x, `public_inputs[${i}]`)),
    stored: array(o.stored ?? [], "stored").map((x, i) => str(x, `stored[${i}]`)),
    records: array(o.records ?? [], "records").map((x, i) => parseResultRecord(x, `records[${i}]`)),
    signatures: signatures(o.signatures, "signatures"),
  };
}

function parseNodeKeys(v: unknown, path: string): NodeKeys {
  const o = object(v, path, ["enc", "sig"]);
  return { enc: parsePoint(o.enc, `${path}.enc`), sig: parsePoint(o.sig, `${path}.sig`) };
}

export function parseNodesResponse(v: unknown): NodesResponse {
  const o = object(v, "", ["nodes"]);
  const nodes = array(o.nodes, "nodes", NODES).map((p, i) => parseNodeKeys(p, `nodes[${i}]`));
  return { nodes: nodes as Triple<NodeKeys> };
}

/** A registry sequence number: a JSON integer from 0 to 2^53 - 1 (the Rust
 * side is a u64; larger values cannot occur before 2^53 registry bodies). */
function seqNumber(v: unknown, path = "seq"): number {
  if (typeof v !== "number" || !Number.isSafeInteger(v) || v < 0) {
    throw new ProtocolError(`field \`${path}\`: not a non-negative integer`);
  }
  return v;
}

function bool(v: unknown, path: string): boolean {
  if (typeof v !== "boolean") throw new ProtocolError(`field \`${path}\`: not a boolean`);
  return v;
}

function parseSignature(v: unknown, path: string): Signature {
  const o = object(v, path, ["s", "e"]);
  const pair = (p: unknown, at: string) => array(p, at, 2).map((x, i) => field(x, `${at}[${i}]`)) as [string, string];
  return { s: pair(o.s, `${path}.s`), e: pair(o.e, `${path}.e`) };
}

function signatures(v: unknown, path: string): Triple<Signature> {
  return array(v, path, NODES).map((x, i) => parseSignature(x, `${path}[${i}]`)) as Triple<Signature>;
}

export function parseManifestResponse(v: unknown): ManifestResponse {
  const o = object(v, "", ["manifest_hash", "packages_hash", "npk_app_hash", "seq", "signatures"]);
  return {
    manifest_hash: field(o.manifest_hash, "manifest_hash"),
    packages_hash: field(o.packages_hash, "packages_hash"),
    npk_app_hash: field(o.npk_app_hash, "npk_app_hash"),
    seq: seqNumber(o.seq),
    signatures: signatures(o.signatures, "signatures"),
  };
}

export function parseDisableResponse(v: unknown): DisableResponse {
  const o = object(v, "", ["namespace", "circuit", "vk_hash", "npk_app_hash", "disabled", "seq", "signatures"]);
  if (o.disabled !== true) throw new ProtocolError("field `disabled`: not true");
  return {
    namespace: field(o.namespace, "namespace"),
    circuit: str(o.circuit, "circuit"),
    vk_hash: field(o.vk_hash, "vk_hash"),
    npk_app_hash: field(o.npk_app_hash, "npk_app_hash"),
    disabled: true,
    seq: seqNumber(o.seq),
    signatures: signatures(o.signatures, "signatures"),
  };
}

export function parseNamespaceResponse(v: unknown): NamespaceResponse {
  const o = object(v, "", ["namespace", "owner_pubkey", "seq", "npk_app_hash", "manifest_hash"]);
  return {
    namespace: field(o.namespace, "namespace"),
    owner_pubkey: parsePoint(o.owner_pubkey, "owner_pubkey"),
    seq: seqNumber(o.seq),
    npk_app_hash: field(o.npk_app_hash, "npk_app_hash"),
    manifest_hash: field(o.manifest_hash, "manifest_hash"),
  };
}

export function parseContractManifestResponse(v: unknown): ContractManifestResponse {
  const o = object(v, "", ["namespace", "manifest_hash", "seq", "manifest"]);
  return {
    namespace: field(o.namespace, "namespace"),
    manifest_hash: field(o.manifest_hash, "manifest_hash"),
    seq: seqNumber(o.seq),
    manifest: o.manifest,
  };
}

export function parsePackageResponse(v: unknown): PackageResponse {
  const o = object(v, "", ["namespace", "name", "manifest_hash", "circuit", "manifest", "vk", "vk_hash", "disabled", "seq"]);
  return {
    namespace: field(o.namespace, "namespace"),
    name: str(o.name, "name"),
    manifest_hash: field(o.manifest_hash, "manifest_hash"),
    circuit: o.circuit,
    manifest: o.manifest,
    vk: bytes(o.vk, "vk"),
    vk_hash: field(o.vk_hash, "vk_hash"),
    disabled: bool(o.disabled, "disabled"),
    seq: seqNumber(o.seq),
  };
}

/** Normalise a signature to the wire form. */
export function normaliseSignature(sig: Signature): Signature {
  const pair = (p: unknown, what: string): [string, string] => {
    if (!Array.isArray(p) || p.length !== 2) throw new RangeError(`${what}: expected [lo, hi]`);
    return [fieldHex(p[0], `${what}[0]`), fieldHex(p[1], `${what}[1]`)];
  };
  return { s: pair(sig.s, "signature.s"), e: pair(sig.e, "signature.e") };
}

// JSON numbers in a signed body. RFC 8785 serialises numbers as ECMAScript
// does for doubles; this serialiser accepts only integers of magnitude at
// most 2^53 - 1 and refuses every other number, the same rule as
// sidecar-core's canonical_json. Within that range the decimal form is the
// same in JavaScript and Rust, so the client and the nodes sign and check the
// same bytes; a float or a larger integer could be printed or rounded
// differently and fail the signature check at the nodes. Write large values
// as strings (nargo output already carries its `hash` as one).
/** RFC 8785 (JCS) canonical JSON: object members sorted by the UTF-16 code
 * units of their names, no whitespace, strings escaped as JSON.stringify does,
 * integers in plain decimal. Refuses non-integers, integers outside
 * ±(2^53 - 1) and strings that are not well-formed UTF-16 (a lone surrogate
 * has no UTF-8 form for the nodes to read). Members whose value is undefined
 * are left out, as JSON.stringify leaves them out of the body that is sent. */
export function canonicalJson(v: unknown): string {
  if (v === null || typeof v === "boolean") return JSON.stringify(v);
  if (typeof v === "string") {
    if (!v.isWellFormed()) throw new RangeError("canonical JSON: a string with a lone surrogate");
    return JSON.stringify(v);
  }
  if (typeof v === "number") {
    if (!Number.isSafeInteger(v)) {
      throw new RangeError(`canonical JSON: the number ${v} is not an integer within ±(2^53 - 1); write it as a string`);
    }
    return JSON.stringify(v);
  }
  if (Array.isArray(v)) return "[" + v.map(canonicalJson).join(",") + "]";
  if (typeof v === "object") {
    const o = v as Json;
    const keys = Object.keys(o).filter((k) => o[k] !== undefined).sort();
    return "{" + keys.map((k) => canonicalJson(k) + ":" + canonicalJson(o[k])).join(",") + "}";
  }
  throw new TypeError(`canonical JSON: cannot encode a ${typeof v}`);
}

/** Parse a receipt answer: exactly its four fields, `expiry_block` a u32. */
export function parseReceiptResponse(v: unknown): ReceiptResponse {
  const o = object(v, "", ["request_id", "inputs_hash", "expiry_block", "signatures"]);
  return {
    request_id: field(o.request_id, "request_id"),
    inputs_hash: field(o.inputs_hash, "inputs_hash"),
    expiry_block: u32(o.expiry_block, "field `expiry_block`", "block number", ProtocolError),
    signatures: signatures(o.signatures, "signatures"),
  };
}
