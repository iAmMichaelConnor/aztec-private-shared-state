// Building the execute request: a fresh request id, the public map, the keys,
// the INPUT_SHARED envelopes, the supplied state records with their hashes, the
// requester and its signature, as the exact JSON body that is saved and sent.
// The canonical body, body_hash and input_body_hash follow
// machine/sidecar-core/src/request.rs byte for byte.

import { randomBytes } from "node:crypto";

import { poseidon2HashBytes } from "@aztec-labs/foundation/crypto/poseidon";
import type { Fr } from "@aztec-labs/foundation/curves/bn254";

import { sealSharedInput, shareHash, type SealRandomness } from "./envelope.ts";
import type { PointInput } from "./grumpkin.ts";
import { fieldHex, fieldShortHex, hexBytes, requestIdHex, type FieldLike } from "./field.ts";
import { isQueued, stateOf, type Manifest } from "./manifest.ts";
import { recordHashes } from "./records.ts";
import { EXECUTE_DOMAIN, messageFor, verifySignature, type SchnorrSigner } from "./signing.ts";
import type { ExecuteRequest, GrumpkinPoint, StateKeys, PublicValue, SharedInput, StateRecord, Triple } from "./wire.ts";
import { NODES, canonicalJson, checkName, normaliseSignature } from "./wire.ts";

/** The machine's fixed keys, which a request key may not equal (manifest.rs). */
export const FIXED_KEYS: readonly string[] = ["nsk_app"];

/** A key as the caller gives it. A string is sent as written; a number, bigint
 * or Fr is written as a field element in its one key spelling, 0x and lowercase
 * hex digits without leading zeros (requestKey). */
export type KeyLike = string | Exclude<FieldLike, string>;

/** One secret input in plaintext: the client shares and seals it. */
export interface SharedInputValue {
  /** The INPUT_SHARED name the manifest gives the parameter. */
  name: string;
  value: FieldLike;
}

/** A record to supply: as a RecordStore keeps it, or as a round returned it. */
export interface RecordInput {
  key: string;
  note_hash: FieldLike;
  c: Triple<string>;
}

// DEV DECISION: INPUT_SHARED versus PUBLIC per circuit parameter, chosen in
// the manifest (`from: {PUBLIC: name}` or `from: {INPUT_SHARED: name}`), no
// default; the client follows it. `public` values go in the clear to the
// orchestrator and every node; `sharedInputs` are shared into three
// replicated shares and sealed to each node's pinned enc key, so no single
// party (orchestrator or node) learns the value. A value in the wrong map is
// refused by the nodes at binding (400). Choose INPUT_SHARED for anything
// secret (a hidden door, a private amount); PUBLIC costs nothing extra and is
// the right form for values public on chain anyway (nonces, slots, the
// namespace). Design guide: "intake" (question 1, "Who must not see the
// state and the inputs?").
export interface BuildRequestInput {
  circuit: string;
  /** Public values by ABI parameter name: one field element, or a list. */
  public?: Record<string, FieldLike | FieldLike[]>;
  stateKeys?: { reads?: KeyLike[]; writes?: KeyLike[] };
  /** Secret inputs in plaintext, in the order the body lists them. Needs the
   * pinned enc keys. */
  sharedInputs?: SharedInputValue[];
  /** The state record of each loaded client-held key. Needs a signer. */
  records?: RecordInput[];
  /** The requester key: signs the request and owns its records. */
  signer?: SchnorrSigner;
  /** The requester's public key, when it is to be checked against the
   * signer's or named on a request that needs no signature. */
  requester?: { x: FieldLike; y: FieldLike };
}

/** Known answers for buildExecuteRequestWith: a fixed request id and, per
 * shared input name, its sharing and ephemeral secrets. */
export interface KnownAnswerInputs {
  requestId: FieldLike;
  sealing?: Record<string, SealRandomness>;
}

/** A request ready to send: its id, the body, and the exact JSON text that is
 * saved before sending and resent unchanged on retry. */
export interface PreparedRequest {
  requestId: string;
  circuit: string;
  namespace: string;
  body: ExecuteRequest;
  json: string;
}

// request_id generation. Each request gets 128 bits from the operating
// system's CSPRNG (crypto.randomBytes(16)), read as a big-endian integer and
// written as the field element it is: 0x + 64 hex digits, the top 32 of them
// zero. 128 bits is below the modulus, so every draw is a valid id with no
// reduction and no bias. Fewer bits would make ids guessable; more buy
// nothing a FETCH guesser could use. buildExecuteRequest offers no way to
// choose an id; only buildExecuteRequestWith, which exists for known-answer
// tests, takes one. EXECUTE and FETCH are unauthenticated and FETCH is
// scoped only by (namespace, request_id), so the id's unguessability is what
// keeps other requesters from fetching this round's proof and public
// outputs. A counter, a timestamp or a content hash would make results
// fetchable by anyone who can guess them.
export function newRequestId(): string {
  return requestIdHex(randomBytes(16));
}

/** Whether a manifest stores a client-held key: some output's STORE key has
 * the state holder `client`. */
export function manifestStoresClientKey(m: Manifest): boolean {
  return m.outputs.some((o) => stateOf(m, o.STORE) === "client");
}

/** Whether a manifest gives the request key `$state_keys.reads[j]` the state holder
 * `client`: a read whose state the requester supplies as a record. */
function manifestReadsClientKey(m: Manifest, j: number): boolean {
  return stateOf(m, `$state_keys.reads[${j}]`) === "client";
}

// Key spelling. A key is a store row by its string, so "0xa002" and
// "0x0a002" are two different keys in the nodes' store; a key is 1 to 256
// bytes of visible ASCII (checkName). A key the manifest feeds into PUBLIC is
// also a public value by its field element, so under intake direct the nodes
// admit only its short spelling: 0x and lowercase hex digits without leading
// zeros, 0x0 for zero (sidecar-core's bind.rs; 400 otherwise). A key given as
// a number, bigint or Fr is written in that spelling; a string is sent exactly
// as written, and with the circuit's manifest a string key that feeds PUBLIC
// in another spelling is refused here. Use one spelling per key for the life
// of the deployment; mixing them makes a LOAD miss the stored value (409) or
// a STORE create a second row.
/** A request or record key as a request carries it: a string as written
 * (visible ASCII, not a fixed key), anything else as a field element in short
 * hex (fieldShortHex). A RangeError naming `what` otherwise. */
export function requestKey(k: KeyLike, what = "key"): string {
  if (typeof k === "string") {
    checkName(what, "key", k);
    if (FIXED_KEYS.includes(k)) throw new RangeError(`${what}: \`${k}\` is a fixed key`);
    return k;
  }
  return fieldShortHex(k, what);
}

const KEY_REF = /^\$state_keys\.(reads|writes)\[(0|[1-9][0-9]*)\]$/;

/** Refuse a request key that `manifest` (intake direct) feeds into PUBLIC
 * unless it is a field element spelled as fieldShortHex spells it, as the
 * nodes do at binding. A key past the manifest's count is left to the nodes. */
function checkPublicStateKeys(stateKeys: StateKeys, manifest: Manifest): void {
  if (isQueued(manifest)) return;
  for (const w of manifest.witness) {
    const pub = w.from.PUBLIC;
    for (const op of Array.isArray(pub) ? pub : [pub]) {
      const ref = typeof op === "string" ? KEY_REF.exec(op) : null;
      if (ref === null) continue;
      const list = ref[1] as "reads" | "writes";
      const what = `stateKeys.${list}[${ref[2]}]`;
      const key = stateKeys[list][Number(ref[2])];
      if (key === undefined) continue;
      let short: string;
      try {
        short = fieldShortHex(key, what);
      } catch (e) {
        throw new RangeError(`${(e as Error).message}; the manifest feeds ${op} into parameter \`${w.param}\`, so it must be a field element`);
      }
      if (key !== short) {
        throw new RangeError(
          `${what}: \`${key}\` feeds parameter \`${w.param}\` and is spelled \`${short}\`; a key that is a field element is 0x and lowercase hex digits without leading zeros`,
        );
      }
    }
  }
}

function publicValue(v: FieldLike | FieldLike[], what: string): PublicValue {
  if (Array.isArray(v)) {
    if (v.length === 0) throw new RangeError(`${what}: an empty list fills no parameter`);
    return v.map((x, i) => fieldHex(x, `${what}[${i}]`));
  }
  return fieldHex(v, what);
}

const point = (p: { x: FieldLike; y: FieldLike }, what: string): GrumpkinPoint => ({
  x: fieldHex(p.x, `${what}.x`),
  y: fieldHex(p.y, `${what}.y`),
});

// ---- the canonical body ----

// The canonical body is rebuilt from the request's values in the wire's
// normal form, never hashed from the caller's own formatting: field elements
// (the request id among them) 0x + 64 lowercase digits; `public`, `state_keys`
// (both lists), `shared_inputs` and `records` always present; `requester`
// only when set; every `shares` and `c` and the `signature` left out; then
// RFC 8785 (JCS). This is sidecar-core's canonical_body exactly, so the
// client, the orchestrator and every node compute the same body_hash, signed
// message and envelope associated data; testvectors/envelope.json carries a
// worked example.
/** The canonical body of an execute request: the request without `shares`,
 * `c` and `signature`, in the wire's normal form. */
export function canonicalBody(body: ExecuteRequest): Record<string, unknown> {
  const pub: Record<string, PublicValue> = {};
  for (const [name, v] of Object.entries(body.public ?? {})) pub[name] = publicValue(v, `public.${name}`);
  const out: Record<string, unknown> = {
    namespace: fieldHex(body.namespace, "namespace"),
    circuit: body.circuit,
    request_id: requestIdHex(body.request_id),
    public: pub,
    state_keys: { reads: [...(body.state_keys?.reads ?? [])], writes: [...(body.state_keys?.writes ?? [])] },
    shared_inputs: (body.shared_inputs ?? []).map((s, k) => ({
      name: s.name,
      share_hashes: triple(s.share_hashes, `shared_inputs[${k}].share_hashes`, (h, i) => fieldHex(h, `shared_inputs[${k}].share_hashes[${i}]`)),
    })),
    records: (body.records ?? []).map((r, k) => ({
      key: r.key,
      note_hash: fieldHex(r.note_hash, `records[${k}].note_hash`),
      record_hashes: triple(r.record_hashes, `records[${k}].record_hashes`, (h, i) => fieldHex(h, `records[${k}].record_hashes[${i}]`)),
    })),
  };
  if (body.requester !== undefined) out.requester = point(body.requester, "requester");
  return out;
}

/** The field element the requester signs for an execute request:
 * `poseidon2HashBytes("cosnark-sidecar/v1/execute" ‖ JCS(canonical body))`,
 * sidecar-core's Request::signed_message. */
export function executeMessage(body: ExecuteRequest): Promise<Fr> {
  return messageFor(EXECUTE_DOMAIN, canonicalBody(body));
}

const hashText = async (text: string) => fieldHex((await poseidon2HashBytes(Buffer.from(text, "utf8"))).toBigInt());

/** `poseidon2_hash_bytes(JCS(canonical body))`: the nodes' replay check and
 * session handshake key. */
export function bodyHash(body: ExecuteRequest): Promise<string> {
  return hashText(canonicalJson(canonicalBody(body)));
}

/** The hash of the canonical body without the whole `shared_inputs` array,
 * which every envelope's associated data covers. */
export function inputBodyHash(body: ExecuteRequest): Promise<string> {
  const { shared_inputs: _omit, ...rest } = canonicalBody(body);
  return hashText(canonicalJson(rest));
}

function triple<T, U>(xs: T[], what: string, f: (x: T, i: number) => U): Triple<U> {
  if (!Array.isArray(xs) || xs.length !== NODES) throw new RangeError(`${what}: expected ${NODES} entries`);
  return xs.map(f) as Triple<U>;
}

// ---- building ----

/** Build the execute request for `namespace`. Checks what sidecar-core's
 * Request::validate checks: a circuit name, every key and every shared-input
 * name of visible ASCII (checkName); no fixed key and no key listed twice in
 * `stateKeys.reads` or in `stateKeys.writes`; no duplicate shared-input name or record
 * key; a public map that flattens to distinct witness names; with `manifest`,
 * every key it feeds into PUBLIC spelled in short hex (requestKey).
 * Checks before sealing anything what the nodes check at steps 4 and 8 of the
 * request lifecycle: every record's key is a key the request reads and, with
 * `manifest` (the circuit's registered manifest, parsed), one whose state mode is
 * `client`; a request that supplies a record, whose manifest stores a
 * client-held key, or that carries a shared input has a signer. Shares and
 * seals every shared input to `encKeys` (node 0 first; the pinned keys, never keys the orchestrator
 * reports), hashes every supplied record's thirds, and names the requester
 * and signs whenever a signer is given. Every refusal is a RangeError naming
 * the field. PssClient.buildRequest passes the configured manifest; without
 * one, a request that stores a client-held key is signed only when a signer
 * is given. */
export function buildExecuteRequest(namespace: FieldLike, input: BuildRequestInput, encKeys?: Triple<PointInput>, manifest?: Manifest): Promise<PreparedRequest> {
  return build(namespace, input, encKeys, { requestId: newRequestId() }, manifest);
}

/** buildExecuteRequest with a fixed request id, sharings and ephemeral
 * secrets, for known answers (testvectors/envelope.json). A client uses
 * buildExecuteRequest: reusing an id or a sharing reveals secrets. */
export function buildExecuteRequestWith(
  namespace: FieldLike,
  input: BuildRequestInput,
  encKeys: Triple<PointInput> | undefined,
  known: KnownAnswerInputs,
  manifest?: Manifest,
): Promise<PreparedRequest> {
  return build(namespace, input, encKeys, known, manifest);
}

// One key twice in one list would bind two parameters to one stored value (or
// store one key twice); a key may appear once in `reads` and once in `writes`.
function keyList(keys: KeyLike[] | undefined, list: "reads" | "writes"): string[] {
  const seen = new Set<string>();
  return (keys ?? []).map((k, i) => {
    const key = requestKey(k, `stateKeys.${list}[${i}]`);
    if (seen.has(key)) throw new RangeError(`stateKeys.${list}[${i}]: \`${key}\` is listed twice`);
    seen.add(key);
    return key;
  });
}

async function build(
  namespace: FieldLike,
  input: BuildRequestInput,
  encKeys: Triple<PointInput> | undefined,
  known: KnownAnswerInputs,
  manifest: Manifest | undefined,
): Promise<PreparedRequest> {
  checkName("circuit", "circuit name", input.circuit);
  const pub: Record<string, PublicValue> = {};
  const flat = new Set<string>();
  for (const [name, v] of Object.entries(input.public ?? {})) {
    if (name.length === 0 || name.startsWith("$")) throw new RangeError(`public.${name}: not a public value name`);
    const value = publicValue(v, `public.${name}`);
    pub[name] = value;
    const names = Array.isArray(value) && value.length > 1 ? value.map((_, i) => `${name}[${i}]`) : [name];
    for (const n of names) {
      if (flat.has(n)) throw new RangeError(`public.${n}: duplicated after flattening lists`);
      flat.add(n);
    }
  }
  const stateKeys: StateKeys = { reads: keyList(input.stateKeys?.reads, "reads"), writes: keyList(input.stateKeys?.writes, "writes") };
  if (manifest !== undefined) checkPublicStateKeys(stateKeys, manifest);
  const shared = input.sharedInputs ?? [];
  const names = new Set<string>();
  for (const [k, s] of shared.entries()) {
    const what = `sharedInputs[${k}]`;
    checkName(`${what}.name`, "input name", s.name);
    if (names.has(s.name)) throw new RangeError(`${what}.name: \`${s.name}\` is duplicated`);
    names.add(s.name);
    fieldHex(s.value, `${what}.value`);
  }
  if (shared.length > 0 && encKeys === undefined) {
    throw new RangeError("sharedInputs: sealing needs the three pinned node enc keys");
  }
  const recordKeys = new Set<string>();
  const records: StateRecord[] = [];
  for (const [k, r] of (input.records ?? []).entries()) {
    const what = `records[${k}]`;
    const key = requestKey(r.key, `${what}.key`);
    if (recordKeys.has(key)) throw new RangeError(`${what}.key: \`${key}\` is duplicated`);
    recordKeys.add(key);
    // A record no client-held read opens is refused by the nodes (400) after
    // the loads; refuse it here, before anything is sealed.
    const j = stateKeys.reads.indexOf(key);
    if (j < 0) throw new RangeError(`${what}: the request reads no key \`${key}\``);
    if (manifest !== undefined && !manifestReadsClientKey(manifest, j)) {
      throw new RangeError(`${what}: circuit \`${input.circuit}\` reads no client-held key \`${key}\``);
    }
    const c = triple(r.c, `${what}.c`, (c, i) => hexBytes(c, `${what}.c[${i}]`));
    records.push({ key, note_hash: fieldHex(r.note_hash, `${what}.note_hash`), c, record_hashes: await recordHashes(c) });
  }

  // The requester key source. The requester is the key of the `signer` the
  // caller passes: often the user's Aztec account signing key behind a
  // SchnorrSigner, or a dedicated RequesterKey the app keeps per user, never
  // the namespace owner key (see the key roles in signing.ts). It owns every
  // client-held record the request creates, and only a request signed by it
  // can supply those records again. Without a signer the request names no
  // requester; a request that supplies a record, whose manifest stores a
  // client-held key, or that carries a shared input needs one and is refused
  // here without a signer (the nodes would answer 400 or 403). The signature
  // over the body covers every share hash, and the requester is in every
  // envelope's associated data, so no one who sees the body can swap in an
  // envelope of their own beside this request's others. Losing the key loses
  // the states it owns; one key per user keeps users' records apart.
  const why = signedBecause(records.length > 0, shared.length > 0, manifest);
  if (why !== undefined && input.signer === undefined) {
    throw new RangeError(`signer: a request that ${why} must be signed by its requester key`);
  }
  let requester: GrumpkinPoint | undefined;
  if (input.signer !== undefined) {
    requester = point(await input.signer.publicKey(), "signer");
    if (input.requester !== undefined) {
      const given = point(input.requester, "requester");
      if (given.x !== requester.x || given.y !== requester.y) throw new RangeError("requester: not the signer's public key");
    }
  } else if (input.requester !== undefined) {
    requester = point(input.requester, "requester");
  }

  const body: ExecuteRequest = {
    namespace: fieldHex(namespace, "namespace"),
    circuit: input.circuit,
    request_id: requestIdHex(known.requestId),
    public: pub,
    state_keys: stateKeys,
    shared_inputs: [],
    records,
  };
  if (requester !== undefined) body.requester = requester;

  // The envelopes' associated data covers everything but shared_inputs, so it
  // is fixed before the first envelope is sealed.
  if (shared.length > 0) {
    const ibh = await inputBodyHash(body);
    const sealed: SharedInput[] = [];
    for (const s of shared) {
      const ad = { namespace: body.namespace, requestId: body.request_id, circuit: body.circuit, name: s.name, binds: ibh };
      sealed.push(await sealSharedInput(ad, s.value, encKeys!, known.sealing?.[s.name]));
    }
    body.shared_inputs = sealed;
  }
  const prepared: PreparedRequest = { requestId: body.request_id, circuit: body.circuit, namespace: body.namespace, body, json: JSON.stringify(body) };
  return requester !== undefined && input.signer !== undefined ? signRequest(prepared, input.signer) : prepared;
}

/** Check that every `share_hashes[i]` is the hash of `shares[i]` and every
 * `record_hashes[i]` the hash of `c[i]`; a mismatch would be refused by node i
 * (400) after the orchestrator fanned out. */
export async function checkCiphertextHashes(body: ExecuteRequest): Promise<void> {
  for (const [k, input] of body.shared_inputs.entries()) {
    for (const [i, share] of input.shares.entries()) {
      if ((await shareHash(share)) !== fieldHex(input.share_hashes[i]!)) {
        throw new RangeError(`shared_inputs[${k}].share_hashes[${i}]: not the hash of shares[${i}]`);
      }
    }
  }
  for (const [k, r] of body.records.entries()) {
    const want = await recordHashes(r.c);
    for (let i = 0; i < NODES; i++) {
      if (want[i] !== fieldHex(r.record_hashes[i]!, `records[${k}].record_hashes[${i}]`)) {
        throw new RangeError(`records[${k}].record_hashes[${i}]: not the hash of c[${i}]`);
      }
    }
  }
}

/** Why a request must be signed by its requester (sidecar-core's step 4
 * under intake direct), or undefined when it need not be: it supplies
 * records, its manifest stores a client-held key, or it carries a shared
 * input. */
function signedBecause(supplies: boolean, carriesShared: boolean, manifest: Manifest | undefined): string | undefined {
  if (supplies) return "supplies records";
  if (manifest !== undefined && manifestStoresClientKey(manifest)) return "stores a client-held key";
  if (carriesShared) return "carries a shared input";
  return undefined;
}

/** Check that a request that supplies records, whose `manifest` stores a
 * client-held key, or that carries a shared input names its requester and
 * carries the requester's signature, and that any signature the body carries
 * verifies over its canonical body. */
export async function checkRequestSignature(body: ExecuteRequest, manifest?: Manifest): Promise<void> {
  const why = signedBecause(body.records.length > 0, body.shared_inputs.length > 0, manifest);
  if (why === undefined && body.signature === undefined) return;
  if (body.requester === undefined) throw new RangeError(`requester: a request that ${why ?? "is signed"} must name its requester key`);
  if (body.signature === undefined) throw new RangeError(`signature: a request that ${why} must be signed by its requester key`);
  if (!(await verifySignature((await executeMessage(body)).toBigInt(), body.requester, body.signature))) {
    throw new RangeError("signature: does not verify under requester over the canonical body");
  }
}

/** Add the requester's signature to a prepared request: the signer's key must
 * be the body's `requester`, and the signature covers the canonical body
 * under the EXECUTE domain (executeMessage). buildExecuteRequest calls it when
 * given a signer; call it yourself only for a body built without one. */
export async function signRequest(prepared: PreparedRequest, signer: SchnorrSigner): Promise<PreparedRequest> {
  const requester = prepared.body.requester;
  if (requester === undefined) throw new RangeError("requester: a signed request must name its requester key");
  const pub = await signer.publicKey();
  if (fieldHex(pub.x) !== requester.x || fieldHex(pub.y) !== requester.y) {
    throw new RangeError("requester: the signer's public key is not the body's requester key");
  }
  const signature = normaliseSignature(await signer.sign(await executeMessage(prepared.body)));
  const body: ExecuteRequest = { ...prepared.body, signature };
  return { ...prepared, body, json: JSON.stringify(body) };
}
