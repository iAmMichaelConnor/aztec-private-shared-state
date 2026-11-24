// Owner-bound state records on the client: the hash a request carries for each
// node's sealed third, the key id of a node key, the check of the records an
// answer returns, and the store that keeps every record a round returned, as
// machine/sidecar-core/src/record.rs and keys.rs define them.
//
//   c_i         = key_id (8 bytes) ‖ ct[0] ‖ ... ‖ ct[n-1] ‖ tag   each field 32 bytes big-endian
//   key_id      = the first 8 bytes of poseidon2([enc_pk.x, enc_pk.y]) as 32 bytes big-endian
//   record_hash = poseidon2([key_id as a big-endian integer, ct[0], ..., tag])   record_hashes[i]
//
// The client cannot open a third (only node i holds K_i); it keeps the three
// thirds exactly as the round returned them and presents them again with the
// requester key that owns them.

import { poseidon2Hash } from "@aztec-labs/foundation/crypto/poseidon";
import { Fr } from "@aztec-labs/foundation/curves/bn254";

import { ConfigError, ProtocolError } from "./errors.ts";
import { BN254_MODULUS, bytesFromHex, fieldBigInt, fieldHex, hexBytes, requestIdHex, type FieldLike } from "./field.ts";
import { stateOf, type DirectManifest } from "./manifest.ts";
import { JsonFile } from "./store.ts";
import { NODES, type ExecuteResponse, type ResultRecord, type StateKeys, type Triple } from "./wire.ts";

/** The length of a key id in bytes. */
export const KEY_ID_LEN = 8;
const FIELD_LEN = 32;

/** The key id of a node's `enc` public key, as `0x` + 16 hex digits: the
 * first bytes of every third sealed under it. */
export async function keyId(encPk: { x: FieldLike; y: FieldLike }): Promise<string> {
  const h = await poseidon2Hash([new Fr(fieldBigInt(encPk.x, "enc.x")), new Fr(fieldBigInt(encPk.y, "enc.y"))]);
  return "0x" + h.toBigInt().toString(16).padStart(64, "0").slice(0, 2 * KEY_ID_LEN);
}

/** The key id a sealed third starts with. */
export function recordKeyId(c: string): string {
  const bytes = bytesFromHex(c, "c");
  if (bytes.length < KEY_ID_LEN) throw new RangeError(`${bytes.length} bytes are not a sealed state record`);
  return hexBytes(bytes.subarray(0, KEY_ID_LEN));
}

/** The fields of the sealed third `c`: its key id read as a big-endian
 * integer, then its 32-byte field elements (ciphertext, then tag), `[key id,
 * ct…, tag]`, as sidecar-core's record_hash hashes them. Refuses what
 * record_hash refuses: a length that is not 8 + 32k with k >= 2, or a chunk that is not a
 * canonical field element. */
export function recordFields(c: string): bigint[] {
  const bytes = bytesFromHex(c, "c");
  const body = bytes.subarray(KEY_ID_LEN);
  const notRecord = () => new RangeError(`${bytes.length} bytes are not a sealed state record`);
  if (bytes.length < KEY_ID_LEN || body.length % FIELD_LEN !== 0 || body.length < 2 * FIELD_LEN) throw notRecord();
  const fields = [BigInt(hexBytes(bytes.subarray(0, KEY_ID_LEN)))];
  for (let o = 0; o < body.length; o += FIELD_LEN) {
    const v = BigInt(hexBytes(body.subarray(o, o + FIELD_LEN)));
    if (v >= BN254_MODULUS) throw notRecord();
    fields.push(v);
  }
  return fields;
}

/** `record_hashes[i]` for the sealed third `c`: Poseidon2 over its fields
 * (recordFields). */
export async function recordHash(c: string): Promise<string> {
  return fieldHex((await poseidon2Hash(recordFields(c).map((v) => new Fr(v)))).toBigInt());
}

/** The three record hashes of a record's thirds, node 0 first. */
export async function recordHashes(c: Triple<string>): Promise<Triple<string>> {
  return (await Promise.all(c.map(recordHash))) as Triple<string>;
}

/** One state record as the client keeps it: what the round returned, the
 * request that created it (the requester of that request owns it) and, once
 * known, the note nonce and the hash of the transaction that landed it. */
export interface StoredRecord {
  namespace: string;
  key: string;
  note_hash: string;
  c: Triple<string>;
  request_id: string;
  nonce?: string;
  tx_hash?: string;
}

// The record store. A record is the only copy of a client-held state outside
// the nodes' requests table, which is pruned after its retention window
// (default 30 days); losing it loses the state. The store keeps, per
// (namespace, key), every record a round returned, newest last, and never
// edits a third: put() adds a new record, a second put() of the same
// (namespace, key, request_id) must carry the identical thirds, and
// markLanded() only fills in nonce and tx_hash. Older records stay because a
// round whose transaction never lands is recovered by the operator's
// rollback, after which the previous record is the one to present again;
// prune them yourself once a later round has landed.
// Operator knob: DESIGN.md, "Configuration reference" (pss-client record
// store). MemoryRecordStore by default, which a process exit loses.
/** A durable map from (namespace, key) to the records rounds returned. */
export interface RecordStore {
  /** Add a record. Refuses a different record under the same (namespace,
   * key, request_id). Must be durable when it resolves. */
  put(record: StoredRecord): Promise<void>;
  /** The newest record of (namespace, key), or undefined. */
  latest(namespace: string, key: string): Promise<StoredRecord | undefined>;
  /** Every record of (namespace, key), oldest first. */
  history(namespace: string, key: string): Promise<StoredRecord[]>;
  /** Record the note nonce and transaction hash of a landed record. */
  markLanded(namespace: string, key: string, requestId: string, landed: { nonce?: FieldLike; tx_hash?: string }): Promise<void>;
  /** Drop every record of (namespace, key) older than the one created by `requestId`. */
  pruneBefore(namespace: string, key: string, requestId: string): Promise<void>;
}

function normaliseRecord(r: StoredRecord): StoredRecord {
  if (typeof r.key !== "string" || r.key.length === 0) throw new RangeError("record: empty key");
  if (!Array.isArray(r.c) || r.c.length !== NODES) throw new RangeError(`record ${r.key}: expected ${NODES} thirds`);
  const out: StoredRecord = {
    namespace: fieldHex(r.namespace, "namespace"),
    key: r.key,
    note_hash: fieldHex(r.note_hash, "note_hash"),
    c: r.c.map((c, i) => hexBytes(c, `c[${i}]`)) as Triple<string>,
    request_id: requestIdHex(r.request_id),
  };
  if (r.nonce !== undefined) out.nonce = fieldHex(r.nonce, "nonce");
  if (r.tx_hash !== undefined) out.tx_hash = r.tx_hash;
  return out;
}

const sameThirds = (a: StoredRecord, b: StoredRecord) =>
  a.note_hash === b.note_hash && a.c.every((c, i) => c === b.c[i]);

/** The records of one committed round, ready for a RecordStore. */
export function recordsFromResponse(namespace: FieldLike, response: Pick<ExecuteResponse, "request_id" | "records">): StoredRecord[] {
  return response.records.map((r: ResultRecord) =>
    normaliseRecord({ namespace: fieldHex(namespace, "namespace"), key: r.key, note_hash: r.note_hash, c: r.c, request_id: response.request_id }),
  );
}

/** The labels of the records a sidecar-path answer returns, checked before
 * any is kept: one record per client-held output of the manifest, in
 * manifest order; records[j].note_hash is the round's new commitment, the
 * public input at that output's note-hash index (`noteHashIndices`, in
 * manifest order); and, given the request's `state_keys`, records[j].key is the
 * request's write key that the output's STORE reference names. The result
 * signatures cover the thirds and the commitments but not these labels,
 * which the orchestrator assembles, so a relabelled record would otherwise be
 * kept and refused only when presented at the next round (step 8, the third
 * does not open). A ProtocolError naming the record otherwise. */
export function checkReturnedRecords(
  circuit: string,
  manifest: DirectManifest,
  noteHashIndices: readonly number[],
  response: Pick<ExecuteResponse, "public_inputs" | "records">,
  stateKeys?: StateKeys,
): void {
  const held = manifest.outputs.flatMap((o, k) => (stateOf(manifest, o.STORE) === "client" ? [{ store: o.STORE, index: noteHashIndices[k]! }] : []));
  if (response.records.length !== held.length) {
    throw new ProtocolError(`${circuit}: the answer carries ${response.records.length} records; the manifest's client-held outputs give ${held.length}`);
  }
  response.records.forEach((r, j) => {
    const { store, index } = held[j]!;
    const commitment = response.public_inputs[index];
    if (commitment === undefined || fieldBigInt(r.note_hash, `records[${j}].note_hash`) !== fieldBigInt(commitment, `public_inputs[${index}]`)) {
      throw new ProtocolError(`${circuit}: records[${j}] is labelled note_hash ${r.note_hash}, not the new commitment ${commitment} at public input ${index}`);
    }
    if (stateKeys === undefined) return;
    const w = /^\$state_keys\.writes\[(\d+)\]$/.exec(store);
    const key = w ? stateKeys.writes[Number(w[1])] : undefined;
    if (key === undefined) throw new ConfigError(`${circuit}: output STORE ${store} names no write key of the request`);
    if (r.key !== key) {
      throw new ProtocolError(`${circuit}: records[${j}] is labelled key ${r.key}, not ${key}, the request's key for ${store}`);
    }
  });
}

type Table = Record<string, StoredRecord[]>;
const slot = (namespace: string, key: string) => `${fieldHex(namespace, "namespace")}/${key}`;

function putInto(t: Table, record: StoredRecord): void {
  const r = normaliseRecord(record);
  const list = (t[slot(r.namespace, r.key)] ??= []);
  const existing = list.find((x) => x.request_id === r.request_id);
  if (existing !== undefined) {
    if (!sameThirds(existing, r)) throw new RangeError(`record ${r.key} of request ${r.request_id}: already stored with other thirds; records are never edited`);
    return;
  }
  list.push(Object.freeze({ ...r, c: Object.freeze([...r.c]) as unknown as Triple<string> }));
}

function markInto(t: Table, namespace: string, key: string, requestId: string, landed: { nonce?: FieldLike; tx_hash?: string }): void {
  const list = t[slot(namespace, key)] ?? [];
  const id = requestIdHex(requestId);
  const at = list.findIndex((x) => x.request_id === id);
  if (at < 0) throw new RangeError(`record ${key} of request ${id}: not stored`);
  const next: StoredRecord = { ...list[at]! };
  if (landed.nonce !== undefined) next.nonce = fieldHex(landed.nonce, "nonce");
  if (landed.tx_hash !== undefined) next.tx_hash = landed.tx_hash;
  list[at] = Object.freeze(next);
}

function pruneIn(t: Table, namespace: string, key: string, requestId: string): void {
  const s = slot(namespace, key);
  const list = t[s] ?? [];
  const at = list.findIndex((x) => x.request_id === requestIdHex(requestId));
  if (at < 0) throw new RangeError(`record ${key} of request ${requestId}: not stored`);
  t[s] = list.slice(at);
}

/** The default record store: in memory, lost when the process exits. */
export class MemoryRecordStore implements RecordStore {
  private readonly table: Table = {};
  async put(record: StoredRecord): Promise<void> {
    putInto(this.table, record);
  }
  async latest(namespace: string, key: string): Promise<StoredRecord | undefined> {
    return this.table[slot(namespace, key)]?.at(-1);
  }
  async history(namespace: string, key: string): Promise<StoredRecord[]> {
    return [...(this.table[slot(namespace, key)] ?? [])];
  }
  async markLanded(namespace: string, key: string, requestId: string, landed: { nonce?: FieldLike; tx_hash?: string }): Promise<void> {
    markInto(this.table, namespace, key, requestId, landed);
  }
  async pruneBefore(namespace: string, key: string, requestId: string): Promise<void> {
    pruneIn(this.table, namespace, key, requestId);
  }
}

/** A JSON file `{ "<namespace>/<key>": [record, ...], ... }` (store.ts
 * JsonFile). */
export class JsonFileRecordStore implements RecordStore {
  readonly path: string;
  private readonly file: JsonFile<Table>;
  constructor(path: string) {
    this.path = path;
    this.file = new JsonFile(path, "record store");
  }

  put(record: StoredRecord): Promise<void> {
    return this.file.update((t) => putInto(t, record));
  }
  async latest(namespace: string, key: string): Promise<StoredRecord | undefined> {
    return (await this.file.read())[slot(namespace, key)]?.at(-1);
  }
  async history(namespace: string, key: string): Promise<StoredRecord[]> {
    return (await this.file.read())[slot(namespace, key)] ?? [];
  }
  markLanded(namespace: string, key: string, requestId: string, landed: { nonce?: FieldLike; tx_hash?: string }): Promise<void> {
    return this.file.update((t) => markInto(t, namespace, key, requestId, landed));
  }
  pruneBefore(namespace: string, key: string, requestId: string): Promise<void> {
    return this.file.update((t) => pruneIn(t, namespace, key, requestId));
  }
}
