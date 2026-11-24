// What became of a queued request, for a user (docs/ARCHITECTURE.md section
// 6, rows "relayer" and "outputs", and "Private outcomes"): pollResult
// watches the queue until the request is finished and reads what the app's
// apply stored. Under the non-secret-shared intakes results are public via
// `apply`; there are no outcome events, so `done[index]` tells an apply from
// a skip. Under the secret-shared intakes the outcome is private: the round seals it
// inside the MPC (pss_core tip/outcome.nr), the result transaction pushes the
// hash of the note completing the request's partial note and emits the
// outcome log `[tag, note_hash, ciphertext..., padding...]`, and the user
// opens the log with its outcome key under the nonce of the note hash it
// carries and rebuilds the note (openOutcomeLog; discovery.ts's
// OutcomeReader finds the log).
// outcomeResultParts and noirOutcomeResult are that path's result for
// whoever lands it. Landing a result is lander.ts's.

import { AztecAddress } from "@aztec-labs/aztec.js/addresses";
import { poseidon2HashWithSeparator } from "@aztec-labs/foundation/crypto/poseidon";
import { Fr } from "@aztec-labs/foundation/curves/bn254";
import { computeSiloedPrivateLogFirstField } from "@aztec-labs/stdlib/hash";

import { abiOf, publicLayout } from "./abi.ts";
import { aeDecrypt, TagMismatchError } from "./ae.ts";
import { ProtocolError } from "./errors.ts";
import { fieldAddress, fieldBigInt, fieldFr, fieldHex, type FieldHexString, type FieldLike, hashFields } from "./field.ts";
import { publicReadParams, type QueuedManifest } from "./manifest.ts";
import { DONE_APPLIED, DONE_PENDING, DONE_SKIPPED, type QueueReader } from "./queue.ts";
import { sleep } from "./sleep.ts";
import { ProvedInputs, signatureLimbs, type ProvedLayout, type ProvedParts } from "./proved.ts";
import { stateModule, tipStateOf, type TipStateHolder } from "./state.ts";
import type { ResultForm } from "./result.ts";
import type { ExecuteResponse } from "./wire.ts";
import { asciiLabel } from "./labels.ts";

// ---- pollResult ----

/** What the app's apply stored for a queue index: the app's own reader
 * (`outcome_at(index)`, as pss_public_contract_test names it). */
export type OutputsReader<T> = (index: number) => Promise<T>;

export type PolledResult<T> =
  | { status: "applied"; index: number; requestId: FieldHexString; outputs: T; block: number }
  | { status: "skipped"; index: number; requestId: FieldHexString; block: number };

export interface PollResultOptions<T, U> {
  queue: QueueReader;
  chainRequestId: FieldLike;
  /** The first queue index to look for the request at; default 0. */
  fromIndex?: number;
  /** Reads what apply stored; without it an applied result has outputs undefined. */
  readOutputs?: OutputsReader<T>;
  /** Turns the stored outputs into what the caller wants. */
  decrypt?: (outputs: T, index: number) => Promise<U>;
  /** Default DEFAULT_POLL_INTERVAL_MS. */
  intervalMs?: number;
  /** Give up (rejects with an Error) after this long; default none. */
  timeoutMs?: number;
  signal?: AbortSignal;
}

// How pollResult finds and watches a request. It looks for the chain request
// id in requests[i] from `fromIndex` (default 0) up to the tail, once per
// poll, remembering how far it has looked, until the intake has landed; then
// it waits for head to pass the index and reads done[index]: 1 is an apply
// (it calls readOutputs(index), the app's own reader of what its apply hook
// stored), 2 a skip. Every poll after it found the index reads requests[index]
// again at the poll's block: when a replaced block took the request out of
// the queue (another request can then sit at that index), it forgets the
// index and looks again from `fromIndex`, so it does not report another
// request's fate (a poll's reads are by block number, so a replacement of
// that block between them can still mix two chains). The polling period `intervalMs` defaults to 2,000 ms (a
// third of a proposed block); no timeout unless given. The queue stores ids
// by index and no index by id, and the library emits no outcome event, so the
// index and done[index] are what a client can read. A client that knows the
// queue's tail before its intake should pass it as fromIndex, since a scan
// from 0 reads one slot per earlier request; a shorter period costs one
// storage read per poll and finds the outcome sooner.
export const DEFAULT_POLL_INTERVAL_MS = 2_000;

/** Wait until the queue has finished chain request `chainRequestId`; report
 * an apply with what the app stored (and decrypted), or a skip. */
export async function pollResult<T = unknown, U = T>(options: PollResultOptions<T, U>): Promise<PolledResult<U>> {
  const chain = fieldHex(options.chainRequestId, "chain_request_id");
  const interval = options.intervalMs ?? DEFAULT_POLL_INTERVAL_MS;
  const deadline = options.timeoutMs === undefined ? Infinity : Date.now() + options.timeoutMs;
  const from = options.fromIndex ?? 0;
  let next = from;
  let index: number | undefined;
  for (;;) {
    const snap = await options.queue.snapshot();
    if (index !== undefined && (index >= snap.tail || (await options.queue.requestAt(index, snap.block)) !== chain)) {
      // a replaced block took the request out of the queue at this index
      index = undefined;
      next = from;
    }
    if (index === undefined) {
      for (; next < snap.tail; next++) {
        if ((await options.queue.requestAt(next, snap.block)) === chain) {
          index = next;
          break;
        }
      }
    }
    if (index !== undefined && snap.head > index) {
      const done = await options.queue.doneAt(index, snap.block);
      if (done === DONE_SKIPPED) return { status: "skipped", index, requestId: chain, block: snap.block };
      if (done !== DONE_APPLIED) {
        throw new ProtocolError(`queue index ${index}: head ${snap.head} has passed it but done is ${done === DONE_PENDING ? "pending" : done}`);
      }
      const stored = (options.readOutputs ? await options.readOutputs(index) : undefined) as T;
      const outputs = (options.decrypt ? await options.decrypt(stored, index) : stored) as U;
      return { status: "applied", index, requestId: chain, outputs, block: snap.block };
    }
    if (Date.now() + interval > deadline) {
      throw new Error(
        `chain request ${chain}: ${index === undefined ? "not queued" : `queue index ${index} not finished`} within ${options.timeoutMs} ms`,
      );
    }
    await sleep(interval, options.signal);
  }
}

// ---- private outcomes (the secret-shared intakes) ----

/** ASCII "sidecar.outcome" read big-endian: the AEAD nonce's domain of an
 * outcome whose round's shares open C, and of every delivery (pss_core
 * tip/outcome.nr SIDECAR_OUTCOME_AD). */
export const SIDECAR_OUTCOME_AD = asciiLabel("sidecar.outcome");
/** ASCII "sidecar.mismatch" read big-endian: the outcome AEAD nonce's domain
 * in a round whose shares do not open C (pss_core tip/outcome.nr
 * SIDECAR_MISMATCH_AD). */
export const SIDECAR_MISMATCH_AD = asciiLabel("sidecar.mismatch");
/** aztec-nr v6's note-hash separator, DOM_SEP__NOTE_HASH. */
export const DOM_SEP_NOTE_HASH = 116501019;
/** The fields of every outcome log, the full v6 private log with its tag:
 * `[tag, note_hash, ct..., padding...]`, `note_hash` the hash of the
 * completed note whose plaintext the ciphertext seals (pss_public_contract
 * outcome_log). */
export const OUTCOME_LOG_FIELDS = 16;


/** The AEAD nonce of a sealed plaintext (pss_core tip/outcome.nr
 * seal_nonce): `poseidon2([note_hash, SIDECAR_OUTCOME_AD])` when the
 * round's shares open C, `poseidon2([note_hash, SIDECAR_MISMATCH_AD])` when
 * they do not, `note_hash` the hash of the completed note that packs the
 * plaintext. The note hash commits to the plaintext, so under one key one
 * nonce only ever seals one plaintext, whatever blinding a run draws and
 * however often the nodes rerun a round. */
export async function sealNonce(noteHash: FieldLike, opened: boolean): Promise<bigint> {
  return hashFields([fieldBigInt(noteHash, "note_hash"), opened ? SIDECAR_OUTCOME_AD : SIDECAR_MISMATCH_AD]);
}

/** Open a ciphertext `[ct..., tag]` sealed under `key` with
 * `sealNonce(noteHash, opened)`; TagMismatchError when it does not open
 * there. */
export async function openSealed(ciphertext: readonly FieldLike[], key: FieldLike, noteHash: FieldLike, opened: boolean): Promise<bigint[]> {
  if (ciphertext.length < 2) throw new RangeError("an outcome ciphertext has at least one field and the tag");
  const body = ciphertext.slice(0, -1);
  return aeDecrypt(key, await sealNonce(noteHash, opened), body, ciphertext[ciphertext.length - 1]!);
}

/** Open an outcome ciphertext `[ct..., tag]` under `outcomeKey` with the
 * nonce of `noteHash`, the note hash its log carries: in the opened domain,
 * or, when the tag does not match there, in the mismatch domain, where a
 * round whose shares did not open C sealed `[mismatch code, 0, ...]`, so
 * the user reads that code. TagMismatchError when it opens in neither. */
export async function openOutcome(ciphertext: readonly FieldLike[], outcomeKey: FieldLike, noteHash: FieldLike): Promise<bigint[]> {
  try {
    return await openSealed(ciphertext, outcomeKey, noteHash, true);
  } catch (e) {
    if (!(e instanceof TagMismatchError)) throw e;
    return openSealed(ciphertext, outcomeKey, noteHash, false);
  }
}

/** A log that opens under the key but whose note, rebuilt from the
 * plaintext and the caller's owner, randomness, storage slot or request
 * id, is not the note hash the log carries: the PXE would drop the note. */
export class NoteMismatchError extends Error {
  constructor(logged: FieldHexString, rebuilt: FieldHexString) {
    super(`the log carries note hash ${logged}, the keys rebuild ${rebuilt}`);
    this.name = "NoteMismatchError";
  }
}

// ---- partial-note delivery (docs/ARCHITECTURE.md section 6, "Partial-note delivery") ----

/** aztec-nr v6's partial-note commitment separator,
 * DOM_SEP__PARTIAL_NOTE_COMMITMENT. */
export const DOM_SEP_PARTIAL_NOTE_COMMITMENT = 568912195;
/** aztec-nr v6's completion log tag separator, DOM_SEP__NOTE_COMPLETION_LOG_TAG. */
export const DOM_SEP_NOTE_COMPLETION_LOG_TAG = 3372669888;
/** The most fields a note packs (aztec-nr MAX_NOTE_PACKED_LEN): a completed
 * note holds at most seven outcome fields and the chain request id. */
export const MAX_NOTE_PACKED_LEN = 8;

/** A partial note's commitment, `poseidon2_hash_with_separator([owner, rho],
 * DOM_SEP__PARTIAL_NOTE_COMMITMENT)` (pss_core tip/outcome.nr
 * partial_commitment): the request's `$partial_note`, which the app's
 * request function recomputes from the same owner and `rho`. */
export async function partialCommitment(owner: FieldLike | AztecAddress, rho: FieldLike): Promise<bigint> {
  const o = owner instanceof AztecAddress ? owner.toBigInt() : fieldBigInt(owner, "owner");
  return (await poseidon2HashWithSeparator([new Fr(o), new Fr(fieldBigInt(rho, "rho"))], DOM_SEP_PARTIAL_NOTE_COMMITMENT)).toBigInt();
}

/** The hash of the note completing `partial` at `storageSlot` with the
 * outcome `fields` and the chain request id, `poseidon2_hash_with_separator(
 * [storage_slot, partial, fields..., request_id], DOM_SEP__NOTE_HASH)`
 * (pss_core completed_note_hash): the note packs `[fields..., request_id]`,
 * at most eight fields. */
export async function completedNoteHash(storageSlot: FieldLike, partial: FieldLike, fields: readonly FieldLike[], requestId: FieldLike): Promise<bigint> {
  if (fields.length + 1 > MAX_NOTE_PACKED_LEN) throw new RangeError(`fields: a completed note packs at most ${MAX_NOTE_PACKED_LEN} fields, request_id last`);
  const input = [fieldBigInt(storageSlot, "storage_slot"), fieldBigInt(partial, "partial"), ...fields.map((f, i) => fieldBigInt(f, `fields[${i}]`)), fieldBigInt(requestId, "request_id")];
  return (await poseidon2HashWithSeparator(input.map((x) => new Fr(x)), DOM_SEP_NOTE_HASH)).toBigInt();
}

/** The tag of a public completion's log, `compute_log_tag(partial,
 * DOM_SEP__NOTE_COMPLETION_LOG_TAG)` (pss_core completion_log_tag): a client
 * that lost its state finds a public completion under it from the
 * re-derived `rho` (SecretStore.recover). */
export async function completionLogTag(partial: FieldLike): Promise<bigint> {
  return (await poseidon2HashWithSeparator([new Fr(fieldBigInt(partial, "partial"))], DOM_SEP_NOTE_COMPLETION_LOG_TAG)).toBigInt();
}

/** One message of a transaction's offchain output (aztec.js's send result
 * `offchainMessages`: recipient, payload, emitting contract, anchor block
 * timestamp). */
export interface SentOffchainMessage {
  recipient: AztecAddress;
  payload: readonly FieldLike[];
  contractAddress: AztecAddress;
  anchorBlockTimestamp: bigint;
}

/** One message as the app's `offchain_receive` utility (injected by
 * aztec-nr's `#[aztec]`) takes it. */
export interface OffchainReceiveMessage {
  ciphertext: Fr[];
  recipient: AztecAddress;
  tx_hash: { _is_some: boolean; _value: Fr };
  anchor_block_timestamp: bigint;
}

// A request under the public completion tells its owner's PXE of the
// partial note with an offchain partial-note message (pss_public_contract
// `partial_note::deliver_partial_note`, `MessageDelivery::offchain()`): the
// wallet does not deliver it, even to its own sender; aztec.js returns it
// among the send result's `offchainMessages`, and the client hands it to the
// app's `offchain_receive` utility, tied to the request's transaction, after
// which the PXE completes the note when `apply` emits its completion log.
/** The `offchain_receive` argument of the messages `contract` emitted in
 * transaction `txHash` for `recipient` (another contract's or another
 * recipient's left out). */
export function offchainReceiveArgs(
  messages: readonly SentOffchainMessage[],
  contract: FieldLike | AztecAddress,
  recipient: FieldLike | AztecAddress,
  txHash: FieldLike,
): OffchainReceiveMessage[] {
  const app = fieldBigInt(contract instanceof AztecAddress ? contract.toBigInt() : contract, "contract");
  const to = fieldBigInt(recipient instanceof AztecAddress ? recipient.toBigInt() : recipient, "recipient");
  return messages
    .filter((m) => m.contractAddress.toBigInt() === app && m.recipient.toBigInt() === to)
    .map((m) => ({
      ciphertext: m.payload.map((f) => fieldFr(f)),
      recipient: m.recipient,
      tx_hash: { _is_some: true, _value: fieldFr(txHash) },
      anchor_block_timestamp: m.anchorBlockTimestamp,
    }));
}

/** The outcome log's tag as the chain shows it: `$outcome_tag` siloed with
 * the contract address by the kernel (stdlib computeSiloedPrivateLogFirstField). */
export async function outcomeLogTag(contract: FieldLike | AztecAddress, outcomeTag: FieldLike): Promise<Fr> {
  const address = fieldAddress(contract, "contract");
  return computeSiloedPrivateLogFirstField(address, new Fr(fieldBigInt(outcomeTag, "outcome_tag")));
}

/** The padding field at position `i` of a private log emitted under `tag`
 * (unsiloed), counting from the first field after the tag:
 * `poseidon2([tag, i])` (pss_core tip/outcome.nr log_padding). The outcome
 * log holds it at every position past its ciphertext. */
export async function logPadding(tag: FieldLike, i: number): Promise<bigint> {
  if (!Number.isInteger(i) || i < 0) throw new RangeError("i: a log position");
  return hashFields([fieldBigInt(tag, "tag"), BigInt(i)]);
}

/** An outcome log's fields as `process_result` emits them, the siloed tag
 * first: `[outcomeLogTag(contract, outcomeTag), note_hash, ciphertext...,
 * padding...]`, the padding `logPadding(outcomeTag, i)` at each position
 * `i` (after the tag) past the ciphertext. A delivery's log has the same
 * layout under its own tag and note hash. */
export async function outcomeLogFields(contract: FieldLike | AztecAddress, outcomeTag: FieldLike, noteHash: FieldLike, ciphertext: readonly FieldLike[]): Promise<bigint[]> {
  const body = [fieldBigInt(noteHash, "note_hash"), ...ciphertext.map((c, k) => fieldBigInt(c, `ciphertext[${k}]`))];
  if (body.length > OUTCOME_LOG_FIELDS - 1) throw new RangeError(`a ciphertext of ${ciphertext.length} fields does not fit one private log`);
  for (let i = body.length; i < OUTCOME_LOG_FIELDS - 1; i++) body.push(await logPadding(outcomeTag, i));
  return [(await outcomeLogTag(contract, outcomeTag)).toBigInt(), ...body];
}

/** One outcome log, read: the note hash it carries and the app's
 * ciphertext (its plaintext length plus the tag), the padding dropped. */
export interface OutcomeLog {
  noteHash: FieldHexString;
  ciphertext: bigint[];
}

/** Read an outcome log's fields (`logData`, the siloed tag first) for an app
 * whose outcome plaintext has `plaintextLength` fields. RangeError when it is
 * not a full private log or the ciphertext does not fit. */
export function parseOutcomeLog(fields: readonly FieldLike[], plaintextLength: number): OutcomeLog {
  if (!Number.isInteger(plaintextLength) || plaintextLength < 1) throw new RangeError("plaintextLength: at least one field");
  if (2 + plaintextLength + 1 > OUTCOME_LOG_FIELDS) throw new RangeError(`an outcome of ${plaintextLength} fields does not fit one private log`);
  if (fields.length !== OUTCOME_LOG_FIELDS) throw new RangeError(`an outcome log has ${OUTCOME_LOG_FIELDS} fields, this one ${fields.length}`);
  const at = (i: number) => fieldBigInt(fields[i]!, `log[${i}]`);
  return {
    noteHash: fieldHex(at(1)),
    ciphertext: Array.from({ length: plaintextLength + 1 }, (_, k) => at(2 + k)),
  };
}

/** The note the round completed, as its owner rebuilds it: what the app's
 * outcome-note utility takes (pss_public_contract `deliver_outcome_note`). */
export interface OutcomeNote {
  owner: FieldHexString;
  storageSlot: FieldHexString;
  randomness: FieldHexString;
  packed: FieldHexString[];
  noteHash: FieldHexString;
}

export interface OpenedOutcome {
  plaintext: bigint[];
  /** The note rebuilt from the plaintext and the keys. */
  note: OutcomeNote;
  /** The note hash the log carries, the one the round pushed. */
  loggedNoteHash: FieldHexString;
  /** Whether the rebuilt note is the logged one, so its delivery lands in
   * the PXE. False when an owner, rho, storage slot or request id passed in
   * is not the request's (a rescan that does not know the request id yet
   * reads the plaintext all the same), or in a round whose shares did not
   * open C when a node changed its partial-note share: the code still
   * reads, but the note is not the user's. outcomeDeliveryArgs refuses it. */
  noteMatches: boolean;
}

export interface OutcomeKeys {
  /** `$outcome_key`, the request's AEAD key. */
  outcomeKey: FieldLike;
  /** The note's owner: the account whose partial note the request
   * committed (`$partial_note` = partialCommitment(owner, rho)), an account
   * in the user's PXE. */
  owner: FieldLike;
  /** The request's partial-note randomness (SecretStore). */
  rho: FieldLike;
  /** The request's chain request id, the completed note's last field. */
  requestId: FieldLike;
  /** The app's outcome note storage slot (the round circuit's constant). */
  storageSlot: FieldLike;
  /** The number of outcome plaintext fields (the AMM's 2, lending's 7). */
  plaintextLength: number;
}

// The note of an app, as the client rebuilds it from the opened plaintext:
// the completion of the request's partial note, `[plaintext...,
// request_id]` under randomness `rho`, hashed as completedNoteHash over
// partialCommitment(owner, rho), the hash the round output. The note's
// storage slot is the app's constant, the one its round circuits hash with.
// The rebuild is compared with the note hash the log carries, so a wrong
// key is reported at once rather than when the PXE drops the note
// (deliver_outcome_note); a wrong rebuild loses no value either way: the
// note stays in the chain's tree and a corrected client delivers it.
/** Open an outcome log (openOutcome under the note hash it carries: a round
 * that did not open C gives its mismatch code), rebuild its note and
 * compare it with the logged note hash (`noteMatches`). TagMismatchError
 * when the log does not open under the key (another request's log under a
 * reused tag). */
export async function openOutcomeLog(fields: readonly FieldLike[], keys: OutcomeKeys): Promise<OpenedOutcome> {
  const log = parseOutcomeLog(fields, keys.plaintextLength);
  const plaintext = await openOutcome(log.ciphertext, keys.outcomeKey, log.noteHash);
  const packed = [...plaintext, fieldBigInt(keys.requestId, "request_id")].map((v, i) => fieldHex(v, `note[${i}]`));
  const partial = await partialCommitment(keys.owner, keys.rho);
  const noteHash = fieldHex(await completedNoteHash(keys.storageSlot, partial, plaintext, keys.requestId));
  return {
    plaintext,
    loggedNoteHash: log.noteHash,
    noteMatches: BigInt(noteHash) === BigInt(log.noteHash),
    note: {
      owner: fieldHex(keys.owner, "owner"),
      storageSlot: fieldHex(keys.storageSlot, "storage_slot"),
      randomness: fieldHex(keys.rho, "rho"),
      packed,
      noteHash,
    },
  };
}

// ---- the private-outcome result, for whoever lands it ----

/** The shape of a round under private outcomes: R keys read, W written, Q
 * pinned reads, T new leaf hashes of a tree-valued key and H completed note
 * hashes; the ciphertext takes the rest, the last public inputs. */
export interface OutcomeShape {
  circuit: string;
  reads: number;
  writes: number;
  pinned: number;
  /** The new leaf hashes T of a round that writes a tree-valued key (the
   * manifest's `tree` `new_hashes`: lending's 2 for an owner-bound round, K
   * for a liquidation), after npk_app_hash; 0 (the default) for flat keys.
   * The result function takes them as an argument of their own after the
   * result (pss_public_contract `outcome::Private::tree`). */
  newHashes?: number;
  noteHashes: number;
  /** The K public values of the attempt after the ciphertext (pss_core
   * tip/outcome.nr `Valued`'s `app_values`, e.g. the inputs-opened bit of
   * an app that escrows),
   * which the result function takes as an argument of their own after the
   * new leaf hashes (pss_public_contract `outcome::Private::valued`);
   * 0 (the default) for a round that returns `Private`. */
  appValues?: number;
  /** The D deliveries after the app values of a round whose app uses the
   * standing delivery handle (pss_core tip/handle.nr `Delivered`; handle.ts),
   * each `[tag, note_hash, ciphertext[M]]`, `deliveryLength` M; the result
   * function takes them as an argument of their own after the app values
   * (pss_public_contract `handle::Delivered`). 0 (the default) for a round
   * without. */
  deliveries?: number;
  deliveryLength?: number;
  state: TipStateHolder;
  /** The records a round's answer carries, each as the position of its
   * output (the state module's records). */
  records: readonly number[];
}

/** The shape of a secret-shared-intake round from its compiled circuit (the nargo
 * output JSON or its `abi`) and its parsed manifest: R and W the manifest's
 * keys, Q the pinned values (each read's value, then an epoch read's epoch),
 * T and H the return value's `new_hashes` and `note_hashes` elements and K
 * its `app_values` elements (the library's names, pss_core tip/outcome.nr
 * `Private` and `Valued`). RangeError when the
 * public parameters are not the
 * library's `[namespace, vk_hash, in_slots[R], out_slots[W], pinned[Q]]` or
 * the return value is not public. */
export function outcomeShape(circuit: unknown, m: QueuedManifest): OutcomeShape {
  const { publicFields, returnLeaves, returnPublic } = publicLayout(abiOf(circuit));
  if (!returnPublic) throw new RangeError(`${m.circuit}: the return value is not public`);
  const { reads, writes } = m.stateKeys;
  const pinned = m.publicReads.flatMap(publicReadParams).length;
  if (publicFields !== 2 + reads + writes + pinned) {
    throw new RangeError(
      `${m.circuit}: ${publicFields} public parameter fields; the outcome layout has ${2 + reads + writes + pinned} ` +
        `(namespace, vk_hash, ${reads} read slot(s), ${writes} written slot(s), ${pinned} pinned value(s))`,
    );
  }
  const count = (name: string) => returnLeaves.filter((l) => new RegExp(`(^|\\.)${name}\\[\\d+\\]$`).test(l.path)).length;
  const sent = returnLeaves.flatMap((l) => {
    const d = /^deliveries\[(\d+)\]\.ciphertext\[\d+\]$/.exec(l.path);
    return d ? [Number(d[1])] : [];
  });
  const deliveries = new Set(sent).size;
  const state = tipStateOf(m);
  return {
    circuit: m.circuit,
    reads,
    writes,
    pinned,
    newHashes: count("new_hashes"),
    noteHashes: count("note_hashes"),
    ...(count("app_values") > 0 ? { appValues: count("app_values") } : {}),
    ...(deliveries > 0 ? { deliveries, deliveryLength: sent.length / deliveries } : {}),
    state,
    records: stateModule(state).records(m),
  };
}

/** The number of outcome plaintext fields of a secret-shared-intake round
 * from its compiled circuit (the nargo output JSON or its `abi`): its return
 * value's `ciphertext` elements (pss_core tip/outcome.nr `Private`, at the
 * top of `Valued` and `Delivered` too) less the AEAD tag; a delivery's
 * ciphertext is not counted. What an outcome log is read with
 * (OutcomeKeys.plaintextLength). RangeError when the return value has no
 * ciphertext of at least two fields. */
export function outcomePlaintextLength(circuit: unknown): number {
  const { returnLeaves } = publicLayout(abiOf(circuit));
  const length = returnLeaves.filter((l) => /^ciphertext\[\d+\]$/.test(l.path)).length;
  if (length < 2) throw new RangeError("the return value has no outcome ciphertext of at least one field and the tag");
  return length - 1;
}

/** Where each part of a private-outcome result sits in a proof's public
 * inputs: the parts every form binds (ProvedLayout, the proof's machine
 * request id among them), then the outcome layout's own. */
export interface OutcomeLayout extends ProvedLayout {
  npkAppHash: number;
  newHashes: number[];
  outcomeTag: number;
  noteHashes: number[];
  ciphertext: number[];
  appValues: number[];
  deliveries: { tag: number; noteHash: number; ciphertext: number[] }[];
}

// The private-outcome result layout the client expects is the
// library's outcome_public_inputs: public parameters `[namespace, vk_hash,
// in_slots[R], out_slots[W], reads[Q]]`, then the return value
// `[request_id, machine_request_id, old_commitments[R], new_commitments[W],
// npk_app_hash, new_hashes[T], outcome_tag, note_hashes[H], ciphertext[L],
// app_values[K], deliveries[D]]`, T = 0 for flat keys, K = 0 for a round
// without app values (a value is one the app may show, never an amount or an
// owner) and D = 0 for an app without the delivery handle: a circuit with another order cannot verify in
// process_result. Nothing in it is value-bearing in the clear: the code and
// every app output are inside the ciphertext, and the note hash hides its
// owner behind the partial note (pss_public_contract outcome.nr).
/** The layout of a proof of `length` public inputs under `shape`: the
 * ciphertext takes what the shape's fixed parts and its app values leave.
 * RangeError when the shape's counts are not whole numbers or the public
 * inputs are too short for it. */
export function outcomeLayout(shape: OutcomeShape, length: number): OutcomeLayout {
  const { reads: R, writes: W, pinned: Q, noteHashes: H } = shape;
  const T = shape.newHashes ?? 0;
  const K = shape.appValues ?? 0;
  const D = shape.deliveries ?? 0;
  const M = shape.deliveryLength ?? 0;
  if (!Number.isInteger(T) || T < 0) throw new RangeError(`${shape.circuit}: newHashes must be a whole number, not ${T}`);
  if (!Number.isInteger(K) || K < 0) throw new RangeError(`${shape.circuit}: appValues must be a whole number, not ${K}`);
  if (!Number.isInteger(D) || D < 0 || !Number.isInteger(M) || M < 0 || (D > 0 && M < 2)) {
    throw new RangeError(`${shape.circuit}: deliveries and deliveryLength must be whole numbers, a delivery's ciphertext at least two fields`);
  }
  const sent = D * (2 + M);
  const prefix = 2 + R + W + Q;
  const fixed = prefix + 2 + R + W + 2 + T + H + K + sent;
  if (length < fixed + 2) throw new RangeError(`${shape.circuit}: ${length} public inputs; the shape needs ${fixed} and a ciphertext of at least two fields`);
  const range = (from: number, n: number) => Array.from({ length: n }, (_, k) => from + k);
  const olds = prefix + 2;
  const tag = olds + R + W + 1 + T;
  return {
    circuit: shape.circuit,
    state: shape.state,
    records: shape.records,
    requestId: prefix,
    machineRequestId: prefix + 1,
    oldCommitments: range(olds, R),
    newCommitments: range(olds + R, W),
    reads: range(2 + R + W, Q),
    npkAppHash: olds + R + W,
    newHashes: range(olds + R + W + 1, T),
    outcomeTag: tag,
    noteHashes: range(tag + 1, H),
    ciphertext: range(tag + 1 + H, length - (tag + 1 + H) - K - sent),
    appValues: range(length - sent - K, K),
    deliveries: Array.from({ length: D }, (_, d) => {
      const at = length - sent + d * (2 + M);
      return { tag: at, noteHash: at + 1, ciphertext: range(at + 2, M) };
    }),
  };
}

/** Everything the app's private-outcome process_result needs from one
 * checked answer, named as pss_public_contract's OutcomeResult names it. */
export interface OutcomeResultParts extends ProvedParts {
  /** A tree-valued key's new leaf hashes, in slot order; empty for flat
   * keys. */
  newHashes: FieldHexString[];
  outcomeTag: FieldHexString;
  noteHashes: FieldHexString[];
  ciphertext: FieldHexString[];
  /** The round's public values for the app's apply, in order; empty for a
   * round without app values. */
  appValues: FieldHexString[];
  /** The round's deliveries (handle.ts), in order; empty for a round
   * without. */
  deliveries: DeliveryParts[];
}

/** One delivery of a round (pss_public_contract `handle::Delivery`): its
 * log tag, its completed note's hash and its ciphertext. */
export interface DeliveryParts {
  tag: FieldHexString;
  noteHash: FieldHexString;
  ciphertext: FieldHexString[];
}

/** The parts of a checked answer to FETCH by chain request id under private
 * outcomes, read at the shape's layout (outcomeLayout: RangeError when the
 * public inputs are too short for it) and bound as every form's are
 * (ProvedInputs.bind, the proof's own machine request id included;
 * ProtocolError otherwise). */
export async function outcomeResultParts(
  shape: OutcomeShape,
  namespace: FieldLike,
  chainRequestIdValue: FieldLike,
  response: ExecuteResponse,
): Promise<OutcomeResultParts> {
  const layout = outcomeLayout(shape, response.public_inputs.length);
  const proved = new ProvedInputs(shape.circuit, response);
  const bound = await proved.bind(layout, namespace, chainRequestIdValue);
  return {
    ...bound,
    newHashes: proved.take(layout.newHashes, "new leaf hash"),
    outcomeTag: proved.at(layout.outcomeTag, "outcome tag"),
    noteHashes: proved.take(layout.noteHashes, "note hash"),
    ciphertext: proved.take(layout.ciphertext, "ciphertext field"),
    appValues: proved.take(layout.appValues, "app value"),
    deliveries: layout.deliveries.map((d) => ({
      tag: proved.at(d.tag, "delivery tag"),
      noteHash: proved.at(d.noteHash, "delivery note hash"),
      ciphertext: proved.take(d.ciphertext, "delivery ciphertext field"),
    })),
  };
}

/** pss_public_contract's OutcomeResult as aztec.js encodes it: the apply part
 * keeps the new commitments and then the pinned read values in one array,
 * `values`. */
export interface NoirOutcomeResult {
  apply: { request_id: Fr; old_commitments: Fr[]; values: Fr[] };
  outcome_tag: Fr;
  note_hashes: Fr[];
  ciphertext: Fr[];
}

/** The OutcomeResult struct of the parts. */
export function noirOutcomeResult(parts: OutcomeResultParts): NoirOutcomeResult {
  return {
    apply: {
      request_id: fieldFr(parts.requestId),
      old_commitments: parts.oldCommitments.map((x) => fieldFr(x)),
      values: [...parts.newCommitments, ...parts.reads].map((x) => fieldFr(x)),
    },
    outcome_tag: fieldFr(parts.outcomeTag),
    note_hashes: parts.noteHashes.map((x) => fieldFr(x)),
    ciphertext: parts.ciphertext.map((x) => fieldFr(x)),
  };
}

/** The library's argument order of a private-outcome process_result:
 * `[result, (new_hashes,) (app_values,) (deliveries,) ...stateArgs,
 * signatures]`: a tree-valued key's new leaf hashes `new_hashes: [Field;
 * T]` only for a round that writes one (`Private::tree`; an entry point
 * takes no empty array), the app values `[Field; K]` only for a round that
 * outputs them (`Private::valued`), the deliveries `[Delivery<M>; D]` only
 * for a round that outputs them (`handle::Delivered`), then the state
 * module's arguments (none under node-held state), as for the
 * public-output path. */
export function outcomeResultArgs(parts: OutcomeResultParts): unknown[] {
  const stateArgs = stateModule(parts.state).resultArgs(parts.stateArgs);
  const treeArgs = parts.newHashes.length === 0 ? [] : [parts.newHashes.map((x) => fieldFr(x))];
  const valueArgs = parts.appValues.length === 0 ? [] : [parts.appValues.map((x) => fieldFr(x))];
  const deliveryArgs = parts.deliveries.length === 0 ? [] : [parts.deliveries.map(noirDelivery)];
  return [noirOutcomeResult(parts), ...treeArgs, ...valueArgs, ...deliveryArgs, ...stateArgs, parts.signatures.map(signatureLimbs)];
}

/** A delivery as aztec.js encodes pss_public_contract's `handle::Delivery`. */
function noirDelivery(d: DeliveryParts): { tag: Fr; note_hash: Fr; ciphertext: Fr[] } {
  return { tag: fieldFr(d.tag), note_hash: fieldFr(d.noteHash), ciphertext: d.ciphertext.map((x) => fieldFr(x)) };
}

/** The identity of one private-outcome result for a lander's send count, as
 * resultKey is a public one's: the attempt and everything it writes and
 * emits. */
export function outcomeResultKey(parts: OutcomeResultParts): string {
  return [
    parts.machineRequestId,
    ...parts.newCommitments,
    ...parts.newHashes,
    ...parts.noteHashes,
    ...parts.ciphertext,
    ...parts.appValues,
    ...parts.deliveries.flatMap((d) => [d.tag, d.noteHash, ...d.ciphertext]),
  ].join(",");
}

/** The private-outcome form (result.ts): a secret-shared intake's round, its result
 * the library's OutcomeResult, landed through process_result in the
 * library's order (outcomeShape, outcomeResultParts, outcomeResultArgs,
 * outcomeResultKey). */
export const privateOutcomes: ResultForm<OutcomeResultParts> = {
  form: "outcome",
  reader(circuit, manifest) {
    const shape = outcomeShape(circuit, manifest);
    return {
      form: "outcome",
      circuit: shape.circuit,
      plaintextLength: outcomePlaintextLength(circuit),
      parts: (namespace, chainRequestId, response) => outcomeResultParts(shape, namespace, chainRequestId, response),
      callArgs: (parts) => outcomeResultArgs(parts),
      key: outcomeResultKey,
      summary: (p) => ({
        form: "outcome",
        machineRequestId: p.machineRequestId,
        oldCommitments: p.oldCommitments,
        newCommitments: p.newCommitments,
        reads: p.reads,
        moves: true,
        outcomeTag: p.outcomeTag,
        noteHashes: p.noteHashes,
        ciphertextLength: p.ciphertext.length,
      }),
    };
  },
};
