// The standing delivery handle, the client side (pss_core tip/handle.nr,
// pss_public_contract handle.nr; docs/ARCHITECTURE.md section 6, "The
// standing delivery handle"): how a user is delivered a note by a round it did not request.
//
// The user's request leaves a handle in its entry of the shared state, two
// shared values in C after the app inputs:
//
//   handle_partial = partialCommitment(owner, handle_randomness)   (the request function computes it)
//   handle_key     = poseidon2([PSS_HANDLE_KEY, wallet_secret, namespace, n])
//   handle_randomness = poseidon2([PSS_HANDLE_RANDOMNESS, wallet_secret, namespace, n])
//
// derived from the same request counter n as the request's own secrets
// (secrets.ts), so a rescan finds handles too. A later round requested by
// anyone may complete it: its result carries a delivery, a 16-field private
// log under handleTag(handle_key, request_id) (siloed with the app's
// address), request_id the delivering round's chain request id, holding the
// delivered note's hash and the ciphertext of its packed fields
// (`[fields..., request_id]`) under that note hash's nonce. A handle stays
// in the entry until the user's next request on it writes a new one, and
// any number of rounds may complete it in between, each a note of its own
// under a tag of its own. A user who knows the delivering round's request
// id finds the log under that tag with DeliveryReader.read; an owner of an
// app with exit tags who does not reads it in the transaction that spent its
// newest note's tag (hatch.ts exitTagSpender, DeliveryReader.readIn). Either
// way it opens the log with the handle's key (openDeliveryLog) and hands its
// PXE the note through the app's outcome-note utility under the handle's
// randomness (discovery.ts outcomeDeliveryArgs takes the result). A client
// keeps the handle of its latest request on each entry.

import { AztecAddress } from "@aztec-labs/aztec.js/addresses";
import { SiloedTag } from "@aztec-labs/stdlib/logs";

import { TagMismatchError } from "./ae.ts";
import { type FoundOutcome, logTx, type PrivateLogNode, type TxEffects } from "./discovery.ts";
import { fieldAddress, fieldBigInt, fieldHex, hashFields, type FieldHexString, type FieldLike } from "./field.ts";
import { asciiLabel } from "./labels.ts";
import { completedNoteHash, NoteMismatchError, OUTCOME_LOG_FIELDS, openSealed, outcomeLogTag, parseOutcomeLog, partialCommitment, MAX_NOTE_PACKED_LEN, type OutcomeNote } from "./outcome.ts";

/** The manifest names of a request's handle values, app inputs of C after
 * the round's own (not machine-reserved: the machine only shares them). */
export const HANDLE_PARTIAL_NAME = "handle_partial";
export const HANDLE_KEY_NAME = "handle_key";

/** ASCII "pss.handle_tag" read big-endian: a delivery's log tag domain
 * (pss_core tip/handle.nr PSS_HANDLE_TAG). */
export const PSS_HANDLE_TAG = asciiLabel("pss.handle_tag");
/** ASCII "pss.handle_randomness": the handle's partial-note randomness label. */
export const PSS_HANDLE_RANDOMNESS = asciiLabel("pss.handle_randomness");
/** ASCII "pss.handle_key": the handle's key label. */
export const PSS_HANDLE_KEY = asciiLabel("pss.handle_key");

/** A delivery's log tag, `poseidon2([key, PSS_HANDLE_TAG, requestId])`
 * (unsiloed), `requestId` the delivering round's chain request id. */
export async function handleTag(key: FieldLike, requestId: FieldLike): Promise<bigint> {
  return hashFields([fieldBigInt(key, "handle_key"), PSS_HANDLE_TAG, fieldBigInt(requestId, "request_id")]);
}

/** What the user's n-th request leaves as its handle. */
export interface HandleSecrets {
  n: number;
  /** The handle's partial-note randomness: the request function's
   * `handle_rho`, the delivered note's randomness. */
  handleRho: FieldHexString;
  /** The handle's AEAD key. */
  handleKey: FieldHexString;
}

/** The handle secrets of the user's n-th request in `namespace`. */
export async function handleSecrets(walletSecret: FieldLike, namespace: FieldLike, n: number): Promise<HandleSecrets> {
  if (!Number.isSafeInteger(n) || n < 0) throw new RangeError("n: a non-negative integer");
  const derive = (label: bigint) => hashFields([label, fieldBigInt(walletSecret, "wallet_secret"), fieldBigInt(namespace, "namespace"), BigInt(n)]);
  return { n, handleRho: fieldHex(await derive(PSS_HANDLE_RANDOMNESS)), handleKey: fieldHex(await derive(PSS_HANDLE_KEY)) };
}

/** A request's handle about to be committed (SecretStore.handle): its
 * secrets, its partial commitment, and where each goes. */
export interface NextHandle extends HandleSecrets {
  /** The handle's owner, the request function's sender. */
  owner: FieldHexString;
  /** `handle_partial` = partialCommitment(owner, handleRho). */
  handlePartial: FieldHexString;
  /** Merge into the request's named inputs, which C commits to. */
  inputs: { [HANDLE_PARTIAL_NAME]: FieldHexString; [HANDLE_KEY_NAME]: FieldHexString };
  /** The request function's argument in the partial commitment's place
   * (requestIntake's `values`): `handleRho`, from which the function
   * computes the commitment itself. */
  values: { [HANDLE_PARTIAL_NAME]: FieldHexString };
}

/** The handle of `secrets` for `owner`. */
export async function nextHandle(secrets: HandleSecrets, owner: FieldLike | AztecAddress): Promise<NextHandle> {
  const handlePartial = fieldHex(await partialCommitment(owner, secrets.handleRho));
  const o = owner instanceof AztecAddress ? owner.toBigInt() : fieldBigInt(owner, "owner");
  return {
    ...secrets,
    owner: fieldHex(o),
    handlePartial,
    inputs: { [HANDLE_PARTIAL_NAME]: handlePartial, [HANDLE_KEY_NAME]: secrets.handleKey },
    values: { [HANDLE_PARTIAL_NAME]: secrets.handleRho },
  };
}

/** What opens a delivery and rebuilds its note. */
export interface DeliveryKeys {
  /** The handle's key. */
  handleKey: FieldLike;
  /** The handle's owner (an account in the user's PXE) and randomness. */
  owner: FieldLike;
  handleRho: FieldLike;
  /** The app's outcome note storage slot. */
  storageSlot: FieldLike;
  /** The delivered note's packed fields, the request id last (lending's 8). */
  packedLength: number;
}

/** A delivery opened: the note's fields, the request id and the note. */
export interface OpenedDelivery {
  /** The delivered note's fields before the request id. */
  plaintext: bigint[];
  /** The request id of the round that delivered it. */
  requestId: FieldHexString;
  note: OutcomeNote;
}

/** Open a delivery log's fields (the siloed tag first) under the nonce of
 * the note hash it carries and rebuild its note: the completion of
 * partialCommitment(owner, handleRho) with the opened packed fields, which
 * must be the logged note hash. TagMismatchError when it does not open
 * under the key; NoteMismatchError when the rebuilt note is not the logged
 * one (another owner, randomness or storage slot); RangeError when it is
 * not a full private log or the note does not fit. */
export async function openDeliveryLog(fields: readonly FieldLike[], keys: DeliveryKeys): Promise<OpenedDelivery> {
  const n = keys.packedLength;
  if (!Number.isInteger(n) || n < 2 || n > MAX_NOTE_PACKED_LEN) throw new RangeError(`packedLength: 2 to ${MAX_NOTE_PACKED_LEN} fields`);
  // a delivery's log has an outcome log's layout
  const { noteHash: logged, ciphertext } = parseOutcomeLog(fields, n);
  // a delivery is sealed in the opened domain only (pss_core
  // tip/handle.nr), so the mismatch domain is never tried: no round seals a
  // handle's packed fields there
  const packed = await openSealed(ciphertext, keys.handleKey, logged, true);
  const plaintext = packed.slice(0, -1);
  const requestId = packed[packed.length - 1]!;
  const partial = await partialCommitment(keys.owner, keys.handleRho);
  const noteHash = fieldHex(await completedNoteHash(keys.storageSlot, partial, plaintext, requestId));
  if (BigInt(noteHash) !== BigInt(logged)) throw new NoteMismatchError(logged, noteHash);
  return {
    plaintext,
    requestId: fieldHex(requestId),
    note: {
      owner: fieldHex(keys.owner, "owner"),
      storageSlot: fieldHex(keys.storageSlot, "storage_slot"),
      randomness: fieldHex(keys.handleRho, "handle_rho"),
      packed: packed.map((v, i) => fieldHex(v, `note[${i}]`)),
      noteHash,
    },
  };
}

/** A delivery found on the chain: opened, with its transaction (the shape
 * discovery.ts outcomeDeliveryArgs takes). */
export interface FoundDelivery extends OpenedDelivery {
  tx: FoundOutcome["tx"];
}

// How the user reads a delivery. By request id (read): the siloed tag of
// handleTag(handle key, request id), the private logs under it with their
// transaction effects (one getPrivateLogsByTags call), the first that opens
// under the handle's key to the note the keys rebuild. A request lands
// once, so one tag carries at most one delivery; a filler never carries a
// user's tag. In a known transaction (readIn): its private logs, the first
// that opens under the handle's key, which must rebuild to the note it
// carries and sit under the tag of the request id it holds; the other logs
// of the transaction (the requester's outcome, fillers, other deliveries)
// do not open under the key and are passed over.
/** Finds a delivery to a handle, opens it and rebuilds its note. */
export class DeliveryReader {
  private readonly node: PrivateLogNode;
  private readonly contract: AztecAddress;

  constructor(node: PrivateLogNode, contract: FieldLike | AztecAddress) {
    this.node = node;
    this.contract = fieldAddress(contract, "contract");
  }

  /** The delivery to the handle `keys` opens made by the round of chain
   * request `requestId`, with its transaction; undefined when there is none.
   * When logs carry the tag but none opens to the keys' note, the last
   * TagMismatchError or NoteMismatchError is thrown. */
  async read(keys: DeliveryKeys, requestId: FieldLike): Promise<FoundDelivery | undefined> {
    const tag = new SiloedTag(await outcomeLogTag(this.contract, await handleTag(keys.handleKey, requestId)));
    const [logs] = await this.node.getPrivateLogsByTags({ tags: [tag], includeEffects: true });
    let last: unknown;
    for (const log of logs ?? []) {
      try {
        const opened = await openDeliveryLog(log.logData, keys);
        return { ...opened, tx: logTx(log) };
      } catch (e) {
        if (!(e instanceof TagMismatchError) && !(e instanceof NoteMismatchError) && !(e instanceof RangeError)) throw e;
        last = e;
      }
    }
    if (last !== undefined) throw last;
    return undefined;
  }

  /** The delivery to the handle `keys` opens among the private logs of
   * transaction `tx` (its effects, as a block's body carries them), with no
   * tag query; undefined when no log opens under the handle's key. A log
   * that opens but rebuilds another note (NoteMismatchError) or sits under
   * another tag than handleTag(key, its request id) siloed with the app's
   * address is thrown when no other log is the delivery. */
  async readIn(keys: DeliveryKeys, tx: TxEffects): Promise<FoundDelivery | undefined> {
    let last: unknown;
    for (const log of tx.privateLogs) {
      const fields = log.fields.slice(0, log.emittedLength);
      if (fields.length !== OUTCOME_LOG_FIELDS) continue;
      let opened: OpenedDelivery;
      try {
        opened = await openDeliveryLog(fields, keys);
      } catch (e) {
        if (e instanceof TagMismatchError) continue;
        if (!(e instanceof NoteMismatchError)) throw e;
        last = e;
        continue;
      }
      const tag = await outcomeLogTag(this.contract, await handleTag(keys.handleKey, opened.requestId));
      if (!fields[0]!.equals(tag)) {
        last = new Error(`a delivery to the handle (request ${opened.requestId}) is logged under ${fields[0]}, not under the handle's tag ${tag}`);
        continue;
      }
      return { ...opened, tx: logTx(tx) };
    }
    if (last !== undefined) throw last;
    return undefined;
  }
}
