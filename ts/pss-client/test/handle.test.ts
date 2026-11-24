// The standing delivery handle, the client side (src/handle.ts): the handle a
// request leaves (SecretStore.handle), and a delivery to it found under the
// delivering round's request id, or among the private logs of a known
// transaction, opened and rebuilt as the recipient's note (DeliveryReader
// over a mocked log source, or a transaction's effects, holding a delivery
// log as pss_public_contract's handle::Delivered emits it), and the owner's
// walk from a spent exit tag to the notice its spender delivered (hatch.ts
// recoverExitNote). The labels are pss_core tip/handle.nr's.

import assert from "node:assert/strict";
import { describe, test } from "node:test";

import { AztecAddress } from "@aztec-labs/aztec.js/addresses";
import { Fr } from "@aztec-labs/foundation/curves/bn254";
import { siloNullifier } from "@aztec-labs/stdlib/hash";

import {
  aeEncrypt,
  completedNoteHash,
  DeliveryReader,
  exitTagOf,
  fieldHex,
  HANDLE_KEY_NAME,
  HANDLE_PARTIAL_NAME,
  handleSecrets,
  NoteMismatchError,
  handleTag,
  hashFields,
  openDeliveryLog,
  outcomeLogFields,
  partialCommitment,
  PSS_HANDLE_KEY,
  PSS_HANDLE_RANDOMNESS,
  PSS_HANDLE_TAG,
  recoverExitNote,
  SecretStore,
  sealNonce,
  TagMismatchError,
  type ExitNote,
  type PrivateLogNode,
  type TxEffects,
} from "../src/internal.ts";
import { encryptOutcome, logNode, spenderNode } from "@aztec-pss/test-support";

const CONTRACT = 0xc0ffeen;
const WALLET = 0xa11ce5ecn;
const OWNER = 0xa11cen;
const SLOT = 0x2an;
const REQUEST = 0x1dn;
// a seven-field note, the request id packed after it
const FIELDS = [0n, 1n, 1_000_000_017n, 554n, 851n, 0n, 0x4a1n];

/** The delivered note's hash: the handle's partial note (OWNER under
 * `handleRho`) completed with FIELDS and REQUEST. */
async function deliveredNoteHash(handleRho: string): Promise<bigint> {
  return completedNoteHash(SLOT, await partialCommitment(OWNER, handleRho), FIELDS, REQUEST);
}

/** The delivery log a result emits to the handle `key` of randomness
 * `handleRho`: the note's hash, then its packed fields `[fields...,
 * request_id]` under the key with that note hash's nonce, under
 * handleTag(key, REQUEST), padded as an outcome log is. */
async function deliveryLog(key: bigint, handleRho: string, tagRequest = REQUEST): Promise<bigint[]> {
  const tag = await handleTag(key, tagRequest);
  const noteHash = await deliveredNoteHash(handleRho);
  return outcomeLogFields(CONTRACT, tag, noteHash, await encryptOutcome([...FIELDS, REQUEST], key, noteHash));
}

describe("the delivery handle", () => {
  test("the labels are pss_core's and the tag is poseidon2([key, PSS_HANDLE_TAG, request_id])", async () => {
    assert.equal(PSS_HANDLE_TAG, 0x7073732e68616e646c655f746167n);
    assert.equal(PSS_HANDLE_RANDOMNESS, 0x7073732e68616e646c655f72616e646f6d6e657373n);
    assert.equal(PSS_HANDLE_KEY, 0x7073732e68616e646c655f6b6579n);
    assert.equal(await handleTag(0x6bn, REQUEST), await hashFields([0x6bn, PSS_HANDLE_TAG, REQUEST]));
    // each delivering round logs under a tag of its own
    assert.notEqual(await handleTag(0x6bn, REQUEST), await handleTag(0x6bn, REQUEST + 1n));
    assert.notEqual(await handleTag(0x6bn, REQUEST), await handleTag(0x6cn, REQUEST));
  });

  test("a request's handle derives from its counter and commits its owner", async () => {
    const store = new SecretStore(WALLET, CONTRACT);
    const h = await store.handle(OWNER, 3);
    const s = await handleSecrets(WALLET, CONTRACT, 3);
    assert.equal(h.handleRho, fieldHex(await hashFields([PSS_HANDLE_RANDOMNESS, WALLET, CONTRACT, 3n])));
    assert.equal(h.handleKey, fieldHex(await hashFields([PSS_HANDLE_KEY, WALLET, CONTRACT, 3n])));
    assert.deepEqual([h.handleRho, h.handleKey], [s.handleRho, s.handleKey]);
    assert.equal(h.handlePartial, fieldHex(await partialCommitment(OWNER, h.handleRho)));
    assert.deepEqual(h.inputs, { [HANDLE_PARTIAL_NAME]: h.handlePartial, [HANDLE_KEY_NAME]: h.handleKey });
    assert.deepEqual(h.values, { [HANDLE_PARTIAL_NAME]: h.handleRho });
    // another counter, another handle; taking a handle does not move the counter
    assert.notEqual((await store.handle(OWNER, 4)).handleKey, h.handleKey);
    assert.equal(await store.peek(), 0);
  });

  test("the owner finds its delivery, opens it and rebuilds the note the round completed", async () => {
    const h = await handleSecrets(WALLET, CONTRACT, 0);
    const key = BigInt(h.handleKey);
    const keys = { handleKey: key, owner: OWNER, handleRho: h.handleRho, storageSlot: SLOT, packedLength: 8 };
    const found = await new DeliveryReader(logNode([await deliveryLog(key, h.handleRho)]), CONTRACT).read(keys, REQUEST);
    assert.ok(found);
    assert.deepEqual(found.plaintext, FIELDS);
    assert.equal(found.requestId, fieldHex(REQUEST));
    assert.deepEqual(found.note.packed, [...FIELDS, REQUEST].map((v) => fieldHex(v)));
    assert.equal(found.note.randomness, h.handleRho);
    const partial = await partialCommitment(OWNER, h.handleRho);
    assert.equal(found.note.noteHash, fieldHex(await completedNoteHash(SLOT, partial, FIELDS, REQUEST)));
    assert.equal(found.tx.firstNullifier, fieldHex(0x99n));
    // no log under another handle's tag
    const other = await handleSecrets(WALLET, CONTRACT, 1);
    assert.equal(await new DeliveryReader(logNode([await deliveryLog(key, h.handleRho)]), CONTRACT).read({ ...keys, handleKey: other.handleKey }, REQUEST), undefined);
    // no log under another request id's tag: the delivery is the round of REQUEST's
    assert.equal(await new DeliveryReader(logNode([await deliveryLog(key, h.handleRho)]), CONTRACT).read(keys, REQUEST + 1n), undefined);
  });

  test("a rebuild that is not the note the log carries is refused; another key does not open it", async () => {
    const h = await handleSecrets(WALLET, CONTRACT, 0);
    const key = BigInt(h.handleKey);
    const log = await deliveryLog(key, h.handleRho);
    const keys = { handleKey: key, owner: OWNER, handleRho: h.handleRho, storageSlot: SLOT, packedLength: 8 };
    const owner = await openDeliveryLog(log, keys);
    assert.equal(owner.note.noteHash, fieldHex(log[1]!));
    // another owner, randomness or slot opens the log but rebuilds another note
    for (const wrong of [{ owner: 0xb0bn }, { handleRho: fieldHex(BigInt(h.handleRho) + 1n) }, { storageSlot: SLOT + 1n }]) {
      await assert.rejects(openDeliveryLog(log, { ...keys, ...wrong }), NoteMismatchError);
      await assert.rejects(new DeliveryReader(logNode([log]), CONTRACT).read({ ...keys, ...wrong }, REQUEST), NoteMismatchError);
    }
    await assert.rejects(openDeliveryLog(log, { ...keys, handleKey: key + 1n }), TagMismatchError);
    await assert.rejects(openDeliveryLog(log.slice(1), keys), RangeError);
  });

  test("a delivery opens in the opened domain only, never the mismatch domain", async () => {
    const h = await handleSecrets(WALLET, CONTRACT, 0);
    const key = BigInt(h.handleKey);
    const noteHash = await deliveredNoteHash(h.handleRho);
    const sealed = await aeEncrypt(key, await sealNonce(noteHash, false), [...FIELDS, REQUEST]);
    const log = await outcomeLogFields(CONTRACT, await handleTag(key, REQUEST), noteHash, [...sealed.ciphertext, sealed.tag]);
    const keys = { handleKey: key, owner: OWNER, handleRho: h.handleRho, storageSlot: SLOT, packedLength: 8 };
    await assert.rejects(openDeliveryLog(log, keys), TagMismatchError);
  });
});

/** A transaction's effects holding `logs`, each padded to a private log's
 * 16 fields with how many it emitted. */
function txOf(logs: bigint[][]): TxEffects {
  return {
    txHash: { toString: () => fieldHex(0x7777n) },
    noteHashes: [new Fr(0x4an)],
    nullifiers: [new Fr(0x99n), new Fr(0x9an)],
    privateLogs: logs.map((l) => ({ fields: [...l, ...Array(16 - l.length).fill(0n)].map((f) => new Fr(f)), emittedLength: l.length })),
  };
}

describe("a delivery in a known transaction", () => {
  test("the owner finds it among the transaction's logs and reads the request id from it", async () => {
    const h = await handleSecrets(WALLET, CONTRACT, 0);
    const key = BigInt(h.handleKey);
    const keys = { handleKey: key, owner: OWNER, handleRho: h.handleRho, storageSlot: SLOT, packedLength: 8 };
    const other = await handleSecrets(WALLET, CONTRACT, 1);
    // another handle's delivery and a short log come first
    const tx = txOf([await deliveryLog(BigInt(other.handleKey), other.handleRho), [0x1n, 0x2n, 0x3n], await deliveryLog(key, h.handleRho)]);
    const reader = new DeliveryReader(logNode([]), CONTRACT);
    const found = await reader.readIn(keys, tx);
    assert.ok(found);
    assert.deepEqual(found.plaintext, FIELDS);
    assert.equal(found.requestId, fieldHex(REQUEST));
    assert.equal(found.note.noteHash, fieldHex(await deliveredNoteHash(h.handleRho)));
    assert.deepEqual(found.tx, { txHash: fieldHex(0x7777n), uniqueNoteHashes: [fieldHex(0x4an)], firstNullifier: fieldHex(0x99n) });
    // the same as the reader by request id finds
    const byTag = await new DeliveryReader(logNode([await deliveryLog(key, h.handleRho)]), CONTRACT).read(keys, REQUEST);
    assert.deepEqual({ ...found, tx: undefined }, { ...byTag, tx: undefined });
    // a transaction with no delivery to this handle
    assert.equal(await reader.readIn(keys, txOf([await deliveryLog(BigInt(other.handleKey), other.handleRho)])), undefined);
    assert.equal(await reader.readIn(keys, txOf([])), undefined);
  });

  test("a delivery that rebuilds another note, or sits under another tag, is refused", async () => {
    const h = await handleSecrets(WALLET, CONTRACT, 0);
    const key = BigInt(h.handleKey);
    const keys = { handleKey: key, owner: OWNER, handleRho: h.handleRho, storageSlot: SLOT, packedLength: 8 };
    const reader = new DeliveryReader(logNode([]), CONTRACT);
    await assert.rejects(reader.readIn({ ...keys, storageSlot: SLOT + 1n }, txOf([await deliveryLog(key, h.handleRho)])), NoteMismatchError);
    // opens to the note it carries, under the tag of another request id than the one it holds
    await assert.rejects(reader.readIn(keys, txOf([await deliveryLog(key, h.handleRho, REQUEST + 1n)])), /not under the handle's tag/);
    // and another app's: the tag is siloed with the app's address
    await assert.rejects(new DeliveryReader(logNode([]), CONTRACT + 1n).readIn(keys, txOf([await deliveryLog(key, h.handleRho)])), /not under the handle's tag/);
    // a good delivery after a bad one is found
    assert.ok(await reader.readIn(keys, txOf([await deliveryLog(key, h.handleRho, REQUEST + 1n), await deliveryLog(key, h.handleRho)])));
  });
});

describe("the recovery walk (hatch.ts recoverExitNote)", () => {
  // The owner's newest note of entry 1 (FIELDS[1]), from request 0x0d; a
  // round of request REQUEST spent its tag and delivered FIELDS to the
  // entry's handle.
  const ENTRY_FIELD = 1;
  const first: ExitNote = { owner: OWNER, rho: 0x5eedn, requestId: 0x0dn, entry: 1n };

  /** `tx` holding the app's nullifier of `note`'s tag. */
  async function spending(note: ExitNote, logs: bigint[][], hash: bigint): Promise<TxEffects> {
    const siloed = await siloNullifier(AztecAddress.fromBigIntUnsafe(CONTRACT), await exitTagOf(note));
    return { ...txOf(logs), txHash: { toString: () => fieldHex(hash) }, nullifiers: [new Fr(hash), siloed] };
  }

  /** A node whose block 40 + k holds `txs[k]`, with no private logs. */
  function chain(txs: TxEffects[]): ReturnType<typeof spenderNode> & PrivateLogNode {
    return Object.assign(spenderNode(txs.map((t, k) => ({ number: 40 + k, txs: [t] }))), { getPrivateLogsByTags: async () => [] });
  }

  test("follows a notice to the note an exit takes, or stops at a tag spent with no delivery", async () => {
    const h = await handleSecrets(WALLET, CONTRACT, 0);
    const handle = { handleKey: BigInt(h.handleKey), owner: OWNER, handleRho: h.handleRho, storageSlot: SLOT, packedLength: 8 };
    const notice: ExitNote = { owner: OWNER, rho: h.handleRho, requestId: fieldHex(REQUEST), entry: 1n };
    const landing = await spending(first, [await deliveryLog(BigInt(h.handleKey), h.handleRho)], 0x5an);

    // the notice's tag unspent: it is the note an exit takes
    const seen: ExitNote[] = [];
    const live = await recoverExitNote({ node: chain([landing]), app: CONTRACT, note: first, handle, entryField: ENTRY_FIELD, onNotice: async (_, n) => void seen.push(n) });
    assert.equal(live.status, "live");
    assert.deepEqual(live.note, notice);
    assert.deepEqual(seen, [notice]);
    assert.deepEqual(live.notices.map((f) => f.requestId), [fieldHex(REQUEST)]);

    // the notice's tag spent by a transaction with no delivery to the handle:
    // the owner's own exit, or a round of its own
    const exit = await spending(notice, [], 0x5bn);
    const spent = await recoverExitNote({ node: chain([landing, exit]), app: CONTRACT, note: first, handle });
    assert.equal(spent.status, "spent-by-owner");
    assert.deepEqual(spent.note, notice);
    assert.equal(spent.notices.length, 1);
    if (spent.status === "spent-by-owner") assert.equal(spent.spent.block, 41);

    // an entry that holds no handle: a spent tag ends the walk at once
    const bare = await recoverExitNote({ node: chain([landing]), app: CONTRACT, note: first });
    assert.equal(bare.status, "spent-by-owner");
    assert.deepEqual(bare.notices, []);

    // the first note's tag unspent: nothing to walk
    const none = await recoverExitNote({ node: chain([]), app: CONTRACT, note: first, handle });
    assert.deepEqual({ status: none.status, notices: none.notices }, { status: "live", notices: [] });

    // the tags are read at the proposed tip, or at the caller's block
    const node = chain([landing]);
    await recoverExitNote({ node, app: CONTRACT, note: first, handle });
    await recoverExitNote({ node, app: CONTRACT, note: first, handle, at: "checkpointed" });
    assert.deepEqual(node.at, ["proposed", "proposed", "checkpointed", "checkpointed"]);

    // a notice of another entry, and a walk past the bound, are refused
    const second = { ...first, entry: 2n };
    const elsewhere = await spending(second, [await deliveryLog(BigInt(h.handleKey), h.handleRho)], 0x5cn);
    await assert.rejects(recoverExitNote({ node: chain([elsewhere]), app: CONTRACT, note: second, handle, entryField: ENTRY_FIELD }), /names entry 1, not 2/);
    await assert.rejects(recoverExitNote({ node: chain([landing]), app: CONTRACT, note: first, handle, maxNotices: 0 }), /more than 0 notices/);
  });
});
