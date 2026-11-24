// Nonce mining, once the round's transaction is mined: the protocol nonce of each note hash a
// PSS contract function pushed, recovered from the mined transaction's effects
// and checked against the leaf the chain holds.
//
// A note-hash leaf is computeUniqueNoteHash(nonce, siloNoteHash(contract,
// inner_note_hash)) with nonce = computeNoteHashNonce(first nullifier of the
// tx, index of the note hash in the tx). The sidecar and the contract need the
// nonce to recompose the leaf in a later round (as in<i>_nonce), and it can
// only be derived from the creating transaction.

import { Fr } from "@aztec-labs/aztec.js/fields";
import { computeNoteHashNonce, computeUniqueNoteHash, siloNoteHash, siloNullifier } from "@aztec-labs/stdlib/hash";

import { fieldAddress, fieldFr, fieldHex, type FieldLike } from "./field.ts";

/** The parts of a mined transaction's effects that nonce mining reads. */
export interface TxEffectLike {
  txHash?: { toString(): string } | string;
  nullifiers: FieldLike[];
  noteHashes: FieldLike[];
}

/** The note-hash index a contract function documents for a PSS note, and the
 * inner note hash the proof output for it (effects.new_note_hashes[j]). */
export interface ExpectedNote {
  index: number;
  innerNoteHash: FieldLike;
}

/** What the user stores per key the network holds: the inner note hash (or
 * the state record's note_hash), its nonce and the creating tx hash. */
export interface MinedNote {
  index: number;
  inner_note_hash: Fr;
  nonce: Fr;
  leaf: Fr;
  tx_hash: string;
}

/** Read nullifiers and note hashes from `node.getTxEffect(txHash)`'s answer
 * (an IndexedTxEffect, whose `data` is the TxEffect). */
export function txEffectFrom(inBlock: unknown): TxEffectLike {
  if (!inBlock) throw new RangeError("no tx effect");
  const e = ((inBlock as { data?: unknown }).data ?? inBlock) as TxEffectLike;
  if (!Array.isArray(e.nullifiers) || !Array.isArray(e.noteHashes)) {
    throw new RangeError("tx effect: no nullifiers or note hashes");
  }
  return e;
}

// Nonce mining indices. A PSS note's nonce is computed at the index the
// contract function documents for it in the transaction's note hashes
// (pss_contract::apply pushes its note hashes after anything the function
// pushed before the call, in new_note_hashes order). The AMM example
// documents: init_pool 0 = seed note, 1 = anchor; start_pool 0 = pool note;
// swap 0 = new pool note. The caller passes the index per note. The leaf is
// always checked against the chain's note hash at that index, so a wrong
// index fails here rather than producing a nonce whose leaf is not in the
// tree (which the next round would only discover in the kernel). A function
// that pushes other note hashes before apply moves every index.
/** Mine the nonce of each expected note from a mined transaction's effects.
 * `firstNullifier` defaults to the effect's first nullifier and must equal it
 * when given. Throws, naming the index, when a recomposed leaf is not the
 * chain's note hash at that index. */
export async function mineNonces(
  txEffect: TxEffectLike,
  firstNullifier: FieldLike | undefined,
  expectedInnerNoteHashes: ExpectedNote[],
  contractAddress: FieldLike,
): Promise<MinedNote[]> {
  if (txEffect.nullifiers.length === 0) throw new RangeError("tx effect: no nullifiers");
  const first = fieldFr(txEffect.nullifiers[0]!, "nullifiers[0]");
  if (firstNullifier !== undefined && !fieldFr(firstNullifier, "firstNullifier").equals(first)) {
    throw new RangeError(`first nullifier ${fieldHex(firstNullifier)} is not the tx's first nullifier ${first}`);
  }
  const contract = fieldAddress(contractAddress, "contractAddress");
  const txHash = txEffect.txHash === undefined ? "" : txEffect.txHash.toString();
  const out: MinedNote[] = [];
  for (const { index, innerNoteHash } of expectedInnerNoteHashes) {
    if (!Number.isInteger(index) || index < 0) throw new RangeError(`note index ${index}: not a non-negative integer`);
    const inner = fieldFr(innerNoteHash, `note ${index}`);
    const nonce = await computeNoteHashNonce(first, index);
    const leaf = await computeUniqueNoteHash(nonce, await siloNoteHash(contract, inner));
    const onChain = txEffect.noteHashes[index];
    if (onChain === undefined || !leaf.equals(fieldFr(onChain, `noteHashes[${index}]`))) {
      throw new RangeError(
        `note ${index}: leaf ${leaf} of inner note hash ${inner} does not match note hash ${index} of the tx (${onChain === undefined ? "none" : fieldHex(onChain)})`,
      );
    }
    out.push({ index, inner_note_hash: inner, nonce, leaf, tx_hash: txHash });
  }
  return out;
}

// The anchoredNonce pattern. State many parties must read (the AMM's Config,
// which pins npk_app_hash) is a raw note hash the contract pushed once; a
// reader hashes the published preimage, takes the creating transaction's
// first nullifier, computes the nonce at the documented index and checks the
// leaf is that transaction's note hash at that index. The check is mandatory:
// anchoredNonce throws rather than return an unchecked nonce. The preimage
// comes from the operator off chain, and this check is what makes a
// substituted preimage fail before any transaction is built.
/** The nonce of the raw note hash `noteHash` that a transaction pushed at
 * `index`, checked against the chain's leaf. */
export async function anchoredNonce(
  effects: TxEffectLike,
  index: number,
  contractAddress: FieldLike,
  noteHash: FieldLike,
  what = "anchor",
): Promise<Fr> {
  try {
    const [mined] = await mineNonces(effects, undefined, [{ index, innerNoteHash: noteHash }], contractAddress);
    return mined!.nonce;
  } catch (e) {
    throw new RangeError(`${what}: ${(e as Error).message}`);
  }
}

/** Check that a consumed note's nullifier, siloed with the contract address,
 * is among the transaction's nullifiers; returns the siloed value. */
export async function checkNullified(effects: TxEffectLike, contractAddress: FieldLike, nullifier: FieldLike, what = "note"): Promise<Fr> {
  const siloed = await siloNullifier(fieldAddress(contractAddress, "contractAddress"), fieldFr(nullifier, "nullifier"));
  if (!effects.nullifiers.some((n) => fieldFr(n, "nullifier").equals(siloed))) {
    throw new RangeError(`${what}: the tx lacks nullifier ${siloed} (siloed from ${fieldHex(nullifier)})`);
  }
  return siloed;
}
