// These tests build a synthetic tx effect with the same @aztec-labs/stdlib
// functions the chain's kernel uses and check that mining recovers the nonces
// and refuses a wrong index. siloNoteHash is tied to the Rust side by its known answer in
// machine/sidecar-core/src/hash.rs.

import assert from "node:assert/strict";
import { describe, test } from "node:test";

import { AztecAddress } from "@aztec-labs/aztec.js/addresses";
import { Fr } from "@aztec-labs/aztec.js/fields";
import { poseidon2HashWithSeparator } from "@aztec-labs/foundation/crypto/poseidon";
import { computeNoteHashNonce, computeUniqueNoteHash, siloNoteHash, siloNullifier } from "@aztec-labs/stdlib/hash";

import { anchoredNonce, checkNullified, mineNonces, txEffectFrom, type TxEffectLike } from "../src/internal.ts";

const CONTRACT = "0x1ac1704880851219793ebcb14b7d910d576186d4846fa8b42b51108ebd236888";
const contract = AztecAddress.fromStringUnsafe(CONTRACT);

// A tx in which the contract pushed [seed note, anchor] after one unrelated
// note hash index: like init_pool, but with the PSS notes at indices 1 and 2.
async function syntheticTx() {
  const firstNullifier = new Fr(0x5eed_0001n);
  const consumed = new Fr(0xdead_beefn);
  const inner = [new Fr(0x1111n), new Fr(0x2222n), new Fr(0x3333n)];
  const noteHashes: Fr[] = [];
  for (const [i, h] of inner.entries()) {
    const nonce = await computeNoteHashNonce(firstNullifier, i);
    noteHashes.push(await computeUniqueNoteHash(nonce, await siloNoteHash(contract, h)));
  }
  const effect: TxEffectLike = {
    txHash: "0x" + "ab".repeat(32),
    nullifiers: [firstNullifier, await siloNullifier(contract, consumed)],
    noteHashes,
  };
  return { firstNullifier, consumed, inner, effect };
}

describe("nonce mining", () => {
  test("siloNoteHash matches sidecar-core's known answer", async () => {
    const h = await siloNoteHash(AztecAddress.fromBigIntUnsafe(0xc0ffeen), new Fr(0x1234n));
    assert.equal(h.toString(), "0x07b3cb8631f5db484a19696369f2ad2e123fa64cc0d95375db1ee76d87742014");
    // and it is poseidon2 with DOM_SEP__SILOED_NOTE_HASH, as the Rust test states
    const p = await poseidon2HashWithSeparator([new Fr(0xc0ffeen), new Fr(0x1234n)], 3361878420);
    assert.ok(p.equals(h));
  });

  test("mines the nonce at each documented index and checks the leaf", async () => {
    const { firstNullifier, inner, effect } = await syntheticTx();
    const mined = await mineNonces(effect, firstNullifier, [
      { index: 1, innerNoteHash: inner[1]! },
      { index: 2, innerNoteHash: inner[2]!.toString() },
    ], CONTRACT);
    assert.equal(mined.length, 2);
    for (const m of mined) {
      assert.ok(m.nonce.equals(await computeNoteHashNonce(firstNullifier, m.index)));
      assert.ok(m.leaf.equals(effect.noteHashes[m.index] as Fr));
      assert.equal(m.tx_hash, effect.txHash);
    }
    assert.ok(mined[0]!.inner_note_hash.equals(inner[1]!));
    // the first nullifier defaults to the effect's own
    const again = await mineNonces(effect, undefined, [{ index: 0, innerNoteHash: inner[0]! }], contract.toString());
    assert.ok(again[0]!.leaf.equals(effect.noteHashes[0] as Fr));
  });

  test("refuses a wrong index, a wrong note, a wrong contract and a wrong first nullifier", async () => {
    const { firstNullifier, inner, effect } = await syntheticTx();
    await assert.rejects(mineNonces(effect, undefined, [{ index: 2, innerNoteHash: inner[1]! }], CONTRACT), /note 2: leaf .* does not match note hash 2/);
    await assert.rejects(mineNonces(effect, undefined, [{ index: 5, innerNoteHash: inner[1]! }], CONTRACT), /\(none\)/);
    await assert.rejects(mineNonces(effect, undefined, [{ index: 1, innerNoteHash: inner[1]! }], 0xc0ffee), /does not match/);
    await assert.rejects(mineNonces(effect, firstNullifier.add(new Fr(1n)), [{ index: 1, innerNoteHash: inner[1]! }], CONTRACT), /not the tx's first nullifier/);
  });

  test("anchoredNonce and checkNullified", async () => {
    const { consumed, inner, effect } = await syntheticTx();
    const nonce = await anchoredNonce(effect, 2, CONTRACT, inner[2]!, "anchor");
    assert.ok(nonce.equals(await computeNoteHashNonce(effect.nullifiers[0] as Fr, 2)));
    await assert.rejects(anchoredNonce(effect, 1, CONTRACT, inner[2]!, "anchor"), /^RangeError: anchor: note 1/);
    const siloed = await checkNullified(effect, CONTRACT, consumed, "seed note");
    assert.ok(siloed.equals(effect.nullifiers[1] as Fr));
    await assert.rejects(checkNullified(effect, CONTRACT, new Fr(1n), "seed note"), /seed note: the tx lacks nullifier/);
  });

  test("txEffectFrom reads an IndexedTxEffect or a bare TxEffect", async () => {
    const { effect } = await syntheticTx();
    assert.equal(txEffectFrom({ data: effect, l2BlockNumber: 7 }), effect);
    assert.equal(txEffectFrom(effect), effect);
    assert.throws(() => txEffectFrom(undefined), /no tx effect/);
  });
});
