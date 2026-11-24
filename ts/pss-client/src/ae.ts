// The field-native authenticated encryption every sealed value uses: the
// Poseidon2 duplex (SAFE sponge) of pss_utils/src/ae.nr, generalised to any
// number of plaintext fields, as machine/sidecar-core/src/ae.rs defines it.
//
//   state = permutation([key, nonce, 0, patternTag(n)])
//   for each block of up to 3 fields (fields 3b .. 3b+k):
//       if b > 0: state = permutation(state)
//       for j in 0..k: state[j] += pt[3b + j]; ct[3b + j] = state[j]
//   tag = permutation(state)[0]
//
// Decryption runs the same transitions with pt = ct - state[j] and
// state[j] = ct, and refuses a tag that differs: ae.nr's AE::encrypt and
// AE::decrypt; an INPUT_SHARED envelope is n = 2. The tag comparison is not
// constant-time: the party decrypting holds the key and nothing remote
// observes its timing.

import { poseidon2Hash, poseidon2Permutation } from "@aztec-labs/foundation/crypto/poseidon";
import { Fr } from "@aztec-labs/foundation/curves/bn254";

import { fieldBigInt, modR, type FieldLike } from "./field.ts";

/** Fields per duplex block: the sponge's rate. */
export const RATE = 3;

// The AEAD pattern tags. The capacity element of the initial state carries
// the SAFE IO pattern of the call, so a ciphertext of one length never
// decrypts as another length: ae.nr's domain separator 0x4142, the words
// packed into one field for up to two blocks (n <= 6), hashed beyond, exactly
// as sidecar-core's ae.rs. Changing any of it changes every ciphertext:
// envelopes the nodes can no longer open and records that no longer
// authenticate.
/** The domain separator appended to every IO pattern. */
export const DOMAIN_SEPARATOR = 0x4142n;
/** The most blocks whose packed pattern still fits one field element. */
export const MAX_PACKED_BLOCKS = 2;

const ABSORB = 0x8000_0000;

/** The SAFE IO-pattern words for `n` plaintext fields, without the domain
 * separator: `[0x80000002, k_0, 0x80000000|k_0, ..., 1]`. */
function patternWords(n: number): number[] {
  if (!Number.isSafeInteger(n) || n < 1) throw new RangeError("the authenticated encryption needs at least one field");
  const words = [ABSORB + 2];
  for (let left = n; left > 0; ) {
    const k = Math.min(left, RATE);
    words.push(k, ABSORB + k);
    left -= k;
  }
  words.push(1);
  return words;
}

/** The capacity element of the initial state for `n` plaintext fields. */
export async function patternTag(n: number): Promise<bigint> {
  const words = patternWords(n);
  if (Math.ceil(n / RATE) <= MAX_PACKED_BLOCKS) {
    const packed = words.reduce((acc, w) => (acc << 32n) + BigInt(w), 0n);
    return (packed << 16n) + DOMAIN_SEPARATOR;
  }
  const h = await poseidon2Hash([...words.map((w) => new Fr(BigInt(w))), new Fr(DOMAIN_SEPARATOR)]);
  return h.toBigInt();
}


async function permute(state: bigint[]): Promise<bigint[]> {
  const out = await poseidon2Permutation(state.map((v) => new Fr(v)));
  return out.map((f) => f.toBigInt());
}

async function initialState(key: bigint, nonce: bigint, n: number): Promise<bigint[]> {
  return permute([key, nonce, 0n, await patternTag(n)]);
}

/** A ciphertext with its authentication tag, as field elements. */
export interface Sealed {
  ciphertext: bigint[];
  tag: bigint;
}

/** Encrypt `plaintext` under `(key, nonce)`. A `(key, nonce)` pair must never
 * encrypt two different plaintexts. */
export async function aeEncrypt(key: FieldLike, nonce: FieldLike, plaintext: FieldLike[]): Promise<Sealed> {
  if (plaintext.length === 0) throw new RangeError("the authenticated encryption needs at least one field");
  const pt = plaintext.map((v, j) => fieldBigInt(v, `plaintext[${j}]`));
  let state = await initialState(fieldBigInt(key, "key"), fieldBigInt(nonce, "nonce"), pt.length);
  const ciphertext: bigint[] = [];
  for (const [i, p] of pt.entries()) {
    if (i > 0 && i % RATE === 0) state = await permute(state);
    const c = modR(state[i % RATE]! + p);
    state[i % RATE] = c;
    ciphertext.push(c);
  }
  const [tag] = await permute(state);
  return { ciphertext, tag: tag! };
}

/** The ciphertext does not open: wrong key, nonce (associated data) or length,
 * or a tampered ciphertext or tag. */
export class TagMismatchError extends Error {
  constructor() {
    super("authentication tag mismatch");
    this.name = "TagMismatchError";
  }
}

/** Decrypt and authenticate. Throws TagMismatchError on an empty ciphertext
 * or a tag that differs; no plaintext is returned then. */
export async function aeDecrypt(key: FieldLike, nonce: FieldLike, ciphertext: FieldLike[], tag: FieldLike): Promise<bigint[]> {
  if (ciphertext.length === 0) throw new TagMismatchError();
  const ct = ciphertext.map((v, j) => fieldBigInt(v, `ciphertext[${j}]`));
  let state = await initialState(fieldBigInt(key, "key"), fieldBigInt(nonce, "nonce"), ct.length);
  const plaintext: bigint[] = [];
  for (const [i, c] of ct.entries()) {
    if (i > 0 && i % RATE === 0) state = await permute(state);
    plaintext.push(modR(c - state[i % RATE]!));
    state[i % RATE] = c;
  }
  state = await permute(state);
  if (state[0] !== fieldBigInt(tag, "tag")) throw new TagMismatchError();
  return plaintext;
}
