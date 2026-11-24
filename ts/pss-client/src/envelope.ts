// INPUT_SHARED envelopes: node i's pair [x_i, x_{i-1}] of a shared input,
// encrypted to node i's pinned `enc` key and bound to the request body, or
// under secret-shared receipt intake to the chain request, as
// machine/sidecar-core/src/envelope.rs defines them.
//
//   x_0, x_1     uniform mod r from the CSPRNG,  x_2 = x - x_0 - x_1
//   pair_i       = [x_i, x_{i-1}]
//   eph          a random nonzero field element, read as a Grumpkin scalar (pss_utils/dh.nr)
//   E            = eph · G
//   S            = (eph · enc_pk_i).x            node i computes (enc_i · E).x
//   nonce        = poseidon2([namespace, request_id, poseidon2_hash_bytes(circuit),
//                             poseidon2_hash_bytes(name), i, input_body_hash])      body AD
//                = poseidon2([namespace, chain_request_id, poseidon2_hash_bytes(circuit),
//                             poseidon2_hash_bytes(name), i, SIDECAR_INTAKE_AD])    intake AD
//   (ct, tag)    = aeEncrypt(S, nonce, pair_i)  ae.nr's AE::encrypt, N = 2
//   envelope     = {eph: E, ct: [ct0, ct1], tag}
//   share_hashes[i] = poseidon2([E.x, E.y, ct0, ct1, tag])
//
// request_id is the request's one field element; input_body_hash is
// inputBodyHash() of request.ts, the canonical body without `shared_inputs`.
// Under secret-shared receipt intake the client cannot know the body the scheduler
// synthesises, so it seals under the intake associated data (intakeEnvelopeAd)
// over the chain request id, before any body exists.

import { Grumpkin } from "@aztec-labs/foundation/crypto/grumpkin";
import { poseidon2Hash, poseidon2HashBytes } from "@aztec-labs/foundation/crypto/poseidon";
import { Fr } from "@aztec-labs/foundation/curves/bn254";
import { GrumpkinScalar, type Point } from "@aztec-labs/foundation/curves/grumpkin";

import { aeDecrypt, aeEncrypt } from "./ae.ts";
import { fieldBigInt, fieldHex, modR, randomField, requestIdHex, type FieldLike } from "./field.ts";
import { curvePoint, ephemeralSecret, ephScalar, type PointInput } from "./grumpkin.ts";
import { asciiLabel } from "./labels.ts";
import { NODES, nodeIndex, type GrumpkinPoint, type ShareCiphertext, type SharedInput, type Triple } from "./wire.ts";


/** A replicated sharing of `x`: x_0 and x_1 uniform mod r from the CSPRNG,
 * x_2 = x - x_0 - x_1, so the three sum to x and any two reveal nothing. */
export function shareField(x: FieldLike): Triple<bigint> {
  const v = fieldBigInt(x, "shared value");
  const x0 = randomField();
  const x1 = randomField();
  return [x0, x1, modR(v - x0 - x1)];
}

/** Node `i`'s pair of a sharing: `[x_i, x_{i-1}]`. */
export function sharePair(sharing: Triple<FieldLike>, i: number): [bigint, bigint] {
  nodeIndex(i);
  const prev = (i + NODES - 1) % NODES;
  return [fieldBigInt(sharing[i]!, `sharing[${i}]`), fieldBigInt(sharing[prev]!, `sharing[${prev}]`)];
}

/** The request id as the field element the associated data carries: the id
 * itself, after the field-element checks of requestIdHex. */
export function requestIdField(requestId: FieldLike): bigint {
  return BigInt(requestIdHex(requestId));
}

/** Everything an envelope's associated data binds except the node index. */
export interface EnvelopeAd {
  namespace: FieldLike;
  /** The request id (body AD) or the chain request id (intake AD). */
  requestId: FieldLike;
  circuit: string;
  /** The shared input's name. */
  name: string;
  /** The last element: inputBodyHash() of the request the envelope belongs
   * to (body AD), or SIDECAR_INTAKE_AD (intake AD). */
  binds: FieldLike;
}

/** SIDECAR_INTAKE_AD, the last element of the intake associated data: ASCII
 * "sidecar.intake" read big-endian as one field element (sidecar-core's
 * envelope.rs). */
export const SIDECAR_INTAKE_AD = asciiLabel("sidecar.intake");

/** The intake associated data of the shared input `name` of the chain
 * request `chainRequestId` of `circuit` under `namespace`: what a secret-shared
 * receipt intake client seals under. A client may seal all of node i's pairs
 * under one ephemeral key: the input name in the nonce keeps every
 * encryption under that key distinct. */
export function intakeEnvelopeAd(namespace: FieldLike, chainRequestId: FieldLike, circuit: string, name: string): EnvelopeAd {
  return { namespace, requestId: chainRequestId, circuit, name, binds: SIDECAR_INTAKE_AD };
}

const bytesHash = async (s: string) => (await poseidon2HashBytes(Buffer.from(s, "utf8"))).toBigInt();

// The envelope's associated data is (namespace, request_id, circuit, input
// name, node index i, input_body_hash), hashed with Poseidon2 into the AE
// nonce slot, the same rule as sidecar-core's EnvelopeAd::nonce. An envelope
// therefore opens only at node i, for this namespace, request, circuit and
// input, and only while every other part of
// the body (public values, keys, record hashes, requester) is the one it was
// sealed under. Consequence for callers: build the whole body before sealing,
// and never edit a sealed body; an edit makes every node refuse the envelope.
// Under secret-shared receipt intake the chain request id stands for request_id and
// SIDECAR_INTAKE_AD for input_body_hash (intakeEnvelopeAd): the chain request
// id commits to C, which covers every input, and stays fixed across the
// recomputes of one queued request; the constant keeps an intake envelope
// from opening as a body envelope.
/** The AE nonce of the envelope to node `i`. */
export async function envelopeNonce(ad: EnvelopeAd, i: number): Promise<bigint> {
  nodeIndex(i);
  const h = await poseidon2Hash([
    new Fr(fieldBigInt(ad.namespace, "namespace")),
    new Fr(requestIdField(ad.requestId)),
    new Fr(await bytesHash(ad.circuit)),
    new Fr(await bytesHash(ad.name)),
    new Fr(BigInt(i)),
    new Fr(fieldBigInt(ad.binds, "associated data")),
  ]);
  return h.toBigInt();
}

const wirePoint = (p: Point): GrumpkinPoint => ({ x: fieldHex(p.x.toBigInt()), y: fieldHex(p.y.toBigInt()) });

/** Seal node `i`'s pair under its pinned `encPk`. `eph` is the ephemeral
 * secret, a nonzero field element read as a Grumpkin scalar; leave it out and
 * a fresh one is drawn from the CSPRNG. Pass it only for known answers. */
export async function sealEnvelope(
  encPk: PointInput,
  i: number,
  ad: EnvelopeAd,
  pair: [FieldLike, FieldLike],
  eph?: FieldLike,
): Promise<ShareCiphertext> {
  nodeIndex(i);
  const pk = curvePoint(encPk, `enc key of node ${i}`);
  const scalar = ephScalar(ephemeralSecret(eph));
  const E = await Grumpkin.mul(Grumpkin.generator, scalar);
  const S = (await Grumpkin.mul(pk, scalar)).x.toBigInt();
  const { ciphertext, tag } = await aeEncrypt(S, await envelopeNonce(ad, i), pair);
  const [ct0, ct1] = ciphertext as [bigint, bigint];
  return { eph: wirePoint(E), ct: [fieldHex(ct0), fieldHex(ct1)], tag: fieldHex(tag) };
}

/** Node `i`'s side, for tests and local checks: open an envelope with the
 * node's `enc` scalar. Throws TagMismatchError when it does not open. */
export async function openEnvelope(encSecret: FieldLike | bigint, i: number, ad: EnvelopeAd, envelope: ShareCiphertext): Promise<[bigint, bigint]> {
  nodeIndex(i);
  const secret = typeof encSecret === "bigint" ? encSecret : BigInt(fieldHex(encSecret));
  if (secret <= 0n || secret >= GrumpkinScalar.MODULUS) throw new RangeError("enc: not a Grumpkin scalar");
  const E = curvePoint(envelope.eph, "eph");
  const S = (await Grumpkin.mul(E, new GrumpkinScalar(secret))).x.toBigInt();
  const [x, y] = (await aeDecrypt(S, await envelopeNonce(ad, i), envelope.ct, envelope.tag)) as [bigint, bigint];
  return [x, y];
}

/** The hash a request carries for one envelope in `share_hashes`: Poseidon2 of
 * `[eph.x, eph.y, ct[0], ct[1], tag]` (ShareCiphertext::hash in sidecar-core). */
export async function shareHash(c: ShareCiphertext): Promise<string> {
  const h = await poseidon2Hash([c.eph.x, c.eph.y, c.ct[0], c.ct[1], c.tag].map((v, j) => new Fr(fieldBigInt(v, `envelope field ${j}`))));
  return fieldHex(h.toBigInt());
}

/** Known-answer inputs for sealing one shared input: its sharing and the
 * three ephemeral secrets. A client leaves them out. */
export interface SealRandomness {
  sharing?: Triple<FieldLike>;
  eph?: Triple<FieldLike>;
}

/** Share `value`, seal node i's pair to `encPks[i]` for every node, and hash
 * the three envelopes: one `shared_inputs` entry. `ad` is the input's
 * associated data (its `name` is the entry's name). */
export async function sealSharedInput(
  ad: EnvelopeAd,
  value: FieldLike,
  encPks: Triple<PointInput>,
  randomness: SealRandomness = {},
): Promise<SharedInput> {
  const x = fieldBigInt(value, `shared input \`${ad.name}\``);
  let sharing: Triple<bigint>;
  if (randomness.sharing !== undefined) {
    sharing = randomness.sharing.map((v, j) => fieldBigInt(v, `sharing[${j}]`)) as Triple<bigint>;
    if (modR(sharing[0] + sharing[1] + sharing[2]) !== x) throw new RangeError(`shared input \`${ad.name}\`: the sharing does not sum to the value`);
  } else {
    sharing = shareField(x);
  }
  const shares = (await Promise.all(
    encPks.map((pk, i) => sealEnvelope(pk, i, ad, sharePair(sharing, i), randomness.eph?.[i])),
  )) as Triple<ShareCiphertext>;
  const share_hashes = (await Promise.all(shares.map(shareHash))) as Triple<string>;
  return { name: ad.name, shares, share_hashes };
}
