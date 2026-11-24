// Hex encodings shared by every wire type: field elements (the request id is
// one) and opaque bytes. They follow machine/sidecar-core/src/field.rs exactly, so a value
// the client writes parses on the node side with the same meaning. The
// conversions every module shares sit here too: a field element as an Fr
// (fieldFr), a Grumpkin scalar (fieldFq) or an address (fieldAddress), a u32 block number or epoch,
// reduction mod r, Poseidon2 over integers, and the client's source of secret
// randomness (randomField).

import { randomBytes } from "node:crypto";

import { AztecAddress } from "@aztec-labs/aztec.js/addresses";
import { Fr } from "@aztec-labs/aztec.js/fields";
import { Fq } from "@aztec-labs/foundation/curves/bn254";
import { poseidon2Hash } from "@aztec-labs/foundation/crypto/poseidon";

/** The BN254 scalar field modulus r. Grumpkin's base field is the same field. */
export const BN254_MODULUS =
  0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001n;

/** Poseidon2 over field elements given as integers below r. */
export async function hashFields(xs: readonly bigint[]): Promise<bigint> {
  return (await poseidon2Hash(xs.map((x) => new Fr(x)))).toBigInt();
}

/** `v` reduced mod r into [0, r). */
export const modR = (v: bigint): bigint => ((v % BN254_MODULUS) + BN254_MODULUS) % BN254_MODULUS;

const MASK_254 = (1n << 254n) - 1n;

// The client's source of secret randomness. Every sharing (x_0 and x_1 of
// shareField) and every envelope's ephemeral scalar (sealEnvelope) is drawn
// by randomField below: 32 bytes from the operating system's CSPRNG
// (node:crypto randomBytes), masked to 254 bits, and drawn again until the
// value is below r. Known answers pass their own values to
// buildExecuteRequestWith instead.
// Why node:crypto and not foundation's randomness singleton: tests and
// simulators can make that singleton deterministic process-wide, and a
// deterministic sharing or ephemeral key would reveal every shared input to
// whoever repeats it (OwnerKey.generate makes the same choice). Why rejection
// sampling and not reduction: r is about 0.76 of 2^254, so a reduced 254- or
// 256-bit draw would favour small values by a visible margin, while rejection
// gives exactly uniform values at about 1.3 draws on average. Why the
// ephemeral scalar is uniform over Fr (the BN254 scalar field) rather than
// over the Grumpkin scalar order: the Grumpkin order is the BN254 base field,
// which exceeds r by less than 2^127, so the unreachable scalars are a
// fraction below 2^-126 of the group; and an Fr read as a Grumpkin scalar is
// the rule of pss_utils/dh.nr and of sidecar-core's envelope.rs (Fr::rand,
// scalar_from_field), so the three implementations draw from one
// distribution. Consequence: replacing this source with anything weaker or
// seedable lets a party that predicts it open every envelope and recombine
// every shared input; the nodes cannot detect it.
/** A field element uniform mod r from the operating system's CSPRNG
 * (rejection sampling of 254-bit draws, so no modular bias). */
export function randomField(): bigint {
  for (;;) {
    const v = BigInt("0x" + randomBytes(32).toString("hex")) & MASK_254;
    if (v < BN254_MODULUS) return v;
  }
}

/** Anything the client accepts where a field element goes. A string is
 * always hex, with or without `0x`: `"1000"` is 4096, never one thousand;
 * give a decimal amount as a bigint or a number. */
export type FieldLike = Fr | bigint | number | string;

/** A field element as `0x` + 64 lowercase hex digits. */
export type FieldHexString = string;

function isFr(x: unknown): x is { toBigInt(): bigint } {
  return typeof x === "object" && x !== null && typeof (x as { toBigInt?: unknown }).toBigInt === "function";
}

// Field-element encoding. The client writes every field element as `0x` +
// 64 lowercase hex digits (as aztec.js prints an Fr) and refuses a value at
// or above the BN254 scalar modulus instead of reducing it, the same rule
// sidecar-core applies on input. Reducing would let two spellings mean one
// field element and hide client overflow bugs; the nodes would refuse the
// body anyway, after a round trip. A refusal names the field (`what`) and the
// reason, never the value: the same parser reads secret inputs, sharings,
// ephemeral and AE keys and plaintexts, and an app that logs exceptions would
// otherwise write a refused secret to its log.
/** Parse a field element: an Fr, a non-negative bigint or safe integer, or a
 * string of an optional `0x` and 1 to 64 hex digits (big-endian). */
export function fieldBigInt(x: FieldLike, what = "value"): bigint {
  return parseBelow(x, what, BN254_MODULUS, "the bn254 scalar field modulus");
}

/** The integer `x` names (fieldBigInt's rules), refused at or above
 * `modulus` (`modulusName` in the refusal); never names the value. */
function parseBelow(x: FieldLike | Fq, what: string, modulus: bigint, modulusName: string): bigint {
  let v: bigint;
  if (typeof x === "bigint") {
    v = x;
  } else if (typeof x === "number") {
    if (!Number.isSafeInteger(x)) throw new RangeError(`${what}: not a safe integer`);
    v = BigInt(x);
  } else if (typeof x === "string") {
    const digits = x.startsWith("0x") ? x.slice(2) : x;
    if (digits.length === 0 || digits.length > 64 || !/^[0-9a-fA-F]+$/.test(digits)) {
      throw new RangeError(`${what}: not a 1 to 64 digit hex number`);
    }
    v = BigInt("0x" + digits);
  } else if (isFr(x)) {
    v = x.toBigInt();
  } else {
    throw new TypeError(`${what}: not a field element`);
  }
  if (v < 0n) throw new RangeError(`${what}: negative`);
  if (v >= modulus) {
    throw new RangeError(`${what}: not below ${modulusName}`);
  }
  return v;
}

/** A Grumpkin scalar (an element of the BN254 base field, which exceeds the
 * scalar field: an account's signing key) as foundation's Fq: an Fq, or
 * what fieldBigInt accepts, refused at or above the Grumpkin scalar modulus.
 * As fieldBigInt, a refusal names `what` and never the value. */
export function fieldFq(x: FieldLike | Fq, what = "value"): Fq {
  return new Fq(parseBelow(x, what, Fq.MODULUS, "the Grumpkin scalar field modulus"));
}

/** Normalise a field element to `0x` + 64 lowercase hex digits. */
export function fieldHex(x: FieldLike, what = "value"): FieldHexString {
  return "0x" + fieldBigInt(x, what).toString(16).padStart(64, "0");
}

/** A field element as `0x` and lowercase hex digits without leading zeros
 * (`0x0` for zero): sidecar-core's fr_to_short_hex, the one spelling of a
 * request key that is a field element. */
export function fieldShortHex(x: FieldLike, what = "value"): string {
  return "0x" + fieldBigInt(x, what).toString(16);
}

/** A field element as an aztec.js Fr (fieldBigInt's rules). */
export function fieldFr(x: FieldLike, what = "value"): Fr {
  return new Fr(fieldBigInt(x, what));
}

/** An Aztec address: an AztecAddress as given, a field element as the
 * address it encodes (fieldBigInt's rules). */
export function fieldAddress(x: FieldLike | AztecAddress, what = "address"): AztecAddress {
  return x instanceof AztecAddress ? x : AztecAddress.fromBigIntUnsafe(fieldBigInt(x, what));
}

/** The largest u32, the type of a block number and an epoch in Noir. */
const U32_MAX = 0xffffffff;

/** A u32 given as a number (a block number, an epoch): an `error`
 * (default RangeError) naming `what` and the `noun` otherwise. */
export function u32(v: unknown, what: string, noun: string, error: new (message: string) => Error = RangeError): number {
  if (typeof v !== "number" || !Number.isInteger(v) || v < 0 || v > U32_MAX) throw new error(`${what}: not a u32 ${noun}`);
  return v;
}

/** Opaque bytes as `0x` + an even number of hex digits (lowercase on output).
 * The `0x` is required, as in sidecar-core's `HexBytes`. */
export function hexBytes(x: string | Uint8Array, what = "bytes"): string {
  if (x instanceof Uint8Array) return "0x" + Buffer.from(x).toString("hex");
  if (typeof x !== "string" || !x.startsWith("0x")) {
    throw new RangeError(`${what}: \`${String(x).slice(0, 40)}\` does not start with 0x`);
  }
  const digits = x.slice(2);
  if (digits.length % 2 !== 0) throw new RangeError(`${what}: odd number of hex digits`);
  if (!/^[0-9a-fA-F]*$/.test(digits)) throw new RangeError(`${what}: not valid hex`);
  return "0x" + digits.toLowerCase();
}

/** Decode `0x` hex bytes. */
export function bytesFromHex(x: string, what = "bytes"): Uint8Array {
  return new Uint8Array(Buffer.from(hexBytes(x, what).slice(2), "hex"));
}

// The request id is one field element, written and parsed like every other
// field (`0x` + 1 to 64 hex digits in, `0x` + 64 lowercase digits out,
// refused at or above the BN254 scalar modulus), the rule of sidecar-core's
// `RequestId`. It enters the envelope associated data and every node-side
// hash as itself, so the client and the nodes never convert it. An id written
// with fewer digits is the same field element and is normalised to 64 digits
// on the way out, so compare ids only after requestIdHex.
/** A request id: one field element, `0x` + 64 lowercase hex digits on output.
 * Accepts what fieldBigInt accepts, or big-endian bytes (at most 32) read as an
 * unsigned integer; refused at or above the BN254 scalar modulus. */
export function requestIdHex(x: FieldLike | Uint8Array, what = "request_id"): FieldHexString {
  if (x instanceof Uint8Array) {
    if (x.length === 0 || x.length > 32) throw new RangeError(`${what}: ${x.length} bytes, expected 1 to 32`);
    return fieldHex(BigInt("0x" + Buffer.from(x).toString("hex")), what);
  }
  return fieldHex(x, what);
}
