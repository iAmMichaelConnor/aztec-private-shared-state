// Grumpkin points and the ephemeral secret as the client takes them: a
// point given by the caller is checked on the curve (never the zero point),
// and an ephemeral secret is a nonzero field element read as a Grumpkin
// scalar (its integer value, as pss_utils dh.nr and sidecar-core
// scalar_from_field read it: every BN254 scalar is below the Grumpkin
// modulus), drawn from randomField when the caller gives none.

import { Fr } from "@aztec-labs/foundation/curves/bn254";
import { GrumpkinScalar, Point } from "@aztec-labs/foundation/curves/grumpkin";

import { fieldBigInt, randomField, type FieldLike } from "./field.ts";

/** A point as the caller may give it. */
export interface PointInput {
  x: FieldLike;
  y: FieldLike;
}

/** `p` as a Grumpkin point; RangeError naming `what` for the zero point or
 * a point off the curve. */
export function curvePoint(p: PointInput, what: string): Point {
  const x = fieldBigInt(p.x, `${what}.x`);
  const y = fieldBigInt(p.y, `${what}.y`);
  const point = new Point(new Fr(x), new Fr(y));
  if ((x === 0n && y === 0n) || !point.isOnCurve()) throw new RangeError(`${what}: not a point on Grumpkin`);
  return point;
}

/** The ephemeral secret: `given` (RangeError when zero), or a fresh nonzero
 * draw from the CSPRNG. Pass one only for known answers. */
export function ephemeralSecret(given?: FieldLike): bigint {
  if (given !== undefined) {
    const e = fieldBigInt(given, "eph");
    if (e === 0n) throw new RangeError("eph: the ephemeral secret is zero");
    return e;
  }
  let e = 0n;
  while (e === 0n) e = randomField();
  return e;
}

/** A nonzero ephemeral secret as a Grumpkin scalar. */
export function ephScalar(eph: FieldLike): GrumpkinScalar {
  return new GrumpkinScalar(ephemeralSecret(eph));
}
