// The effects split: the shape (R, W, P, A) of a pss_core circuit from its ABI,
// and the canonical public-input array cut into the prefix, the app inputs and
// the PssEffects the contract function takes.
//
// Canonical layout (pss_core, PssEffects):
//   [namespace, owner, in_slots[R], out_slots[W], app_inputs[P],
//    read_leaves[R], nullifiers[R], new_note_hashes[W], npk_app_hash, app_outputs[A]]
// length 3 + 3R + 2W + P + A. npk_app_hash is always present (0 when R = 0).

import { Fr } from "@aztec-labs/aztec.js/fields";

import { abiOf, abiWidth, type AbiType } from "./abi.ts";
import { fieldHex, type FieldLike } from "./field.ts";

/** Notes read, notes written, app input fields, app output fields. */
export interface Shape {
  R: number;
  W: number;
  P: number;
  A: number;
}

/** A shape read from an ABI, with the app input parameters in declaration order. */
export interface CircuitShape extends Shape {
  /** The namespace parameter (`namespace` in every circuit of this repository). */
  namespaceParam: string;
  /** Public parameters after the prefix, in declaration order, with their flattened widths. */
  appInputs: { name: string; width: number }[];
}

/** The return struct of every pss_core circuit, as the contract takes it. */
export interface PssEffects {
  read_leaves: Fr[];
  nullifiers: Fr[];
  new_note_hashes: Fr[];
  npk_app_hash: Fr;
  app_outputs: Fr[];
}

export interface SplitEffects {
  namespace: Fr;
  owner: Fr;
  in_slots: Fr[];
  out_slots: Fr[];
  app_inputs: Fr[];
  effects: PssEffects;
}

/** The length of the canonical array for a shape. */
export function canonicalLength(s: Shape): number {
  return 3 + 3 * s.R + 2 * s.W + s.P + s.A;
}

function fieldArrayLength(t: AbiType, what: string): number {
  if (t.kind !== "array" || t.type?.kind !== "field" || typeof t.length !== "number") {
    throw new RangeError(`${what}: not [Field; _]`);
  }
  return t.length;
}

// The fixed parameter names of the pss_core interface: the namespace
// parameter, the owner and the slot arrays. The namespace parameter is the
// first public parameter in every pss_core circuit; the circuits of this
// repository call it `namespace`.
const OWNER = "owner";
const IN_SLOTS = "in_slots";
const OUT_SLOTS = "out_slots";
const EFFECT_FIELDS = ["read_leaves", "nullifiers", "new_note_hashes", "npk_app_hash", "app_outputs"] as const;

/** Read (R, W, P, A) from a compiled circuit (nargo output JSON, or its `abi`).
 * Checks the pss_core interface's rules: public parameters start with the namespace
 * parameter, owner, in_slots (absent when R = 0) and out_slots (absent when
 * W = 0), every other public parameter is an app input, and the return value is
 * a public PssEffects whose read_leaves, nullifiers, new_note_hashes,
 * npk_app_hash and app_outputs have widths R, R, W, 1 and A. */
export function shapeFromAbi(circuitJson: unknown): CircuitShape {
  const abi = abiOf(circuitJson);
  for (const p of abi.parameters) {
    if (p.visibility === "databus") throw new RangeError(`parameter ${p.name}: databus visibility`);
  }
  const pub = abi.parameters.filter((p) => p.visibility === "public");
  let i = 0;
  const ns = pub[i++];
  if (!ns || ns.type.kind !== "field") throw new RangeError("the first public parameter (the namespace) must be a single Field");
  const owner = pub[i++];
  if (!owner || owner.name !== OWNER || owner.type.kind !== "field") {
    throw new RangeError("the second public parameter must be `owner: pub Field`");
  }
  let R = 0;
  let W = 0;
  if (pub[i]?.name === IN_SLOTS) R = fieldArrayLength(pub[i++]!.type, IN_SLOTS);
  if (pub[i]?.name === OUT_SLOTS) W = fieldArrayLength(pub[i++]!.type, OUT_SLOTS);
  const appInputs = pub.slice(i).map((p) => {
    if (p.name === IN_SLOTS || p.name === OUT_SLOTS || p.name === OWNER) {
      throw new RangeError(`parameter ${p.name}: out of order in the public prefix`);
    }
    return { name: p.name, width: abiWidth(p.type) };
  });
  const P = appInputs.reduce((n, a) => n + a.width, 0);

  const ret = abi.return_type;
  if (!ret || ret.visibility !== "public" || ret.abi_type.kind !== "struct") {
    throw new RangeError("return value: not a public PssEffects struct");
  }
  const fields = (ret.abi_type.fields ?? []) as { name: string; type: AbiType }[];
  const names = fields.map((f) => f.name);
  if (names.join() !== EFFECT_FIELDS.join()) {
    throw new RangeError(`return value: fields ${names.join(", ")}, expected ${EFFECT_FIELDS.join(", ")}`);
  }
  const width = (k: number) => fieldArrayLength(fields[k]!.type, `return value ${fields[k]!.name}`);
  if (width(0) !== R) throw new RangeError(`read_leaves has width ${width(0)}, in_slots ${R}`);
  if (width(1) !== R) throw new RangeError(`nullifiers has width ${width(1)}, in_slots ${R}`);
  if (width(2) !== W) throw new RangeError(`new_note_hashes has width ${width(2)}, out_slots ${W}`);
  if (fields[3]!.type.kind !== "field") throw new RangeError("npk_app_hash: not a Field");
  const A = width(4);
  return { R, W, P, A, namespaceParam: ns.name, appInputs };
}

/** What the prefix must equal: the request's namespace and keys, and
 * optionally the owner and app inputs. */
export interface ExpectedPrefix {
  namespace?: FieldLike;
  owner?: FieldLike;
  reads?: FieldLike[];
  writes?: FieldLike[];
  appInputs?: FieldLike[];
}

/** Cut the canonical public-input array by shape. With `expect`, also check
 * the prefix against the request (the e2e driver's answer step does). */
export function splitEffects(publicInputs: FieldLike[], shape: Shape, expect?: ExpectedPrefix): SplitEffects {
  const { R, W, P, A } = shape;
  const n = canonicalLength(shape);
  if (publicInputs.length !== n) {
    throw new RangeError(`public inputs: ${publicInputs.length} values, the shape (R=${R}, W=${W}, P=${P}, A=${A}) has ${n}`);
  }
  const v = publicInputs.map((x, k) => Fr.fromString(fieldHex(x, `public_inputs[${k}]`)));
  let at = 0;
  const take = (len: number) => {
    const out = v.slice(at, at + len);
    at += len;
    return out;
  };
  const [namespace] = take(1);
  const [owner] = take(1);
  const split: SplitEffects = {
    namespace: namespace!,
    owner: owner!,
    in_slots: take(R),
    out_slots: take(W),
    app_inputs: take(P),
    effects: {
      read_leaves: take(R),
      nullifiers: take(R),
      new_note_hashes: take(W),
      npk_app_hash: take(1)[0]!,
      app_outputs: take(A),
    },
  };
  if (expect) checkPrefix(split, expect);
  return split;
}

function sameList(got: Fr[], want: FieldLike[], what: string): void {
  if (got.length !== want.length || got.some((g, k) => g.toString() !== fieldHex(want[k]!))) {
    throw new RangeError(`${what}: public inputs carry [${got.join(", ")}], the request [${want.map((w) => fieldHex(w)).join(", ")}]`);
  }
}

function checkPrefix(split: SplitEffects, expect: ExpectedPrefix): void {
  if (expect.namespace !== undefined) sameList([split.namespace], [expect.namespace], "namespace");
  if (expect.owner !== undefined) sameList([split.owner], [expect.owner], "owner");
  if (expect.reads !== undefined) sameList(split.in_slots, expect.reads, "in_slots");
  if (expect.writes !== undefined) sameList(split.out_slots, expect.writes, "out_slots");
  if (expect.appInputs !== undefined) sameList(split.app_inputs, expect.appInputs, "app_inputs");
}
