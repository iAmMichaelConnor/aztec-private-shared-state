// The one walker of a circuit's ABI (nargo output JSON): the flattened leaves
// of a type, with the paths sidecar-core's abi.rs gives them (`a[0]`, `s.f`,
// `t.0`), and the public-input layout of a circuit, public parameters first
// and then the public return value. The effects split, the note-hash indices,
// the tip's intake inputs and the tip's result layout all read the ABI
// through here, and a contract's packed struct members (abiMembers) too; abiArg shapes flattened fields into one argument of a
// contract function for aztec.js (intake.ts's request function parameters).

import { AztecAddress } from "@aztec-labs/aztec.js/addresses";
import type { Fr } from "@aztec-labs/foundation/curves/bn254";
import { isAztecAddressStruct, type AbiType as ContractAbiType } from "@aztec-labs/stdlib/abi";

/** An ABI type as nargo writes it. */
export interface AbiType {
  kind: string;
  length?: number;
  width?: number;
  type?: AbiType;
  fields?: ({ name: string; type: AbiType } | AbiType)[];
}

export interface AbiParam {
  name: string;
  type: AbiType;
  visibility: string;
}

export interface Abi {
  parameters: AbiParam[];
  return_type?: { abi_type: AbiType; visibility: string } | null;
}

/** The ABI of a nargo output JSON, or the ABI itself. RangeError when it has
 * no parameter list. */
export function abiOf(circuit: unknown): Abi {
  const c = circuit as { abi?: unknown };
  const abi = (c && typeof c === "object" && "abi" in c ? c.abi : c) as Partial<Abi> | null | undefined;
  if (!abi || !Array.isArray(abi.parameters)) throw new RangeError("abi.parameters: missing");
  return abi as Abi;
}

/** One flattened element of an ABI type. */
export interface AbiLeaf {
  /** The element's path under the root path the walk started from. */
  path: string;
  /** field, integer, boolean, or string (one byte of a string). */
  kind: "field" | "integer" | "boolean" | "string";
  /** An integer's bit width, as the ABI gives it. */
  width?: number;
}

/** Every leaf of `t` in flattening order, named from `path`. RangeError for a
 * kind the client does not support. */
export function abiLeaves(t: AbiType, path = "", out: AbiLeaf[] = []): AbiLeaf[] {
  const join = (part: string) => (path === "" ? part : `${path}.${part}`);
  switch (t.kind) {
    case "field":
    case "boolean":
      out.push({ path, kind: t.kind });
      return out;
    case "integer": {
      const leaf: AbiLeaf = { path, kind: "integer" };
      if (typeof t.width === "number") leaf.width = t.width;
      out.push(leaf);
      return out;
    }
    case "string":
      for (let i = 0; i < (t.length ?? 0); i++) out.push({ path: `${path}[${i}]`, kind: "string" });
      return out;
    case "array":
      for (let i = 0; i < (t.length ?? 0); i++) abiLeaves(t.type as AbiType, `${path}[${i}]`, out);
      return out;
    case "struct":
      for (const f of (t.fields ?? []) as { name: string; type: AbiType }[]) abiLeaves(f.type, join(f.name), out);
      return out;
    case "tuple":
      (t.fields ?? []).forEach((f, i) => abiLeaves(f as AbiType, join(String(i)), out));
      return out;
    default:
      throw new RangeError(`ABI type kind ${t.kind}: not supported`);
  }
}

/** The number of field elements an ABI type flattens to. */
export function abiWidth(t: AbiType): number {
  return abiLeaves(t).length;
}

/** The members of a struct type by name, each with its offset in the
 * struct packed member by member (each member its flattened width) and its
 * type: how a contract stores a struct from its slot on. RangeError when `t`
 * is not a struct. */
export function abiMembers(t: AbiType): Map<string, { offset: number; type: AbiType }> {
  if (t.kind !== "struct") throw new RangeError(`ABI type kind ${t.kind}: not a struct`);
  const out = new Map<string, { offset: number; type: AbiType }>();
  let offset = 0;
  for (const f of (t.fields ?? []) as { name: string; type: AbiType }[]) {
    out.set(f.name, { offset, type: f.type });
    offset += abiWidth(f.type);
  }
  return out;
}

/** Where a circuit's public inputs come from: each public parameter's first
 * index and width, the number of public parameter fields, and the return
 * value's leaves, which follow them when the return value is public. */
export interface PublicLayout {
  params: Map<string, { index: number; width: number }>;
  publicFields: number;
  /** The return value's leaves; a struct's paths start at its fields, any
   * other type's at `return`. Empty without a return value. */
  returnLeaves: AbiLeaf[];
  returnPublic: boolean;
}

/** The public-input layout of an ABI. RangeError for databus visibility. */
export function publicLayout(abi: Abi): PublicLayout {
  const params = new Map<string, { index: number; width: number }>();
  let publicFields = 0;
  for (const p of abi.parameters) {
    if (p.visibility === "databus") throw new RangeError(`parameter ${p.name}: databus visibility`);
    if (p.visibility !== "public") continue;
    const width = abiWidth(p.type);
    params.set(p.name, { index: publicFields, width });
    publicFields += width;
  }
  const ret = abi.return_type ?? null;
  if (ret !== null && ret.visibility === "databus") throw new RangeError("the return value uses databus visibility");
  const returnLeaves = ret === null ? [] : abiLeaves(ret.abi_type, ret.abi_type.kind === "struct" ? "" : "return");
  return { params, publicFields, returnLeaves, returnPublic: ret?.visibility === "public" };
}

/** The public-input index of each output's note hash, in output order: the
 * number of public parameter fields plus the position of the output's
 * `note_hash` path among the public return value's elements. The same rule
 * as REGISTER's check of a manifest against its ABI (sidecar-core abi.rs),
 * and refused for the same reasons: a path that is not a single Field of a
 * public return value, or one two outputs name. */
export function outputNoteHashIndices(abi: Abi, outputs: readonly { note_hash: string }[]): number[] {
  const { publicFields, returnLeaves, returnPublic } = publicLayout(abi);
  const named = new Set<string>();
  return outputs.map(({ note_hash: path }, k) => {
    const at = `manifest.outputs[${k}].note_hash`;
    const i = returnLeaves.findIndex((l) => l.path === path);
    if (i < 0) throw new RangeError(`${at}: \`${path}\` is not one element of the circuit's return value`);
    if (!returnPublic) throw new RangeError(`${at}: \`${path}\` is a private output`);
    if (returnLeaves[i]!.kind !== "field") throw new RangeError(`${at}: \`${path}\` is not a Field`);
    if (named.has(path)) throw new RangeError(`${at}: \`${path}\` is named by two outputs`);
    named.add(path);
    return publicFields + i;
  });
}

/** `fields` as one argument of contract ABI type `t` (an aztec.js
 * FunctionAbi parameter's type), in the form aztec.js encodes: a Field an
 * Fr, an integer a bigint, a boolean a boolean, an AztecAddress struct an
 * AztecAddress, an array a list and any other struct an object, member by
 * member; `at` names the argument in errors. RangeError for a string or a
 * tuple. */
export function abiArg(t: ContractAbiType, fields: readonly Fr[], at: string): unknown {
  switch (t.kind) {
    case "field":
      return fields[0];
    case "integer":
      return fields[0]!.toBigInt();
    case "boolean":
      return fields[0]!.toBigInt() !== 0n;
    case "array": {
      const w = abiWidth(t.type as AbiType);
      return Array.from({ length: t.length }, (_, i) => abiArg(t.type, fields.slice(i * w, (i + 1) * w), `${at}[${i}]`));
    }
    case "struct": {
      if (isAztecAddressStruct(t)) return AztecAddress.fromBigIntUnsafe(fields[0]!.toBigInt());
      let k = 0;
      return Object.fromEntries(t.fields.map((f) => {
        const w = abiWidth(f.type as AbiType);
        return [f.name, abiArg(f.type, fields.slice(k, (k += w)), `${at}.${f.name}`)];
      }));
    }
    default:
      throw new RangeError(`${at}: an argument of kind ${t.kind} is not built from fields`);
  }
}

