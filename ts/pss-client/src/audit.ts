// The requester audit (docs/ARCHITECTURE.md section 6, "The hidden
// requester"), for the e2e drivers and the client's tests: no requester
// address appears in a chain request id, a receipt body or row, a
// synthesised request's public map, an intake transaction's public call
// arguments or logs, or a proof's public inputs. A driver names the
// addresses it must not find (the accounts its requests came from) and the
// places; assertNoRequester throws RequesterLeakError naming the place and
// the path of the first address it finds. The machine's in-process suites
// use sidecar-tip's `audit` module and the contract suites pss_tip_test's.
//
// A value names an address when it equals one as a field element. Every
// value is walked whole: arrays and objects recursively, and every bigint,
// safe integer, hex string or object with toBigInt() (Fr, AztecAddress)
// counts, whatever its key.

import { fieldBigInt, fieldHex, type FieldLike } from "./field.ts";
import { chainRequestId, tipInputsHash } from "./tip.ts";

/** A non-secret-shared intake's chain request id with the parts it must be made of. */
export interface PlainIdAudit {
  chainRequestId: FieldLike;
  namespace: FieldLike;
  vkHash: FieldLike;
  inputs: readonly FieldLike[];
  userNonce: FieldLike;
}

/** The places assertNoRequester looks at; each is optional. */
export interface RequesterAuditPlaces {
  /** Each must be the requester-free id of its parts. */
  plainIds?: readonly PlainIdAudit[];
  receiptBodies?: readonly unknown[];
  receiptRows?: readonly unknown[];
  publicMaps?: readonly unknown[];
  /** An intake transaction's public call arguments (or any call's). */
  callArgs?: readonly unknown[];
  /** Public logs, each as its fields. */
  logs?: readonly unknown[];
  /** A proof's public inputs. */
  publicInputs?: readonly unknown[];
}

/** An address was found where no request may name one. */
export class RequesterLeakError extends Error {
  readonly place: string;
  readonly path: string;
  readonly address: string;
  constructor(place: string, path: string, address: string) {
    super(`${place}: ${path || "the value"} is the requester address ${address}`);
    this.name = "RequesterLeakError";
    this.place = place;
    this.path = path;
    this.address = address;
  }
}

// The field element a leaf value is, or undefined for one that is none (a
// word, a boolean, a negative or oversize number).
function asField(v: unknown): bigint | undefined {
  if (typeof v === "bigint" || typeof v === "number" || typeof v === "string") {
    try {
      return fieldBigInt(v as FieldLike);
    } catch {
      return undefined;
    }
  }
  if (v !== null && typeof v === "object" && typeof (v as { toBigInt?: unknown }).toBigInt === "function") {
    try {
      return (v as { toBigInt(): bigint }).toBigInt();
    } catch {
      return undefined;
    }
  }
  return undefined;
}

/** Every field element in `v`, with its path. */
export function auditFields(v: unknown, path = ""): [string, bigint][] {
  const leaf = asField(v);
  if (leaf !== undefined) return [[path, leaf]];
  if (Array.isArray(v)) return v.flatMap((x, i) => auditFields(x, `${path}[${i}]`));
  if (v !== null && typeof v === "object") {
    return Object.entries(v as Record<string, unknown>).flatMap(([k, x]) => auditFields(x, path ? `${path}.${k}` : k));
  }
  return [];
}

/** Throw RequesterLeakError when one of `addresses` appears in any of the
 * places, or Error when a non-secret-shared id is not the requester-free id of its
 * parts (poseidon2([namespace, vk_hash, inputs_hash, user_nonce])). */
export async function assertNoRequester(addresses: readonly unknown[], places: RequesterAuditPlaces): Promise<void> {
  const banned = new Set(addresses.map((a, i) => {
    const f = asField(a);
    if (f === undefined) throw new TypeError(`addresses[${i}]: not a field element`);
    return f;
  }));
  const scan = (place: string, values: readonly unknown[] | undefined) => {
    (values ?? []).forEach((value, k) => {
      for (const [path, f] of auditFields(value, `[${k}]`)) {
        if (banned.has(f)) throw new RequesterLeakError(place, path, fieldHex(f));
      }
    });
  };
  for (const [k, id] of (places.plainIds ?? []).entries()) {
    const want = await chainRequestId(id.namespace, id.vkHash, await tipInputsHash(id.inputs), id.userNonce);
    if (want.toBigInt() !== fieldBigInt(id.chainRequestId, `plainIds[${k}].chainRequestId`)) {
      throw new Error(`non-secret-shared id ${k}: ${fieldHex(id.chainRequestId)} is not the requester-free id ${fieldHex(want.toBigInt())} of its inputs and nonce`);
    }
    scan("non-secret-shared id", [[id.chainRequestId, ...id.inputs, id.userNonce]]);
  }
  scan("receipt body", places.receiptBodies);
  scan("receipt row", places.receiptRows);
  scan("public map", places.publicMaps);
  scan("call arguments", places.callArgs);
  scan("public log", places.logs);
  scan("public inputs", places.publicInputs);
}
