// The run's scope: every value a scenario can name, and the one way scenario
// values are read (references, templates, the literal escape) and computed.
import { AztecAddress } from "@aztec-labs/aztec.js/addresses";
import { Fr } from "@aztec-labs/aztec.js/fields";
import { poseidon2HashWithSeparator } from "@aztec-labs/foundation/crypto/poseidon";
import { fieldHex, type FieldLike, requestKey, sleep } from "@aztec-pss/pss-client";

/** A scenario value: plain data. A string `$a.b[0]` is a reference into the
 * run's scope; a string with `${a.b}` in it is a template; `$$` in a string
 * is one literal `$` (so `$$a` is the string `$a`, never a reference);
 * everything else is literal and goes to pss-client or the contract call as
 * written (a bigint key is spelt in short hex by pss-client, a string
 * key exactly as written). */
export type Value = string | number | bigint | boolean | null | Value[] | { [k: string]: Value };
/** A value computed once, when a `let` step (or the scenario's `values` or `namespaces`) is evaluated. */
export type Expr = Value | { poseidon2: Value[]; separator: number | bigint } | { random: "field" };
/** `[op, a, b]`: a = b, a ≠ b, a > b, a is one of the list b, the list a has b entries. */
export type Expect = ["eq" | "ne" | "gt" | "in" | "len", Value, Value];

/** The names the engine defines; a scenario's own names must differ. */
export const RESERVED: readonly string[] = ["accounts", "contracts", "namespaces", "pins"];

/** Throws `what` unless `ok`: every assertion of the driver, its steps and
 * the harness. */
export function check(ok: unknown, what: string): asserts ok {
  if (!ok) throw new Error(what);
}

/** Throws `what`; for an expression (`x ?? fail(...)`). */
export function fail(what: string): never {
  throw new Error(what);
}

/** Reads every `everyMs` until `done` holds of the value read or `limitMs`
 * has passed: the last value read, and whether it was done. */
export async function poll<T>(read: () => Promise<T>, done: (value: T) => boolean, limitMs: number, everyMs = 2_000): Promise<{ value: T; done: boolean }> {
  const deadline = Date.now() + limitMs;
  for (;;) {
    const value = await read();
    if (done(value)) return { value, done: true };
    if (Date.now() > deadline) return { value, done: false };
    await sleep(everyMs);
  }
}

/** Waits until `ok` holds, checked every `everyMs`; throws `what within
 * limitS s` past the limit. */
export async function until(what: string, limitS: number, ok: () => Promise<boolean> | boolean, everyMs = 500): Promise<void> {
  const { done } = await poll(async () => ok(), (v) => v, limitS * 1000, everyMs);
  check(done, `${what} within ${limitS} s`);
}

export function show(x: unknown): string {
  if (Array.isArray(x)) return `[${x.map(show).join(", ")}]`;
  return String(x);
}

export function big(x: unknown): bigint {
  if (typeof x === "bigint") return x;
  if (typeof x === "number" || typeof x === "boolean") return BigInt(x);
  if (typeof x === "string") return BigInt(fieldHex(x));
  if (x instanceof Fr) return x.toBigInt();
  if (x instanceof AztecAddress) return x.toField().toBigInt();
  throw new Error(`not a field element: ${show(x)}`);
}

/** A value as pss-client takes a field (a boolean as 0 or 1). */
export const fieldLike = (x: unknown): FieldLike => (typeof x === "boolean" ? Number(x) : x instanceof AztecAddress ? x.toField() : (x as FieldLike));

/** A key as a request spells it (pss-client's requestKey: a string as written, anything else short hex). */
export const keyHex = (k: FieldLike): string => requestKey(k);

export class Scope {
  readonly data: Record<string, unknown> = { accounts: {}, contracts: {}, namespaces: {}, pins: {} };

  /** Binds a scenario name (a named round, note, transaction or `let` value). */
  set(name: string, value: unknown): void {
    this.data[name] = value;
  }

  lookup(path: string): unknown {
    let x: unknown = this.data;
    for (const p of path.match(/[^.[\]]+/g) ?? []) {
      if (x === null || x === undefined || !(p in Object(x))) throw new Error(`$${path}: \`${p}\` is not defined`);
      x = (x as Record<string, unknown>)[p];
    }
    return x;
  }

  resolve(v: Value): unknown {
    if (typeof v === "string") {
      if (/^\$[A-Za-z_]/.test(v)) return this.lookup(v.slice(1));
      return v.includes("$") ? v.replace(/\$\$|\$\{([^}]+)\}/g, (m, p: string | undefined) => (p === undefined ? "$" : show(this.lookup(p)))) : v;
    }
    if (Array.isArray(v)) return v.map((x) => this.resolve(x));
    if (v !== null && typeof v === "object") return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, this.resolve(x)]));
    return v;
  }

  async evaluate(e: Expr): Promise<unknown> {
    if (e !== null && typeof e === "object" && !Array.isArray(e)) {
      if ("poseidon2" in e && "separator" in e) return poseidon2HashWithSeparator((this.resolve(e.poseidon2) as unknown[]).map((x) => new Fr(big(x))), e.separator as number);
      if ("random" in e) return Fr.random();
    }
    return this.resolve(e as Value);
  }

  expectAll(label: string, list: Expect[]): void {
    for (const [op, a0, b0] of list) {
      const [a, b] = [this.resolve(a0), this.resolve(b0)];
      const ok =
        op === "eq" ? big(a) === big(b)
        : op === "ne" ? big(a) !== big(b)
        : op === "gt" ? big(a) > big(b)
        : op === "in" ? (b as unknown[]).some((x) => big(x) === big(a))
        : (a as unknown[]).length === Number(b);
      check(ok, `${label}: expected ${show(a0)} ${op} ${show(b0)}, got ${show(a)} and ${show(b)}`);
    }
  }
}
