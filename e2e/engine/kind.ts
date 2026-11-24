// The step-kind interface every module under steps/ implements, the fields
// every step shares, and the load-time check of a scenario against the
// registry: one kind per step, no field the step's variant does not take,
// no name the engine reserves.
import type { Scenario } from "../scenario.ts";
import type { RunContext } from "./context.ts";
import type { TxOfStep } from "./gas.ts";
import { ONE_WALLET } from "./network.ts";
import { check, RESERVED } from "./scope.ts";

/** The fields every step may carry. */
export interface Common {
  /** The step's label in the log (default: its name or circuit). */
  what?: string;
  /** Appended to the failure message. */
  hint?: string;
}

const COMMON = ["what", "hint"];

/** One kind of step. A step names its kind by carrying the kind's `key` field. */
export interface StepKind<S extends Common> {
  readonly key: string;
  /** The load-time check of one step: the fields its variant takes besides
   * `what` and `hint` (the kind's key among them), and the scope
   * names it binds. Throws on a combination the kind does not run. */
  check(step: S, scenario: Scenario): { fields: readonly string[]; binds?: (string | undefined)[] };
  run(ctx: RunContext, step: S): Promise<void>;
  /** After a run: the transactions the step sent or landed, with their
   * kinds, for the run's gas record (engine/gas.ts); `sent` are those the
   * wallets submitted during the step, in order. Default: none. */
  txs?(ctx: RunContext, step: S, sent: string[]): TxOfStep[];
}

/** A kind as the registry holds it. */
export type AnyKind = StepKind<Common>;
export const defineKind = <S extends Common>(kind: StepKind<S>): AnyKind => kind as unknown as AnyKind;

/** The step's kind: the one registry key it carries. */
export function kindOf(registry: ReadonlyMap<string, AnyKind>, step: Common): AnyKind {
  const keys = Object.keys(step).filter((k) => registry.has(k));
  check(keys.length === 1, `a step carries ${keys.length ? keys.join(" and ") : "no"} kind field${keys.length === 1 ? "" : "s"} (one of ${[...registry.keys()].join(", ")}): ${JSON.stringify(step, (_, v) => (typeof v === "bigint" ? `${v}n` : v))}`);
  return registry.get(keys[0]!)!;
}

/** Checks the whole scenario before anything runs. */
export function checkScenario(registry: ReadonlyMap<string, AnyKind>, s: Scenario): void {
  const names = (what: string, list: string[], known: string[]) => {
    for (const n of list) check(known.includes(n), `${what} ${n} is not one of the scenario's`);
  };
  const tip = Object.keys(s.tip ?? {});
  check(Object.keys(s.contracts).length + tip.length > 0, "the scenario names no contract");
  check(Object.keys(s.namespaces).length + tip.length > 0, "the scenario names no namespace");
  for (const n of tip) check(!(n in s.contracts) && !(n in s.namespaces), `tip deployment ${n}: the name is also a contract's or a namespace's`);
  names("account", [...Object.values(s.contracts).map((c) => c.from), ...(s.senders ?? [])], s.accounts);
  if (s.wallets) {
    const held = Object.values(s.wallets).flat();
    names("account", held, s.accounts);
    for (const a of s.accounts) check(held.filter((h) => h === a).length === 1, `account ${a} is held by ${held.filter((h) => h === a).length} wallets, not one`);
  }
  names("wallet", Object.keys(s.tagging ?? {}), walletNames(s));
  if (s.signer !== undefined) names("key", [s.signer], Object.keys(s.keys));
  for (const n of Object.keys(s.values ?? {})) check(!RESERVED.includes(n), `value ${n}: the name is the engine's (${RESERVED.join(", ")})`);
  for (const [k, step] of s.steps.entries()) {
    const at = `step ${k} (${step.what ?? Object.keys(step).find((f) => registry.has(f)) ?? "?"})`;
    try {
      const kind = kindOf(registry, step);
      const { fields, binds = [] } = kind.check(step, s);
      const extra = Object.keys(step).filter((f) => !COMMON.includes(f) && !fields.includes(f));
      check(extra.length === 0, `${kind.key} step: ${extra.join(", ")} not taken here (takes ${fields.join(", ")})`);
      for (const b of binds) check(b === undefined || !RESERVED.includes(b), `the name ${b} is the engine's (${RESERVED.join(", ")})`);
    } catch (error) {
      throw new Error(`scenario ${at}: ${(error as Error).message}`, { cause: error });
    }
  }
}

/** The scenario's wallet names (`ONE_WALLET` without `wallets`). */
export const walletNames = (s: Scenario): string[] => (s.wallets ? Object.keys(s.wallets) : [ONE_WALLET]);

/** Shared checks of the names a step refers to. */
export const refs = {
  key(s: Scenario, k: string | undefined, kind?: "owner" | "requester"): void {
    if (k === undefined) return;
    check(k in s.keys, `key ${k} is not one of the scenario's`);
    if (kind) check(s.keys[k] === kind, `key ${k} is a ${s.keys[k]} key, not ${kind}`);
  },
  account(s: Scenario, a: string): void {
    check(s.accounts.includes(a), `account ${a} is not one of the scenario's`);
  },
  namespace(s: Scenario, ns: string | undefined): void {
    if (ns !== undefined) check(ns in s.namespaces || ns in (s.tip ?? {}), `namespace ${ns} is not one of the scenario's`);
  },
  /** A tip deployment's name (default: the scenario's first). */
  tip(s: Scenario, ns: string | undefined): void {
    const names = Object.keys(s.tip ?? {});
    check(names.length > 0, "the scenario names no tip deployment");
    if (ns !== undefined) check(names.includes(ns), `${ns} is not one of the scenario's tip deployments (${names.join(", ")})`);
  },
  wallet(s: Scenario, w: string): void {
    check(walletNames(s).includes(w), `wallet ${w} is not one of the scenario's (${walletNames(s).join(", ")})`);
  },
  /** A contract of the scenario, a tip deployment's, or one a tip
   * deployment deployed first (`<tip name>.<name>`, checked when it runs). */
  contract(s: Scenario, c: string | undefined): void {
    if (c === undefined) return;
    const [tip, first, ...more] = c.split(".");
    check(c in s.contracts || c in (s.tip ?? {}) || (first !== undefined && more.length === 0 && tip! in (s.tip ?? {})), `contract ${c} is not one of the scenario's`);
  },
};
