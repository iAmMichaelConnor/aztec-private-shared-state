// What a tip contract's artifact says about its bricks, read once for the
// contract manifest generator (contract-manifest.ts) and pss-manifest verify
// (verify.ts).
//
// The `node_keys` and `upgrades` axis values come from the bricks
// themselves: the app's state view returns pss_public_contract's
// `TipState<Config, S, K, U>`, whose `node_keys` member is the app's
// node-keys brick (`KeyEpochs` or `FixedKeys`) and whose `upgrades` member
// is its upgrades brick (`FixedCircuits`, `UpgradesCircuits` or
// `UpgradesContract`), each a struct with no fields, so the artifact's ABI
// names the brick by its path and the view returns nothing more. The
// function's name is the app's own: the view is found by its return type.
//
// The names below are the ones an app's contract must use because the
// contract library, pss-client, pss-relayer or the node read or call them
// by name. `RESERVED_NAMES` is the one list: docs/design-guide/design-space.json
// `reservedNames` describes each entry and scripts/check-design-space.py
// checks that the two lists name the same entries. `checkBricks` refuses an
// artifact whose functions disagree with the bricks its view reports: a
// wrapper the library enqueues by selector missing or of another signature,
// an entry point the client calls missing, or an entry point of a brick the
// view does not report.

import { decodeFunctionSignature, getFunctionReturnType, type AbiType, type FunctionAbi } from "@aztec-labs/stdlib/abi";

/** Which code relies on a reserved name. */
export type ReservedKind = "storage field" | "function the library calls" | "function the client calls" | "default function name";

/** One reserved name: a storage field's name, a function's name, or (for
 * a function the library enqueues by selector) its exact signature. */
export interface ReservedName {
  name: string;
  kind: ReservedKind;
}

/** Every name an app's contract must use, by role. */
export const RESERVED_NAMES = {
  config: { name: "config", kind: "storage field" },
  queue: { name: "queue", kind: "storage field" },
  configured: { name: "configured", kind: "storage field" },
  sharedOnchain: { name: "shared_onchain", kind: "storage field" },
  circuitUpgrades: { name: "circuit_upgrades", kind: "storage field" },
  assertKeyEpoch: { name: "assert_key_epoch(u32,bool)", kind: "function the library calls" },
  assertUpgradeClass: { name: "assert_upgrade_class(Field)", kind: "function the library calls" },
  rotateKeys: { name: "rotate_keys", kind: "function the client calls" },
  upgradeCircuits: { name: "upgrade_circuits", kind: "function the client calls" },
  upgradeContract: { name: "upgrade_contract", kind: "function the client calls" },
  getEncKey: { name: "get_enc_key", kind: "function the client calls" },
  rotateEncKey: { name: "rotate_enc_key", kind: "function the client calls" },
  processResult: { name: "process_result", kind: "default function name" },
  skip: { name: "skip", kind: "default function name" },
} as const satisfies Record<string, ReservedName>;

/** The `node_keys` and `upgrades` values a contract's bricks report. */
export interface Bricks {
  node_keys: "rotating" | "fixed";
  upgrades: "fixed" | "circuits" | "contract";
}

/** The ABI path of the library's state view. */
export const TIP_STATE_PATH = "pss_public_contract::view::TipState";

/** Each brick's ABI path, by the axis value it is. */
const NODE_KEYS_BRICKS: Record<string, Bricks["node_keys"]> = {
  "pss_public_contract::key_epoch::KeyEpochs": "rotating",
  "pss_public_contract::signing_keys::FixedKeys": "fixed",
};
const UPGRADES_BRICKS: Record<string, Bricks["upgrades"]> = {
  "pss_public_contract::upgrades::FixedCircuits": "fixed",
  "pss_public_contract::upgrades::UpgradesCircuits": "circuits",
  "pss_public_contract::upgrades::UpgradesContract": "contract",
};

/** The artifact shape the readers here take (an aztec.js ContractArtifact
 * has it). */
export interface BrickArtifact {
  name: string;
  functions: readonly FunctionAbi[];
  nonDispatchPublicFunctions?: readonly FunctionAbi[];
}

function allFunctions(artifact: BrickArtifact): FunctionAbi[] {
  return [...artifact.functions, ...(artifact.nonDispatchPublicFunctions ?? [])];
}

/** The path of struct member `name` of `type`. */
function memberPath(type: AbiType, name: string, what: string): string {
  if (type.kind !== "struct") throw new RangeError(`${what} is not a struct`);
  const member = type.fields.find((f) => f.name === name);
  if (member === undefined) throw new RangeError(`${what} has no member \`${name}\``);
  if (member.type.kind !== "struct") throw new RangeError(`${what}.${name} is not a brick (a struct)`);
  return member.type.path;
}

function brickOf<V>(table: Record<string, V>, path: string, what: string): V {
  const value = table[path];
  if (value === undefined) throw new RangeError(`${what} is \`${path}\`, which is none of ${Object.keys(table).join(", ")}`);
  return value;
}

/** The artifact's state views: the functions that return the library's
 * `TipState`, whatever the app calls them. */
function stateViews(artifact: BrickArtifact): FunctionAbi[] {
  return allFunctions(artifact).filter((f) => {
    const t = getFunctionReturnType(f);
    return t?.kind === "struct" && t.path === TIP_STATE_PATH;
  });
}

/** The name of the artifact's state view (the examples' `get_state`), found
 * by its return type. RangeError when no function returns `TipState`. */
export function stateViewName(artifact: BrickArtifact): string {
  const [view] = stateViews(artifact);
  if (view === undefined) throw new RangeError(`${artifact.name}: no function returns ${TIP_STATE_PATH}, so it has no state view`);
  return view.name;
}

/** The bricks the artifact's state view reports, or undefined when no
 * function returns the library's `TipState` (a contract that is no tip app). */
export function bricksOf(artifact: BrickArtifact): Bricks | undefined {
  const views = stateViews(artifact);
  if (views.length === 0) return undefined;
  const reports = views.map((f) => {
    const t = getFunctionReturnType(f)!;
    const what = `${artifact.name}'s ${f.name}`;
    return {
      node_keys: brickOf(NODE_KEYS_BRICKS, memberPath(t, "node_keys", what), `${what} node_keys`),
      upgrades: brickOf(UPGRADES_BRICKS, memberPath(t, "upgrades", what), `${what} upgrades`),
    };
  });
  const first = reports[0]!;
  if (reports.some((r) => r.node_keys !== first.node_keys || r.upgrades !== first.upgrades)) {
    throw new RangeError(`${artifact.name}: its state views ${views.map((f) => f.name).join(", ")} report different bricks`);
  }
  return first;
}

/** What `checkBricks` takes besides the artifact: whether a package of the
 * deployment takes secret-shared on-chain intake (its enc key entry points). */
export interface BrickUse {
  sharedOnchain: boolean;
}

/** The problems with `artifact` against the bricks it reports (`bricks`,
 * fixed and fixed for a contract with no state view): each wrapper the
 * library enqueues by selector present with exactly its signature, each
 * entry point the client calls present, and no entry point of a brick the
 * view does not report. Empty when the artifact agrees. */
export function brickProblems(artifact: BrickArtifact, bricks: Bricks | undefined, use: BrickUse): string[] {
  const b = bricks ?? { node_keys: "fixed", upgrades: "fixed" };
  const functions = allFunctions(artifact);
  const byName = new Map(functions.map((f) => [f.name, f]));
  const problems: string[] = [];
  const signature = (f: FunctionAbi) => decodeFunctionSignature(f.name, f.parameters);
  const needSelector = (r: ReservedName, why: string) => {
    const name = r.name.slice(0, r.name.indexOf("("));
    const f = byName.get(name);
    if (f === undefined) problems.push(`${why}, so the library enqueues ${r.name} by selector, which the artifact does not declare`);
    else if (f.functionType !== "public" || signature(f) !== r.name) {
      problems.push(`${why}, so the library enqueues ${r.name} by selector, but the artifact's ${name} is the ${f.functionType} ${signature(f)}`);
    }
  };
  const need = (r: ReservedName, why: string) => {
    if (!byName.has(r.name)) problems.push(`${why}, so the artifact must declare ${r.name}, which it does not`);
  };
  const refuse = (r: ReservedName, why: string) => {
    const name = r.name.includes("(") ? r.name.slice(0, r.name.indexOf("(")) : r.name;
    if (byName.has(name)) problems.push(`${why}, but the artifact declares ${name}`);
  };
  const keys = `the state view reports node_keys ${b.node_keys}`;
  const upgrades = `the state view reports upgrades ${b.upgrades}`;
  if (b.node_keys === "rotating") {
    needSelector(RESERVED_NAMES.assertKeyEpoch, keys);
    need(RESERVED_NAMES.rotateKeys, keys);
  } else {
    refuse(RESERVED_NAMES.assertKeyEpoch, keys);
    refuse(RESERVED_NAMES.rotateKeys, keys);
  }
  if (b.upgrades === "fixed") {
    for (const r of [RESERVED_NAMES.assertUpgradeClass, RESERVED_NAMES.upgradeCircuits, RESERVED_NAMES.upgradeContract]) refuse(r, upgrades);
  } else {
    needSelector(RESERVED_NAMES.assertUpgradeClass, upgrades);
    need(RESERVED_NAMES.upgradeCircuits, upgrades);
    if (b.upgrades === "contract") need(RESERVED_NAMES.upgradeContract, upgrades);
    else refuse(RESERVED_NAMES.upgradeContract, upgrades);
  }
  if (use.sharedOnchain) {
    const why = "a package takes secret-shared on-chain intake";
    need(RESERVED_NAMES.getEncKey, why);
    need(RESERVED_NAMES.rotateEncKey, why);
  }
  return problems;
}

/** The bricks `artifact` reports (`bricksOf`; fixed and fixed for a
 * contract with no state view), refusing an artifact that disagrees with
 * them (`brickProblems`). */
export function checkedBricks(artifact: BrickArtifact, use: BrickUse): Bricks {
  const bricks = bricksOf(artifact);
  const problems = brickProblems(artifact, bricks, use);
  if (problems.length > 0) throw new RangeError(`${artifact.name}: ${problems.join("; ")}`);
  return bricks ?? { node_keys: "fixed", upgrades: "fixed" };
}
