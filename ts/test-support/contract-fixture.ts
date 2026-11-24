// The contract ABI fixtures (fixtures/<Contract>.*.abi.json): the storage
// layout and the named functions' FunctionAbi parts, as aztec.js 6.0.0
// loadContractArtifact reads them from `aztec compile` (nargo compile, then
// bb aztec_process) output; and the circuit ABI fixtures
// (fixtures/<circuit>.abi.json, <circuit>.circuit.json): the compiled round
// circuit's `noir_version` and the `abi` parts the fixture keeps, with its
// `bytecode` when it keeps one. pss-client's fixtures.test.ts compares each
// fixture with its build. A command line, from the repository root with the
// pinned tools in the environment (`source scripts/toolchain.sh` in bash
// sets NARGO_BIN, CONTRACT_NARGO_BIN and BB_BIN):
//
//   node --conditions=source ts/test-support/contract-fixture.ts build      # compile every fixture's contract into its target directory
//   node --conditions=source ts/test-support/contract-fixture.ts write      # rewrite every contract fixture from its build, same functions
//   node --conditions=source ts/test-support/contract-fixture.ts circuits   # compile every fixture's circuit and rewrite its fixture
//   node --conditions=source ts/test-support/contract-fixture.ts <artifact.json> <fixture.json> <function>...
//
// The last form writes or extends one fixture, the functions in the
// fixture's order.

import { execFileSync } from "node:child_process";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { argv, env } from "node:process";
import { fileURLToPath } from "node:url";

import { loadContractArtifact, type ContractArtifact } from "@aztec-labs/stdlib/abi";
import { fixturePath } from "./support.ts";

/** The repository root. */
export const REPO = fileURLToPath(new URL("../../", import.meta.url));

/** A contract fixture's source: the contract package, the directory its
 * build goes to (the package's workspace target) and the built file in it. */
export interface ContractSource {
  pkg: string;
  target: string;
  file: string;
}

// fixture -> the contract package it is read from
export const CONTRACTS: Record<string, ContractSource> = {
  "PssPublicTest.result.abi.json": {
    pkg: "noir/pss_public_contract_test",
    target: "noir/pss_public_contract_test/target",
    file: "pss_public_contract_test-PssPublicTest.json",
  },
  "AmmTip.result.abi.json": {
    pkg: "examples/amm-tip/contract/amm_tip",
    target: "examples/amm-tip/contract/target",
    file: "amm_tip-AmmTip.json",
  },
  "LendingTip.result.abi.json": {
    pkg: "examples/lending-tip/contract/lending_tip",
    target: "examples/lending-tip/contract/target",
    file: "lending_tip-LendingTip.json",
  },
};

// fixture -> the round circuit package it is the nargo 1.0.0 output of
export const CIRCUITS: Record<string, string> = {
  "amm_init.abi.json": "examples/amm/circuits/amm_init",
  "amm_swap.abi.json": "examples/amm/circuits/amm_swap",
  "amm_init_tip.abi.json": "examples/amm-tip/circuits/amm_init_tip",
  "amm_swap_tip.abi.json": "examples/amm-tip/circuits/amm_swap_tip",
  "amm_swap_tip_shared.abi.json": "examples/amm-tip/circuits/amm_swap_tip_shared",
  "lending_init.abi.json": "examples/lending-tip/circuits/lending_init",
  "deposit.abi.json": "examples/lending-tip/circuits/deposit",
  "deposit_shared.abi.json": "examples/lending-tip/circuits/deposit_shared",
  "withdraw_shared.abi.json": "examples/lending-tip/circuits/withdraw_shared",
  "supply_shared.abi.json": "examples/lending-tip/circuits/supply_shared",
  "withdraw_supply_shared.abi.json": "examples/lending-tip/circuits/withdraw_supply_shared",
  "quote_shared.abi.json": "examples/lending-tip/circuits/quote_shared",
  "borrow_shared.abi.json": "examples/lending-tip/circuits/borrow_shared",
  "repay_shared.abi.json": "examples/lending-tip/circuits/repay_shared",
  "view_shared.abi.json": "examples/lending-tip/circuits/view_shared",
  "liquidate_shared.abi.json": "examples/lending-tip/circuits/liquidate_shared",
  "pss_seed.abi.json": "examples/amm/circuits/pss_seed",
  "pss_seed.circuit.json": "examples/amm/circuits/pss_seed",
};

/** The compiled artifact of a circuit fixture's package, repository-relative. */
export const builtCircuit = (pkg: string): string => `${pkg}/target/${pkg.split("/").pop()}.json`;

/** A circuit fixture as kept. */
export interface CircuitFixture {
  noir_version: string;
  abi: Record<string, unknown>;
  bytecode?: string;
}

/** The built artifact of a contract fixture, repository-relative. */
export const builtFile = (c: ContractSource): string => `${c.target}/${c.file}`;

/** The FunctionAbi parts a contract fixture keeps (no bytecode or keys; its
 * error types are left empty). */
export const FUNCTION_KEYS = ["name", "functionType", "isOnlySelf", "isStatic", "isInitializer", "parameters", "returnTypes"] as const;

/** A contract fixture as kept. */
export interface ContractFixture {
  contract: string;
  storageLayout: Record<string, { slot: string }>;
  functions: Record<string, unknown>[];
}

/** The artifact's storage layout as a fixture keeps it. */
export function keptLayout(built: ContractArtifact): Record<string, { slot: string }> {
  return Object.fromEntries(Object.entries(built.storageLayout).map(([k, v]) => [k, { slot: v.slot.toString() }]));
}

/** Every function of the artifact, private, utility and public. */
export function allFunctions(built: ContractArtifact): Record<string, unknown>[] {
  return [...built.functions, ...(built.nonDispatchPublicFunctions ?? [])] as unknown as Record<string, unknown>[];
}

/** The fixture of `names` in the artifact at `path`; RangeError for a name it lacks. */
function contractFixture(path: string, names: readonly string[]): ContractFixture {
  const built = loadContractArtifact(JSON.parse(readFileSync(path, "utf8")));
  const all = allFunctions(built);
  const functions = names.map((name) => {
    const f = all.find((x) => x.name === name);
    if (f === undefined) throw new RangeError(`${path}: no function ${name}`);
    return { ...Object.fromEntries(FUNCTION_KEYS.map((k) => [k, f[k]])), errorTypes: {} };
  });
  return { contract: built.name, storageLayout: keptLayout(built), functions };
}


function writeFixture(out: string, fixture: ContractFixture): void {
  writeFileSync(out, `${JSON.stringify(fixture, null, 1)}\n`);
}

/** Compiles each fixture's contract with the pinned contract nargo and
 * processes it with bb (`aztec compile`'s two steps). */
function build(): void {
  const tool = (name: string) => {
    const bin = env[name];
    if (bin === undefined || bin === "") throw new Error(`${name} is not set: source scripts/toolchain.sh`);
    return bin;
  };
  const nargo = tool("CONTRACT_NARGO_BIN");
  const bb = tool("BB_BIN");
  for (const c of Object.values(CONTRACTS)) {
    const target = join(REPO, c.target);
    console.log(`compile ${c.pkg}`);
    execFileSync(nargo, ["compile", "--program-dir", join(REPO, c.pkg), "--target-dir", target], { stdio: "inherit" });
    execFileSync(bb, ["aztec_process", "-i", join(target, c.file)], { stdio: "inherit" });
  }
}

/** Rewrites each contract fixture from its build, keeping its functions in
 * order (a renamed function: write that fixture with the third form). */
function writeAll(): void {
  for (const [name, c] of Object.entries(CONTRACTS)) {
    const path = join(REPO, builtFile(c));
    if (!existsSync(path)) throw new Error(`${builtFile(c)} is not built: node --conditions=source ts/test-support/contract-fixture.ts build`);
    const kept = JSON.parse(readFileSync(fixturePath(name), "utf8")) as ContractFixture;
    writeFixture(fixturePath(name), contractFixture(path, kept.functions.map((f) => String(f.name))));
    console.log(`wrote ${fixturePath(name)}`);
  }
}

/** Compiles each circuit fixture's package with the pinned nargo and
 * rewrites the fixture from it, keeping the fixture's `abi` parts, its
 * bytecode when it has one, and its layout. */
function writeCircuits(): void {
  const nargo = env.NARGO_BIN;
  if (nargo === undefined || nargo === "") throw new Error("NARGO_BIN is not set: source scripts/toolchain.sh");
  const pkgs = new Set(Object.values(CIRCUITS));
  for (const pkg of pkgs) {
    console.log(`compile ${pkg}`);
    execFileSync(nargo, ["compile", "--silence-warnings"], { cwd: join(REPO, pkg), stdio: "inherit" });
  }
  for (const [name, pkg] of Object.entries(CIRCUITS)) {
    const built = JSON.parse(readFileSync(join(REPO, builtCircuit(pkg)), "utf8")) as CircuitFixture;
    const text = readFileSync(fixturePath(name), "utf8");
    const kept = JSON.parse(text) as CircuitFixture;
    const abi = Object.fromEntries(Object.keys(kept.abi).map((k) => [k, built.abi[k]]));
    const fixture: CircuitFixture = { noir_version: built.noir_version, abi, ...("bytecode" in kept && { bytecode: built.bytecode }) };
    // the layout the fixture has: indented with a final newline, or one line
    const indented = text.startsWith("{\n");
    writeFileSync(fixturePath(name), indented ? `${JSON.stringify(fixture, null, 1)}\n` : JSON.stringify(fixture));
    console.log(`wrote ${fixturePath(name)}`);
  }
}

if (import.meta.url === `file://${argv[1]}`) {
  const [first, out, ...names] = argv.slice(2);
  if (first === "build" && out === undefined) build();
  else if (first === "write" && out === undefined) writeAll();
  else if (first === "circuits" && out === undefined) writeCircuits();
  else if (first !== undefined && out !== undefined && names.length > 0) writeFixture(out, contractFixture(first, names));
  else {
    console.error("usage: node --conditions=source ts/test-support/contract-fixture.ts build | write | circuits | <artifact.json> <fixture.json> <function>...");
    process.exit(2);
  }
}
