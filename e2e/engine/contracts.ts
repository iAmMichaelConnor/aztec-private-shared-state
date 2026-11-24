// The scenario's contracts: built from the example's sources (or a package
// of the repository's own, such as noir/pss_probe) into the run directory,
// then deployed as the scenario's `contracts` say.
import type { AztecAddress } from "@aztec-labs/aztec.js/addresses";
import { Contract } from "@aztec-labs/aztec.js/contracts";
import { loadContractArtifact, type ContractArtifact } from "@aztec-labs/stdlib/abi";
import type { ContractInstanceWithAddress } from "@aztec-labs/stdlib/contract";
import type { Wallet } from "@aztec-labs/aztec.js/wallet";
import type { FeeSendOptions } from "@aztec-pss/pss-client";

import { execFile } from "node:child_process";
import { closeSync, cpSync, mkdirSync, openSync, readFileSync, readdirSync, rmSync, writeFileSync, writeSync } from "node:fs";
import { isAbsolute, join, resolve } from "node:path";
import { promisify } from "node:util";

import type { ExampleFiles, Harness } from "../harness/harness.ts";
import type { Value } from "./scope.ts";

/** A contract of the scenario. */
export interface ContractSpec {
  /** The contract package under `<example>/contract/`, or under `dir`. */
  package: string;
  /** The directory holding the package, relative to the repository root, in
   * place of the example's `contract/` (`noir` for the test probe). */
  dir?: string;
  /** The deploying account. */
  from: string;
  /** The initializer and its arguments; without `deploy` the contract is deployed without an initializer. */
  deploy?: { initializer: string; args: Value[] };
}

/** A deployed contract. */
export interface Deployed {
  address: AztecAddress;
  artifact: ContractArtifact;
  /** What another wallet registers to call it. */
  instance: ContractInstanceWithAddress;
}

// The contract build. The driver compiles each contract package
// of the scenario itself, into <run>/contracts/<package> (never into the
// repository's target/), with the pinned contract nargo (1.0.0-rc.3) and the
// compiler's default inliner, then runs the pinned bb's aztec_process
// (transpile and private-function verification keys), each bounded by
// 1800 s, for a cold dependency cache. The harness.json file names the tools but
// no contract artifact, and a run must deploy what its sources say; a cached
// artifact from elsewhere could deploy a stale contract. Within one run the
// sources do not change, so each package is built once and every later
// deployment of it (the lending deployments' two tokens, a second deployment
// of the same app) reuses that build; builds of different packages may run
// side by side.
const BUILD_TIMEOUT_MS = 1_800_000;
const execFileAsync = promisify(execFile);

/** This process's builds, by run directory and package directory. */
const built = new Map<string, Promise<ContractArtifact>>();

/** buildPackage of an example's contract package `pkg`. */
export function buildContract(h: Harness, files: Pick<ExampleFiles, "dir">, scenarioName: string, pkg: string): Promise<ContractArtifact> {
  return buildPackage(h, join(files.dir, "contract", pkg), scenarioName, pkg);
}

/** A scenario contract's build: its package under `dir` when the spec names
 * one, else the example's. */
export function buildSpec(h: Harness, files: Pick<ExampleFiles, "dir">, scenarioName: string, spec: ContractSpec): Promise<ContractArtifact> {
  return spec.dir === undefined ? buildContract(h, files, scenarioName, spec.package) : buildPackage(h, join(h.repoRoot, spec.dir, spec.package), scenarioName, spec.package);
}

/** nargo compile plus bb aztec_process of the contract package at
 * `packageDir`, logged to <run>/logs/<scenario>-contract-build-<package>.log
 * and written into <run>/contracts/<package>; once per package and run. */
function buildPackage(h: Harness, packageDir: string, scenarioName: string, pkg: string): Promise<ContractArtifact> {
  const key = `${h.runDir}\0${packageDir}`;
  let build = built.get(key);
  if (!build) {
    build = compileContract(h, packageDir, scenarioName, pkg);
    built.set(key, build);
  }
  return build;
}

// The second class of an upgradable contract. A class upgrade
// (pss_public_contract `upgrade_contract`) moves the instance to another
// contract class, and the e2e builds that class from the very sources of the
// first, with one edit: the package is copied into <run>/staged/<package>@<tag>,
// each relative `path` dependency of its Nargo.toml made absolute (from the
// package's own directory), one source line replaced (`edit`: its file,
// the text, which must occur exactly once, and its replacement; amm-tip's
// `CLASS_VERSION: Field = 1;` in src/class.nr becomes `= 2;`), then compiled
// and processed as buildPackage does, into <run>/contracts/<package>@<tag>.
// Nothing is copied in the repository: nargo refuses a crate root reached
// through a symbolic link, so the second class cannot be a package of its
// own without a copy of the contract.
/** One source edit of a staged contract package. */
export interface SourceEdit {
  /** The file, relative to the package directory. */
  file: string;
  /** The text to replace; it must occur exactly once. */
  replace: string;
  with: string;
}

/** The contract package `pkg` built from its sources with `edit` applied
 * (see above); once per package, tag and run. */
export function buildStagedContract(h: Harness, files: Pick<ExampleFiles, "dir">, scenarioName: string, pkg: string, tag: string, edit: SourceEdit): Promise<ContractArtifact> {
  const packageDir = join(files.dir, "contract", pkg);
  const name = `${pkg}@${tag}`;
  const key = `${h.runDir}\0${packageDir}\0${tag}`;
  let build = built.get(key);
  if (!build) {
    const staged = join(h.runDir, "staged", name);
    rmSync(staged, { recursive: true, force: true });
    cpSync(packageDir, staged, { recursive: true, filter: (src) => !src.includes(`${packageDir}/target`) });
    const toml = join(staged, "Nargo.toml");
    writeFileSync(
      toml,
      readFileSync(toml, "utf8").replace(/path\s*=\s*"([^"]+)"/g, (whole, p: string) => (isAbsolute(p) ? whole : `path = "${resolve(packageDir, p)}"`)),
    );
    const source = join(staged, edit.file);
    const text = readFileSync(source, "utf8");
    const at = text.split(edit.replace).length - 1;
    if (at !== 1) throw new Error(`${pkg}/${edit.file}: \`${edit.replace}\` occurs ${at} times; a staged edit replaces exactly one`);
    writeFileSync(source, text.replace(edit.replace, edit.with));
    build = compileContract(h, staged, scenarioName, name);
    built.set(key, build);
  }
  return build;
}

async function compileContract(h: Harness, packageDir: string, scenarioName: string, pkg: string): Promise<ContractArtifact> {
  const targetDir = join(h.runDir, "contracts", pkg);
  mkdirSync(targetDir, { recursive: true });
  const log = openSync(join(h.runDir, "logs", `${scenarioName}-contract-build-${pkg}.log`), "a");
  try {
    const run = async (bin: string, args: string[]) => {
      // execFile buffers the output it is given; the log file takes it instead.
      const child = execFileAsync(bin, args, { timeout: BUILD_TIMEOUT_MS, env: process.env, maxBuffer: 1 << 30 });
      try {
        const { stdout, stderr } = await child;
        writeSync(log, stdout + stderr);
      } catch (e) {
        const { stdout = "", stderr = "" } = e as { stdout?: string; stderr?: string };
        writeSync(log, stdout + stderr);
        throw new Error(`${bin} ${args.join(" ")} failed; see ${join(h.runDir, "logs", `${scenarioName}-contract-build-${pkg}.log`)}`, { cause: e });
      }
    };
    await run(h.contractNargoBin, ["compile", "--program-dir", packageDir, "--target-dir", targetDir]);
    const artifacts = readdirSync(targetDir).filter((f) => f.endsWith(".json"));
    if (artifacts.length !== 1) throw new Error(`contract build wrote ${artifacts.length} artifacts in ${targetDir}`);
    const path = join(targetDir, artifacts[0]!);
    await run(h.bbBin, ["aztec_process", "-i", path]);
    const json = JSON.parse(readFileSync(path, "utf8")) as { transpiled?: boolean };
    if (json.transpiled !== true) throw new Error(`${path} was not processed by bb aztec_process`);
    return loadContractArtifact(json as never);
  } finally {
    closeSync(log);
  }
}

/** Deploys one contract from `from`, through its initializer when the spec
 * names one, paying under `fee` (Network.fee("deploy")). */
export async function deployContract(
  wallet: Wallet,
  artifact: ContractArtifact,
  from: AztecAddress,
  deploy: { initializer: string; args: unknown[] } | undefined,
  fee: FeeSendOptions,
): Promise<Deployed> {
  const method = deploy ? Contract.deploy(wallet, artifact, deploy.args, deploy.initializer) : Contract.deploy(wallet, artifact, []);
  const { contract: deployed, instance } = await method.send({ ...fee, from, skipInitialization: deploy === undefined });
  return { address: deployed.address, artifact, instance };
}
