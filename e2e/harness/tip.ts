// The tip deployments of a run (docs/ARCHITECTURE.md section 6, "Deployment,
// configure and the init round"; DESIGN.md, "The tip sections"). run.sh calls
// it twice when E2E_TIP=1:
//
//   node harness/tip.ts plan <deployment> ...   after `sidecar-node setup`, before any service starts
//   node harness/tip.ts deploy                  once the network is up and the fee setup passed
//   node harness/tip.ts init                    once the relayers run
//
// A deployment is e2e/tip/<deployment>.json, the test-only facts: the example
// (prepared by run.sh), the app's deployment descriptor
// (examples/<example>/deployments/<descriptor>.json: its contract package,
// the package list with each package's circuit and state key names, the
// init round, the stale period and the contract each placeholder pinned
// read calls), the contracts it deploys first (each one's address goes into
// the Config and, through the descriptor's read_contracts, into the
// manifests' pinned reads of it), a stale period in place of the
// descriptor's, the tokens it mints once deployed (`fund`), the app's own
// Config members besides `tip`, the app's init function, and the result
// function of each package whose results do not land through
// `process_result`.
//
// plan builds each contract (engine/contracts.ts), the deployment's own and
// the ones it deploys first, fixes the addresses of those (a salt drawn
// each, a universal deployment, the constructor arguments resolved),
// generates the deployment's contract manifest (pss-client
// buildContractManifest: every slot from the artifact, the vk hashes as
// prepared) and writes it and each package's circuit manifest from it
// (<run>/manifests/tip-<deployment>/), and two pss-client configurations of
// them (<run>/pss-client/: tip-<deployment>.json of every package, for the
// drivers, and tip-<deployment>-relayer.json of the list's, for the relayer,
// which finds a result's circuit by its vk hash), draws its salt, computes
// the constructor's pins (pss-client tipPins over the manifest's listed
// packages, with the sig keys setup printed, so the address commits to the
// circuits) and from them the address of a universal deployment, which is
// the namespace; the manifest must not name that address (a read of the
// contract itself is `$self`). It writes <run>/config/tip.toml, the
// [[tip.namespaces]] allowlist (each deployment's address), which run.sh
// copies unchanged into the three node configs and the orchestrator's; the
// slots are the registered contract manifest's, which the machine reads
// from the registry. It records each
// deployment in harness.json under tip.deployments. The namespace must be
// known before the nodes and the orchestrator start, and nothing is sent
// anywhere: the salt stays in the run directory until deploy.
//
// deploy first deploys each deployment's own first contracts at their
// planned addresses (the oracle a pinned read calls, the tokens a market
// holds), then runs
// pss-client deployTip for each planned
// deployment with a TipDeployer over aztec.js: the address must be the
// planned one, the contract manifest (every package, the aliases included)
// is REGISTERed once, at seq 0, by a fresh owner key (saved under keys/),
// then the constructor and configure land, configure with the answer's
// three manifest signatures, both paid through wFJ (the pss-client fee setting)
// from the first local-network account (harness/fees.ts funded it). It then
// reads back the slots the contract manifest names (the stale period, the
// configured flag, the init inputs),
// mints the spec's `fund` (each token's private balances of the
// local-network accounts and the deployment's public balance), and writes the
// relayer's configuration of each deployment, which pays through wFJ from
// the relayer account harness/fees.ts funded, FETCHes on the orchestrator's
// public listener and lands the init round with the init inputs read back from the chain.
//
// init waits, for each deployment with an init round, until every slot the
// init creates holds a commitment (the scheduler computed the round, the
// relayer landed it) and the relayer's status has left "pending", polling
// both, at most INIT_TIMEOUT seconds (default 1800), and fails naming the
// deployment, the slot and the relayer's status otherwise. The relayer must report the landing as its
// own transaction (GET /status, `init`), which it records in harness.json
// (tip.deployments.<name>.initTx) for the fee-payer check.
//
// A contract whose constructor takes an `upgrade_authority` (upgradable
// circuits) is given the local network's first account, the operator. A
// spec may name an upgraded contract manifest of the same contract
// (`upgrade`, its own descriptor): plan generates it beside the deployed one
// (<run>/manifests/tip-<deployment>-upgrade/) for a scenario to register and
// schedule (steps/tip-upgrade.ts), and the relayer's configuration lists
// each package it replaces as `<package>@upgrade`, so the relayer finds a
// result's circuit by its vk hash under either version.
//
// A spec may also name the contract's second class (`classUpgrade`, one
// source edit): plan builds it from the same sources (engine/contracts.ts
// buildStagedContract), generates its contract manifest from the deployment's
// descriptor beside the deployed one (<run>/manifests/tip-<deployment>-class/)
// for a scenario to publish, register and schedule, and gives the relayer
// its artifact (`upgradeArtifacts`), so it follows the instance to it.
//
// Environment: what every harness script gets (E2E_HARNESS, NODE_EXTRA_CA_CERTS);
// plan also AZTEC_NODE_URL for the relayer configuration.
import { getInitialTestAccountsData } from "@aztec-labs/accounts/testing/lazy";
import { AztecAddress } from "@aztec-labs/aztec.js/addresses";
import { BatchCall, Contract, type ContractFunctionInteraction } from "@aztec-labs/aztec.js/contracts";
import { Fr } from "@aztec-labs/aztec.js/fields";
import type { AztecNode } from "@aztec-labs/aztec.js/node";
import { getPXEConfig } from "@aztec-labs/pxe/server";
import type { ContractArtifact } from "@aztec-labs/stdlib/abi";
import { loadContractArtifact } from "@aztec-labs/stdlib/abi";
import { getContractInstanceFromInstantiationParams } from "@aztec-labs/stdlib/contract";
import { TxHash } from "@aztec-labs/stdlib/tx";
import { EmbeddedWallet } from "@aztec-labs/wallets/embedded";
import { registerInitialLocalNetworkAccountsInWallet } from "@aztec-labs/wallets/testing";
import {
  OwnerKey,
  buildContractManifest,
  contractManifestHash,
  deployTip,
  feeOptions,
  fieldAddress,
  fieldHex,
  listedPackages,
  refuseOwnAddress,
  registerWfj,
  tipPins,
  type ContractManifest,
  type Descriptor,
  type ResultFunction,
  type Triple,
} from "@aztec-pss/pss-client";

import { chmodSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { buildContract, buildStagedContract, type SourceEdit } from "../engine/contracts.ts";
import { fail, poll } from "../engine/scope.ts";
import { relayerStatusOf, type RelayerStatus } from "../engine/tip.ts";
import { TIP_FEE_SETTINGS, tipFeeSetting } from "./fee-settings.ts";
import { compiledCircuit, connectNode, declaredGas, example, harnessLogger, loadHarness, pssClient, timed, type CircuitFiles, type CreditSpec, type FirstDeployment, type Harness, type TipDeployment } from "./harness.ts";

const logger = harnessLogger("tip");

/** A contract a deployment deploys before REGISTER and its own contract
 * (DeploymentSpec.contracts). */
interface FirstContract {
  /** The example directory holding `contract/<package>` (its base name);
   * default the deployment's. */
  example?: string;
  /** The contract package. */
  package: string;
  /** Its `constructor`'s arguments, `$operator` standing for the local
   * network's first account (the deploying account); without them it is
   * deployed without an initializer. */
  args?: unknown[];
}

/** e2e/tip/<deployment>.json. */
interface DeploymentSpec {
  /** The example directory's base name, prepared by run.sh (E2E_EXAMPLES). */
  example: string;
  /** The deployment descriptor: examples/<example>/deployments/<descriptor>.json. */
  descriptor: string;
  /** The contracts deployed first, in order, by the name a Config member
   * refers to as `$<name>` (its address), the descriptor's read_contracts
   * names a pinned read's callee by, and a driver names
   * `<tip name>.<name>`. Default none. */
  contracts?: Record<string, FirstContract>;
  /** The stale period, in blocks, in place of the descriptor's (null: never
   * skipped); the contract manifest and the constructor take it. */
  staleBlocks?: number | null;
  /** The app's own Config members besides `tip`, as aztec.js encodes them;
   * a string `$<name>` at any depth (a member of a struct member too:
   * lending's `deposit.token`) is the address of the first contract of that
   * name. */
  config: Record<string, unknown>;
  /** Tokens minted once the deployment is configured, by first contract (a
   * token whose constructor made `$operator` its admin and minter, as
   * examples/token's does): `accounts`, the amount minted into the private
   * balance of every local-network initial account (`mint_to_private`; a
   * scenario's accounts are among them), and `app`, the amount minted into
   * the deployment contract's public balance (`mint_to_public`: lending's
   * seeded liquidity, its Config's `init_liquidity`, in the borrowed
   * asset). One transaction per token from the operator, paid through wFJ
   * under the deploy kind. Default none. */
  fund?: Record<string, { accounts?: number; app?: number }>;
  /** The app's init function the relayer lands the init round through
   * (the round itself is the descriptor's `init`). */
  init?: { method: string };
  /** The deployment descriptor of an upgraded contract manifest of the
   * same contract (examples/<example>/deployments/<upgrade>.json: the same
   * packages and state keys, other circuits), which plan generates beside
   * the deployed one (TipDeployment.upgrade) for a scenario to register and
   * schedule. Only for a contract with upgradable circuits. */
  upgrade?: string;
  /** The second class of the contract, for a class upgrade (`upgrades:
   * contract`): the contract package built again from its sources with one
   * edit (engine/contracts.ts buildStagedContract; amm-tip's
   * `{ "file": "src/class.nr", "replace": "CLASS_VERSION: Field = 1;",
   * "with": "CLASS_VERSION: Field = 2;" }`). Plan generates its contract
   * manifest from the deployment's descriptor (the same circuits, the new
   * class id; TipDeployment.classUpgrade) for a scenario to publish,
   * register and schedule. */
  classUpgrade?: SourceEdit;
  /** Per package whose results land through another function than
   * `process_result`, that function and the arguments it takes before the
   * library's (the relayer's `methods`; lending's secret-shared rounds,
   * `{ "name": "process_shared", "args": [<ROUND_* index>] }` and the header
   * form). Default none: every result lands through `process_result`. */
  methods?: Record<string, ResultFunction>;
  /** The app's fee setting, by its name in harness/fee-settings.ts
   * TIP_FEE_SETTINGS: what the harness's and the relayer's transactions of
   * the deployment, and those of a scenario that uses it, pay under.
   * Default pss-client's DEFAULT_FEE_SETTING. */
  fee?: string;
  /** How the app keeps credits (lending's), for the steps that fund, read
   * and are paid into them. Default none. */
  credit?: CreditSpec;
}

function readSpec(h: Harness, name: string): DeploymentSpec {
  const path = join(h.repoRoot, "e2e", "tip", `${name}.json`);
  let text: string;
  try {
    text = readFileSync(path, "utf8");
  } catch {
    fail(`no tip deployment e2e/tip/${name}.json (E2E_TIP_DEPLOYMENTS names deployments by file, without .json)`);
  }
  const spec = JSON.parse(text) as DeploymentSpec;
  if (typeof spec.descriptor !== "string") fail(`e2e/tip/${name}.json: descriptor names no deployment descriptor (examples/${spec.example}/deployments/<descriptor>.json)`);
  const descriptor = readDescriptor(h, spec);
  if ((spec.init === undefined) !== (descriptor.init === undefined)) fail(`e2e/tip/${name}.json: init.method is given exactly when the descriptor has an init round`);
  if (spec.init && typeof spec.init.method !== "string") fail(`e2e/tip/${name}.json: init.method names no init function (the relayer lands the init round through it)`);
  for (const [pkg, fn] of Object.entries(spec.methods ?? {})) {
    if (!descriptor.packages.some((p) => p.name === pkg && p.alias_of === undefined)) fail(`e2e/tip/${name}.json: methods.${pkg} is not a listed package of the descriptor`);
    if (typeof fn?.name !== "string" || fn.name === "") fail(`e2e/tip/${name}.json: methods.${pkg} names no result function ({ name, args? })`);
    if (fn.args !== undefined && !Array.isArray(fn.args)) fail(`e2e/tip/${name}.json: methods.${pkg}.args is not a list`);
  }
  if (spec.upgrade !== undefined) {
    const upgraded = readDescriptor(h, { ...spec, descriptor: spec.upgrade });
    if (upgraded.contract !== descriptor.contract) fail(`e2e/tip/${name}.json: upgrade ${spec.upgrade} deploys contract ${upgraded.contract}, not the deployment's ${descriptor.contract}`);
  }
  for (const [k, c] of Object.entries(spec.contracts ?? {})) {
    if (!/^[a-z][a-z0-9_]*$/.test(k)) fail(`e2e/tip/${name}.json: contracts.${k}: a name of lower-case letters, digits and _`);
    if (typeof c.package !== "string") fail(`e2e/tip/${name}.json: contracts.${k} names no package`);
  }
  for (const [path, v] of contractRefs(spec.config, "config")) {
    if (!Object.hasOwn(spec.contracts ?? {}, v.slice(1))) fail(`e2e/tip/${name}.json: ${path} is ${v}, which names no contract of \`contracts\``);
  }
  if (spec.fee !== undefined && !Object.hasOwn(TIP_FEE_SETTINGS, spec.fee)) fail(`e2e/tip/${name}.json: fee ${spec.fee} is not a fee setting of harness/fee-settings.ts (${Object.keys(TIP_FEE_SETTINGS).join(", ")})`);
  if (spec.credit !== undefined) {
    const c = spec.credit;
    if (typeof c.fund !== "string" || typeof c.balance !== "string") fail(`e2e/tip/${name}.json: credit names its fund and balance functions`);
    if (Object.keys(c.assets ?? {}).length === 0) fail(`e2e/tip/${name}.json: credit.assets names no token`);
    for (const [k, asset] of Object.entries(c.assets)) {
      if (!Object.hasOwn(spec.contracts ?? {}, k)) fail(`e2e/tip/${name}.json: credit.assets.${k} names no contract of \`contracts\``);
      if (!Number.isSafeInteger(asset)) fail(`e2e/tip/${name}.json: credit.assets.${k} is not an asset number`);
    }
  }
  for (const [k, f] of Object.entries(spec.fund ?? {})) {
    if (!Object.hasOwn(spec.contracts ?? {}, k)) fail(`e2e/tip/${name}.json: fund.${k} names no contract of \`contracts\``);
    for (const [m, v] of Object.entries(f)) {
      if ((m !== "accounts" && m !== "app") || !Number.isSafeInteger(v) || (v as number) <= 0) fail(`e2e/tip/${name}.json: fund.${k}.${m}: \`accounts\` or \`app\`, a positive amount`);
    }
  }
  for (const [fn, k] of Object.entries(descriptor.read_contracts ?? {})) {
    if (!Object.hasOwn(spec.contracts ?? {}, k)) fail(`e2e/tip/${name}.json: the descriptor's ${fn} reads call contract ${k}, which \`contracts\` does not deploy`);
  }
  return spec;
}

/** The deployment descriptor a spec names. */
function readDescriptor(h: Harness, spec: DeploymentSpec): Descriptor {
  const path = join(h.repoRoot, "examples", spec.example, "deployments", `${spec.descriptor}.json`);
  try {
    return JSON.parse(readFileSync(path, "utf8")) as Descriptor;
  } catch (e) {
    fail(`no deployment descriptor examples/${spec.example}/deployments/${spec.descriptor}.json: ${(e as Error).message}`);
  }
}

/** The contract package the descriptor deploys. */
function contractPackage(descriptor: Descriptor): string {
  return descriptor.contract ?? fail(`descriptor ${descriptor.name} names no contract package`);
}

/** The local network's first account: what `$operator` stands for. */
async function operatorAddress(): Promise<AztecAddress> {
  const [first] = await getInitialTestAccountsData();
  return first?.address ?? fail("the local network has no initial account");
}

/** A first contract's constructor arguments with `$operator` resolved. */
function contractArgs(c: FirstContract, operator: AztecAddress): unknown[] | undefined {
  return c.args?.map((a) => (a === "$operator" ? operator : a));
}

/** Every string `$<name>` in a Config value, at any depth, with its path. */
function contractRefs(v: unknown, path: string): [string, string][] {
  if (typeof v === "string") return v.startsWith("$") ? [[path, v]] : [];
  if (Array.isArray(v)) return v.flatMap((x, i) => contractRefs(x, `${path}[${i}]`));
  if (v !== null && typeof v === "object") return Object.entries(v).flatMap(([k, x]) => contractRefs(x, `${path}.${k}`));
  return [];
}

/** A Config value with each string `$<name>`, at any depth, the address of that first contract. */
function resolveRefs(v: unknown, contracts: Record<string, FirstDeployment>): unknown {
  if (typeof v === "string") return v.startsWith("$") ? fieldAddress(contracts[v.slice(1)]!.address) : v;
  if (Array.isArray(v)) return v.map((x) => resolveRefs(x, contracts));
  if (v !== null && typeof v === "object") return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, resolveRefs(x, contracts)]));
  return v;
}

/** The app's Config members with each `$<name>` the address of that first contract. */
function configOf(spec: DeploymentSpec, contracts: Record<string, FirstDeployment>): Record<string, unknown> {
  return resolveRefs(spec.config, contracts) as Record<string, unknown>;
}

/** The constructor's parameter names. */
function constructorParams(artifact: ContractArtifact): string[] {
  const ctor = [...artifact.functions, ...artifact.nonDispatchPublicFunctions].find((f) => f.name === "constructor") ?? fail(`${artifact.name} has no constructor`);
  return ctor.parameters.map((p) => p.name);
}

/** Whether the contract's constructor pins an upgrade authority
 * (`upgrade_authority`: pss_public_contract CircuitUpgrades). */
function takesUpgradeAuthority(artifact: ContractArtifact): boolean {
  return constructorParams(artifact).includes("upgrade_authority");
}

/** The tip contract's constructor arguments: its Config (the spec's members
 * with `tip` the pins), then, for a contract with upgradable circuits, the
 * upgrade authority: the local network's first account, the operator, which
 * scenarios name `operator` and send the authority's call from. */
function constructorArgs(artifact: ContractArtifact, config: Record<string, unknown>, pins: unknown, operator: AztecAddress): unknown[] {
  const params = constructorParams(artifact);
  const args: unknown[] = [{ ...config, tip: pins }];
  if (params.includes("upgrade_authority")) args.push(operator);
  if (params.length !== args.length) fail(`${artifact.name}'s constructor takes (${params.join(", ")}); the harness gives config${args.length > 1 ? " and upgrade_authority" : ""}`);
  return args;
}

/** The deployment's first contracts, built and placed: a salt each and the
 * address of the universal deployment of the constructor arguments. */
async function planContracts(h: Harness, name: string, spec: DeploymentSpec): Promise<Record<string, FirstDeployment>> {
  const out: Record<string, FirstDeployment> = {};
  const operator = await operatorAddress();
  for (const [k, c] of Object.entries(spec.contracts ?? {})) {
    const dir = join(h.repoRoot, "examples", c.example ?? spec.example);
    const artifact = await timed(logger, `${name}: contract build of ${k} (${c.package})`, async () => buildContract(h, { dir }, `tip-${name}`, c.package));
    const args = contractArgs(c, operator);
    const salt = Fr.random();
    const instance = await getContractInstanceFromInstantiationParams(artifact, {
      ...(args && { constructorArtifact: "constructor", constructorArgs: args }),
      salt,
      deployer: AztecAddress.ZERO,
    });
    out[k] = { package: c.package, artifact: artifactPath(h, c.package), salt: salt.toString(), address: fieldHex(instance.address.toBigInt()) };
    logger.info(`${name}: ${k} (${c.package}) will be at ${out[k].address}`);
  }
  return out;
}

/** The artifact file the contract build (engine/contracts.ts buildPackage)
 * wrote into <run>/contracts/<package>. */
function artifactPath(h: Harness, pkg: string): string {
  const dir = join(h.runDir, "contracts", pkg);
  const files = readdirSync(dir).filter((f) => f.endsWith(".json"));
  if (files.length !== 1) fail(`expected one artifact in ${dir}, found ${files.length}`);
  return join(dir, files[0]!);
}

const hex = (x: bigint | number) => fieldHex(BigInt(x));

/** The compiled circuits of a contract manifest, by circuit id, as
 * REGISTER takes them (pss-client strips each). */
function compiledCircuits(m: ContractManifest, circuits: Record<string, CircuitFiles>): Record<string, unknown> {
  const read = (path: string) => JSON.parse(readFileSync(path, "utf8")) as unknown;
  return Object.fromEntries(m.packages.map((p) => [p.circuit, read(circuits[p.name]!.circuit)]));
}

/** A deployment's contract manifest (pss-client buildContractManifest):
 * the descriptor's packages with the example's circuit manifests, the vk
 * hashes as prepared, the slots from the artifact, the first contracts'
 * addresses in the reads the descriptor names them for, and the spec's
 * stale period if it gives one. */
async function contractManifest(
  h: Harness,
  name: string,
  spec: DeploymentSpec,
  artifact: ContractArtifact,
  contracts: Record<string, FirstDeployment>,
  descriptor: Descriptor = readDescriptor(h, spec),
): Promise<ContractManifest> {
  const files = example(h, spec.example);
  const manifests: Record<string, unknown> = {};
  const vkHashes: Record<string, string> = {};
  for (const p of descriptor.packages) {
    manifests[p.name] = JSON.parse(readFileSync(join(files.dir, "manifests", `${p.name}.json`), "utf8"));
    vkHashes[p.circuit] = (compiledCircuit(files, p.circuit) ?? fail(`${name}: package ${p.name}: example ${spec.example} has no circuit ${p.circuit}`)).vkHash;
  }
  try {
    return await buildContractManifest({
      descriptor,
      manifests,
      vkHashes,
      artifact,
      contracts: Object.fromEntries(Object.entries(contracts).map(([k, c]) => [k, c.address])),
      ...(spec.staleBlocks !== undefined && { staleBlocks: spec.staleBlocks }),
    });
  } catch (e) {
    fail(`${name}: the contract manifest: ${(e as Error).message}`);
  }
}

/** The packages of a contract manifest (the listed ones, then the aliases),
 * each with its circuit manifest written from it into
 * <run>/manifests/tip-<name>/, beside the contract manifest itself
 * (contract-manifest.json, whose path is the second value). */
function deploymentCircuits(h: Harness, name: string, spec: DeploymentSpec, m: ContractManifest, dirName = `tip-${name}`): [Record<string, CircuitFiles>, string] {
  const files = example(h, spec.example);
  const dir = join(h.runDir, "manifests", dirName);
  mkdirSync(dir, { recursive: true });
  const manifestPath = join(dir, "contract-manifest.json");
  writeFileSync(manifestPath, JSON.stringify(m, null, 2) + "\n");
  const out: Record<string, CircuitFiles> = {};
  for (const pkg of [...listedPackages(m), ...m.packages.filter((p) => p.alias_of !== undefined)]) {
    const compiled = compiledCircuit(files, pkg.circuit) ?? fail(`${name}: package ${pkg.name}: example ${spec.example} has no circuit ${pkg.circuit}`);
    const path = join(dir, `${pkg.name}.json`);
    writeFileSync(path, JSON.stringify(pkg.manifest, null, 2) + "\n");
    out[pkg.name] = { circuit: compiled.circuit, manifest: path, vk: compiled.vk, vkHash: compiled.vkHash, aliasOf: pkg.alias_of };
  }
  return [out, manifestPath];
}

/** The slots a deployment's contract manifest states. */
function slots(m: ContractManifest): TipDeployment["slots"] {
  const queue = m.queue ?? fail(`${m.name}: the contract manifest has no queue (no queued package)`);
  return {
    queue: queue.slot,
    staleBlocks: queue.stale_blocks_slot,
    configured: m.storage!.configured,
    stateKeys: { ...m.state_keys },
    ...(m.storage!.shared_onchain !== undefined && { sharedOnchain: m.storage!.shared_onchain }),
    ...(m.init !== undefined && { initInputs: m.init.input_slots }),
  };
}

/** A pss-client configuration (without `contractAddress`) of `names` among
 * the deployment's packages, written to <run>/pss-client/<file>. */
function writeClientConfig(h: Harness, d: Pick<TipDeployment, "example" | "circuits">, names: string[], file: string, overrides: Record<string, unknown> = {}): string {
  const base = JSON.parse(readFileSync(example(h, d.example).clientConfig, "utf8")) as Record<string, unknown>;
  const read = (path: string) => JSON.parse(readFileSync(path, "utf8")) as unknown;
  const config = {
    ...base,
    ...overrides,
    vkHashes: Object.fromEntries(names.map((n) => [n, d.circuits[n]!.vkHash])),
    circuits: Object.fromEntries(names.map((n) => {
      const { circuit, manifest, aliasOf } = d.circuits[n]!;
      return [n, { circuit: read(circuit), manifest: read(manifest), aliasOf }];
    })),
  };
  const path = join(h.runDir, "pss-client", file);
  writeFileSync(path, JSON.stringify(config) + "\n");
  return path;
}

const sigKeys = (h: Harness) => h.nodeKeys.map((k) => k.sig) as Triple<{ x: string; y: string }>;

/** One [[tip.namespaces]] entry (sidecar_tip::TipNamespace): the
 * deployment's address, which the operator lists; everything else is its
 * registered contract manifest's. */
function namespaceToml(d: TipDeployment): string {
  return [`# ${d.example}: ${d.contract} at ${d.address}`, "[[tip.namespaces]]", `contract = "${d.address}"`].join("\n") + "\n";
}

async function plan(h: Harness, names: string[]): Promise<void> {
  if (names.length === 0) fail("no [tip] section: E2E_TIP_DEPLOYMENTS names no deployment, so the nodes and the orchestrator would start without [tip] namespaces");
  const deployments: Record<string, TipDeployment> = {};
  const toml: string[] = [
    "# The [[tip.namespaces]] entries of this run (written by e2e/harness/tip.ts plan),",
    "# copied unchanged into the three node configs and the orchestrator config.",
  ];
  // Every contract package of every deployment builds side by side here, each
  // once; the builds below reuse them.
  await timed(logger, "contract builds of every deployment, side by side", async () =>
    Promise.all(
      names.flatMap((name) => {
        const spec = readSpec(h, name);
        return [
          ...Object.values(spec.contracts ?? {}).map((c) =>
            buildContract(h, { dir: join(h.repoRoot, "examples", c.example ?? spec.example) }, `tip-${name}`, c.package),
          ),
          buildContract(h, example(h, spec.example), `tip-${name}`, contractPackage(readDescriptor(h, spec))),
        ];
      }),
    ),
  );
  for (const name of names) {
    const spec = readSpec(h, name);
    const files = example(h, spec.example);
    const contract = contractPackage(readDescriptor(h, spec));
    const contracts = await planContracts(h, name, spec);
    const artifact = await timed(logger, `${name}: contract build (${contract})`, async () => buildContract(h, files, `tip-${name}`, contract));
    const m = await contractManifest(h, name, spec, artifact, contracts);
    const [circuits, manifestPath] = deploymentCircuits(h, name, spec, m);
    const capacity = m.contract?.package_capacity ?? fail(`${name}: the contract manifest states no package capacity`);
    const listed = listedPackages(m).map((p) => p.name);
    const pins = await tipPins(m, sigKeys(h));
    const salt = Fr.random();
    const operator = await operatorAddress();
    const instance = await getContractInstanceFromInstantiationParams(artifact, {
      constructorArtifact: "constructor",
      constructorArgs: constructorArgs(artifact, configOf(spec, contracts), pins, operator),
      salt,
      deployer: AztecAddress.ZERO,
    });
    let upgrade: TipDeployment["upgrade"];
    if (spec.upgrade !== undefined) {
      if (m.upgrades === "fixed") fail(`${name}: upgrade ${spec.upgrade}: contract ${contract} has fixed circuits (no upgrade_circuits)`);
      const next = await contractManifest(h, name, spec, artifact, contracts, readDescriptor(h, { ...spec, descriptor: spec.upgrade }));
      const [nextCircuits, nextPath] = deploymentCircuits(h, name, spec, next, `tip-${name}-upgrade`);
      upgrade = { manifest: nextPath, circuits: nextCircuits };
      logger.info(`${name}: the upgraded contract manifest (${spec.upgrade}) written to ${nextPath}`);
    }
    let classUpgrade: TipDeployment["classUpgrade"];
    if (spec.classUpgrade !== undefined) {
      if (m.upgrades !== "contract") fail(`${name}: classUpgrade: contract ${contract} has upgrades \`${m.upgrades}\` (no upgrade_contract)`);
      const second = await timed(logger, `${name}: contract build of the second class (${contract}@class)`, async () =>
        buildStagedContract(h, files, `tip-${name}`, contract, "class", spec.classUpgrade!),
      );
      const next = await contractManifest(h, name, spec, second, contracts);
      if (next.contract?.class_id === m.contract?.class_id) fail(`${name}: classUpgrade: the edit leaves the class id ${m.contract?.class_id} unchanged`);
      const [nextCircuits, nextPath] = deploymentCircuits(h, name, spec, next, `tip-${name}-class`);
      classUpgrade = { artifact: artifactPath(h, `${contract}@class`), manifest: nextPath, circuits: nextCircuits, classId: next.contract!.class_id };
      logger.info(`${name}: the second class ${next.contract!.class_id} and its contract manifest written to ${nextPath}`);
    }
    const address = fieldHex(instance.address.toBigInt());
    try {
      refuseOwnAddress(m, address);
    } catch (e) {
      fail(`${name}: ${(e as Error).message}`);
    }
    const d: TipDeployment = {
      example: spec.example,
      contract,
      artifact: artifactPath(h, contract),
      salt: salt.toString(),
      address,
      manifest: manifestPath,
      packages: listed,
      ...(spec.contracts && { contracts }),
      circuits,
      // under upgradable circuits the client's receipt requests name the
      // version its vk hashes are from (pss-client manifestHash)
      clientConfig: writeClientConfig(h, { example: spec.example, circuits }, Object.keys(circuits), `tip-${name}.json`, {
        staleBlocks: m.queue!.stale_blocks,
        ...(m.upgrades !== "fixed" && { manifestHash: fieldHex((await contractManifestHash(m)).toBigInt()) }),
      }),
      staleBlocks: pins.stale_blocks.enabled ? pins.stale_blocks.blocks : null,
      slots: slots(m),
      requestKeys: {},
      ...(takesUpgradeAuthority(artifact) && { upgradeAuthority: fieldHex(operator.toBigInt()) }),
      ...(upgrade && { upgrade }),
      ...(classUpgrade && { classUpgrade }),
      ...(spec.fee !== undefined && { fee: spec.fee }),
      ...(spec.credit && { credit: spec.credit }),
    };
    for (const p of m.packages) {
      if (p.state_keys === undefined) continue;
      d.requestKeys[p.name] = { reads: p.state_keys.reads.map((f) => m.state_keys![f]!), writes: p.state_keys.writes.map((f) => m.state_keys![f]!) };
    }
    deployments[name] = d;
    toml.push("", namespaceToml(d));
    logger.info(
      `${name}: ${contract} will be at ${d.address} (queue ${d.slots.queue}, stale_blocks ${d.slots.staleBlocks}${d.slots.sharedOnchain === undefined ? "" : `, shared_onchain ${d.slots.sharedOnchain}`}, ${listed.length} of ${capacity} packages)`,
    );
  }
  writeFileSync(join(h.runDir, "config", "tip.toml"), toml.join("\n"));
  h.tip = { ...h.tip, deployments };
  writeHarness(h);
}

function writeHarness(h: Harness): void {
  writeFileSync(process.env.E2E_HARNESS!, JSON.stringify(h, null, 2) + "\n");
}

async function deploy(h: Harness): Promise<void> {
  const tip = h.tip ?? fail("harness.json has no tip section: run tip.ts plan first");
  if (!tip.wfj) fail("no fee setup: harness.json has no tip.wfj (harness/fees.ts did not run or failed)");
  const relayerAccounts = tip.relayerAccounts ?? fail("no fee setup: harness.json names no relayer accounts (harness/fees.ts)");
  const { node, checks } = await connectNode(h, logger);
  const wallet = await EmbeddedWallet.create(node, { ephemeral: true, pxe: { ...getPXEConfig(), proverEnabled: h.expectRealProofs } });
  try {
    const [operator] = await registerInitialLocalNetworkAccountsInWallet(wallet);
    if (!operator) fail("the local network has no initial account");
    await registerWfj(wallet, node);
    for (const [name, d] of Object.entries(tip.deployments)) {
      const spec = readSpec(h, name);
      const fee = tipFeeSetting(spec.fee);
      await deployFirst(h, node, wallet, operator, name, spec, d);
      const config = configOf(spec, d.contracts ?? {});
      const artifact = loadContractArtifact(JSON.parse(readFileSync(d.artifact, "utf8")));
      const m = JSON.parse(readFileSync(d.manifest, "utf8")) as ContractManifest;
      const owner = OwnerKey.generate();
      const ownerFile = join(h.runDir, "keys", `tip-${name}-owner.key`);
      await owner.save(ownerFile);
      const salt = Fr.fromString(d.salt);
      let contract: Contract | undefined;
      const registry = pssClient(h, spec.example, d.address);
      const result = await timed(logger, `${name}: deployTip (REGISTER the contract manifest of ${m.packages.length} packages, deploy, configure)`, () =>
        deployTip({
          registry,
          owner,
          manifest: m,
          circuits: compiledCircuits(m, d.circuits),
          sigKeys: sigKeys(h),
          salt,
          deployer: {
            address: async (s, pins) => {
              const method = Contract.deploy(wallet, artifact, constructorArgs(artifact, config, pins, operator), "constructor", { salt: s, universalDeploy: true });
              const at = fieldHex((await method.getInstance()).address.toBigInt());
              if (at !== d.address) fail(`${name}: the deployment would be at ${at}, but the nodes and the orchestrator were configured for ${d.address}`);
              return at;
            },
            deploy: async (s, pins) => {
              const method = Contract.deploy(wallet, artifact, constructorArgs(artifact, config, pins, operator), "constructor", { salt: s, universalDeploy: true });
              const { contract: deployed, receipt } = await timed(logger, `${name}: tx deploy ${artifact.name}`, async () => method.send({ ...(await feeOptions(fee, "deploy")), from: operator }));
              d.deployTx = await declared(h, node, receipt.txHash);
              contract = Contract.at(deployed.address, artifact, wallet);
            },
            configure: async (args) => {
              const { receipt } = await timed(logger, `${name}: tx configure`, async () => contract!.methods.configure!(args.npk_app_hash, args.answer).send({ ...(await feeOptions(fee, "configure")), from: operator }));
              d.configureTx = await declared(h, node, receipt.txHash);
            },
          },
        }),
      );
      if (result.answer.seq !== 0) fail(`${name}: the contract manifest was registered at seq ${result.answer.seq}, not 0`);
      // The slots the contract manifest states, which the nodes and the
      // orchestrator read, read back.
      const address = fieldAddress(d.address);
      const at = async (slot: string) => (await node.getPublicStorageAt("latest", address, Fr.fromString(slot))).toBigInt();
      const stale = [await at(d.slots.staleBlocks), await at(hex(BigInt(d.slots.staleBlocks) + 1n))];
      const wantStale = d.staleBlocks === null ? [0n, 0n] : [1n, BigInt(d.staleBlocks)];
      if (stale[0] !== wantStale[0] || stale[1] !== wantStale[1]) {
        fail(`${name}: queue.stale_blocks_slot ${d.slots.staleBlocks} holds [${stale.join(", ")}], the constructor wrote [${wantStale.join(", ")}]`);
      }
      if ((await at(d.slots.configured)) !== 1n) fail(`${name}: storage.configured ${d.slots.configured} does not hold true after configure`);
      let init: RelayerInit | undefined;
      if (spec.init && m.init) {
        const inputs: string[] = [];
        for (const slot of d.slots.initInputs ?? []) inputs.push(hex(await at(slot)));
        init = { circuit: m.init.package, method: spec.init.method, inputs };
      }
      await fund(h, node, wallet, operator, name, spec, d);
      d.owner = ownerFile;
      d.npkAppHash = result.configure.npk_app_hash.toString();
      const relayerAccount = relayerAccounts[name] ?? fail(`no fee setup: harness.json names no relayer account of ${name} (harness/fees.ts)`);
      d.relayer = relayerConfig(h, name, d, relayerAccount, init, spec.methods);
      logger.info(`${name}: deployed and configured at ${d.address}; npk_app_hash ${d.npkAppHash}; the contract manifest's slots read back`);
    }
    checks?.finish({ requireNegative: false });
  } finally {
    await wallet.stop();
  }
  writeHarness(h);
}

/** Records the gas a mined transaction declared (harness.json
 * tip.declaredGas) while the node still holds it; returns its hash. */
async function declared(h: Harness, node: AztecNode, txHash: TxHash): Promise<string> {
  const tx = (await node.getTxByHash(txHash)) ?? fail(`the node does not hold transaction ${txHash}, just mined`);
  h.tip!.declaredGas = { ...h.tip!.declaredGas, [txHash.toString()]: declaredGas(tx) };
  return txHash.toString();
}

/** Deploy a deployment's first contracts at their planned addresses, from
 * the operator, paid through wFJ. */
async function deployFirst(h: Harness, node: AztecNode, wallet: EmbeddedWallet, operator: AztecAddress, name: string, spec: DeploymentSpec, d: TipDeployment): Promise<void> {
  if (!operator.equals(await operatorAddress())) fail(`${name}: the deploying account ${operator} is not the local network's first account, which \`$operator\` was planned as`);
  for (const [k, c] of Object.entries(spec.contracts ?? {})) {
    const planned = d.contracts?.[k] ?? fail(`${name}: contract ${k} was not planned`);
    const artifact = loadContractArtifact(JSON.parse(readFileSync(planned.artifact, "utf8")));
    const args = contractArgs(c, operator);
    const salt = Fr.fromString(planned.salt);
    const method = args
      ? Contract.deploy(wallet, artifact, args, "constructor", { salt, universalDeploy: true })
      : Contract.deploy(wallet, artifact, [], undefined, { salt, universalDeploy: true });
    const at = fieldHex((await method.getInstance()).address.toBigInt());
    if (at !== planned.address) fail(`${name}: ${k} would be at ${at}, but the manifests and the Config were written for ${planned.address}`);
    const { receipt } = await timed(logger, `${name}: tx deploy ${k} (${c.package}${args ? "" : ", no initializer"})`, async () =>
      method.send({ ...(await feeOptions(tipFeeSetting(spec.fee), "deploy")), from: operator, ...(args ? {} : { skipInitialization: true }) }),
    );
    planned.deployTx = await declared(h, node, receipt.txHash);
    logger.info(`${name}: ${k} deployed at ${at}`);
  }
}

/** Mint the spec's `fund` of each token (DeploymentSpec.fund) from the
 * operator, one transaction per token paid through wFJ: `accounts` into the
 * private balance of every local-network initial account, `app` into the
 * deployment contract's public balance, which is read back. */
async function fund(h: Harness, node: AztecNode, wallet: EmbeddedWallet, operator: AztecAddress, name: string, spec: DeploymentSpec, d: TipDeployment): Promise<void> {
  const accounts = (await getInitialTestAccountsData()).map((a) => a.address);
  const app = fieldAddress(d.address);
  for (const [k, f] of Object.entries(spec.fund ?? {})) {
    const planned = d.contracts?.[k] ?? fail(`${name}: fund.${k}: contract ${k} was not planned`);
    const token = Contract.at(fieldAddress(planned.address), loadContractArtifact(JSON.parse(readFileSync(planned.artifact, "utf8"))), wallet);
    const m = token.methods as unknown as Record<string, (...a: unknown[]) => ContractFunctionInteraction>;
    const calls = [...(f.accounts === undefined ? [] : accounts.map((a) => m.mint_to_private!(a, BigInt(f.accounts!)))), ...(f.app === undefined ? [] : [m.mint_to_public!(app, BigInt(f.app))])];
    const what = [f.accounts === undefined ? "" : `${f.accounts} to each of ${accounts.length} accounts' private balances`, f.app === undefined ? "" : `${f.app} to ${d.contract}'s public balance`].filter(Boolean).join(", ");
    const { receipt } = await timed(logger, `${name}: tx fund ${k} (${what})`, async () =>
      new BatchCall(wallet, calls).send({ ...(await feeOptions(tipFeeSetting(spec.fee), "deploy")), from: operator }),
    );
    planned.fundTx = await declared(h, node, receipt.txHash);
    if (f.app !== undefined) {
      const { result } = await m.balance_of_public!(app).simulate({ from: operator });
      if (BigInt(result as bigint) !== BigInt(f.app)) fail(`${name}: ${k}'s public balance of ${d.contract} is ${result} after the mint, not ${f.app}`);
    }
    logger.info(`${name}: ${k} minted ${what} in tx ${receipt.txHash}`);
  }
}

/** The suffix of an upgraded package's name in the relayer's configuration. */
const UPGRADED = "@upgrade";

/** The relayer configuration's init round (pss-relayer main.ts `init`). */
interface RelayerInit {
  circuit: string;
  method: string;
  inputs: string[];
}

/** The relayer's configuration file of one deployment (pss-relayer main.ts):
 * its PXE registers the app contract alone, since a result transaction calls
 * no other contract privately. */
function relayerConfig(h: Harness, name: string, d: TipDeployment, accountFile: string, init: RelayerInit | undefined, methods: Record<string, ResultFunction> | undefined): string {
  const port = Number(process.env.RELAYER_PORT ?? 3301) + Object.keys(h.tip!.deployments).indexOf(name);
  const path = join(h.runDir, "config", `relayer-${name}.json`);
  const account = JSON.parse(readFileSync(accountFile, "utf8")) as { secretKey: string; signingKey: string; salt: string };
  // An upgradable deployment's relayer knows the upgraded manifest's
  // replaced circuits from the start, each listed package whose vk hash the
  // upgrade changes under `<package>@upgrade`: it finds a result's circuit
  // by the answer's vk hash, so it lands results under either version.
  const circuits: Record<string, CircuitFiles> = { ...d.circuits };
  const names = Object.keys(circuits);
  for (const pkg of d.packages) {
    const next = d.upgrade?.circuits[pkg];
    if (next === undefined || next.vkHash === d.circuits[pkg]!.vkHash) continue;
    circuits[`${pkg}${UPGRADED}`] = next;
    names.push(`${pkg}${UPGRADED}`);
  }
  const config = {
    aztecNodeUrl: h.aztecNodeUrl,
    client: writeClientConfig(h, { example: d.example, circuits }, names, `tip-${name}-relayer.json`, { staleBlocks: d.staleBlocks }),
    contractAddress: d.address,
    artifact: d.artifact,
    // under a class upgrade the relayer registers the instance again with
    // the second class's artifact once it runs it
    ...(d.classUpgrade && { upgradeArtifacts: [d.classUpgrade.artifact] }),
    vk: Object.fromEntries(names.map((n) => [n, circuits[n]!.vk])),
    ...(init && { init }),
    ...(methods && { methods }),
    account: { secretKey: account.secretKey, signingKey: account.signingKey, salt: account.salt },
    // the app's fee setting: wFJ, with its fixed gas of a result (the init
    // round's too) and a skip
    fee: tipFeeSetting(d.fee),
    proverEnabled: h.expectRealProofs,
    pollIntervalMs: 2000,
    statusPort: port,
  };
  writeFileSync(path, JSON.stringify(config, null, 2) + "\n", { mode: 0o600 });
  chmodSync(path, 0o600);
  return path;
}

/** The relayer's GET /status (pss-relayer main.ts), or why there is none. */
/** The relayer's status, or why GET /status failed (it may still be starting). */
const relayerStatus = (d: TipDeployment): Promise<RelayerStatus | string> =>
  relayerStatusOf(d.relayer!).catch((e: unknown) => `GET /status of ${d.relayer} failed: ${(e as Error).message}`);

/** Wait until the relayer of each deployment with an init round has landed
 * it: every slot the init creates holds a commitment, and the relayer
 * reports the transaction as its own. */
async function init(h: Harness): Promise<void> {
  const tip = h.tip ?? fail("harness.json has no tip section: run tip.ts plan and deploy first");
  const limitS = Number(process.env.INIT_TIMEOUT ?? 1800);
  const { node } = await connectNode(h, logger);
  for (const [name, d] of Object.entries(tip.deployments)) {
    const spec = readSpec(h, name);
    if (!spec.init) continue;
    if (!d.relayer) fail(`${name}: no relayer configuration (tip.ts deploy did not finish)`);
    const m = JSON.parse(readFileSync(d.manifest, "utf8")) as ContractManifest;
    const initPackage = m.packages.find((p) => p.name === m.init?.package);
    const fields = initPackage?.state_keys?.writes ?? fail(`${name}: the contract manifest's init package names no state key it creates`);
    const address = fieldAddress(d.address);
    const slots = fields.map((f) => ({ field: f, slot: d.slots.stateKeys[f]! }));
    const read = async () => Promise.all(slots.map(async (s) => (await node.getPublicStorageAt("latest", address, Fr.fromString(s.slot))).toBigInt()));
    // the slots are written once the transaction is mined, the relayer's
    // status once its wait for the receipt returns: wait for both
    const { values, status } = await timed(logger, `${name}: the init round landed by the relayer (${spec.init.method})`, async () => {
      const landed = await poll(
        async () => ({ values: await read(), status: await relayerStatus(d) }),
        ({ values: v, status }) => {
          const state = typeof status === "string" ? undefined : status.init?.state;
          return v.every((x) => x !== 0n) && state !== undefined && state !== "pending";
        },
        limitS * 1000,
      );
      if (!landed.done) {
        const { values: v, status } = landed.value;
        const empty = slots.filter((_, k) => v[k] === 0n).map((s) => `${s.field} (slot ${s.slot})`);
        fail(
          `${name}: the init round did not land within ${limitS} s: ${empty.length ? `${empty.join(", ")} still 0` : "the slots are written"}; ` +
            `relayer status ${JSON.stringify(status)}`,
        );
      }
      return landed.value;
    });
    const st = typeof status === "string" ? undefined : status.init;
    if (st?.state !== "landed" || !st.tx) fail(`${name}: the init slots are written, but the relayer does not report landing the init round: ${JSON.stringify(status)}`);
    d.initTx = await declared(h, node, TxHash.fromString(st.tx));
    logger.info(`${name}: init round landed by the relayer in tx ${st.tx}: ${slots.map((s, k) => `${s.field} = ${hex(values[k]!)}`).join(", ")}`);
  }
  writeHarness(h);
}

async function main() {
  const h = loadHarness();
  const [command, ...rest] = process.argv.slice(2);
  if (command === "plan") await plan(h, rest);
  else if (command === "deploy") await deploy(h);
  else if (command === "init") await init(h);
  else fail("usage: tip.ts plan <deployment> ... | tip.ts deploy | tip.ts init");
}

main().catch((err) => {
  logger.error(`tip: FAIL: ${err?.stack ?? err}`);
  process.exit(1);
});
