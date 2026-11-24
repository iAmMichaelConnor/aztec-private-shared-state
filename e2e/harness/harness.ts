// What run.sh hands the drivers: the run's harness.json (service URLs, the
// node keys setup printed, the circuit files of each example with their vk
// hashes, the network log) and helpers that turn it into a ready pss-client,
// a node client with the node-side verification checks, and timed steps.
//
// run.sh starts every driver as
//   NODE_EXTRA_CA_CERTS=<run>/keys/https-ca.pem E2E_HARNESS=<run>/harness.json \
//     node --conditions=source --import ../ts/hooks/register.mjs <driver>.ts
// so `loadHarness()` needs no argument.
import { createLogger, type Logger } from "@aztec-labs/aztec.js/log";
import { createAztecNodeClient, waitForNode, type AztecNode } from "@aztec-labs/aztec.js/node";
import { PssClient, type PssClientConfig, type PssClientOptions } from "@aztec-pss/pss-client";

import type { Tx } from "@aztec-labs/stdlib/tx";

import { readFileSync } from "node:fs";

import { enforceNodeVerification, requireNodeVerifier, type NodeVerification } from "./node-verification.ts";

/** A point as harness.json writes it: 0x + 64 hex digits per coordinate. */
export interface PointHex {
  x: string;
  y: string;
}

/** One registered-to-be circuit of an example, as files in the run directory. */
export interface CircuitFiles {
  /** The nargo output JSON (compiled by scripts/prepare-data.sh with Noir 1.0.0). */
  circuit: string;
  /** The example's manifest of it (a copy). */
  manifest: string;
  /** The target package of an alias in a deployment. */
  aliasOf?: string;
  /** The vk.json bb 6.0.0 wrote for it (`bb write_vk --output_format json`). */
  vk: string;
  /** Poseidon2 of the vk fields: what REGISTER answers and the contract pins. */
  vkHash: string;
}

/** One example's files. */
export interface ExampleFiles {
  /** The example directory in the repository (`examples/amm`). */
  dir: string;
  /** The ready pss-client configuration without `contractAddress`. */
  clientConfig: string;
  circuits: Record<string, CircuitFiles>;
  /** The example's compiled circuits without a manifest of their own (no
   * manifests/<circuit>.json): a replacement circuit, which an upgraded
   * contract manifest registers under another package's name and manifest
   * (amm-tip's amm_swap_tip_next, under amm_swap_tip). Not in the client
   * configuration. */
  replacements?: Record<string, Omit<CircuitFiles, "manifest">>;
}

/** An example's compiled circuit by id: one with its own manifest, or a
 * replacement (ExampleFiles.replacements); undefined for neither. */
export function compiledCircuit(files: ExampleFiles, id: string): Omit<CircuitFiles, "manifest"> | undefined {
  return files.circuits[id] ?? files.replacements?.[id];
}

/** harness.json. */
export interface Harness {
  /** E2E_LOG_DIR: every key, artifact copy, config and log of the run. */
  runDir: string;
  /** The repository root. */
  repoRoot: string;
  aztecNodeUrl: string;
  /** The local network's log, where the node's verifier lines appear. */
  networkLog: string;
  /** EXPECT_REAL_PROOFS=1: the PXE proves client-side and the node verifies. */
  expectRealProofs: boolean;
  /** https://127.0.0.1:<port> of the orchestrator's public API. */
  orchestratorUrl: string;
  /** The development CA the orchestrator's certificate chains to. */
  caCert: string;
  /** The pinned bb 6.0.0 and the contracts' nargo (scripts/toolchain.sh). */
  bbBin: string;
  contractNargoBin: string;
  /** The three nodes' keys as `sidecar-node setup` printed them, node 0 first. */
  nodeKeys: [{ enc: PointHex; sig: PointHex }, { enc: PointHex; sig: PointHex }, { enc: PointHex; sig: PointHex }];
  /** Keyed by example name (the directory's base name: `amm`, `monty-hall`). */
  examples: Record<string, ExampleFiles>;
  /** A tip run's deployments, fee setup and relayers (E2E_TIP=1); absent otherwise. */
  tip?: TipHarness;
}

/** One tip deployment (e2e/tip/<name>.json and its descriptor), as tip.ts planned and deployed it. */
export interface TipDeployment {
  /** The example's name in `examples`. */
  example: string;
  /** The contract package under `<example>/contract/` and its built artifact. */
  contract: string;
  artifact: string;
  /** The deployment's salt (secret until the deployment lands) and the
   * address of the universal deployment: the namespace. */
  salt: string;
  address: string;
  /** The contract manifest tip.ts plan generated (contract-manifest.json in
   * the run directory). */
  manifest: string;
  /** The listed packages in REGISTER order. */
  packages: string[];
  /** The contracts deployed before REGISTER and this one (the spec's
   * `contracts`), by name; a driver names one `<tip name>.<name>`. */
  contracts?: Record<string, FirstDeployment>;
  /** Every package the deployment REGISTERs, the listed ones and the
   * aliases after them, by name: the compiled circuit, the circuit manifest
   * as the contract manifest holds it (a copy in the run directory), its vk
   * and vk hash. */
  circuits: Record<string, CircuitFiles>;
  /** The pss-client configuration (without `contractAddress`) of every
   * package in `circuits`, which a driver's client of this namespace takes. */
  clientConfig: string;
  /** The manifests' stale period, as the constructor pins it (null: never skipped). */
  staleBlocks: number | null;
  /** The storage slots its contract manifest states, which the harness
   * reads back after the deployment. */
  slots: {
    queue: string;
    staleBlocks: string;
    configured: string;
    initInputs?: string[];
    /** Each request key's storage field and its slot. */
    stateKeys: Record<string, string>;
    /** The slot of the app's `SharedOnchain` (its `shared_onchain` storage
     * field), when the deployment registers a secret-shared on-chain intake
     * package: the manifest's `storage.shared_onchain`. */
    sharedOnchain?: string;
  };
  /** Per queued package, the slots of its request keys, as its contract
   * manifest gives them. */
  requestKeys: Record<string, { reads: string[]; writes: string[] }>;
  /** Set by tip.ts deploy: the namespace owner's key file, the configured
   * npk_app_hash, the relayer's configuration file, and the deployment and
   * configure transactions (the driver's gas record, engine/gas.ts). */
  owner?: string;
  npkAppHash?: string;
  relayer?: string;
  deployTx?: string;
  configureTx?: string;
  /** Set by tip.ts init: the relayer's init transaction. */
  initTx?: string;
  /** The upgrade authority the constructor pinned (the local network's
   * first account), for a contract whose constructor takes one
   * (`upgrade_authority`: upgradable circuits). */
  upgradeAuthority?: string;
  /** The upgraded contract manifest of the deployment (the spec's
   * `upgrade`), generated by tip.ts plan from the same contract and its
   * own descriptor and written beside the deployed one: its path and every
   * package it registers, as `circuits`. A scenario registers it at the
   * next seq and has the authority schedule its pins (the tipUpgrade
   * step); the relayer's configuration knows its replaced circuits from
   * the start (`<package>@upgrade`). */
  upgrade?: { manifest: string; circuits: Record<string, CircuitFiles> };
  /** The contract's second class (the spec's `classUpgrade`), built by
   * tip.ts plan from the same sources with one edit: its artifact, the
   * contract manifest generated from it with the deployment's descriptor
   * (the same circuits, the new class id) and every package it registers,
   * and the class id. A scenario publishes the class, registers the
   * manifest at the next seq and has the authority call `upgrade_contract`
   * (the tipUpgrade step); the relayer follows the instance to it. */
  classUpgrade?: { artifact: string; manifest: string; circuits: Record<string, CircuitFiles>; classId: string };
  /** The spec's `fee`: the name of the app's fee setting
   * (harness/fee-settings.ts), absent for the default one. */
  fee?: string;
  /** The spec's `credit`: how the app keeps credits, absent for an app
   * that keeps none. */
  credit?: CreditSpec;
}

/** How a tip deployment's app keeps credits (e2e/tip/<deployment>.json
 * `credit`): a private balance per asset that its requests draw on, and
 * that redeems and exits pay into, instead of token notes (lending's). */
export interface CreditSpec {
  /** The app's funding function: each asset's amount in the order `assets`
   * lists them, then a struct of each asset's authwit nonce by its token's
   * name (lending's `fund(collateral, borrowed, nonces)`). */
  fund: string;
  /** The app's utility that reads an account's credit, `(owner, asset)`
   * (lending's `credit_balance`). */
  balance: string;
  /** By token (a first contract of the deployment), the asset its credit
   * is read and funded under. */
  assets: Record<string, number>;
}

/** A contract a tip deployment deploys first, as tip.ts planned it. */
export interface FirstDeployment {
  /** The contract package and its built artifact. */
  package: string;
  artifact: string;
  /** The salt and the address of its universal deployment. */
  salt: string;
  address: string;
  /** Set by tip.ts deploy: its deployment transaction, and the one that
   * minted the spec's `fund` of it (a token's). */
  deployTx?: string;
  fundTx?: string;
}

/** harness.json's `tip`. */
export interface TipHarness {
  deployments: Record<string, TipDeployment>;
  /** wFJ, the PrivateFPC every tip transaction pays through (harness/fees.ts). */
  wfj?: { address: string; salt: string };
  /** Every funded payer by name: `account<i>` (the local network's initial
   * accounts) and `relayer-<deployment>`. */
  payers?: Record<string, string>;
  /** Per deployment, its relayer's own account keys (JSON: secretKey,
   * signingKey, salt, address); one account per relayer, as each runs its
   * own PXE over the account's private balance. */
  relayerAccounts?: Record<string, string>;
  /** The fee setup's first block and each payer's funding transaction hash
   * (harness/fees.ts), from which harness/fee-payers.ts checks every
   * transaction's fee payer. */
  fees?: { fromBlock: number; funding: Record<string, string>; wfjBalanceBefore?: string };
  /** The gas tip.ts deploy's transactions and the relayers' init
   * transactions declared, by transaction hash (the driver's gas record,
   * engine/gas.ts, reads them once the node no longer holds the transactions). */
  declaredGas?: Record<string, DeclaredGas>;
}

/** What a transaction declared about its gas, as sent: its gas limits, its
 * max fees per gas, the gas its private part used (the kernel's metering
 * with the transaction overhead) and whether it enqueued public calls. */
export interface DeclaredGas {
  limits: { daGas: number; l2Gas: number };
  maxFeesPerGas: { feePerDaGas: string; feePerL2Gas: string };
  privateGas: { daGas: number; l2Gas: number };
  publicCalls: boolean;
}

/** A transaction's DeclaredGas. */
export function declaredGas(tx: Tx): DeclaredGas {
  const { gasLimits, maxFeesPerGas } = tx.data.constants.txContext.gasSettings;
  return {
    limits: { daGas: gasLimits.daGas, l2Gas: gasLimits.l2Gas },
    maxFeesPerGas: { feePerDaGas: maxFeesPerGas.feePerDaGas.toString(), feePerL2Gas: maxFeesPerGas.feePerL2Gas.toString() },
    privateGas: { daGas: tx.data.gasUsed.daGas, l2Gas: tx.data.gasUsed.l2Gas },
    publicCalls: tx.data.forPublic !== undefined,
  };
}

/** The file run.sh writes the process id of a deployment's relayer to. */
export function relayerPidFile(harness: Harness, deployment: string): string {
  return `${harness.runDir}/run/relayer-${deployment}.pid`;
}

/** Reads harness.json (default: the E2E_HARNESS file run.sh sets). */
export function loadHarness(path = process.env.E2E_HARNESS): Harness {
  if (!path) throw new Error("E2E_HARNESS is not set; start this through e2e/run.sh");
  const harness = JSON.parse(readFileSync(path, "utf8")) as Harness;
  // fetch() trusts the development CA only through NODE_EXTRA_CA_CERTS,
  // which node reads once at start-up.
  if (process.env.NODE_EXTRA_CA_CERTS !== harness.caCert) {
    throw new Error(`NODE_EXTRA_CA_CERTS must be ${harness.caCert} (the development CA of this run) when the process starts`);
  }
  return harness;
}

/** The files of one example, or an error naming the examples prepared. */
export function example(harness: Harness, name: string): ExampleFiles {
  const files = harness.examples[name];
  if (!files) throw new Error(`example ${name} was not prepared; this run has ${Object.keys(harness.examples).join(", ")}`);
  return files;
}

/** The ready pss-client configuration of `exampleName` in the namespace
 * `contractAddress`: pinned node keys, the orchestrator URL, the vk hashes and
 * every circuit of the example with its manifest. `overrides` replaces any
 * field (timeouts, a verifyProof hook). */
export function pssClientConfig(
  harness: Harness,
  exampleName: string,
  contractAddress: { toString(): string } | string | bigint,
  overrides: Partial<PssClientConfig> = {},
): PssClientConfig {
  const base = JSON.parse(readFileSync(example(harness, exampleName).clientConfig, "utf8")) as Omit<PssClientConfig, "contractAddress">;
  return { ...base, contractAddress: typeof contractAddress === "bigint" ? contractAddress : contractAddress.toString(), ...overrides };
}

/** A PssClient from pssClientConfig(). */
export function pssClient(
  harness: Harness,
  exampleName: string,
  contractAddress: { toString(): string } | string | bigint,
  overrides: Partial<PssClientConfig> = {},
  options: PssClientOptions = {},
): PssClient {
  return new PssClient(pssClientConfig(harness, exampleName, contractAddress, overrides), options);
}

/** A circuit's nargo JSON and manifest JSON, parsed, as REGISTER takes them. */
export function circuitPackage(harness: Harness, exampleName: string, circuit: string): { circuit: unknown; manifest: unknown; vkHash: string } {
  const files = example(harness, exampleName).circuits[circuit];
  if (!files) throw new Error(`example ${exampleName} has no circuit ${circuit}`);
  return {
    circuit: JSON.parse(readFileSync(files.circuit, "utf8")),
    manifest: JSON.parse(readFileSync(files.manifest, "utf8")),
    vkHash: files.vkHash,
  };
}

/** A connected node client, and in a real-proof run the node-side checks
 * already armed on it: the verifier line is confirmed and every sendTx through
 * this client must be accepted by hash after its own verification line
 * (node-verification.ts). Create
 * the wallet with this `node`. `checks` is undefined when the run does not
 * expect real proofs. */
export async function connectNode(harness: Harness, logger: Logger): Promise<{ node: AztecNode; checks?: NodeVerification }> {
  const node = createAztecNodeClient(harness.aztecNodeUrl);
  await waitForNode(node, logger);
  if (!harness.expectRealProofs) {
    logger.warn("EXPECT_REAL_PROOFS is not 1: the node accepts any proof bytes, and nothing here checks it");
    return { node };
  }
  if ((await node.getNodeInfo()).realProofs !== true) {
    throw new Error("a real-proof run requires node transaction proof verification (getNodeInfo().realProofs)");
  }
  await requireNodeVerifier(harness.networkLog, logger);
  return { node, checks: enforceNodeVerification(node, harness.networkLog, logger) };
}

/** A logger under the harness's module prefix. */
export function harnessLogger(name: string): Logger {
  return createLogger(`pss-e2e:${name}`);
}

/** Runs one step and logs its wall-clock duration as `[timing] <label>: <s> s`. */
export async function timed<T>(logger: Logger, label: string, step: () => Promise<T>): Promise<T> {
  const start = performance.now();
  try {
    return await step();
  } finally {
    logger.info(`[timing] ${label}: ${((performance.now() - start) / 1000).toFixed(1)} s`);
  }
}
