// What setup.ts and record-logs.ts share: compiling a contract package with
// the pinned contract nargo and bb through `aztec compile`, a wallet on the
// local network with its first two funded accounts, PssPublicTest's
// constructor arguments (checked against its compiled constructor), and the
// value a view function returns.
import type { AztecAddress } from "@aztec-labs/aztec.js/addresses";
import { Contract } from "@aztec-labs/aztec.js/contracts";
import type { Fr } from "@aztec-labs/aztec.js/fields";
import { createAztecNodeClient, waitForNode, type AztecNode } from "@aztec-labs/aztec.js/node";
import { createLogger } from "@aztec-labs/aztec.js/log";
import { getPXEConfig } from "@aztec-labs/pxe/server";
import { loadContractArtifact, type ContractArtifact } from "@aztec-labs/stdlib/abi";
import { EmbeddedWallet } from "@aztec-labs/wallets/embedded";
import { registerInitialLocalNetworkAccountsInWallet } from "@aztec-labs/wallets/testing";

import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

export const repo = join(dirname(fileURLToPath(import.meta.url)), "../../../..");

// The circuit pins: both non-secret-shared intake functions hash VK_HASH, the pool
// round's, into the chain request id and assert only that it is not 0;
// HELD_VK_HASH is the node-held round's, which nothing here sends. No circuit
// is registered here, so any other value serves for either.
export const VK_HASH = 0x5eedn;
export const HELD_VK_HASH = 0x5eefn;
// The network pin; nothing here checks it.
const NPK_APP_HASH = 0x9an;
// Receipt keys; nothing here sends a receipt, so the Grumpkin generator
// stands in for each node's key.
const GENERATOR = { x: 1n, y: 17631683881184975370165255887551781615748388533673675138860n, is_infinite: false };
// The stale period the contract is deployed with; the reader does not use it.
const STALE_BLOCKS = 4;
const COMPILE_TIMEOUT_MS = 1_800_000;

const { AZTEC_NODE_URL, CONTRACT_NARGO_BIN, BB_BIN } = process.env;
if (!AZTEC_NODE_URL || !CONTRACT_NARGO_BIN || !BB_BIN) {
  throw new Error("set AZTEC_NODE_URL, CONTRACT_NARGO_BIN and BB_BIN");
}
export const nodeUrl = AZTEC_NODE_URL;

/** Compiles the contract package at `pkg` (relative to the repository) and loads `target/<file>`. */
export function compile(pkg: string, file: string): ContractArtifact {
  const dir = join(repo, pkg);
  const run = spawnSync(join(repo, "node_modules/.bin/aztec"), ["compile"], {
    cwd: dir,
    env: { ...process.env, NARGO: CONTRACT_NARGO_BIN, BB: BB_BIN },
    stdio: ["ignore", "pipe", "pipe"],
    timeout: COMPILE_TIMEOUT_MS,
  });
  if (run.status !== 0) {
    process.stderr.write(run.stdout ?? "");
    process.stderr.write(run.stderr ?? "");
    throw new Error(`aztec compile in ${pkg} exited with ${run.status ?? run.signal}`);
  }
  return loadContractArtifact(JSON.parse(readFileSync(join(dir, "target", file), "utf8")));
}

// The constructor testContractArgs mirrors: PssPublicTest's
// `constructor(config: TipConfig, vk_hash: Field, held_vk_hash: Field)`
// (noir/pss_public_contract_test/src/main.nr), with TipConfig
// `{ stale_blocks, node_sig_keys, npk_app_hash }`
// (noir/pss_public_contract/src/config.nr).
const CONSTRUCTOR = ["config", "vk_hash", "held_vk_hash"];

/** PssPublicTest's constructor arguments: the config, VK_HASH and
 * HELD_VK_HASH. */
export const testContractArgs = () => [
  {
    stale_blocks: { enabled: true, blocks: STALE_BLOCKS },
    node_sig_keys: [GENERATOR, GENERATOR, GENERATOR],
    npk_app_hash: NPK_APP_HASH,
  },
  VK_HASH,
  HELD_VK_HASH,
];

/** PssPublicTest (noir/pss_public_contract_test), compiled; an
 * Error when its constructor no longer takes what testContractArgs gives
 * (the parameters by name, the config's fields by name and order). */
export function compileTestContract(): ContractArtifact {
  const artifact = compile("noir/pss_public_contract_test", "pss_public_contract_test-PssPublicTest.json");
  const ctor = [...artifact.functions, ...(artifact.nonDispatchPublicFunctions ?? [])].find((f) => f.name === "constructor");
  const params = ctor?.parameters.map((p) => p.name) ?? [];
  const config = ctor?.parameters[0]?.type;
  const fields = config?.kind === "struct" ? config.fields.map((f) => f.name) : [];
  const want = Object.keys(testContractArgs()[0] as object);
  if (params.join() !== CONSTRUCTOR.join() || fields.join() !== want.join()) {
    throw new Error(`PssPublicTest's constructor takes (${params.join(", ")}), config {${fields.join(", ")}}; testContractArgs gives (${CONSTRUCTOR.join(", ")}), config {${want.join(", ")}}`);
  }
  return artifact;
}

export interface Session {
  node: AztecNode;
  wallet: EmbeddedWallet;
  // the local network's first two funded accounts
  deployer: Awaited<ReturnType<typeof registerInitialLocalNetworkAccountsInWallet>>[number];
  user: Awaited<ReturnType<typeof registerInitialLocalNetworkAccountsInWallet>>[number];
}

/** Runs `body` with a wallet on the network at AZTEC_NODE_URL, and stops the wallet after. */
export async function withSession<T>(logName: string, body: (s: Session) => Promise<T>): Promise<T> {
  const node = createAztecNodeClient(nodeUrl);
  await waitForNode(node, createLogger(logName));
  const wallet = await EmbeddedWallet.create(node, { ephemeral: true, pxe: { ...getPXEConfig(), proverEnabled: false } });
  try {
    const [deployer, user] = await registerInitialLocalNetworkAccountsInWallet(wallet);
    return await body({ node, wallet, deployer: deployer!, user: user! });
  } finally {
    await wallet.stop?.();
  }
}

/** Deploys `artifact` from `from`; a fixed `salt` gives the same address on every fresh network. */
export async function deploy(s: Session, artifact: ContractArtifact, args: unknown[], salt?: Fr): Promise<Contract> {
  const method = salt === undefined ? Contract.deploy(s.wallet, artifact, args) : Contract.deploy(s.wallet, artifact, args, undefined, { salt });
  const { contract } = await method.send({ from: s.deployer });
  return contract;
}

/** The value a view function returns, simulated from `from`. */
export async function view(call: { simulate(o: { from: AztecAddress }): Promise<unknown> }, from: AztecAddress): Promise<unknown> {
  const out = (await call.simulate({ from })) as { result?: unknown } | unknown;
  return out !== null && typeof out === "object" && "result" in out ? (out as { result: unknown }).result : out;
}
