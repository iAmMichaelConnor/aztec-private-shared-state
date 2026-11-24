// The harness's own check, run by run.sh after every service is up and
// before any driver: the machine answers through pss-client, and the local
// network verifies a client-proved transaction.
//
//   1. GET /v1/nodes through the orchestrator equals the keys setup printed
//      (pss-client's checkNodes against the pinned keys).
//   2. The first REGISTER (seq 0) in a fresh namespace, of the contract
//      manifest of one circuit (SMOKE_CIRCUIT=<example>/<circuit>, default
//      amm/pss_seed; run.sh sets the first deployment's first package in a
//      tip run, whose contract facts are placeholders: no contract is at the namespace and
//      no tip configuration lists it, so nothing reads them), answers the
//      manifest hash, npk_app_hash and seq 0, with every node signature
//      pss-client verified against the pinned sig keys and the circuit's vk
//      hash bb's.
//   3. One transaction on the local network: the deployment of a contract
//      without a constructor (in a tip run paid through wFJ, like every
//      transaction of the run). In a real-proof run the PXE proves it
//      client-side, the node must log "Chonk verification successful" for
//      it, and a copy with one Chonk proof field changed is sent first and
//      must be refused with "Invalid proof" (node-verification.ts).
import { Fr } from "@aztec-labs/aztec.js/fields";
import { NoConstructorContract } from "@aztec-labs/noir-test-contracts.js/NoConstructor";
import { getPXEConfig } from "@aztec-labs/pxe/server";
import { EmbeddedWallet } from "@aztec-labs/wallets/embedded";
import { registerInitialLocalNetworkAccountsInWallet } from "@aztec-labs/wallets/testing";
import { checkContractManifest, DEFAULT_FEE_SETTING, OwnerKey, feeOptions, fieldHex, registerWfj, type ContractManifest } from "@aztec-pss/pss-client";

import { circuitPackage, connectNode, harnessLogger, loadHarness, pssClient, timed } from "./harness.ts";

const logger = harnessLogger("smoke");
const harness = loadHarness();

/** The smoke's contract manifest of one circuit: on the sidecar path as it
 * is; a queued circuit with placeholder contract facts (every request key
 * the one state key `smoke`). */
function smokeManifest(name: string, circuit: Record<string, unknown>, vkHash: string): ContractManifest {
  const keys = circuit.state_keys as { reads: number; writes: number };
  const queued = circuit.intake !== undefined && circuit.intake !== "direct";
  const slot = (n: number) => fieldHex(n);
  const m: ContractManifest = {
    contract_manifest: 1,
    name: "smoke",
    node_keys: "fixed",
    upgrades: "fixed",
    ...(queued && {
      contract: { class_id: slot(1), package_capacity: 1 },
      queue: { slot: slot(2), stale_blocks: 50, stale_blocks_slot: slot(3) },
      storage: { configured: slot(4) },
      state_keys: { smoke: slot(5) },
    }),
    circuits: { [name]: { vk_hash: fieldHex(vkHash) } },
    packages: [
      {
        name,
        circuit: name,
        ...(queued && { state_keys: { reads: Array<string>(keys.reads).fill("smoke"), writes: Array<string>(keys.writes).fill("smoke") } }),
        manifest: circuit,
      },
    ],
  };
  checkContractManifest(m);
  return m;
}

async function main() {
  ////////////// the machine: pinned keys and a first REGISTER //////////////
  // The smoke's namespace is a fresh random field element per
  // run, not a contract address: the stores are new for every run, and the
  // smoke registers only to prove the machine answers. A driver uses its
  // contract's address (the namespace on Aztec).
  const namespace = Fr.random();
  const [exampleName, circuitName] = (process.env.SMOKE_CIRCUIT ?? "amm/pss_seed").split("/") as [string, string];
  const client = pssClient(harness, exampleName, namespace);
  await timed(logger, "GET /v1/nodes check", () => client.checkNodes());
  logger.info("GET /v1/nodes through the orchestrator matches the keys setup printed");

  const pkg = circuitPackage(harness, exampleName, circuitName);
  const owner = OwnerKey.generate();
  const manifest = smokeManifest(circuitName, pkg.manifest as Record<string, unknown>, pkg.vkHash);
  const answer = await timed(logger, `REGISTER ${circuitName} (seq 0)`, () => client.registerManifest({ manifest, circuits: { [circuitName]: pkg.circuit }, seq: 0 }, owner));
  if (answer.seq !== 0) throw new Error(`REGISTER answered seq ${answer.seq}, expected 0`);
  if (BigInt(answer.npk_app_hash) === 0n) throw new Error("REGISTER answered npk_app_hash 0");
  const info = await client.getNamespace(namespace);
  if (!info || info.seq !== 0 || info.npk_app_hash !== answer.npk_app_hash || info.manifest_hash !== answer.manifest_hash) {
    throw new Error(`GET /v1/namespaces disagrees with the REGISTER answer: ${JSON.stringify(info)}`);
  }
  logger.info(
    `REGISTER ${circuitName} in ${namespace}: contract manifest ${answer.manifest_hash}, vk_hash ${pkg.vkHash} (= bb's), npk_app_hash ${answer.npk_app_hash}, seq ${answer.seq}, every node signature verified`,
  );

  ////////////// the network: one client-proved transaction //////////////
  const { node, checks } = await connectNode(harness, logger);
  const wallet = await EmbeddedWallet.create(node, {
    ephemeral: true,
    pxe: { ...getPXEConfig(), proverEnabled: harness.expectRealProofs },
  });
  try {
    const [operator] = await registerInitialLocalNetworkAccountsInWallet(wallet);
    if (operator === undefined) throw new Error("the local network registered no initial account");
    if (harness.tip?.wfj) await registerWfj(wallet, node);
    const fee = harness.tip?.wfj ? await feeOptions(DEFAULT_FEE_SETTING, "deploy") : {};
    checks?.rejectTamperedCopyOfNextTx("smoke deployment");
    const { contract } = await timed(logger, "smoke deployment tx (client proving and mining)", () =>
      NoConstructorContract.deploy(wallet).send({ ...fee, from: operator }),
    );
    logger.info(`smoke contract deployed at ${contract.address}`);
    checks?.finish();
  } finally {
    await wallet.stop();
  }
  logger.info("smoke: PASS");
}

main().catch((err) => {
  logger.error(`smoke: FAIL: ${err?.stack ?? err}`);
  process.exit(1);
});
