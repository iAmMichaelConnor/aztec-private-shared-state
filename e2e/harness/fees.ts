// The fee setup of a tip run (docs/ARCHITECTURE.md section 6, "Fee payment";
// docs/DECISIONS.md section 12): every tip transaction pays through
// Wonderland's private fee-payment contract (wFJ, the PrivateFPC of
// @alejoamiras/private-fee-juice). run.sh calls it once the network is up,
// before any tip transaction:
//
//   node harness/fees.ts
//
// The payers are the local network's initial accounts (the users and the
// operator of every driver) and each deployment's relayer's own account, a
// fresh initializerless Schnorr account whose keys go to
// keys/relayer-<deployment>-account.json. Why one per relayer: each relayer
// runs its own PXE, and two PXEs paying from one account's private balance
// spend the same note when their transactions overlap (the node refuses the
// second with "Existing nullifier").
// For each payer it
//   1. deposits FeeJuice on L1 to the contract's address
//      (FeeJuicePortal.depositToAztecPublic) under a secret bound to the
//      payer's address (the contract's derive_bridge_secret), so the
//      contract's public FeeJuice balance is backed by the deposit;
//   2. mines empty blocks (the local network's debug API) until the L1 to
//      L2 message is ready;
//   3. sends a funding transaction of its own from the payer with no
//      call but its fee payment, FeeJuice.claim and mint_and_pay_fee
//      (PrivateMintAndPayFeePaymentMethod), which credits the payer's
//      private FJ balance and pays this transaction through the contract.
// Then it checks, from this PXE, what every later transaction needs: the
// contract registered at the address pss-client pins for the node's Aztec
// version (registerWfj), its public FeeJuice balance nonzero, and every
// payer's private balance nonzero. A missing piece stops the run here,
// naming it.
//
// Writes harness.json tip.wfj, tip.payers, tip.relayerAccounts and tip.fees
// (the first block of the fee setup and each funding transaction, which
// harness/fee-payers.ts checks from). Environment: E2E_HARNESS,
// NODE_EXTRA_CA_CERTS, ANVIL_PORT.
import { FeeJuicePortalAbi } from "@aztec-foundation/l1-artifacts/FeeJuicePortalAbi";
import type { AztecAddress } from "@aztec-labs/aztec.js/addresses";
import { BatchCall } from "@aztec-labs/aztec.js/contracts";
import { L1FeeJuicePortalManager } from "@aztec-labs/aztec.js/ethereum";
import { Fr } from "@aztec-labs/aztec.js/fields";
import { ProtocolContractAddress } from "@aztec-labs/aztec.js/protocol";
import { isL1ToL2MessageReady } from "@aztec-labs/aztec.js/messaging";
import { getFeeJuiceBalance } from "@aztec-labs/aztec.js/utils";
import { createExtendedL1Client } from "@aztec-labs/ethereum/client";
import { extractEvent } from "@aztec-labs/ethereum/utils";
import { poseidon2HashBytes, poseidon2HashWithSeparator } from "@aztec-labs/foundation/crypto/sync";
import { BlockNumber } from "@aztec-labs/foundation/branded-types";
import { Fq } from "@aztec-labs/foundation/curves/bn254";
import { createLogger } from "@aztec-labs/foundation/log";
import { getPXEConfig } from "@aztec-labs/pxe/server";
import { computeSecretHash, deriveStorageSlotInMap } from "@aztec-labs/stdlib/hash";
import { createAztecNodeDebugClient } from "@aztec-labs/stdlib/interfaces/client";
import { EmbeddedWallet } from "@aztec-labs/wallets/embedded";
import { registerInitialLocalNetworkAccountsInWallet } from "@aztec-labs/wallets/testing";
import { PrivateMintAndPayFeePaymentMethod } from "@alejoamiras/private-fee-juice";
import { WFJ, registerWfj } from "@aztec-pss/pss-client";

import { writeFileSync } from "node:fs";
import { join } from "node:path";

import { connectNode, harnessLogger, loadHarness, timed } from "./harness.ts";

const logger = harnessLogger("fees");

/** The anvil account the local network funds, as `aztec start --local-network` uses it. */
const L1_MNEMONIC = "test test test test test test test test test test test junk";
/** The contract's DOM_SEP__FPC_BRIDGE_SECRET: poseidon2_hash_bytes("az_dom_sep__fpc_bridge_secret") as u32. */
const BRIDGE_SECRET_SEPARATOR = Number(poseidon2HashBytes(Buffer.from("az_dom_sep__fpc_bridge_secret")).toBigInt() & 0xffff_ffffn);
/** Empty blocks mined while waiting for one L1 to L2 message, at most. */
const MAX_BLOCKS = 40;

class FeeSetupMissing extends Error {}
const missing = (what: string): never => {
  throw new FeeSetupMissing(what);
};

interface Deposit {
  payer: string;
  address: AztecAddress;
  amount: bigint;
  salt: Fr;
  secret: Fr;
  leafIndex: Fr;
  messageHash: Fr;
}

async function main() {
  const h = loadHarness();
  if (!h.tip) throw new Error("harness.json has no tip section: run tip.ts plan first");
  const { node, checks } = await connectNode(h, logger);
  const fromBlock = (await node.getBlockNumber()) + 1;
  const wallet = await EmbeddedWallet.create(node, { ephemeral: true, pxe: { ...getPXEConfig(), proverEnabled: h.expectRealProofs } });
  try {
    const initial = await registerInitialLocalNetworkAccountsInWallet(wallet);
    const relayers: [string, AztecAddress][] = [];
    const relayerAccounts: Record<string, string> = {};
    for (const deployment of Object.keys(h.tip.deployments)) {
      const keys = { secretKey: Fr.random(), signingKey: Fq.random(), salt: Fr.random() };
      const relayer = await wallet.createSchnorrInitializerlessAccount(keys.secretKey, keys.salt, keys.signingKey, `pss-relayer-${deployment}`);
      const accountFile = join(h.runDir, "keys", `relayer-${deployment}-account.json`);
      writeFileSync(
        accountFile,
        JSON.stringify({ secretKey: keys.secretKey.toString(), signingKey: keys.signingKey.toString(), salt: keys.salt.toString(), address: relayer.address.toString() }) + "\n",
        { mode: 0o600 },
      );
      relayers.push([`relayer-${deployment}`, relayer.address]);
      relayerAccounts[deployment] = accountFile;
    }
    const payers: Record<string, AztecAddress> = Object.fromEntries([...initial.map((a, i) => [`account${i}`, a] as const), ...relayers]);
    logger.info(`payers: ${Object.entries(payers).map(([n, a]) => `${n} ${a}`).join(", ")}`);

    // The address pss-client pins, after checking the node runs its Aztec version.
    const fpc = await registerWfj(wallet, node);
    logger.info(`wFJ (PrivateFPC, Aztec ${WFJ.aztecVersion}) registered at ${fpc.address}`);
    // wFJ's public FeeJuice balance before the fee setup (the FeeJuice
    // contract's balances map, slot 1), recorded with the fee setup:
    // fee-payers.ts starts from it after the scenarios
    const wfjBalanceBefore =
      fromBlock > 1
        ? (await node.getPublicStorageAt(BlockNumber(fromBlock - 1), ProtocolContractAddress.FeeJuice, await deriveStorageSlotInMap(new Fr(1n), fpc.address))).toBigInt()
        : 0n;

    const funding: Record<string, string> = {};
    const deposits = await timed(logger, "L1 deposits to wFJ", () => depositAll(node, fpc.address, payers));
    await timed(logger, "L1 to L2 messages ready", () => waitForMessages(h.aztecNodeUrl, node, deposits));
    for (const d of deposits) {
      const { receipt } = await timed(logger, `funding tx of ${d.payer} (claim, mint_and_pay_fee)`, () =>
        new BatchCall(wallet, []).send({
          from: d.address,
          fee: { paymentMethod: new PrivateMintAndPayFeePaymentMethod(fpc.address, d.amount, d.secret, d.salt, d.leafIndex) },
        }),
      );
      funding[d.payer] = receipt.txHash.toString();
    }

    // The check every tip transaction depends on.
    const registered = await wallet.getContractMetadata(fpc.address);
    if (!registered.instance) missing(`wFJ is not registered in the PXE at ${fpc.address}`);
    const publicBalance = await getFeeJuiceBalance(fpc.address, node);
    if (publicBalance === 0n) missing(`wFJ ${fpc.address} has no public FeeJuice balance to pay the sequencer`);
    const unfunded: string[] = [];
    for (const [name, address] of Object.entries(payers)) {
      const { result } = await fpc.methods.balance_of(address).simulate({ from: address });
      const balance = BigInt(result as bigint);
      logger.info(`${name} ${address}: private FJ balance ${balance}`);
      if (balance === 0n) unfunded.push(`${name} ${address}`);
    }
    if (unfunded.length) missing(`unfunded payer${unfunded.length > 1 ? "s" : ""} (no private FJ balance in wFJ ${fpc.address}): ${unfunded.join(", ")}`);
    logger.info(`wFJ public FeeJuice balance ${publicBalance}; every payer funded`);
    checks?.finish({ requireNegative: false });

    h.tip.wfj = { address: fpc.address.toString(), salt: new Fr(WFJ.salt).toString() };
    h.tip.fees = { fromBlock, funding, wfjBalanceBefore: wfjBalanceBefore.toString() };
    h.tip.payers = Object.fromEntries(Object.entries(payers).map(([n, a]) => [n, a.toString()]));
    h.tip.relayerAccounts = relayerAccounts;
    writeFileSync(process.env.E2E_HARNESS!, JSON.stringify(h, null, 2) + "\n");
  } finally {
    await wallet.stop();
  }
}

/** One deposit per payer, each under a secret bound to the payer's address. */
async function depositAll(node: Parameters<typeof L1FeeJuicePortalManager.new>[0], fpc: AztecAddress, payers: Record<string, AztecAddress>): Promise<Deposit[]> {
  const l1 = createExtendedL1Client([`http://127.0.0.1:${process.env.ANVIL_PORT ?? 8545}`], L1_MNEMONIC);
  const portal = await L1FeeJuicePortalManager.new(node, l1, createLogger("pss-e2e:fees:l1"));
  const tokens = portal.getTokenManager();
  const { l1ContractAddresses } = await node.getNodeInfo();
  const portalAddress = l1ContractAddresses.feeJuicePortalAddress.toString() as `0x${string}`;
  const out: Deposit[] = [];
  for (const [payer, address] of Object.entries(payers)) {
    const amount = await tokens.getMintAmount();
    await tokens.mint(l1.account.address);
    await tokens.approve(amount, portalAddress, "FeeJuice Portal");
    const salt = Fr.random();
    const secret = poseidon2HashWithSeparator([salt, address], BRIDGE_SECRET_SEPARATOR);
    const secretHash = await computeSecretHash(secret);
    const hash = await l1.writeContract({
      address: portalAddress,
      abi: FeeJuicePortalAbi,
      functionName: "depositToAztecPublic",
      args: [fpc.toString() as `0x${string}`, amount, secretHash.toString() as `0x${string}`],
    });
    const receipt = await l1.waitForTransactionReceipt({ hash });
    const event = extractEvent(receipt.logs, portalAddress, FeeJuicePortalAbi, "DepositToAztecPublic", (l) => l.args.amount === amount && l.args.to?.toLowerCase() === fpc.toString().toLowerCase());
    out.push({ payer, address, amount, salt, secret, leafIndex: new Fr(event.args.index as bigint), messageHash: Fr.fromString(event.args.key as string) });
    logger.info(`${payer}: deposited ${amount} to wFJ on L1 (message ${event.args.key})`);
  }
  return out;
}

/** Mine empty blocks until every deposit's L1 to L2 message is ready. */
async function waitForMessages(nodeUrl: string, node: Parameters<typeof isL1ToL2MessageReady>[0], deposits: Deposit[]): Promise<void> {
  const debug = createAztecNodeDebugClient(nodeUrl);
  for (let i = 0; ; i++) {
    const ready = await Promise.all(deposits.map((d) => isL1ToL2MessageReady(node, d.messageHash)));
    if (ready.every(Boolean)) return;
    if (i >= MAX_BLOCKS) {
      throw new Error(`L1 to L2 deposit messages not ready after ${MAX_BLOCKS} blocks: ${deposits.filter((_, k) => !ready[k]).map((d) => d.payer).join(", ")}`);
    }
    await debug.mineBlock();
  }
}

main().catch((err) => {
  if (err instanceof FeeSetupMissing) {
    logger.error(`fee setup: ${err.message}`);
    process.exit(2);
  }
  logger.error(`fees: FAIL: ${err?.stack ?? err}`);
  process.exit(1);
});
