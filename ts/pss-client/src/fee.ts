// The fee setting (docs/ARCHITECTURE.md section 6, "Fee payment"): how a
// transaction this client sends, or helps send, pays its fee. One setting
// per app: the fee method and one fixed gas setting per transaction kind.
// Every transaction the library sends (a result through the Lander, a
// request through submitIntake, a deployment, configure, skip or enc key
// rotation) takes txSendOptions(setting, kind): the fee (feeOptions) and the
// receipt status the send waits for (SEND_WAIT, proposed); a caller that
// sends its own transaction (a redeem, an exit) spreads
// `await feeOptions(setting, kind)` into its send options. The wallet registers wFJ once
// (registerWfj), which checks the node's version against the pin; the local
// network's SponsoredFPC is a fallback setting (sponsoredFeeSetting).

import type { registerPrivateContract } from "@alejoamiras/private-fee-juice/utils";
import { FPCFeePaymentMethod } from "@alejoamiras/private-fee-juice/fee-payment-methods";
import { AztecAddress } from "@aztec-labs/aztec.js/addresses";
import { getContractInstanceFromInstantiationParams, type WaitOpts } from "@aztec-labs/aztec.js/contracts";
import type { FeePaymentMethod } from "@aztec-labs/aztec.js/fee";
import { SponsoredFeePaymentMethod } from "@aztec-labs/aztec.js/fee/testing";
import { Fr } from "@aztec-labs/aztec.js/fields";
import { TxStatus } from "@aztec-labs/aztec.js/tx";
import type { Wallet } from "@aztec-labs/aztec.js/wallet";
import { Gas, type GasFees } from "@aztec-labs/stdlib/gas";
import { ProtocolContractAddress } from "@aztec-labs/aztec.js/protocol";
import { SPONSORED_FPC_SALT } from "@aztec-labs/constants";

import { ConfigError } from "./errors.ts";

/** wFJ as this client pins it: the canonical deployment of the PrivateFPC
 * of @alejoamiras/private-fee-juice for the Aztec version the client runs
 * (the package's canonical-deployment.json; a test holds the two equal). The
 * address follows from the contract's class and the salt, so another Aztec
 * version means another address. */
export const WFJ = {
  aztecVersion: "6.0.0",
  salt: 1n,
  address: "0x0516ebb4f9c7988eb3cf6dd9459a47556f7a92db06b17cfa47ffb37fd35c6915",
} as const;

/** wFJ's pinned address. */
export const wfjAddress = (): AztecAddress => AztecAddress.fromBigIntUnsafe(BigInt(WFJ.address));

/** The transaction kinds a fee setting fixes the gas of. The init round's
 * landing is a result; an escape-hatch exit (private only) is its own kind. */
export type FeeTxKind = "deploy" | "configure" | "request" | "result" | "redeem" | "exit" | "skip";

export interface GasLimits {
  daGas: number;
  l2Gas: number;
}

/** The gas one transaction kind declares. */
export interface KindGas {
  gasLimits: GasLimits;
  /** Default: the wallet's estimate of the transaction's teardown, none
   * under wFJ, which runs no teardown. */
  teardownGasLimits?: GasLimits;
}

// DEV DECISION: the fee method an app chooses for its users and its relayer,
// default "wfj"; every transaction calls wFJ's pay_fee() in its setup phase,
// which takes the maximum gas cost from the sender's private FJ balance and
// makes wFJ the fee payer, so the fee names nobody (what stays public: its
// timing, gas settings and fee, the number of balance notes spent, and each
// L1 deposit with its claim, to which a distinctive amount spent soon after
// can be linked). The payer funds its balance in a funding transaction of
// its own (FeeJuice.claim with mint_and_pay_fee), so feeOptions refuses a
// payment method that claims FeeJuice. `{ paymentMethod, name }`, an
// app-sponsored fee-payment contract, shows the sponsor's address as fee
// payer in every transaction, which names the app and its sponsor, and the
// sponsor sees and decides whom it pays for (the local network's
// SponsoredFPC has this form and is a local fallback only). "account" pays
// from the sender's own public FeeJuice balance, so every transaction names
// the sender as fee payer and links all its requests, which undoes the
// hidden requester (section 6); it reveals nothing new for an operator's
// relayer, whose address is public in every transaction it sends. Design
// guide: "Fixed properties" (Fees).
export type FeeMethod = "wfj" | "account" | { paymentMethod: FeePaymentMethod; name: string };

/** One app's fee setting. */
export interface FeeSetting {
  method: FeeMethod;
  /** Fixed gas per transaction kind, never estimated per transaction, so the
   * gas settings tell no round type apart. A kind left out declares what
   * the wallet chooses: aztec.js's EmbeddedWallet simulates the transaction
   * and declares its gas used plus 10%, which follows the transaction (a
   * failed swap's result declares less than a filled one's), so an app fixes
   * every kind it sends. wFJ charges the maximum gas cost in full with no
   * refund, so an app sets limits close to each kind's need. */
  gas?: Partial<Record<FeeTxKind, KindGas>>;
}

/** wFJ for every kind, with no fixed gas: each transaction declares what
 * the wallet chooses (see FeeSetting.gas). */
export const DEFAULT_FEE_SETTING: FeeSetting = { method: "wfj" };

// Every party follows the proposed chain (docs/ARCHITECTURE.md section 6,
// "Following the chain"; what a replaced block does: the pss-client README,
// "Replaced blocks"): a send returns once its transaction is in a proposed
// block, not once that block's checkpoint is on L1 (aztec.js's default,
// `checkpointed`).
/** The receipt status every transaction this library sends waits for:
 * `proposed`. Where a call takes the caller's send options, a `wait` there
 * replaces it. */
export const SEND_WAIT: WaitOpts = { waitForStatus: TxStatus.PROPOSED };

/** What feeOptions adds to aztec.js send options. */
export interface FeeSendOptions {
  fee?: { paymentMethod?: FeePaymentMethod; gasSettings?: { gasLimits: Gas; teardownGasLimits?: Gas; maxFeesPerGas?: GasFees } };
}

// ---- the maximum gas cost ----
//
// What wFJ's pay_fee() takes in full from the payer's private balance, with
// no refund: the declared gas limits at the declared max fees per gas. The
// e2e records it per transaction as the charge (e2e/engine/gas.ts).

/** Fees per gas, one per dimension, as GasFees holds them. */
export interface FeesPerGas {
  feePerDaGas: bigint;
  feePerL2Gas: bigint;
}

/** The maximum gas cost of `gasLimits` at `maxFeesPerGas`: wFJ's
 * get_max_gas_cost, `feePerDaGas * daGas + feePerL2Gas * l2Gas` (teardown
 * gas and priority fees excluded). */
export function maxGasCost(gasLimits: GasLimits, maxFeesPerGas: FeesPerGas): bigint {
  return maxFeesPerGas.feePerDaGas * BigInt(gasLimits.daGas) + maxFeesPerGas.feePerL2Gas * BigInt(gasLimits.l2Gas);
}

function checkGas(kind: string, what: string, g: GasLimits): void {
  for (const dim of ["daGas", "l2Gas"] as const) {
    if (!Number.isSafeInteger(g[dim]) || g[dim] <= 0) throw new ConfigError(`fee.gas.${kind}.${what}.${dim}: a positive integer, got ${g[dim]}`);
  }
}

/** The fee part of the send options of a `kind` transaction under `setting`.
 * ConfigError for a method whose payment claims FeeJuice (a cold-start
 * mint_and_pay_fee): funding is a transaction of its own. */
export async function feeOptions(setting: FeeSetting = DEFAULT_FEE_SETTING, kind: FeeTxKind): Promise<FeeSendOptions> {
  const gas = setting.gas?.[kind];
  if (gas) {
    checkGas(kind, "gasLimits", gas.gasLimits);
    if (gas.teardownGasLimits) checkGas(kind, "teardownGasLimits", gas.teardownGasLimits);
  }
  const gasSettings = gas && {
    gasLimits: Gas.from(gas.gasLimits),
    ...(gas.teardownGasLimits && { teardownGasLimits: Gas.from(gas.teardownGasLimits) }),
  };
  const method = setting.method;
  if (method === "account") return gasSettings ? { fee: { gasSettings } } : {};
  let paymentMethod: FeePaymentMethod;
  if (method === "wfj") {
    paymentMethod = new FPCFeePaymentMethod(wfjAddress());
  } else {
    paymentMethod = method.paymentMethod;
    const payload = await paymentMethod.getExecutionPayload();
    if (payload.calls.some((c) => c.to.equals(ProtocolContractAddress.FeeJuice))) {
      throw new ConfigError(`fee method ${method.name}: its payment calls FeeJuice (a claim); a payer funds its balance in a funding transaction of its own, never inside a ${kind}`);
    }
  }
  return { fee: { paymentMethod, ...(gasSettings && { gasSettings }) } };
}

/** The aztec.js send options of a `kind` transaction this library sends
 * under `setting`: its fee (feeOptions) and the wait (SEND_WAIT). */
export async function txSendOptions(setting: FeeSetting | undefined, kind: FeeTxKind): Promise<FeeSendOptions & { wait: WaitOpts }> {
  return { ...(await feeOptions(setting, kind)), wait: SEND_WAIT };
}

/** What checkWfjNode reads from the node. */
export interface NodeVersionSource {
  getNodeInfo(): Promise<{ nodeVersion: string }>;
}

/** ConfigError unless the node runs the Aztec version wFJ is pinned for:
 * on another version the pinned address is not wFJ. */
export async function checkWfjNode(node: NodeVersionSource): Promise<void> {
  const { nodeVersion } = await node.getNodeInfo();
  if (nodeVersion !== WFJ.aztecVersion) {
    throw new ConfigError(`the node runs Aztec ${nodeVersion}, wFJ is pinned at ${WFJ.address} for Aztec ${WFJ.aztecVersion}: another version means another address`);
  }
}

/** The wFJ contract registerWfj returns (the package's PrivateFPCContract). */
export type WfjContract = Awaited<ReturnType<typeof registerPrivateContract>>;

/** Check the node's version against the pin, then register wFJ in the
 * wallet's PXE at the pinned address (no deployment transaction: the
 * contract has no public function and no constructor). */
export async function registerWfj(wallet: Wallet, node: NodeVersionSource): Promise<WfjContract> {
  await checkWfjNode(node);
  // Loaded here, not at the top: it carries the contract's artifact.
  const { registerPrivateContract } = await import("@alejoamiras/private-fee-juice/utils");
  const contract = await registerPrivateContract(wallet, new Fr(WFJ.salt), { assertCanonical: true });
  if (!contract.address.equals(wfjAddress())) throw new ConfigError(`wFJ registered at ${contract.address}, pinned at ${WFJ.address}`);
  return contract;
}

/** The local network's SponsoredFPC as a fee setting (no fixed gas),
 * registered in the wallet: a local fallback only, for a network on which
 * wFJ cannot be registered or a payer that holds no FeeJuice. */
export async function sponsoredFeeSetting(wallet: Wallet): Promise<FeeSetting> {
  return { method: { paymentMethod: new SponsoredFeePaymentMethod(await registerSponsoredFpc(wallet)), name: "SponsoredFPC" } };
}

/** The canonical SponsoredFPC's address, registered in the wallet. */
export async function registerSponsoredFpc(wallet: Wallet): Promise<AztecAddress> {
  // Loaded here, not at the top: it carries the contract's artifact.
  const { SponsoredFPCContract } = await import("@aztec-labs/noir-contracts.js/SponsoredFPC");
  const fpc = await getContractInstanceFromInstantiationParams(SponsoredFPCContract.artifact, { salt: new Fr(SPONSORED_FPC_SALT) });
  await wallet.registerContract(fpc, SponsoredFPCContract.artifact);
  return fpc.address;
}
