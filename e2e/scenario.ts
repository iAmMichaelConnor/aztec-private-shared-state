// The scenario format (scenarios/README.md): what a scenario module exports.
// Each step kind's fields are defined by its module under steps/.
import type { ContractSpec } from "./engine/contracts.ts";
import type { Expr } from "./engine/scope.ts";
import type { RedeemStep } from "./steps/redeem.ts";
import type { ReorgStep } from "./steps/reorg.ts";
import type { DisableStep } from "./steps/disable.ts";
import type { FetchStep } from "./steps/fetch.ts";
import type { KeeperStep } from "./steps/keeper.ts";
import type { LetStep } from "./steps/let.ts";
import type { LogStep } from "./steps/log.ts";
import type { AdvanceStep } from "./steps/advance.ts";
import type { RegisterStep } from "./steps/register.ts";
import type { RelayerStep } from "./steps/relayer.ts";
import type { RestoreStep } from "./steps/restore.ts";
import type { RoundStep } from "./steps/round.ts";
import type { SameBlockStep } from "./steps/same-block.ts";
import type { SenderStep } from "./steps/sender.ts";
import type { TipAttemptStep } from "./steps/tip-attempt.ts";
import type { TipAuditStep } from "./steps/tip-audit.ts";
import type { TipEncKeyStep } from "./steps/tip-enc-key.ts";
import type { TipExitStep } from "./steps/tip-exit.ts";
import type { TipFundStep } from "./steps/tip-fund.ts";
import type { TipPauseStep } from "./steps/tip-pause.ts";
import type { TipRecoverStep } from "./steps/tip-recover.ts";
import type { TipReplaceNodeStep } from "./steps/tip-replace-node.ts";
import type { TipInitStep } from "./steps/tip-init.ts";
import type { TipLandStep } from "./steps/tip-land.ts";
import type { TipNoticeStep } from "./steps/tip-notice.ts";
import type { TipOutbidStep } from "./steps/tip-outbid.ts";
import type { TipOutcomeStep } from "./steps/tip-outcome.ts";
import type { TipRequestStep } from "./steps/tip-request.ts";
import type { TipResultStep } from "./steps/tip-result.ts";
import type { TipUpgradeStep } from "./steps/tip-upgrade.ts";
import type { TxStep } from "./steps/tx.ts";
import type { ViewStep } from "./steps/view.ts";

export type { ContractSpec } from "./engine/contracts.ts";
export type { Refusal } from "./engine/machine.ts";
export type { Expect, Expr, Value } from "./engine/scope.ts";
export type { AnsweredRound, RefusedRound } from "./steps/round.ts";

export type Step =
  | RegisterStep
  | DisableStep
  | RoundStep
  | TxStep
  | FetchStep
  | RestoreStep
  | SenderStep
  | TipInitStep
  | TipEncKeyStep
  | TipExitStep
  | TipFundStep
  | TipPauseStep
  | TipReplaceNodeStep
  | TipRequestStep
  | SameBlockStep
  | TipResultStep
  | TipUpgradeStep
  | TipAttemptStep
  | TipOutcomeStep
  | TipNoticeStep
  | TipRecoverStep
  | TipLandStep
  | TipOutbidStep
  | TipAuditStep
  | RedeemStep
  | ViewStep
  | KeeperStep
  | RelayerStep
  | AdvanceStep
  | ReorgStep
  | LetStep
  | LogStep;

export interface Scenario {
  /** The example's directory name (harness.json `examples`). */
  example: string;
  /** Names for the local network's initial accounts, in order, or with
   * `freshAccounts` for as many fresh ones. */
  accounts: string[];
  /** The accounts are new initializerless Schnorr accounts of random keys
   * instead of the local network's initial accounts, so nothing an earlier
   * scenario of the run left on chain between the initial accounts (a
   * handshake) reaches them. They hold no FeeJuice and pay through the
   * local network's SponsoredFPC: not in a tip run. */
  freshAccounts?: boolean;
  /** The wallets, by name, each its own PXE holding the keys of the accounts
   * listed; every account in exactly one. Without it one wallet holds every
   * account. */
  wallets?: Record<string, string[]>;
  /** Accounts every wallet registers as senders (their tagged notes are
   * scanned) before anything is deployed; a `sender` step registers one in
   * one wallet at its place among the steps. */
  senders?: string[];
  /** By wallet name (`wallet` without `wallets`), the tagging secret
   * strategy the wallet's `resolveTaggingSecretStrategy` hook picks for
   * every message its PXE sends. A wallet not named has no hook: its PXE
   * tags a message to an account it does not hold through a non-interactive
   * handshake with the standard handshake registry, and a self-send with the
   * address-derived secret either way. */
  tagging?: Record<string, "address-derived">;
  /** Fresh keys of the run: namespace owner keys and requester keys. */
  keys: Record<string, "owner" | "requester">;
  /** The default requester key of rounds. */
  signer?: string;
  /** Values computed once, before the contracts deploy (their initializer arguments may use them). */
  values?: Record<string, Expr>;
  /** The contracts, by the name steps use, built and deployed in order; the first is the steps' default. */
  contracts: Record<string, ContractSpec>;
  /** The tip deployments the harness deployed and configured (E2E_TIP=1;
   * harness.json tip.deployments), by the name steps use: each is a
   * contract and a namespace of that name (its address), registered in
   * every wallet, and its namespace's client knows every package the
   * deployment registers. After `contracts` and `namespaces` in the
   * default order. */
  tip?: Record<string, string>;
  /** The namespaces, by the name steps use, each a value computed after the
   * deploys (`$contracts.<name>` for a contract's address, `{random: "field"}`
   * for a fresh one); the first is the steps' default. */
  namespaces: Record<string, Expr>;
  /** Circuits registered under another name: alias → circuit. Every client knows them. */
  aliases?: Record<string, string>;
  steps: Step[];
}
