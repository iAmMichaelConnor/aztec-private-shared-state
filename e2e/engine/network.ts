// The local network as a run sees it: the node client (with the node-side
// verification checks and the dropped-transaction hook), the wallets, each
// its own PXE with the scenario's tagging hook if it names one, the named
// accounts (the initial ones, or fresh ones) and the fee setting every
// transaction pays under.
import { getInitialTestAccountsData } from "@aztec-labs/accounts/testing/lazy";
import type { AztecAddress } from "@aztec-labs/aztec.js/addresses";
import { Fr } from "@aztec-labs/aztec.js/fields";
import type { Logger } from "@aztec-labs/aztec.js/log";
import type { AztecNode } from "@aztec-labs/aztec.js/node";
import { GrumpkinScalar } from "@aztec-labs/foundation/curves/grumpkin";
import { getPXEConfig } from "@aztec-labs/pxe/server";
import type { Tx } from "@aztec-labs/stdlib/tx";
import { EmbeddedWallet } from "@aztec-labs/wallets/embedded";
import { feeOptions, registerWfj, sponsoredFeeSetting, type FeeSendOptions, type FeeSetting, type FeeTxKind } from "@aztec-pss/pss-client";

import { tipFeeSetting } from "../harness/fee-settings.ts";
import { connectNode, type Harness } from "../harness/harness.ts";
import type { NodeVerification } from "../harness/node-verification.ts";
import type { Scenario } from "../scenario.ts";
import { check } from "./scope.ts";

/** The name of the fee setting a tip run of `s` pays under: the one its tip
 * deployments name (each must name the same, or none), none without them. */
function runFee(h: Harness, s: Pick<Scenario, "tip">): string | undefined {
  const fees = new Set(Object.values(s.tip ?? {}).map((d) => h.tip?.deployments[d]?.fee));
  check(fees.size <= 1, `the scenario's tip deployments name different fee settings (${[...fees].join(", ")})`);
  return [...fees][0];
}

/** The one wallet of a scenario without `wallets`. */
export const ONE_WALLET = "wallet";

export interface Network {
  node: AztecNode;
  /** The node-side verification checks; undefined unless the run expects real proofs. */
  checks?: NodeVerification;
  /** The wallets by the scenario's names (`ONE_WALLET` without `wallets`). */
  wallets: Record<string, EmbeddedWallet>;
  /** The wallet that holds an account's keys. */
  walletOf(account: string): EmbeddedWallet;
  /** The scenario's accounts under its names: the local network's initial
   * accounts, or with `freshAccounts` new ones. */
  accounts: Record<string, AztecAddress>;
  /** The fee setting every transaction pays under. */
  feeSetting: FeeSetting;
  /** The fee options of a `kind` transaction, spread into its send options. */
  fee(kind: FeeTxKind): Promise<FeeSendOptions>;
  /** Every transaction the wallets submitted to the node, by hash, as sent
   * (its public calls with their calldata, its fee payer). */
  sentTxs: ReadonlyMap<string, Tx>;
  /** Arms the loss of the next transaction the wallet sends (`label` names it in the error). */
  dropNextTx(label: string): void;
  /** The hash of the transaction last dropped. */
  droppedTxHash(): string | undefined;
  /** Holds the next `n` transactions the wallets send until all `n` are
   * proved, then awaits `release` and submits them to the node at once.
   * Returns `held(k)`, which resolves once `k` of them are held (proved). */
  holdNextTxs(n: number, release: () => Promise<void>): (k: number) => Promise<void>;
  /** Stops every wallet. */
  stop(): Promise<void>;
}

/** Connects the node, creates the wallets and names the accounts; the
 * caller calls `stop`. */
export async function connectNetwork(h: Harness, logger: Logger, s: Pick<Scenario, "tip" | "accounts" | "freshAccounts" | "senders" | "wallets" | "tagging">): Promise<Network> {
  const { node, checks } = await connectNode(h, logger);

  // How a dropped transaction is made. The driver wraps the
  // node client's sendTx (outside the node-side verification wrapper) and,
  // when a `drop` step arms it, throws instead of forwarding: the
  // transaction was proved and signed, and is lost before the node sees it,
  // as on a dropped connection or a crashed client. The node then has no
  // receipt for it. The recovery is the sidecar-path one (ARCHITECTURE.md
  // section 8): FETCH the committed round by request id and land the same proof.
  const sender = node as unknown as { sendTx(tx: Tx): Promise<void> };
  const forward = sender.sendTx.bind(sender);
  let dropNext: string | undefined;
  let dropped: string | undefined;
  // The next `n` sendTx calls wait for one another; the last one runs
  // `release` and lets them all through.
  let hold: { n: number; release: () => Promise<void>; waiting: { go: () => void; fail: (e: unknown) => void }[]; arrived: (() => void)[] } | undefined;
  const sentTxs = new Map<string, Tx>();
  sender.sendTx = async (tx: Tx) => {
    if (hold !== undefined) {
      const h = hold;
      await new Promise<void>((go, fail) => {
        h.waiting.push({ go, fail });
        h.arrived[h.waiting.length - 1]!();
        if (h.waiting.length < h.n) return;
        hold = undefined;
        h.release().then(
          () => h.waiting.forEach((w) => w.go()),
          (e: unknown) => h.waiting.forEach((w) => w.fail(e)),
        );
      });
    }
    if (dropNext === undefined) {
      sentTxs.set(tx.getTxHash().toString(), tx);
      return forward(tx);
    }
    const label = dropNext;
    dropNext = undefined;
    dropped = tx.getTxHash().toString();
    throw new Error(`${label}: transaction ${dropped} dropped before it reached the node`);
  };

  // Fresh accounts are initializerless Schnorr accounts of random keys: no
  // earlier scenario of the run has sent them anything. They hold no
  // FeeJuice, so they pay through the local network's SponsoredFPC, which a
  // tip run's fee-payer check refuses.
  check(!(s.freshAccounts && h.tip?.wfj), "fresh accounts pay through the local network's SponsoredFPC; a tip run pays every transaction through wFJ");
  const initial = s.freshAccounts
    ? s.accounts.map(() => ({ secret: Fr.random(), salt: Fr.random(), signingKey: GrumpkinScalar.random() }))
    : await getInitialTestAccountsData();
  check(initial.length >= s.accounts.length, `the local network has ${initial.length} initial accounts, the scenario names ${s.accounts.length}`);
  // Without `wallets`, the one wallet holds every initial account; with
  // them, each wallet is its own PXE and holds the keys of its own accounts
  // only, so a note one account sends another is delivered between PXEs.
  const holders: Record<string, number[]> = s.wallets
    ? Object.fromEntries(Object.entries(s.wallets).map(([w, names]) => [w, names.map((n) => s.accounts.indexOf(n))]))
    : { [ONE_WALLET]: initial.map((_, i) => i) };
  const wallets: Record<string, EmbeddedWallet> = {};
  const holder: Record<string, string> = {};
  const accounts: Record<string, AztecAddress> = {};
  try {
    for (const [w, indices] of Object.entries(holders)) {
      const strategy = s.tagging?.[w];
      const hooks = strategy && { resolveTaggingSecretStrategy: async () => ({ type: strategy }) };
      const wallet = (wallets[w] = await EmbeddedWallet.create(node, { ephemeral: true, pxe: { ...getPXEConfig(), proverEnabled: h.expectRealProofs, ...(hooks && { hooks }) } }));
      if (strategy) logger.info(`wallet ${w}: the tagging hook picks the ${strategy} secret for every message`);
      for (const i of indices) {
        const a = initial[i]!;
        const address = (await wallet.createSchnorrInitializerlessAccount(a.secret, a.salt, a.signingKey)).address;
        const n = s.accounts[i];
        if (n === undefined) continue;
        accounts[n] = address;
        holder[n] = w;
      }
    }
    logger.info(s.accounts.map((n) => `${n} ${accounts[n]}${s.wallets ? ` (wallet ${holder[n]})` : ""}`).join(", "));
    // A tip run pays every transaction through wFJ under the fee setting its
    // tip deployments name (e2e/tip/<deployment>.json `fee`: the app's fixed
    // gas per transaction kind; harness/fees.ts funded the accounts; each PXE
    // registers it at the pinned address, and harness/fee-payers.ts checks
    // the payer of each). A run without the tip services has no wFJ and pays
    // from the accounts' own FeeJuice, or for fresh accounts through the
    // SponsoredFPC, which each PXE registers (the settings are one).
    const sponsored = s.freshAccounts ? await Promise.all(Object.values(wallets).map((w) => sponsoredFeeSetting(w))) : [];
    const setting: FeeSetting = h.tip?.wfj ? tipFeeSetting(runFee(h, s)) : (sponsored[0] ?? { method: "account" });
    for (const wallet of Object.values(wallets)) {
      for (const n of s.senders ?? []) await wallet.registerSender(accounts[n]!, n);
      if (h.tip?.wfj) await registerWfj(wallet, node);
    }
    return {
      node,
      checks,
      wallets,
      walletOf(account) {
        const w = holder[account];
        check(w !== undefined, `account ${account} is not one of the scenario's`);
        return wallets[w]!;
      },
      accounts,
      feeSetting: setting,
      fee: (kind) => feeOptions(setting, kind),
      sentTxs,
      dropNextTx(label) {
        dropNext = label;
        dropped = undefined;
      },
      droppedTxHash: () => dropped,
      holdNextTxs(n, release) {
        check(hold === undefined, "transactions are already held");
        const arrived: (() => void)[] = [];
        const held = Array.from({ length: n }, () => new Promise<void>((resolve) => arrived.push(resolve)));
        hold = { n, release, waiting: [], arrived };
        return (k: number) => held[k - 1]!;
      },
      stop: () => stopAll(wallets),
    };
  } catch (error) {
    await stopAll(wallets);
    throw error;
  }
}

async function stopAll(wallets: Record<string, EmbeddedWallet>): Promise<void> {
  for (const wallet of Object.values(wallets)) await wallet.stop();
}
