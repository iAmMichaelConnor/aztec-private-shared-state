// Secret-shared on-chain intake in the lending tip (scenarios/README.md,
// "lending-tip-shared-onchain.ts"): one deployment the harness made of
// examples/lending-tip's LendingTip with its two tokens and LendingOracle
// deployed first (E2E_TIP=1,
// E2E_TIP_DEPLOYMENTS="lending-tip-shared-onchain"), the secret-shared deployment
// with the secret-shared deposit registered again under secret-shared on-chain intake
// (`deposit_shared_onchain`, the same compiled circuit, its outcome key and
// tag chosen) and its `shared_onchain_slot` in the nodes' configuration. The
// nodes key the contract at epoch 1; `alice` opens a position with no
// off-chain step (position 0 clear in the log, the amount, her partial note
// and the outcome key and tag her client derives for the request encoded
// under the stored keys; the amount escrowed and the usage deposit paid
// from her credit, with no token transfer); the relayer lands it through
// `process_shared(ROUND_DEPOSIT, ...)`, she opens the outcome (position 1)
// and takes its note, the audit finds no input, no requester and no
// private value in a public place of either transaction, and the market
// kept the usage deposit.
import type { Scenario } from "../scenario.ts";
import { funded, ONE, USAGE_DEPOSIT, outcome, sharedResult } from "./lending-tip.ts";

export const scenario: Scenario = {
  example: "lending-tip",
  accounts: ["operator", "alice", "bob"],
  wallets: { alice: ["operator", "alice"], bob: ["bob"] },
  senders: ["operator"],
  keys: {},
  values: {},
  contracts: {},
  namespaces: {},
  tip: { shared: "lending-tip-shared-onchain" },
  steps: [
    { tipInit: "shared", name: "sharedInit" },
    ...funded("shared", ["alice"]),
    { tipEncKey: "shared", epoch: 1, from: "operator", name: "encKeys" },
    {
      tipRequest: "deposit_shared_onchain",
      namespace: "shared",
      from: "alice",
      method: "deposit_shared_onchain",
      // the partial note and the derived outcome key and tag come from alice's request secrets
      inputs: { position: 0, amount: 1_500 },
      name: "onchainOpen",
      // a real-proof run's node-side negative: a copy of the request with one Chonk proof field changed, refused
      nodeTamper: true,
    },
    sharedResult("onchainOpen", "$sharedInit.newCommitments[0]"),
    outcome("onchainOpen", "alice", [0, 1, ONE, 1_500, 0, 0]),
    // the escrow is drawn from alice's credit: no token transfer, so the amount appears nowhere public
    { tipAudit: "onchainOpen", outcome: "onchainOpenOutcome" },
    { view: "get_kept_deposits", contract: "shared", from: "operator", name: "sharedKept", expect: [["eq", "$sharedKept", USAGE_DEPOSIT]] },
  ],
};
