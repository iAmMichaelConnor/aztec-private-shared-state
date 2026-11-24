// Secret-shared on-chain intake in the AMM tip (scenarios/README.md,
// "amm-tip-shared-onchain.ts"): one deployment the harness made of
// examples/amm-tip's AmmTip (E2E_TIP=1,
// E2E_TIP_DEPLOYMENTS="amm-tip-shared-onchain"), the secret-shared deployment with
// the secret-shared swap registered again under secret-shared on-chain intake
// (`amm_swap_tip_shared_onchain`, the same compiled circuit, its outcome key
// and tag chosen) and its `shared_onchain_slot` in the nodes' configuration.
// The nodes key the contract (each signs its enc key at epoch 1 over its
// admin socket, the operator lands the three rotations); a trader's swap
// (the swap inputs, her partial note and the outcome key and tag her client
// derives for the request) is then encoded under the keys the contract
// stores and queued with no off-chain step; the relayer
// lands its result through `process_result_shared`, the trader opens the
// outcome and takes the completed note, and the audit finds no input,
// requester or private value in a public place of either transaction.
import type { Scenario } from "../scenario.ts";
import { sharedOutcome, sharedResult } from "./amm-tip.ts";

export const scenario: Scenario = {
  example: "amm-tip",
  accounts: ["operator", "alice", "bob"],
  wallets: { alice: ["operator", "alice"], bob: ["bob"] },
  keys: {},
  contracts: {},
  namespaces: {},
  tip: { shared: "amm-tip-shared-onchain" },
  steps: [
    { tipInit: "shared", name: "sharedInit" },
    // each node keeps its enc scalar pending at epoch 1 of the contract and signs; operator lands rotate_enc_key x3
    { tipEncKey: "shared", epoch: 1, from: "operator", name: "encKeys" },
    // bob's swap under secret-shared on-chain intake: the request function reads the three keys at its anchor,
    // emits one private log of the encoded shares (six chosen values) and queues the id with the log's hash
    {
      tipRequest: "amm_swap_tip_shared_onchain",
      namespace: "shared",
      from: "bob",
      method: "swap_shared_onchain",
      inputs: { amount_in: 31_337, direction: 0, min_out: 1_234 },
      name: "onchainSwap",
      // a real-proof run's node-side negative: a copy of the request with one Chonk proof field changed, refused
      nodeTamper: true,
    },
    sharedResult("onchainSwap", "$sharedInit.newCommitments[0]"),
    sharedOutcome("onchainSwap", "bob", [
      ["eq", "$onchainSwapOutcome.plaintext[0]", 0],
      ["gt", "$onchainSwapOutcome.plaintext[1]", 1_234],
    ]),
    { tipAudit: "onchainSwap", outcome: "onchainSwapOutcome" },
  ],
};
