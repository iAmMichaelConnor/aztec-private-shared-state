// A node operator's enc key rotation into its secret-shared on-chain intake
// contracts (enc-key.ts), as the operator runs it on the node's host while
// the node runs:
//
//   node --conditions=source --import <repo>/ts/hooks/register.mjs ts/pss-relayer/src/rotate-enc-key.ts rotate.json
//
// (`npm run rotate-enc-key --workspace ts/pss-relayer -- rotate.json`
// does the same). The configuration file is JSON:
//
//   {
//     "aztecNodeUrl": "http://127.0.0.1:8380",
//     "adminSocket": "<the node's admin socket: its config's admin_socket, default <run_dir>/admin.sock>",
//     "party": 0,
//     "contracts": [{ "address": "0x...", "artifact": "<its aztec compile output>", "epoch": 2 }],
//     "account": { "keyFile": "<a mode 0600 JSON file: { secretKey, signingKey, salt }>" } | { "secretKey": "0x..", ... } | "local-network",
//     "fee": { "method": "wfj" | "account", "gas": { "configure": { "gasLimits": { "daGas": <n>, "l2Gas": <n> } } } },
//     "proverEnabled": true
//   }
//
// For each contract in order it signs the node's current enc key at the
// contract's stored epoch + 1 (`epoch`, optional, is the epoch the operator
// expects, refused if it is another), submits rotate_enc_key, checks the
// stored key and asks the node to record it, printing one JSON line per
// contract; it stops at the first failure. A rerun sends nothing to a
// contract that already stores the node's current key and signs the failed
// contract's epoch again (the node replaces its pending scalar). Run
// `sidecar-node rotate-enc` first to rotate to a new scalar; without it each
// contract takes the node's current key. Relative paths inside the file are
// read from its directory (config-file.ts).

import { Contract } from "@aztec-labs/aztec.js/contracts";
import { loadContractArtifact } from "@aztec-labs/stdlib/abi";
import type { FeeSetting } from "@aztec-pss/pss-client";

import { operatorWallet, registerContracts, type RelayerAccount } from "./aztec.ts";
import { configAccount, readConfigFile } from "./config-file.ts";
import { adminSocket, rotateEncKey, type EncKeyContract } from "./enc-key.ts";

// Operator knob: DESIGN.md, "Configuration reference" (pss-relayer
// `rotate-enc-key` configuration). No defaults: `party` is the node config's
// `party`, `adminSocket` its `admin_socket`, and `aztecNodeUrl` naturally
// its own `[tip] aztec_node`; `account`, `fee` and `proverEnabled` are the
// relayer's settings, and the rotation pays as the fee kind `configure`.
interface FileConfig {
  aztecNodeUrl: string;
  adminSocket: string;
  party: number;
  contracts: { address: string; artifact: string; epoch?: number }[];
  account: RelayerAccount | { keyFile: string };
  fee?: FeeSetting;
  proverEnabled?: boolean;
}

async function main(path: string | undefined) {
  const file = readConfigFile<FileConfig>(path, "usage: rotate-enc-key.ts <rotate.json>");
  const { cfg, at, read } = file;
  if (typeof cfg.aztecNodeUrl !== "string") throw new RangeError("aztecNodeUrl: the Aztec node's URL (the node's own [tip] aztec_node serves)");
  if (!Number.isInteger(cfg.party) || cfg.party < 0 || cfg.party > 2) throw new RangeError(`party: 0, 1 or 2, got ${cfg.party}`);
  if (!Array.isArray(cfg.contracts) || cfg.contracts.length === 0) throw new RangeError("contracts: at least one secret-shared on-chain intake contract");
  const log = { info: (m: string) => console.error(`[rotate-enc-key] ${m}`), warn: (m: string) => console.error(`[rotate-enc-key] warning: ${m}`) };
  const ow = await operatorWallet({
    aztecNodeUrl: cfg.aztecNodeUrl,
    account: configAccount(cfg.account, file, log),
    fee: cfg.fee,
    proverEnabled: cfg.proverEnabled,
    log,
  });
  try {
    const admin = adminSocket(at(cfg.adminSocket));
    for (const c of cfg.contracts) {
      const artifact = loadContractArtifact(JSON.parse(read(c.artifact)));
      const [address] = await registerContracts(ow.wallet, ow.node, [{ address: c.address, artifact }]);
      const contract = Contract.at(address!, artifact, ow.wallet) as unknown as EncKeyContract;
      const done = await rotateEncKey({ admin, contract, address: address!.toString(), party: cfg.party, from: ow.from, fee: ow.fee, epoch: c.epoch, log });
      console.log(JSON.stringify(done));
    }
  } finally {
    await ow.wallet.stop();
  }
}

main(process.argv[2]).catch((e) => {
  console.error(`[rotate-enc-key] ${e?.stack ?? e}`);
  process.exit(1);
});
