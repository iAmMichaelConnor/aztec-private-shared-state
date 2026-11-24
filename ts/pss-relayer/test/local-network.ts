// The relayer on a local Aztec network (started by local-network.sh): it
// never sends skip() for an empty queue, and it sends skip() for a stale head
// and only then. The app is pss_public_contract_test (PssPublicTest),
// deployed with the test_plain manifest's stale period (3 blocks), which the
// relayer reads from the same manifest; `request(id)` stands in for intake; the
// orchestrator is the pss-client tests' mock, answering 404 to every FETCH by
// chain request id, as a network that never serves the request would.
// Transactions are sent from the local network's first test account (the
// deployer) and from the relayer's own wallet, both paying with the
// sponsored fee contract; nothing is proved client-side (proverEnabled
// false), since this checks the queue logic, not the proofs.
//
//   AZTEC_NODE_URL=http://127.0.0.1:11280 ARTIFACT=<PssPublicTest.json> \
//     node --conditions=source --import <repo>/ts/hooks/register.mjs test/local-network.ts

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { Contract } from "@aztec-labs/aztec.js/contracts";
import { SponsoredFeePaymentMethod } from "@aztec-labs/aztec.js/fee/testing";
import { Fr } from "@aztec-labs/aztec.js/fields";
import { createAztecNodeClient, waitForNode } from "@aztec-labs/aztec.js/node";
import { createLogger } from "@aztec-labs/aztec.js/log";
import { getPXEConfig } from "@aztec-labs/pxe/server";
import { loadContractArtifact } from "@aztec-labs/stdlib/abi";
import { EmbeddedWallet } from "@aztec-labs/wallets/embedded";
import { registerInitialLocalNetworkAccountsInWallet } from "@aztec-labs/wallets/testing";
import { DONE_SKIPPED, fieldHex, registerSponsoredFpc, sponsoredFeeSetting } from "@aztec-pss/pss-client";

import { clientConfig, MockOrchestrator, NODE_KEYS, TEST_PLAIN, TEST_PLAIN_STALE_BLOCKS, VK_FIELDS, VK_HASH } from "@aztec-pss/test-support";
import { createAztecRelayer } from "../src/aztec.ts";

const STALE_BLOCKS = TEST_PLAIN_STALE_BLOCKS;
const STALE = { enabled: true, blocks: STALE_BLOCKS };
const logger = createLogger("pss-relayer:local-network");
const url = process.env.AZTEC_NODE_URL ?? "http://127.0.0.1:11280";
const artifact = loadContractArtifact(JSON.parse(readFileSync(process.env.ARTIFACT!, "utf8")));

async function main() {
  const t0 = performance.now();
  const node = createAztecNodeClient(url);
  await waitForNode(node, logger);
  const wallet = await EmbeddedWallet.create(node, { ephemeral: true, pxe: { ...getPXEConfig(), proverEnabled: false } });
  const orch = new MockOrchestrator();
  const orchUrl = await orch.start();
  orch.on("POST", "/v1/fetch/chain", () => ({ status: 404, body: { error: "no attempt at this chain request", class: "not_found" } }));
  let relay: Awaited<ReturnType<typeof createAztecRelayer>> | undefined;
  try {
    const [deployer] = await registerInitialLocalNetworkAccountsInWallet(wallet);
    const fee = { paymentMethod: new SponsoredFeePaymentMethod(await registerSponsoredFpc(wallet)) };
    const config = {
      stale_blocks: STALE,
      node_sig_keys: NODE_KEYS.map((k) => ({ x: new Fr(BigInt(k.sig.x as string)), y: new Fr(BigInt(k.sig.y as string)) })),
      npk_app_hash: new Fr(0x9bn),
    };
    const { contract: deployed } = await Contract.deploy(wallet, artifact, [config, new Fr(BigInt(VK_HASH))]).send({ from: deployer!, fee });
    const app = Contract.at(deployed.address, artifact, wallet);
    logger.info(`PssPublicTest at ${deployed.address}`);

    relay = await createAztecRelayer({
      aztecNodeUrl: url,
      node,
      client: clientConfig(orchUrl, { test_plain: TEST_PLAIN }, STALE_BLOCKS),
      contract: { address: deployed.address, artifact },
      vkFields: { test_plain: VK_FIELDS },
      account: "local-network",
      fee: sponsoredFeeSetting,
      proverEnabled: false,
      log: { info: (m) => logger.info(m), warn: (m) => logger.warn(m) },
    });
    const { relayer, queue } = relay;
    assert.equal(relayer.staleBlocks, STALE_BLOCKS);
    // one transaction from the deployer, to move the chain on by a block
    let price = 0;
    const nextBlock = async () => {
      await app.methods.set_price!(new Fr(BigInt(++price))).send({ from: deployer!, fee });
    };

    // 1. an empty queue: head_since (0) + stale_blocks is long past, and the
    //    relayer stays idle block after block
    for (let i = 0; i < 3; i++) {
      const out = await relayer.tick();
      assert.equal(out.action, "idle", `empty queue, tick ${i}: ${out.action}`);
      await nextBlock();
    }
    let s = await queue.snapshot();
    assert.deepEqual([s.head, s.tail], [0, 0]);
    assert.ok(s.block >= STALE_BLOCKS, `block ${s.block}`);
    assert.equal(orch.received.length, 0, "no FETCH for an empty queue");
    logger.info(`empty queue at block ${s.block}: idle, no skip`);

    // 2. one request: fresh, so the relayer FETCHes (404) and waits
    const id = fieldHex(0xa11ce5n);
    await app.methods.request!(new Fr(BigInt(id))).send({ from: deployer!, fee });
    s = await queue.snapshot();
    assert.deepEqual([s.head, s.tail, s.headRequest], [0, 1, id]);
    const since = s.headSince;
    let out = await relayer.tick();
    while (out.snapshot.block < since + STALE_BLOCKS) {
      assert.equal(out.action, "waiting", `fresh head at block ${out.snapshot.block} (since ${since}): ${out.action}`);
      await nextBlock();
      out = await relayer.tick();
    }
    // 3. stale: skip() at the first tick at or after head_since + stale_blocks
    assert.equal(out.action, "skipped", `stale head at block ${out.snapshot.block} (since ${since}): ${out.action}`);
    assert.ok(orch.count("POST", "/v1/fetch/chain") >= 1);
    s = await queue.snapshot();
    assert.deepEqual([s.head, s.tail], [1, 1]);
    assert.equal(await queue.doneAt(0), DONE_SKIPPED);
    logger.info(`stale head skipped at block ${out.snapshot.block} (head_since ${since}, stale_blocks ${STALE_BLOCKS}); done[0] = ${DONE_SKIPPED}`);

    // 4. empty again: idle, no second skip
    for (let i = 0; i < 2; i++) {
      await nextBlock();
      assert.equal((await relayer.tick()).action, "idle");
    }
    s = await queue.snapshot();
    assert.deepEqual([s.head, s.tail], [1, 1]);
    logger.info(`local-network relayer check: PASS (${((performance.now() - t0) / 1000).toFixed(1)} s)`);
  } finally {
    await relay?.close();
    await wallet.stop();
    await orch.stop();
  }
}

main().then(
  () => process.exit(0),
  (e) => {
    logger.error(`local-network relayer check: FAIL: ${e?.stack ?? e}`);
    process.exit(1);
  },
);
