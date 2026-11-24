// Writes a queue on a local Aztec 6.0.0 network for the chain reader's
// integration test (tests/chain.rs): compiles PssPublicTest
// (noir/pss_public_contract_test) with the pinned contract nargo
// and bb through `aztec compile`, deploys it, enqueues three requests
// through its on-chain intake `request_onchain` (which appends and emits the
// request log) and four more through `request` (an id the test chooses), and
// prints one JSON line with the address, the ids and the queue as the
// contract's own view functions report it, for the Rust test to compare
// with what the reader reads.
//
//   AZTEC_NODE_URL=http://127.0.0.1:10280 CONTRACT_NARGO_BIN=... BB_BIN=... \
//     node --import ../../../../ts/hooks/register.mjs setup.ts
//
// Nothing here calls apply, so nothing emits a sealed-thirds log and the
// commitment slot stays 0 (only `apply` writes it); the sealed-thirds log
// is covered by the recorded fixture
// tests/fixtures/logs.json (record-logs.ts).
import { compileTestContract, deploy, testContractArgs, view, VK_HASH, withSession } from "./network.ts";

// Seven requests, more than the reader's default window (the head and four
// after it), so the test also sees the window end before the tail: three
// on-chain intake requests (amount_in, direction; user_nonce), then four ids.
const ONCHAIN = [
  { inputs: [1000n, 0n], nonce: 0x77n },
  { inputs: [2500n, 1n], nonce: 0x78n },
  { inputs: [42n, 0n], nonce: 0x79n },
];
const CHOSEN_IDS = [0xd4n, 0xe5n, 0xf6n, 0x107n];

const artifact = compileTestContract();
await withSession("pss-tip:chain-setup", async (s) => {
  const { node, user } = s;
  const contract = await deploy(s, artifact, testContractArgs());
  const blocks: number[] = [];
  for (const r of ONCHAIN) {
    await contract.methods.request_onchain!(r.inputs, r.nonce).send({ from: user });
    blocks.push(await node.getBlockNumber("proposed"));
  }
  for (const id of CHOSEN_IDS) {
    await contract.methods.request!(id).send({ from: user });
    blocks.push(await node.getBlockNumber("proposed"));
  }
  const head = (await view(contract.methods.get_head!(), user)) as { index: bigint; since: bigint };
  const tail = (await view(contract.methods.get_tail!(), user)) as bigint;
  const pool = (await view(contract.methods.get_pool!(), user)) as bigint;
  const ids: bigint[] = [];
  for (let i = 0; i < ONCHAIN.length + CHOSEN_IDS.length; i++) ids.push(BigInt((await view(contract.methods.request_at!(i), user)) as bigint));
  const out = {
    contract: contract.address.toString(),
    vk_hash: "0x" + VK_HASH.toString(16),
    // the contract's storage slots, as the compiled artifact lays them out
    slots: { queue: artifact.storageLayout.queue!.slot.toString(), pool: artifact.storageLayout.pool!.slot.toString() },
    onchain: ONCHAIN.map((r) => ({ inputs: r.inputs.map((v) => "0x" + v.toString(16)), user_nonce: "0x" + r.nonce.toString(16) })),
    request_ids: ids.map((id) => "0x" + id.toString(16)),
    blocks,
    head: { index: Number(head.index), since: Number(head.since) },
    tail: Number(tail),
    pool: "0x" + BigInt(pool).toString(16),
    tip: await node.getBlockNumber("proposed"),
  };
  process.stdout.write(JSON.stringify(out) + "\n");
});
