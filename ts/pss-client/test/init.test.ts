// The init round's result (src/init-result.ts, PssClient.fetchInitResult and
// Lander.attemptInit): the init layout from the example circuits' ABIs, FETCH
// by the init's fixed chain request id against a mock orchestrator, the
// refusals of the binding checks, the default init encoder for a slot key
// and a tree-valued key (encoded against the compiled contracts), and the lander sending nothing once a slot the init
// creates is written.

import assert from "node:assert/strict";
import { after, before, beforeEach, describe, test } from "node:test";

import { encodeArguments } from "@aztec-labs/stdlib/abi";

import {
  ConfigError,
  Lander,
  ProtocolError,
  PssClient,
  SidecarError,
  WFJ,
  chainRequestId,
  defaultInitEncoder,
  fieldHex,
  initCallContext,
  initChainRequestId,
  initResultLayout,
  tipInputsHash,
  type ResultContract,
} from "../src/internal.ts";
import {
  AMM_INIT,
  AMM_SWAP,
  ammInitAnswer,
  clientConfig,
  contractAbis,
  LENDING_INIT,
  lendingInitAnswer,
  LIQUIDITY,
  MARKET_KEY,
  MockOrchestrator,
  NAMESPACE,
  POOL_KEY,
  queued,
  recordingContract,
  replies,
  VK_FIELDS,
  VK_HASH,
} from "@aztec-pss/test-support";

const SENDER = "0x00000000000000000000000000000000000000000000000000000000000c0ffe";

let orch: MockOrchestrator;
let url: string;
before(async () => {
  orch = new MockOrchestrator();
  url = await orch.start();
});
after(async () => orch.stop());
beforeEach(() => {
  orch.routes.clear();
  orch.received.length = 0;
});



describe("the init layout", () => {
  test("amm_init_tip: [namespace, vk_hash, out_slots[1], request_id, old_c, new_c, npk_app_hash], no new leaf hashes", () => {
    const l = initResultLayout(AMM_INIT.circuit, queued(AMM_INIT.manifest));
    assert.deepEqual([l.slots, l.requestId, l.oldCommitments, l.newCommitments, l.npkAppHash, l.newHashes, l.records, l.state], [[2], 3, [4], [5], 6, [], [], "node"]);
  });
  test("lending_init: the tree header's new leaf hash is the tail", () => {
    const l = initResultLayout(LENDING_INIT.circuit, queued(LENDING_INIT.manifest));
    assert.deepEqual([l.slots, l.newCommitments, l.npkAppHash, l.newHashes], [[2], [5], 6, [7]]);
  });
  test("a round that reads a key is no init", () => {
    assert.throws(() => initResultLayout(AMM_SWAP.circuit, queued(AMM_SWAP.manifest)), /an init round reads no key/);
  });
  test("the client configuration keeps the init's layout, and refuses its results as a queued round's", () => {
    const client = new PssClient(clientConfig(url, { amm_init_tip: AMM_INIT, amm_swap_tip: AMM_SWAP }));
    assert.deepEqual(Object.keys(client.config.initResultLayouts), ["amm_init_tip"]);
    assert.ok(!("amm_init_tip" in client.config.resultReaders));
    assert.throws(() => client.resultReader("amm_init_tip"), ConfigError);
  });
});

describe("PssClient.fetchInitResult", () => {
  test("the init id is the plain chain request id of the inputs with user_nonce 0", async () => {
    const id = await initChainRequestId(NAMESPACE, VK_HASH, [LIQUIDITY]);
    assert.equal(id.toString(), (await chainRequestId(NAMESPACE, VK_HASH, await tipInputsHash([LIQUIDITY]), 0n)).toString());
  });

  test("FETCHes by the init id and splits the answer", async () => {
    const { chain, response } = await ammInitAnswer(0x77n);
    orch.on("POST", "/v1/fetch/chain", replies([response]));
    const client = new PssClient(clientConfig(url, { amm_init_tip: AMM_INIT }));
    const r = await client.fetchInitResult({ circuit: "amm_init_tip" });
    assert.deepEqual(JSON.parse(orch.received[0]!.body), { namespace: NAMESPACE, chain_request_id: chain });
    assert.equal(r.chainRequestId, chain);
    assert.deepEqual([r.parts.slots, r.parts.newCommitments, r.parts.newHashes], [[fieldHex(POOL_KEY)], [fieldHex(0x77n)], []]);
    assert.deepEqual(r.parts.stateArgs, [[], [], []]);
  });

  test("lending's init carries its new leaf hash, under the init id of its liquidity", async () => {
    const { chain, response } = await lendingInitAnswer(0x88n, 0x99n);
    orch.on("POST", "/v1/fetch/chain", replies([response]));
    const client = new PssClient(clientConfig(url, { lending_init: LENDING_INIT }));
    const r = await client.fetchInitResult({ circuit: "lending_init", inputs: [LIQUIDITY] });
    assert.equal(r.chainRequestId, chain);
    assert.deepEqual([r.parts.slots, r.parts.newHashes], [[fieldHex(MARKET_KEY)], [fieldHex(0x99n)]]);
  });

  test("refuses an answer for other inputs, an old commitment that is not 0, and 404 reaches the caller", async () => {
    const client = new PssClient(clientConfig(url, { amm_init_tip: AMM_INIT }));
    const other = await ammInitAnswer(0x77n, { inputs: [5n] });
    orch.on("POST", "/v1/fetch/chain", replies([other.response]));
    await assert.rejects(client.fetchInitResult({ circuit: "amm_init_tip" }), (e: unknown) => e instanceof ProtocolError && /the proof's request id .* is not/.test(e.message));
    const written = await ammInitAnswer(0x77n, { oldC: 0x11n });
    orch.on("POST", "/v1/fetch/chain", replies([written.response]));
    await assert.rejects(client.fetchInitResult({ circuit: "amm_init_tip" }), (e: unknown) => e instanceof ProtocolError && /old commitments are 0/.test(e.message));
    orch.on("POST", "/v1/fetch/chain", replies([{ status: 404, body: { error: "none", class: "not_found" } }]));
    await assert.rejects(client.fetchInitResult({ circuit: "amm_init_tip" }), (e: unknown) => e instanceof SidecarError && e.class === "not_found");
  });
});

describe("the init call", () => {
  test("the default encoder: init_pool(new_c, signatures), init_market(new_c, new_hashes, signatures)", async () => {
    orch.on("POST", "/v1/fetch/chain", replies([(await ammInitAnswer(0x77n)).response]));
    const amm = await new PssClient(clientConfig(url, { amm_init_tip: AMM_INIT })).fetchInitResult({ circuit: "amm_init_tip" });
    const a = defaultInitEncoder(initCallContext(amm.parts)) as [{ toBigInt(): bigint }, unknown[][]];
    assert.equal(a.length, 2);
    assert.equal(a[0].toBigInt(), 0x77n);
    assert.deepEqual(a[1].map((s) => s.length), [4, 4, 4]);

    orch.on("POST", "/v1/fetch/chain", replies([(await lendingInitAnswer(0x88n, 0x99n)).response]));
    const lending = await new PssClient(clientConfig(url, { lending_init: LENDING_INIT })).fetchInitResult({ circuit: "lending_init", inputs: [LIQUIDITY] });
    const l = defaultInitEncoder(initCallContext(lending.parts)) as [{ toBigInt(): bigint }, { toBigInt(): bigint }[], unknown[]];
    assert.equal(l.length, 3);
    assert.deepEqual([l[0].toBigInt(), l[1].map((x) => x.toBigInt())], [0x88n, [0x99n]]);

    // aztec.js encodes them as the compiled contracts' init functions take them
    const limbs = (parts: { signatures: { s: string[]; e: string[] }[] }) => parts.signatures.flatMap((s) => [...s.s, ...s.e].map(BigInt));
    const flat = (fn: string, contract: "AmmTip" | "LendingTip", args: unknown[]) => encodeArguments(contractAbis(contract).functions[fn]!, args).map((f) => f.toBigInt());
    assert.deepEqual(flat("init_pool", "AmmTip", a), [0x77n, ...limbs(amm.parts)]);
    assert.deepEqual(flat("init_market", "LendingTip", l), [0x88n, 0x99n, ...limbs(lending.parts)]);
  });
});

describe("Lander.attemptInit", () => {
  const lander = (contract: ResultContract) =>
    new Lander({
      client: new PssClient(clientConfig(url, { amm_init_tip: AMM_INIT })),
      calls: { contract, address: NAMESPACE, from: SENDER, vkFields: { amm_init_tip: VK_FIELDS } },
      policy: { sendsPerResult: 2, transactions: Infinity, refetchDelayMs: 0 },
    });

  test("an empty slot: the app's init function, paid through wFJ as a result", async () => {
    orch.on("POST", "/v1/fetch/chain", replies([(await ammInitAnswer(0x77n)).response]));
    const { contract, calls } = recordingContract(0);
    const seen: string[][] = [];
    const a = await lander(contract).attemptInit({ circuit: "amm_init_tip", method: "init_pool", written: async (slots) => (seen.push([...slots]), false) });
    assert.equal(a.status, "landed");
    assert.deepEqual(seen, [[fieldHex(POOL_KEY)]]);
    assert.deepEqual(calls.map((c) => [c.method, c.args.length]), [["init_pool", 2]]);
    assert.equal((await calls[0]!.options.fee!.paymentMethod!.getFeePayer()).toString(), WFJ.address);
  });

  test("a written slot: nothing sent", async () => {
    orch.on("POST", "/v1/fetch/chain", replies([(await ammInitAnswer(0x77n)).response]));
    const { contract, calls } = recordingContract(0);
    const a = await lander(contract).attemptInit({ circuit: "amm_init_tip", method: "init_pool", written: async () => true });
    assert.equal(a.status, "written");
    assert.equal(calls.length, 0);
  });

  test("the same failing init is sent at most sendsPerResult times, then held", async () => {
    orch.on("POST", "/v1/fetch/chain", replies([(await ammInitAnswer(0x77n)).response]));
    const { contract, calls } = recordingContract(100);
    const l = lander(contract);
    const init = { circuit: "amm_init_tip", method: "init_pool", written: async () => false };
    const statuses = [];
    for (let i = 0; i < 3; i++) statuses.push((await l.attemptInit(init)).status);
    assert.deepEqual(statuses, ["failed", "failed", "held"]);
    assert.equal(calls.length, 2);
  });

  test("the init backs off after identical send failures and lands when the node recovers", async () => {
    orch.on("POST", "/v1/fetch/chain", replies([(await ammInitAnswer(0x77n)).response]));
    const { contract, calls } = recordingContract(2, "fetch failed");
    const l = lander(contract);
    const init = { circuit: "amm_init_tip", method: "init_pool", written: async () => false };
    const attempts = [];
    for (let i = 0; i < 4; i++) attempts.push(await l.attemptInit(init));
    assert.deepEqual(attempts.map((a) => a.status), ["failed", "backoff", "backoff", "landed"]);
    assert.deepEqual(attempts.map((a) => ("failures" in a ? a.failures : undefined)), [0, 2, 2, undefined]);
    assert.equal(calls.length, 3);
  });
});
