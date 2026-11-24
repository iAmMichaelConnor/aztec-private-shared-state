// The relayer's loop (src/relayer.ts) against a mock orchestrator (HTTP), an
// in-memory queue and a recording contract: the stale period from the tip
// manifests, skip() exactly when the head is stale and the queue is not
// empty, landing the head's latest result, re-fetching after a revert, the
// hold after repeated reverts, backoff after identical send failures,
// waiting on 404 and 409, a failing tick
// recorded for /status, a secret-shared intake's private outcome through the
// result function named for its circuit, held results sent again once the
// chain goes back, and the init round: landed through the app's init
// function before anything is queued, not again while its slot is written,
// and again when a replaced block empties it; and the contracts the PXE
// registers.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { after, before, beforeEach, describe, test } from "node:test";

import {
  PssClient,
  ResultSignatureError,
  resultFunctions,
  WFJ,
  fieldHex,
  type CircuitPackage,
  type QueueReader,
  type QueueSnapshot,
  type ResultContract,
} from "@aztec-pss/pss-client";

import {
  AMM_INIT,
  AMM_PARTIAL_NOTE,
  AMM_SWAP,
  AMM_SWAP_RECEIPT,
  ammInitAnswer,
  ammSwapAnswer,
  clientConfig,
  depositSharedAnswer,
  FakeQueue,
  fixture,
  LENDING_DEPOSIT_SHARED,
  MockOrchestrator,
  NAMESPACE,
  recordingContract,
  replies,
  VK_FIELDS,
} from "@aztec-pss/test-support";
import { registerContracts, relayerAccount, relayerFeeSetting, relayerResultFunction } from "../src/aztec.ts";
import { MAX_SKIP_BACKOFF_TICKS, Relayer, shouldSkip, staleBlocksOfClient } from "../src/relayer.ts";

/** examples/lending-tip's deposit round: ROUND_DEPOSIT through process_shared. */
const ROUND_DEPOSIT = 1;
const DEPOSIT_SHARED = { name: "process_shared", args: [ROUND_DEPOSIT] };

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


function relayer(queue: QueueReader, contract: ResultContract, opts: { skips?: number[] } = {}) {
  const skips = opts.skips ?? [];
  return new Relayer({
    client: new PssClient(clientConfig(url, { amm_swap_tip: AMM_SWAP })),
    queue,
    calls: { contract, address: NAMESPACE, from: SENDER, vkFields: { amm_swap_tip: VK_FIELDS } },
    skip: async () => {
      skips.push((await queue.snapshot()).head);
      return "skipped";
    },
  });
}

describe("the skip rule", () => {
  const s = (o: Partial<QueueSnapshot>): QueueSnapshot => ({ block: 100, blockHash: "0x64", head: 0, headSince: 50, tail: 1, ...o });
  test("stale and non-empty: skip, from head_since + stale_blocks on", () => {
    assert.equal(shouldSkip(s({ block: 100, headSince: 50 }), 50), true);
    assert.equal(shouldSkip(s({ block: 101, headSince: 50 }), 50), true);
    assert.equal(shouldSkip(s({ block: 99, headSince: 50 }), 50), false);
  });
  test("never for an empty queue, never with skipping disabled", () => {
    assert.equal(shouldSkip(s({ head: 1, tail: 1, block: 1000 }), 50), false);
    assert.equal(shouldSkip(s({ block: 1000 }), null), false);
    assert.equal(shouldSkip(s({ block: 50, headSince: 50 }), 0), true);
  });
});

describe("the stale period", () => {
  const json = (p: string) => JSON.parse(readFileSync(new URL(p, import.meta.url), "utf8")) as unknown;
  const DIRECT = { circuit: fixture("amm_swap.abi.json"), manifest: json("../../../examples/amm/manifests/amm_swap.json") };
  const of = (circuits: Record<string, CircuitPackage>, staleBlocks?: number | null) =>
    staleBlocksOfClient(new PssClient({ ...clientConfig("http://127.0.0.1:1", circuits), staleBlocks }).config);
  test("is the configuration's staleBlocks (the contract manifest's), or null where skipping is disabled", () => {
    assert.equal(of({ amm_swap_tip: AMM_SWAP, amm_swap_tip_receipt: { ...AMM_SWAP_RECEIPT, aliasOf: "amm_swap_tip" } }, 50), 50);
    // a sidecar-path circuit beside a tip circuit changes nothing
    assert.equal(of({ amm_swap: DIRECT, amm_swap_tip: AMM_SWAP }, 7), 7);
    assert.equal(of({ amm_swap_tip: AMM_SWAP }, null), null);
  });
  test("refuses a configuration without staleBlocks, or without a tip circuit", () => {
    assert.throws(() => of({ amm_swap_tip: AMM_SWAP }), /staleBlocks: missing/);
    assert.throws(() => of({ amm_swap: DIRECT }, 50), /no tip circuit/);
  });
  test("the relayer skips at the contract manifest's period, not before", async () => {
    const { request } = await ammSwapAnswer(0x0cn, 0x1cn);
    orch.on("POST", "/v1/fetch/chain", replies([{ status: 404, body: { error: "no attempt at this chain request", class: "not_found" } }]));
    const q = new FakeQueue();
    q.requests = [request.chainRequestId];
    q.headSince = 50;
    q.block = 99;
    const skips: number[] = [];
    const { contract } = recordingContract(0);
    const r = new Relayer({
      client: new PssClient(clientConfig(url, { amm_swap_tip: AMM_SWAP }, 60)),
      queue: q,
      calls: { contract, address: NAMESPACE, from: SENDER, vkFields: { amm_swap_tip: VK_FIELDS } },
      skip: async () => (skips.push(q.head), "skipped"),
    });
    assert.equal(r.staleBlocks, 60);
    q.block = 100;
    assert.notEqual((await r.tick()).action, "skipped");
    q.block = 110;
    assert.equal((await r.tick()).action, "skipped");
    assert.deepEqual(skips, [0]);
  });
});

describe("Relayer.tick", () => {
  test("an empty queue: idle, no FETCH, no skip, even long after head_since", async () => {
    const q = new FakeQueue();
    q.block = 10_000;
    const skips: number[] = [];
    const { contract, calls } = recordingContract(0);
    const out = await relayer(q, contract, { skips }).tick();
    assert.equal(out.action, "idle");
    assert.deepEqual(skips, []);
    assert.equal(calls.length, 0);
    assert.equal(orch.received.length, 0);
  });

  test("a stale head: skip(), and no result is sent for it", async () => {
    const { request, response } = await ammSwapAnswer(0x0cn, 0x1cn);
    orch.on("POST", "/v1/fetch/chain", replies([response]));
    const q = new FakeQueue();
    q.requests = [request.chainRequestId];
    q.headSince = 50;
    q.block = 100;
    const skips: number[] = [];
    const { contract, calls } = recordingContract(0);
    const out = await relayer(q, contract, { skips }).tick();
    assert.equal(out.action, "skipped");
    assert.deepEqual(skips, [0]);
    assert.equal(calls.length, 0);
    assert.equal(orch.received.length, 0);
  });

  test("a failing skip() is sent again after a backoff that doubles up to its cap", async () => {
    const q = new FakeQueue();
    q.requests = [fieldHex(0x5c1fn)];
    q.headSince = 50;
    q.block = 100;
    const { contract } = recordingContract(0);
    const sends: number[] = [];
    let tick = 0;
    let fail = true;
    const r = new Relayer({
      client: new PssClient(clientConfig(url, { amm_swap_tip: AMM_SWAP })),
      queue: q,
      calls: { contract, address: NAMESPACE, from: SENDER, vkFields: { amm_swap_tip: VK_FIELDS } },
      skip: async () => {
        sends.push(tick);
        if (fail) throw new Error("dropped");
        q.head++;
        return "skipped";
      },
    });
    const actions: string[] = [];
    for (; tick < 200; tick++) actions.push((await r.tick()).action);
    // a send, then 1, 2, 4, ... 32 ticks between sends, never more
    const gaps = sends.slice(1).map((t, k) => t - sends[k]! - 1);
    assert.deepEqual(gaps.slice(0, 7), [1, 2, 4, 8, 16, 32, 32]);
    assert.ok(gaps.every((g) => g <= MAX_SKIP_BACKOFF_TICKS));
    assert.deepEqual(new Set(actions), new Set(["skip-failed", "waiting"]));
    assert.equal(orch.received.length, 0);
    // once it lands the queue is empty; a later stale head starts from a send at once
    fail = false;
    while (actions.at(-1) !== "skipped") {
      actions.push((await r.tick()).action);
      tick++;
    }
    q.requests.push(fieldHex(0x5c2fn));
    assert.equal((await r.tick()).action, "skipped");
  });

  test("a fresh head with a result: process_result with the request's inputs; no skip", async () => {
    const { request, response } = await ammSwapAnswer(0x0cn, 0x1cn);
    orch.on("POST", "/v1/fetch/chain", replies([response]));
    const q = new FakeQueue();
    q.requests = [request.chainRequestId];
    const skips: number[] = [];
    const { contract, calls } = recordingContract(0);
    const out = await relayer(q, contract, { skips }).tick();
    assert.equal(out.action, "landed");
    assert.deepEqual(skips, []);
    assert.equal(calls.length, 1);
    assert.equal(calls[0]!.method, "process_result");
    assert.equal((await calls[0]!.options.fee!.paymentMethod!.getFeePayer()).toString(), WFJ.address, "the result pays through wFJ by default");
    assert.deepEqual(JSON.parse(orch.received[0]!.body), { namespace: NAMESPACE, chain_request_id: request.chainRequestId });
  });

  test("404 and 409: waiting, nothing sent", async () => {
    orch.on("POST", "/v1/fetch/chain", replies([
      { status: 404, body: { error: "none", class: "not_found" } },
      { status: 409, body: { error: "rolled back", class: "conflict" } },
    ]));
    const q = new FakeQueue();
    q.requests = [fieldHex(0xa1n)];
    const { contract, calls } = recordingContract(0);
    const r = relayer(q, contract);
    assert.deepEqual([(await r.tick()).action, (await r.tick()).action], ["waiting", "waiting"]);
    assert.equal(calls.length, 0);
  });

  test("a tick that throws is recorded as the last outcome (what GET /status serves)", async () => {
    const { request, response } = await ammSwapAnswer(0x0cn, 0x1cn);
    const bad = structuredClone(response);
    bad.signatures[1]!.s[0] = fieldHex(BigInt(bad.signatures[1]!.s[0]) ^ 1n);
    orch.on("POST", "/v1/fetch/chain", replies([bad]));
    const q = new FakeQueue();
    q.requests = [request.chainRequestId];
    const { contract, calls } = recordingContract(0);
    const r = relayer(q, contract);
    await assert.rejects(r.tick(), ResultSignatureError);
    assert.equal(r.last?.action, "error");
    assert.ok(r.last?.action === "error" && r.last.error instanceof ResultSignatureError);
    assert.equal(calls.length, 0);
  });

  test("a secret-shared intake's head lands its private outcome through the function named for its circuit", async () => {
    const id = fieldHex(0x1dn);
    orch.on("POST", "/v1/fetch/chain", replies([await depositSharedAnswer(id, 0x0cn, 0x1cn)]));
    const q = new FakeQueue();
    q.requests = [id];
    const { contract, calls } = recordingContract(0);
    const r = new Relayer({
      client: new PssClient(clientConfig(url, { deposit_shared: LENDING_DEPOSIT_SHARED })),
      queue: q,
      calls: { contract, address: NAMESPACE, from: SENDER, vkFields: { deposit_shared: VK_FIELDS }, resultFunction: resultFunctions({ deposit_shared: DEPOSIT_SHARED }) },
      skip: async () => "skipped",
    });
    const out = await r.tick();
    assert.equal(out.action, "landed");
    assert.ok(out.action === "landed" && out.result.form === "outcome");
    // [round, result, new_hashes, values, signatures]: the round's index, the
    // book's two new leaf hashes and the round's app values, no sealed thirds
    assert.deepEqual(calls.map((c) => [c.method, c.args.length, c.args[0]]), [["process_shared", 6, ROUND_DEPOSIT]]);
  });

  test("resultFunctions: a listed circuit's function, process_result for the others", () => {
    const fn = resultFunctions({ deposit_shared: DEPOSIT_SHARED });
    assert.deepEqual(fn({ circuit: "deposit_shared" } as never), DEPOSIT_SHARED);
    assert.deepEqual(fn({ circuit: "amm_swap_tip" } as never), { name: "process_result" });
    assert.deepEqual(fn({ circuit: "toString" } as never), { name: "process_result" });
  });

  test("the configuration's methods name client circuits and the artifact's functions", () => {
    const cfg = {
      client: clientConfig(url, { deposit_shared: LENDING_DEPOSIT_SHARED }),
      contract: { address: NAMESPACE, artifact: { name: "LendingTip", functions: [{ name: "process_shared" }] } as never },
    };
    assert.equal(relayerResultFunction(cfg), undefined);
    assert.deepEqual(relayerResultFunction({ ...cfg, methods: { deposit_shared: DEPOSIT_SHARED } })!({ circuit: "deposit_shared" } as never), DEPOSIT_SHARED);
    assert.throws(() => relayerResultFunction({ ...cfg, methods: { borrow_shared: DEPOSIT_SHARED } }), /methods.borrow_shared: not a circuit/);
    assert.throws(() => relayerResultFunction({ ...cfg, methods: { deposit_shared: { name: "process_header_shared" } } }), /LendingTip has no function process_header_shared/);
    assert.throws(() => relayerResultFunction({ ...cfg, methods: { deposit_shared: "process_shared" as never } }), /\{ name, args\? \}/);
    assert.throws(() => relayerResultFunction({ ...cfg, methods: {}, resultFunction: () => ({ name: "x" }) }), /not both/);
  });

  test("after a revert it re-fetches and sends the newer attempt at once", async () => {
    const first = await ammSwapAnswer(0x0cn, 0x1cn);
    const second = await ammSwapAnswer(0x0dn, 0x1dn, { salt: 2 });
    orch.on("POST", "/v1/fetch/chain", replies([first.response, second.response]));
    const q = new FakeQueue();
    q.requests = [first.request.chainRequestId];
    const { contract, calls } = recordingContract(1);
    const r = relayer(q, contract);
    assert.equal((await r.tick()).action, "submit-failed");
    const out = await r.tick();
    assert.equal(out.action, "landed");
    assert.equal(orch.count("POST", "/v1/fetch/chain"), 2);
    assert.equal(calls.length, 2);
    // the PartialResult: the trader's partial note, then the TipResult
    const round = calls[1]!.args[0] as { partial_note: { toBigInt(): bigint }; result: { old_commitments: { toBigInt(): bigint }[] } };
    assert.equal(round.partial_note.toBigInt(), AMM_PARTIAL_NOTE);
    assert.equal(round.result.old_commitments[0]!.toBigInt(), 0x0dn);
  });

  test("the same failing result is sent at most twice, then the relayer waits; the stale head is skipped", async () => {
    const first = await ammSwapAnswer(0x0cn, 0x1cn);
    orch.on("POST", "/v1/fetch/chain", replies([first.response]));
    const q = new FakeQueue();
    q.requests = [first.request.chainRequestId];
    const skips: number[] = [];
    const { contract, calls } = recordingContract(100);
    const r = relayer(q, contract, { skips });
    const actions = [];
    for (let i = 0; i < 4; i++) actions.push((await r.tick()).action);
    assert.deepEqual(actions, ["submit-failed", "submit-failed", "waiting", "waiting"]);
    assert.equal(calls.length, 2);
    q.block = q.headSince + 50;
    assert.equal((await r.tick()).action, "skipped");
    assert.deepEqual(skips, [0]);
  });

  test("held results are sent again once the chain goes back (a replaced block)", async () => {
    const first = await ammSwapAnswer(0x0cn, 0x1cn);
    orch.on("POST", "/v1/fetch/chain", replies([first.response]));
    const q = new FakeQueue();
    q.requests = [first.request.chainRequestId];
    const { contract, calls } = recordingContract(2);
    const r = relayer(q, contract);
    const actions = [];
    for (let i = 0; i < 3; i++) actions.push((await r.tick()).action);
    assert.deepEqual(actions, ["submit-failed", "submit-failed", "waiting"]);
    // the queue is read at a lower block: the result is sent again, and lands
    q.block -= 2;
    assert.equal((await r.tick()).action, "landed");
    assert.equal(calls.length, 3);
  });

  test("a same-height block replacement releases a held result", async () => {
    const first = await ammSwapAnswer(0x0cn, 0x1cn);
    orch.on("POST", "/v1/fetch/chain", replies([first.response]));
    const q = new FakeQueue();
    q.requests = [first.request.chainRequestId];
    const { contract, calls } = recordingContract(2);
    const r = relayer(q, contract);
    for (let i = 0; i < 2; i++) assert.equal((await r.tick()).action, "submit-failed");
    const held = await r.tick();
    assert.equal(held.action, "waiting");
    q.fork++;
    const landed = await r.tick();
    assert.equal(landed.action, "landed");
    assert.equal(landed.snapshot.block, held.snapshot.block);
    assert.equal(landed.snapshot.head, held.snapshot.head);
    assert.notEqual(landed.snapshot.blockHash, held.snapshot.blockHash);
    assert.equal(calls.length, 3);
  });

  test("identical send failures report backoff and the relayer keeps retrying", async () => {
    const first = await ammSwapAnswer(0x0cn, 0x1cn);
    orch.on("POST", "/v1/fetch/chain", replies([first.response]));
    const q = new FakeQueue();
    q.requests = [first.request.chainRequestId];
    const message = "the configured account cannot pay the fee";
    const { contract, calls } = recordingContract(3, message);
    const r = relayer(q, contract);
    assert.equal((await r.tick()).action, "submit-failed");
    const checkBackoff = async (failures: number, retryInTicks: number, sends: number) => {
      const outcome = await r.tick();
      assert.equal(outcome.action, "submit-backoff");
      assert.equal(outcome.failures, failures);
      assert.equal(outcome.retryInTicks, retryInTicks);
      assert.equal((outcome.error as Error).message, message);
      assert.equal(r.last, outcome);
      assert.equal(calls.length, sends);
    };
    await checkBackoff(2, 2, 2);
    await checkBackoff(2, 1, 2);
    await checkBackoff(3, 3, 3);
    await checkBackoff(3, 2, 3);
    await checkBackoff(3, 1, 3);
    assert.equal((await r.tick()).action, "landed");
    assert.equal(calls.length, 4);
  });

  test("a poll interval below 1 ms or not whole is refused, so the loop never spins", () => {
    const { contract } = recordingContract(0);
    for (const pollIntervalMs of [0, -5, 1.5, NaN]) {
      assert.throws(
        () => new Relayer({ client: new PssClient(clientConfig(url, { amm_swap_tip: AMM_SWAP })), queue: new FakeQueue(), calls: { contract, address: NAMESPACE, from: SENDER, vkFields: {} }, skip: async () => undefined, pollIntervalMs }),
        /pollIntervalMs: a whole number of ms, at least 1/,
      );
    }
  });

  test("start() ticks until stop()", async () => {
    const q = new FakeQueue();
    let ticks = 0;
    const counting: QueueReader = { ...q, blockNumber: () => q.blockNumber(), requestAt: (i) => q.requestAt(i), doneAt: (i) => q.doneAt(i), snapshot: async () => (ticks++, q.snapshot()) };
    const { contract } = recordingContract(0);
    const r = new Relayer({
      client: new PssClient(clientConfig(url, { amm_swap_tip: AMM_SWAP })),
      queue: counting,
      calls: { contract, address: NAMESPACE, from: SENDER, vkFields: {} },
      skip: async () => undefined,
      pollIntervalMs: 5,
    });
    r.start();
    await new Promise((res) => setTimeout(res, 60));
    await r.stop();
    const seen = ticks;
    assert.ok(seen >= 2, `ticked ${seen} times`);
    await new Promise((res) => setTimeout(res, 20));
    assert.equal(ticks, seen);
  });
});

describe("the init round", () => {
  function initRelayer(q: FakeQueue, contract: ResultContract, slot: { value: bigint }) {
    return new Relayer({
      client: new PssClient(clientConfig(url, { amm_init_tip: AMM_INIT, amm_swap_tip: AMM_SWAP })),
      queue: q,
      calls: { contract, address: NAMESPACE, from: SENDER, vkFields: { amm_init_tip: VK_FIELDS, amm_swap_tip: VK_FIELDS } },
      skip: async () => "skipped",
      init: { circuit: "amm_init_tip", method: "init_pool", written: async () => slot.value !== 0n },
    });
  }

  test("waits for the scheduler's result, lands it through init_pool once, then relays the queue", async () => {
    const { chain, response } = await ammInitAnswer(0x77n);
    orch.on("POST", "/v1/fetch/chain", replies([{ status: 404, body: { error: "none", class: "not_found" } }, response]));
    const q = new FakeQueue();
    const slot = { value: 0n };
    const { contract, calls } = recordingContract(0);
    const r = initRelayer(q, contract, slot);
    assert.deepEqual(r.initStatus, { state: "pending" });
    const first = await r.tick();
    assert.equal(first.action, "waiting");
    assert.match((first as { reason: string }).reason, /no init result yet/);
    assert.equal((await r.tick()).action, "init-landed");
    assert.deepEqual(JSON.parse(orch.received[1]!.body), { namespace: NAMESPACE, chain_request_id: chain });
    assert.deepEqual(calls.map((c) => [c.method, c.args.length]), [["init_pool", 2]]);
    assert.equal((await calls[0]!.options.fee!.paymentMethod!.getFeePayer()).toString(), WFJ.address, "the init pays through wFJ");
    assert.deepEqual(r.initStatus, { state: "landed", tx: "0xabc" });
    slot.value = 0x77n;
    // landed: no more init FETCH, the empty queue is idle
    assert.equal((await r.tick()).action, "idle");
    assert.equal(orch.count("POST", "/v1/fetch/chain"), 2);
    assert.equal(calls.length, 1);
  });

  test("a landed init that a replaced block takes back is landed again, without a restart", async () => {
    const { response } = await ammInitAnswer(0x77n);
    orch.on("POST", "/v1/fetch/chain", replies([response]));
    const q = new FakeQueue();
    const slot = { value: 0n };
    const { contract, calls } = recordingContract(0);
    const r = initRelayer(q, contract, slot);
    assert.equal((await r.tick()).action, "init-landed");
    slot.value = 0x77n;
    assert.equal((await r.tick()).action, "idle");
    // the block holding apply_init is replaced, and the pool did not mine
    // the init again: the slot is empty and nothing is queued
    slot.value = 0n;
    assert.equal((await r.tick()).action, "init-landed");
    assert.deepEqual(calls.map((c) => c.method), ["init_pool", "init_pool"]);
    slot.value = 0x77n;
    assert.equal((await r.tick()).action, "idle");
    assert.equal(calls.length, 2);
  });

  test("a slot already written: nothing sent (a restarted relayer, or anyone landed it)", async () => {
    orch.on("POST", "/v1/fetch/chain", replies([(await ammInitAnswer(0x77n)).response]));
    const { contract, calls } = recordingContract(0);
    const r = initRelayer(new FakeQueue(), contract, { value: 0x77n });
    assert.equal((await r.tick()).action, "idle");
    assert.deepEqual(r.initStatus, { state: "written" });
    assert.equal((await r.tick()).action, "idle");
    assert.equal(calls.length, 0);
    assert.equal(orch.count("POST", "/v1/fetch/chain"), 1);
  });

  test("a queue that ever held a request: the init landed, no init FETCH", async () => {
    const { request, response } = await ammSwapAnswer(0x0cn, 0x1cn);
    orch.on("POST", "/v1/fetch/chain", replies([response]));
    const q = new FakeQueue();
    q.requests = [request.chainRequestId];
    const { contract, calls } = recordingContract(0);
    const r = initRelayer(q, contract, { value: 0n });
    assert.equal((await r.tick()).action, "landed");
    assert.deepEqual(r.initStatus, { state: "written" });
    assert.deepEqual(calls.map((c) => c.method), ["process_result"]);
  });

  test("a failing init is re-sent under the result rule, then held", async () => {
    orch.on("POST", "/v1/fetch/chain", replies([(await ammInitAnswer(0x77n)).response]));
    const { contract, calls } = recordingContract(100);
    const r = initRelayer(new FakeQueue(), contract, { value: 0n });
    const actions = [];
    for (let i = 0; i < 3; i++) actions.push((await r.tick()).action);
    assert.deepEqual(actions, ["init-failed", "init-failed", "waiting"]);
    assert.equal(calls.length, 2);
    assert.deepEqual(r.initStatus, { state: "pending" });
  });
});

describe("the relayer's fee setting", () => {
  const from = { toString: () => "0x01" } as never;
  test("wfj checks the node's version before it registers anything", async () => {
    const node = { getNodeInfo: async () => ({ nodeVersion: "5.0.1" }) } as never;
    await assert.rejects(relayerFeeSetting({ method: "wfj" }, {} as never, node, from), /the node runs Aztec 5\.0\.1, wFJ is pinned at .* for Aztec 6\.0\.0/);
  });
  test("account carries the gas; a function builds its setting in the wallet", async () => {
    const gas = { result: { gasLimits: { daGas: 1, l2Gas: 2 } } };
    assert.deepEqual(await relayerFeeSetting({ method: "account", gas }, {} as never, {} as never, from), { method: "account", gas });
    const wallet = { name: "relayer wallet" } as never;
    const built = await relayerFeeSetting(async (w) => ({ method: "account", gas: w === wallet ? gas : undefined }), wallet, {} as never, from);
    assert.deepEqual(built, { method: "account", gas });
  });
});

describe("the relayer's account", () => {
  test("has no default: a missing or partial account is refused, the local network's only when named", () => {
    for (const bad of [undefined, {}, { secretKey: 1 }]) assert.throws(() => relayerAccount(bad as never), /account: .*"local-network"/);
    assert.equal(relayerAccount("local-network"), "local-network");
    const parsed = relayerAccount({ secretKey: 1n, signingKey: 2n });
    assert.ok(parsed !== "local-network");
    assert.deepEqual([parsed.secretKey.toBigInt(), parsed.signingKey.toBigInt(), parsed.salt.toBigInt()], [1n, 2n, 0n]);
  });

  test("reads the three keys by one rule: an un-prefixed string is hex for each, the signing key a Grumpkin scalar", () => {
    const k = relayerAccount({ secretKey: "1234", signingKey: "1234", salt: "0x1234" });
    assert.ok(k !== "local-network");
    assert.deepEqual([k.secretKey.toBigInt(), k.signingKey.toBigInt(), k.salt.toBigInt()], [0x1234n, 0x1234n, 0x1234n]);
    // above the BN254 scalar field, below the Grumpkin scalar field
    const big = 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd46n;
    const b = relayerAccount({ secretKey: 1n, signingKey: "0x" + big.toString(16) });
    assert.ok(b !== "local-network");
    assert.equal(b.signingKey.toBigInt(), big);
  });

  test("a refused key never appears in the error or its stack", () => {
    const secret = "1a2b3c4d5e6f7a8b9c0d";
    for (const [account, why] of [
      [{ secretKey: 1n, signingKey: secret + "q" }, /^account\.signingKey: not a 1 to 64 digit hex number$/],
      [{ secretKey: 1n, signingKey: "f".repeat(44) + secret }, /^account\.signingKey: not below the Grumpkin scalar field modulus$/],
      [{ secretKey: "f".repeat(44) + secret, signingKey: 1n }, /^account\.secretKey: not below the bn254 scalar field modulus$/],
      [{ secretKey: 1n, signingKey: 2n, salt: "0x" + secret + "g" }, /^account\.salt: /],
    ] as const) {
      assert.throws(() => relayerAccount(account as never), (e: unknown) => e instanceof RangeError && why.test(e.message) && !String(e.stack).includes(secret));
    }
  });
});

describe("the contracts the PXE registers", () => {
  const APP = "0x" + "0a".repeat(32);
  const OTHER = "0x" + "0c".repeat(32);
  const artifact = (name: string) => ({ name }) as never;
  /** A node holding an instance at each of `held`, and a wallet recording what it registers. */
  const fakes = (held: string[]) => {
    const registered: [string, string][] = [];
    const node = { getContract: async (a: { toString(): string }) => (held.includes(a.toString()) ? ({ address: a.toString() } as never) : undefined) };
    const wallet = { registerContract: async (instance: { address: string }, a: { name: string }) => void registered.push([instance.address, a.name]) } as never;
    return { node, wallet, registered };
  };

  // the relayer registers its app contract; an enc-key rotation each
  // secret-shared on-chain intake contract it names (rotate-enc-key.ts)
  test("each contract, in order, under the node's instances", async () => {
    const { node, wallet, registered } = fakes([APP, OTHER]);
    const addresses = await registerContracts(wallet, node, [
      { address: APP, artifact: artifact("AmmTip") },
      { address: BigInt(OTHER), artifact: artifact("LendingTip") },
    ]);
    assert.deepEqual(addresses.map(String), [APP, OTHER]);
    assert.deepEqual(registered, [[APP, "AmmTip"], [OTHER, "LendingTip"]]);
  });

  test("refuses a contract the node holds no instance of, naming it", async () => {
    const { node, wallet } = fakes([APP]);
    await assert.rejects(
      registerContracts(wallet, node, [{ address: APP, artifact: artifact("AmmTip") }, { address: OTHER, artifact: artifact("LendingTip") }]),
      new RegExp(`no contract at ${OTHER} on the node \\(the configuration's LendingTip\\)`),
    );
  });
});
