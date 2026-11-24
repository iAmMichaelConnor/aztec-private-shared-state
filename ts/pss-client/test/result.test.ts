// The tip's result functions (src/tip-result.ts, src/lander.ts, src/outcome.ts, src/queue.ts
// and PssClient.fetchChainResult): FETCH by chain request id against a mock
// orchestrator and the latest-row rule, the refusals of the result checks, the
// arguments of process_result against the compiled contracts' ABIs, the
// capsule, submitResult's re-fetch after a revert, pollResult on an applied and
// a skipped request, and the queue's storage
// slots and logs; and a secret-shared intake's private outcome read and landed
// (its result reader, fetchChainResult, Lander.attempt, submitResult) under
// the round's own method.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { after, before, beforeEach, describe, test } from "node:test";

import { FPCFeePaymentMethod } from "@alejoamiras/private-fee-juice/fee-payment-methods";
import { AztecAddress } from "@aztec-labs/aztec.js/addresses";
import { Fr } from "@aztec-labs/foundation/curves/bn254";
import { encodeArguments } from "@aztec-labs/stdlib/abi";
import type { BlockParameter } from "@aztec-labs/stdlib/block";
import type { Tag } from "@aztec-labs/stdlib/logs";

import {
  CAPSULE_SLOT_PROOF,
  DONE_APPLIED,
  DONE_PENDING,
  DONE_SKIPPED,
  Lander,
  NodeQueueReader,
  ProtocolError,
  ProvedInputs,
  PssClient,
  QueueSlots,
  ResultSignatureError,
  SidecarError,
  SubmitResultError,
  computeRequestLogTag,
  computeSealedLogTag,
  fieldHex,
  intakeModule,
  isRevert,
  machineRequestId,
  outcomeResultArgs,
  outcomeResultParts,
  outcomeShape,
  parseManifest,
  parseSealedLog,
  pollResult,
  prepareResult,
  privateOutcomes,
  publicResults,
  queueBaseSlot,
  readRequestLog,
  resultKey,
  intakeLayout,
  stateModule,
  tipStateOf,
  resultSummary,
  submitResult,
  tipResultLayout,
  wfjAddress,
  type ChainResult,
  type LogNode,
  type QueuedManifest,
  type QueuedResult,
  type ResultCallSettings,
  type ResultContract,
} from "../src/internal.ts";
import {
  AMM_PARTIAL_NOTE,
  AMM_SWAP,
  AMM_SWAP_HELD,
  AMM_SWAP_RECEIPT,
  blockHashOf,
  ammAnswer,
  ammSwapAnswer,
  clientConfig,
  contractAbis,
  depositAnswer,
  depositSharedAnswer,
  FakeQueue,
  hex,
  keyId,
  LENDING_DEPOSIT,
  LENDING_DEPOSIT_SHARED,
  MockOrchestrator,
  NAMESPACE,
  queued,
  recordingContract,
  replies,
  sharedRound,
  sharedRoundAnswer,
  TEST_PLAIN,
  testPlainAnswer,
  THIRD_FIELDS,
  VK_FIELDS,
  VK_HASH,
} from "@aztec-pss/test-support";

const SENDER = "0x00000000000000000000000000000000000000000000000000000000000c0ffe";

// examples/lending-tip's result functions (app.nr's ROUND_* indices): the
// owner-bound rounds and the liquidation through process_shared, the scan
// and the quote through process_header_shared
const ROUNDS = { deposit: 1, borrow: 2, repay: 3, view: 4, liquidate: 5, scan: 6, withdraw: 7, supply: 8, withdraw_supply: 9, quote: 10 } as const;
const ROUND_DEPOSIT = ROUNDS.deposit;
const DEPOSIT_SHARED = { name: "process_shared", args: [ROUND_DEPOSIT] };

/** The result call of `r` from SENDER under VK_FIELDS (prepareResult). */
const resultCall = (r: QueuedResult, over: Partial<ResultCallSettings> = {}) =>
  prepareResult(r, { contract: { methods: {} }, address: NAMESPACE, from: SENDER, vkFields: { [r.circuit]: VK_FIELDS }, ...over });

let orch: MockOrchestrator;
let url: string;
before(async () => {
  orch = new MockOrchestrator();
  url = await orch.start();
});
after(async () => orch.stop());
beforeEach(() => {
  orch.routes.clear();
  orch.prefixes.clear();
  orch.received.length = 0;
});


// ---- the layouts ----

describe("the result layout", () => {
  test("the AMM swap circuit follows the library's layout under both non-secret-shared intakes", () => {
    const plain = tipResultLayout(AMM_SWAP.circuit, queued(AMM_SWAP.manifest));
    assert.deepEqual(
      { id: plain.requestId, old: plain.oldCommitments, new: plain.newCommitments, npk: plain.npkAppHash, ok: plain.ok, partial: plain.partialNote, out: plain.appOutputs, reads: plain.reads },
      { id: 4, old: [5], new: [6], npk: 7, ok: 8, partial: 9, out: [10, 11], reads: [] },
    );
    assert.deepEqual([plain.state, plain.records], ["chain", [0]]);
    // the same compiled circuit under the receipt-intake manifest: the same layout
    const receipt = tipResultLayout(AMM_SWAP_RECEIPT.circuit, queued(AMM_SWAP_RECEIPT.manifest));
    assert.deepEqual({ ...receipt, circuit: plain.circuit }, plain);
    const t = tipResultLayout(TEST_PLAIN.circuit, queued(TEST_PLAIN.manifest));
    assert.deepEqual([t.requestId, t.reads, t.oldCommitments, t.appOutputs], [5, [4], [6], [10, 11]]);
  });

  test("a round writing a node-held and a chain-held key checks the record against its own output's commitment", async () => {
    const m = queued(AMM_SWAP.manifest);
    const chainHeld = m.outputs[0]!;
    // output 0 under a key the manifest leaves node-held, output 1 chain-held
    const mixed: QueuedManifest = { ...m, outputs: [{ ...chainHeld, STORE: "$state_keys.writes[1]" }, chainHeld] };
    assert.equal(tipStateOf(mixed), "chain");
    assert.deepEqual(stateModule("chain").records(mixed), [1]);
    // the swap's answer as a two-output round: new commitments at public
    // inputs 5 (the node-held output) and 6 (the chain-held one, which the
    // record is sealed under)
    const { request, response } = await ammSwapAnswer(0x0cn, 0x1cn);
    const plain = tipResultLayout(AMM_SWAP.circuit, queued(AMM_SWAP.manifest));
    const layout = { ...plain, newCommitments: [5, 6], records: [1] };
    const parts = await new ProvedInputs("mixed", response).bind(layout, NAMESPACE, request.chainRequestId);
    assert.deepEqual(parts.newCommitments, [hex(0x0cn), hex(0x1cn)]);
    assert.equal(parts.stateArgs[0]!.length, 1);
    // the record put against the other output's commitment is refused
    await assert.rejects(new ProvedInputs("mixed", response).bind({ ...layout, records: [0] }, NAMESPACE, request.chainRequestId), /record 0 is sealed under .* not its output's new commitment/);
  });

  test("a circuit whose return value is in another order is refused", () => {
    const abi = structuredClone(AMM_SWAP.circuit.abi) as { return_type: { abi_type: { fields: unknown[] } } };
    const f = abi.return_type.abi_type.fields;
    [f[0], f[1]] = [f[1], f[0]];
    assert.throws(() => tipResultLayout({ abi }, queued(AMM_SWAP.manifest)), /pss_public_contract's layout/);
  });
});

// ---- FETCH by chain request id ----

/** A public result, as a non-secret-shared intake's round answers. */
function pub(r: QueuedResult): ChainResult {
  assert.equal(r.form, "public");
  return r as ChainResult;
}

describe("PssClient.fetchChainResult", () => {
  test("asks POST /v1/fetch/chain {namespace, chain_request_id} and returns the checked parts", async () => {
    const { request, response } = await ammSwapAnswer(0x0cn, 0x1cn);
    orch.on("POST", "/v1/fetch/chain", replies([response]));
    const client = new PssClient(clientConfig(url, { amm_swap_tip: AMM_SWAP }));
    const r = pub(await client.fetchChainResult(request.chainRequestId));
    assert.deepEqual(JSON.parse(orch.received[0]!.body), { namespace: NAMESPACE, chain_request_id: request.chainRequestId });
    assert.equal(r.circuit, "amm_swap_tip");
    assert.equal(r.parts.requestId, request.chainRequestId);
    assert.equal(r.parts.machineRequestId, response.request_id);
    assert.deepEqual(r.parts.oldCommitments, [hex(0x0cn)]);
    assert.deepEqual(r.parts.newCommitments, [hex(0x1cn)]);
    assert.equal(r.parts.ok, true);
    assert.deepEqual(r.parts.appOutputs, [hex(0n), hex(33450n)]);
    assert.equal(r.parts.stateArgs.length, 3);
    assert.equal(r.parts.stateArgs[0]!.length, 1);
    assert.equal(r.parts.stateArgs[0]![0]!.length, THIRD_FIELDS);
    assert.equal(r.parts.stateArgs[2]![0]![0], hex(keyId(2)));
  });

  test("the latest row: a second FETCH after a recompute answers the newer attempt", async () => {
    const first = await ammSwapAnswer(0x0cn, 0x1cn);
    const second = await ammSwapAnswer(0x0dn, 0x1dn, { salt: 2 });
    orch.on("POST", "/v1/fetch/chain", replies([first.response, second.response]));
    const client = new PssClient(clientConfig(url, { amm_swap_tip: AMM_SWAP }));
    const a = pub(await client.fetchChainResult(first.request.chainRequestId));
    const b = pub(await client.fetchChainResult(first.request.chainRequestId));
    assert.notEqual(a.parts.machineRequestId, b.parts.machineRequestId);
    assert.deepEqual(b.parts.oldCommitments, [hex(0x0dn)]);
    assert.notEqual(resultKey(a.parts), resultKey(b.parts));
  });

  test("a priced circuit's answer is bound to its pinned read: another price under the same id is refused", async () => {
    const { request, response } = await testPlainAnswer(0x0cn, 0x1cn);
    // the price, the pinned value after the key slots
    const moved = { ...response, public_inputs: response.public_inputs.map((x, i) => (i === 4 ? hex(0xe1n) : x)) };
    orch.on("POST", "/v1/fetch/chain", replies([response, moved]));
    const client = new PssClient(clientConfig(url, { test_plain: TEST_PLAIN }));
    const r = pub(await client.fetchChainResult(request.chainRequestId));
    assert.deepEqual(r.parts.reads, [hex(0xe0n)]);
    assert.equal(r.parts.machineRequestId, hex(await machineRequestId(request.chainRequestId, [0x0cn], [0xe0n])));
    assert.notEqual(r.parts.machineRequestId, hex(await machineRequestId(request.chainRequestId, [0x0cn])));
    await assert.rejects(client.fetchChainResult(request.chainRequestId), /its pinned reads/);
  });

  test("404 (no attempt yet) and 409 (the latest was rolled back) reach the caller as SidecarErrors", async () => {
    const client = new PssClient(clientConfig(url, { amm_swap_tip: AMM_SWAP }));
    orch.on("POST", "/v1/fetch/chain", replies([
      { status: 404, body: { error: "no attempt", class: "not_found" } },
      { status: 409, body: { error: "rolled back", class: "conflict" } },
    ]));
    await assert.rejects(client.fetchChainResult(1n), (e: unknown) => e instanceof SidecarError && e.class === "not_found");
    await assert.rejects(client.fetchChainResult(1n), (e: unknown) => e instanceof SidecarError && e.class === "conflict");
  });

  test("two landing readers for one pinned vk hash are refused at configuration", () => {
    assert.throws(
      () => new PssClient(clientConfig(url, { amm_swap_tip: AMM_SWAP, amm_swap_tip_receipt: AMM_SWAP_RECEIPT })),
      /amm_swap_tip_receipt and amm_swap_tip have result readers for the same vk hash/,
    );
  });

  test("an alias keeps its intake and lands through its target's result reader", async () => {
    const { request, response } = await ammSwapAnswer(0x0cn, 0x1cn);
    orch.on("POST", "/v1/fetch/chain", replies([response]));
    const client = new PssClient(clientConfig(url, {
      amm_swap_tip: AMM_SWAP,
      amm_swap_tip_receipt: { ...AMM_SWAP_RECEIPT, aliasOf: "amm_swap_tip" },
    }));
    assert.equal(client.config.intakeLayouts.amm_swap_tip_receipt?.intake, "receipt");
    assert.equal(client.resultReader("amm_swap_tip_receipt"), client.resultReader("amm_swap_tip"));
    for (const options of [{}, { circuit: "amm_swap_tip_receipt" }]) {
      const r = pub(await client.fetchChainResult(request.chainRequestId, options));
      assert.equal(r.circuit, "amm_swap_tip");
    }
  });

  test("a receipt intake answer carries the proved request id", async () => {
    const id = hex(0x1234n);
    const response = await ammAnswer(id, 0x0cn, 0x1cn);
    orch.on("POST", "/v1/fetch/chain", replies([response, { ...response, public_inputs: response.public_inputs.map((x, i) => (i === 4 ? hex(0x9999n) : x)) }]));
    const client = new PssClient(clientConfig(url, { amm_swap_tip_receipt: AMM_SWAP_RECEIPT }));
    const r = pub(await client.fetchChainResult(id));
    // the parts are data: the state holder by value, no modules
    assert.deepEqual(Object.keys(JSON.parse(JSON.stringify(r.parts))).slice(0, 2), ["circuit", "state"]);
    assert.equal(r.parts.requestId, id);
    // another proved request id (the signatures do not cover it): refused
    await assert.rejects(client.fetchChainResult(id), (e: unknown) => e instanceof ProtocolError && /proof's request id/.test(String(e)));
  });
});

describe("the result checks refuse", () => {
  const client = () => new PssClient(clientConfig(url, { amm_swap_tip: AMM_SWAP }));

  test("a tampered signature, naming the node", async () => {
    const { request, response } = await ammSwapAnswer(0x0cn, 0x1cn);
    const bad = structuredClone(response);
    bad.signatures[1]!.s[0] = hex(BigInt(bad.signatures[1]!.s[0]) ^ 1n);
    orch.on("POST", "/v1/fetch/chain", replies([bad]));
    await assert.rejects(client().fetchChainResult(request.chainRequestId), (e: unknown) => e instanceof ResultSignatureError && e.node === 1);
  });

  test("swapped signatures, at the first moved node", async () => {
    const { request, response } = await ammSwapAnswer(0x0cn, 0x1cn);
    const bad = structuredClone(response);
    bad.signatures = [bad.signatures[1]!, bad.signatures[0]!, bad.signatures[2]!];
    orch.on("POST", "/v1/fetch/chain", replies([bad]));
    await assert.rejects(client().fetchChainResult(request.chainRequestId), (e: unknown) => e instanceof ResultSignatureError && e.node === 0);
  });

  test("a tampered app output passes the signatures; a verifyProof hook catches it", async () => {
    const { request, response } = await ammSwapAnswer(0x0cn, 0x1cn);
    const layout = tipResultLayout(AMM_SWAP.circuit, queued(AMM_SWAP.manifest));
    const forged = structuredClone(response);
    forged.public_inputs[layout.appOutputs[1]!] = hex(999_999n);
    orch.on("POST", "/v1/fetch/chain", replies([forged]));
    // the signatures do not cover the app outputs
    const unchecked = pub(await client().fetchChainResult(request.chainRequestId));
    assert.deepEqual(resultSummary(unchecked).appOutputs, [hex(0n), hex(999_999n)]);
    // a local verifier that accepts the proof only with the inputs it was made for
    const verified: { publicInputs: string[] }[] = [];
    const verifyProof = async (input: { proof: string; publicInputs: string[] }) => {
      verified.push(input);
      return input.proof === response.proof && input.publicInputs.every((x, i) => x === response.public_inputs[i]);
    };
    const checking = () => new PssClient({ ...clientConfig(url, { amm_swap_tip: AMM_SWAP }), verifyProof });
    await assert.rejects(checking().fetchChainResult(request.chainRequestId), (e: unknown) => e instanceof ProtocolError && /the local verifier refused the proof/.test(e.message));
    orch.on("POST", "/v1/fetch/chain", replies([response]));
    const r = pub(await checking().fetchChainResult(request.chainRequestId));
    assert.deepEqual(r.parts.appOutputs, [hex(0n), hex(33450n)]);
    assert.equal(verified.length, 2);
  });

  test("a changed third", async () => {
    const { request, response } = await ammSwapAnswer(0x0cn, 0x1cn);
    const bad = structuredClone(response);
    bad.records[0]!.c[2] = bad.records[0]!.c[2]!.slice(0, -2) + "ff";
    orch.on("POST", "/v1/fetch/chain", replies([bad]));
    await assert.rejects(client().fetchChainResult(request.chainRequestId), (e: unknown) => e instanceof ResultSignatureError && e.node === 2);
  });

  test("a configured circuit whose result layout is not the library's: intake works, results are refused", async () => {
    const abi = structuredClone(AMM_SWAP.circuit.abi) as { return_type: { abi_type: { fields: unknown[] } } };
    abi.return_type.abi_type.fields.splice(3);
    const c = new PssClient(clientConfig(url, { odd: { circuit: { abi }, manifest: AMM_SWAP.manifest } }));
    await assert.rejects(c.fetchChainResult(1n, { circuit: "odd" }), /its results cannot be read: .*no npk_app_hash/);
    assert.equal(orch.received.length, 0);
  });

  test("an answer under another vk hash", async () => {
    const { request, response } = await ammSwapAnswer(0x0cn, 0x1cn);
    orch.on("POST", "/v1/fetch/chain", replies([{ ...response, vk_hash: hex(5n) }]));
    await assert.rejects(client().fetchChainResult(request.chainRequestId), /pins no configured/);
  });
});

// ---- process_result's arguments against the compiled contracts ----

// The flattened field encoding of a FunctionAbi's arguments.
const encoded = (abi: unknown, args: unknown[]) => encodeArguments(abi as never, args).map((f) => hex(f));

describe("process_result arguments against the contracts' ABIs", () => {
  test("pss_public_contract_test process_result (both non-secret-shared intakes): TipResult, sealed, signatures", async () => {
    const { request, response } = await testPlainAnswer(0x0cn, 0x1cn);
    orch.on("POST", "/v1/fetch/chain", replies([response]));
    const client = new PssClient(clientConfig(url, { test_plain: TEST_PLAIN }));
    const r = pub(await client.fetchChainResult(request.chainRequestId));
    const call = await resultCall(r);
    assert.equal(call.method, "process_result");
    const abi = contractAbis("PssPublicTest").functions.process_result!;
    assert.deepEqual(abi.parameters.map((p) => p.name), ["result", "sealed", "signatures"]);
    const flat = encoded(abi, call.args);
    const sigs = response.signatures.flatMap((s) => [...s.s, ...s.e]);
    const sealed = r.parts.stateArgs.flatMap((node) => node.flat());
    assert.deepEqual(flat, [
      request.chainRequestId, hex(0x0cn), hex(0x1cn), hex(1n), hex(0xe0n), hex(5n), hex(6n), // request_id, old, new, ok, values (reads, app_outputs)
      ...sealed, // sealed[3][1][5]
      ...sigs.map((x) => fieldHex(x)),
    ]);
    assert.equal(sealed.length, 15);
  });

  test("examples/amm-tip process_result takes the PartialResult in the library's node-held shape", async () => {
    const id = hex(0x1234n);
    orch.on("POST", "/v1/fetch/chain", replies([await ammAnswer(id, 0x0cn, 0x1cn, { held: true })]));
    const r = pub(await new PssClient(clientConfig(url, { amm_swap_tip_held: AMM_SWAP_HELD })).fetchChainResult(id));
    const call = await resultCall(r);
    const abi = contractAbis("AmmTip").functions.process_result!;
    assert.deepEqual(abi.parameters.map((p) => p.name), ["round", "signatures"]);
    const flat = encoded(abi, call.args);
    // partial_note, then TipResult: request_id, old, new, ok, values (app outputs)
    assert.equal(r.parts.partialNote, hex(AMM_PARTIAL_NOTE));
    assert.deepEqual(flat.slice(0, 7), [
      hex(AMM_PARTIAL_NOTE), id, hex(0x0cn), hex(0x1cn), hex(1n), hex(0n), hex(33450n),
    ]);
    assert.equal(flat.length, 7 + 12);
  });

  // Partial-note delivery under public outputs: lending's non-secret-shared
  // deposit echoes the request's partial note right after ok, and its
  // process_result takes pss_public_contract's PartialResult (the contract's
  // OwnerResult: three pinned values, the six owner outputs), the partial
  // note before the TipResult, which apply completes in public.
  test("examples/lending-tip process_result takes the PartialResult: the partial note, then the TipResult", async () => {
    const chain = fieldHex(0x1dn);
    // the request: the partial note a clear app input under its parameter's name
    const intake = intakeLayout(LENDING_DEPOSIT.circuit, queued(LENDING_DEPOSIT.manifest));
    assert.equal(intake.partialNote, "partial_note");
    assert.deepEqual(intake.keys, ["position", "amount", "partial_note"]);
    assert.equal(intakeLayout(AMM_SWAP.circuit, queued(AMM_SWAP.manifest)).partialNote, "partial_note");
    assert.equal(intakeLayout(TEST_PLAIN.circuit, queued(TEST_PLAIN.manifest)).partialNote, undefined);
    const layout = tipResultLayout(LENDING_DEPOSIT.circuit, queued(LENDING_DEPOSIT.manifest));
    assert.equal(layout.partialNote, 12);
    // the owner layout: [code, position, mask, payout, new_hashes[2]]
    assert.deepEqual(layout.appOutputs, [13, 14, 15, 16, 17, 18]);
    orch.on("POST", "/v1/fetch/chain", replies([await depositAnswer(chain, 0x0cn, 0x1cn)]));
    const r = pub(await new PssClient(clientConfig(url, { deposit: LENDING_DEPOSIT })).fetchChainResult(chain));
    assert.equal(r.parts.partialNote, hex(0x9an));
    assert.deepEqual(r.parts.appOutputs, [0n, 1n, 1n, 0n, 0x11n, 0x12n].map(hex));
    assert.equal(resultSummary(r).partialNote, hex(0x9an));
    const call = await resultCall(r);
    const abi = contractAbis("LendingTip").functions.process_result!;
    assert.deepEqual(abi.parameters.map((p) => p.name), ["round", "signatures"]);
    const flat = encoded(abi, call.args);
    // partial_note, then TipResult: request_id, old, new, ok, values (pinned, app outputs)
    assert.deepEqual(flat.slice(0, 14), [0x9an, BigInt(chain), 0x0cn, 0x1cn, 1n, 0xfan, 1n, 0x64n, 0n, 1n, 1n, 0n, 0x11n, 0x12n].map(hex));
    assert.equal(flat.length, 14 + 12);
  });

  // A private outcome lands through the app's result function with the
  // library's argument order (outcomeResultArgs) after the function's own:
  // lending's secret-shared rounds through process_shared(round, result,
  // new_hashes, values, deliveries, signatures) (the owner-bound rounds and
  // the liquidation) or process_header_shared(round, result, new_hashes,
  // values, deliveries, signatures) (the quote and the scan), the round's
  // ROUND_* index first, then the new leaf hashes of its tree-valued book,
  // its app values (the exit tag, then the book's append index and the
  // inputs-opened bit; the quote, which writes no position, has the exit
  // tag and the bit) and its one delivery (a liquidation's notice or a filler:
  // tag, note hash, nine ciphertext fields); the AMM's secret-shared swap
  // through process_result_shared(result, signatures), its partial note
  // completed in the round, with no call values.
  // aztec.js refuses an array of another length, so each round's T, H, L and
  // K are checked against the compiled contract.
  const sharedFlat = (parts: Awaited<ReturnType<typeof outcomeResultParts>>, extra: string[]) => [
    parts.requestId, ...parts.oldCommitments, ...parts.newCommitments, ...parts.reads, // apply: request_id, old_commitments, values
    parts.outcomeTag, ...parts.noteHashes, ...parts.ciphertext,
    ...extra,
    ...parts.signatures.flatMap((s) => [...s.s, ...s.e]).map((x) => fieldHex(x)),
  ];

  for (const circuit of ["deposit_shared", "withdraw_shared", "borrow_shared", "repay_shared", "supply_shared", "withdraw_supply_shared", "view_shared", "quote_shared", "liquidate_shared"] as const) {
    const round = ROUNDS[circuit.replace(/_shared$/, "") as keyof typeof ROUNDS];
    const header = circuit === "quote_shared";
    const name = header ? "process_header_shared" : "process_shared";
    test(`examples/lending-tip ${name}(${round}, ...) takes ${circuit}'s outcome, its new leaf hashes, its app values and the signatures`, async () => {
      const chain = fieldHex(0x1dn);
      const { shape, response } = await sharedRoundAnswer(sharedRound("lending-tip", circuit), chain);
      const parts = await outcomeResultParts(shape, NAMESPACE, chain, response);
      const abi = contractAbis("LendingTip").functions[name]!;
      assert.deepEqual(abi.parameters.map((p) => p.name), ["round", "result", "new_hashes", "values", "deliveries", "signatures"]);
      assert.ok(parts.newHashes.length > 0 && parts.appValues.length === (header ? 2 : 3));
      assert.deepEqual(parts.deliveries.map((d) => d.ciphertext.length), [9]);
      const sent = parts.deliveries.flatMap((d) => [d.tag, d.noteHash, ...d.ciphertext]);
      assert.deepEqual(encoded(abi, [round, ...outcomeResultArgs(parts)]), [hex(round), ...sharedFlat(parts, [...parts.newHashes, ...parts.appValues, ...sent])]);
    });
  }

  test("examples/amm-tip process_result_shared takes the outcome and the signatures", async () => {
    const chain = fieldHex(0x1dn);
    const { shape, response } = await sharedRoundAnswer(sharedRound("amm-tip", "amm_swap_tip_shared"), chain);
    const parts = await outcomeResultParts(shape, NAMESPACE, chain, response);
    const abi = contractAbis("AmmTip").functions.process_result_shared!;
    assert.deepEqual(abi.parameters.map((p) => p.name), ["result", "signatures"]);
    assert.ok(parts.newHashes.length === 0);
    assert.deepEqual(encoded(abi, outcomeResultArgs(parts)), sharedFlat(parts, []));
  });

  test("the capsule: slot 0x10 under the sender, vk then proof", async () => {
    const { request, response } = await ammSwapAnswer(0x0cn, 0x1cn);
    orch.on("POST", "/v1/fetch/chain", replies([response]));
    const r = pub(await new PssClient(clientConfig(url, { amm_swap_tip: AMM_SWAP })).fetchChainResult(request.chainRequestId));
    const call = await resultCall(r);
    const c = call.capsule as unknown as { contractAddress: AztecAddress; storageSlot: Fr; data: Fr[]; scope?: AztecAddress };
    assert.equal(c.contractAddress.toString(), NAMESPACE);
    assert.equal(c.storageSlot.toBigInt(), BigInt(CAPSULE_SLOT_PROOF));
    assert.equal(c.data.length, 115 + 458);
    assert.equal(hex(c.data[115]!), hex(1n));
    assert.equal(String(c.scope ?? (call.capsule as unknown as { scope: unknown }).scope), SENDER);
  });

  test("refused before proving: other vk fields", async () => {
    const { request, response } = await ammSwapAnswer(0x0cn, 0x1cn);
    orch.on("POST", "/v1/fetch/chain", replies([response]));
    const r = pub(await new PssClient(clientConfig(url, { amm_swap_tip: AMM_SWAP })).fetchChainResult(request.chainRequestId));
    await assert.rejects(resultCall(r, { vkFields: { amm_swap_tip: [...VK_FIELDS.slice(1), new Fr(1n)] } }), /vk fields hash/);
    await assert.rejects(resultCall(r, { vkFields: {} }), /no vk fields for circuit amm_swap_tip/);
  });
});

// ---- node-held state: results without records ----

describe("node-held state: FETCH and process_result without records", () => {
  test("the layout: node-held, no records", () => {
    const layout = tipResultLayout(AMM_SWAP_HELD.circuit, queued(AMM_SWAP_HELD.manifest));
    assert.deepEqual([layout.state, layout.records], ["node", []]);
  });

  test("a receipt intake answer without records: signed over H(sealed_i) = 0, empty thirds", async () => {
    const id = hex(0x1234n);
    orch.on("POST", "/v1/fetch/chain", replies([await ammAnswer(id, 0x0cn, 0x1cn, { held: true })]));
    const r = pub(await new PssClient(clientConfig(url, { amm_swap_tip_held: AMM_SWAP_HELD })).fetchChainResult(id));
    assert.equal(r.parts.state, "node");
    assert.deepEqual(r.parts.stateArgs, [[], [], []]);
    assert.deepEqual([r.parts.oldCommitments, r.parts.newCommitments, r.parts.ok], [[hex(0x0cn)], [hex(0x1cn)], true]);
  });

  test("pss_public_contract_test process_result_held (receipt intake, node-held): TipResult, signatures", async () => {
    const abi = contractAbis("PssPublicTest").functions.process_result_held!;
    assert.deepEqual(abi.parameters.map((p) => p.name), ["result", "signatures"]);
    const id = hex(0x1234n);
    const response = await ammAnswer(id, 0x0cn, 0x1cn, { held: true });
    orch.on("POST", "/v1/fetch/chain", replies([response]));
    const r = pub(await new PssClient(clientConfig(url, { amm_swap_tip_held: AMM_SWAP_HELD })).fetchChainResult(id));
    // the test contract's held entry takes the TipResult alone (no partial
    // note): the AMM swap's parts without it
    const call = await resultCall({ ...r, parts: { ...r.parts, partialNote: undefined } }, { resultFunction: () => ({ name: "process_result_held" }) });
    assert.equal(call.method, "process_result_held");
    assert.equal(call.args.length, 2);
    const sigs = response.signatures.flatMap((s) => [...s.s, ...s.e]);
    assert.deepEqual(encoded(abi, call.args), [
      id, hex(0x0cn), hex(0x1cn), hex(1n), hex(0n), hex(33450n), // request_id, old, new, ok, values (app outputs)
      ...sigs.map((x) => fieldHex(x)),
    ]);
  });

  test("a node-held round's answer that carries a record is refused", async () => {
    const id = hex(0x1234n);
    orch.on("POST", "/v1/fetch/chain", replies([await ammAnswer(id, 0x0cn, 0x1cn)]));
    const client = new PssClient(clientConfig(url, { amm_swap_tip_held: AMM_SWAP_HELD }));
    await assert.rejects(client.fetchChainResult(id), (e: unknown) => e instanceof ProtocolError && /1 records; under node-held state the manifest gives 0/.test(String(e)));
  });

  test("signatures over the hashes of thirds the answer does not carry are refused", async () => {
    const id = hex(0x1234n);
    const chainHeld = await ammAnswer(id, 0x0cn, 0x1cn);
    orch.on("POST", "/v1/fetch/chain", replies([{ ...chainHeld, records: [] }]));
    const client = new PssClient(clientConfig(url, { amm_swap_tip_held: AMM_SWAP_HELD }));
    await assert.rejects(client.fetchChainResult(id), (e: unknown) => e instanceof ResultSignatureError);
  });

  test("submitResult lands a node-held result through the app's method", async () => {
    const id = hex(0x1234n);
    orch.on("POST", "/v1/fetch/chain", replies([await ammAnswer(id, 0x0cn, 0x1cn, { held: true })]));
    const { contract, calls } = recordingContract(0);
    const client = new PssClient(clientConfig(url, { amm_swap_tip_held: AMM_SWAP_HELD }));
    const out = await submitResult({
      contract,
      client,
      address: NAMESPACE,
      from: SENDER,
      vkFields: { amm_swap_tip_held: VK_FIELDS },
      resultFunction: () => ({ name: "process_result_held" }),
      chainRequestId: id,
    });
    assert.equal(out.attempts, 1);
    assert.deepEqual(calls.map((c) => [c.method, c.args.length]), [["process_result_held", 2]]);
  });
});

// ---- submitResult ----


describe("submitResult", () => {
  const settings = (contract: ResultContract) => ({
    contract,
    address: NAMESPACE,
    from: SENDER,
    vkFields: { amm_swap_tip: VK_FIELDS },
    sendOptions: { wait: { timeout: 60 } },
    refetchDelayMs: 1,
  });

  test("lands the fetched result from the given account", async () => {
    const { request, response } = await ammSwapAnswer(0x0cn, 0x1cn);
    orch.on("POST", "/v1/fetch/chain", replies([response]));
    const { contract, calls } = recordingContract(0);
    const client = new PssClient(clientConfig(url, { amm_swap_tip: AMM_SWAP }));
    const out = await submitResult({ ...settings(contract), client, chainRequestId: request.chainRequestId });
    assert.equal(out.attempts, 1);
    assert.equal(calls.length, 1);
    assert.equal(calls[0]!.method, "process_result");
    assert.equal(String(calls[0]!.options.from), SENDER);
    assert.deepEqual(calls[0]!.options.wait, { timeout: 60 });
    const fee = calls[0]!.options.fee as { paymentMethod: FPCFeePaymentMethod };
    assert.ok(fee.paymentMethod instanceof FPCFeePaymentMethod, "the default fee setting pays through wFJ");
    assert.ok((await fee.paymentMethod.getFeePayer()).equals(wfjAddress()));
    assert.equal(calls[0]!.capsules.length, 1);
  });

  test("re-fetches after a revert and sends the newer attempt", async () => {
    const first = await ammSwapAnswer(0x0cn, 0x1cn);
    const second = await ammSwapAnswer(0x0dn, 0x1dn, { salt: 2 });
    orch.on("POST", "/v1/fetch/chain", replies([first.response, second.response]));
    const { contract, calls } = recordingContract(1);
    const client = new PssClient(clientConfig(url, { amm_swap_tip: AMM_SWAP }));
    const out = await submitResult({ ...settings(contract), client, chainRequestId: first.request.chainRequestId });
    assert.equal(out.attempts, 2);
    assert.equal(orch.count("POST", "/v1/fetch/chain"), 2);
    assert.equal(out.result.parts.machineRequestId, second.response.request_id);
    // the PartialResult: the partial note, then the TipResult
    const round = calls[1]!.args[0] as { partial_note: Fr; result: { old_commitments: Fr[] } };
    assert.equal(hex(round.partial_note), hex(AMM_PARTIAL_NOTE));
    assert.equal(hex(round.result.old_commitments[0]!), hex(0x0dn));
  });

  test("does not re-send the same result after a revert: SubmitResultError", async () => {
    const first = await ammSwapAnswer(0x0cn, 0x1cn);
    orch.on("POST", "/v1/fetch/chain", replies([first.response]));
    const { contract, calls } = recordingContract(5);
    const client = new PssClient(clientConfig(url, { amm_swap_tip: AMM_SWAP }));
    await assert.rejects(
      submitResult({ ...settings(contract), client, chainRequestId: first.request.chainRequestId }),
      (e: unknown) => e instanceof SubmitResultError && e.attempts === 1 && /not the head/.test(String((e as Error).cause)),
    );
    assert.equal(calls.length, 1);
    assert.equal(orch.count("POST", "/v1/fetch/chain"), 2);
  });

  test("sends the same result again after a failure that is not a revert, within its attempts", async () => {
    const first = await ammSwapAnswer(0x0cn, 0x1cn);
    orch.on("POST", "/v1/fetch/chain", replies([first.response]));
    const { contract, calls } = recordingContract(1, "Timeout awaiting isMined");
    const client = new PssClient(clientConfig(url, { amm_swap_tip: AMM_SWAP }));
    const out = await submitResult({ ...settings(contract), client, chainRequestId: first.request.chainRequestId, refetchDelayMs: 0 });
    assert.equal(out.attempts, 2);
    assert.equal(calls.length, 2);
  });

  test("isRevert: a mined transaction whose public part reverted, nothing else", () => {
    assert.equal(isRevert(new Error("Transaction 0x2a7f reverted: app_logic_reverted. Reason: not the head")), true);
    for (const e of [new Error("fetch failed"), new Error("Transaction 0x2a7f was dropped. Reason: unknown"), new Error("Timeout awaiting isMined"), "Transaction 0x1 reverted", undefined]) {
      assert.equal(isRevert(e), false, String(e));
    }
  });
});

// ---- a secret-shared intake's private outcome ----

describe("a secret-shared intake's result: the private outcome, read and landed", () => {
  const chain = hex(0x1dn);
  const shared = () => new PssClient(clientConfig(url, { deposit_shared: LENDING_DEPOSIT_SHARED }));

  test("its reader is the private outcomes', chosen from its intake; its shape comes from the manifest and the circuit", () => {
    const client = shared();
    assert.equal(client.resultReader("deposit_shared").form, "outcome");
    assert.equal(intakeModule("shared_receipt").results, privateOutcomes);
    assert.equal(intakeModule("receipt").results, publicResults);
    assert.deepEqual(outcomeShape(LENDING_DEPOSIT_SHARED.circuit, parseManifest(LENDING_DEPOSIT_SHARED.manifest) as QueuedManifest), {
      circuit: "deposit_shared",
      reads: 1,
      writes: 1,
      pinned: 3,
      newHashes: 2,
      noteHashes: 1,
      appValues: 3,
      deliveries: 1,
      deliveryLength: 9,
      state: "node",
      records: [],
    });
  });

  test("fetchChainResult splits it into the outcome's parts", async () => {
    orch.on("POST", "/v1/fetch/chain", replies([await depositSharedAnswer(chain, 0x0cn, 0x1cn)]));
    const r = await shared().fetchChainResult(chain);
    assert.equal(r.form, "outcome");
    assert.equal(r.circuit, "deposit_shared");
    if (r.form !== "outcome") return;
    assert.deepEqual(r.parts.reads, [0x7d0n, 4n, 0x64n].map(hex));
    assert.deepEqual(r.parts.newHashes, [0x11n, 0x12n].map(hex));
    assert.deepEqual(r.parts.noteHashes, [hex(0x4an)]);
    assert.equal(r.parts.ciphertext.length, 8);
    assert.equal(r.parts.outcomeTag, hex(0x7an));
    assert.deepEqual(r.parts.appValues, [hex(0xe1n), hex(0n), hex(1n)]);
    assert.deepEqual(r.parts.deliveries, [{ tag: hex(0xdan), noteHash: hex(0xdbn), ciphertext: Array.from({ length: 9 }, (_, k) => hex(0xd0n + BigInt(k))) }]);
    const s = resultSummary(r);
    assert.deepEqual([s.form, s.moves, s.ciphertextLength, s.outcomeTag, s.ok], ["outcome", true, 8, hex(0x7an), undefined]);
  });

  test("fetchChainResult answers a non-secret-shared intake's result in its public form", async () => {
    const { request, response } = await ammSwapAnswer(0x0cn, 0x1cn);
    orch.on("POST", "/v1/fetch/chain", replies([response]));
    const r = await new PssClient(clientConfig(url, { amm_swap_tip: AMM_SWAP })).fetchChainResult(request.chainRequestId);
    assert.equal(r.form, "public");
    assert.equal(r.parts.machineRequestId, response.request_id);
    const s = resultSummary(r);
    assert.deepEqual([s.form, s.moves, s.ok, s.outcomeTag], ["public", true, true, undefined]);
  });

  test("submitResult lands it from the user's account, through the circuit's method", async () => {
    orch.on("POST", "/v1/fetch/chain", replies([await depositSharedAnswer(chain, 0x0cn, 0x1cn)]));
    const { contract, calls } = recordingContract(0);
    const out = await submitResult({
      contract,
      client: shared(),
      address: NAMESPACE,
      from: SENDER,
      vkFields: { deposit_shared: VK_FIELDS },
      resultFunction: () => DEPOSIT_SHARED,
      chainRequestId: chain,
    });
    assert.equal(out.attempts, 1);
    assert.equal(out.result.form, "outcome");
    assert.deepEqual(calls.map((c) => [c.method, c.args.length, String(c.options.from)]), [["process_shared", 6, SENDER]]);
  });

  test("Lander.attempt lands it through the circuit's function, [round, result, new_hashes, values, deliveries, signatures], and holds a failing one", async () => {
    orch.on("POST", "/v1/fetch/chain", replies([await depositSharedAnswer(chain, 0x0cn, 0x1cn)]));
    const { contract, calls } = recordingContract(2);
    const lander = new Lander({
      client: shared(),
      calls: {
        contract,
        address: NAMESPACE,
        from: SENDER,
        vkFields: { deposit_shared: VK_FIELDS },
        resultFunction: (r) => (r.circuit === "deposit_shared" ? DEPOSIT_SHARED : { name: "process_result" }),
      },
      policy: { sendsPerResult: 2, transactions: Infinity, refetchDelayMs: 1 },
    });
    const first = await lander.attempt(chain);
    assert.equal(first.status, "failed");
    assert.equal((await lander.attempt(chain)).status, "failed");
    assert.equal((await lander.attempt(chain)).status, "held");
    orch.on("POST", "/v1/fetch/chain", replies([await depositSharedAnswer(chain, 0x0cn, 0x1cn, 0xd0n)]));
    const landed = await lander.attempt(chain);
    assert.equal(landed.status, "landed");
    assert.deepEqual(calls.map((c) => [c.method, c.args.length]), Array(3).fill(["process_shared", 6]));
    const [round, result, newHashes, values, deliveries, signatures] = calls[2]!.args as [
      number,
      { apply: { values: Fr[] }; ciphertext: Fr[] },
      Fr[],
      Fr[],
      { tag: Fr; note_hash: Fr; ciphertext: Fr[] }[],
      unknown[],
    ];
    assert.equal(round, ROUND_DEPOSIT);
    assert.deepEqual(newHashes.map(hex), [0x11n, 0x12n].map(hex));
    assert.deepEqual(values.map(hex), [hex(0xe1n), hex(0n), hex(1n)]);
    assert.deepEqual(deliveries.map((d) => [hex(d.tag), hex(d.note_hash), d.ciphertext.length]), [[hex(0xdan), hex(0xdbn), 9]]);
    assert.deepEqual(result.apply.values.map(hex), [0x1cn, 0x7d0n, 4n, 0x64n].map(hex));
    assert.equal(hex(result.ciphertext[0]!), hex(0xd0n));
    assert.equal(signatures.length, 3);
    assert.equal(calls[2]!.capsules.length, 1);
  });

  test("prepareResult: the library's function or a named one with its leading arguments, the app values after new_hashes, the deliveries after them, and wrong vk fields refused", async () => {
    orch.on("POST", "/v1/fetch/chain", replies([await depositSharedAnswer(chain, 0x0cn, 0x1cn)]));
    const r = await shared().fetchChainResult(chain);
    assert.equal(r.form, "outcome");
    if (r.form !== "outcome") return;
    const plain = await resultCall(r);
    assert.equal(plain.method, "process_result");
    // [result, new_hashes, values, deliveries, signatures]
    assert.equal(plain.args.length, 5);
    assert.deepEqual((plain.args[2] as Fr[]).map((f) => f.toBigInt()), r.parts.appValues.map(BigInt));
    assert.equal((plain.args[3] as unknown[]).length, 1);
    const named = await resultCall(r, { resultFunction: () => DEPOSIT_SHARED });
    assert.equal(named.method, "process_shared");
    assert.deepEqual(named.args, [ROUND_DEPOSIT, ...plain.args]);
    await assert.rejects(resultCall(r, { vkFields: { deposit_shared: VK_FIELDS.map(() => 12n) } }), RangeError);
  });
});

// ---- the queue ----


describe("pollResult", () => {
  test("applied: waits for the head to pass the index, then reads and decrypts what apply stored", async () => {
    const q = new FakeQueue();
    q.requests = [hex(0xa0n), hex(0xa1n)];
    const read: number[] = [];
    let polls = 0;
    const p = pollResult({
      queue: {
        ...q,
        blockNumber: () => q.blockNumber(),
        requestAt: (i: number) => q.requestAt(i),
        doneAt: (i: number) => q.doneAt(i),
        snapshot: async () => {
          if (++polls === 3) {
            q.head = 2;
            q.done.set(0, DONE_APPLIED);
            q.done.set(1, DONE_APPLIED);
          }
          return q.snapshot();
        },
      },
      chainRequestId: 0xa1n,
      intervalMs: 1,
      readOutputs: async (i) => {
        read.push(i);
        return [5n, 6n];
      },
      decrypt: async (o) => o.map((x) => x * 2n),
    });
    const r = await p;
    assert.deepEqual(r, { status: "applied", index: 1, requestId: hex(0xa1n), outputs: [10n, 12n], block: 100 });
    assert.deepEqual(read, [1]);
    assert.equal(polls, 3);
  });

  test("skipped: done[index] = 2, no outputs read", async () => {
    const q = new FakeQueue();
    q.requests = [hex(0xa0n)];
    q.head = 1;
    q.done.set(0, DONE_SKIPPED);
    let read = false;
    const r = await pollResult({ queue: q, chainRequestId: 0xa0n, intervalMs: 1, readOutputs: async () => (read = true) });
    assert.equal(r.status, "skipped");
    assert.equal(read, false);
  });

  test("a replaced block that moves the request: the remembered index is checked again, and the request's own fate reported", async () => {
    const q = new FakeQueue();
    q.requests = [hex(0xa0n), hex(0xa1n)];
    const read: number[] = [];
    let polls = 0;
    const r = await pollResult({
      queue: {
        ...q,
        blockNumber: () => q.blockNumber(),
        requestAt: (i: number) => q.requestAt(i),
        doneAt: (i: number) => q.doneAt(i),
        snapshot: async () => {
          polls++;
          if (polls === 2) {
            // the block holding 0xa1's intake was replaced: 0xb1 took index
            // 1 and was applied, 0xa1 was queued again at index 2
            q.requests = [hex(0xa0n), hex(0xb1n), hex(0xa1n)];
            q.head = 2;
            q.done.set(0, DONE_APPLIED);
            q.done.set(1, DONE_APPLIED);
          }
          if (polls === 3) {
            q.head = 3;
            q.done.set(2, DONE_APPLIED);
          }
          return q.snapshot();
        },
      },
      chainRequestId: 0xa1n,
      intervalMs: 1,
      readOutputs: async (i) => {
        read.push(i);
        return i;
      },
    });
    assert.deepEqual(r, { status: "applied", index: 2, requestId: hex(0xa1n), outputs: 2, block: 100 });
    assert.deepEqual(read, [2], "never index 1, 0xb1's");
    assert.equal(polls, 3);
  });

  test("a request not yet queued is waited for, and the timeout is reported", async () => {
    const q = new FakeQueue();
    await assert.rejects(pollResult({ queue: q, chainRequestId: 0xa0n, intervalMs: 5, timeoutMs: 20 }), /not queued/);
  });
});

describe("NodeQueueReader and the logs", () => {
  test("slots: the known answers of sidecar-tip chain/layout.rs (base 12)", async () => {
    const s = new QueueSlots(12);
    assert.equal(hex(await s.request(0)), "0x0b8231a42f1b14f6d5723e64e4e4d3c4061c684f446e5eaaea1b1848ce4fed97");
    assert.equal(hex(await s.request(1)), "0x1734bbf673a816bc80a7223360b826f1f446bc59afd737ff2119a4e6cb129e2d");
    assert.equal(hex(await s.seen(0xa1)), "0x2508af14acd99fac2f9e3c66b2042e61a52510ba7070c8d11ef477add048b2c2");
    assert.equal(hex(await s.done(0)), "0x2acc00a91751b6025e9506841accdb3c82ffc1dbfb4b1222a766f5463862ecec");
    assert.deepEqual([s.tail(), s.headIndex(), s.headSince()].map((f) => f.toBigInt()), [13n, 14n, 15n]);
    assert.equal(hex(await computeSealedLogTag(0xa1n)), "0x259ea36028d558d9c5b79fd56007a1684164f271f1d087f2779911190666ac61");
  });

  test("slots and done codes: testvectors/queue.json (sidecar-tip chain/layout.rs, queue.nr)", async () => {
    const file = JSON.parse(readFileSync(new URL("../../../testvectors/queue.json", import.meta.url), "utf8")) as {
      done: { pending: number; applied: number; skipped: number };
      vectors: {
        name: string;
        base: string;
        tail: string;
        head_index: string;
        head_since: string;
        requests: { index: string; slot: string }[];
        seen: { request_id: string; slot: string }[];
        done: { index: string; slot: string }[];
      }[];
    };
    assert.deepEqual([DONE_PENDING, DONE_APPLIED, DONE_SKIPPED], [file.done.pending, file.done.applied, file.done.skipped]);
    for (const v of file.vectors) {
      const s = new QueueSlots(v.base);
      assert.deepEqual([s.tail(), s.headIndex(), s.headSince()].map((f) => hex(f)), [v.tail, v.head_index, v.head_since], v.name);
      for (const e of v.requests) assert.equal(hex(await s.request(BigInt(e.index))), e.slot, `${v.name}: requests[${e.index}]`);
      for (const e of v.seen) assert.equal(hex(await s.seen(e.request_id)), e.slot, `${v.name}: seen[${e.request_id}]`);
      for (const e of v.done) assert.equal(hex(await s.done(BigInt(e.index))), e.slot, `${v.name}: done[${e.index}]`);
    }
  });

  test("the base slot comes from the artifact's storage layout", () => {
    assert.equal(queueBaseSlot(contractAbis("PssPublicTest") as never), 15n);
    assert.equal(queueBaseSlot(contractAbis("AmmTip") as never), 32n);
    assert.throws(() => queueBaseSlot({ storageLayout: {} }), /no storage field/);
  });

  test("a snapshot pins all storage reads to the same block hash", async () => {
    const s = new QueueSlots(13);
    const storage = new Map<string, bigint>([
      [hex(s.headIndex()), 1n],
      [hex(s.headSince()), 40n],
      [hex(s.tail()), 3n],
      [hex(await s.request(1)), 0xbeefn],
      [hex(await s.done(0)), 2n],
    ]);
    const blockHash = blockHashOf(44);
    const blocks: BlockParameter[] = [];
    const node = {
      getBlockNumber: async () => 44,
      getBlockData: async (block: number) => {
        assert.equal(block, 44);
        return { blockHash };
      },
      getPublicStorageAt: async (block: BlockParameter, contract: AztecAddress, slot: Fr) => {
        blocks.push(block);
        assert.equal(contract.toString(), NAMESPACE);
        return new Fr(storage.get(hex(slot)) ?? 0n);
      },
    };
    const r = new NodeQueueReader(node, NAMESPACE, 13);
    assert.deepEqual(await r.snapshot(), { block: 44, blockHash: blockHash.toString(), head: 1, headSince: 40, tail: 3, headRequest: hex(0xbeefn) });
    assert.deepEqual(blocks, Array(4).fill(blockHash));
    assert.equal(await r.doneAt(0), 2);
  });

  test("readRequestLog finds and checks the on-chain request log by its tag", async () => {
    const { request } = await ammSwapAnswer(0x0cn, 0x1cn);
    const tag = await computeRequestLogTag(request.chainRequestId);
    const fields = [tag, ...request.inputs.map((x) => new Fr(BigInt(x))), new Fr(BigInt(request.userNonce))];
    const node: LogNode = {
      getPublicLogsByTags: async (q) => {
        assert.equal(q.contractAddress.toString(), NAMESPACE);
        const asked = q.tags[0] as Tag;
        return [hex(asked.value) === hex(tag) ? [{ logData: fields }] : []];
      },
    };
    const log = await readRequestLog(node, NAMESPACE, request.chainRequestId, VK_HASH);
    assert.deepEqual([log?.inputs, log?.userNonce], [request.inputs, request.userNonce]);
    assert.equal(await readRequestLog(node, NAMESPACE, 5n, VK_HASH), undefined);
  });

  test("parseSealedLog reads (new commitments, sealed) and checks the tag", async () => {
    const tag = await computeSealedLogTag(0xa1n);
    const body = [tag.toBigInt(), 0x1cn, ...Array.from({ length: 15 }, (_, k) => BigInt(k + 1))];
    const log = await parseSealedLog(body, { W: 1, T: 1, L: 5 }, 0xa1n);
    assert.deepEqual(log.newCommitments, [hex(0x1cn)]);
    assert.deepEqual(log.sealed[1]![0], [6n, 7n, 8n, 9n, 10n].map(hex));
    await assert.rejects(parseSealedLog(body, { W: 1, T: 1, L: 5 }, 0xa2n), ProtocolError);
    await assert.rejects(parseSealedLog(body.slice(1), { W: 1, T: 1, L: 5 }), /expected 17/);
  });
});
