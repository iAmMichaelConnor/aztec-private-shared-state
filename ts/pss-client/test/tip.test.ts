// The tip's intake functions (src/tip.ts and PssClient.tipRequest /
// obtainIntake): the shared vectors chain_request_id.json, receipts.json and
// log_tags.json reproduced through them; the app inputs' order and typed
// ranges; the receipt flow against a mock orchestrator; the shapes of the
// request functions' arguments as aztec.js encodes them; and the on-chain intake
// request log.

import assert from "node:assert/strict";
import { after, before, beforeEach, describe, test } from "node:test";

import { Fr } from "@aztec-labs/foundation/curves/bn254";
import { encodeArguments, type FunctionAbi } from "@aztec-labs/stdlib/abi";

import {
  assertNoRequester,
  ConfigError,
  NODE_KEYS_LEN,
  NODE_KEYS_SLOT,
  NodeKeyMismatchError,
  SIDECAR_INTAKE_AD,
  ProtocolError,
  PSS_ATTEMPT,
  PSS_STATE,
  PssClient,
  RECEIPT_DOMAIN,
  RequesterLeakError,
  REQUEST_DOMAIN,
  ReceiptSignatureError,
  SchnorrKey,
  SEND_WAIT,
  SidecarError,
  TipReceipts,
  buildTipRequest,
  buildTipRequestWith,
  chainRequestId,
  checkReceiptAnswer,
  commitmentValues,
  computeRequestLogTag,
  computeSealedLogTag,
  fieldHex,
  envelopeNonce,
  inputsCommitment,
  intakeEnvelopeAd,
  intakeLayout,
  intakeModule,
  intakeRequestLogs,
  intakeSummary,
  isQueued,
  machineRequestId,
  newUserNonce,
  noirReceipt,
  normaliseSignature,
  onchainIntake,
  onchainIntakeArgs,
  openEnvelope,
  parseManifest,
  parsePlainRequestLog,
  receiptIntake,
  receiptIntakeArgs,
  receiptMessage,
  sharedReceiptMessage,
  sharedReceiptMessageOf,
  shareHash,
  sharedChainRequestId,
  signatureFromBytes,
  submitIntake,
  tipInputs,
  tipInputsByName,
  tipInputsHash,
  verifyReceipts,
  type IntakeAsk,
  type PssClientConfig,
  type ReceiptIntakeInput,
  type Signature,
  type Triple,
} from "../src/internal.ts";
import { MockOrchestrator, type Received, hex, hash, queued, repoJson, vectorJson } from "@aztec-pss/test-support";


const KEY_VECTORS = vectorJson("keys.json") as {
  nodes: { enc: string; enc_pk: { x: string; y: string }; sig: string; sig_pk: { x: string; y: string } }[];
};
const NODE_KEYS = KEY_VECTORS.nodes.map((n) => ({ enc: n.enc_pk, sig: n.sig_pk })) as PssClientConfig["nodeKeys"];
const SIG_KEYS = KEY_VECTORS.nodes.map((n) => n.sig_pk) as Triple<{ x: string; y: string }>;
const NODE_SIGNERS = KEY_VECTORS.nodes.map((n) => SchnorrKey.fromHex(n.sig));

// ---- the shared vectors ----

const CHAIN_IDS = vectorJson("chain_request_id.json") as {
  pss_attempt: string;
  vectors: {
    name: string;
    namespace: string;
    vk_hash: string;
    inputs: string[];
    inputs_hash: string;
    user_nonce: string;
    chain_request_id: string;
    request_log: string[];
    old_commitments: string[];
    pinned_reads: string[];
    machine_request_id: string;
  }[];
};

describe("chain_request_id.json through buildTipRequestWith and machineRequestId", () => {
  test("PSS_ATTEMPT is the file's", () => assert.equal(hex(PSS_ATTEMPT), CHAIN_IDS.pss_attempt));
  for (const v of CHAIN_IDS.vectors) {
    test(v.name, async () => {
      const r = await buildTipRequestWith({ namespace: v.namespace, vkHash: v.vk_hash, inputs: v.inputs }, v.user_nonce);
      assert.equal(r.inputsHash, v.inputs_hash);
      assert.equal(r.chainRequestId, v.chain_request_id);
      assert.deepEqual(r.inputs, v.inputs);
      assert.equal(hex(await tipInputsHash(v.inputs)), v.inputs_hash);
      assert.equal(hex(await chainRequestId(v.namespace, v.vk_hash, v.inputs_hash, v.user_nonce)), v.chain_request_id);
      assert.equal(hex(await machineRequestId(v.chain_request_id, v.old_commitments, v.pinned_reads)), v.machine_request_id);
      if (v.pinned_reads.length > 0) {
        // a moved pinned value is another attempt at the same state
        const moved = v.pinned_reads.map((x, q) => (q === 0 ? BigInt(x) + 1n : BigInt(x)));
        assert.notEqual(hex(await machineRequestId(v.chain_request_id, v.old_commitments, moved)), v.machine_request_id);
      }
    });
  }
});

describe("chain_request_id.json's request logs through onchainIntake and parsePlainRequestLog", () => {
  for (const v of CHAIN_IDS.vectors) {
    test(v.name, async () => {
      const request = await buildTipRequestWith({ namespace: v.namespace, vkHash: v.vk_hash, inputs: v.inputs }, v.user_nonce);
      assert.deepEqual(await onchainIntake.requestLogs({ intake: "onchain", request }), [v.request_log]);
      const log = await parsePlainRequestLog(v.request_log, { namespace: v.namespace, vkHash: v.vk_hash }, v.inputs.length);
      assert.deepEqual(log, { tag: v.request_log[0], inputs: v.inputs, userNonce: v.user_nonce, inputsHash: v.inputs_hash, requestId: v.chain_request_id });
      assert.deepEqual(await parsePlainRequestLog(v.request_log), { tag: v.request_log[0], inputs: v.inputs, userNonce: v.user_nonce });
    });
  }
});

const RECEIPTS = vectorJson("receipts.json") as {
  receipt_domain: string;
  nodes: { node: number; sig_pk: { x: string; y: string } }[];
  vectors: {
    name: string;
    namespace: string;
    vk_hash: string;
    inputs: string[];
    inputs_hash: string;
    user_nonce: string;
    request_id: string;
    expiry_block: number;
    message: string;
    signatures: Signature[];
    signature_bytes: string[];
  }[];
};

describe("receipts.json through receiptMessage, verifyReceipts and checkReceiptAnswer", () => {
  test("RECEIPT_DOMAIN and the nodes' sig keys are the files'", () => {
    assert.equal(hex(RECEIPT_DOMAIN), RECEIPTS.receipt_domain);
    assert.deepEqual(RECEIPTS.nodes.map((n) => n.sig_pk), SIG_KEYS);
  });
  const pinned = RECEIPTS.nodes.map((n) => n.sig_pk) as Triple<{ x: string; y: string }>;
  for (const v of RECEIPTS.vectors) {
    test(v.name, async () => {
      const r = await buildTipRequestWith({ namespace: v.namespace, vkHash: v.vk_hash, inputs: v.inputs }, v.user_nonce);
      assert.equal(r.chainRequestId, v.request_id);
      assert.equal(r.inputsHash, v.inputs_hash);
      assert.equal(hex(await receiptMessage(v.request_id, v.inputs_hash, v.expiry_block)), v.message);
      const sigs = v.signatures as Triple<Signature>;
      v.signature_bytes.forEach((b, i) => assert.deepEqual(normaliseSignature(signatureFromBytes(Buffer.from(b.slice(2), "hex"))), normaliseSignature(sigs[i]!)));
      await verifyReceipts(v.request_id, v.inputs_hash, v.expiry_block, sigs, pinned, receiptMessage);
      // node 0's receipt in node 1's position (and the reverse) is refused, naming node 0
      await assert.rejects(verifyReceipts(v.request_id, v.inputs_hash, v.expiry_block, [sigs[1]!, sigs[0]!, sigs[2]!], pinned, receiptMessage), (e: unknown) => e instanceof ReceiptSignatureError && e.node === 0);
      // another expiry is another message
      await assert.rejects(verifyReceipts(v.request_id, v.inputs_hash, v.expiry_block - 1, sigs, pinned, receiptMessage), ReceiptSignatureError);
      const answer = { request_id: v.request_id, inputs_hash: v.inputs_hash, expiry_block: v.expiry_block, signatures: sigs };
      await checkReceiptAnswer(answer, { requestId: r.chainRequestId, inputsHash: r.inputsHash, currentBlock: v.expiry_block - 300, ttlBlocks: 300, signs: receiptMessage }, pinned);
      // the Noir Receipt shape carries the wire limbs as field elements
      const nr = noirReceipt(sigs[0]!);
      assert.deepEqual([...nr.s, ...nr.e].map((x) => hex(x)), [...sigs[0]!.s, ...sigs[0]!.e].map((x) => fieldHex(x)));
    });
  }
});

describe("log_tags.json through computeRequestLogTag and computeSealedLogTag", () => {
  const file = vectorJson("log_tags.json") as { request_domain: number; pss_state: number; vectors: { chain_request_id: string; request_tag: string; sealed_tag: string }[] };
  test("REQUEST_DOMAIN and PSS_STATE are the file's", () => {
    assert.equal(REQUEST_DOMAIN, file.request_domain);
    assert.equal(PSS_STATE, file.pss_state);
  });
  test("each request tag and sealed-thirds tag", async () => {
    for (const v of file.vectors) {
      assert.equal(hex(await computeRequestLogTag(v.chain_request_id)), v.request_tag);
      assert.equal(hex(await computeSealedLogTag(v.chain_request_id)), v.sealed_tag);
    }
  });
});

// ---- buildTipRequest ----

describe("buildTipRequest", () => {
  const base = { namespace: 0x1234n, vkHash: 0xabcdn, inputs: [5000n, 0n] };
  test("a fresh 128-bit user_nonce per request, and the id it gives", async () => {
    const a = await buildTipRequest(base);
    const b = await buildTipRequest(base);
    assert.match(a.userNonce, /^0x0{32}[0-9a-f]{32}$/);
    assert.notEqual(a.userNonce, b.userNonce);
    assert.notEqual(a.chainRequestId, b.chainRequestId);
    assert.equal(a.inputsHash, b.inputsHash);
    assert.equal(a.chainRequestId, hex(await hash([base.namespace, base.vkHash, a.inputsHash, a.userNonce])));
    assert.match(newUserNonce(), /^0x0{32}[0-9a-f]{32}$/);
  });
  test("the caller's static check runs on the ABI-order inputs", async () => {
    const valid = (x: readonly bigint[]) => x[0] !== 0n && x[0]! < 1n << 64n && (x[1] === 0n || x[1] === 1n);
    await buildTipRequest({ ...base, isValid: valid });
    await assert.rejects(buildTipRequest({ ...base, inputs: [0n, 0n], isValid: valid }), RangeError);
    await assert.rejects(buildTipRequest({ ...base, inputs: [1n, 2n], isValid: valid }), RangeError);
  });
  test("an input at the modulus is refused", async () => {
    await assert.rejects(buildTipRequest({ ...base, inputs: ["0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001"] }), RangeError);
  });
});

// ---- the app inputs' order ----

const field = { kind: "field" };
const arr = (n: number, t: unknown = field) => ({ kind: "array", length: n, type: t });
// A receipt intake swap shaped like amm_swap_tip_receipt, with a u64 min_out, a
// two-element `path` filled by one name, and a pinned public read.
const SWAP_ABI = {
  abi: {
    parameters: [
      { name: "namespace", type: field, visibility: "public" },
      { name: "in_slots", type: arr(1), visibility: "public" },
      { name: "out_slots", type: arr(1), visibility: "public" },
      { name: "price", type: field, visibility: "public" },
      { name: "amount_in", type: field, visibility: "private" },
      { name: "direction", type: field, visibility: "private" },
      { name: "min_out", type: { kind: "integer", sign: "unsigned", width: 64 }, visibility: "private" },
      { name: "path", type: arr(2), visibility: "private" },
      { name: "again", type: field, visibility: "private" },
      { name: "pool", type: arr(2), visibility: "private" },
      { name: "r_old", type: field, visibility: "private" },
    ],
    return_type: {
      abi_type: { kind: "struct", path: "Out", fields: [{ name: "request_id", type: field }, { name: "old_c", type: field }, { name: "new_c", type: field }] },
      visibility: "public",
    },
  },
};
const swapManifest = (intake: "receipt" | "onchain", over: Record<string, unknown> = {}) => ({
  manifest: 1,
  circuit: `swap_${intake}`,
  namespace_param: "namespace",
  state_keys: { reads: 1, writes: 1 },
  intake,
  // a round that completes no partial note
  outcome: "none",
  binding: "turn",
  witness: [
    { param: "namespace", from: { PUBLIC: "$namespace" } },
    { param: "in_slots", from: { PUBLIC: ["$state_keys.reads[0]"] } },
    { param: "out_slots", from: { PUBLIC: ["$state_keys.writes[0]"] } },
    { param: "price", from: { PUBLIC: "price" } },
    { param: "amount_in", from: { PUBLIC: "amount_in" } },
    { param: "direction", from: { PUBLIC: "direction" } },
    { param: "min_out", from: { PUBLIC: "min_out" } },
    { param: "path", from: { PUBLIC: "path" } },
    // a name used twice counts once
    { param: "again", from: { PUBLIC: "amount_in" } },
    { param: "pool", from: { LOAD: "$state_keys.reads[0]", slice: [0, 2], len: 3 } },
    { param: "r_old", from: { LOAD: "$state_keys.reads[0]", slice: [2, 3], len: 3 } },
  ],
  outputs: [{ TACEO_store: "out0", STORE: "$state_keys.writes[0]", len: 3, note_hash: "new_c" }],
  state: { "$state_keys.reads[0]": "chain", "$state_keys.writes[0]": "chain" },
  commitment_slot: { "$state_keys.reads[0]": { old: "old_c" } },
  public_reads: [{ contract: "0x01", function: "get_price", args: [], param: "price" }],
  ...over,
});

// A tip manifest JSON, parsed (intakeLayout takes the parsed manifest).

describe("intakeLayout and tipInputs: the order inputs_hash hashes and the typed ranges", () => {
  const layout = intakeLayout(SWAP_ABI, queued(swapManifest("receipt")));
  const named = { amount_in: 5000n, direction: 1n, min_out: 7n, path: [0xaan, 0xbbn] };
  test("request public names in ABI walk order; $namespace, keys, LOADs and the public read are not inputs", () => {
    assert.equal(layout.intake, "receipt");
    assert.equal(intakeLayout(SWAP_ABI, queued(swapManifest("onchain"))).intake, "onchain");
    assert.deepEqual(layout.keys, ["amount_in", "direction", "min_out", "path[0]", "path[1]"]);
    assert.deepEqual(tipInputs(layout, named), [5000n, 1n, 7n, 0xaan, 0xbbn].map((x) => fieldHex(x)));
  });
  test("tipInputsByName is the inverse, in the public-map spelling", () => {
    const inputs = tipInputs(layout, named);
    assert.deepEqual(tipInputsByName(layout, inputs), {
      amount_in: fieldHex(5000n),
      direction: fieldHex(1n),
      min_out: fieldHex(7n),
      path: [fieldHex(0xaan), fieldHex(0xbbn)],
    });
    assert.deepEqual(tipInputs(layout, tipInputsByName(layout, inputs)), inputs);
    assert.throws(() => tipInputsByName(layout, inputs.slice(1)), RangeError);
  });
  test("a missing, an extra, a $-name and an out-of-range input are refused, naming it", () => {
    const { min_out: _drop, ...missing } = named;
    assert.throws(() => tipInputs(layout, missing), /inputs\.min_out: missing/);
    assert.throws(() => tipInputs(layout, { ...named, extra: 1n }), /inputs\.extra: unexpected/);
    assert.throws(() => tipInputs(layout, { ...named, price: 1n }), /inputs\.price: unexpected/);
    assert.throws(() => tipInputs(layout, { ...named, $namespace: 1n }), /not a public value name/);
    assert.throws(() => tipInputs(layout, { ...named, min_out: 1n << 64n }), /min_out.*64 bit/);
    tipInputs(layout, { ...named, min_out: (1n << 64n) - 1n });
    // raw Fields are unchecked: the app's predicate is what catches them
    tipInputs(layout, { ...named, direction: 2n });
  });
  test("INPUT_SHARED under a non-secret-shared intake, an intake direct manifest and a parameter without an entry are refused", () => {
    const m = swapManifest("receipt");
    const shared = { ...m, witness: m.witness.map((w) => (w.param === "direction" ? { param: "direction", from: { INPUT_SHARED: "direction" } } : w)) };
    assert.throws(() => intakeLayout(SWAP_ABI, queued(shared)), /INPUT_SHARED; intake receipt takes no shared input/);
    const { binding: _b, commitment_slot: _c, outcome: _o, ...rest } = m;
    // an intake direct manifest has no intake layout: the configuration builds none for it
    assert.equal(isQueued(parseManifest({ ...rest, intake: "direct", state: {} })), false);
    assert.throws(() => intakeLayout(SWAP_ABI, queued({ ...m, witness: m.witness.filter((w) => w.param !== "r_old") })), /r_old.*no witness entry/);
  });
});

// The node's receipt route on the AMM tip's receipt-intake manifest, whose vk_hash
// and user_nonce are the reserved operands: the client walks the same
// three app inputs the node hashed (testvectors/receipt_route.json).
const ROUTE = vectorJson("receipt_route.json") as {
  manifest: string;
  abi: unknown;
  vk_hash: string;
  body: { namespace: string; inputs: Record<string, string>; user_nonce: string; expiry_block: number };
  inputs: string[];
  inputs_hash: string;
  request_id: string;
  signatures: Signature[];
};

describe("receipt_route.json: intakeLayout skips the reserved operands as the node does", () => {
  const manifest = repoJson(ROUTE.manifest);
  const layout = intakeLayout(ROUTE.abi, queued(manifest));
  test("the app inputs are amount_in, direction, min_out and the partial note; $vk_hash and $user_nonce are not", async () => {
    assert.equal(layout.circuit, "amm_swap_tip_receipt");
    assert.deepEqual(layout.keys, ["amount_in", "direction", "min_out", "partial_note"]);
    const inputs = tipInputs(layout, ROUTE.body.inputs);
    assert.deepEqual(inputs, ROUTE.inputs);
    assert.equal(hex(await tipInputsHash(inputs)), ROUTE.inputs_hash);
    const r = await buildTipRequestWith(
      { namespace: ROUTE.body.namespace, vkHash: ROUTE.vk_hash, inputs },
      ROUTE.body.user_nonce,
    );
    assert.equal(r.chainRequestId, ROUTE.request_id);
    await verifyReceipts(ROUTE.request_id, ROUTE.inputs_hash, ROUTE.body.expiry_block, ROUTE.signatures as Triple<Signature>, SIG_KEYS, receiptMessage);
  });
  test("naming a reserved value among the inputs is refused, as the node refuses it", () => {
    for (const name of ["vk_hash", "user", "user_nonce"]) {
      assert.throws(() => tipInputs(layout, { ...ROUTE.body.inputs, [name]: "0x01" }), new RegExp(`inputs\\.${name}: unexpected`));
    }
  });
});

// ---- the receipt flow ----

const NS = "0x1ac1704880851219793ebcb14b7d910d576186d4846fa8b42b51108ebd236888";
const VK = "0x2f6b59841e2b734fd187ca207ac63a4407b68fc31cf3a9a804eaeaf5295b82ab";
const USER = "0x0b7e3a1f00c0ffee00000000000000000000000000000000000000000000beef";
const CURRENT = 1000;

type Signer = (body: Record<string, unknown>, expiry: number) => Promise<{ status: number; body: unknown }>;

describe("PssClient.obtainIntake under receipt intake against a mock orchestrator", () => {
  const mock = new MockOrchestrator();
  let url: string;
  let reply: { expiry?: (current: number) => number; tamper?: (sigs: Signature[], requestId: string, inputsHash: string) => Promise<Signature[]> | Signature[]; requestId?: (id: string) => Promise<string> | string } = {};

  // The orchestrator's job as sidecar-tip and the nodes do it, computed here
  // independently: ABI-order inputs, both ids, three signatures.
  const sign: Signer = async (b, expiry) => {
    const inputs = b.inputs as Record<string, string | string[]>;
    const ordered = [inputs.amount_in, inputs.direction, inputs.min_out, ...(inputs.path as string[])] as string[];
    const inputsHash = hex(await hash(ordered));
    let requestId = hex(await hash([b.namespace as string, VK, inputsHash, b.user_nonce as string]));
    if (reply.requestId) requestId = await reply.requestId(requestId);
    const message = await hash([RECEIPT_DOMAIN, requestId, inputsHash, BigInt(expiry)]);
    let sigs: Signature[] = await Promise.all(NODE_SIGNERS.map((k) => k.sign(new Fr(message))));
    if (reply.tamper) sigs = await reply.tamper(sigs, requestId, inputsHash);
    return { status: 200, body: { request_id: requestId, inputs_hash: inputsHash, expiry_block: expiry, signatures: sigs } };
  };

  before(async () => {
    url = await mock.start();
  });
  after(async () => {
    await mock.stop();
  });
  beforeEach(() => {
    mock.received.length = 0;
    reply = {};
    mock.on("GET", "/v1/nodes", () => ({ status: 200, body: { nodes: NODE_KEYS } }));
    mock.on("POST", "/v1/receipt", async (r: Received) => {
      const b = JSON.parse(r.body) as Record<string, unknown>;
      return sign(b, (reply.expiry ?? ((c) => c + 300))(b.current_block as number));
    });
  });

  const client = (over: Partial<PssClientConfig> = {}) =>
    new PssClient({
      orchestratorUrl: url,
      allowInsecureHttp: true,
      nodeKeys: NODE_KEYS,
      vkHashes: { swap_receipt: VK, swap_onchain: VK },
      circuits: { swap_receipt: { circuit: SWAP_ABI, manifest: swapManifest("receipt"), aliasOf: "swap_onchain" }, swap_onchain: { circuit: SWAP_ABI, manifest: swapManifest("onchain") } },
      contractAddress: NS,
      timeoutMs: 2_000,
      ...over,
    });
  const ask = { circuit: "swap_receipt", inputs: { amount_in: 5000n, direction: 1n, min_out: 7n, path: [0xaan, 0xbbn] }, currentBlock: CURRENT };
  // the receipt intake's receipts, as obtainIntake gives them
  const receiptsOf = async (c: PssClient, a: IntakeAsk): Promise<TipReceipts> => {
    const intake = await c.obtainIntake(a);
    assert.equal(intake.intake, "receipt");
    return (intake as ReceiptIntakeInput).receipts;
  };

  test("three valid receipts are accepted, under the client's own ids", async () => {
    const c = client();
    const r = await receiptsOf(c, { ...ask, userNonce: 0xfeedn });
    assert.ok(r instanceof TipReceipts);
    const inputs = [5000n, 1n, 7n, 0xaan, 0xbbn].map((x) => fieldHex(x));
    const inputsHash = hex(await hash(inputs));
    assert.deepEqual(r.inputs, inputs);
    assert.equal(r.inputsHash, inputsHash);
    assert.equal(r.requestId, hex(await hash([NS, VK, inputsHash, 0xfeedn])));
    assert.equal(r.expiryBlock, CURRENT + 300);
    assert.equal(r.userNonce, fieldHex(0xfeedn));
    await verifyReceipts(r.requestId, r.inputsHash, r.expiryBlock, r.receipts, SIG_KEYS, receiptMessage);
    // the body: inputs by public name, no expiry_block
    const sent = JSON.parse(mock.received.find((x) => x.path === "/v1/receipt")!.body);
    assert.deepEqual(sent, {
      namespace: NS,
      circuit: "swap_receipt",
      inputs: { amount_in: inputs[0], direction: inputs[1], min_out: inputs[2], path: [inputs[3], inputs[4]] },
      user_nonce: fieldHex(0xfeedn),
      current_block: CURRENT,
    });
    // the hidden requester: neither the body, the id nor the intake arguments name the sender
    await assertNoRequester([USER], {
      plainIds: [{ chainRequestId: r.requestId, namespace: NS, vkHash: VK, inputs, userNonce: r.userNonce }],
      receiptBodies: [sent],
      callArgs: r.intakeArgs(),
    });
    // asking again with the same nonce gives the same id; the node keys are checked once per client
    const again = await receiptsOf(c, { ...ask, userNonce: r.userNonce, currentBlock: CURRENT + 100 });
    assert.equal(again.requestId, r.requestId);
    assert.equal(again.expiryBlock, CURRENT + 400);
    assert.equal(mock.count("GET", "/v1/nodes"), 1);
    assert.equal(mock.count("POST", "/v1/receipt"), 2);
  });

  test("a random nonce by default", async () => {
    const r = await receiptsOf(client(), ask);
    assert.match(r.userNonce, /^0x0{32}[0-9a-f]{32}$/);
  });

  test("a wrong signature is refused, naming the node", async () => {
    reply.tamper = async (sigs) => [sigs[0]!, await NODE_SIGNERS[1]!.sign(new Fr(1n)), sigs[2]!];
    await assert.rejects(receiptsOf(client(), ask), (e: unknown) => e instanceof ReceiptSignatureError && e.node === 1);
  });

  test("receipts in the wrong node positions are refused", async () => {
    reply.tamper = (sigs) => [sigs[1]!, sigs[0]!, sigs[2]!];
    await assert.rejects(receiptsOf(client(), ask), (e: unknown) => e instanceof ReceiptSignatureError && e.node === 0);
    reply.tamper = (sigs) => [sigs[0]!, sigs[2]!, sigs[1]!];
    await assert.rejects(receiptsOf(client(), ask), (e: unknown) => e instanceof ReceiptSignatureError && e.node === 1);
  });

  test("an answer under another request id is refused, though its signatures verify for it", async () => {
    reply.requestId = (id) => fieldHex(BigInt(id) ^ 1n);
    await assert.rejects(receiptsOf(client(), ask), (e: unknown) => e instanceof ProtocolError && /request_id/.test(e.message));
  });

  test("an expiry beyond the configured TTL, or not after the current block, is refused", async () => {
    reply.expiry = (c) => c + 301;
    await assert.rejects(receiptsOf(client(), ask), (e: unknown) => e instanceof ProtocolError && /at most 300/.test(e.message));
    // a deployment with a longer published TTL
    assert.equal((await receiptsOf(client({ receiptTtlBlocks: 400 }), ask)).expiryBlock, CURRENT + 301);
    reply.expiry = (c) => c;
    await assert.rejects(receiptsOf(client(), ask), (e: unknown) => e instanceof ProtocolError && /not after the current block/.test(e.message));
  });

  test("expiresSoon at the configured margin", async () => {
    const r = await receiptsOf(client(), ask);
    assert.equal(r.marginBlocks, 20);
    assert.equal(r.expiresSoon(CURRENT), false);
    assert.equal(r.expiresSoon(CURRENT + 279), false);
    assert.equal(r.expiresSoon(CURRENT + 280), true);
    assert.equal(r.expiresSoon(CURRENT + 300), true);
    assert.equal(r.expiresSoon(CURRENT + 290, 5), false);
    const wide = await receiptsOf(client({ receiptMarginBlocks: 100 }), ask);
    assert.equal(wide.expiresSoon(CURRENT + 200), true);
  });

  test("a node key other than the pinned one stops the flow before any receipt request", async () => {
    mock.on("GET", "/v1/nodes", () => ({ status: 200, body: { nodes: [NODE_KEYS[0], { ...NODE_KEYS[1], sig: NODE_KEYS[2].sig }, NODE_KEYS[2]] } }));
    await assert.rejects(receiptsOf(client(), ask), (e: unknown) => e instanceof NodeKeyMismatchError && e.index === 1 && e.key === "sig");
    assert.equal(mock.count("POST", "/v1/receipt"), 0);
  });

  test("the node key check runs again when the contract's key epoch moves, against the contract's set", async () => {
    // a contract at epoch 0 (nothing stored), then at epoch 1 under a new set
    let fields: bigint[] = new Array(NODE_KEYS_LEN).fill(0n);
    const keyEpochNode = {
      getBlockNumber: async () => CURRENT,
      getPublicStorageAt: async (_b: never, _c: unknown, slot: Fr) => new Fr(fields[Number(slot.toBigInt() - NODE_KEYS_SLOT)]!),
    };
    const c = client({ keyEpochNode });
    await receiptsOf(c, ask);
    await receiptsOf(c, ask);
    assert.equal(mock.count("GET", "/v1/nodes"), 1);
    fields = Array.from({ length: NODE_KEYS_LEN }, (_, k) => BigInt(k));
    fields[0] = 1n;
    // GET /v1/nodes still reports epoch 0's keys: refused before any receipt request of the new epoch
    const sent = mock.count("POST", "/v1/receipt");
    await assert.rejects(receiptsOf(c, ask), (e: unknown) => e instanceof NodeKeyMismatchError && e.index === 0);
    assert.equal(mock.count("GET", "/v1/nodes"), 2);
    assert.equal(mock.count("POST", "/v1/receipt"), sent);
  });

  test("an orchestrator refusal is a SidecarError", async () => {
    mock.on("POST", "/v1/receipt", () => ({ status: 400, body: { error: "parameter `min_out`: does not fit", class: "bad_request" } }));
    await assert.rejects(receiptsOf(client(), ask), (e: unknown) => e instanceof SidecarError && e.class === "bad_request");
  });

  test("on-chain intake reads no node keys and takes no receipts", async () => {
    const c = client({
      keyEpochNode: {
        getBlockNumber: async () => { throw new Error("on-chain intake needs no key epoch"); },
        getPublicStorageAt: async () => { throw new Error("on-chain intake needs no node keys"); },
      },
    });
    const onchain = await c.obtainIntake({ ...ask, circuit: "swap_onchain", userNonce: 1n });
    assert.equal(onchain.intake, "onchain");
    assert.equal(intakeSummary(onchain).chainRequestId, (await c.tipRequest({ circuit: "swap_onchain", inputs: ask.inputs, userNonce: 1n })).chainRequestId);
    assert.equal(mock.received.length, 0);
  });

  test("an unpinned circuit and bad inputs are refused before anything is sent", async () => {
    const c = client();
    await assert.rejects(receiptsOf(c, { ...ask, circuit: "nope" }), ConfigError);
    await assert.rejects(receiptsOf(c, { ...ask, inputs: { ...ask.inputs, min_out: 1n << 64n } }), RangeError);
    await assert.rejects(receiptsOf(c, { ...ask, isValid: (x) => x[1] === 0n }), RangeError);
    await assert.rejects(receiptsOf(c, { ...ask, currentBlock: -1 }), RangeError);
    assert.equal(mock.received.length, 0);
  });

  test("tipRequest: an on-chain intake request in the configured namespace under the pinned vk hash", async () => {
    const r = await client().tipRequest({ circuit: "swap_onchain", inputs: ask.inputs, userNonce: 1n });
    assert.equal(r.namespace, NS);
    assert.equal(r.vkHash, VK);
    assert.equal(r.chainRequestId, hex(await hash([NS, VK, r.inputsHash, 1n])));
  });
});

// ---- the request functions' arguments and sending ----

// The test contract's two request functions as aztec.js sees them
// (pss_public_contract_test: request_onchain, request_with_receipts).
const RECEIPT_STRUCT = {
  kind: "struct",
  path: "pss_public_contract::receipt::Receipt",
  fields: [
    { name: "s", type: arr(2) },
    { name: "e", type: arr(2) },
  ],
};
const fn = (name: string, parameters: unknown[]): FunctionAbi =>
  ({ name, functionType: "private", isOnlySelf: false, isStatic: false, isInitializer: false, parameters, returnTypes: [], errorTypes: {} }) as unknown as FunctionAbi;
const REQUEST_ONCHAIN = fn("request_onchain", [
  { name: "app_inputs", type: arr(2), visibility: "private" },
  { name: "user_nonce", type: field, visibility: "private" },
]);
const REQUEST_WITH_RECEIPTS = fn("request_with_receipts", [
  { name: "app_inputs", type: arr(2), visibility: "private" },
  { name: "user_nonce", type: field, visibility: "private" },
  { name: "expiry_block", type: { kind: "integer", sign: "unsigned", width: 32 }, visibility: "private" },
  { name: "receipts", type: arr(3, RECEIPT_STRUCT), visibility: "private" },
]);

describe("intakeModule: one module per queued intake", () => {
  test("the lookup maps each manifest value to its module, and the module names it", () => {
    assert.equal(intakeModule("onchain"), onchainIntake);
    assert.equal(intakeModule("receipt"), receiptIntake);
    for (const intake of ["onchain", "receipt", "shared_receipt", "shared_onchain"] as const) {
      assert.equal(intakeModule(intake).intake, intake);
    }
    assert.throws(() => intakeModule("direct" as never), (e: unknown) => e instanceof ConfigError && /not a queued intake/.test(String(e)));
  });
  test("what differs: the request side only (one result call serves both non-secret-shared intakes)", async () => {
    const v = RECEIPTS.vectors[0]!;
    const request = { namespace: v.namespace, vkHash: v.vk_hash, inputs: v.inputs, userNonce: v.user_nonce, inputsHash: v.inputs_hash, chainRequestId: v.request_id };
    // on-chain intake: the request function logs [tag, inputs..., user_nonce]
    const onchain = { intake: "onchain" as const, request };
    const [log] = await intakeRequestLogs(onchain);
    const parsed = await parsePlainRequestLog(log!, { namespace: v.namespace, vkHash: v.vk_hash }, v.inputs.length);
    assert.equal(parsed.requestId, v.request_id);
    assert.deepEqual(intakeSummary(onchain), { chainRequestId: v.request_id, values: v.inputs, userNonce: v.user_nonce, privateValues: [] });
    // receipt intake: no log; the inputs and the nonce stay off the chain
    const receipts = new TipReceipts({ ...request, circuit: "c", requestId: v.request_id, expiryBlock: v.expiry_block, receipts: v.signatures as Triple<Signature>, marginBlocks: 20 });
    assert.deepEqual(await intakeRequestLogs({ intake: "receipt", receipts }), []);
    const s = intakeSummary({ intake: "receipt", receipts });
    assert.equal(s.expiryBlock, v.expiry_block);
    assert.deepEqual(s.privateValues.map(([, x]) => x), [...v.inputs, v.user_nonce]);
  });
});

describe("intake arguments and submitIntake", () => {
  const v = RECEIPTS.vectors[0]!;
  const sigs = v.signatures as Triple<Signature>;
  const receipts = new TipReceipts({
    namespace: v.namespace,
    circuit: "amm_swap_tip_receipt",
    requestId: v.request_id,
    inputsHash: v.inputs_hash,
    expiryBlock: v.expiry_block,
    receipts: sigs,
    inputs: v.inputs,
    userNonce: v.user_nonce,
    marginBlocks: 20,
  });

  test("on-chain intake: (inputs, user_nonce), encoded as request_onchain takes them", () => {
    const args = onchainIntakeArgs({ inputs: v.inputs, userNonce: v.user_nonce });
    assert.equal(args.length, 2);
    assert.ok(args[0].every((x) => x instanceof Fr) && args[1] instanceof Fr);
    assert.deepEqual(encodeArguments(REQUEST_ONCHAIN, args).map((x) => x.toString()), [...v.inputs, v.user_nonce]);
  });

  test("receipt intake: (inputs, user_nonce, expiry_block, receipts as {s: [lo, hi], e: [lo, hi]}), encoded as request_with_receipts takes them", () => {
    const args = receiptIntakeArgs({ inputs: v.inputs, userNonce: v.user_nonce, expiryBlock: v.expiry_block, receipts: sigs });
    assert.deepEqual(receipts.intakeArgs(), args);
    assert.equal(args[2], v.expiry_block);
    assert.equal(args[3].length, 3);
    const flat = encodeArguments(REQUEST_WITH_RECEIPTS, args).map((x) => x.toString());
    assert.deepEqual(flat, [...v.inputs, v.user_nonce, fieldHex(v.expiry_block), ...sigs.flatMap((s) => [...s.s, ...s.e])]);
    assert.throws(() => receiptIntakeArgs({ inputs: v.inputs, userNonce: v.user_nonce, expiryBlock: -1, receipts: sigs }), RangeError);
    assert.throws(() => receiptIntakeArgs({ inputs: v.inputs, userNonce: v.user_nonce, expiryBlock: 1, receipts: sigs.slice(0, 2) as never }), RangeError);
  });

  // A stand-in for aztec.js: methods return an interaction whose send records
  // the arguments and the options.
  const calls: { method: string; args: unknown[]; opts: unknown }[] = [];
  const interaction = (method: string) => (...args: unknown[]) => ({
    send: async (opts: unknown) => {
      calls.push({ method, args, opts });
      return { txHash: `0x${method}` };
    },
  });
  const contract = { methods: { request_onchain: interaction("request_onchain"), request_with_receipts: interaction("request_with_receipts") } };
  const request = { namespace: v.namespace, vkHash: v.vk_hash, inputs: v.inputs, userNonce: v.user_nonce, inputsHash: v.inputs_hash, chainRequestId: v.request_id };

  test("submitIntake sends through a contract and method name, or a factory", async () => {
    calls.length = 0;
    const from = { toBigInt: () => BigInt(USER) };
    const one = await submitIntake({ contract, method: "request_onchain" }, { intake: "onchain", request }, { from, fee: "x" });
    assert.deepEqual(one, { txHash: "0xrequest_onchain" });
    assert.deepEqual(calls[0]!.args, onchainIntakeArgs({ inputs: v.inputs, userNonce: v.user_nonce }));
    assert.deepEqual(calls[0]!.opts, { wait: SEND_WAIT, from, fee: "x" });
    await submitIntake(contract.methods.request_with_receipts, { intake: "receipt", receipts }, { from, fee: "x" }, { currentBlock: v.expiry_block - 100 });
    assert.equal(calls[1]!.method, "request_with_receipts");
    assert.deepEqual(calls[1]!.args, receipts.intakeArgs());
    assert.deepEqual(calls[1]!.opts, { wait: SEND_WAIT, from, fee: "x" });
  });

  test("submitIntake sends the same arguments from any account (no request names its sender)", async () => {
    calls.length = 0;
    const onchain = { intake: "onchain" as const, request };
    await submitIntake({ contract, method: "request_onchain" }, onchain, { from: 0x1234n, fee: "x" });
    await submitIntake({ contract, method: "request_onchain" }, onchain, { from: USER, fee: "x" });
    assert.deepEqual(calls[0]!.args, calls[1]!.args);
    await assertNoRequester([0x1234n, USER], { callArgs: calls.flatMap((c) => c.args) });
  });

  test("submitIntake refuses receipts that expire soon, and an unknown method", async () => {
    calls.length = 0;
    const onchain = { intake: "onchain" as const, request };
    await assert.rejects(submitIntake({ contract, method: "request_with_receipts" }, { intake: "receipt", receipts }, { from: USER }, { currentBlock: v.expiry_block - 20 }), /ask again/);
    await assert.rejects(submitIntake({ contract, method: "nope" }, onchain, { from: USER }), /no method nope/);
    assert.equal(calls.length, 0);
  });
});

// ---- the on-chain request log ----

describe("parsePlainRequestLog", () => {
  test("[tag, inputs, user_nonce] read and checked against the recomputed id", async () => {
    const r = await buildTipRequestWith({ namespace: NS, vkHash: VK, inputs: [5000n, 1n, 7n] }, 0xfeedn);
    const tag = hex(await computeRequestLogTag(r.chainRequestId));
    const fields = [tag, ...r.inputs, r.userNonce];
    const bare = await parsePlainRequestLog(fields);
    assert.deepEqual(bare, { tag, inputs: r.inputs, userNonce: r.userNonce });
    const checked = await parsePlainRequestLog(fields, { namespace: NS, vkHash: VK }, 3);
    assert.equal(checked.requestId, r.chainRequestId);
    assert.equal(checked.inputsHash, r.inputsHash);
    // another input, another vk hash or another namespace: the tag no longer matches
    const moved = [tag, fieldHex(5001n), ...fields.slice(2)];
    await assert.rejects(parsePlainRequestLog(moved, { namespace: NS, vkHash: VK }), ProtocolError);
    await assert.rejects(parsePlainRequestLog(fields, { namespace: NS, vkHash: 1n }), ProtocolError);
    await assert.rejects(parsePlainRequestLog(fields, { namespace: 2n, vkHash: VK }), ProtocolError);
    await assert.rejects(parsePlainRequestLog(fields, undefined, 2), ProtocolError);
    await assert.rejects(parsePlainRequestLog(fields.slice(0, 1)), ProtocolError);
    await assertNoRequester([USER], { logs: [fields] });
  });
});

describe("assertNoRequester", () => {
  test("finds an address anywhere in a value, naming the place and the path", async () => {
    await assertNoRequester([USER], { receiptBodies: [{ inputs: { a: "0x01" }, user_nonce: "0x02" }], callArgs: [[new Fr(3n)], 4n] });
    await assert.rejects(
      assertNoRequester([USER], { receiptBodies: [{ inputs: { a: "0x01", b: [USER] } }] }),
      (e: unknown) => e instanceof RequesterLeakError && e.place === "receipt body" && e.path === "[0].inputs.b[0]",
    );
    await assert.rejects(assertNoRequester([BigInt(USER)], { callArgs: [new Fr(BigInt(USER))] }), RequesterLeakError);
    await assert.rejects(assertNoRequester([USER], { publicInputs: [1n, BigInt(USER)] }), RequesterLeakError);
  });
  test("a non-secret-shared id must be the requester-free id of its parts", async () => {
    const r = await buildTipRequestWith({ namespace: NS, vkHash: VK, inputs: [5n] }, 9n);
    const id = { chainRequestId: r.chainRequestId, namespace: NS, vkHash: VK, inputs: [5n], userNonce: 9n };
    await assertNoRequester([USER], { plainIds: [id] });
    const withUser = hex(await hash([NS, VK, r.inputsHash, USER, 9n]));
    await assert.rejects(assertNoRequester([USER], { plainIds: [{ ...id, chainRequestId: withUser }] }), /not the requester-free id/);
  });
});

// ---- secret-shared receipt intake (testvectors/shared_intake.json) ----

// sidecar-tip's vectors module writes the file: the commitment walk, C and
// the chain request id of a secret-shared receipt intake request, node i's envelope
// of every shared value under the intake associated data, the salts' last,
// and the receipts over C and the sharing digest D. The client reproduces
// each through its own functions.
const SHARED = vectorJson("shared_intake.json") as {
  manifest: string;
  abi: unknown;
  circuit: string;
  vk_hash: string;
  namespace: string;
  intake_ad: string;
  values: Record<string, string>;
  commitment_names: string[];
  commitment_values: string[];
  blinding: string;
  inputs_commitment: string;
  chain_request_id: string;
  shared_inputs: { name: string; shares: Triple<{ eph: { x: string; y: string }; ct: [string, string]; tag: string }>; share_hashes: Triple<string> }[];
  envelopes: { name: string; value: string; sharing: Triple<string>; nodes: { node: number; pair: [string, string]; eph_secret: string; nonce: string }[] }[];
  receipt_body_node0: { inputs: Record<string, string>; inputs_hash: string };
  sharing_digest: string;
  summand_salt_name: string;
  receipt: { expiry_block: number; message: string; message_preimage: string[]; signatures: Triple<Signature> };
};

describe("secret-shared receipt intake (testvectors/shared_intake.json)", () => {
  const manifest = repoJson(SHARED.manifest);
  const layout = intakeLayout(SHARED.abi, queued(manifest));

  test("the walk: clear keys, the shared names, and C's order with $blinding last", () => {
    assert.equal(layout.intake, "shared_receipt");
    assert.deepEqual(layout.keys, Object.keys(SHARED.receipt_body_node0.inputs));
    assert.deepEqual(layout.commitment, SHARED.commitment_names);
    assert.deepEqual([...layout.shared, SHARED.summand_salt_name], SHARED.shared_inputs.map((s) => s.name));
    assert.deepEqual(commitmentValues(layout, SHARED.values).map((v) => hex(v)), SHARED.commitment_values);
    assert.throws(() => commitmentValues(layout, { amount: 1n }), /values\.position: missing/);
    // the non-secret-shared intakes' commitment is their keys, and they share nothing
    const plain = intakeLayout(SWAP_ABI, queued(swapManifest("receipt")));
    assert.deepEqual([plain.commitment, plain.shared], [plain.keys, []]);
  });

  test("C and the chain request id", async () => {
    const c = await inputsCommitment(SHARED.commitment_values, SHARED.blinding);
    assert.equal(hex(c), SHARED.inputs_commitment);
    assert.equal(hex(await sharedChainRequestId(SHARED.namespace, SHARED.vk_hash, c)), SHARED.chain_request_id);
  });

  test("node i opens its own envelope of every shared value under the intake associated data", async () => {
    assert.equal(hex(SIDECAR_INTAKE_AD), SHARED.intake_ad);
    for (const [k, s] of SHARED.shared_inputs.entries()) {
      const d = SHARED.envelopes[k]!;
      const ad = intakeEnvelopeAd(SHARED.namespace, SHARED.chain_request_id, SHARED.circuit, s.name);
      for (let i = 0; i < 3; i++) {
        assert.equal(hex(await envelopeNonce(ad, i)), d.nodes[i]!.nonce, `${s.name}: node ${i}`);
        const pair = await openEnvelope(KEY_VECTORS.nodes[i]!.enc, i, ad, s.shares[i]!);
        assert.deepEqual(pair.map((v) => hex(v)), d.nodes[i]!.pair);
        assert.equal(await shareHash(s.shares[i]!), s.share_hashes[i]);
      }
    }
  });

  test("each node's receipt over C and D verifies, and only over the five-element message", async () => {
    const { expiry_block: expiry, signatures } = SHARED.receipt;
    assert.deepEqual(SHARED.receipt.message_preimage, [hex(RECEIPT_DOMAIN), SHARED.chain_request_id, SHARED.inputs_commitment, hex(expiry), SHARED.sharing_digest]);
    const message = await sharedReceiptMessage(SHARED.chain_request_id, SHARED.inputs_commitment, expiry, SHARED.sharing_digest);
    assert.equal(hex(message), SHARED.receipt.message);
    await verifyReceipts(SHARED.chain_request_id, SHARED.inputs_commitment, expiry, signatures, SIG_KEYS, sharedReceiptMessageOf(SHARED.sharing_digest));
    // not receipt intake's four-element message, nor another D
    assert.notEqual(hex(await receiptMessage(SHARED.chain_request_id, SHARED.inputs_commitment, expiry)), SHARED.receipt.message);
    await assert.rejects(verifyReceipts(SHARED.chain_request_id, SHARED.inputs_commitment, expiry, signatures, SIG_KEYS, receiptMessage), ReceiptSignatureError);
    await assert.rejects(verifyReceipts(SHARED.chain_request_id, SHARED.inputs_commitment, expiry, signatures, SIG_KEYS, sharedReceiptMessageOf(hex(BigInt(SHARED.sharing_digest) ^ 1n))), ReceiptSignatureError);
  });
});
