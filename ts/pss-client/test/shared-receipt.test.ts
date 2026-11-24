// Secret-shared receipt intake on the client side (src/intake-shared-receipt.ts and
// PssClient.obtainIntake and requestIntake): testvectors/shared_intake.json reproduced
// through the request builder, the sharing and its commitments included; a
// request with fresh randomness opened by the three nodes, whose pairs are
// the summand vectors; the refusals; the request function's arguments as
// aztec.js encodes them; and the receipt flow against a mock orchestrator,
// with the receipts over C and D and the audit that no shared value, no
// summand and no account reaches the orchestrator.

import assert from "node:assert/strict";
import { after, before, beforeEach, describe, test } from "node:test";

import { Fr } from "@aztec-labs/foundation/curves/bn254";
import { encodeArguments, type FunctionAbi } from "@aztec-labs/stdlib/abi";

import {
  BN254_MODULUS,
  ConfigError,
  ProtocolError,
  PssClient,
  RECEIPT_DOMAIN,
  ReceiptSignatureError,
  SHARING_DOMAIN,
  SUMMANDS_DOMAIN,
  SUMMAND_SALT_NAME,
  SEND_WAIT,
  SchnorrKey,
  SharedReceipts,
  assertNoRequester,
  buildSharedReceiptRequest,
  drawSharedSecrets,
  fieldHex,
  intakeEnvelopeAd,
  intakeLayout,
  isQueued,
  openEnvelope,
  parseManifest,
  sharedReceiptBody,
  sharedReceiptIntakeArgs,
  sharingDigest,
  summandCommitment,
  summandNames,
  intakeSummary,
  valueKinds,
  type IntakeAsk,
  type PssClientConfig,
  type SharedReceiptIntakeInput,
  type Signature,
  type Triple,
} from "../src/internal.ts";
import { MockOrchestrator, type Received, hex, hash, repoJson, vectorJson } from "@aztec-pss/test-support";


const KEYS = vectorJson("keys.json") as {
  nodes: { enc: string; enc_pk: { x: string; y: string }; sig: string; sig_pk: { x: string; y: string } }[];
};
const NODE_KEYS = KEYS.nodes.map((n) => ({ enc: n.enc_pk, sig: n.sig_pk })) as PssClientConfig["nodeKeys"];
const ENC_KEYS = KEYS.nodes.map((n) => n.enc_pk) as Triple<{ x: string; y: string }>;
const SIGNERS = KEYS.nodes.map((n) => SchnorrKey.fromHex(n.sig));

type Envelope = { eph: { x: string; y: string }; ct: [string, string]; tag: string };
const SHARED = vectorJson("shared_intake.json") as {
  manifest: string;
  abi: unknown;
  circuit: string;
  vk_hash: string;
  namespace: string;
  values: Record<string, string>;
  commitment_names: string[];
  commitment_values: string[];
  blinding: string;
  inputs_commitment: string;
  chain_request_id: string;
  summands_domain: string;
  sharing_domain: string;
  summand_names: string[];
  summand_salt_name: string;
  summands: Triple<string[]>;
  salts: Triple<string>;
  summand_commitments: Triple<string>;
  value_kinds: string[];
  clear_values: string[];
  sharing_digest: string;
  shared_inputs: { name: string; shares: Triple<Envelope>; share_hashes: Triple<string> }[];
  envelopes: { name: string; value: string; sharing: Triple<string>; nodes: { node: number; pair: [string, string]; eph_secret: string }[] }[];
  receipt_body_node0: {
    inputs: Record<string, string>;
    inputs_hash: string;
    summand_commitments: Triple<string>;
    sharing_digest: string;
    shared_inputs: { name: string; share: Envelope; share_hashes: Triple<string> }[];
  };
};
const MANIFEST = repoJson(SHARED.manifest) as Record<string, unknown>;
const LAYOUT = (() => {
  const m = parseManifest(MANIFEST);
  assert.ok(isQueued(m));
  return intakeLayout(SHARED.abi, m);
})();

// the app inputs by name, as a user gives them; the reserved values are the
// vector's, given as known answers
const INPUTS = { amount: SHARED.values.amount!, position: SHARED.values.position!, $partial_note: SHARED.values["$partial_note"]! };
const SECRETS = {
  blinding: BigInt(SHARED.values.$blinding!),
  outcomeKey: BigInt(SHARED.values.$outcome_key!),
  outcomeTag: BigInt(SHARED.values.$outcome_tag!),
};
const SEAL = Object.fromEntries(SHARED.envelopes.map((e) => [e.name, { sharing: e.sharing, eph: e.nodes.map((n) => n.eph_secret) as Triple<string> }]));

const known = () =>
  buildSharedReceiptRequest(
    { layout: LAYOUT, namespace: SHARED.namespace, vkHash: SHARED.vk_hash, inputs: INPUTS, encKeys: ENC_KEYS },
    { secrets: SECRETS, seal: SEAL },
  );

describe("shared_intake.json through buildSharedReceiptRequest", () => {
  test("C's values, C, the chain request id and the reserved values", async () => {
    const r = await known();
    assert.deepEqual(r.commitmentNames, SHARED.commitment_names);
    assert.deepEqual(r.values, SHARED.commitment_values);
    assert.equal(r.blinding, SHARED.blinding);
    assert.equal(r.inputsCommitment, SHARED.inputs_commitment);
    assert.equal(r.chainRequestId, SHARED.chain_request_id);
    assert.equal(r.outcomeKey, SHARED.values.$outcome_key);
    assert.equal(r.outcomeTag, SHARED.values.$outcome_tag);
    assert.equal(r.circuit, SHARED.circuit);
  });

  test("the summand names, the summand vectors, the salts, S_j and D", async () => {
    const r = await known();
    assert.deepEqual(r.summandNames, SHARED.summand_names);
    assert.deepEqual(summandNames(LAYOUT), SHARED.summand_names);
    assert.equal(SUMMAND_SALT_NAME, SHARED.summand_salt_name);
    assert.deepEqual(r.sharing, { summands: SHARED.summands, salts: SHARED.salts });
    assert.deepEqual(r.summandCommitments, SHARED.summand_commitments);
    assert.equal(r.sharingDigest, SHARED.sharing_digest);
  });

  test("the envelopes of every shared value, the reserved ones included, in ABI order, then the salts'", async () => {
    const r = await known();
    assert.deepEqual(r.sharedInputs, SHARED.shared_inputs);
    assert.deepEqual(r.sharedInputs.map((s) => s.name), [...LAYOUT.shared, SUMMAND_SALT_NAME]);
    assert.deepEqual(r.clearInputs, SHARED.receipt_body_node0.inputs);
  });

  test("the body carries what node 0's projection of it holds, the summand commitments and D among it", async () => {
    const body = sharedReceiptBody(await known(), 1000);
    assert.deepEqual(Object.keys(body).sort(), [
      "circuit",
      "current_block",
      "inputs",
      "inputs_hash",
      "namespace",
      "shared_inputs",
      "sharing_digest",
      "summand_commitments",
    ]);
    assert.equal(body.inputs_hash, SHARED.receipt_body_node0.inputs_hash);
    assert.deepEqual(body.summand_commitments, SHARED.receipt_body_node0.summand_commitments);
    assert.equal(body.sharing_digest, SHARED.receipt_body_node0.sharing_digest);
    assert.equal(body.shared_inputs.at(-1)!.name, SUMMAND_SALT_NAME);
    assert.deepEqual(body.inputs, SHARED.receipt_body_node0.inputs);
    assert.deepEqual(
      body.shared_inputs.map((s) => ({ name: s.name, share: s.shares[0], share_hashes: s.share_hashes })),
      SHARED.receipt_body_node0.shared_inputs,
    );
  });
});

describe("a secret-shared receipt request with fresh randomness", () => {
  test("the client draws the blinding, the outcome key and the outcome tag uniformly, fresh per request", async () => {
    const s = drawSharedSecrets();
    for (const v of [s.blinding, s.outcomeKey, s.outcomeTag]) assert.ok(v >= 0n && v < BN254_MODULUS);
    assert.equal(new Set([s.blinding, s.outcomeKey, s.outcomeTag]).size, 3);
    const build = () => buildSharedReceiptRequest({ layout: LAYOUT, namespace: SHARED.namespace, vkHash: SHARED.vk_hash, inputs: INPUTS, encKeys: ENC_KEYS });
    const [a, b] = [await build(), await build()];
    assert.notEqual(a.chainRequestId, b.chainRequestId);
    assert.notEqual(a.outcomeKey, b.outcomeKey);
    assert.notEqual(a.outcomeTag, b.outcomeTag);
  });

  test("node i opens its own pair of every shared value, and the pairs are one Rep3 sharing of it", async () => {
    const r = await buildSharedReceiptRequest({ layout: LAYOUT, namespace: SHARED.namespace, vkHash: SHARED.vk_hash, inputs: INPUTS, encKeys: ENC_KEYS });
    const salt = hex(r.sharing.salts.reduce((a, b) => a + BigInt(b), 0n) % BN254_MODULUS);
    const value: Record<string, string> = { ...INPUTS, $blinding: r.blinding, $outcome_key: r.outcomeKey, $outcome_tag: r.outcomeTag, [SUMMAND_SALT_NAME]: salt };
    assert.deepEqual(r.sharedInputs.map((s) => s.name), [...LAYOUT.shared, SUMMAND_SALT_NAME]);
    for (const s of r.sharedInputs) {
      const ad = intakeEnvelopeAd(r.namespace, r.chainRequestId, r.circuit, s.name);
      const pairs = await Promise.all([0, 1, 2].map((i) => openEnvelope(KEYS.nodes[i]!.enc, i, ad, s.shares[i]!)));
      // pair_i = [x_i, x_{i-1}]
      for (let i = 0; i < 3; i++) assert.equal(pairs[i]![1], pairs[(i + 2) % 3]![0]);
      assert.equal(hex((pairs[0]![0] + pairs[1]![0] + pairs[2]![0]) % BN254_MODULUS), fieldHex(value[s.name]!));
      // node i cannot open node i+1's envelope
      await assert.rejects(openEnvelope(KEYS.nodes[1]!.enc, 0, ad, s.shares[0]!));
    }
    // C over the values in commitment order, then the blinding
    const c = await hash([...r.values, r.blinding]);
    assert.equal(r.inputsCommitment, hex(c));
    assert.equal(r.chainRequestId, hex(await hash([SHARED.namespace, SHARED.vk_hash, c])));
  });

  test("the summand vectors add up to the shared values and the blinding, and node i's pairs are s_i, s_{i-1} and their salts", async () => {
    const r = await buildSharedReceiptRequest({ layout: LAYOUT, namespace: SHARED.namespace, vkHash: SHARED.vk_hash, inputs: INPUTS, encKeys: ENC_KEYS });
    const { summands, salts } = r.sharing;
    const value: Record<string, string> = { ...INPUTS, $blinding: r.blinding, $outcome_key: r.outcomeKey, $outcome_tag: r.outcomeTag };
    assert.deepEqual(r.summandNames, ["amount", "$partial_note", "$outcome_key", "$outcome_tag", "$blinding"]);
    for (const s of summands) assert.equal(s.length, r.summandNames.length);
    for (const [k, name] of r.summandNames.entries()) {
      const sum = (BigInt(summands[0][k]!) + BigInt(summands[1][k]!) + BigInt(summands[2][k]!)) % BN254_MODULUS;
      assert.equal(hex(sum), fieldHex(value[name]!), name);
    }
    // C's value positions, the blinding last, are the ones the summands add up to
    assert.deepEqual(r.summandNames.slice(0, -1).map((n) => r.values[r.commitmentNames.indexOf(n)]), r.summandNames.slice(0, -1).map((n) => fieldHex(value[n]!)));
    const pairOf = (i: number, column: readonly (string | bigint)[]) => [column[i]!, column[(i + 2) % 3]!].map((v) => BigInt(v));
    const byName = new Map(r.sharedInputs.map((s) => [s.name, s]));
    for (let i = 0; i < 3; i++) {
      for (const [k, name] of r.summandNames.entries()) {
        const ad = intakeEnvelopeAd(r.namespace, r.chainRequestId, r.circuit, name);
        const pair = await openEnvelope(KEYS.nodes[i]!.enc, i, ad, byName.get(name)!.shares[i]!);
        assert.deepEqual(pair, pairOf(i, summands.map((s) => s[k]!)), `${name}: node ${i}`);
      }
      const ad = intakeEnvelopeAd(r.namespace, r.chainRequestId, r.circuit, SUMMAND_SALT_NAME);
      assert.deepEqual(await openEnvelope(KEYS.nodes[i]!.enc, i, ad, byName.get(SUMMAND_SALT_NAME)!.shares[i]!), pairOf(i, salts), `salts: node ${i}`);
    }
    // a fresh salt per vector and per request
    assert.equal(new Set(salts).size, 3);
    const secrets = { blinding: BigInt(r.blinding), outcomeKey: BigInt(r.outcomeKey), outcomeTag: BigInt(r.outcomeTag) };
    const again = await buildSharedReceiptRequest({ layout: LAYOUT, namespace: SHARED.namespace, vkHash: SHARED.vk_hash, inputs: INPUTS, encKeys: ENC_KEYS }, { secrets });
    assert.equal(again.chainRequestId, r.chainRequestId);
    assert.notDeepEqual(again.sharing, r.sharing);
    assert.notEqual(again.sharingDigest, r.sharingDigest);
  });

  test("S_j = poseidon2([SUMMANDS_DOMAIN, s_j..., salt_j]) and D = poseidon2([SHARING_DOMAIN, S_0, S_1, S_2, kinds..., clear values...])", async () => {
    assert.equal(SUMMANDS_DOMAIN, 0x736964656361722e73756d6d616e6473n);
    assert.equal(SHARING_DOMAIN, 0x736964656361722e73686172696e67n);
    assert.equal(hex(SUMMANDS_DOMAIN), SHARED.summands_domain);
    assert.equal(hex(SHARING_DOMAIN), SHARED.sharing_domain);
    const r = await buildSharedReceiptRequest({ layout: LAYOUT, namespace: SHARED.namespace, vkHash: SHARED.vk_hash, inputs: INPUTS, encKeys: ENC_KEYS });
    const S = await Promise.all([0, 1, 2].map((j) => hash([SUMMANDS_DOMAIN, ...r.sharing.summands[j as 0 | 1 | 2], r.sharing.salts[j as 0 | 1 | 2]])));
    assert.deepEqual(r.summandCommitments, S.map(hex));
    // D over them, the kind of each of C's values (position clear) and the
    // clear position
    const kinds = valueKinds(LAYOUT);
    assert.deepEqual(kinds, ["chosen", "clear", "chosen", "chosen", "chosen"]);
    assert.deepEqual(kinds.map((k) => hex(k === "chosen" ? 1n : 0n)), SHARED.value_kinds);
    assert.deepEqual(SHARED.clear_values, [SHARED.values.position]);
    assert.equal(r.sharingDigest, hex(await hash([SHARING_DOMAIN, ...S, 1n, 0n, 1n, 1n, 1n, BigInt(SHARED.values.position!)])));
    // the vector file's, through the client's own functions
    for (let j = 0; j < 3; j++) {
      assert.equal(hex(await summandCommitment(SHARED.summands[j as 0 | 1 | 2], SHARED.salts[j as 0 | 1 | 2])), SHARED.summand_commitments[j]);
    }
    assert.equal(hex(await sharingDigest(SHARED.summand_commitments, kinds, SHARED.clear_values)), SHARED.sharing_digest);
    // every summand, the salt and each S_j's place change them
    const [s0, s1, s2] = SHARED.summands;
    assert.notEqual(hex(await summandCommitment([...s0.slice(0, -1), hex(BigInt(s0.at(-1)!) + 1n)], SHARED.salts[0])), SHARED.summand_commitments[0]);
    assert.notEqual(hex(await summandCommitment(s0, hex(BigInt(SHARED.salts[0]) + 1n))), SHARED.summand_commitments[0]);
    assert.notEqual(hex(await summandCommitment(s1, SHARED.salts[0])), SHARED.summand_commitments[1]);
    assert.notEqual(hex(await summandCommitment(s2, SHARED.salts[1])), SHARED.summand_commitments[2]);
    const [c0, c1, c2] = SHARED.summand_commitments;
    assert.notEqual(hex(await sharingDigest([c1, c0, c2], kinds, SHARED.clear_values)), SHARED.sharing_digest);
    // another clear value, or the same values under another layout, is another D
    assert.notEqual(hex(await sharingDigest(SHARED.summand_commitments, kinds, [hex(BigInt(SHARED.values.position!) + 1n)])), SHARED.sharing_digest);
    assert.notEqual(hex(await sharingDigest(SHARED.summand_commitments, ["clear", "chosen", "chosen", "chosen", "chosen"], SHARED.clear_values)), SHARED.sharing_digest);
  });

  test("refusals: reserved names, missing or listed shared inputs, the manifest's ranges, the app's check, a non-secret-shared intake", async () => {
    const build = (inputs: Record<string, unknown>, over: Record<string, unknown> = {}) =>
      buildSharedReceiptRequest({ layout: LAYOUT, namespace: SHARED.namespace, vkHash: SHARED.vk_hash, inputs: inputs as never, encKeys: ENC_KEYS, ...over });
    for (const name of ["$blinding", "$outcome_key", "$outcome_tag"]) {
      await assert.rejects(build({ ...INPUTS, [name]: 1n }), new RegExp(`inputs\\.\\${name}: reserved`));
    }
    // a known-answer sharing that does not add up to its value
    const sharing = SEAL.amount!.sharing.map((v, j) => (j === 0 ? hex(BigInt(v) + 1n) : v)) as Triple<string>;
    await assert.rejects(
      buildSharedReceiptRequest({ layout: LAYOUT, namespace: SHARED.namespace, vkHash: SHARED.vk_hash, inputs: INPUTS, encKeys: ENC_KEYS }, { secrets: SECRETS, seal: { ...SEAL, amount: { sharing } } }),
      /shared input `amount`: the sharing does not sum to the value/,
    );
    await assert.rejects(build({ amount: 1n, position: 7n }), /inputs\.\$partial_note: missing/);
    await assert.rejects(build({ ...INPUTS, amount: [1n, 2n] }), /inputs\.amount: a shared input is one field element/);
    await assert.rejects(build({ ...INPUTS, position: 1n << 32n }), /does not fit in 32 bit/);
    await assert.rejects(build({ ...INPUTS, extra: 1n }), /inputs\.extra: unexpected/);
    // the app's check sees C's values in commitment order
    let seen: readonly bigint[] = [];
    await build(INPUTS, { isValid: (v: readonly bigint[]) => ((seen = v), true) });
    assert.deepEqual(seen.slice(0, 3).map((v) => hex(v)), SHARED.commitment_values.slice(0, 3));
    assert.equal(seen.length, 5);
    await assert.rejects(build(INPUTS, { isValid: () => false }), /refused by the app's static check/);
    await assert.rejects(build(INPUTS, { layout: { ...LAYOUT, intake: "receipt" } }), (e: unknown) => e instanceof ConfigError);
  });
});


// ---- the request function's arguments ----

const field = { kind: "field" };
const arr = (n: number, type: unknown = field) => ({ kind: "array", length: n, type });
const RECEIPT_STRUCT = { kind: "struct", path: "pss_public_contract::receipt::Receipt", fields: [{ name: "s", type: arr(2) }, { name: "e", type: arr(2) }] };
/** `Sharing<L>` as aztec.js sees it. */
const sharingStruct = (l: number) => ({
  kind: "struct",
  path: "pss_public_contract::shared_intake::Sharing",
  fields: [{ name: "summands", type: arr(3, arr(l)) }, { name: "salts", type: arr(3) }],
});
// pss_public_contract_test's request_shared as aztec.js sees it, at the
// vector circuit's sizes: C's five values and five summands each
const REQUEST_SHARED = {
  name: "request_shared",
  functionType: "private",
  isOnlySelf: false,
  isStatic: false,
  isInitializer: false,
  parameters: [
    { name: "values", type: arr(5), visibility: "private" },
    { name: "sharing", type: sharingStruct(5), visibility: "private" },
    { name: "expiry_block", type: { kind: "integer", sign: "unsigned", width: 32 }, visibility: "private" },
    { name: "receipts", type: arr(3, RECEIPT_STRUCT), visibility: "private" },
  ],
  returnTypes: [],
  errorTypes: {},
} as unknown as FunctionAbi;

describe("the secret-shared receipt request function's arguments", () => {
  test("(values, {summands, salts}, expiry_block, receipts), encoded as request_shared takes them", async () => {
    const r = await known();
    const sigs = (await Promise.all(SIGNERS.map((k) => k.sign(new Fr(7n))))) as Triple<Signature>;
    const receipts = new SharedReceipts(r, 1300, sigs, 20);
    const args = receipts.intakeArgs();
    assert.deepEqual(args, sharedReceiptIntakeArgs({ values: r.values, sharing: r.sharing, expiryBlock: 1300, receipts: sigs }));
    assert.equal(args.length, 4);
    assert.deepEqual(Object.keys(args[1]).sort(), ["salts", "summands"]);
    const flat = encodeArguments(REQUEST_SHARED, args).map((x) => x.toString());
    assert.deepEqual(flat, [
      ...SHARED.commitment_values,
      ...SHARED.summands.flat(),
      ...SHARED.salts,
      fieldHex(1300),
      ...sigs.flatMap((s) => [...s.s, ...s.e]),
    ]);
    assert.equal(receipts.requestId, SHARED.chain_request_id);
    assert.equal(receipts.expiresSoon(1279), false);
    assert.equal(receipts.expiresSoon(1280), true);
    const base = { values: r.values, sharing: r.sharing, expiryBlock: 1, receipts: sigs };
    assert.throws(() => sharedReceiptIntakeArgs({ ...base, expiryBlock: -1 }), RangeError);
    assert.throws(() => sharedReceiptIntakeArgs({ ...base, receipts: sigs.slice(0, 2) as never }), RangeError);
    assert.throws(() => sharedReceiptIntakeArgs({ ...base, sharing: { ...r.sharing, salts: r.sharing.salts.slice(0, 2) as never } }), /sharing: expected 3/);
    assert.throws(() => sharedReceiptIntakeArgs({ ...base, sharing: { ...r.sharing, summands: [r.sharing.summands[0], r.sharing.summands[1], r.sharing.summands[2].slice(1)] } }), /one nonzero length/);
  });
});

// ---- the receipt flow ----

const USER = "0x0b7e3a1f00c0ffee00000000000000000000000000000000000000000000beef";
const CURRENT = 1000;

describe("PssClient.obtainIntake and requestIntake under secret-shared receipt intake against a mock orchestrator", () => {
  const mock = new MockOrchestrator();
  let url: string;
  let reply: {
    expiry?: (current: number) => number;
    requestId?: (id: string) => string;
    tamper?: (sigs: Signature[]) => Promise<Signature[]> | Signature[];
    /** Sign receipt intake's four-element message instead. */
    fourElements?: boolean;
  } = {};

  // The nodes' job, computed here independently: the chain request id over
  // the C the client sent, D over the summand commitments it sent, the
  // layout's kinds (position clear) and the clear position it sent, and
  // three signatures over the five-element receipt message.
  const sign = async (b: Record<string, unknown>, expiry: number) => {
    const c = b.inputs_hash as string;
    let requestId = hex(await hash([b.namespace as string, SHARED.vk_hash, c]));
    if (reply.requestId) requestId = reply.requestId(requestId);
    const d = b.sharing_digest as string;
    const position = BigInt((b.inputs as Record<string, string>).position!);
    assert.equal(hex(await hash([SHARING_DOMAIN, ...(b.summand_commitments as string[]), 1n, 0n, 1n, 1n, 1n, position])), d);
    const message = await hash(reply.fourElements ? [RECEIPT_DOMAIN, requestId, c, BigInt(expiry)] : [RECEIPT_DOMAIN, requestId, c, BigInt(expiry), d]);
    let sigs: Signature[] = await Promise.all(SIGNERS.map((k) => k.sign(new Fr(message))));
    if (reply.tamper) sigs = await reply.tamper(sigs);
    return { status: 200, body: { request_id: requestId, inputs_hash: c, expiry_block: expiry, signatures: sigs } };
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

  const client = () =>
    new PssClient({
      orchestratorUrl: url,
      allowInsecureHttp: true,
      nodeKeys: NODE_KEYS,
      vkHashes: { [SHARED.circuit]: SHARED.vk_hash },
      circuits: { [SHARED.circuit]: { circuit: { abi: SHARED.abi }, manifest: MANIFEST } },
      contractAddress: SHARED.namespace,
      timeoutMs: 2_000,
    });
  // the partial note stands in as the user's own account
  const ask = { circuit: SHARED.circuit, inputs: { amount: 5000n, position: 7n, $partial_note: USER }, currentBlock: CURRENT };
  // the receipts over C, as obtainIntake gives them
  const receiptsOf = async (c: PssClient, a: IntakeAsk): Promise<SharedReceipts> => {
    const intake = await c.obtainIntake(a);
    assert.equal(intake.intake, "shared_receipt");
    return (intake as SharedReceiptIntakeInput).receipts;
  };

  test("three receipts over C and D are accepted; the orchestrator sees no shared value, no summand and no account", async () => {
    const c = client();
    const r = await receiptsOf(c, ask);
    assert.ok(r instanceof SharedReceipts);
    assert.equal(r.expiryBlock, CURRENT + 300);
    assert.equal(r.requestId, hex(await hash([SHARED.namespace, SHARED.vk_hash, r.request.inputsCommitment])));
    const sent = JSON.parse(mock.received.find((x) => x.path === "/v1/receipt")!.body);
    assert.deepEqual(sent, sharedReceiptBody(r.request, CURRENT));
    assert.deepEqual(sent.inputs, { position: fieldHex(7n) });
    assert.deepEqual(sent.summand_commitments, r.request.summandCommitments);
    assert.equal(sent.sharing_digest, r.request.sharingDigest);
    // no plaintext shared value: the amount, the partial note, the blinding, the
    // outcome key, the outcome tag, the summands and the salts appear nowhere
    // in the body
    const secret = [5000n, USER, r.request.blinding, r.request.outcomeKey, r.request.outcomeTag, ...r.request.sharing.summands.flat(), ...r.request.sharing.salts];
    await assertNoRequester(secret, { receiptBodies: [sent] });
    // the public call takes the request id and the expiry block only
    await assertNoRequester(secret, { callArgs: [r.requestId, r.expiryBlock] });
    // asking again with the same request gives the same id and envelopes
    const again = await receiptsOf(c, { circuit: SHARED.circuit, request: r.request, currentBlock: CURRENT + 100 });
    assert.equal(again.requestId, r.requestId);
    assert.equal(again.expiryBlock, CURRENT + 400);
    const resent = JSON.parse(mock.received.filter((x) => x.path === "/v1/receipt")[1]!.body);
    assert.deepEqual(resent.shared_inputs, sent.shared_inputs);
    assert.deepEqual([resent.summand_commitments, resent.sharing_digest], [sent.summand_commitments, sent.sharing_digest]);
    assert.deepEqual(again.intakeArgs()[1], r.intakeArgs()[1]);
    assert.equal(mock.count("GET", "/v1/nodes"), 1);
  });

  test("the ask's secrets are the request's outcome key, tag and blinding", async () => {
    const secrets = { blinding: 0xb1n, outcomeKey: 0x0e1n, outcomeTag: 0x7a6n };
    const r = await receiptsOf(client(), { ...ask, secrets });
    assert.deepEqual([r.request.blinding, r.request.outcomeKey, r.request.outcomeTag], [0xb1n, 0x0e1n, 0x7a6n].map((v) => fieldHex(v)));
  });

  test("an answer under another request id, a wrong signature or a long expiry is refused", async () => {
    reply.requestId = (id) => fieldHex(BigInt(id) ^ 1n);
    await assert.rejects(receiptsOf(client(), ask), (e: unknown) => e instanceof ProtocolError && /request_id/.test(e.message));
    reply = { tamper: async (sigs) => [sigs[0]!, await SIGNERS[1]!.sign(new Fr(1n)), sigs[2]!] };
    await assert.rejects(receiptsOf(client(), ask), (e: unknown) => e instanceof ReceiptSignatureError && e.node === 1);
    reply = { expiry: (c) => c + 301 };
    await assert.rejects(receiptsOf(client(), ask), (e: unknown) => e instanceof ProtocolError && /at most 300/.test(e.message));
  });

  test("receipts over receipt intake's four-element message, without D, are refused", async () => {
    reply = { fourElements: true };
    await assert.rejects(receiptsOf(client(), ask), (e: unknown) => e instanceof ReceiptSignatureError && e.node === 0);
  });

  test("a circuit not under secret-shared receipt intake, or another circuit's request, is refused before anything is sent", async () => {
    const plain = new PssClient({
      orchestratorUrl: url,
      allowInsecureHttp: true,
      nodeKeys: NODE_KEYS,
      vkHashes: { shared_receipt_round: SHARED.vk_hash },
      circuits: { shared_receipt_round: { circuit: { abi: SHARED.abi }, manifest: { ...MANIFEST, intake: "shared_onchain" } } },
      contractAddress: SHARED.namespace,
      timeoutMs: 2_000,
    });
    await assert.rejects(receiptsOf(plain, ask), (e: unknown) => e instanceof RangeError && /encKeys/.test(e.message));
    const r = await known();
    await assert.rejects(
      receiptsOf(client(), { circuit: SHARED.circuit, request: { ...r, vkHash: fieldHex(1n) }, currentBlock: CURRENT }),
      (e: unknown) => e instanceof ConfigError,
    );
    // an earlier request of another namespace
    await assert.rejects(
      receiptsOf(client(), { circuit: SHARED.circuit, request: { ...r, namespace: fieldHex(0xbeefn) }, currentBlock: CURRENT }),
      (e: unknown) => e instanceof ConfigError && /in 0x0+beef, not the configured/.test(e.message),
    );
    await assert.rejects(receiptsOf(client(), { circuit: SHARED.circuit, currentBlock: CURRENT }), RangeError);
    assert.equal(mock.count("POST", "/v1/receipt"), 0);
  });

  test("requestIntake obtains the intake and sends C's values through the request function; laid arguments go as given", async () => {
    const sends: { args: unknown[]; opts: unknown }[] = [];
    const send = (...args: unknown[]) => ({ send: async (opts: unknown) => (sends.push({ args, opts }), { txHash: "0x01" }) });
    const c = client();
    const r = await c.requestIntake(send, ask, { from: USER, fee: "x" }, { currentBlock: CURRENT });
    assert.equal(r.intake?.intake, "shared_receipt");
    const s = intakeSummary(r.intake!);
    assert.deepEqual(sends[0]!.args, (r.intake as SharedReceiptIntakeInput).receipts.intakeArgs());
    assert.deepEqual(sends[0]!.opts, { wait: SEND_WAIT, from: USER, fee: "x" });
    assert.deepEqual(r.sent, { txHash: "0x01" });
    assert.equal(s.outcomeTag, (r.intake as SharedReceiptIntakeInput).receipts.request.outcomeTag);
    const again = await c.requestIntake(send, { args: r.args }, { from: USER, fee: "x" });
    assert.deepEqual(sends[1]!.args, r.args);
    assert.equal(again.intake, undefined);
    await assert.rejects(c.requestIntake(send, { args: r.args }, { from: USER, fee: "x" }, { values: { amount: 1n } }), /laid arguments take no values/);
    await assert.rejects(c.requestIntake(send, { circuit: SHARED.circuit, intake: r.intake! }, { from: USER, fee: "x" }, { values: { nope: 1n } }), /values\.nope: not a value of/);
    assert.equal(mock.count("POST", "/v1/receipt"), 1);
  });
});
