import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { readFile, rm } from "node:fs/promises";
import { join } from "node:path";
import { after, before, beforeEach, describe, test } from "node:test";

import { Fr } from "@aztec-labs/aztec.js/fields";
import { Fq } from "@aztec-labs/foundation/curves/bn254";

import {
  BN254_MODULUS,
  circuitPackages,
  ConfigError,
  JsonFileRequestStore,
  MemoryRequestStore,
  NodeKeyMismatchError,
  MAX_RESPONSE_BYTES,
  ProtocolError,
  PssClient,
  resolveConfig,
  ResultSignatureError,
  SidecarError,
  UnknownOutcomeError,
  VkHashMismatchError,
  RequesterKey,
  SchnorrKey,
  executeMessage,
  fieldFq,
  fieldHex,
  registerMessage,
  signRequest,
  shareHash,
  verifySignature,
  EXECUTE_DOMAIN,
  canonicalBody,
  canonicalJson,
  manifestStoresClientKey,
  parseManifest,
  buildExecuteRequest,
  checkName,
  messageFor,
  newRequestId,
  recordHashes,
  requestIdField,
  requestIdHex,
  requestKey,
  resultMessages,
  type ExecuteRequest,
  type ExecuteResponse,
  type PssClientConfig,
  type ResultRecord,
} from "../src/internal.ts";
import { MockOrchestrator, fixture, scratchDir } from "@aztec-pss/test-support";


const NS = "0x1ac1704880851219793ebcb14b7d910d576186d4846fa8b42b51108ebd236888";
const VK = "0x2f6b59841e2b734fd187ca207ac63a4407b68fc31cf3a9a804eaeaf5295b82ab";
// The deployment keys of testvectors/keys.json: real Grumpkin points, and the
// nodes' sig secrets, with which the mock signs its answers.
const KEY_VECTORS = JSON.parse(readFileSync(new URL("../../../testvectors/keys.json", import.meta.url), "utf8")) as {
  nodes: { enc_pk: { x: string; y: string }; sig: string; sig_pk: { x: string; y: string }; key_id: string }[];
};
const SIG = KEY_VECTORS.nodes.map((n) => n.sig_pk);
// Placeholder enc keys (not curve points) beside the real sig keys.
const KEYS = [
  { enc: { x: "0x1", y: "0x2" }, sig: SIG[0]! },
  { enc: { x: "0x3", y: "0x4" }, sig: SIG[1]! },
  { enc: { x: "0x5", y: "0x6" }, sig: SIG[2]! },
] as const;
const NODE_SIGNERS = KEY_VECTORS.nodes.map((n) => SchnorrKey.fromHex(n.sig));
// amm_swap as registered: its ABI and manifest. Its one output's note hash,
// new_note_hashes[0], is public input 8 of 11.
const AMM_SWAP = {
  circuit: fixture("amm_swap.abi.json"),
  manifest: JSON.parse(readFileSync(new URL("../../../examples/amm/manifests/amm_swap.json", import.meta.url), "utf8")) as unknown,
};
// The same circuit registered with client-held state: its read is supplied
// as a record and its write is sealed to the requester.
const CLIENT_SWAP = {
  circuit: AMM_SWAP.circuit,
  manifest: { ...(AMM_SWAP.manifest as object), circuit: "client_swap", state: { "$state_keys.reads[0]": "client", "$state_keys.writes[0]": "client" } },
};
const NEW_NOTE_HASH = fieldHex(0xc0ffee);
const REAL_KEYS = KEY_VECTORS.nodes.map((n) => ({ enc: n.enc_pk, sig: n.sig_pk })) as PssClientConfig["nodeKeys"];
// A record third of the sealed shape: node i's key id, one ciphertext field and a tag.
const third = (n: number) => KEY_VECTORS.nodes[n % 3]!.key_id + fieldHex(n + 1).slice(2) + fieldHex(n + 100).slice(2);
// The record a client_swap round on key 0xb001 returns: its note hash is the
// round's new commitment, public input 8 of the answer.
const NEW_RECORD: ResultRecord = { key: "0xb001", note_hash: NEW_NOTE_HASH, c: [third(3), third(4), third(5)] };
// A note-mode request id: one field element, 0x + 64 digits, 128 random bits.
const ID_RE = /^0x0{32}[0-9a-f]{32}$/;
const FIELD_RE = /^0x[0-9a-f]{64}$/;

function config(url: string, over: Partial<PssClientConfig> = {}): PssClientConfig {
  return {
    orchestratorUrl: url,
    // the mock listens on plain http on the loopback address
    allowInsecureHttp: true,
    nodeKeys: [KEYS[0], KEYS[1], KEYS[2]],
    vkHashes: { amm_swap: VK, client_swap: VK, pss_seed: 0x95cn },
    circuits: { amm_swap: AMM_SWAP, client_swap: CLIENT_SWAP },
    contractAddress: NS,
    timeoutMs: 2_000,
    fetchRetry: { attempts: 3, initialDelayMs: 10, maxDelayMs: 40, timeoutMs: 500 },
    ...over,
  };
}

// An amm_swap answer as the orchestrator sends it, signed by the three nodes
// of keys.json over the result messages of `namespace`.
async function answer(requestId: string, o: { vk?: string; records?: ResultRecord[]; namespace?: string } = {}) {
  const unsigned = {
    request_id: requestId,
    vk_hash: o.vk ?? VK,
    proof: "0xABCD",
    // namespace, owner, in_slots, out_slots, amount_in, direction,
    // read_leaves, nullifiers, new_note_hashes, npk_app_hash, app_outputs
    public_inputs: [NS, "0xafafaf", "0xa002", "0xa002", "0x2710", "0x0", "0x51", "0x52", NEW_NOTE_HASH, "0x53", "0x54"],
    stored: ["0xa002"],
    records: o.records ?? [],
  };
  const normal = { ...unsigned, request_id: requestIdHex(requestId), public_inputs: unsigned.public_inputs.map((x) => fieldHex(x)) };
  const messages = await resultMessages(o.namespace ?? NS, normal as ExecuteResponse, [8]);
  const signatures = await Promise.all(NODE_SIGNERS.map((k, i) => k.sign(messages[i]!)));
  return { ...unsigned, signatures };
}

const swapInput = {
  circuit: "amm_swap",
  public: { amount_in: 10_000n, direction: 0 },
  stateKeys: { reads: ["0xa002"], writes: ["0xa002"] },
};
// A swap on a client-held state, whose record the requester supplies.
const clientSwapInput = { ...swapInput, circuit: "client_swap", stateKeys: { reads: ["0xb001"], writes: ["0xb001"] } };

describe("request ids", () => {
  test("a produced id is one field element of 64 hex digits from 128 random bits", () => {
    const ids = new Set<string>();
    for (let k = 0; k < 64; k++) {
      const id = newRequestId();
      assert.match(id, /^0x[0-9a-f]{64}$/);
      assert.match(id, ID_RE);
      assert.equal(requestIdHex(id), id);
      assert.equal(requestIdField(id) < 1n << 128n, true);
      ids.add(id);
    }
    assert.equal(ids.size, 64);
  });
  test("parse like any field element: 1 to 64 digits in, 64 out", () => {
    assert.equal(requestIdHex("0x41D3"), "0x" + "0".repeat(60) + "41d3");
    assert.equal(requestIdHex("41d3"), requestIdHex(0x41d3n));
    assert.equal(requestIdHex("0x" + "0".repeat(32) + "000102030405060708090a0b0c0d0e0f"), requestIdHex(Uint8Array.from({ length: 16 }, (_, i) => i)));
    // any field element is an id (the tip derives its ids by hashing)
    assert.equal(requestIdHex(BN254_MODULUS - 1n), "0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000");
  });
  test("refuse an id at or above the modulus, and bad hex", () => {
    assert.throws(() => requestIdHex("0x" + BN254_MODULUS.toString(16)), /not below the bn254 scalar field modulus/);
    assert.throws(() => requestIdHex(BN254_MODULUS + 1n), /modulus/);
    assert.throws(() => requestIdHex("0x" + "f".repeat(64)), /modulus/);
    assert.throws(() => requestIdHex(new Uint8Array(32).fill(0xff)), /modulus/);
    assert.throws(() => requestIdHex("0x" + "1".repeat(65)), /1 to 64 digit/);
    assert.throws(() => requestIdHex("0x"), /1 to 64 digit/);
    assert.throws(() => requestIdHex("swap-41d3"), /1 to 64 digit/);
    assert.throws(() => requestIdHex(new Uint8Array(33)), /expected 1 to 32/);
  });
});

describe("field elements", () => {
  test("normalise to 0x + 64 lowercase digits", () => {
    assert.equal(fieldHex("0xA002"), "0x" + "0".repeat(60) + "a002");
    assert.equal(fieldHex("a002"), fieldHex(0xa002));
    assert.equal(fieldHex(new Fr(0xa002n)), fieldHex(0xa002n));
    assert.equal(fieldHex(BN254_MODULUS - 1n), "0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000");
  });
  test("refuse the modulus and above, negatives and bad hex", () => {
    assert.throws(() => fieldHex(BN254_MODULUS), /not below the bn254 scalar field modulus/);
    assert.throws(() => fieldHex("0x" + BN254_MODULUS.toString(16)), /modulus/);
    assert.throws(() => fieldHex("0x" + "f".repeat(64)), /modulus/);
    assert.throws(() => fieldHex("0x" + "1".repeat(65)), /1 to 64 digit/);
    assert.throws(() => fieldHex("0x"), /1 to 64 digit/);
    assert.throws(() => fieldHex("0xzz"), /1 to 64 digit/);
    assert.throws(() => fieldHex(-1n), /negative/);
    assert.throws(() => fieldHex(1.5), /safe integer/);
  });
  test("a Grumpkin scalar may exceed the scalar field, never its own modulus, and a refusal never names it", () => {
    assert.equal(fieldFq(BN254_MODULUS).toBigInt(), BN254_MODULUS);
    assert.equal(fieldFq("1000").toBigInt(), 0x1000n);
    assert.equal(fieldFq(Fq.MODULUS - 1n).toBigInt(), Fq.MODULUS - 1n);
    const secret = "9a8b7c6d5e4f3a2b";
    for (const [x, why] of [
      [secret + "zz", /^signingKey: not a 1 to 64 digit hex number$/],
      ["0x" + Fq.MODULUS.toString(16), /^signingKey: not below the Grumpkin scalar field modulus$/],
      ["0x" + secret.repeat(4), /^signingKey: not below the Grumpkin scalar field modulus$/],
    ] as const) {
      assert.throws(() => fieldFq(x, "signingKey"), (e: unknown) => e instanceof RangeError && why.test(e.message) && !String(e.stack).includes(secret));
    }
  });
});

describe("configuration", () => {
  test("the orchestrator URL is https unless allowInsecureHttp is set", () => {
    const base = config("https://pss.example");
    assert.equal(resolveConfig({ ...base, allowInsecureHttp: undefined }).orchestratorUrl, "https://pss.example");
    assert.equal(resolveConfig({ ...base, orchestratorUrl: "https://pss.example:3200/", allowInsecureHttp: false }).orchestratorUrl, "https://pss.example:3200");
    for (const orchestratorUrl of ["http://pss.example", "http://127.0.0.1:1"]) {
      assert.throws(() => resolveConfig({ ...base, orchestratorUrl, allowInsecureHttp: undefined }), (e: unknown) => {
        assert.ok(e instanceof ConfigError);
        assert.match(e.message, /plain http is refused/);
        return true;
      });
      assert.throws(() => resolveConfig({ ...base, orchestratorUrl, allowInsecureHttp: false }), ConfigError);
      assert.equal(resolveConfig({ ...base, orchestratorUrl, allowInsecureHttp: true }).orchestratorUrl, orchestratorUrl);
    }
    assert.throws(() => resolveConfig({ ...base, orchestratorUrl: "ftp://pss.example", allowInsecureHttp: true }), /protocol ftp: is not https/);
    assert.throws(() => resolveConfig({ ...base, orchestratorUrl: "pss.example" }), /is not a URL/);
  });

  test("circuitPackages pairs each compiled circuit with its manifest by name, and refuses a name with one", () => {
    const circuits = { a: { abi: 1 }, b: { abi: 2 } };
    const manifests = { b: { manifest: 2 }, a: { manifest: 1 } };
    assert.deepEqual(circuitPackages(circuits, manifests), { a: { circuit: circuits.a, manifest: manifests.a }, b: { circuit: circuits.b, manifest: manifests.b } });
    assert.throws(() => circuitPackages(circuits, { a: manifests.a }), (e: unknown) => e instanceof ConfigError && /circuits\.b:/.test(e.message));
    assert.throws(() => circuitPackages({ a: circuits.a }, manifests), /circuits\.b:/);
  });

  test("a timeout is positive; a retry delay may be 0", () => {
    const base = config("https://pss.example");
    assert.throws(() => resolveConfig({ ...base, timeoutMs: 0 }), /timeoutMs: not a positive number/);
    const retry = { attempts: 2, initialDelayMs: 0, maxDelayMs: 0, timeoutMs: 1 };
    assert.equal(resolveConfig({ ...base, fetchRetry: retry }).fetchRetry.initialDelayMs, 0);
    assert.throws(() => resolveConfig({ ...base, fetchRetry: { ...retry, timeoutMs: 0 } }), /fetchRetry.timeoutMs: not a positive number/);
  });
});

describe("client against a mock orchestrator", () => {
  let mock: MockOrchestrator;
  let url: string;

  before(async () => {
    mock = new MockOrchestrator();
    url = await mock.start();
  });
  after(async () => {
    await mock.stop();
  });
  beforeEach(() => {
    mock.routes.clear();
    mock.received.length = 0;
  });

  test("checkNodes passes on the pinned keys, short and long spellings alike", async () => {
    mock.on("GET", "/v1/nodes", () => ({
      status: 200,
      body: { nodes: [{ enc: { x: fieldHex(1), y: "0x02" }, sig: { x: SIG[0]!.x.toUpperCase().replace("0X", "0x"), y: fieldHex(SIG[0]!.y) } }, KEYS[1], KEYS[2]] },
    }));
    await new PssClient(config(url)).checkNodes();
  });

  test("checkNodes refuses a substituted key and names the node", async () => {
    mock.on("GET", "/v1/nodes", () => ({ status: 200, body: { nodes: [KEYS[0], { ...KEYS[1], enc: { x: "0x3", y: "0x5" } }, KEYS[2]] } }));
    await assert.rejects(new PssClient(config(url)).checkNodes(), (e: unknown) => {
      assert.ok(e instanceof NodeKeyMismatchError);
      assert.equal(e.index, 1);
      assert.equal(e.key, "enc");
      assert.match(e.message, /^node 1: the orchestrator reports enc key/);
      return true;
    });
    mock.on("GET", "/v1/nodes", () => ({ status: 200, body: { nodes: [KEYS[0], KEYS[1], { ...KEYS[2], sig: KEYS[1].sig }] } }));
    await assert.rejects(new PssClient(config(url)).checkNodes(), (e: unknown) => e instanceof NodeKeyMismatchError && e.index === 2 && e.key === "sig");
    mock.on("GET", "/v1/nodes", () => ({ status: 200, body: { nodes: [KEYS[0], KEYS[1], KEYS[2].enc] } }));
    await assert.rejects(new PssClient(config(url)).checkNodes(), /nodes\[2\]\.x`: unknown field/);
    mock.on("GET", "/v1/nodes", () => ({ status: 200, body: { nodes: [KEYS[0], KEYS[1]] } }));
    await assert.rejects(new PssClient(config(url)).checkNodes(), /nodes.*2 entries, expected 3/);
  });

  test("a reply over MAX_RESPONSE_BYTES is refused", async () => {
    mock.on("GET", "/v1/nodes", () => ({ status: 200, body: JSON.stringify("x".repeat(MAX_RESPONSE_BYTES)) }));
    await assert.rejects(new PssClient(config(url)).checkNodes(), (e: unknown) => e instanceof ProtocolError && /over 8388608 bytes/.test(e.message));
  });

  test("buildRequest writes the exact wire format", async () => {
    const client = new PssClient(config(url));
    const p = await client.buildRequest({
      ...swapInput,
      public: { ...swapInput.public, limbs: [1, 2n, "0x3"] },
      stateKeys: { reads: ["0xa002"], writes: [0xa002n] },
    });
    assert.match(p.requestId, ID_RE);
    assert.equal(p.body.request_id, p.requestId);
    assert.deepEqual(Object.keys(p.body), ["namespace", "circuit", "request_id", "public", "state_keys", "shared_inputs", "records"]);
    assert.equal(p.body.namespace, NS);
    assert.equal(p.body.public.amount_in, fieldHex(10_000));
    assert.equal(p.body.public.direction, fieldHex(0));
    assert.deepEqual(p.body.public.limbs, [1, 2, 3].map((x) => fieldHex(x)));
    for (const v of [p.body.public.amount_in, p.body.public.direction]) assert.match(v as string, FIELD_RE);
    // a string key is opaque and sent as written; a numeric key is a field
    // element in short hex, the one spelling the nodes take for a key that
    // feeds PUBLIC
    assert.deepEqual(p.body.state_keys, { reads: ["0xa002"], writes: ["0xa002"] });
    assert.deepEqual(p.body.shared_inputs, []);
    assert.deepEqual(p.body.records, []);
    assert.equal(p.json, JSON.stringify(p.body));
    const q = await client.buildRequest(swapInput);
    assert.notEqual(q.requestId, p.requestId);
  });

  test("buildRequest refuses what sidecar-core refuses", async () => {
    const client = new PssClient(config(url));
    await assert.rejects(client.buildRequest({ ...swapInput, circuit: "amm_init" }), ConfigError);
    await assert.rejects(client.buildRequest({ ...swapInput, public: { amount_in: BN254_MODULUS } }), /modulus/);
    await assert.rejects(client.buildRequest({ ...swapInput, stateKeys: { reads: ["nsk_app"] } }), /fixed key/);
    await assert.rejects(client.buildRequest({ ...swapInput, stateKeys: { writes: [""] } }), /empty key/);
    await assert.rejects(client.buildRequest({ ...swapInput, public: { $namespace: 1 } }), /not a public value name/);
    await assert.rejects(client.buildRequest({ ...swapInput, public: { a: [] } }), /empty list/);
    await assert.rejects(client.buildRequest({ ...swapInput, public: { "a[0]": 1, a: [1, 2] } }), /duplicated after flattening/);
    // one key twice in one list; once in each list is a read-and-write
    await assert.rejects(client.buildRequest({ ...swapInput, stateKeys: { reads: ["0xa002", "0xa002"] } }), /^RangeError: stateKeys\.reads\[1\]: `0xa002` is listed twice$/);
    await assert.rejects(client.buildRequest({ ...swapInput, stateKeys: { reads: ["0xa002"], writes: [0xa003n, "0xa003"] } }), /stateKeys\.writes\[1\]: .* is listed twice/);
    const rec = { key: "0xb001", note_hash: "0x77", c: [third(0), third(1), third(2)] as [string, string, string] };
    const signer = RequesterKey.generate();
    await assert.rejects(client.buildRequest({ ...clientSwapInput, records: [rec, rec], signer }), /duplicated/);
    await assert.rejects(client.buildRequest({ ...clientSwapInput, records: [{ ...rec, c: ["0x00", "0x01", "0x02"] }], signer }), /not a sealed state record/);
    const built = await client.buildRequest({ ...clientSwapInput, records: [rec], signer });
    assert.deepEqual(built.body.records, [
      { key: "0xb001", note_hash: fieldHex(0x77), c: rec.c, record_hashes: await recordHashes(rec.c) },
    ]);
    assert.deepEqual(built.body.requester, await signer.publicKey());
    // a requester given beside the signer must be the signer's key
    await assert.rejects(client.buildRequest({ ...clientSwapInput, records: [rec], signer, requester: { x: 7n, y: 8n } }), /not the signer's public key/);
    // no requester, no record: the optional fields are absent from the body
    const plain = (await client.buildRequest(swapInput)).body;
    assert.ok(!("requester" in plain) && !("signature" in plain));
  });

  test("a key is written short and spelled once where the manifest feeds it to PUBLIC", () => {
    assert.equal(requestKey(0xa002n), "0xa002");
    assert.equal(requestKey(0), "0x0");
    assert.equal(requestKey(new Fr(0xa001n)), "0xa001");
    assert.equal(requestKey("0x0a002"), "0x0a002");
    assert.equal(requestKey("pool"), "pool");
    assert.throws(() => requestKey("nsk_app", "stateKeys.reads[0]"), /^RangeError: stateKeys\.reads\[0\]: `nsk_app` is a fixed key$/);
  });

  test("a key amm_swap feeds to PUBLIC is refused in any but its short spelling", async () => {
    const client = new PssClient(config(url));
    // amm_swap feeds $state_keys.reads[0] and $state_keys.writes[0] into in_slots and out_slots
    for (const alias of ["0x0a002", "a002", "0xA002", fieldHex(0xa002)]) {
      await assert.rejects(
        client.buildRequest({ ...swapInput, stateKeys: { reads: [alias], writes: ["0xa002"] } }),
        new RegExp(`^RangeError: stateKeys\\.reads\\[0\\]: \`${alias}\` feeds parameter \`in_slots\` and is spelled \`0xa002\``),
      );
    }
    await assert.rejects(client.buildRequest({ ...swapInput, stateKeys: { reads: ["0xa002"], writes: ["pool"] } }), /stateKeys\.writes\[0\]: not a 1 to 64 digit hex number; the manifest feeds \$state_keys\.writes\[0\] into parameter `out_slots`, so it must be a field element/);
    // short hex, and a number, pass; without the manifest a string is sent as written
    assert.deepEqual((await client.buildRequest({ ...swapInput, stateKeys: { reads: [0xa002n], writes: ["0xa002"] } })).body.state_keys, { reads: ["0xa002"], writes: ["0xa002"] });
    const unpinned = await buildExecuteRequest(NS, { ...swapInput, stateKeys: { reads: ["0x0a002"], writes: ["0x0a002"] } });
    assert.deepEqual(unpinned.body.state_keys, { reads: ["0x0a002"], writes: ["0x0a002"] });
  });

  test("every name a binding hashes is 1 to 256 bytes of visible ASCII", async () => {
    const client = new PssClient(config(url, { nodeKeys: REAL_KEYS }));
    const signer = RequesterKey.generate();
    const bad: [string, RegExp][] = [
      ["k\0", /has byte 0x00; a key is visible ASCII \(0x21 to 0x7E\)$/],
      ["a b", /has byte 0x20/],
      ["é", /has byte 0xc3/],
      ["", /empty key$/],
      ["k".repeat(257), /key longer than 256 bytes$/],
    ];
    for (const [name, why] of bad) {
      assert.throws(() => checkName("f", "key", name), why);
      await assert.rejects(client.buildRequest({ ...swapInput, stateKeys: { reads: ["0xa002"], writes: [name] } }), /^RangeError: stateKeys\.writes\[0\]: /);
      await assert.rejects(buildExecuteRequest(NS, { circuit: name }), /^RangeError: circuit: /);
      await assert.rejects(client.buildRequest({ ...swapInput, sharedInputs: [{ name, value: 1 }], signer }), /^RangeError: sharedInputs\[0\]\.name: /);
      const rec = { key: name, note_hash: "0x77", c: [third(0), third(1), third(2)] as [string, string, string] };
      await assert.rejects(buildExecuteRequest(NS, { circuit: "c", stateKeys: { reads: ["ok"] }, records: [rec], signer }), /^RangeError: records\[0\]\.key: /);
    }
    assert.equal(checkName("f", "key", "k".repeat(256)), "k".repeat(256));
    assert.equal(mock.received.length, 0);
  });

  test("a request that carries a shared input is refused without a signer", async () => {
    const store = new MemoryRequestStore();
    const client = new PssClient(config(url, { nodeKeys: REAL_KEYS }), { store });
    // the node-held amm_swap needs no signer, until the request carries a shared input
    await assert.rejects(client.buildRequest({ ...swapInput, sharedInputs: [{ name: "door", value: 2 }] }), /^RangeError: signer: a request that carries a shared input must be signed by its requester key$/);
    const signer = RequesterKey.generate();
    const signed = await client.buildRequest({ ...swapInput, sharedInputs: [{ name: "door", value: 2 }], signer });
    assert.ok(await verifySignature(await executeMessage(signed.body), signed.body.requester!, signed.body.signature!));
    // the same body unsigned is refused before it is saved or sent
    const { signature: _s, ...unsigned } = signed.body;
    await assert.rejects(client.execute({ ...signed, body: unsigned, json: JSON.stringify(unsigned) }), /signature: a request that carries a shared input must be signed/);
    const { requester: _r, ...anonymous } = unsigned;
    await assert.rejects(client.execute({ ...signed, body: anonymous, json: JSON.stringify(anonymous) }), /requester: a request that carries a shared input must name/);
    assert.deepEqual(await store.list(), []);
    assert.equal(mock.count("POST", "/v1/execute"), 0);
  });

  test("a record-supplying or client-storing request is refused without a signer", async () => {
    const client = new PssClient(config(url));
    const rec = { key: "0xb001", note_hash: "0x77", c: [third(0), third(1), third(2)] as [string, string, string] };
    await assert.rejects(client.buildRequest({ ...clientSwapInput, records: [rec] }), /supplies records must be signed/);
    await assert.rejects(client.buildRequest({ ...clientSwapInput, records: [rec], requester: { x: 7n, y: 8n } }), /supplies records must be signed/);
    const manifest = { ...(AMM_SWAP.manifest as object), state: { "$state_keys.writes[0]": "client" } };
    assert.equal(manifestStoresClientKey(parseManifest(manifest)), true);
    assert.equal(manifestStoresClientKey(parseManifest({ ...manifest, state: { "$state_keys.writes[0]": "node" } })), false);
    // an unsigned body that supplies records is refused before it is saved
    const signer = RequesterKey.generate();
    const signed = await client.buildRequest({ ...clientSwapInput, records: [rec], signer });
    const { signature: _drop, ...unsigned } = signed.body;
    await assert.rejects(client.execute({ ...signed, body: unsigned, json: JSON.stringify(unsigned) }), /supplies records must be signed/);
    assert.equal(mock.count("POST", "/v1/execute"), 0);
  });

  test("whether a request stores a client-held key comes from the configured manifest", async () => {
    // amm_swap registered with a client-held write key: no caller flag
    const manifest = { ...(AMM_SWAP.manifest as object), state: { "$state_keys.reads[0]": "node", "$state_keys.writes[0]": "client" } };
    const store = new MemoryRequestStore();
    const client = new PssClient(config(url, { circuits: { amm_swap: { ...AMM_SWAP, manifest } } }), { store });
    await assert.rejects(client.buildRequest(swapInput), /^RangeError: signer: a request that stores a client-held key must be signed by its requester key$/);
    const signer = RequesterKey.generate();
    const signed = await client.buildRequest({ ...swapInput, signer });
    assert.deepEqual(signed.body.requester, await signer.publicKey());
    assert.ok(await verifySignature(await executeMessage(signed.body), signed.body.requester!, signed.body.signature!));
    // the same body without its signature, or without requester and signature,
    // is refused before it is saved or sent
    const { signature: _s, ...unsigned } = signed.body;
    await assert.rejects(client.execute({ ...signed, body: unsigned, json: JSON.stringify(unsigned) }), /signature: a request that stores a client-held key must be signed/);
    const { requester: _r, ...anonymous } = unsigned;
    await assert.rejects(client.execute({ ...signed, body: anonymous, json: JSON.stringify(anonymous) }), /requester: a request that stores a client-held key must name/);
    assert.deepEqual(await store.list(), []);
    assert.equal(mock.count("POST", "/v1/execute"), 0);
    // the node-held amm_swap of the default configuration needs no signer
    assert.ok(!("signature" in (await new PssClient(config(url)).buildRequest(swapInput)).body));
  });

  test("a record for a key the request does not read as client-held is refused before sealing", async () => {
    const client = new PssClient(config(url, { nodeKeys: REAL_KEYS }));
    const signer = RequesterKey.generate();
    const rec = (key: string) => ({ key, note_hash: "0x77", c: [third(0), third(1), third(2)] as [string, string, string] });
    // a key the request does not read
    const input = { ...clientSwapInput, stateKeys: { reads: ["0xb001"], writes: ["0xb001"] }, sharedInputs: [{ name: "door", value: 1 }], signer };
    await assert.rejects(client.buildRequest({ ...input, records: [rec("0xb002")] }), /^RangeError: records\[0\]: the request reads no key `0xb002`$/);
    // a key the request writes but does not read
    await assert.rejects(client.buildRequest({ ...input, stateKeys: { reads: ["0xb001"], writes: ["0xb002"] }, records: [rec("0xb002")] }), /records\[0\]: the request reads no key `0xb002`/);
    // a read the manifest holds at the nodes
    await assert.rejects(client.buildRequest({ ...swapInput, records: [rec("0xa002")], signer }), /^RangeError: records\[0\]: circuit `amm_swap` reads no client-held key `0xa002`$/);
    // the client-held read is accepted
    assert.equal((await client.buildRequest({ ...input, records: [rec("0xb001")] })).body.records[0]!.key, "0xb001");
    assert.equal(mock.received.length, 0);
  });

  test("the requester's signature covers the canonical body under the EXECUTE domain", async () => {
    const client = new PssClient(config(url));
    const key = RequesterKey.generate();
    const requester = await key.publicKey();
    const rec = { key: "0xb001", note_hash: "0x77", c: [third(0), third(1), third(2)] as [string, string, string] };
    const signed = await client.buildRequest({ ...clientSwapInput, records: [rec], signer: key });
    const message = await executeMessage(signed.body);
    // the message is over the canonical body: no `c`, no `signature`
    const canonical = canonicalJson(canonicalBody(signed.body));
    assert.ok(!canonical.includes(rec.c[0]) && !canonical.includes('"signature"'));
    assert.equal(message.toString(), (await messageFor(EXECUTE_DOMAIN, canonicalBody(signed.body))).toString());
    assert.ok(await verifySignature(message, requester, signed.body.signature!));
    // and the same signature is no REGISTER signature
    assert.equal(await verifySignature(await registerMessage(signed.body), requester, signed.body.signature!), false);
    mock.on("POST", "/v1/execute", async () => ({ status: 200, body: await answer(signed.requestId, { records: [NEW_RECORD] }) }));
    await client.execute(signed);
    assert.equal(mock.received.at(-1)!.body, signed.json);
    // signRequest re-signs a body built with a requester but no signer
    const p = await client.buildRequest({ ...swapInput, requester });
    assert.ok(!("signature" in p.body));
    const resigned = await signRequest(p, key);
    assert.ok(await verifySignature(await executeMessage(resigned.body), requester, resigned.body.signature!));
    await assert.rejects(signRequest(await client.buildRequest(swapInput), key), /must name its requester/);
    await assert.rejects(signRequest(p, RequesterKey.generate()), /not the body's requester key/);
    // an edited body no longer verifies
    const edited = { ...signed.body, public: { ...signed.body.public, amount_in: fieldHex(1) } };
    await assert.rejects(client.execute({ ...signed, body: edited, json: JSON.stringify(edited) }), /does not verify/);
  });

  test("execute saves before sending and returns the checked answer", async () => {
    const store = new MemoryRequestStore();
    const client = new PssClient(config(url), { store });
    const p = await client.buildRequest(swapInput);
    let savedAtSend: string | undefined;
    let sent: Awaited<ReturnType<typeof answer>> | undefined;
    mock.on("POST", "/v1/execute", async (r) => {
      savedAtSend = await store.load(p.requestId);
      sent = await answer(JSON.parse(r.body).request_id);
      return { status: 200, body: sent };
    });
    const out = await client.execute(p);
    assert.equal(savedAtSend, p.json);
    assert.equal(mock.received[0]!.body, p.json);
    assert.equal(out.via, "execute");
    assert.equal(out.response.proof, "0xabcd");
    assert.equal(out.response.public_inputs.length, 11);
    assert.deepEqual(out.response.public_inputs.slice(0, 3), [NS, fieldHex(0xafafaf), fieldHex(0xa002)]);
    assert.deepEqual(out.response.records, []);
    // the three checked signatures are on the result, for process_result
    assert.equal(out.response.signatures.length, 3);
    assert.deepEqual(out.response.signatures, sent!.signatures);
    assert.deepEqual(await store.list(), [p.requestId]);
    await client.discard(p.requestId);
    assert.deepEqual(await store.list(), []);
  });

  test("execute refuses an answer under another vk hash or for another id", async () => {
    const client = new PssClient(config(url));
    const p = await client.buildRequest(swapInput);
    mock.on("POST", "/v1/execute", async () => ({ status: 200, body: await answer(p.requestId, { vk: "0x1234" }) }));
    await assert.rejects(client.execute(p), VkHashMismatchError);
    mock.on("POST", "/v1/execute", async () => ({ status: 200, body: await answer("0x" + "0".repeat(64)) }));
    await assert.rejects(client.execute(p), /expected 0x/);
    mock.on("POST", "/v1/execute", async () => ({ status: 200, body: { ...(await answer(p.requestId)), effects: {} } }));
    await assert.rejects(client.execute(p), /field `effects`: unknown field/);
  });

  test("every execute and FETCH answer needs the three nodes' result signatures", async () => {
    const client = new PssClient(config(url));
    const p = await client.buildRequest(swapInput);
    for (let i = 0; i < 3; i++) {
      const tampered = async () => {
        const a = await answer(p.requestId, { records: [NEW_RECORD] });
        a.signatures[i]!.e[1] = fieldHex(BigInt(a.signatures[i]!.e[1]) + 1n);
        return { status: 200, body: a };
      };
      mock.on("POST", "/v1/execute", tampered);
      await assert.rejects(client.execute(p), (e: unknown) => {
        assert.ok(e instanceof ResultSignatureError && !(e instanceof SidecarError));
        assert.equal(e.node, i);
        assert.equal(e.requestId, p.requestId);
        return true;
      });
      mock.on("POST", "/v1/fetch", tampered);
      await assert.rejects(client.fetch(p.requestId), (e: unknown) => e instanceof ResultSignatureError && e.node === i);
    }
    // a refused answer is definite: no FETCH after it, and none of its records kept
    assert.equal(mock.count("POST", "/v1/fetch"), 3);
    assert.equal(await client.recordStore.latest(NS, "0xb001"), undefined);
    // signatures over another namespace, or the record's thirds changed after signing
    mock.on("POST", "/v1/execute", async () => ({ status: 200, body: await answer(p.requestId, { namespace: fieldHex(BigInt(NS) + 1n) }) }));
    await assert.rejects(client.execute(p), (e: unknown) => e instanceof ResultSignatureError && e.node === 0);
    mock.on("POST", "/v1/execute", async () => {
      const a = await answer(p.requestId, { records: [NEW_RECORD] });
      return { status: 200, body: { ...a, records: [{ ...NEW_RECORD, c: [third(6), third(4), third(5)] }] } };
    });
    await assert.rejects(client.execute(p), (e: unknown) => e instanceof ResultSignatureError && e.node === 0);
    // two signatures, four, or none: not the wire format
    const good = await answer(p.requestId);
    for (const signatures of [good.signatures.slice(0, 2), [...good.signatures, good.signatures[0]]]) {
      mock.on("POST", "/v1/execute", () => ({ status: 200, body: { ...good, signatures } }));
      await assert.rejects(client.execute(p), /field `signatures`: [24] entries, expected 3/);
    }
    const { signatures: _omit, ...unsigned } = good;
    mock.on("POST", "/v1/execute", () => ({ status: 200, body: unsigned }));
    await assert.rejects(client.execute(p), /field `signatures`: missing/);
    // the good answer passes both ways
    mock.on("POST", "/v1/execute", async () => ({ status: 200, body: await answer(p.requestId) }));
    const out = await client.execute(p);
    assert.equal(out.response.signatures.length, 3);
    mock.on("POST", "/v1/fetch", async () => ({ status: 200, body: await answer(p.requestId) }));
    assert.equal((await client.fetch(p.requestId)).request_id, p.requestId);
    // FETCH of an answer under a vk hash other than the request circuit's pin
    mock.on("POST", "/v1/fetch", async () => ({ status: 200, body: await answer(p.requestId, { vk: "0x1234" }) }));
    await assert.rejects(client.fetch(p.requestId), VkHashMismatchError);
  });

  test("a returned record must carry the request's key and the signed commitment of its output", async () => {
    const client = new PssClient(config(url));
    const signer = RequesterKey.generate();
    const rec = { key: "0xb001", note_hash: "0x77", c: [third(0), third(1), third(2)] as [string, string, string] };
    const p = await client.buildRequest({ ...clientSwapInput, records: [rec], signer });
    const refused = async (records: ResultRecord[], why: RegExp) => {
      const route = async () => ({ status: 200, body: await answer(p.requestId, { records }) });
      mock.on("POST", "/v1/execute", route);
      await assert.rejects(client.execute(p), (e: unknown) => e instanceof ProtocolError && why.test(e.message));
      mock.on("POST", "/v1/fetch", route);
      await assert.rejects(client.fetch(p.requestId), (e: unknown) => e instanceof ProtocolError && why.test(e.message));
    };
    // the nodes signed the thirds and the commitment, the orchestrator relabelled the record
    await refused([{ ...NEW_RECORD, key: "0xb002" }], /^client_swap: records\[0\] is labelled key 0xb002, not 0xb001, the request's key for \$state_keys\.writes\[0\]$/);
    await refused([{ ...NEW_RECORD, note_hash: fieldHex(0x78) }], /records\[0\] is labelled note_hash 0x0+78, not the new commitment 0x0+c0ffee at public input 8$/);
    // one record per client-held output: none, or one too many
    await refused([], /the answer carries 0 records; the manifest's client-held outputs give 1/);
    await refused([NEW_RECORD, NEW_RECORD], /the answer carries 2 records; the manifest's client-held outputs give 1/);
    // a refusal is definite (no FETCH after an execute) and keeps no record
    assert.equal(mock.count("POST", "/v1/fetch"), 4);
    assert.equal(await client.recordStore.latest(NS, "0xb001"), undefined);
    assert.equal(await client.recordStore.latest(NS, "0xb002"), undefined);
    // a node-held output returns no record
    const nodeHeld = await client.buildRequest(swapInput);
    mock.on("POST", "/v1/execute", async () => ({ status: 200, body: await answer(nodeHeld.requestId, { records: [NEW_RECORD] }) }));
    await assert.rejects(client.execute(nodeHeld), /amm_swap: the answer carries 1 records; the manifest's client-held outputs give 0/);
    // the record as the nodes labelled it is kept
    mock.on("POST", "/v1/execute", async () => ({ status: 200, body: await answer(p.requestId, { records: [NEW_RECORD] }) }));
    await client.execute(p);
    assert.equal((await client.recordStore.latest(NS, "0xb001"))?.note_hash, NEW_NOTE_HASH);
  });

  test("fetch checks an answer as the circuit the request was built for, never the one its vk_hash names", async () => {
    // Two pinned circuits with the same note-hash indices; the result message
    // does not cover vk_hash, so the nodes' signatures hold under either.
    const V1 = fieldHex(0x1111);
    const V2 = fieldHex(0x2222);
    const client = new PssClient(config(url, { vkHashes: { amm_swap: V1, amm_swap_v2: V2 }, circuits: { amm_swap: AMM_SWAP, amm_swap_v2: AMM_SWAP } }));
    const p = await client.buildRequest(swapInput);
    await client.store.save(p.requestId, p.json);
    mock.on("POST", "/v1/fetch", async () => ({ status: 200, body: await answer(p.requestId, { vk: V2 }) }));
    const relabelled = (e: unknown) => {
      assert.ok(e instanceof VkHashMismatchError);
      assert.equal(e.circuit, "amm_swap");
      assert.match(e.message, /0x0+2222 differs from the pinned 0x0+1111/);
      return true;
    };
    await assert.rejects(client.fetch(p.requestId), relabelled);
    await assert.rejects(client.fetch(p.requestId, { circuit: "amm_swap" }), relabelled);
    // the saved body names the circuit; a caller cannot override it
    await assert.rejects(client.fetch(p.requestId, { circuit: "amm_swap_v2" }), (e: unknown) => e instanceof ConfigError && /sent for circuit amm_swap, not amm_swap_v2/.test(e.message));
    await assert.rejects(client.fetch(p.requestId, { namespace: 7 }), (e: unknown) => e instanceof ConfigError && /sent in namespace/.test(e.message));
    // the answer for the circuit the request was built for passes
    mock.on("POST", "/v1/fetch", async () => ({ status: 200, body: await answer(p.requestId, { vk: V1 }) }));
    assert.equal((await client.fetch(p.requestId)).vk_hash, V1);
    // a foreign id: the caller names the circuit, and the same rule holds
    const foreign = newRequestId();
    mock.on("POST", "/v1/fetch", async () => ({ status: 200, body: await answer(foreign, { vk: V2 }) }));
    await assert.rejects(client.fetch(foreign, { circuit: "amm_swap" }), relabelled);
    assert.equal((await client.fetch(foreign, { circuit: "amm_swap_v2" })).vk_hash, V2);
    // with neither a saved body nor a circuit, or for an unconfigured circuit,
    // nothing is sent
    const sent = mock.count("POST", "/v1/fetch");
    await assert.rejects(client.fetch(foreign), (e: unknown) => e instanceof ConfigError && /no saved body/.test(e.message));
    await assert.rejects(client.fetch(foreign, { circuit: "pss_seed" }), (e: unknown) => e instanceof ConfigError && /no vk hash pinned/.test(e.message));
    assert.equal(mock.count("POST", "/v1/fetch"), sent);
  });

  test("a circuit needs its registered circuit and manifest for its answers to be checked", async () => {
    const client = new PssClient(config(url));
    await assert.rejects(client.buildRequest({ circuit: "pss_seed", stateKeys: { writes: ["0xa003"] } }), (e: unknown) => {
      assert.ok(e instanceof ConfigError);
      assert.match(e.message, /pss_seed: no circuit and manifest in the configuration/);
      return true;
    });
    const manifest = structuredClone(AMM_SWAP.manifest) as { outputs: { note_hash: string }[] };
    manifest.outputs[0]!.note_hash = "new_note_hashes[1]";
    assert.throws(() => new PssClient(config(url, { circuits: { amm_swap: { ...AMM_SWAP, manifest } } })), /circuits\.amm_swap: .*`new_note_hashes\[1\]` is not one element/);
    manifest.outputs[0]!.note_hash = "npk_app_hash";
    assert.equal(new PssClient(config(url, { circuits: { amm_swap: { ...AMM_SWAP, manifest } } })).config.noteHashIndices.amm_swap![0], 9);
    assert.deepEqual(client.config.noteHashIndices, { amm_swap: [8], client_swap: [8] });
  });

  test("the local verifier hook can refuse a proof", async () => {
    let seen = "";
    const client = new PssClient(
      config(url, {
        verifyProof: async ({ circuit }) => {
          seen = circuit;
          return false;
        },
      }),
    );
    const p = await client.buildRequest(swapInput);
    mock.on("POST", "/v1/execute", async () => ({ status: 200, body: await answer(p.requestId) }));
    await assert.rejects(client.execute(p), /local verifier refused/);
    assert.equal(seen, "amm_swap");
  });

  test("a timeout after sending goes to FETCH, not to a second execute", async () => {
    const client = new PssClient(config(url, { timeoutMs: 150 }));
    const p = await client.buildRequest(swapInput);
    mock.on("POST", "/v1/execute", () => ({ hang: true }));
    // the round is still running at the first FETCH, then commits
    mock.on("POST", "/v1/fetch", async (_r, n) =>
      n === 1
        ? { status: 404, body: { error: "unknown request id", class: "not_found" } }
        : { status: 200, body: await answer(p.requestId) },
    );
    const out = await client.execute(p);
    assert.equal(out.via, "fetch");
    assert.equal(mock.count("POST", "/v1/execute"), 1);
    assert.equal(mock.count("POST", "/v1/fetch"), 2);
    const fetchBody = JSON.parse(mock.received.find((r) => r.path === "/v1/fetch")!.body);
    assert.deepEqual(fetchBody, { namespace: NS, request_id: p.requestId });
  });

  test("a dropped connection goes to FETCH as well", async () => {
    const client = new PssClient(config(url));
    const p = await client.buildRequest(swapInput);
    mock.on("POST", "/v1/execute", () => ({ drop: true }));
    mock.on("POST", "/v1/fetch", async () => ({ status: 200, body: await answer(p.requestId) }));
    const out = await client.execute(p);
    assert.equal(out.via, "fetch");
  });

  test("FETCH 404 after a send failure is an unknown outcome carrying the saved body", async () => {
    const store = new MemoryRequestStore();
    const client = new PssClient(config(url, { timeoutMs: 100 }), { store });
    const p = await client.buildRequest(swapInput);
    mock.on("POST", "/v1/execute", () => ({ hang: true }));
    mock.on("POST", "/v1/fetch", () => ({ status: 404, body: { error: "unknown request id", class: "not_found" } }));
    await assert.rejects(client.execute(p), (e: unknown) => {
      assert.ok(e instanceof UnknownOutcomeError);
      assert.equal(e.requestId, p.requestId);
      assert.equal(e.body, p.json);
      assert.ok(e.cause instanceof SidecarError && e.cause.class === "not_found");
      return true;
    });
    assert.equal(mock.count("POST", "/v1/fetch"), 3);
    // the caller resends the SAME body
    mock.on("POST", "/v1/execute", async (r) => ({ status: 200, body: await answer(JSON.parse(r.body).request_id) }));
    const out = await client.resend(p.requestId);
    assert.equal(out.via, "execute");
    const sends = mock.received.filter((r) => r.path === "/v1/execute");
    assert.equal(sends.length, 2);
    assert.equal(sends[1]!.body, sends[0]!.body);
    assert.equal(sends[1]!.body, p.json);
  });

  test("refusals map to SidecarError with the server's class", async () => {
    const client = new PssClient(config(url));
    const p = await client.buildRequest(swapInput);
    mock.on("POST", "/v1/execute", () => ({
      status: 409,
      body: { error: "state already consumed (once)", class: "conflict" },
    }));
    await assert.rejects(client.execute(p), (e: unknown) => {
      assert.ok(e instanceof SidecarError);
      assert.equal(e.status, 409);
      assert.equal(e.class, "conflict");
      assert.equal(e.message, "state already consumed (once)");
      return true;
    });
    assert.equal(mock.count("POST", "/v1/fetch"), 0);
    for (const [status, cls] of [
      [400, "bad_request"],
      [403, "forbidden"],
      [422, "unsatisfied"],
      [500, "mpc_failure"],
    ] as const) {
      mock.on("POST", "/v1/execute", () => ({ status, body: { error: "x", class: cls } }));
      await assert.rejects(client.execute(p), (e: unknown) => e instanceof SidecarError && e.status === status && e.class === cls);
    }
    assert.equal(mock.count("POST", "/v1/fetch"), 0);
    // a body that is not a sidecar refusal
    mock.on("POST", "/v1/execute", () => ({ status: 418, body: "teapot" }));
    await assert.rejects(client.execute(p), (e: unknown) => e instanceof SidecarError && e.class === "unknown" && e.status === 418);
    // a gateway error says nothing about the outcome: FETCH
    mock.on("POST", "/v1/execute", () => ({ status: 502, body: "<html>bad gateway</html>" }));
    mock.on("POST", "/v1/fetch", async () => ({ status: 200, body: await answer(p.requestId) }));
    assert.equal((await client.execute(p)).via, "fetch");
  });

  test("fetch and getPackage", async () => {
    const client = new PssClient(config(url));
    const id = "0x41D3000000000000000000000000BEEF";
    const wide = "0x" + "0".repeat(32) + id.slice(2).toLowerCase();
    mock.on("POST", "/v1/fetch", async () => ({ status: 200, body: await answer(wide) }));
    const r = await client.fetch(id, { circuit: "amm_swap" });
    assert.equal(r.request_id, wide);
    assert.deepEqual(JSON.parse(mock.received.at(-1)!.body), { namespace: NS, request_id: wide });
    mock.on("POST", "/v1/fetch", () => ({ status: 404, body: { error: "unknown", class: "not_found" } }));
    await assert.rejects(client.fetch(id, { circuit: "amm_swap" }), (e: unknown) => e instanceof SidecarError && e.class === "not_found");
    await assert.rejects(client.fetch("0x" + BN254_MODULUS.toString(16), { circuit: "amm_swap" }), /modulus/);
    await assert.rejects(client.fetch("not-an-id", { circuit: "amm_swap" }), /1 to 64 digit/);
    const path = `/v1/packages/${NS}/amm_swap`;
    mock.on("GET", path, () => ({
      status: 200,
      body: { namespace: NS, name: "amm_swap", manifest_hash: fieldHex(0x6d), circuit: { abi: {} }, manifest: { manifest: 1 }, vk: "0x00ff", vk_hash: VK, disabled: false, seq: 2 },
    }));
    const pkg = await client.getPackage(NS, "amm_swap");
    assert.equal(pkg.vk_hash, VK);
    assert.equal(pkg.manifest_hash, fieldHex(0x6d));
    assert.equal(pkg.vk, "0x00ff");
    assert.equal(pkg.seq, 2);
    assert.equal(pkg.disabled, false);
  });

  test("shared inputs are sealed to the pinned enc keys and checked before saving", async () => {
    const store = new MemoryRequestStore();
    const client = new PssClient(config(url, { nodeKeys: REAL_KEYS }), { store });
    const signer = RequesterKey.generate();
    const good = await client.buildRequest({ ...swapInput, sharedInputs: [{ name: "door", value: 2 }], signer });
    const input = good.body.shared_inputs[0]!;
    assert.equal(input.name, "door");
    for (const [i, share] of input.shares.entries()) assert.equal(input.share_hashes[i], await shareHash(share));
    const bad = structuredClone(good);
    bad.body.shared_inputs[0]!.share_hashes = [input.share_hashes[1], input.share_hashes[0], input.share_hashes[2]];
    // a body edited without its json is not what would be sent
    await assert.rejects(client.execute(bad), /the prepared json is not the prepared body/);
    bad.json = JSON.stringify(bad.body);
    await assert.rejects(client.execute(bad), /share_hashes\[0\]: not the hash/);
    assert.deepEqual(await store.list(), []);
    mock.on("POST", "/v1/execute", async () => ({ status: 200, body: await answer(good.requestId) }));
    await client.execute(good);
    assert.equal(mock.received.at(-1)!.body, good.json);
    // the unpinned test keys are not curve points: nothing is sealed to them
    await assert.rejects(new PssClient(config(url)).buildRequest({ ...swapInput, sharedInputs: [{ name: "door", value: 2 }], signer }), /not a point on Grumpkin/);
  });

  test("a lost answer is retried by FETCH, then the identical saved body, never a re-encryption", async () => {
    const store = new MemoryRequestStore();
    const client = new PssClient(config(url, { nodeKeys: REAL_KEYS, timeoutMs: 100 }), { store });
    const signer = RequesterKey.generate();
    const rec = { key: "0xb001", note_hash: "0x77", c: [third(0), third(1), third(2)] as [string, string, string] };
    const p = await client.buildRequest({ ...clientSwapInput, sharedInputs: [{ name: "door", value: 1 }], records: [rec], signer });
    mock.on("POST", "/v1/execute", () => ({ hang: true }));
    mock.on("POST", "/v1/fetch", () => ({ status: 404, body: { error: "unknown request id", class: "not_found" } }));
    await assert.rejects(client.execute(p), UnknownOutcomeError);
    const fetchesBefore = mock.count("POST", "/v1/fetch");
    mock.on("POST", "/v1/execute", async (r) => ({ status: 200, body: await answer(JSON.parse(r.body).request_id, { records: [NEW_RECORD] }) }));
    const out = await client.resend(p.requestId);
    assert.equal(out.via, "execute");
    assert.equal(mock.count("POST", "/v1/fetch"), fetchesBefore + 1);
    const sends = mock.received.filter((r) => r.path === "/v1/execute");
    assert.equal(sends.length, 2);
    assert.equal(sends[1]!.body, sends[0]!.body);
    assert.equal(sends[1]!.body, p.json);
    // the round's new record is kept with the request that created it
    const kept = await client.recordStore.latest(NS, "0xb001");
    assert.deepEqual(kept, { namespace: NS, key: "0xb001", note_hash: NEW_NOTE_HASH, c: NEW_RECORD.c, request_id: p.requestId });
    // a resend of a committed id is answered by FETCH alone
    mock.on("POST", "/v1/fetch", async () => ({ status: 200, body: await answer(p.requestId, { records: [NEW_RECORD] }) }));
    assert.equal((await client.resend(p.requestId)).via, "fetch");
    assert.equal(mock.count("POST", "/v1/execute"), 2);
  });

  test("resend checks the saved body as execute does before any FETCH or send", async () => {
    const store = new MemoryRequestStore();
    const client = new PssClient(config(url, { nodeKeys: REAL_KEYS }), { store });
    const signer = RequesterKey.generate();
    const rec = { key: "0xb001", note_hash: "0x77", c: [third(0), third(1), third(2)] as [string, string, string] };
    const p = await client.buildRequest({ ...clientSwapInput, sharedInputs: [{ name: "door", value: 1 }], records: [rec], signer });
    mock.on("POST", "/v1/fetch", () => ({ status: 404, body: { error: "unknown request id", class: "not_found" } }));
    mock.on("POST", "/v1/execute", async (r) => ({ status: 200, body: await answer(JSON.parse(r.body).request_id, { records: [NEW_RECORD] }) }));
    const resave = async (edit: (b: ExecuteRequest) => unknown) => {
      const b = structuredClone(p.body);
      edit(b);
      await store.save(p.requestId, JSON.stringify(b));
    };
    // share_hashes[0] swapped with share_hashes[1]
    await resave((b) => {
      const h = b.shared_inputs[0]!.share_hashes;
      b.shared_inputs[0]!.share_hashes = [h[1], h[0], h[2]];
    });
    await assert.rejects(client.resend(p.requestId), /^RangeError: shared_inputs\[0\]\.share_hashes\[0\]: not the hash of shares\[0\]$/);
    // a record third changed after hashing
    await resave((b) => {
      b.records[0]!.c[1] = third(4);
    });
    await assert.rejects(client.resend(p.requestId), /records\[0\]\.record_hashes\[1\]: not the hash of c\[1\]/);
    // the signature dropped, or the body edited under it
    await resave((b) => {
      delete b.signature;
    });
    await assert.rejects(client.resend(p.requestId), /signature: a request that supplies records must be signed/);
    await resave((b) => {
      b.public.amount_in = fieldHex(1);
    });
    await assert.rejects(client.resend(p.requestId), /signature: does not verify/);
    // a body saved under another id, or not an execute request
    await store.save(p.requestId, JSON.stringify({ ...p.body, request_id: newRequestId() }));
    await assert.rejects(client.resend(p.requestId), /the body carries request_id/);
    await store.save(p.requestId, "{not json");
    await assert.rejects(client.resend(p.requestId), /the body is not JSON/);
    assert.equal(mock.count("POST", "/v1/fetch"), 0);
    assert.equal(mock.count("POST", "/v1/execute"), 0);
    // the saved body as built passes and is sent unchanged after the FETCH
    await store.save(p.requestId, p.json);
    assert.equal((await client.resend(p.requestId)).via, "execute");
    assert.equal(mock.received.at(-1)!.body, p.json);
  });
});

describe("JsonFileRequestStore", () => {
  test("saves, lists, loads and deletes across instances", async () => {
    const dir = scratchDir();
    try {
      const path = join(dir, "sub", "requests.json");
      const a = new JsonFileRequestStore(path);
      await Promise.all([a.save("0x01", '{"a":1}'), a.save("0x02", '{"b":2}')]);
      const b = new JsonFileRequestStore(path);
      assert.deepEqual((await b.list()).sort(), ["0x01", "0x02"]);
      assert.equal(await b.load("0x02"), '{"b":2}');
      await b.delete("0x01");
      assert.deepEqual(JSON.parse(await readFile(path, "utf8")), { "0x02": '{"b":2}' });
      assert.equal(await new JsonFileRequestStore(join(dir, "none.json")).load("0x01"), undefined);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});
