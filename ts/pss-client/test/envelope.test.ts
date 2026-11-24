// The request-side cryptography against the Rust vectors: testvectors/ae.json
// (the Poseidon2 duplex), keys.json (key ids) and envelope.json (a complete
// sealed Monty Hall request with a record, its canonical body, body hash, input
// body hash and six envelopes), which sidecar-core's tests wrote.

import assert from "node:assert/strict";
import { rm } from "node:fs/promises";
import { join } from "node:path";
import { describe, test } from "node:test";

import { poseidon2HashBytes } from "@aztec-labs/foundation/crypto/poseidon";

import {
  BN254_MODULUS,
  EXECUTE_DOMAIN,
  JsonFileRecordStore,
  MemoryRecordStore,
  RequesterKey,
  TagMismatchError,
  aeDecrypt,
  aeEncrypt,
  bodyHash,
  buildExecuteRequestWith,
  canonicalBody,
  canonicalJson,
  envelopeNonce,
  executeMessage,
  fieldHex,
  inputBodyHash,
  keyId,
  openEnvelope,
  patternTag,
  recordHash,
  recordKeyId,
  recordsFromResponse,
  sealEnvelope,
  sealSharedInput,
  shareField,
  shareHash,
  sharePair,
  verifySignature,
  type EnvelopeAd,
  type ExecuteRequest,
  type RecordStore,
  type ShareCiphertext,
  type StoredRecord,
} from "../src/internal.ts";
import { hex, scratchDir, vectorJson } from "@aztec-pss/test-support";


interface AeVector {
  n: number;
  key: string;
  nonce: string;
  pattern_tag: string;
  plaintext: string[];
  ciphertext: string[];
  tag: string;
}
interface Point {
  x: string;
  y: string;
}
interface KeyVector {
  node: number;
  enc: string;
  enc_pk: Point;
  key_id: string;
}
interface EnvelopeVector {
  i: number;
  name: string;
  eph: string;
  E: Point;
  enc_pk: Point;
  nonce: string;
  pair: [string, string];
  shared_secret: string;
  ct: [string, string];
  tag: string;
  share_hash: string;
}

const AE = vectorJson("ae.json") as { vectors: AeVector[] };
const KEYS = vectorJson("keys.json") as { nodes: KeyVector[] };
const ENV = vectorJson("envelope.json") as {
  namespace: string;
  circuit: string;
  names: string[];
  values: string[];
  request: ExecuteRequest;
  canonical_body: string;
  body_hash: string;
  input_body: string;
  input_body_hash: string;
  envelopes: EnvelopeVector[];
};

const encKeys = KEYS.nodes.map((n) => n.enc_pk) as [Point, Point, Point];


describe("the Poseidon2 duplex AEAD (testvectors/ae.json)", () => {
  for (const v of AE.vectors) {
    test(`n = ${v.n}: pattern tag, ciphertext and tag match; it decrypts back`, async () => {
      assert.equal(hex(await patternTag(v.n)), v.pattern_tag);
      const sealed = await aeEncrypt(v.key, v.nonce, v.plaintext);
      assert.deepEqual(sealed.ciphertext.map(hex), v.ciphertext);
      assert.equal(hex(sealed.tag), v.tag);
      assert.deepEqual((await aeDecrypt(v.key, v.nonce, v.ciphertext, v.tag)).map(hex), v.plaintext);
    });
  }

  test("a changed key, nonce, ciphertext, tag or length does not open", async () => {
    const v = AE.vectors.find((x) => x.n === 4)!;
    const bump = (h: string) => hex((BigInt(h) + 1n) % BN254_MODULUS);
    const refused = (p: Promise<unknown>) => assert.rejects(p, TagMismatchError);
    await refused(aeDecrypt(bump(v.key), v.nonce, v.ciphertext, v.tag));
    await refused(aeDecrypt(v.key, bump(v.nonce), v.ciphertext, v.tag));
    await refused(aeDecrypt(v.key, v.nonce, [bump(v.ciphertext[0]!), ...v.ciphertext.slice(1)], v.tag));
    await refused(aeDecrypt(v.key, v.nonce, v.ciphertext, bump(v.tag)));
    await refused(aeDecrypt(v.key, v.nonce, v.ciphertext.slice(0, 3), v.tag));
    await refused(aeDecrypt(v.key, v.nonce, [], v.tag));
  });
});

describe("node key ids (testvectors/keys.json)", () => {
  test("key id = the first 8 bytes of poseidon2([enc_pk.x, enc_pk.y])", async () => {
    for (const n of KEYS.nodes) assert.equal(await keyId(n.enc_pk), n.key_id);
  });
  test("every third of the vector record starts with its node's key id", () => {
    ENV.request.records[0]!.c.forEach((c, i) => assert.equal(recordKeyId(c), KEYS.nodes[i]!.key_id));
  });
});

describe("the sealed Monty Hall request (testvectors/envelope.json)", () => {
  // The vector's requester is the Grumpkin key 5 · G.
  const requesterKey = RequesterKey.fromHex(fieldHex(5));
  const record = ENV.request.records[0]!;

  async function rebuild() {
    const sealing: Record<string, { sharing: [string, string, string]; eph: [string, string, string] }> = {};
    for (const name of ENV.names) {
      const envs = ENV.envelopes.filter((e) => e.name === name).sort((a, b) => a.i - b.i);
      // envelope i carries [x_i, x_{i-1}]
      sealing[name] = { sharing: envs.map((e) => e.pair[0]) as [string, string, string], eph: envs.map((e) => e.eph) as [string, string, string] };
    }
    return buildExecuteRequestWith(
      ENV.namespace,
      {
        circuit: ENV.circuit,
        public: ENV.request.public as Record<string, string>,
        stateKeys: ENV.request.state_keys,
        sharedInputs: ENV.names.map((name, k) => ({ name, value: ENV.values[k]! })),
        records: [{ key: record.key, note_hash: record.note_hash, c: record.c }],
        signer: requesterKey,
      },
      encKeys,
      { requestId: ENV.request.request_id, sealing },
    );
  }

  test("the whole request is reproduced: canonical body, body hash, input body hash", async () => {
    const built = await rebuild();
    const { signature, ...unsigned } = built.body;
    assert.ok(signature !== undefined);
    assert.deepEqual(unsigned, ENV.request);
    assert.equal(canonicalJson(canonicalBody(built.body)), ENV.canonical_body);
    assert.equal(await bodyHash(built.body), ENV.body_hash);
    const { shared_inputs: _omit, ...withoutInputs } = canonicalBody(built.body);
    assert.equal(canonicalJson(withoutInputs), ENV.input_body);
    assert.equal(await inputBodyHash(built.body), ENV.input_body_hash);
    // the vector's own body, re-spelled with short hex, has the same canonical form
    const short = structuredClone(ENV.request);
    short.namespace = "0x1f2ea9c0";
    short.records[0]!.note_hash = "0x77";
    assert.equal(canonicalJson(canonicalBody(short)), ENV.canonical_body);
  });

  test("record_hashes are the hashes of the given thirds", async () => {
    for (let i = 0; i < 3; i++) assert.equal(await recordHash(record.c[i]!), record.record_hashes[i]);
    await assert.rejects(recordHash(record.c[0]!.slice(0, -2)), /not a sealed state record/);
    await assert.rejects(recordHash(KEYS.nodes[0]!.key_id + "ff".repeat(64)), /not a sealed state record/);
  });

  test("the requester's signature verifies over the canonical body", async () => {
    const built = await rebuild();
    assert.deepEqual(built.body.requester, ENV.request.requester);
    const message = await executeMessage(built.body);
    const expected = await poseidon2HashBytes(Buffer.from(EXECUTE_DOMAIN + ENV.canonical_body, "utf8"));
    assert.equal(message.toString(), expected.toString());
    assert.ok(await verifySignature(message, ENV.request.requester!, built.body.signature!));
    assert.equal(await verifySignature(message, encKeys[0], built.body.signature!), false);
  });

  test("every envelope reproduces its nonce, E, ct, tag and share hash", async () => {
    for (const e of ENV.envelopes) {
      const ad: EnvelopeAd = { namespace: ENV.namespace, requestId: ENV.request.request_id, circuit: ENV.circuit, name: e.name, binds: ENV.input_body_hash };
      assert.deepEqual(e.enc_pk, encKeys[e.i]);
      assert.equal(hex(await envelopeNonce(ad, e.i)), e.nonce);
      const sealed = await sealEnvelope(e.enc_pk, e.i, ad, e.pair, e.eph);
      assert.deepEqual(sealed, { eph: e.E, ct: e.ct, tag: e.tag });
      assert.equal(await shareHash(sealed), e.share_hash);
      const input = ENV.request.shared_inputs.find((s) => s.name === e.name)!;
      assert.deepEqual(input.shares[e.i], sealed);
      assert.equal(input.share_hashes[e.i], e.share_hash);
      // node i opens it with its enc scalar
      assert.deepEqual((await openEnvelope(KEYS.nodes[e.i]!.enc, e.i, ad, sealed)).map(hex), e.pair);
    }
  });

  test("an envelope opens only at its node, for its request body", async () => {
    const e = ENV.envelopes[0]!;
    const ad: EnvelopeAd = { namespace: ENV.namespace, requestId: ENV.request.request_id, circuit: ENV.circuit, name: e.name, binds: ENV.input_body_hash };
    const env: ShareCiphertext = { eph: e.E, ct: e.ct, tag: e.tag };
    const refused = (p: Promise<unknown>) => assert.rejects(p, TagMismatchError);
    await refused(openEnvelope(KEYS.nodes[1]!.enc, e.i, ad, env));
    await refused(openEnvelope(KEYS.nodes[0]!.enc, 1, ad, env));
    await refused(openEnvelope(KEYS.nodes[0]!.enc, 0, { ...ad, name: "door_randomness" }, env));
    await refused(openEnvelope(KEYS.nodes[0]!.enc, 0, { ...ad, circuit: "monty_hall_finish" }, env));
    await refused(openEnvelope(KEYS.nodes[0]!.enc, 0, { ...ad, requestId: "0x41d3000000000000000000000000beee" }, env));
    await refused(openEnvelope(KEYS.nodes[0]!.enc, 0, { ...ad, namespace: "0x1f2ea9c1" }, env));
    await refused(openEnvelope(KEYS.nodes[0]!.enc, 0, { ...ad, binds: ENV.body_hash }, env));
  });
});

describe("sharing and sealing with fresh randomness", () => {
  test("the three shares sum to the value, each pair is [x_i, x_{i-1}], and two sharings differ", () => {
    for (const x of [0n, 1n, 0xdeadn, BN254_MODULUS - 1n]) {
      const s = shareField(x);
      assert.equal((s[0] + s[1] + s[2]) % BN254_MODULUS, x);
      for (const v of s) assert.ok(v >= 0n && v < BN254_MODULUS);
      assert.deepEqual(sharePair(s, 0), [s[0], s[2]]);
      assert.deepEqual(sharePair(s, 1), [s[1], s[0]]);
      assert.deepEqual(sharePair(s, 2), [s[2], s[1]]);
      assert.notDeepEqual(shareField(x), s);
    }
    assert.throws(() => sharePair([1n, 2n, 3n], 3), /out of range/);
  });

  test("seal then open round-trips at every node; a fresh eph each time", async () => {
    const ad: EnvelopeAd = { namespace: 7, requestId: "0x" + "ab".repeat(16), circuit: "c", name: "secret", binds: 9 };
    const s = shareField(42);
    for (let i = 0; i < 3; i++) {
      const pair = sharePair(s, i);
      const a = await sealEnvelope(encKeys[i]!, i, ad, pair);
      const b = await sealEnvelope(encKeys[i]!, i, ad, pair);
      assert.notDeepEqual(a.eph, b.eph);
      assert.deepEqual(await openEnvelope(KEYS.nodes[i]!.enc, i, ad, a), pair);
      assert.deepEqual(await openEnvelope(KEYS.nodes[i]!.enc, i, ad, b), pair);
    }
    await assert.rejects(sealEnvelope({ x: 1, y: 2 }, 0, ad, [1, 2]), /not a point on Grumpkin/);
    await assert.rejects(sealEnvelope(encKeys[0], 0, ad, [1, 2], 0), /ephemeral secret is zero/);
  });

  test("a request with shared inputs needs the enc keys; the sharing must sum to the value", async () => {
    const input = { circuit: "c", sharedInputs: [{ name: "x", value: 3 }] };
    await assert.rejects(buildExecuteRequestWith(1, input, undefined, { requestId: "0x" + "00".repeat(16) }), /pinned node enc keys/);
    await assert.rejects(
      buildExecuteRequestWith(1, { ...input, signer: RequesterKey.generate() }, encKeys, { requestId: "0x" + "00".repeat(16), sealing: { x: { sharing: [1, 1, 2] } } }),
      /does not sum to the value/,
    );
  });

  test("a refused secret is named, never echoed, in the error", async () => {
    const BAD_HEX = "0xdeadbeefsecret";
    const AT_MODULUS = "0x" + BN254_MODULUS.toString(16);
    const ABOVE = BN254_MODULUS + 0x5ec2e7n;
    const ad: EnvelopeAd = { namespace: 7, requestId: "0x" + "ab".repeat(16), circuit: "c", name: "door", binds: 9 };
    // the message, and nothing of the value: neither its digits nor its hex
    const refused = (what: string, reason: RegExp, ...values: string[]) => (e: unknown) => {
      assert.ok(e instanceof RangeError);
      assert.equal(e.message.startsWith(`${what}: `), true, e.message);
      assert.match(e.message, reason);
      for (const v of values) assert.equal(e.message.includes(v), false, `${e.message} contains ${v}`);
      return true;
    };
    const badHex = /^[^:]+(\[\d\])?[^:]*: not a 1 to 64 digit hex number$/;
    const atModulus = /: not below the bn254 scalar field modulus$/;
    const hexDigits = (s: string) => [s, s.slice(2), s.slice(2, 14)];
    const known = { requestId: "0x" + "00".repeat(16) };
    const build = (value: string | bigint) => buildExecuteRequestWith(1, { circuit: "c", sharedInputs: [{ name: "door", value }] }, encKeys, known);
    // building a request: the shared input's value
    await assert.rejects(build(BAD_HEX), refused("sharedInputs[0].value", badHex, ...hexDigits(BAD_HEX)));
    await assert.rejects(build(AT_MODULUS), refused("sharedInputs[0].value", atModulus, ...hexDigits(AT_MODULUS)));
    await assert.rejects(build(ABOVE), refused("sharedInputs[0].value", atModulus, ABOVE.toString(), ABOVE.toString(16), "5ec2e7"));
    // sealing directly, and a known-answer sharing
    await assert.rejects(sealSharedInput(ad, BAD_HEX, encKeys), refused("shared input `door`", badHex, ...hexDigits(BAD_HEX)));
    await assert.rejects(sealSharedInput(ad, AT_MODULUS, encKeys), refused("shared input `door`", atModulus, ...hexDigits(AT_MODULUS)));
    await assert.rejects(sealSharedInput(ad, 3, encKeys, { sharing: [1, AT_MODULUS, 2] }), refused("sharing[1]", atModulus, ...hexDigits(AT_MODULUS)));
    assert.throws(() => shareField(BAD_HEX), refused("shared value", badHex, ...hexDigits(BAD_HEX)));
    // the AE: a plaintext field and the key
    await assert.rejects(aeEncrypt(1, 2, [5, BAD_HEX]), refused("plaintext[1]", badHex, ...hexDigits(BAD_HEX)));
    await assert.rejects(aeEncrypt(1, 2, [AT_MODULUS]), refused("plaintext[0]", atModulus, ...hexDigits(AT_MODULUS)));
    await assert.rejects(aeEncrypt(AT_MODULUS, 2, [5]), refused("key", atModulus, ...hexDigits(AT_MODULUS)));
    await assert.rejects(aeEncrypt(1, 2, [Number.MAX_SAFE_INTEGER + 2]), refused("plaintext[0]", /: not a safe integer$/, String(Number.MAX_SAFE_INTEGER + 2)));
  });
});

describe("record stores", () => {
  const NS = fieldHex(0x1f2ea9c0);
  const response = (id: string, c: string[]) => ({
    request_id: id,
    vk_hash: fieldHex(1),
    proof: "0x00",
    public_inputs: [],
    stored: [],
    records: [{ key: "0xb001", note_hash: fieldHex(0x77), c: c as [string, string, string] }],
  });
  const ID1 = "0x" + "0".repeat(32) + "11".repeat(16);
  const ID2 = "0x" + "0".repeat(32) + "22".repeat(16);

  async function exercise(store: RecordStore) {
    const [first] = recordsFromResponse(NS, response(ID1, ENV.request.records[0]!.c));
    await store.put(first!);
    await store.put(first!); // the same record again is a no-op
    const edited: StoredRecord = { ...first!, c: [first!.c[1], first!.c[0], first!.c[2]] };
    await assert.rejects(store.put(edited), /never edited/);
    const [second] = recordsFromResponse(NS, response(ID2, [first!.c[2], first!.c[1], first!.c[0]]));
    await store.put(second!);
    assert.equal((await store.latest(NS, "0xb001"))!.request_id, ID2);
    assert.deepEqual((await store.history(NS, "0xb001")).map((r) => r.request_id), [ID1, ID2]);
    await store.markLanded(NS, "0xb001", ID2, { nonce: 5, tx_hash: "0xabc" });
    const landed = (await store.latest(NS, "0xb001"))!;
    assert.equal(landed.nonce, fieldHex(5));
    assert.equal(landed.tx_hash, "0xabc");
    assert.deepEqual(landed.c, second!.c);
    await store.pruneBefore(NS, "0xb001", ID2);
    assert.deepEqual((await store.history(NS, "0xb001")).map((r) => r.request_id), [ID2]);
    assert.equal(await store.latest(NS, "0xb002"), undefined);
  }

  test("MemoryRecordStore keeps every record, newest last, and never edits a third", async () => {
    await exercise(new MemoryRecordStore());
  });

  test("JsonFileRecordStore does the same across instances", async () => {
    const dir = scratchDir();
    try {
      const path = join(dir, "records.json");
      await exercise(new JsonFileRecordStore(path));
      assert.equal((await new JsonFileRecordStore(path).latest(NS, "0xb001"))!.request_id, ID2);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});
