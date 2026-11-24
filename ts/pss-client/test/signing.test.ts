// The signer and the message rule against the Rust vectors in
// testvectors/schnorr.json, which sidecar-core's write_vectors test wrote and
// noir-lang/schnorr v0.4.0's own pinned vectors seed.

import assert from "node:assert/strict";
import { readFile, rm, stat } from "node:fs/promises";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { inspect } from "node:util";
import { describe, test } from "node:test";

import { Schnorr, SchnorrSignature } from "@aztec-labs/foundation/crypto/schnorr";
import { Fr } from "@aztec-labs/foundation/curves/bn254";
import { GrumpkinScalar, Point } from "@aztec-labs/foundation/curves/grumpkin";

import {
  DISABLE_DOMAIN,
  EXECUTE_DOMAIN,
  OwnerKey,
  RequesterKey,
  REGISTER_DOMAIN,
  canonicalJson,
  disableBody,
  disableMessage,
  fieldHex,
  messageFor,
  registerMessage,
  signDisable,
  signManifest,
  signatureFromBytes,
  signatureToBytes,
  verifySignature,
  type GrumpkinPoint,
  type Signature,
} from "../src/internal.ts";
import { scratchDir } from "@aztec-pss/test-support";

interface Vector {
  name: string;
  source: string;
  message: string;
  pubkey: GrumpkinPoint;
  signature: Signature;
  expected: boolean;
}
interface SignedMessage {
  name: string;
  domain: string;
  body_without_signature: Record<string, unknown>;
  canonical: string;
  message: string;
}

const VECTORS = JSON.parse(readFileSync(new URL("../../../testvectors/schnorr.json", import.meta.url), "utf8")) as {
  vectors: Vector[];
  signed_messages: SignedMessage[];
};
const vector = (name: string) => VECTORS.vectors.find((v) => v.name === name)!;
const signedMessage = (name: string) => VECTORS.signed_messages.find((v) => v.name === name)!;

// foundation's verifier on the 64-byte form, without this package's checks.
async function foundationVerify(v: { message: string; pubkey: GrumpkinPoint; signature: Signature }): Promise<boolean> {
  try {
    const pk = new Point(Fr.fromString(v.pubkey.x), Fr.fromString(v.pubkey.y));
    const sig = new SchnorrSignature(Buffer.from(signatureToBytes(v.signature)));
    return await new Schnorr().verifySignature(Fr.fromString(v.message), pk, sig);
  } catch {
    return false;
  }
}

describe("Schnorr vectors", () => {
  test("the file has the twelve vectors and five signed messages", () => {
    assert.equal(VECTORS.vectors.length, 12);
    assert.equal(VECTORS.signed_messages.length, 5);
  });

  for (const v of VECTORS.vectors) {
    test(`${v.name}: ${v.expected ? "verifies" : "is refused"}`, async () => {
      assert.equal(await foundationVerify(v), v.expected, "foundation Schnorr.verifySignature");
      assert.equal(await verifySignature(v.message, v.pubkey, v.signature), v.expected, "verifySignature");
      // limbs -> 64 bytes -> limbs is the identity
      assert.deepEqual(signatureFromBytes(signatureToBytes(v.signature)), v.signature);
    });
  }

  test("the 64-byte layout is s.hi s.lo e.hi e.lo", () => {
    const bytes = new Uint8Array(64).map((_, i) => i + 1);
    const sig = signatureFromBytes(bytes);
    const limb = (from: number) => fieldHex("0x" + Buffer.from(bytes.slice(from, from + 16)).toString("hex"));
    assert.deepEqual(sig, { s: [limb(16), limb(0)], e: [limb(48), limb(32)] });
    assert.throws(() => signatureToBytes({ s: ["0x" + "1".repeat(33), "0x0"], e: ["0x1", "0x0"] }), /not below 2\^128/);
    assert.throws(() => signatureFromBytes(new Uint8Array(63)), /63 bytes/);
  });

  test("keys off the curve and out-of-range limbs are refused, not thrown", async () => {
    const v = vector("rust_register_body");
    assert.equal(await verifySignature(v.message, { x: "0x0", y: "0x0" }, v.signature), false);
    assert.equal(await verifySignature(v.message, { x: v.pubkey.x, y: "0x5" }, v.signature), false);
    const wide: Signature = { s: [fieldHex(1n << 128n), v.signature.s[1]], e: v.signature.e };
    assert.equal(await verifySignature(v.message, v.pubkey, wide), false);
  });
});

describe("signed-body messages", () => {
  for (const m of VECTORS.signed_messages) {
    test(`${m.name}: canonical form and message match byte for byte`, async () => {
      assert.ok(Buffer.from(canonicalJson(m.body_without_signature), "utf8").equals(Buffer.from(m.canonical, "utf8")));
      assert.equal((await messageFor(m.domain, m.body_without_signature)).toString(), m.message);
      // a top-level signature member is left out
      const withSig = { ...m.body_without_signature, signature: { s: ["0x1", "0x2"], e: ["0x3", "0x4"] } };
      assert.equal((await messageFor(m.domain, withSig)).toString(), m.message);
      // (an execute request's helper, executeMessage, takes a typed request and
      // applies the canonical body first; the envelope vectors check it)
      const helper = {
        [REGISTER_DOMAIN]: registerMessage,
        [DISABLE_DOMAIN]: disableMessage,
        [EXECUTE_DOMAIN]: (b: object) => messageFor(EXECUTE_DOMAIN, b),
      }[m.domain]!;
      assert.equal((await helper(m.body_without_signature)).toString(), m.message);
    });
  }

  test("the domains are sidecar-core's", () => {
    assert.equal(REGISTER_DOMAIN, "cosnark-sidecar/v1/register");
    assert.equal(DISABLE_DOMAIN, "cosnark-sidecar/v1/disable");
    assert.equal(EXECUTE_DOMAIN, "cosnark-sidecar/v1/execute");
  });

  test("the Rust-signed REGISTER body verifies under the REGISTER message", async () => {
    const m = signedMessage("register_like");
    const v = vector("rust_register_body");
    assert.equal(v.message, m.message);
    const body = { ...m.body_without_signature, signature: v.signature };
    assert.deepEqual(m.body_without_signature.owner_pubkey, v.pubkey);
    assert.ok(await verifySignature(await registerMessage(body), v.pubkey, v.signature));
    assert.equal(await verifySignature(await disableMessage(body), v.pubkey, v.signature), false);
    assert.equal(await verifySignature(await registerMessage({ ...body, name: "pss_seeds" }), v.pubkey, v.signature), false);
  });

  test("canonicalJson refuses what the nodes would read differently", () => {
    assert.equal(canonicalJson({ b: -(2 ** 53 - 1), a: [0, -0], c: undefined }), `{"a":[0,0],"b":-9007199254740991}`);
    assert.throws(() => canonicalJson({ a: 1.5 }), /not an integer/);
    assert.throws(() => canonicalJson([2 ** 53]), /not an integer/);
    assert.throws(() => canonicalJson(Number.NaN), /not an integer/);
    assert.throws(() => canonicalJson("\ud800"), /lone surrogate/);
    assert.throws(() => canonicalJson({ ["\udc00"]: 1 }), /lone surrogate/);
    assert.throws(() => canonicalJson(1n), /cannot encode a bigint/);
  });

  test("messageFor signs the body as sent and refuses non-objects", async () => {
    const m = signedMessage("register_small");
    // a member with a toJSON is signed as JSON.stringify sends it
    const viaToJson = { ...m.body_without_signature, a: { toJSON: () => 1 } };
    assert.equal((await registerMessage(viaToJson)).toString(), m.message);
    await assert.rejects(messageFor(REGISTER_DOMAIN, [1, 2]), /not a JSON object/);
  });
});

describe("SchnorrKey, as OwnerKey and RequesterKey", () => {
  test("a key serialises without its secret", () => {
    assert.equal(JSON.stringify({ requester: RequesterKey.generate() }), '{"requester":"SchnorrKey"}');
  });

  test("the TypeScript signer verifies under the vector's verifier", async () => {
    // The vector carries no private key, so sign its message with a fresh key.
    const v = vector("typescript_signer");
    const key = OwnerKey.generate();
    const pubkey = await key.publicKey();
    const sig = await key.sign(Fr.fromString(v.message));
    assert.ok(await verifySignature(v.message, pubkey, sig));
    assert.ok(await foundationVerify({ message: v.message, pubkey, signature: sig }));
    assert.equal(await verifySignature(v.message, v.pubkey, sig), false);
    for (const limb of [...sig.s, ...sig.e]) assert.ok(BigInt(limb) < 1n << 128n);
  });

  test("public key is secret·G, as foundation computes it", async () => {
    const secret = 0x2a_1234n;
    const key = OwnerKey.fromHex("0x" + secret.toString(16).padStart(64, "0"));
    const p = await new Schnorr().computePublicKey(new GrumpkinScalar(secret));
    assert.deepEqual(await key.publicKey(), { x: fieldHex(p.x.toBigInt()), y: fieldHex(p.y.toBigInt()) });
  });

  test("hex and file round trips; the file is 0600 and never overwritten", async () => {
    const key = OwnerKey.generate();
    assert.notEqual(key.toHex(), OwnerKey.generate().toHex());
    assert.match(key.toHex(), /^0x[0-9a-f]{64}$/);
    assert.equal(OwnerKey.fromHex(key.toHex()).toHex(), key.toHex());
    const dir = scratchDir();
    try {
      const path = join(dir, "keys", "owner.key");
      await key.save(path);
      assert.equal((await stat(path)).mode & 0o777, 0o600);
      assert.equal(await readFile(path, "utf8"), key.toHex() + "\n");
      assert.deepEqual(await (await OwnerKey.load(path)).publicKey(), await key.publicKey());
      await assert.rejects(OwnerKey.generate().save(path), /EEXIST/);
      assert.equal((await OwnerKey.load(path)).toHex(), key.toHex());
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  test("bad keys are refused and the secret is never printed", () => {
    assert.throws(() => OwnerKey.fromHex("0x" + "0".repeat(64)), /zero scalar/);
    assert.throws(() => OwnerKey.fromHex("0x" + GrumpkinScalar.MODULUS.toString(16)), /not below the Grumpkin scalar order/);
    assert.throws(() => OwnerKey.fromHex("0x1234"), /64 hex digits/);
    const key = OwnerKey.generate();
    const digits = key.toHex().slice(2);
    assert.ok(!JSON.stringify({ key }).includes(digits));
    assert.ok(!inspect(key, { depth: 5, showHidden: true }).includes(digits));
    assert.ok(!String(key).includes(digits));
  });

  test("signManifest adds owner_pubkey and a signature over the body including it and seq", async () => {
    const key = OwnerKey.generate();
    const m = signedMessage("register_like");
    const namespace = m.body_without_signature.namespace as string;
    const manifest = { contract_manifest: 1, name: "app" };
    const circuits = { c: { noir_version: "1.0.0" } };
    const signed = await signManifest({ namespace, manifest, circuits, seq: 3 }, key);
    assert.equal(signed.namespace, fieldHex(namespace));
    assert.equal(signed.seq, 3);
    assert.deepEqual(signed.owner_pubkey, await key.publicKey());
    assert.deepEqual(Object.keys(signed).sort(), ["circuits", "manifest", "namespace", "owner_pubkey", "seq", "signature"]);
    assert.ok(await verifySignature(await registerMessage(signed), signed.owner_pubkey, signed.signature));
    // owner_pubkey, seq and the manifest are covered
    const other = await OwnerKey.generate().publicKey();
    assert.equal(await verifySignature(await registerMessage({ ...signed, owner_pubkey: other }), signed.owner_pubkey, signed.signature), false);
    assert.equal(await verifySignature(await registerMessage({ ...signed, seq: 4 }), signed.owner_pubkey, signed.signature), false);
    assert.equal(await verifySignature(await registerMessage({ ...signed, manifest: { ...manifest, name: "b" } }), signed.owner_pubkey, signed.signature), false);
    await assert.rejects(signManifest({ namespace, manifest, circuits, seq: -1 }, key), /seq: not a non-negative integer/);
  });

  test("signDisable signs {namespace, circuit, owner_pubkey, seq} under the DISABLE domain", async () => {
    const key = OwnerKey.generate();
    const m = signedMessage("disable");
    const body = disableBody(m.body_without_signature.namespace as string, m.body_without_signature.circuit as string, 1);
    const signed = await signDisable(body, key);
    assert.deepEqual(Object.keys(signed).sort(), ["circuit", "namespace", "owner_pubkey", "seq", "signature"]);
    assert.ok(await verifySignature(await disableMessage(signed), signed.owner_pubkey, signed.signature));
    assert.equal(await verifySignature(await disableMessage({ ...signed, seq: 2 }), signed.owner_pubkey, signed.signature), false);
    assert.equal(await verifySignature(await registerMessage(signed), signed.owner_pubkey, signed.signature), false);
    assert.throws(() => disableBody(1, "", 1), /^RangeError: circuit: empty circuit name$/);
    assert.throws(() => disableBody(1, "c\0", 1), /^RangeError: circuit: circuit name .* has byte 0x00/);
    assert.throws(() => disableBody(1, "c", 1.5), /seq/);
  });
});
