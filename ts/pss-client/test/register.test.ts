// REGISTER (the manifest message) and DISABLE against a mock orchestrator
// that applies the nodes' owner, seq and contract manifest rules and signs its
// answers with three node keys, and the registry vectors of
// testvectors/registry.json (signed bodies with seq and the nodes' signed
// answers), which sidecar-core's tests wrote.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { after, before, beforeEach, describe, test } from "node:test";

import {
  OwnerKey,
  SchnorrKey,
  ProtocolError,
  PssClient,
  REGISTRY_DOMAIN,
  ConfigError,
  SidecarError,
  NODE_KEYS_LEN,
  NODE_KEYS_SLOT,
  buildContractManifest,
  contractManifestHash,
  disableBody,
  disableMessage,
  fieldHex,
  manifestMessage,
  packagesHash,
  MANIFEST_DOMAIN,
  registerMessage,
  registryMessage,
  signDisable,
  signManifest,
  verifyRegistryAnswer,
  verifySignature,
  type ContractManifest,
  type GrumpkinPoint,
  type KeyEpochNode,
  type PssClientConfig,
  type Signature,
} from "../src/internal.ts";
import { Fr } from "@aztec-labs/foundation/curves/bn254";
import { MockOrchestrator, MockRegistry, fixture } from "@aztec-pss/test-support";

interface RegistryResult {
  node: number;
  namespace: string;
  name: string;
  vk_hash: string;
  npk_app_hash: string;
  seq: number;
  disabled: boolean;
  message: string;
  sig_secret: string;
  sig_pubkey: GrumpkinPoint;
  signature: Signature;
}
const VECTORS = JSON.parse(readFileSync(new URL("../../../testvectors/registry.json", import.meta.url), "utf8")) as {
  registry_domain: string;
  owner_pubkey: GrumpkinPoint;
  register: { body: Record<string, unknown> & { owner_pubkey: GrumpkinPoint; signature: Signature }; message: string };
  disable: { body: Record<string, unknown> & { owner_pubkey: GrumpkinPoint; signature: Signature }; message: string };
  results: RegistryResult[];
  manifest: {
    manifest_domain: string;
    namespace: string;
    manifest_hash: string;
    packages_hash: string;
    npk_app_hash: string;
    seq: number;
    results: { node: number; message: string; sig_pubkey: GrumpkinPoint; signature: Signature }[];
  };
};
const NODE_SIG = VECTORS.results.filter((r) => !r.disabled).sort((a, b) => a.node - b.node);
const SIG_KEYS = NODE_SIG.map((r) => r.sig_pubkey) as [GrumpkinPoint, GrumpkinPoint, GrumpkinPoint];

const NS = "0x1ac1704880851219793ebcb14b7d910d576186d4846fa8b42b51108ebd236888";
const PSS_SEED_VK_HASH = "0x255a24297767ccd4fea94c6bfcc2aec6057adb3433a6fc6d16da2883e2b5a3d6";
const NPK_APP_HASH = fieldHex(0x1f21c078530872675c230b247bed26ffce80c76ab6eeb360895ca8cbd8b92e16n);
const AMM_INIT_VK_HASH = fieldHex(0xa171);
// the compiled circuit every package runs here (the mock builds no vk), with
// the `hash` member nargo writes
const CIRCUIT = { ...(fixture("pss_seed.circuit.json") as object), hash: "7" };
const CIRCUITS = { pss_seed: CIRCUIT, amm_init: CIRCUIT };
const example = (name: string) => JSON.parse(readFileSync(new URL(`../../../examples/amm/manifests/${name}.json`, import.meta.url), "utf8")) as unknown;

/** The sidecar-path contract manifest of examples/amm's `names`. */
async function manifestOf(names: string[]): Promise<ContractManifest> {
  return buildContractManifest({
    descriptor: { descriptor: 1, name: "amm", packages: names.map((n) => ({ name: n, circuit: n })) },
    manifests: Object.fromEntries(names.map((n) => [n, example(n)])),
    vkHashes: { pss_seed: PSS_SEED_VK_HASH, amm_init: AMM_INIT_VK_HASH },
  });
}
const SEED = await manifestOf(["pss_seed"]);
const BOTH = await manifestOf(["pss_seed", "amm_init"]);
const seed = { manifest: SEED, circuits: CIRCUITS };
const both = { manifest: BOTH, circuits: CIRCUITS };

function config(url: string, sig = SIG_KEYS, keyEpochNode?: KeyEpochNode): PssClientConfig {
  return {
    keyEpochNode,
    orchestratorUrl: url,
    // the mock listens on plain http on the loopback address
    allowInsecureHttp: true,
    nodeKeys: [
      { enc: { x: 1, y: 2 }, sig: sig[0] },
      { enc: { x: 5, y: 6 }, sig: sig[1] },
      { enc: { x: 9, y: 10 }, sig: sig[2] },
    ],
    vkHashes: { pss_seed: PSS_SEED_VK_HASH },
    contractAddress: NS,
    timeoutMs: 2_000,
  };
}

const conflict = (e: unknown) => e instanceof SidecarError && e.status === 409 && e.class === "conflict";

describe("the registry vectors (testvectors/registry.json)", () => {
  test("REGISTER and DISABLE bodies with seq: message and owner signature", async () => {
    assert.equal((await registerMessage(VECTORS.register.body)).toString(), VECTORS.register.message);
    assert.equal((await disableMessage(VECTORS.disable.body)).toString(), VECTORS.disable.message);
    for (const b of [VECTORS.register.body, VECTORS.disable.body]) {
      const message = b === VECTORS.register.body ? VECTORS.register.message : VECTORS.disable.message;
      assert.ok(await verifySignature(message, VECTORS.owner_pubkey, b.signature));
    }
    // disableBody and the vector's body give the same message
    const d = VECTORS.disable.body as unknown as { namespace: string; circuit: string; seq: number };
    const ours = { ...disableBody(d.namespace, d.circuit, d.seq), owner_pubkey: VECTORS.owner_pubkey };
    assert.equal((await disableMessage(ours)).toString(), VECTORS.disable.message);
  });

  test("the manifest message: the register body's hashes, each node's manifest result message and signature", async () => {
    const v = VECTORS.manifest;
    const body = VECTORS.register.body as unknown as { namespace: string; manifest: ContractManifest; seq: number };
    assert.equal(fieldHex(MANIFEST_DOMAIN), v.manifest_domain);
    assert.equal(fieldHex(body.namespace), v.namespace);
    assert.equal(body.seq, v.seq);
    assert.equal(fieldHex((await contractManifestHash(body.manifest)).toBigInt()), v.manifest_hash);
    assert.equal(fieldHex((await packagesHash(body.manifest)).toBigInt()), v.packages_hash);
    assert.equal(v.results.length, 3);
    for (const r of v.results) {
      const m = await manifestMessage(v.namespace, v.manifest_hash, v.packages_hash, v.npk_app_hash, v.seq, r.node);
      assert.equal(m.toString(), r.message, `node ${r.node}`);
      assert.ok(await verifySignature(m, r.sig_pubkey, r.signature), `node ${r.node}`);
      // the registry result message of the same values is another message
      assert.notEqual((await registryMessage(v.namespace, "pss_seed", v.packages_hash, v.npk_app_hash, v.seq, false, r.node)).toString(), r.message);
    }
    // the nodes' sig keys are those of the registry results
    assert.deepEqual(v.results.sort((a, b) => a.node - b.node).map((r) => r.sig_pubkey), SIG_KEYS);
    // the register body is a manifest message signed by the owner over its REGISTER message
    assert.deepEqual(Object.keys(VECTORS.register.body).sort(), ["circuits", "manifest", "namespace", "owner_pubkey", "seq", "signature"]);
    assert.equal((await registerMessage(VECTORS.register.body)).toString(), VECTORS.register.message);
    assert.ok(await verifySignature(VECTORS.register.message, VECTORS.owner_pubkey, VECTORS.register.body.signature));
    assert.equal(await verifySignature(await registerMessage({ ...VECTORS.register.body, seq: 1 }), VECTORS.owner_pubkey, VECTORS.register.body.signature), false);
  });

  test("the registry result messages and node signatures", async () => {
    assert.equal(fieldHex(REGISTRY_DOMAIN), VECTORS.registry_domain);
    for (const r of VECTORS.results) {
      const m = await registryMessage(r.namespace, r.name, r.vk_hash, r.npk_app_hash, r.seq, r.disabled, r.node);
      assert.equal(m.toString(), r.message);
      assert.deepEqual(await SchnorrKey.fromHex(r.sig_secret).publicKey(), r.sig_pubkey);
      assert.ok(await verifySignature(m, r.sig_pubkey, r.signature));
    }
  });

  test("verifyRegistryAnswer accepts the vectors' answers and refuses any change", async () => {
    for (const disabled of [false, true]) {
      const rs = VECTORS.results.filter((r) => r.disabled === disabled).sort((a, b) => a.node - b.node);
      const r0 = rs[0]!;
      const answer = {
        vk_hash: r0.vk_hash,
        npk_app_hash: r0.npk_app_hash,
        seq: r0.seq,
        disabled,
        signatures: rs.map((r) => r.signature) as [Signature, Signature, Signature],
      };
      const expected = { namespace: r0.namespace, name: r0.name, seq: r0.seq, disabled };
      await verifyRegistryAnswer(answer, expected, [SIG_KEYS]);
      await assert.rejects(verifyRegistryAnswer(answer, { ...expected, seq: r0.seq + 1 }, [SIG_KEYS]), /the body sent seq/);
      await assert.rejects(verifyRegistryAnswer(answer, { ...expected, disabled: !disabled }, [SIG_KEYS]), ProtocolError);
      await assert.rejects(verifyRegistryAnswer(answer, { ...expected, name: "amm_swap" }, [SIG_KEYS]), /node 0's signature/);
      await assert.rejects(verifyRegistryAnswer({ ...answer, npk_app_hash: fieldHex(1) }, expected, [SIG_KEYS]), /node 0's signature/);
      const swapped = [SIG_KEYS[0], SIG_KEYS[2], SIG_KEYS[1]] as typeof SIG_KEYS;
      await assert.rejects(verifyRegistryAnswer(answer, expected, [swapped]), /node 1's signature/);
      // a second accepted set (a key epoch's previous one) does not rescue a mixed answer
      await assert.rejects(verifyRegistryAnswer(answer, expected, [swapped, swapped]), /node 1's signature/);
      await verifyRegistryAnswer(answer, expected, [swapped, SIG_KEYS]);
    }
  });
});

describe("the manifest result message", () => {
  test("MANIFEST_DOMAIN is ASCII sidecar.manifest; the message changes with every member", async () => {
    assert.equal(MANIFEST_DOMAIN, BigInt("0x" + Buffer.from("sidecar.manifest").toString("hex")));
    const base = [NS, 1n, 2n, NPK_APP_HASH, 3, 0] as const;
    const m = (await manifestMessage(...base)).toString();
    for (let k = 0; k < base.length; k++) {
      const changed = [...base] as unknown as Parameters<typeof manifestMessage>;
      (changed as unknown[])[k] = k === 4 || k === 5 ? Number(base[k]) + 1 : fieldHex(BigInt(base[k] as never) + 1n);
      assert.notEqual((await manifestMessage(...changed)).toString(), m, `member ${k}`);
    }
    await assert.rejects(manifestMessage(NS, 1n, 2n, NPK_APP_HASH, 3, 3), /node index 3/);
  });
});

describe("REGISTER and DISABLE against a mock orchestrator", () => {
  let mock: MockOrchestrator;
  let url: string;
  let registry: MockRegistry;

  before(async () => {
    mock = new MockOrchestrator();
    url = await mock.start();
  });
  after(async () => {
    await mock.stop();
  });
  beforeEach(() => {
    mock.routes.clear();
    mock.prefixes.clear();
    mock.received.length = 0;
    registry = new MockRegistry(NODE_SIG.map((r) => SchnorrKey.fromHex(r.sig_secret)) as [SchnorrKey, SchnorrKey, SchnorrKey], NPK_APP_HASH);
    registry.install(mock);
  });

  const sent = () => JSON.parse(mock.received.filter((r) => r.method === "POST").at(-1)!.body);
  const hashOf = async (m: ContractManifest) => fieldHex((await contractManifestHash(m)).toBigInt());

  test("first REGISTER: the namespace answers 404, so seq 0; the signed answer is checked and seq recorded", async () => {
    const client = new PssClient(config(url));
    const owner = OwnerKey.generate();
    assert.equal(await client.getNamespace(NS), undefined);
    assert.equal(await client.nextSeq(), 0);
    const unsigned = await client.manifestBody(seed);
    assert.deepEqual(Object.keys(unsigned).sort(), ["circuits", "manifest", "namespace", "seq"]);
    assert.deepEqual([unsigned.namespace, unsigned.seq, Object.keys(unsigned.circuits)], [NS, 0, ["pss_seed"]]);
    // the circuit travels stripped
    assert.deepEqual(unsigned.circuits.pss_seed, { ...CIRCUIT, debug_symbols: "q1ZKSU0qTY/PzEvLL1ayio6tBQA=", file_map: {} });
    const body = await signManifest(unsigned, owner);
    const r = await client.register(body);
    assert.equal(r.manifest_hash, await hashOf(SEED));
    assert.equal(r.npk_app_hash, NPK_APP_HASH);
    assert.equal(r.seq, 0);
    assert.equal(r.packages_hash, fieldHex((await packagesHash(SEED)).toBigInt()));
    assert.equal(mock.received.at(-1)!.body, JSON.stringify(body));
    assert.equal(client.lastSeq(), 0);
    const info = await client.getNamespace(NS);
    assert.deepEqual(info, { namespace: NS, owner_pubkey: await owner.publicKey(), seq: 0, npk_app_hash: NPK_APP_HASH, manifest_hash: r.manifest_hash });
    assert.deepEqual(await client.getContractManifest(NS), { namespace: NS, manifest_hash: r.manifest_hash, seq: 0, manifest: SEED });
    // on the sidecar path another contract manifest replaces the stored one, in one call: seq read as stored + 1
    const again = await client.registerManifest(both, owner);
    assert.equal(again.seq, 1);
    assert.equal(sent().seq, 1);
    assert.equal(client.lastSeq(), 1);
    assert.equal(again.manifest_hash, await hashOf(BOTH));
    assert.equal(registry.packages.get(`${NS}/amm_init`)!.seq, 1);
  });

  // A client configured without a namespace (deployTip's registry, before
  // the contract exists) registers under the namespace each call names, and
  // refuses a call that names none.
  test("a client without contractAddress registers under the namespace it is given and refuses one it is not", async () => {
    const { contractAddress: _, ...rest } = config(url);
    const client = new PssClient(rest);
    const owner = OwnerKey.generate();
    await assert.rejects(client.nextSeq(), (e: unknown) => e instanceof ConfigError && /no namespace/.test(e.message));
    assert.throws(() => client.lastSeq(), /no namespace/);
    await assert.rejects(client.manifestBody(seed), /no namespace/);
    const r = await client.registerManifest({ ...seed, namespace: NS }, owner);
    assert.equal(r.seq, 0);
    assert.equal(sent().namespace, NS);
    assert.equal(client.lastSeq(NS), 0);
  });

  test("a contract manifest that names a circuit not given is refused before sending", async () => {
    const client = new PssClient(config(url));
    await assert.rejects(client.registerManifest({ manifest: BOTH, circuits: { pss_seed: CIRCUIT } }, OwnerKey.generate()), /circuits\.amm_init: the contract manifest names it/);
    assert.equal(mock.count("POST", "/v1/register"), 0);
  });

  test("another key under an owned namespace is a 403", async () => {
    const client = new PssClient(config(url));
    await client.registerManifest(seed, OwnerKey.generate());
    const intruder = await signManifest(await client.manifestBody(both), OwnerKey.generate());
    await assert.rejects(client.register(intruder), (e: unknown) => e instanceof SidecarError && e.status === 403 && /namespace owner/.test(e.message));
  });

  test("a stale seq is a 409; a replayed body never registers, disables or re-enables; the same contract manifest re-enables", async () => {
    const client = new PssClient(config(url));
    const owner = OwnerKey.generate();
    const first = await signManifest(await client.manifestBody(both), owner);
    await client.register(first);
    // a body built with a seq that is not stored + 1
    const stale = await signManifest(await client.manifestBody({ ...seed, seq: 0 }), owner);
    await assert.rejects(client.register(stale), conflict);
    const ahead = await signManifest(await client.manifestBody({ ...seed, seq: 5 }), owner);
    await assert.rejects(client.register(ahead), conflict);
    // DISABLE pss_seed at seq 1, keeping the signed body
    const disable = await signDisable(disableBody(NS, "pss_seed", await client.nextSeq()), owner);
    assert.equal(disable.seq, 1);
    const d = await client.sendDisable(disable);
    assert.equal(d.seq, 1);
    assert.equal(registry.packages.get(`${NS}/pss_seed`)!.disabled, true);
    // replaying the first REGISTER would re-enable the package: refused
    await assert.rejects(client.register(first), conflict);
    assert.equal(registry.packages.get(`${NS}/pss_seed`)!.disabled, true);
    // the owner re-enables it with the same contract manifest in a fresh body (seq 2) ...
    const reenabled = await client.registerManifest(both, owner);
    assert.equal(reenabled.seq, 2);
    assert.equal(reenabled.manifest_hash, await hashOf(BOTH));
    // ... and replaying the old DISABLE cannot disable it again
    await assert.rejects(client.sendDisable(disable), conflict);
    assert.equal(registry.packages.get(`${NS}/pss_seed`)!.disabled, false);
    assert.equal(registry.namespaces.get(NS)!.seq, 2);
  });

  test("the last body resent with its seq answers the stored values", async () => {
    const client = new PssClient(config(url));
    const owner = OwnerKey.generate();
    await client.registerManifest(seed, owner);
    const body = await signManifest(await client.manifestBody(both), owner);
    const a = await client.register(body);
    const b = await client.register(body);
    assert.equal(a.seq, 1);
    assert.equal(b.seq, 1);
    assert.equal(registry.namespaces.get(NS)!.seq, 1);
  });

  test("an answer the pinned sig keys did not sign, for another seq or another contract manifest, is refused", async () => {
    const owner = OwnerKey.generate();
    const others = (await Promise.all([1, 2, 3].map(() => OwnerKey.generate().publicKey()))) as typeof SIG_KEYS;
    const unpinned = new PssClient(config(url, others));
    await assert.rejects(unpinned.registerManifest(seed, owner), /node 0's manifest signature does not verify/);
    const client = new PssClient(config(url));
    const body = await signManifest(await client.manifestBody(both), owner);
    const edit = (over: object) =>
      mock.on("POST", "/v1/register", async (r) => {
        const reply = await registry.register(r.body);
        return "body" in reply ? { ...reply, body: { ...(reply.body as object), ...over } } : reply;
      });
    edit({ seq: 7 });
    await assert.rejects(client.register(body), /seq 7, the body sent seq 1/);
    edit({ manifest_hash: fieldHex(0x99) });
    await assert.rejects(client.register(body), /manifest hash 0x0*99/);
    edit({ packages_hash: fieldHex(0x99) });
    await assert.rejects(client.register(body), /packages hash 0x0*99/);
    edit({ packages: [] });
    await assert.rejects(client.register(body), /field `packages`/);
    mock.on("POST", "/v1/register", () => ({ status: 200, body: { manifest_hash: fieldHex(1), npk_app_hash: NPK_APP_HASH } }));
    await assert.rejects(client.register(body), /field `packages_hash`: missing/);
  });

  test("after a node replacement, answers verify under the contract's key epoch, not the pinned keys", async () => {
    // node 1 is replaced at block 40 with a grace window of 10 blocks; the
    // configuration still pins epoch 0's keys
    const replacement = SchnorrKey.generate();
    const current = [SIG_KEYS[0], await replacement.publicKey(), SIG_KEYS[2]] as typeof SIG_KEYS;
    let block = 51;
    const fields = [
      1n,
      40n,
      10n,
      ...current.flatMap((k) => [BigInt(k.x), BigInt(k.y)]),
      ...[1n, 2n, 3n, 4n, 5n, 6n], // enc keys, unused here
      ...SIG_KEYS.flatMap((k) => [BigInt(k.x), BigInt(k.y)]),
    ];
    assert.equal(fields.length, NODE_KEYS_LEN);
    const keyEpochNode: KeyEpochNode = {
      getBlockNumber: async () => block,
      getPublicStorageAt: async (_b: never, _c: unknown, slot: Fr) => new Fr(fields[Number(slot.toBigInt() - NODE_KEYS_SLOT)]!),
    };
    const owner = OwnerKey.generate();
    const client = new PssClient(config(url, SIG_KEYS, keyEpochNode));
    const old = NODE_SIG.map((r) => SchnorrKey.fromHex(r.sig_secret)) as [SchnorrKey, SchnorrKey, SchnorrKey];
    // the replaced node still signs with its rotated-out key: refused once the window is over
    await assert.rejects(client.registerManifest(seed, owner), /node 1's manifest signature does not verify/);
    // the current set's answer is accepted, REGISTER and DISABLE alike
    new MockRegistry([old[0], replacement, old[2]], NPK_APP_HASH).install(mock);
    assert.equal((await client.registerManifest(seed, owner)).seq, 0);
    assert.equal((await client.disable(NS, "pss_seed", owner)).seq, 1);
    // inside the grace window the previous set is still accepted, as for results
    block = 50;
    const graced = new MockRegistry(old, NPK_APP_HASH);
    graced.install(mock);
    assert.equal((await client.registerManifest(seed, owner)).seq, 0);
  });

  test("an edited or re-spelled body is refused before sending", async () => {
    const client = new PssClient(config(url));
    const body = await signManifest(await client.manifestBody(seed), OwnerKey.generate());
    await assert.rejects(client.register({ ...body, manifest: BOTH }), /does not verify under owner_pubkey/);
    await assert.rejects(client.register({ ...body, seq: 1 }), /does not verify under owner_pubkey/);
    const upper = { ...body, namespace: "0x" + body.namespace.slice(2).toUpperCase() };
    await assert.rejects(client.register(upper), /normal form/);
    await assert.rejects(client.register({ ...body, signature: { s: ["0x1", "0x2"], e: ["0x3", "0x4"] } }), /normal form/);
    assert.equal(mock.count("POST", "/v1/register"), 0);
  });

  test("disable: owner-signed body with seq, the signed answer checked", async () => {
    const client = new PssClient(config(url));
    const owner = OwnerKey.generate();
    await client.registerManifest(seed, owner);
    const d = await client.disable(NS, "pss_seed", owner);
    assert.equal(d.namespace, NS);
    assert.equal(d.circuit, "pss_seed");
    assert.equal(d.disabled, true);
    assert.equal(d.seq, 1);
    assert.equal(d.vk_hash, PSS_SEED_VK_HASH);
    assert.equal(registry.packages.get(`${NS}/pss_seed`)!.disabled, true);
    const body = sent();
    assert.deepEqual(Object.keys(body).sort(), ["circuit", "namespace", "owner_pubkey", "seq", "signature"]);
    assert.deepEqual(body.owner_pubkey, await owner.publicKey());
    // REGISTER of the same contract manifest re-enables it
    await client.registerManifest(seed, owner);
    assert.equal(registry.packages.get(`${NS}/pss_seed`)!.disabled, false);
  });

  test("disable: not the owner is 403, an unknown circuit 404, a REGISTER signature is refused locally", async () => {
    const client = new PssClient(config(url));
    const owner = OwnerKey.generate();
    await client.registerManifest(seed, owner);
    await assert.rejects(client.disable(NS, "pss_seed", OwnerKey.generate()), (e: unknown) => e instanceof SidecarError && e.status === 403);
    await assert.rejects(client.disable(NS, "amm_swap", owner), (e: unknown) => e instanceof SidecarError && e.status === 404 && e.class === "not_found");
    // a signature over the same members under the REGISTER domain is no DISABLE signature
    const signed = await signDisable(disableBody(NS, "pss_seed", 1), owner);
    const wrongDomain = { ...signed, signature: await owner.sign(await registerMessage(signed)) };
    const before = mock.count("POST", "/v1/disable");
    await assert.rejects(client.sendDisable(wrongDomain), /does not verify/);
    assert.equal(mock.count("POST", "/v1/disable"), before);
    assert.equal(registry.packages.get(`${NS}/pss_seed`)!.disabled, false);
  });

  test("disable: an answer for another circuit is a protocol error", async () => {
    const client = new PssClient(config(url));
    const owner = OwnerKey.generate();
    await client.registerManifest(seed, owner);
    mock.on("POST", "/v1/disable", async (r) => {
      const reply = await registry.disable(r.body);
      return "body" in reply ? { ...reply, body: { ...(reply.body as object), circuit: "other" } } : reply;
    });
    await assert.rejects(client.disable(NS, "pss_seed", owner), /answered for/);
    mock.on("POST", "/v1/disable", async (r) => {
      const reply = await registry.disable(r.body);
      return "body" in reply ? { ...reply, body: { ...(reply.body as object), disabled: false } } : reply;
    });
    await assert.rejects(client.disable(NS, "pss_seed", owner), /`disabled`: not true/);
  });
});
