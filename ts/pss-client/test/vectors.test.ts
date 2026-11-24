// The shared client-node vectors that sidecar-core's tests/write_vectors.rs
// wrote and its tests/vectors.rs reads: sealed record thirds (records.json),
// signed bodies for the three domains (bodies.json), result-signature
// messages (results.json), field-element and request-id spellings with
// response documents (field_hex.json) and the nsk_app / npk_app_hash
// derivation (npk_app_hash.json), and the example circuits' note-hash indices
// and vk hashes (shapes.json). The client recomputes every value it can;
// a record third it cannot open (only node i holds K_i), so it rebuilds the
// third from the node's published key material in the file instead.
// The other vector files are read by envelope.test.ts (ae, keys, envelope),
// signing.test.ts (schnorr) and register.test.ts (registry); tip.test.ts
// reads chain_request_id, receipts and log_tags again through the client's
// intake functions (src/tip.ts). tip_results.json (the tip's chain-held
// rounds, with the non-secret-shared and init public-input layouts) is read here through
// the result-signature helpers and the layout parsers, and
// slot_commitment.json (a chain-held key's slot commitment) is recomputed
// here from its preimages. outcome.json (private outcomes) is written and
// read by outcome.test.ts.

import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, test } from "node:test";

import { Grumpkin } from "@aztec-labs/foundation/crypto/grumpkin";
import { poseidon2HashBytes } from "@aztec-labs/foundation/crypto/poseidon";
import { Fr } from "@aztec-labs/foundation/curves/bn254";
import { GrumpkinScalar } from "@aztec-labs/foundation/curves/grumpkin";
import { computeLogTag } from "@aztec-labs/stdlib/hash";

import {
  BN254_MODULUS,
  DISABLE_DOMAIN,
  EXECUTE_DOMAIN,
  RequesterKey,
  SchnorrKey,
  REGISTER_DOMAIN,
  PSS_ATTEMPT,
  PSS_STATE,
  RESULT_DOMAIN,
  ResultSignatureError,
  aeDecrypt,
  aeEncrypt,
  canonicalBody,
  canonicalJson,
  checkCiphertextHashes,
  checkRequestSignature,
  disableMessage,
  executeMessage,
  fieldHex,
  keyId,
  localVkHash,
  noteHashIndices,
  parseDisableResponse,
  parseExecuteResponse,
  parseNamespaceResponse,
  parseNodesResponse,
  parseManifestResponse,
  recordHash,
  recordKeyId,
  registerMessage,
  requestIdHex,
  resultMessage,
  sealedHash,
  chainRequestId,
  computeSealedLogTag,
  machineRequestId,
  parseSealedLog,
  recordFields,
  tipInputsHash,
  verifyResultSignatures,
  verifySignature,
  vkFieldsFromBbJson,
  vkHashFromFields,
  initChainRequestId,
  initResultLayout,
  initResultParts,
  MAX_MAP_DEPTH,
  MAX_NAME_BYTES,
  MAX_TREE_DEPTH,
  MAX_TREE_WINDOW,
  MIN_MAP_DEPTH,
  tipResultLayout,
  tipResultParts,
  type ExecuteRequest,
  type ExecuteResponse,
  type GrumpkinPoint,
  type InitResultLayout,
  type Signature,
  type TipResultLayout,
  type Triple,
  asciiLabel,
} from "../src/internal.ts";
import { AMM_INIT, AMM_SWAP, fixturePath, hash, hex, LENDING_INIT, queued, repoJson, vectorJson } from "@aztec-pss/test-support";

const bytesHash = async (s: string) => (await poseidon2HashBytes(Buffer.from(s, "utf8"))).toBigInt();
const limbs = (v: bigint) => [v & ((1n << 128n) - 1n), v >> 128n];

// ---- records.json ----

interface Elements {
  public?: string;
  shared?: [string, string] | string;
}
interface Third {
  node: number;
  owner: GrumpkinPoint;
  elements: Elements[];
  plaintext: string[];
  nonce: string;
  ciphertext: string[];
  tag: string;
  c: string;
  record_hash: string;
}
interface RecordVector {
  name: string;
  owner_kind: "requester" | "machine";
  namespace: string;
  key: string;
  key_hash: string;
  note_hash: string;
  value: Elements[];
  thirds: Third[];
}
interface RecordNode {
  node: number;
  enc: string;
  enc_limbs: { lo: string; hi: string };
  enc_pk: GrumpkinPoint;
  record_key: string;
  key_id_hash: string;
  key_id: string;
}
const RECORDS = vectorJson("records.json") as {
  sidecar_seal_key: string;
  sidecar_record_ad: string;
  requester: { secret: string; pubkey: GrumpkinPoint };
  nodes: RecordNode[];
  records: RecordVector[];
};
const KEYS = vectorJson("keys.json") as { nodes: (RecordNode & { sig: string; sig_pk: GrumpkinPoint })[] };

describe("sealed record thirds (testvectors/records.json)", () => {
  test("the labels and the requester key", async () => {
    assert.equal(hex(asciiLabel("sidecar.seal_key")), RECORDS.sidecar_seal_key);
    assert.equal(hex(asciiLabel("sidecar.record_ad")), RECORDS.sidecar_record_ad);
    assert.deepEqual(await RequesterKey.fromHex(RECORDS.requester.secret).publicKey(), RECORDS.requester.pubkey);
  });

  test("K_i and the key id from node i's enc scalar", async () => {
    for (const n of RECORDS.nodes) {
      const k = KEYS.nodes[n.node]!;
      for (const f of ["enc", "enc_limbs", "enc_pk", "record_key", "key_id"] as const) assert.deepEqual(n[f], k[f], `node ${n.node} ${f}`);
      const enc = BigInt(n.enc);
      assert.deepEqual(limbs(enc).map(hex), [n.enc_limbs.lo, n.enc_limbs.hi]);
      const pk = await Grumpkin.mul(Grumpkin.generator, new GrumpkinScalar(enc));
      assert.deepEqual({ x: hex(pk.x), y: hex(pk.y) }, n.enc_pk);
      assert.equal(hex(await hash([...limbs(enc), asciiLabel("sidecar.seal_key")])), n.record_key);
      assert.equal(hex(await hash([n.enc_pk.x, n.enc_pk.y])), n.key_id_hash);
      assert.equal(n.key_id, n.key_id_hash.slice(0, 18));
      assert.equal(await keyId(n.enc_pk), n.key_id);
    }
  });

  for (const r of RECORDS.records) {
    test(`${r.name}: AD, plaintext, ciphertext, sealed third and record hash`, async () => {
      assert.equal(hex(await bytesHash(r.key)), r.key_hash);
      assert.equal(r.thirds.length, 3);
      for (const t of r.thirds) {
        const node = RECORDS.nodes[t.node]!;
        assert.deepEqual(t.owner, r.owner_kind === "machine" ? node.enc_pk : RECORDS.requester.pubkey, `${r.name} node ${t.node}: owner`);
        const plaintext = [r.namespace, r.key_hash, r.note_hash].map((x) => BigInt(x));
        for (const e of t.elements) {
          if (e.public !== undefined) plaintext.push(0n, BigInt(e.public));
          else plaintext.push(1n, ...(e.shared as [string, string]).map((x) => BigInt(x)));
        }
        assert.deepEqual(plaintext.map(hex), t.plaintext);
        const nonce = await hash([r.namespace, r.key_hash, r.note_hash, t.owner.x, t.owner.y, asciiLabel("sidecar.record_ad")]);
        assert.equal(hex(nonce), t.nonce);
        const sealed = await aeEncrypt(node.record_key, nonce, plaintext);
        assert.deepEqual(sealed.ciphertext.map(hex), t.ciphertext);
        assert.equal(hex(sealed.tag), t.tag);
        assert.deepEqual((await aeDecrypt(node.record_key, nonce, t.ciphertext, t.tag)).map(hex), t.plaintext);
        const c = node.key_id + [...t.ciphertext, t.tag].map((x) => x.slice(2)).join("");
        assert.equal(c, t.c);
        assert.equal(recordKeyId(t.c), node.key_id);
        assert.equal(await recordHash(t.c), t.record_hash);
        assert.equal(hex(await hash([node.key_id, ...t.ciphertext, t.tag])), t.record_hash);
      }
      // The pairs of a shared element are one replicated sharing of the value.
      r.value.forEach((v, j) => {
        const at = r.thirds.map((t) => t.elements[j]!);
        if (v.public !== undefined) return at.forEach((e) => assert.equal(e.public, v.public));
        const pairs = at.map((e) => (e.shared as [string, string]).map((x) => BigInt(x)));
        assert.equal(hex((pairs[0]![0]! + pairs[1]![0]! + pairs[2]![0]!) % BN254_MODULUS), v.shared);
        for (let i = 0; i < 3; i++) assert.equal(pairs[i]![1], pairs[(i + 2) % 3]![0]);
      });
    });
  }

  test("client_b001 is envelope.json's record", () => {
    const env = vectorJson("envelope.json") as { request: ExecuteRequest };
    const b001 = RECORDS.records.find((r) => r.name === "client_b001")!;
    const record = env.request.records[0]!;
    assert.equal(b001.key, record.key);
    assert.equal(b001.note_hash, record.note_hash);
    assert.deepEqual(b001.thirds.map((t) => t.c), record.c);
    assert.deepEqual(b001.thirds.map((t) => t.record_hash), record.record_hashes);
  });
});

// ---- bodies.json ----

interface BodyVector {
  name: string;
  domain: string;
  signer: string;
  secret: string;
  pubkey: GrumpkinPoint;
  body: Record<string, unknown> & { signature: Signature };
  canonical: string;
  message: string;
}
const BODIES = vectorJson("bodies.json") as { bodies: BodyVector[] };

describe("signed bodies (testvectors/bodies.json)", () => {
  test("one body per domain", () => {
    assert.deepEqual(BODIES.bodies.map((b) => b.domain), [REGISTER_DOMAIN, DISABLE_DOMAIN, EXECUTE_DOMAIN]);
  });
  for (const b of BODIES.bodies) {
    test(`${b.name}: canonical body, message and signature`, async () => {
      assert.equal(hex(await bytesHash(b.domain + b.canonical)), b.message);
      assert.deepEqual(await SchnorrKey.fromHex(b.secret).publicKey(), b.pubkey);
      let message: Fr;
      if (b.domain === EXECUTE_DOMAIN) {
        const body = b.body as unknown as ExecuteRequest;
        assert.ok(body.records.length > 0 && body.requester !== undefined);
        assert.deepEqual(body.requester, b.pubkey);
        assert.equal(canonicalJson(canonicalBody(body)), b.canonical);
        message = await executeMessage(body);
        await checkCiphertextHashes(body);
        await checkRequestSignature(body);
        await assert.rejects(checkRequestSignature({ ...body, request_id: requestIdHex(BigInt(body.request_id) + 1n) }), /does not verify/);
      } else {
        const { signature: _omit, ...unsigned } = b.body;
        assert.equal(typeof unsigned.seq, "number");
        assert.deepEqual(unsigned.owner_pubkey, b.pubkey);
        assert.equal(canonicalJson(unsigned), b.canonical);
        message = await (b.domain === REGISTER_DOMAIN ? registerMessage(b.body) : disableMessage(b.body));
      }
      assert.equal(hex(message), b.message);
      assert.ok(await verifySignature(message, b.pubkey, b.body.signature));
      assert.equal(await verifySignature(message.toBigInt() + 1n, b.pubkey, b.body.signature), false);
    });
  }
  test("the execute body is envelope.json's request, signed", () => {
    const { signature: _omit, ...unsigned } = BODIES.bodies.find((b) => b.domain === EXECUTE_DOMAIN)!.body;
    assert.deepEqual(unsigned, (vectorJson("envelope.json") as { request: unknown }).request);
  });
});

// ---- results.json ----

interface ResultCase {
  name: string;
  request_id: string;
  outputs: { key: string; state: string; note_hash: string; record: string | null }[];
  commitments: string[];
  nodes: { node: number; sig_pubkey: GrumpkinPoint; record_hashes: string[]; sealed_hash: string; message: string; signature: Signature }[];
}
const RESULTS = vectorJson("results.json") as { result_domain: string; namespace: string; cases: ResultCase[] };

const SIG_KEYS = KEYS.nodes.map((n) => n.sig_pk) as [GrumpkinPoint, GrumpkinPoint, GrumpkinPoint];

// A case as the orchestrator would answer it: the commitments as the whole
// public-input array (so the note-hash indices are 0, 1, ...), each
// client-held output's record with its three thirds from records.json, and
// the three signatures. Node-held outputs return no record.
function caseResponse(c: ResultCase): { response: ExecuteResponse; indices: number[] } {
  const records = c.outputs
    .filter((o) => o.state === "client")
    .map((o) => {
      const r = RECORDS.records.find((x) => x.name === o.record)!;
      return { key: o.key, note_hash: o.note_hash, c: r.thirds.map((t) => t.c) as [string, string, string] };
    });
  const response: ExecuteResponse = {
    request_id: requestIdHex(c.request_id),
    vk_hash: fieldHex(1),
    proof: "0x00",
    public_inputs: c.commitments,
    stored: c.outputs.filter((o) => o.state === "node").map((o) => o.key),
    records,
    signatures: c.nodes.map((n) => n.signature) as ExecuteResponse["signatures"],
  };
  return { response, indices: c.commitments.map((_, k) => k) };
}

describe("result-signature messages (testvectors/results.json)", () => {
  test("RESULT_DOMAIN is ASCII sidecar.result", () => {
    assert.equal(RESULTS.result_domain, hex(asciiLabel("sidecar.result")));
    assert.equal(hex(RESULT_DOMAIN), RESULTS.result_domain);
  });
  for (const c of RESULTS.cases) {
    test(`${c.name}: H(sealed_i), the message and node i's signature`, async () => {
      assert.match(requestIdHex(c.request_id), /^0x0{32}[0-9a-f]{32}$/);
      assert.deepEqual(c.outputs.map((o) => o.note_hash), c.commitments);
      for (const n of c.nodes) {
        assert.deepEqual(n.sig_pubkey, KEYS.nodes[n.node]!.sig_pk);
        const thirds = c.outputs
          .filter((o) => o.state === "client")
          .map((o) => RECORDS.records.find((r) => r.name === o.record)!.thirds[n.node]!);
        assert.deepEqual(await Promise.all(thirds.map((t) => recordHash(t.c))), n.record_hashes);
        const sealed = await sealedHash(n.record_hashes);
        assert.equal(hex(sealed), n.sealed_hash);
        assert.equal(hex(sealed), hex(n.record_hashes.length === 0 ? 0n : await hash(n.record_hashes)));
        const message = await resultMessage(RESULTS.namespace, c.request_id, c.commitments, n.node, sealed);
        assert.equal(hex(message), n.message);
        assert.equal(hex(message), hex(await hash([RESULTS.result_domain, RESULTS.namespace, c.request_id, ...c.commitments, BigInt(n.node), sealed.toBigInt()])));
        assert.ok(await verifySignature(message.toBigInt(), n.sig_pubkey, n.signature), `${c.name} node ${n.node}`);
        const other = await resultMessage(RESULTS.namespace, c.request_id, c.commitments, (n.node + 1) % 3, sealed);
        assert.equal(await verifySignature(other.toBigInt(), n.sig_pubkey, n.signature), false);
      }
    });
  }
  test("verifyResultSignatures accepts all nine signatures from the answers' own records and public inputs", async () => {
    let checked = 0;
    for (const c of RESULTS.cases) {
      const { response, indices } = caseResponse(c);
      await verifyResultSignatures(RESULTS.namespace, response, indices, [SIG_KEYS]);
      checked += response.signatures.length;
    }
    assert.equal(checked, 9);
  });
  test("verifyResultSignatures takes several key sets: the signatures must all verify under one of them", async () => {
    const other = SIG_KEYS.map((k) => ({ x: k.y, y: k.x })) as typeof SIG_KEYS;
    for (const c of RESULTS.cases) {
      const { response, indices } = caseResponse(c);
      // a contract's current key set that did not sign, and the previous one that did (inside its window)
      await verifyResultSignatures(RESULTS.namespace, response, indices, [other, SIG_KEYS]);
      await assert.rejects(verifyResultSignatures(RESULTS.namespace, response, indices, [other]), (e: unknown) => e instanceof ResultSignatureError && e.node === 0);
      // a mix of the two sets verifies under neither
      const mixed = [SIG_KEYS[0], SIG_KEYS[1], other[2]] as typeof SIG_KEYS;
      await assert.rejects(verifyResultSignatures(RESULTS.namespace, response, indices, [mixed, other]), (e: unknown) => e instanceof ResultSignatureError && e.node === 2);
    }
  });
  test("a tampered signature of each node is refused with ResultSignatureError naming the node", async () => {
    for (const c of RESULTS.cases) {
      for (let i = 0; i < 3; i++) {
        const { response, indices } = caseResponse(c);
        const bad = structuredClone(response);
        bad.signatures[i]!.s[0] = fieldHex(BigInt(bad.signatures[i]!.s[0]) ^ 1n);
        await assert.rejects(verifyResultSignatures(RESULTS.namespace, bad, indices, [SIG_KEYS]), (e: unknown) => {
          assert.ok(e instanceof ResultSignatureError, `${c.name} node ${i}`);
          assert.equal(e.node, i);
          assert.equal(e.requestId, response.request_id);
          assert.match(e.message, new RegExp(`node ${i}'s result signature`));
          return true;
        });
        // node i's valid signature in node j's place fails at the first moved node
        const swapped = structuredClone(response);
        const j = (i + 1) % 3;
        [swapped.signatures[i], swapped.signatures[j]] = [swapped.signatures[j]!, swapped.signatures[i]!];
        await assert.rejects(verifyResultSignatures(RESULTS.namespace, swapped, indices, [SIG_KEYS]), (e: unknown) => e instanceof ResultSignatureError && e.node === Math.min(i, j));
      }
      // another namespace, a changed commitment, or a changed third fail at node 0
      const { response, indices } = caseResponse(c);
      const refusedAt0 = (p: Promise<void>) => assert.rejects(p, (e: unknown) => e instanceof ResultSignatureError && e.node === 0);
      await refusedAt0(verifyResultSignatures(fieldHex(BigInt(RESULTS.namespace) + 1n), response, indices, [SIG_KEYS]));
      await refusedAt0(verifyResultSignatures(RESULTS.namespace, { ...response, public_inputs: [fieldHex(7), ...response.public_inputs.slice(1)] }, indices, [SIG_KEYS]));
      if (response.records.length > 0) {
        const r0 = response.records[0]!;
        const other = RECORDS.records.find((x) => x.thirds[0]!.c !== r0.c[0])!.thirds[0]!.c;
        const records = [{ ...r0, c: [other, r0.c[1], r0.c[2]] as [string, string, string] }, ...response.records.slice(1)];
        await refusedAt0(verifyResultSignatures(RESULTS.namespace, { ...response, records }, indices, [SIG_KEYS]));
      }
    }
  });
  test("parseExecuteResponse keeps the three signatures and refuses two, four or none", () => {
    for (const c of RESULTS.cases) {
      const { response } = caseResponse(c);
      const parsed = parseExecuteResponse(JSON.parse(JSON.stringify(response)));
      assert.deepEqual(parsed, response);
      assert.deepEqual(parsed.signatures, c.nodes.map((n) => n.signature));
      const sigs = response.signatures;
      assert.throws(() => parseExecuteResponse({ ...response, signatures: sigs.slice(0, 2) }), /field `signatures`: 2 entries, expected 3/);
      assert.throws(() => parseExecuteResponse({ ...response, signatures: [...sigs, sigs[0]] }), /field `signatures`: 4 entries, expected 3/);
      const { signatures: _omit, ...unsigned } = response;
      assert.throws(() => parseExecuteResponse(unsigned), /field `signatures`: missing/);
      assert.throws(() => parseExecuteResponse({ ...response, signatures: [sigs[0], sigs[1], { ...sigs[2], r: [] }] }), /field `signatures\[2\]\.r`: unknown field/);
      assert.throws(() => parseExecuteResponse({ ...response, signatures: [sigs[0], sigs[1], { s: sigs[2]!.s, e: [sigs[2]!.e[0]] }] }), /signatures\[2\]\.e`: 1 entries, expected 2/);
    }
  });
  test("one round makes no thirds: H(sealed_i) = 0", () => {
    assert.ok(RESULTS.cases.some((c) => c.nodes.every((n) => n.record_hashes.length === 0 && BigInt(n.sealed_hash) === 0n)));
  });
});

// ---- field_hex.json ----

const FIELD_HEX = vectorJson("field_hex.json") as {
  modulus: string;
  field_elements: { accepted: { text: string; value: string }[]; refused: { text: string; why: string }[] };
  request_ids: { accepted: { text: string; value: string }[]; refused: { text: string; why: string }[] };
  documents: { name: string; type: string; json: unknown; accepted: boolean; why?: string }[];
};

describe("field-hex edge cases (testvectors/field_hex.json)", () => {
  test("the modulus", () => {
    assert.equal(BigInt(FIELD_HEX.modulus), BN254_MODULUS);
  });
  test("field elements: 1 to 64 digits in, 64 lowercase out, refused at or above the modulus", () => {
    for (const v of FIELD_HEX.field_elements.accepted) assert.equal(fieldHex(v.text), v.value, v.text);
    for (const v of FIELD_HEX.field_elements.refused) assert.throws(() => fieldHex(v.text), RangeError, `${JSON.stringify(v.text)} (${v.why})`);
  });
  test("request ids: the same rule", () => {
    for (const v of FIELD_HEX.request_ids.accepted) assert.equal(requestIdHex(v.text), v.value, v.text);
    for (const v of FIELD_HEX.request_ids.refused) assert.throws(() => requestIdHex(v.text), RangeError, `${v.text} (${v.why})`);
  });
  test("response documents: unknown fields and bad values refused", () => {
    const parsers: Record<string, (v: unknown) => unknown> = {
      NamespaceResponse: parseNamespaceResponse,
      ManifestResponse: parseManifestResponse,
      DisableResponse: parseDisableResponse,
      NodesResponse: parseNodesResponse,
    };
    for (const d of FIELD_HEX.documents) {
      const parse = parsers[d.type];
      assert.ok(parse !== undefined, `no parser for ${d.type}`);
      let ok = true;
      try {
        parse(d.json);
      } catch {
        ok = false;
      }
      assert.equal(ok, d.accepted, `${d.name}${d.why ? ` (${d.why})` : ""}`);
    }
  });
});

// ---- npk_app_hash.json ----

const NPK = vectorJson("npk_app_hash.json") as {
  vectors: { name: string; master: string; namespace: string; nsk_app: string; npk_app: GrumpkinPoint; npk_app_hash: string }[];
};

describe("nsk_app and npk_app_hash (testvectors/npk_app_hash.json)", () => {
  for (const v of NPK.vectors) {
    test(v.name, async () => {
      const nsk = await hash([asciiLabel("sidecar.nsk_app"), v.master, v.namespace]);
      assert.equal(hex(nsk), v.nsk_app);
      const npk = await Grumpkin.mul(Grumpkin.generator, new GrumpkinScalar(nsk));
      assert.deepEqual({ x: hex(npk.x), y: hex(npk.y) }, v.npk_app);
      assert.equal(hex(await hash([asciiLabel("sidecar.npk_app"), npk.x.toBigInt(), npk.y.toBigInt()])), v.npk_app_hash);
    });
  }
});

// ---- slot_commitment.json ----

// The slot commitment of a chain-held tip key (sidecar-tip's vectors module
// writes the file; pss_core's tip::slot::commitment is checked against it by
// testvectors/noir/tip_round_vectors): poseidon2 over the separator, the
// namespace, the slot, the fields and the blinding.
const SLOTS = vectorJson("slot_commitment.json") as {
  tip_state_sep: string;
  vectors: { name: string; namespace: string; slot: string; fields: string[]; blinding: string; commitment: string }[];
};

describe("the tip's slot commitment (testvectors/slot_commitment.json)", () => {
  test("TIP_STATE_SEP is ASCII pss.tip.state", () => {
    assert.equal(hex(asciiLabel("pss.tip.state")), SLOTS.tip_state_sep);
  });
  for (const v of SLOTS.vectors) {
    test(v.name, async () => {
      const preimage = [SLOTS.tip_state_sep, v.namespace, v.slot, ...v.fields, v.blinding];
      assert.equal(hex(await hash(preimage)), v.commitment);
      // another blinding is another commitment
      assert.notEqual(hex(await hash([...preimage.slice(0, -1), (BigInt(v.blinding) + 1n) % BN254_MODULUS])), v.commitment);
    });
  }
});

// ---- shapes.json ----

interface ShapeVector {
  example: string;
  circuit: string;
  artifact: string;
  manifest: string;
  abi: unknown;
  public_param_fields: number;
  public_input_count: number;
  outputs: { note_hash: string; note_hash_index: number }[];
  vk_fields: string[];
  vk_hash: string;
}

describe("note-hash indices and vk hashes of the example circuits (testvectors/shapes.json)", () => {
  const SHAPES = vectorJson("shapes.json") as { circuits: ShapeVector[] };
  const REPO = new URL("../../../", import.meta.url);
  const BB_BIN = process.env.BB_BIN;

  test("the file lists every round circuit of both examples", () => {
    assert.deepEqual(
      SHAPES.circuits.map((c) => `${c.example}/${c.circuit}`),
      [
        "examples/amm/pss_seed",
        "examples/amm/amm_init",
        "examples/amm/amm_swap",
        "examples/monty-hall/pss_seed",
        "examples/monty-hall/monty_hall_init",
        "examples/monty-hall/monty_hall_open_door",
        "examples/monty-hall/monty_hall_finish",
      ],
    );
  });

  for (const c of SHAPES.circuits) {
    test(`${c.example}/${c.circuit}: noteHashIndices of the ABI and manifest are the Rust note_hash_index`, () => {
      const manifest = repoJson(c.manifest) as { outputs: { note_hash: string }[] };
      assert.deepEqual(manifest.outputs.map((o) => o.note_hash), c.outputs.map((o) => o.note_hash));
      assert.deepEqual(noteHashIndices({ abi: c.abi }, manifest), c.outputs.map((o) => o.note_hash_index));
      // the nargo output JSON and its bare abi give the same indices
      assert.deepEqual(noteHashIndices(c.abi, manifest), c.outputs.map((o) => o.note_hash_index));
    });
    test(`${c.example}/${c.circuit}: vkHashFromFields of the vk fields is the Rust vk_hash`, async () => {
      assert.equal(c.vk_fields.length, 115);
      assert.equal(hex(await vkHashFromFields(c.vk_fields)), c.vk_hash);
    });
  }

  test("pss_seed's vk fields are bb's in the client's vk fixture", () => {
    const fixture = readFileSync(fixturePath("pss_seed.vk.json"), "utf8");
    const seed = SHAPES.circuits.find((c) => c.circuit === "pss_seed")!;
    assert.deepEqual(vkFieldsFromBbJson(fixture).map((x) => hex(x)), seed.vk_fields);
    assert.equal(fieldHex(JSON.parse(fixture).hash), seed.vk_hash);
  });

  // With bb and the compiled circuits of scripts/prepare-data.sh, localVkHash
  // of each artifact is the Rust vk_hash too.
  const artifacts = [...new Map(SHAPES.circuits.map((c) => [c.artifact, c.vk_hash])).entries()];
  const missing = artifacts.find(([path]) => !existsSync(new URL(path, REPO)))?.[0];
  const skip = BB_BIN === undefined ? "BB_BIN is not set" : missing !== undefined ? `${missing} is missing; run scripts/prepare-data.sh` : false;
  test("localVkHash of every compiled example circuit is the Rust vk_hash", { skip }, async () => {
    for (const [path, vkHash] of artifacts) assert.equal(await localVkHash(fileURLToPath(new URL(path, REPO)), BB_BIN), vkHash, path);
  });
});

// ---- tip_results.json ----

// The tip's chain-held rounds (sidecar-tip's vectors module writes them):
// the ids, each node's third rebuilt from its keys.json record key (the
// client cannot open a machine-owned third, but the vector publishes K_i),
// H(sealed_i) and the result message rebuilt with result-signatures.ts, the three
// signatures checked under the pinned sig keys (one by one and as
// verifyResultSignatures checks an answer whose request id is the machine
// request id), the sealed-thirds log body and its tag, and REGISTER's count;
// and each round's and init round's public inputs through tipResultParts and
// initResultParts at the vector's indices, which tipResultLayout and
// initResultLayout read from the example circuits' ABIs.
interface TipThird {
  node: number;
  owner: GrumpkinPoint;
  elements: [string, string][];
  plaintext: string[];
  nonce: string;
  ciphertext: string[];
  tag: string;
  c: string;
  fields: string[];
  record_hash: string;
}
interface TipRound {
  name: string;
  namespace: string;
  vk_hash: string;
  inputs: string[];
  inputs_hash: string;
  user_nonce: string;
  chain_request_id: string;
  old_commitments: string[];
  reads: string[];
  machine_request_id: string;
  key: string;
  key_hash: string;
  len: number;
  value: { shared: string }[];
  new_commitments: string[];
  thirds: TipThird[];
  nodes: { node: number; sig_pk: GrumpkinPoint; record_hashes: string[]; sealed_hash: string; message_preimage: string[]; message: string; signature: Signature }[];
  sealed_log: { tag: string; writes: number; chain_outputs: number; third_len: number; body: string[] };
  register: { len: number; chain_outputs: number; writes: number; sealed_thirds_fields: number; log_fields: number; accepted: boolean };
  in_slots: string[];
  out_slots: string[];
  npk_app_hash: string;
  ok: boolean;
  app_outputs: string[];
  public_inputs: string[];
  layout: Record<"namespace" | "vk_hash" | "request_id" | "npk_app_hash" | "ok", number> &
    Record<"in_slots" | "out_slots" | "reads" | "old_commitments" | "new_commitments" | "app_outputs", number[]>;
}
interface TipInitRound {
  name: string;
  namespace: string;
  vk_hash: string;
  inputs: string[];
  chain_request_id: string;
  machine_request_id: string;
  out_slots: string[];
  new_commitments: string[];
  npk_app_hash: string;
  new_hashes: string[];
  public_inputs: string[];
  layout: Record<"namespace" | "vk_hash" | "request_id" | "npk_app_hash", number> &
    Record<"out_slots" | "old_commitments" | "new_commitments" | "new_hashes", number[]>;
}
const TIP_RESULTS = vectorJson("tip_results.json") as {
  result_domain: string;
  pss_attempt: string;
  pss_state: number;
  public_log: { payload_fields: number; header_fields: number; max_log_fields: number };
  register_bound: { len: number; chain_outputs: number; writes: number; sealed_thirds_fields: number; log_fields: number; accepted: boolean }[];
  rounds: TipRound[];
  init_rounds: TipInitRound[];
};

/** An answer carrying a vector's public inputs under its machine request
 * id, as the layouts' parsers take it (no records: node-held state). */
function layoutAnswer(r: { vk_hash: string; machine_request_id: string; public_inputs: string[] }): ExecuteResponse {
  const sig = { s: ["0x00", "0x00"], e: ["0x00", "0x00"] } as unknown as Signature;
  return { request_id: r.machine_request_id, vk_hash: r.vk_hash, proof: "0x", public_inputs: r.public_inputs, stored: [], records: [], signatures: [sig, sig, sig] as Triple<Signature> };
}

describe("the tip's chain-held results (testvectors/tip_results.json)", () => {
  test("the domains are the client's and the other files'", () => {
    assert.equal(TIP_RESULTS.result_domain, hex(RESULT_DOMAIN));
    assert.equal(TIP_RESULTS.pss_state, Number(asciiLabel("PSS") * 256n + 2n));
    // Aztec v6 (FLAT_PUBLIC_LOGS_PAYLOAD_LENGTH, PUBLIC_LOG_HEADER_LENGTH, MAX_PUBLIC_LOG_SIZE_IN_FIELDS)
    assert.deepEqual(TIP_RESULTS.public_log, { payload_fields: 4096, header_fields: 2, max_log_fields: 4094 });
    assert.deepEqual(TIP_RESULTS.rounds.map((r) => r.len), [2, 3]);
    assert.equal(hex(PSS_ATTEMPT), TIP_RESULTS.pss_attempt);
    assert.equal(PSS_STATE, TIP_RESULTS.pss_state);
  });
  for (const r of TIP_RESULTS.rounds) {
    test(`${r.name}: ids, thirds, H(sealed_i), messages and signatures`, async () => {
      const inputsHash = await tipInputsHash(r.inputs);
      assert.equal(hex(inputsHash), r.inputs_hash);
      const chain = await chainRequestId(r.namespace, r.vk_hash, inputsHash, r.user_nonce);
      assert.equal(hex(chain), r.chain_request_id);
      const machine = await machineRequestId(chain.toBigInt(), r.old_commitments, r.reads);
      assert.equal(hex(machine), r.machine_request_id);
      assert.equal(hex(await bytesHash(r.key)), r.key_hash);
      assert.equal(r.new_commitments.length, 1);
      const noteHash = r.new_commitments[0]!;
      for (const t of r.thirds) {
        const node = KEYS.nodes[t.node]!;
        assert.deepEqual(t.owner, node.enc_pk, `${r.name} node ${t.node}: the machine owns its third`);
        const plaintext = [r.namespace, r.key_hash, noteHash].map((x) => BigInt(x));
        for (const [a, b] of t.elements) plaintext.push(1n, BigInt(a), BigInt(b));
        assert.deepEqual(plaintext.map(hex), t.plaintext);
        const nonce = await hash([r.namespace, r.key_hash, noteHash, t.owner.x, t.owner.y, asciiLabel("sidecar.record_ad")]);
        assert.equal(hex(nonce), t.nonce);
        const sealed = await aeEncrypt(node.record_key, nonce, plaintext);
        assert.deepEqual(sealed.ciphertext.map(hex), t.ciphertext);
        assert.equal(hex(sealed.tag), t.tag);
        assert.equal(node.key_id + [...t.ciphertext, t.tag].map((x) => x.slice(2)).join(""), t.c);
        assert.deepEqual(t.fields, [hex(BigInt(node.key_id)), ...t.ciphertext, t.tag]);
        assert.equal(t.fields.length, 3 * r.len + 5);
        assert.equal(await recordHash(t.c), t.record_hash);
      }
      // the shared elements are one replicated sharing of the value
      r.value.forEach((v, j) => {
        const pairs = r.thirds.map((t) => t.elements[j]!.map((x) => BigInt(x)));
        assert.equal(hex((pairs[0]![0]! + pairs[1]![0]! + pairs[2]![0]!) % BN254_MODULUS), v.shared);
        for (let i = 0; i < 3; i++) assert.equal(pairs[i]![1], pairs[(i + 2) % 3]![0]);
      });
      for (const n of r.nodes) {
        assert.deepEqual(n.sig_pk, KEYS.nodes[n.node]!.sig_pk);
        assert.deepEqual(n.record_hashes, [r.thirds[n.node]!.record_hash]);
        const sealed = await sealedHash(n.record_hashes);
        assert.equal(hex(sealed), n.sealed_hash);
        assert.equal(hex(sealed), hex(await hash(n.record_hashes)));
        const preimage = [TIP_RESULTS.result_domain, r.namespace, r.machine_request_id, ...r.new_commitments, hex(BigInt(n.node)), n.sealed_hash];
        assert.deepEqual(n.message_preimage, preimage);
        const message = await resultMessage(r.namespace, r.machine_request_id, r.new_commitments, n.node, sealed);
        assert.equal(hex(message), n.message);
        assert.equal(hex(message), hex(await hash(preimage)));
        assert.ok(await verifySignature(message.toBigInt(), SIG_KEYS[n.node]!, n.signature), `${r.name} node ${n.node}`);
        assert.equal(await verifySignature(message.toBigInt(), SIG_KEYS[(n.node + 1) % 3]!, n.signature), false);
        // signed over the machine request id, not the chain request id
        const overChain = await resultMessage(r.namespace, r.chain_request_id, r.new_commitments, n.node, sealed);
        assert.equal(await verifySignature(overChain.toBigInt(), SIG_KEYS[n.node]!, n.signature), false);
      }
    });
    test(`${r.name}: verifyResultSignatures accepts the round as an answer under the machine request id`, async () => {
      const response: ExecuteResponse = {
        request_id: requestIdHex(r.machine_request_id),
        vk_hash: r.vk_hash,
        proof: "0x00",
        public_inputs: r.new_commitments,
        stored: [],
        records: [{ key: r.key, note_hash: r.new_commitments[0]!, c: r.thirds.map((t) => t.c) as [string, string, string] }],
        signatures: r.nodes.map((n) => n.signature) as ExecuteResponse["signatures"],
      };
      await verifyResultSignatures(r.namespace, response, [0], [SIG_KEYS]);
      await assert.rejects(
        verifyResultSignatures(r.namespace, { ...response, request_id: requestIdHex(r.chain_request_id) }, [0], [SIG_KEYS]),
        (e: unknown) => e instanceof ResultSignatureError && e.node === 0,
      );
    });
    test(`${r.name}: the sealed-thirds log and REGISTER's count`, async () => {
      const log = r.sealed_log;
      assert.equal((await computeLogTag(Fr.fromHexString(r.chain_request_id), TIP_RESULTS.pss_state)).toString(), log.tag);
      assert.deepEqual([log.writes, log.chain_outputs], [1, 1]);
      assert.equal(log.third_len, 3 * r.len + 5);
      assert.equal(log.body.length, log.writes + 3 * log.chain_outputs * log.third_len);
      // the new commitments, then node by node each third's fields
      assert.deepEqual(log.body, [...r.new_commitments, ...r.thirds.flatMap((t) => t.fields)]);
      assert.equal(r.register.len, r.len);
      assert.equal(r.register.sealed_thirds_fields, 9 * r.len + 15);
      assert.equal(r.register.sealed_thirds_fields, 3 * log.third_len);
      assert.deepEqual([r.register.chain_outputs, r.register.writes], [log.chain_outputs, log.writes]);
      // the log REGISTER bounds: the tag, then the body
      assert.equal(r.register.log_fields, 1 + log.writes + r.register.sealed_thirds_fields);
      assert.equal(r.register.log_fields, 1 + log.body.length);
      assert.equal(r.register.accepted, r.register.log_fields <= TIP_RESULTS.public_log.max_log_fields);
    });
  }
  for (const r of TIP_RESULTS.rounds) {
    test(`${r.name}: machineRequestId, recordFields, computeSealedLogTag and parseSealedLog (tip-result.ts)`, async () => {
      assert.equal(hex(await machineRequestId(r.chain_request_id, r.old_commitments, r.reads)), r.machine_request_id);
      // another old commitment is another attempt
      assert.notEqual(hex(await machineRequestId(r.chain_request_id, r.old_commitments.map((c) => BigInt(c) + 1n), r.reads)), r.machine_request_id);
      for (const t of r.thirds) assert.deepEqual(recordFields(t.c).map((x) => hex(x)), t.fields);
      const log = r.sealed_log;
      assert.equal(hex(await computeSealedLogTag(r.chain_request_id)), log.tag);
      const shape = { W: log.writes, T: log.chain_outputs, L: log.third_len };
      const parsed = await parseSealedLog([log.tag, ...log.body], shape, r.chain_request_id);
      assert.equal(parsed.tag, log.tag);
      assert.deepEqual(parsed.newCommitments, r.new_commitments);
      assert.deepEqual(parsed.sealed, r.thirds.map((t) => [t.fields]));
      // the log of another chain request, and a body of another shape, are refused
      await assert.rejects(parseSealedLog([log.tag, ...log.body], shape, r.machine_request_id), /not the state tag/);
      await assert.rejects(parseSealedLog([log.tag, ...log.body.slice(1)], shape), /fields, expected/);
    });
  }
  // amm_swap_tip completes the request's partial note in apply: its
  // partial_note output sits right after ok and moves the app outputs one on
  test("rounds[0] is amm_swap_tip's non-secret-shared layout with the partial note after ok, as tipResultLayout reads it from the circuit's ABI", () => {
    const l = tipResultLayout(AMM_SWAP.circuit, queued({ ...AMM_SWAP.manifest, state: { "$state_keys.reads[0]": "node", "$state_keys.writes[0]": "node" } }));
    const v = TIP_RESULTS.rounds[0]!.layout;
    assert.deepEqual([l.requestId, l.oldCommitments, l.newCommitments, l.npkAppHash, l.ok, l.reads], [v.request_id, v.old_commitments, v.new_commitments, v.npk_app_hash, v.ok, v.reads]);
    assert.equal(l.partialNote, v.ok + 1);
    assert.deepEqual(l.appOutputs, v.app_outputs.map((i) => i + 1));
  });
  for (const r of TIP_RESULTS.rounds) {
    test(`${r.name}: tipResultParts takes each part from its public inputs (proved_public_inputs)`, async () => {
      const v = r.layout;
      const layout: TipResultLayout = {
        circuit: r.name,
        state: "node",
        oldCommitments: v.old_commitments,
        newCommitments: v.new_commitments,
        requestId: v.request_id,
        npkAppHash: v.npk_app_hash,
        ok: v.ok,
        appOutputs: v.app_outputs,
        reads: v.reads,
        records: [],
      };
      const parts = await tipResultParts(layout, r.namespace, r.chain_request_id, layoutAnswer(r));
      assert.equal(parts.machineRequestId, r.machine_request_id);
      assert.deepEqual([parts.oldCommitments, parts.newCommitments, parts.reads, parts.ok, parts.appOutputs], [r.old_commitments, r.new_commitments, r.reads, r.ok, r.app_outputs]);
      const pi = r.public_inputs;
      assert.deepEqual([pi[v.namespace], pi[v.vk_hash], pi[v.npk_app_hash]], [r.namespace, r.vk_hash, r.npk_app_hash]);
      assert.deepEqual([v.in_slots.map((i) => pi[i]), v.out_slots.map((i) => pi[i])], [r.in_slots, r.out_slots]);
      assert.equal(pi.length, v.app_outputs.at(-1)! + 1);
    });
  }
  const initLayouts = [AMM_INIT, LENDING_INIT].map((c) => initResultLayout(c.circuit, queued(c.manifest)));
  TIP_RESULTS.init_rounds.forEach((r, k) => {
    test(`${r.name}: initResultLayout reads its layout from the circuit's ABI, initResultParts its parts (init_public_inputs)`, async () => {
      const l: InitResultLayout = initLayouts[k]!;
      const v = r.layout;
      assert.deepEqual([l.slots, l.requestId, l.oldCommitments, l.newCommitments, l.npkAppHash, l.newHashes], [v.out_slots, v.request_id, v.old_commitments, v.new_commitments, v.npk_app_hash, v.new_hashes]);
      assert.equal(hex(await initChainRequestId(r.namespace, r.vk_hash, r.inputs)), r.chain_request_id);
      const parts = await initResultParts(l, r.namespace, r.chain_request_id, layoutAnswer(r));
      assert.equal(parts.machineRequestId, r.machine_request_id);
      assert.deepEqual([parts.slots, parts.newCommitments, parts.newHashes], [r.out_slots, r.new_commitments, r.new_hashes]);
      assert.deepEqual([r.public_inputs[v.namespace], r.public_inputs[v.npk_app_hash]], [r.namespace, r.npk_app_hash]);
    });
  });
  test("REGISTER's bound: the apply log within one public log (453 elements at T = 1, not 3 × 150)", () => {
    const { payload_fields, header_fields, max_log_fields } = TIP_RESULTS.public_log;
    assert.equal(max_log_fields, payload_fields - header_fields);
    for (const b of TIP_RESULTS.register_bound) {
      assert.equal(b.writes, b.chain_outputs);
      assert.equal(b.sealed_thirds_fields, b.chain_outputs * (9 * b.len + 15));
      assert.equal(b.log_fields, 1 + b.writes + b.sealed_thirds_fields);
      assert.equal(b.accepted, b.log_fields <= max_log_fields);
    }
    assert.deepEqual(
      TIP_RESULTS.register_bound.map((b) => [b.len, b.chain_outputs, b.log_fields, b.accepted]),
      [[453, 1, 4094, true], [454, 1, 4103, false], [149, 3, 4072, true], [150, 3, 4099, false]],
    );
  });
});

describe("the manifest bounds (testvectors/manifest_limits.json)", () => {
  test("the client's bounds are the ones REGISTER enforces", () => {
    const v = vectorJson("manifest_limits.json") as Record<string, number>;
    assert.deepEqual(
      { max_tree_depth: MAX_TREE_DEPTH, max_tree_window: MAX_TREE_WINDOW, min_map_depth: MIN_MAP_DEPTH, max_map_depth: MAX_MAP_DEPTH, max_name_bytes: MAX_NAME_BYTES },
      { max_tree_depth: v.max_tree_depth, max_tree_window: v.max_tree_window, min_map_depth: v.min_map_depth, max_map_depth: v.max_map_depth, max_name_bytes: v.max_name_bytes },
    );
  });
});
