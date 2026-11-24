// Secret-shared on-chain intake on the client side (src/intake-shared-onchain.ts):
// testvectors/shared_onchain.json reproduced value by value (the key
// exchange, the wraps, the encoding, C, the request id, the log tags, the
// log and its data hash, every node's pair of every shared value, the
// layout's correction positions, node 1's enc key rotation); the request
// builder on the vector's ephemeral secret and on a fresh one, opened by
// the three nodes; and its refusals.

import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { describe, test } from "node:test";

import { Fr } from "@aztec-labs/foundation/curves/bn254";

import {
  BN254_MODULUS,
  ConfigError,
  MAX_LOGGED_VALUES,
  PSS_ENC_ROTATE,
  REQUEST_LOG_LEN,
  SIDECAR_INTAKE_PRF,
  buildSharedOnchainRequest,
  computeRequestLogTag,
  derivedShare,
  encRotationMessage,
  encodeShared,
  fieldHex,
  inputsCommitment,
  intakeLayout,
  intakeModule,
  intakeSummary,
  intakeWraps,
  layIntakeArgs,
  keyExchange,
  liftX,
  logPadding,
  nodePair,
  onchainLayout,
  packEpochs,
  requestDataHash,
  requestLogSiloedTag,
  sharedChainRequestId,
  sharedOnchainIntake,
  sharedOnchainIntakeArgs,
  sharedRequestLog,
  unpackEpochs,
  verifySignature,
  type EncKeyInput,
  type IntakeRoute,
  type Signature,
  type Triple,
} from "../src/internal.ts";
import { fixture, fixturePath, hex, queued, repoJson, vectorJson } from "@aztec-pss/test-support";

const hexes = (vs: readonly bigint[]) => vs.map((v) => hex(v));

type P = { x: string; y: string };
const V = vectorJson("shared_onchain.json") as {
  sidecar_intake_prf: string;
  pss_enc_rotate: string;
  namespace: string;
  vk_hash: string;
  kinds: { name: string; kind: "clear" | "chosen" }[];
  values: { name: string; value: string }[];
  eph: string;
  node_enc: Triple<string>;
  node_enc_pk: Triple<P>;
  epochs: Triple<number>;
  epochs_packed: string;
  secrets: Triple<string>;
  eph_x: string;
  wraps: Triple<string>;
  blinding: string;
  clear: string[];
  corrections: string[];
  inputs_commitment: string;
  chain_request_id: string;
  tag: string;
  siloed_tag: string;
  log: string[];
  data_hash: string;
  shared: { name: string; correction?: number }[];
  pairs: Triple<{ name: string; pair: [string, string] }[]>;
  rotation: { node: number; pk: P; epoch: number; message: string; signature: Signature };
};
const KEYS = vectorJson("keys.json") as { nodes: { sig_pk: P }[] };
// the ABI of testvectors/manifests/shared_onchain_round.json is secret-shared
// receipt intake's vectors' (sidecar-tip testing::shared_circuit_abi)
const ABI = (vectorJson("shared_intake.json") as { abi: unknown }).abi;
const MANIFEST = vectorJson("manifests/shared_onchain_round.json") as Record<string, unknown>;

const LAYOUT = onchainLayout(ABI, queued(MANIFEST));
const ENC_KEYS = V.node_enc_pk.map((pk, i) => ({ ...pk, epoch: V.epochs[i]! })) as Triple<EncKeyInput>;
const value = (name: string) => V.values.find((v) => v.name === name)!.value;
// C's values in its order (the vector lists them so)
const VALUES = V.values.map((v) => v.value);
// the user's values by name: the clear and chosen ones
const INPUTS = { amount: value("amount"), position: value("position"), $partial_note: value("$partial_note"), $outcome_key: value("$outcome_key"), $outcome_tag: value("$outcome_tag") };
const sum = (vs: readonly bigint[]) => vs.reduce((a, b) => a + b, 0n) % BN254_MODULUS;

const build = (eph?: string, over: Partial<Parameters<typeof buildSharedOnchainRequest>[0]> = {}) =>
  buildSharedOnchainRequest(
    { layout: LAYOUT, namespace: V.namespace, vkHash: V.vk_hash, inputs: INPUTS, encKeys: ENC_KEYS, ...over },
    eph === undefined ? {} : { eph },
  );

describe("shared_onchain.json: the encoding", () => {
  test("the constants and the packed epochs", () => {
    assert.equal(hex(SIDECAR_INTAKE_PRF), V.sidecar_intake_prf);
    assert.equal(hex(PSS_ENC_ROTATE), V.pss_enc_rotate);
    assert.equal(hex(packEpochs(V.epochs)), V.epochs_packed);
    assert.deepEqual(unpackEpochs(V.epochs_packed), V.epochs);
    assert.equal(unpackEpochs(1n << 96n), null);
    assert.throws(() => packEpochs([1, 2, 2 ** 32]), RangeError);
  });

  test("the layout: each value's kind and every shared value's correction position", () => {
    assert.deepEqual(LAYOUT.kinds, V.kinds);
    assert.deepEqual(LAYOUT.shared, V.shared);
    assert.equal(LAYOUT.clear, V.clear.length);
    assert.equal(LAYOUT.corrections, V.corrections.length);
  });

  test("the key-exchange secrets, E.x and the wraps", async () => {
    const { secrets, ephX } = await keyExchange(V.eph, V.node_enc_pk);
    assert.deepEqual(hexes(secrets), V.secrets);
    assert.equal(hex(ephX), V.eph_x);
    assert.deepEqual(hexes(await intakeWraps(secrets)), V.wraps);
    await assert.rejects(keyExchange(0n, V.node_enc_pk), RangeError);
    await assert.rejects(keyExchange(V.eph, [V.node_enc_pk[0], { x: "0x1", y: "0x2" }, V.node_enc_pk[2]]), RangeError);
  });

  test("the blinding, the clear values and the corrections", async () => {
    assert.deepEqual(V.values.map((v) => v.name), V.kinds.map((k) => k.name));
    const e = await encodeShared(V.kinds.map((k) => k.kind), VALUES, V.eph, V.node_enc_pk);
    assert.equal(hex(e.blinding), V.blinding);
    assert.deepEqual(hexes(e.clear), V.clear);
    assert.deepEqual(hexes(e.corrections), V.corrections);
    assert.equal(hex(e.ephX), V.eph_x);
    assert.deepEqual(hexes(e.wraps), V.wraps);
  });

  test("C, the chain request id, the log's tag and siloed tag, the log and its data hash", async () => {
    const c = await inputsCommitment(VALUES, V.blinding);
    assert.equal(hex(c), V.inputs_commitment);
    const id = await sharedChainRequestId(V.namespace, V.vk_hash, c);
    assert.equal(hex(id), V.chain_request_id);
    const tag = await computeRequestLogTag(id);
    assert.equal(hex(tag), V.tag);
    assert.equal(hex(await requestLogSiloedTag(V.namespace, tag)), V.siloed_tag);
    const log = await sharedRequestLog(V.inputs_commitment, V.epochs, { blinding: BigInt(V.blinding), ephX: BigInt(V.eph_x), wraps: V.wraps.map(BigInt) as Triple<bigint>, clear: V.clear.map(BigInt), corrections: V.corrections.map(BigInt) });
    assert.equal(log.length, REQUEST_LOG_LEN);
    assert.deepEqual(hexes(log), V.log);
    const first = 6 + V.clear.length + V.corrections.length;
    // padded under the blinding, not the tag, which the public request id gives
    for (let i = first; i < REQUEST_LOG_LEN; i++) {
      assert.equal(log[i], await logPadding(V.blinding, i));
      assert.notEqual(log[i], await logPadding(V.tag, i));
    }
    assert.equal(hex(await requestDataHash(log)), V.data_hash);
    await assert.rejects(sharedRequestLog(1n, V.epochs, { blinding: 1n, ephX: 1n, wraps: [1n, 1n, 1n], clear: Array(MAX_LOGGED_VALUES + 1).fill(1n), corrections: [] }), RangeError);
  });

  test("every node's pair of every shared value, from the log and its enc scalar", async () => {
    const log = { fields: V.log, shared: V.shared };
    for (let i = 0; i < 3; i++) {
      for (const want of V.pairs[i]!) {
        assert.deepEqual(hexes(await derivedShare(V.node_enc[i]!, i, log, want.name)), want.pair, `node ${i} ${want.name}`);
      }
    }
    // the same from the key-exchange secrets directly
    for (let i = 0; i < 3; i++) {
      for (const [j, s] of V.shared.entries()) {
        const correction = s.correction === undefined ? 0n : V.log[s.correction]!;
        const pair = await nodePair(i, V.secrets[i]!, V.wraps[(i + 2) % 3]!, j, correction);
        assert.deepEqual(hexes(pair), V.pairs[i]![j]!.pair);
      }
    }
    // E.x lifts to a point; a node with another node's scalar gets another pair
    assert.ok(await liftX(V.eph_x));
    assert.equal(await liftX(0n), null);
    assert.notDeepEqual(hexes(await derivedShare(V.node_enc[1], 0, log, "amount")), V.pairs[0][0]!.pair);
    await assert.rejects(derivedShare(V.node_enc[0], 0, log, "other"), RangeError);
  });

  test("node 1's enc key rotation: the message, and its signature under node 1's sig key", async () => {
    const r = V.rotation;
    const message = await encRotationMessage(V.namespace, r.node, r.pk, r.epoch);
    assert.equal(hex(message), r.message);
    assert.equal(await verifySignature(message, KEYS.nodes[r.node]!.sig_pk, r.signature), true);
    assert.equal(await verifySignature(message, KEYS.nodes[0]!.sig_pk, r.signature), false);
    assert.equal(await verifySignature(await encRotationMessage(V.namespace, r.node, r.pk, r.epoch + 1), KEYS.nodes[r.node]!.sig_pk, r.signature), false);
  });
});

describe("buildSharedOnchainRequest", () => {
  test("on the vector's ephemeral secret it reproduces the vector's request", async () => {
    const r = await build(V.eph);
    assert.deepEqual(r.commitmentNames, V.kinds.map((k) => k.name));
    assert.deepEqual(r.values, VALUES);
    assert.equal(r.eph, V.eph);
    assert.equal(r.blinding, V.blinding);
    assert.equal(r.outcomeKey, value("$outcome_key"));
    assert.equal(r.outcomeTag, value("$outcome_tag"));
    assert.equal(r.inputsCommitment, V.inputs_commitment);
    assert.equal(r.chainRequestId, V.chain_request_id);
    assert.equal(r.logTag, V.tag);
    assert.deepEqual(r.epochs, V.epochs);
    assert.deepEqual(r.log, V.log);
    assert.equal(r.dataHash, V.data_hash);
    assert.deepEqual(r.clearInputs, { position: V.clear[0] });
    const [values, eph] = sharedOnchainIntakeArgs(r);
    assert.deepEqual(values.map((v) => hex(v)), VALUES);
    assert.equal(hex(eph), V.eph);
  });

  test("a fresh ephemeral secret gives another log whose node pairs still open to the values", async () => {
    const [a, b] = await Promise.all([build(), build()]);
    assert.notEqual(a.eph, V.eph);
    assert.notEqual(a.eph, b.eph);
    assert.notDeepEqual(a.log, V.log);
    assert.notEqual(a.chainRequestId, b.chainRequestId);
    assert.equal(a.outcomeKey, value("$outcome_key"));
    assert.equal(a.outcomeTag, value("$outcome_tag"));
    const log = { fields: a.log, shared: LAYOUT.shared };
    const want: Record<string, string> = { amount: value("amount"), $partial_note: value("$partial_note"), $outcome_key: a.outcomeKey, $outcome_tag: a.outcomeTag, $blinding: a.blinding };
    for (const s of LAYOUT.shared) {
      const pairs = await Promise.all([0, 1, 2].map((i) => derivedShare(V.node_enc[i]!, i, log, s.name)));
      for (let i = 0; i < 3; i++) assert.equal(pairs[i]![1], pairs[(i + 2) % 3]![0], `${s.name}: node ${i}'s second is node ${(i + 2) % 3}'s first`);
      assert.equal(hex(sum(pairs.map((p) => p[0]))), want[s.name], s.name);
    }
    assert.equal(a.inputsCommitment, hex(await inputsCommitment(a.values, a.blinding)));
    assert.equal(a.dataHash, hex(await requestDataHash(a.log)));
    assert.equal(a.log[0], a.inputsCommitment);
  });

  test("the refusals", async () => {
    await assert.rejects(build(undefined, { inputs: { ...INPUTS, $blinding: "0x1" } }), /inputs\.\$blinding: the encoding defines it/);
    const { $outcome_key: _, ...noKey } = INPUTS;
    await assert.rejects(build(undefined, { inputs: noKey }), /inputs\.\$outcome_key: missing/);
    const { $outcome_tag: __, ...noTag } = INPUTS;
    await assert.rejects(build(undefined, { inputs: noTag }), /inputs\.\$outcome_tag: missing/);
    await assert.rejects(build(undefined, { inputs: { ...INPUTS, amount: ["0x1", "0x2"] } }), /one field element/);
    await assert.rejects(build(undefined, { inputs: { ...INPUTS, position: 2n ** 32n } }), /does not fit in 32 bit/);
    await assert.rejects(build(undefined, { inputs: { ...INPUTS, other: "0x1" } }), /inputs\.other: unexpected/);
    await assert.rejects(build(undefined, { encKeys: [ENC_KEYS[0], { ...ENC_KEYS[1], epoch: 0 }, ENC_KEYS[2]] }), /encKeys\[1\]\.epoch: 0/);
    await assert.rejects(build(undefined, { encKeys: [ENC_KEYS[0], ENC_KEYS[1], { x: "0x1", y: "0x2", epoch: 1 }] }), /enc key of node 2/);
    await assert.rejects(build(undefined, { isValid: () => false }), /isValid/);
    await assert.rejects(build("0x0"), /eph: the ephemeral secret is zero/);
    const seen: bigint[][] = [];
    await build(V.eph, { isValid: (vs) => (seen.push([...vs]), true) });
    assert.deepEqual(hexes(seen[0]!), VALUES);
  });

  test("a layout under another intake is refused", () => {
    assert.throws(() => onchainLayout(ABI, queued({ ...MANIFEST, intake: "shared_receipt" })), ConfigError);
  });
});

describe("sharedOnchainIntake: the IntakeModule of secret-shared on-chain intake", () => {
  // what obtain reads of the route: the circuit's intake layout, the
  // namespace and the vk hash; nothing is sent
  const route = {
    layout: intakeLayout(ABI, queued(MANIFEST)),
    namespace: fieldHex(BigInt(V.namespace)),
    vkHash: fieldHex(BigInt(V.vk_hash)),
  } as unknown as IntakeRoute;
  const ask = { circuit: "shared_onchain_round", inputs: INPUTS, encKeys: ENC_KEYS, randomness: { eph: V.eph } };

  test("obtain builds the vector's request; the arguments, summary and logs follow from it", async () => {
    assert.equal(intakeModule("shared_onchain"), sharedOnchainIntake);
    const intake = await sharedOnchainIntake.obtain(route, ask);
    assert.equal(intake.intake, "shared_onchain");
    assert.deepEqual(intake.request.log, V.log);
    // the stored keys through a reader: the same request
    const read = await sharedOnchainIntake.obtain(route, { ...ask, encKeys: async () => ENC_KEYS });
    assert.equal(read.request.chainRequestId, V.chain_request_id);
    assert.equal(intake.request.chainRequestId, V.chain_request_id);
    assert.equal(intake.request.dataHash, V.data_hash);
    // the request function's arguments: C's values as one array, then eph
    const [values, eph] = sharedOnchainIntake.intakeArgs(intake, {}) as [Fr[], Fr];
    assert.deepEqual(values.map((v) => hex(v)), VALUES);
    assert.equal(hex(eph), V.eph);
    assert.deepEqual(sharedOnchainIntake.parameters, [["eph", "field"]]);
    // laid onto `request_shared_onchain(values: [Field; 5], eph: Field)`
    const field = { kind: "field" } as const;
    const fn = {
      name: "request_shared_onchain",
      parameters: [
        { name: "values", type: { kind: "array", length: 5, type: field }, visibility: "private" },
        { name: "eph", type: field, visibility: "private" },
      ],
    } as never;
    const laid = layIntakeArgs(fn, "shared_onchain", [values, eph]) as [Fr[], Fr];
    assert.deepEqual(laid[0].map((v) => hex(v)), VALUES);
    // what the request is, and what it keeps off the chain: the shared
    // values (the outcome key among them), the blinding and the ephemeral
    // secret; the clear `position` is in the log
    const summary = intakeSummary(intake);
    assert.equal(summary.chainRequestId, V.chain_request_id);
    assert.deepEqual(summary.values, VALUES);
    assert.equal(summary.outcomeKey, value("$outcome_key"));
    assert.equal(summary.expiryBlock, undefined);
    assert.deepEqual(
      summary.privateValues.map(([n]) => n),
      [...V.kinds.filter((k) => k.kind !== "clear").map((k) => k.name), "blinding", "eph"],
    );
    assert.ok(!summary.privateValues.some(([n]) => n === "position"));
    // its request log is a private log: no public log
    assert.deepEqual(await sharedOnchainIntake.requestLogs(intake), []);
    assert.equal(sharedOnchainIntake.results.form, "outcome");
  });

  test("obtain draws the outcome key and tag when the ask gives no secrets and the inputs name none", async () => {
    const { $outcome_key: _, $outcome_tag: __, ...inputs } = INPUTS;
    const [one, two] = await Promise.all([0, 1].map(() => sharedOnchainIntake.obtain(route, { ...ask, inputs })));
    for (const r of [one!.request, two!.request]) {
      assert.equal(r.values[r.commitmentNames.indexOf("$outcome_key")], r.outcomeKey);
      assert.equal(r.values[r.commitmentNames.indexOf("$outcome_tag")], r.outcomeTag);
    }
    assert.notEqual(one!.request.outcomeKey, two!.request.outcomeKey);
    assert.notEqual(one!.request.outcomeTag, two!.request.outcomeTag);
    // the ask's secrets where given
    const secrets = { blinding: 1n, outcomeKey: 0x0beefn, outcomeTag: 0x7a6n };
    const given = await sharedOnchainIntake.obtain(route, { ...ask, inputs, secrets });
    assert.equal(given.request.outcomeKey, fieldHex(0x0beefn));
    assert.equal(given.request.outcomeTag, fieldHex(0x7a6n));
  });

  test("obtain refuses an ask without the inputs or the stored enc keys", async () => {
    await assert.rejects(sharedOnchainIntake.obtain(route, { ...ask, inputs: undefined }), /no inputs/);
    await assert.rejects(sharedOnchainIntake.obtain(route, { ...ask, encKeys: undefined }), /encKeys/);
  });
});

// ---- testvectors/onchain_layouts.json ----

// Each secret-shared example round's encoding layout as sidecar-tip derives it
// from its manifest (`onchain_layout`), the vector the examples' Noir tests
// assert their Layout globals against: the client derives the same kinds, clear
// count and corrections from the round's ABI (test-support fixtures, pinned against the
// compiled circuit by fixtures.test.ts) and the manifest, for every round whose
// ABI test-support holds, every secret-shared on-chain round among them. A round
// under secret-shared receipt intake has the same layout (its CHOSEN values are
// the sharing's summand order), read here as onchainLayout of its manifest under
// shared_onchain.
describe("the examples' secret-shared layouts", () => {
  const L = vectorJson("onchain_layouts.json") as {
    kinds: Record<"clear" | "chosen", number>;
    rounds: { circuit: string; manifest: string; names: string[]; kinds: number[]; clear: number; corrections: number }[];
  };
  test("are the client's onchainLayout of each round's ABI and manifest", () => {
    const manifestOf = (r: { manifest: string }) =>
      repoJson(r.manifest) as { intake: string };
    const rounds = L.rounds.filter((r) => existsSync(fixturePath(`${r.circuit}.abi.json`)));
    for (const r of L.rounds) {
      if (manifestOf(r).intake === "shared_onchain") assert.ok(rounds.includes(r), `${r.circuit}.abi.json is not a fixture`);
    }
    assert.ok(rounds.length > 2, "the receipt-intake rounds with an ABI fixture");
    for (const r of rounds) {
      const abi = fixture(`${r.circuit}.abi.json`) as { abi: unknown };
      const layout = onchainLayout(abi.abi, queued({ ...manifestOf(r), intake: "shared_onchain" }));
      assert.deepEqual(layout.kinds.map((k) => k.name), r.names, r.manifest);
      assert.deepEqual(layout.kinds.map((k) => L.kinds[k.kind]), r.kinds, r.manifest);
      assert.equal(layout.clear, r.clear, r.manifest);
      assert.equal(layout.corrections, r.corrections, r.manifest);
    }
  });
});
