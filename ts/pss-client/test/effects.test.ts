import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { describe, test } from "node:test";

import { canonicalLength, fieldHex, noteHashIndices, resultCommitments, shapeFromAbi, splitEffects, type Shape } from "../src/internal.ts";
import { fixture } from "@aztec-pss/test-support";

const abiFixture = (name: string): unknown => fixture(`${name}.abi.json`);

// A canonical array whose values say where they belong: segment base + index.
const BASE = { ns: 0x1000, owner: 0x2000, in: 0x3000, out: 0x4000, app: 0x5000, leaf: 0x6000, nul: 0x7000, nh: 0x8000, npk: 0x9000, ao: 0xa000 };
function canonical({ R, W, P, A }: Shape): bigint[] {
  const seg = (base: number, n: number) => Array.from({ length: n }, (_, i) => BigInt(base + i));
  return [
    ...seg(BASE.ns, 1),
    ...seg(BASE.owner, 1),
    ...seg(BASE.in, R),
    ...seg(BASE.out, W),
    ...seg(BASE.app, P),
    ...seg(BASE.leaf, R),
    ...seg(BASE.nul, R),
    ...seg(BASE.nh, W),
    // npk_app_hash is always present; 0 when R = 0
    R === 0 ? 0n : BigInt(BASE.npk),
    ...seg(BASE.ao, A),
  ];
}

const big = (xs: { toBigInt(): bigint }[]) => xs.map((x) => x.toBigInt());
const seq = (base: number, n: number) => Array.from({ length: n }, (_, i) => BigInt(base + i));

describe("splitEffects", () => {
  for (const [R, W, P, A] of [
    [0, 1, 0, 0],
    [1, 1, 0, 0],
    [1, 1, 2, 1],
    [1, 0, 1, 1],
    [1, 1, 0, 2],
  ] as const) {
    test(`shape (R=${R}, W=${W}, P=${P}, A=${A})`, () => {
      const shape = { R, W, P, A };
      const pis = canonical(shape).map((v) => fieldHex(v));
      assert.equal(pis.length, canonicalLength(shape));
      assert.equal(pis.length, 3 + 3 * R + 2 * W + P + A);
      const s = splitEffects(pis, shape, {
        namespace: BASE.ns,
        owner: BASE.owner,
        reads: seq(BASE.in, R),
        writes: seq(BASE.out, W),
        appInputs: seq(BASE.app, P),
      });
      assert.equal(s.namespace.toBigInt(), BigInt(BASE.ns));
      assert.equal(s.owner.toBigInt(), BigInt(BASE.owner));
      assert.deepEqual(big(s.in_slots), seq(BASE.in, R));
      assert.deepEqual(big(s.out_slots), seq(BASE.out, W));
      assert.deepEqual(big(s.app_inputs), seq(BASE.app, P));
      assert.deepEqual(big(s.effects.read_leaves), seq(BASE.leaf, R));
      assert.deepEqual(big(s.effects.nullifiers), seq(BASE.nul, R));
      assert.deepEqual(big(s.effects.new_note_hashes), seq(BASE.nh, W));
      assert.equal(s.effects.npk_app_hash.toBigInt(), R === 0 ? 0n : BigInt(BASE.npk));
      assert.deepEqual(big(s.effects.app_outputs), seq(BASE.ao, A));
    });
  }

  test("refuses a wrong length and a prefix that differs from the request", () => {
    const shape = { R: 1, W: 1, P: 2, A: 1 };
    const pis = canonical(shape);
    assert.throws(() => splitEffects(pis.slice(1), shape), /10 values, the shape .* has 11/);
    assert.throws(() => splitEffects(pis, shape, { namespace: 1 }), /namespace: public inputs carry/);
    assert.throws(() => splitEffects(pis, shape, { writes: [BASE.out + 1] }), /out_slots/);
    assert.throws(() => splitEffects([...pis.slice(0, 10), 2n ** 254n], shape), /modulus/);
  });
});

describe("shapeFromAbi", () => {
  test("the AMM circuits", () => {
    const seed = shapeFromAbi(abiFixture("pss_seed"));
    assert.deepEqual({ R: seed.R, W: seed.W, P: seed.P, A: seed.A }, { R: 0, W: 1, P: 0, A: 0 });
    assert.equal(canonicalLength(seed), 5);
    const init = shapeFromAbi(abiFixture("amm_init"));
    assert.deepEqual({ R: init.R, W: init.W, P: init.P, A: init.A }, { R: 1, W: 1, P: 0, A: 0 });
    assert.equal(canonicalLength(init), 8);
    const swap = shapeFromAbi(abiFixture("amm_swap"));
    assert.deepEqual({ R: swap.R, W: swap.W, P: swap.P, A: swap.A }, { R: 1, W: 1, P: 2, A: 1 });
    assert.equal(swap.namespaceParam, "namespace");
    assert.deepEqual(swap.appInputs, [
      { name: "amount_in", width: 1 },
      { name: "direction", width: 1 },
    ]);
    assert.equal(canonicalLength(swap), 11);
    // the compiled circuit itself (abi nested), not only the abi
    assert.equal(shapeFromAbi({ abi: (abiFixture("amm_swap") as { abi: unknown }).abi }).P, 2);
  });

  // ABIs for the shapes no AMM circuit has: (1, 0, 1, 1) and (1, 1, 0, 2),
  // with a wider app input to exercise flattening.
  const F = { kind: "field" };
  const arr = (n: number, type: unknown = F) => ({ kind: "array", length: n, type });
  const pub = (name: string, type: unknown) => ({ name, type, visibility: "public" });
  const priv = (name: string, type: unknown = F) => ({ name, type, visibility: "private" });
  const ret = (R: number, W: number, A: number) => ({
    abi_type: {
      kind: "struct",
      path: "pss_core::effects::PssEffects",
      fields: [
        { name: "read_leaves", type: arr(R) },
        { name: "nullifiers", type: arr(R) },
        { name: "new_note_hashes", type: arr(W) },
        { name: "npk_app_hash", type: F },
        { name: "app_outputs", type: arr(A) },
      ],
    },
    visibility: "public",
  });
  const abi = (params: unknown[], r: unknown) => ({ abi: { parameters: params, return_type: r } });

  test("synthetic shapes (1, 0, 1, 1) and (1, 1, 0, 2)", () => {
    const readOnly = shapeFromAbi(
      abi([pub("namespace", F), pub("owner", F), pub("in_slots", arr(1)), pub("switch", { kind: "boolean" }), priv("in0_fields", arr(9)), priv("nsk_app")], ret(1, 0, 1)),
    );
    assert.deepEqual([readOnly.R, readOnly.W, readOnly.P, readOnly.A], [1, 0, 1, 1]);
    const twoOut = shapeFromAbi(
      abi([pub("namespace", F), pub("owner", F), pub("in_slots", arr(1)), pub("out_slots", arr(1)), priv("nsk_app")], ret(1, 1, 2)),
    );
    assert.deepEqual([twoOut.R, twoOut.W, twoOut.P, twoOut.A], [1, 1, 0, 2]);
    const wide = shapeFromAbi(
      abi(
        [
          pub("namespace", F),
          pub("owner", F),
          pub("out_slots", arr(1)),
          pub("limbs", arr(3, { kind: "integer", sign: "unsigned", width: 64 })),
          pub("pair", { kind: "struct", path: "P", fields: [{ name: "a", type: F }, { name: "b", type: arr(2) }] }),
        ],
        ret(0, 1, 0),
      ),
    );
    assert.equal(wide.P, 6);
    assert.deepEqual(wide.appInputs, [
      { name: "limbs", width: 3 },
      { name: "pair", width: 3 },
    ]);
  });

  test("refuses ABIs outside the pss_core interface", () => {
    const base = [pub("namespace", F), pub("owner", F), pub("in_slots", arr(1)), pub("out_slots", arr(1))];
    assert.throws(() => shapeFromAbi(abi([pub("owner", F), pub("namespace", F)], ret(0, 0, 0))), /owner: pub Field/);
    assert.throws(() => shapeFromAbi(abi([pub("namespace", F), pub("owner", F), pub("x", F), pub("out_slots", arr(1))], ret(0, 1, 0))), /out of order/);
    assert.throws(() => shapeFromAbi(abi(base, ret(2, 1, 0))), /read_leaves has width 2, in_slots 1/);
    assert.throws(() => shapeFromAbi(abi(base, ret(1, 2, 0))), /new_note_hashes has width 2/);
    const npkM = ret(1, 1, 0);
    npkM.abi_type.fields[3]!.name = "npk_m_hash";
    assert.throws(() => shapeFromAbi(abi(base, npkM)), /expected read_leaves, nullifiers, new_note_hashes, npk_app_hash, app_outputs/);
    assert.throws(() => shapeFromAbi(abi(base, null)), /not a public PssEffects/);
    assert.throws(() => shapeFromAbi(abi([...base, { name: "d", type: F, visibility: "databus" }], ret(1, 1, 0))), /databus/);
  });
});

describe("note-hash indices from the ABI and the manifest", () => {
  for (const name of ["amm_init", "amm_swap", "pss_seed"]) {
    test(`${name}: each output's note hash is the new_note_hashes element the manifest names`, () => {
      const abi = abiFixture(name);
      const manifest = JSON.parse(readFileSync(new URL(`../../../examples/amm/manifests/${name}.json`, import.meta.url), "utf8")) as {
        outputs: { note_hash: string }[];
      };
      const shape = shapeFromAbi(abi);
      const indices = noteHashIndices(abi, manifest);
      assert.equal(indices.length, manifest.outputs.length);
      const values = canonical(shape).map((v) => fieldHex(v));
      const split = splitEffects(values, shape);
      manifest.outputs.forEach((o, k) => {
        const at = Number(/^new_note_hashes\[(\d+)\]$/.exec(o.note_hash)![1]);
        assert.equal(resultCommitments(values, indices)[k], split.effects.new_note_hashes[at]!.toString());
      });
    });
  }
  test("refuses what REGISTER refuses", () => {
    const abi = abiFixture("amm_swap");
    const manifest = JSON.parse(readFileSync(new URL("../../../examples/amm/manifests/amm_swap.json", import.meta.url), "utf8")) as {
      outputs: { note_hash: string }[];
    };
    const out = (...paths: string[]) => ({ ...manifest, outputs: paths.map((note_hash) => ({ ...manifest.outputs[0]!, note_hash })) });
    assert.throws(() => noteHashIndices(abi, out("new_note_hashes")), /not one element/);
    assert.throws(() => noteHashIndices(abi, out("npk_app_hash", "npk_app_hash")), /named by two outputs/);
    assert.throws(() => noteHashIndices(abi, { ...manifest, outputs: undefined }), /manifest.outputs: missing/);
    const priv = structuredClone(abi) as { abi: { return_type: { visibility: string } } };
    priv.abi.return_type.visibility = "private";
    assert.throws(() => noteHashIndices(priv, out("new_note_hashes[0]")), /private output/);
    assert.throws(() => resultCommitments(["0x01"], [3]), /1 public inputs, none at the note-hash index 3/);
  });
});
