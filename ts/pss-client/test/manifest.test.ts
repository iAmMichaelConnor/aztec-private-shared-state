// parseManifest (src/manifest.ts): the schema's defaults, a defaulted field
// given as null refused, the path rules (consume under intake direct only;
// binding and commitment_slot under a queued intake only; the
// state holders each path allows), the node default as tipResultLayout
// counts chain-held outputs, and the tree layout of a tree-valued key with
// `$new_leaf`.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { describe, test } from "node:test";

import { isQueued, isSharedIntake, MAX_TREE_WINDOW, parseManifest, publicReadParams, stateOf, tipResultLayout, treeOf, treeParams } from "../src/internal.ts";
import { TEST_PLAIN, queued } from "@aztec-pss/test-support";

const DIRECT = {
  manifest: 1,
  circuit: "swap",
  namespace_param: "namespace",
  state_keys: { reads: 1, writes: 1 },
  witness: [{ param: "namespace", from: { PUBLIC: "$namespace" } }],
  outputs: [{ TACEO_store: "out0", STORE: "$state_keys.writes[0]", len: 2, note_hash: "new_c" }],
};
// a non-secret-shared round that completes no note says so (`outcome: none`)
const QUEUED = { ...DIRECT, intake: "onchain", outcome: "none", state: { "$state_keys.reads[0]": "chain", "$state_keys.writes[0]": "chain" } };
/** QUEUED under `intake`, a secret-shared one under the default `partial`. */
const queuedAt = (intake: string) => ({ ...QUEUED, intake, outcome: intake.startsWith("shared_") ? "partial" : "none" });

describe("parseManifest", () => {
  test("defaults: intake direct, state node, no consume; a queued intake binds by turn", () => {
    const d = parseManifest(DIRECT);
    assert.equal(d.intake, "direct");
    assert.equal(isQueued(d), false);
    assert.equal(stateOf(d, "$state_keys.writes[0]"), "node");
    assert.deepEqual(d.intake === "direct" && d.consume, []);
    assert.deepEqual(d.publicReads, []);
    const once = parseManifest({ ...DIRECT, consume: [{ key: "$state_keys.reads[0]" }] });
    assert.deepEqual(once.intake === "direct" && once.consume, [{ key: "$state_keys.reads[0]", policy: "once" }]);

    const q = parseManifest(QUEUED);
    assert.ok(isQueued(q));
    assert.equal(q.binding, "turn");
    assert.deepEqual(q.commitmentSlot, {});
    assert.equal(stateOf(q, "$state_keys.reads[0]"), "chain");
    assert.equal(stateOf(q, "nsk_app"), "node");
  });

  test("the secret-shared intakes parse as queued intakes", () => {
    for (const intake of ["shared_receipt", "shared_onchain"] as const) {
      const m = parseManifest(queuedAt(intake));
      assert.ok(isQueued(m));
      assert.equal(m.intake, intake);
      assert.ok(isSharedIntake(m.intake));
    }
    assert.ok(!isSharedIntake("onchain") && !isSharedIntake("receipt"));
    const shipped = JSON.parse(readFileSync(new URL("../../../testvectors/manifests/shared_receipt_round.json", import.meta.url), "utf8"));
    assert.equal(parseManifest(shipped).intake, "shared_receipt");
  });

  test("a structurally bad manifest is refused", () => {
    assert.throws(() => parseManifest(null), /manifest: not an object/);
    assert.throws(() => parseManifest([]), /manifest: not an object/);
    assert.throws(() => parseManifest({ ...DIRECT, manifest: 2 }), /manifest\.manifest: expected 1/);
    assert.throws(() => parseManifest({ ...DIRECT, intake: "relayed" }), /manifest\.intake: expected direct, onchain, receipt, shared_receipt, shared_onchain/);
    assert.throws(() => parseManifest({ ...DIRECT, outputs: undefined }), /manifest\.outputs: missing/);
  });

  test("a defaulted field given as null is refused, not defaulted (as the machine and the schema refuse it)", () => {
    for (const [base, f, re] of [
      [DIRECT, "intake", /manifest\.intake: expected direct, onchain, receipt, shared_receipt, shared_onchain/],
      [DIRECT, "state", /manifest\.state: not an object/],
      [DIRECT, "public_reads", /manifest\.public_reads: missing/],
      [DIRECT, "consume", /manifest\.consume: missing/],
      [QUEUED, "binding", /manifest\.binding: expected turn or exact/],
      [QUEUED, "commitment_slot", /manifest\.commitment_slot: not an object/],
    ] as const) {
      assert.throws(() => parseManifest({ ...base, [f]: null }), re, f);
    }
    assert.throws(() => parseManifest({ ...DIRECT, consume: [{ key: "$state_keys.reads[0]", policy: null }] }), /manifest\.consume\[0\]\.policy: expected once or never/);
  });

  test("`$user` is refused under every intake (the hidden requester)", () => {
    for (const intake of ["onchain", "receipt", "shared_receipt"]) {
      for (const PUBLIC of ["$user", ["$user"]]) {
        const m = { ...queuedAt(intake), witness: [...QUEUED.witness, { param: "user", from: { PUBLIC } }] };
        assert.throws(() => parseManifest(m), /manifest\.witness\[1\]\.from\.PUBLIC: `\$user` is refused under every intake/);
      }
    }
    assert.throws(() => parseManifest({ ...DIRECT, witness: [{ param: "user", from: { PUBLIC: "$user" } }] }), /`\$user` is refused/);
    parseManifest({ ...QUEUED, witness: [...QUEUED.witness, { param: "user_nonce", from: { PUBLIC: "$user_nonce" } }] });
  });

  test("a field of the other path is refused", () => {
    assert.throws(() => parseManifest({ ...QUEUED, consume: [] }), /manifest\.consume: intake direct only; this manifest takes intake onchain/);
    for (const [f, v] of [["binding", "turn"], ["commitment_slot", {}]] as const) {
      assert.throws(() => parseManifest({ ...DIRECT, [f]: v }), new RegExp(`manifest\\.${f}: a queued intake .* only`));
    }
  });

  test("a state holder the path does not allow is refused", () => {
    assert.throws(() => parseManifest({ ...DIRECT, state: { "$state_keys.writes[0]": "chain" } }), /state\.\$state_keys\.writes\[0\]: expected client or node under intake direct/);
    assert.throws(() => parseManifest({ ...QUEUED, intake: "receipt", state: { "$state_keys.writes[0]": "client" } }), /expected node or chain under intake receipt/);
    assert.throws(() => parseManifest({ ...DIRECT, state: { "$state_keys.writes[0]": "elsewhere" } }), /expected client or node/);
  });

  test("tipResultLayout counts a key missing from `state` as node-held, not chain-held", () => {
    const chain = tipResultLayout(TEST_PLAIN.circuit, queued(TEST_PLAIN.manifest));
    assert.deepEqual([chain.state, chain.records], ["chain", [0]]);
    const { "$state_keys.writes[0]": _drop, ...state } = TEST_PLAIN.manifest.state;
    const node = tipResultLayout(TEST_PLAIN.circuit, queued({ ...TEST_PLAIN.manifest, state }));
    assert.deepEqual([node.state, node.records], ["node", []]);
  });

  test("a pinned read names its freshness policy: exact by default, epoch with its epoch parameter, tolerance with a band", () => {
    const read = { contract: "0x01", function: "get_price", args: [], param: "price" };
    const parse = (r: Record<string, unknown>) => parseManifest({ ...QUEUED, public_reads: [{ ...read, ...r }] }).publicReads[0]!;
    assert.deepEqual(parse({}), { ...read, freshness: "exact" });
    assert.deepEqual(parse({ freshness: "exact" }), { ...read, freshness: "exact" });
    const epoch = parse({ freshness: "epoch", epoch_param: "price_epoch" });
    assert.deepEqual(epoch, { ...read, freshness: "epoch", epochParam: "price_epoch" });
    assert.deepEqual(publicReadParams(epoch), ["price", "price_epoch"]);
    assert.deepEqual(parse({ freshness: "tolerance", band: { absolute: "340282366920938463463374607431768211455" } }).band, {
      absolute: (1n << 128n) - 1n,
    });
    assert.deepEqual(parse({ freshness: "tolerance", band: { relative_bps: 50 } }).band, { relativeBps: 50 });
  });

  test("an unknown policy, a tolerance without a band and a field of another policy are refused, as REGISTER refuses them", () => {
    const read = { contract: "0x01", function: "get_price", args: [], param: "price" };
    const refused = (r: Record<string, unknown>, re: RegExp) =>
      assert.throws(() => parseManifest({ ...QUEUED, public_reads: [{ ...read, ...r }] }), re);
    refused({ freshness: "fresh" }, /public_reads\[0\]\.freshness: expected exact, epoch, tolerance/);
    refused({ freshness: null }, /public_reads\[0\]\.freshness: expected/);
    refused({ freshness: "tolerance" }, /public_reads\[0\]\.band: missing: a tolerance read needs a band/);
    refused({ freshness: "epoch" }, /public_reads\[0\]\.epoch_param: missing/);
    refused({ freshness: "epoch", epoch_param: "price" }, /`price` is filled by two reads/);
    refused({ epoch_param: "price_epoch" }, /epoch_param: only under freshness epoch, not exact/);
    refused({ band: { absolute: "1" } }, /band: only under freshness tolerance, not exact/);
    refused({ freshness: "epoch", epoch_param: "e", band: { absolute: "1" } }, /band: only under freshness tolerance, not epoch/);
    for (const band of [{}, { absolute: "1", relative_bps: 1 }, { percent: 1 }]) {
      refused({ freshness: "tolerance", band }, /band: expected exactly one of absolute or relative_bps/);
    }
    refused({ freshness: "tolerance", band: { absolute: 100 } }, /band\.absolute: not a decimal integer string/);
    refused({ freshness: "tolerance", band: { absolute: "0x64" } }, /band\.absolute: not a decimal integer string/);
    refused({ freshness: "tolerance", band: { absolute: (1n << 128n).toString() } }, /band\.absolute: does not fit 128 bits/);
    refused({ freshness: "tolerance", band: { absolute: "0" } }, /band\.absolute: 0 is no band/);
    for (const relative_bps of [0, 10_001, 1.5, "50"]) {
      refused({ freshness: "tolerance", band: { relative_bps } }, /band\.relative_bps: expected an integer in 1 \.\.= 10000/);
    }
  });

  test("a tree-valued key parses with its layout; the scheduler's parameters are not app inputs", () => {
    const read = (path: string) => JSON.parse(readFileSync(new URL(path, import.meta.url), "utf8"));
    const m = parseManifest(read("../../../examples/lending-tip/manifests/liquidate_shared.json"));
    assert.ok(isQueued(m));
    const loaded = m.tree["$state_keys.reads[0]"]!;
    assert.deepEqual(
      { depth: loaded.depth, leafLen: loaded.leafLen, probe: loaded.probe, header: loaded.header, index: loaded.index, count: loaded.count },
      { depth: 16, leafLen: 8, probe: 2, header: true, index: ["p1"], count: "count" },
    );
    assert.deepEqual(loaded.params, { leaves: "leaves", oldHashes: "old_hashes", siblings: "siblings", indices: "indices" });
    // declared once: the stored reference takes the loaded entry's layout
    assert.deepEqual(Object.keys(m.tree), ["$state_keys.reads[0]"]);
    assert.equal(loaded.store, "$state_keys.writes[0]");
    assert.equal(treeOf(m, "$state_keys.writes[0]"), loaded);
    assert.equal(treeOf(m, "$state_keys.writes[0]")!.newHashes, "new_hashes");
    assert.equal(treeOf(m, "$state_keys.reads[1]"), undefined);
    assert.deepEqual(treeParams(m), ["old_hashes", "siblings", "indices"]);
    // an opening deposit takes $new_leaf
    const d = parseManifest(read("../../../examples/lending-tip/manifests/deposit.json"));
    assert.ok(isQueued(d) && d.tree["$state_keys.reads[0]"]!.open === "position");
    for (const f of ["tip_tree.json", "tip_tree_init.json"]) {
      const t = parseManifest(read(`../../../machine/circuits/manifests/${f}`));
      assert.ok(isQueued(t) && Object.keys(t.tree).length > 0, f);
    }
    // no tree: an empty layout
    const q = parseManifest(QUEUED);
    assert.ok(isQueued(q));
    assert.deepEqual(q.tree, {});
  });

  test("a bad tree layout or a `$new_leaf` without an opening tree is refused", () => {
    const base = {
      ...QUEUED,
      state: { "$state_keys.reads[0]": "node", "$state_keys.writes[0]": "node" },
      witness: [
        { param: "namespace", from: { PUBLIC: "$namespace" } },
        { param: "new_leaf", from: { PUBLIC: "$new_leaf" } },
      ],
    };
    const entry = { depth: 16, leaf_len: 4, probe: 2, header: true, index: ["p"], open: "p", new_hashes: "h" };
    const refused = (tree: unknown, why: RegExp, extra: object = {}) =>
      assert.throws(() => parseManifest({ ...base, ...extra, tree: { "$state_keys.writes[0]": tree } }), why);
    assert.ok(isQueued(parseManifest({ ...base, tree: { "$state_keys.writes[0]": entry } })));
    refused({ ...entry, depth: 0 }, /depth: 0 is not in 1 \.\.= 32/);
    refused({ ...entry, depth: 33 }, /depth: 33 is not in 1 \.\.= 32/);
    refused({ ...entry, probe: 3 }, /probe: 3 is not the header plus one slot per index input \(2/);
    refused({ ...entry, open: "q" }, /open: `q` is not an index input/);
    refused({ ...entry, count: "p" }, /count: `p` is an index input/);
    refused({ ...entry, index: ["p", "p"], probe: 3 }, /index: an input is listed twice/);
    refused({ ...entry, new_hashes: undefined }, /missing: a created tree names the output/);
    refused({ ...entry, store: "$state_keys.writes[0]" }, /params and store only under the key reference that loads/);
    refused({ ...entry, depht: 16 }, /depht: not a field of a tree layout/);
    refused(entry, /a tree-valued key is node-held/, { state: { "$state_keys.writes[0]": "chain" } });
    // $new_leaf exactly when a tree opens leaves
    refused({ ...entry, open: undefined }, /`\$new_leaf` is used, and no tree opens leaves/);
    assert.throws(
      () => parseManifest({ ...base, witness: base.witness.slice(0, 1), tree: { "$state_keys.writes[0]": entry } }),
      /a tree opens leaves \(`open`\), and no parameter takes `\$new_leaf`/,
    );
    // a direct manifest takes no tree
    assert.throws(() => parseManifest({ ...DIRECT, tree: {} }), /manifest\.tree: a queued intake/);
  });

  test("a keyed map is created with one unused slot and loaded with one slot per key", () => {
    const read = (path: string) => JSON.parse(readFileSync(new URL(path, import.meta.url), "utf8"));
    const init = read("../../../examples/credits-tip/manifests/credits_init.json");
    const m = parseManifest(init);
    assert.ok(isQueued(m));
    const created = m.tree["$state_keys.writes[0]"]!;
    assert.equal(created.keyed, true);
    assert.equal(created.probe, 1);
    assert.deepEqual(created.index, []);
    const entry = init.tree["$state_keys.writes[0]"];
    assert.throws(() => parseManifest({ ...init, tree: { "$state_keys.writes[0]": { ...entry, probe: 2 } } }), /probe: 2 is not 1: a keyed map is created with one unused slot/);
    const mv = parseManifest(read("../../../examples/credits-tip/manifests/move.json"));
    assert.ok(isQueued(mv));
    const move = mv.tree["$state_keys.reads[0]"]!;
    assert.equal(move.probe, 2);
    assert.deepEqual(move.index, ["from", "to"]);
  });

  test("a window is read after the slots, its parameters the scheduler's, its width within the bound", () => {
    const read = (path: string) => JSON.parse(readFileSync(new URL(path, import.meta.url), "utf8"));
    const base = read("../../../examples/lending-tip/manifests/scan_shared.json");
    const m = parseManifest(base);
    assert.ok(isQueued(m));
    const loaded = m.tree["$state_keys.reads[0]"]!;
    assert.deepEqual(loaded.window, {
      width: 8,
      start: "start",
      params: { leaves: "window_leaves", oldHashes: "window_hashes", siblings: "window_siblings" },
    });
    assert.equal(loaded.probe, 1);
    assert.deepEqual(treeParams(m), ["old_hashes", "siblings", "indices", "window_hashes", "window_siblings"]);
    const entry = base.tree["$state_keys.reads[0]"];
    const refused = (window: unknown, why: RegExp) =>
      assert.throws(() => parseManifest({ ...base, tree: { "$state_keys.reads[0]": { ...entry, window } } }), why);
    // W + 1 and 2W are refused, as REGISTER refuses them
    for (const width of [MAX_TREE_WINDOW + 1, 2 * MAX_TREE_WINDOW, 0, 3]) {
      refused({ ...entry.window, width }, /width: .* is not a power of two in 1 \.\.= 8/);
    }
    refused({ ...entry.window, wdith: 8 }, /wdith: not a field of a tree window/);
    refused({ ...entry.window, params: { ...entry.window.params, extra: "x" } }, /extra: not a parameter of a tree window/);
    const created = { ...entry, window: entry.window };
    delete created.params;
    delete created.store;
    assert.throws(() => parseManifest({ ...base, tree: { "$state_keys.writes[0]": created } }), /window: only under the key reference that loads/);
  });

  test("a loaded tree is declared once and stored back by `store`", () => {
    const read = (path: string) => JSON.parse(readFileSync(new URL(path, import.meta.url), "utf8"));
    const base = read("../../../examples/lending-tip/manifests/borrow_shared.json");
    const loaded = base.tree["$state_keys.reads[0]"];
    const created = { ...loaded };
    delete created.params;
    delete created.store;
    const refused = (tree: unknown, why: RegExp) => assert.throws(() => parseManifest({ ...base, tree }), why);
    refused({ "$state_keys.reads[0]": { ...loaded, store: undefined } }, /names both store and new_hashes/);
    refused({ "$state_keys.reads[0]": { ...loaded, new_hashes: undefined } }, /names both store and new_hashes/);
    refused({ "$state_keys.reads[0]": { ...loaded, params: undefined } }, /params: missing/);
    refused({ "$state_keys.reads[0]": { ...loaded, store: "nsk_app" } }, /is not a \$state_keys\.writes\[j\] reference/);
    refused({ nsk_app: created }, /not a \$state_keys\.reads\[i\] or \$state_keys\.writes\[j\] reference/);
    // the stored tree declared a second time
    refused({ "$state_keys.reads[0]": loaded, "$state_keys.writes[0]": created }, /declared twice; declare it once/);
    // a loaded tree not stored back beside a created one
    refused(
      { "$state_keys.reads[0]": { ...loaded, store: undefined, new_hashes: undefined }, "$state_keys.writes[0]": created },
      /stores each tree it loads \(`store`\) and creates none/,
    );
    // a read-only tree: loaded, not stored back
    const view = parseManifest({ ...base, tree: { "$state_keys.reads[0]": { ...loaded, store: undefined, new_hashes: undefined } } });
    assert.ok(isQueued(view) && treeOf(view, "$state_keys.writes[0]") === undefined);
  });
});

// The reader of an oblivious tree (docs/ARCHITECTURE.md section 6, "The
// oblivious tree") and of a keyed map (docs/ARCHITECTURE.md section 6, "The
// keyed map's manifest entry and REGISTER"), on the shipped manifests and
// against REGISTER's refusals (sidecar-core manifest/tree.rs validate_oblivious
// and validate_keyed).
describe("the oblivious and keyed tree readers", () => {
  const read = (path: string) => JSON.parse(readFileSync(new URL(path, import.meta.url), "utf8"));
  const LENDING = "../../../examples/lending-tip/manifests/";
  const CREDITS = "../../../examples/credits-tip/manifests/";

  test("every oblivious lending manifest and every credits manifest parses with its layout", () => {
    for (const round of ["deposit", "supply", "borrow", "withdraw", "repay", "withdraw_supply", "view", "liquidate", "quote", "scan"]) {
      const m = parseManifest(read(`${LENDING}${round}_oblivious.json`));
      assert.ok(isQueued(m), round);
      const t = m.tree["$state_keys.reads[0]"]!;
      assert.equal(t.access, "oblivious", round);
      assert.equal(t.keyed, false, round);
      assert.equal(t.depth, 16, round);
      assert.equal(t.params!.indices, undefined, `${round}: an oblivious tree places no indices`);
      assert.equal(t.newHashes, undefined, `${round}: no leaf hash is output`);
      assert.equal(t.store, "$state_keys.writes[0]", round);
      assert.equal(treeOf(m, "$state_keys.writes[0]"), t, round);
      assert.deepEqual(treeParams(m), [], `${round}: the slots are LOAD slices, not names the scheduler fills`);
    }
    const deposit = parseManifest(read(`${LENDING}deposit_oblivious.json`));
    assert.ok(isQueued(deposit));
    const opening = deposit.tree["$state_keys.reads[0]"]!;
    assert.equal(opening.open, "opens");
    assert.ok(!opening.index.includes("opens"), "the opening flag is a public input of its own");
    assert.equal(opening.nextIndex, "app_values[1]");

    const init = parseManifest(read(`${LENDING}lending_init_oblivious.json`));
    assert.ok(isQueued(init));
    const created = init.tree["$state_keys.writes[0]"]!;
    assert.deepEqual([created.access, created.header, created.params, created.newHashes, created.nextIndex], ["oblivious", true, undefined, undefined, undefined]);

    for (const round of ["pay", "claim", "view", "move"]) {
      const m = parseManifest(read(`${CREDITS}${round}.json`));
      assert.ok(isQueued(m), round);
      const t = m.tree["$state_keys.reads[0]"]!;
      assert.deepEqual([t.access, t.keyed, t.depth, t.leafLen, t.header], ["oblivious", true, 64, 3, false], round);
      assert.equal(t.capacity, undefined, `${round}: the default capacity`);
      assert.deepEqual([t.open, t.nextIndex, t.window, t.params!.indices], [undefined, undefined, undefined, undefined], round);
      assert.equal(t.index.length, round === "move" ? 2 : 1, round);
      assert.deepEqual(treeParams(m), [], round);
    }
    // the created map: one unused slot, no key input
    const credits = parseManifest(read(`${CREDITS}credits_init.json`));
    assert.ok(isQueued(credits));
    const map = credits.tree["$state_keys.writes[0]"]!;
    assert.deepEqual([map.keyed, map.probe, map.index], [true, 1, []]);
    const wide = { ...read(`${CREDITS}credits_init.json`) };
    wide.tree = { "$state_keys.writes[0]": { ...wide.tree["$state_keys.writes[0]"], probe: 2 } };
    assert.throws(() => parseManifest(wide), /probe: 2 is not 1: a keyed map is created with one unused slot/);
  });

  test("an oblivious tree's refusals", () => {
    const base = read(`${LENDING}deposit_oblivious.json`);
    const loaded = base.tree["$state_keys.reads[0]"];
    const refused = (tree: unknown, why: RegExp) => assert.throws(() => parseManifest({ ...base, tree: { "$state_keys.reads[0]": tree } }), why);
    refused({ ...loaded, access: "hidden" }, /access: not clear or oblivious/);
    refused({ ...loaded, params: { ...loaded.params, indices: "indices" } }, /params\.indices: an oblivious tree places no indices/);
    refused({ ...loaded, new_hashes: "new_hashes" }, /new_hashes: an oblivious tree outputs no leaf hashes/);
    refused({ ...loaded, store: undefined }, /store: missing: a round on an oblivious tree stores it back/);
    refused({ ...loaded, open: "position" }, /open: `position` is an index input; an oblivious tree's opening flag is a public input of its own/);
    refused({ ...loaded, capacity: 20 }, /capacity: only a keyed map has a capacity/);
    // next_index belongs to an oblivious tree only
    const clear = read(`${LENDING}deposit.json`);
    const clearTree = clear.tree["$state_keys.reads[0]"];
    assert.throws(() => parseManifest({ ...clear, tree: { "$state_keys.reads[0]": { ...clearTree, next_index: "next" } } }), /next_index: only under access: oblivious/);
  });

  test("a keyed map's refusals", () => {
    const base = read(`${CREDITS}pay.json`);
    const loaded = base.tree["$state_keys.reads[0]"];
    const refused = (tree: unknown, why: RegExp) => assert.throws(() => parseManifest({ ...base, tree: { "$state_keys.reads[0]": tree } }), why);
    const grown = parseManifest({ ...base, tree: { "$state_keys.reads[0]": { ...loaded, capacity: 20 } } });
    assert.ok(isQueued(grown));
    assert.equal(grown.tree["$state_keys.reads[0]"]!.capacity, 20);
    refused({ ...loaded, keyed: "yes" }, /keyed: not a boolean/);
    refused({ ...loaded, depth: 16 }, /depth: 16 is not in 32 \.\.= 120 \(a keyed map\)/);
    refused({ ...loaded, depth: 121 }, /depth: 121 is not in 32 \.\.= 120/);
    refused({ ...loaded, leaf_len: 2 }, /a keyed map's leaf holds the key, a value and the blinding: at least 3 elements/);
    refused({ ...loaded, access: undefined }, /keyed: a keyed map is access: oblivious/);
    refused({ ...loaded, header: true, probe: 2 }, /header: a keyed map has no header/);
    refused({ ...loaded, next_index: "next" }, /a keyed map has no open, next_index or window/);
    refused({ ...loaded, open: "opens" }, /a keyed map has no open, next_index or window/);
  });
});

// The outcome form: `outcome` only under a queued intake, `partial` by
// default, `none` written out under a non-secret-shared intake only, and a
// non-secret-shared round under `partial` fills a parameter with PUBLIC
// `$partial_note`, as REGISTER refuses them (sidecar-core manifest.rs
// validate_outcome, validate_partial).
describe("the outcome form", () => {
  const SHARED = queuedAt("shared_receipt");
  const PARTIAL = { param: "partial_note", from: { PUBLIC: "$partial_note" } };
  const COMPLETED = { ...QUEUED, outcome: undefined, witness: [...QUEUED.witness, PARTIAL] };

  test("every queued intake takes the partial form by default; a non-secret-shared one takes none when it says so", () => {
    for (const m of [parseManifest({ ...SHARED, outcome: undefined }), parseManifest(SHARED)]) {
      assert.ok(isQueued(m));
      assert.equal(m.outcome, "partial");
      assert.ok(!Object.hasOwn(m, "callValues"));
    }
    for (const intake of ["onchain", "receipt"]) {
      const completed = parseManifest({ ...COMPLETED, intake });
      assert.ok(isQueued(completed));
      assert.equal(completed.outcome, "partial");
      const none = parseManifest({ ...QUEUED, intake });
      assert.ok(isQueued(none));
      assert.equal(none.outcome, "none");
    }
  });

  test("none under a secret-shared intake, claim, call and an outcome on direct are refused", () => {
    for (const intake of ["onchain", "receipt"]) {
      for (const outcome of ["claim", "call", "push", null]) {
        assert.throws(() => parseManifest({ ...COMPLETED, intake, outcome }), new RegExp(`manifest\\.outcome: expected partial or none under intake ${intake}`));
      }
    }
    for (const intake of ["shared_receipt", "shared_onchain"]) {
      for (const outcome of ["none", "claim", "call"]) {
        assert.throws(() => parseManifest({ ...queuedAt(intake), outcome }), new RegExp(`manifest\\.outcome: expected partial under intake ${intake}`));
      }
    }
    assert.throws(() => parseManifest({ ...DIRECT, outcome: "partial" }), /manifest\.outcome: only with a queued intake; this manifest takes intake direct/);
  });

  test("call_values is not a manifest field", () => {
    for (const m of [SHARED, QUEUED, COMPLETED]) {
      assert.throws(() => parseManifest({ ...m, call_values: ["a"] }), /manifest\.call_values: not a manifest field/);
    }
  });

  test("a non-secret-shared round under partial takes PUBLIC $partial_note; under none no partial note", () => {
    for (const intake of ["onchain", "receipt"]) {
      assert.throws(() => parseManifest({ ...QUEUED, intake, outcome: "partial" }), new RegExp(`manifest\\.witness: intake ${intake}: no parameter takes PUBLIC \`\\$partial_note\``));
      assert.throws(() => parseManifest({ ...QUEUED, intake, outcome: undefined }), /no parameter takes PUBLIC `\$partial_note` \(`outcome: partial`, the default/);
      const from = { PUBLIC: "$partial_note" };
      assert.throws(() => parseManifest({ ...QUEUED, intake, witness: [...QUEUED.witness, { param: "p", from }] }), /manifest\.witness\[1\]: a partial note belongs to `outcome: partial`; this manifest takes `outcome: none`/);
    }
    // a PUBLIC list may carry it
    assert.equal(parseManifest({ ...COMPLETED, witness: [...QUEUED.witness, { param: "inputs", from: { PUBLIC: ["amount", "$partial_note"] } }] }).intake, "onchain");
  });
});
