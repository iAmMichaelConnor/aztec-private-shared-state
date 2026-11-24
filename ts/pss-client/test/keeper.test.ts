// The keeper's loop (src/keeper.ts): its shape from the lending example's
// scan_shared and liquidate_shared manifests as committed (its scan and act
// rounds), a scan outcome read as its report, the reported indices and the
// act rounds a report gives, and whole passes over a tree model whose scans
// report as the round does (bit j for leaf start + j, index 0 counting for
// neither, occupied the window's opened leaves): it advances by W, acts on
// each window's indices before the next scan, and stops at the occupancy
// frontier, at the tree's last window, or at a failed scan.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { describe, test } from "node:test";

import {
  actRounds,
  isQueued,
  isWindowStart,
  keeperPass,
  keeperShape,
  parseManifest,
  ProtocolError,
  reportedIndices,
  scanReport,
  windowFull,
  type KeeperShape,
  type QueuedManifest,
  type ScanLayout,
  type ScanReport,
} from "../src/internal.ts";

const lending = (name: string): QueuedManifest => {
  const m = parseManifest(JSON.parse(readFileSync(new URL(`../../../examples/lending-tip/manifests/${name}.json`, import.meta.url), "utf8")));
  assert.ok(isQueued(m));
  return m;
};

// an act round of three slots (K = 3: two indices), the loop's general case
const SHAPE: KeeperShape = { width: 8, depth: 16, start: "start", indexInputs: ["p1", "p2"], count: "count" };
// lending's: K = 2, one index per liquidate round
const LENDING_SHAPE: KeeperShape = { ...SHAPE, indexInputs: ["p1"] };
// lending's scan outcome [code, 0, report, 0, start, 0, occupied]
const LENDING_SCAN: ScanLayout = { fields: 7, code: 0, report: 2, start: 4, occupied: 6, zero: [1, 3, 5] };

/** A tree of `opened` leaves 1 ..= opened, the `flagged` ones reported,
 * scanned as the round scans it. */
function book(opened: number, flagged: number[], width = 8) {
  return (start: number): ScanReport => {
    let report = 0n;
    let occupied = 0;
    for (let j = 0; j < width; j++) {
      const i = start + j;
      if (i === 0 || i > opened) continue;
      occupied++;
      if (flagged.includes(i)) report |= 1n << BigInt(j);
    }
    return { ok: true, code: 0, start, report, occupied };
  };
}

/** A pass over `scan` recording the order of scans and act rounds. */
async function pass(scan: (start: number) => ScanReport, shape = SHAPE, from?: number) {
  const log: string[] = [];
  const result = await keeperPass({
    shape,
    from,
    scan: async (start) => {
      log.push(`scan ${start}`);
      return scan(start);
    },
    act: async (round) => {
      log.push(`act ${round.indices.join(" ")}`);
    },
  });
  return { result, log };
}

describe("the keeper's loop", () => {
  test("its shape from lending's scan_shared and liquidate_shared manifests", () => {
    assert.deepEqual(keeperShape(lending("scan_shared"), lending("liquidate_shared")), LENDING_SHAPE);
    assert.deepEqual(actRounds([3, 7], LENDING_SHAPE), [
      { indices: [3], inputs: { p1: 3, count: 1 } },
      { indices: [7], inputs: { p1: 7, count: 1 } },
    ]);
    assert.throws(() => keeperShape(lending("liquidate_shared"), lending("liquidate_shared")), /has no window/);
    assert.throws(() => keeperShape(lending("scan_shared"), lending("lending_init")), /loads 0 trees/);
  });

  test("a scan outcome as its report", () => {
    // lending's [code, 0, report, 0, start, 0, occupied]
    assert.deepEqual(scanReport([0, 0, 0b101, 0, 8, 0, 8], LENDING_SCAN), { ok: true, code: 0, start: 8, report: 0b101n, occupied: 8 });
    assert.deepEqual(scanReport(["0x6", "0x0", "0x0", "0x0", "0x0", "0x0", "0x0"], LENDING_SCAN), { ok: false, code: 6, start: 0, report: 0n, occupied: 0 });
    assert.throws(() => scanReport([0, 0, 8, 0, 8, 0], LENDING_SCAN), ProtocolError);
    // a scan's note names no position and pays nothing: position, x and payout are 0
    assert.throws(() => scanReport([0, 8, 0b101, 0, 8, 0, 8], LENDING_SCAN), ProtocolError);
    assert.throws(() => scanReport([0, 0, 0b101, 3, 8, 0, 8], LENDING_SCAN), ProtocolError);
    assert.throws(() => scanReport([0, 0, 0b101, 0, 8, 1, 8], LENDING_SCAN), ProtocolError);
    // another app's layout: [start, occupied, report, code], no zero fields
    const other: ScanLayout = { fields: 4, code: 3, report: 2, start: 0, occupied: 1 };
    assert.deepEqual(scanReport([16, 5, 0b11, 0], other), { ok: true, code: 0, start: 16, report: 0b11n, occupied: 5 });
    // a layout naming a field past the outcome is the caller's error
    assert.throws(() => scanReport([0, 0, 0], { ...other, fields: 3 }), RangeError);
  });

  test("a window's start is a multiple of W below 2^D", () => {
    for (const s of [0, 8, 65528]) assert.ok(isWindowStart(s, 8, 16), `${s}`);
    for (const s of [4, 65536, -8, 8.5]) assert.ok(!isWindowStart(s, 8, 16), `${s}`);
  });

  test("the reported indices: bit j is leaf start + j", () => {
    const r = (start: number, report: bigint, occupied = 8): ScanReport => ({ ok: true, code: 0, start, report, occupied });
    assert.deepEqual(reportedIndices(r(8, 0b10100101n), 8), [8, 10, 13, 15]);
    assert.deepEqual(reportedIndices(r(0, 0b10n, 7), 8), [1]);
    assert.deepEqual(reportedIndices({ ...r(8, 0n), ok: false, code: 4 }, 8), []);
    assert.throws(() => reportedIndices(r(8, 1n << 8n), 8), /past the window/);
    assert.throws(() => reportedIndices(r(0, 1n, 7), 8), /index 0/);
    assert.throws(() => reportedIndices(r(8, 0n, 9), 8), /occupied/);
  });

  test("a window is full at W occupied, window 0 at W - 1", () => {
    const r = (start: number, occupied: number): ScanReport => ({ ok: true, code: 0, start, report: 0n, occupied });
    assert.ok(windowFull(r(0, 7), 8));
    assert.ok(!windowFull(r(0, 6), 8));
    assert.ok(windowFull(r(8, 8), 8));
    assert.ok(!windowFull(r(8, 7), 8));
  });

  test("act rounds of K - 1 indices, the last one's count the number used", () => {
    assert.deepEqual(actRounds([1, 2, 5], SHAPE), [
      { indices: [1, 2], inputs: { p1: 1, p2: 2, count: 2 } },
      { indices: [5], inputs: { p1: 5, p2: 0, count: 1 } },
    ]);
    assert.deepEqual(actRounds([], SHAPE), []);
    const noCount = { indexInputs: ["p1", "p2"] };
    assert.deepEqual(actRounds([3, 4], noCount), [{ indices: [3, 4], inputs: { p1: 3, p2: 4 } }]);
    assert.throws(() => actRounds([3], noCount), /no count input/);
  });

  test("a pass advances by W, acts on each window before the next scan and stops at the frontier", async () => {
    const { result, log } = await pass(book(20, [3, 7, 8, 17, 20]));
    assert.deepEqual(log, ["scan 0", "act 3 7", "scan 8", "act 8", "scan 16", "act 17 20"]);
    assert.deepEqual(result.scanned, [0, 8, 16]);
    assert.deepEqual(result.reported, [3, 7, 8, 17, 20]);
    assert.deepEqual(
      result.acts.map((round) => round.inputs),
      [{ p1: 3, p2: 7, count: 2 }, { p1: 8, p2: 0, count: 1 }, { p1: 17, p2: 20, count: 2 }],
    );
    assert.equal(result.stop, "frontier");
  });

  test("a tree that ends at a window's edge: the next window is empty, the frontier", async () => {
    const { result } = await pass(book(15, [15]));
    assert.deepEqual(result.scanned, [0, 8, 16]);
    assert.deepEqual(result.reported, [15]);
    assert.equal(result.stop, "frontier");
  });

  test("a small tree: one window", async () => {
    const { result, log } = await pass(book(2, [1]));
    assert.deepEqual(log, ["scan 0", "act 1"]);
    assert.equal(result.stop, "frontier");
  });

  test("a pass from a later window", async () => {
    const { result } = await pass(book(20, [3, 17]), SHAPE, 16);
    assert.deepEqual(result.scanned, [16]);
    assert.deepEqual(result.reported, [17]);
    await assert.rejects(pass(book(20, []), SHAPE, 4), RangeError);
  });

  test("a full tree: the pass ends at its last window", async () => {
    const shape = { ...SHAPE, width: 4, depth: 3 };
    const { result } = await pass(book(7, [5], 4), shape);
    assert.deepEqual(result.scanned, [0, 4]);
    assert.deepEqual(result.reported, [5]);
    assert.equal(result.stop, "end");
  });

  test("a failed scan stops the pass with its code", async () => {
    const scan = (start: number): ScanReport => (start === 8 ? { ok: false, code: 6, start: 0, report: 0n, occupied: 0 } : book(30, [2])(start));
    const { result, log } = await pass(scan);
    assert.deepEqual(log, ["scan 0", "act 2", "scan 8"]);
    assert.equal(result.stop, "failed");
    assert.equal(result.code, 6);
  });

  test("a report of another window is refused", async () => {
    await assert.rejects(
      pass((start) => ({ ...book(30, [])(start), start: start + 8 })),
      ProtocolError,
    );
  });

  test("an aborted pass stops before its next scan", async () => {
    const ac = new AbortController();
    let scans = 0;
    await assert.rejects(
      keeperPass({
        shape: SHAPE,
        signal: ac.signal,
        scan: async (start) => {
          scans++;
          ac.abort();
          return book(30, [])(start);
        },
        act: async () => {},
      }),
      { name: "AbortError" },
    );
    assert.equal(scans, 1);
  });
});
