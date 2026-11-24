// The keeper's loop over a tree-valued key (docs/ARCHITECTURE.md section 6,
// "A read-only window on a tree key"): a scan round reads the window of W
// leaves from `start` and reports, by the app's own predicate, which of them
// it names (bit j of `report` is leaf start + j) and how many are occupied;
// an act round then acts on the indices a report names, K - 1 per round.
// keeperPass sweeps the tree once: it scans from `from` (default 0),
// advancing start by W, hands each window's reported indices to the act
// round as they arrive, and stops at the occupancy frontier. Leaves are
// appended and never reclaimed, so the occupied indices are a prefix and the
// first window that is not full ends the tree (index 0, the header, counts
// as unoccupied, so window 0 is full at W - 1).
//
// keeperShape reads W, D, the start input and the act round's index and
// count inputs from the two rounds' manifests (their `tree` entries), and
// scanReport reads a scan's outcome at the field positions the app gives
// (ScanLayout), so the loop knows no app by name. The rounds themselves go
// through the caller's `scan` and `act` (a secret-shared receipt intake
// request each, whose outcome the keeper opens; tip-client.ts and
// outcome.ts). Lending is the worked example: its scan round reports
// unhealthy positions and its liquidate round is the act round.

import { ProtocolError } from "./errors.ts";
import { fieldBigInt, type FieldLike } from "./field.ts";
import type { QueuedManifest, TreeLayout } from "./manifest.ts";

/** A scan's report, read from its outcome (scanReport): the code (ok when
 * 0), the window's start, the report and the occupied count; report, start
 * and occupied are 0 when not ok. */
export interface ScanReport {
  ok: boolean;
  code: number;
  start: number;
  /** Bit j: leaf start + j is reported (by the app's predicate; lending's:
   * unhealthy at the round's pinned price). */
  report: bigint;
  /** The window's occupied leaves (index 0 never counts). */
  occupied: number;
}

/** Where a scan round's outcome holds its report: the outcome's field count
 * and the field index of each part, which the app's scan round fixes (its
 * outcome note's fields). `zero` lists the fields a scan leaves 0, e.g. those
 * that would name a leaf or a payout, so a scan's note confers nothing;
 * scanReport refuses an outcome where one is not. Lending's scan outcome
 * `[code, 0, report, 0, start, 0, occupied]` is
 * `{fields: 7, code: 0, report: 2, start: 4, occupied: 6, zero: [1, 3, 5]}`. */
export interface ScanLayout {
  fields: number;
  code: number;
  report: number;
  start: number;
  occupied: number;
  zero?: readonly number[];
}

/** What the loop needs from the two rounds' manifests. */
export interface KeeperShape {
  /** W, the scan round's window width. */
  width: number;
  /** D, the tree's depth: starts are below 2^D. */
  depth: number;
  /** The scan round's app input that names the window's first leaf. */
  start: string;
  /** The act round's index inputs, in slot order (K - 1 of them). */
  indexInputs: string[];
  /** The act round's input that says how many index inputs are used;
   * undefined when the round always uses all of them. */
  count?: string;
}

/** One act round's app inputs: the indices it names (unused index inputs
 * 0) and, when the round has one, its count. The round's other inputs are
 * the caller's to add (e.g. lending's `budget`, the most the liquidator
 * repays, which its request escrows). */
export interface ActRound {
  indices: number[];
  inputs: Record<string, number>;
}

/** The loaded tree entry of a round's manifest (its `params` form). */
function loadedTree(m: QueuedManifest, what: string): TreeLayout {
  const loaded = Object.values(m.tree).filter((t) => t.params !== undefined);
  if (loaded.length !== 1) throw new RangeError(`${what} (${m.circuit}): loads ${loaded.length} trees, not the one tree`);
  return loaded[0]!;
}

/** The loop's shape from the scan round's manifest (its tree entry's
 * `window`) and the act round's (its tree entry's `index` and `count`
 * inputs), which must read a tree of the same depth. */
export function keeperShape(scan: QueuedManifest, act: QueuedManifest): KeeperShape {
  const tree = loadedTree(scan, "the scan round");
  if (tree.window === undefined) throw new RangeError(`the scan round (${scan.circuit}): its tree entry has no window`);
  const probes = loadedTree(act, "the act round");
  if (probes.depth !== tree.depth) throw new RangeError(`the act round (${act.circuit}) reads a tree of depth ${probes.depth}, the scan round ${tree.depth}`);
  if (probes.index.length === 0) throw new RangeError(`the act round (${act.circuit}): its tree entry names no index inputs`);
  return { width: tree.window.width, depth: tree.depth, start: tree.window.start, indexInputs: [...probes.index], count: probes.count };
}

const small = (x: FieldLike, what: string): number => {
  const v = fieldBigInt(x, what);
  if (v > BigInt(Number.MAX_SAFE_INTEGER)) throw new ProtocolError(`${what}: ${v} is not a small integer`);
  return Number(v);
};

/** A scan's opened outcome plaintext as its report, read at the app's
 * field positions `layout`. */
export function scanReport(plaintext: readonly FieldLike[], layout: ScanLayout): ScanReport {
  if (plaintext.length !== layout.fields) throw new ProtocolError(`a scan outcome has ${layout.fields} fields, not ${plaintext.length}`);
  const at = (k: number): FieldLike => {
    const v = plaintext[k];
    if (v === undefined) throw new RangeError(`the scan layout names field ${k} of ${layout.fields}`);
    return v;
  };
  const code = small(at(layout.code), "code");
  for (const k of layout.zero ?? []) {
    if (fieldBigInt(at(k), "field") !== 0n) throw new ProtocolError(`a scan outcome's field ${k} is not 0: a scan names no leaf and pays nothing`);
  }
  return {
    ok: code === 0,
    code,
    start: small(at(layout.start), "start"),
    report: fieldBigInt(at(layout.report), "report"),
    occupied: small(at(layout.occupied), "occupied"),
  };
}

/** Whether `start` is a window's: below 2^depth and a multiple of width.
 * A scan from any other start reads window 0 and reports code 3. */
export function isWindowStart(start: number, width: number, depth: number): boolean {
  return Number.isSafeInteger(start) && start >= 0 && start < 2 ** depth && start % width === 0;
}

/** The indices an ok report names, in index order. Refuses a report with a
 * bit past the window, on index 0, or more occupied leaves than the window
 * holds. */
export function reportedIndices(r: ScanReport, width: number): number[] {
  if (!r.ok) return [];
  if (r.report >> BigInt(width) !== 0n) throw new ProtocolError(`scan at ${r.start}: report ${r.report} has a bit past the window of ${width}`);
  if (r.start === 0 && (r.report & 1n) === 1n) throw new ProtocolError("scan at 0: the report names index 0, the header");
  if (r.occupied > width) throw new ProtocolError(`scan at ${r.start}: ${r.occupied} occupied leaves in a window of ${width}`);
  const out: number[] = [];
  for (let j = 0; j < width; j++) if ((r.report >> BigInt(j)) & 1n) out.push(r.start + j);
  return out;
}

/** Whether an ok report's window is full, so the tree may go on past it:
 * W occupied leaves, W - 1 in window 0 (the header is not counted). */
export function windowFull(r: ScanReport, width: number): boolean {
  return r.occupied === width - (r.start === 0 ? 1 : 0);
}

/** The act rounds for `indices`: K - 1 per round in the order given, the
 * last one's unused index inputs 0 and its count the number used. A round
 * without a count input takes only full batches, so it refuses a
 * remainder. */
export function actRounds(indices: readonly number[], shape: Pick<KeeperShape, "indexInputs" | "count">): ActRound[] {
  const per = shape.indexInputs.length;
  const out: ActRound[] = [];
  for (let at = 0; at < indices.length; at += per) {
    const batch = indices.slice(at, at + per);
    if (batch.length < per && shape.count === undefined) {
      throw new RangeError(`the act round has no count input: ${batch.length} indices left for ${per} index inputs`);
    }
    const inputs: Record<string, number> = Object.fromEntries(shape.indexInputs.map((name, k) => [name, batch[k] ?? 0]));
    if (shape.count !== undefined) inputs[shape.count] = batch.length;
    out.push({ indices: batch, inputs });
  }
  return out;
}

export interface KeeperPassOptions {
  shape: KeeperShape;
  /** The first window's start (default 0), a window's start. */
  from?: number;
  /** Requests a scan of the window at `start` and resolves to its opened
   * outcome (scanReport of the outcome plaintext at the app's ScanLayout). */
  scan(start: number): Promise<ScanReport>;
  /** Requests one act round; called for each round of a window's reported
   * indices before the next scan is requested. */
  act(round: ActRound): Promise<void>;
  signal?: AbortSignal;
}

/** One pass: the windows scanned, the indices reported and the act rounds
 * requested, and why it stopped: `frontier` (a window that is not full: the
 * tree ends inside it), `end` (the last window of the
 * tree), or `failed` (a scan reported `code`; the loop stops there, so a
 * transient failure such as a missing price is retried by the next pass). */
export interface KeeperPass {
  scanned: number[];
  reported: number[];
  acts: ActRound[];
  stop: "frontier" | "end" | "failed";
  /** The failed scan's code (stop `failed`). */
  code?: number;
}

/** Sweep the tree once from `from`, advancing start by W, acting on each
 * window's reported indices, and stopping at the occupancy frontier. */
export async function keeperPass(o: KeeperPassOptions): Promise<KeeperPass> {
  const { width, depth } = o.shape;
  let start = o.from ?? 0;
  if (!isWindowStart(start, width, depth)) throw new RangeError(`from: ${start} is not a window's start (a multiple of ${width} below 2^${depth})`);
  const pass: KeeperPass = { scanned: [], reported: [], acts: [], stop: "end" };
  for (;;) {
    o.signal?.throwIfAborted();
    const r = await o.scan(start);
    pass.scanned.push(start);
    if (!r.ok) return { ...pass, stop: "failed", code: r.code };
    if (r.start !== start) throw new ProtocolError(`the scan of window ${start} reports window ${r.start}`);
    const found = reportedIndices(r, width);
    pass.reported.push(...found);
    for (const round of actRounds(found, o.shape)) {
      o.signal?.throwIfAborted();
      await o.act(round);
      pass.acts.push(round);
    }
    if (!windowFull(r, width)) return { ...pass, stop: "frontier" };
    start += width;
    if (start >= 2 ** depth) return pass;
  }
}
