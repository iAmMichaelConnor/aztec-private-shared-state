// The tip's result transaction on the client side (docs/ARCHITECTURE.md
// section 6, rows "result" and "relayer"): from a checked answer of FETCH by
// chain request id to the arguments of an app's private `process_result`,
// shared by the operator's relayer (pss-relayer) and a user who submits a
// result themselves (lander.ts submitResult). The parts are read and bound
// by proved.ts, the one reader of every form's proved public inputs.
//
// The Noir side is noir/pss_public_contract/src/result.nr
// (TipResult, PartialResult, check_round, proved_public_inputs: one layout
// for both non-secret-shared intakes); the node side is machine/sidecar-tip (synth.rs
// old_commitments_of). The return value, mirrored here:
//
//   [request_id, old_commitments[R], new_commitments[W], npk_app_hash, ok, app_outputs[A]]
//
// and under partial-note delivery (`outcome: partial`, pss_public_contract's
// PartialResult) the request's partial note right after `ok`:
//
//   [request_id, old_commitments[R], new_commitments[W], npk_app_hash, ok, partial_note, app_outputs[A]]
//
// The old commitments are the manifest's `commitment_slot` olds in key order
// ($state_keys.reads[i] by i, then $state_keys.writes[j] by j, then fixed keys), the
// pinned values those of the manifest's `public_reads` in order (each read's
// value, then an epoch read's epoch), the new
// commitments the outputs' note hashes in manifest order, each read from the
// public inputs at the index the circuit's ABI gives it. What the result
// carries beyond them depends on the state holder (state.ts), resolved from
// the manifest once, in tipResultLayout; nothing depends on the non-secret-shared intake
// that queued the request.

import type { Fr } from "@aztec-labs/aztec.js/fields";

import { abiOf, outputNoteHashIndices, publicLayout } from "./abi.ts";
import { RESERVED_NAMES } from "./bricks.ts";
import { ProtocolError } from "./errors.ts";
import { fieldFr, type FieldHexString, type FieldLike } from "./field.ts";
import { publicReadParams, type QueuedManifest } from "./manifest.ts";
import { ProvedInputs, signatureLimbs, type ProvedLayout, type ProvedParts } from "./proved.ts";
import type { ResultForm } from "./result.ts";
import { stateModule, tipStateOf } from "./state.ts";
import type { ExecuteResponse } from "./wire.ts";

// ---- the layout of a tip circuit's public inputs ----

// sidecar-core's KeyRef order: $state_keys.reads[i] by i, then $state_keys.writes[j] by
// j, then fixed keys by name.
function keyOrder(key: string): [number, number, string] {
  const r = /^\$state_keys\.reads\[(\d+)\]$/.exec(key);
  if (r) return [0, Number(r[1]), ""];
  const w = /^\$state_keys\.writes\[(\d+)\]$/.exec(key);
  if (w) return [1, Number(w[1]), ""];
  return [2, 0, key];
}

function compareKeys(a: string, b: string): number {
  const [ka, ia, sa] = keyOrder(a);
  const [kb, ib, sb] = keyOrder(b);
  return ka - kb || ia - ib || (sa < sb ? -1 : sa > sb ? 1 : 0);
}

/** Where each part of a tip round's result sits in its public inputs, read
 * once from the circuit's ABI and manifest: the parts every form binds
 * (ProvedLayout), then the non-secret-shared layout's own. */
export interface TipResultLayout extends ProvedLayout {
  npkAppHash: number;
  ok: number;
  /** Under `outcome: partial`: the request's partial note, the output right
   * after `ok`, which the app's `apply` completes in public. */
  partialNote?: number;
  /** The app outputs, in return order. */
  appOutputs: number[];
}

// The result layout the client expects. A tip circuit's return value must be
// pss_public_contract's order, `[request_id, old_commitments[R],
// new_commitments[W], npk_app_hash, ok, app_outputs[A]]`, with the
// manifest's commitment_slot olds and output note hashes naming exactly
// those positions; tipResultLayout refuses (RangeError) anything else, at
// configuration time. It is the order proved_public_inputs rebuilds, so a
// circuit with another order cannot verify in process_result and is better
// refused before a round is paid for.
/** The layout of a tip circuit's result, from its nargo output JSON (or its
 * `abi`), as sent to REGISTER, and its parsed manifest. RangeError when the
 * circuit does not follow the library's return order. */
export function tipResultLayout(circuit: unknown, m: QueuedManifest): TipResultLayout {
  const abi = abiOf(circuit);
  const name = m.circuit;
  const state = tipStateOf(m);

  const { params, publicFields, returnLeaves, returnPublic } = publicLayout(abi);
  if (!returnPublic) throw new RangeError("the return value is not public");
  const paths = returnLeaves.map((l) => l.path);
  const indexOf = (path: string, what: string): number => {
    const i = paths.indexOf(path);
    if (i < 0) throw new RangeError(`${what}: \`${path}\` is not one element of the circuit's return value`);
    return publicFields + i;
  };

  const slotKeys = Object.keys(m.commitmentSlot).sort(compareKeys);
  const oldCommitments = slotKeys.map((k) => indexOf(m.commitmentSlot[k]!.old, `manifest.commitment_slot.${k}.old`));
  const newCommitments = outputNoteHashIndices(abi, m.outputs);
  const R = oldCommitments.length;
  const W = newCommitments.length;
  // the proved chain request id first, then the commitments
  const requestId = publicFields;
  const at = publicFields + 1;
  const expect = (got: number[], from: number, what: string) => {
    got.forEach((g, k) => {
      if (g !== from + k) {
        throw new RangeError(
          `${name}: ${what}[${k}] is public input ${g}; pss_public_contract's layout puts it at ${from + k} ` +
            "(return value: request_id, old commitments, new commitments, npk_app_hash, ok, app outputs)",
        );
      }
    });
  };
  expect(oldCommitments, at, "old commitment");
  expect(newCommitments, at + R, "new commitment");
  const npkAppHash = at + R + W;
  const ok = npkAppHash + 1;
  const end = publicFields + paths.length;
  if (ok >= end) throw new RangeError(`${name}: the return value has no npk_app_hash and ok after the commitments`);
  // under partial-note delivery the request's partial note comes right
  // after ok (REGISTER requires the output named `partial_note` there)
  let partialNote: number | undefined;
  if (m.outcome === "partial") {
    if (paths[ok + 1 - publicFields] !== "partial_note") {
      throw new RangeError(`${name}: under \`outcome: partial\` the return value has \`partial_note\` right after ok`);
    }
    partialNote = ok + 1;
  }
  const appOutputs: number[] = [];
  for (let i = partialNote === undefined ? ok + 1 : ok + 2; i < end; i++) appOutputs.push(i);

  // each read's value, then an epoch read's epoch, as the circuit's next
  // public input
  const reads = m.publicReads.flatMap((read, q) =>
    publicReadParams(read).map((param, k) => {
      const field = k === 0 ? "param" : "epoch_param";
      const p = params.get(param);
      if (p === undefined) throw new RangeError(`manifest.public_reads[${q}].${field}: not a public parameter of ${name}`);
      if (p.width !== 1) throw new RangeError(`manifest.public_reads[${q}].${field}: \`${param}\` is not one field`);
      return p.index;
    }),
  );
  reads.forEach((i, k) => {
    if (k > 0 && i !== reads[k - 1]! + 1) {
      throw new RangeError(`${name}: the pinned values are not consecutive public inputs (each read's value, then an epoch read's epoch)`);
    }
  });
  return {
    circuit: name,
    state,
    oldCommitments,
    newCommitments,
    requestId,
    npkAppHash,
    ok,
    ...(partialNote !== undefined && { partialNote }),
    appOutputs,
    reads,
    records: stateModule(state).records(m),
  };
}

// ---- the parts of one result ----

/** Everything process_result needs from one checked answer, named as the
 * library's TipResult names it. */
export interface TipResultParts extends ProvedParts {
  ok: boolean;
  /** Under `outcome: partial`: the request's partial note. */
  partialNote?: FieldHexString;
  appOutputs: FieldHexString[];
}

/** The parts of a checked answer to FETCH by chain request id, bound to it
 * as every form's are (ProvedInputs.bind), and ok 0 or 1 (ProtocolError
 * otherwise). The result signatures are checked by the caller (PssClient). */
export async function tipResultParts(
  layout: TipResultLayout,
  namespace: FieldLike,
  chainRequestIdValue: FieldLike,
  response: ExecuteResponse,
): Promise<TipResultParts> {
  const proved = new ProvedInputs(layout.circuit, response);
  const bound = await proved.bind(layout, namespace, chainRequestIdValue);
  const okField = BigInt(proved.at(layout.ok, "ok"));
  if (okField !== 0n && okField !== 1n) throw new ProtocolError(`${layout.circuit}: ok is ${okField}, not 0 or 1`);
  const { circuit, ...rest } = bound;
  const partialNote = layout.partialNote === undefined ? undefined : proved.at(layout.partialNote, "partial_note");
  return {
    circuit,
    ...rest,
    ok: okField === 1n,
    ...(partialNote !== undefined && { partialNote }),
    appOutputs: proved.take(layout.appOutputs, "app output"),
  };
}

/** Two answers are the same result when they are the same attempt with the
 * same outcome: the machine request id and the new commitments. A relayer
 * and submitResult re-send an answer only when this key changes. */
export function resultKey(parts: Pick<TipResultParts, "machineRequestId" | "newCommitments" | "ok" | "appOutputs" | "partialNote">): string {
  return [parts.machineRequestId, ...parts.newCommitments, parts.ok ? "1" : "0", ...(parts.partialNote === undefined ? [] : [parts.partialNote]), ...parts.appOutputs].join(",");
}

// ---- process_result's arguments ----

/** The library's TipResult as aztec.js encodes it: the pinned read values
 * and then the app outputs share one array, `values` (so a round without
 * pinned reads is still a contract argument). */
export interface NoirTipResult {
  request_id: Fr;
  old_commitments: Fr[];
  new_commitments: Fr[];
  ok: boolean;
  values: Fr[];
}

/** The library's PartialResult as aztec.js encodes it: the request's
 * partial note, then the TipResult. */
export interface NoirPartialResult {
  partial_note: Fr;
  result: NoirTipResult;
}

/** What an encoder gets: the parts, the TipResult (under `outcome: partial`
 * the PartialResult around it), the state module's result arguments (none
 * under node-held state) and the signatures already in aztec.js form. */
export interface ProcessResultContext {
  parts: TipResultParts;
  result: NoirTipResult | NoirPartialResult;
  stateArgs: unknown[];
  signatures: [Fr, Fr, Fr, Fr][];
}

/** Turns one result into the app's process_result arguments, in its order. */
export type ProcessResultEncoder = (ctx: ProcessResultContext) => unknown[];

/** The TipResult struct of the parts. */
function noirTipResult(parts: TipResultParts): NoirTipResult {
  return {
    request_id: fieldFr(parts.requestId),
    old_commitments: parts.oldCommitments.map((x) => fieldFr(x)),
    new_commitments: parts.newCommitments.map((x) => fieldFr(x)),
    ok: parts.ok,
    values: [...parts.reads, ...parts.appOutputs].map((x) => fieldFr(x)),
  };
}

// The default process_result encoder (a ProcessResultEncoder), for an app
// whose wrapper takes the library's TipResult as pss_public_contract_test's
// does: `process_result(result: TipResult<..>, (state arguments,)
// signatures: [ResultSignature; 3])`, one wrapper per round for both non-secret-shared
// intakes, the state module's arguments between them (none under node-held
// state). Default: this order and name (DEFAULT_RESULT_METHOD, with the
// state module's resultArgs). An app with its own argument shape passes an
// encoder, and an app with its own result function a ResultFunction
// (lander.ts; examples/lending-tip's secret-shared rounds land through
// `process_shared(round, ...)`), and says so in its README; aztec.js then checks the arguments against the
// function's ABI before anything is proved, so a wrong encoder fails at
// once.
/** The library's argument order: `[result, ...stateArgs, signatures]`. */
export const defaultProcessResultEncoder: ProcessResultEncoder = (ctx) => [ctx.result, ...ctx.stateArgs, ctx.signatures];

/** The library's wrapper name, under either non-secret-shared intake. */
export const DEFAULT_RESULT_METHOD = RESERVED_NAMES.processResult.name;

/** The process_result context of one result: the TipResult, or under
 * partial-note delivery the PartialResult (`{partial_note, result}`, which
 * pss_public_contract's check_round takes for that delivery). */
function processResultContext(parts: TipResultParts): ProcessResultContext {
  const result = noirTipResult(parts);
  return {
    parts,
    result: parts.partialNote === undefined ? result : { partial_note: fieldFr(parts.partialNote), result },
    stateArgs: stateModule(parts.state).resultArgs(parts.stateArgs),
    signatures: parts.signatures.map(signatureLimbs),
  };
}

// ---- the public form's reader ----

/** The public form (result.ts): a non-secret-shared intake's round, its result the
 * library's TipResult, landed through process_result with its public
 * outputs (tipResultLayout, tipResultParts, the default encoder, resultKey). */
export const publicResults: ResultForm<TipResultParts> = {
  form: "public",
  reader(circuit, manifest) {
    const layout = tipResultLayout(circuit, manifest);
    return {
      form: "public",
      circuit: layout.circuit,
      parts: (namespace, chainRequestId, response) => tipResultParts(layout, namespace, chainRequestId, response),
      callArgs: (parts, encode) => (encode ?? defaultProcessResultEncoder)(processResultContext(parts)),
      key: resultKey,
      summary: (p) => ({
        form: "public",
        machineRequestId: p.machineRequestId,
        oldCommitments: p.oldCommitments,
        newCommitments: p.newCommitments,
        reads: p.reads,
        moves: p.ok,
        ok: p.ok,
        ...(p.partialNote !== undefined && { partialNote: p.partialNote }),
        appOutputs: p.appOutputs,
      }),
    };
  },
};
