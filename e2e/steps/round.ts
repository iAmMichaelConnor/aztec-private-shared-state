// A round: build the request, send it, and either check the answer (an
// answered round, optionally with its answer lost in transit) or require the
// machine to refuse it (a refused round, optionally tampered with first).
import { Fr } from "@aztec-labs/aztec.js/fields";
import {
  executeMessage,
  inputBodyHash,
  normaliseSignature,
  parseExecuteResponse,
  sealEnvelope,
  shareField,
  shareHash,
  signRequest,
  type BuildRequestInput,
  type ExecuteRequest,
  type ExecuteResponse,
  type PreparedRequest,
  type PssClient,
  type RequesterKey,
  type ResultRecord,
  type ShareCiphertext,
  type Triple,
} from "@aztec-pss/pss-client";

import { checkAnswer, roundOf, same, type Note } from "../engine/answer.ts";
import type { RunContext } from "../engine/context.ts";
import { defineKind, refs, type Common } from "../engine/kind.ts";
import type { Refusal } from "../engine/machine.ts";
import { check, fieldLike, show, type Expect, type Value } from "../engine/scope.ts";
import { timed } from "../harness/harness.ts";

/** What a round sends: the request to the circuit `round`. */
interface RoundRequest extends Common {
  round: string;
  public?: Record<string, Value>;
  stateKeys?: { reads?: Value[]; writes?: Value[] };
  /** State records (results' `records[j]`) the round loads. */
  records?: Value[];
  /** INPUT_SHARED inputs, by name, in body order. */
  shared?: Record<string, Value>;
  /** The requester key (default: the scenario's `signer`; null: none). */
  signer?: string | null;
  /** One of the scenario's namespaces (default: its first). */
  namespace?: string;
}
/** A round the machine must answer. */
export interface AnsweredRound extends RoundRequest {
  /** The scope name of the answered round. */
  name?: string;
  /** Per read key, the note the chain holds: its leaf must be the round's read leaf. */
  consumes?: Value[];
  expect?: Expect[];
  /** The answer is dropped in transit; FETCH, FETCH again and a resend of the
   * saved body must all return it. */
  answer?: "lost";
  refused?: never;
  tamper?: never;
  clientRefuses?: never;
}
/** A round the machine must refuse. */
export interface RefusedRound extends RoundRequest {
  refused: Refusal;
  /** A change to the honest body before it is sent. */
  tamper?: Tamper;
  /** With a tamper: pss-client must refuse the tampered body (mentions); it is then POSTed past the client. */
  clientRefuses?: string[];
  name?: never;
  consumes?: never;
  expect?: never;
  answer?: never;
}
export type RoundStep = AnsweredRound | RefusedRound;

/** A change to an honest body before it is sent. */
export type Tamper =
  /** Node 1's pair of the named INPUT_SHARED input disagrees with node 0's on x_0; re-signed. */
  | { share: string }
  /** Node `node`'s third of record `record` comes from another record. */
  | { third: { record: number; node: number; from: Value } }
  /** Signed by another requester key, the requester named unchanged. */
  | { signWith: string };

const REQUEST = ["round", "public", "stateKeys", "records", "shared", "signer", "namespace"];

export default defineKind<RoundStep>({
  key: "round",
  check(step, s) {
    refs.namespace(s, step.namespace);
    if (step.signer) refs.key(s, step.signer, "requester");
    if (step.refused === undefined) return { fields: [...REQUEST, "name", "consumes", "expect", "answer"], binds: [step.name] };
    check(step.clientRefuses === undefined || step.tamper !== undefined, "clientRefuses takes a tamper (pss-client sends an honest body)");
    if (step.tamper && "signWith" in step.tamper) refs.key(s, step.tamper.signWith, "requester");
    if (step.tamper && "share" in step.tamper) {
      check(step.shared?.[step.tamper.share] !== undefined, `tamper share ${step.tamper.share}: the round shares no such input`);
      check((step.signer === undefined ? s.signer : step.signer) != null, "tamper share re-signs the body: the round needs a signer");
    }
    return { fields: [...REQUEST, "refused", "tamper", "clientRefuses"] };
  },
  async run(ctx, step) {
    const label = step.what ?? step.name ?? step.round;
    const ns = ctx.namespace(step.namespace);
    const client = ctx.client(ns);
    const input = requestInput(ctx, step);
    const prepared = await client.buildRequest(input);
    check(!ctx.requestIds.has(prepared.requestId), `${label}: the client drew request id ${prepared.requestId} twice`);
    ctx.requestIds.add(prepared.requestId);
    if (step.refused) return refused(ctx, label, step, client, input, prepared);

    const response = step.answer === "lost" ? await lostAnswer(ctx, label, client, prepared) : await executed(ctx, label, client, prepared);
    const effects = await checkAnswer(ctx, label, step.round, ns, input, prepared.requestId, response);
    for (const [i, n] of (step.consumes ?? []).entries()) {
      const note = ctx.scope.resolve(n) as Note;
      check(effects.read_leaves[i]!.equals(note.leaf), `${label}: read leaf ${effects.read_leaves[i]}, the chain holds ${note.leaf}`);
      ctx.logger.info(`${label}: read leaf ${i} = the leaf the chain holds`);
    }
    if (step.name) ctx.scope.set(step.name, roundOf(step.round, ns, input, prepared.requestId, response, effects));
    ctx.scope.expectAll(label, step.expect ?? []);
    if (effects.app_outputs.length) ctx.logger.info(`${label}: app outputs ${show(effects.app_outputs.map((f) => f.toBigInt()))}`);
  },
});

function requestInput(ctx: RunContext, step: RoundStep): BuildRequestInput {
  const { scope } = ctx;
  const signer = step.signer === undefined ? ctx.scenario.signer : (step.signer ?? undefined);
  const input: BuildRequestInput = { circuit: step.round };
  if (step.public) input.public = Object.fromEntries(Object.entries(step.public).map(([k, v]) => [k, fieldLike(scope.resolve(v))]));
  if (step.stateKeys) input.stateKeys = scope.resolve(step.stateKeys) as BuildRequestInput["stateKeys"];
  if (step.records) input.records = (scope.resolve(step.records) as ResultRecord[]).map((r) => ({ key: r.key, note_hash: r.note_hash, c: r.c }));
  if (step.shared) input.sharedInputs = Object.entries(step.shared).map(([name, v]) => ({ name, value: fieldLike(scope.resolve(v)) }));
  if (signer !== undefined) input.signer = ctx.key<RequesterKey>(signer);
  return input;
}

async function executed(ctx: RunContext, label: string, client: PssClient, prepared: PreparedRequest): Promise<ExecuteResponse> {
  const outcome = await timed(ctx.logger, `round ${label} (${prepared.circuit})`, () => client.execute(prepared));
  check(outcome.via === "execute", `${label}: answered via ${outcome.via}`);
  return outcome.response;
}

async function refused(ctx: RunContext, label: string, step: RefusedRound, client: PssClient, input: BuildRequestInput, honest: PreparedRequest): Promise<void> {
  const prepared = step.tamper ? await tamper(ctx, step.tamper, honest, client, input) : honest;
  if (step.clientRefuses) {
    await ctx.machine.expectClientRefusal(label, step.clientRefuses, () => client.checkBeforeSend(prepared.requestId, prepared.json));
    await ctx.machine.expectRefusal(`${label}, sent past the client`, step.refused, () => ctx.machine.postRaw(prepared.json));
  } else {
    await ctx.machine.expectRefusal(label, step.refused, () => client.execute(prepared));
  }
}

/** Executes with the answer dropped; FETCH, FETCH again and a resend of the
 * saved body must return the first answer, which the nodes give from their
 * requests rows without a second round. */
async function lostAnswer(ctx: RunContext, label: string, client: PssClient, prepared: PreparedRequest): Promise<ExecuteResponse> {
  const { logger, machine } = ctx;
  machine.dropNextAnswer();
  const outcome = await timed(logger, `round ${label} (${prepared.circuit}), answer lost and FETCHed`, () => client.execute(prepared));
  const dropped = machine.droppedAnswer;
  check(dropped !== undefined, `${label}: the answer was not dropped`);
  const first = parseExecuteResponse(JSON.parse(dropped));
  check(outcome.via === "fetch", `${label}: the outcome came via ${outcome.via}, expected fetch after the lost answer`);
  check(same(outcome.response, first), `${label}: FETCH after the lost answer returned another result than the first`);
  logger.info(`[retry] ${label} answer lost: the client's FETCH of ${prepared.requestId} returned the first result`);
  check(same(await timed(logger, `FETCH ${label}`, () => client.fetch(prepared.requestId)), first), `${label}: FETCH by request id returned another result`);
  const saved = await client.store.load(prepared.requestId);
  check(saved !== undefined && saved === prepared.json, `${label}: the client did not keep the exact body`);
  const resent = await timed(logger, `resend of the saved ${label} body`, () => machine.postRaw(saved));
  await client.checkResponse(prepared.circuit, prepared.requestId, resent, prepared.namespace, prepared.body.state_keys);
  check(same(resent, first), `${label}: the resent body returned another result than the first`);
  logger.info(`[retry] ${label}: FETCH by request id and a resend of the saved body both returned the first result (no second round)`);
  return first;
}

async function tamper(ctx: RunContext, t: Tamper, honest: PreparedRequest, client: PssClient, input: BuildRequestInput): Promise<PreparedRequest> {
  const body: ExecuteRequest = structuredClone(honest.body);
  if ("third" in t) {
    body.records[t.third.record]!.c[t.third.node] = (ctx.scope.resolve(t.third.from) as ResultRecord).c[t.third.node]!;
    return { ...honest, body, json: JSON.stringify(body) };
  }
  if ("signWith" in t) {
    body.signature = normaliseSignature(await ctx.key<RequesterKey>(t.signWith).sign(await executeMessage(body)));
    return { ...honest, body, json: JSON.stringify(body) };
  }
  // The named input shared inconsistently: node 1 receives a pair whose
  // second element is not node 0's first, so the two neighbours that both
  // hold x_0 hold different values. Envelopes, hashes and signature honest.
  delete body.signature;
  const ad = { namespace: body.namespace, requestId: body.request_id, circuit: body.circuit, name: t.share, binds: await inputBodyHash(body) };
  const value = input.sharedInputs!.find((x) => x.name === t.share)!.value;
  const [x0, x1, x2] = shareField(value);
  const pairs: [bigint, bigint][] = [
    [x0, x2],
    [x1, (x0 + 1n) % Fr.MODULUS],
    [x2, x1],
  ];
  const encKeys = client.config.nodeKeys.map((k) => k.enc);
  const shares = (await Promise.all(pairs.map((pair, i) => sealEnvelope(encKeys[i]!, i, ad, pair)))) as Triple<ShareCiphertext>;
  const k = body.shared_inputs.findIndex((x) => x.name === t.share);
  body.shared_inputs[k] = { name: t.share, shares, share_hashes: (await Promise.all(shares.map(shareHash))) as Triple<string> };
  return signRequest({ ...honest, body, json: JSON.stringify(body) }, input.signer!);
}
