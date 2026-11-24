// The checks of every answered round (executed or fetched), and the shapes
// rounds and notes take in the scope.
import { Fr } from "@aztec-labs/aztec.js/fields";
import {
  canonicalJson,
  noteHashIndices,
  resultMessages,
  shapeFromAbi,
  splitEffects,
  verifySignature,
  type BuildRequestInput,
  type ExecuteResponse,
  type FieldLike,
  type PssEffects,
  type ResultRecord,
  type WitnessEntry,
} from "@aztec-pss/pss-client";

import type { RunContext } from "./context.ts";
import { check, keyHex } from "./scope.ts";

/** A round the driver ran (or fetched), as scenarios reference it. */
export interface Round {
  circuit: string;
  /** The scenario's name of its namespace. */
  namespace: string;
  input: BuildRequestInput;
  requestId: string;
  response: ExecuteResponse;
  effects: PssEffects;
  /** effects.app_outputs. */
  out: Fr[];
  /** response.records. */
  records: ResultRecord[];
}

/** A note the chain holds. */
export interface Note {
  nonce: Fr;
  leaf: Fr;
  /** Its inner note hash, as the round that created it reported it. */
  noteHash: Fr;
}

export const same = (a: ExecuteResponse, b: ExecuteResponse) => canonicalJson(a) === canonicalJson(b);

/** The value a request gives the circuit's `owner` parameter, by the
 * manifest's witness entry for it: a const, or a named public input. */
function ownerOf(label: string, manifest: unknown, input: BuildRequestInput): FieldLike {
  const entry = (manifest as { witness?: WitnessEntry[] }).witness?.find((w) => w.param === "owner");
  const from = entry?.from.PUBLIC;
  if (from !== null && typeof from === "object" && "const" in from) return (from as { const: FieldLike }).const;
  if (typeof from === "string" && !from.startsWith("$")) {
    const v = input.public?.[from];
    check(v !== undefined && !Array.isArray(v), `${label}: the request has no public value ${from} for the owner`);
    return v as FieldLike;
  }
  throw new Error(`${label}: the manifest's owner source ${JSON.stringify(entry?.from)} is neither a const nor a public input`);
}

/** The checks of every answer: the vk hash REGISTER answered in the round's
 * namespace, the result signatures against the keys setup printed, the
 * public-input prefix against the request, the namespace's npk_app_hash and
 * the returned records. */
export async function checkAnswer(ctx: RunContext, label: string, circuit: string, ns: string, input: BuildRequestInput, requestId: string, response: ExecuteResponse): Promise<PssEffects> {
  const pins = ctx.pins(ns);
  const pinned = pins.vk[circuit];
  check(response.request_id === requestId, `${label}: answer for request ${response.request_id}`);
  check(pinned !== undefined, `${label}: ${circuit} has no REGISTER answer in namespace ${ns}`);
  check(response.vk_hash === pinned, `${label}: vk_hash ${response.vk_hash} is not the REGISTER answer ${pinned}`);
  check(response.signatures.length === 3, `${label}: ${response.signatures.length} result signatures`);
  // pss-client verified the result signatures already; verify them again
  // from the client's message rebuild and the keys setup printed
  // (harness.json), not the client's configuration.
  const pkg = ctx.pkg(circuit);
  const nsValue = ctx.nsValue(ns);
  const messages = await resultMessages(nsValue, response, noteHashIndices(pkg.circuit, pkg.manifest));
  for (let i = 0; i < 3; i++) {
    check(await verifySignature(messages[i]!.toBigInt(), ctx.harness.nodeKeys[i]!.sig, response.signatures[i]!), `${label}: node ${i}'s result signature does not verify under its setup sig key`);
  }
  const shape = shapeFromAbi(pkg.circuit);
  const appInputs = shape.appInputs.flatMap((a) => {
    const v = input.public?.[a.name];
    check(v !== undefined, `${label}: the request has no public value for the app input ${a.name}`);
    return [v].flat();
  });
  const reads = input.stateKeys?.reads ?? [];
  const writes = input.stateKeys?.writes ?? [];
  const { effects } = splitEffects(response.public_inputs, shape, { namespace: nsValue, owner: ownerOf(label, pkg.manifest, input), reads, writes, appInputs });
  if (shape.R > 0) check(effects.npk_app_hash.toString() === pins.npk_app_hash, `${label}: npk_app_hash ${effects.npk_app_hash}, namespace ${ns}'s ${pins.npk_app_hash}`);
  for (const r of response.records) {
    const j = writes.findIndex((w) => keyHex(w) === r.key);
    check(j >= 0 && r.note_hash === effects.new_note_hashes[j]!.toString(), `${label}: record ${r.key}/${r.note_hash} is no written key's new note hash`);
  }
  ctx.logger.info(`${label}: request ${requestId}, vk_hash ${response.vk_hash} (= REGISTER), 3 result signatures verified, ${response.public_inputs.length} public inputs, ${response.records.length} record(s)`);
  return effects;
}

/** A round as the scope keeps it. */
export function roundOf(circuit: string, namespace: string, input: BuildRequestInput, requestId: string, response: ExecuteResponse, effects: PssEffects): Round {
  return { circuit, namespace, input, requestId, response, effects, out: effects.app_outputs, records: response.records };
}
