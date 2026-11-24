// The init round's result on the client side (docs/ARCHITECTURE.md section
// 6, "Deployment, configure and the init round"): from a checked answer of
// FETCH by the init's chain request id to the arguments of the app's private
// init function (examples/amm-tip's `init_pool`, examples/lending-tip's
// `init_market`), which pss-relayer sends through the Lander.
//
// The Noir side is noir/pss_public_contract/src/init.nr
// (init_request_id, init_public_inputs, process_init); the node side is
// machine/sidecar-tip's init module. The rules, mirrored here:
//
//   init chain request id = chain_request_id(namespace, init vk hash, inputs_hash(inputs), 0)
//   machine request id    = poseidon2([PSS_ATTEMPT, init id, 0 (W times)])
//   public inputs         = [namespace, vk_hash, out_slots[W], request_id, 0 (W times),
//                            new_commitments[W], npk_app_hash, new_hashes[H]]
//
// with W the keys the init creates and H the new leaf hashes a tree-valued
// key's init outputs (none for slot keys).

import type { Fr } from "@aztec-labs/aztec.js/fields";

import { abiOf, outputNoteHashIndices, publicLayout } from "./abi.ts";
import { ProtocolError } from "./errors.ts";
import { fieldFr, type FieldHexString, type FieldLike } from "./field.ts";
import type { QueuedManifest } from "./manifest.ts";
import { ProvedInputs, signatureLimbs, type ProvedLayout, type ProvedParts } from "./proved.ts";
import { stateModule, tipStateOf } from "./state.ts";
import { chainRequestId, tipInputsHash } from "./tip.ts";
import type { ExecuteResponse } from "./wire.ts";

/** The init round's fixed chain request id: the non-secret-shared id of `inputs` (the
 * init circuit's app inputs, the constants the app's Config pins) with
 * `user_nonce` 0 under the init vk hash (init.nr init_request_id). */
export async function initChainRequestId(namespace: FieldLike, initVkHash: FieldLike, inputs: readonly FieldLike[]): Promise<Fr> {
  return chainRequestId(namespace, initVkHash, await tipInputsHash(inputs), 0n);
}

/** Where each part of an init round's result sits in its public inputs,
 * read once from the init circuit's ABI and manifest: the parts every form
 * binds (ProvedLayout: the init request id; the empty slots' old
 * commitments, each 0; no pinned reads), then the init layout's own. */
export interface InitResultLayout extends ProvedLayout {
  /** The public-input indices of the slots the init creates (`out_slots`). */
  slots: number[];
  npkAppHash: number;
  /** The new leaf hashes of a tree-valued key, the layout's tail. */
  newHashes: number[];
}

/** The layout of an init circuit's result, from its nargo output JSON (or
 * its `abi`) and its parsed manifest. RangeError when the circuit reads a
 * key or does not follow init.nr's init_public_inputs. */
export function initResultLayout(circuit: unknown, m: QueuedManifest): InitResultLayout {
  const name = m.circuit;
  if (m.stateKeys.reads !== 0) throw new RangeError(`${name}: an init round reads no key; the manifest reads ${m.stateKeys.reads}`);
  const W = m.stateKeys.writes;
  if (W < 1) throw new RangeError(`${name}: an init round creates at least one key`);
  const abi = abiOf(circuit);
  const { publicFields, returnLeaves, returnPublic } = publicLayout(abi);
  if (!returnPublic) throw new RangeError(`${name}: the return value is not public`);
  if (publicFields !== 2 + W) {
    throw new RangeError(`${name}: ${publicFields} public parameter fields; init.nr's layout has 2 + W = ${2 + W} (namespace, vk_hash, out_slots)`);
  }
  const requestId = publicFields;
  const range = (from: number, n: number) => Array.from({ length: n }, (_, k) => from + k);
  const oldCommitments = range(requestId + 1, W);
  const newCommitments = outputNoteHashIndices(abi, m.outputs);
  if (newCommitments.length !== W || newCommitments.some((i, k) => i !== requestId + 1 + W + k)) {
    throw new RangeError(
      `${name}: the new commitments are public inputs ${newCommitments.join(", ")}; init.nr's layout puts them at ${range(requestId + 1 + W, W).join(", ")} ` +
        "(return value: request_id, old commitments, new commitments, npk_app_hash, new_hashes)",
    );
  }
  const npkAppHash = requestId + 1 + 2 * W;
  const end = publicFields + returnLeaves.length;
  if (npkAppHash >= end) throw new RangeError(`${name}: the return value has no npk_app_hash after the commitments`);
  const state = tipStateOf(m);
  return {
    circuit: name,
    state,
    slots: range(2, W),
    requestId,
    oldCommitments,
    newCommitments,
    npkAppHash,
    newHashes: range(npkAppHash + 1, end - npkAppHash - 1),
    reads: [],
    records: stateModule(state).records(m),
  };
}

/** Everything the app's init function needs from one checked answer: the
 * init chain request id as its request id. */
export interface InitResultParts extends ProvedParts {
  /** The storage slots the init creates, as its proof states them. */
  slots: FieldHexString[];
  newHashes: FieldHexString[];
}

/** The parts of a checked answer to FETCH by the init's chain request id:
 * every old commitment 0 (ProtocolError otherwise), then bound to the init
 * id as every form's are (ProvedInputs.bind). The result signatures are
 * checked by the caller (PssClient). */
export async function initResultParts(
  layout: InitResultLayout,
  namespace: FieldLike,
  initChainRequestIdValue: FieldLike,
  response: ExecuteResponse,
): Promise<InitResultParts> {
  const proved = new ProvedInputs(layout.circuit, response);
  const olds = proved.take(layout.oldCommitments, "old commitment");
  if (olds.some((c) => BigInt(c) !== 0n)) throw new ProtocolError(`${layout.circuit}: an init's old commitments are 0, the proof states ${olds.join(", ")}`);
  const bound = await proved.bind(layout, namespace, initChainRequestIdValue);
  return { ...bound, slots: proved.take(layout.slots, "out_slots"), newHashes: proved.take(layout.newHashes, "new_hashes") };
}

// ---- the init function's arguments ----

/** What an init encoder gets: the parts, and the values in aztec.js form. */
export interface InitCallContext {
  parts: InitResultParts;
  newCommitments: Fr[];
  newHashes: Fr[];
  /** The state module's result arguments (none under node-held state). */
  stateArgs: unknown[];
  signatures: [Fr, Fr, Fr, Fr][];
}

/** Turns one init result into the app's init function arguments, in its order. */
export type InitCallEncoder = (ctx: InitCallContext) => unknown[];

/** The init call context of one result. */
export function initCallContext(parts: InitResultParts): InitCallContext {
  return {
    parts,
    newCommitments: parts.newCommitments.map((x) => fieldFr(x)),
    newHashes: parts.newHashes.map((x) => fieldFr(x)),
    stateArgs: stateModule(parts.state).resultArgs(parts.stateArgs),
    signatures: parts.signatures.map(signatureLimbs),
  };
}

// The default init encoder (an InitCallEncoder; an app with another shape
// passes its own), for an app whose init function takes process_init's
// values in its order: `init_<x>(new_c..., (new_hashes,) (state arguments,)
// signatures: [ResultSignature; 3])`, each new commitment as a Field of its
// own, `new_hashes` as one array only when the init outputs new leaf hashes
// (H > 0), then the state module's result arguments (none under node-held
// state). The function's name is the app's (examples/amm-tip
// `init_pool(new_c, signatures)`, examples/lending-tip `init_market(new_c,
// new_hashes, signatures)`), so the relayer is configured with it. aztec.js
// checks the arguments against the function's ABI before anything is
// proved.
export const defaultInitEncoder: InitCallEncoder = (ctx) => [
  ...ctx.newCommitments,
  ...(ctx.newHashes.length > 0 ? [ctx.newHashes] : []),
  ...ctx.stateArgs,
  ctx.signatures,
];
