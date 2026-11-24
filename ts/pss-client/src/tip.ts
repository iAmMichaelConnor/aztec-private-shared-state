// The tip's intake on the client side (docs/ARCHITECTURE.md section 6, row
// "intake"): the content-derived chain request id, the tip request and the
// order of the app inputs. Each intake's own part (its request function's
// arguments, receipts, the request log) is its module's (intake.ts).
//
// The Noir side is noir/pss_public_contract (intake.nr, domains.nr);
// the node side is machine/sidecar-tip (ids.rs, receipt.rs). The rules,
// written once there and mirrored here:
//
//   inputs_hash       = poseidon2(app inputs in ABI order)
//   chain_request_id  = poseidon2([namespace, vk_hash, inputs_hash, user_nonce])
//
// with poseidon2 the width-4 sponge of ARCHITECTURE section 1 (aztec.js
// poseidon2Hash, Noir's p2_hash), namespace the app contract's address,
// vk_hash the circuit's pin and user_nonce a random salt per request. No id,
// request log, receipt or argument names the requester (ARCHITECTURE
// section 6, "The hidden requester"), so any account may send the intake
// transaction.
//
// Under the secret-shared intakes (secret-shared receipt intake, secret-shared on-chain intake)
// the chain request id commits to a hiding commitment of the inputs instead
// (docs/ARCHITECTURE.md section 6, "The inputs commitment and the request id"):
//
//   C                 = poseidon2([v_1, ..., v_m, blinding])
//   chain_request_id  = poseidon2([namespace, vk_hash, C])
//   S_j               = poseidon2([SUMMANDS_DOMAIN, s_j..., salt_j])     j = 0, 1, 2
//   D                 = poseidon2([SHARING_DOMAIN, S_0, S_1, S_2, kinds..., clear values...])
//
// v_1 ... v_m the values of every app input, clear or INPUT_SHARED, and of
// `$outcome_key` and `$outcome_tag`, in the order the ABI walk first meets
// each (IntakeLayout.commitment), and blinding the value of `$blinding`. S_j
// and D commit to a secret-shared receipt request's sharing, its three Rep3
// summand vectors s_0 + s_1 + s_2 and their salts (intake-shared-receipt.ts).
// The non-secret-shared intakes take no INPUT_SHARED input (intakeLayout refuses such a
// manifest, as REGISTER does).

import { randomBytes } from "node:crypto";

import { poseidon2Hash } from "@aztec-labs/foundation/crypto/poseidon";
import { Fr } from "@aztec-labs/foundation/curves/bn254";

import { abiLeaves, abiOf, type AbiLeaf } from "./abi.ts";
import { fieldBigInt, fieldHex, randomField, type FieldHexString, type FieldLike } from "./field.ts";
import { asciiLabel } from "./labels.ts";
import { isSharedIntake, PARTIAL_NOTE_NAME, publicReadParams, type QueuedIntake, type QueuedManifest, treeParams } from "./manifest.ts";
import type { PublicValue, Triple } from "./wire.ts";

// ---- ids ----

/** The inputs commitment of a secret-shared intake: `C = poseidon2([values...,
 * blinding])`, `values` in the order of IntakeLayout.commitment (sidecar-tip
 * ids.rs inputs_commitment, pss_core's tip::intake::commit). */
export async function inputsCommitment(values: readonly FieldLike[], blinding: FieldLike): Promise<Fr> {
  return poseidon2Hash([...values.map((x, i) => new Fr(fieldBigInt(x, `values[${i}]`))), new Fr(fieldBigInt(blinding, "blinding"))]);
}

/** The chain request id of a secret-shared intake: `poseidon2([namespace, vk_hash,
 * C])` (sidecar-tip ids.rs shared_chain_request_id, pss_core's
 * tip::intake::shared). */
export async function sharedChainRequestId(namespace: FieldLike, vkHash: FieldLike, c: FieldLike): Promise<Fr> {
  return poseidon2Hash([
    new Fr(fieldBigInt(namespace, "namespace")),
    new Fr(fieldBigInt(vkHash, "vk_hash")),
    new Fr(fieldBigInt(c, "inputs_commitment")),
  ]);
}

/** ASCII "sidecar.summands" read big-endian: the first element of a summand
 * commitment (pss_core tip/intake.nr SUMMANDS_DOMAIN). */
export const SUMMANDS_DOMAIN = asciiLabel("sidecar.summands");

/** ASCII "sidecar.sharing" read big-endian: the first element of a sharing
 * digest (pss_core tip/intake.nr SHARING_DOMAIN). */
export const SHARING_DOMAIN = asciiLabel("sidecar.sharing");

/** The commitment to one summand vector of a secret-shared receipt request,
 * `S_j = poseidon2([SUMMANDS_DOMAIN, s_j..., salt_j])` (pss_core's
 * tip::intake::summand_commitment, sidecar-tip ids.rs). */
export async function summandCommitment(summands: readonly FieldLike[], salt: FieldLike): Promise<Fr> {
  return poseidon2Hash([
    new Fr(SUMMANDS_DOMAIN),
    ...summands.map((x, k) => new Fr(fieldBigInt(x, `summands[${k}]`))),
    new Fr(fieldBigInt(salt, "salt")),
  ]);
}

/** The kind of one of C's values: a clear app input, or a shared value
 * the user chooses (an INPUT_SHARED app input or a reserved value). */
export type ValueKind = "clear" | "chosen";

/** The kind of each of C's values, in IntakeLayout.commitment order
 * (sidecar-tip commitment_layout's kinds). */
export function valueKinds(layout: IntakeLayout): ValueKind[] {
  const shared = new Set(layout.shared);
  return layout.commitment.map((name) => (shared.has(name) ? "chosen" : "clear"));
}

/** The sharing digest of a secret-shared receipt request, `D =
 * poseidon2([SHARING_DOMAIN, S_0, S_1, S_2, kind_1, ..., kind_m, clear_1,
 * ..., clear_q])`: the summand commitments, the kind of each of C's values
 * (valueKinds; clear 0, chosen 1) and the clear values in C's order. Every
 * node's receipt signs it, each node computing it over the clear inputs it
 * stores, and the request function recomputes it over C's own (pss_core's
 * tip::intake::sharing_digest, sidecar-tip ids.rs). */
export async function sharingDigest(commitments: Triple<FieldLike>, kinds: readonly ValueKind[], clear: readonly FieldLike[]): Promise<Fr> {
  return poseidon2Hash([
    new Fr(SHARING_DOMAIN),
    ...commitments.map((x, j) => new Fr(fieldBigInt(x, `summand_commitments[${j}]`))),
    ...kinds.map((k) => new Fr(k === "chosen" ? 1n : 0n)),
    ...clear.map((x, q) => new Fr(fieldBigInt(x, `clear[${q}]`))),
  ]);
}

/** The values C commits to, in IntakeLayout.commitment order, from a map
 * holding each by name (a clear input under its flattened key, a shared one
 * under its name); RangeError naming a missing one. */
export function commitmentValues(layout: IntakeLayout, values: Readonly<Record<string, FieldLike>>): bigint[] {
  return layout.commitment.map((k) => {
    if (!Object.hasOwn(values, k)) throw new RangeError(`values.${k}: missing; C commits to ${JSON.stringify(layout.commitment)}`);
    return fieldBigInt(values[k]!, `values.${k}`);
  });
}

// ---- what the secret-shared intakes share ----

/** The reserved INPUT_SHARED names of the secret-shared intakes: C's
 * blinding, and the key and tag of the request's private outcome. */
export const BLINDING_NAME = "$blinding";
export const OUTCOME_KEY_NAME = "$outcome_key";
export const OUTCOME_TAG_NAME = "$outcome_tag";

/** The three secrets of a secret-shared request: the blinding of C, and the
 * key and tag of its private outcome. */
export interface SharedSecrets {
  blinding: bigint;
  outcomeKey: bigint;
  outcomeTag: bigint;
}

/** Three field elements uniform mod r from the operating system's CSPRNG
 * (randomField): a reused blinding links two requests, a reused key or tag
 * exposes an outcome. */
export function drawSharedSecrets(): SharedSecrets {
  return { blinding: randomField(), outcomeKey: randomField(), outcomeTag: randomField() };
}

/** The static check over C's values in commitment order, as the contract's
 * request function asserts it (`is_valid`): the app reads its inputs by
 * position and ignores the reserved ones. */
export type SharedStaticCheck = (values: readonly bigint[]) => boolean;

/** The order of a secret-shared request's shared values: every INPUT_SHARED
 * value of C in C's order (IntakeLayout.commitment), then `$blinding`
 * (sidecar-tip CommitmentLayout::summand_names). Secret-shared receipt intake's summand
 * vectors hold one element per name in this order, the order the request
 * function matches them to C's values in (pss_public_contract
 * shared_intake.nr `opened_sharing`); secret-shared on-chain intake's
 * encoding derives the shared values in it. */
export function summandNames(layout: IntakeLayout): string[] {
  const shared = new Set(layout.shared);
  return [...layout.commitment.filter((n) => shared.has(n)), BLINDING_NAME];
}

/** A secret-shared request's C over `values` (C's values in commitment
 * order) and `blinding`, and its chain request id, after the app's static
 * check over the values. RangeError when `isValid` refuses them. */
export async function sharedRequestCommitment(
  request: { namespace: FieldLike; vkHash: FieldLike; isValid?: SharedStaticCheck },
  values: readonly bigint[],
  blinding: FieldLike,
): Promise<{ namespace: FieldHexString; vkHash: FieldHexString; c: bigint; chainRequestId: FieldHexString }> {
  if (request.isValid && !request.isValid(values)) throw new RangeError("inputs: refused by the app's static check (isValid)");
  const namespace = fieldHex(request.namespace, "namespace");
  const vkHash = fieldHex(request.vkHash, "vk_hash");
  const c = (await inputsCommitment(values, blinding)).toBigInt();
  const chainRequestId = fieldHex((await sharedChainRequestId(namespace, vkHash, c)).toBigInt());
  return { namespace, vkHash, c, chainRequestId };
}

/** `inputs_hash = poseidon2(inputs)`, the app inputs in ABI order. */
export async function tipInputsHash(inputs: readonly FieldLike[]): Promise<Fr> {
  return poseidon2Hash(inputs.map((x, i) => new Fr(fieldBigInt(x, `inputs[${i}]`))));
}

/** The non-secret-shared intakes' chain request id: `poseidon2([namespace, vk_hash,
 * inputs_hash, user_nonce])`, intake.nr's chain_request_id and sidecar-tip's
 * ids.rs. It names no requester. */
export async function chainRequestId(namespace: FieldLike, vkHash: FieldLike, inputsHash: FieldLike, userNonce: FieldLike): Promise<Fr> {
  return poseidon2Hash([
    new Fr(fieldBigInt(namespace, "namespace")),
    new Fr(fieldBigInt(vkHash, "vk_hash")),
    new Fr(fieldBigInt(inputsHash, "inputs_hash")),
    new Fr(fieldBigInt(userNonce, "user_nonce")),
  ]);
}

// user_nonce generation. Each tip request gets 128 bits from the operating
// system's CSPRNG (crypto.randomBytes(16)), written as the field element it
// is (0x + 64 hex digits, the top 32 zero), the only source buildTipRequest
// uses; buildTipRequestWith takes a nonce for known-answer tests and for
// asking again under the same request id. In receipt intake the nonce is
// what makes request_id a hiding commitment to the inputs (without it,
// low-entropy inputs fall to trying values against the public request_id),
// and in both modes two requests with equal inputs need distinct ids, since
// append() reverts on a repeated id and the id names no requester. A counter
// would make ids guessable and link a user's requests. Under on-chain intake
// the log publishes the nonce, so it hides nothing there. Fewer bits weaken
// the hiding and risk collisions between users; more buy nothing.
/** A fresh user_nonce: 128 random bits as a field element. */
export function newUserNonce(): FieldHexString {
  return fieldHex(BigInt("0x" + randomBytes(16).toString("hex")));
}

/** The app's static-validity predicate, as the contract's `is_valid` sees
 * the inputs: in ABI order, each as an integer below the field modulus. It
 * must decide from the inputs alone (ranges, enum values, non-zero amounts);
 * nothing state-dependent. */
export type StaticCheck = (inputs: readonly bigint[]) => boolean;

export interface TipRequestInput {
  /** The app contract's address. */
  namespace: FieldLike;
  /** The circuit's vk hash, as the contract's Config pins it. */
  vkHash: FieldLike;
  /** The app inputs in ABI order (intakeLayout / tipInputs give the order
   * from a manifest and named values). */
  inputs: readonly FieldLike[];
  /** The app's static check, default none; see the comment at buildTipRequestWith. */
  isValid?: StaticCheck;
}

/** A tip request before intake: its inputs, nonce and both hashes. */
export interface TipRequest {
  namespace: FieldHexString;
  vkHash: FieldHexString;
  inputs: FieldHexString[];
  userNonce: FieldHexString;
  inputsHash: FieldHexString;
  chainRequestId: FieldHexString;
}

/** A tip request with a fresh random user_nonce (newUserNonce). */
export function buildTipRequest(input: TipRequestInput): Promise<TipRequest> {
  return buildTipRequestWith(input, newUserNonce());
}

// Where the client's static checks come from. buildTipRequest runs the
// caller-supplied predicate `isValid` (optional, default none: the app's own
// rule, the same one its contract's request function asserts; for the test
// contract and the AMM, a non-zero amount below 2^64 and a direction of 0 or
// 1), and tipInputs, which turns named values into the ABI-order list, runs
// the manifest's typed ranges (the checks a node runs before it signs: bool 1
// bit, u<N>/i<N> N bits, string bytes 8 bits; a Field unchecked). Both run
// when the caller goes through tipInputs and passes isValid; neither is
// required. The tip circuits take raw Field inputs for totality, so the
// typed ranges alone admit everything and only the app's predicate catches a
// request the contract will revert ("invalid inputs") after a full
// client-side proving run. Without isValid such a request fails at the
// transaction (on-chain intake) or is refused by the nodes before they sign
// (receipt intake, typed ranges only), never silently accepted.
/** A tip request with the given user_nonce: for known-answer tests, and for
 * asking again for receipts under the same request id. Throws RangeError
 * naming the value when an input is not a field element, and when `isValid`
 * refuses the inputs. */
export async function buildTipRequestWith(input: TipRequestInput, userNonce: FieldLike): Promise<TipRequest> {
  const inputs = input.inputs.map((x, i) => fieldHex(x, `inputs[${i}]`));
  if (input.isValid && !input.isValid(inputs.map((x) => BigInt(x)))) {
    throw new RangeError("inputs: refused by the app's static check (isValid)");
  }
  const namespace = fieldHex(input.namespace, "namespace");
  const vkHash = fieldHex(input.vkHash, "vk_hash");
  const nonce = fieldHex(userNonce, "user_nonce");
  const inputsHash = await tipInputsHash(inputs);
  const id = await chainRequestId(namespace, vkHash, inputsHash, nonce);
  return {
    namespace,
    vkHash,
    inputs,
    userNonce: nonce,
    inputsHash: fieldHex(inputsHash.toBigInt()),
    chainRequestId: fieldHex(id.toBigInt()),
  };
}

// ---- the app inputs and their order ----

// The bit length a leaf's value may have: null for a Field, else its bits
// (sidecar-core abi.rs Leaf).
function leafBits(leaf: AbiLeaf): number | null {
  switch (leaf.kind) {
    case "field":
      return null;
    case "boolean":
      return 1;
    case "string":
      return 8;
    case "integer":
      if (leaf.width === undefined) throw new RangeError("integer ABI type without a width");
      return leaf.width;
  }
}

/** One use of a request public name element by the ABI walk. */
export interface IntakeUse {
  /** The request public name. */
  name: string;
  /** The element index, for a name that fills a parameter wider than one. */
  index?: number;
  /** `name` or `name[index]`: the key the values are matched by. */
  key: string;
  /** The ABI parameter it fills. */
  param: string;
  /** The bit length the value may have; null for a Field (unchecked). */
  bits: number | null;
}

/** The app inputs of a tip circuit and their order: every use of a
 * request public name by the ABI walk, in walk order. The ABI-order inputs
 * are the distinct keys in order of first use. */
export interface IntakeLayout {
  circuit: string;
  /** The manifest's intake (its module: intakeModule). */
  intake: QueuedIntake;
  uses: IntakeUse[];
  /** The distinct keys in ABI order: what inputs_hash hashes, and under a
   * secret-shared intake the clear inputs the nodes range-check. */
  keys: string[];
  /** Every INPUT_SHARED name in ABI order, the reserved `$blinding`,
   * `$outcome_key` and `$outcome_tag` included: the shared inputs a secret-shared
   * intake request carries (none under the non-secret-shared intakes). */
  shared: string[];
  /** The names C commits to before the blinding, in the order the ABI walk
   * first meets each: every clear key, every INPUT_SHARED app input, and
   * `$outcome_key` and `$outcome_tag` (sidecar-tip receipt.rs
   * commitment_names). Under the non-secret-shared intakes it is `keys`. */
  commitment: string[];
  /** A non-secret-shared intake under `outcome: partial`: the app input
   * (the parameter's name) that carries the request's clear
   * `$partial_note`, which the request function computes from `rho`;
   * undefined otherwise. */
  partialNote?: string;
}

// The app inputs and their order, the rule of sidecar-tip's receipt.rs
// intake_inputs, which the node signs and the scheduler rebuilds the public
// map with. They are the values of the request public names the manifest's
// PUBLIC sources take, in the order the ABI walk first meets each name
// element (parameters in declaration order; `name[i]` in index order for a
// name that fills a wider parameter); a name used twice counts once. Not app
// inputs: `$namespace`, request keys, constants, the reserved operands
// `$vk_hash`, `$user_nonce` and `$new_leaf` (filled by the machine; the chain
// request id takes the first two beside inputs_hash), the parameters a
// pinned public read fills, and a tree's old hashes, siblings and indices
// (the scheduler fills them from the nodes' trees). This list is what
// inputs_hash hashes and what the app's request function takes as
// `[Field; N]`; the client, the nodes and the contract must walk it the same
// way, or every request id differs.
/** The intake layout of a tip circuit from its nargo output JSON (or its
 * `abi`), as sent to REGISTER, and its parsed manifest. RangeError when a
 * parameter has no witness entry, a PUBLIC list does not fill its parameter,
 * or a parameter is INPUT_SHARED under a non-secret-shared intake (which takes none;
 * REGISTER refuses it). */
export function intakeLayout(circuit: unknown, m: QueuedManifest): IntakeLayout {
  const abi = abiOf(circuit);
  // the pinned reads' parameters and a loaded tree's old hashes, siblings and
  // indices are filled by the machine, not app inputs
  const readParams = new Set([...m.publicReads.flatMap(publicReadParams), ...treeParams(m)]);
  const sources = new Map(m.witness.map((w) => [w.param, w.from]));
  const uses: IntakeUse[] = [];
  const shared: string[] = [];
  const walk: string[] = [];
  let partialNote: string | undefined;
  for (const p of abi.parameters) {
    const from = sources.get(p.name);
    if (from === undefined) throw new RangeError(`manifest.witness: parameter \`${p.name}\` has no witness entry`);
    if (readParams.has(p.name)) continue;
    if (Object.hasOwn(from, "INPUT_SHARED")) {
      if (!isSharedIntake(m.intake)) {
        throw new RangeError(
          `parameter \`${p.name}\` is INPUT_SHARED; intake ${m.intake} takes no shared input (REGISTER refuses it), a secret-shared intake does`,
        );
      }
      const name = String(from.INPUT_SHARED);
      shared.push(name);
      if (name !== BLINDING_NAME) walk.push(name);
      continue;
    }
    if (!Object.hasOwn(from, "PUBLIC")) continue;
    const ls = abiLeaves(p.type).map(leafBits);
    const src = from.PUBLIC;
    let operands: { op: unknown; index?: number }[];
    if (Array.isArray(src)) {
      if (src.length !== ls.length) {
        throw new RangeError(`parameter \`${p.name}\`: PUBLIC lists ${src.length} values for ${ls.length} elements`);
      }
      operands = src.map((op) => ({ op }));
    } else if (ls.length === 1) {
      operands = [{ op: src }];
    } else {
      operands = ls.map((_, i) => ({ op: src, index: i }));
    }
    operands.forEach(({ op, index }, i) => {
      // A request public name is a string not starting with `$`; a clear
      // partial note (`$partial_note`, a non-secret-shared intake under
      // `outcome: partial`) is an app input the user supplies
      // under the name of the parameter it fills, as the machine walks it;
      // `$namespace`, `$state_keys...`, the other reserved operands and `{const}`
      // are not app inputs.
      if (typeof op !== "string") return;
      const name = op === PARTIAL_NOTE_NAME ? p.name : op;
      if (op === PARTIAL_NOTE_NAME) partialNote = name;
      if (name.startsWith("$")) return;
      if (name.length === 0) throw new RangeError(`parameter \`${p.name}\`: an empty public name`);
      const use: IntakeUse = { name, key: index === undefined ? name : `${name}[${index}]`, param: p.name, bits: ls[i]! };
      if (index !== undefined) use.index = index;
      uses.push(use);
      walk.push(use.key);
    });
  }
  const keys: string[] = [];
  for (const u of uses) if (!keys.includes(u.key)) keys.push(u.key);
  const commitment: string[] = [];
  for (const k of walk) if (!commitment.includes(k)) commitment.push(k);
  return { circuit: m.circuit, intake: m.intake, uses, keys, shared, commitment, ...(partialNote !== undefined && { partialNote }) };
}

// The values flattened as an execute request's `public` map is: a one-element
// list is the name itself, a longer list `name[0]`, `name[1]`, ...
function flattenNamed(named: Record<string, FieldLike | readonly FieldLike[]>): Map<string, bigint> {
  const out = new Map<string, bigint>();
  const push = (key: string, v: FieldLike) => {
    if (out.has(key)) throw new RangeError(`inputs.${key}: duplicated after flattening lists`);
    out.set(key, fieldBigInt(v, `inputs.${key}`));
  };
  for (const [name, value] of Object.entries(named)) {
    if (name.length === 0 || name.startsWith("$")) throw new RangeError(`inputs.${name}: not a public value name`);
    if (Array.isArray(value)) {
      if (value.length === 0) throw new RangeError(`inputs.${name}: an empty list fills no parameter`);
      if (value.length === 1) push(name, value[0]!);
      else value.forEach((v: FieldLike, i: number) => push(`${name}[${i}]`, v));
    } else {
      push(name, value as FieldLike);
    }
  }
  return out;
}

/** How a secret-shared intake reads named inputs (splitNamedInputs). */
export interface NamedInputSplit {
  /** The names given as one shared field element each. */
  shared: readonly string[];
  /** The names the client defines itself, refused as inputs, and why. */
  defined: readonly string[];
  definedWhy: string;
  /** What a missing shared name is, for its error. */
  sharedNoun: string;
}

/** Split a secret-shared request's named inputs: the shared names one
 * field element each, the rest clear app inputs put in ABI order and
 * range-checked by the manifest (tipInputs). `values` holds the shared
 * values and the clear inputs by key. RangeError naming the input when one
 * is defined by the client, missing, or a list for a shared name. */
export function splitNamedInputs(
  layout: IntakeLayout,
  inputs: Record<string, FieldLike | readonly FieldLike[]>,
  split: NamedInputSplit,
): { values: Record<string, bigint>; clear: FieldHexString[] } {
  const clearNamed: Record<string, FieldLike | readonly FieldLike[]> = {};
  const values: Record<string, bigint> = {};
  for (const [name, value] of Object.entries(inputs)) {
    if (split.defined.includes(name)) throw new RangeError(`inputs.${name}: ${split.definedWhy}`);
    if (split.shared.includes(name)) {
      if (Array.isArray(value)) throw new RangeError(`inputs.${name}: a shared input is one field element`);
      values[name] = fieldBigInt(value as FieldLike, `inputs.${name}`);
    } else {
      clearNamed[name] = value;
    }
  }
  for (const name of split.shared) {
    if (!Object.hasOwn(values, name)) throw new RangeError(`inputs.${name}: missing (${split.sharedNoun})`);
  }
  const clear = tipInputs(layout, clearNamed);
  layout.keys.forEach((k, i) => (values[k] = BigInt(clear[i]!)));
  return { values, clear };
}

/** The app inputs in ABI order from named values (as an execute request's
 * `public` map spells them), with the manifest's typed range checks, the
 * node's static-validity check: every name present, none extra, each value
 * within its ABI leaf's bits. RangeError naming the input otherwise. */
export function tipInputs(layout: IntakeLayout, named: Record<string, FieldLike | readonly FieldLike[]>): FieldHexString[] {
  const given = flattenNamed(named);
  for (const u of layout.uses) {
    const v = given.get(u.key);
    if (v === undefined) throw new RangeError(`inputs.${u.key}: missing (parameter \`${u.param}\`)`);
    if (u.bits !== null && (v === 0n ? 0 : v.toString(2).length) > u.bits) {
      throw new RangeError(`parameter \`${u.param}\`: inputs.${u.key} does not fit in ${u.bits} bit(s)`);
    }
  }
  for (const k of given.keys()) {
    if (!layout.keys.includes(k)) throw new RangeError(`inputs.${k}: unexpected; circuit ${layout.circuit} takes ${JSON.stringify(layout.keys)}`);
  }
  return layout.keys.map((k) => fieldHex(given.get(k)!));
}

/** The inverse of tipInputs: the named map (`public`-map spelling) of
 * ABI-order inputs, as the receipt route takes them. */
export function tipInputsByName(layout: IntakeLayout, inputs: readonly FieldLike[]): Record<string, PublicValue> {
  if (inputs.length !== layout.keys.length) {
    throw new RangeError(`inputs: ${inputs.length} values, circuit ${layout.circuit} takes ${layout.keys.length}`);
  }
  const out: Record<string, PublicValue> = {};
  const lists = new Map<string, string[]>();
  layout.keys.forEach((k, i) => {
    const u = layout.uses.find((x) => x.key === k)!;
    const v = fieldHex(inputs[i]!, `inputs[${i}]`);
    if (u.index === undefined) out[u.name] = v;
    else (lists.get(u.name) ?? lists.set(u.name, []).get(u.name)!)[u.index] = v;
  });
  for (const [name, list] of lists) out[name] = list;
  return out;
}
