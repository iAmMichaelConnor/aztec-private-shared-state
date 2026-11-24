// On-chain intake on the client side: the IntakeModule `onchainIntake`, the
// arguments of the app's on-chain request function and the codec of the
// on-chain request log it emits (pss_public_contract intake.nr):
//
//   request log tag   = compute_log_tag(request_id, REQUEST_DOMAIN)
//   request log       = [tag, inputs..., user_nonce]   (no requester)
//
// testvectors/chain_request_id.json carries each case's request log.

import { Fr } from "@aztec-labs/aztec.js/fields";
import { computeLogTag } from "@aztec-labs/stdlib/hash";

import { ProtocolError } from "./errors.ts";
import { fieldBigInt, fieldHex, type FieldHexString, type FieldLike } from "./field.ts";
import type { IntakeModule } from "./intake.ts";
import { chainRequestId, tipInputsHash, type TipRequest } from "./tip.ts";
import { publicResults } from "./tip-result.ts";

// REQUEST_DOMAIN, the u32 separator of the on-chain request log's tag: ASCII
// "psrq" read big-endian, domains.nr's REQUEST_DOMAIN and
// testvectors/log_tags.json. A reader that tags with another value finds no
// request logs.
export const REQUEST_DOMAIN = 0x70737271;

/** A request's intake under on-chain intake: the tip request. */
export interface OnchainIntakeInput {
  intake: "onchain";
  request: TipRequest;
}

/** `(inputs, user_nonce)`: the arguments of an app's on-chain intake request function
 * (pss_public_contract_test's `request_onchain(app_inputs: [Field; N],
 * user_nonce: Field)`). */
export type OnchainIntakeArgs = [inputs: Fr[], userNonce: Fr];

/** The on-chain intake arguments of a tip request. */
export function onchainIntakeArgs(r: { inputs: readonly FieldLike[]; userNonce: FieldLike }): OnchainIntakeArgs {
  return [r.inputs.map((x, i) => new Fr(fieldBigInt(x, `inputs[${i}]`))), new Fr(fieldBigInt(r.userNonce, "user_nonce"))];
}

/** On-chain intake: the request function `(app_inputs, user_nonce)` logs the
 * inputs and the nonce, from which the nodes fill the round's private inputs;
 * the round outputs the chain request id over them, as under receipt
 * intake. Its intake is the tip request itself; it takes no receipts. */
export const onchainIntake: IntakeModule<OnchainIntakeInput> = {
  intake: "onchain",
  parameters: [["user_nonce", "field"]],
  results: publicResults,
  obtain: async (route) => ({ intake: "onchain", request: await route.tipRequest() }),
  intakeArgs: (intake) => onchainIntakeArgs(intake.request),
  summary: ({ request }) => ({ chainRequestId: request.chainRequestId, values: request.inputs, userNonce: request.userNonce, privateValues: [] }),
  requestLogs: async ({ request }) => [[fieldHex((await computeRequestLogTag(request.chainRequestId)).toBigInt()), ...request.inputs, request.userNonce]],
};

// ---- the request log ----

/** The tag of the on-chain request log of `requestId`:
 * `compute_log_tag(request_id, REQUEST_DOMAIN)`, the first log field. */
export async function computeRequestLogTag(requestId: FieldLike): Promise<Fr> {
  return computeLogTag(new Fr(fieldBigInt(requestId, "request_id")), REQUEST_DOMAIN as never);
}

/** An on-chain request log, read. */
export interface PlainRequestLog {
  tag: FieldHexString;
  inputs: FieldHexString[];
  userNonce: FieldHexString;
  /** With the namespace and vk hash given: the recomputed hashes. */
  inputsHash?: FieldHexString;
  requestId?: FieldHexString;
}

export interface PlainRequestLogContext {
  /** The emitting contract: the namespace. */
  namespace: FieldLike;
  /** The circuit's pinned vk hash. */
  vkHash: FieldLike;
}

/** Read an on-chain request log, `[tag, inputs..., user_nonce]` (intake.nr's
 * layout; N = fields.length - 2 inputs, or `inputCount` and then exactly that
 * many fields). With `context`, recompute inputs_hash and the request id and
 * check that the tag is computeRequestLogTag(request id) (ProtocolError
 * otherwise), as the chain reader does. */
export async function parsePlainRequestLog(
  fields: readonly FieldLike[],
  context?: PlainRequestLogContext,
  inputCount?: number,
): Promise<PlainRequestLog> {
  if (fields.length < 2) throw new ProtocolError(`request log: ${fields.length} fields, at least 2 (tag, user_nonce)`);
  if (inputCount !== undefined && fields.length !== inputCount + 2) {
    throw new ProtocolError(`request log: ${fields.length} fields, expected ${inputCount + 2} for ${inputCount} inputs`);
  }
  const hex = fields.map((x, i) => {
    try {
      return fieldHex(x, `fields[${i}]`);
    } catch (e) {
      throw new ProtocolError(`request log: ${(e as Error).message}`);
    }
  });
  const n = hex.length - 2;
  const log: PlainRequestLog = { tag: hex[0]!, inputs: hex.slice(1, 1 + n), userNonce: hex[n + 1]! };
  if (context) {
    const inputsHash = await tipInputsHash(log.inputs);
    const id = await chainRequestId(context.namespace, context.vkHash, inputsHash, log.userNonce);
    const tag = fieldHex((await computeRequestLogTag(id)).toBigInt());
    if (tag !== log.tag) throw new ProtocolError(`request log: tag ${log.tag} is not the tag ${tag} of the request id ${fieldHex(id.toBigInt())}`);
    log.inputsHash = fieldHex(inputsHash.toBigInt());
    log.requestId = fieldHex(id.toBigInt());
  }
  return log;
}
