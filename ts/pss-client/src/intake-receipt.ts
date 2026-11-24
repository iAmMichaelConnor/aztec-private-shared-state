// Receipt intake on the client side: the IntakeModule `receiptIntake`, the
// receipts and their check, and the arguments of the app's receipt request
// function (pss_public_contract receipt.nr; sidecar-tip receipt.rs):
//
//   receipt message   = poseidon2([RECEIPT_DOMAIN, request_id, inputs_hash, expiry_block])
//
// Secret-shared receipt intake's receipts sign five elements, C for
// inputs_hash and the sharing digest D last (sharedReceiptMessage).

import { poseidon2Hash } from "@aztec-labs/foundation/crypto/poseidon";
import { Fr } from "@aztec-labs/foundation/curves/bn254";

import { ProtocolError, ReceiptSignatureError } from "./errors.ts";
import { fieldBigInt, fieldFr, fieldHex, u32, type FieldHexString, type FieldLike } from "./field.ts";
import type { IntakeModule, IntakeRoute } from "./intake.ts";
import { onchainIntakeArgs } from "./intake-onchain.ts";
import { failingNode } from "./signing.ts";
import { tipInputsByName } from "./tip.ts";
import { publicResults } from "./tip-result.ts";
import { NODES, type ReceiptRequestBody, type ReceiptResponse, type Signature, type Triple } from "./wire.ts";
import { asciiLabel } from "./labels.ts";

// RECEIPT_DOMAIN, the first element of every receipt message: ASCII
// "sidecar.receipt" read as a big-endian integer, the value of sidecar-tip's
// receipt.rs and pss_public_contract's domains.nr. It keeps a receipt from
// verifying as a result or registry signature by the same node sig key.
// Changing it on one side makes every receipt fail the client's check and the
// contract's.
export const RECEIPT_DOMAIN = asciiLabel("sidecar.receipt");

/** A request's intake under receipt intake: the checked receipts. */
export interface ReceiptIntakeInput {
  intake: "receipt";
  receipts: TipReceipts;
}

/** Receipt intake: the request function `(app_inputs, user_nonce,
 * expiry_block, receipts)` checks the nodes' receipts, which the client
 * obtains through the orchestrator; the nodes keep the inputs for the round,
 * which outputs the chain request id over them. Only the request id and the
 * expiry reach the chain. */
export const receiptIntake: IntakeModule<ReceiptIntakeInput> = {
  intake: "receipt",
  parameters: [["user_nonce", "field"], ["expiry_block", "integer"], ["receipts", "array"]],
  results: publicResults,
  async obtain(route, ask) {
    const keys = await route.receiptKeys();
    const current = u32(ask.currentBlock, "currentBlock", "block number");
    const req = await route.tipRequest();
    const body: ReceiptRequestBody = {
      namespace: req.namespace,
      circuit: ask.circuit,
      inputs: tipInputsByName(route.layout, req.inputs),
      user_nonce: req.userNonce,
      current_block: current,
    };
    const receipts = await obtainReceipts(route, keys, body, { requestId: req.chainRequestId, inputsHash: req.inputsHash, currentBlock: current, signs: receiptMessage }, (answer) =>
      new TipReceipts({
        namespace: req.namespace,
        circuit: ask.circuit,
        requestId: answer.request_id,
        inputsHash: answer.inputs_hash,
        expiryBlock: answer.expiry_block,
        receipts: answer.signatures,
        inputs: req.inputs,
        userNonce: req.userNonce,
        marginBlocks: route.marginBlocks,
      }),
    );
    return { intake: "receipt", receipts };
  },
  intakeArgs({ receipts }, options) {
    refuseExpiring(receipts, options.currentBlock);
    return receipts.intakeArgs();
  },
  summary: ({ receipts }) => ({
    chainRequestId: receipts.requestId,
    values: receipts.inputs,
    userNonce: receipts.userNonce,
    expiryBlock: receipts.expiryBlock,
    privateValues: [...receipts.inputs.map((v, k): [string, FieldHexString] => [`inputs[${k}]`, v]), ["user_nonce", receipts.userNonce]],
  }),
  requestLogs: async () => [],
};

/** RangeError when `currentBlock` is given and receipts sent at it may land
 * too late (expiresSoon): ask again. */
export function refuseExpiring(receipts: Receipts<unknown>, currentBlock: number | undefined): void {
  if (currentBlock !== undefined && receipts.expiresSoon(currentBlock)) {
    throw new RangeError(`receipts for ${receipts.requestId} expire at block ${receipts.expiryBlock}, too soon after ${currentBlock}; ask again`);
  }
}

// ---- receipts ----

/** The receipt message's first four elements. */
function receiptPreimage(requestId: FieldLike, inputsHash: FieldLike, expiryBlock: number): Fr[] {
  return [
    new Fr(RECEIPT_DOMAIN),
    new Fr(fieldBigInt(requestId, "request_id")),
    new Fr(fieldBigInt(inputsHash, "inputs_hash")),
    new Fr(BigInt(u32(expiryBlock, "expiry_block", "block number"))),
  ];
}

/** The message every node signs for a receipt:
 * `poseidon2([RECEIPT_DOMAIN, request_id, inputs_hash, expiry_block])`. */
export async function receiptMessage(requestId: FieldLike, inputsHash: FieldLike, expiryBlock: number): Promise<Fr> {
  return poseidon2Hash(receiptPreimage(requestId, inputsHash, expiryBlock));
}

/** How an intake's receipts sign: the message over the request id, its
 * inputs hash (C under secret-shared receipt intake) and the expiry block.
 * Receipt intake's is receiptMessage; secret-shared receipt intake's binds
 * the request's sharing digest (sharedReceiptMessageOf). */
export type ReceiptMessage = (requestId: FieldLike, inputsHash: FieldLike, expiryBlock: number) => Promise<Fr>;

/** Secret-shared receipt intake's ReceiptMessage for a request of sharing
 * digest `sharingDigest`: sharedReceiptMessage over it. */
export function sharedReceiptMessageOf(sharingDigest: FieldLike): ReceiptMessage {
  return (requestId, c, expiryBlock) => sharedReceiptMessage(requestId, c, expiryBlock, sharingDigest);
}

/** The message every node signs under secret-shared receipt intake:
 * `poseidon2([RECEIPT_DOMAIN, request_id, C, expiry_block, D])`, `D` the
 * sharing digest (tip.ts sharingDigest) over the summand commitments the
 * node checked its envelopes against, the layout and the clear inputs it
 * stores (pss_public_contract receipt.nr
 * shared_receipt_message). Five elements, so it is never a receipt intake
 * message. */
export async function sharedReceiptMessage(requestId: FieldLike, c: FieldLike, expiryBlock: number, sharingDigest: FieldLike): Promise<Fr> {
  return poseidon2Hash([...receiptPreimage(requestId, c, expiryBlock), new Fr(fieldBigInt(sharingDigest, "sharing_digest"))]);
}

/** Check three receipts: receipt i must verify under `sigKeys[i]` (the
 * contract's current set, never keys a server reports) over the intake's
 * receipt message (`signs`: receiptMessage, or sharedReceiptMessageOf the
 * request's sharing digest with C as `inputsHash`), so each counts only in
 * its own node's position, as the contract's check_receipts (signing.ts
 * failingNode). Throws ReceiptSignatureError naming the first node whose
 * receipt does not verify. */
export async function verifyReceipts(
  requestId: FieldLike,
  inputsHash: FieldLike,
  expiryBlock: number,
  receipts: Triple<Signature>,
  sigKeys: Triple<{ x: FieldLike; y: FieldLike }>,
  signs: ReceiptMessage,
): Promise<void> {
  const message = (await signs(requestId, inputsHash, expiryBlock)).toBigInt();
  const failed = await failingNode([message, message, message], receipts, [sigKeys]);
  if (failed !== undefined) throw new ReceiptSignatureError(failed, fieldHex(requestId, "request_id"));
}

/** What the client asked for and expects the receipt answer to carry. */
export interface ReceiptExpectation {
  requestId: FieldLike;
  inputsHash: FieldLike;
  /** The block the client sent as `current_block`. */
  currentBlock: number;
  /** The most blocks after currentBlock the client accepts an expiry at. */
  ttlBlocks: number;
  /** The message the intake's receipts sign (verifyReceipts). */
  signs: ReceiptMessage;
}

/** Check an orchestrator's receipt answer against the client's own
 * recomputation: the same request_id and inputs_hash (ProtocolError
 * otherwise), an expiry after currentBlock and at most ttlBlocks after it
 * (ProtocolError otherwise), and the three signatures under the contract's
 * current sig keys over the intake's receipt message (`expected.signs`;
 * ReceiptSignatureError naming the node). */
export async function checkReceiptAnswer(
  answer: ReceiptResponse,
  expected: ReceiptExpectation,
  sigKeys: Triple<{ x: FieldLike; y: FieldLike }>,
): Promise<void> {
  const id = fieldHex(expected.requestId, "request_id");
  if (answer.request_id !== id) throw new ProtocolError(`receipt answer: request_id ${answer.request_id}, the client computes ${id}`);
  const ih = fieldHex(expected.inputsHash, "inputs_hash");
  if (answer.inputs_hash !== ih) throw new ProtocolError(`receipt answer: inputs_hash ${answer.inputs_hash}, the client computes ${ih}`);
  const current = u32(expected.currentBlock, "current_block", "block number");
  if (answer.expiry_block <= current) {
    throw new ProtocolError(`receipt answer: expiry_block ${answer.expiry_block} is not after the current block ${current}`);
  }
  if (answer.expiry_block - current > expected.ttlBlocks) {
    throw new ProtocolError(
      `receipt answer: expiry_block ${answer.expiry_block} is ${answer.expiry_block - current} blocks after the current block ${current}; ` +
        `the configuration accepts at most ${expected.ttlBlocks}`,
    );
  }
  await verifyReceipts(id, ih, answer.expiry_block, answer.signatures, sigKeys, expected.signs);
}

/** Send a receipt request body after the node key check and check the
 * answer against what the client computed (checkReceiptAnswer under the
 * route's TTL and sig keys); `make` keeps the checked answer. */
export async function obtainReceipts<R>(
  route: Pick<IntakeRoute, "send" | "ttlBlocks">,
  keys: Awaited<ReturnType<IntakeRoute["receiptKeys"]>>,
  body: Parameters<IntakeRoute["send"]>[0],
  expected: Omit<ReceiptExpectation, "ttlBlocks">,
  make: (answer: ReceiptResponse) => R,
): Promise<R> {
  await keys.checkNodes();
  const answer = await route.send(body);
  await checkReceiptAnswer(answer, { ...expected, ttlBlocks: route.ttlBlocks }, keys.sigKeys);
  return make(answer);
}

/** Three checked receipts of either receipt intake: the expiry, the
 * signatures and the margin, and the arguments of the app's request
 * function (`A`). */
export abstract class Receipts<A> {
  /** The chain request id the three nodes signed. */
  abstract readonly requestId: FieldHexString;
  /** The intake transaction must land in a block below this. */
  readonly expiryBlock: number;
  /** Node 0's first, each checked under its node's sig key. */
  readonly receipts: Triple<Signature>;
  /** The default margin of expiresSoon (the configuration's). */
  readonly marginBlocks: number;

  constructor(expiryBlock: number, receipts: Triple<Signature>, marginBlocks: number) {
    this.expiryBlock = u32(expiryBlock, "expiry_block", "block number");
    this.receipts = receipts;
    this.marginBlocks = marginBlocks;
  }

  /** Whether an intake transaction sent at `currentBlock` may land too late:
   * `currentBlock + marginBlocks >= expiryBlock`. Then ask again for a later
   * expiry under the same request id (PssClient.obtainIntake with the same
   * userNonce, or with the same `request` under secret-shared receipt
   * intake). */
  expiresSoon(currentBlock: number, marginBlocks = this.marginBlocks): boolean {
    return u32(currentBlock, "currentBlock", "block number") + marginBlocks >= this.expiryBlock;
  }

  /** The arguments of the app's request function. */
  abstract intakeArgs(): A;
}

/** A receipt in the Noir `Receipt` shape {s: [lo, hi], e: [lo, hi]}, as
 * aztec.js encodes it for a request function's `receipts: [Receipt; 3]`. */
export interface NoirReceipt {
  s: [Fr, Fr];
  e: [Fr, Fr];
}

/** Three checked receipts for one tip request, with what the app's receipt intake
 * request function needs. */
export class TipReceipts extends Receipts<ReceiptIntakeArgs> {
  readonly namespace: FieldHexString;
  readonly circuit: string;
  readonly requestId: FieldHexString;
  readonly inputsHash: FieldHexString;
  /** The app inputs in ABI order. */
  readonly inputs: FieldHexString[];
  readonly userNonce: FieldHexString;

  constructor(v: Omit<TipReceipts, "expiresSoon" | "intakeArgs">) {
    super(v.expiryBlock, v.receipts, v.marginBlocks);
    this.namespace = v.namespace;
    this.circuit = v.circuit;
    this.requestId = v.requestId;
    this.inputsHash = v.inputsHash;
    this.inputs = v.inputs;
    this.userNonce = v.userNonce;
  }

  intakeArgs(): ReceiptIntakeArgs {
    return receiptIntakeArgs(this);
  }
}

// ---- the request function's arguments ----

/** `(inputs, user_nonce, expiry_block, receipts)`: the arguments of an app's
 * receipt intake request function (`request_with_receipts(app_inputs: [Field; N],
 * user_nonce: Field, expiry_block: u32, receipts: [Receipt; 3])`). */
export type ReceiptIntakeArgs = [inputs: Fr[], userNonce: Fr, expiryBlock: number, receipts: Triple<NoirReceipt>];

/** A wire signature in the Noir Receipt shape. */
export function noirReceipt(sig: Signature): NoirReceipt {
  return { s: [fieldFr(sig.s[0], "s[0]"), fieldFr(sig.s[1], "s[1]")], e: [fieldFr(sig.e[0], "e[0]"), fieldFr(sig.e[1], "e[1]")] };
}

/** The receipt intake arguments: the inputs and nonce the receipts were obtained for,
 * their expiry block and the three receipts, node 0's first. */
export function receiptIntakeArgs(r: {
  inputs: readonly FieldLike[];
  userNonce: FieldLike;
  expiryBlock: number;
  receipts: Triple<Signature>;
}): ReceiptIntakeArgs {
  if (!Array.isArray(r.receipts) || r.receipts.length !== NODES) throw new RangeError(`receipts: expected ${NODES}, node 0 first`);
  const [inputs, nonce] = onchainIntakeArgs(r);
  return [inputs, nonce, u32(r.expiryBlock, "expiry_block", "block number"), r.receipts.map(noirReceipt) as Triple<NoirReceipt>];
}
