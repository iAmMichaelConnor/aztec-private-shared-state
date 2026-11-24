// The queued intakes on the client side: one IntakeModule per value of the
// manifest's `intake` that queues a request at the tip, and intakeModule, the
// one place that maps the manifest's value to its module:
//
//   onchain          intake-onchain.ts          the request function puts the
//                                               app inputs in the clear on the chain
//   receipt          intake-receipt.ts          the nodes sign receipts for the
//                                               request off the chain
//   shared_receipt   intake-shared-receipt.ts   the inputs secret-shared to the
//                                               nodes, their receipts over C
//                                               and the sharing's digest D
//   shared_onchain   intake-shared-onchain.ts   the inputs encoded under the
//                                               nodes' stored enc keys into a
//                                               private request log
//
// A module obtains a request's intake from an ask (the tip request, and the
// receipts where its intake takes them), gives the request function's
// arguments and the parameters they end in, says what the request is (its
// chain request id, its values, what it keeps off the chain) and which public
// logs its request function emits, and names the form its rounds' results
// take (result.ts: public results under the non-secret-shared intakes, private outcomes
// under the secret-shared ones), from which the configuration picks each circuit's
// result reader. Layouts carry the value; code that obtains or sends an
// intake or reads a result asks the value's module or reader and never
// compares the value itself. Relayed intake is deferred.
//
// The modules give the request function's arguments in one order: the values
// (the app inputs; under a secret-shared intake C's values) as one array, then the
// intake's own arguments. layIntakeArgs lays them onto the function's ABI
// parameters, so an app's request function may take its values as one array
// or one by one.

import { Fr } from "@aztec-labs/foundation/curves/bn254";
import type { FunctionAbi } from "@aztec-labs/stdlib/abi";

import { abiArg, abiWidth, type AbiType } from "./abi.ts";
import { ConfigError } from "./errors.ts";
import { type FeeSetting, SEND_WAIT, txSendOptions } from "./fee.ts";
import { fieldBigInt, type FieldHexString, type FieldLike } from "./field.ts";
import { onchainIntake, type OnchainIntakeInput } from "./intake-onchain.ts";
import { receiptIntake, type ReceiptIntakeInput } from "./intake-receipt.ts";
import { sharedOnchainIntake, type EncKeyInput, type SharedOnchainIntakeInput, type SharedOnchainRandomness } from "./intake-shared-onchain.ts";
import {
  sharedReceiptIntake,
  type SharedReceiptIntakeInput,
  type SharedReceiptRandomness,
  type SharedReceiptRequest,
  type SharedReceiptRequestBody,
} from "./intake-shared-receipt.ts";
import type { QueuedIntake } from "./manifest.ts";
import type { ResultForm } from "./result.ts";
import type { IntakeLayout, SharedSecrets, TipRequest } from "./tip.ts";
import type { GrumpkinPoint, ReceiptRequestBody, ReceiptResponse, Triple } from "./wire.ts";

/** What PssClient.obtainIntake asks for: a request of a configured tip
 * circuit, through the intake its manifest names. */
export interface IntakeAsk {
  circuit: string;
  /** The block the client last saw, which the orchestrator counts a
   * receipt's expiry from; an intake that takes receipts needs it. */
  currentBlock?: number;
  /** The app inputs by name: under the non-secret-shared intakes by public name (the
   * `public`-map spelling: one value, or a list for a name that fills an
   * array parameter); under a secret-shared intake every app input, clear or
   * INPUT_SHARED (buildSharedReceiptRequest). Not needed with `request`. */
  inputs?: Record<string, FieldLike | FieldLike[]>;
  /** The non-secret-shared intakes: default a fresh newUserNonce(). Give the earlier
   * one to ask again for receipts under the same request id. */
  userNonce?: FieldLike;
  /** Secret-shared receipt intake: an earlier request of this circuit
   * (SharedReceipts.request), to ask again under a later expiry with the
   * same id and envelopes. */
  request?: SharedReceiptRequest;
  /** The app's static check, as the contract's request function asserts it:
   * over the app inputs in ABI order, under a secret-shared intake over C's values. */
  isValid?: (values: readonly bigint[]) => boolean;
  /** The nodes' enc keys and epochs the app contract stores
   * (`SharedOnchain.enc_keys`), node 0 first, as the request function will
   * read them at the anchor block it is proven against; or a reader of
   * them, called only by an intake that encodes under them (secret-shared
   * on-chain). Reading them is the caller's. */
  encKeys?: Triple<EncKeyInput> | (() => Promise<Triple<EncKeyInput>>);
  /** The request's derived outcome key and tag with a fresh blinding
   * (SecretStore.next): secret-shared receipt intake takes all three
   * (default drawn), secret-shared on-chain intake the key and tag where
   * the inputs name none (its encoding defines the blinding), the others
   * none. */
  secrets?: SharedSecrets;
  /** The secret-shared intakes: known answers, for tests; a client leaves them out. */
  randomness?: SharedReceiptRandomness & SharedOnchainRandomness;
  /** Default: the configured contract address. */
  namespace?: FieldLike;
  /** Default: the configured request timeout. */
  timeoutMs?: number;
}

/** What the client gives an intake module to obtain an intake with. */
export interface IntakeRoute {
  /** The circuit's intake layout. */
  layout: IntakeLayout;
  /** The ask's namespace and the circuit's pinned vk hash. */
  namespace: FieldHexString;
  vkHash: FieldHexString;
  /** The non-secret-shared tip request of the ask (PssClient.tipRequest). */
  tipRequest(): Promise<TipRequest>;
  /** The contract's current key set for receipts (the pinned keys at epoch 0)
   * and the check against the orchestrator's keys before sending. */
  receiptKeys(): Promise<{
    encKeys: Triple<GrumpkinPoint>;
    sigKeys: Triple<GrumpkinPoint>;
    checkNodes(): Promise<void>;
  }>;
  /** POST /v1/receipt, parsed. */
  send(body: ReceiptRequestBody | SharedReceiptRequestBody): Promise<ReceiptResponse>;
  /** The configuration's receiptTtlBlocks and receiptMarginBlocks. */
  ttlBlocks: number;
  marginBlocks: number;
}

/** What a request is, whatever its intake. */
export interface IntakeSummary {
  /** The chain request id the queue holds. */
  chainRequestId: FieldHexString;
  /** The values the request function takes first, in IntakeLayout.commitment
   * order: the app inputs, under a secret-shared intake C's values. */
  values: FieldHexString[];
  /** The non-secret-shared intakes' user nonce. */
  userNonce?: FieldHexString;
  /** An intake with receipts: the intake transaction must land in a block
   * below this. */
  expiryBlock?: number;
  /** A secret-shared intake: the outcome key and tag the client drew, which open
   * and find the request's outcome log. */
  outcomeKey?: FieldHexString;
  outcomeTag?: FieldHexString;
  /** What the request keeps off the chain, by name: nothing under on-chain
   * intake; the app inputs and the nonce under receipt intake; C's values
   * (the outcome key and tag among them), the blinding and the sharing's
   * summands and salts under secret-shared receipt intake; the shared
   * values (the outcome key and tag among them), the blinding and the
   * ephemeral secret under secret-shared on-chain intake. */
  privateValues: [name: string, value: FieldHexString][];
}

/** One queued intake: everything about a tip request that depends on how
 * the request reaches the chain. `I` is the intake as obtainIntake gives it
 * and submitIntake takes it. */
export interface IntakeModule<I extends { intake: QueuedIntake } = RequestIntake> {
  /** The manifest's `intake` value. */
  readonly intake: I["intake"];
  /** The parameters a request function ends in under this intake, after the
   * ones that take the values, by name and ABI kind (layIntakeArgs). */
  readonly parameters: readonly (readonly [name: string, kind: string])[];
  /** A request's intake from an ask, through `route`: the tip request, or
   * the three nodes' checked receipts for it. */
  obtain(route: IntakeRoute, ask: IntakeAsk): Promise<I>;
  /** The request function's arguments in the modules' order (RangeError for
   * receipts that expiresSoon at options.currentBlock, when given). */
  intakeArgs(intake: I, options: SubmitOptions): unknown[];
  /** What the request is. */
  summary(intake: I): IntakeSummary;
  /** The public logs the request function emits, as fields, in order. */
  requestLogs(intake: I): Promise<FieldHexString[][]>;
  /** The form its rounds' results take. */
  readonly results: ResultForm;
}

/** A request's intake, one form per queued intake, `intake` naming it: what
 * obtainIntake gives and submitIntake takes. */
export type RequestIntake = OnchainIntakeInput | ReceiptIntakeInput | SharedReceiptIntakeInput | SharedOnchainIntakeInput;

const MODULES: { readonly [K in QueuedIntake]: IntakeModule<Extract<RequestIntake, { intake: K }>> } = {
  onchain: onchainIntake,
  receipt: receiptIntake,
  shared_receipt: sharedReceiptIntake,
  shared_onchain: sharedOnchainIntake,
};

/** The module of a queued intake value. */
export function intakeModule(intake: QueuedIntake): IntakeModule {
  if (!Object.hasOwn(MODULES, intake)) throw new ConfigError(`intake ${intake}: not a queued intake`);
  return MODULES[intake] as IntakeModule;
}

/** What `intake` is (its module's summary). */
export function intakeSummary(intake: RequestIntake): IntakeSummary {
  return intakeModule(intake.intake).summary(intake);
}

/** The public logs `intake`'s request function emits (its module's). */
export function intakeRequestLogs(intake: RequestIntake): Promise<FieldHexString[][]> {
  return intakeModule(intake.intake).requestLogs(intake);
}

// ---- sending ----

/** What an aztec.js ContractFunctionInteraction offers for sending. */
export interface SendableInteraction<R = unknown> {
  send(options: IntakeSendOptions): Promise<R>;
}

/** The send options; `from` is any account: no request names its sender
 * (docs/ARCHITECTURE.md section 6, "The hidden requester"), so a fresh
 * account keeps a user's requests unlinked. */
export interface IntakeSendOptions {
  from: { toBigInt(): bigint } | FieldLike;
  [option: string]: unknown;
}

/** An app's request function: a factory of interactions from arguments, as
 * `contract.methods.request_onchain` is, or a contract and a method name.
 * A contract that carries its artifact, as an aztec.js Contract does, gets
 * the arguments laid onto the method's parameters (layIntakeArgs); a
 * factory gets them in the modules' order. */
export type IntakeTarget<R = unknown> =
  | ((...args: never[]) => SendableInteraction<R>)
  | {
      contract: {
        methods: Record<string, (...args: never[]) => SendableInteraction<R>>;
        artifact?: { functions: readonly FunctionAbi[] };
      };
      method: string;
    };

/** A request function's arguments already laid onto its parameters, sent
 * as given: an earlier request's, sent again. */
export interface LaidIntake {
  args: readonly unknown[];
}

export interface SubmitOptions {
  /** An intake with receipts: refuse to send when they expiresSoon at this block. */
  currentBlock?: number;
  /** The fee setting a request pays under when `sendOptions` carries no
   * `fee`; default DEFAULT_FEE_SETTING (wFJ). */
  fee?: FeeSetting;
  /** Values sent in place of the intake's, by their position among the
   * values the request function takes first (IntakeLayout.commitment
   * order): for a request function that takes a private value where the
   * request holds a value derived from it (`rho` in the place of
   * `$partial_note`). PssClient.requestIntake takes them by name. Not with
   * laid arguments. */
  valuesAt?: Readonly<Record<number, FieldLike>>;
  /** Arguments the request function takes after its intake's own, laid as
   * given: the app's (e.g. lending's authwit nonces of its token transfers,
   * `nonces: { escrow, deposit }`). Default none. */
  after?: readonly unknown[];
}

/** One intake transaction, its arguments laid and ready to send. */
export interface IntakeCall<R> {
  /** The request function's arguments, as sent. */
  args: unknown[];
  /** Send them through aztec.js with the default fee unless `sendOptions`
   * carries one (submitIntake). */
  send(sendOptions: IntakeSendOptions): Promise<R>;
}

/** The intake transaction of `intake` to `target`: the arguments of the
 * intake's module (intakeArgs, with options.valuesAt in place of the
 * values it names), laid onto the method's parameters when the target's
 * contract carries its artifact; or laid arguments as given. */
export function intakeCall<R>(target: IntakeTarget<R>, intake: RequestIntake | LaidIntake, options: SubmitOptions = {}): IntakeCall<R> {
  let method: (...args: never[]) => SendableInteraction<R>;
  let fn: Pick<FunctionAbi, "name" | "parameters"> | undefined;
  if (typeof target === "function") {
    method = target;
  } else {
    const m = target.contract.methods[target.method];
    if (typeof m !== "function") throw new RangeError(`the contract has no method ${target.method}`);
    method = m;
    fn = target.contract.artifact?.functions.find((f) => f.name === target.method);
  }
  let args: unknown[];
  if ("args" in intake) {
    if (options.valuesAt !== undefined) throw new RangeError("laid arguments take no values in place of the intake's (valuesAt)");
    args = [...intake.args];
  } else {
    const order = withValues(intakeArgs(intake, options), options.valuesAt);
    args = fn === undefined ? [...order, ...(options.after ?? [])] : layIntakeArgs(fn, intake.intake, order, options.after);
  }
  return {
    args,
    async send(sendOptions) {
      // `fee` is taken out before the spread: an own `fee: undefined` would
      // otherwise overwrite the default and make the sender the fee payer.
      // The wait is SEND_WAIT unless the caller gives its own.
      const { fee, ...rest } = sendOptions;
      const base = fee === undefined ? await txSendOptions(options.fee, "request") : { wait: SEND_WAIT, fee };
      const interaction = (method as (...a: unknown[]) => SendableInteraction<R>)(...args);
      return interaction.send({ ...base, ...rest });
    },
  };
}

// An intake with receipts refuses when options.currentBlock is given and the
// receipts expiresSoon. The sender is not checked: the request id names no
// requester, so any account sends the same request. A repeated request id is
// not checked here: append() reverts on it, under every intake.
/** Build the request function's arguments for `intake` (intakeCall: its
 * module's arguments, laid onto the method's parameters when the target's
 * contract carries its artifact), or take laid arguments as given, and send
 * them through aztec.js: `target(...args).send(sendOptions)`, the way the
 * drivers send transactions (`contract.methods.f(...).send({ from })`).
 * Returns what send returns (by default the mined receipt).
 *
 * The fee: a `fee` in `sendOptions` is sent as given. Without one (absent
 * or undefined), the
 * request pays under `options.fee` (default wFJ, feeOptions of a
 * "request"), never the wallet's own fee payment, which would name its
 * sender as fee payer (docs/ARCHITECTURE.md section 6, "Fee payment"). */
export async function submitIntake<R>(
  target: IntakeTarget<R>,
  intake: RequestIntake | LaidIntake,
  sendOptions: IntakeSendOptions,
  options: SubmitOptions = {},
): Promise<R> {
  return intakeCall(target, intake, options).send(sendOptions);
}

/** The request function's arguments for `intake` in the modules' order: the
 * values (C's values under a secret-shared intake) as one array, then the intake's
 * own (RangeError for receipts that expiresSoon at options.currentBlock,
 * when given). */
export function intakeArgs(intake: RequestIntake, options: SubmitOptions = {}): unknown[] {
  return intakeModule(intake.intake).intakeArgs(intake, options);
}

/** `args` with `valuesAt` in place of the values at those positions. */
function withValues(args: unknown[], valuesAt: Readonly<Record<number, FieldLike>> | undefined): unknown[] {
  if (valuesAt === undefined) return args;
  const values = [...(args[0] as readonly unknown[])];
  for (const [at, v] of Object.entries(valuesAt)) {
    const k = Number(at);
    if (!Number.isInteger(k) || k < 0 || k >= values.length) throw new RangeError(`valuesAt[${at}]: the request function takes ${values.length} values`);
    values[k] = new Fr(fieldBigInt(v, `valuesAt[${at}]`));
  }
  return [values, ...args.slice(1)];
}

// ---- the request function's parameters ----

// An app's request function ends in its intake's parameters under these
// names, after the parameters that take the app inputs (C's values under
// secret-shared receipt intake), which it may take as one array or one by one. The
// names default to those of pss_public_contract's examples and of both tip
// apps. A function named otherwise is refused by layIntakeArgs (and so by
// submitIntake's contract form); its sender lays the arguments itself or
// sends the modules' order through the factory form.
// The parameters a request function ends with under each intake, by name
// and ABI kind, are its module's `parameters` (pss_public_contract
// intake.nr, receipt.nr and shared_intake.nr): on-chain intake `(...,
// user_nonce)`, receipt intake `(..., user_nonce, expiry_block, receipts:
// [Receipt; 3])`, secret-shared receipt intake `(..., sharing: Sharing<L>,
// expiry_block, receipts: [Receipt; 3])`, secret-shared on-chain intake `(..., eph)`
// (shared_onchain.nr).

/** Lay `args`, an intake's arguments in the modules' order (the values as one
 * array, then the intake's own), onto `fn`'s parameters: the intake's own
 * are the function's last parameters, checked by name and kind (the
 * module's `parameters`); the parameters before them take the values in
 * order, each as many as its ABI type flattens to, shaped as aztec.js encodes
 * that type (one array parameter takes them as a list, `request_onchain(app_inputs:
 * [Field; N], user_nonce)`; scalar parameters one each, AmmTip's
 * `swap(amount_in, direction, min_out, user_nonce)` and lending's
 * `deposit_shared(position, amount, rho, outcome_key, outcome_tag, sharing,
 * expiry_block, receipts)`; an address struct an AztecAddress).
 * `after`, the app's arguments past the intake's own (e.g. lending's
 * `nonces`), are the function's last parameters, laid as given. RangeError
 * naming the function when the parameters do not end in the intake's (then
 * `after`), or their widths do not add up to the values. */
export function layIntakeArgs(
  fn: Pick<FunctionAbi, "name" | "parameters">,
  intake: QueuedIntake,
  args: readonly unknown[],
  after: readonly unknown[] = [],
): unknown[] {
  const own = intakeModule(intake).parameters;
  const [values, ...rest] = args as [readonly Fr[], ...unknown[]];
  if (!Array.isArray(values) || rest.length !== own.length) throw new RangeError(`${fn.name}: ${intake} intake arguments are the values and ${own.length} more`);
  const lead = fn.parameters.length - own.length - after.length;
  const tail = fn.parameters.slice(Math.max(lead, 0), fn.parameters.length - after.length);
  const ends = own.map(([n, k]) => `${n}: ${k}`).join(", ");
  if (lead < 0 || tail.some((p, i) => p.name !== own[i]![0] || p.type.kind !== own[i]![1])) {
    throw new RangeError(`${fn.name}: its parameters (${fn.parameters.map((p) => `${p.name}: ${p.type.kind}`).join(", ")}) do not end in ${intake} intake's (${ends})`);
  }
  const params = fn.parameters.slice(0, lead);
  const widths = params.map((p) => abiWidth(p.type as AbiType));
  const total = widths.reduce((n, w) => n + w, 0);
  if (total !== values.length) throw new RangeError(`${fn.name}: its ${params.length} parameters before ${own[0]?.[0] ?? "the end"} take ${total} fields; the intake gives ${values.length} values`);
  let at = 0;
  return [...params.map((p, i) => abiArg(p.type, values.slice(at, (at += widths[i]!)), `${fn.name}.${p.name}`)), ...rest, ...after];
}
