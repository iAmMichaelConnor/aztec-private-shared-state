// Secret-shared on-chain intake on the client side (docs/ARCHITECTURE.md section 6,
// "Secret-shared on-chain intake"): the encoding the app's private request function
// computes (pss_public_contract shared_onchain.nr shared_onchain_request,
// pss_core tip/derived.nr; sidecar-core derived.rs is the node's side), the
// round's encoding layout from its manifest and ABI (sidecar-tip
// intake/shared_onchain.rs onchain_layout), and the request builder:
//
//   PRF(k, j)          = poseidon2([k, j, SIDECAR_INTAKE_PRF])
//   E                  = e·G,                     E.x in the log
//   s_i                = x(e·P_i) = x(enc_i·E)    P_i node i's stored enc key
//   t_i                = PRF(s_i, 0),   w_i = t_i + PRF(s_{i+1}, 1)
//   a_{i,j}            = PRF(t_i, j + 2)
//   shared x_j:          c_j = x_j − Σ_i a_{i,j}  (node 2's summand a_{2,j} + c_j)
//   blinding:            b = Σ_i a_{i,m}          (m shared values before it)
//   C                  = poseidon2([values..., blinding])
//   chain_request_id   = poseidon2([namespace, vk_hash, C])
//   tag                = compute_log_tag(chain_request_id, REQUEST_DOMAIN)
//   log                = [C, epochs, E.x, w_0, w_1, w_2, clear..., corrections..., padding...]
//   data_hash          = poseidon2(log)
//
// The values are C's, in IntakeLayout.commitment order, each of one kind:
// CLEAR (a clear app input, logged as is) or CHOSEN (an INPUT_SHARED app
// input, the partial note, or the outcome key and tag the client derives:
// one correction). The j-th shared value counts the chosen values in that
// order and then `$blinding`, which the encoding defines. The log holds 15 fields after its tag;
// position i past the clear values and corrections holds logPadding(blinding,
// i): the tag follows from the public request id, the blinding is secret and
// fixed by the encoding, so the padding shows nothing of the round type.
// `epochs` packs the three epochs the contract stores beside the keys
// (`e_0 + e_1·2^32 + e_2·2^64`), which name the scalar each node opens with.
//
// The client draws the ephemeral secret e, passes `(values, eph)` to the
// app's request function as private arguments (they never reach the chain)
// and computes the same encoding itself, to know C and the request id; it
// reads its outcome with the outcome key and tag it derived (OutcomeReader,
// openOutcomeLog). No value but the clear ones reaches the chain, and nothing
// reaches the nodes or the orchestrator off the chain.

import { Grumpkin } from "@aztec-labs/foundation/crypto/grumpkin";
import { Fr } from "@aztec-labs/foundation/curves/bn254";
import { GrumpkinScalar, Point } from "@aztec-labs/foundation/curves/grumpkin";
import { AztecAddress } from "@aztec-labs/aztec.js/addresses";
import { computeSiloedPrivateLogFirstField } from "@aztec-labs/stdlib/hash";

import { ConfigError } from "./errors.ts";
import { fieldAddress, fieldBigInt, fieldHex, modR, u32, type FieldHexString, type FieldLike, hashFields } from "./field.ts";
import { curvePoint, ephemeralSecret, ephScalar, type PointInput } from "./grumpkin.ts";
import { asciiLabel } from "./labels.ts";
import { computeRequestLogTag } from "./intake-onchain.ts";
import type { IntakeModule } from "./intake.ts";
import type { QueuedManifest } from "./manifest.ts";
import { logPadding, privateOutcomes } from "./outcome.ts";
import {
  BLINDING_NAME,
  commitmentValues,
  drawSharedSecrets,
  intakeLayout,
  OUTCOME_KEY_NAME,
  OUTCOME_TAG_NAME,
  sharedRequestCommitment,
  splitNamedInputs,
  summandNames,
  tipInputsByName,
  valueKinds,
  type IntakeLayout,
  type SharedStaticCheck,
  type ValueKind,
} from "./tip.ts";
import { NODES, nodeIndex, type PublicValue, type Triple } from "./wire.ts";

/** ASCII "sidecar.intake_prf" read big-endian: the PRF's domain (pss_core
 * tip/derived.nr SIDECAR_INTAKE_PRF). */
export const SIDECAR_INTAKE_PRF = asciiLabel("sidecar.intake_prf");
/** ASCII "pss.enc_rotate" read big-endian: the first element of a node's
 * enc key rotation message (domains.nr PSS_ENC_ROTATE). */
export const PSS_ENC_ROTATE = asciiLabel("pss.enc_rotate");
/** The request log's length after its tag: the v6 private log's 15. */
export const REQUEST_LOG_LEN = 15;
/** The fields before the clear values: C, the epochs, E.x and the wraps. */
export const REQUEST_LOG_HEADER = 6;
/** At most this many clear values and corrections together fit one log. */
export const MAX_LOGGED_VALUES = REQUEST_LOG_LEN - REQUEST_LOG_HEADER;


// ---- the encoding ----

/** `PRF(k, j) = poseidon2([k, j, SIDECAR_INTAKE_PRF])`. */
function intakePrf(k: FieldLike, j: number | bigint): Promise<bigint> {
  return hashFields([fieldBigInt(k, "k"), BigInt(j), SIDECAR_INTAKE_PRF]);
}

/** The three named epochs in one field: `e_0 + e_1·2^32 + e_2·2^64`. */
export function packEpochs(epochs: Triple<number>): bigint {
  if (!Array.isArray(epochs) || epochs.length !== NODES) throw new RangeError(`epochs: expected ${NODES}, node 0 first`);
  return epochs.reduce((acc, e, i) => acc | (BigInt(u32(e, `epochs[${i}]`, "epoch")) << BigInt(32 * i)), 0n);
}

/** The three epochs a packed field names; null when it is not three u32s. */
export function unpackEpochs(packed: FieldLike): Triple<number> | null {
  const v = fieldBigInt(packed, "epochs");
  if (v >> 96n !== 0n) return null;
  return [0, 1, 2].map((i) => Number((v >> BigInt(32 * i)) & 0xffffffffn)) as Triple<number>;
}

/** The key-exchange secrets `s_i = x(e·P_i)` of the ephemeral secret `eph`
 * with the nodes' keys, node 0 first, and `E.x` of `E = e·G`. RangeError for
 * a zero `eph` or a key that is not a point. */
export async function keyExchange(eph: FieldLike, keys: Triple<PointInput>): Promise<{ secrets: Triple<bigint>; ephX: bigint }> {
  if (!Array.isArray(keys) || keys.length !== NODES) throw new RangeError(`keys: expected ${NODES}, node 0 first`);
  const scalar = ephScalar(eph);
  const points = keys.map((k, i) => curvePoint(k, `enc key of node ${i}`));
  const products = await Grumpkin.batchMul(points, scalar);
  const E = await Grumpkin.mul(Grumpkin.generator, scalar);
  return { secrets: products.map((p) => p.x.toBigInt()) as Triple<bigint>, ephX: E.x.toBigInt() };
}

/** The seed `t = PRF(s, 0)` of a key-exchange secret. */
function intakeSeed(secret: FieldLike): Promise<bigint> {
  return intakePrf(secret, 0);
}

/** The wraps `w_i = t_i + PRF(s_{i+1}, 1)` of the three secrets. */
export async function intakeWraps(secrets: Triple<FieldLike>): Promise<Triple<bigint>> {
  return (await Promise.all(
    secrets.map(async (s, i) => modR((await intakeSeed(s)) + (await intakePrf(secrets[(i + 1) % NODES]!, 1)))),
  )) as Triple<bigint>;
}

/** The three summands `a_{i,j} = PRF(t_i, j + 2)` of the j-th shared value
 * before its correction. */
async function intakeSummands(secrets: Triple<FieldLike>, j: number): Promise<Triple<bigint>> {
  return (await Promise.all(secrets.map(async (s) => intakePrf(await intakeSeed(s), j + 2)))) as Triple<bigint>;
}

/** One request's encoding, as the app's private request function computes it. */
export interface SharedEncoding {
  /** `$blinding`, the last shared value, defined by the encoding. */
  blinding: bigint;
  clear: bigint[];
  corrections: bigint[];
  /** `E.x`. */
  ephX: bigint;
  secrets: Triple<bigint>;
  wraps: Triple<bigint>;
}

/** The encoding of `values` (in C's order, each of `kinds[p]`) under the
 * ephemeral secret `eph` and the nodes' keys. RangeError when the lengths
 * differ or a kind is neither. */
export async function encodeShared(kinds: readonly ValueKind[], values: readonly FieldLike[], eph: FieldLike, keys: Triple<PointInput>): Promise<SharedEncoding> {
  if (kinds.length !== values.length) throw new RangeError(`values: ${values.length} values for ${kinds.length} kinds`);
  const { secrets, ephX } = await keyExchange(eph, keys);
  const clear: bigint[] = [];
  const corrections: bigint[] = [];
  const sum = async (j: number) => modR((await intakeSummands(secrets, j)).reduce((a, b) => a + b, 0n));
  for (const [p, kind] of kinds.entries()) {
    const v = fieldBigInt(values[p]!, `values[${p}]`);
    if (kind === "clear") clear.push(v);
    // the k-th chosen value is the k-th shared value
    else if (kind === "chosen") corrections.push(modR(v - (await sum(corrections.length))));
    else throw new RangeError(`kinds[${p}]: expected clear or chosen`);
  }
  return { blinding: await sum(corrections.length), clear, corrections, ephX, secrets, wraps: await intakeWraps(secrets) };
}

/** The request log after its tag, padded with logPadding(blinding, i) at
 * each position i past the clear values and corrections. RangeError when
 * they do not fit (more than MAX_LOGGED_VALUES together). */
export async function sharedRequestLog(c: FieldLike, epochs: Triple<number>, encoding: Pick<SharedEncoding, "blinding" | "ephX" | "wraps" | "clear" | "corrections">): Promise<bigint[]> {
  const log = [fieldBigInt(c, "C"), packEpochs(epochs), fieldBigInt(encoding.ephX, "E.x"), ...encoding.wraps, ...encoding.clear, ...encoding.corrections].map((v) => fieldBigInt(v, "log field"));
  if (log.length > REQUEST_LOG_LEN) {
    throw new RangeError(`${encoding.clear.length + encoding.corrections.length} clear values and corrections do not fit one request log (at most ${MAX_LOGGED_VALUES})`);
  }
  const blinding = fieldBigInt(encoding.blinding, "blinding");
  for (let i = log.length; i < REQUEST_LOG_LEN; i++) log.push(await logPadding(blinding, i));
  return log;
}

/** The data hash the contract stores beside the queue entry: `poseidon2`
 * of the request log after its tag. */
export function requestDataHash(log: readonly FieldLike[]): Promise<bigint> {
  return hashFields(log.map((v, i) => fieldBigInt(v, `log[${i}]`)));
}

/** The request log's tag as the chain shows it: `tag` (computeRequestLogTag
 * of the chain request id) siloed with the app's address by the kernel. */
export async function requestLogSiloedTag(namespace: FieldLike | AztecAddress, tag: FieldLike): Promise<bigint> {
  const address = fieldAddress(namespace, "namespace");
  return (await computeSiloedPrivateLogFirstField(address, new Fr(fieldBigInt(tag, "tag")))).toBigInt();
}

// ---- the node's side ----

/** Node i's pair `(x_i, x_{i-1})` of the j-th shared value from its
 * key-exchange secret, the wrap `w_{i-1}` and the value's correction (zero
 * for `$blinding`). */
export async function nodePair(i: number, secret: FieldLike, wrapBefore: FieldLike, j: number, correction: FieldLike = 0n): Promise<[bigint, bigint]> {
  nodeIndex(i);
  const own = await intakeSeed(secret);
  const before = modR(fieldBigInt(wrapBefore, "wrap") - (await intakePrf(secret, 1)));
  const pair: [bigint, bigint] = [await intakePrf(own, j + 2), await intakePrf(before, j + 2)];
  const c = fieldBigInt(correction, "correction");
  if (i === 2) pair[0] = modR(pair[0] + c);
  if (i === 0) pair[1] = modR(pair[1] + c);
  return pair;
}

/** A point with x-coordinate `x` (either root: the key exchange takes the
 * x-coordinate of the product, the same for `±E`); null when there is none. */
export async function liftX(x: FieldLike): Promise<Point | null> {
  const fx = new Fr(fieldBigInt(x, "x"));
  if (fx.isZero()) return null;
  const y = await fx.mul(fx).mul(fx).sub(new Fr(17n)).sqrt();
  if (y === null) return null;
  const point = new Point(fx, y);
  return point.isOnCurve() ? point : null;
}

/** One INPUT_SHARED value as the encoding orders it, with the log position
 * (after the tag) of its correction for a chosen one. */
export interface DerivedInput {
  name: string;
  correction?: number;
}

/** A request log and the circuit's shared values in the encoding's order:
 * what a synthesised request carries as `shared_log`. */
export interface SharedLog {
  fields: readonly FieldLike[];
  shared: readonly DerivedInput[];
}

/** Node i's Rep3 pair of the shared value `name` of `log`, derived with
 * `encScalar`, its enc scalar for the epoch the log names (sidecar-core
 * derived_share): a check of a request against the nodes' side. RangeError
 * when the log does not carry `name` or its E.x is no point's. */
export async function derivedShare(encScalar: FieldLike, i: number, log: SharedLog, name: string): Promise<[bigint, bigint]> {
  nodeIndex(i);
  if (log.fields.length !== REQUEST_LOG_LEN) throw new RangeError(`log: ${log.fields.length} fields; a request log has ${REQUEST_LOG_LEN} after its tag`);
  const j = log.shared.findIndex((s) => s.name === name);
  if (j < 0) throw new RangeError(`log.shared: missing \`${name}\``);
  const E = await liftX(log.fields[2]!);
  if (E === null) throw new RangeError("log.fields[2]: E.x is no point's x-coordinate");
  const secret = (await Grumpkin.mul(E, new GrumpkinScalar(fieldBigInt(encScalar, "enc")))).x.toBigInt();
  const at = log.shared[j]!.correction;
  const correction = at === undefined ? 0n : fieldBigInt(log.fields[at]!, `log.fields[${at}]`);
  return nodePair(i, secret, log.fields[3 + ((i + NODES - 1) % NODES)]!, j, correction);
}

/** The message node `i` signs to set its key in `namespace` to `pk` at
 * `epoch`: `poseidon2([PSS_ENC_ROTATE, namespace, i, pk.x, pk.y, epoch])`
 * (pss_public_contract enc_rotation_message), checked under its pinned sig
 * key by the app's rotation function. */
export function encRotationMessage(namespace: FieldLike, i: number, pk: PointInput, epoch: number): Promise<bigint> {
  nodeIndex(i);
  return hashFields([PSS_ENC_ROTATE, fieldBigInt(namespace, "namespace"), BigInt(i), fieldBigInt(pk.x, "pk.x"), fieldBigInt(pk.y, "pk.y"), BigInt(u32(epoch, "epoch", "epoch"))]);
}

// ---- the layout ----

/** A round's encoding layout: the kind of each of C's values in its order,
 * and every INPUT_SHARED value in the encoding's order (the shared values in
 * C's order, then `$blinding`) with the log position of its correction,
 * after the header and the clear values (sidecar-tip onchain_layout). */
export interface OnchainLayout {
  /** The circuit's intake layout (intakeLayout). */
  intake: IntakeLayout;
  kinds: { name: string; kind: ValueKind }[];
  shared: DerivedInput[];
  /** How many of the values are clear, and how many corrections the log carries. */
  clear: number;
  corrections: number;
}

/** The encoding layout of a tip circuit (its nargo output JSON or its `abi`)
 * under its parsed manifest (onchainLayoutOf its intakeLayout). ConfigError
 * when the manifest's intake is not shared_onchain. */
export function onchainLayout(circuit: unknown, m: QueuedManifest): OnchainLayout {
  if (m.intake !== "shared_onchain") throw new ConfigError(`circuit ${m.circuit}: its manifest takes \`intake: ${m.intake}\`, not shared_onchain`);
  return onchainLayoutOf(intakeLayout(circuit, m));
}

/** The encoding layout of a circuit's intake layout: every shared value
 * (INPUT_SHARED app input or reserved value) chosen, every clear app input
 * clear; the shared values in the order of a secret-shared receipt
 * request's summand vectors (summandNames). RangeError when the
 * clear values and corrections do not fit one request log (REGISTER refuses
 * that manifest). */
function onchainLayoutOf(intake: IntakeLayout): OnchainLayout {
  const names = summandNames(intake);
  const kinds = valueKinds(intake).map((kind, p) => ({ name: intake.commitment[p]!, kind }));
  const clear = kinds.filter((k) => k.kind === "clear").length;
  const shared: DerivedInput[] = names.map((name, k) => (name === BLINDING_NAME ? { name } : { name, correction: REQUEST_LOG_HEADER + clear + k }));
  const corrections = shared.length - 1;
  if (clear + corrections > MAX_LOGGED_VALUES) {
    throw new RangeError(
      `manifest.witness: ${clear} clear input(s) and ${corrections} chosen shared value(s); secret-shared on-chain intake's request log holds at most ${MAX_LOGGED_VALUES} together`,
    );
  }
  return { intake, kinds, shared, clear, corrections };
}

// ---- the request ----

/** Node i's current enc key in the app contract and its epoch, as
 * `SharedOnchain.enc_keys[i]` stores it and the request function reads it at
 * its anchor block. */
export interface EncKeyInput extends PointInput {
  epoch: number;
}

/** A node's enc key as the app contract stores it. */
export interface StoredEncKey {
  x: bigint;
  y: bigint;
  epoch: number;
}

/** The app contract's `get_enc_key` view, as aztec.js's Contract exposes it. */
export interface EncKeyReader {
  methods: { get_enc_key(i: number): { simulate(options: object): Promise<unknown> } };
}

/** Node `i`'s key as `get_enc_key(i)` answers it, simulated from `from`. */
export async function storedEncKey(contract: EncKeyReader, i: number, from: unknown): Promise<StoredEncKey> {
  const answer = (await contract.methods.get_enc_key(i).simulate({ from })) as { result?: unknown } | Record<string, unknown>;
  const v = ("result" in answer ? answer.result : answer) as { x: unknown; y: unknown; epoch: unknown };
  return { x: BigInt(String(v.x)), y: BigInt(String(v.y)), epoch: Number(v.epoch) };
}

/** The three nodes' stored keys, node 0 first: a secret-shared on-chain
 * ask's `encKeys`. */
export async function storedEncKeys(contract: EncKeyReader, from: unknown): Promise<Triple<StoredEncKey>> {
  const keys: StoredEncKey[] = [];
  for (let i = 0; i < NODES; i++) keys.push(await storedEncKey(contract, i, from));
  return keys as Triple<StoredEncKey>;
}

export interface SharedOnchainRequestInput {
  /** The round's encoding layout (onchainLayout). */
  layout: OnchainLayout;
  /** The app contract's address. */
  namespace: FieldLike;
  /** The circuit's vk hash, as the contract pins it. */
  vkHash: FieldLike;
  /** Every app input by name: a clear one (a request public name) as
   * tipInputs spells it, an INPUT_SHARED one by its name, and the reserved
   * shared values (the partial note, the outcome key and tag), one field
   * element each. Not `$blinding`, which the encoding defines. */
  inputs: Record<string, FieldLike | readonly FieldLike[]>;
  /** The nodes' keys and epochs in the contract, node 0 first: what the
   * request function will read at the anchor block the transaction is
   * proven against. Reading them is the caller's. */
  encKeys: Triple<EncKeyInput>;
  /** The app's static check, over C's values, as the request function
   * asserts it. */
  isValid?: SharedStaticCheck;
}

/** For tests only: the ephemeral secret the builder would draw. */
export interface SharedOnchainRandomness {
  eph?: FieldLike;
}

/** A secret-shared on-chain intake request: the request function's private
 * arguments and everything the client computes alongside them. */
export interface SharedOnchainRequest {
  namespace: FieldHexString;
  vkHash: FieldHexString;
  circuit: string;
  /** The names C commits to before the blinding (IntakeLayout.commitment). */
  commitmentNames: string[];
  /** Their values, in that order: the request function's `values`. */
  values: FieldHexString[];
  /** The ephemeral secret: the request function's `eph`. Used once. */
  eph: FieldHexString;
  blinding: FieldHexString;
  /** The outcome key and tag the request chose: they open the outcome log
   * (OutcomeKeys.outcomeKey) and find it (its tag). */
  outcomeKey: FieldHexString;
  outcomeTag: FieldHexString;
  inputsCommitment: FieldHexString;
  chainRequestId: FieldHexString;
  /** The epochs the log names, node 0 first. */
  epochs: Triple<number>;
  /** The request log's tag before the kernel silos it. */
  logTag: FieldHexString;
  /** The request log after its tag, and its hash, which the contract stores. */
  log: FieldHexString[];
  dataHash: FieldHexString;
  /** The clear app inputs by public name. */
  clearInputs: Record<string, PublicValue>;
}

/** Build a secret-shared on-chain intake request: split the named inputs into the
 * clear ones (put in ABI order and range-checked by the manifest, tipInputs)
 * and the chosen shared ones, draw a fresh non-zero ephemeral secret from the
 * CSPRNG, encode the values under the nodes' stored keys, run `isValid` over
 * C's values, and compute C, the chain
 * request id, the request log and its data hash, as the request function
 * will. RangeError naming the input when one is missing, unexpected, defined
 * by the encoding, a list for a shared name, out of range, or refused by
 * `isValid`, and naming the node when a key is not a point or has epoch 0
 * (no key yet: the request function reverts). */
export async function buildSharedOnchainRequest(
  input: SharedOnchainRequestInput,
  randomness: SharedOnchainRandomness = {},
): Promise<SharedOnchainRequest> {
  const { layout } = input;
  const intake = layout.intake;
  if (!Array.isArray(input.encKeys) || input.encKeys.length !== NODES) throw new RangeError(`encKeys: expected ${NODES}, node 0 first`);
  const epochs = input.encKeys.map((k, i) => {
    const e = u32(k.epoch, `encKeys[${i}].epoch`, "epoch");
    if (e === 0) throw new RangeError(`encKeys[${i}].epoch: 0, node ${i} has no enc key in this contract`);
    return e;
  }) as Triple<number>;
  const { values, clear } = splitNamedInputs(intake, input.inputs, {
    shared: layout.kinds.filter((k) => k.kind === "chosen").map((k) => k.name),
    defined: [BLINDING_NAME],
    definedWhy: "the encoding defines it",
    sharedNoun: "a chosen shared value",
  });

  const eph = ephemeralSecret(randomness.eph);
  const cValues = commitmentValues(intake, values);
  const encoding = await encodeShared(
    layout.kinds.map((k) => k.kind),
    cValues,
    eph,
    input.encKeys,
  );
  const { namespace, vkHash, c, chainRequestId } = await sharedRequestCommitment(input, cValues, encoding.blinding);
  const tag = (await computeRequestLogTag(chainRequestId)).toBigInt();
  const log = await sharedRequestLog(c, epochs, encoding);
  const at = (name: string) => {
    const p = intake.commitment.indexOf(name);
    if (p < 0) throw new RangeError(`circuit ${intake.circuit}: C commits to no \`${name}\``);
    return cValues[p]!;
  };
  return {
    namespace,
    vkHash,
    circuit: intake.circuit,
    commitmentNames: [...intake.commitment],
    values: cValues.map((v) => fieldHex(v)),
    eph: fieldHex(eph),
    blinding: fieldHex(encoding.blinding),
    outcomeKey: fieldHex(at(OUTCOME_KEY_NAME)),
    outcomeTag: fieldHex(at(OUTCOME_TAG_NAME)),
    inputsCommitment: fieldHex(c),
    chainRequestId,
    epochs,
    logTag: fieldHex(tag),
    log: log.map((v) => fieldHex(v)),
    dataHash: fieldHex(await requestDataHash(log)),
    clearInputs: tipInputsByName(intake, clear),
  };
}

/** `(values, eph)`: the private arguments of an app's secret-shared on-chain
 * request function (`swap_onchain(values: [Field; M], eph: Field)`). */
export type SharedOnchainIntakeArgs = [values: Fr[], eph: Fr];

/** The secret-shared on-chain intake arguments of a request. */
export function sharedOnchainIntakeArgs(r: Pick<SharedOnchainRequest, "values" | "eph">): SharedOnchainIntakeArgs {
  return [r.values.map((x, i) => new Fr(fieldBigInt(x, `values[${i}]`))), new Fr(fieldBigInt(r.eph, "eph"))];
}

// ---- the intake module ----

/** A secret-shared on-chain intake request as obtainIntake gives it and
 * submitIntake takes it. */
export interface SharedOnchainIntakeInput {
  intake: "shared_onchain";
  request: SharedOnchainRequest;
}

/** Secret-shared on-chain intake (IntakeModule): obtain builds the request from
 * the ask's named inputs, with the outcome key and tag of the ask's
 * `secrets` (drawn when it gives none, as secret-shared receipt intake
 * draws them), under the nodes' keys and epochs the app contract
 * stores (the ask's `encKeys`, which the caller reads; nothing is sent to
 * the nodes or the orchestrator); the request function takes C's values and
 * the ephemeral secret, both private; it emits no public log (its request
 * log is a private log, `request.log` under `request.logTag`); its rounds'
 * results are private outcomes. */
export const sharedOnchainIntake: IntakeModule<SharedOnchainIntakeInput> = {
  intake: "shared_onchain",
  parameters: [["eph", "field"]],
  results: privateOutcomes,
  async obtain(route, ask) {
    if (ask.inputs === undefined) throw new RangeError(`circuit ${ask.circuit}: no inputs to build the request from`);
    if (ask.encKeys === undefined) throw new RangeError(`circuit ${ask.circuit}: secret-shared on-chain intake needs the encKeys the app contract stores`);
    const encKeys = typeof ask.encKeys === "function" ? await ask.encKeys() : ask.encKeys;
    // the client chooses the outcome key and tag: the ask's secrets (drawn
    // when it gives none), unless the inputs name their own
    const secrets = ask.secrets ?? drawSharedSecrets();
    const chosen: Record<string, FieldLike> = { [OUTCOME_KEY_NAME]: secrets.outcomeKey, [OUTCOME_TAG_NAME]: secrets.outcomeTag };
    const request = await buildSharedOnchainRequest(
      {
        layout: onchainLayoutOf(route.layout),
        namespace: route.namespace,
        vkHash: route.vkHash,
        inputs: { ...chosen, ...ask.inputs },
        encKeys,
        isValid: ask.isValid,
      },
      { eph: ask.randomness?.eph },
    );
    return { intake: "shared_onchain", request };
  },
  intakeArgs: ({ request }) => sharedOnchainIntakeArgs(request),
  summary({ request: r }) {
    const shared = r.commitmentNames
      .map((n, k): [string, FieldHexString] => [n, r.values[k]!])
      .filter(([n]) => !Object.hasOwn(r.clearInputs, n));
    return {
      chainRequestId: r.chainRequestId,
      values: r.values,
      outcomeKey: r.outcomeKey,
      outcomeTag: r.outcomeTag,
      privateValues: [...shared, ["blinding", r.blinding], ["eph", r.eph]],
    };
  },
  requestLogs: async () => [],
};
