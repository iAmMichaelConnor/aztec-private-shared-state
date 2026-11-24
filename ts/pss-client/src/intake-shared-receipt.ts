// Secret-shared receipt intake on the client side (docs/ARCHITECTURE.md section 6,
// "Secret-shared receipt intake, end to end", step 1): the IntakeModule
// `sharedReceiptIntake`, the request builder, the receipts over C and D and the
// arguments of the app's secret-shared receipt request function (pss_public_contract
// shared_intake.nr; sidecar-tip receipt.rs):
//
//   C                 = poseidon2([v_1, ..., v_m, blinding])
//   chain_request_id  = poseidon2([namespace, vk_hash, C])
//   S_j               = poseidon2([SUMMANDS_DOMAIN, s_j..., salt_j])     j = 0, 1, 2
//   D                 = poseidon2([SHARING_DOMAIN, S_0, S_1, S_2, kinds..., clear values...])
//   receipt message   = poseidon2([RECEIPT_DOMAIN, chain_request_id, C, expiry_block, D])
//
// v_1 ... v_m in IntakeLayout.commitment order (every app input, clear or
// INPUT_SHARED, and `$outcome_key` and `$outcome_tag`). The client draws
// `$blinding` uniformly, takes `$outcome_key` and `$outcome_tag` from its
// SecretStore (derived from the wallet secret and the request counter:
// SecretStore.nextPartial, which the app passes as `secrets`; given none, the
// builder draws them uniformly too), and shares every INPUT_SHARED value, the
// reserved ones included, as Rep3 (envelope.ts). The sharings make the three
// summand vectors s_0, s_1, s_2: one element per shared value in C's order,
// then the blinding's (summandNames), the k-th elements of the three the
// sharing of the k-th value. It draws a salt per vector and shares the salts as
// one more shared value, `$summand_salt` (its sharing is [salt_0, salt_1,
// salt_2]), so node i's envelopes open to s_i, s_{i-1} and their salts. It
// seals node i's pair of every shared value under the intake associated data
// over the chain request id, sends `C`, the summand commitments S_j, D (over
// them, the kind of each of C's values and the clear values), the clear app
// inputs and the envelopes to the receipt route, checks the receipts over C and
// D, and keeps the outcome key and tag to read the outcome (OutcomeReader,
// openOutcomeLog). The request function takes the sharing and proves it adds up
// to C's shared values and blinding. No input but the clear ones reaches a node
// or the orchestrator in the clear, and nothing but the request id and the
// expiry block reaches the chain.

import { Fr } from "@aztec-labs/foundation/curves/bn254";

import { ConfigError } from "./errors.ts";
import { intakeEnvelopeAd, sealSharedInput, shareField, type SealRandomness } from "./envelope.ts";
import { fieldBigInt, fieldFr, fieldHex, modR, randomField, u32, type FieldHexString, type FieldLike } from "./field.ts";
import type { PointInput } from "./grumpkin.ts";
import type { IntakeModule } from "./intake.ts";
import { noirReceipt, obtainReceipts, Receipts, refuseExpiring, sharedReceiptMessageOf, type NoirReceipt } from "./intake-receipt.ts";
import { privateOutcomes } from "./outcome.ts";
import {
  BLINDING_NAME,
  commitmentValues,
  drawSharedSecrets,
  OUTCOME_KEY_NAME,
  OUTCOME_TAG_NAME,
  sharedRequestCommitment,
  sharingDigest,
  splitNamedInputs,
  summandCommitment,
  summandNames,
  tipInputsByName,
  valueKinds,
  type IntakeLayout,
  type SharedSecrets,
  type SharedStaticCheck,
} from "./tip.ts";
import { NODES, type PublicValue, type SharedInput, type Signature, type Triple } from "./wire.ts";

const RESERVED = [BLINDING_NAME, OUTCOME_KEY_NAME, OUTCOME_TAG_NAME];

/** The name the three summand salts are sealed under, as one more shared
 * value after the circuit's own: its sharing is [salt_0, salt_1, salt_2]. */
export const SUMMAND_SALT_NAME = "$summand_salt";

/** A secret-shared receipt request's sharing, the request function's
 * `sharing` (pss_public_contract shared_intake.nr `Sharing<L>`): the three
 * Rep3 summand vectors, node 0's first, each with one element per name of
 * summandNames, and the salt of each vector. Node i's envelopes open to
 * `summands[i]`, `summands[i - 1]` and their salts. */
export interface Sharing {
  summands: Triple<FieldHexString[]>;
  salts: Triple<FieldHexString>;
}

export interface SharedReceiptRequestInput {
  /** The circuit's intake layout (intakeLayout); its intake must be
   * `shared_receipt`. */
  layout: IntakeLayout;
  /** The app contract's address. */
  namespace: FieldLike;
  /** The circuit's vk hash, as the contract pins it. */
  vkHash: FieldLike;
  /** Every app input by name: a clear one (a request public name) as
   * tipInputs spells it, an INPUT_SHARED one by its name, one field element
   * each, with `$partial_note` where the round takes it. Not `$blinding`, `$outcome_key` or `$outcome_tag`, which the builder
   * fills. */
  inputs: Record<string, FieldLike | readonly FieldLike[]>;
  /** The nodes' pinned enc keys, node 0 first. */
  encKeys: Triple<PointInput>;
  isValid?: SharedStaticCheck;
}

/** Values the builder would draw: `secrets`, the request's derived outcome
 * key and tag with a fresh blinding (SecretStore.next, secrets.ts), or known
 * answers for tests; and, for tests only, per
 * INPUT_SHARED name its sharing and the three ephemeral secrets, under
 * `$summand_salt` the three salts as its sharing. A client leaves them out
 * for every other request. */
export interface SharedReceiptRandomness {
  secrets?: SharedSecrets;
  seal?: Record<string, SealRandomness>;
}

/** A secret-shared receipt intake request before its receipts. */
export interface SharedReceiptRequest {
  namespace: FieldHexString;
  vkHash: FieldHexString;
  circuit: string;
  /** The names C commits to before the blinding (IntakeLayout.commitment). */
  commitmentNames: string[];
  /** Their values, in that order: the request function's `values`. */
  values: FieldHexString[];
  /** C's last element. */
  blinding: FieldHexString;
  /** The names the summand vectors hold, in order (summandNames). */
  summandNames: string[];
  /** The request function's `sharing`, which the envelopes seal: keep it
   * with them to ask again. */
  sharing: Sharing;
  /** S_0, S_1, S_2 (tip.ts summandCommitment). */
  summandCommitments: Triple<FieldHexString>;
  /** D (tip.ts sharingDigest: over the summand commitments, the layout and
   * the clear inputs), which the receipts sign. */
  sharingDigest: FieldHexString;
  /** Keep both: they open the outcome log (OutcomeKeys.outcomeKey) and find
   * it (its tag). */
  outcomeKey: FieldHexString;
  outcomeTag: FieldHexString;
  inputsCommitment: FieldHexString;
  chainRequestId: FieldHexString;
  /** The clear app inputs by public name, as the receipt route takes them. */
  clearInputs: Record<string, PublicValue>;
  /** One entry per INPUT_SHARED name in ABI order, then `$summand_salt`:
   * the three envelopes and their hashes. */
  sharedInputs: SharedInput[];
}

/** `POST /v1/receipt` of a secret-shared receipt intake request, as the client
 * sends it to the orchestrator, which checks each envelope against its hash,
 * fixes `expiry_block` and gives node i its own envelope. */
export interface SharedReceiptRequestBody {
  namespace: string;
  circuit: string;
  inputs: Record<string, PublicValue>;
  shared_inputs: SharedInput[];
  /** C. */
  inputs_hash: string;
  /** S_0, S_1, S_2: each node checks the two vectors its envelopes open to
   * against theirs. */
  summand_commitments: Triple<string>;
  /** D over the three, the layout and the clear inputs, which each node
   * checks and its receipt signs. */
  sharing_digest: string;
  current_block: number;
  /** The contract manifest version the request was built under (its vk
   * hash is that version's): set under upgradable circuits, absent under
   * fixed ones. The nodes refuse a version their chain view's pins do not
   * name. */
  manifest_hash?: string;
}

/** Build a secret-shared receipt intake request: split the named inputs into the
 * clear ones (put in ABI order and range-checked by the manifest, tipInputs)
 * and the INPUT_SHARED ones, draw the blinding, the outcome key and the
 * outcome tag, run `isValid` over C's values, compute C and the chain request
 * id, draw a Rep3 sharing of every summand name's value and the three salts,
 * commit to the summand vectors (S_j, D), and seal every INPUT_SHARED value,
 * then `$summand_salt`, to the three nodes under the intake associated
 * data, each with its sharing. ConfigError when the circuit is not under
 * secret-shared receipt intake; RangeError naming the input when one is missing, unexpected,
 * reserved, a list for a shared name, out of range, or refused by `isValid`. */
export async function buildSharedReceiptRequest(
  input: SharedReceiptRequestInput,
  randomness: SharedReceiptRandomness = {},
): Promise<SharedReceiptRequest> {
  const { layout } = input;
  if (layout.intake !== "shared_receipt") {
    throw new ConfigError(`circuit ${layout.circuit}: its manifest takes \`intake: ${layout.intake}\`, not shared_receipt`);
  }
  const { values, clear } = splitNamedInputs(layout, input.inputs, {
    shared: layout.shared.filter((n) => !RESERVED.includes(n)),
    defined: RESERVED,
    definedWhy: "reserved; the client draws it",
    sharedNoun: "an INPUT_SHARED input",
  });

  const secrets = randomness.secrets ?? drawSharedSecrets();
  const blinding = fieldBigInt(secrets.blinding, "blinding");
  values[OUTCOME_KEY_NAME] = fieldBigInt(secrets.outcomeKey, "outcome_key");
  values[OUTCOME_TAG_NAME] = fieldBigInt(secrets.outcomeTag, "outcome_tag");
  const committed = commitmentValues(layout, values);
  const { namespace, vkHash, c, chainRequestId: id } = await sharedRequestCommitment(input, committed, blinding);
  values[BLINDING_NAME] = blinding;

  // the sharing of every shared value, drawn once: its envelopes seal it
  // and the summand vectors are made of it
  const names = summandNames(layout);
  const sharings = new Map<string, Triple<FieldLike>>();
  for (const name of [...names, ...layout.shared]) {
    if (!sharings.has(name)) sharings.set(name, randomness.seal?.[name]?.sharing ?? shareField(values[name]!));
  }
  const salts = (randomness.seal?.[SUMMAND_SALT_NAME]?.sharing ?? [randomField(), randomField(), randomField()]).map((v, j) =>
    fieldBigInt(v, `salts[${j}]`),
  ) as Triple<bigint>;
  const summands = [0, 1, 2].map((j) => names.map((name, k) => fieldBigInt(sharings.get(name)![j]!, `summands[${j}][${k}]`))) as Triple<bigint[]>;
  const commitments = (await Promise.all(summands.map(async (s, j) => fieldHex((await summandCommitment(s, salts[j]!)).toBigInt())))) as Triple<FieldHexString>;
  const kinds = valueKinds(layout);
  const clearValues = committed.filter((_, p) => kinds[p] === "clear");
  const digest = fieldHex((await sharingDigest(commitments, kinds, clearValues)).toBigInt());

  const seal = (name: string, value: FieldLike, sharing: Triple<FieldLike>) =>
    sealSharedInput(intakeEnvelopeAd(namespace, id, layout.circuit, name), value, input.encKeys, { sharing, eph: randomness.seal?.[name]?.eph });
  const sharedInputs = await Promise.all([
    ...layout.shared.map((name) => seal(name, values[name]!, sharings.get(name)!)),
    seal(SUMMAND_SALT_NAME, modR(salts[0] + salts[1] + salts[2]), salts),
  ]);
  return {
    namespace,
    vkHash,
    circuit: layout.circuit,
    commitmentNames: [...layout.commitment],
    values: committed.map((v) => fieldHex(v)),
    blinding: fieldHex(blinding),
    summandNames: names,
    sharing: {
      summands: summands.map((s) => s.map((v) => fieldHex(v))) as Triple<FieldHexString[]>,
      salts: salts.map((v) => fieldHex(v)) as Triple<FieldHexString>,
    },
    summandCommitments: commitments,
    sharingDigest: digest,
    outcomeKey: fieldHex(values[OUTCOME_KEY_NAME]!),
    outcomeTag: fieldHex(values[OUTCOME_TAG_NAME]!),
    inputsCommitment: fieldHex(c),
    chainRequestId: id,
    clearInputs: tipInputsByName(layout, clear),
    sharedInputs,
  };
}

/** The receipt route body of a request, counting the expiry from
 * `currentBlock`. The same request sent again (a later currentBlock, when
 * its receipts expire too soon) has the same id, envelopes and sharing. */
export function sharedReceiptBody(request: SharedReceiptRequest, currentBlock: number): SharedReceiptRequestBody {
  return {
    namespace: request.namespace,
    circuit: request.circuit,
    inputs: request.clearInputs,
    shared_inputs: request.sharedInputs,
    inputs_hash: request.inputsCommitment,
    summand_commitments: request.summandCommitments,
    sharing_digest: request.sharingDigest,
    current_block: u32(currentBlock, "current_block", "block number"),
  };
}

/** A sharing in the Noir `Sharing` shape {summands, salts}, as aztec.js
 * encodes it for a request function's `sharing: Sharing<L>`. */
export interface NoirSharing {
  summands: Triple<Fr[]>;
  salts: Triple<Fr>;
}

/** `(values, sharing, expiry_block, receipts)`: the arguments of an app's
 * secret-shared receipt request function (pss_public_contract_test's
 * `request_shared(values: [Field; M], sharing: Sharing<L>, expiry_block:
 * u32, receipts: [Receipt; 3])`). */
export type SharedReceiptIntakeArgs = [values: Fr[], sharing: NoirSharing, expiryBlock: number, receipts: Triple<NoirReceipt>];

/** A sharing in the Noir shape; RangeError unless it has three summand
 * vectors of one nonzero length and three salts. */
function noirSharing(sharing: { summands: Triple<readonly FieldLike[]>; salts: Triple<FieldLike> }): NoirSharing {
  const { summands, salts } = sharing;
  if (!Array.isArray(summands) || summands.length !== NODES || !Array.isArray(salts) || salts.length !== NODES) {
    throw new RangeError(`sharing: expected ${NODES} summand vectors and ${NODES} salts, node 0's first`);
  }
  const length = summands[0]!.length;
  if (length === 0 || summands.some((s) => !Array.isArray(s) || s.length !== length)) {
    throw new RangeError("sharing.summands: three vectors of one nonzero length");
  }
  return {
    summands: summands.map((s, j) => s.map((x, k) => fieldFr(x, `sharing.summands[${j}][${k}]`))) as Triple<Fr[]>,
    salts: salts.map((x, j) => fieldFr(x, `sharing.salts[${j}]`)) as Triple<Fr>,
  };
}

/** The secret-shared receipt intake arguments: C's values, the sharing, the
 * expiry block and the three receipts, node 0's first. */
export function sharedReceiptIntakeArgs(r: {
  values: readonly FieldLike[];
  sharing: { summands: Triple<readonly FieldLike[]>; salts: Triple<FieldLike> };
  expiryBlock: number;
  receipts: Triple<Signature>;
}): SharedReceiptIntakeArgs {
  if (!Array.isArray(r.receipts) || r.receipts.length !== NODES) throw new RangeError(`receipts: expected ${NODES}, node 0 first`);
  return [
    r.values.map((x, i) => new Fr(fieldBigInt(x, `values[${i}]`))),
    noirSharing(r.sharing),
    u32(r.expiryBlock, "expiry_block", "block number"),
    r.receipts.map(noirReceipt) as Triple<NoirReceipt>,
  ];
}

/** A request's intake under secret-shared receipt intake: the receipts over C and D,
 * which hold the request. */
export interface SharedReceiptIntakeInput {
  intake: "shared_receipt";
  receipts: SharedReceipts;
}

/** Secret-shared receipt intake: the client builds the request from named inputs
 * (or takes an earlier one, `ask.request`, to ask again under a later
 * expiry), sends C, the summand commitments, D, the clear inputs and the
 * envelopes to the receipt route and checks the receipts over C and D; the
 * request function `(values, sharing, expiry_block, receipts)` proves the
 * sharing opens C and checks them. Only the request id and the expiry reach
 * the chain. */
export const sharedReceiptIntake: IntakeModule<SharedReceiptIntakeInput> = {
  intake: "shared_receipt",
  parameters: [["sharing", "struct"], ["expiry_block", "integer"], ["receipts", "array"]],
  results: privateOutcomes,
  async obtain(route, ask) {
    const { layout } = route;
    const keys = await route.receiptKeys();
    let request = ask.request;
    if (request === undefined) {
      if (ask.inputs === undefined) throw new RangeError(`circuit ${ask.circuit}: give the inputs or an earlier request`);
      request = await buildSharedReceiptRequest(
        { layout, namespace: route.namespace, vkHash: route.vkHash, inputs: ask.inputs, encKeys: keys.encKeys, isValid: ask.isValid },
        { ...ask.randomness, ...(ask.secrets && { secrets: ask.secrets }) },
      );
    } else if (request.circuit !== layout.circuit || request.vkHash !== route.vkHash || request.namespace !== route.namespace) {
      throw new ConfigError(`the request is for circuit ${request.circuit} under vk hash ${request.vkHash} in ${request.namespace}, not the configured ${layout.circuit} in ${route.namespace}`);
    }
    const currentBlock = u32(ask.currentBlock, "currentBlock", "block number");
    // the receipts over C and D: the client's own chain request id and C, an
    // expiry within the TTL, three receipts under the sig keys over the
    // five-element message (obtainReceipts)
    const receipts = await obtainReceipts(
      route,
      keys,
      sharedReceiptBody(request, currentBlock),
      { requestId: request.chainRequestId, inputsHash: request.inputsCommitment, currentBlock, signs: sharedReceiptMessageOf(request.sharingDigest) },
      (answer) => new SharedReceipts(request, answer.expiry_block, answer.signatures, route.marginBlocks),
    );
    return { intake: "shared_receipt", receipts };
  },
  intakeArgs({ receipts }, options) {
    refuseExpiring(receipts, options.currentBlock);
    return receipts.intakeArgs();
  },
  summary({ receipts }) {
    const r = receipts.request;
    return {
      chainRequestId: r.chainRequestId,
      values: r.values,
      expiryBlock: receipts.expiryBlock,
      outcomeKey: r.outcomeKey,
      outcomeTag: r.outcomeTag,
      privateValues: [
        ...r.commitmentNames.map((n, k): [string, FieldHexString] => [n, r.values[k]!]),
        ["blinding", r.blinding],
        ...r.sharing.summands.flatMap((s, j) => s.map((v, k): [string, FieldHexString] => [`summands[${j}][${k}]`, v])),
        ...r.sharing.salts.map((v, j): [string, FieldHexString] => [`salts[${j}]`, v]),
      ],
    };
  },
  requestLogs: async () => [],
};

/** Three checked receipts over C and D for one secret-shared request. */
export class SharedReceipts extends Receipts<SharedReceiptIntakeArgs> {
  readonly request: SharedReceiptRequest;

  constructor(request: SharedReceiptRequest, expiryBlock: number, receipts: Triple<Signature>, marginBlocks: number) {
    super(expiryBlock, receipts, marginBlocks);
    this.request = request;
  }

  get requestId(): FieldHexString {
    return this.request.chainRequestId;
  }

  intakeArgs(): SharedReceiptIntakeArgs {
    return sharedReceiptIntakeArgs({ ...this.request, expiryBlock: this.expiryBlock, receipts: this.receipts });
  }
}
