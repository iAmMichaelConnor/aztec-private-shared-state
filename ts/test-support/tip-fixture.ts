// Signed tip results for the result tests of pss-client and pss-relayer: an
// answer to FETCH by chain request id, made the way the orchestrator answers
// it (the machine request id of the chain request and the round's old
// commitments, the public inputs in pss_public_contract's layout, one
// chain-held record and the three nodes' result signatures with the
// keys.json sig keys), for examples/amm-tip's swap circuit under both non-secret-shared
// intakes (one compiled circuit, two manifests) with the pool chain-held (the
// chain-held option over the example's circuit: the example itself is
// node-held) and for a circuit shaped like pss_public_contract_test's
// TipResult<1, 1, 1, 2> with sealed thirds of five fields; and the swap as the
// example registers it, node-held (AMM_SWAP_HELD), whose answer carries no
// record and whose signatures end in H(sealed_i) = 0.
//
// fixtures/amm_swap_tip.abi.json is the `abi` of the circuit compiled
// with nargo 1.0.0; {PssPublicTest,AmmTip,LendingTip}.result.abi.json hold
// the FunctionAbi of the contracts' functions that
// pss-client builds arguments for, and their storage layout, as aztec.js 6.0.0
// loadContractArtifact reads them from `aztec compile` output
// (contract-fixture.ts); pss-client's fixtures.test.ts compares each
// with its build.

import { readFileSync } from "node:fs";

import type { FunctionAbi } from "@aztec-labs/stdlib/abi";

import {
  SchnorrKey,
  buildTipRequestWith,
  fieldHex,
  isQueued,
  parseManifest,
  machineRequestId,
  outcomeShape,
  publicLayout,
  recordHash,
  resultMessage,
  sealedHash,
  vkFieldsFromBbJson,
  vkHashFromFields,
  type ExecuteResponse,
  type OutcomeShape,
  type PssClientConfig,
  type QueuedManifest,
  type Signature,
  type TipRequest,
  type Triple,
} from "@aztec-pss/pss-client/internal";

const here = (p: string) => new URL(p, import.meta.url);

/** A tip manifest JSON, parsed (the layouts take the parsed manifest). */
export function queued(manifest: unknown): QueuedManifest {
  const m = parseManifest(manifest);
  if (!isQueued(m)) throw new RangeError("not a tip manifest");
  return m;
}
const json = (p: string) => JSON.parse(readFileSync(here(p), "utf8"));

const KEYS = json("../../testvectors/keys.json") as {
  nodes: { enc_pk: { x: string; y: string }; sig: string; sig_pk: { x: string; y: string } }[];
};
export const NODE_KEYS = KEYS.nodes.map((n) => ({ enc: n.enc_pk, sig: n.sig_pk })) as PssClientConfig["nodeKeys"];
export const NODE_SIGNERS = KEYS.nodes.map((n) => SchnorrKey.fromHex(n.sig));

/** 115 real vk fields (pss_seed's vk.json) and their Poseidon2. */
export const VK_FIELDS = vkFieldsFromBbJson(readFileSync(here("fixtures/pss_seed.vk.json"), "utf8"));
export const VK_HASH = fieldHex((await vkHashFromFields(VK_FIELDS)).toBigInt());

export const NAMESPACE = "0x0000000000000000000000000000000000000000000000000000000000a11ce5";
export const POOL_KEY = 20n;
/** The lending market's key. */
export const MARKET_KEY = 0x30n;
/** The npk_app_hash the answers carry. */
export const NPK_APP_HASH = 0x9bn;

/** The pool chain-held: the example's swap manifests with `state` naming
 * the chain, the fixtures of the chain-held result path. */
const CHAIN_HELD = { "$state_keys.reads[0]": "chain", "$state_keys.writes[0]": "chain" };

export const AMM_SWAP = {
  circuit: { abi: json("fixtures/amm_swap_tip.abi.json").abi },
  manifest: { ...json("../../examples/amm-tip/manifests/amm_swap_tip.json"), state: CHAIN_HELD },
};
/** The same compiled circuit under the receipt-intake manifest. */
export const AMM_SWAP_RECEIPT = {
  circuit: AMM_SWAP.circuit,
  manifest: { ...json("../../examples/amm-tip/manifests/amm_swap_tip_receipt.json"), state: CHAIN_HELD },
};

/** The receipt intake swap with node-held keys, as the example declares them:
 * the same circuit, as pss_public_contract_test's `process_result_held`
 * (TipResult<1, 1, 0, 2>, no sealed thirds) takes it. */
export const AMM_SWAP_HELD = {
  circuit: AMM_SWAP_RECEIPT.circuit,
  manifest: {
    ...(AMM_SWAP_RECEIPT.manifest as object),
    circuit: "amm_swap_tip_held",
    state: { "$state_keys.reads[0]": "node", "$state_keys.writes[0]": "node" },
  },
};

const field = { kind: "field" };
const arr = (n: number) => ({ kind: "array", length: n, type: field });
const pub = (name: string, type: unknown) => ({ name, type, visibility: "public" });
const priv = (name: string, type: unknown) => ({ name, type, visibility: "private" });

/** The stale period pss_public_contract_test's contract is deployed with,
 * for TEST_PLAIN's namespace. */
export const TEST_PLAIN_STALE_BLOCKS = 3;

/** An on-chain intake circuit with pss_public_contract_test's result shape: one
 * chain-held key read and written, two private app inputs, one pinned read
 * (public, after the key slots), two app outputs, one third of five fields
 * per node; the return value leads with the request id. */
export const TEST_PLAIN = {
  circuit: {
    abi: {
      parameters: [
        pub("namespace", field),
        pub("vk_hash", field),
        pub("in_slots", arr(1)),
        pub("out_slots", arr(1)),
        pub("price", field),
        priv("amount_in", field),
        priv("direction", field),
        priv("user_nonce", field),
        priv("state", arr(2)),
        priv("nsk_app", field),
      ],
      return_type: {
        abi_type: {
          kind: "struct",
          path: "Out",
          fields: [
            { name: "request_id", type: field },
            { name: "old_c", type: field },
            { name: "new_c", type: field },
            { name: "npk_app_hash", type: field },
            { name: "ok", type: field },
            { name: "o0", type: field },
            { name: "o1", type: field },
          ],
        },
        visibility: "public",
      },
      error_types: {},
    },
  },
  manifest: {
    manifest: 1,
    circuit: "test_plain",
    namespace_param: "namespace",
    state_keys: { reads: 1, writes: 1 },
    intake: "onchain",
    outcome: "none",
    binding: "turn",
    witness: [
      { param: "namespace", from: { PUBLIC: "$namespace" } },
      { param: "vk_hash", from: { PUBLIC: "$vk_hash" } },
      { param: "in_slots", from: { PUBLIC: ["$state_keys.reads[0]"] } },
      { param: "out_slots", from: { PUBLIC: ["$state_keys.writes[0]"] } },
      { param: "price", from: { PUBLIC: "price" } },
      { param: "amount_in", from: { PUBLIC: "amount_in" } },
      { param: "direction", from: { PUBLIC: "direction" } },
      { param: "user_nonce", from: { PUBLIC: "$user_nonce" } },
      { param: "state", from: { LOAD: "$state_keys.reads[0]", slice: [0, 2], len: 2 } },
      { param: "nsk_app", from: { LOAD: "nsk_app", slice: [0, 1], len: 1 } },
    ],
    outputs: [{ TACEO_store: "out0", STORE: "$state_keys.writes[0]", len: 2, note_hash: "new_c" }],
    state: { "$state_keys.reads[0]": "chain", "$state_keys.writes[0]": "chain" },
    commitment_slot: { "$state_keys.reads[0]": { old: "old_c" } },
    public_reads: [{ contract: "0x01", function: "get_price()", args: [], param: "price" }],
  },
};

/** The client configuration with the three circuits pinned to VK_HASH
 * (one at a time is pinned per test where the vk hash must pick the circuit)
 * and the namespace's stale period `staleBlocks` (the examples' 50 unless
 * given). */
export function clientConfig(url: string, circuits: NonNullable<PssClientConfig["circuits"]>, staleBlocks: number | null = 50): PssClientConfig {
  return {
    staleBlocks,
    orchestratorUrl: url,
    allowInsecureHttp: true,
    nodeKeys: NODE_KEYS,
    vkHashes: Object.fromEntries(Object.keys(circuits).map((n) => [n, VK_HASH])),
    circuits,
    contractAddress: NAMESPACE,
    timeoutMs: 5_000,
  };
}

const TEST_PROOF = "0x" + Array.from({ length: 458 }, (_, i) => (i + 1).toString(16).padStart(64, "0")).join("");

/** The fields of each third of the AMM swap's chain-held record. */
export const THIRD_FIELDS = 14;

/** Node `node`'s key id in a fixture third. */
export const keyId = (node: number): bigint => 0x1100n + BigInt(node);

/** One sealed third: an 8-byte key id and `fields - 1` 32-byte fields. */
export function third(node: number, salt: number, fields: number): string {
  const keyId_ = keyId(node).toString(16).padStart(16, "0");
  const body = Array.from({ length: fields - 1 }, (_, k) => (salt * 1000 + node * 100 + k + 1).toString(16).padStart(64, "0")).join("");
  return "0x" + keyId_ + body;
}

export interface AnswerInput {
  /** The public inputs before the request id binding (built by the caller). */
  publicInputs: (bigint | string)[];
  chainRequestId: string;
  oldCommitments: (bigint | string)[];
  /** The pinned read values the machine request id covers (none by default). */
  reads?: (bigint | string)[];
  newCommitments: (bigint | string)[];
  /** Fields per third; 0 for no record. */
  thirdFields: number;
  salt?: number;
  /** Sign under this request id instead of the machine request id. */
  signedRequestId?: string;
}

/** A signed answer of FETCH by chain request id. */
export async function signedAnswer(a: AnswerInput): Promise<ExecuteResponse> {
  const request_id =
    a.signedRequestId ??
    fieldHex((await machineRequestId(a.chainRequestId, a.oldCommitments.map((x) => BigInt(x)), (a.reads ?? []).map((x) => BigInt(x)))).toBigInt());
  const commitments = a.newCommitments.map((c) => fieldHex(BigInt(c)));
  const records =
    a.thirdFields > 0
      ? [{ key: "pool", note_hash: commitments[0]!, c: [0, 1, 2].map((i) => third(i, a.salt ?? 1, a.thirdFields)) as Triple<string> }]
      : [];
  const signatures: Signature[] = [];
  for (let i = 0; i < 3; i++) {
    const hashes = await Promise.all(records.map((r) => recordHash(r.c[i]!)));
    const m = await resultMessage(NAMESPACE, request_id, commitments, i, await sealedHash(hashes));
    signatures.push(await NODE_SIGNERS[i]!.sign(m));
  }
  return {
    request_id,
    vk_hash: VK_HASH,
    proof: TEST_PROOF,
    public_inputs: a.publicInputs.map((x) => fieldHex(BigInt(x))),
    stored: [],
    records,
    signatures: signatures as Triple<Signature>,
  };
}

/** The trader's partial note in the AMM swap fixtures: a clear app input
 * of the swap, which the round echoes right after ok. */
export const AMM_PARTIAL_NOTE = 0x9an;

/** An AMM swap answer for chain request `chainRequestId` at old commitment
 * `oldC` (an attempt; another oldC is another attempt), under either
 * non-secret-shared intake (the proof outputs the chain request id): with
 * one chain-held record of THIRD_FIELDS-field thirds, or `held`, the
 * node-held answer (AMM_SWAP_HELD) with no record. */
export async function ammAnswer(chainRequestId: string, oldC: bigint, newC: bigint, opts: { ok?: boolean; salt?: number; held?: boolean } = {}) {
  const ok = opts.ok ?? true;
  return signedAnswer({
    chainRequestId,
    publicInputs: [BigInt(NAMESPACE), BigInt(VK_HASH), POOL_KEY, POOL_KEY, chainRequestId, oldC, newC, NPK_APP_HASH, ok ? 1n : 0n, AMM_PARTIAL_NOTE, ok ? 0n : 8n, ok ? 33450n : 0n],
    oldCommitments: [oldC],
    newCommitments: [newC],
    thirdFields: opts.held ? 0 : THIRD_FIELDS,
    salt: opts.salt,
  });
}

/** An AMM swap request (user nonce `nonce`, default 7) and ammAnswer for it. */
export async function ammSwapAnswer(oldC: bigint, newC: bigint, opts: { nonce?: bigint; ok?: boolean; salt?: number; held?: boolean } = {}) {
  const request: TipRequest = await buildTipRequestWith(
    { namespace: NAMESPACE, vkHash: VK_HASH, inputs: [25000n, 0n, 33000n, AMM_PARTIAL_NOTE] },
    opts.nonce ?? 7n,
  );
  return { request, response: await ammAnswer(request.chainRequestId, oldC, newC, opts) };
}

/** examples/lending-tip's deposit round under secret-shared receipt intake, as it
 * registers: node-held, a tree-valued book (two new leaf hashes), the
 * epoch-pinned price (two pinned values), one completed note hash, an
 * outcome ciphertext of eight fields and its three app values: the exit tag
 * it replaced (a filler where it replaced none), the book's append index (0
 * on the clear deployment) and the inputs-opened bit. */
export const LENDING_DEPOSIT_SHARED = {
  circuit: { abi: json("fixtures/deposit_shared.abi.json").abi },
  manifest: json("../../examples/lending-tip/manifests/deposit_shared.json"),
};

/** A signed answer for lending's secret-shared deposit at chain request
 * `chainRequestId` (the proof's request id over C): price 0x7d0 at epoch 4,
 * new leaf hashes 0x11 and 0x12, outcome tag 0x7a, note hash 0x4a,
 * ciphertext 0xc0.. 0xc7, the exit tag 0xe1, the append index 0, the
 * inputs-opened bit 1, then its one delivery: tag 0xda, note hash 0xdb,
 * ciphertext 0xd0.. 0xd8. */
export async function depositSharedAnswer(chainRequestId: string, oldC: bigint, newC: bigint, ciphertext = 0xc0n) {
  const reads = [0x7d0n, 4n, 0x64n];
  const mrid = (await machineRequestId(chainRequestId, [oldC], reads)).toBigInt();
  const ct = Array.from({ length: 8 }, (_, k) => ciphertext + BigInt(k));
  return signedAnswer({
    chainRequestId,
    publicInputs: [
      BigInt(NAMESPACE), BigInt(VK_HASH), MARKET_KEY, MARKET_KEY, ...reads, chainRequestId, mrid, oldC, newC, NPK_APP_HASH, 0x11n, 0x12n, 0x7an, 0x4an, ...ct, 0xe1n, 0n, 1n,
      0xdan, 0xdbn, ...Array.from({ length: 9 }, (_, k) => 0xd0n + BigInt(k)),
    ],
    oldCommitments: [oldC],
    reads,
    newCommitments: [newC],
    thirdFields: 0,
  });
}

/** examples/lending-tip's deposit under on-chain intake, as it registers:
 * node-held, a tree-valued book, the epoch-pinned price and the
 * tolerance-pinned clock, partial-note delivery under public outputs
 * (`outcome: partial`: the request's partial note right after ok), and the
 * owner layout's app outputs `[code, position, mask, payout, new_hashes[2]]`
 * (`OwnerNoteOutputs`). */
export const LENDING_DEPOSIT = {
  circuit: { abi: json("fixtures/deposit.abi.json").abi },
  manifest: json("../../examples/lending-tip/manifests/deposit.json"),
};

/** A signed answer for lending's deposit at chain request `chainRequestId`
 * (the proof's request id over its inputs), 19 public inputs: price 0xfa at
 * epoch 1, clock 100, ok, the partial note 0x9a, code 0, position 1, mask 1,
 * payout 0, new leaf hashes 0x11 and 0x12. */
export async function depositAnswer(chainRequestId: string, oldC: bigint, newC: bigint) {
  const reads = [0xfan, 1n, 0x64n];
  return signedAnswer({
    chainRequestId,
    publicInputs: [BigInt(NAMESPACE), BigInt(VK_HASH), MARKET_KEY, MARKET_KEY, ...reads, chainRequestId, oldC, newC, NPK_APP_HASH, 1n, 0x9an, 0n, 1n, 1n, 0n, 0x11n, 0x12n],
    oldCommitments: [oldC],
    reads,
    newCommitments: [newC],
    thirdFields: 0,
  });
}

/** A test_plain request and answer: inputs [10, 1], price 0xe0, outputs [5, 6]. */
export async function testPlainAnswer(oldC: bigint, newC: bigint) {
  const request = await buildTipRequestWith({ namespace: NAMESPACE, vkHash: VK_HASH, inputs: [10n, 1n] }, 3n);
  const response = await signedAnswer({
    chainRequestId: request.chainRequestId,
    publicInputs: [BigInt(NAMESPACE), BigInt(VK_HASH), 0x5001n, 0x5001n, 0xe0n, request.chainRequestId, oldC, newC, NPK_APP_HASH, 1n, 5n, 6n],
    oldCommitments: [oldC],
    reads: [0xe0n],
    newCommitments: [newC],
    thirdFields: 5,
  });
  return { request, response };
}

/** A secret-shared-intake round as it registers: the circuit's ABI fixture
 * (`fixtures/<circuit>.abi.json`) and the example's manifest. */
export function sharedRound(example: string, circuit: string) {
  return { circuit: { abi: json(`fixtures/${circuit}.abi.json`).abi }, manifest: json(`../../examples/${example}/manifests/${circuit}.json`) };
}

/** A secret-shared round's outcome shape (outcomeShape) and a signed answer for it
 * at chain request `chainRequestId`, every public input at the library's
 * place and told apart: slots 0x5100 + k, pinned values 0x7d0 + k, old
 * commitments 0x0c + k, new 0x1c + k, npk_app_hash 0x9b, new leaf hashes
 * 0x11 + k, the outcome tag 0x7a, note hashes 0x4a + k, the ciphertext 0xc0
 * + k (as many fields as the circuit's `ciphertext` output), the app values
 * 1 and the deliveries' fields 0xd0 + k. */
export async function sharedRoundAnswer(round: { circuit: { abi: unknown }; manifest: unknown }, chainRequestId: string): Promise<{ shape: OutcomeShape; response: ExecuteResponse }> {
  const shape = outcomeShape(round.circuit, queued(round.manifest));
  const L = publicLayout(round.circuit.abi as never).returnLeaves.filter((l) => /^ciphertext\[\d+\]$/.test(l.path)).length;
  const run = (from: bigint, n: number) => Array.from({ length: n }, (_, k) => from + BigInt(k));
  const { reads: R, writes: W, pinned: Q, noteHashes: H } = shape;
  const T = shape.newHashes ?? 0;
  const K = shape.appValues ?? 0;
  const sent = (shape.deliveries ?? 0) * (2 + (shape.deliveryLength ?? 0));
  const pinned = run(0x7d0n, Q);
  const oldC = run(0x0cn, R);
  const newC = run(0x1cn, W);
  const mrid = (await machineRequestId(chainRequestId, oldC, pinned)).toBigInt();
  const response = await signedAnswer({
    chainRequestId,
    publicInputs: [
      BigInt(NAMESPACE), BigInt(VK_HASH), ...run(0x5100n, R), ...run(0x5100n, W), ...pinned,
      BigInt(chainRequestId), mrid, ...oldC, ...newC, NPK_APP_HASH, ...run(0x11n, T), 0x7an, ...run(0x4an, H), ...run(0xc0n, L), ...Array<bigint>(K).fill(1n),
      ...run(0xd0n, sent),
    ],
    oldCommitments: oldC,
    reads: pinned,
    newCommitments: newC,
    thirdFields: 0,
  });
  return { shape, response };
}

const CONTRACT_FIXTURES = {
  PssPublicTest: "PssPublicTest.result.abi.json",
  AmmTip: "AmmTip.result.abi.json",
  LendingTip: "LendingTip.result.abi.json",
} as const;

/** A contract's fixture functions as aztec.js loads them. */
export function contractAbis(name: keyof typeof CONTRACT_FIXTURES): { storageLayout: Record<string, { slot: string }>; functions: Record<string, FunctionAbi> } {
  const f = json(`fixtures/${CONTRACT_FIXTURES[name]}`) as { storageLayout: Record<string, { slot: string }>; functions: FunctionAbi[] };
  return { storageLayout: f.storageLayout, functions: Object.fromEntries(f.functions.map((x) => [x.name, x])) };
}

