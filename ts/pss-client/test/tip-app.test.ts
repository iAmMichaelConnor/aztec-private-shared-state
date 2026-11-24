// A deployed tip app as its user's client reaches it (tip-app.ts): the
// request under partial-note delivery with what it keeps, the wait on the
// queue at the artifact's slot, and the private outcome read at the state
// view's outcome slot with the circuit's plaintext length.

import assert from "node:assert/strict";
import { describe, test } from "node:test";

import { AztecAddress } from "@aztec-labs/aztec.js/addresses";
import { Fr } from "@aztec-labs/aztec.js/fields";
import type { AbiType, FunctionAbi } from "@aztec-labs/stdlib/abi";
import { FunctionType } from "@aztec-labs/stdlib/abi";

import {
  completedNoteHash,
  DONE_APPLIED,
  fieldHex,
  HANDLE_KEY_NAME,
  HANDLE_PARTIAL_NAME,
  OUTCOME_LOG_FIELDS,
  outcomeDeliveryArgs,
  outcomeLogTag,
  outcomePlaintextLength,
  outcomeSlot,
  PARTIAL_NOTE_NAME,
  partialCommitment,
  QueueSlots,
  readAndDeliverOutcome,
  readOutcome,
  requestOutcome,
  resolveConfig,
  SecretStore,
  stateViewName,
  TIP_STATE_PATH,
  tipAppAt,
  waitForRequest,
  type Descriptor,
  type OutcomeRequest,
  type TipApp,
} from "../src/internal.ts";
import { AMM_SWAP, blockHashOf, clientConfig, encryptOutcome, logNode, NODE_KEYS, sharedRound } from "@aztec-pss/test-support";

const AMM_SHARED = sharedRound("amm-tip", "amm_swap_tip_shared");
const BORROW = sharedRound("lending-tip", "borrow_shared");
const config = clientConfig("http://127.0.0.1:1", { amm_swap_tip_shared: AMM_SHARED, borrow_shared: BORROW, amm_swap_tip: AMM_SWAP });
const CONFIG = resolveConfig({ ...config, vkHashes: { ...config.vkHashes, amm_swap_tip_shared: 1n, borrow_shared: 2n } });
const CONTRACT = AztecAddress.fromBigIntUnsafe(0xa11ce5n);
const OWNER = 0x0a11cen;
const QUEUE_SLOT = 7n;
const OUTCOME_SLOT = 0x2an;

/** The app's state view, named `state` here (the name is the app's). */
const VIEW: FunctionAbi = {
  name: "state",
  functionType: FunctionType.UTILITY,
  isOnlySelf: false,
  isStatic: true,
  isInitializer: false,
  parameters: [],
  returnType: { kind: "struct", path: TIP_STATE_PATH, fields: [{ name: "outcome_slot", type: { kind: "field" } }] } as AbiType,
  errorTypes: {},
};

interface Sent {
  target: unknown;
  request: { circuit: string; inputs: Record<string, unknown>; currentBlock: number; secrets: unknown };
  send: unknown;
  options: { currentBlock: number; values: Record<string, unknown> };
}

/** A TipApp over stand-ins: the node's block, storage and logs, the
 * contract's view, and a pss-client whose requestIntake records what it is
 * given and answers with a secret-shared receipt intake of request id 0x1d. */
function app(storage: Map<bigint, bigint> = new Map(), logs: Fr[][] = []): TipApp & { sent: Sent[] } {
  const sent: Sent[] = [];
  const pss = {
    config: CONFIG,
    requestIntake: async (target: unknown, request: Sent["request"], send: unknown, options: Sent["options"]) => {
      sent.push({ target, request, send, options });
      const s = request.secrets as { outcomeKey: bigint; outcomeTag: bigint };
      const r = {
        chainRequestId: fieldHex(0x1dn),
        values: [],
        outcomeKey: fieldHex(s.outcomeKey),
        outcomeTag: fieldHex(s.outcomeTag),
        commitmentNames: [],
        blinding: fieldHex(1n),
        sharing: { summands: [[fieldHex(2n)], [fieldHex(3n)], [fieldHex(4n)]], salts: [fieldHex(5n), fieldHex(6n), fieldHex(7n)] },
      };
      return { intake: { intake: "shared_receipt", receipts: { request: r, expiryBlock: 99 } }, args: ["args"], sent: "receipt" };
    },
  };
  return {
    sent,
    node: {
      getBlockNumber: async () => 42,
      getBlockData: async (block) => ({ blockHash: blockHashOf(block) }),
      getPublicStorageAt: async (_block, _contract: AztecAddress, slot: Fr) => new Fr(storage.get(slot.toBigInt()) ?? 0n),
      getPrivateLogsByTags: logNode(logs).getPrivateLogsByTags,
    },
    contract: {
      address: CONTRACT,
      artifact: { name: "App", functions: [VIEW], storageLayout: { queue: { slot: fieldHex(QUEUE_SLOT) } } },
      methods: { state: () => ({ send: async () => undefined, simulate: async () => ({ result: { outcome_slot: OUTCOME_SLOT } }) }) },
    },
    pss: pss as never,
  };
}

const sender = { toBigInt: () => OWNER };

describe("a tip app's request, wait and outcome", () => {
  test("the plaintext length is the circuit's ciphertext less the tag, for private outcomes only", () => {
    assert.equal(outcomePlaintextLength(AMM_SHARED.circuit), 2);
    assert.equal(outcomePlaintextLength(BORROW.circuit), 7);
    assert.throws(() => outcomePlaintextLength(AMM_SWAP.circuit), /no outcome ciphertext/);
    assert.deepEqual(CONFIG.plaintextLengths, { amm_swap_tip_shared: 2, borrow_shared: 7 });
  });

  test("the state view is found by its return type, and the outcome slot read from it", async () => {
    const a = app();
    assert.equal(stateViewName(a.contract.artifact), "state");
    assert.equal(await outcomeSlot(a.contract, CONTRACT), OUTCOME_SLOT);
    assert.throws(() => stateViewName({ name: "App", functions: [] }), /no state view/);
  });

  // An app's client reaches a deployed app with its descriptor, manifests
  // and build: the contract at the address, and a pss-client of the
  // namespace with the build's circuits and the descriptor's stale period.
  test("tipAppAt reaches a deployed app with the namespace's pss-client", () => {
    const descriptor: Descriptor = { descriptor: 1, name: "amm-tip", stale_blocks: 77, packages: [{ name: "amm_swap_tip_shared", circuit: "amm_swap_tip_shared" }] };
    const reached = tipAppAt({
      node: app().node,
      wallet: {} as never,
      network: { orchestratorUrl: "https://127.0.0.1:1", nodeKeys: NODE_KEYS },
      build: { artifact: { name: "App", functions: [VIEW], nonDispatchPublicFunctions: [], outputs: { structs: {}, globals: {} }, storageLayout: {}, fileMap: {} } as never, circuits: { amm_swap_tip_shared: AMM_SHARED.circuit }, vkHashes: { amm_swap_tip_shared: "0x01" } },
      descriptor,
      manifests: { amm_swap_tip_shared: AMM_SHARED.manifest },
      address: CONTRACT,
    });
    assert.ok(reached.contract.address.equals(CONTRACT));
    assert.equal(reached.pss.config.staleBlocks, 77);
    assert.equal(reached.pss.config.contractAddress, fieldHex(CONTRACT.toBigInt()));
    assert.deepEqual(Object.keys(reached.pss.config.manifests), ["amm_swap_tip_shared"]);
    assert.equal(reached.pss.config.plaintextLengths.amm_swap_tip_shared, 2);
  });

  // The secret-shared swap: the sender's partial note merged under its
  // reserved name and its rho sent in its place, the store's outcome key and
  // tag drawn, the block the node reports, and the request's keys kept.
  test("requestOutcome merges the partial note, sends rho in its place and keeps the request's keys", async () => {
    const a = app();
    const secrets = new SecretStore(0x5ecn, CONTRACT.toBigInt());
    const expected = await new SecretStore(0x5ecn, CONTRACT.toBigInt()).nextPartial(OWNER);
    const out = await requestOutcome(a, { circuit: "amm_swap_tip_shared", method: "swap_shared", inputs: { amount_in: 5n, direction: 0n, min_out: 0n }, secrets }, { from: sender });
    const [s] = a.sent;
    assert.deepEqual(s!.target, { contract: a.contract, method: "swap_shared" });
    assert.deepEqual(s!.request.inputs, { amount_in: 5n, direction: 0n, min_out: 0n, [PARTIAL_NOTE_NAME]: fieldHex(await partialCommitment(OWNER, expected.rho)) });
    assert.deepEqual(s!.options, { currentBlock: 42, values: { [PARTIAL_NOTE_NAME]: expected.rho } });
    assert.equal(s!.request.currentBlock, 42);
    assert.deepEqual(out.request, {
      circuit: "amm_swap_tip_shared",
      chainRequestId: fieldHex(0x1dn),
      owner: fieldHex(OWNER),
      rho: expected.rho,
      n: 0,
      outcomeKey: fieldHex(expected.outcomeKey),
      outcomeTag: fieldHex(expected.outcomeTag),
    });
    assert.equal(out.sent, "receipt");
  });

  // The enc keys a secret-shared on-chain round encodes under: by default a
  // reader of the keys the contract stores (get_enc_key, simulated as the
  // sender), which only that intake calls; an ask's own keys pass through.
  test("requestOutcome reads the enc keys the contract stores unless the ask gives them", async () => {
    const a = app();
    const asked: { i: number; from: unknown }[] = [];
    a.contract.methods.get_enc_key = ((i: number) => ({
      send: async () => undefined,
      simulate: async (options: { from: unknown }) => (asked.push({ i, from: options.from }), { result: { x: 10n + BigInt(i), y: 20n, epoch: 1n } }),
    })) as never;
    const secrets = new SecretStore(0x5ecn, CONTRACT.toBigInt());
    const ask = { circuit: "amm_swap_tip_shared", method: "swap_shared", inputs: { amount_in: 5n, direction: 0n, min_out: 0n }, secrets };
    await requestOutcome(a, ask, { from: sender });
    const read = (a.sent[0]!.request as unknown as { encKeys: () => Promise<unknown> }).encKeys;
    assert.equal(typeof read, "function");
    assert.equal(asked.length, 0, "read only when the intake encodes under them");
    assert.deepEqual(await read(), [0, 1, 2].map((i) => ({ x: 10n + BigInt(i), y: 20n, epoch: 1 })));
    assert.deepEqual(asked, [0, 1, 2].map((i) => ({ i, from: sender })));
    const own = [{ x: 1n, y: 2n, epoch: 3 }, { x: 1n, y: 2n, epoch: 3 }, { x: 1n, y: 2n, epoch: 3 }];
    await requestOutcome(a, { ...ask, encKeys: own as never }, { from: sender });
    assert.equal((a.sent[1]!.request as unknown as { encKeys: unknown }).encKeys, own);
  });

  // A round whose C commits a delivery handle (lending's borrow): the handle
  // of the same request counter, merged and kept.
  test("requestOutcome takes the delivery handle of the same counter where C commits one", async () => {
    const a = app();
    const secrets = new SecretStore(0x5ecn, CONTRACT.toBigInt());
    const handle = await new SecretStore(0x5ecn, CONTRACT.toBigInt()).handle(OWNER, 0);
    const out = await requestOutcome(a, { circuit: "borrow_shared", method: "borrow_shared", inputs: { position: 1n, amount: 2n }, secrets, owner: OWNER }, { from: sender });
    const [s] = a.sent;
    assert.equal(s!.request.inputs[HANDLE_PARTIAL_NAME], handle.handlePartial);
    assert.equal(s!.request.inputs[HANDLE_KEY_NAME], handle.inputs[HANDLE_KEY_NAME]);
    assert.equal(s!.options.values[HANDLE_PARTIAL_NAME], handle.handleRho);
    assert.deepEqual(out.request.handle, { handleKey: handle.handleKey, handleRho: handle.handleRho });
  });

  // The non-secret-shared swap: the partial note is its clear input, and its
  // outcome is a public completion, which readOutcome refuses.
  test("requestOutcome puts a non-secret-shared round's partial note at its clear input", async () => {
    const a = app();
    const name = CONFIG.intakeLayouts.amm_swap_tip!.partialNote!;
    const pss = { ...(a.pss as unknown as object), requestIntake: async (_t: unknown, request: Sent["request"], _s: unknown, options: Sent["options"]) => {
      a.sent.push({ target: _t, request, send: _s, options });
      return { intake: { intake: "onchain", request: { chainRequestId: fieldHex(0x1dn), values: [], userNonce: fieldHex(3n) } }, args: [], sent: undefined };
    } };
    const secrets = new SecretStore(0x5ecn, CONTRACT.toBigInt());
    const out = await requestOutcome({ ...a, pss: pss as never }, { circuit: "amm_swap_tip", method: "swap", inputs: { amount_in: 5n }, secrets }, { from: sender });
    assert.equal(out.request.outcomeKey, undefined);
    const [s] = a.sent;
    assert.ok(Object.hasOwn(s!.request.inputs, name));
    assert.ok(!Object.hasOwn(s!.request.inputs, PARTIAL_NOTE_NAME));
    assert.equal(s!.options.values[name], (await new SecretStore(0x5ecn, CONTRACT.toBigInt()).nextPartial(OWNER)).rho);
    const request: OutcomeRequest = { circuit: "amm_swap_tip", chainRequestId: fieldHex(1n), owner: fieldHex(OWNER), rho: fieldHex(2n), n: 0 };
    await assert.rejects(readOutcome(a, request, CONTRACT), /no private outcome/);
  });

  test("waitForRequest watches the queue at the artifact's slot until the head passes the request", async () => {
    const slots = new QueueSlots(QUEUE_SLOT);
    const storage = new Map<bigint, bigint>([
      [slots.tail().toBigInt(), 1n],
      [slots.headIndex().toBigInt(), 1n],
      [(await slots.request(0)).toBigInt(), 0x1dn],
      [(await slots.done(0)).toBigInt(), BigInt(DONE_APPLIED)],
    ]);
    const polled = await waitForRequest(app(storage), { chainRequestId: 0x1dn }, { intervalMs: 1, timeoutMs: 1_000 });
    assert.equal(polled.status, "applied");
    assert.equal(polled.index, 0);
  });

  test("readOutcome opens the log under the request's tag and rebuilds the note at the view's slot", async () => {
    const r: OutcomeRequest = { circuit: "amm_swap_tip_shared", chainRequestId: fieldHex(0x1dn), owner: fieldHex(OWNER), rho: fieldHex(0x5eedn), n: 0, outcomeKey: fieldHex(0x6b6bn), outcomeTag: fieldHex(0x7a7an) };
    const noteHash = await completedNoteHash(OUTCOME_SLOT, await partialCommitment(OWNER, 0x5eedn), [0n, 24000n], 0x1dn);
    const log = [await outcomeLogTag(CONTRACT, 0x7a7an), new Fr(noteHash), ...(await encryptOutcome([0n, 24000n], 0x6b6bn, noteHash)).map((x) => new Fr(x))];
    while (log.length < OUTCOME_LOG_FIELDS) log.push(Fr.random());
    const found = await readOutcome(app(new Map(), [log]), r, CONTRACT);
    assert.ok(found);
    assert.deepEqual(found.plaintext, [0n, 24000n]);
    assert.equal(found.note.noteHash, fieldHex(await completedNoteHash(OUTCOME_SLOT, await partialCommitment(OWNER, 0x5eedn), [0n, 24000n], 0x1dn)));
    assert.equal(found.tx.txHash, fieldHex(0x7777n));
  });

  test("readAndDeliverOutcome hands the logged note to the owner's PXE through the outcome-note utility", async () => {
    const r: OutcomeRequest = { circuit: "amm_swap_tip_shared", chainRequestId: fieldHex(0x1dn), owner: fieldHex(OWNER), rho: fieldHex(0x5eedn), n: 0, outcomeKey: fieldHex(0x6b6bn), outcomeTag: fieldHex(0x7a7an) };
    const log = async (requestId: bigint) => {
      const noteHash = await completedNoteHash(OUTCOME_SLOT, await partialCommitment(OWNER, 0x5eedn), [0n, 24000n], requestId);
      const fields = [await outcomeLogTag(CONTRACT, 0x7a7an), new Fr(noteHash), ...(await encryptOutcome([0n, 24000n], 0x6b6bn, noteHash)).map((x) => new Fr(x))];
      while (fields.length < OUTCOME_LOG_FIELDS) fields.push(Fr.random());
      return fields;
    };
    const delivered: { args: unknown[]; from: unknown }[] = [];
    const withUtility = (logs: Fr[][]) => {
      const a = app(new Map(), logs);
      a.contract.methods.deliver_outcome = ((...args: unknown[]) => ({ send: async () => undefined, simulate: async ({ from }: { from: unknown }) => void delivered.push({ args, from }) })) as never;
      return a;
    };
    const found = await readAndDeliverOutcome(withUtility([await log(0x1dn)]), r, CONTRACT);
    assert.ok(found?.noteMatches);
    assert.deepEqual(delivered, [{ args: outcomeDeliveryArgs(found), from: CONTRACT }]);
    // a note completed under another request id is not the logged one: read, not delivered
    const other = await readAndDeliverOutcome(withUtility([await log(0x1en)]), r, CONTRACT);
    assert.equal(other?.noteMatches, false);
    assert.equal(delivered.length, 1);
    await assert.rejects(readAndDeliverOutcome(app(), r, CONTRACT), /no method deliver_outcome/);
  });
});
