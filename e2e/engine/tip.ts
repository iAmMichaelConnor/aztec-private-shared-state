// What the tip steps share: a scenario's tip deployment as the run sees it
// (harness.json tip.deployments), its queue and key slots read at a block,
// the transaction that finished a queue index, the notes each owner's client
// keeps, a send that skips the wallet's simulation, the relayer's status and
// process, and the local network's admin and debug calls.
import { AztecAddress } from "@aztec-labs/aztec.js/addresses";
import { Contract } from "@aztec-labs/aztec.js/contracts";
import { Fr } from "@aztec-labs/aztec.js/fields";
import { BlockNumber } from "@aztec-labs/foundation/branded-types";
import type { PXE } from "@aztec-labs/pxe/server";
import { GasFees } from "@aztec-labs/stdlib/gas";
import { computePublicDataTreeLeafSlot } from "@aztec-labs/stdlib/hash";
import { createAztecNodeDebugClient } from "@aztec-labs/stdlib/interfaces/client";
import { TxHash, type ExecutionPayload, type TxReceipt } from "@aztec-labs/stdlib/tx";
import { BaseWallet } from "@aztec-labs/wallet-sdk/base-wallet";
import {
  NodeQueueReader,
  fieldAddress,
  fieldHex,
  vkFieldsFromBbJson,
  type ExitNote,
  type FeeSendOptions,
  type FieldHexString,
  type FoundDelivery,
  resultFunctions,
  SEND_WAIT,
  type QueuedResult,
  type ResultFunction,
} from "@aztec-pss/pss-client";

import { readFileSync } from "node:fs";

import { relayerPidFile, type TipDeployment } from "../harness/harness.ts";
import type { RunContext } from "./context.ts";
import { check } from "./scope.ts";

/** One tip deployment of the scenario, by the name steps use. */
export interface Tip {
  name: string;
  /** The deployment's name in harness.json (its e2e/tip/<name>.json). */
  deployment: string;
  d: TipDeployment;
  address: AztecAddress;
  queue: NodeQueueReader;
}

export function tipOf(ctx: RunContext, ns: string | undefined): Tip {
  const name = ctx.namespace(ns);
  const deployment = ctx.scenario.tip?.[name];
  check(deployment !== undefined, `namespace ${name} is not one of the scenario's tip deployments`);
  const d = ctx.harness.tip?.deployments[deployment];
  check(d !== undefined, `tip deployment ${deployment} was not deployed`);
  const address = fieldAddress(d.address);
  return { name, deployment, d, address, queue: new NodeQueueReader(ctx.network.node, address, d.slots.queue) };
}

/** The deployment's contract in the wallet of `account`. */
export function tipContract(ctx: RunContext, tip: Tip, account: string): Contract {
  return Contract.at(tip.address, ctx.contract(tip.name).artifact, ctx.network.walletOf(account));
}

/** A package's 115 vk fields. */
export function tipVkFields(tip: Tip, circuit: string): Fr[] {
  const c = tip.d.circuits[circuit];
  check(c !== undefined, `${tip.name}: no package ${circuit}`);
  return vkFieldsFromBbJson(readFileSync(c.vk, "utf8"));
}

/** The slots of a circuit's request keys (harness.json `requestKeys`). */
export function keySlots(tip: Tip, circuit: string): { reads: string[]; writes: string[] } {
  const k = tip.d.requestKeys[circuit];
  check(k !== undefined, `${tip.name}: no request keys of ${circuit}`);
  return k;
}

/** A slot as harness.json spells it, or its value. */
type Slot = string | bigint;

/** A public storage slot of the deployment at `block` (default the latest). */
export async function storageAt(ctx: RunContext, tip: Tip, slot: Slot, block?: number): Promise<FieldHexString> {
  const value = await ctx.network.node.getPublicStorageAt((block ?? "latest") as never, tip.address, Fr.fromString(fieldHex(slot)));
  return fieldHex(value.toBigInt());
}

/** Where chain request `chainRequestId` sits in the deployment's queue at
 * `block`: its index, scanning from `from` (the last match; undefined when
 * it is not queued there), and the queue's tail. */
export async function queueIndexOf(tip: Tip, chainRequestId: string, block: number, from = 0): Promise<{ index?: number; tail: number }> {
  const { tail } = await tip.queue.snapshot(block);
  let index: number | undefined;
  for (let i = from; i < tail; i++) if ((await tip.queue.requestAt(i, block)) === chainRequestId) index = i;
  return { index, tail };
}

/** The queue's head and tail, the request's done flag and its circuit's
 * request keys' slots at `block` (default the latest), as one string: what
 * a landing that must change nothing compares before and after. */
export async function landingState(ctx: RunContext, tip: Tip, req: { circuit: string; index: number }, block?: number): Promise<string> {
  const s = await tip.queue.snapshot(block);
  return JSON.stringify([
    s.head,
    s.tail,
    await tip.queue.doneAt(req.index, block),
    ...(await Promise.all(keySlots(tip, req.circuit).writes.map((slot) => storageAt(ctx, tip, slot, block)))),
  ]);
}

/** A transaction as a block holds it. */
export interface MinedTx {
  block: number;
  txHash: string;
  /** Public storage written: leaf slot → value. */
  writes: Map<string, bigint>;
  /** The public logs the deployment emitted in it, as fields. */
  logs: Fr[][];
}

/** The leaf of a public storage slot of the deployment. */
export async function leafOf(tip: Tip, slot: Slot): Promise<string> {
  return (await computePublicDataTreeLeafSlot(tip.address, Fr.fromString(fieldHex(slot)))).toString();
}

/** The transactions of blocks `from`..latest, in order. */
export async function minedSince(ctx: RunContext, tip: Tip, from: number): Promise<MinedTx[]> {
  const node = ctx.network.node;
  const latest = await node.getBlockNumber();
  const out: MinedTx[] = [];
  for (let b = Math.max(1, from); b <= latest; b += 50) {
    const blocks = await node.getBlocks(BlockNumber(b), Math.min(50, latest - b + 1), { includeTransactions: true });
    for (const block of blocks) {
      for (const effect of block.body.txEffects) {
        out.push({
          block: Number(block.header.globalVariables.blockNumber),
          txHash: effect.txHash.toString(),
          writes: new Map(effect.publicDataWrites.map((w) => [w.leafSlot.toString(), w.value.toBigInt()])),
          logs: effect.publicLogs.filter((l) => l.contractAddress.equals(tip.address)).map((l) => l.getEmittedFields()),
        });
      }
    }
  }
  return out;
}

/** The mined transaction with this hash. */
export async function minedTx(ctx: RunContext, tip: Tip, txHash: string, block: number): Promise<MinedTx> {
  const tx = (await minedSince(ctx, tip, block)).find((t) => t.txHash === txHash);
  check(tx !== undefined, `transaction ${txHash} is not in block ${block} or later`);
  return tx;
}

/** The transaction that finished queue index `index` (wrote `done[index]`),
 * from block `from` on. */
export async function finishing(ctx: RunContext, tip: Tip, index: number, from: number): Promise<MinedTx> {
  const leaf = await leafOf(tip, (await tip.queue.slots.done(index)).toBigInt());
  const tx = (await minedSince(ctx, tip, from)).find((t) => t.writes.has(leaf));
  check(tx !== undefined, `${tip.name}: no transaction from block ${from} on wrote done[${index}]`);
  return tx;
}

// ---- contract functions ------------------------------------------------------

/** One function of an aztec.js Contract as the steps call it. */
export type Method = (...args: unknown[]) => {
  send(options: object): Promise<{ receipt: { txHash: { toString(): string }; blockNumber?: number } }>;
  simulate(options: object): Promise<{ result: unknown }>;
  getFunctionCall(): Promise<never>;
};

/** A Contract's functions by name. */
export function methodsOf(contract: { methods: object }): Record<string, Method> {
  return contract.methods as unknown as Record<string, Method>;
}

/** A call as a transaction is built from it: aztec.js's
 * ContractFunctionInteraction or BatchCall. */
export interface Requestable {
  request(options?: { fee?: FeeSendOptions["fee"] }): Promise<ExecutionPayload>;
}

// A send without the wallet's simulation. EmbeddedWallet.sendTx simulates
// the transaction's public part first and throws when it reverts, so a
// transaction whose public part reverts never reaches the node from it. A
// hostile lander needs no such wallet, and the tests of what a reverted
// landing leaves on the chain need its transaction mined: this proves and
// sends through wallet-sdk's BaseWallet.sendTx (proveTx, then the node's
// sendTx), named by its class: the EmbeddedWallet the node entrypoint
// exports is a subclass of the simulating one, so its prototype's parent
// is not BaseWallet. It runs after the PXE sync EmbeddedWallet.sendTx runs,
// with the fee options' fixed gas limits (there is no simulation to
// estimate them) and an optional priority fee, and waits for the block
// without throwing on a revert.
/** Proves and sends `call` from `account` with no simulation first; the
 * mined receipt, reverted or not. */
export async function sendUnsimulated(ctx: RunContext, account: string, call: Requestable, fee: FeeSendOptions, priorityFeePerL2Gas = 0n): Promise<TxReceipt> {
  const gas = fee.fee?.gasSettings;
  check(gas?.gasLimits !== undefined, "a send with no simulation takes the fee setting's fixed gas limits");
  const wallet = ctx.network.walletOf(account);
  const payload = await call.request({ fee: fee.fee });
  await (wallet as unknown as { pxe: PXE }).pxe.sync();
  const wait = { ...SEND_WAIT, dontThrowOnRevert: true };
  const send = BaseWallet.prototype.sendTx<typeof wait>;
  const { receipt } = await send.call(wallet, payload, {
    from: ctx.account(account),
    fee: { gasSettings: { ...gas, ...(priorityFeePerL2Gas > 0n && { maxPriorityFeesPerGas: new GasFees(0, priorityFeePerL2Gas) }) } },
    wait,
  });
  check(receipt.isMined(), `transaction ${receipt.txHash} is not mined (${receipt.status})`);
  return receipt;
}

// ---- the owners' notes -------------------------------------------------------

/** An owner's note of a tip deployment as the owner's client keeps it: an
 * outcome a tipOutcome step opened, or a notice a tipNotice or tipRecover
 * step opened. It holds what the note's exit tag is computed from
 * (pss-client ExitNote: the owner, the randomness, the request id; the
 * entry is the app's field of the plaintext) and the delivery handle the
 * note's entry holds after its round, under which the owner finds the
 * notice of a later round it did not request. */
export interface HeldNote {
  /** The tip deployment (a scenario's name). */
  namespace: string;
  /** The owner's account name. */
  owner: string;
  /** The note's fields before the request id. */
  plaintext: bigint[];
  /** The note's randomness: its request's rho, or the delivery handle's. */
  rho: string;
  /** The chain request id of the round that issued it. */
  requestId: string;
  /** The transaction that carried it. */
  tx: FoundDelivery["tx"];
  /** The handle the entry holds after the note's round: the request's own,
   * or for a notice the handle it was delivered to; none when the round
   * left none (a lender's). */
  handle?: { handleKey: string; handleRho: string };
}

const kept = new WeakMap<RunContext, HeldNote[]>();

/** Keeps `note` among its owner's notes (every step that opens a note
 * calls it). */
export function keepNote(ctx: RunContext, note: HeldNote): void {
  let notes = kept.get(ctx);
  if (!notes) kept.set(ctx, (notes = []));
  notes.push(note);
}

/** The notes `owner` keeps in the deployment whose plaintext field
 * `entryField` is `entry`, newest first: by the block and the place in the
 * block of the transaction that carried each. */
export async function notesOf(ctx: RunContext, tip: Tip, owner: string, entryField: number, entry: bigint): Promise<HeldNote[]> {
  const notes = (kept.get(ctx) ?? []).filter((n) => n.namespace === tip.name && n.owner === owner && n.plaintext[entryField] === entry);
  const placed = await Promise.all(
    notes.map(async (n, k) => {
      const r = await ctx.network.node.getTxReceipt(TxHash.fromString(n.tx.txHash));
      check(r.isMined(), `${tip.name}: the transaction ${n.tx.txHash} of ${owner}'s note of request ${n.requestId} is not mined`);
      return { n, at: [Number(r.blockNumber), r.txIndexInBlock ?? 0, k] };
    }),
  );
  placed.sort((a, b) => b.at[0]! - a.at[0]! || b.at[1]! - a.at[1]! || b.at[2]! - a.at[2]!);
  return placed.map((p) => p.n);
}

/** A kept note as pss-client's hatch helpers take it. */
export function exitNoteOf(ctx: RunContext, note: HeldNote, entry: bigint): ExitNote {
  return { owner: ctx.account(note.owner), rho: note.rho, requestId: note.requestId, entry };
}

// ---- the relayer -----------------------------------------------------------

/** The relayer's GET /status (pss-relayer main.ts). */
export interface RelayerStatus {
  from: string;
  last: { action: string; reason?: string; snapshot?: { head: number; tail: number; block: number } } | null;
  init: { state: string; tx?: string } | null;
}

/** GET /status of the relayer whose configuration file is `config`. */
export async function relayerStatusOf(config: string): Promise<RelayerStatus> {
  const { statusPort } = JSON.parse(readFileSync(config, "utf8")) as { statusPort: number };
  const res = await fetch(`http://127.0.0.1:${statusPort}/status`, { signal: AbortSignal.timeout(10_000) });
  return (await res.json()) as RelayerStatus;
}

/** GET /status of the deployment's relayer. */
export async function relayerStatus(tip: Tip): Promise<RelayerStatus> {
  check(tip.d.relayer !== undefined, `${tip.name}: the deployment has no relayer configuration`);
  return relayerStatusOf(tip.d.relayer);
}

/** The relayer's init round, as its configuration names it. */
export function relayerInit(tip: Tip): { circuit: string; method: string; inputs: string[] } | undefined {
  check(tip.d.relayer !== undefined, `${tip.name}: the deployment has no relayer configuration`);
  return (JSON.parse(readFileSync(tip.d.relayer, "utf8")) as { init?: { circuit: string; method: string; inputs: string[] } }).init;
}

/** The deployment's result function per circuit, as its relayer's
 * configuration names them (`methods`): what a user landing a result sends
 * too. */
export function tipResultFunction(tip: Tip): (result: QueuedResult) => ResultFunction {
  check(tip.d.relayer !== undefined, `${tip.name}: the deployment has no relayer configuration`);
  const { methods } = JSON.parse(readFileSync(tip.d.relayer, "utf8")) as { methods?: Record<string, ResultFunction> };
  return resultFunctions(methods ?? {});
}

export function relayerPid(ctx: RunContext, tip: Tip): number {
  const pid = Number(readFileSync(relayerPidFile(ctx.harness, tip.deployment), "utf8").trim());
  check(Number.isInteger(pid) && pid > 1, `${tip.name}: no relayer pid in ${relayerPidFile(ctx.harness, tip.deployment)}`);
  return pid;
}

/** The scheduler state letter of a process (/proc/<pid>/stat): `T` when stopped. */
export function processState(pid: number): string {
  const stat = readFileSync(`/proc/${pid}/stat`, "utf8");
  return stat.slice(stat.lastIndexOf(")") + 2).split(" ")[0]!;
}

// ---- the local network's admin and debug calls -------------------------------

async function adminRpc(method: string, params: unknown[]): Promise<unknown> {
  const { AZTEC_ADMIN_PORT, E2E_ADMIN_API_KEY } = process.env;
  check(AZTEC_ADMIN_PORT !== undefined && E2E_ADMIN_API_KEY !== undefined, "AZTEC_ADMIN_PORT and E2E_ADMIN_API_KEY are not set (run.sh exports both)");
  const res = await fetch(`http://127.0.0.1:${AZTEC_ADMIN_PORT}`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-api-key": E2E_ADMIN_API_KEY },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
  check(res.ok, `${method}: HTTP ${res.status}`);
  const body = (await res.json()) as { result?: unknown; error?: unknown };
  check(body.error === undefined, `${method}: ${JSON.stringify(body.error)}`);
  return body.result;
}

/** The sequencer's minTxsPerBlock (the local network's automine sequencer
 * reads it before each build). */
export async function minTxsPerBlock(): Promise<number> {
  const config = (await adminRpc("nodeAdmin_getConfig", [])) as { minTxsPerBlock?: number };
  return config.minTxsPerBlock ?? 1;
}

export async function setMinTxsPerBlock(n: number): Promise<void> {
  await adminRpc("nodeAdmin_setConfig", [{ minTxsPerBlock: n }]);
}

/** Mines one empty block (the local network's debug API). */
export async function mineBlock(ctx: RunContext): Promise<void> {
  await createAztecNodeDebugClient(ctx.harness.aztecNodeUrl).mineBlock();
}

/** Moves the local network's L2 time forward by at least `seconds`: the
 * automine sequencer's next L1 block takes the later timestamp and one
 * empty L2 checkpoint is built at it (the debug API's
 * warpL2TimeAtLeastBy). Every transaction anchored before it whose
 * expiration falls in between can no longer be included. */
export async function warpL2Time(ctx: RunContext, seconds: number): Promise<void> {
  await createAztecNodeDebugClient(ctx.harness.aztecNodeUrl).warpL2TimeAtLeastBy(seconds);
}
