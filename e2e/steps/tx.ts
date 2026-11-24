// A transaction calling a contract method, optionally carrying a round's
// proof as a capsule: landed (with the node-side and client-side negatives
// as options), proved and dropped before the node sees it, or refused by
// the sender's PXE in simulation.
import type { AztecAddress } from "@aztec-labs/aztec.js/addresses";
import { Contract } from "@aztec-labs/aztec.js/contracts";
import { Fr } from "@aztec-labs/aztec.js/fields";
import type { TxReceipt } from "@aztec-labs/stdlib/tx";
import { anchoredNonce, checkNullified, fieldHex, mineNonces, proofToFields, stageCapsule, txEffectFrom, type FeeSendOptions } from "@aztec-pss/pss-client";

import type { Note, Round } from "../engine/answer.ts";
import type { RunContext } from "../engine/context.ts";
import { expectRefused } from "../engine/machine.ts";
import { defineKind, refs, type Common } from "../engine/kind.ts";
import { big, check, keyHex, type Value } from "../engine/scope.ts";
import { timed } from "../harness/harness.ts";

// The client-side tamper. Proof field 100 of the capsule proof
// is XORed with 0xab, and the PXE's proving must refuse it with the backend
// message pinned here (the bb 6.0.0 shipped with @aztec-labs 6.0.0). Any
// other error (fees, transport, a contract assertion) fails the driver,
// because it would not show that the in-circuit verification caught the
// change. Simulated (EXPECT_REAL_PROOFS=0) verification is a no-op, so the
// case is skipped.
export const TAMPER_FIELD = 100;
export const TAMPER_MESSAGE = "Failed to verify the generated proof";

/** `proof`'s fields with field TAMPER_FIELD XORed with 0xab. */
export function tamperedProof(proof: string): Fr[] {
  const fields = proofToFields(proof);
  fields[TAMPER_FIELD] = new Fr(fields[TAMPER_FIELD]!.toBigInt() ^ 0xabn);
  return fields;
}

/** What every transaction step sends: the contract method `tx`. */
interface TxCall extends Common {
  tx: string;
  /** One of the scenario's contracts (default: its first). */
  contract?: string;
  /** The sending account. */
  from: string;
  args: Value[];
  /** The round whose proof the capsule carries (scoped to the sender). */
  capsule?: Value;
}
/** A transaction that lands: it must carry every nullifier of the capsule's
 * round and every new note hash of it, wherever the contract puts them. */
export interface LandedTx extends TxCall {
  name?: string;
  /** Scope names for the capsule round's new notes, in the round's order. */
  notes?: string[];
  /** Other notes whose nonces to mine: inner note hash, scope name, and the
   * index among the transaction's note hashes it must have (default: any). */
  mine?: { index?: number; hash: Value; as: string }[];
  /** How many note hashes the transaction must push. */
  noteHashes?: number;
  /** A copy with one Chonk proof field changed is sent first; the node must refuse it. */
  nodeTamper?: boolean;
  /** Sent first with a capsule proof field changed; client-side proving must refuse it. Takes a capsule. */
  clientTamper?: boolean;
  drop?: never;
  simulationRefused?: never;
}
/** Proved, then lost before the node sees it; nothing lands. */
export interface DroppedTx extends TxCall {
  drop: true;
  name?: never;
  notes?: never;
  mine?: never;
  noteHashes?: never;
  nodeTamper?: never;
  clientTamper?: never;
  simulationRefused?: never;
}
/** Simulated only: the sender's PXE must refuse it with a message containing
 * every substring; nothing is proved or sent. */
export interface RefusedTx extends TxCall {
  simulationRefused: string[];
  drop?: never;
  name?: never;
  notes?: never;
  mine?: never;
  noteHashes?: never;
  nodeTamper?: never;
  clientTamper?: never;
}
export type TxStep = LandedTx | DroppedTx | RefusedTx;

/** A contract call as the driver sends it. */
interface Call {
  with(options: { capsules: ReturnType<typeof stageCapsule>[] }): Call;
  send(options: { from: AztecAddress } & FeeSendOptions): Promise<{ receipt: TxReceipt }>;
  simulate(options: { from: AztecAddress } & FeeSendOptions): Promise<unknown>;
}

const CALL = ["tx", "contract", "from", "args", "capsule"];

export default defineKind<TxStep>({
  key: "tx",
  check(step, s) {
    refs.account(s, step.from);
    refs.contract(s, step.contract);
    if (step.drop) return { fields: [...CALL, "drop"] };
    if (step.simulationRefused) {
      check(step.simulationRefused.length > 0, "simulationRefused names at least one substring of the PXE's message");
      return { fields: [...CALL, "simulationRefused"] };
    }
    check(step.capsule !== undefined || (step.notes === undefined && !step.clientTamper), "notes and clientTamper take a capsule");
    return { fields: [...CALL, "name", "notes", "mine", "noteHashes", "nodeTamper", "clientTamper"], binds: [step.name, ...(step.notes ?? []), ...(step.mine ?? []).map((m) => m.as)] };
  },
  async run(ctx, step) {
    const label = step.what ?? step.name ?? step.tx;
    const from = ctx.account(step.from);
    const { address, artifact } = ctx.contract(step.contract);
    const contract = Contract.at(address, artifact, ctx.network.walletOf(step.from));
    const r = step.capsule === undefined ? undefined : (ctx.scope.resolve(step.capsule) as Round);
    const args = step.args.map((a) => ctx.scope.resolve(a));
    const method = (contract.methods as unknown as Record<string, ((...a: unknown[]) => Call) | undefined>)[step.tx];
    check(method !== undefined, `${label}: the contract has no method ${step.tx}`);
    const fee = await ctx.network.fee(r ? "result" : "request");
    const build = (proof?: string | Fr[]) => {
      const call = method(...args);
      return r ? call.with({ capsules: [stageCapsule(address, from, ctx.vkFields(r.circuit), proof ?? r.response.proof)] }) : call;
    };
    const send = (proof?: string | Fr[]) => build(proof).send({ ...fee, from });
    if (step.simulationRefused) return refusedInSimulation(ctx, label, () => build().simulate({ ...fee, from }), step.simulationRefused);
    if (step.drop) return dropped(ctx, label, send);
    if (step.clientTamper) await clientTamper(ctx, label, r!, send);
    if (step.nodeTamper) ctx.network.checks?.rejectTamperedCopyOfNextTx(label);
    const { receipt } = await timed(ctx.logger, `tx ${label}${step.nodeTamper ? " (with the node-side negative)" : ""}`, () => send());
    const effects = txEffectFrom(await ctx.network.node.getTxEffect(receipt.txHash));
    ctx.logger.info(`${label} mined ${receipt.txHash}: ${effects.noteHashes.length} note hashes, ${effects.nullifiers.length} nullifiers`);
    if (step.noteHashes !== undefined) check(effects.noteHashes.length === step.noteHashes, `${label} pushed ${effects.noteHashes.length} note hashes, expected ${step.noteHashes}`);
    if (r) {
      for (const [i, n] of r.effects.nullifiers.entries()) {
        ctx.logger.info(`${label}: consumed note ${i} nullified: ${await checkNullified(effects, address.toString(), n, `${label}: consumed note ${i}`)}`);
      }
      const notes: Note[] = [];
      for (const [j, hash] of r.effects.new_note_hashes.entries()) {
        const { nonce, leaf, index } = await findNote(effects, address, hash, `${label}: new note ${j}`);
        notes.push({ nonce, leaf, noteHash: hash });
        if (step.notes?.[j]) ctx.scope.set(step.notes[j], notes[j]);
        ctx.logger.info(`${label}: new note ${j} at note hash ${index}, nonce ${nonce}`);
      }
      const writes = r.input.stateKeys?.writes ?? [];
      for (const rec of r.records) {
        const j = writes.findIndex((w) => keyHex(w) === rec.key);
        await ctx.client(r.namespace).recordStore.markLanded(fieldHex(ctx.nsValue(r.namespace)), rec.key, r.requestId, { nonce: notes[j]!.nonce, tx_hash: receipt.txHash.toString() });
      }
    }
    for (const m of step.mine ?? []) {
      const hash = new Fr(big(ctx.scope.resolve(m.hash)));
      ctx.scope.set(m.as, m.index === undefined ? (await findNote(effects, address, hash, m.as)).nonce : await anchoredNonce(effects, m.index, address.toString(), hash, m.as));
    }
    if (step.name) ctx.scope.set(step.name, { txHash: receipt.txHash.toString(), effects });
  },
  txs: (_ctx, step, sent) => sent.map((txHash) => ({ kind: "other", txHash, round: step.tx })),
});

type Send = (proof?: string | Fr[]) => Promise<{ receipt: TxReceipt }>;
type Effects = ReturnType<typeof txEffectFrom>;

/** The transaction note hash that commits to `inner` under the contract,
 * and its nonce; undefined when none does. */
export async function noteIn(effects: Effects, address: AztecAddress, inner: Fr): Promise<{ nonce: Fr; leaf: Fr; index: number } | undefined> {
  for (let index = 0; index < effects.noteHashes.length; index++) {
    const [mined] = await mineNonces(effects, undefined, [{ index, innerNoteHash: inner }], address.toString()).catch(() => [undefined]);
    if (mined) return { nonce: mined.nonce, leaf: mined.leaf, index };
  }
  return undefined;
}

/** noteIn, which must find it. */
async function findNote(effects: Effects, address: AztecAddress, inner: Fr, what: string): Promise<{ nonce: Fr; leaf: Fr; index: number }> {
  const found = await noteIn(effects, address, inner);
  if (found === undefined) throw new Error(`${what}: none of the transaction's ${effects.noteHashes.length} note hashes commits to inner note hash ${inner}`);
  return found;
}

async function dropped(ctx: RunContext, label: string, send: Send): Promise<void> {
  ctx.network.dropNextTx(label);
  let lost: unknown;
  try {
    await timed(ctx.logger, `tx ${label} (proved, then dropped)`, () => send());
  } catch (error) {
    lost = error;
  }
  const hash = ctx.network.droppedTxHash();
  check(lost !== undefined && hash !== undefined, `${label}: the transaction was not dropped: ${lost}`);
  const receipt = await ctx.network.node.getTxReceipt(hash as never);
  check(receipt.blockNumber === undefined, `${label}: the dropped transaction is in block ${receipt.blockNumber}`);
  ctx.logger.info(`${label}: transaction ${hash} dropped (node receipt status ${receipt.status})`);
}

async function refusedInSimulation(ctx: RunContext, label: string, simulate: () => Promise<unknown>, mentions: string[]): Promise<void> {
  const refusal = await expectRefused(label, mentions, () => timed(ctx.logger, `tx ${label} (simulated only)`, simulate), {
    accepted: `the PXE simulated the transaction, expected a refusal mentioning ${mentions.join(", ")}`,
  });
  ctx.logger.info(`[simulation refusal] ${label}: the PXE refused it, nothing sent: ${refusal.split("\n")[0]}`);
}

async function clientTamper(ctx: RunContext, label: string, r: Round, send: Send): Promise<void> {
  if (!ctx.harness.expectRealProofs) return;
  const refusal = await expectRefused(label, [TAMPER_MESSAGE], () => timed(ctx.logger, `tx ${label} with a tampered proof (client-side proving)`, () => send(tamperedProof(r.response.proof))), {
    accepted: "a TAMPERED proof was accepted",
  });
  ctx.logger.info(`[client tamper] ${label} with proof field ${TAMPER_FIELD} changed: client-side proving refused it ("${TAMPER_MESSAGE}"), nothing sent: ${refusal.split("\n")[0]}`);
}
