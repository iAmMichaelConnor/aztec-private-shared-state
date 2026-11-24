// The nodes' enc keys in a tip deployment that takes secret-shared on-chain intake
// (docs/ARCHITECTURE.md section 6, "Secret-shared on-chain intake"): each node, over
// its admin socket (`sign_enc_key`, what `sidecar-node sign-enc-key` sends),
// keeps its current enc scalar pending as the epoch's in the contract and signs
// the rotation (its pruning job records it once the rotation lands); the sending account lands the contract's `rotate_enc_key(i, key,
// signature)` for each, and the contract's `get_enc_key(i)` then reads back
// each node's key at that epoch. A secret-shared on-chain request reverts until all
// three nodes have a key.
import { Fr } from "@aztec-labs/aztec.js/fields";
import { storedEncKey, type AdminAnswer, type EncKeyReader, type EncKeySigned, type StoredEncKey } from "@aztec-pss/pss-client";

import { defineKind, refs, type Common } from "../engine/kind.ts";
import { check } from "../engine/scope.ts";
import { tipContract, tipOf, methodsOf } from "../engine/tip.ts";
import { timed } from "../harness/harness.ts";

export interface TipEncKeyStep extends Common {
  /** The tip deployment. */
  tipEncKey: string;
  /** The epoch every node's key takes in the contract: the stored one + 1
   * (1 for a contract's first keys). */
  epoch: number;
  /** The account that lands the three rotations; no rotation names it. */
  from: string;
  /** Binds the three keys, node 0 first: [{x, y, epoch}], as the request
   * function reads them. */
  name?: string;
}


export default defineKind<TipEncKeyStep>({
  key: "tipEncKey",
  check(step, s) {
    refs.tip(s, step.tipEncKey);
    refs.account(s, step.from);
    check(Number.isInteger(step.epoch) && step.epoch > 0, "an enc key's epoch is a positive integer (epoch 0 is no key)");
    return { fields: ["tipEncKey", "epoch", "from", "name"], binds: [step.name] };
  },
  async run(ctx, step) {
    const tip = tipOf(ctx, step.tipEncKey);
    const label = step.what ?? `${tip.name} enc keys at epoch ${step.epoch}`;
    check(tip.d.slots.sharedOnchain !== undefined, `${label}: ${tip.deployment} registers no secret-shared on-chain intake package (no shared_onchain_slot)`);
    const methods = methodsOf(tipContract(ctx, tip, step.from));
    const fee = await ctx.network.fee("request");
    const keys: StoredEncKey[] = [];
    for (let i = 0; i < 3; i++) {
      const answer = (await timed(ctx.logger, `admin sign_enc_key on node ${i}`, () =>
        ctx.machine.admin(i, { op: "sign_enc_key", namespace: tip.d.address, epoch: step.epoch }),
      )) as AdminAnswer & { enc_key?: EncKeySigned };
      check(answer.ok === true && answer.enc_key !== undefined, `${label}: node ${i} refused to sign: ${JSON.stringify(answer.refusal)}`);
      const signed = answer.enc_key;
      check(signed.index === i && signed.epoch === step.epoch, `${label}: node ${i} signed index ${signed.index} at epoch ${signed.epoch}`);
      check(BigInt(signed.namespace) === BigInt(tip.d.address), `${label}: node ${i} signed for ${signed.namespace}, not ${tip.d.address}`);
      const key = { x: new Fr(BigInt(signed.enc.x)), y: new Fr(BigInt(signed.enc.y)), epoch: step.epoch };
      const signature = { s: signed.signature.s.map((v) => new Fr(BigInt(v))), e: signed.signature.e.map((v) => new Fr(BigInt(v))) };
      const { receipt } = await timed(ctx.logger, `tx ${label}: rotate_enc_key of node ${i}`, () => methods.rotate_enc_key!(i, key, signature).send({ ...fee, from: ctx.account(step.from) }));
      keys.push({ x: key.x.toBigInt(), y: key.y.toBigInt(), epoch: step.epoch });
      ctx.logger.info(`${label}: node ${i}'s key ${signed.enc.x} set at epoch ${step.epoch} in tx ${receipt.txHash.toString()} (block ${receipt.blockNumber})`);
    }
    for (let i = 0; i < 3; i++) {
      const stored = await storedEncKey({ methods } as unknown as EncKeyReader, i, ctx.account(step.from));
      check(stored.x === keys[i]!.x && stored.y === keys[i]!.y && stored.epoch === step.epoch, `${label}: get_enc_key(${i}) answers ${JSON.stringify({ ...stored, x: stored.x.toString(16), y: stored.y.toString(16) })}`);
    }
    if (step.name) ctx.scope.set(step.name, keys.map((k) => ({ x: `0x${k.x.toString(16)}`, y: `0x${k.y.toString(16)}`, epoch: k.epoch })));
  },
  txs(ctx, step, sent) {
    return sent.map((txHash) => ({ kind: "other" as const, txHash, round: "rotate_enc_key", deployment: tipOf(ctx, step.tipEncKey).name }));
  },
});
