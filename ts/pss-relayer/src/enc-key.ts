// A node operator's rotation of its node's `enc` key into the app contracts
// that take secret-shared on-chain intake (docs/ARCHITECTURE.md section 6, "Secret-shared
// on-chain intake"; DESIGN.md, "Rotating a node's `enc` key"), contract by
// contract, on the node's host:
//
//   read     the contract's stored key for node i (get_enc_key(i)): epoch S
//   sign     the node's admin socket, sign_enc_key at S + 1: the node keeps its
//            current enc scalar pending at that epoch and signs the rotation
//   submit   rotate_enc_key(i, key, signature) from the operator's account
//   check    get_enc_key(i) answers the signed key at S + 1
//   record   the node's admin socket, prune: the node's pruning job reads the
//            stored key through its own Aztec node and records the scalar
//
// The node records the scalar only once it sees the rotation land, so a
// rotation that fails to land leaves nothing to clear: the next run signs the
// same epoch again and the new signature replaces the pending one. A contract
// that already stores the node's current key (its rotation landed in an
// earlier run) gets no transaction: the run only asks the node to record it. The
// signature is node i's, so any account may send the transaction; the
// operator's account pays it (fee kind `configure`, an operator transaction).

import { Fr } from "@aztec-labs/aztec.js/fields";
import { adminSocket as nodeAdminSocket, storedEncKey, txSendOptions, type AdminAnswer, type AdminCall, type EncKeySigned, type FeeSetting } from "@aztec-pss/pss-client";

// The bound on one admin command: the node answers a signature at once; a
// prune reads the chain through the node's own Aztec node, which its own
// reads bound by 120 s (sidecar-tip DEFAULT_STANDING_TIMEOUT), plus its store
// passes.
/** How long one admin command may take before the call fails, in ms. */
const ADMIN_TIMEOUT_MS = 180_000;

/** The node's admin socket at `path` (`<run_dir>/admin.sock` by default)
 * under the rotation's bound (pss-client adminSocket). */
export function adminSocket(path: string, timeoutMs = ADMIN_TIMEOUT_MS): AdminCall {
  return nodeAdminSocket(path, timeoutMs);
}

/** What the pruning job read and changed of one contract's epochs
 * (sidecar-node `EpochsObserved`). */
export interface EpochsObserved {
  namespace: string;
  stored_epoch: number;
  recorded: number[];
  retired: number[];
}

type Sendable = { send(options: object): Promise<unknown> };
type Simulatable = { simulate(options: object): Promise<unknown> };

/** The app contract's two key functions, as aztec.js's Contract exposes
 * them: the library's `rotate_enc_key` and `get_enc_key`. */
export interface EncKeyContract {
  methods: {
    rotate_enc_key(i: number, key: { x: Fr; y: Fr; epoch: number }, signature: { s: Fr[]; e: Fr[] }): Sendable;
    get_enc_key(i: number): Simulatable;
  };
}

export interface EncKeyRotationOptions {
  /** The node's admin socket. */
  admin: AdminCall;
  /** The app contract (a secret-shared on-chain intake namespace). */
  contract: EncKeyContract;
  /** Its address, the namespace the node signs for. */
  address: string;
  /** The node's index (its config's `party`), the contract's `i`. */
  party: number;
  /** The sending account. */
  from: unknown;
  /** The fee setting; the transaction pays as kind `configure`. */
  fee: FeeSetting;
  /** The epoch the operator expects to sign, refused unless it is the
   * stored one + 1, or the stored one when the contract already stores the
   * node's current key; default the stored one + 1 (1 for a first key). */
  epoch?: number;
  log?: { info(msg: string): void; warn(msg: string): void };
}

/** One rotation's outcome. */
export interface EncKeyRotation {
  namespace: string;
  index: number;
  /** The epoch the contract stores the node's current key at. */
  epoch: number;
  /** False when the contract already stored the node's current key (a rerun
   * after this contract's rotation landed): no transaction was sent. */
  rotated: boolean;
  /** The transaction's hash, when the wallet answered one. */
  txHash?: string;
  /** Whether the node recorded the scalar at once; when false its pruning
   * job records it once the node's own Aztec node shows the rotation. */
  recorded: boolean;
}

const refusal = (a: AdminAnswer) => (a.refusal ? `${a.refusal.class}: ${a.refusal.error}` : "no refusal given");

/** Sign node `party`'s rotation into one contract on its admin socket,
 * submit it, check the stored key and ask the node to record it (see the
 * module comment). A contract that already stores the node's current key
 * (the signed key is the stored one) is not sent a transaction again: the
 * node is only asked to record it, so a rerun after a partial run rotates
 * only the contracts still behind. Throws when the epoch is not the stored
 * one + 1 (or the stored one, for a contract already rotated), the node
 * refuses or signs something else, or the stored key is not the signed one
 * after the transaction. */
export async function rotateEncKey(o: EncKeyRotationOptions): Promise<EncKeyRotation> {
  const label = `enc key of node ${o.party} in ${o.address}`;
  const stored = await storedEncKey(o.contract, o.party, o.from);
  const epoch = stored.epoch + 1;
  const wrongEpoch = () => new RangeError(`${label}: the contract stores epoch ${stored.epoch}, so it takes epoch ${epoch}, not ${o.epoch}`);
  if (o.epoch !== undefined && o.epoch !== epoch && o.epoch !== stored.epoch) throw wrongEpoch();

  const answer = await o.admin({ op: "sign_enc_key", namespace: o.address, epoch });
  const signed = answer.enc_key as EncKeySigned | undefined;
  if (!answer.ok || signed === undefined) throw new Error(`${label}: the node refused to sign epoch ${epoch}: ${refusal(answer)}`);
  if (signed.index !== o.party) throw new Error(`${label}: the node is party ${signed.index}, not ${o.party}`);
  if (signed.epoch !== epoch || BigInt(signed.namespace) !== BigInt(o.address)) {
    throw new Error(`${label}: the node signed epoch ${signed.epoch} of ${signed.namespace}`);
  }
  const key = { x: new Fr(BigInt(signed.enc.x)), y: new Fr(BigInt(signed.enc.y)), epoch };
  if (stored.x === key.x.toBigInt() && stored.y === key.y.toBigInt()) {
    // a rerun after this contract's rotation landed: the signature at the
    // next epoch stays pending at the node and is replaced by the next run
    o.log?.info(`${label}: the contract already stores the node's current key at epoch ${stored.epoch}; nothing sent`);
    return { namespace: o.address, index: o.party, epoch: stored.epoch, rotated: false, recorded: await record(o, label, stored.epoch) };
  }
  if (o.epoch !== undefined && o.epoch !== epoch) throw wrongEpoch();
  const signature = { s: signed.signature.s.map((v) => new Fr(BigInt(v))), e: signed.signature.e.map((v) => new Fr(BigInt(v))) };
  const sent = (await o.contract.methods.rotate_enc_key(o.party, key, signature).send({ ...(await txSendOptions(o.fee, "configure")), from: o.from })) as {
    receipt?: { txHash?: { toString(): string } };
  };
  const txHash = sent?.receipt?.txHash?.toString();
  o.log?.info(`${label}: rotate_enc_key at epoch ${epoch} landed${txHash ? ` in ${txHash}` : ""}`);

  const now = await storedEncKey(o.contract, o.party, o.from);
  if (now.epoch !== epoch || now.x !== key.x.toBigInt() || now.y !== key.y.toBigInt()) {
    throw new Error(`${label}: after the transaction the contract stores epoch ${now.epoch} under x 0x${now.x.toString(16)}, not the signed key at epoch ${epoch}`);
  }
  return { namespace: o.address, index: o.party, epoch, rotated: true, txHash, recorded: await record(o, label, epoch) };
}

/** Ask the node to record the stored key at `epoch` (its prune): whether it
 * did at once. A refused or failed prune is not fatal: the node's pruning
 * job records the scalar later. */
async function record(o: EncKeyRotationOptions, label: string, epoch: number): Promise<boolean> {
  let pruned: AdminAnswer;
  try {
    pruned = await o.admin({ op: "prune" });
  } catch (e) {
    o.log?.warn(`${label}: the node's prune failed (${(e as Error).message}); its timer records the scalar later`);
    return false;
  }
  const seen = ((pruned.enc_epochs as EpochsObserved[] | undefined) ?? []).find((e) => BigInt(e.namespace) === BigInt(o.address));
  // the node records every epoch up to the stored one whose key it holds,
  // and the stored key is its own (checked by the caller)
  const recorded = pruned.ok && seen !== undefined && seen.stored_epoch >= epoch;
  if (!pruned.ok) o.log?.warn(`${label}: the node's prune was refused (${refusal(pruned)}); its timer records the scalar later`);
  else if (!recorded) o.log?.info(`${label}: the node's Aztec node does not show epoch ${epoch} yet; its pruning job records the scalar once it does`);
  return recorded;
}
