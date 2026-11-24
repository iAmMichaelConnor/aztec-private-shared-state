// Key epochs (docs/ARCHITECTURE.md section 6, "Node replacement and key
// epochs"): the numbered key set, the three nodes' `sig` and `enc` keys, that
// an app contract checks every node signature under. Epoch 0 is the
// constructor's `sig` keys, the ones a client pins (`nodeKeys`); a node
// replacement moves the contract to the next epoch with a new set, signed by
// two of the three current nodes (`rotate_keys`), and the contract accepts the
// previous set's signatures for a grace window of `grace` blocks after
// `rotated_at`.
//
// The contract keeps its key epoch at the library's own public-storage slot,
// NODE_KEYS_SLOT (ASCII "pss.node_keys"), the 21 fields of pss_public_contract
// `NodeKeys` in their packing order:
//
//   epoch, rotated_at, grace, sig_0.x, sig_0.y, sig_1.x, sig_1.y, sig_2.x,
//   sig_2.y, enc_0.x .. enc_2.y, previous_0.x .. previous_2.y
//
// all zero until the first rotation. A contract with a fixed key set
// (pss_public_contract `FixedKeys`) never writes it, so it reads as epoch 0
// for good: the pinned keys, the ones that contract checks every signature
// under. A client given an Aztec node to read it
// from (`keyEpochNode`) checks result signatures and receipts under the
// contract's current set, or under the previous one inside its window, and
// seals envelopes to the current set's `enc` keys; without one it uses the
// pinned keys, which stay right until a replacement.

import { Fr } from "@aztec-labs/foundation/curves/bn254";
import type { AztecAddress } from "@aztec-labs/aztec.js/addresses";

import { ProtocolError } from "./errors.ts";
import { fieldAddress, fieldHex, type FieldLike } from "./field.ts";
import type { GrumpkinPoint, NodeKeys, Triple } from "./wire.ts";
import { asciiLabel } from "./labels.ts";

/** The key epoch's slot: ASCII "pss.node_keys" read big-endian. */
export const NODE_KEYS_SLOT = asciiLabel("pss.node_keys");

/** The key epoch's packed length; its hash is the next slot. */
export const NODE_KEYS_LEN = 21;

/** A contract's key epoch as stored. */
export interface KeyEpoch {
  epoch: number;
  /** The current set, node 0 first. */
  keys: Triple<NodeKeys>;
  /** The previous set's `sig` keys (zero points at epoch 0). */
  previous: Triple<GrumpkinPoint>;
  rotatedAt: number;
  grace: number;
}

/** The Aztec node methods the read uses (aztec.js AztecNode). */
export interface KeyEpochNode {
  getBlockNumber(): Promise<number>;
  getPublicStorageAt(block: never, contract: AztecAddress, slot: Fr): Promise<Fr>;
}

function small(v: bigint, what: string): number {
  if (v > 0xffffffffn) throw new ProtocolError(`the key epoch's ${what} ${v} is not a u32`);
  return Number(v);
}

/** Unpack the NODE_KEYS_LEN fields read from NODE_KEYS_SLOT onwards. */
export function unpackKeyEpoch(fields: bigint[]): KeyEpoch {
  if (fields.length !== NODE_KEYS_LEN) throw new ProtocolError(`a key epoch is ${NODE_KEYS_LEN} fields, not ${fields.length}`);
  const point = (k: number): GrumpkinPoint => ({ x: fieldHex(fields[k]!), y: fieldHex(fields[k + 1]!) });
  const keys = [0, 1, 2].map((i) => ({ sig: point(3 + 2 * i), enc: point(9 + 2 * i) })) as Triple<NodeKeys>;
  const previous = [0, 1, 2].map((i) => point(15 + 2 * i)) as Triple<GrumpkinPoint>;
  return {
    epoch: small(fields[0]!, "epoch"),
    rotatedAt: small(fields[1]!, "rotated_at"),
    grace: small(fields[2]!, "grace"),
    keys,
    previous,
  };
}

/** `contract`'s key epoch at `block` (the node's latest when not given),
 * with the block read. */
export async function readKeyEpoch(node: KeyEpochNode, contract: FieldLike | AztecAddress, block?: number): Promise<{ block: number; keyEpoch: KeyEpoch }> {
  const at = fieldAddress(contract, "contract");
  const b = block ?? Number(await node.getBlockNumber());
  const fields = await Promise.all(
    Array.from({ length: NODE_KEYS_LEN }, (_, k) => node.getPublicStorageAt(b as never, at, new Fr(NODE_KEYS_SLOT + BigInt(k)))),
  );
  return { block: b, keyEpoch: unpackKeyEpoch(fields.map((f) => f.toBigInt())) };
}

/** The node keys a client acts under: the pinned keys at epoch 0, the
 * contract's current set after a rotation. */
export function currentKeys(keyEpoch: KeyEpoch | undefined, pinned: Triple<NodeKeys>): Triple<NodeKeys> {
  return keyEpoch === undefined || keyEpoch.epoch === 0 ? pinned : keyEpoch.keys;
}

/** The `sig` key sets signatures are accepted under at `block`, the current
 * one first: the pinned keys at epoch 0; after a rotation the current set,
 * and the previous one while `block <= rotatedAt + grace` (the contract's
 * rule). */
export function signatureKeySets(keyEpoch: KeyEpoch | undefined, pinned: Triple<NodeKeys>, block: number): Triple<GrumpkinPoint>[] {
  const sig = (keys: Triple<NodeKeys>) => keys.map((k) => k.sig) as Triple<GrumpkinPoint>;
  if (keyEpoch === undefined || keyEpoch.epoch === 0) return [sig(pinned)];
  const sets = [sig(keyEpoch.keys)];
  if (block <= keyEpoch.rotatedAt + keyEpoch.grace) sets.push(keyEpoch.previous);
  return sets;
}

/** Refuse a namespace whose contract manifest says `node_keys: fixed`
 * before a node replacement starts: no rotation can land in its contract,
 * whose app is redeployed instead; `name` names it in the message. The
 * generator writes `node_keys` from the brick the contract's state view
 * reports (bricks.ts). */
export function assertKeyRotation(manifest: { node_keys: "rotating" | "fixed" }, name: string): void {
  if (manifest.node_keys !== "rotating") {
    throw new ProtocolError(`${name}'s contract manifest says node_keys ${manifest.node_keys} (its node-keys brick is FixedKeys), so no rotation can land in its contract: its app is redeployed instead`);
  }
}
