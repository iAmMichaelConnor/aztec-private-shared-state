// The tip queue as a client reads it from the chain (docs/ARCHITECTURE.md
// section 6, rows "relayer" and "outputs"): the storage slots of
// pss_public_contract's Queue, a consistent snapshot of head, head_since,
// tail, requests[head] and done. The relayer and pollResult read through the
// QueueReader interface, so tests and other transports can stand in for an
// Aztec node. Logs are discovery.ts's.
//
// Storage layout (pss_public_contract/src/queue.nr, sidecar-tip chain/layout.rs),
// from the slot the app's #[storage] gives its Queue:
//   +0 requests (Map<u64, Field>), +1 tail (u64), +2 head.index (u64),
//   +3 head.since (u32), +4 seen (Map<Field, bool>), +5 done (Map<u64, u8>)
// with the slot of map.at(key) = poseidon2_hash_with_separator([map_slot, key],
// DOM_SEP__PUBLIC_STORAGE_MAP_SLOT) (aztec.js deriveStorageSlotInMap).

import { AztecAddress } from "@aztec-labs/aztec.js/addresses";
import { Fr } from "@aztec-labs/aztec.js/fields";
import { BlockNumber } from "@aztec-labs/foundation/branded-types";
import type { BlockHash } from "@aztec-labs/stdlib/block";
import { deriveStorageSlotInMap } from "@aztec-labs/stdlib/hash";

import { RESERVED_NAMES } from "./bricks.ts";
import { ProtocolError } from "./errors.ts";
import { fieldAddress, fieldBigInt, fieldHex, type FieldHexString, type FieldLike } from "./field.ts";

/** `done[index]` codes (queue.nr DONE_PENDING, DONE_APPLIED, DONE_SKIPPED;
 * testvectors/queue.json, with the slots below at three base slots). */
export const DONE_PENDING = 0;
export const DONE_APPLIED = 1;
export const DONE_SKIPPED = 2;

/** The slots of one Queue, from its base slot (the contract artifact's
 * storage layout entry for the app's `queue` field). */
export class QueueSlots {
  readonly base: bigint;
  constructor(base: FieldLike) {
    this.base = fieldBigInt(base, "queue base slot");
  }
  private at(offset: number): Fr {
    return new Fr(this.base + BigInt(offset));
  }
  request(index: bigint | number): Promise<Fr> {
    return deriveStorageSlotInMap(this.at(0), new Fr(BigInt(index)));
  }
  tail(): Fr {
    return this.at(1);
  }
  headIndex(): Fr {
    return this.at(2);
  }
  headSince(): Fr {
    return this.at(3);
  }
  seen(requestId: FieldLike): Promise<Fr> {
    return deriveStorageSlotInMap(this.at(4), new Fr(fieldBigInt(requestId, "request_id")));
  }
  done(index: bigint | number): Promise<Fr> {
    return deriveStorageSlotInMap(this.at(5), new Fr(BigInt(index)));
  }
}

/** The queue's base slot from an aztec.js ContractArtifact's storage layout
 * (`artifact.storageLayout[field].slot`). */
export function queueBaseSlot(artifact: { storageLayout?: Record<string, { slot: { toBigInt(): bigint } | FieldLike }> }, field: string = RESERVED_NAMES.queue.name): bigint {
  const entry = artifact.storageLayout?.[field];
  if (entry === undefined) throw new RangeError(`the contract artifact has no storage field \`${field}\``);
  const slot = entry.slot as unknown;
  return typeof slot === "object" && slot !== null && "toBigInt" in slot
    ? (slot as { toBigInt(): bigint }).toBigInt()
    : fieldBigInt(slot as FieldLike, "slot");
}

/** The queue at one block. */
export interface QueueSnapshot {
  /** The block every value below was read at. */
  block: number;
  /** The hash that anchors the storage reads. */
  blockHash: string;
  head: number;
  /** `head_since`: the block at which the head last moved. */
  headSince: number;
  tail: number;
  /** `requests[head]`, when head < tail. */
  headRequest?: FieldHexString;
}

/** What the relayer and pollResult read. Every method reads at one block, the
 * latest unless `block` is given. */
export interface QueueReader {
  /** The latest block number the reader sees. */
  blockNumber(): Promise<number>;
  snapshot(block?: number): Promise<QueueSnapshot>;
  requestAt(index: number, block?: number): Promise<FieldHexString>;
  doneAt(index: number, block?: number): Promise<number>;
}

/** The Aztec node methods a NodeQueueReader uses (aztec.js AztecNode). */
export interface StorageNode {
  getBlockNumber(): Promise<number>;
  getBlockData(block: BlockNumber): Promise<{ blockHash: BlockHash } | undefined>;
  getPublicStorageAt(block: BlockNumber | BlockHash, contract: AztecAddress, slot: Fr): Promise<Fr>;
}

function smallInt(v: Fr, what: string, max: bigint): number {
  const n = v.toBigInt();
  if (n > max) throw new ProtocolError(`${what}: ${n} does not fit`);
  return Number(n);
}

// How the queue is read. NodeQueueReader reads the Queue's public storage
// slots directly with getPublicStorageAt. It resolves the block number to
// a hash and pins every storage read of a snapshot to that hash. It needs
// no account, PXE or app view functions. The reader trusts its node for
// liveness only (a lying node can make the relayer
// send a transaction that reverts, or not send one); the base slot must be
// the app's (queueBaseSlot of its artifact), or every read is of unrelated
// storage.
/** A QueueReader over an Aztec node's public storage. */
export class NodeQueueReader implements QueueReader {
  readonly contract: AztecAddress;
  readonly slots: QueueSlots;
  private readonly node: StorageNode;

  constructor(node: StorageNode, contract: FieldLike | AztecAddress, baseSlot: FieldLike) {
    this.node = node;
    this.contract = fieldAddress(contract, "contract");
    this.slots = new QueueSlots(baseSlot);
  }

  private read(block: BlockNumber | BlockHash, slot: Fr): Promise<Fr> {
    return this.node.getPublicStorageAt(block, this.contract, slot);
  }

  async blockNumber(): Promise<number> {
    return Number(await this.node.getBlockNumber());
  }

  async snapshot(block?: number): Promise<QueueSnapshot> {
    const b = block ?? (await this.blockNumber());
    const data = await this.node.getBlockData(BlockNumber(b));
    if (data === undefined) throw new ProtocolError(`the Aztec node has no block ${b}`);
    const { blockHash } = data;
    const [head, since, tail] = await Promise.all([
      this.read(blockHash, this.slots.headIndex()),
      this.read(blockHash, this.slots.headSince()),
      this.read(blockHash, this.slots.tail()),
    ]);
    const s: QueueSnapshot = {
      block: b,
      blockHash: blockHash.toString(),
      head: smallInt(head, "head", BigInt(Number.MAX_SAFE_INTEGER)),
      headSince: smallInt(since, "head_since", 0xffffffffn),
      tail: smallInt(tail, "tail", BigInt(Number.MAX_SAFE_INTEGER)),
    };
    if (s.head > s.tail) throw new ProtocolError(`queue at block ${b}: head ${s.head} is past tail ${s.tail}`);
    if (s.head < s.tail) s.headRequest = await this.readRequest(s.head, blockHash);
    return s;
  }

  async requestAt(index: number, block?: number): Promise<FieldHexString> {
    const b = block ?? (await this.blockNumber());
    return this.readRequest(index, BlockNumber(b));
  }

  private async readRequest(index: number, block: BlockNumber | BlockHash): Promise<FieldHexString> {
    return fieldHex((await this.read(block, await this.slots.request(index))).toBigInt());
  }

  async doneAt(index: number, block?: number): Promise<number> {
    const b = block ?? (await this.blockNumber());
    return smallInt(await this.read(BlockNumber(b), await this.slots.done(index)), "done", 2n);
  }
}
