// Small helpers every client and relayer test shares: field-element
// spellings, Poseidon2 over integers, the fixture files, a queue in memory,
// a result contract that records its calls, the mock orchestrator's
// scripted replies, and stand-in nodes for private logs and spent
// nullifiers.

import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { Fr } from "@aztec-labs/foundation/curves/bn254";
import { BlockHash, type BlockParameter } from "@aztec-labs/stdlib/block";
import { MerkleTreeId } from "@aztec-labs/stdlib/trees";

import {
  aeEncrypt,
  fieldHex,
  hashFields,
  sealNonce,
  type EffectLog,
  type FieldHexString,
  type FieldLike,
  type PrivateLogNode,
  type QueueReader,
  type QueueSnapshot,
  type ResultContract,
  type SpenderNode,
  type TxEffects,
} from "@aztec-pss/pss-client/internal";

import type { Reply } from "./mock-orchestrator.ts";

/** A field element as `0x` + 64 hex digits. */
export const hex = (v: bigint | number | string | Fr): FieldHexString => fieldHex(typeof v === "object" ? v.toBigInt() : BigInt(v));

/** Poseidon2 over integers (or their spellings). */
export const hash = (xs: readonly (bigint | number | string)[]): Promise<bigint> => hashFields(xs.map((x) => BigInt(x)));

/** The path of a fixture file (fixtures/; contract-fixture.ts writes the
 * contract ones and fixtures.test.ts compares each with its build). */
export const fixturePath = (name: string): string => fileURLToPath(new URL(`./fixtures/${name}`, import.meta.url));

/** A fixture file, parsed. */
export const fixture = (name: string): unknown => JSON.parse(readFileSync(fixturePath(name), "utf8"));

/** A repository file (from the repository root), parsed. */
export const repoJson = (path: string): unknown => JSON.parse(readFileSync(new URL(`../../${path}`, import.meta.url), "utf8"));

/** A vector file of testvectors/, parsed. */
export const vectorJson = (name: string): unknown => repoJson(`testvectors/${name}`);

/** The switch that makes checkOrWrite write: `PSS_WRITE_VECTORS=1`. */
export const WRITE_VECTORS = "PSS_WRITE_VECTORS";

/** A file a test writes from what the code computes (a vector file, a
 * Noir program's Prover.toml): written when PSS_WRITE_VECTORS is 1, then
 * required to equal `text`, so code, file and circuit cannot drift apart. */
export function checkOrWrite(path: URL | string, text: string): void {
  if (process.env[WRITE_VECTORS] === "1") writeFileSync(path, text);
  assert.equal(readFileSync(path, "utf8"), text, `${String(path)}: rerun with ${WRITE_VECTORS}=1`);
}

/** A TOML string. */
export const tomlString = (v: string | number): string => `"${v}"`;

/** A TOML list of strings. */
export const tomlList = (vs: readonly (string | number)[]): string => `[${vs.map(tomlString).join(", ")}]`;

/** A ciphertext as a round outputs it, `[ct..., tag]`: the plaintext
 * under the key with the opened domain's nonce of `noteHash` (sealNonce),
 * `noteHash` the hash of the note that packs the plaintext. */
export async function encryptOutcome(plaintext: readonly FieldLike[], key: FieldLike, noteHash: FieldLike): Promise<bigint[]> {
  const sealed = await aeEncrypt(key, await sealNonce(noteHash, true), [...plaintext]);
  return [...sealed.ciphertext, sealed.tag];
}

/** A QueueReader over in-memory state: block 100, a head fresh since 90. */
export class FakeQueue implements QueueReader {
  block = 100;
  fork = 0;
  head = 0;
  headSince = 90;
  requests: string[] = [];
  done = new Map<number, number>();
  async blockNumber() {
    return this.block;
  }
  async snapshot(): Promise<QueueSnapshot> {
    const s: QueueSnapshot = { block: this.block, blockHash: blockHashOf(this.block + this.fork).toString(), head: this.head, headSince: this.headSince, tail: this.requests.length };
    if (this.head < this.requests.length) s.headRequest = this.requests[this.head];
    return s;
  }
  async requestAt(i: number) {
    return this.requests[i] ?? hex(0n);
  }
  async doneAt(i: number) {
    return this.done.get(i) ?? 0;
  }
}

/** One recorded result call. */
export interface RecordedCall {
  method: string;
  args: unknown[];
  capsules: unknown[];
  options: { from?: unknown; wait?: unknown; fee?: { paymentMethod?: { getFeePayer(): Promise<{ toString(): string }> } } } & Record<string, unknown>;
}

/** A ResultContract whose first `failures` sends throw `revert`, recording
 * every call. */
export function recordingContract(failures: number, revert = "Transaction reverted: not the head") {
  const calls: RecordedCall[] = [];
  const contract: ResultContract = {
    methods: new Proxy({}, {
      get: (_t, method: string) => (...args: unknown[]) => ({
        with: (extra: { capsules: unknown[] }) => ({
          send: async (options: RecordedCall["options"]) => {
            calls.push({ method, args, capsules: extra.capsules, options });
            if (calls.length <= failures) throw new Error(revert);
            return { receipt: { status: "success", txHash: "0xabc" } };
          },
        }),
      }),
    }) as ResultContract["methods"],
  };
  return { contract, calls };
}

/** A mock orchestrator route answering the n-th request with the n-th of
 * `list` (the last one from then on): a Reply as given, anything else as a
 * 200 with that body. */
export const replies = (list: readonly unknown[]) => (_r: unknown, n: number): Reply => {
  const a = list[Math.min(n, list.length) - 1] as Reply | object;
  return "status" in a || "hang" in a || "drop" in a ? (a as Reply) : { status: 200, body: a };
};

// ---- stand-in nodes ----

/** A private log as a node answers it with its transaction's effects:
 * `fields` (the siloed tag first) in transaction 0x7777, whose note hash is
 * 0x4a and first nullifier 0x99. */
export const effectLog = (fields: readonly (bigint | Fr)[]): EffectLog => ({
  logData: fields.map((f) => (typeof f === "bigint" ? new Fr(f) : f)),
  txHash: { toString: () => fieldHex(0x7777n) },
  noteHashes: [new Fr(0x4an)],
  nullifiers: [new Fr(0x99n)],
});

/** A node holding the private logs `logs`, each its fields with the siloed
 * tag first, that answers a tag query with the logs under each tag
 * (effectLog); `asked` keeps the tags asked for. */
export function logNode(logs: readonly (readonly (bigint | Fr)[])[]): PrivateLogNode & { asked: bigint[] } {
  const asked: bigint[] = [];
  const tagOf = (l: readonly (bigint | Fr)[]) => (typeof l[0] === "bigint" ? l[0] : l[0]!.toBigInt());
  return {
    asked,
    async getPrivateLogsByTags({ tags }) {
      asked.push(...tags.map((t) => t.value.toBigInt()));
      return tags.map((t) => logs.filter((l) => tagOf(l) === t.value.toBigInt()).map(effectLog));
    },
  };
}

/** A transaction's effects with `nullifiers` and no logs. */
export function txWith(hash: bigint, nullifiers: Fr[]): TxEffects {
  return { txHash: { toString: () => fieldHex(hash) }, noteHashes: [], nullifiers, privateLogs: [] };
}

/** The hash a stand-in chain gives block `n`. */
export const blockHashOf = (n: number): BlockHash => new BlockHash(new Fr(0xb10c00n + BigInt(n)));

/** A node whose nullifier tree names, for each of `blocks`' nullifiers, that
 * block by number and hash (blockHashOf), and which serves each block's
 * transactions by its hash, except those in `unserved`. `at` keeps the
 * block each lookup read at, `asked` the hashes asked for. */
export function spenderNode(blocks: { number: number; txs: TxEffects[] }[], unserved: number[] = []): SpenderNode & { at: BlockParameter[]; asked: BlockHash[] } {
  const n = {
    at: [] as BlockParameter[],
    asked: [] as BlockHash[],
    async findLeavesIndexes(block: BlockParameter, treeId: MerkleTreeId, values: Fr[]) {
      assert.equal(treeId, MerkleTreeId.NULLIFIER_TREE);
      n.at.push(block);
      return values.map((v) => {
        const b = blocks.find((b) => b.txs.some((t) => t.nullifiers.some((x) => x.equals(v))));
        return b === undefined ? undefined : { l2BlockNumber: BigInt(b.number), l2BlockHash: blockHashOf(b.number) };
      });
    },
    async getBlock(hash: BlockHash, options: { includeTransactions: true }) {
      assert.equal(options.includeTransactions, true);
      n.asked.push(hash);
      const b = blocks.find((b) => blockHashOf(b.number).equals(hash));
      return b === undefined || unserved.includes(b.number) ? undefined : { body: { txEffects: b.txs } };
    },
  };
  return n;
}
