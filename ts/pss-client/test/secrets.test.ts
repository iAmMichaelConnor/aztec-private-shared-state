// SecretStore (src/secrets.ts): the request counter, the derivations of
// each request's partial-note randomness, refund randomness, outcome key and
// outcome tag, and the rescan that rebuilds the counter from the wallet
// secret alone, over a real OutcomeReader whose node is a mocked log source
// holding real outcome logs (encrypted under the derived keys, under the
// derived tags). testvectors/secret_store.json holds the derivations' known
// answers, written here with `PSS_WRITE_VECTORS=1 node --conditions=source
// --test test/secrets.test.ts`; testvectors/noir/outcome_vectors checks them with
// Noir's Poseidon2 (Prover.toml written by test/outcome.test.ts).

import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { inspect } from "node:util";

import {
  DEFAULT_GAP_LIMIT,
  MemoryRequestStore,
  OutcomeReader,
  PSS_OUTCOME_KEY,
  PSS_OUTCOME_TAG,
  PSS_PARTIAL_RANDOMNESS,
  SecretStore,
  completedNoteHash,
  completionLogTag,
  fieldHex,
  outcomeLogFields,
  partialCommitment,
  requestSecrets,
  type PrivateLogNode,
  type RequestSecrets,
} from "../src/internal.ts";
import { checkOrWrite, effectLog, encryptOutcome } from "@aztec-pss/test-support";

const CONTRACT = 0xc0ffeen;
const WALLET = 0xa11ce5ecn;
const OWNER = 0xa11cen;
const KEYS = { owner: OWNER, storageSlot: 0x2an, plaintextLength: 2 };

const VECTORS = new URL("../../../testvectors/secret_store.json", import.meta.url);


/** A chain: the private logs under each siloed tag, as a node answers them. */
class Chain implements PrivateLogNode {
  readonly logs = new Map<bigint, bigint[][]>();
  queries = 0;

  /** Land the private outcome `[code, amount]` of the wallet's n-th request. */
  async land(n: number, code = 0n): Promise<void> {
    const s = await requestSecrets(WALLET, CONTRACT, n);
    const requestId = 0x1000n + BigInt(n);
    const noteHash = await completedNoteHash(KEYS.storageSlot, await partialCommitment(OWNER, s.rho), [code, 500n], requestId);
    const fields = await outcomeLogFields(CONTRACT, s.outcomeTag, noteHash, await encryptOutcome([code, 500n], s.outcomeKey, noteHash));
    const tag = fields[0]!;
    this.logs.set(tag, [...(this.logs.get(tag) ?? []), fields]);
  }

  async getPrivateLogsByTags({ tags }: Parameters<PrivateLogNode["getPrivateLogsByTags"]>[0]) {
    this.queries++;
    return tags.map((t) => (this.logs.get(t.value.toBigInt()) ?? []).map(effectLog));
  }
}

/** The private completion's finder: the outcome log under the request's
 * tag that opens under its key (the note's last field, the chain request
 * id, comes from the queue; finding the log does not need it). */
const privateFinder = (chain: Chain) => {
  const reader = new OutcomeReader(chain, CONTRACT);
  return async (s: RequestSecrets) => (await reader.read(s.outcomeTag, { ...KEYS, outcomeKey: s.outcomeKey, rho: s.rho, requestId: 0n })) !== undefined;
};

describe("the request secrets", () => {
  test("testvectors/secret_store.json is what the client derives", async () => {
    const vectors = [];
    for (const n of [0, 1, 2]) {
      const s = await requestSecrets(WALLET, CONTRACT, n);
      const partial = await partialCommitment(OWNER, s.rho);
      vectors.push({
        n,
        rho: s.rho,
        outcome_key: s.outcomeKey,
        outcome_tag: s.outcomeTag,
        partial_note: fieldHex(partial),
        completion_log_tag: fieldHex(await completionLogTag(partial)),
      });
    }
    const file = {
      description:
        "The user's per-request secrets (pss-client src/secrets.ts): rho, the outcome key and the outcome tag of the n-th request of one wallet in one namespace, and the request's partial note and its completion log tag for one owner. Written and read by pss-client test/secrets.test.ts; testvectors/noir/outcome_vectors checks them with Noir's Poseidon2 and pss_core's partial-note functions.",
      rules: {
        rho: "poseidon2([PSS_PARTIAL_RANDOMNESS, wallet_secret, namespace, n])",
        outcome_key: "poseidon2([PSS_OUTCOME_KEY, wallet_secret, namespace, n])",
        outcome_tag: "poseidon2([PSS_OUTCOME_TAG, wallet_secret, namespace, n])",
        partial_note: "poseidon2_hash_with_separator([owner, rho], DOM_SEP__PARTIAL_NOTE_COMMITMENT = 568912195)",
        completion_log_tag: "poseidon2_hash_with_separator([partial_note], DOM_SEP__NOTE_COMPLETION_LOG_TAG = 3372669888)",
      },
      pss_partial_randomness: fieldHex(PSS_PARTIAL_RANDOMNESS),
      pss_outcome_key: fieldHex(PSS_OUTCOME_KEY),
      pss_outcome_tag: fieldHex(PSS_OUTCOME_TAG),
      wallet_secret: fieldHex(WALLET),
      namespace: fieldHex(CONTRACT),
      owner: fieldHex(OWNER),
      vectors,
    };
    const json = JSON.stringify(file, null, 2) + "\n";
    checkOrWrite(VECTORS, json);
  });

  test("a completed note hashes over the partial note, the fields and the request id", async () => {
    const s = await requestSecrets(WALLET, CONTRACT, 0);
    const p = await partialCommitment(OWNER, s.rho);
    const h = await completedNoteHash(0x2an, p, [0n, 500n], 0x1dn);
    assert.notEqual(h, await completedNoteHash(0x2an, p, [0n, 500n], 0x1en));
    await assert.rejects(async () => completedNoteHash(0x2an, p, [0n, 1n, 2n, 3n, 4n, 5n, 6n, 7n], 0x1dn), /at most 8 fields/);
  });
});

describe("SecretStore", () => {
  test("next() advances the counter before it resolves, whatever becomes of the request", async () => {
    const store = new SecretStore(WALLET, CONTRACT);
    assert.equal(await store.peek(), 0);
    const a = await store.next();
    const b = await store.next();
    assert.deepEqual([a.n, b.n], [0, 1]);
    assert.equal(await store.peek(), 2);
    assert.deepEqual(a, { ...(await requestSecrets(WALLET, CONTRACT, 0)), secrets: a.secrets });
    assert.equal(a.secrets.outcomeKey, BigInt(a.outcomeKey));
    assert.equal(a.secrets.outcomeTag, BigInt(a.outcomeTag));
    assert.notEqual(a.secrets.blinding, b.secrets.blinding);
  });

  test("the wallet secret is neither inspectable nor serialised", () => {
    const store = new SecretStore(WALLET, CONTRACT);
    const secret = BigInt(WALLET).toString(16);
    assert.ok(!inspect(store, { showHidden: true, depth: 5 }).includes(secret));
    assert.ok(!inspect(store).includes(BigInt(WALLET).toString()));
    assert.equal(JSON.stringify({ store }), '{"store":"SecretStore"}');
    assert.ok(!Object.values(store).some((v) => v === BigInt(WALLET)));
  });

  test("concurrent next() calls never take one counter twice", async () => {
    const store = new SecretStore(WALLET, CONTRACT);
    const taken = await Promise.all([store.next(), store.next(), store.next()]);
    assert.deepEqual(taken.map((t) => t.n).sort(), [0, 1, 2]);
  });

  test("the counter survives in the request store", async () => {
    const map = new MemoryRequestStore();
    await new SecretStore(WALLET, CONTRACT, map).next();
    assert.equal(await new SecretStore(WALLET, CONTRACT, map).peek(), 1);
    await map.save(fieldHex(CONTRACT), JSON.stringify({ next: -1 }));
    await assert.rejects(new SecretStore(WALLET, CONTRACT, map).peek(), /not a request counter/);
  });

  test("recover rescans to the gap limit and moves the counter past the last request found", async () => {
    const chain = new Chain();
    await chain.land(0);
    await chain.land(1, 9n); // a failed round has an outcome too
    await chain.land(4); // n = 2 and 3 never sent
    const store = new SecretStore(WALLET, CONTRACT);
    assert.deepEqual(await store.recover(privateFinder(chain)), [0, 1, 4]);
    assert.equal(await store.peek(), 5);
    assert.equal(chain.queries, 5 + DEFAULT_GAP_LIMIT);
    // a gap longer than the limit hides what lies past it
    const short = new SecretStore(WALLET, CONTRACT);
    assert.deepEqual(await short.recover(privateFinder(chain), 2), [0, 1]);
    assert.equal(await short.peek(), 2);
    await assert.rejects(short.recover(privateFinder(chain), 0), /gapLimit/);
  });

  test("recover under the public completion looks for each request's completion tag", async () => {
    const completed = new Set<bigint>();
    for (const n of [0, 2]) completed.add(await completionLogTag(await partialCommitment(OWNER, (await requestSecrets(WALLET, CONTRACT, n)).rho)));
    const find = async (s: RequestSecrets) => completed.has(await completionLogTag(await partialCommitment(OWNER, s.rho)));
    const store = new SecretStore(WALLET, CONTRACT);
    assert.deepEqual(await store.recover(find, 3), [0, 2]);
    assert.equal(await store.peek(), 3);
  });
});
