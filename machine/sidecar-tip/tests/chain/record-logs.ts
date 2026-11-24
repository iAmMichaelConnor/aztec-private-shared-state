// Records tests/fixtures/logs.json, the node answers the chain reader's log
// tests (src/chain/mod.rs) replay, from a fresh local Aztec 6.0.0 network:
// deploys PssPublicTest as C, whose on-chain intake emits the request log of
// chain request R0, and two LogEmitter instances (log_emitter/) as A and B,
// which emit a request-shaped log under R0's request tag (B) and a
// sealed-shaped log under R0's sealed tag (B, then A); then records the
// node's answers to the reads the test makes. After those, A emits more
// logs under one tag than the node answers in a page, and a private log,
// and the recording goes on with the reads the reader makes of them: the
// follower's next poll (its tip and the block hashes it compares), the
// paged query with afterLog, a private-log query, a query whose reference
// block the node does not have, and a block past the tip.
//
//   AZTEC_NODE_URL=http://127.0.0.1:10280 CONTRACT_NARGO_BIN=... BB_BIN=... \
//     node --import ../../../../ts/hooks/register.mjs record-logs.ts
//
// tests/chain/run.sh --record starts the network and runs this. Every
// contract is deployed with a fixed salt from the network's fixed accounts,
// so the addresses, R0, the tags, the block numbers and the log contents are
// the same on every fresh network. A block hash, a log's blockTimestamp and
// txHash are not (block timestamps follow L1's wall clock, and the hashes
// commit to them), so when a recording differs from the committed file only
// in the PER_RUN keys the file is kept as it is; otherwise it is rewritten.
// OUT (default tests/fixtures/logs.json) names the file.
import { Fr } from "@aztec-labs/aztec.js/fields";
import { computeLogTag, computeSiloedPrivateLogFirstField } from "@aztec-labs/stdlib/hash";

import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { isDeepStrictEqual } from "node:util";

import { compile, compileTestContract, deploy, nodeUrl, repo, testContractArgs, view, VK_HASH, withSession } from "./network.ts";

const OUT = process.env.OUT ?? join(repo, "machine/sidecar-tip/tests/fixtures/logs.json");
// sidecar-tip src/chain/layout.rs: REQUEST_DOMAIN ("psrq"); src/state/chain.rs: PSS_STATE ("PSS\x02")
const REQUEST_DOMAIN = 0x70737271;
const PSS_STATE = 0x50535302;
// C's on-chain intake request (amount_in, direction; user_nonce), the id
// appended without intake, and what A and B emit under R0's tags.
const R0_REQUEST = { inputs: [1000n, 0n], nonce: 0x77n };
const CHOSEN_ID = 0xd4n;
const B_REQUEST = [999999n, 1n, 0xbadn];
const B_SEALED = Array<bigint>(6).fill(9n);
const A_SEALED = [11n, 12n, 13n, 14n, 15n, 16n];
const SALT = { c: new Fr(1n), a: new Fr(2n), b: new Fr(3n) };
// What A emits for the reader's tag queries: PAGED_COUNT one-field logs under
// PAGED_TAG, one more than the node's page of 20 (stdlib MAX_LOGS_PER_TAG),
// and a private log under PRIVATE_TAG (before the kernel silos it).
const PAGED_TAG = 0x9a9en;
const PAGED_COUNT = 21;
const PAGED_PAGE = 20;
const PRIVATE_TAG = 0x9217n;
const PRIVATE_FIELDS = [21n, 22n, 23n];
// a reference block no network has
const GONE = "0x" + "0d".repeat(32);
// the keys of a recorded answer that change on every network (a block hash,
// and the reference block every query names)
const PER_RUN = new Set(["blockHash", "blockTimestamp", "txHash", "hash", "referenceBlock"]);

interface Log {
  logData: string[];
  blockNumber: number;
  txIndexWithinBlock: number;
  logIndexWithinTx: number;
}
interface Tips {
  proposed: { number: number; hash: string };
  proven: { block: { number: number } };
}
interface Call {
  method: string;
  params: unknown[];
  response: { result: unknown } | { error: unknown };
}

const hex = (v: bigint) => "0x" + v.toString(16).padStart(64, "0");
const tagOf = async (id: bigint, domain: number) => (await computeLogTag(new Fr(id), domain)).toString();

let rpcId = 0;
async function rpc(method: string, params: unknown[]): Promise<{ result?: unknown; error?: unknown }> {
  const res = await fetch(nodeUrl, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", method, params, id: ++rpcId }),
  });
  return (await res.json()) as { result?: unknown; error?: unknown };
}

const testArtifact = compileTestContract();
const emitterArtifact = compile("machine/sidecar-tip/tests/chain/log_emitter", "log_emitter-LogEmitter.json");

const fixture = await withSession("pss-tip:record-logs", async (s) => {
  const { user } = s;
  const c = await deploy(s, testArtifact, testContractArgs(), SALT.c);
  await c.methods.request_onchain!(R0_REQUEST.inputs, R0_REQUEST.nonce).send({ from: user });
  await c.methods.request!(CHOSEN_ID).send({ from: user });
  const r0 = BigInt((await view(c.methods.request_at!(0), user)) as bigint);
  const a = await deploy(s, emitterArtifact, [], SALT.a);
  const b = await deploy(s, emitterArtifact, [], SALT.b);
  await b.methods.emit_request!(r0, B_REQUEST).send({ from: user });
  await b.methods.emit_sealed!(r0, B_SEALED).send({ from: user });
  await a.methods.emit_sealed!(r0, A_SEALED).send({ from: user });

  // the reads the test makes, in its order, each recorded with its answer
  const calls: Call[] = [];
  const record = async (method: string, params: unknown[]) => {
    const { result, error } = await rpc(method, params);
    if (error !== undefined) throw new Error(`${method}: ${JSON.stringify(error)}`);
    calls.push({ method, params, response: { result } });
    return result;
  };
  // a call the node refuses, recorded with its error
  const recordRefusal = async (method: string, params: unknown[]) => {
    const { result, error } = await rpc(method, params);
    if (error === undefined) throw new Error(`${method} answered ${JSON.stringify(result)}; expected a refusal`);
    calls.push({ method, params, response: { error } });
    return error as { message: string };
  };
  // a block's data, kept to the keys the reader reads (blockHash) and
  // the block's number: the rest of the header (tree roots, the timestamp,
  // fees) differs on every network
  const recordBlockData = async (n: number) => {
    const { result, error } = await rpc("node_getBlockData", [n]);
    if (error !== undefined) throw new Error(`node_getBlockData: ${JSON.stringify(error)}`);
    const data = result as { blockHash: string; header: { globalVariables: { blockNumber: number } } } | null;
    const kept = data && { blockHash: data.blockHash, header: { globalVariables: { blockNumber: data.header.globalVariables.blockNumber } } };
    calls.push({ method: "node_getBlockData", params: [n], response: { result: kept } });
    return kept;
  };
  // every log under `tag`, paged the way the reader pages it: a full page
  // is asked again with afterLog set to its last log
  const paged = async (method: string, query: Record<string, unknown>, tag: string) => {
    const logs: Log[] = [];
    let entry: unknown = tag;
    for (;;) {
      const [page] = (await record(method, [{ ...query, tags: [entry] }])) as Log[][];
      logs.push(...page!);
      const last = page!.at(-1);
      if (page!.length < PAGED_PAGE || !last) return logs;
      const { blockNumber, txIndexWithinBlock, logIndexWithinTx } = last;
      entry = { tag, afterLog: { blockNumber, txIndexWithinBlock, logIndexWithinTx } };
    }
  };
  // the reader's snapshot is a poll of the reader's follower; every query
  // is anchored at the proposed tip's hash
  const tips = (await record("node_getChainTips", [])) as Tips;
  const referenceBlock = tips.proposed.hash;
  const byTag = async (contract: string, tag: string) =>
    ((await record("node_getPublicLogsByTags", [{ contractAddress: contract, tags: [tag], referenceBlock }])) as Log[][])[0] ?? [];
  const [C, A, B] = [c.address.toString(), a.address.toString(), b.address.toString()];
  const requestTag = await tagOf(r0, REQUEST_DOMAIN);
  const sealedTag = await tagOf(r0, PSS_STATE);
  const [ours] = await byTag(C, requestTag);
  const [theirs] = await byTag(B, requestTag);
  const [sealedA] = await byTag(A, sealedTag);
  const [sealedB] = await byTag(B, sealedTag);
  const chosen = await byTag(C, await tagOf(CHOSEN_ID, REQUEST_DOMAIN));
  if (!ours || !theirs || !sealedA || !sealedB || chosen.length !== 0) {
    throw new Error(`unexpected logs: ${JSON.stringify(calls.map((x) => x.response))}`);
  }

  // the tag queries' reads past the reader's
  await a.methods.emit_many!(PAGED_TAG, PAGED_COUNT).send({ from: user });
  await a.methods.emit_private!(PRIVATE_TAG, PRIVATE_FIELDS).send({ from: user });
  // the follower's next poll: the tip, then the hash of the block it held
  // and of each block between it and the tip above the proven tip (the
  // follower skips the blocks at or below it that no poll read)
  const later = (await record("node_getChainTips", [])) as Tips;
  await recordBlockData(tips.proposed.number);
  const from = Math.max(tips.proposed.number + 1, Math.min(later.proven.block.number, later.proposed.number));
  for (let n = from; n < later.proposed.number; n++) await recordBlockData(n);
  const at = later.proposed.hash;
  const pagedLogs = await paged("node_getPublicLogsByTags", { contractAddress: A, referenceBlock: at }, hex(PAGED_TAG));
  const privateTag = (await computeSiloedPrivateLogFirstField(a.address, new Fr(PRIVATE_TAG))).toString();
  const privateLogs = await paged("node_getPrivateLogsByTags", { referenceBlock: at }, privateTag);
  const gone = await recordRefusal("node_getPublicLogsByTags", [{ contractAddress: A, tags: [hex(PAGED_TAG)], referenceBlock: GONE }]);
  const past = await recordBlockData(later.proposed.number + 1);
  if (pagedLogs.length !== PAGED_COUNT || privateLogs.length !== 1 || !gone.message.includes("not found") || past !== null) {
    throw new Error(`unexpected answers: ${JSON.stringify(calls.slice(-6).map((x) => x.response))}`);
  }

  const fields = (v: bigint[]) => v.map(String).join(", ");
  return {
    recorded:
      "Recorded from a fresh local Aztec 6.0.0 network (aztec start --local-network) by tests/chain/run.sh --record. " +
      `C is PssPublicTest, deployed with vk_hash 0x${VK_HASH.toString(16)}, whose on-chain intake emitted the request log of chain request R0 ` +
      `(inputs ${fields(R0_REQUEST.inputs)}; user_nonce 0x${R0_REQUEST.nonce.toString(16)}) in block ${ours.blockNumber}. ` +
      `B, a LogEmitter (tests/chain/log_emitter), later emitted a log of other inputs (${fields(B_REQUEST.slice(0, 2))}; user_nonce 0x${B_REQUEST[2]!.toString(16)}) ` +
      `under the same tag, compute_log_tag(R0, REQUEST_DOMAIN), in block ${theirs.blockNumber}. ` +
      "A and B (two instances of LogEmitter) each emitted a six-field sealed-shaped log under compute_log_tag(R0, PSS_STATE), " +
      `B first (blocks ${sealedB.blockNumber} and ${sealedA.blockNumber}); every tag was computed in Noir by aztec-nr. ` +
      `The chosen id 0x${CHOSEN_ID.toString(16)}, appended without intake, has no log. ` +
      `Then A emitted ${PAGED_COUNT} one-field logs (0 to ${PAGED_COUNT - 1}) under the tag 0x${PAGED_TAG.toString(16)} in block ${pagedLogs[0]!.blockNumber}, ` +
      `and a private log (${fields(PRIVATE_FIELDS)}) under 0x${PRIVATE_TAG.toString(16)}, siloed with A's address (private_tag), in block ${privateLogs[0]!.blockNumber}; ` +
      `the second node_getChainTips answer (block ${later.proposed.number}) is the follower's next poll, with the node_getBlockData answers it compares, ` +
      "the paged query (a page of 20, then afterLog), the private query, a query whose reference block (gone) no network has, and the block past the tip follow. " +
      "A node_getBlockData answer is kept to blockHash and the block number. " +
      "A log's blockHash, blockTimestamp and txHash, and every block hash (the tips', each query's referenceBlock), differ on every network; the rest is reproduced.",
    c: C,
    a: A,
    b: B,
    r0: hex(r0),
    vk_hash: hex(VK_HASH),
    paged_tag: hex(PAGED_TAG),
    private_tag: privateTag,
    gone: GONE,
    calls,
  };
});

// the recording without the keys that change on every network
const stable = (v: unknown): unknown =>
  Array.isArray(v)
    ? v.map(stable)
    : v !== null && typeof v === "object"
      ? Object.fromEntries(Object.entries(v).filter(([k]) => !PER_RUN.has(k)).map(([k, x]) => [k, stable(x)]))
      : v;
const committed = existsSync(OUT) ? (JSON.parse(readFileSync(OUT, "utf8")) as unknown) : undefined;
if (committed !== undefined && isDeepStrictEqual(stable(committed), stable(fixture))) {
  console.log(`REPRODUCED ${OUT}: the recording equals it but for ${[...PER_RUN].join(", ")}; kept as it is`);
} else {
  writeFileSync(OUT, JSON.stringify(fixture, null, 1) + "\n");
  console.log(`WROTE ${OUT}: ${committed === undefined ? "new" : "the recording differs in more than the per-run keys"}`);
}
