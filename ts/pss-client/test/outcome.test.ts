// Private outcomes on the client side (src/outcome.ts, src/discovery.ts's
// OutcomeReader) and testvectors/outcome.json, the outcome vectors that the
// round's own functions (pss_core tip/outcome.nr, through
// testvectors/noir/outcome_vectors) and the client agree on: the machine
// request id, the partial note, the completed note hash, the AEAD nonce of
// that note hash, the ciphertext and the outcome log's padding, for an
// AMM-shaped outcome (2 fields) and a lending-shaped one (7 fields, a
// pinned read, two new leaf hashes); a lending-shaped round whose shares do
// not open C (its code alone, the mismatch domain's nonce and the opened
// domain's nonce of the same note hash); each case's public-input array in the private-outcome
// layout (pss_public_contract outcome.nr outcome_public_inputs), which
// outcomeResultParts parses at the case's shape; a delivery's log tag
// (pss_core tip/handle.nr handle_tag, handleTag); and the AMM tip's
// secret-shared swap, its shape and its completed note as OutcomeReader
// rebuilds it.
//
// The file and the two Noir programs' Prover.toml (outcome_vectors, the
// round's functions; outcome_layout_vectors, the contract library's layout)
// are written from `vectorFile()`; this test requires them to equal it, so
// client, file and circuit cannot drift apart. Regenerate them with
// `PSS_WRITE_VECTORS=1 node --conditions=source --test test/outcome.test.ts`.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { describe, test } from "node:test";

import { AztecAddress } from "@aztec-labs/aztec.js/addresses";
import { poseidon2Hash, poseidon2HashWithSeparator } from "@aztec-labs/foundation/crypto/poseidon";
import { Fr } from "@aztec-labs/foundation/curves/bn254";
import { encodeArguments, type FunctionAbi } from "@aztec-labs/stdlib/abi";
import { computeSiloedPrivateLogFirstField } from "@aztec-labs/stdlib/hash";

import {
  DOM_SEP_NOTE_COMPLETION_LOG_TAG,
  DOM_SEP_NOTE_HASH,
  DOM_SEP_PARTIAL_NOTE_COMMITMENT,
  completedNoteHash,
  completionLogTag,
  offchainReceiveArgs,
  partialCommitment,
  MAX_NOTE_HASHES_PER_TX,
  NoteMismatchError,
  OUTCOME_LOG_FIELDS,
  OutcomeReader,
  PSS_ATTEMPT,
  ProtocolError,
  SIDECAR_MISMATCH_AD,
  SIDECAR_OUTCOME_AD,
  TagMismatchError,
  PSS_HANDLE_TAG,
  aeEncrypt,
  handleTag,
  hashFields,
  logPadding,
  machineRequestId,
  noirOutcomeResult,
  openOutcome,
  openOutcomeLog,
  outcomeDeliveryArgs,
  outcomeLogFields,
  outcomeLogTag,
  outcomeResultArgs,
  outcomeResultKey,
  outcomeResultParts,
  outcomeLayout,
  outcomeShape,
  parseOutcomeLog,
  sealNonce,
  type ExecuteResponse,
  type OutcomeShape,
  type PrivateLogNode,
  asciiLabel,
  logTx,
} from "../src/internal.ts";
import type { AztecNode } from "@aztec-labs/aztec.js/node";
import { checkOrWrite, contractAbis, encryptOutcome, fixture, queued, repoJson, hex, logNode, tomlList, tomlString } from "@aztec-pss/test-support";

const VECTORS = new URL("../../../testvectors/outcome.json", import.meta.url);
const PROVER = new URL("../../../testvectors/noir/outcome_vectors/Prover.toml", import.meta.url);
const SECRET_VECTORS = new URL("../../../testvectors/secret_store.json", import.meta.url);
const LAYOUT_PROVER = new URL("../../../testvectors/noir/outcome_layout_vectors/Prover.toml", import.meta.url);
/** examples/amm-tip's secret-shared swap: its compiled circuit's ABI and its manifest. */
const AMM_SWAP_SHARED = {
  circuit: { abi: (fixture("amm_swap_tip_shared.abi.json") as { abi: unknown }).abi },
  manifest: repoJson("examples/amm-tip/manifests/amm_swap_tip_shared.json"),
};

interface Case {
  name: string;
  chain_request_id: string;
  old_commitments: string[];
  pinned: string[];
  machine_request_id: string;
  outcome_key: string;
  nonce: string;
  plaintext: string[];
  ciphertext: string[];
  owner: string;
  rho: string;
  partial_note: string;
  storage_slot: string;
  note_hash: string;
  outcome_tag: string;
  padding: string[];
  namespace: string;
  vk_hash: string;
  in_slots: string[];
  out_slots: string[];
  new_commitments: string[];
  npk_app_hash: string;
  new_hashes: string[];
  /** R, W, Q, T, H and the ciphertext's L of outcome_public_inputs. */
  shape: { reads: number; writes: number; pinned: number; new_hashes: number; note_hashes: number; ciphertext: number };
  public_inputs: string[];
}

/** The round's public parts beside its outcome: the slots, the new
 * commitments, npk_app_hash and a tree-valued key's new leaf hashes. */
interface RoundParts {
  namespace: bigint;
  vkHash: bigint;
  inSlots: bigint[];
  outSlots: bigint[];
  newCommitments: bigint[];
  npkAppHash: bigint;
  newHashes: bigint[];
}

/** The partial-note case: the request's partial note and the round's
 * completed note, as pss_core computes them and pss_public_contract_test's
 * two-step note type hashes them. */
async function partialCase() {
  const owner = 0xa11cen, rho = 0x5eed01n, slot = 0x2an, requestId = 0x1dn, key = 0x6b6bn;
  const fields = [0n, 24000n];
  const partial = await partialCommitment(owner, rho);
  const noteHash = await completedNoteHash(slot, partial, fields, requestId);
  return {
    name: "an AMM-shaped completed note [code, amount_out, request_id], completed inside the co-SNARK",
    owner: hex(owner),
    rho: hex(rho),
    partial_note: hex(partial),
    storage_slot: hex(slot),
    request_id: hex(requestId),
    outcome_key: hex(key),
    plaintext: fields.map(hex),
    ciphertext: (await encryptOutcome(fields, key, noteHash)).map(hex),
    note_hash: hex(noteHash),
    completion_log_tag: hex(await completionLogTag(partial)),
  };
}

/** The mismatch case: a lending-shaped round whose shares do not open C
 * seals its code alone, `[code, 0, ...]` (pss_core encrypt_mismatch), under
 * the mismatch domain's nonce of its note hash; `opened_nonce` is the
 * opened domain's nonce of the same note hash, which it must not equal. */
async function mismatchCase() {
  const code = 14n, owner = 0xa11cen, rho = 0x5eed03n, slot = 0x2bn, requestId = 0x3dn, key = 0x6d6dn;
  const plaintext = [code, 0n, 0n, 0n, 0n, 0n, 0n];
  const partial = await partialCommitment(owner, rho);
  const noteHash = await completedNoteHash(slot, partial, plaintext, requestId);
  const nonce = await sealNonce(noteHash, false);
  const sealed = await aeEncrypt(key, nonce, plaintext);
  return {
    name: "a lending-shaped round whose shares do not open C: the code alone [14, 0, ...] in the mismatch domain",
    code: hex(code),
    owner: hex(owner),
    rho: hex(rho),
    partial_note: hex(partial),
    storage_slot: hex(slot),
    request_id: hex(requestId),
    outcome_key: hex(key),
    plaintext: plaintext.map(hex),
    note_hash: hex(noteHash),
    nonce: hex(nonce),
    opened_nonce: hex(await sealNonce(noteHash, true)),
    ciphertext: [...sealed.ciphertext, sealed.tag].map(hex),
  };
}

/** A delivery's log tag under a handle key, for the delivering round's
 * chain request id. */
async function handleCase() {
  const key = 0x4b4bn, requestId = 0x3dn;
  return {
    name: "a delivery's log tag: handle key 0x4b4b, request 0x3d",
    key: hex(key),
    request_id: hex(requestId),
    tag: hex(await handleTag(key, requestId)),
  };
}

/** The note the round completes: the owner's partial note under `rho`,
 * completed with the plaintext and the chain request id. */
interface Note {
  owner: bigint;
  rho: bigint;
  slot: bigint;
}

async function outcomeCase(name: string, chain: bigint, old: bigint[], pinned: bigint[], key: bigint, plaintext: bigint[], note: Note, tag: bigint, round: RoundParts): Promise<Case> {
  const mrid = (await machineRequestId(chain, old, pinned)).toBigInt();
  const partial = await partialCommitment(note.owner, note.rho);
  const noteHash = await completedNoteHash(note.slot, partial, plaintext, chain);
  const ciphertext = await encryptOutcome(plaintext, key, noteHash);
  // outcome_public_inputs: [namespace, vk_hash, in_slots, out_slots, reads,
  // request_id, machine_request_id, old_commitments, new_commitments,
  // npk_app_hash, new_hashes, outcome_tag, note_hashes, ciphertext]
  const publicInputs = [
    round.namespace,
    round.vkHash,
    ...round.inSlots,
    ...round.outSlots,
    ...pinned,
    chain,
    mrid,
    ...old,
    ...round.newCommitments,
    round.npkAppHash,
    ...round.newHashes,
    tag,
    noteHash,
    ...ciphertext,
  ];
  const padding: bigint[] = [];
  // log positions after the tag: the note hash, the ciphertext, then the padding
  for (let i = 1 + ciphertext.length; i < OUTCOME_LOG_FIELDS - 1; i++) padding.push(await logPadding(tag, i));
  return {
    name,
    chain_request_id: hex(chain),
    old_commitments: old.map(hex),
    pinned: pinned.map(hex),
    machine_request_id: hex(mrid),
    outcome_key: hex(key),
    nonce: hex(await sealNonce(noteHash, true)),
    plaintext: plaintext.map(hex),
    ciphertext: ciphertext.map(hex),
    owner: hex(note.owner),
    rho: hex(note.rho),
    partial_note: hex(partial),
    storage_slot: hex(note.slot),
    note_hash: hex(noteHash),
    outcome_tag: hex(tag),
    padding: padding.map(hex),
    namespace: hex(round.namespace),
    vk_hash: hex(round.vkHash),
    in_slots: round.inSlots.map(hex),
    out_slots: round.outSlots.map(hex),
    new_commitments: round.newCommitments.map(hex),
    npk_app_hash: hex(round.npkAppHash),
    new_hashes: round.newHashes.map(hex),
    shape: {
      reads: old.length,
      writes: round.newCommitments.length,
      pinned: pinned.length,
      new_hashes: round.newHashes.length,
      note_hashes: 1,
      ciphertext: ciphertext.length,
    },
    public_inputs: publicInputs.map(hex),
  };
}

const NAMESPACE_V = 0x1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f809n;
const VK_HASH_V = 0x2a8f1c0e9b7d6a5f4e3c2b1a09f8e7d6c5b4a39281706f5e4d3c2b1a09f8e7d6n;

async function vectorFile() {
  return {
    description:
      "Private outcomes: what a secret-shared-intake round computes inside the MPC for the user (pss_core tip/outcome.nr), and the client recomputes (pss-client src/outcome.ts), and a delivery's log tag (pss_core tip/handle.nr, pss-client src/handle.ts). Written and read by pss-client test/outcome.test.ts, which also writes testvectors/noir/outcome_vectors/Prover.toml from it; the Noir program checks it with pss_core's functions, and pss_public_contract_test checks the completed note hash against aztec-nr's two-step note hash.",
    rules: {
      machine_request_id: "poseidon2([PSS_ATTEMPT, chain_request_id, old_commitments..., pinned...])",
      nonce: "poseidon2([note_hash, SIDECAR_OUTCOME_AD]) when the round's shares open C, poseidon2([note_hash, SIDECAR_MISMATCH_AD]) when they do not (pss_core seal_nonce): the note hash commits to the plaintext, so one nonce seals one plaintext",
      ciphertext: "the Poseidon2 duplex AEAD of pss_utils ae.nr (testvectors/ae.json) of the plaintext under (outcome_key, nonce): ct..., then the tag",
      mismatch: "a round whose shares do not open C seals [code, 0, ...] (pss_core encrypt_mismatch): its note hash over that plaintext, the nonce in the mismatch domain; opened_nonce is the opened domain's nonce of the same note hash",
      note_hash: "poseidon2_hash_with_separator([storage_slot, partial_note, plaintext..., chain_request_id], DOM_SEP__NOTE_HASH), the completed note (pss_core completed_note_hash)",
      padding: "the outcome log [note_hash, ciphertext..., padding...]'s fields past the ciphertext: poseidon2([outcome_tag, i]) at each log position i after the tag, from 1 + len(ciphertext) to 14 (pss_core log_padding, pss_public_contract outcome_log)",
      partial_note: "poseidon2_hash_with_separator([owner, rho], DOM_SEP__PARTIAL_NOTE_COMMITMENT), the request's $partial_note (pss_core partial_commitment)",
      completed_note_hash: "poseidon2_hash_with_separator([storage_slot, partial_note, plaintext..., request_id], DOM_SEP__NOTE_HASH), the completed note (pss_core completed_note_hash), which pss_public_contract_test's two-step note type hashes alike over its packed fields [plaintext..., request_id]",
      completion_log_tag: "poseidon2_hash_with_separator([partial_note], DOM_SEP__NOTE_COMPLETION_LOG_TAG), the tag of a public completion's log",
      handle_tag: "poseidon2([key, PSS_HANDLE_TAG, request_id]), a delivery's log tag under its handle key for the delivering round's chain request id, before the kernel silos it with the contract (pss_core tip/handle.nr handle_tag, pss-client handleTag)",
      public_inputs: "the round's public-input array in the private-outcome layout, pss_public_contract outcome.nr outcome_public_inputs: [namespace, vk_hash, in_slots[R], out_slots[W], pinned[Q], chain_request_id, machine_request_id, old_commitments[R], new_commitments[W], npk_app_hash, new_hashes[T], outcome_tag, note_hash (H = 1), ciphertext[L]]; shape gives R, W, Q, T, H and L. The lending-shaped case has a tree-valued key's two new leaf hashes",
    },
    pss_attempt: hex(PSS_ATTEMPT),
    sidecar_outcome_ad: hex(SIDECAR_OUTCOME_AD),
    sidecar_mismatch_ad: hex(SIDECAR_MISMATCH_AD),
    pss_handle_tag: hex(PSS_HANDLE_TAG),
    dom_sep_note_hash: DOM_SEP_NOTE_HASH,
    dom_sep_partial_note_commitment: DOM_SEP_PARTIAL_NOTE_COMMITMENT,
    dom_sep_note_completion_log_tag: DOM_SEP_NOTE_COMPLETION_LOG_TAG,
    partial_note: await partialCase(),
    mismatch: await mismatchCase(),
    handle_tag: await handleCase(),
    vectors: [
      await outcomeCase("an AMM-shaped outcome [code, amount_out], no pinned read", 0x1dn, [0x4e0n], [], 0x6b6bn, [0n, 24000n], { owner: 0xa11cen, rho: 0x5eedn, slot: 0x2an }, 0x7a7an, {
        namespace: NAMESPACE_V,
        vkHash: VK_HASH_V,
        inSlots: [0xa002n],
        outSlots: [0xa002n],
        newCommitments: [0x4e1n],
        npkAppHash: 0x9bn,
        newHashes: [],
      }),
      await outcomeCase(
        "a lending-shaped outcome [code, position, mask, x, y, payout, leaf_hash], one pinned read",
        0x2dn,
        [0x5e0n],
        [0x7d0n],
        0x6c6cn,
        [0n, 7n, 0n, 100n, 200n, 50n, 0x1eafn],
        { owner: 0xa11cen, rho: 0x5eed02n, slot: 0x2bn },
        0x7b7bn,
        {
          namespace: NAMESPACE_V,
          vkHash: VK_HASH_V,
          inSlots: [0x30n],
          outSlots: [0x30n],
          newCommitments: [0x5e1n],
          npkAppHash: 0x9bn,
          newHashes: [0x1ea1n, 0x1ea2n],
        },
      ),
    ],
  };
}

const q = tomlString;
const list = tomlList;

function proverToml(file: Awaited<ReturnType<typeof vectorFile>>): string {
  const lines = [
    "# Written by pss-client test/outcome.test.ts from testvectors/outcome.json.",
    `pss_attempt = ${q(file.pss_attempt)}`,
    `sidecar_outcome_ad = ${q(file.sidecar_outcome_ad)}`,
    `sidecar_mismatch_ad = ${q(file.sidecar_mismatch_ad)}`,
    `pss_handle_tag = ${q(file.pss_handle_tag)}`,
    "",
  ];
  const tables = ["amm", "lending"];
  file.vectors.forEach((v, i) => {
    lines.push(`# ${v.name}`, `[${tables[i]}]`);
    for (const k of ["chain_request_id", "machine_request_id", "outcome_key", "nonce", "owner", "rho", "partial_note", "storage_slot", "note_hash", "outcome_tag"] as const) {
      lines.push(`${k} = ${q(v[k])}`);
    }
    for (const k of ["old_commitments", "pinned", "plaintext", "ciphertext", "padding"] as const) {
      // an entry point takes no empty array: the program supplies `[]`
      if (v[k].length > 0) lines.push(`${k} = ${list(v[k])}`);
    }
    lines.push("");
  });
  const p = file.partial_note;
  lines.push(`# ${p.name}`, "[partial]");
  for (const k of ["owner", "rho", "partial_note", "storage_slot", "request_id", "outcome_key", "note_hash", "completion_log_tag"] as const) lines.push(`${k} = ${q(p[k])}`);
  lines.push(`plaintext = ${list(p.plaintext)}`, `ciphertext = ${list(p.ciphertext)}`, "");
  const m = file.mismatch;
  lines.push(`# ${m.name}`, "[mismatch]");
  for (const k of ["code", "owner", "rho", "partial_note", "storage_slot", "request_id", "outcome_key", "note_hash", "nonce", "opened_nonce"] as const) lines.push(`${k} = ${q(m[k])}`);
  lines.push(`plaintext = ${list(m.plaintext)}`, `ciphertext = ${list(m.ciphertext)}`, "");
  const t = file.handle_tag;
  lines.push(`# ${t.name}`, "[handle]");
  for (const k of ["key", "request_id", "tag"] as const) lines.push(`${k} = ${q(t[k])}`);
  lines.push("");
  // testvectors/secret_store.json (test/secrets.test.ts writes it)
  const s = JSON.parse(readFileSync(SECRET_VECTORS, "utf8")) as {
    pss_partial_randomness: string; pss_outcome_key: string; pss_outcome_tag: string;
    wallet_secret: string; namespace: string; owner: string;
    vectors: { rho: string; outcome_key: string; outcome_tag: string; partial_note: string; completion_log_tag: string }[];
  };
  lines.push("# testvectors/secret_store.json: the n-th request's derivations, n = 0, 1, 2", "[secrets]");
  for (const k of ["pss_partial_randomness", "pss_outcome_key", "pss_outcome_tag", "wallet_secret", "namespace", "owner"] as const) lines.push(`${k} = ${q(s[k])}`);
  for (const k of ["rho", "outcome_key", "outcome_tag", "partial_note", "completion_log_tag"] as const) lines.push(`${k} = ${list(s.vectors.map((v) => v[k]))}`);
  lines.push("");
  return lines.join("\n");
}

/** outcome_layout_vectors' Prover.toml: each case's public parts and its
 * public inputs; the pinned values and new leaf hashes at the top level as
 * `{case}_{name}` where a case has some. */
function layoutProverToml(file: Awaited<ReturnType<typeof vectorFile>>): string {
  const lines = ["# Written by pss-client test/outcome.test.ts from testvectors/outcome.json."];
  const tables = ["amm", "lending"];
  file.vectors.forEach((v, i) => {
    for (const k of ["pinned", "new_hashes"] as const) {
      // an entry point takes no empty array: the program supplies `[]`
      if (v[k].length > 0) lines.push(`${tables[i]}_${k} = ${list(v[k])}`);
    }
  });
  lines.push("");
  file.vectors.forEach((v, i) => {
    lines.push(`# ${v.name}`, `[${tables[i]}]`);
    for (const k of ["namespace", "vk_hash", "chain_request_id", "machine_request_id", "npk_app_hash", "outcome_tag", "note_hash"] as const) lines.push(`${k} = ${q(v[k])}`);
    for (const k of ["in_slots", "out_slots", "old_commitments", "new_commitments", "ciphertext", "public_inputs"] as const) lines.push(`${k} = ${list(v[k])}`);
    lines.push("");
  });
  return lines.join("\n");
}

describe("the outcome vectors (testvectors/outcome.json)", () => {
  test("the file and the Noir programs' Prover.toml are what the client computes", async () => {
    const file = await vectorFile();
    const json = JSON.stringify(file, null, 2) + "\n";
    const toml = proverToml(file);
    const layoutToml = layoutProverToml(file);
    checkOrWrite(VECTORS, json);
    checkOrWrite(PROVER, toml);
    checkOrWrite(LAYOUT_PROVER, layoutToml);
  });

  test("outcomeResultParts takes each part from a case's public inputs at its shape", async () => {
    const file = JSON.parse(readFileSync(VECTORS, "utf8")) as Awaited<ReturnType<typeof vectorFile>>;
    for (const v of file.vectors) {
      const shape: OutcomeShape = {
        circuit: v.name,
        reads: v.shape.reads,
        writes: v.shape.writes,
        pinned: v.shape.pinned,
        newHashes: v.shape.new_hashes,
        noteHashes: v.shape.note_hashes,
        state: "node",
        records: [],
      };
      const sig = { s: ["0x00", "0x00"], e: ["0x00", "0x00"] };
      const response = { request_id: v.machine_request_id, vk_hash: v.vk_hash, proof: "0x", public_inputs: v.public_inputs, stored: [], records: [], signatures: [sig, sig, sig] } as unknown as ExecuteResponse;
      const parts = await outcomeResultParts(shape, v.namespace, v.chain_request_id, response);
      assert.deepEqual(
        [parts.machineRequestId, parts.oldCommitments, parts.newCommitments, parts.reads, parts.newHashes, parts.outcomeTag, parts.noteHashes, parts.ciphertext],
        [v.machine_request_id, v.old_commitments, v.new_commitments, v.pinned, v.new_hashes, v.outcome_tag, [v.note_hash], v.ciphertext],
        v.name,
      );
      assert.equal(v.shape.ciphertext, v.ciphertext.length);
      const { reads: R, writes: W, pinned: Q, new_hashes: T, note_hashes: H, ciphertext: L } = v.shape;
      assert.equal(v.public_inputs.length, 2 + R + W + Q + 2 + R + W + 1 + T + 1 + H + L);
      assert.deepEqual([v.public_inputs[0], v.public_inputs[1], v.public_inputs.slice(2, 2 + R), v.public_inputs.slice(2 + R, 2 + R + W)], [v.namespace, v.vk_hash, v.in_slots, v.out_slots]);
      assert.equal(v.public_inputs[2 + R + W + Q + 2 + R + W], v.npk_app_hash);
    }
  });

  // examples/amm-tip's secret-shared swap: one key read and written, one
  // completed note hash, then the ciphertext of [code, amount_out] and its
  // tag, the last public inputs.
  test("amm_swap_tip_shared's shape, as outcomeShape reads it from the circuit's ABI", () => {
    const s = outcomeShape(AMM_SWAP_SHARED.circuit, queued(AMM_SWAP_SHARED.manifest));
    assert.deepEqual([s.reads, s.writes, s.pinned, s.newHashes, s.noteHashes], [1, 1, 0, 0, 1]);
    const layout = outcomeLayout(s, 14);
    assert.deepEqual([layout.noteHashes, layout.ciphertext], [[10], [11, 12, 13]]);
  });

  test("the domains are their labels and the rules are poseidon2 over their preimages", async () => {
    const file = JSON.parse(readFileSync(VECTORS, "utf8")) as Awaited<ReturnType<typeof vectorFile>>;
    assert.equal(BigInt(file.sidecar_outcome_ad), asciiLabel("sidecar.outcome"));
    assert.equal(BigInt(file.sidecar_mismatch_ad), asciiLabel("sidecar.mismatch"));
    assert.equal(BigInt(file.pss_attempt), asciiLabel("sidecar.attempt"));
    assert.equal(BigInt(file.pss_handle_tag), asciiLabel("pss.handle_tag"));
    const h = async (xs: string[]) => hex((await poseidon2Hash(xs.map((x) => new Fr(BigInt(x))))).toBigInt());
    for (const v of file.vectors) {
      assert.equal(v.machine_request_id, await h([file.pss_attempt, v.chain_request_id, ...v.old_commitments, ...v.pinned]));
      const p = await poseidon2HashWithSeparator([v.owner, v.rho].map((x) => new Fr(BigInt(x))), file.dom_sep_partial_note_commitment);
      assert.equal(v.partial_note, hex(p.toBigInt()));
      const nh = await poseidon2HashWithSeparator([v.storage_slot, v.partial_note, ...v.plaintext, v.chain_request_id].map((x) => new Fr(BigInt(x))), file.dom_sep_note_hash);
      assert.equal(v.note_hash, hex(nh.toBigInt()));
      assert.equal(v.nonce, await h([v.note_hash, file.sidecar_outcome_ad]));
      assert.deepEqual((await openOutcome(v.ciphertext, v.outcome_key, v.note_hash)).map(hex), v.plaintext);
      assert.equal(v.ciphertext.length, v.plaintext.length + 1);
      assert.equal(1 + v.ciphertext.length + v.padding.length, OUTCOME_LOG_FIELDS - 1);
      for (const [k, p] of v.padding.entries()) assert.equal(p, await h([v.outcome_tag, hex(BigInt(1 + v.ciphertext.length + k))]));
    }
    // the mismatch case: the code alone, its note hash, the mismatch
    // domain's nonce, which differs from the opened domain's of that note
    // hash, and the ciphertext opens to the code under openOutcome
    const m = file.mismatch;
    assert.deepEqual(m.plaintext, [m.code, ...Array<string>(6).fill(hex(0n))]);
    const mp = await poseidon2HashWithSeparator([m.owner, m.rho].map((x) => new Fr(BigInt(x))), file.dom_sep_partial_note_commitment);
    assert.equal(m.partial_note, hex(mp.toBigInt()));
    const mnh = await poseidon2HashWithSeparator([m.storage_slot, m.partial_note, ...m.plaintext, m.request_id].map((x) => new Fr(BigInt(x))), file.dom_sep_note_hash);
    assert.equal(m.note_hash, hex(mnh.toBigInt()));
    assert.equal(m.nonce, await h([m.note_hash, file.sidecar_mismatch_ad]));
    assert.equal(m.opened_nonce, await h([m.note_hash, file.sidecar_outcome_ad]));
    assert.notEqual(m.nonce, m.opened_nonce);
    assert.deepEqual((await openOutcome(m.ciphertext, m.outcome_key, m.note_hash)).map(hex), m.plaintext);
    const p = file.partial_note;
    assert.deepEqual((await openOutcome(p.ciphertext, p.outcome_key, p.note_hash)).map(hex), p.plaintext);
    const t = file.handle_tag;
    assert.equal(t.tag, await h([t.key, file.pss_handle_tag, t.request_id]));
  });
});

describe("private outcomes", () => {
  const KEY = 0x6b6bn;
  // a note hash the tests seal under
  const NOTE = 0x3an;

  test("an outcome opens with its key under its note hash's nonce, and only there", async () => {
    const ct = await encryptOutcome([1n, 0n, 24000n], KEY, NOTE);
    assert.deepEqual(await openOutcome(ct, KEY, NOTE), [1n, 0n, 24000n]);
    await assert.rejects(openOutcome(ct, KEY + 1n, NOTE), TagMismatchError);
    await assert.rejects(openOutcome(ct, KEY, NOTE + 1n), TagMismatchError);
  });

  test("one note hash has two nonces: opened when the shares open C, mismatch when they do not", async () => {
    assert.notEqual(await sealNonce(NOTE, true), await sealNonce(NOTE, false));
  });

  test("a round whose shares did not open C: its code alone opens in the mismatch domain, through its log; in neither domain it does not open", async () => {
    // the app's mismatch code alone, the other fields zero (pss_core
    // tip/outcome.nr encrypt_mismatch), its note over that plaintext
    const code = [7n, 0n, 0n];
    const noteHash = await completedNoteHash(0x2an, await partialCommitment(0xa11cen, 0x5eedn), code, 0x1dn);
    const sealed = await aeEncrypt(KEY, await sealNonce(noteHash, false), code);
    const ct = [...sealed.ciphertext, sealed.tag];
    assert.deepEqual(await openOutcome(ct, KEY, noteHash), code);
    await assert.rejects(openOutcome(ct, KEY + 1n, noteHash), TagMismatchError);
    await assert.rejects(openOutcome(ct, KEY, noteHash + 1n), TagMismatchError);
    // sealed under neither domain of the note hash
    const other = await aeEncrypt(KEY, await hashFields([noteHash, asciiLabel("sidecar.other")]), code);
    await assert.rejects(openOutcome([...other.ciphertext, other.tag], KEY, noteHash), TagMismatchError);
    // the opened domain comes first: an opened round's outcome reads as sealed
    const ok = await encryptOutcome([1n, 0n, 24000n], KEY, NOTE);
    assert.deepEqual(await openOutcome(ok, KEY, NOTE), [1n, 0n, 24000n]);
    // its log [tag, note_hash, ct..., padding...] opens, and the note is rebuilt over the code
    const fields = await outcomeLogFields(0xc0ffeen, 0x7a7an, noteHash, ct);
    const opened = await openOutcomeLog(fields, { outcomeKey: KEY, owner: 0xa11cen, rho: 0x5eedn, requestId: 0x1dn, storageSlot: 0x2an, plaintextLength: 3 });
    assert.deepEqual(opened.plaintext, code);
    assert.equal(opened.note.noteHash, hex(noteHash));
    assert.equal(opened.noteMatches, true);
    // a node that changed its partial-note share: the code reads, the note
    // is another partial note's completion, reported as not the user's
    const changed = await completedNoteHash(0x2an, (await partialCommitment(0xa11cen, 0x5eedn)) + 1n, code, 0x1dn);
    const sealedChanged = await aeEncrypt(KEY, await sealNonce(changed, false), code);
    const changedLog = await outcomeLogFields(0xc0ffeen, 0x7a7an, changed, [...sealedChanged.ciphertext, sealedChanged.tag]);
    const read = await openOutcomeLog(changedLog, { outcomeKey: KEY, owner: 0xa11cen, rho: 0x5eedn, requestId: 0x1dn, storageSlot: 0x2an, plaintextLength: 3 });
    assert.deepEqual(read.plaintext, code);
    assert.equal(read.loggedNoteHash, hex(changed));
    assert.equal(read.noteMatches, false);
  });

  test("an opened round's log opens in the opened domain under the note hash it carries", async () => {
    const pt = [1n, 0n, 24000n];
    const noteHash = await completedNoteHash(0x2an, await partialCommitment(0xa11cen, 0x5eedn), pt, 0x1dn);
    const fields = await outcomeLogFields(0xc0ffeen, 0x7a7an, noteHash, await encryptOutcome(pt, KEY, noteHash));
    const opened = await openOutcomeLog(fields, { outcomeKey: KEY, owner: 0xa11cen, rho: 0x5eedn, requestId: 0x1dn, storageSlot: 0x2an, plaintextLength: 3 });
    assert.deepEqual(opened.plaintext, pt);
    assert.equal(opened.note.noteHash, hex(noteHash));
    // a log carrying another note hash does not open
    const moved = [...fields];
    moved[1] = noteHash + 1n;
    await assert.rejects(openOutcomeLog(moved, { outcomeKey: KEY, owner: 0xa11cen, rho: 0x5eedn, requestId: 0x1dn, storageSlot: 0x2an, plaintextLength: 3 }), TagMismatchError);
  });

  test("two plaintexts under one key have two note hashes, so they do not share a keystream", async () => {
    const partial = await partialCommitment(0xa11cen, 0x5eedn);
    const [pa, pb] = [[1n, 0n, 24000n], [1n, 0n, 25000n]];
    const [na, nb] = [await completedNoteHash(0x2an, partial, pa, 0x1dn), await completedNoteHash(0x2an, partial, pb, 0x1dn)];
    assert.notEqual(na, nb);
    const a = await encryptOutcome(pa, KEY, na);
    const b = await encryptOutcome(pb, KEY, nb);
    assert.notEqual(b[2]! - a[2]!, 1000n);
  });

  test("an outcome log is padded with poseidon2([tag, i]), read past its padding, and its note rebuilt", async () => {
    const pt = [1n, 0n, 24000n];
    const noteHash = await completedNoteHash(0x2an, await partialCommitment(0xa11cen, 0x5eedn), pt, 0x1dn);
    const ct = await encryptOutcome(pt, KEY, noteHash);
    const fields = await outcomeLogFields(0xc0ffeen, 0x7a7an, noteHash, ct);
    assert.equal(fields.length, OUTCOME_LOG_FIELDS);
    assert.ok(new Fr(fields[0]!).equals(await outcomeLogTag(0xc0ffeen, 0x7a7an)));
    assert.deepEqual(fields.slice(1, 6), [noteHash, ...ct]);
    for (let i = 5; i < OUTCOME_LOG_FIELDS - 1; i++) {
      assert.equal(fields[1 + i], (await poseidon2Hash([new Fr(0x7a7an), new Fr(BigInt(i))])).toBigInt());
    }
    assert.notEqual((await outcomeLogFields(0xc0ffeen, 0x7a7bn, noteHash, ct))[6], fields[6]);
    assert.deepEqual(parseOutcomeLog(fields, 3), { noteHash: hex(noteHash), ciphertext: ct });
    const opened = await openOutcomeLog(fields, { outcomeKey: KEY, owner: 0xa11cen, rho: 0x5eedn, requestId: 0x1dn, storageSlot: 0x2an, plaintextLength: 3 });
    assert.deepEqual(opened.plaintext, pt);
    assert.equal(opened.note.randomness, hex(0x5eedn));
    assert.deepEqual(opened.note.packed, [...pt, 0x1dn].map(hex));
    assert.equal(opened.note.noteHash, hex(noteHash));
    assert.throws(() => parseOutcomeLog(fields.slice(0, 15), 3), RangeError);
    assert.throws(() => parseOutcomeLog(fields, 14), RangeError);
  });

  test("the log tag is the outcome tag siloed with the contract", async () => {
    const contract = AztecAddress.fromBigIntUnsafe(0xc0ffeen);
    assert.ok((await outcomeLogTag(0xc0ffeen, 0x7a7an)).equals(await computeSiloedPrivateLogFirstField(contract, new Fr(0x7a7an))));
  });
});

// ---- the result, for whoever lands it ----

const SHAPE: OutcomeShape = { circuit: "shared_round", reads: 1, writes: 1, pinned: 1, noteHashes: 1, state: "node", records: [] };
const sig = { s: [hex(1n), hex(2n)] as [string, string], e: [hex(3n), hex(4n)] as [string, string] };

async function answer(chain: bigint, old: bigint, read: bigint): Promise<ExecuteResponse> {
  const mrid = hex((await machineRequestId(chain, [old], [read])).toBigInt());
  // [namespace, vk_hash, in_slot, out_slot, read | request_id, mrid, old, new, npk_app_hash, tag, note hash, ct(4)]
  const pi = [0xa0n, 0x7en, 0x51n, 0x51n, read, chain, BigInt(mrid), old, 0x1cn, 0x9bn, 0x7an, 0x4an, 0xc0n, 0xc1n, 0xc2n, 0xc3n].map(hex);
  return { request_id: mrid, vk_hash: hex(0x7en), proof: "0x", public_inputs: pi, stored: [], records: [], signatures: [sig, sig, sig] };
}

describe("the private-outcome result", () => {
  test("its parts are read at the library's layout, and the binding checked", async () => {
    const parts = await outcomeResultParts(SHAPE, 0xa0n, 0x1dn, await answer(0x1dn, 0x0cn, 0x7d0n));
    assert.deepEqual(parts.oldCommitments, [hex(0x0cn)]);
    assert.deepEqual(parts.newCommitments, [hex(0x1cn)]);
    assert.deepEqual(parts.reads, [hex(0x7d0n)]);
    assert.equal(parts.outcomeTag, hex(0x7an));
    assert.deepEqual(parts.noteHashes, [hex(0x4an)]);
    assert.deepEqual(parts.ciphertext, [0xc0n, 0xc1n, 0xc2n, 0xc3n].map(hex));
    await assert.rejects(outcomeResultParts(SHAPE, 0xa1n, 0x1dn, await answer(0x1dn, 0x0cn, 0x7d0n)), ProtocolError);
    await assert.rejects(outcomeResultParts(SHAPE, 0xa0n, 0x1en, await answer(0x1dn, 0x0cn, 0x7d0n)), ProtocolError);
    const moved = await answer(0x1dn, 0x0cn, 0x7d0n);
    moved.public_inputs[4] = hex(0x7d1n);
    await assert.rejects(outcomeResultParts(SHAPE, 0xa0n, 0x1dn, moved), ProtocolError);
  });

  test("a tree-valued key's new leaf hashes follow npk_app_hash and are process_result's second argument", async () => {
    const flat = await outcomeResultParts(SHAPE, 0xa0n, 0x1dn, await answer(0x1dn, 0x0cn, 0x7d0n));
    assert.deepEqual(flat.newHashes, []);
    const response = await answer(0x1dn, 0x0cn, 0x7d0n);
    // after npk_app_hash (public input 9 here), before the tag
    response.public_inputs.splice(10, 0, ...[0x11n, 0x12n].map(hex));
    const tree = await outcomeResultParts({ ...SHAPE, newHashes: 2 }, 0xa0n, 0x1dn, response);
    assert.deepEqual(tree.newHashes, [0x11n, 0x12n].map(hex));
    assert.equal(tree.outcomeTag, flat.outcomeTag);
    assert.deepEqual(tree.noteHashes, flat.noteHashes);
    assert.deepEqual(tree.ciphertext, flat.ciphertext);
    assert.deepEqual(noirOutcomeResult(tree), noirOutcomeResult(flat));
    const args = outcomeResultArgs(tree);
    assert.equal(args.length, 3);
    assert.deepEqual((args[1] as Fr[]).map((f) => f.toBigInt()), [0x11n, 0x12n]);
    await assert.rejects(outcomeResultParts({ ...SHAPE, newHashes: 1.5 }, 0xa0n, 0x1dn, response), RangeError);
  });

  test("a round's app values are its last public inputs, after the ciphertext, and process_result's argument before the signatures", async () => {
    const flat = await outcomeResultParts(SHAPE, 0xa0n, 0x1dn, await answer(0x1dn, 0x0cn, 0x7d0n));
    assert.deepEqual(flat.appValues, []);
    const response = await answer(0x1dn, 0x0cn, 0x7d0n);
    response.public_inputs.splice(10, 0, ...[0x11n, 0x12n].map(hex));
    response.public_inputs.push(hex(1n));
    const valued = await outcomeResultParts({ ...SHAPE, newHashes: 2, appValues: 1 }, 0xa0n, 0x1dn, response);
    assert.deepEqual(valued.appValues, [hex(1n)]);
    assert.deepEqual(valued.ciphertext, flat.ciphertext);
    const args = outcomeResultArgs(valued);
    assert.equal(args.length, 4);
    assert.deepEqual((args[2] as Fr[]).map((f) => f.toBigInt()), [1n]);
    assert.notEqual(outcomeResultKey(valued), outcomeResultKey({ ...valued, appValues: [hex(0n)] }));
    await assert.rejects(outcomeResultParts({ ...SHAPE, appValues: -1 }, 0xa0n, 0x1dn, response), RangeError);
  });

  test("its arguments are the OutcomeResult, then the signatures, with nothing about the outcome in the apply", async () => {
    const parts = await outcomeResultParts(SHAPE, 0xa0n, 0x1dn, await answer(0x1dn, 0x0cn, 0x7d0n));
    const r = noirOutcomeResult(parts);
    assert.deepEqual(
      [r.apply.request_id, ...r.apply.old_commitments, ...r.apply.values].map((f) => f.toBigInt()),
      [0x1dn, 0x0cn, 0x1cn, 0x7d0n],
    );
    const args = outcomeResultArgs(parts);
    assert.equal(args.length, 2);
    assert.equal((args[1] as Fr[][]).length, 3);
  });
});

// ---- the outcome reader ----

describe("OutcomeReader", () => {
  const contract = 0xc0ffeen;
  const keys = { outcomeKey: 0x6b6bn, owner: 0xa11cen, rho: 0x5eedn, requestId: 0x1dn, storageSlot: 0x2an, plaintextLength: 3 };

  /** A log `[tag, note_hash, ct..., padding]` of `pt` under `key` with the
   * note hash `noteHash`'s nonce (the reader takes the note hash from the
   * log); by default the hash of the note `keys` complete with `pt`, as a
   * round outputs it. */
  async function logOf(key: bigint, pt: bigint[], noteHash?: bigint): Promise<Fr[]> {
    noteHash ??= await completedNoteHash(keys.storageSlot, await partialCommitment(keys.owner, keys.rho), pt, keys.requestId);
    const fields = [await outcomeLogTag(contract, 0x7a7an), new Fr(noteHash), ...(await encryptOutcome(pt, key, noteHash)).map((x) => new Fr(x))];
    while (fields.length < OUTCOME_LOG_FIELDS) fields.push(Fr.random());
    return fields;
  }

  const node = logNode;

  // pss_public_contract's `OutcomeTx` as nargo writes it into a contract
  // artifact: the parameter the outcome-note utility takes
  const OUTCOME_TX_ABI = {
    name: "deliver",
    parameters: [
      {
        name: "tx",
        visibility: "private",
        type: {
          kind: "struct",
          path: "pss_public_contract::outcome::OutcomeTx",
          fields: [
            { name: "tx_hash", type: { kind: "field" } },
            {
              name: "unique_note_hashes",
              type: {
                kind: "struct",
                path: "std::collections::bounded_vec::BoundedVec",
                fields: [
                  { name: "storage", type: { kind: "array", length: MAX_NOTE_HASHES_PER_TX, type: { kind: "field" } } },
                  { name: "len", type: { kind: "integer", sign: "unsigned", width: 32 } },
                ],
              },
            },
            { name: "first_nullifier", type: { kind: "field" } },
          ],
        },
      },
    ],
  } as unknown as FunctionAbi;

  test("finds the log under the siloed tag, passes over one that does not open, and delivers the note", async () => {
    const n = node([await logOf(0x1111n, [9n, 9n, 9n]), await logOf(keys.outcomeKey, [1n, 0n, 24000n])]);
    const delivered: unknown[][] = [];
    const found = await new OutcomeReader(n, contract).readAndDeliver(0x7a7an, keys, async (f) => {
      delivered.push(outcomeDeliveryArgs(f));
    });
    assert.deepEqual(n.asked, [(await outcomeLogTag(contract, 0x7a7an)).toBigInt()]);
    assert.ok(found);
    assert.deepEqual(found.plaintext, [1n, 0n, 24000n]);
    assert.deepEqual(found.tx, { txHash: hex(0x7777n), uniqueNoteHashes: [hex(0x4an)], firstNullifier: hex(0x99n) });
    assert.equal(delivered.length, 1);
    const tx = delivered[0]![3] as { unique_note_hashes: Fr[] };
    assert.deepEqual(tx.unique_note_hashes, [new Fr(0x4an)]);
    // aztec.js encodes it as the library's OutcomeTx: the hash, the BoundedVec
    // (storage padded to 64, then len) and the first nullifier
    assert.deepEqual(
      encodeArguments(OUTCOME_TX_ABI, [tx]).map((f) => f.toBigInt()),
      [0x7777n, 0x4an, ...Array(MAX_NOTE_HASHES_PER_TX - 1).fill(0n), 1n, 0x99n],
    );
  });

  // The node's answer as aztec.js types it, effects optional: an aztec.js
  // AztecNode is a PrivateLogNode (checked by the test build), and a log
  // that comes without its transaction's effects is refused, never read as a
  // transaction with no note hashes.
  test("an aztec.js node is a PrivateLogNode, and a log without effects is refused", async () => {
    const asNode = (n: AztecNode): PrivateLogNode => n;
    void asNode;
    const log = await logOf(keys.outcomeKey, [1n, 0n, 24000n]);
    const bare: PrivateLogNode = { getPrivateLogsByTags: async () => [[{ logData: log, txHash: { toString: () => hex(0x7777n) } }]] };
    await assert.rejects(new OutcomeReader(bare, contract).read(0x7a7an, keys), /transaction effects are missing/);
    assert.deepEqual(logTx({ txHash: { toString: () => hex(0x7777n) }, noteHashes: [new Fr(0x4an)], nullifiers: [new Fr(0x99n), new Fr(1n)] }), {
      txHash: hex(0x7777n),
      uniqueNoteHashes: [hex(0x4an)],
      firstNullifier: hex(0x99n),
    });
  });

  // The note is the completion of the request's partial note:
  // [plaintext..., request_id] under rho, its hash the completed note hash
  // over partialCommitment(owner, rho), the hash the round outputs and the
  // log carries; another rho, owner, slot or request id rebuilds another
  // note, which is reported and never delivered.
  test("an outcome rebuilds the completed note under the request's rho, and another rebuild is not delivered", async () => {
    const k = { ...keys, plaintextLength: 2 };
    const found = await new OutcomeReader(node([await logOf(k.outcomeKey, [0n, 24000n])]), contract).read(0x7a7an, k);
    assert.ok(found);
    assert.deepEqual(found.plaintext, [0n, 24000n]);
    assert.deepEqual(found.note.packed, [hex(0n), hex(24000n), hex(0x1dn)]);
    assert.equal(found.note.randomness, hex(0x5eedn));
    const p = await partialCommitment(keys.owner, 0x5eedn);
    assert.equal(found.note.noteHash, hex(await completedNoteHash(keys.storageSlot, p, [0n, 24000n], 0x1dn)));
    assert.equal(found.loggedNoteHash, found.note.noteHash);
    assert.equal(found.noteMatches, true);
    assert.equal(outcomeDeliveryArgs(found).length, 4);
    for (const wrong of [{ rho: 0x5eeen }, { owner: 0xb0bn }, { storageSlot: 0x2bn }, { requestId: 0x1en }]) {
      const n = node([await logOf(k.outcomeKey, [0n, 24000n])]);
      const other = await new OutcomeReader(n, contract).read(0x7a7an, { ...k, ...wrong });
      assert.ok(other);
      // the plaintext still reads; the note is not the logged one
      assert.deepEqual(other.plaintext, [0n, 24000n]);
      assert.equal(other.loggedNoteHash, found.note.noteHash);
      assert.notEqual(other.note.noteHash, found.note.noteHash);
      assert.equal(other.noteMatches, false);
      assert.throws(() => outcomeDeliveryArgs(other), NoteMismatchError);
      const delivered: unknown[] = [];
      assert.ok(await new OutcomeReader(n, contract).readAndDeliver(0x7a7an, { ...k, ...wrong }, async (f) => void delivered.push(f)));
      assert.equal(delivered.length, 0, `${Object.keys(wrong)[0]}: a note that is not the logged one is not delivered`);
    }
  });

  // The compiled utilities: the AMM's deliver_outcome(owner, rho, packed,
  // tx) with its completed note [code, amount_out, request_id] and
  // lending's deliver_outcome(owner, rho, packed, tx) with its completed
  // note [code, position, mask, x, y, payout, leaf_hash, request_id].
  test("the delivery arguments encode as the compiled outcome-note utilities take them", async () => {
    const tx = [0x7777n, 0x4an, ...Array(MAX_NOTE_HASHES_PER_TX - 1).fill(0n), 1n, 0x99n];
    const flat = (contract: "AmmTip" | "LendingTip", fn: string, args: unknown[]) =>
      encodeArguments(contractAbis(contract).functions[fn]!, args).map((f) => f.toBigInt());
    const amm = { ...keys, plaintextLength: 2 };
    const swap = await new OutcomeReader(node([await logOf(amm.outcomeKey, [0n, 24000n])]), contract).read(0x7a7an, amm);
    assert.ok(swap);
    assert.deepEqual(flat("AmmTip", "deliver_outcome", outcomeDeliveryArgs(swap)), [BigInt(swap.note.owner), 0x5eedn, 0n, 24000n, 0x1dn, ...tx]);
    const pt = [0n, 1n, 0n, 1000n, 0n, 0n, 0x1eafn];
    const lending = { ...keys, plaintextLength: pt.length };
    const found = await new OutcomeReader(node([await logOf(lending.outcomeKey, pt)]), contract).read(0x7a7an, lending);
    assert.ok(found);
    assert.deepEqual(flat("LendingTip", "deliver_outcome", outcomeDeliveryArgs(found)), [BigInt(found.note.owner), 0x5eedn, ...pt, 0x1dn, ...tx]);
  });

  // The public completion's partial-note message, from the send result's
  // offchain output to the app's offchain_receive: only the app's messages
  // for the owner, tied to the request's transaction.
  test("offchainReceiveArgs keeps the app's messages for the owner, tied to the transaction", () => {
    const app = AztecAddress.fromBigIntUnsafe(0xa99n);
    const owner = AztecAddress.fromBigIntUnsafe(0x0a11cen);
    const message = (recipient: AztecAddress, contractAddress: AztecAddress) => ({ recipient, payload: [1n, 2n, 3n], contractAddress, anchorBlockTimestamp: 77n });
    const args = offchainReceiveArgs([message(owner, app), message(AztecAddress.fromBigIntUnsafe(0xb0bn), app), message(owner, AztecAddress.fromBigIntUnsafe(0x70c3n))], app, owner, 0x7777n);
    assert.equal(args.length, 1);
    assert.deepEqual(args[0]!.ciphertext.map((f) => f.toBigInt()), [1n, 2n, 3n]);
    assert.equal(args[0]!.recipient.toBigInt(), 0x0a11cen);
    assert.deepEqual([args[0]!.tx_hash._is_some, args[0]!.tx_hash._value.toBigInt(), args[0]!.anchor_block_timestamp], [true, 0x7777n, 77n]);
    // it encodes as the compiled offchain_receive takes it
    const abi = contractAbis("LendingTip").functions.offchain_receive!;
    assert.ok(encodeArguments(abi, [args]).length > 0);
  });

  test("nothing yet: undefined; only logs that do not open: their error", async () => {
    assert.equal(await new OutcomeReader(node([]), contract).read(0x7a7an, keys), undefined);
    await assert.rejects(new OutcomeReader(node([await logOf(0x1111n, [9n, 9n, 9n])]), contract).read(0x7a7an, keys), TagMismatchError);
  });
});
