#!/usr/bin/env node
// pss-manifest: generate a deployment's contract manifest (contract-manifest.ts).
//
//   pss-manifest build --descriptor <file> --example <dir> --artifact <file>
//                      [--circuits <dir>] [--contract <name>=<address> ...]
//                      [--stale-blocks <n>|null] [--out <file>]
//
// --descriptor   the deployment descriptor (examples/<example>/deployments/<deployment>.json)
// --example      the example directory; package <name>'s circuit manifest is <example>/manifests/<name>.json
// --artifact     the compiled contract artifact (aztec compile's JSON); left out for a deployment without a contract
// --circuits     the compiled circuits, <circuits>/<circuit>.json (default $DATA_DIR/circuits, else machine/data/circuits,
//                where scripts/prepare-data.sh writes them); each vk hash is computed with bb (localVkHash, BB_BIN)
// --contract     the address of a contract the descriptor's read_contracts names (repeatable)
// --stale-blocks a stale period in place of the descriptor's
// --out          where to write the manifest (default: standard output)
//
// The manifest hash goes to standard error (standard output when --out is given).
//
//   pss-manifest verify --manifest <file> --artifact <file> --node <url> --address <address>
//                       [--descriptor <file> --example <dir> [--circuits <dir>] [--contract <name>=<address> ...]
//                        [--stale-blocks <n>|null]]
//
// Checks a deployed contract against a contract manifest (verify.ts): the
// instance's current class, the artifact's class and contract.class_id agree;
// every slot and fact the generator derives from the artifact is the
// manifest's; the manifest's hash, package list and vk hashes are the pins
// the contract holds in force. With --descriptor and --example the manifest
// is also generated again and its hash compared (as `build` takes them). One
// line per check; the exit status is 1 when any check fails.

import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { parseArgs } from "node:util";

import { createAztecNodeClient } from "@aztec-labs/aztec.js/node";
import { loadContractArtifact } from "@aztec-labs/stdlib/abi";

import { buildContractManifest, contractManifestHash, type ContractManifest, type Descriptor } from "../contract-manifest.ts";
import type { CircuitPinsNode, ClassFollowNode } from "../upgrades.ts";
import { verifyDeployment } from "../verify.ts";
import { fieldHex } from "../field.ts";
import { localVkHash } from "../vk.ts";

const USAGE =
  "usage: pss-manifest build --descriptor <file> --example <dir> [--artifact <file>] [--circuits <dir>] " +
  "[--contract <name>=<address> ...] [--stale-blocks <n>|null] [--out <file>]\n" +
  "       pss-manifest verify --manifest <file> --artifact <file> --node <url> --address <address> " +
  "[--descriptor <file> --example <dir> [--circuits <dir>] [--contract <name>=<address> ...] [--stale-blocks <n>|null]]";

async function readJson(path: string): Promise<unknown> {
  return JSON.parse(await readFile(path, "utf8")) as unknown;
}

/** The options a manifest is generated from, `build`'s and `verify`'s. */
const GENERATE = {
  descriptor: { type: "string" },
  example: { type: "string" },
  artifact: { type: "string" },
  circuits: { type: "string" },
  contract: { type: "string", multiple: true },
  "stale-blocks": { type: "string" },
} as const;

/** The contract manifest of a deployment, from `build`'s options. */
async function generate(values: {
  descriptor: string;
  example: string;
  artifact?: string;
  circuits?: string;
  contract?: string[];
  "stale-blocks"?: string;
}): Promise<ContractManifest> {
  const descriptor = (await readJson(values.descriptor)) as Descriptor;
  const circuitsDir = values.circuits ?? join(process.env.DATA_DIR ?? "machine/data", "circuits");
  const manifests: Record<string, unknown> = {};
  for (const p of descriptor.packages) manifests[p.name] = await readJson(join(values.example, "manifests", `${p.name}.json`));
  const vkHashes: Record<string, string> = {};
  for (const circuit of new Set(descriptor.packages.map((p) => p.circuit))) {
    vkHashes[circuit] = await localVkHash(join(circuitsDir, `${circuit}.json`));
  }
  const contracts: Record<string, string> = {};
  for (const c of values.contract ?? []) {
    const [name, address] = c.split("=");
    if (!name || !address) throw new Error(`--contract ${c}: expected <name>=<address>`);
    contracts[name] = address;
  }
  const stale = values["stale-blocks"];
  return buildContractManifest({
    descriptor,
    manifests,
    vkHashes,
    ...(values.artifact !== undefined && { artifact: loadContractArtifact((await readJson(values.artifact)) as never) }),
    contracts,
    ...(stale !== undefined && { staleBlocks: stale === "null" ? null : Number(stale) }),
  });
}

async function build(argv: string[]): Promise<void> {
  const { values } = parseArgs({ args: argv, options: { ...GENERATE, out: { type: "string" } }, strict: true });
  const { descriptor, example } = values;
  if (descriptor === undefined || example === undefined) throw new Error(USAGE);
  const manifest = await generate({ ...values, descriptor, example });
  const hash = fieldHex((await contractManifestHash(manifest)).toBigInt());
  const text = JSON.stringify(manifest, null, 2) + "\n";
  if (values.out === undefined) {
    process.stdout.write(text);
    process.stderr.write(`manifest hash ${hash}\n`);
  } else {
    await writeFile(values.out, text);
    process.stdout.write(`${values.out}: manifest hash ${hash}\n`);
  }
}

async function verify(argv: string[]): Promise<void> {
  const { values } = parseArgs({
    args: argv,
    options: { ...GENERATE, manifest: { type: "string" }, node: { type: "string" }, address: { type: "string" } },
    strict: true,
  });
  const { manifest: file, artifact, node: url, address, descriptor, example } = values;
  if (file === undefined || artifact === undefined || url === undefined || address === undefined) throw new Error(USAGE);
  if ((descriptor === undefined) !== (example === undefined)) throw new Error("verify: --descriptor and --example go together");
  const manifest = (await readJson(file)) as ContractManifest;
  const regenerated = descriptor !== undefined && example !== undefined ? await generate({ ...values, descriptor, example }) : undefined;
  const node = createAztecNodeClient(url) as unknown as CircuitPinsNode & ClassFollowNode;
  const lines = await verifyDeployment(node, address, loadContractArtifact((await readJson(artifact)) as never), manifest, regenerated);
  for (const l of lines) process.stdout.write(`${l.ok ? "ok  " : "FAIL"} ${l.check}: ${l.detail}\n`);
  const failed = lines.filter((l) => !l.ok).length;
  process.stdout.write(failed === 0 ? `${file}: every check holds\n` : `${file}: ${failed} check(s) fail\n`);
  if (failed > 0) process.exitCode = 1;
}

const [command, ...rest] = process.argv.slice(2);
(command === "build" ? build(rest) : command === "verify" ? verify(rest) : Promise.reject(new Error(USAGE))).catch((e: unknown) => {
  process.stderr.write(`pss-manifest: ${(e as Error).message}\n`);
  process.exit(1);
});
