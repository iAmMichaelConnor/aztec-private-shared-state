// Writes the run's harness.json and one ready pss-client configuration per
// example, from what run.sh prepared: the compiled circuits and the CRS in
// <run>/data, the vk.json files in <run>/vks, and the node keys `sidecar-node
// setup` printed. run.sh calls it once, after setup and before any service
// is used:
//
//   node harness/prepare.ts <example dir> ...
//
// Environment (run.sh sets every one): E2E_RUN_DIR, REPO_ROOT, DATA_DIR,
// VK_DIR, NODE_KEYS (a JSON file: the three setup lines, node 0 first),
// ORCHESTRATOR_URL, CA_CERT, AZTEC_NODE_URL, NETWORK_LOG, EXPECT_REAL_PROOFS,
// BB_BIN, CONTRACT_NARGO_BIN.
import { vkHashFromBbJson, type PssClientConfig } from "@aztec-pss/pss-client";

import { copyFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { basename, join, resolve } from "node:path";

import type { ExampleFiles, Harness } from "./harness.ts";

function env(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is not set (run.sh sets it)`);
  return value;
}

const runDir = env("E2E_RUN_DIR");
const dataDir = env("DATA_DIR");
const vkDir = env("VK_DIR");
const examples = process.argv.slice(2);
if (examples.length === 0) throw new Error("usage: prepare.ts <example dir> ...");

// The three setup lines, node 0 first: {"party": i, "enc": {x, y}, "sig": {x, y}}.
const setup = JSON.parse(readFileSync(env("NODE_KEYS"), "utf8")) as { party: number; enc: { x: string; y: string }; sig: { x: string; y: string } }[];
if (setup.length !== 3 || setup.some((k, i) => k.party !== i)) {
  throw new Error(`NODE_KEYS must hold the three setup lines, node 0 first; got parties ${setup.map((k) => k.party)}`);
}
const nodeKeys = setup.map(({ enc, sig }) => ({ enc, sig })) as Harness["nodeKeys"];

/** The circuit names of an example's circuits.env (CIRCUITS="a b c"). */
function exampleCircuits(dir: string): string[] {
  const text = readFileSync(join(dir, "circuits", "circuits.env"), "utf8");
  const match = /^CIRCUITS="([^"]*)"/m.exec(text);
  if (!match) throw new Error(`${dir}/circuits/circuits.env names no CIRCUITS`);
  return (match[1] ?? "").split(/\s+/).filter(Boolean);
}

const harness: Harness = {
  runDir,
  repoRoot: env("REPO_ROOT"),
  aztecNodeUrl: env("AZTEC_NODE_URL"),
  networkLog: env("NETWORK_LOG"),
  expectRealProofs: env("EXPECT_REAL_PROOFS") === "1",
  orchestratorUrl: env("ORCHESTRATOR_URL"),
  caCert: env("CA_CERT"),
  bbBin: env("BB_BIN"),
  contractNargoBin: env("CONTRACT_NARGO_BIN"),
  nodeKeys,
  examples: {},
};

mkdirSync(join(runDir, "pss-client"), { recursive: true });
for (const exampleDir of examples.map((d) => resolve(d))) {
  const name = basename(exampleDir);
  const files: ExampleFiles = { dir: exampleDir, clientConfig: join(runDir, "pss-client", `${name}.json`), circuits: {} };
  const config: Omit<PssClientConfig, "contractAddress"> = {
    orchestratorUrl: harness.orchestratorUrl,
    nodeKeys,
    vkHashes: {},
    circuits: {},
  };
  mkdirSync(join(runDir, "manifests", name), { recursive: true });
  for (const circuit of exampleCircuits(exampleDir)) {
    const vk = join(vkDir, `${circuit}.vk.json`);
    const vkHash = await vkHashFromBbJson(readFileSync(vk, "utf8"));
    const circuitPath = join(dataDir, "circuits", `${circuit}.json`);
    const own = join(exampleDir, "manifests", `${circuit}.json`);
    if (!existsSync(own)) {
      // a replacement circuit: an upgraded contract manifest registers it
      // under another package's name and manifest
      (files.replacements ??= {})[circuit] = { circuit: circuitPath, vk, vkHash };
      continue;
    }
    const manifest = join(runDir, "manifests", name, `${circuit}.json`);
    copyFileSync(own, manifest);
    files.circuits[circuit] = { circuit: circuitPath, manifest, vk, vkHash };
    config.vkHashes[circuit] = vkHash;
    config.circuits![circuit] = {
      circuit: JSON.parse(readFileSync(circuitPath, "utf8")),
      manifest: JSON.parse(readFileSync(manifest, "utf8")),
    };
  }
  writeFileSync(files.clientConfig, JSON.stringify(config) + "\n");
  harness.examples[name] = files;
  const replacements = Object.keys(files.replacements ?? {});
  console.log(`${name}: ${Object.keys(files.circuits).join(", ")}${replacements.length ? ` (replacements: ${replacements.join(", ")})` : ""} -> ${files.clientConfig}`);
}
writeFileSync(join(runDir, "harness.json"), JSON.stringify(harness, null, 2) + "\n");
console.log(`harness: ${join(runDir, "harness.json")}`);
