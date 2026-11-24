// The ABI fixtures against the circuits and contracts they were taken from.
// Each fixture names its source package; when that package's compiled
// artifact is in its target directory and newer than the sources it is built
// from (the package's own and those of every package it reaches through path
// dependencies in this repository), the fixture must equal the artifact in
// every part it keeps, so a fixture left behind by a circuit, contract or
// library change fails here. Without a fresh artifact (nargo compile for a
// circuit; `node --conditions=source ts/test-support/contract-fixture.ts
// build` for the contracts) the comparison is skipped and says why, unless
// FIXTURES_REQUIRE_BUILT=1: then it fails. CI's abi-fixtures job sets it,
// with every circuit compiled by the noir-circuits shards and the contracts
// built.
//
// A circuit fixture is the compiled JSON's `noir_version` and `abi`; it and
// a contract fixture are written from their builds by test-support's
// contract-fixture.ts.

import assert from "node:assert/strict";
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { join, relative, resolve, sep } from "node:path";
import { describe, test } from "node:test";

import { loadContractArtifact } from "@aztec-labs/stdlib/abi";

import {
  CIRCUITS,
  CONTRACTS,
  FUNCTION_KEYS,
  REPO as repo,
  allFunctions,
  builtCircuit,
  builtFile,
  fixture,
  keptLayout,
  type CircuitFixture,
  type ContractFixture,
} from "@aztec-pss/test-support";


/** The newest modification time of a package's Nargo.toml and src/ files,
 * and of every package it reaches through path dependencies in this
 * repository (deps/, the pinned Aztec and total-noir checkouts, left out). */
function newestSource(dir: string, seen = new Set<string>()): number {
  if (seen.has(dir)) return 0;
  seen.add(dir);
  const toml = join(dir, "Nargo.toml");
  let newest = statSync(toml).mtimeMs;
  const walk = (d: string) => {
    for (const e of readdirSync(d, { withFileTypes: true })) {
      const p = join(d, e.name);
      if (e.isDirectory()) walk(p);
      else newest = Math.max(newest, statSync(p).mtimeMs);
    }
  };
  walk(join(dir, "src"));
  for (const [, path] of readFileSync(toml, "utf8").matchAll(/\bpath\s*=\s*"([^"]+)"/g)) {
    const dep = resolve(dir, path!);
    const rel = relative(repo, dep);
    if (rel.startsWith("..") || rel === "deps" || rel.startsWith(`deps${sep}`)) continue;
    newest = Math.max(newest, newestSource(dep, seen));
  }
  return newest;
}

const REQUIRE_BUILT = process.env.FIXTURES_REQUIRE_BUILT === "1";

/** The artifact's path, or why there is none to compare with. */
function artifact(pkg: string, file: string): { path: string } | { skip: string } {
  const path = join(repo, file);
  if (!existsSync(path)) return { skip: `${file} is not built` };
  if (statSync(path).mtimeMs < newestSource(join(repo, pkg))) return { skip: `${file} is older than the sources of ${pkg} or a package it depends on` };
  return { path };
}

/** The test's skip option: the reason there is no artifact, never a skip
 * under FIXTURES_REQUIRE_BUILT=1. */
function skipped(found: { path: string } | { skip: string }): string | false {
  return "skip" in found && !REQUIRE_BUILT ? found.skip : false;
}

/** The artifact's path; fails the test when there is none to compare with. */
function builtPath(found: { path: string } | { skip: string }): string {
  if ("skip" in found) assert.fail(`${found.skip} (FIXTURES_REQUIRE_BUILT=1)`);
  return found.path;
}

describe("ABI fixtures", () => {
  for (const [name, pkg] of Object.entries(CIRCUITS)) {
    const found = artifact(pkg, builtCircuit(pkg));
    test(`${name} is ${pkg} as compiled`, { skip: skipped(found) }, () => {
      const path = builtPath(found);
      const built = JSON.parse(readFileSync(path, "utf8"));
      const kept = fixture(name) as CircuitFixture;
      const stale = `test-support/fixtures/${name} is stale against ${builtCircuit(pkg)}: node --conditions=source ts/test-support/contract-fixture.ts circuits`;
      assert.equal(kept.noir_version, built.noir_version, stale);
      for (const key of Object.keys(kept.abi)) assert.deepEqual(kept.abi[key], built.abi[key], `${stale} (abi.${key})`);
      // the full artifact keeps its program; debug symbols and the hash carry paths
      if ("bytecode" in kept) assert.equal(kept.bytecode, built.bytecode, `${stale} (bytecode)`);
    });
  }

  for (const [name, c] of Object.entries(CONTRACTS)) {
    const { pkg } = c;
    const file = builtFile(c);
    const found = artifact(pkg, file);
    test(`${name} is ${pkg} as compiled`, { skip: skipped(found) }, () => {
      const path = builtPath(found);
      const built = loadContractArtifact(JSON.parse(readFileSync(path, "utf8")));
      const kept = fixture(name) as ContractFixture;
      const stale = `test-support/fixtures/${name} is stale against ${file}`;
      assert.equal(kept.contract, built.name, stale);
      assert.deepEqual(kept.storageLayout, keptLayout(built), `${stale} (storageLayout)`);
      const all = allFunctions(built);
      for (const f of kept.functions) {
        const b = all.find((x) => x.name === f.name);
        assert.ok(b, `${stale}: no function ${String(f.name)}`);
        for (const key of FUNCTION_KEYS) assert.deepEqual(f[key], b[key], `${stale} (${String(f.name)}.${key})`);
      }
    });
  }
});
