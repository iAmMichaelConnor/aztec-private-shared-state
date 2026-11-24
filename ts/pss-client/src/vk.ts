// The vk hash of a circuit computed on the developer's machine with bb, before
// any REGISTER: the value the contract pins and the nodes return.

import { execFile } from "node:child_process";
import { mkdirSync, mkdtempSync } from "node:fs";
import { readFile, rm } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

import { vkFieldsFromBbJson, vkHashFromFields } from "./capsule.ts";
import { fieldHex } from "./field.ts";

const run = promisify(execFile);

// Where localVkHash keeps bb's output: a fresh directory under
// TXE_TMP_ROOT (environment variable), default .runs/tmp at the root of this
// repository (gitignored), removed after use; never the system temp
// directory. Moving the root changes where the directory appears and nothing
// else.
function scratchDir(): string {
  const root = process.env.TXE_TMP_ROOT ?? fileURLToPath(new URL("../../../.runs/tmp", import.meta.url));
  mkdirSync(root, { recursive: true });
  return mkdtempSync(join(root, "pss-client."));
}

/** The vk hash of a `vk.json` that `bb write_vk --output_format json` wrote,
 * given as text or parsed JSON: Poseidon2 of its vk fields. When the file
 * carries bb's own `hash`, it must agree. */
export async function vkHashFromBbJson(vkJson: string | { vk: unknown; hash?: unknown }): Promise<string> {
  const json = (typeof vkJson === "string" ? JSON.parse(vkJson) : vkJson) as { vk: unknown; hash?: unknown };
  const hash = fieldHex(await vkHashFromFields(vkFieldsFromBbJson(json)));
  if (json.hash !== undefined && fieldHex(json.hash as string, "vk.json hash") !== hash) {
    throw new RangeError(`vk.json: bb's hash ${String(json.hash)} is not the Poseidon2 hash of its fields (${hash})`);
  }
  return hash;
}

// The vk hash before REGISTER. localVkHash runs
// `bb write_vk --scheme ultra_honk --oracle_hash poseidon2 --output_format json`
// on the nargo output and hashes the vk fields with Poseidon2, so the
// developer can pin the vk hash in the contract (and in this client's
// vkHashes) before the nodes confirm it, then pass it to register() as
// expectVkHash. bb is the `bbBin` argument, else BB_BIN (environment
// variable), else `bb` on PATH; the flags above are the ones the nodes use
// for bb 6.0.0 UltraHonk with the ZK Poseidon2 transcript the contract
// verifies, so the deployment's pins come from the developer's own toolchain
// rather than from the network's answer. Another bb version or other flags
// give another vk and a hash that no node returns; REGISTER with
// expectVkHash then fails with VkHashMismatchError.
/** Compute a circuit's vk hash locally with bb. `circuitJsonPath` is the
 * nargo output JSON (ACIR bytecode plus ABI). */
export async function localVkHash(circuitJsonPath: string, bbBin: string = process.env.BB_BIN ?? "bb"): Promise<string> {
  const dir = scratchDir();
  try {
    try {
      await run(
        bbBin,
        ["write_vk", "--scheme", "ultra_honk", "--oracle_hash", "poseidon2", "--output_format", "json", "-b", circuitJsonPath, "-o", dir],
        { maxBuffer: 16 << 20 },
      );
    } catch (e) {
      const err = e as Error & { stderr?: string };
      throw new Error(`${bbBin} write_vk ${circuitJsonPath}: ${(err.stderr ?? "").trim().split("\n").at(-1) || err.message}`, { cause: e });
    }
    return await vkHashFromBbJson(await readFile(join(dir, "vk.json"), "utf8"));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}
