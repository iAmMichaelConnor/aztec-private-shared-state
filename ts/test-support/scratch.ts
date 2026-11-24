// Scratch directories for the tests: a fresh directory under TXE_TMP_ROOT
// (environment variable), default .runs/tmp at the repository root
// (gitignored), never the system temp directory. Moving the root changes only
// where the directories appear; it must stay short where a test binds a Unix
// socket below it (107-byte path limit).

import { mkdirSync, mkdtempSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

/** A new scratch directory; the test removes it. */
export function scratchDir(): string {
  const root = process.env.TXE_TMP_ROOT ?? fileURLToPath(new URL("../../.runs/tmp", import.meta.url));
  mkdirSync(root, { recursive: true });
  return mkdtempSync(join(root, "pss-client."));
}
