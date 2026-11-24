// The configuration file of the package's command-line tools (main.ts,
// rotate-enc-key.ts): one JSON file, read from the path given on the command
// line (relative to the working directory); the relative paths inside it are
// read from the file's own directory. A file that is not JSON is refused
// naming the file, never quoting its content (it may hold the account's
// keys).
//
// The account's keys (configAccount). The documented way is a key file of
// their own, `"account": { "keyFile": "<path>" }`, holding the JSON object
// `{ "secretKey", "signingKey", "salt" }`, which its owner alone may read
// (mode 0600 or tighter, the rule sidecar-node applies to its key files): a
// key file that group or others have access to is refused. The keys may also
// sit inline in the configuration, `"account": { "secretKey", ... }`; that
// file then holds them too, and a warning says so when group or others have
// access to it. `"local-network"` names the local network's public test account.

import { readFileSync, statSync } from "node:fs";
import { dirname, resolve } from "node:path";

import type { RelayerAccount } from "./aztec.ts";

/** A configuration file, read. */
export interface ConfigFile<T> {
  /** The file's absolute path. */
  path: string;
  /** Its content. */
  cfg: T;
  /** A path inside it, resolved against its directory. */
  at(p: string): string;
  /** The text of a file a path inside it names. */
  read(p: string): string;
}

/** Read the configuration file at `path` (`usage` is the refusal when no
 * path is given). The shape is the caller's to check. */
export function readConfigFile<T>(path: string | undefined, usage: string): ConfigFile<T> {
  if (!path) throw new Error(usage);
  const file = resolve(path);
  const dir = dirname(file);
  const at = (p: string) => resolve(dir, p);
  return { path: file, cfg: parseJson(readFileSync(file, "utf8"), file) as T, at, read: (p) => readFileSync(at(p), "utf8") };
}

/** `text` as JSON; a SyntaxError naming `path` alone otherwise (the parser's
 * own message quotes the text). */
export function parseJson(text: string, path: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    throw new SyntaxError(`${path}: not valid JSON`);
  }
}

/** The permission bits of the file at `path`. */
function modeOf(path: string): number {
  return statSync(path).mode & 0o777;
}

/** The account a configuration file names (see the module comment): its
 * `account` as given, or the keys of its `{ keyFile }`. The keys are
 * checked and parsed by relayerAccount. RangeError for a key file that
 * group or others have access to, or a `keyFile` beside other fields. */
export function configAccount(account: unknown, file: Pick<ConfigFile<unknown>, "path" | "at">, log?: { warn(m: string): void }): RelayerAccount {
  if (typeof account !== "object" || account === null) return account as RelayerAccount;
  if (Object.hasOwn(account, "keyFile")) {
    const { keyFile, ...rest } = account as { keyFile: unknown };
    if (typeof keyFile !== "string" || Object.keys(rest).length > 0) throw new RangeError('account: { "keyFile": "<path>" } alone, or the keys inline');
    return readKeyFile(file.at(keyFile));
  }
  if ((modeOf(file.path) & 0o077) !== 0) {
    log?.warn(`${file.path} holds the account's keys and group or others have access to it; move them to a key file of mode 0600 ("account": { "keyFile": ... })`);
  }
  return account as RelayerAccount;
}

/** The keys in the key file at `path`: `{ secretKey, signingKey, salt }`,
 * other fields ignored. RangeError when group or others have access to it. */
function readKeyFile(path: string): RelayerAccount {
  const mode = modeOf(path);
  if ((mode & 0o077) !== 0) throw new RangeError(`account.keyFile ${path}: group or others have access to it (mode 0${mode.toString(8)}); make it the owner's alone (chmod 600)`);
  const keys = parseJson(readFileSync(path, "utf8"), path);
  if (typeof keys !== "object" || keys === null || Array.isArray(keys)) throw new RangeError(`account.keyFile ${path}: not a JSON object`);
  const { secretKey, signingKey, salt } = keys as Record<string, unknown>;
  return { secretKey, signingKey, salt } as RelayerAccount;
}
