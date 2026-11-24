// The command-line tools' configuration file (src/config-file.ts): the file
// read from the path given, relative to the working directory, and the paths
// inside it from its own directory; a file that is not JSON refused without
// quoting it; the account's keys from a key file its owner alone may read,
// or inline with a warning when the configuration is readable by others.

import assert from "node:assert/strict";
import { chmodSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { join, relative } from "node:path";
import { after, describe, test } from "node:test";

import { scratchDir } from "@aztec-pss/test-support";

import { relayerAccount } from "../src/aztec.ts";
import { configAccount, readConfigFile } from "../src/config-file.ts";

const dir = scratchDir();
after(() => rmSync(dir, { recursive: true, force: true }));

describe("the configuration file", () => {
  test("a relative path is the working directory's; the paths inside it are the file's directory's", () => {
    mkdirSync(join(dir, "conf"));
    writeFileSync(join(dir, "conf", "relayer.json"), JSON.stringify({ artifact: "app.json" }));
    writeFileSync(join(dir, "conf", "app.json"), "the artifact");
    const path = relative(process.cwd(), join(dir, "conf", "relayer.json"));
    assert.ok(path.includes("/conf/relayer.json"));
    const file = readConfigFile<{ artifact: string }>(path, "usage");
    assert.equal(file.path, join(dir, "conf", "relayer.json"));
    assert.equal(file.read(file.cfg.artifact), "the artifact");
    assert.equal(file.at("app.json"), join(dir, "conf", "app.json"));
  });

  test("no path is the usage; a file that is not JSON is named, not quoted", () => {
    assert.throws(() => readConfigFile(undefined, "usage: main.ts <relayer.json>"), /^Error: usage: main\.ts/);
    const bad = join(dir, "bad.json");
    writeFileSync(bad, '{ "account": { "secretKey": "0x1a2b3c4d' );
    assert.throws(
      () => readConfigFile(bad, "usage"),
      (e: unknown) => e instanceof SyntaxError && e.message === `${bad}: not valid JSON` && !String((e as Error).stack).includes("1a2b3c4d"),
    );
  });
});

describe("the account's keys", () => {
  const KEYS = { secretKey: "0x1234", signingKey: "0x5678", salt: "0x9a" };
  /** A configuration file in its own directory naming `account`, at `mode`. */
  const config = (name: string, account: unknown, mode = 0o600) => {
    mkdirSync(join(dir, name));
    const path = join(dir, name, "rotate.json");
    writeFileSync(path, JSON.stringify({ account }), { mode });
    chmodSync(path, mode);
    return readConfigFile<{ account: unknown }>(path, "usage");
  };
  const warnings = () => {
    const lines: string[] = [];
    return { lines, warn: (m: string) => void lines.push(m) };
  };

  test("a key file beside the configuration, its owner's alone", () => {
    const file = config("keyfile", { keyFile: "keys/relayer.keys" }, 0o644);
    mkdirSync(join(dir, "keyfile", "keys"));
    const keys = join(dir, "keyfile", "keys", "relayer.keys");
    writeFileSync(keys, JSON.stringify({ ...KEYS, address: "0xabc" }), { mode: 0o600 });
    const log = warnings();
    const k = relayerAccount(configAccount(file.cfg.account, file, log));
    assert.ok(k !== "local-network");
    assert.deepEqual([k.secretKey.toBigInt(), k.signingKey.toBigInt(), k.salt.toBigInt()], [0x1234n, 0x5678n, 0x9an]);
    assert.deepEqual(log.lines, []);
    for (const mode of [0o640, 0o604, 0o660]) {
      chmodSync(keys, mode);
      assert.throws(() => configAccount(file.cfg.account, file), new RegExp(`group or others have access to it \\(mode 0${mode.toString(8)}\\); .*chmod 600`));
    }
  });

  test("a key file that is not JSON is named, not quoted; keyFile stands alone", () => {
    const file = config("badkeys", { keyFile: "relayer.keys" });
    writeFileSync(join(dir, "badkeys", "relayer.keys"), '{ "signingKey": 1a2b3c4d5e }', { mode: 0o600 });
    assert.throws(() => configAccount(file.cfg.account, file), (e: unknown) => e instanceof SyntaxError && /relayer\.keys: not valid JSON$/.test(e.message) && !String(e.stack).includes("1a2b3c4d5e"));
    assert.throws(() => configAccount({ keyFile: "relayer.keys", salt: "0x1" }, file), /alone, or the keys inline/);
  });

  test("inline keys are read; a configuration others may read draws a warning", () => {
    const shared = config("inline", KEYS, 0o644);
    const log = warnings();
    assert.deepEqual(configAccount(shared.cfg.account, shared, log), KEYS);
    assert.match(log.lines[0]!, /holds the account's keys and group or others have access to it/);
    const own = config("inline-own", KEYS);
    const quiet = warnings();
    assert.deepEqual(configAccount(own.cfg.account, own, quiet), KEYS);
    assert.equal(configAccount("local-network", own, quiet), "local-network");
    assert.deepEqual(quiet.lines, []);
  });
});
