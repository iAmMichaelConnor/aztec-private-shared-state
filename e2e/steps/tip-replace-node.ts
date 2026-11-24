// Node replacement under load (docs/ARCHITECTURE.md section 6, "Node
// replacement and key epochs"; DESIGN.md, "Node replacement"), as
// an operator runs it, with the orchestrator already paused (tipPause):
//
//   1. the departed node's process is stopped (it need not exist);
//   2. the newcomer: a config of the departed party with an empty key
//      directory and an empty store (a new database in the party's Postgres
//      container), `sidecar-node setup --newcomer` (enc and sig keys only);
//   3. `sidecar-node replace-node` on all three at once: the two remaining
//      nodes through their admin sockets, the newcomer directly; each prints
//      its report and one rotate_keys line per contract;
//   4. rotate_keys submitted to every scenario deployment the lines name,
//      and the contract's key epoch read back;
//   5. the newcomer served, the orchestrator's [[nodes]] given the new key
//      set, the orchestrator restarted paused, then resumed (the resume's
//      registry check must pass with the newcomer).
//
// One harness shortcut: the newcomer keeps the departed party's mesh
// certificate and ports, so the remaining nodes need no restart for a new
// mesh pin; a deployment gives the newcomer a certificate of its own and
// restarts them with it. The services the step starts are written to
// $E2E_PIDS/extra, which run.sh's teardown stops.
import { execFileSync, spawn } from "node:child_process";
import { appendFileSync, mkdirSync, openSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { Fr } from "@aztec-labs/aztec.js/fields";
import { assertKeyRotation, readKeyEpoch, sleep } from "@aztec-pss/pss-client";

import { defineKind, refs, type Common } from "../engine/kind.ts";
import { check, until } from "../engine/scope.ts";
import { tipContract, tipOf, methodsOf } from "../engine/tip.ts";
import { timed } from "../harness/harness.ts";
import { orchestratorAdmin } from "./tip-pause.ts";

export interface TipReplaceNodeStep extends Common {
  /** The departed node's index. */
  tipReplaceNode: number;
  /** The scenario's tip deployments whose contracts take the rotation. */
  deployments: string[];
  /** The account that submits the rotations. */
  from: string;
  /** Binds the new key set, node 0 first ([{enc, sig}]). */
  name?: string;
}

interface Point {
  x: string;
  y: string;
}
interface Sig {
  s: [string, string];
  e: [string, string];
}
interface Rotation {
  namespace: string;
  epoch: number;
  keys: { sig: [Point, Point, Point]; enc: [Point, Point, Point] };
  signatures: [Sig | null, Sig | null, Sig | null];
}


function env(name: string): string {
  const v = process.env[name];
  check(v !== undefined && v !== "", `${name} is unset (run.sh exports it)`);
  return v;
}

/** Start a service in the background, its output to `log`, its pid kept for
 * the teardown. */
function service(bin: string, args: string[], log: string): number {
  const fd = openSync(log, "a");
  const child = spawn(bin, args, { detached: true, stdio: ["ignore", fd, fd], env: { ...process.env, RUST_LOG: "info" } });
  child.unref();
  appendFileSync(join(env("E2E_PIDS"), "extra"), `${child.pid}\n`);
  return child.pid!;
}

function stop(pid: number): void {
  try {
    process.kill(pid, "SIGTERM");
  } catch {
    // gone already
  }
}

function alive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

/** Run one replace-node process; resolves with its stdout. */
function replaceNode(bin: string, config: string, departed: number, newcomer: string, pins: string, log: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const child = spawn(bin, ["replace-node", "--config", config, "--departed", String(departed), "--newcomer", newcomer, "--pins", pins], { env: { ...process.env, RUST_LOG: "info" } });
    let out = "";
    let err = "";
    child.stdout.on("data", (d) => (out += d));
    child.stderr.on("data", (d) => (err += d));
    child.on("close", (code) => {
      writeFileSync(log, `${out}\n---- stderr\n${err}`);
      code === 0 ? resolve(out) : reject(new Error(`replace-node on ${config} exited ${code}: ${err.split("\n").slice(-5).join("\n")}`));
    });
  });
}

const limbs = (s: Sig | null): Fr[] => (s === null ? [0n, 0n, 0n, 0n] : [s.s[0], s.s[1], s.e[0], s.e[1]].map((v) => BigInt(v))).map((v) => new Fr(v));
const point = (p: Point) => ({ x: new Fr(BigInt(p.x)), y: new Fr(BigInt(p.y)) });

export default defineKind<TipReplaceNodeStep>({
  key: "tipReplaceNode",
  check(step, s) {
    check(Number.isInteger(step.tipReplaceNode) && step.tipReplaceNode >= 0 && step.tipReplaceNode < 3, "tipReplaceNode: the departed index, 0, 1 or 2");
    check(Array.isArray(step.deployments) && step.deployments.length > 0, "tipReplaceNode: deployments names the scenario's tip deployments to rotate");
    for (const d of step.deployments) refs.tip(s, d);
    refs.account(s, step.from);
    return { fields: ["tipReplaceNode", "deployments", "from", "name"], binds: [step.name] };
  },
  async run(ctx, step) {
    const i = step.tipReplaceNode;
    const label = step.what ?? `replace node ${i}`;
    const [nodeBin, orchBin, cfg, logs, pids] = ["E2E_NODE_BIN", "E2E_ORCH_BIN", "E2E_CFG", "E2E_LOGS", "E2E_PIDS"].map(env) as [string, string, string, string, string];
    const run = ctx.harness.runDir;
    check(orchestratorAdmin("status").paused, `${label}: the orchestrator is not paused (a tipPause step comes first)`);
    // A contract whose manifest says node_keys fixed (pss_public_contract
    // FixedKeys) has no rotate_keys: a replacement cannot move it, its app is
    // redeployed.
    for (const name of step.deployments) {
      const manifest = JSON.parse(readFileSync(tipOf(ctx, name).d.manifest, "utf8")) as { node_keys: "rotating" | "fixed" };
      assertKeyRotation(manifest, `${label}: ${name}`);
    }

    // 1. the departed node gone
    const departedPid = Number(readFileSync(join(pids, `node${i}`), "utf8").trim());
    stop(departedPid);
    await until(`${label}: node ${i} (pid ${departedPid}) stops`, 60, () => !alive(departedPid));

    // 2. the newcomer's config, store and keys
    const db = `newcomer${i}`;
    execFileSync("docker", ["exec", `${env("E2E_PG_PREFIX")}${i}`, "psql", "-U", "postgres", "-c", `CREATE DATABASE ${db}`], { encoding: "utf8" });
    const keyDir = join(run, "keys", `newcomer${i}`);
    const runDir = join(run, "run", `newcomer${i}`);
    mkdirSync(runDir, { recursive: true });
    const text = readFileSync(join(cfg, `node${i}.toml`), "utf8")
      .replace(/^key_dir = .*$/m, `key_dir = "${keyDir}"`)
      .replace(/^run_dir = .*$/m, `run_dir = "${runDir}"`)
      .replace(/(url = "postgresql:\/\/[^"]*\/)postgres"/, `$1${db}"`);
    const newcomerCfg = join(cfg, `newcomer${i}.toml`);
    writeFileSync(newcomerCfg, text, { mode: 0o600 });
    const printed = execFileSync(nodeBin, ["setup", "--config", newcomerCfg, "--newcomer"], { encoding: "utf8" }).trim().split("\n").at(-1)!;
    const newcomerFile = join(run, "keys", `newcomer${i}.json`);
    writeFileSync(newcomerFile, printed);
    const newcomer = JSON.parse(printed) as { enc: Point; sig: Point };
    const current = ctx.harness.nodeKeys.map((k) => ({ enc: k.enc, sig: k.sig }));
    const pinsFile = join(run, "keys", `pins-before-replace${i}.json`);
    writeFileSync(pinsFile, JSON.stringify({ nodes: current }));
    ctx.logger.info(`${label}: newcomer keys ${JSON.stringify(newcomer)}`);

    // 3. replace-node on all three at once
    const configs = [0, 1, 2].map((j) => (j === i ? newcomerCfg : join(cfg, `node${j}.toml`)));
    const outs = await timed(ctx.logger, `${label}: replace-node on three nodes`, () =>
      Promise.all(configs.map((c, j) => replaceNode(nodeBin, c, i, newcomerFile, pinsFile, join(logs, `replace-node${j}.log`)))),
    );
    const rotations = outs.map((out) =>
      out
        .split("\n")
        .filter((l) => l.startsWith('{"rotate_keys"'))
        .map((l) => (JSON.parse(l) as { rotate_keys: Rotation }).rotate_keys),
    );
    check(JSON.stringify(rotations[0]) === JSON.stringify(rotations[1]) && JSON.stringify(rotations[1]) === JSON.stringify(rotations[2]), `${label}: the three nodes printed different rotations`);
    const report = JSON.parse(outs[(i + 1) % 3]!.split("\n")[0]!) as { refreshed?: { namespaces: number; master: boolean } };
    check(report.refreshed !== undefined && report.refreshed.master, `${label}: node ${(i + 1) % 3} did not refresh its master share: ${JSON.stringify(report.refreshed)}`);

    // 4. the rotations submitted, under the configure kind's gas (a rotation
    // writes the whole key epoch, 22 slots: more than a request's limit)
    const fee = await ctx.network.fee("configure");
    for (const name of step.deployments) {
      const tip = tipOf(ctx, name);
      const r = rotations[0]!.find((x) => BigInt(x.namespace) === BigInt(tip.d.address));
      check(r !== undefined, `${label}: no rotate_keys line names ${name} (${tip.d.address})`);
      check(r.signatures[i] === null && r.signatures.filter((x) => x !== null).length === 2, `${label}: ${name}: the signatures are not the two remaining nodes'`);
      const methods = methodsOf(tipContract(ctx, tip, step.from));
      const keys = { sig: r.keys.sig.map(point), enc: r.keys.enc.map(point) };
      const { receipt } = await timed(ctx.logger, `tx ${label}: rotate_keys of ${name} to epoch ${r.epoch}`, () =>
        methods.rotate_keys!(r.epoch, keys, r.signatures.map(limbs)).send({ ...fee, from: ctx.account(step.from) }),
      );
      const { keyEpoch } = await readKeyEpoch(ctx.network.node, tip.d.address);
      check(keyEpoch.epoch === r.epoch && BigInt(keyEpoch.keys[i]!.sig.x) === BigInt(newcomer.sig.x), `${label}: ${name} stores key epoch ${keyEpoch.epoch} with node ${i}'s sig ${keyEpoch.keys[i]!.sig.x}`);
      ctx.logger.info(`${label}: ${name} at key epoch ${r.epoch} in tx ${receipt.txHash.toString()} (block ${receipt.blockNumber})`);
    }

    // 5. the newcomer served; the orchestrator restarted with the new key set, paused, then resumed
    const newcomerLog = join(logs, `newcomer${i}.log`);
    const pid = service(nodeBin, ["serve", "--config", newcomerCfg], newcomerLog);
    await until(`${label}: the newcomer serves (${newcomerLog})`, 300, () => alive(pid) && readFileSync(newcomerLog, "utf8").includes("node serving"));
    const orchCfg = join(cfg, "orchestrator.toml");
    const blocks = readFileSync(orchCfg, "utf8").split("\n[[nodes]]\n");
    check(blocks.length === 4, `${label}: ${orchCfg} has ${blocks.length - 1} [[nodes]] blocks`);
    const toml = (p: Point) => `{ x = "${p.x}", y = "${p.y}" }`;
    blocks[i + 1] = blocks[i + 1]!.replace(/^enc = .*$/m, `enc = ${toml(newcomer.enc)}`).replace(/^sig = .*$/m, `sig = ${toml(newcomer.sig)}`);
    writeFileSync(orchCfg, blocks.join("\n[[nodes]]\n"));
    const orchPid = Number(readFileSync(join(pids, "orchestrator"), "utf8").trim());
    stop(orchPid);
    await until(`${label}: the orchestrator (pid ${orchPid}) stops`, 60, () => !alive(orchPid));
    const orchLog = join(logs, "orchestrator-after-replace.log");
    const restarted = service(orchBin, ["--config", orchCfg, "--paused"], orchLog);
    writeFileSync(join(pids, "orchestrator"), `${restarted}\n`);
    await until(`${label}: the restarted orchestrator serves (${orchLog})`, 300, () => alive(restarted) && readFileSync(orchLog, "utf8").includes("admin socket bound") && (readFileSync(orchLog, "utf8").match(/orchestrator serving/g) ?? []).length >= 1);
    await sleep(2000);
    const resumed = orchestratorAdmin("resume");
    check(resumed.ok && !resumed.paused, `${label}: resume refused: ${JSON.stringify(resumed)}`);
    const keys = current.map((k, j) => (j === i ? newcomer : k));
    if (step.name) ctx.scope.set(step.name, keys);
    ctx.logger.info(`${label}: the newcomer serves as node ${i}; the orchestrator resumed under the new key set`);
  },
  txs(ctx, step, sent) {
    return sent.map((txHash) => ({ kind: "other" as const, txHash, round: "rotate_keys", deployment: step.deployments[0]! }));
  },
});
