// A circuit upgrade of a tip deployment with upgradable circuits
// (pss_public_contract `upgrades`; pss-client upgrades.ts), one action per
// step at its place among the others:
//
// - `register`: the namespace owner (the deployment's owner key) sends the
//   upgraded contract manifest the harness generated (TipDeployment.upgrade)
//   as a manifest message at the namespace's next seq; the nodes answer it
//   like any REGISTER, and the version is then readable by its hash (GET
//   /v1/namespaces/{ns}/manifests/{hash}), the deployed one too. Nothing
//   changes on chain: the contract's pins still name the deployed version.
// - `schedule`: the upgrade authority (`from`, the account the constructor
//   pinned) sends `upgrade_circuits` with the upgraded manifest's circuit
//   pins; the stored pins then carry the change and its time, and the
//   deployed version stays in force until then. Any other sender is refused
//   ("not the upgrade authority").
// - `follow`: the upgraded version is in force on chain (a block at or past
//   the time of change: an `advance: {warp}` step), the client reads that
//   from the contract's pins, fetches the version by its hash and takes its
//   vk hashes (PssClient.adoptManifest), so its next requests bind the new
//   circuits and its result checks pin them.
//
//
// A class upgrade (`upgrades: contract`; the spec's `classUpgrade`, the
// contract's second class built from the same sources) takes the same steps
// with `kind: "contract"`, and two of its own:
//
// - `publishClass`: the operator publishes the second class (the protocol's
//   class registry), which the registry's `update` requires; no instance.
// - `register` and `schedule` with `kind: "contract"`: the contract manifest
//   generated from the second class's artifact (the same circuits, the new
//   class id), and the authority's `upgrade_contract`, which schedules the
//   class change and its pins together.
// - `followClass`: the instance runs the second class on chain (a block at
//   or past the time of change); every wallet of the run registers the
//   instance again with the artifact of the class it runs
//   (followContractClass), so its private calls are proven under that class,
//   and the app's class version utility (the step's `classVersion`,
//   amm-tip's `get_class_version`) answers from the new code.
//
// Binds `name` to {manifestHash, seq} (register), {manifestHash,
// timeOfChange} (schedule), {manifestHash, block, timestamp} (follow),
// {classId} (publishClass) or {classId, version} (followClass).
import {
  OwnerKey,
  classIdOf,
  followContractClass,
  pendingUpgrade,
  readCircuitPins,
  upgradeCircuits,
  upgradeContract,
  type UpgradeContractContract,
  contractManifestHash,
  feeOptions,
  fieldHex,
  type ContractManifest,
  type UpgradeCircuitsContract,
} from "@aztec-pss/pss-client";

import { publishContractClass } from "@aztec-labs/aztec.js/deployment";
import { loadContractArtifact, type ContractArtifact } from "@aztec-labs/stdlib/abi";

import { readFileSync } from "node:fs";

import type { RunContext } from "../engine/context.ts";
import { defineKind, refs, type Common } from "../engine/kind.ts";
import { expectRefused } from "../engine/machine.ts";
import { check, type Expect } from "../engine/scope.ts";
import { methodsOf, tipContract, tipOf, type Tip } from "../engine/tip.ts";
import { timed } from "../harness/harness.ts";

export interface TipUpgradeStep extends Common {
  tipUpgrade: "register" | "schedule" | "follow" | "publishClass" | "followClass";
  /** register and schedule: a circuit upgrade (default) or a class
   * upgrade, `contract` (the second class's contract manifest,
   * `upgrade_contract`). */
  kind?: "circuits" | "contract";
  /** The tip deployment (default: the scenario's first). */
  namespace?: string;
  /** schedule: the sender, the upgrade authority unless `refused`. */
  from?: string;
  /** schedule: expect the call refused with a message holding one of these. */
  refused?: string[];
  /** followClass: the app's utility that answers the class version it runs
   * (amm-tip's `get_class_version()`), bound as `version`. */
  classVersion?: string;
  name?: string;
  expect?: Expect[];
}

const read = <T>(path: string) => JSON.parse(readFileSync(path, "utf8")) as T;

function deployed(tip: Tip): ContractManifest {
  return read<ContractManifest>(tip.d.manifest);
}

function upgraded(tip: Tip, kind: TipUpgradeStep["kind"] = "circuits"): { manifest: ContractManifest; circuits: Record<string, unknown> } {
  const u = kind === "contract" ? tip.d.classUpgrade : tip.d.upgrade;
  check(u !== undefined, `${tip.name}: the deployment has no ${kind === "contract" ? "second class (its e2e/tip spec names no `classUpgrade`)" : "upgraded contract manifest (its e2e/tip spec names no `upgrade`)"}`);
  const manifest = read<ContractManifest>(u.manifest);
  const circuits = Object.fromEntries(manifest.packages.map((p) => [p.circuit, read<unknown>(u.circuits[p.name]!.circuit)]));
  return { manifest, circuits };
}

const hashOf = async (m: ContractManifest) => fieldHex((await contractManifestHash(m)).toBigInt());

async function register(ctx: RunContext, tip: Tip, step: TipUpgradeStep, label: string): Promise<Record<string, unknown>> {
  const client = ctx.client(tip.name);
  check(tip.d.owner !== undefined, `${tip.name}: no owner key (tip.ts deploy did not finish)`);
  const owner = await OwnerKey.load(tip.d.owner);
  const { manifest, circuits } = upgraded(tip, step.kind);
  const seq = await client.nextSeq(tip.d.address);
  const answer = await timed(ctx.logger, `${label}: REGISTER the upgraded contract manifest at seq ${seq}`, () =>
    client.registerManifest({ manifest, circuits, namespace: tip.d.address, seq }, owner),
  );
  const manifestHash = await hashOf(manifest);
  check(answer.manifest_hash === manifestHash && answer.seq === seq, `${label}: answered manifest ${answer.manifest_hash} at seq ${answer.seq}`);
  check(answer.npk_app_hash === tip.d.npkAppHash, `${label}: npk_app_hash ${answer.npk_app_hash}, the deployment's ${tip.d.npkAppHash}`);
  // both versions held: the upgraded one and the one the contract still names
  const before = await hashOf(deployed(tip));
  for (const h of [manifestHash, before]) {
    const r = await client.getManifestVersion(tip.d.address, h);
    check(r.manifest_hash === h, `${label}: GET the version ${h} answered ${r.manifest_hash}`);
  }
  const pins = await readCircuitPins(ctx.network.node, tip.address, manifest);
  check(pins.manifestHash === before, `${label}: the contract's pins name ${pins.manifestHash}, not the deployed version ${before}`);
  ctx.logger.info(`${label}: the upgraded contract manifest ${manifestHash} registered at seq ${seq}; the nodes hold it beside ${before}, which the contract's pins still name`);
  return { manifestHash, seq };
}

async function schedule(ctx: RunContext, tip: Tip, step: TipUpgradeStep, label: string): Promise<Record<string, unknown> | undefined> {
  const from = step.from!;
  const { manifest } = upgraded(tip, step.kind);
  const contract = tipContract(ctx, tip, from);
  const fn = step.kind === "contract" ? "upgrade_contract" : "upgrade_circuits";
  const send = async () => {
    const options = { ...(await feeOptions(ctx.network.feeSetting, "configure")), from: ctx.account(from) };
    return step.kind === "contract"
      ? upgradeContract(contract as unknown as UpgradeContractContract, manifest, options)
      : upgradeCircuits(contract as unknown as UpgradeCircuitsContract, manifest, options);
  };
  if (step.refused) {
    const refusal = await expectRefused(label, step.refused, () => timed(ctx.logger, `tx ${label}: ${fn} from ${from}`, send), {
      accepted: `${fn} from ${from} was accepted`,
      any: true,
    });
    ctx.logger.info(`[refused] ${label}: ${fn} from ${from}: ${refusal.split("\n")[0]}`);
    return undefined;
  }
  check(tip.d.upgradeAuthority === undefined || BigInt(tip.d.upgradeAuthority) === ctx.account(from).toBigInt(), `${label}: ${from} is not the upgrade authority ${tip.d.upgradeAuthority}`);
  await timed(ctx.logger, `tx ${label}: ${fn} from ${from}`, send);
  const manifestHash = await hashOf(manifest);
  const pins = await readCircuitPins(ctx.network.node, tip.address, manifest);
  const pending = pendingUpgrade(pins.stored, pins.timestamp);
  check(pending !== undefined && fieldHex(pending.manifestHash) === manifestHash, `${label}: the stored pins schedule ${pending ? fieldHex(pending.manifestHash) : "nothing"}, not ${manifestHash}`);
  check(pins.manifestHash === (await hashOf(deployed(tip))), `${label}: the version in force moved before its time of change`);
  ctx.logger.info(`${label}: ${manifestHash} scheduled, in force from timestamp ${pending.timeOfChange} (block ${pins.block} is at ${pins.timestamp})`);
  return { manifestHash, timeOfChange: Number(pending.timeOfChange) };
}

async function follow(ctx: RunContext, tip: Tip, label: string): Promise<Record<string, unknown>> {
  const client = ctx.client(tip.name);
  const pins = await readCircuitPins(ctx.network.node, tip.address, deployed(tip));
  const version = await client.getManifestVersion(tip.d.address, pins.manifestHash);
  await client.adoptManifest(version.manifest as ContractManifest);
  ctx.logger.info(`${label}: at block ${pins.block} (timestamp ${pins.timestamp}) the contract's pins name ${pins.manifestHash}; the client takes its vk hashes`);
  return { manifestHash: pins.manifestHash, block: pins.block, timestamp: Number(pins.timestamp) };
}

/** The second class's artifact. */
function secondClass(tip: Tip): ContractArtifact {
  const c = tip.d.classUpgrade;
  check(c !== undefined, `${tip.name}: the deployment has no second class (its e2e/tip spec names no \`classUpgrade\`)`);
  return loadContractArtifact(read(c.artifact));
}

async function publishClass(ctx: RunContext, tip: Tip, label: string): Promise<Record<string, unknown>> {
  const artifact = secondClass(tip);
  const classId = fieldHex(await classIdOf(artifact));
  check(classId === fieldHex(BigInt(tip.d.classUpgrade!.classId)), `${label}: the second class's artifact builds ${classId}, the harness planned ${tip.d.classUpgrade!.classId}`);
  const publish = await publishContractClass(ctx.network.walletOf("operator"), artifact);
  await timed(ctx.logger, `tx ${label}: publish class ${classId}`, async () =>
    publish.send({ ...(await feeOptions(ctx.network.feeSetting, "deploy")), from: ctx.account("operator") }),
  );
  ctx.logger.info(`${label}: the second class ${classId} is published; no instance runs it yet`);
  return { classId };
}

async function followClass(ctx: RunContext, tip: Tip, classVersion: string, label: string): Promise<Record<string, unknown>> {
  const artifacts = [ctx.contract(tip.name).artifact, secondClass(tip)];
  let classId = 0n;
  for (const [name, wallet] of Object.entries(ctx.network.wallets)) {
    const r = await followContractClass(wallet, ctx.network.node, tip.address, artifacts);
    classId = r.classId;
    ctx.logger.info(`${label}: wallet ${name} holds the instance under class ${fieldHex(r.classId)}`);
  }
  const answer = methodsOf(tipContract(ctx, tip, "operator"))[classVersion];
  check(answer !== undefined, `${label}: ${tip.name} has no ${classVersion}`);
  const { result } = await answer().simulate({ from: ctx.account("operator") });
  const version = Number(BigInt(result as bigint));
  ctx.logger.info(`${label}: the instance runs class ${fieldHex(classId)}, whose ${classVersion} answers ${version}`);
  return { classId: fieldHex(classId), version };
}

export default defineKind<TipUpgradeStep>({
  key: "tipUpgrade",
  check(step, s) {
    refs.tip(s, step.namespace);
    check(
      ["register", "schedule", "follow", "publishClass", "followClass"].includes(step.tipUpgrade),
      `tipUpgrade: register, schedule, follow, publishClass or followClass, not ${step.tipUpgrade}`,
    );
    check(step.kind === undefined || ((step.tipUpgrade === "register" || step.tipUpgrade === "schedule") && ["circuits", "contract"].includes(step.kind)), "kind: circuits or contract, on register and schedule only");
    check((step.tipUpgrade === "schedule") === (step.from !== undefined), "the schedule action, and only it, names its sender (from)");
    if (step.from !== undefined) refs.account(s, step.from);
    check(step.refused === undefined || (step.tipUpgrade === "schedule" && step.refused.length > 0 && step.name === undefined), "refused: a schedule's refusal substrings, with no name");
    check((step.tipUpgrade === "followClass") === (step.classVersion !== undefined), "the followClass action, and only it, names the app's class version utility (classVersion)");
    return { fields: ["tipUpgrade", "kind", "namespace", "from", "refused", "classVersion", "name", "expect"], binds: [step.name] };
  },
  async run(ctx, step) {
    const tip = tipOf(ctx, step.namespace);
    const label = step.what ?? `${tip.name} upgrade: ${step.tipUpgrade}`;
    const run = {
      register: () => register(ctx, tip, step, label),
      schedule: () => schedule(ctx, tip, step, label),
      follow: () => follow(ctx, tip, label),
      publishClass: () => publishClass(ctx, tip, label),
      followClass: () => followClass(ctx, tip, step.classVersion!, label),
    }[step.tipUpgrade];
    const bound = await run();
    if (step.name && bound) ctx.scope.set(step.name, bound);
    if (step.expect) ctx.scope.expectAll(label, step.expect);
  },
});
