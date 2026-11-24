// REGISTER one contract manifest in a namespace (the manifest message), or
// require it refused.
import { buildContractManifest, vkHashFromFields, type ContractManifest, type OwnerKey } from "@aztec-pss/pss-client";

import type { RunContext } from "../engine/context.ts";
import { defineKind, refs, type Common } from "../engine/kind.ts";
import type { Refusal } from "../engine/machine.ts";
import { check } from "../engine/scope.ts";
import { timed } from "../harness/harness.ts";

/** REGISTER the contract manifest of the packages `register` (each named
 * after its circuit, or an alias of the scenario's), on the sidecar path, at
 * `seq` (default 0). The same list again at the next seq is the same contract
 * manifest, which re-enables every package a DISABLE stopped. */
export interface RegisterStep extends Common {
  register: string[];
  seq?: number;
  /** The owner key (default `owner`). */
  by?: string;
  /** One of the scenario's namespaces (default: its first). */
  namespace?: string;
  /** Expect the REGISTER refused; the namespace's seq must not move. */
  refused?: Refusal;
}

/** The sidecar-path contract manifest of `names` in namespace `ns`: one
 * package per name on its circuit (an alias on its original's), the vk
 * hashes bb computed. Deterministic, so the same list gives the same
 * manifest hash. */
async function manifestOf(ctx: RunContext, ns: string, names: string[]): Promise<{ manifest: ContractManifest; circuits: Record<string, unknown> }> {
  const manifest = await buildContractManifest({
    descriptor: { descriptor: 1, name: `${ctx.scenario.example}-${ns}`, packages: names.map((n) => ({ name: n, circuit: ctx.original(n) })) },
    manifests: Object.fromEntries(names.map((n) => [n, ctx.pkg(n).manifest])),
    vkHashes: Object.fromEntries(names.map((n) => [ctx.original(n), ctx.pkg(n).vkHash])),
  });
  return { manifest, circuits: Object.fromEntries(names.map((n) => [ctx.original(n), ctx.pkg(n).circuit])) };
}

export default defineKind<RegisterStep>({
  key: "register",
  check(step, s) {
    check(step.register.length > 0, "register names no package");
    check(new Set(step.register).size === step.register.length, "register names a package twice");
    refs.key(s, step.by ?? "owner", "owner");
    refs.namespace(s, step.namespace);
    return { fields: ["register", "seq", "by", "namespace", "refused"] };
  },
  async run(ctx, step) {
    const ns = ctx.namespace(step.namespace);
    const client = ctx.client(ns);
    const owner = ctx.key<OwnerKey>(step.by ?? "owner");
    const seq = step.seq ?? 0;
    const input = { ...(await manifestOf(ctx, ns, step.register)), seq };
    const what = `REGISTER ${step.register.join(", ")} (seq ${seq}) in namespace ${ns}`;
    if (step.refused) {
      const before = (await client.getNamespace(ctx.nsValue(ns)))?.seq;
      await ctx.machine.expectRefusal(step.what ?? what, step.refused, () => client.registerManifest(input, owner));
      check((await client.getNamespace(ctx.nsValue(ns)))?.seq === before, "the refused REGISTER moved the namespace's seq");
      return;
    }
    for (const name of step.register) {
      check((await vkHashFromFields(ctx.vkFields(name))).toString() === ctx.pkg(name).vkHash, `${name}: poseidon2 of the vk.json fields is not bb's vk hash`);
    }
    // registerManifest checks the manifest hash, the packages hash and every
    // node signature; the nodes refuse a vk hash that is not the circuit's
    const answer = await timed(ctx.logger, what, () => client.registerManifest(input, owner));
    check(answer.seq === seq, `${what}: answered seq ${answer.seq}`);
    check(BigInt(answer.npk_app_hash) !== 0n, `${what}: npk_app_hash 0`);
    const pins = ctx.pins(ns);
    pins.npk_app_hash ??= answer.npk_app_hash;
    check(answer.npk_app_hash === pins.npk_app_hash, `${what}: npk_app_hash ${answer.npk_app_hash}, namespace ${ns}'s ${pins.npk_app_hash}`);
    for (const p of input.manifest.packages) pins.vk[p.name] = input.manifest.circuits[p.circuit]!.vk_hash;
    const info = await client.getNamespace(ctx.nsValue(ns));
    check(info?.seq === seq && info.npk_app_hash === answer.npk_app_hash && info.manifest_hash === answer.manifest_hash, `GET /v1/namespaces: ${JSON.stringify(info)}`);
    ctx.logger.info(`${what}: contract manifest ${answer.manifest_hash}, ${input.manifest.packages.length} package(s) at bb's vk hashes, npk_app_hash ${answer.npk_app_hash}, every node signature verified`);
  },
});
