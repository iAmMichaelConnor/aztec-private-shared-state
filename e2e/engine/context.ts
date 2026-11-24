// The run context every step takes: the scope, the run's keys, accounts,
// contracts and namespaces, a pss-client per namespace, the pins REGISTER
// answered per namespace, the network and the machine's side doors.
import type { AztecAddress } from "@aztec-labs/aztec.js/addresses";
import type { Fr } from "@aztec-labs/aztec.js/fields";
import type { Logger } from "@aztec-labs/aztec.js/log";
import { OwnerKey, PssClient, RequesterKey, vkFieldsFromBbJson, type PssClientConfig } from "@aztec-pss/pss-client";

import { readFileSync } from "node:fs";

import { circuitPackage, pssClientConfig, type ExampleFiles, type Harness } from "../harness/harness.ts";
import type { Scenario } from "../scenario.ts";
import type { Deployed } from "./contracts.ts";
import { REQUEST_TIMEOUT_MS, type Machine } from "./machine.ts";
import type { Network } from "./network.ts";
import { check, type Scope } from "./scope.ts";

/** What REGISTER answered in one namespace: the vk hash per registered name,
 * and the namespace's npk_app_hash. Scenarios read them as
 * `$pins.<namespace>.vk.<name>` and `$pins.<namespace>.npk_app_hash`. */
export interface Pins {
  vk: Record<string, string>;
  npk_app_hash?: string;
}

/** A circuit package as REGISTER takes it. */
export interface CircuitPackage {
  circuit: unknown;
  manifest: unknown;
  vkHash: string;
}

export class RunContext {
  /** Every request id a client drew in this run. */
  readonly requestIds = new Set<string>();
  readonly keys: Record<string, OwnerKey | RequesterKey>;
  readonly #clients = new Map<string, PssClient>();

  readonly name: string;
  readonly scenario: Scenario;
  readonly harness: Harness;
  readonly files: ExampleFiles;
  readonly logger: Logger;
  readonly scope: Scope;
  readonly machine: Machine;
  readonly network: Network;
  readonly contracts: Record<string, Deployed>;

  constructor(o: { name: string; scenario: Scenario; harness: Harness; files: ExampleFiles; logger: Logger; scope: Scope; machine: Machine; network: Network; contracts: Record<string, Deployed> }) {
    ({ name: this.name, scenario: this.scenario, harness: this.harness, files: this.files, logger: this.logger, scope: this.scope, machine: this.machine, network: this.network, contracts: this.contracts } = o);
    this.keys = Object.fromEntries(Object.entries(o.scenario.keys).map(([n, kind]) => [n, kind === "owner" ? OwnerKey.generate() : RequesterKey.generate()]));
  }

  /** The namespace a step names, or the scenario's first (a tip
   * deployment's when the scenario names no other). */
  namespace(ns: string | undefined): string {
    const tip = this.scenario.tip ?? {};
    const name = ns ?? [...Object.keys(this.scenario.namespaces), ...Object.keys(tip)][0]!;
    check(name in this.scenario.namespaces || name in tip, `namespace ${name} is not one of the scenario's`);
    return name;
  }

  /** A namespace's field value, as pss-client and the machine take it. */
  nsValue(ns: string): string {
    return (this.scope.data.namespaces as Record<string, string>)[this.namespace(ns)]!;
  }

  pins(ns: string): Pins {
    const all = this.scope.data.pins as Record<string, Pins>;
    return (all[this.namespace(ns)] ??= { vk: {} });
  }

  /** The contract a step names, or the scenario's first (a tip
   * deployment's when the scenario deploys none). */
  contract(name: string | undefined): Deployed {
    const n = name ?? Object.keys(this.contracts)[0]!;
    const c = this.contracts[n];
    check(c !== undefined, `contract ${n} is not one of the scenario's`);
    return c;
  }

  account(name: string): AztecAddress {
    const a = this.network.accounts[name];
    check(a !== undefined, `account ${name} is not one of the scenario's`);
    return a;
  }

  key<K extends OwnerKey | RequesterKey>(name: string): K {
    const k = this.keys[name];
    check(k !== undefined, `key ${name} is not one of the scenario's`);
    return k as K;
  }

  /** The circuit a registered name stands for (an alias's circuit, or itself). */
  original(name: string): string {
    return this.scenario.aliases?.[name] ?? name;
  }

  /** A circuit's package; an alias carries its circuit's files under its own name. */
  pkg(name: string): CircuitPackage {
    const pkg = circuitPackage(this.harness, this.scenario.example, this.original(name));
    return name === this.original(name) ? pkg : { ...pkg, manifest: { ...(pkg.manifest as object), circuit: name } };
  }

  vkFields(name: string): Fr[] {
    return vkFieldsFromBbJson(readFileSync(this.files.circuits[this.original(name)]!.vk, "utf8"));
  }

  /** The client of a namespace (`fresh`: a new one, with no saved bodies). */
  client(ns: string, fresh = false): PssClient {
    const name = this.namespace(ns);
    const kept = this.#clients.get(name);
    if (kept && !fresh) return kept;
    const client = new PssClient(this.#clientConfig(name), { fetch: this.machine.fetch });
    if (!fresh) this.#clients.set(name, client);
    return client;
  }

  /** A namespace's client configuration: a tip deployment's, or the example's. */
  #clientConfig(name: string): PssClientConfig {
    const deployment = this.scenario.tip?.[name];
    const base =
      deployment === undefined
        ? pssClientConfig(this.harness, this.scenario.example, this.nsValue(name))
        : { ...(JSON.parse(readFileSync(this.harness.tip!.deployments[deployment]!.clientConfig, "utf8")) as Omit<PssClientConfig, "contractAddress">), contractAddress: this.nsValue(name) };
    const aliases = Object.keys(this.scenario.aliases ?? {});
    return {
      ...base,
      // a tip deployment's checks follow its contract's key epoch, across a
      // node replacement (pss-client key-epoch.ts)
      ...(deployment !== undefined && { keyEpochNode: this.network.node }),
      timeoutMs: REQUEST_TIMEOUT_MS,
      vkHashes: { ...base.vkHashes, ...Object.fromEntries(aliases.map((a) => [a, this.pkg(a).vkHash])) },
      circuits: { ...base.circuits, ...Object.fromEntries(aliases.map((a) => [a, { circuit: this.pkg(a).circuit, manifest: this.pkg(a).manifest }])) },
    };
  }
}
