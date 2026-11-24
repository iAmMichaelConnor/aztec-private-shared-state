// The e2e driver: one engine that runs any example end to end from its
// manifests (through harness.json and pss-client) and a scenario, a data
// module under scenarios/ (scenarios/README.md). run.sh starts it once per
// scenario named on its command line:
//
//   node --conditions=source --import ../ts/hooks/register.mjs driver.ts <scenario>
//
// What it does, in order:
//   1. checks every step of the scenario against the step registry
//      (steps/index.ts), before anything runs;
//   2. builds the scenario's contracts (nargo compile, then bb aztec_process,
//      into the run directory), evaluates its values, deploys the contracts
//      as their specs say, registers the tip deployments the harness
//      deployed, and the contracts each deployed first, in every wallet
//      and evaluates its namespaces;
//   3. runs the steps, each through the module of its kind with the run
//      context (engine/context.ts);
//   4. checks the node's verification count (one line per accepted
//      transaction, and the node-side negative), records in a tip run the
//      gas and fee of every transaction the steps named (engine/gas.ts) and
//      reports PASS.
import { AztecAddress } from "@aztec-labs/aztec.js/addresses";
import { loadContractArtifact, type ContractArtifact } from "@aztec-labs/stdlib/abi";
import { fieldAddress, fieldHex } from "@aztec-pss/pss-client";

import { readFileSync } from "node:fs";

import { buildSpec, deployContract, type Deployed } from "./engine/contracts.ts";
import { RunContext } from "./engine/context.ts";
import { checkScenario, kindOf } from "./engine/kind.ts";
import { GasLedger, gasReport } from "./engine/gas.ts";
import { Machine } from "./engine/machine.ts";
import { connectNetwork } from "./engine/network.ts";
import { Scope } from "./engine/scope.ts";
import { example, harnessLogger, loadHarness, timed } from "./harness/harness.ts";
import type { Scenario } from "./scenario.ts";
import { registry } from "./steps/index.ts";

const scenarioName = process.argv[2] ?? "";
if (!scenarioName || !/^[a-z0-9_-]+$/.test(scenarioName)) throw new Error("usage: driver.ts <scenario> (a file scenarios/<scenario>.ts)");
const s = ((await import(`./scenarios/${scenarioName}.ts`)) as { scenario: Scenario }).scenario;
checkScenario(registry, s);
const logger = harnessLogger(scenarioName);
const h = loadHarness();
const files = example(h, s.example);

async function main() {
  logger.info(`scenario ${scenarioName}: example ${s.example}, orchestrator ${h.orchestratorUrl}, node ${h.aztecNodeUrl}, real proofs ${h.expectRealProofs}`);
  // The contracts build side by side, each package once.
  const artifacts: ContractArtifact[] = await Promise.all(
    Object.entries(s.contracts).map(([n, c]) =>
      timed(logger, `contract build of ${n} (package ${c.package}; nargo compile, bb aztec_process)`, async () => buildSpec(h, files, scenarioName, c)),
    ),
  );
  const network = await connectNetwork(h, logger, s);
  try {
    if (!h.expectRealProofs) logger.warn("EXPECT_REAL_PROOFS is not 1: nothing is proved client-side, and the client-side tamper negative is skipped");
    const scope = new Scope();
    Object.assign(scope.data.accounts as object, network.accounts);
    for (const [k, e] of Object.entries(s.values ?? {})) scope.set(k, await scope.evaluate(e));

    const contracts: Record<string, Deployed> = {};
    for (const [k, [n, c]] of Object.entries(s.contracts).entries()) {
      const deploy = c.deploy && { initializer: c.deploy.initializer, args: c.deploy.args.map((a) => scope.resolve(a)) };
      const from = network.accounts[c.from] as AztecAddress;
      const deployer = network.walletOf(c.from);
      contracts[n] = await timed(logger, `tx deploy ${n}${deploy ? ` (${deploy.initializer})` : " (no initializer)"}`, async () => deployContract(deployer, artifacts[k]!, from, deploy, await network.fee("deploy")));
      (scope.data.contracts as Record<string, AztecAddress>)[n] = contracts[n].address;
      logger.info(`${n} deployed at ${contracts[n].address}`);
      for (const [w, wallet] of Object.entries(network.wallets)) {
        if (wallet === deployer) continue;
        await wallet.registerContract(contracts[n].instance, contracts[n].artifact);
        logger.info(`${n} registered in wallet ${w}`);
      }
    }
    // The tip deployments: deployed and configured by the harness (harness/tip.ts).
    for (const [n, deployment] of Object.entries(s.tip ?? {})) {
      const d = h.tip?.deployments[deployment];
      if (!d) throw new Error(`tip deployment ${n}: ${deployment} was not deployed; run with E2E_TIP=1 and E2E_TIP_DEPLOYMENTS naming ${Object.values(s.tip!).join(" ")}`);
      const address = fieldAddress(d.address);
      const instance = await network.node.getContract(address);
      if (!instance) throw new Error(`tip deployment ${n}: the node has no contract instance at ${d.address}`);
      const artifact = loadContractArtifact(JSON.parse(readFileSync(d.artifact, "utf8")));
      contracts[n] = { address, artifact, instance };
      for (const wallet of Object.values(network.wallets)) await wallet.registerContract(instance, artifact);
      (scope.data.contracts as Record<string, AztecAddress>)[n] = address;
      (scope.data.namespaces as Record<string, string>)[n] = fieldHex(address.toBigInt());
      logger.info(`tip deployment ${n} (${deployment}): ${d.contract} at ${d.address}, registered in ${Object.keys(network.wallets).join(", ")}`);
      // the contracts it deployed first (its oracle, its tokens), as `<n>.<name>`
      for (const [k, c] of Object.entries(d.contracts ?? {})) {
        const at = fieldAddress(c.address);
        const first = await network.node.getContract(at);
        if (!first) throw new Error(`tip deployment ${n}: the node has no contract instance of ${k} at ${c.address}`);
        const art = loadContractArtifact(JSON.parse(readFileSync(c.artifact, "utf8")));
        contracts[`${n}.${k}`] = { address: at, artifact: art, instance: first };
        for (const wallet of Object.values(network.wallets)) await wallet.registerContract(first, art);
        logger.info(`tip deployment ${n}: ${k} (${c.package}) at ${c.address} registered as ${n}.${k}`);
      }
    }
    for (const [n, e] of Object.entries(s.namespaces)) {
      const value = String(await scope.evaluate(e));
      (scope.data.namespaces as Record<string, string>)[n] = value;
      logger.info(`namespace ${n} = ${value}`);
    }

    const ctx = new RunContext({ name: scenarioName, scenario: s, harness: h, files, logger, scope, machine: new Machine(h, logger, scope), network, contracts });
    await ctx.client(ctx.namespace(undefined)).checkNodes();
    const gas = new GasLedger();
    if (h.tip?.wfj) await gas.addHarness(ctx);
    for (const step of s.steps) {
      const kind = kindOf(registry, step);
      const before = network.sentTxs.size;
      try {
        await kind.run(ctx, step);
      } catch (error) {
        if (step.hint) throw new Error(`${(error as Error).message}; ${step.hint}`, { cause: error });
        throw error;
      }
      if (h.tip?.wfj) await gas.add(ctx, kind.txs?.(ctx, step, [...network.sentTxs.keys()].slice(before)) ?? []);
    }
    network.checks?.finish();
    if (h.tip?.wfj && gas.txs.length) await gasReport(ctx, gas);
    logger.info(`${scenarioName}: PASS`);
  } finally {
    await network.stop();
  }
}

main().catch((err) => {
  logger.error(`${scenarioName}: FAIL: ${err?.stack ?? err}`);
  process.exit(1);
});
