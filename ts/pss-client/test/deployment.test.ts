// The deployment of a tip app: the package name hashes against the contracts'
// constants, the constructor's pins from the contract manifest, configure's
// arguments from the answer to one manifest message signed by a mock
// registry, both encoded against the compiled tip contracts, and deployTip's
// order (the address over the constructor's pins with the manifest hash and
// the vk hashes, one
// REGISTER of the contract manifest at seq 0, deploy, configure).

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { after, before, beforeEach, describe, test } from "node:test";

import { AztecAddress } from "@aztec-labs/aztec.js/addresses";
import { Fr } from "@aztec-labs/foundation/curves/bn254";
import { encodeArguments, type AbiType } from "@aztec-labs/stdlib/abi";

import {
  OwnerKey,
  ProtocolError,
  PssClient,
  SchnorrKey,
  configureArgs,
  contractManifestHash,
  aztecDeployer,
  deployTip,
  fieldHex,
  packageNameHash,
  staleBlocksOf,
  tipPins,
  type ContractManifest,
  type GrumpkinPoint,
  type ManifestResponse,
  type TipDeployer,
  type TipPinsArgs,
  type Triple,
} from "../src/internal.ts";
import { contractAbis, fixture, MockOrchestrator, MockRegistry } from "@aztec-pss/test-support";

type AbiStruct = Extract<AbiType, { kind: "struct" }>;

const json = (path: string) => JSON.parse(readFileSync(new URL(path, import.meta.url), "utf8")) as unknown;

interface RegistryResult {
  node: number;
  disabled: boolean;
  sig_secret: string;
  sig_pubkey: GrumpkinPoint;
}
const RESULTS = (json("../../../testvectors/registry.json") as { results: RegistryResult[] }).results;
const NODE_SIG = RESULTS.filter((r) => !r.disabled).sort((a, b) => a.node - b.node);
const SIG_KEYS = NODE_SIG.map((r) => r.sig_pubkey) as Triple<GrumpkinPoint>;
const nodeKeys = () => NODE_SIG.map((r) => SchnorrKey.fromHex(r.sig_secret)) as Triple<SchnorrKey>;

const VK_HASH = fieldHex(0x255a24297767ccd4fea94c6bfcc2aec6057adb3433a6fc6d16da2883e2b5a3d6n);
const NPK_APP_HASH = fieldHex(0x1f21c078530872675c230b247bed26ffce80c76ab6eeb360895ca8cbd8b92e16n);
// the compiled circuit every package runs here (the mock builds no vk), with
// the `hash` member nargo writes
const CIRCUIT = { ...(fixture("pss_seed.circuit.json") as object), hash: "7" };
const NS = "0x0d1e2a8f4c3b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1";

/** One package of a test contract manifest: its name, and the listed package
 * it is another intake of. */
type Pkg = string | { name: string; alias_of: string };

/** A tip contract manifest of `example`'s `packages` (each circuit manifest
 * from examples/<example>/manifests, every request key the one state key
 * `key`, every circuit with VK_HASH), for a contract with room for
 * `capacity` packages; made-up slots, as the generator would write them from
 * an artifact. The first package is the init round. */
function tipManifest(example: string, packages: Pkg[], capacity: number, key: string, stale: number | null = 50): ContractManifest {
  const slot = (n: number) => fieldHex(n);
  const entries = packages.map((p) => {
    const name = typeof p === "string" ? p : p.name;
    const alias = typeof p === "string" ? undefined : p.alias_of;
    const manifest = json(`../../../examples/${example}/manifests/${name}.json`) as { state_keys: { reads: number; writes: number } } & Record<string, unknown>;
    return {
      name,
      circuit: alias ?? name,
      ...(alias !== undefined && { alias_of: alias }),
      state_keys: { reads: Array<string>(manifest.state_keys.reads).fill(key), writes: Array<string>(manifest.state_keys.writes).fill(key) },
      manifest,
    };
  });
  return {
    contract_manifest: 1,
    name: example,
    node_keys: "fixed",
    upgrades: "fixed",
    contract: { class_id: slot(0xc1a55), package_capacity: capacity },
    queue: { slot: slot(12), stale_blocks: stale, stale_blocks_slot: slot(1) },
    storage: { configured: slot(11) },
    state_keys: { [key]: slot(16) },
    init: { package: entries[0]!.name, input_slots: [] },
    circuits: Object.fromEntries(entries.map((e) => [e.circuit, { vk_hash: VK_HASH }])),
    packages: entries,
  };
}

const ammManifest = (capacity = 3) => tipManifest("amm-tip", ["amm_init_tip", "amm_swap_tip", { name: "amm_swap_tip_receipt", alias_of: "amm_swap_tip" }], capacity, "pool");
const circuitsOf = (m: ContractManifest) => Object.fromEntries(Object.keys(m.circuits).map((id) => [id, CIRCUIT]));

// The contracts' name constants (examples/*/contract/*/src/app.nr)
const CONTRACT_NAMES: Record<string, string> = {
  amm_init_tip: "0x07daf5e0d19e1533cb9c1abef284c5d232b9abd416302a5d691476f6f8003417",
  amm_swap_tip: "0x26336c8688915c2f234d0850720bf3ec29865920f00866499168adc410ecb917",
  amm_swap_tip_receipt: "0x27ec83f6b4b9db4248a9c820bae7beca3ad15ad69db438fa1b6640a5267c9fda",
  lending_init: "0x225001fa7478ec5fa2e2e2f58d153d7033a5b1d909bf4e664db5cc5cc880c9ac",
  deposit: "0x303abe1bdc8c85c442624bcd062899a710d6902a302148bf0ae4a194423ad67c",
};

describe("the constructor's pins", () => {
  test("each package name hash is the contracts' constant", async () => {
    for (const [name, hash] of Object.entries(CONTRACT_NAMES)) assert.equal((await packageNameHash(name)).toString(), hash, name);
  });

  test("tipPins: the stale period, the sig keys, the manifest hash, the listed packages and their vk hashes padded to the capacity", async () => {
    const pins = await tipPins(ammManifest(3), SIG_KEYS);
    assert.ok(pins.circuits.manifest_hash.equals(await contractManifestHash(ammManifest(3))));
    assert.deepEqual(pins.stale_blocks, { enabled: true, blocks: 50 });
    assert.deepEqual(pins.node_sig_keys.map((k) => fieldHex(k.x.toBigInt())), SIG_KEYS.map((k) => k.x));
    // the alias is not in the contract's list
    assert.deepEqual(pins.circuits.packages.map((p) => p.toString()), [CONTRACT_NAMES.amm_init_tip, CONTRACT_NAMES.amm_swap_tip, Fr.ZERO.toString()]);
    assert.deepEqual(pins.circuits.vk_hashes.map((v) => fieldHex(v.toBigInt())), [VK_HASH, VK_HASH, fieldHex(0)]);
    const zero = ammManifest(3);
    zero.circuits.amm_init_tip = { vk_hash: fieldHex(0) };
    await assert.rejects(tipPins(zero, SIG_KEYS), /vk hash 0/);
  });

  test("the stale period is the contract manifest's; null disables skipping", () => {
    assert.deepEqual(staleBlocksOf(ammManifest()), { enabled: true, blocks: 50 });
    assert.deepEqual(staleBlocksOf(tipManifest("amm-tip", ["amm_init_tip", "amm_swap_tip"], 2, "pool", null)), { enabled: false, blocks: 0 });
    assert.throws(() => staleBlocksOf({ name: "amm" }), /no queue/);
  });

  test("a list that could never be configured is refused", async () => {
    await assert.rejects(tipPins(ammManifest(1), SIG_KEYS), /room for 1/);
    const { queue: _q, ...sidecar } = ammManifest();
    await assert.rejects(tipPins(sidecar as ContractManifest, SIG_KEYS), /not a tip contract manifest/);
  });
});

describe("configure's arguments and deployTip against a mock registry", () => {
  let mock: MockOrchestrator;
  let url: string;
  let registry: MockRegistry;

  before(async () => {
    mock = new MockOrchestrator();
    url = await mock.start();
  });
  after(async () => {
    await mock.stop();
  });
  beforeEach(() => {
    mock.routes.clear();
    mock.prefixes.clear();
    mock.received.length = 0;
    registry = new MockRegistry(nodeKeys(), NPK_APP_HASH);
    registry.install(mock);
  });

  const client = () =>
    new PssClient({
      orchestratorUrl: url,
      allowInsecureHttp: true,
      nodeKeys: [
        { enc: { x: 1, y: 2 }, sig: SIG_KEYS[0] },
        { enc: { x: 5, y: 6 }, sig: SIG_KEYS[1] },
        { enc: { x: 9, y: 10 }, sig: SIG_KEYS[2] },
      ],
      vkHashes: {},
      contractAddress: NS,
      timeoutMs: 2_000,
    });

  const register = (m: ContractManifest, namespace = NS): Promise<ManifestResponse> =>
    client().registerManifest({ manifest: m, circuits: circuitsOf(m), namespace, seq: 0 }, OwnerKey.generate());

  test("configureArgs: npk_app_hash, the answer's seq and its three manifest signatures as limbs", async () => {
    const m = ammManifest(3);
    const answer = await register(m);
    const args = await configureArgs(NS, m, answer, SIG_KEYS);
    assert.equal(fieldHex(args.npk_app_hash.toBigInt()), NPK_APP_HASH);
    assert.equal(args.answer.seq.toBigInt(), 0n);
    assert.equal(args.answer.signatures.length, 3);
    assert.equal(fieldHex(args.answer.signatures[2]![0].toBigInt()), fieldHex(answer.signatures[2].s[0]));
    assert.equal(fieldHex(args.answer.signatures[1]![3].toBigInt()), fieldHex(answer.signatures[1].e[1]));
  });

  test("configureArgs refuses what configure would: another namespace, another contract manifest, another npk_app_hash", async () => {
    const m = ammManifest(3);
    const answer = await register(m);
    await assert.rejects(configureArgs(fieldHex(1), m, answer, SIG_KEYS), /node 0's manifest signature/);
    const other = ammManifest(3);
    other.circuits.amm_swap_tip = { vk_hash: fieldHex(0x77) };
    await assert.rejects(configureArgs(NS, other, answer, SIG_KEYS), (e: unknown) => e instanceof ProtocolError && /manifest hash/.test(e.message));
    await assert.rejects(configureArgs(NS, m, { ...answer, npk_app_hash: fieldHex(7) }, SIG_KEYS), /node 0's manifest signature/);
    const forged = { ...answer, signatures: [answer.signatures[1], answer.signatures[0], answer.signatures[2]] as typeof answer.signatures };
    await assert.rejects(configureArgs(NS, m, forged, SIG_KEYS), /node 0's manifest signature/);
  });

  // The compiled contracts' constructor(config) (AmmTip's with its upgrade
  // authority) and configure(npk_app_hash, answer), each with room for its
  // own package list.
  test("the constructor's pins and configure's arguments encode as both tip contracts take them", async () => {
    const LISTS = {
      AmmTip: { example: "amm-tip", key: "pool", names: ["amm_init_tip", "amm_swap_tip_shared"] },
      LendingTip: { example: "lending-tip", key: "market", names: ["lending_init", "deposit_shared", "borrow_shared", "repay_shared", "view_shared", "liquidate_shared", "scan_shared", "withdraw_shared", "supply_shared", "withdraw_supply_shared", "quote_shared"] },
    } as const;
    for (const [contract, { example, key, names }] of Object.entries(LISTS) as [keyof typeof LISTS, (typeof LISTS)[keyof typeof LISTS]][]) {
      const abis = contractAbis(contract).functions;
      const ctor = abis["constructor" as string]!.parameters[0]!.type as AbiStruct;
      const tipType = ctor.fields.find((f) => f.name === "tip")!.type as AbiStruct;
      const circuitsType = tipType.fields.find((f) => f.name === "circuits")!.type as AbiStruct;
      const capacity = (circuitsType.fields.find((f) => f.name === "packages")!.type as { length: number }).length;
      assert.equal(capacity, names.length, contract);
      const m = tipManifest(example, [...names], capacity, key);
      const pins = await tipPins(m, SIG_KEYS);
      // AmmTip's Config is (tip); LendingTip's (init_liquidity, oracle, collateral, borrowed,
      // deposit: {token, amount, kept}, treasury, t_live, tip)
      const config =
        contract === "AmmTip"
          ? { tip: pins }
          : { tip: pins, oracle: AztecAddress.ZERO, init_liquidity: new Fr(1000n), collateral: AztecAddress.ZERO, borrowed: AztecAddress.ZERO, deposit: { token: AztecAddress.ZERO, amount: 5n, kept: true }, treasury: AztecAddress.fromBigIntUnsafe(0x7ea5n), t_live: 60 };
      const tip = [
        1n,
        50n,
        ...SIG_KEYS.flatMap((k) => [BigInt(k.x), BigInt(k.y)]),
        (await contractManifestHash(m)).toBigInt(),
        ...pins.circuits.packages.map((p) => p.toBigInt()),
        ...names.map(() => BigInt(VK_HASH)),
      ];
      // AmmTip's constructor also takes its upgrade authority, after the Config
      const authority = AztecAddress.fromBigIntUnsafe(0xa07n);
      const ctorArgs = contract === "AmmTip" ? [config, authority] : [config];
      const encodedConfig = encodeArguments(abis["constructor" as string]!, ctorArgs).map((f) => f.toBigInt());
      assert.deepEqual(encodedConfig, contract === "AmmTip" ? [...tip, 0xa07n] : [1000n, 0n, 0n, 0n, 0n, 5n, 1n, 0x7ea5n, 60n, ...tip]);

      // one namespace per contract: the mock registry keeps a namespace's owner
      const ns = contract === "AmmTip" ? NS : fieldHex(0x1e9d);
      const answer = await register(m, ns);
      const args = await configureArgs(ns, m, answer, SIG_KEYS);
      const flat = encodeArguments(abis.configure!, [args.npk_app_hash, args.answer]).map((f) => fieldHex(f.toBigInt()));
      assert.deepEqual(flat, [NPK_APP_HASH, fieldHex(0), ...answer.signatures.flatMap((sig) => [...sig.s, ...sig.e].map((x) => fieldHex(x)))]);
    }
  });

  /** A chain side that records its calls and deploys to NS. */
  function recordingDeployer(calls: string[]): TipDeployer & { pins?: TipPinsArgs; configured?: unknown } {
    const d: TipDeployer & { pins?: TipPinsArgs; configured?: unknown } = {
      async address(_salt, pins) {
        calls.push("address");
        d.pins = pins;
        return NS;
      },
      async deploy() {
        calls.push(`deploy after ${mock.count("POST", "/v1/register")} REGISTER`);
      },
      async configure(args) {
        calls.push("configure");
        d.configured = args;
      },
    };
    return d;
  }

  test("deployTip: the address, one REGISTER of the contract manifest at seq 0, then the deployment, then configure", async () => {
    const calls: string[] = [];
    const deployer = recordingDeployer(calls);
    const salt = new Fr(0x5a17n);
    const m = ammManifest(3);
    const out = await deployTip({ registry: client(), owner: OwnerKey.generate(), manifest: m, circuits: circuitsOf(m), sigKeys: SIG_KEYS, deployer, salt });
    assert.deepEqual(calls, ["address", "deploy after 1 REGISTER", "configure"]);
    const [body] = mock.received.filter((r) => r.path === "/v1/register").map((r) => JSON.parse(r.body) as { seq: number; namespace: string; manifest: unknown; circuits: Record<string, Record<string, unknown>> });
    assert.deepEqual([body!.seq, body!.namespace], [0, NS]);
    assert.deepEqual(body!.manifest, m);
    // each circuit once, stripped
    assert.deepEqual(Object.keys(body!.circuits).sort(), ["amm_init_tip", "amm_swap_tip"]);
    assert.deepEqual(Object.keys(body!.circuits.amm_swap_tip!).sort(), ["abi", "bytecode", "debug_symbols", "file_map", "hash", "noir_version"]);
    assert.equal(out.address, NS);
    assert.ok(out.salt.equals(salt));
    assert.equal(out.answer.seq, 0);
    assert.equal(deployer.configured, out.configure);
    assert.deepEqual(deployer.pins, out.pins);
    assert.deepEqual(out.pins.circuits.vk_hashes.map((v) => fieldHex(v.toBigInt())), [VK_HASH, VK_HASH, fieldHex(0)]);
  });

  // aztecDeployer: one universally deployed Contract.deploy of the artifact
  // with `[{ tip: pins }]` under the drawn salt, for the address and for the
  // deployment, then configure on the deployed contract, each from the
  // operator under its fee kind.
  test("deployTip over aztecDeployer: the address and the deployment from one deploy method, then configure", async () => {
    const seen: { args: unknown[]; ctor: string; opts: { salt: Fr; universalDeploy: boolean } }[] = [];
    const sends: { what: string; from: unknown; fee: unknown }[] = [];
    let configured: unknown[] = [];
    const fake = {
      methods: {
        configure: (...a: unknown[]) => ({
          send: async (o: { from: unknown; fee: unknown }) => {
            configured = a;
            sends.push({ what: "configure", from: o.from, fee: o.fee });
          },
        }),
      },
    };
    const contracts = {
      deploy: (_wallet: unknown, _artifact: unknown, args: unknown[], ctor: string, opts: { salt: Fr; universalDeploy: boolean }) => {
        seen.push({ args, ctor, opts });
        return {
          getInstance: async () => ({ address: { toBigInt: () => BigInt(NS) } }),
          send: async (o: { from: unknown; fee: unknown }) => {
            sends.push({ what: "deploy", from: o.from, fee: o.fee });
            return { contract: fake };
          },
        };
      },
    };
    const operator = { toString: () => "operator" };
    const deployer = aztecDeployer({ wallet: {} as never, artifact: {} as never, from: operator as never, contracts: contracts as never });
    assert.throws(() => deployer.contract(), /not deployed yet/);
    const salt = new Fr(0x5a17n);
    const m = ammManifest(3);
    const out = await deployTip({ registry: client(), owner: OwnerKey.generate(), manifest: m, circuits: circuitsOf(m), sigKeys: SIG_KEYS, deployer, salt });
    assert.equal(out.address, NS);
    assert.equal(seen.length, 2);
    for (const s of seen) {
      assert.deepEqual(s.args, [{ tip: out.pins }]);
      assert.equal(s.ctor, "constructor");
      assert.ok(s.opts.salt.equals(salt));
      assert.equal(s.opts.universalDeploy, true);
    }
    assert.deepEqual(sends.map((s) => [s.what, s.from]), [["deploy", operator], ["configure", operator]]);
    assert.ok(sends.every((s) => s.fee !== undefined));
    assert.deepEqual(configured, [out.configure.npk_app_hash, out.configure.answer]);
    assert.equal(deployer.contract(), fake);
  });

  test("deployTip refuses an answer for another contract manifest, before the deployment", async () => {
    const calls: string[] = [];
    mock.on("POST", "/v1/register", async (r) => {
      const reply = await registry.register(r.body);
      return "body" in reply ? { ...reply, body: { ...(reply.body as object), packages_hash: fieldHex(0x77) } } : reply;
    });
    const m = ammManifest(3);
    await assert.rejects(
      deployTip({ registry: client(), owner: OwnerKey.generate(), manifest: m, circuits: circuitsOf(m), sigKeys: SIG_KEYS, deployer: recordingDeployer(calls) }),
      /packages hash/,
    );
    assert.deepEqual(calls, ["address"]);
  });

  test("deployTip refuses a namespace that already has a registration, before any REGISTER or deployment", async () => {
    await register(tipManifest("amm-tip", ["amm_init_tip", "amm_swap_tip"], 2, "pool"));
    mock.received.length = 0;
    const calls: string[] = [];
    const m = ammManifest(3);
    await assert.rejects(
      deployTip({ registry: client(), owner: OwnerKey.generate(), manifest: m, circuits: circuitsOf(m), sigKeys: SIG_KEYS, deployer: recordingDeployer(calls) }),
      (e: unknown) => e instanceof ProtocolError && /draw a new salt/.test(e.message),
    );
    assert.deepEqual(calls, ["address"]);
    assert.equal(mock.count("POST", "/v1/register"), 0);
  });
});
