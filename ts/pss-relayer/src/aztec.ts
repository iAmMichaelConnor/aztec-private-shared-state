// The relayer on an Aztec network: an aztec.js node client, an embedded
// wallet (PXE) with the relayer's account, the app's fee setting (wFJ by
// default, pss-client fee.ts), the app contract, a NodeQueueReader over its
// queue and,
// for an app with an init round, the init's slots read from the node.
// createAztecRelayer is what main.ts runs; test/local-network.ts embeds it
// the same way.

import { AztecAddress } from "@aztec-labs/aztec.js/addresses";
import { Contract } from "@aztec-labs/aztec.js/contracts";
import { Fr } from "@aztec-labs/aztec.js/fields";
import { createAztecNodeClient, type AztecNode } from "@aztec-labs/aztec.js/node";
import type { Fq } from "@aztec-labs/foundation/curves/bn254";
import { getPXEConfig } from "@aztec-labs/pxe/server";
import type { ContractArtifact } from "@aztec-labs/stdlib/abi";
import { EmbeddedWallet } from "@aztec-labs/wallets/embedded";
import { registerInitialLocalNetworkAccountsInWallet } from "@aztec-labs/wallets/testing";
import {
  DEFAULT_FEE_SETTING,
  NodeQueueReader,
  PssClient,
  fieldAddress,
  fieldFq,
  fieldFr,
  fieldHex,
  followContractClass,
  registerWfj,
  queueBaseSlot,
  txSendOptions,
  type FeeSetting,
  type FieldLike,
  type ProcessResultEncoder,
  type PssClientConfig,
  type PssClientOptions,
  type ResultContract,
  resultFunctions,
  type ResultFunction,
} from "@aztec-pss/pss-client";

import { DEFAULT_RELAYER_POLL_INTERVAL_MS, Relayer, type RelayerLog, type RelayerOptions } from "./relayer.ts";

// Operator knob: DESIGN.md, "Configuration reference" (pss-relayer account).
// Required, no default: an initializerless Schnorr account from the
// operator's secret key, signing key and salt, or "local-network", the local
// network's first genesis-funded test account, whose keys are public (a
// local network only, and only when named). The three keys are read by
// pss-client's field parsers (fieldFr, fieldFq for the signing key, a
// Grumpkin scalar): a string is hex with or without `0x`, and a refusal names
// the key, never its value. The command-line tools also take the keys from a
// key file of their own (config-file.ts configAccount).
export type RelayerAccount = "local-network" | { secretKey: FieldLike; signingKey: FieldLike | Fq; salt?: FieldLike };

/** An account's keys, parsed. */
export interface RelayerKeys {
  secretKey: Fr;
  /** A Grumpkin scalar, which may exceed the BN254 scalar field. */
  signingKey: Fq;
  salt: Fr;
}

/** The relayer's fee: pss-client's fee setting (its DEV DECISION says what
 * each method reveals), or a function that builds one in the relayer's
 * wallet (pss-client sponsoredFeeSetting). */
export type RelayerFee = FeeSetting | ((wallet: EmbeddedWallet) => Promise<FeeSetting>);

export interface AztecRelayerConfig {
  /** The Aztec node's JSON-RPC URL. */
  aztecNodeUrl: string;
  /** The pss-client configuration: orchestrator URL, pinned node keys, vk
   * hashes and the tip circuits (with their registered manifests, whose
   * `stale_blocks` the relayer skips by) the queue serves. */
  client: PssClientConfig;
  clientOptions?: PssClientOptions;
  /** The app contract and its aztec.js artifact. */
  contract: RelayerContract & { queueField?: string };
  /** Under `upgrades: contract`, the artifacts of the classes the app may
   * move to: the relayer registers the instance again with the artifact of
   * the class it runs whenever that changes (followContractClass, checked
   * once per poll), so its result transactions are proven under the class
   * in force. */
  upgradeArtifacts?: readonly ContractArtifact[];
  /** The 115 vk fields of each circuit, by name (the init circuit's among
   * them). */
  vkFields: Record<string, readonly FieldLike[]>;
  /** The app's init round, which the relayer lands once the scheduler has
   * computed it: the init circuit (a configured client circuit), its inputs
   * (the constants the app's Config pins, in the circuit's input order;
   * default none) and the app's init function (examples/amm-tip
   * `init_pool`, examples/lending-tip `init_market`). */
  init?: { circuit: string; method: string; inputs?: readonly FieldLike[] };
  /** The account the relayer's transactions are sent from (RelayerAccount). */
  account: RelayerAccount;
  /** The fee setting its result (and init) and skip transactions pay
   * under, the app's (the gas of its `result` and `skip` kinds); default
   * DEFAULT_FEE_SETTING, wFJ from the relayer's own private balance, which
   * must be funded before it starts (createAztecRelayer refuses an empty
   * one). */
  fee?: RelayerFee;
  /** Whether the PXE proves transactions (real proofs); default true. */
  proverEnabled?: boolean;
  encode?: ProcessResultEncoder;
  /** The result function of each circuit whose results do not land through
   * `process_result`, by circuit name (resultFunctions): a configured client
   * circuit each, a function of the artifact each, with the arguments it
   * takes before the library's. */
  methods?: Readonly<Record<string, ResultFunction>>;
  /** The result function per result, in place of `methods`. */
  resultFunction?: RelayerOptions["calls"]["resultFunction"];
  /** The name of the app's skip function; default "skip". */
  skipMethod?: string;
  pollIntervalMs?: number;
  maxSameResultSends?: number;
  log?: RelayerLog;
  /** An already-connected node client (an embedder's); default one from aztecNodeUrl. */
  node?: AztecNode;
}

/** A deployed contract the relayer's PXE holds: its address and artifact. */
export interface RelayerContract {
  address: FieldLike | AztecAddress;
  artifact: ContractArtifact;
}

/** A relayer with everything it runs on. `close()` stops the loop and the wallet. */
export interface AztecRelayer {
  relayer: Relayer;
  wallet: EmbeddedWallet;
  node: AztecNode;
  client: PssClient;
  queue: NodeQueueReader;
  from: AztecAddress;
  contract: Contract;
  close(): Promise<void>;
}

/** The relayer's fee setting, ready in its wallet: under wFJ, wFJ
 * registered and the account's private balance in it checked (an empty one
 * refused); a function's setting built in the wallet. */
export async function relayerFeeSetting(fee: RelayerFee, wallet: EmbeddedWallet, node: AztecNode, from: AztecAddress, log?: RelayerLog): Promise<FeeSetting> {
  const setting = typeof fee === "function" ? await fee(wallet) : fee;
  const method = setting.method;
  if (method === "wfj") {
    const wfj = await registerWfj(wallet, node);
    const { result } = await wfj.methods.balance_of(from).simulate({ from });
    const balance = BigInt(result as bigint);
    if (balance === 0n) throw new Error(`fee: ${from} has no private FJ balance in wFJ ${wfj.address}; fund it (FeeJuice.claim with mint_and_pay_fee) before starting the relayer`);
    log?.info(`fee: through wFJ (PrivateFPC ${wfj.address}), private FJ balance ${balance}`);
  } else if (method === "account") {
    log?.info(`fee: from ${from}'s own FeeJuice balance`);
  } else {
    log?.warn(`fee: through ${method.name}`);
  }
  return setting;
}

/** Register each contract in the wallet under the instance the node holds
 * at its address, in order; their addresses. Refuses an address the node
 * holds no contract at. */
export async function registerContracts(
  wallet: Pick<EmbeddedWallet, "registerContract">,
  node: Pick<AztecNode, "getContract">,
  contracts: readonly RelayerContract[],
): Promise<AztecAddress[]> {
  const addresses: AztecAddress[] = [];
  for (const c of contracts) {
    const address = fieldAddress(c.address, `${c.artifact.name} address`);
    const instance = await node.getContract(address);
    if (!instance) throw new Error(`no contract at ${address} on the node (the configuration's ${c.artifact.name})`);
    await wallet.registerContract(instance, c.artifact);
    addresses.push(address);
  }
  return addresses;
}

/** The result function per circuit of a configuration: `resultFunction`,
 * or resultFunctions of `methods`, each checked against the client's
 * circuits and the artifact's functions (RangeError). */
export function relayerResultFunction(
  cfg: Pick<AztecRelayerConfig, "client" | "contract" | "resultFunction" | "methods">,
): RelayerOptions["calls"]["resultFunction"] {
  if (cfg.methods === undefined) return cfg.resultFunction;
  if (cfg.resultFunction !== undefined) throw new RangeError("methods: give `methods` or `resultFunction`, not both");
  const functions = new Set(cfg.contract.artifact.functions.map((f) => f.name));
  for (const [circuit, fn] of Object.entries(cfg.methods)) {
    if (!Object.hasOwn(cfg.client.circuits ?? {}, circuit)) throw new RangeError(`methods.${circuit}: not a circuit of the client configuration`);
    if (typeof fn?.name !== "string") throw new RangeError(`methods.${circuit}: { name, args? }, the result function and its leading arguments`);
    if (!functions.has(fn.name)) throw new RangeError(`methods.${circuit}: ${cfg.contract.artifact.name} has no function ${fn.name}`);
    if (fn.args !== undefined && !Array.isArray(fn.args)) throw new RangeError(`methods.${circuit}.args: a list`);
  }
  return resultFunctions(cfg.methods);
}

/** What an operator's transactions go through: the node client, an
 * embedded wallet with the operator's account, and its fee setting. */
export interface OperatorWallet {
  node: AztecNode;
  wallet: EmbeddedWallet;
  from: AztecAddress;
  fee: FeeSetting;
}

/** The configured account, checked: "local-network", or a key triple
 * parsed (RelayerAccount); a missing account is refused rather than
 * defaulted. No refusal names a key's value. */
export function relayerAccount(account: RelayerAccount | undefined): "local-network" | RelayerKeys {
  if (account === "local-network") return account;
  if (typeof account !== "object" || account === null || account.secretKey === undefined || account.signingKey === undefined) {
    throw new RangeError('account: { "secretKey", "signingKey", "salt"? } of the operator\'s account, or "local-network" for the local network\'s public test account');
  }
  return {
    secretKey: fieldFr(account.secretKey, "account.secretKey"),
    signingKey: fieldFq(account.signingKey, "account.signingKey"),
    salt: fieldFr(account.salt ?? 0, "account.salt"),
  };
}

/** Connect to the Aztec node, create an embedded wallet (PXE) with the
 * account, and ready the fee setting in it (relayerFeeSetting); the
 * relayer's and the enc key rotation's transactions go through it. Stops
 * the wallet on failure. */
export async function operatorWallet(cfg: Pick<AztecRelayerConfig, "aztecNodeUrl" | "node" | "account" | "fee" | "proverEnabled" | "log">): Promise<OperatorWallet> {
  const account = relayerAccount(cfg.account);
  const node = cfg.node ?? createAztecNodeClient(cfg.aztecNodeUrl);
  const wallet = await EmbeddedWallet.create(node, {
    ephemeral: true,
    pxe: { ...getPXEConfig(), proverEnabled: cfg.proverEnabled ?? true },
  });
  try {
    let from: AztecAddress;
    if (account === "local-network") {
      const accounts = await registerInitialLocalNetworkAccountsInWallet(wallet);
      if (accounts[0] === undefined) throw new Error("the local network registered no initial account");
      from = accounts[0];
    } else {
      const manager = await wallet.createSchnorrInitializerlessAccount(account.secretKey, account.salt, account.signingKey, "pss-relayer");
      from = manager.address;
    }
    const fee = await relayerFeeSetting(cfg.fee ?? DEFAULT_FEE_SETTING, wallet, node, from, cfg.log);
    return { node, wallet, from, fee };
  } catch (e) {
    await wallet.stop();
    throw e;
  }
}

/** Connect to the network, set up the account, fee payment and contract,
 * and build the Relayer (not started: call `relayer.start()` or `tick()`). */
export async function createAztecRelayer(cfg: AztecRelayerConfig): Promise<AztecRelayer> {
  const resultFunction = relayerResultFunction(cfg);
  const { node, wallet, from, fee } = await operatorWallet(cfg);
  try {
    const [address] = (await registerContracts(wallet, node, [cfg.contract])) as [AztecAddress];
    const contract = Contract.at(address, cfg.contract.artifact, wallet);
    const classes = cfg.upgradeArtifacts?.length ? followClasses(wallet, node, address, [cfg.contract.artifact, ...cfg.upgradeArtifacts], cfg) : undefined;
    await classes?.follow();
    // the client reads the contract's key epoch through the relayer's own
    // node, so its result checks follow a node replacement (pss-client
    // key-epoch.ts) without a new configuration
    const client = new PssClient(
      { keyEpochNode: node, ...cfg.client, contractAddress: address.toString() },
      cfg.clientOptions,
    );
    const queue = new NodeQueueReader(node, address, queueBaseSlot(cfg.contract.artifact as never, cfg.contract.queueField));
    const skipMethod = cfg.skipMethod ?? "skip";
    const relayer = new Relayer({
      client,
      queue,
      calls: {
        contract: contract as unknown as ResultContract,
        address,
        from,
        vkFields: cfg.vkFields,
        encode: cfg.encode,
        resultFunction,
        fee,
      },
      skip: async () => (contract.methods[skipMethod]!() as { send(o: unknown): Promise<unknown> }).send({ ...(await txSendOptions(fee, "skip")), from }),
      init: cfg.init && {
        ...cfg.init,
        written: async (slots) => {
          const values = await Promise.all(slots.map((slot) => node.getPublicStorageAt("latest", address, Fr.fromString(slot))));
          return values.some((v) => !v.isZero());
        },
      },
      pollIntervalMs: cfg.pollIntervalMs,
      maxSameResultSends: cfg.maxSameResultSends,
      log: cfg.log,
    });
    return {
      relayer,
      wallet,
      node,
      client,
      queue,
      from,
      contract,
      close: async () => {
        classes?.stop();
        await relayer.stop();
        await wallet.stop();
      },
    };
  } catch (e) {
    await wallet.stop();
    throw e;
  }
}

/** A follower of the app's contract class: `follow()` registers the
 * instance again when its class changed, and a timer calls it once per
 * poll period until `stop()`; a failure is logged and retried. */
function followClasses(
  wallet: EmbeddedWallet,
  node: AztecNode,
  address: AztecAddress,
  artifacts: readonly ContractArtifact[],
  cfg: Pick<AztecRelayerConfig, "pollIntervalMs" | "log">,
): { follow(): Promise<void>; stop(): void } {
  let registered: bigint | undefined;
  const follow = async () => {
    try {
      const r = await followContractClass(wallet, node, address, artifacts, registered);
      if (r.registered && registered !== undefined) cfg.log?.info(`the app now runs class ${fieldHex(r.classId)}: its instance is registered again with that class's artifact`);
      registered = r.classId;
    } catch (e) {
      cfg.log?.warn(`following the app's contract class: ${(e as Error).message}`);
    }
  };
  const timer = setInterval(() => void follow(), cfg.pollIntervalMs ?? DEFAULT_RELAYER_POLL_INTERVAL_MS);
  timer.unref();
  return { follow, stop: () => clearInterval(timer) };
}
