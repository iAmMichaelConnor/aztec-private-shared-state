// A deployed tip app as its user's client reaches it (TipApp: the Aztec node,
// the app contract and the namespace's PssClient), and the three steps of a
// request under partial-note delivery over it: request (requestOutcome),
// wait until the queue has finished it (waitForRequest), and read its
// private outcome (readOutcome; readAndDeliverOutcome also hands the note to
// the owner's PXE). Each is a composition of the calls below it
// (SecretStore.nextPartial, PssClient.requestIntake and intakeSummary;
// NodeQueueReader and pollResult; OutcomeReader), which stay the long form
// for a client that needs a step between them.
//
// deployTipApp and tipAppAt make the TipApp: the first deploys the app (the
// contract manifest from the deployment descriptor, deployTip over
// aztecDeployer), the second reaches a deployed one from a user's wallet;
// both configure the namespace's PssClient from the network, the build and
// the descriptor (its stale period).
//
// What the steps read rather than take: the request's partial note and its
// place (the intake layout: a shared `$partial_note`, or a non-secret-shared
// round's clear input), a delivery handle when the round's C commits one,
// the request's derived outcome key and tag (the request secrets the intake
// takes what it needs from), the queue's slot from the artifact
// (queueBaseSlot), the outcome notes' slot from the app's state view
// (`TipState.outcome_slot`, the view found by its return type, so the slot
// is the one the contract checks its circuits' against), and the outcome's
// plaintext length from the round circuit (outcomePlaintextLength).

import type { AztecAddress } from "@aztec-labs/aztec.js/addresses";
import { Contract } from "@aztec-labs/aztec.js/contracts";
import type { Wallet } from "@aztec-labs/aztec.js/wallet";
import type { ContractArtifact } from "@aztec-labs/stdlib/abi";

import { stateViewName, type BrickArtifact } from "./bricks.ts";
import { PssClient } from "./client.ts";
import { circuitPackages, type NodeKeysLike } from "./config.ts";
import { buildContractManifest, type Descriptor } from "./contract-manifest.ts";
import { aztecDeployer, deployTip, type AztecDeployerOptions, type TipDeployment } from "./deployment.ts";
import { OutcomeReader, outcomeDeliveryArgs, type FoundOutcome, type PrivateLogNode } from "./discovery.ts";
import { fieldBigInt, fieldHex, type FieldHexString, type FieldLike } from "./field.ts";
import { HANDLE_PARTIAL_NAME } from "./handle.ts";
import { storedEncKeys, type EncKeyReader } from "./intake-shared-onchain.ts";
import { intakeSummary, type IntakeAsk, type IntakeSendOptions, type RequestIntake, type SendableInteraction } from "./intake.ts";
import { PARTIAL_NOTE_NAME } from "./manifest.ts";
import { pollResult, type OutcomeKeys, type PolledResult } from "./outcome.ts";
import { NodeQueueReader, queueBaseSlot, type StorageNode } from "./queue.ts";
import type { SecretStore } from "./secrets.ts";
import type { SchnorrSigner } from "./signing.ts";
import type { Triple } from "./wire.ts";

/** What a TipApp calls on the app contract (an aztec.js Contract has it):
 * the request functions it sends and the state view it simulates. */
export interface SimulatableInteraction<R = unknown> extends SendableInteraction<R> {
  simulate(options: { from: AztecAddress }): Promise<{ result: unknown }>;
}

/** The app contract as a TipApp takes it (an aztec.js Contract). */
export interface TipAppContract {
  address: AztecAddress;
  artifact: BrickArtifact & { storageLayout?: Record<string, { slot: { toBigInt(): bigint } | FieldLike }> };
  methods: Record<string, (...args: never[]) => SimulatableInteraction>;
}

/** A deployed tip app as its user's client reaches it. */
export interface TipApp {
  /** An Aztec node (an aztec.js AztecNode). */
  node: StorageNode & PrivateLogNode;
  contract: TipAppContract;
  /** The namespace's pss-client, configured with the round circuits. */
  pss: PssClient;
}

/** What the network's operator publishes: where its orchestrator listens
 * and each node's keys, node 0 first. */
export interface TipNetwork {
  orchestratorUrl: string;
  nodeKeys: Triple<NodeKeysLike>;
}

/** An app's build: the compiled contract, and per circuit its nargo output
 * and vk hash (`bb write_vk`, localVkHash), by circuit name. */
export interface TipBuild {
  artifact: ContractArtifact;
  circuits: Record<string, unknown>;
  vkHashes: Record<string, FieldLike>;
}

/** What tipAppAt takes: the app (its deployment descriptor, its circuit
 * manifests by package and its build), the network, and where the client
 * reaches it. */
export interface TipAppAtOptions<N extends TipApp["node"]> {
  /** An Aztec node (an aztec.js AztecNode). */
  node: N;
  /** The wallet the contract's calls go through. */
  wallet: Wallet;
  network: TipNetwork;
  build: TipBuild;
  /** The deployment descriptor (examples/<example>/deployments/<deployment>.json):
   * the client's stale period is its `stale_blocks`. */
  descriptor: Descriptor;
  manifests: Record<string, unknown>;
  /** The app contract: the namespace. */
  address: AztecAddress;
}

/** A TipApp whose node and contract are aztec.js's. */
export interface DeployedTipApp<N extends TipApp["node"]> extends TipApp {
  node: N;
  contract: Contract;
}

/** The namespace's PssClient of an app at `address`: the network, the build's
 * vk hashes and circuits with their manifests, the descriptor's stale
 * period. */
function namespaceClient(o: Omit<TipAppAtOptions<TipApp["node"]>, "node" | "wallet">): PssClient {
  const packages = o.descriptor.packages;
  const circuits = Object.fromEntries(packages.map((p) => [p.name, o.build.circuits[p.circuit]]));
  const vkHashes = Object.fromEntries(packages.map((p) => [p.name, o.build.vkHashes[p.circuit]!]));
  return new PssClient({
    orchestratorUrl: o.network.orchestratorUrl,
    nodeKeys: o.network.nodeKeys,
    vkHashes,
    circuits: circuitPackages(circuits, o.manifests, packages),
    contractAddress: o.address.toBigInt(),
    ...(o.descriptor.stale_blocks !== undefined && { staleBlocks: o.descriptor.stale_blocks }),
  });
}

/** A deployed tip app as a user's client reaches it: the contract at
 * `address` through `wallet`, and the namespace's PssClient. */
export function tipAppAt<N extends TipApp["node"]>(o: TipAppAtOptions<N>): DeployedTipApp<N> {
  return { node: o.node, contract: Contract.at(o.address, o.build.artifact, o.wallet), pss: namespaceClient(o) };
}

/** What deployTipApp takes: tipAppAt's options without the address, and the
 * deployment's sender, owner and chain side. */
export interface DeployTipAppOptions<N extends TipApp["node"]> extends Omit<TipAppAtOptions<N>, "address"> {
  /** The account that sends the deployment and configure. */
  operator: AztecAddress;
  /** The namespace owner's key: keep it, it signs every later REGISTER and
   * DISABLE. */
  owner: SchnorrSigner;
  /** The address of each contract the descriptor's `read_contracts` names. */
  contracts?: Record<string, FieldLike>;
  /** As aztecDeployer's: the constructor's arguments from the pins (default
   * `[{ tip: pins }]`) and the fee setting. */
  constructorArgs?: AztecDeployerOptions["constructorArgs"];
  fee?: AztecDeployerOptions["fee"];
}

/** Deploy a tip app (the operator, once): the contract manifest from the
 * descriptor, the circuit manifests, the build's vk hashes and the artifact's
 * slots (buildContractManifest); then deployTip REGISTERs it under the
 * address the constructor's pins give, deploys and configures, through a
 * registry PssClient of the network and aztecDeployer. The network then runs
 * the init round and its relayer lands it. Returns the app as tipAppAt does
 * (the contract through the operator's wallet) and what deployTip did. */
export async function deployTipApp<N extends TipApp["node"]>(o: DeployTipAppOptions<N>): Promise<DeployedTipApp<N> & { deployment: TipDeployment }> {
  const manifest = await buildContractManifest({
    descriptor: o.descriptor,
    manifests: o.manifests,
    vkHashes: o.build.vkHashes,
    artifact: o.build.artifact,
    ...(o.contracts !== undefined && { contracts: o.contracts }),
  });
  // the registry is a pss-client of the network with no namespace: REGISTER names it
  const registry = new PssClient({ orchestratorUrl: o.network.orchestratorUrl, nodeKeys: o.network.nodeKeys, vkHashes: o.build.vkHashes });
  const deployer = aztecDeployer({
    wallet: o.wallet,
    artifact: o.build.artifact,
    from: o.operator,
    ...(o.constructorArgs !== undefined && { constructorArgs: o.constructorArgs }),
    ...(o.fee !== undefined && { fee: o.fee }),
  });
  const keys = o.network.nodeKeys;
  const deployment = await deployTip({ registry, owner: o.owner, manifest, circuits: o.build.circuits, sigKeys: [keys[0].sig, keys[1].sig, keys[2].sig], deployer });
  const contract = deployer.contract();
  return { node: o.node, contract, pss: namespaceClient({ ...o, address: contract.address }), deployment };
}

/** What a request under partial-note delivery keeps until its outcome is
 * read. */
export interface OutcomeRequest {
  circuit: string;
  chainRequestId: FieldHexString;
  /** The note's owner. */
  owner: FieldHexString;
  /** The partial note's randomness. */
  rho: FieldHexString;
  /** The requester's request counter (SecretStore). */
  n: number;
  /** A secret-shared intake: the key and tag its outcome log opens and is
   * found under. A non-secret-shared round completes its note in public. */
  outcomeKey?: FieldHexString;
  outcomeTag?: FieldHexString;
  /** A round whose C commits a delivery handle: its key and randomness, kept
   * until a delivery under it is found or a later request replaces it. */
  handle?: { handleKey: FieldHexString; handleRho: FieldHexString };
}

/** What requestOutcome sends. */
export interface OutcomeAsk {
  circuit: string;
  /** The app's request function. */
  method: string;
  /** The app inputs by name, without the partial note or handle. */
  inputs: Record<string, FieldLike | FieldLike[]>;
  /** The requester's store in this namespace. */
  secrets: SecretStore;
  /** The note's owner; default the sender (`send.from`). */
  owner?: FieldLike;
  /** As IntakeAsk's; default the keys the app contract stores, read as the
   * sender (storedEncKeys), which only secret-shared on-chain intake reads. */
  encKeys?: IntakeAsk["encKeys"];
  isValid?: IntakeAsk["isValid"];
}

/** What requestOutcome sent. */
export interface SentOutcomeRequest {
  request: OutcomeRequest;
  intake: RequestIntake;
  args: unknown[];
  /** What the request function's send returned (by default the mined receipt). */
  sent: unknown;
}

function senderOf(from: IntakeSendOptions["from"]): FieldLike {
  return typeof from === "object" && from !== null && "toBigInt" in from ? from.toBigInt() : (from as FieldLike);
}

/** Request `ask` under partial-note delivery: the next request secrets of
 * the requester's store, the partial note (and a delivery handle where the
 * round's C commits one) merged into the inputs and their randomness sent in
 * the request function's place, the intake obtained (under secret-shared
 * on-chain intake with the enc keys the app contract stores, unless the ask
 * gives its own) and the request function sent (PssClient.requestIntake).
 * Swapping the round's intake within the secret-shared family changes
 * nothing here. Returns what the request keeps.
 * RangeError when the round commits no partial note. */
export async function requestOutcome(app: TipApp, ask: OutcomeAsk, send: IntakeSendOptions): Promise<SentOutcomeRequest> {
  const layout = app.pss.config.intakeLayouts[ask.circuit];
  if (layout === undefined) throw new RangeError(`${ask.circuit}: no tip circuit of this pss-client`);
  const shared = layout.commitment.includes(PARTIAL_NOTE_NAME);
  if (!shared && layout.partialNote === undefined) throw new RangeError(`${ask.circuit}: its request commits no partial note`);
  const owner = fieldHex(ask.owner ?? senderOf(send.from), "owner");
  const next = await ask.secrets.nextPartial(owner);
  const place = shared ? PARTIAL_NOTE_NAME : layout.partialNote!;
  const handle = layout.commitment.includes(HANDLE_PARTIAL_NAME) ? await ask.secrets.handle(owner, next.n) : undefined;
  const currentBlock = Number(await app.node.getBlockNumber());
  const { intake, args, sent } = await app.pss.requestIntake(
    { contract: app.contract, method: ask.method },
    {
      circuit: ask.circuit,
      inputs: { ...ask.inputs, [place]: next.partialNote, ...handle?.inputs },
      currentBlock,
      secrets: next.secrets,
      encKeys: ask.encKeys ?? (() => storedEncKeys(app.contract as TipAppContract & EncKeyReader, send.from)),
      ...(ask.isValid !== undefined && { isValid: ask.isValid }),
    },
    send,
    { currentBlock, values: { [place]: next.rho, ...handle?.values } },
  );
  const s = intakeSummary(intake!);
  return {
    request: {
      circuit: ask.circuit,
      chainRequestId: s.chainRequestId,
      owner,
      rho: next.rho,
      n: next.n,
      ...(s.outcomeKey !== undefined && { outcomeKey: s.outcomeKey, outcomeTag: s.outcomeTag! }),
      ...(handle !== undefined && { handle: { handleKey: handle.handleKey, handleRho: handle.handleRho } }),
    },
    intake: intake!,
    args,
    sent,
  };
}

/** The app's queue, read from the node at the slot its artifact gives. */
export function queueOf(app: TipApp): NodeQueueReader {
  return new NodeQueueReader(app.node, app.contract.address, queueBaseSlot(app.contract.artifact));
}

/** Wait until the app's queue has finished `request` (pollResult): applied,
 * or skipped when it went stale. */
export function waitForRequest(
  app: TipApp,
  request: { chainRequestId: FieldLike },
  options: { timeoutMs?: number; intervalMs?: number; fromIndex?: number } = {},
): Promise<PolledResult<unknown>> {
  return pollResult({ queue: queueOf(app), chainRequestId: request.chainRequestId, ...options });
}

/** The storage slot of the app's outcome notes, from its state view
 * (`TipState.outcome_slot`), simulated as `from`. */
export async function outcomeSlot(contract: TipAppContract, from: AztecAddress): Promise<bigint> {
  const view = contract.methods[stateViewName(contract.artifact)]!;
  const state = (await view().simulate({ from })).result as { outcome_slot?: FieldLike };
  if (state?.outcome_slot === undefined) throw new RangeError("the state view returned no outcome_slot");
  return fieldBigInt(state.outcome_slot, "outcome_slot");
}

/** The private outcome of a landed `request`: its outcome log found by the
 * request's tag and opened with its key, and the completed note rebuilt at
 * the app's outcome slot (read as `from`, the owner's account) with the
 * round circuit's plaintext length; undefined when no log is on chain yet.
 * Hand the note to the owner's PXE with the app's outcome-note utility and
 * outcomeDeliveryArgs. RangeError for a request with no private outcome. */
export async function readOutcome(app: TipApp, request: OutcomeRequest, from: AztecAddress): Promise<FoundOutcome | undefined> {
  const { reader, tag, keys } = await outcomeRead(app, request, from);
  return reader.read(tag, keys);
}

/** readOutcome, then the completed note handed to `from`'s PXE through the
 * app's outcome-note utility (`utility`, simulated as `from`, with
 * outcomeDeliveryArgs) when it is the logged note (`noteMatches`: a round
 * whose shares did not open C may have completed another partial note).
 * Returns what readOutcome found. */
export async function readAndDeliverOutcome(
  app: TipApp,
  request: OutcomeRequest,
  from: AztecAddress,
  utility = "deliver_outcome",
): Promise<FoundOutcome | undefined> {
  const deliver = app.contract.methods[utility] as ((...args: unknown[]) => SimulatableInteraction) | undefined;
  if (deliver === undefined) throw new RangeError(`the contract has no method ${utility}`);
  const { reader, tag, keys } = await outcomeRead(app, request, from);
  return reader.readAndDeliver(tag, keys, async (found) => void (await deliver(...outcomeDeliveryArgs(found)).simulate({ from })));
}

/** The reader, tag and keys of a request's private outcome. */
async function outcomeRead(app: TipApp, request: OutcomeRequest, from: AztecAddress): Promise<{ reader: OutcomeReader; tag: FieldHexString; keys: OutcomeKeys }> {
  const plaintextLength = app.pss.config.plaintextLengths[request.circuit];
  if (request.outcomeKey === undefined || request.outcomeTag === undefined || plaintextLength === undefined) {
    throw new RangeError(`${request.circuit}: the request has no private outcome to read`);
  }
  const keys = {
    outcomeKey: request.outcomeKey,
    owner: request.owner,
    rho: request.rho,
    requestId: request.chainRequestId,
    storageSlot: await outcomeSlot(app.contract, from),
    plaintextLength,
  };
  return { reader: new OutcomeReader(app.node, app.contract.address), tag: request.outcomeTag, keys };
}
