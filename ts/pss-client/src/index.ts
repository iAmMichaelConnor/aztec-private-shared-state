// pss-client: the user side of PSS on Aztec.
//
// PssClient (client.ts) is three parts over one shared core (core.ts: the
// configuration, transport.ts, the node key check and the checks of every
// answer: the pinned vk hash and the three nodes' result signatures,
// result-signatures.ts):
//
// - execute.ts, the sidecar path: builds execute requests (request.ts:
//   request ids, the public map, keys, shared inputs sealed to the pinned
//   node enc keys with envelope.ts and ae.ts, state records kept per
//   (namespace, key) by records.ts, the requester's signature), sends them
//   with FETCH on failure and resends the saved bytes after an unknown
//   outcome; after a round effects.ts splits the public inputs, capsule.ts
//   stages the vk and proof and nonces.ts mines the new notes' nonces;
// - registry.ts: owner-signed REGISTER and DISABLE with the namespace's
//   registry sequence number, and the nodes' signed answers; vk.ts computes a
//   circuit's vk hash locally so the contract can pin it before REGISTER;
//   deployment.ts deploys a tip app (the constructor's pins, REGISTER of the
//   contract manifest before the deployment, the arguments of configure;
//   aztecDeployer, the aztec.js chain side most apps need);
//   contract-manifest.ts generates a deployment's contract manifest from the
//   contract artifact, the circuits and a descriptor, and hashes it (the
//   `pss-manifest build` command, bin/pss-manifest.ts);
//   upgrades.ts reads an upgradable app's circuit pins in force (the
//   contract manifest version the contract verifies under) and sends its
//   upgrade authority's `upgrade_circuits`;
// - tip-client.ts, the tip: tip requests (tip.ts: the chain request id and
//   the app inputs' order), a request's intake through its circuit's intake
//   module (obtainIntake) and its intake transaction (requestIntake), and
//   FETCH by chain request id (fetchChainResult), split by the circuit's
//   result reader (result.ts) into a public result's parts (tip-result.ts)
//   or a private outcome's (outcome.ts), and of the init round
//   (fetchInitResult), split into the init function's values
//   (init-result.ts); proved.ts is the one reader of the three layouts'
//   proved public inputs and their binding to the chain request;
//   tip-app.ts, a deployed tip app as its user's client reaches it (the
//   node, the contract, the PssClient; deployTipApp and tipAppAt make it)
//   and a request under partial-note delivery over it in three calls:
//   requestOutcome, waitForRequest and readOutcome.
//
// Each choice a manifest makes is resolved once into one module: the intake
// (intake.ts: intake-onchain.ts, intake-receipt.ts, intake-shared-receipt.ts
// with C, the envelopes, the outcome key and tag; intake-shared-onchain.ts,
// whose example cases the examples' READMEs list), each naming its rounds'
// result form (result.ts: public results, tip-result.ts; private outcomes, outcome.ts), and the tip state holder
// (state.ts: node-held there, chain-state.ts). abi.ts is the one ABI walker.
// lander.ts lands a result (one Lander with a RetryPolicy: submitResult for a
// user, pss-relayer's tick for the operator); fee.ts is the fee setting every
// transaction pays under (wFJ by default, a fixed gas setting per
// transaction kind), which the Lander applies to each result; queue.ts reads the queue's
// storage and discovery.ts the chain's logs (the request log; the outcome
// log, OutcomeReader); outcome.ts watches a request until it is applied or
// skipped (pollResult), opens private outcomes (openOutcomeLog: the outcome
// AEAD and the completed note), computes partial-note
// delivery's hashes (partialCommitment, completedNoteHash,
// completionLogTag) and the public completion's offchain message hand-off
// (offchainReceiveArgs), and reads a
// private-outcome result for whoever lands it (outcomeResultParts).
// secrets.ts is the per-request secrets (SecretStore): the partial note's
// randomness, the refund note's and the outcome key and tag of the user's
// n-th request, derived from a wallet secret and a client-side request
// counter, and the rescan that recovers the counter from the wallet secret
// alone. handle.ts is the standing delivery handle: the handle a request
// leaves in its entry (SecretStore.handle), and the delivery another
// party's round makes to it, found, opened and rebuilt as a note
// (DeliveryReader, openDeliveryLog, under a tag of the handle's key and the
// delivering round's request id, or in a known transaction). hatch.ts is the escape hatch's client
// side: an entry's exit tags (exitTag, exitTagOf), the owner's newest note
// as the one whose tag is unspent (liveExitNote), the block and the
// transaction that spent a tag (exitTagSpentAt, exitTagSpender), the
// owner's walk through the notices of rounds it did not request to the note
// an exit takes (recoverExitNote) and the keeper's trigger check
// (hatchReady). keeper.ts is the keeper's loop over
// a tree-valued key: scan a window at a time, advancing start by the window
// width, hand each window's reported indices to the act round, and stop at
// the occupancy frontier. field.ts (field elements, Poseidon2 over
// integers, the CSPRNG draw), labels.ts (ASCII domain labels) and grumpkin.ts
// (points and the ephemeral secret) are the encodings every module shares.
//
// The rest: config.ts (the client's configuration), errors.ts (the errors it
// throws), wire.ts (the JSON bodies of the sidecar API), signing.ts (Schnorr
// over Grumpkin for signed bodies), store.ts (the sent request ids and
// bodies, for FETCH and resend), manifest.ts (the typed manifest view),
// key-epoch.ts (the numbered node key sets a contract checks signatures
// under), bricks.ts (what a tip contract's artifact says about its bricks),
// verify.ts (pss-manifest verify), watch.ts (watching a request across
// replaced blocks, opt-in), audit.ts (the requester audit), admin-socket.ts
// (a node's admin socket) and sleep.ts (an abortable wait).
//
// Layout and dependencies: one workspace of the npm workspace at the
// repository root, installed from the root package-lock.json (`npm ci` at
// the root). Runtime dependencies are @aztec-labs/aztec.js, constants,
// foundation, noir-contracts.js and stdlib 6.0.0 and
// @alejoamiras/private-fee-juice 6.0.0 (wFJ, versioned with Aztec). Sources
// are TypeScript with erasable syntax only, which Node runs directly under
// the `source` export condition (tests: `npm test`);
// `npm run build` type-checks sources and tests and emits dist/.
//
// The exports below are the public API. internal.ts re-exports every
// module, for this package's tests and @aztec-pss/test-support.

export { abiMembers } from "./abi.ts";
export { adminSocket, type AdminAnswer, type AdminCall, type EncKeySigned } from "./admin-socket.ts";
export { TagMismatchError } from "./ae.ts";
export { assertNoRequester, auditFields, RequesterLeakError } from "./audit.ts";
export { proofToFields, stageCapsule, vkFieldsFromBbJson, vkHashFromFields } from "./capsule.ts";
export { PssClient, type PssClientOptions } from "./client.ts";
export {
  type CircuitPackage,
  circuitPackages,
  type PssClientConfig,
  resolveConfig,
  type ResolvedConfig,
} from "./config.ts";
export {
  buildContractManifest,
  type BuildContractManifestInput,
  checkContractManifest,
  constructorConfig,
  type ContractManifest,
  contractManifestHash,
  type ContractManifestPackage,
  type Descriptor,
  type DescriptorPackage,
  listedPackages,
  type NamedStateKeys,
  packageCapacity,
  packagesHash,
  refuseOwnAddress,
  STRIPPED_DEBUG_SYMBOLS,
  storageSlot,
  stripCircuit,
} from "./contract-manifest.ts";
export {
  type AztecDeployer,
  aztecDeployer,
  type AztecDeployerOptions,
  type CircuitPinsArgs,
  circuitPinsOf,
  configureArgs,
  deployTip,
  staleBlocksOf,
  tipPins,
} from "./deployment.ts";
export {
  type CircuitPinsNode,
  type ClassFollowNode,
  type ClassFollowWallet,
  classIdOf,
  followContractClass,
  manifestHashAt,
  pendingUpgrade,
  pinsAt,
  type PinsRead,
  readCircuitPins,
  type StoredCircuitPins,
  type UpgradableManifest,
  upgradeCircuits,
  type UpgradeCircuitsContract,
  upgradeContract,
  type UpgradeContractContract,
  type UpgradedPins,
  unpackCircuitPins,
  vkHashesOf,
} from "./upgrades.ts";
export {
  artifactFacts,
  compareClass,
  compareFacts,
  comparePins,
  type PinsValues,
  readPinsInForce,
  statedPins,
  verifyDeployment,
  type VerifyLine,
} from "./verify.ts";
export { type FoundOutcome, type LogNode, outcomeDeliveryArgs, OutcomeReader, readRequestLog, taggedLogs, type TxEffects } from "./discovery.ts";
export { type PssEffects, shapeFromAbi, splitEffects } from "./effects.ts";
export { sealEnvelope, shareField, shareHash } from "./envelope.ts";
export {
  ConfigError,
  type ErrorClass,
  NodeKeyMismatchError,
  ProtocolError,
  ReceiptSignatureError,
  ResultSignatureError,
  SidecarError,
  TransportError,
  UnknownOutcomeError,
  VkHashMismatchError,
} from "./errors.ts";
export { type ExecuteOutcome, type FetchOptions } from "./execute.ts";
export {
  DEFAULT_FEE_SETTING,
  feeOptions,
  type FeeSendOptions,
  type FeeSetting,
  type FeeTxKind,
  maxGasCost,
  registerSponsoredFpc,
  registerWfj,
  SEND_WAIT,
  sponsoredFeeSetting,
  txSendOptions,
  WFJ,
} from "./fee.ts";
export { fieldAddress, fieldFq, fieldFr, fieldHex, fieldShortHex, type FieldHexString, type FieldLike } from "./field.ts";
export {
  exitTag,
  exitTagOf,
  exitTagSpentAt,
  exitTagSpender,
  type ExitNote,
  type ExitRecovery,
  hatchReady,
  type HatchState,
  liveExitNote,
  MAX_RECOVERED_NOTICES,
  type NullifierNode,
  PSS_EXIT_TAG,
  recoverExitNote,
  type RecoverOptions,
  type SpenderNode,
} from "./hatch.ts";
export { defaultInitEncoder } from "./init-result.ts";
export { TipReceipts } from "./intake-receipt.ts";
export { type EncKeyInput, type EncKeyReader, storedEncKey, storedEncKeys, type StoredEncKey } from "./intake-shared-onchain.ts";
export {
  buildSharedReceiptRequest,
  type SharedReceiptRequest,
  SharedReceipts,
  type Sharing,
} from "./intake-shared-receipt.ts";
export {
  type IntakeAsk,
  intakeRequestLogs,
  type IntakeSendOptions,
  intakeSummary,
  type IntakeTarget,
  type LaidIntake,
  layIntakeArgs,
  type RequestIntake,
  submitIntake,
  type SubmitOptions,
} from "./intake.ts";
export {
  type ActRound,
  actRounds,
  type KeeperPass,
  keeperPass,
  type KeeperPassOptions,
  type KeeperShape,
  keeperShape,
  reportedIndices,
  type ScanLayout,
  scanReport,
  type ScanReport,
} from "./keeper.ts";
export { assertKeyRotation, type KeyEpochNode, readKeyEpoch } from "./key-epoch.ts";
export { brickProblems, type Bricks, bricksOf, checkedBricks, RESERVED_NAMES, type ReservedName, stateViewName } from "./bricks.ts";
export { asciiLabel } from "./labels.ts";
export {
  type InitCallSettings,
  isRevert,
  type LandAttempt,
  Lander,
  type LanderOptions,
  type PreparedCall,
  prepareResult,
  resultFunctions,
  type ResultCallSettings,
  type ResultFunction,
  type ResultContract,
  type RetryPolicy,
  sendResultCall,
  submitResult,
  SubmitResultError,
  USER_RETRY_POLICY,
} from "./lander.ts";
export { isQueued, PARTIAL_NOTE_NAME, readContract, SELF_CONTRACT, type WitnessEntry } from "./manifest.ts";
export { anchoredNonce, checkNullified, mineNonces, txEffectFrom } from "./nonces.ts";
export {
  completedNoteHash,
  completionLogTag,
  NoteMismatchError,
  offchainReceiveArgs,
  openOutcomeLog,
  type OutcomeKeys,
  outcomePlaintextLength,
  partialCommitment,
  pollResult,
  type SentOffchainMessage,
} from "./outcome.ts";
export {
  DONE_APPLIED,
  DONE_SKIPPED,
  NodeQueueReader,
  queueBaseSlot,
  type QueueReader,
  type QueueSnapshot,
  type StorageNode,
} from "./queue.ts";
export { JsonFileRecordStore, MemoryRecordStore, type RecordStore } from "./records.ts";
export { type ManifestBodyInput, REGISTER_TIMEOUT_MS, type RegisterOptions } from "./registry.ts";
export {
  type BuildRequestInput,
  executeMessage,
  inputBodyHash,
  type KeyLike,
  type PreparedRequest,
  requestKey,
  signRequest,
} from "./request.ts";
export { noteHashIndices, resultMessages } from "./result-signatures.ts";
export {
  type ChainResult,
  type OutcomeChainResult,
  type QueuedResult,
  type ResultReader,
  type ResultSummary,
  resultSummary,
} from "./result.ts";
export { DEFAULT_GAP_LIMIT, type NextPartialRequest, SecretStore } from "./secrets.ts";
export {
  type DeliveryKeys,
  DeliveryReader,
  type FoundDelivery,
  HANDLE_KEY_NAME,
  HANDLE_PARTIAL_NAME,
  handleSecrets,
  type HandleSecrets,
  handleTag,
  type NextHandle,
  nextHandle,
  openDeliveryLog,
  type OpenedDelivery,
  PSS_HANDLE_KEY,
  PSS_HANDLE_RANDOMNESS,
  PSS_HANDLE_TAG,
} from "./handle.ts";
export {
  OwnerKey,
  RequesterKey,
  type SchnorrSigner,
  verifySignature,
} from "./signing.ts";
export { sleep } from "./sleep.ts";
export { JsonFileRequestStore, MemoryRequestStore, type RequestStore } from "./store.ts";
export {
  type DeployedTipApp,
  deployTipApp,
  type DeployTipAppOptions,
  type OutcomeAsk,
  type OutcomeRequest,
  outcomeSlot,
  queueOf,
  readAndDeliverOutcome,
  readOutcome,
  requestOutcome,
  type SentOutcomeRequest,
  type SimulatableInteraction,
  type TipApp,
  tipAppAt,
  type TipAppAtOptions,
  type TipAppContract,
  type TipBuild,
  type TipNetwork,
  waitForRequest,
} from "./tip-app.ts";
export {
  type ChainFetchOptions,
  type InitFetchOptions,
  type InitResult,
  type IntakeRequest,
  type RequestedIntake,
  type RequestIntakeOptions,
  type TipRequestOptions,
} from "./tip-client.ts";
export {
  DEFAULT_RESULT_METHOD,
  defaultProcessResultEncoder,
  type ProcessResultEncoder,
} from "./tip-result.ts";
export { newUserNonce, type SharedSecrets, type TipRequest } from "./tip.ts";
export { MAX_RESPONSE_BYTES, sidecarError, Transport } from "./transport.ts";
export { vkHashFromBbJson } from "./vk.ts";
export {
  type TxReceiptNode,
  watchOutcome,
  type WatchOutcomeOptions,
  watchRequest,
  type WatchRequestOptions,
  type WatchedRequest,
  type WatchedStatus,
} from "./watch.ts";
export {
  canonicalJson,
  type DisableRequest,
  type DisableResponse,
  type ExecuteRequest,
  type ExecuteResponse,
  type GrumpkinPoint,
  type NamespaceResponse,
  type NodeKeys,
  type NodesResponse,
  normaliseSignature,
  type PackageResponse,
  parseExecuteResponse,
  type ContractManifestResponse,
  type ManifestBody,
  type ManifestMessage,
  type ManifestResponse,
  type ResultRecord,
  type ShareCiphertext,
  type Signature,
  type StateKeys,
  type Triple,
} from "./wire.ts";
