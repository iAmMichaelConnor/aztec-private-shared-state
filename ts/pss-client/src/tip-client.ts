// The tip (a queued intake) on the client side: a tip request from named
// inputs, a request's intake (its circuit's intake module obtains it through
// this client: the tip request, or the receipts of an intake that takes
// them) and its intake transaction (requestIntake), and FETCH by chain
// request id with the answer bound to the chain request and split by its
// circuit's result reader into the parts its result call takes.

import type { ClientCore } from "./core.ts";
import { ProtocolError } from "./errors.ts";
import { fieldHex, type FieldHexString, type FieldLike } from "./field.ts";
import {
  intakeCall,
  intakeModule,
  type IntakeAsk,
  type IntakeSendOptions,
  type IntakeTarget,
  type LaidIntake,
  type RequestIntake,
  type SubmitOptions,
} from "./intake.ts";
import { buildTipRequestWith, newUserNonce, tipInputs, type StaticCheck, type TipRequest } from "./tip.ts";
import { initChainRequestId, initResultParts, type InitResultParts } from "./init-result.ts";
import type { QueuedResult } from "./result.ts";
import { parseExecuteResponse, parseReceiptResponse, type ExecuteResponse, type GrumpkinPoint, type NodeKeys, type Triple } from "./wire.ts";

/** A tip request of a configured tip circuit, from named inputs. */
export interface TipRequestOptions {
  circuit: string;
  /** The app inputs by public name (the `public`-map spelling: one value, or
   * a list for a name that fills an array parameter). */
  inputs: Record<string, FieldLike | FieldLike[]>;
  /** Default: a fresh newUserNonce(). Give the earlier one to ask again for
   * receipts under the same request id. */
  userNonce?: FieldLike;
  /** The app's static check, as the contract's request function asserts it. */
  isValid?: StaticCheck;
  /** Default: the configured contract address. */
  namespace?: FieldLike;
}

/** A request intake of `circuit` already obtained (obtainIntake), for
 * requestIntake to lay and send. */
interface CircuitIntake {
  circuit: string;
  intake: RequestIntake;
}

/** What requestIntake sends: an ask (the intake obtained through the
 * circuit's module first), an intake already obtained, or arguments already
 * laid (an earlier request's, sent again). */
export type IntakeRequest = IntakeAsk | CircuitIntake | LaidIntake;

export interface RequestIntakeOptions extends Omit<SubmitOptions, "valuesAt"> {
  /** Values sent in place of the intake's, by name among the values the
   * request function takes first (IntakeLayout.commitment): for a request
   * function that takes a private value where the request holds a value
   * derived from it (a request under partial-note delivery takes `rho`
   * where the request holds `$partial_note`, SecretStore.nextPartial's
   * `values`). Not with laid arguments. */
  values?: Record<string, FieldLike>;
}

/** What requestIntake sent. */
export interface RequestedIntake<R> {
  /** The intake, unless laid arguments were sent. */
  intake?: RequestIntake;
  /** The request function's arguments as sent. */
  args: unknown[];
  /** What send returned (by default the mined receipt). */
  sent: R;
}

/** Which result a fetchChainResult() is for. */
export interface ChainFetchOptions {
  /** The circuit the chain request is served by. Default: the one configured
   * circuit whose pinned vk hash is the answer's (ProtocolError when none
   * is). */
  circuit?: string;
  /** Default: the configured contract address. */
  namespace?: FieldLike;
  /** Default: the configured request timeout. */
  timeoutMs?: number;
}

/** Which init round a fetchInitResult() is for. */
export interface InitFetchOptions {
  /** The init circuit, configured with its pinned vk hash. */
  circuit: string;
  /** Its app inputs, the constants the app's Config pins, in the circuit's
   * input order (none for examples/amm-tip, `[liquidity]` for
   * examples/lending-tip). Default none. */
  inputs?: readonly FieldLike[];
  /** Default: the configured contract address. */
  namespace?: FieldLike;
  /** Default: the configured request timeout. */
  timeoutMs?: number;
}

/** A checked answer of FETCH by the init's chain request id, and its parts. */
export interface InitResult {
  circuit: string;
  /** The init chain request id it was fetched by. */
  chainRequestId: string;
  response: ExecuteResponse;
  parts: InitResultParts;
}

/** The tip part of one client, over the shared core. */
export class TipClient {
  private readonly core: ClientCore;
  /** The node key check that passed or is running, by namespace and key epoch. */
  private readonly nodesChecked = new Map<string, Promise<void>>();

  constructor(core: ClientCore) {
    this.core = core;
  }

  /** A tip request (tip.ts buildTipRequestWith) of a configured tip circuit,
   * in this client's namespace unless another is given, under the circuit's
   * pinned vk hash: the named inputs are put in ABI order and range-checked
   * by the manifest (tipInputs), then `isValid` runs. obtainIntake builds it
   * for a request under a non-secret-shared intake. */
  async tipRequest(input: TipRequestOptions): Promise<TipRequest> {
    const layout = this.core.intakeLayout(input.circuit);
    return buildTipRequestWith(
      {
        namespace: this.core.namespace(input.namespace),
        vkHash: this.core.vkHash(input.circuit),
        inputs: tipInputs(layout, input.inputs),
        isValid: input.isValid,
      },
      input.userNonce ?? newUserNonce(),
    );
  }

  // The node key check before receipts. obtainIntake compares GET /v1/nodes
  // with the contract's key set before the first receipt request of each
  // key epoch and remembers a success (a failure is checked again next time);
  // it has no switch. A rotation moves the epoch and so runs the check again
  // before anything is sealed to the new set: a substituted key then needs
  // both the orchestrator and the Aztec node read through keyEpochNode. The
  // receipts are verified under the contract's sig keys whatever GET
  // /v1/nodes says, so a substituted key is refused either way; the check
  // turns a mismatch into a NodeKeyMismatchError naming the node and key.
  /** A request's intake through the module of its circuit's manifest
   * (intakeModule): under on-chain intake the tip request (tipRequest); under
   * receipt intake the tip request and POST /v1/receipt with the inputs in
   * the clear, by public name; under secret-shared receipt intake the request built
   * from named inputs (buildSharedReceiptRequest: the clear app inputs, C,
   * and every INPUT_SHARED value sealed to the contract's current enc keys) and POST
   * /v1/receipt with them; under secret-shared on-chain intake the request built
   * from named inputs under the ask's `encKeys`, the keys and epochs the app
   * contract stores (buildSharedOnchainRequest: C, the request log and its
   * data hash), nothing sent. The orchestrator fixes expiry_block and returns
   * the three nodes' receipts. The answer must carry the request id and
   * inputs hash (C) this client computes itself, an expiry after
   * currentBlock and at most receiptTtlBlocks after it (ProtocolError
   * otherwise), and three signatures that verify under the contract's
   * current sig keys (ClientCore.nodeKeysNow: the pinned keys until a node
   * replacement), each in its own node's position (ReceiptSignatureError naming the node).
   * The circuit must be configured with a manifest and a pinned vk hash
   * (ConfigError otherwise, nothing sent). A refusal by the orchestrator is a
   * SidecarError (400 for inputs that fail the nodes' static checks). Ask
   * again when the receipts expiresSoon: with the same userNonce under a
   * non-secret-shared intake, with `request: receipts.request` under secret-shared receipt
   * intake; the nodes re-sign under a later expiry. */
  async obtainIntake(ask: IntakeAsk): Promise<RequestIntake> {
    const layout = this.core.intakeLayout(ask.circuit);
    const config = this.core.config;
    const namespace = this.core.namespace(ask.namespace);
    return intakeModule(layout.intake).obtain(
      {
        layout,
        namespace,
        vkHash: fieldHex(this.core.vkHash(ask.circuit)),
        tipRequest: () => {
          if (ask.inputs === undefined) throw new RangeError(`circuit ${ask.circuit}: no inputs to build the tip request from`);
          return this.tipRequest({ ...ask, inputs: ask.inputs });
        },
        receiptKeys: async () => {
          const { epoch, keys } = await this.core.nodeKeysNow(namespace);
          return {
            encKeys: keys.map((k) => k.enc) as Triple<GrumpkinPoint>,
            sigKeys: keys.map((k) => k.sig) as Triple<GrumpkinPoint>,
            checkNodes: () => this.checkNodesOnce(namespace, epoch, keys),
          };
        },
        // under upgradable circuits the request names the version its vk
        // hash is from, which the nodes check against their chain view
        send: async (body) =>
          parseReceiptResponse(
            await this.core.transport.call(
              "POST",
              "/v1/receipt",
              JSON.stringify(config.manifestHash === undefined ? body : { ...body, manifest_hash: config.manifestHash }),
              ask.timeoutMs ?? config.timeoutMs,
            ),
          ),
        ttlBlocks: config.receiptTtlBlocks,
        marginBlocks: config.receiptMarginBlocks,
      },
      ask,
    );
  }

  private checkNodesOnce(namespace: FieldHexString, epoch: number, keys: Triple<NodeKeys>): Promise<void> {
    const at = `${namespace}:${epoch}`;
    let check = this.nodesChecked.get(at);
    if (check === undefined) {
      check = this.core.checkNodes(keys).catch((e: unknown) => {
        this.nodesChecked.delete(at);
        throw e;
      });
      this.nodesChecked.set(at, check);
    }
    return check;
  }

  /** Send a request's intake through the app's request function `target`
   * from any account (submitIntake: the arguments laid onto the method's
   * parameters, the default fee unless `sendOptions` carries one): an ask is
   * obtained first (obtainIntake), an obtained intake is laid as its module
   * gives it, with `options.values` in place of the values they name, and
   * laid arguments are sent as given. */
  async requestIntake<R>(
    target: IntakeTarget<R>,
    request: IntakeRequest,
    sendOptions: IntakeSendOptions,
    options: RequestIntakeOptions = {},
  ): Promise<RequestedIntake<R>> {
    const { values, ...submit } = options;
    if ("args" in request) {
      if (values !== undefined) throw new RangeError("laid arguments take no values in place of the intake's");
      const call = intakeCall(target, request, submit);
      return { args: call.args, sent: await call.send(sendOptions) };
    }
    const layout = this.core.intakeLayout(request.circuit);
    const intake = "intake" in request ? request.intake : await this.obtainIntake(request);
    const valuesAt: Record<number, FieldLike> = {};
    for (const [name, v] of Object.entries(values ?? {})) {
      const k = layout.commitment.indexOf(name);
      if (k < 0) throw new RangeError(`values.${name}: not a value of ${request.circuit} (${layout.commitment.join(", ")})`);
      valuesAt[k] = v;
    }
    const call = intakeCall(target, intake, { ...submit, ...(values !== undefined && { valuesAt }) });
    return { intake, args: call.args, sent: await call.send(sendOptions) };
  }

  // FETCH by chain request id. fetchChainResult asks the orchestrator's
  // `POST /v1/fetch/chain {namespace, chain_request_id}`, which answers the
  // latest committed attempt at a queued request (the nodes' requests row
  // with the greatest created_at carrying it), 404 not_found when there is
  // none and 409 conflict when the latest attempt was rolled back; both reach
  // the caller as a SidecarError (the relayer waits and asks again). The
  // answer is checked as every execute and FETCH answer is (checkResponse:
  // the pinned vk hash, the three result signatures, the optional local
  // verifier), then bound to the chain request asked for (the reader's
  // parts: the answered request id must be the machine request id of that
  // chain request and the round's own old commitments, since the signatures
  // cover the machine request id only). The circuit is the caller's or the
  // one whose pinned vk hash the answer carries; the queue does not say which
  // circuit serves an entry. There is no switch to skip a check. Asking again
  // after a revert gives the newest attempt, which is the one to land.
  /** POST /v1/fetch/chain: the latest committed attempt at chain request
   * `chainRequestId` of any queued round, checked and split by its circuit's
   * result reader (result.ts) into the parts its result call takes: a non-secret-shared
   * intake's public outputs (tipResultParts) or a secret-shared intake's private
   * outcome (outcomeResultParts), each bound to the chain request asked
   * for. */
  async fetchChainResult(chainRequestId: FieldLike, options: ChainFetchOptions = {}): Promise<QueuedResult> {
    let selected = options.circuit;
    if (selected !== undefined) {
      this.core.resultReader(selected);
      selected = this.core.config.resultAliases.get(selected) ?? selected;
    }
    const chain = fieldHex(chainRequestId, "chain_request_id");
    const namespace = this.core.namespace(options.namespace);
    const { circuit, response } = await this.fetchChain(chain, namespace, selected, options.timeoutMs);
    const reader = this.core.resultReader(circuit);
    const parts = await reader.parts(namespace, chain, response);
    return { form: reader.form, circuit, response, parts, reader } as QueuedResult;
  }

  /** One FETCH by chain request id, its circuit the caller's or the one
   * result reader whose pinned vk hash the answer carries, checked
   * (checkResponse). */
  private async fetchChain(chain: FieldHexString, namespace: FieldHexString, circuit: string | undefined, timeoutMs: number | undefined) {
    const body = JSON.stringify({ namespace, chain_request_id: chain });
    const response = parseExecuteResponse(await this.core.transport.call("POST", "/v1/fetch/chain", body, timeoutMs ?? this.core.config.timeoutMs));
    if (circuit === undefined) {
      circuit = this.core.config.landingCircuits.get(response.vk_hash);
      if (circuit === undefined) {
        throw new ProtocolError(`chain request ${chain}: the answer's vk hash ${response.vk_hash} pins no configured tip circuit`);
      }
    }
    await this.core.checkResponse(circuit, response.request_id, response, namespace);
    return { circuit, response };
  }

  /** POST /v1/fetch/chain for the init round: the latest committed attempt
   * at the init's fixed chain request id (initChainRequestId of the
   * namespace, the circuit's pinned vk hash and `inputs`), which the
   * scheduler sends once the contract is configured, checked as every FETCH
   * answer is (checkResponse) and bound to the init id (initResultParts).
   * A SidecarError 404 until the round has been computed. */
  async fetchInitResult(options: InitFetchOptions): Promise<InitResult> {
    const { circuit } = options;
    const layout = this.core.initLayout(circuit);
    const namespace = this.core.namespace(options.namespace);
    const chain = fieldHex((await initChainRequestId(namespace, this.core.vkHash(circuit), options.inputs ?? [])).toBigInt());
    const { response } = await this.fetchChain(chain, namespace, circuit, options.timeoutMs);
    const parts = await initResultParts(layout, namespace, chain, response);
    return { circuit, chainRequestId: chain, response, parts };
  }
}
