// The one reader of a tip round's proved public inputs (docs/ARCHITECTURE.md
// section 6, rows "result" and "relayer"). Every tip circuit's proof states
// its public parameters `[namespace, vk_hash, slots..., (pinned values...)]`
// and then its return value, which starts with the chain request id; each
// result form's layout names the public-input index of every part:
//
//   tipResultLayout    a non-secret-shared intake's round (pss_public_contract result.nr
//                      proved_public_inputs; testvectors/tip_results.json rounds)
//   initResultLayout   the init round (init.nr init_public_inputs;
//                      tip_results.json init_rounds)
//   outcomeLayout      a secret-shared intake's round (outcome.nr
//                      outcome_public_inputs; testvectors/outcome.json)
//
// ProvedInputs takes each part at its indices and binds the answer as every
// form binds it: the proof's namespace, vk hash and chain request id are the
// ones asked for, the answer's request id is the machine request id of that
// chain request, the round's old commitments and its pinned reads (the
// proof's own too, where its layout states it), and the answer carries the
// state module's number of records. The node side is machine/sidecar-tip
// (ids.rs machine_request_id).

import { Fr } from "@aztec-labs/aztec.js/fields";
import { poseidon2Hash } from "@aztec-labs/foundation/crypto/poseidon";

import { ProtocolError } from "./errors.ts";
import { fieldFr, fieldHex, type FieldHexString, type FieldLike } from "./field.ts";
import { stateModule, type StateArgs, type TipStateHolder } from "./state.ts";
import type { ExecuteResponse, Signature, Triple } from "./wire.ts";
import { asciiLabel } from "./labels.ts";

// PSS_ATTEMPT, the first element of the machine request id: ASCII
// "sidecar.attempt" read as a big-endian integer, sidecar-tip's ids.rs and
// pss_public_contract's domains.nr. The nodes sign the result under the
// machine request id, so a client that hashes with another value refuses
// every FETCH-by-chain-request-id answer (the binding check of
// ProvedInputs.bind).
export const PSS_ATTEMPT = asciiLabel("sidecar.attempt");

/** The machine request id of one attempt at chain request `chainRequestId`
 * against the state with these old commitments and at these pinned read
 * values (the one place the client computes it; ProvedInputs.bind and every
 * caller go through here):
 * `poseidon2([PSS_ATTEMPT, chain_request_id, old commitments..., pinned values...])`,
 * the pinned values in the manifest's `public_reads` order (each read's
 * value, then an epoch read's epoch); a circuit without
 * pinned reads passes none (the default), which leaves the id over the old
 * commitments alone. sidecar-tip's ids.rs documents the layout. */
export async function machineRequestId(
  chainRequestId: FieldLike,
  oldCommitments: readonly FieldLike[],
  reads: readonly FieldLike[] = [],
): Promise<Fr> {
  return poseidon2Hash([
    new Fr(PSS_ATTEMPT),
    fieldFr(chainRequestId, "chain_request_id"),
    ...oldCommitments.map((c, i) => fieldFr(c, `old_commitments[${i}]`)),
    ...reads.map((c, q) => fieldFr(c, `reads[${q}]`)),
  ]);
}

/** A result signature as the library's result functions take it
 * (`ResultSignature = [Field; 4]`): `[s.lo, s.hi, e.lo, e.hi]`. */
export function signatureLimbs(sig: Signature): [Fr, Fr, Fr, Fr] {
  return [fieldFr(sig.s[0], "s[0]"), fieldFr(sig.s[1], "s[1]"), fieldFr(sig.e[0], "e[0]"), fieldFr(sig.e[1], "e[1]")];
}

/** Where the parts every form binds sit in a round's public inputs; the
 * namespace and the vk hash are the first two in every form. */
export interface ProvedLayout {
  circuit: string;
  /** The rounds' state holder (its module: stateModule). */
  state: TipStateHolder;
  /** The records a round's answer carries, each as the position of its
   * output among the round's outputs and new commitments (the state
   * module's records). */
  records: readonly number[];
  /** The proved chain request id, the return value's first element. */
  requestId: number;
  /** The old commitments, in commitment_slot key order. */
  oldCommitments: number[];
  /** The new commitments, in manifest output order. */
  newCommitments: number[];
  /** The pinned values, in manifest `public_reads` order: each read's value,
   * then an epoch read's epoch. */
  reads: number[];
  /** The proof's own machine request id, in a layout that states one (a
   * private outcome's). */
  machineRequestId?: number;
}

/** What every form's parts carry from one bound answer. */
export interface ProvedParts {
  circuit: string;
  state: TipStateHolder;
  namespace: FieldHexString;
  /** The chain request id, what the queue holds. */
  requestId: FieldHexString;
  /** The machine request id the nodes signed under. */
  machineRequestId: FieldHexString;
  vkHash: FieldHexString;
  oldCommitments: FieldHexString[];
  newCommitments: FieldHexString[];
  reads: FieldHexString[];
  /** The state module's arguments for the result call (its stateArgs;
   * empty under node-held state). */
  stateArgs: StateArgs;
  signatures: Triple<Signature>;
  /** The bb proof (`0x` hex) and the public inputs, as the answer carries them. */
  proof: string;
  publicInputs: FieldHexString[];
}

/** One answer's proved public inputs, read at a layout's indices. */
export class ProvedInputs {
  readonly circuit: string;
  readonly response: ExecuteResponse;

  constructor(circuit: string, response: ExecuteResponse) {
    this.circuit = circuit;
    this.response = response;
  }

  /** The number of public inputs. */
  get length(): number {
    return this.response.public_inputs.length;
  }

  /** The public input at `index` (ProtocolError past the end). */
  at(index: number, what: string): FieldHexString {
    const pi = this.response.public_inputs;
    const v = pi[index];
    if (v === undefined) throw new ProtocolError(`${this.circuit}: the answer has ${pi.length} public inputs, no ${what} at ${index}`);
    return v;
  }

  /** The public inputs at `indices`, in order. */
  take(indices: readonly number[], what: string): FieldHexString[] {
    return indices.map((i, k) => this.at(i, `${what} ${k}`));
  }

  /** The parts every form shares, with the answer bound to chain request
   * `chainRequestId` in `namespace` (ProtocolError otherwise): the proof's
   * namespace, vk hash and request id are the ones asked for, the answer's
   * request id (and the proof's own, where the layout states it) is the
   * machine request id of the chain request, the round's old commitments
   * and its pinned reads, and the answer carries the layout's number of
   * records (the state module checks them and gives their thirds). The
   * result signatures are checked by the caller (PssClient). */
  async bind(layout: ProvedLayout, namespace: FieldLike, chainRequestId: FieldLike): Promise<ProvedParts> {
    const { circuit } = this;
    const response = this.response;
    const ns = fieldHex(namespace, "namespace");
    const chain = fieldHex(chainRequestId, "chain_request_id");
    if (this.at(0, "namespace") !== ns) throw new ProtocolError(`${circuit}: the proof's namespace ${this.at(0, "namespace")} is not ${ns}`);
    if (this.at(1, "vk hash") !== response.vk_hash) throw new ProtocolError(`${circuit}: the proof states vk hash ${this.at(1, "vk hash")}, the answer ${response.vk_hash}`);
    if (this.at(layout.requestId, "request id") !== chain) {
      throw new ProtocolError(`${circuit}: the proof's request id ${this.at(layout.requestId, "request id")} is not ${chain}`);
    }
    const oldCommitments = this.take(layout.oldCommitments, "old commitment");
    const newCommitments = this.take(layout.newCommitments, "new commitment");
    const reads = this.take(layout.reads, "pinned read");
    const machine = fieldHex((await machineRequestId(chain, oldCommitments, reads)).toBigInt());
    const proved = layout.machineRequestId === undefined ? machine : this.at(layout.machineRequestId, "machine request id");
    if (response.request_id !== machine || proved !== machine) {
      throw new ProtocolError(
        `${circuit}: the machine request id of chain request ${chain}, the round's old commitments and its pinned reads is ${machine}; ` +
          `the answer has ${response.request_id}${layout.machineRequestId === undefined ? "" : `, the proof ${proved}`}`,
      );
    }
    if (response.records.length !== layout.records.length) {
      throw new ProtocolError(`${circuit}: the answer carries ${response.records.length} records; under ${layout.state}-held state the manifest gives ${layout.records.length}`);
    }
    return {
      circuit,
      state: layout.state,
      namespace: ns,
      requestId: chain,
      machineRequestId: machine,
      vkHash: response.vk_hash,
      oldCommitments,
      newCommitments,
      reads,
      stateArgs: stateModule(layout.state).stateArgs(circuit, response, layout.records.map((k) => newCommitments[k]!)),
      signatures: response.signatures,
      proof: response.proof,
      publicInputs: response.public_inputs,
    };
  }
}
