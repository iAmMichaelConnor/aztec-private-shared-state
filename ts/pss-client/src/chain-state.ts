// Chain-held state on the client side: the StateModule `chainState` (the
// answer's records become the sealed thirds the result call carries, and
// `apply` logs them) and the codec of that sealed-thirds log
// (pss_public_contract chain_state.nr; sidecar-tip state/chain.rs):
//
//   sealed[i][t]       = recordFields(records[t].c[i])   ([key id, ct..., tag])
//   sealed log tag     = compute_log_tag(chain_request_id, PSS_STATE)
//   sealed log         = [tag, new_commitments[W], sealed[3][T][L]]
//
// Chain-held state is opt-in, for small fixed-size states; nothing outside
// this module and state.ts's lookup names it.

import { Fr } from "@aztec-labs/aztec.js/fields";
import { computeLogTag } from "@aztec-labs/stdlib/hash";

import { ProtocolError } from "./errors.ts";
import { fieldBigInt, fieldHex, type FieldHexString, type FieldLike } from "./field.ts";
import { stateOf } from "./manifest.ts";
import { recordFields } from "./records.ts";
import type { StateModule } from "./state.ts";
import { NODES } from "./wire.ts";

/** Chain-held state: every chain-held output comes back as a record whose
 * three thirds the result call carries (`sealed`, node by node, output by
 * output) and `apply` logs for the nodes to reload. Record t is the t-th
 * chain-held output, sealed under that output's new commitment (in a round
 * that also writes node-held keys, not the t-th new commitment; sidecar-tip
 * `TipManifest::sealed_records`). Its state arguments are the thirds,
 * `sealed[i][t]`. */
export const chainState: StateModule = {
  holder: "chain",
  records: (m) => m.outputs.flatMap((o, k) => (stateOf(m, o.STORE) === "chain" ? [k] : [])),
  stateArgs(circuit, response, recordCommitments) {
    response.records.forEach((r, t) => {
      if (r.note_hash !== recordCommitments[t]) {
        throw new ProtocolError(`${circuit}: record ${t} is sealed under ${r.note_hash}, not its output's new commitment ${recordCommitments[t]}`);
      }
    });
    const sealed: FieldHexString[][][] = [];
    let L: number | undefined;
    for (let i = 0; i < NODES; i++) {
      sealed.push(
        response.records.map((r, t) => {
          let f: bigint[];
          try {
            f = recordFields(r.c[i]!);
          } catch (e) {
            throw new ProtocolError(`record ${t}, node ${i}: ${(e as Error).message}`);
          }
          if (L === undefined) L = f.length;
          if (f.length !== L) throw new ProtocolError(`record ${t}, node ${i}: ${f.length} fields, another third has ${L}`);
          return f.map((x) => fieldHex(x));
        }),
      );
    }
    return sealed;
  },
  resultArgs: (sealed) => [sealed.map((node) => node.map((third) => third.map((x) => new Fr(BigInt(x)))))],
};

// ---- the sealed-thirds log ----

// PSS_STATE, the u32 separator of the sealed-thirds log's tag that `apply`
// emits in state mode chain: 0x50535302, ASCII "PSS" and index 2, the value
// of the contract library's chain_state.nr, sidecar-tip's state/chain.rs and
// testvectors/log_tags.json. A reader that tags with another value finds no
// state logs.
export const PSS_STATE = 0x50535302;

/** The tag of the sealed-thirds log of chain request `chainRequestId`'s
 * apply: `compute_log_tag(request_id, PSS_STATE)`. */
export async function computeSealedLogTag(chainRequestIdValue: FieldLike): Promise<Fr> {
  return computeLogTag(new Fr(fieldBigInt(chainRequestIdValue, "chain_request_id")), PSS_STATE as never);
}

/** A sealed-thirds log, read: the new commitments, then `sealed[i][t]`. */
export interface SealedLog {
  tag: FieldHexString;
  newCommitments: FieldHexString[];
  /** `sealed[i][t]`: node i's third of chain-held output t. */
  sealed: FieldHexString[][][];
}

/** Read a sealed-thirds log `[tag, new_commitments[W], sealed[3][T][L]]`
 * (chain_state.nr's emit_state_log, from apply_round and apply_init: node by
 * node, output by output), for W new
 * commitments and T thirds of L fields per node. With `chainRequestId`,
 * check that the tag is computeSealedLogTag of it. ProtocolError otherwise. */
export async function parseSealedLog(
  fields: readonly FieldLike[],
  shape: { W: number; T: number; L: number },
  chainRequestIdValue?: FieldLike,
): Promise<SealedLog> {
  const { W, T, L } = shape;
  const want = 1 + W + NODES * T * L;
  if (fields.length !== want) throw new ProtocolError(`sealed log: ${fields.length} fields, expected ${want} (W=${W}, T=${T}, L=${L})`);
  const hex = fields.map((x, i) => {
    try {
      return fieldHex(x, `fields[${i}]`);
    } catch (e) {
      throw new ProtocolError(`sealed log: ${(e as Error).message}`);
    }
  });
  if (chainRequestIdValue !== undefined) {
    const tag = fieldHex((await computeSealedLogTag(chainRequestIdValue)).toBigInt());
    if (tag !== hex[0]) throw new ProtocolError(`sealed log: tag ${hex[0]} is not the state tag ${tag} of ${fieldHex(chainRequestIdValue)}`);
  }
  let at = 1 + W;
  const sealed: FieldHexString[][][] = [];
  for (let i = 0; i < NODES; i++) {
    const node: FieldHexString[][] = [];
    for (let t = 0; t < T; t++, at += L) node.push(hex.slice(at, at + L));
    sealed.push(node);
  }
  return { tag: hex[0]!, newCommitments: hex.slice(1, 1 + W), sealed };
}
