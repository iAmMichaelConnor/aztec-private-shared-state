// The tip's state on the client side: one StateModule per state holder a tip
// round's outputs can have (node-held here, chain-held in chain-state.ts),
// and tipStateOf, the one place that reads the holder from a manifest.
// tipResultLayout resolves it once; layouts and result parts carry the
// holder, and the code that reads a result or builds its call asks the
// holder's module (stateModule).

import { chainState } from "./chain-state.ts";
import { stateOf, type QueuedManifest } from "./manifest.ts";
import type { FieldHexString } from "./field.ts";
import { NODES, type ExecuteResponse } from "./wire.ts";

/** Who holds a tip round's output state. */
export type TipStateHolder = "node" | "chain";

/** What a result's parts carry for its state holder, as fields: what the
 * holder's module takes from the answer (stateArgs) and turns into the
 * result call's state arguments (resultArgs), opaque to everything else.
 * Three empty lists under node-held state. */
export type StateArgs = FieldHexString[][][];

/** One tip state holder: what the result of a round depends on where its
 * output state is held. */
export interface StateModule {
  readonly holder: TipStateHolder;
  /** The records a round's answer carries: one per output whose state goes
   * back to the chain, in manifest output order, each as its output's
   * position among the round's outputs (and so among its new
   * commitments). */
  records(m: QueuedManifest): number[];
  /** The answer's records as the parts' state arguments, after checking
   * each against the new commitment of its own output, `recordCommitments[t]`
   * for record t (ProtocolError otherwise). The caller has checked the
   * number of records. */
  stateArgs(circuit: string, response: ExecuteResponse, recordCommitments: readonly FieldHexString[]): StateArgs;
  /** The result call's state arguments in aztec.js form, after the
   * TipResult (defaultProcessResultEncoder), the init's values
   * (defaultInitEncoder) or the outcome result's values
   * (outcomeResultArgs), from the parts' state arguments. */
  resultArgs(stateArgs: StateArgs): unknown[];
}

/** Node-held state: the nodes keep the outputs; the answer carries no
 * records and the result call no thirds. */
const nodeState: StateModule = {
  holder: "node",
  records: () => [],
  stateArgs: () => Array.from({ length: NODES }, () => []),
  resultArgs: () => [],
};

const MODULES = { node: nodeState, chain: chainState } satisfies { readonly [K in TipStateHolder]: StateModule };

/** The state holder of a tip round: chain-held when any output's key is,
 * node-held otherwise. */
export function tipStateOf(m: QueuedManifest): TipStateHolder {
  return m.outputs.some((o) => stateOf(m, o.STORE) === "chain") ? "chain" : "node";
}

/** The module of a tip state holder. */
export function stateModule(holder: TipStateHolder): StateModule {
  return MODULES[holder];
}
