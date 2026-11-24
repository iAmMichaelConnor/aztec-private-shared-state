// The Monty Hall game of monty.ts with the operator and the player in two
// wallets, each its own PXE holding only its own account's keys: the same
// steps and checks, and the Game note that start_game sends the player is
// delivered between PXEs (examples/monty-hall/README.md, "The contract's
// state"). scenarios/README.md lists what differs.
import type { Scenario, Step } from "../scenario.ts";
import type { LandedTx } from "../steps/tx.ts";
import { scenario as monty } from "./monty.ts";

/** Whether a step is a landed transaction calling `method`. */
export const isLandedTx = (step: Step, method: string): step is LandedTx => "tx" in step && step.tx === method && !step.drop && !step.simulationRefused;

// How many note hashes start_game pushes when the player's wallet is not the
// operator's: the game-state note and the player's Game note, as in one
// wallet, and the operator's handshake note. The operator's PXE has no
// tagging hook and does not hold the player's keys, so the delivery is not a
// self-send and the PXE's default tagging strategy, a non-interactive
// handshake with the standard handshake registry, runs inside the same
// transaction.
const START_GAME_NOTE_HASHES = 3;

const steps: Step[] = monty.steps.map((step) => (isLandedTx(step, "start_game") ? { ...step, noteHashes: START_GAME_NOTE_HASHES } : step));

export const scenario: Scenario = {
  ...monty,
  wallets: { operator: ["operator"], player: ["player"] },
  // No wallet registers a sender: the player's PXE finds the Game note
  // through the operator's handshake, which it discovers in its sync.
  senders: [],
  steps,
};
