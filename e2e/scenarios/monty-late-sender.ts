// The game of monty-registered-sender.ts with the operator registered as a
// sender only after start_game is mined: the player's PXE first syncs the
// contract and must not find the Game note (a simulated choose_door is
// refused), then, once the operator is registered, rescans and finds it at
// choose_door (examples/monty-hall/README.md, "The contract's state").
// scenarios/README.md lists what differs.
import type { Scenario, Step } from "../scenario.ts";
import { addressTagged, REGISTER_OPERATOR } from "./monty-registered-sender.ts";
import { isLandedTx } from "./monty-two-wallets.ts";

// The message aztec-nr's get_note fails with when the caller's PXE holds no note at the slot.
const NO_NOTE = "Failed to get a note";

export const scenario: Scenario = {
  // fresh accounts (addressTagged): no earlier handshake lets the player's
  // PXE find the Game note before the registration
  ...addressTagged,
  steps: addressTagged.steps.flatMap((step): Step[] =>
    isLandedTx(step, "choose_door")
      ? [{ tx: step.tx, from: step.from, args: step.args, what: "choose_door before the player knows the operator", simulationRefused: [NO_NOTE] }, REGISTER_OPERATOR, step]
      : [step],
  ),
};
