// The game of monty-two-wallets.ts with the operator's wallet tagging every
// message with the address-derived secret (its resolveTaggingSecretStrategy
// hook), so the Game note that start_game sends the player is found only by
// a PXE that knows the operator as a sender: the player's wallet registers
// the operator just before start_game (examples/monty-hall/README.md, "The
// contract's state"). scenarios/README.md lists what differs.
import type { Scenario, Step } from "../scenario.ts";
import { scenario as monty } from "./monty.ts";
import { isLandedTx, scenario as twoWallets } from "./monty-two-wallets.ts";

/** The player's wallet registers the operator as a sender. */
export const REGISTER_OPERATOR: Step = { sender: "operator", wallet: "player", what: "the player registers the operator" };

/** monty-two-wallets.ts with the address-derived hook on the operator's
 * wallet. start_game pushes the two note hashes of monty.ts (the game-state
 * note and the Game note): no handshake. Fresh accounts: a handshake an
 * earlier scenario of the run left between the initial accounts
 * (monty-two-wallets.ts) would let the player's PXE find the Game note
 * whether or not it registers the operator. */
export const addressTagged: Scenario = { ...twoWallets, tagging: { operator: "address-derived" }, freshAccounts: true, steps: monty.steps };

export const scenario: Scenario = {
  ...addressTagged,
  steps: addressTagged.steps.flatMap((step): Step[] => (isLandedTx(step, "start_game") ? [REGISTER_OPERATOR, step] : [step])),
};
