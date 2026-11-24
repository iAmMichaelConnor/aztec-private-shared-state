// An account registered as a sender in one wallet, at the step's place in
// the run: the wallet's PXE then scans the tags of the account's
// address-derived secret from index 0 and re-syncs every contract at its
// next call, so a note the account sent before the registration is found
// too.
import { defineKind, refs, type Common } from "../engine/kind.ts";

export interface SenderStep extends Common {
  /** The account registered as a sender. */
  sender: string;
  /** The wallet that registers it. */
  wallet: string;
}

export default defineKind<SenderStep>({
  key: "sender",
  check(step, s) {
    refs.account(s, step.sender);
    refs.wallet(s, step.wallet);
    return { fields: ["sender", "wallet"] };
  },
  async run(ctx, step) {
    await ctx.network.wallets[step.wallet]!.registerSender(ctx.account(step.sender), step.sender);
    ctx.logger.info(`${step.what ?? "sender"}: wallet ${step.wallet} registered ${step.sender} (${ctx.account(step.sender)}) as a sender`);
  },
});
