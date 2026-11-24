// The step registry: one module per kind. A new kind is a module here and a
// member of `Step` in ../scenario.ts; the engine knows no kind by name.
import type { AnyKind } from "../engine/kind.ts";
import redeem from "./redeem.ts";
import reorg from "./reorg.ts";
import disable from "./disable.ts";
import fetch from "./fetch.ts";
import keeper from "./keeper.ts";
import letKind from "./let.ts";
import log from "./log.ts";
import advance from "./advance.ts";
import register from "./register.ts";
import relayer from "./relayer.ts";
import restore from "./restore.ts";
import round from "./round.ts";
import sameBlock from "./same-block.ts";
import sender from "./sender.ts";
import tipAttempt from "./tip-attempt.ts";
import tipAudit from "./tip-audit.ts";
import tipEncKey from "./tip-enc-key.ts";
import tipExit from "./tip-exit.ts";
import tipFund from "./tip-fund.ts";
import tipInit from "./tip-init.ts";
import tipLand from "./tip-land.ts";
import tipNotice from "./tip-notice.ts";
import tipOutbid from "./tip-outbid.ts";
import tipOutcome from "./tip-outcome.ts";
import tipPause from "./tip-pause.ts";
import tipRecover from "./tip-recover.ts";
import tipReplaceNode from "./tip-replace-node.ts";
import tipRequest from "./tip-request.ts";
import tipResult from "./tip-result.ts";
import tipUpgrade from "./tip-upgrade.ts";
import tx from "./tx.ts";
import view from "./view.ts";

export const registry: ReadonlyMap<string, AnyKind> = new Map(
  [register, disable, round, tx, fetch, restore, sender, tipInit, tipEncKey, tipRequest, sameBlock, tipResult, tipAttempt, tipOutcome, tipNotice, tipRecover, tipAudit, tipLand, tipOutbid, tipExit, tipFund, tipPause, tipReplaceNode, tipUpgrade, redeem, view, keeper, relayer, advance, reorg, letKind, log].map((k) => [k.key, k]),
);
