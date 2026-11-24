// The orchestrator's pause or resume of scheduling at the step's place, on
// its admin socket (`sidecar-orchestrator pause` / `resume`, what an operator
// runs around a node replacement): while paused, no execute, REGISTER or
// DISABLE session starts and no scheduler computes, so requests queued then
// wait. A resume runs the registry check first and is refused, still
// paused, while the nodes' registries differ.
import { execFileSync } from "node:child_process";
import { join } from "node:path";

import { defineKind, type Common } from "../engine/kind.ts";
import { check } from "../engine/scope.ts";

export interface TipPauseStep extends Common {
  tipPause: "pause" | "resume";
}

/** Run `sidecar-orchestrator <command>` against the run's orchestrator config
 * and parse its one JSON answer line. */
export function orchestratorAdmin(command: "pause" | "resume" | "status"): { ok: boolean; paused: boolean; refusal?: unknown } {
  const bin = process.env.E2E_ORCH_BIN;
  const cfg = process.env.E2E_CFG;
  check(bin !== undefined && cfg !== undefined, "E2E_ORCH_BIN and E2E_CFG are unset (run.sh exports them)");
  let out: string;
  try {
    out = execFileSync(bin, ["--config", join(cfg, "orchestrator.toml"), command], { encoding: "utf8", timeout: 900_000 });
  } catch (e) {
    const err = e as { stdout?: string; stderr?: string };
    throw new Error(`sidecar-orchestrator ${command} failed: ${err.stdout ?? ""}${err.stderr ?? ""}`, { cause: e });
  }
  return JSON.parse(out.trim().split("\n").at(-1)!) as { ok: boolean; paused: boolean; refusal?: unknown };
}

export default defineKind<TipPauseStep>({
  key: "tipPause",
  check(step) {
    check(step.tipPause === "pause" || step.tipPause === "resume", `tipPause: pause or resume, not ${step.tipPause}`);
    return { fields: ["tipPause"] };
  },
  async run(ctx, step) {
    const answer = orchestratorAdmin(step.tipPause);
    check(answer.ok && answer.paused === (step.tipPause === "pause"), `orchestrator ${step.tipPause}: ${JSON.stringify(answer)}`);
    ctx.logger.info(`orchestrator ${step.tipPause === "pause" ? "paused between rounds" : "resumed"}`);
  },
});
