// A tip deployment's relayer stopped or started at the step's place: the
// harness runs one pss-relayer per deployment, and this suspends its
// process (SIGSTOP) once its queue is idle, so it sends nothing until it is
// resumed (SIGCONT), when it reads the queue again as after any pause.
// run.sh resumes every service at teardown, and the driver resumes the
// relayers it stopped when it exits.
import { defineKind, refs, type Common } from "../engine/kind.ts";
import { check, until } from "../engine/scope.ts";
import { processState, relayerPid, relayerStatus, tipOf } from "../engine/tip.ts";

export interface RelayerStep extends Common {
  relayer: "stop" | "start";
  /** The tip deployment (default: the scenario's first). */
  namespace?: string;
}

const stopped = new Set<number>();
process.on("exit", () => {
  for (const pid of stopped) {
    try {
      process.kill(pid, "SIGCONT");
    } catch {
      // gone already
    }
  }
});

export default defineKind<RelayerStep>({
  key: "relayer",
  check(step, s) {
    refs.tip(s, step.namespace);
    check(step.relayer === "stop" || step.relayer === "start", `relayer: stop or start, not ${step.relayer}`);
    return { fields: ["relayer", "namespace"] };
  },
  async run(ctx, step) {
    const tip = tipOf(ctx, step.namespace);
    const pid = relayerPid(ctx, tip);
    const label = step.what ?? `relayer of ${tip.name} ${step.relayer}`;
    if (step.relayer === "stop") {
      // between ticks of an idle queue, so no transaction of it is in flight
      await until(`${label}: the relayer's queue is not idle`, 600, async () => {
        const [s, q] = [await relayerStatus(tip), await tip.queue.snapshot()];
        return q.head === q.tail && s.last?.action === "idle" && s.init?.state !== "pending";
      });
      process.kill(pid, "SIGSTOP");
      stopped.add(pid);
      await until(`${label}: process ${pid} did not stop`, 10, () => processState(pid) === "T");
      ctx.logger.info(`${label}: relayer process ${pid} stopped (SIGSTOP) on an idle queue; it sends nothing until started`);
    } else {
      check(processState(pid) === "T", `${label}: relayer process ${pid} is not stopped`);
      process.kill(pid, "SIGCONT");
      stopped.delete(pid);
      await until(`${label}: the relayer does not answer GET /status`, 60, async () => relayerStatus(tip).then(() => true, () => false));
      ctx.logger.info(`${label}: relayer process ${pid} resumed (SIGCONT), status answering`);
    }
  },
});
