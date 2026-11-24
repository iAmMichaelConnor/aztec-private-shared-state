// The abortable wait (src/sleep.ts): it ends, it rejects with the signal's
// reason, and a wait that ends leaves no listener on its signal.

import assert from "node:assert/strict";
import { getEventListeners } from "node:events";
import { describe, test } from "node:test";

import { sleep } from "../src/sleep.ts";

describe("sleep", () => {
  test("waits out on one signal many times without piling up listeners", async () => {
    const controller = new AbortController();
    for (let i = 0; i < 20; i++) await sleep(0, controller.signal);
    assert.equal(getEventListeners(controller.signal, "abort").length, 0);
  });

  test("rejects with the signal's reason, at once when it already aborted", async () => {
    const controller = new AbortController();
    const waiting = sleep(60_000, controller.signal);
    controller.abort(new Error("stopped"));
    await assert.rejects(waiting, /stopped/);
    await assert.rejects(sleep(60_000, controller.signal), /stopped/);
  });
});
