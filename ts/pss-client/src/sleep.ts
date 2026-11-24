// A wait that an AbortSignal can cut short (rejecting with its reason).

/** Wait `ms`, or reject with `signal`'s reason once it aborts. A wait that
 * ends leaves no listener on the signal (the relayer's loop and pollResult
 * wait on one signal many times). */
export function sleep(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise<void>((resolve, reject) => {
    if (signal?.aborted) return reject(signal.reason);
    const abort = () => {
      clearTimeout(t);
      reject(signal!.reason);
    };
    const t = setTimeout(() => {
      signal?.removeEventListener("abort", abort);
      resolve();
    }, ms);
    signal?.addEventListener("abort", abort, { once: true });
  });
}
