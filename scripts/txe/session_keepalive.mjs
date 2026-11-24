// Keeps a TXE test session alive while its test runs a long unconstrained
// computation with no oracle call. Used by serve.mjs; it has no Aztec imports,
// so it loads without the TXE.
//
// The pinned TXE (@aztec-labs/txe 6.0.0, dest/rpc_server.js) tags each HTTP
// socket with the session id of its first oracle call and disposes that
// session when the socket closes. Two idle limits close a test's socket
// before the test ends:
// - Node's HTTP server destroys a keep-alive socket after
//   `server.keepAliveTimeout` (5 s by default) without a request, and after
//   `server.timeout` (5 min in the TXE binary) without any traffic.
//   `listen` turns both off: the runner owns the server and stops it at the
//   end of the run.
// - The pinned nargo's oracle client (jsonrpsee 0.26 over hyper-util 0.1.20)
//   drops a pooled connection that has been idle for more than 90 s
//   (hyper-util's default `pool_idle_timeout`) when it sends the next call,
//   then sends that call on a new connection. nargo cannot be configured.
//   `keepIdleSessions` therefore keeps a session while another socket that
//   carried its calls is open, and delays the disposal of a session whose
//   only socket closes after a long idle period until its next call.
//
// The TXE tags a socket only after the first call on it has ended. If the
// socket closed during that call, its close handler is never added and the
// session would stay until the server stops. `keepIdleSessions` therefore
// watches each socket that carried a call itself, and treats a socket that
// had closed by the end of its first call as a close.

import { AsyncLocalStorage } from "node:async_hooks";
import http from "node:http";
import { closeSync, writeSync } from "node:fs";

// SESSION_IDLE_MS (60 s) and RECONNECT_GRACE_MS (30 s) decide when a closed
// socket keeps its session. The idle limit must stay below nargo's 90 s pool
// expiry, so that a socket nargo drops after idling is recognised; the grace
// is how long such a session waits for nargo's next call on a new connection.
// A shorter grace can lose a session in a slow test; a longer one only keeps
// abandoned sessions in memory longer.
/** Idle time after which a socket close may be nargo's pool expiry (< 90 s). */
export const SESSION_IDLE_MS = 60_000;
/** How long such a session waits for its next call before it is disposed. */
export const RECONNECT_GRACE_MS = 30_000;

// The socket of the HTTP request being handled (set by `listen`).
const requestSocket = new AsyncLocalStorage();

/** The socket of the current request, or undefined outside `listen`. */
export function currentSocket() {
  return requestSocket.getStore();
}

/**
 * Wraps `dispatcher.resolve_foreign_call` and `dispatcher.disposeSession` (a
 * TXEDispatcher or TXEDispatcherPool) in place. Each call records the socket
 * that carries it. When a socket that carried calls of a session closes (the
 * TXE's close handler or the wrapper's own; a socket can have both):
 * - if another socket that carried a call of the session is still open, the
 *   session stays; that socket's close asks again (nargo's stale pooled
 *   connection can close after the call on its replacement has finished);
 * - else, if the session has had no call for `idleMs` or more, disposal
 *   waits `graceMs` and the session's next call cancels it (the stale
 *   connection closed before the call on its replacement);
 * - else the session is disposed at once, as the TXE does (the end of a
 *   test, or nargo abandoned a call).
 * A request to dispose a session that the wrapper has already disposed is
 * ignored (TXEDispatcherPool throws for a session it no longer maps); a new
 * call with that session id starts it again.
 */
export function keepIdleSessions(dispatcher, options = {}) {
  const {
    idleMs = SESSION_IDLE_MS,
    graceMs = RECONNECT_GRACE_MS,
    now = Date.now,
    setTimer = setTimeout,
    clearTimer = clearTimeout,
    socket = currentSocket,
    logger,
  } = options;
  for (const name of ["resolve_foreign_call", "disposeSession"]) {
    if (typeof dispatcher?.[name] !== "function") {
      throw new Error(
        `The TXE dispatcher has no ${name}; check the pinned @aztec-labs/txe`,
      );
    }
  }
  const resolve = dispatcher.resolve_foreign_call.bind(dispatcher);
  const dispose = dispatcher.disposeSession.bind(dispatcher);
  // session id -> { sockets (that carried its calls), last (end of the last
  // call), timer (deferred disposal) }
  const sessions = new Map();
  // Ids of sessions that the wrapper disposed and that have had no call since.
  const disposed = new Set();
  // Sockets whose close the wrapper watches -> ids of the sessions they carried.
  const watched = new WeakMap();
  let warned = false;

  function disposeNow(sessionId) {
    sessions.delete(sessionId);
    disposed.add(sessionId);
    try {
      return Promise.resolve(dispose(sessionId)).catch((err) =>
        logger?.warn(`Session ${sessionId} dispose failed`, err),
      );
    } catch (err) {
      logger?.warn(`Session ${sessionId} dispose failed`, err);
      return Promise.resolve();
    }
  }

  // Called when a socket that carried calls of `sessionId` has closed.
  function socketClosed(sessionId) {
    if (disposed.has(sessionId)) {
      logger?.debug(`Session ${sessionId} already disposed`);
      return Promise.resolve();
    }
    const state = sessions.get(sessionId);
    if (state === undefined) {
      return disposeNow(sessionId);
    }
    if (state.timer !== undefined) {
      return Promise.resolve();
    }
    for (const s of state.sockets) {
      if (s.destroyed) {
        state.sockets.delete(s);
      }
    }
    if (state.sockets.size > 0) {
      logger?.debug(`Session ${sessionId} continues on another connection`);
      return Promise.resolve();
    }
    if (now() - state.last < idleMs) {
      return disposeNow(sessionId);
    }
    state.timer = setTimer(() => {
      state.timer = undefined;
      if (sessions.get(sessionId) === state) {
        void disposeNow(sessionId);
      }
    }, graceMs);
    logger?.debug(
      `Session ${sessionId} socket closed after idling; disposal deferred`,
    );
    return Promise.resolve();
  }

  // Watches `carrier` after a call of `sessionId` on it has ended, as the TXE
  // does, but also when the socket closed during that call.
  function watch(carrier, sessionId) {
    let ids = watched.get(carrier);
    if (ids === undefined) {
      ids = new Set();
      watched.set(carrier, ids);
      carrier.once("close", () => {
        for (const id of ids) {
          void socketClosed(id);
        }
      });
    }
    if (ids.has(sessionId)) {
      return;
    }
    ids.add(sessionId);
    if (carrier.destroyed) {
      void socketClosed(sessionId);
    }
  }

  dispatcher.resolve_foreign_call = async (callData) => {
    const sessionId = callData.session_id;
    disposed.delete(sessionId);
    let state = sessions.get(sessionId);
    if (state === undefined) {
      state = { sockets: new Set(), last: now(), timer: undefined };
      sessions.set(sessionId, state);
    }
    if (state.timer !== undefined) {
      clearTimer(state.timer);
      state.timer = undefined;
      logger?.debug(`Session ${sessionId} resumed on a new connection`);
    }
    const carrier = socket();
    if (carrier !== undefined) {
      state.sockets.add(carrier);
    } else if (!warned) {
      warned = true;
      logger?.warn("Oracle call without a request socket; check serve.mjs");
    }
    try {
      return await resolve(callData);
    } finally {
      state.last = now();
      if (carrier !== undefined) {
        watch(carrier, sessionId);
      }
    }
  };

  dispatcher.disposeSession = socketClosed;
  return dispatcher;
}

/**
 * Serves `callback` on 127.0.0.1:`port` with no keep-alive timeout and no
 * socket inactivity timeout, and makes each request's socket available to
 * `currentSocket`. Resolves to the listening server.
 */
export function listen(callback, port) {
  const server = http.createServer((req, res) =>
    requestSocket.run(req.socket, () => callback(req, res)),
  );
  server.keepAliveTimeout = 0;
  server.timeout = 0;
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen({ host: "127.0.0.1", port }, () => resolve(server));
  });
}

/** Acknowledge a bound listener only to the parent that supplied this pipe.
 * Direct launcher use without the optional startup channel stays supported.
 */
export function reportReady(server, env = process.env) {
  if (env.TXE_READY_FD === undefined) return;
  const fd = Number(env.TXE_READY_FD);
  if (!Number.isInteger(fd) || fd < 0 || !env.TXE_READY_TOKEN) {
    throw new Error("Invalid TXE startup channel");
  }
  const address = server.address();
  if (!server.listening || address?.address !== "127.0.0.1" || !address.port) {
    throw new Error("TXE startup acknowledgement requires a loopback listener");
  }
  try {
    writeSync(
      fd,
      JSON.stringify({
        port: address.port,
        pid: process.pid,
        token: env.TXE_READY_TOKEN,
      }) + "\n",
    );
  } finally {
    closeSync(fd);
  }
}
