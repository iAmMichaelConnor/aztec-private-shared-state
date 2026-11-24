// Starts the pinned TXE server for scripts/txe/noir_txe.py. It does what
// @aztec-labs/txe 6.0.0 dest/bin/index.js does (the package's public
// `@aztec-labs/txe/server` export on 127.0.0.1:$TXE_PORT), except that a test
// session survives a long unconstrained computation between two oracle
// calls; see session_keepalive.mjs. It serves no /status route (nargo and
// the runner do not use one). The installed package is not modified.

// @aztec-labs/foundation 6.0.0 is a dependency of @aztec-labs/txe. package.json
// declares it at the version package-lock.json pins; its logger reads
// LOG_LEVEL as the TXE's bundled copy does.
import { createLogger } from "@aztec-labs/foundation/log";
import { createTXERpcServer } from "@aztec-labs/txe/server";

import { keepIdleSessions, listen, reportReady } from "./session_keepalive.mjs";

// HARDWARE_CONCURRENCY, default "2", copied from dest/bin/index.js so that
// the server behaves as the TXE binary does: the TXE sizes its libuv pool and
// each session's LMDB reader slots to it. It is the upstream default, not a
// cap chosen here; a value in the environment wins. Each test session has its
// own stores in one of the TXE's worker threads, so it does not limit how many
// tests run at once (the runner's test_threads and package_jobs).
process.env.HARDWARE_CONCURRENCY ??= "2";

const logger = createLogger("txe:rpc");
for (const signal of ["SIGTERM", "SIGINT"]) {
  process.on(signal, () => {
    logger.info(`Received ${signal}.`);
    process.exit(0);
  });
}

try {
  logger.info("Setting up TXE...");
  const rpcServer = await createTXERpcServer(logger);
  keepIdleSessions(rpcServer.proxy.handler, { logger });
  const server = await listen(
    rpcServer.getApp().callback(),
    Number(process.env.TXE_PORT ?? 8080),
  );
  reportReady(server);
  logger.info(`TXE listening on port ${server.address().port}`);
} catch (err) {
  console.error(err);
  process.exit(1);
}
