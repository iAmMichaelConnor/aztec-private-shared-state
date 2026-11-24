// Loaded into the local network's Node processes by e2e/run.sh
// (NODE_OPTIONS=--import): every server that listens on a TCP port without
// naming a host binds 127.0.0.1 instead of every interface. The pinned
// @aztec-labs/aztec CLI starts its node RPC and admin servers with no host and
// has no option for one, and those ports serve the node's debug API (mining,
// time warp) without authentication. A listen that names a host, a Unix
// socket path or a handle is left as it is.
import net from "node:net";

const LOOPBACK = "127.0.0.1";
const listen = net.Server.prototype.listen;
const isPort = (x) => typeof x === "number" || (typeof x === "string" && /^\d+$/.test(x));

net.Server.prototype.listen = function (...args) {
  const [first] = args;
  if (first !== null && typeof first === "object") {
    // listen(options[, callback]), or listen(handle, ...)
    if (!("fd" in first) && !("_handle" in first) && first.path === undefined && first.host === undefined) {
      args[0] = { ...first, host: LOOPBACK };
    }
  } else if (first === undefined || typeof first === "function") {
    // listen([callback]): an ephemeral port
    args.splice(0, first === undefined ? 1 : 0, 0, LOOPBACK);
  } else if (isPort(first) && typeof args[1] !== "string") {
    // listen(port[, backlog][, callback])
    args.splice(1, 0, LOOPBACK);
  }
  return listen.apply(this, args);
};
