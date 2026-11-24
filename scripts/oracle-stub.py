#!/usr/bin/env python3
"""Answer nargo's TACEO_store foreign calls with an empty result.

Plain `nargo execute` has no MPC driver to take the shares a round circuit
hands to TACEO_store; this loopback JSON-RPC server acknowledges each call
and stores nothing. Any other foreign call is refused, so a circuit that
calls an unexpected oracle fails its execution.

Usage: oracle-stub.py [PORT]   (PORT 0, the default, picks a free port)
Prints the server URL on the first line of stdout, then serves until it is
killed. Request shape: Noir 1.0.0 tooling/nargo/src/foreign_calls/rpc.rs.
"""

from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import sys

ALLOWED = {"TACEO_store"}
MAX_BODY = 1 << 20


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_POST(self):
        request_id = None
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= MAX_BODY:
                raise ValueError("bad length")
            request = json.loads(self.rfile.read(length))
            request_id = request.get("id")
            if request.get("method") != "resolve_foreign_call":
                error = (-32601, "unknown RPC method")
            else:
                call = request["params"][0]
                if call.get("function") in ALLOWED:
                    error = None
                else:
                    error = (-32601, f"oracle {call.get('function')!r} is not stubbed")
        except (ValueError, KeyError, IndexError, TypeError, AttributeError):
            error = (-32700, "malformed oracle request")
        response = {"jsonrpc": "2.0", "id": request_id}
        if error:
            print(f"oracle-stub: {error[1]}", file=sys.stderr, flush=True)
            response["error"] = {"code": error[0], "message": error[1]}
        else:
            response["result"] = {"values": []}
        data = json.dumps(response).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def main(argv):
    port = int(argv[0]) if argv else 0
    server = HTTPServer(("127.0.0.1", port), Handler)
    print(f"http://127.0.0.1:{server.server_port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
