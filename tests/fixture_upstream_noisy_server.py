"""A real MCP-shaped stdio upstream that, unlike ``fixture_upstream_server.py``,
deliberately writes assorted NON-protocol lines to stdout before each valid
JSON-RPC response -- exactly the reported repro: a stray ``DEBUG:``
banner line, other free text, and a bare JSON scalar/array, all mixed onto
the same stdout stream the JSON-RPC responses are read from. Real MCP
servers commonly do this (startup banners, debug logging that wasn't routed
to stderr, etc.); the proxy must survive it without crashing and without
ever mistaking a noisy line for the actual response.

No network, synthetic only."""

import json
import sys


def main() -> None:
    for raw_line in sys.stdin:
        line = raw_line.rstrip("\r\n")
        if not line.strip():
            continue
        message = json.loads(line)

        # Noisy, non-protocol lines written to the SAME stdout stream the
        # real JSON-RPC response is read from -- must never crash the
        # reader and must never be mistaken for the response.
        sys.stdout.write("DEBUG: starting request handler\n")
        sys.stdout.write("this is not json at all\n")
        sys.stdout.write(json.dumps(42) + "\n")  # bare scalar
        sys.stdout.write(json.dumps(["a", "b"]) + "\n")  # bare array
        sys.stdout.flush()

        response = {
            "jsonrpc": "2.0",
            "id": message.get("id"),
            "result": {
                "content": [{"type": "text", "text": "fixture upstream response"}],
                "received_raw": line,
            },
        }
        sys.stdout.write(json.dumps(response) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
