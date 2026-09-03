"""A tiny real MCP-shaped stdio upstream, for a subprocess-based transparency
smoke test. Reads newline-delimited JSON-RPC requests, echoes a canned
result for any tools/call, and exits on EOF. No network, synthetic only.

The response also echoes back the exact raw request line it received
(``received_raw``), so a test can assert byte-identity of what the proxy
forwarded upstream (including a non-ASCII argument value and non-compact
JSON formatting) without any extra plumbing. The reply is deliberately
serialized with json.dumps' DEFAULT (non-compact) separators -- distinct
from mcpbouncer's own compact ``separators=(",", ":")`` -- so a test can
tell a true byte-for-byte pass-through apart from a re-serialize that
happens to reproduce the same bytes by coincidence."""

import json
import sys


def main() -> None:
    for raw_line in sys.stdin:
        line = raw_line.rstrip("\r\n")
        if not line.strip():
            continue
        message = json.loads(line)
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
