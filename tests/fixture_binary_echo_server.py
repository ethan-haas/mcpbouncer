"""A raw-byte-level MCP-shaped stdio upstream for the E3 (CRLF framing)
regression test.

Unlike ``fixture_upstream_server.py`` (which uses Python's text-mode
``sys.stdin`` -- itself subject to universal-newlines translation on read,
which would silently absorb any injected ``\\r`` before this fixture could
ever observe it), this fixture reads and writes RAW BYTES via
``sys.stdin.buffer`` / ``sys.stdout.buffer`` so it can truthfully report
whether the line it received on the wire was CRLF- or LF-terminated, and so
its own reply is unambiguously LF-only (no local text-mode translation can
inject a \\r into what this fixture emits).
"""

import json
import sys


def main() -> None:
    stdin = sys.stdin.buffer
    stdout = sys.stdout.buffer
    while True:
        raw = stdin.readline()
        if not raw:
            break
        had_cr = b"\r" in raw
        line = raw.rstrip(b"\r\n")
        if not line.strip():
            continue
        message = json.loads(line.decode("utf-8"))
        response = {
            "jsonrpc": "2.0",
            "id": message.get("id"),
            "result": {
                "content": [{"type": "text", "text": "fixture upstream response"}],
                "request_line_had_cr": had_cr,
            },
        }
        out = json.dumps(response).encode("utf-8") + b"\n"
        stdout.write(out)
        stdout.flush()


if __name__ == "__main__":
    main()
