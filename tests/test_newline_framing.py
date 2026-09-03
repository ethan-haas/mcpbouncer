"""E3 -- MEDIUM: gate 5 transparency requires forwarded messages be
byte-identical except declared redactions. The proxy must never inject a
``\\r`` that the source did not have, in EITHER direction:

  (a) proxy -> upstream, via ``StdioTransport.send_raw`` (used by
      ``Bouncer.handle_raw``)
  (b) proxy -> client, via ``Bouncer.run_stdio``'s stdout

Both are driven through a REAL subprocess and asserted on raw bytes read
off the actual OS pipe -- not through Python's own (translating) text-mode
stdio, which would hide the bug being regression-tested.
"""

import json
import os
import subprocess
import sys

from mcpbouncer.audit import AuditLog
from mcpbouncer.engine import Engine
from mcpbouncer.proxy import Bouncer, spawn_upstream

FIXTURE_DIR = os.path.dirname(os.path.abspath(__file__))
BINARY_FIXTURE = os.path.join(FIXTURE_DIR, "fixture_binary_echo_server.py")


def test_proxy_to_upstream_send_raw_injects_no_cr(policy, tmp_path):
    """(a) the proxy's write into the upstream's stdin must not translate
    the trailing "\\n" into "\\r\\n" -- confirmed by asking the real
    subprocess upstream whether the line it read off its own raw byte
    stream contained a "\\r"."""
    upstream = spawn_upstream([sys.executable, BINARY_FIXTURE])
    try:
        engine = Engine(policy)
        audit = AuditLog(tmp_path / "audit.jsonl")
        audit.reset()
        bouncer = Bouncer(engine=engine, audit=audit, upstream=upstream)

        request_obj = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "files__read_file", "arguments": {"path": "/srv/app/ok.txt"}},
        }
        raw_line = json.dumps(request_obj)

        out = bouncer.handle_raw(raw_line)
        assert out is not None
        response = json.loads(out)
        assert response["result"]["request_line_had_cr"] is False, (
            "the upstream subprocess observed a \\r on the raw byte stream it read -- "
            "the proxy injected CRLF framing on the write to upstream stdin"
        )
    finally:
        upstream.close()


def test_run_stdio_to_client_injects_no_cr(policy_path, tmp_path):
    """(b) the real end-to-end path: spawn `mcpbouncer proxy` itself as a
    subprocess, talk to it with RAW BINARY pipes from the test process
    (bypassing any of Python's own text-mode translation on the test
    side), send one LF-terminated request line, and assert the response
    line handed back has no injected \\r."""
    audit_path = tmp_path / "proxy-audit.jsonl"
    proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "mcpbouncer",
            "proxy",
            "--policy",
            str(policy_path),
            "--audit-log",
            str(audit_path),
            "--upstream",
            sys.executable,
            BINARY_FIXTURE,
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        bufsize=0,  # unbuffered, raw bytes -- no text-mode wrapper at all
    )
    try:
        request_obj = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "files__read_file", "arguments": {"path": "/srv/app/ok.txt"}},
        }
        raw_bytes = json.dumps(request_obj).encode("utf-8") + b"\n"
        assert proc.stdin is not None and proc.stdout is not None
        proc.stdin.write(raw_bytes)
        proc.stdin.flush()

        response_bytes = proc.stdout.readline()
        assert response_bytes, f"no response from proxy subprocess; stderr={proc.stderr.read()!r}"
        assert b"\r" not in response_bytes, (
            f"proxy->client response line was CRLF-framed, not LF-only: {response_bytes!r}"
        )
        assert response_bytes.endswith(b"\n")

        response = json.loads(response_bytes.rstrip(b"\r\n").decode("utf-8"))
        assert response["result"]["content"][0]["text"] == "fixture upstream response"
        # The upstream subprocess itself must also have seen an LF-only
        # request line off the wire -- proves both directions are clean.
        assert response["result"]["request_line_had_cr"] is False
    finally:
        proc.stdin.close()
        proc.terminate()
        proc.wait(timeout=5)
