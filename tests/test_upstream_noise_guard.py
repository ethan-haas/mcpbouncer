"""Upstream-inbound non-JSON stdout must not break framing.

r7-e1 -- MEDIUM (availability/robustness, fails closed, no leak): the
upstream-response read path (``StdioTransport.recv`` / ``recv_raw``, used
from ``Bouncer.handle_raw`` / ``handle_request``) did an UNGUARDED
``json.loads`` on the next line the upstream wrote to stdout. Any real MCP
server commonly writes stdout lines that are not a JSON-RPC response at
all -- a stray ``DEBUG:``/log/startup-banner line, other non-JSON text, or
a bare JSON scalar/array (``42``, ``"hi"``, ``true``, ``null``, ``[...]``).
Such a line raised ``json.JSONDecodeError`` (non-JSON text) or
``TypeError``/``AttributeError`` (a non-dict JSON value has no ``.get``)
straight out of the transport, killing the whole proxy process -- one
noisy upstream line took down the gate for the entire session, not just
the one call.

Fixed by making ``StdioTransport.recv``/``recv_raw`` skip (never return,
never raise on) any line that isn't valid JSON or that parses to something
other than a JSON object, and keep reading on the same connection until
either a genuine JSON-RPC object line arrives or the upstream closes. A
skipped line is, by construction, never scanned for redaction and never
forwarded to the client as a ``tools/call`` result -- it is simply not a
protocol message. This is the upstream-inbound analog of the client-inbound
client-inbound malformed-shape guard.
"""

import json
import os
import sys

from mcpbouncer.audit import AuditLog
from mcpbouncer.engine import Engine
from mcpbouncer.proxy import Bouncer, FunctionTransport, StdioTransport, spawn_upstream

NOISY_FIXTURE_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "fixture_upstream_noisy_server.py"
)


def _make_call(call_id: int, path: str = "/srv/app/ok.txt") -> str:
    return json.dumps(
        {
            "jsonrpc": "2.0",
            "id": call_id,
            "method": "tools/call",
            "params": {"name": "files__read_file", "arguments": {"path": path}},
        }
    )


# ---------------------------------------------------------------------------
# End-to-end repro against a real subprocess: a DEBUG banner (plus other
# non-JSON / non-object noise) written before the valid response must not
# crash the session, and the pending call must still get its correct reply.
# ---------------------------------------------------------------------------


def test_noisy_upstream_banner_does_not_crash_and_call_still_gets_correct_response(policy, tmp_path):
    upstream = spawn_upstream([sys.executable, NOISY_FIXTURE_PATH])
    try:
        engine = Engine(policy)
        audit = AuditLog(tmp_path / "audit.jsonl")
        audit.reset()
        bouncer = Bouncer(engine=engine, audit=audit, upstream=upstream)

        raw_line = _make_call(1)
        # Must not raise -- this is the actual crash repro from the audit.
        out = bouncer.handle_raw(raw_line)

        assert out is not None, "a noisy upstream line must never silence the pending response"
        parsed = json.loads(out)
        assert "error" not in parsed, f"unexpected error response: {parsed}"
        assert parsed["result"]["content"][0]["text"] == "fixture upstream response"
        assert parsed["result"]["received_raw"] == raw_line
    finally:
        upstream.close()


def test_session_survives_noisy_line_and_a_following_call_also_works(policy, tmp_path):
    """The session-liveness half of the repro: after the noisy line is
    absorbed by call 1, a SECOND call on the same live connection must
    also route correctly -- proving the reader wasn't left mid-stream on
    stale/skipped bytes."""
    upstream = spawn_upstream([sys.executable, NOISY_FIXTURE_PATH])
    try:
        engine = Engine(policy)
        audit = AuditLog(tmp_path / "audit.jsonl")
        audit.reset()
        bouncer = Bouncer(engine=engine, audit=audit, upstream=upstream)

        out1 = bouncer.handle_raw(_make_call(1))
        assert out1 is not None
        assert "error" not in json.loads(out1)

        out2 = bouncer.handle_raw(_make_call(2, path="/srv/app/other.txt"))
        assert out2 is not None
        parsed2 = json.loads(out2)
        assert "error" not in parsed2, f"second call must also succeed: {parsed2}"
        assert parsed2["id"] == 2
        assert parsed2["result"]["content"][0]["text"] == "fixture upstream response"
        assert parsed2["result"]["received_raw"] == _make_call(2, path="/srv/app/other.txt")

        records = audit.read_records()
        rule_ids = [r["rule_id"] for r in records]
        assert rule_ids.count("allow") == 2, "both calls must be individually gated and audited"
    finally:
        upstream.close()


# ---------------------------------------------------------------------------
# Unit-level coverage directly on StdioTransport.recv / recv_raw, using a
# fake ``proc.stdout`` so each noise shape is isolated (no subprocess
# needed) -- non-JSON text, a bare int, a bare string, null, true, and an
# array, each individually.
# ---------------------------------------------------------------------------


class _FakeStdout:
    def __init__(self, lines):
        self._lines = list(lines)

    def readline(self):
        if not self._lines:
            return ""
        return self._lines.pop(0)


class _FakeProc:
    def __init__(self, lines):
        self.stdin = None
        self.stdout = _FakeStdout(lines)


NOISE_LINES = [
    "DEBUG: starting up\n",
    "this is not json at all {{{\n",
    "42\n",
    '"hi"\n',
    "true\n",
    "null\n",
    '["a", "b"]\n',
]


def test_stdio_transport_recv_skips_every_noise_shape_and_finds_the_response():
    valid_response = {"jsonrpc": "2.0", "id": 1, "result": {"ok": True}}
    lines = NOISE_LINES + [json.dumps(valid_response) + "\n"]
    transport = StdioTransport(_FakeProc(lines))

    result = transport.recv()
    assert result == valid_response


def test_stdio_transport_recv_raw_skips_every_noise_shape_and_finds_the_response():
    valid_response = {"jsonrpc": "2.0", "id": 1, "result": {"ok": True}}
    response_text = json.dumps(valid_response)
    lines = NOISE_LINES + [response_text + "\n"]
    transport = StdioTransport(_FakeProc(lines))

    result = transport.recv_raw()
    assert result == response_text


def test_stdio_transport_recv_returns_none_on_eof_after_only_noise():
    """All-noise, then a genuine EOF (readline returns "") -- must return
    None, not hang or raise, once the connection actually closes."""
    transport = StdioTransport(_FakeProc(list(NOISE_LINES)))
    assert transport.recv() is None


def test_stdio_transport_recv_raw_returns_none_on_eof_after_only_noise():
    transport = StdioTransport(_FakeProc(list(NOISE_LINES)))
    assert transport.recv_raw() is None


# ---------------------------------------------------------------------------
# Non-regression: FunctionTransport-based paths and normal (clean) upstream
# behavior are unaffected.
# ---------------------------------------------------------------------------


def test_function_transport_path_unaffected_by_the_fix(policy, tmp_path):
    def fixture_server(message):
        return {
            "jsonrpc": "2.0",
            "id": message.get("id"),
            "result": {"content": [{"type": "text", "text": "clean response"}]},
        }

    engine = Engine(policy)
    audit = AuditLog(tmp_path / "audit.jsonl")
    audit.reset()
    bouncer = Bouncer(engine=engine, audit=audit, upstream=FunctionTransport(fixture_server))

    response = bouncer.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": {"name": "files__read_file", "arguments": {"path": "/srv/app/ok.txt"}},
        }
    )
    assert response["result"]["content"][0]["text"] == "clean response"
