"""End-to-end smoke test: the real StdioTransport / spawn_upstream path
against an actual subprocess (a tiny synthetic fixture server, no network)."""

import os
import sys

from mcpbouncer.audit import AuditLog
from mcpbouncer.engine import Engine
from mcpbouncer.proxy import Bouncer, spawn_upstream


def test_real_subprocess_transport_allowed_call_roundtrips(policy, tmp_path):
    fixture_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixture_upstream_server.py")
    upstream = spawn_upstream([sys.executable, fixture_path])
    try:
        engine = Engine(policy)
        audit = AuditLog(tmp_path / "audit.jsonl")
        audit.reset()
        bouncer = Bouncer(engine=engine, audit=audit, upstream=upstream)

        response = bouncer.handle_request(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "files__read_file", "arguments": {"path": "/srv/app/ok.txt"}},
            }
        )
        assert response["result"]["content"][0]["text"] == "fixture upstream response"
    finally:
        upstream.close()


def test_real_subprocess_transport_denied_call_never_dispatched(policy, tmp_path):
    fixture_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixture_upstream_server.py")
    upstream = spawn_upstream([sys.executable, fixture_path])
    try:
        engine = Engine(policy)
        audit = AuditLog(tmp_path / "audit.jsonl")
        audit.reset()
        bouncer = Bouncer(engine=engine, audit=audit, upstream=upstream)

        response = bouncer.handle_request(
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": "files__read_file", "arguments": {"path": "/etc/shadow"}},
            }
        )
        assert response["error"]["data"]["decision"] == "deny"
        assert response["error"]["data"]["rule_id"] == "path_confinement"
    finally:
        upstream.close()
