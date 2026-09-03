"""Gate 5: transparency -- an allowed call's request and response must be
forwarded UNMODIFIED except for declared redactions, proven against a
fixture server."""

import copy
import json
import os
import sys

from mcpbouncer.audit import AuditLog
from mcpbouncer.engine import Engine
from mcpbouncer.proxy import Bouncer, FunctionTransport, spawn_upstream


def test_allowed_call_forwarded_byte_identical(policy, tmp_path):
    sent = {}

    def fixture_server(message):
        sent["request"] = copy.deepcopy(message)
        return {
            "jsonrpc": "2.0",
            "id": message.get("id"),
            "result": {"content": [{"type": "text", "text": "hello from upstream, nothing sensitive"}]},
        }

    engine = Engine(policy)
    audit = AuditLog(tmp_path / "audit.jsonl")
    audit.reset()
    bouncer = Bouncer(engine=engine, audit=audit, upstream=FunctionTransport(fixture_server))

    request_msg = {
        "jsonrpc": "2.0",
        "id": 7,
        "method": "tools/call",
        "params": {"name": "files__read_file", "arguments": {"path": "/srv/app/ok.txt"}},
    }
    original = copy.deepcopy(request_msg)
    response = bouncer.handle_request(request_msg)

    assert sent["request"] == original, "the forwarded request must be byte-identical to what the client sent"
    expected_result = {"content": [{"type": "text", "text": "hello from upstream, nothing sensitive"}]}
    assert response["result"] == expected_result, "an allowed response with no secrets must pass through unchanged"


def test_allowed_call_with_secret_gets_only_that_declared_redaction(policy, tmp_path):
    fake_key = "AKIA" + "Z" * 16

    def fixture_server(message):
        return {
            "jsonrpc": "2.0",
            "id": message.get("id"),
            "result": {"content": [{"type": "text", "text": f"unrelated text, key={fake_key}, more text"}]},
        }

    engine = Engine(policy)
    audit = AuditLog(tmp_path / "audit.jsonl")
    audit.reset()
    bouncer = Bouncer(engine=engine, audit=audit, upstream=FunctionTransport(fixture_server))

    request_msg = {
        "jsonrpc": "2.0",
        "id": 8,
        "method": "tools/call",
        "params": {"name": "files__read_file", "arguments": {"path": "/srv/app/ok.txt"}},
    }
    response = bouncer.handle_request(request_msg)

    text = response["result"]["content"][0]["text"]
    assert fake_key not in text
    assert "unrelated text" in text and "more text" in text, "only the declared secret span is masked"

    records = audit.read_records()
    redaction_records = [r for r in records if r["rule_id"] == "redaction"]
    assert len(redaction_records) == 1
    assert redaction_records[0]["evidence"] == {"aws_access_key": 1}


def test_non_tools_call_method_forwarded_unchanged(policy, tmp_path):
    def fixture_server(message):
        return {"jsonrpc": "2.0", "id": message.get("id"), "result": {"tools": ["read_file"]}}

    engine = Engine(policy)
    audit = AuditLog(tmp_path / "audit.jsonl")
    audit.reset()
    bouncer = Bouncer(engine=engine, audit=audit, upstream=FunctionTransport(fixture_server))

    response = bouncer.handle_request({"jsonrpc": "2.0", "id": 9, "method": "tools/list"})
    assert response == {"jsonrpc": "2.0", "id": 9, "result": {"tools": ["read_file"]}}


# E2 -- HIGH: the proxy must advertise the name it accepts. `tools/list`
# is rewritten (when `server_name` is configured) so every advertised name
# is the qualified `server__tool` name that actually routes on `tools/call`
# -- otherwise a conforming client calling the advertised bare name is
# 100% denied (unmatched-deny server='').


def test_tools_list_advertises_qualified_names_when_server_name_set(policy, tmp_path):
    def fixture_server(message):
        if message.get("method") == "tools/list":
            return {
                "jsonrpc": "2.0",
                "id": message.get("id"),
                "result": {
                    "tools": [
                        {"name": "read_file", "description": "read a file"},
                        {"name": "write_file", "description": "write a file"},
                    ]
                },
            }
        return {"jsonrpc": "2.0", "id": message.get("id"), "result": {}}

    engine = Engine(policy)
    audit = AuditLog(tmp_path / "audit.jsonl")
    audit.reset()
    bouncer = Bouncer(
        engine=engine, audit=audit, upstream=FunctionTransport(fixture_server), server_name="files"
    )

    response = bouncer.handle_request({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    names = [t["name"] for t in response["result"]["tools"]]
    assert names == ["files__read_file", "files__write_file"]
    # other tool fields (e.g. description) must survive the rewrite
    assert response["result"]["tools"][0]["description"] == "read a file"


def test_tools_list_without_server_name_configured_unchanged(policy, tmp_path):
    """No server_name configured (the prior default) -- tools/list still
    passes through unchanged, matching existing behavior."""

    def fixture_server(message):
        return {
            "jsonrpc": "2.0",
            "id": message.get("id"),
            "result": {"tools": [{"name": "read_file"}]},
        }

    engine = Engine(policy)
    audit = AuditLog(tmp_path / "audit.jsonl")
    audit.reset()
    bouncer = Bouncer(engine=engine, audit=audit, upstream=FunctionTransport(fixture_server))

    response = bouncer.handle_request({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    assert response["result"]["tools"][0]["name"] == "read_file"


def test_advertised_qualified_name_routes_on_tools_call(policy, tmp_path):
    """The actual escape repro: drive tools/list through the proxy, take
    each advertised name, issue a tools/call with that exact name, and
    assert it ROUTES -- never unmatched-deny server=''."""

    def fixture_server(message):
        if message.get("method") == "tools/list":
            return {
                "jsonrpc": "2.0",
                "id": message.get("id"),
                "result": {"tools": [{"name": "read_file"}]},
            }
        return {
            "jsonrpc": "2.0",
            "id": message.get("id"),
            "result": {"content": [{"type": "text", "text": "ok"}]},
        }

    engine = Engine(policy)
    audit = AuditLog(tmp_path / "audit.jsonl")
    audit.reset()
    bouncer = Bouncer(
        engine=engine, audit=audit, upstream=FunctionTransport(fixture_server), server_name="files"
    )

    listed = bouncer.handle_request({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    advertised_names = [t["name"] for t in listed["result"]["tools"]]
    assert advertised_names == ["files__read_file"]

    for name in advertised_names:
        response = bouncer.handle_request(
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": name, "arguments": {"path": "/srv/app/ok.txt"}},
            }
        )
        assert "error" not in response, f"advertised name {name!r} did not route: {response}"
        assert response["result"]["content"][0]["text"] == "ok"


# E3 -- MEDIUM, part (a): the proxy must not gratuitously re-serialize an
# allowed call's request/response (whitespace stripped, key order changed)
# -- a byte comparison against the client's original bytes, not merely a
# parsed-dict equality check, per SPEC gate 5.
# E3 -- MEDIUM, part (b): non-ASCII argument values must round-trip
# correctly through the proxy's real stdio pipe to a real subprocess
# upstream (Windows defaults `text=True` Popen pipes to the locale
# encoding, e.g. cp1252, not UTF-8, without an explicit `encoding=`).


def test_allowed_call_raw_roundtrip_byte_identical_and_utf8(policy, tmp_path):
    fixture_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixture_upstream_server.py")
    upstream = spawn_upstream([sys.executable, fixture_path])
    try:
        engine = Engine(policy)
        audit = AuditLog(tmp_path / "audit.jsonl")
        audit.reset()
        bouncer = Bouncer(engine=engine, audit=audit, upstream=upstream)

        request_obj = {
            "jsonrpc": "2.0",
            "id": 42,
            "method": "tools/call",
            "params": {"name": "files__read_file", "arguments": {"path": "/srv/app/café.txt"}},
        }
        # Deliberately default (non-compact) json.dumps separators, so a
        # gratuitous re-serialize to mcpbouncer's own compact separators
        # would be caught by the byte-identity assertion below.
        raw_line = json.dumps(request_obj)

        out = bouncer.handle_raw(raw_line)
        assert out is not None

        # (a) response forwarded byte-identically: the fixture always
        # replies with json.dumps' default (non-compact) separators, so a
        # match here proves mcpbouncer returned the upstream's raw bytes,
        # not a re-serialized dict.
        expected_response = {
            "jsonrpc": "2.0",
            "id": 42,
            "result": {
                "content": [{"type": "text", "text": "fixture upstream response"}],
                "received_raw": raw_line,
            },
        }
        assert out == json.dumps(expected_response), (
            "an allowed call's response must be forwarded byte-identically "
            "(zero redactions) rather than re-serialized"
        )

        # (a) request forwarded byte-identically: the fixture echoes back
        # the exact raw line it received on the wire.
        response = json.loads(out)
        assert response["result"]["received_raw"] == raw_line, (
            "the forwarded request must be byte-identical to what the client sent, "
            "not re-serialized with different whitespace/key order"
        )

        # (b) UTF-8 correctness: the non-ASCII argument value must arrive
        # at upstream intact, not mis-decoded (e.g. "café" -> "cafÃ©").
        received_request = json.loads(response["result"]["received_raw"])
        assert received_request["params"]["arguments"]["path"] == "/srv/app/café.txt"
    finally:
        upstream.close()
