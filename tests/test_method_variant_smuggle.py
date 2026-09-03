"""Method-variant smuggling: defects found in review.

r4-e1 -- MEDIUM: rule 7 (redaction) only scanned the `result` payload of an
intercepted tools/call response. When upstream returns a JSON-RPC ERROR
envelope instead of a success, a secret-shaped token in `error.message` (or
`error.data`) was forwarded byte-identical and UNREDACTED -- the exact
secret class rule 7 exists to stop. Fixed by applying the same declared
redaction table to `error.message`/`error.data` (recursively), masking +
counting + auditing, before the error reaches the client.

r4-e2 -- MEDIUM: interception keyed on an EXACT case-sensitive
`"tools/call"` string; a case/whitespace variant (`Tools/Call`,
`TOOLS/CALL`, `tools/Call`, `tools/call ` with trailing/leading whitespace)
was passed straight through to upstream with zero policy checks -- a
fail-open smuggle around the allowlist/path-confinement/redaction/rate
gates. Fixed by normalizing the method (strip + casefold) before deciding
whether to gate; an EXACT match still gates normally, a normalized-but-not-
exact match is denied fail-unsafe as malformed, and genuinely unrelated
methods (`initialize`, `ping`, `resources/*`) still pass through untouched.
"""

import json

from mcpbouncer.audit import AuditLog
from mcpbouncer.engine import Engine
from mcpbouncer.proxy import Bouncer, FunctionTransport


# ---------------------------------------------------------------------------
# r4-e1: secret leaks through the tools/call ERROR path
# ---------------------------------------------------------------------------


def _fake_aws_key() -> str:
    # Synthesized from disjoint fragments, matching the declared
    # `aws_access_key` pattern (`AKIA[0-9A-Z]{16}`) -- inert placeholder,
    # not a real credential (see mcpbouncer/corpus.py for the same
    # convention).
    return "AKIA" + "0" * 16


def test_error_message_secret_is_redacted_via_handle_request(policy, tmp_path):
    fake_key = _fake_aws_key()

    def fixture_server(message):
        return {
            "jsonrpc": "2.0",
            "id": message.get("id"),
            "error": {"code": -32000, "message": f"boom {fake_key}"},
        }

    engine = Engine(policy)
    audit = AuditLog(tmp_path / "audit.jsonl")
    audit.reset()
    bouncer = Bouncer(engine=engine, audit=audit, upstream=FunctionTransport(fixture_server))

    request_msg = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "files__read_file", "arguments": {"path": "/srv/app/ok.txt"}},
    }
    response = bouncer.handle_request(request_msg)

    assert fake_key not in json.dumps(response), "the raw secret must never reach the client"
    assert "[REDACTED:aws_access_key]" in response["error"]["message"]
    assert "boom" in response["error"]["message"]

    records = audit.read_records()
    redaction_records = [r for r in records if r["rule_id"] == "redaction"]
    assert len(redaction_records) == 1
    assert redaction_records[0]["evidence"] == {"aws_access_key": 1}
    assert redaction_records[0]["json_pointer"] == "/error"


def test_error_data_secret_is_redacted_recursively(policy, tmp_path):
    """Secret hidden in `error.data` (not just `error.message`), nested
    inside a dict, must also be masked."""
    fake_key = _fake_aws_key()

    def fixture_server(message):
        return {
            "jsonrpc": "2.0",
            "id": message.get("id"),
            "error": {
                "code": -32000,
                "message": "upstream failed",
                "data": {"detail": f"leaked key {fake_key}", "nested": {"more": fake_key}},
            },
        }

    engine = Engine(policy)
    audit = AuditLog(tmp_path / "audit.jsonl")
    audit.reset()
    bouncer = Bouncer(engine=engine, audit=audit, upstream=FunctionTransport(fixture_server))

    request_msg = {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {"name": "files__read_file", "arguments": {"path": "/srv/app/ok.txt"}},
    }
    response = bouncer.handle_request(request_msg)

    assert fake_key not in json.dumps(response)
    assert response["error"]["data"]["detail"] == "leaked key [REDACTED:aws_access_key]"
    assert response["error"]["data"]["nested"]["more"] == "[REDACTED:aws_access_key]"

    records = audit.read_records()
    redaction_records = [r for r in records if r["rule_id"] == "redaction"]
    assert len(redaction_records) == 1
    assert redaction_records[0]["evidence"] == {"aws_access_key": 2}


def test_error_without_secret_is_forwarded_unchanged(policy, tmp_path):
    """No false positives: an error envelope with no declared-pattern match
    is forwarded as-is and produces zero redaction audit records."""

    def fixture_server(message):
        return {
            "jsonrpc": "2.0",
            "id": message.get("id"),
            "error": {"code": -32000, "message": "plain failure, nothing sensitive"},
        }

    engine = Engine(policy)
    audit = AuditLog(tmp_path / "audit.jsonl")
    audit.reset()
    bouncer = Bouncer(engine=engine, audit=audit, upstream=FunctionTransport(fixture_server))

    request_msg = {
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {"name": "files__read_file", "arguments": {"path": "/srv/app/ok.txt"}},
    }
    response = bouncer.handle_request(request_msg)

    assert response["error"]["message"] == "plain failure, nothing sensitive"
    records = audit.read_records()
    assert [r for r in records if r["rule_id"] == "redaction"] == []


def test_error_message_secret_is_redacted_via_handle_raw_dict_fallback(policy, tmp_path):
    """Same repro through the byte-transparent `handle_raw` path (falls
    back to the dict round trip since FunctionTransport has no
    send_raw/recv_raw)."""
    fake_key = _fake_aws_key()

    def fixture_server(message):
        return {
            "jsonrpc": "2.0",
            "id": message.get("id"),
            "error": {"code": -32000, "message": f"boom {fake_key}"},
        }

    engine = Engine(policy)
    audit = AuditLog(tmp_path / "audit.jsonl")
    audit.reset()
    bouncer = Bouncer(engine=engine, audit=audit, upstream=FunctionTransport(fixture_server))

    raw_line = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {"name": "files__read_file", "arguments": {"path": "/srv/app/ok.txt"}},
        }
    )
    out = bouncer.handle_raw(raw_line)
    assert out is not None
    assert fake_key not in out
    parsed = json.loads(out)
    assert "[REDACTED:aws_access_key]" in parsed["error"]["message"]


# ---------------------------------------------------------------------------
# r4-e2: method case/whitespace variant smuggled through ungated
# ---------------------------------------------------------------------------

METHOD_VARIANTS = ["Tools/Call", "TOOLS/CALL", "tools/Call", "tools/call ", " tools/call"]


def test_method_variants_never_reach_upstream_via_handle_request(policy, tmp_path):
    upstream_calls = []

    def handler(message):
        upstream_calls.append(message)
        return {"jsonrpc": "2.0", "id": message.get("id"), "result": "should never be seen"}

    engine = Engine(policy)
    audit = AuditLog(tmp_path / "audit.jsonl")
    audit.reset()
    bouncer = Bouncer(engine=engine, audit=audit, upstream=FunctionTransport(handler))

    for variant in METHOD_VARIANTS:
        request_msg = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": variant,
            "params": {"name": "files__read_file", "arguments": {"path": "/srv/app/ok.txt"}},
        }
        response = bouncer.handle_request(request_msg)
        assert response is not None
        assert "error" in response, f"variant {variant!r} must be denied, got {response}"
        assert response["error"]["data"]["rule_id"] == "malformed_method"

    assert upstream_calls == [], "a tools/call method variant must never reach the upstream transport"


def test_method_variants_never_reach_upstream_via_handle_raw(policy, tmp_path):
    upstream_calls = []

    def handler(message):
        upstream_calls.append(message)
        return {"jsonrpc": "2.0", "id": message.get("id"), "result": "should never be seen"}

    engine = Engine(policy)
    audit = AuditLog(tmp_path / "audit.jsonl")
    audit.reset()
    bouncer = Bouncer(engine=engine, audit=audit, upstream=FunctionTransport(handler))

    for variant in METHOD_VARIANTS:
        raw_line = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": variant,
                "params": {"name": "files__read_file", "arguments": {"path": "/srv/app/ok.txt"}},
            }
        )
        out = bouncer.handle_raw(raw_line)
        assert out is not None
        parsed = json.loads(out)
        assert "error" in parsed, f"variant {variant!r} must be denied, got {parsed}"
        assert parsed["error"]["data"]["rule_id"] == "malformed_method"

    assert upstream_calls == [], "a tools/call method variant must never reach the upstream transport"


def test_exact_tools_call_still_gated_normally(policy, tmp_path):
    """Control: the exact literal method must still be gated (allowed when
    policy allows, denied when it doesn't) -- the fix must not turn EVERY
    tools/call into a malformed-method denial."""

    def fixture_server(message):
        return {
            "jsonrpc": "2.0",
            "id": message.get("id"),
            "result": {"content": [{"type": "text", "text": "ok"}]},
        }

    engine = Engine(policy)
    audit = AuditLog(tmp_path / "audit.jsonl")
    audit.reset()
    bouncer = Bouncer(engine=engine, audit=audit, upstream=FunctionTransport(fixture_server))

    request_msg = {
        "jsonrpc": "2.0",
        "id": 5,
        "method": "tools/call",
        "params": {"name": "files__read_file", "arguments": {"path": "/srv/app/ok.txt"}},
    }
    response = bouncer.handle_request(request_msg)
    assert "error" not in response
    assert response["result"]["content"][0]["text"] == "ok"


def test_unrelated_methods_still_pass_through_untouched(policy, tmp_path):
    """Control: genuinely unrelated methods (not tools/call-shaped at all)
    must still pass straight through, unaffected by the variant check."""

    def fixture_server(message):
        return {"jsonrpc": "2.0", "id": message.get("id"), "result": {"ok": True}}

    engine = Engine(policy)
    audit = AuditLog(tmp_path / "audit.jsonl")
    audit.reset()
    bouncer = Bouncer(engine=engine, audit=audit, upstream=FunctionTransport(fixture_server))

    for method in ["initialize", "ping", "resources/list", "prompts/get"]:
        response = bouncer.handle_request({"jsonrpc": "2.0", "id": 6, "method": method})
        assert response == {"jsonrpc": "2.0", "id": 6, "result": {"ok": True}}
