"""NFKC method spoofing and proxy-shape crashes: defects found in review.

r5-e1 -- MEDIUM: the method-variant guard (``is_tools_call_method_variant``)
strips whitespace and casefolds, but does not NFKC-normalize. A fullwidth
(NFKC-compatibility) confusable of ``tools/call`` -- e.g.
``ｔｏｏｌｓ／ｃａｌｌ`` (U+FF54
U+FF4F U+FF4F U+FF4C U+FF53 U+FF0F U+FF43 U+FF41 U+FF4C U+FF4C), which
NFKC-folds to exactly ``tools/call`` -- was forwarded to upstream as
ordinary passthrough with zero policy checks and no audit line, while the
NBSP variant of the identical request (``tools/call ``) was correctly
denied ``malformed_method``. Fixed by NFKC-normalizing (in addition to the
existing strip + casefold) before comparing to ``tools/call``.

r5-e2 -- MEDIUM: ``Bouncer.handle_raw`` raised an unhandled
``AttributeError``/``TypeError`` (e.g. ``'list' object has no attribute
'get'``) on a JSON-RPC batch array (``[req, req]``), a bare scalar
(``"hello"``, ``1234``, ``null``, ``true``), invalid JSON, ``params`` as an
array instead of an object, or a non-string ``params.name`` -- killing the
whole stdio session (``run_stdio``'s ``for raw_line in stdin`` loop never
resumes after an uncaught exception mid-iteration), so every later call in
the session was silently dropped with no denial and no audit line. Fixed by
validating message shape (``Bouncer._validate_message_shape``) and
``tools/call`` params shape (``Bouncer._resolve_tools_call``) up front and
returning a structured ``malformed_input`` JSON-RPC error response instead
of raising -- nothing forwarded upstream, an audit line always written, and
the session keeps processing subsequent lines.
"""

import json

import pytest

from mcpbouncer.audit import AuditLog
from mcpbouncer.engine import Engine
from mcpbouncer.proxy import Bouncer, FunctionTransport, is_tools_call_method_variant


# ---------------------------------------------------------------------------
# r5-e1: NFKC-confusable method spoof
# ---------------------------------------------------------------------------

# U+FF54 U+FF4F U+FF4F U+FF4C U+FF53 U+FF0F U+FF43 U+FF41 U+FF4C U+FF4C --
# fullwidth-Unicode spelling of "tools/call"; NFKC-folds to exactly
# "tools/call" but is not byte-identical to it.
FULLWIDTH_TOOLS_CALL = "ｔｏｏｌｓ／ｃａｌｌ"

# A second NFKC confusable: fullwidth digits/letters are common, but a
# fullwidth solidus alone (rest ASCII) also NFKC-folds to "tools/call".
PARTIAL_FULLWIDTH_TOOLS_CALL = "tools／call"

NFKC_CONFUSABLES = [FULLWIDTH_TOOLS_CALL, PARTIAL_FULLWIDTH_TOOLS_CALL]

# Controls: genuinely unrelated methods (not tools/call-shaped at all, even
# after NFKC) must not be mis-denied by the new normalization step.
NON_OVERCATCH_METHODS = [
    "tools/list",
    "tools/call/extra",
    "notifications/tools/call",
    "atools/call",
    "tools/calls",
    "initialize",
]


@pytest.mark.parametrize("variant", NFKC_CONFUSABLES)
def test_is_tools_call_method_variant_detects_nfkc_confusables(variant):
    assert is_tools_call_method_variant(variant) is True


@pytest.mark.parametrize("method", NON_OVERCATCH_METHODS)
def test_is_tools_call_method_variant_no_overcatch(method):
    assert is_tools_call_method_variant(method) is False


def test_exact_tools_call_is_not_flagged_as_variant():
    assert is_tools_call_method_variant("tools/call") is False


@pytest.mark.parametrize("variant", NFKC_CONFUSABLES)
def test_nfkc_confusable_denied_and_not_forwarded_via_handle_raw(policy, tmp_path, variant):
    upstream_calls = []

    def handler(message):
        upstream_calls.append(message)
        return {"jsonrpc": "2.0", "id": message.get("id"), "result": "should never be seen"}

    engine = Engine(policy)
    audit = AuditLog(tmp_path / "audit.jsonl")
    audit.reset()
    bouncer = Bouncer(engine=engine, audit=audit, upstream=FunctionTransport(handler))

    raw_line = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": variant,
            "params": {"name": "files__read_file", "arguments": {"path": "../../etc/passwd"}},
        }
    )
    out = bouncer.handle_raw(raw_line)
    assert out is not None
    parsed = json.loads(out)
    assert "error" in parsed, f"variant {variant!r} must be denied, got {parsed}"
    assert parsed["error"]["data"]["rule_id"] == "malformed_method"

    assert upstream_calls == [], "an NFKC-confusable method spoof must never reach upstream"

    records = audit.read_records()
    assert any(r["rule_id"] == "malformed_method" for r in records), "denial must be audited"


def test_nbsp_control_still_denied_alongside_nfkc_fix(policy, tmp_path):
    """Control from the audit report: the NBSP variant must remain denied
    after the NFKC fix (regression guard against the fix narrowing the
    existing strip+casefold behavior)."""
    upstream_calls = []

    def handler(message):
        upstream_calls.append(message)
        return {"jsonrpc": "2.0", "id": message.get("id"), "result": "should never be seen"}

    engine = Engine(policy)
    audit = AuditLog(tmp_path / "audit.jsonl")
    audit.reset()
    bouncer = Bouncer(engine=engine, audit=audit, upstream=FunctionTransport(handler))

    raw_line = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call ",
            "params": {"name": "files__read_file", "arguments": {"path": "/srv/app/ok.txt"}},
        }
    )
    out = bouncer.handle_raw(raw_line)
    parsed = json.loads(out)
    assert parsed["error"]["data"]["rule_id"] == "malformed_method"
    assert upstream_calls == []


@pytest.mark.parametrize("method", NON_OVERCATCH_METHODS)
def test_unrelated_methods_still_pass_through_after_nfkc_fix(policy, tmp_path, method):
    """Control: methods that are NOT tools/call-shaped, even after NFKC
    normalization, must still pass through untouched (no over-catch)."""

    def fixture_server(message):
        return {"jsonrpc": "2.0", "id": message.get("id"), "result": {"ok": True}}

    engine = Engine(policy)
    audit = AuditLog(tmp_path / "audit.jsonl")
    audit.reset()
    bouncer = Bouncer(engine=engine, audit=audit, upstream=FunctionTransport(fixture_server))

    response = bouncer.handle_request({"jsonrpc": "2.0", "id": 6, "method": method})
    assert response == {"jsonrpc": "2.0", "id": 6, "result": {"ok": True}}


# ---------------------------------------------------------------------------
# r5-e2: malformed/batch message shapes must not crash the proxy
# ---------------------------------------------------------------------------


def _make_bouncer(policy, tmp_path, handler):
    engine = Engine(policy)
    audit = AuditLog(tmp_path / "audit.jsonl")
    audit.reset()
    bouncer = Bouncer(engine=engine, audit=audit, upstream=FunctionTransport(handler))
    return bouncer, audit


MALFORMED_RAW_LINES = [
    pytest.param(
        json.dumps(
            [
                {"jsonrpc": "2.0", "id": 1, "method": "tools/call"},
                {"jsonrpc": "2.0", "id": 2, "method": "tools/call"},
            ]
        ),
        id="batch-array",
    ),
    pytest.param(json.dumps("hello"), id="bare-string-scalar"),
    pytest.param(json.dumps(1234), id="bare-int-scalar"),
    pytest.param(json.dumps(None), id="bare-null"),
    pytest.param(json.dumps(True), id="bare-bool"),
    pytest.param("not json at all {{{", id="invalid-json"),
    pytest.param(
        json.dumps({"jsonrpc": "2.0", "id": 9, "method": "tools/call", "params": ["a", "b"]}),
        id="params-is-array",
    ),
    pytest.param(
        json.dumps(
            {"jsonrpc": "2.0", "id": 10, "method": "tools/call", "params": {"name": 123}}
        ),
        id="name-is-non-string-int",
    ),
    pytest.param(
        json.dumps(
            {"jsonrpc": "2.0", "id": 11, "method": "tools/call", "params": {"name": None}}
        ),
        id="name-is-none",
    ),
    pytest.param(
        json.dumps({"jsonrpc": "2.0", "id": 12, "method": ""}),
        id="blank-method",
    ),
    pytest.param(
        json.dumps({"jsonrpc": "2.0", "id": 13}),
        id="missing-method",
    ),
]


@pytest.mark.parametrize("raw_line", MALFORMED_RAW_LINES)
def test_malformed_shape_never_crashes_handle_raw(policy, tmp_path, raw_line):
    upstream_calls = []

    def handler(message):
        upstream_calls.append(message)
        return {"jsonrpc": "2.0", "id": message.get("id") if isinstance(message, dict) else None, "result": "x"}

    bouncer, audit = _make_bouncer(policy, tmp_path, handler)

    # Must not raise.
    out = bouncer.handle_raw(raw_line)

    assert out is not None, "a malformed message must produce a structured error, not silence"
    parsed = json.loads(out)
    assert parsed["jsonrpc"] == "2.0"
    assert "error" in parsed
    assert parsed["error"]["data"]["rule_id"] == "malformed_input"

    assert upstream_calls == [], "a malformed message must never reach upstream"

    records = audit.read_records()
    assert any(r["rule_id"] == "malformed_input" for r in records), "denial must be audited"


def test_batch_array_does_not_kill_session_next_valid_call_processed(policy, tmp_path):
    """The core session-liveness regression: after a crash-shaped line, a
    subsequent VALID tools/call in the same stream/session must still be
    gated and forwarded normally."""
    upstream_calls = []

    def handler(message):
        upstream_calls.append(message)
        return {"jsonrpc": "2.0", "id": message.get("id"), "result": "fixture ok"}

    bouncer, audit = _make_bouncer(policy, tmp_path, handler)

    batch_line = json.dumps(
        [
            {"jsonrpc": "2.0", "id": 1, "method": "tools/call"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/call"},
        ]
    )
    out1 = bouncer.handle_raw(batch_line)
    assert out1 is not None
    assert "error" in json.loads(out1)

    scalar_line = json.dumps(1234)
    out2 = bouncer.handle_raw(scalar_line)
    assert out2 is not None
    assert "error" in json.loads(out2)

    valid_line = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 99,
            "method": "tools/call",
            "params": {"name": "files__read_file", "arguments": {"path": "/srv/app/ok.txt"}},
        }
    )
    out3 = bouncer.handle_raw(valid_line)
    assert out3 is not None
    parsed3 = json.loads(out3)
    assert parsed3["result"] == "fixture ok"

    assert len(upstream_calls) == 1
    assert upstream_calls[0]["id"] == 99

    records = audit.read_records()
    rule_ids = [r["rule_id"] for r in records]
    assert rule_ids.count("malformed_input") == 2
    assert rule_ids[-1] == "allow"


def test_malformed_shapes_never_crash_handle_request_directly(policy, tmp_path):
    """The dict-based path (``handle_request``) must reject the same
    malformed shapes without raising, for callers that bypass
    ``handle_raw`` entirely."""

    def handler(message):
        return {"jsonrpc": "2.0", "id": message.get("id"), "result": "x"}

    bouncer, audit = _make_bouncer(policy, tmp_path, handler)

    for message in [
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": ["a", "b"]},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": 123}},
        {"jsonrpc": "2.0", "id": 3, "method": ""},
        {"jsonrpc": "2.0", "id": 4},
    ]:
        response = bouncer.handle_request(message)
        assert response is not None
        assert "error" in response
        assert response["error"]["data"]["rule_id"] == "malformed_input"


def test_valid_calls_and_non_tools_call_methods_unaffected_by_shape_guard(policy, tmp_path):
    """Non-regression control: well-formed tools/call and well-formed
    unrelated methods must still work exactly as before."""

    def handler(message):
        return {"jsonrpc": "2.0", "id": message.get("id"), "result": {"ok": True}}

    bouncer, audit = _make_bouncer(policy, tmp_path, handler)

    ok_response = bouncer.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "files__read_file", "arguments": {"path": "/srv/app/ok.txt"}},
        }
    )
    assert "error" not in ok_response

    other_response = bouncer.handle_request({"jsonrpc": "2.0", "id": 2, "method": "initialize"})
    assert other_response == {"jsonrpc": "2.0", "id": 2, "result": {"ok": True}}
