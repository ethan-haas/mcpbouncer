"""Redaction must scan object KEY names, not only values.

r6-e1 -- LOW: result redaction (rule 7 / ``_walk_redact``) recursively
scanned every string VALUE in a ``tools/call`` response (result +
``error.message``/``error.data``, arrays, nested objects, a bare-string
result) but never scanned object KEY names. If the upstream emitted a
secret-shaped token AS A KEY (e.g. ``{"AKIA...": "v"}``), it reached the
client unredacted and uncounted -- a silent miss: the audit trail showed
zero redactions even though a declared-pattern secret was present in the
response. SPEC rule 7 requires declared patterns be masked in the response
and never silently dropped; a key-name token is a match in the response
that reached the model.

Fixed by extending ``_walk_redact``'s dict branch to also run each key
string through ``Engine.redact`` (same declared pattern table as values),
substituting the masked key and folding its hit counts into the same
``counts`` mapping used for value matches. Collisions (two distinct
original keys masking down to the same string) are handled deterministically
by ordinary dict-literal semantics -- last key processed wins the slot in
the output mapping -- while every colliding key's secret is still gone
(no leak) and still counted independently before the collision collapses
the mapping.
"""

import copy
import json

from mcpbouncer.audit import AuditLog
from mcpbouncer.engine import Engine
from mcpbouncer.proxy import Bouncer, FunctionTransport, _walk_redact


def _make_bouncer(policy, tmp_path, fixture_server):
    engine = Engine(policy)
    audit = AuditLog(tmp_path / "audit.jsonl")
    audit.reset()
    return Bouncer(engine=engine, audit=audit, upstream=FunctionTransport(fixture_server)), audit


def _call(bouncer, request_id=1):
    request_msg = {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "tools/call",
        "params": {"name": "files__read_file", "arguments": {"path": "/srv/app/ok.txt"}},
    }
    return bouncer.handle_request(request_msg)


# ---------------------------------------------------------------------------
# r6-e1: secret-shaped OBJECT KEY NAME must be masked and counted
# ---------------------------------------------------------------------------


def test_secret_shaped_key_name_is_masked_and_counted(policy, tmp_path):
    fake_key = "AKIA" + "0" * 16  # matches the declared aws_access_key pattern

    def fixture_server(message):
        return {
            "jsonrpc": "2.0",
            "id": message.get("id"),
            "result": {fake_key: "v"},
        }

    bouncer, audit = _make_bouncer(policy, tmp_path, fixture_server)
    response = _call(bouncer)

    result = response["result"]
    assert fake_key not in result, "the secret-shaped key must not reach the client verbatim"
    assert result == {"[REDACTED:aws_access_key]": "v"}, "value must be untouched by the key mask"

    records = audit.read_records()
    redaction_records = [r for r in records if r["rule_id"] == "redaction"]
    assert len(redaction_records) == 1, "a key-name mask must produce a redaction audit record"
    assert redaction_records[0]["evidence"] == {"aws_access_key": 1}, (
        "the key-name mask must be counted, not silently applied with count 0"
    )


def test_secret_shaped_key_and_value_both_counted(policy, tmp_path):
    """{TOKEN: TOKEN} -- prior behaviour masked the value (count 1) but left
    the key intact; both the key and the value are separate matches and
    both must be counted."""
    fake_key = "AKIA" + "1" * 16

    def fixture_server(message):
        return {
            "jsonrpc": "2.0",
            "id": message.get("id"),
            "result": {fake_key: fake_key},
        }

    bouncer, audit = _make_bouncer(policy, tmp_path, fixture_server)
    response = _call(bouncer)

    result = response["result"]
    assert fake_key not in json.dumps(result), "neither the key nor the value may leak the secret"
    assert result == {"[REDACTED:aws_access_key]": "[REDACTED:aws_access_key]"}

    records = audit.read_records()
    redaction_records = [r for r in records if r["rule_id"] == "redaction"]
    assert len(redaction_records) == 1
    assert redaction_records[0]["evidence"] == {"aws_access_key": 2}, (
        "key match and value match are two independent hits, both counted"
    )


def test_key_with_no_match_is_unchanged_and_byte_identical_on_zero_redactions(policy, tmp_path):
    def fixture_server(message):
        return {
            "jsonrpc": "2.0",
            "id": message.get("id"),
            "result": {"content": [{"type": "text", "text": "nothing sensitive here"}]},
        }

    bouncer, audit = _make_bouncer(policy, tmp_path, fixture_server)
    request_msg = {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {"name": "files__read_file", "arguments": {"path": "/srv/app/ok.txt"}},
    }
    expected_result = {"content": [{"type": "text", "text": "nothing sensitive here"}]}
    response = bouncer.handle_request(copy.deepcopy(request_msg))

    assert response["result"] == expected_result, "keys/values with no match must be byte-unchanged"
    records = audit.read_records()
    assert not [r for r in records if r["rule_id"] == "redaction"], (
        "zero redactions must produce zero redaction audit records"
    )


def test_colliding_masked_keys_are_deterministic_no_leak_no_crash(policy):
    """Two distinct keys that both fully match the declared pattern (and so
    both mask down to the identical placeholder string) must not crash, must
    not leak either secret, and must still count both hits -- even though
    only one slot survives in the resulting dict (last-key-wins, ordinary
    dict-literal semantics)."""
    engine = Engine(policy)
    key_a = "AKIA" + "2" * 16
    key_b = "AKIA" + "3" * 16
    assert key_a != key_b

    counts: dict[str, int] = {}
    result = _walk_redact({key_a: "value-a", key_b: "value-b"}, engine, counts)

    assert key_a not in result and key_b not in result, "neither original secret key may leak"
    assert list(result.keys()) == ["[REDACTED:aws_access_key]"], (
        "collision collapses deterministically to one slot (last-wins)"
    )
    assert result["[REDACTED:aws_access_key]"] == "value-b", "last key processed wins the slot"
    assert counts == {"aws_access_key": 2}, "both colliding keys are still counted independently"


def test_error_path_key_name_also_masked(policy, tmp_path):
    fake_key = "AKIA" + "4" * 16

    def fixture_server(message):
        return {
            "jsonrpc": "2.0",
            "id": message.get("id"),
            "error": {"code": -1, "message": "boom", "data": {fake_key: "v"}},
        }

    bouncer, audit = _make_bouncer(policy, tmp_path, fixture_server)
    response = _call(bouncer)

    assert fake_key not in json.dumps(response["error"])
    assert response["error"]["data"] == {"[REDACTED:aws_access_key]": "v"}

    records = audit.read_records()
    redaction_records = [r for r in records if r["rule_id"] == "redaction"]
    assert len(redaction_records) == 1
    assert redaction_records[0]["json_pointer"] == "/error"
    assert redaction_records[0]["evidence"] == {"aws_access_key": 1}
