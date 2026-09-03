"""Gate 3: unmatched is denied, and that is tested directly -- a tool
absent from policy must be denied with unmatched-deny, never forwarded.

This also covers the argument-key-coverage escape: an undeclared argument
key on an otherwise-declared tool must be denied (unmatched-deny /
unmatched_arg), never silently allowed through. Confirmed by an independent
independent review against a policy that declares `files.read_file` with only
arg `path`, root `/srv/app`."""

import json

from mcpbouncer.audit import AuditLog
from mcpbouncer.cli import main
from mcpbouncer.engine import Engine
from mcpbouncer.proxy import Bouncer, FunctionTransport


def test_unmatched_tool_never_reaches_upstream(policy, tmp_path):
    upstream_calls = []

    def handler(message):
        upstream_calls.append(message)
        return {"jsonrpc": "2.0", "id": message.get("id"), "result": "should never be seen"}

    engine = Engine(policy)
    audit = AuditLog(tmp_path / "audit.jsonl")
    audit.reset()
    bouncer = Bouncer(engine=engine, audit=audit, upstream=FunctionTransport(handler))

    request_msg = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "files__delete_everything", "arguments": {}},
    }
    response = bouncer.handle_request(request_msg)

    assert upstream_calls == [], "denied call must never reach the upstream transport"
    assert response["error"]["data"]["decision"] == "unmatched-deny"
    assert response["error"]["data"]["rule_id"] == "unmatched"


def test_unmatched_server_never_reaches_upstream(policy, tmp_path):
    upstream_calls = []

    def handler(message):
        upstream_calls.append(message)
        return {"jsonrpc": "2.0", "id": message.get("id"), "result": "leaked"}

    engine = Engine(policy)
    audit = AuditLog(tmp_path / "audit.jsonl")
    audit.reset()
    bouncer = Bouncer(engine=engine, audit=audit, upstream=FunctionTransport(handler))

    request_msg = {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {"name": "shell__exec", "arguments": {"cmd": "rm -rf /"}},
    }
    response = bouncer.handle_request(request_msg)

    assert upstream_calls == []
    assert response["error"]["data"]["decision"] == "unmatched-deny"


def test_qualified_name_without_separator_is_unmatched(policy, tmp_path):
    engine = Engine(policy)
    audit = AuditLog(tmp_path / "audit.jsonl")
    audit.reset()
    bouncer = Bouncer(engine=engine, audit=audit, upstream=FunctionTransport(lambda m: {"result": "x"}))

    request_msg = {
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {"name": "read_file", "arguments": {}},
    }
    response = bouncer.handle_request(request_msg)
    assert response["error"]["data"]["decision"] == "unmatched-deny"


def test_undeclared_arg_key_path_confinement_bypass_denied(policy):
    """HIGH repro: policy declares files.read_file with only arg `path`,
    root `/srv/app`. An undeclared `altpath` key carrying a traversal
    target must never be allowed through by smuggling past path
    confinement, which only walks declared path args."""
    engine = Engine(policy)
    decision = engine.evaluate(
        {
            "server": "files",
            "tool": "read_file",
            "arguments": {"path": "/srv/app/ok", "altpath": "/etc/passwd"},
        }
    )
    assert decision.decision == "unmatched-deny"
    assert decision.rule_id == "unmatched_arg"
    assert decision.json_pointer == "/arguments/altpath"
    assert "altpath" in decision.message


def test_undeclared_arg_key_unknown_denied(policy):
    """MED repro: an undeclared key with no special shape must still be
    denied -- unknown is unmatched, never defaulted to allow."""
    engine = Engine(policy)
    decision = engine.evaluate(
        {
            "server": "files",
            "tool": "read_file",
            "arguments": {"path": "/srv/app/ok", "surprise": "x"},
        }
    )
    assert decision.decision == "unmatched-deny"
    assert decision.rule_id == "unmatched_arg"
    assert decision.json_pointer == "/arguments/surprise"


def test_undeclared_arg_key_smuggle_denied_via_cli(tmp_path, policy_path):
    """Same HIGH repro end-to-end through `mcpbouncer check`: exit code 1,
    and the printed decision record carries a resolving pointer to the
    undeclared key."""
    calls = tmp_path / "calls.jsonl"
    calls.write_text(
        json.dumps(
            {
                "id": "c1",
                "server": "files",
                "tool": "read_file",
                "arguments": {"path": "/srv/app/ok", "altpath": "/etc/passwd"},
            }
        )
        + "\n",
        encoding="utf-8",
    )
    code = main(["check", str(policy_path), str(calls)])
    assert code == 1


def test_undeclared_arg_key_surprise_denied_via_cli(tmp_path, policy_path, capsys):
    calls = tmp_path / "calls.jsonl"
    calls.write_text(
        json.dumps(
            {
                "id": "c1",
                "server": "files",
                "tool": "read_file",
                "arguments": {"path": "/srv/app/ok", "surprise": "x"},
            }
        )
        + "\n",
        encoding="utf-8",
    )
    code = main(["check", str(policy_path), str(calls)])
    assert code == 1
    out = capsys.readouterr().out
    records = [json.loads(line) for line in out.splitlines() if line.strip()]
    decision_record = [r for r in records if not r.get("summary")][0]
    assert decision_record["decision"] == "unmatched-deny"
    assert decision_record["rule_id"] == "unmatched_arg"
    assert decision_record["json_pointer"] == "/arguments/surprise"
