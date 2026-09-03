"""mcpbouncer command-line interface.

``mcpbouncer check policy.toml calls.jsonl`` evaluates a recorded call log
offline, no server involved. Exit codes: 0 all allowed, 1 >= 1 denial,
2 malformed policy/input.

``mcpbouncer init`` writes a working starter policy -- sixty-second
install-to-value, no account, no network.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from mcpbouncer.audit import AuditLog
from mcpbouncer.corpus import DEFAULT_POLICY_TOML
from mcpbouncer.engine import Engine
from mcpbouncer.policy import PolicyError, load_policy

EXIT_OK = 0
EXIT_DENIED = 1
EXIT_MALFORMED = 2


def _error(kind: str, message: str, **extra) -> None:
    payload = {"error": kind, "message": message, **extra}
    print(json.dumps(payload, sort_keys=True), file=sys.stderr)


def cmd_check(args: argparse.Namespace) -> int:
    try:
        policy = load_policy(args.policy)
    except PolicyError as exc:
        _error("malformed_policy", str(exc), policy=args.policy)
        return EXIT_MALFORMED

    calls_path = Path(args.calls)
    if not calls_path.exists():
        _error("malformed_input", f"calls file not found: {calls_path}")
        return EXIT_MALFORMED

    try:
        raw_lines = [line for line in calls_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    except OSError as exc:
        _error("malformed_input", str(exc))
        return EXIT_MALFORMED

    parsed_calls = []
    for i, line in enumerate(raw_lines, start=1):
        try:
            parsed_calls.append(json.loads(line))
        except json.JSONDecodeError as exc:
            _error("malformed_input", f"line {i} is not valid JSON: {exc}")
            return EXIT_MALFORMED

    engine = Engine(policy)
    audit_path = Path(args.audit_log) if args.audit_log else calls_path.with_suffix(".audit.jsonl")
    audit = AuditLog(audit_path)
    audit.reset()

    counts: dict = {}
    any_denied = False
    for i, call in enumerate(parsed_calls):
        if not isinstance(call, dict):
            _error("malformed_input", f"line {i + 1} is not a JSON object")
            return EXIT_MALFORMED
        session = call.get("session", "default")
        request = {
            "server": call.get("server"),
            "tool": call.get("tool"),
            "arguments": call.get("arguments", {}),
        }
        decision = engine.evaluate(request, session=session, counts=counts)
        audit.append(decision)
        record = {
            "id": call.get("id", i),
            "decision": decision.decision,
            "rule_id": decision.rule_id,
            "server": decision.server,
            "tool": decision.tool,
            "json_pointer": decision.json_pointer,
            "message": decision.message,
        }
        print(json.dumps(record, sort_keys=True))
        if decision.decision != "allow":
            any_denied = True

    total = len(parsed_calls)
    denied = sum(1 for line in _reread(audit_path) if line.get("decision") != "allow")
    print(
        json.dumps(
            {
                "summary": True,
                "total": total,
                "denied": denied,
                "allowed": total - denied,
                "denial_rate": (denied / total) if total else 0.0,
                "audit_log": str(audit_path),
            },
            sort_keys=True,
        )
    )

    return EXIT_DENIED if any_denied else EXIT_OK


def _reread(path: Path):
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            yield json.loads(line)


def cmd_init(args: argparse.Namespace) -> int:
    out_path = Path(args.out)
    if out_path.exists() and not args.force:
        _error("already_exists", f"{out_path} already exists; pass --force to overwrite")
        return EXIT_MALFORMED

    policy_text = DEFAULT_POLICY_TOML
    servers_seen: list[str] = []
    if args.config:
        config_path = Path(args.config)
        try:
            client_config = json.loads(config_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            _error("malformed_input", f"could not read client config: {exc}")
            return EXIT_MALFORMED
        servers_seen = sorted((client_config.get("mcpServers") or {}).keys())

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(policy_text, encoding="utf-8")

    print(
        json.dumps(
            {
                "wrote": str(out_path),
                "policy_version": 1,
                "servers_declared": ["files", "web", "admin"],
                "client_servers_seen": servers_seen,
                "next_step": f"mcpbouncer check {out_path} calls.jsonl",
            },
            sort_keys=True,
        )
    )
    return EXIT_OK


def cmd_proxy(args: argparse.Namespace) -> int:  # pragma: no cover - live stdio IO loop
    from mcpbouncer.engine import Engine
    from mcpbouncer.proxy import Bouncer, spawn_upstream

    try:
        policy = load_policy(args.policy)
    except PolicyError as exc:
        _error("malformed_policy", str(exc), policy=args.policy)
        return EXIT_MALFORMED

    if not args.upstream:
        _error("malformed_input", "--upstream requires a command, e.g. --upstream python -m my_server")
        return EXIT_MALFORMED

    server_name = args.server
    if server_name is not None and server_name not in policy.servers:
        _error(
            "malformed_input",
            f"--server {server_name!r} is not declared in the policy",
            policy=args.policy,
        )
        return EXIT_MALFORMED

    engine = Engine(policy)
    audit = AuditLog(Path(args.audit_log))
    upstream = spawn_upstream(args.upstream)
    bouncer = Bouncer(
        engine=engine,
        audit=audit,
        upstream=upstream,
        session=args.session,
        server_name=server_name,
    )
    bouncer.run_stdio()
    return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="mcpbouncer", description="MCP policy-gate proxy + CLI")
    sub = parser.add_subparsers(dest="command")

    check = sub.add_parser("check", help="evaluate a recorded call log offline against a policy")
    check.add_argument("policy", help="path to policy.toml")
    check.add_argument("calls", help="path to calls.jsonl")
    check.add_argument("--audit-log", default=None, help="where to write the audit JSONL (default: <calls>.audit.jsonl)")
    check.set_defaults(func=cmd_check)

    init = sub.add_parser("init", help="write a working starter policy")
    init.add_argument("--out", default="policy.toml", help="output policy path (default: policy.toml)")
    init.add_argument("--config", default=None, help="existing MCP client config JSON to read declared servers from")
    init.add_argument("--force", action="store_true", help="overwrite an existing policy file")
    init.set_defaults(func=cmd_init)

    proxy = sub.add_parser("proxy", help="run the live stdio policy-gate proxy in front of an upstream MCP server")
    proxy.add_argument("--policy", required=True, help="path to policy.toml")
    proxy.add_argument("--audit-log", default="mcpbouncer-audit.jsonl", help="append-only audit log path")
    proxy.add_argument("--session", default="default", help="session id for rate-limit accounting")
    proxy.add_argument(
        "--server",
        default=None,
        help=(
            "the [[server]] name (from --policy) this proxy instance fronts -- one upstream "
            "process per proxy invocation. When set, tools/list responses are rewritten so "
            "the advertised tool name is the exact qualified 'server__tool' name this proxy "
            "routes on tools/call, so a conforming client's calls are never falsely denied."
        ),
    )
    proxy.add_argument(
        "--upstream",
        nargs=argparse.REMAINDER,
        required=True,
        help="upstream MCP server command, e.g. --upstream python -m my_server",
    )
    proxy.set_defaults(func=cmd_proxy)

    return parser


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help()
        return EXIT_MALFORMED
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
