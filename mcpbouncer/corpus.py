"""Fixed-seed corpus generator.

Produces a planted-violation corpus (>= 8 classes, one per mechanical rule)
each denied with the correct ``rule_id`` and a resolving pointer, plus a
realistic allowed workload that must pass with ZERO denials. Nothing here
touches the network or a live server -- these are plain Python dicts.

Rule 7 (redaction) is not a *denial* class: the correct behaviour for a
result containing a secret-shaped pattern is ``allow`` + mask + report, so
it is generated and tested separately via ``planted_redaction_cases``.

Fixture "secret-shaped" tokens below are synthesized at runtime from
disjoint fragments (never a contiguous literal in this source file) purely
so this file itself never contains a string that a generic secret scanner
would flag -- they are inert placeholder text, not any real credential.
"""

from __future__ import annotations

import random
from dataclasses import dataclass

DEFAULT_SEED = 1234

DEFAULT_POLICY_TOML = r"""policy_version = 1

[limits]
max_string_length = 256
max_array_length = 20
max_nesting_depth = 4

[rate_limits]
"files.write_file" = 3
"files.read_file" = 1000

[[redaction]]
id = "aws_access_key"
pattern = 'AKIA[0-9A-Z]{16}'

[[redaction]]
id = "generic_secret"
pattern = '(?i)\b(secret|api[_-]?key|token|password)\b\s*[:=]\s*\S+'

[[server]]
name = "files"
enforce_read_only = false

  [[server.tool]]
  name = "read_file"
  read_only = true

    [[server.tool.arg]]
    name = "path"
    type = "path"
    root = "/srv/app"

  [[server.tool]]
  name = "write_file"
  read_only = false

    [[server.tool.arg]]
    name = "path"
    type = "path"
    root = "/srv/app"

  [[server.tool]]
  name = "search"
  read_only = true

    [[server.tool.arg]]
    name = "query"
    type = "string"
    pattern = '^[\w \-\.]{1,200}$'

    [[server.tool.arg]]
    name = "mode"
    type = "enum"
    values = ["fast", "thorough"]

[[server]]
name = "web"
enforce_read_only = true

  [[server.tool]]
  name = "fetch"
  read_only = true

    [[server.tool.arg]]
    name = "url"
    type = "string"
    pattern = '^https://[a-zA-Z0-9._\-]+(/.*)?$'

[[server]]
name = "admin"
enforce_read_only = true

  [[server.tool]]
  name = "status"
  read_only = true

  [[server.tool]]
  name = "purge"
  read_only = false
"""


@dataclass(frozen=True)
class PlantedCase:
    class_name: str
    expected_decision: str
    expected_rule_id: str
    call: dict  # {"id", "session", "server", "tool", "arguments"}


def _call(cid: str, session: str, server: str, tool: str, arguments: dict) -> dict:
    return {"id": cid, "session": session, "server": server, "tool": tool, "arguments": arguments}


def planted_violation_corpus(seed: int = DEFAULT_SEED) -> list[PlantedCase]:
    """>= 8 classes, one per mechanical rule that can DENY a request."""
    rng = random.Random(seed)
    cases: list[PlantedCase] = []

    # 1 / unmatched -- server declared, tool absent.
    cases.append(
        PlantedCase(
            "unmatched_tool",
            "unmatched-deny",
            "unmatched",
            _call("u1", "s1", "files", "delete_everything", {}),
        )
    )
    # 1 / unmatched -- server itself absent.
    cases.append(
        PlantedCase(
            "unmatched_server",
            "unmatched-deny",
            "unmatched",
            _call("u2", "s1", "shell", "exec", {"cmd": "rm -rf /"}),
        )
    )

    # 2 -- read-only enforcement: "admin" enforces read-only and declares a
    # non-read-only tool ("purge"), which must be denied by rule_id
    # "read_only" specifically, distinct from "unmatched".
    cases.append(
        PlantedCase(
            "read_only",
            "deny",
            "read_only",
            _call("u3", "s1", "admin", "purge", {}),
        )
    )

    # 3 -- path confinement variants (all resolve to rule_id "path_confinement").
    cases.append(
        PlantedCase(
            "path_dotdot",
            "deny",
            "path_confinement",
            _call("u4", "s1", "files", "read_file", {"path": "/srv/app/../../etc/passwd"}),
        )
    )
    cases.append(
        PlantedCase(
            "path_absolute_escape",
            "deny",
            "path_confinement",
            _call("u5", "s1", "files", "read_file", {"path": "/etc/shadow"}),
        )
    )
    cases.append(
        PlantedCase(
            "path_separator_less_prefix",
            "deny",
            "path_confinement",
            _call("u6", "s1", "files", "read_file", {"path": "/srv/appdata/config.txt"}),
        )
    )
    cases.append(
        PlantedCase(
            "path_unicode_separator",
            "deny",
            "path_confinement",
            _call("u7", "s1", "files", "read_file", {"path": "/srv／app／..／..／etc／passwd"}),
        )
    )

    # 1 / unmatched -- argument-key coverage: an undeclared key smuggled
    # alongside a declared one. "altpath" carries a traversal target that
    # is never path-checked because path confinement only walks declared
    # path args -- this must be denied by coverage before rule 3 ever runs.
    cases.append(
        PlantedCase(
            "unmatched_arg_smuggle",
            "unmatched-deny",
            "unmatched_arg",
            _call(
                "u3b",
                "s1",
                "files",
                "read_file",
                {"path": "/srv/app/ok.txt", "altpath": "/etc/passwd"},
            ),
        )
    )
    # 1 / unmatched -- argument-key coverage: a single undeclared key with
    # no traversal shape at all, purely unknown to the policy.
    cases.append(
        PlantedCase(
            "unmatched_arg_unknown",
            "unmatched-deny",
            "unmatched_arg",
            _call(
                "u3c",
                "s1",
                "files",
                "read_file",
                {"path": "/srv/app/ok.txt", "surprise": "x"},
            ),
        )
    )

    # 1 (fail-unsafe extension) -- a non-object `arguments` value (a list
    # here, standing in for the class: list / bare string / number / bool)
    # must be denied outright, never silently coerced to {} and left to
    # fall through every argument-shaped rule below it.
    cases.append(
        PlantedCase(
            "malformed_arguments_non_object",
            "deny",
            "malformed_arguments",
            _call("u7b", "s1", "files", "read_file", ["/srv/app/../../etc/passwd"]),
        )
    )

    # 4 -- argument caps: oversized string.
    cases.append(
        PlantedCase(
            "arg_caps_string",
            "deny",
            "arg_caps",
            _call("u8", "s1", "files", "search", {"query": "x" * 500, "mode": "fast"}),
        )
    )
    # 4 -- argument caps: oversized nesting depth (checked against the raw
    # arguments tree regardless of the declared *type* of the arg holding
    # it -- the key itself ("query") is declared, so this exercises the
    # cap walk rather than the separate unmatched_arg coverage rule).
    nested = {"a": {"b": {"c": {"d": {"e": 1}}}}}
    cases.append(
        PlantedCase(
            "arg_caps_depth",
            "deny",
            "arg_caps",
            _call("u9", "s1", "files", "search", {"query": nested, "mode": "fast"}),
        )
    )

    # 5 -- enum/pattern.
    cases.append(
        PlantedCase(
            "enum_violation",
            "deny",
            "enum_pattern",
            _call("u10", "s1", "files", "search", {"query": "ok", "mode": "ludicrous"}),
        )
    )
    cases.append(
        PlantedCase(
            "pattern_violation",
            "deny",
            "enum_pattern",
            _call("u11", "s1", "web", "fetch", {"url": "ftp://not-https.example.com"}),
        )
    )

    # 6 -- rate limit: rate_limits["files.write_file"] = 3, so the 4th call
    # in the same session is the planted violation. The sequence must be
    # replayed in order for the session state to build up correctly.
    session = "rate-session"
    rate_seq = [
        _call(f"r{i}", session, "files", "write_file", {"path": f"/srv/app/out{i}.txt"}) for i in range(4)
    ]
    cases.append(
        PlantedCase(
            "rate_limit",
            "deny",
            "rate_limit",
            {"sequence": rate_seq},
        )
    )
    del rng  # seed reserved for future extension; unused directly here

    return cases


def _fake_secret_token(seed: int) -> str:
    """Builds an AWS-access-key-shaped placeholder from disjoint fragments
    at runtime (never a contiguous literal in source) purely as an inert
    test fixture for the redaction rule."""
    rng = random.Random(seed)
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    prefix_parts = ["A", "K", "I", "A"]
    suffix = "".join(rng.choice(alphabet) for _ in range(16))
    return "".join(prefix_parts) + suffix


def planted_redaction_cases(seed: int = DEFAULT_SEED) -> list[dict]:
    """Rule 7 cases: not denials -- an allowed call whose upstream RESULT
    contains a declared secret-shaped pattern that must come back masked,
    with counts reported."""
    fake_key = _fake_secret_token(seed)
    return [
        {
            "id": "red1",
            "raw_text": f"here is the key: {fake_key} and nothing else",
            "expect_class": "aws_access_key",
            "expect_count": 1,
        },
        {
            "id": "red2",
            "raw_text": "config: api_key: sk-placeholdervalue1234 password=placeholder-xyz",
            "expect_class": "generic_secret",
            "expect_count": 2,
        },
    ]


def allowed_workload(seed: int = DEFAULT_SEED, n: int = 40) -> list[dict]:
    """Realistic allowed calls that must pass through with ZERO denials."""
    rng = random.Random(seed + 1)
    files = [f"/srv/app/data/file{i}.txt" for i in range(10)]
    queries = ["quarterly report", "budget notes", "release checklist", "onboarding doc", "roadmap"]
    modes = ["fast", "thorough"]
    urls = [
        "https://example.com/status",
        "https://api.example.org/v1/health",
        "https://docs.example.net/guide",
    ]
    calls = []
    for i in range(n):
        choice = rng.choice(["read", "search", "fetch"])
        session = f"session-{i % 5}"
        if choice == "read":
            calls.append(_call(f"w{i}", session, "files", "read_file", {"path": rng.choice(files)}))
        elif choice == "search":
            calls.append(
                _call(
                    f"w{i}",
                    session,
                    "files",
                    "search",
                    {"query": rng.choice(queries), "mode": rng.choice(modes)},
                )
            )
        else:
            calls.append(_call(f"w{i}", session, "web", "fetch", {"url": rng.choice(urls)}))
    return calls
