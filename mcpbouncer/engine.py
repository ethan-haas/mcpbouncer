"""Decision engine: evaluate one MCP ``tools/call`` request against a
loaded Policy and return the verdict contract.

Rules are evaluated in a fixed, deterministic order; the first failing rule
wins and names itself in ``rule_id``. A server, tool, or argument KEY the
policy does not declare is ``unmatched-deny`` -- rule 1 (server/tool
allowlist), argument-key coverage, and the unmatched fallback are the same
mechanism by construction: nothing is allowed unless explicitly declared.
An undeclared argument key on an otherwise-declared tool is denied with
``rule_id`` ``unmatched_arg`` before any of the argument-shaped rules
(path confinement, caps, enum/pattern) ever look at it -- a policy that
declares ``path`` for a tool must not let a second, undeclared key like
``altpath`` smuggle a value past path confinement.

Rule 7 (result redaction) is deliberately NOT part of ``evaluate`` -- it
does not classify a *request*, it masks *response* content after an
allowed call returns, and the correct decision for that case is
``allow`` (forwarded) plus a reported redaction count, never a silent
drop. See ``Engine.redact`` and ``mcpbouncer.proxy``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from mcpbouncer.pathconfine import is_under_root
from mcpbouncer.policy import Policy


@dataclass(frozen=True)
class Decision:
    decision: str  # "allow" | "deny" | "unmatched-deny"
    rule_id: str
    server: Any
    tool: Any
    json_pointer: str
    evidence: dict
    message: str

    def as_dict(self) -> dict:
        return {
            "decision": self.decision,
            "rule_id": self.rule_id,
            "server": self.server,
            "tool": self.tool,
            "json_pointer": self.json_pointer,
            "evidence": self.evidence,
            "message": self.message,
        }


def _pointer_token(token: object) -> str:
    s = str(token)
    return s.replace("~", "~0").replace("/", "~1")


def pointer(*parts: object) -> str:
    if not parts:
        return ""
    return "".join("/" + _pointer_token(p) for p in parts)


def _depth(value: Any) -> int:
    if isinstance(value, dict):
        if not value:
            return 1
        return 1 + max(_depth(v) for v in value.values())
    if isinstance(value, list):
        if not value:
            return 1
        return 1 + max(_depth(v) for v in value)
    return 0


def _check_caps(arguments: dict, limits) -> tuple[str, list, dict] | None:
    """Depth-first walk of the arguments tree looking for the first cap
    violation. Returns (cap_kind, pointer_parts, evidence) or None."""

    def walk(value: Any, path: list) -> tuple[str, list, dict] | None:
        if isinstance(value, str):
            if len(value) > limits.max_string_length:
                return (
                    "max_string_length",
                    path,
                    {"limit": limits.max_string_length, "actual": len(value)},
                )
            return None
        if isinstance(value, list):
            if len(value) > limits.max_array_length:
                return (
                    "max_array_length",
                    path,
                    {"limit": limits.max_array_length, "actual": len(value)},
                )
            for i, item in enumerate(value):
                hit = walk(item, path + [i])
                if hit is not None:
                    return hit
            return None
        if isinstance(value, dict):
            for key, item in value.items():
                hit = walk(item, path + [key])
                if hit is not None:
                    return hit
            return None
        return None

    depth = _depth(arguments)
    if depth > limits.max_nesting_depth:
        return "max_nesting_depth", [], {"limit": limits.max_nesting_depth, "actual": depth}
    return walk(arguments, [])


class Engine:
    def __init__(self, policy: Policy):
        self.policy = policy

    def evaluate(
        self,
        request: dict,
        session: str = "default",
        counts: dict | None = None,
    ) -> Decision:
        counts = {} if counts is None else counts
        server_name = request.get("server")
        tool_name = request.get("tool")
        raw_arguments = request.get("arguments")

        # Rule 1 / unmatched: server + tool allowlist.
        server = self.policy.servers.get(server_name)
        if server is None:
            return Decision(
                "unmatched-deny",
                "unmatched",
                server_name,
                tool_name,
                pointer("server"),
                {"reason": "server not declared in policy"},
                f"server {server_name!r} is not declared in the policy",
            )
        tool = server.tools.get(tool_name)
        if tool is None:
            return Decision(
                "unmatched-deny",
                "unmatched",
                server_name,
                tool_name,
                pointer("tool"),
                {"reason": "tool not declared for server", "server": server_name},
                f"tool {tool_name!r} is not declared for server {server_name!r}",
            )

        # Fail-unsafe: `arguments`, if present at all, MUST be a JSON object.
        # A non-object value (list, bare string, number, bool) silently
        # coerced to {} here would skip every argument-shaped rule below
        # (path confinement, arg caps, enum/pattern, arg-key coverage) and
        # fall through to allow -- a fail-OPEN hole. Missing `arguments`
        # entirely (None) is not mandatory by SPEC and is treated as "no
        # arguments"; a *present* non-object value is denied explicitly.
        if raw_arguments is None:
            arguments: dict = {}
        elif isinstance(raw_arguments, dict):
            arguments = raw_arguments
        else:
            value_repr = repr(raw_arguments)
            if len(value_repr) > 200:
                value_repr = value_repr[:200] + "...(truncated)"
            return Decision(
                "deny",
                "malformed_arguments",
                server_name,
                tool_name,
                pointer("arguments"),
                {
                    "reason": "arguments must be a JSON object",
                    "type": type(raw_arguments).__name__,
                    "value": value_repr,
                },
                "arguments must be a JSON object (got "
                f"{type(raw_arguments).__name__})",
            )

        # Rule 1 / unmatched: argument-key coverage. A tool's declared args
        # are the union of every arg name the policy references for it
        # (path-confinement targets, arg-cap targets, enum/pattern targets).
        # Any key present in the request's `arguments` object that is not in
        # that declared set is an argument shape the policy does not cover
        # -- unmatched -> denied, same mechanism as the server/tool
        # allowlist above, never inferred and never defaulted to allow.
        # Iterating `arguments` in (JSON-parse) insertion order keeps the
        # pointer deterministic when more than one key is undeclared.
        for arg_name in arguments:
            if arg_name not in tool.args:
                return Decision(
                    "unmatched-deny",
                    "unmatched_arg",
                    server_name,
                    tool_name,
                    pointer("arguments", arg_name),
                    {
                        "reason": "argument key not declared for tool",
                        "server": server_name,
                        "tool": tool_name,
                        "undeclared_key": arg_name,
                    },
                    f"argument key {arg_name!r} is not declared for tool {tool_name!r} "
                    f"on server {server_name!r}",
                )

        # Rule 2: read-only enforcement.
        if server.enforce_read_only and not tool.read_only:
            return Decision(
                "deny",
                "read_only",
                server_name,
                tool_name,
                pointer("tool"),
                {"enforce_read_only": True, "tool_read_only": tool.read_only},
                f"server {server_name!r} enforces read-only; tool {tool_name!r} is not read-only",
            )

        # Rule 3: path confinement.
        for arg_name, spec in tool.args.items():
            if spec.type != "path" or arg_name not in arguments:
                continue
            value = arguments[arg_name]
            if not isinstance(value, str):
                return Decision(
                    "deny",
                    "path_confinement",
                    server_name,
                    tool_name,
                    pointer("arguments", arg_name),
                    {"reason": "path argument is not a string"},
                    f"argument {arg_name!r} must be a string path",
                )
            ok, resolved = is_under_root(value, spec.root)
            if not ok:
                return Decision(
                    "deny",
                    "path_confinement",
                    server_name,
                    tool_name,
                    pointer("arguments", arg_name),
                    {"root": spec.root, "resolved": resolved, "raw": value},
                    f"argument {arg_name!r} resolves outside declared root {spec.root!r}",
                )

        # Rule 4: argument caps.
        cap_hit = _check_caps(arguments, self.policy.limits)
        if cap_hit is not None:
            kind, path_parts, evidence = cap_hit
            ptr = pointer("arguments", *path_parts) if path_parts else pointer("arguments")
            return Decision(
                "deny",
                "arg_caps",
                server_name,
                tool_name,
                ptr,
                {"cap": kind, **evidence},
                f"argument cap exceeded: {kind}",
            )

        # Rule 5: enum / pattern constraints.
        for arg_name, spec in tool.args.items():
            if arg_name not in arguments:
                continue
            value = arguments[arg_name]
            if spec.type == "enum":
                if value not in (spec.values or ()):
                    return Decision(
                        "deny",
                        "enum_pattern",
                        server_name,
                        tool_name,
                        pointer("arguments", arg_name),
                        {"allowed": list(spec.values or ()), "got": value},
                        f"argument {arg_name!r} is not one of the declared enum values",
                    )
            elif spec.type == "string" and spec.pattern:
                import re

                if not isinstance(value, str) or re.fullmatch(spec.pattern, value) is None:
                    return Decision(
                        "deny",
                        "enum_pattern",
                        server_name,
                        tool_name,
                        pointer("arguments", arg_name),
                        {"pattern": spec.pattern, "got": value},
                        f"argument {arg_name!r} does not match the declared pattern",
                    )

        # Rule 6: rate & budget caps.
        rl_key = f"{server_name}.{tool_name}"
        limit = self.policy.rate_limits.get(rl_key)
        count_key = (session, server_name, tool_name)
        current = counts.get(count_key, 0)
        if limit is not None and current >= limit:
            return Decision(
                "deny",
                "rate_limit",
                server_name,
                tool_name,
                pointer("tool"),
                {"limit": limit, "session_calls": current, "session": session},
                f"rate limit exceeded for {rl_key!r} in session {session!r}",
            )
        counts[count_key] = current + 1

        return Decision(
            "allow",
            "allow",
            server_name,
            tool_name,
            "",
            {},
            "allowed",
        )

    def redact(self, text: str) -> tuple[str, dict[str, int]]:
        """Rule 7: mask declared literal regex classes in response text.
        Returns (redacted_text, counts_per_class).

        Each byte of ``text`` is masked at most ONCE and attributed to
        exactly ONE owning pattern. Patterns are matched against the
        ORIGINAL text (never against a previously-substituted result) and
        claimed in policy declaration order: the first-declared pattern
        whose match span does not overlap an already-claimed span wins that
        span. This is a deliberate, documented choice ("first-match wins")
        -- without it, applying patterns sequentially against the
        already-redacted text lets a later, more general pattern (e.g. a
        generic `key\\s*[:=]\\s*\\S+` catch-all) re-match the placeholder
        text an earlier, more specific pattern already substituted (e.g. an
        AWS-access-key literal), double-counting one masked span as a hit
        for two different rule ids.
        """
        claims: list[tuple[int, int, str]] = []  # (start, end, rule_id), sorted by start at build time
        counts: dict[str, int] = {}

        def _overlaps_claim(start: int, end: int) -> bool:
            return any(not (end <= s or start >= e) for s, e, _ in claims)

        for rule in self.policy.redactions:
            for match in rule.pattern.finditer(text):
                start, end = match.span()
                if start == end:
                    continue  # zero-width match masks nothing
                if _overlaps_claim(start, end):
                    continue
                claims.append((start, end, rule.id))
                counts[rule.id] = counts.get(rule.id, 0) + 1

        if not claims:
            return text, counts

        claims.sort(key=lambda c: c[0])
        pieces: list[str] = []
        cursor = 0
        for start, end, rule_id in claims:
            pieces.append(text[cursor:start])
            pieces.append(f"[REDACTED:{rule_id}]")
            cursor = end
        pieces.append(text[cursor:])
        return "".join(pieces), counts
