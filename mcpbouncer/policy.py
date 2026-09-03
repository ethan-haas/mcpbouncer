"""Policy model + loader for mcpbouncer.

Policy is a declared, versioned TOML file. A tool/server/argument shape the
policy does not cover is `unmatched` -> DENIED. Never inferred, never
defaulted to allow. Parsing is strict: any structural problem raises
PolicyError, which the CLI turns into exit code 2.
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass, field
from typing import Any

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - only exercised on py<3.11
    import tomli as tomllib  # type: ignore[no-redef]


class PolicyError(Exception):
    """Raised for any malformed or structurally invalid policy file."""


@dataclass(frozen=True)
class Limits:
    max_string_length: int = 4096
    max_array_length: int = 100
    max_nesting_depth: int = 6


@dataclass(frozen=True)
class RedactionRule:
    id: str
    pattern: "re.Pattern[str]"
    raw_pattern: str


@dataclass(frozen=True)
class ArgSpec:
    name: str
    type: str  # "path" | "string" | "enum"
    root: str | None = None
    pattern: str | None = None
    values: tuple[str, ...] | None = None


@dataclass(frozen=True)
class ToolSpec:
    name: str
    read_only: bool
    args: dict[str, ArgSpec] = field(default_factory=dict)


@dataclass(frozen=True)
class ServerSpec:
    name: str
    enforce_read_only: bool
    tools: dict[str, ToolSpec] = field(default_factory=dict)


@dataclass(frozen=True)
class Policy:
    version: Any
    limits: Limits
    rate_limits: dict[str, int]
    redactions: tuple[RedactionRule, ...]
    servers: dict[str, ServerSpec]


_VALID_ARG_TYPES = ("path", "string", "enum")

# A string policy_version must be a well-formed dotted version ("1",
# "1.2", "1.2.3", ...) -- digits and dots only. An arbitrary non-numeric
# string ("one") is malformed, same class as a float (1.5) or a bool
# (true), both already rejected below.
_VERSION_STRING_RE = re.compile(r"^\d+(\.\d+)*$")


def _require(cond: bool, message: str) -> None:
    if not cond:
        raise PolicyError(message)


def _require_known_keys(raw: dict[str, Any], allowed: "set[str]", scope: str) -> None:
    """Fail-unsafe: an unrecognized key at ANY policy scope is a malformed
    policy, not something to silently ignore. A misspelled key (e.g.
    ``enforce_readonly`` instead of ``enforce_read_only``) must never load
    with the intended field simply defaulting to its default value -- that
    is a config hole that flips deny -> allow on a one-character typo."""
    unknown = sorted(set(raw.keys()) - allowed)
    if unknown:
        raise PolicyError(
            f"unknown key {unknown[0]!r} in {scope} "
            f"(allowed keys: {', '.join(sorted(allowed))})"
        )


_TOP_LEVEL_KEYS = {"policy_version", "limits", "rate_limits", "redaction", "server"}
_LIMITS_KEYS = {"max_string_length", "max_array_length", "max_nesting_depth"}
_REDACTION_KEYS = {"id", "pattern"}
_SERVER_KEYS = {"name", "enforce_read_only", "tool"}
_TOOL_KEYS = {"name", "read_only", "arg"}
_ARG_KEYS = {"name", "type", "root", "pattern", "values"}


def _parse_limits(raw: dict[str, Any]) -> Limits:
    if raw is None:
        return Limits()
    _require(isinstance(raw, dict), "[limits] must be a table")
    _require_known_keys(raw, _LIMITS_KEYS, "[limits]")
    kwargs: dict[str, int] = {}
    for key in ("max_string_length", "max_array_length", "max_nesting_depth"):
        if key in raw:
            value = raw[key]
            _require(
                isinstance(value, int) and not isinstance(value, bool) and value > 0,
                f"[limits].{key} must be a positive integer",
            )
            kwargs[key] = value
    return Limits(**kwargs)


def _parse_rate_limits(raw: dict[str, Any] | None) -> dict[str, int]:
    if raw is None:
        return {}
    _require(isinstance(raw, dict), "[rate_limits] must be a table")
    out: dict[str, int] = {}
    for key, value in raw.items():
        _require(isinstance(key, str) and "." in key, f"rate_limits key '{key}' must be 'server.tool'")
        _require(
            isinstance(value, int) and not isinstance(value, bool) and value >= 0,
            f"rate_limits.{key} must be a non-negative integer",
        )
        out[key] = value
    return out


def _parse_redactions(raw: list[Any] | None) -> tuple[RedactionRule, ...]:
    if raw is None:
        return ()
    _require(isinstance(raw, list), "[[redaction]] must be an array of tables")
    seen_ids: list[str] = []
    rules: list[RedactionRule] = []
    for entry in raw:
        _require(isinstance(entry, dict), "each [[redaction]] entry must be a table")
        _require_known_keys(entry, _REDACTION_KEYS, "[[redaction]] entry")
        rid = entry.get("id")
        pattern = entry.get("pattern")
        _require(isinstance(rid, str) and rid, "[[redaction]].id must be a non-empty string")
        _require(isinstance(pattern, str) and pattern, "[[redaction]].pattern must be a non-empty string")
        _require(rid not in seen_ids, f"duplicate redaction id '{rid}'")
        seen_ids.append(rid)
        try:
            compiled = re.compile(pattern)
        except re.error as exc:
            raise PolicyError(f"redaction '{rid}' has invalid regex pattern: {exc}") from exc
        rules.append(RedactionRule(id=rid, pattern=compiled, raw_pattern=pattern))
    return tuple(rules)


def _parse_arg(entry: dict[str, Any], tool_name: str) -> ArgSpec:
    _require(isinstance(entry, dict), f"tool '{tool_name}' has a malformed arg entry")
    _require_known_keys(entry, _ARG_KEYS, f"tool '{tool_name}' arg entry")
    name = entry.get("name")
    atype = entry.get("type")
    _require(isinstance(name, str) and name, f"tool '{tool_name}' has an arg with no name")
    _require(atype in _VALID_ARG_TYPES, f"tool '{tool_name}' arg '{name}' has unknown type '{atype}'")
    root = entry.get("root")
    pattern = entry.get("pattern")
    values = entry.get("values")
    if atype == "path":
        _require(isinstance(root, str) and root, f"tool '{tool_name}' arg '{name}' (type=path) requires 'root'")
    if atype == "enum":
        _require(
            isinstance(values, list) and all(isinstance(v, str) for v in values) and values,
            f"tool '{tool_name}' arg '{name}' (type=enum) requires non-empty string 'values'",
        )
        values = tuple(values)
    if pattern is not None:
        _require(isinstance(pattern, str), f"tool '{tool_name}' arg '{name}' pattern must be a string")
        try:
            re.compile(pattern)
        except re.error as exc:
            raise PolicyError(f"tool '{tool_name}' arg '{name}' has invalid regex: {exc}") from exc
    return ArgSpec(name=name, type=atype, root=root, pattern=pattern, values=values)


def _parse_tool(entry: dict[str, Any], server_name: str) -> ToolSpec:
    _require(isinstance(entry, dict), f"server '{server_name}' has a malformed tool entry")
    _require_known_keys(entry, _TOOL_KEYS, f"server '{server_name}' tool entry")
    name = entry.get("name")
    _require(isinstance(name, str) and name, f"server '{server_name}' has a tool with no name")
    read_only = entry.get("read_only", False)
    _require(isinstance(read_only, bool), f"tool '{name}' read_only must be a boolean")
    args: dict[str, ArgSpec] = {}
    for arg_entry in entry.get("arg", []) or []:
        spec = _parse_arg(arg_entry, name)
        _require(spec.name not in args, f"tool '{name}' has a duplicate arg '{spec.name}'")
        args[spec.name] = spec
    return ToolSpec(name=name, read_only=read_only, args=args)


def _parse_server(entry: dict[str, Any]) -> ServerSpec:
    _require(isinstance(entry, dict), "each [[server]] entry must be a table")
    _require_known_keys(entry, _SERVER_KEYS, "[[server]] entry")
    name = entry.get("name")
    _require(isinstance(name, str) and name, "each server needs a non-empty 'name'")
    enforce_read_only = entry.get("enforce_read_only", False)
    _require(isinstance(enforce_read_only, bool), f"server '{name}' enforce_read_only must be a boolean")
    tools: dict[str, ToolSpec] = {}
    for tool_entry in entry.get("tool", []) or []:
        spec = _parse_tool(tool_entry, name)
        _require(spec.name not in tools, f"server '{name}' has a duplicate tool '{spec.name}'")
        tools[spec.name] = spec
    return ServerSpec(name=name, enforce_read_only=enforce_read_only, tools=tools)


def parse_policy(raw: dict[str, Any]) -> Policy:
    _require(isinstance(raw, dict), "policy root must be a table")
    _require_known_keys(raw, _TOP_LEVEL_KEYS, "policy root")
    version = raw.get("policy_version")
    _require(
        isinstance(version, (int, str)) and not isinstance(version, bool),
        "policy_version is required and must be an int or string",
    )
    if isinstance(version, str):
        _require(
            _VERSION_STRING_RE.fullmatch(version) is not None,
            f"policy_version {version!r} is not a valid dotted version string "
            "(expected digits and dots, e.g. '1' or '1.2.3')",
        )
    limits = _parse_limits(raw.get("limits"))
    rate_limits = _parse_rate_limits(raw.get("rate_limits"))
    redactions = _parse_redactions(raw.get("redaction"))

    servers: dict[str, ServerSpec] = {}
    for entry in raw.get("server", []) or []:
        spec = _parse_server(entry)
        _require(spec.name not in servers, f"duplicate server '{spec.name}'")
        servers[spec.name] = spec

    for key in rate_limits:
        server_name, _, tool_name = key.partition(".")
        server = servers.get(server_name)
        _require(server is not None, f"rate_limits references unknown server '{server_name}'")
        _require(
            tool_name in server.tools,
            f"rate_limits references unknown tool '{tool_name}' on server '{server_name}'",
        )

    return Policy(
        version=version,
        limits=limits,
        rate_limits=rate_limits,
        redactions=redactions,
        servers=servers,
    )


def load_policy(path: str) -> Policy:
    try:
        with open(path, "rb") as f:
            raw = tomllib.load(f)
    except FileNotFoundError as exc:
        raise PolicyError(f"policy file not found: {path}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise PolicyError(f"policy file is not valid TOML: {exc}") from exc
    return parse_policy(raw)
