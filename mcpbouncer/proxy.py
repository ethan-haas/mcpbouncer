"""MCP proxy: JSON-RPC 2.0 over stdio, client <-> bouncer <-> upstream.

Only ``tools/call`` is checked against policy. Every other method
(initialize, ...) is relayed to upstream -- NOT byte-identity-guaranteed
the way an intercepted ``tools/call`` is (see below); a passthrough method
may be re-serialized on its way through -- EXCEPT ``tools/list``, which is
still passed through to the real upstream but has its result's tool names
rewritten (when ``server_name`` is configured -- see below) so what the
proxy ADVERTISES is exactly what it will ROUTE on ``tools/call``. Allowed
``tools/call`` requests are forwarded byte-for-byte identical to what the
client sent; the response is forwarded byte-for-byte identical to what
upstream returned, except for declared (rule 7) redactions, which are
reported via an extra audit record, never silently applied -- see
``handle_raw`` for the byte-transparent stdio path, and ``handle_request``
for the dict-based path used by in-process tests and non-``tools/call``
methods.

A request whose method NORMALIZES (NFKC-folded, case-insensitively,
whitespace-stripped) to ``tools/call`` but is not byte-identical to that
exact literal (e.g. ``Tools/Call``, ``tools/call `` with trailing
whitespace, or a fullwidth-Unicode confusable like ``ｔｏｏｌｓ／ｃａｌｌ``
which NFKC-folds to exactly ``tools/call``) is a smuggle attempt around
the exact-string interception key -- denied fail-unsafe as malformed,
never forwarded ungated. See ``is_tools_call_method_variant``.

Any message shape the proxy cannot parse as a well-formed single
JSON-RPC request object -- a JSON parse error, a batch array, a bare
scalar, ``params`` that isn't an object where one is required, or a
non-string ``params.name`` -- returns a structured ``malformed_input``
JSON-RPC error response (fail-safe: nothing forwarded upstream, an audit
line is written) instead of raising and killing the session. See
``Bouncer._validate_message_shape`` / ``Bouncer._resolve_tools_call``.

The upstream transport is injectable so tests never need a real subprocess
or network access -- see ``FunctionTransport`` for an in-process fixture,
and ``StdioTransport``/``spawn_upstream`` for real MCP servers.

Qualified tool naming: a proxy in front of potentially many upstream MCP
servers needs to know *which* server a call is for. Incoming
``params.name`` is expected in the form ``"<server>__<tool>"`` (double
underscore). A name without that separator has an empty server component,
which the policy will never have declared, so it is correctly
``unmatched-deny`` rather than silently routed anywhere. One ``Bouncer``
(and correspondingly one ``mcpbouncer proxy`` process) fronts one upstream
and represents exactly one policy ``[[server]]`` -- passed as
``server_name`` -- so a conforming client that just calls the name
``tools/list`` showed it always routes, rather than being denied for
having sent the bare (unqualified) name upstream itself advertised.
"""

from __future__ import annotations

import json
import subprocess
import sys
import unicodedata
from dataclasses import dataclass, field
from typing import Any, Callable, Optional, Protocol

from mcpbouncer.audit import AuditLog
from mcpbouncer.engine import Decision, Engine, pointer

DENIAL_ERROR_CODE = -32001


class Transport(Protocol):
    def send(self, message: dict) -> None: ...

    def recv(self) -> Optional[dict]: ...


class StdioTransport:
    """Real newline-delimited-JSON stdio transport to a spawned upstream
    MCP server subprocess."""

    def __init__(self, proc: "subprocess.Popen[str]"):
        self.proc = proc

    def send(self, message: dict) -> None:
        assert self.proc.stdin is not None
        self.proc.stdin.write(json.dumps(message, separators=(",", ":")) + "\n")
        self.proc.stdin.flush()

    def recv(self) -> Optional[dict]:
        """Read the next JSON-RPC RESPONSE object from upstream.

        Robustness (fail-safe, session-preserving, upstream-inbound analog
        of the client-inbound guard): a real MCP server commonly
        writes stdout lines that are NOT a JSON-RPC response -- a stray
        ``DEBUG:``/log/startup-banner line, other non-JSON text, or a bare
        JSON scalar/array (``42``, ``"hi"``, ``true``, ``null``, ``[...]``).
        Such a line is not a protocol message the proxy can scan/redact, so
        it is never returned as-if it were the response (that would either
        raise ``JSONDecodeError``/``TypeError`` out of the caller, killing
        the whole stdio session, or -- worse -- let an unscannable line
        slip through as a fake ``tools/call`` result, bypassing
        redaction). Instead it is SKIPPED and reading continues on the same
        connection until either a genuine JSON object line arrives or the
        upstream closes (EOF, ``readline()`` returns ``""``)."""
        assert self.proc.stdout is not None
        while True:
            line = self.proc.stdout.readline()
            if not line:
                return None
            try:
                parsed = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(parsed, dict):
                continue
            return parsed

    def send_raw(self, raw: str) -> None:
        """Forward the exact request text the client sent, unre-serialized
        -- gate 5 (transparency) requires an allowed call be forwarded
        byte-identical to what the client sent, not merely deep-equal after
        a parse/re-dump round trip."""
        assert self.proc.stdin is not None
        self.proc.stdin.write(raw + "\n")
        self.proc.stdin.flush()

    def recv_raw(self) -> Optional[str]:
        """Return the exact response text the upstream sent, unparsed --
        the counterpart to ``send_raw`` for byte-identical forwarding back
        to the client when zero redactions apply.

        Same upstream-inbound robustness as ``recv`` above: a line that
        isn't valid JSON, or that parses to something other than a JSON
        object (a bare scalar/array), is not a JSON-RPC response -- it is
        almost always the upstream's own incidental logging mixed onto
        stdout. It is SKIPPED (never returned, never crashes, never
        forwarded to the client as if it were a ``tools/call`` result) and
        reading continues on the same connection so the matching response
        for the pending request is still found on a later line, keeping
        the session alive for every call after it too."""
        assert self.proc.stdout is not None
        while True:
            line = self.proc.stdout.readline()
            if not line:
                return None
            text = line.rstrip("\r\n")
            try:
                parsed = json.loads(text)
            except json.JSONDecodeError:
                continue
            if not isinstance(parsed, dict):
                continue
            return text

    def close(self) -> None:
        if self.proc.stdin:
            self.proc.stdin.close()
        self.proc.terminate()


def spawn_upstream(command: list[str]) -> StdioTransport:
    proc = subprocess.Popen(
        command,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        bufsize=1,
    )
    # subprocess.Popen has no `newline=` kwarg, so reconfigure the resulting
    # TextIOWrapper pipes directly. newline="" disables Python's text-mode
    # newline translation on BOTH pipes. Without it, on Windows, writing
    # "\n" to proc.stdin gets translated to os.linesep ("\r\n") before it
    # reaches the upstream process, and reading proc.stdout applies
    # universal-newlines normalization -- either way the wire framing no
    # longer matches what was actually sent/emitted. newline="" still
    # tolerates any of \n / \r\n / \r on read (universal-newlines mode
    # stays on for reading) but performs zero translation on write, so a
    # "\n" we write arrives as a bare LF, matching JSON-RPC line framing.
    for stream in (proc.stdin, proc.stdout):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            try:
                reconfigure(newline="")
            except (ValueError, OSError):
                pass
    return StdioTransport(proc)


class FunctionTransport:
    """In-process fixture transport for tests: a callable stands in for the
    upstream server, no subprocess or network required."""

    def __init__(self, handler: Callable[[dict], dict]):
        self.handler = handler
        self._last: Optional[dict] = None

    def send(self, message: dict) -> None:
        self._last = message

    def recv(self) -> Optional[dict]:
        if self._last is None:
            return None
        return self.handler(self._last)


def parse_qualified_tool(name: str) -> tuple[str, str]:
    if "__" not in name:
        return "", name
    server, _, tool = name.partition("__")
    return server, tool


def qualify_tool(server: str, tool: str) -> str:
    return f"{server}__{tool}"


TOOLS_CALL_METHOD = "tools/call"


def is_tools_call_method_variant(method: Any) -> bool:
    """A conforming client always sends the method string as the exact
    literal ``"tools/call"``. If ``method`` is a string that normalizes
    (NFKC-folded, case-insensitively, whitespace-stripped) to that literal
    but is not byte-identical to it -- e.g. ``"Tools/Call"``,
    ``"TOOLS/CALL"``, ``"tools/call "`` with trailing whitespace, or a
    fullwidth-Unicode confusable like ``"ｔｏｏｌｓ／ｃａｌｌ"`` (U+FF54
    U+FF4F ... U+FF0F ... U+FF4C, which NFKC-folds to exactly
    ``"tools/call"``) -- it is a tools/call-shaped variant that must be
    denied fail-unsafe rather than treated as some unrelated method and
    forwarded ungated (interception keys on an exact string match;
    anything not recognized as exactly ``tools/call`` would otherwise fall
    through the passthrough branch with zero policy checks). NFKC
    normalization is mandatory here, not optional: without it, a
    Unicode-compatibility variant that's visually/semantically identical
    to ``tools/call`` after normalization sails through the strip+casefold
    check untouched (it isn't equal to ``tools/call`` under strip+lower
    alone) and is forwarded with zero policy checks. Returns False for the
    exact literal itself (handled by the normal gated path) and for
    anything that isn't tools/call-shaped at all (genuinely unrelated
    methods like ``initialize``/``ping``, or unrelated strings like
    ``tools/list``, ``tools/call/extra``, ``notifications/tools/call``,
    ``atools/call``, ``tools/calls``)."""
    if not isinstance(method, str) or method == TOOLS_CALL_METHOD:
        return False
    normalized = unicodedata.normalize("NFKC", method).strip().lower()
    return normalized == TOOLS_CALL_METHOD


def _walk_redact(value: Any, engine: Engine, counts: dict[str, int]) -> Any:
    if isinstance(value, str):
        redacted, hit_counts = engine.redact(value)
        for key, n in hit_counts.items():
            counts[key] = counts.get(key, 0) + n
        return redacted
    if isinstance(value, list):
        return [_walk_redact(v, engine, counts) for v in value]
    if isinstance(value, dict):
        # Rule 7 also covers object KEY names, not just values: an upstream
        # that emits a secret-shaped token AS A KEY (e.g.
        # {"AKIA...": "v"}) must have that key masked and counted exactly
        # like a value match -- otherwise redaction is trivially defeated
        # by moving the secret from a value position to a key position.
        # Keys are masked against the ORIGINAL key text (never a
        # previously-substituted one, same rule as value matching), and
        # each key's redaction hits are counted independently of whether
        # the redacted key string collides with another key's.
        #
        # Collision handling: if two distinct original keys mask down to
        # the same string (e.g. two different-looking AWS-key-shaped keys
        # whose declared pattern span covers the whole key), we build the
        # output dict by iterating `value` in its original (insertion)
        # order and assigning masked-key -> redacted-value into a single
        # new dict -- ordinary dict-literal semantics make this
        # deterministic "last key wins", the secret text is gone from
        # every colliding key either way (no leak), and both original
        # keys are still counted in `counts` before the collision
        # collapses them in the output mapping.
        new_dict: dict = {}
        for k, v in value.items():
            new_key = k
            if isinstance(k, str):
                redacted_key, key_hit_counts = engine.redact(k)
                if key_hit_counts:
                    new_key = redacted_key
                    for rule_id, n in key_hit_counts.items():
                        counts[rule_id] = counts.get(rule_id, 0) + n
            new_dict[new_key] = _walk_redact(v, engine, counts)
        return new_dict
    return value


@dataclass
class Bouncer:
    engine: Engine
    audit: AuditLog
    upstream: Transport
    session: str = "default"
    counts: dict = field(default_factory=dict)
    # The logical policy `[[server]]` name this proxy instance fronts (one
    # upstream process per Bouncer). When set, `tools/list` responses are
    # rewritten so the name the proxy ADVERTISES is the exact qualified
    # name (`server__tool`) it ACCEPTS on `tools/call` -- otherwise a
    # conforming client that calls the bare advertised name gets
    # unmatched-deny server='' on every call (see qualify_tool /
    # parse_qualified_tool above). Left unset (None), tools/list is
    # forwarded unchanged, matching prior behavior.
    server_name: Optional[str] = None

    def _malformed_method_decision(self, method: Any) -> Decision:
        """Fail-unsafe verdict for a request whose method is a case/
        whitespace variant of ``tools/call`` (see
        ``is_tools_call_method_variant``). Denied and audited exactly like
        any other unmatched shape -- never silently forwarded."""
        return Decision(
            "deny",
            "malformed_method",
            None,
            None,
            pointer("method"),
            {
                "reason": "method is a case/whitespace variant of 'tools/call'",
                "received": method,
                "expected": TOOLS_CALL_METHOD,
            },
            f"method {method!r} is a malformed variant of {TOOLS_CALL_METHOD!r} "
            "and is denied fail-unsafe rather than forwarded ungated",
        )

    def _malformed_input_decision(self, reason: str, evidence: dict, json_pointer: str = "") -> Decision:
        """Fail-safe verdict for a client message that is not a well-formed
        single JSON-RPC request object -- a JSON parse error, a batch
        array, a bare scalar, a missing/blank ``method``, ``params`` that
        isn't an object where one is required, or a non-string
        ``params.name``. Denied and audited under a single, distinct
        ``rule_id`` (``malformed_input``, separate from
        ``malformed_method`` above which is specifically the tools/call
        spoof case) so callers can always tell "shape rejected" apart from
        "policy rejected" -- never silently dropped and never forwarded."""
        return Decision(
            "deny",
            "malformed_input",
            None,
            None,
            json_pointer,
            {"reason": reason, **evidence},
            f"malformed input: {reason}",
        )

    def _validate_message_shape(self, message: Any) -> Optional[Decision]:
        """Reject anything that isn't a well-formed single JSON-RPC
        request object BEFORE any ``.get``/``.get`` chase into it --
        a batch array (``[req, req]``) or a bare scalar (``"hello"``,
        ``1234``, ``null``, ``true``) has no ``.get`` method at all and
        crashing here would kill the whole session (every later call in
        the same session silently dropped), not just deny the one
        malformed line. Returns a ``Decision`` to deny+audit, or ``None``
        when ``message`` is at least shaped enough (a dict with a
        non-blank string ``method``) to dispatch on."""
        if isinstance(message, list):
            return self._malformed_input_decision(
                "batch requests (JSON array) are not supported",
                {"type": "list", "length": len(message)},
            )
        if not isinstance(message, dict):
            return self._malformed_input_decision(
                "top-level message must be a JSON object",
                {"type": type(message).__name__},
            )
        method = message.get("method")
        if not isinstance(method, str) or not method.strip():
            return self._malformed_input_decision(
                "missing or blank 'method'",
                {"received": method},
                pointer("method"),
            )
        return None

    def _resolve_tools_call(self, params: Any):
        """Validate + destructure a ``tools/call`` request's ``params``
        into ``(server_name, tool_name, arguments)``, or return a
        ``Decision`` denying it as malformed. Shared by ``handle_request``
        and ``handle_raw`` so both paths reject the same malformed shapes
        (``params`` not an object, e.g. an array; ``params.name`` present
        but not a string) instead of raising ``AttributeError``/
        ``TypeError`` out of ``dict.get``/``in`` on a non-dict/non-str
        value and killing the session."""
        if params is None:
            params = {}
        elif not isinstance(params, dict):
            return self._malformed_input_decision(
                "params must be a JSON object",
                {"type": type(params).__name__},
                pointer("params"),
            )
        qualified_name = params.get("name", "")
        if not isinstance(qualified_name, str):
            return self._malformed_input_decision(
                "params.name must be a string",
                {"type": type(qualified_name).__name__},
                pointer("params", "name"),
            )
        server_name, tool_name = parse_qualified_tool(qualified_name)
        arguments = params.get("arguments")
        return server_name, tool_name, arguments

    def _denial_response(self, message_id: Any, decision: Decision) -> dict:
        return {
            "jsonrpc": "2.0",
            "id": message_id,
            "error": {
                "code": DENIAL_ERROR_CODE,
                "message": decision.message,
                "data": {
                    "decision": decision.decision,
                    "rule_id": decision.rule_id,
                    "server": decision.server,
                    "tool": decision.tool,
                    "json_pointer": decision.json_pointer,
                    "evidence": decision.evidence,
                },
            },
        }

    def _apply_redaction(self, response: Optional[dict]) -> Optional[dict]:
        """Rule 7: mask declared secret-shaped patterns in an upstream
        tools/call response before it reaches the client. Scans BOTH the
        success path (``result``) and the JSON-RPC ERROR envelope
        (``error.message`` / ``error.data``, recursively) -- an upstream
        that fails and puts a secret in its error message must be masked
        exactly like one that succeeds and puts it in its result, otherwise
        rule 7 is trivially defeated by an upstream returning an error
        instead of a success. A JSON-RPC response carries at most one of
        ``result``/``error``, so at most one branch below actually walks
        anything."""
        if not response:
            return response
        new_response = dict(response)
        result_changed = False
        error_changed = False
        result_counts: dict[str, int] = {}
        error_counts: dict[str, int] = {}

        if "result" in response:
            redacted_result = _walk_redact(response["result"], self.engine, result_counts)
            if result_counts:
                new_response["result"] = redacted_result
                result_changed = True

        if isinstance(response.get("error"), dict):
            redacted_error = _walk_redact(response["error"], self.engine, error_counts)
            if error_counts:
                new_response["error"] = redacted_error
                error_changed = True

        if not result_changed and not error_changed:
            return response

        if result_changed:
            self.audit.append(
                Decision(
                    "allow",
                    "redaction",
                    "-",
                    "-",
                    "/result",
                    dict(sorted(result_counts.items())),
                    "result redacted",
                )
            )
        if error_changed:
            self.audit.append(
                Decision(
                    "allow",
                    "redaction",
                    "-",
                    "-",
                    "/error",
                    dict(sorted(error_counts.items())),
                    "error redacted",
                )
            )
        return new_response

    def _qualify_tools_list(self, response: Optional[dict]) -> Optional[dict]:
        """Rewrite an upstream `tools/list` result so every advertised
        `name` is the exact qualified name (`server__tool`) this Bouncer
        will ROUTE on `tools/call` -- what's shown is what routes. Only
        rewrites when `server_name` is configured and the result has the
        real MCP shape (`{"tools": [{"name": ..., ...}, ...]}`); anything
        else (no server_name, or a differently-shaped result, e.g. a test
        fixture) is left unchanged."""
        if not self.server_name or not response or "result" not in response:
            return response
        result = response["result"]
        if not isinstance(result, dict):
            return response
        tools = result.get("tools")
        if not isinstance(tools, list):
            return response

        changed = False
        new_tools = []
        for entry in tools:
            if isinstance(entry, dict) and isinstance(entry.get("name"), str):
                new_entry = dict(entry)
                new_entry["name"] = qualify_tool(self.server_name, entry["name"])
                new_tools.append(new_entry)
                changed = True
            else:
                new_tools.append(entry)
        if not changed:
            return response

        new_response = dict(response)
        new_result = dict(result)
        new_result["tools"] = new_tools
        new_response["result"] = new_result
        return new_response

    def handle_request(self, message: dict) -> Optional[dict]:
        shape_error = self._validate_message_shape(message)
        if shape_error is not None:
            self.audit.append(shape_error)
            message_id = message.get("id") if isinstance(message, dict) else None
            return self._denial_response(message_id, shape_error)

        method = message.get("method")
        if method == "tools/list":
            self.upstream.send(message)
            response = self.upstream.recv()
            return self._qualify_tools_list(response)

        if is_tools_call_method_variant(method):
            decision = self._malformed_method_decision(method)
            self.audit.append(decision)
            return self._denial_response(message.get("id"), decision)

        if method != "tools/call":
            self.upstream.send(message)
            return self.upstream.recv()

        # Present-but-not-present distinction preserved for the engine: a
        # missing `arguments` key becomes None ("no arguments"), while any
        # present value (including a non-dict one) is passed through
        # unchanged so the engine's own fail-unsafe check (a non-object
        # `arguments` must deny) actually sees it, instead of `or {}`
        # laundering a present-but-falsy/non-dict value into an empty dict.
        resolved = self._resolve_tools_call(message.get("params"))
        if isinstance(resolved, Decision):
            self.audit.append(resolved)
            return self._denial_response(message.get("id"), resolved)
        server_name, tool_name, arguments = resolved

        internal_request = {"server": server_name, "tool": tool_name, "arguments": arguments}
        decision = self.engine.evaluate(internal_request, session=self.session, counts=self.counts)
        self.audit.append(decision)

        if decision.decision != "allow":
            return self._denial_response(message.get("id"), decision)

        self.upstream.send(message)
        response = self.upstream.recv()
        return self._apply_redaction(response)

    def handle_raw(self, raw_line: str) -> Optional[str]:
        """Gate 5 (transparency): the byte-transparent counterpart to
        ``handle_request``. For `tools/call`, an ALLOWED request is
        forwarded to upstream using the client's ORIGINAL raw text (never
        re-serialized through a dict round trip), and the upstream's raw
        response text is returned unchanged when zero redactions apply --
        only a non-zero redaction count re-serializes (unavoidably, since
        the content itself changed). Any other method, or a denial, falls
        back to the dict-based path (no byte-identity requirement there).

        Robustness (fail-safe, session-preserving): a line that isn't
        parseable JSON, or that parses to something that isn't a
        well-formed single JSON-RPC request object (a batch array, a bare
        scalar, ``params``/``params.name`` of the wrong shape), returns a
        structured ``malformed_input`` JSON-RPC error -- it is NEVER
        forwarded upstream, an audit line is always written, and the
        session keeps running so the next (valid) line in the same stream
        is still processed. Previously this path raised
        ``AttributeError``/``TypeError`` straight out of ``handle_raw``,
        which killed the whole stdio loop (``run_stdio``'s ``for raw_line
        in stdin`` never resumes after an uncaught exception) -- every
        later call in the session silently dropped, with no denial, no
        audit line, and no leak.

        The UPSTREAM-inbound analog of the same guard (found in
        escape): a real upstream MCP server commonly writes stdout lines
        that are not a JSON-RPC response at all -- a stray ``DEBUG:``/log/
        startup-banner line, other non-JSON text, or a bare JSON scalar/
        array. ``StdioTransport.recv``/``recv_raw`` (see those docstrings)
        silently SKIP such a line and keep reading on the same connection
        until the actual response arrives or the upstream closes, rather
        than raising ``JSONDecodeError``/``TypeError`` here (which would
        kill the session exactly like the client-inbound case above) or
        forwarding the unscannable line to the client as if it were the
        ``tools/call`` result (which would bypass redaction on content the
        proxy never actually parsed)."""
        line = raw_line.strip()
        if not line:
            return None
        try:
            message = json.loads(line)
        except json.JSONDecodeError as exc:
            decision = self._malformed_input_decision(
                "request line is not valid JSON", {"error": str(exc)}
            )
            self.audit.append(decision)
            return json.dumps(self._denial_response(None, decision), separators=(",", ":"))

        shape_error = self._validate_message_shape(message)
        if shape_error is not None:
            self.audit.append(shape_error)
            message_id = message.get("id") if isinstance(message, dict) else None
            return json.dumps(
                self._denial_response(message_id, shape_error), separators=(",", ":")
            )

        if message.get("method") != "tools/call":
            response = self.handle_request(message)
            if response is None:
                return None
            return json.dumps(response, separators=(",", ":"))

        resolved = self._resolve_tools_call(message.get("params"))
        if isinstance(resolved, Decision):
            decision = resolved
            self.audit.append(decision)
            return json.dumps(
                self._denial_response(message.get("id"), decision), separators=(",", ":")
            )
        server_name, tool_name, arguments = resolved

        internal_request = {"server": server_name, "tool": tool_name, "arguments": arguments}
        decision = self.engine.evaluate(internal_request, session=self.session, counts=self.counts)
        self.audit.append(decision)

        if decision.decision != "allow":
            return json.dumps(
                self._denial_response(message.get("id"), decision), separators=(",", ":")
            )

        send_raw = getattr(self.upstream, "send_raw", None)
        recv_raw = getattr(self.upstream, "recv_raw", None)
        if send_raw is not None and recv_raw is not None:
            send_raw(line)
            raw_response = recv_raw()
            if raw_response is None:
                return None
            # ``recv_raw`` (see ``StdioTransport.recv_raw``) already skips
            # any non-JSON / non-object upstream line (log banner, bare
            # scalar, ...) and only ever returns text that parses to a JSON
            # object, but the parse is re-guarded here defensively in case
            # a different ``Transport`` implementation's ``recv_raw`` does
            # not make that same guarantee -- this path must never raise.
            try:
                response = json.loads(raw_response)
            except json.JSONDecodeError:
                return None
            if not isinstance(response, dict):
                return None
            redacted = self._apply_redaction(response)
            if redacted is response:
                # Zero redactions: forward upstream's bytes untouched.
                return raw_response
            return json.dumps(redacted, separators=(",", ":"))

        # Transports without raw support (e.g. FunctionTransport in tests)
        # fall back to the dict-based round trip.
        self.upstream.send(message)
        response = self.upstream.recv()
        redacted = self._apply_redaction(response)
        if redacted is None:
            return None
        return json.dumps(redacted, separators=(",", ":"))

    def run_stdio(self, stdin=None, stdout=None) -> None:  # pragma: no cover - IO loop
        stdin = stdin or sys.stdin
        stdout = stdout or sys.stdout
        # newline="" disables text-mode newline translation (see
        # spawn_upstream for the same fix on the upstream-facing pipes).
        # Without it, on Windows, stdout.write("...\n") translates the "\n"
        # to os.linesep ("\r\n") before it reaches the client, so a
        # byte-transparent forwarded line arrives CRLF-framed even though
        # nothing else about its content changed.
        for stream in (stdin, stdout):
            reconfigure = getattr(stream, "reconfigure", None)
            if reconfigure is not None:
                try:
                    reconfigure(encoding="utf-8", newline="")
                except (ValueError, OSError):
                    pass
        for raw_line in stdin:
            out = self.handle_raw(raw_line)
            if out is not None:
                stdout.write(out + "\n")
                stdout.flush()
