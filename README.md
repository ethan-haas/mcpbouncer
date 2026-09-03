# mcpbouncer

A blocked `..` traversal against a starter policy produces exactly this
(the full verdict contract, as written to the audit log):

```json
{
  "decision": "deny",
  "evidence": {
    "raw": "/srv/app/../../etc/passwd",
    "resolved": "/etc/passwd",
    "root": "/srv/app"
  },
  "json_pointer": "/arguments/path",
  "message": "argument 'path' resolves outside declared root '/srv/app'",
  "rule_id": "path_confinement",
  "server": "files",
  "tool": "read_file"
}
```

`mcpbouncer` sits in front of your MCP servers. Every `tools/call` is checked
against a declared, versioned policy before it is forwarded. Allowed calls
pass through unchanged. Denied calls return a structured error naming the
rule that denied them. A tool, server, or argument shape the policy does
not cover is `unmatched` -> **denied**, never defaulted to allow.

No natural-language recognition anywhere -- no "does this look dangerous",
no intent classification. Every rule below is mechanically checkable
against a closed structured domain: JSON-RPC envelopes, tool names,
argument trees, and a declared policy table.

## Quickstart (60 seconds, no account, no network)

```bash
pipx run mcpbouncer init                 # writes a working starter policy.toml
pipx run mcpbouncer check policy.toml calls.jsonl   # evaluate a recorded call log offline
```

`init` never touches the network and never asks for an API key -- it just
writes a starter policy with sane defaults you edit for your own servers
and tools. `check` runs entirely offline against a recorded call log; no
server needs to be running.

Exit codes for `check`: `0` everything allowed, `1` at least one denial,
`2` malformed policy or input.

### Wiring it in front of a real MCP client

Point your client's MCP config at `mcpbouncer` instead of the upstream
server directly, e.g. for a Claude Desktop / Claude Code style config:

```json
{
  "mcpServers": {
    "files": {
      "command": "mcpbouncer",
      "args": ["proxy", "--policy", "policy.toml", "--server", "files", "--upstream", "python", "-m", "my_files_server"]
    }
  }
}
```

`mcpbouncer` speaks newline-delimited JSON-RPC 2.0 over stdio on both
sides: client -> bouncer -> upstream. Only `tools/call` is intercepted;
every other method (`initialize`, ...) passes straight through relayed to
upstream, but is not byte-identity-guaranteed the way an intercepted
`tools/call` is (see below) -- a passthrough method may be re-serialized
(e.g. compact separators, key order) on its way through.

The byte-identity guarantee is scoped to an intercepted `tools/call`
request/response pair: an **allowed** `tools/call` request is forwarded to
upstream using the client's original bytes (never re-serialized through a
parse/re-dump round trip), and the upstream's response is returned
byte-identical to the client, except for declared (rule 7) redactions --
which necessarily change the bytes and are reported via an extra audit
record, never silently applied. Rule 7 also applies to a `tools/call`
response's JSON-RPC `error.message`/`error.data`, not just a successful
`result`, so an upstream that fails instead of succeeding cannot leak a
secret-shaped token through the unscanned side.

### Tool naming: what's advertised is what routes

One `mcpbouncer proxy` process fronts one upstream and represents exactly
one policy `[[server]]` -- pass its name via `--server` (matching the key
you gave it in `mcpServers`, `"files"` above). A `tools/call` must name the
tool as `<server>__<tool>` (double underscore) so the proxy knows which
declared `[[server]]` block to check it against; when `--server` is set,
`mcpbouncer` rewrites the upstream's `tools/list` response so every
advertised name is already in that qualified form, so a conforming client
that just calls the name it was shown always routes. A name without the
`__` separator (or an unqualified `--server`-less setup) has an empty
server component, which the policy never declares, so it is correctly
`unmatched-deny` rather than silently routed anywhere.

## The 8 rules

| # | Rule | rule_id | Mechanism |
|---|------|---------|-----------|
| 1 | Server + tool allowlist | `unmatched` | anything not explicitly declared is `unmatched-deny` |
| 1b | Argument-key coverage | `unmatched_arg` | every key in a call's `arguments` object must be declared for that tool via an `[[server.tool.arg]]` entry; an undeclared key -- e.g. `altpath` smuggled alongside a declared `path` -- is `unmatched-deny` before any argument-shaped rule (3-5) ever inspects its value. A legitimate arg with no other constraint is declared `type = "string"` with no `pattern` |
| 2 | Read-only enforcement | `read_only` | a server marked `enforce_read_only` denies any declared tool whose `read_only` is false |
| 3 | Path confinement | `path_confinement` | component-wise containment under a declared root; handles `..`, absolute paths, symlinks (realpath), unicode separators (NFKC), and the separator-less prefix case (`/srv/appdata` is not under `/srv/app`) |
| 4 | Argument caps | `arg_caps` | max string length, max array length, max nesting depth over the whole argument tree |
| 5 | Enum / pattern constraints | `enum_pattern` | a named argument must be one of a declared enum, or fullmatch a declared regex |
| 6 | Rate & budget caps | `rate_limit` | max calls per `server.tool` per session |
| 7 | Result redaction | `redaction` | a declared, versioned table of literal regex patterns masks matches in the response -- both a successful `result` and a JSON-RPC `error.message`/`error.data`; **always reported as counts, never silently dropped** -- decision stays `allow` |
| 8 | Audit completeness | (all of the above) | every decision -- allow, deny, unmatched-deny, redaction -- is appended to an append-only JSONL audit log with its rule id |

Rule 7 is the one place a pattern is used, and it is a declared table of
literal secret-shaped patterns, not a judgement about meaning.

## Verdict contract

```
{decision, rule_id, server, tool, json_pointer, evidence, message}
```

`decision` is one of `allow`, `deny`, `unmatched-deny`. `json_pointer`
(RFC 6901) always resolves into the actual request that caused a denial --
a denial that cannot point at its argument is a bug.

### Robustness: malformed lines never kill the session

Both directions of the stdio pipe are guarded so one bad line degrades
gracefully instead of tearing down the whole proxy process:

- **Client-inbound**: a line that isn't valid JSON, or that isn't a
  well-formed single JSON-RPC request object (batch array, bare scalar,
  wrong-shaped `params`), gets a structured `malformed_input` JSON-RPC
  error response. It is never forwarded upstream, and the session keeps
  processing every later line.
- **Upstream-inbound**: a stdout line from the upstream server that isn't
  valid JSON, or that parses to something other than a JSON object (a
  `DEBUG:`/log/banner line, other free text, or a bare scalar/array), is
  **skipped** -- it is not a JSON-RPC response the proxy can scan for
  redaction, so it is never forwarded to the client as a `tools/call`
  result and never crashes the read loop. The proxy keeps reading on the
  same connection until the real response line arrives (or the upstream
  closes), so the pending request still gets its correct reply and every
  call after it in the same session is unaffected.

## Policy file

Declared, versioned TOML (parsed with `tomllib`):

```toml
policy_version = 1

[limits]
max_string_length = 4096
max_array_length = 100
max_nesting_depth = 6

[rate_limits]
"files.write_file" = 5

[[redaction]]
id = "aws_access_key"
pattern = 'AKIA[0-9A-Z]{16}'

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
```

A malformed policy raises a typed `PolicyError` (CLI exit code `2`), never
a silent fallback.

## Metrics -- never blended

Run against `mcpbouncer`'s own fixed-seed corpus (`mcpbouncer/corpus.py`):

- `denial_rate` -- fraction of the planted-violation corpus correctly denied
- `false_denial_rate` -- fraction of a realistic allowed workload wrongly denied (measured completely separately; a deny-everything proxy scores 1.0 here and fails the gate)
- `unmatched_rate` -- fraction of planted violations caught specifically by the unmatched-deny fallback (coverage honesty: how much of the corpus your allowlist alone is doing)

```bash
python -c "
from mcpbouncer.policy import load_policy
from mcpbouncer.engine import Engine
from mcpbouncer.metrics import compute_metrics
report = compute_metrics(Engine(load_policy('examples/policy.toml')))
print(report.as_dict())
"
```

## Development

```bash
pip install -e ".[dev]"
python -m pytest tests/ -q
```

The test suite mirrors the acceptance gates: planted corpus (>= 8 classes),
two-sided allowed-workload check reported separately from denial rate,
direct unmatched assertions, adversarial path confinement (`..`, absolute,
symlink, unicode separator, separator-less prefix each their own test),
byte-level transparency against a fixture server, cross-process
determinism under differing `PYTHONHASHSEED`, and a positive control
proving the suite can go red.

## License

MIT -- see [LICENSE](LICENSE).
