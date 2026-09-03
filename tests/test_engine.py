from mcpbouncer.engine import Engine


def test_allow_declared_call(policy):
    engine = Engine(policy)
    decision = engine.evaluate(
        {"server": "files", "tool": "read_file", "arguments": {"path": "/srv/app/ok.txt"}}
    )
    assert decision.decision == "allow"
    assert decision.rule_id == "allow"


def test_unmatched_server(policy):
    engine = Engine(policy)
    decision = engine.evaluate({"server": "shell", "tool": "exec", "arguments": {}})
    assert decision.decision == "unmatched-deny"
    assert decision.rule_id == "unmatched"
    assert decision.json_pointer == "/server"


def test_unmatched_tool(policy):
    engine = Engine(policy)
    decision = engine.evaluate({"server": "files", "tool": "delete_everything", "arguments": {}})
    assert decision.decision == "unmatched-deny"
    assert decision.rule_id == "unmatched"
    assert decision.json_pointer == "/tool"


def test_read_only_enforcement(policy):
    engine = Engine(policy)
    decision = engine.evaluate({"server": "admin", "tool": "purge", "arguments": {}})
    assert decision.decision == "deny"
    assert decision.rule_id == "read_only"


def test_read_only_allows_declared_read_only_tool(policy):
    engine = Engine(policy)
    decision = engine.evaluate({"server": "admin", "tool": "status", "arguments": {}})
    assert decision.decision == "allow"


def test_path_confinement_denies_and_pointer_resolves(policy):
    engine = Engine(policy)
    decision = engine.evaluate(
        {"server": "files", "tool": "read_file", "arguments": {"path": "/etc/shadow"}}
    )
    assert decision.decision == "deny"
    assert decision.rule_id == "path_confinement"
    assert decision.json_pointer == "/arguments/path"


def test_path_confinement_non_string_denied(policy):
    engine = Engine(policy)
    decision = engine.evaluate({"server": "files", "tool": "read_file", "arguments": {"path": 12345}})
    assert decision.decision == "deny"
    assert decision.rule_id == "path_confinement"


def test_arg_caps_string_length(policy):
    engine = Engine(policy)
    decision = engine.evaluate(
        {"server": "files", "tool": "search", "arguments": {"query": "x" * 1000, "mode": "fast"}}
    )
    assert decision.decision == "deny"
    assert decision.rule_id == "arg_caps"
    assert decision.evidence["cap"] == "max_string_length"


def test_arg_caps_array_length(policy):
    # The oversized array lives under the *declared* key "query" -- caps
    # apply regardless of the declared arg's nominal type, but the key
    # itself must be declared or coverage (unmatched_arg) denies first.
    engine = Engine(policy)
    decision = engine.evaluate(
        {
            "server": "files",
            "tool": "search",
            "arguments": {"query": list(range(50)), "mode": "fast"},
        }
    )
    assert decision.decision == "deny"
    assert decision.rule_id == "arg_caps"
    assert decision.evidence["cap"] == "max_array_length"


def test_arg_caps_nesting_depth(policy):
    nested = {"a": {"b": {"c": {"d": {"e": 1}}}}}
    engine = Engine(policy)
    decision = engine.evaluate(
        {"server": "files", "tool": "search", "arguments": {"query": nested, "mode": "fast"}}
    )
    assert decision.decision == "deny"
    assert decision.rule_id == "arg_caps"
    assert decision.evidence["cap"] == "max_nesting_depth"


def test_undeclared_arg_key_smuggled_alongside_oversized_declared_arg_still_coverage_denied(policy):
    """An undeclared key is denied by coverage even when a declared key in
    the same call would independently trip an arg cap -- coverage (part of
    rule 1 / unmatched) runs before rule 4, so the more specific
    unmatched_arg classification wins."""
    engine = Engine(policy)
    decision = engine.evaluate(
        {
            "server": "files",
            "tool": "search",
            "arguments": {"query": "x" * 500, "mode": "fast", "smuggled": "y"},
        }
    )
    assert decision.decision == "unmatched-deny"
    assert decision.rule_id == "unmatched_arg"
    assert decision.json_pointer == "/arguments/smuggled"


def test_enum_violation(policy):
    engine = Engine(policy)
    decision = engine.evaluate(
        {"server": "files", "tool": "search", "arguments": {"query": "ok", "mode": "ludicrous"}}
    )
    assert decision.decision == "deny"
    assert decision.rule_id == "enum_pattern"
    assert decision.json_pointer == "/arguments/mode"


def test_pattern_violation(policy):
    engine = Engine(policy)
    decision = engine.evaluate(
        {"server": "web", "tool": "fetch", "arguments": {"url": "ftp://not-https.example.com"}}
    )
    assert decision.decision == "deny"
    assert decision.rule_id == "enum_pattern"
    assert decision.json_pointer == "/arguments/url"


def test_rate_limit(policy):
    engine = Engine(policy)
    counts: dict = {}
    session = "s1"
    for i in range(3):
        decision = engine.evaluate(
            {"server": "files", "tool": "write_file", "arguments": {"path": f"/srv/app/out{i}.txt"}},
            session=session,
            counts=counts,
        )
        assert decision.decision == "allow"
    fourth = engine.evaluate(
        {"server": "files", "tool": "write_file", "arguments": {"path": "/srv/app/out3.txt"}},
        session=session,
        counts=counts,
    )
    assert fourth.decision == "deny"
    assert fourth.rule_id == "rate_limit"


def test_rate_limit_is_per_session(policy):
    engine = Engine(policy)
    counts: dict = {}
    for i in range(3):
        engine.evaluate(
            {"server": "files", "tool": "write_file", "arguments": {"path": f"/srv/app/out{i}.txt"}},
            session="session-a",
            counts=counts,
        )
    decision = engine.evaluate(
        {"server": "files", "tool": "write_file", "arguments": {"path": "/srv/app/other.txt"}},
        session="session-b",
        counts=counts,
    )
    assert decision.decision == "allow"


def test_redact_reports_counts_and_masks(policy):
    engine = Engine(policy)
    fake_key = "AKIA" + "Q" * 16
    text = f"key is {fake_key} end"
    redacted, counts = engine.redact(text)
    assert fake_key not in redacted
    assert counts == {"aws_access_key": 1}


def test_redact_no_match_returns_unchanged(policy):
    engine = Engine(policy)
    redacted, counts = engine.redact("nothing sensitive here")
    assert redacted == "nothing sensitive here"
    assert counts == {}


# E2 -- LOW: overlapping patterns must not double-count / misattribute a
# single masked span. With `token=<AKIA...>`, the `generic_secret` pattern
# (`\S+`) used to greedily re-match the placeholder text the more specific
# `aws_access_key` pattern had already substituted, reporting ONE masked
# span as TWO hits across two different rule ids.


def test_redact_overlapping_patterns_count_once_with_single_owner(policy):
    engine = Engine(policy)
    fake_key = "AKIA" + "Q" * 16
    text = f"token={fake_key}"
    redacted, counts = engine.redact(text)

    assert fake_key not in redacted, "the secret value itself must still be masked"
    assert sum(counts.values()) == 1, (
        f"one masked span must contribute exactly 1 total hit, got {counts}"
    )
    assert counts == {"aws_access_key": 1}, (
        "the more specific, earlier-declared pattern owns the span -- "
        "generic_secret must not also claim it"
    )
    # exactly one owning pattern's placeholder appears, not both
    assert redacted.count("[REDACTED:") == 1


def test_redact_independent_non_overlapping_secrets_each_count_once(policy):
    engine = Engine(policy)
    text = "config: api_key: sk-placeholdervalue1234 password=placeholder-xyz"
    redacted, counts = engine.redact(text)
    assert counts == {"generic_secret": 2}
    assert redacted.count("[REDACTED:generic_secret]") == 2


# E1 -- CRITICAL: a non-object `arguments` must fail-DENY, never
# silently coerce to {} and fall through to allow (which would skip
# path confinement, arg caps, and enum/pattern entirely). Four proven
# repros from the independent audit; each must now deny.


def test_malformed_arguments_list_bypasses_path_confinement_denied(policy):
    """Repro 1: arguments = ["/srv/app/../../etc/passwd"] (a list, not an
    object) must not bypass path confinement on files.read_file."""
    engine = Engine(policy)
    decision = engine.evaluate(
        {
            "server": "files",
            "tool": "read_file",
            "arguments": ["/srv/app/../../etc/passwd"],
        }
    )
    assert decision.decision == "deny"
    assert decision.rule_id == "malformed_arguments"
    assert decision.json_pointer == "/arguments"


def test_malformed_arguments_bare_string_denied(policy):
    """Repro 2: arguments = "/etc/passwd" (a bare string) must deny."""
    engine = Engine(policy)
    decision = engine.evaluate(
        {"server": "files", "tool": "read_file", "arguments": "/etc/passwd"}
    )
    assert decision.decision == "deny"
    assert decision.rule_id == "malformed_arguments"
    assert decision.json_pointer == "/arguments"


def test_malformed_arguments_oversized_string_bypasses_caps_denied(policy):
    """Repro 3: arguments = a 5000-char string (cap=256 for max_string_length)
    must deny via malformed_arguments -- not silently allowed by being
    coerced to {} before the cap walk ever runs."""
    engine = Engine(policy)
    decision = engine.evaluate(
        {"server": "files", "tool": "write_file", "arguments": "x" * 5000}
    )
    assert decision.decision == "deny"
    assert decision.rule_id == "malformed_arguments"


def test_malformed_arguments_list_bypasses_url_pattern_denied(policy):
    """Repro 4: arguments = ["http://evil"] (a list) on web.fetch must not
    bypass the https:// url pattern constraint."""
    engine = Engine(policy)
    decision = engine.evaluate(
        {"server": "web", "tool": "fetch", "arguments": ["http://evil"]}
    )
    assert decision.decision == "deny"
    assert decision.rule_id == "malformed_arguments"
    assert decision.json_pointer == "/arguments"


def test_malformed_arguments_number_denied(policy):
    engine = Engine(policy)
    decision = engine.evaluate({"server": "files", "tool": "read_file", "arguments": 42})
    assert decision.decision == "deny"
    assert decision.rule_id == "malformed_arguments"


def test_malformed_arguments_bool_denied(policy):
    engine = Engine(policy)
    decision = engine.evaluate({"server": "files", "tool": "read_file", "arguments": True})
    assert decision.decision == "deny"
    assert decision.rule_id == "malformed_arguments"


def test_missing_arguments_key_still_allowed(policy):
    """SPEC does not mark `arguments` mandatory -- entirely missing
    (absent key, or None) is still fine, only a PRESENT non-object value
    must deny."""
    engine = Engine(policy)
    decision = engine.evaluate({"server": "admin", "tool": "status"})
    assert decision.decision == "allow"
