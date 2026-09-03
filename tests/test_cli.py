import json

from mcpbouncer.cli import main


def test_check_exit_0_all_allowed(tmp_path, policy_path, capsys):
    calls = tmp_path / "calls.jsonl"
    calls.write_text(
        json.dumps({"id": "c1", "server": "files", "tool": "read_file", "arguments": {"path": "/srv/app/ok.txt"}})
        + "\n",
        encoding="utf-8",
    )
    code = main(["check", str(policy_path), str(calls)])
    assert code == 0


def test_check_exit_1_on_denial(tmp_path, policy_path):
    calls = tmp_path / "calls.jsonl"
    calls.write_text(
        json.dumps(
            {"id": "c1", "server": "files", "tool": "read_file", "arguments": {"path": "/srv/app/../etc/passwd"}}
        )
        + "\n",
        encoding="utf-8",
    )
    code = main(["check", str(policy_path), str(calls)])
    assert code == 1


def test_check_exit_2_on_malformed_policy(tmp_path):
    bad_policy = tmp_path / "bad.toml"
    bad_policy.write_text("not valid [ toml", encoding="utf-8")
    calls = tmp_path / "calls.jsonl"
    calls.write_text("{}\n", encoding="utf-8")
    code = main(["check", str(bad_policy), str(calls)])
    assert code == 2


def test_check_exit_2_on_malformed_calls_json(tmp_path, policy_path):
    calls = tmp_path / "calls.jsonl"
    calls.write_text("not json at all\n", encoding="utf-8")
    code = main(["check", str(policy_path), str(calls)])
    assert code == 2


def test_check_exit_2_on_missing_calls_file(tmp_path, policy_path):
    code = main(["check", str(policy_path), str(tmp_path / "nope.jsonl")])
    assert code == 2


def test_check_writes_resolving_json_pointer(tmp_path, policy_path, capsys):
    calls = tmp_path / "calls.jsonl"
    calls.write_text(
        json.dumps(
            {"id": "c1", "server": "files", "tool": "read_file", "arguments": {"path": "/etc/shadow"}}
        )
        + "\n",
        encoding="utf-8",
    )
    main(["check", str(policy_path), str(calls)])
    out = capsys.readouterr().out
    records = [json.loads(line) for line in out.splitlines() if line.strip()]
    decision_record = [r for r in records if not r.get("summary")][0]
    assert decision_record["json_pointer"] == "/arguments/path"
    assert decision_record["rule_id"] == "path_confinement"


def test_check_malformed_arguments_list_denied_via_cli(tmp_path, policy_path, capsys):
    """E1 repro 1, end to end via `mcpbouncer check`: a non-object
    `arguments` on files.read_file must exit 1 with a resolving pointer,
    never allow the traversal to slip past path confinement."""
    calls = tmp_path / "calls.jsonl"
    calls.write_text(
        json.dumps(
            {
                "id": "c1",
                "server": "files",
                "tool": "read_file",
                "arguments": ["/srv/app/../../etc/passwd"],
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
    assert decision_record["decision"] == "deny"
    assert decision_record["rule_id"] == "malformed_arguments"
    assert decision_record["json_pointer"] == "/arguments"


def test_check_malformed_arguments_bare_string_denied_via_cli(tmp_path, policy_path):
    """E1 repro 2."""
    calls = tmp_path / "calls.jsonl"
    calls.write_text(
        json.dumps({"id": "c1", "server": "files", "tool": "read_file", "arguments": "/etc/passwd"}) + "\n",
        encoding="utf-8",
    )
    code = main(["check", str(policy_path), str(calls)])
    assert code == 1


def test_check_malformed_arguments_oversized_string_denied_via_cli(tmp_path, policy_path):
    """E1 repro 3: a 5000-char string in place of the arguments object
    (cap is 256 for max_string_length) must still deny -- not skip the cap
    walk entirely by being coerced to {}."""
    calls = tmp_path / "calls.jsonl"
    calls.write_text(
        json.dumps({"id": "c1", "server": "files", "tool": "write_file", "arguments": "x" * 5000}) + "\n",
        encoding="utf-8",
    )
    code = main(["check", str(policy_path), str(calls)])
    assert code == 1


def test_check_malformed_arguments_list_on_web_fetch_denied_via_cli(tmp_path, policy_path):
    """E1 repro 4: a list must not bypass the url pattern constraint."""
    calls = tmp_path / "calls.jsonl"
    calls.write_text(
        json.dumps({"id": "c1", "server": "web", "tool": "fetch", "arguments": ["http://evil"]}) + "\n",
        encoding="utf-8",
    )
    code = main(["check", str(policy_path), str(calls)])
    assert code == 1


def test_policy_version_arbitrary_string_rejected(tmp_path):
    """E4: policy_version = "one" must be rejected as malformed (exit 2),
    consistent with 1.5 (float) and true (bool), both already rejected."""
    bad_policy = tmp_path / "bad.toml"
    bad_policy.write_text('policy_version = "one"\n', encoding="utf-8")
    calls = tmp_path / "calls.jsonl"
    calls.write_text("{}\n", encoding="utf-8")
    code = main(["check", str(bad_policy), str(calls)])
    assert code == 2


def test_policy_version_float_rejected(tmp_path):
    bad_policy = tmp_path / "bad.toml"
    bad_policy.write_text("policy_version = 1.5\n", encoding="utf-8")
    calls = tmp_path / "calls.jsonl"
    calls.write_text("{}\n", encoding="utf-8")
    code = main(["check", str(bad_policy), str(calls)])
    assert code == 2


def test_policy_version_bool_rejected(tmp_path):
    bad_policy = tmp_path / "bad.toml"
    bad_policy.write_text("policy_version = true\n", encoding="utf-8")
    calls = tmp_path / "calls.jsonl"
    calls.write_text("{}\n", encoding="utf-8")
    code = main(["check", str(bad_policy), str(calls)])
    assert code == 2


def test_policy_version_dotted_string_accepted(tmp_path):
    """A well-formed dotted version string is a legitimate policy_version,
    distinct from an arbitrary non-numeric string like "one"."""
    good_policy = tmp_path / "good.toml"
    good_policy.write_text('policy_version = "1.2.3"\n', encoding="utf-8")
    calls = tmp_path / "calls.jsonl"
    calls.write_text("", encoding="utf-8")
    code = main(["check", str(good_policy), str(calls)])
    assert code == 0  # empty corpus: nothing denied, nothing malformed


def test_init_writes_starter_policy(tmp_path):
    out = tmp_path / "policy.toml"
    code = main(["init", "--out", str(out)])
    assert code == 0
    assert out.exists()
    from mcpbouncer.policy import load_policy

    policy = load_policy(str(out))
    assert policy.version == 1


def test_init_refuses_overwrite_without_force(tmp_path):
    out = tmp_path / "policy.toml"
    out.write_text("existing", encoding="utf-8")
    code = main(["init", "--out", str(out)])
    assert code == 2
    assert out.read_text(encoding="utf-8") == "existing"


def test_init_force_overwrites(tmp_path):
    out = tmp_path / "policy.toml"
    out.write_text("existing", encoding="utf-8")
    code = main(["init", "--out", str(out), "--force"])
    assert code == 0
    assert "policy_version" in out.read_text(encoding="utf-8")


def test_no_command_prints_help_and_exits_2(capsys):
    code = main([])
    assert code == 2


def test_proxy_malformed_policy_exits_2(tmp_path):
    bad_policy = tmp_path / "bad.toml"
    bad_policy.write_text("not valid [ toml", encoding="utf-8")
    code = main(["proxy", "--policy", str(bad_policy), "--upstream", "python", "-c", "pass"])
    assert code == 2


def test_proxy_is_registered_subcommand(policy_path):
    from mcpbouncer.cli import build_parser

    parser = build_parser()
    args = parser.parse_args(["proxy", "--policy", str(policy_path), "--upstream", "python", "-c", "pass"])
    assert args.command == "proxy"
    assert args.upstream == ["python", "-c", "pass"]


# E1 -- MEDIUM: the enforce_read_only typo, exercised end-to-end through the
# CLI exit code (not just parse_policy directly) -- exit 2, never exit 0
# with the enforcement silently defaulted OFF.


def test_check_enforce_readonly_typo_exits_2(tmp_path):
    bad_policy = tmp_path / "typo.toml"
    bad_policy.write_text(
        "policy_version = 1\n\n"
        "[[server]]\n"
        'name = "admin"\n'
        "enforce_readonly = true\n\n"  # typo of enforce_read_only
        "  [[server.tool]]\n"
        '  name = "purge"\n'
        "  read_only = false\n",
        encoding="utf-8",
    )
    calls = tmp_path / "calls.jsonl"
    calls.write_text(json.dumps({"id": "c1", "server": "admin", "tool": "purge", "arguments": {}}) + "\n", encoding="utf-8")
    code = main(["check", str(bad_policy), str(calls)])
    assert code == 2
