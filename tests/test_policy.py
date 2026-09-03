import pytest

from mcpbouncer.corpus import DEFAULT_POLICY_TOML
from mcpbouncer.policy import PolicyError, load_policy, parse_policy


def test_valid_policy_loads(policy_path):
    policy = load_policy(str(policy_path))
    assert policy.version == 1
    assert "files" in policy.servers
    assert "read_file" in policy.servers["files"].tools


def test_missing_policy_version_raises():
    with pytest.raises(PolicyError):
        parse_policy({"server": []})


def test_bad_toml_raises(tmp_path):
    p = tmp_path / "bad.toml"
    p.write_text("this is not [ valid toml", encoding="utf-8")
    with pytest.raises(PolicyError):
        load_policy(str(p))


def test_missing_file_raises(tmp_path):
    with pytest.raises(PolicyError):
        load_policy(str(tmp_path / "does_not_exist.toml"))


def test_path_arg_without_root_raises():
    raw = {
        "policy_version": 1,
        "server": [
            {
                "name": "files",
                "tool": [
                    {
                        "name": "read_file",
                        "read_only": True,
                        "arg": [{"name": "path", "type": "path"}],
                    }
                ],
            }
        ],
    }
    with pytest.raises(PolicyError):
        parse_policy(raw)


def test_enum_arg_without_values_raises():
    raw = {
        "policy_version": 1,
        "server": [
            {
                "name": "files",
                "tool": [
                    {
                        "name": "search",
                        "read_only": True,
                        "arg": [{"name": "mode", "type": "enum"}],
                    }
                ],
            }
        ],
    }
    with pytest.raises(PolicyError):
        parse_policy(raw)


def test_invalid_regex_pattern_raises():
    raw = {
        "policy_version": 1,
        "server": [
            {
                "name": "files",
                "tool": [
                    {
                        "name": "search",
                        "read_only": True,
                        "arg": [{"name": "q", "type": "string", "pattern": "("}],
                    }
                ],
            }
        ],
    }
    with pytest.raises(PolicyError):
        parse_policy(raw)


def test_invalid_redaction_regex_raises():
    raw = {
        "policy_version": 1,
        "redaction": [{"id": "bad", "pattern": "("}],
        "server": [],
    }
    with pytest.raises(PolicyError):
        parse_policy(raw)


def test_duplicate_server_raises():
    raw = {
        "policy_version": 1,
        "server": [{"name": "files", "tool": []}, {"name": "files", "tool": []}],
    }
    with pytest.raises(PolicyError):
        parse_policy(raw)


def test_duplicate_tool_raises():
    raw = {
        "policy_version": 1,
        "server": [
            {
                "name": "files",
                "tool": [
                    {"name": "read_file", "read_only": True},
                    {"name": "read_file", "read_only": True},
                ],
            }
        ],
    }
    with pytest.raises(PolicyError):
        parse_policy(raw)


def test_rate_limit_unknown_server_raises():
    raw = {
        "policy_version": 1,
        "rate_limits": {"nosuch.tool": 5},
        "server": [],
    }
    with pytest.raises(PolicyError):
        parse_policy(raw)


def test_negative_limit_raises():
    raw = {
        "policy_version": 1,
        "limits": {"max_string_length": -1},
        "server": [],
    }
    with pytest.raises(PolicyError):
        parse_policy(raw)


def test_policy_version_arbitrary_string_raises():
    """E4: policy_version = "one" must be rejected -- consistent with 1.5
    (float, already rejected by the int/str type check) and true (bool,
    already excluded), an arbitrary non-numeric string is the same
    malformed-policy class, not a silently-accepted edge case."""
    with pytest.raises(PolicyError):
        parse_policy({"policy_version": "one", "server": []})


def test_policy_version_float_raises():
    with pytest.raises(PolicyError):
        parse_policy({"policy_version": 1.5, "server": []})


def test_policy_version_bool_raises():
    with pytest.raises(PolicyError):
        parse_policy({"policy_version": True, "server": []})


def test_policy_version_dotted_string_accepted():
    """A well-formed dotted version string is a legitimate declared
    version, distinct from an arbitrary string like "one"."""
    policy = parse_policy({"policy_version": "1.2.3", "server": []})
    assert policy.version == "1.2.3"


def test_policy_version_plain_int_string_accepted():
    policy = parse_policy({"policy_version": "1", "server": []})
    assert policy.version == "1"


def test_default_policy_toml_is_valid(tmp_path):
    p = tmp_path / "default.toml"
    p.write_text(DEFAULT_POLICY_TOML, encoding="utf-8")
    policy = load_policy(str(p))
    assert policy.servers["admin"].enforce_read_only is True
    assert policy.servers["admin"].tools["purge"].read_only is False


# E1 -- MEDIUM: strict unknown-key rejection at every policy scope. Without
# this, misspelling `enforce_read_only` as `enforce_readonly` loaded with
# exit 0, read-only enforcement silently defaulted OFF, and a non-read-only
# tool the author meant to block was ALLOWED -- a one-character typo
# flipping deny -> allow.


def test_server_enforce_readonly_typo_raises():
    """The sharp repro: misspelling the server key `enforce_read_only` as
    `enforce_readonly` must be rejected outright, never silently loaded
    with read-only enforcement defaulting OFF."""
    raw = {
        "policy_version": 1,
        "server": [
            {
                "name": "admin",
                "enforce_readonly": True,  # typo -- correct key is enforce_read_only
                "tool": [{"name": "purge", "read_only": False}],
            }
        ],
    }
    with pytest.raises(PolicyError, match="enforce_readonly"):
        parse_policy(raw)


def test_server_enforce_readonly_correct_key_still_works():
    raw = {
        "policy_version": 1,
        "server": [
            {
                "name": "admin",
                "enforce_read_only": True,
                "tool": [{"name": "purge", "read_only": False}],
            }
        ],
    }
    policy = parse_policy(raw)
    assert policy.servers["admin"].enforce_read_only is True


def test_unknown_key_at_top_level_raises():
    raw = {"policy_version": 1, "server": [], "totally_unknown": True}
    with pytest.raises(PolicyError, match="totally_unknown"):
        parse_policy(raw)


def test_unknown_key_in_limits_raises():
    raw = {"policy_version": 1, "limits": {"max_string_lenght": 10}, "server": []}
    with pytest.raises(PolicyError, match="max_string_lenght"):
        parse_policy(raw)


def test_unknown_key_in_redaction_raises():
    raw = {
        "policy_version": 1,
        "redaction": [{"id": "x", "pattern": "y", "descriptoin": "typo"}],
        "server": [],
    }
    with pytest.raises(PolicyError, match="descriptoin"):
        parse_policy(raw)


def test_unknown_key_in_server_raises():
    raw = {"policy_version": 1, "server": [{"name": "files", "tool": [], "verison": 2}]}
    with pytest.raises(PolicyError, match="verison"):
        parse_policy(raw)


def test_unknown_key_in_tool_raises():
    raw = {
        "policy_version": 1,
        "server": [
            {
                "name": "files",
                "tool": [{"name": "read_file", "read_only": True, "readonly": True}],
            }
        ],
    }
    with pytest.raises(PolicyError, match="readonly"):
        parse_policy(raw)


def test_unknown_key_in_arg_raises():
    raw = {
        "policy_version": 1,
        "server": [
            {
                "name": "files",
                "tool": [
                    {
                        "name": "read_file",
                        "read_only": True,
                        "arg": [{"name": "path", "type": "path", "root": "/srv/app", "rooot": "/srv/app"}],
                    }
                ],
            }
        ],
    }
    with pytest.raises(PolicyError, match="rooot"):
        parse_policy(raw)
