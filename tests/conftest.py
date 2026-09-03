import pytest

from mcpbouncer.corpus import DEFAULT_POLICY_TOML
from mcpbouncer.policy import load_policy


@pytest.fixture
def policy_path(tmp_path):
    p = tmp_path / "policy.toml"
    p.write_text(DEFAULT_POLICY_TOML, encoding="utf-8")
    return p


@pytest.fixture
def policy(policy_path):
    return load_policy(str(policy_path))
