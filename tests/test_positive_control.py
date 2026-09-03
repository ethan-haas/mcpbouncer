"""Gate 7: the gate can go red -- a positive control. Mutate a rule and
prove the suite's own assertions would then fail. This does not mutate the
shipped module; it exercises a deliberately broken subclass so the test
process itself never ends up in a mutated state."""

import pytest

from mcpbouncer.corpus import planted_violation_corpus
from mcpbouncer.engine import Decision, Engine


class PathConfinementDisabledEngine(Engine):
    """Mutant: rule 3 (path confinement) never fires -- everything with a
    path argument is allowed regardless of root."""

    def evaluate(self, request, session="default", counts=None):
        counts = {} if counts is None else counts
        server_name = request.get("server")
        tool_name = request.get("tool")
        server = self.policy.servers.get(server_name)
        if server is None:
            return Decision("unmatched-deny", "unmatched", server_name, tool_name, "/server", {}, "no server")
        tool = server.tools.get(tool_name)
        if tool is None:
            return Decision("unmatched-deny", "unmatched", server_name, tool_name, "/tool", {}, "no tool")
        # Path confinement deliberately skipped -- everything else too, for
        # a maximally permissive mutant.
        return Decision("allow", "allow", server_name, tool_name, "", {}, "allowed (mutant)")


class RateLimitDisabledEngine(Engine):
    """Mutant: rule 6 (rate limiting) never denies."""

    def evaluate(self, request, session="default", counts=None):
        decision = super().evaluate(request, session=session, counts=counts if counts is not None else {})
        if decision.rule_id == "rate_limit":
            return Decision("allow", "allow", decision.server, decision.tool, "", {}, "allowed (mutant)")
        return decision


def _find_case(name):
    for case in planted_violation_corpus():
        if case.class_name == name:
            return case
    raise AssertionError(f"no such case: {name}")


def test_path_confinement_mutant_is_caught(policy):
    case = _find_case("path_dotdot")
    mutant = PathConfinementDisabledEngine(policy)
    request = {
        "server": case.call["server"],
        "tool": case.call["tool"],
        "arguments": case.call["arguments"],
    }
    decision = mutant.evaluate(request)
    # The real assertion the suite makes (see test_corpus.py) is
    # decision.decision == "deny"; the mutant flips that, proving the
    # gate can go red instead of vacuously passing.
    with pytest.raises(AssertionError):
        assert decision.decision == case.expected_decision, "mutant should have been caught here"


def test_rate_limit_mutant_is_caught(policy):
    mutant = RateLimitDisabledEngine(policy)
    counts: dict = {}
    session = "s1"
    for i in range(4):
        decision = mutant.evaluate(
            {"server": "files", "tool": "write_file", "arguments": {"path": f"/srv/app/out{i}.txt"}},
            session=session,
            counts=counts,
        )
    with pytest.raises(AssertionError):
        assert decision.decision == "deny", "mutant should have been caught here"
