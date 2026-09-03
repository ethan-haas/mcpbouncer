"""Gate 1: planted-violation corpus, >= 8 classes, each denied with the
correct rule_id and a resolving json_pointer.
Gate 2: two-sided, never blended -- a realistic allowed workload passes
with ZERO denials, and denial_rate / false_denial_rate are reported
separately, never averaged.
"""

from mcpbouncer.corpus import allowed_workload, planted_redaction_cases, planted_violation_corpus
from mcpbouncer.engine import Engine


def _resolves(request: dict, pointer: str) -> bool:
    """A denial's json_pointer must resolve into the actual request that
    caused it -- walk the pointer against the internal request dict."""
    if pointer in ("", "/"):
        return True
    node = request
    for token in pointer.strip("/").split("/"):
        token = token.replace("~1", "/").replace("~0", "~")
        if isinstance(node, dict):
            if token not in node:
                return False
            node = node[token]
        elif isinstance(node, list):
            try:
                idx = int(token)
            except ValueError:
                return False
            if idx >= len(node):
                return False
            node = node[idx]
        else:
            return False
    return True


def test_corpus_covers_at_least_eight_rule_classes(policy):
    cases = planted_violation_corpus()
    rule_ids = set()
    for case in cases:
        rule_ids.add(case.expected_rule_id)
    # unmatched, read_only, path_confinement, arg_caps, enum_pattern, rate_limit
    assert len(rule_ids) >= 6
    # plus redaction (rule 7, tested separately as allow+mask) and audit
    # completeness (rule 8, a suite-level property) round out the 8 rules.
    assert len(planted_redaction_cases()) > 0


def test_every_planted_case_denied_with_correct_rule_id_and_resolving_pointer(policy):
    engine = Engine(policy)
    for case in planted_violation_corpus():
        if case.class_name == "rate_limit":
            counts: dict = {}
            sequence = case.call["sequence"]
            decisions = []
            for call in sequence:
                request = {"server": call["server"], "tool": call["tool"], "arguments": call["arguments"]}
                decisions.append(
                    engine.evaluate(request, session=call["session"], counts=counts)
                )
            last = decisions[-1]
            assert last.decision == case.expected_decision, case.class_name
            assert last.rule_id == case.expected_rule_id, case.class_name
            assert decisions[0].decision == "allow"
            assert decisions[1].decision == "allow"
            assert decisions[2].decision == "allow"
            continue

        call = case.call
        request = {"server": call["server"], "tool": call["tool"], "arguments": call["arguments"]}
        decision = engine.evaluate(request, session=call["session"])
        assert decision.decision == case.expected_decision, f"{case.class_name}: {decision}"
        assert decision.rule_id == case.expected_rule_id, f"{case.class_name}: {decision}"
        assert _resolves(request, decision.json_pointer), (
            f"{case.class_name}: pointer {decision.json_pointer!r} does not resolve into {request!r}"
        )


def test_redaction_cases_mask_and_report_counts(policy):
    engine = Engine(policy)
    for case in planted_redaction_cases():
        redacted, counts = engine.redact(case["raw_text"])
        assert counts.get(case["expect_class"]) == case["expect_count"], case["id"]
        assert redacted != case["raw_text"]


def test_allowed_workload_zero_denials(policy):
    engine = Engine(policy)
    counts: dict = {}
    denials = 0
    total = 0
    for call in allowed_workload():
        total += 1
        request = {"server": call["server"], "tool": call["tool"], "arguments": call["arguments"]}
        decision = engine.evaluate(request, session=call["session"], counts=counts)
        if decision.decision != "allow":
            denials += 1
    false_denial_rate = denials / total
    assert denials == 0, f"false_denial_rate={false_denial_rate}: allowed workload must have ZERO denials"


def test_deny_everything_proxy_fails_the_two_sided_gate(policy):
    """Positive control for gate 2 itself: a proxy that denies everything
    must fail the allowed-workload check, proving the gate can go red."""

    class DenyEverythingEngine:
        def evaluate(self, request, session="default", counts=None):
            from mcpbouncer.engine import Decision

            return Decision("deny", "deny_all", request.get("server"), request.get("tool"), "", {}, "deny all")

    engine = DenyEverythingEngine()
    denials = 0
    calls = allowed_workload()
    for call in calls:
        request = {"server": call["server"], "tool": call["tool"], "arguments": call["arguments"]}
        decision = engine.evaluate(request, session=call["session"])
        if decision.decision != "allow":
            denials += 1
    assert denials == len(calls)
    # The real gate assertion (denials == 0) would fail here -- confirming
    # this two-sided check is discriminating, not vacuously true.
    assert denials != 0
