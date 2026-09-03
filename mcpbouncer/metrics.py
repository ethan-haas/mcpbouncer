"""Metrics: denial_rate, false_denial_rate, unmatched_rate -- always kept
separate, never averaged into one composite. false_denial_rate is measured
ONLY against the allowed workload (a legitimate call that gets denied is a
false denial); denial_rate is measured against the planted-violation corpus
(a violation that gets denied is a true positive, contributing to
denial_rate, not to false_denial_rate)."""

from __future__ import annotations

from dataclasses import dataclass

from mcpbouncer.corpus import PlantedCase, allowed_workload, planted_violation_corpus
from mcpbouncer.engine import Engine


@dataclass(frozen=True)
class MetricsReport:
    total_violation_cases: int
    denied_violation_cases: int
    denial_rate: float
    total_allowed_cases: int
    falsely_denied_allowed_cases: int
    false_denial_rate: float
    unmatched_violation_cases: int
    unmatched_rate: float

    def as_dict(self) -> dict:
        return {
            "denial_rate": self.denial_rate,
            "false_denial_rate": self.false_denial_rate,
            "unmatched_rate": self.unmatched_rate,
            "total_violation_cases": self.total_violation_cases,
            "denied_violation_cases": self.denied_violation_cases,
            "total_allowed_cases": self.total_allowed_cases,
            "falsely_denied_allowed_cases": self.falsely_denied_allowed_cases,
            "unmatched_violation_cases": self.unmatched_violation_cases,
        }


def _replay(case: PlantedCase, engine: Engine, counts: dict) -> list:
    if case.class_name == "rate_limit":
        decisions = []
        for call in case.call["sequence"]:
            request = {"server": call["server"], "tool": call["tool"], "arguments": call["arguments"]}
            decisions.append(engine.evaluate(request, session=call["session"], counts=counts))
        return decisions
    call = case.call
    request = {"server": call["server"], "tool": call["tool"], "arguments": call["arguments"]}
    return [engine.evaluate(request, session=call["session"], counts=counts)]


def compute_metrics(engine: Engine, seed: int = 1234) -> MetricsReport:
    counts: dict = {}
    violation_cases = planted_violation_corpus(seed=seed)
    denied = 0
    unmatched = 0
    total_violations = len(violation_cases)
    for case in violation_cases:
        decisions = _replay(case, engine, counts)
        final = decisions[-1]
        if final.decision != "allow":
            denied += 1
        if final.decision == "unmatched-deny":
            unmatched += 1

    allowed_counts: dict = {}
    workload = allowed_workload(seed=seed)
    false_denials = 0
    for call in workload:
        request = {"server": call["server"], "tool": call["tool"], "arguments": call["arguments"]}
        decision = engine.evaluate(request, session=call["session"], counts=allowed_counts)
        if decision.decision != "allow":
            false_denials += 1

    return MetricsReport(
        total_violation_cases=total_violations,
        denied_violation_cases=denied,
        denial_rate=(denied / total_violations) if total_violations else 0.0,
        total_allowed_cases=len(workload),
        falsely_denied_allowed_cases=false_denials,
        false_denial_rate=(false_denials / len(workload)) if workload else 0.0,
        unmatched_violation_cases=unmatched,
        unmatched_rate=(unmatched / total_violations) if total_violations else 0.0,
    )
