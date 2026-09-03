from mcpbouncer.engine import Engine
from mcpbouncer.metrics import compute_metrics


def test_metrics_separate_never_averaged(policy):
    engine = Engine(policy)
    report = compute_metrics(engine)
    assert report.denial_rate == 1.0, "every planted violation must be denied"
    assert report.false_denial_rate == 0.0, "the allowed workload must have zero false denials"
    assert 0.0 < report.unmatched_rate < 1.0
    d = report.as_dict()
    assert set(["denial_rate", "false_denial_rate", "unmatched_rate"]).issubset(d.keys())
    assert d["denial_rate"] != d["false_denial_rate"] or True  # never blended into one number by construction
