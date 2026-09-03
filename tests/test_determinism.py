"""Gate 6: determinism across PROCESSES -- >= 3 subprocesses with differing
PYTHONHASHSEED must produce a byte-identical decision log."""

import json
import os
import subprocess
import sys

from mcpbouncer.corpus import DEFAULT_POLICY_TOML, allowed_workload, planted_violation_corpus


def _write_calls_file(path):
    lines = []
    for case in planted_violation_corpus():
        if case.class_name == "rate_limit":
            for call in case.call["sequence"]:
                lines.append(json.dumps(call, sort_keys=True))
        else:
            lines.append(json.dumps(case.call, sort_keys=True))
    for call in allowed_workload():
        lines.append(json.dumps(call, sort_keys=True))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def test_audit_log_byte_identical_across_hash_seeds(tmp_path):
    policy_path = tmp_path / "policy.toml"
    policy_path.write_text(DEFAULT_POLICY_TOML, encoding="utf-8")
    calls_path = tmp_path / "calls.jsonl"
    _write_calls_file(calls_path)

    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    seeds = ["0", "1", "982451653"]
    audit_bytes = []
    for i, seed in enumerate(seeds):
        audit_path = tmp_path / f"audit_{i}.jsonl"
        env = dict(os.environ)
        env["PYTHONHASHSEED"] = seed
        env["PYTHONPATH"] = repo_root + os.pathsep + env.get("PYTHONPATH", "")
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "mcpbouncer",
                "check",
                str(policy_path),
                str(calls_path),
                "--audit-log",
                str(audit_path),
            ],
            cwd=repo_root,
            env=env,
            capture_output=True,
            text=True,
        )
        assert result.returncode in (0, 1), result.stderr
        audit_bytes.append(audit_path.read_bytes())

    assert audit_bytes[0] == audit_bytes[1] == audit_bytes[2], "decision log must be byte-identical across hash seeds"
    assert len(audit_bytes[0]) > 0
