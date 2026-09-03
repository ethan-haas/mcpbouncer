"""Append-only JSONL audit log.

Every decision (allow, deny, unmatched-deny, redaction) is appended with its
rule id -- rule 8, audit completeness. Records deliberately carry NO
wallclock timestamp: determinism across processes (differing
``PYTHONHASHSEED``) must yield byte-identical decision logs, so nothing
time-dependent is in the identity bytes, keys are always sorted, and
iteration never touches a ``set``.
"""

from __future__ import annotations

import json
from pathlib import Path

from mcpbouncer.engine import Decision


def decision_record(decision: Decision) -> dict:
    return decision.as_dict()


def encode_record(record: dict) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


class AuditLog:
    """Append-only JSONL writer. Truncate explicitly with ``reset()`` --
    the log never truncates itself implicitly, matching append-only
    semantics."""

    def __init__(self, path: str | Path):
        self.path = Path(path)

    def reset(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text("", encoding="utf-8")

    def append(self, decision: Decision) -> str:
        record = decision_record(decision)
        line = encode_record(record)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.path, "a", encoding="utf-8", newline="\n") as f:
            f.write(line + "\n")
        return line

    def read_records(self) -> list[dict]:
        if not self.path.exists():
            return []
        records = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                records.append(json.loads(line))
        return records
