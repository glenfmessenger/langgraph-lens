"""SQL / metadata-injection detector for checkpoint-backend fields.

`SqliteSaver` and `PostgresSaver` accept user-controlled strings for
`thread_id`, `checkpoint_ns`, and `checkpoint_id`. In well-behaved
deployments those values are server-issued UUIDs; in less-well-behaved
ones they're passed through from client input and end up concatenated
into SQL by older saver versions.

This detector scans those fields for canonical injection signatures.
It does *not* sit in the query path — it inspects values as the lens
sees them via the checkpoint-inspection hook.
"""

from __future__ import annotations

import re

from ..config import SQLInjectionConfig
from ..events import Detection, Severity

_PATTERNS: list[tuple[str, re.Pattern[str], Severity]] = [
    (
        "union_select",
        re.compile(r"\bunion\b.*\bselect\b", re.I | re.S),
        Severity.CRITICAL,
    ),
    (
        "comment_terminator",
        re.compile(r"(?:'|\"|;)\s*(?:--|#|/\*)"),
        Severity.HIGH,
    ),
    (
        "stacked_query",
        re.compile(r";\s*(?:drop|truncate|delete|update|insert|alter)\b", re.I),
        Severity.CRITICAL,
    ),
    (
        "metadata_escape",
        # Postgres-style array / jsonb escape attempts embedded in an
        # ostensibly opaque identifier.
        re.compile(r"(?:\}'|::regclass|pg_(?:sleep|read_file)|information_schema)", re.I),
        Severity.HIGH,
    ),
]


class SQLInjectionDetector:
    def __init__(self, config: SQLInjectionConfig) -> None:
        self.config = config

    def scan(self, *, field: str, value: str) -> list[Detection]:
        if not self.config.enabled or field not in self.config.fields:
            return []
        rules = set(self.config.rules)
        out: list[Detection] = []
        for name, pat, sev in _PATTERNS:
            if name not in rules:
                continue
            m = pat.search(value)
            if m:
                out.append(
                    Detection(
                        detector="sql_injection",
                        rule=name,
                        severity=sev,
                        extra={"field": field, "match": m.group(0)},
                    )
                )
        return out
