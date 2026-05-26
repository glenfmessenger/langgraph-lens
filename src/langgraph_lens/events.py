"""Event and Detection types.

The shape of events is part of the public contract — downstream log
pipelines and audit tools depend on these fields. Treat any change to
field names or to `EventKind` values as a breaking change.
"""

from __future__ import annotations

import enum
import hashlib
import json
import secrets
import sys
import time
from dataclasses import dataclass, field
from typing import Any


class EventKind(str, enum.Enum):
    NODE_INSPECTED = "node_inspected"
    CHECKPOINT_INSPECTED = "checkpoint_inspected"
    TOOL_CALL_INSPECTED = "tool_call_inspected"
    MEMORY_INSPECTED = "memory_inspected"
    PROMPT_SCAN = "prompt_scan"
    ATTACK_SURFACE_SCAN = "attack_surface_scan"
    SQL_INSPECTED = "sql_inspected"


class Severity(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(slots=True)
class Detection:
    detector: str
    rule: str
    severity: Severity = Severity.MEDIUM
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self, *, include_match_text: bool = False) -> dict[str, Any]:
        extra = dict(self.extra)
        if not include_match_text:
            extra.pop("match", None)
        return {
            "detector": self.detector,
            "rule": self.rule,
            "severity": self.severity.value,
            **extra,
        }


@dataclass(slots=True)
class Event:
    event: EventKind
    correlation_id: str
    detections: list[Detection] = field(default_factory=list)
    run_id: str | None = None
    thread_id: str | None = None
    node: str | None = None
    checkpoint_id: str | None = None
    state_hash: str | None = None
    timestamp: float = field(default_factory=time.time)

    def to_dict(self, *, include_match_text: bool = False) -> dict[str, Any]:
        out: dict[str, Any] = {
            "event": self.event.value,
            "correlation_id": self.correlation_id,
            "timestamp": self.timestamp,
            "detections": [d.to_dict(include_match_text=include_match_text) for d in self.detections],
        }
        for k in ("run_id", "thread_id", "node", "checkpoint_id", "state_hash"):
            v = getattr(self, k)
            if v is not None:
                out[k] = v
        return out


def new_correlation_id(*, prefix: str = "") -> str:
    return f"{prefix}{secrets.token_hex(8)}"


def hash_state(state: Any) -> str:
    """SHA-256 of a JSON-canonicalised state dict. Falls back to repr()."""
    try:
        blob = json.dumps(state, sort_keys=True, default=str).encode("utf-8")
    except (TypeError, ValueError):
        blob = repr(state).encode("utf-8")
    return "sha256:" + hashlib.sha256(blob).hexdigest()


def write_event(
    event: Event,
    *,
    destination: str = "stderr",
    file_path: str | None = None,
    include_match_text: bool = False,
) -> None:
    line = json.dumps(event.to_dict(include_match_text=include_match_text))
    if destination == "file" and file_path:
        try:
            with open(file_path, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
            return
        except OSError:
            # Fall through to stderr — never lose an event because the
            # configured log file is unavailable.
            pass
    print(line, file=sys.stderr)
