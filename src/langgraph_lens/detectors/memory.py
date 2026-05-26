"""Memory / context-poisoning detector.

LangGraph deployments increasingly rely on a `BaseStore`-backed memory
layer to persist agent context across runs. That store is reachable from
the tools the agent invokes — meaning any tool that writes back to memory
can effectively inject content the next run will retrieve.

This detector inspects every memory write and flags:

  - Entries that look like system-prompt overrides (the canonical
    indirect-injection shape).
  - Entries large enough to dominate retrieval results.
  - Writes to a key that doesn't belong to the current thread / owner.
"""

from __future__ import annotations

import re
from typing import Any

from ..config import MemoryConfig
from ..events import Detection, Severity

_SYSTEM_PROMPT_OVERRIDE_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\byou are now\b", re.I),
    re.compile(r"\bignore (?:all )?(?:previous|prior|above) instructions?\b", re.I),
    re.compile(r"\bnew system prompt\b", re.I),
    re.compile(r"\bact as\b.*\b(?:admin|root|developer mode)\b", re.I),
    re.compile(r"<\|?im_start\|?>system", re.I),
]


class MemoryDetector:
    def __init__(self, config: MemoryConfig) -> None:
        self.config = config

    def scan(
        self,
        *,
        key: str,
        value: Any,
        owner: str | None = None,
    ) -> list[Detection]:
        if not self.config.enabled:
            return []
        out: list[Detection] = []
        rules = set(self.config.rules)
        text = _stringify(value)

        if "system_prompt_override" in rules:
            for pat in _SYSTEM_PROMPT_OVERRIDE_PATTERNS:
                m = pat.search(text)
                if m:
                    out.append(
                        Detection(
                            detector="memory",
                            rule="system_prompt_override",
                            severity=Severity.HIGH,
                            extra={"key": key, "match": m.group(0)},
                        )
                    )
                    break

        if "oversized_entry" in rules and len(text) > self.config.max_entry_bytes:
            out.append(
                Detection(
                    detector="memory",
                    rule="oversized_entry",
                    severity=Severity.MEDIUM,
                    extra={
                        "key": key,
                        "bytes": len(text),
                        "max_bytes": self.config.max_entry_bytes,
                        "advisory": "Oversized memory entries dominate retrieval and crowd out legitimate context.",
                    },
                )
            )

        if "cross_tenant_key" in rules and owner and not _key_belongs_to(key, owner):
            out.append(
                Detection(
                    detector="memory",
                    rule="cross_tenant_key",
                    severity=Severity.HIGH,
                    extra={"key": key, "owner": owner},
                )
            )

        return out


def _stringify(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).decode("utf-8", errors="replace")
    try:
        import json

        return json.dumps(value, default=str)
    except (TypeError, ValueError):
        return repr(value)


def _key_belongs_to(key: str, owner: str) -> bool:
    """Heuristic — a memory key 'belongs to' an owner if the owner string
    is a prefix component (slash- or colon-separated) of the key.
    """
    parts = re.split(r"[/:]", key)
    return owner in parts
