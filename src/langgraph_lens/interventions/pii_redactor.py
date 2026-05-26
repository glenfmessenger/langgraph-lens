"""Hard PII redaction.

Scans the message list and free-form state fields for the configured PII
patterns and replaces matches in-place with `[REDACTED:<type>]`. The
result is returned as a *new* state dict on the decision — the lens
never mutates the caller's state object.

Modes:
  - `redact` (default) — substitute matches, allow the graph to continue.
  - `block`            — refuse to forward the state; raise a terminal
                         decision instead. Useful when policy says PII
                         in agent inputs is itself the violation.
"""

from __future__ import annotations

import copy
import re
from typing import Any

from ..config import PIIRedactionConfig
from ..detectors.pii import _BUILTIN, _CompiledPattern, _luhn
from ..events import Detection, Severity
from .decisions import LensDecision


class PIIRedactorIntervention:
    def __init__(self, config: PIIRedactionConfig) -> None:
        self.config = config
        self._compiled: list[_CompiledPattern] = []
        for p in config.patterns:
            if p.type and p.type in _BUILTIN:
                pat, sev = _BUILTIN[p.type]
                self._compiled.append(
                    _CompiledPattern(name=p.type, pattern=pat, severity=sev)
                )
            elif p.regex:
                self._compiled.append(
                    _CompiledPattern(
                        name=p.name or "custom",
                        pattern=re.compile(p.regex),
                        severity=Severity.MEDIUM,
                    )
                )
        for p in config.custom_patterns:
            if p.regex:
                self._compiled.append(
                    _CompiledPattern(
                        name=p.name or "custom",
                        pattern=re.compile(p.regex),
                        severity=Severity.MEDIUM,
                    )
                )

    def evaluate(
        self, state: dict[str, Any]
    ) -> tuple[LensDecision, list[Detection]]:
        if not self.config.enabled or not isinstance(state, dict):
            return LensDecision(), []

        modified = copy.deepcopy(state)
        detections: list[Detection] = []
        hit_types: set[str] = set()

        def _scrub(text: str) -> str:
            scrubbed = text
            for cp in self._compiled:
                if cp.name == "credit_card":
                    name = cp.name

                    def _sub(m: re.Match[str], _name: str = name) -> str:
                        return (
                            f"[REDACTED:{_name}]"
                            if _luhn(m.group(0))
                            else m.group(0)
                        )

                    new = cp.pattern.sub(_sub, scrubbed)
                else:
                    new = cp.pattern.sub(f"[REDACTED:{cp.name}]", scrubbed)
                if new != scrubbed:
                    hit_types.add(cp.name)
                    scrubbed = new
            return scrubbed

        # messages list — both dict-shaped and BaseMessage-shaped.
        msgs = modified.get("messages")
        if isinstance(msgs, list):
            for m in msgs:
                if isinstance(m, dict):
                    c = m.get("content")
                    if isinstance(c, str):
                        m["content"] = _scrub(c)
                    elif isinstance(c, list):
                        for sub in c:
                            if isinstance(sub, dict) and isinstance(sub.get("text"), str):
                                sub["text"] = _scrub(sub["text"])

        # Free-form string state fields.
        for k in list(modified.keys()):
            if k == "messages":
                continue
            v = modified[k]
            if isinstance(v, str):
                modified[k] = _scrub(v)

        if not hit_types:
            return LensDecision(), []

        for t in sorted(hit_types):
            detections.append(
                Detection(
                    detector="pii_redactor",
                    rule=t,
                    severity=Severity.HIGH,
                    extra={"type": t},
                )
            )

        if self.config.mode == "block":
            return (
                LensDecision(
                    action="block",
                    reason="pii_in_state",
                    triggered_by=[f"pii_redactor.{t}" for t in sorted(hit_types)],
                    status_code=400,
                ),
                detections,
            )

        return (
            LensDecision(
                action="redact",
                triggered_by=[f"pii_redactor.{t}" for t in sorted(hit_types)],
                modified_state=modified,
            ),
            detections,
        )
