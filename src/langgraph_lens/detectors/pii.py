"""PII regex detectors.

These run against decoded request, response, checkpoint, and memory
text. They are intentionally conservative: false negatives are preferable
to noisy false positives in an always-on observability path. See
`docs/pii-limitations.md` for known gaps.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from ..config import PIIConfig, PIIPattern
from ..events import Detection, Severity

# Built-in patterns. Anchored where possible to reduce false positives.
_BUILTIN: dict[str, tuple[re.Pattern[str], Severity]] = {
    "ssn": (
        re.compile(r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"),
        Severity.HIGH,
    ),
    "credit_card": (
        re.compile(r"\b(?:\d[ -]?){13,19}\b"),
        Severity.HIGH,
    ),
    "phone_us": (
        re.compile(r"\b(?:\+?1[-.\s]?)?\(?[2-9]\d{2}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"),
        Severity.MEDIUM,
    ),
    "phone_intl": (
        re.compile(r"\+\d{1,3}[\s-]?\d{1,4}[\s-]?\d{3,4}[\s-]?\d{3,4}"),
        Severity.MEDIUM,
    ),
    "email": (
        re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
        Severity.MEDIUM,
    ),
    "ip_address": (
        re.compile(
            r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}"
            r"(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b"
        ),
        Severity.LOW,
    ),
}


@dataclass(slots=True)
class _CompiledPattern:
    name: str
    pattern: re.Pattern[str]
    severity: Severity


def _luhn(card: str) -> bool:
    digits = [int(c) for c in card if c.isdigit()]
    if len(digits) < 13:
        return False
    checksum = 0
    parity = len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


class PIIDetector:
    """Scans a string body for PII patterns and returns Detections."""

    def __init__(self, config: PIIConfig) -> None:
        self.config = config
        self._compiled: list[_CompiledPattern] = []
        for p in config.patterns:
            compiled = self._compile(p)
            if compiled is not None:
                self._compiled.append(compiled)
        for p in config.custom_patterns:
            compiled = self._compile(p)
            if compiled is not None:
                self._compiled.append(compiled)

    @staticmethod
    def _compile(p: PIIPattern) -> _CompiledPattern | None:
        if p.type and p.type in _BUILTIN:
            pat, sev = _BUILTIN[p.type]
            return _CompiledPattern(name=p.type, pattern=pat, severity=sev)
        if p.regex:
            return _CompiledPattern(
                name=p.name or "custom",
                pattern=re.compile(p.regex),
                severity=Severity.MEDIUM,
            )
        return None

    def scan(self, text: str, direction: str) -> list[Detection]:
        if not self.config.enabled:
            return []
        if direction == "ingress" and not self.config.scan_ingress:
            return []
        if direction == "egress" and not self.config.scan_egress:
            return []
        if direction == "checkpoint" and not self.config.scan_checkpoints:
            return []

        results: list[Detection] = []
        for cp in self._compiled:
            matches = cp.pattern.findall(text)
            if not matches:
                continue
            if cp.name == "credit_card":
                matches = [m for m in matches if _luhn(m)]
                if not matches:
                    continue
            first = matches[0]
            results.append(
                Detection(
                    detector="pii",
                    rule=cp.name,
                    severity=cp.severity,
                    extra={
                        "type": cp.name,
                        "direction": direction,
                        "match_count": len(matches),
                        "match": first if isinstance(first, str) else str(first),
                    },
                )
            )
        return results
