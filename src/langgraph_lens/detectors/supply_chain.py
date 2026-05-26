"""Supply-chain detector — prompt loading.

Scans prompt files (Jinja2, f-string, mustache) for known-bad signatures
and flags path-traversal sequences in the loader call. The canonical
target is **CVE-2026-34070**: Jinja2 SSTI via a prompt pulled from an
untrusted prompt registry.
"""

from __future__ import annotations

import re
from pathlib import Path

from ..config import SupplyChainConfig
from ..events import Detection, Severity

# Canonical Jinja2 sandbox-escape patterns. These are signature matches,
# not semantic — a benign prompt that legitimately references `__class__`
# will be flagged. That trade-off is acceptable for an observability
# path.
_JINJA_SSTI_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\{\{[^}]*__class__[^}]*\}\}"),
    re.compile(r"\{\{[^}]*__mro__[^}]*\}\}"),
    re.compile(r"\{\{[^}]*__subclasses__[^}]*\}\}"),
    re.compile(r"\{\{[^}]*__globals__[^}]*\}\}"),
    re.compile(r"\{\{[^}]*config\.\__class__[^}]*\}\}"),
    re.compile(r"\{%\s*set\s+\w+\s*=\s*[^%]*__\w+__[^%]*%\}"),
]

# Path-traversal sequences in loader paths.
_PATH_TRAVERSAL_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\.\./"),
    re.compile(r"\.\.\\"),
    re.compile(r"^/(etc|root|home)/"),
    re.compile(r"file:///"),
]

# Chat-template framing tokens that, if present in *rendered* output (not
# template source), indicate the template is unsafely concatenating
# user input into structural roles.
_UNSAFE_CHAT_TEMPLATE_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\{\{\s*messages\s*\|\s*safe\s*\}\}"),
    re.compile(r"autoescape\s*=\s*False"),
]


class SupplyChainDetector:
    def __init__(self, config: SupplyChainConfig) -> None:
        self.config = config

    def scan_path(self, path: str | Path) -> list[Detection]:
        if not self.config.enabled:
            return []
        rules = set(self.config.rules)
        out: list[Detection] = []
        p = Path(path)

        if "path_traversal" in rules:
            for pat in _PATH_TRAVERSAL_PATTERNS:
                if pat.search(str(path)):
                    out.append(
                        Detection(
                            detector="supply_chain",
                            rule="path_traversal",
                            severity=Severity.HIGH,
                            extra={"path": str(path)},
                        )
                    )
                    break

        if p.is_file():
            out.extend(self._scan_file(p, rules))
        elif p.is_dir():
            for child in sorted(p.rglob("*")):
                if child.is_file() and child.suffix in (
                    ".jinja2",
                    ".j2",
                    ".tmpl",
                    ".prompt",
                    ".txt",
                    ".yaml",
                    ".yml",
                ):
                    out.extend(self._scan_file(child, rules))

        return out

    def scan_text(
        self, text: str, *, filename: str = "<inline>"
    ) -> list[Detection]:
        """Scan an in-memory prompt template string."""
        if not self.config.enabled:
            return []
        return list(self._scan_string(text, filename, set(self.config.rules)))

    def _scan_file(self, path: Path, rules: set[str]) -> list[Detection]:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []
        return list(self._scan_string(text, str(path), rules))

    @staticmethod
    def _scan_string(text: str, filename: str, rules: set[str]) -> list[Detection]:
        out: list[Detection] = []
        if "jinja_ssti" in rules:
            for pat in _JINJA_SSTI_PATTERNS:
                m = pat.search(text)
                if m:
                    out.append(
                        Detection(
                            detector="supply_chain",
                            rule="jinja_ssti",
                            severity=Severity.CRITICAL,
                            extra={
                                "file": filename,
                                "match": m.group(0),
                                "advisory": "Jinja2 SSTI signature — CVE-2026-34070 shape.",
                            },
                        )
                    )
                    break

        if "unsafe_chat_template" in rules:
            for pat in _UNSAFE_CHAT_TEMPLATE_PATTERNS:
                m = pat.search(text)
                if m:
                    out.append(
                        Detection(
                            detector="supply_chain",
                            rule="unsafe_chat_template",
                            severity=Severity.HIGH,
                            extra={"file": filename, "match": m.group(0)},
                        )
                    )
                    break

        return out
