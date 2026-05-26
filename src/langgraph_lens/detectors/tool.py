"""Tool enumeration & misuse detector.

Flags four kinds of signal at tool-call time:

  1. The agent is calling a tool that isn't in the declared
     `bind_tools(...)` allow-list. Either a model hallucinated a tool name
     or the binding diverged from the runtime.
  2. The agent enumerates many distinct tools within a short window —
     classic "tool sweep" behaviour that often precedes mis-use.
  3. The args contain shell metacharacters / SSRF-looking URLs.
  4. The args are unreasonably large — a soft DoS signal and often the
     vehicle for indirect-injection content stuffed into a tool arg.
"""

from __future__ import annotations

import json
import re
import time
from collections import defaultdict, deque
from typing import Any

from ..config import ToolConfig
from ..events import Detection, Severity

_SHELL_METACHAR_PATTERNS = [
    re.compile(r";\s*(?:rm|cat|curl|wget|sh|bash|nc|ncat)\b"),
    re.compile(r"\|\s*(?:sh|bash|/bin/sh|/bin/bash)\b"),
    re.compile(r"\$\([^)]+\)"),
    re.compile(r"`[^`]+`"),
    re.compile(r"&&\s*(?:rm|cat|curl|wget|sh|bash)\b"),
]

_SSRF_PATTERNS = [
    re.compile(r"https?://(?:127\.0\.0\.1|localhost|0\.0\.0\.0|::1)"),
    re.compile(r"https?://169\.254\.169\.254"),  # AWS metadata
    re.compile(r"https?://metadata\.google\.internal"),
    re.compile(r"file:///"),
    re.compile(r"gopher://"),
]


class ToolDetector:
    def __init__(self, config: ToolConfig) -> None:
        self.config = config
        # Per-thread sliding window of distinct tool names called.
        self._enum_windows: dict[str, deque[tuple[float, str]]] = defaultdict(deque)

    def scan(
        self,
        *,
        tool: str,
        args: dict[str, Any] | str,
        allowed_tools: list[str] | None = None,
        thread_id: str | None = None,
    ) -> list[Detection]:
        if not self.config.enabled:
            return []
        out: list[Detection] = []
        rules = set(self.config.rules)

        if "out_of_allowlist" in rules and allowed_tools is not None and tool not in allowed_tools:
            out.append(
                Detection(
                    detector="tool",
                    rule="out_of_allowlist",
                    severity=Severity.HIGH,
                    extra={"tool": tool, "allowed": sorted(allowed_tools)},
                )
            )

        if "enumeration" in rules and thread_id:
            window = self._enum_windows[thread_id]
            now = time.time()
            cutoff = now - self.config.enumeration_window_seconds
            window.append((now, tool))
            while window and window[0][0] < cutoff:
                window.popleft()
            distinct = {t for _, t in window}
            if len(distinct) >= self.config.enumeration_threshold:
                out.append(
                    Detection(
                        detector="tool",
                        rule="enumeration",
                        severity=Severity.MEDIUM,
                        extra={
                            "distinct_tools": sorted(distinct),
                            "window_seconds": self.config.enumeration_window_seconds,
                        },
                    )
                )

        arg_text = _stringify_args(args)

        if "oversized_args" in rules and len(arg_text) > self.config.max_arg_bytes:
            out.append(
                Detection(
                    detector="tool",
                    rule="oversized_args",
                    severity=Severity.LOW,
                    extra={
                        "tool": tool,
                        "bytes": len(arg_text),
                        "max_bytes": self.config.max_arg_bytes,
                    },
                )
            )

        if "shell_metachar" in rules:
            for pat in _SHELL_METACHAR_PATTERNS:
                m = pat.search(arg_text)
                if m:
                    out.append(
                        Detection(
                            detector="tool",
                            rule="shell_metachar",
                            severity=Severity.HIGH,
                            extra={"tool": tool, "match": m.group(0)},
                        )
                    )
                    break

        if "ssrf_pattern" in rules:
            for pat in _SSRF_PATTERNS:
                m = pat.search(arg_text)
                if m:
                    out.append(
                        Detection(
                            detector="tool",
                            rule="ssrf_pattern",
                            severity=Severity.HIGH,
                            extra={"tool": tool, "match": m.group(0)},
                        )
                    )
                    break

        return out


def _stringify_args(args: dict[str, Any] | str) -> str:
    if isinstance(args, str):
        return args
    try:
        return json.dumps(args, default=str)
    except (TypeError, ValueError):
        return repr(args)
