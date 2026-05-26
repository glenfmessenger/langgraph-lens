"""Tool allow-list / misuse defense.

Wraps the Tier 1 tool detector and turns its detections into a terminal
decision. Two policy axes:

  - **allowlist** — only tools whose name appears in `allowed_tools` may
    be invoked. Unknown tools produce a `block` decision regardless of
    argument shape.
  - **misuse**   — independent of the allow-list, calls whose arguments
    match the Tier 1 `shell_metachar` / `ssrf_pattern` / `oversized_args`
    rules produce a `block` (in `block` mode) or `allow` (in `log` mode,
    used to gradually roll the intervention out).
"""

from __future__ import annotations

from typing import Any

from ..config import ToolAllowlistConfig
from ..detectors.tool import ToolDetector
from ..events import Detection
from .decisions import LensDecision


class ToolAllowlistIntervention:
    def __init__(
        self, config: ToolAllowlistConfig, *, t1_detector: ToolDetector
    ) -> None:
        self.config = config
        self._t1 = t1_detector

    def evaluate(
        self,
        *,
        tool: str,
        args: dict[str, Any] | str,
        thread_id: str | None = None,
    ) -> tuple[LensDecision, list[Detection]]:
        if not self.config.enabled:
            return LensDecision(), []

        triggered: list[str] = []
        detections: list[Detection] = []

        if self.config.allowed_tools is not None and tool not in self.config.allowed_tools:
            triggered.append("tool_allowlist.out_of_allowlist")

        # Re-use the Tier 1 detector for misuse signals.
        t1 = self._t1.scan(
            tool=tool,
            args=args,
            allowed_tools=self.config.allowed_tools,
            thread_id=thread_id,
        )
        for d in t1:
            if d.rule in self.config.block_on_rules:
                triggered.append(f"tool_allowlist.{d.rule}")
                detections.append(d)

        if not triggered:
            return LensDecision(), []

        if self.config.mode == "log":
            return LensDecision(triggered_by=triggered), detections

        return (
            LensDecision(
                action="block",
                reason="tool_blocked",
                triggered_by=triggered,
                status_code=403,
            ),
            detections,
        )
