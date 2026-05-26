"""Agent goal / prompt guard.

Wraps the Tier 1 goal-hijack detector and turns its findings into a
terminal decision. Two policies:

  - **block_on_drift** — `system_prompt_drift` or `tool_call_drift` (the
    high-severity goal-hijack rules) produce a `block` decision. This
    is the right default when the watch-substring list is short and
    well-curated.
  - **off_topic** — `off_topic_subgoal` (medium severity) is *not* a
    block signal by default. False-positive rate is too high to be a
    terminal control. Operators who want it must add `off_topic_subgoal`
    to `block_on_rules` explicitly.

Mode:
  - `block` (default) — terminal decision.
  - `log`             — triggered_by only, pass through.
"""

from __future__ import annotations

from typing import Any

from ..config import GoalGuardConfig
from ..detectors.goal_hijack import GoalHijackDetector
from ..events import Detection
from .decisions import LensDecision


class GoalGuardIntervention:
    def __init__(
        self, config: GoalGuardConfig, *, t1_detector: GoalHijackDetector
    ) -> None:
        self.config = config
        self._t1 = t1_detector

    def evaluate(
        self,
        *,
        state: dict[str, Any],
        originating_intent: str | None,
    ) -> tuple[LensDecision, list[Detection]]:
        if not self.config.enabled or originating_intent is None:
            return LensDecision(), []

        t1 = self._t1.scan(state=state, originating_intent=originating_intent)
        triggered: list[str] = []
        detections: list[Detection] = []
        for d in t1:
            if d.rule in self.config.block_on_rules:
                triggered.append(f"goal_guard.{d.rule}")
                detections.append(d)

        if not triggered:
            return LensDecision(), []

        if self.config.mode == "log":
            return LensDecision(triggered_by=triggered), detections

        return (
            LensDecision(
                action="block",
                reason="goal_hijack",
                triggered_by=triggered,
                status_code=403,
            ),
            detections,
        )
