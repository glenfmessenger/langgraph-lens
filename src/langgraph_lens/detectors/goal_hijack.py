"""Agent goal-hijack detector.

Heuristic check for "the agent's effective goal no longer matches what
the user asked for." We don't try to be clever about semantic similarity
— that's a research problem, and false positives in an always-on
observability path are worse than false negatives. Instead we use three
crude but useful signals:

  1. **system_prompt_drift** — the current effective system prompt
     contains substrings from a watch-list (`transfer funds`, `delete
     account`, `curl http`, etc.) that were absent from the originating
     user message. That shape is the canonical indirect-injection
     hijack.
  2. **tool_call_drift** — the same watch-list, but applied to pending
     tool-call args.
  3. **off_topic_subgoal** — token-overlap similarity between the
     originating user message and the current state's pending action
     description drops below `user_intent_similarity_threshold`. Useful
     for catching wholesale topic switches; tune the threshold to your
     workload.
"""

from __future__ import annotations

import re
from typing import Any

from ..config import GoalHijackConfig
from ..events import Detection, Severity

_WORD = re.compile(r"\w+")


class GoalHijackDetector:
    def __init__(self, config: GoalHijackConfig) -> None:
        self.config = config

    def scan(
        self,
        *,
        state: dict[str, Any],
        originating_intent: str | None,
    ) -> list[Detection]:
        if not self.config.enabled or not originating_intent:
            return []
        out: list[Detection] = []
        rules = set(self.config.rules)

        system_prompt = _extract_system_prompt(state)
        tool_calls_text = _extract_tool_calls(state)

        watch = [w.lower() for w in self.config.watch_substrings]
        intent_lower = originating_intent.lower()

        if "system_prompt_drift" in rules and system_prompt:
            sys_lower = system_prompt.lower()
            for w in watch:
                if w in sys_lower and w not in intent_lower:
                    out.append(
                        Detection(
                            detector="goal_hijack",
                            rule="system_prompt_drift",
                            severity=Severity.HIGH,
                            extra={
                                "match": w,
                                "advisory": "System prompt contains a sensitive directive that wasn't in the user's request.",
                            },
                        )
                    )
                    break

        if "tool_call_drift" in rules and tool_calls_text:
            tc_lower = tool_calls_text.lower()
            for w in watch:
                if w in tc_lower and w not in intent_lower:
                    out.append(
                        Detection(
                            detector="goal_hijack",
                            rule="tool_call_drift",
                            severity=Severity.HIGH,
                            extra={"match": w},
                        )
                    )
                    break

        if "off_topic_subgoal" in rules:
            pending = _extract_pending_action(state)
            if pending:
                sim = _token_jaccard(originating_intent, pending)
                if sim < self.config.user_intent_similarity_threshold:
                    out.append(
                        Detection(
                            detector="goal_hijack",
                            rule="off_topic_subgoal",
                            severity=Severity.MEDIUM,
                            extra={
                                "similarity": round(sim, 3),
                                "threshold": self.config.user_intent_similarity_threshold,
                            },
                        )
                    )

        return out


def _extract_system_prompt(state: dict[str, Any]) -> str:
    if not isinstance(state, dict):
        return ""
    msgs = state.get("messages")
    if not isinstance(msgs, list):
        return ""
    for m in msgs:
        role = m.get("role") if isinstance(m, dict) else getattr(m, "type", None)
        if role in ("system",):
            return _content_of(m)
    return ""


def _extract_tool_calls(state: dict[str, Any]) -> str:
    if not isinstance(state, dict):
        return ""
    parts: list[str] = []
    msgs = state.get("messages")
    if isinstance(msgs, list):
        for m in msgs:
            tc = m.get("tool_calls") if isinstance(m, dict) else getattr(m, "tool_calls", None)
            if isinstance(tc, list):
                for call in tc:
                    if isinstance(call, dict):
                        args = call.get("args") or call.get("arguments")
                        parts.append(repr(args))
    pending = state.get("pending_tool_calls")
    if isinstance(pending, list):
        parts.append(repr(pending))
    return "\n".join(parts)


def _extract_pending_action(state: dict[str, Any]) -> str:
    if not isinstance(state, dict):
        return ""
    # Most-recent assistant message content is a reasonable proxy for
    # "what the agent is currently planning to do."
    msgs = state.get("messages")
    if isinstance(msgs, list):
        for m in reversed(msgs):
            role = m.get("role") if isinstance(m, dict) else getattr(m, "type", None)
            if role in ("assistant", "ai"):
                c = _content_of(m)
                if c:
                    return c
    return ""


def _content_of(m: Any) -> str:
    c = m.get("content") if isinstance(m, dict) else getattr(m, "content", None)
    if isinstance(c, str):
        return c
    if isinstance(c, list):
        return "\n".join(
            str(sub.get("text", "")) if isinstance(sub, dict) else str(sub) for sub in c
        )
    return ""


def _token_jaccard(a: str, b: str) -> float:
    ta = {w.lower() for w in _WORD.findall(a)}
    tb = {w.lower() for w in _WORD.findall(b)}
    if not ta or not tb:
        return 1.0
    inter = ta & tb
    union = ta | tb
    return len(inter) / len(union) if union else 1.0
