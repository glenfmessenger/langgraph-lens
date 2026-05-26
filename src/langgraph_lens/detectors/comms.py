"""Inter-agent / graph-communication anomaly detector.

LangGraph's `StateGraph` declares its edges at compile time. At runtime,
the lens can compare the actual traversal against the declared topology
and flag deviations: edges that weren't declared, `Send(...)` calls to
subgraphs that weren't listed as targets, or recursion that's already
past the configured `recursion_limit` and likely to loop until the
runtime kills it.
"""

from __future__ import annotations

from typing import Any

from ..config import CommsConfig
from ..events import Detection, Severity


class CommsDetector:
    def __init__(self, config: CommsConfig) -> None:
        self.config = config
        # Last-seen node per thread so we can validate the incoming edge.
        self._last_node: dict[str, str] = {}

    def scan(
        self,
        *,
        node: str,
        state: dict[str, Any],
        declared_edges: list[tuple[str, str]] | None = None,
        recursion_limit: int | None = None,
        recursion_depth: int | None = None,
        initial_state_size: int | None = None,
        thread_id: str | None = None,
    ) -> list[Detection]:
        if not self.config.enabled:
            return []
        out: list[Detection] = []
        rules = set(self.config.rules)

        if "undeclared_edge" in rules and declared_edges is not None and thread_id:
            previous = self._last_node.get(thread_id)
            if previous is not None and (previous, node) not in declared_edges:
                out.append(
                    Detection(
                        detector="comms",
                        rule="undeclared_edge",
                        severity=Severity.HIGH,
                        extra={"from": previous, "to": node},
                    )
                )
            self._last_node[thread_id] = node

        if (
            "recursion_exceeded" in rules
            and isinstance(recursion_limit, int)
            and isinstance(recursion_depth, int)
            and recursion_depth >= recursion_limit
        ):
            out.append(
                Detection(
                    detector="comms",
                    rule="recursion_exceeded",
                    severity=Severity.MEDIUM,
                    extra={
                        "recursion_depth": recursion_depth,
                        "recursion_limit": recursion_limit,
                    },
                )
            )

        if "send_to_undeclared_target" in rules and declared_edges is not None:
            for target in _send_targets(state):
                if not any(target == dst for _, dst in declared_edges):
                    out.append(
                        Detection(
                            detector="comms",
                            rule="send_to_undeclared_target",
                            severity=Severity.HIGH,
                            extra={"node": node, "target": target},
                        )
                    )

        if (
            "oversized_state_growth" in rules
            and isinstance(initial_state_size, int)
            and initial_state_size > 0
        ):
            current = _approx_size(state)
            if current >= initial_state_size * self.config.state_growth_multiplier:
                out.append(
                    Detection(
                        detector="comms",
                        rule="oversized_state_growth",
                        severity=Severity.MEDIUM,
                        extra={
                            "initial_bytes": initial_state_size,
                            "current_bytes": current,
                            "multiplier": self.config.state_growth_multiplier,
                        },
                    )
                )

        return out


def _send_targets(state: dict[str, Any]) -> list[str]:
    """Pull declared Send(...) targets out of state.

    LangGraph's `Send` objects carry a `node` attribute. We accept either
    real Send objects or dict-shaped equivalents (`{"node": ..., "arg": ...}`)
    that test fixtures and serialised checkpoints use.
    """
    if not isinstance(state, dict):
        return []
    out: list[str] = []
    sends = state.get("__pregel_send__") or state.get("sends") or []
    if isinstance(sends, list):
        for s in sends:
            t = getattr(s, "node", None) or (s.get("node") if isinstance(s, dict) else None)
            if isinstance(t, str):
                out.append(t)
    return out


def _approx_size(state: Any) -> int:
    try:
        import json

        return len(json.dumps(state, default=str))
    except (TypeError, ValueError):
        return len(repr(state))
