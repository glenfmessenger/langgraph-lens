"""LensDecision — the shape returned by every Tier 2 intervention.

A decision describes what the lens wants the caller to *do* with a node,
checkpoint, or tool call:

  - `allow`   — pass through unchanged. The default. Tier 1 detections
                may still have been emitted; the caller is free to ignore
                this decision and continue.
  - `redact`  — pass through, but use `modified_state` instead of the
                original. The lens has scrubbed PII or other sensitive
                content; the agent continues without knowing.
  - `throttle`— rate-limited. The caller should sleep `retry_after`
                seconds and retry, or return a `429`-equivalent to the
                user.
  - `block`   — terminal. The caller must not invoke the underlying
                node / tool / checkpoint operation. The decision carries
                the reason and (optionally) the HTTP status code that
                fits the failure mode.

Decisions compose via `merge(...)`: the first terminal decision wins,
non-terminal decisions accumulate their `triggered_by` lists so the
final audit record reflects everything the lens saw.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

Action = Literal["allow", "redact", "throttle", "block"]

_TERMINAL_ACTIONS: frozenset[Action] = frozenset({"block"})


class LensBlockedError(RuntimeError):
    """Raised by `LensCallback` when a Tier 2 `block` decision fires and
    `enforce_blocks=True`. Catch this around `graph.invoke(...)` to
    surface a clean error to the user — the message is the lens
    `reason`, the `.decision` attribute carries the full decision.
    """

    def __init__(self, decision: LensDecision) -> None:
        super().__init__(decision.reason or "blocked by langgraph-lens")
        self.decision = decision


@dataclass(slots=True)
class LensDecision:
    action: Action = "allow"
    reason: str | None = None
    triggered_by: list[str] = field(default_factory=list)
    modified_state: dict[str, Any] | None = None
    headers: dict[str, str] = field(default_factory=dict)
    status_code: int | None = None
    retry_after: float | None = None

    @property
    def is_terminal(self) -> bool:
        return self.action in _TERMINAL_ACTIONS

    def merge(self, other: LensDecision) -> LensDecision:
        """Combine two decisions. Terminal beats non-terminal; among
        non-terminals, `redact` and `throttle` beat `allow`.
        """
        if self.is_terminal:
            self.triggered_by.extend(other.triggered_by)
            return self
        if other.is_terminal:
            other.triggered_by = [*self.triggered_by, *other.triggered_by]
            # Preserve any state-modifications already accumulated.
            if other.modified_state is None and self.modified_state is not None:
                other.modified_state = self.modified_state
            return other
        # Both non-terminal. Prefer the more-restrictive action.
        rank: dict[Action, int] = {"allow": 0, "redact": 1, "throttle": 2, "block": 3}
        winner = self if rank[self.action] >= rank[other.action] else other
        loser = other if winner is self else self
        winner.triggered_by.extend(loser.triggered_by)
        if winner.modified_state is None and loser.modified_state is not None:
            winner.modified_state = loser.modified_state
        return winner

    def with_audit_headers(
        self,
        *,
        triggered_header: str = "X-Lens-Triggered",
        reason_header: str = "X-Lens-Reason",
        action_header: str = "X-Lens-Action",
    ) -> LensDecision:
        """Stamp the canonical audit headers onto `self.headers` if any
        intervention fired. Idempotent.
        """
        if not self.triggered_by and self.action == "allow":
            return self
        self.headers.setdefault(triggered_header, "true")
        self.headers.setdefault(action_header, self.action)
        if self.triggered_by:
            self.headers.setdefault(reason_header, ",".join(sorted(set(self.triggered_by))))
        if self.retry_after is not None:
            self.headers.setdefault("Retry-After", str(int(self.retry_after)))
        return self
