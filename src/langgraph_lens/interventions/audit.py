"""Audit signaling — `X-Lens-Triggered` / `X-Lens-Action` / `X-Lens-Reason`.

This is the cheapest of the Tier 2 features and the one that's safe to
enable on its own: it never blocks, redacts, or rate-limits. It exists
so that downstream callers (proxies, audit pipelines, the caller's own
client code) can detect that *something* fired without parsing event
logs.

Two surfaces:

  - **HTTP** — when langgraph-lens is mounted as a server middleware
    (`langgraph_lens.server.LensMiddleware`), the headers in
    `decision.headers` are stamped onto the outgoing response.
  - **State** — when `stamp_state: true`, the same fields are written
    into `state["__lens__"]` so downstream nodes can read them
    programmatically.
"""

from __future__ import annotations

from typing import Any

from ..config import AuditSignalingConfig
from .decisions import LensDecision


class AuditSignalingIntervention:
    def __init__(self, config: AuditSignalingConfig) -> None:
        self.config = config

    def stamp(self, decision: LensDecision) -> LensDecision:
        if not self.config.enabled:
            return decision
        return decision.with_audit_headers(
            triggered_header=self.config.triggered_header,
            reason_header=self.config.reason_header,
            action_header=self.config.action_header,
        )

    def stamp_state(self, state: dict[str, Any], decision: LensDecision) -> None:
        """Optionally annotate the state itself so downstream nodes can
        observe the lens decision without reading HTTP headers.
        """
        if not self.config.enabled or not self.config.stamp_state:
            return
        if not decision.triggered_by:
            return
        state.setdefault("__lens__", {}).update(
            {
                "triggered": True,
                "action": decision.action,
                "reason": decision.reason,
                "triggered_by": list(decision.triggered_by),
            }
        )
