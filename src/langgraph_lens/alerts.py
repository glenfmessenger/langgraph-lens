"""Slack / webhook alerts.

Deliberately minimal. The lens is observational and these alerts exist for
the small number of detections that genuinely warrant a page:
`supply_chain` (you loaded a compromised prompt), `attack_surface` (you
have a pickle-fallback checkpoint backend reachable from a multi-tenant
endpoint), `checkpoint` (an unsafe pickle opcode hit your saver), and
`goal_hijack` (an agent's effective goal has drifted from the user's
intent). PII and tool detections fire too often to be useful as alerts;
dashboard them instead.
"""

from __future__ import annotations

import contextlib
import json
import time
import urllib.error
import urllib.request
from collections.abc import Iterable

from .config import AlertsConfig
from .events import Event


class AlertSender:
    def __init__(self, config: AlertsConfig) -> None:
        self.config = config
        self._last_sent: dict[str, float] = {}

    def maybe_send(self, event: Event) -> None:
        if not self.config.enabled or not self.config.slack_webhook:
            return

        firing_kinds = {d.detector for d in event.detections}
        relevant = firing_kinds & set(self.config.alert_on)
        if not relevant:
            return

        # Per-detector cooldown.
        now = time.time()
        for kind in relevant:
            last = self._last_sent.get(kind, 0.0)
            if now - last < self.config.cooldown_seconds:
                continue
            self._last_sent[kind] = now
            self._send(kind, event)

    def _send(self, kind: str, event: Event) -> None:
        text = _format_slack(kind, event)
        body = json.dumps({"text": text}).encode()
        req = urllib.request.Request(
            self.config.slack_webhook,
            data=body,
            headers={"Content-Type": "application/json"},
        )
        # Best-effort — alert failures must not interfere with agent execution.
        with contextlib.suppress(urllib.error.URLError, TimeoutError):
            urllib.request.urlopen(req, timeout=5).close()


def _format_slack(kind: str, event: Event) -> str:
    rules = _collect_rules(d.rule for d in event.detections if d.detector == kind)
    extras = []
    if event.thread_id:
        extras.append(f"thread_id: {event.thread_id}")
    if event.node:
        extras.append(f"node: {event.node}")
    if event.run_id:
        extras.append(f"run_id: {event.run_id}")
    suffix = " | ".join(extras)
    return (
        f"[langgraph-lens] {kind} detection — "
        f"rules: {', '.join(sorted(rules))} | "
        f"correlation_id: {event.correlation_id}"
        + (f" | {suffix}" if suffix else "")
    )


def _collect_rules(rules: Iterable[str]) -> set[str]:
    return set(rules)
