"""Circuit breaker for cascading failures.

Standard 3-state breaker (`closed` → `open` → `half_open` → `closed`)
with two trip conditions:

  1. **Error rate** — the rolling fraction of failed responses in the
     last `window_seconds` exceeds `error_rate_threshold` once at least
     `min_samples` calls have been observed.
  2. **Attack signals** — when `fail_closed_on_attack` is true, the
     breaker also opens preemptively if at least
     `fail_closed_min_attack_signals` detections of severity ≥
     `fail_closed_min_severity` arrive within
     `fail_closed_attack_window_seconds`.

While `open`, every request returns a terminal `block` with HTTP 503.
After `cooldown_seconds`, the breaker moves to `half_open` and allows a
single probe request through; success closes the breaker, failure
re-opens it.
"""

from __future__ import annotations

import enum
import time
from collections import deque

from ..config import CircuitBreakerConfig
from ..events import Detection, Severity
from .decisions import LensDecision


class _State(enum.IntEnum):
    CLOSED = 0
    HALF_OPEN = 1
    OPEN = 2


_SEVERITY_RANK: dict[str, int] = {
    "low": 0,
    "medium": 1,
    "high": 2,
    "critical": 3,
}


def _rank(s: Severity | str) -> int:
    return _SEVERITY_RANK.get(s.value if isinstance(s, Severity) else s, 0)


class CircuitBreakerIntervention:
    def __init__(self, config: CircuitBreakerConfig) -> None:
        self.config = config
        self._state: _State = _State.CLOSED
        self._opened_at: float = 0.0
        self._calls: deque[tuple[float, bool]] = deque()  # (ts, error)
        self._attacks: deque[tuple[float, Severity]] = deque()
        self._half_open_probes_inflight = 0

    @property
    def state_value(self) -> int:
        return int(self._state)

    # -- gate at request entry -------------------------------------------

    def evaluate_request(self) -> tuple[LensDecision, list[Detection]]:
        if not self.config.enabled:
            return LensDecision(), []
        now = time.time()
        self._maybe_transition_from_open(now)

        if self._state == _State.OPEN:
            return (
                LensDecision(
                    action="block",
                    reason="circuit_open",
                    triggered_by=["circuit_breaker.open"],
                    status_code=503,
                    retry_after=max(
                        0.0,
                        (self._opened_at + self.config.cooldown_seconds) - now,
                    ),
                ),
                [
                    Detection(
                        detector="circuit_breaker",
                        rule="open",
                        severity=Severity.HIGH,
                    )
                ],
            )
        if self._state == _State.HALF_OPEN and self._half_open_probes_inflight > 0:
            # Only one probe at a time.
            return (
                LensDecision(
                    action="block",
                    reason="circuit_half_open",
                    triggered_by=["circuit_breaker.half_open"],
                    status_code=503,
                ),
                [],
            )
        if self._state == _State.HALF_OPEN:
            self._half_open_probes_inflight += 1
        return LensDecision(), []

    # -- record outcomes -------------------------------------------------

    def record_response(self, *, error: bool) -> None:
        if not self.config.enabled:
            return
        now = time.time()
        self._calls.append((now, error))
        self._gc(now)

        if self._state == _State.HALF_OPEN:
            self._half_open_probes_inflight = max(0, self._half_open_probes_inflight - 1)
            if error:
                self._open(now)
            else:
                self._close()
            return

        if self._state == _State.CLOSED and self._should_trip(now):
            self._open(now)

    def record_attack_signal(self, severity: Severity) -> None:
        if not self.config.enabled or not self.config.fail_closed_on_attack:
            return
        now = time.time()
        self._attacks.append((now, severity))
        self._gc_attacks(now)

        threshold = self.config.fail_closed_min_severity
        if _rank(severity) < _rank(threshold):
            return

        recent_strong = sum(
            1
            for _, s in self._attacks
            if _SEVERITY_RANK[s] >= _rank(threshold)
        )
        if recent_strong >= self.config.fail_closed_min_attack_signals:
            self._open(now)

    # -- internals -------------------------------------------------------

    def _maybe_transition_from_open(self, now: float) -> None:
        if (
            self._state == _State.OPEN
            and now - self._opened_at >= self.config.cooldown_seconds
        ):
            self._state = _State.HALF_OPEN
            self._half_open_probes_inflight = 0

    def _should_trip(self, now: float) -> bool:
        self._gc(now)
        if len(self._calls) < self.config.min_samples:
            return False
        errors = sum(1 for _, e in self._calls if e)
        rate = errors / len(self._calls)
        return rate >= self.config.error_rate_threshold

    def _gc(self, now: float) -> None:
        cutoff = now - self.config.window_seconds
        while self._calls and self._calls[0][0] < cutoff:
            self._calls.popleft()

    def _gc_attacks(self, now: float) -> None:
        cutoff = now - self.config.fail_closed_attack_window_seconds
        while self._attacks and self._attacks[0][0] < cutoff:
            self._attacks.popleft()

    def _open(self, now: float) -> None:
        self._state = _State.OPEN
        self._opened_at = now

    def _close(self) -> None:
        self._state = _State.CLOSED
        self._half_open_probes_inflight = 0
