from __future__ import annotations

import time

from langgraph_lens import Lens, LensConfig
from langgraph_lens.events import Severity


def _lens(**overrides: object) -> Lens:
    cfg = LensConfig.default()
    cfg.prometheus.enabled = False
    cfg.logging.enabled = False
    cb = cfg.tier2.circuit_breaker
    cb.enabled = True
    cb.window_seconds = 60
    cb.min_samples = 4
    cb.error_rate_threshold = 0.5
    cb.cooldown_seconds = 60
    for k, v in overrides.items():
        setattr(cb, k, v)
    return Lens(cfg)


def test_trips_on_error_rate() -> None:
    lens = _lens()
    # 4 calls, 3 errors -> 75% > 50% threshold -> trip on the next check.
    for err in [True, True, True, False]:
        lens.record_upstream_result(error=err)
    d, _ = lens.decide_tool_call(tool="search", args={}, thread_id="t")
    assert d.action == "block"
    assert "circuit_breaker.open" in d.triggered_by


def test_fail_closed_on_attack_signals() -> None:
    lens = _lens(
        fail_closed_on_attack=True,
        fail_closed_min_severity="high",
        fail_closed_min_attack_signals=2,
        fail_closed_attack_window_seconds=60,
    )
    lens.circuit_breaker.record_attack_signal(Severity.HIGH)
    lens.circuit_breaker.record_attack_signal(Severity.HIGH)
    d, _ = lens.decide_tool_call(tool="search", args={}, thread_id="t")
    assert d.action == "block"


def test_low_severity_signals_dont_trip() -> None:
    lens = _lens(
        fail_closed_on_attack=True,
        fail_closed_min_severity="high",
        fail_closed_min_attack_signals=2,
    )
    for _ in range(10):
        lens.circuit_breaker.record_attack_signal(Severity.LOW)
    d, _ = lens.decide_tool_call(tool="search", args={}, thread_id="t")
    assert d.action == "allow"


def test_half_open_after_cooldown() -> None:
    # Short but non-zero cooldown — the first decide_tool_call must still
    # see the breaker as open; the second, after the sleep, must see it
    # half-open and allow a single probe.
    lens = _lens(min_samples=2, error_rate_threshold=0.5, cooldown_seconds=1)
    lens.record_upstream_result(error=True)
    lens.record_upstream_result(error=True)
    d, _ = lens.decide_tool_call(tool="search", args={}, thread_id="t")
    assert d.action == "block"
    # Drop the cooldown to 0 and sleep a tick so the transition fires.
    lens.circuit_breaker.config.cooldown_seconds = 0
    time.sleep(0.01)
    d2, _ = lens.decide_tool_call(tool="search", args={}, thread_id="t")
    # First call in half_open is allowed as a probe.
    assert d2.action == "allow"
