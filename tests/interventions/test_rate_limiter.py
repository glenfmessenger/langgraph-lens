from __future__ import annotations

from langgraph_lens import Lens, LensConfig


def _lens(mode: str = "throttle", capacity: float = 2.0) -> Lens:
    cfg = LensConfig.default()
    cfg.prometheus.enabled = False
    cfg.logging.enabled = False
    cfg.tier2.rate_limit.enabled = True
    cfg.tier2.rate_limit.mode = mode  # type: ignore[assignment]
    cfg.tier2.rate_limit.capacity = capacity
    cfg.tier2.rate_limit.refill_per_second = 0.0001  # effectively no refill in test window
    cfg.tier2.rate_limit.key_by_tool = True
    return Lens(cfg)


def test_throttles_after_capacity() -> None:
    lens = _lens(capacity=2.0)
    for _ in range(2):
        d, _ = lens.decide_tool_call(tool="search", args={}, thread_id="t")
        assert d.action == "allow"
    d, _ = lens.decide_tool_call(tool="search", args={}, thread_id="t")
    assert d.action == "throttle"
    assert d.retry_after is not None and d.retry_after > 0


def test_block_mode_returns_429_equivalent() -> None:
    lens = _lens(mode="block", capacity=1.0)
    d, _ = lens.decide_tool_call(tool="search", args={}, thread_id="t")
    assert d.action == "allow"
    d, _ = lens.decide_tool_call(tool="search", args={}, thread_id="t")
    assert d.action == "block"
    assert d.status_code == 429


def test_separate_keys_have_separate_buckets() -> None:
    lens = _lens(capacity=1.0)
    d1, _ = lens.decide_tool_call(tool="search", args={}, thread_id="t-a")
    d2, _ = lens.decide_tool_call(tool="search", args={}, thread_id="t-b")
    assert d1.action == "allow"
    assert d2.action == "allow"  # different thread -> different bucket


def test_disabled_passthrough() -> None:
    cfg = LensConfig.default()
    cfg.prometheus.enabled = False
    cfg.logging.enabled = False
    lens = Lens(cfg)
    for _ in range(100):
        d, _ = lens.decide_tool_call(tool="search", args={}, thread_id="t")
        assert d.action == "allow"
