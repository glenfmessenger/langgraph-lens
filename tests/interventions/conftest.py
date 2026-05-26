from __future__ import annotations

import pytest

from langgraph_lens import Lens, LensConfig


def _quiet(cfg: LensConfig) -> LensConfig:
    cfg.prometheus.enabled = False
    cfg.logging.enabled = False
    return cfg


@pytest.fixture()
def t2_lens() -> Lens:
    """Lens with every Tier 2 intervention enabled in its default mode."""
    cfg = _quiet(LensConfig.default())
    cfg.tier2.pii_redaction.enabled = True
    cfg.tier2.tool_allowlist.enabled = True
    cfg.tier2.tool_allowlist.allowed_tools = ["search", "calculator"]
    cfg.tier2.checkpoint_protector.enabled = True
    cfg.tier2.goal_guard.enabled = True
    cfg.tier2.rate_limit.enabled = True
    cfg.tier2.rate_limit.capacity = 3
    cfg.tier2.rate_limit.refill_per_second = 0.0001
    cfg.tier2.circuit_breaker.enabled = True
    cfg.tier2.audit_signaling.enabled = True
    return Lens(cfg)
