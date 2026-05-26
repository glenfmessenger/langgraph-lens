from __future__ import annotations

import pytest

from langgraph_lens import Lens, LensConfig


@pytest.fixture()
def lens() -> Lens:
    cfg = LensConfig.default()
    cfg.prometheus.enabled = False
    cfg.logging.enabled = False
    return Lens(cfg)
