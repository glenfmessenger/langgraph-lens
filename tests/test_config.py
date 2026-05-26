from __future__ import annotations

from pathlib import Path

from langgraph_lens import LensConfig


def test_defaults_have_all_detectors_enabled() -> None:
    cfg = LensConfig.default()
    assert cfg.attack_surface.enabled
    assert cfg.checkpoint.enabled
    assert cfg.supply_chain.enabled
    assert cfg.tool.enabled
    assert cfg.memory.enabled
    assert cfg.pii.enabled
    assert cfg.goal_hijack.enabled
    assert cfg.comms.enabled
    assert cfg.sql_injection.enabled


def test_yaml_roundtrip(tmp_path: Path) -> None:
    src = Path(__file__).parent.parent / "lens.yaml"
    cfg = LensConfig.from_yaml(src)
    assert cfg.pii.enabled
    assert "ssn" in [p.type for p in cfg.pii.patterns]


def test_from_env_with_no_path_returns_default(monkeypatch) -> None:
    monkeypatch.delenv("LANGGRAPH_LENS_CONFIG", raising=False)
    cfg = LensConfig.from_env()
    assert cfg.checkpoint.enabled
