from __future__ import annotations

from langgraph_lens import Lens
from langgraph_lens.detectors.attack_surface import RuntimeInfo


def test_pickle_backend_flagged(lens: Lens) -> None:
    info = RuntimeInfo(
        checkpoint_saver="PostgresSaver",
        checkpoint_serializer="JsonPlusSerializer",
    )
    event = lens.scan_attack_surface(info)
    rules = [(d.detector, d.rule) for d in event.detections]
    assert ("attack_surface", "pickle_checkpoint_backend") in rules


def test_server_without_auth_critical(lens: Lens) -> None:
    info = RuntimeInfo(server_mode=True, server_auth_configured=False)
    event = lens.scan_attack_surface(info)
    assert any(
        d.detector == "attack_surface"
        and d.rule == "server_without_auth"
        and d.severity.value == "critical"
        for d in event.detections
    )


def test_memorysaver_does_not_flag(lens: Lens) -> None:
    info = RuntimeInfo(
        checkpoint_saver="MemorySaver",
        checkpoint_serializer="JsonPlusSerializer",
    )
    event = lens.scan_attack_surface(info)
    assert not any(
        d.detector == "attack_surface" and d.rule == "pickle_checkpoint_backend"
        for d in event.detections
    )
