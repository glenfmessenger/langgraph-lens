from __future__ import annotations

from langgraph_lens import Lens, LensConfig


def _lens(mode: str = "block", allow: list[str] | None = None) -> Lens:
    cfg = LensConfig.default()
    cfg.prometheus.enabled = False
    cfg.logging.enabled = False
    cfg.tier2.tool_allowlist.enabled = True
    cfg.tier2.tool_allowlist.mode = mode  # type: ignore[assignment]
    cfg.tier2.tool_allowlist.allowed_tools = allow
    cfg.tier2.audit_signaling.enabled = True
    return Lens(cfg)


def test_unknown_tool_blocked() -> None:
    lens = _lens(allow=["search", "calculator"])
    decision, _ = lens.decide_tool_call(tool="exec_python", args={}, thread_id="t")
    assert decision.action == "block"
    assert decision.status_code == 403
    assert "tool_allowlist.out_of_allowlist" in decision.triggered_by


def test_shell_metachar_blocked_via_misuse_rule() -> None:
    lens = _lens()  # no allowlist enforced
    decision, _ = lens.decide_tool_call(
        tool="shell", args={"cmd": "ls; rm -rf /"}, thread_id="t"
    )
    assert decision.action == "block"
    assert "tool_allowlist.shell_metachar" in decision.triggered_by


def test_log_mode_passes_through() -> None:
    lens = _lens(mode="log")
    decision, _ = lens.decide_tool_call(
        tool="shell", args={"cmd": "ls; rm -rf /"}, thread_id="t"
    )
    assert decision.action == "allow"
    assert "tool_allowlist.shell_metachar" in decision.triggered_by


def test_disabled_passthrough() -> None:
    cfg = LensConfig.default()
    cfg.prometheus.enabled = False
    cfg.logging.enabled = False
    # tool_allowlist stays disabled
    lens = Lens(cfg)
    decision, _ = lens.decide_tool_call(tool="any_tool", args={}, thread_id="t")
    assert decision.action == "allow"
    assert decision.triggered_by == []
