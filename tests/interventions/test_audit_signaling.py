from __future__ import annotations

from langgraph_lens import Lens, LensConfig


def test_audit_headers_only_when_triggered() -> None:
    cfg = LensConfig.default()
    cfg.prometheus.enabled = False
    cfg.logging.enabled = False
    cfg.tier2.audit_signaling.enabled = True
    lens = Lens(cfg)

    # Nothing fires -> no audit headers.
    decision, _ = lens.decide_node(
        node="plan", state={"input": "summarise this"}, thread_id="t"
    )
    assert decision.headers == {}


def test_state_stamping() -> None:
    cfg = LensConfig.default()
    cfg.prometheus.enabled = False
    cfg.logging.enabled = False
    cfg.tier2.pii_redaction.enabled = True
    cfg.tier2.audit_signaling.enabled = True
    cfg.tier2.audit_signaling.stamp_state = True
    lens = Lens(cfg)

    decision, _ = lens.decide_node(
        node="act",
        state={"messages": [{"role": "user", "content": "SSN 123-45-6789"}]},
        thread_id="t",
    )
    assert decision.modified_state is not None
    stamp = decision.modified_state.get("__lens__")
    assert stamp is not None
    assert stamp["triggered"] is True
    assert stamp["action"] == "redact"
    assert any("pii_redactor" in t for t in stamp["triggered_by"])
