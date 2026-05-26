from __future__ import annotations

import copy

from langgraph_lens import Lens, LensConfig


def _lens(mode: str = "redact") -> Lens:
    cfg = LensConfig.default()
    cfg.prometheus.enabled = False
    cfg.logging.enabled = False
    cfg.tier2.pii_redaction.enabled = True
    cfg.tier2.pii_redaction.mode = mode  # type: ignore[assignment]
    cfg.tier2.audit_signaling.enabled = True
    return Lens(cfg)


def test_redact_ssn_in_messages() -> None:
    lens = _lens()
    state = {"messages": [{"role": "user", "content": "My SSN is 123-45-6789"}]}
    decision, _event = lens.decide_node(node="act", state=state, thread_id="t")
    assert decision.action == "redact"
    assert "pii_redactor.ssn" in decision.triggered_by
    assert decision.modified_state is not None
    assert "[REDACTED:ssn]" in decision.modified_state["messages"][0]["content"]


def test_caller_state_is_not_mutated() -> None:
    lens = _lens()
    state = {"messages": [{"role": "user", "content": "My SSN is 123-45-6789"}]}
    snapshot = copy.deepcopy(state)
    lens.decide_node(node="act", state=state, thread_id="t")
    assert state == snapshot


def test_clean_state_no_redaction() -> None:
    lens = _lens()
    state = {"messages": [{"role": "user", "content": "summarise this PDF"}]}
    decision, _event = lens.decide_node(node="act", state=state, thread_id="t")
    assert decision.action == "allow"
    assert decision.modified_state is None


def test_block_mode_terminates() -> None:
    lens = _lens(mode="block")
    state = {"messages": [{"role": "user", "content": "card 4111 1111 1111 1111"}]}
    decision, _event = lens.decide_node(node="act", state=state, thread_id="t")
    assert decision.action == "block"
    assert decision.status_code == 400


def test_audit_headers_set_on_redact() -> None:
    lens = _lens()
    decision, _event = lens.decide_node(
        node="act",
        state={"input": "email me at user@example.com"},
        thread_id="t",
    )
    assert decision.headers.get("X-Lens-Triggered") == "true"
    assert decision.headers.get("X-Lens-Action") == "redact"
    assert "pii_redactor.email" in decision.headers.get("X-Lens-Reason", "")
