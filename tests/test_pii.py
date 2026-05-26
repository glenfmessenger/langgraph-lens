from __future__ import annotations

from langgraph_lens import Lens, LensConfig
from langgraph_lens.config import PIIPattern


def test_ssn_detected_at_ingress(lens: Lens) -> None:
    event = lens.inspect_node(
        node="act",
        state={"messages": [{"role": "user", "content": "My SSN is 123-45-6789"}]},
        thread_id="t",
    )
    rules = [(d.detector, d.rule) for d in event.detections]
    assert ("pii", "ssn") in rules


def test_email_detected_at_ingress(lens: Lens) -> None:
    event = lens.inspect_node(
        node="act",
        state={"input": "contact me at user@example.com"},
        thread_id="t",
    )
    rules = [(d.detector, d.rule) for d in event.detections]
    assert ("pii", "email") in rules


def test_no_pii_in_clean_state(lens: Lens) -> None:
    event = lens.inspect_node(
        node="act", state={"input": "summarise this PDF"}, thread_id="t"
    )
    assert not any(d.detector == "pii" for d in event.detections)


def test_invalid_credit_card_rejected_by_luhn(lens: Lens) -> None:
    # Looks like a card, fails Luhn — should NOT fire.
    event = lens.inspect_node(
        node="act",
        state={"input": "card 1234 5678 9012 3456"},
        thread_id="t",
    )
    assert not any(
        d.detector == "pii" and d.rule == "credit_card" for d in event.detections
    )


# -- Custom PII patterns (PIIPattern(name=..., regex=...)) ---------------


def _lens_with_custom_pattern(*patterns: PIIPattern) -> Lens:
    cfg = LensConfig.default()
    cfg.prometheus.enabled = False
    cfg.logging.enabled = False
    cfg.pii.custom_patterns = list(patterns)
    return Lens(cfg)


def test_custom_pii_pattern_fires_at_ingress() -> None:
    # An internal employee-ID format like ACME-12345.
    lens = _lens_with_custom_pattern(
        PIIPattern(name="employee_id", regex=r"\bACME-\d{5}\b")
    )
    event = lens.inspect_node(
        node="act",
        state={"input": "lookup user ACME-12345"},
        thread_id="t",
    )
    detections = [(d.detector, d.rule) for d in event.detections]
    assert ("pii", "employee_id") in detections


def test_custom_pii_pattern_does_not_fire_on_misses() -> None:
    lens = _lens_with_custom_pattern(
        PIIPattern(name="employee_id", regex=r"\bACME-\d{5}\b")
    )
    event = lens.inspect_node(
        node="act",
        state={"input": "lookup user ACME-99"},  # 2 digits, not 5
        thread_id="t",
    )
    assert not any(
        d.detector == "pii" and d.rule == "employee_id" for d in event.detections
    )


def test_custom_pii_pattern_unnamed_falls_back_to_custom() -> None:
    """A custom pattern with no `name` should still compile, using
    the literal 'custom' as the rule name."""
    lens = _lens_with_custom_pattern(PIIPattern(regex=r"\bSECRET-[A-Z]{4}\b"))
    event = lens.inspect_node(
        node="act",
        state={"input": "the key is SECRET-WXYZ"},
        thread_id="t",
    )
    assert any(
        d.detector == "pii" and d.rule == "custom" for d in event.detections
    )


def test_custom_pii_pattern_appears_in_redactor() -> None:
    """A custom pattern configured under `tier2.pii_redaction.custom_patterns`
    should also be honoured by the Tier 2 redactor.
    """
    cfg = LensConfig.default()
    cfg.prometheus.enabled = False
    cfg.logging.enabled = False
    cfg.tier2.pii_redaction.enabled = True
    cfg.tier2.pii_redaction.custom_patterns = [
        PIIPattern(name="employee_id", regex=r"\bACME-\d{5}\b")
    ]
    lens = Lens(cfg)
    decision, _event = lens.decide_node(
        node="act",
        state={"messages": [{"role": "user", "content": "User ACME-12345 paid"}]},
        thread_id="t",
    )
    assert decision.action == "redact"
    assert "pii_redactor.employee_id" in decision.triggered_by
    assert decision.modified_state is not None
    assert "[REDACTED:employee_id]" in decision.modified_state["messages"][0]["content"]


def test_pattern_with_neither_type_nor_regex_is_silently_skipped() -> None:
    """A PIIPattern with neither `type` nor `regex` shouldn't crash the
    detector — it's just inert.
    """
    lens = _lens_with_custom_pattern(PIIPattern(name="ghost"))
    # Should not raise.
    event = lens.inspect_node(
        node="act",
        state={"input": "any text"},
        thread_id="t",
    )
    assert not any(
        d.detector == "pii" and d.rule == "ghost" for d in event.detections
    )
