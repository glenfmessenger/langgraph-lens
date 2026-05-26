from __future__ import annotations

from langgraph_lens import Lens


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
