from __future__ import annotations

from pathlib import Path

from langgraph_lens import Lens


def test_jinja_ssti_detected_in_demo_canary(lens: Lens) -> None:
    demo = Path(__file__).parent.parent / "demo" / "malicious-prompt"
    event = lens.scan_prompt(demo)
    rules = [(d.detector, d.rule) for d in event.detections]
    assert ("supply_chain", "jinja_ssti") in rules


def test_path_traversal_in_path(lens: Lens) -> None:
    event = lens.scan_prompt("../../etc/passwd")
    rules = [(d.detector, d.rule) for d in event.detections]
    assert ("supply_chain", "path_traversal") in rules


def test_benign_prompt_no_detection(tmp_path: Path, lens: Lens) -> None:
    p = tmp_path / "ok.jinja2"
    p.write_text("You are a helpful assistant. User: {{ user_input }}\n")
    event = lens.scan_prompt(p)
    assert not any(d.detector == "supply_chain" for d in event.detections)
