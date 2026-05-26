from __future__ import annotations

from langgraph_lens import Lens


def test_shell_metachar_detected(lens: Lens) -> None:
    event = lens.inspect_tool_call(
        tool="shell",
        args={"cmd": "ls; rm -rf /"},
        thread_id="t",
    )
    assert any(
        d.detector == "tool" and d.rule == "shell_metachar" for d in event.detections
    )


def test_ssrf_pattern_detected(lens: Lens) -> None:
    event = lens.inspect_tool_call(
        tool="http_get",
        args={"url": "http://169.254.169.254/latest/meta-data/"},
        thread_id="t",
    )
    assert any(
        d.detector == "tool" and d.rule == "ssrf_pattern" for d in event.detections
    )


def test_out_of_allowlist(lens: Lens) -> None:
    event = lens.inspect_tool_call(
        tool="exec_python",
        args={},
        allowed_tools=["search", "calculator"],
        thread_id="t",
    )
    assert any(
        d.detector == "tool" and d.rule == "out_of_allowlist" for d in event.detections
    )


def test_enumeration_fires_after_threshold(lens: Lens) -> None:
    for i in range(9):
        lens.inspect_tool_call(tool=f"tool_{i}", args={}, thread_id="t-enum")
    # The 9th call should push distinct-count to 9 ≥ 8.
    events = lens.events_for_thread("t-enum")
    assert any(
        any(d.rule == "enumeration" for d in e.detections) for e in events
    )
