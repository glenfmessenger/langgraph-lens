from __future__ import annotations

from langgraph_lens import Lens


def test_union_select_in_thread_id(lens: Lens) -> None:
    event = lens.inspect_checkpoint(
        blob={"v": 1, "ts": "x", "channel_values": {}},
        metadata={"thread_id": "abc' UNION SELECT * FROM users --"},
        thread_id="abc",
        direction="write",
    )
    assert any(
        d.detector == "sql_injection" and d.rule == "union_select"
        for d in event.detections
    )


def test_clean_thread_id_no_detection(lens: Lens) -> None:
    event = lens.inspect_checkpoint(
        blob={"v": 1, "ts": "x", "channel_values": {}},
        metadata={"thread_id": "01J9ABCDEF1234"},
        thread_id="01J9ABCDEF1234",
        direction="write",
    )
    assert not any(d.detector == "sql_injection" for d in event.detections)
